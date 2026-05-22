// Smoldot
// Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use log::info;
use smoldot_e2e_tests::bulletin::{
    self, ArchiveChecksums, BulletinManifest, ManifestPayload, Payload,
};
use zombienet_sdk::{
    subxt::{
        config::{
            substrate::SubstrateConfig, transaction_extensions, Config,
            DefaultExtrinsicParamsBuilder,
        },
        dynamic::{tx, Value},
        OnlineClient,
    },
    subxt_signer::sr25519::{dev, Keypair},
    LocalFileSystem, Network, NetworkConfigBuilder,
};

const SPAWN_TIMEOUT_SECS: u64 = 300;
const EXTRINSIC_TIMEOUT_SECS: u64 = 60;

/// Authorisation budget granted to //Alice. Lets one account post the
/// whole payload set (4 transactions, max 1 MiB each).
const AUTH_TX_LIMIT: u32 = 1000;
const AUTH_BYTE_LIMIT: u64 = 100_000_000;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
enum BulletinConfig {}

type BulletinExtrinsicParams = transaction_extensions::AnyOf<
    BulletinConfig,
    (
        transaction_extensions::VerifySignature<BulletinConfig>,
        transaction_extensions::CheckSpecVersion,
        transaction_extensions::CheckTxVersion,
        transaction_extensions::CheckNonce,
        transaction_extensions::CheckGenesis<BulletinConfig>,
        transaction_extensions::CheckMortality<BulletinConfig>,
        transaction_extensions::ChargeAssetTxPayment<BulletinConfig>,
        transaction_extensions::ChargeTransactionPayment,
        transaction_extensions::CheckMetadataHash,
    ),
>;

impl Config for BulletinConfig {
    type AccountId = <SubstrateConfig as Config>::AccountId;
    type Address = <SubstrateConfig as Config>::Address;
    type Signature = <SubstrateConfig as Config>::Signature;
    type Hasher = <SubstrateConfig as Config>::Hasher;
    type Header = <SubstrateConfig as Config>::Header;
    type ExtrinsicParams = BulletinExtrinsicParams;
    type AssetId = <SubstrateConfig as Config>::AssetId;
}

struct SnapshotOpts {
    chain_spec: PathBuf,
    out_dir: PathBuf,
    target_height: u64,
}

impl SnapshotOpts {
    fn from_env() -> Result<Self> {
        let chain_spec = std::env::var("BULLETIN_CHAIN_SPEC")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("chain-specs/bulletin-westend-local-spec.json")
            });
        if !chain_spec.exists() {
            bail!(
                "bulletin chain spec not found at {}. Override with BULLETIN_CHAIN_SPEC \
                 or regenerate via polkadot-bulletin-chain/scripts/create_bulletin_westend_spec.sh",
                chain_spec.display()
            );
        }

        let out_dir = std::env::var("BULLETIN_SNAPSHOT_OUT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/snapshots"));

        let target_height: u64 = std::env::var("BULLETIN_SNAPSHOT_TARGET_HEIGHT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(bulletin::DEFAULT_SNAPSHOT_HEIGHT);

        let smoke = matches!(
            std::env::var("BULLETIN_SNAPSHOT_SMOKE").as_deref(),
            Ok("1") | Ok("true")
        );
        if !smoke && target_height <= 1000 {
            bail!(
                "target_height={target_height} must exceed 1000. \
                 Set BULLETIN_SNAPSHOT_SMOKE=1 to bypass"
            );
        }

        Ok(Self {
            chain_spec,
            out_dir,
            target_height,
        })
    }
}

/// Manual generator for the bulletin-chain DB snapshots used by the bitswap
/// zombienet tests.
///
/// Flow:
///   1. Spawn westend-local relay and bulletin parachain (para id 2487).
///   2. Authorise //Alice, then submit `transactionStorage::store` for
///      every entry in `bulletin::payloads()`.
///   3. Wait until the parachain reaches `BULLETIN_SNAPSHOT_TARGET_HEIGHT`.
///   4. Tar/gzip the relay and bulletin DBs and write a `manifest.json`.
///
/// Outputs land under `${BULLETIN_SNAPSHOT_OUT_DIR:-e2e-tests/target/snapshots}/`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "produces large DB snapshots and must be run manually"]
async fn bulletin_generate_snapshot() -> Result<()> {
    env_logger::try_init().ok();

    let opts = SnapshotOpts::from_env()?;
    std::fs::create_dir_all(&opts.out_dir)
        .with_context(|| format!("creating {}", opts.out_dir.display()))?;

    let network = spawn_network(&opts.chain_spec).await?;
    let collator = network.get_node("collator-1")?;
    let api = connect_subxt(collator.ws_uri()).await?;

    info!("authorising //Alice");
    let alice = dev::alice();
    authorize_account(&api, &alice, &alice).await?;

    let payloads = bulletin::payloads();
    let (phase_1, phase_2) = payloads.split_at(bulletin::PARTIAL_FORK_INDEX);
    info!(
        "injecting {} pre-fork + {} post-fork payloads",
        phase_1.len(),
        phase_2.len()
    );

    let mut emitted_cids = Vec::new();
    for payload in phase_1 {
        let cid_str = submit_store(&api, &alice, payload).await?;
        emitted_cids.push((payload.label, cid_str));
    }

    let base_dir = PathBuf::from(
        network
            .base_dir()
            .ok_or_else(|| anyhow!("network has no base_dir"))?,
    );
    let staging_dir = base_dir.join("partial-staging");

    info!("forking bulletin DB after {} payloads", phase_1.len());
    fork_collator_db(&network, &base_dir, &staging_dir).await?;

    for payload in phase_2 {
        let cid_str = submit_store(&api, &alice, payload).await?;
        emitted_cids.push((payload.label, cid_str));
    }

    info!("waiting for parachain height >= {}", opts.target_height);
    collator
        .wait_metric_with_timeout(
            "block_height{status=\"best\"}",
            |h| h >= opts.target_height as f64,
            7200u64,
        )
        .await?;

    // The full snapshot (relay + bulletin-with-all-payloads) is taken via
    // the same pause/copy/resume primitive as the partial fork so the on-
    // disk RocksDB state is consistent. Calling `network.destroy()` instead
    // would trigger zombienet's crash watcher, which `process::exit(1)`s
    // before we finish tarring.
    let final_staging = base_dir.join("final-staging");
    info!("snapshotting full state");
    snapshot_full_state(&network, &base_dir, &final_staging).await?;

    info!("packing snapshots");
    let relay_archive = pack_node_dirs(
        &final_staging.join("relay").join("data"),
        None,
        &opts.out_dir.join("relay.tgz"),
    )?;
    let bulletin_full_archive = pack_node_dirs(
        &final_staging.join("bulletin").join("data"),
        Some(&final_staging.join("bulletin").join("relay-data")),
        &opts.out_dir.join("bulletin-full.tgz"),
    )?;
    let bulletin_partial_archive = pack_node_dirs(
        &staging_dir.join("data"),
        Some(&staging_dir.join("relay-data")),
        &opts.out_dir.join("bulletin-partial.tgz"),
    )?;

    info!("writing manifest.json");
    let manifest = build_manifest(
        &opts,
        &emitted_cids,
        &payloads,
        &relay_archive,
        &bulletin_full_archive,
        &bulletin_partial_archive,
    )?;
    let manifest_path = opts.out_dir.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("writing {}", manifest_path.display()))?;

    info!("snapshots written to {}", opts.out_dir.display());
    Ok(())
}

/// Pauses both collators (SIGSTOP), copies collator-1's `data/` and
/// `relay-data/` into `staging`, then resumes the collators (SIGCONT).
/// The pause window is the only consistent point at which we can fork
/// RocksDB without risking a torn snapshot.
async fn fork_collator_db(
    network: &Network<LocalFileSystem>,
    base_dir: &Path,
    staging: &Path,
) -> Result<()> {
    let collator1 = network.get_node("collator-1")?;
    let collator2 = network.get_node("collator-2")?;

    collator1.pause().await?;
    collator2.pause().await?;

    let copy_result: Result<()> = (|| {
        let src = base_dir.join("collator-1");
        std::fs::create_dir_all(staging)
            .with_context(|| format!("creating {}", staging.display()))?;
        copy_dir_all(&src.join("data"), &staging.join("data"))?;
        let relay_data = src.join("relay-data");
        if relay_data.is_dir() {
            copy_dir_all(&relay_data, &staging.join("relay-data"))?;
        }
        Ok(())
    })();

    collator1.resume().await?;
    collator2.resume().await?;
    copy_result
}

/// Pauses every node, copies the relay (alice) and bulletin (collator-1)
/// directories into `staging/{relay,bulletin}/`, and resumes. The pause
/// window is shorter than the zombienet crash-watcher's poll interval so
/// it doesn't fire `process::exit(1)` on us.
async fn snapshot_full_state(
    network: &Network<LocalFileSystem>,
    base_dir: &Path,
    staging: &Path,
) -> Result<()> {
    let alice = network.get_node("alice")?;
    let bob = network.get_node("bob")?;
    let collator1 = network.get_node("collator-1")?;
    let collator2 = network.get_node("collator-2")?;

    alice.pause().await?;
    bob.pause().await?;
    collator1.pause().await?;
    collator2.pause().await?;

    let copy_result: Result<()> = (|| {
        let relay_dst = staging.join("relay");
        std::fs::create_dir_all(&relay_dst)
            .with_context(|| format!("creating {}", relay_dst.display()))?;
        copy_dir_all(
            &base_dir.join("alice").join("data"),
            &relay_dst.join("data"),
        )?;

        let bulletin_dst = staging.join("bulletin");
        std::fs::create_dir_all(&bulletin_dst)
            .with_context(|| format!("creating {}", bulletin_dst.display()))?;
        let collator_src = base_dir.join("collator-1");
        copy_dir_all(&collator_src.join("data"), &bulletin_dst.join("data"))?;
        let collator_relay = collator_src.join("relay-data");
        if collator_relay.is_dir() {
            copy_dir_all(&collator_relay, &bulletin_dst.join("relay-data"))?;
        }
        Ok(())
    })();

    alice.resume().await?;
    bob.resume().await?;
    collator1.resume().await?;
    collator2.resume().await?;
    copy_result
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst).with_context(|| format!("creating {}", dst.display()))?;
    for entry in std::fs::read_dir(src).with_context(|| format!("reading {}", src.display()))? {
        let entry = entry?;
        let dst_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &dst_path)?;
        } else {
            std::fs::copy(entry.path(), &dst_path).with_context(|| {
                format!(
                    "copying {} -> {}",
                    entry.path().display(),
                    dst_path.display()
                )
            })?;
        }
    }
    Ok(())
}

async fn spawn_network(chain_spec: &Path) -> Result<Network<LocalFileSystem>> {
    let chain_spec_str = chain_spec
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 chain spec path"))?
        .to_string();

    let config = NetworkConfigBuilder::new()
        .with_relaychain(|rc| {
            rc.with_chain(bulletin::RELAY_CHAIN)
                .with_default_command(bulletin::RELAY_BINARY)
                .with_validator(|node| node.with_name("alice"))
                .with_validator(|node| node.with_name("bob"))
        })
        .with_parachain(|p| {
            p.with_id(bulletin::PARA_ID)
                .with_chain_spec_path(chain_spec_str.as_str())
                .cumulus_based(true)
                .with_collator(|c| {
                    c.with_name("collator-1")
                        .validator(true)
                        .with_command(bulletin::PARA_BINARY)
                        // `--ipfs-server` exposes bitswap so the eventual
                        // CI test can dial against the snapshot.
                        .with_args(vec!["--ipfs-server".into()])
                })
                .with_collator(|c| {
                    c.with_name("collator-2")
                        .validator(true)
                        .with_command(bulletin::PARA_BINARY)
                        .with_args(vec!["--ipfs-server".into()])
                })
        })
        .with_global_settings(|g| {
            g.with_spawn_concurrency(1) // https://github.com/paritytech/smoldot/pull/3249#issuecomment-4438807458
        })
        .build()
        .map_err(|e| anyhow!("network config errors: {e:?}"))?;

    let spawn_fn = zombienet_sdk::environment::get_spawn_fn();
    let network = spawn_fn(config).await?;

    let alice = network.get_node("alice")?;
    alice
        .wait_metric_with_timeout(
            "block_height{status=\"best\"}",
            |h| h >= 20.0,
            SPAWN_TIMEOUT_SECS,
        )
        .await?;

    let collator = network.get_node("collator-1")?;
    collator
        .wait_metric_with_timeout(
            "block_height{status=\"best\"}",
            |h| h >= 2.0,
            SPAWN_TIMEOUT_SECS,
        )
        .await?;

    Ok(network)
}

async fn connect_subxt(ws_url: &str) -> Result<OnlineClient<BulletinConfig>> {
    OnlineClient::<BulletinConfig>::from_url(ws_url)
        .await
        .with_context(|| format!("subxt connect to {ws_url}"))
}

/// Calls `transactionStorage::authorize_account(who, transactions, bytes)`
/// signed by `authorizer`. The bulletin runtime grants the `Authorizer`
/// origin to a fixed set of test accounts (Alice in `bulletin-westend`'s
/// `local_testnet` preset), so no sudo wrapping is needed.
async fn authorize_account(
    api: &OnlineClient<BulletinConfig>,
    authorizer: &Keypair,
    target: &Keypair,
) -> Result<()> {
    let target_account = target.public_key().to_account_id();
    let call = tx(
        "TransactionStorage",
        "authorize_account",
        vec![
            Value::from_bytes(target_account.0),
            Value::u128(AUTH_TX_LIMIT as u128),
            Value::u128(AUTH_BYTE_LIMIT as u128),
        ],
    );

    let params = DefaultExtrinsicParamsBuilder::<BulletinConfig>::new().build();
    let progress = tokio::time::timeout(
        Duration::from_secs(EXTRINSIC_TIMEOUT_SECS),
        api.tx()
            .sign_and_submit_then_watch(&call, authorizer, params),
    )
    .await
    .map_err(|_| anyhow!("authorize_account timed out"))??;

    let _events = tokio::time::timeout(
        Duration::from_secs(EXTRINSIC_TIMEOUT_SECS),
        progress.wait_for_finalized_success(),
    )
    .await
    .map_err(|_| anyhow!("authorize_account finalization timed out"))??;

    Ok(())
}

/// Submits `transactionStorage::store(data)` and waits for the `Stored`
/// event. Returns the predicted CID for the manifest.
async fn submit_store(
    api: &OnlineClient<BulletinConfig>,
    signer: &Keypair,
    payload: &Payload,
) -> Result<String> {
    let predicted = payload.predicted_cid();
    info!(
        "store {} ({} bytes) {}",
        payload.label,
        payload.size(),
        predicted
    );

    let call = tx(
        "TransactionStorage",
        "store",
        vec![Value::from_bytes(payload.content)],
    );

    let params = DefaultExtrinsicParamsBuilder::<BulletinConfig>::new().build();
    let progress = tokio::time::timeout(
        Duration::from_secs(EXTRINSIC_TIMEOUT_SECS),
        api.tx().sign_and_submit_then_watch(&call, signer, params),
    )
    .await
    .map_err(|_| anyhow!("store({}) submit timed out", payload.label))??;

    let events = tokio::time::timeout(
        Duration::from_secs(EXTRINSIC_TIMEOUT_SECS * 2),
        progress.wait_for_finalized_success(),
    )
    .await
    .map_err(|_| anyhow!("store({}) finalize timed out", payload.label))??;

    for ev in events.iter() {
        let ev = ev?;
        if ev.pallet_name() == "TransactionStorage" && ev.variant_name() == "Stored" {
            return Ok(predicted);
        }
    }
    bail!("no TransactionStorage::Stored event for {}", payload.label);
}

/// Tar/gzips `data` (and optionally `relay_data`) into `archive_path` and
/// returns the hex-encoded SHA-256 of the archive. Top-level entries are
/// `data/` and `relay-data/` so zombienet-sdk's auto-extract drops the
/// contents at the node's expected paths.
fn pack_node_dirs(data: &Path, relay_data: Option<&Path>, archive_path: &Path) -> Result<String> {
    use sha2::{Digest as _, Sha256};

    if !data.is_dir() {
        bail!("data dir not found: {}", data.display());
    }

    let f = std::fs::File::create(archive_path)
        .with_context(|| format!("creating {}", archive_path.display()))?;
    let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    tar.append_dir_all("data", data)
        .with_context(|| format!("tarring {}", data.display()))?;

    if let Some(rd) = relay_data {
        if rd.is_dir() {
            tar.append_dir_all("relay-data", rd)
                .with_context(|| format!("tarring {}", rd.display()))?;
        }
    }

    tar.finish()?;
    drop(tar);

    let bytes = std::fs::read(archive_path)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn build_manifest(
    opts: &SnapshotOpts,
    emitted: &[(&'static str, String)],
    payloads: &[Payload],
    relay_sha256: &str,
    bulletin_full_sha256: &str,
    bulletin_partial_sha256: &str,
) -> Result<BulletinManifest> {
    let manifest_payloads = emitted
        .iter()
        .map(|(label, cid)| {
            let p = payloads
                .iter()
                .find(|p| p.label == *label)
                .ok_or_else(|| anyhow!("emitted CID for unknown payload {label}"))?;
            Ok::<_, anyhow::Error>(ManifestPayload {
                label: label.to_string(),
                cid: cid.clone(),
                sha256: p.sha256_hex(),
                size: p.size(),
                on_partial: p.on_partial,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(BulletinManifest {
        schema_version: 1,
        snapshot_height: opts.target_height,
        bulletin_release_tag: std::env::var("BULLETIN_RELEASE_TAG")
            .unwrap_or_else(|_| "dev".into()),
        polkadot_release_tag: std::env::var("POLKADOT_RELEASE_TAG")
            .unwrap_or_else(|_| "polkadot-stable2603".into()),
        payloads: manifest_payloads,
        archives: ArchiveChecksums {
            relay_sha256: relay_sha256.to_string(),
            bulletin_full_sha256: bulletin_full_sha256.to_string(),
            bulletin_partial_sha256: bulletin_partial_sha256.to_string(),
        },
    })
}
