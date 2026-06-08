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
use smoldot_e2e_tests::{
    bulletin::{self, Payload},
    harness::bulletin_network_config,
    resolve_base_dir,
};
use zombienet_sdk::{
    snapshot::BundleBuilder,
    subxt::{
        config::{substrate::SubstrateConfig, DefaultExtrinsicParamsBuilder},
        dynamic::{tx, Value},
        OnlineClient,
    },
    subxt_signer::sr25519::{dev, Keypair},
    LocalFileSystem, Network,
};

const SPAWN_TIMEOUT_SECS: u64 = 300;
const EXTRINSIC_TIMEOUT_SECS: u64 = 60;

/// Authorisation budget granted to //Alice. Lets one account post the
/// whole payload set (4 transactions, max 1 MiB each).
const AUTH_TX_LIMIT: u32 = 1000;
const AUTH_BYTE_LIMIT: u64 = 100_000_000;

// The bulletin chain is a vanilla substrate chain (standard AccountId32 /
// MultiAddress / sr25519 / Blake2 header) whose signed extensions all fall
// within subxt's `DefaultExtrinsicParams` set, so stock `SubstrateConfig`
// works. The actual calls are built dynamically against the live chain's
// metadata (see `tx(...)` below), so they target the real bulletin runtime.

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

/// Generator for the bulletin-chain DB snapshots used by the bitswap
/// zombienet tests.
///
/// Flow:
///   1. Spawn westend-local relay and bulletin parachain (para id 2487).
///   2. Authorise //Alice, then submit `transactionStorage::store` for
///      every entry in `bulletin::payloads()`, snapshotting the partial
///      collator DB after the first `PARTIAL_FORK_INDEX` payloads.
///   3. Wait until the parachain reaches `BULLETIN_SNAPSHOT_TARGET_HEIGHT`.
///   4. Snapshot the relay + full collator DBs.
///   5. Pack relay + full + partial archives into a single `bundle.tar.gz`
///      via the zombienet-sdk `BundleBuilder` (manifest embedded).
///
/// The per-node tarring / pause-resume / checksumming is done by the SDK
/// (`NetworkNode::snapshot_db`, `Network::pause`/`resume`,
/// `snapshot::BundleBuilder`); this test only orchestrates payload
/// injection and the snapshot points.
///
/// Outputs land under `${BULLETIN_SNAPSHOT_OUT_DIR:-e2e-tests/target/snapshots}/`:
/// the loose `relay.tgz` / `bulletin-full.tgz` / `bulletin-partial.tgz`
/// plus the bundled `bundle.tar.gz`.
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
    let alice_signer = dev::alice();
    authorize_account(&api, &alice_signer, &alice_signer).await?;

    let payloads = bulletin::payloads();
    let (phase_1, phase_2) = payloads.split_at(bulletin::PARTIAL_FORK_INDEX);
    info!(
        "injecting {} pre-fork + {} post-fork payloads",
        phase_1.len(),
        phase_2.len()
    );

    for payload in phase_1 {
        submit_store(&api, &alice_signer, payload).await?;
    }

    // Partial snapshot: collator-1's DB after only the pre-fork payloads.
    // No `relay-data/` ends up in the archive — collators run with
    // `--relay-chain-rpc-urls`, so the embedded relay client loads nothing
    // from disk anyway, and `snapshot_db` only includes `relay-data/` when
    // it exists.
    info!(
        "snapshotting partial bulletin DB after {} payloads",
        phase_1.len()
    );
    network.pause().await?;
    let partial = collator
        .snapshot_db(opts.out_dir.join("bulletin-partial.tgz"))
        .await?;
    network.resume().await?;

    for payload in phase_2 {
        submit_store(&api, &alice_signer, payload).await?;
    }

    info!("waiting for parachain height >= {}", opts.target_height);
    collator
        .wait_metric_with_timeout(
            "block_height{status=\"best\"}",
            |h| h >= opts.target_height as f64,
            7200u64,
        )
        .await?;

    // Full snapshot: relay (alice) + collator-1 with every payload.
    info!("snapshotting full state");
    network.pause().await?;
    let relay = network
        .get_node("alice")?
        .snapshot_db(opts.out_dir.join("relay.tgz"))
        .await?;
    let full = collator
        .snapshot_db(opts.out_dir.join("bulletin-full.tgz"))
        .await?;
    network.resume().await?;

    info!("packing bundle.tar.gz");
    let payload_meta: Vec<serde_json::Value> = payloads
        .iter()
        .map(|p| {
            serde_json::json!({
                "label": p.label,
                "cid": p.predicted_cid(),
                "sha256": p.sha256_hex(),
                "size": p.size(),
                "on_partial": p.on_partial,
            })
        })
        .collect();

    let bundle = BundleBuilder::new()
        .add(relay)
        .add(full)
        .add(partial)
        .user_data(serde_json::json!({
            "snapshot_height": opts.target_height,
            "partial_fork_index": bulletin::PARTIAL_FORK_INDEX,
            "bulletin_release_tag": std::env::var("BULLETIN_RELEASE_TAG")
                .unwrap_or_else(|_| "dev".into()),
            "polkadot_release_tag": std::env::var("POLKADOT_RELEASE_TAG")
                .unwrap_or_else(|_| "polkadot-stable2603".into()),
            "payloads": payload_meta,
        }))
        .build(opts.out_dir.join("bundle.tar.gz"))?;

    info!(
        "snapshot bundle written to {} (sha256={}, {} bytes)",
        bundle.path.display(),
        bundle.sha256,
        bundle.size
    );
    Ok(())
}

async fn spawn_network(chain_spec: &Path) -> Result<Network<LocalFileSystem>> {
    let base_dir = resolve_base_dir()?;
    let config = bulletin_network_config(&base_dir, chain_spec, None, &[])?;

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

async fn connect_subxt(ws_url: &str) -> Result<OnlineClient<SubstrateConfig>> {
    OnlineClient::<SubstrateConfig>::from_url(ws_url)
        .await
        .with_context(|| format!("subxt connect to {ws_url}"))
}

/// Calls `transactionStorage::authorize_account(who, transactions, bytes)`
/// signed by `authorizer`. The bulletin runtime grants the `Authorizer`
/// origin to a fixed set of test accounts (Alice in `bulletin-westend`'s
/// `local_testnet` preset), so no sudo wrapping is needed.
async fn authorize_account(
    api: &OnlineClient<SubstrateConfig>,
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

    let params = DefaultExtrinsicParamsBuilder::<SubstrateConfig>::new().build();
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
/// event. Returns the predicted CID.
async fn submit_store(
    api: &OnlineClient<SubstrateConfig>,
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

    let params = DefaultExtrinsicParamsBuilder::<SubstrateConfig>::new().build();
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
