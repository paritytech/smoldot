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

//! Snapshot generator for the smoldot smoke scenarios.
//!
//! Builds the artifact set consumed by `smoke_cold` / `smoke_warm` (network
//! DB tarballs, chain specs with `lightSyncState`, smoldot databaseContent
//! dumps). Marked `#[ignore]`: only runs when invoked explicitly with
//! `cargo test … -- --ignored`.
//!
//! Driven by env vars (set when invoking `cargo test`):
//!   * `SMOKE_SNAPSHOT_OUT`               — output directory (required)
//!   * `SMOKE_SNAPSHOT_TARGET_FINALIZED`  — snapshot block height (default 100)
//!   * `SMOKE_SNAPSHOT_SPEC_AT_FINALIZED` — `lightSyncState` block (default target/2)
//!   * `SMOKE_SNAPSHOT_RELAY_DB`          — resume validators from this tarball
//!   * `SMOKE_SNAPSHOT_PARA_DB`           — resume collators from this tarball
//!
//! See `e2e-tests/docs/smoke-scenarios.md` for the produced layout and
//! the regeneration procedure.

use std::path::{Path, PathBuf};

use anyhow::anyhow;
use serde_json::Value;
use smoldot_e2e_tests::{
    elastic_scaling_genesis_overrides, ensure_js_deps_installed, ensure_smoldot_built,
    resolve_base_dir, run_js_test, BEST_METRIC, ELASTIC_VALIDATOR_COUNT, FINALIZED_METRIC, PARA_ID,
};
use zombienet_sdk::{
    snapshot::BundleBuilder, subxt::ext::subxt_rpcs::rpc_params, Bundle, LocalFileSystem, Network,
    NetworkConfig, NetworkConfigBuilder, NetworkNode,
};

const DEFAULT_TARGET_FINALIZED: u32 = 2500;

/// Smoldot triggers real warp sync (vs follow-forward) when the gap between
/// `lightSyncState` and current head exceeds this many blocks.
const WARP_SYNC_MINIMUM_GAP: u32 = 32;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "produces large DB snapshots and must be run manually"]
async fn smoke_generate_snapshots() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let args = Args::from_env()?;
    log::info!(
        "smoke_generate_snapshots: out={} spec_at=#{} target_finalized=#{} relay_snap={:?} para_snap={:?}",
        args.out.display(),
        args.spec_at_finalized,
        args.target_finalized,
        args.relay_db_snapshot,
        args.para_db_snapshot,
    );

    std::fs::create_dir_all(&args.out)?;
    let base_dir = resolve_base_dir()?;
    let base_dir_str = base_dir.to_str().expect("UTF-8 path").to_owned();

    let config = build_config(
        &base_dir_str,
        args.relay_db_snapshot.as_deref(),
        args.para_db_snapshot.as_deref(),
    )?;

    log::info!("spawning zombienet network");
    let spawn_fn = zombienet_sdk::environment::get_spawn_fn();
    let network = spawn_fn(config).await?;

    network.wait_until_is_up(120).await?;
    log::info!("network is up");

    let validator = network.get_node("validator-0")?;

    // Step 1: capture the spec when finalized reaches `spec_at_finalized`.
    // Doing this earlier than the snapshot makes the gap between
    // `lightSyncState` and current head wide enough to trigger smoldot's
    // real warp sync (gap > WARP_SYNC_MINIMUM_GAP), which handles
    // GRANDPA authority-set changes via fragments — what follow-forward
    // does not do.
    wait_for_finalized(validator, args.spec_at_finalized).await?;
    gen_sync_spec(
        network.get_node("validator-0")?,
        &args.out.join("relay-spec.json"),
    )
    .await?;
    write_light_sync_state_spec(
        network.get_node("validator-0")?,
        &args.out.join("relay-spec.json"),
        &args.out.join("relay-spec-lightSyncState.json"),
    )
    .await?;
    // Cumulus parachains don't expose `sync_state_genSyncSpec` — there's no
    // independent finality on a parachain, so there's no `lightSyncState`
    // to bake. Smoldot's cold/warm path for the parachain is automatic
    // given the relay's `lightSyncState`. Copy the zombienet-emitted raw
    // spec verbatim.
    let network_base = PathBuf::from(
        network
            .base_dir()
            .ok_or_else(|| anyhow!("no network base_dir"))?,
    );
    let parachain = network
        .parachain(PARA_ID)
        .ok_or_else(|| anyhow!("parachain {PARA_ID} not found"))?;
    let para_chain_name = parachain.chain_id().unwrap_or(parachain.unique_id());
    let para_spec_src = network_base.join(format!("{para_chain_name}.json"));
    let para_spec_dst = args.out.join("para-spec.json");
    copy_spec_stripping_bootnodes(&para_spec_src, &para_spec_dst)?;
    log::info!(
        "copied para spec {} -> {} (bootnodes stripped, {} bytes)",
        para_spec_src.display(),
        para_spec_dst.display(),
        std::fs::metadata(&para_spec_dst)?.len()
    );
    write_light_sync_state_spec(
        network.get_node("alice")?,
        &para_spec_dst,
        &args.out.join("para-spec-lightSyncState.json"),
    )
    .await?;

    // Step 2: keep the network running until finalized reaches
    // `target_finalized`, then run smoldot to capture its `databaseContent`
    // dump while the network is still advancing.
    wait_for_finalized(validator, args.target_finalized).await?;

    dump_smoldot_db(&args.out, &network).await?;

    // Step 3: drain in-flight parachain candidates so the unfinalized relay
    // suffix is candidate-free at snapshot time (see `drain_parachain_pipeline`).
    drain_parachain_pipeline(&network).await?;

    // Step 4: snapshot the DBs *after* the dump, so they are not frozen behind
    // smoldot's persisted finalized (else the consumer hangs on
    // `storage-proof-request-error`). `snapshot_db` tars `data/` (minus
    // `keystore/`/`network/`); `BundleBuilder` packs both tarballs + a manifest
    // carrying the lightSyncState specs and smoldot-db dumps in `user_data`.
    log::info!("pausing network for DB snapshots");
    network.pause().await?;
    let relay_snap = network
        .get_node("validator-0")?
        .snapshot_db(args.out.join("relaychain-db.tgz"))
        .await?;
    let para_snap = network
        .get_node("alice")?
        .snapshot_db(args.out.join("parachain-db.tgz"))
        .await?;
    network.resume().await?;
    log::info!("network resumed");

    let bundle = BundleBuilder::new()
        .add(relay_snap)
        .add(para_snap)
        .user_data(build_user_data(&args.out)?)
        .build(args.out.join("bundle.tar.gz"))?;

    print_manifest(&bundle);
    log::info!("done");
    Ok(())
}

/// Pauses the collators and waits for the relay to finalize past any in-flight
/// candidate, so the snapshot has no backed-but-unapproved candidate in its
/// unfinalized suffix.
///
/// Why: the single-node snapshot is restored to every consumer validator, so
/// network-wide there is only one validator's erasure chunk per candidate. A
/// candidate still pending approval at snapshot time can't be recovered after
/// resume (n=6 needs 2 distinct chunks), so its relay block never gets approved
/// and finality freezes. Post-resume candidates get full chunk distribution and
/// are fine — only the boundary ones are a problem, and draining removes them.
async fn drain_parachain_pipeline(network: &Network<LocalFileSystem>) -> Result<(), anyhow::Error> {
    /// Margin past best-at-pause, covering a collation already in flight.
    const DRAIN_MARGIN: u64 = 4;

    let relay = network.get_node("validator-0")?;
    let best_at_pause = relay.reports(BEST_METRIC).await? as u64;
    log::info!("draining parachain pipeline: pausing collators (relay best #{best_at_pause})");
    for collator in ["alice", "bob"] {
        network.get_node(collator)?.pause().await?;
    }

    let drain_target = best_at_pause + DRAIN_MARGIN;
    let timeout_secs = (DRAIN_MARGIN * 12).max(180);
    relay
        .wait_metric_with_timeout(FINALIZED_METRIC, |h| h >= drain_target as f64, timeout_secs)
        .await
        .map_err(|e| {
            anyhow!("relay did not finalize through #{drain_target} while draining: {e}")
        })?;
    log::info!("parachain pipeline drained: relay finalized >= #{drain_target}");
    Ok(())
}

/// Embeds every non-tarball artifact (full specs, lightSyncState specs,
/// smoldot-db dumps — all JSON) into the manifest `user_data`, keyed for
/// `snapshot::materialize`.
fn build_user_data(out: &Path) -> Result<serde_json::Value, anyhow::Error> {
    let read_json = |rel: &str| -> Result<Value, anyhow::Error> {
        let p = out.join(rel);
        serde_json::from_slice(&std::fs::read(&p).map_err(|e| anyhow!("{}: {e}", p.display()))?)
            .map_err(|e| anyhow!("{}: {e}", p.display()))
    };
    Ok(serde_json::json!({
        "artifacts_version": smoldot_e2e_tests::snapshot::ARTIFACTS_VERSION,
        "relay_full_spec": read_json("relay-spec.json")?,
        "para_full_spec": read_json("para-spec.json")?,
        "relay_spec_light_sync_state": read_json("relay-spec-lightSyncState.json")?,
        "para_spec_light_sync_state": read_json("para-spec-lightSyncState.json")?,
        "smoldot_db_relay": read_json("smoldot-db/relay.json")?,
        "smoldot_db_para": read_json("smoldot-db/para.json")?,
    }))
}

/// Writes a light-sync-state copy of `full_spec_path` to `lss_spec_path`:
/// replaces `genesis.raw` (full state KV pairs, MB-sized) with
/// `genesis.stateRootHash` (single hash) so smoldot can load it without
/// computing the genesis state root from scratch. Smoldot logs an INFO line
/// suggesting this exact optimization. Substrate nodes still need the full
/// spec.
///
/// The state root is fetched from the genesis header on `node`; matches what
/// smoldot computes internally.
async fn write_light_sync_state_spec(
    node: &NetworkNode,
    full_spec_path: &Path,
    lss_spec_path: &Path,
) -> Result<(), anyhow::Error> {
    let rpc = node.rpc().await?;
    let genesis_hash: Value = rpc
        .request("chain_getBlockHash", rpc_params![0_u32])
        .await
        .map_err(|e| anyhow!("chain_getBlockHash(0) on {} failed: {e}", node.name()))?;
    let genesis_hash_str = genesis_hash
        .as_str()
        .ok_or_else(|| anyhow!("chain_getBlockHash returned non-string"))?;
    let header: Value = rpc
        .request("chain_getHeader", rpc_params![genesis_hash_str])
        .await
        .map_err(|e| anyhow!("chain_getHeader on {} failed: {e}", node.name()))?;
    let state_root = header
        .get("stateRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("chain_getHeader missing stateRoot"))?
        .to_owned();

    let mut spec: Value = serde_json::from_slice(&std::fs::read(full_spec_path)?)?;
    let genesis = spec
        .get_mut("genesis")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("{}: missing genesis object", full_spec_path.display()))?;
    genesis.remove("raw");
    genesis.insert(
        "stateRootHash".to_string(),
        Value::String(state_root.clone()),
    );
    std::fs::write(lss_spec_path, serde_json::to_string_pretty(&spec)?)?;
    log::info!(
        "wrote {} (stateRootHash={state_root}, {} bytes)",
        lss_spec_path.display(),
        std::fs::metadata(lss_spec_path)?.len()
    );
    Ok(())
}

/// Reads `src` as JSON, sets `bootNodes` to `[]`, and writes the result to
/// `dst`. The committed artifact must be port-agnostic (per-spawn ports
/// would invalidate it), so all bootnodes are stripped at generation time
/// and re-injected at consumption time.
fn copy_spec_stripping_bootnodes(src: &Path, dst: &Path) -> Result<(), anyhow::Error> {
    let mut spec: Value = serde_json::from_slice(&std::fs::read(src)?)?;
    if let Some(obj) = spec.as_object_mut() {
        obj.insert("bootNodes".to_string(), Value::Array(Vec::new()));
    }
    std::fs::write(dst, serde_json::to_string_pretty(&spec)?)?;
    Ok(())
}

/// Reads `src` as JSON and writes a copy to `dst` with `bootNodes` set to
/// `multiaddrs`. Used to prepare a runtime spec for smoldot from the
/// committed (port-agnostic) artifact.
fn copy_spec_with_bootnodes(
    src: &Path,
    dst: &Path,
    multiaddrs: &[String],
) -> Result<(), anyhow::Error> {
    let mut spec: Value = serde_json::from_slice(&std::fs::read(src)?)?;
    let array = multiaddrs
        .iter()
        .map(|m| Value::String(m.clone()))
        .collect();
    if let Some(obj) = spec.as_object_mut() {
        obj.insert("bootNodes".to_string(), Value::Array(array));
    }
    std::fs::write(dst, serde_json::to_string_pretty(&spec)?)?;
    Ok(())
}

/// Runs `js/smoke.js` against the live network with the freshly produced
/// specs and `SMOLDOT_DB_DUMP_DIR` set, capturing smoldot's persisted
/// `databaseContent` for both chains. Builds runtime spec copies with
/// current bootnode multiaddrs since the committed artifacts have empty
/// `bootNodes`.
async fn dump_smoldot_db(
    out: &Path,
    network: &Network<LocalFileSystem>,
) -> Result<(), anyhow::Error> {
    log::info!("building smoldot + JS deps for dump");
    ensure_smoldot_built();
    ensure_js_deps_installed();

    let smoldot_db_dir = out.join("smoldot-db");
    std::fs::create_dir_all(&smoldot_db_dir)?;

    let relay_bootnodes: Vec<String> = ["validator-0", "validator-1"]
        .into_iter()
        .map(|n| network.get_node(n).map(|node| node.multiaddr().to_string()))
        .collect::<Result<_, _>>()?;
    let para_bootnodes: Vec<String> = ["alice", "bob"]
        .into_iter()
        .map(|n| network.get_node(n).map(|node| node.multiaddr().to_string()))
        .collect::<Result<_, _>>()?;
    log::info!("relay bootnodes: {relay_bootnodes:?}");
    log::info!("para  bootnodes: {para_bootnodes:?}");

    let relay_runtime_spec = out.join("relay-spec.runtime.json");
    let para_runtime_spec = out.join("para-spec.runtime.json");
    copy_spec_with_bootnodes(
        &out.join("relay-spec.json"),
        &relay_runtime_spec,
        &relay_bootnodes,
    )?;
    copy_spec_with_bootnodes(
        &out.join("para-spec.json"),
        &para_runtime_spec,
        &para_bootnodes,
    )?;

    let relay_spec_str = relay_runtime_spec.to_str().expect("UTF-8 path").to_owned();
    let para_spec_str = para_runtime_spec.to_str().expect("UTF-8 path").to_owned();
    let dump_str = smoldot_db_dir.to_str().expect("UTF-8 path").to_owned();

    log::info!(
        "running smoldot smoke.js to dump databaseContent into {}",
        smoldot_db_dir.display()
    );
    run_js_test(
        "js/smoke.js",
        &[
            ("RELAY_CHAIN_SPEC", relay_spec_str.as_str()),
            ("PARA_CHAIN_SPEC", para_spec_str.as_str()),
            ("REQUIRED_BLOCKS", "5"),
            ("EXPECTED_INITIAL_FINALIZED", "0"),
            ("SMOLDOT_DB_DUMP_DIR", dump_str.as_str()),
        ],
    )
    .await
    .map_err(|e| anyhow!("smoldot dump failed: {e}"))?;

    for name in ["relay.json", "para.json"] {
        let p = smoldot_db_dir.join(name);
        if !p.is_file() {
            return Err(anyhow!("smoldot dump missing {}", p.display()));
        }
        log::info!(
            "dump {} ({} bytes)",
            p.display(),
            std::fs::metadata(&p)?.len()
        );
    }

    // Runtime spec copies were a per-spawn aid; not part of the artifact
    // set. Remove them so the out dir contains only committable files.
    for p in [&relay_runtime_spec, &para_runtime_spec] {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

/// Prints the bundle sha256/size and the `snapshot.rs` constant lines to pin.
/// The bundle is fully self-contained — nothing else to commit.
fn print_manifest(bundle: &Bundle) {
    println!("\n=== artifact manifest ===");
    println!(
        "  {}  {:>10} bytes  {}",
        bundle.path.display(),
        bundle.size,
        bundle.sha256
    );
    println!("\n=== snapshot.rs constants ===");
    println!("pub const ARTIFACTS_VERSION: &str = \"v1\";");
    println!("const BUNDLE_SHA256: &str = \"{}\";", bundle.sha256);
}

async fn wait_for_finalized(node: &NetworkNode, height: u32) -> Result<(), anyhow::Error> {
    let target = height as f64;
    let timeout_secs = (height as u64 * 12).max(120);
    log::info!(
        "waiting for {} finalized to reach #{height} (timeout={timeout_secs}s)",
        node.name()
    );
    node.wait_metric_with_timeout(FINALIZED_METRIC, |h| h >= target, timeout_secs)
        .await
        .map_err(|e| anyhow!("{} did not reach finalized #{height}: {e}", node.name()))?;
    log::info!("{} finalized reached #{height}", node.name());
    Ok(())
}

/// Calls `sync_state_genSyncSpec(true)` on `node` and writes the returned
/// raw chain spec (with `lightSyncState`) to `out_path`.
async fn gen_sync_spec(node: &NetworkNode, out_path: &Path) -> Result<(), anyhow::Error> {
    log::info!(
        "generating sync spec from {} -> {}",
        node.name(),
        out_path.display()
    );
    let rpc = node.rpc().await?;
    let spec: Value = rpc
        .request("sync_state_genSyncSpec", rpc_params![true])
        .await
        .map_err(|e| anyhow!("sync_state_genSyncSpec on {} failed: {e}", node.name()))?;
    if spec.get("lightSyncState").is_none() {
        return Err(anyhow!(
            "spec from {} has no lightSyncState field",
            node.name()
        ));
    }
    std::fs::write(out_path, serde_json::to_string_pretty(&spec)?)?;
    let size = std::fs::metadata(out_path)?.len();
    log::info!("wrote {} ({} bytes)", out_path.display(), size);
    Ok(())
}

struct Args {
    out: PathBuf,
    target_finalized: u32,
    spec_at_finalized: u32,
    relay_db_snapshot: Option<PathBuf>,
    para_db_snapshot: Option<PathBuf>,
}

impl Args {
    fn from_env() -> Result<Self, anyhow::Error> {
        let out = std::env::var("SMOKE_SNAPSHOT_OUT")
            .map(PathBuf::from)
            .map_err(|_| anyhow!("SMOKE_SNAPSHOT_OUT is required (output directory)"))?;

        let target_finalized =
            parse_env_u32("SMOKE_SNAPSHOT_TARGET_FINALIZED")?.unwrap_or(DEFAULT_TARGET_FINALIZED);
        let spec_at_finalized =
            parse_env_u32("SMOKE_SNAPSHOT_SPEC_AT_FINALIZED")?.unwrap_or(target_finalized / 2);
        if spec_at_finalized > target_finalized {
            return Err(anyhow!(
                "SMOKE_SNAPSHOT_SPEC_AT_FINALIZED (#{spec_at_finalized}) must be ≤ \
                 SMOKE_SNAPSHOT_TARGET_FINALIZED (#{target_finalized})"
            ));
        }
        let gap = target_finalized.saturating_sub(spec_at_finalized);
        if gap > 0 && gap < WARP_SYNC_MINIMUM_GAP {
            log::warn!(
                "spec→target gap = {gap} < smoldot's warp_sync_minimum_gap ({WARP_SYNC_MINIMUM_GAP}); \
                 smoldot will use follow-forward and may stall on GRANDPA rotations"
            );
        }

        let relay_db_snapshot = std::env::var("SMOKE_SNAPSHOT_RELAY_DB")
            .ok()
            .map(PathBuf::from);
        let para_db_snapshot = std::env::var("SMOKE_SNAPSHOT_PARA_DB")
            .ok()
            .map(PathBuf::from);

        Ok(Self {
            out,
            target_finalized,
            spec_at_finalized,
            relay_db_snapshot,
            para_db_snapshot,
        })
    }
}

fn parse_env_u32(key: &str) -> Result<Option<u32>, anyhow::Error> {
    match std::env::var(key) {
        Ok(v) => {
            Ok(Some(v.parse().map_err(|e| {
                anyhow!("{key} must be a positive integer: {e}")
            })?))
        }
        Err(_) => Ok(None),
    }
}

fn build_config(
    base_dir_str: &str,
    relay_db: Option<&Path>,
    para_db: Option<&Path>,
) -> Result<NetworkConfig, anyhow::Error> {
    let images = zombienet_sdk::environment::get_images_from_env();
    let relay_db = relay_db.map(Path::to_path_buf);
    let para_db = para_db.map(Path::to_path_buf);
    NetworkConfigBuilder::new()
        .with_relaychain(|r| {
            // Bake elastic-scaling cores + validator set into genesis so the
            // snapshot can back multiple cores. Regenerate from genesis only:
            // changing genesis config changes the hash, mismatching an old DB.
            let r = r
                .with_chain("westend-local")
                .with_default_command("polkadot")
                .with_default_image(images.polkadot.as_str())
                .with_genesis_overrides(elastic_scaling_genesis_overrides())
                .with_optional_default_db_snapshot(relay_db.clone())
                // validator-0 outside the fold sets the typestate the fold builds on.
                .with_validator(|n| n.with_name("validator-0").bootnode(true));
            (1..ELASTIC_VALIDATOR_COUNT).fold(r, |acc, i| {
                acc.with_validator(|n| n.with_name(&format!("validator-{i}")).bootnode(true))
            })
        })
        .with_parachain(|p| {
            p.with_id(PARA_ID)
                .with_default_command("polkadot-parachain")
                .with_default_image(images.cumulus.as_str())
                .with_chain("people-westend-local")
                .with_default_args(vec![
                    "--force-authoring".into(),
                    "--authoring=slot-based".into(),
                ])
                .with_optional_default_db_snapshot(para_db.clone())
                .with_collator(|n| n.with_name("alice").bootnode(true))
                .with_collator(|n| n.with_name("bob").bootnode(true))
        })
        .with_global_settings(|g| {
            g.with_base_dir(base_dir_str).with_spawn_concurrency(1) // https://github.com/paritytech/smoldot/pull/3249#issuecomment-4438807458
        })
        .build()
        .map_err(|errs| {
            anyhow!(
                "config errors: {}",
                errs.into_iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}
