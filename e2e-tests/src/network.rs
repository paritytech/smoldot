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

//! Smoke-test scenario plumbing.
//!
//! Three scenarios share this module:
//! - **Fresh**: network from genesis, vanilla spec, no smoldot DB.
//! - **Cold**: network from snapshot, spec with `lightSyncState`, no smoldot DB.
//! - **Warm**: network from snapshot, spec with `lightSyncState`, smoldot DB preloaded.
//!
//! Cold/warm consume the artifact set produced by `generate_snapshots`; see
//! `e2e-tests/docs/smoke-scenarios.md` and `crate::snapshot`.

use std::path::{Path, PathBuf};

use anyhow::anyhow;
use serde_json::Value;
use zombienet_sdk::{LocalFileSystem, Network, NetworkConfig, NetworkConfigBuilder};

/// `BlockNumber` width on substrate-based chains used here (westend, people-westend).
const BLOCK_NUMBER_BYTES: usize = 4;

pub const PARA_ID: u32 = 1004;
pub const FINALIZED_METRIC: &str = "block_height{status=\"finalized\"}";
pub const BEST_METRIC: &str = "block_height{status=\"best\"}";

/// Timeout for the fresh-scenario gate that waits for the relay to produce
/// its first finalized block before launching smoldot. Confirms GrandPa is
/// alive; failure here surfaces as a clear gate-failure rather than a
/// downstream smoldot timeout.
const RELAY_FIRST_FINALIZED_TIMEOUT_SECS: u64 = 120;

pub enum StartMode {
    Fresh,
    FromSnapshot {
        relay_db_tgz: PathBuf,
        para_db_tgz: PathBuf,
    },
}

pub enum SpecMode {
    Vanilla,
    WithLightSyncState { relay: PathBuf, para: PathBuf },
}

pub enum SmoldotState {
    None,
    FromDb {
        relay_db_json: PathBuf,
        para_db_json: PathBuf,
    },
}

pub struct ScenarioConfig {
    pub start: StartMode,
    pub spec: SpecMode,
    pub smoldot: SmoldotState,
}

impl ScenarioConfig {
    pub fn fresh() -> Self {
        Self {
            start: StartMode::Fresh,
            spec: SpecMode::Vanilla,
            smoldot: SmoldotState::None,
        }
    }
}

pub struct LiveNetwork {
    pub network: Network<LocalFileSystem>,
    pub relay_spec: PathBuf,
    pub para_spec: PathBuf,
    /// Floor that smoldot's first reported finalized block must clear.
    /// Fresh: 0. Cold: from `lightSyncState`. Warm: max(cold, persisted DB).
    pub finalized_floor: u64,
}

/// Spawns the network described by `cfg` and returns the artifacts smoldot
/// needs (spec paths, finalized floor). Builds smoldot + JS deps in parallel
/// with node startup so the test is ready to drive smoldot as soon as the
/// network is up.
pub async fn spawn_scenario(
    cfg: &ScenarioConfig,
    base_dir_str: &str,
) -> Result<LiveNetwork, anyhow::Error> {
    let config = build_network_config(cfg, base_dir_str)?;

    log::info!("spawning zombienet network");
    let spawn_fn = zombienet_sdk::environment::get_spawn_fn();
    let network = spawn_fn(config).await?;
    network.detach().await;

    log::info!("building smoldot + installing JS deps");
    crate::ensure_smoldot_built();
    crate::ensure_js_deps_installed();

    network.wait_until_is_up(120).await?;
    log::info!("network is up");

    if matches!(cfg.start, StartMode::Fresh) {
        wait_for_relay_first_finalized(&network).await?;
    }

    let (relay_spec, para_spec) = match &cfg.spec {
        SpecMode::Vanilla => extract_emitted_specs(&network)?,
        SpecMode::WithLightSyncState { relay, para } => {
            // Committed artifacts have empty `bootNodes` (they're per-spawn
            // and would invalidate the artifact). Inject current multiaddrs
            // into runtime copies that smoldot will load.
            prepare_runtime_specs(&network, relay, para, base_dir_str)?
        }
    };

    let mut finalized_floor = match &cfg.spec {
        SpecMode::Vanilla => 0,
        SpecMode::WithLightSyncState { relay, .. } => parse_finalized_height_from_spec(relay)?,
    };
    if let SmoldotState::FromDb { relay_db_json, .. } = &cfg.smoldot {
        let persisted = parse_finalized_height_from_db(relay_db_json)?;
        finalized_floor = finalized_floor.max(persisted);
    }

    Ok(LiveNetwork {
        network,
        relay_spec,
        para_spec,
        finalized_floor,
    })
}

fn build_network_config(
    cfg: &ScenarioConfig,
    base_dir_str: &str,
) -> Result<NetworkConfig, anyhow::Error> {
    let images = zombienet_sdk::environment::get_images_from_env();

    // Per-node copies of the snapshot tarballs work around a TOCTOU race in
    // zombienet-provider's `with_db_snapshot` cache: sibling nodes sharing one
    // source path corrupt the partially-written file. Each per-node copy gets
    // its own cache slot (sha256 keyed on path string).
    let staged = match &cfg.start {
        StartMode::Fresh => StagedSnapshots::default(),
        StartMode::FromSnapshot {
            relay_db_tgz,
            para_db_tgz,
        } => stage_per_node_snapshots(base_dir_str, relay_db_tgz, para_db_tgz)?,
    };
    let (relay_spec_path, para_spec_path) = match &cfg.spec {
        SpecMode::Vanilla => (None, None),
        SpecMode::WithLightSyncState { relay, para } => (
            Some(relay.to_str().expect("UTF-8 path").to_owned()),
            Some(para.to_str().expect("UTF-8 path").to_owned()),
        ),
    };

    let builder = NetworkConfigBuilder::new()
        .with_relaychain(|r| {
            let r = r
                .with_chain("westend-local")
                .with_default_command("polkadot")
                .with_default_image(images.polkadot.as_str());
            let r = match relay_spec_path.as_deref() {
                None => r,
                Some(p) => r.with_chain_spec_path(p),
            };
            r.with_validator(|n| {
                let n = n.with_name("validator-0").bootnode(true);
                match staged.validator_0.as_deref() {
                    Some(p) => n.with_db_snapshot(p),
                    None => n,
                }
            })
            .with_validator(|n| {
                let n = n.with_name("validator-1").bootnode(true);
                match staged.validator_1.as_deref() {
                    Some(p) => n.with_db_snapshot(p),
                    None => n,
                }
            })
        })
        .with_parachain(|p| {
            let p = p
                .with_id(PARA_ID)
                .with_default_command("polkadot-parachain")
                .with_default_image(images.cumulus.as_str())
                .with_chain("people-westend-local")
                .with_default_args(vec![
                    "--force-authoring".into(),
                    "--authoring=slot-based".into(),
                ]);
            let p = match para_spec_path.as_deref() {
                None => p,
                Some(path) => p.with_chain_spec_path(path),
            };
            p.with_collator(|n| {
                let n = n.with_name("alice").bootnode(true);
                match staged.alice.as_deref() {
                    Some(p) => n.with_db_snapshot(p),
                    None => n,
                }
            })
            .with_collator(|n| {
                let n = n.with_name("bob").bootnode(true);
                match staged.bob.as_deref() {
                    Some(p) => n.with_db_snapshot(p),
                    None => n,
                }
            })
        })
        .with_global_settings(|g| g.with_base_dir(base_dir_str));

    builder.build().map_err(|errs| {
        anyhow!(
            "config errors: {}",
            errs.into_iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

async fn wait_for_relay_first_finalized(
    network: &Network<LocalFileSystem>,
) -> Result<(), anyhow::Error> {
    let validator = network.get_node("validator-0")?;
    log::info!("waiting for relay to produce its first finalized block");
    validator
        .wait_metric_with_timeout(
            FINALIZED_METRIC,
            |h| h >= 1.0,
            RELAY_FIRST_FINALIZED_TIMEOUT_SECS,
        )
        .await
        .map_err(|e| anyhow!("relay did not finalize any block: {e}"))?;
    log::info!("relay produced its first finalized block");
    Ok(())
}

#[derive(Default)]
struct StagedSnapshots {
    validator_0: Option<String>,
    validator_1: Option<String>,
    alice: Option<String>,
    bob: Option<String>,
}

fn stage_per_node_snapshots(
    base_dir_str: &str,
    relay_db: &Path,
    para_db: &Path,
) -> Result<StagedSnapshots, anyhow::Error> {
    let stage_dir = PathBuf::from(base_dir_str).join("staged-snapshots");
    std::fs::create_dir_all(&stage_dir)?;
    let stage = |src: &Path, name: &str| -> Result<String, anyhow::Error> {
        let dst = stage_dir.join(format!("{name}.tgz"));
        std::fs::copy(src, &dst)
            .map_err(|e| anyhow!("copy {} -> {}: {e}", src.display(), dst.display()))?;
        Ok(dst.to_str().expect("UTF-8 path").to_owned())
    };
    Ok(StagedSnapshots {
        validator_0: Some(stage(relay_db, "relay-validator-0")?),
        validator_1: Some(stage(relay_db, "relay-validator-1")?),
        alice: Some(stage(para_db, "para-alice")?),
        bob: Some(stage(para_db, "para-bob")?),
    })
}

/// Reads `committed_relay` / `committed_para` (port-agnostic artifacts with
/// empty `bootNodes`), injects current bootnode multiaddrs, and writes
/// runtime copies under `{base_dir}/smoldot-runtime-specs/`.
fn prepare_runtime_specs(
    network: &Network<LocalFileSystem>,
    committed_relay: &Path,
    committed_para: &Path,
    base_dir_str: &str,
) -> Result<(PathBuf, PathBuf), anyhow::Error> {
    let runtime_dir = PathBuf::from(base_dir_str).join("smoldot-runtime-specs");
    std::fs::create_dir_all(&runtime_dir)?;

    let relay_multi = collect_multiaddrs(network, &["validator-0", "validator-1"])?;
    let para_multi = collect_multiaddrs(network, &["alice", "bob"])?;

    let relay_runtime = runtime_dir.join("relay-spec.json");
    let para_runtime = runtime_dir.join("para-spec.json");
    write_spec_with_bootnodes(committed_relay, &relay_runtime, &relay_multi)?;
    write_spec_with_bootnodes(committed_para, &para_runtime, &para_multi)?;
    log::info!(
        "prepared runtime specs (relay={}, para={})",
        relay_runtime.display(),
        para_runtime.display()
    );
    Ok((relay_runtime, para_runtime))
}

fn collect_multiaddrs(
    network: &Network<LocalFileSystem>,
    names: &[&str],
) -> Result<Vec<String>, anyhow::Error> {
    names
        .iter()
        .map(|n| {
            network
                .get_node(*n)
                .map(|node| node.multiaddr().to_string())
        })
        .collect::<Result<Vec<_>, _>>()
}

fn write_spec_with_bootnodes(
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

fn extract_emitted_specs(
    network: &Network<LocalFileSystem>,
) -> Result<(PathBuf, PathBuf), anyhow::Error> {
    let zombienet_base = PathBuf::from(
        network
            .base_dir()
            .ok_or_else(|| anyhow!("network has no base_dir"))?,
    );
    let relay_spec = zombienet_base.join(format!("{}.json", network.relaychain().chain()));
    let parachain = network
        .parachain(PARA_ID)
        .ok_or_else(|| anyhow!("parachain {PARA_ID} not found"))?;
    let para_spec_name = parachain.chain_id().unwrap_or(parachain.unique_id());
    let para_spec = zombienet_base.join(format!("{para_spec_name}.json"));
    Ok((relay_spec, para_spec))
}

fn parse_finalized_height_from_spec(path: &Path) -> Result<u64, anyhow::Error> {
    let spec: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let header_hex = spec
        .pointer("/lightSyncState/finalizedBlockHeader")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow!(
                "{}: missing lightSyncState.finalizedBlockHeader",
                path.display()
            )
        })?;
    decode_header_number(header_hex).map_err(|e| anyhow!("{}: {e}", path.display()))
}

fn parse_finalized_height_from_db(path: &Path) -> Result<u64, anyhow::Error> {
    let db: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let header_hex = db
        .pointer("/chain/finalized_block_header")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{}: missing chain.finalized_block_header", path.display()))?;
    decode_header_number(header_hex).map_err(|e| anyhow!("{}: {e}", path.display()))
}

/// Decodes a hex SCALE-encoded substrate header and returns its block number.
/// Accepts either a `0x`-prefixed string (chain spec lightSyncState format) or
/// raw hex (smoldot databaseContent format). Uses smoldot's own header
/// decoder.
fn decode_header_number(hex_str: &str) -> Result<u64, anyhow::Error> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped).map_err(|e| anyhow!("invalid hex: {e}"))?;
    let header = smoldot::header::decode(&bytes, BLOCK_NUMBER_BYTES)
        .map_err(|e| anyhow!("smoldot header decode: {e}"))?;
    Ok(header.number)
}

/// Runs `js/smoke.js` against a live network. Env-injects spec paths, the
/// finalized floor, and (warm only) smoldot DB content paths.
pub async fn run_smoke_js(
    live: &LiveNetwork,
    cfg: &ScenarioConfig,
    required_blocks: u32,
) -> Result<(), anyhow::Error> {
    let relay_spec_str = live.relay_spec.to_str().expect("UTF-8 path");
    let para_spec_str = live.para_spec.to_str().expect("UTF-8 path");
    let required = required_blocks.to_string();
    let floor = live.finalized_floor.to_string();

    let smoldot_db_paths = match &cfg.smoldot {
        SmoldotState::None => None,
        SmoldotState::FromDb {
            relay_db_json,
            para_db_json,
        } => Some((
            relay_db_json.to_str().expect("UTF-8 path").to_owned(),
            para_db_json.to_str().expect("UTF-8 path").to_owned(),
        )),
    };

    let mut env_vars: Vec<(&str, &str)> = vec![
        ("RELAY_CHAIN_SPEC", relay_spec_str),
        ("PARA_CHAIN_SPEC", para_spec_str),
        ("REQUIRED_BLOCKS", required.as_str()),
        ("FINALIZED_FLOOR", floor.as_str()),
    ];
    if let Some((relay_db, para_db)) = smoldot_db_paths.as_ref() {
        env_vars.push(("SMOLDOT_DB_RELAY", relay_db.as_str()));
        env_vars.push(("SMOLDOT_DB_PARA", para_db.as_str()));
    }

    log::info!(
        "running smoldot JS smoke test (relay_spec={relay_spec_str}, para_spec={para_spec_str}, required_blocks={required_blocks}, floor={floor})"
    );
    crate::run_js_test("js/smoke.js", &env_vars)
        .await
        .map_err(|e| anyhow!("JS test failed: {e}"))
}
