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
//! Cold/Warm depend on artifacts not yet committed; their branches are stubbed
//! with `todo!()` and will land alongside `tests/smoke_cold.rs` /
//! `tests/smoke_warm.rs`. See `e2e-tests/docs/smoke-scenarios.md`.

use std::path::{Path, PathBuf};

use anyhow::anyhow;
use zombienet_sdk::{LocalFileSystem, Network, NetworkConfig, NetworkConfigBuilder};

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
        SpecMode::WithLightSyncState { relay, para } => (relay.clone(), para.clone()),
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

    let (relay_db_path, para_db_path) = match &cfg.start {
        StartMode::Fresh => (None, None),
        StartMode::FromSnapshot {
            relay_db_tgz,
            para_db_tgz,
        } => (
            Some(relay_db_tgz.to_str().expect("UTF-8 path").to_owned()),
            Some(para_db_tgz.to_str().expect("UTF-8 path").to_owned()),
        ),
    };

    let builder = NetworkConfigBuilder::new()
        .with_relaychain(|r| {
            let r = r
                .with_chain("westend-local")
                .with_default_command("polkadot")
                .with_default_image(images.polkadot.as_str());
            match relay_db_path.as_deref() {
                None => r
                    .with_validator(|n| n.with_name("validator-0").bootnode(true))
                    .with_validator(|n| n.with_name("validator-1").bootnode(true)),
                Some(path) => r
                    .with_validator(|n| {
                        n.with_name("validator-0")
                            .bootnode(true)
                            .with_db_snapshot(path)
                    })
                    .with_validator(|n| {
                        n.with_name("validator-1")
                            .bootnode(true)
                            .with_db_snapshot(path)
                    }),
            }
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
            match para_db_path.as_deref() {
                None => p
                    .with_collator(|n| n.with_name("alice").bootnode(true))
                    .with_collator(|n| n.with_name("bob").bootnode(true)),
                Some(path) => p
                    .with_collator(|n| n.with_name("alice").bootnode(true).with_db_snapshot(path))
                    .with_collator(|n| n.with_name("bob").bootnode(true).with_db_snapshot(path)),
            }
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

fn parse_finalized_height_from_spec(_path: &Path) -> Result<u64, anyhow::Error> {
    todo!("cold/warm scenarios — implemented when artifacts/v1 lands")
}

fn parse_finalized_height_from_db(_path: &Path) -> Result<u64, anyhow::Error> {
    todo!("warm scenario — implemented when artifacts/v1 lands")
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
