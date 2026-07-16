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
//! Cold/warm consume the artifact set produced by `smoke_generate_snapshots`; see
//! `e2e-tests/docs/smoke-scenarios.md` and `crate::snapshot`.

use std::path::{Path, PathBuf};

use anyhow::anyhow;
use serde_json::Value;
use zombienet_sdk::subxt::ext::subxt_rpcs::client::RpcParams;
use zombienet_sdk::{Arg, LocalFileSystem, Network, NetworkConfig, NetworkConfigBuilder};

pub const PARA_ID: u32 = 1004;
pub const PARA_CHAIN: &str = "people-westend-local";

/// UDP port for `name`'s WebRTC listener. `validator-{i}` gets `33000 + i`
/// (any index below ELASTIC_VALIDATOR_COUNT), the fixed names live above that range.
fn webrtc_udp_port(name: &str) -> u16 {
    let mut base_port = 33000;
    if let Some(i) = name
        .strip_prefix("validator-")
        .and_then(|s| s.parse::<u16>().ok())
    {
        if u32::from(i) >= ELASTIC_VALIDATOR_COUNT {
            unreachable!("validator name: {name}, not associated to any udp port")
        }
        return base_port + i;
    }
    base_port += ELASTIC_VALIDATOR_COUNT as u16;
    match name {
        "alice" => base_port,
        "bob" => base_port + 1,
        // Bulletin network collators (src/harness.rs).
        "collator-1" => base_port + 2,
        "collator-2" => base_port + 3,
        _ => unreachable!("name: {name}, not associated to any udp port"),
    }
}

/// Looks up the fixed WebRTC UDP port assigned to `name` and returns the CLI
/// args that make a substrate node listen for WebRTC on it.
pub fn listener_args(name: &str) -> Vec<Arg> {
    let udp_port = webrtc_udp_port(name);
    vec![
        ("--listen-addr", "/ip4/0.0.0.0/tcp/0/ws").into(),
        "--experimental-webrtc".into(),
        (
            "--listen-addr",
            format!("/ip4/127.0.0.1/udp/{udp_port}/webrtc-direct").as_str(),
        )
            .into(),
    ]
}

pub const FINALIZED_METRIC: &str = "block_height{status=\"finalized\"}";
pub const BEST_METRIC: &str = "block_height{status=\"best\"}";

/// Timeout for the fresh-scenario gate that waits for the relay to produce
/// its first finalized block before launching smoldot. Confirms GrandPa is
/// alive; failure here surfaces as a clear gate-failure rather than a
/// downstream smoldot timeout.
const RELAY_FIRST_FINALIZED_TIMEOUT_SECS: u64 = 120;

/// smoldot's warp-sync engages only when its finalized-to-tip gap exceeds this;
/// mirrors `warp_sync_minimum_gap` in `lib/src/sync/all.rs`.
const WARP_SYNC_MINIMUM_GAP: u64 = 32;

/// Core indices assigned to the parachain for elastic scaling.
pub const ELASTIC_SCALING_CORES: &[u32] = &[0, 1, 2];

/// Validators per backing group; `cores × this` = validator-set size to back
/// every core in one relay block.
pub const ELASTIC_MAX_VALIDATORS_PER_CORE: u32 = 2;

/// Relay validators to spawn for elastic scaling, all genesis authorities.
pub const ELASTIC_VALIDATOR_COUNT: u32 =
    ELASTIC_SCALING_CORES.len() as u32 * ELASTIC_MAX_VALIDATORS_PER_CORE;

/// Genesis `scheduler_params` override declaring the cores. Only effective on a
/// generated genesis; a raw spec / DB snapshot has its core count fixed already.
pub fn elastic_scaling_genesis_overrides() -> serde_json::Value {
    serde_json::json!({
        "configuration": {
            "config": {
                "scheduler_params": {
                    "num_cores": ELASTIC_SCALING_CORES.len(),
                    "max_validators_per_core": ELASTIC_MAX_VALIDATORS_PER_CORE
                }
            }
        }
    })
}

pub struct SnapshotPaths {
    /// Relay-validator DB tarballs (all validators, element `i` -> `validator-i`),
    /// so every erasure chunk survives restore.
    pub relay_db_tgz: Vec<PathBuf>,
    pub para_db_tgz: PathBuf,
    /// Full chain spec with `genesis.raw`. Passed to substrate via
    /// `with_chain_spec_path` so node DB extraction matches.
    pub relay_full_spec: PathBuf,
    pub para_full_spec: PathBuf,
    /// Smoldot-dedicated specs (not what substrate loads): `genesis.stateRootHash`
    /// only (no full state) plus the `lightSyncState` checkpoint. Faster init,
    /// smaller artifact than the full spec.
    pub smoldot_relay_spec: PathBuf,
    pub smoldot_para_spec: PathBuf,
}

pub struct SmoldotDbPaths {
    pub relay_db_json: PathBuf,
    pub para_db_json: PathBuf,
}

pub enum Scenario {
    /// Network from genesis, vanilla spec, no smoldot DB.
    Fresh,
    /// Network from snapshot, spec with `lightSyncState`, no smoldot DB.
    Cold(SnapshotPaths),
    /// Network from snapshot, spec with `lightSyncState`, smoldot DB preloaded.
    Warm {
        snapshot: SnapshotPaths,
        smoldot_db: SmoldotDbPaths,
    },
}

impl Scenario {
    fn snapshot(&self) -> Option<&SnapshotPaths> {
        match self {
            Scenario::Fresh => None,
            Scenario::Cold(s) | Scenario::Warm { snapshot: s, .. } => Some(s),
        }
    }

    fn smoldot_db(&self) -> Option<&SmoldotDbPaths> {
        match self {
            Scenario::Warm { smoldot_db, .. } => Some(smoldot_db),
            _ => None,
        }
    }
}

pub struct LiveNetwork {
    pub network: Network<LocalFileSystem>,
    pub relay_spec: PathBuf,
    pub para_spec: PathBuf,
    /// Lower bound on the finalized block smoldot reports at `chainHead` init:
    /// the live tip if it will warp-sync, else its start head. Fresh: 0.
    pub expected_initial_finalized: u64,
}

/// Spawns the network described by `cfg` and returns the artifacts smoldot
/// needs (spec paths, expected initial finalized). Builds smoldot + JS deps
/// in parallel with node startup so the test is ready to drive smoldot as
/// soon as the network is up.
pub async fn spawn_scenario(
    cfg: &Scenario,
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

    if matches!(cfg, Scenario::Fresh) {
        wait_for_relay_finalized(&network).await?;
        assign_elastic_cores(&network).await?;
    }

    // If fresh then vanilla spec from zombienet is used
    // otherwise the committed light-sync-state specs.
    // In both cases we overwrite bootNodes with the
    // running nodes current multiaddrs, TCP and WebRTC.
    let (relay_base, para_base) = match cfg.snapshot() {
        None => spawned_chain_spec_paths(&network)?,
        Some(s) => (s.smoldot_relay_spec.clone(), s.smoldot_para_spec.clone()),
    };
    let (relay_spec, para_spec) =
        prepare_runtime_specs(&network, &relay_base, &para_base, base_dir_str).await?;

    // Floor for the finalized block smoldot reports at `chainHead` init. It
    // starts from its DB head (warm) or the spec's `lightSyncState` (cold), then
    // either warp-syncs to ~tip (gap > WARP_SYNC_MINIMUM_GAP) or commits
    // AllForksOnly and reports `start` (gap at-or-below it). Mirror that choice.
    // Reading the tip here, its lowest point, keeps the floor safe under either
    // outcome: smoldot warps to at-or-past it, and AllForksOnly reports `start`.
    let expected_initial_finalized = match cfg.snapshot() {
        None => 0,
        Some(snapshot) => {
            let start = match cfg.smoldot_db() {
                Some(db) => parse_finalized_height_from_db(&db.relay_db_json)?,
                None => parse_finalized_height_from_spec(&snapshot.smoldot_relay_spec)?,
            };
            let tip = wait_for_relay_finalized(&network).await?;
            if tip.saturating_sub(start) > WARP_SYNC_MINIMUM_GAP {
                tip
            } else {
                start
            }
        }
    };

    Ok(LiveNetwork {
        network,
        relay_spec,
        para_spec,
        expected_initial_finalized,
    })
}

fn build_network_config(
    cfg: &Scenario,
    base_dir_str: &str,
) -> Result<NetworkConfig, anyhow::Error> {
    let images = zombienet_sdk::environment::get_images_from_env();

    let snap = cfg.snapshot();
    let relay_dbs = snap.map(|s| s.relay_db_tgz.clone()).unwrap_or_default();
    let para_db = snap.map(|s| s.para_db_tgz.clone());
    // Substrate gets the *full* spec — it needs `genesis.raw` to bootstrap.
    let relay_spec_path = snap.map(|s| s.relay_full_spec.to_str().expect("UTF-8 path").to_owned());
    let para_spec_path = snap.map(|s| s.para_full_spec.to_str().expect("UTF-8 path").to_owned());

    let builder = NetworkConfigBuilder::new()
        .with_relaychain(|r| {
            let r = r
                .with_chain("westend-local")
                .with_default_command("polkadot")
                .with_default_image(images.polkadot.as_str());
            let r = match relay_spec_path.as_deref() {
                // Only effective on Fresh's generated genesis; snapshots bring their own.
                None => r.with_genesis_overrides(elastic_scaling_genesis_overrides()),
                Some(p) => r.with_chain_spec_path(p),
            }
            // Per-node DB, element i onto validator-i; empty on Fresh.
            // validator-0 outside the fold sets the typestate.
            .with_validator(|n| {
                n.with_name("validator-0")
                    .bootnode(true)
                    .with_args(listener_args("validator-0"))
                    .with_optional_db_snapshot(relay_dbs.first().cloned())
            });
            (1..ELASTIC_VALIDATOR_COUNT).fold(r, |acc, i| {
                let db = relay_dbs.get(i as usize).cloned();
                acc.with_validator(|n| {
                    n.with_name(&format!("validator-{i}"))
                        .bootnode(true)
                        .with_args(listener_args(&format!("validator-{i}")))
                        .with_optional_db_snapshot(db)
                })
            })
        })
        .with_parachain(|p| {
            let p = p
                .with_id(PARA_ID)
                .with_default_command("polkadot-parachain")
                .with_default_image(images.cumulus.as_str())
                .with_chain(PARA_CHAIN)
                .with_default_args(vec![
                    "--force-authoring".into(),
                    "--authoring=slot-based".into(),
                ])
                .with_optional_default_db_snapshot(para_db.clone());
            let p = match para_spec_path.as_deref() {
                None => p,
                Some(path) => p.with_chain_spec_path(path),
            };
            p.with_collator(|n| {
                // Node-level `with_args` replaces the parachain `default_args`,
                // so the two default flags must be repeated here.
                let mut args = vec!["--force-authoring".into(), "--authoring=slot-based".into()];
                args.extend(listener_args("alice"));
                n.with_name("alice").bootnode(true).with_args(args)
            })
            .with_collator(|n| {
                let mut args = vec!["--force-authoring".into(), "--authoring=slot-based".into()];
                args.extend(listener_args("bob"));
                n.with_name("bob").bootnode(true).with_args(args)
            })
        })
        .with_global_settings(|g| {
            g.with_base_dir(base_dir_str).with_spawn_concurrency(1) // https://github.com/paritytech/smoldot/pull/3249#issuecomment-4438807458
        });

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

/// Waits until the relay validator reports a finalized block and returns its
/// height. For snapshot scenarios this is the restored target head; for fresh
/// it is the first block finalized after genesis.
async fn wait_for_relay_finalized(
    network: &Network<LocalFileSystem>,
) -> Result<u64, anyhow::Error> {
    let validator = network.get_node("validator-0")?;
    log::info!("waiting for relay to report a finalized block");
    validator
        .wait_metric_with_timeout(
            FINALIZED_METRIC,
            |h| h >= 1.0,
            RELAY_FIRST_FINALIZED_TIMEOUT_SECS,
        )
        .await
        .map_err(|e| anyhow!("relay did not finalize any block: {e}"))?;
    let finalized = validator.reports(FINALIZED_METRIC).await? as u64;
    log::info!("relay finalized #{finalized}");
    Ok(finalized)
}

/// Assigns [`ELASTIC_SCALING_CORES`] to the parachain at runtime via
/// `Sudo(Coretime::assign_core)`, mirroring polkadot-sdk's elastic-scaling
/// zombienet tests. Runtime assignment (rather than the genesis
/// `with_num_cores` path) is what people-westend's relay runtime actually
/// honours, and it avoids mutating genesis.
async fn assign_elastic_cores(network: &Network<LocalFileSystem>) -> Result<(), anyhow::Error> {
    use zombienet_sdk::subxt::{ext::scale_value::value, OnlineClient, PolkadotConfig};

    let relay = network.get_node("validator-0")?;
    let client: OnlineClient<PolkadotConfig> = relay.wait_client().await?;

    let assign_calls: Vec<_> = ELASTIC_SCALING_CORES
        .iter()
        .map(|core| {
            value! {
                Coretime(assign_core { core: *core, begin: 0, assignment: ((Task(PARA_ID), 57600)), end_hint: None() })
            }
        })
        .collect();
    let tx = zombienet_sdk::subxt::tx::dynamic(
        "Sudo",
        "sudo",
        vec![value! { Utility(batch { calls: assign_calls }) }],
    );

    log::info!("assigning cores {ELASTIC_SCALING_CORES:?} to para {PARA_ID}");
    let signer = zombienet_sdk::subxt_signer::sr25519::dev::alice();
    client
        .tx()
        .sign_and_submit_then_watch_default(&tx, &signer)
        .await?
        .wait_for_finalized_success()
        .await?;
    log::info!("cores assigned to para {PARA_ID}");
    Ok(())
}

/// Reads the relay and para specs, overwrites their `bootNodes`
/// with the running nodes' current multiaddrs (TCP + WebRTC)
pub async fn prepare_runtime_specs(
    network: &Network<LocalFileSystem>,
    relay_base: &Path,
    para_base: &Path,
    base_dir_str: &str,
) -> Result<(PathBuf, PathBuf), anyhow::Error> {
    let relay_runtime = prepare_runtime_spec(
        network,
        relay_base,
        &["validator-0", "validator-1"],
        base_dir_str,
        "relay-spec.json",
    )
    .await?;
    let para_runtime = prepare_runtime_spec(
        network,
        para_base,
        &["alice", "bob"],
        base_dir_str,
        "para-spec.json",
    )
    .await?;
    Ok((relay_runtime, para_runtime))
}

/// Writes a copy of `base_spec` to `{base_dir}/smoldot-runtime-specs/{out_name}`
/// whose `bootNodes` are the current dialable multiaddrs (TCP + WebRTC) of the
/// named nodes. This is the generic way to hand a live network's chain spec to
/// smoldot so that both hosts can connect (Node over TCP, browser over WebRTC).
pub async fn prepare_runtime_spec(
    network: &Network<LocalFileSystem>,
    base_spec: &Path,
    bootnode_names: &[&str],
    base_dir_str: &str,
    out_name: &str,
) -> Result<PathBuf, anyhow::Error> {
    let runtime_dir = PathBuf::from(base_dir_str).join("smoldot-runtime-specs");
    std::fs::create_dir_all(&runtime_dir)?;
    let multiaddrs = collect_bootnode_multiaddrs(network, bootnode_names).await?;
    let out = runtime_dir.join(out_name);
    write_spec_with_bootnodes(base_spec, &out, &multiaddrs)?;
    log::info!(
        "prepared runtime spec {} (bootnodes: {multiaddrs:?})",
        out.display()
    );
    Ok(out)
}

/// For each named node, returns its dialable multiaddrs to seed `bootNodes`.
async fn collect_bootnode_multiaddrs(
    network: &Network<LocalFileSystem>,
    names: &[&str],
) -> Result<Vec<String>, anyhow::Error> {
    let mut out: Vec<String> = Vec::new();
    for name in names {
        let node = network.get_node(*name)?;
        let rpc = node.rpc().await?;
        let mut listen_addrs: Vec<String> = rpc
            .request::<Vec<String>>("system_localListenAddresses", RpcParams::new())
            .await
            .map_err(|e| anyhow!("{name}: system_localListenAddresses failed: {e}"))?
            .into_iter()
            // Keep only loopback addresses.
            .filter(|addr| addr.contains("/ip4/127.0.0.1/"))
            .collect();
        // Sanitize multiaddrs: system_localListenAddresses currently appends an
        // extra /p2p/<peer_id> even when one is already present.
        for addr in listen_addrs.iter_mut() {
            if addr.matches("/p2p/").count() == 2 {
                if let Some(idx) = addr.rfind("/p2p/") {
                    addr.truncate(idx);
                }
            }
        }

        let has_tcp = listen_addrs.iter().any(|a| a.contains("/tcp/"));
        let has_webrtc = listen_addrs.iter().any(|a| a.contains("/webrtc"));
        if !has_tcp || !has_webrtc {
            return Err(anyhow!(
                "{name}: missing TCP or WebRTC listen address (got {listen_addrs:?})"
            ));
        }

        out.extend(listen_addrs);
    }
    Ok(out)
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

/// Returns the relay & parachain chain-spec files zombienet emits under
/// `network.base_dir()` after spawn. Both already include the bootnodes —
/// no patching required.
pub fn spawned_chain_spec_paths(
    network: &Network<LocalFileSystem>,
) -> Result<(PathBuf, PathBuf), anyhow::Error> {
    let zombienet_base = PathBuf::from(
        network
            .base_dir()
            .ok_or_else(|| anyhow!("network has no base_dir"))?,
    );
    let relay_spec = zombienet_base.join(format!("{}.json", network.relaychain().chain()));
    // zombienet_sdk::Parachain does not expose chain() getter, so we use const here
    let para_spec = zombienet_base.join(format!("{PARA_CHAIN}.json"));

    log::info!(
        "Resolved chain-spec paths: relay={}, para={}",
        relay_spec.display(),
        para_spec.display()
    );
    Ok((relay_spec, para_spec))
}

/// `BlockNumber` width on the substrate chains used here (westend, people-westend).
const BLOCK_NUMBER_BYTES: usize = 4;

/// Finalized head smoldot starts a warm resume from (its persisted DB head).
fn parse_finalized_height_from_db(path: &Path) -> Result<u64, anyhow::Error> {
    let db: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let header_hex = db
        .pointer("/chain/finalized_block_header")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{}: missing chain.finalized_block_header", path.display()))?;
    decode_header_number(header_hex).map_err(|e| anyhow!("{}: {e}", path.display()))
}

/// Finalized head smoldot starts a cold sync from (the spec's `lightSyncState`).
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

/// Decodes a hex SCALE-encoded substrate header and returns its block number.
/// Accepts either a `0x`-prefixed string (chain spec lightSyncState format) or
/// raw hex (smoldot databaseContent format). Uses smoldot's own header decoder.
fn decode_header_number(hex_str: &str) -> Result<u64, anyhow::Error> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped).map_err(|e| anyhow!("invalid hex: {e}"))?;
    let header = smoldot::header::decode(&bytes, BLOCK_NUMBER_BYTES)
        .map_err(|e| anyhow!("smoldot header decode: {e}"))?;
    Ok(header.number)
}

/// Chain the JS driver subscribes `chainHead_v1_follow` to. Selected by whether
/// `PARA_CHAIN_SPEC` is passed: omitting it makes the JS run relay-only.
pub enum FollowChain {
    Relay,
    Para,
}

/// Runs the shared `chainhead_v1_follow` body against a live network on both
/// hosts in sequence: the Node host over TCP, then the browser host over
/// WebRTC. Snapshots the relay and para best/finalized heights from the
/// validator/collator metrics immediately before launching each host, so the
/// validator can flag an initialized finalized that lags too far behind the
/// live network.
pub async fn run_chainhead_v1_follow(
    live: &LiveNetwork,
    cfg: &Scenario,
    with_runtime: bool,
    follow: FollowChain,
) -> Result<(), anyhow::Error> {
    let relay_spec_str = live.relay_spec.to_str().expect("UTF-8 path");
    let para_spec_str = live.para_spec.to_str().expect("UTF-8 path");

    let smoldot_db_paths = cfg.smoldot_db().map(|db| {
        (
            db.relay_db_json.to_str().expect("UTF-8 path").to_owned(),
            db.para_db_json.to_str().expect("UTF-8 path").to_owned(),
        )
    });

    crate::ensure_js_deps_installed();
    crate::ensure_browser_deps_installed();

    let with_runtime_str = if with_runtime { "true" } else { "false" };
    let followed = match follow {
        FollowChain::Relay => "relay",
        FollowChain::Para => "para",
    };

    // NOTE: temporarily disable tests exec within browser.
    for host in [crate::Host::Node /* crate::Host::Browser */] {
        // Re-sample the live heights per host: the network keeps advancing
        // while the previous host runs, and the validator compares smoldot's
        // initial finalized against these values for the lag-regression check.
        let relay_node = live.network.get_node("validator-0")?;
        let relay_best = relay_node.reports(BEST_METRIC).await? as u64;
        let relay_finalized = relay_node.reports(FINALIZED_METRIC).await? as u64;
        let para_node = live.network.get_node("alice")?;
        let para_best = para_node.reports(BEST_METRIC).await? as u64;
        let para_finalized = para_node.reports(FINALIZED_METRIC).await? as u64;
        let relay_best_str = relay_best.to_string();
        let relay_finalized_str = relay_finalized.to_string();
        let para_best_str = para_best.to_string();
        let para_finalized_str = para_finalized.to_string();

        let mut env_vars: Vec<(&str, &str)> = vec![
            ("RELAY_CHAIN_SPEC", relay_spec_str),
            ("RELAY_BEST_AT_LAUNCH", relay_best_str.as_str()),
            ("RELAY_FINALIZED_AT_LAUNCH", relay_finalized_str.as_str()),
            ("PARA_BEST_AT_LAUNCH", para_best_str.as_str()),
            ("PARA_FINALIZED_AT_LAUNCH", para_finalized_str.as_str()),
            ("WITH_RUNTIME", with_runtime_str),
        ];
        // The JS subscribes to the para chain iff PARA_CHAIN_SPEC is set;
        // omitting it runs relay-only.
        if matches!(follow, FollowChain::Para) {
            env_vars.push(("PARA_CHAIN_SPEC", para_spec_str));
        }
        if let Some((relay_db, para_db)) = smoldot_db_paths.as_ref() {
            env_vars.push(("SMOLDOT_DB_RELAY", relay_db.as_str()));
            env_vars.push(("SMOLDOT_DB_PARA", para_db.as_str()));
        }

        log::info!(
            "running chainHead_v1_follow on {host:?} host (follow={followed}, with_runtime={with_runtime}, relay best/finalized=#{relay_best}/#{relay_finalized}, para best/finalized=#{para_best}/#{para_finalized})"
        );
        crate::run_shared_test(host, "chainhead_v1_follow", &env_vars)
            .await
            .map_err(|e| anyhow!("chainhead_v1_follow failed on {host:?} host: {e}"))?;
    }
    Ok(())
}

/// Runs the shared `smoke` body against a single live network on both hosts in
/// sequence: the Node host over TCP, then the Browser host in headless Chrome
/// with `forbidTcp` (→ WebRTC). Both hosts execute the same `shared/smoke.js`
/// and load the same chain spec — its `bootNodes` are expected to carry both
/// TCP and WebRTC multiaddrs.
pub async fn run_smoke(
    live: &LiveNetwork,
    cfg: &Scenario,
    required_blocks: u32,
) -> Result<(), anyhow::Error> {
    let relay_spec_str = live.relay_spec.to_str().expect("UTF-8 path");
    let para_spec_str = live.para_spec.to_str().expect("UTF-8 path");
    let required = required_blocks.to_string();
    let expected_finalized = live.expected_initial_finalized.to_string();

    let smoldot_db_paths = cfg.smoldot_db().map(|db| {
        (
            db.relay_db_json.to_str().expect("UTF-8 path").to_owned(),
            db.para_db_json.to_str().expect("UTF-8 path").to_owned(),
        )
    });

    let mut env_vars: Vec<(&str, &str)> = vec![
        ("RELAY_CHAIN_SPEC", relay_spec_str),
        ("PARA_CHAIN_SPEC", para_spec_str),
        ("REQUIRED_BLOCKS", required.as_str()),
        ("EXPECTED_INITIAL_FINALIZED", expected_finalized.as_str()),
    ];
    if let Some((relay_db, para_db)) = smoldot_db_paths.as_ref() {
        env_vars.push(("SMOLDOT_DB_RELAY", relay_db.as_str()));
        env_vars.push(("SMOLDOT_DB_PARA", para_db.as_str()));
    }

    log::info!(
        "running smoldot smoke test (relay_spec={}, para_spec={}, required_blocks={}, expected_initial_finalized={})",
        relay_spec_str,
        para_spec_str,
        required_blocks,
        expected_finalized
    );

    // Node host (TCP).
    crate::ensure_js_deps_installed();
    crate::run_shared_test(crate::Host::Node, "smoke", &env_vars)
        .await
        .map_err(|e| anyhow!("node smoke test failed: {e}"))?;

    // Browser host (WebRTC).
    crate::ensure_browser_deps_installed();
    crate::run_shared_test(crate::Host::Browser, "smoke", &env_vars)
        .await
        .map_err(|e| anyhow!("browser smoke test failed: {e}"))?;

    Ok(())
}
