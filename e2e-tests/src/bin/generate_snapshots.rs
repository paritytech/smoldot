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
//! dumps). Run manually; never invoked from `cargo test`.
//!
//! See `e2e-tests/docs/smoke-scenarios.md` for the produced layout and
//! the regeneration procedure.

use std::path::{Path, PathBuf};

use anyhow::anyhow;
use serde_json::Value;
use smoldot_e2e_tests::{
    ensure_js_deps_installed, ensure_smoldot_built, resolve_base_dir, run_js_test,
    FINALIZED_METRIC, PARA_ID,
};
use zombienet_sdk::{
    subxt::ext::subxt_rpcs::rpc_params, LocalFileSystem, Network, NetworkConfig,
    NetworkConfigBuilder, NetworkNode,
};

const DEFAULT_TARGET_FINALIZED: u32 = 100;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let args = Args::parse()?;
    log::info!(
        "generate_snapshots: out={} target_finalized=#{}",
        args.out.display(),
        args.target_finalized
    );

    std::fs::create_dir_all(&args.out)?;
    let base_dir = resolve_base_dir()?;
    let base_dir_str = base_dir.to_str().expect("UTF-8 path").to_owned();

    let config = build_config(&base_dir_str)?;

    log::info!("spawning zombienet network");
    let spawn_fn = zombienet_sdk::environment::get_spawn_fn();
    let network = spawn_fn(config).await?;

    network.wait_until_is_up(120).await?;
    log::info!("network is up");

    let validator = network.get_node("validator-0")?;
    let target = args.target_finalized as f64;
    let timeout_secs = (args.target_finalized as u64 * 12).max(120);
    log::info!(
        "waiting for relay finalized to reach #{} (timeout={timeout_secs}s)",
        args.target_finalized
    );
    validator
        .wait_metric_with_timeout(FINALIZED_METRIC, |h| h >= target, timeout_secs)
        .await
        .map_err(|e| {
            anyhow!(
                "relay did not reach target finalized #{}: {e}",
                args.target_finalized
            )
        })?;
    log::info!("relay finalized reached #{}", args.target_finalized);

    let network_base = PathBuf::from(
        network
            .base_dir()
            .ok_or_else(|| anyhow!("no network base_dir"))?,
    );

    pause_and_tar(
        &network,
        "validator-0",
        &network_base,
        &args.out.join("relaychain-db.tgz"),
    )
    .await?;
    pause_and_tar(
        &network,
        "alice",
        &network_base,
        &args.out.join("parachain-db.tgz"),
    )
    .await?;

    gen_sync_spec(
        network.get_node("validator-0")?,
        &args.out.join("relay-spec.json"),
    )
    .await?;
    // Cumulus parachains don't expose `sync_state_genSyncSpec` — there's no
    // independent finality on a parachain, so there's no `lightSyncState`
    // to bake. Smoldot's cold/warm path for the parachain is automatic
    // given the relay's `lightSyncState`. Copy the zombienet-emitted raw
    // spec verbatim.
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

    dump_smoldot_db(&args.out, &network).await?;

    print_manifest(&args.out)?;
    log::info!("done");
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
            ("FINALIZED_FLOOR", "0"),
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

/// Computes a manifest of the artifact files (sha256 + size) and prints
/// suggested constant lines for `e2e-tests/src/snapshot.rs`. Uses
/// `sha256sum` from coreutils.
fn print_manifest(out: &Path) -> Result<(), anyhow::Error> {
    let entries = [
        ("relaychain-db.tgz", "RELAY_DB_SHA256"),
        ("parachain-db.tgz", "PARA_DB_SHA256"),
        ("relay-spec.json", "RELAY_SPEC_SHA256"),
        ("para-spec.json", "PARA_SPEC_SHA256"),
        ("smoldot-db/relay.json", "SMOLDOT_DB_RELAY_SHA256"),
        ("smoldot-db/para.json", "SMOLDOT_DB_PARA_SHA256"),
    ];

    println!("\n=== artifact manifest ===");
    let mut consts = String::new();
    for (rel, const_name) in entries {
        let path = out.join(rel);
        if !path.is_file() {
            return Err(anyhow!("manifest: missing {}", path.display()));
        }
        let size = std::fs::metadata(&path)?.len();
        let hash = sha256_of(&path)?;
        println!("  {rel:30}  {size:>10} bytes  {hash}");
        consts.push_str(&format!("const {const_name}: &str = \"{hash}\";\n"));
    }
    println!("\n=== snapshot.rs constants ===");
    println!("pub const ARTIFACTS_VERSION: &str = \"v1\";");
    println!("{consts}");
    Ok(())
}

fn sha256_of(path: &Path) -> Result<String, anyhow::Error> {
    let output = std::process::Command::new("sha256sum").arg(path).output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "sha256sum failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8(output.stdout)?;
    let hex = stdout
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("empty sha256sum output for {}", path.display()))?;
    Ok(hex.to_string())
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

/// Pauses `node_name`, tars its `data/` dir into `out_tgz`, and resumes it.
/// `network_base` is the zombienet namespace base dir.
async fn pause_and_tar(
    network: &Network<LocalFileSystem>,
    node_name: &str,
    network_base: &Path,
    out_tgz: &Path,
) -> Result<(), anyhow::Error> {
    let node = network.get_node(node_name)?;
    log::info!("pausing {node_name} for snapshot");
    node.pause().await?;

    let node_base = network_base.join(node_name);
    let data_dir = node_base.join("data");
    if !data_dir.is_dir() {
        return Err(anyhow!(
            "{node_name} data dir missing at {}",
            data_dir.display()
        ));
    }
    log::info!("tarring {} -> {}", data_dir.display(), out_tgz.display());
    let status = std::process::Command::new("tar")
        .arg("-czf")
        .arg(out_tgz)
        .arg("-C")
        .arg(&node_base)
        .arg("data")
        .status()?;
    if !status.success() {
        return Err(anyhow!("tar failed for {node_name} (exit {status})"));
    }
    let size = std::fs::metadata(out_tgz)?.len();
    log::info!("wrote {} ({} bytes)", out_tgz.display(), size);

    log::info!("resuming {node_name}");
    node.resume().await?;
    Ok(())
}

struct Args {
    out: PathBuf,
    target_finalized: u32,
}

impl Args {
    fn parse() -> Result<Self, anyhow::Error> {
        let mut out: Option<PathBuf> = None;
        let mut target_finalized: Option<u32> = None;

        let mut iter = std::env::args().skip(1);
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--out" => {
                    let v = iter.next().ok_or_else(|| anyhow!("--out needs a value"))?;
                    out = Some(PathBuf::from(v));
                }
                "--target-finalized" => {
                    let v = iter
                        .next()
                        .ok_or_else(|| anyhow!("--target-finalized needs a value"))?;
                    target_finalized = Some(v.parse().map_err(|e| {
                        anyhow!("--target-finalized must be a positive integer: {e}")
                    })?);
                }
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                other => return Err(anyhow!("unknown argument: {other}")),
            }
        }

        Ok(Self {
            out: out.ok_or_else(|| anyhow!("--out <DIR> is required"))?,
            target_finalized: target_finalized.unwrap_or(DEFAULT_TARGET_FINALIZED),
        })
    }
}

fn print_help() {
    println!(
        "usage: generate_snapshots --out <DIR> [--target-finalized N]\n\
         \n\
         Spawns westend-local + people-westend-local from genesis and waits for\n\
         the relay to reach the target finalized block. Slice A only — produces\n\
         no artifacts yet.\n\
         \n\
         options:\n\
           --out <DIR>             Artifact output directory (created if missing).\n\
           --target-finalized N    Target relay finalized block. Default: {}.",
        DEFAULT_TARGET_FINALIZED
    );
}

fn build_config(base_dir_str: &str) -> Result<NetworkConfig, anyhow::Error> {
    let images = zombienet_sdk::environment::get_images_from_env();
    NetworkConfigBuilder::new()
        .with_relaychain(|r| {
            r.with_chain("westend-local")
                .with_default_command("polkadot")
                .with_default_image(images.polkadot.as_str())
                .with_validator(|n| n.with_name("validator-0").bootnode(true))
                .with_validator(|n| n.with_name("validator-1").bootnode(true))
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
                .with_collator(|n| n.with_name("alice").bootnode(true))
                .with_collator(|n| n.with_name("bob").bootnode(true))
        })
        .with_global_settings(|g| g.with_base_dir(base_dir_str))
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
