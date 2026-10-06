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

//! Scaffolding for the JAM scenarios (`tests/jam_*.rs`): the PolkaJam network
//! on zombienet-sdk's JAM support, node-side facts over the ordinary node's
//! JSON-RPC, fault injection through the SDK's node handles, the aged database
//! snapshot, and the `DEV_MODE` keep-alive.
//!
//! The JAM light client has a browser transport only (WebTransport), so every
//! JAM body runs on the browser host. See `docs/jam-scenarios.md`.

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zombienet_sdk::{
    subxt::ext::jsonrpsee::{core::client::ClientT, rpc_params, ws_client::WsClient},
    LocalFileSystem, Network, NetworkConfig, NetworkConfigBuilder,
};

/// The six validators of the tiny network, in genesis order.
pub const VALIDATORS: [&str; 6] = ["jam0", "jam1", "jam2", "jam3", "jam4", "jam5"];

/// The ordinary node; the only one serving JSON-RPC.
pub const ORDINARY: &str = "jam-or";

/// The PolkaJam commit these scenarios are written against: the head of the
/// fork branch `skunert/polkajam-light-client`. Recorded in the snapshot
/// manifest; nothing checks the binary against it.
pub const POLKAJAM_COMMIT: &str = "3ccb03b7dc5ca54b16de81db7fdf7076de083ad0";

/// `ProtocolParameters::tiny()` slot duration.
pub const SLOT_SECONDS: u64 = 6;

/// Validator p2p ports and the RPC port of the aged network, in that order.
///
/// A JAM validator's address is part of the genesis validator set, so the
/// generated spec only comes out the same on every spawn when the ports are
/// fixed. The aged snapshot is restored onto a new spawn and only fits the
/// genesis it was produced under, hence these. Every other scenario lets
/// zombienet pick free ports.
pub const AGED_PORTS: [u16; 7] = [47210, 47211, 47212, 47213, 47214, 47215, 47216];

/// How long a node gets to exit after `SIGINT` before it is killed. PolkaJam
/// flushes its database only on Ctrl-C; a `SIGKILL`ed node comes back with
/// whatever reached the disk.
pub const NODE_STOP_GRACE: Duration = Duration::from_secs(15);

const RPC_READY_TIMEOUT: Duration = Duration::from_secs(120);
const NODE_START_TIMEOUT: Duration = Duration::from_secs(120);
const WEBTRANSPORT_LINE: &str = "For WebTransport, use";

/// The finality mode every node runs (`--finality-mode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finality {
    /// No finality: the C2 (browser end-to-end test and CI gate) network.
    Dummy,
    /// GRANDPA, as the manual demo and every finality scenario use.
    Grandpa,
}

impl Finality {
    fn arg(self) -> &'static str {
        match self {
            Finality::Dummy => "--finality-mode=dummy",
            Finality::Grandpa => "--finality-mode=grandpa",
        }
    }
}

/// The tiny six-validator plus one ordinary node network.
///
/// `ports` fixes the six validator p2p ports and the RPC port
/// ([`AGED_PORTS`]); without it zombienet picks them. Native nodes get only
/// `TZ`, `LANG` and `PATH` from zombienet, so `POLKAVM_BACKEND` (hosts without
/// the PolkaVM sandbox) and `RUST_LOG` go through each node's env.
pub fn jam_network_config(
    finality: Finality,
    ports: Option<[u16; 7]>,
    base_dir: &Path,
) -> Result<NetworkConfig> {
    let base_dir = base_dir
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 base dir"))?
        .to_string();
    // `JAM_NODE_RUST_LOG` overrides the nodes' log filter, e.g. `info,grandpa=debug`.
    let rust_log = std::env::var("JAM_NODE_RUST_LOG").unwrap_or_else(|_| "info".into());
    let env = || {
        vec![
            ("POLKAVM_BACKEND", "interpreter"),
            ("RUST_LOG", rust_log.as_str()),
        ]
    };
    NetworkConfigBuilder::new()
        .with_jamchain(|jam| {
            let mut jam = jam
                .with_id("dev")
                .with_default_command("polkajam")
                .with_default_args(vec![finality.arg().into()])
                .with_validator(|n| {
                    let n = n.with_name(VALIDATORS[0]).with_env(env());
                    match ports {
                        Some(ports) => n.with_p2p_port(ports[0]),
                        None => n,
                    }
                });
            for (index, name) in VALIDATORS.iter().enumerate().skip(1) {
                jam = jam.with_validator(|n| {
                    let n = n.with_name(*name).with_env(env());
                    match ports {
                        Some(ports) => n.with_p2p_port(ports[index]),
                        None => n,
                    }
                });
            }
            jam.with_ordinary(|n| {
                let n = n.with_name(ORDINARY).with_env(env());
                match ports {
                    Some(ports) => n.with_rpc_port(ports[6]),
                    None => n,
                }
            })
        })
        .with_global_settings(|g| g.with_base_dir(base_dir.as_str()))
        .build()
        .map_err(|e| anyhow!("network config errors: {e:?}"))
}

/// A block as the node's `bestBlock`, `finalizedBlock` and `parent` describe it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockDesc {
    pub hash: [u8; 32],
    pub slot: u32,
}

impl BlockDesc {
    /// `0x`-prefixed hex, the way smoldot reports block hashes.
    pub fn hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.hash))
    }

    fn from_json(value: &Value) -> Result<Self> {
        let text = value["header_hash"]
            .as_str()
            .ok_or_else(|| anyhow!("BlockDesc without header_hash: {value}"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(text)
            .with_context(|| format!("header_hash {text} is not base64"))?;
        let hash = <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| anyhow!("header_hash {text} is not 32 bytes"))?;
        let slot = value["slot"]
            .as_u64()
            .and_then(|slot| u32::try_from(slot).ok())
            .ok_or_else(|| anyhow!("BlockDesc without a u32 slot: {value}"))?;
        Ok(BlockDesc { hash, slot })
    }

    fn base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.hash)
    }
}

/// A running JAM network spawned by [`spawn_jam`].
pub struct LiveJam {
    pub network: Network<LocalFileSystem>,
    pub base_dir: PathBuf,
    pub finality: Finality,
    rpc: WsClient,
}

/// Spawns the network, restoring `snapshot` into the base directory first,
/// and waits until the ordinary node's RPC reports a block past genesis.
///
/// With a snapshot, the regenerated spec must equal the snapshot's: the
/// restored databases only fit that genesis.
pub async fn spawn_jam(
    finality: Finality,
    ports: Option<[u16; 7]>,
    snapshot: Option<&JamSnapshot>,
) -> Result<LiveJam> {
    spawn_jam_at(crate::resolve_base_dir()?, finality, ports, snapshot).await
}

/// [`spawn_jam`] in a given base directory.
pub async fn spawn_jam_at(
    base_dir: PathBuf,
    finality: Finality,
    ports: Option<[u16; 7]>,
    snapshot: Option<&JamSnapshot>,
) -> Result<LiveJam> {
    std::fs::create_dir_all(&base_dir)?;
    if let Some(snapshot) = snapshot {
        snapshot.restore(&base_dir)?;
    }
    let config = jam_network_config(finality, ports, &base_dir)?;
    let started = Instant::now();
    let spawn_fn = zombienet_sdk::environment::get_spawn_fn();
    let network = spawn_fn(config)
        .await
        .map_err(|e| anyhow!("spawning the JAM network failed: {e}"))?;
    log::info!(
        "JAM network ({finality:?}) deployed in {:.2?} at {}",
        started.elapsed(),
        base_dir.display()
    );

    if let Some(snapshot) = snapshot {
        let spec = std::fs::read(base_dir.join("jam_spec.json"))?;
        let actual = spec_sha256(&spec)?;
        if actual != snapshot.manifest.spec_sha256 {
            bail!(
                "zombienet generated a different spec (canonical SHA-256 {actual}) than the \
                 snapshot's ({}); the restored databases do not fit it",
                snapshot.manifest.spec_sha256
            );
        }
        log::info!("regenerated spec equals the snapshot's (canonical SHA-256 {actual})");
    }

    let rpc = network
        .get_jam_node(ORDINARY)?
        .wait_client_with_timeout(60_u64)
        .await
        .context("connecting to the ordinary node's RPC")?;
    let live = LiveJam {
        network,
        base_dir,
        finality,
        rpc,
    };
    let deadline = Instant::now() + RPC_READY_TIMEOUT;
    loop {
        match live.best_block().await {
            Ok(best) if best.slot > 0 => break,
            Ok(_) | Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await
            }
            Ok(best) => bail!("RPC not ready: best block {best:?}"),
            Err(e) => return Err(e.context("RPC not ready")),
        }
    }
    log::info!("JAM network ready in {:.2?}", started.elapsed());
    Ok(live)
}

impl LiveJam {
    /// The spec zombienet generated: six combined bootnodes, P-256 ids in the
    /// genesis `C(8)`. The light client takes it unchanged.
    pub fn spec_path(&self) -> PathBuf {
        self.base_dir.join("jam_spec.json")
    }

    pub fn rpc_port(&self) -> Result<u16> {
        let uri = self.network.get_jam_node(ORDINARY)?.rpc_uri();
        uri.rsplit(':')
            .next()
            .and_then(|port| port.parse().ok())
            .ok_or_else(|| anyhow!("no port in {uri}"))
    }

    /// The ordinary node's JSON-RPC over HTTP, for the bodies (`fetch`).
    pub fn rpc_url(&self) -> Result<String> {
        Ok(format!("http://127.0.0.1:{}", self.rpc_port()?))
    }

    async fn request(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        let mut builder = rpc_params![];
        for param in params {
            builder.insert(param)?;
        }
        self.rpc
            .request(method, builder)
            .await
            .with_context(|| format!("RPC {method}"))
    }

    pub async fn best_block(&self) -> Result<BlockDesc> {
        BlockDesc::from_json(&self.request("bestBlock", vec![]).await?)
    }

    pub async fn finalized_block(&self) -> Result<BlockDesc> {
        BlockDesc::from_json(&self.request("finalizedBlock", vec![]).await?)
    }

    pub async fn parent(&self, block: &BlockDesc) -> Result<BlockDesc> {
        BlockDesc::from_json(
            &self
                .request("parent", vec![Value::String(block.base64())])
                .await?,
        )
    }

    /// `epoch_period` from the node's `parameters`.
    pub async fn epoch_period(&self) -> Result<u32> {
        let params = self.request("parameters", vec![]).await?;
        params["V1"]["epoch_period"]
            .as_u64()
            .and_then(|e| u32::try_from(e).ok())
            .filter(|e| *e > 0)
            .ok_or_else(|| anyhow!("no epoch_period in {params}"))
    }

    /// Walks from `from` to genesis. Returns the number of blocks after
    /// genesis, the slot of the earliest of them, and the number of epoch
    /// changes along the way.
    ///
    /// The GRANDPA set changes once per epoch: the first block of an epoch
    /// carries the epoch mark that names the next set, so the epoch changes on
    /// the finalized chain are the finalized set changes, which is the set id
    /// a client reaches by following the chain (`jam-finalized; set_id=N`).
    pub async fn ancestry(&self, from: BlockDesc) -> Result<Ancestry> {
        let epoch = self.epoch_period().await?;
        let mut blocks = 0u32;
        let mut set_changes = 0u32;
        let mut earliest_slot = from.slot;
        let mut current = from;
        while current.slot > 0 {
            blocks += 1;
            earliest_slot = current.slot;
            let parent = self.parent(&current).await?;
            if parent.slot / epoch != current.slot / epoch {
                set_changes += 1;
            }
            current = parent;
            if blocks > 100_000 {
                bail!("ancestry exceeds the measurement budget");
            }
        }
        Ok(Ancestry {
            blocks,
            earliest_slot,
            set_changes,
        })
    }

    /// Waits until the finalized chain carries at least `set_changes` epoch
    /// changes (finalized GRANDPA set changes), then returns the finalized
    /// block.
    pub async fn wait_for_set_changes(
        &self,
        set_changes: u32,
        timeout: Duration,
    ) -> Result<(BlockDesc, Ancestry)> {
        let deadline = Instant::now() + timeout;
        loop {
            let finalized = self.finalized_block().await?;
            let ancestry = self.ancestry(finalized).await?;
            if ancestry.set_changes >= set_changes {
                return Ok((finalized, ancestry));
            }
            if Instant::now() > deadline {
                bail!(
                    "{set_changes} finalized set changes not reached within {timeout:?} \
                     (finalized slot {}, {} set changes)",
                    finalized.slot,
                    ancestry.set_changes
                );
            }
            log::info!(
                "waiting for {set_changes} finalized set changes: {} so far, finalized slot {}",
                ancestry.set_changes,
                finalized.slot
            );
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    /// Stops a node and leaves it stopped (`SIGINT`, then `SIGKILL` after
    /// [`NODE_STOP_GRACE`]), through zombienet's node handle.
    pub async fn kill_node(&self, name: &str) -> Result<()> {
        let node = self.network.get_jam_node(name)?;
        node.core()
            .kill(Some(NODE_STOP_GRACE))
            .await
            .with_context(|| format!("killing {name}"))?;
        log::info!("{name} killed");
        Ok(())
    }

    /// Starts a node stopped by [`LiveJam::kill_node`] on its own directory
    /// and database, and waits for its WebTransport startup line.
    pub async fn start_node(&self, name: &str) -> Result<()> {
        let node = self.network.get_jam_node(name)?;
        let before = count_lines(&node.core().logs().await?, WEBTRANSPORT_LINE);
        node.core()
            .start()
            .await
            .with_context(|| format!("starting {name}"))?;
        let deadline = Instant::now() + NODE_START_TIMEOUT;
        loop {
            let logs = node.core().logs().await?;
            if count_lines(&logs, WEBTRANSPORT_LINE) > before {
                break;
            }
            if Instant::now() > deadline {
                let tail: Vec<&str> = logs.lines().rev().take(20).collect();
                bail!(
                    "{name} did not restart within {NODE_START_TIMEOUT:?}; log tail:\n{}",
                    tail.into_iter().rev().collect::<Vec<_>>().join("\n")
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        log::info!("{name} started");
        Ok(())
    }

    /// How often the node wrote a genesis block, from its log. One means a
    /// restarted node came back on its own database instead of a fresh one.
    pub async fn genesis_writes(&self, name: &str) -> Result<usize> {
        let logs = self.network.get_jam_node(name)?.core().logs().await?;
        Ok(count_lines(&logs, "Writing genesis block"))
    }

    /// Whether the node was last started after being killed, as zombienet
    /// tracks it.
    pub fn node_running(&self, name: &str) -> Result<bool> {
        Ok(self.network.get_jam_node(name)?.core().is_running())
    }

    /// Stops every node gracefully, in parallel; used before archiving.
    pub async fn kill_all(&self) -> Result<()> {
        tokio::try_join!(
            self.kill_node(VALIDATORS[0]),
            self.kill_node(VALIDATORS[1]),
            self.kill_node(VALIDATORS[2]),
            self.kill_node(VALIDATORS[3]),
            self.kill_node(VALIDATORS[4]),
            self.kill_node(VALIDATORS[5]),
            self.kill_node(ORDINARY),
        )?;
        Ok(())
    }

    /// Tears the network down, checks that no PolkaJam process of this
    /// network survived, and removes the base directory.
    pub async fn teardown(self) -> Result<()> {
        let base_dir = self.base_dir.clone();
        drop(self.rpc);
        self.network
            .destroy()
            .await
            .map_err(|e| anyhow!("destroying the network: {e}"))?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut leftovers = leftover_processes(&base_dir);
        while !leftovers.is_empty() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(200)).await;
            leftovers = leftover_processes(&base_dir);
        }
        if !leftovers.is_empty() {
            bail!(
                "PolkaJam processes survived teardown: {}",
                leftovers.join(" | ")
            );
        }
        std::fs::remove_dir_all(&base_dir)
            .with_context(|| format!("removing {}", base_dir.display()))?;
        log::info!(
            "network torn down, no PolkaJam process left, {} removed",
            base_dir.display()
        );
        Ok(())
    }
}

/// What [`LiveJam::ancestry`] measured.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Ancestry {
    pub blocks: u32,
    pub earliest_slot: u32,
    pub set_changes: u32,
}

fn count_lines(logs: &str, needle: &str) -> usize {
    logs.lines().filter(|line| line.contains(needle)).count()
}

/// PolkaJam processes still running from `base_dir`: a teardown check only,
/// never used to find a node to stop (that goes through the node handles).
fn leftover_processes(base_dir: &Path) -> Vec<String> {
    let Some(needle) = base_dir.to_str() else {
        return vec![];
    };
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return vec![];
    };
    entries
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().parse::<u32>().is_ok())
        .filter_map(|entry| {
            let cmdline = std::fs::read(entry.path().join("cmdline")).ok()?;
            let cmdline = String::from_utf8_lossy(&cmdline).replace('\0', " ");
            let program = cmdline.split(' ').next().unwrap_or_default();
            (program.ends_with("polkajam") && cmdline.contains(needle))
                .then(|| format!("{} {}", entry.file_name().to_string_lossy(), cmdline.trim()))
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// SHA-256 of a spec's JSON with every object's keys sorted and no whitespace.
///
/// `gen-spec` writes `genesis_state` from a hash map, so two runs on the same
/// config write the same spec with its keys in a different order; the hash must
/// not depend on that.
pub fn spec_sha256(spec: &[u8]) -> Result<String> {
    fn canonical(value: &Value, out: &mut String) {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&Value::String(key.clone()).to_string());
                    out.push(':');
                    canonical(&map[key], out);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    canonical(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let value: Value = serde_json::from_slice(spec).context("parsing a chain spec")?;
    let mut out = String::new();
    canonical(&value, &mut out);
    Ok(sha256_hex(out.as_bytes()))
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(sha256_hex(
        &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    ))
}

/// Runs a JAM body on the browser host, after making sure the smoldot bundle
/// and the browser dependencies are in place.
pub async fn run_jam_body(test_name: &str, env: &[(&str, &str)]) -> Result<()> {
    crate::ensure_smoldot_built();
    crate::ensure_browser_deps_installed();
    let mut env = env.to_vec();
    // The JAM assertions read the client's `jam-*` lines, which are debug.
    if !env.iter().any(|(key, _)| *key == "SMOLDOT_LOG_LEVEL") {
        env.push(("SMOLDOT_LOG_LEVEL", "4"));
    }
    crate::run_shared_test(crate::Host::Browser, test_name, &env)
        .await
        .map_err(|e| anyhow!("{test_name} failed: {e}"))
}

/// `DEV_MODE`: prints how to run the body (`Some((test_name, env))`, on the
/// browser host; `None` prints the demo page regression instead) and how to
/// attach the manual demo to this network, then keeps the network alive for
/// `KEEP_ALIVE_SECS` (default 36000) or until Ctrl-C. Returns `false` when
/// `DEV_MODE` is unset.
pub async fn dev_mode_keep_alive(
    live: &LiveJam,
    body: Option<(&str, &[(&str, &str)])>,
) -> Result<bool> {
    if std::env::var("DEV_MODE").is_err() {
        return Ok(false);
    }
    let spec = live.spec_path();
    let spec = spec.to_str().ok_or_else(|| anyhow!("non-utf8 spec path"))?;
    let port = live.rpc_port()?;
    match body {
        Some((test_name, env)) => {
            let mut dev_env = env.to_vec();
            dev_env.push(("TEST_NAME", test_name));
            dev_env.push(("SMOLDOT_LOG_LEVEL", "4"));
            crate::harness::print_dev_mode_invocation(&dev_env, "hosts/browser/run.js");
        }
        None => {
            println!();
            println!("=== DEV_MODE: skipping the page regression, run it manually with: ===");
            println!();
            println!("cd wasm-node/javascript && JAM_SPEC_PATH='{spec}' JAM_RPC_PORT={port} node test/jam/demo.mjs --live");
            println!();
        }
    }
    println!("=== DEV_MODE: the manual demo page attaches with: ===");
    println!();
    println!("just demo-jam-attach '{spec}' {port}");
    println!();
    let secs: u64 = std::env::var("KEEP_ALIVE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(36000);
    eprintln!("DEV_MODE: keeping the JAM network alive for {secs}s (set KEEP_ALIVE_SECS to override; Ctrl-C stops it)...");
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
        _ = tokio::signal::ctrl_c() => eprintln!("DEV_MODE: Ctrl-C, tearing the network down"),
    }
    Ok(true)
}

/// Archive name inside the snapshot directory.
pub const SNAPSHOT_ARCHIVE: &str = "jam-aged-snapshot.tar.gz";
/// Manifest name inside the snapshot directory.
pub const SNAPSHOT_MANIFEST: &str = "manifest.json";
/// Where `jam_aged` looks for the snapshot; default `~/.cache/smoldot-e2e/jam/`.
pub const SNAPSHOT_DIR_ENV: &str = "JAM_SNAPSHOT_DIR";
/// Where `jam_generate_snapshot` writes it; default the same directory.
pub const SNAPSHOT_OUT_ENV: &str = "JAM_SNAPSHOT_OUT";
/// The spec the snapshot was produced under, inside the archive.
const SNAPSHOT_SPEC: &str = "snapshot-jam_spec.json";
const SNAPSHOT_FORMAT: u32 = 1;
/// The command that produces the snapshot, for error messages and docs.
pub const SNAPSHOT_GENERATOR: &str = "cargo test --manifest-path e2e-tests/Cargo.toml \
    --test jam_generate_snapshot -- --ignored --nocapture";

/// `manifest.json` next to the archive.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub format: u32,
    pub archive: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    /// SHA-256 of the generated `jam_spec.json` in canonical form ([`spec_sha256`]);
    /// a restore must regenerate the same spec.
    pub spec_sha256: String,
    /// The validator p2p ports and the RPC port the spec was generated with.
    pub ports: [u16; 7],
    /// The last finalized block before the nodes were stopped.
    pub final_slot: u32,
    pub final_hash: String,
    /// The best block before the nodes were stopped.
    pub best_slot: u32,
    /// Finalized GRANDPA set changes, that is the set id at `final_slot`.
    pub set_id: u32,
    /// Blocks after genesis on the finalized chain.
    pub finalized_blocks: u32,
    pub polkajam_commit: String,
    pub created: String,
}

/// The aged network's databases, as `jam_generate_snapshot` left them.
pub struct JamSnapshot {
    pub archive: PathBuf,
    pub manifest: SnapshotManifest,
}

/// `$XDG_CACHE_HOME/smoldot-e2e/jam` or `~/.cache/smoldot-e2e/jam`.
pub fn default_snapshot_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or_else(|| anyhow!("neither XDG_CACHE_HOME nor HOME is set"))?;
    Ok(base.join("smoldot-e2e").join("jam"))
}

impl JamSnapshot {
    /// Finds the snapshot in `JAM_SNAPSHOT_DIR` (default
    /// [`default_snapshot_dir`]) and checks the archive against its manifest.
    pub fn resolve() -> Result<Self> {
        let dir = match std::env::var_os(SNAPSHOT_DIR_ENV) {
            Some(dir) => PathBuf::from(dir),
            None => default_snapshot_dir()?,
        };
        Self::load(&dir)
    }

    /// The snapshot in `dir`, checked against its manifest.
    pub fn load(dir: &Path) -> Result<Self> {
        let manifest_path = dir.join(SNAPSHOT_MANIFEST);
        // TODO: once the bundle is uploaded to the `zombienet-db-snaps` GCS
        // bucket, download it here when `manifest_path` is missing, as
        // `crate::snapshot` does: pin its URL and SHA-256 in constants, fetch it
        // into the cache directory with `crate::snapshot::download`, check it
        // with `crate::snapshot::verify_sha256`, and unpack the archive and
        // manifest next to each other. Until then the snapshot is local only.
        if !manifest_path.is_file() {
            bail!(
                "no JAM aged snapshot at {} ({SNAPSHOT_DIR_ENV} or the default {}); produce it \
                 with `{SNAPSHOT_GENERATOR}` (writes to {SNAPSHOT_OUT_ENV}, default the same \
                 directory)",
                manifest_path.display(),
                default_snapshot_dir()?.display()
            );
        }
        let manifest: SnapshotManifest = serde_json::from_slice(&std::fs::read(&manifest_path)?)
            .with_context(|| format!("parsing {}", manifest_path.display()))?;
        if manifest.format != SNAPSHOT_FORMAT {
            bail!(
                "{}: snapshot format {} is not {SNAPSHOT_FORMAT}; regenerate it with `{SNAPSHOT_GENERATOR}`",
                manifest_path.display(),
                manifest.format
            );
        }
        let archive = dir.join(&manifest.archive);
        let actual = sha256_file(&archive)?;
        if actual != manifest.archive_sha256 {
            bail!(
                "{}: SHA-256 {actual} does not match the manifest's {}",
                archive.display(),
                manifest.archive_sha256
            );
        }
        log::info!(
            "JAM snapshot {} ({} bytes, final slot {}, set id {})",
            archive.display(),
            manifest.archive_bytes,
            manifest.final_slot,
            manifest.set_id
        );
        Ok(JamSnapshot { archive, manifest })
    }

    /// Unpacks every node's `data` and `cfg` into `base_dir`, where zombienet
    /// finds them and spawns the nodes on them.
    fn restore(&self, base_dir: &Path) -> Result<()> {
        if std::fs::read_dir(base_dir)?.next().is_some() {
            bail!(
                "{} is not empty; a snapshot restores into a fresh base directory",
                base_dir.display()
            );
        }
        run_tar(&["-xzf", path_str(&self.archive)?, "-C", path_str(base_dir)?])?;
        let spec = base_dir.join(SNAPSHOT_SPEC);
        if spec_sha256(&std::fs::read(&spec)?)? != self.manifest.spec_sha256 {
            bail!("the archived spec does not match the manifest");
        }
        std::fs::remove_file(spec)?;
        log::info!("snapshot restored into {}", base_dir.display());
        Ok(())
    }
}

/// Stops the network's nodes gracefully, archives every node's `data` and
/// `cfg` plus the spec as one `.tar.gz` under `out_dir`, and writes the
/// manifest next to it.
pub async fn write_snapshot(
    live: &LiveJam,
    out_dir: &Path,
    ports: [u16; 7],
) -> Result<SnapshotManifest> {
    let best = live.best_block().await?;
    let finalized = live.finalized_block().await?;
    let ancestry = live.ancestry(finalized).await?;
    live.kill_all().await?;

    std::fs::create_dir_all(out_dir)?;
    std::fs::copy(live.spec_path(), live.base_dir.join(SNAPSHOT_SPEC))?;
    let archive = out_dir.join(SNAPSHOT_ARCHIVE);
    let partial = out_dir.join(format!("{SNAPSHOT_ARCHIVE}.partial"));
    let mut args: Vec<String> = vec![
        "-czf".into(),
        path_str(&partial)?.into(),
        "-C".into(),
        path_str(&live.base_dir)?.into(),
        SNAPSHOT_SPEC.into(),
    ];
    for name in VALIDATORS.iter().copied().chain([ORDINARY]) {
        args.push(format!("{name}/data"));
        args.push(format!("{name}/cfg"));
    }
    run_tar(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
    std::fs::rename(&partial, &archive)?;

    let spec_bytes = std::fs::read(live.spec_path())?;
    let manifest = SnapshotManifest {
        format: SNAPSHOT_FORMAT,
        archive: SNAPSHOT_ARCHIVE.into(),
        archive_sha256: sha256_file(&archive)?,
        archive_bytes: std::fs::metadata(&archive)?.len(),
        spec_sha256: spec_sha256(&spec_bytes)?,
        ports,
        final_slot: finalized.slot,
        final_hash: finalized.hash_hex(),
        best_slot: best.slot,
        set_id: ancestry.set_changes,
        finalized_blocks: ancestry.blocks,
        polkajam_commit: POLKAJAM_COMMIT.into(),
        created: utc_now(),
    };
    std::fs::write(
        out_dir.join(SNAPSHOT_MANIFEST),
        serde_json::to_string_pretty(&manifest)? + "\n",
    )?;
    Ok(manifest)
}

fn utc_now() -> String {
    std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("non-utf8 path {}", path.display()))
}

fn run_tar(args: &[&str]) -> Result<()> {
    let status = std::process::Command::new("tar").args(args).status()?;
    if !status.success() {
        bail!("tar {} failed ({status})", args.join(" "));
    }
    Ok(())
}

/// A JAM body running on the browser host in the background, so Rust can
/// inject faults at the points the body announces with `ctx.sendSync`.
pub struct BodyRun {
    handle: Option<tokio::task::JoinHandle<Result<()>>>,
    result: Option<Result<()>>,
}

impl BodyRun {
    /// Starts `test_name` with `env` (owned, since the body outlives the call).
    pub fn spawn(test_name: &'static str, env: Vec<(String, String)>) -> Self {
        let handle = tokio::spawn(async move {
            let env: Vec<(&str, &str)> =
                env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            run_jam_body(test_name, &env).await
        });
        BodyRun {
            handle: Some(handle),
            result: None,
        }
    }

    /// Waits until the body sends `label`, or fails early if the body exits
    /// first (with its own error, if it failed).
    pub async fn wait_for(
        &mut self,
        sync: &crate::SyncFile,
        label: &str,
        timeout: Duration,
    ) -> Result<()> {
        let Some(handle) = self.handle.as_mut() else {
            bail!("the body already exited before sending {label}");
        };
        tokio::select! {
            waited = sync.wait_for_js(label, timeout) => waited,
            joined = handle => {
                self.handle = None;
                let result = joined.map_err(|e| anyhow!("body task panicked: {e}")).and_then(|r| r);
                let message = match &result {
                    Ok(()) => format!("the body exited before sending {label}"),
                    Err(e) => format!("the body failed before sending {label}: {e:#}"),
                };
                self.result = Some(result);
                Err(anyhow!(message))
            }
        }
    }

    /// Waits for the body to finish and returns its outcome.
    pub async fn finish(mut self) -> Result<()> {
        if let Some(result) = self.result.take() {
            return result;
        }
        match self.handle.take() {
            Some(handle) => handle
                .await
                .map_err(|e| anyhow!("body task panicked: {e}"))?,
            None => bail!("the body's outcome was already taken"),
        }
    }
}

/// Runs the manual demo's live page regression (`node test/jam/demo.mjs
/// --live` in `wasm-node/javascript`) against this network: the demo harness
/// attaches to it through `JAM_SPEC_PATH` and `JAM_RPC_PORT`. Its output is
/// forwarded as it arrives.
pub async fn run_demo_regression(live: &LiveJam) -> Result<()> {
    crate::ensure_smoldot_built();
    let js_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow!("no repository root"))?
        .join("wasm-node/javascript");
    let mut cmd = tokio::process::Command::new("node");
    cmd.args(["test/jam/demo.mjs", "--live"])
        .current_dir(&js_dir)
        .env("JAM_SPEC_PATH", live.spec_path())
        .env("JAM_RPC_PORT", live.rpc_port()?.to_string())
        .kill_on_drop(true);
    let status = cmd.status().await.context("running test/jam/demo.mjs")?;
    if !status.success() {
        bail!("test/jam/demo.mjs --live failed ({status})");
    }
    Ok(())
}

/// Waits until a restored network finalizes past the snapshot's best block,
/// with its best block ahead of that, as on a network that never stopped.
pub async fn wait_finalizing_past(
    live: &LiveJam,
    snapshot: &JamSnapshot,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let finalized = live.finalized_block().await?;
        let best = live.best_block().await?;
        if finalized.slot > snapshot.manifest.best_slot && best.slot > finalized.slot {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!(
                "the restored network did not finalize past the snapshot within {timeout:?} \
                 (best {}, finalized {}, snapshot best {}, snapshot created {})",
                best.slot,
                finalized.slot,
                snapshot.manifest.best_slot,
                snapshot.manifest.created
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Restores the snapshot in `dir` into `base_dir`, which must not hold a
/// running network, and checks that the restored network finalizes again.
/// Some stops leave the validators in a state from which GRANDPA never
/// resumes (every validator casts the next round's prevote and none is
/// counted); such an archive is useless for `jam_aged`.
pub async fn verify_snapshot(dir: &Path, base_dir: PathBuf) -> Result<Duration> {
    let snapshot = JamSnapshot::load(dir)?;
    let started = Instant::now();
    let live = spawn_jam_at(
        base_dir,
        Finality::Grandpa,
        Some(snapshot.manifest.ports),
        Some(&snapshot),
    )
    .await?;
    let outcome = wait_finalizing_past(&live, &snapshot, Duration::from_secs(90)).await;
    let elapsed = started.elapsed();
    live.teardown().await?;
    outcome.map(|()| elapsed)
}
