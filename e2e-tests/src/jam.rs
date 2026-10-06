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

//! Helpers for the JAM scenarios (`tests/jam_*.rs`): a PolkaJam network on
//! zombienet-sdk, node-side checks over its JSON-RPC, fault injection and the
//! aged snapshot. See `docs/jam-scenarios.md`.

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
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

/// The PolkaJam commit the scenarios are written against, recorded in the
/// snapshot manifest. Nothing checks the binary against it.
pub const POLKAJAM_COMMIT: &str = "78fbf75e6e5a11380fadd70daf302f2a81930b4d";

/// `ProtocolParameters::tiny()` slot duration.
pub const SLOT_SECONDS: u64 = 6;

/// Validator p2p ports and the RPC port of the aged network, in that order. A
/// validator's address is part of the genesis, so the aged snapshot only fits
/// a network spawned on these ports.
pub const AGED_PORTS: [u16; 7] = [47210, 47211, 47212, 47213, 47214, 47215, 47216];

/// How long a node gets to exit after `SIGINT` before it is killed; PolkaJam
/// flushes its database only on Ctrl-C.
pub const NODE_STOP_GRACE: Duration = Duration::from_secs(15);

const RPC_READY_TIMEOUT: Duration = Duration::from_secs(120);
const NODE_START_TIMEOUT: Duration = Duration::from_secs(120);
const WEBTRANSPORT_LINE: &str = "For WebTransport, use";

/// The finality mode every node runs (`--finality-mode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finality {
    Dummy,
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

/// The six validators and the ordinary node. `ports` fixes the validator p2p
/// ports and the RPC port ([`AGED_PORTS`]); otherwise zombienet picks them.
/// Native nodes only get `TZ`, `LANG` and `PATH` from zombienet, so
/// `POLKAVM_BACKEND` and `RUST_LOG` go through each node's env.
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
    // A macro, as zombienet-sdk does not export the node builder's type.
    macro_rules! validator {
        ($index:expr) => {
            |n| {
                let n = n.with_name(VALIDATORS[$index]).with_env(env());
                match ports {
                    Some(ports) => n.with_p2p_port(ports[$index]),
                    None => n,
                }
            }
        };
    }
    NetworkConfigBuilder::new()
        .with_jamchain(|jam| {
            let mut jam = jam
                .with_id("dev")
                .with_default_command("polkajam")
                .with_default_args(vec![finality.arg().into()])
                .with_validator(validator!(0));
            for index in 1..VALIDATORS.len() {
                jam = jam.with_validator(validator!(index));
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
/// and waits until the ordinary node's RPC reports a block past genesis. With
/// a snapshot, the regenerated spec must equal the snapshot's.
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
    /// The spec zombienet generated, which the light client takes unchanged.
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

    pub async fn epoch_period(&self) -> Result<u32> {
        let params = self.request("parameters", vec![]).await?;
        params["V1"]["epoch_period"]
            .as_u64()
            .and_then(|e| u32::try_from(e).ok())
            .filter(|e| *e > 0)
            .ok_or_else(|| anyhow!("no epoch_period in {params}"))
    }

    /// Walks from `from` to genesis, counting blocks and epoch changes. The
    /// GRANDPA set changes once per epoch, so the epoch changes on the
    /// finalized chain equal the set id a following client logs.
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

    /// Waits until the finalized chain carries at least `set_changes` set
    /// changes, then returns the finalized block.
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

    /// Stops a node with `SIGINT`, then `SIGKILL` after [`NODE_STOP_GRACE`].
    pub async fn kill_node(&self, name: &str) -> Result<()> {
        let node = self.network.get_jam_node(name)?;
        node.core()
            .kill(Some(NODE_STOP_GRACE))
            .await
            .with_context(|| format!("killing {name}"))?;
        ensure!(!self.node_running(name)?, "{name} must be down");
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
        ensure!(
            self.genesis_writes(name).await? == 1,
            "{name} did not restart on its own database"
        );
        log::info!("{name} started");
        Ok(())
    }

    /// The body's environment: the spec, the ordinary node's RPC and, with
    /// `sync`, the sync file.
    pub fn body_env(&self, sync: Option<&crate::SyncFile>) -> Result<Vec<(String, String)>> {
        let path = |path: &Path| path.to_string_lossy().into_owned();
        let mut env = vec![
            ("JAM_CHAIN_SPEC".to_string(), path(&self.spec_path())),
            ("JAM_RPC_URL".to_string(), self.rpc_url()?),
        ];
        env.extend(sync.map(|sync| ("SYNC_PATH".to_string(), path(sync.path()))));
        Ok(env)
    }

    /// How often the node wrote a genesis block, from its log. One means a
    /// restarted node came back on its own database instead of a fresh one.
    async fn genesis_writes(&self, name: &str) -> Result<usize> {
        let logs = self.network.get_jam_node(name)?.core().logs().await?;
        Ok(count_lines(&logs, "Writing genesis block"))
    }

    pub fn node_running(&self, name: &str) -> Result<bool> {
        Ok(self.network.get_jam_node(name)?.core().is_running())
    }

    /// Stops every node gracefully, in parallel; used before archiving.
    pub async fn kill_all(&self) -> Result<()> {
        let [a, b, c, d, e, f] = VALIDATORS.map(|name| self.kill_node(name));
        tokio::try_join!(a, b, c, d, e, f, self.kill_node(ORDINARY))?;
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

/// PolkaJam processes still running from `base_dir`, for the teardown check.
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

/// SHA-256 of a spec's JSON with every object's keys sorted and no whitespace:
/// `gen-spec` writes `genesis_state` from a hash map, so the key order differs
/// between runs. Without serde_json's `preserve_order`, objects are sorted maps.
pub fn spec_sha256(spec: &[u8]) -> Result<String> {
    let value: Value = serde_json::from_slice(spec).context("parsing a chain spec")?;
    Ok(sha256_hex(&serde_json::to_vec(&value)?))
}

/// Logs at `info`, unless `RUST_LOG` says otherwise.
pub fn init_logging() {
    let env = env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info");
    let _ = env_logger::try_init_from_env(env);
}

/// The environment variable `name` as a `T`, or `default` when it is unset or
/// does not parse.
pub fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// `(key, value)` pairs as string slices.
pub fn env_refs(env: &[(String, String)]) -> Vec<(&str, &str)> {
    env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
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

/// `DEV_MODE`: prints how to run the body (`(test_name, env)`, on the browser
/// host), then keeps the network alive for `KEEP_ALIVE_SECS` (default 36000)
/// or until Ctrl-C. Returns `false` when `DEV_MODE` is unset.
pub async fn dev_mode_keep_alive((test_name, env): (&str, &[(&str, &str)])) -> Result<bool> {
    if std::env::var("DEV_MODE").is_err() {
        return Ok(false);
    }
    let mut dev_env = env.to_vec();
    dev_env.push(("TEST_NAME", test_name));
    dev_env.push(("SMOLDOT_LOG_LEVEL", "4"));
    crate::harness::print_dev_mode_invocation(&dev_env, "hosts/browser/run.js");
    let secs = env_or("KEEP_ALIVE_SECS", 36000u64);
    eprintln!("DEV_MODE: keeping the JAM network alive for {secs}s (set KEEP_ALIVE_SECS to override; Ctrl-C stops it)...");
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
        _ = tokio::signal::ctrl_c() => eprintln!("DEV_MODE: Ctrl-C, tearing the network down"),
    }
    Ok(true)
}

pub const SNAPSHOT_ARCHIVE: &str = "jam-aged-snapshot.tar.gz";
pub const SNAPSHOT_MANIFEST: &str = "manifest.json";
/// Where `jam_aged` looks for the snapshot; default `~/.cache/smoldot-e2e/jam/`.
pub const SNAPSHOT_DIR_ENV: &str = "JAM_SNAPSHOT_DIR";
/// Where `jam_generate_snapshot` writes it; default the same directory.
pub const SNAPSHOT_OUT_ENV: &str = "JAM_SNAPSHOT_OUT";
/// The spec the snapshot was produced under, inside the archive.
const SNAPSHOT_SPEC: &str = "snapshot-jam_spec.json";
const SNAPSHOT_FORMAT: u32 = 1;
pub const SNAPSHOT_GENERATOR: &str = "cargo test --manifest-path e2e-tests/Cargo.toml \
    --features jam --test jam_generate_snapshot -- --ignored --nocapture";

/// `manifest.json` next to the archive.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub format: u32,
    pub archive: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    /// [`spec_sha256`] of the spec a restore must regenerate.
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

pub fn default_snapshot_dir() -> Result<PathBuf> {
    crate::snapshot::cache_dir("jam")
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
        // TODO: download the snapshot when it is missing, as `crate::snapshot`
        // does, once it is uploaded.
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
        crate::snapshot::verify_sha256(&archive, &manifest.archive_sha256)?;
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
        crate::snapshot::extract_tarball(&self.archive, base_dir)?;
        let spec = base_dir.join(SNAPSHOT_SPEC);
        if spec_sha256(&std::fs::read(&spec)?)? != self.manifest.spec_sha256 {
            bail!("the archived spec does not match the manifest");
        }
        std::fs::remove_file(spec)?;
        log::info!("snapshot restored into {}", base_dir.display());
        Ok(())
    }
}

/// Stops every node, archives each node's `data` and `cfg` plus the spec under
/// `out_dir`, and writes the manifest next to it.
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
    let status = std::process::Command::new("tar").args(&args).status()?;
    ensure!(status.success(), "tar {} failed ({status})", args.join(" "));
    std::fs::rename(&partial, &archive)?;

    let spec_bytes = std::fs::read(live.spec_path())?;
    let manifest = SnapshotManifest {
        format: SNAPSHOT_FORMAT,
        archive: SNAPSHOT_ARCHIVE.into(),
        archive_sha256: sha256_hex(&std::fs::read(&archive)?),
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

/// A JAM body running on the browser host in the background, so Rust can
/// inject faults at the points the body announces with `ctx.sendSync`.
pub struct BodyRun {
    handle: Option<tokio::task::JoinHandle<Result<()>>>,
    result: Option<Result<()>>,
}

impl BodyRun {
    pub fn spawn(test_name: &'static str, env: Vec<(String, String)>) -> Self {
        let handle = tokio::spawn(async move { run_jam_body(test_name, &env_refs(&env)).await });
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
/// Some archives never resume finality and are useless for `jam_aged`.
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

#[cfg(test)]
mod tests {
    #[test]
    fn spec_sha256_ignores_key_order_and_whitespace() {
        let sorted = br#"{"a":"x","b":[{"c":null,"d":true}],"n":1.5}"#;
        let shuffled = br#"{ "n": 1.5, "b": [{"d": true, "c": null}], "a": "x" }"#;
        let expected = "e5306599a752bfcc9cebc573fb1e76f36c1f280ed2b214f8dabcc4586c6608de";
        assert_eq!(super::spec_sha256(sorted).unwrap(), expected);
        assert_eq!(super::spec_sha256(shuffled).unwrap(), expected);
    }
}
