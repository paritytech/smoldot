//! Shared pieces for smoldot startup benchmarks.
//!
//! Kept small on purpose — most heavy lifting (network spawn, smoldot JS build)
//! is reused from `smoldot-e2e-tests`.

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context};
use log::info;
use serde_json::Value;
use zombienet_sdk::{subxt::ext::subxt_rpcs::rpc_params, LocalFileSystem, Network, NetworkNode};

/// Installs JS deps for `benchmarks/js` if not already present.
///
/// Mirrors the e2e-tests helper but targets the benchmarks dir.
pub fn ensure_js_deps_installed() {
    let js_dir = benchmarks_js_dir();
    if js_dir.join("node_modules").exists() {
        return;
    }
    let status = std::process::Command::new("npm")
        .arg("install")
        .current_dir(&js_dir)
        .status()
        .expect("failed to run npm install");
    assert!(status.success(), "npm install in benchmarks/js failed");
}

/// Installs smoldot's own JS deps in `wasm-node/javascript` if `node_modules`
/// is missing.
///
/// `smoldot_e2e_tests::ensure_smoldot_built` runs `npm run build` but never
/// installs deps; CI does `npm ci` explicitly before it. Without this, a fresh
/// checkout fails at `tsc` with "Cannot find @types/node" and similar.
pub fn ensure_smoldot_js_deps_installed() {
    let js_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("wasm-node/javascript");
    if js_dir.join("node_modules").exists() {
        return;
    }
    let status = std::process::Command::new("npm")
        .arg("ci")
        .current_dir(&js_dir)
        .status()
        .expect("failed to run npm ci in wasm-node/javascript");
    assert!(status.success(), "npm ci in wasm-node/javascript failed");
}

pub fn benchmarks_js_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("js")
}

/// Human-facing identifiers pulled from a chain-spec JSON file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainSpecInfo {
    pub name: Option<String>,
    pub id: Option<String>,
}

/// Reads the top-level `name` and `id` fields from a chain-spec JSON.
///
/// Both fields are optional so partially-formed specs still produce a value
/// rather than an error.
pub fn read_chain_spec_info(path: &Path) -> Result<ChainSpecInfo, anyhow::Error> {
    let bytes =
        std::fs::read(path).with_context(|| format!("read chain spec {}", path.display()))?;
    let v: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse chain spec {}", path.display()))?;
    Ok(ChainSpecInfo {
        name: v.get("name").and_then(|x| x.as_str()).map(String::from),
        id: v.get("id").and_then(|x| x.as_str()).map(String::from),
    })
}

impl ChainSpecInfo {
    /// Returns a compact `"Name (id)"` / `"Name"` / `"id"` label for humans.
    pub fn label(&self) -> String {
        match (&self.name, &self.id) {
            (Some(n), Some(i)) if n != i => format!("{n} ({i})"),
            (Some(n), _) => n.clone(),
            (_, Some(i)) => i.clone(),
            _ => "<unknown>".to_string(),
        }
    }
}

/// Polls `chain_getFinalizedHead` + `chain_getHeader` on `node` until the
/// finalized block number is at least `min_block`, or `timeout` elapses.
///
/// Returns the finalized block number observed on success.
pub async fn wait_for_finalized_block(
    node: &NetworkNode,
    min_block: u64,
    timeout: Duration,
) -> Result<u64, anyhow::Error> {
    let rpc = node.rpc().await?;
    let deadline = Instant::now() + timeout;
    let mut last_logged = 0u64;
    loop {
        let finalized_hash: String = rpc
            .request("chain_getFinalizedHead", rpc_params![])
            .await
            .context("chain_getFinalizedHead")?;
        let header: Value = rpc
            .request("chain_getHeader", rpc_params![finalized_hash.clone()])
            .await
            .context("chain_getHeader")?;
        let number = parse_hex_u64(
            header
                .get("number")
                .and_then(|n| n.as_str())
                .ok_or_else(|| anyhow!("header.number missing or not a string"))?,
        )?;
        if number != last_logged {
            info!("{} finalized block: {number}", node.name());
            last_logged = number;
        }
        if number >= min_block {
            return Ok(number);
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "timed out waiting for finalized block >= {min_block} on {}: last seen {number}",
                node.name()
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Reads the current finalized block number on `node`. Single RPC roundtrip.
pub async fn current_finalized_block(node: &NetworkNode) -> Result<u64, anyhow::Error> {
    let rpc = node.rpc().await?;
    let finalized_hash: String = rpc.request("chain_getFinalizedHead", rpc_params![]).await?;
    let header: Value = rpc
        .request("chain_getHeader", rpc_params![finalized_hash])
        .await?;
    parse_hex_u64(
        header
            .get("number")
            .and_then(|n| n.as_str())
            .ok_or_else(|| anyhow!("header.number missing"))?,
    )
}

fn parse_hex_u64(s: &str) -> Result<u64, anyhow::Error> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(stripped, 16).map_err(|e| anyhow!("invalid hex number {s:?}: {e}"))
}

/// Returns the first relay validator and first parachain collator nodes.
///
/// Matches the naming used by `smoldot-e2e-tests::statement::spawn_network`.
pub fn pick_bench_nodes(
    network: &Network<LocalFileSystem>,
) -> Result<(&NetworkNode, &NetworkNode), anyhow::Error> {
    let validator = network.get_node("validator-0")?;
    let alice = network.get_node("alice")?;
    Ok((validator, alice))
}

/// Sample statistics over a set of f64 measurements (milliseconds).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Stats {
    pub n: usize,
    pub mean: f64,
    pub median: f64,
    pub p95: f64,
    pub stddev: f64,
    pub min: f64,
    pub max: f64,
}

impl Stats {
    pub fn from_samples(samples: &[f64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let n = samples.len();
        let mean = samples.iter().sum::<f64>() / n as f64;
        let variance = samples
            .iter()
            .map(|x| {
                let d = x - mean;
                d * d
            })
            .sum::<f64>()
            / n as f64;
        let stddev = variance.sqrt();

        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = percentile(&sorted, 50.0);
        let p95 = percentile(&sorted, 95.0);
        let min = *sorted.first().unwrap();
        let max = *sorted.last().unwrap();

        Some(Self {
            n,
            mean,
            median,
            p95,
            stddev,
            min,
            max,
        })
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    // Linear interpolation between closest ranks (type 7, same as numpy default).
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (p / 100.0) * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        return sorted[lo];
    }
    let frac = rank - lo as f64;
    sorted[lo] + frac * (sorted[hi] - sorted[lo])
}
