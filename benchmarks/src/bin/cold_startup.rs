//! Cold-startup benchmark for the smoldot light client.
//!
//! Measures the time from `start()` to the first `chainHead_v1_follow`
//! notification with `event: "initialized"`. Each iteration runs in a fresh
//! `node` subprocess — cold = fresh V8, fresh WASM bring-up, fresh client.
//!
//! See `benchmarks/README.md` for caveats (notably: on a zombienet-local chain
//! with no warp-sync checkpoint, the number measured is NOT representative of
//! mainnet cold-start latency).

use std::{path::PathBuf, process::Stdio, time::Duration};

use anyhow::{anyhow, Context};
use clap::Parser;
use log::{info, warn};
use smoldot_benchmarks::{
    current_finalized_block, ensure_js_deps_installed, ensure_smoldot_js_deps_installed,
    pick_bench_nodes, wait_for_finalized_block, Stats,
};
use smoldot_e2e_tests::{
    ensure_smoldot_built, resolve_base_dir,
    statement::{create_para_chain_spec_with_allowances, spawn_network, spawned_chain_spec_paths},
};
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Parser, Debug)]
#[command(about = "Cold-startup benchmark for smoldot")]
struct Args {
    /// Number of measured iterations.
    #[arg(long, default_value_t = 10)]
    iterations: usize,

    /// Warm-up iterations discarded before measuring.
    #[arg(long, default_value_t = 0)]
    warmup: usize,

    /// Which chain's `chainHead_v1_follow` to subscribe to.
    #[arg(long, value_enum, default_value_t = Target::Para)]
    target: Target,

    /// Override relay chain spec path. If set, zombienet is NOT spawned and the
    /// spec's own bootnodes are used — point this at e.g. `demo-chain-specs/polkadot.json`
    /// to bench against a live network.
    #[arg(long)]
    relay_chain_spec: Option<PathBuf>,

    /// Override parachain chain spec path. Only meaningful with
    /// `--target para` and `--relay-chain-spec`.
    #[arg(long)]
    para_chain_spec: Option<PathBuf>,

    /// Per-iteration timeout (seconds).
    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,

    /// Wait for the relay's finalized block number to reach at least this
    /// value before starting iterations. Readiness is always gated on the
    /// relay (parachain finality derives from it and can lag significantly on
    /// a fresh local network). Only applies when zombienet is spawned.
    #[arg(long, default_value_t = 1)]
    min_finalized_before_bench: u64,

    /// Max time to wait for the relay finalization gate (seconds).
    #[arg(long, default_value_t = 180)]
    finalized_wait_secs: u64,

    /// Pass `withRuntime: false` to chainHead_v1_follow. Default: true (stricter,
    /// matches what most light-client users care about).
    #[arg(long, default_value_t = false)]
    no_with_runtime: bool,

    /// Emit results as a single JSON object on stdout (in addition to the
    /// human-readable table). Useful for CI dashboards.
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
enum Target {
    Relay,
    Para,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    )
    .ok();

    let args = Args::parse();

    info!("Ensuring smoldot's own JS deps are installed (wasm-node/javascript)");
    ensure_smoldot_js_deps_installed();
    info!("Ensuring smoldot JS bundle is built");
    ensure_smoldot_built();
    info!("Ensuring benchmark JS deps are installed");
    ensure_js_deps_installed();

    // Decide: spawn zombienet, or use user-supplied specs?
    let (relay_spec, para_spec, network) = if args.relay_chain_spec.is_some() {
        if matches!(args.target, Target::Para) && args.para_chain_spec.is_none() {
            return Err(anyhow!(
                "--target para requires --para-chain-spec when --relay-chain-spec is given"
            ));
        }
        info!("Using user-supplied chain specs; skipping zombienet spawn");
        (
            args.relay_chain_spec.clone().unwrap(),
            args.para_chain_spec.clone(),
            None,
        )
    } else {
        let base_dir = resolve_base_dir()?;
        info!("Base dir: {}", base_dir.display());

        // Empty allowances — the bench doesn't need them, we just want the
        // same statement-store parachain spec the e2e tests use.
        let para_spec_path = create_para_chain_spec_with_allowances(&[], &base_dir)?;
        info!("Spawning zombienet network");
        let network = spawn_network(&base_dir, &para_spec_path).await?;
        let (relay_path, para_path) = spawned_chain_spec_paths(&network)?;

        let (validator, _) = pick_bench_nodes(&network)?;
        info!(
            "Waiting for relay finalized block >= {} on {} (timeout {}s)",
            args.min_finalized_before_bench,
            validator.name(),
            args.finalized_wait_secs,
        );
        wait_for_finalized_block(
            validator,
            args.min_finalized_before_bench,
            Duration::from_secs(args.finalized_wait_secs),
        )
        .await?;

        (relay_path, Some(para_path), Some(network))
    };

    let total = args.warmup + args.iterations;
    info!(
        "Running {} warmup + {} measured iteration(s), target={:?}",
        args.warmup, args.iterations, args.target
    );

    let before = drift_blocks(network.as_ref()).await;

    let mut samples = Vec::with_capacity(args.iterations);
    for i in 0..total {
        let label = if i < args.warmup {
            format!("warmup {}/{}", i + 1, args.warmup)
        } else {
            format!("sample {}/{}", i - args.warmup + 1, args.iterations)
        };
        let ms = run_one(&args, &relay_spec, para_spec.as_deref())
            .await
            .with_context(|| format!("iteration {label} failed"))?;
        info!("[{label}] initialized_ms = {ms:.1}");
        if i >= args.warmup {
            samples.push(ms);
        }
    }

    let after = drift_blocks(network.as_ref()).await;

    let stats = Stats::from_samples(&samples)
        .ok_or_else(|| anyhow!("no samples collected"))?;
    print_report(&args, &stats, before, after);
    Ok(())
}

async fn run_one(
    args: &Args,
    relay_spec: &std::path::Path,
    para_spec: Option<&std::path::Path>,
) -> Result<f64, anyhow::Error> {
    let script = smoldot_benchmarks::benchmarks_js_dir().join("cold_startup.js");
    let cwd = smoldot_benchmarks::benchmarks_js_dir()
        .parent()
        .unwrap()
        .to_path_buf();

    let mut cmd = tokio::process::Command::new("node");
    cmd.arg(&script)
        .current_dir(&cwd)
        .env("RELAY_CHAIN_SPEC", relay_spec)
        .env(
            "TARGET",
            match args.target {
                Target::Relay => "relay",
                Target::Para => "para",
            },
        )
        .env(
            "WITH_RUNTIME",
            if args.no_with_runtime { "false" } else { "true" },
        )
        .env("TIMEOUT_MS", (args.timeout_secs * 1000).to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    if let Some(p) = para_spec {
        cmd.env("PARA_CHAIN_SPEC", p);
    }

    let mut child = cmd.spawn().context("spawn node")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("child stdout missing"))?;
    let mut lines = BufReader::new(stdout).lines();

    let mut result_line: Option<String> = None;
    while let Some(line) = lines.next_line().await? {
        if let Some(rest) = line.strip_prefix("RESULT ") {
            result_line = Some(rest.to_string());
            break;
        }
    }

    let status = child.wait().await?;
    let result_line = result_line
        .ok_or_else(|| anyhow!("no RESULT line emitted; child exit: {status}"))?;

    if !status.success() {
        warn!("child exited non-zero ({status}) despite RESULT line; parsing anyway");
    }

    let v: serde_json::Value = serde_json::from_str(&result_line)
        .with_context(|| format!("parse RESULT line: {result_line}"))?;
    v.get("initialized_ms")
        .and_then(|x| x.as_f64())
        .ok_or_else(|| anyhow!("RESULT missing initialized_ms field: {result_line}"))
}

#[derive(Copy, Clone, Debug, Default)]
struct DriftBlocks {
    relay: Option<u64>,
    para: Option<u64>,
}

async fn drift_blocks(
    network: Option<&zombienet_sdk::Network<zombienet_sdk::LocalFileSystem>>,
) -> DriftBlocks {
    let Some(network) = network else {
        return DriftBlocks::default();
    };
    let Ok((validator, collator)) = pick_bench_nodes(network) else {
        return DriftBlocks::default();
    };
    let relay = match current_finalized_block(validator).await {
        Ok(n) => Some(n),
        Err(e) => {
            warn!("relay drift read failed: {e}");
            None
        }
    };
    let para = match current_finalized_block(collator).await {
        Ok(n) => Some(n),
        Err(e) => {
            warn!("para drift read failed: {e}");
            None
        }
    };
    DriftBlocks { relay, para }
}

fn print_report(args: &Args, stats: &Stats, before: DriftBlocks, after: DriftBlocks) {
    println!();
    println!("=== cold-startup benchmark ===");
    println!("target              : {:?}", args.target);
    println!("iterations          : {}", stats.n);
    println!("warmup              : {}", args.warmup);
    println!("with_runtime        : {}", !args.no_with_runtime);
    print_drift("relay finalized", before.relay, after.relay);
    print_drift("para finalized", before.para, after.para);
    println!();
    println!("initialized_ms:");
    println!("  mean    = {:.1}", stats.mean);
    println!("  median  = {:.1}", stats.median);
    println!("  p95     = {:.1}", stats.p95);
    println!("  stddev  = {:.1}", stats.stddev);
    println!("  min/max = {:.1} / {:.1}", stats.min, stats.max);

    if args.json {
        let obj = serde_json::json!({
            "target": format!("{:?}", args.target).to_lowercase(),
            "iterations": stats.n,
            "warmup": args.warmup,
            "with_runtime": !args.no_with_runtime,
            "initialized_ms": stats,
            "relay_finalized_before": before.relay,
            "relay_finalized_after": after.relay,
            "para_finalized_before": before.para,
            "para_finalized_after": after.para,
        });
        println!();
        println!("JSON {}", serde_json::to_string(&obj).unwrap());
    }
}

fn print_drift(label: &str, before: Option<u64>, after: Option<u64>) {
    if let (Some(b), Some(a)) = (before, after) {
        println!("{label:<20}: {b} -> {a} (drift {})", a.saturating_sub(b));
    }
}
