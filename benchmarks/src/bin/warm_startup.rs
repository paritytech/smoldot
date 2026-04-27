//! Warm-startup benchmark for the smoldot light client.
//!
//! "Warm" = fresh `node` subprocess but pre-saved DB. Smoldot reads the DB
//! blob passed to `addChain({ databaseContent })` and skips warp-sync,
//! resuming from the serialized snapshot. This matches what a browser-based
//! light client experiences on page reload when the prior session persisted
//! its state to IndexedDB.
//!
//! Flow:
//!   1. Spawn zombienet (or use user-supplied specs). Wait for relay finality.
//!   2. Save-DB step (one Node subprocess): start smoldot, addChain, wait for
//!      chainHead_v1_follow `initialized`, then call
//!      `chainHead_unstable_finalizedDatabase` on each needed chain and
//!      write `<chainId>.db` into `--db-dir`.
//!   3. Measurement: N fresh Node subprocesses, each loading the saved DB
//!      blobs and measuring time-to-finalized-block (same gate as cold).
//!
//! DB scope:
//!   - `--target relay` saves only the relay DB.
//!   - `--target para` saves both relay and para DBs (smoldot needs both).

use std::{path::PathBuf, process::Stdio, time::Duration};

use anyhow::{anyhow, Context};
use clap::Parser;
use log::{info, warn};
use smoldot_benchmarks::{
    current_finalized_block, ensure_js_deps_installed, ensure_smoldot_js_deps_installed,
    pick_bench_nodes, read_chain_spec_info, wait_for_finalized_block, ChainSpecInfo, Stats,
};
use smoldot_e2e_tests::{
    ensure_smoldot_built, resolve_base_dir,
    statement::{create_para_chain_spec_with_allowances, spawn_network, spawned_chain_spec_paths},
};
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Parser, Debug)]
#[command(about = "Warm-startup benchmark for smoldot (uses pre-saved DB)")]
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
    /// spec's own bootnodes are used. Accepts a short name that resolves to
    /// `demo-chain-specs/<name>.json`.
    #[arg(long)]
    relay_chain_spec: Option<PathBuf>,

    /// Override parachain chain spec path. Only meaningful with
    /// `--target para` and `--relay-chain-spec`.
    #[arg(long)]
    para_chain_spec: Option<PathBuf>,

    /// Per-iteration timeout (seconds).
    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,

    /// Max time to wait for the relay finalization gate (seconds). Only
    /// applies when zombienet is spawned.
    #[arg(long, default_value_t = 180)]
    finalized_wait_secs: u64,

    /// Minimum relay finalized block required before starting the save-DB
    /// step. Only applies when zombienet is spawned.
    #[arg(long, default_value_t = 1)]
    min_finalized_before_bench: u64,

    /// Directory to write/read `<chainId>.db` files. Defaults to the zombienet
    /// base dir (cleaned up with the run) or a tempdir for user-supplied specs.
    #[arg(long)]
    db_dir: Option<PathBuf>,

    /// Reuse DB files in `--db-dir` if they already exist (skip save step).
    /// Default: always regenerate the DB.
    #[arg(long, default_value_t = false)]
    reuse_db: bool,

    /// Emit a JSON line in addition to the human report.
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

    let (relay_spec, para_spec, default_db_dir, network) = if args.relay_chain_spec.is_some() {
        if matches!(args.target, Target::Para) && args.para_chain_spec.is_none() {
            return Err(anyhow!(
                "--target para requires --para-chain-spec when --relay-chain-spec is given"
            ));
        }
        let relay = resolve_chain_spec(&args.relay_chain_spec.clone().unwrap())?;
        let para = args
            .para_chain_spec
            .as_ref()
            .map(|p| resolve_chain_spec(p))
            .transpose()?;
        info!("Using chain specs: relay={}", relay.display());
        if let Some(p) = &para {
            info!("Using chain specs: para={}", p.display());
        }
        let tempdir = std::env::temp_dir().join(format!("smoldot-bench-{}", std::process::id()));
        (relay, para, tempdir, None)
    } else {
        let base_dir = resolve_base_dir()?;
        info!("Base dir: {}", base_dir.display());
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

        (relay_path, Some(para_path), base_dir, Some(network))
    };

    let relay_info = read_chain_spec_info(&relay_spec)?;
    let para_info = match para_spec.as_deref() {
        Some(p) => Some(read_chain_spec_info(p)?),
        None => None,
    };
    info!("Relay chain: {}", relay_info.label());
    if let Some(p) = &para_info {
        info!("Para chain:  {}", p.label());
    }

    let db_dir = args.db_dir.clone().unwrap_or(default_db_dir);
    std::fs::create_dir_all(&db_dir)
        .with_context(|| format!("create db-dir {}", db_dir.display()))?;

    // Figure out which DB files we need.
    let relay_db_id = relay_info
        .id
        .clone()
        .ok_or_else(|| anyhow!("relay chain spec has no `id` field; cannot name DB file"))?;
    let para_db_id = if matches!(args.target, Target::Para) {
        Some(
            para_info
                .as_ref()
                .and_then(|p| p.id.clone())
                .ok_or_else(|| anyhow!("para chain spec has no `id` field; cannot name DB file"))?,
        )
    } else {
        None
    };

    let needed_db_files: Vec<PathBuf> = std::iter::once(db_dir.join(format!("{relay_db_id}.db")))
        .chain(
            para_db_id
                .as_ref()
                .map(|id| db_dir.join(format!("{id}.db"))),
        )
        .collect();

    let all_exist = needed_db_files.iter().all(|p| p.is_file());
    if args.reuse_db && all_exist {
        info!(
            "Reusing existing DB files in {}: {}",
            db_dir.display(),
            needed_db_files
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    } else {
        if args.reuse_db && !all_exist {
            warn!(
                "--reuse-db set but not all DB files present in {}; regenerating",
                db_dir.display()
            );
        }
        info!("Saving DBs to {}", db_dir.display());
        run_save_db(&args, &relay_spec, para_spec.as_deref(), &db_dir).await?;
    }

    let total = args.warmup + args.iterations;
    info!(
        "Running {} warmup + {} measured iteration(s), target={:?}",
        args.warmup, args.iterations, args.target
    );

    let before = drift_blocks(network.as_ref()).await;

    let mut samples: Vec<Sample> = Vec::with_capacity(args.iterations);
    for i in 0..total {
        let label = if i < args.warmup {
            format!("warmup {}/{}", i + 1, args.warmup)
        } else {
            format!("sample {}/{}", i - args.warmup + 1, args.iterations)
        };
        let s = run_one(&args, &relay_spec, para_spec.as_deref(), &db_dir)
            .await
            .with_context(|| format!("iteration {label} failed"))?;
        info!(
            "[{label}] finalized_ms = {:.1} (addChain_relay={:.1} addChain_para={:.1} wait_finalized={:.1})",
            s.finalized_ms,
            s.add_chain_relay_ms.unwrap_or(f64::NAN),
            s.add_chain_para_ms.unwrap_or(f64::NAN),
            s.wait_finalized_ms.unwrap_or(f64::NAN),
        );
        if i >= args.warmup {
            samples.push(s);
        }
    }

    let after = drift_blocks(network.as_ref()).await;

    let total_stats = stats_over(&samples, |s| Some(s.finalized_ms))
        .ok_or_else(|| anyhow!("no samples collected"))?;
    let phase_stats = PhaseStats {
        add_chain_relay: stats_over(&samples, |s| s.add_chain_relay_ms),
        add_chain_para: stats_over(&samples, |s| s.add_chain_para_ms),
        wait_finalized: stats_over(&samples, |s| s.wait_finalized_ms),
    };
    let source = if network.is_some() {
        "zombienet-local"
    } else {
        "user-supplied spec"
    };
    print_report(&Report {
        args: &args,
        source,
        relay: &relay_info,
        para: para_info.as_ref(),
        db_dir: &db_dir,
        total: &total_stats,
        phases: &phase_stats,
        before,
        after,
    });
    Ok(())
}

#[derive(Clone, Debug)]
struct Sample {
    finalized_ms: f64,
    add_chain_relay_ms: Option<f64>,
    add_chain_para_ms: Option<f64>,
    wait_finalized_ms: Option<f64>,
}

struct PhaseStats {
    add_chain_relay: Option<Stats>,
    add_chain_para: Option<Stats>,
    wait_finalized: Option<Stats>,
}

fn stats_over<F>(samples: &[Sample], f: F) -> Option<Stats>
where
    F: Fn(&Sample) -> Option<f64>,
{
    let vals: Vec<f64> = samples.iter().filter_map(&f).collect();
    Stats::from_samples(&vals)
}

fn resolve_chain_spec(input: &std::path::Path) -> Result<PathBuf, anyhow::Error> {
    if input.is_file() {
        return Ok(input.to_path_buf());
    }
    let as_str = input.to_string_lossy();
    let looks_like_name =
        !as_str.contains('/') && !as_str.contains('\\') && input.extension().is_none();
    if looks_like_name {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let candidate = repo_root.join("demo-chain-specs").join(format!("{as_str}.json"));
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(anyhow!(
        "chain spec {:?} not found (tried as-is and as demo-chain-specs/<name>.json)",
        input
    ))
}

async fn run_save_db(
    args: &Args,
    relay_spec: &std::path::Path,
    para_spec: Option<&std::path::Path>,
    db_dir: &std::path::Path,
) -> Result<(), anyhow::Error> {
    let script = smoldot_benchmarks::benchmarks_js_dir().join("save_db.js");
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
        .env("SAVE_DB_DIR", db_dir)
        .env("TIMEOUT_MS", (args.timeout_secs * 1000).to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(p) = para_spec {
        cmd.env("PARA_CHAIN_SPEC", p);
    }

    let mut child = cmd.spawn().context("spawn node (save_db)")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("child stdout missing"))?;
    let mut lines = BufReader::new(stdout).lines();
    let mut saw_saved = false;
    while let Some(line) = lines.next_line().await? {
        if line.starts_with("SAVED ") {
            saw_saved = true;
        }
    }
    let status = child.wait().await?;
    if !status.success() || !saw_saved {
        return Err(anyhow!(
            "save_db step failed: exit {status}, saw SAVED line = {saw_saved}"
        ));
    }
    Ok(())
}

async fn run_one(
    args: &Args,
    relay_spec: &std::path::Path,
    para_spec: Option<&std::path::Path>,
    db_dir: &std::path::Path,
) -> Result<Sample, anyhow::Error> {
    let script = smoldot_benchmarks::benchmarks_js_dir().join("startup.js");
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
        .env("TIMEOUT_MS", (args.timeout_secs * 1000).to_string())
        .env("LOAD_DB_DIR", db_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(p) = para_spec {
        cmd.env("PARA_CHAIN_SPEC", p);
    }

    let mut child = cmd.spawn().context("spawn node (warm_startup)")?;
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
    let finalized_ms = v
        .get("finalized_ms")
        .and_then(|x| x.as_f64())
        .ok_or_else(|| anyhow!("RESULT missing finalized_ms field: {result_line}"))?;
    let phases = v.get("phases");
    let get_phase = |name: &str| -> Option<f64> {
        phases.and_then(|p| p.get(name)).and_then(|x| x.as_f64())
    };
    Ok(Sample {
        finalized_ms,
        add_chain_relay_ms: get_phase("add_chain_relay_ms"),
        add_chain_para_ms: get_phase("add_chain_para_ms"),
        wait_finalized_ms: get_phase("wait_finalized_ms"),
    })
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

struct Report<'a> {
    args: &'a Args,
    source: &'a str,
    relay: &'a ChainSpecInfo,
    para: Option<&'a ChainSpecInfo>,
    db_dir: &'a std::path::Path,
    total: &'a Stats,
    phases: &'a PhaseStats,
    before: DriftBlocks,
    after: DriftBlocks,
}

fn print_report(r: &Report<'_>) {
    println!();
    println!("=== warm-startup benchmark ===");
    println!("source              : {}", r.source);
    println!("relay chain         : {}", r.relay.label());
    if let Some(p) = r.para {
        println!("para chain          : {}", p.label());
    }
    println!("target              : {:?}", r.args.target);
    println!("db dir              : {}", r.db_dir.display());
    println!("iterations          : {}", r.total.n);
    println!("warmup              : {}", r.args.warmup);
    print_drift("relay finalized", r.before.relay, r.after.relay);
    print_drift("para finalized", r.before.para, r.after.para);
    println!();
    print_stats_block("finalized_ms (total)", r.total);
    if let Some(s) = &r.phases.add_chain_relay {
        print_stats_block("  addChain relay", s);
    }
    if let Some(s) = &r.phases.add_chain_para {
        print_stats_block("  addChain para", s);
    }
    if let Some(s) = &r.phases.wait_finalized {
        print_stats_block("  wait finalized block", s);
    }

    if r.args.json {
        let obj = serde_json::json!({
            "source": r.source,
            "relay_chain": r.relay,
            "para_chain": r.para,
            "target": format!("{:?}", r.args.target).to_lowercase(),
            "db_dir": r.db_dir.display().to_string(),
            "iterations": r.total.n,
            "warmup": r.args.warmup,
            "finalized_ms": r.total,
            "phases": {
                "add_chain_relay_ms": r.phases.add_chain_relay,
                "add_chain_para_ms": r.phases.add_chain_para,
                "wait_finalized_ms": r.phases.wait_finalized,
            },
            "relay_finalized_before": r.before.relay,
            "relay_finalized_after": r.after.relay,
            "para_finalized_before": r.before.para,
            "para_finalized_after": r.after.para,
        });
        println!();
        println!("JSON {}", serde_json::to_string(&obj).unwrap());
    }
}

fn print_stats_block(label: &str, s: &Stats) {
    println!(
        "{label:<28} mean={:.1} median={:.1} p95={:.1} stddev={:.1} min={:.1} max={:.1}",
        s.mean, s.median, s.p95, s.stddev, s.min, s.max
    );
}

fn print_drift(label: &str, before: Option<u64>, after: Option<u64>) {
    if let (Some(b), Some(a)) = (before, after) {
        println!("{label:<20}: {b} -> {a} (drift {})", a.saturating_sub(b));
    }
}
