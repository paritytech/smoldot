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

//! Bench: spawns the cold zombienet scenario once, then drives the JS
//! `chainHead_v1_follow` validator multiple times against it, measuring
//! parachain bootstrap latency (request → `initialized`) across three
//! variants: cold (rm smoldot DB each iter), warm back-to-back (use prior
//! dumped DB), and warm aged (sleep before iter to drift the DB).
//!
//! Counts and aged-sleep are env-configurable so the test can be tuned.
//! Marked `#[ignore]` so it doesn't run in the default suite.

use anyhow::anyhow;
use smoldot_e2e_tests::*;
use std::path::PathBuf;
use std::time::Duration;

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn stats(label: &str, samples: &[i64]) {
    if samples.is_empty() {
        log::info!("{label}: no samples");
        return;
    }
    let mut sorted: Vec<i64> = samples.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    let sum: i64 = sorted.iter().sum();
    let avg = sum / (n as i64);
    let med = if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    };
    let min = *sorted.first().unwrap();
    let max = *sorted.last().unwrap();
    log::info!(
        "{label} (n={n}): avg={avg}ms median={med}ms min={min}ms max={max}ms  samples={samples:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn chainhead_v1_follow_bench() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let cold_iters = env_usize("BENCH_COLD", 5);
    let warm_iters = env_usize("BENCH_WARM", 5);
    let aged_iters = env_usize("BENCH_AGED", 3);
    let aged_sleep_secs = env_u64("BENCH_AGED_SLEEP_SECS", 180);

    let base_dir = resolve_base_dir()?;
    let base_dir_str = base_dir.to_str().expect("UTF-8 path").to_owned();

    let cfg = Scenario::Cold(SnapshotPaths {
        relay_db_tgz: snapshot::relay_db()?,
        para_db_tgz: snapshot::para_db()?,
        relay_full_spec: snapshot::relay_spec()?,
        para_full_spec: snapshot::para_spec()?,
        smoldot_relay_spec: snapshot::relay_spec_light_sync_state()?,
        smoldot_para_spec: snapshot::para_spec_light_sync_state()?,
    });

    log::info!("spawning zombienet (cold scenario, snapshot-backed)");
    let live = spawn_scenario(&cfg, &base_dir_str).await?;

    // Wait for the parachain to produce some real blocks before benching, so
    // that lightSyncState isn't trivially at the network head.
    let alice = live.network.get_node("alice")?;
    let baseline = alice.reports(BEST_METRIC).await? as u32;
    let target = baseline + 5;
    alice
        .wait_metric_with_timeout(BEST_METRIC, |h| h >= target as f64, 180u64)
        .await
        .map_err(|e| {
            anyhow!("alice did not produce 5 parachain blocks past #{baseline}: {e}")
        })?;
    log::info!("alice reached #{target}; starting bench");

    let dump_dir: PathBuf = base_dir.join("smoldot-bench-db");
    let relay_db = dump_dir.join("relay.json");
    let para_db = dump_dir.join("para.json");

    // Cold.
    let mut cold_samples: Vec<i64> = Vec::new();
    for i in 1..=cold_iters {
        let _ = std::fs::remove_dir_all(&dump_dir);
        std::fs::create_dir_all(&dump_dir)?;
        log::info!("[cold {i}/{cold_iters}] running");
        let ms = run_chainhead_v1_follow_bench_js(&live, &dump_dir, None).await?;
        log::info!("[cold {i}/{cold_iters}] bootstrap={ms}ms");
        cold_samples.push(ms);
    }

    // Warm back-to-back. Assumes the last cold iter dumped DB; if cold_iters==0
    // seed once with a cold run so warm has something to load.
    if warm_iters > 0 && !relay_db.exists() {
        log::info!("[seed-for-warm] running one cold iter to populate DB");
        let _ = std::fs::remove_dir_all(&dump_dir);
        std::fs::create_dir_all(&dump_dir)?;
        let _ = run_chainhead_v1_follow_bench_js(&live, &dump_dir, None).await?;
    }
    let mut warm_samples: Vec<i64> = Vec::new();
    for i in 1..=warm_iters {
        log::info!("[warm {i}/{warm_iters}] running (preloaded DB)");
        let ms =
            run_chainhead_v1_follow_bench_js(&live, &dump_dir, Some((&relay_db, &para_db))).await?;
        log::info!("[warm {i}/{warm_iters}] bootstrap={ms}ms");
        warm_samples.push(ms);
    }

    // Aged. Re-seed before each iter, then sleep, then run.
    let mut aged_samples: Vec<i64> = Vec::new();
    for i in 1..=aged_iters {
        let _ = std::fs::remove_dir_all(&dump_dir);
        std::fs::create_dir_all(&dump_dir)?;
        log::info!("[aged {i}/{aged_iters}] seeding DB");
        let _ = run_chainhead_v1_follow_bench_js(&live, &dump_dir, None).await?;
        log::info!("[aged {i}/{aged_iters}] sleeping {aged_sleep_secs}s to age DB");
        tokio::time::sleep(Duration::from_secs(aged_sleep_secs)).await;
        log::info!("[aged {i}/{aged_iters}] running");
        let ms =
            run_chainhead_v1_follow_bench_js(&live, &dump_dir, Some((&relay_db, &para_db))).await?;
        log::info!("[aged {i}/{aged_iters}] bootstrap={ms}ms");
        aged_samples.push(ms);
    }

    log::info!("=== bench summary ===");
    stats("cold (rm DB each)", &cold_samples);
    stats("warm (back-to-back)", &warm_samples);
    stats(&format!("aged ({}s sleep)", aged_sleep_secs), &aged_samples);

    Ok(())
}
