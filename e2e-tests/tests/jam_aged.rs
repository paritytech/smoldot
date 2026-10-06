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

use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use smoldot_e2e_tests::jam::{
    dev_mode_keep_alive, run_jam_body, spawn_jam, wait_finalizing_past, Finality, JamSnapshot,
    SLOT_SECONDS,
};

/// The aged join (D7, GRANDPA warp sync; D2, verified state reads; D14,
/// ascending catch-up): the network is restored from the aged snapshot
/// (`jam_generate_snapshot`), and a fresh browser client must warp to the
/// finalized head, read its state there and reach the node's tip. Body:
/// `shared/jam_aged.js`. The whole scenario must finish within two minutes.
///
/// `JAM_AGED_BLOCKS` (default 201) is the minimum chain age in actual blocks,
/// `JAM_AGED_BOUND_MS` (default 180000) the client's catch-up bound.
#[tokio::test(flavor = "multi_thread")]
async fn jam_aged() -> Result<()> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
    let started = Instant::now();
    let snapshot = JamSnapshot::resolve()?;
    let live = spawn_jam(
        Finality::Grandpa,
        Some(snapshot.manifest.ports),
        Some(&snapshot),
    )
    .await?;
    let restored_in = started.elapsed();

    // The client joins a live network, as on a network that never stopped:
    // wait until the restored nodes produced and finalized past the snapshot
    // (they resume at the current wall-clock slot, after the gap). The
    // generator checks that its archive resumes finality before keeping it.
    let resume_secs: u64 = std::env::var("JAM_AGED_RESUME_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    wait_finalizing_past(&live, &snapshot, Duration::from_secs(resume_secs)).await?;
    let resumed_in = started.elapsed();

    // Node-side: the chain is as old as the acceptance needs, in actual
    // blocks (the first live slot is millions past genesis) and in time.
    let minimum: u32 = std::env::var("JAM_AGED_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(201);
    let tip = live.best_block().await?;
    let finalized = live.finalized_block().await?;
    let ancestry = live.ancestry(tip).await?;
    let age_seconds = u64::from(tip.slot - ancestry.earliest_slot) * SLOT_SECONDS;
    log::info!(
        "restored chain: best slot {} ({} blocks after genesis, earliest slot {}, {} s), \
         finalized slot {} (snapshot's: {}), {} set changes on the best chain; restored in {:.1?}, finalizing again after {:.1?}",
        tip.slot,
        ancestry.blocks,
        ancestry.earliest_slot,
        age_seconds,
        finalized.slot,
        snapshot.manifest.final_slot,
        ancestry.set_changes,
        restored_in,
        resumed_in
    );
    ensure!(
        ancestry.blocks >= minimum,
        "the restored chain has {} blocks, fewer than {minimum}",
        ancestry.blocks
    );
    ensure!(
        age_seconds >= 1200,
        "the restored chain spans {age_seconds} s, less than 1200"
    );
    ensure!(
        finalized.slot >= snapshot.manifest.final_slot,
        "the restored node finalized less than the snapshot ({} < {})",
        finalized.slot,
        snapshot.manifest.final_slot
    );

    let spec = live.spec_path().to_string_lossy().into_owned();
    let rpc_url = live.rpc_url()?;
    let bound = std::env::var("JAM_AGED_BOUND_MS").unwrap_or_else(|_| "180000".into());
    let env = [
        ("JAM_CHAIN_SPEC", spec.as_str()),
        ("JAM_RPC_URL", rpc_url.as_str()),
        ("JAM_AGED_BOUND_MS", bound.as_str()),
    ];
    if dev_mode_keep_alive(&live, Some(("jam_aged", &env))).await? {
        return live.teardown().await;
    }
    run_jam_body("jam_aged", &env).await?;

    let elapsed = started.elapsed();
    log::info!("jam_aged passed in {elapsed:.1?}");
    live.teardown().await?;
    ensure!(
        elapsed < Duration::from_secs(120),
        "the aged scenario took {elapsed:.1?}, more than two minutes"
    );
    Ok(())
}
