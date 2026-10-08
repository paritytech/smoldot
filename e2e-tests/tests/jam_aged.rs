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
    dev_mode_keep_alive, env_or, env_refs, init_logging, run_jam_body, spawn_jam,
    wait_finalizing_past, Finality, JamSnapshot, SLOT_SECONDS,
};

/// The aged join. The network is restored from the aged snapshot
/// (`jam_generate_snapshot`), so its finalized head is far from genesis with
/// many set changes behind it, and a fresh browser client must reach the
/// node's tip. Body: `shared/jam_aged.js`. The client must:
///
/// - apply a warp at set id 3 or later and re-initialize its follow at the
///   finalized join head F, which the node has finalized;
/// - freeze F as the latest UP0 finalized block its serving connection
///   advertised before the join head was selected;
/// - fetch only F (one descending CE 128 request for one block) and read its
///   state at F on the same connection, with at most two CE 129 responses;
/// - take F's finality from the warp fragment or from a CE 130 on that
///   connection;
/// - reach the tip in at most two ascending CE 128 batches, with the first
///   block within 5 s of connecting, followed by a finalized event.
///
/// The whole scenario must finish within two minutes. `JAM_AGED_BLOCKS`
/// (default 201) is the minimum chain age in actual blocks, `JAM_AGED_BOUND_MS`
/// (default 180000) the client's catch-up bound.
#[tokio::test(flavor = "multi_thread")]
async fn jam_aged() -> Result<()> {
    init_logging();
    let started = Instant::now();
    let snapshot = JamSnapshot::resolve()?;
    let live = spawn_jam(
        Finality::Grandpa,
        Some(snapshot.manifest.ports),
        Some(&snapshot),
    )
    .await?;
    let restored_in = started.elapsed();

    // The client joins a live network: wait until the restored nodes finalize
    // past the snapshot.
    let resume = Duration::from_secs(env_or("JAM_AGED_RESUME_SECS", 60));
    wait_finalizing_past(&live, &snapshot, resume).await?;
    let resumed_in = started.elapsed();

    // Node-side: the chain is old enough, in actual blocks (slots are
    // wall-clock) and in time.
    let minimum = env_or("JAM_AGED_BLOCKS", 201u32);
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

    let mut env = live.body_env(None)?;
    let bound = std::env::var("JAM_AGED_BOUND_MS").unwrap_or_else(|_| "180000".into());
    env.push(("JAM_AGED_BOUND_MS".into(), bound));
    if dev_mode_keep_alive(&live, Some(("jam_aged", &env_refs(&env)))).await? {
        return live.teardown().await;
    }
    run_jam_body("jam_aged", &env_refs(&env)).await?;

    let elapsed = started.elapsed();
    log::info!("jam_aged passed in {elapsed:.1?}");
    live.teardown().await?;
    ensure!(
        elapsed < Duration::from_secs(120),
        "the aged scenario took {elapsed:.1?}, more than two minutes"
    );
    Ok(())
}
