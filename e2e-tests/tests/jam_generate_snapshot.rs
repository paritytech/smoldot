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

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::Result;
use smoldot_e2e_tests::jam::{
    default_snapshot_dir, spawn_jam, verify_snapshot, write_snapshot, Finality, AGED_PORTS,
    SLOT_SECONDS, SNAPSHOT_OUT_ENV,
};

/// Produces the aged snapshot `jam_aged` restores: a GRANDPA network with the
/// fixed [`AGED_PORTS`] runs until three set changes are finalized, then two
/// more epochs, and until its finalized chain holds at least
/// `JAM_SNAPSHOT_MIN_BLOCKS` blocks (default 201, the D7 aged acceptance);
/// then every node is stopped with SIGINT and each node's `data` and `cfg`
/// plus the spec are archived as `jam-aged-snapshot.tar.gz`, with
/// `manifest.json` next to it, under `JAM_SNAPSHOT_OUT` (default
/// `~/.cache/smoldot-e2e/jam/`). Nothing is uploaded. Last, the archive is
/// restored once and must finalize again within 90 s.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "generator: run explicitly with --ignored"]
async fn jam_generate_snapshot() -> Result<()> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
    let started = Instant::now();
    let out_dir = match std::env::var_os(SNAPSHOT_OUT_ENV) {
        Some(dir) => PathBuf::from(dir),
        None => default_snapshot_dir()?,
    };
    let min_blocks: u32 = std::env::var("JAM_SNAPSHOT_MIN_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(201);

    let live = spawn_jam(Finality::Grandpa, Some(AGED_PORTS), None).await?;
    let (_, after_three) = live
        .wait_for_set_changes(3, Duration::from_secs(15 * 60))
        .await?;
    live.wait_for_set_changes(after_three.set_changes + 2, Duration::from_secs(10 * 60))
        .await?;
    let deadline =
        Instant::now() + Duration::from_secs(u64::from(min_blocks) * SLOT_SECONDS * 2 + 300);
    // PolkaJam's GRANDPA occasionally stops finalizing for good while blocks
    // keep coming; fail fast then instead of waiting out the deadline.
    let mut last_finalized = (0, Instant::now());
    loop {
        let finalized = live.finalized_block().await?;
        let ancestry = live.ancestry(finalized).await?;
        if ancestry.blocks >= min_blocks {
            break;
        }
        if finalized.slot != last_finalized.0 {
            last_finalized = (finalized.slot, Instant::now());
        }
        anyhow::ensure!(
            last_finalized.1.elapsed() < Duration::from_secs(180),
            "finality stalled at slot {} for three minutes while blocks kept coming; \
             generate the snapshot again",
            finalized.slot
        );
        anyhow::ensure!(
            Instant::now() < deadline,
            "the finalized chain did not reach {min_blocks} blocks in time ({})",
            ancestry.blocks
        );
        log::info!("aging: {}/{min_blocks} finalized blocks", ancestry.blocks);
        tokio::time::sleep(Duration::from_secs(30)).await;
    }

    let manifest = write_snapshot(&live, &out_dir, AGED_PORTS).await?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    println!(
        "snapshot written to {} in {:.1?}",
        out_dir.display(),
        started.elapsed()
    );

    // The archive is only useful if a restore finalizes again; check once,
    // with the generating network stopped (it holds the same ports).
    let check_dir = live.base_dir.join("restore-check");
    let resumed = verify_snapshot(&out_dir, check_dir).await;
    live.teardown().await?;
    let resumed = resumed.map_err(|e| {
        e.context(format!(
            "the snapshot in {} does not resume finality when restored; generate it again",
            out_dir.display()
        ))
    })?;
    println!("restore check: the restored network finalized again after {resumed:.1?}");
    Ok(())
}
