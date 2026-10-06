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
use smoldot_e2e_tests::{
    jam::{dev_mode_keep_alive, env_refs, init_logging, spawn_jam, BodyRun, Finality, VALIDATORS},
    SyncFile,
};

/// The JAM browser gate, on a Dummy (no finality) network. Body:
/// `shared/jam_follow.js`.
///
/// 1. Positive: the client anchors at the spec's genesis hash, reports at
///    least five new blocks within five slots, each with a previously
///    reported parent, and a best block change, `jamHead_unstable_header`
///    returns bytes that hash to the requested hash and hold the slot the new
///    block reported, and `chainHead_v1_follow` is method-not-found.
/// 2. Restart: Rust kills jam0 and starts it again on its own database; the
///    next new block must link to a block reported before the restart, not
///    just to the anchor.
/// 3. Unfollow: `jamHead_unstable_unfollow` resolves and the events stop.
/// 4. Negative: a second client whose spec carries a corrupted genesis
///    authority set anchors at its own genesis hash, is refused by the
///    network, and never reports a new block.
/// 5. Dummy wire facts: CE 153 ends with a typed NoData, no CE 129 request,
///    no live `C(8)` read, and no finalized event.
///
/// `DEV_MODE=1` skips the body, keeps the network up and prints how to run the
/// body.
#[tokio::test(flavor = "multi_thread")]
async fn jam_follow() -> Result<()> {
    init_logging();
    let started = Instant::now();
    let live = spawn_jam(Finality::Dummy, None, None).await?;
    let sync = SyncFile::new()?;
    let env = live.body_env(Some(&sync))?;
    if dev_mode_keep_alive(("jam_follow", &env_refs(&env))).await? {
        return live.teardown().await;
    }

    let best_at_start = live.best_block().await?;
    let mut body = BodyRun::spawn("jam_follow", env);

    body.wait_for(&sync, "POSITIVE_DONE", Duration::from_secs(300))
        .await?;
    live.kill_node(VALIDATORS[0]).await?;
    sync.send("KILLED")?;

    body.wait_for(&sync, "RESTART_READY", Duration::from_secs(120))
        .await?;
    live.start_node(VALIDATORS[0]).await?;
    sync.send("RESTARTED")?;

    body.finish().await?;

    // Node-side: the chain kept growing across the run, jam0 is up again.
    let best = live.best_block().await?;
    ensure!(
        best.slot > best_at_start.slot,
        "the network's best block did not advance ({} -> {})",
        best_at_start.slot,
        best.slot
    );
    ensure!(
        live.node_running(VALIDATORS[0])?,
        "jam0 is not running at the end"
    );
    log::info!(
        "jam_follow passed in {:.1?}; best slot {} -> {}",
        started.elapsed(),
        best_at_start.slot,
        best.slot
    );
    live.teardown().await
}
