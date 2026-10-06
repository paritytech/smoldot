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

use anyhow::Result;
use smoldot_e2e_tests::jam::{dev_mode_keep_alive, run_demo_regression, spawn_jam, Finality};

/// The manual demo's live page regression (C3, manual demo; D18, zombienet
/// demo) on a GRANDPA network aged past a set change: the demo harness
/// attaches to the network, the page warps and re-follows, follows blocks and
/// finality, unfollows, refuses the wrong-authority spec (walkthrough step 10),
/// and works with every, one or no bootnode in the spec. The JavaScript step is
/// `node wasm-node/javascript/test/jam/demo.mjs --live`; its controlled-stream
/// cases stay unit tests (`node --test test/jam/demo.mjs`).
///
/// `DEV_MODE=1` keeps this GRANDPA network up for the manual demo instead
/// (`just demo-jam-dev`).
#[tokio::test(flavor = "multi_thread")]
async fn jam_demo() -> Result<()> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
    let started = Instant::now();
    let live = spawn_jam(Finality::Grandpa, None, None).await?;
    if dev_mode_keep_alive(&live, None).await? {
        return live.teardown().await;
    }

    // The page must warp: age the network past a finalized set change. The
    // first one is the epoch mark of the first block after genesis, so two.
    let (finalized, ancestry) = live
        .wait_for_set_changes(2, Duration::from_secs(300))
        .await?;
    log::info!(
        "aged: finalized slot {}, {} set change(s), {} blocks",
        finalized.slot,
        ancestry.set_changes,
        ancestry.blocks
    );
    run_demo_regression(&live).await?;
    log::info!("jam_demo passed in {:.1?}", started.elapsed());
    live.teardown().await
}
