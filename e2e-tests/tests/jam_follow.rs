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
    jam::{dev_mode_keep_alive, spawn_jam, BodyRun, Finality, VALIDATORS},
    SyncFile,
};

/// The JAM browser gate (C2, browser end-to-end test and CI gate) on a Dummy
/// network: follow, header authenticity, jam0 restart catch-up, unfollow and
/// the wrong-authority-set negative case. Body: `shared/jam_follow.js`.
///
/// `DEV_MODE=1` skips the body, keeps the network up and prints how to run the
/// body and how to attach the manual demo page to it.
#[tokio::test(flavor = "multi_thread")]
async fn jam_follow() -> Result<()> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
    let started = Instant::now();
    let live = spawn_jam(Finality::Dummy, None, None).await?;
    let spec = live.spec_path().to_string_lossy().into_owned();
    let rpc_url = live.rpc_url()?;
    let sync = SyncFile::new()?;
    let sync_path = sync.path().to_string_lossy().into_owned();
    let env = vec![
        ("JAM_CHAIN_SPEC".to_string(), spec),
        ("JAM_RPC_URL".to_string(), rpc_url),
        ("SYNC_PATH".to_string(), sync_path),
    ];
    let env_refs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    if dev_mode_keep_alive(&live, Some(("jam_follow", &env_refs))).await? {
        return live.teardown().await;
    }

    let best_at_start = live.best_block().await?;
    let mut body = BodyRun::spawn("jam_follow", env);

    body.wait_for(&sync, "POSITIVE_DONE", Duration::from_secs(300))
        .await?;
    live.kill_node(VALIDATORS[0]).await?;
    ensure!(!live.node_running(VALIDATORS[0])?, "jam0 must be down");
    sync.send("KILLED")?;

    body.wait_for(&sync, "RESTART_READY", Duration::from_secs(120))
        .await?;
    live.start_node(VALIDATORS[0]).await?;
    ensure!(
        live.genesis_writes(VALIDATORS[0]).await? == 1,
        "jam0 did not restart on its own database"
    );
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
