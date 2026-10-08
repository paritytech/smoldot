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

use anyhow::{anyhow, ensure, Result};
use smoldot_e2e_tests::{
    jam::{
        dev_mode_keep_alive, env_or, env_refs, init_logging, spawn_jam, BodyRun, Finality,
        VALIDATORS,
    },
    SyncFile,
};

/// Live peer discovery from the validator set. The client's only bootnode is
/// jam0: the spec's other `bootnodes_p256` entries are dropped, its genesis
/// `C(8)` stays.
/// Body: `shared/jam_discovery.js`.
///
/// 1. The client follows the chain, sees verified finality, reads the active
///    set `C(8)` (six validators, five besides jam0) and connects to jam0 as
///    bootnode plus one other validator.
/// 2. At the tip, Rust kills jam0; the client must hold two other validators
///    and keep receiving verified headers and finalized events.
/// 3. Rust starts jam0 again; the client must connect to it as a bootnode
///    again.
///
/// Peer state comes from the client's slot log lines (`peerTracker` in
/// `shared/jam.js`). `JAM_DISCOVERY_AGE_SECONDS` ages the network before the
/// client starts, so it warps first and discovers afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn jam_discovery() -> Result<()> {
    init_logging();
    let started = Instant::now();
    let live = spawn_jam(Finality::Grandpa, None, None).await?;
    let spec: serde_json::Value = serde_json::from_slice(&std::fs::read(live.spec_path())?)?;
    // jam0's `bootnodes_p256` entry in the generated spec, found by its P-256 id.
    let node0_p256 = live
        .network
        .get_jam_node(VALIDATORS[0])?
        .p256_id()
        .to_string();
    let node0_bootnode = spec["bootnodes_p256"]
        .as_array()
        .and_then(|list| {
            list.iter()
                .filter_map(|b| b.as_str())
                .find(|b| b.starts_with(&format!("{node0_p256}@")))
        })
        .ok_or_else(|| anyhow!("jam0 ({node0_p256}) is not in the spec's bootnodes_p256"))?
        .to_string();
    let sync = SyncFile::new()?;
    let mut env = live.body_env(Some(&sync))?;
    env.push(("JAM_NODE0_BOOTNODE".into(), node0_bootnode));
    if dev_mode_keep_alive(&live, Some(("jam_discovery", &env_refs(&env)))).await? {
        return live.teardown().await;
    }
    let age = env_or("JAM_DISCOVERY_AGE_SECONDS", 0u64);
    if age > 0 {
        log::info!("aging the network for {age} s before the client starts");
        tokio::time::sleep(Duration::from_secs(age)).await;
    }

    let mut body = BodyRun::spawn("jam_discovery", env);
    body.wait_for(&sync, "AT_TIP", Duration::from_secs(360))
        .await?;
    live.kill_node(VALIDATORS[0]).await?;
    sync.send("KILLED")?;

    body.wait_for(&sync, "CONTINUED", Duration::from_secs(300))
        .await?;
    live.start_node(VALIDATORS[0]).await?;
    sync.send("STARTED")?;

    body.finish().await?;
    ensure!(
        live.node_running(VALIDATORS[0])?,
        "jam0 is not running at the end"
    );
    log::info!("jam_discovery passed in {:.1?}", started.elapsed());
    live.teardown().await
}
