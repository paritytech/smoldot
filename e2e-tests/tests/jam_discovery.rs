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
    jam::{dev_mode_keep_alive, spawn_jam, BodyRun, Finality, VALIDATORS},
    SyncFile,
};

/// Live peer discovery (D3, peer discovery from the validator set): a client
/// whose only bootnode is jam0 reads the active set, carries on through other
/// validators while jam0 is down, and returns to jam0 once it is back. Body:
/// `shared/jam_discovery.js`.
///
/// `JAM_DISCOVERY_AGE_SECONDS` ages the network before the client starts, so it
/// warps first and discovers afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn jam_discovery() -> Result<()> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
    let started = Instant::now();
    let live = spawn_jam(Finality::Grandpa, None, None).await?;
    let spec_path = live.spec_path();
    let spec: serde_json::Value = serde_json::from_slice(&std::fs::read(&spec_path)?)?;
    // jam0's combined bootnode from the generated spec, found by its P-256 id.
    let node0_p256 = live
        .network
        .get_jam_node(VALIDATORS[0])?
        .p256_id()
        .to_string();
    let node0_bootnode = spec["bootnodes"]
        .as_array()
        .and_then(|list| {
            list.iter()
                .filter_map(|b| b.as_str())
                .find(|b| b.contains(&format!("+{node0_p256}@")))
        })
        .ok_or_else(|| anyhow!("jam0 ({node0_p256}) is not among the spec's bootnodes"))?
        .to_string();
    let sync = SyncFile::new()?;
    let env = vec![
        (
            "JAM_CHAIN_SPEC".to_string(),
            spec_path.to_string_lossy().into_owned(),
        ),
        ("JAM_RPC_URL".to_string(), live.rpc_url()?),
        ("JAM_NODE0_BOOTNODE".to_string(), node0_bootnode),
        (
            "SYNC_PATH".to_string(),
            sync.path().to_string_lossy().into_owned(),
        ),
    ];
    let env_refs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    if dev_mode_keep_alive(&live, Some(("jam_discovery", &env_refs))).await? {
        return live.teardown().await;
    }
    let age: u64 = std::env::var("JAM_DISCOVERY_AGE_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if age > 0 {
        log::info!("aging the network for {age} s before the client starts");
        tokio::time::sleep(Duration::from_secs(age)).await;
    }

    let mut body = BodyRun::spawn("jam_discovery", env);
    body.wait_for(&sync, "AT_TIP", Duration::from_secs(360))
        .await?;
    live.kill_node(VALIDATORS[0]).await?;
    ensure!(!live.node_running(VALIDATORS[0])?, "jam0 must be down");
    sync.send("KILLED")?;

    body.wait_for(&sync, "CONTINUED", Duration::from_secs(300))
        .await?;
    live.start_node(VALIDATORS[0]).await?;
    ensure!(
        live.genesis_writes(VALIDATORS[0]).await? == 1,
        "jam0 did not restart on its own database"
    );
    sync.send("STARTED")?;

    body.finish().await?;
    ensure!(
        live.node_running(VALIDATORS[0])?,
        "jam0 is not running at the end"
    );
    log::info!("jam_discovery passed in {:.1?}", started.elapsed());
    live.teardown().await
}
