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

use anyhow::anyhow;
use smoldot_e2e_tests::*;

const REQUIRED_BLOCKS: u32 = 5;

/// Cold chainHead_v1_follow conformance + warp-sync-regression test. Spawns
/// westend-local + people-westend-local from snapshots, hands smoldot a chain
/// spec carrying `lightSyncState` (no persisted DB), and drives the JS
/// validator. The cold-only regression check fails if smoldot's initial
/// finalized hash equals the chain-spec checkpoint hash (the warp-sync bug).
#[tokio::test(flavor = "multi_thread")]
async fn chainhead_v1_follow_cold() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let base_dir = resolve_base_dir()?;
    let base_dir_str = base_dir.to_str().expect("UTF-8 path").to_owned();

    let cfg = Scenario::Cold(SnapshotPaths {
        relay_db_tgz: snapshot::relay_dbs()?,
        para_db_tgz: snapshot::para_db()?,
        relay_full_spec: snapshot::relay_spec()?,
        para_full_spec: snapshot::para_spec()?,
        smoldot_relay_spec: snapshot::relay_spec_light_sync_state()?,
        smoldot_para_spec: snapshot::para_spec_light_sync_state()?,
    });
    let live = spawn_scenario(&cfg, &base_dir_str).await?;

    log::info!("checking that alice has produced post-snapshot parachain blocks (best)");
    let alice = live.network.get_node("alice")?;
    let baseline = alice.reports(BEST_METRIC).await? as u32;
    let target = baseline + REQUIRED_BLOCKS;
    alice
        .wait_metric_with_timeout(BEST_METRIC, |h| h >= target as f64, 180u64)
        .await
        .map_err(|e| {
            anyhow!(
                "alice did not produce {REQUIRED_BLOCKS} parachain blocks past #{baseline}: {e}"
            )
        })?;
    log::info!("alice reached #{target} (>= baseline+{REQUIRED_BLOCKS})");

    // Follow the para chain, with and without runtime.
    run_chainhead_v1_follow_js(&live, &cfg, true, FollowChain::Para).await?;
    run_chainhead_v1_follow_js(&live, &cfg, false, FollowChain::Para).await?;

    // Follow the relay chain directly (validates relay finality resuming from
    // the snapshot), with and without runtime.
    run_chainhead_v1_follow_js(&live, &cfg, true, FollowChain::Relay).await?;
    run_chainhead_v1_follow_js(&live, &cfg, false, FollowChain::Relay).await?;

    Ok(())
}
