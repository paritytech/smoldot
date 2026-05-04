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

/// Warm-startup smoke: spawn westend-local + people-westend-local from
/// committed DB snapshots, hand smoldot a chain spec carrying
/// `lightSyncState` AND a persisted `databaseContent` from the prior
/// session, assert it resumes past the persisted finalized block and
/// sees new parachain blocks.
#[tokio::test(flavor = "multi_thread")]
async fn smoke_warm() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let base_dir = resolve_base_dir()?;
    let base_dir_str = base_dir.to_str().expect("UTF-8 path").to_owned();

    let cfg = Scenario::Warm {
        snapshot: SnapshotPaths {
            relay_db_tgz: snapshot::relay_db()?,
            para_db_tgz: snapshot::para_db()?,
            relay_full_spec: snapshot::relay_spec()?,
            para_full_spec: snapshot::para_spec()?,
            smoldot_relay_spec: snapshot::relay_spec_light_sync_state()?,
            smoldot_para_spec: snapshot::para_spec_light_sync_state()?,
        },
        smoldot_db: SmoldotDbPaths {
            relay_db_json: snapshot::smoldot_db_relay()?,
            para_db_json: snapshot::smoldot_db_para()?,
        },
    };
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

    run_smoke_js(&live, &cfg, REQUIRED_BLOCKS).await?;
    Ok(())
}
