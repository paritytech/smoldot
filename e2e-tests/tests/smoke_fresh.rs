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

/// Fresh-startup smoke: spawn westend-local + people-westend-local from
/// genesis and assert smoldot warp-syncs and sees new parachain blocks.
#[tokio::test(flavor = "multi_thread")]
async fn smoke_fresh() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let base_dir = resolve_base_dir()?;
    let base_dir_str = base_dir.to_str().expect("UTF-8 path").to_owned();

    let cfg = Scenario::Fresh;
    let live = spawn_scenario(&cfg, &base_dir_str).await?;

    log::info!("checking that alice has ≥{REQUIRED_BLOCKS} parachain blocks (best)");
    live.network
        .get_node("alice")?
        .wait_metric_with_timeout(BEST_METRIC, |h| h >= REQUIRED_BLOCKS as f64, 180u64)
        .await
        .map_err(|e| anyhow!("alice did not produce parachain blocks: {e}"))?;
    log::info!("alice has ≥{REQUIRED_BLOCKS} parachain blocks");

    run_smoke_js(&live, &cfg, REQUIRED_BLOCKS).await?;
    Ok(())
}
