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

//! Legacy runtime calls (`state_call`, `state_getRuntimeVersion`) at new blocks must not
//! download a runtime the light client already holds.
//!
//! See <https://github.com/paritytech/smoldot/issues/3396>.

use anyhow::anyhow;
use smoldot_e2e_tests::*;

const REQUIRED_BLOCKS: u32 = 2;

#[tokio::test(flavor = "multi_thread")]
async fn runtime_no_redownload() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let base_dir = resolve_base_dir()?;
    let base_dir_str = base_dir.to_str().expect("UTF-8 path").to_owned();

    let live = spawn_scenario(&Scenario::Fresh, &base_dir_str).await?;

    live.network
        .get_node("alice")?
        .wait_metric_with_timeout(BEST_METRIC, |h| h >= REQUIRED_BLOCKS as f64, 180u64)
        .await
        .map_err(|e| anyhow!("alice did not produce parachain blocks: {e}"))?;

    let env_vars = [
        (
            "RELAY_CHAIN_SPEC",
            live.relay_spec.to_str().expect("UTF-8 path"),
        ),
        (
            "PARA_CHAIN_SPEC",
            live.para_spec.to_str().expect("UTF-8 path"),
        ),
        ("ROUNDS", "3"),
    ];

    ensure_js_deps_installed();
    run_shared_test(Host::Node, "runtime_no_redownload", &env_vars)
        .await
        .map_err(|e| anyhow!("runtime_no_redownload failed on Node host: {e}"))?;
    Ok(())
}
