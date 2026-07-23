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

/// Regression test for <https://github.com/paritytech/smoldot/issues/3305>:
/// the browser delivering `RTCDataChannel`'s `open` event twice on the same
/// channel must not crash smoldot. Runs the smoke body on the browser host
/// (WebRTC) with a prepare extension that makes every `open` handler fire
/// twice; without the guard in `no-auto-bytecode-browser.ts` the wasm panics
/// with "same stream_id used multiple times in connection_stream_opened" on
/// the first substream. Browser-only: the Node host has no WebRTC.
#[tokio::test(flavor = "multi_thread")]
async fn webrtc_double_open() -> Result<(), anyhow::Error> {
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

    let relay_spec = live.relay_spec.to_str().expect("UTF-8 path");
    let para_spec = live.para_spec.to_str().expect("UTF-8 path");
    let required = REQUIRED_BLOCKS.to_string();
    let expected_finalized = live.expected_initial_finalized.to_string();
    let env_vars: Vec<(&str, &str)> = vec![
        ("RELAY_CHAIN_SPEC", relay_spec),
        ("PARA_CHAIN_SPEC", para_spec),
        ("REQUIRED_BLOCKS", required.as_str()),
        ("EXPECTED_INITIAL_FINALIZED", expected_finalized.as_str()),
    ];

    ensure_browser_deps_installed();
    run_shared_test(Host::Browser, "webrtc_double_open", &env_vars)
        .await
        .map_err(|e| anyhow!("browser webrtc_double_open test failed: {e}"))?;

    Ok(())
}
