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

use log::info;
use smoldot_e2e_tests::*;
use smoldot_e2e_tests::statement::*;

/// A statement submitted by smoldot propagates to the full-node network.
///
/// Flow:
///   1. Spawn alice + bob; subscribe on both over RPC.
///   2. Start smoldot; it peers with the collators and submits a statement.
///   3. Both collators must deliver that exact statement to their subscribers.
#[tokio::test(flavor = "multi_thread")]
async fn statement_reaches_full_node() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    // Setup
    let (seed, pubkey) = test_keypair();

    let base_dir = resolve_base_dir()?;
    let para_spec_path = create_para_chain_spec_with_allowances(&[pubkey], &base_dir)?;
    info!("Parachain chain spec created at {}", para_spec_path.display());

    let network = spawn_network(&base_dir, &para_spec_path).await?;
    info!("Network spawned");

    let (relay_spec_path, para_spec_path) = spawned_chain_spec_paths(&network)?;

    // Create statement in Rust
    let topic = [0u8; 32];
    let data = b"light-node-submission-test";
    let statement_hex = create_test_statement(&seed, &topic, data);
    info!("Test statement created ({} bytes encoded)", statement_hex.len() / 2);

    // Subscribe on both collators
    let alice_rpc = network.get_node("alice")?.rpc().await?;
    let bob_rpc = network.get_node("bob")?.rpc().await?;
    let mut alice_sub = subscribe_any(&alice_rpc).await?;
    let mut bob_sub = subscribe_any(&bob_rpc).await?;
    info!("Subscribed to statements on alice and bob");

    // Ensure smoldot is built and JS deps are installed
    info!("Ensuring smoldot JS bundle is built");
    ensure_smoldot_built();
    info!("Ensuring JS test dependencies are installed");
    ensure_js_deps_installed();

    // Run smoldot JS test and wait for statement concurrently
    let relay_spec_str = relay_spec_path.to_str().unwrap().to_string();
    let para_spec_str = para_spec_path.to_str().unwrap().to_string();
    let statement_hex_clone = statement_hex.clone();

    info!(
        "Spawning JS test: js/statement_store_submission.js (relay_spec={}, para_spec={})",
        relay_spec_str, para_spec_str
    );
    let js_handle = tokio::spawn(async move {
        run_js_test(
            "js/statement_store_submission.js",
            &[
                ("RELAY_CHAIN_SPEC", relay_spec_str.as_str()),
                ("PARA_CHAIN_SPEC", para_spec_str.as_str()),
                ("STATEMENT_HEX", statement_hex_clone.as_str()),
            ],
        )
        .await
    });

    info!("Waiting up to 180s for statement to arrive on both collators");
    let (alice_received, bob_received) = tokio::try_join!(
        receive_statements(1, &mut alice_sub, 180),
        receive_statements(1, &mut bob_sub, 180),
    )?;
    assert_eq!(alice_received[0], statement_hex);
    assert_eq!(bob_received[0], statement_hex);
    info!("Submitted statement received on both alice and bob");

    info!("Waiting for JS test to finish");
    let js_result = js_handle.await.expect("JS task panicked");
    js_result.map_err(|e| anyhow::anyhow!("JS test failed: {e}"))?;
    info!("JS test finished successfully");

    info!("Light node statement submission test passed");
    Ok(())
}
