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
use smoldot_e2e_tests::statement::*;
use smoldot_e2e_tests::*;

/// Smoldot keeps receiving statements after each of its peers disappears and
/// comes back.
///
/// Flow:
///   1. Spawn collator-0 + collator-1; smoldot connects and subscribes.
///   2. Submit stmt_1 via collator-0 → must arrive at smoldot.
///   3. Restart collator-0, wait for smoldot to reconnect, submit stmt_2 via
///      collator-0 → must arrive at smoldot.
///   4. Restart collator-1, wait for smoldot to reconnect, submit stmt_3 via
///      collator-1 → must arrive at smoldot.
#[tokio::test(flavor = "multi_thread")]
async fn recovers_statement_delivery_after_peer_restart() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let (seed, pubkey) = test_keypair();

    let base_dir = resolve_base_dir()?;
    let para_spec_path = create_para_chain_spec_with_allowances(&[pubkey], &base_dir)?;
    info!("Parachain chain spec created at {}", para_spec_path.display());

    let network = spawn_network(&base_dir, &para_spec_path).await?;
    info!("Network spawned");

    let (relay_spec_path, para_spec_path) = spawned_chain_spec_paths(&network)?;

    let topic = [0x11u8; 32];
    let stmt_1_hex = create_test_statement(&seed, &topic, b"peer-connection-stmt-1");
    let stmt_2_hex = create_test_statement(&seed, &topic, b"peer-connection-stmt-2");
    let stmt_3_hex = create_test_statement(&seed, &topic, b"peer-connection-stmt-3");
    let statement_hexes = format!("{stmt_1_hex},{stmt_2_hex},{stmt_3_hex}");

    info!("Ensuring smoldot JS bundle is built");
    ensure_smoldot_built();
    info!("Ensuring JS test dependencies are installed");
    ensure_js_deps_installed();

    let relay_spec_str = relay_spec_path.to_str().unwrap().to_string();
    let para_spec_str = para_spec_path.to_str().unwrap().to_string();

    info!("Spawning JS test: js/statement_store_peer_connection.js");
    let js_handle = tokio::spawn(async move {
        run_js_test(
            "js/statement_store_peer_connection.js",
            &[
                ("RELAY_CHAIN_SPEC", relay_spec_str.as_str()),
                ("PARA_CHAIN_SPEC", para_spec_str.as_str()),
                ("STATEMENT_HEXES", statement_hexes.as_str()),
            ],
        )
        .await
    });

    // Wait until smoldot has peered with collator-0, then submit the baseline
    // statement. Smoldot's statement-store only delivers statements received
    // over the gossip protocol while peered, so timing matters.
    let collator_0 = network.get_node("collator-0")?;
    wait_until_peered(collator_0, 2, 120).await?;
    submit_statement(collator_0, &stmt_1_hex, "stmt_1").await?;

    info!("Restarting collator-0");
    collator_0
        .restart(None)
        .await
        .map_err(|e| anyhow::anyhow!("restart(collator-0) failed: {e}"))?;
    wait_until_peered(collator_0, 2, 120).await?;
    submit_statement(collator_0, &stmt_2_hex, "stmt_2").await?;

    let collator_1 = network.get_node("collator-1")?;
    info!("Restarting collator-1");
    collator_1
        .restart(None)
        .await
        .map_err(|e| anyhow::anyhow!("restart(collator-1) failed: {e}"))?;
    wait_until_peered(collator_1, 2, 120).await?;
    submit_statement(collator_1, &stmt_3_hex, "stmt_3").await?;

    info!("Waiting for JS test to finish");
    let js_result = js_handle.await.expect("JS task panicked");
    js_result.map_err(|e| anyhow::anyhow!("JS test failed: {e}"))?;

    info!("Light node peer-connection test passed");
    Ok(())
}
