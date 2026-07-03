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
///   1. Spawn alice + bob; smoldot connects and subscribes.
///   2. Submit stmt_1 via alice → must arrive at smoldot.
///   3. Restart alice, wait for smoldot to reconnect, submit stmt_2 via
///      alice → must arrive at smoldot.
///   4. Restart bob, wait for smoldot to reconnect, submit stmt_3 via
///      bob → must arrive at smoldot.
#[tokio::test(flavor = "multi_thread")]
async fn recovers_statement_delivery_after_peer_restart() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let (seed, pubkey) = test_keypair();

    let base_dir = resolve_base_dir()?;
    let para_spec_path = create_para_chain_spec_with_allowances(&[pubkey], &base_dir)?;
    info!(
        "Parachain chain spec created at {}",
        para_spec_path.display()
    );

    let network = spawn_network(&base_dir, &para_spec_path).await?;
    info!("Network spawned");

    let (relay_base, para_base) = spawned_chain_spec_paths(&network)?;

    let base_dir_str = base_dir.to_str().expect("UTF-8 path").to_owned();
    let (relay_spec_path, para_spec_path) =
        prepare_runtime_specs(&network, &relay_base, &para_base, &base_dir_str).await?;

    let topic = [0x11u8; 32];

    info!("Ensuring smoldot JS bundle is built");
    ensure_smoldot_built();
    info!("Ensuring JS test dependencies are installed");
    ensure_js_deps_installed();
    ensure_browser_deps_installed();

    let relay_spec_str = relay_spec_path.to_str().unwrap().to_string();
    let para_spec_str = para_spec_path.to_str().unwrap().to_string();

    for host in [Host::Node, Host::Browser] {
        // Statements needs to be re-created for each host otherwise they
        // persist in the collators' store and get pushed to the next host
        // right away during the initial sync, making the test pass without
        // exercising any restart.
        let stmt_1_hex =
            create_test_statement(&seed, &topic, format!("stmt-1-{host:?}").as_bytes());
        let stmt_2_hex =
            create_test_statement(&seed, &topic, format!("stmt-2-{host:?}").as_bytes());
        let stmt_3_hex =
            create_test_statement(&seed, &topic, format!("stmt-3-{host:?}").as_bytes());
        let statement_hexes = format!("{stmt_1_hex},{stmt_2_hex},{stmt_3_hex}");

        info!("Spawning test statement_store_peer_connection within host {:?}", host);
        let js_handle = tokio::spawn({
            let relay_spec_str = relay_spec_str.clone();
            let para_spec_str = para_spec_str.clone();
            let statement_hexes = statement_hexes.clone();
            async move {
            run_shared_test(
                host,
                "statement_store_peer_connection",
                &[
                    ("RELAY_CHAIN_SPEC", relay_spec_str.as_str()),
                    ("PARA_CHAIN_SPEC", para_spec_str.as_str()),
                    ("STATEMENT_HEXES", statement_hexes.as_str()),
                ],
            )
            .await
        }});

        // Wait until smoldot has peered with alice, then submit the baseline
        // statement. Smoldot's statement-store only delivers statements received
        // over the gossip protocol while peered, so timing matters.
        let alice = network.get_node("alice")?;
        wait_until_peered(alice, 1, 120).await?;
        submit_statement(alice, &stmt_1_hex, "stmt_1").await?;

        info!("Restarting alice");
        alice
            .restart(None)
            .await
            .map_err(|e| anyhow::anyhow!("restart(alice) failed: {e}"))?;
        wait_until_peered(alice, 1, 120).await?;
        submit_statement(alice, &stmt_2_hex, "stmt_2").await?;

        let bob = network.get_node("bob")?;
        info!("Restarting bob");
        bob.restart(None)
            .await
            .map_err(|e| anyhow::anyhow!("restart(bob) failed: {e}"))?;
        wait_until_peered(bob, 1, 120).await?;
        submit_statement(bob, &stmt_3_hex, "stmt_3").await?;

        info!("Waiting for JS test to finish");
        let js_result = js_handle.await.expect("JS task panicked");
        js_result.map_err(|e| anyhow::anyhow!("JS test failed: {e}"))?;

        info!("Light node peer-connection test passed");
    }
    Ok(())
}
