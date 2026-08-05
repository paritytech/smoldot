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

/// Smoldot serves the `statement_unstable_*` JSON-RPC API: filters are attached
/// to a subscription and detached from it, only statements matching an attached
/// filter are reported, and each one carries the ids of the filters it matched.
///
/// Flow:
///   1. Spawn alice + bob.
///   2. Submit stmt_A and stmt_B to alice; wait for both to reach bob via
///      gossip, so that both collators hold them.
///   3. Start smoldot; it subscribes, turns down the filters the specification
///      doesn't define, then attaches a `matchAll` filter on stmt_A's topic.
///   4. Smoldot must report `replayDone` for that filter, then deliver stmt_A
///      exactly once carrying the filter id, and never stmt_B.
///   5. The filter is detached and the subscription closed, both answering null.
#[tokio::test(flavor = "multi_thread")]
async fn serves_the_unstable_statement_api() -> Result<(), anyhow::Error> {
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

    // Subscribe on bob first so we don't miss gossip from alice. Bind the RPC
    // client — dropping it closes the websocket and terminates the subscription.
    let alice = network.get_node("alice")?;
    let bob = network.get_node("bob")?;
    let bob_rpc = bob.rpc().await?;
    let mut bob_sub = subscribe_any(&bob_rpc).await?;

    info!("Ensuring smoldot JS bundle is built");
    ensure_smoldot_built();
    info!("Ensuring JS test dependencies are installed");
    ensure_js_deps_installed();

    // Statements *and topics* need to be distinct per host, otherwise they
    // persist in the collators' store and get pushed to the next host during
    // the initial sync.
    for (idx, host) in [Host::Node].into_iter().enumerate() {
        let mut topic_a = [0xaau8; 32];
        let mut topic_b = [0xbbu8; 32];
        topic_a[31] = idx as u8;
        topic_b[31] = idx as u8;
        let stmt_a_hex = create_test_statement(
            &seed,
            &topic_a,
            format!("spec-api-test-A-{host:?}").as_bytes(),
        );
        let stmt_b_hex = create_test_statement(
            &seed,
            &topic_b,
            format!("spec-api-test-B-{host:?}").as_bytes(),
        );

        submit_statement(alice, &stmt_a_hex, "stmt_A").await?;
        submit_statement(alice, &stmt_b_hex, "stmt_B").await?;

        let received = receive_statements(2, &mut bob_sub, 120).await?;
        assert!(received.contains(&stmt_a_hex) && received.contains(&stmt_b_hex));
        info!("Both statements confirmed on bob via gossip");

        let sync = SyncFile::new()?;
        let sync_path_str = sync.path().to_str().unwrap().to_string();

        let topic_a_hex = format!("0x{}", hex::encode(topic_a));
        let relay_spec_str = relay_spec_path.to_str().unwrap().to_string();
        let para_spec_str = para_spec_path.to_str().unwrap().to_string();
        let stmt_a_hex_js = stmt_a_hex.clone();
        let stmt_b_hex_js = stmt_b_hex.clone();
        let topic_a_hex_js = topic_a_hex.clone();

        info!("Spawning test statement_store_spec_api within host {host:?} (topicA={topic_a_hex})");
        let js_handle = tokio::spawn(async move {
            run_shared_test(
                host,
                "statement_store_spec_api",
                &[
                    ("RELAY_CHAIN_SPEC", relay_spec_str.as_str()),
                    ("PARA_CHAIN_SPEC", para_spec_str.as_str()),
                    ("TOPIC_A", topic_a_hex_js.as_str()),
                    ("STATEMENT_A_HEX", stmt_a_hex_js.as_str()),
                    ("STATEMENT_B_HEX", stmt_b_hex_js.as_str()),
                    ("SYNC_PATH", sync_path_str.as_str()),
                ],
            )
            .await
        });

        // Wait for smoldot to peer with both collators at the statement-store
        // level. Each collator already holds stmt_A, and pushes it once it
        // learns about smoldot's topic affinity.
        wait_until_peered(alice, 1, 120).await?;
        wait_until_peered(bob, 1, 120).await?;

        sync.send("READY")?;
        info!("Signalled JS READY");

        let js_result = js_handle.await.expect("JS task panicked");
        js_result.map_err(|e| anyhow::anyhow!("JS test failed: {e}"))?;

        info!("Unstable statement API test passed on host {host:?}");
    }
    Ok(())
}
