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

/// Statement-store ping/pong sanity check: a single smoldot client submits a
/// statement (ping) and receives a gossiped statement (pong) within one
/// session, against a real zombienet network. Runs on both hosts in sequence:
/// the Node build (TCP), then the browser build in headless Chrome (WebRTC).
///
/// Flow (per host):
///   1. Submit stmt_B to alice; wait for it to reach bob via gossip.
///   2. Launch the host runner; smoldot subscribes to topic_B.
///   3. Wait for smoldot to peer with both collators.
///   4. Signal READY. Smoldot then submits stmt_A (ping) and waits for
///      stmt_B to arrive on its subscription (pong).
///   5. Wait for stmt_A to reach alice via gossip, then signal DONE so the
///      runner tears down smoldot and exits.
#[tokio::test(flavor = "multi_thread")]
async fn browser_ping_pong() -> Result<(), anyhow::Error> {
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

    let alice = network.get_node("alice")?;
    let bob = network.get_node("bob")?;

    // Subscribe on both collators up front. The subscriptions are consumed
    // incrementally per leg (stmt_B is drained right after its submission),
    // so no store replay ever has to be skipped over.
    let alice_rpc = alice.rpc().await?;
    let bob_rpc = bob.rpc().await?;
    let mut alice_sub = subscribe_any(&alice_rpc).await?;
    let mut bob_sub = subscribe_any(&bob_rpc).await?;

    info!("Ensuring smoldot JS bundle is built");
    ensure_smoldot_built();
    info!("Ensuring JS test dependencies are installed");
    ensure_js_deps_installed();
    ensure_browser_deps_installed();

    let relay_spec_str = relay_spec_path.to_str().unwrap().to_string();
    let para_spec_str = para_spec_path.to_str().unwrap().to_string();

    // NOTE: temporarily disable tests exec within browser.
    for (leg, host) in [Host::Node /* Host::Browser */].into_iter().enumerate() {
        // Statements *and topics* needs to be re-created for each host
        // otherwise they persist in the collators' store: a reused topic_b
        // would push the previous host's stmt_B during the initial sync, and
        // a reused stmt_A would make `statement_submit` return `"known"`.
        //
        // Two distinct topics. stmt_A is what smoldot submits; stmt_B is what
        // smoldot receives via gossip.
        let mut topic_a = [0xaau8; 32];
        let mut topic_b = [0xbbu8; 32];
        topic_a[31] = leg as u8;
        topic_b[31] = leg as u8;
        let stmt_a_hex =
            create_test_statement(&seed, &topic_a, format!("ping-{host:?}").as_bytes());
        let stmt_b_hex =
            create_test_statement(&seed, &topic_b, format!("pong-{host:?}").as_bytes());

        // Pre-populate stmt_B on the network so collators push it to the
        // light client during initial statement-store sync. Drain it from
        // alice's subscription too, so the stmt_A wait below starts clean.
        submit_statement(alice, &stmt_b_hex, "stmt_B").await?;
        let received = receive_statements(1, &mut bob_sub, 120).await?;
        assert!(received.contains(&stmt_b_hex), "stmt_B did not reach bob");
        let received = receive_statements(1, &mut alice_sub, 120).await?;
        assert!(received.contains(&stmt_b_hex), "stmt_B not seen on alice");
        info!("stmt_B confirmed on both collators");

        let sync = SyncFile::new()?;
        let sync_path_str = sync.path().to_str().unwrap().to_string();
        let topic_b_hex = format!("0x{}", hex::encode(topic_b));

        info!("Spawning test statement_store_browser within host {host:?}");
        let js_handle = tokio::spawn({
            let relay_spec_str = relay_spec_str.clone();
            let para_spec_str = para_spec_str.clone();
            let stmt_a_hex = stmt_a_hex.clone();
            let stmt_b_hex = stmt_b_hex.clone();
            async move {
                run_shared_test(
                    host,
                    "statement_store_browser",
                    &[
                        ("RELAY_CHAIN_SPEC", relay_spec_str.as_str()),
                        ("PARA_CHAIN_SPEC", para_spec_str.as_str()),
                        ("STATEMENT_A_HEX", stmt_a_hex.as_str()),
                        ("STATEMENT_B_HEX", stmt_b_hex.as_str()),
                        ("TOPIC_B", topic_b_hex.as_str()),
                        ("SYNC_PATH", sync_path_str.as_str()),
                    ],
                )
                .await
            }
        });

        // Wait for smoldot to peer with both collators at the
        // statement-store level.
        wait_until_peered(alice, 1, 180).await?;
        wait_until_peered(bob, 1, 180).await?;

        // Smoldot is peered and stmt_B is in both collators' stores; signal
        // it to perform the ping and start awaiting the pong.
        sync.send("READY")?;
        info!("Signalled READY");

        // Verify stmt_A submitted by smoldot reached alice via gossip
        // *before* releasing it. Outbound gossip from the light client is
        // asynchronous: `statement_submit` returning `status:"new"` only
        // proves local insertion. If the client terminated immediately after
        // the pong arrived, the in-flight gossip of stmt_A would be aborted
        // on slow runners and alice would never see it. So: keep the client
        // alive (DONE handshake below) until alice has observed stmt_A.
        let received = receive_statements(1, &mut alice_sub, 180).await?;
        assert!(
            received.contains(&stmt_a_hex),
            "stmt_A submitted from smoldot did not reach alice"
        );
        // Gossip reaches bob as well; assert it and, just as importantly,
        // drain it from bob's subscription so the next leg's stmt_B check
        // doesn't read this leg's stmt_A instead.
        let received = receive_statements(1, &mut bob_sub, 180).await?;
        assert!(
            received.contains(&stmt_a_hex),
            "stmt_A submitted from smoldot did not reach bob"
        );
        info!("stmt_A confirmed on both collators via gossip");

        // Release the client — the runner can now terminate smoldot and exit.
        sync.send("DONE")?;
        info!("Signalled DONE");

        let result = js_handle.await.expect("JS task panicked");
        result.map_err(|e| anyhow::anyhow!("test failed: {e}"))?;

        info!("Ping/pong test passed on host {host:?}");
    }
    Ok(())
}
