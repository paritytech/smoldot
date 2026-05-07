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

/// Browser sanity check: smoldot's browser bundle running inside headless
/// Chromium can submit a statement (ping) and receive a gossiped statement
/// (pong) against a real zombienet network.
///
/// Flow:
///   1. Spawn alice + bob.
///   2. Submit stmt_B to alice; wait for it to reach bob via gossip.
///   3. Launch the Playwright runner; the page subscribes to topic_B.
///   4. Wait for smoldot to peer with both collators.
///   5. Signal READY. The page then submits stmt_A (ping) and waits for
///      stmt_B to arrive on its subscription (pong).
///   6. Wait for stmt_A to reach alice via gossip, then signal DONE so the
///      page tears down smoldot and exits.
#[tokio::test(flavor = "multi_thread")]
async fn browser_ping_pong() -> Result<(), anyhow::Error> {
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

    // Two distinct topics. stmt_A is what the browser submits; stmt_B is what
    // the browser receives via gossip.
    let topic_a = [0xaau8; 32];
    let topic_b = [0xbbu8; 32];
    let stmt_a_hex = create_test_statement(&seed, &topic_a, b"browser-ping");
    let stmt_b_hex = create_test_statement(&seed, &topic_b, b"browser-pong");

    let alice = network.get_node("alice")?;
    let bob = network.get_node("bob")?;

    // Pre-populate stmt_B on the network so collators push it to the browser
    // light client during initial statement-store sync.
    let bob_rpc = bob.rpc().await?;
    let mut bob_sub = subscribe_any(&bob_rpc).await?;
    submit_statement(alice, &stmt_b_hex, "stmt_B").await?;
    let received = receive_statements(1, &mut bob_sub, 120).await?;
    assert!(received.contains(&stmt_b_hex), "stmt_B did not reach bob");
    info!("stmt_B confirmed on bob via gossip");

    info!("Ensuring smoldot JS bundle is built");
    ensure_smoldot_built();
    info!("Ensuring browser test dependencies are installed");
    ensure_browser_deps_installed();

    let sync = SyncFile::new()?;
    let sync_path_str = sync.path().to_str().unwrap().to_string();

    let topic_b_hex = format!("0x{}", hex::encode(topic_b));
    let relay_spec_str = relay_spec_path.to_str().unwrap().to_string();
    let para_spec_str = para_spec_path.to_str().unwrap().to_string();
    let stmt_a_hex_js = stmt_a_hex.clone();
    let stmt_b_hex_js = stmt_b_hex.clone();

    info!("Spawning browser test: browser/statement_store_browser.js");
    let browser_handle = tokio::spawn(async move {
        run_browser_test(
            "statement_store_browser.js",
            &[
                ("RELAY_CHAIN_SPEC", relay_spec_str.as_str()),
                ("PARA_CHAIN_SPEC", para_spec_str.as_str()),
                ("STATEMENT_A_HEX", stmt_a_hex_js.as_str()),
                ("STATEMENT_B_HEX", stmt_b_hex_js.as_str()),
                ("TOPIC_B", topic_b_hex.as_str()),
                ("SYNC_PATH", sync_path_str.as_str()),
            ],
        )
        .await
    });

    // Wait for smoldot (running inside the browser) to peer with both
    // collators at the statement-store level.
    wait_until_peered(alice, 2, 180).await?;
    wait_until_peered(bob, 2, 180).await?;

    // Subscribe on alice before signalling READY so we don't miss stmt_A
    // gossiped from the browser.
    let alice_rpc = alice.rpc().await?;
    let mut alice_sub = subscribe_any(&alice_rpc).await?;

    // Smoldot is peered and stmt_B is in both collators' stores; signal the
    // page to perform the ping and start awaiting the pong.
    sync.send("READY")?;
    info!("Signalled browser READY");

    // Verify stmt_A submitted by the browser reached alice via gossip *before*
    // releasing the browser. Outbound gossip from the browser's smoldot
    // light-client is asynchronous: `statement_submit` returning `status:"new"`
    // only proves local insertion. If the page calls `client.terminate()`
    // immediately after the pong arrives, the in-flight gossip of stmt_A is
    // aborted on slow runners and alice never sees it. So: keep the browser
    // alive (DONE handshake below) until alice has actually observed stmt_A.
    //
    // Read two statements because the subscription replays stmt_B (already in
    // alice's store when the subscription was opened) before stmt_A arrives.
    let received = receive_statements(2, &mut alice_sub, 180).await?;
    assert!(
        received.contains(&stmt_a_hex),
        "stmt_A submitted from the browser did not reach alice"
    );
    info!("stmt_A confirmed on alice via gossip");

    // Release the browser — it can now terminate the smoldot client and exit.
    sync.send("DONE")?;
    info!("Signalled browser DONE");

    let result = browser_handle.await.expect("browser task panicked");
    result.map_err(|e| anyhow::anyhow!("browser test failed: {e}"))?;

    info!("Browser sanity check passed");
    Ok(())
}
