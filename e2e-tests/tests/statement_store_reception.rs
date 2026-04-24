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
use smoldot::network::codec::statement_hash;
use smoldot_e2e_tests::statement::*;
use smoldot_e2e_tests::*;

fn decode_hex_0x(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("valid hex")
}

/// Smoldot delivers statements that match its subscription filter, dedups
/// across peers, and drops statements outside the filter.
///
/// Flow:
///   1. Spawn collator-0 + collator-1.
///   2. Submit stmt_A (topic A) and stmt_B (topic B) to collator-0; wait for
///      both to reach collator-1 so the two full nodes hold the same set.
///   3. Start smoldot; it peers with both collators and subscribes to topic A.
///   4. Smoldot must deliver stmt_A to the subscriber exactly once, never
///      deliver stmt_B, and never deliver any unrelated statement.
#[tokio::test(flavor = "multi_thread")]
async fn receives_only_subscribed_statements() -> Result<(), anyhow::Error> {
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

    // Two statements with distinct topics. stmt_A is subscribed; stmt_B is not.
    let topic_a = [0xaau8; 32];
    let topic_b = [0xbbu8; 32];
    let stmt_a_hex = create_test_statement(&seed, &topic_a, b"reception-test-A");
    let stmt_b_hex = create_test_statement(&seed, &topic_b, b"reception-test-B");
    let hash_a = statement_hash(&decode_hex_0x(&stmt_a_hex));
    let hash_b = statement_hash(&decode_hex_0x(&stmt_b_hex));
    info!(
        "stmt_A hash={}, stmt_B hash={}",
        hex::encode(hash_a),
        hex::encode(hash_b)
    );

    // Submit both statements to collator-0, then confirm they reach collator-1
    // via gossip. Once confirmed, both collators hold the same statements and
    // smoldot will see them from each peer.
    let collator_0 = network.get_node("collator-0")?;
    submit_statement(collator_0, &stmt_a_hex, "stmt_A").await?;
    submit_statement(collator_0, &stmt_b_hex, "stmt_B").await?;

    let rpc_1 = network.get_node("collator-1")?.rpc().await?;
    let mut sub_1 = subscribe_any(&rpc_1).await?;

    let received = receive_statements(2, &mut sub_1, 120).await?;
    assert!(received.contains(&stmt_a_hex) && received.contains(&stmt_b_hex));
    info!("Both statements confirmed on collator-1 via gossip");

    info!("Ensuring smoldot JS bundle is built");
    ensure_smoldot_built();
    info!("Ensuring JS test dependencies are installed");
    ensure_js_deps_installed();

    let topic_a_hex = format!("0x{}", hex::encode(topic_a));

    info!("Running JS test: js/statement_store_reception.js (topicA={topic_a_hex})");
    run_js_test(
        "js/statement_store_reception.js",
        &[
            ("RELAY_CHAIN_SPEC", relay_spec_path.to_str().unwrap()),
            ("PARA_CHAIN_SPEC", para_spec_path.to_str().unwrap()),
            ("TOPIC_A", topic_a_hex.as_str()),
            ("STATEMENT_A_HEX", stmt_a_hex.as_str()),
            ("STATEMENT_B_HEX", stmt_b_hex.as_str()),
        ],
    )
    .await
    .map_err(|e| anyhow::anyhow!("JS test failed: {e}"))?;

    info!("Light node reception test passed");
    Ok(())
}
