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

use std::time::{Duration, Instant};
use log::info;
use smoldot_e2e_tests::statement::*;
use smoldot_e2e_tests::*;
use zombienet_sdk::subxt::ext::subxt_rpcs::rpc_params;
use zombienet_sdk::NetworkNode;

async fn submit(node: &NetworkNode, stmt_hex: &str, label: &str) -> Result<(), anyhow::Error> {
    let rpc = node.rpc().await?;
    let res: serde_json::Value = rpc
        .request("statement_submit", rpc_params![&stmt_hex])
        .await?;
    info!("statement_submit({label}) on {} => {res}", node.name());
    Ok(())
}

/// Test: the light node keeps receiving statements after a peer it was using
/// disappears and comes back.
///
/// Flow:
///   1. Spawn collator-0 + collator-1. Smoldot connects and subscribes.
///   2. Baseline: submit stmt_1 via collator-0 → must arrive at smoldot.
///   3. `restart(collator-0)` — kill and respawn the process. Same PeerId (via
///      pinned `--node-key`), new sockets, no prior state continuity at the
///      libp2p layer.
///   4. Wait for smoldot to re-establish the connection.
///   5. Submit stmt_2 via the restarted collator-0 → must arrive at smoldot.
///      Delivery here proves smoldot re-dialled a peer it had already seen,
///      and re-negotiated the statement protocol on top of the new connection.
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
    let statement_hexes = format!("{stmt_1_hex},{stmt_2_hex}");

    let ready_file = tempfile::Builder::new().suffix(".ready").tempfile()?;
    let ready_path = ready_file.path().to_path_buf();
    std::fs::write(&ready_path, "")?;

    info!("Ensuring smoldot JS bundle is built");
    ensure_smoldot_built();
    info!("Ensuring JS test dependencies are installed");
    ensure_js_deps_installed();

    let relay_spec_str = relay_spec_path.to_str().unwrap().to_string();
    let para_spec_str = para_spec_path.to_str().unwrap().to_string();
    let ready_path_str = ready_path.to_str().unwrap().to_string();

    info!("Spawning JS test: js/statement_store_peer_connection.js");
    let js_handle = tokio::spawn(async move {
        run_js_test(
            "js/statement_store_peer_connection.js",
            &[
                ("RELAY_CHAIN_SPEC", relay_spec_str.as_str()),
                ("PARA_CHAIN_SPEC", para_spec_str.as_str()),
                ("STATEMENT_HEXES", statement_hexes.as_str()),
                ("READY_FD_PATH", ready_path_str.as_str()),
            ],
        )
        .await
    });

    info!(
        "Waiting up to 120s for JS READY signal at {}",
        ready_path.display()
    );
    let ready_deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let contents = tokio::fs::read_to_string(&ready_path)
            .await
            .unwrap_or_default();
        if contents.contains("READY") {
            break;
        }
        if Instant::now() >= ready_deadline {
            anyhow::bail!("Timed out waiting for JS READY signal");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    info!("JS signalled READY");

    // Baseline — delivery works before any disruption.
    submit(network.get_node("collator-0")?, &stmt_1_hex, "stmt_1").await?;
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Restart collator-0 (same PeerId via --node-key). This tears down all
    // libp2p connections and the statement-protocol substream with smoldot.
    info!("Restarting collator-0");
    network
        .get_node("collator-0")?
        .restart(None)
        .await
        .map_err(|e| anyhow::anyhow!("restart(collator-0) failed: {e}"))?;

    // Give smoldot time to redial via chain-spec bootnodes and reopen the
    // statement protocol. 45s is conservative; discovery backs off up to 120s.
    info!("Waiting 45s for smoldot to reconnect to collator-0");
    tokio::time::sleep(Duration::from_secs(45)).await;

    // Submit via the restarted peer. If smoldot successfully re-established
    // the statement protocol with it, gossip will deliver stmt_2.
    submit(network.get_node("collator-0")?, &stmt_2_hex, "stmt_2").await?;

    info!("Waiting for JS test to finish");
    let js_result = js_handle.await.expect("JS task panicked");
    js_result.map_err(|e| anyhow::anyhow!("JS test failed: {e}"))?;

    info!("Light node peer-connection test passed");
    Ok(())
}
