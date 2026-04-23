use std::time::{Duration, Instant};

use log::info;
use smoldot::network::codec::statement_hash;
use smoldot_e2e_tests::statement::*;
use smoldot_e2e_tests::*;
use zombienet_sdk::subxt::ext::subxt_rpcs::rpc_params;

fn decode_hex_0x(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("valid hex")
}

#[tokio::test(flavor = "multi_thread")]
async fn light_node_receives_only_subscribed_statements() -> Result<(), anyhow::Error> {
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

    // Prepare a READY signal file the JS will write when peered + subscribed.
    let ready_file = tempfile::Builder::new()
        .suffix(".ready")
        .tempfile()?;
    let ready_path = ready_file.path().to_path_buf();
    std::fs::write(&ready_path, "")?;

    // Spawn JS light node concurrently with Rust waiting for READY.
    info!("Ensuring smoldot JS bundle is built");
    ensure_smoldot_built();
    info!("Ensuring JS test dependencies are installed");
    ensure_js_deps_installed();

    let relay_spec_str = relay_spec_path.to_str().unwrap().to_string();
    let para_spec_str = para_spec_path.to_str().unwrap().to_string();
    let topic_a_hex = format!("0x{}", hex::encode(topic_a));
    let ready_path_str = ready_path.to_str().unwrap().to_string();
    let stmt_a_hex_for_js = stmt_a_hex.clone();
    let stmt_b_hex_for_js = stmt_b_hex.clone();

    info!("Spawning JS test: js/light_node_reception.js (topicA={topic_a_hex})");
    let js_handle = tokio::spawn(async move {
        run_js_test(
            "js/light_node_reception.js",
            &[
                ("RELAY_CHAIN_SPEC", relay_spec_str.as_str()),
                ("PARA_CHAIN_SPEC", para_spec_str.as_str()),
                ("TOPIC_A", topic_a_hex.as_str()),
                ("STATEMENT_A_HEX", stmt_a_hex_for_js.as_str()),
                ("STATEMENT_B_HEX", stmt_b_hex_for_js.as_str()),
                ("READY_FD_PATH", ready_path_str.as_str()),
            ],
        )
        .await
    });

    // Wait for JS to signal READY (subscription active, peers settled).
    info!("Waiting up to 120s for JS READY signal at {}", ready_path.display());
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

    // Submit both statements on collator-0. They will propagate via gossip to
    // the smoldot light node through two independent paths (collator-0 and
    // collator-1 → smoldot), exercising smoldot's per-subscription dedup.
    let collator0 = network.get_node("collator-0")?;
    let rpc0 = collator0.rpc().await?;

    let submit_a: serde_json::Value = rpc0
        .request("statement_submit", rpc_params![&stmt_a_hex])
        .await?;
    info!("statement_submit(stmt_A) on collator-0 => {submit_a}");
    let submit_b: serde_json::Value = rpc0
        .request("statement_submit", rpc_params![&stmt_b_hex])
        .await?;
    info!("statement_submit(stmt_B) on collator-0 => {submit_b}");

    info!("Waiting for JS test to finish");
    let js_result = js_handle.await.expect("JS task panicked");
    js_result.map_err(|e| anyhow::anyhow!("JS test failed: {e}"))?;

    info!("Light node reception test passed");
    Ok(())
}
