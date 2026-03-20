use std::path::PathBuf;

use log::info;
use smoldot_e2e_tests::*;
use smoldot_e2e_tests::statement::*;

#[tokio::test(flavor = "multi_thread")]
async fn light_node_statement_reaches_full_node() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    // Setup
    let (seed, pubkey) = test_keypair();

    let base_dir = std::env::var("ZOMBIENET_SDK_BASE_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(format!("zombienet-{}", std::process::id())));
    std::fs::create_dir_all(&base_dir)?;

    let para_spec_path = create_para_chain_spec(&pubkey, &base_dir)?;
    info!("Parachain chain spec created at {}", para_spec_path.display());

    let network = spawn_network(&para_spec_path).await?;
    info!("Network spawned");

    // Prepare chain specs with bootnodes for smoldot
    let (relay_spec, relay_bootnodes) = get_relay_spec_and_bootnodes(&network)?;
    let para_spec = std::fs::read_to_string(&para_spec_path)?;
    let para_bootnodes = get_para_bootnodes(&network)?;

    let relay_spec_file = write_temp_spec(&patch_bootnodes(&relay_spec, &relay_bootnodes));
    let para_spec_file = write_temp_spec(&patch_bootnodes(&para_spec, &para_bootnodes));

    info!(
        "Relay bootnodes: {:?}, Para bootnodes: {:?}",
        relay_bootnodes, para_bootnodes
    );

    // Create statement in Rust
    let topic = [0u8; 32];
    let data = b"light-node-submission-test";
    let statement_hex = create_test_statement(&seed, &topic, data);
    info!("Test statement created ({} bytes encoded)", statement_hex.len() / 2);

    // Subscribe on collator-1 (verify statement reaches a node that may not be directly
    // connected to smoldot, proving gossip propagation)
    let collator = network.get_node("collator-1")?;
    let rpc = collator.rpc().await?;
    let mut sub = subscribe_any(&rpc).await?;
    info!("Subscribed to statements on collator-1");

    // Ensure smoldot is built and JS deps are installed
    ensure_smoldot_built();
    ensure_js_deps_installed();

    // Run smoldot JS test and wait for statement concurrently
    let relay_spec_str = relay_spec_file.path().to_str().unwrap().to_string();
    let para_spec_str = para_spec_file.path().to_str().unwrap().to_string();
    let statement_hex_clone = statement_hex.clone();

    let js_handle = tokio::spawn(async move {
        run_js_test(
            "js/light_node_submission.js",
            &[
                ("RELAY_CHAIN_SPEC", relay_spec_str.as_str()),
                ("PARA_CHAIN_SPEC", para_spec_str.as_str()),
                ("STATEMENT_HEX", statement_hex_clone.as_str()),
            ],
        )
        .await
    });

    let received = expect_one_statement(&mut sub, 180).await?;
    info!("Statement received on full node: {:?}", received);

    let js_result = js_handle.await.expect("JS task panicked");
    js_result.map_err(|e| anyhow::anyhow!("JS test failed: {e}"))?;

    info!("Light node statement submission test passed");
    Ok(())
}
