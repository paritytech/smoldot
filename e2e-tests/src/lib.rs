pub mod statement;

use std::path::{Path, PathBuf};

use anyhow::anyhow;
use log::info;
use serde_json::Value;
use zombienet_sdk::{LocalFileSystem, Network, NetworkConfigBuilder};

/// Creates a parachain chain spec with a statement allowance for the given public key.
///
/// Follows the same approach as polkadot-sdk's `create_chain_spec_with_allowances`:
/// loads a bundled template, injects the allowance into `genesis.raw.top`, writes to file.
pub fn create_para_chain_spec(
    pubkey: &[u8; 32],
    base_dir: &Path,
) -> Result<PathBuf, anyhow::Error> {
    let template = include_str!("../chain-specs/people-westend-local-spec.json");
    let mut spec: Value =
        serde_json::from_str(template).map_err(|e| anyhow!("Failed to parse chain spec: {e}"))?;

    let genesis = spec
        .get_mut("genesis")
        .and_then(|g| g.get_mut("raw"))
        .and_then(|r| r.get_mut("top"))
        .and_then(|t| t.as_object_mut())
        .ok_or_else(|| anyhow!("Failed to access genesis.raw.top in chain spec"))?;

    // Storage key: b":statement_allowance:" + pubkey (no hashing, well-known prefix)
    let prefix_hex = hex::encode(b":statement_allowance:");
    let pubkey_hex = hex::encode(pubkey);
    let storage_key = format!("0x{prefix_hex}{pubkey_hex}");

    // Storage value: SCALE-encoded StatementAllowance { max_count: 100u32, max_size: 1_000_000u32 }
    let max_count = 100u32;
    let max_size = 1_000_000u32;
    let mut allowance_bytes = Vec::with_capacity(8);
    allowance_bytes.extend_from_slice(&max_count.to_le_bytes());
    allowance_bytes.extend_from_slice(&max_size.to_le_bytes());
    let storage_value = format!("0x{}", hex::encode(&allowance_bytes));

    info!("Injecting statement allowance: key={storage_key}, value={storage_value}");
    genesis.insert(storage_key, Value::String(storage_value));

    let chain_spec_path = base_dir.join("people-westend-custom.json");
    let json = serde_json::to_string_pretty(&spec)?;
    std::fs::write(&chain_spec_path, json)?;

    Ok(chain_spec_path)
}

/// Spawns a zombienet network with relay chain + parachain (statement-store enabled).
///
/// Follows the same pattern as polkadot-sdk's `spawn_network_with_injected_allowances`.
pub async fn spawn_network(
    para_spec_path: &Path,
) -> Result<Network<LocalFileSystem>, anyhow::Error> {
    let images = zombienet_sdk::environment::get_images_from_env();

    let config = NetworkConfigBuilder::new()
        .with_relaychain(|r| {
            r.with_chain("westend-local")
                .with_default_command("polkadot")
                .with_default_image(images.polkadot.as_str())
                .with_default_args(vec!["-lparachain=debug".into()])
                .with_node(|node| node.with_name("validator-0"))
                .with_node(|node| node.with_name("validator-1"))
        })
        .with_parachain(|p| {
            p.with_id(1004)
                .with_chain_spec_path(para_spec_path.to_str().expect("Valid UTF-8 path"))
                .with_default_command("polkadot-parachain")
                .with_default_image(images.cumulus.as_str())
                .with_default_args(vec![
                    "--force-authoring".into(),
                    "--enable-statement-store".into(),
                    "-linfo,statement-store=info,statement-gossip=info".into(),
                ])
                .with_collator(|n| n.with_name("collator-0"))
                .with_collator(|n| n.with_name("collator-1"))
        })
        .build()
        .map_err(|e| {
            let errs = e
                .into_iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow!("config errors: {errs}")
        })?;

    let spawn_fn = zombienet_sdk::environment::get_spawn_fn();
    let network = spawn_fn(config).await?;
    network.detach().await;
    network.wait_until_is_up(120).await?;

    Ok(network)
}

/// Reads the relay chain spec and collects validator multiaddrs from the network.
pub fn get_relay_spec_and_bootnodes(
    network: &Network<LocalFileSystem>,
) -> Result<(String, Vec<String>), anyhow::Error> {
    let base_dir = network
        .base_dir()
        .ok_or_else(|| anyhow!("network has no base_dir"))?;

    let chain = network.relaychain().chain();
    let spec_path = PathBuf::from(base_dir).join(format!("{chain}.json"));
    let spec = std::fs::read_to_string(&spec_path)
        .map_err(|e| anyhow!("failed to read relay spec at {}: {e}", spec_path.display()))?;

    let bootnodes: Vec<String> = network
        .relaychain()
        .nodes()
        .iter()
        .map(|node| node.multiaddr().to_string())
        .collect();

    Ok((spec, bootnodes))
}

/// Collects collator multiaddrs from the parachain.
pub fn get_para_bootnodes(
    network: &Network<LocalFileSystem>,
) -> Result<Vec<String>, anyhow::Error> {
    let para = network
        .parachain(1004)
        .ok_or_else(|| anyhow!("parachain 1004 not found"))?;

    let bootnodes: Vec<String> = para
        .collators()
        .iter()
        .map(|node| node.multiaddr().to_string())
        .collect();

    Ok(bootnodes)
}

/// Patches a chain spec JSON with the given bootnodes.
pub fn patch_bootnodes(spec_json: &str, bootnodes: &[String]) -> String {
    let mut spec: Value = serde_json::from_str(spec_json).expect("invalid chain spec JSON");
    spec["bootNodes"] = Value::Array(bootnodes.iter().map(|b| Value::String(b.clone())).collect());
    serde_json::to_string_pretty(&spec).unwrap()
}

/// Writes a chain spec string to a temporary file.
pub fn write_temp_spec(content: &str) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut file = tempfile::Builder::new()
        .suffix(".json")
        .tempfile()
        .expect("failed to create temp file");
    file.write_all(content.as_bytes())
        .expect("failed to write temp spec");
    file.flush().unwrap();
    file
}

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Ensures the smoldot JS bundle is built.
pub fn ensure_smoldot_built() {
    let js_dir = project_root().join("wasm-node/javascript");
    let dist_dir = js_dir.join("dist");
    if dist_dir.exists() {
        return;
    }
    let status = std::process::Command::new("npm")
        .arg("run")
        .arg("build")
        .current_dir(&js_dir)
        .status()
        .expect("failed to run npm build");
    assert!(status.success(), "smoldot npm build failed");
}

/// Ensures JS test dependencies are installed.
pub fn ensure_js_deps_installed() {
    let js_dir = project_root().join("e2e-tests/js");
    let node_modules = js_dir.join("node_modules");
    if node_modules.exists() {
        return;
    }
    let status = std::process::Command::new("npm")
        .arg("install")
        .current_dir(&js_dir)
        .status()
        .expect("failed to run npm install");
    assert!(status.success(), "npm install in e2e-tests/js failed");
}

/// Runs a JS test script with the given environment variables.
///
/// Uses `tokio::process::Command` for async compatibility.
pub async fn run_js_test(script: &str, env_vars: &[(&str, &str)]) -> Result<(), String> {
    let e2e_dir = project_root().join("e2e-tests");
    let script_path = e2e_dir.join(script);

    let mut cmd = tokio::process::Command::new("node");
    cmd.arg(&script_path);
    cmd.current_dir(&e2e_dir);
    for (key, val) in env_vars {
        cmd.env(key, val);
    }

    let output = cmd.output().await.expect("failed to run node");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("--- JS stdout ---\n{stdout}");
    eprintln!("--- JS stderr ---\n{stderr}");

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "JS test exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status, stdout, stderr
        ))
    }
}
