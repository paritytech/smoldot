pub mod statement;

use std::path::{Path, PathBuf};

use anyhow::anyhow;
use log::info;
use serde_json::Value;
use zombienet_sdk::{LocalFileSystem, Network, NetworkConfigBuilder};

/// Para id used by the statement-store e2e fixture. Zombienet writes the
/// final chain-spec (with bootnodes patched in) to `<base_dir>/<para_id>.json`.
pub const PARA_ID: u32 = 1004;

/// Well-known prefix for the per-account statement allowance storage key.
pub const STATEMENT_ALLOWANCE_PREFIX: &[u8] = b":statement_allowance:";

/// Constructs a per-account statement allowance storage key.
///
/// # Arguments
/// * `account_id` - Account identifier as byte slice
///
/// # Returns
/// Storage key: `":statement_allowance:" ++ account_id`
pub fn statement_allowance_key(account_id: impl AsRef<[u8]>) -> Vec<u8> {
    let mut key = STATEMENT_ALLOWANCE_PREFIX.to_vec();
    key.extend_from_slice(account_id.as_ref());
    key
}

/// Resolves the base directory tests share with zombienet.
///
/// Mirrors polkadot-sdk's convention: honour `ZOMBIENET_SDK_BASE_DIR` if set,
/// otherwise fall back to a per-pid temp dir. Zombienet is configured (via
/// `with_global_settings`) to use the same path, so the chain-specs it emits
/// land where the tests can read them back.
pub fn resolve_base_dir() -> Result<PathBuf, anyhow::Error> {
    let path = std::env::var("ZOMBIENET_SDK_BASE_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(format!("zombienet-{}", std::process::id())));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

/// Template for the statement-store parachain chain spec.
///
/// Bundled rather than generated on the fly — polkadot-sdk's statement-store
/// zombienet tests use the same approach (see `cumulus/zombienet/.../common.rs`).
/// Regenerated via the `create_people_westend_spec.sh` script in
/// paritytech/individuality.
const PEOPLE_WESTEND_LOCAL_SPEC: &str =
    include_str!("../chain-specs/people-westend-local-spec.json");

/// Creates a parachain chain spec with a statement allowance for each given public key.
pub fn create_para_chain_spec_with_allowances(
    pubkeys: &[[u8; 32]],
    base_dir: &Path,
) -> Result<PathBuf, anyhow::Error> {
    let mut spec: Value = serde_json::from_str(PEOPLE_WESTEND_LOCAL_SPEC)
        .map_err(|e| anyhow!("Failed to parse chain spec: {e}"))?;

    let genesis = spec
        .get_mut("genesis")
        .and_then(|g| g.get_mut("raw"))
        .and_then(|r| r.get_mut("top"))
        .and_then(|t| t.as_object_mut())
        .ok_or_else(|| anyhow!("Failed to access genesis.raw.top in chain spec"))?;

    // Storage value: SCALE-encoded StatementAllowance { max_count: 100u32, max_size: 1_000_000u32 }
    let max_count = 100u32;
    let max_size = 1_000_000u32;
    let mut allowance_bytes = Vec::with_capacity(8);
    allowance_bytes.extend_from_slice(&max_count.to_le_bytes());
    allowance_bytes.extend_from_slice(&max_size.to_le_bytes());
    let storage_value = format!("0x{}", hex::encode(&allowance_bytes));

    for pubkey in pubkeys {
        let storage_key = format!("0x{}", hex::encode(statement_allowance_key(pubkey)));
        info!("Injecting statement allowance: key={storage_key}, value={storage_value}");
        genesis.insert(storage_key, Value::String(storage_value.clone()));
    }

    let chain_spec_path = base_dir.join("people-westend-custom.json");
    let json = serde_json::to_string_pretty(&spec)?;
    std::fs::write(&chain_spec_path, json)?;

    Ok(chain_spec_path)
}

/// Spawns a zombienet network with relay chain + parachain (statement-store enabled).
///
/// All relay validators and parachain collators are marked as bootnodes, so the
/// chain-spec files zombienet writes into `base_dir` end up with a fully populated
/// `bootNodes` array — smoldot can then consume those files directly without any
/// post-spawn patching.
pub async fn spawn_network(
    base_dir: &Path,
    para_spec_path: &Path,
) -> Result<Network<LocalFileSystem>, anyhow::Error> {
    let images = zombienet_sdk::environment::get_images_from_env();
    let base_dir_str = base_dir.to_str().expect("base_dir is valid UTF-8").to_owned();

    let config = NetworkConfigBuilder::new()
        .with_relaychain(|r| {
            r.with_chain("westend-local")
                .with_default_command("polkadot")
                .with_default_image(images.polkadot.as_str())
                .with_default_args(vec!["-lparachain=debug".into()])
                .with_node(|node| node.with_name("validator-0").bootnode(true))
                .with_node(|node| node.with_name("validator-1").bootnode(true))
        })
        .with_parachain(|p| {
            p.with_id(PARA_ID)
                .with_chain_spec_path(para_spec_path.to_str().expect("Valid UTF-8 path"))
                .with_default_command("polkadot-parachain")
                .with_default_image(images.cumulus.as_str())
                .with_default_args({
                    let log_filter = std::env::var("SMOLDOT_E2E_COLLATOR_LOG")
                        .unwrap_or_else(|_| {
                            "info,statement-store=info,statement-gossip=info".to_string()
                        });
                    let log_arg = format!("-l{log_filter}");
                    vec![
                        "--force-authoring".into(),
                        "--enable-statement-store".into(),
                        log_arg.as_str().into(),
                    ]
                })
                .with_collator(|n| n.with_name("collator-0").bootnode(true))
                .with_collator(|n| n.with_name("collator-1").bootnode(true))
        })
        .with_global_settings(|g| g.with_base_dir(base_dir_str.as_str()))
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

/// Returns the chain-spec files zombienet emits for the relay chain and the
/// statement-store parachain. Both already include the bootnodes — no patching
/// required. Paths live under `network.base_dir()`.
pub fn spawned_chain_spec_paths(
    network: &Network<LocalFileSystem>,
) -> Result<(PathBuf, PathBuf), anyhow::Error> {
    let base_dir = PathBuf::from(
        network
            .base_dir()
            .ok_or_else(|| anyhow!("network has no base_dir"))?,
    );

    let relay_chain = network.relaychain().chain();
    let relay_path = base_dir.join(format!("{relay_chain}.json"));

    let para = network
        .parachain(PARA_ID)
        .ok_or_else(|| anyhow!("parachain {PARA_ID} not found"))?;
    let para_path = base_dir.join(format!("{}.json", para.unique_id()));

    info!(
        "Resolved chain-spec paths: relay={}, para={}",
        relay_path.display(),
        para_path.display()
    );
    Ok((relay_path, para_path))
}

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Ensures the smoldot JS bundle is built and up to date.
///
/// Rebuilds if the `dist` directory is missing, or if any Rust source under
/// `wasm-node/rust` is newer than the bundle. This matters during development
/// when `lib.rs` has changed since the last build — the cached `dist` can lag.
pub fn ensure_smoldot_built() {
    let js_dir = project_root().join("wasm-node/javascript");
    let dist_dir = js_dir.join("dist");
    let needs_build = !dist_dir.exists() || is_dist_stale(&dist_dir);
    if !needs_build {
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

fn is_dist_stale(dist_dir: &Path) -> bool {
    let Ok(dist_mtime) = dist_dir.metadata().and_then(|m| m.modified()) else {
        return true;
    };
    let sources = [
        project_root().join("wasm-node/rust"),
        project_root().join("lib"),
        project_root().join("light-base"),
    ];
    for src in &sources {
        if walk_newer_than(src, dist_mtime) {
            return true;
        }
    }
    false
}

fn walk_newer_than(path: &Path, cutoff: std::time::SystemTime) -> bool {
    let Ok(meta) = path.metadata() else {
        return false;
    };
    if meta.is_file() {
        return meta.modified().map(|m| m > cutoff).unwrap_or(false);
    }
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            // Skip target and node_modules — they churn without affecting the bundle.
            if matches!(name.to_str(), Some("target") | Some("node_modules")) {
                continue;
            }
            if walk_newer_than(&entry.path(), cutoff) {
                return true;
            }
        }
    }
    false
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
