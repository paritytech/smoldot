use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::anyhow;
use ed25519_dalek::{Signer, SigningKey};
use log::info;
use serde_json::Value;
use smoldot::network::codec::{Proof, Statement, encode_statement};
use zombienet_sdk::{
    LocalFileSystem, Network, NetworkConfigBuilder,
    subxt::{
        backend::rpc::RpcClient,
        ext::subxt_rpcs::{client::RpcSubscription, rpc_params},
    },
};

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

/// Returns a deterministic Ed25519 keypair (seed, public key) for testing.
pub fn test_keypair() -> ([u8; 32], [u8; 32]) {
    let seed = [1u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey = signing_key.verifying_key().to_bytes();
    (seed, pubkey)
}

/// Subscribes to all statements on a full node.
pub async fn subscribe_any(
    rpc: &RpcClient,
) -> Result<RpcSubscription<Value>, anyhow::Error> {
    let subscription = rpc
        .subscribe::<Value>(
            "statement_subscribeStatement",
            rpc_params!["any"],
            "statement_unsubscribeStatement",
        )
        .await?;
    Ok(subscription)
}

/// Waits for a single statement from a subscription.
pub async fn expect_one_statement(
    subscription: &mut RpcSubscription<Value>,
    timeout_secs: u64,
) -> Result<Value, anyhow::Error> {
    loop {
        let item = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            subscription.next(),
        )
        .await
        .map_err(|_| anyhow!("Timeout waiting for statement after {timeout_secs}s"))?
        .ok_or_else(|| anyhow!("Subscription stream ended unexpectedly"))?
        .map_err(|e| anyhow!("Subscription error: {e}"))?;

        // StatementEvent is { "event": "newStatements", "data": { "statements": [...], ... } }
        if let Some(statements) = item
            .get("data")
            .and_then(|d| d.get("statements"))
            .and_then(|s| s.as_array())
        {
            if !statements.is_empty() {
                return Ok(item);
            }
        }
    }
}

/// Creates a signed Ed25519 statement and returns its hex-encoded form.
pub fn create_test_statement(seed: &[u8; 32], topic: &[u8; 32], data: &[u8]) -> String {
    let signing_key = SigningKey::from_bytes(seed);
    let pubkey = signing_key.verifying_key().to_bytes();

    // Expiry: upper 32 bits = u32::MAX (never expires), lower 32 bits = 0 (seq)
    let expiry: u64 = (u32::MAX as u64) << 32;

    // The signature covers the statement encoded without its proof field and without the
    // leading SCALE compact field-count prefix (first byte of `encode_statement`).
    let unsigned = Statement {
        proof: None,
        decryption_key: None,
        expiry,
        channel: None,
        topics: vec![*topic],
        data: Some(data.to_vec()),
    };
    let unsigned_bytes = encode_statement(&unsigned).expect("valid statement");
    let signature = signing_key.sign(&unsigned_bytes[1..]);

    let signed = Statement {
        proof: Some(Proof::Ed25519 {
            signature: signature.to_bytes(),
            signer: pubkey,
        }),
        ..unsigned
    };
    let encoded = encode_statement(&signed).expect("valid statement");

    format!("0x{}", hex::encode(&encoded))
}
