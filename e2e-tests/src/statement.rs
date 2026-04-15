use std::time::Duration;

use anyhow::anyhow;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use zombienet_sdk::subxt::{
    backend::rpc::RpcClient,
    ext::subxt_rpcs::{client::RpcSubscription, rpc_params},
};

/// Returns a deterministic Ed25519 keypair (seed, public key) for testing.
pub fn test_keypair() -> ([u8; 32], [u8; 32]) {
    let seed = [1u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey = signing_key.verifying_key().to_bytes();
    (seed, pubkey)
}

/// Subscribes to all statements on a full node.
///
/// Same pattern as polkadot-sdk's `subscribe_topic`, but with a catch-all filter.
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
///
/// Same pattern as polkadot-sdk's `expect_one_statement`.
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

/// Encodes a SCALE compact integer (sufficient for values < 2^30).
fn encode_scale_compact(value: usize) -> Vec<u8> {
    if value < 0x40 {
        vec![(value as u8) << 2]
    } else if value < 0x4000 {
        let v = ((value as u16) << 2) | 0x01;
        v.to_le_bytes().to_vec()
    } else if value < 0x4000_0000 {
        let v = ((value as u32) << 2) | 0x02;
        v.to_le_bytes().to_vec()
    } else {
        panic!("Value too large for compact encoding");
    }
}

/// Creates a signed Ed25519 statement and returns its hex-encoded form.
///
/// The encoding follows the wire format defined in
/// `smoldot/lib/src/network/codec/statement.rs`.
pub fn create_test_statement(seed: &[u8; 32], topic: &[u8; 32], data: &[u8]) -> String {
    let signing_key = SigningKey::from_bytes(seed);
    let pubkey = signing_key.verifying_key().to_bytes();

    // Expiry: upper 32 bits = u32::MAX (never expires), lower 32 bits = 0 (seq)
    let expiry: u64 = (u32::MAX as u64) << 32;

    // Build signature material (encoded statement without proof and without field count prefix)
    let mut sig_material = Vec::new();
    sig_material.push(2); // FIELD_EXPIRY
    sig_material.extend_from_slice(&expiry.to_le_bytes());
    sig_material.push(4); // FIELD_TOPIC_START
    sig_material.extend_from_slice(topic);
    sig_material.push(8); // FIELD_DATA
    sig_material.extend_from_slice(&encode_scale_compact(data.len()));
    sig_material.extend_from_slice(data);

    let signature = signing_key.sign(&sig_material);

    // Build full encoded statement
    let mut encoded = Vec::new();

    // Field count: proof + expiry + topic + data = 4
    encoded.extend_from_slice(&encode_scale_compact(4));

    // FIELD_PROOF (discriminant 0)
    encoded.push(0);
    encoded.push(1); // PROOF_ED25519
    encoded.extend_from_slice(&signature.to_bytes());
    encoded.extend_from_slice(&pubkey);

    // FIELD_EXPIRY (discriminant 2)
    encoded.push(2);
    encoded.extend_from_slice(&expiry.to_le_bytes());

    // FIELD_TOPIC (discriminant 4)
    encoded.push(4);
    encoded.extend_from_slice(topic);

    // FIELD_DATA (discriminant 8)
    encoded.push(8);
    encoded.extend_from_slice(&encode_scale_compact(data.len()));
    encoded.extend_from_slice(data);

    format!("0x{}", hex::encode(&encoded))
}
