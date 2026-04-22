use std::time::Duration;

use anyhow::anyhow;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use smoldot::network::codec::{Proof, Statement, encode_statement};
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
