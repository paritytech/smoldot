// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

//! "Database" encoding and decoding.
//!
//! The light client is capable of serializing the state of the finalized block, which is called
//! a database. It is not really what is commonly called a database, but rather simply a small
//! JSON document.
//! It can later de-serialize this database.
//!
//! This database doesn't contain just the state of the finalized block, but also other
//! information. See [`DatabaseContent`].
//!
//! This module provides the function to encode and decode this so-called database.

use alloc::{
    borrow::ToOwned as _,
    boxed::Box,
    format,
    string::{String, ToString as _},
    vec::Vec,
};
use core::cmp;
use smoldot::{
    chain,
    database::finalized_serialize,
    libp2p::{PeerId, multiaddr},
};

use crate::{network_service, platform, runtime_service, sync_service};

pub use smoldot::trie::Nibble;

/// A decoded database.
pub struct DatabaseContent {
    /// Hash of the genesis block, as provided to [`encode_database`].
    pub genesis_block_hash: [u8; 32],

    /// Information about the finalized chain.
    pub chain_information: Option<chain::chain_information::ValidChainInformation>,

    /// List of nodes that were known to be part of the peer-to-peer network when the database
    /// was encoded.
    pub known_nodes: Vec<(PeerId, Vec<multiaddr::Multiaddr>)>,

    /// Known valid Merkle value and storage value combination for the `:code` key.
    ///
    /// Does **not** necessarily match the finalized block found in
    /// [`DatabaseContent::chain_information`].
    pub runtime_code_hint: Option<DatabaseContentRuntimeCodeHint>,
}

/// See [`DatabaseContent::runtime_code_hint`].
#[derive(Debug, Clone)]
pub struct DatabaseContentRuntimeCodeHint {
    /// Merkle value of the `:code` trie node in the storage main trie.
    pub code_merkle_value: Vec<u8>,
    /// Closest ancestor of the `:code` key except for `:code` itself.
    // TODO: this punches a bit through abstraction layers, but it's temporary
    pub closest_ancestor_excluding: Vec<Nibble>,
}

/// Serializes the finalized state of the chain, using the given services.
///
/// The returned string is guaranteed to not exceed `max_size` bytes. A truncated or invalid
/// database is intentionally returned if `max_size` is too low to fit all the information.
pub async fn encode_database<TPlat: platform::PlatformRef>(
    network_service: &network_service::NetworkServiceChain<TPlat>,
    sync_service: &sync_service::SyncService<TPlat>,
    runtime_service: &runtime_service::RuntimeService<TPlat>,
    genesis_block_hash: &[u8; 32],
    max_size: usize,
) -> String {
    let (_code_storage_value, code_merkle_value, code_closest_ancestor_excluding) = runtime_service
        .finalized_runtime_storage_merkle_values()
        .await
        .unwrap_or((None, None, None));

    // Craft the structure containing all the data that we would like to include.
    let mut database_draft = SerdeDatabase {
        genesis_hash: hex::encode(genesis_block_hash),
        chain: sync_service.serialize_chain_information().await.map(|ci| {
            let encoded = finalized_serialize::encode_chain(&ci, sync_service.block_number_bytes());
            serde_json::from_str(&encoded).unwrap()
        }),
        nodes: network_service
            .discovered_nodes()
            .await
            .map(|(peer_id, addrs)| {
                (
                    peer_id.to_base58(),
                    addrs.map(|a| a.to_string()).collect::<Vec<_>>(),
                )
            })
            .collect(),
        code_merkle_value: code_merkle_value.map(hex::encode),
        code_storage_value: None,
        code_closest_ancestor_excluding: code_closest_ancestor_excluding.map(|key| {
            key.iter()
                .map(|nibble| format!("{:x}", nibble))
                .collect::<String>()
        }),
    };

    // Cap the database length to the maximum size.
    loop {
        let serialized = serde_json::to_string(&database_draft).unwrap();
        if serialized.len() <= max_size {
            // Success!
            return serialized;
        }

        // Scrap the code, as it is the biggest item.
        if database_draft.code_merkle_value.is_some() || database_draft.code_storage_value.is_some()
        {
            database_draft.code_merkle_value = None;
            database_draft.code_storage_value = None;
            continue;
        }

        if database_draft.nodes.is_empty() {
            // Can't shrink the database anymore. Return the string `"<too-large>"` which will
            // fail to decode but will indicate what is wrong.
            let dummy_message = "<too-large>";
            return if dummy_message.len() > max_size {
                String::new()
            } else {
                dummy_message.to_owned()
            };
        }

        // Try to reduce the size of the database.

        // Remove half of the nodes.
        // Which nodes are removed doesn't really matter.
        let mut nodes_to_remove = cmp::max(1, database_draft.nodes.len() / 2);
        database_draft.nodes.retain(|_, _| {
            if nodes_to_remove >= 1 {
                nodes_to_remove -= 1;
                false
            } else {
                true
            }
        });
    }
}

/// Tries to decode the given database.
///
/// An error is returned if the data is in an invalid format.
///
/// Must be passed the number of bytes used to encode the number of a block for the given chain.
pub fn decode_database(encoded: &str, block_number_bytes: usize) -> Result<DatabaseContent, ()> {
    let decoded: SerdeDatabase = serde_json::from_str(encoded).map_err(|_| ())?;

    let genesis_block_hash = if decoded.genesis_hash.len() == 64 {
        <[u8; 32]>::try_from(hex::decode(&decoded.genesis_hash).map_err(|_| ())?).unwrap()
    } else {
        return Err(());
    };

    let chain_information = match &decoded.chain {
        Some(chain) => Some(
            finalized_serialize::decode_chain(
                &serde_json::to_string(chain).unwrap(),
                block_number_bytes,
            )
            .map_err(|_| ())?
            .chain_information,
        ),
        None => None,
    };

    // Nodes that fail to decode are simply ignored. This is especially important for
    // multiaddresses, as the definition of a valid or invalid multiaddress might change across
    // versions.
    let known_nodes = decoded
        .nodes
        .iter()
        .filter_map(|(peer_id, addrs)| {
            let addrs = addrs
                .iter()
                .filter_map(|a| a.parse::<multiaddr::Multiaddr>().ok())
                .collect();
            Some((peer_id.parse::<PeerId>().ok()?, addrs))
        })
        .collect::<Vec<_>>();

    let runtime_code_hint = match (
        decoded.code_merkle_value,
        decoded.code_closest_ancestor_excluding,
    ) {
        (Some(mv), Some(an)) => Some(DatabaseContentRuntimeCodeHint {
            code_merkle_value: hex::decode(mv).map_err(|_| ())?,
            closest_ancestor_excluding: an
                .as_bytes()
                .iter()
                .map(|char| Nibble::from_ascii_hex_digit(*char).ok_or(()))
                .collect::<Result<Vec<Nibble>, ()>>()?,
        }),
        _ => None,
    };

    Ok(DatabaseContent {
        genesis_block_hash,
        chain_information,
        known_nodes,
        runtime_code_hint,
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerdeDatabase {
    /// Hexadecimal-encoded hash of the genesis block header. Has no `0x` prefix.
    #[serde(rename = "genesisHash")]
    genesis_hash: String,
    #[serde(default = "Default::default", skip_serializing_if = "Option::is_none")]
    chain: Option<Box<serde_json::value::RawValue>>,
    nodes: hashbrown::HashMap<String, Vec<String>, fnv::FnvBuildHasher>,
    #[serde(
        rename = "runtimeCode",
        default = "Default::default",
        skip_serializing_if = "Option::is_none"
    )]
    code_storage_value: Option<String>,
    #[serde(
        rename = "codeMerkleValue",
        default = "Default::default",
        skip_serializing_if = "Option::is_none"
    )]
    code_merkle_value: Option<String>,
    #[serde(
        rename = "codeClosestAncestor",
        default = "Default::default",
        skip_serializing_if = "Option::is_none"
    )]
    code_closest_ancestor_excluding: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_db_json_with_code(code_size: usize) -> String {
        let fake_code = vec![0x42u8; code_size];
        let code_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, &fake_code);
        let merkle_hex = hex::encode([0xAAu8; 32]);
        format!(
            r#"{{"genesisHash":"{}","nodes":{{}},"runtimeCode":"{}","codeMerkleValue":"{}","codeClosestAncestor":"3a"}}"#,
            hex::encode([0u8; 32]),
            code_b64,
            merkle_hex,
        )
    }

    fn make_db_json_without_code() -> String {
        let merkle_hex = hex::encode([0xAAu8; 32]);
        format!(
            r#"{{"genesisHash":"{}","nodes":{{}},"codeMerkleValue":"{}","codeClosestAncestor":"3a"}}"#,
            hex::encode([0u8; 32]),
            merkle_hex,
        )
    }

    #[test]
    fn decode_db_without_code_is_fast() {
        let db = make_db_json_without_code();
        assert!(db.len() < 300);

        let start = std::time::Instant::now();
        for _ in 0..100 {
            let result = decode_database(&db, 4);
            assert!(result.is_ok());
            let content = result.unwrap();
            assert!(content.runtime_code_hint.is_some());
        }
        let elapsed = start.elapsed();
        // 100 decodes of a small DB should take well under 100ms.
        assert!(
            elapsed.as_millis() < 100,
            "100 decodes took {elapsed:?}, expected < 100ms"
        );
    }

    #[test]
    fn decode_db_with_legacy_code_field_still_works() {
        // Old databases contain a runtimeCode field. decode_database must still
        // accept them (backwards compatibility), but the code field is ignored.
        let db = make_db_json_with_code(2_000_000);
        assert!(db.len() > 2_000_000);

        let result = decode_database(&db, 4);
        assert!(result.is_ok());
        let content = result.unwrap();
        // The hint is present (merkle value + ancestor were in the JSON).
        assert!(content.runtime_code_hint.is_some());
        let hint = content.runtime_code_hint.unwrap();
        assert_eq!(hint.code_merkle_value, vec![0xAAu8; 32]);
    }

    #[test]
    fn new_encode_omits_runtime_code() {
        // Verify that SerdeDatabase with code_storage_value: None serializes
        // without the runtimeCode field.
        let db = SerdeDatabase {
            genesis_hash: hex::encode([0u8; 32]),
            chain: None,
            nodes: Default::default(),
            code_merkle_value: Some(hex::encode([0xBBu8; 32])),
            code_storage_value: None,
            code_closest_ancestor_excluding: Some("3a".to_owned()),
        };
        let json = serde_json::to_string(&db).unwrap();
        assert!(!json.contains("runtimeCode"));
        assert!(json.contains("codeMerkleValue"));
        assert!(json.contains("codeClosestAncestor"));
        // DB without code should be tiny.
        assert!(json.len() < 300);
    }

    #[test]
    fn decode_with_code_much_slower_than_without() {
        // Demonstrates the performance problem: decoding a database with a 2 MiB
        // base64-encoded runtime code blob is orders of magnitude slower than
        // decoding one without it.
        let db_with_code = make_db_json_with_code(2_000_000);
        let db_without_code = make_db_json_without_code();

        assert!(
            db_with_code.len() > 2_600_000,
            "DB with 2 MiB code should be >2.6 MB (base64 overhead), got {}",
            db_with_code.len()
        );
        assert!(
            db_without_code.len() < 300,
            "DB without code should be <300 bytes, got {}",
            db_without_code.len()
        );

        let iterations = 10;

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = decode_database(&db_with_code, 4).unwrap();
        }
        let with_code_elapsed = start.elapsed();

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = decode_database(&db_without_code, 4).unwrap();
        }
        let without_code_elapsed = start.elapsed();

        // The database with code should be at least 10x slower to decode.
        // In practice it's 100-1000x slower (native) or more (Wasm).
        let ratio = with_code_elapsed.as_nanos() / without_code_elapsed.as_nanos().max(1);
        assert!(
            ratio >= 10,
            "Expected decode with 2 MiB code to be >=10x slower than without. \
             With code: {:?}, without: {:?}, ratio: {}x",
            with_code_elapsed,
            without_code_elapsed,
            ratio,
        );

        eprintln!(
            "decode_database benchmark ({iterations} iterations):\n  \
             with 2 MiB code:    {:?} ({:.1}ms/iter, JSON size: {} bytes)\n  \
             without code:       {:?} ({:.1}ms/iter, JSON size: {} bytes)\n  \
             ratio: {}x slower with code",
            with_code_elapsed,
            with_code_elapsed.as_secs_f64() / iterations as f64 * 1000.0,
            db_with_code.len(),
            without_code_elapsed,
            without_code_elapsed.as_secs_f64() / iterations as f64 * 1000.0,
            db_without_code.len(),
            ratio,
        );
    }

    #[test]
    fn database_size_comparison() {
        // Documents the database size impact of storing runtime code.
        let db_with_code = make_db_json_with_code(2_000_000);
        let db_without_code = make_db_json_without_code();

        let size_with = db_with_code.len();
        let size_without = db_without_code.len();
        let reduction_pct = (1.0 - size_without as f64 / size_with as f64) * 100.0;

        eprintln!(
            "Database size comparison:\n  \
             with 2 MiB runtime code: {} bytes ({:.1} MB)\n  \
             without runtime code:    {} bytes ({:.1} KB)\n  \
             reduction: {:.1}%",
            size_with,
            size_with as f64 / 1_000_000.0,
            size_without,
            size_without as f64 / 1_000.0,
            reduction_pct,
        );

        // The database without code should be <0.1% of the size with code.
        assert!(size_without * 1000 < size_with);
    }
}
