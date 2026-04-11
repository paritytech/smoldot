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

    /// Runtime code hint that is known to match [`DatabaseContent::chain_information`].
    pub finalized_runtime: Option<DatabaseContentFinalizedRuntime>,
}

/// See [`DatabaseContent::runtime_code_hint`].
#[derive(Debug, Clone)]
pub struct DatabaseContentRuntimeCodeHint {
    /// Storage value of the `:code` trie node corresponding to
    /// [`DatabaseContentRuntimeCodeHint::code_merkle_value`].
    pub code: Vec<u8>,
    /// Merkle value of the `:code` trie node in the storage main trie.
    pub code_merkle_value: Vec<u8>,
    /// Closest ancestor of the `:code` key except for `:code` itself.
    // TODO: this punches a bit through abstraction layers, but it's temporary
    pub closest_ancestor_excluding: Vec<Nibble>,
}

/// See [`DatabaseContent::finalized_runtime`].
#[derive(Debug, Clone)]
pub struct DatabaseContentFinalizedRuntime {
    pub code: Vec<u8>,
    pub code_merkle_value: Vec<u8>,
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
    let runtime_snapshot = runtime_service
        .finalized_runtime_storage_merkle_values()
        .await;
    let chain_information = sync_service.serialize_chain_information().await;

    let finalized_runtime = runtime_snapshot.as_ref().and_then(|snapshot| {
        let chain_information = chain_information.as_ref()?;
        let chain_information = chain_information.as_ref();

        if chain_information
            .finalized_block_header
            .hash(sync_service.block_number_bytes())
            != snapshot.finalized_block_hash
            || *chain_information.finalized_block_header.state_root
                != snapshot.finalized_block_state_root_hash
        {
            return None;
        }

        Some(SerdeFinalizedRuntime {
            block_hash: hex::encode(snapshot.finalized_block_hash),
            state_root: hex::encode(snapshot.finalized_block_state_root_hash),
        })
    });

    let code_storage_value = runtime_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.runtime_code.clone());
    let code_merkle_value = runtime_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.code_merkle_value.clone());
    let code_closest_ancestor_excluding = runtime_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.closest_ancestor_excluding.clone());

    // Craft the structure containing all the data that we would like to include.
    let mut database_draft = SerdeDatabase {
        genesis_hash: hex::encode(genesis_block_hash),
        chain: chain_information.map(|ci| {
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
        // While it might seem like a good idea to compress the runtime code, in practice it is
        // normally already zstd-compressed, and additional compressing shouldn't improve the size.
        code_storage_value: code_storage_value.map(|data| {
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, data)
        }),
        code_closest_ancestor_excluding: code_closest_ancestor_excluding.map(|key| {
            key.iter()
                .map(|nibble| format!("{:x}", nibble))
                .collect::<String>()
        }),
        finalized_runtime,
    };

    // Cap the database length to the maximum size.
    loop {
        let serialized = serde_json::to_string(&database_draft).unwrap();
        if serialized.len() <= max_size {
            // Success!
            return serialized;
        }

        // Scrap the code, as it is the biggest item.
        if database_draft.finalized_runtime.is_some()
            || database_draft.code_merkle_value.is_some()
            || database_draft.code_storage_value.is_some()
            || database_draft.code_closest_ancestor_excluding.is_some()
        {
            database_draft.finalized_runtime = None;
            database_draft.code_merkle_value = None;
            database_draft.code_storage_value = None;
            database_draft.code_closest_ancestor_excluding = None;
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

    let code_storage_value = decoded
        .code_storage_value
        .map(|sv| base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, sv))
        .transpose()
        .map_err(|_| ())?;
    let code_merkle_value = decoded
        .code_merkle_value
        .map(hex::decode)
        .transpose()
        .map_err(|_| ())?;
    let code_closest_ancestor_excluding = decoded
        .code_closest_ancestor_excluding
        .map(|an| {
            an.as_bytes()
                .iter()
                .map(|char| Nibble::from_ascii_hex_digit(*char).ok_or(()))
                .collect::<Result<Vec<Nibble>, ()>>()
        })
        .transpose()?;

    let runtime_code_hint = match (
        &code_merkle_value,
        &code_storage_value,
        &code_closest_ancestor_excluding,
    ) {
        (Some(mv), Some(sv), Some(an)) => Some(DatabaseContentRuntimeCodeHint {
            code: sv.clone(),
            code_merkle_value: mv.clone(),
            closest_ancestor_excluding: an.clone(),
        }),
        // A combination of `Some` and `None` is technically invalid, but we simply ignore this
        // situation.
        _ => None,
    };

    let finalized_runtime = match (
        &code_storage_value,
        &code_merkle_value,
        &code_closest_ancestor_excluding,
        decoded.finalized_runtime,
    ) {
        (
            Some(code_storage_value),
            Some(code_merkle_value),
            Some(code_closest_ancestor_excluding),
            Some(SerdeFinalizedRuntime {
                block_hash,
                state_root,
            }),
        ) if block_hash.len() == 64 && state_root.len() == 64 => {
            let block_hash =
                <[u8; 32]>::try_from(hex::decode(block_hash).map_err(|_| ())?).unwrap();
            let state_root =
                <[u8; 32]>::try_from(hex::decode(state_root).map_err(|_| ())?).unwrap();

            let matches_chain_information = chain_information.as_ref().map_or(false, |ci| {
                let ci = ci.as_ref();
                ci.finalized_block_header.hash(block_number_bytes) == block_hash
                    && *ci.finalized_block_header.state_root == state_root
            });

            if matches_chain_information {
                Some(DatabaseContentFinalizedRuntime {
                    code: code_storage_value.clone(),
                    code_merkle_value: code_merkle_value.clone(),
                    closest_ancestor_excluding: code_closest_ancestor_excluding.clone(),
                })
            } else {
                None
            }
        }
        _ => None,
    };

    Ok(DatabaseContent {
        genesis_block_hash,
        chain_information,
        known_nodes,
        runtime_code_hint,
        finalized_runtime,
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
    #[serde(
        rename = "finalizedRuntime",
        default = "Default::default",
        skip_serializing_if = "Option::is_none"
    )]
    finalized_runtime: Option<SerdeFinalizedRuntime>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerdeFinalizedRuntime {
    #[serde(rename = "blockHash")]
    block_hash: String,
    #[serde(rename = "stateRoot")]
    state_root: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_chain_information() -> chain::chain_information::ValidChainInformation {
        let chain_spec = smoldot::chain_spec::ChainSpec::from_json_bytes(include_str!(
            "../../lib/src/chain_spec/tests/example.json"
        ))
        .unwrap();
        chain_spec.to_chain_information().unwrap().0
    }

    fn database_with_finalized_runtime(
        chain_information: &chain::chain_information::ValidChainInformation,
        block_hash: [u8; 32],
        state_root: [u8; 32],
        include_runtime_hint: bool,
    ) -> String {
        let runtime_hint = if include_runtime_hint {
            r#"
                ,"codeMerkleValue":"1111111111111111111111111111111111111111111111111111111111111111",
                "codeClosestAncestor":"1234"
            "#
        } else {
            ""
        };

        format!(
            r#"{{
                "genesisHash":"{genesis_hash}",
                "chain":{chain},
                "nodes":{{}},
                "runtimeCode":"AQID",
                "finalizedRuntime":{{
                    "blockHash":"{block_hash}",
                    "stateRoot":"{state_root}",
                    "heapPages":"BAU"
                }}{runtime_hint}
            }}"#,
            genesis_hash = "00".repeat(32),
            chain = finalized_serialize::encode_chain(chain_information, 4),
            block_hash = hex::encode(block_hash),
            state_root = hex::encode(state_root),
            runtime_hint = runtime_hint,
        )
    }

    #[test]
    fn test_decodes_block_bound_finalized_runtime_with_merkle_hint() {
        let chain_information = example_chain_information();
        let block_hash = chain_information.as_ref().finalized_block_header.hash(4);
        let state_root = *chain_information.as_ref().finalized_block_header.state_root;

        let database = decode_database(
            &database_with_finalized_runtime(&chain_information, block_hash, state_root, true),
            4,
        )
        .unwrap();

        let finalized_runtime = database.finalized_runtime.unwrap();
        assert_eq!(finalized_runtime.code, vec![1, 2, 3]);
        assert_eq!(finalized_runtime.code_merkle_value, vec![0x11; 32]);
        assert_eq!(finalized_runtime.closest_ancestor_excluding.len(), 4);
        assert!(database.runtime_code_hint.is_some());
    }

    #[test]
    fn test_rejects_finalized_runtime_without_merkle_hint() {
        let chain_information = example_chain_information();
        let block_hash = chain_information.as_ref().finalized_block_header.hash(4);
        let state_root = *chain_information.as_ref().finalized_block_header.state_root;

        let database = decode_database(
            &database_with_finalized_runtime(&chain_information, block_hash, state_root, false),
            4,
        )
        .unwrap();

        assert!(database.finalized_runtime.is_none());
        assert!(database.runtime_code_hint.is_none());
    }

    #[test]
    fn test_rejects_finalized_runtime_for_different_block() {
        let chain_information = example_chain_information();
        let block_hash = [1; 32];
        let state_root = *chain_information.as_ref().finalized_block_header.state_root;

        let database = decode_database(
            &database_with_finalized_runtime(&chain_information, block_hash, state_root, true),
            4,
        )
        .unwrap();

        assert!(database.finalized_runtime.is_none());
    }
}
