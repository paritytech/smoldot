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

    /// Raw bytes of the runtime code (`:code` storage value) saved from the last session.
    ///
    /// When present, a parachain warm-start can compile this code locally and skip the ~2 MiB
    /// P2P runtime download, falling back to cold bootstrap only on failure.
    pub runtime_code: Option<Vec<u8>>,
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
    let (code_storage_value, code_merkle_value, code_closest_ancestor_excluding) = runtime_service
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

    let (runtime_code_hint, runtime_code) = match (
        decoded.code_merkle_value,
        decoded.code_storage_value,
        decoded.code_closest_ancestor_excluding,
    ) {
        (Some(mv), Some(sv), Some(an)) => {
            let code =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, &sv)
                    .map_err(|_| ())?;
            let hint = DatabaseContentRuntimeCodeHint {
                code: code.clone(),
                code_merkle_value: hex::decode(mv).map_err(|_| ())?,
                closest_ancestor_excluding: an
                    .as_bytes()
                    .iter()
                    .map(|char| Nibble::from_ascii_hex_digit(*char).ok_or(()))
                    .collect::<Result<Vec<Nibble>, ()>>()?,
            };
            (Some(hint), Some(code))
        }
        // When only the storage value is present (no merkle value / ancestor), we still
        // expose the raw code for the parachain warm-start path.
        (None, Some(sv), _) => {
            let code =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, &sv)
                    .map_err(|_| ())?;
            (None, Some(code))
        }
        // A combination of `Some` and `None` for the hint fields is technically invalid, but
        // we simply ignore this situation.
        _ => (None, None),
    };

    Ok(DatabaseContent {
        genesis_block_hash,
        chain_information,
        known_nodes,
        runtime_code_hint,
        runtime_code,
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
