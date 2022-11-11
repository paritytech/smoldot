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
    string::{String, ToString as _},
    vec::Vec,
};
use core::cmp;
use smoldot::{
    chain,
    database::finalized_serialize,
    libp2p::{multiaddr, PeerId},
};

use crate::{network_service, platform, sync_service};

/// A decoded database.
pub struct DatabaseContent {
    /// Hash of the genesis block, as provided to [`encode_database`].
    pub genesis_block_hash: [u8; 32],
    /// Information about the finalized chain.
    pub chain_information: chain::chain_information::ValidChainInformation,
    /// List of nodes that were known to be part of the peer-to-peer network when the database
    /// was encoded.
    pub known_nodes: Vec<(PeerId, Vec<multiaddr::Multiaddr>)>,
}

/// Serializes the finalized state of the chain, using the given services.
///
/// The returned string is guaranteed to not exceed `max_size` bytes. A truncated or invalid
/// database is intentionally returned if `max_size` is too low to fit all the information.
pub async fn encode_database<TPlat: platform::Platform>(
    network_service: &network_service::NetworkService<TPlat>,
    sync_service: &sync_service::SyncService<TPlat>,
    genesis_block_hash: &[u8; 32],
    max_size: usize,
) -> String {
    // Craft the structure containing all the data that we would like to include.
    let mut database_draft = SerdeDatabase {
        genesis_hash: hex::encode(genesis_block_hash),
        chain: match sync_service.serialize_chain_information().await {
            Some(ci) => {
                let encoded =
                    finalized_serialize::encode_chain(&ci, sync_service.block_number_bytes());
                serde_json::from_str(&encoded).unwrap()
            }
            None => {
                // If the chain information can't be obtained, we just return a dummy value that
                // will intentionally fail to decode if passed back.
                let dummy_message = "<unknown>";
                return if dummy_message.len() > max_size {
                    String::new()
                } else {
                    dummy_message.to_owned()
                };
            }
        },
        nodes: network_service
            .discovered_nodes(0) // TODO: hacky chain_index
            .await
            .map(|(peer_id, addrs)| {
                (
                    peer_id.to_base58(),
                    addrs.map(|a| a.to_string()).collect::<Vec<_>>(),
                )
            })
            .collect(),
    };

    // Cap the database length to the maximum size.
    loop {
        let serialized = serde_json::to_string(&database_draft).unwrap();
        if serialized.len() <= max_size {
            // Success!
            return serialized;
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

    let (chain_information, _) = finalized_serialize::decode_chain(
        &serde_json::to_string(&decoded.chain).unwrap(),
        block_number_bytes,
    )
    .map_err(|_| ())?;

    // Nodes that fail to decode are simply ignored. This is especially important for
    // multiaddresses, as the definition of a valid or invalid multiaddress might change across
    // versions.
    let known_nodes = decoded
        .nodes
        .iter()
        .filter_map(|(peer_id, addrs)| {
            let addrs = addrs
                .iter()
                .filter_map(|a| Some(a.parse::<multiaddr::Multiaddr>().ok()?))
                .collect();
            Some((peer_id.parse::<PeerId>().ok()?, addrs))
        })
        .collect::<Vec<_>>();

    Ok(DatabaseContent {
        genesis_block_hash,
        chain_information,
        known_nodes,
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerdeDatabase {
    /// Hexadecimal-encoded hash of the genesis block header. Has no `0x` prefix.
    #[serde(rename = "genesisHash")]
    genesis_hash: String,
    chain: Box<serde_json::value::RawValue>,
    nodes: hashbrown::HashMap<String, Vec<String>, fnv::FnvBuildHasher>,
}
