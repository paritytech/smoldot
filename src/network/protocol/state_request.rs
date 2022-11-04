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

//! State requests protocol.
//!
//! # Overview
//!
//! A state request consists in asking for the remote to send back all the storage entries
//! starting at a specific key. As many storage entries are included in the response as possible,
//! until the response fits the size of 2MiB.
//!
//! After a response has been received, the sender is expected to send back another request (with
//! a start key right after the last key of the response) in order to continue downloading the
//! storage entries.
//!
//! The format of the response is a compact Merkle proof.
//!
//! > **Note**: The implementation in this module always requests a proof from the server.
//! >           Substrate nodes also support a "no proof" mode where, instead of a proof, the list
//! >           of entries are simply returned without any way to verify them. This alternative
//! >           mode is supposed to be used only in situations where the peer the request is sent
//! >           to is trusted. Because this "no proof" mode is very niche, the implementation in
//! >           this module doesn't support it.
//!
//! # About child tries
//!
//! For the purpose of this protocol, the content of child tries is as if they existed in the main
//! trie under the key `:child_storage:default:`. For example, the child trie `0xabcd` is
//! considered to be at key `concat(b":child_storage:default:", 0xabcd)`.
//!
//! In the response, the child trie Merkle proof is associated with the main trie entry
//! corresponding to the child trie. In other words, it is as if the child trie entry in the main
//! trie was a branch node, except that it has a value corresponding to the hash of the root of
//! the child trie.
//!

use crate::util::protobuf;

use alloc::vec::Vec;

/// Description of a state request that can be sent to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRequest<'a> {
    /// Hash of the block to make the request against.
    pub block_hash: &'a [u8; 32],

    /// Response shouldn't contain any key lexicographically inferior to this key.
    ///
    /// > **Note**: Because a response has a limited size, this field lets you send additional
    /// >           requests that start where the previous response has ended.
    pub start_key: StateRequestStart<'a>,
}

/// See [`StateRequest::start_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateRequestStart<'a> {
    /// Start iterating at a key in the main trie.
    MainTrie(&'a [u8]),
    /// Start iterating at a key in a child trie.
    ChildTrieDefault {
        /// Key of the child trie.
        child_trie: &'a [u8],
        /// Key within the child trie.
        key: &'a [u8],
    },
}

// See https://github.com/paritytech/substrate/blob/c8653447fc8ef8d95a92fe164c96dffb37919e85/client/network/sync/src/schema/api.v1.proto#L73-L106
// for protocol definition.

/// Builds the bytes corresponding to a state request.
pub fn build_state_request(
    config: StateRequest<'_>,
) -> impl Iterator<Item = impl AsRef<[u8]> + '_> + '_ {
    let start = match config.start_key {
        StateRequestStart::MainTrie(key) => {
            either::Left(protobuf::bytes_tag_encode(2, key).map(either::Left))
        }
        StateRequestStart::ChildTrieDefault { child_trie, key } => either::Right(
            protobuf::bytes_tag_encode(2, {
                let mut vec = b":child_storage:default:".to_vec();
                vec.extend(child_trie);
                vec
            })
            .map(either::Left)
            .chain(protobuf::bytes_tag_encode(2, key).map(either::Right))
            .map(either::Right),
        ),
    };

    protobuf::bytes_tag_encode(1, config.block_hash)
        .map(either::Right)
        .map(either::Right)
        .chain(start.map(either::Left).map(either::Right))
        .chain(protobuf::bool_tag_encode(3, false).map(either::Left))
}

/// Decodes a response to a state request.
///
/// On success, contains a list of Merkle proof entries.
pub fn decode_state_response(
    response_bytes: &[u8],
) -> Result<Vec<&[u8]>, DecodeStateResponseError> {
    let mut parser = nom::combinator::all_consuming::<_, _, nom::error::Error<&[u8]>, _>(
        nom::combinator::complete(protobuf::message_decode! {
            #[required] proof = 2 => nom::combinator::map_parser(protobuf::bytes_tag_decode, nom::combinator::flat_map(
                crate::util::nom_scale_compact_usize,
                move |num_elems| {
                    nom::multi::many_m_n(num_elems, num_elems, nom::multi::length_data(crate::util::nom_scale_compact_usize))
                },
            )),
        }),
    );

    let decoded = match nom::Finish::finish(parser(response_bytes)) {
        Ok((_, entries)) => entries,
        Err(_) => return Err(DecodeStateResponseError::ProtobufDecode),
    };

    Ok(decoded.proof)
}

/// Error potentially returned by [`decode_state_response`].
#[derive(Debug, derive_more::Display, Clone)]
#[display(fmt = "Failed to decode response")]
pub enum DecodeStateResponseError {
    /// Error while decoding the Protobuf encoding.
    ProtobufDecode,
}
