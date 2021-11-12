// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
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

// TODO: also implement the "proof" way to request the state
// TODO: support child trie requests

use super::{schema, ProtobufDecodeError};

use alloc::{vec, vec::Vec};
use core::iter;
use prost::Message as _;

/// Description of a state request that can be sent to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRequestConfig {
    /// Hash of the block to make the request against.
    pub block_hash: [u8; 32],

    /// Response shouldn't contain any key lexicographically inferior to this key.
    ///
    /// > **Note**: Because a response has a limited size, this value lets you send additional
    /// >           requests that start where the previous response has ended.
    // TODO: use a slice, maybe?
    pub start_key: Vec<u8>,
}

/// Builds the bytes corresponding to a state request.
pub fn build_state_request(config: StateRequestConfig) -> impl Iterator<Item = impl AsRef<[u8]>> {
    // Note: while the API of this function allows for a zero-cost implementation, the protobuf
    // library doesn't permit to avoid allocations.

    let request = schema::StateRequest {
        block: config.block_hash.to_vec(),
        start: vec![config.start_key],
        no_proof: true,
    };

    let request_bytes = {
        let mut buf = Vec::with_capacity(request.encoded_len());
        request.encode(&mut buf).unwrap();
        buf
    };

    iter::once(request_bytes)
}

/// Decodes a response to a state request.
// TODO: should have a more zero-cost API, but we're limited by the protobuf library for that
pub fn decode_state_response(
    response_bytes: &[u8],
) -> Result<Vec<StateResponseEntry>, DecodeStateResponseError> {
    let response = schema::StateResponse::decode(response_bytes)
        .map_err(ProtobufDecodeError)
        .map_err(DecodeStateResponseError::ProtobufDecode)?;

    let entries = response
        .entries
        .into_iter()
        .flat_map(|e| e.entries.into_iter())
        .map(|entry| StateResponseEntry {
            key: entry.key,
            value: entry.value,
        })
        .collect();

    Ok(entries)
}

/// Entry sent in a state response.
///
/// > **Note**: Assuming that this response comes from the network, the information in this struct
/// >           can be erroneous and shouldn't be trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateResponseEntry {
    /// Storage key concerned by the entry.
    pub key: Vec<u8>,
    /// Storage value concerned by the entry.
    pub value: Vec<u8>,
}

/// Error potentially returned by [`decode_state_response`].
#[derive(Debug, derive_more::Display)]
pub enum DecodeStateResponseError {
    /// Error while decoding the protobuf encoding.
    ProtobufDecode(ProtobufDecodeError),
}
