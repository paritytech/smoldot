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

// TODO: also implement the "proof" way to request the state
// TODO: support child trie requests

use crate::util::protobuf;

use alloc::vec::Vec;

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

// See https://github.com/paritytech/substrate/blob/c8653447fc8ef8d95a92fe164c96dffb37919e85/client/network/light/src/schema/light.v1.proto
// for protocol definition.

/// Builds the bytes corresponding to a state request.
pub fn build_state_request(config: StateRequestConfig) -> impl Iterator<Item = impl AsRef<[u8]>> {
    protobuf::bytes_tag_encode(1, config.block_hash)
        .map(either::Right)
        .map(either::Right)
        .chain(
            protobuf::bytes_tag_encode(2, config.start_key)
                .map(either::Left)
                .map(either::Right),
        )
        .chain(protobuf::bool_tag_encode(3, true).map(either::Left))
}

/// Decodes a response to a state request.
// TODO: should have a more zero-cost API
pub fn decode_state_response(
    response_bytes: &[u8],
) -> Result<Vec<StateResponseEntry>, DecodeStateResponseError> {
    let mut parser = nom::combinator::all_consuming::<_, _, nom::error::Error<&[u8]>, _>(
        nom::combinator::complete(protobuf::message_decode((protobuf::message_tag_decode(
            1,
            protobuf::message_decode((
                protobuf::bytes_tag_decode(1),
                protobuf::message_tag_decode(
                    2,
                    protobuf::message_decode((
                        protobuf::bytes_tag_decode(1),
                        protobuf::bytes_tag_decode(2),
                    )),
                ),
                protobuf::bool_tag_decode(3),
            )),
        ),))),
    );

    let entries: Vec<((&[u8],), Vec<((&[u8],), (&[u8],))>, (bool,))> =
        match nom::Finish::finish(parser(response_bytes)) {
            Ok((_, (entries,))) => entries,
            Err(_) => return Err(DecodeStateResponseError::ProtobufDecode),
        };

    let entries = entries
        .into_iter()
        .flat_map(|(_, entries, _)| entries.into_iter())
        .map(|((key,), (value,))| StateResponseEntry {
            key: key.to_vec(),
            value: value.to_vec(),
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
    /// Error while decoding the Protobuf encoding.
    ProtobufDecode,
}
