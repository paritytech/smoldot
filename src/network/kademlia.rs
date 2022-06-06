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

// TODO: work in progress

use crate::{
    libp2p::{multiaddr, peer_id},
    util::protobuf,
};

use alloc::vec::Vec;

pub mod kbuckets;

/// Data structure containing the k-buckets and the state of the current Kademlia queries.
// TODO: unused
pub struct Kademlia {}

impl Kademlia {
    /// Initializes a new empty data structure with empty k-buckets.
    pub fn new() -> Self {
        Kademlia {}
    }
}

impl Default for Kademlia {
    fn default() -> Self {
        Self::new()
    }
}

// See https://github.com/libp2p/specs/tree/master/kad-dht#rpc-messages for the protobuf format.

/// Builds a wire message to send on the Kademlia request-response protocol to ask the target to
/// return the nodes closest to the parameter.
// TODO: parameter type?
pub fn build_find_node_request(peer_id: &[u8]) -> Vec<u8> {
    // The capacity is arbitrary but large enough to avoid Vec reallocations.
    let mut out = Vec::with_capacity(64 + peer_id.len());
    for slice in protobuf::enum_tag_encode(1, 4) {
        out.extend_from_slice(slice.as_ref());
    }
    for slice in protobuf::bytes_tag_encode(2, peer_id) {
        out.extend_from_slice(slice.as_ref());
    }
    out
}

/// Decodes a response to a request built using [`build_find_node_request`].
// TODO: return a borrow of the response bytes ; we're limited by protobuf library
pub fn decode_find_node_response(
    response_bytes: &[u8],
) -> Result<Vec<(peer_id::PeerId, Vec<multiaddr::Multiaddr>)>, DecodeFindNodeResponseError> {
    let mut parser = nom::combinator::all_consuming::<_, _, nom::error::Error<&[u8]>, _>(
        protobuf::message_decode::<((_,), Vec<_>), _, _>((
            protobuf::enum_tag_decode(1),
            protobuf::message_tag_decode(
                8,
                protobuf::message_decode::<((_,), Vec<_>), _, _>((
                    protobuf::bytes_tag_decode(1),
                    protobuf::bytes_tag_decode(2),
                )),
            ),
        )),
    );

    let closer_peers: Vec<_> = match nom::Finish::finish(parser(response_bytes)) {
        Ok((_, ((4,), peers))) => peers,
        Ok((_, ((_other_message_ty,), _))) => {
            return Err(DecodeFindNodeResponseError::BadResponseTy)
        }
        Err(_) => {
            return Err(DecodeFindNodeResponseError::ProtobufDecode(
                ProtobufDecodeError,
            ))
        }
    };

    let mut result = Vec::with_capacity(closer_peers.len());
    for ((peer_id,), addrs) in closer_peers {
        let peer_id = peer_id::PeerId::from_bytes(peer_id.to_vec())
            .map_err(|(err, _)| DecodeFindNodeResponseError::BadPeerId(err))?;

        let mut multiaddrs = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let addr = multiaddr::Multiaddr::try_from(addr.to_vec())
                .map_err(DecodeFindNodeResponseError::BadMultiaddr)?;
            multiaddrs.push(addr);
        }

        result.push((peer_id, multiaddrs));
    }

    Ok(result)
}

/// Error potentially returned by [`decode_find_node_response`].
#[derive(Debug, derive_more::Display)]
pub enum DecodeFindNodeResponseError {
    /// Error while decoding the Protobuf encoding.
    ProtobufDecode(ProtobufDecodeError),
    /// Response isn't a response to a find node request.
    BadResponseTy,
    /// Error while parsing a [`peer_id::PeerId`] in the response.
    BadPeerId(peer_id::FromBytesError),
    /// Error while parsing a [`multiaddr::Multiaddr`] in the response.
    BadMultiaddr(multiaddr::FromVecError),
}

/// Error while decoding the Protobuf encoding.
#[derive(Debug, derive_more::Display)]
pub struct ProtobufDecodeError;
