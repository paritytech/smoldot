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

//! The identify protocol is a request-response protocol.
//!
//! The request's body is empty. Contrary to other request-response protocols, it doesn't even
//! contain a message length. As soon as the protocol has been negotiated, the other side should
//! send back the response.
//!
//! The response's body consists in various useful general-purpose information about the node.
//! See [`IdentifyResponse`] for details.
//!
//! The two most important fields are [`IdentifyResponse::listen_addrs`] and
//! [`IdentifyResponse::observed_addr`]. They are necessary in order for nodes to discover their
//! public address, and in order to insert peers in the Kademlia k-buckets.
//!
//! See also [the official specification](https://github.com/libp2p/specs/tree/69e57d59dc5d59d3979d79842b577ec2c483f7fa/identify).

use super::{schema, ProtobufDecodeError};
use crate::libp2p::{
    peer_id::{FromProtobufEncodingError, PublicKey},
    Multiaddr,
};

use alloc::{
    borrow::{Cow, ToOwned as _},
    string::String,
    vec::{self, Vec},
};
use core::iter;
use prost::Message as _;

/// Description of a response to an identify request.
// TODO: the Cows in there should be slices once the response decoding is zero cost
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifyResponse<'a, TLaIter, TProtoIter> {
    pub protocol_version: Cow<'a, str>,
    pub agent_version: Cow<'a, str>,
    /// Ed25519 public key of the local node.
    pub ed25519_public_key: Cow<'a, [u8; 32]>,
    /// List of addresses the local node is listening on. This should include first and foremost
    /// addresses that are publicly-reachable.
    pub listen_addrs: TLaIter,
    /// Address of the sender of the identify request, as seen from the receiver.
    pub observed_addr: Cow<'a, Multiaddr>,
    /// Names of the protocols supported by the local node.
    pub protocols: TProtoIter,
}

/// Builds the bytes corresponding to a block request.
pub fn build_identify_response<'a>(
    config: IdentifyResponse<
        'a,
        impl Iterator<Item = &'a Multiaddr>,
        impl Iterator<Item = &'a str>,
    >,
) -> impl Iterator<Item = impl AsRef<[u8]>> {
    // Note: while the API of this function allows for a zero-cost implementation, the protobuf
    // library doesn't permit to avoid allocations.

    let protobuf = schema::Identify {
        protocol_version: Some(config.protocol_version.into_owned()),
        agent_version: Some(config.agent_version.into_owned()),
        public_key: Some(PublicKey::Ed25519(*config.ed25519_public_key).to_protobuf_encoding()),
        listen_addrs: config.listen_addrs.map(|addr| addr.to_vec()).collect(),
        observed_addr: Some(config.observed_addr.to_vec()),
        protocols: config.protocols.map(|p| p.to_owned()).collect(),
    };

    let request_bytes = {
        let mut buf = Vec::with_capacity(protobuf.encoded_len());
        protobuf.encode(&mut buf).unwrap();
        buf
    };

    iter::once(request_bytes)
}

/// Decodes a response to an identify request.
// TODO: should have a more zero-cost API, but we're limited by the protobuf library for that
pub fn decode_identify_response(
    response_bytes: &[u8],
) -> Result<
    IdentifyResponse<'static, vec::IntoIter<Multiaddr>, vec::IntoIter<String>>,
    DecodeIdentifyResponseError,
> {
    let response = schema::Identify::decode(response_bytes)
        .map_err(ProtobufDecodeError)
        .map_err(DecodeIdentifyResponseError::ProtobufDecode)?;

    Ok(IdentifyResponse {
        agent_version: response.agent_version.unwrap_or_default().into(),
        protocol_version: response.protocol_version.unwrap_or_default().into(),
        ed25519_public_key: match PublicKey::from_protobuf_encoding(
            &response.public_key.unwrap_or_default(),
        )
        .map_err(DecodeIdentifyResponseError::InvalidPublicKey)?
        {
            PublicKey::Ed25519(key) => Cow::Owned(key),
        },
        listen_addrs: response
            .listen_addrs
            .into_iter()
            .map(Multiaddr::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| DecodeIdentifyResponseError::InvalidMultiaddr)?
            .into_iter(),
        observed_addr: Cow::Owned(
            Multiaddr::try_from(response.observed_addr.unwrap_or_default())
                .map_err(|_| DecodeIdentifyResponseError::InvalidMultiaddr)?,
        ),
        protocols: response.protocols.into_iter(),
    })
}

/// Error potentially returned by [`decode_identify_response`].
#[derive(Debug, derive_more::Display)]
pub enum DecodeIdentifyResponseError {
    /// Error while decoding the protobuf encoding.
    ProtobufDecode(ProtobufDecodeError),
    /// Couldn't decode one of the multiaddresses.
    InvalidMultiaddr,
    /// Couldn't decode the public key of the remote.
    InvalidPublicKey(FromProtobufEncodingError),
}
