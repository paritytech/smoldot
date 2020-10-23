// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// TODO: docs

use core::{convert::TryFrom, iter};

/// Decoded handshake sent or received when opening a block announces notifications substream.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BlockAnnouncesHandshakeRef<'a> {
    /// Role a node reports playing on the network.
    pub role: Role,

    /// Height of the best block according to this node.
    pub best_number: u64,

    /// Hash of the best block according to this node.
    pub best_hash: &'a [u8; 32],

    /// Hash of the genesis block according to this node.
    ///
    /// > **Note**: This should be compared to the locally known genesis block hash, to make sure
    /// >           that both nodes are on the same chain.
    pub genesis_hash: &'a [u8; 32],
}

/// Role a node reports playing on the network.
// TODO: document why this is here and what this entails
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Role {
    Full,
    Light,
    Authority,
}

/// Turns a block announces handshake into its SCALE-encoding ready to be sent over the wire.
///
/// This function returns an iterator of buffers. The encoded message consists in the
/// concatenation of the buffers.
pub fn encode_block_announces_handshake<'a>(
    handshake: BlockAnnouncesHandshakeRef<'a>,
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
    let mut header = [0; 5];
    header[0] = match handshake.role {
        Role::Full => 0b1,
        Role::Light => 0b10,
        Role::Authority => 0b100,
    };

    // TODO: the message actually contains a u32, and doesn't use compact encoding; as such, any block height superior to 2^32 cannot be encoded
    assert!(handshake.best_number < u64::from(u32::max_value()));
    header[1..].copy_from_slice(&handshake.best_number.to_le_bytes()[..4]);

    iter::once(either::Left(header))
        .chain(iter::once(either::Right(handshake.best_hash)))
        .chain(iter::once(either::Right(handshake.genesis_hash)))
}

/// Decodes a SCALE-encoded block announces handshake.
pub fn decode_block_announces_handshake<'a>(
    handshake: &'a [u8],
) -> Result<BlockAnnouncesHandshakeRef<'a>, BlockAnnouncesDecodeError<'a>> {
    nom::combinator::all_consuming(nom::combinator::map(
        nom::sequence::tuple((
            nom::branch::alt((
                nom::combinator::map(nom::bytes::complete::tag(&[0b1]), |_| Role::Full),
                nom::combinator::map(nom::bytes::complete::tag(&[0b10]), |_| Role::Light),
                nom::combinator::map(nom::bytes::complete::tag(&[0b100]), |_| Role::Authority),
            )),
            nom::number::complete::le_u32,
            nom::bytes::complete::take(32u32),
            nom::bytes::complete::take(32u32),
        )),
        |(role, best_number, best_hash, genesis_hash)| BlockAnnouncesHandshakeRef {
            role,
            best_number: u64::from(best_number),
            best_hash: TryFrom::try_from(best_hash).unwrap(),
            genesis_hash: TryFrom::try_from(genesis_hash).unwrap(),
        },
    ))(handshake)
    .map(|(_, hs)| hs)
    .map_err(BlockAnnouncesDecodeError)
}

/// Error potentially returned by [`decode_block_announces_handshake`].
#[derive(Debug, derive_more::Display)]
pub struct BlockAnnouncesDecodeError<'a>(nom::Err<(&'a [u8], nom::error::ErrorKind)>);
