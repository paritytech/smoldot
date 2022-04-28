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

use super::{schema, ProtobufDecodeError};

use alloc::{borrow::ToOwned as _, vec::Vec};
use core::{iter, num::NonZeroU32};
use prost::Message as _;

/// Description of a block request that can be sent to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlocksRequestConfig {
    /// First block that the remote must return.
    pub start: BlocksRequestConfigStart,
    /// Number of blocks to request. The remote is free to return fewer blocks than requested.
    pub desired_count: NonZeroU32,
    /// Whether the first block should be the one with the highest number, of the one with the
    /// lowest number.
    pub direction: BlocksRequestDirection,
    /// Which fields should be present in the response.
    pub fields: BlocksRequestFields,
}

/// Whether the first block should be the one with the highest number, of the one with the lowest
/// number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlocksRequestDirection {
    /// Blocks should be returned in ascending number, starting from the requested one.
    Ascending,
    /// Blocks should be returned in descending number, starting from the requested one.
    Descending,
}

/// Which fields should be present in the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlocksRequestFields {
    pub header: bool,
    pub body: bool,
    pub justifications: bool,
}

/// Which block the remote must return first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlocksRequestConfigStart {
    /// Hash of the block.
    Hash([u8; 32]),
    /// Number of the block, where 0 would be the genesis block.
    Number(u64),
}

/// Builds the bytes corresponding to a block request.
pub fn build_block_request(config: BlocksRequestConfig) -> impl Iterator<Item = impl AsRef<[u8]>> {
    // Note: while the API of this function allows for a zero-cost implementation, the protobuf
    // library doesn't permit to avoid allocations.

    let request = {
        let mut fields = 0u32;
        if config.fields.header {
            fields |= 1 << 24;
        }
        if config.fields.body {
            fields |= 1 << 25;
        }
        if config.fields.justifications {
            fields |= 1 << 28;
        }

        schema::BlockRequest {
            fields,
            from_block: match config.start {
                BlocksRequestConfigStart::Hash(h) => {
                    Some(schema::block_request::FromBlock::Hash(h.to_vec()))
                }
                BlocksRequestConfigStart::Number(n) => Some(
                    // The exact format is the SCALE encoding of a block number.
                    // The block number can have a varying number of bytes, and it is therefore
                    // not really possible to know how many bytes to send here.
                    // Fortunately, Substrate uses the `Decode` method of `parity_scale_codec`
                    // instead of `DecodeAll`, meaning that it will ignore any extra byte after
                    // the decoded value. We can thus send as many bytes as we want, as long as
                    // there are enough bytes Substrate will accept the request.
                    // Since the SCALE encoding of a number is in little endian, it's the higher
                    // bytes that get will discarded. These higher bytes are most likely 0s,
                    // otherwise the blockchain in question has a big problem.
                    // In other words, we send the bytes containing the little endian block number
                    // followed with enough 0s to make Substrate accept the request.
                    // This is a hack, but it is not really fixable in smoldot alone and shows a
                    // bigger problem in the Substrate network protocol/architecture. A better
                    // protocol would for example use the SCALE-compact encoding, which doesn't
                    // have this issue.
                    schema::block_request::FromBlock::Number(n.to_le_bytes().to_vec()),
                ),
            },
            to_block: Vec::new(),
            direction: match config.direction {
                BlocksRequestDirection::Ascending => schema::Direction::Ascending as i32,
                BlocksRequestDirection::Descending => schema::Direction::Descending as i32,
            },
            max_blocks: config.desired_count.get(),
            // The `support_multiple_justifications` indicates that we support responses
            // containing multiple justifications. This flag is simply a way to maintain backwards
            // compatibility in the protocol.
            support_multiple_justifications: true,
        }
    };

    let request_bytes = {
        let mut buf = Vec::with_capacity(request.encoded_len());
        request.encode(&mut buf).unwrap();
        buf
    };

    iter::once(request_bytes)
}

/// Decodes a blocks request.
// TODO: should have a more zero-cost API, but we're limited by the protobuf library for that
pub fn decode_block_request(
    request_bytes: &[u8],
) -> Result<BlocksRequestConfig, DecodeBlockRequestError> {
    let request = schema::BlockRequest::decode(request_bytes)
        .map_err(ProtobufDecodeError)
        .map_err(DecodeBlockRequestError::ProtobufDecode)?;

    Ok(BlocksRequestConfig {
        start: match request.from_block {
            Some(schema::block_request::FromBlock::Hash(h)) => BlocksRequestConfigStart::Hash(
                <[u8; 32]>::try_from(&h[..])
                    .map_err(|_| DecodeBlockRequestError::InvalidBlockHashLength)?,
            ),
            Some(schema::block_request::FromBlock::Number(n)) => {
                // The exact format is the SCALE encoding of a block number.
                // The block number can have a varying number of bytes, and it is therefore
                // not really possible to know how many bytes to expect here.
                // Because the SCALE encoding of a number is the number in little endian format,
                // we decode the bytes in little endian format in a way that works no matter the
                // number of bytes.
                let mut num = 0u64;
                let mut shift = 0u32;
                for byte in n {
                    let shifted = u64::from(byte)
                        .checked_mul(1 << shift)
                        .ok_or(DecodeBlockRequestError::InvalidBlockNumber)?;
                    num = num
                        .checked_add(shifted)
                        .ok_or(DecodeBlockRequestError::InvalidBlockNumber)?;
                    shift = shift
                        .checked_add(8)
                        .ok_or(DecodeBlockRequestError::InvalidBlockNumber)?;
                }

                BlocksRequestConfigStart::Number(num)
            }
            None => return Err(DecodeBlockRequestError::MissingStartBlock),
        },
        desired_count: NonZeroU32::new(request.max_blocks)
            .ok_or(DecodeBlockRequestError::ZeroBlocksRequested)?,
        direction: match schema::Direction::from_i32(request.direction)
            .ok_or(DecodeBlockRequestError::InvalidDirection)?
        {
            schema::Direction::Ascending => BlocksRequestDirection::Ascending,
            schema::Direction::Descending => BlocksRequestDirection::Descending,
        },
        // TODO: should detect and error if unknown field bit
        fields: BlocksRequestFields {
            header: (request.fields & (1 << 24)) != 0,
            body: (request.fields & (1 << 25)) != 0,
            justifications: (request.fields & (1 << 28)) != 0,
        },
    })
}

/// Builds the bytes corresponding to a block response.
pub fn build_block_response(response: Vec<BlockData>) -> impl Iterator<Item = impl AsRef<[u8]>> {
    // Note: while the API of this function allows for a zero-cost implementation, the protobuf
    // library doesn't permit to avoid allocations.

    // Note that this function assumes that `support_multiple_justifications` was true in the
    // request. We intentionally don't support old versions where it was false.

    let response = schema::BlockResponse {
        blocks: response
            .into_iter()
            .map(|block| {
                let justifications = if let Some(justifications) = block.justifications {
                    let mut j = Vec::with_capacity(
                        4 + justifications
                            .iter()
                            .fold(0, |sz, (_, j)| sz + 4 + 6 + j.len()),
                    );
                    j.extend_from_slice(
                        crate::util::encode_scale_compact_usize(justifications.len()).as_ref(),
                    );
                    for (consensus_engine, justification) in &justifications {
                        j.extend_from_slice(consensus_engine);
                        j.extend_from_slice(
                            crate::util::encode_scale_compact_usize(justification.len()).as_ref(),
                        );
                        j.extend_from_slice(justification);
                    }
                    j
                } else {
                    Vec::new()
                };

                schema::BlockData {
                    hash: block.hash.to_vec(),
                    header: block.header.map_or(Vec::new(), |h| h.to_vec()),
                    body: block.body.map_or(Vec::new(), |b| b.to_vec()),
                    justifications,
                    justification: Vec::new(),
                    is_empty_justification: false, // Flag is irrelevant w.r.t. `justifications`.
                    receipt: Vec::new(),
                    message_queue: Vec::new(),
                    indexed_body: Vec::new(),
                }
            })
            .collect(),
    };

    let response_bytes = {
        let mut buf = Vec::with_capacity(response.encoded_len());
        response.encode(&mut buf).unwrap();
        buf
    };

    iter::once(response_bytes)
}

/// Decodes a response to a block request.
// TODO: should have a more zero-cost API, but we're limited by the protobuf library for that
pub fn decode_block_response(
    response_bytes: &[u8],
) -> Result<Vec<BlockData>, DecodeBlockResponseError> {
    let response = schema::BlockResponse::decode(response_bytes)
        .map_err(ProtobufDecodeError)
        .map_err(DecodeBlockResponseError::ProtobufDecode)?;

    let mut blocks = Vec::with_capacity(response.blocks.len());
    for block in response.blocks {
        if block.hash.len() != 32 {
            return Err(DecodeBlockResponseError::InvalidHashLength);
        }

        blocks.push(BlockData {
            hash: <[u8; 32]>::try_from(&block.hash[..]).unwrap(),
            header: if !block.header.is_empty() {
                Some(block.header)
            } else {
                None
            },
            // TODO: no; we might not have asked for the body
            body: Some(block.body),
            justifications: if !block.justifications.is_empty() {
                let result: nom::IResult<_, _> =
                    nom::combinator::all_consuming(justifications)(&block.justifications);
                match result {
                    Ok((_, out)) => Some(out),
                    Err(nom::Err::Error(_) | nom::Err::Failure(_)) => {
                        return Err(DecodeBlockResponseError::InvalidJustifications)
                    }
                    Err(_) => unreachable!(),
                }
            } else {
                None
            },
        });
    }

    Ok(blocks)
}

/// Block sent in a block response.
///
/// > **Note**: Assuming that this response comes from the network, the information in this struct
/// >           can be erroneous and shouldn't be trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockData {
    /// Block hash.
    ///
    /// > **Note**: This should contain the hash of the header, but, like the rest of this
    /// >           structure, this cannot be trusted.
    pub hash: [u8; 32],

    /// SCALE-encoded block header, if requested.
    pub header: Option<Vec<u8>>,

    /// Block body, if requested. Each item (each `Vec<u8>`) is a SCALE-encoded extrinsic.
    /// These extrinsics aren't decodable, as their meaning depends on the chain.
    ///
    /// > **Note**: Be aware that in many chains an extrinsic is actually a `Vec<u8>`, which
    /// >           means that you will find, at the beginning of each SCALE-encoded extrinsic,
    /// >           a length prefix. Don't get fooled into thinking that this length prefix must
    /// >           be removed. It is part of the opaque format extrinsic format.
    pub body: Option<Vec<Vec<u8>>>,

    /// List of justifications, if requested and available.
    ///
    /// Each justification is a tuple of a "consensus engine id" and a SCALE-encoded
    /// justifications.
    ///
    /// Will be `None` if and only if not requested.
    // TODO: consider strong typing for the consensus engine id
    pub justifications: Option<Vec<([u8; 4], Vec<u8>)>>,
}

/// Error potentially returned by [`decode_block_request`].
#[derive(Debug, derive_more::Display)]
pub enum DecodeBlockRequestError {
    /// Error while decoding the Protobuf encoding.
    ProtobufDecode(ProtobufDecodeError),
    /// Zero blocks requested.
    ZeroBlocksRequested,
    /// Value in the direction field is invalid.
    InvalidDirection,
    /// Start block field is missing.
    MissingStartBlock,
    /// Invalid block number passed.
    InvalidBlockNumber,
    /// Block hash length isn't correct.
    InvalidBlockHashLength,
}

/// Error potentially returned by [`decode_block_response`].
#[derive(Debug, derive_more::Display)]
pub enum DecodeBlockResponseError {
    /// Error while decoding the Protobuf encoding.
    ProtobufDecode(ProtobufDecodeError),
    /// Hash length isn't of the correct length.
    InvalidHashLength,
    BodyDecodeError,
    /// List of justifications isn't in a correct format.
    InvalidJustifications,
}

fn justifications<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], Vec<([u8; 4], Vec<u8>)>, E> {
    nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
        nom::multi::many_m_n(
            num_elems,
            num_elems,
            nom::combinator::map(
                nom::sequence::tuple((
                    nom::bytes::complete::take(4u32),
                    crate::util::nom_bytes_decode,
                )),
                move |(consensus_engine, justification)| {
                    (
                        <[u8; 4]>::try_from(consensus_engine).unwrap(),
                        justification.to_owned(),
                    )
                },
            ),
        )
    })(bytes)
}
