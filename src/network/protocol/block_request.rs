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

use crate::util::protobuf;

use alloc::{borrow::ToOwned as _, vec::Vec};
use core::num::NonZeroU32;

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
    /// Blocks should be returned in ascending number, starting from the requested one. In other
    /// words, amongst all the blocks in the response, the requested block must be the one with
    /// the lowest block number, and all the other blocks are its descendants.
    Ascending,
    /// Blocks should be returned in descending number, starting from the requested one. In other
    /// words, amongst all the blocks in the response, the requested block must be the one with
    /// the highest block number, and all the other blocks are its ancestors.
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

// See https://github.com/paritytech/substrate/blob/c8653447fc8ef8d95a92fe164c96dffb37919e85/client/network/sync/src/schema/api.v1.proto
// for protocol definition.

/// Builds the bytes corresponding to a block request.
pub fn build_block_request(
    block_number_bytes: usize,
    config: &BlocksRequestConfig,
) -> impl Iterator<Item = impl AsRef<[u8]>> {
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

    let from_block = match config.start {
        BlocksRequestConfigStart::Hash(h) => {
            either::Left(protobuf::bytes_tag_encode(2, h).map(either::Left))
        }
        BlocksRequestConfigStart::Number(n) => {
            let mut data = Vec::with_capacity(block_number_bytes);
            data.extend_from_slice(&n.to_le_bytes());
            // TODO: unclear what to do if the block number doesn't fit within `expected_block_number_bytes`
            data.resize(block_number_bytes, 0);
            either::Right(protobuf::bytes_tag_encode(3, data).map(either::Right))
        }
    };

    protobuf::uint32_tag_encode(1, fields)
        .map(either::Left)
        .map(either::Left)
        .map(either::Left)
        .chain(
            from_block
                .map(either::Right)
                .map(either::Left)
                .map(either::Left),
        )
        .chain(
            protobuf::enum_tag_encode(
                5,
                match config.direction {
                    BlocksRequestDirection::Ascending => 0,
                    BlocksRequestDirection::Descending => 1,
                },
            )
            .map(either::Left)
            .map(either::Right)
            .map(either::Left),
        )
        .chain(
            protobuf::uint32_tag_encode(6, config.desired_count.get())
                .map(either::Right)
                .map(either::Right)
                .map(either::Left),
        )
        // The `support_multiple_justifications` flag indicates that we support responses
        // containing multiple justifications. This flag is simply a way to maintain backwards
        // compatibility in the protocol.
        .chain(protobuf::bool_tag_encode(7, true).map(either::Right))
}

/// Decodes a blocks request.
// TODO: should have a more zero-cost API, but we're limited by the protobuf library for that
pub fn decode_block_request(
    expected_block_number_bytes: usize,
    request_bytes: &[u8],
) -> Result<BlocksRequestConfig, DecodeBlockRequestError> {
    let mut parser = nom::combinator::all_consuming::<_, _, nom::error::Error<&[u8]>, _>(
        nom::combinator::complete(protobuf::message_decode! {
            fields = 1 => protobuf::uint32_tag_decode,
            #[optional] hash = 2 => protobuf::bytes_tag_decode,
            #[optional] number = 3 => protobuf::bytes_tag_decode,
            #[optional] direction = 5 => protobuf::enum_tag_decode,
            #[optional] max_blocks = 6 => protobuf::uint32_tag_decode,
        }),
    );

    let decoded = match nom::Finish::finish(parser(request_bytes)) {
        Ok((_, rq)) => rq,
        Err(_) => return Err(DecodeBlockRequestError::ProtobufDecode),
    };

    Ok(BlocksRequestConfig {
        start: match (decoded.hash, decoded.number) {
            (Some(h), None) => BlocksRequestConfigStart::Hash(
                <[u8; 32]>::try_from(h)
                    .map_err(|_| DecodeBlockRequestError::InvalidBlockHashLength)?,
            ),
            (None, Some(n)) => {
                if n.len() != expected_block_number_bytes {
                    return Err(DecodeBlockRequestError::InvalidBlockNumber);
                }

                // The exact format is the SCALE encoding of a block number.
                // The block number can have a varying number of bytes, and it is therefore
                // not really possible to know how many bytes to expect here.
                // Because the SCALE encoding of a number is the number in little endian format,
                // we decode the bytes in little endian format in a way that works no matter the
                // number of bytes.
                let mut num = 0u64;
                let mut shift = 0u32;
                for byte in n {
                    let shifted = u64::from(*byte)
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
            (Some(_), Some(_)) => return Err(DecodeBlockRequestError::ProtobufDecode),
            (None, None) => return Err(DecodeBlockRequestError::MissingStartBlock),
        },
        desired_count: {
            // A missing field or a `0` field are both interpreted as "no limit".
            NonZeroU32::new(decoded.max_blocks.unwrap_or(u32::max_value()))
                .unwrap_or(NonZeroU32::new(u32::max_value()).unwrap())
        },
        direction: match decoded.direction {
            None | Some(0) => BlocksRequestDirection::Ascending,
            Some(1) => BlocksRequestDirection::Descending,
            Some(_) => return Err(DecodeBlockRequestError::InvalidDirection),
        },
        fields: {
            if (decoded.fields & !(1 << 24 | 1 << 25 | 1 << 28)) != 0 {
                return Err(DecodeBlockRequestError::UnknownFieldBits);
            }
            BlocksRequestFields {
                header: (decoded.fields & (1 << 24)) != 0,
                body: (decoded.fields & (1 << 25)) != 0,
                justifications: (decoded.fields & (1 << 28)) != 0,
            }
        },
    })
}

/// Builds the bytes corresponding to a block response.
// TODO: more zero-cost API
pub fn build_block_response(response: Vec<BlockData>) -> impl Iterator<Item = impl AsRef<[u8]>> {
    // Note that this function assumes that `support_multiple_justifications` was true in the
    // request. We intentionally don't support old versions where it was false.

    response.into_iter().flat_map(|block| {
        protobuf::message_tag_encode(1, {
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
                Some(j)
            } else {
                None
            };

            protobuf::bytes_tag_encode(1, block.hash)
                .map(either::Left)
                .chain(
                    block
                        .header
                        .into_iter()
                        .flat_map(|h| protobuf::bytes_tag_encode(2, h))
                        .map(either::Right),
                )
                .map(either::Left)
                .chain(
                    block
                        .body
                        .into_iter()
                        .flat_map(|b| b.into_iter())
                        .flat_map(|tx| protobuf::bytes_tag_encode(3, tx))
                        .map(either::Left)
                        .chain(
                            justifications
                                .into_iter()
                                .flat_map(|j| protobuf::bytes_tag_encode(8, j))
                                .map(either::Right),
                        )
                        .map(either::Right),
                )
        })
    })
}

/// Decodes a response to a block request.
// TODO: should have a more zero-cost API
pub fn decode_block_response(
    response_bytes: &[u8],
) -> Result<Vec<BlockData>, DecodeBlockResponseError> {
    let mut parser = nom::combinator::all_consuming::<_, _, nom::error::Error<&[u8]>, _>(
        nom::combinator::complete(protobuf::message_decode! {
            #[repeated(max = 32768)] blocks = 1 => protobuf::message_tag_decode(protobuf::message_decode!{
                hash = 1 => protobuf::bytes_tag_decode,
                header = 2 => protobuf::bytes_tag_decode,
                #[repeated(max = usize::max_value())] body = 3 => protobuf::bytes_tag_decode,
                #[optional] justifications = 8 => protobuf::bytes_tag_decode,
            }),
        }),
    );

    let blocks = match nom::Finish::finish(parser(response_bytes)) {
        Ok((_, out)) => out.blocks,
        Err(_) => return Err(DecodeBlockResponseError::ProtobufDecode),
    };

    let mut blocks_out = Vec::with_capacity(blocks.len());
    for block in blocks {
        if block.hash.len() != 32 {
            return Err(DecodeBlockResponseError::InvalidHashLength);
        }

        blocks_out.push(BlockData {
            hash: <[u8; 32]>::try_from(block.hash).unwrap(),
            header: if !block.header.is_empty() {
                Some(block.header.to_vec())
            } else {
                None
            },
            // TODO: no; we might not have asked for the body
            body: Some(block.body.into_iter().map(|tx| tx.to_vec()).collect()),
            justifications: if let Some(justifications) = block.justifications {
                let result: nom::IResult<_, _> = nom::combinator::all_consuming(
                    nom::combinator::complete(decode_justifications),
                )(justifications);
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

    Ok(blocks_out)
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
    ProtobufDecode,
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
    /// Requested fields contains bits that are unknown.
    UnknownFieldBits,
}

/// Error potentially returned by [`decode_block_response`].
#[derive(Debug, derive_more::Display)]
pub enum DecodeBlockResponseError {
    /// Error while decoding the Protobuf encoding.
    ProtobufDecode,
    /// Hash length isn't of the correct length.
    InvalidHashLength,
    BodyDecodeError,
    /// List of justifications isn't in a correct format.
    InvalidJustifications,
}

fn decode_justifications<'a, E: nom::error::ParseError<&'a [u8]>>(
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

#[cfg(test)]
mod tests {
    #[test]
    fn regression_2339() {
        // Regression test for https://github.com/paritytech/smoldot/issues/2339.
        let _ = super::decode_block_request(4, &[26, 10]);
    }

    #[test]
    fn regression_incomplete_justification() {
        let _ = super::decode_block_response(&[
            200, 200, 255, 255, 10, 8, 0, 47, 0, 1, 26, 0, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88,
            88, 88, 88, 88, 88, 88, 1, 10, 1, 255, 2, 0, 0, 1, 255, 2, 10, 0, 36, 1, 8, 105, 105,
            105, 105, 105, 105, 97, 105, 105, 88, 1, 0, 0, 88, 88, 88, 88, 88, 88, 10, 175, 10, 0,
            105, 1, 10, 1, 255, 2, 0, 0, 10, 4, 66, 0, 66, 38, 88, 88, 18, 0, 88, 26, 0, 8, 5, 0,
            0, 0, 0, 0, 0, 0, 105, 1, 8, 105, 105, 105, 105, 105, 105, 88, 88, 88, 88, 88, 0, 0,
            88, 88, 0, 0, 0, 18, 0, 26, 1, 88, 88, 88, 88, 36, 10, 255, 0, 2, 10, 0, 36, 1, 8, 105,
            105, 105, 105, 105, 105, 97, 105, 105, 105, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 48,
            10, 0, 105, 1, 10, 2, 0, 12, 0, 0, 0, 0, 0, 0, 0, 18, 0, 26, 1, 88, 88, 88, 88, 36, 10,
            1, 255, 2, 10, 0, 105, 1, 8, 105, 105, 105, 105, 105, 105, 97, 105, 105, 105, 88, 88,
            88, 0, 88, 88, 36, 10, 1, 255, 2, 10, 0, 36, 1, 8, 0, 1, 26, 0, 88, 88, 88, 88, 88, 88,
            10, 48, 10, 0, 105, 1, 10, 1, 255, 2, 0, 0, 0, 18, 0, 26, 1, 88, 88, 88, 88, 36, 244,
            1, 88, 88, 88, 88, 10, 48, 10, 0, 105, 1, 10, 1, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18,
            0, 26, 1, 88, 88, 0, 0, 0, 0, 0, 0, 26, 0, 26, 1, 88, 88, 88, 88, 36, 10, 1, 255, 2,
            10, 0, 105, 1, 8, 105, 105, 105, 105, 105, 105, 97, 105, 105, 105, 18, 0, 0, 0, 0, 0,
            0, 0, 88, 0, 18, 0, 26, 1, 88, 88, 0, 0, 0, 0, 0, 0, 18, 0, 26, 1, 88, 88, 88, 88, 36,
            10, 1, 255, 2, 10, 0, 105, 1, 86, 0, 0, 0, 0, 0, 0, 0, 8, 105, 105, 105, 105, 105, 105,
            97, 105, 88, 88, 88, 88, 88, 10, 48, 10, 0, 105, 1, 10, 1, 255, 2, 128, 0, 0, 0, 32, 0,
            0, 0, 0, 18, 0, 26, 1, 88, 88, 88, 88, 36, 10, 1, 88, 88, 36, 10, 1, 255, 2, 10, 0,
            105, 1, 8, 105, 105, 105, 105, 105, 105, 97, 105, 105, 105, 88, 88, 88, 88, 88, 88, 88,
            88, 88, 10, 48, 10, 0, 105, 1, 10, 1, 255, 2, 0, 0, 0, 0, 32, 0, 0, 0, 0, 18, 0, 26, 1,
            88, 88, 88, 88, 36, 10, 1, 255, 2, 0, 0, 0, 0, 0, 0, 0, 8, 0, 47, 0, 1, 0, 0, 88, 88,
            88, 88, 88, 88, 10, 48, 10, 0, 105, 1, 10, 1, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0,
            26, 1, 88, 88, 88, 88, 36, 10, 1, 255, 2, 10, 0, 105, 1, 8, 105, 105, 105, 105, 105,
            105, 97, 105, 105, 105, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 10, 0, 105, 139,
            10, 1, 255, 2, 0, 0, 0, 0, 0, 0, 18, 0, 26, 1, 88, 88, 0, 0, 0, 0, 0, 0, 18, 0, 26, 1,
            0, 1, 26, 0, 88, 88, 88, 88, 88, 88, 10, 48, 10, 0, 105, 1, 10, 1, 255, 2, 0, 0, 0, 18,
            0, 26, 1, 88, 88, 88, 88, 36, 10, 1, 88, 88, 88, 88, 10, 48, 10, 0, 105, 1, 10, 1, 255,
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 18, 0, 26, 1, 88, 88, 88, 88, 36, 10,
            1, 88, 88, 36, 10, 1, 255, 2, 10, 0, 105, 1, 8, 105, 105, 105, 105, 105, 105, 97, 105,
            105, 105, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 0, 18, 0, 26, 1, 88, 88, 0, 0, 0, 0,
            0, 0, 18, 0, 26, 1, 88, 88, 88, 88, 36, 10, 1, 255, 2, 10, 0, 105, 1, 86, 0, 0, 0, 0,
            0, 0, 0, 8, 105, 105, 105, 105, 105, 105, 97, 105, 88, 88, 88, 88, 88, 10, 48, 10, 0,
            105, 1, 10, 1, 255, 2, 0, 0, 0, 0, 32, 0, 0, 0, 0, 18, 0, 26, 1, 88, 88, 88, 88, 36,
            10, 1, 88, 88, 36, 10, 1, 255, 2, 10, 0, 105, 1, 8, 105, 93, 105, 105, 105, 105, 105,
            97, 105, 105, 0, 47, 0, 1, 0, 0, 88, 88, 88, 88, 88, 88, 10, 48, 10, 0, 105, 1, 10, 1,
            255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 26, 1, 88, 88, 88, 88, 36, 10, 1, 255, 2, 10,
            0, 105, 1, 8, 105, 105, 105, 105, 97, 105, 88, 88, 88, 88, 88, 10, 48, 10, 0, 105, 1,
            10, 1, 255, 2, 0, 0, 0, 0, 32, 0, 0, 0, 0, 18, 0, 26, 1, 88, 88, 88, 88, 36, 10, 1, 88,
            88, 36, 10, 1, 255, 2, 10, 0, 105, 1, 8, 105, 93, 105, 105, 105, 105, 105, 97, 105,
            105, 0, 47, 0, 1, 0, 0, 88, 88, 88, 88, 88, 88, 10, 48, 10, 0, 105, 1, 10, 1, 255, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 26, 1, 88, 88, 88, 88, 36, 10, 1, 255, 2, 10, 0, 105,
            1, 8, 105, 105, 105, 105, 105, 105, 97, 105, 105, 105, 88, 88, 88, 88, 88, 88, 88, 88,
            88, 10, 32, 10, 0, 105, 139, 10, 0, 0, 0, 0, 0, 18, 0, 26, 1, 88, 88, 88, 88, 36, 10,
            1, 255, 2, 10, 0, 105, 1, 86, 0, 0, 0, 0, 0, 0, 0, 8, 105, 105, 105, 105, 105, 105, 97,
            105, 88, 88, 88, 88, 88, 10, 48, 10, 0, 105, 1, 10, 1, 255, 2, 0, 0, 0, 0, 32, 0, 0, 0,
            0, 18, 0, 26, 1, 88, 88, 88, 88, 36, 10, 1, 88, 88, 36, 10, 1, 255, 2, 10, 0, 105, 1,
            8, 105, 105, 105, 105, 105, 105, 97, 105, 105, 105, 88, 88, 88, 88, 88, 88, 88, 88, 88,
            10, 48, 10, 0, 105, 0, 10, 1, 255, 2, 0, 0, 0, 0, 32, 0, 0, 0, 0, 18, 0, 26, 1, 88, 88,
            88, 88, 36, 10, 1, 255, 2, 0, 0, 0, 0, 0, 0, 0, 8, 0, 47, 0, 1, 0, 0, 88, 88, 88, 88,
            88, 88, 10, 48, 10, 0, 105, 1, 10, 1, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 26, 1,
            88, 88, 88, 88, 36, 142, 1, 255, 2, 10, 0, 105, 1, 8, 105, 105, 105, 105, 105, 105, 97,
            105, 105, 105, 88, 88, 88, 88, 88, 88, 88, 88, 88, 10, 32, 10, 0, 105, 139, 10, 1, 255,
            2, 0, 0, 0, 0, 0, 0, 18, 0, 26, 1, 88, 88, 0, 0, 0, 0, 0, 0, 18, 0, 26, 1, 88, 88, 88,
            88, 0, 26, 1, 88, 88, 88, 88, 36, 10, 1, 255, 2, 10, 0, 36, 1, 8, 105, 105, 105, 105,
            105, 105, 97, 105, 105, 105, 88, 88, 88, 88, 88, 88, 2, 0, 0, 0, 0, 32, 88, 36, 10, 1,
            255, 255, 255, 251, 2, 10, 0, 105, 1, 86, 0, 0, 0, 0, 0, 0, 0, 8, 105, 105, 105, 105,
            105, 105, 97, 105, 88, 88, 88, 88, 0, 0, 0, 0, 32, 0, 0, 0, 0, 18, 5, 26, 1, 88, 88,
            88, 88, 36, 10, 1, 255, 2, 0, 0, 0, 0, 0, 0, 0, 8, 0, 47, 0, 1, 0, 0, 88, 88, 88, 88,
            88, 88, 10, 48, 10, 0, 105, 1, 10, 1, 255, 2, 0, 0, 0, 0, 0, 0, 128, 0, 0, 18, 0, 26,
            1, 88, 88, 88, 88, 36, 142, 1, 255, 2, 255, 10, 0, 105, 1, 8, 105, 255, 2, 10, 0, 36,
            1, 8, 105, 105, 105, 105, 105, 105, 97, 105, 105, 105, 88, 88, 88, 88, 88, 88, 2, 0, 0,
            0, 0, 1, 255, 2, 105, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88,
        ]);
    }

    #[test]
    fn regression_2833() {
        // Regression test for https://github.com/paritytech/smoldot/issues/2833.
        let decoded = super::decode_block_request(
            4,
            &[
                8, 128, 128, 128, 136, 1, 26, 4, 237, 91, 33, 0, 48, 1, 56, 1,
            ],
        )
        .unwrap();
        assert!(matches!(
            decoded.direction,
            super::BlocksRequestDirection::Ascending
        ));
    }
}
