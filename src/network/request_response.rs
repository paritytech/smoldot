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

//! Builds requests and responses of high-level request-response-type protocols.

// TODO: expand docs

use core::{
    convert::TryFrom as _,
    iter,
    num::{NonZeroU32, NonZeroU64},
};
use prost::Message as _;

mod schema {
    include!(concat!(env!("OUT_DIR"), "/api.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/api.v1.finality.rs"));
    include!(concat!(env!("OUT_DIR"), "/api.v1.light.rs"));
}

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
    pub justification: bool,
}

/// Which block the remote must return first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlocksRequestConfigStart {
    /// Hash of the block.
    Hash([u8; 32]),
    /// Number of the block, where 0 would be the genesis block.
    Number(NonZeroU64),
}

/// Builds the bytes corresponding to a block request.
pub fn build_block_request(config: BlocksRequestConfig) -> impl Iterator<Item = impl AsRef<[u8]>> {
    let request = {
        let mut fields = 0u32;
        if config.fields.header {
            fields |= 0b00000001;
        }
        if config.fields.body {
            fields |= 0b00000010;
        }
        if config.fields.justification {
            fields |= 0b00000010;
        }

        schema::BlockRequest {
            // TODO: make this cleaner; don't use swap_bytes
            fields: fields.swap_bytes(),
            from_block: match config.start {
                BlocksRequestConfigStart::Hash(h) => {
                    Some(schema::block_request::FromBlock::Hash(h.to_vec()))
                }
                BlocksRequestConfigStart::Number(n) => Some(
                    schema::block_request::FromBlock::Number(n.get().to_le_bytes().to_vec()),
                ),
            },
            to_block: Vec::new(),
            direction: match config.direction {
                BlocksRequestDirection::Ascending => schema::Direction::Ascending as i32,
                BlocksRequestDirection::Descending => schema::Direction::Descending as i32,
            },
            max_blocks: config.desired_count.get(),
        }
    };

    let request_bytes = {
        let mut buf = Vec::with_capacity(request.encoded_len());
        request.encode(&mut buf).unwrap();
        buf
    };

    iter::once(request_bytes)
}

/// Decodes a response to a block request.
// TODO: should have a more zero-cost API, but we're limited by the protobuf library for that
pub fn decode_block_response(
    response_bytes: &[u8],
) -> Result<Vec<BlockData>, DecodeBlockResponseError> {
    let response = schema::BlockResponse::decode(&response_bytes[..])
        .map_err(ProtobufDecodeError)
        .map_err(DecodeBlockResponseError::ProtobufDecode)?;

    let mut blocks = Vec::with_capacity(response.blocks.len());
    for block in response.blocks {
        if block.hash.len() != 32 {
            return Err(DecodeBlockResponseError::InvalidHashLength);
        }

        let mut body = Vec::with_capacity(block.body.len());
        for extrinsic in block.body {
            // TODO: this encoding really is a bit stupid
            let ext = match <Vec<u8> as parity_scale_codec::DecodeAll>::decode_all(
                &mut extrinsic.as_ref(),
            ) {
                Ok(e) => e,
                Err(_) => {
                    return Err(DecodeBlockResponseError::BodyDecodeError);
                }
            };

            body.push(ext);
        }

        blocks.push(BlockData {
            hash: <[u8; 32]>::try_from(&block.hash[..]).unwrap(),
            header: if !block.header.is_empty() {
                Some(block.header)
            } else {
                None
            },
            // TODO: no; we might not have asked for the body
            body: Some(body),
            justification: if !block.justification.is_empty() {
                Some(block.justification)
            } else if block.is_empty_justification {
                Some(Vec::new())
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

    /// Block body, if requested.
    pub body: Option<Vec<Vec<u8>>>,

    /// Justification, if requested and available.
    pub justification: Option<Vec<u8>>,
}

/// Error potentially returned by [`decode_block_response`].
#[derive(Debug, derive_more::Display)]
pub enum DecodeBlockResponseError {
    /// Error while decoding the protobuf encoding.
    ProtobufDecode(ProtobufDecodeError),
    /// Hash length isn't of the correct length.
    InvalidHashLength,
    BodyDecodeError,
}

/// Error while decoding the protobuf encoding.
#[derive(Debug, derive_more::Display)]
#[display(fmt = "{}", _0)]
pub struct ProtobufDecodeError(prost::DecodeError);
