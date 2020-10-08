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
#[derive(Debug, PartialEq, Eq)]
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
#[derive(Debug, PartialEq, Eq)]
pub enum BlocksRequestDirection {
    /// Blocks should be returned in ascending number, starting from the requested one.
    Ascending,
    /// Blocks should be returned in descending number, starting from the requested one.
    Descending,
}

/// Which fields should be present in the response.
#[derive(Debug, PartialEq, Eq)]
pub struct BlocksRequestFields {
    pub header: bool,
    pub body: bool,
    pub justification: bool,
}

/// Which block the remote must return first.
#[derive(Debug, PartialEq, Eq)]
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
