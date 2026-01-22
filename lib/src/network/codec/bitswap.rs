// Smoldot
// Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
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

//! Bitswap protocol codec.
//!
//! The Bitswap protocol is used to exchange blocks of data, primarily for IPFS.
//! Protocol name: `/ipfs/bitswap/1.2.0`
//!
//! See <https://specs.ipfs.tech/bitswap-protocol/#bitswap-1-2-0> for the specification.

use crate::util::protobuf;

use alloc::vec::Vec;

/// Maximum size of a Bitswap message.
pub const MAX_BITSWAP_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// Maximum number of wanted blocks in a single request.
pub const MAX_WANTED_BLOCKS: usize = 1024;

/// Maximum number of blocks in a response.
pub const MAX_RESPONSE_BLOCKS: usize = 1024;

/// Maximum number of block presences in a response.
pub const MAX_BLOCK_PRESENCES: usize = 1024;

/// Type of want request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WantType {
    /// Request the actual block data.
    Block = 0,
    /// Only request presence information (Have/DontHave).
    Have = 1,
}

impl WantType {
    fn from_u64(val: u64) -> Option<Self> {
        match val {
            0 => Some(WantType::Block),
            1 => Some(WantType::Have),
            _ => None,
        }
    }
}

/// Block presence type in response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockPresenceType {
    /// The peer has this block.
    Have = 0,
    /// The peer does not have this block.
    DontHave = 1,
}

impl BlockPresenceType {
    fn from_u64(val: u64) -> Option<Self> {
        match val {
            0 => Some(BlockPresenceType::Have),
            1 => Some(BlockPresenceType::DontHave),
            _ => None,
        }
    }
}

/// A wantlist entry requesting a specific block.
#[derive(Debug, Clone)]
pub struct WantlistEntry<'a> {
    /// The CID (Content Identifier) of the wanted block.
    pub cid: &'a [u8],
    /// Priority of the request (higher = more important).
    pub priority: i32,
    /// If true, this cancels a previous request for this CID.
    pub cancel: bool,
    /// Type of want request (Block or Have).
    pub want_type: WantType,
    /// If true, request DontHave responses for missing blocks.
    pub send_dont_have: bool,
}

/// A wantlist containing multiple block requests.
#[derive(Debug, Clone)]
pub struct Wantlist<'a> {
    /// List of wanted block entries.
    pub entries: Vec<WantlistEntry<'a>>,
    /// If true, this is the full wantlist (replaces any previous).
    pub full: bool,
}

/// A block with its CID prefix and data.
#[derive(Debug, Clone)]
pub struct Block<'a> {
    /// CID prefix (version, codec, hash type, hash length).
    pub prefix: &'a [u8],
    /// The actual block data.
    pub data: &'a [u8],
}

/// Block presence information.
#[derive(Debug, Clone)]
pub struct BlockPresence<'a> {
    /// The CID of the block.
    pub cid: &'a [u8],
    /// Whether the peer has the block or not.
    pub presence_type: BlockPresenceType,
}

/// A decoded Bitswap message.
#[derive(Debug, Clone, Default)]
pub struct Message<'a> {
    /// Wantlist containing requested blocks.
    pub wantlist: Option<Wantlist<'a>>,
    /// Blocks sent in response (Bitswap 1.0.0 format).
    pub blocks_legacy: Vec<&'a [u8]>,
    /// Blocks sent in response (Bitswap 1.1.0+ format with prefix).
    pub payload: Vec<Block<'a>>,
    /// Block presence information.
    pub block_presences: Vec<BlockPresence<'a>>,
    /// Number of bytes of data pending to be sent.
    pub pending_bytes: i32,
}

/// Builds a Bitswap message requesting blocks.
///
/// # Arguments
/// * `cids` - Iterator of CIDs to request
/// * `want_type` - Whether to request full blocks or just presence info
/// * `send_dont_have` - Whether to request DontHave responses
/// * `full` - Whether this is the full wantlist
pub fn build_want_message(
    cids: impl Iterator<Item = impl AsRef<[u8]>>,
    want_type: WantType,
    send_dont_have: bool,
    full: bool,
) -> Vec<u8> {
    let cids: Vec<_> = cids.collect();

    // Build wantlist entries
    let mut entries_encoded = Vec::new();
    for (priority, cid) in cids.iter().enumerate() {
        let entry = build_wantlist_entry(cid.as_ref(), priority as i32, want_type, send_dont_have);
        // Encode as repeated message field (tag 1, wire type 2)
        for slice in protobuf::message_tag_encode(1, core::iter::once(entry.as_slice())) {
            entries_encoded.extend_from_slice(slice.as_ref());
        }
    }

    // Add full flag if true
    if full {
        for slice in protobuf::bool_tag_encode(2, true) {
            entries_encoded.extend_from_slice(slice.as_ref());
        }
    }

    // Wrap in wantlist message (tag 1)
    let mut out = Vec::with_capacity(entries_encoded.len() + 16);
    for slice in protobuf::message_tag_encode(1, core::iter::once(entries_encoded.as_slice())) {
        out.extend_from_slice(slice.as_ref());
    }

    out
}

/// Builds a single wantlist entry as a byte vector.
fn build_wantlist_entry(
    cid: &[u8],
    priority: i32,
    want_type: WantType,
    send_dont_have: bool,
) -> Vec<u8> {
    let mut entry = Vec::new();

    // Field 1: block (CID)
    for slice in protobuf::bytes_tag_encode(1, cid) {
        entry.extend_from_slice(slice.as_ref());
    }

    // Field 2: priority (int32)
    for slice in protobuf::uint32_tag_encode(2, priority as u32) {
        entry.extend_from_slice(slice.as_ref());
    }

    // Field 4: wantType (enum) - only encode if not Block (default)
    if want_type != WantType::Block {
        for slice in protobuf::enum_tag_encode(4, want_type as u64) {
            entry.extend_from_slice(slice.as_ref());
        }
    }

    // Field 5: sendDontHave (bool) - only encode if true
    if send_dont_have {
        for slice in protobuf::bool_tag_encode(5, true) {
            entry.extend_from_slice(slice.as_ref());
        }
    }

    entry
}

/// Builds a Bitswap response message with blocks.
pub fn build_bitswap_block_response(
    blocks: impl Iterator<Item = (impl AsRef<[u8]>, impl AsRef<[u8]>)>,
) -> Vec<u8> {
    let mut out = Vec::new();

    for (prefix, data) in blocks {
        // Build Block message
        let mut block_msg = Vec::new();
        for slice in protobuf::bytes_tag_encode(1, prefix.as_ref()) {
            block_msg.extend_from_slice(slice.as_ref());
        }
        for slice in protobuf::bytes_tag_encode(2, data.as_ref()) {
            block_msg.extend_from_slice(slice.as_ref());
        }

        // Encode as payload field (tag 3)
        for slice in protobuf::message_tag_encode(3, core::iter::once(block_msg.as_slice())) {
            out.extend_from_slice(slice.as_ref());
        }
    }

    out
}

/// Builds a Bitswap response with block presence information.
pub fn build_bitswap_presence_response(
    presences: impl Iterator<Item = (impl AsRef<[u8]>, BlockPresenceType)>,
) -> Vec<u8> {
    let mut out = Vec::new();

    for (cid, presence_type) in presences {
        // Build BlockPresence message
        let mut presence_msg = Vec::new();
        for slice in protobuf::bytes_tag_encode(1, cid.as_ref()) {
            presence_msg.extend_from_slice(slice.as_ref());
        }
        for slice in protobuf::enum_tag_encode(2, presence_type as u64) {
            presence_msg.extend_from_slice(slice.as_ref());
        }

        // Encode as blockPresences field (tag 4)
        for slice in protobuf::message_tag_encode(4, core::iter::once(presence_msg.as_slice())) {
            out.extend_from_slice(slice.as_ref());
        }
    }

    out
}

/// Decodes a Bitswap message.
pub fn decode_message(bytes: &[u8]) -> Result<Message<'_>, DecodeMessageError> {
    // Parse the outer message
    let mut parser = nom::combinator::all_consuming::<_, nom::error::Error<&[u8]>, _>(
        nom::combinator::complete(protobuf::message_decode! {
            #[optional] wantlist = 1 => protobuf::message_tag_decode(protobuf::message_decode! {
                #[repeated(max = MAX_WANTED_BLOCKS)] entries = 1 => protobuf::message_tag_decode(protobuf::message_decode! {
                    #[optional] block = 1 => protobuf::bytes_tag_decode,
                    #[optional] priority = 2 => protobuf::uint32_tag_decode,
                    #[optional] cancel = 3 => protobuf::bool_tag_decode,
                    #[optional] want_type = 4 => protobuf::enum_tag_decode,
                    #[optional] send_dont_have = 5 => protobuf::bool_tag_decode,
                }),
                #[optional] full = 2 => protobuf::bool_tag_decode,
            }),
            #[repeated(max = MAX_RESPONSE_BLOCKS)] blocks_legacy = 2 => protobuf::bytes_tag_decode,
            #[repeated(max = MAX_RESPONSE_BLOCKS)] payload = 3 => protobuf::message_tag_decode(protobuf::message_decode! {
                #[optional] prefix = 1 => protobuf::bytes_tag_decode,
                #[optional] data = 2 => protobuf::bytes_tag_decode,
            }),
            #[repeated(max = MAX_BLOCK_PRESENCES)] block_presences = 4 => protobuf::message_tag_decode(protobuf::message_decode! {
                #[optional] cid = 1 => protobuf::bytes_tag_decode,
                #[optional] presence_type = 2 => protobuf::enum_tag_decode,
            }),
            #[optional] pending_bytes = 5 => protobuf::uint32_tag_decode,
        }),
    );

    let parsed = match nom::Finish::finish(nom::Parser::parse(&mut parser, bytes)) {
        Ok((_, out)) => out,
        Err(_) => return Err(DecodeMessageError::ProtobufDecode),
    };

    // Convert parsed data to Message struct
    let wantlist = if let Some(wl) = parsed.wantlist {
        let entries = wl
            .entries
            .into_iter()
            .map(|e| {
                Ok(WantlistEntry {
                    cid: e.block.ok_or(DecodeMessageError::MissingCid)?,
                    priority: e.priority.unwrap_or(1) as i32,
                    cancel: e.cancel.unwrap_or(false),
                    want_type: WantType::from_u64(e.want_type.unwrap_or(0))
                        .ok_or(DecodeMessageError::InvalidWantType)?,
                    send_dont_have: e.send_dont_have.unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Some(Wantlist {
            entries,
            full: wl.full.unwrap_or(false),
        })
    } else {
        None
    };

    let payload = parsed
        .payload
        .into_iter()
        .map(|b| Block {
            prefix: b.prefix.unwrap_or(&[]),
            data: b.data.unwrap_or(&[]),
        })
        .collect();

    let block_presences = parsed
        .block_presences
        .into_iter()
        .filter_map(|bp| {
            Some(BlockPresence {
                cid: bp.cid?,
                presence_type: BlockPresenceType::from_u64(bp.presence_type.unwrap_or(0))?,
            })
        })
        .collect();

    Ok(Message {
        wantlist,
        blocks_legacy: parsed.blocks_legacy,
        payload,
        block_presences,
        pending_bytes: parsed.pending_bytes.unwrap_or(0) as i32,
    })
}

/// Error while decoding a Bitswap message.
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub enum DecodeMessageError {
    /// Error decoding the Protobuf encoding.
    #[display("Protobuf decode error")]
    ProtobufDecode,
    /// Missing CID in wantlist entry.
    #[display("Missing CID in wantlist entry")]
    MissingCid,
    /// Invalid want type value.
    #[display("Invalid want type")]
    InvalidWantType,
    /// Invalid block presence type value.
    #[display("Invalid block presence type")]
    InvalidPresenceType,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_want_message() {
        let cids = vec![[1u8; 32], [2u8; 32]];
        let encoded = build_want_message(cids.iter(), WantType::Block, true, false);

        let decoded = decode_message(&encoded).unwrap();
        let wantlist = decoded.wantlist.unwrap();

        assert_eq!(wantlist.entries.len(), 2);
        assert_eq!(wantlist.entries[0].cid, &[1u8; 32]);
        assert_eq!(wantlist.entries[1].cid, &[2u8; 32]);
        assert_eq!(wantlist.entries[0].want_type, WantType::Block);
        assert!(wantlist.entries[0].send_dont_have);
        assert!(!wantlist.full);
    }

    #[test]
    fn encode_decode_want_have() {
        let cids = vec![[0xABu8; 32]];
        let encoded = build_want_message(cids.iter(), WantType::Have, false, true);

        let decoded = decode_message(&encoded).unwrap();
        let wantlist = decoded.wantlist.unwrap();

        assert_eq!(wantlist.entries.len(), 1);
        assert_eq!(wantlist.entries[0].want_type, WantType::Have);
        assert!(!wantlist.entries[0].send_dont_have);
        assert!(wantlist.full);
    }

    #[test]
    fn encode_decode_block_response() {
        let blocks = vec![
            ([1u8, 2, 3, 4].as_slice(), [5u8, 6, 7, 8].as_slice()),
            ([9u8, 10].as_slice(), [11u8, 12, 13].as_slice()),
        ];
        let encoded = build_bitswap_block_response(blocks.into_iter());

        let decoded = decode_message(&encoded).unwrap();

        assert_eq!(decoded.payload.len(), 2);
        assert_eq!(decoded.payload[0].prefix, &[1, 2, 3, 4]);
        assert_eq!(decoded.payload[0].data, &[5, 6, 7, 8]);
        assert_eq!(decoded.payload[1].prefix, &[9, 10]);
        assert_eq!(decoded.payload[1].data, &[11, 12, 13]);
    }

    #[test]
    fn encode_decode_presence_response() {
        let presences = vec![
            ([1u8; 32].as_slice(), BlockPresenceType::Have),
            ([2u8; 32].as_slice(), BlockPresenceType::DontHave),
        ];
        let encoded = build_bitswap_presence_response(presences.into_iter());

        let decoded = decode_message(&encoded).unwrap();

        assert_eq!(decoded.block_presences.len(), 2);
        assert_eq!(decoded.block_presences[0].cid, &[1u8; 32]);
        assert_eq!(
            decoded.block_presences[0].presence_type,
            BlockPresenceType::Have
        );
        assert_eq!(decoded.block_presences[1].cid, &[2u8; 32]);
        assert_eq!(
            decoded.block_presences[1].presence_type,
            BlockPresenceType::DontHave
        );
    }

    #[test]
    fn decode_empty_message() {
        let decoded = decode_message(&[]).unwrap();
        assert!(decoded.wantlist.is_none());
        assert!(decoded.payload.is_empty());
        assert!(decoded.block_presences.is_empty());
    }
}
