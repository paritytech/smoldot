// Substrate-lite
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

//! Collection of "disjoint" blocks, in other words blocks whose existence is known but which
//! can't be verified yet.
//!
//! Example: the local node knows about block 5. A peer announces block 7. Since the local node
//! doesn't know block 6, it has to store block 7 for later, then download block 6. The container
//! in this module is where block 7 is temporarily stored.
//!
//! # Details
//!
//! The [`DisjointBlocks`] collection stores a list of pending blocks. In context, of syncing,
//! these blocks are blocks that cannot be verified yet or are about to be verified.
//!
//! Each block consists in an optional parent hash (present if and only if it is known) and a
//! user data.
//!
//! Blocks can only be removed in three different ways:
//!
//! - Calling [`OccupiedBlockEntry::remove_verify_success`] marks a block as valid and removes
//! it, as it is not pending anymore.
//! - Calling [`OccupiedBlockEntry::remove_verify_failed`] marks a block and all its descendants
//! as invalid. This may or may not remove the block itself and all its descendants.
//! - Calling [`OccupiedBlockEntry::remove_uninteresting`] removes a block in order to reduce
//! the memory usage of the data structure.
//!

// TODO: details in docs concerning "KnownBad"

use alloc::collections::BTreeMap;

/// Configuration for the [`DisjointBlocks`].
// TODO: exaggerated to have a config with one field
#[derive(Debug)]
pub struct Config {
    /// Pre-allocated capacity for the number of blocks between the finalized block and the head
    /// of the chain.
    pub blocks_capacity: usize,
}

/// Collection of pending blocks.
pub struct DisjointBlocks<TBl> {
    /// All blocks in the collection. Keys are the block height and hash.
    blocks: BTreeMap<(u64, [u8; 32]), Block<TBl>>,
}

struct Block<TBl> {
    user_data: TBl,
    inner: BlockInner,
}

enum BlockInner {
    /// Header of the block isn't known.
    Unknown,
    /// Header of the block is known.
    // TODO: rename
    UnverifiedHeader { parent_hash: [u8; 32] },
    /// Block is considered as bad by the API user. It is stored in the collection in order to be
    /// able to immediately rejecting children of this block without having to re-download it.
    KnownBad { parent_hash: [u8; 32] },
}

impl BlockInner {
    /// Returns the parent hash of this block, if it is known.
    fn parent_hash(&self) -> Option<&[u8; 32]> {
        match self {
            BlockInner::Unknown => None,
            BlockInner::KnownBad { parent_hash } => Some(parent_hash),
            BlockInner::UnverifiedHeader { parent_hash } => Some(parent_hash),
        }
    }
}

impl<TBl> DisjointBlocks<TBl> {
    /// Initializes a new empty collection of blocks.
    pub fn new(config: Config) -> Self {
        DisjointBlocks {
            blocks: Default::default(),
        }
    }

    /// Inserts the block in the collection, passing a user data.
    ///
    /// Returns the previous user data associated to this block, if any.
    pub fn insert(
        &mut self,
        height: u64,
        hash: [u8; 32],
        parent_hash: Option<[u8; 32]>,
        user_data: TBl,
    ) -> Option<TBl> {
        self.blocks
            .insert(
                (height, hash),
                Block {
                    user_data,
                    inner: if let Some(parent_hash) = parent_hash {
                        BlockInner::UnverifiedHeader { parent_hash }
                    } else {
                        BlockInner::Unknown
                    },
                },
            )
            .map(|b| b.user_data)
    }

    /// Returns `true` if this data structure doesn't contain any block.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Returns the number of blocks stored in the data structure.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the list of blocks whose parent hash is known but absent from the list of disjoint
    /// blocks. These blocks can potentially be verified.
    pub fn good_leaves(&'_ self) -> impl Iterator<Item = PendingVerificationBlock> + '_ {
        self.blocks
            .iter()
            .filter_map(move |((height, hash), block)| {
                let parent_hash = block.inner.parent_hash()?;

                // Return `None` if parent is in the list of blocks.
                if self.blocks.contains_key(&(*height - 1, *parent_hash)) {
                    return None;
                }

                Some(PendingVerificationBlock {
                    block_hash: *hash,
                    block_number: *height,
                    parent_block_hash: *parent_hash,
                })
            })
    }

    /// Returns an iterator yielding blocks that are known to exist but which either haven't been
    /// inserted, or whose parent hash isn't known.
    ///
    /// The iterator returns:
    ///
    /// - Blocks that have been inserted in this data structure but whose parent hash is unknown.
    /// - Parents of blocks that have been inserted in this data structure and whose parent hash
    /// is known and whose parent is missing.
    ///
    /// Blocks in the second category might include blocks that are already known by the user of
    /// this data structure. To avoid this, you are encouraged to remove from the
    /// [`DisjointBlocks`] any block that can be verified prior to calling this method.
    ///
    /// The blocks yielded by the iterator are always ordered by ascending height.
    pub fn unknown_blocks(&'_ self) -> impl Iterator<Item = (u64, &'_ [u8; 32])> + '_ {
        // TODO: bad ordering of items returned
        self.blocks
            .iter()
            .filter(|(_, s)| matches!(s.inner, BlockInner::Unknown))
            .map(|((n, h), b)| (*n, h))
            .chain(
                self.blocks
                    .iter()
                    .filter_map(|((n, _), s)| s.inner.parent_hash().map(|h| (n - 1, h)))
                    .filter(move |(n, h)| !self.blocks.contains_key(&(*n, **h))),
            )
    }

    /// Returns the user data associated to the block. This is the value originally passed
    /// through [`DisjointBlocks::insert`].
    ///
    /// Returns `None` if the block hasn't been inserted before.
    pub fn user_data(&self, height: u64, hash: &[u8; 32]) -> Option<&TBl> {
        Some(&self.blocks.get(&(height, *hash))?.user_data)
    }

    /// Returns the user data associated to the block. This is the value originally passed
    /// through [`DisjointBlocks::insert`].
    ///
    /// Returns `None` if the block hasn't been inserted before.
    pub fn user_data_mut(&mut self, height: u64, hash: &[u8; 32]) -> Option<&mut TBl> {
        Some(&mut self.blocks.get_mut(&(height, *hash))?.user_data)
    }

    /// Sets the parent hash of the given block.
    ///
    /// # Panic
    ///
    /// Panics if the block with the given height and hash hasn't been inserted before.
    ///
    pub fn set_parent_hash(&mut self, height: u64, hash: &[u8; 32], parent_hash: [u8; 32]) {
        let block = self.blocks.get_mut(&(height, *hash)).unwrap();
        match &block.inner {
            // Transition from `Unknown` to `UnverifiedHeader`.
            BlockInner::Unknown => {
                block.inner = BlockInner::UnverifiedHeader { parent_hash };
            }

            // Parent hash doesn't interest us anymore.
            BlockInner::KnownBad { .. } => {}

            // Parent hash already known. Do a basic sanity check.
            BlockInner::UnverifiedHeader {
                parent_hash: already_in,
            } => {
                debug_assert_eq!(*already_in, parent_hash);
            }
        };
    }

    /// Removes the block from the collection, as it has now been successfully verified.
    ///
    /// # Panic
    ///
    /// Panics if the block with the given height and hash hasn't been inserted before.
    ///
    pub fn remove_verify_success(&mut self, height: u64, hash: &[u8; 32]) -> TBl {
        self.blocks.remove(&(height, *hash)).unwrap().user_data
    }

    /// Removes the block from the collection, as its verification has failed.
    ///
    /// # Panic
    ///
    /// Panics if the block with the given height and hash hasn't been inserted before.
    ///
    pub fn remove_verify_failed(&mut self, height: u64, hash: &[u8; 32]) {
        //self.blocks.remove(&(height, *hash)).unwrap().user_data

        // TODO: remove children of the block as well
        todo!()
    }

    /// Removes the block from the collection in order to leave space.
    ///
    /// # Panic
    ///
    /// Panics if the block with the given height and hash hasn't been inserted before.
    ///
    pub fn remove_uninteresting(&mut self, height: u64, hash: &[u8; 32]) {
        // TODO: temporary implementation
        self.remove_verify_failed(height, hash);
    }

    // TODO: deal with that
    /*/// Passed a known entry in `blocks`. Removes this entry and any known children of this block.
    ///
    /// # Panic
    ///
    /// Panics if `(number, hash)` isn't an entry in [`DisjointBlocks::blocks`].
    ///
    pub fn discard_chain(&mut self, number: u64, hash: [u8; 32]) -> Vec<(u64, [u8; 32])> {
        // TODO: keep a list of banned blocks for later? this is required by chain specs anyway

        // The implementation consists in iterating over the increasing block number, and removing
        // all blocks whose parent was removed at the previous iteration.

        // Return value of the function.
        let mut result = Vec::with_capacity(64);

        // List of blocks to discard at the next iteration.
        let mut blocks_to_discard = Vec::with_capacity(16);
        blocks_to_discard.push(hash);

        for number in number.. {
            // The `for` loop would be infinite unless we put an explicit `break`.
            if blocks_to_discard.is_empty() {
                break;
            }

            // Find in `disjoint_headers` any block whose parent is in `blocks_to_discard`.
            let blocks_to_discard_next = {
                let mut blocks_to_discard_next = Vec::with_capacity(16);
                for ((_, hash), block) in self
                    .blocks
                    .range((number + 1, [0; 32])..=(number + 1, [0xff; 32]))
                {
                    let decoded = header::decode(&block.scale_encoded_header).unwrap();
                    if blocks_to_discard.iter().any(|b| b == decoded.parent_hash) {
                        blocks_to_discard_next.push(*hash);
                    }
                }
                blocks_to_discard_next
            };

            // Now discard `blocks_to_discard`.
            for to_discard in mem::replace(&mut blocks_to_discard, blocks_to_discard_next) {
                let mut discarded_block = self.blocks.remove(&(number, to_discard)).unwrap();

                let requests_ids = self
                    .blocks_requests
                    .range(
                        (number, to_discard, RequestId(usize::min_value()))
                            ..=(number, to_discard, RequestId(usize::max_value())),
                    )
                    .map(|(_, _, id)| *id)
                    .collect::<Vec<_>>();

                for request_id in requests_ids {
                    let _was_in = self
                        .blocks_requests
                        .remove(&(number, to_discard, request_id));
                    debug_assert!(_was_in);

                    let request = self.requests.remove(&request_id.0).unwrap();
                }

                result.push((number, to_discard, discarded_block));
            }
        }

        result
    }*/

    /// Returns the list of children of the given block that are in the collection.
    fn children_mut<'a>(
        &'a mut self,
        height: u64,
        hash: &'a [u8; 32],
    ) -> impl Iterator<Item = ((u64, [u8; 32]), &mut Block<TBl>)> + 'a {
        self.blocks
            .range_mut((height + 1, [0x0; 32])..=(height + 1, [0xff; 32]))
            .filter(move |(_, block)| block.inner.parent_hash() == Some(hash))
            .map(|(k, v)| (*k, v))
    }
}

/// See [`DisjointBlocks::pending_verification_blocks`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PendingVerificationBlock {
    /// Hash of the block that can potentially be verified.
    pub block_hash: [u8; 32],
    /// Height of the block that can potentially be verified.
    pub block_number: u64,
    /// Hash of the parent of the block.
    pub parent_block_hash: [u8; 32],
}
