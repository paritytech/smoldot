// Substrate-lite
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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

//! *All-forks* header and body syncing.
//!
//! # Overview
//!
//! This state machine holds:
//!
//! - A list of sources of blocks, maintained by the API user.
//!  - For each source, a list of blocks hashes known by the source.
//! - The latest known finalized block.
//! - A tree of valid non-finalized blocks that all descend from the latest known finalized block.
//! - (if full mode) A list of block headers whose body is currently being downloaded.
//! - (if full mode) A list of block header and bodies waiting to be verified and whose ancestry
//! with the latest finalized block is currently unknown.
//!
//! The state machine has the objective to synchronize the tree of non-finalized blocks with its
//! equivalent on the sources added by the API user.
//!
//! Because it is not possible to predict which block in this tree is going to be finalized in
//! the future, the entire tree needs to be synchronized.
//!
//! > **Example**: If the latest finalized block is block number 4, and the tree contains blocks
//! >              5, 6, and 7, and a source announces a block 5 that is different from the
//! >              locally-known block 5, a block request will be emitted for this block 5, even
//! >              if it is certain that this "other" block 5 will not become the local best
//! >              block. This is necessary in case it is this other block 5 that will end up
//! >              being finalized.
//!
//! # Full vs non-full
//!
//! The [`Config::full`] option configures whether the state machine only holds headers of the
//! non-finalized blocks (`full` equal to `false`), or the headers, and bodies, and storage
//! (`full` equal to `true`).
//!
//! In full mode, .

use crate::{
    chain::{blocks_tree, chain_information},
    header,
};

use alloc::collections::BTreeSet;
use core::{convert::TryFrom as _, num::NonZeroU32, time::Duration};

/// Configuration for the [`AllForksSync`].
#[derive(Debug)]
pub struct Config {
    /// Information about the latest finalized block and its ancestors.
    pub chain_information: chain_information::ChainInformation,

    /// Pre-allocated capacity for the number of block sources.
    pub sources_capacity: usize,

    /// Pre-allocated capacity for the number of blocks between the finalized block and the head
    /// of the chain.
    ///
    /// Should be set to the maximum number of block between two consecutive justifications.
    pub blocks_capacity: usize,

    /// If true, the block bodies and storage are also synchronized.
    pub full: bool,
}

pub struct AllForksSync<TSrc, TBl> {
    /// Data structure containing the blocks.
    ///
    /// The user data, [`Block`], isn't used internally but stores information later reported
    /// to the user.
    chain: blocks_tree::NonFinalizedTree<Block<TBl>>,

    /// Extra fields. In a separate structure in order to be moved around.
    inner: Inner<TSrc>,
}

/// Extra fields. In a separate structure in order to be moved around.
struct Inner<TSrc> {
    /// See [`Config::full`].
    full: bool,

    /// List of sources. Controlled by the API user.
    sources: hashbrown::HashMap<SourceId, Source<TSrc>>,

    /// Identifier to allocate to the next source. Identifiers are never reused, which allows
    /// keeping obsolete identifiers in the internal state.
    next_source_id: SourceId,

    /// List of blocks whose body is currently being downloaded from a source.
    ///
    /// Always empty if `full` is `false`.
    pending_downloads: hashbrown::HashMap<[u8; 32], Option<SourceId>, fnv::FnvBuildHasher>,

    /// Stores `(source, block hash)` tuples. Each tuple is an information about the fact that
    /// this source knows about the given block. Only contains blocks whose height is higher than
    /// the height of the local finalized block.
    known_blocks1: BTreeSet<(SourceId, [u8; 32])>,

    /// Contains the same entries as [`Inner::known_blocks1`], but in reverse.
    known_blocks2: BTreeSet<([u8; 32], SourceId)>,

    block_hashes_by_height: Vec<(u64, [u8; 32])>,
}

struct Block<TBl> {
    user_data: TBl,
}

struct Source<TSrc> {
    best_block_number: u64,
    best_block_hash: [u8; 32],
    user_data: TSrc,
}

impl<TSrc, TBl> AllForksSync<TSrc, TBl> {
    pub fn new(config: Config) -> Self {
        let chain = blocks_tree::NonFinalizedTree::new(blocks_tree::Config {
            chain_information: config.chain_information,
            blocks_capacity: config.blocks_capacity,
        });

        Self {
            chain,
            inner: Inner {
                full: config.full,
                sources: Default::default(),
                next_source_id: SourceId(0),
                pending_downloads: Default::default(),
                known_blocks1: Default::default(),
                known_blocks2: Default::default(),
            },
        }
    }

    /// Inform the [`AllForksSync`] of a new potential source of blocks.
    ///
    /// The `user_data` parameter is opaque and decided entirely by the user. It can later be
    /// retrieved using [`SourceMutAccess::user_data`].
    pub fn add_source(
        &mut self,
        user_data: TSrc,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    ) -> SourceMutAccess<TSrc, TBl> {
        let new_id = {
            let id = self.inner.next_source_id;
            self.inner.next_source_id.0 += 1;
            id
        };

        self.inner.sources.insert(
            new_id,
            Source {
                best_block_number,
                best_block_hash,
                user_data,
            },
        );

        if best_block_number > self.chain.finalized_block_header().number {
            self.inner.known_blocks1.insert((new_id, best_block_hash));
            self.inner.known_blocks2.insert((best_block_hash, new_id));
        }

        SourceMutAccess {
            parent: self,
            source_id: new_id,
        }
    }

    /// Grants access to a source, using its identifier.
    pub fn source_mut(&mut self, id: SourceId) -> Option<SourceMutAccess<TSrc, TBl>> {
        if self.inner.sources.contains_key(&id) {
            Some(SourceMutAccess {
                parent: self,
                source_id: id,
            })
        } else {
            None
        }
    }

    pub fn blocks_response(self, source_id: SourceId) {}
}

/// Access to a source in a [`AllForksSync`]. Obtained through [`AllForksSync::source_mut`].
pub struct SourceMutAccess<'a, TSrc, TBl> {
    parent: &'a mut AllForksSync<TSrc, TBl>,
    source_id: SourceId,
}

impl<'a, TSrc, TBl> SourceMutAccess<'a, TSrc, TBl> {
    /// Returns the identifier of this source.
    pub fn id(&self) -> SourceId {
        self.source_id
    }

    /// Removes the source from the [`AllForksSync`].
    ///
    /// Removing the source cancels the request that is associated to it (if any).
    pub fn remove(self) -> TSrc {
        let source = self.parent.inner.sources.remove(&self.source_id).unwrap();
        source.user_data
    }

    /// Update the source with a newly-announced block.
    ///
    /// > **Note**: This information is normally reported by the source itself. In the case of a
    /// >           a networking peer, call this when the source sent a block announce.
    ///
    /// Must be passed the current UNIX time in order to verify that the block doesn't pretend to
    /// come from the future.
    pub fn block_announce(
        &mut self,
        announced_scale_encoded_header: Vec<u8>,
        is_best: bool,
        now_from_unix_epoch: Duration,
    ) -> BlockAnnounceOutcome {
        let announced_header = match header::decode(&announced_scale_encoded_header) {
            Ok(h) => h,
            Err(err) => return BlockAnnounceOutcome::InvalidHeader(err), // TODO: punish?
        };

        let announced_header_hash = announced_header.hash();

        // No matter what is done below, start by updating the "best block" according to this
        // source.
        if is_best {
            let source = self.parent.inner.sources.get_mut(&self.source_id).unwrap();
            source.best_block_number = announced_header.number;
            source.best_block_hash = announced_header.hash();
        }

        // It is assumed that all sources will eventually agree on the same finalized chain. If
        // the announced block number is lower or equal than the locally-finalized block number,
        // it is assumed that this source is simply late compared to the local node, and that the
        // block being announced will get discarded by this source in the future.
        if announced_header.number <= self.parent.chain.finalized_block_header().number {
            return BlockAnnounceOutcome::TooOld;
        }

        // Now that it is known that the block height.  TODO:
        debug_assert_eq!(
            self.parent.inner.known_blocks1.len(),
            self.parent.inner.known_blocks2.len()
        );
        self.parent
            .inner
            .known_blocks1
            .insert((self.source_id, announced_header_hash));
        self.parent
            .inner
            .known_blocks2
            .insert((announced_header_hash, self.source_id));

        // If the block is already part of the local tree of blocks, nothing more to do.
        if self
            .parent
            .chain
            .non_finalized_block_by_hash(&announced_header_hash)
            .is_some()
        {
            return BlockAnnounceOutcome::AlreadyVerified;
        }

        // Determine whether if the parent of the announced block is in the `NonFinalizedTree`.
        let parent_is_in_chain = {
            let local_finalized_block_hash = self.parent.chain.finalized_block_hash();
            self.parent
                .chain
                .non_finalized_block_by_hash(announced_header.parent_hash)
                .is_some()
                || *announced_header.parent_hash == local_finalized_block_hash
        };

        if let Some(pending) = self
            .parent
            .inner
            .pending_downloads
            .get_mut(&announced_header_hash)
        {
            // This block header has already been received in the past.
            if pending.is_none() {
                // If no source is currently downloading this block, add the source that has
                // just announced it.
                *pending = Some(self.source_id);
            }
        } else if parent_is_in_chain {
            // Parent is in the `NonFinalizedTree`, meaning it is possible to verify it.

            // Start by verifying the header alone.
            match self
                .parent
                .chain
                .verify_header(announced_scale_encoded_header, now_from_unix_epoch)
            {
                Ok(blocks_tree::HeaderVerifySuccess::Duplicate) => unreachable!(),
                Ok(blocks_tree::HeaderVerifySuccess::Insert { .. }) if self.parent.inner.full => {}
                Ok(blocks_tree::HeaderVerifySuccess::Insert {
                    insert,
                    is_new_best,
                    ..
                }) => {
                    insert.insert(());
                    return;
                }
                Err(_) => {
                    return;
                }
            }

            // Header if valid, and config is in full mode. Request the block body.
            self.parent
                .inner
                .pending_downloads
                .insert(announced_header_hash, Some(self.source_id));
            return;
        } else if announced_header.number == self.parent.chain.finalized_block_header().number + 1 {
            debug_assert_ne!(
                *announced_header.parent_hash,
                self.parent.chain.finalized_block_hash()
            );

            // Announced block is not part of the finalized chain.
            return BlockAnnounceOutcome::NotFinalizedChain;
        } else {
            // Parent is not in the `NonFinalizedTree`.
        }
    }

    /// Returns the user data associated to the source. This is the value originally passed
    /// through [`AllForksSync::add_source`].
    pub fn user_data(&mut self) -> &mut TSrc {
        let source = self.parent.inner.sources.get_mut(&self.source_id).unwrap();
        &mut source.user_data
    }

    /// Returns the user data associated to the source. This is the value originally passed
    /// through [`AllForksSync::add_source`].
    pub fn into_user_data(self) -> &'a mut TSrc {
        let source = self.parent.inner.sources.get_mut(&self.source_id).unwrap();
        &mut source.user_data
    }
}

#[derive(Debug)]
pub enum BlockAnnounceOutcome {
    /// Failed to decode announced header.
    InvalidHeader(header::Error),
    /// Announced block is too old to be part of the finalized chain.
    TooOld,
    /// Announced block has already been successfully verified and is part of the non-finalized
    /// chain.
    AlreadyVerified,
    /// Announced block is known to not be a descendant of the finalized block.
    NotFinalizedChain,
}

/// Identifier for a source in the [`AllForksSync`].
//
// Implementation note: the `u64` values are never re-used, making it possible to avoid clearing
// obsolete SourceIds in the `AllForksSync` state machine.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SourceId(u64);

/// State of the processing of blocks.
pub enum ProcessOne<TSrc, TBl> {
    /// No processing is necessary.
    ///
    /// Calling [`AllForksSync::process_one`] again is unnecessary.
    Idle {
        /// The state machine.
        /// The [`AllForksSync::process_one`] method takes ownership of the
        /// [`AllForksSync`]. This field yields it back.
        sync: AllForksSync<TSrc, TBl>,
    },

    /// An issue happened when verifying the block or its justification, resulting in resetting
    /// the chain to the latest finalized block.
    ///
    /// > **Note**: The latest finalized block might be a block imported during the same
    /// >           operation.
    Reset {
        /// The state machine.
        /// The [`AllForksSync::process_one`] method takes ownership of the
        /// [`AllForksSync`]. This field yields it back.
        sync: AllForksSync<TSrc, TBl>,

        /// Height of the best block before the reset.
        previous_best_height: u64,

        /// Problem that happened and caused the reset.
        reason: ResetCause,
    },

    /// Processing of the block is over.
    ///
    /// There might be more blocks remaining. Call [`AllForksSync::process_one`] again.
    NewBest {
        /// The state machine.
        /// The [`AllForksSync::process_one`] method takes ownership of the
        /// [`AllForksSync`]. This field yields it back.
        sync: AllForksSync<TSrc, TBl>,

        new_best_number: u64,
        new_best_hash: [u8; 32],
    },

    /// Processing of the block is over. The block has been finalized.
    ///
    /// There might be more blocks remaining. Call [`AllForksSync::process_one`] again.
    Finalized {
        /// The state machine.
        /// The [`AllForksSync::process_one`] method takes ownership of the
        /// [`AllForksSync`]. This field yields it back.
        sync: AllForksSync<TSrc, TBl>,

        /// Blocks that have been finalized. Includes the block that has just been verified.
        finalized_blocks: Vec<Block<TBl>>,
    },

    /// Loading a storage value of the finalized block is required in order to continue.
    FinalizedStorageGet(StorageGet<TSrc, TBl>),

    /// Fetching the list of keys of the finalized block with a given prefix is required in order
    /// to continue.
    FinalizedStoragePrefixKeys(StoragePrefixKeys<TSrc, TBl>),

    /// Fetching the key of the finalized block storage that follows a given one is required in
    /// order to continue.
    FinalizedStorageNextKey(StorageNextKey<TSrc, TBl>),
}
