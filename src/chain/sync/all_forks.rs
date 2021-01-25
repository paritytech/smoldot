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

// TODO: finish ^

use crate::{
    chain::{blocks_tree, chain_information},
    header, verify,
};

use alloc::collections::{btree_map, BTreeMap, BTreeSet};
use core::{mem, num::NonZeroU64, time::Duration};

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
    /// Data structure containing the non-finalized blocks.
    chain: blocks_tree::NonFinalizedTree<Block<TBl>>,

    /// Extra fields. In a separate structure in order to be moved around.
    inner: Inner<TSrc>,
}

/// Extra fields. In a separate structure in order to be moved around.
struct Inner<TSrc> {
    /// See [`Config::full`].
    full: bool,

    /// List of sources. Controlled by the API user.
    sources: hashbrown::HashMap<SourceId, Source<TSrc>, fnv::FnvBuildHasher>,

    /// Identifier to allocate to the next source. Identifiers are never reused, which allows
    /// keeping obsolete identifiers in the internal state.
    next_source_id: SourceId,

    /// List of blocks whose body is currently being downloaded from a source or should be
    /// downloaded from a source as soon as possible.
    ///
    /// Contains a value the SCALE-encoded header and source the block is currently being
    /// downloaded from.
    ///
    /// Always empty if `full` is `false`.
    pending_body_downloads:
        hashbrown::HashMap<[u8; 32], (header::Header, Option<SourceId>), fnv::FnvBuildHasher>,

    /// Stores `(source, block hash)` tuples. Each tuple is an information about the fact that
    /// this source knows about the given block. Only contains blocks whose height is strictly
    /// superior to the height of the local finalized block.
    known_blocks1: BTreeSet<(SourceId, [u8; 32])>, // TODO: move to standalone container?

    /// Contains the same entries as [`Inner::known_blocks1`], but in reverse.
    known_blocks2: BTreeSet<([u8; 32], SourceId)>, // TODO: move to standalone container?

    /// Map of blocks whose parent is either unknown or present in `disjoint_blocks` as well.
    ///
    /// Only contains blocks whose height is strictly superior to the height of the local
    /// finalized block.
    ///
    /// The keys are `(block_height, block_hash)`. Using a b-tree and putting the block number in
    /// the key makes it possible to remove obsolete entries once blocks are finalized. For
    /// example, when block `N` is finalized, all entries whose key starts with `N` can be
    /// removed.
    disjoint_blocks: BTreeMap<(u64, [u8; 32]), DisjointBlock>, // TODO: move to standalone container?
}

struct Block<TBl> {
    user_data: TBl,
}

struct DisjointBlock {
    /// Header of the block. Guaranteed to be a valid header.
    scale_encoded_header: Vec<u8>,

    /// If `Some`, the given source is currently performing an ancestry search whose first
    /// block is the parent of this one.
    /// [`Source::occupation`] must be [`SourceOccupation::AncestrySearch`] with the parent hash
    /// indicated by [`DisjointBlock::scale_encoded_header`].
    ancestry_search: Option<SourceId>,
}

/// Extra fields specific to each blocks source.
struct Source<TSrc> {
    best_block_number: u64,
    best_block_hash: [u8; 32],
    occupation: SourceOccupation,
    user_data: TSrc,
}

#[derive(Debug)]
enum SourceOccupation {
    /// Source isn't doing anything.
    Idle,
    /// Source is performing an ancestry search. Contains the hash of the first block expected in
    /// the response.
    AncestrySearch([u8; 32]),
}

impl<TSrc, TBl> AllForksSync<TSrc, TBl> {
    /// Initializes a new [`AllForksSync`].
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
                pending_body_downloads: Default::default(),
                known_blocks1: Default::default(),
                known_blocks2: Default::default(),
                disjoint_blocks: Default::default(),
            },
        }
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct corresponding to the current
    /// latest finalized block. Can later be used to reconstruct a chain.
    pub fn as_chain_information(&self) -> chain_information::ChainInformationRef {
        self.chain.as_chain_information()
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
                occupation: SourceOccupation::Idle,
                user_data,
            },
        );

        if best_block_number > self.chain.finalized_block_header().number {
            self.inner.known_blocks1.insert((new_id, best_block_hash));
            self.inner.known_blocks2.insert((best_block_hash, new_id));
        }

        // TODO: start a header request for the best block, if it is unknown locally?

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

    /// Call in response to a [`BlockAnnounceOutcome::AncestrySearchStart`].
    ///
    /// The headers are expected to be sorted in decreasing order. The first element of the
    /// iterator should be the block with the hash passed through
    /// [`BlockAnnounceOutcome::AncestrySearchStart::first_block_hash`]. Each subsequent element
    /// is then expected to be the parent of the previous one.
    ///
    /// It is legal for the iterator to be shorter than the number of blocks that were requested
    /// through [`BlockAnnounceOutcome::AncestrySearchStart::num_blocks`].
    ///
    /// # Panic
    ///
    /// Panics if the source wasn't known locally as downloading something.
    ///
    pub fn ancestry_search_response(
        &mut self,
        now_from_unix_epoch: Duration,
        source_id: SourceId,
        scale_encoded_headers: Result<impl Iterator<Item = impl AsRef<[u8]>>, ()>,
    ) -> AncestrySearchResponseOutcome {
        // Height of the finalized chain. Saved for later.
        let local_finalized_block_number = self.chain.finalized_block_header().number;

        // The next block in the list of headers should have a hash equal to this one.
        // Sets the `occupation` of `source_id` back to `Idle`.
        let expected_next_hash = match mem::replace(
            &mut self.inner.sources.get_mut(&source_id).unwrap().occupation,
            SourceOccupation::Idle,
        ) {
            SourceOccupation::AncestrySearch(hash) => hash,
            _ => panic!(),
        };

        // Set to true if any block in the response is "valid", in the sense that it has made
        // progress.
        let mut any_progress = false;

        // Iterate through the response. If the request has failed, treat it the same way as if
        // no blocks were returned.
        for scale_encoded_header in scale_encoded_headers.into_iter().flat_map(|l| l) {
            let scale_encoded_header = scale_encoded_header.as_ref();

            // Compare expected with actual hash.
            if expected_next_hash != header::hash_from_scale_encoded_header(scale_encoded_header) {
                break;
            }

            // Invalid headers are skipped. The next iteration will likely fail when comparing
            // actual with expected hash, but we give it a chance.
            let decoded_header = match header::decode(scale_encoded_header) {
                Ok(h) => h,
                Err(_) => continue,
            };

            any_progress = true;

            // Whether to continue looping after inserting in `disjoint_blocks`.
            let stop_looping = {
                // Is `decoded_header.parent_hash` known locally?
                let parent_is_in_chain: bool = {
                    let local_finalized_block_hash = self.chain.finalized_block_hash();
                    *decoded_header.parent_hash == local_finalized_block_hash
                        || self
                            .chain
                            .non_finalized_block_by_hash(decoded_header.parent_hash)
                            .is_some()
                };

                // Parent is in chain or parent *should be* in chain
                parent_is_in_chain || decoded_header.number == local_finalized_block_number + 1
            };

            // This is equivalent to `disjoint_blocks.insert(...)`, except that we don't want
            // to modify the value of a `DisjointBlock::ancestry_search` field that might
            // already be present.
            match self
                .inner
                .disjoint_blocks
                .entry((decoded_header.number, expected_next_hash))
            {
                btree_map::Entry::Occupied(mut entry) => {
                    debug_assert_eq!(entry.get_mut().scale_encoded_header, scale_encoded_header);
                }
                btree_map::Entry::Vacant(entry) => {
                    entry.insert(DisjointBlock {
                        scale_encoded_header: scale_encoded_header.to_vec(),
                        ancestry_search: None,
                    });
                }
            }

            // Stop looping if the iteration reached the locally-known chain.
            if stop_looping {
                break;
            }
        }

        // If this is reached, then the ancestry search was inconclusive. Only blocks of unknown
        // ancestry have been received.

        if !any_progress {
            // The response from the node was useless.
            // TODO: somehow ban the node
        }

        todo!()
    }

    /// Call in response to a [`BlockAnnounceOutcome::BlockBodyDownloadStart`].
    ///
    /// # Panic
    ///
    /// Panics if the source wasn't known locally as downloading something.
    ///
    pub fn block_body_response(
        mut self,
        now_from_unix_epoch: Duration,
        source_id: SourceId,
        block_body: impl Iterator<Item = impl AsRef<[u8]>>,
    ) -> BlockBodyVerify<TSrc, TBl> {
        // TODO: unfinished

        // TODO: update occupation?

        // Removes traces of the request from the state machine.
        let block_header_hash = if let Some((h, _)) = self
            .inner
            .pending_body_downloads
            .iter_mut()
            .find(|(_, (_, s))| *s == Some(source_id))
        {
            let hash = *h;
            let header = self.inner.pending_body_downloads.remove(&hash).unwrap().0;
            (header, hash)
        } else {
            panic!()
        };

        // Sanity check.
        debug_assert_eq!(block_header_hash.1, block_header_hash.0.hash());

        // If not full, there shouldn't be any block body download happening in the first place.
        debug_assert!(self.inner.full);

        match self
            .chain
            .verify_body(
                block_header_hash.0.scale_encoding()
                    .fold(Vec::new(), |mut a, b| { a.extend_from_slice(b.as_ref()); a }), now_from_unix_epoch) // TODO: stupid extra allocation
        {
            blocks_tree::BodyVerifyStep1::BadParent { .. }
            | blocks_tree::BodyVerifyStep1::InvalidHeader(..)
            | blocks_tree::BodyVerifyStep1::Duplicate(_) => unreachable!(),
            blocks_tree::BodyVerifyStep1::ParentRuntimeRequired(_runtime_req) => {
                todo!()
            }
        }
    }

    fn next_action(&mut self) {
        // Height of the finalized chain. Saved for later.
        let local_finalized_block_number = self.chain.finalized_block_header().number;

        // Try find any disjoint block that is ready to be verified.
        // TODO:

        // Try find any disjoint block that could be .
    }

    /// Passed a known entry in `disjoint_blocks`. Removes this entry and any known children of
    /// this block.
    ///
    /// # Panic
    ///
    /// Panics if `(number, hash)` isn't an entry in [`Inner::disjoint_chain]`.
    ///
    fn discard_disjoint_chain(&mut self, number: u64, hash: [u8; 32]) {
        // TODO: keep a list of banned blocks for later? this is required by chain specs anyway

        // The implementation consists in iterating over the increasing block number, and removing
        // all blocks whose parent was removed at the previous iteration.

        // List of blocks to discard at the next iteration.
        let mut blocks_to_discard = Vec::with_capacity(16);
        blocks_to_discard.push(hash);

        for number in number.. {
            // Find in `disjoint_blocks` any block whose parent is in `blocks_to_discard`.
            let blocks_to_discard_next = {
                let mut blocks_to_discard_next = Vec::with_capacity(16);
                for ((_, hash), block) in self
                    .inner
                    .disjoint_blocks
                    .range((number + 1, [0; 32])..(number + 2, [0; 32]))
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
                let discarded_block = self
                    .inner
                    .disjoint_blocks
                    .remove(&(number, to_discard))
                    .unwrap();

                // Any ongoing search needs to be cancelled.
                if let Some(_source_id) = discarded_block.ancestry_search {
                    todo!() // TODO:
                }
            }

            // The `for` loop would be infinite unless we put an explicit `break`.
            // Note that `blocks_to_discard` was replaced with `blocks_to_discard_next` above,
            // we're therefore testing `blocks_to_discard_next.is_empty()`.
            if blocks_to_discard.is_empty() {
                break;
            }
        }
    }
}

/// Access to a source in a [`AllForksSync`]. Obtained through [`AllForksSync::source_mut`].
pub struct SourceMutAccess<'a, TSrc, TBl> {
    parent: &'a mut AllForksSync<TSrc, TBl>,

    /// Guaranteed to be a valid entry in [`AllForksSync::sources`].
    source_id: SourceId,
}

impl<'a, TSrc, TBl> SourceMutAccess<'a, TSrc, TBl> {
    /// Returns the identifier of this source.
    pub fn id(&self) -> SourceId {
        self.source_id
    }

    /// Returns true if the source has earlier announced the block passed as parameter or one of
    /// its descendants.
    // TODO: document precisely what it means
    pub fn knows_block(&self, hash: &[u8; 32]) -> bool {
        if self
            .parent
            .inner
            .known_blocks1
            .contains(&(self.source_id, *hash))
        {
            return true;
        }

        let source = self.parent.inner.sources.get(&self.source_id).unwrap();

        // TODO: finish
        false
    }

    /// Removes the source from the [`AllForksSync`].
    ///
    /// Returns the user data that was originally passed to [`AllForksSync::add_source`].
    ///
    /// Removing the source implicitly cancels the request that is associated to it (if any).
    pub fn remove(self) -> TSrc {
        let source_id = self.source_id;
        let source = self.parent.inner.sources.remove(&source_id).unwrap();

        if let Some((_, (_, src))) = self
            .parent
            .inner
            .pending_body_downloads
            .iter_mut()
            .find(|(_, (_, s))| *s == Some(source_id))
        {
            // TODO: redirect download to other source
            *src = None;
        }

        match source.occupation {
            SourceOccupation::Idle => {},
            SourceOccupation::AncestrySearch(hash) => {
                todo!()
            }
        }

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
            Err(err) => return BlockAnnounceOutcome::InvalidHeader(err),
        };

        let announced_header_hash = announced_header.hash();

        // No matter what is done below, start by updating the view the local state machine
        // maintains for this source.
        if is_best {
            let source = self.parent.inner.sources.get_mut(&self.source_id).unwrap();
            source.best_block_number = announced_header.number;
            source.best_block_hash = announced_header.hash();
        }

        // It is assumed that all sources will eventually agree on the same finalized chain. If
        // the announced block number is lower or equal than the locally-finalized block number,
        // it is assumed that this source is simply late compared to the local node, and that the
        // block being announced is either part of the finalized chain or belongs to a fork that
        // will get discarded by this source in the future.
        if announced_header.number <= self.parent.chain.finalized_block_header().number {
            return BlockAnnounceOutcome::TooOld;
        }

        // Calculate the height of the parent of the announced block.
        let parent_header_number = match announced_header.number.checked_sub(1) {
            Some(n) => n,
            // The code right above verifies that `announced_header.number <= finalized_number`,
            // which is always true if `announced_header.number` is 0.
            None => unreachable!(),
        };

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

        // Determine whether the parent of the announced block is in the `NonFinalizedTree`.
        let parent_is_in_chain = {
            let local_finalized_block_hash = self.parent.chain.finalized_block_hash();
            *announced_header.parent_hash == local_finalized_block_hash
                || self
                    .parent
                    .chain
                    .non_finalized_block_by_hash(announced_header.parent_hash)
                    .is_some()
        };

        if let Some(pending) = self
            .parent
            .inner
            .pending_body_downloads
            .get_mut(&announced_header_hash)
        {
            debug_assert!(self.parent.inner.full);

            // The parent block header has already been announced in the past.
            // If `pending` is `Some`, it is currently being downloaded.
            if pending.1.is_some() {
                return BlockAnnounceOutcome::Queued;
            } else {
                // No source is currently downloading this block. Add the source that has just
                // announced it.
                pending.1 = Some(self.source_id);
            }
            todo!() // TODO:
        } else if parent_is_in_chain {
            // Parent is in the `NonFinalizedTree`, meaning it is possible to verify it.

            // Start by verifying the header alone.
            let header = match self
                .parent
                .chain
                .verify_header(announced_scale_encoded_header, now_from_unix_epoch)
            {
                Ok(blocks_tree::HeaderVerifySuccess::Duplicate) => unreachable!(),
                Ok(blocks_tree::HeaderVerifySuccess::Insert { insert, .. })
                    if self.parent.inner.full =>
                {
                    insert.into_header()
                }
                Ok(blocks_tree::HeaderVerifySuccess::Insert {
                    insert,
                    is_new_best,
                    ..
                }) => {
                    // insert.insert(());
                    todo!(); // TODO: ^
                    return BlockAnnounceOutcome::HeaderImported;
                }
                Err(blocks_tree::HeaderVerifyError::BadParent { .. })
                | Err(blocks_tree::HeaderVerifyError::InvalidHeader(_)) => unreachable!(),
                Err(blocks_tree::HeaderVerifyError::VerificationFailed(err)) => {
                    return BlockAnnounceOutcome::HeaderVerifyError(err);
                }
            };

            // Header if valid, and config is in full mode. Request the block body.
            // TODO: must make sure that source isn't busy
            self.parent
                .inner
                .pending_body_downloads
                .insert(announced_header_hash, (header, Some(self.source_id)));
            return BlockAnnounceOutcome::BlockBodyDownloadStart;
        } else if announced_header.number == self.parent.chain.finalized_block_header().number + 1 {
            // Checked above.
            debug_assert_ne!(
                *announced_header.parent_hash,
                self.parent.chain.finalized_block_hash()
            );

            // Announced block is not part of the finalized chain.
            return BlockAnnounceOutcome::NotFinalizedChain;
        } else {
            // Parent is not in the `NonFinalizedTree`. It is unknown whether this block belongs
            // to the same finalized chain as the one known locally, but we expect that it is the
            // case.
            if let btree_map::Entry::Vacant(entry) = self
                .parent
                .inner
                .disjoint_blocks
                .entry((announced_header.number, announced_header_hash))
            {
                entry.insert(DisjointBlock {
                    scale_encoded_header: announced_scale_encoded_header,
                    ancestry_search: None,
                });
            }

            // TODO: move out the thing below
            match &mut self
                .parent
                .inner
                .sources
                .get_mut(&self.source_id)
                .unwrap()
                .occupation
            {
                // If the source is idle, start an ancestry search in order to find a block whose
                // parent is known locally.
                occupation @ &mut SourceOccupation::Idle => {
                    *occupation = SourceOccupation::AncestrySearch(*announced_header.parent_hash);
                    BlockAnnounceOutcome::AncestrySearchStart {
                        first_block_hash: *announced_header.parent_hash,
                        // It is checked above that the announced block number is always strictly
                        // superior to the finalized block number.
                        num_blocks: NonZeroU64::new(
                            announced_header.number
                                - self.parent.chain.finalized_block_header().number,
                        )
                        .unwrap(),
                    }
                }
                // If the source is already busy with something else, delay the ancestry search
                // for later.
                _ => todo!(),
            }

            /*self.parent
            .inner
            .unverified
            .insert(parent_header_number, *announced_header.parent_hash);*/
            //todo!() // TODO:
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

/// Outcome of calling [`SourceMutAccess::block_announce`].
#[derive(Debug)]
pub enum BlockAnnounceOutcome {
    /// Announced header has been successfully added to the local tree of headers.
    ///
    /// Can only happen when in non-full mode.
    // TODO: should contain an object that lets user pass user data of block
    HeaderImported,

    /// Announced header has been successfully verified and added to the local tree of
    /// non-finalized blocks.
    ///
    /// Can only happen when in full mode.
    ///
    /// A block request should be start towards this source for the block header that has just
    /// been announced.
    ///
    /// The [`AllForksSync::block_body_response`] method must later be called.
    // TODO: should contain an object that lets user pass user data of block
    BlockBodyDownloadStart,

    /// Parent of the block being announced is completely unknown to the local state machine. An
    /// ancestry search must be started towards the source.
    ///
    /// > **Note**: This situation can happen for instance after a network split (also called
    /// >           *netsplit*) ends. During the split, some nodes have produced one chain, while
    /// >           some other nodes have produced a different chain.
    ///
    /// An ancestry search consists in asking the source for its block headers in the range
    /// `first_block_height ..= last_block_height`. The answer will make it possible for the local
    /// state machine to determine how the chain is connected.
    AncestrySearchStart {
        /// Hash of the first block to request.
        first_block_hash: [u8; 32],

        /// Number of blocks the request should return.
        num_blocks: NonZeroU64,
    },

    /// Announced block is too old to be part of the finalized chain.
    ///
    /// It is assumed that all sources will eventually agree on the same finalized chain. Blocks
    /// whose height is inferior to the height of the latest known finalized block should simply
    /// be ignored. Whether or not this old block is indeed part of the finalized block isn't
    /// verified, and it is assumed that the source is simply late.
    TooOld,
    /// Announced block has already been successfully verified and is part of the non-finalized
    /// chain.
    AlreadyVerified,
    /// Announced block is known to not be a descendant of the finalized block.
    NotFinalizedChain,
    /// Header has been queued for verification. Verifying the header is waiting for an ongoing
    /// download to finish.
    Queued,

    /// Failed to decode announced header.
    InvalidHeader(header::Error),
    /// Error while verifying validity of header.
    HeaderVerifyError(verify::header_only::Error),
}

/// Outcome of calling [`SourceMutAccess::ancestry_search_response`].
#[derive(Debug)]
pub enum AncestrySearchResponseOutcome {
    /// Source has given blocks that aren't part of the finalized chain.
    ///
    /// This doesn't necessarily mean that the source is malicious or uses a different chain. It
    /// is possible for this to legitimately happen, for example if the finalized chain has been
    /// updated while the ancestry search was in progress.
    NotFinalizedChain {
        /// List of block headers that were pending verification and that have now been discarded
        /// since it has been found out that they don't belong to the finalized chain.
        discarded_unverified_block_headers: Vec<Vec<u8>>,
    },
}

/// Identifier for a source in the [`AllForksSync`].
//
// Implementation note: the `u64` values are never re-used, making it possible to avoid clearing
// obsolete SourceIds in the `AllForksSync` state machine.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SourceId(u64);

/// State of the processing of blocks.
pub enum BlockBodyVerify<TSrc, TBl> {
    #[doc(hidden)]
    Foo(core::marker::PhantomData<(TSrc, TBl)>),
    // TODO: finish
    /*/// Processing of the block is over.
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
    FinalizedStorageNextKey(StorageNextKey<TSrc, TBl>),*/
}
