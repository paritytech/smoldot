// Substrate-lite
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
//! - A list of block header waiting to be verified and whose ancestry with the latest finalized
//!   block is currently unknown.
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
//!
//! # Bounded and unbounded containers
//!
//! It is important to limit the memory usage of this state machine no matter how the
//! potentially-malicious sources behave.
//!
//! The state in this state machine can be put into three categories:
//!
//! - Each source of blocks has a certain fixed-size state associated to it (containing for
//!   instance its best block number and height). Each source also has up to one in-flight
//!   request, which might incur more memory usage. Managing this additional request is out of
//!   scope of this module. The user of this module is expected to limit the number of
//!   simultaneous sources.
//!
//! - A set of verified blocks that descend from the latest finalized block. This set is
//!   unbounded. The consensus and finalization algorithms of the chain are supposed to limit
//!   the number of possible blocks in this set.
//!
//! - A set of blocks that can't be verified yet. Receiving a block announce inserts an element
//!   in this set. In order to handle situations where a malicious source announces lots of
//!   invalid blocks, this set must be bounded. Once it has reached a certain size, the blocks
//!   with the highest block number are discarded if their parent is also in this set or being
//!   downloaded from a source.
//!
//! Consequently, and assuming that the number of simultaneous sources is bounded, and that
//! the consensus and finalization algorithms of the chain are properly configured, malicious
//! sources can't indefinitely grow the state in this state machine.
//! Malicious sources, however, can potentially increase the number of block requests required to
//! download a long fork. This is, at most, an annoyance, and not a vulnerability.
//!

// TODO: finish ^

use crate::{
    chain::{blocks_tree, chain_information},
    header, verify,
};

use alloc::{
    borrow::ToOwned as _,
    vec::{self, Vec},
};
use core::{iter, num::NonZeroU32, ops, time::Duration};

mod disjoint;
mod pending_blocks;

pub mod sources;

pub use pending_blocks::{RequestId, RequestParams, SourceId};

/// Configuration for the [`AllForksSync`].
#[derive(Debug)]
pub struct Config<TBannedBlocksIter> {
    /// Information about the latest finalized block and its ancestors.
    pub chain_information: chain_information::ValidChainInformation,

    /// Pre-allocated capacity for the number of block sources.
    pub sources_capacity: usize,

    /// Pre-allocated capacity for the number of blocks between the finalized block and the head
    /// of the chain.
    ///
    /// Should be set to the maximum number of block between two consecutive justifications.
    pub blocks_capacity: usize,

    /// Maximum number of blocks of unknown ancestry to keep in memory. A good default is 1024.
    ///
    /// When a potential long fork is detected, its blocks are downloaded progressively in
    /// descending order until a common ancestor is found.
    /// Unfortunately, an attack could generate fake very long forks in order to make the node
    /// consume a lot of memory keeping track of the blocks in that fork.
    /// In order to avoid this, a limit is added to the number of blocks of unknown ancestry that
    /// are kept in memory.
    ///
    /// Note that the download of long forks will always work no matter this limit. In the worst
    /// case scenario, the same blocks will be downloaded multiple times. There is an implicit
    /// minimum size equal to the number of sources that have been added to the state machine.
    ///
    /// Increasing this value has no drawback, except for increasing the maximum possible memory
    /// consumption of this state machine.
    //
    // Implementation note: the size of `disjoint_headers` can temporarily grow above this limit
    // due to the internal processing of the state machine.
    pub max_disjoint_headers: usize,

    /// Maximum number of simultaneous pending requests made towards the same block.
    ///
    /// Should be set according to the failure rate of requests. For example if requests have a
    /// 10% chance of failing, then setting to value to `2` gives a 1% chance that downloading
    /// this block will overall fail and has to be attempted again.
    ///
    /// Also keep in mind that sources might maliciously take a long time to answer requests. A
    /// higher value makes it possible to reduce the risks of the syncing taking a long time
    /// because of malicious sources.
    ///
    /// The higher the value, the more bandwidth is potentially wasted.
    pub max_requests_per_block: NonZeroU32,

    /// If true, the block bodies and storage are also synchronized.
    pub full: bool,

    /// List of block hashes that are known to be bad and shouldn't be downloaded or verified.
    ///
    /// > **Note**: This list is typically filled with a list of blocks found in the chain
    /// >           specification. It is part of the "trusted setup" of the node, in other words
    /// >           the information that is passed by the user and blindly assumed to be true.
    pub banned_blocks: TBannedBlocksIter,
}

pub struct AllForksSync<TBl, TRq, TSrc> {
    /// Data structure containing the non-finalized blocks.
    ///
    /// If [`Config::full`], this only contains blocks whose header *and* body have been verified.
    chain: blocks_tree::NonFinalizedTree<Block<TBl>>,

    /// Extra fields. In a separate structure in order to be moved around.
    inner: Inner<TRq, TSrc>,
}

/// Extra fields. In a separate structure in order to be moved around.
struct Inner<TRq, TSrc> {
    blocks: pending_blocks::PendingBlocks<PendingBlock, TRq, TSrc>,

    /// Justifications waiting to be verified.
    ///
    /// These justifications came with a block header that has been successfully verified in the
    /// past.
    pending_justifications_verify: vec::IntoIter<([u8; 4], Vec<u8>)>,

    /// Same value as [`Config::banned_blocks`].
    banned_blocks: hashbrown::HashSet<[u8; 32], fnv::FnvBuildHasher>,
}

struct PendingBlock {
    header: Option<header::Header>,
    body: Option<Vec<Vec<u8>>>,
    justifications: Vec<([u8; 4], Vec<u8>)>,
}

struct Block<TBl> {
    header: header::Header,
    user_data: TBl,
}

impl<TBl, TRq, TSrc> AllForksSync<TBl, TRq, TSrc> {
    /// Initializes a new [`AllForksSync`].
    pub fn new(config: Config<impl Iterator<Item = [u8; 32]>>) -> Self {
        let finalized_block_height = config
            .chain_information
            .as_ref()
            .finalized_block_header
            .number;

        let chain = blocks_tree::NonFinalizedTree::new(blocks_tree::Config {
            chain_information: config.chain_information,
            blocks_capacity: config.blocks_capacity,
        });

        Self {
            chain,
            inner: Inner {
                blocks: pending_blocks::PendingBlocks::new(pending_blocks::Config {
                    blocks_capacity: config.blocks_capacity,
                    finalized_block_height,
                    max_requests_per_block: config.max_requests_per_block,
                    sources_capacity: config.sources_capacity,
                    verify_bodies: config.full,
                }),
                pending_justifications_verify: Vec::new().into_iter(),
                banned_blocks: config.banned_blocks.collect(),
            },
        }
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct corresponding to the current
    /// latest finalized block. Can later be used to reconstruct a chain.
    pub fn as_chain_information(&self) -> chain_information::ValidChainInformationRef {
        self.chain.as_chain_information()
    }

    /// Returns the header of the finalized block.
    pub fn finalized_block_header(&self) -> header::HeaderRef {
        self.chain
            .as_chain_information()
            .as_ref()
            .finalized_block_header
    }

    /// Returns the header of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_header(&self) -> header::HeaderRef {
        self.chain.best_block_header()
    }

    /// Returns the number of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_number(&self) -> u64 {
        self.chain.best_block_header().number
    }

    /// Returns the hash of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_hash(&self) -> [u8; 32] {
        self.chain.best_block_hash()
    }

    /// Returns the header of all known non-finalized blocks in the chain without any specific
    /// order.
    pub fn non_finalized_blocks_unordered(
        &'_ self,
    ) -> impl Iterator<Item = header::HeaderRef<'_>> + '_ {
        self.chain.iter_unordered()
    }

    /// Returns the header of all known non-finalized blocks in the chain.
    ///
    /// The returned items are guaranteed to be in an order in which the parents are found before
    /// their children.
    pub fn non_finalized_blocks_ancestry_order(
        &'_ self,
    ) -> impl Iterator<Item = header::HeaderRef<'_>> + '_ {
        self.chain.iter_ancestry_order()
    }

    /// Inform the [`AllForksSync`] of a new potential source of blocks.
    ///
    /// The `user_data` parameter is opaque and decided entirely by the user. It can later be
    /// retrieved using the `Index` trait implementation of this container.
    ///
    /// Returns the newly-created source entry, plus optionally a request that should be started
    /// towards this source.
    pub fn add_source(
        &mut self,
        user_data: TSrc,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    ) -> SourceId {
        let source_id = self
            .inner
            .blocks
            .add_source(user_data, best_block_number, best_block_hash);

        let needs_verification = best_block_number > self.chain.finalized_block_header().number
            && self
                .chain
                .non_finalized_block_by_hash(&best_block_hash)
                .is_none();
        let is_in_disjoints_list = self
            .inner
            .blocks
            .contains_unverified_block(best_block_number, &best_block_hash);
        debug_assert!(!(!needs_verification && is_in_disjoints_list));

        if needs_verification && !is_in_disjoints_list {
            self.inner.blocks.insert_unverified_block(
                best_block_number,
                best_block_hash,
                pending_blocks::UnverifiedBlockState::HeightHashKnown,
                PendingBlock {
                    header: None,
                    body: None,
                    justifications: Vec::new(),
                },
            );

            if self.inner.banned_blocks.contains(&best_block_hash) {
                self.inner
                    .blocks
                    .mark_unverified_block_as_bad(best_block_number, &best_block_hash);
            }
        }

        source_id
    }

    /// Removes the source from the [`AllForksSync`].
    ///
    /// Removing the source implicitly cancels the request that is associated to it (if any).
    ///
    /// Returns the user data that was originally passed to [`AllForksSync::add_source`], plus
    /// an `Option`.
    /// If this `Option` is `Some`, it contains a request that must be started towards the source
    /// indicated by the [`SourceId`].
    ///
    /// > **Note**: For example, if the source that has just been removed was performing an
    /// >           ancestry search, the `Option` might contain that same ancestry search.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn remove_source(
        &mut self,
        source_id: SourceId,
    ) -> (TSrc, impl Iterator<Item = (RequestId, RequestParams, TRq)>) {
        self.inner.blocks.remove_source(source_id)
    }

    /// Returns the list of sources in this state machine.
    pub fn sources(&'_ self) -> impl ExactSizeIterator<Item = SourceId> + '_ {
        self.inner.blocks.sources()
    }

    /// Returns true if the source has earlier announced the block passed as parameter or one of
    /// its descendants.
    ///
    /// Also returns true if the requested block is inferior or equal to the known finalized block
    /// and the source has announced a block higher or equal to the known finalized block.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    /// Panics if `height` is inferior or equal to the finalized block height. Finalized blocks
    /// are intentionally not tracked by this data structure, and panicking when asking for a
    /// potentially-finalized block prevents potentially confusing or erroneous situations.
    ///
    pub fn source_knows_non_finalized_block(
        &self,
        source_id: SourceId,
        height: u64,
        hash: &[u8; 32],
    ) -> bool {
        self.inner
            .blocks
            .source_knows_non_finalized_block(source_id, height, hash)
    }

    /// Returns the list of sources for which [`AllForksSync::source_knows_non_finalized_block`]
    /// would return `true`.
    ///
    /// # Panic
    ///
    /// Panics if `height` is inferior or equal to the finalized block height. Finalized blocks
    /// are intentionally not tracked by this data structure, and panicking when asking for a
    /// potentially-finalized block prevents potentially confusing or erroneous situations.
    ///
    pub fn knows_non_finalized_block<'a>(
        &'a self,
        height: u64,
        hash: &[u8; 32],
    ) -> impl Iterator<Item = SourceId> + 'a {
        self.inner.blocks.knows_non_finalized_block(height, hash)
    }

    /// Returns the current best block of the given source.
    ///
    /// This corresponds either the latest call to [`AllForksSync::block_announce`] where
    /// `is_best` was `true`, or to the parameter passed to [`AllForksSync::add_source`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn source_best_block(&self, source_id: SourceId) -> (u64, &[u8; 32]) {
        self.inner.blocks.source_best_block(source_id)
    }

    /// Returns the number of ongoing requests that concern this source.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn source_num_ongoing_requests(&self, source_id: SourceId) -> usize {
        self.inner.blocks.source_num_ongoing_requests(source_id)
    }

    /// Returns the details of a request to start towards a source.
    ///
    /// This method doesn't modify the state machine in any way. [`AllForksSync::add_request`]
    /// must be called in order for the request to actually be marked as started.
    pub fn desired_requests(
        &'_ self,
    ) -> impl Iterator<Item = (SourceId, &'_ TSrc, RequestParams)> + '_ {
        // TODO: need to periodically query for justifications of non-finalized blocks that change GrandPa authorities

        self.inner
            .blocks
            .desired_requests()
            .filter(move |rq| {
                !self
                    .chain
                    .contains_non_finalized_block(&rq.request_params.first_block_hash)
            })
            .map(move |rq| {
                (
                    rq.source_id,
                    &self.inner.blocks[rq.source_id],
                    rq.request_params,
                )
            })
    }

    /// Inserts a new request in the data structure.
    ///
    /// > **Note**: The request doesn't necessarily have to match a request returned by
    /// >           [`AllForksSync::desired_requests`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn add_request(
        &mut self,
        source_id: SourceId,
        detail: RequestParams,
        user_data: TRq,
    ) -> RequestId {
        self.inner.blocks.add_request(source_id, detail, user_data)
    }

    /// Returns a list of requests that are considered obsolete and can be removed using
    /// [`AllForksSync::finish_ancestry_search`] or similar.
    ///
    /// A request becomes obsolete if the state of the request blocks changes in such a way that
    /// they don't need to be requested anymore. The response to the request will be useless.
    ///
    /// > **Note**: It is in no way mandatory to actually call this function and cancel the
    /// >           requests that are returned.
    pub fn obsolete_requests(&'_ self) -> impl Iterator<Item = (RequestId, &'_ TRq)> + '_ {
        self.inner.blocks.obsolete_requests()
    }

    /// Call in response to a blocks request being successful.
    ///
    /// This method takes ownership of the [`AllForksSync`] and puts it in a mode where the blocks
    /// of the response can be added one by one.
    ///
    /// The added blocks are expected to be sorted in decreasing order. The first block should be
    /// the block with the hash that was referred by [`RequestParams::first_block_hash`]. Each
    /// subsequent element is then expected to be the parent of the previous one.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    pub fn finish_ancestry_search(
        mut self,
        request_id: RequestId,
    ) -> (TRq, FinishAncestrySearch<TBl, TRq, TSrc>) {
        // Sets the `occupation` of `source_id` back to `AllSync`.
        let (
            pending_blocks::RequestParams {
                first_block_hash: requested_block_hash,
                first_block_height: requested_block_height,
                ..
            },
            source_id,
            request_user_data,
        ) = self.inner.blocks.finish_request(request_id);

        (
            request_user_data,
            FinishAncestrySearch {
                inner: self,
                source_id,
                any_progress: false,
                index_in_response: 0,
                requested_block_hash,
                requested_block_height,
                expected_next_hash: requested_block_hash,
                expected_next_height: requested_block_height,
            },
        )
    }

    /// Call in response to a blocks request having failed.
    ///
    /// This removes the request from the state machine and returns its user data.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    // TODO: taking a `&mut self` instead of a `self` would be more correct, however this doesn't give any benefit and complicates the implementation at the moment, so it might not be worth doing
    pub fn ancestry_search_failed(
        self,
        request_id: RequestId,
    ) -> (TRq, AllForksSync<TBl, TRq, TSrc>) {
        let (user_data, inner) = self.finish_ancestry_search(request_id);
        (user_data, inner.finish())
    }

    /// Update the source with a newly-announced block.
    ///
    /// > **Note**: This information is normally reported by the source itself. In the case of a
    /// >           a networking peer, call this when the source sent a block announce.
    ///
    /// # Panic
    ///
    /// Panics if `source_id` is invalid.
    ///
    pub fn block_announce(
        &mut self,
        source_id: SourceId,
        announced_scale_encoded_header: Vec<u8>,
        is_best: bool,
    ) -> BlockAnnounceOutcome {
        let announced_header = match header::decode(&announced_scale_encoded_header) {
            Ok(h) => h,
            Err(error) => return BlockAnnounceOutcome::InvalidHeader(error),
        };

        let announced_header_hash = announced_header.hash();

        match self.block_from_source(
            source_id,
            &announced_header_hash,
            announced_header,
            None,
            &mut iter::empty(),
            is_best,
        ) {
            HeaderFromSourceOutcome::HeaderVerify => BlockAnnounceOutcome::HeaderVerify,
            HeaderFromSourceOutcome::TooOld {
                announce_block_height,
                finalized_block_height,
            } => BlockAnnounceOutcome::TooOld {
                announce_block_height,
                finalized_block_height,
            },
            HeaderFromSourceOutcome::AlreadyInChain => BlockAnnounceOutcome::AlreadyInChain,
            HeaderFromSourceOutcome::NotFinalizedChain => BlockAnnounceOutcome::NotFinalizedChain,
            HeaderFromSourceOutcome::Disjoint => BlockAnnounceOutcome::Disjoint,
        }
    }

    /// Update the state machine with a Grandpa commit message received from the network.
    ///
    /// On success, the finalized block has been updated.
    // TODO: return which blocks are removed as finalized
    pub fn grandpa_commit_message(
        &mut self,
        scale_encoded_message: &[u8],
    ) -> Result<(), blocks_tree::CommitVerifyError> {
        // TODO: must also handle the `NotEnoughBlocks` error separately
        match self
            .chain
            .verify_grandpa_commit_message(scale_encoded_message)
        {
            Ok(apply) => {
                apply.apply();
                Ok(())
            }
            // In case where the commit message concerns a block older or equal to the finalized
            // block, the operation is silently considered successful.
            Err(blocks_tree::CommitVerifyError::FinalityVerify(
                blocks_tree::FinalityVerifyError::EqualToFinalized
                | blocks_tree::FinalityVerifyError::BelowFinalized,
            )) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Process the next block in the queue of verification.
    ///
    /// This method takes ownership of the [`AllForksSync`] and starts a verification
    /// process. The [`AllForksSync`] is yielded back at the end of this process.
    pub fn process_one(mut self) -> ProcessOne<TBl, TRq, TSrc> {
        if let Some(justification_to_verify) = self.inner.pending_justifications_verify.next() {
            return ProcessOne::JustificationVerify(JustificationVerify {
                parent: self,
                justification_to_verify,
            });
        }

        let block = self.inner.blocks.unverified_leaves().find(|block| {
            block.parent_block_hash == self.chain.finalized_block_hash()
                || self
                    .chain
                    .contains_non_finalized_block(&block.parent_block_hash)
        });

        if let Some(block) = block {
            ProcessOne::HeaderVerify(HeaderVerify {
                parent: self,
                block_to_verify: block,
            })
        } else {
            ProcessOne::AllSync { sync: self }
        }
    }

    /// Called when a source reports a header and an optional body, either through a block
    /// announce, an ancestry search result, or a block request, and so on.
    ///
    /// `known_to_be_source_best` being `true` means that we are sure that this is the best block
    /// of the source. `false` means "it is not", but also "maybe", "unknown", and similar.
    ///
    /// # Panic
    ///
    /// Panics if `source_id` is invalid.
    ///
    fn block_from_source(
        &mut self,
        source_id: SourceId,
        header_hash: &[u8; 32],
        header: header::HeaderRef,
        body: Option<Vec<Vec<u8>>>,
        justifications: &mut dyn Iterator<Item = ([u8; 4], Vec<u8>)>,
        known_to_be_source_best: bool,
    ) -> HeaderFromSourceOutcome {
        debug_assert_eq!(header.hash(), *header_hash);

        // Code below does `header.number - 1`. Make sure that `header.number` isn't 0.
        if header.number == 0 {
            return HeaderFromSourceOutcome::TooOld {
                announce_block_height: 0,
                finalized_block_height: self.chain.finalized_block_header().number,
            };
        }

        // No matter what is done below, start by updating the view the state machine maintains
        // for this source.
        if known_to_be_source_best {
            self.inner.blocks.add_known_block_to_source_and_set_best(
                source_id,
                header.number,
                *header_hash,
            );
        } else {
            self.inner
                .blocks
                .add_known_block_to_source(source_id, header.number, *header_hash);
        }

        // Source also knows the parent of the announced block.
        self.inner.blocks.add_known_block_to_source(
            source_id,
            header.number - 1,
            *header.parent_hash,
        );

        // It is assumed that all sources will eventually agree on the same finalized chain. If
        // the block number is lower or equal than the locally-finalized block number, it is
        // assumed that this source is simply late compared to the local node, and that the block
        // that has been received is either part of the finalized chain or belongs to a fork that
        // will get discarded by this source in the future.
        if header.number <= self.chain.finalized_block_header().number {
            return HeaderFromSourceOutcome::TooOld {
                announce_block_height: header.number,
                finalized_block_height: self.chain.finalized_block_header().number,
            };
        }

        // If the block is already part of the local tree of blocks, nothing more to do.
        if self.chain.contains_non_finalized_block(header_hash) {
            return HeaderFromSourceOutcome::AlreadyInChain;
        }

        // At this point, we have excluded blocks that are already part of the chain or too old.
        // We insert the block in the list of unverified blocks so as to treat all blocks the
        // same.
        if !self
            .inner
            .blocks
            .contains_unverified_block(header.number, header_hash)
        {
            self.inner.blocks.insert_unverified_block(
                header.number,
                *header_hash,
                if body.is_some() {
                    pending_blocks::UnverifiedBlockState::HeaderBodyKnown {
                        parent_hash: *header.parent_hash,
                    }
                } else {
                    pending_blocks::UnverifiedBlockState::HeaderKnown {
                        parent_hash: *header.parent_hash,
                    }
                },
                PendingBlock {
                    body,
                    header: Some(header.clone().into()),
                    justifications: justifications
                        .map(|(e, j)| (e, j.clone()))
                        .collect::<Vec<_>>(),
                },
            );

            if self.inner.banned_blocks.contains(header_hash) {
                self.inner
                    .blocks
                    .mark_unverified_block_as_bad(header.number, header_hash);
            }

            // If there are too many blocks stored in the blocks list, remove unnecessary ones.
            // Not doing this could lead to an explosion of the size of the collections.
            // TODO: removing blocks should only be done explicitly through an API endpoint, because we want to store user datas in unverified blocks too; see https://github.com/paritytech/smoldot/issues/1572
            while self.inner.blocks.num_unverified_blocks() >= 100 {
                // TODO: arbitrary constant
                let (height, hash) = match self.inner.blocks.unnecessary_unverified_blocks().next()
                {
                    Some((n, h)) => (n, *h),
                    None => break,
                };

                self.inner.blocks.remove_sources_known_block(height, &hash);
                self.inner.blocks.remove_unverified_block(height, &hash);
            }
        } else {
            if body.is_some() {
                self.inner.blocks.set_unverified_block_header_body_known(
                    header.number,
                    header_hash,
                    *header.parent_hash,
                );
            } else {
                self.inner.blocks.set_unverified_block_header_known(
                    header.number,
                    header_hash,
                    *header.parent_hash,
                );
            }

            let block_user_data = self
                .inner
                .blocks
                .unverified_block_user_data_mut(header.number, header_hash);
            if block_user_data.header.is_none() {
                block_user_data.header = Some(header.clone().into()); // TODO: copying bytes :-/
            }
            // TODO: what if body was already known, but differs from what is stored?
            if block_user_data.body.is_none() {
                if let Some(body) = body {
                    block_user_data.body = Some(body);
                }
            }
        }

        // TODO: what if the pending block already contains a justification and it is not the
        //       same as here? since justifications aren't immediately verified, it is possible
        //       for a malicious peer to send us bad justifications

        // Block is not part of the finalized chain.
        if header.number == self.chain.finalized_block_header().number + 1
            && *header.parent_hash != self.chain.finalized_block_hash()
        {
            // TODO: remove_verify_failed
            return HeaderFromSourceOutcome::NotFinalizedChain;
        }

        if *header.parent_hash == self.chain.finalized_block_hash()
            || self
                .chain
                .non_finalized_block_by_hash(header.parent_hash)
                .is_some()
        {
            // TODO: ambiguous naming
            return HeaderFromSourceOutcome::HeaderVerify;
        }

        // TODO: if pending_blocks.num_blocks() > some_max { remove uninteresting block }

        HeaderFromSourceOutcome::Disjoint
    }

    /*/// Call in response to a [`BlockAnnounceOutcome::BlockBodyDownloadStart`].
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    pub fn block_body_response(
        mut self,
        now_from_unix_epoch: Duration,
        request_id: RequestId,
        block_body: impl Iterator<Item = impl AsRef<[u8]>>,
    ) -> (BlockBodyVerify<TBl, TRq, TSrc>, Option<Request>) {
        // TODO: unfinished

        todo!()

        /*// TODO: update occupation

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
        }*/
    }*/
}

impl<TBl, TRq, TSrc> ops::Index<SourceId> for AllForksSync<TBl, TRq, TSrc> {
    type Output = TSrc;

    #[track_caller]
    fn index(&self, id: SourceId) -> &TSrc {
        &self.inner.blocks[id]
    }
}

impl<TBl, TRq, TSrc> ops::IndexMut<SourceId> for AllForksSync<TBl, TRq, TSrc> {
    #[track_caller]
    fn index_mut(&mut self, id: SourceId) -> &mut TSrc {
        &mut self.inner.blocks[id]
    }
}

/// See [`AllForksSync::finish_ancestry_search`].
pub struct FinishAncestrySearch<TBl, TRq, TSrc> {
    inner: AllForksSync<TBl, TRq, TSrc>,

    /// Source that has sent the request that is being answered.
    source_id: SourceId,

    /// Set to true if any block at all have been added.
    any_progress: bool,

    /// Number of blocks added before through that data structure.
    index_in_response: usize,

    /// Hash of the block that was initially request.
    requested_block_hash: [u8; 32],
    /// Height of the block that was initially request.
    requested_block_height: u64,

    /// The next block to add should have a hash equal to this one.
    expected_next_hash: [u8; 32],
    /// The next block to add should have a height equal to this one.
    expected_next_height: u64,
}

impl<TBl, TRq, TSrc> FinishAncestrySearch<TBl, TRq, TSrc> {
    /// Adds a block coming from the response that the source has provided.
    ///
    /// On success, the block is inserted in the state machine.
    ///
    /// If an error is returned, the [`FinishAncestrySearch`] is turned back again into a
    /// [`AllForksSync`], but all the blocks that have already been added are retained.
    pub fn add_block(
        mut self,
        scale_encoded_header: &[u8],
        scale_encoded_justifications: impl Iterator<Item = ([u8; 4], impl AsRef<[u8]>)>,
    ) -> Result<Self, (AncestrySearchResponseError, AllForksSync<TBl, TRq, TSrc>)> {
        // Compare expected with actual hash.
        // This ensure that each header being processed is the parent of the previous one.
        if self.expected_next_hash != header::hash_from_scale_encoded_header(scale_encoded_header) {
            return Err((AncestrySearchResponseError::UnexpectedBlock, self.finish()));
        }

        // Invalid headers are erroneous.
        let decoded_header = match header::decode(scale_encoded_header) {
            Ok(h) => h,
            Err(err) => {
                return Err((
                    AncestrySearchResponseError::InvalidHeader(err),
                    self.finish(),
                ))
            }
        };

        // Also compare the block numbers.
        // The utility of checking the height (even though we've already checked the hash) is
        // questionable, but considering that blocks are identified with their combination of
        // hash and number, checking both the hash and number might prevent malicious sources
        // from introducing state inconsistenties, even though it's unclear how that could happen.
        if self.expected_next_height != decoded_header.number {
            return Err((AncestrySearchResponseError::UnexpectedBlock, self.finish()));
        }

        // At this point, the source has given us correct blocks, and we consider the response
        // as a whole to be useful.
        self.any_progress = true;

        let block_from_source_result = {
            // Code below does `header.number - 1`. Make sure that `header.number` isn't 0.
            if decoded_header.number == 0 {
                return HeaderFromSourceOutcome::TooOld {
                    announce_block_height: 0,
                    finalized_block_height: self.inner.chain.finalized_block_header().number,
                };
            }

            // No matter what is done below, start by updating the view the state machine maintains
            // for this source.
            if false {
                self.inner.inner.blocks.add_known_block_to_source_and_set_best(
                    self.source_id,
                    decoded_header.number,
                    self.expected_next_hash,
                );
            } else {
                self.inner.inner
                    .blocks
                    .add_known_block_to_source(self.source_id, decoded_header.number, self.expected_next_hash);
            }

            // Source also knows the parent of the announced block.
            self.inner.inner.blocks.add_known_block_to_source(
                self.source_id,
                decoded_header.number - 1,
                *decoded_header.parent_hash,
            );

            // It is assumed that all sources will eventually agree on the same finalized chain. If
            // the block number is lower or equal than the locally-finalized block number, it is
            // assumed that this source is simply late compared to the local node, and that the block
            // that has been received is either part of the finalized chain or belongs to a fork that
            // will get discarded by this source in the future.
            if decoded_header.number <= self.inner.chain.finalized_block_header().number {
                return HeaderFromSourceOutcome::TooOld {
                    announce_block_height: decoded_header.number,
                    finalized_block_height: self.inner.chain.finalized_block_header().number,
                };
            }

            // If the block is already part of the local tree of blocks, nothing more to do.
            if self.inner.chain.contains_non_finalized_block(&self.expected_next_hash) {
                return HeaderFromSourceOutcome::AlreadyInChain;
            }

            // At this point, we have excluded blocks that are already part of the chain or too old.
            // We insert the block in the list of unverified blocks so as to treat all blocks the
            // same.
            if !self.inner
                .inner
                .blocks
                .contains_unverified_block(decoded_header.number, &self.expected_next_hash)
            {
                self.inner.inner.blocks.insert_unverified_block(
                    decoded_header.number,
                    self.expected_next_hash,
                    {
                        pending_blocks::UnverifiedBlockState::HeaderKnown {
                            parent_hash: *decoded_header.parent_hash,
                        }
                    },
                    PendingBlock {
                        body: None,
                        header: Some(decoded_header.clone().into()),
                        justifications: scale_encoded_justifications
                            .map(|(e, j)| (e, j.as_ref().to_owned()))
                            .collect::<Vec<_>>(),
                    },
                );

                if self.inner.inner.banned_blocks.contains(&self.expected_next_hash) {
                    self.inner.inner
                        .blocks
                        .mark_unverified_block_as_bad(decoded_header.number, &self.expected_next_hash);
                }

                // If there are too many blocks stored in the blocks list, remove unnecessary ones.
                // Not doing this could lead to an explosion of the size of the collections.
                // TODO: removing blocks should only be done explicitly through an API endpoint, because we want to store user datas in unverified blocks too; see https://github.com/paritytech/smoldot/issues/1572
                while self.inner.inner.blocks.num_unverified_blocks() >= 100 {
                    // TODO: arbitrary constant
                    let (height, hash) =
                        match self.inner.inner.blocks.unnecessary_unverified_blocks().next() {
                            Some((n, h)) => (n, *h),
                            None => break,
                        };

                    self.inner.inner.blocks.remove_sources_known_block(height, &hash);
                    self.inner.inner.blocks.remove_unverified_block(height, &hash);
                }
            } else {
                {
                    self.inner.inner.blocks.set_unverified_block_header_known(
                        decoded_header.number,
                        &self.expected_next_hash,
                        *decoded_header.parent_hash,
                    );
                }

                let block_user_data = self.inner
                    .inner
                    .blocks
                    .unverified_block_user_data_mut(decoded_header.number, &self.expected_next_hash);
                if block_user_data.header.is_none() {
                    block_user_data.header = Some(decoded_header.clone().into()); // TODO: copying bytes :-/
                }
                // TODO: what if body was already known, but differs from what is stored?
                if block_user_data.body.is_none() {
                }
            }

            // TODO: what if the pending block already contains a justification and it is not the
            //       same as here? since justifications aren't immediately verified, it is possible
            //       for a malicious peer to send us bad justifications

            // Block is not part of the finalized chain.
            if decoded_header.number == self.inner.chain.finalized_block_header().number + 1
                && *decoded_header.parent_hash != self.inner.chain.finalized_block_hash()
            {
                // TODO: remove_verify_failed
                return HeaderFromSourceOutcome::NotFinalizedChain;
            }

            if *decoded_header.parent_hash == self.inner.chain.finalized_block_hash()
                || self.inner
                    .chain
                    .non_finalized_block_by_hash(decoded_header.parent_hash)
                    .is_some()
            {
                // TODO: ambiguous naming
                return HeaderFromSourceOutcome::HeaderVerify;
            }

            // TODO: if pending_blocks.num_blocks() > some_max { remove uninteresting block }

            HeaderFromSourceOutcome::Disjoint
        };

        match block_from_source_result {
            HeaderFromSourceOutcome::HeaderVerify => {
                // Header is ready to be verified.
                // We continue accepting blocks, knowing that the next block should return
                // `Err(AlreadyInChain)`.
            }
            HeaderFromSourceOutcome::TooOld { .. } => {
                // Block is below the finalized block number.
                // Ancestry searches never request any block earlier than the finalized block
                // number. `TooOld` can happen if the source is misbehaving, but also if the
                // finalized block has been updated between the moment the request was emitted
                // and the moment the response is received.
                debug_assert_eq!(self.index_in_response, 0);
                return Err((AncestrySearchResponseError::TooOld, self.finish()));
            }
            HeaderFromSourceOutcome::NotFinalizedChain => {
                // Block isn't part of the finalized chain.
                // This doesn't necessarily mean that the source and the local node disagree
                // on the finalized chain. It is possible that the finalized block has been
                // updated between the moment the request was emitted and the moment the
                // response is received.
                let error = AncestrySearchResponseError::NotFinalizedChain {
                    discarded_unverified_block_headers: Vec::new(), // TODO: not properly implemented /!\
                };
                return Err((error, self.finish()));
            }
            HeaderFromSourceOutcome::AlreadyInChain => {
                // Block is already in chain. Can happen if a different response or
                // announcement has arrived and been processed between the moment the request
                // was emitted and the moment the response is received.
                debug_assert_eq!(self.index_in_response, 0);
                return Err((AncestrySearchResponseError::AlreadyInChain, self.finish()));
            }
            HeaderFromSourceOutcome::Disjoint => {
                // Block of unknown ancestry. Continue accepting blocks.
            }
        }

        // Update the state machine for the next iteration.
        // Note: this can't be reached if `expected_next_height` is 0, because that should have
        // resulted either in `NotFinalizedChain` or `AlreadyInChain`, both of which return early.
        self.expected_next_hash = *decoded_header.parent_hash;
        self.expected_next_height -= 1;
        self.index_in_response += 1;
        Ok(self)
    }

    /// Notifies of the end of the response, and returns back the [`AllForksSync`].
    ///
    /// It is legal to insert fewer blocks than the number of blocks that were requested through
    /// [`RequestParams::num_blocks`].
    /// However, if no block has been added at all (i.e. the response is empty), then the source
    /// of the request is marked as bad.
    ///
    /// > **Note**: Network protocols have a limit to the size of their response, meaning that all
    /// >           the requested blocks might not fit in a single response. For this reason, it
    /// >           is legal for a response to be shorter than expected.
    pub fn finish(mut self) -> AllForksSync<TBl, TRq, TSrc> {
        // If this is reached, then none of the blocks the source has sent back were useful.
        if !self.any_progress {
            // Assume that the source doesn't know this block, as it is apparently unable to
            // serve it anyway. This avoids sending the same request to the same source over and
            // over again.
            self.inner.inner.blocks.remove_known_block_of_source(
                self.source_id,
                self.requested_block_height,
                &self.requested_block_hash,
            );
        }

        self.inner
    }
}

/// Outcome of calling [`AllForksSync::block_from_source`].
///
/// Not public.
enum HeaderFromSourceOutcome {
    /// Header is ready to be verified.
    HeaderVerify,

    /// Announced block is too old to be part of the finalized chain.
    ///
    /// It is assumed that all sources will eventually agree on the same finalized chain. Blocks
    /// whose height is inferior to the height of the latest known finalized block should simply
    /// be ignored. Whether or not this old block is indeed part of the finalized block isn't
    /// verified, and it is assumed that the source is simply late.
    TooOld {
        /// Height of the announced block.
        announce_block_height: u64,
        /// Height of the currently finalized block.
        finalized_block_height: u64,
    },
    /// Announced block has already been successfully verified and is part of the non-finalized
    /// chain.
    AlreadyInChain,
    /// Announced block is known to not be a descendant of the finalized block.
    NotFinalizedChain,
    /// Header cannot be verified now, and has been stored for later.
    Disjoint,
}

/// Outcome of calling [`AllForksSync::block_announce`].
pub enum BlockAnnounceOutcome {
    /// Header is ready to be verified.
    HeaderVerify,

    /// Announced block is too old to be part of the finalized chain.
    ///
    /// It is assumed that all sources will eventually agree on the same finalized chain. Blocks
    /// whose height is inferior to the height of the latest known finalized block should simply
    /// be ignored. Whether or not this old block is indeed part of the finalized block isn't
    /// verified, and it is assumed that the source is simply late.
    TooOld {
        /// Height of the announced block.
        announce_block_height: u64,
        /// Height of the currently finalized block.
        finalized_block_height: u64,
    },
    /// Announced block has already been successfully verified and is part of the non-finalized
    /// chain.
    AlreadyInChain,
    /// Announced block is known to not be a descendant of the finalized block.
    NotFinalizedChain,
    /// Header cannot be verified now, and has been stored for later.
    Disjoint,
    /// Failed to decode announce header.
    InvalidHeader(header::Error),
}

/// Error when adding a block using [`FinishAncestrySearch::add_block`].
pub enum AncestrySearchResponseError {
    /// Failed to decode block header.
    InvalidHeader(header::Error),

    /// Provided block isn't a block that we expect to be added.
    ///
    /// If this is the first block, then it doesn't correspond to the block that has been
    /// requested. If this is not the first block, then it doesn't correspond to the parent of
    /// the previous block that has been added.
    UnexpectedBlock,

    /// The block height is equal to the locally-known finalized block height, but its hash isn't
    /// the same.
    ///
    /// This doesn't necessarily mean that the source is malicious or uses a different chain. It
    /// is possible for this to legitimately happen, for example if the finalized chain has been
    /// updated while the ancestry search was in progress.
    NotFinalizedChain {
        /// List of block headers that were pending verification and that have now been discarded
        /// since it has been found out that they don't belong to the finalized chain.
        discarded_unverified_block_headers: Vec<Vec<u8>>,
    },

    /// Height of the block is below the height of the finalized block.
    ///
    /// Note that in most situation the previous block should have returned a
    /// [`AncestrySearchResponseError::NotFinalizedChain`] as we notice that its height is equal
    /// to the finalized block's height but hash is different.
    /// However, a [`AncestrySearchResponseError::TooOld`] can still happen in some niche
    /// situations, such as an update to the finalized block height above the first block of the
    /// request.
    TooOld,

    /// The block is already in the list of verified blocks.
    ///
    /// This can happen for example if a block announce or different ancestry search response has
    /// been processed in between the request and response.
    AlreadyInChain,
}

/// Header verification to be performed.
///
/// Internally holds the [`AllForksSync`].
pub struct HeaderVerify<TBl, TRq, TSrc> {
    parent: AllForksSync<TBl, TRq, TSrc>,
    /// Block that can be verified.
    block_to_verify: pending_blocks::TreeRoot,
}

impl<TBl, TRq, TSrc> HeaderVerify<TBl, TRq, TSrc> {
    /// Returns the height of the block to be verified.
    pub fn height(&self) -> u64 {
        self.block_to_verify.block_number
    }

    /// Returns the hash of the block to be verified.
    pub fn hash(&self) -> &[u8; 32] {
        &self.block_to_verify.block_hash
    }

    /// Perform the verification.
    pub fn perform(
        mut self,
        now_from_unix_epoch: Duration,
        user_data: TBl,
    ) -> HeaderVerifyOutcome<TBl, TRq, TSrc> {
        let to_verify_scale_encoded_header = self
            .parent
            .inner
            .blocks
            .unverified_block_user_data(
                self.block_to_verify.block_number,
                &self.block_to_verify.block_hash,
            )
            .header
            .as_ref()
            .unwrap()
            .scale_encoding_vec();

        let result = match self
            .parent
            .chain
            .verify_header(to_verify_scale_encoded_header, now_from_unix_epoch)
        {
            Ok(blocks_tree::HeaderVerifySuccess::Insert {
                insert,
                is_new_best,
                ..
            }) => {
                // TODO: cloning the header :-/
                let block = Block {
                    header: insert.header().into(),
                    user_data,
                };
                insert.insert(block);
                Ok(is_new_best)
            }
            Err(blocks_tree::HeaderVerifyError::VerificationFailed(error)) => {
                Err((HeaderVerifyError::VerificationFailed(error), user_data))
            }
            Err(blocks_tree::HeaderVerifyError::ConsensusMismatch) => {
                Err((HeaderVerifyError::ConsensusMismatch, user_data))
            }
            Ok(blocks_tree::HeaderVerifySuccess::Duplicate)
            | Err(
                blocks_tree::HeaderVerifyError::BadParent { .. }
                | blocks_tree::HeaderVerifyError::InvalidHeader(_),
            ) => unreachable!(),
        };

        // Remove the verified block from `pending_blocks`.
        let justifications = if result.is_ok() {
            self.parent.inner.blocks.remove_sources_known_block(
                self.block_to_verify.block_number,
                &self.block_to_verify.block_hash,
            );
            let outcome = self.parent.inner.blocks.remove_unverified_block(
                self.block_to_verify.block_number,
                &self.block_to_verify.block_hash,
            );
            outcome.justifications
        } else {
            self.parent.inner.blocks.mark_unverified_block_as_bad(
                self.block_to_verify.block_number,
                &self.block_to_verify.block_hash,
            );
            Vec::new()
        };

        // Store the justification in `pending_justification_verify`.
        // A `HeaderVerify` can only exist if `pending_justification_verify` is `None`, meaning
        // that there's no risk of accidental overwrite.
        debug_assert!(self
            .parent
            .inner
            .pending_justifications_verify
            .as_slice()
            .is_empty());
        self.parent.inner.pending_justifications_verify = justifications.into_iter();

        match result {
            Ok(is_new_best) => HeaderVerifyOutcome::Success {
                is_new_best,
                sync: self.parent,
            },
            Err((error, user_data)) => HeaderVerifyOutcome::Error {
                sync: self.parent,
                error,
                user_data,
            },
        }
    }

    /// Do not actually proceed with the verification.
    pub fn cancel(self) -> AllForksSync<TBl, TRq, TSrc> {
        self.parent
    }
}

/// Justification verification to be performed.
///
/// Internally holds the [`AllForksSync`].
pub struct JustificationVerify<TBl, TRq, TSrc> {
    parent: AllForksSync<TBl, TRq, TSrc>,
    /// Justification that can be verified and its consensus engine id.
    justification_to_verify: ([u8; 4], Vec<u8>),
}

impl<TBl, TRq, TSrc> JustificationVerify<TBl, TRq, TSrc> {
    /// Perform the verification.
    pub fn perform(
        mut self,
    ) -> (
        AllForksSync<TBl, TRq, TSrc>,
        JustificationVerifyOutcome<TBl>,
    ) {
        let outcome = match self.parent.chain.verify_justification(
            self.justification_to_verify.0,
            &self.justification_to_verify.1,
        ) {
            Ok(success) => {
                let finalized_blocks_iter = success.apply();
                let updates_best_block = finalized_blocks_iter.updates_best_block();
                let finalized_blocks = finalized_blocks_iter
                    .map(|b| (b.header, b.user_data))
                    .collect::<Vec<_>>();
                self.parent
                    .inner
                    .blocks
                    .set_finalized_block_height(finalized_blocks.last().unwrap().0.number);
                JustificationVerifyOutcome::NewFinalized {
                    finalized_blocks,
                    updates_best_block,
                }
            }
            Err(err) => JustificationVerifyOutcome::Error(err),
        };

        (self.parent, outcome)
    }

    /// Do not actually proceed with the verification.
    pub fn cancel(self) -> AllForksSync<TBl, TRq, TSrc> {
        self.parent
    }
}

/// State of the processing of blocks.
pub enum ProcessOne<TBl, TRq, TSrc> {
    /// No processing is necessary.
    ///
    /// Calling [`AllForksSync::process_one`] again is unnecessary.
    AllSync {
        /// The state machine.
        /// The [`AllForksSync::process_one`] method takes ownership of the [`AllForksSync`]. This
        /// field yields it back.
        sync: AllForksSync<TBl, TRq, TSrc>,
    },

    /// A header is ready for verification.
    HeaderVerify(HeaderVerify<TBl, TRq, TSrc>),

    /// A justification is ready for verification.
    JustificationVerify(JustificationVerify<TBl, TRq, TSrc>),
}

/// Outcome of calling [`HeaderVerify::perform`].
pub enum HeaderVerifyOutcome<TBl, TRq, TSrc> {
    /// Header has been successfully verified.
    Success {
        /// True if the newly-verified block is considered the new best block.
        is_new_best: bool,
        /// State machine yielded back. Use to continue the processing.
        sync: AllForksSync<TBl, TRq, TSrc>,
    },

    /// Header verification failed.
    Error {
        /// State machine yielded back. Use to continue the processing.
        sync: AllForksSync<TBl, TRq, TSrc>,
        /// Error that happened.
        error: HeaderVerifyError,
        /// User data that was passed to [`HeaderVerify::perform`] and is unused.
        user_data: TBl,
    },
}

/// Error that can happen when verifying a block header.
#[derive(Debug, derive_more::Display)]
pub enum HeaderVerifyError {
    /// Block uses a different consensus than the rest of the chain.
    ConsensusMismatch,
    /// The block verification has failed. The block is invalid and should be thrown away.
    VerificationFailed(verify::header_only::Error),
}

/// Information about the outcome of verifying a justification.
#[derive(Debug)]
pub enum JustificationVerifyOutcome<TBl> {
    /// Justification verification successful. The block and all its ancestors is now finalized.
    NewFinalized {
        /// List of finalized blocks, in decreasing block number.
        // TODO: use `Vec<u8>` instead of `Header`?
        finalized_blocks: Vec<(header::Header, TBl)>,
        // TODO: missing pruned blocks
        /// If `true`, this operation modifies the best block of the non-finalized chain.
        /// This can happen if the previous best block isn't a descendant of the now finalized
        /// block.
        updates_best_block: bool,
    },
    /// Problem while verifying justification.
    Error(blocks_tree::JustificationVerifyError),
}

/// State of the processing of blocks.
pub enum BlockBodyVerify<TBl, TRq, TSrc> {
    #[doc(hidden)]
    Foo(core::marker::PhantomData<(TBl, TRq, TSrc)>),
    // TODO: finish
    /*/// Processing of the block is over.
    ///
    /// There might be more blocks remaining. Call [`AllForksSync::process_one`] again.
    NewBest {
        /// The state machine.
        /// The [`AllForksSync::process_one`] method takes ownership of the
        /// [`AllForksSync`]. This field yields it back.
        sync: AllForksSync<TBl, TRq, TSrc>,

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
        sync: AllForksSync<TBl, TRq, TSrc>,

        /// Blocks that have been finalized. Includes the block that has just been verified.
        finalized_blocks: Vec<Block<TBl>>,
    },

    /// Loading a storage value of the finalized block is required in order to continue.
    FinalizedStorageGet(StorageGet<TBl, TRq, TSrc>),

    /// Fetching the list of keys of the finalized block with a given prefix is required in order
    /// to continue.
    FinalizedStoragePrefixKeys(StoragePrefixKeys<TBl, TRq, TSrc>),

    /// Fetching the key of the finalized block storage that follows a given one is required in
    /// order to continue.
    FinalizedStorageNextKey(StorageNextKey<TBl, TRq, TSrc>),*/
}
