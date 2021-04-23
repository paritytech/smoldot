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

//! Collection of "pending" blocks, in other words blocks whose existence is known but which
//! can't be verified yet. Used for the `all_forks` syncing.
//!
//! Example: the local node knows about block 5. A peer announces block 7. Since the local node
//! doesn't know block 6, it has to store block 7 for later, then download block 6. The container
//! in this module is where block 7 is temporarily stored.
//!
//! In addition to a set of blocks, this data structure also stores a set of ongoing requests that
//! related to these blocks. In the example above, it would store the request that asks for block
//! 6 from the network.
//!
//! # Blocks
//!
//! The [`PendingBlocks`] collection stores a list of pending blocks.
//!
//! Blocks are expected to be added to this collection whenever we hear about them from a source
//! of blocks (such as a peer) and that it is not possible to verify them immediately (because
//! their parent isn't known).
//!
//! Each block has zero, one, or more *requests* associated to it. When a request is associated
//! to a block, it means that we expect the response of the request to contain needed information
//! about the block in question.
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
//! # Requests
//!
//! In addition to a list of blocks, this data structure also stores a list of ongoing requests.
//! Each block has zero, one, or more requests associated to it.
//!
//! Call [`PendingBlocks::desired_requests`] to obtain the next query that should be started.
//! Call [`PendingBlocks::add_request`] to allocate a new [`RequestId`] and add a new request. This has
//! the effect of changing the outcome of calling [`PendingBlocks::desired_requests`].
//! Call [`PendingBlocks::finish_request`] to destroy a request after it has finished.
//!

use super::{disjoint, sources};

use alloc::{collections::BTreeSet, vec, vec::Vec};
use core::{
    convert::TryFrom as _,
    iter,
    num::{NonZeroU32, NonZeroU64},
};

pub use disjoint::PendingVerificationBlock;
pub use sources::SourceId;

/// Configuration for the [`PendingBlocks`].
#[derive(Debug)]
pub struct Config {
    /// Pre-allocated capacity for the number of blocks between the finalized block and the head
    /// of the chain.
    pub blocks_capacity: usize,

    /// Pre-allocated capacity for the number of sources that will be added to the collection.
    pub sources_capacity: usize,

    /// Height of the known finalized block. Can be lower than the actual value, and increased
    /// later.
    pub finalized_block_height: u64,

    /// If `true`, block bodies are downloaded and verified. If `false`, only headers are
    /// verified.
    pub verify_bodies: bool,

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

    /// List of block hashes that are known to be bad and shouldn't be downloaded or verified.
    ///
    /// > **Note**: This list is typically filled with a list of blocks found in the chain
    /// >           specifications. It is part of the "trusted setup" of the node, in other words
    /// >           the information that is passed by the user and blindly assumed to be true.
    // TODO: unused
    pub banned_blocks: Vec<[u8; 64]>,
}

/// State of a block in the data structure.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UnverifiedBlockState {
    /// Only the height and hash of the block is known.
    HeightHashKnown,
    /// The header of the block is known, but not its body.
    HeaderKnown {
        /// Hash of the block that is parent of this one.
        parent_hash: [u8; 32],
    },
    /// The header and body of the block are both known. The block is waiting to be verified.
    BodyKnown {
        /// Hash of the block that is parent of this one.
        parent_hash: [u8; 32],
    },
}

impl UnverifiedBlockState {
    /// Returns the parent block hash stored in this instance, if any.
    pub fn parent_hash(&self) -> Option<&[u8; 32]> {
        match self {
            UnverifiedBlockState::HeightHashKnown => None,
            UnverifiedBlockState::HeaderKnown { parent_hash } => Some(parent_hash),
            UnverifiedBlockState::BodyKnown { parent_hash } => Some(parent_hash),
        }
    }
}

/// Identifier for a request in the [`PendingBlocks`].
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RequestId(usize);

/// Collection of pending blocks and requests.
pub struct PendingBlocks<TBl, TRq, TSrc> {
    /// All sources in the collection.
    sources: sources::AllForksSources<Source<TSrc>>,

    /// Blocks whose validity couldn't be determined yet.
    blocks: disjoint::DisjointBlocks<UnverifiedBlock<TBl>>,

    /// See [`Config::verify_bodies`].
    verify_bodies: bool,

    /// Set of `(block_height, block_hash, request_id)`.
    /// Contains the list of all requests, associated to their block.
    ///
    /// The `request_id` is an index in [`PendingBlocks::requests`].
    ///
    /// > **Note**: This is a more optimized way compared to adding a `Vec<RequestId>` in the
    /// >           [`Block`] struct.
    blocks_requests: BTreeSet<(u64, [u8; 32], RequestId)>,

    /// All ongoing requests.
    requests: slab::Slab<Request<TRq>>,

    /// See [`Config::max_requests_per_block`].
    /// Since it is always compared with `usize`s, converted to `usize` ahead of time.
    max_requests_per_block: usize,
}

struct UnverifiedBlock<TBl> {
    state: UnverifiedBlockState,
    user_data: TBl,
}

struct Request<TRq> {
    detail: RequestParams,
    source_id: SourceId,
    user_data: TRq,
}

#[derive(Debug)]
struct Source<TSrc> {
    /// Number of requests that can be started on this source.
    // TODO: merge with occupation somehow
    requests_slots: u32,
    /// What the source is busy doing.
    occupation: Option<RequestId>,
    /// Opaque object passed by the user.
    user_data: TSrc,
}

impl<TBl, TRq, TSrc> PendingBlocks<TBl, TRq, TSrc> {
    /// Initializes a new empty collection.
    pub fn new(config: Config) -> Self {
        PendingBlocks {
            sources: sources::AllForksSources::new(
                config.sources_capacity,
                config.finalized_block_height,
            ),
            blocks: disjoint::DisjointBlocks::new(disjoint::Config {
                blocks_capacity: config.blocks_capacity,
            }),
            verify_bodies: config.verify_bodies,
            blocks_requests: Default::default(),
            requests: slab::Slab::with_capacity(
                config.blocks_capacity
                    * usize::try_from(config.max_requests_per_block.get())
                        .unwrap_or(usize::max_value()),
            ),
            max_requests_per_block: usize::try_from(config.max_requests_per_block.get())
                .unwrap_or(usize::max_value()),
        }
    }

    /// Add a new source to the container.
    ///
    /// The `user_data` parameter is opaque and decided entirely by the user. It can later be
    /// retrieved using [`source_user_data`].
    ///
    /// Returns the newly-created source entry.
    pub fn add_source(
        &mut self,
        user_data: TSrc,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    ) -> SourceId {
        self.sources.add_source(
            best_block_number,
            best_block_hash,
            Source {
                requests_slots: 1, // TODO: ?!
                occupation: None,
                user_data,
            },
        )
    }

    /// Removes the source from the [`PendingBlocks`].
    ///
    /// Returns the user data that was originally passed to [`PendingBlocks::add_source`], plus
    /// a list of all the requests that were targetting this source. These request are now
    /// invalid.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    // TODO: don't return a `Vec` but an iterator
    pub fn remove_source(
        &mut self,
        source_id: SourceId,
    ) -> (TSrc, Vec<(RequestId, RequestParams, TRq)>) {
        let user_data = self.sources.remove(source_id);

        let pending_requests = if let Some(pending_request_id) = user_data.occupation {
            debug_assert!(self.requests.contains(pending_request_id.0));
            let request = self.requests.remove(pending_request_id.0);

            let _was_in = self.blocks_requests.remove(&(
                request.detail.first_block_height,
                request.detail.first_block_hash,
                pending_request_id,
            ));
            debug_assert!(_was_in);

            vec![(pending_request_id, request.detail, request.user_data)]
        } else {
            Vec::new()
        };

        (user_data.user_data, pending_requests)
    }

    /// Registers a new block that the source is aware of.
    ///
    /// Has no effect if `height` is inferior or equal to the finalized block height.
    ///
    /// The block does not need to be known by the data structure.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn add_known_block(&mut self, source_id: SourceId, height: u64, hash: [u8; 32]) {
        self.sources.add_known_block(source_id, height, hash);
    }

    /// Sets the best block of this source.
    ///
    /// The block does not need to be known by the data structure.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn set_best_block(&mut self, source_id: SourceId, height: u64, hash: [u8; 32]) {
        self.sources.set_best_block(source_id, height, hash);
    }

    /// Returns true if [`SourceMutAccess::add_known_block`] or [`SourceMutAccess::set_best_block`]
    /// has earlier been called on this source with this height and hash, or if the source was
    /// originally created (using [`PendingBlocks::add_source`]) with this height and hash.
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
        self.sources
            .source_knows_non_finalized_block(source_id, height, hash)
    }

    /// Returns the user data associated to the source. This is the value originally passed
    /// through [`PendingBlocks::add_source`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn source_user_data(&self, source_id: SourceId) -> &TSrc {
        &self.sources.user_data(source_id).user_data
    }

    /// Returns the user data associated to the source. This is the value originally passed
    /// through [`PendingBlocks::add_source`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn source_user_data_mut(&mut self, source_id: SourceId) -> &mut TSrc {
        &mut self.sources.user_data_mut(source_id).user_data
    }

    /// Updates the height of the finalized block.
    ///
    /// This removes from the collection, and will ignore in the future, all blocks whose height
    /// is inferior or equal to this value.
    ///
    /// # Panic
    ///
    /// Panics if the new height is inferior to the previous value.
    ///
    pub fn set_finalized_block_height(&mut self, height: u64) {
        self.sources.set_finalized_block_height(height);
        // TODO: remove unverified blocks
    }

    /// Inserts an unverified block in the collection.
    ///
    /// Returns the previous user data associated to this block, if any.
    // TODO: what if height <= known_finalized?
    pub fn insert_unverified_block(
        &mut self,
        height: u64,
        hash: [u8; 32],
        state: UnverifiedBlockState,
        user_data: TBl,
    ) -> Option<(TBl, UnverifiedBlockState)> {
        let parent_hash = state.parent_hash().map(|h| *h);
        self.blocks
            .insert(
                height,
                hash,
                parent_hash,
                UnverifiedBlock { state, user_data },
            )
            .map(|b| (b.user_data, b.state))
    }

    /// Returns `true` if the block with the given height and hash is in the collection.
    pub fn contains(&self, height: u64, hash: &[u8; 32]) -> bool {
        self.blocks.contains(height, hash)
    }

    /// Gives access to the user data stored for this block.
    ///
    /// # Panic
    ///
    /// Panics if the block wasn't present in the data structure.
    ///
    pub fn block_user_data(&self, height: u64, hash: &[u8; 32]) -> &TBl {
        &self.blocks.user_data(height, hash).unwrap().user_data
    }

    /// Gives access to the user data stored for this block.
    ///
    /// # Panic
    ///
    /// Panics if the block wasn't present in the data structure.
    ///
    pub fn block_user_data_mut(&mut self, height: u64, hash: &[u8; 32]) -> &mut TBl {
        &mut self.blocks.user_data_mut(height, hash).unwrap().user_data
    }

    /// Modifies the state of the given block.
    ///
    /// This influences the outcome of [`PendingBlocks::desired_requests`].
    ///
    /// # Panic
    ///
    /// Panics if the block wasn't present in the data structure.
    ///
    pub fn set_block_state(&mut self, height: u64, hash: &[u8; 32], state: UnverifiedBlockState) {
        if let Some(parent_hash) = state.parent_hash() {
            self.blocks.set_parent_hash(height, hash, *parent_hash);
        }

        self.blocks.user_data_mut(height, hash).unwrap().state = state;
    }

    /// Modifies the state of the given block. This is a convenience around
    /// [`PendingBlocks::set_block_state`].
    ///
    /// If the current block's state implies that the header isn't known yet, updates it to a
    /// state where the header is known.
    ///
    /// # Panic
    ///
    /// Panics if the block wasn't present in the data structure.
    ///
    pub fn set_block_header_known(&mut self, height: u64, hash: &[u8; 32], parent_hash: [u8; 32]) {
        let curr = &mut self.blocks.user_data_mut(height, hash).unwrap().state;

        match curr {
            UnverifiedBlockState::HeaderKnown {
                parent_hash: cur_ph,
            }
            | UnverifiedBlockState::BodyKnown {
                parent_hash: cur_ph,
            } if *cur_ph == parent_hash => return,
            UnverifiedBlockState::HeaderKnown { .. } | UnverifiedBlockState::BodyKnown { .. } => {
                panic!()
            }
            UnverifiedBlockState::HeightHashKnown => {}
        }

        *curr = UnverifiedBlockState::HeaderKnown { parent_hash };
        self.blocks.set_parent_hash(height, hash, parent_hash);
    }

    /// Removes the given block from the collection after it has successfully been verified.
    ///
    /// # Panic
    ///
    /// Panics if the block wasn't present in the data structure.
    ///
    pub fn remove_verify_success(&mut self, height: u64, hash: &[u8; 32]) -> TBl {
        self.blocks.remove_verify_success(height, hash).user_data
    }

    /// Removes the given block from the collection after it has been determined to be bad.
    ///
    /// # Panic
    ///
    /// Panics if the block wasn't present in the data structure.
    ///
    pub fn remove_verify_failed(&mut self, height: u64, hash: &[u8; 32]) -> TBl {
        todo!()
    }

    /// Returns the number of blocks stored in the data structure.
    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the list of blocks whose parent hash is known but absent from the list of disjoint
    /// blocks. These blocks can potentially be verified.
    pub fn unverified_leaves(&'_ self) -> impl Iterator<Item = PendingVerificationBlock> + '_ {
        self.blocks.good_leaves()
    }

    /// Inserts a new request in the data structure.
    ///
    /// > **Note**: The request doesn't necessarily have to match a request returned by
    /// >           [`PendingBlocks::desired_requests`] or
    /// >           [`PendingBlocks::source_desired_requests`].
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
        let request_entry = self.requests.vacant_entry();

        let request_id = RequestId(request_entry.key());

        // TODO: what if source was already busy?
        let source_occupation = &mut self.sources.user_data_mut(source_id).occupation;
        debug_assert!(source_occupation.is_none());
        *source_occupation = Some(request_id);

        self.blocks_requests.insert((
            detail.first_block_height,
            detail.first_block_hash,
            request_id,
        ));

        request_entry.insert(Request {
            detail,
            source_id,
            user_data,
        });

        request_id
    }

    /// Marks a request as finished.
    ///
    /// Returns the parameters that were passed to [`PendingBlocks::add_request`].
    ///
    /// The next call to [`PendingBlocks::desired_requests`] might return the same request again.
    /// In order to avoid that, you are encouraged to update the state of the sources and blocks
    /// in the container with the outcome of the request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    #[track_caller]
    pub fn finish_request(&mut self, request_id: RequestId) -> (RequestParams, SourceId, TRq) {
        assert!(self.requests.contains(request_id.0));
        let request = self.requests.remove(request_id.0);

        let _was_in = self.blocks_requests.remove(&(
            request.detail.first_block_height,
            request.detail.first_block_hash,
            request_id,
        ));
        debug_assert!(_was_in);

        let source_occupation = &mut self.sources.user_data_mut(request.source_id).occupation;
        debug_assert_eq!(*source_occupation, Some(request_id));
        *source_occupation = None;

        (request.detail, request.source_id, request.user_data)
    }

    /// Returns the source that the given request is being performed on.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is out of range.
    ///
    pub fn request_source(&self, request_id: RequestId) -> SourceId {
        self.requests.get(request_id.0).unwrap().source_id
    }

    /// Returns a list of requests that are considered obsolete and can be removed using
    /// [`PendingBlocks::finish_request`].
    ///
    /// A request becomes obsolete if the state of the request blocks changes in such a way that
    /// they don't need to be requested anymore. The response to the request will be useless.
    ///
    /// > **Note**: It is in no way mandatory to actually call this function and cancel the
    /// >           requests that are returned.
    pub fn obsolete_requests(&self) -> impl Iterator<Item = RequestId> {
        iter::empty() // TODO:
    }

    /// Returns the details of a request to start towards a source.
    ///
    /// This method doesn't modify the state machine in any way. [`PendingBlocks::add_request`]
    /// must be called in order for the request to actually be marked as started.
    pub fn desired_requests(&'_ self) -> impl Iterator<Item = (SourceId, RequestParams)> + '_ {
        self.desired_requests_inner(None)
    }

    /// Returns the details of a request to start towards the source.
    ///
    /// This method doesn't modify the state machine in any way. [`PendingBlocks::add_request`]
    /// must be called in order for the request to actually be marked as started.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn source_desired_requests(
        &'_ self,
        source_id: SourceId,
    ) -> impl Iterator<Item = RequestParams> + '_ {
        self.desired_requests_inner(Some(source_id))
            .map(move |(_actual_source, request)| {
                debug_assert_eq!(_actual_source, source_id);
                request
            })
    }

    /// Inner implementation of [`PendingBlocks::desired_requests`] and
    /// [`PendingBlocks::source_desired_requests`].
    ///
    /// If `force_source` is `Some`, only the given source will be considered.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    fn desired_requests_inner(
        &'_ self,
        force_source: Option<SourceId>,
    ) -> impl Iterator<Item = (SourceId, RequestParams)> + '_ {
        // TODO: this is O(n²); maybe do something more optimized once it's fully working and has unit tests
        self.blocks
            .unknown_blocks()
            .filter(move |(unknown_block_height, unknown_block_hash)| {
                // Don't request blocks that don't need to be requested.
                match self
                    .blocks
                    .user_data(*unknown_block_height, unknown_block_hash)
                    .map(|ud| &ud.state)
                {
                    None | Some(UnverifiedBlockState::HeightHashKnown) => true,
                    Some(UnverifiedBlockState::HeaderKnown { .. }) if self.verify_bodies => true,
                    Some(UnverifiedBlockState::HeaderKnown { .. })
                    | Some(UnverifiedBlockState::BodyKnown { .. }) => false,
                }
            })
            .filter(move |(unknown_block_height, unknown_block_hash)| {
                // Cap by `max_requests_per_block`.
                // TODO: is that correct?
                let num_existing_requests = self
                    .blocks_requests
                    .range(
                        (
                            *unknown_block_height,
                            **unknown_block_hash,
                            RequestId(usize::min_value()),
                        )
                            ..=(
                                *unknown_block_height,
                                **unknown_block_hash,
                                RequestId(usize::max_value()),
                            ),
                    )
                    .count();

                debug_assert!(num_existing_requests <= self.max_requests_per_block);
                num_existing_requests < self.max_requests_per_block
            })
            .flat_map(move |(unknown_block_height, unknown_block_hash)| {
                // Try to find all appropriate sources.
                let possible_sources = if let Some(force_source) = force_source {
                    either::Left(iter::once(force_source).filter(move |id| {
                        self.sources.source_knows_non_finalized_block(
                            *id,
                            unknown_block_height,
                            unknown_block_hash,
                        )
                    }))
                } else {
                    either::Right(
                        self.sources
                            .knows_non_finalized_block(unknown_block_height, unknown_block_hash),
                    )
                };

                possible_sources.filter_map(move |source_id| {
                    debug_assert!(self.sources.source_knows_non_finalized_block(
                        source_id,
                        unknown_block_height,
                        unknown_block_hash
                    ));

                    // Don't start more than one request at a time.
                    // TODO: in the future, allow multiple requests
                    if self.sources.user_data(source_id).occupation.is_some() {
                        return None;
                    }

                    // As documented, this only returns an informative object to the user, and
                    // doesn't actually start the query yet.
                    Some((
                        source_id,
                        RequestParams {
                            first_block_hash: *unknown_block_hash,
                            first_block_height: unknown_block_height,
                            num_blocks: NonZeroU64::new(1).unwrap(), // TODO: *unknown_block_height - ...
                        },
                    ))
                })
            })
    }
}

/// Information about a blocks request to be performed on a source.
// TODO: needs more documentation
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestParams {
    /// Height of the first block to request.
    pub first_block_height: u64,

    /// Hash of the first block to request.
    pub first_block_hash: [u8; 32],

    /// Number of blocks the request should return.
    ///
    /// Note that this is only an indication, and the source is free to give fewer blocks
    /// than requested. If that happens, the state machine might later send out further
    /// ancestry search requests to complete the chain.
    pub num_blocks: NonZeroU64,
}
