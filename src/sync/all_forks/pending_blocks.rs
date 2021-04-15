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
//! Call [`PendingBlocks::next_desired_query`] to obtain the next query that should be started.
//! Call [`PendingBlocks::add_request`] to allocate a new [`RequestId`] and add a new request. This has
//! the effect of changing the outcome of calling [`PendingBlocks::next_desired_query`].
//! Call [`PendingBlocks::finish_request`] to destroy a request after it has finished.
//!

use super::{disjoint, sources};

use alloc::{collections::BTreeSet, vec::Vec};
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

/// Identifier for a request in the [`PendingBlocks`].
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RequestId(usize);

/// Collection of pending blocks and requests.
pub struct PendingBlocks<TBl, TRq, TSrc> {
    /// All sources in the collection.
    sources: sources::AllForksSources<Source<TSrc>>,

    /// Blocks whose header validity couldn't be determined yet.
    unverified_headers: disjoint::DisjointBlocks<UnverifiedHeaderBlock<TBl>>,

    /// List of blocks whose header has been determined to be valid, but whose body isn't known
    /// yet.
    ///
    /// `Some` if and only if [`Config::verify_bodies`] was true.
    valid_header_pending_body: Option<BTreeSet<()>>,

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

struct UnverifiedHeaderBlock<TBl> {
    user_data: TBl,
    known_body: Option<Vec<u8>>,
}

struct Request<TRq> {
    detail: DesiredRequest,
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
            unverified_headers: disjoint::DisjointBlocks::new(disjoint::Config {
                blocks_capacity: config.blocks_capacity,
            }),
            valid_header_pending_body: if config.verify_bodies {
                Some(BTreeSet::default())
            } else {
                None
            },
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
    /// Returns the user data that was originally passed to [`PendingBlocks::add_source`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn remove_source(&mut self, source_id: SourceId) -> TSrc {
        let user_data = self.sources.remove(source_id);

        todo!()
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
    pub fn knows_non_finalized_block(
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
    pub fn source_user_data(&mut self, source_id: SourceId) -> &mut TSrc {
        &mut self.sources.user_data_mut(source_id).user_data
    }

    /// Inserts an unverified block in the collection.
    pub fn insert_unverified_block(
        &mut self,
        height: u64,
        hash: [u8; 32],
        parent_hash: Option<[u8; 32]>,
        user_data: TBl,
    ) {
        self.unverified_headers.insert(
            height,
            hash,
            parent_hash,
            UnverifiedHeaderBlock {
                known_body: None,
                user_data,
            },
        );
    }

    /// Removes the given block from the collection after it has successfully been verified.
    ///
    /// # Panic
    ///
    /// Panics if the block wasn't present in the data structure.
    ///
    pub fn remove_verify_success(&mut self, height: u64, hash: [u8; 32]) -> TBl {
        todo!()
    }

    /// Returns the number of blocks stored in the data structure.
    pub fn num_blocks(&self) -> usize {
        self.unverified_headers.len()
    }

    /// Returns the list of blocks whose parent hash is known but absent from the list of disjoint
    /// blocks. These blocks can potentially be verified.
    pub fn unverified_leaves(&'_ self) -> impl Iterator<Item = PendingVerificationBlock> + '_ {
        self.unverified_headers.good_leaves()
    }

    /// Inserts a new request in the data structure.
    ///
    /// > **Note**: The request doesn't necessarily have to match a request returned by
    /// >           [`PendingBlocks::next_desired_query`] or
    /// >           [`PendingBlocks::source_next_desired_query`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn add_request(
        &mut self,
        source_id: SourceId,
        detail: DesiredRequest,
        user_data: TRq,
    ) -> RequestId {
        // TODO: update source

        let request_entry = self.requests.vacant_entry();

        let request_id = RequestId(request_entry.key());

        self.blocks_requests.insert((
            detail.first_block_height,
            detail.first_block_hash,
            request_id,
        ));

        request_entry.insert(Request { detail, user_data });

        request_id
    }

    /// Marks a request as finished.
    ///
    /// Returns the parameters that were passed to [`PendingBlocks::add_request`].
    ///
    /// The next call to [`PendingBlocks::next_desired_query`] might return the same request again.
    /// In order to avoid that, you are encouraged to update the state of the sources and blocks
    /// in the container with the outcome of the request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    pub fn finish_request(&mut self, request_id: RequestId) -> (DesiredRequest, TRq) {
        let request = self.requests.remove(request_id.0);

        let _was_in = self.blocks_requests.remove(&(
            request.detail.first_block_height,
            request.detail.first_block_hash,
            request_id,
        ));
        debug_assert!(_was_in);

        // TODO: remove occupation from source

        (request.detail, request.user_data)
    }

    /// Returns the details of a request to start towards a source.
    ///
    /// This method doesn't modify the state machine in any way. [`PendingBlocks::add_request`] must be
    /// called in order for the request to actually be marked as started.
    pub fn desired_queries(&self) -> impl Iterator<Item = (SourceId, DesiredRequest)> + '_ {
        self.desired_queries_inner(None)
    }

    /// Returns the details of a request to start towards the source.
    ///
    /// This method doesn't modify the state machine in any way. [`PendingBlocks::add_request`] must be
    /// called in order for the request to actually be marked as started.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn source_desired_queries(
        &self,
        source_id: SourceId,
    ) -> impl Iterator<Item = DesiredRequest> + '_ {
        self.desired_queries_inner(Some(source_id))
            .map(move |(_actual_source, request)| {
                debug_assert_eq!(_actual_source, source_id);
                request
            })
    }

    /// Inner implementation of [`PendingBlocks::next_desired_query`] and
    /// [`SourceMutAccess::next_desired_query`].
    ///
    /// If `force_source` is `Some`, only the given source will be considered.
    ///
    /// # Panic
    ///
    /// Panics if `source_id` is invalid.
    ///
    fn desired_queries_inner(
        &'_ self,
        force_source: Option<SourceId>,
    ) -> impl Iterator<Item = (SourceId, DesiredRequest)> + '_ {
        // TODO: need to start requests for bodies

        // TODO: this is O(n²); maybe do something more optimized once it's fully working and has unit tests
        self.unverified_headers.unknown_blocks().filter_map(
            move |(unknown_block_height, unknown_block_hash)| {
                // TODO: is that correct?
                let num_existing_requests = self
                    .blocks_requests
                    .range(
                        (
                            unknown_block_height,
                            *unknown_block_hash,
                            RequestId(usize::min_value()),
                        )
                            ..=(
                                unknown_block_height,
                                *unknown_block_hash,
                                RequestId(usize::max_value()),
                            ),
                    )
                    .count();

                debug_assert!(num_existing_requests <= self.max_requests_per_block);
                if num_existing_requests == self.max_requests_per_block {
                    return None;
                }

                // Try to find an appropriate source.
                let possible_sources = if let Some(force_source) = force_source {
                    either::Left(iter::once(force_source).filter(|id| {
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

                for source_id in possible_sources {
                    debug_assert!(self.sources.source_knows_non_finalized_block(
                        source_id,
                        unknown_block_height,
                        unknown_block_hash
                    ));

                    // Don't start more than one request at a time.
                    // TODO: in the future, allow multiple requests
                    if self.sources.user_data(source_id).occupation.is_some() {
                        continue;
                    }

                    // As documented, this only returns an informative object to the user, and
                    // doesn't actually start the query yet.
                    return Some((
                        source_id,
                        DesiredRequest {
                            first_block_hash: *unknown_block_hash,
                            first_block_height: unknown_block_height,
                            num_blocks: NonZeroU64::new(128).unwrap(), // TODO: *unknown_block_height - ...
                        },
                    ));
                }

                None
            },
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DesiredRequest {
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

/// Outcome of removing a block from the collection.
#[must_use]
pub struct RemoveOutcome<TBl, TRq> {
    /// User data of the block that has been removed.
    pub user_data: TBl,

    /// List of requests that concerned the block that has been successfully verified. These
    /// request IDs are now invalid.
    pub cancelled_requests: Vec<(RequestId, TRq)>,
}
