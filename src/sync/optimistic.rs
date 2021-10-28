// Smoldot
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

//! Optimistic header and body syncing.
//!
//! This state machine builds, from a set of sources, a fully verified chain of blocks headers
//! and bodies.
//!
//! # Overview
//!
//! The algorithm used by this state machine is called "optimistic syncing". It consists in
//! sending requests for blocks to a certain list of sources, aggregating the answers, and
//! verifying them.
//!
//! The [`OptimisticSync`] struct holds a list of sources, a list of pending block requests,
//! a chain, and a list of blocks received as answers and waiting to be verified.
//!
//! The requests are emitted ahead of time, so that they can be answered asynchronously while
//! blocks in the verification queue are being processed.
//!
//! The syncing is said to be *optimistic* because it is assumed that all sources will provide
//! correct blocks.
//! In the case where the verification of a block fails, the state machine jumps back to the
//! latest known finalized block and resumes syncing from there, possibly using different sources
//! this time.
//!
//! The *optimism* aspect comes from the fact that, while a bad source can't corrupt the state of
//! the local chain, and can't stall the syncing process (unless there isn't any other source
//! available), it can still slow it down.

// TODO: document better
// TODO: this entire module needs clean up

use crate::{
    chain::{blocks_tree, chain_information},
    executor::host,
    header,
    trie::calculate_root,
};

use alloc::{borrow::ToOwned as _, collections::BTreeMap, vec::Vec};
use core::{
    cmp, fmt, iter, mem,
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};
use hashbrown::{HashMap, HashSet};

mod verification_queue;

/// Configuration for the [`OptimisticSync`].
#[derive(Debug)]
pub struct Config {
    /// Information about the latest finalized block and its ancestors.
    pub chain_information: chain_information::ValidChainInformation,

    /// Pre-allocated capacity for the number of block sources.
    pub sources_capacity: usize,

    /// Pre-allocated capacity for the number of blocks between the finalized block and the head
    /// of the chain.
    ///
    /// Should be set to the maximum number of block between two consecutive justifications.
    pub blocks_capacity: usize,

    /// Number of blocks to download ahead of the best block.
    ///
    /// Whenever the latest best block is updated, the state machine will start block
    /// requests for the block `best_block_height + download_ahead_blocks` and all its
    /// ancestors. Considering that requesting blocks has some latency, downloading blocks ahead
    /// of time ensures that verification isn't blocked waiting for a request to be finished.
    ///
    /// The ideal value here depends on the speed of blocks verification speed and latency of
    /// block requests.
    pub download_ahead_blocks: NonZeroU32,

    /// If `Some`, the block bodies and storage are also synchronized. Contains the extra
    /// configuration.
    pub full: Option<ConfigFull>,
}

/// See [`Config::full`].
#[derive(Debug)]
pub struct ConfigFull {
    /// Compiled runtime code of the finalized block.
    pub finalized_runtime: host::HostVmPrototype,
}

/// Identifier for an ongoing request in the [`OptimisticSync`].
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RequestId(u64);

/// Identifier for a source in the [`OptimisticSync`].
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SourceId(u64);

/// Optimistic headers-only syncing.
pub struct OptimisticSync<TRq, TSrc, TBl> {
    /// Data structure containing the blocks.
    ///
    /// The user data, [`Block`], isn't used internally but stores information later reported
    /// to the user.
    chain: blocks_tree::NonFinalizedTree<Block<TBl>>,

    /// Extra fields. In a separate structure in order to be moved around.
    inner: OptimisticSyncInner<TRq, TSrc, TBl>,
}

/// Extra fields. In a separate structure in order to be moved around.
struct OptimisticSyncInner<TRq, TSrc, TBl> {
    /// Configuration for the actual finalized block of the chain.
    /// Used if the `chain` field needs to be recreated.
    finalized_chain_information: blocks_tree::Config,

    /// See [`ConfigFull::finalized_runtime`]. `None` in non-full mode.
    finalized_runtime: Option<host::HostVmPrototype>,

    /// Changes in the storage of the best block compared to the finalized block.
    /// The `BTreeMap`'s keys are storage keys, and its values are new values or `None` if the
    /// value has been erased from the storage.
    best_to_finalized_storage_diff: BTreeMap<Vec<u8>, Option<Vec<u8>>>,

    /// Compiled runtime code of the best block. `None` if it is the same as
    /// [`OptimisticSyncInner::finalized_runtime`].
    best_runtime: Option<host::HostVmPrototype>,

    /// Cache of calculation for the storage trie of the best block.
    /// Providing this value when verifying a block considerably speeds up the verification.
    top_trie_root_calculation_cache: Option<calculate_root::CalculationCache>,

    /// See [`Config::download_ahead_blocks`].
    download_ahead_blocks: NonZeroU32,

    /// List of sources of blocks.
    sources: HashMap<SourceId, Source<TSrc>, fnv::FnvBuildHasher>,

    /// Next [`SourceId`] to allocate.
    /// SourceIds are unique so that the source in the [`verification_queue::VerificationQueue`]
    /// doesn't accidentally collide with a new source.
    next_source_id: SourceId,

    /// Queue of block requests, either waiting to be started, in progress, or completed.
    verification_queue: verification_queue::VerificationQueue<TRq, RequestSuccessBlock<TBl>>,

    /// Justification, if any, of the block that has just been verified.
    pending_encoded_justification: Option<(Vec<u8>, SourceId)>,

    /// Identifier to assign to the next request.
    next_request_id: RequestId,

    /// Requests that have been started but whose answers are no longer desired.
    obsolete_requests: HashMap<RequestId, (SourceId, TRq), fnv::FnvBuildHasher>,
}

impl<TRq, TSrc, TBl> OptimisticSyncInner<TRq, TSrc, TBl> {
    fn make_requests_obsolete(&mut self, chain: &blocks_tree::NonFinalizedTree<Block<TBl>>) {
        let former_queue = mem::replace(
            &mut self.verification_queue,
            verification_queue::VerificationQueue::new(chain.best_block_header().number + 1),
        );

        for (user_data, request_id, source) in former_queue.into_requests() {
            let _was_in = self
                .obsolete_requests
                .insert(request_id, (source, user_data));
            debug_assert!(_was_in.is_none());
        }
    }

    fn with_requests_obsoleted(
        mut self,
        chain: &blocks_tree::NonFinalizedTree<Block<TBl>>,
    ) -> Self {
        self.make_requests_obsolete(chain);
        self
    }
}

struct Source<TSrc> {
    /// Opaque value passed to [`OptimisticSync::add_source`].
    user_data: TSrc,

    /// Best block that the source has reported having.
    best_block_number: u64,

    /// If `true`, this source is banned and shouldn't use be used to request blocks.
    /// Note that the ban is lifted if the source is removed. This ban isn't meant to be a line of
    /// defense against malicious peers but rather an optimisation.
    banned: bool,

    /// Number of requests that use this source.
    num_ongoing_requests: u32,
}

// TODO: doc
pub struct Block<TBl> {
    /// Header of the block.
    pub header: header::Header,

    /// SCALE-encoded justification of this block, if any.
    pub justification: Option<Vec<u8>>,

    /// User data associated to the block.
    pub user_data: TBl,

    /// Extra fields for full block verifications.
    pub full: Option<BlockFull>,
}

// TODO: doc
pub struct BlockFull {
    /// List of SCALE-encoded extrinsics that form the block's body.
    pub body: Vec<Vec<u8>>,

    /// Changes to the storage made by this block compared to its parent.
    pub storage_top_trie_changes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,

    /// List of changes to the offchain storage that this block performs.
    pub offchain_storage_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
}

impl<TRq, TSrc, TBl> OptimisticSync<TRq, TSrc, TBl> {
    /// Builds a new [`OptimisticSync`].
    pub fn new(config: Config) -> Self {
        let blocks_tree_config = blocks_tree::Config {
            chain_information: config.chain_information,
            blocks_capacity: config.blocks_capacity,
        };

        let chain = blocks_tree::NonFinalizedTree::new(blocks_tree_config.clone());
        let best_block_header_num = chain.best_block_header().number;

        OptimisticSync {
            chain,
            inner: OptimisticSyncInner {
                finalized_chain_information: blocks_tree_config,
                finalized_runtime: config.full.map(|f| f.finalized_runtime),
                best_to_finalized_storage_diff: BTreeMap::new(),
                best_runtime: None,
                top_trie_root_calculation_cache: None,
                sources: HashMap::with_capacity_and_hasher(
                    config.sources_capacity,
                    Default::default(),
                ),
                next_source_id: SourceId(0),
                verification_queue: verification_queue::VerificationQueue::new(
                    best_block_header_num + 1,
                ),
                pending_encoded_justification: None,
                download_ahead_blocks: config.download_ahead_blocks,
                next_request_id: RequestId(0),
                obsolete_requests: HashMap::with_capacity_and_hasher(0, Default::default()),
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
        self.inner
            .finalized_chain_information
            .chain_information
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

    /// Disassembles the state machine into its raw components.
    pub fn disassemble(self) -> Disassemble<TRq, TSrc> {
        Disassemble {
            chain_information: self.inner.finalized_chain_information.chain_information,
            sources: self
                .inner
                .sources
                .into_iter()
                .map(|(id, source)| DisassembleSource {
                    id,
                    user_data: source.user_data,
                    best_block_number: source.best_block_number,
                })
                .collect(),
            requests: self
                .inner
                .verification_queue
                .into_requests()
                .map(|(user_data, request_id, _)| (request_id, user_data))
                .collect(),
        }
    }

    /// Inform the [`OptimisticSync`] of a new potential source of blocks.
    pub fn add_source(&mut self, source: TSrc, best_block_number: u64) -> SourceId {
        let new_id = {
            let id = self.inner.next_source_id;
            self.inner.next_source_id.0 += 1;
            id
        };

        self.inner.sources.insert(
            new_id,
            Source {
                user_data: source,
                best_block_number,
                banned: false,
                num_ongoing_requests: 0,
            },
        );

        new_id
    }

    /// Returns the current best block of the given source.
    ///
    /// This corresponds either the latest call to [`OptimisticSync::raise_source_best_block`],
    /// or to the parameter passed to [`OptimisticSync::add_source`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn source_best_block(&self, source_id: SourceId) -> u64 {
        self.inner
            .sources
            .get(&source_id)
            .unwrap()
            .best_block_number
    }

    /// Updates the best known block of the source.
    ///
    /// Has no effect if the previously-known best block is lower than the new one.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn raise_source_best_block(&mut self, id: SourceId, best_block_number: u64) {
        let current = &mut self.inner.sources.get_mut(&id).unwrap().best_block_number;
        if *current < best_block_number {
            *current = best_block_number;
        }
    }

    /// Inform the [`OptimisticSync`] that a source of blocks is no longer available.
    ///
    /// This automatically cancels all the requests that have been emitted for this source.
    /// This list of requests is returned as part of this function.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn remove_source(
        &'_ mut self,
        source_id: SourceId,
    ) -> (TSrc, impl Iterator<Item = (RequestId, TRq)> + '_) {
        let src_user_data = self.inner.sources.remove(&source_id).unwrap().user_data;
        let drain = RequestsDrain {
            iter: self.inner.verification_queue.drain_source(source_id),
        };
        (src_user_data, drain)
    }

    /// Returns the list of sources in this state machine.
    pub fn sources(&'_ self) -> impl ExactSizeIterator<Item = SourceId> + '_ {
        self.inner.sources.keys().copied()
    }

    pub fn source_user_data(&self, source_id: SourceId) -> &TSrc {
        &self.inner.sources.get(&source_id).unwrap().user_data
    }

    pub fn source_user_data_mut(&mut self, source_id: SourceId) -> &mut TSrc {
        &mut self.inner.sources.get_mut(&source_id).unwrap().user_data
    }

    /// Returns the number of ongoing requests that concern this source.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn source_num_ongoing_requests(&self, source_id: SourceId) -> usize {
        let num_obsolete = self
            .inner
            .obsolete_requests
            .values()
            .filter(|(id, _)| *id == source_id)
            .count();
        let num_regular = self
            .inner
            .verification_queue
            .source_num_ongoing_requests(source_id);
        num_obsolete + num_regular
    }

    /// Returns an iterator that yields all the requests whose outcome is no longer desired.
    pub fn obsolete_requests(&'_ self) -> impl Iterator<Item = (RequestId, &'_ TRq)> + '_ {
        self.inner
            .obsolete_requests
            .iter()
            .map(|(id, (_, ud))| (*id, ud))
    }

    /// Returns an iterator that yields all requests that could be started.
    pub fn desired_requests(&'_ self) -> impl Iterator<Item = RequestDetail> + '_ {
        let sources = &self.inner.sources;
        self.inner
            .verification_queue
            .desired_requests(self.inner.download_ahead_blocks)
            .flat_map(move |e| sources.iter().map(move |s| (e, s)))
            .filter_map(|((block_height, num_blocks), (source_id, source))| {
                if source.num_ongoing_requests != 0 {
                    return None;
                }
                let source_avail_blocks =
                    source.best_block_number.checked_sub(block_height.get())?;
                Some(RequestDetail {
                    block_height,
                    num_blocks: cmp::min(
                        NonZeroU32::new(u32::try_from(source_avail_blocks).unwrap()).unwrap(),
                        num_blocks,
                    ),
                    source_id: *source_id,
                })
            })
    }

    /// Updates the [`OptimisticSync`] with the fact that a request has been started.
    ///
    /// Returns the identifier for the request that must later be passed back to
    /// [`OptimisticSync::finish_request`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn insert_request(&mut self, detail: RequestDetail, user_data: TRq) -> RequestId {
        self.inner
            .sources
            .get_mut(&detail.source_id)
            .unwrap()
            .num_ongoing_requests += 1;

        let request_id = self.inner.next_request_id;
        self.inner.next_request_id.0 += 1;

        match self.inner.verification_queue.insert_request(
            detail.block_height,
            detail.num_blocks,
            request_id,
            detail.source_id,
            user_data,
        ) {
            Ok(()) => {}
            Err(user_data) => {
                self.inner
                    .obsolete_requests
                    .insert(request_id, (detail.source_id, user_data));
            }
        }

        request_id
    }

    /// Update the [`OptimisticSync`] with the outcome of a request.
    ///
    /// Returns the user data that was associated to that request.
    ///
    /// If the state machine only handles light clients, that is if [`Config::full`] was `false`,
    /// then the values of [`RequestSuccessBlock::scale_encoded_extrinsics`] are silently ignored.
    ///
    /// > **Note**: If [`Config::full`] is `false`, you are encouraged to not request the block's
    /// >           body from the source altogether, and to fill the
    /// >           [`RequestSuccessBlock::scale_encoded_extrinsics`] fields with `Vec::new()`.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    pub fn finish_request(
        &mut self,
        request_id: RequestId,
        outcome: Result<impl Iterator<Item = RequestSuccessBlock<TBl>>, RequestFail>,
    ) -> (TRq, FinishRequestOutcome<TSrc>) {
        if let Some((source_id, user_data)) = self.inner.obsolete_requests.remove(&request_id) {
            self.inner.obsolete_requests.shrink_to_fit();
            self.inner
                .sources
                .get_mut(&source_id)
                .unwrap()
                .num_ongoing_requests -= 1;
            return (user_data, FinishRequestOutcome::Obsolete);
        }

        let outcome_is_err = outcome.is_err();

        let (user_data, source_id) = self
            .inner
            .verification_queue
            .finish_request(request_id, outcome.map_err(|_| ()));

        self.inner
            .sources
            .get_mut(&source_id)
            .unwrap()
            .num_ongoing_requests -= 1;

        if outcome_is_err {
            self.inner.sources.get_mut(&source_id).unwrap().banned = true;

            // If all sources are banned, unban them.
            if self.inner.sources.iter().all(|(_, s)| s.banned) {
                for src in self.inner.sources.values_mut() {
                    src.banned = false;
                }
            }
        }

        (
            user_data,
            if !outcome_is_err {
                FinishRequestOutcome::Queued
            } else {
                FinishRequestOutcome::SourcePunished(
                    &mut self.inner.sources.get_mut(&source_id).unwrap().user_data,
                )
            },
        )
    }

    /// Process the next block in the queue of verification.
    ///
    /// This method takes ownership of the [`OptimisticSync`]. The [`OptimisticSync`] is yielded
    /// back in the returned value.
    pub fn process_one(self) -> ProcessOne<TRq, TSrc, TBl> {
        if self.inner.pending_encoded_justification.is_some() {
            return ProcessOne::VerifyJustification(JustificationVerify {
                chain: self.chain,
                inner: self.inner,
            });
        }

        // The block isn't immediately extracted. A `Verify` struct is built, whose existence
        // confirms that a block is ready. If the `Verify` is dropped without `start` being called,
        // the block stays in the list.
        if self.inner.verification_queue.blocks_ready() {
            ProcessOne::VerifyBlock(BlockVerify {
                inner: self.inner,
                chain: self.chain,
            })
        } else {
            ProcessOne::Idle { sync: self }
        }
    }
}

pub struct RequestSuccessBlock<TBl> {
    pub scale_encoded_header: Vec<u8>,
    pub scale_encoded_justification: Option<Vec<u8>>,
    pub scale_encoded_extrinsics: Vec<Vec<u8>>,
    pub user_data: TBl,
}

/// State of the processing of blocks.
pub enum ProcessOne<TRq, TSrc, TBl> {
    /// No processing is necessary.
    ///
    /// Calling [`OptimisticSync::process_one`] again is unnecessary.
    Idle {
        /// The state machine.
        /// The [`OptimisticSync::process_one`] method takes ownership of the
        /// [`OptimisticSync`]. This field yields it back.
        sync: OptimisticSync<TRq, TSrc, TBl>,
    },

    VerifyBlock(BlockVerify<TRq, TSrc, TBl>),

    VerifyJustification(JustificationVerify<TRq, TSrc, TBl>),
}

/// Start the processing of a block verification.
pub struct BlockVerify<TRq, TSrc, TBl> {
    inner: OptimisticSyncInner<TRq, TSrc, TBl>,
    chain: blocks_tree::NonFinalizedTree<Block<TBl>>,
}

impl<TRq, TSrc, TBl> BlockVerify<TRq, TSrc, TBl> {
    /// Returns the height of the block about to be verified.
    pub fn height(&self) -> u64 {
        // TODO: unwrap?
        header::decode(self.header()).unwrap().number
    }

    /// Returns the hash of the block about to be verified.
    pub fn hash(&self) -> [u8; 32] {
        header::hash_from_scale_encoded_header(self.header())
    }

    /// Returns true if [`Config::full`] was `Some` at initialization.
    pub fn is_full_verification(&self) -> bool {
        self.inner.finalized_runtime.is_some()
    }

    /// Returns the SCALE-encoded header of the block about to be verified.
    fn header(&self) -> &[u8] {
        &self
            .inner
            .verification_queue
            .first_block()
            .unwrap()
            .scale_encoded_header
    }

    /// Start the verification of the block.
    ///
    /// Must be passed the current UNIX time in order to verify that the block doesn't pretend to
    /// come from the future.
    pub fn start(mut self, now_from_unix_epoch: Duration) -> BlockVerification<TRq, TSrc, TBl> {
        // Extract the block to process. We are guaranteed that a block is available because a
        // `Verify` is built only when that is the case.
        // Be aware that `source_id` might refer to an obsolete source.
        let (block, source_id) = self.inner.verification_queue.pop_first_block().unwrap();

        debug_assert!(self.inner.pending_encoded_justification.is_none());
        self.inner.pending_encoded_justification = block
            .scale_encoded_justification
            .clone()
            .map(|j| (j, source_id));

        if self.inner.finalized_runtime.is_some() {
            BlockVerification::from(
                Inner::Step1(
                    self.chain
                        .verify_body(block.scale_encoded_header, now_from_unix_epoch),
                ),
                BlockVerificationShared {
                    inner: self.inner,
                    block_body: block.scale_encoded_extrinsics,
                    block_user_data: Some(block.user_data),
                    source_id,
                },
            )
        } else {
            let error = match self
                .chain
                .verify_header(block.scale_encoded_header, now_from_unix_epoch)
            {
                Ok(blocks_tree::HeaderVerifySuccess::Insert {
                    insert,
                    is_new_best: true,
                    ..
                }) => {
                    let header = insert.header().into();
                    insert.insert(Block {
                        header,
                        justification: block.scale_encoded_justification.clone(),
                        user_data: block.user_data,
                        full: None,
                    });
                    None
                }
                Ok(blocks_tree::HeaderVerifySuccess::Duplicate)
                | Ok(blocks_tree::HeaderVerifySuccess::Insert {
                    is_new_best: false, ..
                }) => Some(ResetCause::NonCanonical),
                Err(err) => Some(ResetCause::HeaderError(err)),
            };

            if let Some(reason) = error {
                if let Some(src) = self.inner.sources.get_mut(&source_id) {
                    src.banned = true;
                }

                // If all sources are banned, unban them.
                if self.inner.sources.iter().all(|(_, s)| s.banned) {
                    for src in self.inner.sources.values_mut() {
                        src.banned = false;
                    }
                }

                self.inner.make_requests_obsolete(&self.chain);
                self.inner.best_to_finalized_storage_diff = Default::default();
                self.inner.best_runtime = None;
                self.inner.top_trie_root_calculation_cache = None;

                let previous_best_height = self.chain.best_block_header().number;
                BlockVerification::Reset {
                    sync: OptimisticSync {
                        inner: self.inner,
                        chain: self.chain,
                    },
                    previous_best_height,
                    reason,
                }
            } else {
                let new_best_hash = self.chain.best_block_hash();
                let new_best_number = self.chain.best_block_header().number;

                BlockVerification::NewBest {
                    sync: OptimisticSync {
                        inner: self.inner,
                        chain: self.chain,
                    },
                    new_best_hash,
                    new_best_number,
                }
            }
        }
    }
}

/// State of the processing of blocks.
pub enum BlockVerification<TRq, TSrc, TBl> {
    /// An issue happened when verifying the block or its justification, resulting in resetting
    /// the chain to the latest finalized block.
    Reset {
        /// The state machine.
        /// The [`OptimisticSync::process_one`] method takes ownership of the
        /// [`OptimisticSync`]. This field yields it back.
        sync: OptimisticSync<TRq, TSrc, TBl>,

        /// Height of the best block before the reset.
        previous_best_height: u64,

        /// Problem that happened and caused the reset.
        reason: ResetCause,
    },

    /// Processing of the block is over.
    ///
    /// There might be more blocks remaining. Call [`OptimisticSync::process_one`] again.
    NewBest {
        /// The state machine.
        /// The [`OptimisticSync::process_one`] method takes ownership of the
        /// [`OptimisticSync`]. This field yields it back.
        sync: OptimisticSync<TRq, TSrc, TBl>,

        new_best_number: u64,
        new_best_hash: [u8; 32],
    },

    /// Loading a storage value of the finalized block is required in order to continue.
    FinalizedStorageGet(StorageGet<TRq, TSrc, TBl>),

    /// Fetching the list of keys of the finalized block with a given prefix is required in order
    /// to continue.
    FinalizedStoragePrefixKeys(StoragePrefixKeys<TRq, TSrc, TBl>),

    /// Fetching the key of the finalized block storage that follows a given one is required in
    /// order to continue.
    FinalizedStorageNextKey(StorageNextKey<TRq, TSrc, TBl>),
}

enum Inner<TBl> {
    Step1(blocks_tree::BodyVerifyStep1<Block<TBl>>),
    Step2(blocks_tree::BodyVerifyStep2<Block<TBl>>),
}

struct BlockVerificationShared<TRq, TSrc, TBl> {
    /// See [`OptimisticSync::inner`].
    inner: OptimisticSyncInner<TRq, TSrc, TBl>,
    /// Body of the block being verified.
    block_body: Vec<Vec<u8>>,
    /// User data of the block being verified.
    block_user_data: Option<TBl>,
    /// Source the block has been downloaded from. Might be obsolete.
    source_id: SourceId,
}

impl<TRq, TSrc, TBl> BlockVerification<TRq, TSrc, TBl> {
    fn from(mut inner: Inner<TBl>, mut shared: BlockVerificationShared<TRq, TSrc, TBl>) -> Self {
        // This loop drives the process of the verification.
        // `inner` is updated at each iteration until a state that cannot be resolved internally
        // is found.
        'verif_steps: loop {
            match inner {
                Inner::Step1(blocks_tree::BodyVerifyStep1::ParentRuntimeRequired(req)) => {
                    // The verification process is asking for a Wasm virtual machine containing
                    // the parent block's runtime.
                    //
                    // Since virtual machines are expensive to create, a re-usable virtual machine
                    // is maintained for the best block.
                    //
                    // The code below extracts that re-usable virtual machine with the intention
                    // to store it back after the verification is over.
                    let parent_runtime = match shared.inner.best_runtime.take() {
                        Some(r) => r,
                        None => shared.inner.finalized_runtime.take().unwrap(),
                    };

                    inner = Inner::Step2(req.resume(
                        parent_runtime,
                        shared.block_body.iter(),
                        shared.inner.top_trie_root_calculation_cache.take(),
                    ));
                }

                Inner::Step2(blocks_tree::BodyVerifyStep2::Finished {
                    storage_top_trie_changes,
                    offchain_storage_changes,
                    top_trie_root_calculation_cache,
                    parent_runtime,
                    new_runtime,
                    insert,
                }) => {
                    // Successfully verified block!

                    debug_assert_eq!(
                        new_runtime.is_some(),
                        storage_top_trie_changes.contains_key(&b":code"[..])
                            || storage_top_trie_changes.contains_key(&b":heappages"[..])
                    );

                    // Before the verification, we extracted the runtime either from
                    // `finalized_runtime` or `best_runtime`.
                    if shared.inner.finalized_runtime.is_some() {
                        // If `finalized_runtime` is still `Some` now, that means we have
                        // extracted from `best_runtime`.
                        shared.inner.best_runtime = if let Some(new_runtime) = new_runtime {
                            Some(new_runtime)
                        } else {
                            Some(parent_runtime)
                        };
                    } else {
                        shared.inner.finalized_runtime = Some(parent_runtime);

                        debug_assert!(shared.inner.best_runtime.is_none());
                        if let Some(new_runtime) = new_runtime {
                            shared.inner.best_runtime = Some(new_runtime);
                        }
                    }

                    shared.inner.top_trie_root_calculation_cache =
                        Some(top_trie_root_calculation_cache);
                    for (key, value) in &storage_top_trie_changes {
                        shared
                            .inner
                            .best_to_finalized_storage_diff
                            .insert(key.clone(), value.clone());
                    }

                    let chain = {
                        let header = insert.header().into();
                        insert.insert(Block {
                            header,
                            justification: None, // TODO: /!\
                            user_data: shared.block_user_data.take().unwrap(),
                            full: Some(BlockFull {
                                body: mem::take(&mut shared.block_body),
                                storage_top_trie_changes,
                                offchain_storage_changes,
                            }),
                        })
                    };

                    let new_best_hash = chain.best_block_hash();
                    let new_best_number = chain.best_block_header().number;
                    break BlockVerification::NewBest {
                        sync: OptimisticSync {
                            chain,
                            inner: shared.inner,
                        },
                        new_best_hash,
                        new_best_number,
                    };
                }

                Inner::Step2(blocks_tree::BodyVerifyStep2::StorageGet(req)) => {
                    // The underlying verification process is asking for a storage entry in the
                    // parent block.
                    //
                    // The [`OptimisticSync`] stores the difference between the best block's
                    // storage and the finalized block's storage.
                    // As such, the requested value is either found in one of this diff, in which
                    // case it can be returned immediately to continue the verification, or in
                    // the finalized block, in which case the user needs to be queried.
                    if let Some(value) = shared
                        .inner
                        .best_to_finalized_storage_diff
                        .get(&req.key_as_vec())
                    {
                        inner = Inner::Step2(
                            req.inject_value(value.as_ref().map(|v| iter::once(&v[..]))),
                        );
                        continue 'verif_steps;
                    }

                    // The value hasn't been found in any of the diffs, meaning that the storage
                    // value of the parent is the same as the one of the finalized block. The
                    // user needs to be queried.
                    break BlockVerification::FinalizedStorageGet(StorageGet {
                        inner: req,
                        shared,
                    });
                }

                Inner::Step2(blocks_tree::BodyVerifyStep2::StorageNextKey(req)) => {
                    // The underlying verification process is asking for the key that follows
                    // the requested one.
                    break BlockVerification::FinalizedStorageNextKey(StorageNextKey {
                        inner: req,
                        shared,
                        key_overwrite: None,
                    });
                }

                Inner::Step2(blocks_tree::BodyVerifyStep2::StoragePrefixKeys(req)) => {
                    // The underlying verification process is asking for all the keys that start
                    // with a certain prefix.
                    // The first step is to ask the user for that information when it comes to
                    // the finalized block.
                    break BlockVerification::FinalizedStoragePrefixKeys(StoragePrefixKeys {
                        inner: req,
                        shared,
                    });
                }

                Inner::Step2(blocks_tree::BodyVerifyStep2::RuntimeCompilation(c)) => {
                    // The underlying verification process requires compiling a runtime code.
                    inner = Inner::Step2(c.build());
                    continue 'verif_steps;
                }

                // The three variants below correspond to problems during the verification.
                //
                // When that happens:
                //
                // - A `BlockVerification::Reset` event is emitted.
                // - `cancelling_requests` is set to true in order to cancel all ongoing requests.
                // - `chain` is recreated using `finalized_chain_information`.
                //
                Inner::Step1(blocks_tree::BodyVerifyStep1::InvalidHeader(old_chain, error)) => {
                    if let Some(source) = shared.inner.sources.get_mut(&shared.source_id) {
                        source.banned = true;
                    }

                    // If all sources are banned, unban them.
                    if shared.inner.sources.iter().all(|(_, s)| s.banned) {
                        for src in shared.inner.sources.values_mut() {
                            src.banned = false;
                        }
                    }

                    let chain = blocks_tree::NonFinalizedTree::new(
                        shared.inner.finalized_chain_information.clone(),
                    );
                    let inner = OptimisticSyncInner {
                        best_to_finalized_storage_diff: Default::default(),
                        best_runtime: None,
                        top_trie_root_calculation_cache: None,
                        ..shared.inner.with_requests_obsoleted(&chain)
                    };

                    break BlockVerification::Reset {
                        previous_best_height: old_chain.best_block_header().number,
                        sync: OptimisticSync { chain, inner },
                        reason: ResetCause::InvalidHeader(error),
                    };
                }
                Inner::Step1(blocks_tree::BodyVerifyStep1::Duplicate(old_chain))
                | Inner::Step1(blocks_tree::BodyVerifyStep1::BadParent {
                    chain: old_chain, ..
                }) => {
                    if let Some(source) = shared.inner.sources.get_mut(&shared.source_id) {
                        source.banned = true;
                    }
                    // If all sources are banned, unban them.
                    if shared.inner.sources.iter().all(|(_, s)| s.banned) {
                        for src in shared.inner.sources.values_mut() {
                            src.banned = false;
                        }
                    }

                    let chain = blocks_tree::NonFinalizedTree::new(
                        shared.inner.finalized_chain_information.clone(),
                    );
                    let inner = OptimisticSyncInner {
                        best_to_finalized_storage_diff: Default::default(),
                        best_runtime: None,
                        top_trie_root_calculation_cache: None,
                        ..shared.inner.with_requests_obsoleted(&chain)
                    };

                    break BlockVerification::Reset {
                        previous_best_height: old_chain.best_block_header().number,
                        sync: OptimisticSync { chain, inner },
                        reason: ResetCause::NonCanonical,
                    };
                }
                Inner::Step2(blocks_tree::BodyVerifyStep2::Error {
                    chain: old_chain,
                    error,
                    parent_runtime,
                }) => {
                    if shared.inner.finalized_runtime.is_none() {
                        shared.inner.finalized_runtime = Some(parent_runtime);
                    }
                    if let Some(source) = shared.inner.sources.get_mut(&shared.source_id) {
                        source.banned = true;
                    }
                    // If all sources are banned, unban them.
                    if shared.inner.sources.iter().all(|(_, s)| s.banned) {
                        for src in shared.inner.sources.values_mut() {
                            src.banned = false;
                        }
                    }

                    let chain = blocks_tree::NonFinalizedTree::new(
                        shared.inner.finalized_chain_information.clone(),
                    );
                    let inner = OptimisticSyncInner {
                        best_to_finalized_storage_diff: Default::default(),
                        best_runtime: None,
                        top_trie_root_calculation_cache: None,
                        ..shared.inner.with_requests_obsoleted(&chain)
                    };

                    break BlockVerification::Reset {
                        previous_best_height: old_chain.best_block_header().number,
                        sync: OptimisticSync { chain, inner },
                        reason: ResetCause::HeaderBodyError(error),
                    };
                }
            }
        }
    }
}

/// Start the processing of a justification verification.
pub struct JustificationVerify<TRq, TSrc, TBl> {
    inner: OptimisticSyncInner<TRq, TSrc, TBl>,
    chain: blocks_tree::NonFinalizedTree<Block<TBl>>,
}

impl<TRq, TSrc, TBl> JustificationVerify<TRq, TSrc, TBl> {
    /// Verify the justification.
    pub fn perform(
        mut self,
    ) -> (
        OptimisticSync<TRq, TSrc, TBl>,
        JustificationVerification<TBl>,
    ) {
        let (justification, source_id) = self.inner.pending_encoded_justification.take().unwrap();

        let mut apply = match self.chain.verify_justification(&justification) {
            Ok(a) => a,
            Err(error) => {
                if let Some(source) = self.inner.sources.get_mut(&source_id) {
                    source.banned = true;
                }

                // If all sources are banned, unban them.
                if self.inner.sources.iter().all(|(_, s)| s.banned) {
                    for src in self.inner.sources.values_mut() {
                        src.banned = false;
                    }
                }

                let chain = blocks_tree::NonFinalizedTree::new(
                    self.inner.finalized_chain_information.clone(),
                );
                let inner = OptimisticSyncInner {
                    best_to_finalized_storage_diff: Default::default(),
                    best_runtime: None,
                    top_trie_root_calculation_cache: None,
                    ..self.inner.with_requests_obsoleted(&chain)
                };

                let previous_best_height = chain.best_block_header().number;
                return (
                    OptimisticSync { chain, inner },
                    JustificationVerification::Reset {
                        previous_best_height,
                        error,
                    },
                );
            }
        };

        assert!(apply.is_current_best_block()); // TODO: can legitimately fail in case of malicious node

        // As part of the finalization, put the justification in the chain that's
        // going to be reported to the user.
        apply.block_user_data().justification = Some(justification);

        // Applying the finalization and iterating over the now-finalized block.
        // Since `apply()` returns the blocks in decreasing block number, we have
        // to revert the list in order to get them in increasing block number
        // instead.
        // While this intermediary buffering is an overhead, the increased code
        // complexity to avoid it is probably not worth the speed gain.
        let finalized_blocks = apply
            .apply()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        // Since the best block is now the finalized block, reset the storage
        // diff.
        debug_assert!(self.chain.is_empty());
        self.inner.best_to_finalized_storage_diff.clear();

        if let Some(runtime) = self.inner.best_runtime.take() {
            self.inner.finalized_runtime = Some(runtime);
        }

        self.inner.finalized_chain_information.chain_information =
            self.chain.as_chain_information().into();

        (
            OptimisticSync {
                chain: self.chain,
                inner: self.inner,
            },
            JustificationVerification::Finalized { finalized_blocks },
        )
    }
}

/// Outcome of the verification of a justification.
pub enum JustificationVerification<TBl> {
    /// An issue happened when verifying the justification, resulting in resetting the chain to
    /// the latest finalized block.
    Reset {
        /// Height of the best block before the reset.
        previous_best_height: u64,

        /// Problem that happened and caused the reset.
        error: blocks_tree::JustificationVerifyError,
    },

    /// Processing of the justification is over. The best block has now been finalized.
    ///
    /// There might be more blocks remaining. Call [`OptimisticSync::process_one`] again.
    Finalized {
        /// Blocks that have been finalized.
        finalized_blocks: Vec<Block<TBl>>,
    },
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet<TRq, TSrc, TBl> {
    inner: blocks_tree::StorageGet<Block<TBl>>,
    shared: BlockVerificationShared<TRq, TSrc, TBl>,
}

impl<TRq, TSrc, TBl> StorageGet<TRq, TSrc, TBl> {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key(&'_ self) -> impl Iterator<Item = impl AsRef<[u8]> + '_> + '_ {
        self.inner.key()
    }

    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    ///
    /// This method is a shortcut for calling `key` and concatenating the returned slices.
    pub fn key_as_vec(&self) -> Vec<u8> {
        self.inner.key_as_vec()
    }

    /// Injects the corresponding storage value.
    pub fn inject_value(self, value: Option<&[u8]>) -> BlockVerification<TRq, TSrc, TBl> {
        let inner = self.inner.inject_value(value.map(iter::once));
        BlockVerification::from(Inner::Step2(inner), self.shared)
    }
}

/// Fetching the list of keys with a given prefix is required in order to continue.
#[must_use]
pub struct StoragePrefixKeys<TRq, TSrc, TBl> {
    inner: blocks_tree::StoragePrefixKeys<Block<TBl>>,
    shared: BlockVerificationShared<TRq, TSrc, TBl>,
}

impl<TRq, TSrc, TBl> StoragePrefixKeys<TRq, TSrc, TBl> {
    /// Returns the prefix whose keys to load.
    pub fn prefix(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner.prefix()
    }

    /// Injects the list of keys ordered lexicographically.
    pub fn inject_keys_ordered(
        self,
        keys: impl Iterator<Item = impl AsRef<[u8]>>,
    ) -> BlockVerification<TRq, TSrc, TBl> {
        let mut keys = keys
            .map(|k| k.as_ref().to_owned())
            .collect::<HashSet<_, fnv::FnvBuildHasher>>();

        {
            let prefix = self.inner.prefix();
            for (k, v) in self
                .shared
                .inner
                .best_to_finalized_storage_diff
                .range(prefix.as_ref().to_owned()..)
                .take_while(|(k, _)| k.starts_with(prefix.as_ref()))
            {
                if v.is_some() {
                    keys.insert(k.clone());
                } else {
                    keys.remove(k);
                }
            }
        }

        let inner = self.inner.inject_keys_ordered(keys.iter());
        BlockVerification::from(Inner::Step2(inner), self.shared)
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct StorageNextKey<TRq, TSrc, TBl> {
    inner: blocks_tree::StorageNextKey<Block<TBl>>,
    shared: BlockVerificationShared<TRq, TSrc, TBl>,

    /// If `Some`, ask for the key inside of this field rather than the one of `inner`. Used in
    /// corner-case situations where the key provided by the user has been erased from storage.
    key_overwrite: Option<Vec<u8>>,
}

impl<TRq, TSrc, TBl> StorageNextKey<TRq, TSrc, TBl> {
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        if let Some(key_overwrite) = &self.key_overwrite {
            either::Left(key_overwrite)
        } else {
            either::Right(self.inner.key())
        }
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl AsRef<[u8]>>) -> BlockVerification<TRq, TSrc, TBl> {
        let key = key.as_ref().map(|k| k.as_ref());

        // The key provided by the user as parameter is the next key in the storage of the
        // finalized block.
        // `best_to_finalized_storage_diff` needs to be taken into account in order to provide
        // the next key in the best block instead.

        let inner_key = self.inner.key();
        let requested_key = if let Some(key_overwrite) = &self.key_overwrite {
            key_overwrite
        } else {
            inner_key.as_ref()
        };

        if let Some(key) = key {
            assert!(key > requested_key);
        }

        let in_diff = self
            .shared
            .inner
            .best_to_finalized_storage_diff
            .range(requested_key.to_vec()..) // TODO: don't use to_vec()
            .map(|(k, v)| (k, v.is_some()))
            .find(|(k, _)| &***k > requested_key);

        let outcome = match (key, in_diff) {
            (Some(a), Some((b, true))) if a <= &b[..] => Some(a),
            (Some(a), Some((b, false))) if a < &b[..] => Some(a),
            (Some(a), Some((b, false))) => {
                debug_assert!(a >= &b[..]);
                debug_assert_ne!(&b[..], requested_key);

                // The next key according to the finalized block storage has been erased since
                // then. It is necessary to ask the user again, this time for the key after the
                // one that has been erased.
                // This `clone()` is necessary, as `b` borrows from
                // `self.shared.best_to_finalized_storage_diff`.
                let key_overwrite = Some(b.clone());
                drop(inner_key); // Solves borrowing errors.
                return BlockVerification::FinalizedStorageNextKey(StorageNextKey {
                    inner: self.inner,
                    shared: self.shared,
                    key_overwrite,
                });
            }
            (Some(a), Some((b, true))) => {
                debug_assert!(a >= &b[..]);
                Some(&b[..])
            }

            (Some(a), None) => Some(a),
            (None, Some((b, true))) => Some(&b[..]),
            (None, Some((b, false))) => {
                debug_assert!(&b[..] > requested_key);
                self.shared
                    .inner
                    .best_to_finalized_storage_diff
                    .range(b.clone()..) // TODO: don't clone?
                    .filter(|(_, value)| value.is_some())
                    .map(|(k, _)| &k[..])
                    .next()
            }
            (None, None) => None,
        };

        drop(inner_key); // Solves borrowing errors.
        let inner = self.inner.inject_key(outcome);
        BlockVerification::from(Inner::Step2(inner), self.shared)
    }
}

/// Request that should be emitted towards a certain source.
#[derive(Debug)]
pub struct RequestDetail {
    /// Source where to request blocks from.
    pub source_id: SourceId,
    /// Height of the block to request.
    pub block_height: NonZeroU64,
    /// Number of blocks to request. This might be equal to `u32::max_value()` in case no upper
    /// bound is required. The API user is responsible for clamping this value to a reasonable
    /// limit.
    pub num_blocks: NonZeroU32,
}

pub enum FinishRequestOutcome<'a, TSrc> {
    Obsolete,
    Queued,
    SourcePunished(&'a mut TSrc),
}

/// Reason why a request has failed.
pub enum RequestFail {
    /// Requested blocks aren't available from this source.
    BlocksUnavailable,
}

/// Iterator that drains requests after a source has been removed.
pub struct RequestsDrain<'a, TRq, TBl> {
    iter: verification_queue::SourceDrain<'a, TRq, TBl>,
}

impl<'a, TRq, TBl> Iterator for RequestsDrain<'a, TRq, TBl> {
    type Item = (RequestId, TRq);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a, TRq, TBl> fmt::Debug for RequestsDrain<'a, TRq, TBl> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("RequestsDrain").finish()
    }
}

impl<'a, TRq, TBl> Drop for RequestsDrain<'a, TRq, TBl> {
    fn drop(&mut self) {
        // Drain all remaining elements even if the iterator is dropped eagerly.
        // This is the reason why a custom iterator type is needed.
        for _ in self {}
    }
}

/// Problem that happened and caused the reset.
#[derive(Debug, derive_more::Display)]
pub enum ResetCause {
    /// Error while decoding a header.
    InvalidHeader(header::Error),
    /// Error while verifying a header.
    HeaderError(blocks_tree::HeaderVerifyError),
    /// Error while verifying a header and body.
    HeaderBodyError(blocks_tree::BodyVerifyError),
    /// Received block isn't a child of the current best block.
    NonCanonical,
}

/// Output of [`OptimisticSync::disassemble`].
#[derive(Debug)]
pub struct Disassemble<TRq, TSrc> {
    /// Information about the latest finalized block and its ancestors.
    pub chain_information: chain_information::ValidChainInformation,

    /// List of sources that were within the state machine.
    pub sources: Vec<DisassembleSource<TSrc>>,

    /// List of the requests that were active.
    pub requests: Vec<(RequestId, TRq)>,
    // TODO: add non-finalized blocks?
}

/// See [`Disassemble::sources`].
#[derive(Debug)]
pub struct DisassembleSource<TSrc> {
    /// Identifier that the source had.
    pub id: SourceId,

    /// Opaque value passed to [`OptimisticSync::add_source`].
    pub user_data: TSrc,

    /// Best block that the source has reported having.
    pub best_block_number: u64,
}
