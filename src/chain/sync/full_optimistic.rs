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
//! The [`OptimisticFullSync`] struct holds a list of sources, a list of pending block requests,
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

use super::super::{blocks_tree, chain_information};
use crate::{
    executor::{host, vm},
    header,
    trie::calculate_root,
};

use alloc::{
    collections::{BTreeMap, VecDeque},
    vec,
    vec::Vec,
};
use core::{
    cmp,
    convert::TryFrom as _,
    fmt, iter,
    marker::PhantomData,
    mem,
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};
use hashbrown::{HashMap, HashSet};
use rand::{seq::IteratorRandom as _, SeedableRng as _};

/// Configuration for the [`OptimisticFullSync`].
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

    /// Maximum number of blocks returned by a response.
    ///
    /// > **Note**: If blocks are requested from the network, this should match the network
    /// >           protocol enforced limit.
    pub blocks_request_granularity: NonZeroU32,

    /// Number of blocks to download ahead of the best block.
    ///
    /// Whenever the latest best block is updated, the state machine will start block
    /// requests for the block `best_block_height + download_ahead_blocks` and all its
    /// ancestors. Considering that requesting blocks has some latency, downloading blocks ahead
    /// of time ensures that verification isn't blocked waiting for a request to be finished.
    ///
    /// The ideal value here depends on the speed of blocks verification speed and latency of
    /// block requests.
    pub download_ahead_blocks: u32,

    /// Seed used by the PRNG (Pseudo-Random Number Generator) that selects which source to start
    /// requests with.
    ///
    /// You are encouraged to use something like `rand::random()` to fill this field, except in
    /// situations where determinism/reproducibility is desired.
    pub source_selection_randomness_seed: u64,

    /// If true, the block bodies and storage are also synchronized.
    pub full: bool,
}

/// Identifier for an ongoing request in the [`OptimisticFullSync`].
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RequestId(u64);

/// Identifier for a source in the [`OptimisticFullSync`].
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SourceId(usize);

/// Optimistic headers-only syncing.
pub struct OptimisticFullSync<TRq, TSrc> {
    /// Data structure containing the blocks.
    ///
    /// The user data, [`Block`], isn't used internally but stores information later reported
    /// to the user.
    chain: blocks_tree::NonFinalizedTree<Block>,

    /// Extra fields. In a separate structure in order to be moved around.
    inner: OptimisticFullSyncInner<TRq, TSrc>,
}

/// Extra fields. In a separate structure in order to be moved around.
struct OptimisticFullSyncInner<TRq, TSrc> {
    /// Configuration for the actual finalized block of the chain.
    /// Used if the `chain` field needs to be recreated.
    finalized_chain_information: blocks_tree::Config,

    /// Changes in the storage of the best block compared to the finalized block.
    /// The `BTreeMap`'s keys are storage keys, and its values are new values or `None` if the
    /// value has been erased from the storage.
    best_to_finalized_storage_diff: BTreeMap<Vec<u8>, Option<Vec<u8>>>,

    /// Compiled runtime code of the best block block.
    /// This field is a cache. As such, it will stay at `None` until this value has been needed
    /// for the first time.
    runtime_code_cache: Option<host::HostVmPrototype>,

    /// Cache of calculation for the storage trie of the best block.
    /// Providing this value when verifying a block considerably speeds up the verification.
    top_trie_root_calculation_cache: Option<calculate_root::CalculationCache>,

    /// See [`Config::full`].
    full: bool,

    /// See [`Config::blocks_request_granularity`].
    blocks_request_granularity: NonZeroU32,

    /// See [`Config::download_ahead_blocks`].
    download_ahead_blocks: u32,

    /// List of sources of blocks.
    sources: slab::Slab<Source<TSrc>>,

    /// If true, the next step of the state machine is to cancel requests in progress, as they
    /// are no longer valid.
    cancelling_requests: bool,

    /// Queue of block requests, either waiting to be started, in progress, or completed.
    verification_queue: VecDeque<VerificationQueueEntry<TRq>>,

    /// Identifier to assign to the next request.
    next_request_id: RequestId,

    /// PRNG used to select the source to start a query with.
    source_selection_rng: rand_chacha::ChaCha8Rng,
}

struct Source<TSrc> {
    user_data: TSrc,
    banned: bool, // TODO: ban shouldn't be held forever
}

struct VerificationQueueEntry<TRq> {
    block_height: NonZeroU64,
    ty: VerificationQueueEntryTy<TRq>,
}

enum VerificationQueueEntryTy<TRq> {
    Missing,
    Requested {
        id: RequestId,
        /// User-chosen data for this request.
        user_data: TRq,
        // Index of this source within [`OptimisticFullSyncInner::sources`].
        source: usize,
    },
    Queued(VecDeque<RequestSuccessBlock>),
}

// TODO: doc
pub struct Block {
    /// Header of the block.
    pub header: header::Header,

    /// List of SCALE-encoded extrinsics that form the block's body.
    pub body: Vec<Vec<u8>>,

    /// SCALE-encoded justification of this block, if any.
    pub justification: Option<Vec<u8>>,

    /// Changes to the storage made by this block compared to its parent.
    pub storage_top_trie_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,

    /// List of changes to the offchain storage that this block performs.
    pub offchain_storage_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
}

impl<TRq, TSrc> OptimisticFullSync<TRq, TSrc> {
    /// Builds a new [`OptimisticFullSync`].
    pub fn new(config: Config) -> Self {
        let blocks_tree_config = blocks_tree::Config {
            chain_information: config.chain_information,
            blocks_capacity: usize::try_from(config.blocks_request_granularity.get())
                .unwrap_or(usize::max_value()),
        };

        let chain = blocks_tree::NonFinalizedTree::new(blocks_tree_config.clone());

        OptimisticFullSync {
            chain,
            inner: OptimisticFullSyncInner {
                finalized_chain_information: blocks_tree_config,
                best_to_finalized_storage_diff: BTreeMap::new(),
                runtime_code_cache: None,
                top_trie_root_calculation_cache: None,
                full: config.full,
                sources: slab::Slab::with_capacity(config.sources_capacity),
                cancelling_requests: false,
                verification_queue: VecDeque::with_capacity(
                    usize::try_from(
                        config.download_ahead_blocks / config.blocks_request_granularity.get(),
                    )
                    .unwrap()
                    .saturating_add(1),
                ),
                blocks_request_granularity: config.blocks_request_granularity,
                download_ahead_blocks: config.download_ahead_blocks,
                next_request_id: RequestId(0),
                source_selection_rng: rand_chacha::ChaCha8Rng::seed_from_u64(
                    config.source_selection_randomness_seed,
                ),
            },
        }
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct corresponding to the current
    /// latest finalized block. Can later be used to reconstruct a chain.
    pub fn as_chain_information(&self) -> chain_information::ChainInformationRef {
        self.chain.as_chain_information()
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

    /// Inform the [`OptimisticFullSync`] of a new potential source of blocks.
    // TODO: pass best block
    pub fn add_source(&mut self, source: TSrc) -> SourceId {
        SourceId(self.inner.sources.insert(Source {
            user_data: source,
            banned: false,
        }))
    }

    /// Inform the [`OptimisticFullSync`] that a source of blocks is no longer available.
    ///
    /// This automatically cancels all the requests that have been emitted for this source.
    /// This list of requests is returned as part of this function.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn remove_source<'a>(
        &'a mut self,
        source: SourceId,
    ) -> (TSrc, impl Iterator<Item = (RequestId, TRq)> + 'a) {
        let src_user_data = self.inner.sources.remove(source.0).user_data;
        let drain = RequestsDrain {
            iter: self.inner.verification_queue.iter_mut().fuse(),
            source_index: source.0,
        };
        (src_user_data, drain)
    }

    /// Returns an iterator that extracts all requests that need to be started and requests that
    /// need to be cancelled.
    pub fn next_request_action(&mut self) -> Option<RequestAction<TRq, TSrc>> {
        if self.inner.cancelling_requests {
            while let Some(queue_elem) = self.inner.verification_queue.pop_back() {
                if let VerificationQueueEntryTy::Requested {
                    id,
                    source,
                    user_data,
                } = queue_elem.ty
                {
                    return Some(RequestAction::Cancel {
                        request_id: id,
                        user_data,
                        source_id: SourceId(source),
                        source: &mut self.inner.sources[source].user_data,
                    });
                }
            }

            self.inner.cancelling_requests = false;
        }

        while self.inner.verification_queue.back().map_or(true, |rq| {
            rq.block_height.get() + u64::from(self.inner.blocks_request_granularity.get())
                < self
                    .chain
                    .best_block_header()
                    .number
                    .checked_add(u64::from(self.inner.download_ahead_blocks))
                    .unwrap()
        }) {
            let block_height = self
                .inner
                .verification_queue
                .back()
                .map(|rq| {
                    rq.block_height.get() + u64::from(self.inner.blocks_request_granularity.get())
                })
                .unwrap_or(self.chain.best_block_header().number + 1);
            self.inner
                .verification_queue
                .push_back(VerificationQueueEntry {
                    block_height: NonZeroU64::new(block_height).unwrap(),
                    ty: VerificationQueueEntryTy::Missing,
                });
        }

        if let Some((missing_pos, _)) = self
            .inner
            .verification_queue
            .iter()
            .enumerate()
            .find(|(_, e)| matches!(e.ty, VerificationQueueEntryTy::Missing))
        {
            let source = self
                .inner
                .sources
                .iter()
                .filter(|(_, src)| !src.banned)
                .choose(&mut self.inner.source_selection_rng)?
                .0;

            let block_height = self.inner.verification_queue[missing_pos].block_height;

            let num_blocks = if let Some(next) = self.inner.verification_queue.get(missing_pos + 1)
            {
                NonZeroU32::new(
                    u32::try_from(cmp::min(
                        u64::from(self.inner.blocks_request_granularity.get()),
                        next.block_height
                            .get()
                            .checked_sub(block_height.get())
                            .unwrap(),
                    ))
                    .unwrap(),
                )
                .unwrap()
            } else {
                self.inner.blocks_request_granularity
            };

            return Some(RequestAction::Start {
                source_id: SourceId(source),
                source: &mut self.inner.sources[source].user_data,
                block_height,
                num_blocks,
                start: Start {
                    verification_queue: &mut self.inner.verification_queue,
                    missing_pos,
                    next_request_id: &mut self.inner.next_request_id,
                    source,
                    marker: PhantomData,
                },
            });
        }

        None
    }

    /// Update the [`OptimisticFullSync`] with the outcome of a request.
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
        outcome: Result<impl Iterator<Item = RequestSuccessBlock>, RequestFail>,
    ) -> (TRq, FinishRequestOutcome<TSrc>) {
        // TODO: what if cancelling requests?

        let (verification_queue_entry, source_id) = self
            .inner
            .verification_queue
            .iter()
            .enumerate()
            .filter_map(|(pos, entry)| match entry.ty {
                VerificationQueueEntryTy::Requested { id, source, .. } if id == request_id => {
                    Some((pos, source))
                }
                _ => None,
            })
            .next()
            .expect("invalid RequestId");

        let blocks = match outcome {
            Ok(blocks) => blocks.collect(),
            Err(_) => {
                let user_data = match mem::replace(
                    &mut self.inner.verification_queue[verification_queue_entry].ty,
                    VerificationQueueEntryTy::Missing,
                ) {
                    VerificationQueueEntryTy::Requested { user_data, .. } => user_data,
                    _ => unreachable!(),
                };

                // TODO: we don't actually punish the source

                return (
                    user_data,
                    FinishRequestOutcome::SourcePunished(
                        &mut self.inner.sources[source_id].user_data,
                    ),
                );
            }
        };

        // TODO: handle if blocks.len() < expected_number_of_blocks

        let user_data = match mem::replace(
            &mut self.inner.verification_queue[verification_queue_entry].ty,
            VerificationQueueEntryTy::Queued(blocks),
        ) {
            VerificationQueueEntryTy::Requested { user_data, .. } => user_data,
            _ => unreachable!(),
        };

        (user_data, FinishRequestOutcome::Queued)
    }

    /// Process the next block in the queue of verification.
    ///
    /// This method takes ownership of the [`OptimisticFullSync`] and starts a verification
    /// process. The [`OptimisticFullSync`] is yielded back at the end of this process.
    ///
    /// Must be passed the current UNIX time in order to verify that the block doesn't pretend to
    /// come from the future.
    pub fn process_one(mut self, now_from_unix_epoch: Duration) -> ProcessOne<TRq, TSrc> {
        if self.inner.cancelling_requests {
            return ProcessOne::Idle { sync: self };
        }

        // Extract the block to process next.
        let block = loop {
            match &mut self.inner.verification_queue.get_mut(0).map(|b| &mut b.ty) {
                Some(VerificationQueueEntryTy::Queued(blocks)) => match blocks.pop_front() {
                    Some(b) => break b,
                    None => {
                        self.inner.verification_queue.pop_front().unwrap();
                    }
                },
                _ => return ProcessOne::Idle { sync: self },
            }
        };

        let expected_block_height = self.inner.verification_queue[0].block_height.get();

        if self.inner.full {
            ProcessOne::from(
                Inner::Step1(self.chain.verify_body(
                    block.scale_encoded_header,
                    now_from_unix_epoch,
                    block.scale_encoded_extrinsics.into_iter(),
                )),
                ProcessOneShared {
                    pending_encoded_justification: block.scale_encoded_justification,
                    expected_block_height,
                    inner: self.inner,
                    now_from_unix_epoch,
                },
            )
        } else {
            match self
                .chain
                .verify_header(block.scale_encoded_header, now_from_unix_epoch)
            {
                Ok(blocks_tree::HeaderVerifySuccess::Duplicate) => todo!(),
                Ok(blocks_tree::HeaderVerifySuccess::Insert {
                    insert,
                    ..  // TODO: check is_new_best?
                }) => {
                    let header = insert.header().into();
                    // TODO: half of the fields of `Block` are irrelevant for headers-only
                    insert.insert(Block {
                        header,
                        body: Vec::new(),
                        justification: block.scale_encoded_justification.clone(),
                        storage_top_trie_changes: Default::default(),
                        offchain_storage_changes: Default::default(),
                    });
                    ProcessOne::from(
                        Inner::JustificationVerif(self.chain),
                        ProcessOneShared {
                            pending_encoded_justification: block.scale_encoded_justification,
                            expected_block_height,
                            inner: self.inner,
                            now_from_unix_epoch,
                        },
                    )
                }
                Err(err) => {
                    self.inner.cancelling_requests = true;
                    ProcessOne::Reset {
                        sync: self,
                        reason: ResetCause::HeaderError(err),
                    }
                }
            }
        }
    }
}

pub struct RequestSuccessBlock {
    pub scale_encoded_header: Vec<u8>,
    pub scale_encoded_justification: Option<Vec<u8>>,
    pub scale_encoded_extrinsics: Vec<Vec<u8>>,
}

/// State of the processing of blocks.
pub enum ProcessOne<TRq, TSrc> {
    /// No processing is necessary.
    ///
    /// Calling [`OptimisticFullSync::process_one`] again is unnecessary.
    Idle {
        /// The state machine.
        /// The [`OptimisticFullSync::process_one`] method takes ownership of the
        /// [`OptimisticFullSync`]. This field yields it back.
        sync: OptimisticFullSync<TRq, TSrc>,
    },

    /// An issue happened when verifying the block or its justification, resulting in resetting
    /// the chain to the latest finalized block.
    ///
    /// > **Note**: The latest finalized block might be a block imported during the same
    /// >           operation.
    Reset {
        /// The state machine.
        /// The [`OptimisticFullSync::process_one`] method takes ownership of the
        /// [`OptimisticFullSync`]. This field yields it back.
        sync: OptimisticFullSync<TRq, TSrc>,

        /// Problem that happened and caused the reset.
        reason: ResetCause,
    },

    /// Processing of the block is over.
    ///
    /// There might be more blocks remaining. Call [`OptimisticFullSync::process_one`] again.
    NewBest {
        /// The state machine.
        /// The [`OptimisticFullSync::process_one`] method takes ownership of the
        /// [`OptimisticFullSync`]. This field yields it back.
        sync: OptimisticFullSync<TRq, TSrc>,

        new_best_number: u64,
        new_best_hash: [u8; 32],
    },

    /// Processing of the block is over. The block has been finalized.
    ///
    /// There might be more blocks remaining. Call [`OptimisticFullSync::process_one`] again.
    Finalized {
        /// The state machine.
        /// The [`OptimisticFullSync::process_one`] method takes ownership of the
        /// [`OptimisticFullSync`]. This field yields it back.
        sync: OptimisticFullSync<TRq, TSrc>,

        /// Blocks that have been finalized. Includes the block that has just been verified.
        finalized_blocks: Vec<Block>,
    },

    /// Loading a storage value of the finalized block is required in order to continue.
    FinalizedStorageGet(StorageGet<TRq, TSrc>),

    /// Fetching the list of keys of the finalized block with a given prefix is required in order
    /// to continue.
    FinalizedStoragePrefixKeys(StoragePrefixKeys<TRq, TSrc>),

    /// Fetching the key of the finalized block storage that follows a given one is required in
    /// order to continue.
    FinalizedStorageNextKey(StorageNextKey<TRq, TSrc>),
}

enum Inner {
    Step1(blocks_tree::BodyVerifyStep1<Block, vec::IntoIter<Vec<u8>>>),
    Step2(blocks_tree::BodyVerifyStep2<Block>),
    JustificationVerif(blocks_tree::NonFinalizedTree<Block>),
}

struct ProcessOneShared<TRq, TSrc> {
    pending_encoded_justification: Option<Vec<u8>>,
    expected_block_height: u64,
    /// See [`OptimisticFullSync::inner`].
    inner: OptimisticFullSyncInner<TRq, TSrc>,
    now_from_unix_epoch: Duration,
}

impl<TRq, TSrc> ProcessOne<TRq, TSrc> {
    fn from(mut inner: Inner, mut shared: ProcessOneShared<TRq, TSrc>) -> Self {
        // This loop drives the process of the verification.
        // `inner` is updated at each iteration until a state that cannot be resolved internally
        // is found.
        'verif_steps: loop {
            match inner {
                Inner::Step1(blocks_tree::BodyVerifyStep1::InvalidHeader(chain, error)) => {
                    // TODO: DRY
                    println!("invalid header: {:?}", error); // TODO: remove

                    break ProcessOne::Reset {
                        sync: OptimisticFullSync {
                            inner: OptimisticFullSyncInner {
                                best_to_finalized_storage_diff: Default::default(),
                                runtime_code_cache: None,
                                top_trie_root_calculation_cache: None,
                                cancelling_requests: true,
                                ..shared.inner
                            },
                            chain,
                        },
                        reason: ResetCause::HeaderError(
                            blocks_tree::HeaderVerifyError::InvalidHeader(error),
                        ),
                    };
                }

                Inner::Step1(blocks_tree::BodyVerifyStep1::Duplicate(chain))
                | Inner::Step1(blocks_tree::BodyVerifyStep1::BadParent { chain, .. }) => {
                    // TODO: DRY
                    break ProcessOne::Reset {
                        sync: OptimisticFullSync {
                            inner: OptimisticFullSyncInner {
                                best_to_finalized_storage_diff: Default::default(),
                                runtime_code_cache: None,
                                top_trie_root_calculation_cache: None,
                                cancelling_requests: true,
                                ..shared.inner
                            },
                            chain,
                        },
                        reason: ResetCause::NonCanonical,
                    };
                }

                Inner::Step1(blocks_tree::BodyVerifyStep1::ParentRuntimeRequired(req)) => {
                    // The verification process is asking for a Wasm virtual machine containing
                    // the parent block's runtime.
                    //
                    // Since virtual machines are expensive to create, a re-usable virtual machine
                    // is maintained for the best block.
                    //
                    // The code below extracts that re-usable virtual machine with the intention
                    // to store it back after the verification is over.
                    let parent_runtime = match shared.inner.runtime_code_cache.take() {
                        Some(r) => r,
                        None => {
                            // TODO: simplify code below
                            match (
                                shared
                                    .inner
                                    .best_to_finalized_storage_diff
                                    .get(&b":code"[..]),
                                shared
                                    .inner
                                    .best_to_finalized_storage_diff
                                    .get(&b":heappages"[..]),
                            ) {
                                (Some(wasm_code), Some(heap_pages)) => {
                                    let wasm_code =
                                        wasm_code.as_ref().expect("no runtime code?!?!"); // TODO: what to do?
                                    let heap_pages = u64::from_le_bytes(
                                        <[u8; 8]>::try_from(&heap_pages.as_ref().unwrap()[..])
                                            .unwrap(), // TODO: don't unwrap
                                    );
                                    host::HostVmPrototype::new(
                                        &wasm_code,
                                        heap_pages,
                                        vm::ExecHint::CompileAheadOfTime,
                                    )
                                    .expect("invalid runtime code?!?!") // TODO: what to do?
                                }
                                (Some(wasm_code), None) => {
                                    return ProcessOne::FinalizedStorageGet(StorageGet {
                                        inner: StorageGetTarget::HeapPages(
                                            req,
                                            wasm_code.as_ref().unwrap().clone(),
                                        ), // TODO: don't unwrap
                                        shared,
                                    });
                                }
                                (None, Some(heap_pages)) => {
                                    let heap_pages = u64::from_le_bytes(
                                        <[u8; 8]>::try_from(&heap_pages.as_ref().unwrap()[..])
                                            .unwrap(), // TODO: don't unwrap
                                    );
                                    return ProcessOne::FinalizedStorageGet(StorageGet {
                                        inner: StorageGetTarget::Runtime(req, heap_pages), // TODO: don't unwrap
                                        shared,
                                    });
                                }
                                (None, None) => {
                                    // No cache has been found anywhere in the hierarchy.
                                    // The user needs to be asked for the storage entry containing the
                                    // runtime code.
                                    return ProcessOne::FinalizedStorageGet(StorageGet {
                                        inner: StorageGetTarget::HeapPagesAndRuntime(req),
                                        shared,
                                    });
                                }
                            }
                        }
                    };

                    inner = Inner::Step2(req.resume(
                        parent_runtime,
                        shared.inner.top_trie_root_calculation_cache.take(),
                    ));
                }

                Inner::Step2(blocks_tree::BodyVerifyStep2::Finished {
                    storage_top_trie_changes,
                    offchain_storage_changes,
                    top_trie_root_calculation_cache,
                    parent_runtime,
                    result: Ok(success),
                }) => {
                    // Successfully verified block!
                    // Inserting it into the chain and updated all the caches.
                    if !storage_top_trie_changes.contains_key(&b":code"[..])
                        && !storage_top_trie_changes.contains_key(&b":heappages"[..])
                    {
                        shared.inner.runtime_code_cache = Some(parent_runtime);
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
                        let header = success.header().into();
                        success.insert(Block {
                            header,
                            body: Vec::new(), // TODO: // FIXME: wrong! dummy!
                            // Set to `Some` below if the justification check success.
                            justification: None,
                            storage_top_trie_changes,
                            offchain_storage_changes,
                        })
                    };

                    inner = Inner::JustificationVerif(chain);
                }

                Inner::JustificationVerif(mut chain) => {
                    // `pending_encoded_justification` contains the justification (if any)
                    // corresponding to the block that has just been verified. Verifying the
                    // justification as well.
                    if let Some(justification) = shared.pending_encoded_justification.take() {
                        let mut apply = match chain.verify_justification(&justification) {
                            Ok(a) => a,
                            Err(_) => todo!(), // TODO:
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
                        debug_assert!(chain.is_empty());
                        shared.inner.best_to_finalized_storage_diff.clear();

                        break ProcessOne::Finalized {
                            sync: OptimisticFullSync {
                                chain,
                                inner: shared.inner,
                            },
                            finalized_blocks,
                        };
                    } else {
                        let new_best_hash = chain.best_block_hash();
                        let new_best_number = chain.best_block_header().number;
                        break ProcessOne::NewBest {
                            sync: OptimisticFullSync {
                                chain,
                                inner: shared.inner,
                            },
                            new_best_hash,
                            new_best_number,
                        };
                    }
                }

                Inner::Step2(blocks_tree::BodyVerifyStep2::Finished {
                    result: Err(err), ..
                }) => todo!("verif failure"),

                Inner::Step2(blocks_tree::BodyVerifyStep2::StorageGet(req)) => {
                    // The underlying verification process is asking for a storage entry in the
                    // parent block.
                    //
                    // The [`OptimisticFullSync`] stores the difference between the best block's
                    // storage and the finalized block's storage.
                    // As such, the requested value is either found in one of this diff, in which
                    // case it can be returned immediately to continue the verification, or in
                    // the finalized block, in which case the user needs to be queried.
                    if let Some(value) = shared
                        .inner
                        .best_to_finalized_storage_diff
                        .get(&req.key_as_vec())
                    {
                        inner = Inner::Step2(req.inject_value(value.as_ref().map(|v| &v[..])));
                        continue 'verif_steps;
                    }

                    // The value hasn't been found in any of the diffs, meaning that the storage
                    // value of the parent is the same as the one of the finalized block. The
                    // user needs to be queried.
                    break ProcessOne::FinalizedStorageGet(StorageGet {
                        inner: StorageGetTarget::Storage(req),
                        shared,
                    });
                }

                Inner::Step2(blocks_tree::BodyVerifyStep2::StorageNextKey(req)) => {
                    // The underlying verification process is asking for the key that follows
                    // the requested one.
                    break ProcessOne::FinalizedStorageNextKey(StorageNextKey {
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
                    break ProcessOne::FinalizedStoragePrefixKeys(StoragePrefixKeys {
                        inner: req,
                        shared,
                    });
                }
            }
        }
    }
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet<TRq, TBl> {
    inner: StorageGetTarget,
    shared: ProcessOneShared<TRq, TBl>,
}

enum StorageGetTarget {
    Storage(blocks_tree::StorageGet<Block>),
    HeapPagesAndRuntime(blocks_tree::BodyVerifyRuntimeRequired<Block, vec::IntoIter<Vec<u8>>>),
    Runtime(
        blocks_tree::BodyVerifyRuntimeRequired<Block, vec::IntoIter<Vec<u8>>>,
        u64,
    ),
    HeapPages(
        blocks_tree::BodyVerifyRuntimeRequired<Block, vec::IntoIter<Vec<u8>>>,
        Vec<u8>,
    ),
}

impl<TRq, TBl> StorageGet<TRq, TBl> {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key<'b>(&'b self) -> impl Iterator<Item = impl AsRef<[u8]> + 'b> + 'b {
        match &self.inner {
            StorageGetTarget::Storage(inner) => {
                either::Either::Left(inner.key().map(either::Either::Left))
            }
            StorageGetTarget::HeapPagesAndRuntime(_) | StorageGetTarget::HeapPages(_, _) => {
                either::Either::Right(iter::once(either::Either::Right(&b":heappages"[..])))
            }
            StorageGetTarget::Runtime(_, _) => {
                either::Either::Right(iter::once(either::Either::Right(&b":code"[..])))
            }
        }
    }

    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    ///
    /// This method is a shortcut for calling `key` and concatenating the returned slices.
    pub fn key_as_vec(&self) -> Vec<u8> {
        match &self.inner {
            StorageGetTarget::Storage(inner) => inner.key_as_vec(),
            StorageGetTarget::HeapPagesAndRuntime(_) | StorageGetTarget::HeapPages(_, _) => {
                b":heappages".to_vec()
            }
            StorageGetTarget::Runtime(_, _) => b":code".to_vec(),
        }
    }

    /// Injects the corresponding storage value.
    // TODO: change API, see execute_block::StorageGet
    pub fn inject_value(mut self, value: Option<&[u8]>) -> ProcessOne<TRq, TBl> {
        // TODO: simplify code inside here
        match self.inner {
            StorageGetTarget::Storage(inner) => {
                let inner = inner.inject_value(value);
                ProcessOne::from(Inner::Step2(inner), self.shared)
            }
            StorageGetTarget::HeapPagesAndRuntime(inner) => {
                let heap_pages = if let Some(value) = value {
                    u64::from_le_bytes(
                        <[u8; 8]>::try_from(&value[..]).unwrap(), // TODO: don't unwrap
                    )
                } else {
                    1024 // TODO: default heap pages
                };
                ProcessOne::FinalizedStorageGet(StorageGet {
                    inner: StorageGetTarget::Runtime(inner, heap_pages),
                    shared: self.shared,
                })
            }
            StorageGetTarget::Runtime(inner, heap_pages) => {
                let wasm_code = value.expect("no runtime code in storage?"); // TODO: ?!?!
                let wasm_vm = host::HostVmPrototype::new(
                    wasm_code,
                    heap_pages,
                    vm::ExecHint::CompileAheadOfTime,
                )
                .expect("invalid runtime code?!?!"); // TODO: ?!?!
                let inner = inner.resume(
                    wasm_vm,
                    self.shared.inner.top_trie_root_calculation_cache.take(),
                );
                ProcessOne::from(Inner::Step2(inner), self.shared)
            }
            StorageGetTarget::HeapPages(inner, wasm_code) => {
                let heap_pages = if let Some(value) = value {
                    u64::from_le_bytes(
                        <[u8; 8]>::try_from(&value[..]).unwrap(), // TODO: don't unwrap
                    )
                } else {
                    1024 // TODO: default heap pages
                };
                let wasm_vm = host::HostVmPrototype::new(
                    &wasm_code,
                    heap_pages,
                    vm::ExecHint::CompileAheadOfTime,
                )
                .expect("invalid runtime code?!?!"); // TODO: ?!?!
                let inner = inner.resume(
                    wasm_vm,
                    self.shared.inner.top_trie_root_calculation_cache.take(),
                );
                ProcessOne::from(Inner::Step2(inner), self.shared)
            }
        }
    }
}

/// Fetching the list of keys with a given prefix is required in order to continue.
#[must_use]
pub struct StoragePrefixKeys<TRq, TBl> {
    inner: blocks_tree::StoragePrefixKeys<Block>,
    shared: ProcessOneShared<TRq, TBl>,
}

impl<TRq, TBl> StoragePrefixKeys<TRq, TBl> {
    /// Returns the prefix whose keys to load.
    pub fn prefix(&self) -> &[u8] {
        self.inner.prefix()
    }

    /// Injects the list of keys.
    pub fn inject_keys(self, keys: impl Iterator<Item = impl AsRef<[u8]>>) -> ProcessOne<TRq, TBl> {
        let mut keys = keys
            .map(|k| k.as_ref().to_owned())
            .collect::<HashSet<_, fnv::FnvBuildHasher>>();

        let prefix = self.inner.prefix();
        for (k, v) in self
            .shared
            .inner
            .best_to_finalized_storage_diff
            .range(prefix.to_owned()..)
            .take_while(|(k, _)| k.starts_with(prefix))
        {
            if v.is_some() {
                keys.insert(k.clone());
            } else {
                keys.remove(k);
            }
        }

        let inner = self.inner.inject_keys(keys.iter());
        ProcessOne::from(Inner::Step2(inner), self.shared)
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct StorageNextKey<TRq, TBl> {
    inner: blocks_tree::StorageNextKey<Block>,
    shared: ProcessOneShared<TRq, TBl>,

    /// If `Some`, ask for the key inside of this field rather than the one of `inner`. Used in
    /// corner-case situations where the key provided by the user has been erased from storage.
    key_overwrite: Option<Vec<u8>>,
}

impl<TRq, TBl> StorageNextKey<TRq, TBl> {
    /// Returns the key whose next key must be passed back.
    pub fn key(&self) -> &[u8] {
        if let Some(key_overwrite) = &self.key_overwrite {
            key_overwrite
        } else {
            self.inner.key()
        }
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl AsRef<[u8]>>) -> ProcessOne<TRq, TBl> {
        let key = key.as_ref().map(|k| k.as_ref());

        // The key provided by the user as parameter is the next key in the storage of the
        // finalized block.
        // `best_to_finalized_storage_diff` needs to be taken into account in order to provide
        // the next key in the best block instead.

        let requested_key = if let Some(key_overwrite) = &self.key_overwrite {
            key_overwrite
        } else {
            self.inner.key()
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
                return ProcessOne::FinalizedStorageNextKey(StorageNextKey {
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
            (None, Some((b, _))) => Some(&b[..]),
            (None, None) => None,
        };

        let inner = self.inner.inject_key(outcome);
        ProcessOne::from(Inner::Step2(inner), self.shared)
    }
}

/// Request that should be emitted towards a certain source.
#[derive(Debug)]
pub enum RequestAction<'a, TRq, TSrc> {
    /// A request must be emitted for the given source.
    ///
    /// The request has **not** been acknowledged when this event is emitted. You **must** call
    /// [`Start::start`] to notify the [`OptimisticFullSyncInner`] that the request has been sent
    /// out.
    Start {
        /// Source where to request blocks from.
        source_id: SourceId,
        /// User data of source where to request blocks from.
        source: &'a mut TSrc,
        /// Must be used to accept the request.
        start: Start<'a, TRq, TSrc>,
        /// Height of the block to request.
        block_height: NonZeroU64,
        /// Number of blocks to request. Always smaller than the value passed through
        /// [`Config::blocks_request_granularity`].
        num_blocks: NonZeroU32,
    },

    /// The given [`RequestId`] is no longer valid.
    ///
    /// > **Note**: The request can either be cancelled, or the request can be let through but
    /// >           marked in a way that [`OptimisticFullSyncInner::finish_request`] isn't called.
    Cancel {
        /// Identifier for the request. No longer valid.
        request_id: RequestId,
        /// User data associated with the request.
        user_data: TRq,
        /// Source where to request blocks from.
        source_id: SourceId,
        /// User data of source where to request blocks from.
        source: &'a mut TSrc,
    },
}

/// Must be used to accept the request.
#[must_use]
pub struct Start<'a, TRq, TSrc> {
    verification_queue: &'a mut VecDeque<VerificationQueueEntry<TRq>>,
    source: usize,
    missing_pos: usize,
    next_request_id: &'a mut RequestId,
    marker: PhantomData<&'a TSrc>,
}

impl<'a, TRq, TSrc> Start<'a, TRq, TSrc> {
    /// Updates the [`OptimisticFullSyncInner`] with the fact that the request has actually been
    /// started. Returns the identifier for the request that must later be passed back to
    /// [`OptimisticFullSyncInner::finish_request`].
    pub fn start(self, user_data: TRq) -> RequestId {
        let request_id = *self.next_request_id;
        self.next_request_id.0 += 1;

        self.verification_queue[self.missing_pos].ty = VerificationQueueEntryTy::Requested {
            id: request_id,
            source: self.source,
            user_data,
        };

        request_id
    }
}

impl<'a, TRq, TSrc> fmt::Debug for Start<'a, TRq, TSrc> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Start").finish()
    }
}

pub enum FinishRequestOutcome<'a, TSrc> {
    Queued,
    SourcePunished(&'a mut TSrc),
}

/// Reason why a request has failed.
pub enum RequestFail {
    /// Requested blocks aren't available from this source.
    BlocksUnavailable,
}

/// Iterator that drains requests after a source has been removed.
pub struct RequestsDrain<'a, TRq> {
    iter: iter::Fuse<alloc::collections::vec_deque::IterMut<'a, VerificationQueueEntry<TRq>>>,
    source_index: usize,
}

impl<'a, TRq> Iterator for RequestsDrain<'a, TRq> {
    type Item = (RequestId, TRq);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.iter.next()?;
            match entry.ty {
                VerificationQueueEntryTy::Requested { source, .. }
                    if source == self.source_index =>
                {
                    match mem::replace(&mut entry.ty, VerificationQueueEntryTy::Missing) {
                        VerificationQueueEntryTy::Requested { id, user_data, .. } => {
                            return Some((id, user_data));
                        }
                        _ => unreachable!(),
                    }
                }
                _ => {}
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, self.iter.size_hint().1)
    }
}

impl<'a, TRq> fmt::Debug for RequestsDrain<'a, TRq> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("RequestsDrain").finish()
    }
}

impl<'a, TRq> Drop for RequestsDrain<'a, TRq> {
    fn drop(&mut self) {
        // Drain all remaining elements even if the iterator is dropped eagerly.
        // This is the reason why a custom iterator type is needed, rather than using combinators.
        for _ in self {}
    }
}

/// Problem that happened and caused the reset.
#[derive(Debug, derive_more::Display)]
pub enum ResetCause {
    /// Error while verifying a justification.
    JustificationError(blocks_tree::JustificationVerifyError),
    /// Error while verifying a header.
    HeaderError(blocks_tree::HeaderVerifyError),
    /// Received block isn't a child of the current best block.
    NonCanonical,
    /// Received block number doesn't match expected number.
    // TODO: unused?
    #[display(fmt = "Received block height doesn't match expected number")]
    UnexpectedBlockNumber {
        /// Number of the block that was expected to be verified next.
        expected: u64,
        /// Number of the block that was verified.
        actual: u64,
    },
}
