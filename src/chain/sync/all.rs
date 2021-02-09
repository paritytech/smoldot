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

//! All syncing strategies (optimistic, warp sync, all forks) grouped together.

use crate::{
    chain::{
        chain_information,
        sync::{all_forks, grandpa_warp_sync, optimistic},
    },
    header, verify,
};

use core::{
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};

/// Configuration for the [`AllSync`].
// TODO: review these fields
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

#[derive(derive_more::From)]
pub enum AllSync<TRq, TSrc, TBl> {
    Idle(Idle<TRq, TSrc, TBl>),
    HeaderVerify(HeaderVerify<TRq, TSrc, TBl>),
}

impl<TRq, TSrc, TBl> AllSync<TRq, TSrc, TBl> {
    /// Shortcut for [`Idle::new`] then putting the result in [`AllSync::Idle`].
    pub fn new(config: Config) -> Self {
        AllSync::Idle(Idle::new(config))
    }
}

pub struct Idle<TRq, TSrc, TBl> {
    inner: IdleInner<TSrc, TBl>,
    shared: Shared,
    marker: core::marker::PhantomData<TRq>, // TODO: remove
}

enum IdleInner<TSrc, TBl> {
    Optimistic(optimistic::OptimisticSync<(), OptimisticSourceExtra<TSrc>, TBl>),
    /// > **Note**: Must never contain [`grandpa_warp_sync::GrandpaWarpSync::Finished`].
    GrandpaWarpSync(grandpa_warp_sync::GrandpaWarpSync<TSrc>),
    AllForks(all_forks::AllForksSync<TSrc, TBl>),
}

struct OptimisticSourceExtra<TSrc> {
    user_data: TSrc,
    best_block_hash: [u8; 32],
    outer_source_id: SourceId,
}

/// Identifier for a source in the [`AllSync`].
//
// Implementation note: this is an index in `Idle::sources`.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SourceId(usize);

/// Identifier for a request in the [`AllSync`].
//
// Implementation note: this is an index in `Idle::requests`.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RequestId(usize);

impl<TRq, TSrc, TBl> Idle<TRq, TSrc, TBl> {
    /// Initializes a new state machine.
    pub fn new(config: Config) -> Self {
        Idle {
            /*// TODO: use GrandPa warp sync instead
            inner: IdleInner::GrandpaWarpSync(grandpa_warp_sync::grandpa_warp_sync(
                grandpa_warp_sync::Config {
                    start_chain_information: config.chain_information,
                    sources_capacity: config.sources_capacity,
                },
            )),*/
            inner: IdleInner::Optimistic(optimistic::OptimisticSync::new(optimistic::Config {
                chain_information: config.chain_information,
                sources_capacity: config.sources_capacity,
                blocks_capacity: config.blocks_capacity,
                blocks_request_granularity: config.blocks_request_granularity,
                download_ahead_blocks: config.download_ahead_blocks,
                source_selection_randomness_seed: config.source_selection_randomness_seed,
                full: config.full,
            })),
            shared: Shared {
                sources: slab::Slab::with_capacity(config.sources_capacity),
                requests: slab::Slab::with_capacity(config.sources_capacity),
            },
            marker: Default::default(),
        }
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct corresponding to the current
    /// latest finalized block. Can later be used to reconstruct a chain.
    pub fn as_chain_information(&self) -> chain_information::ChainInformationRef {
        match &self.inner {
            IdleInner::Optimistic(sync) => sync.as_chain_information(),
            _ => todo!(),
        }
    }

    /// Returns the header of the finalized block.
    pub fn finalized_block_header(&self) -> header::HeaderRef {
        match &self.inner {
            IdleInner::Optimistic(sync) => sync.finalized_block_header(),
            _ => todo!(),
        }
    }

    /// Returns the header of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_header(&self) -> header::HeaderRef {
        match &self.inner {
            IdleInner::Optimistic(sync) => sync.best_block_header(),
            _ => todo!(),
        }
    }

    /// Returns the number of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_number(&self) -> u64 {
        match &self.inner {
            IdleInner::Optimistic(sync) => sync.best_block_number(),
            _ => todo!(),
        }
    }

    /// Returns the hash of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_hash(&self) -> [u8; 32] {
        match &self.inner {
            IdleInner::Optimistic(sync) => sync.best_block_hash(),
            _ => todo!(),
        }
    }

    /// Adds a new source to the sync state machine.
    ///
    /// Must be passed the best block number and hash of the source, as usually reported by itself.
    ///
    /// Returns an identifier for the source, plus an optional request.
    pub fn add_source(
        &mut self,
        user_data: TSrc,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    ) -> (SourceId, Vec<Action>) {
        match &mut self.inner {
            IdleInner::GrandpaWarpSync(grandpa_warp_sync::GrandpaWarpSync::WaitingForSources(
                waiting,
            )) => {
                //waiting.add_source(user_data);
                todo!()
            }
            IdleInner::GrandpaWarpSync(grandpa_warp_sync::GrandpaWarpSync::WarpSyncRequest(
                waiting,
            )) => {
                //waiting.add_source(user_data);
                todo!()
            }
            IdleInner::Optimistic(optimistic) => {
                let outer_source_id_entry = self.shared.sources.vacant_entry();
                let outer_source_id = SourceId(outer_source_id_entry.key());

                let inner_source_id = optimistic.add_source(
                    OptimisticSourceExtra {
                        best_block_hash,
                        user_data,
                        outer_source_id,
                    },
                    best_block_number,
                );

                outer_source_id_entry.insert(SourceMapping::Optimistic(inner_source_id));

                let mut requests_to_start = Vec::new();

                while let Some(action) = optimistic.next_request_action() {
                    requests_to_start.push(self.shared.optimistic_action_to_request(action));
                }

                (outer_source_id, requests_to_start)
            }
            _ => todo!(),
        }
    }

    /// Removes a source from the state machine. Returns the user data of this source, and all
    /// the requests that this source were expected to perform.
    ///
    /// All the [`RequestId`]s returned are immediately considered invalid.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] doesn't correspond to a valid source.
    ///
    pub fn remove_source(&mut self, source_id: SourceId) -> Vec<(RequestId, TRq)> {
        todo!()
    }

    pub fn source_user_data_mut(&mut self, source_id: SourceId) -> &mut TSrc {
        match (
            &mut self.inner,
            self.shared.sources.get(source_id.0).unwrap(),
        ) {
            (IdleInner::Optimistic(sync), SourceMapping::Optimistic(src)) => {
                &mut sync.source_user_data_mut(*src).user_data
            }
            (IdleInner::AllForks(sync), SourceMapping::AllForks(src)) => {
                sync.source_mut(*src).unwrap().into_user_data()
            }
            _ => panic!(), // TODO:
        }
    }

    /// Injects a block announcement made by a source into the state machine.
    pub fn block_announce(
        mut self,
        source_id: SourceId,
        announced_scale_encoded_header: Vec<u8>,
        is_best: bool,
    ) -> BlockAnnounceOutcome<TRq, TSrc, TBl> {
        let source_id = self.shared.sources.get(source_id.0).unwrap();

        match (self.inner, source_id) {
            (IdleInner::Optimistic(mut sync), &SourceMapping::Optimistic(source_id)) => {
                let decoded = header::decode(&announced_scale_encoded_header).unwrap();
                sync.source_user_data_mut(source_id).best_block_hash =
                    header::hash_from_scale_encoded_header(&announced_scale_encoded_header);
                sync.raise_source_best_block(source_id, decoded.number);

                let mut next_actions = Vec::new();
                while let Some(action) = sync.next_request_action() {
                    next_actions.push(self.shared.optimistic_action_to_request(action));
                }

                BlockAnnounceOutcome::Disjoint {
                    sync: Idle {
                        inner: IdleInner::Optimistic(sync),
                        ..self
                    },
                    next_actions,
                }
            }
            /*(IdleInner::AllForks(mut sync), &SourceMapping::AllForks(source_id)) => {

            }*/
            _ => todo!(),
        }
    }

    /// Inject a response to a previously-emitted blocks request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    pub fn blocks_request_response(
        mut self,
        request_id: RequestId,
        blocks: Result<impl Iterator<Item = BlockRequestSuccessBlock<TBl>>, ()>,
        now_from_unix_epoch: Duration, // TODO: remove
    ) -> BlocksRequestResponseOutcome<TRq, TSrc, TBl> {
        debug_assert!(self.shared.requests.contains(request_id.0));
        let request = self.shared.requests.remove(request_id.0);

        match (self.inner, request) {
            (IdleInner::GrandpaWarpSync(_), _) => panic!(), // Grandpa warp sync never starts block requests.
            (IdleInner::Optimistic(mut sync), RequestMapping::Optimistic(request_id)) => {
                let _ = sync.finish_request(
                    request_id,
                    blocks
                        .map(|iter| {
                            iter.map(|block| optimistic::RequestSuccessBlock {
                                scale_encoded_header: block.scale_encoded_header,
                                scale_encoded_extrinsics: block.scale_encoded_extrinsics,
                                scale_encoded_justification: block.scale_encoded_justification,
                                user_data: block.user_data,
                            })
                        })
                        .map_err(|()| optimistic::RequestFail::BlocksUnavailable),
                );

                match sync.process_one(now_from_unix_epoch) {
                    optimistic::ProcessOne::Idle { mut sync } => {
                        let mut next_actions = Vec::new();
                        while let Some(action) = sync.next_request_action() {
                            next_actions.push(self.shared.optimistic_action_to_request(action));
                        }

                        BlocksRequestResponseOutcome::Queued {
                            sync: Idle {
                                inner: IdleInner::Optimistic(sync),
                                marker: Default::default(),
                                shared: self.shared,
                            },
                            next_actions,
                        }
                    }
                    other => BlocksRequestResponseOutcome::VerifyHeader(HeaderVerify {
                        inner: HeaderVerifyInner::Optimistic(other),
                        shared: self.shared,
                        marker: Default::default(),
                    }),
                }
            }
            (IdleInner::AllForks(sync), RequestMapping::AllForks(source_id)) => {
                match sync.ancestry_search_response(
                    source_id,
                    blocks.map(|iter| iter.map(|block| block.scale_encoded_header)),
                ) {
                    all_forks::AncestrySearchResponseOutcome::Verify(verify) => {
                        BlocksRequestResponseOutcome::VerifyHeader(HeaderVerify {
                            inner: HeaderVerifyInner::AllForks(verify),
                            shared: self.shared,
                            marker: Default::default(),
                        })
                    }
                    all_forks::AncestrySearchResponseOutcome::NotFinalizedChain {
                        sync,
                        next_request,
                        discarded_unverified_block_headers,
                    } => BlocksRequestResponseOutcome::NotFinalizedChain {
                        sync: Idle {
                            inner: IdleInner::AllForks(sync),
                            ..self
                        },
                        next_actions: next_request
                            .into_iter()
                            .map(|req| Action::Start {
                                request_id: todo!(),
                                source_id: todo!(),
                                detail: todo!(),
                            })
                            .collect(),
                        discarded_unverified_block_headers,
                    },
                    all_forks::AncestrySearchResponseOutcome::Inconclusive {
                        sync,
                        next_request,
                    } => BlocksRequestResponseOutcome::Inconclusive {
                        sync: Idle {
                            inner: IdleInner::AllForks(sync),
                            ..self
                        },
                        next_actions: next_request
                            .into_iter()
                            .map(|req| Action::Start {
                                request_id: todo!(),
                                source_id: todo!(),
                                detail: todo!(),
                            })
                            .collect(),
                    },
                    all_forks::AncestrySearchResponseOutcome::AllAlreadyInChain {
                        sync,
                        next_request,
                    } => BlocksRequestResponseOutcome::AllAlreadyInChain {
                        sync: Idle {
                            inner: IdleInner::AllForks(sync),
                            ..self
                        },
                        next_actions: next_request
                            .into_iter()
                            .map(|req| Action::Start {
                                request_id: todo!(),
                                source_id: todo!(),
                                detail: todo!(),
                            })
                            .collect(),
                    },
                }
            }
            // TODO: not all variants implemented
            _ => panic!(),
        }
    }

    /*/// Inject a response to a previously-emitted GrandPa warp sync request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    pub fn grandpa_warp_sync_response(
        self,
        request_id: RequestId,
        // TODO: don't use crate::network::protocol
        response: Result<Vec<crate::network::protocol::GrandpaWarpSyncResponseFragment>, ()>,
    ) -> AllSync<TRq, TSrc, TBl> {
        // TODO: check request_id?!
        match self.inner {
            IdleInner::GrandpaWarpSync(grandpa_warp_sync::GrandpaWarpSync::WarpSyncRequest(
                grandpa,
            )) => {
                let mut grandpa_warp_sync = grandpa.handle_response(response);
                loop {
                    match grandpa_warp_sync {
                        grandpa_warp_sync::GrandpaWarpSync::Finished(Ok((
                            chain_information,
                            finalized_block_runtime,
                        ))) => {}
                        grandpa_warp_sync::GrandpaWarpSync::Finished(Err(_)) => {
                            todo!()
                        }
                        grandpa_warp_sync::GrandpaWarpSync::StorageGet(get) => {
                            todo!()
                        }
                        grandpa_warp_sync::GrandpaWarpSync::NextKey(next_key) => {
                            todo!()
                        }
                        grandpa_warp_sync::GrandpaWarpSync::Verifier(verifier) => {
                            grandpa_warp_sync = verifier.next();
                        }
                        grandpa_warp_sync::GrandpaWarpSync::WarpSyncRequest(rq) => {
                            todo!()
                        }
                        grandpa_warp_sync::GrandpaWarpSync::VirtualMachineParamsGet(rq) => {
                            todo!()
                        }
                        gp @ grandpa_warp_sync::GrandpaWarpSync::WaitingForSources(_) => {
                            return AllSync::Idle(Idle {
                                inner: IdleInner::GrandpaWarpSync(gp),
                                ..self
                            })
                        }
                    }
                }
            }

            // Only the GrandPa warp syncing ever starts GrandPa warp sync requests.
            _ => panic!(),
        }
    }*/

    /*/// Inject a response to a previously-emitted storage proof request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    pub fn storage_get_response(
        self,
        request_id: RequestId,
        response: Result<Option<impl Iterator<Item = impl AsRef<[u8]>>>, ()>,
    ) -> StorageGetResponseOutcome<TRq, TSrc, TBl> {
        // TODO: check request_id?!
        match self.inner {
            /*IdleInner::GrandpaWarpSync(grandpa_warp_sync::GrandpaWarpSync::StorageGet(grandpa)) => {
                AllSync::from_grandpa_inner(grandpa.inject_value(response));
            }*/
            // Only the GrandPa warp syncing ever starts GrandPa warp sync requests.
            _ => panic!(),
        }
    }*/
}

/// Start or cancel a request.
#[derive(Debug, Clone)]
pub enum Action {
    /// Start a request towards a source.
    Start {
        /// Identifier of the request to pass back later in order to indicate a response.
        request_id: RequestId,
        /// Identifier of the source that must perform the request.
        source_id: SourceId,
        /// Actual details of the request to perform.
        detail: RequestDetail,
    },
    /// Cancel a previously-emitted request.
    Cancel(RequestId),
}

/// See [`Request::detail`].
#[derive(Debug, Clone)]
#[must_use]
pub enum RequestDetail {
    /// Requesting blocks from the source is requested.
    BlocksRequest {
        /// Hash of the first block to request.
        first_block: BlocksRequestFirstBlock,
        /// `True` if the `first_block_hash` is the response should contain blocks in an
        /// increasing number, starting from `first_block_hash` with the lowest number. If `false`,
        /// the blocks should be in decreasing number, with `first_block_hash` as the highest
        /// number.
        ascending: bool,
        /// Number of blocks the request should return.
        ///
        /// Note that this is only an indication, and the source is free to give fewer blocks
        /// than requested.
        num_blocks: NonZeroU64,
        /// `True` if headers should be included in the response.
        request_headers: bool,
        /// `True` if bodies should be included in the response.
        request_bodies: bool,
        /// `True` if the justification should be included in the response, if any.
        request_justification: bool,
    },

    /// Sending a Grandpa warp sync request is requested.
    GrandpaWarpSync {
        /// Height of the known finalized block. Starting point of the request.
        local_finalized_block_height: u64,
    },

    /// Sending a storage query is requested.
    StorageGet {
        /// Hash of the block whose storage is requested.
        block_hash: [u8; 32],
        /// Merkle value of the root of the storage trie of the block.
        state_trie_root: [u8; 32],
        /// Key whose value is requested.
        key: Vec<u8>,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BlocksRequestFirstBlock {
    Hash([u8; 32]),
    Number(NonZeroU64),
}

pub struct BlockRequestSuccessBlock<TBl> {
    pub scale_encoded_header: Vec<u8>,
    pub scale_encoded_justification: Option<Vec<u8>>,
    pub scale_encoded_extrinsics: Vec<Vec<u8>>,
    pub user_data: TBl,
}

/// Outcome of calling [`Idle::block_announce`].
pub enum BlockAnnounceOutcome<TRq, TSrc, TBl> {
    /// Header is ready to be verified.
    HeaderVerify(HeaderVerify<TRq, TSrc, TBl>),

    /// Announced block is too old to be part of the finalized chain.
    ///
    /// It is assumed that all sources will eventually agree on the same finalized chain. Blocks
    /// whose height is inferior to the height of the latest known finalized block should simply
    /// be ignored. Whether or not this old block is indeed part of the finalized block isn't
    /// verified, and it is assumed that the source is simply late.
    TooOld(Idle<TRq, TSrc, TBl>),
    /// Announced block has already been successfully verified and is part of the non-finalized
    /// chain.
    AlreadyInChain(Idle<TRq, TSrc, TBl>),
    /// Announced block is known to not be a descendant of the finalized block.
    NotFinalizedChain(Idle<TRq, TSrc, TBl>),
    /// Header cannot be verified now, and has been stored for later.
    Disjoint {
        sync: Idle<TRq, TSrc, TBl>,
        /// Next requests that the same source should now perform.
        next_actions: Vec<Action>,
    },
    /// Failed to decode announce header.
    InvalidHeader {
        sync: Idle<TRq, TSrc, TBl>,
        error: header::Error,
    },
}

/// Outcome of calling [`Idle::blocks_request_response`].
pub enum BlocksRequestResponseOutcome<TRq, TSrc, TBl> {
    /// Ready to start verifying one or more headers returned in the ancestry search.
    VerifyHeader(HeaderVerify<TRq, TSrc, TBl>),

    /// Blocks have been queued and will be processed later.
    Queued {
        sync: Idle<TRq, TSrc, TBl>,

        /// Next requests that must be started.
        next_actions: Vec<Action>,
    },

    /// Source has given blocks that aren't part of the finalized chain.
    ///
    /// This doesn't necessarily mean that the source is malicious or uses a different chain. It
    /// is possible for this to legitimately happen, for example if the finalized chain has been
    /// updated while the ancestry search was in progress.
    NotFinalizedChain {
        sync: Idle<TRq, TSrc, TBl>,

        /// Next requests that must be started.
        next_actions: Vec<Action>,

        /// List of block headers that were pending verification and that have now been discarded
        /// since it has been found out that they don't belong to the finalized chain.
        discarded_unverified_block_headers: Vec<Vec<u8>>,
    },

    /// Couldn't verify any of the blocks of the ancestry search. Some or all of these blocks
    /// have been stored in the local machine for later.
    Inconclusive {
        sync: Idle<TRq, TSrc, TBl>,

        /// Next requests that must be started.
        next_actions: Vec<Action>,
    },

    /// All blocks in the ancestry search response were already in the list of verified blocks.
    ///
    /// This can happen if a block announce or different ancestry search response has been
    /// processed in between the request and response.
    AllAlreadyInChain {
        sync: Idle<TRq, TSrc, TBl>,

        /// Next requests that must be started.
        next_actions: Vec<Action>,
    },
}

pub struct HeaderVerify<TRq, TSrc, TBl> {
    inner: HeaderVerifyInner<TSrc, TBl>,
    shared: Shared,
    marker: core::marker::PhantomData<TRq>, // TODO: remove
}

enum HeaderVerifyInner<TSrc, TBl> {
    AllForks(all_forks::HeaderVerify<TSrc, TBl>),
    Optimistic(optimistic::ProcessOne<(), OptimisticSourceExtra<TSrc>, TBl>),
}

impl<TRq, TSrc, TBl> HeaderVerify<TRq, TSrc, TBl> {
    /// Perform the verification.
    pub fn perform(
        mut self,
        now_from_unix_epoch: Duration,
        user_data: TBl,
    ) -> HeaderVerifyOutcome<TRq, TSrc, TBl> {
        match self.inner {
            // TODO: the verification in the optimistic is immediate ; change that
            HeaderVerifyInner::Optimistic(optimistic::ProcessOne::Idle { .. }) => unreachable!(),
            HeaderVerifyInner::Optimistic(optimistic::ProcessOne::NewBest {
                mut sync,
                new_best_number,
                ..
            }) => {
                if new_best_number >= 3130000 {
                    // TODO: lol ^
                    let (all_forks, next_actions) =
                        self.shared.transition_optimistic_all_forks(sync);
                    return HeaderVerifyOutcome::Success {
                        is_new_best: true,
                        sync: Idle {
                            inner: IdleInner::AllForks(all_forks),
                            marker: Default::default(),
                            shared: self.shared,
                        }
                        .into(),
                        next_actions,
                    };
                }

                let mut next_actions = Vec::new();
                while let Some(action) = sync.next_request_action() {
                    next_actions.push(self.shared.optimistic_action_to_request(action));
                }

                match sync.process_one(now_from_unix_epoch) {
                    optimistic::ProcessOne::Idle { sync } => HeaderVerifyOutcome::Success {
                        is_new_best: true,
                        sync: Idle {
                            inner: IdleInner::Optimistic(sync),
                            marker: Default::default(),
                            shared: self.shared,
                        }
                        .into(),
                        next_actions,
                    },
                    other => {
                        self.inner = HeaderVerifyInner::Optimistic(other);
                        HeaderVerifyOutcome::Success {
                            is_new_best: true,
                            sync: self.into(),
                            next_actions,
                        }
                    }
                }
            }
            HeaderVerifyInner::Optimistic(optimistic::ProcessOne::Reset { .. }) => todo!(),
            HeaderVerifyInner::Optimistic(optimistic::ProcessOne::Finalized { .. }) => todo!(),
            HeaderVerifyInner::Optimistic(optimistic::ProcessOne::FinalizedStorageGet(_))
            | HeaderVerifyInner::Optimistic(optimistic::ProcessOne::FinalizedStorageNextKey(_))
            | HeaderVerifyInner::Optimistic(optimistic::ProcessOne::FinalizedStoragePrefixKeys(
                _,
            )) => {
                unreachable!()
            }
            _ => todo!(),
        }
    }
}

/// Outcome of calling [`HeaderVerify::perform`].
pub enum HeaderVerifyOutcome<TRq, TSrc, TBl> {
    /// Header has been successfully verified.
    Success {
        /// True if the newly-verified block is considered the new best block.
        is_new_best: bool,
        /// State machine yielded back. Use to continue the processing.
        sync: AllSync<TRq, TSrc, TBl>,
        /// Next requests that must be started.
        next_actions: Vec<Action>,
    },

    /// Header verification failed.
    Error {
        /// State machine yielded back. Use to continue the processing.
        sync: AllSync<TRq, TSrc, TBl>,
        /// Error that happened.
        error: verify::header_only::Error,
        /// User data that was passed to [`HeaderVerify::perform`] and is unused.
        user_data: TBl,
        /// Next requests that must be started.
        next_actions: Vec<Action>,
    },
}

struct Shared {
    sources: slab::Slab<SourceMapping>,
    requests: slab::Slab<RequestMapping>,
}

impl Shared {
    fn optimistic_action_to_request<TSrc, TBl>(
        &mut self,
        action: optimistic::RequestAction<(), OptimisticSourceExtra<TSrc>, TBl>,
    ) -> Action {
        match action {
            optimistic::RequestAction::Start {
                block_height,
                num_blocks,
                start,
                source,
                source_id,
            } => {
                let request_id = RequestId(
                    self.requests
                        .insert(RequestMapping::Optimistic(start.start(()))),
                );

                debug_assert_eq!(
                    self.sources[source.outer_source_id.0],
                    SourceMapping::Optimistic(source_id)
                );

                Action::Start {
                    request_id,
                    source_id: source.outer_source_id,
                    detail: RequestDetail::BlocksRequest {
                        first_block: BlocksRequestFirstBlock::Number(block_height),
                        ascending: true,
                        num_blocks: NonZeroU64::from(num_blocks),
                        request_bodies: true, // TODO: ?!
                        request_headers: true,
                        request_justification: false, // TODO: should be true, but "finalized" panics now
                    },
                }
            }
            _ => unreachable!(),
        }
    }

    fn all_forks_request_to_request(
        &mut self,
        source_id: all_forks::SourceId,
        request: all_forks::Request,
    ) -> Action {
        let request_id = RequestId(self.requests.insert(RequestMapping::AllForks(source_id)));

        // TODO: O(n), should store id in user data instead
        let outer_source_id = self
            .sources
            .iter()
            .find(|(id, s)| **s == SourceMapping::AllForks(source_id))
            .map(|(id, _)| SourceId(id))
            .unwrap();

        match request {
            all_forks::Request::AncestrySearch {
                first_block_hash,
                num_blocks,
            } => Action::Start {
                request_id,
                source_id: outer_source_id,
                detail: RequestDetail::BlocksRequest {
                    first_block: BlocksRequestFirstBlock::Hash(first_block_hash),
                    ascending: false,
                    num_blocks,
                    request_bodies: false,
                    request_headers: true,
                    request_justification: false,
                },
            },
            all_forks::Request::HeaderRequest { hash, .. } => Action::Start {
                request_id,
                source_id: outer_source_id,
                detail: RequestDetail::BlocksRequest {
                    first_block: BlocksRequestFirstBlock::Hash(hash),
                    ascending: true,
                    num_blocks: NonZeroU64::new(1).unwrap(),
                    request_bodies: false,
                    request_headers: true,
                    request_justification: false,
                },
            },
            all_forks::Request::BodyRequest { .. } => todo!(),
        }
    }

    /// Transitions the sync state machine from the optimistic strategy to the "all-forks"
    /// strategy.
    fn transition_optimistic_all_forks<TSrc, TBl>(
        &mut self,
        optimistic: optimistic::OptimisticSync<(), OptimisticSourceExtra<TSrc>, TBl>,
    ) -> (all_forks::AllForksSync<TSrc, TBl>, Vec<Action>) {
        debug_assert!(self
            .requests
            .iter()
            .all(|(_, s)| matches!(s, RequestMapping::Optimistic(_))));
        debug_assert!(self
            .sources
            .iter()
            .all(|(_, s)| matches!(s, SourceMapping::Optimistic(_))));

        let disassembled = optimistic.disassemble();

        // TODO: arbitrary config
        let mut all_forks = all_forks::AllForksSync::new(all_forks::Config {
            chain_information: disassembled.chain_information,
            sources_capacity: 1024,
            blocks_capacity: 1024,
            max_disjoint_headers: 1024,
            max_requests_per_block: NonZeroU32::new(128).unwrap(),
            full: false,
        });

        let mut all_forks_demands = Vec::with_capacity(disassembled.sources.len());

        for source in disassembled.sources {
            let (updated_source_id, request) = all_forks.add_source(
                source.user_data.user_data,
                source.best_block_number,
                source.user_data.best_block_hash,
            );
            let updated_source_id = updated_source_id.id();

            debug_assert_eq!(
                self.sources[source.user_data.outer_source_id.0],
                SourceMapping::Optimistic(source.id)
            );

            self.sources[source.user_data.outer_source_id.0] =
                SourceMapping::AllForks(updated_source_id);

            if let Some(request) = request {
                all_forks_demands.push((updated_source_id, request));
            }
        }

        debug_assert!(self
            .sources
            .iter()
            .all(|(_, s)| matches!(s, SourceMapping::AllForks(_))));

        let mut next_actions = Vec::with_capacity(self.requests.len() + all_forks_demands.len());
        for (request_id, _) in self.requests.iter() {
            next_actions.push(Action::Cancel(RequestId(request_id)));
        }
        self.requests.clear();
        for (source_id, demand) in all_forks_demands {
            next_actions.push(self.all_forks_request_to_request(source_id, demand));
        }

        (all_forks, next_actions)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestMapping {
    Optimistic(optimistic::RequestId),
    GrandpaWarpSync(usize), // TODO:
    AllForks(all_forks::SourceId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SourceMapping {
    Optimistic(optimistic::SourceId),
    GrandpaWarpSync(usize), // TODO:
    AllForks(all_forks::SourceId),
}
