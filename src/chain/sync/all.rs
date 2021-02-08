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
    header,
};

use core::num::{NonZeroU32, NonZeroU64};

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

pub enum AllSync<TRq, TSrc, TBl> {
    Idle(Idle<TRq, TSrc, TBl>),
}

impl<TRq, TSrc, TBl> AllSync<TRq, TSrc, TBl> {
    /// Shortcut for [`Idle::new`] then putting the result in [`AllSync::Idle`].
    pub fn new(config: Config) -> Self {
        AllSync::Idle(Idle::new(config))
    }
}

pub struct Idle<TRq, TSrc, TBl> {
    inner: IdleInner<TRq, TSrc, TBl>,
    sources: slab::Slab<SourceMapping>,
    requests: slab::Slab<RequestMapping>,
}

enum IdleInner<TRq, TSrc, TBl> {
    Optimistic(optimistic::OptimisticSync<TRq, OptimisticSourceExtra<TSrc>, TBl>),
    /// > **Note**: Must never contain [`grandpa_warp_sync::GrandpaWarpSync::Finished`].
    GrandpaWarpSync(grandpa_warp_sync::GrandpaWarpSync<TSrc>),
    AllForks(all_forks::AllForksSync<TSrc, TBl>),
}

enum RequestMapping {
    Optimistic(optimistic::RequestId),
    GrandpaWarpSync(usize), // TODO:
    AllForks(all_forks::SourceId),
}

enum SourceMapping {
    Optimistic(optimistic::SourceId),
    GrandpaWarpSync(usize), // TODO:
    AllForks(all_forks::SourceId),
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
            sources: slab::Slab::with_capacity(config.sources_capacity),
            requests: slab::Slab::with_capacity(config.sources_capacity),
        }
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct corresponding to the current
    /// latest finalized block. Can later be used to reconstruct a chain.
    pub fn as_chain_information(&self) -> chain_information::ChainInformationRef {
        todo!()
    }

    /// Returns the header of the finalized block.
    pub fn finalized_block_header(&self) -> header::HeaderRef {
        todo!()
    }

    /// Returns the header of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_header(&self) -> header::HeaderRef {
        todo!()
    }

    /// Returns the number of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_number(&self) -> u64 {
        todo!()
    }

    /// Returns the hash of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_hash(&self) -> [u8; 32] {
        todo!()
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
    ) -> (SourceId, Vec<Request>) {
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
                let outer_source_id_entry = self.sources.vacant_entry();
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

                optimistic.next_request_action();
            }
            _ => todo!(),
        }

        todo!()
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
    pub fn remove_source(&mut self, source_id: SourceId) -> Vec<RequestId> {
        todo!()
    }

    /// Injects a block announcement made by a source into the state machine.
    pub fn block_announce(
        self,
        source_id: SourceId,
        announced_scale_encoded_header: Vec<u8>,
        is_best: bool,
    ) -> BlockAnnounceOutcome<TRq, TSrc, TBl> {
        todo!()
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
    ) -> BlocksRequestResponseOutcome<TRq, TSrc, TBl> {
        let request = self.requests.remove(request_id.0);

        match (self.inner, request) {
            (IdleInner::GrandpaWarpSync(_), _) => panic!(), // Grandpa warp sync never starts block requests.
            (IdleInner::Optimistic(mut sync), RequestMapping::Optimistic(request_id)) => {
                let (_, outcome) = sync.finish_request(
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

                todo!()
            }
            (IdleInner::AllForks(sync), RequestMapping::AllForks(source_id)) => {
                match sync.ancestry_search_response(
                    source_id,
                    blocks.map(|iter| iter.map(|block| block.scale_encoded_header)),
                ) {
                    all_forks::AncestrySearchResponseOutcome::Verify(verify) => {
                        BlocksRequestResponseOutcome::VerifyHeader(HeaderVerify {
                            inner: HeaderVerifyInner::AllForks(verify),
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
                        next_request: next_request
                            .into_iter()
                            .map(|req| Request {
                                id: todo!(),
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
                        next_request: next_request
                            .into_iter()
                            .map(|req| Request {
                                id: todo!(),
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
                        next_request: next_request
                            .into_iter()
                            .map(|req| Request {
                                id: todo!(),
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

/// Request that should be performed towards a source.
#[derive(Debug, Clone)]
pub struct Request {
    /// Identifier of the request to pass back later in order to indicate a response.
    pub id: RequestId,
    /// Actual details of the request to perform.
    pub detail: RequestDetail,
}

/// See [`Request::detail`].
#[derive(Debug, Clone)]
#[must_use]
pub enum RequestDetail {
    /// Requesting blocks from the source is requested.
    BlocksRequest {
        /// Hash of the first block to request.
        first_block_hash: [u8; 32],
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
        next_request: Vec<Request>,
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

    /// Source has given blocks that aren't part of the finalized chain.
    ///
    /// This doesn't necessarily mean that the source is malicious or uses a different chain. It
    /// is possible for this to legitimately happen, for example if the finalized chain has been
    /// updated while the ancestry search was in progress.
    NotFinalizedChain {
        sync: Idle<TRq, TSrc, TBl>,

        /// Next requests that the same source should now perform.
        next_request: Vec<Request>,

        /// List of block headers that were pending verification and that have now been discarded
        /// since it has been found out that they don't belong to the finalized chain.
        discarded_unverified_block_headers: Vec<Vec<u8>>,
    },

    /// Couldn't verify any of the blocks of the ancestry search. Some or all of these blocks
    /// have been stored in the local machine for later.
    Inconclusive {
        sync: Idle<TRq, TSrc, TBl>,

        /// Next request that the same source should now perform.
        next_request: Vec<Request>,
    },

    /// All blocks in the ancestry search response were already in the list of verified blocks.
    ///
    /// This can happen if a block announce or different ancestry search response has been
    /// processed in between the request and response.
    AllAlreadyInChain {
        sync: Idle<TRq, TSrc, TBl>,

        /// Next request that the same source should now perform.
        next_request: Vec<Request>,
    },
}

pub struct HeaderVerify<TRq, TSrc, TBl> {
    inner: HeaderVerifyInner<TSrc, TBl>,
    marker: core::marker::PhantomData<TRq>, // TODO: remove
}

enum HeaderVerifyInner<TSrc, TBl> {
    AllForks(all_forks::HeaderVerify<TSrc, TBl>),
}
