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
//!
//! This state machine combines GrandPa warp syncing, optimistic syncing, and all forks syncing
//! into one state machine.
//!
//! # Overview
//!
//! This state machine acts as a container of sources, blocks (verified or not), and requests.
//! In order to initialize it, you need to pass, amongst other things, a
//! [`chain_information::ChainInformation`] struct indicating the known state of the finality of
//! the chain.
//!
//! After initialization, the [`AllSync`] can be either in the [`AllSync::Idle`] state, or in
//! progress of verifying blocks (the other variants).
//!
//! The [`AllSync::Idle`] and its content, the [`Idle`] object, are the most common state. When
//! idle, one can inspect the state of the chain, add and remove sources of blocks, and/or obtain
//! new requests to perform on these sources.
//!
//! A *request* represents a query for information from a source. Once the request has finished,
//! call one of the methods of the [`Idle`] in order to notify the state machine of the oucome.

// TODO: this module needs considerable clean-up

use crate::{
    chain::chain_information,
    executor::{host, vm::ExecHint},
    header,
    sync::{all_forks, grandpa_warp_sync, optimistic},
    verify,
};

use alloc::{vec, vec::Vec};

use core::{
    iter, mem,
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

#[derive(derive_more::From)]
pub enum AllSync<TRq, TSrc, TBl> {
    Idle(Idle<TRq, TSrc, TBl>),
    HeaderVerify(HeaderVerify<TRq, TSrc, TBl>),
}

impl<TRq, TSrc, TBl> AllSync<TRq, TSrc, TBl> {
    /// Shortcut for [`Idle::new`] then putting the result in [`AllSync::Idle`].
    pub fn new(config: Config) -> Self {
        Idle::new(config).into()
    }
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

pub struct Idle<TRq, TSrc, TBl> {
    inner: IdleInner<TRq, TSrc, TBl>,
    shared: Shared,
}

impl<TRq, TSrc, TBl> Idle<TRq, TSrc, TBl> {
    /// Initializes a new state machine.
    pub fn new(config: Config) -> Self {
        Idle {
            inner: if config.full.is_some() {
                IdleInner::Optimistic(optimistic::OptimisticSync::new(optimistic::Config {
                    chain_information: config.chain_information,
                    sources_capacity: config.sources_capacity,
                    blocks_capacity: config.blocks_capacity,
                    blocks_request_granularity: config.blocks_request_granularity,
                    download_ahead_blocks: config.download_ahead_blocks,
                    source_selection_randomness_seed: config.source_selection_randomness_seed,
                    full: config.full.map(|cfg| optimistic::ConfigFull {
                        finalized_runtime: cfg.finalized_runtime,
                    }),
                }))
            } else {
                IdleInner::GrandpaWarpSync(grandpa_warp_sync::grandpa_warp_sync(
                    grandpa_warp_sync::Config {
                        start_chain_information: config.chain_information,
                        sources_capacity: config.sources_capacity,
                    },
                ))
            },
            shared: Shared {
                sources: slab::Slab::with_capacity(config.sources_capacity),
                requests: slab::Slab::with_capacity(config.sources_capacity),
                highest_block_on_network: 0,
            },
        }
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct corresponding to the current
    /// latest finalized block. Can later be used to reconstruct a chain.
    pub fn as_chain_information(&self) -> chain_information::ChainInformationRef {
        match &self.inner {
            IdleInner::Optimistic(sync) => sync.as_chain_information(),
            IdleInner::AllForks(sync) => sync.as_chain_information(),
            IdleInner::GrandpaWarpSync(sync) => sync.as_chain_information(),
            IdleInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the header of the finalized block.
    pub fn finalized_block_header(&self) -> header::HeaderRef {
        match &self.inner {
            IdleInner::Optimistic(sync) => sync.finalized_block_header(),
            IdleInner::AllForks(sync) => sync.finalized_block_header(),
            IdleInner::GrandpaWarpSync(sync) => sync.as_chain_information().finalized_block_header,
            IdleInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the header of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_header(&self) -> header::HeaderRef {
        match &self.inner {
            IdleInner::Optimistic(sync) => sync.best_block_header(),
            IdleInner::AllForks(sync) => sync.best_block_header(),
            IdleInner::GrandpaWarpSync(_) => self.finalized_block_header(),
            IdleInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the number of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_number(&self) -> u64 {
        match &self.inner {
            IdleInner::Optimistic(sync) => sync.best_block_number(),
            IdleInner::AllForks(sync) => sync.best_block_number(),
            IdleInner::GrandpaWarpSync(_) => self.best_block_header().number,
            IdleInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the hash of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_hash(&self) -> [u8; 32] {
        match &self.inner {
            IdleInner::Optimistic(sync) => sync.best_block_hash(),
            IdleInner::AllForks(sync) => sync.best_block_hash(),
            IdleInner::GrandpaWarpSync(_) => self.best_block_header().hash(),
            IdleInner::Poisoned => unreachable!(),
        }
    }

    /// Returns true if it is believed that we are near the head of the chain.
    ///
    /// The way this method is implemented is opaque and cannot be relied on. The return value
    /// should only ever be shown to the user and not used for any meaningful logic.
    pub fn is_near_head_of_chain_heuristic(&self) -> bool {
        match &self.inner {
            IdleInner::Optimistic(_) => false,
            IdleInner::AllForks(_) => true,
            IdleInner::GrandpaWarpSync(_) => false,
            IdleInner::Poisoned => unreachable!(),
        }
    }

    /// Adds a new source to the sync state machine.
    ///
    /// Must be passed the best block number and hash of the source, as usually reported by the
    /// source itself.
    ///
    /// Returns an identifier for this new source, plus a list of requests to start or cancel.
    pub fn add_source(
        &mut self,
        user_data: TSrc,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    ) -> (SourceId, Vec<Action>) {
        // TODO: remove
        if best_block_number > self.shared.highest_block_on_network {
            self.shared.highest_block_on_network = best_block_number;
        }

        // `inner` is temporarily replaced with `Poisoned`. A new value must be put back before
        // returning.
        match mem::replace(&mut self.inner, IdleInner::Poisoned) {
            IdleInner::GrandpaWarpSync(
                grandpa_warp_sync::InProgressGrandpaWarpSync::WaitingForSources(waiting),
            ) => {
                let outer_source_id_entry = self.shared.sources.vacant_entry();
                let outer_source_id = SourceId(outer_source_id_entry.key());

                let warp_sync_request = waiting.add_source(GrandpaWarpSyncSourceExtra {
                    user_data,
                    outer_source_id,
                    best_block_number,
                    best_block_hash,
                });

                let inner_source_id = warp_sync_request.current_source().0;

                outer_source_id_entry.insert(SourceMapping::GrandpaWarpSync(inner_source_id));

                let action = self
                    .shared
                    .grandpa_warp_sync_request_to_request(&warp_sync_request);

                self.inner = IdleInner::GrandpaWarpSync(warp_sync_request.into());
                (outer_source_id, vec![action])
            }
            IdleInner::GrandpaWarpSync(mut grandpa) => {
                let outer_source_id_entry = self.shared.sources.vacant_entry();
                let outer_source_id = SourceId(outer_source_id_entry.key());

                let source_extra = GrandpaWarpSyncSourceExtra {
                    user_data,
                    outer_source_id,
                    best_block_number,
                    best_block_hash,
                };

                let inner_source_id = match &mut grandpa {
                    grandpa_warp_sync::InProgressGrandpaWarpSync::WaitingForSources(_) => {
                        unreachable!()
                    }
                    grandpa_warp_sync::InProgressGrandpaWarpSync::WarpSyncRequest(sync) => {
                        sync.add_source(source_extra)
                    }
                    grandpa_warp_sync::InProgressGrandpaWarpSync::VirtualMachineParamsGet(sync) => {
                        sync.add_source(source_extra)
                    }
                    grandpa_warp_sync::InProgressGrandpaWarpSync::Verifier(sync) => {
                        sync.add_source(source_extra)
                    }
                    grandpa_warp_sync::InProgressGrandpaWarpSync::StorageGet(sync) => {
                        sync.add_source(source_extra)
                    }
                    grandpa_warp_sync::InProgressGrandpaWarpSync::NextKey(sync) => {
                        sync.add_source(source_extra)
                    }
                };

                outer_source_id_entry.insert(SourceMapping::GrandpaWarpSync(inner_source_id));

                self.inner = IdleInner::GrandpaWarpSync(grandpa);
                (outer_source_id, Vec::new())
            }
            IdleInner::Optimistic(mut optimistic) => {
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

                let mut next_actions = Vec::with_capacity(16);
                while let Some(action) = optimistic.next_request_action() {
                    next_actions.push(self.shared.optimistic_action_to_request(action));
                }

                self.inner = IdleInner::Optimistic(optimistic);
                (outer_source_id, next_actions)
            }
            IdleInner::AllForks(mut all_forks) => {
                let outer_source_id_entry = self.shared.sources.vacant_entry();
                let outer_source_id = SourceId(outer_source_id_entry.key());

                let source_id = all_forks.add_source(
                    AllForksSourceExtra {
                        user_data,
                        outer_source_id,
                    },
                    best_block_number,
                    best_block_hash,
                );
                outer_source_id_entry.insert(SourceMapping::AllForks(source_id));

                let next_actions = self.shared.all_forks_next_actions(&mut all_forks);

                self.inner = IdleInner::AllForks(all_forks);
                (outer_source_id, next_actions)
            }
            IdleInner::Poisoned => unreachable!(),
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
    // TODO: return requests as iterator
    // TODO: return the `TRq`s as well
    pub fn remove_source(&mut self, source_id: SourceId) -> (Vec<RequestId>, TSrc) {
        debug_assert!(self.shared.sources.contains(source_id.0));
        match (&mut self.inner, self.shared.sources.remove(source_id.0)) {
            (IdleInner::Optimistic(sync), SourceMapping::Optimistic(src)) => {
                let (user_data, requests) = sync.remove_source(src);
                debug_assert_eq!(user_data.outer_source_id, source_id);

                for (rq_id, _) in requests {
                    // TODO: O(n)
                    let outer_request_id = self
                        .shared
                        .requests
                        .iter()
                        .find(|(_, s)| **s == RequestMapping::Optimistic(rq_id))
                        .map(|(id, _)| RequestId(id))
                        .unwrap();
                    self.shared.requests.remove(outer_request_id.0);
                }

                todo!()
            }
            (IdleInner::AllForks(sync), SourceMapping::AllForks(source_id)) => {
                let (user_data, requests) = sync.remove_source(source_id);
                let requests = requests
                    .into_iter()
                    .map(|(inner_request_id, _, request_inner_user_data)| {
                        debug_assert!(self
                            .shared
                            .requests
                            .contains(request_inner_user_data.outer_request_id.0));
                        self.shared
                            .requests
                            .remove(request_inner_user_data.outer_request_id.0);
                        request_inner_user_data.outer_request_id
                    })
                    .collect();
                (requests, user_data.user_data)
            }
            (IdleInner::GrandpaWarpSync(sync), SourceMapping::GrandpaWarpSync(src)) => {
                todo!()
            }
            (IdleInner::Poisoned, _) => unreachable!(),
            (IdleInner::Optimistic(_), SourceMapping::AllForks(_))
            | (IdleInner::Optimistic(_), SourceMapping::GrandpaWarpSync(_))
            | (IdleInner::AllForks(_), SourceMapping::Optimistic(_))
            | (IdleInner::AllForks(_), SourceMapping::GrandpaWarpSync(_))
            | (IdleInner::GrandpaWarpSync(_), SourceMapping::AllForks(_))
            | (IdleInner::GrandpaWarpSync(_), SourceMapping::Optimistic(_)) => unreachable!(),
        }
    }

    /// Returns the user data (`TSrc`) corresponding to the given source.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn source_user_data_mut(&mut self, source_id: SourceId) -> &mut TSrc {
        debug_assert!(self.shared.sources.contains(source_id.0));
        match (
            &mut self.inner,
            self.shared.sources.get(source_id.0).unwrap(),
        ) {
            (IdleInner::Optimistic(sync), SourceMapping::Optimistic(src)) => {
                &mut sync.source_user_data_mut(*src).user_data
            }
            (IdleInner::AllForks(sync), SourceMapping::AllForks(src)) => {
                &mut sync.source_user_data_mut(*src).user_data
            }
            (IdleInner::GrandpaWarpSync(sync), SourceMapping::GrandpaWarpSync(src)) => {
                &mut sync.source_user_data_mut(*src).user_data
            }
            (IdleInner::Poisoned, _) => unreachable!(),
            (IdleInner::Optimistic(_), SourceMapping::AllForks(_))
            | (IdleInner::Optimistic(_), SourceMapping::GrandpaWarpSync(_))
            | (IdleInner::AllForks(_), SourceMapping::Optimistic(_))
            | (IdleInner::AllForks(_), SourceMapping::GrandpaWarpSync(_))
            | (IdleInner::GrandpaWarpSync(_), SourceMapping::AllForks(_))
            | (IdleInner::GrandpaWarpSync(_), SourceMapping::Optimistic(_)) => unreachable!(),
        }
    }

    /// Injects a block announcement made by a source into the state machine.
    pub fn block_announce(
        mut self,
        source_id: SourceId,
        announced_scale_encoded_header: Vec<u8>,
        is_best: bool,
    ) -> BlockAnnounceOutcome<TRq, TSrc, TBl> {
        if let Ok(header) = header::decode(&announced_scale_encoded_header) {
            if header.number > self.shared.highest_block_on_network {
                self.shared.highest_block_on_network = header.number;
            }
        }

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
            (IdleInner::AllForks(mut sync), &SourceMapping::AllForks(source_id)) => {
                match sync.block_announce(source_id, announced_scale_encoded_header, is_best) {
                    all_forks::BlockAnnounceOutcome::HeaderVerify => {
                        BlockAnnounceOutcome::HeaderVerify(HeaderVerify {
                            inner: HeaderVerifyInner::AllForks(match sync.process_one() {
                                all_forks::ProcessOne::Idle { .. } => unreachable!(),
                                all_forks::ProcessOne::HeaderVerify(verify) => verify,
                            }),
                            shared: self.shared,
                        })
                    }
                    all_forks::BlockAnnounceOutcome::TooOld => {
                        self.inner = IdleInner::AllForks(sync);
                        BlockAnnounceOutcome::TooOld(self)
                    }
                    all_forks::BlockAnnounceOutcome::AlreadyInChain => {
                        self.inner = IdleInner::AllForks(sync);
                        BlockAnnounceOutcome::AlreadyInChain(self)
                    }
                    all_forks::BlockAnnounceOutcome::NotFinalizedChain => {
                        self.inner = IdleInner::AllForks(sync);
                        BlockAnnounceOutcome::NotFinalizedChain(self)
                    }
                    all_forks::BlockAnnounceOutcome::Disjoint => {
                        let next_actions = self.shared.all_forks_next_actions(&mut sync);
                        self.inner = IdleInner::AllForks(sync);
                        BlockAnnounceOutcome::Disjoint {
                            sync: self,
                            next_actions,
                        }
                    }
                    all_forks::BlockAnnounceOutcome::InvalidHeader(error) => {
                        self.inner = IdleInner::AllForks(sync);
                        BlockAnnounceOutcome::InvalidHeader { sync: self, error }
                    }
                }
            }
            (IdleInner::GrandpaWarpSync(mut sync), &SourceMapping::GrandpaWarpSync(source_id)) => {
                // If GrandPa warp syncing is in progress, the best block of the source is stored
                // in the user data. It will be useful later when transitioning to another
                // syncing strategy.
                if is_best {
                    let mut user_data = sync.source_user_data_mut(source_id);
                    // TODO: this can't panic right now, but it should be made explicit in the API that the header must be valid
                    let header = header::decode(&announced_scale_encoded_header).unwrap();
                    user_data.best_block_number = header.number;
                    user_data.best_block_hash = header.hash();
                }

                self.inner = IdleInner::GrandpaWarpSync(sync);
                BlockAnnounceOutcome::Disjoint {
                    sync: self,
                    next_actions: Vec::new(),
                }
            }
            (IdleInner::Poisoned, _) => unreachable!(),

            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (IdleInner::Optimistic(_), SourceMapping::AllForks(_)) => unreachable!(),
            (IdleInner::Optimistic(_), SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
            (IdleInner::GrandpaWarpSync(_), SourceMapping::AllForks(_)) => unreachable!(),
            (IdleInner::GrandpaWarpSync(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (IdleInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (IdleInner::AllForks(_), SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
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
    ) -> ResponseOutcome<TRq, TSrc, TBl> {
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

                        ResponseOutcome::Queued {
                            sync: Idle {
                                inner: IdleInner::Optimistic(sync),
                                shared: self.shared,
                            },
                            next_actions,
                        }
                    }
                    other => ResponseOutcome::VerifyHeader(HeaderVerify {
                        inner: HeaderVerifyInner::Optimistic(other),
                        shared: self.shared,
                    }),
                }
            }
            (IdleInner::AllForks(mut sync), RequestMapping::AllForks(request_id)) => {
                match sync.finish_ancestry_search(
                    request_id,
                    blocks.map(|iter| {
                        iter.map(|block| all_forks::RequestSuccessBlock {
                            scale_encoded_header: block.scale_encoded_header,
                            scale_encoded_justification: block.scale_encoded_justification,
                        })
                    }),
                ) {
                    all_forks::AncestrySearchResponseOutcome::Verify => match sync.process_one() {
                        all_forks::ProcessOne::Idle { mut sync } => {
                            let next_actions = self.shared.all_forks_next_actions(&mut sync);
                            ResponseOutcome::Queued {
                                sync: Idle {
                                    inner: IdleInner::AllForks(sync),
                                    shared: self.shared,
                                },
                                next_actions,
                            }
                        }
                        all_forks::ProcessOne::HeaderVerify(verify) => {
                            ResponseOutcome::VerifyHeader(HeaderVerify {
                                inner: HeaderVerifyInner::AllForks(verify),
                                shared: self.shared,
                            })
                        }
                    },
                    all_forks::AncestrySearchResponseOutcome::NotFinalizedChain {
                        discarded_unverified_block_headers,
                    } => {
                        let next_actions = self.shared.all_forks_next_actions(&mut sync);
                        ResponseOutcome::NotFinalizedChain {
                            sync: Idle {
                                inner: IdleInner::AllForks(sync),
                                ..self
                            },
                            next_actions,
                            discarded_unverified_block_headers,
                        }
                    }
                    all_forks::AncestrySearchResponseOutcome::Inconclusive => {
                        let next_actions = self.shared.all_forks_next_actions(&mut sync);
                        ResponseOutcome::Queued {
                            sync: Idle {
                                inner: IdleInner::AllForks(sync),
                                ..self
                            },
                            next_actions,
                        }
                    }
                    all_forks::AncestrySearchResponseOutcome::AllAlreadyInChain => {
                        let next_actions = self.shared.all_forks_next_actions(&mut sync);
                        ResponseOutcome::AllAlreadyInChain {
                            sync: Idle {
                                inner: IdleInner::AllForks(sync),
                                ..self
                            },
                            next_actions,
                        }
                    }
                }
            }
            // TODO: not all variants implemented
            _ => panic!(),
        }
    }

    /// Inject a response to a previously-emitted GrandPa warp sync request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    pub fn grandpa_warp_sync_response(
        mut self,
        request_id: RequestId,
        // TODO: don't use crate::network::protocol
        // TODO: Result instead of Option?
        response: Option<crate::network::protocol::GrandpaWarpSyncResponse>,
    ) -> ResponseOutcome<TRq, TSrc, TBl> {
        debug_assert!(self.shared.requests.contains(request_id.0));
        let request = self.shared.requests.remove(request_id.0);
        assert!(matches!(request, RequestMapping::GrandpaWarpSync));

        match self.inner {
            IdleInner::GrandpaWarpSync(
                grandpa_warp_sync::InProgressGrandpaWarpSync::WarpSyncRequest(grandpa),
            ) => {
                let grandpa_warp_sync = grandpa.handle_response(response);
                Self::from_in_progress_grandpa(grandpa_warp_sync, self.shared)
            }

            // Only the GrandPa warp syncing ever starts GrandPa warp sync requests.
            _ => unreachable!(),
        }
    }

    /// Inject a response to a previously-emitted storage proof request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    /// Panics if the number of items in the response doesn't match the number of keys that have
    /// been requested.
    ///
    pub fn storage_get_response(
        mut self,
        request_id: RequestId,
        response: Result<impl Iterator<Item = Option<impl AsRef<[u8]>>>, ()>,
    ) -> ResponseOutcome<TRq, TSrc, TBl> {
        debug_assert!(self.shared.requests.contains(request_id.0));
        let request = self.shared.requests.remove(request_id.0);
        assert!(matches!(request, RequestMapping::GrandpaWarpSync));

        let mut response = response.unwrap(); // TODO: handle this properly; requires changes in the grandpa warp sync machine

        match self.inner {
            IdleInner::GrandpaWarpSync(
                grandpa_warp_sync::InProgressGrandpaWarpSync::VirtualMachineParamsGet(sync),
            ) => {
                // In this state, we expect the response to be one value for `:code` and one for
                // `:heappages`. As documented, we panic if the number of items isn't 2.
                let code = response.next().unwrap();
                let heap_pages = response.next().unwrap();
                assert!(response.next().is_none());

                // TODO: we use `Oneshot` because the VM is thrown away afterwards; ideally it wouldn't be be thrown away
                let (grandpa_warp_sync, error) =
                    sync.set_virtual_machine_params(code, heap_pages, ExecHint::Oneshot);

                if let Some(error) = error {
                    // TODO: error handling
                }

                Self::from_grandpa(grandpa_warp_sync, self.shared)
            }
            IdleInner::GrandpaWarpSync(
                grandpa_warp_sync::InProgressGrandpaWarpSync::StorageGet(sync),
            ) => {
                // In this state, we expect the response to be one value. As documented, we panic
                // if the number of items isn't 1.
                let value = response.next().unwrap();
                assert!(response.next().is_none());

                let (grandpa_warp_sync, error) = sync.inject_value(value.map(iter::once));

                if let Some(error) = error {
                    // TODO: error handling
                }

                Self::from_grandpa(grandpa_warp_sync, self.shared)
            }
            // Only the GrandPa warp syncing ever starts GrandPa warp sync requests.
            _ => panic!(),
        }
    }

    fn from_grandpa(
        grandpa_warp_sync: grandpa_warp_sync::GrandpaWarpSync<GrandpaWarpSyncSourceExtra<TSrc>>,
        mut shared: Shared,
    ) -> ResponseOutcome<TRq, TSrc, TBl> {
        match grandpa_warp_sync {
            grandpa_warp_sync::GrandpaWarpSync::InProgress(in_progress) => {
                Self::from_in_progress_grandpa(in_progress, shared)
            }
            grandpa_warp_sync::GrandpaWarpSync::Finished(success) => {
                let (all_forks, next_actions) =
                    shared.transition_grandpa_warp_sync_all_forks(success);
                return ResponseOutcome::WarpSyncFinished {
                    sync: Idle {
                        inner: IdleInner::AllForks(all_forks),
                        shared,
                    },
                    next_actions,
                };
            }
        }
    }

    fn from_in_progress_grandpa(
        mut grandpa_warp_sync: grandpa_warp_sync::InProgressGrandpaWarpSync<
            GrandpaWarpSyncSourceExtra<TSrc>,
        >,
        mut shared: Shared,
    ) -> ResponseOutcome<TRq, TSrc, TBl> {
        loop {
            match grandpa_warp_sync {
                grandpa_warp_sync::InProgressGrandpaWarpSync::StorageGet(get) => {
                    debug_assert!(shared.requests.is_empty());
                    let request_id =
                        RequestId(shared.requests.insert(RequestMapping::GrandpaWarpSync));
                    let outer_source_id = get.warp_sync_source().outer_source_id;
                    let action = Action::Start {
                        request_id,
                        source_id: outer_source_id,
                        detail: RequestDetail::StorageGet {
                            block_hash: get.warp_sync_header().hash(),
                            state_trie_root: *get.warp_sync_header().state_root,
                            keys: vec![get.key_as_vec()],
                        },
                    };

                    return ResponseOutcome::Queued {
                        sync: Idle {
                            inner: IdleInner::GrandpaWarpSync(get.into()),
                            shared,
                        },
                        next_actions: vec![action],
                    };
                }
                grandpa_warp_sync::InProgressGrandpaWarpSync::NextKey(_next_key) => {
                    todo!()
                }
                grandpa_warp_sync::InProgressGrandpaWarpSync::Verifier(verifier) => {
                    let (next_grandpa_warp_sync, _error) = verifier.next();
                    grandpa_warp_sync = next_grandpa_warp_sync;
                }
                grandpa_warp_sync::InProgressGrandpaWarpSync::WarpSyncRequest(rq) => {
                    let action = shared.grandpa_warp_sync_request_to_request(&rq);
                    return ResponseOutcome::Queued {
                        sync: Idle {
                            inner: IdleInner::GrandpaWarpSync(rq.into()),
                            shared,
                        },
                        next_actions: vec![action],
                    };
                }
                grandpa_warp_sync::InProgressGrandpaWarpSync::VirtualMachineParamsGet(rq) => {
                    debug_assert!(shared.requests.is_empty());
                    let request_id =
                        RequestId(shared.requests.insert(RequestMapping::GrandpaWarpSync));
                    let outer_source_id = rq.warp_sync_source().outer_source_id;
                    let action = Action::Start {
                        request_id,
                        source_id: outer_source_id,
                        detail: RequestDetail::StorageGet {
                            block_hash: rq.warp_sync_header().hash(),
                            state_trie_root: *rq.warp_sync_header().state_root,
                            keys: vec![b":code".to_vec(), b":heappages".to_vec()],
                        },
                    };

                    return ResponseOutcome::Queued {
                        sync: Idle {
                            inner: IdleInner::GrandpaWarpSync(rq.into()),
                            shared,
                        },
                        next_actions: vec![action],
                    };
                }
                gp @ grandpa_warp_sync::InProgressGrandpaWarpSync::WaitingForSources(_) => {
                    return ResponseOutcome::Queued {
                        sync: Idle {
                            inner: IdleInner::GrandpaWarpSync(gp),
                            shared,
                        },
                        next_actions: Vec::new(),
                    }
                }
            }
        }
    }
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

/// See [`Action::Start::detail`].
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
        /// Hash of the known finalized block. Starting point of the request.
        sync_start_block_hash: [u8; 32],
    },

    /// Sending a storage query is requested.
    StorageGet {
        /// Hash of the block whose storage is requested.
        block_hash: [u8; 32],
        /// Merkle value of the root of the storage trie of the block.
        state_trie_root: [u8; 32],
        /// Keys whose values is requested.
        keys: Vec<Vec<u8>>,
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

/// Outcome of injecting a response in the [`Idle`].
pub enum ResponseOutcome<TRq, TSrc, TBl> {
    /// Ready to start verifying one or more headers returned in the ancestry search.
    VerifyHeader(HeaderVerify<TRq, TSrc, TBl>),

    /// Content of the response has been queued and will be processed later.
    Queued {
        sync: Idle<TRq, TSrc, TBl>,

        /// Next requests that must be started.
        next_actions: Vec<Action>,
    },

    /// Response has made it possible to finish warp syncing.
    WarpSyncFinished {
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
    inner: HeaderVerifyInner<TRq, TSrc, TBl>,
    shared: Shared,
}

enum HeaderVerifyInner<TRq, TSrc, TBl> {
    AllForks(all_forks::HeaderVerify<TBl, AllForksRequestExtra<TRq>, AllForksSourceExtra<TSrc>>),
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
            HeaderVerifyInner::Optimistic(optimistic::ProcessOne::NewBest { .. })
            | HeaderVerifyInner::Optimistic(optimistic::ProcessOne::Finalized { .. }) => {
                let (mut sync, new_best_number, is_new_finalized) = match self.inner {
                    HeaderVerifyInner::Optimistic(optimistic::ProcessOne::NewBest {
                        sync,
                        new_best_number,
                        ..
                    }) => (sync, new_best_number, false),
                    HeaderVerifyInner::Optimistic(optimistic::ProcessOne::Finalized {
                        sync,
                        finalized_blocks,
                        ..
                    }) => (sync, finalized_blocks.last().unwrap().header.number, true),
                    _ => unreachable!(),
                };

                if new_best_number >= self.shared.highest_block_on_network - 1024 {
                    // TODO: do this better ^
                    let (all_forks, next_actions) =
                        self.shared.transition_optimistic_all_forks(sync);
                    return HeaderVerifyOutcome::Success {
                        is_new_best: true,
                        is_new_finalized,
                        sync: Idle {
                            inner: IdleInner::AllForks(all_forks),
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
                        is_new_finalized,
                        sync: Idle {
                            inner: IdleInner::Optimistic(sync),
                            shared: self.shared,
                        }
                        .into(),
                        next_actions,
                    },
                    other => {
                        self.inner = HeaderVerifyInner::Optimistic(other);
                        HeaderVerifyOutcome::Success {
                            is_new_finalized,
                            is_new_best: true,
                            sync: self.into(),
                            next_actions,
                        }
                    }
                }
            }
            HeaderVerifyInner::Optimistic(optimistic::ProcessOne::Reset { mut sync, .. }) => {
                let mut next_actions = Vec::new();
                while let Some(action) = sync.next_request_action() {
                    next_actions.push(self.shared.optimistic_action_to_request(action));
                }

                match sync.process_one(now_from_unix_epoch) {
                    optimistic::ProcessOne::Idle { sync } => HeaderVerifyOutcome::Error {
                        sync: Idle {
                            inner: IdleInner::Optimistic(sync),
                            shared: self.shared,
                        }
                        .into(),
                        next_actions,
                        error: verify::header_only::Error::BadBlockNumber, // TODO: this is the completely wrong error; needs some deeper API changes
                        user_data,
                    },
                    other => {
                        self.inner = HeaderVerifyInner::Optimistic(other);
                        HeaderVerifyOutcome::Error {
                            sync: self.into(),
                            next_actions,
                            error: verify::header_only::Error::BadBlockNumber, // TODO: this is the completely wrong error; needs some deeper API changes
                            user_data,
                        }
                    }
                }
            }
            HeaderVerifyInner::Optimistic(optimistic::ProcessOne::FinalizedStorageGet(_))
            | HeaderVerifyInner::Optimistic(optimistic::ProcessOne::FinalizedStorageNextKey(_))
            | HeaderVerifyInner::Optimistic(optimistic::ProcessOne::FinalizedStoragePrefixKeys(
                _,
            )) => {
                unreachable!()
            }
            HeaderVerifyInner::AllForks(verify) => {
                match verify.perform(now_from_unix_epoch, user_data) {
                    all_forks::HeaderVerifyOutcome::Success {
                        is_new_best,
                        mut sync,
                        justification_verification,
                    } => {
                        let next_actions = self.shared.all_forks_next_actions(&mut sync);
                        HeaderVerifyOutcome::Success {
                            is_new_best,
                            is_new_finalized: justification_verification.is_success(),
                            sync: Idle {
                                inner: IdleInner::AllForks(sync),
                                shared: self.shared,
                            }
                            .into(),
                            next_actions,
                        }
                    }
                    all_forks::HeaderVerifyOutcome::Error {
                        mut sync,
                        error,
                        user_data,
                    } => {
                        let next_actions = self.shared.all_forks_next_actions(&mut sync);
                        HeaderVerifyOutcome::Error {
                            sync: Idle {
                                inner: IdleInner::AllForks(sync),
                                shared: self.shared,
                            }
                            .into(),
                            error,
                            user_data,
                            next_actions,
                        }
                    }
                }
            }
        }
    }
}

/// Outcome of calling [`HeaderVerify::perform`].
pub enum HeaderVerifyOutcome<TRq, TSrc, TBl> {
    /// Header has been successfully verified.
    Success {
        /// True if the newly-verified block is considered the new best block.
        is_new_best: bool,
        /// True if the newly-verified block is considered the latest finalized block.
        is_new_finalized: bool,
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

enum IdleInner<TRq, TSrc, TBl> {
    Optimistic(optimistic::OptimisticSync<(), OptimisticSourceExtra<TSrc>, TBl>),
    /// > **Note**: Must never contain [`grandpa_warp_sync::GrandpaWarpSync::Finished`].
    GrandpaWarpSync(grandpa_warp_sync::InProgressGrandpaWarpSync<GrandpaWarpSyncSourceExtra<TSrc>>),
    AllForks(all_forks::AllForksSync<TBl, AllForksRequestExtra<TRq>, AllForksSourceExtra<TSrc>>),
    Poisoned,
}

struct OptimisticSourceExtra<TSrc> {
    user_data: TSrc,
    best_block_hash: [u8; 32],
    outer_source_id: SourceId,
}

struct AllForksSourceExtra<TSrc> {
    outer_source_id: SourceId,
    user_data: TSrc,
}

struct AllForksRequestExtra<TRq> {
    outer_request_id: RequestId,
    user_data: Option<TRq>,
}

struct GrandpaWarpSyncSourceExtra<TSrc> {
    outer_source_id: SourceId,
    user_data: TSrc,
    best_block_number: u64,
    best_block_hash: [u8; 32],
}

struct Shared {
    sources: slab::Slab<SourceMapping>,
    requests: slab::Slab<RequestMapping>,
    // TODO: this is an insecure way to do things; see https://github.com/paritytech/smoldot/issues/490
    highest_block_on_network: u64,
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
                        request_justification: true,
                    },
                }
            }
            optimistic::RequestAction::Cancel { request_id, .. } => {
                // TODO: O(n); store the outer ID in the user data instead
                let outer_request_id = self
                    .requests
                    .iter()
                    .find(|(id, s)| **s == RequestMapping::Optimistic(request_id))
                    .map(|(id, _)| RequestId(id))
                    .unwrap();
                self.requests.remove(outer_request_id.0);
                Action::Cancel(outer_request_id)
            }
        }
    }

    fn all_forks_next_actions<TRq, TSrc, TBl>(
        &mut self,
        all_forks: &mut all_forks::AllForksSync<
            TBl,
            AllForksRequestExtra<TRq>,
            AllForksSourceExtra<TSrc>,
        >,
    ) -> Vec<Action> {
        let mut out = Vec::new();

        loop {
            let (source_id, request_details) = match all_forks.desired_requests().next() {
                Some(s) => s,
                None => break,
            };

            let request_mapping_entry = self.requests.vacant_entry();
            let outer_request_id = RequestId(request_mapping_entry.key());

            let inner_request_id = all_forks.add_request(
                source_id,
                request_details,
                AllForksRequestExtra {
                    outer_request_id,
                    user_data: None,
                },
            );

            request_mapping_entry.insert(RequestMapping::AllForks(inner_request_id));

            let outer_source_id = all_forks.source_user_data(source_id).outer_source_id;

            out.push(Action::Start {
                request_id: outer_request_id,
                source_id: outer_source_id,
                detail: RequestDetail::BlocksRequest {
                    first_block: BlocksRequestFirstBlock::Hash(request_details.first_block_hash),
                    ascending: false,
                    num_blocks: request_details.num_blocks,
                    request_bodies: false,
                    request_headers: true,
                    request_justification: true, // TODO: only do this on blocks that change the GP authorities?
                },
            });
        }

        out
    }

    fn grandpa_warp_sync_request_to_request<TSrc>(
        &mut self,
        grandpa_warp_sync: &grandpa_warp_sync::WarpSyncRequest<GrandpaWarpSyncSourceExtra<TSrc>>,
    ) -> Action {
        debug_assert!(self.requests.is_empty());
        let request_id = RequestId(self.requests.insert(RequestMapping::GrandpaWarpSync));
        let outer_source_id = grandpa_warp_sync.current_source().1.outer_source_id;
        Action::Start {
            request_id,
            source_id: outer_source_id,
            detail: RequestDetail::GrandpaWarpSync {
                sync_start_block_hash: grandpa_warp_sync.start_block_hash(),
            },
        }
    }

    /// Transitions the sync state machine from the optimistic strategy to the "all-forks"
    /// strategy.
    fn transition_optimistic_all_forks<TRq, TSrc, TBl>(
        &mut self,
        optimistic: optimistic::OptimisticSync<(), OptimisticSourceExtra<TSrc>, TBl>,
    ) -> (
        all_forks::AllForksSync<TBl, AllForksRequestExtra<TRq>, AllForksSourceExtra<TSrc>>,
        Vec<Action>,
    ) {
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

        for source in disassembled.sources {
            let updated_source_id = all_forks.add_source(
                AllForksSourceExtra {
                    user_data: source.user_data.user_data,
                    outer_source_id: source.user_data.outer_source_id,
                },
                source.best_block_number,
                source.user_data.best_block_hash,
            );

            debug_assert_eq!(
                self.sources[source.user_data.outer_source_id.0],
                SourceMapping::Optimistic(source.id)
            );

            self.sources[source.user_data.outer_source_id.0] =
                SourceMapping::AllForks(updated_source_id);
        }

        debug_assert!(self
            .sources
            .iter()
            .all(|(_, s)| matches!(s, SourceMapping::AllForks(_))));

        let mut next_actions = Vec::with_capacity(self.requests.len());
        for (request_id, _) in self.requests.iter() {
            next_actions.push(Action::Cancel(RequestId(request_id)));
        }
        self.requests.clear();

        next_actions.extend(self.all_forks_next_actions(&mut all_forks));
        (all_forks, next_actions)
    }

    /// Transitions the sync state machine from the grandpa warp strategy to the "all-forks"
    /// strategy.
    fn transition_grandpa_warp_sync_all_forks<TRq, TSrc, TBl>(
        &mut self,
        grandpa: grandpa_warp_sync::Success<GrandpaWarpSyncSourceExtra<TSrc>>,
    ) -> (
        all_forks::AllForksSync<TBl, AllForksRequestExtra<TRq>, AllForksSourceExtra<TSrc>>,
        Vec<Action>,
    ) {
        debug_assert!(self.requests.is_empty()); // GrandPa only does one request at a time
        debug_assert!(self
            .sources
            .iter()
            .all(|(_, s)| matches!(s, SourceMapping::GrandpaWarpSync(_))));

        // TODO: arbitrary config
        let mut all_forks = all_forks::AllForksSync::new(all_forks::Config {
            chain_information: grandpa.chain_information,
            sources_capacity: 1024,
            blocks_capacity: 1024,
            max_disjoint_headers: 1024,
            max_requests_per_block: NonZeroU32::new(128).unwrap(),
            full: false,
        });

        for source in grandpa.sources {
            let updated_source_id = all_forks.add_source(
                AllForksSourceExtra {
                    user_data: source.user_data,
                    outer_source_id: source.outer_source_id,
                },
                source.best_block_number,
                source.best_block_hash,
            );

            self.sources[source.outer_source_id.0] = SourceMapping::AllForks(updated_source_id);
        }

        debug_assert!(self
            .sources
            .iter()
            .all(|(_, s)| matches!(s, SourceMapping::AllForks(_))));

        let mut next_actions = Vec::with_capacity(self.requests.len());
        self.requests.clear();

        next_actions.extend(self.all_forks_next_actions(&mut all_forks));
        (all_forks, next_actions)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestMapping {
    Optimistic(optimistic::RequestId),
    GrandpaWarpSync,
    AllForks(all_forks::RequestId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SourceMapping {
    Optimistic(optimistic::SourceId),
    GrandpaWarpSync(grandpa_warp_sync::SourceId),
    AllForks(all_forks::SourceId),
}
