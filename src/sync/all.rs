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
//! A *request* represents a query for information from a source. Once the request has finished,
//! call one of the methods of the [`AllSync`] in order to notify the state machine of the oucome.

use crate::{
    chain::{blocks_tree, chain_information},
    executor::{host, vm::ExecHint},
    header,
    sync::{all_forks, grandpa_warp_sync, optimistic},
    verify,
};

use alloc::{vec, vec::Vec};

use core::{
    convert::TryFrom as _,
    iter, mem,
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};

/// Configuration for the [`AllSync`].
// TODO: review these fields
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

    /// Maximum number of blocks of unknown ancestry to keep in memory.
    ///
    /// See [`all_forks::Config::max_disjoint_headers`] for more information.
    pub max_disjoint_headers: usize,

    /// Maximum number of simultaneous pending requests made towards the same block.
    ///
    /// See [`all_forks::Config::max_requests_per_block`] for more information.
    pub max_requests_per_block: NonZeroU32,

    /// Number of blocks to download ahead of the best verified block.
    ///
    /// Whenever the latest best block is updated, the state machine will start block
    /// requests for the block `best_block_height + download_ahead_blocks` and all its
    /// ancestors. Considering that requesting blocks has some latency, downloading blocks ahead
    /// of time ensures that verification isn't blocked waiting for a request to be finished.
    ///
    /// The ideal value here depends on the speed of blocks verification speed and latency of
    /// block requests.
    pub download_ahead_blocks: u32,

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

/// Identifier for a source in the [`AllSync`].
//
// Implementation note: this is an index in `AllSync::sources`.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SourceId(usize);

/// Identifier for a request in the [`AllSync`].
//
// Implementation note: this is an index in `AllSync::requests`.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RequestId(usize);

pub struct AllSync<TRq, TSrc, TBl> {
    inner: AllSyncInner<TRq, TSrc, TBl>,
    shared: Shared<TRq>,
}

impl<TRq, TSrc, TBl> AllSync<TRq, TSrc, TBl> {
    /// Initializes a new state machine.
    pub fn new(config: Config) -> Self {
        AllSync {
            inner: if let Some(config_full) = config.full {
                AllSyncInner::Optimistic {
                    inner: optimistic::OptimisticSync::new(optimistic::Config {
                        chain_information: config.chain_information,
                        sources_capacity: config.sources_capacity,
                        blocks_capacity: config.blocks_capacity,
                        blocks_request_granularity: NonZeroU32::new(256).unwrap(), // TODO: ask through config
                        download_ahead_blocks: config.download_ahead_blocks,
                        full: Some(optimistic::ConfigFull {
                            finalized_runtime: config_full.finalized_runtime,
                        }),
                    }),
                }
            } else {
                AllSyncInner::GrandpaWarpSync {
                    inner: grandpa_warp_sync::grandpa_warp_sync(grandpa_warp_sync::Config {
                        start_chain_information: config.chain_information,
                        sources_capacity: config.sources_capacity,
                    }),
                }
            },
            shared: Shared {
                sources: slab::Slab::with_capacity(config.sources_capacity),
                requests: slab::Slab::with_capacity(config.sources_capacity),
                sources_capacity: config.sources_capacity,
                blocks_capacity: config.blocks_capacity,
                max_disjoint_headers: config.max_disjoint_headers,
                max_requests_per_block: config.max_requests_per_block,
            },
        }
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct corresponding to the current
    /// latest finalized block. Can later be used to reconstruct a chain.
    pub fn as_chain_information(&self) -> chain_information::ValidChainInformationRef {
        match &self.inner {
            AllSyncInner::AllForks(sync) => sync.as_chain_information(),
            AllSyncInner::GrandpaWarpSync { inner: sync } => sync.as_chain_information(),
            AllSyncInner::Optimistic { inner } => inner.as_chain_information(),
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the header of the finalized block.
    pub fn finalized_block_header(&self) -> header::HeaderRef {
        match &self.inner {
            AllSyncInner::AllForks(sync) => sync.finalized_block_header(),
            AllSyncInner::Optimistic { inner } => inner.finalized_block_header(),
            AllSyncInner::GrandpaWarpSync { inner: sync } => {
                sync.as_chain_information().as_ref().finalized_block_header
            }
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the header of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_header(&self) -> header::HeaderRef {
        match &self.inner {
            AllSyncInner::AllForks(sync) => sync.best_block_header(),
            AllSyncInner::Optimistic { inner } => inner.best_block_header(),
            AllSyncInner::GrandpaWarpSync { .. } => self.finalized_block_header(),
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the number of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_number(&self) -> u64 {
        match &self.inner {
            AllSyncInner::AllForks(sync) => sync.best_block_number(),
            AllSyncInner::Optimistic { inner } => inner.best_block_number(),
            AllSyncInner::GrandpaWarpSync { .. } => self.best_block_header().number,
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the hash of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_hash(&self) -> [u8; 32] {
        match &self.inner {
            AllSyncInner::AllForks(sync) => sync.best_block_hash(),
            AllSyncInner::Optimistic { inner } => inner.best_block_hash(),
            AllSyncInner::GrandpaWarpSync { .. } => self.best_block_header().hash(),
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the header of all known non-finalized blocks in the chain.
    ///
    /// The order of the blocks is unspecified.
    pub fn non_finalized_blocks(&self) -> impl Iterator<Item = header::HeaderRef> {
        match &self.inner {
            AllSyncInner::AllForks(sync) => {
                let iter = sync.non_finalized_blocks();
                either::Left(iter)
            }
            AllSyncInner::Optimistic { inner } => {
                let iter = inner.non_finalized_blocks();
                either::Right(either::Left(iter))
            }
            AllSyncInner::GrandpaWarpSync { .. } => either::Right(either::Right(iter::empty())),
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns true if it is believed that we are near the head of the chain.
    ///
    /// The way this method is implemented is opaque and cannot be relied on. The return value
    /// should only ever be shown to the user and not used for any meaningful logic.
    pub fn is_near_head_of_chain_heuristic(&self) -> bool {
        match &self.inner {
            AllSyncInner::AllForks(_) => true,
            AllSyncInner::Optimistic { .. } => false,
            AllSyncInner::GrandpaWarpSync { .. } => false,
            AllSyncInner::Poisoned => unreachable!(),
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
    ) -> SourceId {
        // `inner` is temporarily replaced with `Poisoned`. A new value must be put back before
        // returning.
        match mem::replace(&mut self.inner, AllSyncInner::Poisoned) {
            AllSyncInner::GrandpaWarpSync {
                inner: grandpa_warp_sync::InProgressGrandpaWarpSync::WaitingForSources(waiting),
            } => {
                let outer_source_id_entry = self.shared.sources.vacant_entry();
                let outer_source_id = SourceId(outer_source_id_entry.key());

                let warp_sync_request = waiting.add_source(GrandpaWarpSyncSourceExtra {
                    outer_source_id,
                    user_data,
                    best_block_number,
                    best_block_hash,
                });

                let inner_source_id = warp_sync_request.current_source().0;
                outer_source_id_entry.insert(SourceMapping::GrandpaWarpSync(inner_source_id));

                self.inner = AllSyncInner::GrandpaWarpSync {
                    inner: warp_sync_request.into(),
                };

                outer_source_id
            }
            AllSyncInner::GrandpaWarpSync { inner: mut grandpa } => {
                let outer_source_id_entry = self.shared.sources.vacant_entry();
                let outer_source_id = SourceId(outer_source_id_entry.key());

                let source_extra = GrandpaWarpSyncSourceExtra {
                    outer_source_id,
                    user_data,
                    best_block_number,
                    best_block_hash,
                };

                let inner_source_id = match &mut grandpa {
                    grandpa_warp_sync::InProgressGrandpaWarpSync::WaitingForSources(_) => {
                        unreachable!()
                    }
                    grandpa_warp_sync::InProgressGrandpaWarpSync::Verifier(sync) => {
                        sync.add_source(source_extra)
                    }
                    grandpa_warp_sync::InProgressGrandpaWarpSync::WarpSyncRequest(sync) => {
                        sync.add_source(source_extra)
                    }
                    grandpa_warp_sync::InProgressGrandpaWarpSync::VirtualMachineParamsGet(sync) => {
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

                self.inner = AllSyncInner::GrandpaWarpSync { inner: grandpa };
                outer_source_id
            }
            AllSyncInner::AllForks(mut all_forks) => {
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

                self.inner = AllSyncInner::AllForks(all_forks);
                outer_source_id
            }
            AllSyncInner::Optimistic { mut inner } => {
                let outer_source_id_entry = self.shared.sources.vacant_entry();
                let outer_source_id = SourceId(outer_source_id_entry.key());

                let source_id = inner.add_source(
                    OptimisticSourceExtra {
                        user_data,
                        outer_source_id,
                        best_block_hash,
                    },
                    best_block_number,
                );
                outer_source_id_entry.insert(SourceMapping::Optimistic(source_id));

                self.inner = AllSyncInner::Optimistic { inner };
                outer_source_id
            }
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Removes a source from the state machine. Returns the user data of this source, and all
    /// the requests that this source were expected to perform.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] doesn't correspond to a valid source.
    ///
    pub fn remove_source(
        &mut self,
        source_id: SourceId,
    ) -> (TSrc, impl Iterator<Item = (RequestId, RequestDetail, TRq)>) {
        debug_assert!(self.shared.sources.contains(source_id.0));
        match (&mut self.inner, self.shared.sources.remove(source_id.0)) {
            (AllSyncInner::AllForks(sync), SourceMapping::AllForks(source_id)) => {
                let (user_data, requests) = sync.remove_source(source_id);
                let requests = requests
                    .map(
                        |(_inner_request_id, request_params, request_inner_user_data)| {
                            debug_assert!(self
                                .shared
                                .requests
                                .contains(request_inner_user_data.outer_request_id.0));
                            let _removed = self
                                .shared
                                .requests
                                .remove(request_inner_user_data.outer_request_id.0);
                            debug_assert!(matches!(
                                _removed,
                                RequestMapping::AllForks(_inner_request_id)
                            ));

                            (
                                request_inner_user_data.outer_request_id,
                                all_forks_request_convert(request_params),
                                request_inner_user_data.user_data.unwrap(),
                            )
                        },
                    )
                    .collect::<Vec<_>>()
                    .into_iter();

                // TODO: also handle the "inline" requests

                (user_data.user_data, requests)
            }
            (AllSyncInner::Optimistic { inner }, SourceMapping::Optimistic(source_id)) => {
                let (user_data, requests) = inner.remove_source(source_id);
                // TODO: do properly
                let requests = core::iter::empty() /*requests
                    .map(
                        |(_inner_request_id, request_params, request_inner_user_data)| {
                            debug_assert!(self
                                .shared
                                .requests
                                .contains(request_inner_user_data.outer_request_id.0));
                            let _removed = self
                                .shared
                                .requests
                                .remove(request_inner_user_data.outer_request_id.0);
                            debug_assert!(matches!(
                                _removed,
                                RequestMapping::AllForks(_inner_request_id)
                            ));
                            (
                                request_inner_user_data.outer_request_id,
                                all_forks_request_convert(request_params),
                                request_inner_user_data.user_data.unwrap(),
                            )
                        },
                    )*/
                    .collect::<Vec<_>>()
                    .into_iter();

                // TODO: also handle the "inline" requests

                (user_data.user_data, requests)
            }
            (AllSyncInner::GrandpaWarpSync { .. }, SourceMapping::GrandpaWarpSync(source_id)) => {
                let sync = match mem::replace(&mut self.inner, AllSyncInner::Poisoned) {
                    AllSyncInner::GrandpaWarpSync { inner: sync } => sync,
                    _ => unreachable!(),
                };

                let (user_data, grandpa_warp_sync) = sync.remove_source(source_id);
                self.inner = AllSyncInner::GrandpaWarpSync {
                    inner: grandpa_warp_sync,
                };

                (user_data.user_data, Vec::new().into_iter()) // TODO: properly return requests
            }

            (AllSyncInner::Poisoned, _) => unreachable!(),
            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (AllSyncInner::GrandpaWarpSync { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::GrandpaWarpSync { .. }, SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
        }
    }

    /// Returns the list of sources in this state machine.
    pub fn sources(&'_ self) -> impl Iterator<Item = SourceId> + '_ {
        match &self.inner {
            AllSyncInner::GrandpaWarpSync { inner: sync } => {
                let iter = sync
                    .sources()
                    .map(move |id| sync.source_user_data(id).outer_source_id);
                either::Left(either::Left(iter))
            }
            AllSyncInner::Optimistic { inner: sync } => {
                let iter = sync
                    .sources()
                    .map(move |id| sync.source_user_data(id).outer_source_id);
                either::Left(either::Right(iter))
            }
            AllSyncInner::AllForks(sync) => {
                let iter = sync
                    .sources()
                    .map(move |id| sync.source_user_data(id).outer_source_id);
                either::Right(iter)
            }
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the user data (`TSrc`) corresponding to the given source.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn source_user_data(&self, source_id: SourceId) -> &TSrc {
        debug_assert!(self.shared.sources.contains(source_id.0));
        match (&self.inner, self.shared.sources.get(source_id.0).unwrap()) {
            (AllSyncInner::AllForks(sync), SourceMapping::AllForks(src)) => {
                &sync.source_user_data(*src).user_data
            }
            (AllSyncInner::Optimistic { inner }, SourceMapping::Optimistic(src)) => {
                &inner.source_user_data(*src).user_data
            }
            (
                AllSyncInner::GrandpaWarpSync { inner: sync },
                SourceMapping::GrandpaWarpSync(src),
            ) => &sync.source_user_data(*src).user_data,

            (AllSyncInner::Poisoned, _) => unreachable!(),
            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (AllSyncInner::GrandpaWarpSync { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::GrandpaWarpSync { .. }, SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
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
            (AllSyncInner::AllForks(sync), SourceMapping::AllForks(src)) => {
                &mut sync.source_user_data_mut(*src).user_data
            }
            (AllSyncInner::Optimistic { inner }, SourceMapping::Optimistic(src)) => {
                &mut inner.source_user_data_mut(*src).user_data
            }
            (
                AllSyncInner::GrandpaWarpSync { inner: sync },
                SourceMapping::GrandpaWarpSync(src),
            ) => &mut sync.source_user_data_mut(*src).user_data,

            (AllSyncInner::Poisoned, _) => unreachable!(),
            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (AllSyncInner::GrandpaWarpSync { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::GrandpaWarpSync { .. }, SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
        }
    }

    /// Returns the current best block of the given source.
    ///
    /// This corresponds either the latest call to [`AllSync::block_announce`] where `is_best` was
    /// `true`, or to the parameter passed to [`AllSync::add_source`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn source_best_block(&self, source_id: SourceId) -> (u64, &[u8; 32]) {
        debug_assert!(self.shared.sources.contains(source_id.0));
        match (&self.inner, self.shared.sources.get(source_id.0).unwrap()) {
            (AllSyncInner::AllForks(sync), SourceMapping::AllForks(src)) => {
                sync.source_best_block(*src)
            }
            (AllSyncInner::Optimistic { inner }, SourceMapping::Optimistic(src)) => {
                let height = inner.source_best_block(*src);
                let hash = &inner.source_user_data(*src).best_block_hash;
                (height, hash)
            }
            (
                AllSyncInner::GrandpaWarpSync { inner: sync },
                SourceMapping::GrandpaWarpSync(src),
            ) => {
                let ud = sync.source_user_data(*src);
                (ud.best_block_number, &ud.best_block_hash)
            }

            (AllSyncInner::Poisoned, _) => unreachable!(),
            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (AllSyncInner::GrandpaWarpSync { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::GrandpaWarpSync { .. }, SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
        }
    }

    /// Returns true if the source has earlier announced the block passed as parameter or one of
    /// its descendants.
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
        debug_assert!(self.shared.sources.contains(source_id.0));
        match (&self.inner, self.shared.sources.get(source_id.0).unwrap()) {
            (AllSyncInner::AllForks(sync), SourceMapping::AllForks(src)) => {
                sync.source_knows_non_finalized_block(*src, height, hash)
            }
            (AllSyncInner::Optimistic { inner }, SourceMapping::Optimistic(src)) => {
                // TODO: is this correct?
                inner.source_best_block(*src) >= height
            }
            (
                AllSyncInner::GrandpaWarpSync { inner: sync },
                SourceMapping::GrandpaWarpSync(src),
            ) => {
                assert!(
                    height
                        > sync
                            .as_chain_information()
                            .as_ref()
                            .finalized_block_header
                            .number
                );

                let user_data = sync.source_user_data(*src);
                user_data.best_block_hash == *hash && user_data.best_block_number == height
            }

            (AllSyncInner::Poisoned, _) => unreachable!(),
            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (AllSyncInner::GrandpaWarpSync { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::GrandpaWarpSync { .. }, SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
        }
    }

    /// Returns the list of sources for which [`AllSync::source_knows_non_finalized_block`] would
    /// return `true`.
    ///
    /// # Panic
    ///
    /// Panics if `height` is inferior or equal to the finalized block height. Finalized blocks
    /// are intentionally not tracked by this data structure, and panicking when asking for a
    /// potentially-finalized block prevents potentially confusing or erroneous situations.
    ///
    pub fn knows_non_finalized_block(
        &'_ self,
        height: u64,
        hash: &[u8; 32],
    ) -> impl Iterator<Item = SourceId> + '_ {
        match &self.inner {
            AllSyncInner::GrandpaWarpSync { inner: sync } => {
                assert!(
                    height
                        > sync
                            .as_chain_information()
                            .as_ref()
                            .finalized_block_header
                            .number
                );

                let hash = *hash;
                let iter = sync
                    .sources()
                    .filter(move |source_id| {
                        let user_data = sync.source_user_data(*source_id);
                        user_data.best_block_hash == hash && user_data.best_block_number == height
                    })
                    .map(move |id| sync.source_user_data(id).outer_source_id);

                either::Right(either::Left(iter))
            }
            AllSyncInner::AllForks(sync) => {
                let iter = sync
                    .knows_non_finalized_block(height, hash)
                    .map(move |id| sync.source_user_data(id).outer_source_id);
                either::Left(iter)
            }
            AllSyncInner::Optimistic { inner } => {
                // TODO: is this correct?
                let iter = inner
                    .sources()
                    .filter(move |source_id| inner.source_best_block(*source_id) >= height)
                    .map(move |source_id| inner.source_user_data(source_id).outer_source_id);
                either::Right(either::Right(iter))
            }
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the details of a request to start towards a source.
    ///
    /// This method doesn't modify the state machine in any way. [`AllSync::add_request`] must be
    /// called in order for the request to actually be marked as started.
    pub fn desired_requests(&'_ self) -> impl Iterator<Item = (SourceId, RequestDetail)> + '_ {
        match &self.inner {
            AllSyncInner::AllForks(sync) => {
                let iter = sync
                    .desired_requests()
                    .map(move |(inner_source_id, rq_params)| {
                        (
                            sync.source_user_data(inner_source_id).outer_source_id,
                            all_forks_request_convert(rq_params),
                        )
                    });

                either::Left(iter)
            }
            AllSyncInner::Optimistic { inner } => {
                let iter = inner.desired_requests().map(move |rq_detail| {
                    (
                        inner.source_user_data(rq_detail.source_id).outer_source_id,
                        optimistic_request_convert(rq_detail),
                    )
                });

                either::Right(either::Left(iter))
            }
            AllSyncInner::GrandpaWarpSync { inner } => {
                // Grandpa warp sync only ever requires one request at a time. Determine which
                // one it is, if any.
                let desired_request = match inner {
                    grandpa_warp_sync::InProgressGrandpaWarpSync::WarpSyncRequest(rq) => Some((
                        rq.current_source().1.outer_source_id,
                        RequestDetail::GrandpaWarpSync {
                            sync_start_block_hash: rq.start_block_hash(),
                        },
                    )),
                    grandpa_warp_sync::InProgressGrandpaWarpSync::StorageGet(get) => Some((
                        get.warp_sync_source().1.outer_source_id,
                        RequestDetail::StorageGet {
                            block_hash: get.warp_sync_header().hash(),
                            state_trie_root: *get.warp_sync_header().state_root,
                            keys: vec![get.key_as_vec()],
                        },
                    )),
                    grandpa_warp_sync::InProgressGrandpaWarpSync::VirtualMachineParamsGet(rq) => {
                        Some((
                            rq.warp_sync_source().1.outer_source_id,
                            RequestDetail::StorageGet {
                                block_hash: rq.warp_sync_header().hash(),
                                state_trie_root: *rq.warp_sync_header().state_root,
                                keys: vec![b":code".to_vec(), b":heappages".to_vec()],
                            },
                        ))
                    }
                    _ => None,
                };

                let iter = if let Some(desired_request) = desired_request {
                    if self.shared.requests.iter().any(|(_, rq)| match rq {
                        RequestMapping::Inline(src_id, ud, _) => {
                            (src_id, ud) == (&desired_request.0, &desired_request.1)
                        }
                        _ => false,
                    }) {
                        either::Left(iter::empty())
                    } else {
                        either::Right(iter::once(desired_request))
                    }
                } else {
                    either::Left(iter::empty())
                };

                either::Right(either::Right(iter))
            }
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Inserts a new request in the data structure.
    ///
    /// > **Note**: The request doesn't necessarily have to match a request returned by
    /// >           [`AllSync::desired_requests`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn add_request(
        &mut self,
        source_id: SourceId,
        detail: RequestDetail,
        user_data: TRq,
    ) -> RequestId {
        match (&mut self.inner, &detail) {
            (
                AllSyncInner::AllForks(sync),
                RequestDetail::BlocksRequest {
                    ascending: false, // TODO: ?
                    first_block_hash: Some(first_block_hash),
                    first_block_height,
                    num_blocks,
                    ..
                },
            ) => {
                let inner_source_id = match self.shared.sources.get(source_id.0).unwrap() {
                    SourceMapping::AllForks(inner_source_id) => *inner_source_id,
                    _ => unreachable!(),
                };

                let request_mapping_entry = self.shared.requests.vacant_entry();
                let outer_request_id = RequestId(request_mapping_entry.key());

                let inner_request_id = sync.add_request(
                    inner_source_id,
                    all_forks::RequestParams {
                        first_block_hash: *first_block_hash,
                        first_block_height: *first_block_height,
                        num_blocks: *num_blocks,
                    },
                    AllForksRequestExtra {
                        outer_request_id,
                        user_data: Some(user_data),
                    },
                );

                request_mapping_entry.insert(RequestMapping::AllForks(inner_request_id));
                return outer_request_id;
            }
            (
                AllSyncInner::Optimistic { inner },
                RequestDetail::BlocksRequest {
                    ascending: true, // TODO: ?
                    first_block_height,
                    num_blocks,
                    ..
                },
            ) => {
                let inner_source_id = match self.shared.sources.get(source_id.0).unwrap() {
                    SourceMapping::Optimistic(inner_source_id) => *inner_source_id,
                    _ => unreachable!(),
                };

                let request_mapping_entry = self.shared.requests.vacant_entry();
                let outer_request_id = RequestId(request_mapping_entry.key());

                let inner_request_id = inner.insert_request(
                    optimistic::RequestDetail {
                        source_id: inner_source_id,
                        block_height: NonZeroU64::new(*first_block_height).unwrap(), // TODO: correct to unwrap?
                        num_blocks: NonZeroU32::new(u32::try_from(num_blocks.get()).unwrap())
                            .unwrap(), // TODO: don't unwrap
                    },
                    OptimisticRequestExtra {
                        outer_request_id,
                        user_data,
                    },
                );

                request_mapping_entry.insert(RequestMapping::Optimistic(inner_request_id));
                return outer_request_id;
            }
            (AllSyncInner::AllForks { .. }, _) => {}
            (AllSyncInner::Optimistic { .. }, _) => {}
            (AllSyncInner::GrandpaWarpSync { .. }, _) => {}
            (AllSyncInner::Poisoned, _) => unreachable!(),
        }

        RequestId(
            self.shared
                .requests
                .insert(RequestMapping::Inline(source_id, detail, user_data)),
        )
    }

    /// Returns a list of requests that are considered obsolete and can be removed using
    /// [`AllSync::blocks_request_response`] or similar.
    ///
    /// A request becomes obsolete if the state of the request blocks changes in such a way that
    /// they don't need to be requested anymore. The response to the request will be useless.
    ///
    /// > **Note**: It is in no way mandatory to actually call this function and cancel the
    /// >           requests that are returned.
    pub fn obsolete_requests(&'_ self) -> impl Iterator<Item = RequestId> + '_ {
        match &self.inner {
            AllSyncInner::AllForks(sync) => {
                let iter = sync
                    .obsolete_requests()
                    .map(move |(_, rq)| rq.outer_request_id)
                    .chain(
                        self.shared
                            .requests
                            .iter()
                            .filter(|(_, rq)| matches!(rq, RequestMapping::Inline(..)))
                            .map(|(id, _)| RequestId(id)),
                    );
                either::Left(iter)
            }
            AllSyncInner::Optimistic { inner } => {
                let iter = inner
                    .obsolete_requests()
                    .map(move |(_, rq)| rq.outer_request_id)
                    .chain(
                        self.shared
                            .requests
                            .iter()
                            .filter(|(_, rq)| matches!(rq, RequestMapping::Inline(..)))
                            .map(|(id, _)| RequestId(id)),
                    );
                either::Right(either::Left(iter))
            }
            AllSyncInner::GrandpaWarpSync { .. } => either::Right(either::Right(iter::empty())), // TODO: not implemented properly
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Process the next block in the queue of verification.
    ///
    /// This method takes ownership of the [`AllSync`] and starts a verification process. The
    /// [`AllSync`] is yielded back at the end of this process.
    pub fn process_one(mut self) -> ProcessOne<TRq, TSrc, TBl> {
        match self.inner {
            AllSyncInner::GrandpaWarpSync {
                inner: grandpa_warp_sync::InProgressGrandpaWarpSync::Verifier(_),
            } => ProcessOne::VerifyWarpSyncFragment(WarpSyncFragmentVerify { inner: self }),
            AllSyncInner::GrandpaWarpSync { .. } => ProcessOne::AllSync(self),
            AllSyncInner::AllForks(sync) => match sync.process_one() {
                all_forks::ProcessOne::AllSync { sync } => {
                    self.inner = AllSyncInner::AllForks(sync);
                    ProcessOne::AllSync(self)
                }
                all_forks::ProcessOne::HeaderVerify(verify) => {
                    ProcessOne::VerifyHeader(HeaderVerify {
                        inner: HeaderVerifyInner::AllForks(verify),
                        shared: self.shared,
                    })
                }
            },
            AllSyncInner::Optimistic { inner } => match inner.process_one() {
                optimistic::ProcessOne::Idle { sync } => {
                    self.inner = AllSyncInner::Optimistic { inner: sync };
                    ProcessOne::AllSync(self)
                }
                optimistic::ProcessOne::Verify(inner) => {
                    ProcessOne::VerifyBodyHeader(HeaderBodyVerify {
                        inner: HeaderBodyVerifyInner::Optimistic(inner),
                        shared: self.shared,
                    })
                }
            },
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Injects a block announcement made by a source into the state machine.
    pub fn block_announce(
        &mut self,
        source_id: SourceId,
        announced_scale_encoded_header: Vec<u8>,
        is_best: bool,
    ) -> BlockAnnounceOutcome {
        let source_id = self.shared.sources.get(source_id.0).unwrap();

        match (&mut self.inner, source_id) {
            (AllSyncInner::AllForks(sync), &SourceMapping::AllForks(source_id)) => {
                match sync.block_announce(source_id, announced_scale_encoded_header, is_best) {
                    all_forks::BlockAnnounceOutcome::HeaderVerify => {
                        BlockAnnounceOutcome::HeaderVerify
                    }
                    all_forks::BlockAnnounceOutcome::TooOld {
                        announce_block_height,
                        finalized_block_height,
                    } => BlockAnnounceOutcome::TooOld {
                        announce_block_height,
                        finalized_block_height,
                    },
                    all_forks::BlockAnnounceOutcome::AlreadyInChain => {
                        BlockAnnounceOutcome::AlreadyInChain
                    }
                    all_forks::BlockAnnounceOutcome::NotFinalizedChain => {
                        BlockAnnounceOutcome::NotFinalizedChain
                    }
                    all_forks::BlockAnnounceOutcome::Disjoint => BlockAnnounceOutcome::Disjoint,
                    all_forks::BlockAnnounceOutcome::InvalidHeader(error) => {
                        BlockAnnounceOutcome::InvalidHeader(error)
                    }
                }
            }
            (AllSyncInner::Optimistic { inner }, &SourceMapping::Optimistic(source_id)) => {
                match header::decode(&announced_scale_encoded_header) {
                    Ok(header) => {
                        if is_best {
                            inner.raise_source_best_block(source_id, header.number);
                            inner.source_user_data_mut(source_id).best_block_hash =
                                header::hash_from_scale_encoded_header(
                                    &announced_scale_encoded_header,
                                );
                        }
                        BlockAnnounceOutcome::Disjoint // TODO: ?!
                    }
                    Err(err) => BlockAnnounceOutcome::InvalidHeader(err),
                }
            }
            (
                AllSyncInner::GrandpaWarpSync { inner: sync },
                &SourceMapping::GrandpaWarpSync(source_id),
            ) => {
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

                BlockAnnounceOutcome::Disjoint
            }
            (AllSyncInner::Poisoned, _) => unreachable!(),

            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (AllSyncInner::GrandpaWarpSync { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::GrandpaWarpSync { .. }, SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::GrandpaWarpSync(_)) => unreachable!(),
        }
    }

    /// Update the state machine with a Grandpa commit message received from the network.
    ///
    /// On success, the finalized block might have been updated.
    // TODO: return which blocks are removed as finalized
    pub fn grandpa_commit_message(
        &mut self,
        scale_encoded_message: &[u8],
    ) -> Result<(), blocks_tree::CommitVerifyError> {
        // TODO: clearly indicate if message has been ignored
        match &mut self.inner {
            AllSyncInner::AllForks(sync) => sync.grandpa_commit_message(scale_encoded_message),
            AllSyncInner::Optimistic { .. } => Ok(()),
            AllSyncInner::GrandpaWarpSync { .. } => Ok(()),
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Inject a response to a previously-emitted blocks request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    // TODO: return the TRq?
    pub fn blocks_request_response(
        &mut self,
        request_id: RequestId,
        blocks: Result<impl Iterator<Item = BlockRequestSuccessBlock<TBl>>, ()>,
    ) -> ResponseOutcome {
        debug_assert!(self.shared.requests.contains(request_id.0));
        let request = self.shared.requests.remove(request_id.0);

        match (&mut self.inner, request) {
            (AllSyncInner::GrandpaWarpSync { .. }, _) => panic!(), // Grandpa warp sync never starts block requests.
            (AllSyncInner::AllForks(sync), RequestMapping::AllForks(request_id)) => {
                match sync.finish_ancestry_search(
                    request_id,
                    blocks.map(|iter| {
                        iter.map(|block| all_forks::RequestSuccessBlock {
                            scale_encoded_header: block.scale_encoded_header,
                            scale_encoded_justification: block.scale_encoded_justification,
                        })
                    }),
                ) {
                    all_forks::AncestrySearchResponseOutcome::Verify => ResponseOutcome::Queued,
                    all_forks::AncestrySearchResponseOutcome::NotFinalizedChain {
                        discarded_unverified_block_headers,
                    } => ResponseOutcome::NotFinalizedChain {
                        discarded_unverified_block_headers,
                    },
                    all_forks::AncestrySearchResponseOutcome::Inconclusive => {
                        ResponseOutcome::Queued
                    }
                    all_forks::AncestrySearchResponseOutcome::AllAlreadyInChain => {
                        ResponseOutcome::AllAlreadyInChain
                    }
                }
            }
            (AllSyncInner::Optimistic { inner }, RequestMapping::Optimistic(request_id)) => {
                match inner
                    .finish_request(
                        request_id,
                        blocks
                            .map_err(|()| optimistic::RequestFail::BlocksUnavailable)
                            .map(|iter| {
                                iter.map(|block| optimistic::RequestSuccessBlock {
                                    scale_encoded_header: block.scale_encoded_header,
                                    scale_encoded_justification: block.scale_encoded_justification,
                                    scale_encoded_extrinsics: block.scale_encoded_extrinsics,
                                    user_data: block.user_data,
                                })
                            }),
                    )
                    .1
                {
                    _ => ResponseOutcome::Queued, // TODO: do correctly
                }
            }
            _ => unreachable!(),
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
        &mut self,
        request_id: RequestId,
        // TODO: don't use crate::network::protocol
        // TODO: Result instead of Option?
        response: Option<crate::network::protocol::GrandpaWarpSyncResponse>,
    ) -> ResponseOutcome {
        debug_assert!(self.shared.requests.contains(request_id.0));
        let request = self.shared.requests.remove(request_id.0);
        assert!(matches!(request, RequestMapping::Inline(..)));

        match mem::replace(&mut self.inner, AllSyncInner::Poisoned) {
            AllSyncInner::GrandpaWarpSync {
                inner: grandpa_warp_sync::InProgressGrandpaWarpSync::WarpSyncRequest(grandpa),
            } => {
                let updated_grandpa = grandpa.handle_response(response);
                self.inner = AllSyncInner::GrandpaWarpSync {
                    inner: updated_grandpa,
                };
                ResponseOutcome::Queued
            }

            // Only the GrandPa warp syncing ever starts GrandPa warp sync requests.
            other => {
                self.inner = other;
                ResponseOutcome::Queued // TODO: no
            }
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
        &mut self,
        request_id: RequestId,
        response: Result<impl Iterator<Item = Option<impl AsRef<[u8]>>>, ()>,
    ) -> ResponseOutcome {
        debug_assert!(self.shared.requests.contains(request_id.0));
        let request = self.shared.requests.remove(request_id.0);
        assert!(matches!(request, RequestMapping::Inline(..)));

        let mut response = response.unwrap(); // TODO: handle this properly; requires changes in the grandpa warp sync machine

        match mem::replace(&mut self.inner, AllSyncInner::Poisoned) {
            AllSyncInner::GrandpaWarpSync {
                inner: grandpa_warp_sync::InProgressGrandpaWarpSync::VirtualMachineParamsGet(sync),
            } => {
                // In this state, we expect the response to be one value for `:code` and one for
                // `:heappages`. As documented, we panic if the number of items isn't 2.
                let code = response.next().unwrap();
                let heap_pages = response.next().unwrap();
                assert!(response.next().is_none());

                // TODO: we use `Oneshot` because the VM is thrown away afterwards; ideally it wouldn't be be thrown away
                let (grandpa_warp_sync, error) =
                    sync.set_virtual_machine_params(code, heap_pages, ExecHint::Oneshot);

                if let Some(_error) = error {
                    // TODO: error handling
                }

                self.inject_grandpa(grandpa_warp_sync)
            }
            AllSyncInner::GrandpaWarpSync {
                inner: grandpa_warp_sync::InProgressGrandpaWarpSync::StorageGet(sync),
            } => {
                // In this state, we expect the response to be one value. As documented, we panic
                // if the number of items isn't 1.
                let value = response.next().unwrap();
                assert!(response.next().is_none());

                let (grandpa_warp_sync, error) = sync.inject_value(value.map(iter::once));

                if let Some(_error) = error {
                    // TODO: error handling
                }

                self.inject_grandpa(grandpa_warp_sync)
            }
            // Only the GrandPa warp syncing ever starts GrandPa warp sync requests.
            other => {
                self.inner = other;
                ResponseOutcome::Queued // TODO: no
            }
        }
    }

    // TODO: questionable function
    fn inject_grandpa(
        &mut self,
        grandpa_warp_sync: grandpa_warp_sync::GrandpaWarpSync<GrandpaWarpSyncSourceExtra<TSrc>>,
    ) -> ResponseOutcome {
        match grandpa_warp_sync {
            grandpa_warp_sync::GrandpaWarpSync::InProgress(inner) => {
                self.inner = AllSyncInner::GrandpaWarpSync { inner };
                ResponseOutcome::Queued
            }
            grandpa_warp_sync::GrandpaWarpSync::Finished(success) => {
                let all_forks = self.shared.transition_grandpa_warp_sync_all_forks(success);
                self.inner = AllSyncInner::AllForks(all_forks);
                ResponseOutcome::WarpSyncFinished
            }
        }
    }
}

/// See [`AllSync::desired_requests`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum RequestDetail {
    /// Requesting blocks from the source is requested.
    BlocksRequest {
        /// Height of the first block to request.
        first_block_height: u64,
        /// Hash of the first block to request. `None` if not known.
        first_block_hash: Option<[u8; 32]>,
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

pub struct BlockRequestSuccessBlock<TBl> {
    pub scale_encoded_header: Vec<u8>,
    pub scale_encoded_justification: Option<Vec<u8>>,
    pub scale_encoded_extrinsics: Vec<Vec<u8>>,
    pub user_data: TBl,
}

/// Outcome of calling [`AllSync::block_announce`].
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

/// Outcome of calling [`AllSync::process_one`].
pub enum ProcessOne<TRq, TSrc, TBl> {
    /// No block ready to be processed.
    AllSync(AllSync<TRq, TSrc, TBl>),

    /// Ready to start verifying a header.
    VerifyHeader(HeaderVerify<TRq, TSrc, TBl>),

    /// Ready to start verifying a header and a body.
    VerifyBodyHeader(HeaderBodyVerify<TRq, TSrc, TBl>),

    /// Ready to start verifying a warp sync fragment.
    VerifyWarpSyncFragment(WarpSyncFragmentVerify<TRq, TSrc, TBl>),
}

/// Outcome of injecting a response in the [`AllSync`].
pub enum ResponseOutcome {
    /// Content of the response has been queued and will be processed later.
    Queued,

    /// Response has made it possible to finish warp syncing.
    WarpSyncFinished,

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

    /// All blocks in the ancestry search response were already in the list of verified blocks.
    ///
    /// This can happen if a block announce or different ancestry search response has been
    /// processed in between the request and response.
    AllAlreadyInChain,
}

pub struct HeaderVerify<TRq, TSrc, TBl> {
    inner: HeaderVerifyInner<TRq, TSrc, TBl>,
    shared: Shared<TRq>,
}

enum HeaderVerifyInner<TRq, TSrc, TBl> {
    AllForks(all_forks::HeaderVerify<TBl, AllForksRequestExtra<TRq>, AllForksSourceExtra<TSrc>>),
}

impl<TRq, TSrc, TBl> HeaderVerify<TRq, TSrc, TBl> {
    /// Returns the height of the block to be verified.
    pub fn height(&self) -> u64 {
        match &self.inner {
            HeaderVerifyInner::AllForks(verify) => verify.height(),
        }
    }

    /// Returns the hash of the block to be verified.
    pub fn hash(&self) -> [u8; 32] {
        match &self.inner {
            HeaderVerifyInner::AllForks(verify) => *verify.hash(),
        }
    }

    /// Perform the verification.
    pub fn perform(
        self,
        now_from_unix_epoch: Duration,
        user_data: TBl,
    ) -> HeaderVerifyOutcome<TRq, TSrc, TBl> {
        match self.inner {
            HeaderVerifyInner::AllForks(verify) => {
                match verify.perform(now_from_unix_epoch, user_data) {
                    all_forks::HeaderVerifyOutcome::Success {
                        is_new_best,
                        sync,
                        justification_verification,
                    } => HeaderVerifyOutcome::Success {
                        is_new_best,
                        is_new_finalized: justification_verification.is_success(),
                        sync: AllSync {
                            inner: AllSyncInner::AllForks(sync),
                            shared: self.shared,
                        },
                    },
                    all_forks::HeaderVerifyOutcome::Error {
                        sync,
                        error,
                        user_data,
                    } => HeaderVerifyOutcome::Error {
                        sync: AllSync {
                            inner: AllSyncInner::AllForks(sync),
                            shared: self.shared,
                        },
                        error: match error {
                            all_forks::HeaderVerifyError::VerificationFailed(error) => {
                                HeaderVerifyError::VerificationFailed(error)
                            }
                            all_forks::HeaderVerifyError::ConsensusMismatch => {
                                HeaderVerifyError::ConsensusMismatch
                            }
                        },
                        user_data,
                    },
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
    },

    /// Header verification failed.
    Error {
        /// State machine yielded back. Use to continue the processing.
        sync: AllSync<TRq, TSrc, TBl>,
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

pub struct WarpSyncFragmentVerify<TRq, TSrc, TBl> {
    inner: AllSync<TRq, TSrc, TBl>,
}

impl<TRq, TSrc, TBl> WarpSyncFragmentVerify<TRq, TSrc, TBl> {
    /// Returns the identifier and user data of the source that has sent the fragment to be
    /// verified.
    pub fn proof_sender(&self) -> (SourceId, &TSrc) {
        let sender = match &self.inner.inner {
            AllSyncInner::GrandpaWarpSync {
                inner: grandpa_warp_sync::InProgressGrandpaWarpSync::Verifier(verifier),
            } => verifier.proof_sender(),
            _ => unreachable!(),
        };

        (sender.1.outer_source_id, &sender.1.user_data)
    }

    /// Perform the verification.
    pub fn perform(
        mut self,
    ) -> (
        AllSync<TRq, TSrc, TBl>,
        Result<(), grandpa_warp_sync::FragmentError>,
    ) {
        let (next_grandpa_warp_sync, error) =
            match mem::replace(&mut self.inner.inner, AllSyncInner::Poisoned) {
                AllSyncInner::GrandpaWarpSync {
                    inner: grandpa_warp_sync::InProgressGrandpaWarpSync::Verifier(verifier),
                } => verifier.next(),
                _ => unreachable!(),
            };

        self.inner.inner = AllSyncInner::GrandpaWarpSync {
            inner: next_grandpa_warp_sync,
        };

        (self.inner, error)
    }
}

pub struct HeaderBodyVerify<TRq, TSrc, TBl> {
    inner: HeaderBodyVerifyInner<TRq, TSrc, TBl>,
    shared: Shared<TRq>,
}

enum HeaderBodyVerifyInner<TRq, TSrc, TBl> {
    Optimistic(optimistic::Verify<OptimisticRequestExtra<TRq>, OptimisticSourceExtra<TSrc>, TBl>),
}

impl<TRq, TSrc, TBl> HeaderBodyVerify<TRq, TSrc, TBl> {
    /// Returns the height of the block to be verified.
    pub fn height(&self) -> u64 {
        match &self.inner {
            HeaderBodyVerifyInner::Optimistic(verify) => verify.height(),
        }
    }

    /// Returns the hash of the block to be verified.
    pub fn hash(&self) -> [u8; 32] {
        match &self.inner {
            HeaderBodyVerifyInner::Optimistic(verify) => verify.hash(),
        }
    }

    /// Start the verification process.
    pub fn start(
        self,
        now_from_unix_epoch: Duration,
        user_data: TBl,
    ) -> BlockVerification<TRq, TSrc, TBl> {
        match self.inner {
            HeaderBodyVerifyInner::Optimistic(verify) => BlockVerification::from_inner(
                verify.start(now_from_unix_epoch),
                self.shared,
                user_data,
            ),
        }
    }
}

/// State of the processing of blocks.
pub enum BlockVerification<TRq, TSrc, TBl> {
    /// Block has been successfully verified.
    Success {
        /// True if the newly-verified block is considered the new best block.
        is_new_best: bool,
        /// State machine yielded back. Use to continue the processing.
        sync: AllSync<TRq, TSrc, TBl>,
    },

    /// Block has been successfully verified and finalized.
    // TODO: should refactor that so that `ProcessOne` verifies justifications separately from blocks; the present API doesn't make sense for the all_forks strategy
    Finalized {
        /// State machine yielded back. Use to continue the processing.
        sync: AllSync<TRq, TSrc, TBl>,
        /// List of blocks that have been finalized. Includes the block that has just been
        /// verified itself.
        // TODO leaky type
        finalized_blocks: Vec<optimistic::Block<TBl>>,
    },

    /// Block verification failed.
    Error {
        /// State machine yielded back. Use to continue the processing.
        sync: AllSync<TRq, TSrc, TBl>,
        /// Error that happened.
        error: verify::header_only::Error,
        /// User data that was passed to [`HeaderVerify::perform`] and is unused.
        user_data: TBl,
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

impl<TRq, TSrc, TBl> BlockVerification<TRq, TSrc, TBl> {
    fn from_inner(
        inner: optimistic::BlockVerification<
            OptimisticRequestExtra<TRq>,
            OptimisticSourceExtra<TSrc>,
            TBl,
        >,
        mut shared: Shared<TRq>,
        user_data: TBl,
    ) -> Self {
        match inner {
            optimistic::BlockVerification::NewBest { mut sync, .. } => {
                // TODO: transition to all_forks
                BlockVerification::Success {
                    is_new_best: true,
                    sync: AllSync {
                        inner: AllSyncInner::Optimistic { inner: sync },
                        shared,
                    },
                }
            }
            optimistic::BlockVerification::Finalized {
                mut sync,
                finalized_blocks,
                ..
            } => {
                // TODO: transition to all_forks
                BlockVerification::Finalized {
                    sync: AllSync {
                        inner: AllSyncInner::Optimistic { inner: sync },
                        shared,
                    },
                    finalized_blocks,
                }
            }
            optimistic::BlockVerification::Reset { sync, .. } => {
                BlockVerification::Error {
                    sync: AllSync {
                        inner: AllSyncInner::Optimistic { inner: sync },
                        shared,
                    },
                    error: verify::header_only::Error::NonSequentialBlockNumber, // TODO: this is the completely wrong error; needs some deeper API changes
                    user_data,
                }
            }
            optimistic::BlockVerification::FinalizedStorageGet(inner) => {
                BlockVerification::FinalizedStorageGet(StorageGet {
                    inner,
                    shared,
                    user_data,
                })
            }
            optimistic::BlockVerification::FinalizedStoragePrefixKeys(inner) => {
                BlockVerification::FinalizedStoragePrefixKeys(StoragePrefixKeys {
                    inner,
                    shared,
                    user_data,
                })
            }
            optimistic::BlockVerification::FinalizedStorageNextKey(inner) => {
                BlockVerification::FinalizedStorageNextKey(StorageNextKey {
                    inner,
                    shared,
                    user_data,
                })
            }
        }
    }
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet<TRq, TSrc, TBl> {
    inner: optimistic::StorageGet<OptimisticRequestExtra<TRq>, OptimisticSourceExtra<TSrc>, TBl>,
    shared: Shared<TRq>,
    user_data: TBl,
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
        let inner = self.inner.inject_value(value);
        BlockVerification::from_inner(inner, self.shared, self.user_data)
    }
}

/// Fetching the list of keys with a given prefix is required in order to continue.
#[must_use]
pub struct StoragePrefixKeys<TRq, TSrc, TBl> {
    inner: optimistic::StoragePrefixKeys<
        OptimisticRequestExtra<TRq>,
        OptimisticSourceExtra<TSrc>,
        TBl,
    >,
    shared: Shared<TRq>,
    user_data: TBl,
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
        let inner = self.inner.inject_keys_ordered(keys);
        BlockVerification::from_inner(inner, self.shared, self.user_data)
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct StorageNextKey<TRq, TSrc, TBl> {
    inner:
        optimistic::StorageNextKey<OptimisticRequestExtra<TRq>, OptimisticSourceExtra<TSrc>, TBl>,
    shared: Shared<TRq>,
    user_data: TBl,
}

impl<TRq, TSrc, TBl> StorageNextKey<TRq, TSrc, TBl> {
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner.key()
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl AsRef<[u8]>>) -> BlockVerification<TRq, TSrc, TBl> {
        let inner = self.inner.inject_key(key);
        BlockVerification::from_inner(inner, self.shared, self.user_data)
    }
}

enum AllSyncInner<TRq, TSrc, TBl> {
    GrandpaWarpSync {
        inner: grandpa_warp_sync::InProgressGrandpaWarpSync<GrandpaWarpSyncSourceExtra<TSrc>>,
    },
    Optimistic {
        inner: optimistic::OptimisticSync<
            OptimisticRequestExtra<TRq>,
            OptimisticSourceExtra<TSrc>,
            TBl,
        >,
    },
    AllForks(all_forks::AllForksSync<TBl, AllForksRequestExtra<TRq>, AllForksSourceExtra<TSrc>>),
    Poisoned,
}

struct AllForksSourceExtra<TSrc> {
    outer_source_id: SourceId,
    user_data: TSrc,
}

struct AllForksRequestExtra<TRq> {
    outer_request_id: RequestId,
    user_data: Option<TRq>, // TODO: why option?
}

struct OptimisticSourceExtra<TSrc> {
    user_data: TSrc,
    best_block_hash: [u8; 32],
    outer_source_id: SourceId,
}

struct OptimisticRequestExtra<TRq> {
    outer_request_id: RequestId,
    user_data: TRq,
}

struct GrandpaWarpSyncSourceExtra<TSrc> {
    outer_source_id: SourceId,
    user_data: TSrc,
    best_block_number: u64,
    best_block_hash: [u8; 32],
}

struct Shared<TRq> {
    sources: slab::Slab<SourceMapping>,
    requests: slab::Slab<RequestMapping<TRq>>,

    /// Value passed through [`Config::sources_capacity`].
    sources_capacity: usize,
    /// Value passed through [`Config::blocks_capacity`].
    blocks_capacity: usize,
    /// Value passed through [`Config::max_disjoint_headers`].
    max_disjoint_headers: usize,
    /// Value passed through [`Config::max_requests_per_block`].
    max_requests_per_block: NonZeroU32,
}

impl<TRq> Shared<TRq> {
    /// Transitions the sync state machine from the grandpa warp strategy to the "all-forks"
    /// strategy.
    fn transition_grandpa_warp_sync_all_forks<TSrc, TBl>(
        &mut self,
        grandpa: grandpa_warp_sync::Success<GrandpaWarpSyncSourceExtra<TSrc>>,
    ) -> all_forks::AllForksSync<TBl, AllForksRequestExtra<TRq>, AllForksSourceExtra<TSrc>> {
        let mut all_forks = all_forks::AllForksSync::new(all_forks::Config {
            chain_information: grandpa.chain_information,
            sources_capacity: self.sources_capacity,
            blocks_capacity: self.blocks_capacity,
            max_disjoint_headers: self.max_disjoint_headers,
            max_requests_per_block: self.max_requests_per_block,
            full: false,
        });

        debug_assert!(self
            .sources
            .iter()
            .all(|(_, s)| matches!(s, SourceMapping::GrandpaWarpSync(_))));

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

        all_forks
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestMapping<TRq> {
    Inline(SourceId, RequestDetail, TRq),
    AllForks(all_forks::RequestId),
    Optimistic(optimistic::RequestId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SourceMapping {
    GrandpaWarpSync(grandpa_warp_sync::SourceId),
    AllForks(all_forks::SourceId),
    Optimistic(optimistic::SourceId),
}

fn all_forks_request_convert(rq_params: all_forks::RequestParams) -> RequestDetail {
    RequestDetail::BlocksRequest {
        ascending: false,
        first_block_hash: Some(rq_params.first_block_hash),
        first_block_height: rq_params.first_block_height,
        num_blocks: rq_params.num_blocks,
        request_bodies: false, // TODO: true if full?
        request_headers: true,
        request_justification: true,
    }
}

fn optimistic_request_convert(rq_params: optimistic::RequestDetail) -> RequestDetail {
    RequestDetail::BlocksRequest {
        ascending: true, // TODO: ?!?!
        first_block_hash: None,
        first_block_height: rq_params.block_height.get(),
        num_blocks: rq_params.num_blocks.into(),
        request_bodies: true, // TODO: only if full?
        request_headers: true,
        request_justification: true,
    }
}
