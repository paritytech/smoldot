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

//! All syncing strategies grouped together.
//!
//! This state machine combines GrandPa warp syncing and all forks syncing into one state machine.
//!
//! # Overview
//!
//! This state machine acts as a container of sources, blocks (verified or not), and requests.
//! In order to initialize it, you need to pass, amongst other things, a
//! [`chain_information::ChainInformation`] struct indicating the known state of the finality of
//! the chain.
//!
//! A *request* represents a query for information from a source. Once the request has finished,
//! call one of the methods of the [`AllSync`] in order to notify the state machine of the outcome.

use crate::{
    chain::{blocks_tree, chain_information},
    executor::host,
    finality::decode,
    header,
    sync::{all_forks, warp_sync},
    trie::Nibble,
    verify,
};

use alloc::{borrow::Cow, vec::Vec};
use core::{iter, marker::PhantomData, num::NonZero, ops, time::Duration};

pub use crate::executor::vm::ExecHint;
pub use blocks_tree::{CommitVerifyError, JustificationVerifyError};
pub use warp_sync::{
    BuildChainInformationError as WarpSyncBuildChainInformationError,
    BuildRuntimeError as WarpSyncBuildRuntimeError, ConfigCodeTrieNodeHint, VerifyFragmentError,
    WarpSyncFragment,
};

use super::{all_forks::AllForksSync, warp_sync::RuntimeInformation};

/// Configuration for the [`AllSync`].
// TODO: review these fields
#[derive(Debug)]
pub struct Config {
    /// Information about the latest finalized block and its ancestors.
    pub chain_information: chain_information::ValidChainInformation,

    /// Number of bytes used when encoding/decoding the block number. Influences how various data
    /// structures should be parsed.
    pub block_number_bytes: usize,

    /// If `false`, blocks containing digest items with an unknown consensus engine will fail to
    /// verify.
    ///
    /// Note that blocks must always contain digest items that are relevant to the current
    /// consensus algorithm. This option controls what happens when blocks contain additional
    /// digest items that aren't recognized by the implementation.
    ///
    /// Passing `true` can lead to blocks being considered as valid when they shouldn't, as these
    /// additional digest items could have some logic attached to them that restricts which blocks
    /// are valid and which are not.
    ///
    /// However, since a recognized consensus engine must always be present, both `true` and
    /// `false` guarantee that the number of authorable blocks over the network is bounded.
    pub allow_unknown_consensus_engines: bool,

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
    pub max_requests_per_block: NonZero<u32>,

    /// Number of blocks to download ahead of the best verified block.
    ///
    /// Whenever the latest best block is updated, the state machine will start block
    /// requests for the block `best_block_height + download_ahead_blocks` and all its
    /// ancestors. Considering that requesting blocks has some latency, downloading blocks ahead
    /// of time ensures that verification isn't blocked waiting for a request to be finished.
    ///
    /// The ideal value here depends on the speed of blocks verification speed and latency of
    /// block requests.
    pub download_ahead_blocks: NonZero<u32>,

    /// If true, the body of a block is downloaded (if necessary) before a
    /// [`ProcessOne::VerifyBlock`] is generated.
    pub download_bodies: bool,

    /// If `true`, all the storage proofs and call proofs necessary in order to compute the chain
    /// information of the warp synced block will be downloaded during the warp syncing process.
    /// If `false`, the finality information of the warp synced block is inferred from the warp
    /// sync fragments instead.
    pub download_all_chain_information_storage_proofs: bool,

    /// Known valid Merkle value and storage value combination for the `:code` key.
    ///
    /// If provided, the warp syncing algorithm will first fetch the Merkle value of `:code`, and
    /// if it matches the Merkle value provided in the hint, use the storage value in the hint
    /// instead of downloading it. If the hint doesn't match, an extra round-trip will be needed,
    /// but if the hint matches it saves a big download.
    // TODO: provide only in non-full mode?
    pub code_trie_node_hint: Option<ConfigCodeTrieNodeHint>,
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

/// Status of the synchronization.
#[derive(Debug)]
pub enum Status<'a, TSrc> {
    /// Regular syncing mode.
    Sync,
    /// Warp syncing algorithm is downloading Grandpa warp sync fragments containing a finality
    /// proof.
    WarpSyncFragments {
        /// Source from which the fragments are currently being downloaded, if any.
        source: Option<(SourceId, &'a TSrc)>,
        /// Hash of the highest block that is proven to be finalized.
        ///
        /// This isn't necessarily the same block as returned by
        /// [`AllSync::as_chain_information`], as this function first has to download extra
        /// information compared to just the finalized block.
        finalized_block_hash: [u8; 32],
        /// Height of the block indicated by [`Status::WarpSyncFragments::finalized_block_hash`].
        finalized_block_number: u64,
    },
    /// Warp syncing algorithm has reached the head of the finalized chain and is downloading and
    /// building the chain information.
    WarpSyncChainInformation {
        /// Hash of the highest block that is proven to be finalized.
        ///
        /// This isn't necessarily the same block as returned by
        /// [`AllSync::as_chain_information`], as this function first has to download extra
        /// information compared to just the finalized block.
        finalized_block_hash: [u8; 32],
        /// Height of the block indicated by
        /// [`Status::WarpSyncChainInformation::finalized_block_hash`].
        finalized_block_number: u64,
    },
}

pub struct AllSync<TRq, TSrc, TBl> {
    warp_sync: Option<warp_sync::WarpSync<WarpSyncSourceExtra, WarpSyncRequestExtra>>,
    ready_to_transition: Option<warp_sync::RuntimeInformation>,
    // TODO: we store an `Option<TBl>` instead of `TBl` because we need to be able to extract block user datas when a warp sync is finished
    /// Always `Some`, except for temporary extractions.
    all_forks:
        Option<all_forks::AllForksSync<Option<TBl>, AllForksRequestExtra, AllForksSourceExtra>>,
    shared: Shared<TRq, TSrc>,
}

impl<TRq, TSrc, TBl> AllSync<TRq, TSrc, TBl> {
    /// Initializes a new state machine.
    pub fn new(config: Config) -> Self {
        AllSync {
            // TODO: notify API user if can't start warp sync?
            warp_sync: warp_sync::start_warp_sync(warp_sync::Config {
                start_chain_information: config.chain_information.clone(),
                block_number_bytes: config.block_number_bytes,
                sources_capacity: config.sources_capacity,
                requests_capacity: config.sources_capacity, // TODO: ?! add as config?
                download_all_chain_information_storage_proofs: config
                    .download_all_chain_information_storage_proofs,
                code_trie_node_hint: config.code_trie_node_hint,
                num_download_ahead_fragments: 128, // TODO: make configurable?
                // TODO: make configurable?
                warp_sync_minimum_gap: 32,
                download_block_body: config.download_bodies,
            })
            .ok(),
            ready_to_transition: None,
            all_forks: Some(AllForksSync::new(all_forks::Config {
                chain_information: config.chain_information,
                block_number_bytes: config.block_number_bytes,
                sources_capacity: config.sources_capacity,
                blocks_capacity: config.blocks_capacity,
                download_bodies: config.download_bodies,
                allow_unknown_consensus_engines: config.allow_unknown_consensus_engines,
                max_disjoint_headers: config.max_disjoint_headers,
                max_requests_per_block: config.max_requests_per_block,
            })),
            shared: Shared {
                sources: slab::Slab::with_capacity(config.sources_capacity),
                requests: slab::Slab::with_capacity(config.sources_capacity),
                download_bodies: config.download_bodies,
                sources_capacity: config.sources_capacity,
                blocks_capacity: config.blocks_capacity,
                max_disjoint_headers: config.max_disjoint_headers,
                max_requests_per_block: config.max_requests_per_block,
                block_number_bytes: config.block_number_bytes,
                allow_unknown_consensus_engines: config.allow_unknown_consensus_engines,
            },
        }
    }

    /// Returns the value that was initially passed in [`Config::block_number_bytes`].
    pub fn block_number_bytes(&self) -> usize {
        self.shared.block_number_bytes
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct corresponding to the current
    /// latest finalized block. Can later be used to reconstruct a chain.
    pub fn as_chain_information(&'_ self) -> chain_information::ValidChainInformationRef<'_> {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks.as_chain_information()
    }

    /// Returns the current status of the syncing.
    pub fn status(&'_ self) -> Status<'_, TSrc> {
        // TODO:
        Status::Sync
        /*match &self.inner {
            AllSyncInner::AllForks(_) => Status::Sync,
            AllSyncInner::WarpSync { inner, .. } => match inner.status() {
                warp_sync::Status::Fragments {
                    source: None,
                    finalized_block_hash,
                    finalized_block_number,
                } => Status::WarpSyncFragments {
                    source: None,
                    finalized_block_hash,
                    finalized_block_number,
                },
                warp_sync::Status::Fragments {
                    source: Some((_, user_data)),
                    finalized_block_hash,
                    finalized_block_number,
                } => Status::WarpSyncFragments {
                    source: Some((user_data.outer_source_id, &user_data.user_data)),
                    finalized_block_hash,
                    finalized_block_number,
                },
                warp_sync::Status::ChainInformation {
                    finalized_block_hash,
                    finalized_block_number,
                } => Status::WarpSyncChainInformation {
                    finalized_block_hash,
                    finalized_block_number,
                },
            },
            AllSyncInner::Poisoned => unreachable!(),
        }*/
    }

    /// Returns the header of the finalized block.
    pub fn finalized_block_header(&self) -> &[u8] {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks.finalized_block_header()
    }

    /// Returns the height of the finalized block.
    pub fn finalized_block_number(&self) -> u64 {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks.finalized_block_number()
    }

    /// Returns the hash of the finalized block.
    pub fn finalized_block_hash(&self) -> &[u8; 32] {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks.finalized_block_hash()
    }

    /// Updates the finalized block to the given `block_hash`.
    ///
    /// This should be used when the finality is outsourced.
    pub fn set_finalized_block(
        &mut self,
        block_hash: &[u8; 32],
    ) -> Result<SetFinalizedBlockResult<TBl>, SetFinalizedBlockError> {
        let Some(all_forks) = self.all_forks.as_mut() else {
            unreachable!()
        };

        let result = all_forks
            .set_finalized_block(block_hash)
            .map_err(|_| SetFinalizedBlockError::UnknownBlock)?;

        Ok(SetFinalizedBlockResult {
            finalized_blocks: result
                .finalized_blocks
                .into_iter()
                .map(|b| Block {
                    header: b.scale_encoded_header,
                    block_hash: b.block_hash,
                    // Should be always `Some`.
                    user_data: b.user_data.unwrap(),
                })
                .collect(),
            pruned_blocks: result
                .pruned_blocks
                .into_iter()
                .map(|b| b.block_hash)
                .collect(),
            updates_best_block: result.updates_best_block,
        })
    }

    /// Returns the header of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_header(&self) -> &[u8] {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks.best_block_header()
    }

    /// Returns the number of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_number(&self) -> u64 {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks.best_block_number()
    }

    /// Returns the hash of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_hash(&self) -> &[u8; 32] {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks.best_block_hash()
    }

    /// Returns consensus information about the current best block of the chain.
    pub fn best_block_consensus(&'_ self) -> chain_information::ChainInformationConsensusRef<'_> {
        todo!() // TODO:
    }

    /// Returns the header of all known non-finalized blocks in the chain without any specific
    /// order.
    pub fn non_finalized_blocks_unordered(&'_ self) -> impl Iterator<Item = header::HeaderRef<'_>> {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks.non_finalized_blocks_unordered()
    }

    /// Returns the header of all known non-finalized blocks in the chain.
    ///
    /// The returned items are guaranteed to be in an order in which the parents are found before
    /// their children.
    pub fn non_finalized_blocks_ancestry_order(
        &'_ self,
    ) -> impl Iterator<Item = header::HeaderRef<'_>> {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks.non_finalized_blocks_ancestry_order()
    }

    /// Returns true if it is believed that we are near the head of the chain.
    ///
    /// The way this method is implemented is opaque and cannot be relied on. The return value
    /// should only ever be shown to the user and not used for any meaningful logic.
    // TODO: remove this function as it's too imprecise
    pub fn is_near_head_of_chain_heuristic(&self) -> bool {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        let local_best_block = all_forks.best_block_number();

        // We return `false` if any source is more than 5 blocks ahead, and `true` otherwise.
        !self.shared.sources.iter().any(|(_, src)| {
            all_forks.source_best_block(src.all_forks).0 > local_best_block.saturating_add(5)
        })
    }

    /// Start the process of adding a new source to the sync state machine.
    ///
    /// Must be passed the best block number and hash of the source, as usually reported by the
    /// source itself.
    ///
    /// This function call doesn't modify anything but returns an object that allows actually
    /// inserting the source.
    pub fn prepare_add_source(
        &'_ mut self,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    ) -> AddSource<'_, TRq, TSrc, TBl> {
        match self
            .all_forks
            .as_mut()
            .unwrap_or_else(|| unreachable!())
            .prepare_add_source(best_block_number, best_block_hash)
        {
            all_forks::AddSource::BestBlockAlreadyVerified(all_forks) => {
                AddSource::BestBlockAlreadyVerified(AddSourceKnown {
                    all_forks,
                    slab_insertion: self.shared.sources.vacant_entry(),
                    warp_sync: &mut self.warp_sync,
                    marker: PhantomData,
                })
            }
            all_forks::AddSource::BestBlockPendingVerification(all_forks) => {
                AddSource::BestBlockPendingVerification(AddSourceKnown {
                    all_forks,
                    slab_insertion: self.shared.sources.vacant_entry(),
                    warp_sync: &mut self.warp_sync,
                    marker: PhantomData,
                })
            }
            all_forks::AddSource::OldBestBlock(all_forks) => {
                AddSource::OldBestBlock(AddSourceOldBlock {
                    all_forks,
                    slab_insertion: self.shared.sources.vacant_entry(),
                    warp_sync: &mut self.warp_sync,
                    marker: PhantomData,
                })
            }
            all_forks::AddSource::UnknownBestBlock(all_forks) => {
                AddSource::UnknownBestBlock(AddSourceUnknown {
                    all_forks,
                    slab_insertion: self.shared.sources.vacant_entry(),
                    warp_sync: &mut self.warp_sync,
                    marker: PhantomData,
                })
            }
        }
    }

    /// Removes a source from the state machine. Returns the user data of this source, and all
    /// the requests that this source was expected to perform.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] doesn't correspond to a valid source.
    ///
    pub fn remove_source(
        &mut self,
        source_id: SourceId,
    ) -> (TSrc, impl Iterator<Item = (RequestId, TRq)>) {
        let source_info = self.shared.sources.remove(source_id.0);

        let Some(all_forks) = &mut self.all_forks else {
            unreachable!()
        };

        let _ = all_forks.remove_source(source_info.all_forks);
        if let Some(warp_sync) = &mut self.warp_sync {
            let _ = warp_sync.remove_source(source_info.warp_sync.unwrap());
        }

        // TODO: optimize
        let request_ids = self
            .shared
            .requests
            .iter()
            .filter(|(_, rq)| rq.source_id == source_id)
            .map(|(id, _)| id)
            .collect::<Vec<_>>();

        let mut requests = Vec::with_capacity(request_ids.len());
        for request_id in request_ids.into_iter().rev() {
            let rq = self.shared.requests.remove(request_id);
            requests.push((RequestId(request_id), rq.user_data));
        }

        (source_info.user_data, requests.into_iter())
    }

    /// Returns the list of sources in this state machine.
    pub fn sources(&self) -> impl Iterator<Item = SourceId> {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks
            .sources()
            .map(move |id| all_forks[id].outer_source_id)
    }

    /// Returns the number of ongoing requests that concern this source.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn source_num_ongoing_requests(&self, source_id: SourceId) -> usize {
        let Some(&SourceMapping {
            num_requests: num_request,
            ..
        }) = self.shared.sources.get(source_id.0)
        else {
            panic!()
        };

        num_request
    }

    /// Returns the current best block of the given source.
    ///
    /// This corresponds either the latest call to [`AllSync::block_announce`] where `is_best` was
    /// `true`, or to the parameter passed to [`AllSync::prepare_add_source`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn source_best_block(&self, source_id: SourceId) -> (u64, &[u8; 32]) {
        let Some(&SourceMapping {
            all_forks: inner_source_id,
            ..
        }) = self.shared.sources.get(source_id.0)
        else {
            panic!()
        };

        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks.source_best_block(inner_source_id)
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
        let Some(&SourceMapping {
            all_forks: inner_source_id,
            ..
        }) = self.shared.sources.get(source_id.0)
        else {
            panic!()
        };

        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks.source_knows_non_finalized_block(inner_source_id, height, hash)
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
        &self,
        height: u64,
        hash: &[u8; 32],
    ) -> impl Iterator<Item = SourceId> {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks
            .knows_non_finalized_block(height, hash)
            .map(move |id| all_forks[id].outer_source_id)
    }

    /// Try register a new block that the source is aware of.
    ///
    /// Has no effect if `height` is inferior or equal to the finalized block height, or if the
    /// source was already known to know this block.
    ///
    /// The block does not need to be known by the data structure.
    ///
    /// This is automatically done for the blocks added through block announces or block requests..
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn try_add_known_block_to_source(
        &mut self,
        source_id: SourceId,
        height: u64,
        hash: [u8; 32],
    ) {
        let Some(&SourceMapping {
            all_forks: inner_source_id,
            ..
        }) = self.shared.sources.get(source_id.0)
        else {
            panic!()
        };

        let Some(all_forks) = &mut self.all_forks else {
            unreachable!()
        };

        all_forks.add_known_block_to_source(inner_source_id, height, hash);
    }

    /// Returns the details of a request to start towards a source.
    ///
    /// This method doesn't modify the state machine in any way. [`AllSync::add_request`] must be
    /// called in order for the request to actually be marked as started.
    pub fn desired_requests(&self) -> impl Iterator<Item = (SourceId, &TSrc, DesiredRequest)> {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        let all_forks_requests =
            all_forks
                .desired_requests()
                .map(move |(inner_source_id, _, rq_params)| {
                    (
                        all_forks[inner_source_id].outer_source_id,
                        &self.shared.sources[all_forks[inner_source_id].outer_source_id.0]
                            .user_data,
                        all_forks_request_convert(rq_params, self.shared.download_bodies),
                    )
                });

        let warp_sync_requests =
            if let Some(warp_sync) = &self.warp_sync {
                either::Left(warp_sync.desired_requests().map(
                    move |(_, src_user_data, rq_detail)| {
                        let detail = match rq_detail {
                            warp_sync::DesiredRequest::WarpSyncRequest { block_hash } => {
                                DesiredRequest::WarpSync {
                                    sync_start_block_hash: block_hash,
                                }
                            }
                            warp_sync::DesiredRequest::BlockBodyDownload {
                                block_hash,
                                block_number,
                                ..
                            } => DesiredRequest::BlocksRequest {
                                first_block_height: block_number,
                                first_block_hash: block_hash,
                                num_blocks: NonZero::<u64>::new(1).unwrap(),
                                request_headers: false,
                                request_bodies: true,
                                request_justification: false,
                            },
                            warp_sync::DesiredRequest::StorageGetMerkleProof {
                                block_hash,
                                state_trie_root,
                                keys,
                            } => DesiredRequest::StorageGetMerkleProof {
                                block_hash,
                                state_trie_root,
                                keys,
                            },
                            warp_sync::DesiredRequest::RuntimeCallMerkleProof {
                                block_hash,
                                function_name,
                                parameter_vectored,
                            } => DesiredRequest::RuntimeCallMerkleProof {
                                block_hash,
                                function_name,
                                parameter_vectored,
                            },
                        };

                        (
                            src_user_data.outer_source_id,
                            &self.shared.sources[src_user_data.outer_source_id.0].user_data,
                            detail,
                        )
                    },
                ))
            } else {
                either::Right(iter::empty())
            };

        // We always prioritize warp sync requests over all fork requests.
        // The warp sync algorithm will only ever try to emit requests concerning sources that are
        // (or pretend to be) far ahead of the local node. Given a source that is (or pretends to
        // be) far ahead of the local node, it is more desirable to try to warp sync from it
        // rather than download blocks that are close.
        warp_sync_requests.chain(all_forks_requests)
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
        let Some(source_ids) = self.shared.sources.get_mut(source_id.0) else {
            panic!()
        };

        let request_mapping_entry = self.shared.requests.vacant_entry();
        let outer_request_id = RequestId(request_mapping_entry.key());

        let all_forks_request_id = match detail {
            RequestDetail::BlocksRequest {
                first_block_height,
                first_block_hash,
                num_blocks,
                request_headers: true,
                request_bodies,
                request_justification: _,
            } if request_bodies || !self.shared.download_bodies => {
                let Some(all_forks) = &mut self.all_forks else {
                    unreachable!()
                };

                Some(all_forks.add_request(
                    source_ids.all_forks,
                    all_forks::RequestParams {
                        first_block_hash,
                        first_block_height,
                        num_blocks,
                    },
                    AllForksRequestExtra { outer_request_id },
                ))
            }
            _ => None,
        };

        let warp_sync_request_id = match (&mut self.warp_sync, source_ids.warp_sync, detail) {
            (
                Some(warp_sync),
                Some(inner_source_id),
                RequestDetail::WarpSync {
                    sync_start_block_hash,
                },
            ) => Some(warp_sync.add_request(
                inner_source_id,
                WarpSyncRequestExtra {},
                warp_sync::RequestDetail::WarpSyncRequest {
                    block_hash: sync_start_block_hash,
                },
            )),
            (
                Some(warp_sync),
                Some(inner_source_id),
                RequestDetail::BlocksRequest {
                    first_block_height,
                    first_block_hash,
                    request_bodies: true,
                    ..
                },
            ) => Some(warp_sync.add_request(
                inner_source_id,
                WarpSyncRequestExtra {},
                warp_sync::RequestDetail::BlockBodyDownload {
                    block_hash: first_block_hash,
                    block_number: first_block_height,
                },
            )),
            (
                Some(warp_sync),
                Some(inner_source_id),
                RequestDetail::StorageGet { block_hash, keys },
            ) => Some(warp_sync.add_request(
                inner_source_id,
                WarpSyncRequestExtra {},
                warp_sync::RequestDetail::StorageGetMerkleProof { block_hash, keys },
            )),
            (
                Some(warp_sync),
                Some(inner_source_id),
                RequestDetail::RuntimeCallMerkleProof {
                    block_hash,
                    function_name,
                    parameter_vectored,
                },
            ) => Some(warp_sync.add_request(
                inner_source_id,
                WarpSyncRequestExtra {},
                warp_sync::RequestDetail::RuntimeCallMerkleProof {
                    block_hash,
                    function_name,
                    parameter_vectored,
                },
            )),
            (None, None, _) | (Some(_), Some(_), _) => None,
            (Some(_), None, _) | (None, Some(_), _) => {
                debug_assert!(false);
                None
            }
        };

        source_ids.num_requests += 1;

        request_mapping_entry.insert(RequestInfo {
            all_forks: all_forks_request_id,
            warp_sync: warp_sync_request_id,
            source_id,
            user_data,
        });

        outer_request_id
    }

    /// Removes the given request from the state machine. Returns the user data that was associated
    /// to it.
    ///
    /// > **Note**: The state machine might want to re-start the same request again. It is out of
    /// >           the scope of this module to keep track of requests that don't succeed.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    pub fn remove_request(&mut self, request_id: RequestId) -> TRq {
        debug_assert!(self.shared.requests.contains(request_id.0));
        let request = self.shared.requests.remove(request_id.0);

        self.shared.sources[request.source_id.0].num_requests -= 1;

        if let Some(all_forks_request_id) = request.all_forks {
            let Some(all_forks) = self.all_forks.as_mut() else {
                unreachable!()
            };
            let (_, _) = all_forks.finish_request(all_forks_request_id);
        }

        if let Some(warp_sync_request_id) = request.warp_sync {
            let Some(warp_sync) = &mut self.warp_sync else {
                unreachable!()
            };
            warp_sync.remove_request(warp_sync_request_id);
        }

        request.user_data
    }

    /// Returns a list of requests that are considered obsolete and can be removed using
    /// [`AllSync::blocks_request_response`] or similar.
    ///
    /// A request becomes obsolete if the state of the request blocks changes in such a way that
    /// they don't need to be requested anymore. The response to the request will be useless.
    ///
    /// > **Note**: It is in no way mandatory to actually call this function and cancel the
    /// >           requests that are returned.
    pub fn obsolete_requests(&self) -> impl Iterator<Item = RequestId> {
        // TODO: not implemented properly
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks
            .obsolete_requests()
            .map(move |(_, rq)| rq.outer_request_id)
            .chain(
                self.shared
                    .requests
                    .iter()
                    .filter(|(_, rq)| rq.all_forks.is_none() && rq.warp_sync.is_none())
                    .map(|(id, _)| RequestId(id)),
            )
    }

    /// Returns the [`SourceId`] that is expected to fulfill the given request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    pub fn request_source_id(&self, request_id: RequestId) -> SourceId {
        let Some(request) = self.shared.requests.get(request_id.0) else {
            panic!()
        };

        request.source_id
    }

    /// Process the next block in the queue of verification.
    ///
    /// This method takes ownership of the [`AllSync`] and starts a verification process. The
    /// [`AllSync`] is yielded back at the end of this process.
    pub fn process_one(mut self) -> ProcessOne<TRq, TSrc, TBl> {
        if let Some(warp_sync) = self.warp_sync.take() {
            match warp_sync.process_one() {
                warp_sync::ProcessOne::Idle(inner) => {
                    self.warp_sync = Some(inner);
                }
                warp_sync::ProcessOne::VerifyWarpSyncFragment(inner) => {
                    let Some(all_forks) = self.all_forks.take() else {
                        unreachable!()
                    };
                    return ProcessOne::VerifyWarpSyncFragment(WarpSyncFragmentVerify {
                        inner,
                        ready_to_transition: None,
                        all_forks,
                        shared: self.shared,
                    });
                }
                warp_sync::ProcessOne::BuildRuntime(inner) => {
                    let Some(all_forks) = self.all_forks.take() else {
                        unreachable!()
                    };
                    return ProcessOne::WarpSyncBuildRuntime(WarpSyncBuildRuntime {
                        inner,
                        ready_to_transition: None,
                        all_forks,
                        shared: self.shared,
                    });
                }
                warp_sync::ProcessOne::BuildChainInformation(inner) => {
                    let Some(all_forks) = self.all_forks.take() else {
                        unreachable!()
                    };
                    return ProcessOne::WarpSyncBuildChainInformation(
                        WarpSyncBuildChainInformation {
                            inner,
                            all_forks,
                            shared: self.shared,
                        },
                    );
                }
            }
        }

        if let Some(RuntimeInformation {
            finalized_runtime: finalized_block_runtime,
            finalized_body,
            finalized_storage_code,
            finalized_storage_heap_pages,
            finalized_storage_code_merkle_value,
            finalized_storage_code_closest_ancestor_excluding,
        }) = self.ready_to_transition.take()
        {
            let (Some(all_forks), Some(warp_sync)) =
                (self.all_forks.as_mut(), self.warp_sync.as_mut())
            else {
                unreachable!()
            };

            let mut new_all_forks = AllForksSync::new(all_forks::Config {
                chain_information: warp_sync.as_chain_information().into(),
                block_number_bytes: self.shared.block_number_bytes,
                sources_capacity: self.shared.sources_capacity,
                blocks_capacity: self.shared.blocks_capacity,
                download_bodies: self.shared.download_bodies,
                allow_unknown_consensus_engines: self.shared.allow_unknown_consensus_engines,
                max_disjoint_headers: self.shared.max_disjoint_headers,
                max_requests_per_block: self.shared.max_requests_per_block,
            });

            for warp_sync_source_id in warp_sync.sources() {
                let outer_source_id = warp_sync[warp_sync_source_id].outer_source_id;

                let (best_block_number, &best_block_hash) =
                    all_forks.source_best_block(self.shared.sources[outer_source_id.0].all_forks);

                let new_inner_source_id =
                    match new_all_forks.prepare_add_source(best_block_number, best_block_hash) {
                        all_forks::AddSource::BestBlockAlreadyVerified(b)
                        | all_forks::AddSource::BestBlockPendingVerification(b) => {
                            b.add_source(AllForksSourceExtra { outer_source_id })
                        }
                        all_forks::AddSource::OldBestBlock(b) => {
                            b.add_source(AllForksSourceExtra { outer_source_id })
                        }
                        all_forks::AddSource::UnknownBestBlock(b) => {
                            // If the best block of the source is unknown to the new state machine,
                            // it necessarily means that this block's user data hasn't been
                            // extracted from the old state machine yet.
                            let block_user_data = all_forks[(best_block_number, &best_block_hash)]
                                .take()
                                .unwrap_or_else(|| unreachable!());
                            b.add_source_and_insert_block(
                                AllForksSourceExtra { outer_source_id },
                                Some(block_user_data),
                            )
                        }
                    };

                new_all_forks.update_source_finality_state(
                    new_inner_source_id,
                    warp_sync.source_finality_state(warp_sync_source_id),
                );

                self.shared.sources[outer_source_id.0].all_forks = new_inner_source_id;
            }

            for (_, request) in self.shared.requests.iter_mut() {
                request.all_forks = None;
            }

            self.all_forks = Some(new_all_forks);

            return ProcessOne::WarpSyncFinished {
                sync: self,
                finalized_block_runtime,
                finalized_body,
                finalized_storage_code,
                finalized_storage_heap_pages,
                finalized_storage_code_merkle_value,
                finalized_storage_code_closest_ancestor_excluding,
            };
        }

        let Some(all_forks) = self.all_forks.take() else {
            unreachable!()
        };
        match all_forks.process_one() {
            all_forks::ProcessOne::AllSync { sync } => {
                self.all_forks = Some(sync);
            }
            all_forks::ProcessOne::BlockVerify(inner) => {
                return ProcessOne::VerifyBlock(BlockVerify {
                    inner,
                    warp_sync: self.warp_sync,
                    ready_to_transition: self.ready_to_transition,
                    shared: self.shared,
                });
            }
            all_forks::ProcessOne::FinalityProofVerify(inner) => {
                return ProcessOne::VerifyFinalityProof(FinalityProofVerify {
                    inner,
                    warp_sync: self.warp_sync,
                    ready_to_transition: self.ready_to_transition,
                    shared: self.shared,
                });
            }
        }

        ProcessOne::AllSync(self)
    }

    /// Injects a block announcement made by a source into the state machine.
    ///
    /// > **Note**: This information is normally reported by the source itself. In the case of a
    /// >           a networking peer, call this when the source sent a block announce.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn block_announce(
        &'_ mut self,
        source_id: SourceId,
        announced_scale_encoded_header: Vec<u8>,
        is_best: bool,
    ) -> BlockAnnounceOutcome<'_, TRq, TSrc, TBl> {
        let Some(&SourceMapping {
            all_forks: inner_source_id,
            ..
        }) = self.shared.sources.get(source_id.0)
        else {
            panic!()
        };

        let Some(all_forks) = &mut self.all_forks else {
            unreachable!()
        };

        match all_forks.block_announce(inner_source_id, announced_scale_encoded_header, is_best) {
            all_forks::BlockAnnounceOutcome::TooOld {
                announce_block_height,
                finalized_block_height,
            } => BlockAnnounceOutcome::TooOld {
                announce_block_height,
                finalized_block_height,
            },
            all_forks::BlockAnnounceOutcome::Unknown(inner) => {
                BlockAnnounceOutcome::Unknown(AnnouncedBlockUnknown {
                    inner,
                    marker: PhantomData,
                })
            }
            all_forks::BlockAnnounceOutcome::AlreadyPending(inner) => {
                BlockAnnounceOutcome::AlreadyPending(AnnouncedBlockKnown {
                    inner,
                    marker: PhantomData,
                })
            }
            all_forks::BlockAnnounceOutcome::AlreadyVerified(inner) => {
                BlockAnnounceOutcome::AlreadyVerified(AnnouncedBlockKnown {
                    inner,
                    marker: PhantomData,
                })
            }
            all_forks::BlockAnnounceOutcome::InvalidHeader(error) => {
                BlockAnnounceOutcome::InvalidHeader(error)
            }
        }
    }

    /// Update the finalized block height of the given source.
    ///
    /// # Panic
    ///
    /// Panics if `source_id` is invalid.
    ///
    pub fn update_source_finality_state(
        &mut self,
        source_id: SourceId,
        finalized_block_height: u64,
    ) {
        let source_id = self.shared.sources.get(source_id.0).unwrap();

        match (&mut self.warp_sync, source_id.warp_sync) {
            (Some(warp_sync), Some(inner_source_id)) => {
                warp_sync.set_source_finality_state(inner_source_id, finalized_block_height);
            }
            (None, None) => {}
            _ => {
                // Invalid internal state.
                debug_assert!(false);
            }
        }

        let Some(all_forks) = &mut self.all_forks else {
            unreachable!()
        };
        all_forks.update_source_finality_state(source_id.all_forks, finalized_block_height);
    }

    /// Update the state machine with a Grandpa commit message received from the network.
    ///
    /// This function only inserts the commit message into the state machine, and does not
    /// immediately verify it.
    pub fn grandpa_commit_message(
        &mut self,
        source_id: SourceId,
        scale_encoded_message: Vec<u8>,
    ) -> GrandpaCommitMessageOutcome {
        let source_id = self.shared.sources.get(source_id.0).unwrap();

        match (&mut self.warp_sync, source_id.warp_sync) {
            (Some(warp_sync), Some(inner_source_id)) => {
                let block_number = match decode::decode_grandpa_commit(
                    &scale_encoded_message,
                    warp_sync.block_number_bytes(),
                ) {
                    Ok(msg) => msg.target_number,
                    Err(_) => return GrandpaCommitMessageOutcome::Discarded,
                };

                warp_sync.set_source_finality_state(inner_source_id, block_number);
            }
            (None, None) => {}
            _ => {
                // Invalid internal state.
                debug_assert!(false);
            }
        }

        let Some(all_forks) = &mut self.all_forks else {
            unreachable!()
        };
        match all_forks.grandpa_commit_message(source_id.all_forks, scale_encoded_message) {
            all_forks::GrandpaCommitMessageOutcome::ParseError => {
                GrandpaCommitMessageOutcome::Discarded
            }
            all_forks::GrandpaCommitMessageOutcome::Queued => GrandpaCommitMessageOutcome::Queued,
        }
    }

    /// Inject a response to a previously-emitted blocks request.
    ///
    /// The blocks should be provided in decreasing number, with `first_block_hash` as the highest
    /// number.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    // TODO: refactor this function so that the user can know the state of each block
    pub fn blocks_request_response(
        &mut self,
        request_id: RequestId,
        blocks: impl Iterator<Item = BlockRequestSuccessBlock<TBl>>,
    ) -> (TRq, ResponseOutcome) {
        debug_assert!(self.shared.requests.contains(request_id.0));
        let request = self.shared.requests.remove(request_id.0);

        self.shared.sources[request.source_id.0].num_requests -= 1;

        let mut blocks_iter = blocks.into_iter();

        let mut all_forks_blocks_append = if let Some(all_forks_request_id) = request.all_forks {
            let Some(all_forks) = self.all_forks.as_mut() else {
                unreachable!()
            };
            let (_, blocks_append) = all_forks.finish_request(all_forks_request_id);
            Some(blocks_append)
        } else {
            None
        };

        let mut is_first_block = true;

        let outcome = loop {
            let block = match blocks_iter.next() {
                Some(v) => v,
                None => {
                    if let (true, Some(warp_sync_request_id)) = (is_first_block, request.warp_sync)
                    {
                        let Some(warp_sync) = self.warp_sync.as_mut() else {
                            unreachable!()
                        };
                        // TODO: report source misbehaviour
                        warp_sync.remove_request(warp_sync_request_id);
                    }
                    break ResponseOutcome::Queued;
                }
            };

            if let (true, Some(warp_sync_request_id)) = (is_first_block, request.warp_sync) {
                let Some(warp_sync) = self.warp_sync.as_mut() else {
                    unreachable!()
                };
                warp_sync.body_download_response(
                    warp_sync_request_id,
                    block.scale_encoded_extrinsics.clone(), // TODO: clone?
                );
            }

            if let Some(blocks_append) = all_forks_blocks_append {
                // TODO: many of the errors don't properly translate here, needs some refactoring
                match blocks_append.add_block(
                    block.scale_encoded_header,
                    block.scale_encoded_extrinsics,
                    block
                        .scale_encoded_justifications
                        .into_iter()
                        .map(|j| (j.engine_id, j.justification)),
                ) {
                    Ok(all_forks::AddBlock::UnknownBlock(ba)) => {
                        all_forks_blocks_append = Some(ba.insert(Some(block.user_data)))
                    }
                    Ok(all_forks::AddBlock::AlreadyPending(ba)) => {
                        // TODO: replacing the user data entirely is very opinionated, instead the API of the AllSync should be changed
                        all_forks_blocks_append = Some(ba.replace(Some(block.user_data)).0)
                    }
                    Ok(all_forks::AddBlock::AlreadyInChain(_)) if is_first_block => {
                        break ResponseOutcome::AllAlreadyInChain;
                    }
                    Ok(all_forks::AddBlock::AlreadyInChain(_)) => {
                        break ResponseOutcome::Queued;
                    }
                    Err(all_forks::AncestrySearchResponseError::NotFinalizedChain {
                        discarded_unverified_block_headers,
                    }) => {
                        break ResponseOutcome::NotFinalizedChain {
                            discarded_unverified_block_headers,
                        };
                    }
                    Err(_) => {
                        break ResponseOutcome::Queued;
                    }
                }
            }

            is_first_block = false;
        };

        (request.user_data, outcome)
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
        fragments: Vec<WarpSyncFragment>,
        is_finished: bool,
    ) -> (TRq, ResponseOutcome) {
        debug_assert!(self.shared.requests.contains(request_id.0));

        let request = self.shared.requests.remove(request_id.0);

        self.shared.sources[request.source_id.0].num_requests -= 1;

        if let Some(warp_sync_request_id) = request.warp_sync {
            self.warp_sync.as_mut().unwrap().warp_sync_request_response(
                warp_sync_request_id,
                fragments,
                is_finished,
            );
        }

        // TODO: type of request not always verified

        // TODO: don't always return Queued
        (request.user_data, ResponseOutcome::Queued)
    }

    /// Inject a response to a previously-emitted storage proof request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    pub fn storage_get_response(
        &mut self,
        request_id: RequestId,
        response: Vec<u8>,
    ) -> (TRq, ResponseOutcome) {
        debug_assert!(self.shared.requests.contains(request_id.0));

        let request = self.shared.requests.remove(request_id.0);

        self.shared.sources[request.source_id.0].num_requests -= 1;

        if let Some(warp_sync_request_id) = request.warp_sync {
            self.warp_sync
                .as_mut()
                .unwrap()
                .storage_get_response(warp_sync_request_id, response);
        }

        // TODO: type of request not always verified

        // TODO: don't always return Queued
        (request.user_data, ResponseOutcome::Queued)
    }

    /// Inject a response to a previously-emitted call proof request.
    ///
    /// On success, must contain the encoded Merkle proof. See the
    /// [`trie`](crate::trie) module for a description of the format of Merkle proofs.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    pub fn call_proof_response(
        &mut self,
        request_id: RequestId,
        response: Vec<u8>,
    ) -> (TRq, ResponseOutcome) {
        debug_assert!(self.shared.requests.contains(request_id.0));

        let request = self.shared.requests.remove(request_id.0);

        self.shared.sources[request.source_id.0].num_requests -= 1;

        if let Some(warp_sync_request_id) = request.warp_sync {
            self.warp_sync
                .as_mut()
                .unwrap()
                .runtime_call_merkle_proof_response(warp_sync_request_id, response);
        }

        // TODO: type of request not always verified

        // TODO: don't always return Queued
        (request.user_data, ResponseOutcome::Queued)
    }
}

impl<TRq, TSrc, TBl> ops::Index<SourceId> for AllSync<TRq, TSrc, TBl> {
    type Output = TSrc;

    #[track_caller]
    fn index(&self, source_id: SourceId) -> &TSrc {
        let Some(SourceMapping { user_data, .. }) = self.shared.sources.get(source_id.0) else {
            panic!()
        };

        user_data
    }
}

impl<TRq, TSrc, TBl> ops::IndexMut<SourceId> for AllSync<TRq, TSrc, TBl> {
    #[track_caller]
    fn index_mut(&mut self, source_id: SourceId) -> &mut TSrc {
        let Some(SourceMapping { user_data, .. }) = self.shared.sources.get_mut(source_id.0) else {
            panic!()
        };

        user_data
    }
}

impl<'a, TRq, TSrc, TBl> ops::Index<(u64, &'a [u8; 32])> for AllSync<TRq, TSrc, TBl> {
    type Output = TBl;

    #[track_caller]
    fn index(&self, (block_height, block_hash): (u64, &'a [u8; 32])) -> &TBl {
        let Some(all_forks) = &self.all_forks else {
            unreachable!()
        };

        all_forks[(block_height, block_hash)]
            .as_ref()
            .unwrap_or_else(|| unreachable!())
    }
}

impl<'a, TRq, TSrc, TBl> ops::IndexMut<(u64, &'a [u8; 32])> for AllSync<TRq, TSrc, TBl> {
    #[track_caller]
    fn index_mut(&mut self, (block_height, block_hash): (u64, &'a [u8; 32])) -> &mut TBl {
        let Some(all_forks) = &mut self.all_forks else {
            unreachable!()
        };

        all_forks[(block_height, block_hash)]
            .as_mut()
            .unwrap_or_else(|| unreachable!())
    }
}

/// Outcome of calling [`AllSync::prepare_add_source`].
#[must_use]
pub enum AddSource<'a, TRq, TSrc, TBl> {
    /// The best block of the source is older or equal to the local latest finalized block. This
    /// block isn't tracked by the state machine.
    OldBestBlock(AddSourceOldBlock<'a, TRq, TSrc, TBl>),

    /// The best block of the source has already been verified by this state machine.
    BestBlockAlreadyVerified(AddSourceKnown<'a, TRq, TSrc, TBl>),

    /// The best block of the source is already known to this state machine but hasn't been
    /// verified yet.
    BestBlockPendingVerification(AddSourceKnown<'a, TRq, TSrc, TBl>),

    /// The best block of the source isn't in this state machine yet and needs to be inserted.
    UnknownBestBlock(AddSourceUnknown<'a, TRq, TSrc, TBl>),
}

impl<'a, TRq, TSrc, TBl> AddSource<'a, TRq, TSrc, TBl> {
    /// Inserts the source, and the best block if it is unknown.
    ///
    /// The `best_block_user_data` is silently discarded if the block is already known or too old.
    pub fn add_source(self, source_user_data: TSrc, best_block_user_data: TBl) -> SourceId {
        match self {
            AddSource::BestBlockAlreadyVerified(b) => b.add_source(source_user_data),
            AddSource::BestBlockPendingVerification(b) => b.add_source(source_user_data),
            AddSource::OldBestBlock(b) => b.add_source(source_user_data),
            AddSource::UnknownBestBlock(b) => {
                b.add_source_and_insert_block(source_user_data, best_block_user_data)
            }
        }
    }
}

/// See [`AddSource`] and [`AllSync::prepare_add_source`].
#[must_use]
pub struct AddSourceOldBlock<'a, TRq, TSrc, TBl> {
    slab_insertion: slab::VacantEntry<'a, SourceMapping<TSrc>>,
    all_forks:
        all_forks::AddSourceOldBlock<'a, Option<TBl>, AllForksRequestExtra, AllForksSourceExtra>,
    warp_sync: &'a mut Option<warp_sync::WarpSync<WarpSyncSourceExtra, WarpSyncRequestExtra>>,
    marker: PhantomData<TRq>,
}

impl<'a, TRq, TSrc, TBl> AddSourceOldBlock<'a, TRq, TSrc, TBl> {
    /// Inserts a new source in the state machine.
    ///
    /// Returns the newly-allocated identifier for that source.
    ///
    /// The `user_data` parameter is opaque and decided entirely by the user. It can later be
    /// retrieved using the `Index` trait implementation of the [`AllSync`].
    pub fn add_source(self, source_user_data: TSrc) -> SourceId {
        let outer_source_id = SourceId(self.slab_insertion.key());

        let all_forks_source_id = self
            .all_forks
            .add_source(AllForksSourceExtra { outer_source_id });

        let warp_sync_source_id = if let Some(warp_sync) = self.warp_sync {
            Some(warp_sync.add_source(WarpSyncSourceExtra { outer_source_id }))
        } else {
            None
        };

        self.slab_insertion.insert(SourceMapping {
            warp_sync: warp_sync_source_id,
            all_forks: all_forks_source_id,
            user_data: source_user_data,
            num_requests: 0,
        });

        outer_source_id
    }
}

/// See [`AddSource`] and [`AllSync::prepare_add_source`].
#[must_use]
pub struct AddSourceKnown<'a, TRq, TSrc, TBl> {
    slab_insertion: slab::VacantEntry<'a, SourceMapping<TSrc>>,
    all_forks:
        all_forks::AddSourceKnown<'a, Option<TBl>, AllForksRequestExtra, AllForksSourceExtra>,
    warp_sync: &'a mut Option<warp_sync::WarpSync<WarpSyncSourceExtra, WarpSyncRequestExtra>>,
    marker: PhantomData<TRq>,
}

impl<'a, TRq, TSrc, TBl> AddSourceKnown<'a, TRq, TSrc, TBl> {
    /// Gives access to the user data of the block.
    pub fn user_data_mut(&mut self) -> &mut TBl {
        self.all_forks
            .user_data_mut()
            .as_mut()
            .unwrap_or_else(|| unreachable!())
    }

    /// Inserts a new source in the state machine.
    ///
    /// Returns the newly-allocated identifier for that source.
    ///
    /// The `user_data` parameter is opaque and decided entirely by the user. It can later be
    /// retrieved using the `Index` trait implementation of the [`AllForksSync`].
    pub fn add_source(self, source_user_data: TSrc) -> SourceId {
        let outer_source_id = SourceId(self.slab_insertion.key());

        let all_forks_source_id = self
            .all_forks
            .add_source(AllForksSourceExtra { outer_source_id });

        let warp_sync_source_id = if let Some(warp_sync) = self.warp_sync {
            Some(warp_sync.add_source(WarpSyncSourceExtra { outer_source_id }))
        } else {
            None
        };

        self.slab_insertion.insert(SourceMapping {
            warp_sync: warp_sync_source_id,
            all_forks: all_forks_source_id,
            user_data: source_user_data,
            num_requests: 0,
        });

        outer_source_id
    }
}

/// See [`AddSource`] and [`AllSync::prepare_add_source`].
#[must_use]
pub struct AddSourceUnknown<'a, TRq, TSrc, TBl> {
    slab_insertion: slab::VacantEntry<'a, SourceMapping<TSrc>>,
    all_forks:
        all_forks::AddSourceUnknown<'a, Option<TBl>, AllForksRequestExtra, AllForksSourceExtra>,
    warp_sync: &'a mut Option<warp_sync::WarpSync<WarpSyncSourceExtra, WarpSyncRequestExtra>>,
    marker: PhantomData<TRq>,
}

impl<'a, TRq, TSrc, TBl> AddSourceUnknown<'a, TRq, TSrc, TBl> {
    /// Inserts a new source in the state machine, plus the best block of that source.
    ///
    /// Returns the newly-allocated identifier for that source.
    ///
    /// The `source_user_data` parameter is opaque and decided entirely by the user. It can later
    /// be retrieved using the `Index` trait implementation of the [`AllForksSync`].
    ///
    /// The `best_block_user_data` parameter is opaque and decided entirely by the user and is
    /// associated with the best block of the newly-added source.
    pub fn add_source_and_insert_block(
        self,
        source_user_data: TSrc,
        best_block_user_data: TBl,
    ) -> SourceId {
        let outer_source_id = SourceId(self.slab_insertion.key());

        let all_forks_source_id = self.all_forks.add_source_and_insert_block(
            AllForksSourceExtra { outer_source_id },
            Some(best_block_user_data),
        );

        let warp_sync_source_id = if let Some(warp_sync) = self.warp_sync {
            Some(warp_sync.add_source(WarpSyncSourceExtra { outer_source_id }))
        } else {
            None
        };

        self.slab_insertion.insert(SourceMapping {
            warp_sync: warp_sync_source_id,
            all_forks: all_forks_source_id,
            user_data: source_user_data,
            num_requests: 0,
        });

        outer_source_id
    }
}

/// See [`AllSync::desired_requests`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum DesiredRequest {
    /// Requesting blocks from the source is requested.
    ///
    /// The blocks should be provided in decreasing number, with `first_block_hash` as the highest
    /// number.
    BlocksRequest {
        /// Height of the first block to request.
        first_block_height: u64,
        /// Hash of the first block to request.
        first_block_hash: [u8; 32],
        /// Number of blocks the request should return.
        ///
        /// Note that this is only an indication, and the source is free to give fewer blocks
        /// than requested.
        ///
        /// This might be equal to `u64::MAX` in case no upper bound is required. The API
        /// user is responsible for clamping this value to a reasonable limit.
        num_blocks: NonZero<u64>,
        /// `True` if headers should be included in the response.
        request_headers: bool,
        /// `True` if bodies should be included in the response.
        request_bodies: bool,
        /// `True` if the justification should be included in the response, if any.
        request_justification: bool,
    },

    /// Sending a Grandpa warp sync request is requested.
    WarpSync {
        /// Hash of the known finalized block. Starting point of the request.
        sync_start_block_hash: [u8; 32],
    },

    /// Sending a storage query is requested.
    StorageGetMerkleProof {
        /// Hash of the block whose storage is requested.
        block_hash: [u8; 32],
        /// Merkle value of the root of the storage trie of the block.
        state_trie_root: [u8; 32],
        /// Keys whose values is requested.
        keys: Vec<Vec<u8>>,
    },

    /// Sending a call proof query is requested.
    RuntimeCallMerkleProof {
        /// Hash of the block whose call is made against.
        block_hash: [u8; 32],
        /// Name of the function to be called.
        function_name: Cow<'static, str>,
        /// Concatenated SCALE-encoded parameters to provide to the call.
        parameter_vectored: Cow<'static, [u8]>,
    },
}

/// See [`AllSync::desired_requests`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum RequestDetail {
    /// Requesting blocks from the source is requested.
    BlocksRequest {
        /// Height of the first block to request.
        first_block_height: u64,
        /// Hash of the first block to request.
        first_block_hash: [u8; 32],
        /// Number of blocks the request should return.
        ///
        /// Note that this is only an indication, and the source is free to give fewer blocks
        /// than requested.
        ///
        /// This might be equal to `u64::MAX` in case no upper bound is required. The API
        /// user is responsible for clamping this value to a reasonable limit.
        num_blocks: NonZero<u64>,
        /// `True` if headers should be included in the response.
        request_headers: bool,
        /// `True` if bodies should be included in the response.
        request_bodies: bool,
        /// `True` if the justification should be included in the response, if any.
        request_justification: bool,
    },

    /// Sending a Grandpa warp sync request is requested.
    WarpSync {
        /// Hash of the known finalized block. Starting point of the request.
        sync_start_block_hash: [u8; 32],
    },

    /// Sending a storage query is requested.
    StorageGet {
        /// Hash of the block whose storage is requested.
        block_hash: [u8; 32],
        /// Keys whose values is requested.
        keys: Vec<Vec<u8>>,
    },

    /// Sending a call proof query is requested.
    RuntimeCallMerkleProof {
        /// Hash of the block whose call is made against.
        block_hash: [u8; 32],
        /// Name of the function to be called.
        function_name: Cow<'static, str>,
        /// Concatenated SCALE-encoded parameters to provide to the call.
        parameter_vectored: Cow<'static, [u8]>,
    },
}

impl From<DesiredRequest> for RequestDetail {
    fn from(rq: DesiredRequest) -> RequestDetail {
        match rq {
            DesiredRequest::BlocksRequest {
                first_block_height,
                first_block_hash,
                num_blocks,
                request_headers,
                request_bodies,
                request_justification,
            } => RequestDetail::BlocksRequest {
                first_block_height,
                first_block_hash,
                num_blocks,
                request_headers,
                request_bodies,
                request_justification,
            },
            DesiredRequest::WarpSync {
                sync_start_block_hash,
            } => RequestDetail::WarpSync {
                sync_start_block_hash,
            },
            DesiredRequest::StorageGetMerkleProof {
                block_hash, keys, ..
            } => RequestDetail::StorageGet { block_hash, keys },
            DesiredRequest::RuntimeCallMerkleProof {
                block_hash,
                function_name,
                parameter_vectored,
            } => RequestDetail::RuntimeCallMerkleProof {
                block_hash,
                function_name,
                parameter_vectored,
            },
        }
    }
}

pub struct BlockRequestSuccessBlock<TBl> {
    pub scale_encoded_header: Vec<u8>,
    pub scale_encoded_justifications: Vec<Justification>,
    pub scale_encoded_extrinsics: Vec<Vec<u8>>,
    pub user_data: TBl,
}

/// See [`BlockRequestSuccessBlock::scale_encoded_justifications`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Justification {
    /// Short identifier of the consensus engine associated with that justification.
    pub engine_id: [u8; 4],
    /// Body of the justification.
    pub justification: Vec<u8>,
}

/// Outcome of calling [`AllSync::block_announce`].
pub enum BlockAnnounceOutcome<'a, TRq, TSrc, TBl> {
    /// Announced block is too old to be part of the finalized chain.
    ///
    /// It is assumed that all sources will eventually agree on the same finalized chain. Blocks
    /// whose height is inferior to the height of the latest known finalized block should simply
    /// be ignored. Whether or not this old block is indeed part of the finalized block isn't
    /// verified, and it is assumed that the source is simply late.
    ///
    /// If the announced block was the source's best block, the state machine has been updated to
    /// take this information into account.
    TooOld {
        /// Height of the announced block.
        announce_block_height: u64,
        /// Height of the currently finalized block.
        finalized_block_height: u64,
    },

    /// Announced block has already been successfully verified and is part of the non-finalized
    /// chain.
    AlreadyVerified(AnnouncedBlockKnown<'a, TRq, TSrc, TBl>),

    /// Announced block is already known by the state machine but hasn't been verified yet.
    AlreadyPending(AnnouncedBlockKnown<'a, TRq, TSrc, TBl>),

    /// Announced block isn't in the state machine.
    Unknown(AnnouncedBlockUnknown<'a, TRq, TSrc, TBl>),

    /// Failed to decode announce header.
    InvalidHeader(header::Error),
}

/// See [`BlockAnnounceOutcome`] and [`AllSync::block_announce`].
#[must_use]
pub struct AnnouncedBlockKnown<'a, TRq, TSrc, TBl> {
    inner:
        all_forks::AnnouncedBlockKnown<'a, Option<TBl>, AllForksRequestExtra, AllForksSourceExtra>,
    marker: PhantomData<(TSrc, TRq)>,
}

impl<'a, TRq, TSrc, TBl> AnnouncedBlockKnown<'a, TRq, TSrc, TBl> {
    /// Returns the parent hash of the announced block.
    pub fn parent_hash(&self) -> &[u8; 32] {
        self.inner.parent_hash()
    }

    /// Returns the height of the announced block.
    pub fn height(&self) -> u64 {
        self.inner.height()
    }

    /// Returns the hash of the announced block.
    pub fn hash(&self) -> &[u8; 32] {
        self.inner.hash()
    }

    /// Gives access to the user data of the block.
    pub fn user_data_mut(&mut self) -> &mut TBl {
        self.inner
            .user_data_mut()
            .as_mut()
            .unwrap_or_else(|| unreachable!())
    }

    /// Updates the state machine to keep track of the fact that this source knows this block.
    /// If the announced block is the source's best block, also updates this information.
    pub fn update_source_and_block(self) {
        self.inner.update_source_and_block()
    }
}

/// See [`BlockAnnounceOutcome`] and [`AllForksSync::block_announce`].
#[must_use]
pub struct AnnouncedBlockUnknown<'a, TRq, TSrc, TBl> {
    inner: all_forks::AnnouncedBlockUnknown<
        'a,
        Option<TBl>,
        AllForksRequestExtra,
        AllForksSourceExtra,
    >,
    marker: PhantomData<(TSrc, TRq)>,
}

impl<'a, TRq, TSrc, TBl> AnnouncedBlockUnknown<'a, TRq, TSrc, TBl> {
    /// Returns the parent hash of the announced block.
    pub fn parent_hash(&self) -> &[u8; 32] {
        self.inner.parent_hash()
    }

    /// Returns the height of the announced block.
    pub fn height(&self) -> u64 {
        self.inner.height()
    }

    /// Returns the hash of the announced block.
    pub fn hash(&self) -> &[u8; 32] {
        self.inner.hash()
    }

    /// Inserts the block in the state machine and keeps track of the fact that this source knows
    /// this block.
    ///
    /// If the announced block is the source's best block, also updates this information.
    pub fn insert_and_update_source(self, user_data: TBl) {
        self.inner.insert_and_update_source(Some(user_data))
    }
}

/// Response to a GrandPa warp sync request.
#[derive(Debug)]
pub struct WarpSyncResponseFragment<'a> {
    /// Header of a block in the chain.
    pub scale_encoded_header: &'a [u8],

    /// Justification that proves the finality of
    /// [`WarpSyncResponseFragment::scale_encoded_header`].
    pub scale_encoded_justification: &'a [u8],
}

/// Outcome of calling [`AllSync::process_one`].
pub enum ProcessOne<TRq, TSrc, TBl> {
    /// No block ready to be processed.
    AllSync(AllSync<TRq, TSrc, TBl>),

    /// Building the runtime is necessary in order for the warp syncing to continue.
    WarpSyncBuildRuntime(WarpSyncBuildRuntime<TRq, TSrc, TBl>),

    /// Building the chain information is necessary in order for the warp syncing to continue.
    WarpSyncBuildChainInformation(WarpSyncBuildChainInformation<TRq, TSrc, TBl>),

    /// Response has made it possible to finish warp syncing.
    WarpSyncFinished {
        sync: AllSync<TRq, TSrc, TBl>,

        /// Runtime of the newly finalized block.
        ///
        /// > **Note**: Use methods such as [`AllSync::finalized_block_header`] to know which
        /// >           block this runtime corresponds to.
        finalized_block_runtime: host::HostVmPrototype,

        /// SCALE-encoded extrinsics of the finalized block. The ordering is important.
        ///
        /// `Some` if and only if [`Config::download_bodies`] was `true`.
        finalized_body: Option<Vec<Vec<u8>>>,

        /// Storage value at the `:code` key of the finalized block.
        finalized_storage_code: Option<Vec<u8>>,

        /// Storage value at the `:heappages` key of the finalized block.
        finalized_storage_heap_pages: Option<Vec<u8>>,

        /// Merkle value of the `:code` trie node of the finalized block.
        finalized_storage_code_merkle_value: Option<Vec<u8>>,

        /// Closest ancestor of the `:code` trie node of the finalized block excluding `:code`
        /// itself.
        finalized_storage_code_closest_ancestor_excluding: Option<Vec<Nibble>>,
    },

    /// Ready to start verifying a block.
    VerifyBlock(BlockVerify<TRq, TSrc, TBl>),

    /// Ready to start verifying a proof of finality.
    VerifyFinalityProof(FinalityProofVerify<TRq, TSrc, TBl>),

    /// Ready to start verifying a warp sync fragment.
    VerifyWarpSyncFragment(WarpSyncFragmentVerify<TRq, TSrc, TBl>),
}

/// Outcome of injecting a response in the [`AllSync`].
pub enum ResponseOutcome {
    /// Request was no longer interesting for the state machine.
    Outdated,

    /// Content of the response has been queued and will be processed later.
    Queued,

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

/// See [`AllSync::grandpa_commit_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrandpaCommitMessageOutcome {
    /// Message has been silently discarded.
    Discarded,
    /// Message has been queued for later verification.
    Queued,
}

// TODO: doc
#[derive(Debug, Clone)]
pub struct Block<TBl> {
    /// Header of the block.
    pub header: Vec<u8>,

    /// Hash of the block.
    pub block_hash: [u8; 32],

    /// User data associated to the block.
    pub user_data: TBl,
}

pub struct BlockVerify<TRq, TSrc, TBl> {
    inner: all_forks::BlockVerify<Option<TBl>, AllForksRequestExtra, AllForksSourceExtra>,
    warp_sync: Option<warp_sync::WarpSync<WarpSyncSourceExtra, WarpSyncRequestExtra>>,
    ready_to_transition: Option<warp_sync::RuntimeInformation>,
    shared: Shared<TRq, TSrc>,
}

impl<TRq, TSrc, TBl> BlockVerify<TRq, TSrc, TBl> {
    /// Returns the hash of the block to be verified.
    pub fn hash(&self) -> [u8; 32] {
        // TODO: return by ref
        *self.inner.hash()
    }

    /// Returns the list of SCALE-encoded extrinsics of the block to verify.
    ///
    /// This is `Some` if and only if [`Config::download_bodies`] is `true`
    pub fn scale_encoded_extrinsics(
        &self,
    ) -> Option<impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone> + Clone> {
        self.inner.scale_encoded_extrinsics()
    }

    /// Returns the SCALE-encoded header of the block about to be verified.
    pub fn scale_encoded_header(&self) -> &[u8] {
        self.inner.scale_encoded_header()
    }

    /// Verify the header of the block.
    pub fn verify_header(
        self,
        now_from_unix_epoch: Duration,
    ) -> HeaderVerifyOutcome<TRq, TSrc, TBl> {
        let verified_block_hash = *self.inner.hash();

        match self.inner.verify_header(now_from_unix_epoch) {
            all_forks::HeaderVerifyOutcome::Success {
                is_new_best,
                success,
            } => HeaderVerifyOutcome::Success {
                is_new_best,
                success: HeaderVerifySuccess {
                    inner: success,
                    warp_sync: self.warp_sync,
                    ready_to_transition: self.ready_to_transition,
                    shared: self.shared,
                    verified_block_hash,
                },
            },
            all_forks::HeaderVerifyOutcome::Error { sync, error } => HeaderVerifyOutcome::Error {
                sync: AllSync {
                    all_forks: Some(sync),
                    warp_sync: self.warp_sync,
                    ready_to_transition: self.ready_to_transition,
                    shared: self.shared,
                },
                error: match error {
                    all_forks::HeaderVerifyError::VerificationFailed(error) => {
                        HeaderVerifyError::VerificationFailed(error)
                    }
                    all_forks::HeaderVerifyError::UnknownConsensusEngine => {
                        HeaderVerifyError::UnknownConsensusEngine
                    }
                    all_forks::HeaderVerifyError::ConsensusMismatch => {
                        HeaderVerifyError::ConsensusMismatch
                    }
                },
            },
        }
    }
}

/// Outcome of calling [`BlockVerify::verify_header`].
pub enum HeaderVerifyOutcome<TRq, TSrc, TBl> {
    /// Header has been successfully verified.
    Success {
        /// True if the newly-verified block is considered the new best block.
        is_new_best: bool,
        success: HeaderVerifySuccess<TRq, TSrc, TBl>,
    },

    /// Header verification failed.
    Error {
        /// State machine yielded back. Use to continue the processing.
        sync: AllSync<TRq, TSrc, TBl>,
        /// Error that happened.
        error: HeaderVerifyError,
    },
}

/// Error that can happen when verifying a block header.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum HeaderVerifyError {
    /// Block can't be verified as it uses an unknown consensus engine.
    UnknownConsensusEngine,
    /// Block uses a different consensus than the rest of the chain.
    ConsensusMismatch,
    /// The block verification has failed. The block is invalid and should be thrown away.
    #[display("{_0}")]
    VerificationFailed(verify::header_only::Error),
}

pub struct HeaderVerifySuccess<TRq, TSrc, TBl> {
    inner: all_forks::HeaderVerifySuccess<Option<TBl>, AllForksRequestExtra, AllForksSourceExtra>,
    warp_sync: Option<warp_sync::WarpSync<WarpSyncSourceExtra, WarpSyncRequestExtra>>,
    ready_to_transition: Option<warp_sync::RuntimeInformation>,
    shared: Shared<TRq, TSrc>,
    verified_block_hash: [u8; 32],
}

impl<TRq, TSrc, TBl> HeaderVerifySuccess<TRq, TSrc, TBl> {
    /// Returns the height of the block that was verified.
    pub fn height(&self) -> u64 {
        self.inner.height()
    }

    /// Returns the hash of the block that was verified.
    pub fn hash(&self) -> [u8; 32] {
        // TODO: return by ref
        *self.inner.hash()
    }

    /// Returns the list of SCALE-encoded extrinsics of the block to verify.
    ///
    /// This is `Some` if and only if [`Config::download_bodies`] is `true`
    pub fn scale_encoded_extrinsics(
        &self,
    ) -> Option<impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone> + Clone> {
        self.inner.scale_encoded_extrinsics()
    }

    /// Returns the hash of the parent of the block that was verified.
    pub fn parent_hash(&self) -> &[u8; 32] {
        self.inner.parent_hash()
    }

    /// Returns the user data of the parent of the block to be verified, or `None` if the parent
    /// is the finalized block.
    pub fn parent_user_data(&self) -> Option<&TBl> {
        self.inner
            .parent_user_data()
            .map(|ud| ud.as_ref().unwrap_or_else(|| unreachable!()))
    }

    /// Returns the SCALE-encoded header of the block that was verified.
    pub fn scale_encoded_header(&self) -> &[u8] {
        self.inner.scale_encoded_header()
    }

    /// Returns the SCALE-encoded header of the parent of the block.
    pub fn parent_scale_encoded_header(&self) -> &[u8] {
        self.inner.parent_scale_encoded_header()
    }

    /// Cancel the block verification.
    pub fn cancel(self) -> AllSync<TRq, TSrc, TBl> {
        let all_forks = self.inner.cancel();
        AllSync {
            all_forks: Some(all_forks),
            warp_sync: self.warp_sync,
            ready_to_transition: self.ready_to_transition,
            shared: self.shared,
        }
    }

    /// Reject the block and mark it as bad.
    pub fn reject_bad_block(self) -> AllSync<TRq, TSrc, TBl> {
        let all_forks = self.inner.reject_bad_block();
        AllSync {
            all_forks: Some(all_forks),
            warp_sync: self.warp_sync,
            ready_to_transition: self.ready_to_transition,
            shared: self.shared,
        }
    }

    /// Finish inserting the block header.
    pub fn finish(self, user_data: TBl) -> AllSync<TRq, TSrc, TBl> {
        let height = self.height();
        let mut all_forks = self.inner.finish();
        all_forks[(height, &self.verified_block_hash)] = Some(user_data);
        AllSync {
            all_forks: Some(all_forks),
            warp_sync: self.warp_sync,
            ready_to_transition: self.ready_to_transition,
            shared: self.shared,
        }
    }
}

pub struct FinalityProofVerify<TRq, TSrc, TBl> {
    inner: all_forks::FinalityProofVerify<Option<TBl>, AllForksRequestExtra, AllForksSourceExtra>,
    warp_sync: Option<warp_sync::WarpSync<WarpSyncSourceExtra, WarpSyncRequestExtra>>,
    ready_to_transition: Option<warp_sync::RuntimeInformation>,
    shared: Shared<TRq, TSrc>,
}

impl<TRq, TSrc, TBl> FinalityProofVerify<TRq, TSrc, TBl> {
    /// Returns the source the justification was obtained from.
    pub fn sender(&self) -> (SourceId, &TSrc) {
        let sender = self.inner.sender().1;
        (
            sender.outer_source_id,
            &self.shared.sources[sender.outer_source_id.0].user_data,
        )
    }

    /// Perform the verification.
    ///
    /// A randomness seed must be provided and will be used during the verification. Note that the
    /// verification is nonetheless deterministic.
    pub fn perform(
        mut self,
        randomness_seed: [u8; 32],
    ) -> (AllSync<TRq, TSrc, TBl>, FinalityProofVerifyOutcome<TBl>) {
        let (all_forks, outcome) = match self.inner.perform(randomness_seed) {
            (
                sync,
                all_forks::FinalityProofVerifyOutcome::NewFinalized {
                    finalized_blocks_newest_to_oldest,
                    pruned_blocks,
                    updates_best_block,
                },
            ) => {
                if let Some(warp_sync) = &mut self.warp_sync {
                    warp_sync.set_chain_information(sync.as_chain_information())
                }

                (
                    sync,
                    // TODO: weird conversions
                    FinalityProofVerifyOutcome::NewFinalized {
                        finalized_blocks_newest_to_oldest: finalized_blocks_newest_to_oldest
                            .into_iter()
                            .map(|b| Block {
                                header: b.scale_encoded_header,
                                block_hash: b.block_hash,
                                user_data: b.user_data.unwrap(),
                            })
                            .collect(),
                        pruned_blocks: pruned_blocks.into_iter().map(|b| b.block_hash).collect(),
                        updates_best_block,
                    },
                )
            }
            (sync, all_forks::FinalityProofVerifyOutcome::AlreadyFinalized) => {
                (sync, FinalityProofVerifyOutcome::AlreadyFinalized)
            }
            (sync, all_forks::FinalityProofVerifyOutcome::GrandpaCommitPending) => {
                (sync, FinalityProofVerifyOutcome::GrandpaCommitPending)
            }
            (sync, all_forks::FinalityProofVerifyOutcome::JustificationError(error)) => {
                (sync, FinalityProofVerifyOutcome::JustificationError(error))
            }
            (sync, all_forks::FinalityProofVerifyOutcome::GrandpaCommitError(error)) => {
                (sync, FinalityProofVerifyOutcome::GrandpaCommitError(error))
            }
        };

        (
            AllSync {
                all_forks: Some(all_forks),
                warp_sync: self.warp_sync,
                ready_to_transition: self.ready_to_transition,
                shared: self.shared,
            },
            outcome,
        )
    }
}

/// Information about the outcome of verifying a finality proof.
#[derive(Debug)]
pub enum FinalityProofVerifyOutcome<TBl> {
    /// Proof verification successful. The block and all its ancestors is now finalized.
    NewFinalized {
        /// List of finalized blocks, in decreasing block number.
        finalized_blocks_newest_to_oldest: Vec<Block<TBl>>,
        /// List of hashes of blocks that are no longer descendant of the finalized block, in
        /// an unspecified order.
        pruned_blocks: Vec<[u8; 32]>,
        /// If `true`, this operation modifies the best block of the non-finalized chain.
        /// This can happen if the previous best block isn't a descendant of the now finalized
        /// block.
        updates_best_block: bool,
    },
    /// Finality proof concerns block that was already finalized.
    AlreadyFinalized,
    /// GrandPa commit cannot be verified yet and has been stored for later.
    GrandpaCommitPending,
    /// Problem while verifying justification.
    JustificationError(JustificationVerifyError),
    /// Problem while verifying GrandPa commit.
    GrandpaCommitError(CommitVerifyError),
}

/// Returned by [`AllSync::set_finalized_block`].
pub struct SetFinalizedBlockResult<TBl> {
    /// The finalized blocks.
    pub finalized_blocks: Vec<Block<TBl>>,
    /// The blocks that got pruned while finalizing.
    pub pruned_blocks: Vec<[u8; 32]>,
    /// Is set to `true`, if the best block changed.
    pub updates_best_block: bool,
}

/// Potential error returned by [`AllSync::set_finalized_block`].
#[derive(Debug, derive_more::Display)]
pub enum SetFinalizedBlockError {
    UnknownBlock,
}

pub struct WarpSyncFragmentVerify<TRq, TSrc, TBl> {
    inner: warp_sync::VerifyWarpSyncFragment<WarpSyncSourceExtra, WarpSyncRequestExtra>,
    ready_to_transition: Option<warp_sync::RuntimeInformation>,
    shared: Shared<TRq, TSrc>,
    all_forks: all_forks::AllForksSync<Option<TBl>, AllForksRequestExtra, AllForksSourceExtra>,
}

impl<TRq, TSrc, TBl> WarpSyncFragmentVerify<TRq, TSrc, TBl> {
    /// Returns the identifier and user data of the source that has sent the fragment to be
    /// verified.
    ///
    /// Returns `None` if the source has been removed since the fragments have been downloaded.
    pub fn proof_sender(&self) -> Option<(SourceId, &TSrc)> {
        let (_, ud) = self.inner.proof_sender()?;
        Some((
            ud.outer_source_id,
            &self.shared.sources[ud.outer_source_id.0].user_data,
        ))
    }

    /// Perform the verification.
    ///
    /// A randomness seed must be provided and will be used during the verification. Note that the
    /// verification is nonetheless deterministic.
    ///
    /// On success, returns the block hash and height that have been verified as being part of
    /// the chain.
    pub fn perform(
        self,
        randomness_seed: [u8; 32],
    ) -> (
        AllSync<TRq, TSrc, TBl>,
        Result<([u8; 32], u64), VerifyFragmentError>,
    ) {
        let (warp_sync, result) = self.inner.verify(randomness_seed);

        (
            AllSync {
                warp_sync: Some(warp_sync),
                ready_to_transition: self.ready_to_transition,
                all_forks: Some(self.all_forks),
                shared: self.shared,
            },
            result,
        )
    }
}

/// Compiling a new runtime is necessary for the warp sync process.
#[must_use]
pub struct WarpSyncBuildRuntime<TRq, TSrc, TBl> {
    inner: warp_sync::BuildRuntime<WarpSyncSourceExtra, WarpSyncRequestExtra>,
    ready_to_transition: Option<warp_sync::RuntimeInformation>,
    shared: Shared<TRq, TSrc>,
    all_forks: all_forks::AllForksSync<Option<TBl>, AllForksRequestExtra, AllForksSourceExtra>,
}

impl<TRq, TSrc, TBl> WarpSyncBuildRuntime<TRq, TSrc, TBl> {
    /// Builds the runtime.
    ///
    /// Assuming that the warp syncing goes to completion, the provided parameters are used to
    /// compile the runtime that will be yielded in
    /// [`ProcessOne::WarpSyncFinished::finalized_block_runtime`].
    pub fn build(
        self,
        exec_hint: ExecHint,
        allow_unresolved_imports: bool,
    ) -> (
        AllSync<TRq, TSrc, TBl>,
        Result<(), WarpSyncBuildRuntimeError>,
    ) {
        let (warp_sync, outcome) = self.inner.build(exec_hint, allow_unresolved_imports);

        (
            AllSync {
                warp_sync: Some(warp_sync),
                ready_to_transition: self.ready_to_transition,
                all_forks: Some(self.all_forks),
                shared: self.shared,
            },
            outcome,
        )
    }
}

/// Building the chain information is necessary for the warp sync process.
#[must_use]
pub struct WarpSyncBuildChainInformation<TRq, TSrc, TBl> {
    inner: warp_sync::BuildChainInformation<WarpSyncSourceExtra, WarpSyncRequestExtra>,
    shared: Shared<TRq, TSrc>,
    all_forks: all_forks::AllForksSync<Option<TBl>, AllForksRequestExtra, AllForksSourceExtra>,
}

impl<TRq, TSrc, TBl> WarpSyncBuildChainInformation<TRq, TSrc, TBl> {
    /// Builds the chain information.
    pub fn build(
        self,
    ) -> (
        AllSync<TRq, TSrc, TBl>,
        Result<(), WarpSyncBuildChainInformationError>,
    ) {
        let (warp_sync, outcome) = self.inner.build();

        let (ready_to_transition, outcome) = match outcome {
            Ok(info) => (Some(info), Ok(())),
            Err(err) => (None, Err(err)),
        };

        (
            AllSync {
                warp_sync: Some(warp_sync),
                ready_to_transition,
                all_forks: Some(self.all_forks),
                shared: self.shared,
            },
            outcome,
        )
    }
}

// TODO: are these structs useful?
struct AllForksSourceExtra {
    outer_source_id: SourceId,
}

struct AllForksRequestExtra {
    outer_request_id: RequestId,
}

struct WarpSyncSourceExtra {
    outer_source_id: SourceId,
}

// TODO: consider removing struct altogether
struct WarpSyncRequestExtra {}

struct Shared<TRq, TSrc> {
    sources: slab::Slab<SourceMapping<TSrc>>,
    requests: slab::Slab<RequestInfo<TRq>>,

    /// See [`Config::download_bodies`].
    download_bodies: bool,

    /// Value passed through [`Config::sources_capacity`].
    sources_capacity: usize,
    /// Value passed through [`Config::blocks_capacity`].
    blocks_capacity: usize,
    /// Value passed through [`Config::max_disjoint_headers`].
    max_disjoint_headers: usize,
    /// Value passed through [`Config::max_requests_per_block`].
    max_requests_per_block: NonZero<u32>,
    /// Value passed through [`Config::block_number_bytes`].
    block_number_bytes: usize,
    /// Value passed through [`Config::allow_unknown_consensus_engines`].
    allow_unknown_consensus_engines: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestInfo<TRq> {
    warp_sync: Option<warp_sync::RequestId>,
    all_forks: Option<all_forks::RequestId>,
    source_id: SourceId,
    user_data: TRq,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceMapping<TSrc> {
    warp_sync: Option<warp_sync::SourceId>,
    all_forks: all_forks::SourceId,
    // TODO: all_forks also has a requests count tracker, deduplicate
    num_requests: usize,
    user_data: TSrc,
}

fn all_forks_request_convert(
    rq_params: all_forks::RequestParams,
    download_body: bool,
) -> DesiredRequest {
    DesiredRequest::BlocksRequest {
        first_block_hash: rq_params.first_block_hash,
        first_block_height: rq_params.first_block_height,
        num_blocks: rq_params.num_blocks,
        request_bodies: download_body,
        request_headers: true,
        request_justification: true,
    }
}
