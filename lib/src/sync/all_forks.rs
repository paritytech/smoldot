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
    finality::decode,
    header, verify,
};

use alloc::{borrow::ToOwned as _, boxed::Box, vec::Vec};
use core::{cmp, mem, num::NonZero, ops, time::Duration};

mod disjoint;
mod pending_blocks;

pub mod sources;

pub use pending_blocks::{RequestId, RequestParams, SourceId};

/// Configuration for the [`AllForksSync`].
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
    /// `10%` chance of failing, then setting to value to `2` gives a `1%` chance that downloading
    /// this block will overall fail and has to be attempted again.
    ///
    /// Also keep in mind that sources might maliciously take a long time to answer requests. A
    /// higher value makes it possible to reduce the risks of the syncing taking a long time
    /// because of malicious sources.
    ///
    /// The higher the value, the more bandwidth is potentially wasted.
    pub max_requests_per_block: NonZero<u32>,

    /// If true, the body of a block is downloaded (if necessary) before a
    /// [`ProcessOne::BlockVerify`] is generated.
    pub download_bodies: bool,
}

pub struct AllForksSync<TBl, TRq, TSrc> {
    /// Data structure containing the non-finalized blocks.
    chain: blocks_tree::NonFinalizedTree<TBl>,

    /// Extra fields. In a separate structure in order to be moved around.
    inner: Box<Inner<TBl, TRq, TSrc>>,
}

/// Extra fields. In a separate structure in order to be moved around.
struct Inner<TBl, TRq, TSrc> {
    blocks: pending_blocks::PendingBlocks<PendingBlock<TBl>, TRq, Source<TSrc>>,
}

struct PendingBlock<TBl> {
    header: Option<Vec<u8>>,
    /// SCALE-encoded extrinsics of the block. `None` if unknown. Only ever filled
    /// if [`Config::download_bodies`] was `true`.
    body: Option<Vec<Vec<u8>>>,
    user_data: TBl,
}

struct Source<TSrc> {
    /// Each source stores between zero and two finality proofs that haven't been verified yet.
    ///
    /// If more than two finality proofs are received from the same source, only the one with the
    /// lowest target block and the one with the highest target block are kept in memory. This is
    /// done in order to have a maximum bound to the amount of memory that is allocated per source
    /// and avoid DoS attack vectors.
    ///
    /// The finality proof with the highest target block is the "best" finality proof. However,
    /// keeping the finality proof with the lowest target block guarantees that, assuming the
    /// source isn't malicious, we will able to make *some* progress in the finality.
    unverified_finality_proofs: SourcePendingJustificationProofs,

    /// Height of the highest finalized block according to that source. `0` if unknown.
    finalized_block_number: u64,

    /// Similar to [`Source::unverified_finality_proofs`]. Contains proofs that have been checked
    /// and have been determined to not be verifiable right now.
    pending_finality_proofs: SourcePendingJustificationProofs,

    /// Opaque data chosen by the API user.
    user_data: TSrc,
}

enum SourcePendingJustificationProofs {
    None,
    One {
        target_height: u64,
        proof: FinalityProofs,
    },
    Two {
        low_target_height: u64,
        low_proof: FinalityProofs,
        high_target_height: u64,
        high_proof: FinalityProofs,
    },
}

impl SourcePendingJustificationProofs {
    fn is_none(&self) -> bool {
        matches!(self, SourcePendingJustificationProofs::None)
    }

    fn insert(&mut self, new_target_height: u64, new_proof: FinalityProofs) {
        // An empty list of justifications is an invalid state.
        debug_assert!(
            !matches!(&new_proof, FinalityProofs::Justifications(list) if list.is_empty())
        );

        match mem::replace(self, SourcePendingJustificationProofs::None) {
            SourcePendingJustificationProofs::None => {
                *self = SourcePendingJustificationProofs::One {
                    target_height: new_target_height,
                    proof: new_proof,
                };
            }
            SourcePendingJustificationProofs::One {
                target_height,
                proof,
            } if target_height < new_target_height => {
                *self = SourcePendingJustificationProofs::Two {
                    low_target_height: target_height,
                    low_proof: proof,
                    high_target_height: new_target_height,
                    high_proof: new_proof,
                };
            }
            SourcePendingJustificationProofs::One {
                target_height,
                proof,
            } if target_height > new_target_height => {
                *self = SourcePendingJustificationProofs::Two {
                    low_target_height: new_target_height,
                    low_proof: new_proof,
                    high_target_height: target_height,
                    high_proof: proof,
                };
            }
            SourcePendingJustificationProofs::One { .. } => {
                *self = SourcePendingJustificationProofs::One {
                    target_height: new_target_height,
                    proof: new_proof,
                };
            }
            SourcePendingJustificationProofs::Two {
                high_target_height,
                low_proof,
                low_target_height,
                ..
            } if new_target_height >= high_target_height => {
                *self = SourcePendingJustificationProofs::Two {
                    high_proof: new_proof,
                    high_target_height: new_target_height,
                    low_proof,
                    low_target_height,
                };
            }
            SourcePendingJustificationProofs::Two {
                high_proof,
                high_target_height,
                low_target_height,
                ..
            } if new_target_height <= low_target_height => {
                *self = SourcePendingJustificationProofs::Two {
                    high_proof,
                    high_target_height,
                    low_proof: new_proof,
                    low_target_height: new_target_height,
                };
            }
            val @ SourcePendingJustificationProofs::Two { .. } => {
                *self = val;
            }
        }
    }

    fn take_one(&mut self) -> Option<FinalityProof> {
        match mem::replace(self, SourcePendingJustificationProofs::None) {
            SourcePendingJustificationProofs::None => {
                *self = SourcePendingJustificationProofs::None;
                None
            }
            SourcePendingJustificationProofs::One {
                proof: FinalityProofs::GrandpaCommit(commit),
                ..
            } => {
                *self = SourcePendingJustificationProofs::None;
                Some(FinalityProof::GrandpaCommit(commit))
            }
            SourcePendingJustificationProofs::One {
                proof: FinalityProofs::Justifications(justifications),
                ..
            } if justifications.len() == 1 => {
                *self = SourcePendingJustificationProofs::None;
                let j = justifications.into_iter().next().unwrap();
                Some(FinalityProof::Justification(j))
            }
            SourcePendingJustificationProofs::One {
                target_height,
                proof: FinalityProofs::Justifications(mut justifications),
            } => {
                let j = justifications.pop().unwrap();
                *self = SourcePendingJustificationProofs::One {
                    target_height,
                    proof: FinalityProofs::Justifications(justifications),
                };
                Some(FinalityProof::Justification(j))
            }
            SourcePendingJustificationProofs::Two {
                high_proof: FinalityProofs::GrandpaCommit(commit),
                low_proof,
                low_target_height,
                ..
            } => {
                *self = SourcePendingJustificationProofs::One {
                    target_height: low_target_height,
                    proof: low_proof,
                };
                Some(FinalityProof::GrandpaCommit(commit))
            }
            SourcePendingJustificationProofs::Two {
                high_proof: FinalityProofs::Justifications(justifications),
                low_proof,
                low_target_height,
                ..
            } if justifications.len() == 1 => {
                let j = justifications.into_iter().next().unwrap();
                *self = SourcePendingJustificationProofs::One {
                    target_height: low_target_height,
                    proof: low_proof,
                };
                Some(FinalityProof::Justification(j))
            }
            SourcePendingJustificationProofs::Two {
                high_proof: FinalityProofs::Justifications(mut justifications),
                high_target_height,
                low_proof,
                low_target_height,
            } => {
                let j = justifications.pop().unwrap();
                *self = SourcePendingJustificationProofs::Two {
                    high_proof: FinalityProofs::Justifications(justifications),
                    high_target_height,
                    low_proof,
                    low_target_height,
                };
                Some(FinalityProof::Justification(j))
            }
        }
    }

    fn merge(&mut self, other: Self) {
        match other {
            SourcePendingJustificationProofs::None => {}
            SourcePendingJustificationProofs::One {
                target_height,
                proof,
            } => self.insert(target_height, proof),
            SourcePendingJustificationProofs::Two {
                high_proof,
                high_target_height,
                low_proof,
                low_target_height,
            } => {
                self.insert(high_target_height, high_proof);
                self.insert(low_target_height, low_proof);
            }
        }
    }
}

enum FinalityProofs {
    GrandpaCommit(Vec<u8>),
    Justifications(Vec<([u8; 4], Vec<u8>)>),
}

enum FinalityProof {
    GrandpaCommit(Vec<u8>),
    Justification(([u8; 4], Vec<u8>)),
}

impl<TBl, TRq, TSrc> AllForksSync<TBl, TRq, TSrc> {
    /// Initializes a new [`AllForksSync`].
    pub fn new(config: Config) -> Self {
        let finalized_block_height = config
            .chain_information
            .as_ref()
            .finalized_block_header
            .number;

        let chain = blocks_tree::NonFinalizedTree::new(blocks_tree::Config {
            chain_information: config.chain_information,
            block_number_bytes: config.block_number_bytes,
            blocks_capacity: config.blocks_capacity,
            allow_unknown_consensus_engines: config.allow_unknown_consensus_engines,
        });

        Self {
            chain,
            inner: Box::new(Inner {
                blocks: pending_blocks::PendingBlocks::new(pending_blocks::Config {
                    blocks_capacity: config.blocks_capacity,
                    finalized_block_height,
                    max_requests_per_block: config.max_requests_per_block,
                    sources_capacity: config.sources_capacity,
                    download_bodies: config.download_bodies,
                }),
            }),
        }
    }

    /// Returns the value that was initially passed in [`Config::block_number_bytes`].
    pub fn block_number_bytes(&self) -> usize {
        self.chain.block_number_bytes()
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct corresponding to the current
    /// latest finalized block. Can later be used to reconstruct a chain.
    pub fn as_chain_information(&'_ self) -> chain_information::ValidChainInformationRef<'_> {
        self.chain.as_chain_information()
    }

    /// Returns the header of the finalized block.
    pub fn finalized_block_header(&self) -> &[u8] {
        self.chain.finalized_block_header()
    }

    /// Returns the height of the finalized block.
    pub fn finalized_block_number(&self) -> u64 {
        self.chain.finalized_block_height()
    }

    /// Returns the hash of the finalized block.
    pub fn finalized_block_hash(&self) -> &[u8; 32] {
        self.chain.finalized_block_hash()
    }

    /// Updates the finalized block to the given `block_hash`.
    ///
    /// This should be used when the finality is outsourced.
    pub fn set_finalized_block(
        &mut self,
        block_hash: &[u8; 32],
    ) -> Result<SetFinalizedBlockResult<TBl>, blocks_tree::SetFinalizedError> {
        let iter = self.chain.set_finalized_block(block_hash)?;
        let updates_best_block = iter.updates_best_block();
        let mut finalized_blocks = Vec::new();
        let mut pruned_blocks = Vec::new();
        for block in iter {
            match block.ty {
                blocks_tree::RemovedBlockType::Finalized => finalized_blocks.push(RemovedBlock {
                    block_hash: block.block_hash,
                    block_number: block.block_number,
                    user_data: block.user_data,
                    scale_encoded_header: block.scale_encoded_header,
                }),
                blocks_tree::RemovedBlockType::Pruned => pruned_blocks.push(RemovedBlock {
                    block_hash: block.block_hash,
                    block_number: block.block_number,
                    user_data: block.user_data,
                    scale_encoded_header: block.scale_encoded_header,
                }),
            }
        }

        if let Some(last) = finalized_blocks.last() {
            let _ = self
                .inner
                .blocks
                .set_finalized_block_height(last.block_number)
                .count();
        }

        Ok(SetFinalizedBlockResult {
            finalized_blocks,
            pruned_blocks,
            updates_best_block,
        })
    }

    /// Returns the header of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_header(&self) -> &[u8] {
        self.chain.best_block_header()
    }

    /// Returns the number of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_number(&self) -> u64 {
        self.chain.best_block_height()
    }

    /// Returns the hash of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_hash(&self) -> &[u8; 32] {
        self.chain.best_block_hash()
    }

    /// Returns the header of all known non-finalized blocks in the chain without any specific
    /// order.
    pub fn non_finalized_blocks_unordered(&'_ self) -> impl Iterator<Item = header::HeaderRef<'_>> {
        self.chain.iter_unordered()
    }

    /// Returns the header of all known non-finalized blocks in the chain.
    ///
    /// The returned items are guaranteed to be in an order in which the parents are found before
    /// their children.
    pub fn non_finalized_blocks_ancestry_order(
        &'_ self,
    ) -> impl Iterator<Item = header::HeaderRef<'_>> {
        self.chain.iter_ancestry_order()
    }

    /// Starts the process of inserting a new source in the [`AllForksSync`].
    ///
    /// This function doesn't modify the state machine, but only looks at the current state of the
    /// block referenced by `best_block_number` and `best_block_hash`. It returns an enum that
    /// allows performing the actual insertion.
    pub fn prepare_add_source(
        &'_ mut self,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    ) -> AddSource<'_, TBl, TRq, TSrc> {
        if best_block_number <= self.chain.finalized_block_height() {
            return AddSource::OldBestBlock(AddSourceOldBlock {
                inner: self,
                best_block_hash,
                best_block_number,
            });
        }

        let best_block_already_verified = self.chain.contains_non_finalized_block(&best_block_hash);
        let best_block_in_disjoints_list = self
            .inner
            .blocks
            .contains_unverified_block(best_block_number, &best_block_hash);

        match (best_block_already_verified, best_block_in_disjoints_list) {
            (false, false) => AddSource::UnknownBestBlock(AddSourceUnknown {
                inner: self,
                best_block_hash,
                best_block_number,
            }),
            (true, false) => AddSource::BestBlockAlreadyVerified(AddSourceKnown {
                inner: self,
                best_block_hash,
                best_block_number,
            }),
            (false, true) => AddSource::BestBlockPendingVerification(AddSourceKnown {
                inner: self,
                best_block_hash,
                best_block_number,
            }),
            (true, true) => unreachable!(),
        }
    }

    /// Removes the source from the [`AllForksSync`].
    ///
    /// Removing the source implicitly cancels the request that is associated to it (if any).
    ///
    /// Returns the user data that was originally passed when inserting the source, plus an
    /// `Option`.
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
        let (user_data, iter) = self.inner.blocks.remove_source(source_id);
        (user_data.user_data, iter)
    }

    /// Returns the list of sources in this state machine.
    pub fn sources(&self) -> impl ExactSizeIterator<Item = SourceId> {
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
    ) -> impl Iterator<Item = SourceId> + use<'a, TBl, TRq, TSrc> {
        self.inner.blocks.knows_non_finalized_block(height, hash)
    }

    /// Registers a new block that the source is aware of.
    ///
    /// Has no effect if `height` is inferior or equal to the finalized block height, or if the
    /// source was already known to know this block.
    ///
    /// The block does not need to be known by the data structure.
    ///
    /// This is automatically done for the blocks added through [`AllForksSync::block_announce`],
    /// [`AllForksSync::prepare_add_source`] or [`FinishRequest::add_block`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn add_known_block_to_source(&mut self, source_id: SourceId, height: u64, hash: [u8; 32]) {
        self.inner
            .blocks
            .add_known_block_to_source(source_id, height, hash);
    }

    /// Returns the current best block of the given source.
    ///
    /// This corresponds either the latest call to [`AllForksSync::block_announce`] where
    /// `is_best` was `true`, or to the parameter passed to [`AllForksSync::prepare_add_source`].
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
    pub fn desired_requests(&self) -> impl Iterator<Item = (SourceId, &TSrc, RequestParams)> {
        // Query justifications of blocks that are necessary in order for finality to progress
        // against sources that have reported these blocks as finalized.
        // TODO: make it clear in the API docs that justifications should be requested as part of a request
        // TODO: this is O(n)
        let justification_requests =
            self.chain
                .finality_checkpoints()
                .flat_map(move |(block_height, block_hash)| {
                    self.inner
                        .blocks
                        .sources()
                        .filter(move |s| {
                            // We assume that all sources have the same finalized blocks and thus
                            // don't check hashes.
                            self.inner.blocks[*s].unverified_finality_proofs.is_none()
                                && self.inner.blocks[*s].finalized_block_number >= block_height
                        })
                        .map(move |source_id| {
                            (
                                source_id,
                                &self.inner.blocks[source_id].user_data,
                                RequestParams {
                                    first_block_hash: *block_hash,
                                    first_block_height: block_height,
                                    num_blocks: NonZero::<u64>::new(1).unwrap(),
                                },
                            )
                        })
                });

        let block_requests = self
            .inner
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
                    &self.inner.blocks[rq.source_id].user_data,
                    rq.request_params,
                )
            });

        justification_requests.chain(block_requests)
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
    /// [`AllForksSync::finish_request`].
    ///
    /// A request becomes obsolete if the state of the request blocks changes in such a way that
    /// they don't need to be requested anymore. The response to the request will be useless.
    ///
    /// > **Note**: It is in no way mandatory to actually call this function and cancel the
    /// >           requests that are returned.
    pub fn obsolete_requests(&self) -> impl Iterator<Item = (RequestId, &TRq)> {
        // TODO: requests meant to query justifications only are considered obsolete by the underlying state machine, which right now is okay because the underlying state machine is pretty loose in its definition of obsolete
        self.inner.blocks.obsolete_requests()
    }

    /// Returns the [`SourceId`] that is expected to fulfill the given request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    pub fn request_source_id(&self, request_id: RequestId) -> SourceId {
        self.inner.blocks.request_source_id(request_id)
    }

    /// Call in response to a request being successful or failing.
    ///
    /// This state machine doesn't differentiate between successful or failed requests. If a
    /// request has failed, call this function and immediately call [`FinishRequest::finish`].
    /// Additionally, it is allow to insert fewer blocks than the number indicated in
    /// [`RequestParams::num_blocks`].
    ///
    /// The added blocks are expected to be sorted in decreasing order. The first block should be
    /// the block with the hash that was referred by [`RequestParams::first_block_hash`]. Each
    /// subsequent element is then expected to be the parent of the previous one.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    pub fn finish_request(
        &'_ mut self,
        request_id: RequestId,
    ) -> (TRq, FinishRequest<'_, TBl, TRq, TSrc>) {
        // Sets the `occupation` of `source_id` back to `AllSync`.
        let (
            pending_blocks::RequestParams {
                first_block_hash: requested_block_hash,
                first_block_height: requested_block_height,
                ..
            },
            source_id,
            request_user_data,
        ) = self.inner.blocks.remove_request(request_id);

        (
            request_user_data,
            FinishRequest {
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
        &'_ mut self,
        source_id: SourceId,
        announced_scale_encoded_header: Vec<u8>,
        is_best: bool,
    ) -> BlockAnnounceOutcome<'_, TBl, TRq, TSrc> {
        let announced_header = match header::decode(
            &announced_scale_encoded_header,
            self.chain.block_number_bytes(),
        ) {
            Ok(h) => h,
            Err(error) => return BlockAnnounceOutcome::InvalidHeader(error),
        };

        let announced_header_number = announced_header.number;
        let announced_header_parent_hash = *announced_header.parent_hash;
        let announced_header_hash = announced_header.hash(self.chain.block_number_bytes());

        // It is assumed that all sources will eventually agree on the same finalized chain. If
        // the block number is lower or equal than the locally-finalized block number, it is
        // assumed that this source is simply late compared to the local node, and that the block
        // that has been received is either part of the finalized chain or belongs to a fork that
        // will get discarded by this source in the future.
        if announced_header_number <= self.chain.finalized_block_height() {
            // Even if the block is below the finalized block, we still need to set it as the
            // best block of this source, if anything for API consistency purposes.
            if is_best {
                self.inner.blocks.add_known_block_to_source_and_set_best(
                    source_id,
                    announced_header_number,
                    announced_header_hash,
                );
            }

            return BlockAnnounceOutcome::TooOld {
                announce_block_height: announced_header_number,
                finalized_block_height: self.chain.finalized_block_height(),
            };
        }

        // If the block is already part of the local tree of blocks, nothing more to do.
        if self
            .chain
            .contains_non_finalized_block(&announced_header_hash)
        {
            return BlockAnnounceOutcome::AlreadyVerified(AnnouncedBlockKnown {
                inner: self,
                announced_header_hash,
                announced_header_number,
                announced_header_parent_hash,
                announced_header_encoded: announced_scale_encoded_header,
                source_id,
                is_in_chain: true,
                is_best,
            });
        }

        // At this point, we have excluded blocks that are already part of the chain or too old.
        // We insert the block in the list of unverified blocks so as to treat all blocks the
        // same.
        if !self
            .inner
            .blocks
            .contains_unverified_block(announced_header_number, &announced_header_hash)
        {
            BlockAnnounceOutcome::Unknown(AnnouncedBlockUnknown {
                inner: self,
                announced_header_hash,
                announced_header_number,
                announced_header_parent_hash,
                announced_header_encoded: announced_scale_encoded_header,
                source_id,
                is_best,
            })
        } else {
            BlockAnnounceOutcome::AlreadyPending(AnnouncedBlockKnown {
                inner: self,
                announced_header_hash,
                announced_header_number,
                announced_header_parent_hash,
                announced_header_encoded: announced_scale_encoded_header,
                is_in_chain: false,
                source_id,
                is_best,
            })
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
        let source = &mut self.inner.blocks[source_id];
        source.finalized_block_number =
            cmp::max(source.finalized_block_number, finalized_block_height);
    }

    /// Update the state machine with a Grandpa commit message received from the network.
    ///
    /// This function only inserts the commit message into the state machine, and does not
    /// immediately verify it.
    ///
    /// # Panic
    ///
    /// Panics if `source_id` is invalid.
    ///
    pub fn grandpa_commit_message(
        &mut self,
        source_id: SourceId,
        scale_encoded_commit: Vec<u8>,
    ) -> GrandpaCommitMessageOutcome {
        let source = &mut self.inner.blocks[source_id];

        let block_number = match decode::decode_grandpa_commit(
            &scale_encoded_commit,
            self.chain.block_number_bytes(),
        ) {
            Ok(msg) => msg.target_number,
            Err(_) => return GrandpaCommitMessageOutcome::ParseError,
        };

        // The finalized block number of the source is increased even if the commit message
        // isn't known to be valid yet.
        source.finalized_block_number = cmp::max(source.finalized_block_number, block_number);

        source.unverified_finality_proofs.insert(
            block_number,
            FinalityProofs::GrandpaCommit(scale_encoded_commit),
        );

        GrandpaCommitMessageOutcome::Queued
    }

    /// Process the next block in the queue of verification.
    ///
    /// This method takes ownership of the [`AllForksSync`] and starts a verification
    /// process. The [`AllForksSync`] is yielded back at the end of this process.
    pub fn process_one(mut self) -> ProcessOne<TBl, TRq, TSrc> {
        // Try to find a block to verify.
        // All blocks are always verified before verifying justifications, in order to guarantee
        // that the block that a justification targets has already been verified.
        // TODO: revisit that ^ as advancing finality should have priority over advancing the chain
        let block_to_verify = self.inner.blocks.unverified_leaves().find(|block| {
            block.parent_block_hash == *self.chain.finalized_block_hash()
                || self
                    .chain
                    .contains_non_finalized_block(&block.parent_block_hash)
        });
        if let Some(block) = block_to_verify {
            return ProcessOne::BlockVerify(BlockVerify {
                parent: self,
                block_to_verify: block,
            });
        }

        // Try to find a justification to verify.
        // TODO: O(n)
        let source_id_with_finality_proof = self
            .inner
            .blocks
            .sources()
            .find(|id| !self.inner.blocks[*id].unverified_finality_proofs.is_none());
        if let Some(source_id_with_finality_proof) = source_id_with_finality_proof {
            let finality_proof_to_verify = self.inner.blocks[source_id_with_finality_proof]
                .unverified_finality_proofs
                .take_one()
                .unwrap(); // `take()` always returns `Some` because we've checked `is_none()` above
            return ProcessOne::FinalityProofVerify(FinalityProofVerify {
                parent: self,
                source_id: source_id_with_finality_proof,
                finality_proof_to_verify,
            });
        }

        ProcessOne::AllSync { sync: self }
    }
}

impl<TBl, TRq, TSrc> ops::Index<SourceId> for AllForksSync<TBl, TRq, TSrc> {
    type Output = TSrc;

    #[track_caller]
    fn index(&self, id: SourceId) -> &TSrc {
        &self.inner.blocks[id].user_data
    }
}

impl<TBl, TRq, TSrc> ops::IndexMut<SourceId> for AllForksSync<TBl, TRq, TSrc> {
    #[track_caller]
    fn index_mut(&mut self, id: SourceId) -> &mut TSrc {
        &mut self.inner.blocks[id].user_data
    }
}

impl<'a, TBl, TRq, TSrc> ops::Index<(u64, &'a [u8; 32])> for AllForksSync<TBl, TRq, TSrc> {
    type Output = TBl;

    #[track_caller]
    fn index(&self, (block_height, block_hash): (u64, &'a [u8; 32])) -> &TBl {
        if let Some(block) = self.chain.non_finalized_block_user_data(block_hash) {
            return block;
        }

        &self
            .inner
            .blocks
            .unverified_block_user_data(block_height, block_hash)
            .user_data
    }
}

impl<'a, TBl, TRq, TSrc> ops::IndexMut<(u64, &'a [u8; 32])> for AllForksSync<TBl, TRq, TSrc> {
    #[track_caller]
    fn index_mut(&mut self, (block_height, block_hash): (u64, &'a [u8; 32])) -> &mut TBl {
        if let Some(block) = self.chain.non_finalized_block_user_data_mut(block_hash) {
            return block;
        }

        &mut self
            .inner
            .blocks
            .unverified_block_user_data_mut(block_height, block_hash)
            .user_data
    }
}

/// See [`AllForksSync::finish_request`].
pub struct FinishRequest<'a, TBl, TRq, TSrc> {
    inner: &'a mut AllForksSync<TBl, TRq, TSrc>,

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

impl<'a, TBl, TRq, TSrc> FinishRequest<'a, TBl, TRq, TSrc> {
    /// Adds a block coming from the response that the source has provided.
    ///
    /// On success, the [`FinishRequest`] is turned into an [`AddBlock`]. The block is
    /// inserted in the state machine only after one of the methods in [`AddBlock`] is added.
    ///
    /// If an error is returned, the [`FinishRequest`] is turned back again into a
    /// [`AllForksSync`], but all the blocks that have already been added are retained.
    ///
    /// If [`Config::download_bodies`] was `false`, the content of `scale_encoded_extrinsics`
    /// is ignored.
    pub fn add_block(
        mut self,
        scale_encoded_header: Vec<u8>,
        scale_encoded_extrinsics: Vec<Vec<u8>>,
        scale_encoded_justifications: impl Iterator<Item = ([u8; 4], impl AsRef<[u8]>)>,
    ) -> Result<AddBlock<'a, TBl, TRq, TSrc>, AncestrySearchResponseError> {
        // Compare expected with actual hash.
        // This ensure that each header being processed is the parent of the previous one.
        if self.expected_next_hash != header::hash_from_scale_encoded_header(&scale_encoded_header)
        {
            return Err(AncestrySearchResponseError::UnexpectedBlock);
        }

        // Invalid headers are erroneous.
        let decoded_header =
            match header::decode(&scale_encoded_header, self.inner.chain.block_number_bytes()) {
                Ok(h) => h,
                Err(err) => return Err(AncestrySearchResponseError::InvalidHeader(err)),
            };

        // Also compare the block numbers.
        // The utility of checking the height (even though we've already checked the hash) is
        // questionable, but considering that blocks are identified with their combination of
        // hash and number, checking both the hash and number might prevent malicious sources
        // from introducing state inconsistenties, even though it's unclear how that could happen.
        if self.expected_next_height != decoded_header.number {
            return Err(AncestrySearchResponseError::UnexpectedBlock);
        }

        // Check whether the SCALE-encoded extrinsics match the extrinsics root found in
        // the header.
        if self.inner.inner.blocks.downloading_bodies() {
            let calculated = header::extrinsics_root(&scale_encoded_extrinsics);
            if calculated != *decoded_header.extrinsics_root {
                return Err(AncestrySearchResponseError::ExtrinsicsRootMismatch);
            }
        }

        // At this point, the source has given us correct blocks, and we consider the response
        // as a whole to be useful.
        self.any_progress = true;

        // It is assumed that all sources will eventually agree on the same finalized chain. If
        // the block number is lower or equal than the locally-finalized block number, it is
        // assumed that this source is simply late compared to the local node, and that the block
        // that has been received is either part of the finalized chain or belongs to a fork that
        // will get discarded by this source in the future.
        if decoded_header.number <= self.inner.chain.finalized_block_height() {
            return Err(AncestrySearchResponseError::TooOld);
        }

        // Convert the justifications in an "owned" format, because we're likely going to store
        // them.
        let justifications = scale_encoded_justifications
            .map(|(e, j)| (e, j.as_ref().to_owned()))
            .collect::<Vec<_>>();

        // If the block is already part of the local tree of blocks, nothing more to do.
        // Note that the block body is silently discarded, as in the API only non-verified blocks
        // exhibit a body.
        if self
            .inner
            .chain
            .contains_non_finalized_block(&self.expected_next_hash)
        {
            if !justifications.is_empty() {
                self.inner.inner.blocks[self.source_id]
                    .unverified_finality_proofs
                    .insert(
                        decoded_header.number,
                        FinalityProofs::Justifications(justifications),
                    );
            }

            return Ok(AddBlock::AlreadyInChain(AddBlockOccupied {
                inner: self,
                block_number: decoded_header.number,
                block_parent_hash: *decoded_header.parent_hash,
                block_header: scale_encoded_header,
                is_verified: true,
            }));
        }

        // Block is not part of the finalized chain.
        // TODO: also give possibility to update user data
        if decoded_header.number == self.inner.chain.finalized_block_height() + 1
            && *decoded_header.parent_hash != *self.inner.chain.finalized_block_hash()
        {
            // TODO: remove_verify_failed
            // Block isn't part of the finalized chain.
            // This doesn't necessarily mean that the source and the local node disagree
            // on the finalized chain. It is possible that the finalized block has been
            // updated between the moment the request was emitted and the moment the
            // response is received.
            let error = AncestrySearchResponseError::NotFinalizedChain {
                discarded_unverified_block_headers: Vec::new(), // TODO: not properly implemented /!\
            };
            return Err(error);
        }

        // At this point, we have excluded blocks that are already part of the chain or too old.
        // We insert the block in the list of unverified blocks so as to treat all blocks the
        // same.
        if !self
            .inner
            .inner
            .blocks
            .contains_unverified_block(decoded_header.number, &self.expected_next_hash)
        {
            Ok(AddBlock::UnknownBlock(AddBlockVacant {
                inner: self,
                block_number: decoded_header.number,
                block_parent_hash: *decoded_header.parent_hash,
                block_header: scale_encoded_header,
                scale_encoded_extrinsics,
                justifications,
            }))
        } else {
            if !justifications.is_empty() {
                self.inner.inner.blocks[self.source_id]
                    .unverified_finality_proofs
                    .insert(
                        decoded_header.number,
                        FinalityProofs::Justifications(justifications),
                    );
            }

            if self.inner.inner.blocks.downloading_bodies() {
                self.inner
                    .inner
                    .blocks
                    .set_unverified_block_header_body_known(
                        decoded_header.number,
                        &self.expected_next_hash,
                        *decoded_header.parent_hash,
                    );
                self.inner
                    .inner
                    .blocks
                    .unverified_block_user_data_mut(decoded_header.number, &self.expected_next_hash)
                    .body = Some(scale_encoded_extrinsics);
            }

            Ok(AddBlock::AlreadyPending(AddBlockOccupied {
                inner: self,
                block_number: decoded_header.number,
                block_parent_hash: *decoded_header.parent_hash,
                block_header: scale_encoded_header,
                is_verified: false,
            }))
        }
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
    pub fn finish(self) {
        drop(self);
    }
}

impl<'a, TBl, TRq, TSrc> Drop for FinishRequest<'a, TBl, TRq, TSrc> {
    fn drop(&mut self) {
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
    }
}

/// Result of calling [`FinishRequest::add_block`].
pub enum AddBlock<'a, TBl, TRq, TSrc> {
    /// The block is already in the list of unverified blocks.
    AlreadyPending(AddBlockOccupied<'a, TBl, TRq, TSrc>),

    /// The block hasn't been heard of before.
    UnknownBlock(AddBlockVacant<'a, TBl, TRq, TSrc>),

    /// The block is already in the list of verified blocks.
    ///
    /// This can happen for example if a block announce or different ancestry search response has
    /// been processed in between the request and response.
    AlreadyInChain(AddBlockOccupied<'a, TBl, TRq, TSrc>),
}

/// See [`FinishRequest::add_block`] and [`AddBlock`].
pub struct AddBlockOccupied<'a, TBl, TRq, TSrc> {
    inner: FinishRequest<'a, TBl, TRq, TSrc>,
    block_header: Vec<u8>,
    block_number: u64,
    block_parent_hash: [u8; 32],
    is_verified: bool,
}

impl<'a, TBl, TRq, TSrc> AddBlockOccupied<'a, TBl, TRq, TSrc> {
    /// Gives access to the user data of the block.
    pub fn user_data_mut(&mut self) -> &mut TBl {
        if self.is_verified {
            &mut self.inner.inner.chain[&self.inner.expected_next_hash]
        } else {
            &mut self
                .inner
                .inner
                .inner
                .blocks
                .unverified_block_user_data_mut(self.block_number, &self.inner.expected_next_hash)
                .user_data
        }
    }

    /// Replace the existing user data of the block.
    ///
    /// Returns an object that allows continuing inserting blocks, plus the former user data that
    /// was overwritten by the new one.
    pub fn replace(mut self, user_data: TBl) -> (FinishRequest<'a, TBl, TRq, TSrc>, TBl) {
        // Update the view the state machine maintains for this source.
        self.inner.inner.inner.blocks.add_known_block_to_source(
            self.inner.source_id,
            self.block_number,
            self.inner.expected_next_hash,
        );

        // Source also knows the parent of the announced block.
        // TODO: do this for the entire chain of blocks if it is known locally?
        self.inner.inner.inner.blocks.add_known_block_to_source(
            self.inner.source_id,
            self.block_number - 1,
            self.block_parent_hash,
        );

        let former_user_data = if self.is_verified {
            mem::replace(
                &mut self.inner.inner.chain[&self.inner.expected_next_hash],
                user_data,
            )
        } else {
            self.inner
                .inner
                .inner
                .blocks
                .set_unverified_block_header_known(
                    self.block_number,
                    &self.inner.expected_next_hash,
                    self.block_parent_hash,
                );

            let block_user_data = self
                .inner
                .inner
                .inner
                .blocks
                .unverified_block_user_data_mut(self.block_number, &self.inner.expected_next_hash);
            if block_user_data.header.is_none() {
                block_user_data.header = Some(self.block_header);
                // TODO: copying bytes :-/
            }

            mem::replace(&mut block_user_data.user_data, user_data)
        };

        // Update the state machine for the next iteration.
        // Note: this can't be reached if `expected_next_height` is 0, because that should have
        // resulted either in `NotFinalizedChain` or `AlreadyInChain`, both of which return early.
        self.inner.expected_next_hash = self.block_parent_hash;
        self.inner.expected_next_height -= 1;
        self.inner.index_in_response += 1;
        (self.inner, former_user_data)
    }
}

/// See [`FinishRequest::add_block`] and [`AddBlock`].
pub struct AddBlockVacant<'a, TBl, TRq, TSrc> {
    inner: FinishRequest<'a, TBl, TRq, TSrc>,
    block_header: Vec<u8>,
    block_number: u64,
    block_parent_hash: [u8; 32],
    justifications: Vec<([u8; 4], Vec<u8>)>,
    scale_encoded_extrinsics: Vec<Vec<u8>>,
}

impl<'a, TBl, TRq, TSrc> AddBlockVacant<'a, TBl, TRq, TSrc> {
    /// Insert the block in the state machine, with the given user data.
    pub fn insert(mut self, user_data: TBl) -> FinishRequest<'a, TBl, TRq, TSrc> {
        // Update the view the state machine maintains for this source.
        self.inner.inner.inner.blocks.add_known_block_to_source(
            self.inner.source_id,
            self.block_number,
            self.inner.expected_next_hash,
        );

        // Source also knows the parent of the announced block.
        // TODO: do this for the entire chain of blocks if it is known locally?
        self.inner.inner.inner.blocks.add_known_block_to_source(
            self.inner.source_id,
            self.block_number - 1,
            self.block_parent_hash,
        );

        self.inner.inner.inner.blocks.insert_unverified_block(
            self.block_number,
            self.inner.expected_next_hash,
            if self.inner.inner.inner.blocks.downloading_bodies() {
                pending_blocks::UnverifiedBlockState::HeaderBody {
                    parent_hash: self.block_parent_hash,
                }
            } else {
                pending_blocks::UnverifiedBlockState::Header {
                    parent_hash: self.block_parent_hash,
                }
            },
            PendingBlock {
                header: Some(self.block_header),
                body: Some(self.scale_encoded_extrinsics),
                user_data,
            },
        );

        if !self.justifications.is_empty() {
            self.inner.inner.inner.blocks[self.inner.source_id]
                .unverified_finality_proofs
                .insert(
                    self.block_number,
                    FinalityProofs::Justifications(self.justifications),
                );
        }

        // If there are too many blocks stored in the blocks list, remove unnecessary ones.
        // Not doing this could lead to an explosion of the size of the collections.
        // TODO: removing blocks should only be done explicitly through an API endpoint, because we want to store user datas in unverified blocks too; see https://github.com/paritytech/smoldot/issues/1572
        while self.inner.inner.inner.blocks.num_unverified_blocks() >= 100 {
            // TODO: arbitrary constant
            let (height, hash) = match self
                .inner
                .inner
                .inner
                .blocks
                .unnecessary_unverified_blocks()
                .next()
            {
                Some((n, h)) => (n, *h),
                None => break,
            };

            // TODO: restore this block of code; it is extremely complicated because it is unclear which source-block combinations we can add and keep without making memory usage explode
            /*self.inner
            .inner
            .inner
            .blocks
            .remove_sources_known_block(height, &hash);*/
            self.inner
                .inner
                .inner
                .blocks
                .remove_unverified_block(height, &hash);
        }

        // Update the state machine for the next iteration.
        // Note: this can't be reached if `expected_next_height` is 0, because that should have
        // resulted either in `NotFinalizedChain` or `AlreadyInChain`, both of which return early.
        self.inner.expected_next_hash = self.block_parent_hash;
        self.inner.expected_next_height -= 1;
        self.inner.index_in_response += 1;
        self.inner
    }
}

/// Outcome of calling [`AllForksSync::block_announce`].
pub enum BlockAnnounceOutcome<'a, TBl, TRq, TSrc> {
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
    AlreadyVerified(AnnouncedBlockKnown<'a, TBl, TRq, TSrc>),

    /// Announced block is already known by the state machine but hasn't been verified yet.
    AlreadyPending(AnnouncedBlockKnown<'a, TBl, TRq, TSrc>),

    /// Announced block isn't in the state machine.
    Unknown(AnnouncedBlockUnknown<'a, TBl, TRq, TSrc>),

    /// Failed to decode announce header.
    InvalidHeader(header::Error),
}

/// See [`BlockAnnounceOutcome`] and [`AllForksSync::block_announce`].
#[must_use]
pub struct AnnouncedBlockKnown<'a, TBl, TRq, TSrc> {
    inner: &'a mut AllForksSync<TBl, TRq, TSrc>,
    announced_header_hash: [u8; 32],
    announced_header_parent_hash: [u8; 32],
    announced_header_number: u64,
    announced_header_encoded: Vec<u8>,
    is_in_chain: bool,
    is_best: bool,
    source_id: SourceId,
}

impl<'a, TBl, TRq, TSrc> AnnouncedBlockKnown<'a, TBl, TRq, TSrc> {
    /// Returns the parent hash of the announced block.
    pub fn parent_hash(&self) -> &[u8; 32] {
        &self.announced_header_parent_hash
    }

    /// Returns the height of the announced block.
    pub fn height(&self) -> u64 {
        self.announced_header_number
    }

    /// Returns the hash of the announced block.
    pub fn hash(&self) -> &[u8; 32] {
        &self.announced_header_hash
    }

    /// Gives access to the user data of the block.
    pub fn user_data_mut(&mut self) -> &mut TBl {
        if self.is_in_chain {
            &mut self.inner.chain[&self.announced_header_hash]
        } else {
            &mut self
                .inner
                .inner
                .blocks
                .unverified_block_user_data_mut(
                    self.announced_header_number,
                    &self.announced_header_hash,
                )
                .user_data
        }
    }

    /// Updates the state machine to keep track of the fact that this source knows this block.
    /// If the announced block is the source's best block, also updates this information.
    pub fn update_source_and_block(self) {
        // No matter what is done below, start by updating the view the state machine maintains
        // for this source.
        if self.is_best {
            self.inner
                .inner
                .blocks
                .add_known_block_to_source_and_set_best(
                    self.source_id,
                    self.announced_header_number,
                    self.announced_header_hash,
                );
        } else {
            self.inner.inner.blocks.add_known_block_to_source(
                self.source_id,
                self.announced_header_number,
                self.announced_header_hash,
            );
        }

        // Source also knows the parent of the announced block.
        self.inner.inner.blocks.add_known_block_to_source(
            self.source_id,
            self.announced_header_number - 1,
            self.announced_header_parent_hash,
        );

        if !self.is_in_chain {
            self.inner.inner.blocks.set_unverified_block_header_known(
                self.announced_header_number,
                &self.announced_header_hash,
                self.announced_header_parent_hash,
            );

            let block_user_data = self.inner.inner.blocks.unverified_block_user_data_mut(
                self.announced_header_number,
                &self.announced_header_hash,
            );
            if block_user_data.header.is_none() {
                block_user_data.header = Some(self.announced_header_encoded);
            }

            // Mark block as bad if it is not part of the finalized chain.
            // This might not have been known before, as the header might not have been known.
            if self.announced_header_number == self.inner.chain.finalized_block_height() + 1
                && self.announced_header_parent_hash != *self.inner.chain.finalized_block_hash()
            {
                self.inner.inner.blocks.mark_unverified_block_as_bad(
                    self.announced_header_number,
                    &self.announced_header_hash,
                );
            }
        }

        // TODO: if pending_blocks.num_blocks() > some_max { remove uninteresting block }
    }
}

/// See [`BlockAnnounceOutcome`] and [`AllForksSync::block_announce`].
#[must_use]
pub struct AnnouncedBlockUnknown<'a, TBl, TRq, TSrc> {
    inner: &'a mut AllForksSync<TBl, TRq, TSrc>,
    announced_header_hash: [u8; 32],
    announced_header_parent_hash: [u8; 32],
    announced_header_number: u64,
    announced_header_encoded: Vec<u8>,
    is_best: bool,
    source_id: SourceId,
}

impl<'a, TBl, TRq, TSrc> AnnouncedBlockUnknown<'a, TBl, TRq, TSrc> {
    /// Returns the parent hash of the announced block.
    pub fn parent_hash(&self) -> &[u8; 32] {
        &self.announced_header_parent_hash
    }

    /// Returns the height of the announced block.
    pub fn height(&self) -> u64 {
        self.announced_header_number
    }

    /// Returns the hash of the announced block.
    pub fn hash(&self) -> &[u8; 32] {
        &self.announced_header_hash
    }

    /// Inserts the block in the state machine and keeps track of the fact that this source knows
    /// this block.
    ///
    /// If the announced block is the source's best block, also updates this information.
    pub fn insert_and_update_source(self, user_data: TBl) {
        // No matter what is done below, start by updating the view the state machine maintains
        // for this source.
        if self.is_best {
            self.inner
                .inner
                .blocks
                .add_known_block_to_source_and_set_best(
                    self.source_id,
                    self.announced_header_number,
                    self.announced_header_hash,
                );
        } else {
            self.inner.inner.blocks.add_known_block_to_source(
                self.source_id,
                self.announced_header_number,
                self.announced_header_hash,
            );
        }

        // Source also knows the parent of the announced block.
        self.inner.inner.blocks.add_known_block_to_source(
            self.source_id,
            self.announced_header_number - 1,
            self.announced_header_parent_hash,
        );

        self.inner.inner.blocks.insert_unverified_block(
            self.announced_header_number,
            self.announced_header_hash,
            pending_blocks::UnverifiedBlockState::Header {
                parent_hash: self.announced_header_parent_hash,
            },
            PendingBlock {
                header: Some(self.announced_header_encoded),
                body: None,
                user_data,
            },
        );

        // If there are too many blocks stored in the blocks list, remove unnecessary ones.
        // Not doing this could lead to an explosion of the size of the collections.
        // TODO: removing blocks should only be done explicitly through an API endpoint, because we want to store user datas in unverified blocks too; see https://github.com/paritytech/smoldot/issues/1572
        while self.inner.inner.blocks.num_unverified_blocks() >= 100 {
            // TODO: arbitrary constant
            let (height, hash) = match self
                .inner
                .inner
                .blocks
                .unnecessary_unverified_blocks()
                .next()
            {
                Some((n, h)) => (n, *h),
                None => break,
            };

            // TODO: restore this block of code; it is extremely complicated because it is unclear which source-block combinations we can add and keep without making memory usage explode
            /*self.inner
            .inner
            .blocks
            .remove_sources_known_block(height, &hash);*/
            self.inner
                .inner
                .blocks
                .remove_unverified_block(height, &hash);
        }

        // TODO: if pending_blocks.num_blocks() > some_max { remove uninteresting block }
    }
}

/// Error when adding a block using [`FinishRequest::add_block`].
pub enum AncestrySearchResponseError {
    /// Failed to decode block header.
    InvalidHeader(header::Error),

    /// Provided block isn't a block that we expect to be added.
    ///
    /// If this is the first block, then it doesn't correspond to the block that has been
    /// requested. If this is not the first block, then it doesn't correspond to the parent of
    /// the previous block that has been added.
    UnexpectedBlock,

    /// List of SCALE-encoded extrinsics doesn't match the extrinsics root found in the header.
    ///
    /// This can only happen if [`Config::download_bodies`] was `true`.
    ExtrinsicsRootMismatch,

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
}

/// Outcome of calling [`AllForksSync::prepare_add_source`].
#[must_use]
pub enum AddSource<'a, TBl, TRq, TSrc> {
    /// The best block of the source is older or equal to the local latest finalized block. This
    /// block isn't tracked by the state machine.
    OldBestBlock(AddSourceOldBlock<'a, TBl, TRq, TSrc>),

    /// The best block of the source has already been verified by this state machine.
    BestBlockAlreadyVerified(AddSourceKnown<'a, TBl, TRq, TSrc>),

    /// The best block of the source is already known to this state machine but hasn't been
    /// verified yet.
    BestBlockPendingVerification(AddSourceKnown<'a, TBl, TRq, TSrc>),

    /// The best block of the source isn't in this state machine yet and needs to be inserted.
    UnknownBestBlock(AddSourceUnknown<'a, TBl, TRq, TSrc>),
}

/// See [`AddSource`] and [`AllForksSync::prepare_add_source`].
#[must_use]
pub struct AddSourceOldBlock<'a, TBl, TRq, TSrc> {
    inner: &'a mut AllForksSync<TBl, TRq, TSrc>,
    best_block_number: u64,
    best_block_hash: [u8; 32],
}

impl<'a, TBl, TRq, TSrc> AddSourceOldBlock<'a, TBl, TRq, TSrc> {
    /// Inserts a new source in the state machine.
    ///
    /// Returns the newly-allocated identifier for that source.
    ///
    /// The `user_data` parameter is opaque and decided entirely by the user. It can later be
    /// retrieved using the `Index` trait implementation of the [`AllForksSync`].
    pub fn add_source(self, source_user_data: TSrc) -> SourceId {
        self.inner.inner.blocks.add_source(
            Source {
                user_data: source_user_data,
                unverified_finality_proofs: SourcePendingJustificationProofs::None,
                finalized_block_number: 0,
                pending_finality_proofs: SourcePendingJustificationProofs::None,
            },
            self.best_block_number,
            self.best_block_hash,
        )
    }
}

/// See [`AddSource`] and [`AllForksSync::prepare_add_source`].
#[must_use]
pub struct AddSourceKnown<'a, TBl, TRq, TSrc> {
    inner: &'a mut AllForksSync<TBl, TRq, TSrc>,
    best_block_number: u64,
    best_block_hash: [u8; 32],
}

impl<'a, TBl, TRq, TSrc> AddSourceKnown<'a, TBl, TRq, TSrc> {
    /// Gives access to the user data of the block.
    pub fn user_data_mut(&mut self) -> &mut TBl {
        if let Some(block_access) = self
            .inner
            .chain
            .non_finalized_block_user_data_mut(&self.best_block_hash)
        {
            block_access
        } else {
            &mut self
                .inner
                .inner
                .blocks
                .unverified_block_user_data_mut(self.best_block_number, &self.best_block_hash)
                .user_data
        }
    }

    /// Inserts a new source in the state machine.
    ///
    /// Returns the newly-allocated identifier for that source.
    ///
    /// The `user_data` parameter is opaque and decided entirely by the user. It can later be
    /// retrieved using the `Index` trait implementation of the [`AllForksSync`].
    pub fn add_source(self, source_user_data: TSrc) -> SourceId {
        self.inner.inner.blocks.add_source(
            Source {
                user_data: source_user_data,
                unverified_finality_proofs: SourcePendingJustificationProofs::None,
                finalized_block_number: 0,
                pending_finality_proofs: SourcePendingJustificationProofs::None,
            },
            self.best_block_number,
            self.best_block_hash,
        )
    }
}

/// See [`AddSource`] and [`AllForksSync::prepare_add_source`].
#[must_use]
pub struct AddSourceUnknown<'a, TBl, TRq, TSrc> {
    inner: &'a mut AllForksSync<TBl, TRq, TSrc>,
    best_block_number: u64,
    best_block_hash: [u8; 32],
}

impl<'a, TBl, TRq, TSrc> AddSourceUnknown<'a, TBl, TRq, TSrc> {
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
        let source_id = self.inner.inner.blocks.add_source(
            Source {
                user_data: source_user_data,
                unverified_finality_proofs: SourcePendingJustificationProofs::None,
                finalized_block_number: 0,
                pending_finality_proofs: SourcePendingJustificationProofs::None,
            },
            self.best_block_number,
            self.best_block_hash,
        );

        self.inner.inner.blocks.insert_unverified_block(
            self.best_block_number,
            self.best_block_hash,
            pending_blocks::UnverifiedBlockState::HeightHash,
            PendingBlock {
                header: None,
                body: None,
                user_data: best_block_user_data,
            },
        );

        source_id
    }
}

/// Block verification to be performed.
///
/// Internally holds the [`AllForksSync`].
pub struct BlockVerify<TBl, TRq, TSrc> {
    parent: AllForksSync<TBl, TRq, TSrc>,
    /// Block that can be verified.
    block_to_verify: pending_blocks::TreeRoot,
}

impl<TBl, TRq, TSrc> BlockVerify<TBl, TRq, TSrc> {
    /// Returns the hash of the block to be verified.
    pub fn hash(&self) -> &[u8; 32] {
        &self.block_to_verify.block_hash
    }

    /// Returns the list of SCALE-encoded extrinsics of the block to verify.
    ///
    /// This is `Some` if and only if [`Config::download_bodies`] is `true`
    pub fn scale_encoded_extrinsics(
        &self,
    ) -> Option<impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone> + Clone> {
        if self.parent.inner.blocks.downloading_bodies() {
            Some(
                self.parent
                    .inner
                    .blocks
                    .unverified_block_user_data(
                        self.block_to_verify.block_number,
                        &self.block_to_verify.block_hash,
                    )
                    .body
                    .as_ref()
                    // The block shouldn't have been proposed for verification if it doesn't
                    // have its body available.
                    .unwrap_or_else(|| unreachable!())
                    .iter(),
            )
        } else {
            None
        }
    }

    /// Returns the SCALE-encoded header of the block about to be verified.
    pub fn scale_encoded_header(&self) -> &[u8] {
        self.parent
            .inner
            .blocks
            .unverified_block_user_data(
                self.block_to_verify.block_number,
                &self.block_to_verify.block_hash,
            )
            .header
            .as_ref()
            .unwrap()
    }

    /// Perform the verification.
    pub fn verify_header(
        mut self,
        now_from_unix_epoch: Duration,
    ) -> HeaderVerifyOutcome<TBl, TRq, TSrc> {
        let to_verify_scale_encoded_header = self.scale_encoded_header().to_owned(); // TODO: overhead

        let result = match self
            .parent
            .chain
            .verify_header(to_verify_scale_encoded_header, now_from_unix_epoch)
        {
            Ok(blocks_tree::HeaderVerifySuccess::Verified {
                verified_header,
                is_new_best,
            }) => {
                // Block is valid!
                Ok((verified_header, is_new_best))
            }
            Err(blocks_tree::HeaderVerifyError::VerificationFailed(error)) => {
                // Remove the block from `pending_blocks`.
                self.parent.inner.blocks.mark_unverified_block_as_bad(
                    self.block_to_verify.block_number,
                    &self.block_to_verify.block_hash,
                );

                Err(HeaderVerifyError::VerificationFailed(error))
            }
            Err(blocks_tree::HeaderVerifyError::ConsensusMismatch) => {
                // Remove the block from `pending_blocks`.
                self.parent.inner.blocks.mark_unverified_block_as_bad(
                    self.block_to_verify.block_number,
                    &self.block_to_verify.block_hash,
                );

                Err(HeaderVerifyError::ConsensusMismatch)
            }
            Err(blocks_tree::HeaderVerifyError::UnknownConsensusEngine) => {
                // Remove the block from `pending_blocks`.
                self.parent.inner.blocks.mark_unverified_block_as_bad(
                    self.block_to_verify.block_number,
                    &self.block_to_verify.block_hash,
                );

                Err(HeaderVerifyError::UnknownConsensusEngine)
            }
            Ok(blocks_tree::HeaderVerifySuccess::Duplicate)
            | Err(
                blocks_tree::HeaderVerifyError::BadParent { .. }
                | blocks_tree::HeaderVerifyError::InvalidHeader(_),
            ) => unreachable!(),
        };

        match result {
            Ok((verified_header, is_new_best)) => HeaderVerifyOutcome::Success {
                is_new_best,
                success: HeaderVerifySuccess {
                    parent: self.parent,
                    block_to_verify: self.block_to_verify,
                    verified_header,
                },
            },
            Err(error) => HeaderVerifyOutcome::Error {
                sync: self.parent,
                error,
            },
        }
    }

    /// Do not actually proceed with the verification.
    pub fn cancel(self) -> AllForksSync<TBl, TRq, TSrc> {
        self.parent
    }
}

/// Header verification successful.
///
/// Internally holds the [`AllForksSync`].
pub struct HeaderVerifySuccess<TBl, TRq, TSrc> {
    parent: AllForksSync<TBl, TRq, TSrc>,
    block_to_verify: pending_blocks::TreeRoot,
    verified_header: blocks_tree::VerifiedHeader,
}

impl<TBl, TRq, TSrc> HeaderVerifySuccess<TBl, TRq, TSrc> {
    /// Returns the height of the block that was verified.
    pub fn height(&self) -> u64 {
        self.block_to_verify.block_number
    }

    /// Returns the hash of the block that was verified.
    pub fn hash(&self) -> &[u8; 32] {
        &self.block_to_verify.block_hash
    }

    /// Returns the hash of the parent of the block that was verified.
    pub fn parent_hash(&self) -> &[u8; 32] {
        &self.block_to_verify.parent_block_hash
    }

    /// Returns the user data of the parent of the block to be verified, or `None` if the parent
    /// is the finalized block.
    pub fn parent_user_data(&self) -> Option<&TBl> {
        self.parent
            .chain
            .non_finalized_block_user_data(&self.block_to_verify.parent_block_hash)
    }

    /// Returns the SCALE-encoded header of the block that was verified.
    pub fn scale_encoded_header(&self) -> &[u8] {
        self.verified_header.scale_encoded_header()
    }

    /// Returns the list of SCALE-encoded extrinsics of the block to verify.
    ///
    /// This is `Some` if and only if [`Config::download_bodies`] is `true`
    pub fn scale_encoded_extrinsics(
        &self,
    ) -> Option<impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone> + Clone> {
        if self.parent.inner.blocks.downloading_bodies() {
            Some(
                self.parent
                    .inner
                    .blocks
                    .unverified_block_user_data(
                        self.block_to_verify.block_number,
                        &self.block_to_verify.block_hash,
                    )
                    .body
                    .as_ref()
                    // The block shouldn't have been proposed for verification if it doesn't
                    // have its body available.
                    .unwrap_or_else(|| unreachable!())
                    .iter(),
            )
        } else {
            None
        }
    }

    /// Returns the SCALE-encoded header of the block that was verified.
    pub fn parent_scale_encoded_header(&self) -> &[u8] {
        if self.block_to_verify.parent_block_hash == *self.parent.chain.finalized_block_hash() {
            self.parent.chain.finalized_block_header()
        } else {
            self.parent
                .chain
                .non_finalized_block_header(&self.block_to_verify.parent_block_hash)
                .unwrap()
        }
    }

    /// Cancel the block verification.
    pub fn cancel(self) -> AllForksSync<TBl, TRq, TSrc> {
        self.parent
    }

    /// Reject the block and mark it as bad.
    pub fn reject_bad_block(mut self) -> AllForksSync<TBl, TRq, TSrc> {
        // Remove the block from `pending_blocks`.
        self.parent.inner.blocks.mark_unverified_block_as_bad(
            self.block_to_verify.block_number,
            &self.block_to_verify.block_hash,
        );

        self.parent
    }

    /// Finish inserting the block header.
    pub fn finish(mut self) -> AllForksSync<TBl, TRq, TSrc> {
        // Remove the block from `pending_blocks`.
        let pending_block = self.parent.inner.blocks.remove_unverified_block(
            self.block_to_verify.block_number,
            &self.block_to_verify.block_hash,
        );

        // Now insert the block in `chain`.
        self.parent
            .chain
            .insert_verified_header(self.verified_header, pending_block.user_data);

        // Because a new block is now in the chain, all the previously-unverifiable
        // finality proofs might have now become verifiable.
        // TODO: this way of doing it is correct but quite inefficient
        for source in self.parent.inner.blocks.sources_user_data_iter_mut() {
            let pending = mem::replace(
                &mut source.pending_finality_proofs,
                SourcePendingJustificationProofs::None,
            );

            source.unverified_finality_proofs.merge(pending)
        }

        self.parent
    }
}

/// Finality proof verification to be performed.
///
/// Internally holds the [`AllForksSync`].
pub struct FinalityProofVerify<TBl, TRq, TSrc> {
    parent: AllForksSync<TBl, TRq, TSrc>,
    /// Source that has sent the finality proof.
    source_id: SourceId,
    /// Justification and its consensus engine id, or commit that can be verified.
    finality_proof_to_verify: FinalityProof,
}

impl<TBl, TRq, TSrc> FinalityProofVerify<TBl, TRq, TSrc> {
    /// Returns the source the justification was obtained from.
    pub fn sender(&self) -> (SourceId, &TSrc) {
        (self.source_id, &self.parent[self.source_id])
    }

    /// Perform the verification.
    ///
    /// A randomness seed must be provided and will be used during the verification. Note that the
    /// verification is nonetheless deterministic.
    pub fn perform(
        mut self,
        randomness_seed: [u8; 32],
    ) -> (
        AllForksSync<TBl, TRq, TSrc>,
        FinalityProofVerifyOutcome<TBl>,
    ) {
        let finality_apply = match self.finality_proof_to_verify {
            FinalityProof::GrandpaCommit(scale_encoded_commit) => {
                match self
                    .parent
                    .chain
                    .verify_grandpa_commit_message(&scale_encoded_commit, randomness_seed)
                {
                    Ok(finality_apply) => finality_apply,

                    // In case where the commit message concerns a block older or equal to the
                    // finalized block, the operation is silently considered successful.
                    Err(blocks_tree::CommitVerifyError::FinalityVerify(
                        blocks_tree::FinalityVerifyError::EqualToFinalized
                        | blocks_tree::FinalityVerifyError::BelowFinalized,
                    )) => return (self.parent, FinalityProofVerifyOutcome::AlreadyFinalized),

                    // The commit can't be verified yet.
                    Err(
                        blocks_tree::CommitVerifyError::FinalityVerify(
                            blocks_tree::FinalityVerifyError::UnknownTargetBlock {
                                block_number,
                                ..
                            },
                        )
                        | blocks_tree::CommitVerifyError::FinalityVerify(
                            blocks_tree::FinalityVerifyError::TooFarAhead {
                                justification_block_number: block_number,
                                ..
                            },
                        )
                        | blocks_tree::CommitVerifyError::NotEnoughKnownBlocks {
                            target_block_number: block_number,
                        },
                    ) => {
                        self.parent.inner.blocks[self.source_id]
                            .pending_finality_proofs
                            .insert(
                                block_number,
                                FinalityProofs::GrandpaCommit(scale_encoded_commit),
                            );
                        return (
                            self.parent,
                            FinalityProofVerifyOutcome::GrandpaCommitPending,
                        );
                    }

                    // Any other error means that the commit is invalid.
                    Err(err) => {
                        return (
                            self.parent,
                            FinalityProofVerifyOutcome::GrandpaCommitError(err),
                        );
                    }
                }
            }

            FinalityProof::Justification((consensus_engine_id, scale_encoded_justification)) => {
                match self.parent.chain.verify_justification(
                    consensus_engine_id,
                    &scale_encoded_justification,
                    randomness_seed,
                ) {
                    Ok(finality_apply) => finality_apply,

                    // In case where the commit message concerns a block older or equal to the
                    // finalized block, the operation is silently considered successful.
                    Err(blocks_tree::JustificationVerifyError::FinalityVerify(
                        blocks_tree::FinalityVerifyError::EqualToFinalized
                        | blocks_tree::FinalityVerifyError::BelowFinalized,
                    )) => return (self.parent, FinalityProofVerifyOutcome::AlreadyFinalized),

                    // Note that, contrary to commits, there's no such thing as a justification
                    // that can't be verified yet.
                    Err(err) => {
                        return (
                            self.parent,
                            FinalityProofVerifyOutcome::JustificationError(err),
                        );
                    }
                }
            }
        };

        // Commit or justification successfully verified.
        // Update the local state with the newly-finalized block.

        let finalized_blocks_iter = finality_apply.apply();
        let updates_best_block = finalized_blocks_iter.updates_best_block();
        let mut finalized_blocks = Vec::new();
        let mut pruned_blocks = Vec::new();
        // TODO: a bit weird to perform a conversion here
        for block in finalized_blocks_iter {
            if matches!(block.ty, blocks_tree::RemovedBlockType::Finalized) {
                finalized_blocks.push(RemovedBlock {
                    block_hash: block.block_hash,
                    block_number: block.block_number,
                    user_data: block.user_data,
                    scale_encoded_header: block.scale_encoded_header,
                });
            } else {
                pruned_blocks.push(RemovedBlock {
                    block_hash: block.block_hash,
                    block_number: block.block_number,
                    user_data: block.user_data,
                    scale_encoded_header: block.scale_encoded_header,
                });
            }
        }
        let _finalized_blocks = self
            .parent
            .inner
            .blocks
            .set_finalized_block_height(finalized_blocks.last().unwrap().block_number);

        (
            self.parent,
            FinalityProofVerifyOutcome::NewFinalized {
                finalized_blocks_newest_to_oldest: finalized_blocks,
                pruned_blocks,
                updates_best_block,
            },
        )
    }

    /// Do not actually proceed with the verification.
    pub fn cancel(self) -> AllForksSync<TBl, TRq, TSrc> {
        self.parent
    }
}

/// See [`AllForksSync::grandpa_commit_message`].
#[derive(Debug, Clone)]
pub enum GrandpaCommitMessageOutcome {
    /// Failed to parse message. Commit has been silently discarded.
    ParseError, // TODO: should probably contain the error, but difficult due to lifetimes in said error
    /// Message has been queued for later verification.
    Queued,
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

    /// A block is ready for verification.
    BlockVerify(BlockVerify<TBl, TRq, TSrc>),

    /// A justification is ready for verification.
    FinalityProofVerify(FinalityProofVerify<TBl, TRq, TSrc>),
}

/// Outcome of calling [`BlockVerify::verify_header`].
pub enum HeaderVerifyOutcome<TBl, TRq, TSrc> {
    /// Header has been successfully verified.
    Success {
        /// True if the newly-verified block is considered the new best block.
        is_new_best: bool,
        success: HeaderVerifySuccess<TBl, TRq, TSrc>,
    },

    /// Header verification failed.
    Error {
        /// State machine yielded back. Use to continue the processing.
        sync: AllForksSync<TBl, TRq, TSrc>,
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

/// Information about the outcome of verifying a finality proof.
#[derive(Debug)]
pub enum FinalityProofVerifyOutcome<TBl> {
    /// Verification successful. The block and all its ancestors is now finalized.
    NewFinalized {
        /// List of finalized blocks, in decreasing block number.
        finalized_blocks_newest_to_oldest: Vec<RemovedBlock<TBl>>,
        /// List of blocks that aren't descendant of the latest finalized block, in an unspecified order.
        pruned_blocks: Vec<RemovedBlock<TBl>>,
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
    JustificationError(blocks_tree::JustificationVerifyError),
    /// Problem while verifying GrandPa commit.
    GrandpaCommitError(blocks_tree::CommitVerifyError),
}

/// See [`FinalityProofVerifyOutcome`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemovedBlock<TBl> {
    /// Hash of the block.
    pub block_hash: [u8; 32],
    /// Height of the block.
    pub block_number: u64,
    /// User data that was associated with that block.
    pub user_data: TBl,
    /// SCALE-encoded header of the block.
    pub scale_encoded_header: Vec<u8>,
}

/// Result of [`AllForkSync::set_finalized_block`].
pub struct SetFinalizedBlockResult<TBl> {
    /// The blocks that got finalized.
    pub finalized_blocks: Vec<RemovedBlock<TBl>>,
    /// The blocks that got pruned in the process of finalizing.
    pub pruned_blocks: Vec<RemovedBlock<TBl>>,
    /// Is set to `true`, if the best block changed.
    pub updates_best_block: bool,
}
