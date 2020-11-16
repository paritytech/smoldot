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

//! Finalized block header, plus tree of authenticated non-finalized block headers.
//!
//! This module provides the [`NonFinalizedTree`] type. This type is a data structure
//! containing a valid tree of block headers, plus the state necessary to verify new blocks with
//! the intent to add them to that tree. Each block header additionally holds a user-chosen
//! opaque data.
//!
//! The state in the [`NonFinalizedTree`] consists of:
//!
//! - One "latest finalized" block and various information about its ancestors, akin to a
//!   [`chain_information::ChainInformation`].
//! - Zero or more blocks that descend from that latest finalized block.
//!
//! The latest finalized block is a block that is guaranted to never be reverted. While it can
//! always be set to the genesis block of the chain, it is preferable, in order to reduce
//! memory utilization, to maintain it to a block that is as high as possible in the chain.
//!
//! > **Note**: While mechanisms such as GrandPa provide a network-wide way to designate a block
//! >           as final, the concept of GrandPa-provided finality doesn't necessarily have to
//! >           match the concept of finality in the [`NonFinalizedTree`]. For example, an API
//! >           user might decide to optimistically assume that the block whose number is
//! >           `highest_block - 5` is automatically finalized, and fall back to rebuilding a new
//! >           [`NonFinalizedTree`] if that assumption turns out to not be true. The finalized
//! >           block in the [`NonFinalizedTree`] only represents a block that the
//! >           [`NonFinalizedTree`] cannot remove, not a block that cannot be removed in the
//! >           absolute.
//!
//! A block can be added to the chain by calling [`NonFinalizedTree::verify_header`] or
//! [`NonFinalizedTree::verify_body`]. As explained in details in
//! [the `verify` module](crate::verify), verifying the header only verifies the authenticity of
//! a block and not its correctness. Verifying both the header and body provides the strongest
//! guarantee, but requires knowledge of the storage of the block that is parent of the block to
//! verify.
//!
//! > **Note**: There typically exists two kinds of clients: full and light. Full clients store
//! >           the state of the storage, while light clients don't. For this reason, light
//! >           clients can only verify the header of new blocks. Both full and light clients
//! >           should wait for a block to be finalized if they want to be certain that it will
//! >           forever remain part of the chain.
//!
//! Additionally, a [`NonFinalizedTree::verify_justification`] method is provided in order to
//! verify the correctness of a [justification](crate::finality::justification).

// TODO: expand this doc ^
// TODO: this module is an essential part of the code and needs clean up and testing

use crate::{
    chain::{chain_information, fork_tree},
    executor::host,
    finality::justification,
    header,
    trie::calculate_root,
    verify,
};

use alloc::{sync::Arc, vec::Vec};
use core::{cmp, convert::TryFrom as _, fmt, mem, num::NonZeroU64, time::Duration};
use hashbrown::HashMap;

/// Configuration for the [`NonFinalizedTree`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Information about the latest finalized block and its ancestors.
    pub chain_information: chain_information::ChainInformation,

    /// Pre-allocated size of the chain, in number of non-finalized blocks.
    pub blocks_capacity: usize,
}

/// Holds state about the current state of the chain for the purpose of verifying headers.
pub struct NonFinalizedTree<T> {
    /// Header of the highest known finalized block.
    finalized_block_header: header::Header,
    /// Hash of [`NonFinalizedTree::finalized_block_header`].
    finalized_block_hash: [u8; 32],
    /// Grandpa authorities set ID of the block right after the finalized block.
    grandpa_after_finalized_block_authorities_set_id: u64,
    /// List of GrandPa authorities that need to finalize the block right after the finalized
    /// block.
    grandpa_finalized_triggered_authorities: Vec<header::GrandpaAuthority>,
    /// Change in the GrandPa authorities list that has been scheduled by a block that is already
    /// finalized but not triggered yet. These changes will for sure happen. Contains the block
    /// number where the changes are to be triggered.
    grandpa_finalized_scheduled_change: Option<(u64, Vec<header::GrandpaAuthority>)>,

    /// State of the consensus of the finalized block.
    finalized_consensus: FinalizedConsensus,

    /// Container for non-finalized blocks.
    blocks: fork_tree::ForkTree<Block<T>>,
    /// Index within [`NonFinalizedTree::blocks`] of the current best block. `None` if and only
    /// if the fork tree is empty.
    current_best: Option<fork_tree::NodeIndex>,
}

/// State of the consensus of the finalized block.
#[derive(Clone)]
enum FinalizedConsensus {
    Aura {
        /// List of authorities that must sign the child of the finalized block.
        authorities_list: Arc<Vec<header::AuraAuthority>>,

        /// Duration, in milliseconds, of a slot.
        slot_duration: NonZeroU64,
    },
    Babe {
        /// See [`chain_information::ChainInformationConsensus::Babe::finalized_block_epoch_information`].
        block_epoch_information: Option<Arc<chain_information::BabeEpochInformation>>,

        /// See [`chain_information::ChainInformationConsensus::Babe::finalized_next_epoch_transition`].
        next_epoch_transition: Arc<chain_information::BabeEpochInformation>,

        /// See [`chain_information::ChainInformationConsensus::Babe::slots_per_epoch`].
        slots_per_epoch: NonZeroU64,
    },
}

struct Block<T> {
    /// Header of the block.
    header: header::Header,
    /// Cache of the hash of the block. Always equal to the hash of the header stored in this
    /// same struct.
    hash: [u8; 32],
    /// Changes to the consensus made by the block.
    consensus: BlockConsensus,
    /// Opaque data decided by the user.
    user_data: T,
}

/// Changes to the consensus made by a block.
#[derive(Clone)]
enum BlockConsensus {
    Aura {
        /// If `Some`, list of authorities that must verify the child of this block.
        /// This can be a clone of the value of the parent, a clone of
        /// [`FinalizedConsensus::Aura::authorities_list`], or a new value if the block modifies
        /// this list.
        authorities_list: Arc<Vec<header::AuraAuthority>>,
    },
    Babe {
        /// Information about the Babe epoch the block belongs to. `None` if the block belongs to
        /// epoch #0.
        current_epoch: Option<Arc<chain_information::BabeEpochInformation>>,
        /// Information about the Babe epoch the block belongs to.
        next_epoch: Arc<chain_information::BabeEpochInformation>,
    },
}

impl<T> NonFinalizedTree<T> {
    /// Initializes a new queue.
    ///
    /// # Panic
    ///
    /// Panics if the chain information is incorrect.
    ///
    pub fn new(config: Config) -> Self {
        if let chain_information::ChainInformationConsensus::Babe {
            finalized_next_epoch_transition,
            finalized_block_epoch_information,
            ..
        } = &config.chain_information.consensus
        {
            if let Some(finalized_block_epoch_information) = &finalized_block_epoch_information {
                assert!(config.chain_information.finalized_block_header.number >= 1);
                assert_eq!(
                    finalized_block_epoch_information
                        .start_slot_number
                        .is_some(),
                    finalized_block_epoch_information.epoch_index != 0
                );
                assert_eq!(
                    finalized_block_epoch_information.epoch_index + 1,
                    finalized_next_epoch_transition.epoch_index
                );
            } else {
                assert_eq!(config.chain_information.finalized_block_header.number, 0);
            }
        }

        if config.chain_information.finalized_block_header.number == 0 {
            assert_eq!(
                config
                    .chain_information
                    .grandpa_after_finalized_block_authorities_set_id,
                0
            );
        }

        // TODO: also check that babe_finalized_block_epoch_information is None if and only if block is in epoch #0

        let finalized_block_hash = config.chain_information.finalized_block_header.hash();

        if let Some(scheduled) = config
            .chain_information
            .grandpa_finalized_scheduled_change
            .as_ref()
        {
            assert!(scheduled.0 > config.chain_information.finalized_block_header.number);
        }

        NonFinalizedTree {
            finalized_block_header: config.chain_information.finalized_block_header,
            finalized_block_hash,
            grandpa_after_finalized_block_authorities_set_id: config
                .chain_information
                .grandpa_after_finalized_block_authorities_set_id,
            grandpa_finalized_triggered_authorities: config
                .chain_information
                .grandpa_finalized_triggered_authorities,
            grandpa_finalized_scheduled_change: config
                .chain_information
                .grandpa_finalized_scheduled_change,
            finalized_consensus: match config.chain_information.consensus {
                chain_information::ChainInformationConsensus::Aura {
                    finalized_authorities_list,
                    slot_duration,
                } => FinalizedConsensus::Aura {
                    authorities_list: Arc::new(finalized_authorities_list),
                    slot_duration,
                },
                chain_information::ChainInformationConsensus::Babe {
                    finalized_block_epoch_information,
                    finalized_next_epoch_transition,
                    slots_per_epoch,
                } => FinalizedConsensus::Babe {
                    slots_per_epoch,
                    block_epoch_information: finalized_block_epoch_information.map(Arc::new),
                    next_epoch_transition: Arc::new(finalized_next_epoch_transition),
                },
            },
            blocks: fork_tree::ForkTree::with_capacity(config.blocks_capacity),
            current_best: None,
        }
    }

    /// Removes all non-finalized blocks from the tree.
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.current_best = None;
    }

    /// Returns true if there isn't any non-finalized block in the chain.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Returns the number of non-finalized blocks in the chain.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Reserves additional capacity for at least `additional` new blocks without allocating.
    pub fn reserve(&mut self, additional: usize) {
        self.blocks.reserve(additional)
    }

    /// Shrink the capacity of the chain as much as possible.
    pub fn shrink_to_fit(&mut self) {
        self.blocks.shrink_to_fit()
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct that might later be used to
    /// build a new [`NonFinalizedTree`].
    pub fn as_chain_information(&self) -> chain_information::ChainInformationRef {
        chain_information::ChainInformationRef {
            finalized_block_header: (&self.finalized_block_header).into(),
            consensus: match &self.finalized_consensus {
                FinalizedConsensus::Aura {
                    authorities_list,
                    slot_duration,
                } => chain_information::ChainInformationConsensusRef::Aura {
                    finalized_authorities_list: header::AuraAuthoritiesIter::from_slice(
                        &authorities_list,
                    ),
                    slot_duration: *slot_duration,
                },
                FinalizedConsensus::Babe {
                    block_epoch_information,
                    next_epoch_transition,
                    slots_per_epoch,
                } => chain_information::ChainInformationConsensusRef::Babe {
                    slots_per_epoch: *slots_per_epoch,
                    finalized_block_epoch_information: block_epoch_information
                        .as_ref()
                        .map(|info| From::from(&**info)),
                    finalized_next_epoch_transition: next_epoch_transition.as_ref().into(),
                },
            },
            grandpa_after_finalized_block_authorities_set_id: self
                .grandpa_after_finalized_block_authorities_set_id,
            grandpa_finalized_triggered_authorities: &self.grandpa_finalized_triggered_authorities,
            grandpa_finalized_scheduled_change: self
                .grandpa_finalized_scheduled_change
                .as_ref()
                .map(|(n, l)| (*n, &l[..])),
        }
    }

    /// Returns the header of the latest finalized block.
    pub fn finalized_block_header(&self) -> header::HeaderRef {
        (&self.finalized_block_header).into()
    }

    /// Returns the hash of the latest finalized block.
    pub fn finalized_block_hash(&self) -> [u8; 32] {
        self.finalized_block_hash
    }

    /// Returns the header of the best block.
    pub fn best_block_header(&self) -> header::HeaderRef {
        if let Some(index) = self.current_best {
            (&self.blocks.get(index).unwrap().header).into()
        } else {
            (&self.finalized_block_header).into()
        }
    }

    /// Returns the hash of the best block.
    pub fn best_block_hash(&self) -> [u8; 32] {
        if let Some(index) = self.current_best {
            self.blocks.get(index).unwrap().hash
        } else {
            self.finalized_block_hash
        }
    }

    /// Verifies the given block.
    ///
    /// The verification is performed in the context of the chain. In particular, the
    /// verification will fail if the parent block isn't already in the chain.
    ///
    /// If the verification succeeds, an [`HeaderInsert`] object might be returned which can be
    /// used to then insert the block in the chain.
    ///
    /// Must be passed the current UNIX time in order to verify that the block doesn't pretend to
    /// come from the future.
    #[must_use]
    pub fn verify_header(
        &mut self,
        scale_encoded_header: Vec<u8>,
        now_from_unix_epoch: Duration,
    ) -> Result<HeaderVerifySuccess<T>, HeaderVerifyError> {
        // TODO: lots of code here is duplicated from verify_body

        let decoded_header = match header::decode(&scale_encoded_header) {
            Ok(h) => h,
            Err(err) => {
                return Err(HeaderVerifyError::InvalidHeader(err));
            }
        };

        let hash = header::hash_from_scale_encoded_header(&scale_encoded_header);

        if self.blocks.find(|b| b.hash == hash).is_some() {
            return Ok(HeaderVerifySuccess::Duplicate);
        }

        // Try to find the parent block in the tree of known blocks.
        // `Some` with an index of the parent within the tree of unfinalized blocks.
        // `None` means that the parent is the finalized block.
        //
        // The parent hash is first checked against `self.current_best`, as it is most likely
        // that new blocks are built on top of the current best.
        let parent_tree_index = if self.current_best.map_or(false, |best| {
            *decoded_header.parent_hash == self.blocks.get(best).unwrap().hash
        }) {
            Some(self.current_best.unwrap())
        } else if *decoded_header.parent_hash == self.finalized_block_hash {
            None
        } else {
            let parent_hash = *decoded_header.parent_hash;
            match self.blocks.find(|b| b.hash == parent_hash) {
                Some(parent) => Some(parent),
                None => {
                    return Err(HeaderVerifyError::BadParent { parent_hash });
                }
            }
        };

        let parent_block_header = if let Some(parent_tree_index) = parent_tree_index {
            &self.blocks.get(parent_tree_index).unwrap().header
        } else {
            &self.finalized_block_header
        };

        // Some consensus-specific information must be fetched from the tree of ancestry. The
        // information is found either in the parent block, or in the finalized block.
        let consensus_specific = if let Some(parent_tree_index) = parent_tree_index {
            match &self.blocks.get(parent_tree_index).unwrap().consensus {
                BlockConsensus::Aura { authorities_list } => VerifyConsensusSpecific::Aura {
                    authorities_list: authorities_list.clone(),
                },
                BlockConsensus::Babe {
                    current_epoch,
                    next_epoch,
                } => VerifyConsensusSpecific::Babe {
                    current_epoch: current_epoch.clone(),
                    next_epoch: next_epoch.clone(),
                },
            }
        } else {
            // Some consensus-specific information must be fetched from the tree of ancestry. The
            // information is found either in the parent block, or in the finalized block.
            if let Some(parent_tree_index) = parent_tree_index {
                match &self.blocks.get(parent_tree_index).unwrap().consensus {
                    BlockConsensus::Aura { authorities_list } => VerifyConsensusSpecific::Aura {
                        authorities_list: authorities_list.clone(),
                    },
                    BlockConsensus::Babe {
                        current_epoch,
                        next_epoch,
                    } => VerifyConsensusSpecific::Babe {
                        current_epoch: current_epoch.clone(),
                        next_epoch: next_epoch.clone(),
                    },
                }
            } else {
                match &self.finalized_consensus {
                    FinalizedConsensus::Aura {
                        authorities_list, ..
                    } => VerifyConsensusSpecific::Aura {
                        authorities_list: authorities_list.clone(),
                    },
                    FinalizedConsensus::Babe {
                        block_epoch_information,
                        next_epoch_transition,
                        ..
                    } => VerifyConsensusSpecific::Babe {
                        current_epoch: block_epoch_information.clone(),
                        next_epoch: next_epoch_transition.clone(),
                    },
                }
            }
        };

        let result = verify::header_only::verify(verify::header_only::Config {
            consensus: match (&self.finalized_consensus, &consensus_specific) {
                (
                    FinalizedConsensus::Aura { slot_duration, .. },
                    VerifyConsensusSpecific::Aura { authorities_list },
                ) => {
                    verify::header_only::ConfigConsensus::Aura {
                        // TODO: meh for allocating :-/
                        current_authorities: authorities_list.iter().map(|a| a.into()).collect(),
                        now_from_unix_epoch,
                        slot_duration: *slot_duration,
                    }
                }
                (
                    FinalizedConsensus::Babe {
                        slots_per_epoch, ..
                    },
                    VerifyConsensusSpecific::Babe {
                        current_epoch,
                        next_epoch,
                    },
                ) => verify::header_only::ConfigConsensus::Babe {
                    parent_block_epoch: current_epoch.as_ref().map(|v| (&**v).into()),
                    parent_block_next_epoch: (&**next_epoch).into(),
                    slots_per_epoch: *slots_per_epoch,
                    now_from_unix_epoch,
                },
                // TODO: don't panic! this is before any verification
                _ => unreachable!(),
            },
            block_header: decoded_header.clone(),
            parent_block_header: parent_block_header.into(),
        })
        .map_err(HeaderVerifyError::VerificationFailed)?;

        let is_new_best = if let Some(current_best) = self.current_best {
            is_better_block(
                &self.blocks,
                current_best,
                parent_tree_index,
                decoded_header.clone(),
            )
        } else {
            true
        };

        let consensus = match (
            result,
            consensus_specific,
            self.finalized_consensus.clone(),
            parent_tree_index.map(|idx| self.blocks.get(idx).unwrap().consensus.clone()),
        ) {
            (
                verify::header_only::Success::Aura { authorities_change },
                VerifyConsensusSpecific::Aura {
                    authorities_list: parent_authorities,
                },
                FinalizedConsensus::Aura { .. },
                _,
            ) => {
                if authorities_change {
                    BlockConsensus::Aura {
                        authorities_list: todo!(), // TODO: fetch from header
                    }
                } else {
                    BlockConsensus::Aura {
                        authorities_list: parent_authorities,
                    }
                }
            }

            (
                verify::header_only::Success::Babe {
                    epoch_transition_target: Some(epoch_transition_target),
                    slot_number,
                },
                VerifyConsensusSpecific::Babe { .. },
                FinalizedConsensus::Babe { .. },
                Some(BlockConsensus::Babe { next_epoch, .. }),
            ) => BlockConsensus::Babe {
                current_epoch: Some(next_epoch),
                next_epoch: Arc::new(epoch_transition_target),
            },

            (
                verify::header_only::Success::Babe {
                    epoch_transition_target: None,
                    slot_number,
                },
                VerifyConsensusSpecific::Babe { .. },
                FinalizedConsensus::Babe { .. },
                Some(BlockConsensus::Babe {
                    current_epoch,
                    next_epoch,
                }),
            ) => BlockConsensus::Babe {
                current_epoch,
                next_epoch,
            },

            (
                verify::header_only::Success::Babe {
                    epoch_transition_target: Some(epoch_transition_target),
                    slot_number,
                },
                VerifyConsensusSpecific::Babe { .. },
                FinalizedConsensus::Babe {
                    next_epoch_transition,
                    ..
                },
                None,
            ) => BlockConsensus::Babe {
                current_epoch: Some(next_epoch_transition.clone()),
                next_epoch: Arc::new(epoch_transition_target),
            },

            (
                verify::header_only::Success::Babe {
                    epoch_transition_target: None,
                    slot_number,
                },
                VerifyConsensusSpecific::Babe { .. },
                FinalizedConsensus::Babe {
                    block_epoch_information,
                    next_epoch_transition,
                    ..
                },
                None,
            ) => BlockConsensus::Babe {
                current_epoch: block_epoch_information.clone(),
                next_epoch: next_epoch_transition.clone(),
            },

            // Any mismatch between consensus algorithms should have been detected by the
            // block verification.
            _ => unreachable!(),
        };

        Ok(HeaderVerifySuccess::Insert {
            block_height: decoded_header.number,
            is_new_best,
            insert: HeaderInsert {
                chain: self,
                parent_tree_index,
                is_new_best,
                header: decoded_header.into(),
                hash,
                consensus,
            },
        })
    }

    /// Verifies the given block.
    ///
    /// The verification is performed in the context of the chain. In particular, the
    /// verification will fail if the parent block isn't already in the chain.
    ///
    /// This method takes ownership of both the block's information and the [`NonFinalizedTree`].
    /// It turns an object that must be driver by the user, until either the verification is
    /// finished or the process aborted, at which point the [`NonFinalizedTree`] can be retrieved
    /// back. The state of the [`NonFinalizedTree`] isn't modified until [`BodyInsert::insert`] is
    /// called after the end of the verification.
    ///
    /// Must be passed the current UNIX time in order to verify that the block doesn't pretend to
    /// come from the future.
    pub fn verify_body<I, E>(
        self,
        scale_encoded_header: Vec<u8>,
        now_from_unix_epoch: Duration,
        body: I,
    ) -> BodyVerifyStep1<T, I>
    where
        I: ExactSizeIterator<Item = E> + Clone,
        E: AsRef<[u8]> + Clone,
    {
        let decoded_header = match header::decode(&scale_encoded_header) {
            Ok(h) => h,
            Err(err) => return BodyVerifyStep1::InvalidHeader(self, err),
        };

        let hash = header::hash_from_scale_encoded_header(&scale_encoded_header);

        if self.blocks.find(|b| b.hash == hash).is_some() {
            return BodyVerifyStep1::Duplicate(self);
        }

        // Try to find the parent block in the tree of known blocks.
        // `Some` with an index of the parent within the tree of unfinalized blocks.
        // `None` means that the parent is the finalized block.
        //
        // The parent hash is first checked against `self.current_best`, as it is most likely
        // that new blocks are built on top of the current best.
        let parent_tree_index = if self.current_best.map_or(false, |best| {
            *decoded_header.parent_hash == self.blocks.get(best).unwrap().hash
        }) {
            Some(self.current_best.unwrap())
        } else if *decoded_header.parent_hash == self.finalized_block_hash {
            None
        } else {
            let parent_hash = *decoded_header.parent_hash;
            match self.blocks.find(|b| b.hash == parent_hash) {
                Some(parent) => Some(parent),
                None => {
                    return BodyVerifyStep1::BadParent {
                        chain: self,
                        parent_hash,
                    }
                }
            }
        };

        // Some consensus-specific information must be fetched from the tree of ancestry. The
        // information is found either in the parent block, or in the finalized block.
        let consensus = if let Some(parent_tree_index) = parent_tree_index {
            match &self.blocks.get(parent_tree_index).unwrap().consensus {
                BlockConsensus::Aura { authorities_list } => VerifyConsensusSpecific::Aura {
                    authorities_list: authorities_list.clone(),
                },
                BlockConsensus::Babe {
                    current_epoch,
                    next_epoch,
                } => VerifyConsensusSpecific::Babe {
                    current_epoch: current_epoch.clone(),
                    next_epoch: next_epoch.clone(),
                },
            }
        } else {
            match &self.finalized_consensus {
                FinalizedConsensus::Aura {
                    authorities_list, ..
                } => VerifyConsensusSpecific::Aura {
                    authorities_list: authorities_list.clone(),
                },
                FinalizedConsensus::Babe {
                    block_epoch_information,
                    next_epoch_transition,
                    ..
                } => VerifyConsensusSpecific::Babe {
                    current_epoch: block_epoch_information.clone(),
                    next_epoch: next_epoch_transition.clone(),
                },
            }
        };

        BodyVerifyStep1::ParentRuntimeRequired(BodyVerifyRuntimeRequired {
            chain: self,
            header: decoded_header.into(),
            parent_tree_index,
            body,
            consensus,
            now_from_unix_epoch,
        })
    }

    /// Verifies the given justification.
    ///
    /// The verification is performed in the context of the chain. In particular, the
    /// verification will fail if the target block isn't already in the chain.
    ///
    /// If the verification succeeds, a [`JustificationApply`] object will be returned which can
    /// be used to apply the finalization.
    // TODO: expand the documentation about how blocks with authorities changes have to be finalized before any further block can be finalized
    pub fn verify_justification(
        &mut self,
        scale_encoded_justification: &[u8],
    ) -> Result<JustificationApply<T>, JustificationVerifyError> {
        // Turn justification into a strongly-typed struct.
        let decoded = justification::decode::decode(&scale_encoded_justification)
            .map_err(JustificationVerifyError::InvalidJustification)?;

        // Find in the list of non-finalized blocks the one targeted by the justification.
        let block_index = match self.blocks.find(|b| b.hash == *decoded.target_hash) {
            Some(idx) => idx,
            None => {
                return Err(JustificationVerifyError::UnknownTargetBlock {
                    block_number: From::from(decoded.target_number),
                    block_hash: *decoded.target_hash,
                });
            }
        };

        // If any block between the latest finalized one and the target block trigger any GrandPa
        // authorities change, then we need to finalize that triggering block (or any block
        // after or including the one that schedules these changes) before finalizing the one
        // targeted by the justification.
        // TODO: rethink and reexplain this ^

        // Find out the next block height where an authority change will be triggered.
        let earliest_trigger = {
            // Scheduled change that is already finalized.
            let scheduled = self
                .grandpa_finalized_scheduled_change
                .as_ref()
                .map(|(n, _)| *n);

            // First change that would be scheduled if we finalize the target block.
            let would_happen = {
                let mut trigger_height = None;
                // TODO: lot of boilerplate code here
                for node in self.blocks.root_to_node_path(block_index) {
                    let header = &self.blocks.get(node).unwrap().header;
                    for grandpa_digest_item in header.digest.logs().filter_map(|d| match d {
                        header::DigestItemRef::GrandpaConsensus(gp) => Some(gp),
                        _ => None,
                    }) {
                        match grandpa_digest_item {
                            header::GrandpaConsensusLogRef::ScheduledChange(change) => {
                                let trigger_block_height =
                                    header.number.checked_add(u64::from(change.delay)).unwrap();
                                match trigger_height {
                                    Some(_) => panic!("invalid block!"), // TODO: this problem is not checked during block verification
                                    None => trigger_height = Some(trigger_block_height),
                                }
                            }
                            _ => {} // TODO: unimplemented
                        }
                    }
                }
                trigger_height
            };

            match (scheduled, would_happen) {
                (Some(a), Some(b)) => Some(cmp::min(a, b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            }
        };

        // As explained above, `target_number` must be <= `earliest_trigger`, otherwise the
        // finalization is unsecure.
        if let Some(earliest_trigger) = earliest_trigger {
            if u64::from(decoded.target_number) > earliest_trigger {
                let block_to_finalize_hash = self
                    .blocks
                    .node_to_root_path(block_index)
                    .filter_map(|b| {
                        let b = self.blocks.get(b).unwrap();
                        if b.header.number == earliest_trigger {
                            Some(b.hash)
                        } else {
                            None
                        }
                    })
                    .next()
                    .unwrap();
                return Err(JustificationVerifyError::TooFarAhead {
                    justification_block_number: u64::from(decoded.target_number),
                    justification_block_hash: *decoded.target_hash,
                    block_to_finalize_number: earliest_trigger,
                    block_to_finalize_hash,
                });
            }
        }

        // Find which authorities are supposed to finalize the target block.
        let authorities_list = self
            .grandpa_finalized_scheduled_change
            .as_ref()
            .filter(|(trigger_height, _)| *trigger_height < u64::from(decoded.target_number))
            .map(|(_, list)| list)
            .unwrap_or(&self.grandpa_finalized_triggered_authorities);

        // As per above check, we know that the authorities of the target block are either the
        // same as the ones of the latest finalized block, or the ones contained in the header of
        // the latest finalized block.
        justification::verify::verify(justification::verify::Config {
            justification: decoded,
            authorities_set_id: self.grandpa_after_finalized_block_authorities_set_id,
            authorities_list: authorities_list.iter().map(|a| a.public_key),
        })
        .map_err(JustificationVerifyError::VerificationFailed)?;

        // Justification has been successfully verified!
        Ok(JustificationApply {
            chain: self,
            to_finalize: block_index,
        })
    }

    /// Sets the latest known finalized block. Trying to verify a block that isn't a descendant of
    /// that block will fail.
    ///
    /// The block must have been passed to [`NonFinalizedTree::verify_header`].
    ///
    /// Returns an iterator containing the now-finalized blocks in decreasing block numbers. In
    /// other words, the first element of the iterator is always the block whose hash is the
    /// `block_hash` passed as parameter.
    ///
    /// > **Note**: This function returns blocks in decreasing block number, because any other
    /// >           ordering would incur a performance cost. While returning blocks in increasing
    /// >           block number would often be more convenient, the overhead of doing so is
    /// >           moved to the user.
    ///
    /// The pruning is completely performed, even if the iterator is dropped eagerly.
    pub fn set_finalized_block(
        &mut self,
        block_hash: &[u8; 32],
    ) -> Result<SetFinalizedBlockIter<T>, SetFinalizedError> {
        let block_index = match self.blocks.find(|b| b.hash == *block_hash) {
            Some(idx) => idx,
            None => return Err(SetFinalizedError::UnknownBlock),
        };

        Ok(self.set_finalized_block_inner(block_index))
    }

    /// Private function that does the same as [`NonFinalizedTree::set_finalized_block`].
    fn set_finalized_block_inner(
        &mut self,
        block_index: fork_tree::NodeIndex,
    ) -> SetFinalizedBlockIter<T> {
        let target_block_height = self.blocks.get_mut(block_index).unwrap().header.number;

        // Update the scheduled GrandPa change with the latest scheduled-but-non-finalized change
        // that could be found.
        self.grandpa_finalized_scheduled_change = None;
        for node in self.blocks.root_to_node_path(block_index) {
            let node = self.blocks.get(node).unwrap();
            //node.header.number
            for grandpa_digest_item in node.header.digest.logs().filter_map(|d| match d {
                header::DigestItemRef::GrandpaConsensus(gp) => Some(gp),
                _ => None,
            }) {
                match grandpa_digest_item {
                    header::GrandpaConsensusLogRef::ScheduledChange(change) => {
                        let trigger_block_height = node
                            .header
                            .number
                            .checked_add(u64::from(change.delay))
                            .unwrap();
                        if trigger_block_height > target_block_height {
                            self.grandpa_finalized_scheduled_change = Some((
                                trigger_block_height,
                                change.next_authorities.map(Into::into).collect(),
                            ));
                        } else {
                            self.grandpa_finalized_triggered_authorities =
                                change.next_authorities.map(Into::into).collect();
                            self.grandpa_after_finalized_block_authorities_set_id += 1;
                        }
                    }
                    _ => {} // TODO: unimplemented
                }
            }
        }

        let new_finalized_block = self.blocks.get_mut(block_index).unwrap();

        match (
            &mut self.finalized_consensus,
            &new_finalized_block.consensus,
        ) {
            (
                FinalizedConsensus::Aura {
                    authorities_list, ..
                },
                BlockConsensus::Aura {
                    authorities_list: new_list,
                },
            ) => {
                *authorities_list = new_list.clone();
            }
            (
                FinalizedConsensus::Babe {
                    block_epoch_information,
                    next_epoch_transition,
                    ..
                },
                BlockConsensus::Babe {
                    current_epoch,
                    next_epoch,
                },
            ) => {
                *block_epoch_information = current_epoch.clone();
                *next_epoch_transition = next_epoch.clone();
            }
            // Any mismatch of consensus engines between the chain and the newly-finalized block
            // should have been detected when the block got added to the chain.
            _ => unreachable!(),
        }

        mem::swap(
            &mut self.finalized_block_header,
            &mut new_finalized_block.header,
        );
        self.finalized_block_hash = self.finalized_block_header.hash();

        SetFinalizedBlockIter {
            iter: self.blocks.prune_ancestors(block_index),
            current_best: &mut self.current_best,
        }
    }
}

impl<T> fmt::Debug for NonFinalizedTree<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map()
            .entries(self.blocks.iter().map(|v| (&v.hash, &v.user_data)))
            .finish()
    }
}

/// Block verification, either just finished or still in progress.
///
/// Holds ownership of both the block to verify and the [`NonFinalizedTree`].
#[must_use]
#[derive(Debug)]
pub enum BodyVerifyStep1<T, I> {
    /// Block is already known.
    Duplicate(NonFinalizedTree<T>),

    /// Error while decoding the header.
    InvalidHeader(NonFinalizedTree<T>, header::Error),

    /// The parent of the block isn't known.
    BadParent {
        chain: NonFinalizedTree<T>,
        /// Hash of the parent block in question.
        parent_hash: [u8; 32],
    },

    /// Verification is pending. In order to continue, a [`host::HostVmPrototype`] of the
    /// runtime of the parent block must be provided.
    ParentRuntimeRequired(BodyVerifyRuntimeRequired<T, I>),
}

#[derive(Debug)]
enum VerifyConsensusSpecific {
    Aura {
        authorities_list: Arc<Vec<header::AuraAuthority>>,
    },
    Babe {
        current_epoch: Option<Arc<chain_information::BabeEpochInformation>>,
        next_epoch: Arc<chain_information::BabeEpochInformation>,
    },
}

/// Verification is pending. In order to continue, a [`host::HostVmPrototype`] of the runtime
/// of the parent block must be provided.
#[must_use]
#[derive(Debug)]
pub struct BodyVerifyRuntimeRequired<T, I> {
    chain: NonFinalizedTree<T>,
    header: header::Header,
    parent_tree_index: Option<fork_tree::NodeIndex>,
    body: I,
    consensus: VerifyConsensusSpecific,
    now_from_unix_epoch: Duration,
}

impl<T, I, E> BodyVerifyRuntimeRequired<T, I>
where
    I: ExactSizeIterator<Item = E> + Clone,
    E: AsRef<[u8]> + Clone,
{
    /// Access to the parent block's information and hierarchy. Returns `None` if the parent is
    /// the finalized block.
    pub fn parent_block(&mut self) -> Option<BlockAccess<T>> {
        Some(BlockAccess {
            tree: &mut self.chain,
            node_index: self.parent_tree_index?,
        })
    }

    /// Access to the Nth ancestor's information and hierarchy. Returns `None` if `n` is too
    /// large. A value of `0` for `n` corresponds to the parent block. A value of `1` corresponds
    /// to the parent's parent. And so on.
    pub fn nth_ancestor(&mut self, n: u64) -> Option<BlockAccess<T>> {
        let parent_index = self.parent_tree_index?;
        let n = usize::try_from(n).ok()?;
        let ret = self.chain.blocks.node_to_root_path(parent_index).nth(n)?;
        Some(BlockAccess {
            tree: &mut self.chain,
            node_index: ret,
        })
    }

    /// Returns the number of non-finalized blocks in the tree that are ancestors to the block
    /// being verified.
    pub fn num_non_finalized_ancestors(&self) -> u64 {
        let parent_index = match self.parent_tree_index {
            Some(p) => p,
            None => return 0,
        };

        u64::try_from(self.chain.blocks.node_to_root_path(parent_index).count()).unwrap()
    }

    /// Resume the verification process by passing the requested information.
    ///
    /// `parent_runtime` must be a Wasm virtual machine containing the runtime code of the parent
    /// block.
    ///
    /// The value of `top_trie_root_calculation_cache` can be the one provided by the
    /// [`BodyVerifyStep2::Finished`] variant when the parent block has been verified. `None` can
    /// be passed if this information isn't available.
    ///
    /// While `top_trie_root_calculation_cache` is optional, providing a value will considerably
    /// speed up the calculation.
    pub fn resume(
        self,
        parent_runtime: host::HostVmPrototype,
        top_trie_root_calculation_cache: Option<calculate_root::CalculationCache>,
    ) -> BodyVerifyStep2<T> {
        let parent_block_header = if let Some(parent_tree_index) = self.parent_tree_index {
            &self.chain.blocks.get(parent_tree_index).unwrap().header
        } else {
            &self.chain.finalized_block_header
        };

        let process = verify::header_body::verify(verify::header_body::Config {
            parent_runtime,
            consensus: match (&self.chain.finalized_consensus, &self.consensus) {
                (
                    FinalizedConsensus::Aura { slot_duration, .. },
                    VerifyConsensusSpecific::Aura { authorities_list },
                ) => {
                    verify::header_body::ConfigConsensus::Aura {
                        // TODO: meh for allocation
                        current_authorities: authorities_list.iter().map(|a| a.into()).collect(),
                        now_from_unix_epoch: self.now_from_unix_epoch,
                        slot_duration: *slot_duration,
                    }
                }
                (
                    FinalizedConsensus::Babe {
                        slots_per_epoch, ..
                    },
                    VerifyConsensusSpecific::Babe {
                        current_epoch,
                        next_epoch,
                    },
                ) => verify::header_body::ConfigConsensus::Babe {
                    parent_block_epoch: current_epoch.as_ref().map(|v| (&**v).into()),
                    parent_block_next_epoch: (&**next_epoch).into(),
                    slots_per_epoch: *slots_per_epoch,
                    now_from_unix_epoch: self.now_from_unix_epoch,
                },
                // TODO: don't panic /!\ this is before the verification
                _ => unreachable!(),
            },
            block_header: (&self.header).into(),
            parent_block_header: parent_block_header.into(),
            block_body: self.body,
            top_trie_root_calculation_cache,
        });

        BodyVerifyStep2::from_inner(
            process,
            BodyVerifyShared {
                chain: self.chain,
                parent_tree_index: self.parent_tree_index,
                header: self.header,
                consensus: self.consensus,
            },
        )
    }

    /// Abort the verification and return the unmodified tree.
    pub fn abort(self) -> NonFinalizedTree<T> {
        self.chain
    }
}

/// Block verification, either just finished or still in progress.
///
/// Holds ownership of both the block to verify and the [`NonFinalizedTree`].
#[must_use]
pub enum BodyVerifyStep2<T> {
    /// Verification is over.
    ///
    /// Use the provided [`BodyInsert`] to insert the block in the chain if desired.
    Finished {
        /// Value that was passed to [`BodyVerifyRuntimeRequired::resume`].
        parent_runtime: host::HostVmPrototype,
        /// List of changes to the storage top trie that the block performs.
        storage_top_trie_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
        /// List of changes to the offchain storage that this block performs.
        offchain_storage_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
        /// Cache of calculation for the storage trie of the best block.
        /// Pass this value to [`BodyVerifyRuntimeRequired::resume`] when verifying a children of
        /// this block in order to considerably speed up the verification.
        top_trie_root_calculation_cache: calculate_root::CalculationCache,
        /// Outcome of the verification.
        result: Result<BodyInsert<T>, HeaderVerifyError>, // TODO: BodyVerifyError, or rename the error to be common
    },
    /// Loading a storage value is required in order to continue.
    StorageGet(StorageGet<T>),
    /// Fetching the list of keys with a given prefix is required in order to continue.
    StoragePrefixKeys(StoragePrefixKeys<T>),
    /// Fetching the key that follows a given one is required in order to continue.
    StorageNextKey(StorageNextKey<T>),
}

struct BodyVerifyShared<T> {
    chain: NonFinalizedTree<T>,
    parent_tree_index: Option<fork_tree::NodeIndex>,
    header: header::Header,
    consensus: VerifyConsensusSpecific,
}

impl<T> BodyVerifyStep2<T> {
    fn from_inner(mut inner: verify::header_body::Verify, chain: BodyVerifyShared<T>) -> Self {
        loop {
            match inner {
                verify::header_body::Verify::Finished(Ok(success)) => {
                    // TODO: lots of code in common with header verification

                    // Block verification is successful!
                    let is_new_best = if let Some(current_best) = chain.chain.current_best {
                        is_better_block(
                            &chain.chain.blocks,
                            current_best,
                            chain.parent_tree_index,
                            (&chain.header).into(),
                        )
                    } else {
                        true
                    };

                    let consensus = match (
                        success.consensus,
                        &chain.consensus,
                        chain.chain.finalized_consensus.clone(),
                        chain
                            .parent_tree_index
                            .map(|idx| chain.chain.blocks.get(idx).unwrap().consensus.clone()),
                    ) {
                        (
                            verify::header_body::SuccessConsensus::Aura { authorities_change },
                            VerifyConsensusSpecific::Aura {
                                authorities_list: parent_authorities,
                            },
                            FinalizedConsensus::Aura { .. },
                            _,
                        ) => {
                            if authorities_change {
                                BlockConsensus::Aura {
                                    authorities_list: todo!(), // TODO: fetch from header
                                }
                            } else {
                                BlockConsensus::Aura {
                                    authorities_list: parent_authorities.clone(),
                                }
                            }
                        }

                        (
                            verify::header_body::SuccessConsensus::Babe {
                                epoch_transition_target: Some(epoch_transition_target),
                                slot_number,
                            },
                            VerifyConsensusSpecific::Babe { .. },
                            FinalizedConsensus::Babe { .. },
                            Some(BlockConsensus::Babe { next_epoch, .. }),
                        ) => BlockConsensus::Babe {
                            current_epoch: Some(next_epoch),
                            next_epoch: Arc::new(epoch_transition_target),
                        },

                        (
                            verify::header_body::SuccessConsensus::Babe {
                                epoch_transition_target: None,
                                slot_number,
                            },
                            VerifyConsensusSpecific::Babe { .. },
                            FinalizedConsensus::Babe { .. },
                            Some(BlockConsensus::Babe {
                                current_epoch,
                                next_epoch,
                            }),
                        ) => BlockConsensus::Babe {
                            current_epoch,
                            next_epoch,
                        },

                        (
                            verify::header_body::SuccessConsensus::Babe {
                                epoch_transition_target: Some(epoch_transition_target),
                                slot_number,
                            },
                            VerifyConsensusSpecific::Babe { .. },
                            FinalizedConsensus::Babe {
                                next_epoch_transition,
                                ..
                            },
                            None,
                        ) => BlockConsensus::Babe {
                            current_epoch: Some(next_epoch_transition),
                            next_epoch: Arc::new(epoch_transition_target),
                        },

                        (
                            verify::header_body::SuccessConsensus::Babe {
                                epoch_transition_target: None,
                                slot_number,
                            },
                            VerifyConsensusSpecific::Babe { .. },
                            FinalizedConsensus::Babe {
                                block_epoch_information,
                                next_epoch_transition,
                                ..
                            },
                            None,
                        ) => BlockConsensus::Babe {
                            current_epoch: block_epoch_information.clone(),
                            next_epoch: next_epoch_transition.clone(),
                        },

                        // Any mismatch between consensus algorithms should have been detected by the
                        // block verification.
                        _ => unreachable!(),
                    };

                    let hash = chain.header.hash();

                    return BodyVerifyStep2::Finished {
                        parent_runtime: success.parent_runtime,
                        storage_top_trie_changes: success.storage_top_trie_changes,
                        offchain_storage_changes: success.offchain_storage_changes,
                        top_trie_root_calculation_cache: success.top_trie_root_calculation_cache,
                        result: Ok(BodyInsert {
                            chain: chain.chain,
                            parent_tree_index: chain.parent_tree_index,
                            is_new_best,
                            header: chain.header,
                            hash,
                            consensus,
                        }),
                    };
                }
                verify::header_body::Verify::Finished(Err(err)) => todo!("verify err: {:?}", err),
                verify::header_body::Verify::StorageGet(inner) => {
                    return BodyVerifyStep2::StorageGet(StorageGet { chain, inner })
                }
                verify::header_body::Verify::StorageNextKey(inner) => {
                    return BodyVerifyStep2::StorageNextKey(StorageNextKey { chain, inner })
                }
                verify::header_body::Verify::StoragePrefixKeys(inner) => {
                    return BodyVerifyStep2::StoragePrefixKeys(StoragePrefixKeys { chain, inner })
                }
            }
        }
    }
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet<T> {
    inner: verify::header_body::StorageGet,
    chain: BodyVerifyShared<T>,
}

impl<T> StorageGet<T> {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key<'b>(&'b self) -> impl Iterator<Item = impl AsRef<[u8]> + 'b> + 'b {
        self.inner.key()
    }

    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    ///
    /// This method is a shortcut for calling `key` and concatenating the returned slices.
    pub fn key_as_vec(&self) -> Vec<u8> {
        self.inner.key_as_vec()
    }

    /// Access to the Nth ancestor's information and hierarchy. Returns `None` if `n` is too
    /// large. A value of `0` for `n` corresponds to the parent block. A value of `1` corresponds
    /// to the parent's parent. And so on.
    pub fn nth_ancestor(&mut self, n: u64) -> Option<BlockAccess<T>> {
        let parent_index = self.chain.parent_tree_index?;
        let n = usize::try_from(n).ok()?;
        let ret = self
            .chain
            .chain
            .blocks
            .node_to_root_path(parent_index)
            .nth(n)?;
        Some(BlockAccess {
            tree: &mut self.chain.chain,
            node_index: ret,
        })
    }

    /// Returns the number of non-finalized blocks in the tree that are ancestors to the block
    /// being verified.
    pub fn num_non_finalized_ancestors(&self) -> u64 {
        let parent_index = match self.chain.parent_tree_index {
            Some(p) => p,
            None => return 0,
        };

        u64::try_from(
            self.chain
                .chain
                .blocks
                .node_to_root_path(parent_index)
                .count(),
        )
        .unwrap()
    }

    /// Injects the corresponding storage value.
    // TODO: change API, see execute_block::StorageGet
    pub fn inject_value(self, value: Option<&[u8]>) -> BodyVerifyStep2<T> {
        let inner = self.inner.inject_value(value);
        BodyVerifyStep2::from_inner(inner, self.chain)
    }
}

/// Fetching the list of keys with a given prefix is required in order to continue.
#[must_use]
pub struct StoragePrefixKeys<T> {
    inner: verify::header_body::StoragePrefixKeys,
    chain: BodyVerifyShared<T>,
}

impl<T> StoragePrefixKeys<T> {
    /// Returns the prefix whose keys to load.
    pub fn prefix(&self) -> &[u8] {
        self.inner.prefix()
    }

    /// Access to the Nth ancestor's information and hierarchy. Returns `None` if `n` is too
    /// large. A value of `0` for `n` corresponds to the parent block. A value of `1` corresponds
    /// to the parent's parent. And so on.
    pub fn nth_ancestor(&mut self, n: u64) -> Option<BlockAccess<T>> {
        let parent_index = self.chain.parent_tree_index?;
        let n = usize::try_from(n).ok()?;
        let ret = self
            .chain
            .chain
            .blocks
            .node_to_root_path(parent_index)
            .nth(n)?;
        Some(BlockAccess {
            tree: &mut self.chain.chain,
            node_index: ret,
        })
    }

    /// Returns the number of non-finalized blocks in the tree that are ancestors to the block
    /// being verified.
    pub fn num_non_finalized_ancestors(&self) -> u64 {
        let parent_index = match self.chain.parent_tree_index {
            Some(p) => p,
            None => return 0,
        };

        u64::try_from(
            self.chain
                .chain
                .blocks
                .node_to_root_path(parent_index)
                .count(),
        )
        .unwrap()
    }

    /// Injects the list of keys.
    pub fn inject_keys(self, keys: impl Iterator<Item = impl AsRef<[u8]>>) -> BodyVerifyStep2<T> {
        let inner = self.inner.inject_keys(keys);
        BodyVerifyStep2::from_inner(inner, self.chain)
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct StorageNextKey<T> {
    inner: verify::header_body::StorageNextKey,
    chain: BodyVerifyShared<T>,
}

impl<T> StorageNextKey<T> {
    /// Returns the key whose next key must be passed back.
    pub fn key(&self) -> &[u8] {
        self.inner.key()
    }

    /// Access to the Nth ancestor's information and hierarchy. Returns `None` if `n` is too
    /// large. A value of `0` for `n` corresponds to the parent block. A value of `1` corresponds
    /// to the parent's parent. And so on.
    pub fn nth_ancestor(&mut self, n: u64) -> Option<BlockAccess<T>> {
        let parent_index = self.chain.parent_tree_index?;
        let n = usize::try_from(n).ok()?;
        let ret = self
            .chain
            .chain
            .blocks
            .node_to_root_path(parent_index)
            .nth(n)?;
        Some(BlockAccess {
            tree: &mut self.chain.chain,
            node_index: ret,
        })
    }

    /// Returns the number of non-finalized blocks in the tree that are ancestors to the block
    /// being verified.
    pub fn num_non_finalized_ancestors(&self) -> u64 {
        let parent_index = match self.chain.parent_tree_index {
            Some(p) => p,
            None => return 0,
        };

        u64::try_from(
            self.chain
                .chain
                .blocks
                .node_to_root_path(parent_index)
                .count(),
        )
        .unwrap()
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl AsRef<[u8]>>) -> BodyVerifyStep2<T> {
        let inner = self.inner.inject_key(key);
        BodyVerifyStep2::from_inner(inner, self.chain)
    }
}

///
#[derive(Debug)]
pub enum HeaderVerifySuccess<'c, T> {
    /// Block is already known.
    Duplicate,
    /// Block wasn't known and is ready to be inserted.
    Insert {
        /// Height of the verified block.
        block_height: u64,
        /// True if the verified block will become the new "best" block after being inserted.
        is_new_best: bool,
        /// Use this struct to insert the block in the chain after its successful verification.
        insert: HeaderInsert<'c, T>,
    },
}

/// Mutably borrows the [`NonFinalizedTree`] and allows insert a successfully-verified block
/// into it.
#[must_use]
pub struct HeaderInsert<'c, T> {
    chain: &'c mut NonFinalizedTree<T>,
    /// Copy of the value in [`HeaderVerifySuccess::is_new_best`].
    is_new_best: bool,
    /// Index of the parent in [`NonFinalizedTree::blocks`].
    parent_tree_index: Option<fork_tree::NodeIndex>,
    header: header::Header,
    hash: [u8; 32],
    consensus: BlockConsensus,
}

impl<'c, T> HeaderInsert<'c, T> {
    /// Inserts the block with the given user data.
    pub fn insert(self, user_data: T) {
        let new_node_index = self.chain.blocks.insert(
            self.parent_tree_index,
            Block {
                header: self.header,
                hash: self.hash,
                consensus: self.consensus,
                user_data,
            },
        );

        if self.is_new_best {
            self.chain.current_best = Some(new_node_index);
        }
    }

    /// Destroys the object without inserting the block in the chain. Returns the block header.
    pub fn into_header(self) -> header::Header {
        self.header
    }
}

impl<'c, T> fmt::Debug for HeaderInsert<'c, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("HeaderInsert").field(&self.header).finish()
    }
}

/// Error that can happen when verifying a block header.
#[derive(Debug, derive_more::Display)]
pub enum HeaderVerifyError {
    /// Error while decoding the header.
    InvalidHeader(header::Error),
    /// The parent of the block isn't known.
    #[display(fmt = "The parent of the block isn't known.")]
    BadParent {
        /// Hash of the parent block in question.
        parent_hash: [u8; 32],
    },
    /// The block verification has failed. The block is invalid and should be thrown away.
    VerificationFailed(verify::header_only::Error),
}

/// Returned by [`NonFinalizedTree::verify_justification`] on success.
///
/// As long as [`JustificationApply::apply`] isn't called, the underlying [`NonFinalizedTree`]
/// isn't modified.
#[must_use]
pub struct JustificationApply<'c, T> {
    chain: &'c mut NonFinalizedTree<T>,
    to_finalize: fork_tree::NodeIndex,
}

impl<'c, T> JustificationApply<'c, T> {
    /// Applies the justification, finalizing the given block.
    ///
    /// This function, including its return type, behaves in the same way as
    /// [`NonFinalizedTree::set_finalized_block`].
    pub fn apply(self) -> SetFinalizedBlockIter<'c, T> {
        self.chain.set_finalized_block_inner(self.to_finalize)
    }

    /// Returns the user data of the block about to be justified.
    pub fn block_user_data(&mut self) -> &mut T {
        &mut self
            .chain
            .blocks
            .get_mut(self.to_finalize)
            .unwrap()
            .user_data
    }

    /// Returns true if the block to be finalized is the current best block.
    pub fn is_current_best_block(&self) -> bool {
        Some(self.to_finalize) == self.chain.current_best
    }
}

impl<'c, T> fmt::Debug for JustificationApply<'c, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("JustificationApply").finish()
    }
}

/// Error that can happen when verifying a justification.
#[derive(Debug, derive_more::Display)]
pub enum JustificationVerifyError {
    /// Error while decoding the justification.
    InvalidJustification(justification::decode::Error),
    /// Justification targets a block that isn't in the chain.
    #[display(fmt = "Justification targets a block that isn't in the chain.")]
    UnknownTargetBlock {
        /// Number of the block that isn't in the chain.
        block_number: u64,
        /// Hash of the block that isn't in the chain.
        block_hash: [u8; 32],
    },
    /// There exists a block in-between the latest finalized block and the block targeted by the
    /// justification that must first be finalized.
    #[display(
        fmt = "There exists a block in-between the latest finalized block and the block \
                     targeted by the justification that must first be finalized"
    )]
    TooFarAhead {
        /// Number of the block contained in the justification.
        justification_block_number: u64,
        /// Hash of the block contained in the justification.
        justification_block_hash: [u8; 32],
        /// Number of the block to finalize first.
        block_to_finalize_number: u64,
        /// Hash of the block to finalize first.
        block_to_finalize_hash: [u8; 32],
    },
    /// The justification verification has failed. The justification is invalid and should be
    /// thrown away.
    VerificationFailed(justification::verify::Error),
}

/// Iterator producing the newly-finalized blocks removed from the state when the finalized block
/// is updated.
pub struct SetFinalizedBlockIter<'a, T> {
    iter: fork_tree::PruneAncestorsIter<'a, Block<T>>,
    current_best: &'a mut Option<fork_tree::NodeIndex>,
}

impl<'a, T> Iterator for SetFinalizedBlockIter<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let pruned = self.iter.next()?;
            if Some(pruned.index) == *self.current_best {
                *self.current_best = None;
            }
            if !pruned.is_prune_target_ancestor {
                continue;
            }
            break Some(pruned.user_data.user_data);
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a, T> Drop for SetFinalizedBlockIter<'a, T> {
    fn drop(&mut self) {
        // Make sure the iteration goes to the end.
        while let Some(_) = self.next() {}

        // TODO: update current_best with the new best block
    }
}

/// Error that can happen when setting the finalized block.
#[derive(Debug, derive_more::Display)]
pub enum SetFinalizedError {
    /// Block must have been passed to [`NonFinalizedTree::verify_header`] in the past.
    UnknownBlock,
}

/// Holds the [`NonFinalizedTree`] and allows insert a successfully-verified block into it.
#[must_use]
pub struct BodyInsert<T> {
    chain: NonFinalizedTree<T>,
    is_new_best: bool,
    /// Index of the parent in [`NonFinalizedTree::blocks`].
    parent_tree_index: Option<fork_tree::NodeIndex>,
    header: header::Header,
    hash: [u8; 32],
    consensus: BlockConsensus,
}

impl<T> BodyInsert<T> {
    /// Returns the header of the block about to be inserted.
    pub fn header(&self) -> header::HeaderRef {
        (&self.header).into()
    }

    /// Inserts the block with the given user data.
    pub fn insert(mut self, user_data: T) -> NonFinalizedTree<T> {
        let new_node_index = self.chain.blocks.insert(
            self.parent_tree_index,
            Block {
                header: self.header,
                hash: self.hash,
                consensus: self.consensus,
                user_data,
            },
        );

        if self.is_new_best {
            self.chain.current_best = Some(new_node_index);
        }

        self.chain
    }

    /// Destroys the object without inserting the block in the chain.
    pub fn abort(self) -> NonFinalizedTree<T> {
        self.chain
    }
}

impl<T> fmt::Debug for BodyInsert<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("BodyInsert").field(&self.header).finish()
    }
}

/// Access to a block's information and hierarchy.
pub struct BlockAccess<'a, T> {
    tree: &'a mut NonFinalizedTree<T>,
    node_index: fork_tree::NodeIndex,
}

impl<'a, T> BlockAccess<'a, T> {
    /// Access to the parent block's information and hierarchy. Returns an `Err` containing `self`
    /// if the parent is the finalized block.
    pub fn parent_block(self) -> Result<BlockAccess<'a, T>, BlockAccess<'a, T>> {
        let parent = self
            .tree
            .blocks
            .node_to_root_path(self.node_index)
            .skip(1)
            .next();

        let parent = match parent {
            Some(p) => p,
            None => return Err(self),
        };

        Ok(BlockAccess {
            tree: self.tree,
            node_index: parent,
        })
    }

    pub fn into_user_data(self) -> &'a mut T {
        &mut self.tree.blocks.get_mut(self.node_index).unwrap().user_data
    }

    pub fn user_data_mut(&mut self) -> &mut T {
        &mut self.tree.blocks.get_mut(self.node_index).unwrap().user_data
    }
}

/// Accepts as parameter a container of blocks and indices within this container.
///
/// Returns true if `maybe_new_best` on top of `maybe_new_best_parent` is a better block compared
/// to `old_best`.
fn is_better_block<T>(
    blocks: &fork_tree::ForkTree<Block<T>>,
    old_best: fork_tree::NodeIndex,
    maybe_new_best_parent: Option<fork_tree::NodeIndex>,
    maybe_new_best: header::HeaderRef,
) -> bool {
    debug_assert!(
        maybe_new_best_parent.map_or(true, |p_idx| blocks.get(p_idx).unwrap().hash
            == *maybe_new_best.parent_hash)
    );

    if maybe_new_best_parent.map_or(false, |p_idx| blocks.is_ancestor(old_best, p_idx)) {
        // A descendant is always preferred to its ancestor.
        true
    } else {
        // In order to determine whether the new block is our new best:
        //
        // - Find the common ancestor between the current best and the new block's parent.
        // - Count the number of Babe primary slot claims between the common ancestor and
        //   the current best.
        // - Count the number of Babe primary slot claims between the common ancestor and
        //   the new block's parent. Add one if the new block has a Babe primary slot
        //   claim.
        // - If the number for the new block is strictly superior, then the new block is
        //   out new best.
        //
        let (ascend, descend) = blocks.ascend_and_descend(old_best, maybe_new_best_parent.unwrap());

        // TODO: update for Aura?
        // TODO: what if there's a mix of Babe and non-Babe blocks here?

        let curr_best_primary_slots: usize = ascend
            .map(|i| {
                if blocks
                    .get(i)
                    .unwrap()
                    .header
                    .digest
                    .babe_pre_runtime()
                    .map_or(false, |pr| pr.is_primary())
                {
                    1
                } else {
                    0
                }
            })
            .sum();

        let new_block_primary_slots = {
            if maybe_new_best
                .digest
                .babe_pre_runtime()
                .map_or(false, |pr| pr.is_primary())
            {
                1
            } else {
                0
            }
        };

        let parent_primary_slots: usize = descend
            .map(|i| {
                if blocks
                    .get(i)
                    .unwrap()
                    .header
                    .digest
                    .babe_pre_runtime()
                    .map_or(false, |pr| pr.is_primary())
                {
                    1
                } else {
                    0
                }
            })
            .sum();

        // Note the strictly superior. If there is an equality, we keep the current best.
        parent_primary_slots + new_block_primary_slots > curr_best_primary_slots
    }
}
