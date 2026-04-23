// Smoldot
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
//! The latest finalized block is a block that is guaranteed to never be reverted. While it can
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
//! >           [`NonFinalizedTree`] itself cannot remove, not a block that cannot be removed in
//! >           the absolute.
//!
//! A block can be added to the chain by calling [`NonFinalizedTree::verify_header`] then
//! [`NonFinalizedTree::insert_verified_header`]. As explained in details in
//! [the `verify` module](crate::verify), verifying the header only verifies the authenticity of
//! a block and not its correctness. Additionally verifying the body of the block provides the
//! strongest guarantee, but is the responsibility of the API user and is out of the scope of
//! this module.
//!
//! > **Note**: There typically exists two kinds of clients: full and light. Full clients store
//! >           the state of the storage, while light clients don't. For this reason, light
//! >           clients can only verify the header of new blocks. Both full and light clients
//! >           should wait for a block to be finalized if they want to be certain that it will
//! >           forever remain part of the chain.
//!
//! Additionally, a [`NonFinalizedTree::verify_justification`] method is provided in order to
//! verify the correctness of a [justification](crate::finality).

// TODO: expand this doc ^

use crate::{
    chain::{chain_information, fork_tree},
    header,
};

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    sync::Arc,
    vec::Vec,
};
use core::{cmp, fmt, mem, num::NonZero, ops, time::Duration};
use hashbrown::HashMap;

mod finality;
mod tests;
mod verify;

pub use self::finality::*;
pub use self::verify::*;

/// Configuration for the [`NonFinalizedTree`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Information about the latest finalized block and its ancestors.
    pub chain_information: chain_information::ValidChainInformation,

    /// Number of bytes used when encoding/decoding the block number. Influences how various data
    /// structures should be parsed.
    pub block_number_bytes: usize,

    /// Pre-allocated size of the chain, in number of non-finalized blocks.
    pub blocks_capacity: usize,

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
}

/// Holds state about the current state of the chain for the purpose of verifying headers.
pub struct NonFinalizedTree<T> {
    /// Header of the highest known finalized block.
    ///
    /// Guaranteed to be valid.
    finalized_block_header: Vec<u8>,
    /// Hash of [`NonFinalizedTree::finalized_block_header`].
    finalized_block_hash: [u8; 32],
    /// Number of [`NonFinalizedTree::finalized_block_header`].
    finalized_block_number: u64,
    /// State of the chain finality engine.
    finality: Finality,
    /// State of the consensus of the finalized block.
    finalized_consensus: FinalizedConsensus,
    /// Best score of the finalized block.
    finalized_best_score: BestScore,

    /// Container for non-finalized blocks.
    blocks: fork_tree::ForkTree<Block<T>>,
    /// Counter increased by 1 every time a block is inserted in the collection. This value is used
    /// in order to guarantee that blocks inserted before are always considered as better than
    /// blocks inserted later.
    /// We use a `u128` rather than a `u64`. While it is unlikely that `2^64` blocks ever get
    /// inserted into the collection, the fact that the block number is a `u64`, and that there
    /// are potentially more than one block per height, means that a `u64` here is technically
    /// too small.
    blocks_insertion_counter: u128,
    /// For each block hash, the index of this block in [`NonFinalizedTree::blocks`].
    /// Must always have the same number of entries as [`NonFinalizedTree::blocks`].
    blocks_by_hash: HashMap<[u8; 32], fork_tree::NodeIndex, fnv::FnvBuildHasher>,
    /// Blocks indexed by the value in [`Block::best_score`]. The best block is the one with the
    /// highest score.
    blocks_by_best_score: BTreeMap<BestScore, fork_tree::NodeIndex>,
    /// Subset of [`NonFinalizedTree::blocks`] whose [`BlockFinality::Grandpa::triggers_change`]
    /// is `true`, indexed by the value in
    /// [`BlockFinality::Grandpa::prev_auth_change_trigger_number`].
    blocks_trigger_gp_change: BTreeSet<(Option<u64>, fork_tree::NodeIndex)>,
    /// See [`Config::block_number_bytes`].
    block_number_bytes: usize,
    /// See [`Config::allow_unknown_consensus_engines`].
    allow_unknown_consensus_engines: bool,
}

impl<T> NonFinalizedTree<T> {
    /// Initializes a new queue.
    ///
    /// # Panic
    ///
    /// Panics if the chain information is incorrect.
    ///
    pub fn new(config: Config) -> Self {
        let chain_information: chain_information::ChainInformation =
            config.chain_information.into();

        NonFinalizedTree {
            finalized_block_number: chain_information.finalized_block_header.number,
            finalized_block_hash: chain_information
                .finalized_block_header
                .hash(config.block_number_bytes),
            finalized_block_header: chain_information
                .finalized_block_header
                .scale_encoding_vec(config.block_number_bytes),
            finality: match chain_information.finality {
                chain_information::ChainInformationFinality::Outsourced => Finality::Outsourced,
                chain_information::ChainInformationFinality::Grandpa {
                    after_finalized_block_authorities_set_id,
                    finalized_scheduled_change,
                    finalized_triggered_authorities,
                } => Finality::Grandpa {
                    after_finalized_block_authorities_set_id,
                    finalized_scheduled_change: finalized_scheduled_change
                        .map(|(n, l)| (n, l.into_iter().collect())),
                    finalized_triggered_authorities: finalized_triggered_authorities
                        .into_iter()
                        .collect(),
                },
            },
            finalized_consensus: match chain_information.consensus {
                chain_information::ChainInformationConsensus::Unknown => {
                    FinalizedConsensus::Unknown
                }
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
                    block_epoch_information: finalized_block_epoch_information.map(Arc::from),
                    next_epoch_transition: Arc::from(finalized_next_epoch_transition),
                },
            },
            finalized_best_score: BestScore {
                num_primary_slots: 0,
                num_secondary_slots: 0,
                insertion_counter: 0,
            },
            blocks: fork_tree::ForkTree::with_capacity(config.blocks_capacity),
            blocks_insertion_counter: 1,
            blocks_by_hash: hashbrown::HashMap::with_capacity_and_hasher(
                config.blocks_capacity,
                Default::default(),
            ),
            blocks_by_best_score: BTreeMap::new(),
            blocks_trigger_gp_change: BTreeSet::new(),
            block_number_bytes: config.block_number_bytes,
            allow_unknown_consensus_engines: config.allow_unknown_consensus_engines,
        }
    }

    /// Removes all non-finalized blocks from the tree.
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.blocks_by_hash.clear();
        self.blocks_by_best_score.clear();
        self.blocks_trigger_gp_change.clear();
    }

    /// Updates the consensus algorithm of the finalized block.
    ///
    /// This is useful when the chain starts with `Unknown` consensus and later
    /// discovers the actual consensus parameters (e.g. Aura authorities).
    ///
    /// Non-finalized blocks that were verified under the old consensus are cleared,
    /// as they may have been verified with incorrect rules.
    pub fn set_finalized_consensus(
        &mut self,
        consensus: chain_information::ChainInformationConsensus,
    ) {
        self.finalized_consensus = match consensus {
            chain_information::ChainInformationConsensus::Unknown => FinalizedConsensus::Unknown,
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
                block_epoch_information: finalized_block_epoch_information.map(Arc::from),
                next_epoch_transition: Arc::from(finalized_next_epoch_transition),
            },
        };
        self.clear();
    }

    /// Returns true if there isn't any non-finalized block in the chain.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Returns the number of non-finalized blocks in the chain.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the header of all known non-finalized blocks in the chain without any specific
    /// order.
    pub fn iter_unordered(&'_ self) -> impl Iterator<Item = header::HeaderRef<'_>> {
        self.blocks
            .iter_unordered()
            .map(move |(_, b)| header::decode(&b.header, self.block_number_bytes).unwrap())
    }

    /// Returns the header of all known non-finalized blocks in the chain.
    ///
    /// The returned items are guaranteed to be in an order in which the parents are found before
    /// their children.
    pub fn iter_ancestry_order(&'_ self) -> impl Iterator<Item = header::HeaderRef<'_>> {
        self.blocks
            .iter_ancestry_order()
            .map(move |(_, b)| header::decode(&b.header, self.block_number_bytes).unwrap())
    }

    /// Reserves additional capacity for at least `additional` new blocks without allocating.
    pub fn reserve(&mut self, additional: usize) {
        self.blocks_by_hash.reserve(additional);
        self.blocks.reserve(additional);
    }

    /// Shrink the capacity of the chain as much as possible.
    pub fn shrink_to_fit(&mut self) {
        self.blocks_by_hash.shrink_to_fit();
        self.blocks.shrink_to_fit();
    }

    /// Returns the value that was initially passed in [`Config::block_number_bytes`].
    pub fn block_number_bytes(&self) -> usize {
        self.block_number_bytes
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct that might later be used to
    /// build a new [`NonFinalizedTree`].
    pub fn as_chain_information(&'_ self) -> chain_information::ValidChainInformationRef<'_> {
        let attempt = chain_information::ChainInformationRef {
            finalized_block_header: header::decode(
                &self.finalized_block_header,
                self.block_number_bytes,
            )
            .unwrap(),
            consensus: match &self.finalized_consensus {
                FinalizedConsensus::Unknown => {
                    chain_information::ChainInformationConsensusRef::Unknown
                }
                FinalizedConsensus::Aura {
                    authorities_list,
                    slot_duration,
                } => chain_information::ChainInformationConsensusRef::Aura {
                    finalized_authorities_list: header::AuraAuthoritiesIter::from_slice(
                        authorities_list,
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
            finality: match &self.finality {
                Finality::Outsourced => chain_information::ChainInformationFinalityRef::Outsourced,
                Finality::Grandpa {
                    after_finalized_block_authorities_set_id,
                    finalized_triggered_authorities,
                    finalized_scheduled_change,
                } => chain_information::ChainInformationFinalityRef::Grandpa {
                    after_finalized_block_authorities_set_id:
                        *after_finalized_block_authorities_set_id,
                    finalized_scheduled_change: finalized_scheduled_change
                        .as_ref()
                        .map(|(n, l)| (*n, &l[..])),
                    finalized_triggered_authorities,
                },
            },
        };

        chain_information::ValidChainInformationRef::try_from(attempt).unwrap()
    }

    /// Returns the header of the latest finalized block.
    pub fn finalized_block_header(&self) -> &[u8] {
        &self.finalized_block_header
    }

    /// Returns the hash of the latest finalized block.
    pub fn finalized_block_hash(&self) -> &[u8; 32] {
        &self.finalized_block_hash
    }

    /// Returns the height of the latest finalized block.
    pub fn finalized_block_height(&self) -> u64 {
        self.finalized_block_number
    }

    /// Returns the header of the best block.
    pub fn best_block_header(&self) -> &[u8] {
        if let Some((_, index)) = self.blocks_by_best_score.last_key_value() {
            &self.blocks.get(*index).unwrap().header
        } else {
            &self.finalized_block_header
        }
    }

    /// Returns the hash of the best block.
    pub fn best_block_hash(&self) -> &[u8; 32] {
        if let Some((_, index)) = self.blocks_by_best_score.last_key_value() {
            &self.blocks.get(*index).unwrap().hash
        } else {
            &self.finalized_block_hash
        }
    }

    /// Returns the height of the best block.
    pub fn best_block_height(&self) -> u64 {
        if let Some((_, index)) = self.blocks_by_best_score.last_key_value() {
            self.blocks.get(*index).unwrap().number
        } else {
            self.finalized_block_number
        }
    }

    /// Returns consensus information about the current best block of the chain.
    pub fn best_block_consensus(&'_ self) -> chain_information::ChainInformationConsensusRef<'_> {
        match (
            &self.finalized_consensus,
            self.blocks_by_best_score
                .last_key_value()
                .map(|(_, idx)| &self.blocks.get(*idx).unwrap().consensus),
        ) {
            (FinalizedConsensus::Unknown, _) => {
                chain_information::ChainInformationConsensusRef::Unknown
            }
            (
                FinalizedConsensus::Aura {
                    authorities_list,
                    slot_duration,
                },
                None,
            )
            | (
                FinalizedConsensus::Aura { slot_duration, .. },
                Some(BlockConsensus::Aura { authorities_list }),
            ) => chain_information::ChainInformationConsensusRef::Aura {
                finalized_authorities_list: header::AuraAuthoritiesIter::from_slice(
                    authorities_list,
                ),
                slot_duration: *slot_duration,
            },
            (
                FinalizedConsensus::Babe {
                    block_epoch_information,
                    next_epoch_transition,
                    slots_per_epoch,
                },
                None,
            ) => chain_information::ChainInformationConsensusRef::Babe {
                slots_per_epoch: *slots_per_epoch,
                finalized_block_epoch_information: block_epoch_information
                    .as_ref()
                    .map(|info| From::from(&**info)),
                finalized_next_epoch_transition: next_epoch_transition.as_ref().into(),
            },
            (
                FinalizedConsensus::Babe {
                    slots_per_epoch, ..
                },
                Some(BlockConsensus::Babe {
                    current_epoch,
                    next_epoch,
                }),
            ) => chain_information::ChainInformationConsensusRef::Babe {
                slots_per_epoch: *slots_per_epoch,
                finalized_block_epoch_information: current_epoch
                    .as_ref()
                    .map(|info| From::from(&**info)),
                finalized_next_epoch_transition: next_epoch.as_ref().into(),
            },

            // Any mismatch of consensus engine between the finalized and best block is not
            // supported at the moment.
            _ => unreachable!(),
        }
    }

    /// Returns true if the block with the given hash is in the [`NonFinalizedTree`].
    pub fn contains_non_finalized_block(&self, hash: &[u8; 32]) -> bool {
        self.blocks_by_hash.contains_key(hash)
    }

    /// Gives access to the user data of a block stored by the [`NonFinalizedTree`], identified
    /// by its hash.
    ///
    /// Returns `None` if the block can't be found.
    pub fn non_finalized_block_user_data(&self, hash: &[u8; 32]) -> Option<&T> {
        let node_index = *self.blocks_by_hash.get(hash)?;
        Some(&self.blocks.get(node_index).unwrap().user_data)
    }

    /// Gives access to the user data of a block stored by the [`NonFinalizedTree`], identified
    /// by its hash.
    ///
    /// Returns `None` if the block can't be found.
    pub fn non_finalized_block_user_data_mut(&mut self, hash: &[u8; 32]) -> Option<&mut T> {
        let node_index = *self.blocks_by_hash.get(hash)?;
        Some(&mut self.blocks.get_mut(node_index).unwrap().user_data)
    }

    /// Returns the SCALE-encoded header of a block stored by the [`NonFinalizedTree`], identified
    /// by its hash.
    ///
    /// Returns `None` if the block can't be found.
    pub fn non_finalized_block_header(&self, hash: &[u8; 32]) -> Option<&[u8]> {
        let node_index = *self.blocks_by_hash.get(hash)?;
        Some(&self.blocks.get(node_index).unwrap().header)
    }
}

impl<T> fmt::Debug for NonFinalizedTree<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct Blocks<'a, T>(&'a NonFinalizedTree<T>);
        impl<'a, T> fmt::Debug for Blocks<'a, T>
        where
            T: fmt::Debug,
        {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_map()
                    .entries(
                        self.0
                            .blocks
                            .iter_unordered()
                            .map(|(_, v)| (format!("0x{}", hex::encode(v.hash)), &v.user_data)),
                    )
                    .finish()
            }
        }

        f.debug_struct("NonFinalizedTree")
            .field(
                "finalized_block_hash",
                &format!(
                    "0x{}",
                    hex::encode(header::hash_from_scale_encoded_header(
                        &self.finalized_block_header
                    ))
                ),
            )
            .field("non_finalized_blocks", &Blocks(self))
            .finish()
    }
}

impl<'a, T> ops::Index<&'a [u8; 32]> for NonFinalizedTree<T> {
    type Output = T;

    #[track_caller]
    fn index(&self, block_hash: &'a [u8; 32]) -> &T {
        let node_index = self
            .blocks_by_hash
            .get(block_hash)
            .unwrap_or_else(|| panic!("invalid block hash"));
        &self
            .blocks
            .get(*node_index)
            .unwrap_or_else(|| unreachable!())
            .user_data
    }
}

impl<'a, T> ops::IndexMut<&'a [u8; 32]> for NonFinalizedTree<T> {
    #[track_caller]
    fn index_mut(&mut self, block_hash: &'a [u8; 32]) -> &mut T {
        let node_index = self
            .blocks_by_hash
            .get(block_hash)
            .unwrap_or_else(|| panic!("invalid block hash"));
        &mut self
            .blocks
            .get_mut(*node_index)
            .unwrap_or_else(|| unreachable!())
            .user_data
    }
}

/// State of the consensus of the finalized block.
#[derive(Clone)]
enum FinalizedConsensus {
    Unknown,
    Aura {
        /// List of authorities that must sign the child of the finalized block.
        authorities_list: Arc<Vec<header::AuraAuthority>>,

        /// Duration, in milliseconds, of a slot.
        slot_duration: NonZero<u64>,
    },
    Babe {
        /// See [`chain_information::ChainInformationConsensus::Babe::finalized_block_epoch_information`].
        block_epoch_information: Option<Arc<chain_information::BabeEpochInformation>>,

        /// See [`chain_information::ChainInformationConsensus::Babe::finalized_next_epoch_transition`].
        next_epoch_transition: Arc<chain_information::BabeEpochInformation>,

        /// See [`chain_information::ChainInformationConsensus::Babe::slots_per_epoch`].
        slots_per_epoch: NonZero<u64>,
    },
}

/// State of the chain finality engine.
#[derive(Clone)]
enum Finality {
    Outsourced,
    Grandpa {
        /// Grandpa authorities set ID of the block right after the finalized block.
        after_finalized_block_authorities_set_id: u64,

        /// List of GrandPa authorities that need to finalize the block right after the finalized
        /// block.
        finalized_triggered_authorities: Arc<[header::GrandpaAuthority]>,

        /// Change in the GrandPa authorities list that has been scheduled by a block that is already
        /// finalized but not triggered yet. These changes will for sure happen. Contains the block
        /// number where the changes are to be triggered. The descendants of the block with that
        /// number need to be finalized with the new authorities.
        finalized_scheduled_change: Option<(u64, Arc<[header::GrandpaAuthority]>)>,
    },
}

struct Block<T> {
    /// Header of the block.
    ///
    /// Guaranteed to be valid.
    header: Vec<u8>,
    /// Cache of the hash of the block. Always equal to the hash of the header stored in this
    /// same struct.
    hash: [u8; 32],
    /// Number contained in [`Block::header`].
    number: u64,
    /// Changes to the consensus made by the block.
    consensus: BlockConsensus,
    /// Information about finality attached to each block.
    finality: BlockFinality,
    /// Score of the block when it comes to determining which block is the best in the chain.
    best_score: BestScore,
    /// Opaque data decided by the user.
    user_data: T,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct BestScore {
    num_primary_slots: u64,
    num_secondary_slots: u64,
    insertion_counter: u128,
}

impl cmp::PartialOrd for BestScore {
    fn partial_cmp(&self, other: &BestScore) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::Ord for BestScore {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.num_primary_slots.cmp(&other.num_primary_slots) {
            cmp::Ordering::Equal => {
                match self.num_secondary_slots.cmp(&other.num_secondary_slots) {
                    cmp::Ordering::Equal => {
                        // Note the inversion.
                        other.insertion_counter.cmp(&self.insertion_counter)
                    }
                    other => other,
                }
            }
            other => other,
        }
    }
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

/// Information about finality attached to each block.
#[derive(Clone)]
enum BlockFinality {
    Outsourced,
    Grandpa {
        /// If a block A triggers a change in the list of Grandpa authorities, and a block B is
        /// a descendant of A, then B cannot be finalized before A is.
        /// This field contains the height of A, if it is known. Contains `None` if A is the
        /// current finalized block or below, and thus doesn't matter anyway.
        ///
        /// If `Some`, the value must always be strictly inferior to the attached block's number.
        prev_auth_change_trigger_number: Option<u64>,

        /// Authorities set id that must be used to finalize the blocks that descend from this
        /// one.
        ///
        /// If `triggers_change` is `false`, then this field must be equal to the parent block's.
        after_block_authorities_set_id: u64,

        /// `true` if this block triggers a change in the list of Grandpa authorities.
        triggers_change: bool,

        /// List of GrandPa authorities that need to finalize the block right after this block.
        ///
        /// If `triggers_change` is `false`, then this field must be equal to the parent block's.
        triggered_authorities: Arc<[header::GrandpaAuthority]>,

        /// A change in the GrandPa authorities list that has been scheduled for the block with the
        /// given number that descends from this one. The block with that number will trigger the
        /// new authorities, meaning that its descendants will need to be finalized with the new
        /// authorities.
        ///
        /// If `Some`, the value must always be strictly superior to the attached block's number.
        scheduled_change: Option<(u64, Arc<[header::GrandpaAuthority]>)>,
    },
}
