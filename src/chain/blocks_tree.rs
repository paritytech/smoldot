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
    header,
};

use alloc::{boxed::Box, format, sync::Arc, vec::Vec};
use core::{cmp, fmt, mem, num::NonZeroU64, time::Duration};
use hashbrown::HashMap;

mod best_block;
mod finality;
mod verify;

pub use self::finality::*;
pub use self::verify::*;

/// Configuration for the [`NonFinalizedTree`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Information about the latest finalized block and its ancestors.
    pub chain_information: chain_information::ValidChainInformation,

    /// Pre-allocated size of the chain, in number of non-finalized blocks.
    pub blocks_capacity: usize,

    /// If `false`, blocks containing digest items with an unknown consensus engine will fail to
    /// verify.
    ///
    /// Passing `true` can lead to blocks being considered as valid when they shouldn't. However,
    /// even if `true` is passed, a recognized consensus engine must always be present.
    /// Consequently, both `true` and `false` guarantee that the number of authorable blocks over
    /// the network is bounded.
    pub allow_unknown_consensus_engines: bool,
}

/// Holds state about the current state of the chain for the purpose of verifying headers.
pub struct NonFinalizedTree<T> {
    /// All fields are wrapped into an `Option` in order to be able to extract the
    /// [`NonFinalizedTree`] and later put it back.
    ///
    /// A `Box` is used in order to minimize the impact of moving the value around, and to reduce
    /// the size of the [`NonFinalizedTree`].
    inner: Option<Box<NonFinalizedTreeInner<T>>>,
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

        let finalized_block_hash = chain_information.finalized_block_header.hash();

        NonFinalizedTree {
            inner: Some(Box::new(NonFinalizedTreeInner {
                finalized_block_header: chain_information.finalized_block_header,
                finalized_block_hash,
                finality: match chain_information.finality {
                    chain_information::ChainInformationFinality::Outsourced => Finality::Outsourced,
                    chain_information::ChainInformationFinality::Grandpa {
                        after_finalized_block_authorities_set_id,
                        finalized_scheduled_change,
                        finalized_triggered_authorities,
                    } => Finality::Grandpa {
                        after_finalized_block_authorities_set_id,
                        finalized_scheduled_change,
                        finalized_triggered_authorities,
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
                        block_epoch_information: finalized_block_epoch_information.map(Arc::new),
                        next_epoch_transition: Arc::new(finalized_next_epoch_transition),
                    },
                },
                blocks: fork_tree::ForkTree::with_capacity(config.blocks_capacity),
                blocks_by_hash: hashbrown::HashMap::with_capacity_and_hasher(
                    config.blocks_capacity,
                    Default::default(),
                ),
                current_best: None,
                allow_unknown_consensus_engines: config.allow_unknown_consensus_engines,
            })),
        }
    }

    /// Removes all non-finalized blocks from the tree.
    pub fn clear(&mut self) {
        let mut inner = self.inner.as_mut().unwrap();
        inner.blocks.clear();
        inner.blocks_by_hash.clear();
        inner.current_best = None;
    }

    /// Returns true if there isn't any non-finalized block in the chain.
    pub fn is_empty(&self) -> bool {
        self.inner.as_ref().unwrap().blocks.is_empty()
    }

    /// Returns the number of non-finalized blocks in the chain.
    pub fn len(&self) -> usize {
        self.inner.as_ref().unwrap().blocks.len()
    }

    /// Returns the header of all known non-finalized blocks in the chain without any specific
    /// order.
    pub fn iter_unordered(&'_ self) -> impl Iterator<Item = header::HeaderRef<'_>> + '_ {
        self.inner
            .as_ref()
            .unwrap()
            .blocks
            .iter_unordered()
            .map(|(_, b)| (&b.header).into())
    }

    /// Returns the header of all known non-finalized blocks in the chain.
    ///
    /// The returned items are guaranteed to be in an order in which the parents are found before
    /// their children.
    pub fn iter_ancestry_order(&'_ self) -> impl Iterator<Item = header::HeaderRef<'_>> + '_ {
        self.inner
            .as_ref()
            .unwrap()
            .blocks
            .iter_ancestry_order()
            .map(|(_, b)| (&b.header).into())
    }

    /// Reserves additional capacity for at least `additional` new blocks without allocating.
    pub fn reserve(&mut self, additional: usize) {
        let inner = self.inner.as_mut().unwrap();
        inner.blocks_by_hash.reserve(additional);
        inner.blocks.reserve(additional);
    }

    /// Shrink the capacity of the chain as much as possible.
    pub fn shrink_to_fit(&mut self) {
        let inner = self.inner.as_mut().unwrap();
        inner.blocks_by_hash.shrink_to_fit();
        inner.blocks.shrink_to_fit();
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct that might later be used to
    /// build a new [`NonFinalizedTree`].
    pub fn as_chain_information(&self) -> chain_information::ValidChainInformationRef {
        let inner = self.inner.as_ref().unwrap();
        let attempt = chain_information::ChainInformationRef {
            finalized_block_header: (&inner.finalized_block_header).into(),
            consensus: match &inner.finalized_consensus {
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
            finality: match &inner.finality {
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
    pub fn finalized_block_header(&self) -> header::HeaderRef {
        (&self.inner.as_ref().unwrap().finalized_block_header).into()
    }

    /// Returns the hash of the latest finalized block.
    pub fn finalized_block_hash(&self) -> [u8; 32] {
        self.inner.as_ref().unwrap().finalized_block_hash
    }

    /// Returns the header of the best block.
    pub fn best_block_header(&self) -> header::HeaderRef {
        let inner = self.inner.as_ref().unwrap();
        if let Some(index) = inner.current_best {
            (&inner.blocks.get(index).unwrap().header).into()
        } else {
            (&inner.finalized_block_header).into()
        }
    }

    /// Returns the hash of the best block.
    pub fn best_block_hash(&self) -> [u8; 32] {
        let inner = self.inner.as_ref().unwrap();
        if let Some(index) = inner.current_best {
            inner.blocks.get(index).unwrap().hash
        } else {
            inner.finalized_block_hash
        }
    }

    /// Returns consensus information about the current best block of the chain.
    pub fn best_block_consensus(&self) -> chain_information::ChainInformationConsensusRef {
        let inner = self.inner.as_ref().unwrap();
        match (
            &inner.finalized_consensus,
            inner
                .current_best
                .map(|idx| &inner.blocks.get(idx).unwrap().consensus),
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
        self.inner
            .as_ref()
            .unwrap()
            .blocks_by_hash
            .contains_key(hash)
    }

    /// Gives access to the user data of a block stored by the [`NonFinalizedTree`], identified
    /// by its hash.
    ///
    /// Returns `None` if the block can't be found.
    pub fn non_finalized_block_user_data(&self, hash: &[u8; 32]) -> Option<&T> {
        let inner = self.inner.as_ref().unwrap();
        let node_index = *inner.blocks_by_hash.get(hash)?;
        Some(&inner.blocks.get(node_index).unwrap().user_data)
    }

    /// Gives access to a block stored by the [`NonFinalizedTree`], identified by its hash.
    pub fn non_finalized_block_by_hash(&mut self, hash: &[u8; 32]) -> Option<BlockAccess<T>> {
        let inner = self.inner.as_mut().unwrap();
        let node_index = *inner.blocks_by_hash.get(hash)?;
        Some(BlockAccess {
            tree: inner,
            node_index,
        })
    }
}

impl<T> fmt::Debug for NonFinalizedTree<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct Blocks<'a, T>(&'a Box<NonFinalizedTreeInner<T>>);
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
                            .map(|(_, v)| (format!("0x{}", hex::encode(&v.hash)), &v.user_data)),
                    )
                    .finish()
            }
        }

        let inner = self.inner.as_ref().unwrap();
        f.debug_struct("NonFinalizedTree")
            .field(
                "finalized_block_hash",
                &format!("0x{}", hex::encode(&inner.finalized_block_header.hash())),
            )
            .field("non_finalized_blocks", &Blocks(inner))
            .finish()
    }
}

/// See [`NonFinalizedTree::inner`].
struct NonFinalizedTreeInner<T> {
    /// Header of the highest known finalized block.
    finalized_block_header: header::Header,
    /// Hash of [`NonFinalizedTree::finalized_block_header`].
    finalized_block_hash: [u8; 32],
    /// State of the chain finality engine.
    finality: Finality,

    /// State of the consensus of the finalized block.
    finalized_consensus: FinalizedConsensus,

    /// Container for non-finalized blocks.
    blocks: fork_tree::ForkTree<Block<T>>,
    /// For each block hash, the index of this block in [`NonFinalizedTreeInner::blocks`].
    /// Must always have the same number of entries as [`NonFinalizedTreeInner::blocks`].
    blocks_by_hash: HashMap<[u8; 32], fork_tree::NodeIndex, fnv::FnvBuildHasher>,
    /// Index within [`NonFinalizedTreeInner::blocks`] of the current best block. `None` if and
    /// only if the fork tree is empty.
    current_best: Option<fork_tree::NodeIndex>,

    /// See [`Config::allow_unknown_consensus_engines`].
    allow_unknown_consensus_engines: bool,
}

/// State of the consensus of the finalized block.
#[derive(Clone)]
enum FinalizedConsensus {
    Unknown,
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

/// State of the chain finality engine.
#[derive(Clone)]
enum Finality {
    Outsourced,
    Grandpa {
        /// Grandpa authorities set ID of the block right after the finalized block.
        after_finalized_block_authorities_set_id: u64,
        /// List of GrandPa authorities that need to finalize the block right after the finalized
        /// block.
        finalized_triggered_authorities: Vec<header::GrandpaAuthority>,
        /// Change in the GrandPa authorities list that has been scheduled by a block that is already
        /// finalized but not triggered yet. These changes will for sure happen. Contains the block
        /// number where the changes are to be triggered.
        finalized_scheduled_change: Option<(u64, Vec<header::GrandpaAuthority>)>,
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

/// Access to a block's information and hierarchy.
pub struct BlockAccess<'a, T> {
    tree: &'a mut NonFinalizedTreeInner<T>,
    node_index: fork_tree::NodeIndex,
}

impl<'a, T> BlockAccess<'a, T> {
    /// Access to the parent block's information and hierarchy. Returns an `Err` containing `self`
    /// if the parent is the finalized block.
    pub fn parent_block(self) -> Result<BlockAccess<'a, T>, BlockAccess<'a, T>> {
        let parent = self.tree.blocks.node_to_root_path(self.node_index).nth(1);

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
