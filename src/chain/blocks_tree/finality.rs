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

//! Extension module containing the API and implementation of everything related to finality.

use super::*;
use crate::finality::{grandpa, justification};

use core::{cmp::Ordering, iter};

impl<T> NonFinalizedTree<T> {
    /// Returns a list of blocks (by their height and hash) that need to be finalized before any
    /// of their descendants can be finalized.
    ///
    /// In other words, blocks in the [`NonFinalizedTree`] can be immediately finalized by call
    /// to [`NonFinalizedTree::verify_justification`] or
    /// [`NonFinalizedTree::verify_grandpa_commit_message`], unless they descend from any of the
    /// blocks returned by this function, in which case that block must be finalized beforehand.
    pub fn finality_checkpoints(&self) -> impl Iterator<Item = (u64, &[u8; 32])> {
        let inner = self.inner.as_ref().unwrap();
        match &inner.finality {
            Finality::Outsourced => {
                // No checkpoint means all blocks allowed.
                either::Left(iter::empty())
            }
            Finality::Grandpa { .. } => {
                // TODO: O(n), could add a cache to make it O(1)
                let iter = inner
                    .blocks
                    .iter_unordered()
                    .filter(move |(_, block)| {
                        if let BlockFinality::Grandpa {
                            triggers_change, ..
                        } = &block.finality
                        {
                            *triggers_change
                        } else {
                            unreachable!()
                        }
                    })
                    .map(|(_, block)| (block.header.number, &block.hash));

                either::Right(iter)
            }
        }
    }

    /// Verifies the given justification.
    ///
    /// The verification is performed in the context of the chain. In particular, the
    /// verification will fail if the target block isn't already in the chain.
    ///
    /// If the verification succeeds, a [`FinalityApply`] object will be returned which can
    /// be used to apply the finalization.
    ///
    /// A randomness seed must be provided and will be used during the verification. Note that the
    /// verification is nonetheless deterministic.
    // TODO: expand the documentation about how blocks with authorities changes have to be finalized before any further block can be finalized
    pub fn verify_justification(
        &mut self,
        consensus_engine_id: [u8; 4],
        scale_encoded_justification: &[u8],
        randomness_seed: [u8; 32],
    ) -> Result<FinalityApply<T>, JustificationVerifyError> {
        self.inner.as_mut().unwrap().verify_justification(
            consensus_engine_id,
            scale_encoded_justification,
            randomness_seed,
        )
    }

    /// Verifies the given Grandpa commit message.
    ///
    /// The verification is performed in the context of the chain. In particular, the
    /// verification will fail if the target block isn't already in the chain or if one of the
    /// voted blocks is unknown locally.
    ///
    /// If the verification succeeds, a [`FinalityApply`] object will be returned which can
    /// be used to apply the finalization.
    ///
    /// A randomness seed must be provided and will be used during the verification. Note that the
    /// verification is nonetheless deterministic.
    pub fn verify_grandpa_commit_message(
        &mut self,
        scale_encoded_commit: &[u8],
        randomness_seed: [u8; 32],
    ) -> Result<FinalityApply<T>, CommitVerifyError> {
        self.inner
            .as_mut()
            .unwrap()
            .verify_grandpa_commit_message(scale_encoded_commit, randomness_seed)
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
    ///
    /// If necessary, the current best block will be updated to be a descendant of the
    /// newly-finalized block.
    // TODO: should return the pruned blocks as well
    pub fn set_finalized_block(
        &mut self,
        block_hash: &[u8; 32],
    ) -> Result<SetFinalizedBlockIter<T>, SetFinalizedError> {
        let inner = self.inner.as_mut().unwrap();

        let block_index = match inner.blocks_by_hash.get(block_hash) {
            Some(idx) => *idx,
            None => return Err(SetFinalizedError::UnknownBlock),
        };

        Ok(inner.set_finalized_block(block_index))
    }
}

impl<T> NonFinalizedTreeInner<T> {
    /// Common function for verifying GrandPa-finality-related messages.
    ///
    /// Returns the index of the possibly finalized block, the expected authorities set id, and
    /// an iterator to the list of authorities.
    ///
    /// # Panic
    ///
    /// Panics if the finality algorithm of the chain isn't Grandpa.
    ///
    fn verify_grandpa_finality(
        &'_ self,
        target_hash: &[u8; 32],
        target_number: u64,
    ) -> Result<
        (
            fork_tree::NodeIndex,
            u64,
            impl Iterator<Item = impl AsRef<[u8]> + '_> + Clone + '_,
        ),
        FinalityVerifyError,
    > {
        match &self.finality {
            Finality::Outsourced => panic!(),
            Finality::Grandpa {
                after_finalized_block_authorities_set_id,
                finalized_scheduled_change,
                finalized_triggered_authorities,
            } => {
                if target_number == self.finalized_block_header.number {
                    if *target_hash == self.finalized_block_hash {
                        return Err(FinalityVerifyError::EqualToFinalized);
                    }
                    return Err(FinalityVerifyError::EqualFinalizedHeightButInequalHash);
                } else if target_number < self.finalized_block_header.number {
                    return Err(FinalityVerifyError::BelowFinalized);
                }

                // Find in the list of non-finalized blocks the one targeted by the justification.
                let block_index = match self.blocks_by_hash.get(target_hash) {
                    Some(idx) => *idx,
                    None => {
                        return Err(FinalityVerifyError::UnknownTargetBlock {
                            block_number: target_number,
                            block_hash: *target_hash,
                        });
                    }
                };

                // If any block between the latest finalized one and the target block triggers any
                // GrandPa authorities change, then we need to finalize that triggering block
                // before finalizing the one targeted by the justification.
                if let BlockFinality::Grandpa {
                    ref prev_auth_change_trigger_number,
                    ..
                } = self.blocks.get(block_index).unwrap().finality
                {
                    if let Some(prev_auth_change_trigger_number) = prev_auth_change_trigger_number {
                        if *prev_auth_change_trigger_number > self.finalized_block_header.number {
                            return Err(FinalityVerifyError::TooFarAhead {
                                justification_block_number: target_number,
                                justification_block_hash: *target_hash,
                                block_to_finalize_number: *prev_auth_change_trigger_number,
                            });
                        }
                    }
                } else {
                    unreachable!()
                }

                // Find which authorities are supposed to finalize the target block.
                let authorities_list = finalized_scheduled_change
                    .as_ref()
                    .filter(|(trigger_height, _)| *trigger_height < target_number)
                    .map_or(finalized_triggered_authorities, |(_, list)| list);

                // As per above check, we know that the authorities of the target block are either
                // the same as the ones of the latest finalized block, or the ones contained in
                // the header of the latest finalized block.

                // First verification step complete.
                Ok((
                    block_index,
                    *after_finalized_block_authorities_set_id,
                    authorities_list.iter().map(|a| a.public_key),
                ))
            }
        }
    }

    /// See [`NonFinalizedTree::verify_justification`].
    fn verify_justification(
        &mut self,
        consensus_engine_id: [u8; 4],
        scale_encoded_justification: &[u8],
        randomness_seed: [u8; 32],
    ) -> Result<FinalityApply<T>, JustificationVerifyError> {
        match (&self.finality, &consensus_engine_id) {
            (Finality::Grandpa { .. }, b"FRNK") => {
                // Turn justification into a strongly-typed struct.
                let decoded = justification::decode::decode_grandpa(
                    scale_encoded_justification,
                    self.block_number_bytes,
                )
                .map_err(JustificationVerifyError::InvalidJustification)?;

                // Delegate the first step to the other function.
                let (block_index, authorities_set_id, authorities_list) = self
                    .verify_grandpa_finality(decoded.target_hash, decoded.target_number)
                    .map_err(JustificationVerifyError::FinalityVerify)?;

                justification::verify::verify(justification::verify::Config {
                    justification: decoded,
                    block_number_bytes: self.block_number_bytes,
                    authorities_set_id,
                    authorities_list,
                    randomness_seed,
                })
                .map_err(JustificationVerifyError::VerificationFailed)?;

                // Justification has been successfully verified!
                Ok(FinalityApply {
                    chain: self,
                    to_finalize: block_index,
                })
            }
            _ => Err(JustificationVerifyError::JustificationEngineMismatch),
        }
    }

    /// See [`NonFinalizedTree::verify_grandpa_commit_message`].
    fn verify_grandpa_commit_message(
        &mut self,
        verify_grandpa_commit_message: &[u8],
        randomness_seed: [u8; 32],
    ) -> Result<FinalityApply<T>, CommitVerifyError> {
        // The code below would panic if the chain doesn't use Grandpa.
        if !matches!(self.finality, Finality::Grandpa { .. }) {
            return Err(CommitVerifyError::NotGrandpa);
        }

        let decoded_commit = grandpa::commit::decode::decode_grandpa_commit(
            verify_grandpa_commit_message,
            self.block_number_bytes,
        )
        .map_err(|_| CommitVerifyError::InvalidCommit)?;

        // Delegate the first step to the other function.
        let (block_index, expected_authorities_set_id, authorities_list) = self
            .verify_grandpa_finality(
                decoded_commit.message.target_hash,
                decoded_commit.message.target_number,
            )
            .map_err(CommitVerifyError::FinalityVerify)?;

        let mut verification = grandpa::commit::verify::verify(grandpa::commit::verify::Config {
            commit: verify_grandpa_commit_message,
            block_number_bytes: self.block_number_bytes,
            expected_authorities_set_id,
            num_authorities: u32::try_from(authorities_list.clone().count()).unwrap(),
            randomness_seed,
        });

        loop {
            match verification {
                grandpa::commit::verify::InProgress::Finished(Ok(())) => {
                    drop(authorities_list);
                    return Ok(FinalityApply {
                        chain: self,
                        to_finalize: block_index,
                    });
                }
                grandpa::commit::verify::InProgress::FinishedUnknown => {
                    return Err(CommitVerifyError::NotEnoughKnownBlocks {
                        target_block_number: decoded_commit.message.target_number,
                    })
                }
                grandpa::commit::verify::InProgress::Finished(Err(error)) => {
                    return Err(CommitVerifyError::VerificationFailed(error))
                }
                grandpa::commit::verify::InProgress::IsAuthority(is_authority) => {
                    let to_find = is_authority.authority_public_key();
                    let result = authorities_list.clone().any(|a| a.as_ref() == to_find);
                    verification = is_authority.resume(result);
                }
                grandpa::commit::verify::InProgress::IsParent(is_parent) => {
                    // Find in the list of non-finalized blocks the target of the check.
                    match self.blocks_by_hash.get(is_parent.block_hash()) {
                        Some(idx) => {
                            let result = self.blocks.is_ancestor(block_index, *idx);
                            verification = is_parent.resume(Some(result));
                        }
                        None => {
                            verification = is_parent.resume(None);
                        }
                    };
                }
            }
        }
    }

    /// Implementation of [`NonFinalizedTree::set_finalized_block`].
    ///
    /// # Panic
    ///
    /// Panics if `block_index_to_finalize` isn't a valid node in the tree.
    ///
    fn set_finalized_block(
        &mut self,
        block_index_to_finalize: fork_tree::NodeIndex,
    ) -> SetFinalizedBlockIter<T> {
        let new_finalized_block = self.blocks.get_mut(block_index_to_finalize).unwrap();

        // Update `self.finality`.
        match (&mut self.finality, &new_finalized_block.finality) {
            (Finality::Outsourced, BlockFinality::Outsourced) => {}
            (
                Finality::Grandpa {
                    after_finalized_block_authorities_set_id,
                    finalized_scheduled_change,
                    finalized_triggered_authorities,
                },
                BlockFinality::Grandpa {
                    after_block_authorities_set_id,
                    triggered_authorities,
                    scheduled_change,
                    ..
                },
            ) => {
                // Some sanity checks.
                debug_assert!(
                    *after_finalized_block_authorities_set_id <= *after_block_authorities_set_id
                );
                debug_assert!(scheduled_change
                    .as_ref()
                    .map(|(n, _)| *n > new_finalized_block.header.number)
                    .unwrap_or(true));

                *after_finalized_block_authorities_set_id = *after_block_authorities_set_id;
                *finalized_triggered_authorities = triggered_authorities.clone();
                *finalized_scheduled_change = scheduled_change.clone();
            }

            // Mismatch between chain finality algorithm and block finality algorithm. Should never
            // happen.
            _ => unreachable!(),
        }

        // If the best block isn't a descendant of the block being finalized, then the best
        // block has to change to a different block.
        //
        // The definition of which block is the best can vary between nodes, but because there is
        // an intentional delay between a block being created and it being finalized, the block
        // being finalized is, under normal circumstances, always a common ancestor of the current
        // best block of all nodes.
        //
        // The situation where this isn't the case is therefore very uncommon: typically after a
        // netsplit (where not all nodes are aware of all blocks), or in extremely unlucky
        // situations.
        //
        // Because this is very uncommon, searching for the new best block is implemented in a
        // naive way, by scanning through each block one by one. This means that, when two blocks
        // are equal to become the new best, it is not necessarily the earliest received block that
        // is picked, contrary to the definition of "best block". But again, considering that this
        // situation is so uncommon, it doesn't really matter.
        debug_assert!(self.current_best.is_some()); // Can only be `None` if the tree is empty.
        let updates_best_block = if block_index_to_finalize == self.current_best.unwrap()
            || !self
                .blocks
                .is_ancestor(block_index_to_finalize, self.current_best.unwrap())
        {
            let mut new_best_block = None;
            for (idx, block) in self.blocks.iter_unordered() {
                if idx == block_index_to_finalize
                    || !self.blocks.is_ancestor(block_index_to_finalize, idx)
                {
                    continue;
                }

                let replace = if let Some(new_best_block) = new_best_block {
                    best_block::is_better_block(
                        &self.blocks,
                        new_best_block,
                        self.blocks.parent(idx),
                        From::from(&block.header),
                    ) == Ordering::Greater
                } else {
                    true
                };

                if replace {
                    new_best_block = Some(idx);
                }
            }

            debug_assert_ne!(self.current_best, new_best_block);
            self.current_best = new_best_block;
            true
        } else {
            false
        };

        let new_finalized_block = self.blocks.get_mut(block_index_to_finalize).unwrap();

        // Update `self.finalized_consensus`.
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

        // Update `self.finalized_block_header` and `self.finalized_block_hash`.
        mem::swap(
            &mut self.finalized_block_header,
            &mut new_finalized_block.header,
        );
        self.finalized_block_hash = self.finalized_block_header.hash(self.block_number_bytes);

        debug_assert_eq!(self.blocks.len(), self.blocks_by_hash.len());
        SetFinalizedBlockIter {
            iter: self.blocks.prune_ancestors(block_index_to_finalize),
            blocks_by_hash: &mut self.blocks_by_hash,
            updates_best_block,
        }
    }
}

/// Returned by [`NonFinalizedTree::verify_justification`] and
/// [`NonFinalizedTree::verify_grandpa_commit_message`] on success.
///
/// As long as [`FinalityApply::apply`] isn't called, the underlying [`NonFinalizedTree`]
/// isn't modified.
#[must_use]
pub struct FinalityApply<'c, T> {
    chain: &'c mut NonFinalizedTreeInner<T>,
    to_finalize: fork_tree::NodeIndex,
}

impl<'c, T> FinalityApply<'c, T> {
    /// Applies the justification, finalizing the given block.
    ///
    /// This function, including its return type, behaves in the same way as
    /// [`NonFinalizedTree::set_finalized_block`].
    pub fn apply(self) -> SetFinalizedBlockIter<'c, T> {
        self.chain.set_finalized_block(self.to_finalize)
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

impl<'c, T> fmt::Debug for FinalityApply<'c, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("FinalityApply").finish()
    }
}

/// Error that can happen when verifying a justification.
#[derive(Debug, derive_more::Display)]
pub enum JustificationVerifyError {
    /// Type of the justification doesn't match the finality mechanism used by the chain.
    ///
    /// > **Note**: If the chain's finality mechanism doesn't use justifications, this error is
    /// >           always returned.
    JustificationEngineMismatch,
    /// Error while decoding the justification.
    #[display(fmt = "Error while decoding the justification: {}", _0)]
    InvalidJustification(justification::decode::Error),
    /// The justification verification has failed. The justification is invalid and should be
    /// thrown away.
    #[display(fmt = "{}", _0)]
    VerificationFailed(justification::verify::Error),
    /// Error while verifying the finality in the context of the chain.
    #[display(fmt = "{}", _0)]
    FinalityVerify(FinalityVerifyError),
}

/// Error that can happen when verifying a Grandpa commit.
#[derive(Debug, derive_more::Display)]
pub enum CommitVerifyError {
    /// Chain doesn't use the GrandPa algorithm.
    NotGrandpa,
    /// Error while decoding the commit.
    InvalidCommit,
    /// Error while verifying the finality in the context of the chain.
    #[display(fmt = "{}", _0)]
    FinalityVerify(FinalityVerifyError),
    /// Not enough blocks are known by the tree to verify this commit.
    ///
    /// This doesn't mean that the commit is bad, but that it can't be verified without adding
    /// more blocks to the tree.
    #[display(fmt = "Not enough blocks are known to verify this commit")]
    NotEnoughKnownBlocks {
        /// Block number that the commit targets.
        target_block_number: u64,
    },
    /// The commit verification has failed. The commit is invalid and should be thrown away.
    #[display(fmt = "{}", _0)]
    VerificationFailed(grandpa::commit::verify::Error),
}

/// Error that can happen when verifying a proof of finality.
#[derive(Debug, derive_more::Display)]
pub enum FinalityVerifyError {
    /// The target block height and hash are the same as the block that is already finalized.
    /// While the proof couldn't be verified, nothing could be gained from actually verifying it.
    EqualToFinalized,
    /// The target block height is the same as the finalized block, but its hash is different.
    /// This means that the proof can't possibly be correct.
    EqualFinalizedHeightButInequalHash,
    /// The target block height is strictly inferior to the finalized block height.
    BelowFinalized,
    /// Finality proof targets a block that isn't in the chain.
    #[display(
        fmt = "Justification targets a block (#{}) that isn't in the chain.",
        block_number
    )]
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
    },
}

/// Iterator producing the newly-finalized blocks removed from the state when the finalized block
/// is updated.
pub struct SetFinalizedBlockIter<'a, T> {
    iter: fork_tree::PruneAncestorsIter<'a, Block<T>>,
    blocks_by_hash: &'a mut HashMap<[u8; 32], fork_tree::NodeIndex, fnv::FnvBuildHasher>,
    updates_best_block: bool,
}

impl<'a, T> SetFinalizedBlockIter<'a, T> {
    /// Returns true if the finalization process modifies the best block of the chain.
    pub fn updates_best_block(&self) -> bool {
        self.updates_best_block
    }
}

impl<'a, T> Iterator for SetFinalizedBlockIter<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let pruned = self.iter.next()?;
            let _removed = self.blocks_by_hash.remove(&pruned.user_data.hash);
            debug_assert_eq!(_removed, Some(pruned.index));
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
        for _ in self {}
    }
}

/// Error that can happen when setting the finalized block.
#[derive(Debug, derive_more::Display)]
pub enum SetFinalizedError {
    /// Block must have been passed to [`NonFinalizedTree::verify_header`] in the past.
    UnknownBlock,
}
