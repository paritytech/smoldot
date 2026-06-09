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
use crate::finality::{decode, verify};

use core::cmp;

impl<T> NonFinalizedTree<T> {
    /// Returns a list of blocks (by their height and hash) that need to be finalized before any
    /// of their descendants can be finalized.
    ///
    /// In other words, blocks in the [`NonFinalizedTree`] can be immediately finalized by call
    /// to [`NonFinalizedTree::verify_justification`] or
    /// [`NonFinalizedTree::verify_grandpa_commit_message`], unless they descend from any of the
    /// blocks returned by this function, in which case that block must be finalized beforehand.
    pub fn finality_checkpoints(&self) -> impl Iterator<Item = (u64, &[u8; 32])> {
        // Note that the code below assumes that GrandPa is the only finality algorithm currently
        // supported.
        debug_assert!(
            self.blocks_trigger_gp_change.is_empty()
                || !matches!(self.finality, Finality::Outsourced)
        );

        // Yield every pending set-change block. The first tuple field holds the previous set-change
        // block that must finalize first; `None` means there is none, so this block is
        // first in line.
        self.blocks_trigger_gp_change.iter().map(
            |(_prev_auth_change_trigger_number, block_index)| {
                let block = self
                    .blocks
                    .get(*block_index)
                    .unwrap_or_else(|| unreachable!());
                (block.number, &block.hash)
            },
        )
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
        &'_ mut self,
        consensus_engine_id: [u8; 4],
        scale_encoded_justification: &[u8],
        randomness_seed: [u8; 32],
    ) -> Result<FinalityApply<'_, T>, JustificationVerifyError> {
        match (&self.finality, &consensus_engine_id) {
            (Finality::Grandpa { .. }, b"FRNK") => {
                // Turn justification into a strongly-typed struct.
                let decoded = decode::decode_grandpa_justification(
                    scale_encoded_justification,
                    self.block_number_bytes,
                )
                .map_err(JustificationVerifyError::InvalidJustification)?;

                // Delegate the first step to the other function.
                let (block_index, authorities_set_id, authorities_list) = self
                    .verify_grandpa_finality_inner(decoded.target_hash, decoded.target_number)
                    .map_err(JustificationVerifyError::FinalityVerify)?;

                verify::verify_justification(verify::JustificationVerifyConfig {
                    justification: scale_encoded_justification,
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
        &'_ mut self,
        scale_encoded_commit: &[u8],
        randomness_seed: [u8; 32],
    ) -> Result<FinalityApply<'_, T>, CommitVerifyError> {
        // The code below would panic if the chain doesn't use Grandpa.
        if !matches!(self.finality, Finality::Grandpa { .. }) {
            return Err(CommitVerifyError::NotGrandpa);
        }

        let decoded_commit =
            decode::decode_grandpa_commit(scale_encoded_commit, self.block_number_bytes)
                .map_err(|_| CommitVerifyError::InvalidCommit)?;

        // Delegate the first step to the other function.
        let (block_index, expected_authorities_set_id, authorities_list) = self
            .verify_grandpa_finality_inner(decoded_commit.target_hash, decoded_commit.target_number)
            .map_err(CommitVerifyError::FinalityVerify)?;

        let mut verification = verify::verify_commit(verify::CommitVerifyConfig {
            commit: scale_encoded_commit,
            block_number_bytes: self.block_number_bytes,
            expected_authorities_set_id,
            num_authorities: u32::try_from(authorities_list.clone().count()).unwrap(),
            randomness_seed,
        });

        loop {
            match verification {
                verify::CommitVerify::Finished(Ok(())) => {
                    drop(authorities_list);
                    return Ok(FinalityApply {
                        chain: self,
                        to_finalize: block_index,
                    });
                }
                verify::CommitVerify::FinishedUnknown => {
                    return Err(CommitVerifyError::NotEnoughKnownBlocks {
                        target_block_number: decoded_commit.target_number,
                    });
                }
                verify::CommitVerify::Finished(Err(error)) => {
                    return Err(CommitVerifyError::VerificationFailed(error));
                }
                verify::CommitVerify::IsAuthority(is_authority) => {
                    let to_find = is_authority.authority_public_key();
                    let result = authorities_list.clone().any(|a| a == to_find);
                    verification = is_authority.resume(result);
                }
                verify::CommitVerify::IsParent(is_parent) => {
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

    /// Sets the latest known finalized block. Trying to verify a block that isn't a descendant of
    /// that block will fail.
    ///
    /// The block must have been passed to [`NonFinalizedTree::verify_header`].
    ///
    /// Returns an iterator containing the now-finalized blocks and the pruned blocks in "reverse
    /// hierarchical order". Each block is yielded by the iterator before its parent.
    ///
    /// > **Note**: This function returns blocks in this order, because any other ordering would
    /// >           incur a performance cost. While returning blocks in hierarchical order would
    /// >           often be more convenient, the overhead of doing so is moved to the user.
    ///
    /// The pruning is completely performed, even if the iterator is dropped eagerly.
    ///
    /// If necessary, the current best block will be updated to be a descendant of the
    /// newly-finalized block.
    pub fn set_finalized_block(
        &'_ mut self,
        block_hash: &[u8; 32],
    ) -> Result<SetFinalizedBlockIter<'_, T>, SetFinalizedError> {
        let block_index = match self.blocks_by_hash.get(block_hash) {
            Some(idx) => *idx,
            None => return Err(SetFinalizedError::UnknownBlock),
        };

        Ok(self.set_finalized_block_inner(block_index))
    }

    /// Common function for verifying GrandPa-finality-related messages.
    ///
    /// Returns the index of the possibly finalized block, the expected authorities set id, and
    /// an iterator to the list of authorities.
    ///
    /// # Panic
    ///
    /// Panics if the finality algorithm of the chain isn't Grandpa.
    ///
    fn verify_grandpa_finality_inner(
        &self,
        target_hash: &[u8; 32],
        target_number: u64,
    ) -> Result<
        (
            fork_tree::NodeIndex,
            u64,
            impl Iterator<Item = &[u8]> + Clone,
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
                match target_number.cmp(&self.finalized_block_number) {
                    cmp::Ordering::Equal if *target_hash == self.finalized_block_hash => {
                        return Err(FinalityVerifyError::EqualToFinalized);
                    }
                    cmp::Ordering::Equal => {
                        return Err(FinalityVerifyError::EqualFinalizedHeightButInequalHash);
                    }
                    cmp::Ordering::Less => return Err(FinalityVerifyError::BelowFinalized),
                    _ => {}
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
                        if *prev_auth_change_trigger_number > self.finalized_block_number {
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
                    authorities_list.iter().map(|a| &a.public_key[..]),
                ))
            }
        }
    }

    /// Implementation of [`NonFinalizedTree::set_finalized_block`].
    ///
    /// # Panic
    ///
    /// Panics if `block_index_to_finalize` isn't a valid node in the tree.
    ///
    fn set_finalized_block_inner(
        &'_ mut self,
        block_index_to_finalize: fork_tree::NodeIndex,
    ) -> SetFinalizedBlockIter<'_, T> {
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
                debug_assert!(
                    scheduled_change
                        .as_ref()
                        .map_or(true, |(n, _)| *n > new_finalized_block.number)
                );

                *after_finalized_block_authorities_set_id = *after_block_authorities_set_id;
                *finalized_triggered_authorities = triggered_authorities.clone();
                *finalized_scheduled_change = scheduled_change.clone();
            }

            // Mismatch between chain finality algorithm and block finality algorithm. Should never
            // happen.
            _ => unreachable!(),
        }

        // If the best block isn't a descendant of the block being finalized, then the best
        // block will change to a different block.
        // TODO: this is `O(n)`, does the user really need to know ahead of time whether the best block is updated?
        let updates_best_block = {
            let current_best: Option<fork_tree::NodeIndex> = self
                .blocks_by_best_score
                .last_key_value()
                .map(|(_, idx)| *idx);
            Some(block_index_to_finalize) == current_best
                || current_best.map_or(true, |current_best| {
                    !self
                        .blocks
                        .is_ancestor(block_index_to_finalize, current_best)
                })
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

        // Update `self.finalized_block_header`, `self.finalized_block_hash`,
        // `self.finalized_block_number`, and `self.finalized_best_score`.
        mem::swap(
            &mut self.finalized_block_header,
            &mut new_finalized_block.header,
        );
        self.finalized_block_hash = new_finalized_block.hash;
        self.finalized_block_number = new_finalized_block.number;
        self.finalized_best_score = new_finalized_block.best_score;

        debug_assert_eq!(self.blocks.len(), self.blocks_by_hash.len());
        debug_assert_eq!(self.blocks.len(), self.blocks_by_best_score.len());
        debug_assert!(self.blocks.len() >= self.blocks_trigger_gp_change.len());
        SetFinalizedBlockIter {
            iter: self.blocks.prune_ancestors(block_index_to_finalize),
            blocks_by_hash: &mut self.blocks_by_hash,
            blocks_by_best_score: &mut self.blocks_by_best_score,
            blocks_trigger_gp_change: &mut self.blocks_trigger_gp_change,
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
    chain: &'c mut NonFinalizedTree<T>,
    to_finalize: fork_tree::NodeIndex,
}

impl<'c, T> FinalityApply<'c, T> {
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
        Some(self.to_finalize)
            == self
                .chain
                .blocks_by_best_score
                .last_key_value()
                .map(|(_, idx)| *idx)
    }
}

impl<'c, T> fmt::Debug for FinalityApply<'c, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("FinalityApply").finish()
    }
}

/// Error that can happen when verifying a justification.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum JustificationVerifyError {
    /// Type of the justification doesn't match the finality mechanism used by the chain.
    ///
    /// > **Note**: If the chain's finality mechanism doesn't use justifications, this error is
    /// >           always returned.
    JustificationEngineMismatch,
    /// Error while decoding the justification.
    #[display("Error while decoding the justification: {_0}")]
    InvalidJustification(decode::JustificationDecodeError),
    /// The justification verification has failed. The justification is invalid and should be
    /// thrown away.
    #[display("{_0}")]
    VerificationFailed(verify::JustificationVerifyError),
    /// Error while verifying the finality in the context of the chain.
    #[display("{_0}")]
    FinalityVerify(FinalityVerifyError),
}

/// Error that can happen when verifying a Grandpa commit.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum CommitVerifyError {
    /// Chain doesn't use the GrandPa algorithm.
    NotGrandpa,
    /// Error while decoding the commit.
    InvalidCommit,
    /// Error while verifying the finality in the context of the chain.
    #[display("{_0}")]
    FinalityVerify(FinalityVerifyError),
    /// Not enough blocks are known by the tree to verify this commit.
    ///
    /// This doesn't mean that the commit is bad, but that it can't be verified without adding
    /// more blocks to the tree.
    #[display("Not enough blocks are known to verify this commit")]
    NotEnoughKnownBlocks {
        /// Block number that the commit targets.
        target_block_number: u64,
    },
    /// The commit verification has failed. The commit is invalid and should be thrown away.
    #[display("{_0}")]
    VerificationFailed(verify::CommitVerifyError),
}

/// Error that can happen when verifying a proof of finality.
#[derive(Debug, derive_more::Display, derive_more::Error)]
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
    #[display("Justification targets a block (#{block_number}) that isn't in the chain.")]
    UnknownTargetBlock {
        /// Number of the block that isn't in the chain.
        block_number: u64,
        /// Hash of the block that isn't in the chain.
        block_hash: [u8; 32],
    },
    /// There exists a block in-between the latest finalized block and the block targeted by the
    /// justification that must first be finalized.
    #[display(
        "There exists a block in-between the latest finalized block and the block \
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
    blocks_by_best_score: &'a mut BTreeMap<BestScore, fork_tree::NodeIndex>,
    blocks_trigger_gp_change: &'a mut BTreeSet<(Option<u64>, fork_tree::NodeIndex)>,
    updates_best_block: bool,
}

impl<'a, T> SetFinalizedBlockIter<'a, T> {
    /// Returns true if the finalization process modifies the best block of the chain.
    pub fn updates_best_block(&self) -> bool {
        self.updates_best_block
    }
}

impl<'a, T> Iterator for SetFinalizedBlockIter<'a, T> {
    type Item = RemovedBlock<T>;

    fn next(&mut self) -> Option<Self::Item> {
        let pruned = self.iter.next()?;
        let _removed = self.blocks_by_hash.remove(&pruned.user_data.hash);
        debug_assert_eq!(_removed, Some(pruned.index));
        let _removed = self
            .blocks_by_best_score
            .remove(&pruned.user_data.best_score);
        debug_assert_eq!(_removed, Some(pruned.index));
        if let BlockFinality::Grandpa {
            prev_auth_change_trigger_number,
            triggers_change: true,
            ..
        } = pruned.user_data.finality
        {
            let _removed = self
                .blocks_trigger_gp_change
                .remove(&(prev_auth_change_trigger_number, pruned.index));
            debug_assert!(_removed);
        }

        Some(RemovedBlock {
            block_hash: pruned.user_data.hash,
            block_number: pruned.user_data.number,
            scale_encoded_header: pruned.user_data.header,
            user_data: pruned.user_data.user_data,
            ty: if pruned.is_prune_target_ancestor {
                RemovedBlockType::Finalized
            } else {
                RemovedBlockType::Pruned
            },
        })
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
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum SetFinalizedError {
    /// Block must have been passed to [`NonFinalizedTree::insert_verified_header`] in the past.
    UnknownBlock,
}

/// Block removed from the [`NonFinalizedTree`] by a [`SetFinalizedBlockIter`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemovedBlock<T> {
    /// Hash of the block.
    pub block_hash: [u8; 32],
    /// Height of the block.
    pub block_number: u64,
    /// User data that was associated with that block in the [`NonFinalizedTree`].
    pub user_data: T,
    /// Reason why the block was removed.
    pub ty: RemovedBlockType,
    /// SCALE-encoded header of the block.
    pub scale_encoded_header: Vec<u8>,
}

/// Reason why a block was removed from the [`NonFinalizedTree`] by a [`SetFinalizedBlockIter`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum RemovedBlockType {
    /// Block is now part of the finalized chain.
    Finalized,
    /// Block is not a descendant of the new finalized block.
    Pruned,
}
