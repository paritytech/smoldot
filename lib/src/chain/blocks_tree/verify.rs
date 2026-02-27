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

//! Extension module containing the API and implementation of everything related to verifying
//! blocks.

use crate::{chain::chain_information, header, verify};

use super::{
    Arc, BestScore, Block, BlockConsensus, BlockFinality, Duration, Finality, FinalizedConsensus,
    NonFinalizedTree, Vec, fmt,
};

impl<T> NonFinalizedTree<T> {
    /// Verifies the given block header.
    ///
    /// The verification is performed in the context of the chain. In particular, the
    /// verification will fail if the parent block isn't already in the chain.
    ///
    /// If the verification succeeds, an [`VerifiedHeader`] object might be returned which can be
    /// used to then insert the block in the chain using
    /// [`NonFinalizedTree::insert_verified_header`].
    ///
    /// Must be passed the current UNIX time in order to verify that the block doesn't pretend to
    /// come from the future.
    pub fn verify_header(
        &self,
        scale_encoded_header: Vec<u8>,
        now_from_unix_epoch: Duration,
    ) -> Result<HeaderVerifySuccess, HeaderVerifyError> {
        let decoded_header = match header::decode(&scale_encoded_header, self.block_number_bytes) {
            Ok(h) => h,
            Err(err) => return Err(HeaderVerifyError::InvalidHeader(err)),
        };

        let hash = header::hash_from_scale_encoded_header(&scale_encoded_header);

        // Check for duplicates.
        if self.blocks_by_hash.contains_key(&hash) {
            return Ok(HeaderVerifySuccess::Duplicate);
        }

        // Try to find the parent block in the tree of known blocks.
        // `Some` with an index of the parent within the tree of unfinalized blocks.
        // `None` means that the parent is the finalized block.
        let parent_tree_index = {
            if *decoded_header.parent_hash == self.finalized_block_hash {
                None
            } else {
                match self.blocks_by_hash.get(decoded_header.parent_hash) {
                    Some(parent) => Some(*parent),
                    None => {
                        let parent_hash = *decoded_header.parent_hash;
                        return Err(HeaderVerifyError::BadParent { parent_hash });
                    }
                }
            }
        };

        // Some consensus-specific information must be fetched from the tree of ancestry. The
        // information is found either in the parent block, or in the finalized block.
        let (parent_consensus, parent_best_score, parent_finality) =
            if let Some(parent_tree_index) = parent_tree_index {
                let parent = self.blocks.get(parent_tree_index).unwrap();
                (
                    Some(parent.consensus.clone()),
                    parent.best_score,
                    parent.finality.clone(),
                )
            } else {
                let consensus = match &self.finalized_consensus {
                    FinalizedConsensus::Unknown => None,
                    FinalizedConsensus::Aura {
                        authorities_list, ..
                    } => Some(BlockConsensus::Aura {
                        authorities_list: authorities_list.clone(),
                    }),
                    FinalizedConsensus::Babe {
                        block_epoch_information,
                        next_epoch_transition,
                        ..
                    } => Some(BlockConsensus::Babe {
                        current_epoch: block_epoch_information.clone(),
                        next_epoch: next_epoch_transition.clone(),
                    }),
                };

                let finality = match self.finality {
                    Finality::Outsourced => BlockFinality::Outsourced,
                    Finality::Grandpa {
                        after_finalized_block_authorities_set_id,
                        ref finalized_scheduled_change,
                        ref finalized_triggered_authorities,
                    } => {
                        debug_assert!(
                            finalized_scheduled_change
                                .as_ref()
                                .map(|(n, _)| *n >= decoded_header.number)
                                .unwrap_or(true)
                        );
                        BlockFinality::Grandpa {
                            prev_auth_change_trigger_number: None,
                            triggers_change: false,
                            scheduled_change: finalized_scheduled_change.clone(),
                            after_block_authorities_set_id:
                                after_finalized_block_authorities_set_id,
                            triggered_authorities: finalized_triggered_authorities.clone(),
                        }
                    }
                };

                (consensus, self.finalized_best_score, finality)
            };

        let parent_block_header = if let Some(parent_tree_index) = parent_tree_index {
            &self
                .blocks
                .get(parent_tree_index)
                .unwrap_or_else(|| unreachable!())
                .header
        } else {
            &self.finalized_block_header
        };

        let (best_score_num_primary_slots, best_score_num_secondary_slots, consensus_update) = {
            let header_verify_result = {
                let consensus_config = match (&self.finalized_consensus, &parent_consensus) {
                    (
                        FinalizedConsensus::Aura { slot_duration, .. },
                        Some(BlockConsensus::Aura { authorities_list }),
                    ) => verify::header_only::ConfigConsensus::Aura {
                        current_authorities: header::AuraAuthoritiesIter::from_slice(
                            authorities_list,
                        ),
                        now_from_unix_epoch,
                        slot_duration: *slot_duration,
                        // Parachains with async backing can produce multiple blocks per
                        // Aura slot. Outsourced finality indicates a parachain.
                        allow_equal_slot_number: matches!(self.finality, Finality::Outsourced),
                    },
                    (
                        FinalizedConsensus::Babe {
                            slots_per_epoch, ..
                        },
                        Some(BlockConsensus::Babe {
                            current_epoch,
                            next_epoch,
                        }),
                    ) => verify::header_only::ConfigConsensus::Babe {
                        parent_block_epoch: current_epoch.as_ref().map(|v| (&**v).into()),
                        parent_block_next_epoch: (&**next_epoch).into(),
                        slots_per_epoch: *slots_per_epoch,
                        now_from_unix_epoch,
                    },
                    (FinalizedConsensus::Unknown, None) => {
                        return Err(HeaderVerifyError::UnknownConsensusEngine);
                    }
                    _ => {
                        return Err(HeaderVerifyError::ConsensusMismatch);
                    }
                };

                match verify::header_only::verify(verify::header_only::Config {
                    consensus: consensus_config,
                    finality: match &parent_finality {
                        BlockFinality::Outsourced => {
                            verify::header_only::ConfigFinality::Outsourced
                        }
                        BlockFinality::Grandpa { .. } => {
                            verify::header_only::ConfigFinality::Grandpa
                        }
                    },
                    allow_unknown_consensus_engines: self.allow_unknown_consensus_engines,
                    block_header: decoded_header.clone(),
                    block_number_bytes: self.block_number_bytes,
                    parent_block_header: {
                        // All headers inserted in `self` are necessarily valid, and thus this
                        // `unwrap()` can't panic.
                        header::decode(parent_block_header, self.block_number_bytes)
                            .unwrap_or_else(|_| unreachable!())
                    },
                }) {
                    Ok(s) => s,
                    Err(err) => {
                        // The code in this module is meant to ensure that the chain is in an
                        // appropriate state, therefore `is_invalid_chain_configuration` being `true`
                        // would indicate a bug in the code somewhere.
                        // We use a `debug_assert` rather than `assert` in order to avoid crashing,
                        // as treating the header as invalid is an appropriate way to handle a bug
                        // here.
                        debug_assert!(!err.is_invalid_chain_configuration());
                        return Err(HeaderVerifyError::VerificationFailed(err));
                    }
                }
            };

            match (
                header_verify_result,
                &parent_consensus,
                self.finalized_consensus.clone(),
                parent_tree_index.map(|idx| self.blocks.get(idx).unwrap().consensus.clone()),
            ) {
                // No Aura epoch transition. Just a regular block.
                (
                    verify::header_only::Success::Aura {
                        authorities_change: None,
                    },
                    Some(BlockConsensus::Aura {
                        authorities_list: parent_authorities,
                    }),
                    FinalizedConsensus::Aura { .. },
                    _,
                ) => (
                    parent_best_score.num_primary_slots + 1,
                    parent_best_score.num_secondary_slots,
                    BlockConsensus::Aura {
                        authorities_list: parent_authorities.clone(),
                    },
                ),

                // Aura epoch transition.
                (
                    verify::header_only::Success::Aura {
                        authorities_change: Some(new_authorities_list),
                    },
                    Some(BlockConsensus::Aura { .. }),
                    FinalizedConsensus::Aura { .. },
                    _,
                ) => (
                    parent_best_score.num_primary_slots + 1,
                    parent_best_score.num_secondary_slots,
                    BlockConsensus::Aura {
                        authorities_list: Arc::new(new_authorities_list),
                    },
                ),

                // No Babe epoch transition. Just a regular block.
                (
                    verify::header_only::Success::Babe {
                        epoch_transition_target: None,
                        is_primary_slot,
                        ..
                    },
                    Some(BlockConsensus::Babe { .. }),
                    FinalizedConsensus::Babe { .. },
                    Some(BlockConsensus::Babe {
                        current_epoch,
                        next_epoch,
                    }),
                )
                | (
                    verify::header_only::Success::Babe {
                        epoch_transition_target: None,
                        is_primary_slot,
                        ..
                    },
                    Some(BlockConsensus::Babe { .. }),
                    FinalizedConsensus::Babe {
                        block_epoch_information: current_epoch,
                        next_epoch_transition: next_epoch,
                        ..
                    },
                    None,
                ) => (
                    parent_best_score.num_primary_slots + if is_primary_slot { 1 } else { 0 },
                    parent_best_score.num_secondary_slots + if is_primary_slot { 0 } else { 1 },
                    BlockConsensus::Babe {
                        current_epoch,
                        next_epoch,
                    },
                ),

                // Babe epoch transition.
                (
                    verify::header_only::Success::Babe {
                        epoch_transition_target: Some(epoch_transition_target),
                        is_primary_slot,
                        ..
                    },
                    Some(BlockConsensus::Babe { .. }),
                    FinalizedConsensus::Babe { .. },
                    Some(BlockConsensus::Babe {
                        next_epoch: next_epoch_transition,
                        ..
                    }),
                )
                | (
                    verify::header_only::Success::Babe {
                        epoch_transition_target: Some(epoch_transition_target),
                        is_primary_slot,
                        ..
                    },
                    Some(BlockConsensus::Babe { .. }),
                    FinalizedConsensus::Babe {
                        next_epoch_transition,
                        ..
                    },
                    None,
                ) if next_epoch_transition.start_slot_number.is_some() => (
                    parent_best_score.num_primary_slots + if is_primary_slot { 1 } else { 0 },
                    parent_best_score.num_secondary_slots + if is_primary_slot { 0 } else { 1 },
                    BlockConsensus::Babe {
                        current_epoch: Some(next_epoch_transition),
                        next_epoch: Arc::new(epoch_transition_target),
                    },
                ),

                // Babe epoch transition to first epoch.
                // Should only ever happen when the verified block is block 1.
                (
                    verify::header_only::Success::Babe {
                        epoch_transition_target: Some(epoch_transition_target),
                        slot_number,
                        is_primary_slot,
                        ..
                    },
                    Some(BlockConsensus::Babe { .. }),
                    FinalizedConsensus::Babe { .. },
                    Some(BlockConsensus::Babe { next_epoch, .. }),
                )
                | (
                    verify::header_only::Success::Babe {
                        epoch_transition_target: Some(epoch_transition_target),
                        slot_number,
                        is_primary_slot,
                        ..
                    },
                    Some(BlockConsensus::Babe { .. }),
                    FinalizedConsensus::Babe {
                        next_epoch_transition: next_epoch,
                        ..
                    },
                    None,
                ) => {
                    debug_assert_eq!(decoded_header.number, 1);
                    (
                        parent_best_score.num_primary_slots + if is_primary_slot { 1 } else { 0 },
                        parent_best_score.num_secondary_slots + if is_primary_slot { 0 } else { 1 },
                        BlockConsensus::Babe {
                            current_epoch: Some(Arc::new(
                                chain_information::BabeEpochInformation {
                                    start_slot_number: Some(slot_number),
                                    allowed_slots: next_epoch.allowed_slots,
                                    epoch_index: next_epoch.epoch_index,
                                    authorities: next_epoch.authorities.clone(),
                                    c: next_epoch.c,
                                    randomness: next_epoch.randomness,
                                },
                            )),
                            next_epoch: Arc::new(epoch_transition_target),
                        },
                    )
                }

                // Any mismatch between consensus algorithms should have been detected by
                // the block verification.
                _ => unreachable!(),
            }
        };

        // Updated finality information for the block being verified.
        let finality_update = match &parent_finality {
            BlockFinality::Outsourced => BlockFinality::Outsourced,
            BlockFinality::Grandpa {
                prev_auth_change_trigger_number: parent_prev_auth_change_trigger_number,
                after_block_authorities_set_id: parent_after_block_authorities_set_id,
                scheduled_change: parent_scheduled_change,
                triggered_authorities: parent_triggered_authorities,
                triggers_change: parent_triggers_change,
                ..
            } => {
                let mut triggered_authorities = parent_triggered_authorities.clone();
                let mut triggers_change = false;
                let mut scheduled_change = parent_scheduled_change.clone();

                // Check whether the verified block schedules a change of authorities.
                for grandpa_digest_item in decoded_header.digest.logs().filter_map(|d| match d {
                    header::DigestItemRef::GrandpaConsensus(gp) => Some(gp),
                    _ => None,
                }) {
                    // TODO: implement items other than ScheduledChange
                    // TODO: when it comes to forced change, they take precedence over scheduled changes but only sheduled changes within the same block
                    if let header::GrandpaConsensusLogRef::ScheduledChange(change) =
                        grandpa_digest_item
                    {
                        let trigger_block_height =
                            decoded_header.number.checked_add(change.delay).unwrap();

                        // It is forbidden to schedule a change while a change is already
                        // scheduled, otherwise the block is invalid. This is verified during
                        // the block verification.
                        match scheduled_change {
                            Some(_) => {
                                // Ignore any new change if a change is already in progress.
                                // Matches the behaviour here: <https://github.com/paritytech/substrate/blob/a357c29ebabb075235977edd5e3901c66575f995/client/finality-grandpa/src/authorities.rs#L479>
                            }
                            None => {
                                scheduled_change = Some((
                                    trigger_block_height,
                                    change.next_authorities.map(|a| a.into()).collect(),
                                ));
                            }
                        }
                    }
                }

                // If the newly-verified block is one where Grandpa scheduled change are
                // triggered, we need update the field values.
                // Note that this is checked after we have potentially fetched `scheduled_change`
                // from the block.
                if let Some((trigger_height, new_list)) = &scheduled_change {
                    if *trigger_height == decoded_header.number {
                        triggers_change = true;
                        triggered_authorities = new_list.clone();
                        scheduled_change = None;
                    }
                }

                // Some sanity checks.
                debug_assert!(
                    scheduled_change
                        .as_ref()
                        .map(|(n, _)| *n > decoded_header.number)
                        .unwrap_or(true)
                );
                debug_assert!(
                    parent_prev_auth_change_trigger_number
                        .as_ref()
                        .map(|n| *n < decoded_header.number)
                        .unwrap_or(true)
                );

                BlockFinality::Grandpa {
                    prev_auth_change_trigger_number: if *parent_triggers_change {
                        Some(decoded_header.number - 1)
                    } else {
                        *parent_prev_auth_change_trigger_number
                    },
                    triggered_authorities,
                    scheduled_change,
                    triggers_change,
                    after_block_authorities_set_id: if triggers_change {
                        *parent_after_block_authorities_set_id + 1
                    } else {
                        *parent_after_block_authorities_set_id
                    },
                }
            }
        };

        // Determine whether this block would be the new best.
        let is_new_best = {
            let current_best_score = self
                .blocks_by_best_score
                .last_key_value()
                .map(|(s, _)| s)
                .unwrap_or(&self.finalized_best_score);

            let new_block_best_score = BestScore {
                num_primary_slots: best_score_num_primary_slots,
                num_secondary_slots: best_score_num_secondary_slots,
                insertion_counter: self.blocks_insertion_counter,
            };

            debug_assert_ne!(new_block_best_score, *current_best_score);
            new_block_best_score > *current_best_score
        };

        Ok(HeaderVerifySuccess::Verified {
            verified_header: VerifiedHeader {
                number: decoded_header.number,
                scale_encoded_header,
                consensus_update,
                finality_update,
                best_score_num_primary_slots,
                best_score_num_secondary_slots,
                hash,
            },
            is_new_best,
        })
    }

    /// Insert a header that has already been verified to be valid.
    ///
    /// # Panic
    ///
    /// Panics if the parent of the block isn't in the tree. The presence of the parent is verified
    /// when the block is verified, so this can only happen if you remove the parent after having
    /// verified the block but before calling this function.
    ///
    pub fn insert_verified_header(&mut self, verified_header: VerifiedHeader, user_data: T) {
        // Try to find the parent block in the tree of known blocks.
        // `Some` with an index of the parent within the tree of unfinalized blocks.
        // `None` means that the parent is the finalized block.
        let parent_tree_index = {
            let decoded_header = header::decode(
                &verified_header.scale_encoded_header,
                self.block_number_bytes,
            )
            .unwrap();

            if *decoded_header.parent_hash == self.finalized_block_hash {
                None
            } else {
                Some(*self.blocks_by_hash.get(decoded_header.parent_hash).unwrap())
            }
        };

        let best_score = BestScore {
            num_primary_slots: verified_header.best_score_num_primary_slots,
            num_secondary_slots: verified_header.best_score_num_secondary_slots,
            insertion_counter: self.blocks_insertion_counter,
        };

        let prev_auth_change_trigger_number_if_trigger = if let BlockFinality::Grandpa {
            prev_auth_change_trigger_number,
            triggers_change: true,
            ..
        } = verified_header.finality_update
        {
            Some(prev_auth_change_trigger_number)
        } else {
            None
        };

        let new_node_index = self.blocks.insert(
            parent_tree_index,
            Block {
                header: verified_header.scale_encoded_header,
                hash: verified_header.hash,
                number: verified_header.number,
                consensus: verified_header.consensus_update,
                finality: verified_header.finality_update,
                best_score,
                user_data,
            },
        );

        let _prev_value = self
            .blocks_by_hash
            .insert(verified_header.hash, new_node_index);
        // A bug here would be serious enough that it is worth being an `assert!`
        assert!(_prev_value.is_none());

        self.blocks_by_best_score.insert(best_score, new_node_index);

        if let Some(prev_auth_change_trigger_number) = prev_auth_change_trigger_number_if_trigger {
            self.blocks_trigger_gp_change
                .insert((prev_auth_change_trigger_number, new_node_index));
        }

        // An overflow here would break the logic of the module. It is better to panic than to
        // continue running.
        self.blocks_insertion_counter = self.blocks_insertion_counter.checked_add(1).unwrap();
    }
}

/// Successfully-verified block header that can be inserted into the chain.
pub struct VerifiedHeader {
    scale_encoded_header: Vec<u8>,
    consensus_update: BlockConsensus,
    finality_update: BlockFinality,
    best_score_num_primary_slots: u64,
    best_score_num_secondary_slots: u64,
    hash: [u8; 32],
    number: u64,
}

impl VerifiedHeader {
    /// Returns the block header.
    pub fn scale_encoded_header(&self) -> &[u8] {
        &self.scale_encoded_header
    }

    /// Returns the block header.
    pub fn into_scale_encoded_header(self) -> Vec<u8> {
        self.scale_encoded_header
    }
}

impl fmt::Debug for VerifiedHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("VerifiedHeader")
            .field(&hex::encode(&self.scale_encoded_header))
            .finish()
    }
}

/// See [`NonFinalizedTree::verify_header`].
#[derive(Debug)]
pub enum HeaderVerifySuccess {
    /// Block is already known.
    Duplicate,
    /// Block wasn't known and has been successfully verified.
    Verified {
        /// Header that has been verified. Can be passed to
        /// [`NonFinalizedTree::insert_verified_header`].
        verified_header: VerifiedHeader,
        /// True if the verified block will become the new "best" block after being inserted.
        is_new_best: bool,
    },
}

/// Error that can happen when verifying a block header.
// TODO: some of these errors are redundant with verify::header_only::Error
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum HeaderVerifyError {
    /// Error while decoding the header.
    #[display("Error while decoding the header: {_0}")]
    InvalidHeader(header::Error),
    /// Block can't be verified as it uses an unknown consensus engine.
    UnknownConsensusEngine,
    /// Block uses a different consensus than the rest of the chain.
    ConsensusMismatch,
    /// The parent of the block isn't known.
    #[display("The parent of the block isn't known.")]
    BadParent {
        /// Hash of the parent block in question.
        parent_hash: [u8; 32],
    },
    /// The block verification has failed. The block is invalid and should be thrown away.
    #[display("{_0}")]
    VerificationFailed(verify::header_only::Error),
}
