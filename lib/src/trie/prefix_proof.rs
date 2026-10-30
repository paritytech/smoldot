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

//! Scanning, through trie proofs, the list of all keys that share a certain prefix.
//!
//! This module is a helper whose objective is to find out the list of all keys that start with
//! a certain prefix by performing storage proofs.
//!
//! The total number of storage proofs required is equal to the maximum depth of the tree below
//! the requested prefix, plus one. For example, if a tree has the nodes `[1, 5]`, `[1, 5, 8, 9]`,
//! and `[1, 5, 8, 9, 2]`, then four queries are necessary to find all the keys whose prefix
//! is `[1]`.

// TODO: usage example

use super::{nibble, proof_decode};

use alloc::{vec, vec::Vec};
use core::{fmt, iter, mem};

mod tests;

/// Configuration to pass to [`prefix_scan`].
pub struct Config<'a> {
    /// Prefix that all the keys must share.
    pub prefix: &'a [u8],

    /// Merkle value (or node value) of the root node of the trie.
    ///
    /// > **Note**: The Merkle value and node value are always the same for the root node.
    pub trie_root_hash: [u8; 32],

    /// If `true`, then the final result will only contain [`StorageValue::Value`] entries and no
    /// [`StorageValue::Hash`] entry. Proofs that only contain a storage value hash when they are
    /// expected to contain the full value are considered as invalid.
    pub full_storage_values_required: bool,
}

/// Start a new scanning process.
pub fn prefix_scan(config: Config) -> PrefixScan {
    PrefixScan {
        trie_root_hash: config.trie_root_hash,
        full_storage_values_required: config.full_storage_values_required,
        next_queries: vec![(
            nibble::bytes_to_nibbles(config.prefix.iter().copied()).collect(),
            QueryTy::Exact,
        )],
        final_result: Vec::with_capacity(32),
    }
}

/// Scan of a prefix in progress.
pub struct PrefixScan {
    trie_root_hash: [u8; 32],
    full_storage_values_required: bool,
    // TODO: we have lots of Vecs here; maybe find a way to optimize
    next_queries: Vec<(Vec<nibble::Nibble>, QueryTy)>,
    // TODO: we have lots of Vecs here; maybe find a way to optimize
    final_result: Vec<(Vec<u8>, StorageValue)>,
}

#[derive(Copy, Clone, Debug)]
enum QueryTy {
    /// Expect to find a trie node with this exact key.
    Exact,
    /// The last nibble of the key is a dummy to force the remote to prove to us either that this
    /// node exists or that this node doesn't exist, and if it doesn't exist prove it by including
    /// the "actual" child that we're looking for in the proof.
    /// It is guaranteed that the trie contains a node whose key is the requested key without its
    /// last nibble.
    Direction,
}

impl PrefixScan {
    /// Returns the list of keys whose storage proof must be queried.
    pub fn requested_keys(&self) -> impl Iterator<Item = impl Iterator<Item = nibble::Nibble>> {
        self.next_queries.iter().map(|(l, _)| l.iter().copied())
    }

    /// Returns whether the storage proof must include the storage values of the requested keys.
    ///
    /// > **Note**: This is always equal to [`Config::full_storage_values_required`].
    pub fn request_storage_values(&self) -> bool {
        self.full_storage_values_required
    }

    /// Injects the proof presumably containing the keys returned by [`PrefixScan::requested_keys`].
    ///
    /// Returns an error if the proof is invalid. In that case, `self` isn't modified.
    ///
    /// Contrary to [`PrefixScan::resume_partial`], a proof is considered valid only if it
    /// fulfills all the keys found in the list returned by [`PrefixScan::requested_keys`].
    pub fn resume_all_keys(self, proof: &[u8]) -> Result<ResumeOutcome, (Self, Error)> {
        self.resume_inner(false, proof)
    }

    /// Injects the proof presumably containing the keys returned by [`PrefixScan::requested_keys`].
    ///
    /// Returns an error if the proof is invalid. In that case, `self` isn't modified.
    ///
    /// Contrary to [`PrefixScan::resume_all_keys`], a proof is considered valid if it advances
    /// the request in any way.
    pub fn resume_partial(self, proof: &[u8]) -> Result<ResumeOutcome, (Self, Error)> {
        self.resume_inner(true, proof)
    }

    /// Injects the proof presumably containing the keys returned by [`PrefixScan::requested_keys`].
    ///
    /// Returns an error if the proof is invalid. In that case, `self` isn't modified.
    fn resume_inner(
        mut self,
        allow_incomplete_proof: bool,
        proof: &[u8],
    ) -> Result<ResumeOutcome, (Self, Error)> {
        let decoded_proof =
            match proof_decode::decode_and_verify_proof(proof_decode::Config { proof }) {
                Ok(d) => d,
                Err(err) => return Err((self, Error::InvalidProof(err))),
            };

        // The code below contains an infinite loop.
        // At each iteration, we update the content of `non_terminal_queries` (by extracting its
        // value then putting a new value back before the next iteration).
        // While this is happening, `self.next_queries` is filled with queries that couldn't be
        // fulfilled with the proof that has been given.

        let mut non_terminal_queries = mem::take(&mut self.next_queries);

        // The entire body is executed as long as the processing goes forward.
        for is_first_iteration in iter::once(true).chain(iter::repeat(false)) {
            // Filled with the queries to perform at the next iteration.
            // Capacity assumes a maximum of 2 children per node on average. This value was chosen
            // completely arbitrarily.
            let mut next = Vec::with_capacity(non_terminal_queries.len() * 2);

            debug_assert!(!non_terminal_queries.is_empty());
            while let Some((query_key, query_ty)) = non_terminal_queries.pop() {
                // If some queries couldn't be fulfilled, and that `allow_incomplete_proof` is
                // `false`, return an error. This is only done at the first iteration, as otherwise
                // it is normal for some queries to not be fulfillable.
                if !self.next_queries.is_empty() && is_first_iteration && !allow_incomplete_proof {
                    self.next_queries.extend(next.into_iter());
                    return Err((self, Error::MissingProofEntry));
                }

                // Get the information from the proof about this key.
                // If the query type is "direction", then instead we look up the parent (that we
                // know for sure exists in the trie) then find the child.
                let info = {
                    let info_of_node = match query_ty {
                        QueryTy::Exact => &query_key[..],
                        QueryTy::Direction => &query_key[..query_key.len() - 1],
                    };

                    match (
                        decoded_proof
                            .trie_node_info(&self.trie_root_hash, info_of_node.iter().copied()),
                        query_ty,
                    ) {
                        (Ok(info), QueryTy::Exact) => info,
                        (Ok(info), QueryTy::Direction) => {
                            match info.children.child(query_key[query_key.len() - 1]) {
                                proof_decode::Child::InProof { child_key, .. } => {
                                    // Rather than complicate this code, we just add the child to
                                    // `next` (this time an `Exact` query) and process it during
                                    // the next iteration.
                                    next.push((child_key.collect::<Vec<_>>(), QueryTy::Exact));
                                    continue;
                                }
                                proof_decode::Child::AbsentFromProof { .. } => {
                                    // Node not in the proof. There's no point in adding this node
                                    // to `next` as we will fail again if we try to verify the
                                    // proof again.
                                    self.next_queries.push((query_key, QueryTy::Direction));
                                    continue;
                                }
                                proof_decode::Child::NoChild => {
                                    // We know for sure that there is a child in this direction,
                                    // otherwise the query wouldn't have been added to this
                                    // state machine.
                                    unreachable!()
                                }
                            }
                        }
                        (Err(proof_decode::IncompleteProofError { .. }), _) => {
                            // Node not in the proof. There's no point in adding this node to
                            // `next` as we will fail again if we try to verify the proof again.
                            self.next_queries.push((query_key, query_ty));
                            continue;
                        }
                    }
                };

                if matches!(
                    info.storage_value,
                    proof_decode::StorageValue::Known { .. }
                        | proof_decode::StorageValue::HashKnownValueMissing(_)
                ) {
                    // Fetch the storage value of this node.
                    let value = match info.storage_value {
                        proof_decode::StorageValue::HashKnownValueMissing(_)
                            if self.full_storage_values_required =>
                        {
                            // Storage values are being explicitly requested, but the proof
                            // doesn't include the desired storage value.
                            self.next_queries.push((query_key, query_ty));
                            continue;
                        }
                        proof_decode::StorageValue::HashKnownValueMissing(hash) => {
                            debug_assert!(!self.full_storage_values_required);
                            StorageValue::Hash(*hash)
                        }
                        proof_decode::StorageValue::Known { value, .. } => {
                            // TODO: considering storing the storage proofs instead of copying individual storage values?
                            StorageValue::Value(value.to_vec())
                        }
                        proof_decode::StorageValue::None => unreachable!(),
                    };

                    // Trie nodes with a value are always aligned to "bytes-keys". In other words,
                    // the number of nibbles is always even.
                    debug_assert_eq!(query_key.len() % 2, 0);
                    let key = query_key
                        .chunks(2)
                        .map(|n| (u8::from(n[0]) << 4) | u8::from(n[1]))
                        .collect::<Vec<_>>();

                    // Insert in final results, making sure we check for duplicates.
                    debug_assert!(!self.final_result.iter().any(|(n, _)| *n == key));
                    self.final_result.push((key, value));
                }

                // For each child of the node, put into `next` the key that goes towards this
                // child.
                for (nibble, child) in info.children.children().enumerate() {
                    match child {
                        proof_decode::Child::NoChild => continue,
                        proof_decode::Child::AbsentFromProof { .. } => {
                            let mut direction = query_key.clone();
                            direction.push(
                                nibble::Nibble::try_from(u8::try_from(nibble).unwrap()).unwrap(),
                            );
                            next.push((direction, QueryTy::Direction));
                        }
                        proof_decode::Child::InProof { child_key, .. } => {
                            next.push((child_key.collect::<Vec<_>>(), QueryTy::Exact))
                        }
                    }
                }
            }

            // Finished when nothing more to request.
            if next.is_empty() && self.next_queries.is_empty() {
                // The trie is traversed in no particular order, but the entries are returned
                // ordered by key.
                self.final_result
                    .sort_unstable_by(|(key1, _), (key2, _)| key1.cmp(key2));
                return Ok(ResumeOutcome::Success {
                    entries: self.final_result,
                    full_storage_values_required: self.full_storage_values_required,
                });
            }

            // If we have failed to make any progress during this iteration, return
            // either `Ok(InProgress)` or an error depending on whether this is the first
            // iteration.
            if next.is_empty() {
                debug_assert!(!self.next_queries.is_empty());
                if is_first_iteration {
                    return Err((self, Error::MissingProofEntry));
                } else {
                    break;
                }
            }

            // Update `non_terminal_queries` for the next iteration.
            non_terminal_queries = next;
        }

        Ok(ResumeOutcome::InProgress(self))
    }
}

impl fmt::Debug for PrefixScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PrefixScan").finish()
    }
}

/// Outcome of calling [`PrefixScan::resume_all_keys`] or [`PrefixScan::resume_partial`].
#[derive(Debug)]
pub enum ResumeOutcome {
    /// Scan must continue with the next storage proof query.
    InProgress(PrefixScan),
    /// Scan has succeeded.
    Success {
        /// List of entries whose key starts with the requested prefix, ordered by key.
        entries: Vec<(Vec<u8>, StorageValue)>,
        /// Value that was passed as [`Config::full_storage_values_required`].
        full_storage_values_required: bool,
    },
}

/// Storage value of a trie entry. See [`ResumeOutcome::Success::entries`].
#[derive(Debug)]
pub enum StorageValue {
    /// Value was found in the proof.
    Value(Vec<u8>),
    /// Only the hash of the value was found in the proof.
    ///
    /// Never happens if [`Config::full_storage_values_required`] was `true`.
    Hash([u8; 32]),
}

/// Possible error returned by [`PrefixScan::resume_all_keys`] or [`PrefixScan::resume_partial`].
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub enum Error {
    /// The proof has an invalid format.
    #[display("{_0}")]
    InvalidProof(proof_decode::Error),
    /// One or more entries in the proof are missing.
    MissingProofEntry,
}
