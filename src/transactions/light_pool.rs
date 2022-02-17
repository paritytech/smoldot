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

//! Transactions pool specialized for light clients usage.
//!
//! See [the `pool` module](../pool) documentation for details about the transactions pool.
//!
//! Contrary to [`super::pool::Pool`], this data structure is opinionated towards a certain light
//! client usage. This means:
//!
//! - Block bodies are initially unknown and can be added later.
//! - Transactions included in block bodies that weren't already in the pool aren't added, and
//! thus also don't need to be validated.
//! - The [`LightPool`] tracks all forks, not just the best chain, so as to not require fetching
//! again later the block bodies that are already known in case of a double re-org.
//!
//! # Usage
//!
//! A [`LightPool`] is a collection of transactions and a tree of blocks.
//!
//! Blocks can be added to the tree using [`LightPool::add_block`]. When a block is added, its
//! body is unknown. You can add a body to a block using [`LightPool::set_block_body`]. The pool
//! also tracks a best block and a finalized block. Use [`LightPool::set_best_block`] and
//! [`LightPool::set_finalized_block`] to match the light pool with the state of the chain.
//!
//! Blocks that have been finalized can be removed with [`LightPool::prune_finalized_with_body`].
//! This method only removes blocks whose body is known. You are encouraged to track the value
//! of [`LightPool::oldest_block_finality_lag`] and make sure that it doesn't go above a certain
//! threshold, in order to avoid adding too many blocks to this pool.
//!
//! Each transaction in the pool exposes three properties:
//!
//! - Whether or not it has been validated, and if yes, the block against which it has been
//! validated and the characteristics of the transaction (as provided by the runtime): the tags it
//! provides and requires, its longevity, and its priority. See [the `validate` module](../validate)
//! for more information.
//! - The block of the best chain, if any, in which the transaction has been included.
//! - A so-called user data, an opaque field controller by the API user, of type `TTx`.
//!
//! Use [`LightPool::add_unvalidated`] to add to the pool a transaction that should be included in
//! a block at a later point in time.
//!
//! Use [`LightPool::unvalidated_transactions`] to obtain the list of transactions that should be
//! validated. Validation should be performed using the [`validate`](../validate) module, and
//! the result reported with [`LightPool::set_validation_result`].
//!

use super::validate::{TransactionValidityError, ValidTransaction};
use crate::chain::fork_tree;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::{fmt, iter};

mod tests;

/// Configuration for [`LightPool::new`].
pub struct Config {
    /// Number of transactions to initially allocate memory for.
    pub transactions_capacity: usize,

    /// Number of blocks to initially allocate memory for.
    pub blocks_capacity: usize,

    /// Hash of the finalized block at initialization.
    pub finalized_block_hash: [u8; 32],
}

/// Identifier of a transaction stored within the [`LightPool`].
///
/// Identifiers can be re-used by the pool. In other words, a transaction id can compare equal to
/// an older transaction id that is no longer in the pool.
//
// Implementation note: corresponds to indices within [`LightPool::transactions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransactionId(usize);

/// Data structure containing transactions. See the module-level documentation for more info.
pub struct LightPool<TTx, TBl> {
    /// Actual list of transactions.
    transactions: slab::Slab<Transaction<TTx>>,

    /// Holds tuples of `(block_hash, transaction_id)`. When an entry is present in this set, it
    /// means that this transaction has been found in the body of this block. The value contains
    /// the index in that body where the transaction is present.
    ///
    /// Blocks are guaranteed to be found in [`LightPool::blocks_tree`].
    ///
    /// It is guaranteed that when a `(block_hash, transaction_id)` combination is in this
    /// container, no other parent and child of this block also includes this transaction. In
    /// other words, a transaction is always included only in the earliest block of any given
    /// fork.
    transactions_by_inclusion: BTreeMap<([u8; 32], TransactionId), usize>,

    /// Symmetry of [`LightPool::transactions_by_inclusion`].
    included_transactions: BTreeSet<(TransactionId, [u8; 32])>,

    /// Holds tuples of `(block_hash, transaction_id)`. When an entry is present in this set, it
    /// means that this transaction has been validated against this block. Contains the result of
    /// this validation.
    ///
    /// Blocks are guaranteed to be found in [`LightPool::blocks_tree`].
    transaction_validations:
        BTreeMap<(TransactionId, [u8; 32]), Result<ValidTransaction, TransactionValidityError>>,

    /// Symmetry of [`LightPool::transaction_validations`].
    transactions_by_validation: BTreeSet<([u8; 32], TransactionId)>,

    /// List of transactions (represented as indices within [`LightPool::transactions`]) whose
    /// status is "not validated".
    not_validated: hashbrown::HashSet<TransactionId, fnv::FnvBuildHasher>,

    /// Transaction ids (i.e. indices within [`LightPool::transactions`]) indexed by the blake2
    /// hash of the bytes of the transaction.
    by_hash: BTreeSet<([u8; 32], TransactionId)>,

    /// Tree of all the non-finalized and finalized blocks. This is necessary in case of a re-org
    /// (i.e. the new best block is a nephew of the previous best block) in order to know which
    /// transactions that were present in the previous best chain are still present in the new
    /// best chain.
    blocks_tree: fork_tree::ForkTree<Block<TBl>>,

    /// Contains all blocks in [`LightPool::blocks_tree`], indexed by their hash.
    blocks_by_id: hashbrown::HashMap<[u8; 32], fork_tree::NodeIndex, fnv::FnvBuildHasher>,

    /// Index of the best block in [`LightPool::blocks_tree`]. `None` iff the tree is empty
    /// or if the best block is [`LightPool::blocks_tree_root_hash`].
    best_block_index: Option<fork_tree::NodeIndex>,

    /// Index of the finalized block in [`LightPool::blocks_tree`]. `None` if the tree is empty
    /// or if the finalized block is [`LightPool::blocks_tree_root_hash`].
    finalized_block_index: Option<fork_tree::NodeIndex>,

    /// Hash of the block that serves as root of all the blocks in [`LightPool::blocks_tree`].
    /// Always a finalized block.
    blocks_tree_root_hash: [u8; 32],

    /// Height of the block that serves as root of all the blocks in [`LightPool::blocks_tree`]
    /// minus height of the block that was passed as [`Config::finalized_block_hash`].
    /// Always a finalized block.
    blocks_tree_root_relative_height: u64,
}

impl<TTx, TBl> LightPool<TTx, TBl> {
    /// Initializes a new transactions pool.
    pub fn new(config: Config) -> Self {
        LightPool {
            transactions: slab::Slab::with_capacity(config.transactions_capacity),
            transactions_by_inclusion: BTreeMap::new(),
            included_transactions: BTreeSet::new(),
            transaction_validations: BTreeMap::new(),
            transactions_by_validation: BTreeSet::new(),
            not_validated: hashbrown::HashSet::with_capacity_and_hasher(
                config.transactions_capacity,
                Default::default(),
            ),
            by_hash: BTreeSet::new(),
            blocks_tree: fork_tree::ForkTree::with_capacity(config.blocks_capacity),
            blocks_by_id: hashbrown::HashMap::with_capacity_and_hasher(
                config.blocks_capacity,
                Default::default(),
            ),
            best_block_index: None,
            finalized_block_index: None,
            blocks_tree_root_hash: config.finalized_block_hash,
            blocks_tree_root_relative_height: 0,
        }
    }

    /// Returns the number of transactions in the pool.
    pub fn num_transactions(&self) -> usize {
        self.transactions.len()
    }

    /// Inserts a new unvalidated transaction in the pool.
    ///
    /// Must be passed as parameter the SCALE-encoded transaction.
    pub fn add_unvalidated(&mut self, scale_encoded: Vec<u8>, user_data: TTx) -> TransactionId {
        let hash = blake2_hash(scale_encoded.as_ref());

        let tx_id = TransactionId(self.transactions.insert(Transaction {
            scale_encoded,
            user_data,
        }));

        let _was_inserted = self.by_hash.insert((hash, tx_id));
        debug_assert!(_was_inserted);

        let _was_inserted = self.not_validated.insert(tx_id);
        debug_assert!(_was_inserted);

        tx_id
    }

    /// Removes from the pool the transaction with the given identifier.
    ///
    /// # Panic
    ///
    /// Panics if the identifier is invalid.
    ///
    #[track_caller]
    pub fn remove_transaction(&mut self, id: TransactionId) -> TTx {
        let tx = self.transactions.remove(id.0); // Panics if `id` is invalid.

        let blocks_included = self
            .included_transactions
            .range((id, [0; 32])..=(id, [0xff; 32]))
            .map(|(_, block)| *block)
            .collect::<Vec<_>>();

        let blocks_validated = self
            .transaction_validations
            .range((id, [0; 32])..=(id, [0xff; 32]))
            .map(|((_, block), _)| *block)
            .collect::<Vec<_>>();

        if blocks_validated.is_empty() {
            let _was_removed = self.not_validated.remove(&id);
            debug_assert!(_was_removed);
        }

        for block_hash in blocks_included {
            let _removed = self.included_transactions.remove(&(id, block_hash));
            debug_assert!(_removed);
            let _removed = self.transactions_by_inclusion.remove(&(block_hash, id));
            debug_assert!(_removed.is_some());
        }

        for block_hash in blocks_validated {
            let _removed = self.transaction_validations.remove(&(id, block_hash));
            debug_assert!(_removed.is_some());
            let _removed = self.transactions_by_validation.remove(&(block_hash, id));
            debug_assert!(_removed);
        }

        let _removed = self.by_hash.remove(&(blake2_hash(&tx.scale_encoded), id));
        debug_assert!(_removed);

        tx.user_data
    }

    /// Returns a list of transactions whose state is "not validated", and their user data.
    ///
    /// These transactions should always be validated against the current best block.
    pub fn unvalidated_transactions(
        &'_ self,
    ) -> impl ExactSizeIterator<Item = (TransactionId, &'_ TTx)> + '_ {
        self.not_validated.iter().copied().map(move |tx_id| {
            let tx = self.transactions.get(tx_id.0).unwrap();
            (tx_id, &tx.user_data)
        })
    }

    /// Returns the list of all transactions within the pool.
    pub fn transactions_iter(&'_ self) -> impl Iterator<Item = (TransactionId, &'_ TTx)> + '_ {
        self.transactions
            .iter()
            .map(|(id, tx)| (TransactionId(id), &tx.user_data))
    }

    /// Returns the list of all transactions within the pool.
    pub fn transactions_iter_mut(
        &'_ mut self,
    ) -> impl Iterator<Item = (TransactionId, &'_ mut TTx)> + '_ {
        self.transactions
            .iter_mut()
            .map(|(id, tx)| (TransactionId(id), &mut tx.user_data))
    }

    /// Returns the user data associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn transaction_user_data(&self, id: TransactionId) -> Option<&TTx> {
        Some(&self.transactions.get(id.0)?.user_data)
    }

    /// Returns the user data associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn transaction_user_data_mut(&mut self, id: TransactionId) -> Option<&mut TTx> {
        Some(&mut self.transactions.get_mut(id.0)?.user_data)
    }

    /// Returns the bytes associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn scale_encoding(&self, id: TransactionId) -> Option<&[u8]> {
        Some(&self.transactions.get(id.0)?.scale_encoded)
    }

    /// Tries to find the transactions in the pool whose bytes are `scale_encoded`.
    pub fn find_transaction(
        &'_ self,
        scale_encoded: &[u8],
    ) -> impl Iterator<Item = TransactionId> + '_ {
        let hash = blake2_hash(scale_encoded);
        self.by_hash
            .range(
                (hash, TransactionId(usize::min_value()))
                    ..=(hash, TransactionId(usize::max_value())),
            )
            .map(|(_, tx_id)| *tx_id)
    }

    /// Returns `true` if the given transaction has been included in the past in an ancestor of
    /// the current best block.
    ///
    /// # Panic
    ///
    /// Panics if the transaction with the given id is invalid.
    ///
    pub fn is_included_best_chain(&self, id: TransactionId) -> bool {
        let mut iter = self
            .included_transactions
            .range((id, [0; 32])..=(id, [0xff; 32]))
            .filter(|(_, block_hash)| {
                let block_index = *self.blocks_by_id.get(block_hash).unwrap();
                self.best_block_index.map_or(false, |best_idx| {
                    self.blocks_tree.is_ancestor(block_index, best_idx)
                })
            });

        let outcome = iter.next().is_some();
        if outcome {
            debug_assert!(iter.next().is_none());
        }
        outcome
    }

    /// Returns `true` if the given transaction has been validated in the past against an ancestor
    /// of the best block and is still within its longevity period.
    ///
    /// Returns `false` if the block has been included in an ancestor of the best block.
    ///
    /// # Panic
    ///
    /// Panics if the transaction with the given id is invalid.
    ///
    pub fn is_valid_against_best_block(&self, id: TransactionId) -> bool {
        if self.is_included_best_chain(id) {
            return false;
        }

        // TODO: wrong implementation /!\
        self.transaction_validations
            .range((id, [0; 32])..=(id, [0xff; 32]))
            .count()
            != 0
    }

    /// Sets the outcome of validating the transaction with the given identifier.
    ///
    /// The block hash must be the block hash against which the transaction has been
    /// validated.
    ///
    /// # Panic
    ///
    /// Panics if the transaction with the given id is invalid.
    /// Panics if no block with that hash has been inserted before.
    ///
    // TODO: is it correct to pass a `Result`, instead of just a `ValidTransaction`?
    // TODO: can the block be the finalized block? (i.e. tree_root_hash)
    pub fn set_validation_result(
        &mut self,
        id: TransactionId,
        block_hash_validated_against: &[u8; 32],
        result: Result<ValidTransaction, TransactionValidityError>,
    ) {
        // Make sure that the block exists.
        let _block_index = *self.blocks_by_id.get(block_hash_validated_against).unwrap();

        // This will replace an existing entry.
        self.transaction_validations
            .insert((id, *block_hash_validated_against), result);
        let inserted = self
            .transactions_by_validation
            .insert((*block_hash_validated_against, id));

        if inserted {
            let _removed = self.not_validated.remove(&id);
            debug_assert_eq!(
                _removed,
                self.transaction_validations
                    .range((id, [0; 32])..=(id, [0xff; 32]))
                    .count()
                    == 1
            );
        }
    }

    /// Adds a block to the collection of blocks.
    ///
    /// Has no effect if that block was already present in the collection.
    ///
    /// If there is no transaction in the pool, then the block is marked as "doesn't need a body",
    /// meaning that it will not be returned by [`LightPool::missing_block_bodies`].
    ///
    /// # Panic
    ///
    /// Panics if the parent block cannot be found in the collection.
    ///
    pub fn add_block(&mut self, hash: [u8; 32], parent_hash: &[u8; 32], user_data: TBl) {
        let (parent_index_in_tree, parent_relative_height) =
            if *parent_hash == self.blocks_tree_root_hash {
                (None, self.blocks_tree_root_relative_height)
            } else {
                // The transactions service tracks all new blocks.
                // The parent of each new best block must therefore already be in the tree.
                let idx = *self.blocks_by_id.get(parent_hash).unwrap();
                (
                    Some(idx),
                    self.blocks_tree.get(idx).unwrap().relative_block_height,
                )
            };

        let entry = match self.blocks_by_id.entry(hash) {
            hashbrown::hash_map::Entry::Occupied(_) => return,
            hashbrown::hash_map::Entry::Vacant(e) => e,
        };

        let block_index = self.blocks_tree.insert(
            parent_index_in_tree,
            Block {
                hash,
                body: if self.transactions.is_empty() {
                    BodyState::NotNeeded
                } else {
                    BodyState::Needed
                },
                relative_block_height: parent_relative_height + 1,
                user_data,
            },
        );

        entry.insert(block_index);
    }

    /// Sets the passed block as the new best block of the chain.
    ///
    /// # Panic
    ///
    /// Panics if no block with the given hash has been inserted before.
    ///
    #[must_use]
    pub fn set_best_block(&mut self, new_best_block_hash: &[u8; 32]) -> SetBestBlock {
        // Index of the provided block within the tree. `None` if equal to `blocks_tree_root_hash`.
        let new_best_block_index = if *new_best_block_hash == self.blocks_tree_root_hash {
            None
        } else {
            Some(*self.blocks_by_id.get(new_best_block_hash).unwrap())
        };

        // Iterators over the potential re-org. Used below to report the transaction status
        // updates.
        let (old_best_to_common_ancestor, common_ancestor_to_new_best) =
            match (self.best_block_index, new_best_block_index) {
                (Some(old_best_index), Some(new_best_block_index)) => {
                    let (ascend, descend) = self
                        .blocks_tree
                        .ascend_and_descend(old_best_index, new_best_block_index);
                    (
                        either::Left(either::Left(ascend)),
                        either::Left(either::Left(descend)),
                    )
                }
                (Some(old_best_index), None) => {
                    let ascend = self.blocks_tree.node_to_root_path(old_best_index);
                    let descend = iter::empty::<fork_tree::NodeIndex>();
                    (either::Left(either::Right(ascend)), either::Right(descend))
                }
                (None, Some(new_best_block_index)) => {
                    let ascend = iter::empty::<fork_tree::NodeIndex>();
                    let descend = self.blocks_tree.root_to_node_path(new_best_block_index);
                    (either::Right(ascend), either::Left(either::Right(descend)))
                }
                (None, None) => {
                    let ascend = iter::empty::<fork_tree::NodeIndex>();
                    let descend = iter::empty::<fork_tree::NodeIndex>();
                    (either::Right(ascend), either::Right(descend))
                }
            };

        let mut retracted_transactions = Vec::new();
        for to_retract_index in old_best_to_common_ancestor {
            let retracted = self.blocks_tree.get(to_retract_index).unwrap();
            for ((_, tx_id), index) in self.transactions_by_inclusion.range(
                (retracted.hash, TransactionId(usize::min_value()))
                    ..=(retracted.hash, TransactionId(usize::max_value())),
            ) {
                retracted_transactions.push((*tx_id, retracted.hash, *index));
            }
        }

        let mut included_transactions = Vec::new();
        for to_include_index in common_ancestor_to_new_best {
            let included = self.blocks_tree.get(to_include_index).unwrap();
            for ((_, tx_id), index) in self.transactions_by_inclusion.range(
                (included.hash, TransactionId(usize::min_value()))
                    ..=(included.hash, TransactionId(usize::max_value())),
            ) {
                included_transactions.push((*tx_id, included.hash, *index));
            }
        }

        self.best_block_index = new_best_block_index;

        SetBestBlock {
            retracted_transactions,
            included_transactions,
        }
    }

    /// Returns `true` if the block with the given hash is present in the pool.
    pub fn has_block(&self, hash: &[u8; 32]) -> bool {
        self.blocks_by_id.contains_key(hash)
    }

    /// Returns the hash of the best block.
    ///
    /// Please note that the block with the given hash might not have an associated user data in
    /// case the best block is equal to the finalized block and all finalized blocks have been
    /// pruned.
    pub fn best_block_hash(&self) -> &[u8; 32] {
        match self.best_block_index {
            Some(idx) => &self.blocks_tree.get(idx).unwrap().hash,
            None => &self.blocks_tree_root_hash,
        }
    }

    /// Returns the user data associated with a given block.
    ///
    /// Returns `None` if the block hash doesn't correspond to a known block.
    pub fn block_user_data(&self, hash: &[u8; 32]) -> Option<&TBl> {
        let index = *self.blocks_by_id.get(hash)?;
        Some(&self.blocks_tree.get(index).unwrap().user_data)
    }

    /// Returns the user data associated with a given block.
    ///
    /// Returns `None` if the block hash doesn't correspond to a known block.
    pub fn block_user_data_mut(&mut self, hash: &[u8; 32]) -> Option<&mut TBl> {
        let index = *self.blocks_by_id.get(hash)?;
        Some(&mut self.blocks_tree.get_mut(index).unwrap().user_data)
    }

    /// Sets the list of single-SCALE-encoded transactions that are present in the body of a block.
    ///
    /// If the block is part of the best chain, returns the list of transactions that are in the
    /// pool, that were found in the body, and that weren't part of the best chain before,
    /// alongside with their index in the body.
    ///
    /// # Panic
    ///
    /// Panics if no block with the given hash has been inserted before.
    ///
    // TODO: return something more precise in case the block in which a transaction is included is updated?
    #[must_use = "`set_block_body` returns the list of transactions that are now included in the chain"]
    pub fn set_block_body(
        &'_ mut self,
        block_hash: &[u8; 32],
        body: impl Iterator<Item = impl AsRef<[u8]>>,
    ) -> impl Iterator<Item = (TransactionId, usize)> + '_ {
        let block_index = *self.blocks_by_id.get(block_hash).unwrap();

        // TODO: what if body was already known? this will trigger the `debug_assert!(_was_included)` below
        // TODO: right now we just panic
        assert!(!matches!(
            self.blocks_tree.get_mut(block_index).unwrap().body,
            BodyState::Known
        ));
        self.blocks_tree.get_mut(block_index).unwrap().body = BodyState::Known;

        let is_in_best_chain = self.best_block_index.map_or(false, |best_block_index| {
            self.blocks_tree.is_ancestor(block_index, best_block_index)
        });

        // Value returned from the function.
        // TODO: optimize by not having Vec
        let mut included_transactions = Vec::new();

        for (included_body_index, included_body) in body.into_iter().enumerate() {
            let included_body = included_body.as_ref();
            let hash = blake2_hash(included_body);

            'tx_in_pool: for (_, known_tx_id) in self.by_hash.range(
                (hash, TransactionId(usize::min_value()))
                    ..=(hash, TransactionId(usize::max_value())),
            ) {
                let mut now_included = is_in_best_chain;

                // Check in which other blocks this transaction has been seen before.
                for (_, existing_included_block) in self
                    .included_transactions
                    .range((*known_tx_id, [0x0; 32])..=(*known_tx_id, [0xff; 32]))
                    .cloned()
                    .collect::<Vec<_>>()
                {
                    let existing_included_block_idx =
                        *self.blocks_by_id.get(&existing_included_block).unwrap();

                    // Skip this transaction if it has already been found in a parent.
                    if self
                        .blocks_tree
                        .is_ancestor(existing_included_block_idx, block_index)
                    {
                        continue 'tx_in_pool;
                    }

                    // If the transaction is found in a children, un-include it. from the child.
                    if self
                        .blocks_tree
                        .is_ancestor(block_index, existing_included_block_idx)
                    {
                        let _was_removed = self
                            .transactions_by_inclusion
                            .remove(&(existing_included_block, *known_tx_id));
                        debug_assert!(_was_removed.is_some());

                        let _was_removed = self
                            .included_transactions
                            .remove(&(*known_tx_id, existing_included_block));
                        debug_assert!(_was_removed);

                        // If `existing_included_block_idx` is in the best chain, set
                        // `now_included` to false.
                        if self.best_block_index.map_or(false, |best_block_index| {
                            self.blocks_tree
                                .is_ancestor(existing_included_block_idx, best_block_index)
                        }) {
                            now_included = false;
                        }
                    }
                }

                let _was_present = self
                    .transactions_by_inclusion
                    .insert((*block_hash, *known_tx_id), included_body_index);
                debug_assert!(_was_present.is_none());

                let _was_included = self
                    .included_transactions
                    .insert((*known_tx_id, *block_hash));
                debug_assert!(_was_included);

                if now_included {
                    included_transactions.push((*known_tx_id, included_body_index));
                }
            }
        }

        included_transactions.into_iter()
    }

    /// Returns the list of blocks whose bodies aren't present in this data structure.
    ///
    /// Blocks that were inserted when there wasn't any transaction in the pool are never
    /// returned.
    // TODO: return whether in best chain
    pub fn missing_block_bodies(&'_ self) -> impl Iterator<Item = (&'_ [u8; 32], &'_ TBl)> + '_ {
        self.blocks_tree
            .iter_unordered()
            .filter_map(move |(_, block)| {
                if !matches!(block.body, BodyState::Needed) {
                    return None;
                }

                Some((&block.hash, &block.user_data))
            })
    }

    /// Sets the finalized block of the chain.
    ///
    /// Removes and returns the blocks that are not part of the finalized chain. Please note that
    /// the finalized chain itself, however, isn't removed.
    ///
    /// The current best block (set using [`LightPool::set_best_block`]) must be a descendant of
    /// or equal to the node passed as parameter. This guarantees that no transaction gets
    /// retracted.
    ///
    /// # Panic
    ///
    /// Panics if no block with the given hash has been inserted before.
    /// Panics if the current best block isn't a descendant of or equal to the new finalized
    /// block.
    ///
    pub fn set_finalized_block(
        &mut self,
        new_finalized_block_hash: &[u8; 32],
    ) -> impl Iterator<Item = ([u8; 32], TBl)> {
        self.finalized_block_index = if *new_finalized_block_hash == self.blocks_tree_root_hash {
            None
        } else {
            let index = *self.blocks_by_id.get(new_finalized_block_hash).unwrap();
            assert!(self
                .blocks_tree
                .is_ancestor(index, self.best_block_index.unwrap()));
            Some(index)
        };

        // TODO: don't allocate a Vec here
        let mut out = Vec::new();

        if let Some(new_finalized_block_index) = self.finalized_block_index {
            for pruned_block in self.blocks_tree.prune_uncles(new_finalized_block_index) {
                debug_assert!(!pruned_block.is_prune_target_ancestor);

                let _expected_index = self.blocks_by_id.remove(&pruned_block.user_data.hash);
                debug_assert_eq!(_expected_index, Some(pruned_block.index));

                let included_txs = self
                    .transactions_by_inclusion
                    .range(
                        (
                            pruned_block.user_data.hash,
                            TransactionId(usize::min_value()),
                        )
                            ..=(
                                pruned_block.user_data.hash,
                                TransactionId(usize::max_value()),
                            ),
                    )
                    .map(|((_, tx), _)| *tx)
                    .collect::<Vec<_>>();

                for tx_id in included_txs {
                    let _was_removed = self
                        .transactions_by_inclusion
                        .remove(&(pruned_block.user_data.hash, tx_id));
                    debug_assert!(_was_removed.is_some());
                    let _was_removed = self
                        .included_transactions
                        .remove(&(tx_id, pruned_block.user_data.hash));
                    debug_assert!(_was_removed);
                }

                let validated_txs = self
                    .transactions_by_validation
                    .range(
                        (
                            pruned_block.user_data.hash,
                            TransactionId(usize::min_value()),
                        )
                            ..=(
                                pruned_block.user_data.hash,
                                TransactionId(usize::max_value()),
                            ),
                    )
                    .map(|(_, tx)| *tx)
                    .collect::<Vec<_>>();

                for tx_id in validated_txs {
                    let _was_removed = self
                        .transactions_by_validation
                        .remove(&(pruned_block.user_data.hash, tx_id));
                    debug_assert!(_was_removed);
                    let _was_removed = self
                        .transaction_validations
                        .remove(&(tx_id, pruned_block.user_data.hash));
                    debug_assert!(_was_removed.is_some());

                    if self
                        .transaction_validations
                        .range((tx_id, [0; 32])..=(tx_id, [0xff; 32]))
                        .next()
                        .is_none()
                    {
                        let _was_inserted = self.not_validated.insert(tx_id);
                        debug_assert!(_was_inserted);
                    }
                }

                out.push((
                    pruned_block.user_data.hash,
                    pruned_block.user_data.user_data,
                ));
            }
        }

        out.into_iter()
    }

    /// Removes from the pool as many blocks as possible from the finalized chain. Blocks are
    /// removed from parent to child until either the first non-finalized block or a block whose
    /// body is missing is encountered.
    ///
    /// Also removes the transactions from the pool that were included in these blocks.
    #[must_use]
    pub fn prune_finalized_with_body(
        &'_ mut self,
    ) -> impl Iterator<Item = PruneBodyFinalized<TTx, TBl>> + '_ {
        // TODO: optimize?

        let finalized_block_index = match self.finalized_block_index {
            Some(idx) => idx,
            None => return either::Right(iter::empty()),
        };

        // Find highest finalized block that can be pruned.
        let (num_blocks_to_remove, upmost_to_remove) = {
            let search = self
                .blocks_tree
                .root_to_node_path(finalized_block_index)
                .take_while(|idx| {
                    !matches!(self.blocks_tree.get(*idx).unwrap().body, BodyState::Needed)
                })
                .enumerate()
                .map(|(n, b)| (n + 1, b))
                .last();
            match search {
                Some(idx) => idx,
                None => return either::Right(iter::empty()),
            }
        };

        // Some internal state update.
        if upmost_to_remove == finalized_block_index {
            self.finalized_block_index = None;
            self.blocks_tree_root_hash = self.blocks_tree.get(upmost_to_remove).unwrap().hash;
        }

        // Return value of the function.
        let mut return_value = Vec::with_capacity(num_blocks_to_remove);

        // Do the actual pruning.
        for pruned in self.blocks_tree.prune_ancestors(upmost_to_remove) {
            // Since all the blocks that we removed are already finalized, we shouldn't find any
            // sibling when pruning.
            debug_assert!(pruned.is_prune_target_ancestor);

            let _removed = self.blocks_by_id.remove(&pruned.user_data.hash);
            debug_assert_eq!(_removed, Some(pruned.index));

            // List of transactions that were included in this block.
            let included_transactions_ids = self
                .transactions_by_inclusion
                .range(
                    (pruned.user_data.hash, TransactionId(usize::min_value()))
                        ..=(pruned.user_data.hash, TransactionId(usize::max_value())),
                )
                .map(|((_, tx_id), index)| (*tx_id, *index))
                .collect::<Vec<_>>();
            let mut included_transactions = Vec::with_capacity(included_transactions_ids.len());

            for (tx_id, index_in_block) in &included_transactions_ids {
                // Completely remove this transaction from the pool, similar to what
                // `remove_transaction` does.
                let tx = self.transactions.remove(tx_id.0);

                let blocks_included = self
                    .included_transactions
                    .range((*tx_id, [0; 32])..=(*tx_id, [0xff; 32]))
                    .map(|(_, block)| *block)
                    .collect::<Vec<_>>();

                let blocks_validated = self
                    .transaction_validations
                    .range((*tx_id, [0; 32])..=(*tx_id, [0xff; 32]))
                    .map(|((_, block), _)| *block)
                    .collect::<Vec<_>>();

                if blocks_validated.is_empty() {
                    let _was_removed = self.not_validated.remove(tx_id);
                    debug_assert!(_was_removed);
                }

                for block_hash in blocks_included {
                    let _removed = self.included_transactions.remove(&(*tx_id, block_hash));
                    debug_assert!(_removed);
                    let _removed = self.transactions_by_inclusion.remove(&(block_hash, *tx_id));
                    debug_assert!(_removed.is_some());
                }

                for block_hash in blocks_validated {
                    let _removed = self.transaction_validations.remove(&(*tx_id, block_hash));
                    debug_assert!(_removed.is_some());
                    let _removed = self
                        .transactions_by_validation
                        .remove(&(block_hash, *tx_id));
                    debug_assert!(_removed);
                }

                let _removed = self
                    .by_hash
                    .remove(&(blake2_hash(&tx.scale_encoded), *tx_id));
                debug_assert!(_removed);

                included_transactions.push((
                    *tx_id,
                    *index_in_block,
                    tx.scale_encoded,
                    tx.user_data,
                ));
            }

            // Purge the state from any validation information about that block.
            let validated_txs = self
                .transactions_by_validation
                .range(
                    (pruned.user_data.hash, TransactionId(usize::min_value()))
                        ..=(pruned.user_data.hash, TransactionId(usize::max_value())),
                )
                .map(|(_, tx)| *tx)
                .collect::<Vec<_>>();

            for tx_id in validated_txs {
                let _was_removed = self
                    .transactions_by_validation
                    .remove(&(pruned.user_data.hash, tx_id));
                debug_assert!(_was_removed);
                let _was_removed = self
                    .transaction_validations
                    .remove(&(tx_id, pruned.user_data.hash));
                debug_assert!(_was_removed.is_some());

                if self
                    .transaction_validations
                    .range((tx_id, [0; 32])..=(tx_id, [0xff; 32]))
                    .next()
                    .is_none()
                {
                    let _was_inserted = self.not_validated.insert(tx_id);
                    debug_assert!(_was_inserted);
                }
            }

            return_value.push(PruneBodyFinalized {
                block_hash: pruned.user_data.hash,
                included_transactions,
                user_data: pruned.user_data.user_data,
            });
        }

        // We returned earlier in the function if `finalized_node_index` is `None`. Consequently,
        // `best_block_index` can't be `None` either.
        if self.best_block_index.unwrap() == upmost_to_remove {
            self.best_block_index = None;
        }

        // Success.
        either::Left(return_value.into_iter())
    }

    /// Returns the number of blocks between the oldest block stored in this data structure and
    /// the finalized block.
    pub fn oldest_block_finality_lag(&self) -> usize {
        if let Some(finalized_block_index) = self.finalized_block_index {
            self.blocks_tree
                .root_to_node_path(finalized_block_index)
                .count()
        } else {
            0
        }
    }
}

impl<TTx: fmt::Debug, TBl> fmt::Debug for LightPool<TTx, TBl> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list()
            .entries(
                self.transactions
                    .iter()
                    .map(|t| (TransactionId(t.0), &t.1.user_data)),
            )
            .finish()
    }
}

/// See [`LightPool::prune_finalized_with_body`].
pub struct PruneBodyFinalized<TTx, TBl> {
    /// Hash of the finalized block.
    pub block_hash: [u8; 32],

    /// User data associated to this block.
    pub user_data: TBl,

    /// List of transactions that were included in this block, alongside with their index within
    /// that block, SCALE encoding, and user data. These transactions have been removed from the
    /// pool.
    // TODO: use proper struct
    pub included_transactions: Vec<(TransactionId, usize, Vec<u8>, TTx)>,
}

/// See [`LightPool::set_best_block`].
#[derive(Debug, Clone)]
pub struct SetBestBlock {
    /// List of transactions that were included in a block of the best chain but no longer are,
    /// the hash of the block in which it was, and the index of the transaction in that block's
    /// body.
    ///
    /// Can share some entries with [`SetBestBlock::included_transactions`] in case a transaction
    /// has been retracted then included.
    pub retracted_transactions: Vec<(TransactionId, [u8; 32], usize)>,

    /// List of transactions that weren't included in a block of the best chain but now are, the
    /// hash of the block in which it was found, and the index of the transaction in that block's
    /// body.
    ///
    /// Can share some entries with [`SetBestBlock::retracted_transactions`] in case a transaction
    /// has been retracted then included.
    pub included_transactions: Vec<(TransactionId, [u8; 32], usize)>,
}

/// Entry in [`LightPool::transactions`].
struct Transaction<TTx> {
    /// Bytes corresponding to the SCALE-encoded transaction.
    scale_encoded: Vec<u8>,

    /// User data chosen by the user.
    user_data: TTx,
}

struct Block<TBl> {
    /// Height of this block minus height of the block that was passed as
    /// [`Config::finalized_block_hash`].
    ///
    /// All the heights manipulated by the [`LightPool`] are relative to the height of the block
    /// passed as [`Config::finalized_block_hash`], making it possible to compare and subtract
    /// them.
    relative_block_height: u64,
    hash: [u8; 32],
    body: BodyState,
    user_data: TBl,
}

enum BodyState {
    Needed,
    NotNeeded,
    Known,
}

/// Utility. Calculates the blake2 hash of the given bytes.
fn blake2_hash(bytes: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(blake2_rfc::blake2b::blake2b(32, &[], bytes).as_bytes()).unwrap()
}
