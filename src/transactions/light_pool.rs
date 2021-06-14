// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
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
//! Contrary to [`pool::Pool`], this data structure is opinionated towards a certain light client
//! usage. This means:
//!
//! - Block bodies are initially unknown and can be added later.
//! - Transactions included in block bodies that weren't already in the pool aren't added, and
//! thus also don't need to be validated.
//! - The [`LightPool`] tracks all forks, not just the best chain, so as to not require fetching
//! again later the block bodies that are already known in case of a double re-org.
//!

use super::{
    pool,
    validate::{InvalidTransaction, ValidTransaction},
};
use crate::chain::fork_tree;

use alloc::vec::Vec;
use core::{convert::TryFrom as _, fmt, iter};

pub use pool::TransactionId;

/// Configuration for [`Pool::new`].
pub struct Config {
    /// Number of transactions to initially allocate memory for.
    pub transactions_capacity: usize,

    /// Number of blocks to initially allocate memory for.
    pub blocks_capacity: usize,

    /// Hash of the finalized block at initialization.
    ///
    /// Non-finalized blocks should be added to the pool after initialization using
    /// [`Pool::append_block`].
    pub finalized_block: [u8; 32],
}

/// Data structure containing transactions. See the module-level documentation for more info.
pub struct LightPool<TTx, TBl> {
    /// Inner transactions pool.
    ///
    /// Always contains `Some`, except temporarily to use [`pool::Pool::append_block`].
    ///
    /// The block heights reported by this pool are not *actual* block heights. Instead, the
    /// finalized block passed at initialization by the user is always block number 0.
    pool: Option<pool::Pool<TTx>>,

    /// Tree of all the non-finalized blocks. This is necessary in case of a re-org (i.e. the new
    /// best block is a nephew of the previous best block) in order to know which transactions
    /// that were present in the previous best chain are still present in the new best chain.
    // TODO: add a maximum size?
    blocks_tree: fork_tree::ForkTree<Block<TBl>>,

    /// Contains all blocks in [`LightPool::blocks_tree`], indexed by their hash.
    blocks_by_id: hashbrown::HashMap<[u8; 32], fork_tree::NodeIndex, fnv::FnvBuildHasher>,

    /// Index of the best block in [`LightPool::blocks_tree`].
    /// `None` if the tree is empty and that the best block is also the latest finalized block.
    best_block_index: Option<fork_tree::NodeIndex>,

    /// As explained in [`LightPool::pool`], the block heights in the underlying pool aren't the
    /// *actual* block heights. This field contains the block height that the current best block
    /// has in the underlying pool. It is set even if the current best block hasn't been included
    /// in the underlying pool yet.
    best_block_virtual_height: u64,

    /// Hash of the latest finalized block. Root of all the blocks in [`LightPool::blocks_tree`].
    latest_finalized_block: [u8; 32],
}

impl<TTx, TBl> LightPool<TTx, TBl> {
    /// Initializes a new transactions pool.
    pub fn new(config: Config) -> Self {
        LightPool {
            pool: Some(pool::Pool::new(pool::Config {
                capacity: config.transactions_capacity,
                // As explained in the doc of `pool`, the block numbers of the pool aren't the
                // actual block heights.
                finalized_block_height: 0,
            })),
            blocks_tree: fork_tree::ForkTree::with_capacity(config.blocks_capacity),
            blocks_by_id: hashbrown::HashMap::with_capacity_and_hasher(
                config.blocks_capacity,
                Default::default(),
            ),
            best_block_index: None,
            // Must match the finalized block height passed to the underlying pool.
            best_block_virtual_height: 0,
            latest_finalized_block: config.finalized_block,
        }
    }

    /// Removes all transactions from the pool, and sets the current best block height to the
    /// value passed as parameter.
    // TODO: change
    pub fn clear_and_reset(&mut self, new_best_block_height: u64) {
        self.pool
            .as_mut()
            .unwrap()
            .clear_and_reset(new_best_block_height);
    }

    /// Returns the number of transactions in the pool.
    pub fn num_transactions(&self) -> usize {
        self.pool.as_ref().unwrap().len()
    }

    /// Inserts a new unvalidated transaction in the pool.
    pub fn add_unvalidated(&mut self, scale_encoded: Vec<u8>, user_data: TTx) -> TransactionId {
        self.pool
            .as_mut()
            .unwrap()
            .add_unvalidated(scale_encoded, user_data)
    }

    /// Removes from the pool the transaction with the given identifier.
    ///
    /// # Panic
    ///
    /// Panics if the identifier is invalid.
    ///
    #[track_caller]
    pub fn remove_transaction(&mut self, id: TransactionId) -> TTx {
        self.pool.as_mut().unwrap().remove(id)
    }

    /// Removes from the pool all the transactions that are included in a block whose height is
    /// inferior or equal to the one passed as parameter.
    ///
    /// Use this method when a block has been finalized.
    ///
    /// The returned iterator is guaranteed to remove all transactions even if it is dropped
    /// eagerly.
    pub fn remove_included(
        &'_ mut self,
        block_inferior_of_equal: u64,
    ) -> impl Iterator<Item = (TransactionId, TTx)> + '_ {
        self.pool
            .as_mut()
            .unwrap()
            .remove_included(block_inferior_of_equal)
    }

    /// Returns a list of transactions whose state is "not validated", and their user data.
    ///
    /// These transactions should always be validated against the current best block.
    pub fn unvalidated_transactions(
        &'_ self,
    ) -> impl ExactSizeIterator<Item = (TransactionId, &'_ TTx)> + '_ {
        self.pool.as_ref().unwrap().unvalidated_transactions().map(
            move |(tx_id, tx_user_data, _block_height)| {
                debug_assert_eq!(
                    _block_height,
                    self.pool.as_ref().unwrap().best_block_height()
                );

                (tx_id, tx_user_data)
            },
        )
    }

    // TODO: unneeded?
    fn virtual_block_height_to_block_index(
        &self,
        virtual_height: u64,
    ) -> Option<fork_tree::NodeIndex> {
        //
        //       virtual_height
        //         +
        //         v
        //
        // B - B - B - B                             self.pool
        //
        // B - B - B - B - B - B                     self.blocks_tree
        //
        //                     ^
        //                     +
        //                   self.best_block_virtual_height
        //                   self.best_block_index
        //
        let diff = self
            .best_block_virtual_height
            .checked_sub(virtual_height)
            .unwrap();

        if let Some(best_block_index) = self.best_block_index {
            let mut index = Some(best_block_index);
            for _ in 0..diff {
                index = self.blocks_tree.parent(index.unwrap());
            }
            index
        } else {
            // If `best_block_index` is `None`, then `self.blocks_tree` is empty.
            assert_eq!(diff, 0);
            None
        }
    }

    /// Returns the list of all transactions within the pool.
    pub fn transactions_iter(&'_ self) -> impl Iterator<Item = (TransactionId, &'_ TTx)> + '_ {
        self.pool.as_ref().unwrap().iter()
    }

    /// Returns the list of all transactions within the pool.
    pub fn transactions_iter_mut(
        &'_ mut self,
    ) -> impl Iterator<Item = (TransactionId, &'_ mut TTx)> + '_ {
        self.pool.as_mut().unwrap().iter_mut()
    }

    /// Returns the user data associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn transaction_user_data(&self, id: TransactionId) -> Option<&TTx> {
        self.pool.as_ref().unwrap().user_data(id)
    }

    /// Returns the user data associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn transaction_user_data_mut(&mut self, id: TransactionId) -> Option<&mut TTx> {
        self.pool.as_mut().unwrap().user_data_mut(id)
    }

    /// Returns the bytes associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn scale_encoding(&self, id: TransactionId) -> Option<&[u8]> {
        self.pool.as_ref().unwrap().scale_encoding(id)
    }

    /// Tries to find a transaction in the pool whose bytes are `scale_encoded`.
    pub fn find_transaction(
        &'_ self,
        scale_encoded: &[u8],
    ) -> impl Iterator<Item = TransactionId> + '_ {
        self.pool.as_ref().unwrap().find(scale_encoded)
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
        let parent_index_in_tree = if *parent_hash == self.latest_finalized_block {
            None
        } else {
            // The transactions service tracks all new blocks.
            // The parent of each new best block must therefore already be in the tree.
            Some(*self.blocks_by_id.get(parent_hash).unwrap())
        };

        let entry = match self.blocks_by_id.entry(hash) {
            hashbrown::hash_map::Entry::Occupied(_) => return,
            hashbrown::hash_map::Entry::Vacant(e) => e,
        };

        let block_index = self.blocks_tree.insert(
            parent_index_in_tree,
            Block {
                hash,
                body: if self.pool.as_ref().unwrap().is_empty() {
                    BodyState::NotNeeded
                } else {
                    BodyState::Needed
                },
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
        let new_best_block_index = *self.blocks_by_id.get(new_best_block_hash).unwrap();

        // Iterators over the potential re-org. Used below to report the transaction status
        // updates.
        let (old_best_to_common_ancestor, common_ancestor_to_new_best) =
            if let Some(old_best_index) = self.best_block_index {
                let (ascend, descend) = self
                    .blocks_tree
                    .ascend_and_descend(old_best_index, new_best_block_index);
                (either::Left(ascend), either::Left(descend))
            } else {
                let ascend = self.blocks_tree.node_to_root_path(new_best_block_index);
                let descend = iter::empty::<fork_tree::NodeIndex>();
                (either::Right(ascend), either::Right(descend))
            };

        // Blocks in `self.pool` correspond to the longest serie of consecutive blocks whose body
        // is known. We need to retract them.
        let mut retracted_transactions = Vec::new();

        for to_retract_index in old_best_to_common_ancestor {
            // Runs unconditionally for each block. For this reason there's no `break` in the
            // rest of this loop.
            self.best_block_virtual_height -= 1;

            // If `self.best_block_virtual_height` is inferior to the pool's best, then we
            // need to retract.
            let need_to_retract =
                self.best_block_virtual_height < self.pool.as_ref().unwrap().best_block_height();
            if !need_to_retract {
                continue;
            }

            let to_retract = self.blocks_tree.get(to_retract_index).unwrap();
            debug_assert!(matches!(to_retract.body, BodyState::Known(_)));

            retracted_transactions.extend(
                self.pool
                    .as_mut()
                    .unwrap()
                    .retract_blocks(1)
                    .map(|(tx_id, _)| (tx_id, to_retract.hash)),
            );
        }

        debug_assert!(
            self.best_block_virtual_height >= self.pool.as_ref().unwrap().best_block_height()
        );

        // Insert in `self.pool` the new longest serie of consecutive best blocks whose body is
        // known.
        let mut included_transactions = Vec::new();
        for node_index in common_ancestor_to_new_best {
            // Runs unconditionally for each block. For this reason there's no `break` in the
            // rest of this loop.
            self.best_block_virtual_height += 1;

            // If the best block is a direct child (not a descendant) of the pool's best block,
            // then try to insert the block in that pool.
            let try_to_insert = self.best_block_virtual_height
                == self.pool.as_ref().unwrap().best_block_height() + 1;
            if !try_to_insert {
                continue;
            }

            let block = self.blocks_tree.get(node_index).unwrap();
            let block_body = match &block.body {
                BodyState::Known(b) => b,
                BodyState::NotNeeded | BodyState::Needed => continue,
            };

            let mut append_block = self.pool.take().unwrap().append_block();
            for transaction in block_body {
                match append_block.block_transaction(transaction) {
                    // Transaction in the block matches one of the transactions in the pool.
                    pool::AppendBlockTransaction::NonIncludedUpdated { id, .. } => {
                        included_transactions.push((id, block.hash));
                    }

                    // Transaction in the block isn't in the pool. In a full node situation, one
                    // would at this point insert the transaction in the pool, in order to:
                    // - Later validate it and prune obsolete non-inserted transaction.
                    // - Include the transaction in a block if the block it already is in is
                    // retracted.
                    // Neither of these points are relevant for this module, and as such we simply
                    // discard the object that would have let us insert said transaction.
                    pool::AppendBlockTransaction::Unknown(_insert) => {}
                }
            }

            self.pool = Some(append_block.finish());

            debug_assert_eq!(
                self.best_block_virtual_height,
                self.pool.as_ref().unwrap().best_block_height()
            );
        }

        self.best_block_index = Some(new_best_block_index);

        SetBestBlock {
            retracted_transactions,
            included_transactions,
        }
    }

    /// Sets the list of transactions that are present in the body of a block.
    ///
    /// Returns the list of transactions that are in the pool and that were found in the body.
    ///
    /// # Panic
    ///
    /// Panics if no block with the given hash has been inserted before.
    ///
    #[must_use]
    pub fn set_block_body(
        &'_ mut self,
        block_hash: &[u8; 32],
        body: impl Iterator<Item = impl Into<Vec<u8>>>,
    ) -> impl Iterator<Item = TransactionId> + '_ {
        let block_index = *self.blocks_by_id.get(block_hash).unwrap();

        self.blocks_tree.get_mut(block_index).unwrap().body =
            BodyState::Known(body.map(Into::into).collect());

        let is_in_best_chain = self.blocks_tree.is_ancestor(
            // `best_block_index` can only be `None` iff the list of blocks is empty, which we
            // know it can't be since `block_index` has been found. Hence safely unwrapping.
            self.best_block_index.unwrap(),
            block_index,
        );

        // Value returned from the function.
        let mut included_transactions = Vec::new();

        // Try add more blocks to `self.pool`.
        if is_in_best_chain
            && self.best_block_virtual_height == self.pool.as_ref().unwrap().best_block_height()
        // TODO: wrong /!\
        {
            for maybe_to_insert_index in self
                .blocks_tree
                .root_to_node_path(self.best_block_index.unwrap())
                .skip_while(|ni| *ni != block_index)
            {
                let maybe_to_insert_block = self.blocks_tree.get(maybe_to_insert_index).unwrap();
                /*debug_assert_eq!(
                    maybe_to_insert_block.height.get(),
                    self.pool.as_ref().unwrap().best_block_height() + 1
                );*/

                let block_body = match &maybe_to_insert_block.body {
                    BodyState::Known(b) => b,
                    BodyState::NotNeeded | BodyState::Needed => break,
                };

                let mut append_block = self.pool.take().unwrap().append_block();
                // TODO: DRY with other code above
                for transaction in block_body {
                    match append_block.block_transaction(transaction) {
                        // Transaction in the block matches one of the transactions in the pool.
                        pool::AppendBlockTransaction::NonIncludedUpdated { id, .. } => {
                            included_transactions.push(id);
                        }

                        // Transaction in the block isn't in the pool. In a full node situation, one
                        // would at this point insert the transaction in the pool, in order to:
                        // - Later validate it and prune obsolete non-inserted transaction.
                        // - Include the transaction in a block if the block it already is in is
                        // retracted.
                        // Neither of these points are relevant for this module, and as such we simply
                        // discard the object that would have let us insert said transaction.
                        pool::AppendBlockTransaction::Unknown(_insert) => {}
                    }
                }

                self.pool = Some(append_block.finish());
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

    /// Sets the outcome of validating the transaction with the given identifier.
    ///
    /// The block number must be the block number against which the transaction has been
    /// validated.
    ///
    /// The validation result might be ignored if it doesn't match one of the entries returned by
    /// [`Pool::unvalidated_transactions`].
    ///
    /// # Panic
    ///
    /// Panics if the transaction with the given id is invalid.
    ///
    pub fn set_validation_result(
        &mut self,
        id: TransactionId,
        block_number_validated_against: u64,
        result: Result<ValidTransaction, InvalidTransaction>,
    ) {
        self.pool.as_mut().unwrap().set_validation_result(
            id,
            block_number_validated_against,
            result,
        )
    }
}

impl<TTx: fmt::Debug, TBl> fmt::Debug for LightPool<TTx, TBl> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.pool, f)
    }
}

/// See [`LightPool::set_best_block`].
#[derive(Debug, Clone)]
pub struct SetBestBlock {
    /// List of transactions that were included in a block of the best chain but no longer are,
    /// and the hash of the block in which it was.
    ///
    /// Can share some entries with [`SetBestBlock::included_transactions`] in case a transaction
    /// has been retracted then included.
    pub retracted_transactions: Vec<(TransactionId, [u8; 32])>,

    /// List of transactions that weren't included in a block of the best chain but now are, and
    /// the hash of the block in which it was found.
    ///
    /// Can share some entries with [`SetBestBlock::retracted_transactions`] in case a transaction
    /// has been retracted then included.
    pub included_transactions: Vec<(TransactionId, [u8; 32])>,
}

struct Block<TBl> {
    hash: [u8; 32],
    body: BodyState,
    user_data: TBl,
}

enum BodyState {
    Needed,
    NotNeeded,
    Known(Vec<Vec<u8>>),
}

// TODO: needs tests
