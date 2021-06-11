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

use alloc::{collections::BTreeSet, vec::Vec};
use core::{convert::TryFrom as _, fmt, iter, num::NonZeroU64};
use hashbrown::HashSet;

pub use pool::TransactionId;

/// Configuration for [`Pool::new`].
pub struct Config {
    /// Number of transactions to initially allocate memory for.
    pub capacity: usize,

    /// Height of the finalized block at initialization.
    ///
    /// The [`Pool`] doesn't track which block is finalized. This value is only used to initialize
    /// the best block number. The field could also have been called `best_block_height`, but it
    /// might have created confusion.
    ///
    /// Non-finalized blocks should be added to the pool after initialization using
    /// [`Pool::append_block`].
    pub finalized_block_height: u64,
}

/// Data structure containing transactions. See the module-level documentation for more info.
pub struct LightPool<TTx> {
    /// Inner transactions pool.
    pool: pool::Pool<TTx>,

    /// Tree of all the non-finalized blocks. This is necessary in case of a re-org (i.e. the new
    /// best block is a nephew of the previous best block) in order to know which transactions
    /// that were present in the previous best chain are still present in the new best chain.
    // TODO: add a maximum size?
    blocks_tree: fork_tree::ForkTree<Block>,

    /// Index of the best block in [`LightPool::blocks_tree`].
    /// `None` if the tree is empty and that the best block is also the latest finalized block.
    best_block_index: Option<fork_tree::NodeIndex>,

    /// Height and hash of the latest finalized block. Root of all the blocks in
    /// [`LightPool::blocks_tree`].
    latest_finalized_block: (u64, [u8; 32]),
}

impl<TTx> LightPool<TTx> {
    /// Initializes a new transactions pool.
    pub fn new(config: Config) -> Self {
        LightPool {
            pool: todo!(),
            blocks_tree: fork_tree::ForkTree::with_capacity(0), // TODO: capacity?
            best_block_index: None,
            latest_finalized_block: todo!(),
        }
    }

    /// Removes all transactions from the pool, and sets the current best block height to the
    /// value passed as parameter.
    pub fn clear_and_reset(&mut self, new_best_block_height: u64) {
        self.pool.clear_and_reset(new_best_block_height);
    }

    /// Returns true if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }

    /// Returns the number of transactions in the pool.
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Inserts a new unvalidated transaction in the pool.
    pub fn add_unvalidated(&mut self, scale_encoded: Vec<u8>, user_data: TTx) -> TransactionId {
        self.pool.add_unvalidated(scale_encoded, user_data)
    }

    /// Removes from the pool the transaction with the given identifier.
    ///
    /// # Panic
    ///
    /// Panics if the identifier is invalid.
    ///
    #[track_caller]
    pub fn remove(&mut self, id: TransactionId) -> TTx {
        self.pool.remove(id)
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
        self.pool.remove_included(block_inferior_of_equal)
    }

    /// Returns a list of transactions whose state is "not validated", their user data, and the
    /// height of the block they should be validated against.
    ///
    /// The block height a transaction should be validated against is always equal to either the
    /// block at which it has been included minus one, or the current best block. It is yielded by
    /// the iterator for convenience, to avoid writing error-prone code.
    pub fn unvalidated_transactions(
        &'_ self,
    ) -> impl ExactSizeIterator<Item = (TransactionId, &TTx, u64)> + '_ {
        self.not_validated.iter().copied().map(move |tx_id| {
            let tx = self.transactions.get(tx_id.0).unwrap();
            let height = tx
                .included_block_height
                .unwrap_or(self.best_block_height)
                .checked_sub(1)
                .unwrap();
            (tx_id, &tx.user_data, height)
        })
    }

    /// Returns the list of all transactions within the pool.
    pub fn iter(&'_ self) -> impl Iterator<Item = (TransactionId, &'_ TTx)> + '_ {
        self.pool.iter()
    }

    /// Returns the list of all transactions within the pool.
    pub fn iter_mut(&'_ mut self) -> impl Iterator<Item = (TransactionId, &'_ mut TTx)> + '_ {
        self.pool.iter_mut()
    }

    /// Returns the user data associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn user_data(&self, id: TransactionId) -> Option<&TTx> {
        self.pool.user_data(id)
    }

    /// Returns the user data associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn user_data_mut(&mut self, id: TransactionId) -> Option<&mut TTx> {
        self.pool.user_data_mut(id)
    }

    /// Returns the block height at which the given transaction has been included.
    ///
    /// A transaction has been included if it has been added to the pool with
    /// [`Pool::append_block`].
    ///
    /// Returns `None` if the identifier is invalid or the transaction doesn't belong to any
    /// block.
    pub fn included_block_height(&self, id: TransactionId) -> Option<u64> {
        self.pool.included_block_height(id)
    }

    /// Returns the bytes associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn scale_encoding(&self, id: TransactionId) -> Option<&[u8]> {
        self.pool.scale_encoding(id)
    }

    /// Tries to find a transaction in the pool whose bytes are `scale_encoded`.
    pub fn find(&'_ self, scale_encoded: &[u8]) -> impl Iterator<Item = TransactionId> + '_ {
        self.pool.find(scale_encoded)
    }

    /// Adds a block to the collection of blocks.
    ///
    /// Has no effect if that block was already present in the collection.
    ///
    /// # Panic
    ///
    /// Panics if the parent block cannot be found in the collection.
    ///
    pub fn add_block(&mut self, hash: [u8; 32], height: NonZeroU64, parent_hash: &[u8; 32]) {
        let parent_index_in_tree = if *parent_hash == self.latest_finalized_block.1 {
            None
        } else {
            // The transactions service tracks all new blocks.
            // The parent of each new best block must therefore already be in the tree.
            Some(self.blocks_tree.find(|b| b.hash == *parent_hash).unwrap())
        };

        self.blocks_tree.insert(
            parent_index_in_tree,
            Block {
                hash,
                height,
                body: todo!(),
            },
        );
    }

    /// Sets the passed block as the new best block of the chain.
    ///
    /// # Panic
    ///
    /// Panics if no block with the given hash and height hasn't been inserted before.
    ///
    pub fn set_best_block(&mut self, new_best_block_hash: &[u8; 32], new_best_block_height: u64) {
        let new_best_block_index = self
            .blocks_tree
            .find(|b| b.height.get() == new_best_block_height && b.hash == *new_best_block_hash)
            .unwrap();

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

        // Iterate over the nodes that used to be part of the best chain but no longer are.
        for node_index in old_best_to_common_ancestor {
            let block_info = self.blocks_tree.get(node_index).unwrap();
            if let DownloadStatus::Success(transactions) = &block_info.download_status {
                for transaction in transactions {
                    let list = self
                        .pending_transactions
                        .user_data_mut(transaction)
                        .unwrap();
                    send_or_drop(
                        &mut list.status_update,
                        TransactionStatus::Retracted(block_info.hash),
                    );
                }
            }
        }

        self.best_block_index = Some(new_best_block_index);
    }

    /// Sets the list of transactions that are present in the body of a block.
    ///
    /// Returns the list of transactions that are in the pool and that were found in the body.
    ///
    /// # Panic
    ///
    /// Panics if no block with the given hash and height hasn't been inserted before.
    ///
    pub fn set_block_body(
        &mut self,
        block_hash: &[u8; 32],
        block_height: u64,
        body: impl Iterator<Item = impl AsRef<[u8]>>,
    ) -> impl Iterator<Item = (TransactionId, &'_ TTx)> {
        let block_index = self
            .blocks_tree
            .find(|b| b.height.get() == block_height && b.hash == *block_hash)
            .unwrap();

        let is_in_best_chain = self
            .blocks_tree
            .is_ancestor(self.best_block_index.unwrap(), block_index);

        core::iter::empty() // TODO:
    }

    /// Returns the list of blocks of the best chain whose bodies aren't present in this data
    /// structure.
    pub fn best_chain_missing_block_bodies(
        &'_ self,
    ) -> impl Iterator<Item = (u64, &'_ [u8; 32])> + '_ {
        if let Some(best_block_index) = self.best_block_index {
            either::Left(
                self.blocks_tree
                    .root_to_node_path(best_block_index)
                    .filter_map(move |node_index| {
                        let block = self.blocks_tree.get(node_index).unwrap();
                        if false {
                            // TODO:
                            return None;
                        }
                        Some((0, &block.hash)) // TODO:
                    }),
            )
        } else {
            either::Right(core::iter::empty())
        }
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
        self.pool
            .set_validation_result(id, block_number_validated_against, result)
    }
}

impl<TTx: fmt::Debug> fmt::Debug for LightPool<TTx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.pool, f)
    }
}

struct Block {
    hash: [u8; 32],
    height: NonZeroU64,
    body: BodyState,
}

enum BodyState {
    /// Download hasn't been started yet.
    NotStarted,
    /// One of the futures in [`Worker::block_downloads`] is current downloading the body of this
    /// block.
    Downloading,
    /// Failed to download block body.
    /// This can legitimately happen if all the other nodes we are connected to have discarded
    /// this block.
    Failed,
    /// Successfully downloaded block body. Contains the list of extrinsics that we have sent
    /// out.
    Success,
}

// TODO: needs tests
