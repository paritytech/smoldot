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

//! General-purpose transactions pool.
//!
//! The transactions pool is a complex data structure that holds a list of pending transactions,
//! in other words transactions that should later be included in blocks, and a list of
//! transactions that have been included in non-finalized blocks.
//!
//! See the [parent module's documentation](..) for an overview of transactions.
//!
//! # Overview
//!
//! The transactions pool stores a list of transactions that the local node desires to include in
//! blocks, and a list of transactions that have already been included in blocks. Each of these
//! transactions is either validated or not. A transaction in a block is assumed to always succeed
//! validation. A validated transaction that isn't present in any block is a transaction that is
//! assumed to be includable in a block in the future.
//!
//! The order in which transactions can be included in a block follows a complex system of
//! "provided" and "required" tags. A transaction that *requires* some tags can only be included
//! after all these tags have been *provided* by transactions earlier in the chain.
//!
//! The transactions pool isn't only about deciding which transactions to include in a block when
//! authoring, but also about tracking the status of interesting transactions between the moment
//! they become interesting and the moment the block they are included in becomes finalized. This
//! is relevant both if the local node can potentially author blocks or not.
//!
//! The transactions pool tracks the height of the *best* chain, and only of the best chain. More
//! precisely, it is aware of the height of the current best block. Forks are tracked.
//!
//! # Usage
//!
//! A [`Pool`] is a collection of transactions. Each transaction in the pool exposes three
//! properties:
//!
//! - Whether or not it has been validated, and if yes, the block against which it has been
//! validated and the characteristics of the transaction (as provided by the runtime): the tags it
//! provides and requires, its longevity, and its priority. See [the `validate` module](../validate)
//! for more information.
//! - The height of the block, if any, in which the transaction has been included.
//! - A so-called user data, an opaque field controller by the API user.
//!
//! Use [`Pool::add_unvalidated`] to add to the pool a transaction that should be included in a
//! block at a later point in time.
//!
//! Use [`Pool::append_block`] and [`Pool::retract_blocks`] when a new block is considered as
//! best in order to let the [`Pool`] track the state of the best block of the chain. The
//! block bodies that are passed to [`Pool::append_block`] are added to the pool.
//!
//! Use [`Pool::unvalidated_transactions`] to obtain the list of transactions that should be
//! validated. Validation should be performed using the [`validate`](../validate) module, and
//! the result reported with [`Pool::set_validation_result`].
//!
//! Use [`Pool::remove_included`] when a block has been finalized to remove from the pool the
//! transactions that are present in the finalized block and below.
//!
//! # Out of scope
//!
//! The following are examples of things that are related transactions pool to but out of scope of
//! this data structure:
//!
//! - Watching the state of transactions.
//! - Sending transactions to other peers.
//!

// TODO: this code is completely untested

use super::validate::{TransactionValidityError, ValidTransaction};

use alloc::{collections::BTreeSet, vec::Vec};
use core::{convert::TryFrom as _, fmt};
use hashbrown::HashSet;

/// Identifier of a transaction stored within the [`Pool`].
///
/// Identifiers can be re-used by the pool. In other words, a transaction id can compare equal to
/// an older transaction id that is no longer in the pool.
//
// Implementation note: corresponds to indices within [`Pool::transactions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransactionId(usize);

/// Configuration for [`Pool::new`].
pub struct Config {
    /// Number of transactions to initially allocate memory for.
    ///
    /// > **Note**: This should take into account the fact that the pool will contain the
    /// >           transactions included in new blocks. In other words, it should be equal to
    /// >           `expected_max_reorg_depth * expected_max_transactions_per_block +
    /// >           max_concurrent_desired_transactions`.
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
pub struct Pool<TTx> {
    /// Actual list of transactions.
    transactions: slab::Slab<Transaction<TTx>>,

    /// List of transactions (represented as indices within [`Pool::transactions`]) whose status
    /// is "not validated".
    not_validated: HashSet<TransactionId, fnv::FnvBuildHasher>,

    /// Transaction ids (i.e. indices within [`Pool::transactions`]) indexed by the blake2 hash
    /// of the bytes of the transaction.
    by_hash: BTreeSet<([u8; 32], TransactionId)>,

    /// Transaction ids (i.e. indices within [`Pool::transactions`]) indexed by the block height
    /// in which the transaction is included.
    by_height: BTreeSet<(u64, TransactionId)>,

    /// Height of the latest best block, as known from the pool.
    best_block_height: u64,
}

impl<TTx> Pool<TTx> {
    /// Initializes a new transactions pool.
    pub fn new(config: Config) -> Self {
        Pool {
            transactions: slab::Slab::with_capacity(config.capacity),
            not_validated: HashSet::with_capacity_and_hasher(config.capacity, Default::default()),
            by_hash: BTreeSet::new(),
            by_height: BTreeSet::new(),
            best_block_height: config.finalized_block_height,
        }
    }

    /// Returns true if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Returns the number of transactions in the pool.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Inserts a new unvalidated transaction in the pool.
    pub fn add_unvalidated(
        &mut self,
        scale_encoded: Vec<u8>,
        user_data: TTx,
    ) -> TransactionId {
        self.add_unvalidated_inner(scale_encoded, None, user_data)
    }

    /// Inserts a new unvalidated transaction in the pool.
    fn add_unvalidated_inner(
        &mut self,
        scale_encoded: impl AsRef<[u8]> + Into<Vec<u8>>,
        included_block_height: Option<u64>,
        user_data: TTx,
    ) -> TransactionId {
        let hash = blake2_hash(scale_encoded.as_ref());

        let tx_id = TransactionId(self.transactions.insert(Transaction {
            scale_encoded: scale_encoded.into(),
            validation: None,
            included_block_height,
            user_data,
        }));

        let _was_inserted = self.by_hash.insert((hash, tx_id));
        debug_assert!(_was_inserted);

        let _was_inserted = self.not_validated.insert(tx_id);
        debug_assert!(_was_inserted);

        if let Some(included_block_height) = included_block_height {
            let _was_inserted = self.by_height.insert((included_block_height, tx_id));
            debug_assert!(_was_inserted);
        }

        tx_id
    }

    /// Removes from the pool the transaction with the given identifier.
    ///
    /// # Panic
    ///
    /// Panics if the identifier is invalid.
    ///
    #[track_caller]
    pub fn remove(&mut self, id: TransactionId) -> TTx {
        let tx = self.transactions.remove(id.0); // Panics if `id` is invalid.

        if tx.validation.is_none() {
            let _removed = self.not_validated.remove(&id);
            debug_assert!(_removed);
        }

        if let Some(included_block_height) = tx.included_block_height {
            let _removed = self.by_height.remove(&(included_block_height, id));
            debug_assert!(_removed);
        }

        let _removed = self
            .by_hash
            .remove(&(blake2_hash(&tx.scale_encoded), id));
        debug_assert!(_removed);

        tx.user_data
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
        let to_remove = self
            .by_height
            .range(
                (u64::min_value(), TransactionId(usize::min_value()))
                    ..=(block_inferior_of_equal, TransactionId(usize::max_value())),
            )
            .map(|(_, tx_id)| *tx_id)
            .collect::<Vec<_>>();

        // TODO: implement more efficiently by not allocating this `out` Vec but removing directly in iterator
        let mut out = Vec::with_capacity(to_remove.len());

        for tx_id in to_remove {
            let tx = self.transactions.remove(tx_id.0);
            out.push((tx_id, tx.user_data));

            debug_assert!(tx.included_block_height.is_some());

            if tx.validation.is_none() {
                let _removed = self.not_validated.remove(&tx_id);
                debug_assert!(_removed);
            }

            let _removed = self
                .by_hash
                .remove(&(blake2_hash(&tx.scale_encoded), tx_id));
            debug_assert!(_removed);
        }

        out.into_iter()
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
                .map(|n| n.checked_sub(1).unwrap())
                .unwrap_or(self.best_block_height);
            (tx_id, &tx.user_data, height)
        })
    }

    /// Returns the transactions from the pool that haven't been included yet in the order in
    /// which they should be inserted in authored blocks.
    pub fn inclusion_order(&'_ self) -> impl Iterator<Item = TransactionId> + '_ {
        // FIXME: /!\
        // TODO: /!\
        #![allow(unreachable_code)]
        let _i: core::iter::Empty<_> = todo!();
        _i
    }

    /// Returns the list of all transactions within the pool.
    pub fn iter(&'_ self) -> impl Iterator<Item = (TransactionId, &'_ TTx)> + '_ {
        self.transactions
            .iter()
            .map(|(id, tx)| (TransactionId(id), &tx.user_data))
    }

    /// Returns the list of all transactions within the pool.
    pub fn iter_mut(&'_ mut self) -> impl Iterator<Item = (TransactionId, &'_ mut TTx)> + '_ {
        self.transactions
            .iter_mut()
            .map(|(id, tx)| (TransactionId(id), &mut tx.user_data))
    }

    /// Returns the user data associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn user_data(&self, id: TransactionId) -> Option<&TTx> {
        Some(&self.transactions.get(id.0)?.user_data)
    }

    /// Returns the user data associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn user_data_mut(&mut self, id: TransactionId) -> Option<&mut TTx> {
        Some(&mut self.transactions.get_mut(id.0)?.user_data)
    }

    /// Returns the block height at which the given transaction has been included.
    ///
    /// A transaction has been included if it has been added to the pool with
    /// [`Pool::append_block`].
    ///
    /// Returns `None` if the identifier is invalid or the transaction doesn't belong to any
    /// block.
    pub fn included_block_height(&self, id: TransactionId) -> Option<u64> {
        self.transactions.get(id.0)?.included_block_height
    }

    /// Returns the bytes associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn scale_encoding(&self, id: TransactionId) -> Option<&[u8]> {
        Some(&self.transactions.get(id.0)?.scale_encoded)
    }

    /// Tries to find a transaction in the pool whose bytes are `scale_encoded`.
    pub fn find(&'_ self, scale_encoded: &[u8]) -> impl Iterator<Item = TransactionId> + '_ {
        let hash = blake2_hash(scale_encoded);
        self.by_hash
            .range(
                (hash, TransactionId(usize::min_value()))
                    ..=(hash, TransactionId(usize::max_value())),
            )
            .map(|(_, tx_id)| *tx_id)
    }

    /// Returns the best block height according to the pool.
    ///
    /// This initially corresponds to the value in [`Config::finalized_block_height`], is
    /// incremented by one every time [`Pool::append_block`], and is decreased when
    /// [`Pool::retract_blocks`] is called.
    pub fn best_block_height(&self) -> u64 {
        self.best_block_height
    }

    /// Adds a block to the chain tracked by the transactions pool.
    ///
    /// This function returns an [`AppendBlock`] struct that wraps around the [`Pool`] and lets
    /// you insert transactions that belong to the body of the new block.
    pub fn append_block(mut self) -> AppendBlock<TTx> {
        self.best_block_height = self.best_block_height.checked_add(1).unwrap();

        // Un-validate non-included transactions whose longevity has expired.
        // TODO: O(n) :-/
        for (_, tx) in &mut self.transactions {
            if tx.included_block_height.is_some() {
                continue;
            }

            match tx.validation {
                Some((block_validated, Ok(ValidTransaction { longevity, .. })))
                    if block_validated.saturating_add(longevity.get())
                        <= self.best_block_height =>
                {
                    tx.validation = None;
                }
                _ => {}
            };
        }

        AppendBlock { inner: self }
    }

    /// Pop a certain number of blocks from the list of blocks.
    ///
    /// Transations that were included in these blocks remain in the transactions pool.
    ///
    /// Returns the list of transactions that were in blocks that have been retracted, with the
    /// height of the block at which they were.
    ///
    /// # Panic
    ///
    /// Panics if `num_to_retract > self.best_block_height()`, in other words if the block number
    /// would go in the negative.
    ///
    pub fn retract_blocks(
        &mut self,
        num_to_retract: u64,
    ) -> impl Iterator<Item = (TransactionId, u64)> {
        // Checks that there's no transaction included above `self.best_block_height`.
        debug_assert!(self
            .by_height
            .range(
                (
                    self.best_block_height + 1,
                    TransactionId(usize::min_value()),
                )..,
            )
            .next()
            .is_none());

        // Update `best_block_height` as first step, in order to panic sooner in case of underflow.
        self.best_block_height = self.best_block_height.checked_sub(num_to_retract).unwrap();

        // List of transactions that were included in these blocks.
        let transactions_to_retract = self
            .by_height
            .range(
                (
                    self.best_block_height + 1,
                    TransactionId(usize::min_value()),
                )..,
            )
            .map(|(block_height, tx_id)| (*tx_id, *block_height))
            .collect::<Vec<_>>();

        // Set `included_block_height` to `None` for each of them.
        for (transaction_id, _) in &transactions_to_retract {
            let mut tx_data = self.transactions.get_mut(transaction_id.0).unwrap();
            debug_assert!(tx_data.included_block_height.unwrap() > self.best_block_height);
            tx_data.included_block_height = None;
        }

        // Must cancel validation results against blocks that have been retracted.
        // TODO: this is O(n), do better
        for (_, transaction) in &mut self.transactions {
            let best_block_height = self.best_block_height;
            if transaction
                .validation
                .as_ref()
                .map_or(false, |(b, _)| *b > best_block_height)
            {
                transaction.validation = None;
            }
        }

        // Return retracted transactions from highest block to lowest block.
        transactions_to_retract.into_iter().rev()
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
        result: Result<ValidTransaction, TransactionValidityError>,
    ) {
        let tx = self.transactions.get_mut(id.0).unwrap();

        // If the transaction has been included in a block, immediately return if the validation
        // has been performed against a different block.
        if tx
            .included_block_height
            .map_or(false, |b| b != block_number_validated_against + 1)
        {
            return;
        }

        tx.validation = Some((block_number_validated_against, result));
    }
}

impl<TTx: fmt::Debug> fmt::Debug for Pool<TTx> {
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

/// Wraps around [`Pool`] while a new best block is being inserted. See [`Pool::append_block`].
#[must_use]
pub struct AppendBlock<TTx> {
    /// The pool. The best block number has already been incremented.
    inner: Pool<TTx>,
}

impl<TTx> AppendBlock<TTx> {
    /// Adds a single-SCALE-encoded transaction to the block being appended.
    ///
    /// The transaction is compared against the list of non-included transactions that are already
    /// in the pool. If a non-included transaction with the same bytes is found, it is switched to
    /// the "included" state and  [`AppendBlockTransaction::NonIncludedUpdated`] is returned.
    /// Otherwise, [`AppendBlockTransaction::Unknown`] is returned and the transaction can be
    /// inserted in the pool.
    // TODO: update for the fact that it's a single-encoded transaction
    pub fn block_transaction<'a, 'b>(
        &'a mut self,
        bytes: &'b [u8],
    ) -> AppendBlockTransaction<'a, 'b, TTx> {
        let hash = blake2_hash(bytes);

        // Try find a non-included transaction with that hash.
        let non_included = self
            .inner
            .by_hash
            .range(
                (hash, TransactionId(usize::min_value()))
                    ..=(hash, TransactionId(usize::max_value())),
            )
            .find(|(_, tx_id)| {
                self.inner
                    .transactions
                    .get(tx_id.0)
                    .unwrap()
                    .included_block_height
                    .is_none()
            })
            .map(|(_, tx_id)| *tx_id);

        // If `non_included` is `Some`, check that its bytes are actually equal to `bytes`.
        debug_assert!(non_included.map_or(true, |id| self
            .inner
            .transactions
            .get(id.0)
            .unwrap()
            .scale_encoded
            == bytes));

        match non_included {
            Some(id) => {
                // Update the transaction stored in the pool.
                let tx = self.inner.transactions.get_mut(id.0).unwrap();
                let best_block_height = self.inner.best_block_height;

                debug_assert!(tx.included_block_height.is_none());
                tx.included_block_height = Some(best_block_height);

                if tx
                    .validation
                    .as_ref()
                    .map_or(false, |(b, _)| *b + 1 != best_block_height)
                {
                    tx.validation = None;
                }

                let user_data = &mut tx.user_data;
                AppendBlockTransaction::NonIncludedUpdated { id, user_data }
            }
            None => AppendBlockTransaction::Unknown(Vacant {
                inner: &mut self.inner,
                bytes,
            }),
        }
    }

    /// Finishes the block insertion process.
    pub fn finish(self) -> Pool<TTx> {
        self.inner
    }
}

impl<TTx: fmt::Debug> fmt::Debug for AppendBlock<TTx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, f)
    }
}

/// See [`AppendBlock::block_transaction`].
#[derive(Debug)]
pub enum AppendBlockTransaction<'a, 'b, TTx> {
    /// Transaction to add isn't in the list of non-included transactions. It can be added to the
    /// pool.
    Unknown(Vacant<'a, 'b, TTx>),
    /// Transaction to add is present in the list of non-included transactions. It is now
    /// considered included.
    NonIncludedUpdated {
        /// Identifier of the non-included transaction with the same bytes.
        id: TransactionId,
        /// User data stored alongside with that transaction.
        user_data: &'a mut TTx,
    },
}

/// See [`AppendBlockTransaction::Unknown`].
pub struct Vacant<'a, 'b, TTx> {
    inner: &'a mut Pool<TTx>,
    bytes: &'b [u8],
}

impl<'a, 'b, TTx> Vacant<'a, 'b, TTx> {
    /// Inserts the transaction in the pool.
    pub fn insert(self, user_data: TTx) -> TransactionId {
        self.inner
            .add_unvalidated_inner(self.bytes, Some(self.inner.best_block_height), user_data)
    }
}

impl<'a, 'b, TTx: fmt::Debug> fmt::Debug for Vacant<'a, 'b, TTx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, f)
    }
}

/// Entry in [`Pool::transactions`].
struct Transaction<TTx> {
    /// Bytes corresponding to the SCALE-encoded transaction.
    scale_encoded: Vec<u8>,

    /// If `Some`, contains the outcome of the validation of this transaction and the block height
    /// it was validated against.
    validation: Option<(u64, Result<ValidTransaction, TransactionValidityError>)>,

    /// If `Some`, the height of the block at which the transaction has been included.
    included_block_height: Option<u64>,

    /// User data chosen by the user.
    user_data: TTx,
}

/// Utility. Calculates the blake2 hash of the given bytes.
fn blake2_hash(bytes: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(blake2_rfc::blake2b::blake2b(32, &[], bytes).as_bytes()).unwrap()
}

// TODO: needs tests
