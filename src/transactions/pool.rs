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

//! Transactions pool.
//!
//! The transactions pool is a complex data structure that holds a list of pending transactions,
//! in other words transactions that should later be included in blocks.
//!
//! See the [parent module's documentation](..) for an overview of transactions.
//!
//! # Overview
//!
//! The transactions pool stores a list of transactions that the local node desires to include in
//! blocks, and a list of transactions that have been included in blocks. Each of these
//! transactions is either validated or not. A transaction in a block is assumed to always succeed
//! validation. A validated transaction that isn't present in any block is a transaction that is
//! assumed to be includable in a block in the future.
//!
//! The order in which transactions can be included in a block follows a complex system of
//! "provided" and "required" tags. A transaction that *requires* some tags can only be included
//! after all these tags have been *provided* by transactions earlier in the chain.
//!
//! The transactions pool isn't only about deciding which transactions to include in a block when
//! authoring, but also about watching the status of transactions in the chain. This is relevant
//! both if the local node can potentially author blocks or not.
//!
//! The transactions pool tracks the height of the *best* chain, and only of the best chain. More
//! precisely, it is aware of the height of the current best block.
//!
//! # Details
//!
//! Each transaction exposes three properties:
//!
//! - Whether or not it has been validated, and if yes, the characteristics of the transactions
//! as provided by the runtime: the tags it provides and requires, its longevity, its priority.
//! - The height of the block, if any, in which the transaction has been included.
//! - A so-called user data, an opaque field controller by the API user.
//!

use super::validate::{InvalidTransaction, ValidTransaction};

use alloc::{collections::BTreeSet, vec::Vec};
use core::convert::TryFrom as _;
use hashbrown::{hash_map, HashMap, HashSet};

/// Identifier of a transaction stored within the [`Pool`].
///
/// Identifiers can be re-used. In other words, a transaction id can compare equal to an older
/// transaction id that is no longer in the pool.
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
    /// Non-finalized blocks should be added to the pool after initialization using
    /// [`Pool::append_block`].
    pub finalized_block_height: u64,

    /// Seed used for the randomness used within the transactions pool.
    ///
    /// The behaviour of the transactions pool is fully determinisic, but it uses randomness in
    /// order to avoid hash collision attacks.
    pub randomness_seed: [u8; 32],
}

/// Data structure containing transactions. See the module-level documentation for more info.
// TODO: impl Debug
pub struct Pool<TTx> {
    /// Actual list of transactions.
    transactions: slab::Slab<Transaction<TTx>>,

    /// List of transactions (represented as indices within [`Pool::transactions`]) whose status
    /// is "not validated".
    not_validated: HashSet<TransactionId, fnv::FnvBuildHasher>,

    /// Transaction ids (i.e. indices within [`Pool::transactions`]) indexed by the blake2 hash
    /// of the bytes of the transaction.
    by_hash: HashMap<[u8; 32], TransactionId, ahash::RandomState>,

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
            by_hash: HashMap::with_capacity_and_hasher(
                config.capacity,
                ahash::RandomState::with_seeds(
                    u64::from_ne_bytes(<[u8; 8]>::try_from(&config.randomness_seed[0..8]).unwrap()),
                    u64::from_ne_bytes(
                        <[u8; 8]>::try_from(&config.randomness_seed[8..16]).unwrap(),
                    ),
                    u64::from_ne_bytes(
                        <[u8; 8]>::try_from(&config.randomness_seed[16..24]).unwrap(),
                    ),
                    u64::from_ne_bytes(
                        <[u8; 8]>::try_from(&config.randomness_seed[24..32]).unwrap(),
                    ),
                ),
            ),
            by_height: BTreeSet::new(),
            best_block_height: config.finalized_block_height,
        }
    }

    /// Inserts a new unvalidated transaction in the pool.
    ///
    /// Returns `None` if a transaction with the same bytes already exists in the pool.
    pub fn add_unvalidated(
        &mut self,
        scale_encoded: Vec<u8>,
        user_data: TTx,
    ) -> Option<TransactionId> {
        self.add_unvalidated_inner(scale_encoded, None, user_data)
    }

    /// Inserts a new unvalidated transaction in the pool.
    ///
    /// Returns `None` if a transaction with the same bytes already exists in the pool.
    fn add_unvalidated_inner(
        &mut self,
        scale_encoded: impl AsRef<[u8]> + Into<Vec<u8>>,
        included_block_height: Option<u64>,
        user_data: TTx,
    ) -> Option<TransactionId> {
        let hash = blake2_hash(scale_encoded.as_ref());

        let by_hash_entry = match self.by_hash.entry(hash) {
            hash_map::Entry::Occupied(_) => return None,
            hash_map::Entry::Vacant(e) => e,
        };

        let tx_id = TransactionId(self.transactions.insert(Transaction {
            scale_encoded: scale_encoded.into(),
            included_block_height,
            user_data,
        }));

        by_hash_entry.insert(tx_id);

        let _was_inserted = self.not_validated.insert(tx_id);
        debug_assert!(_was_inserted);

        if let Some(included_block_height) = included_block_height {
            let _was_inserted = self.by_height.insert((included_block_height, tx_id));
            debug_assert!(_was_inserted);
        }

        Some(tx_id)
    }

    /// Removes from the pool the transaction with the given identifier.
    ///
    /// # Panic
    ///
    /// Panics if the identifier is invalid.
    ///
    #[track_caller]
    pub fn remove(&mut self, id: TransactionId) -> TTx {
        let tx = self.transactions.remove(id.0);

        // TODO: remove from not_validated if relevant

        let _id = self
            .by_hash
            .remove(&blake2_hash(&tx.scale_encoded))
            .unwrap();
        assert_eq!(_id, id);

        tx.user_data
    }

    /// Returns a list of transactions whose state is "not validated".
    pub fn unvalidated_transactions(&'_ self) -> impl ExactSizeIterator<Item = TransactionId> + '_ {
        self.not_validated.iter().copied()
    }

    /// Returns the transactions from the pool in the order in which they should be inserted in
    /// authored blocks.
    pub fn inclusion_order(&'_ self) -> impl Iterator<Item = TransactionId> + '_ {
        // FIXME: /!\
        // TODO: /!\
        core::iter::empty()
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

    /// Returns the bytes associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn scale_encoding(&self, id: TransactionId) -> Option<&[u8]> {
        Some(&self.transactions.get(id.0)?.scale_encoded)
    }

    /// Tries to find a transaction in the pool whose bytes are `scale_encoded`.
    pub fn find(&self, scale_encoded: &[u8]) -> Option<TransactionId> {
        self.by_hash.get(&blake2_hash(&scale_encoded)).cloned()
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
    /// `body` must be the list of transactions included in the block, with a user data associated
    /// to each transaction. The function inserts all transactions.
    ///
    /// Transactions in `body` that aren't yet present in the pool are added to it in the
    /// "unverified" state.
    pub fn append_block<'a>(
        &'a mut self,
        body: impl Iterator<Item = (impl AsRef<[u8]>, TTx)> + 'a,
    ) -> impl Iterator<Item = TransactionId> + 'a {
        // A custom iterator is used in order to insert transactions on-the-fly while making sure
        // to add all the transactions even if the iterator is dropped by the user.
        //
        // Apologize for the extreme complexity introduced by using a separate trait, but it is
        // the only way allowed by Rust to make this compile without adding overly-restrictive
        // lifetime requirements.
        trait Dummy {
            type A: AsRef<[u8]>;
            type B;
            fn into_parts(self) -> (Self::A, Self::B);
        }

        impl<A, B> Dummy for (A, B)
        where
            A: AsRef<[u8]>,
        {
            type A = A;
            type B = B;
            fn into_parts(self) -> (A, B) {
                self
            }
        }

        struct Iter<'a, TTx, TIt>
        where
            TIt: Iterator,
            TIt::Item: Dummy<B = TTx>,
        {
            me: &'a mut Pool<TTx>,
            body: TIt,
        }

        impl<'a, TTx, TIt> Iterator for Iter<'a, TTx, TIt>
        where
            TIt: Iterator,
            TIt::Item: Dummy<B = TTx>,
        {
            type Item = TransactionId;

            fn next(&mut self) -> Option<Self::Item> {
                let (transaction, user_data) = self.body.next()?.into_parts();
                let transaction = transaction.as_ref();
                self.me.add_unvalidated_inner(
                    transaction,
                    Some(self.me.best_block_height),
                    user_data,
                )
            }
        }

        impl<'a, TTx, TIt> Drop for Iter<'a, TTx, TIt>
        where
            TIt: Iterator,
            TIt::Item: Dummy<B = TTx>,
        {
            fn drop(&mut self) {
                while let Some(_) = self.next() {}
                self.me.best_block_height = self.me.best_block_height.checked_add(1).unwrap();
            }
        }

        Iter { me: self, body }
    }

    /// Pop a certain number of blocks from the list of blocks.
    ///
    /// # Panic
    ///
    /// Panics if `num_to_retract > self.best_block_height()`, in other words if the block number
    /// would go in the negative.
    ///
    pub fn retract_blocks(&mut self, num_to_retract: u64) {
        // Iterate `num_to_retract` times.
        for _ in 0..num_to_retract {
            // List of transactions that were included in that block.
            let transactions_to_retract = self
                .by_height
                .range(
                    (self.best_block_height, TransactionId(usize::min_value()))
                        ..=(self.best_block_height, TransactionId(usize::max_value())),
                )
                .map(|(_, tx_id)| *tx_id)
                .collect::<Vec<_>>();

            for transaction_id in transactions_to_retract {
                let mut tx_data = self.transactions.get_mut(transaction_id.0).unwrap();
                debug_assert_eq!(tx_data.included_block_height, Some(self.best_block_height));
                tx_data.included_block_height = None;
            }

            self.best_block_height = self.best_block_height.checked_sub(1).unwrap();
        }
    }

    /// Sets the outcome of validating the transaction with the given identifier.
    // TODO: pass block hash/number?
    pub fn set_validation_result(
        &mut self,
        id: TransactionId,
        result: Result<ValidTransaction, InvalidTransaction>,
    ) {
        todo!()
    }
}

/// Entry in [`Pool::transactions`].
struct Transaction<TTx> {
    /// Bytes corresponding to the SCALE-encoded transaction.
    scale_encoded: Vec<u8>,

    /// If `Some`, the height of the block at which the transaction has been included.
    included_block_height: Option<u64>,

    /// User data chosen by the user.
    user_data: TTx,
}

/// Utility. Calculates the blake2 hash of the given bytes.
fn blake2_hash(bytes: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(blake2_rfc::blake2b::blake2b(32, &[], bytes).as_bytes()).unwrap()
}
