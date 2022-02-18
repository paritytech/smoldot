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

#![cfg(test)]

use core::num::NonZeroU64;

use super::super::validate;
use super::{Config, LightPool};

#[test]
fn regular_path() {
    let mut pool = LightPool::new(Config {
        blocks_capacity: 16,
        finalized_block_hash: [0; 32],
        transactions_capacity: 16,
    });

    assert_eq!(pool.missing_block_bodies().count(), 0);

    let tx_id = pool.add_unvalidated(vec![0], ());

    pool.add_block([1; 32], &[0; 32], ());
    let set_best_block = pool.set_best_block(&[1; 32]);
    assert!(set_best_block.included_transactions.is_empty());
    assert!(set_best_block.retracted_transactions.is_empty());
    assert_eq!(pool.missing_block_bodies().count(), 1);

    let included_txs = pool
        .set_block_body(&[1; 32], vec![vec![0]].into_iter())
        .collect::<Vec<_>>();
    assert_eq!(included_txs, vec![(tx_id, 0)]);
    assert_eq!(pool.missing_block_bodies().count(), 0);

    let mut non_finalized_iter = pool.set_finalized_block(&[1; 32]);
    assert!(non_finalized_iter.next().is_none());

    let mut iter = pool.prune_finalized_with_body();
    let pruned = iter.next().unwrap();
    assert_eq!(pruned.block_hash, [1; 32]);
    assert_eq!(pruned.included_transactions, vec![(tx_id, 0, vec![0], ())]);
}

#[test]
fn included_after_set_best() {
    let mut pool = LightPool::new(Config {
        blocks_capacity: 16,
        finalized_block_hash: [0; 32],
        transactions_capacity: 16,
    });

    assert_eq!(pool.missing_block_bodies().count(), 0);

    let tx_id = pool.add_unvalidated(vec![0], ());

    pool.add_block([1; 32], &[0; 32], ());
    let included_txs = pool
        .set_block_body(&[1; 32], vec![vec![0]].into_iter())
        .collect::<Vec<_>>();
    assert!(included_txs.is_empty());

    let set_best_block = pool.set_best_block(&[1; 32]);
    assert_eq!(
        set_best_block.included_transactions,
        vec![(tx_id, [1; 32], 0)]
    );
    assert!(set_best_block.retracted_transactions.is_empty());
}

#[test]
fn transaction_retracted_after_reorg() {
    let mut pool = LightPool::new(Config {
        blocks_capacity: 16,
        finalized_block_hash: [0; 32],
        transactions_capacity: 16,
    });

    assert_eq!(pool.missing_block_bodies().count(), 0);

    let tx_id = pool.add_unvalidated(vec![0], ());

    // Add blocks 1 and 2, both children of block 0.
    pool.add_block([1; 32], &[0; 32], ());
    pool.add_block([2; 32], &[0; 32], ());

    // Block 1 contains the transaction we want, while block 2 doesn't.
    let included_txs = pool
        .set_block_body(&[1; 32], vec![vec![0]].into_iter())
        .collect::<Vec<_>>();
    assert!(included_txs.is_empty());
    let included_txs = pool
        .set_block_body(&[2; 32], Vec::<Vec<u8>>::new().into_iter())
        .collect::<Vec<_>>();
    assert!(included_txs.is_empty());

    // Set block 1 as the best block. Transaction must be included.
    let set_best_block = pool.set_best_block(&[1; 32]);
    assert_eq!(
        set_best_block.included_transactions,
        vec![(tx_id, [1; 32], 0)]
    );
    assert!(set_best_block.retracted_transactions.is_empty());

    // Set block 2 as the best block. Transaction must be retracted.
    let set_best_block = pool.set_best_block(&[2; 32]);
    assert!(set_best_block.included_transactions.is_empty());
    assert_eq!(
        set_best_block.retracted_transactions,
        vec![(tx_id, [1; 32], 0)]
    );

    // Set block 1 as the best block again. Transaction must be included.
    let set_best_block = pool.set_best_block(&[1; 32]);
    assert_eq!(
        set_best_block.included_transactions,
        vec![(tx_id, [1; 32], 0)]
    );
    assert!(set_best_block.retracted_transactions.is_empty());
}

#[test]
fn longevity_works_non_finalized() {
    let mut pool = LightPool::new(Config {
        blocks_capacity: 16,
        finalized_block_hash: [0; 32],
        transactions_capacity: 16,
    });

    let tx_id = pool.add_unvalidated(vec![0], ());

    // Add one base block.
    pool.add_block([1; 32], &[0; 32], ());
    let _ = pool.set_best_block(&[1; 32]);
    assert!(!pool.is_valid_against_best_block(tx_id));
    assert_eq!(
        pool.unvalidated_transactions()
            .map(|(id, _)| id)
            .collect::<Vec<_>>(),
        vec![tx_id]
    );

    // Validate transaction against that block.
    pool.set_validation_result(
        tx_id,
        &[1; 32],
        Ok(validate::ValidTransaction {
            longevity: NonZeroU64::new(2).unwrap(),
            priority: 1,
            propagate: true,
            provides: Vec::new(),
            requires: Vec::new(),
        }),
    );
    assert!(pool.is_valid_against_best_block(tx_id));
    assert_eq!(pool.unvalidated_transactions().count(), 0);

    // Add more blocks on top of the best chain.
    pool.add_block([2; 32], &[1; 32], ());
    let _ = pool.set_best_block(&[2; 32]);
    pool.add_block([3; 32], &[2; 32], ());
    let _ = pool.set_best_block(&[3; 32]);

    // The transaction is still valid.
    assert!(pool.is_valid_against_best_block(tx_id));
    assert_eq!(pool.unvalidated_transactions().count(), 0);

    // One more block.
    pool.add_block([4; 32], &[3; 32], ());
    let _ = pool.set_best_block(&[4; 32]);

    // Transaction is no longer valid because its longevity has expired.
    assert!(!pool.is_valid_against_best_block(tx_id));
    assert_eq!(
        pool.unvalidated_transactions()
            .map(|(id, _)| id)
            .collect::<Vec<_>>(),
        vec![tx_id]
    );
}

#[test]
fn longevity_works_finalized() {
    let mut pool = LightPool::new(Config {
        blocks_capacity: 16,
        finalized_block_hash: [0; 32],
        transactions_capacity: 16,
    });

    let tx_id = pool.add_unvalidated(vec![0], ());

    // Add one base block.
    pool.add_block([1; 32], &[0; 32], ());
    let _ = pool.set_best_block(&[1; 32]);
    assert!(!pool.is_valid_against_best_block(tx_id));
    assert_eq!(
        pool.unvalidated_transactions()
            .map(|(id, _)| id)
            .collect::<Vec<_>>(),
        vec![tx_id]
    );

    // Validate transaction against that block.
    pool.set_validation_result(
        tx_id,
        &[1; 32],
        Ok(validate::ValidTransaction {
            longevity: NonZeroU64::new(2).unwrap(),
            priority: 1,
            propagate: true,
            provides: Vec::new(),
            requires: Vec::new(),
        }),
    );
    assert!(pool.is_valid_against_best_block(tx_id));
    assert_eq!(pool.unvalidated_transactions().count(), 0);

    // Add more blocks on top of the best chain.
    pool.add_block([2; 32], &[1; 32], ());
    let _ = pool.set_best_block(&[2; 32]);
    pool.add_block([3; 32], &[2; 32], ());
    let _ = pool.set_best_block(&[3; 32]);

    // Finalize the latest block added.
    let _ = pool.set_finalized_block(&[3; 32]);
    let _ = pool.prune_finalized_with_body();

    // The transaction is still valid.
    assert!(pool.is_valid_against_best_block(tx_id));
    assert_eq!(pool.unvalidated_transactions().count(), 0);

    // One more block.
    pool.add_block([4; 32], &[3; 32], ());
    let _ = pool.set_best_block(&[4; 32]);

    // Transaction is no longer valid because its longevity has expired.
    assert!(!pool.is_valid_against_best_block(tx_id));
    assert_eq!(
        pool.unvalidated_transactions()
            .map(|(id, _)| id)
            .collect::<Vec<_>>(),
        vec![tx_id]
    );
}

#[test]
fn longevity_works_finalized_base() {
    let mut pool = LightPool::new(Config {
        blocks_capacity: 16,
        finalized_block_hash: [0; 32],
        transactions_capacity: 16,
    });

    let tx_id = pool.add_unvalidated(vec![0], ());

    // Validate transaction against that block.
    pool.set_validation_result(
        tx_id,
        &[0; 32],
        Ok(validate::ValidTransaction {
            longevity: NonZeroU64::new(2).unwrap(),
            priority: 1,
            propagate: true,
            provides: Vec::new(),
            requires: Vec::new(),
        }),
    );
    assert!(pool.is_valid_against_best_block(tx_id));
    assert_eq!(pool.unvalidated_transactions().count(), 0);

    // Add more blocks on top of the best chain.
    pool.add_block([1; 32], &[0; 32], ());
    let _ = pool.set_best_block(&[1; 32]);
    pool.add_block([2; 32], &[1; 32], ());
    let _ = pool.set_best_block(&[2; 32]);

    // Finalize the latest block added.
    let _ = pool.set_finalized_block(&[2; 32]);
    let _ = pool.prune_finalized_with_body();

    // The transaction is still valid.
    assert!(pool.is_valid_against_best_block(tx_id));
    assert_eq!(pool.unvalidated_transactions().count(), 0);

    // One more block.
    pool.add_block([3; 32], &[2; 32], ());
    let _ = pool.set_best_block(&[3; 32]);

    // Transaction is no longer valid because its longevity has expired.
    assert!(!pool.is_valid_against_best_block(tx_id));
    assert_eq!(
        pool.unvalidated_transactions()
            .map(|(id, _)| id)
            .collect::<Vec<_>>(),
        vec![tx_id]
    );
}

// TODO: more tests
