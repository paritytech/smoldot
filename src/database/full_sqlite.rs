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

//! Filesystem-backed database containing all the information about a chain.
//!
//! This module handles the persistent storage of the chain on disk.
//!
//! # Usage
//!
//! Use the [`open()`] function to create a new database or open an existing one. [`open()`]
//! returns a [`DatabaseOpen`] enum. This enum will contain either a [`SqliteFullDatabase`] object,
//! representing an access to the database, or a [`DatabaseEmpty`] if the database didn't exist or
//! is empty. If that is the case, use [`DatabaseEmpty::initialize`] in order to populate it and
//! obtain a [`SqliteFullDatabase`].
//!
//! Use [`SqliteFullDatabase::insert`] to insert a new block in the database. The block is assumed
//! to have been successfully verified prior to insertion. An error is returned if this block is
//! already in the database or isn't a descendant or ancestor of the latest finalized block.
//!
//! Use [`SqliteFullDatabase::set_finalized`] to mark a block already in the database as finalized.
//! Any block that isn't an ancestor or descendant will be removed. Reverting finalization is
//! not possible.
//!
//! Due to the database's schema, it is not possible to efficiently retrieve the storage items of
//! blocks that are ancestors of the finalized block. When a block is finalized, the storage of
//! its ancestors is lost, and the only way to reconstruct it is to execute all blocks starting
//! from the genesis to the desired one.
//!
//! # About errors handling
//!
//! Most of the functions and methods in this module return a `Result` containing notably an
//! [`AccessError`]. This kind of errors can happen if the operating system returns an error when
//! accessing the file system, or if the database has been corrupted, for example by the user
//! manually modifying it.
//!
//! There isn't much that can be done to properly handle an [`AccessError`]. The only reasonable
//! solutions are either to stop the program, or to delete the entire database and recreate it.
//!
//! # Schema
//!
//! TODO: just put the SQL instead
//!
//! Each section below corresponds to a table in the SQLite database.
//!
//! ## meta
//!
//! Contains all the meta-information about the content.
//!
//! Keys in that tree are:
//!
//! - `best`: Hash of the best block.
//!
//! - `finalized`: Height of the finalized block, as a 64bits big endian number.
//!
//! - `grandpa_authorities_set_id`: A 64bits big endian number representing the id of the
//! authorities set that must finalize the block right after the finalized block. The value is
//! 0 at the genesis block, and increased by 1 at every authorities change. Missing if and only
//! if the chain doesn't use Grandpa.
//!
//! - `grandpa_triggered_authorities`: List of public keys and weights of the GrandPa
//! authorities that must finalize the children of the finalized block. Consists in 40bytes
//! values concatenated together, each value being a 32bytes ed25519 public key and a 8bytes
//! little endian weight. Missing if and only if the chain doesn't use Grandpa.
//!
//! - `grandpa_scheduled_target`: A 64bits big endian number representing the block where the
//! authorities found in `grandpa_scheduled_authorities` will be triggered. Blocks whose height
//! is strictly higher than this value must be finalized using the new set of authorities. This
//! authority change must have been scheduled in or before the finalized block. Missing if no
//! change is scheduled or if the chain doesn't use Grandpa.
//!
//! - `grandpa_scheduled_authorities`: List of public keys and weights of the GrandPa
//! authorities that will be triggered at the block found in `grandpa_scheduled_target`.
//! Consists in 40bytes values concatenated together, each value being a 32bytes ed25519
//! public key and a 8bytes little endian weight. Missing if no change is scheduled or if the
//! chain doesn't use Grandpa.
//!
//! - `aura_slot_duration`: A 64bits big endian number indicating the duration of an Aura
//! slot. Missing if and only if the chain doesn't use Aura.
//!
//! - `aura_finalized_authorities`: List of public keys of the Aura authorities that must
//! author the children of the finalized block. Consists in 32bytes values concatenated
//! together. Missing if and only if the chain doesn't use Aura.
//!
//! - `babe_slots_per_epoch`: A 64bits big endian number indicating the number of slots per
//! Babe epoch. Missing if and only if the chain doesn't use Babe.
//!
//! - `babe_finalized_epoch`: SCALE encoding of a structure that contains the information
//! about the Babe epoch used for the finalized block. Missing if and only if the finalized
//! block is block #0 or the chain doesn't use Babe.
//!
//! - `babe_finalized_next_epoch`: SCALE encoding of a structure that contains the information
//! about the Babe epoch that follows the one described by `babe_finalized_epoch`. If the
//! finalized block is block #0, then this contains information about epoch #0. Missing if and
//! only if the chain doesn't use Babe.
//!
//! ## block_hashes_by_number
//!
//! For each possible block number, stores a list of block hashes having that number.
//!
//! If the key is inferior or equal to the value in `finalized`, guaranteed to only contain on
//! block.
//!
//! Keys in that tree are 64-bits-big-endian block numbers, and values are a concatenation of
//! 32-bytes block hashes (without any encoding). If the value is for example 96 bytes long,
//! that means there are 3 blocks in the database with that block number.
//!
//! Never contains any empty value.
//!
//! ## block_headers
//!
//! Contains an entry for every known block that is an ancestor or descendant of the finalized
//! block.
//! When the finalized block is updated, entries that aren't ancestors or descendants of the new
//! finalized block are automatically purged.
//!
//! Keys are block hashes, and values are SCALE-encoded block headers.
//!
//! ## block_bodies
//!
//! Entries are the same as for `block_headers_tree`.
//!
//! Keys are block hashes, and values are SCALE-encoded `Vec`s containing the extrinsics. Each
//! extrinsic is itself a SCALE-encoded `Vec<u8>`.
//!
//! ## block_justifications
//!
//! Entries are a subset of the ones of `block_headers_tree`.
//! Not all blocks have a justification.
//! Only finalized blocks have a justification.
//!
//! Keys are block hashes, and values are SCALE-encoded `Vec`s containing the justification.
//!
//! ## storage_top_trie
//!
//! Contains the key-value storage at the finalized block.
//!
//! Keys are storage keys, and values are storage values.
//!
//! ## non_finalized_changes_keys
//!
//! For each hash of non-finalized block, contains the list of keys in the storage that this
//! block modifies.
//!
//! Keys are a 32 bytes block hash. Values are a list of SCALE-encoded `Vec<u8>` concatenated
//! together. In other words, each value is a length (SCALE-compact-encoded), a key of that
//! length, a length, a key of that length, and so on.
//!
//! ## non_finalized_changes
//!
//! For each element in `non_finalized_changes_keys_tree`, contains the new value for this
//! storage modification. If an entry is found in `non_finalized_changes_keys_tree` and not in
//! `non_finalized_changes_tree`, that means that the storage entry must be removed.
//!
//! Keys are a 32 bytes block hash followed with a storage key.

// TODO: better docs

#![cfg(feature = "database-sqlite")]
#![cfg_attr(docsrs, doc(cfg(feature = "database-sqlite")))]

use crate::{chain::chain_information, header, util};

use core::{convert::TryFrom, fmt, iter, num::NonZeroU64};
use parking_lot::Mutex;

pub use open::{open, Config, ConfigTy, DatabaseEmpty, DatabaseOpen};

mod open;

/// An open database. Holds file descriptors.
pub struct SqliteFullDatabase {
    /// The SQLite connection.
    ///
    /// The database is constantly within a transaction.
    /// When the database is opened, `BEGIN TRANSACTION` is immediately run. We periodically
    /// call `COMMIT; BEGIN_TRANSACTION` through heuristics. `COMMIT` is basically the equivalent
    /// of `fsync`, and must be called carefully.
    database: Mutex<sqlite::Connection>,
}

impl SqliteFullDatabase {
    /// Returns the hash of the block in the database whose storage is currently accessible.
    pub fn best_block_hash(&self) -> Result<[u8; 32], AccessError> {
        let connection = self.database.lock();

        let val = meta_get(&connection, b"best")?
            .ok_or(AccessError::Corrupted(CorruptedError::MissingMetaKey))?;
        if val.len() == 32 {
            let mut out = [0; 32];
            out.copy_from_slice(&val);
            Ok(out)
        } else {
            Err(AccessError::Corrupted(
                CorruptedError::BestBlockHashBadLength,
            ))
        }
    }

    /// Returns the hash of the finalized block in the database.
    pub fn finalized_block_hash(&self) -> Result<[u8; 32], AccessError> {
        let database = self.database.lock();
        finalized_hash(&database)
    }

    /// Returns the SCALE-encoded header of the given block, or `None` if the block is unknown.
    ///
    /// > **Note**: If this method is called twice times in a row with the same block hash, it
    /// >           is possible for the first time to return `Some` and the second time to return
    /// >           `None`, in case the block has since been removed from the database.
    pub fn block_scale_encoded_header(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, AccessError> {
        let connection = self.database.lock();

        let mut statement = connection
            .prepare(r#"SELECT header FROM block_header WHERE hash = ?"#)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)?;
        statement.bind(1, &block_hash[..]).unwrap();

        if !matches!(statement.next().unwrap(), sqlite::State::Row) {
            return Ok(None);
        }

        let value = statement
            .read::<Vec<u8>>(0)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)?;
        Ok(Some(value))
    }

    /// Returns the list of extrinsics of the given block, or `None` if the block is unknown.
    ///
    /// > **Note**: The list of extrinsics of a block is also known as its *body*.
    ///
    /// > **Note**: If this method is called twice times in a row with the same block hash, it
    /// >           is possible for the first time to return `Some` and the second time to return
    /// >           `None`, in case the block has since been removed from the database.
    pub fn block_extrinsics(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<Option<impl ExactSizeIterator<Item = Vec<u8>>>, AccessError> {
        let connection = self.database.lock();

        let mut statement = connection
            .prepare(r#"SELECT extrinsic FROM block_body WHERE hash = ? ORDER BY idx ASC"#)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)?;

        // TODO: doesn't detect if block is absent

        statement.bind(1, &block_hash[..]).unwrap();

        let mut out = Vec::new();
        while matches!(statement.next().unwrap(), sqlite::State::Row) {
            let extrinsic = statement
                .read::<Vec<u8>>(0)
                .map_err(InternalError)
                .map_err(CorruptedError::Internal)?;
            out.push(extrinsic);
        }
        Ok(Some(out.into_iter()))
    }

    /// Returns the hashes of the blocks given a block number.
    pub fn block_hash_by_number(
        &self,
        block_number: u64,
    ) -> Result<impl ExactSizeIterator<Item = [u8; 32]>, AccessError> {
        let block_number = match i64::try_from(block_number) {
            Ok(n) => n,
            Err(_) => return Ok(either::Right(iter::empty())),
        };

        let connection = self.database.lock();

        let mut statement = connection
            .prepare(r#"SELECT hash FROM blocks_by_number WHERE number = ?"#)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)?;
        statement.bind(1, block_number).unwrap();

        let mut out = Vec::new();
        while matches!(statement.next().unwrap(), sqlite::State::Row) {
            let hash = statement.read::<Vec<u8>>(0).unwrap();
            out.push(
                <[u8; 32]>::try_from(&hash[..])
                    .map_err(|_| AccessError::Corrupted(CorruptedError::InvalidBlockHashLen))?,
            );
        }

        Ok(either::Left(out.into_iter()))
    }

    /// Returns a [`chain_information::ChainInformation`] struct containing the information about
    /// the current finalized state of the chain.
    ///
    /// This method is relatively expensive and should preferably not be called repeatedly.
    ///
    /// In order to avoid race conditions, the known finalized block hash must be passed as
    /// parameter. If the finalized block in the database doesn't match the hash passed as
    /// parameter, most likely because it has been updated in a parallel thread, a
    /// [`FinalizedAccessError::Obsolete`] error is returned.
    pub fn to_chain_information(
        &self,
        finalized_block_hash: &[u8; 32],
    ) -> Result<chain_information::ChainInformation, FinalizedAccessError> {
        let connection = self.database.lock();
        if finalized_hash(&connection)? != *finalized_block_hash {
            return Err(FinalizedAccessError::Obsolete);
        }

        let finalized_block_header = block_header(&connection, &finalized_block_hash)?
            .ok_or(AccessError::Corrupted(CorruptedError::MissingBlockHeader))?;

        let finality = match (
            grandpa_authorities_set_id(&connection)?,
            grandpa_finalized_triggered_authorities(&connection)?,
            grandpa_finalized_scheduled_change(&connection)?,
        ) {
            (
                Some(after_finalized_block_authorities_set_id),
                Some(finalized_triggered_authorities),
                finalized_scheduled_change,
            ) => chain_information::ChainInformationFinality::Grandpa {
                after_finalized_block_authorities_set_id,
                finalized_triggered_authorities,
                finalized_scheduled_change,
            },
            (None, None, None) => chain_information::ChainInformationFinality::Outsourced,
            _ => {
                return Err(FinalizedAccessError::Access(AccessError::Corrupted(
                    CorruptedError::ConsensusAlgorithmMix,
                )))
            }
        };

        let consensus = match (
            meta_get(&connection, b"aura_finalized_authorities")?,
            meta_get(&connection, b"aura_slot_duration")?,
            meta_get(&connection, b"babe_slots_per_epoch")?,
            meta_get(&connection, b"babe_finalized_next_epoch")?,
        ) {
            (None, None, Some(slots_per_epoch), Some(finalized_next_epoch)) => {
                let slots_per_epoch = expect_be_nz_u64(&slots_per_epoch)?;
                let finalized_next_epoch_transition =
                    decode_babe_epoch_information(&finalized_next_epoch)?;
                let finalized_block_epoch_information =
                    meta_get(&connection, b"babe_finalized_epoch")?
                        .map(|v| decode_babe_epoch_information(&v))
                        .transpose()?;
                chain_information::ChainInformationConsensus::Babe {
                    finalized_block_epoch_information,
                    finalized_next_epoch_transition,
                    slots_per_epoch,
                }
            }
            (Some(finalized_authorities), Some(slot_duration), None, None) => {
                let slot_duration = expect_be_nz_u64(&slot_duration)?;
                let finalized_authorities_list =
                    decode_aura_authorities_list(&finalized_authorities)?;
                chain_information::ChainInformationConsensus::Aura {
                    finalized_authorities_list,
                    slot_duration,
                }
            }
            (None, None, None, None) => chain_information::ChainInformationConsensus::AllAuthorized,
            _ => {
                return Err(FinalizedAccessError::Access(AccessError::Corrupted(
                    CorruptedError::ConsensusAlgorithmMix,
                )))
            }
        };

        Ok(chain_information::ChainInformation {
            finalized_block_header,
            consensus,
            finality,
        })
    }

    /// Insert a new block in the database.
    ///
    /// Must pass the header and body of the block, and the changes to the storage that this block
    /// performs relative to its parent.
    ///
    /// Blocks must be inserted in the correct order. An error is returned if the parent of the
    /// newly-inserted block isn't present in the database.
    pub fn insert(
        &self,
        scale_encoded_header: &[u8],
        is_new_best: bool,
        body: impl ExactSizeIterator<Item = impl AsRef<[u8]>>,
        storage_top_trie_changes: impl Iterator<Item = (impl AsRef<[u8]>, Option<impl AsRef<[u8]>>)>
            + Clone,
    ) -> Result<(), InsertError> {
        // Calculate the hash of the new best block.
        let block_hash = header::hash_from_scale_encoded_header(scale_encoded_header);

        // Decode the header, as we will need various information from it.
        let header = header::decode(&scale_encoded_header).map_err(InsertError::BadHeader)?;

        // Locking is performed as late as possible.
        let connection = self.database.lock();

        // Make sure that the block to insert isn't already in the database.
        if has_block(&connection, &block_hash)? {
            return Err(InsertError::Duplicate);
        }

        // Make sure that the parent of the block to insert is in the database.
        if !has_block(&connection, header.parent_hash)? {
            return Err(InsertError::MissingParent);
        }

        // If the height of the block to insert is <= the latest finalized, it doesn't
        // belong to the finalized chain and would be pruned.
        // TODO: what if we don't immediately insert the entire finalized chain, but populate it later? should that not be a use case?
        if header.number <= finalized_num(&connection)? {
            return Err(InsertError::FinalizedNephew);
        }

        let mut statement = connection
            .prepare("INSERT INTO blocks_by_number(number, hash) VALUES (?, ?)")
            .unwrap();
        statement
            .bind(1, i64::try_from(header.number).unwrap())
            .unwrap();
        statement.bind(2, &block_hash[..]).unwrap();
        statement.next().unwrap();

        // Insert the storage changes.
        let mut statement = connection
            .prepare("INSERT INTO non_finalized_changes(hash, key, value) VALUES (?, ?, ?)")
            .unwrap();
        for (key, value) in storage_top_trie_changes {
            statement.bind(1, &block_hash[..]).unwrap();
            statement.bind(2, key.as_ref()).unwrap();
            if let Some(value) = value {
                statement.bind(3, value.as_ref()).unwrap();
            } else {
                // Binds NULL.
                statement.bind(3, ()).unwrap();
            }
            statement.next().unwrap();
            statement.reset().unwrap();
        }

        // Various other updates.
        let mut statement = connection
            .prepare("INSERT INTO block_header(hash, header) VALUES (?, ?)")
            .unwrap();
        statement.bind(1, &block_hash[..]).unwrap();
        statement.bind(2, &scale_encoded_header[..]).unwrap();
        statement.next().unwrap();

        let mut statement = connection
            .prepare("INSERT INTO block_body(hash, idx, extrinsic) VALUES (?, ?, ?)")
            .unwrap();
        for (index, item) in body.enumerate() {
            statement.bind(1, &block_hash[..]).unwrap();
            statement.bind(2, i64::try_from(index).unwrap()).unwrap();
            statement.bind(3, item.as_ref()).unwrap();
            statement.next().unwrap();
            statement.reset().unwrap();
        }
        if is_new_best {
            meta_set(&connection, b"best", &block_hash)?;
        }

        Ok(())
    }

    /// Changes the finalized block to the given one.
    ///
    /// The block must have been previously inserted using [`SqliteFullDatabase::insert`], otherwise
    /// an error is returned.
    ///
    /// Blocks are expected to be valid in context of the chain. Inserting an invalid block can
    /// result in the database being corrupted.
    ///
    /// The block must be a descendant of the current finalized block. Reverting finalization is
    /// forbidden, as the database intentionally discards some information when finality is
    /// applied.
    pub fn set_finalized(
        &self,
        new_finalized_block_hash: &[u8; 32],
    ) -> Result<(), SetFinalizedError> {
        let connection = self.database.lock();

        // Fetch the header of the block to finalize.
        let new_finalized_header = block_header(&connection, &new_finalized_block_hash)?
            .ok_or(SetFinalizedError::UnknownBlock)?;

        // Fetch the current finalized block.
        let current_finalized = finalized_num(&connection)?;

        // If the block to finalize is at the same height as the already-finalized
        // block, considering that the database only contains one block per height on
        // the finalized chain, and that the presence of the block to finalize in
        // the database has already been verified, it is guaranteed that the block
        // to finalize is already the one already finalized.
        if new_finalized_header.number == current_finalized {
            return Ok(());
        }

        // Cannot set the finalized block to a past block. The database can't support
        // reverting finalization.
        if new_finalized_header.number < current_finalized {
            return Err(SetFinalizedError::RevertForbidden);
        }

        // At this point, we are sure that the operation will succeed unless the database is
        // corrupted.
        // Update the finalized block in meta.
        meta_set(
            &connection,
            b"finalized",
            &new_finalized_header.number.to_be_bytes()[..],
        )?;

        // Take each block height between `header.number` and `current_finalized + 1`
        // and remove blocks that aren't an ancestor of the new finalized block.
        {
            // For each block height between the old finalized and new finalized,
            // remove all blocks except the one whose hash is `expected_hash`.
            // `expected_hash` always designates a block in the finalized chain.
            let mut expected_hash = *new_finalized_block_hash;

            for height in (current_finalized + 1..=new_finalized_header.number).rev() {
                let blocks_list = block_hashes_by_number(&connection, height)?;

                let mut expected_block_found = false;
                for hash_at_height in blocks_list {
                    if hash_at_height == expected_hash {
                        expected_block_found = true;
                        continue;
                    }

                    // Remove the block from the database.
                    purge_block(&connection, &hash_at_height, height)?;
                }

                // `expected_hash` not found in the list of blocks with this number.
                if !expected_block_found {
                    return Err(SetFinalizedError::Access(AccessError::Corrupted(
                        CorruptedError::BrokenChain,
                    )));
                }

                // Update `expected_hash` to point to the parent of the current
                // `expected_hash`.
                expected_hash = {
                    let header = block_header(&connection, &expected_hash)?.ok_or(
                        SetFinalizedError::Access(AccessError::Corrupted(
                            CorruptedError::BrokenChain,
                        )),
                    )?;
                    header.parent_hash
                };
            }
        }

        // Take each block height starting from `header.number + 1` and remove blocks
        // that aren't a descendant of the newly-finalized block.
        let mut allowed_parents = vec![*new_finalized_block_hash];
        for height in new_finalized_header.number + 1.. {
            let mut next_iter_allowed_parents = Vec::with_capacity(allowed_parents.len());

            let blocks_list = block_hashes_by_number(&connection, height)?;
            if blocks_list.is_empty() {
                break;
            }

            for block_hash in blocks_list {
                let header = block_header(&connection, &block_hash)?
                    .ok_or(AccessError::Corrupted(CorruptedError::MissingBlockHeader))?;
                if allowed_parents.iter().any(|p| *p == header.parent_hash) {
                    next_iter_allowed_parents.push(block_hash);
                    continue;
                }

                purge_block(&connection, &block_hash, height)?;
            }

            allowed_parents = next_iter_allowed_parents;
        }

        // Now update the finalized block storage.
        for height in current_finalized + 1..=new_finalized_header.number {
            let block_hash =
                {
                    let list = block_hashes_by_number(&connection, height)?;
                    debug_assert_eq!(list.len(), 1);
                    list.into_iter().next().ok_or(SetFinalizedError::Access(
                        AccessError::Corrupted(CorruptedError::MissingBlockHeader),
                    ))?
                };

            let block_header =
                block_header(&connection, &block_hash)?.ok_or(SetFinalizedError::Access(
                    AccessError::Corrupted(CorruptedError::MissingBlockHeader),
                ))?;

            let mut statement = connection
                .prepare(
                    "DELETE FROM finalized_storage_top_trie
                WHERE key IN (
                    SELECT key FROM non_finalized_changes WHERE hash = ? AND value IS NULL
                );",
                )
                .unwrap();
            statement.bind(1, &block_hash[..]).unwrap();
            statement.next().unwrap();

            let mut statement = connection
                .prepare(
                    "INSERT OR REPLACE INTO finalized_storage_top_trie(key, value)
                SELECT key, value
                FROM non_finalized_changes 
                WHERE non_finalized_changes.hash = ? AND non_finalized_changes.value IS NOT NULL",
                )
                .unwrap();
            statement.bind(1, &block_hash[..]).unwrap();
            statement.next().unwrap();

            // Remove the entries from `non_finalized_changes` as they are now finalized.
            let mut statement = connection
                .prepare("DELETE FROM non_finalized_changes WHERE hash = ?")
                .unwrap();
            statement.bind(1, &block_hash[..]).unwrap();
            statement.next().unwrap();

            // TODO: the code below is very verbose and redundant with other similar code in smoldot ; could be improved

            if let Some((new_epoch, next_config)) = block_header.digest.babe_epoch_information() {
                let epoch = meta_get(&connection, b"babe_finalized_next_epoch")?.unwrap(); // TODO: don't unwrap
                let decoded_epoch = decode_babe_epoch_information(&epoch)?;
                meta_set(&connection, b"babe_finalized_epoch", &epoch)?;

                let slot_number = block_header
                    .digest
                    .babe_pre_runtime()
                    .unwrap()
                    .slot_number();
                let slots_per_epoch =
                    expect_be_nz_u64(&meta_get(&connection, b"babe_slots_per_epoch")?.unwrap())?; // TODO: don't unwrap

                let new_epoch = if let Some(next_config) = next_config {
                    chain_information::BabeEpochInformation {
                        epoch_index: decoded_epoch.epoch_index.checked_add(1).unwrap(),
                        start_slot_number: Some(
                            decoded_epoch
                                .start_slot_number
                                .unwrap_or(slot_number)
                                .checked_add(slots_per_epoch.get())
                                .unwrap(),
                        ),
                        authorities: new_epoch.authorities.map(Into::into).collect(),
                        randomness: *new_epoch.randomness,
                        c: next_config.c,
                        allowed_slots: next_config.allowed_slots,
                    }
                } else {
                    chain_information::BabeEpochInformation {
                        epoch_index: decoded_epoch.epoch_index.checked_add(1).unwrap(),
                        start_slot_number: Some(
                            decoded_epoch
                                .start_slot_number
                                .unwrap_or(slot_number)
                                .checked_add(slots_per_epoch.get())
                                .unwrap(),
                        ),
                        authorities: new_epoch.authorities.map(Into::into).collect(),
                        randomness: *new_epoch.randomness,
                        c: decoded_epoch.c,
                        allowed_slots: decoded_epoch.allowed_slots,
                    }
                };

                meta_set(
                    &connection,
                    b"babe_finalized_next_epoch",
                    &encode_babe_epoch_information(From::from(&new_epoch)),
                )?;
            }

            // TODO: implement Aura

            if grandpa_authorities_set_id(&connection)?.is_some() {
                for grandpa_digest_item in block_header.digest.logs().filter_map(|d| match d {
                    header::DigestItemRef::GrandpaConsensus(gp) => Some(gp),
                    _ => None,
                }) {
                    match grandpa_digest_item {
                        header::GrandpaConsensusLogRef::ScheduledChange(change) => {
                            assert_eq!(change.delay, 0); // TODO: not implemented if != 0
                            meta_set(
                                &connection,
                                b"grandpa_triggered_authorities",
                                &encode_grandpa_authorities_list(change.next_authorities),
                            )?;

                            let curr_set_id = expect_be_u64(
                                &meta_get(&connection, b"grandpa_authorities_set_id")?.unwrap(),
                            )?; // TODO: don't unwrap
                            meta_set(
                                &connection,
                                b"grandpa_authorities_set_id",
                                &(curr_set_id + 1).to_be_bytes()[..],
                            )?;
                        }
                        _ => {} // TODO: unimplemented
                    }
                }
            }
        }

        // It is possible that the best block has been pruned.
        // TODO: ^ yeah, how do we handle that exactly ^ ?

        // Perform a flush.
        connection.execute("COMMIT").unwrap();
        connection.execute("BEGIN TRANSACTION").unwrap();

        Ok(())
    }

    /// Returns the value associated to a key in the storage of the finalized block.
    ///
    /// In order to avoid race conditions, the known finalized block hash must be passed as
    /// parameter. If the finalized block in the database doesn't match the hash passed as
    /// parameter, most likely because it has been updated in a parallel thread, a
    /// [`FinalizedAccessError::Obsolete`] error is returned.
    pub fn finalized_block_storage_top_trie_get(
        &self,
        finalized_block_hash: &[u8; 32],
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, FinalizedAccessError> {
        let connection = self.database.lock();

        if finalized_hash(&connection)? != *finalized_block_hash {
            return Err(FinalizedAccessError::Obsolete);
        }

        let mut statement = connection
            .prepare(r#"SELECT value FROM finalized_storage_top_trie WHERE key = ?"#)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)
            .map_err(AccessError::Corrupted)
            .map_err(FinalizedAccessError::Access)?;
        statement.bind(1, key).unwrap();

        if !matches!(statement.next().unwrap(), sqlite::State::Row) {
            return Ok(None);
        }

        let value = statement
            .read::<Vec<u8>>(0)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)
            .map_err(AccessError::Corrupted)
            .map_err(FinalizedAccessError::Access)?;
        Ok(Some(value))
    }

    /// Returns the key in the storage of the finalized block that immediately follows the key
    /// passed as parameter.
    ///
    /// In order to avoid race conditions, the known finalized block hash must be passed as
    /// parameter. If the finalized block in the database doesn't match the hash passed as
    /// parameter, most likely because it has been updated in a parallel thread, a
    /// [`FinalizedAccessError::Obsolete`] error is returned.
    pub fn finalized_block_storage_top_trie_next_key(
        &self,
        finalized_block_hash: &[u8; 32],
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, FinalizedAccessError> {
        let connection = self.database.lock();

        if finalized_hash(&connection)? != *finalized_block_hash {
            return Err(FinalizedAccessError::Obsolete);
        }

        let mut statement = connection
            .prepare(r#"SELECT key FROM finalized_storage_top_trie WHERE key > ? ORDER BY key ASC LIMIT 1"#)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)
            .map_err(AccessError::Corrupted)
            .map_err(FinalizedAccessError::Access)?;
        statement.bind(1, key).unwrap();

        if !matches!(statement.next().unwrap(), sqlite::State::Row) {
            return Ok(None);
        }

        let key = statement
            .read::<Vec<u8>>(0)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)
            .map_err(AccessError::Corrupted)
            .map_err(FinalizedAccessError::Access)?;
        Ok(Some(key))
    }

    /// Returns the list of keys of the storage of the finalized block that start with the given
    /// prefix. Pass `&[]` for the prefix to get the list of all keys.
    ///
    /// In order to avoid race conditions, the known finalized block hash must be passed as
    /// parameter. If the finalized block in the database doesn't match the hash passed as
    /// parameter, most likely because it has been updated in a parallel thread, a
    /// [`FinalizedAccessError::Obsolete`] error is returned.
    pub fn finalized_block_storage_top_trie_keys(
        &self,
        finalized_block_hash: &[u8; 32],
        prefix: &[u8],
    ) -> Result<Vec<Vec<u8>>, FinalizedAccessError> {
        let connection = self.database.lock();

        if finalized_hash(&connection)? != *finalized_block_hash {
            return Err(FinalizedAccessError::Obsolete);
        }

        let mut statement = connection
            .prepare(r#"SELECT key FROM finalized_storage_top_trie WHERE key >= ?"#)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)
            .map_err(AccessError::Corrupted)
            .map_err(FinalizedAccessError::Access)?;
        statement.bind(1, prefix).unwrap();

        let mut out = Vec::new();
        while matches!(statement.next().unwrap(), sqlite::State::Row) {
            let key = statement
                .read::<Vec<u8>>(0)
                .map_err(InternalError)
                .map_err(CorruptedError::Internal)
                .map_err(AccessError::Corrupted)
                .map_err(FinalizedAccessError::Access)?;

            // TODO: hack because I don't know how to ask sqlite to do that
            if !(key.starts_with(prefix)) {
                continue;
            }

            out.push(key);
        }

        Ok(out)
    }
}

impl fmt::Debug for SqliteFullDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SqliteFullDatabase").finish()
    }
}

impl Drop for SqliteFullDatabase {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = self.database.get_mut().execute("PRAGMA optimize;");
            let _ = self.database.get_mut().execute("COMMIT");
        } else {
            // Rolling back if we're unwind is not the worst idea, in case we were in the middle
            // of an update.
            // We might roll back too much, but it is not considered a problem.
            let _ = self.database.get_mut().execute("ROLLBACK");
        }
    }
}

/// Error while accessing some information.
// TODO: completely replace with just CorruptedError?
#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum AccessError {
    /// Database could be accessed, but its content is invalid.
    ///
    /// While these corruption errors are probably unrecoverable, the inner error might however
    /// be useful for debugging purposes.
    Corrupted(CorruptedError),
}

/// Error while calling [`SqliteFullDatabase::insert`].
#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum InsertError {
    /// Error accessing the database.
    Access(AccessError),
    /// Block was already in the database.
    Duplicate,
    /// Error when decoding the header to import.
    BadHeader(header::Error),
    /// Parent of the block to insert isn't in the database.
    MissingParent,
    /// Block isn't a descendant of the latest finalized block.
    FinalizedNephew,
}

/// Error while calling [`SqliteFullDatabase::set_finalized`].
#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum SetFinalizedError {
    /// Error accessing the database.
    Access(AccessError),
    /// New finalized block isn't in the database.
    UnknownBlock,
    /// New finalized block must be a child of the previous finalized block.
    RevertForbidden,
}

/// Error while accessing the storage of the finalized block.
#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum FinalizedAccessError {
    /// Error accessing the database.
    Access(AccessError),
    /// Block hash passed as parameter is no longer the finalized block.
    Obsolete,
}

/// Error in the content of the database.
// TODO: document and see if any entry is unused
#[derive(Debug, derive_more::Display)]
pub enum CorruptedError {
    /// Block numbers are expected to be 64 bits.
    // TODO: remove this and use stronger schema
    InvalidNumber,
    /// Finalized block number stored in the database doesn't match any block.
    InvalidFinalizedNum,
    /// A block hash is expected to be 32 bytes. This isn't the case.
    InvalidBlockHashLen,
    /// The parent of a block in the database couldn't be found in that same database.
    BrokenChain,
    /// Missing a key in the `meta` table.
    MissingMetaKey,
    /// Some parts of the database refer to a block by its hash, but the block's constituents
    /// couldn't be found.
    MissingBlockHeader,
    BestBlockHashBadLength,
    BlockHeaderCorrupted(header::Error),
    BlockBodyCorrupted,
    /// Multiple different consensus algorithms are mixed within the database.
    ConsensusAlgorithmMix,
    InvalidGrandpaAuthoritiesList,
    InvalidBabeEpochInformation,
    Internal(InternalError),
}

/// Low-level database error, such as an error while accessing the file system.
#[derive(Debug, derive_more::Display)]
pub struct InternalError(sqlite::Error);

fn meta_get(database: &sqlite::Connection, key: &[u8]) -> Result<Option<Vec<u8>>, AccessError> {
    let mut statement = database
        .prepare(r#"SELECT value FROM meta WHERE key = ?"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?;
    statement.bind(1, key).unwrap();

    if !matches!(statement.next().unwrap(), sqlite::State::Row) {
        return Ok(None);
    }

    let value = statement
        .read::<Vec<u8>>(0)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?;
    Ok(Some(value))
}

fn meta_set(database: &sqlite::Connection, key: &[u8], value: &[u8]) -> Result<(), AccessError> {
    let mut statement = database
        .prepare(r#"INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?;
    statement.bind(1, key).unwrap();
    statement.bind(2, value).unwrap();
    statement.next().unwrap();
    Ok(())
}

fn has_block(database: &sqlite::Connection, hash: &[u8]) -> Result<bool, AccessError> {
    let mut statement = database
        .prepare(r#"SELECT COUNT(*) FROM block_header WHERE hash = ?"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?;
    statement.bind(1, hash).unwrap();

    if !matches!(statement.next().unwrap(), sqlite::State::Row) {
        panic!()
    }

    Ok(statement.read::<i64>(0).unwrap() != 0)
}

// TODO: the fact that the meta table stores blobs makes it impossible to use joins ; fix that
fn finalized_num(database: &sqlite::Connection) -> Result<u64, AccessError> {
    let value = meta_get(database, b"finalized")?
        .ok_or(AccessError::Corrupted(CorruptedError::MissingMetaKey))?;
    expect_be_u64(&value)
}

fn finalized_hash(database: &sqlite::Connection) -> Result<[u8; 32], AccessError> {
    let num = finalized_num(database)?;

    let mut statement = database
        .prepare(r#"SELECT hash FROM blocks_by_number WHERE number = ?"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?;
    statement.bind(1, i64::try_from(num).unwrap()).unwrap();

    if !matches!(statement.next().unwrap(), sqlite::State::Row) {
        return Err(AccessError::Corrupted(CorruptedError::InvalidFinalizedNum).into());
    }

    let value = statement
        .read::<Vec<u8>>(0)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?;

    if value.len() == 32 {
        let mut out = [0; 32];
        out.copy_from_slice(&value);
        Ok(out)
    } else {
        Err(AccessError::Corrupted(CorruptedError::InvalidBlockHashLen).into())
    }
}

fn block_hashes_by_number(
    database: &sqlite::Connection,
    number: u64,
) -> Result<Vec<[u8; 32]>, AccessError> {
    let number = match i64::try_from(number) {
        Ok(n) => n,
        Err(_) => return Ok(Vec::new()),
    };

    let mut statement = database
        .prepare(r#"SELECT hash FROM blocks_by_number WHERE number = ?"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?;
    statement.bind(1, number).unwrap();

    let mut out = Vec::new();
    while matches!(statement.next().unwrap(), sqlite::State::Row) {
        let value = statement
            .read::<Vec<u8>>(0)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)
            .map_err(AccessError::Corrupted)?;

        out.push(
            <[u8; 32]>::try_from(&value[..])
                .map_err(|_| AccessError::Corrupted(CorruptedError::InvalidBlockHashLen))?,
        );
    }

    Ok(out)
}

fn block_header(
    database: &sqlite::Connection,
    hash: &[u8; 32],
) -> Result<Option<header::Header>, AccessError> {
    let mut statement = database
        .prepare(r#"SELECT header FROM block_header WHERE hash = ?"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?;
    statement.bind(1, &hash[..]).unwrap();

    if !matches!(statement.next().unwrap(), sqlite::State::Row) {
        return Ok(None);
    }

    let encoded = statement
        .read::<Vec<u8>>(0)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?;

    match header::decode(&encoded) {
        Ok(h) => Ok(Some(h.into())),
        Err(err) => Err(AccessError::Corrupted(CorruptedError::BlockHeaderCorrupted(err)).into()),
    }
}

fn purge_block(
    database: &sqlite::Connection,
    hash: &[u8; 32],
    number: u64,
) -> Result<(), AccessError> {
    let number = match i64::try_from(number) {
        Ok(n) => n,
        Err(_) => return Ok(()),
    };

    let mut statement = database
        .prepare(
            "DELETE FROM non_finalized_changes WHERE hash = :hash;
        DELETE FROM block_body WHERE hash = :hash;
        DELETE FROM block_justification WHERE hash = :hash;
        DELETE FROM block_header WHERE hash = :hash;
        DELETE FROM blocks_by_number WHERE hash = :hash AND number = :number",
        )
        .unwrap();
    statement.bind_by_name(":hash", &hash[..]).unwrap();
    statement.bind_by_name(":number", number).unwrap();
    statement.next().unwrap();

    Ok(())
}

fn grandpa_authorities_set_id(database: &sqlite::Connection) -> Result<Option<u64>, AccessError> {
    let value = match meta_get(database, b"grandpa_authorities_set_id")? {
        Some(v) => v,
        None => return Ok(None),
    };

    Ok(Some(expect_be_u64(&value)?))
}

fn grandpa_finalized_triggered_authorities(
    database: &sqlite::Connection,
) -> Result<Option<Vec<header::GrandpaAuthority>>, AccessError> {
    let value = match meta_get(database, b"grandpa_triggered_authorities")? {
        Some(v) => v,
        None => return Ok(None),
    };

    Ok(Some(decode_grandpa_authorities_list(&value)?))
}

fn grandpa_finalized_scheduled_change(
    database: &sqlite::Connection,
) -> Result<Option<(u64, Vec<header::GrandpaAuthority>)>, AccessError> {
    match (
        meta_get(database, b"grandpa_scheduled_authorities")?,
        meta_get(database, b"grandpa_scheduled_target")?,
    ) {
        (Some(authorities), Some(height)) => {
            let authorities = decode_grandpa_authorities_list(&authorities)?;
            let height = expect_be_u64(&height)?;
            Ok(Some((height, authorities)))
        }
        (None, None) => Ok(None),
        _ => Err(AccessError::Corrupted(CorruptedError::InvalidGrandpaAuthoritiesList).into()),
    }
}

fn expect_be_u64(value: &[u8]) -> Result<u64, AccessError> {
    <[u8; 8]>::try_from(value)
        .map(u64::from_be_bytes)
        .map_err(|_| CorruptedError::InvalidNumber)
        .map_err(AccessError::Corrupted)
}

fn expect_be_nz_u64(value: &[u8]) -> Result<NonZeroU64, AccessError> {
    let num = expect_be_u64(value)?;
    NonZeroU64::new(num)
        .ok_or(CorruptedError::InvalidNumber)
        .map_err(AccessError::Corrupted)
}

fn encode_aura_authorities_list(list: header::AuraAuthoritiesIter) -> Vec<u8> {
    let mut out = Vec::with_capacity(list.len() * 32);
    for authority in list {
        out.extend_from_slice(authority.public_key);
    }
    debug_assert_eq!(out.len(), out.capacity());
    out
}

fn decode_aura_authorities_list(value: &[u8]) -> Result<Vec<header::AuraAuthority>, AccessError> {
    if value.len() % 32 != 0 {
        return Err(AccessError::Corrupted(CorruptedError::InvalidGrandpaAuthoritiesList).into());
    }

    Ok(value
        .chunks(32)
        .map(|chunk| {
            let public_key = <[u8; 32]>::try_from(chunk).unwrap();
            header::AuraAuthority { public_key }
        })
        .collect())
}

fn encode_grandpa_authorities_list(list: header::GrandpaAuthoritiesIter) -> Vec<u8> {
    let mut out = Vec::with_capacity(list.len() * 40);
    for authority in list {
        out.extend_from_slice(authority.public_key);
        out.extend_from_slice(&authority.weight.get().to_le_bytes()[..]);
    }
    debug_assert_eq!(out.len(), out.capacity());
    out
}

fn decode_grandpa_authorities_list(
    value: &[u8],
) -> Result<Vec<header::GrandpaAuthority>, AccessError> {
    if value.len() % 40 != 0 {
        return Err(AccessError::Corrupted(CorruptedError::InvalidGrandpaAuthoritiesList).into());
    }

    let mut out = Vec::with_capacity(value.len() / 40);
    for chunk in value.chunks(40) {
        let public_key = <[u8; 32]>::try_from(&chunk[..32]).unwrap();
        let weight = u64::from_le_bytes(<[u8; 8]>::try_from(&chunk[32..]).unwrap());
        let weight = NonZeroU64::new(weight)
            .ok_or(CorruptedError::InvalidGrandpaAuthoritiesList)
            .map_err(AccessError::Corrupted)?;
        out.push(header::GrandpaAuthority { public_key, weight });
    }

    Ok(out)
}

fn encode_babe_epoch_information(info: chain_information::BabeEpochInformationRef) -> Vec<u8> {
    let mut out = Vec::with_capacity(69 + info.authorities.len() * 40);
    out.extend_from_slice(&info.epoch_index.to_le_bytes());
    if let Some(start_slot_number) = info.start_slot_number {
        out.extend_from_slice(&[1]);
        out.extend_from_slice(&start_slot_number.to_le_bytes());
    } else {
        out.extend_from_slice(&[0]);
    }
    out.extend_from_slice(util::encode_scale_compact_usize(info.authorities.len()).as_ref());
    for authority in info.authorities {
        out.extend_from_slice(authority.public_key);
        out.extend_from_slice(&authority.weight.to_le_bytes());
    }
    out.extend_from_slice(info.randomness);
    out.extend_from_slice(&info.c.0.to_le_bytes());
    out.extend_from_slice(&info.c.1.to_le_bytes());
    out.extend_from_slice(match info.allowed_slots {
        header::BabeAllowedSlots::PrimarySlots => &[0],
        header::BabeAllowedSlots::PrimaryAndSecondaryPlainSlots => &[1],
        header::BabeAllowedSlots::PrimaryAndSecondaryVrfSlots => &[2],
    });
    out
}

fn decode_babe_epoch_information(
    value: &[u8],
) -> Result<chain_information::BabeEpochInformation, AccessError> {
    let result = nom::combinator::all_consuming(nom::combinator::map(
        nom::sequence::tuple((
            nom::number::complete::le_u64,
            util::nom_option_decode(nom::number::complete::le_u64),
            nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
                nom::multi::many_m_n(
                    num_elems,
                    num_elems,
                    nom::combinator::map(
                        nom::sequence::tuple((
                            nom::bytes::complete::take(32u32),
                            nom::number::complete::le_u64,
                        )),
                        move |(public_key, weight)| header::BabeAuthority {
                            public_key: TryFrom::try_from(public_key).unwrap(),
                            weight,
                        },
                    ),
                )
            }),
            nom::bytes::complete::take(32u32),
            nom::sequence::tuple((nom::number::complete::le_u64, nom::number::complete::le_u64)),
            nom::branch::alt((
                nom::combinator::map(nom::bytes::complete::tag(&[0]), |_| {
                    header::BabeAllowedSlots::PrimarySlots
                }),
                nom::combinator::map(nom::bytes::complete::tag(&[1]), |_| {
                    header::BabeAllowedSlots::PrimaryAndSecondaryPlainSlots
                }),
                nom::combinator::map(nom::bytes::complete::tag(&[2]), |_| {
                    header::BabeAllowedSlots::PrimaryAndSecondaryVrfSlots
                }),
            )),
        )),
        |(epoch_index, start_slot_number, authorities, randomness, c, allowed_slots)| {
            chain_information::BabeEpochInformation {
                epoch_index,
                start_slot_number,
                authorities,
                randomness: TryFrom::try_from(randomness).unwrap(),
                c,
                allowed_slots,
            }
        },
    ))(&value)
    .map(|(_, v)| v)
    .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| ());

    result
        .map_err(|()| CorruptedError::InvalidBabeEpochInformation)
        .map_err(AccessError::Corrupted)
}
