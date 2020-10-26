// Substrate-lite
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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

//! Database opening code.
//!
//! Contains everything related to the opening and initialization of the database.

use super::{AccessError, SledError, SledFullDatabase};

use sled::Transactional as _;
use std::path::Path;

/// Opens the database using the given [`Config`].
///
/// Note that this doesn't return a [`SledFullDatabase`], but rather a [`DatabaseOpen`].
pub fn open(config: Config) -> Result<DatabaseOpen, SledError> {
    let database = sled::Config::default()
        // We put a `/v1/` behind the path in case we change the schema.
        .path(config.path.join("v1"))
        .use_compression(true)
        .open()
        .map_err(SledError)?;

    let meta_tree = database.open_tree(b"meta").map_err(SledError)?;
    let block_hashes_by_number_tree = database
        .open_tree(b"block_hashes_by_number")
        .map_err(SledError)?;
    let block_headers_tree = database.open_tree(b"block_headers").map_err(SledError)?;
    let block_bodies_tree = database.open_tree(b"block_bodies").map_err(SledError)?;
    let finalized_storage_top_trie_tree = database
        .open_tree(b"finalized_storage_top_trie")
        .map_err(SledError)?;
    let non_finalized_changes_keys_tree = database
        .open_tree(b"non_finalized_changes_keys")
        .map_err(SledError)?;
    let non_finalized_changes_tree = database
        .open_tree(b"non_finalized_changes")
        .map_err(SledError)?;

    Ok(if meta_tree.get(b"best").map_err(SledError)?.is_some() {
        DatabaseOpen::Open(SledFullDatabase {
            block_hashes_by_number_tree,
            meta_tree,
            block_headers_tree,
            block_bodies_tree,
            finalized_storage_top_trie_tree,
            non_finalized_changes_keys_tree,
            non_finalized_changes_tree,
        })
    } else {
        DatabaseOpen::Empty(DatabaseEmpty {
            block_hashes_by_number_tree,
            meta_tree,
            block_headers_tree,
            block_bodies_tree,
            finalized_storage_top_trie_tree,
            non_finalized_changes_keys_tree,
            non_finalized_changes_tree,
        })
    })
}

/// Configuration for the database.
#[derive(Debug)]
pub struct Config<'a> {
    /// Path to the directory containing the database.
    pub path: &'a Path,
}

/// Either existing database or database prototype.
pub enum DatabaseOpen {
    /// A database already existed and has now been opened.
    Open(SledFullDatabase),

    /// Either a database has just been created, or there existed a database but it is empty.
    ///
    /// > **Note**: The situation where a database existed but is empty can happen if you have
    /// >           previously called [`open`] then dropped the [`DatabaseOpen`] object without
    /// >           filling the newly-created database with data.
    Empty(DatabaseEmpty),
}

/// An open database. Holds file descriptors.
pub struct DatabaseEmpty {
    /// See the similar field in [`SledFullDatabase`].
    meta_tree: sled::Tree,

    /// See the similar field in [`SledFullDatabase`].
    block_hashes_by_number_tree: sled::Tree,

    /// See the similar field in [`SledFullDatabase`].
    block_headers_tree: sled::Tree,

    /// See the similar field in [`SledFullDatabase`].
    block_bodies_tree: sled::Tree,

    /// See the similar field in [`SledFullDatabase`].
    finalized_storage_top_trie_tree: sled::Tree,

    /// See the similar field in [`SledFullDatabase`].
    non_finalized_changes_keys_tree: sled::Tree,

    /// See the similar field in [`SledFullDatabase`].
    non_finalized_changes_tree: sled::Tree,
}

impl DatabaseEmpty {
    /// Inserts the genesis block in the database prototype in order to turn it into an actual
    /// database.
    pub fn insert_genesis_block<'a>(
        self,
        scale_encoded_genesis_block_header: &[u8],
        storage_top_trie_entries: impl Iterator<Item = (&'a [u8], &'a [u8])> + Clone,
    ) -> Result<SledFullDatabase, AccessError> {
        // Calculate the hash of the genesis block.
        let genesis_block_hash =
            crate::header::hash_from_scale_encoded_header(scale_encoded_genesis_block_header);

        // Try to apply changes. This is done atomically through a transaction.
        let result = (
            &self.block_hashes_by_number_tree,
            &self.block_headers_tree,
            &self.block_bodies_tree,
            &self.finalized_storage_top_trie_tree,
            &self.meta_tree,
        )
            .transaction(
                move |(
                    block_hashes_by_number,
                    block_headers,
                    block_bodies,
                    storage_top_trie,
                    meta,
                )| {
                    for (key, value) in storage_top_trie_entries.clone() {
                        storage_top_trie.insert(key, value)?;
                    }

                    block_hashes_by_number
                        .insert(&0u64.to_be_bytes()[..], &genesis_block_hash[..])?;

                    block_headers
                        .insert(&genesis_block_hash[..], scale_encoded_genesis_block_header)?;
                    block_bodies.insert(
                        &genesis_block_hash[..],
                        parity_scale_codec::Encode::encode(&Vec::<Vec<u8>>::new()),
                    )?;
                    meta.insert(b"best", &genesis_block_hash[..])?;
                    meta.insert(b"finalized", &0u64.to_be_bytes()[..])?;
                    meta.insert(b"grandpa_authorities_set_id", &0u64.to_be_bytes()[..])?;
                    Ok(())
                },
            );

        match result {
            Ok(()) => Ok(SledFullDatabase {
                block_hashes_by_number_tree: self.block_hashes_by_number_tree,
                meta_tree: self.meta_tree,
                block_headers_tree: self.block_headers_tree,
                block_bodies_tree: self.block_bodies_tree,
                finalized_storage_top_trie_tree: self.finalized_storage_top_trie_tree,
                non_finalized_changes_keys_tree: self.non_finalized_changes_keys_tree,
                non_finalized_changes_tree: self.non_finalized_changes_tree,
            }),
            Err(sled::transaction::TransactionError::Abort(())) => unreachable!(),
            Err(sled::transaction::TransactionError::Storage(err)) => {
                Err(AccessError::Database(SledError(err)))
            }
        }
    }
}
