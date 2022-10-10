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
//! not supported.
//!
//! In order to minimize disk usage, it is not possible to efficiently retrieve the storage items
//! of blocks that are ancestors of the finalized block. When a block is finalized, the storage of
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
//! The SQL schema of the database, with explanatory comments, can be found in `open.rs`.
//!
//! # About blocking behavior
//!
//! This implementation uses the SQLite library, which isn't Rust-asynchronous-compatible. Many
//! functions will, with the help of the operating system, put the current thread to sleep while
//! waiting for an I/O operation to finish. In the context of asynchronous Rust, this is
//! undesirable.
//!
//! For this reason, you are encouraged to isolate the database in its own threads and never
//! access it directly from an asynchronous context.
//!

// TODO: better docs

#![cfg(feature = "database-sqlite")]
#![cfg_attr(docsrs, doc(cfg(feature = "database-sqlite")))]

use crate::{chain::chain_information, executor, header};

use core::{fmt, iter};
use parking_lot::Mutex;

pub use open::{open, Config, ConfigTy, DatabaseEmpty, DatabaseOpen};

mod open;

/// An open database. Holds file descriptors.
pub struct SqliteFullDatabase {
    /// The SQLite connection.
    ///
    /// The database is constantly within a transaction.
    /// When the database is opened, `BEGIN TRANSACTION` is immediately run. We periodically
    /// call `COMMIT; BEGIN_TRANSACTION` when deemed necessary. `COMMIT` is basically the
    /// equivalent of `fsync`, and must be called carefully in order to not lose too much speed.
    database: Mutex<sqlite::Connection>,

    /// Number of bytes used to encode the block number.
    block_number_bytes: usize,
}

impl SqliteFullDatabase {
    /// Returns the hash of the block in the database whose storage is currently accessible.
    pub fn best_block_hash(&self) -> Result<[u8; 32], AccessError> {
        let connection = self.database.lock();

        let val = meta_get_blob(&connection, "best")?
            .ok_or(AccessError::Corrupted(CorruptedError::MissingMetaKey))?;
        if val.len() == 32 {
            let mut out = [0; 32];
            out.copy_from_slice(&val);
            Ok(out)
        } else {
            Err(AccessError::Corrupted(CorruptedError::InvalidBlockHashLen))
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
            .prepare(r#"SELECT header FROM blocks WHERE hash = ?"#)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)?
            .bind(1, &block_hash[..])
            .unwrap();

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
            .prepare(r#"SELECT extrinsic FROM blocks_body WHERE hash = ? ORDER BY idx ASC"#)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)?
            .bind(1, &block_hash[..])
            .unwrap();

        // TODO: doesn't detect if block is absent

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
            .prepare(r#"SELECT hash FROM blocks WHERE number = ?"#)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)?
            .bind(1, block_number)
            .unwrap();

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
    ) -> Result<chain_information::ValidChainInformation, FinalizedAccessError> {
        let connection = self.database.lock();
        if finalized_hash(&connection)? != *finalized_block_hash {
            return Err(FinalizedAccessError::Obsolete);
        }

        let finalized_block_header =
            block_header(&connection, finalized_block_hash, self.block_number_bytes)?
                .ok_or(AccessError::Corrupted(CorruptedError::MissingBlockHeader))?;

        let runtime = {
            let code = finalized_block_storage_top_trie(&connection, b":code")?.ok_or(
                AccessError::Corrupted(CorruptedError::InvalidChainInformation(
                    InvalidChainInformationError::MissingRuntimeCode,
                )),
            )?;
            let heap_pages = executor::storage_heap_pages_to_value(
                finalized_block_storage_top_trie(&connection, b":heappages")?
                    .as_ref()
                    .map(|v| &v[..]),
            )
            .map_err(|err| {
                AccessError::Corrupted(CorruptedError::InvalidChainInformation(
                    InvalidChainInformationError::InvalidHeapPages(err),
                ))
            })?;

            executor::host::HostVmPrototype::new(executor::host::Config {
                module: &code,
                heap_pages,
                exec_hint: executor::vm::ExecHint::Oneshot,
                allow_unresolved_imports: false,
            })
            .map_err(|err| {
                AccessError::Corrupted(CorruptedError::InvalidChainInformation(
                    InvalidChainInformationError::InvalidRuntime(err),
                ))
            })?
        };

        let mut chain_info_builder = chain_information::build::ChainInformationBuild::new(
            chain_information::build::Config {
                runtime,
                finalized_block_header: if finalized_block_header.number == 0 {
                    chain_information::build::ConfigFinalizedBlockHeader::Genesis {
                        state_trie_root_hash: finalized_block_header.state_root,
                    }
                } else {
                    chain_information::build::ConfigFinalizedBlockHeader::NonGenesis {
                        header: finalized_block_header,
                        known_finality: None,
                    }
                },
            },
        );

        // TODO: consider returning the runtime

        let chain_info = loop {
            match chain_info_builder {
                chain_information::build::ChainInformationBuild::Finished {
                    result: Ok(info),
                    ..
                } => {
                    break info;
                }
                chain_information::build::ChainInformationBuild::Finished {
                    result: Err(error),
                    ..
                } => {
                    return Err(FinalizedAccessError::Access(AccessError::Corrupted(
                        CorruptedError::InvalidChainInformation(
                            InvalidChainInformationError::Build(error),
                        ),
                    )))
                }
                chain_information::build::ChainInformationBuild::InProgress(
                    chain_information::build::InProgress::StorageGet(get),
                ) => {
                    let value = finalized_block_storage_top_trie(&connection, &get.key_as_vec())?;
                    chain_info_builder = get.inject_value(value.map(iter::once));
                }
                chain_information::build::ChainInformationBuild::InProgress(
                    chain_information::build::InProgress::NextKey(_),
                ) => {
                    // TODO:
                    todo!()
                }
            }
        };

        Ok(chain_info)
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
        let header = header::decode(scale_encoded_header, self.block_number_bytes)
            .map_err(InsertError::BadHeader)?;

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
            .prepare(
                "INSERT INTO blocks(number, hash, header, justification) VALUES (?, ?, ?, NULL)",
            )
            .unwrap()
            .bind(1, i64::try_from(header.number).unwrap())
            .unwrap()
            .bind(2, &block_hash[..])
            .unwrap()
            .bind(3, scale_encoded_header)
            .unwrap();
        statement.next().unwrap();

        let mut statement = connection
            .prepare("INSERT INTO blocks_body(hash, idx, extrinsic) VALUES (?, ?, ?)")
            .unwrap();
        for (index, item) in body.enumerate() {
            statement = statement
                .bind(1, &block_hash[..])
                .unwrap()
                .bind(2, i64::try_from(index).unwrap())
                .unwrap()
                .bind(3, item.as_ref())
                .unwrap();
            statement.next().unwrap();
            statement = statement.reset().unwrap();
        }

        // Insert the storage changes.
        let mut statement = connection
            .prepare("INSERT INTO non_finalized_changes(hash, key, value) VALUES (?, ?, ?)")
            .unwrap();
        for (key, value) in storage_top_trie_changes {
            statement = statement
                .bind(1, &block_hash[..])
                .unwrap()
                .bind(2, key.as_ref())
                .unwrap();
            if let Some(value) = value {
                statement = statement.bind(3, value.as_ref()).unwrap();
            } else {
                // Binds NULL.
                statement = statement.bind(3, ()).unwrap();
            }
            statement.next().unwrap();
            statement = statement.reset().unwrap();
        }

        // Various other updates.
        if is_new_best {
            meta_set_blob(&connection, "best", &block_hash)?;
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
        let new_finalized_header = block_header(
            &connection,
            new_finalized_block_hash,
            self.block_number_bytes,
        )?
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
        meta_set_number(&connection, "finalized", new_finalized_header.number)?;

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
                    purge_block(&connection, &hash_at_height)?;
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
                    let header =
                        block_header(&connection, &expected_hash, self.block_number_bytes)?.ok_or(
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
                let header = block_header(&connection, &block_hash, self.block_number_bytes)?
                    .ok_or(AccessError::Corrupted(CorruptedError::MissingBlockHeader))?;
                if allowed_parents.iter().any(|p| *p == header.parent_hash) {
                    next_iter_allowed_parents.push(block_hash);
                    continue;
                }

                purge_block(&connection, &block_hash)?;
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

            let mut statement = connection
                .prepare(
                    "DELETE FROM finalized_storage_top_trie
                WHERE key IN (
                    SELECT key FROM non_finalized_changes WHERE hash = ? AND value IS NULL
                );",
                )
                .unwrap()
                .bind(1, &block_hash[..])
                .unwrap();
            statement.next().unwrap();

            let mut statement = connection
                .prepare(
                    "INSERT OR REPLACE INTO finalized_storage_top_trie(key, value)
                SELECT key, value
                FROM non_finalized_changes 
                WHERE non_finalized_changes.hash = ? AND non_finalized_changes.value IS NOT NULL",
                )
                .unwrap()
                .bind(1, &block_hash[..])
                .unwrap();
            statement.next().unwrap();

            // Remove the entries from `non_finalized_changes` as they are now finalized.
            let mut statement = connection
                .prepare("DELETE FROM non_finalized_changes WHERE hash = ?")
                .unwrap()
                .bind(1, &block_hash[..])
                .unwrap();
            statement.next().unwrap();
        }

        // It is possible that the best block has been pruned.
        // TODO: ^ yeah, how do we handle that exactly ^ ?

        // Make sure that everything is saved to disk after this point.
        flush(&connection)?;

        Ok(())
    }

    /// Returns all the keys and values in the storage of the finalized block.
    ///
    /// In order to avoid race conditions, the known finalized block hash must be passed as
    /// parameter. If the finalized block in the database doesn't match the hash passed as
    /// parameter, most likely because it has been updated in a parallel thread, a
    /// [`FinalizedAccessError::Obsolete`] error is returned.
    ///
    /// The return value must implement the `FromIterator` trait, being passed an iterator that
    /// produces tuples of keys and values.
    pub fn finalized_block_storage_top_trie<T: FromIterator<(Vec<u8>, Vec<u8>)>>(
        &self,
        finalized_block_hash: &[u8; 32],
    ) -> Result<T, FinalizedAccessError> {
        let connection = self.database.lock();

        if finalized_hash(&connection)? != *finalized_block_hash {
            return Err(FinalizedAccessError::Obsolete);
        }

        let mut statement = connection
            .prepare(r#"SELECT key, value FROM finalized_storage_top_trie"#)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)
            .map_err(AccessError::Corrupted)
            .map_err(FinalizedAccessError::Access)?;

        let out: T = iter::from_fn(|| {
            if !matches!(statement.next().unwrap(), sqlite::State::Row) {
                return None;
            }

            let key = statement.read::<Vec<u8>>(0).unwrap();
            let value = statement.read::<Vec<u8>>(1).unwrap();
            Some((key, value))
        })
        .collect();

        Ok(out)
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

        finalized_block_storage_top_trie(&connection, key).map_err(FinalizedAccessError::Access)
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
            .map_err(FinalizedAccessError::Access)?.bind(1, key).unwrap();

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

        finalized_block_storage_top_trie_keys(&connection, prefix)
            .map_err(FinalizedAccessError::Access)
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
    #[display(fmt = "Database corrupted: {}", _0)]
    Corrupted(CorruptedError),
}

/// Error while calling [`SqliteFullDatabase::insert`].
#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum InsertError {
    /// Error accessing the database.
    #[display(fmt = "{}", _0)]
    Access(AccessError),
    /// Block was already in the database.
    Duplicate,
    /// Error when decoding the header to import.
    #[display(fmt = "Failed to decode header: {}", _0)]
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
    /// Values in the database are all well-formatted, but are incoherent.
    #[display(fmt = "Invalid chain information: {}", _0)]
    InvalidChainInformation(InvalidChainInformationError),
    /// The parent of a block in the database couldn't be found in that same database.
    BrokenChain,
    /// Missing a key in the `meta` table.
    MissingMetaKey,
    /// Some parts of the database refer to a block by its hash, but the block's constituents
    /// couldn't be found.
    MissingBlockHeader,
    /// The header of a block in the database has failed to decode.
    #[display(fmt = "Corrupted block header: {}", _0)]
    BlockHeaderCorrupted(header::Error),
    /// Multiple different consensus algorithms are mixed within the database.
    ConsensusAlgorithmMix,
    /// The information about a Babe epoch found in the database has failed to decode.
    InvalidBabeEpochInformation,
    #[display(fmt = "Internal error: {}", _0)]
    Internal(InternalError),
}

/// Error in the content of the database.
#[derive(Debug, derive_more::Display)]
pub enum InvalidChainInformationError {
    /// Runtime code is missing from the finalized block storage.
    MissingRuntimeCode,
    /// Heap pages is in an invalid format.
    #[display(fmt = "Invalid heap pages format: {}", _0)]
    InvalidHeapPages(executor::InvalidHeapPagesError),
    /// Failed to build the runtime.
    #[display(fmt = "Failed to build runtime: {}", _0)]
    InvalidRuntime(executor::host::NewErr),
    /// Error while building the chain information from the runtime.
    #[display(fmt = "{}", _0)]
    Build(chain_information::build::Error),
}

/// Low-level database error, such as an error while accessing the file system.
#[derive(Debug, derive_more::Display)]
pub struct InternalError(sqlite::Error);

fn meta_get_blob(database: &sqlite::Connection, key: &str) -> Result<Option<Vec<u8>>, AccessError> {
    let mut statement = database
        .prepare(r#"SELECT value_blob FROM meta WHERE key = ?"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?
        .bind(1, key)
        .unwrap();

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

fn meta_get_number(database: &sqlite::Connection, key: &str) -> Result<Option<u64>, AccessError> {
    let mut statement = database
        .prepare(r#"SELECT value_number FROM meta WHERE key = ?"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?
        .bind(1, key)
        .unwrap();

    if !matches!(statement.next().unwrap(), sqlite::State::Row) {
        return Ok(None);
    }

    let value = statement
        .read::<i64>(0)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?;
    Ok(Some(u64::from_ne_bytes(value.to_ne_bytes())))
}

fn meta_set_blob(
    database: &sqlite::Connection,
    key: &str,
    value: &[u8],
) -> Result<(), AccessError> {
    let mut statement = database
        .prepare(r#"INSERT OR REPLACE INTO meta(key, value_blob) VALUES (?, ?)"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?
        .bind(1, key)
        .unwrap()
        .bind(2, value)
        .unwrap();
    statement.next().unwrap();
    Ok(())
}

fn meta_set_number(
    database: &sqlite::Connection,
    key: &str,
    value: u64,
) -> Result<(), AccessError> {
    let mut statement = database
        .prepare(r#"INSERT OR REPLACE INTO meta(key, value_number) VALUES (?, ?)"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?
        .bind(1, key)
        .unwrap()
        .bind(2, i64::from_ne_bytes(value.to_ne_bytes()))
        .unwrap();
    statement.next().unwrap();
    Ok(())
}

fn has_block(database: &sqlite::Connection, hash: &[u8]) -> Result<bool, AccessError> {
    let mut statement = database
        .prepare(r#"SELECT COUNT(*) FROM blocks WHERE hash = ?"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?
        .bind(1, hash)
        .unwrap();

    if !matches!(statement.next().unwrap(), sqlite::State::Row) {
        panic!()
    }

    Ok(statement.read::<i64>(0).unwrap() != 0)
}

// TODO: the fact that the meta table stores blobs makes it impossible to use joins ; fix that
fn finalized_num(database: &sqlite::Connection) -> Result<u64, AccessError> {
    meta_get_number(database, "finalized")?
        .ok_or(AccessError::Corrupted(CorruptedError::MissingMetaKey))
}

fn finalized_hash(database: &sqlite::Connection) -> Result<[u8; 32], AccessError> {
    let mut statement = database
        .prepare(r#"SELECT hash FROM blocks WHERE number = (SELECT value_number FROM meta WHERE key = "finalized")"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?;

    if !matches!(statement.next().unwrap(), sqlite::State::Row) {
        return Err(AccessError::Corrupted(CorruptedError::InvalidFinalizedNum));
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
        Err(AccessError::Corrupted(CorruptedError::InvalidBlockHashLen))
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
        .prepare(r#"SELECT hash FROM blocks WHERE number = ?"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?
        .bind(1, number)
        .unwrap();

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
    block_number_bytes: usize,
) -> Result<Option<header::Header>, AccessError> {
    let mut statement = database
        .prepare(r#"SELECT header FROM blocks WHERE hash = ?"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?
        .bind(1, &hash[..])
        .unwrap();

    if !matches!(statement.next().unwrap(), sqlite::State::Row) {
        return Ok(None);
    }

    let encoded = statement
        .read::<Vec<u8>>(0)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?;

    match header::decode(&encoded, block_number_bytes) {
        Ok(h) => Ok(Some(h.into())),
        Err(err) => Err(AccessError::Corrupted(
            CorruptedError::BlockHeaderCorrupted(err),
        )),
    }
}

fn finalized_block_storage_top_trie(
    database: &sqlite::Connection,
    key: &[u8],
) -> Result<Option<Vec<u8>>, AccessError> {
    let mut statement = database
        .prepare(r#"SELECT value FROM finalized_storage_top_trie WHERE key = ?"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?
        .bind(1, key)
        .unwrap();

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

fn finalized_block_storage_top_trie_keys(
    database: &sqlite::Connection,
    prefix: &[u8],
) -> Result<Vec<Vec<u8>>, AccessError> {
    let mut statement = database
        .prepare(r#"SELECT key FROM finalized_storage_top_trie WHERE key >= ?"#)
        .map_err(InternalError)
        .map_err(CorruptedError::Internal)
        .map_err(AccessError::Corrupted)?
        .bind(1, prefix)
        .unwrap();

    let mut out = Vec::new();
    while matches!(statement.next().unwrap(), sqlite::State::Row) {
        let key = statement
            .read::<Vec<u8>>(0)
            .map_err(InternalError)
            .map_err(CorruptedError::Internal)
            .map_err(AccessError::Corrupted)?;

        // TODO: hack because I don't know how to ask sqlite to do that
        if !(key.starts_with(prefix)) {
            continue;
        }

        out.push(key);
    }

    Ok(out)
}

fn flush(database: &sqlite::Connection) -> Result<(), AccessError> {
    database.execute("COMMIT; BEGIN TRANSACTION;").unwrap();
    Ok(())
}

fn purge_block(database: &sqlite::Connection, hash: &[u8; 32]) -> Result<(), AccessError> {
    let mut statement = database
        .prepare(
            "DELETE FROM non_finalized_changes WHERE hash = :hash;
        DELETE FROM blocks_body WHERE hash = :hash;
        DELETE FROM blocks WHERE hash = :hash;",
        )
        .unwrap()
        .bind_by_name(":hash", &hash[..])
        .unwrap();
    statement.next().unwrap();

    Ok(())
}
