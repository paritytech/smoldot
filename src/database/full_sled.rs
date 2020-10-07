// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Filesystem-backed database containing all the information about a chain.
//!
//! This module handles the persistent storage of the chain on disk.

// TODO: better docs

#![cfg(feature = "database-sled")]
#![cfg_attr(docsrs, doc(cfg(feature = "database-sled")))]

use crate::header;

use core::{convert::TryFrom as _, fmt, iter, ops};
use sled::Transactional as _;

pub use open::{open, Config, DatabaseOpen};

mod open;

/// An open database. Holds file descriptors.
pub struct SledFullDatabase {
    /// Tree named "meta" in the database.
    /// Contains all the meta-information about the content.
    ///
    /// Keys in that tree are:
    ///
    /// - `best`: Hash of the best block.
    /// - `finalized`: Height of the finalized block, as a 64bits big endian number.
    /// - `grandpa_authorities_set_id`: A 64bits big endian number representing the authorities
    /// set id that must finalize the block right after the finalized block.
    /// - `grandpa_triggered_authorities_scheduled_height`: A 64bits big endian number
    /// containing the height of the finalized block that scheduled the authorities that must
    /// finalize the block right after the latest finalized block. The list of authorities can be
    /// found in that block's header. Missing if `grandpa_authorities_set_id` is 0, in which case
    /// the authorities are the one in the genesis block.
    /// - `grandpa_scheduled_non_triggered_authorities_height`: A 64bits big endian number
    /// containing the height of the finalized block that scheduled authorities that haven't been
    /// triggered yet. The list of authorities can be found in that block's header. Missing
    /// there's no scheduled-but-non-finalized authorities change.
    ///
    meta_tree: sled::Tree,

    /// Tree named "block_hashes_by_number" in the database.
    ///
    /// For each possible block number, stores a list of block hashes having that number.
    ///
    /// Keys in that tree are 64-bits-big-endian block numbers, and values are a concatenation of
    /// 32-bytes block hashes (without any encoding). If the value is for example 96 bytes long,
    /// that means there are 3 blocks in the database with that block number.
    ///
    /// Never contains any empty value.
    block_hashes_by_number_tree: sled::Tree,

    /// Tree named "block_headers" in the database.
    ///
    /// Contains an entry for every known block that is a descendant of the finalized block.
    /// When the finalized block is updated, entries that aren't descendants of the new finalized
    /// block are automatically purged.
    ///
    /// Keys are block hashes, and values are SCALE-encoded block headers.
    block_headers_tree: sled::Tree,

    /// Tree named "block_bodies" in the database.
    ///
    /// Entries are the same as for [`SledFullDatabase::block_headers_tree`].
    ///
    /// Keys are block hashes, and values are SCALE-encoded `Vec`s containing the extrinsics. Each
    /// extrinsic is itself a SCALE-encoded `Vec<u8>`.
    block_bodies_tree: sled::Tree,

    /// Tree named "storage_top_trie" in the database.
    ///
    /// Contains the key-value storage at the finalized block.
    ///
    /// Keys are storage keys, and values are storage values.
    finalized_storage_top_trie_tree: sled::Tree,

    /// Tree named "non_finalized_changes_keys" in the database.
    ///
    /// For each hash of non-finalized block, contains the list of keys in the storage that this
    /// bloc modifies.
    ///
    /// Keys are a 32 bytes block hash. Values are a list of SCALE-encoded `Vec<u8>` concatenated
    /// together. In other words, each value is a length (SCALE-compact-encoded), a key of that
    /// length, a length, a key of that length, and so on.
    non_finalized_changes_keys_tree: sled::Tree,

    /// Tree named "non_finalized_changes" in the database.
    ///
    /// For each element in `non_finalized_changes_keys_tree`, contains the new value for this
    /// storage modification.
    ///
    /// Keys are a 32 bytes block hash followed with a storage key. Values are either `0` if the
    /// storage value is to be removed, or `1` followed with the storage value to set.
    non_finalized_changes_tree: sled::Tree,
}

impl SledFullDatabase {
    /// Returns the hash of the block in the database whose storage is currently accessible.
    pub fn best_block_hash(&self) -> Result<[u8; 32], AccessError> {
        match self.meta_tree.get(b"best").map_err(SledError)? {
            Some(val) => {
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
            None => Err(AccessError::Corrupted(
                CorruptedError::BestBlockHashNotFound,
            )),
        }
    }

    /// Returns the hash of the finalized block in the database.
    pub fn finalized_block_hash(&self) -> Result<[u8; 32], AccessError> {
        let result = (&self.block_hashes_by_number_tree, &self.meta_tree).transaction(
            move |(block_hashes_by_number, meta)| {
                let num = meta
                    .get(b"finalized")?
                    .ok_or(AccessError::Corrupted(
                        CorruptedError::FinalizedBlockNumberNotFound,
                    ))
                    .map_err(sled::transaction::ConflictableTransactionError::Abort)?;

                let hash = block_hashes_by_number
                    .get(num)?
                    .ok_or(AccessError::Corrupted(
                        CorruptedError::FinalizedBlockNumberOutOfRange,
                    ))
                    .map_err(sled::transaction::ConflictableTransactionError::Abort)?;
                if hash.len() == 32 {
                    let mut out = [0; 32];
                    out.copy_from_slice(&hash);
                    Ok(out)
                } else {
                    Err(sled::transaction::ConflictableTransactionError::Abort(
                        AccessError::Corrupted(CorruptedError::BlockHashLenInHashNumberMapping),
                    ))
                }
            },
        );

        match result {
            Ok(hash) => Ok(hash),
            Err(sled::transaction::TransactionError::Abort(err)) => Err(err),
            Err(sled::transaction::TransactionError::Storage(err)) => {
                Err(AccessError::Database(SledError(err)))
            }
        }
    }

    /// Returns the SCALE-encoded header of the given block, or `None` if the block is unknown.
    ///
    /// > **Note**: If this method is called twice times in a row with the same block hash, it
    /// >           is possible for the first time to return `Some` and the second time to return
    /// >           `None`, in case the block has since been removed from the database.
    pub fn block_scale_encoded_header(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<Option<VarLenBytes>, AccessError> {
        Ok(self
            .block_headers_tree
            .get(block_hash)
            .map_err(SledError)?
            .map(VarLenBytes))
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
        let body = match self.block_bodies_tree.get(block_hash).map_err(SledError)? {
            Some(b) => b,
            None => return Ok(None),
        };

        let decoded = <Vec<Vec<u8>> as parity_scale_codec::DecodeAll>::decode_all(body.as_ref())
            .map_err(|err| AccessError::Corrupted(CorruptedError::BlockBodyCorrupted(err)))?;
        Ok(Some(decoded.into_iter()))
    }

    /// Returns the hashes of the blocks given a block number.
    pub fn block_hash_by_number(
        &self,
        block_number: u64,
    ) -> Result<impl ExactSizeIterator<Item = [u8; 32]>, AccessError> {
        let hash = self
            .block_hashes_by_number_tree
            .get(&u64::to_be_bytes(block_number)[..])
            .map_err(SledError)?;
        let hash = match hash {
            Some(h) => h,
            None => return Ok(either::Left(iter::empty())),
        };

        if hash.is_empty() || (hash.len() % 32) != 0 {
            return Err(AccessError::Corrupted(
                CorruptedError::BlockHashLenInHashNumberMapping,
            ));
        }

        struct Iter {
            hash: sled::IVec,
            cursor: usize,
        }

        impl Iterator for Iter {
            type Item = [u8; 32];

            fn next(&mut self) -> Option<Self::Item> {
                if self.hash.len() <= self.cursor {
                    let h =
                        <[u8; 32]>::try_from(&self.hash[self.cursor..(self.cursor + 32)]).unwrap();
                    self.cursor += 32;
                    Some(h)
                } else {
                    None
                }
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                debug_assert_eq!(self.cursor % 32, 0);
                let len = (self.hash.len() - self.cursor) / 32;
                (len, Some(len))
            }
        }

        impl ExactSizeIterator for Iter {}

        Ok(either::Right(Iter { hash, cursor: 0 }))
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
        body: impl Iterator<Item = impl AsRef<[u8]>>,
        storage_top_trie_changes: impl Iterator<Item = (impl AsRef<[u8]>, Option<impl AsRef<[u8]>>)>
            + Clone,
    ) -> Result<(), InsertError> {
        // Calculate the hash of the new best block.
        let block_hash = header::hash_from_scale_encoded_header(scale_encoded_header);

        // Decode the header, as we will need various information from it.
        let header = header::decode(&scale_encoded_header).map_err(InsertError::BadHeader)?;

        // Value to put in `block_bodies_tree`. See the documentation of that field.
        let encoded_body = {
            // TODO: optimize by not building an intermediary `Vec`
            let body = body.map(|e| e.as_ref().to_vec()).collect::<Vec<_>>();
            parity_scale_codec::Encode::encode(&body)
        };

        // Value to put in `non_finalized_changes_keys_tree`. See the documentation of that field.
        let changed_keys =
            storage_top_trie_changes
                .clone()
                .fold(Vec::new(), |mut list, (key, _)| {
                    let key = key.as_ref();
                    // TODO: don't use parity_scale_codec
                    parity_scale_codec::Encode::encode_to(
                        &parity_scale_codec::Compact(u64::try_from(key.len()).unwrap()),
                        &mut list,
                    );
                    list.extend_from_slice(key);
                    list
                });

        // Try to apply changes. This is done atomically through a transaction.
        let result = (
            &self.meta_tree,
            &self.block_hashes_by_number_tree,
            &self.block_headers_tree,
            &self.block_bodies_tree,
            &self.non_finalized_changes_keys_tree,
            &self.non_finalized_changes_tree,
        )
            .transaction(
                move |(
                    meta,
                    block_hashes_by_number,
                    block_headers,
                    block_bodies,
                    non_finalized_changes_keys,
                    non_finalized_changes,
                )| {
                    // Make sure that the block to insert isn't already in the database.
                    if block_headers.get(&block_hash)?.is_some() {
                        return Err(sled::transaction::ConflictableTransactionError::Abort(
                            InsertError::Duplicate,
                        ));
                    }

                    // Make sure that the parent of the block to insert is in the database.
                    if block_headers.get(&header.parent_hash)?.is_none() {
                        return Err(sled::transaction::ConflictableTransactionError::Abort(
                            InsertError::MissingParent,
                        ));
                    }

                    // If the height of the block to insert is <= the latest finalized, it doesn't
                    // belong to the finalized chain and would be pruned.
                    let current_finalized = {
                        let bytes = meta
                            .insert(b"finalized", &u64::to_be_bytes(header.number)[..])?
                            .ok_or(AccessError::Corrupted(
                                CorruptedError::FinalizedBlockNumberNotFound,
                            ))
                            .map_err(InsertError::Access)
                            .map_err(sled::transaction::ConflictableTransactionError::Abort)?;
                        u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[..]).map_err(|_| {
                            sled::transaction::ConflictableTransactionError::Abort(
                                InsertError::Access(AccessError::Corrupted(
                                    CorruptedError::FinalizedBlockNumberOutOfRange,
                                )),
                            )
                        })?)
                    };
                    if header.number <= current_finalized {
                        return Err(sled::transaction::ConflictableTransactionError::Abort(
                            InsertError::FinalizedNephew,
                        ));
                    }

                    // Append the block hash to `block_hashes_by_number`.
                    if let Some(curr) =
                        block_hashes_by_number.get(&u64::to_be_bytes(header.number)[..])?
                    {
                        let mut new_val = Vec::with_capacity(curr.len() + 32);
                        new_val.extend_from_slice(&curr);
                        new_val.extend_from_slice(&block_hash);
                        block_hashes_by_number
                            .insert(&u64::to_be_bytes(header.number)[..], &new_val[..])?;
                    } else {
                        block_hashes_by_number
                            .insert(&u64::to_be_bytes(header.number)[..], &block_hash[..])?;
                    }

                    // Insert the storage changes.
                    for (key, value) in storage_top_trie_changes.clone() {
                        // This block body unfortunately contains many memory copies, but the API
                        // of the `sled` library doesn't give us the choice.
                        let key = key.as_ref();

                        let insert_key = {
                            let mut k = Vec::with_capacity(32 + key.len());
                            k.extend_from_slice(&block_hash[..]);
                            k.extend_from_slice(key);
                            k
                        };

                        if let Some(value) = value {
                            let value = value.as_ref();
                            let mut v = Vec::with_capacity(value.len() + 1);
                            v.extend_from_slice(&[1]);
                            v.extend_from_slice(value);
                            non_finalized_changes.insert(&insert_key[..], &v[..])?;
                        } else {
                            non_finalized_changes.insert(&insert_key[..], &[0])?;
                        }
                    }

                    // Various other updates.
                    non_finalized_changes_keys.insert(&block_hash[..], &changed_keys[..])?;
                    block_headers.insert(&block_hash[..], scale_encoded_header)?;
                    block_bodies.insert(&block_hash[..], &encoded_body[..])?;
                    if is_new_best {
                        meta.insert(b"best", &block_hash[..])?;
                    }

                    Ok(())
                },
            );

        match result {
            Ok(()) => Ok(()),
            Err(sled::transaction::TransactionError::Abort(err)) => Err(err),
            Err(sled::transaction::TransactionError::Storage(err)) => {
                Err(InsertError::Access(AccessError::Database(SledError(err))))
            }
        }
    }

    /// Changes the finalized block to the given one.
    ///
    /// The block must have been previously inserted using [`SledFullDatabase::insert`], otherwise
    /// an error is returned.
    ///
    /// The block must be a descendant of the current finalized block. Reverting finalization is
    /// forbidden, as the database intentionally discards some information when finality is
    /// applied.
    pub fn set_finalized(
        &self,
        new_finalized_block_hash: &[u8; 32],
    ) -> Result<(), SetFinalizedError> {
        let result = (
            &self.meta_tree,
            &self.block_hashes_by_number_tree,
            &self.block_headers_tree,
            &self.block_bodies_tree,
            &self.finalized_storage_top_trie_tree,
            &self.non_finalized_changes_keys_tree,
            &self.non_finalized_changes_tree,
        )
            .transaction(
                move |(
                    meta,
                    block_hashes_by_number,
                    block_headers,
                    block_bodies,
                    finalized_storage_top_trie,
                    non_finalized_changes_keys,
                    non_finalized_changes,
                )| {
                    // Fetch the header of the block to finalize.
                    let scale_encoded_header = block_headers
                        .get(&new_finalized_block_hash)?
                        .ok_or(SetFinalizedError::UnknownBlock)
                        .map_err(sled::transaction::ConflictableTransactionError::Abort)?;

                    // Headers are checked before being inserted. If the decoding fails, it means
                    // that the database is somehow corrupted.
                    let header = header::decode(&scale_encoded_header)
                        .map_err(|err| {
                            SetFinalizedError::Access(AccessError::Corrupted(
                                CorruptedError::BlockHeaderCorrupted(err),
                            ))
                        })
                        .map_err(sled::transaction::ConflictableTransactionError::Abort)?;

                    // Fetch the current finalized block.
                    let current_finalized = {
                        let bytes = meta
                            .insert(b"finalized", &u64::to_be_bytes(header.number)[..])?
                            .ok_or(AccessError::Corrupted(
                                CorruptedError::FinalizedBlockNumberNotFound,
                            ))
                            .map_err(SetFinalizedError::Access)
                            .map_err(sled::transaction::ConflictableTransactionError::Abort)?;
                        u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[..]).map_err(|_| {
                            sled::transaction::ConflictableTransactionError::Abort(
                                SetFinalizedError::Access(AccessError::Corrupted(
                                    CorruptedError::FinalizedBlockNumberOutOfRange,
                                )),
                            )
                        })?)
                    };

                    // If the block to finalize is at the same height as the already-finalized
                    // block, considering that the database only contains one block per height on
                    // the finalized chain, and that the presence of the block to finalize in
                    // the database has already been verified, it is guaranteed that the block
                    // to finalize is already the one already finalized.
                    if header.number == current_finalized {
                        return Ok(());
                    }

                    // Cannot set the finalized block to a past block. The database can't support
                    // reverting finalization.
                    if header.number < current_finalized {
                        return Err(sled::transaction::ConflictableTransactionError::Abort(
                            SetFinalizedError::RevertForbidden,
                        ));
                    }

                    // Take each block height between `header.number` and `current_finalized + 1`
                    // and remove blocks that aren't an ancestor of the new finalized block.
                    {
                        // For each block height between the old finalized and new finalized,
                        // remove all blocks except the one whose hash is `expected_hash`.
                        // `expected_hash` always designates a block in the finalized chain.
                        let mut expected_hash = *new_finalized_block_hash;

                        for height in (current_finalized + 1..header.number).rev() {
                            let blocks_list = block_hashes_by_number
                                .insert(&u64::to_be_bytes(height)[..], &expected_hash[..])?
                                .ok_or(sled::transaction::ConflictableTransactionError::Abort(
                                    SetFinalizedError::Access(AccessError::Corrupted(
                                        CorruptedError::BrokenChain,
                                    )),
                                ))?;
                            let mut expected_block_found = false;
                            for hash_at_height in blocks_list.chunks(32) {
                                if hash_at_height == expected_hash {
                                    expected_block_found = true;
                                    continue;
                                }

                                // Remove the block from the database.
                                block_bodies.remove(hash_at_height)?;
                                block_headers.remove(hash_at_height)?;
                                // TODO: remove the changes list for that block
                            }

                            // `expected_hash` not found in the list of blocks with this number.
                            if !expected_block_found {
                                return Err(
                                    sled::transaction::ConflictableTransactionError::Abort(
                                        SetFinalizedError::Access(AccessError::Corrupted(
                                            CorruptedError::BrokenChain,
                                        )),
                                    ),
                                );
                            }

                            // Update `expected_hash` to point to the parent of the current
                            // `expected_hash`.
                            expected_hash = {
                                let scale_encoded_header = block_headers
                                    .get(&expected_hash)?
                                    .ok_or(SetFinalizedError::Access(AccessError::Corrupted(
                                        CorruptedError::BrokenChain,
                                    )))
                                    .map_err(
                                        sled::transaction::ConflictableTransactionError::Abort,
                                    )?;
                                let header = header::decode(&scale_encoded_header)
                                    .map_err(|err| {
                                        SetFinalizedError::Access(AccessError::Corrupted(
                                            CorruptedError::BlockHeaderCorrupted(err),
                                        ))
                                    })
                                    .map_err(
                                        sled::transaction::ConflictableTransactionError::Abort,
                                    )?;
                                *header.parent_hash
                            };
                        }
                    }

                    // Take each block height starting from `header.number + 1` and remove blocks
                    // that aren't a descendant of the new finalized block.
                    for height in header.number + 1.. {
                        let blocks_list =
                            match block_hashes_by_number.get(&u64::to_be_bytes(height)[..])? {
                                Some(l) => l,
                                None => break,
                            };

                        todo!()
                    }

                    // Now update the finalized block storage.
                    for height in current_finalized + 1..=header.number {
                        let changed_keys = {
                            let block_hash = block_hashes_by_number
                                .get(&u64::to_be_bytes(height)[..])?
                                .ok_or(sled::transaction::ConflictableTransactionError::Abort(
                                    SetFinalizedError::Access(AccessError::Corrupted(
                                        CorruptedError::BrokenChain,
                                    )),
                                ))?;
                            non_finalized_changes_keys.remove(block_hash)?.ok_or(
                                sled::transaction::ConflictableTransactionError::Abort(
                                    SetFinalizedError::Access(AccessError::Corrupted(
                                        CorruptedError::BrokenChain,
                                    )),
                                ),
                            )?
                        };

                        // TODO: update the grandpa stuff in meta

                        todo!()
                    }

                    // It is possible that the best block has been pruned.
                    // TODO: ^ yeah, how do we handle that exactly ^ ?

                    Ok(())
                },
            );

        match result {
            Ok(()) => Ok(()),
            Err(sled::transaction::TransactionError::Abort(err)) => Err(err),
            Err(sled::transaction::TransactionError::Storage(err)) => Err(
                SetFinalizedError::Access(AccessError::Database(SledError(err))),
            ),
        }
    }

    /// Returns the list of keys of the storage of the finalized block.
    ///
    /// In order to avoid race conditions, the known finalized block hash must be passed as
    /// parameter. If the finalized block in the database doesn't match the hash passed as
    /// parameter, most likely because it has been updated in a parallel thread, a
    /// [`FinalizedStorageError::Obsolete`] error is returned.
    pub fn finalized_block_storage_top_trie_keys(
        &self,
        finalized_block_hash: &[u8; 32],
    ) -> Result<Vec<VarLenBytes>, FinalizedStorageError> {
        // TODO: use a transaction rather than checking once before and once after?
        if self.finalized_block_hash()? != *finalized_block_hash {
            return Err(FinalizedStorageError::Obsolete);
        }

        let ret = self
            .finalized_storage_top_trie_tree
            .iter()
            .keys()
            .map(|v| v.map(VarLenBytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(SledError)
            .map_err(AccessError::Database)
            .map_err(FinalizedStorageError::Access)?;

        if self.finalized_block_hash()? != *finalized_block_hash {
            return Err(FinalizedStorageError::Obsolete);
        }

        Ok(ret)
    }

    /// Returns the value associated to a key in the storage of the finalized block.
    ///
    /// In order to avoid race conditions, the known finalized block hash must be passed as
    /// parameter. If the finalized block in the database doesn't match the hash passed as
    /// parameter, most likely because it has been updated in a parallel thread, a
    /// [`FinalizedStorageError::Obsolete`] error is returned.
    pub fn finalized_block_storage_top_trie_get(
        &self,
        finalized_block_hash: &[u8; 32],
        key: &[u8],
    ) -> Result<Option<VarLenBytes>, FinalizedStorageError> {
        // TODO: use a transaction rather than checking once before and once after?
        if self.finalized_block_hash()? != *finalized_block_hash {
            return Err(FinalizedStorageError::Obsolete);
        }

        let ret = self
            .finalized_storage_top_trie_tree
            .get(key)
            .map_err(SledError)
            .map_err(AccessError::Database)
            .map_err(FinalizedStorageError::Access)?
            .map(VarLenBytes);

        if self.finalized_block_hash()? != *finalized_block_hash {
            return Err(FinalizedStorageError::Obsolete);
        }

        Ok(ret)
    }
}

impl fmt::Debug for SledFullDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SledFullDatabase").finish()
    }
}

/// Bytes in the database.
// Note: serves to hide the `sled::IVec` type.
pub struct VarLenBytes(sled::IVec);

impl ops::Deref for VarLenBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

/// Error while accessing some information.
#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum AccessError {
    /// Couldn't access the database.
    #[display(fmt = "Couldn't access the database: {}", _0)]
    Database(SledError),

    /// Database could be accessed, but its content is invalid.
    ///
    /// While these corruption errors are probably unrecoverable, the inner error might however
    /// be useful for debugging purposes.
    Corrupted(CorruptedError),
}

/// Low-level database error, such as an error while accessing the file system.
#[derive(Debug, derive_more::Display)]
pub struct SledError(sled::Error);

/// Error while calling [`SledFullDatabase::insert`].
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

/// Error while calling [`SledFullDatabase::set_finalized`].
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
pub enum FinalizedStorageError {
    /// Error accessing the database.
    Access(AccessError),
    /// Block hash passed as parameter is no longer the finalized block.
    Obsolete,
}

/// Error in the content of the database.
#[derive(Debug, derive_more::Display)]
pub enum CorruptedError {
    /// The parent of a block in the database couldn't be found in the database.
    BrokenChain,
    BestBlockHashNotFound,
    FinalizedBlockNumberNotFound,
    FinalizedBlockNumberOutOfRange,
    BestBlockHashBadLength,
    BestBlockHeaderNotInDatabase,
    BlockHeaderCorrupted(header::Error),
    BlockHashLenInHashNumberMapping,
    BlockBodyCorrupted(parity_scale_codec::Error),
    NonFinalizedChangesMissing,
}
