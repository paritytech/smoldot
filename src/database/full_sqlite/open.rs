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

//! Database opening code.
//!
//! Contains everything related to the opening and initialization of the database.

use super::{
    encode_aura_authorities_list, encode_babe_epoch_information, encode_grandpa_authorities_list,
    AccessError, SqliteFullDatabase,
};
use crate::{chain::chain_information, header};

use std::{convert::TryFrom as _, path::Path};

/// Opens the database using the given [`Config`].
///
/// Note that this doesn't return a [`SqliteFullDatabase`], but rather a [`DatabaseOpen`].
pub fn open(config: Config) -> Result<DatabaseOpen, super::InternalError> {
    let database = match config.ty {
        ConfigTy::Disk(path) => {
            // We put a `/v1/` behind the path in case we change the schema.
            let path = path.join("v1").join("database.sqlite");
            sqlite::open(path)
        }
        ConfigTy::Memory => sqlite::open(":memory:"),
    }
    .map_err(super::InternalError)?;

    database
        .execute(
            r#"
-- See https://sqlite.org/pragma.html and https://www.sqlite.org/wal.html
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA locking_mode = EXCLUSIVE;
PRAGMA auto_vacuum = FULL;
PRAGMA encoding = 'UTF-8';
PRAGMA trusted_schema = false; 

/*
Keys in that table:

 - `best`: Hash of the best block.

 - `finalized`: Height of the finalized block, as a 64bits big endian number.

 - `grandpa_authorities_set_id`: A 64bits big endian number representing the id of the
 authorities set that must finalize the block right after the finalized block. The value is
 0 at the genesis block, and increased by 1 at every authorities change. Missing if and only
 if the chain doesn't use Grandpa.

 - `grandpa_triggered_authorities`: List of public keys and weights of the GrandPa
 authorities that must finalize the children of the finalized block. Consists in 40bytes
 values concatenated together, each value being a 32bytes ed25519 public key and a 8bytes
 little endian weight. Missing if and only if the chain doesn't use Grandpa.

 - `grandpa_scheduled_target`: A 64bits big endian number representing the block where the
 authorities found in `grandpa_scheduled_authorities` will be triggered. Blocks whose height
 is strictly higher than this value must be finalized using the new set of authorities. This
 authority change must have been scheduled in or before the finalized block. Missing if no
 change is scheduled or if the chain doesn't use Grandpa.

 - `grandpa_scheduled_authorities`: List of public keys and weights of the GrandPa
 authorities that will be triggered at the block found in `grandpa_scheduled_target`.
 Consists in 40bytes values concatenated together, each value being a 32bytes ed25519
 public key and a 8bytes little endian weight. Missing if no change is scheduled or if the
 chain doesn't use Grandpa.

 - `aura_slot_duration`: A 64bits big endian number indicating the duration of an Aura
 slot. Missing if and only if the chain doesn't use Aura.

 - `aura_finalized_authorities`: List of public keys of the Aura authorities that must
 author the children of the finalized block. Consists in 32bytes values concatenated
 together. Missing if and only if the chain doesn't use Aura.

 - `babe_slots_per_epoch`: A 64bits big endian number indicating the number of slots per
 Babe epoch. Missing if and only if the chain doesn't use Babe.

 - `babe_finalized_epoch`: SCALE encoding of a structure that contains the information
 about the Babe epoch used for the finalized block. Missing if and only if the finalized
 block is block #0 or the chain doesn't use Babe.

 - `babe_finalized_next_epoch`: SCALE encoding of a structure that contains the information
 about the Babe epoch that follows the one described by `babe_finalized_epoch`. If the
 finalized block is block #0, then this contains information about epoch #0. Missing if and
 only if the chain doesn't use Babe.

*/
CREATE TABLE IF NOT EXISTS meta(
    key BLOB NOT NULL PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS blocks_by_number(
    number INTEGER NOT NULL,
    hash BLOB NOT NULL,
    UNIQUE(number, hash)
);

CREATE TABLE IF NOT EXISTS block_header(
    hash BLOB NOT NULL PRIMARY KEY,
    header BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS block_body(
    hash BLOB NOT NULL,
    idx INTEGER NOT NULL,
    extrinsic BLOB NOT NULL,
    UNIQUE(hash, idx)
);

CREATE TABLE IF NOT EXISTS block_justification(
    hash BLOB NOT NULL PRIMARY KEY,
    justification BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS finalized_storage_top_trie(
    key BLOB NOT NULL PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS non_finalized_changes(
    hash BLOB NOT NULL,
    key BLOB NOT NULL,
    value BLOB,
    UNIQUE(hash, key)
);

    "#,
        )
        .map_err(super::InternalError)?;

    let is_empty = {
        let mut statement = database
            .prepare("SELECT COUNT(*) FROM meta WHERE key = ?")
            .unwrap();
        statement.bind(1, &b"best"[..]).unwrap();
        statement.next().unwrap();
        statement.read::<i64>(0).unwrap() == 0
    };

    // The database is *always* within a transaction.
    database.execute("BEGIN TRANSACTION").unwrap();

    Ok(if !is_empty {
        DatabaseOpen::Open(SqliteFullDatabase {
            database: parking_lot::Mutex::new(database),
        })
    } else {
        DatabaseOpen::Empty(DatabaseEmpty { database })
    })
}

/// Configuration for the database.
#[derive(Debug)]
pub struct Config<'a> {
    /// Type of database.
    pub ty: ConfigTy<'a>,
}

/// Type of database.
#[derive(Debug)]
pub enum ConfigTy<'a> {
    /// Store the database on disk. Path to the directory containing the database.
    Disk(&'a Path),
    /// Store the database in memory. The database is discarded on destruction.
    Memory,
}

/// Either existing database or database prototype.
pub enum DatabaseOpen {
    /// A database already existed and has now been opened.
    Open(SqliteFullDatabase),

    /// Either a database has just been created, or there existed a database but it is empty.
    ///
    /// > **Note**: The situation where a database existed but is empty can happen if you have
    /// >           previously called [`open`] then dropped the [`DatabaseOpen`] object without
    /// >           filling the newly-created database with data.
    Empty(DatabaseEmpty),
}

/// An open database. Holds file descriptors.
pub struct DatabaseEmpty {
    /// See the similar field in [`SqliteFullDatabase`].
    database: sqlite::Connection,
}

impl DatabaseEmpty {
    /// Inserts the given [`chain_information::ChainInformationRef`] in the database prototype in
    /// order to turn it into an actual database.
    ///
    /// Must also pass the body, justification, and state of the storage of the finalized block.
    pub fn initialize<'a>(
        self,
        chain_information: impl Into<chain_information::ChainInformationRef<'a>>,
        finalized_block_body: impl ExactSizeIterator<Item = &'a [u8]>,
        finalized_block_justification: Option<Vec<u8>>,
        finalized_block_storage_top_trie_entries: impl Iterator<Item = (&'a [u8], &'a [u8])> + Clone,
    ) -> Result<SqliteFullDatabase, AccessError> {
        let chain_information = chain_information.into();

        let finalized_block_hash = chain_information.finalized_block_header.hash();

        let scale_encoded_finalized_block_header = chain_information
            .finalized_block_header
            .scale_encoding()
            .fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });

        let mut insert_meta = self
            .database
            .prepare("INSERT INTO meta(key, value) VALUES(?, ?)")
            .unwrap();

        {
            let mut statement = self
                .database
                .prepare("INSERT INTO finalized_storage_top_trie(key, value) VALUES(?, ?)")
                .unwrap();
            for (key, value) in finalized_block_storage_top_trie_entries.clone() {
                statement.bind(1, key).unwrap();
                statement.bind(2, value).unwrap();
                statement.next().unwrap();
                statement.reset().unwrap();
            }
        }

        {
            let mut statement = self
                .database
                .prepare("INSERT INTO blocks_by_number(number, hash) VALUES(?, ?)")
                .unwrap();
            statement
                .bind(
                    1,
                    i64::try_from(chain_information.finalized_block_header.number).unwrap(),
                )
                .unwrap();
            statement.bind(2, &finalized_block_hash[..]).unwrap();
            statement.next().unwrap();
        }

        {
            let mut statement = self
                .database
                .prepare("INSERT INTO block_header(hash, header) VALUES(?, ?)")
                .unwrap();
            statement.bind(1, &finalized_block_hash[..]).unwrap();
            statement
                .bind(2, &scale_encoded_finalized_block_header[..])
                .unwrap();
            statement.next().unwrap();
        }

        {
            let mut statement = self
                .database
                .prepare("INSERT INTO block_body(hash, idx, extrinsic) VALUES(?, ?, ?)")
                .unwrap();
            for (index, item) in finalized_block_body.enumerate() {
                statement.bind(1, &finalized_block_hash[..]).unwrap();
                statement.bind(2, i64::try_from(index).unwrap()).unwrap();
                statement.bind(3, item).unwrap();
                statement.next().unwrap();
                statement.reset().unwrap();
            }
        }

        if let Some(finalized_block_justification) = &finalized_block_justification {
            let mut statement = self
                .database
                .prepare("INSERT INTO block_justification(hash, justification) VALUES(?, ?)")
                .unwrap();
            statement.bind(1, &finalized_block_hash[..]).unwrap();
            statement
                .bind(2, &finalized_block_justification[..])
                .unwrap();
            statement.next().unwrap();
        }

        insert_meta.reset().unwrap();
        insert_meta.bind(1, &b"best"[..]).unwrap();
        insert_meta.bind(2, &finalized_block_hash[..]).unwrap();
        insert_meta.next().unwrap();

        insert_meta.reset().unwrap();
        insert_meta.bind(1, &b"finalized"[..]).unwrap();
        insert_meta
            .bind(
                2,
                &chain_information
                    .finalized_block_header
                    .number
                    .to_be_bytes()[..],
            )
            .unwrap();
        insert_meta.next().unwrap();

        match &chain_information.finality {
            chain_information::ChainInformationFinalityRef::Outsourced => {}
            chain_information::ChainInformationFinalityRef::Grandpa {
                finalized_triggered_authorities,
                after_finalized_block_authorities_set_id,
                finalized_scheduled_change,
            } => {
                insert_meta.reset().unwrap();
                insert_meta
                    .bind(1, &b"grandpa_authorities_set_id"[..])
                    .unwrap();
                insert_meta
                    .bind(
                        2,
                        &after_finalized_block_authorities_set_id.to_be_bytes()[..],
                    )
                    .unwrap();
                insert_meta.next().unwrap();

                insert_meta.reset().unwrap();
                insert_meta
                    .bind(1, &b"grandpa_triggered_authorities"[..])
                    .unwrap();
                insert_meta
                    .bind(
                        2,
                        &encode_grandpa_authorities_list(header::GrandpaAuthoritiesIter::new(
                            finalized_triggered_authorities,
                        ))[..],
                    )
                    .unwrap();
                insert_meta.next().unwrap();

                if let Some((height, list)) = finalized_scheduled_change {
                    insert_meta.reset().unwrap();
                    insert_meta
                        .bind(1, &b"grandpa_scheduled_target"[..])
                        .unwrap();
                    insert_meta.bind(2, &height.to_be_bytes()[..]).unwrap();
                    insert_meta.next().unwrap();

                    insert_meta.reset().unwrap();
                    insert_meta
                        .bind(1, &b"grandpa_scheduled_authorities"[..])
                        .unwrap();
                    insert_meta
                        .bind(
                            2,
                            &encode_grandpa_authorities_list(header::GrandpaAuthoritiesIter::new(
                                list,
                            ))[..],
                        )
                        .unwrap();
                    insert_meta.next().unwrap();
                }
            }
        }

        match &chain_information.consensus {
            chain_information::ChainInformationConsensusRef::AllAuthorized => {}
            chain_information::ChainInformationConsensusRef::Aura {
                finalized_authorities_list,
                slot_duration,
            } => {
                insert_meta.reset().unwrap();
                insert_meta.bind(1, &b"aura_slot_duration"[..]).unwrap();
                insert_meta
                    .bind(2, &slot_duration.get().to_be_bytes()[..])
                    .unwrap();
                insert_meta.next().unwrap();

                insert_meta.reset().unwrap();
                insert_meta
                    .bind(1, &b"aura_finalized_authorities"[..])
                    .unwrap();
                insert_meta
                    .bind(
                        2,
                        &encode_aura_authorities_list(finalized_authorities_list.clone())[..],
                    )
                    .unwrap();
                insert_meta.next().unwrap();
            }
            chain_information::ChainInformationConsensusRef::Babe {
                slots_per_epoch,
                finalized_next_epoch_transition,
                finalized_block_epoch_information,
            } => {
                insert_meta.reset().unwrap();
                insert_meta.bind(1, &b"babe_slots_per_epoch"[..]).unwrap();
                insert_meta
                    .bind(2, &slots_per_epoch.get().to_be_bytes()[..])
                    .unwrap();
                insert_meta.next().unwrap();

                insert_meta.reset().unwrap();
                insert_meta
                    .bind(1, &b"babe_finalized_next_epoch"[..])
                    .unwrap();
                insert_meta
                    .bind(
                        2,
                        &encode_babe_epoch_information(finalized_next_epoch_transition.clone())[..],
                    )
                    .unwrap();
                insert_meta.next().unwrap();

                if let Some(finalized_block_epoch_information) = finalized_block_epoch_information {
                    insert_meta.reset().unwrap();
                    insert_meta.bind(1, &b"babe_finalized_epoch"[..]).unwrap();
                    insert_meta
                        .bind(
                            2,
                            &encode_babe_epoch_information(
                                finalized_block_epoch_information.clone(),
                            )[..],
                        )
                        .unwrap();
                    insert_meta.next().unwrap();
                }
            }
        }

        self.database.execute("COMMIT").unwrap();
        self.database.execute("BEGIN TRANSACTION").unwrap();

        drop(insert_meta);
        Ok(SqliteFullDatabase {
            database: parking_lot::Mutex::new(self.database),
        })
    }
}
