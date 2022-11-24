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

use super::{proof_node_codec, trie_structure};
use core::iter;

pub use super::nibble::Nibble;

pub struct ProofBuilder {
    /// Contains a subset of the trie. Each node is associated with its node value if it is known,
    /// or `None` if it isn't known.
    ///
    /// The `TrieStructure` data structure is very explicit in its usage. Nodes such as branch
    /// nodes are not implicitly but explicitly created. However, the trie structure is normally
    /// not meant to contain branch nodes without any children. In order to bypass this
    /// restriction, we pretend
    // TODO: finish comment
    trie_structure: trie_structure::TrieStructure<Option<Node>>,

    /// List of keys of the nodes in [`ProofBuilder::trie_structure`] whose user data is `None`.
    missing_node_values: hashbrown::HashSet<Vec<Nibble>, fnv::FnvBuildHasher>,
}

#[derive(Debug, Clone)]
struct Node {
    node_value: Vec<u8>,
    unhashed_storage_value: Option<Vec<u8>>,
}

impl ProofBuilder {
    pub fn new() -> Self {
        ProofBuilder {
            trie_structure: trie_structure::TrieStructure::new(),
            missing_node_values: hashbrown::HashSet::with_capacity_and_hasher(
                0,
                Default::default(),
            ),
        }
    }

    pub fn with_nodes_capacity(capacity: usize) -> Self {
        ProofBuilder {
            trie_structure: trie_structure::TrieStructure::with_capacity(capacity),
            missing_node_values: hashbrown::HashSet::with_capacity_and_hasher(
                capacity,
                Default::default(),
            ),
        }
    }

    /// Inserts the node value of a given trie node into the builder.
    ///
    /// Overwrites any previously set value for this key.
    ///
    /// The `node_value` is decoded in order for the proof builder to determine the hierarchy of
    /// the trie and know which node values are missing.
    ///
    /// If the `node_value`.
    ///
    /// # Panic
    ///
    /// Panics if `node_value` is not a valid node value.
    /// Panics in case of mismatch between `unhashed_storage_value` and `node_value`.
    ///
    pub fn set_node_value(
        &mut self,
        key: &[Nibble],
        node_value: &[u8],
        unhashed_storage_value: Option<&[u8]>,
    ) {
        let decoded = match proof_node_codec::decode(node_value) {
            Ok(d) => d,
            Err(err) => panic!("failed to decode node value: {:?}", err),
        };

        match (&decoded.storage_value, &unhashed_storage_value) {
            (
                proof_node_codec::StorageValue::Unhashed(ref in_node_value),
                Some(ref user_provided),
            ) => assert_eq!(in_node_value, user_provided),
            (proof_node_codec::StorageValue::Hashed(ref hash), Some(ref value)) => {
                debug_assert_eq!(
                    blake2_rfc::blake2b::blake2b(32, b"", value).as_bytes(),
                    &hash[..]
                );
            }
            (proof_node_codec::StorageValue::None, Some(_)) => panic!(),
            (_, None) => {}
        }

        let trie_structure_value = Node {
            node_value: node_value.to_owned(),
            unhashed_storage_value: unhashed_storage_value.map(|s| s.to_owned()),
        };

        match self.trie_structure.node(key.iter().copied()) {
            trie_structure::Entry::Occupied(mut entry) => {
                let _was_in = self.missing_node_values.remove(key);
                debug_assert_eq!(_was_in, entry.user_data().is_none());
                *entry.user_data() = Some(trie_structure_value);
            }
            trie_structure::Entry::Vacant(entry) => {
                // We insert a storage value for the given node, even though the node might be
                // a branch node. This is necessary in order for the trie structure to keep our
                // node, as otherwise the node wouldn't exist.
                match entry.insert_storage_value() {
                    trie_structure::PrepareInsert::One(insert) => {
                        insert.insert(Some(trie_structure_value));
                    }
                    trie_structure::PrepareInsert::Two(insert) => {
                        let _was_inserted = self
                            .missing_node_values
                            .insert(insert.branch_node_key().collect());
                        debug_assert!(_was_inserted);
                        insert.insert(Some(trie_structure_value), None);
                    }
                }
            }
        }

        // We must also make sure that the parent of the node is in the proof. Insert the parent
        // in the trie structure as well. This doesn't need to be done if the parent of the node
        // is `[]`.
        let partial_key_len = decoded.partial_key.count();
        if key.len() != partial_key_len {
            let parent_key = &key[..(key.len() - partial_key_len - 1)];
            match self.trie_structure.node(parent_key.iter().copied()) {
                trie_structure::Entry::Occupied(_) => {
                    // The parent is already in the structure. Nothing to do.
                }
                trie_structure::Entry::Vacant(entry) => match entry.insert_storage_value() {
                    trie_structure::PrepareInsert::One(insert) => {
                        let _was_inserted = self.missing_node_values.insert(parent_key.to_owned());
                        debug_assert!(_was_inserted);
                        insert.insert(None);
                    }
                    trie_structure::PrepareInsert::Two(insert) => {
                        let _was_inserted = self.missing_node_values.insert(parent_key.to_owned());
                        debug_assert!(_was_inserted);

                        let _was_inserted = self
                            .missing_node_values
                            .insert(insert.branch_node_key().collect());
                        debug_assert!(_was_inserted);

                        insert.insert(None, None);
                    }
                },
            }
        }
    }

    /// Returns a list of keys for which the node value must be known in order for the proof to be
    /// buildable.
    ///
    /// For each entry returned by this iterator, [`ProofBuilder::set_node_value`] must be called.
    ///
    /// This function has a complexity of `O(1)` and thus can be called repeatedly.
    pub fn missing_node_values(&self) -> impl Iterator<Item = &[Nibble]> {
        self.missing_node_values.iter().map(|v| &v[..])
    }

    /// Builds the Merkle proof.
    ///
    /// This function returns an iterator of buffers. The actual Merkle proof consists in the
    /// concatenation of all the buffers.
    ///
    /// This function will succeed if no entry at all has been inserted in the [`ProofBuilder`].
    ///
    /// # Panic
    ///
    /// Panics if the iterator returned by [`ProofBuilder::missing_merkle_values`] is not empty.
    ///
    pub fn build(mut self) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone {
        // As documented, we panic if any node value is missing.
        assert!(self.missing_node_values.is_empty());

        // The first bytes of the proof contain the number of entries in the proof.
        // TODO: wrong, doesn't handle separate storage values
        let num_entries_encoded =
            crate::util::encode_scale_compact_usize(self.trie_structure.len());

        // TODO: we need to collect the indices into a Vec due to the API of trie_structure not allowing non-mutable access to nodes
        let entries = self
            .trie_structure
            .iter_unordered()
            .collect::<Vec<_>>()
            .into_iter()
            .flat_map(move |node_index| {
                let trie_structure_value = self
                    .trie_structure
                    .node_by_index(node_index)
                    .unwrap()
                    .user_data()
                    .take()
                    .expect("missing node value");
                let length =
                    crate::util::encode_scale_compact_usize(trie_structure_value.node_value.len());
                [
                    either::Left(length),
                    either::Right(trie_structure_value.node_value),
                ]
                .into_iter()
            });

        iter::once(either::Left(num_entries_encoded)).chain(entries.map(either::Right))
    }

    /// Similar to [`ProofBuilder::build`], but returns a `Vec`.
    ///
    /// This is a convenience wrapper around [`ProofBuilder::build`].
    pub fn build_to_vec(self) -> Vec<u8> {
        self.build().fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn empty_works() {
        let proof = super::ProofBuilder::new();
        assert_eq!(proof.missing_node_values().count(), 0);
        assert_eq!(proof.build_to_vec(), &[0]);
    }
}
