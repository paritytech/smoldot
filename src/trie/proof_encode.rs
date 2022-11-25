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

use alloc::{borrow::ToOwned as _, vec::Vec};
use core::iter;

pub use super::nibble::Nibble;

/// Prototype for a Merkle proof whose building is in progress.
pub struct ProofBuilder {
    /// Contains a subset of the trie. Each node is associated with its node value if it is known,
    /// or `None` if it isn't known.
    ///
    /// The `TrieStructure` data structure is very explicit in its usage. Nodes such as branch
    /// nodes are not implicitly but explicitly created. However, the trie structure is normally
    /// not meant to contain branch nodes without any children. In order to bypass this
    /// restriction, we pretend that nodes have a storage value when necessary even if this is
    /// not the case.
    trie_structure: trie_structure::TrieStructure<Option<Node>>,

    /// List of keys of the nodes in [`ProofBuilder::trie_structure`] whose user data is `None`.
    missing_node_values: hashbrown::HashSet<Vec<Nibble>, fnv::FnvBuildHasher>,

    /// Total number of entries that are going to be in the proof.
    num_proof_entries: usize,
}

#[derive(Debug, Clone)]
struct Node {
    /// Value passed as `node_value` by the API user.
    node_value: Vec<u8>,
    /// Node containing the storage value associated with this node.
    storage_value_node: Option<Vec<u8>>,
}

impl ProofBuilder {
    /// Initializes a new empty proof builder.
    ///
    /// This is equivalent to calling [`ProofBuilder::with_nodes_capacity`] with a value of 0.
    pub fn new() -> Self {
        Self::with_nodes_capacity(0)
    }

    /// Initializes a new empty proof builder.
    ///
    /// Memory is allocated to store `capacity` nodes, in other words the number of nodes added
    /// using [`ProofBuilder::set_node_value`].
    pub fn with_nodes_capacity(capacity: usize) -> Self {
        ProofBuilder {
            trie_structure: trie_structure::TrieStructure::with_capacity(capacity),
            missing_node_values: hashbrown::HashSet::with_capacity_and_hasher(
                capacity,
                Default::default(),
            ),
            num_proof_entries: 0,
        }
    }

    /// Inserts the node value of a given trie node into the builder.
    ///
    /// Overwrites any previously-set value for this key.
    ///
    /// The `node_value` is decoded in order for the proof builder to determine the hierarchy of
    /// the trie and know which node values are missing. If the `node_value` is invalid, this
    /// function panics.
    ///
    /// If the `node_value` contains a storage value as a hash, then a `unhashed_storage_value`
    /// can optionally be provided in order to provide the unhashed version of this value.
    ///
    /// The validity of the `node_value` in the context of the other node values that have been
    /// stored in this proof builder isn't verified. For example, a node value can indicate no
    /// children while the node value of a child has been added, or a node value can indicate a
    /// child with a specific hash, while the child in question has a different hash. This will
    /// lead to an invalid proof being generated.
    ///
    /// # Panic
    ///
    /// Panics if `node_value` is not a valid node value.
    /// Panics in case `node_value` indicates no storage value, but `unhashed_storage_value`
    /// is `Some`.
    ///
    pub fn set_node_value(
        &mut self,
        key: &[Nibble],
        node_value: &[u8],
        unhashed_storage_value: Option<&[u8]>,
    ) {
        // The first thing to do is decode the node value, in order to detect invalid node values
        // first things first.
        let decoded_node_value = match proof_node_codec::decode(node_value) {
            Ok(d) => d,
            Err(err) => panic!("failed to decode node value: {:?}", err),
        };

        // Check consistency between `node_value` and `unhashed_storage_value` and determine
        // whether a separate storage node should be included in the proof.
        let storage_value_node = match (&decoded_node_value.storage_value, &unhashed_storage_value)
        {
            (
                proof_node_codec::StorageValue::Unhashed(ref in_node_value),
                Some(ref user_provided),
            ) => {
                assert_eq!(in_node_value, user_provided);
                None
            }
            (proof_node_codec::StorageValue::Hashed(ref hash), Some(ref value)) => {
                debug_assert_eq!(
                    blake2_rfc::blake2b::blake2b(32, b"", value).as_bytes(),
                    &hash[..]
                );
                Some(value.to_vec())
            }
            (proof_node_codec::StorageValue::None, Some(_)) => panic!(),
            (_, None) => None,
        };

        // Value that is going to be inserted in the trie.
        let trie_structure_value = Node {
            node_value: node_value.to_owned(),
            storage_value_node,
        };

        // Update `num_proof_entries`.
        self.num_proof_entries += 1 + if trie_structure_value.storage_value_node.is_some() {
            1
        } else {
            0
        };

        match self.trie_structure.node(key.iter().copied()) {
            trie_structure::Entry::Occupied(mut entry) => {
                // Update the value in the trie structure, and cancel out the previous change
                // to `num_proof_entries`.
                if let Some(prev_entry) = entry.user_data() {
                    self.num_proof_entries -= 1 + if prev_entry.storage_value_node.is_some() {
                        1
                    } else {
                        0
                    };
                }
                let _was_in = self.missing_node_values.remove(key);
                debug_assert_eq!(_was_in, entry.user_data().is_none());
                *entry.user_data() = Some(trie_structure_value);
            }
            trie_structure::Entry::Vacant(entry) => {
                // We insert a storage value for the given node, even though the node might be
                // a branch node. This is necessary in order for the trie structure to store our
                // node, as otherwise the node possibly wouldn't exist.
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
        // in the trie structure as well.
        // This shouldn't be done if the node is the root node of the trie.
        let partial_key_len = decoded_node_value.partial_key.count();
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

    /// Returns a list of keys for which the node value must be known in order to be able to build
    /// the proof.
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
    /// This function will succeed even if [`ProofBuilder::missing_node_values`] returns a
    /// non-zero number of elements. However, the proof produced will then be invalid.
    pub fn build(mut self) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone {
        // The first bytes of the proof contain the number of entries in the proof.
        let num_entries_encoded = crate::util::encode_scale_compact_usize(self.num_proof_entries);

        // Iterator to the entries in the proof.
        // TODO: we need to collect the indices into a Vec due to the API of trie_structure not allowing non-mutable access to nodes
        let entries = self
            .trie_structure
            .iter_unordered()
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(move |node_index| {
                let trie_structure_value = self
                    .trie_structure
                    .node_by_index(node_index)
                    .unwrap()
                    .user_data()
                    .take()?;

                // For each node, there are either two things or four things to output: the
                // length of the node value and the node value, and optionally the length of the
                // storage value and storage value
                let node_value_length = Some(crate::util::encode_scale_compact_usize(
                    trie_structure_value.node_value.len(),
                ));
                let node_value = Some(trie_structure_value.node_value);
                let storage_value = trie_structure_value.storage_value_node;
                let storage_value_length = storage_value
                    .as_ref()
                    .map(|v| crate::util::encode_scale_compact_usize(v.len()));

                Some([
                    node_value_length.map(either::Left),
                    node_value.map(either::Right),
                    storage_value_length.map(either::Left),
                    storage_value.map(either::Right),
                ])
            })
            .flat_map(|v| v.into_iter().flat_map(|v| v.into_iter()));

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
    use super::super::nibble;

    #[test]
    fn empty_works() {
        let proof_builder = super::ProofBuilder::new();
        assert_eq!(proof_builder.missing_node_values().count(), 0);
        assert_eq!(proof_builder.build_to_vec(), &[0]);
    }

    #[test]
    #[should_panic]
    fn invalid_node_value_detected() {
        let mut proof_builder = super::ProofBuilder::new();
        proof_builder.set_node_value(
            &nibble::bytes_to_nibbles([1, 2, 3, 4].into_iter()).collect::<Vec<_>>(),
            b"foobar",
            None,
        );
    }

    #[test]
    fn one_root_node_works() {
        let mut proof_builder = super::ProofBuilder::new();

        proof_builder.set_node_value(
            &nibble::bytes_to_nibbles([1, 2, 3, 4].into_iter()).collect::<Vec<_>>(),
            &[72, 1, 2, 3, 4, 20, 104, 101, 108, 108, 111],
            None,
        );

        assert_eq!(proof_builder.missing_node_values().count(), 0);
        assert_eq!(
            proof_builder.build_to_vec(),
            &[4, 44, 72, 1, 2, 3, 4, 20, 104, 101, 108, 108, 111]
        );
    }

    #[test]
    fn one_node_non_root_detects_root_node() {
        let mut proof_builder = super::ProofBuilder::new();

        proof_builder.set_node_value(
            &nibble::bytes_to_nibbles([1, 2, 3, 4].into_iter()).collect::<Vec<_>>(),
            &[68, 3, 4, 20, 104, 101, 108, 108, 111],
            None,
        );

        assert_eq!(
            proof_builder.missing_node_values().collect::<Vec<_>>(),
            vec![&[
                nibble::Nibble::try_from(0).unwrap(),
                nibble::Nibble::try_from(1).unwrap(),
                nibble::Nibble::try_from(0).unwrap()
            ]]
        );
    }

    #[test]
    fn build_doesnt_panic_if_missing_node() {
        let mut proof_builder = super::ProofBuilder::new();
        proof_builder.set_node_value(
            &nibble::bytes_to_nibbles([1, 2, 3, 4].into_iter()).collect::<Vec<_>>(),
            &[68, 3, 4, 20, 104, 101, 108, 108, 111],
            None,
        );
        let _ = proof_builder.build();
    }
}
