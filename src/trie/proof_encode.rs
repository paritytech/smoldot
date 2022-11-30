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

use super::{nibble, proof_node_codec, trie_structure};

use alloc::{borrow::ToOwned as _, vec::Vec};
use core::{array, iter};

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
        }
    }

    /// Inserts the node value of a given trie node into the builder.
    ///
    /// Overwrites any previously-set value for this key.
    ///
    /// The `node_value` is decoded in order for the proof builder to determine the hierarchy of
    /// the trie and know which node values are missing. If the `node_value` is invalid, this
    /// function panics. In order to avoid difficult-to-debug corner cases, this function also
    /// panics if it is no possible for `node_value` to be found at the given `key` due to a
    /// mismatch.
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
    /// Panics if the partial key found in `node_value` doesn't match the last elements of `key`.
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
            Err(err) => panic!(
                "failed to decode node value: {:?}; value: {:?}",
                err, node_value
            ),
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
            (proof_node_codec::StorageValue::Hashed(_), Some(ref value)) => Some(value.to_vec()),
            (proof_node_codec::StorageValue::None, Some(_)) => panic!(),
            (_, None) => None,
        };

        // Value that is going to be inserted in the trie.
        let trie_structure_value = Node {
            node_value: node_value.to_owned(),
            storage_value_node,
        };

        match self.trie_structure.node(key.iter().copied()) {
            trie_structure::Entry::Occupied(mut entry) => {
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
        let partial_key_len = decoded_node_value.partial_key.len();
        assert!(
            key.len() >= partial_key_len,
            "mismatch between node value partial key and provided key"
        );
        assert!(
            itertools::equal(
                key[(key.len() - partial_key_len)..].iter().copied(),
                decoded_node_value.partial_key.clone()
            ),
            "mismatch between node value partial key and provided key"
        );
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

    /// Returns the hash of the trie root node.
    ///
    /// This function returns `None` if the proof is empty or if the trie root node is missing
    /// from the proof, in which case [`ProofBuilder::missing_node_values`] will return it.
    ///
    /// In other words, if the proof is not empty and if [`ProofBuilder::missing_node_values`]
    /// returns an empty iterator, then you are guaranteed that this function returns `Some`.
    ///
    /// This function has a complexity of `O(1)`.
    pub fn trie_root_hash(&self) -> Option<[u8; 32]> {
        let node_value = &self.trie_structure.root_user_data()?.as_ref()?.node_value;
        Some(blake2_hash(node_value))
    }

    /// Modifies the node values that have been inserted in the proof builder in order to make the
    /// proof coherent, if necessary.
    ///
    /// If all the node values that have been added through [`ProofBuilder::set_node_value`] come
    /// from a valid trie, then the proof is already coherent and there is no need to call this
    /// function. This function is necessary only in situations where the node values have been
    /// manually modified.
    ///
    /// Calling this function when the node values aren't coherent will modify the hash of the trie
    /// root that is found in the proof. Most of the time, the verification of a trie proof checks
    /// whether the hash of the trie root in the proof matches an expected value. When that is the
    /// case, then calling this function would produce a proof that is no longer accepted.
    ///
    /// This function only updates the hashes of storage values and children. Storage values
    /// themselves are always left untouched.
    /// This function also updates the presence of children. If a node has been added using
    /// [`ProofBuilder::set_node_value`] but its parent indicates a lack of child, then calling
    /// this function will modify the parent in order to indicate the presence of a child.
    /// However, this function never removes children. If a node indicates that it has a child, but
    /// the child has not been added using [`ProofBuilder::set_node_value`], it simply indicates
    /// that the child in question is (intentionally) not part of the proof, and the proof is still
    /// valid.
    ///
    /// This function works even if [`ProofBuilder::missing_node_values`] returns a non-empty
    /// iterator, but will not be able to update everything. You are encouraged to call this
    /// function only after having added all missing node values;
    pub fn make_coherent(&mut self) {
        // The implementation of this function iterates over the nodes of the trie in a specific
        // order: we start with the deepest child possible of the root node, then we jump from each
        // node to the deepest child possible of its next sibling. If a node is the last sibling,
        // jump to its parent.
        // This order of iteration guarantees that we traverse all the nodes of the trie, and that
        // we don't traverse a parent before having traversed of all its children.
        // When traversing a node, we calculate the hash of its children and update the node value
        // of that node.

        // Node currently being iterated.
        let mut iter: trie_structure::NodeAccess<_> = {
            let mut node = match self.trie_structure.root_node() {
                Some(c) => c,
                None => {
                    // Trie is empty.
                    return;
                }
            };

            loop {
                match node.into_first_child() {
                    Ok(c) => node = c,
                    Err(c) => break c,
                }
            }
        };

        loop {
            // Due to borrowing issues, we calculate ahead of time the values of the children of
            // the node.
            let children_values: [Option<Option<arrayvec::ArrayVec<u8, 32>>>; 16] =
                array::from_fn(|nibble| {
                    let nibble = nibble::Nibble::try_from(u8::try_from(nibble).unwrap()).unwrap();

                    if let Some(child_node_info) = iter.child_user_data(nibble) {
                        if let Some(child_node_info) = child_node_info {
                            // Node values of length < 32 are inlined.
                            if child_node_info.node_value.len() < 32 {
                                Some(Some(child_node_info.node_value.iter().copied().collect()))
                            } else {
                                Some(Some(blake2_hash(&child_node_info.node_value).into()))
                            }
                        } else {
                            // Missing node value. Don't update anything.
                            None
                        }
                    } else {
                        Some(None)
                    }
                });

            // We only update the current node if its node value has been inserted by the user.
            if let Some(node_info) = iter.user_data().as_mut() {
                // We already make sure that node values are valid when inserting them. As such,
                // it is ok to `unwrap()` here.
                let mut decoded_node_value =
                    proof_node_codec::decode(&node_info.node_value).unwrap();

                // Update the hash of the storage value contained in `decoded_node_value`.
                // This is done in a slightly weird way due to borrowing issues.
                let storage_value_hash = node_info
                    .storage_value_node
                    .as_ref()
                    .map(|v| blake2_hash(v));
                debug_assert_eq!(
                    storage_value_hash.is_some(),
                    matches!(
                        decoded_node_value.storage_value,
                        proof_node_codec::StorageValue::Hashed(_)
                    )
                );
                if let Some(storage_value_hash) = storage_value_hash.as_ref() {
                    decoded_node_value.storage_value =
                        proof_node_codec::StorageValue::Hashed(&storage_value_hash);
                }

                // Update the children.
                for (nibble, child_value) in children_values.iter().enumerate() {
                    if let Some(child_value) = child_value {
                        decoded_node_value.children[nibble] = child_value.as_deref();
                    }
                    // As documented, children are never removed. If `child_value` is `None`, we
                    // intentionally keep the existing value in `decoded_node_value.children`.
                }

                // Re-encode the node value after its updates, and store it.
                let updated_node_value =
                    proof_node_codec::encode(decoded_node_value).fold(Vec::new(), |mut a, b| {
                        a.extend_from_slice(b.as_ref());
                        a
                    });
                node_info.node_value = updated_node_value;
            }

            // Jump to the next node in the order of iteration described at the top of this
            // function.
            match iter.into_next_sibling() {
                Err(n) => match n.into_parent() {
                    Some(p) => iter = p,
                    None => break, // Finished.
                },
                Ok(mut node) => {
                    iter = loop {
                        match node.into_first_child() {
                            Ok(c) => node = c,
                            Err(c) => break c,
                        }
                    };
                }
            }
        }
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
    pub fn build(mut self) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> {
        // Index of the root node in the trie, if any.
        let root_node_index = self.trie_structure.root_node().map(|n| n.node_index());

        // Collect the entries in the proof into a `HashSet` in order to de-duplicate them.
        // TODO: we need to collect the indices into a Vec due to the API of trie_structure not allowing non-mutable access to nodes
        let entries = self
            .trie_structure
            .iter_unordered()
            .collect::<Vec<_>>()
            .into_iter()
            .flat_map(move |node_index| {
                let Some(trie_structure_value) = self
                    .trie_structure
                    .node_by_index(node_index)
                    .unwrap()
                    .user_data()
                    .take()
                // Ignore nodes whose value is missing.
                else { return either::Right(iter::empty()); };

                // Nodes of length < 32 should have been inlined within their parent or ancestor.
                // We thus skip them, unless they're the root node.
                if root_node_index != Some(node_index) && trie_structure_value.node_value.len() < 32
                {
                    debug_assert!(trie_structure_value.storage_value_node.is_none());
                    return either::Right(iter::empty());
                }

                // For each node, there are either one or two things to output: the node value,
                // and the storage value.
                either::Left(
                    iter::once(trie_structure_value.node_value)
                        .chain(trie_structure_value.storage_value_node.into_iter()),
                )
            })
            .collect::<hashbrown::HashSet<_, fnv::FnvBuildHasher>>();

        // The first bytes of the proof contain the number of entries in the proof.
        let num_entries_encoded = crate::util::encode_scale_compact_usize(entries.len());

        // Add the size of each entry before each entry.
        let entries = entries.into_iter().flat_map(|entry| {
            let len = crate::util::encode_scale_compact_usize(entry.len());
            [either::Left(len), either::Right(entry)].into_iter()
        });

        iter::once(either::Left(num_entries_encoded)).chain(entries.into_iter().map(either::Right))
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

fn blake2_hash(data: &[u8]) -> [u8; 32] {
    *&<[u8; 32]>::try_from(blake2_rfc::blake2b::blake2b(32, &[], data).as_bytes()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::super::{nibble, proof_decode, proof_node_codec, trie_structure};
    use core::array;
    use rand::distributions::{Distribution as _, Uniform};

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

    #[test]
    fn build_random_proof() {
        // This test builds a proof of a randomly-generated trie, then fixes it, then checks
        // whether the decoder considers the proof as valid.

        // We repeat the test many times due to its random factor.
        for _ in 0..1500 {
            // Build a trie with entries with randomly generated keys.
            let mut trie = trie_structure::TrieStructure::new();
            // Generate at least one node, as otherwise the test panics. Empty proofs are however
            // valid.
            for _ in 0..Uniform::new_inclusive(1, 32).sample(&mut rand::thread_rng()) {
                let mut key = Vec::new();
                for _ in 0..Uniform::new_inclusive(0, 12).sample(&mut rand::thread_rng()) {
                    key.push(
                        nibble::Nibble::try_from(
                            Uniform::new_inclusive(0, 15).sample(&mut rand::thread_rng()),
                        )
                        .unwrap(),
                    );
                }

                match trie.node(key.into_iter()) {
                    trie_structure::Entry::Vacant(e) => {
                        e.insert_storage_value().insert((), ());
                    }
                    trie_structure::Entry::Occupied(trie_structure::NodeAccess::Branch(e)) => {
                        e.insert_storage_value();
                    }
                    trie_structure::Entry::Occupied(trie_structure::NodeAccess::Storage(_)) => {}
                }
            }

            // Put the content of the trie into the proof builder.
            let mut proof_builder = super::ProofBuilder::new();
            for node_index in trie.iter_unordered().collect::<Vec<_>>() {
                let key = trie
                    .node_full_key_by_index(node_index)
                    .unwrap()
                    .collect::<Vec<_>>();

                // This randomly-generated storage might end up not being used, but that's not
                // problematic.
                let mut storage_value = Vec::new();
                for _ in 0..Uniform::new_inclusive(0, 64).sample(&mut rand::thread_rng()) {
                    storage_value
                        .push(Uniform::new_inclusive(0, 255).sample(&mut rand::thread_rng()));
                }

                let node_value = proof_node_codec::encode_to_vec(proof_node_codec::Decoded {
                    children: array::from_fn(|nibble| {
                        let nibble =
                            nibble::Nibble::try_from(u8::try_from(nibble).unwrap()).unwrap();
                        if trie
                            .node_by_index(node_index)
                            .unwrap()
                            .child_user_data(nibble)
                            .is_some()
                        {
                            Some(&[][..])
                        } else {
                            None
                        }
                    }),
                    partial_key: trie
                        .node_by_index(node_index)
                        .unwrap()
                        .partial_key()
                        .collect::<Vec<_>>()
                        .into_iter(),
                    storage_value: if trie.node_by_index(node_index).unwrap().has_storage_value() {
                        proof_node_codec::StorageValue::Unhashed(&storage_value)
                    } else {
                        proof_node_codec::StorageValue::None
                    },
                });

                proof_builder.set_node_value(&key, &node_value, None);
            }

            // Generate the proof.
            assert!(proof_builder.missing_node_values().next().is_none());
            proof_builder.make_coherent();
            let trie_root_hash = proof_builder.trie_root_hash().unwrap();
            let proof = proof_builder.build_to_vec();

            // Verify the correctness of the proof.
            proof_decode::decode_and_verify_proof(proof_decode::Config {
                trie_root_hash: &trie_root_hash,
                proof,
            })
            .unwrap();
        }
    }

    #[test]
    fn identical_nodes_deduplicated() {
        let mut proof_builder = super::ProofBuilder::new();

        // One root node containing two children with an identical hash.
        proof_builder.set_node_value(
            &nibble::bytes_to_nibbles([].into_iter()).collect::<Vec<_>>(),
            &[
                128, 3, 0, 128, 205, 154, 249, 23, 88, 152, 61, 75, 170, 87, 182, 7, 127, 171, 174,
                60, 2, 124, 79, 166, 31, 155, 155, 185, 182, 155, 250, 63, 139, 166, 222, 184, 128,
                205, 154, 249, 23, 88, 152, 61, 75, 170, 87, 182, 7, 127, 171, 174, 60, 2, 124, 79,
                166, 31, 155, 155, 185, 182, 155, 250, 63, 139, 166, 222, 184,
            ],
            None,
        );

        // Two identical nodes but at a different key.
        // Importantly, the node values are more than 32 bytes long to ensure that they're
        // separate node and should not be inlined.
        proof_builder.set_node_value(
            &nibble::bytes_to_nibbles([0].into_iter()).collect::<Vec<_>>(),
            &[
                65, 0, 81, 1, 108, 111, 110, 103, 32, 115, 116, 111, 114, 97, 103, 101, 32, 118,
                97, 108, 117, 101, 32, 105, 110, 32, 111, 114, 100, 101, 114, 32, 116, 111, 32,
                101, 110, 115, 117, 114, 101, 32, 116, 104, 97, 116, 32, 116, 104, 101, 32, 110,
                111, 100, 101, 32, 118, 97, 108, 117, 101, 32, 105, 115, 32, 109, 111, 114, 101,
                32, 116, 104, 97, 110, 32, 51, 50, 32, 98, 121, 116, 101, 115, 32, 108, 111, 110,
                103,
            ],
            None,
        );
        proof_builder.set_node_value(
            &nibble::bytes_to_nibbles([0x10].into_iter()).collect::<Vec<_>>(),
            &[
                65, 0, 81, 1, 108, 111, 110, 103, 32, 115, 116, 111, 114, 97, 103, 101, 32, 118,
                97, 108, 117, 101, 32, 105, 110, 32, 111, 114, 100, 101, 114, 32, 116, 111, 32,
                101, 110, 115, 117, 114, 101, 32, 116, 104, 97, 116, 32, 116, 104, 101, 32, 110,
                111, 100, 101, 32, 118, 97, 108, 117, 101, 32, 105, 115, 32, 109, 111, 114, 101,
                32, 116, 104, 97, 110, 32, 51, 50, 32, 98, 121, 116, 101, 115, 32, 108, 111, 110,
                103,
            ],
            None,
        );

        // The proof builder should de-duplicate the two children, otherwise the proof is invalid.
        proof_decode::decode_and_verify_proof(proof_decode::Config {
            proof: proof_builder.build_to_vec(),
            trie_root_hash: &[
                198, 201, 55, 96, 115, 79, 43, 132, 215, 236, 180, 232, 125, 60, 98, 103, 17, 46,
                150, 56, 154, 235, 33, 17, 222, 105, 142, 178, 235, 61, 88, 52,
            ],
        })
        .unwrap();
    }
}
