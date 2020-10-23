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

//! Radix-16 Merkle-Patricia trie.
//!
//! This Substrate/Polkadot-specific radix-16 Merkle-Patricia trie is a data structure that
//! associates keys with values, and that allows efficient verification of the integrity of the
//! data.
//!
//! # Overview
//!
//! The key-value storage that the blockchain maintains is represented by
//! [a tree](https://en.wikipedia.org/wiki/Tree_data_structure), where each key-value pair in the
//! storage corresponds to a node in that tree.
//!
//! Each node in this tree has what is called a Merkle value associated to it. This Merkle value
//! consists, in its essence, in the combination of the storage value associated to that node and
//! the Merkle values of all of the node's children. If the resulting Merkle value would be too
//! long, it is first hashed.
//!
//! Since the Merkle values of a node's children depend, in turn, of the Merkle value of their
//! own children, we can say that the Merkle value of a node depends on all of the node's
//! descendants.
//!
//! Consequently, the Merkle value of the root node of the tree depends on the storage values of
//! all the nodes in the tree.
//!
//! See also [the Wikipedia page for Merkle tree for a different
//! explanation](https://en.wikipedia.org/wiki/Merkle_tree).
//!
//! ## Efficient updates
//!
//! When a storage value gets modified, the Merkle value of the root node of the tree also gets
//! modified. Thanks to the tree layout, we don't need to recalculate the Merkle value of the
//! entire tree, but only of the ancestors of the node which has been modified.
//!
//! If the storage consists of N entries, recalculating the Merkle value of the trie root requires
//! on average only `log16(N)` operations.
//!
//! ## Proof of storage entry
//!
//! In the situation where we want to know the storage value associated to a node, but we only
//! know the Merkle value of the root of the trie, it is possible to ask a third-party for the
//! unhashed Merkle values of the desired node and all its ancestors.
//!
//! After having verified that the third-party has provided correct values, and that they match
//! the expected root node Merkle value known locally, we can extract the storage value from the
//! Merkle value of the desired node.
//!
//! # Details
//!
//! This data structure is a tree composed of nodes, each node being identified by a key. A key
//! consists in a sequence of 4-bits values called *nibbles*. Example key: `[3, 12, 7, 0]`.
//!
//! Some of these nodes contain a value.
//!
//! A node A is an *ancestor* of another node B if the key of A is a prefix of the key of B. For
//! example, the node whose key is `[3, 12]` is an ancestor of the node whose key is
//! `[3, 12, 8, 9]`. B is a *descendant* of A.
//!
//! Nodes exist only either if they contain a value, or if their key is the longest shared prefix
//! of two or more nodes that contain a value. For example, if nodes `[7, 2, 9, 11]` and
//! `[7, 2, 14, 8]` contain a value, then node `[7, 2]` also exist, because it is the longest
//! prefix shared between the two.
//!
//! The *Merkle value* of a node is composed, amongst other things, of its associated value and of
//! the Merkle value of its descendants. As such, modifying a node modifies the Merkle value of
//! all its ancestors. Note, however, that modifying a node modifies the Merkle value of *only*
//! its ancestors. As such, the time spent calculating the Merkle value of the root node of a trie
//! mostly depends on the number of modifications that are performed on it, and only a bit on the
//! size of the trie.

use alloc::collections::BTreeMap;
use core::{iter, mem};

mod nibble;

pub mod calculate_root;
pub mod node_value;
pub mod proof_verify;
pub mod trie_structure;

pub use nibble::{bytes_to_nibbles, BytesToNibbles, Nibble, NibbleFromU8Error};

/// Radix-16 Merkle-Patricia trie.
// TODO: probably useless, remove
pub struct Trie {
    /// The entries in the tree.
    ///
    /// Since this is a binary tree, the elements are ordered lexicographically.
    /// Example order: "a", "ab", "ac", "b".
    ///
    /// This list only contains the nodes that have an entry in the storage, and not the nodes
    /// that are branches and don't have a storage entry.
    ///
    /// All the keys have an even number of nibbles.
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Trie {
    /// Builds a new empty [`Trie`].
    pub fn new() -> Trie {
        Trie {
            entries: BTreeMap::new(),
        }
    }

    /// Inserts a new entry in the trie.
    pub fn insert(&mut self, key: &[u8], value: impl Into<Vec<u8>>) {
        self.entries.insert(key.into(), value.into());
    }

    /// Removes an entry from the trie.
    pub fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.entries.remove(key)
    }

    /// Returns true if the `Trie` is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes all the elements from the trie.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Calculates the Merkle value of the root node.
    ///
    /// Passes an optional cache.
    pub fn root_merkle_value(
        &self,
        mut cache: Option<&mut calculate_root::CalculationCache>,
    ) -> [u8; 32] {
        let mut calculation = calculate_root::root_merkle_value({
            if let Some(cache) = &mut cache {
                Some(mem::replace(
                    cache,
                    calculate_root::CalculationCache::empty(),
                ))
            } else {
                None
            }
        });

        loop {
            match calculation {
                calculate_root::RootMerkleValueCalculation::Finished {
                    hash,
                    cache: new_cache,
                } => {
                    if let Some(cache) = cache {
                        *cache = new_cache;
                    }
                    return hash;
                }
                calculate_root::RootMerkleValueCalculation::AllKeys(keys) => {
                    calculation = keys.inject(self.entries.keys().map(|k| k.iter().cloned()));
                }
                calculate_root::RootMerkleValueCalculation::StorageValue(value) => {
                    let key = value.key().collect::<Vec<u8>>();
                    calculation = value.inject(self.entries.get(&key));
                }
            }
        }
    }
}

/// Returns the Merkle value of the root of an empty trie.
pub fn empty_trie_merkle_value() -> [u8; 32] {
    let mut calculation = calculate_root::root_merkle_value(None);

    loop {
        match calculation {
            calculate_root::RootMerkleValueCalculation::Finished { hash, .. } => break hash,
            calculate_root::RootMerkleValueCalculation::AllKeys(keys) => {
                calculation = keys.inject(iter::empty::<iter::Empty<u8>>());
            }
            calculate_root::RootMerkleValueCalculation::StorageValue(val) => {
                calculation = val.inject(None::<&[u8]>);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Trie;

    #[test]
    fn trie_root_one_node() {
        let mut trie = Trie::new();
        trie.insert(b"abcd", b"hello world".to_vec());

        let expected = [
            122, 177, 134, 89, 211, 178, 120, 158, 242, 64, 13, 16, 113, 4, 199, 212, 251, 147,
            208, 109, 154, 182, 168, 182, 65, 165, 222, 124, 63, 236, 200, 81,
        ];

        assert_eq!(trie.root_merkle_value(None), &expected[..]);
    }

    #[test]
    fn trie_root_empty() {
        let trie = Trie::new();
        let expected = blake2_rfc::blake2b::blake2b(32, &[], &[0x0]);
        assert_eq!(trie.root_merkle_value(None), expected.as_bytes());
    }

    #[test]
    fn trie_root_single_tuple() {
        let mut trie = Trie::new();
        trie.insert(&[0xaa], [0xbb].to_vec());

        fn to_compact(n: u8) -> u8 {
            use parity_scale_codec::Encode as _;
            parity_scale_codec::Compact(n).encode()[0]
        }

        let expected = blake2_rfc::blake2b::blake2b(
            32,
            &[],
            &[
                0x42,          // leaf 0x40 (2^6) with (+) key of 2 nibbles (0x02)
                0xaa,          // key data
                to_compact(1), // length of value in bytes as Compact
                0xbb,          // value data
            ],
        );

        assert_eq!(trie.root_merkle_value(None), expected.as_bytes());
    }

    #[test]
    fn trie_root_example() {
        let mut trie = Trie::new();
        trie.insert(&[0x48, 0x19], [0xfe].to_vec());
        trie.insert(&[0x13, 0x14], [0xff].to_vec());

        fn to_compact(n: u8) -> u8 {
            use parity_scale_codec::Encode as _;
            parity_scale_codec::Compact(n).encode()[0]
        }

        let mut ex = Vec::<u8>::new();
        ex.push(0x80); // branch, no value (0b_10..) no nibble
        ex.push(0x12); // slots 1 & 4 are taken from 0-7
        ex.push(0x00); // no slots from 8-15
        ex.push(to_compact(0x05)); // first slot: LEAF, 5 bytes long.
        ex.push(0x43); // leaf 0x40 with 3 nibbles
        ex.push(0x03); // first nibble
        ex.push(0x14); // second & third nibble
        ex.push(to_compact(0x01)); // 1 byte data
        ex.push(0xff); // value data
        ex.push(to_compact(0x05)); // second slot: LEAF, 5 bytes long.
        ex.push(0x43); // leaf with 3 nibbles
        ex.push(0x08); // first nibble
        ex.push(0x19); // second & third nibble
        ex.push(to_compact(0x01)); // 1 byte data
        ex.push(0xfe); // value data

        let expected = blake2_rfc::blake2b::blake2b(32, &[], &ex);
        assert_eq!(trie.root_merkle_value(None), expected.as_bytes());
    }

    #[test]
    fn empty_trie() {
        let obtained = super::empty_trie_merkle_value();
        let expected = blake2_rfc::blake2b::blake2b(32, &[], &[0x0]);
        assert_eq!(obtained, expected.as_bytes());
    }
}
