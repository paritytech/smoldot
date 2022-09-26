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

use crate::util;

use core::iter;

mod nibble;

pub mod calculate_root;
pub mod node_value;
pub mod prefix_proof;
pub mod proof_node_decode;
pub mod proof_verify;
pub mod trie_structure;

pub use nibble::{
    all_nibbles, bytes_to_nibbles, nibbles_to_bytes_extend, BytesToNibbles, Nibble,
    NibbleFromU8Error,
};

/// The format of the nodes of trie has two different versions.
///
/// As a summary of the difference between versions, in `V1` the value of the item in the trie is
/// hashed if it is too large. This isn't the case in `V0` where the value of the item is always
/// unhashed.
///
/// An encoded node value can be decoded unambiguously no matter whether it was encoded using `V0`
/// or `V1`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TrieEntryVersion {
    V0,
    V1,
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
                // Note that the version has no influence whatsoever on the output of the
                // calculation. The version passed here is a dummy value.
                calculation = val.inject(TrieEntryVersion::V1, None::<&[u8]>);
            }
        }
    }
}

/// Returns the Merkle value of a trie containing the entries passed as parameter. The entries
/// passed as parameter are `(key, value)`.
///
/// The complexity of this method is `O(n²)` where `n` is the number of entries.
// TODO: improve complexity?
pub fn trie_root(
    version: TrieEntryVersion,
    entries: &[(impl AsRef<[u8]>, impl AsRef<[u8]>)],
) -> [u8; 32] {
    let mut calculation = calculate_root::root_merkle_value(None);

    loop {
        match calculation {
            calculate_root::RootMerkleValueCalculation::Finished { hash, .. } => {
                return hash;
            }
            calculate_root::RootMerkleValueCalculation::AllKeys(keys) => {
                calculation = keys.inject(entries.iter().map(|(k, _)| k.as_ref().iter().copied()));
            }
            calculate_root::RootMerkleValueCalculation::StorageValue(value) => {
                let result = entries
                    .iter()
                    .find(|(k, _)| k.as_ref().iter().copied().eq(value.key()))
                    .map(|(_, v)| v);
                calculation = value.inject(version, result);
            }
        }
    }
}

/// Returns the Merkle value of a trie containing the entries passed as parameter, where the keys
/// are the SCALE-codec-encoded indices of these entries.
///
/// > **Note**: In isolation, this function seems highly specific. In practice, it is notably used
/// >           in order to build the trie root of the list of extrinsics of a block.
pub fn ordered_root(version: TrieEntryVersion, entries: &[impl AsRef<[u8]>]) -> [u8; 32] {
    const USIZE_COMPACT_BYTES: usize = 1 + (usize::BITS as usize) / 8;

    let mut calculation = calculate_root::root_merkle_value(None);

    loop {
        match calculation {
            calculate_root::RootMerkleValueCalculation::Finished { hash, .. } => {
                return hash;
            }
            calculate_root::RootMerkleValueCalculation::AllKeys(keys) => {
                calculation = keys.inject((0..entries.len()).map(|num| {
                    arrayvec::ArrayVec::<u8, USIZE_COMPACT_BYTES>::try_from(
                        util::encode_scale_compact_usize(num).as_ref(),
                    )
                    .unwrap()
                    .into_iter()
                }));
            }
            calculate_root::RootMerkleValueCalculation::StorageValue(value) => {
                let key = value
                    .key()
                    .collect::<arrayvec::ArrayVec<u8, USIZE_COMPACT_BYTES>>();
                let (_, key) =
                    util::nom_scale_compact_usize::<nom::error::Error<&[u8]>>(&key).unwrap();
                calculation = value.inject(version, entries.get(key));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn empty_trie() {
        let obtained = super::empty_trie_merkle_value();
        let expected = blake2_rfc::blake2b::blake2b(32, &[], &[0x0]);
        assert_eq!(obtained, expected.as_bytes());
    }
}
