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
//! unhashed Merkle values of the desired node and all its ancestors. This is called a Merkle
//! proof.
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
//!
//! ## Trie entry version
//!
//! In the Substrate/Polkadot trie, each trie node that contains a value also has a version
//! associated to it.
//!
//! This version changes the way the hash of the node is calculated and how the Merkle proof is
//! generated. Version 1 leads to more succinct Merkle proofs, which is important when these proofs
//! are sent over the Internet.
//!
//! Note that most of the time all the entries of the trie have the same version. However, it is
//! possible for the trie to be in a hybrid state where some entries have a certain version and
//! other entries a different version. For this reason, most of the trie-related APIs require you
//! to provide a trie entry version alongside with the value.
//!

use crate::util;

use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::Bound;

mod nibble;

pub mod branch_search;
pub mod calculate_root;
pub mod minimize_proof;
pub mod prefix_proof;
pub mod proof_decode;
pub mod proof_encode;
pub mod trie_node;
pub mod trie_structure;

use alloc::collections::BTreeSet;

pub use nibble::{
    BytesToNibbles, Nibble, NibbleFromU8Error, all_nibbles, bytes_to_nibbles,
    nibbles_to_bytes_prefix_extend, nibbles_to_bytes_suffix_extend, nibbles_to_bytes_truncate,
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

impl TryFrom<u8> for TrieEntryVersion {
    type Error = (); // TODO: better error?

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TrieEntryVersion::V0),
            1 => Ok(TrieEntryVersion::V1),
            _ => Err(()),
        }
    }
}

impl From<TrieEntryVersion> for u8 {
    fn from(v: TrieEntryVersion) -> u8 {
        match v {
            TrieEntryVersion::V0 => 0,
            TrieEntryVersion::V1 => 1,
        }
    }
}

/// Hash algorithm used during trie calculations.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HashFunction {
    Blake2,
    Keccak256,
}

/// Merkle value of the root node of an empty trie using [`HashFunction::Blake2`].
pub const EMPTY_BLAKE2_TRIE_MERKLE_VALUE: [u8; 32] = [
    3, 23, 10, 46, 117, 151, 183, 183, 227, 216, 76, 5, 57, 29, 19, 154, 98, 177, 87, 231, 135,
    134, 216, 192, 130, 242, 157, 207, 76, 17, 19, 20,
];

/// Merkle value of the root node of an empty trie using [`HashFunction::Keccak256`].
pub const EMPTY_KECCAK256_TRIE_MERKLE_VALUE: [u8; 32] = [
    188, 54, 120, 158, 122, 30, 40, 20, 54, 70, 66, 41, 130, 143, 129, 125, 102, 18, 247, 180, 119,
    214, 101, 145, 255, 150, 169, 224, 100, 188, 201, 138,
];

/// Prefix that identifies a default child trie within the main trie's storage.
///
/// The root of a default child trie identified by `trie_id` is stored in the main trie under
/// the key `concat(`[`DEFAULT_CHILD_STORAGE_PREFIX`]`, trie_id)`. Use
/// [`default_child_trie_root_key`] to build that key.
pub const DEFAULT_CHILD_STORAGE_PREFIX: &[u8] = b":child_storage:default:";

/// Returns the main-trie storage key under which the root of the default child trie identified
/// by `trie_id` is stored: `concat(`[`DEFAULT_CHILD_STORAGE_PREFIX`]`, trie_id)`.
pub fn default_child_trie_root_key(trie_id: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(DEFAULT_CHILD_STORAGE_PREFIX.len() + trie_id.len());
    k.extend_from_slice(DEFAULT_CHILD_STORAGE_PREFIX);
    k.extend_from_slice(trie_id);
    k
}

/// Returns the Merkle value of a trie containing the entries passed as parameter. The entries
/// passed as parameter are `(key, value)`.
///
/// The entries do not need to be ordered.
pub fn trie_root(
    version: TrieEntryVersion,
    hash_function: HashFunction,
    unordered_entries: &[(impl AsRef<[u8]>, impl AsRef<[u8]>)],
) -> [u8; 32] {
    let ordered_entries = unordered_entries
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_ref()))
        .collect::<BTreeMap<_, _>>();

    let mut calculation = calculate_root::root_merkle_value(hash_function);

    loop {
        match calculation {
            calculate_root::RootMerkleValueCalculation::Finished { hash } => return hash,
            calculate_root::RootMerkleValueCalculation::StorageValue(storage_value) => {
                let val = ordered_entries.get(&storage_value.key().collect::<Vec<_>>()[..]);
                calculation = storage_value.inject(val.map(|v| (v, version)));
            }
            calculate_root::RootMerkleValueCalculation::NextKey(next_key) => {
                let key = next_key
                    .key_before()
                    .chain(next_key.or_equal().then_some(0))
                    .collect::<Vec<_>>();
                let result = ordered_entries
                    .range(&key[..]..)
                    .next()
                    .filter(|(k, _)| {
                        let mut k = k.iter();
                        let mut p = next_key.prefix();
                        loop {
                            match (k.next(), p.next()) {
                                (Some(a), Some(b)) if *a == b => {}
                                (Some(_), Some(_)) => break false,
                                (Some(_), None) => break true,
                                (None, Some(_)) => break false,
                                (None, None) => break true,
                            }
                        }
                    })
                    .map(|(k, _)| *k);
                calculation = next_key.inject_key(result.map(|s| s.iter().copied()));
            }
        }
    }
}

/// Returns the Merkle value of a trie containing the entries passed as parameter, where the keys
/// are the SCALE-codec-encoded indices of these entries.
///
/// > **Note**: In isolation, this function seems highly specific. In practice, it is notably used
/// >           in order to build the trie root of the list of extrinsics of a block.
pub fn ordered_root(
    version: TrieEntryVersion,
    hash_function: HashFunction,
    entries: &[impl AsRef<[u8]>],
) -> [u8; 32] {
    const USIZE_COMPACT_BYTES: usize = 1 + (usize::BITS as usize) / 8;

    // Mapping numbers to SCALE-encoded numbers changes the ordering, so we have to sort the keys
    // beforehand.
    let trie_keys = (0..entries.len())
        .map(|num| util::encode_scale_compact_usize(num).as_ref().to_vec())
        .collect::<BTreeSet<_>>();

    let mut calculation = calculate_root::root_merkle_value(hash_function);

    loop {
        match calculation {
            calculate_root::RootMerkleValueCalculation::Finished { hash, .. } => {
                return hash;
            }
            calculate_root::RootMerkleValueCalculation::NextKey(next_key) => {
                let key_before = next_key.key_before().collect::<Vec<_>>();
                let lower_bound = if next_key.or_equal() {
                    Bound::Included(key_before)
                } else {
                    Bound::Excluded(key_before)
                };
                let k = trie_keys
                    .range((lower_bound, Bound::Unbounded))
                    .next()
                    .filter(|k| {
                        k.iter()
                            .copied()
                            .zip(next_key.prefix())
                            .all(|(a, b)| a == b)
                    });
                calculation = next_key.inject_key(k.map(|k| k.iter().copied()));
            }
            calculate_root::RootMerkleValueCalculation::StorageValue(value_req) => {
                let key = value_req
                    .key()
                    .collect::<arrayvec::ArrayVec<u8, USIZE_COMPACT_BYTES>>();
                let value = match nom::Parser::parse(
                    &mut nom::combinator::all_consuming(
                        util::nom_scale_compact_usize::<nom::error::Error<&[u8]>>,
                    ),
                    &key,
                ) {
                    Ok((_, key)) => entries.get(key).map(move |v| (v, version)),
                    Err(_) => None,
                };
                calculation = value_req.inject(value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HashFunction, trie_node};
    use core::iter;

    #[test]
    fn empty_trie_blake2() {
        let calculated_through_function = *<&[u8; 32]>::try_from(
            trie_node::calculate_merkle_value(
                trie_node::Decoded {
                    children: [None::<&'static [u8]>; 16],
                    partial_key: iter::empty(),
                    storage_value: trie_node::StorageValue::None,
                },
                HashFunction::Blake2,
                true,
            )
            .unwrap()
            .as_ref(),
        )
        .unwrap();

        let calculated_manually = blake2_rfc::blake2b::blake2b(32, &[], &[0x0]);

        assert_eq!(calculated_through_function, calculated_manually.as_bytes());
        assert_eq!(
            calculated_through_function,
            super::EMPTY_BLAKE2_TRIE_MERKLE_VALUE
        );
    }

    #[test]
    fn empty_trie_keccak256() {
        let calculated_through_function = *<&[u8; 32]>::try_from(
            trie_node::calculate_merkle_value(
                trie_node::Decoded {
                    children: [None::<&'static [u8]>; 16],
                    partial_key: iter::empty(),
                    storage_value: trie_node::StorageValue::None,
                },
                HashFunction::Keccak256,
                true,
            )
            .unwrap()
            .as_ref(),
        )
        .unwrap();

        let calculated_manually = <sha3::Keccak256 as sha3::Digest>::digest(&[0x0]);

        assert_eq!(calculated_through_function, calculated_manually.as_ref());
        assert_eq!(
            calculated_through_function,
            super::EMPTY_KECCAK256_TRIE_MERKLE_VALUE
        );
    }

    #[test]
    fn trie_root_example_v0_blake2() {
        let obtained = super::trie_root(
            super::TrieEntryVersion::V0,
            super::HashFunction::Blake2,
            &[(&b"foo"[..], &b"bar"[..]), (&b"foobar"[..], &b"baz"[..])],
        );

        assert_eq!(
            obtained,
            [
                166, 24, 32, 181, 251, 169, 176, 26, 238, 16, 181, 187, 216, 74, 234, 128, 184, 35,
                3, 24, 197, 232, 202, 20, 185, 164, 148, 12, 118, 224, 152, 21
            ]
        );
    }

    #[test]
    fn trie_root_example_v0_keccak() {
        let obtained = super::trie_root(
            super::TrieEntryVersion::V0,
            super::HashFunction::Keccak256,
            &[(&b"foo"[..], &b"bar"[..]), (&b"foobar"[..], &b"baz"[..])],
        );

        assert_eq!(
            obtained,
            [
                109, 13, 46, 4, 44, 192, 37, 121, 213, 230, 248, 34, 108, 36, 86, 23, 164, 52, 162,
                165, 248, 111, 236, 65, 142, 71, 118, 196, 44, 205, 139, 145
            ]
        );
    }

    #[test]
    fn trie_root_example_v1_blake2() {
        let obtained = super::trie_root(
            super::TrieEntryVersion::V1,
            super::HashFunction::Blake2,
            &[
                (&b"bar"[..], &b"foo"[..]),
                (&b"barfoo"[..], &b"hello"[..]),
                (&b"anotheritem"[..], &b"anothervalue"[..]),
            ],
        );

        assert_eq!(
            obtained,
            [
                68, 24, 7, 195, 69, 202, 122, 223, 136, 189, 33, 171, 27, 60, 186, 219, 21, 97,
                106, 187, 137, 22, 126, 185, 254, 40, 93, 213, 206, 205, 4, 200
            ]
        );
    }

    #[test]
    fn trie_root_example_v1_keccak() {
        let obtained = super::trie_root(
            super::TrieEntryVersion::V1,
            super::HashFunction::Keccak256,
            &[
                (&b"bar"[..], &b"foo"[..]),
                (&b"barfoo"[..], &b"hello"[..]),
                (&b"anotheritem"[..], &b"anothervalue"[..]),
            ],
        );

        assert_eq!(
            obtained,
            [
                163, 182, 101, 58, 113, 93, 97, 19, 25, 39, 58, 170, 167, 225, 212, 187, 157, 3,
                230, 21, 92, 129, 196, 38, 212, 190, 49, 103, 242, 0, 4, 65
            ]
        );
    }
}
