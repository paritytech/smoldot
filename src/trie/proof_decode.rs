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

//! Decodes and verifies a trie proof.
//!
//! A trie proof is a proof that a certain key in the trie has a certain storage value (or lacks
//! a storage value). The proof can be verified by knowing only the Merkle value of the root node.
//!
//! # Details
//!
//! > **Note**: For reminder, the Merkle value of a node is the hash of its node value, or the
//! >           node value directly if its length is smaller than 32 bytes.
//!
//! A trie proof consists in a list of node values of nodes in the trie. For the proof to be valid,
//! the hash of one of these node values must match the expected trie root node value. Since a
//! node value contains the Merkle values of the children of the node, it is possible to iterate
//! down the hierarchy of nodes until the one closest to the desired key is found.
//!
//! # Usage
//!
//! This modules provides the [`decode_and_verify_proof`] function that decodes a proof and
//! verifies whether it is correct.
//!
//! Once decoded, one can examine the content of the proof, in other words the list of storage
//! items and values.

use super::{nibble, proof_node_codec};

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{mem, ops};

/// Configuration to pass to [`decode_and_verify_proof`].
pub struct Config<'a, I> {
    /// Merkle value (or node value) of the root node of the trie.
    ///
    /// > **Note**: The Merkle value and node value are always the same for the root node.
    pub trie_root_hash: &'a [u8; 32],

    /// List of node values of nodes found in the trie. At least one entry corresponding to the
    /// root node of the trie must be present in order for the verification to succeed.
    pub proof: I,
}

/// Verifies whether a proof is correct and returns an object that allows examining its content.
///
/// The proof is then stored within the [`DecodedTrieProof`].
///
/// Due to the generic nature of this function, the proof can be either a `Vec<u8>` or a `&[u8]`.
///
/// Returns an error if the proof is invalid, or if the proof contains entries that are
/// disconnected from the root node of the trie.
pub fn decode_and_verify_proof<'a, T>(config: Config<'a, T>) -> Result<DecodedTrieProof<T>, Error>
where
    T: AsRef<[u8]>,
{
    // Call `as_ref()` once at the beginning in order to guarantee stability of the memory
    // location.
    let proof_as_ref = config.proof.as_ref();

    // A Merkle proof is a SCALE-encoded `Vec<Vec<u8>>`.
    //
    // This `Vec` contains two types of items: trie node values, and standalone storage items. In
    // both cases, we will later need a hashed version of them. Create a list of hashes, one per
    // entry in `proof`.
    //
    // This hashmap uses a FNV hasher, theoretically vulnerable to HashDos attacks. While it is
    // possible for an attacker to craft a proof that leads to all entries being in the same
    // bucket, this proof is going to be invalid (unless the blake2 hash function is broken, which
    // we assume it isn't). So while an attacker can slightly increase the time that this function
    // takes, it is always cause this function to return an error and is actually likely to make
    // the function actually take less time than if it was a legitimate proof.
    let merkle_values = {
        // TODO: don't use a Vec?
        let (_, decoded_proof) = nom::combinator::all_consuming(nom::combinator::flat_map(
            crate::util::nom_scale_compact_usize,
            |num_elems| nom::multi::many_m_n(num_elems, num_elems, crate::util::nom_bytes_decode),
        ))(config.proof.as_ref())
        .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| Error::InvalidFormat)?;

        let merkle_values = decoded_proof
            .iter()
            .copied()
            .enumerate()
            .map(
                |(proof_entry_num, proof_entry)| -> (arrayvec::ArrayVec<u8, 32>, (usize, ops::Range<usize>)) {
                    let hash = if proof_entry.len() >= 32 {
                        blake2_rfc::blake2b::blake2b(32, &[], proof_entry)
                            .as_bytes()
                            .iter()
                            .copied()
                            .collect()
                    } else {
                        proof_entry.iter().copied().collect()
                    };

                    let proof_entry_offset = if proof_entry.len() == 0 {
                        0
                    } else {
                        proof_entry.as_ptr() as usize - proof_as_ref.as_ptr() as usize
                    };

                    (
                        hash,
                        (proof_entry_num, proof_entry_offset..(proof_entry_offset + proof_entry.len())),
                    )
                },
            )
            .collect::<hashbrown::HashMap<_, _, fnv::FnvBuildHasher>>();

        // Using a hashmap has the consequence that if multiple proof entries were identical, only
        // one would be tracked. For this reason, we make sure that the proof doesn't contain
        // multiple identical entries.
        if merkle_values.len() != decoded_proof.len() {
            return Err(Error::DuplicateProofEntry);
        }

        merkle_values
    };

    // Dummy empty proofs are always valid.
    if merkle_values.is_empty() {
        return Ok(DecodedTrieProof {
            proof: config.proof,
            entries: BTreeMap::new(),
        });
    }

    // The implementation below iterates down the tree of nodes represented by this proof, keeping
    // note of the traversed elements.

    // Keep track of the proof entries that haven't been visited when traversing.
    let mut unvisited_proof_entries =
        (0..merkle_values.len()).collect::<hashbrown::HashSet<_, fnv::FnvBuildHasher>>();

    // Find the expected trie root in the proof. This is the starting point of the verification.
    let mut remain_iterate = {
        let (root_position, root_range) = merkle_values
            .get(&config.trie_root_hash[..])
            .ok_or(Error::TrieRootNotFound)?
            .clone();
        let _ = unvisited_proof_entries.remove(&root_position);
        vec![(root_range, Vec::new())]
    };

    // Keep track of all the entries found in the proof.
    let mut entries = BTreeMap::new();

    while !remain_iterate.is_empty() {
        // Iterate through each entry in `remain_iterate`.
        // This clears `remain_iterate` so that we can add new entries to it during the iteration.
        for (proof_entry_range, storage_key_before_partial) in
            mem::replace(&mut remain_iterate, Vec::with_capacity(merkle_values.len()))
        {
            // Decodes the proof entry.
            let proof_entry = &proof_as_ref[proof_entry_range.clone()];
            let decoded_node_value =
                proof_node_codec::decode(proof_entry).map_err(Error::InvalidNodeValue)?;
            let decoded_node_value_children_bitmap = decoded_node_value.children_bitmap();

            // Build the storage key of the node.
            let storage_key = {
                let mut storage_key_after_partial = Vec::with_capacity(
                    storage_key_before_partial.len() + decoded_node_value.partial_key.len(),
                );
                storage_key_after_partial.extend_from_slice(&storage_key_before_partial);
                storage_key_after_partial.extend(decoded_node_value.partial_key);
                storage_key_after_partial
            };

            // Add the children to `remain_iterate`.
            for (child_num, child_node_value) in decoded_node_value.children.into_iter().enumerate()
            {
                // Ignore missing children slots.
                let child_node_value = match child_node_value {
                    None => continue,
                    Some(v) => v,
                };

                debug_assert!(child_num < 16);
                let child_nibble =
                    nibble::Nibble::try_from(u8::try_from(child_num).unwrap()).unwrap();

                // Key of the child node before its partial key.
                let mut child_storage_key_before_partial =
                    Vec::with_capacity(storage_key.len() + 1);
                child_storage_key_before_partial.extend_from_slice(&storage_key);
                child_storage_key_before_partial.push(child_nibble);

                // The value of the child node is either directly inlined (if less than 32 bytes)
                // or is a hash.
                if child_node_value.len() < 32 {
                    let offset = proof_entry_range.start
                        + if !child_node_value.is_empty() {
                            child_node_value.as_ptr() as usize - proof_entry.as_ptr() as usize
                        } else {
                            0
                        };
                    debug_assert!(offset <= (proof_entry_range.start + proof_entry.len()));
                    remain_iterate.push((
                        offset..(offset + child_node_value.len()),
                        child_storage_key_before_partial,
                    ));
                } else {
                    // The decoding API guarantees that the child value is never larger than
                    // 32 bytes.
                    debug_assert_eq!(child_node_value.len(), 32);
                    if let Some((child_position, child_entry_range)) =
                        merkle_values.get(child_node_value)
                    {
                        // Remove the entry from `unvisited_proof_entries`.
                        // Note that it is questionable what to do if the same entry is visited
                        // multiple times. In case where multiple storage branches are identical,
                        // the sender of the proof should de-duplicate the identical nodes. For
                        // this reason, it could be legitimate for the same proof entry to be
                        // visited multiple times.
                        let _ = unvisited_proof_entries.remove(child_position);
                        remain_iterate
                            .push((child_entry_range.clone(), child_storage_key_before_partial));
                    }
                }
            }

            // Insert the node into `entries`.
            // This is done at the end so that `storage_key` doesn't need to be cloned.
            let _prev_value = entries.insert(storage_key, {
                let storage_value = match decoded_node_value.storage_value {
                    proof_node_codec::StorageValue::None => StorageValueInner::None,
                    proof_node_codec::StorageValue::Hashed(value_hash) => {
                        if let Some((value_position, value_entry_range)) =
                            merkle_values.get(&value_hash[..])
                        {
                            let _ = unvisited_proof_entries.remove(value_position);
                            StorageValueInner::Known {
                                offset: value_entry_range.start,
                                len: value_entry_range.end - value_entry_range.start,
                            }
                        } else {
                            let offset =
                                value_hash.as_ptr() as usize - proof_as_ref.as_ptr() as usize;
                            debug_assert!(offset >= proof_entry_range.start);
                            debug_assert!(offset <= (proof_entry_range.start + proof_entry.len()));
                            StorageValueInner::HashKnownValueMissing { offset }
                        }
                    }
                    proof_node_codec::StorageValue::Unhashed(v) => {
                        let offset = if !v.is_empty() {
                            v.as_ptr() as usize - proof_as_ref.as_ptr() as usize
                        } else {
                            0
                        };
                        debug_assert!(offset >= proof_entry_range.start);
                        debug_assert!(offset <= (proof_entry_range.start + proof_entry.len()));
                        StorageValueInner::Known {
                            offset,
                            len: v.len(),
                        }
                    }
                };

                (storage_value, decoded_node_value_children_bitmap)
            });
            debug_assert!(_prev_value.is_none());
        }
    }

    // The entire reason why we track the unvisited proof entries is to return this error if
    // necessary.
    if !unvisited_proof_entries.is_empty() {
        return Err(Error::UnusedProofEntry);
    }

    Ok(DecodedTrieProof {
        proof: config.proof,
        entries,
    })
}

/// Equivalent to [`StorageValue`] but contains offsets indexing [`DecodedTrieProof::proof`].
#[derive(Debug, Copy, Clone)]
enum StorageValueInner {
    /// Equivalent to [`StorageValue::Known`].
    Known { offset: usize, len: usize },
    /// Equivalent to [`StorageValue::HashKnownValueMissing`].
    HashKnownValueMissing { offset: usize },
    /// Equivalent to [`StorageValue::None`].
    None,
}

/// Decoded Merkle proof. The proof is guaranteed valid.
// TODO: implement Debug
pub struct DecodedTrieProof<T> {
    /// The proof itself.
    proof: T,

    /// For each storage key, contains the entry found in the proof and the children bitmap.
    // TODO: a BTreeMap is actually kind of stupid since `proof` is itself in a tree format
    entries: BTreeMap<Vec<nibble::Nibble>, (StorageValueInner, u16)>,
}

impl<T: AsRef<[u8]>> DecodedTrieProof<T> {
    /// Returns a list of all elements of the proof, ordered by key in lexicographic order.
    ///
    /// This function is a convenient wrapper around [`DecodedTrieProof::iter_ordered`] that
    /// converts the keys into arrays of bytes. If a key can't be represented as an array of
    /// bytes, then this function panics. Assuming that the trie has only ever been used in the
    /// context of the runtime, then panics cannot happen. See the section below for an
    /// explanation.
    ///
    /// The iterator might include branch nodes. It is not possible for this function to
    /// differentiate between value-less nodes that are present in the proof only because they are
    /// branch nodes, and value-less nodes that are present in the proof because the fact that they
    /// have no value is important for the proof.
    ///
    /// # Detailed explanation
    ///
    /// The trie consists of nodes, each with a key and a value. The keys consist of an array of
    /// "nibbles", which are 4 bits each.
    ///
    /// When the runtime writes a value in the trie, it passes a key as an array a bytes. In order
    /// to know where to write this value, this array of bytes is converted into an array of
    /// nibbles by turning each byte into two nibbles.
    ///
    /// Due to the fact that the host-runtime interface only ever uses arrays of bytes, it is not
    /// possible for the runtime to store a value or read a value in the trie at a key that
    /// consists in an uneven number of nibbles, as an uneven number of nibbles cannot be
    /// converted to an array of bytes.
    ///
    /// In other words, if a trie has only ever been used in the context of a runtime, then it is
    /// guaranteed to not contain any storage value at key that consists in an uneven number of
    /// nibbles.
    ///
    /// The trie format itself, however, technically doesn't forbid storing reading and writing
    /// values at keys that consist in an uneven number of nibbles. For this reason, a proof
    /// containing a value at a key that consists in an uneven number of nibbles is considered as
    /// valid according to [`decode_and_verify_proof`].
    ///
    /// However, given that [`decode_and_verify_proof`] verifies the trie proof against the state
    /// trie root hash, we are also guaranteed that this proof reflects the actual trie. If the
    /// actual trie can't contain any storage value at a key that consists in an uneven number of
    /// nibbles, then the proof is also guaranteed to not contain any storage value at a key that
    /// consists in an uneven number of nibbles.
    ///
    /// As a conclusion, if this proof is made against a trie that has only ever been used in the
    /// context of a runtime, then this function cannot panic. Malicious proofs also cannot trigger
    /// a panic.
    ///
    /// # Panic
    ///
    /// Panics if the proof contains any storage value at a key with an uneven number of nibbles.
    /// This cannot happen if the proof is a proof of a trie that has only ever been used in the
    /// context of the runtime. See the section above for detailed explanations.
    ///
    pub fn iter_runtime_context_ordered(
        &'_ self,
    ) -> impl Iterator<Item = (Vec<u8>, StorageValue<'_>)> + '_ {
        self.iter_ordered().filter_map(|(key, value)| {
            let value = value.storage_value;

            if key.len() % 2 != 0 {
                assert!(matches!(value, StorageValue::None));
                return None;
            }

            let key = nibble::nibbles_to_bytes_suffix_extend(key.iter().copied()).collect();
            Some((key, value))
        })
    }

    /// Returns a list of all elements of the proof, ordered by key in lexicographic order.
    ///
    /// The iterator includes branch nodes.
    pub fn iter_ordered(
        &'_ self,
    ) -> impl Iterator<Item = (&'_ [nibble::Nibble], TrieNodeInfo<'_>)> + '_ {
        self.entries
            .iter()
            .map(|(key, (storage_value, children_bitmap))| {
                let storage_value = match storage_value {
                    StorageValueInner::Known { offset, len } => {
                        StorageValue::Known(&self.proof.as_ref()[*offset..][..*len])
                    }
                    StorageValueInner::None => StorageValue::None,
                    StorageValueInner::HashKnownValueMissing { offset } => {
                        StorageValue::HashKnownValueMissing(
                            <&[u8; 32]>::try_from(&self.proof.as_ref()[*offset..][..32]).unwrap(),
                        )
                    }
                };

                (
                    &key[..],
                    TrieNodeInfo {
                        children: Children {
                            children_bitmap: *children_bitmap,
                        },
                        storage_value,
                    },
                )
            })
    }

    /// Returns information about a trie node.
    ///
    /// Returns `None` if the proof doesn't contain enough information about this trie node.
    pub fn trie_node_info(&'_ self, key: &[nibble::Nibble]) -> Option<TrieNodeInfo<'_>> {
        // If the proof is empty, then we have no information about the node whatsoever.
        // This check is necessary because we assume below that a lack of ancestor means that the
        // key is outside of the trie.
        if self.entries.is_empty() {
            return None;
        }

        // The requested key can be found directly in the proof, but it can also be a child of an
        // item of the proof.
        // Search for the key in the proof that is an ancestor or equal to the requested key.
        // As explained in the comments below, there are at most `key.len()` iterations, making
        // this `O(log n)`.
        let mut to_search = key;
        loop {
            debug_assert!(key.starts_with(to_search));

            match self
                .entries
                .range::<[nibble::Nibble], _>((
                    ops::Bound::Unbounded,
                    ops::Bound::Included(to_search),
                ))
                .next_back()
            {
                None => {
                    debug_assert!(!self.entries.is_empty());
                    // The requested key doesn't have any ancestor in the trie. This means that
                    // it doesn't share any prefix with any other entry in the trie. This means
                    // that it doesn't exist.
                    return Some(TrieNodeInfo {
                        storage_value: StorageValue::None,
                        children: Children { children_bitmap: 0 },
                    });
                }
                Some((found_key, (storage_value, children_bitmap))) if *found_key == key => {
                    // Found exact match. Returning.
                    return Some(TrieNodeInfo {
                        storage_value: match storage_value {
                            StorageValueInner::Known { offset, len } => {
                                StorageValue::Known(&self.proof.as_ref()[*offset..][..*len])
                            }
                            StorageValueInner::None => StorageValue::None,
                            StorageValueInner::HashKnownValueMissing { offset } => {
                                StorageValue::HashKnownValueMissing(
                                    <&[u8; 32]>::try_from(&self.proof.as_ref()[*offset..][..32])
                                        .unwrap(),
                                )
                            }
                        },
                        children: Children {
                            children_bitmap: *children_bitmap,
                        },
                    });
                }
                Some((found_key, (_, children_bitmap))) if key.starts_with(found_key) => {
                    // Requested key is a descendant of an entry found in the proof.
                    // Check whether the entry can have a descendant in the direction towards the
                    // requested key.
                    if children_bitmap & (1 << u8::from(key[found_key.len()])) == 0 {
                        // Child absent.
                        // It has been proven that the requested key doesn't exist in the trie.
                        return Some(TrieNodeInfo {
                            storage_value: StorageValue::None,
                            children: Children { children_bitmap: 0 },
                        });
                    } else if self
                        .entries
                        .range::<[nibble::Nibble], _>((
                            ops::Bound::Included(&key[..found_key.len() + 1]),
                            ops::Bound::Unbounded,
                        ))
                        .next()
                        .map_or(false, |(k, _)| k.starts_with(&key[..found_key.len() + 1]))
                    {
                        // Child present.
                        // There exists at least one node in the proof that starts with
                        // `key[..found_key.len() + 1]` but that isn't `key`, and there isn't any
                        // branch node at the common ancestor between this node and `key`, as
                        // otherwise would have found it when iterating earlier. This branch node
                        // can't be missing from the proof as otherwise the proof would be invalid.
                        // Thus, the requested key doesn't exist in the trie.
                        return Some(TrieNodeInfo {
                            storage_value: StorageValue::None,
                            children: Children { children_bitmap: 0 },
                        });
                    } else {
                        // Child present.
                        // The request key can possibly be in the trie, but we have no way of
                        // knowing because the proof doesn't have enough information.
                        return None;
                    }
                }
                Some((found_key, _)) => {
                    // ̀`found_key` is somewhere between the ancestor of the requested key and the
                    // requested key. Continue searching, this time starting at the common ancestor
                    // between `found_key` and the requested key.
                    // This means that we have at most `key.len()` loop iterations.
                    let common_nibbles = found_key
                        .iter()
                        .zip(key.iter())
                        .take_while(|(a, b)| a == b)
                        .count();
                    debug_assert!(common_nibbles < to_search.len()); // Make sure we progress.
                    debug_assert_eq!(&found_key[..common_nibbles], &key[..common_nibbles]);
                    to_search = &key[..common_nibbles];
                }
            }
        }
    }

    /// Queries from the proof the storage value at the given key.
    ///
    /// Returns `None` if the storage value couldn't be determined from the proof. Returns
    /// `Some(None)` if the storage value is known to have no value.
    ///
    /// > **Note**: This function is a convenient wrapper around
    /// >           [`DecodedTrieProof::trie_node_info`].
    // TODO: return a Result instead of Option?
    pub fn storage_value(&'_ self, key: &[u8]) -> Option<Option<&'_ [u8]>> {
        // Annoyingly we have to create a `Vec` for the key, but the API of BTreeMap gives us
        // no other choice.
        let key = nibble::bytes_to_nibbles(key.iter().copied()).collect::<Vec<_>>();
        match self.trie_node_info(&key)?.storage_value {
            StorageValue::Known(v) => Some(Some(v)),
            StorageValue::HashKnownValueMissing(_) => None,
            StorageValue::None => Some(None),
        }
    }

    // TODO: add a ̀`next_key` and a `prefix_keys` function
}

/// Storage value of the node.
#[derive(Debug, Copy, Clone)]
pub enum StorageValue<'a> {
    /// The storage value was found in the proof. Contains the value.
    Known(&'a [u8]),
    /// The hash of the storage value was found, but the un-hashed value wasn't in the proof. This
    /// indicates an incomplete proof.
    HashKnownValueMissing(&'a [u8; 32]),
    /// The node doesn't have a storage value.
    None,
}

/// Possible error returned by [`decode_and_verify_proof`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum Error {
    /// Proof is in an invalid format.
    InvalidFormat,
    /// Trie root wasn't found in the proof.
    TrieRootNotFound,
    /// One of the node values in the proof has an invalid format.
    #[display(fmt = "A node of the proof has an invalid format: {}", _0)]
    InvalidNodeValue(proof_node_codec::Error),
    /// One of the entries of the proof is disconnected from the root node.
    UnusedProofEntry,
    /// The same entry has been found multiple times in the proof.
    DuplicateProofEntry,
}

/// Information about a node of the trie.
pub struct TrieNodeInfo<'a> {
    /// Storage value of the node, if any.
    pub storage_value: StorageValue<'a>,
    /// Which children the node has.
    pub children: Children,
}

/// See [`TrieNodeInfo::children`].
#[derive(Debug, Copy, Clone)]
pub struct Children {
    /// If `(children_bitmap & (1 << n)) == 1` (where `n is in 0..16`), then this node has a
    /// child whose key starts with the key of the parent, followed with
    /// `Nibble::try_from(n).unwrap()`, followed with 0 or more extra nibbles unknown here.
    children_bitmap: u16,
}

impl Children {
    /// Returns `true` if a child in the direction of the given nibble is present.
    pub fn has_child(&self, nibble: nibble::Nibble) -> bool {
        self.children_bitmap & (1 << u8::from(nibble)) != 0
    }

    /// Iterates over all the children of the node. For each child, contains the nibble that must
    /// be appended to the key of the node in order to find the child.
    pub fn next_nibbles(&'_ self) -> impl Iterator<Item = nibble::Nibble> + '_ {
        nibble::all_nibbles().filter(move |n| (self.children_bitmap & (1 << u8::from(*n)) != 0))
    }

    /// Iterators over all the children of the node. Returns an iterator producing one element per
    /// child, where the element is `key` plus the nibble of this child.
    pub fn unfold_append_to_key(
        &'_ self,
        key: Vec<nibble::Nibble>,
    ) -> impl Iterator<Item = Vec<nibble::Nibble>> + '_ {
        nibble::all_nibbles()
            .filter(move |n| (self.children_bitmap & (1 << u8::from(*n)) != 0))
            .map(move |nibble| {
                let mut k = key.clone();
                k.push(nibble);
                k
            })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn empty_is_valid() {
        let _ = super::decode_and_verify_proof(super::Config {
            trie_root_hash: &[0; 32], // Trie root hash doesn't matter.
            proof: &[0],
        })
        .unwrap();
    }

    #[test]
    fn basic_works() {
        // Key/value taken from the Polkadot genesis block.

        let proof = vec![
            24, 212, 125, 1, 84, 37, 150, 173, 176, 93, 97, 64, 193, 112, 172, 71, 158, 223, 124,
            253, 90, 163, 83, 87, 89, 10, 207, 229, 209, 26, 128, 77, 148, 78, 80, 13, 20, 86, 253,
            218, 123, 142, 199, 249, 229, 199, 148, 205, 131, 25, 79, 5, 147, 228, 234, 53, 5, 128,
            63, 147, 128, 78, 76, 108, 66, 34, 183, 71, 229, 7, 0, 142, 241, 222, 240, 99, 187, 13,
            45, 238, 173, 241, 126, 244, 177, 14, 113, 98, 77, 58, 12, 248, 28, 128, 36, 31, 44, 6,
            242, 46, 197, 137, 104, 251, 104, 212, 50, 49, 158, 37, 230, 200, 250, 163, 173, 44,
            92, 169, 238, 72, 242, 232, 237, 21, 142, 36, 128, 173, 138, 104, 35, 73, 50, 38, 152,
            70, 188, 64, 36, 10, 71, 207, 216, 216, 133, 123, 29, 129, 225, 103, 191, 178, 76, 148,
            122, 76, 218, 217, 230, 128, 200, 69, 144, 227, 159, 139, 121, 162, 105, 74, 210, 191,
            126, 114, 88, 175, 104, 107, 71, 47, 56, 176, 100, 187, 206, 125, 8, 64, 73, 49, 164,
            48, 128, 92, 114, 242, 91, 27, 99, 4, 209, 102, 103, 226, 118, 111, 161, 169, 6, 203,
            8, 23, 136, 235, 69, 2, 120, 125, 247, 195, 89, 116, 18, 177, 123, 128, 110, 33, 197,
            241, 162, 74, 25, 102, 21, 180, 229, 179, 109, 33, 40, 12, 220, 200, 0, 152, 193, 226,
            188, 232, 238, 175, 48, 30, 153, 81, 118, 116, 128, 66, 79, 26, 205, 128, 186, 7, 74,
            44, 232, 209, 128, 191, 52, 136, 165, 202, 145, 203, 129, 251, 169, 108, 140, 60, 29,
            51, 234, 203, 177, 129, 96, 128, 94, 132, 157, 92, 20, 140, 163, 97, 165, 90, 44, 155,
            56, 78, 23, 206, 145, 158, 147, 108, 203, 128, 17, 164, 247, 37, 4, 233, 249, 61, 184,
            205, 128, 237, 208, 5, 161, 73, 92, 112, 37, 13, 119, 248, 28, 36, 193, 90, 153, 25,
            240, 52, 247, 152, 61, 248, 229, 5, 229, 58, 90, 247, 180, 2, 19, 128, 18, 160, 221,
            144, 73, 123, 101, 49, 43, 218, 103, 234, 21, 153, 101, 120, 238, 179, 137, 27, 202,
            134, 102, 149, 26, 50, 102, 18, 65, 142, 49, 67, 177, 4, 128, 85, 93, 128, 67, 251, 73,
            124, 27, 42, 123, 158, 79, 235, 89, 244, 16, 193, 162, 158, 40, 178, 166, 40, 255, 156,
            96, 3, 224, 128, 246, 185, 250, 221, 149, 249, 128, 110, 141, 145, 27, 104, 24, 3, 142,
            183, 200, 83, 74, 248, 231, 142, 153, 32, 161, 171, 141, 147, 156, 54, 211, 230, 155,
            10, 30, 89, 40, 17, 11, 128, 186, 77, 63, 84, 57, 87, 244, 34, 180, 12, 142, 116, 175,
            157, 224, 10, 203, 235, 168, 21, 74, 252, 165, 122, 127, 128, 251, 188, 254, 187, 30,
            74, 128, 61, 27, 143, 92, 241, 120, 139, 41, 69, 55, 184, 253, 45, 52, 172, 236, 70,
            70, 167, 98, 124, 108, 211, 210, 3, 154, 246, 79, 245, 209, 151, 109, 128, 231, 98, 15,
            33, 207, 19, 150, 79, 41, 211, 75, 167, 8, 195, 180, 78, 164, 94, 161, 28, 88, 251,
            190, 221, 162, 157, 19, 71, 11, 200, 12, 160, 128, 249, 138, 174, 79, 131, 216, 27,
            241, 93, 136, 1, 158, 92, 48, 61, 124, 25, 208, 82, 78, 132, 199, 20, 224, 95, 97, 81,
            124, 222, 11, 19, 130, 128, 213, 24, 250, 245, 102, 253, 196, 208, 69, 9, 74, 190, 55,
            43, 179, 187, 236, 212, 117, 63, 118, 219, 140, 65, 186, 159, 192, 21, 85, 139, 242,
            58, 128, 144, 143, 153, 17, 38, 209, 44, 231, 172, 213, 85, 8, 255, 30, 125, 255, 165,
            111, 116, 36, 1, 225, 129, 79, 193, 70, 150, 88, 167, 140, 122, 127, 128, 1, 176, 160,
            141, 160, 200, 50, 83, 213, 192, 203, 135, 114, 134, 192, 98, 218, 47, 83, 10, 228, 36,
            254, 37, 69, 55, 121, 65, 253, 1, 105, 19, 53, 5, 128, 179, 167, 128, 162, 159, 172,
            127, 125, 250, 226, 29, 5, 217, 80, 110, 125, 166, 81, 91, 127, 161, 173, 151, 15, 248,
            118, 222, 53, 241, 190, 194, 89, 158, 192, 2, 128, 91, 103, 114, 220, 106, 78, 118, 4,
            200, 208, 101, 36, 121, 249, 91, 52, 54, 7, 194, 217, 19, 140, 89, 238, 183, 153, 216,
            91, 244, 59, 107, 191, 128, 61, 18, 190, 203, 106, 75, 153, 25, 221, 199, 197, 151, 61,
            4, 238, 215, 105, 108, 131, 79, 144, 199, 121, 252, 31, 207, 115, 80, 204, 194, 141,
            107, 128, 95, 51, 235, 207, 25, 31, 221, 207, 59, 63, 52, 110, 195, 54, 193, 5, 199,
            75, 64, 164, 211, 93, 253, 160, 197, 146, 242, 190, 160, 0, 132, 233, 128, 247, 100,
            199, 51, 214, 227, 87, 113, 169, 178, 106, 31, 168, 107, 155, 236, 89, 116, 43, 4, 111,
            105, 139, 230, 193, 64, 175, 16, 115, 137, 125, 61, 128, 205, 59, 200, 195, 206, 60,
            248, 53, 159, 115, 113, 161, 51, 22, 240, 47, 210, 43, 2, 163, 211, 39, 104, 74, 43,
            97, 244, 164, 126, 0, 34, 184, 128, 218, 117, 42, 250, 235, 146, 93, 83, 0, 228, 91,
            133, 16, 82, 197, 248, 169, 197, 170, 232, 132, 241, 93, 100, 118, 78, 223, 150, 27,
            139, 34, 200, 128, 191, 31, 169, 199, 228, 201, 67, 64, 219, 175, 215, 92, 190, 1, 108,
            152, 13, 14, 93, 91, 78, 118, 130, 63, 161, 30, 97, 98, 144, 20, 195, 75, 128, 79, 84,
            161, 94, 93, 81, 208, 43, 132, 232, 202, 233, 76, 152, 51, 174, 129, 229, 107, 143, 11,
            104, 77, 37, 127, 111, 114, 46, 230, 108, 173, 249, 128, 148, 131, 63, 178, 220, 232,
            199, 141, 68, 60, 214, 120, 110, 12, 1, 216, 151, 74, 75, 119, 156, 23, 142, 245, 230,
            107, 73, 224, 33, 221, 127, 26, 225, 2, 159, 12, 93, 121, 93, 2, 151, 190, 86, 2, 122,
            75, 36, 100, 227, 51, 151, 96, 146, 128, 243, 50, 255, 85, 106, 191, 93, 175, 13, 52,
            82, 61, 247, 200, 205, 19, 105, 188, 182, 173, 187, 35, 164, 128, 147, 191, 7, 10, 151,
            17, 191, 52, 128, 56, 41, 52, 19, 74, 169, 25, 181, 156, 22, 255, 141, 232, 217, 122,
            127, 220, 194, 68, 142, 163, 39, 178, 111, 68, 0, 93, 117, 109, 23, 133, 135, 128, 129,
            214, 52, 20, 11, 54, 206, 3, 28, 75, 108, 98, 102, 226, 167, 193, 157, 154, 136, 227,
            143, 221, 138, 210, 58, 189, 61, 178, 14, 113, 79, 105, 128, 253, 225, 112, 65, 242,
            47, 9, 96, 157, 121, 219, 227, 141, 204, 206, 252, 170, 193, 57, 199, 161, 15, 178, 59,
            210, 132, 193, 196, 146, 176, 4, 253, 128, 210, 135, 173, 29, 10, 222, 101, 230, 77,
            57, 105, 244, 171, 133, 163, 112, 118, 129, 96, 49, 67, 140, 234, 11, 248, 195, 59,
            123, 43, 198, 195, 48, 141, 8, 159, 3, 230, 211, 193, 251, 21, 128, 94, 223, 208, 36,
            23, 46, 164, 129, 125, 255, 255, 128, 21, 40, 51, 227, 74, 133, 46, 151, 81, 207, 192,
            249, 84, 174, 184, 53, 225, 248, 67, 147, 107, 169, 151, 152, 83, 164, 14, 67, 153, 55,
            37, 95, 128, 106, 54, 224, 173, 35, 251, 50, 36, 255, 246, 230, 219, 98, 4, 132, 99,
            167, 242, 124, 203, 146, 246, 91, 78, 52, 138, 205, 90, 122, 163, 160, 104, 128, 39,
            182, 224, 153, 193, 21, 129, 251, 46, 138, 207, 59, 107, 148, 234, 237, 68, 34, 119,
            185, 167, 76, 231, 249, 34, 246, 227, 191, 41, 89, 134, 123, 128, 253, 12, 194, 200,
            70, 219, 106, 158, 209, 154, 113, 93, 108, 60, 212, 106, 72, 183, 244, 9, 136, 60, 112,
            178, 212, 201, 120, 179, 6, 222, 55, 158, 128, 171, 0, 138, 120, 195, 64, 245, 204,
            117, 217, 156, 219, 144, 89, 81, 147, 102, 134, 68, 92, 131, 71, 25, 190, 33, 247, 98,
            11, 149, 13, 205, 92, 128, 109, 134, 175, 84, 213, 223, 177, 192, 111, 63, 239, 221,
            90, 67, 8, 97, 192, 209, 158, 37, 250, 212, 186, 208, 124, 110, 112, 212, 166, 121,
            240, 184, 128, 243, 94, 220, 84, 0, 182, 102, 31, 177, 230, 251, 167, 197, 153, 200,
            186, 137, 20, 88, 209, 68, 0, 3, 15, 165, 6, 153, 154, 25, 114, 54, 159, 128, 116, 108,
            218, 160, 183, 218, 46, 156, 56, 100, 151, 31, 80, 241, 45, 155, 66, 129, 248, 4, 213,
            162, 219, 166, 235, 224, 105, 89, 178, 169, 251, 71, 128, 46, 207, 222, 17, 69, 100,
            35, 200, 127, 237, 128, 104, 244, 20, 165, 186, 68, 235, 227, 174, 145, 176, 109, 20,
            204, 35, 26, 120, 212, 171, 166, 142, 128, 246, 85, 41, 24, 51, 164, 156, 242, 61, 5,
            123, 177, 92, 66, 211, 119, 197, 93, 80, 245, 136, 83, 41, 6, 11, 10, 170, 178, 34,
            131, 203, 177, 128, 140, 149, 251, 43, 98, 186, 243, 7, 24, 184, 51, 14, 246, 138, 82,
            124, 151, 193, 188, 153, 96, 48, 67, 83, 34, 77, 138, 138, 232, 138, 121, 213, 128, 69,
            193, 182, 217, 144, 74, 225, 113, 213, 115, 189, 206, 186, 160, 81, 66, 216, 22, 72,
            189, 190, 177, 108, 238, 221, 197, 74, 14, 209, 93, 62, 43, 128, 168, 234, 25, 50, 130,
            254, 133, 182, 72, 23, 7, 9, 28, 119, 201, 33, 142, 161, 157, 233, 20, 231, 89, 80,
            146, 95, 232, 100, 0, 251, 12, 176, 128, 194, 34, 206, 171, 83, 85, 234, 164, 29, 168,
            7, 20, 111, 46, 45, 247, 255, 100, 140, 62, 139, 187, 109, 142, 226, 50, 116, 186, 114,
            69, 81, 177, 128, 8, 241, 66, 220, 60, 89, 191, 17, 81, 200, 41, 236, 239, 234, 53,
            145, 158, 128, 69, 61, 181, 233, 102, 159, 90, 115, 137, 154, 170, 81, 102, 238, 128,
            79, 29, 33, 251, 220, 1, 128, 196, 222, 136, 107, 244, 15, 145, 223, 194, 32, 43, 62,
            182, 212, 37, 72, 212, 118, 144, 128, 65, 221, 97, 123, 184,
        ];

        let trie_root = {
            let bytes =
                hex::decode(&"29d0d972cd27cbc511e9589fcb7a4506d5eb6a9e8df205f00472e5ab354a4e17")
                    .unwrap();
            <[u8; 32]>::try_from(&bytes[..]).unwrap()
        };

        let decoded = super::decode_and_verify_proof(super::Config {
            trie_root_hash: &trie_root,
            proof,
        })
        .unwrap();

        let requested_key = hex::decode("9c5d795d0297be56027a4b2464e3339763e6d3c1fb15805edfd024172ea4817d7081542596adb05d6140c170ac479edf7cfd5aa35357590acfe5d11a804d944e").unwrap();
        let obtained = decoded.storage_value(&requested_key).unwrap();

        assert_eq!(
            obtained,
            Some(&hex::decode("0d1456fdda7b8ec7f9e5c794cd83194f0593e4ea").unwrap()[..])
        );
    }

    #[test]
    fn node_values_smaller_than_32bytes() {
        let proof = vec![
            12, 17, 1, 158, 195, 101, 195, 207, 89, 214, 113, 235, 114, 218, 14, 122, 65, 19, 196,
            0, 3, 88, 95, 7, 141, 67, 77, 97, 37, 180, 4, 67, 254, 17, 253, 41, 45, 19, 164, 16, 2,
            0, 0, 0, 104, 95, 15, 31, 5, 21, 244, 98, 205, 207, 132, 224, 241, 214, 4, 93, 252,
            187, 32, 80, 82, 127, 41, 119, 1, 0, 0, 185, 5, 128, 175, 188, 128, 15, 126, 137, 9,
            189, 204, 29, 117, 244, 124, 194, 9, 181, 214, 119, 106, 91, 55, 85, 146, 101, 112, 37,
            46, 31, 42, 133, 72, 101, 38, 60, 66, 128, 28, 186, 118, 76, 106, 111, 232, 204, 106,
            88, 52, 218, 113, 2, 76, 119, 132, 172, 202, 215, 130, 198, 184, 230, 206, 134, 44,
            171, 25, 86, 243, 121, 128, 233, 10, 145, 50, 95, 100, 17, 213, 147, 28, 9, 142, 56,
            95, 33, 40, 56, 9, 39, 3, 193, 79, 169, 207, 115, 80, 61, 217, 4, 106, 172, 152, 128,
            12, 255, 241, 157, 249, 219, 101, 33, 139, 178, 174, 121, 165, 33, 175, 0, 232, 230,
            129, 23, 89, 219, 21, 35, 23, 48, 18, 153, 124, 96, 81, 66, 128, 30, 174, 194, 227,
            100, 149, 97, 237, 23, 238, 114, 178, 106, 158, 238, 48, 166, 82, 19, 210, 129, 122,
            70, 165, 94, 186, 31, 28, 80, 29, 73, 252, 128, 16, 56, 19, 158, 188, 178, 192, 234,
            12, 251, 221, 107, 119, 243, 74, 155, 111, 53, 36, 107, 183, 204, 174, 253, 183, 67,
            77, 199, 47, 121, 185, 162, 128, 17, 217, 226, 195, 240, 113, 144, 201, 129, 184, 240,
            237, 204, 79, 68, 191, 165, 29, 219, 170, 152, 134, 160, 153, 245, 38, 181, 131, 83,
            209, 245, 194, 128, 137, 217, 3, 84, 1, 224, 52, 199, 112, 213, 150, 42, 51, 214, 103,
            194, 225, 224, 210, 84, 84, 53, 31, 159, 82, 201, 3, 104, 118, 212, 110, 7, 128, 240,
            251, 81, 190, 126, 80, 60, 139, 88, 152, 39, 153, 231, 178, 31, 184, 56, 44, 133, 31,
            47, 98, 234, 107, 15, 248, 64, 78, 36, 89, 9, 149, 128, 233, 75, 238, 120, 212, 149,
            223, 135, 48, 174, 211, 219, 223, 217, 20, 172, 212, 172, 3, 234, 54, 130, 55, 225, 63,
            17, 255, 217, 150, 252, 93, 15, 128, 89, 54, 254, 99, 202, 80, 50, 27, 92, 48, 57, 174,
            8, 211, 44, 58, 108, 207, 129, 245, 129, 80, 170, 57, 130, 80, 166, 250, 214, 40, 156,
            181, 21, 1, 128, 65, 0, 128, 182, 204, 71, 61, 83, 76, 85, 166, 19, 22, 212, 242, 236,
            229, 51, 88, 16, 191, 227, 125, 217, 54, 7, 31, 36, 176, 211, 111, 72, 220, 181, 241,
            128, 149, 2, 12, 26, 95, 9, 193, 115, 207, 253, 90, 218, 0, 41, 140, 119, 189, 166,
            101, 244, 74, 171, 53, 248, 82, 113, 79, 110, 25, 72, 62, 65,
        ];

        let trie_root = [
            43, 100, 198, 174, 1, 66, 26, 95, 93, 119, 43, 242, 5, 176, 153, 134, 193, 74, 159,
            215, 134, 15, 252, 135, 67, 129, 21, 16, 20, 211, 97, 217,
        ];

        let decoded = super::decode_and_verify_proof(super::Config {
            trie_root_hash: &trie_root,
            proof,
        })
        .unwrap();

        let requested_key =
            hex::decode("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb")
                .unwrap();
        let obtained = decoded.storage_value(&requested_key).unwrap();

        assert_eq!(obtained, Some(&[80, 82, 127, 41, 119, 1, 0, 0][..]));
    }
}
