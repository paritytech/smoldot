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

use super::{TrieEntryVersion, nibble, trie_node};

use alloc::vec::Vec;
use core::{fmt, iter, ops};

mod tests;

/// Configuration to pass to [`decode_and_verify_proof`].
pub struct Config<I> {
    /// List of node values of nodes found in the trie. At least one entry corresponding to the
    /// root node of the trie must be present in order for the verification to succeed.
    pub proof: I,
}

/// Proof is in an invalid format.
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub struct ParseError();

/// Decomposes the given proof into its entries.
///
/// Each entry is a node value.
///
/// Doesn't verify anything about the proof except that it can be decomposed into entries.
pub fn decode_proof(proof: &[u8]) -> Result<impl ExactSizeIterator<Item = &[u8]>, ParseError> {
    // TODO: don't use Vec?
    let (_, decoded_proof) = nom::Parser::parse(
        &mut nom::combinator::all_consuming(nom::combinator::flat_map(
            crate::util::nom_scale_compact_usize,
            |num_elems| nom::multi::many_m_n(num_elems, num_elems, crate::util::nom_bytes_decode),
        )),
        proof,
    )
    .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| ParseError())?;
    Ok(decoded_proof.into_iter())
}

/// Verifies whether a proof is correct and returns an object that allows examining its content.
///
/// The proof is then stored within the [`DecodedTrieProof`].
///
/// Due to the generic nature of this function, the proof can be either a `Vec<u8>` or a `&[u8]`.
///
/// Returns an error if the proof is invalid, or if the proof contains entries that are
/// disconnected from the root node of the trie.
pub fn decode_and_verify_proof<T>(config: Config<T>) -> Result<DecodedTrieProof<T>, Error>
where
    T: AsRef<[u8]>,
{
    // Call `as_ref()` once at the beginning in order to guarantee stability of the memory
    // location.
    let proof_as_ref = config.proof.as_ref();

    struct InProgressEntry<'a> {
        index_in_proof: usize,
        range_in_proof: ops::Range<usize>,
        decode_result: Result<
            trie_node::Decoded<'a, trie_node::DecodedPartialKey<'a>, &'a [u8]>,
            trie_node::Error,
        >,
    }

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
    let entries_by_merkle_value = {
        let decoded_proof = decode_proof(proof_as_ref).map_err(Error::InvalidFormat)?;
        let decoded_proof_len = decoded_proof.len();

        let entries_by_merkle_value = decoded_proof
            .enumerate()
            .map(
                |(proof_entry_num, proof_entry)| -> ([u8; 32], InProgressEntry) {
                    // The merkle value of a trie node is normally either its hash or the node
                    // itself if its length is < 32. In the context of a proof, however, nodes
                    // whose length is < 32 aren't supposed to be their own entry. For this reason,
                    // we only hash each entry.
                    let hash = *<&[u8; 32]>::try_from(
                        blake2_rfc::blake2b::blake2b(32, &[], proof_entry).as_bytes(),
                    )
                    .unwrap();

                    let proof_entry_offset = if proof_entry.is_empty() {
                        0
                    } else {
                        proof_entry.as_ptr() as usize - proof_as_ref.as_ptr() as usize
                    };

                    (
                        hash,
                        InProgressEntry {
                            index_in_proof: proof_entry_num,
                            range_in_proof: proof_entry_offset
                                ..(proof_entry_offset + proof_entry.len()),
                            decode_result: trie_node::decode(proof_entry),
                        },
                    )
                },
            )
            .collect::<hashbrown::HashMap<_, _, fnv::FnvBuildHasher>>();

        // Using a hashmap has the consequence that if multiple proof entries were identical, only
        // one would be tracked. This allows us to make sure that the proof doesn't contain
        // multiple identical entries.
        if entries_by_merkle_value.len() != decoded_proof_len {
            return Err(Error::DuplicateProofEntry);
        }

        entries_by_merkle_value
    };

    // Start by iterating over each element of the proof, and keep track of elements that are
    // decodable but aren't mentioned in any other element. This gives us the tries roots.
    let trie_roots = {
        let mut maybe_trie_roots = entries_by_merkle_value
            .keys()
            .collect::<hashbrown::HashSet<_, fnv::FnvBuildHasher>>();
        for (hash, InProgressEntry { decode_result, .. }) in entries_by_merkle_value.iter() {
            let Ok(decoded) = decode_result else {
                maybe_trie_roots.remove(hash);
                continue;
            };
            for child in decoded.children.into_iter().flatten() {
                if let Ok(child) = &<[u8; 32]>::try_from(child) {
                    maybe_trie_roots.remove(child);
                }
            }
        }
        maybe_trie_roots
    };

    // The implementation below iterates down the tree of nodes represented by this proof, keeping
    // note of the traversed elements.

    // Keep track of all the entries found in the proof.
    let mut entries: Vec<Entry> = Vec::with_capacity(entries_by_merkle_value.len());

    let mut trie_roots_with_entries =
        hashbrown::HashMap::with_capacity_and_hasher(trie_roots.len(), Default::default());

    // Keep track of the proof entries that haven't been visited when traversing.
    let mut unvisited_proof_entries =
        (0..entries_by_merkle_value.len()).collect::<hashbrown::HashSet<_, fnv::FnvBuildHasher>>();

    // We repeat this operation for every trie root.
    for trie_root_hash in trie_roots {
        struct StackEntry<'a> {
            range_in_proof: ops::Range<usize>,
            index_in_entries: usize,
            num_visited_children: u8,
            children_node_values: [Option<&'a [u8]>; 16],
        }

        // Keep track of the number of entries before this trie root.
        // This allows us to truncate `entries` to this value in case of decoding failure.
        let num_entries_before_current_trie_root = entries.len();

        // Keep track of the indices of the proof entries that are visited when traversing this trie.
        let mut visited_proof_entries_during_trie =
            Vec::with_capacity(entries_by_merkle_value.len());

        // TODO: configurable capacity?
        let mut visited_entries_stack: Vec<StackEntry> = Vec::with_capacity(24);

        loop {
            // Find which node to visit next.
            // This is the next child of the node at the top of the stack, or if the node at
            // the top of the stack doesn't have any child, we pop it and continue iterating.
            // If the stack is empty, we are necessarily at the first iteration.
            let (visited_node_entry_range, visited_node_decoded) =
                match visited_entries_stack.last_mut() {
                    None => {
                        // Stack is empty.
                        // Because we immediately `break` after popping the last element, the stack
                        // can only ever be empty at the very start.
                        let InProgressEntry {
                            index_in_proof: root_position,
                            range_in_proof: root_range,
                            decode_result,
                        } = entries_by_merkle_value.get(&trie_root_hash[..]).unwrap();
                        visited_proof_entries_during_trie.push(*root_position);
                        // If the node can't be decoded, we ignore the entire trie and jump
                        // to the next one.
                        let Ok(decoded) = decode_result.clone() else {
                            debug_assert_eq!(num_entries_before_current_trie_root, entries.len());
                            break;
                        };
                        (root_range.clone(), decoded)
                    }
                    Some(StackEntry {
                        num_visited_children: stack_top_visited_children,
                        ..
                    }) if *stack_top_visited_children == 16 => {
                        // We have visited all the children of the top of the stack. Pop the node from
                        // the stack.
                        let Some(StackEntry {
                            index_in_entries: stack_top_index_in_entries,
                            ..
                        }) = visited_entries_stack.pop()
                        else {
                            unreachable!()
                        };

                        // Update the value of `child_entries_follow_up`
                        // and `children_present_in_proof_bitmap` of the parent.
                        if let Some(&StackEntry {
                            index_in_entries: parent_index_in_entries,
                            num_visited_children: parent_children_visited,
                            ..
                        }) = visited_entries_stack.last()
                        {
                            entries[parent_index_in_entries].child_entries_follow_up +=
                                entries[stack_top_index_in_entries].child_entries_follow_up + 1;
                            entries[parent_index_in_entries].children_present_in_proof_bitmap |=
                                1 << (parent_children_visited - 1);
                        }

                        // If we popped the last node of the stack, we have finished the iteration.
                        if visited_entries_stack.is_empty() {
                            trie_roots_with_entries
                                .insert(*trie_root_hash, num_entries_before_current_trie_root);
                            // Remove the visited entries from `unvisited_proof_entries`.
                            // Note that it is questionable what to do if the same entry is visited
                            // multiple times. In case where multiple storage branches are identical,
                            // the sender of the proof should de-duplicate the identical nodes. For
                            // this reason, it could be legitimate for the same proof entry to be
                            // visited multiple times.
                            for entry_num in visited_proof_entries_during_trie {
                                unvisited_proof_entries.remove(&entry_num);
                            }
                            break;
                        } else {
                            continue;
                        }
                    }
                    Some(StackEntry {
                        range_in_proof: stack_top_proof_range,
                        num_visited_children: stack_top_visited_children,
                        children_node_values: stack_top_children,
                        ..
                    }) => {
                        // Find the next child of the top of the stack.
                        let stack_top_entry = &proof_as_ref[stack_top_proof_range.clone()];

                        // Find the index of the next child (that we are about to visit).
                        let next_child_to_visit = stack_top_children
                            .iter()
                            .skip(usize::from(*stack_top_visited_children))
                            .position(|c| c.is_some())
                            .map(|idx| u8::try_from(idx).unwrap() + *stack_top_visited_children)
                            .unwrap_or(16);

                        // `continue` if all children have been visited. The next iteration will
                        // pop the stack entry.
                        if next_child_to_visit == 16 {
                            *stack_top_visited_children = 16;
                            continue;
                        }
                        *stack_top_visited_children = next_child_to_visit + 1;

                        // The value of the child node is either directly inlined (if less
                        // than 32 bytes) or is a hash.
                        let child_node_value =
                            stack_top_children[usize::from(next_child_to_visit)].unwrap();
                        debug_assert!(child_node_value.len() <= 32); // Guaranteed by decoding API.
                        if child_node_value.len() < 32 {
                            let offset = stack_top_proof_range.start
                                + if !child_node_value.is_empty() {
                                    child_node_value.as_ptr() as usize
                                        - stack_top_entry.as_ptr() as usize
                                } else {
                                    0
                                };
                            debug_assert!(offset == 0 || offset >= stack_top_proof_range.start);
                            debug_assert!(
                                offset <= (stack_top_proof_range.start + stack_top_entry.len())
                            );

                            let child_range_in_proof = offset..(offset + child_node_value.len());

                            // Decodes the child.
                            // If the node can't be decoded, we ignore the entire trie and jump
                            // to the next one.
                            let Ok(child_decoded) =
                                trie_node::decode(&proof_as_ref[child_range_in_proof.clone()])
                            else {
                                entries.truncate(num_entries_before_current_trie_root);
                                break;
                            };

                            (child_range_in_proof, child_decoded)
                        } else if let Some(&InProgressEntry {
                            index_in_proof: child_position,
                            range_in_proof: ref child_entry_range,
                            ref decode_result,
                        }) = entries_by_merkle_value.get(child_node_value)
                        {
                            // If the node value of the child is less than 32 bytes long, it should
                            // have been inlined instead of given separately.
                            if child_entry_range.end - child_entry_range.start < 32 {
                                entries.truncate(num_entries_before_current_trie_root);
                                break;
                            }

                            visited_proof_entries_during_trie.push(child_position);

                            // If the node can't be decoded, we ignore the entire trie and jump
                            // to the next one.
                            let Ok(decoded) = decode_result.clone() else {
                                entries.truncate(num_entries_before_current_trie_root);
                                break;
                            };
                            (child_entry_range.clone(), decoded)
                        } else {
                            // Child is a hash that was not found in the proof. Simply continue
                            // iterating, in order to try to find the follow-up child.
                            continue;
                        }
                    }
                };

            // All nodes must either have a child or a storage value or be the root.
            if visited_node_decoded.children_bitmap() == 0
                && matches!(
                    visited_node_decoded.storage_value,
                    trie_node::StorageValue::None
                )
                && !visited_entries_stack.is_empty()
            {
                entries.truncate(num_entries_before_current_trie_root);
                break;
            }

            // Nodes with no storage value and one children are forbidden.
            if visited_node_decoded
                .children
                .iter()
                .filter(|c| c.is_some())
                .count()
                == 1
                && matches!(
                    visited_node_decoded.storage_value,
                    trie_node::StorageValue::None
                )
            {
                entries.truncate(num_entries_before_current_trie_root);
                break;
            }

            // Add an entry for this node in the final list of entries.
            entries.push(Entry {
                parent_entry_index: visited_entries_stack.last().map(|entry| {
                    (
                        entry.index_in_entries,
                        nibble::Nibble::try_from(entry.num_visited_children - 1).unwrap(),
                    )
                }),
                range_in_proof: visited_node_entry_range.clone(),
                storage_value_in_proof: match visited_node_decoded.storage_value {
                    trie_node::StorageValue::None => None,
                    trie_node::StorageValue::Hashed(value_hash) => {
                        if let Some(&InProgressEntry {
                            index_in_proof: value_position,
                            range_in_proof: ref value_entry_range,
                            ..
                        }) = entries_by_merkle_value.get(&value_hash[..])
                        {
                            visited_proof_entries_during_trie.push(value_position);
                            Some(value_entry_range.clone())
                        } else {
                            None
                        }
                    }
                    trie_node::StorageValue::Unhashed(v) => {
                        let offset = if !v.is_empty() {
                            v.as_ptr() as usize - proof_as_ref.as_ptr() as usize
                        } else {
                            0
                        };
                        debug_assert!(offset == 0 || offset >= visited_node_entry_range.start);
                        debug_assert!(offset <= visited_node_entry_range.end);
                        Some(offset..offset + v.len())
                    }
                },
                child_entries_follow_up: 0,          // Filled later.
                children_present_in_proof_bitmap: 0, // Filled later.
            });

            // Add the visited node to the stack. The next iteration will either go to its first
            // child, or pop the node from the stack.
            visited_entries_stack.push(StackEntry {
                range_in_proof: visited_node_entry_range,
                index_in_entries: entries.len() - 1,
                num_visited_children: 0,
                children_node_values: visited_node_decoded.children,
            });
        }
    }

    // The entire reason why we track the unvisited proof entries is to return this error if
    // necessary.
    if !unvisited_proof_entries.is_empty() {
        return Err(Error::UnusedProofEntry);
    }

    drop(entries_by_merkle_value);
    Ok(DecodedTrieProof {
        proof: config.proof,
        entries,
        trie_roots: trie_roots_with_entries,
    })
}

/// Decoded Merkle proof. The proof is guaranteed valid.
pub struct DecodedTrieProof<T> {
    /// The proof itself.
    proof: T,

    /// All entries in the proof, in lexicographic order. Ordering between trie roots is
    /// unspecified.
    entries: Vec<Entry>,

    ///
    /// Given that hashes are verified to actually match their values, there is no risk of
    /// HashDoS attack.
    // TODO: is that true? ^ depends on whether there are a lot of storage values
    trie_roots: hashbrown::HashMap<[u8; 32], usize, fnv::FnvBuildHasher>,
}

struct Entry {
    /// Index within [`DecodedTrieProof::entries`] of the parent of this entry and child direction
    /// nibble, or `None` if it is the root.
    parent_entry_index: Option<(usize, nibble::Nibble)>,

    /// Range within [`DecodedTrieProof::proof`] of the node value of this entry.
    range_in_proof: ops::Range<usize>,

    /// Range within [`DecodedTrieProof::proof`] of the unhashed storage value of this entry.
    /// `None` if the entry doesn't have any storage entry or if it's missing from the proof.
    storage_value_in_proof: Option<ops::Range<usize>>,

    // TODO: doc
    children_present_in_proof_bitmap: u16,

    /// Given an entry of index `N`, it is always followed with `k` entries that correspond to the
    /// sub-tree of that entry, where `k` is equal to [`Entry::child_entries_follow_up`]. In order
    /// to jump to the next sibling of that entry, jump to `N + 1 + k`. If `k` is non-zero, then
    /// entry `N + 1` corresponds to the first child of the entry of index `N`.
    child_entries_follow_up: usize,
    // TODO: by adding the partial key, we should be able to avoid decoding the entry while iterating down the trie
}

impl<T: AsRef<[u8]>> fmt::Debug for DecodedTrieProof<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map()
            .entries(self.iter_ordered().map(
                |(
                    EntryKey {
                        trie_root_hash,
                        key,
                    },
                    entry,
                )| {
                    struct DummyHash<'a>(&'a [u8]);
                    impl<'a> fmt::Debug for DummyHash<'a> {
                        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                            if self.0.is_empty() {
                                write!(f, "∅")?
                            }
                            for byte in self.0 {
                                write!(f, "{:02x}", *byte)?
                            }
                            Ok(())
                        }
                    }

                    struct DummyNibbles<'a, T: AsRef<[u8]>>(EntryKeyIter<'a, T>);
                    impl<'a, T: AsRef<[u8]>> fmt::Debug for DummyNibbles<'a, T> {
                        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                            let mut any_written = false;
                            for nibble in self.0.clone() {
                                any_written = true;
                                write!(f, "{:x}", nibble)?
                            }
                            if !any_written {
                                write!(f, "∅")?
                            }
                            Ok(())
                        }
                    }

                    (
                        (DummyHash(trie_root_hash), DummyNibbles(key)),
                        (
                            entry.trie_node_info.children,
                            entry.trie_node_info.storage_value,
                        ),
                    )
                },
            ))
            .finish()
    }
}

/// Identifier for an entry within a decoded proof.
pub struct EntryKey<'a, K> {
    /// Hash of the root of the trie the key is in.
    pub trie_root_hash: &'a [u8; 32],
    /// The trie node key.
    pub key: K,
}

impl<T: AsRef<[u8]>> DecodedTrieProof<T> {
    /// Returns a list of all elements of the proof, ordered by key in lexicographic order.
    ///
    /// This function is a convenient wrapper around [`DecodedTrieProof::iter_ordered`] that
    /// converts the keys into arrays of bytes. If a key can't be represented as an array of
    /// bytes, then it is filtered out. Assuming that the trie has only ever been used in the
    /// context of the runtime, then this cannot happen. See the section below for an
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
    // TODO: paragraph below not true anymore
    /// However, given that [`decode_and_verify_proof`] verifies the trie proof against the state
    /// trie root hash, we are also guaranteed that this proof reflects the actual trie. If the
    /// actual trie can't contain any storage value at a key that consists in an uneven number of
    /// nibbles, then the proof is also guaranteed to not contain any storage value at a key that
    /// consists in an uneven number of nibbles. Importantly, this is only true if we are sure that
    /// the block is valid, in other words that it has indeed been created using a runtime. Blocks
    /// that are invalid might have been created through a fake trie.
    ///
    /// As a conclusion, if this proof is made against a trie that has only ever been used in the
    /// context of a runtime, and that the block using this trie is guaranteed to be valid, then
    /// this function will work as intended and return the entire content of the proof.
    ///
    // TODO: ordering between trie roots unspecified
    // TODO: consider not returning a Vec
    pub fn iter_runtime_context_ordered(
        &'_ self,
    ) -> impl Iterator<Item = (EntryKey<'_, Vec<u8>>, StorageValue<'_>)> {
        self.iter_ordered().filter_map(
            |(
                EntryKey {
                    trie_root_hash,
                    key,
                },
                entry,
            )| {
                let value = entry.trie_node_info.storage_value;

                if key.clone().count() % 2 != 0 {
                    return None;
                }

                let key = nibble::nibbles_to_bytes_suffix_extend(key).collect();
                Some((
                    EntryKey {
                        trie_root_hash,
                        key,
                    },
                    value,
                ))
            },
        )
    }

    /// Returns a list of all elements of the proof, ordered by key in lexicographic order.
    ///
    /// The iterator includes branch nodes.
    // TODO: ordering between trie roots unspecified
    pub fn iter_ordered(
        &self,
    ) -> impl Iterator<Item = (EntryKey<'_, EntryKeyIter<'_, T>>, ProofEntry<'_, T>)> {
        self.trie_roots
            .iter()
            .flat_map(|(trie_root_hash, &trie_root_entry_index)| {
                (0..=self.entries[trie_root_entry_index].child_entries_follow_up)
                    .map(move |idx| idx + trie_root_entry_index)
                    .map(|entry_index| {
                        (
                            EntryKey {
                                trie_root_hash,
                                key: EntryKeyIter::new(self, entry_index),
                            },
                            self.build_proof_entry(trie_root_hash, entry_index),
                        )
                    })
            })
    }

    /// Returns the [`ProofEntry`] of the given proof entry.
    ///
    /// # Panic
    ///
    /// Panics if `entry_index` is out of range.
    ///
    fn build_proof_entry<'a>(
        &'a self,
        trie_root_hash: &'a [u8; 32],
        entry_index: usize,
    ) -> ProofEntry<'a, T> {
        let proof = self.proof.as_ref();

        let entry = &self.entries[entry_index];

        let Ok(entry_index_decoded) = trie_node::decode(&proof[entry.range_in_proof.clone()])
        else {
            // Proof has been checked to be entirely decodable.
            unreachable!()
        };

        ProofEntry {
            merkle_value: if let Some((parent_index, parent_nibble)) =
                self.entries[entry_index].parent_entry_index
            {
                let Ok(parent_decoded) =
                    trie_node::decode(&proof[self.entries[parent_index].range_in_proof.clone()])
                else {
                    // Proof has been checked to be entirely decodable.
                    unreachable!()
                };
                parent_decoded.children[usize::from(parent_nibble)]
                    .as_ref()
                    .unwrap()
            } else {
                trie_root_hash
            },
            node_value: &self.proof.as_ref()[entry.range_in_proof.clone()],
            partial_key_nibbles: entry_index_decoded.partial_key,
            unhashed_storage_value: entry
                .storage_value_in_proof
                .as_ref()
                .map(|range| &proof[range.clone()]),
            trie_node_info: TrieNodeInfo {
                children: Children {
                    children: {
                        let mut children = core::array::from_fn(|_| Child::NoChild);
                        let mut i = entry_index + 1;
                        for child_num in 0..16 {
                            let Some(child_merkle_value) = entry_index_decoded.children[child_num]
                            else {
                                continue;
                            };
                            if entry.children_present_in_proof_bitmap & (1 << child_num) != 0 {
                                children[child_num] = Child::InProof {
                                    child_key: EntryKeyIter::new(self, i),
                                    merkle_value: child_merkle_value,
                                };
                                i += self.entries[i].child_entries_follow_up;
                                i += 1;
                            } else {
                                children[child_num] = Child::AbsentFromProof {
                                    merkle_value: child_merkle_value,
                                };
                            }
                        }
                        children
                    },
                },
                storage_value: match (
                    entry_index_decoded.storage_value,
                    &entry.storage_value_in_proof,
                ) {
                    (trie_node::StorageValue::Unhashed(value), _) => StorageValue::Known {
                        value,
                        inline: true,
                    },
                    (trie_node::StorageValue::Hashed(_), Some(value_range)) => {
                        StorageValue::Known {
                            value: &proof[value_range.clone()],
                            inline: false,
                        }
                    }
                    (trie_node::StorageValue::Hashed(hash), None) => {
                        StorageValue::HashKnownValueMissing(hash)
                    }
                    (trie_node::StorageValue::None, _v) => {
                        debug_assert!(_v.is_none());
                        StorageValue::None
                    }
                },
            },
        }
    }

    /// Returns the [`ProofEntry`] of the proof entry whose Merkle value is given as parameter.
    ///
    /// The returned [`ProofEntry`] is guaranteed to have no parent.
    ///
    /// Returns `None` if the proof doesn't contain any sub-trie with the given Merkle value.
    pub fn trie_root_proof_entry<'a>(
        &'a self,
        trie_root_merkle_value: &'a [u8; 32],
    ) -> Option<ProofEntry<'a, T>> {
        let entry_index = *self.trie_roots.get(trie_root_merkle_value)?;
        Some(self.build_proof_entry(trie_root_merkle_value, entry_index))
    }

    /// Returns the [`ProofEntry`] of the given key.
    ///
    /// Returns `None` if the key doesn't have any entry in the proof.
    ///
    /// > **Note**: In situations where the key isn't in the proof but the proof contains enough
    /// >           information about the trie in order to infer some information about that key,
    /// >           the [`DecodedTrieProof::trie_node_info`] function will be successful whereas
    /// >           the [`DecodedTrieProof::proof_entry`] function will fail.
    pub fn proof_entry<'a>(
        &'a self,
        trie_root_merkle_value: &'a [u8; 32],
        key: impl Iterator<Item = nibble::Nibble>,
    ) -> Option<ProofEntry<'a, T>> {
        let (entry_index, exact_match) = self
            .closest_ancestor_in_proof_entry(trie_root_merkle_value, key)
            .ok()
            .flatten()?;

        if !exact_match {
            return None;
        }

        Some(self.build_proof_entry(trie_root_merkle_value, entry_index))
    }

    /// Returns the key of the closest ancestor to the given key that can be found in the proof.
    /// If `key` is in the proof, returns `key`.
    ///
    /// Returns `None` if the key is completely outside of the trie (i.e. the trie root is not
    /// an ancestor of the key).
    pub fn closest_ancestor_in_proof<'a>(
        &'a self,
        trie_root_merkle_value: &[u8; 32],
        key: impl Iterator<Item = nibble::Nibble>,
    ) -> Result<Option<EntryKeyIter<'a, T>>, IncompleteProofError> {
        Ok(self
            .closest_ancestor_in_proof_entry(trie_root_merkle_value, key)?
            .map(|(idx, _)| EntryKeyIter::new(self, idx)))
    }

    /// Same as [`DecodedTrieProof::closest_ancestor_in_proof`], but returns the entry index
    /// instead of its key.
    ///
    /// In addition to the entry index, also returns whether there was an exact match.
    fn closest_ancestor_in_proof_entry<'a>(
        &'a self,
        trie_root_merkle_value: &[u8; 32],
        mut key: impl Iterator<Item = nibble::Nibble>,
    ) -> Result<Option<(usize, bool)>, IncompleteProofError> {
        let proof = self.proof.as_ref();

        // If the proof doesn't contain any entry for the requested trie, then we have no
        // information about the node whatsoever.
        // This check is necessary because we assume below that a lack of ancestor means that the
        // key is outside of the trie.
        let Some(&(mut iter_entry)) = self.trie_roots.get(trie_root_merkle_value) else {
            return Err(IncompleteProofError());
        };

        loop {
            let Ok(iter_entry_decoded) =
                trie_node::decode(&proof[self.entries[iter_entry].range_in_proof.clone()])
            else {
                unreachable!()
            };

            let mut iter_entry_partial_key_iter = iter_entry_decoded.partial_key;
            loop {
                match (key.next(), iter_entry_partial_key_iter.next()) {
                    (Some(a), Some(b)) if a == b => {}
                    (_, Some(_)) => {
                        // Mismatch in partial key. Closest ancestor is the parent entry.
                        let Some((parent_entry, _)) = self.entries[iter_entry].parent_entry_index
                        else {
                            // Key is completely outside of the trie.
                            return Ok(None);
                        };
                        return Ok(Some((parent_entry, false)));
                    }
                    (Some(child_num), None) => {
                        if let Some(_) = iter_entry_decoded.children[usize::from(child_num)] {
                            // Key points to child. Update `iter_entry` and continue.
                            let children_present_in_proof_bitmap =
                                self.entries[iter_entry].children_present_in_proof_bitmap;

                            // If the child isn't present in the proof, then the proof is
                            // incomplete.
                            if children_present_in_proof_bitmap & (1 << u8::from(child_num)) == 0 {
                                return Err(IncompleteProofError());
                            }

                            for c in 0..u8::from(child_num) {
                                if children_present_in_proof_bitmap & (1 << c) != 0 {
                                    iter_entry += 1;
                                    iter_entry += self.entries[iter_entry].child_entries_follow_up;
                                }
                            }
                            iter_entry += 1;
                        } else {
                            // Key points to non-existing child. Closest ancestor is `iter_entry`.
                            return Ok(Some((iter_entry, false)));
                        }
                        break;
                    }
                    (None, None) => {
                        // Exact match. Closest ancestor is `iter_entry`.
                        return Ok(Some((iter_entry, true)));
                    }
                }
            }
        }
    }

    /// Returns information about a trie node.
    ///
    /// Returns an error if the proof doesn't contain enough information about this trie node.
    ///
    /// This function will return `Ok` even if there is no node in the trie for `key`, in which
    /// case the returned [`TrieNodeInfo`] will indicate no storage value and no children.
    pub fn trie_node_info(
        &self,
        trie_root_merkle_value: &[u8; 32],
        mut key: impl Iterator<Item = nibble::Nibble>,
    ) -> Result<TrieNodeInfo<'_, T>, IncompleteProofError> {
        let proof = self.proof.as_ref();

        // Find the starting point of the requested trie.
        let Some((mut iter_entry_merkle_value, mut iter_entry)) = self
            .trie_roots
            .get_key_value(trie_root_merkle_value)
            .map(|(k, v)| (&k[..], *v))
        else {
            return Err(IncompleteProofError());
        };

        loop {
            let Ok(iter_entry_decoded) =
                trie_node::decode(&proof[self.entries[iter_entry].range_in_proof.clone()])
            else {
                // Proof has been checked to be entirely decodable.
                unreachable!()
            };

            let mut iter_entry_partial_key_iter = iter_entry_decoded.partial_key;
            loop {
                match (key.next(), iter_entry_partial_key_iter.next()) {
                    (Some(a), Some(b)) if a == b => {}
                    (Some(_), Some(_)) => {
                        // Mismatch in partial key. No node with the requested key in the trie.
                        return Ok(TrieNodeInfo {
                            storage_value: StorageValue::None,
                            children: Children {
                                children: core::array::from_fn(|_| Child::NoChild),
                            },
                        });
                    }
                    (None, Some(a)) => {
                        // Input key is a subslice of `iter_entry`'s key.
                        // One has one descendant that is `iter_entry`.
                        let mut children = core::array::from_fn(|_| Child::NoChild);
                        children[usize::from(a)] = Child::InProof {
                            child_key: EntryKeyIter::new(self, iter_entry),
                            merkle_value: iter_entry_merkle_value,
                        };
                        return Ok(TrieNodeInfo {
                            storage_value: StorageValue::None,
                            children: Children { children },
                        });
                    }
                    (Some(child_num), None) => {
                        if let Some(child) = iter_entry_decoded.children[usize::from(child_num)] {
                            // Key points in the direction of a child.
                            let children_present_in_proof_bitmap =
                                self.entries[iter_entry].children_present_in_proof_bitmap;

                            // If the child isn't present in the proof, then the proof is
                            // incomplete.
                            if children_present_in_proof_bitmap & (1 << u8::from(child_num)) == 0 {
                                return Err(IncompleteProofError());
                            }

                            // Child is present in the proof. Update `iter_entry` and continue.
                            iter_entry_merkle_value = child;
                            for c in 0..u8::from(child_num) {
                                if children_present_in_proof_bitmap & (1 << c) != 0 {
                                    iter_entry += 1;
                                    iter_entry += self.entries[iter_entry].child_entries_follow_up;
                                }
                            }
                            iter_entry += 1;
                            break;
                        } else {
                            // Key points to non-existing child.
                            return Ok(TrieNodeInfo {
                                storage_value: StorageValue::None,
                                children: Children {
                                    children: core::array::from_fn(|_| Child::NoChild),
                                },
                            });
                        }
                    }
                    (None, None) => {
                        // Exact match. Trie node is `iter_entry`.
                        return Ok(TrieNodeInfo {
                            storage_value: match (
                                iter_entry_decoded.storage_value,
                                &self.entries[iter_entry].storage_value_in_proof,
                            ) {
                                (trie_node::StorageValue::Unhashed(value), _) => {
                                    StorageValue::Known {
                                        value,
                                        inline: true,
                                    }
                                }
                                (trie_node::StorageValue::Hashed(_), Some(value_range)) => {
                                    StorageValue::Known {
                                        value: &proof[value_range.clone()],
                                        inline: false,
                                    }
                                }
                                (trie_node::StorageValue::Hashed(hash), None) => {
                                    StorageValue::HashKnownValueMissing(hash)
                                }
                                (trie_node::StorageValue::None, _v) => {
                                    debug_assert!(_v.is_none());
                                    StorageValue::None
                                }
                            },
                            children: Children {
                                children: {
                                    let mut children = core::array::from_fn(|_| Child::NoChild);
                                    let mut i = iter_entry + 1;
                                    for child_num in 0..16 {
                                        let Some(child_merkle_value) =
                                            iter_entry_decoded.children[child_num]
                                        else {
                                            continue;
                                        };
                                        if self.entries[iter_entry].children_present_in_proof_bitmap
                                            & (1 << child_num)
                                            != 0
                                        {
                                            children[child_num] = Child::InProof {
                                                child_key: EntryKeyIter::new(self, i),
                                                merkle_value: child_merkle_value,
                                            };
                                            i += self.entries[i].child_entries_follow_up;
                                            i += 1;
                                        } else {
                                            children[child_num] = Child::AbsentFromProof {
                                                merkle_value: child_merkle_value,
                                            };
                                        }
                                    }
                                    children
                                },
                            },
                        });
                    }
                }
            }
        }
    }

    /// Queries from the proof the storage value at the given key.
    ///
    /// Returns an error if the storage value couldn't be determined from the proof. Returns
    /// `Ok(None)` if the storage value is known to have no value.
    ///
    /// > **Note**: This function is a convenient wrapper around
    /// >           [`DecodedTrieProof::trie_node_info`].
    // TODO: accept param as iterator rather than slice?
    pub fn storage_value(
        &self,
        trie_root_merkle_value: &[u8; 32],
        key: &[u8],
    ) -> Result<Option<(&[u8], TrieEntryVersion)>, IncompleteProofError> {
        match self
            .trie_node_info(
                trie_root_merkle_value,
                nibble::bytes_to_nibbles(key.iter().copied()),
            )?
            .storage_value
        {
            StorageValue::Known { value, inline } => Ok(Some((
                value,
                if inline {
                    TrieEntryVersion::V0
                } else {
                    TrieEntryVersion::V1
                },
            ))),
            StorageValue::HashKnownValueMissing(_) => Err(IncompleteProofError()),
            StorageValue::None => Ok(None),
        }
    }

    /// Find in the proof the trie node that follows `key_before` in lexicographic order.
    ///
    /// If `or_equal` is `true`, then `key_before` is returned if it is equal to a node in the
    /// trie. If `false`, then only keys that are strictly superior are returned.
    ///
    /// The returned value must always start with `prefix`. Note that the value of `prefix` is
    /// important as it can be the difference between `Err(IncompleteProofError)` and `Ok(None)`.
    ///
    /// If `branch_nodes` is `false`, then trie nodes that don't have a storage value are skipped.
    ///
    /// Returns an error if the proof doesn't contain enough information to determine the next key.
    /// Returns `Ok(None)` if the proof indicates that there is no next key (within the given
    /// prefix).
    pub fn next_key(
        &self,
        trie_root_merkle_value: &[u8; 32],
        key_before: impl Iterator<Item = nibble::Nibble>,
        mut or_equal: bool,
        prefix: impl Iterator<Item = nibble::Nibble>,
        branch_nodes: bool,
    ) -> Result<Option<EntryKeyIter<'_, T>>, IncompleteProofError> {
        let proof = self.proof.as_ref();

        // The implementation below might continue iterating `prefix` even after it has returned
        // `None`, thus we have to fuse it.
        let mut prefix = prefix.fuse();

        // The implementation below might continue iterating `key_before` even after it has
        // returned `None`, thus we have to fuse it.
        // Furthermore, `key_before` might be modified in the implementation below. When that
        // happens, de do this by setting it to `either::Right`.
        let mut key_before = either::Left(key_before.fuse());

        // Find the starting point of the requested trie.
        let Some(&(mut iter_entry)) = self.trie_roots.get(trie_root_merkle_value) else {
            return Err(IncompleteProofError());
        };

        // If `true`, then it was determined that `key_before` was after the last child of
        // `iter_entry`. The next iteration must find `iter_entry`'s next sibling.
        let mut iterating_up: bool = false;

        // Indicates the depth of ancestors of `iter_entry` that match `prefix`.
        // For example, if the value is 2, then `iter_entry`'s parent and grandparent match
        // `prefix`, but `iter_entry`'s grandparent parent does not.
        let mut prefix_match_iter_entry_ancestor_depth = 0;

        loop {
            let Ok(iter_entry_decoded) =
                trie_node::decode(&proof[self.entries[iter_entry].range_in_proof.clone()])
            else {
                // Proof has been checked to be entirely decodable.
                unreachable!()
            };

            if iterating_up {
                debug_assert!(matches!(key_before, either::Right(_)));
                debug_assert!(or_equal);

                // It was determined that `key_before` was after the last child of `iter_entry`.
                // The next iteration must find `iter_entry`'s next sibling.

                if prefix_match_iter_entry_ancestor_depth == 0 {
                    // `prefix` only matches `iter_entry` and not its parent and
                    // thus wouldn't match `iter_entry`'s sibling or uncle.
                    // Therefore, the next node is `None`.
                    return Ok(None);
                }

                // Go to `iter_entry`'s next sibling, if any.
                let Some((parent_entry, parent_to_child_nibble)) =
                    self.entries[iter_entry].parent_entry_index
                else {
                    // `iter_entry` is the root of the trie. `key_before` is therefore
                    // after the last entry of the trie.
                    return Ok(None);
                };
                let Ok(parent_entry_decoded) =
                    trie_node::decode(&proof[self.entries[parent_entry].range_in_proof.clone()])
                else {
                    // Proof has been checked to be entirely decodable.
                    unreachable!()
                };

                let Some(child_num) = parent_entry_decoded
                    .children
                    .iter()
                    .skip(usize::from(parent_to_child_nibble) + 1)
                    .position(|c| c.is_some())
                    .map(|n| n + usize::from(parent_to_child_nibble) + 1)
                else {
                    // No child found. Continue iterating up.
                    iterating_up = true;
                    iter_entry = parent_entry;
                    prefix_match_iter_entry_ancestor_depth -= 1;
                    continue;
                };

                // Found a next sibling.

                let children_present_in_proof_bitmap =
                    self.entries[parent_entry].children_present_in_proof_bitmap;

                // If the child isn't present in the proof, then the proof is
                // incomplete. While in some situations we could prove that the child
                // is necessarily the next key, there is no way to know its full key.
                if children_present_in_proof_bitmap & (1 << child_num) == 0 {
                    return Err(IncompleteProofError());
                }

                // `iter_entry` is still pointing to the child at index `parent_to_child_nibble`.
                // Since we're jumping to its next sibling, all we have to do is skip over it
                // and its descedants.
                iter_entry += self.entries[iter_entry].child_entries_follow_up;
                iter_entry += 1;
                iterating_up = false;
                continue; // Continue in order to refresh `iter_entry_decoded`.
            }

            let mut iter_entry_partial_key_iter = iter_entry_decoded.partial_key;
            loop {
                match (
                    key_before.next(),
                    prefix.next(),
                    iter_entry_partial_key_iter.next(),
                ) {
                    (Some(k), Some(p), Some(pk)) if k == p && p == pk => {
                        // Continue descending down the tree.
                    }
                    (None, Some(p), Some(pk)) if p == pk => {
                        // Continue descending down the tree.
                    }
                    (Some(k), None, Some(pk)) if k == pk => {
                        // Continue descending down the tree.
                    }
                    (None, None, Some(_)) => {
                        // Exact match. Due to the `branch_nodes` setting, we can't just
                        // return `iter_entry` and instead continue iterating.
                        or_equal = true;
                    }
                    (Some(k), None, Some(pk)) if k < pk => {
                        // `key_before` points to somewhere between `iter_entry`'s parent
                        // and `iter_entry`. Due to the `branch_nodes` setting, we can't just
                        // return `iter_entry` and instead continue iterating.
                        key_before = either::Right(iter::empty().fuse());
                        or_equal = true;
                    }
                    (Some(k), Some(p), _) if k > p => {
                        // `key_before` is strictly superior to `prefix`. The next key is
                        // thus necessarily `None`.
                        // Note that this is not a situation that is expected to be common, as
                        // doing such a call is pointless.
                        return Ok(None);
                    }
                    (Some(k), Some(p), Some(pk)) if k < p && p == pk => {
                        // The key and prefix diverge.
                        // We know that there isn't any key in the trie between `key_before`
                        // and `prefix`.
                        // Starting next iteration, the next node matching the prefix
                        // will be the result.
                        key_before = either::Right(iter::empty().fuse());
                        or_equal = true;
                    }
                    (_, Some(p), Some(pk)) => {
                        debug_assert!(p != pk); // Other situations covered by other match blocks.

                        // Mismatch between prefix and partial key. No matter the value of
                        // `key_before` There is no node in the trie that starts with `prefix`.
                        return Ok(None);
                    }
                    (Some(k), None, Some(pk)) if k < pk => {
                        // `key_before` points to somewhere between `iter_entry`'s parent
                        // and `iter_entry`. We know that `iter_entry` necessarily matches
                        // the prefix. The next key is necessarily `iter_entry`.
                        return Ok(Some(EntryKeyIter::new(self, iter_entry)));
                    }
                    (Some(k), None, Some(pk)) => {
                        debug_assert!(k > pk); // Checked above.

                        // `key_before` points to somewhere between the last child of `iter_entry`
                        // and its next sibling.
                        // The next key is thus the next sibling of `iter_entry`.
                        iterating_up = true;
                        key_before = either::Right(iter::empty().fuse());
                        or_equal = true;
                        break;
                    }
                    (None, None, None)
                        if or_equal
                            && (branch_nodes
                                || !matches!(
                                    iter_entry_decoded.storage_value,
                                    trie_node::StorageValue::None,
                                )) =>
                    {
                        // Exact match. Next key is `iter_entry`.
                        return Ok(Some(EntryKeyIter::new(self, iter_entry)));
                    }
                    (key_before_nibble, prefix_nibble, None) => {
                        // The moment when we have finished traversing a node and go to the
                        // next one is the most complicated situation.

                        // We know for sure that `iter_entry` can't be returned, as it is covered
                        // by the other match variants above. Therefore, `key_before_nibble` equal
                        // to `None` is the same as if it is equal to `0`.
                        let key_before_nibble = match key_before_nibble {
                            Some(n) => u8::from(n),
                            None => {
                                or_equal = true;
                                0
                            }
                        };

                        // Try to find the first child that is after `key_before`.
                        if let Some(child_num) = iter_entry_decoded
                            .children
                            .iter()
                            .skip(usize::from(key_before_nibble))
                            .position(|c| c.is_some())
                            .map(|n| n + usize::from(key_before_nibble))
                        {
                            // Found a child. Make sure that it matches the prefix nibble.
                            if prefix_nibble.map_or(false, |p| child_num != usize::from(p)) {
                                // Child doesn't match prefix. No next key.
                                return Ok(None);
                            }

                            // Continue iterating down through the child that has been found.

                            let children_present_in_proof_bitmap =
                                self.entries[iter_entry].children_present_in_proof_bitmap;

                            // If the child isn't present in the proof, then the proof is
                            // incomplete. While in some situations we could prove that the child
                            // is necessarily the next key, there is no way to know its full key.
                            if children_present_in_proof_bitmap & (1 << child_num) == 0 {
                                return Err(IncompleteProofError());
                            }

                            for c in 0..child_num {
                                if children_present_in_proof_bitmap & (1 << c) != 0 {
                                    iter_entry += 1;
                                    iter_entry += self.entries[iter_entry].child_entries_follow_up;
                                }
                            }

                            iter_entry += 1;
                            if prefix_nibble.is_none() {
                                prefix_match_iter_entry_ancestor_depth += 1;
                            }
                            if usize::from(key_before_nibble) != child_num {
                                key_before = either::Right(iter::empty().fuse());
                                or_equal = true;
                            }
                            break;
                        } else {
                            // Childless branch nodes are forbidden. This is checked when
                            // decoding the proof.
                            debug_assert!(!matches!(
                                iter_entry_decoded.storage_value,
                                trie_node::StorageValue::None,
                            ));

                            // `key_before` is after the last child of `iter_entry`. The next
                            // node is thus a sibling or uncle of `iter_entry`.
                            iterating_up = true;
                            key_before = either::Right(iter::empty().fuse());
                            or_equal = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Find in the proof the closest trie node that descends from `key` and returns its Merkle
    /// value.
    ///
    /// Returns an error if the proof doesn't contain enough information to determine the Merkle
    /// value.
    /// Returns `Ok(None)` if the proof indicates that there is no descendant.
    pub fn closest_descendant_merkle_value(
        &self,
        trie_root_merkle_value: &[u8; 32],
        mut key: impl Iterator<Item = nibble::Nibble>,
    ) -> Result<Option<&[u8]>, IncompleteProofError> {
        let proof = self.proof.as_ref();

        // Find the starting point of the requested trie.
        let Some((mut iter_entry_merkle_value, mut iter_entry)) = self
            .trie_roots
            .get_key_value(trie_root_merkle_value)
            .map(|(k, v)| (&k[..], *v))
        else {
            return Err(IncompleteProofError());
        };

        loop {
            let Ok(iter_entry_decoded) =
                trie_node::decode(&proof[self.entries[iter_entry].range_in_proof.clone()])
            else {
                // Proof has been checked to be entirely decodable.
                unreachable!()
            };

            let mut iter_entry_partial_key_iter = iter_entry_decoded.partial_key;
            loop {
                match (key.next(), iter_entry_partial_key_iter.next()) {
                    (Some(a), Some(b)) if a == b => {}
                    (Some(_), Some(_)) => {
                        // Mismatch in partial key. No descendant.
                        return Ok(None);
                    }
                    (None, Some(_)) => {
                        // Input key is a subslice of `iter_entry`'s key.
                        // Descendant is thus `iter_entry`.
                        return Ok(Some(iter_entry_merkle_value));
                    }
                    (Some(child_num), None) => {
                        if let Some(child) = iter_entry_decoded.children[usize::from(child_num)] {
                            // Key points in the direction of a child.
                            let children_present_in_proof_bitmap =
                                self.entries[iter_entry].children_present_in_proof_bitmap;

                            // If the child isn't present in the proof, then the proof is
                            // incomplete, unless the input key doesn't have any nibble anymore,
                            // in which case we know that the closest descendant is this child,
                            // even if it's not present.
                            if children_present_in_proof_bitmap & (1 << u8::from(child_num)) == 0 {
                                if key.next().is_none() {
                                    return Ok(Some(child));
                                } else {
                                    return Err(IncompleteProofError());
                                }
                            }

                            // Child is present in the proof. Update `iter_entry` and continue.
                            iter_entry_merkle_value = child;
                            for c in 0..u8::from(child_num) {
                                if children_present_in_proof_bitmap & (1 << c) != 0 {
                                    iter_entry += 1;
                                    iter_entry += self.entries[iter_entry].child_entries_follow_up;
                                }
                            }
                            iter_entry += 1;
                            break;
                        } else {
                            // Key points to non-existing child. We know that there's no
                            // descendant.
                            return Ok(None);
                        }
                    }
                    (None, None) => {
                        // Exact match. Closest descendant is `iter_entry`.
                        return Ok(Some(iter_entry_merkle_value));
                    }
                }
            }
        }
    }
}

/// Proof doesn't contain enough information to answer the request.
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub struct IncompleteProofError();

/// Storage value of the node.
#[derive(Copy, Clone)]
pub enum StorageValue<'a> {
    /// The storage value was found in the proof.
    Known {
        /// The storage value.
        value: &'a [u8],
        /// `true` if the storage value was inline in the node. This indicates "version 0" of the
        /// state version, while `false` indicates "version 1".
        inline: bool,
    },
    /// The hash of the storage value was found, but the un-hashed value wasn't in the proof. This
    /// indicates an incomplete proof.
    HashKnownValueMissing(&'a [u8; 32]),
    /// The node doesn't have a storage value.
    None,
}

impl<'a> fmt::Debug for StorageValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorageValue::Known { value, inline } if value.len() <= 48 => {
                write!(
                    f,
                    "0x{}{}",
                    hex::encode(value),
                    if *inline { " (inline)" } else { "" }
                )
            }
            StorageValue::Known { value, inline } => {
                write!(
                    f,
                    "0x{}…{} ({} bytes{})",
                    hex::encode(&value[0..4]),
                    hex::encode(&value[value.len() - 4..]),
                    value.len(),
                    if *inline { ", inline" } else { "" }
                )
            }
            StorageValue::HashKnownValueMissing(hash) => {
                write!(f, "hash(0x{})", hex::encode(hash))
            }
            StorageValue::None => write!(f, "<none>"),
        }
    }
}

/// Possible error returned by [`decode_and_verify_proof`].
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub enum Error {
    /// Proof is in an invalid format.
    InvalidFormat(ParseError),
    /// One of the entries of the proof is disconnected from the root node.
    UnusedProofEntry,
    /// The same entry has been found multiple times in the proof.
    DuplicateProofEntry,
}

pub struct EntryKeyIter<'a, T> {
    proof: &'a DecodedTrieProof<T>,
    target_entry: usize,
    /// [`EntryKeyIter::entry_key_iterator`] is the `target_entry_depth_remaining` nth ancestor
    /// of [`EntryKeyIter::target_entry`].
    target_entry_depth_remaining: usize,
    /// `None` if iteration is finished.
    entry_key_iterator: Option<trie_node::DecodedPartialKey<'a>>,
}

impl<'a, T: AsRef<[u8]>> EntryKeyIter<'a, T> {
    fn new(proof: &'a DecodedTrieProof<T>, target_entry: usize) -> Self {
        // Find the number of nodes between `target_entry` and the trie root.
        let mut entry_iter = target_entry;
        let mut target_entry_depth_remaining = 0;
        loop {
            if let Some((parent, _)) = proof.entries[entry_iter].parent_entry_index {
                target_entry_depth_remaining += 1;
                entry_iter = parent;
            } else {
                break;
            }
        }

        let Ok(decoded_entry) = trie_node::decode(
            &proof.proof.as_ref()[proof.entries[entry_iter].range_in_proof.clone()],
        ) else {
            unreachable!()
        };

        EntryKeyIter {
            proof,
            target_entry,
            target_entry_depth_remaining,
            entry_key_iterator: Some(decoded_entry.partial_key),
        }
    }
}

impl<'a, T: AsRef<[u8]>> Iterator for EntryKeyIter<'a, T> {
    type Item = nibble::Nibble;

    fn next(&mut self) -> Option<Self::Item> {
        // `entry_key_iterator` is `None` only if the iteration is finished, as a way to fuse
        // the iterator.
        let Some(entry_key_iterator) = &mut self.entry_key_iterator else {
            return None;
        };

        // Still yielding from `entry_key_iterator`.
        if let Some(nibble) = entry_key_iterator.next() {
            return Some(nibble);
        }

        // `entry_key_iterator` has finished iterating. Update the local state for the next node
        // in the hierarchy.
        if self.target_entry_depth_remaining == 0 {
            // Iteration finished.
            self.entry_key_iterator = None;
            return None;
        }
        self.target_entry_depth_remaining -= 1;

        // Find the `target_entry_depth_remaining`th ancestor of `target_entry`.
        let mut entry_iter = self.target_entry;
        for _ in 0..self.target_entry_depth_remaining {
            let Some((parent, _)) = self.proof.entries[entry_iter].parent_entry_index else {
                unreachable!()
            };
            entry_iter = parent;
        }

        // Store the partial key of `entry_iter` in `entry_key_iterator`, so that it starts being
        // yielded at the next iteration.
        self.entry_key_iterator = Some(
            trie_node::decode(
                &self.proof.proof.as_ref()[self.proof.entries[entry_iter].range_in_proof.clone()],
            )
            .unwrap_or_else(|_| unreachable!())
            .partial_key,
        );

        // Yield the "parent-child nibble" of `entry_iter`.
        Some(
            self.proof.entries[entry_iter]
                .parent_entry_index
                .unwrap_or_else(|| unreachable!())
                .1,
        )
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // We know we're going to yield `self.target_entry_depth_remaining` "parent-child nibbles".
        // We add to that the size hint of `entry_key_iterator`.
        let entry_key_iterator = self
            .entry_key_iterator
            .as_ref()
            .map_or(0, |i| i.size_hint().0);
        (entry_key_iterator + self.target_entry_depth_remaining, None)
    }
}

impl<'a, T: AsRef<[u8]>> iter::FusedIterator for EntryKeyIter<'a, T> {}

// We need to implement `Clone` manually, otherwise Rust adds an implicit `T: Clone` requirements.
impl<'a, T> Clone for EntryKeyIter<'a, T> {
    fn clone(&self) -> Self {
        EntryKeyIter {
            proof: self.proof,
            target_entry: self.target_entry,
            target_entry_depth_remaining: self.target_entry_depth_remaining,
            entry_key_iterator: self.entry_key_iterator.clone(),
        }
    }
}

impl<'a, T: AsRef<[u8]>> fmt::Debug for EntryKeyIter<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut any_printed = false;
        for nibble in self.clone() {
            any_printed = true;
            write!(f, "{:x}", nibble)?;
        }
        if !any_printed {
            write!(f, "∅")?;
        }
        Ok(())
    }
}

/// Information about an entry in the proof.
#[derive(Debug)]
pub struct ProofEntry<'a, T> {
    /// Information about the node of the trie associated to this entry.
    pub trie_node_info: TrieNodeInfo<'a, T>,

    /// Merkle value of that proof entry.
    ///
    /// > **Note**: This is a low-level information. If you're not familiar with how the trie
    /// >           works, you most likely don't need this.
    pub merkle_value: &'a [u8],

    /// Node value of that proof entry.
    ///
    /// > **Note**: This is a low-level information. If you're not familiar with how the trie
    /// >           works, you most likely don't need this.
    pub node_value: &'a [u8],

    /// Partial key of that proof entry.
    ///
    /// > **Note**: This is a low-level information. If you're not familiar with how the trie
    /// >           works, you most likely don't need this.
    pub partial_key_nibbles: trie_node::DecodedPartialKey<'a>,

    /// If [`ProofEntry::node_value`] indicates that the storage value is hashed, then this field
    /// contains the unhashed storage value that is found in the proof, if any.
    ///
    /// If this field contains `Some`, then [`TrieNodeInfo::storage_value`] is guaranteed to
    /// contain [`StorageValue::Known`]. However the opposite is not necessarily true.
    ///
    /// > **Note**: This is a low-level information. If you're not familiar with how the trie
    /// >           works, you most likely don't need this.
    pub unhashed_storage_value: Option<&'a [u8]>,
}

// We need to implement `Clone` manually, otherwise Rust adds an implicit `T: Clone` requirements.
impl<'a, T> Clone for ProofEntry<'a, T> {
    fn clone(&self) -> Self {
        ProofEntry {
            trie_node_info: self.trie_node_info.clone(),
            merkle_value: self.merkle_value,
            node_value: self.node_value,
            partial_key_nibbles: self.partial_key_nibbles.clone(),
            unhashed_storage_value: self.unhashed_storage_value,
        }
    }
}

/// Information about a node of the trie.
///
/// > **Note**: This structure might represent a node that doesn't actually exist in the trie.
#[derive(Debug)]
pub struct TrieNodeInfo<'a, T> {
    /// Storage value of the node, if any.
    pub storage_value: StorageValue<'a>,
    /// Which children the node has.
    pub children: Children<'a, T>,
}

// We need to implement `Clone` manually, otherwise Rust adds an implicit `T: Clone` requirements.
impl<'a, T> Clone for TrieNodeInfo<'a, T> {
    fn clone(&self) -> Self {
        TrieNodeInfo {
            storage_value: self.storage_value,
            children: self.children.clone(),
        }
    }
}

/// See [`TrieNodeInfo::children`].
pub struct Children<'a, T> {
    children: [Child<'a, T>; 16],
}

/// Information about a specific child in the list of children.
pub enum Child<'a, T> {
    /// Child exists and can be found in the proof.
    InProof {
        /// Key of the child. Always starts with the key of its parent.
        child_key: EntryKeyIter<'a, T>,
        /// Merkle value of the child.
        merkle_value: &'a [u8],
    },
    /// Child exists but isn't present in the proof.
    AbsentFromProof {
        /// Merkle value of the child.
        merkle_value: &'a [u8],
    },
    /// Child doesn't exist.
    NoChild,
}

impl<'a, T> Child<'a, T> {
    /// Returns the Merkle value of this child. `None` if the child doesn't exist.
    pub fn merkle_value(&self) -> Option<&'a [u8]> {
        match self {
            Child::InProof { merkle_value, .. } => Some(merkle_value),
            Child::AbsentFromProof { merkle_value } => Some(merkle_value),
            Child::NoChild => None,
        }
    }
}

// We need to implement `Clone` manually, otherwise Rust adds an implicit `T: Clone` requirements.
impl<'a, T> Clone for Child<'a, T> {
    fn clone(&self) -> Self {
        match self {
            Child::AbsentFromProof { merkle_value } => Child::AbsentFromProof { merkle_value },
            Child::InProof {
                child_key,
                merkle_value,
            } => Child::InProof {
                child_key: child_key.clone(),
                merkle_value,
            },
            Child::NoChild => Child::NoChild,
        }
    }
}

impl<'a, T> Children<'a, T> {
    /// Returns `true` if a child in the direction of the given nibble is present.
    pub fn has_child(&self, nibble: nibble::Nibble) -> bool {
        match self.children[usize::from(u8::from(nibble))] {
            Child::InProof { .. } | Child::AbsentFromProof { .. } => true,
            Child::NoChild => false,
        }
    }

    /// Returns the information about the child in the given direction.
    pub fn child(&self, direction: nibble::Nibble) -> Child<'a, T> {
        self.children[usize::from(u8::from(direction))].clone()
    }

    /// Returns an iterator of 16 items, one for each child.
    pub fn children(&self) -> impl DoubleEndedIterator + ExactSizeIterator<Item = Child<'a, T>> {
        self.children.iter().cloned()
    }
}

// We need to implement `Clone` manually, otherwise Rust adds an implicit `T: Clone` requirements.
impl<'a, T> Clone for Children<'a, T> {
    fn clone(&self) -> Self {
        Children {
            children: self.children.clone(),
        }
    }
}

impl<'a, T> fmt::Debug for Children<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Binary::fmt(&self, f)
    }
}

impl<'a, T> fmt::Binary for Children<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for child in &self.children {
            let chr = match child {
                Child::InProof { .. } | Child::AbsentFromProof { .. } => '1',
                Child::NoChild => '0',
            };

            fmt::Write::write_char(f, chr)?
        }

        Ok(())
    }
}

/// Verifies a Substrate-style compact Merkle proof.
///
/// Compact proofs (produced by `sp_trie::generate_trie_proof`) replace path children with an
/// empty inline placeholder and omit the target leaf's value. Both are reconstructed during
/// verification from `expected_value`, which for state version V1 is hashed when its length is
/// 33 bytes or more (matching `sp_trie`'s threshold).
///
/// Single-key only: assumes the proof witnesses exactly one `(key, Some(value))` item, which
/// is the contract `ext_trie_blake2_256_verify_proof_*` always passes. Multi-key proofs whose
/// intermediate branch nodes also carry omitted values would silently mis-verify here, since
/// only the terminal value is injected from `expected_value`. Do not reuse this function for
/// the general case.
pub fn verify_compact_trie_proof(
    proof: &[u8],
    root: &[u8; 32],
    key: &[u8],
    expected_value: &[u8],
    state_version: TrieEntryVersion,
) -> bool {
    let entries: Vec<&[u8]> = match decode_proof(proof) {
        Ok(it) => it.collect(),
        Err(_) => return false,
    };
    let mut iter = entries.into_iter();
    let root_node = match iter.next() {
        Some(n) => n,
        None => return false,
    };

    let key_nibbles: Vec<nibble::Nibble> = nibble::bytes_to_nibbles(key.iter().copied()).collect();

    let computed = match compact_proof_compute_merkle(
        root_node,
        &mut iter,
        &key_nibbles[..],
        expected_value,
        state_version,
    ) {
        Some(m) => m,
        None => return false,
    };

    // Reject proofs with trailing entries the verifier never consumed: an attacker could
    // otherwise append unrelated nodes after a valid proof and still pass.
    // Matches `paritytech/trie`'s `Error::ExtraneousNode` check.
    if iter.next().is_some() {
        return false;
    }

    match computed {
        CompactMerkleValue::Hash(h) => h[..] == root[..],
        CompactMerkleValue::Inline(_) => false,
    }
}

enum CompactMerkleValue {
    Hash([u8; 32]),
    Inline(Vec<u8>),
}

enum CompactStorageValueOwned {
    Unhashed(Vec<u8>),
    Hashed([u8; 32]),
    None,
}

struct CompactFrame {
    partial_key: Vec<nibble::Nibble>,
    new_children: [Option<Vec<u8>>; 16],
    new_storage_value: CompactStorageValueOwned,
    descended_into: usize,
    is_root: bool,
}

/// Walk the compact proof iteratively rather than recursively: max depth is bounded by the
/// key length (caller-controlled), which on substrate state tries can reach hundreds of
/// nibbles, so an explicit heap stack keeps us off the native stack.
fn compact_proof_compute_merkle<'a, I: Iterator<Item = &'a [u8]>>(
    root_node_bytes: &'a [u8],
    proof_iter: &mut I,
    key: &[nibble::Nibble],
    expected_value: &[u8],
    state_version: TrieEntryVersion,
) -> Option<CompactMerkleValue> {
    let mut stack: Vec<CompactFrame> = Vec::new();
    let mut node_bytes: &[u8] = root_node_bytes;
    let mut key_pos = 0usize;
    let mut is_root = true;

    let mut current = loop {
        let decoded = trie_node::decode(node_bytes).ok()?;

        let partial_key: Vec<nibble::Nibble> = decoded.partial_key.clone().collect();
        for pk_nibble in &partial_key {
            if key_pos >= key.len() {
                return None;
            }
            if key[key_pos] != *pk_nibble {
                return None;
            }
            key_pos += 1;
        }

        let new_children: [Option<Vec<u8>>; 16] =
            core::array::from_fn(|i| decoded.children[i].map(|c| c.to_vec()));

        if key_pos == key.len() {
            // Substrate picks the placeholder shape by node kind: a leaf uses empty inline
            // (`Unhashed(b"")`), a branch uses `None`. Any other shape would mean the proof
            // carries data it shouldn't — substrate rejects that as `ExtraneousValue`.
            let has_children = decoded.children.iter().any(|c| c.is_some());
            let placeholder_ok = match decoded.storage_value {
                trie_node::StorageValue::None => has_children,
                trie_node::StorageValue::Unhashed(v) => !has_children && v.is_empty(),
                trie_node::StorageValue::Hashed(_) => false,
            };
            if !placeholder_ok {
                return None;
            }
            let new_storage_value = inject_compact_value(expected_value, state_version);
            break compact_encode_node(partial_key, new_children, new_storage_value, is_root)?;
        }

        let child_nibble = key[key_pos];
        key_pos += 1;
        let child_index = u8::from(child_nibble) as usize;
        let child = decoded.children[child_index]?;

        // Compact encoding: an empty inline reference marks a path child whose subtree is
        // the next proof entry; a sub-32-byte reference is the inlined child node itself;
        // a 32-byte reference points outside the proven path, so descending into it means
        // the proof can't prove this key.
        let next_node_bytes: &[u8] = if child.is_empty() {
            proof_iter.next()?
        } else if child.len() < 32 {
            child
        } else {
            return None;
        };

        let new_storage_value = match decoded.storage_value {
            trie_node::StorageValue::Unhashed(v) => CompactStorageValueOwned::Unhashed(v.to_vec()),
            trie_node::StorageValue::Hashed(h) => CompactStorageValueOwned::Hashed(*h),
            trie_node::StorageValue::None => CompactStorageValueOwned::None,
        };

        stack.push(CompactFrame {
            partial_key,
            new_children,
            new_storage_value,
            descended_into: child_index,
            is_root,
        });
        node_bytes = next_node_bytes;
        is_root = false;
    };

    while let Some(mut frame) = stack.pop() {
        frame.new_children[frame.descended_into] = Some(match current {
            CompactMerkleValue::Hash(h) => h.to_vec(),
            CompactMerkleValue::Inline(b) => b,
        });
        current = compact_encode_node(
            frame.partial_key,
            frame.new_children,
            frame.new_storage_value,
            frame.is_root,
        )?;
    }

    Some(current)
}

fn compact_encode_node(
    partial_key: Vec<nibble::Nibble>,
    new_children: [Option<Vec<u8>>; 16],
    new_storage_value: CompactStorageValueOwned,
    is_root: bool,
) -> Option<CompactMerkleValue> {
    let sv_view = match &new_storage_value {
        CompactStorageValueOwned::Unhashed(v) => trie_node::StorageValue::Unhashed(&v[..]),
        CompactStorageValueOwned::Hashed(h) => trie_node::StorageValue::Hashed(h),
        CompactStorageValueOwned::None => trie_node::StorageValue::None,
    };
    let children_view: [Option<&[u8]>; 16] = core::array::from_fn(|i| new_children[i].as_deref());

    let encoded = trie_node::encode_to_vec(trie_node::Decoded {
        partial_key: partial_key.into_iter(),
        children: children_view,
        storage_value: sv_view,
    })
    .ok()?;

    if encoded.len() < 32 && !is_root {
        Some(CompactMerkleValue::Inline(encoded))
    } else {
        let h = blake2_rfc::blake2b::blake2b(32, &[], &encoded);
        let arr = <[u8; 32]>::try_from(h.as_bytes()).ok()?;
        Some(CompactMerkleValue::Hash(arr))
    }
}

fn inject_compact_value(
    expected_value: &[u8],
    state_version: TrieEntryVersion,
) -> CompactStorageValueOwned {
    match state_version {
        TrieEntryVersion::V0 => CompactStorageValueOwned::Unhashed(expected_value.to_vec()),
        TrieEntryVersion::V1 => {
            // Threshold matches `sp_trie`'s `calculate_root.rs` (>= 33 bytes are hashed).
            if expected_value.len() < 33 {
                CompactStorageValueOwned::Unhashed(expected_value.to_vec())
            } else {
                let h = blake2_rfc::blake2b::blake2b(32, &[], expected_value);
                let arr = <[u8; 32]>::try_from(h.as_bytes()).expect("blake2b 32 bytes; qed");
                CompactStorageValueOwned::Hashed(arr)
            }
        }
    }
}
