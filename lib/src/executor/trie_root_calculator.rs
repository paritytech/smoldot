// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

//! Given as input a partial base trie and a diff, calculates the new root of the trie.
//!
//! # Implementation
//!
//! The algorithm for calculating the trie root is roughly:
//!
//! ```notrust
//! TrieRoot = ClosestDescendantMerkleValue(∅, False) || EmptyTrieRootHash
//!
//! ClosestDescendantMerkleValue(Key, ForceRecalculate) =
//!     If !ForceRecalculate AND !DiffContainsEntryWithPrefix(Key)
//!         MaybeMerkleValue := BaseTrieClosestDescendantMerkleValue(Key)
//!         If MaybeMerkleValue
//!             return MaybeMerkleValue
//!
//!     Btcd := BaseTrieClosestDescendant(Key)
//!     MaybeNodeKey := LongestCommonDenominator(Btcd, ...DiffInsertsNodesWithPrefix(Key))
//!     MaybeChildren := Array(ClosestDescendantMerkleValue(Concat(MaybeNodeKey, 0), MaybeNodeKey != Btcd), ..., ClosestDescendantMerkleValue(Concat(MaybeNodeKey, 15), MaybeNodeKey != Btcd))
//!     MaybeStorageValue := DiffInserts(MaybeNodeKey) || (BaseTrieStorageValue(MaybeNodeKey) - DiffErases(MaybeNodeKey))
//!
//!     If MaybeStorageValue = ∅ AND NumChildren(MaybeChildren) == 0
//!         ∅
//!     ElseIf NumChildren(MaybeChildren) == 1 AND BaseTrieStorageValue(MaybeNodeKey) != ∅ AND MaybeStorageValue = ∅
//!         # Because the partial key of the child has changed, we have to recalculate it.
//!         ClosestDescendantMerkleValue(ChildThatExists(MaybeChildren), True)
//!     ElseIf NumChildren(MaybeChildren) == 1 AND BaseTrieStorageValue(MaybeNodeKey) = ∅ AND MaybeStorageValue = ∅
//!         ChildThatExists(MaybeChildren)
//!     Else
//!         Encode(MaybeStorageValue, MaybeChildren)
//! ```
//!
//! The public API functions are thus `BaseTrieClosestDescendant`,
//! `BaseTrieClosestDescendantMerkleValue`, and `BaseTrieStorageValue`.
//!
//! The algorithm above is recursive. In order to implement it, we instead maintain a stack of
//! nodes that are currently being calculated.
//!

use alloc::{boxed::Box, vec::Vec};
use core::{array, iter, ops};

use super::storage_diff::TrieDiff;
use crate::trie;

pub use trie::{Nibble, TrieEntryVersion};

mod tests;

/// Configuration for [`trie_root_calculator`].
pub struct Config {
    /// Diff that is being applied on top of the base trie.
    pub diff: TrieDiff,

    /// Version to use for the storage values written by [`Config::diff`].
    pub diff_trie_entries_version: TrieEntryVersion,

    /// Depth level of the deepest node whose value needs to be calculated. The root node has a
    /// depth level of 1, its children a depth level of 2, etc.
    ///
    /// Used as a hint to pre-allocate a container. Getting the value wrong has no ill
    /// consequence except a very small performance hit.
    pub max_trie_recalculation_depth_hint: usize,
}

/// Starts a new calculation.
pub fn trie_root_calculator(config: Config) -> InProgress {
    Box::new(Inner {
        stack: Vec::with_capacity(config.max_trie_recalculation_depth_hint),
        rewalk_start_stack_len: None,
        diff: config.diff,
        diff_trie_entries_version: config.diff_trie_entries_version,
    })
    .next()
}

/// Trie root calculation in progress.
pub enum InProgress {
    /// Calculation has successfully finished.
    Finished {
        /// Calculated trie root hash.
        trie_root_hash: [u8; 32],
    },
    /// See [`ClosestDescendant`].
    ClosestDescendant(ClosestDescendant),
    /// See [`StorageValue`].
    StorageValue(StorageValue),
    /// See [`ClosestDescendantMerkleValue`].
    ClosestDescendantMerkleValue(ClosestDescendantMerkleValue),
    /// See [`TrieNodeInsertUpdateEvent`].
    // TODO: consider guaranteeing an ordering in the events?
    TrieNodeInsertUpdateEvent(TrieNodeInsertUpdateEvent),
    /// See [`TrieNodeRemoveEvent`].
    TrieNodeRemoveEvent(TrieNodeRemoveEvent),
}

/// In order to continue the calculation, must find in the base trie the closest descendant
/// (including branch node) to a certain key in the trie. This can be equal to the requested key
/// itself.
pub struct ClosestDescendant {
    inner: Box<Inner>,
    /// Extra nibbles to append at the end of what `self.key()` returns.
    key_extra_nibbles: Vec<Nibble>,
    /// `Some` if the diff inserts a value that is equal or a descendant of `self.key()`. If
    /// `Some`, contains the least common denominator shared amongst all these insertions.
    diff_inserts_lcd: Option<Vec<Nibble>>,
}

impl ClosestDescendant {
    /// Returns an iterator of slices, which, when joined together, form the full key of the trie
    /// node whose closest descendant must be fetched.
    pub fn key(&self) -> impl Iterator<Item = impl AsRef<[Nibble]>> {
        self.inner
            .current_node_full_key()
            .map(either::Left)
            .chain(iter::once(either::Right(&self.key_extra_nibbles)))
    }

    /// Returns the same value as [`ClosestDescendant::key`] but as a `Vec`.
    pub fn key_as_vec(&self) -> Vec<Nibble> {
        self.key().fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        })
    }

    /// Indicates the key of the closest descendant to the key indicated by
    /// [`ClosestDescendant::key`] and resume the calculation.
    pub fn inject(
        mut self,
        closest_descendant: Option<impl Iterator<Item = Nibble>>,
    ) -> InProgress {
        // We are after a call to `BaseTrieClosestDescendant`.
        debug_assert!(
            self.inner
                .stack
                .last()
                .map_or(true, |n| n.children.len() != 16)
        );

        // Length of the key of the currently-iterated node.
        let iter_key_len = self
            .inner
            .current_node_full_key()
            .fold(0, |acc, k| acc + k.as_ref().len());

        // Find the value of `MaybeNode`.
        let (maybe_node_partial_key, children_partial_key_changed) =
            match (self.diff_inserts_lcd, closest_descendant) {
                (Some(inserted_key), Some(base_trie_key)) => {
                    // `children_partial_key_changed` is `true` if
                    // `diff_inserts_lcd < closest_descendant`.
                    let mut inserted_key_iter = inserted_key.iter().copied().skip(iter_key_len);
                    let mut base_trie_key = base_trie_key.skip(iter_key_len);
                    let mut maybe_node_pk =
                        Vec::with_capacity(inserted_key.len() - iter_key_len + 8);
                    let mut children_pk_changed = false;
                    loop {
                        match (inserted_key_iter.next(), base_trie_key.next()) {
                            (Some(inib), Some(bnib)) if inib == bnib => maybe_node_pk.push(inib),
                            (Some(_), Some(_)) | (None, Some(_)) => {
                                children_pk_changed = true;
                                break;
                            }
                            (Some(_), None) | (None, None) => break,
                        }
                    }
                    (maybe_node_pk, children_pk_changed)
                }
                (Some(inserted_key), None) => (
                    inserted_key
                        .into_iter()
                        .skip(iter_key_len)
                        .collect::<Vec<_>>(),
                    true,
                ),
                (None, Some(base_trie_key)) => (base_trie_key.skip(iter_key_len).collect(), false),
                (None, None) => {
                    // If neither the base trie nor the diff contain any descendant, then skip ahead.
                    return if self.inner.stack.is_empty() {
                        // If the element doesn't have a parent, then the trie is completely empty.
                        InProgress::Finished {
                            trie_root_hash: trie::EMPTY_BLAKE2_TRIE_MERKLE_VALUE,
                        }
                    } else {
                        // If the element has a parent, indicate that the current iterated node
                        // doesn't exist and continue the algorithm.
                        self.inner.push_child_result(None)
                    };
                }
            };

        // Push `MaybeNode` onto the stack and continue the algorithm.
        self.inner.stack.push(InProgressNode {
            partial_key: maybe_node_partial_key,
            children_partial_key_changed,
            children: arrayvec::ArrayVec::new(),
        });
        self.inner.next()
    }
}

/// In order to continue, must fetch the storage value of the given key in the base trie.
pub struct StorageValue(Box<Inner>);

impl StorageValue {
    /// Returns an iterator of slices, which, when joined together, form the full key of the trie
    /// node whose storage value must be fetched.
    pub fn key(&self) -> impl Iterator<Item = impl AsRef<[Nibble]>> {
        self.0.current_node_full_key()
    }

    /// Returns the same value as [`ClosestDescendant::key`] but as a `Vec`.
    pub fn key_as_vec(&self) -> Vec<Nibble> {
        self.key().fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        })
    }

    /// Indicate the storage value and trie entry version of the trie node indicated by
    /// [`StorageValue::key`] and resume the calculation.
    pub fn inject_value(
        mut self,
        base_trie_storage_value: Option<(&[u8], TrieEntryVersion)>,
    ) -> InProgress {
        // We have finished obtaining `BaseTrieStorageValue` and we are at the last step of
        // `ClosestDescendantMerkleValue` in the algorithm shown at the top.

        // Adjust the storage value to take the diff into account.
        // In other words, we calculate `MaybeStorageValue` from `BaseTrieStorageValue`.
        let maybe_storage_value = if self.key().fold(0, |a, b| a + b.as_ref().len()) % 2 == 0 {
            // TODO: could be optimized?
            let key_nibbles = self.key().fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });
            debug_assert_eq!(key_nibbles.len() % 2, 0);
            let key_as_u8 =
                trie::nibbles_to_bytes_suffix_extend(key_nibbles.into_iter()).collect::<Vec<_>>();
            if let Some((value, _)) = self.0.diff.diff_get(&key_as_u8) {
                value.map(|v| (v, self.0.diff_trie_entries_version))
            } else {
                base_trie_storage_value
            }
        } else {
            base_trie_storage_value
        };

        // Remove the element that is being calculated from the stack, as we finish the
        // calculation down below.
        let calculated_elem = self.0.stack.pop().unwrap_or_else(|| panic!());
        debug_assert_eq!(calculated_elem.children.len(), 16);

        let node_num_children = calculated_elem
            .children
            .iter()
            .filter(|c| c.is_some())
            .count();

        let parent_node = self.0.stack.last_mut();
        debug_assert!(parent_node.map_or(true, |p| p.children.len() != 16));

        match (
            base_trie_storage_value,
            maybe_storage_value,
            node_num_children,
            self.0.stack.last_mut(),
        ) {
            (_, None, 0, Some(_parent_node)) => {
                // Trie node no longer exists after the diff has been applied.
                // This path is only reached if the trie node has a parent, as otherwise the trie
                // node is the trie root and thus necessarily exists.
                let event = TrieNodeRemoveEvent {
                    inner: self.0,
                    calculated_elem,
                    ty: TrieNodeRemoveEventTy::NoChildrenLeft,
                };
                event.report_unless_rewalking()
            }

            (_, None, 1, _parent_node) if !calculated_elem.children_partial_key_changed => {
                // Trie node doesn't exists after the diff has been applied because it has exactly
                // one child.
                // Since `children_partial_key_changed` is `false`, we know that the node existed
                // and generate a `TrieNodeRemoveEvent`.
                // Unfortunately, the child Merkle value is wrong as its partial key has changed
                // and has to be recalculated.

                // To handle this situation, we back jump to `ClosestDescendant` but this time
                // make sure to skip over `calculated_elem`.
                // This isn't done here but in `TrieNodeRemoveEvent::resume`.
                let event = TrieNodeRemoveEvent {
                    inner: self.0,
                    calculated_elem,
                    ty: TrieNodeRemoveEventTy::ReplacedWithSingleChild,
                };
                event.report_unless_rewalking()
            }

            (_, None, 1, _parent_node) => {
                // Same as the previous block, except that `children_partial_key_changed` is
                // `false`. Therefore the node didn't exist in the base trie, and no event shall
                // be generated. Instead, we immediately call `resume` in order to continue
                // execution without notifying the user.
                TrieNodeRemoveEvent {
                    inner: self.0,
                    calculated_elem,
                    ty: TrieNodeRemoveEventTy::ReplacedWithSingleChild,
                }
                .resume()
            }

            (Some(_), None, 0, None) => {
                // Root node of the trie was deleted and trie is now empty.
                InProgress::TrieNodeRemoveEvent(TrieNodeRemoveEvent {
                    inner: self.0,
                    calculated_elem,
                    ty: TrieNodeRemoveEventTy::NoChildrenLeft,
                })
            }

            (None, None, 0, None) if !calculated_elem.children_partial_key_changed => {
                // Root node of the trie was a branch node without any storage value, and all of
                // its children were deleted by the diff. The trie is now empty.
                // Since `children_partial_key_changed` is `false`, we know that this branch node
                // existed in the base trie, and thus its destruction must be reported like for
                // any other node.
                InProgress::TrieNodeRemoveEvent(TrieNodeRemoveEvent {
                    inner: self.0,
                    calculated_elem,
                    ty: TrieNodeRemoveEventTy::NoChildrenLeft,
                })
            }

            (None, None, 0, None) => {
                // Trie is empty, and the node being calculated didn't exist in the base trie.
                // This case is handled separately in order to not generate
                // a `TrieNodeInsertUpdateEvent` or a `TrieNodeRemoveEvent` for a node that
                // doesn't actually exist.
                InProgress::Finished {
                    trie_root_hash: trie::EMPTY_BLAKE2_TRIE_MERKLE_VALUE,
                }
            }

            (_, _, _, parent_node) => {
                // Trie node still exists or was created. Calculate its Merkle value.

                // Due to some borrow checker troubles, we need to calculate the storage value
                // hash ahead of time if relevant.
                let storage_value_hash =
                    if let Some((value, TrieEntryVersion::V1)) = maybe_storage_value {
                        if value.len() >= 33 {
                            Some(blake2_rfc::blake2b::blake2b(32, &[], value))
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                let merkle_value = trie::trie_node::calculate_merkle_value(
                    trie::trie_node::Decoded {
                        children: array::from_fn(|n| calculated_elem.children[n].as_ref()),
                        partial_key: calculated_elem.partial_key.iter().copied(),
                        storage_value: match (maybe_storage_value, storage_value_hash.as_ref()) {
                            (_, Some(storage_value_hash)) => trie::trie_node::StorageValue::Hashed(
                                <&[u8; 32]>::try_from(storage_value_hash.as_bytes())
                                    .unwrap_or_else(|_| panic!()),
                            ),
                            (Some((value, _)), None) => {
                                trie::trie_node::StorageValue::Unhashed(value)
                            }
                            (None, _) => trie::trie_node::StorageValue::None,
                        },
                    },
                    trie::HashFunction::Blake2,
                    parent_node.is_none(),
                )
                .unwrap_or_else(|_| panic!());

                // The stack is updated in `TrieNodeInsertUpdateEvent::resume`.
                InProgress::TrieNodeInsertUpdateEvent(TrieNodeInsertUpdateEvent {
                    inner: self.0,
                    children: calculated_elem.children,
                    inserted_elem_partial_key: calculated_elem.partial_key,
                    merkle_value,
                })
            }
        }
    }
}

/// In order to continue, must fetch the Merkle value of the closest descendant to the given key
/// in the base trie.
///
/// It is possible to continue the calculation even if the Merkle value is unknown, in which case
/// the calculation will walk down the trie in order to calculate the Merkle value manually.
pub struct ClosestDescendantMerkleValue {
    inner: Box<Inner>,
}

impl ClosestDescendantMerkleValue {
    /// Returns an iterator of slices, which, when joined together, form the full key of the trie
    /// node whose closest descendant Merkle value must be fetched.
    pub fn key(&self) -> impl Iterator<Item = impl AsRef<[Nibble]>> {
        // A `ClosestDescendantMerkleValue` is created directly in response to a `ClosestAncestor` without
        // updating the `Inner`.
        self.inner.current_node_full_key()
    }

    /// Returns the same value as [`ClosestDescendantMerkleValue::key`] but as a `Vec`.
    pub fn key_as_vec(&self) -> Vec<Nibble> {
        self.key().fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        })
    }

    /// Indicate that the closest descendant or its Merkle value is unknown and resume the
    /// calculation.
    ///
    /// This function be used if you are unaware of the Merkle value. The algorithm will perform
    /// the calculation of this Merkle value manually, which takes more time.
    pub fn resume_unknown(self) -> InProgress {
        // The element currently being iterated was `Btcd`, and is now switched to being
        // `MaybeNodeKey`. Because a `ClosestDescendantMerkleValue` is only ever created if the diff doesn't
        // contain any entry that descends the currently iterated node, we know for sure that
        // `MaybeNodeKey` is equal to `Btcd`.
        InProgress::ClosestDescendant(ClosestDescendant {
            inner: self.inner,
            key_extra_nibbles: Vec::new(),
            diff_inserts_lcd: None,
        })
    }

    /// Indicate the Merkle value of closest descendant of the trie node indicated by
    /// [`ClosestDescendantMerkleValue::key`] and resume the calculation.
    pub fn inject_merkle_value(self, merkle_value: &[u8]) -> InProgress {
        // We are after a call to `BaseTrieClosestDescendantMerkleValue` in the algorithm shown
        // at the top.

        // Check with a debug_assert! that this is a valid Merkle value. While this algorithm
        // doesn't actually care about the content, providing a wrong value clearly indicates a
        // bug somewhere in the API user's code.
        debug_assert!(merkle_value.len() == 32 || trie::trie_node::decode(merkle_value).is_ok());

        if !self.inner.stack.is_empty() {
            // If the element has a parent, add the Merkle value to its children and resume the
            // algorithm.
            self.inner
                .push_child_result(Some(trie::trie_node::MerkleValueOutput::from_bytes(
                    AsRef::as_ref(&merkle_value),
                )))
        } else {
            // If the element doesn't have a parent, then the Merkle value is the root of trie!
            // This should only ever happen if the diff is empty.
            debug_assert_eq!(self.inner.diff.diff_range_ordered::<Vec<u8>>(..).count(), 0);

            // The trie root hash is always 32 bytes. If not, it indicates a bug in the API user's
            // code.
            let trie_root_hash = <[u8; 32]>::try_from(AsRef::as_ref(&merkle_value))
                .unwrap_or_else(|_| panic!("invalid node value provided"));
            InProgress::Finished { trie_root_hash }
        }
    }
}

/// Event indicating that a trie node has been inserted or updated.
///
/// The API user has nothing to do, but they can use this event to update their local version of
/// the trie.
pub struct TrieNodeInsertUpdateEvent {
    inner: Box<Inner>,

    /// Partial key of the node that was inserted or updated.
    inserted_elem_partial_key: Vec<Nibble>,

    /// Merkle values of the children of the node that was inserted or updated.
    children: arrayvec::ArrayVec<Option<trie::trie_node::MerkleValueOutput>, 16>,

    /// Merkle value of the node that was inserted or updated.
    merkle_value: trie::trie_node::MerkleValueOutput,
}

impl TrieNodeInsertUpdateEvent {
    /// Returns the key of the trie node that was inserted or updated.
    pub fn key(&self) -> impl Iterator<Item = impl AsRef<[Nibble]>> {
        self.inner
            .current_node_full_key()
            .map(either::Left)
            .chain(iter::once(either::Right(&self.inserted_elem_partial_key)))
    }

    /// Returns the same value as [`TrieNodeInsertUpdateEvent::key`] but as a `Vec`.
    pub fn key_as_vec(&self) -> Vec<Nibble> {
        self.key().fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        })
    }

    /// Returns the new Merkle value of the trie node that was inserted or updated.
    pub fn merkle_value(&self) -> &[u8] {
        self.merkle_value.as_ref()
    }

    /// Returns the Merkle values of the children of the trie node that was inserted or updated.
    ///
    /// The iterator always yields exactly 16 elements. The yielded element is `None` if there is
    /// no child at this position.
    pub fn children_merkle_values(&self) -> impl ExactSizeIterator<Item = Option<&[u8]>> {
        self.children
            .iter()
            .map(|child| child.as_ref().map(|merkle_value| merkle_value.as_ref()))
    }

    /// Returns the partial key of the trie node that was inserted or updated.
    pub fn partial_key(&self) -> &[Nibble] {
        &self.inserted_elem_partial_key
    }

    /// Resume the computation.
    pub fn resume(self) -> InProgress {
        if !self.inner.stack.is_empty() {
            self.inner.push_child_result(Some(self.merkle_value))
        } else {
            // No more node in the stack means that this was the root node. The calculated
            // Merkle value is the trie root hash.
            InProgress::Finished {
                // Guaranteed to never panic for the root node.
                trie_root_hash: self.merkle_value.try_into().unwrap_or_else(|_| panic!()),
            }
        }
    }
}

/// Event indicating that a trie node has been destroyed.
///
/// The API user has nothing to do, but they can use this event to update their local version of
/// the trie.
pub struct TrieNodeRemoveEvent {
    inner: Box<Inner>,

    /// Element that was removed from the stack and that we know no longer exists.
    calculated_elem: InProgressNode,

    /// Why the node was removed.
    ty: TrieNodeRemoveEventTy,
}

enum TrieNodeRemoveEventTy {
    NoChildrenLeft,
    ReplacedWithSingleChild,
}

impl TrieNodeRemoveEvent {
    /// Returns the event to the API user, unless a re-walk is in progress. In that case the
    /// removal was already reported during the first walk, and the calculation simply continues.
    fn report_unless_rewalking(self) -> InProgress {
        if self.inner.rewalk_start_stack_len.is_some() {
            self.resume()
        } else {
            InProgress::TrieNodeRemoveEvent(self)
        }
    }

    /// Returns the key of the trie node that was removed.
    pub fn key(&self) -> impl Iterator<Item = impl AsRef<[Nibble]>> {
        self.inner
            .current_node_full_key()
            .map(either::Left)
            .chain(iter::once(either::Right(&self.calculated_elem.partial_key)))
    }

    /// Returns the same value as [`TrieNodeRemoveEvent::key`] but as a `Vec`.
    pub fn key_as_vec(&self) -> Vec<Nibble> {
        self.key().fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        })
    }

    /// Resume the computation.
    pub fn resume(mut self) -> InProgress {
        match self.ty {
            TrieNodeRemoveEventTy::NoChildrenLeft => {
                if !self.inner.stack.is_empty() {
                    self.inner.push_child_result(None)
                } else {
                    InProgress::Finished {
                        trie_root_hash: trie::EMPTY_BLAKE2_TRIE_MERKLE_VALUE,
                    }
                }
            }
            TrieNodeRemoveEventTy::ReplacedWithSingleChild => {
                // The subtree of the single child is walked again below. Removals in that
                // subtree were already reported during the first walk, so reporting is turned
                // off until the re-walk is over. An outer re-walk already in progress covers
                // this one, so it is left untouched.
                if self.inner.rewalk_start_stack_len.is_none() {
                    self.inner.rewalk_start_stack_len = Some(self.inner.stack.len());
                }

                let child_index = self
                    .calculated_elem
                    .children
                    .iter()
                    .position(|c| c.is_some())
                    .unwrap_or_else(|| panic!());

                let mut partial_key = self.calculated_elem.partial_key;
                partial_key.push(
                    Nibble::try_from(u8::try_from(child_index).unwrap_or_else(|_| panic!()))
                        .unwrap_or_else(|_| panic!()),
                );

                // Now calculate `LongestCommonDenominator(DiffInsertsNodesWithPrefix)`.
                let (_, diff_inserts_lcd) = diff_inserts_least_common_denominator(
                    &self.inner.diff,
                    self.inner
                        .current_node_full_key()
                        .map(either::Left)
                        .chain(iter::once(either::Right(&partial_key))),
                );

                InProgress::ClosestDescendant(ClosestDescendant {
                    inner: self.inner,
                    key_extra_nibbles: partial_key,
                    diff_inserts_lcd,
                })
            }
        }
    }
}

struct Inner {
    /// Stack of node entries whose value is currently being calculated. Every time
    /// `BaseTrieClosestDescendant` returns we push an element here.
    ///
    /// The node currently being iterated is either `Btcd` or `MaybeNodeValue` depending on where
    /// we are in the algorithm.
    ///
    /// If the entry at the top of the stack has `children.len() == 16`, then the node currently
    /// being iterated is the one at the top of the stack, otherwise it's the child of the one at
    /// the top of the stack whose entry is past the end of `children`.
    stack: Vec<InProgressNode>,

    /// Depth of [`Inner::stack`] when the current re-walk started, or `None` if no re-walk is
    /// in progress.
    ///
    /// A re-walk happens when a node is removed because it has a single child left (see
    /// [`TrieNodeRemoveEventTy::ReplacedWithSingleChild`]): the subtree of that child is walked
    /// a second time to recalculate its Merkle value. Removals in that subtree were already
    /// reported during the first walk, so they are not reported again while this is `Some`.
    ///
    /// The re-walk is over once the stack shrinks back to this depth, see
    /// [`Inner::push_child_result`].
    rewalk_start_stack_len: Option<usize>,

    /// Same value as [`Config::diff`].
    diff: TrieDiff,

    /// Same value as [`Config::diff_trie_entries_version`].
    diff_trie_entries_version: TrieEntryVersion,
}

#[derive(Debug)]
struct InProgressNode {
    /// Partial key of the node currently being calculated.
    partial_key: Vec<Nibble>,

    /// If `true`, the partial keys of the children of this node have changed compared to their
    /// values in the base trie.
    children_partial_key_changed: bool,

    /// Merkle values of the children of the node. Filled up to 16 elements, then the storage
    /// value is requested. Each element is `Some` or `None` depending on whether a child exists.
    children: arrayvec::ArrayVec<Option<trie::trie_node::MerkleValueOutput>, 16>,
}

impl Inner {
    /// Pushes the result of the node whose calculation just finished (`Some` with its Merkle
    /// value, or `None` if the node doesn't exist) to the children of the node at the top of
    /// the stack, then progresses the algorithm.
    ///
    /// Must only be called if the stack is not empty.
    fn push_child_result(
        mut self: Box<Self>,
        result: Option<trie::trie_node::MerkleValueOutput>,
    ) -> InProgress {
        let parent_node = self.stack.last_mut().unwrap_or_else(|| panic!());
        debug_assert_ne!(parent_node.children.len(), 16);
        parent_node.children.push(result);

        // If the stack is back at the depth where the re-walk started, the re-walk is over.
        if self.rewalk_start_stack_len == Some(self.stack.len()) {
            self.rewalk_start_stack_len = None;
        }

        self.next()
    }

    /// Analyzes the content of the [`Inner`] and progresses the algorithm.
    fn next(self: Box<Self>) -> InProgress {
        if self.stack.last().map_or(false, |n| n.children.len() == 16) {
            // Finished obtaining `MaybeChildren` and jumping to obtaining `MaybeStorageValue`.
            return InProgress::StorageValue(StorageValue(self));
        }

        // In the paths below, we want to obtain `MaybeChildren` and thus we're going to return
        // a `ClosestDescendant`.
        // Now calculate `ForceCalculate` and
        // `LongestCommonDenominator(DiffInsertsNodesWithPrefix)`.
        let (force_recalculate, diff_inserts_lcd) =
            diff_inserts_least_common_denominator(&self.diff, self.current_node_full_key());

        // If the diff doesn't contain any descendant, jump to calling `BaseTrieMerkleValue`.
        if !force_recalculate
            && diff_inserts_lcd.is_none()
            && self
                .stack
                .last()
                .map_or(true, |n| !n.children_partial_key_changed)
        {
            return InProgress::ClosestDescendantMerkleValue(ClosestDescendantMerkleValue {
                inner: self,
            });
        }

        InProgress::ClosestDescendant(ClosestDescendant {
            inner: self,
            key_extra_nibbles: Vec::new(),
            diff_inserts_lcd,
        })
    }

    /// Iterator of arrays which, when joined together, form the full key of the node currently
    /// being iterated.
    fn current_node_full_key(&self) -> impl Iterator<Item = impl AsRef<[Nibble]>> {
        self.stack.iter().flat_map(move |node| {
            let maybe_child_nibble_u8 =
                u8::try_from(node.children.len()).unwrap_or_else(|_| unreachable!());
            let child_nibble = Nibble::try_from(maybe_child_nibble_u8).ok();

            iter::once(either::Right(&node.partial_key))
                .chain(child_nibble.map(|n| either::Left([n])))
        })
    }
}

/// Given a diff and a prefix, returns:
///
/// - Whether the diff contains any entry starts with this prefix.
/// - The least common denominator of all the insertions that start with this prefix, or `None` if
///   there is no insertion.
///
fn diff_inserts_least_common_denominator(
    diff: &TrieDiff,
    prefix: impl Iterator<Item = impl AsRef<[Nibble]>>,
) -> (bool, Option<Vec<Nibble>>) {
    let mut force_recalculate = false;
    let mut diff_inserts_lcd = None::<Vec<Nibble>>;

    // TODO: could be optimized?
    let prefix_nibbles = prefix.fold(Vec::new(), |mut a, b| {
        a.extend_from_slice(b.as_ref());
        a
    });
    let prefix =
        trie::nibbles_to_bytes_suffix_extend(prefix_nibbles.iter().copied()).collect::<Vec<_>>();
    for (key, inserts_entry) in
        diff.diff_range_ordered::<[u8]>((ops::Bound::Included(&prefix[..]), ops::Bound::Unbounded))
    {
        let key = trie::bytes_to_nibbles(key.iter().copied()).collect::<Vec<_>>();
        if !key.starts_with(&prefix_nibbles) {
            break;
        }

        force_recalculate = true;

        if inserts_entry {
            diff_inserts_lcd = match diff_inserts_lcd.take() {
                Some(mut v) => {
                    let lcd = key.iter().zip(v.iter()).take_while(|(a, b)| a == b).count();
                    debug_assert!(lcd >= prefix_nibbles.len());
                    debug_assert_eq!(&key[..lcd], &v[..lcd]);
                    v.truncate(lcd);
                    Some(v)
                }
                None => Some(key),
            };
        }
    }

    (force_recalculate, diff_inserts_lcd)
}
