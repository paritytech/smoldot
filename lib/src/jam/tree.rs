// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Bounded, fork-aware storage of authenticated JAM headers.
//!
//! The trusted starting point is fixed; there is no finalization in the MVP.
//!
//! C1 maps query snapshots and insert results to light-base subscription types;
//! this library must not depend on light-base. An insertion with nonempty
//! `evicted` requires subscriber resnapshot/stop: the existing notifications
//! cannot express pruning without finalization. `Full` likewise signals stop.
//! No notification history is retained here.

use super::{
    params::Params,
    types::{Final, Hash, Header},
    verify::{VerifiedHeader, VerifyError, verify_header},
};
use crate::chain::fork_tree::{ForkTree, NodeIndex};
use alloc::vec::Vec;
use core::{iter, num::NonZeroUsize};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jam::{
        state::LightState,
        types::{SealingSequence, Ticket},
    };
    use alloc::vec;

    fn header(parent: u8, id: u8, slot: u32) -> Header {
        Header {
            parent: [parent; 32],
            prior_state_root: [0; 32],
            extrinsic_hash: [id; 32],
            slot,
            epoch_mark: None,
            tickets_mark: None,
            author_index: 0,
            entropy_source: [0; 96],
            offenders_mark: Vec::new(),
            seal: [0; 96],
        }
    }

    fn root() -> VerifiedHeader {
        VerifiedHeader {
            header: header(255, 0, 0),
            hash: [0; 32],
            slot: 0,
            sealed_with_ticket: false,
            epoch_changed: false,
            post_state: LightState {
                entropy: [[0; 32]; 4],
                active: vec![([1; 32], [2; 32])],
                pending: vec![([3; 32], [4; 32])],
                sealing: SealingSequence::Keys(vec![[5; 32]]),
                pending_tickets: Some(vec![Ticket {
                    id: [6; 32],
                    attempt: 0,
                }]),
                slot: 0,
            },
        }
    }

    fn params() -> Params {
        Params::from_protocol_parameters(&{
            let mut bytes = [0; 122];
            bytes[24] = 2;
            bytes
        })
        .unwrap()
    }

    fn config(capacity: usize) -> Config {
        Config {
            max_blocks: NonZeroUsize::new(capacity).unwrap(),
        }
    }

    fn verify(parent: &VerifiedHeader, header: Header) -> Result<VerifiedHeader, VerifyError> {
        let mut post_state = parent.post_state.clone();
        post_state.entropy.rotate_right(1);
        post_state.entropy[0] = header.extrinsic_hash;
        post_state.slot = header.slot;
        Ok(VerifiedHeader {
            hash: header.extrinsic_hash,
            slot: header.slot,
            sealed_with_ticket: true,
            epoch_changed: false,
            header,
            post_state,
        })
    }

    fn tree(capacity: usize) -> HeaderTree {
        let tree = HeaderTree::with_verifier(params(), root(), config(capacity), verify);
        check(&tree);
        tree
    }

    // Called before/after every insertion, including errors and duplicates.
    fn check(tree: &HeaderTree) {
        let mut seen = Vec::new();
        for block in tree.ancestry_order() {
            assert!(!seen.contains(&block.hash));
            if block.hash != tree.finalized().hash {
                assert!(
                    seen.contains(&block.header.parent),
                    "dangling/out-of-order parent"
                );
            } else {
                assert!(seen.is_empty());
            }
            seen.push(block.hash);
            assert_eq!(tree.get(&block.hash), Some(block));
            let ancestors: Vec<_> = tree.ancestors(&block.hash).collect();
            assert_eq!(ancestors.first().copied(), Some(block));
            assert_eq!(ancestors.last().copied(), Some(tree.finalized()));
        }
        assert_eq!(seen.len(), tree.len());
        assert!(tree.len() <= tree.config.max_blocks.get());
        assert!(!tree.is_empty());
        assert_eq!(tree.finalized(), &tree.root);
        let leaves = tree.leaves();
        assert!(leaves.iter().any(|leaf| leaf.hash == tree.best().hash));
        assert!(leaves.iter().all(|leaf| leaf.slot <= tree.best().slot));
        for block in tree.ancestry_order() {
            let has_children = tree
                .ancestry_order()
                .skip(1)
                .any(|b| b.header.parent == block.hash);
            assert_eq!(
                leaves.iter().any(|leaf| leaf.hash == block.hash),
                !has_children
            );
        }
        assert_eq!(tree.ancestors(&[254; 32]).count(), 0);
        assert!(!tree.is_ancestor(&[254; 32], &[254; 32]));
    }

    fn insert(tree: &mut HeaderTree, parent: u8, header: Header) -> Result<Insert, InsertError> {
        insert_at(tree, [parent; 32], header, 1_000)
    }

    fn insert_at(
        tree: &mut HeaderTree,
        parent: Hash,
        header: Header,
        now: u64,
    ) -> Result<Insert, InsertError> {
        check(tree);
        let before: Vec<_> = tree.ancestry_order().cloned().collect();
        let best = tree.best().hash;
        let root = tree.finalized().clone();
        let result = tree.insert(parent, header, now);
        assert_eq!(tree.finalized(), &root);
        if result.is_err() || matches!(result, Ok(Insert::AlreadyKnown)) {
            assert_eq!(tree.ancestry_order().cloned().collect::<Vec<_>>(), before);
            assert_eq!(tree.best().hash, best);
        }
        check(tree);
        result
    }

    fn add(tree: &mut HeaderTree, parent: u8, id: u8, slot: u32) -> Insert {
        insert(tree, parent, header(parent, id, slot)).unwrap()
    }

    #[test]
    fn linear_and_root_queries() {
        let mut tree = tree(5);
        assert_eq!(
            tree.leaves(),
            vec![Final {
                hash: [0; 32],
                slot: 0
            }]
        );
        for id in 1..5 {
            add(&mut tree, id - 1, id, u32::from(id));
        }
        assert_eq!(tree.best().hash, [4; 32]);
        assert_eq!(
            tree.ancestors(&[4; 32]).map(|b| b.hash).collect::<Vec<_>>(),
            (0..5).rev().map(|id| [id; 32]).collect::<Vec<_>>()
        );
        assert!(tree.is_ancestor(&[0; 32], &[4; 32]));
        assert!(tree.is_ancestor(&[4; 32], &[4; 32]));
        assert!(!tree.is_ancestor(&[4; 32], &[0; 32]));
    }

    #[test]
    fn forks_switch_best_and_keep_ties_and_post_states() {
        let mut tree = tree(9);
        add(&mut tree, 0, 1, 1);
        add(&mut tree, 1, 2, 3);
        add(&mut tree, 0, 3, 2);
        assert_eq!(tree.best().hash, [2; 32]);
        add(&mut tree, 3, 4, 4);
        assert_eq!(tree.best().hash, [4; 32]);
        add(&mut tree, 2, 5, 4);
        assert_eq!(tree.best().hash, [4; 32]);
        add(&mut tree, 0, 6, 10); // Late fork immediately becomes best.
        assert_eq!(tree.best().hash, [6; 32]);
        assert!(!tree.is_ancestor(&[3; 32], &[5; 32]));
        assert_eq!(
            tree.get(&[4; 32]).unwrap().post_state.entropy,
            [[4; 32], [3; 32], [0; 32], [0; 32]]
        );
        assert_eq!(
            tree.get(&[5; 32]).unwrap().post_state.entropy,
            [[5; 32], [2; 32], [1; 32], [0; 32]]
        );
        assert_eq!(
            tree.get(&[5; 32]).unwrap().post_state.pending,
            root().post_state.pending
        );
    }

    #[test]
    fn capacity_prunes_lowest_leaf_chain_to_branch_point() {
        let mut tree = tree(7);
        add(&mut tree, 0, 1, 1);
        add(&mut tree, 1, 2, 2);
        add(&mut tree, 2, 3, 3);
        add(&mut tree, 1, 4, 4);
        add(&mut tree, 0, 5, 10);
        add(&mut tree, 5, 6, 11);
        assert_eq!(
            add(&mut tree, 6, 7, 12),
            Insert::Inserted {
                hash: [7; 32],
                is_new_best: true,
                evicted: vec![[3; 32], [2; 32]],
            }
        );
        assert!(tree.get(&[1; 32]).is_some());
        assert!(tree.get(&[4; 32]).is_some());
        assert!(tree.get(&[2; 32]).is_none());
        assert_eq!(tree.len(), 6);
    }

    #[test]
    fn capacity_protects_incoming_parent_and_old_best_ancestors() {
        let mut tree = tree(5);
        add(&mut tree, 0, 1, 1);
        add(&mut tree, 1, 2, 2);
        add(&mut tree, 0, 3, 9);
        add(&mut tree, 3, 4, 10);
        assert_eq!(
            add(&mut tree, 1, 5, 11),
            Insert::Inserted {
                hash: [5; 32],
                is_new_best: true,
                evicted: vec![[2; 32]],
            }
        );
        assert!(tree.get(&[1; 32]).is_some());
        assert!(tree.get(&[3; 32]).is_some());
        assert!(tree.get(&[4; 32]).is_some());
        // Incoming parent is itself a leaf: it cannot be an eviction candidate.
        let mut tree = self::tree(3);
        add(&mut tree, 0, 1, 1);
        add(&mut tree, 0, 2, 2);
        assert_eq!(
            insert(&mut tree, 1, header(1, 3, 3)),
            Err(InsertError::Full)
        );
    }

    #[test]
    fn full_linear_non_best_and_duplicate_insertions() {
        let mut tree = tree(3);
        add(&mut tree, 0, 1, 1);
        add(&mut tree, 1, 2, 2);
        assert_eq!(
            insert(&mut tree, 2, header(2, 3, 3)),
            Err(InsertError::Full)
        );
        assert_eq!(
            insert(&mut tree, 0, header(0, 4, 1)),
            Err(InsertError::Full)
        );
        assert_eq!(
            insert(&mut tree, 0, header(0, 5, 2)),
            Err(InsertError::Full)
        );
        assert_eq!(
            insert(&mut tree, 0, header(0, 1, 1)),
            Ok(Insert::AlreadyKnown)
        );
        assert_eq!(
            insert(&mut tree, 255, root().header),
            Ok(Insert::AlreadyKnown)
        );
        let mut root_only = self::tree(1);
        assert_eq!(
            insert(&mut root_only, 0, header(0, 1, 1)),
            Err(InsertError::Full)
        );
        assert_eq!(
            insert(&mut root_only, 255, root().header),
            Ok(Insert::AlreadyKnown)
        );
    }

    #[test]
    fn errors_are_atomic_including_verifier_contract_violations() {
        let mut tree = tree(2);
        add(&mut tree, 0, 1, 1);
        assert_eq!(
            insert(&mut tree, 99, header(99, 2, 2)),
            Err(InsertError::UnknownParent)
        );
        assert_eq!(
            insert(&mut tree, 0, header(1, 2, 2)),
            Err(InsertError::ParentMismatch)
        );
        assert_eq!(
            insert(&mut tree, 0, header(1, 1, 1)),
            Err(InsertError::ParentMismatch)
        );
        assert_eq!(
            insert(&mut tree, 1, header(1, 2, 1)),
            Err(InsertError::InvalidVerifiedSlot)
        );
        tree.verifier = Some(alloc::boxed::Box::new(|_, _| {
            Err(VerifyError::SlotInFuture)
        }));
        assert!(matches!(
            insert(&mut tree, 1, header(1, 2, 2)),
            Err(InsertError::Verify(VerifyError::SlotInFuture))
        ));
        // Known headers do not call even a failing verifier.
        assert_eq!(
            insert(&mut tree, 0, header(0, 1, 1)),
            Ok(Insert::AlreadyKnown)
        );
        tree.verifier = Some(alloc::boxed::Box::new(|parent, mut h| {
            h.parent = [99; 32];
            verify(parent, h)
        }));
        assert_eq!(
            insert(&mut tree, 1, header(1, 2, 2)),
            Err(InsertError::ParentMismatch)
        );
    }

    #[test]
    fn uses_verified_score_not_untrusted_header_slot() {
        let mut tree = HeaderTree::with_verifier(params(), root(), config(4), |parent, h| {
            let mut verified = verify(parent, h)?;
            verified.slot = u32::from(verified.hash[0]);
            Ok(verified)
        });
        add(&mut tree, 0, 2, 100);
        add(&mut tree, 0, 1, 200);
        assert_eq!(tree.best().hash, [2; 32]);
    }

    #[test]
    fn ten_times_bound_with_repeated_evictions_and_rejections() {
        let mut tree = tree(8);
        for id in 1..=80 {
            add(&mut tree, 0, id, u32::from(id));
            assert_eq!(tree.best().hash, [id; 32]);
        }
        let mut linear = self::tree(8);
        for id in 1..=80 {
            let parent = linear.best().hash[0];
            let result = insert(&mut linear, parent, header(parent, id, u32::from(id)));
            if id >= 8 {
                assert_eq!(result, Err(InsertError::Full));
            } else {
                assert!(result.is_ok());
            }
        }
    }

    #[test]
    fn production_constructor_accepts_sealed_child() {
        let (params, root, child, now) = HeaderTree::signed_child_fixture();
        let hash = child.hash(&params);
        let parent = root.hash;
        let mut tree = HeaderTree::new(params, root.clone(), config(2));
        assert!(tree.verifier.is_none());
        assert!(matches!(
            insert_at(&mut tree, parent, child.clone(), 0),
            Err(InsertError::Verify(VerifyError::SlotInFuture))
        ));
        assert_eq!(
            insert_at(&mut tree, parent, child.clone(), now).unwrap(),
            Insert::Inserted {
                hash,
                is_new_best: true,
                evicted: Vec::new(),
            }
        );
        let stored = tree.get(&hash).unwrap();
        assert_eq!(stored.header, child);
        assert_eq!(stored.hash, hash);
        assert_eq!(stored.slot, child.slot);
        assert!(!stored.sealed_with_ticket);
        assert!(!stored.epoch_changed);
        assert_eq!(stored.post_state.slot, child.slot);
        assert_ne!(stored.post_state.entropy[0], root.post_state.entropy[0]);
        assert_eq!(stored.post_state.entropy[1..], root.post_state.entropy[1..]);
        assert_eq!(stored.post_state.active, root.post_state.active);
        assert_eq!(stored.post_state.pending, root.post_state.pending);
        assert_eq!(stored.post_state.sealing, root.post_state.sealing);
        assert_eq!(
            stored.post_state.pending_tickets,
            root.post_state.pending_tickets
        );
        assert_eq!(tree.best().hash, hash);
        assert_eq!(tree.len(), 2);
        assert_eq!(
            insert_at(&mut tree, parent, child, now).unwrap(),
            Insert::AlreadyKnown
        );
        assert_eq!(
            insert_at(&mut tree, root.header.parent, root.header, now).unwrap(),
            Insert::AlreadyKnown
        );
    }

    #[test]
    fn production_constructor_rejects_unsealed_and_malformed_seals() {
        let (params, root, child, now) = HeaderTree::signed_child_fixture();
        let parent = root.hash;
        let mut tree = HeaderTree::new(params, root, config(2));
        let mut unsealed = child.clone();
        unsealed.seal = [0; 96];
        let mut malformed = child.clone();
        malformed.seal[70] ^= 1;
        let mut tampered = child.clone();
        tampered.prior_state_root[0] ^= 1;
        for header in [unsealed, malformed, tampered] {
            assert!(matches!(
                insert_at(&mut tree, parent, header, now),
                Err(InsertError::Verify(VerifyError::BadSealSignature(_)))
            ));
        }
        assert!(matches!(
            insert_at(&mut tree, parent, child, now),
            Ok(Insert::Inserted {
                is_new_best: true,
                ..
            })
        ));
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Maximum stored blocks, including the starting point. Must be nonzero.
    pub max_blocks: NonZeroUsize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Insert {
    Inserted {
        hash: Hash,
        is_new_best: bool,
        /// Removed hashes, child before parent; bounded by `max_blocks`.
        evicted: Vec<Hash>,
    },
    AlreadyKnown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertError {
    UnknownParent,
    ParentMismatch,
    Verify(VerifyError),
    /// A verifier violated its structural contract (strictly increasing slots).
    InvalidVerifiedSlot,
    Full,
}

/// A fixed root plus verified descendants. Queries never expose mutable state.
/// Best is the highest verified slot; equal slots retain the earlier insertion.
/// Lookups are linear; eviction rebuilds the bounded tree in quadratic time.
pub struct HeaderTree {
    params: Params,
    config: Config,
    root: VerifiedHeader,
    blocks: ForkTree<VerifiedHeader>,
    best: Option<NodeIndex>,
    #[cfg(test)]
    verifier: Option<alloc::boxed::Box<TestVerifier>>,
}

#[cfg(test)]
type TestVerifier = dyn Fn(&VerifiedHeader, Header) -> Result<VerifiedHeader, VerifyError>;

impl HeaderTree {
    /// Starts at a caller-trusted authenticated checkpoint/genesis.
    pub fn new(params: Params, root: VerifiedHeader, config: Config) -> Self {
        Self {
            params,
            config,
            root,
            blocks: ForkTree::new(),
            best: None,
            #[cfg(test)]
            verifier: None,
        }
    }

    #[cfg(test)]
    fn with_verifier(
        params: Params,
        root: VerifiedHeader,
        config: Config,
        verifier: impl Fn(&VerifiedHeader, Header) -> Result<VerifiedHeader, VerifyError> + 'static,
    ) -> Self {
        let mut tree = Self::new(params, root, config);
        tree.verifier = Some(alloc::boxed::Box::new(verifier));
        tree
    }

    fn verify(
        &self,
        parent: &VerifiedHeader,
        header: Header,
        now_unix_secs: u64,
    ) -> Result<VerifiedHeader, VerifyError> {
        #[cfg(test)]
        if let Some(verifier) = &self.verifier {
            return verifier(parent, header);
        }
        verify_header(&self.params, parent, header, now_unix_secs)
    }

    /// Inserts atomically. Time is Unix seconds, passed to the verifier.
    /// Exact duplicates (including the root) succeed even at capacity and do
    /// not reverify. A mismatched explicit parent is always rejected first.
    pub fn insert(
        &mut self,
        parent_hash: Hash,
        header: Header,
        now_unix_secs: u64,
    ) -> Result<Insert, InsertError> {
        if header.parent != parent_hash {
            return Err(InsertError::ParentMismatch);
        }
        if self.ancestry_order().any(|block| block.header == header) {
            return Ok(Insert::AlreadyKnown);
        }
        let parent = self.get(&parent_hash).ok_or(InsertError::UnknownParent)?;
        let verified = self
            .verify(parent, header, now_unix_secs)
            .map_err(InsertError::Verify)?;
        if verified.header.parent != parent_hash {
            return Err(InsertError::ParentMismatch);
        }
        if self.get(&verified.hash).is_some() {
            return Ok(Insert::AlreadyKnown);
        }
        if verified.slot <= parent.slot {
            return Err(InsertError::InvalidVerifiedSlot);
        }
        let is_new_best = verified.slot > self.best().slot;
        let evicted = if self.len() == self.config.max_blocks.get() {
            if !is_new_best {
                return Err(InsertError::Full);
            }
            self.eviction_chain(&parent_hash).ok_or(InsertError::Full)?
        } else {
            Vec::new()
        };

        // ForkTree only offers finalization-style pruning. Rebuild survivors
        // rather than using those operations, which could discard other forks.
        // Build before committing so any structural failure remains atomic.
        let mut rebuilt = if evicted.is_empty() {
            None
        } else {
            let mut blocks: ForkTree<VerifiedHeader> = ForkTree::new();
            for block in self.ancestry_order().skip(1) {
                if evicted.contains(&block.hash) {
                    continue;
                }
                let parent = if block.header.parent == self.root.hash {
                    None
                } else {
                    Some(
                        blocks
                            .find(|b| b.hash == block.header.parent)
                            .ok_or(InsertError::UnknownParent)?,
                    )
                };
                blocks.insert(parent, block.clone());
            }
            Some(blocks)
        };
        let blocks = rebuilt.as_mut().unwrap_or(&mut self.blocks);
        let parent = if parent_hash == self.root.hash {
            None
        } else {
            Some(
                blocks
                    .find(|b| b.hash == parent_hash)
                    .ok_or(InsertError::UnknownParent)?,
            )
        };
        let hash = verified.hash;
        let index = blocks.insert(parent, verified);
        if let Some(rebuilt) = rebuilt {
            self.blocks = rebuilt;
        }
        // Every rebuild accompanies a new best, so no old index survives it.
        if is_new_best {
            self.best = Some(index);
        }
        Ok(Insert::Inserted {
            hash,
            is_new_best,
            evicted,
        })
    }

    fn eviction_chain(&self, incoming_parent: &Hash) -> Option<Vec<Hash>> {
        let best = self.best().hash;
        let (mut index, _) = self
            .blocks
            .iter_unordered()
            .filter(|(index, block)| {
                self.blocks.children(Some(*index)).next().is_none()
                    && !self.is_ancestor(&block.hash, &best)
                    && !self.is_ancestor(&block.hash, incoming_parent)
            })
            .min_by_key(|(_, block)| (block.slot, block.hash))?;
        let mut removed = Vec::new();
        loop {
            removed.push(self.blocks.get(index)?.hash);
            let Some(parent) = self.blocks.parent(index) else {
                break;
            };
            let block = self.blocks.get(parent)?;
            if self.blocks.children(Some(parent)).count() != 1
                || self.is_ancestor(&block.hash, &best)
                || self.is_ancestor(&block.hash, incoming_parent)
            {
                break;
            }
            index = parent;
        }
        Some(removed)
    }

    /// Looks up any retained block, including the root.
    pub fn get(&self, hash: &Hash) -> Option<&VerifiedHeader> {
        if *hash == self.root.hash {
            Some(&self.root)
        } else {
            self.blocks
                .iter_unordered()
                .find_map(|(_, block)| (block.hash == *hash).then_some(block))
        }
    }

    /// The starting point, which never changes.
    pub fn finalized(&self) -> &VerifiedHeader {
        &self.root
    }

    /// Highest-slot leaf; the root is best only when there are no descendants.
    pub fn best(&self) -> &VerifiedHeader {
        self.best
            .and_then(|index| self.blocks.get(index))
            .unwrap_or(&self.root)
    }

    /// Number of retained blocks, including the root.
    pub fn len(&self) -> usize {
        self.blocks.len() + 1
    }

    /// Always false: the root cannot be removed.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Root first, then every retained descendant exactly once, parent before
    /// child. Sibling ordering is unspecified (not insertion order).
    pub fn ancestry_order(&self) -> impl Iterator<Item = &VerifiedHeader> {
        iter::once(&self.root).chain(self.blocks.iter_ancestry_order().map(|(_, block)| block))
    }

    /// Self-inclusive path from `hash` back to and including the root.
    /// Unknown hashes yield an empty iterator. The root's external parent is
    /// deliberately not followed.
    pub fn ancestors(&self, hash: &Hash) -> impl Iterator<Item = &VerifiedHeader> {
        iter::successors(self.get(hash), |block| {
            if block.hash == self.root.hash {
                None
            } else {
                self.get(&block.header.parent)
            }
        })
    }

    /// Self-inclusive ancestry. False if either hash is unknown.
    pub fn is_ancestor(&self, ancestor: &Hash, descendant: &Hash) -> bool {
        self.ancestors(descendant)
            .any(|block| block.hash == *ancestor)
    }

    /// UP 0 leaves, in unspecified order. Includes the root only when it is
    /// the sole stored block; otherwise includes only non-finalized leaves.
    pub fn leaves(&self) -> Vec<Final> {
        if self.blocks.is_empty() {
            return alloc::vec![Final {
                hash: self.root.hash,
                slot: self.root.slot
            }];
        }
        self.blocks
            .iter_unordered()
            .filter(|(index, _)| self.blocks.children(Some(*index)).next().is_none())
            .map(|(_, block)| Final {
                hash: block.hash,
                slot: block.slot,
            })
            .collect()
    }
}
