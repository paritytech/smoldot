// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Bounded, fork-aware storage of authenticated JAM headers.
//!
//! The trusted starting point advances only with verified GRANDPA evidence.
//!
//! C1 maps query snapshots and insert results to light-base subscription types;
//! this library must not depend on light-base. An insertion with nonempty
//! `evicted` requires subscriber resnapshot/stop: the existing notifications
//! cannot express pruning without finalization. `Full` likewise signals stop.
//! No notification history is retained here.

use super::{
    finality::{self, AuthoritySet, VerifiedFinality},
    params::Params,
    types::{Final, Hash, Header},
    verify::{VerifiedHeader, VerifyError, verify_header},
};
use crate::chain::fork_tree::{ForkTree, NodeIndex};
use alloc::{collections::BTreeMap, vec::Vec};
use core::{iter, num::NonZeroUsize};

#[cfg(test)]
#[path = "tree/finality_tests.rs"]
mod finality_tests;

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
            encoded: header(255, 0, 0).encode(&params()),
            parent: [255; 32],
            hash: [0; 32],
            slot: 0,
            sealed_with_ticket: false,
            epoch_changed: false,
            post_state: LightState::from_parts(
                [[0; 32]; 4],
                vec![([1; 32], [2; 32])],
                vec![([3; 32], [4; 32])],
                SealingSequence::Keys(vec![[5; 32]]),
                Some(vec![Ticket {
                    id: [6; 32],
                    attempt: 0,
                }]),
                0,
            ),
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
            max_bytes: usize::MAX,
            max_epoch_records: core::num::NonZeroUsize::new(8).unwrap(),
        }
    }

    fn verify(parent: &VerifiedHeader, header: Header) -> Result<VerifiedHeader, VerifyError> {
        let mut post_state = parent.post_state.clone();
        let mut entropy = post_state.entropy();
        entropy.rotate_right(1);
        entropy[0] = header.extrinsic_hash;
        post_state.set_entropy(entropy);
        post_state.set_slot(header.slot);
        Ok(VerifiedHeader {
            hash: header.extrinsic_hash,
            slot: header.slot,
            sealed_with_ticket: true,
            epoch_changed: false,
            encoded: header.encode(&params()),
            parent: header.parent,
            post_state,
        })
    }

    fn tree(capacity: usize) -> HeaderTree {
        let mut tree = HeaderTree::with_verifier(params(), root(), config(capacity), verify);
        tree.test_hasher = Some(|header| header.extrinsic_hash);
        check(&tree);
        tree
    }

    #[test]
    fn constructor_checks_root_and_slab_before_allocating() {
        let root = root();
        let mut limits = config(4);
        limits.max_bytes = 0;
        assert!(matches!(
            HeaderTree::new(params(), root.clone(), limits),
            Err(InsertError::Full)
        ));
        limits.max_bytes = usize::MAX;
        let measured = HeaderTree::new(params(), root.clone(), limits)
            .unwrap()
            .retained_bytes();
        limits.max_bytes = measured - 1;
        assert!(matches!(
            HeaderTree::new(params(), root.clone(), limits),
            Err(InsertError::Full)
        ));
        limits.max_bytes = measured;
        let mut tree = HeaderTree::new(params(), root.clone(), limits).unwrap();
        assert_eq!(tree.retained_bytes(), measured);
        assert_eq!(
            tree.insert_verified(root.parent, root.clone()),
            Ok(Insert::AlreadyKnown)
        );
        assert_eq!(
            tree.insert_verified([99; 32], root.clone()),
            Err(InsertError::ParentMismatch)
        );
        limits.max_blocks = NonZeroUsize::new(usize::MAX).unwrap();
        limits.max_bytes = usize::MAX;
        assert!(matches!(
            HeaderTree::new(params(), root, limits),
            Err(InsertError::Full)
        ));
    }

    #[test]
    fn byte_limit_rejects_atomically_and_charges_ticket_allocations_once() {
        let mut tree = tree(4);
        let initial = tree.retained_bytes();
        let mut child = tree.finalized().clone();
        child.encoded = header(0, 1, 1).encode(&params());
        child.parent = [0; 32];
        child.hash = [1; 32];
        child.slot = 1;
        tree.config.max_bytes = initial;
        assert_eq!(
            tree.insert_verified([0; 32], child.clone()),
            Err(InsertError::Full)
        );
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.retained_bytes(), initial);
        let exact = tree.accounting(Some(&child.clone()), &[]).0;
        tree.config.max_bytes = exact;
        tree.insert_verified([0; 32], child.clone()).unwrap();
        assert_eq!(tree.retained_bytes(), exact);
        assert_eq!(tree.epoch_records(), 1);
        child.hash = [2; 32];
        child.encoded = header(0, 2, 1).encode(&params());
        let shared = tree.accounting(Some(&child), &[]).0;
        child.post_state.set_pending_tickets(&[Ticket {
            id: [6; 32],
            attempt: 0,
        }]);
        assert_eq!(
            tree.accounting(Some(&child), &[]).0 - shared,
            (core::mem::size_of::<Ticket>() + 2 * core::mem::size_of::<usize>())
                .next_multiple_of(core::mem::align_of::<usize>())
        );
    }

    #[test]
    fn duplicates_skip_verification_by_hash() {
        let calls = alloc::rc::Rc::new(core::cell::Cell::new(0));
        let counter = calls.clone();
        let p = params();
        let mut tree =
            HeaderTree::with_verifier(p.clone(), root(), config(4), move |parent, header| {
                counter.set(counter.get() + 1);
                let mut verified = verify(parent, header)?;
                verified.hash = super::super::crypto::blake2b_256(&verified.encoded);
                Ok(verified)
            });
        let header = header(0, 1, 1);
        tree.insert(header.parent, header.clone(), 0).unwrap();
        assert_eq!(
            tree.insert(header.parent, header, 0),
            Ok(Insert::AlreadyKnown)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn hundred_real_verified_markless_headers_share_one_dev_epoch() {
        // Dev epochs have only twelve slots: siblings let us retain 100 genuine
        // signatures in one epoch without changing the chain's parameters.
        let (params, root, headers, now) = HeaderTree::signed_markless_fixtures();
        let record = root.post_state.epoch_allocation().1;
        let mut tree = HeaderTree::new(params, root, config(101)).unwrap();
        let before = tree.retained_bytes();
        for header in headers {
            tree.insert(header.parent, header, now).unwrap();
        }
        let growth = (tree.retained_bytes() - before) / 100;
        let amortized =
            growth + core::mem::size_of::<VerifiedHeader>() + 10 * core::mem::size_of::<usize>();
        assert_eq!(tree.epoch_records(), 1);
        assert!(growth < 1024);
        assert!(amortized < 1024);
        std::println!(
            "D13 dev: 100 real markless headers; incremental={growth} bytes/node, amortized node={} bytes, epoch record={record} bytes",
            amortized
        );
    }

    // Called before/after every insertion, including errors and duplicates.
    fn check(tree: &HeaderTree) {
        let mut seen = Vec::new();
        for block in tree.ancestry_order() {
            assert!(!seen.contains(&block.hash));
            if block.hash != tree.finalized().hash {
                assert!(seen.contains(&block.parent), "dangling/out-of-order parent");
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
                .any(|b| b.parent == block.hash);
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
            tree.get(&[4; 32]).unwrap().post_state.entropy(),
            [[4; 32], [3; 32], [0; 32], [0; 32]]
        );
        assert_eq!(
            tree.get(&[5; 32]).unwrap().post_state.entropy(),
            [[5; 32], [2; 32], [1; 32], [0; 32]]
        );
        assert_eq!(
            tree.get(&[5; 32]).unwrap().post_state.epoch().pending,
            root().post_state.epoch().pending
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
            insert(
                &mut tree,
                255,
                Header::decode(&params(), &root().encoded).unwrap()
            ),
            Ok(Insert::AlreadyKnown)
        );
        let mut root_only = self::tree(1);
        assert_eq!(
            insert(&mut root_only, 0, header(0, 1, 1)),
            Err(InsertError::Full)
        );
        assert_eq!(
            insert(
                &mut root_only,
                255,
                Header::decode(&params(), &root().encoded).unwrap()
            ),
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
        let mut tree = HeaderTree::new(params, root.clone(), config(2)).unwrap();
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
        assert_eq!(
            Header::decode(&tree.params, &stored.encoded).unwrap(),
            child
        );
        assert_eq!(stored.hash, hash);
        assert_eq!(stored.slot, child.slot);
        assert!(!stored.sealed_with_ticket);
        assert!(!stored.epoch_changed);
        assert_eq!(stored.post_state.slot(), child.slot);
        assert_ne!(stored.post_state.entropy()[0], root.post_state.entropy()[0]);
        assert_eq!(
            stored.post_state.entropy()[1..],
            root.post_state.entropy()[1..]
        );
        assert_eq!(
            stored.post_state.epoch().active,
            root.post_state.epoch().active
        );
        assert_eq!(
            stored.post_state.epoch().pending,
            root.post_state.epoch().pending
        );
        assert_eq!(
            stored.post_state.epoch().sealing,
            root.post_state.epoch().sealing
        );
        assert_eq!(
            stored.post_state.pending_tickets(),
            root.post_state.pending_tickets()
        );
        assert_eq!(tree.best().hash, hash);
        assert_eq!(tree.len(), 2);
        assert_eq!(
            insert_at(&mut tree, parent, child, now).unwrap(),
            Insert::AlreadyKnown
        );
        let root_header = Header::decode(&tree.params, &root.encoded).unwrap();
        assert_eq!(
            insert_at(&mut tree, root.parent, root_header, now).unwrap(),
            Insert::AlreadyKnown
        );
    }

    #[test]
    fn production_constructor_rejects_unsealed_and_malformed_seals() {
        let (params, root, child, now) = HeaderTree::signed_child_fixture();
        let parent = root.hash;
        let mut tree = HeaderTree::new(params, root, config(2)).unwrap();
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
    /// Retained allocation budget, including shared records and index metadata.
    pub max_bytes: usize,
    /// Maximum distinct shared epoch records (including the root's).
    pub max_epoch_records: NonZeroUsize,
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

/// A finalized root plus verified descendants. Queries never expose mutable state.
/// Best is the highest verified slot; equal slots retain the earlier insertion.
/// Hash-indexed lookups; eviction rebuilds the bounded tree.
pub struct HeaderTree {
    params: Params,
    config: Config,
    root: VerifiedHeader,
    blocks: ForkTree<VerifiedHeader>,
    best: Option<NodeIndex>,
    index: BTreeMap<Hash, NodeIndex>,
    #[cfg(test)]
    verifier: Option<alloc::boxed::Box<TestVerifier>>,
    #[cfg(test)]
    test_hasher: Option<fn(&Header) -> Hash>,
}

#[cfg(test)]
type TestVerifier = dyn Fn(&VerifiedHeader, Header) -> Result<VerifiedHeader, VerifyError>;

/// Changes from a verified root advancement. Hashes never include the old root.
#[derive(Debug)]
pub struct Finalized {
    /// Newly finalized hashes in ascending ancestry order, ending at the new root.
    pub finalized: Vec<Hash>,
    /// Discarded forks, not ancestors that became finalized.
    pub pruned: Vec<Hash>,
    pub best_changed: bool,
}

impl HeaderTree {
    /// Starts at a caller-trusted authenticated checkpoint/genesis.
    pub fn new(params: Params, root: VerifiedHeader, config: Config) -> Result<Self, InsertError> {
        let slot = core::mem::size_of::<VerifiedHeader>() + 10 * core::mem::size_of::<usize>();
        config
            .max_blocks
            .get()
            .checked_mul(slot)
            .ok_or(InsertError::Full)?;
        let mut tree = Self {
            params,
            config,
            root,
            blocks: ForkTree::new(),
            best: None,
            index: BTreeMap::new(),
            #[cfg(test)]
            verifier: None,
            #[cfg(test)]
            test_hasher: None,
        };
        if tree.retained_bytes() > config.max_bytes {
            return Err(InsertError::Full);
        }
        tree.blocks = ForkTree::with_capacity(config.max_blocks.get() - 1);
        Ok(tree)
    }

    #[cfg(test)]
    fn with_verifier(
        params: Params,
        root: VerifiedHeader,
        config: Config,
        verifier: impl Fn(&VerifiedHeader, Header) -> Result<VerifiedHeader, VerifyError> + 'static,
    ) -> Self {
        let mut tree = Self::new(params, root, config).unwrap();
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
        let hash = header.hash(&self.params);
        #[cfg(test)]
        let hash = self.test_hasher.map_or(hash, |hash| hash(&header));
        if self.get(&hash).is_some() {
            return Ok(Insert::AlreadyKnown);
        }
        let parent = self.get(&parent_hash).ok_or(InsertError::UnknownParent)?;
        let verified = self
            .verify(parent, header, now_unix_secs)
            .map_err(InsertError::Verify)?;
        self.insert_verified(parent_hash, verified)
    }

    /// Inserts a header already authenticated by the caller against its retained
    /// parent. Like `new`'s trusted root, this bypasses cryptographic verification;
    /// callers must uphold the `VerifiedHeader` contract. Capacity, ancestry,
    /// duplicate and slot checks remain identical to `insert`.
    pub fn insert_verified(
        &mut self,
        parent_hash: Hash,
        verified: VerifiedHeader,
    ) -> Result<Insert, InsertError> {
        if verified.parent != parent_hash {
            return Err(InsertError::ParentMismatch);
        }
        if self.get(&verified.hash).is_some() {
            return Ok(Insert::AlreadyKnown);
        }
        let parent = self.get(&parent_hash).ok_or(InsertError::UnknownParent)?;
        if verified.slot <= parent.slot {
            return Err(InsertError::InvalidVerifiedSlot);
        }
        let is_new_best = verified.slot > self.best().slot;
        let prospective = self.accounting(Some(&verified), &[]);
        let evicted = if self.len() >= self.config.max_blocks.get()
            || prospective.0 > self.config.max_bytes
            || prospective.1 > self.config.max_epoch_records.get()
        {
            if !is_new_best {
                return Err(InsertError::Full);
            }
            self.eviction_chain(&parent_hash).ok_or(InsertError::Full)?
        } else {
            Vec::new()
        };
        let prospective = self.accounting(Some(&verified), &evicted);
        if prospective.0 > self.config.max_bytes
            || prospective.1 > self.config.max_epoch_records.get()
        {
            return Err(InsertError::Full);
        }

        // ForkTree only offers finalization-style pruning. Rebuild survivors
        // rather than using those operations, which could discard other forks.
        // Build before committing so any structural failure remains atomic.
        let mut rebuilt_index = BTreeMap::new();
        let mut rebuilt = if evicted.is_empty() {
            None
        } else {
            let mut blocks: ForkTree<VerifiedHeader> =
                ForkTree::with_capacity(self.config.max_blocks.get() - 1);
            for block in self.ancestry_order().skip(1) {
                if evicted.contains(&block.hash) {
                    continue;
                }
                let parent = if block.parent == self.root.hash {
                    None
                } else {
                    Some(
                        rebuilt_index
                            .get(&block.parent)
                            .copied()
                            .ok_or(InsertError::UnknownParent)?,
                    )
                };
                let index = blocks.insert(parent, block.clone());
                rebuilt_index.insert(block.hash, index);
            }
            Some(blocks)
        };
        let index = if rebuilt.is_some() {
            &mut rebuilt_index
        } else {
            &mut self.index
        };
        let blocks = rebuilt.as_mut().unwrap_or(&mut self.blocks);
        let parent = if parent_hash == self.root.hash {
            None
        } else {
            Some(
                index
                    .get(&parent_hash)
                    .copied()
                    .ok_or(InsertError::UnknownParent)?,
            )
        };
        let hash = verified.hash;
        let node_index = blocks.insert(parent, verified);
        index.insert(hash, node_index);
        if let Some(rebuilt) = rebuilt {
            self.blocks = rebuilt;
            self.index = rebuilt_index;
        }
        // Every rebuild accompanies a new best, so no old index survives it.
        if is_new_best {
            self.best = Some(node_index);
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
            self.index
                .get(hash)
                .and_then(|index| self.blocks.get(*index))
        }
    }

    /// Advances root and authorities atomically. Each intermediate epoch mark
    /// needs its own proof before the authority set can be advanced again.
    pub fn finalize(
        &mut self,
        proof: &VerifiedFinality,
        authorities: &mut AuthoritySet,
    ) -> Result<Finalized, finality::Error> {
        let target = proof.target();
        let block = self
            .get(&target.hash)
            .ok_or(finality::Error::UnknownTarget)?;
        if block.slot != target.slot {
            return Err(finality::Error::TargetSlotMismatch);
        }
        let next = authorities.after_finalizing(
            &self.params,
            proof,
            block.hash,
            block.slot,
            block
                .epoch_changed
                .then_some(block.post_state.epoch().pending.as_slice()),
        )?;
        let mut finalized = Vec::new();
        for ancestor in self.ancestors(&target.hash) {
            if ancestor.hash == self.root.hash {
                break;
            }
            if ancestor.hash != target.hash && ancestor.epoch_changed {
                return Err(finality::Error::SkippedAuthorityTransition);
            }
            finalized.push(ancestor.hash);
        }
        finalized.reverse();
        let old_best = self.best().hash;
        let mut pruned = Vec::new();
        if let Some(index) = self.index.get(&target.hash).copied() {
            for removed in self.blocks.prune_ancestors(index) {
                self.index.remove(&removed.user_data.hash);
                if removed.user_data.hash == target.hash {
                    self.root = removed.user_data;
                } else if !removed.is_prune_target_ancestor {
                    pruned.push(removed.user_data.hash);
                }
            }
            // Surviving indices are stable. Preserve ties if the old best survived.
            if self.best.is_none_or(|index| !self.blocks.contains(index)) {
                self.best = self
                    .blocks
                    .iter_ancestry_order()
                    .fold(None, |best: Option<(NodeIndex, u32)>, (index, block)| {
                        if best.is_none_or(|(_, slot)| block.slot > slot) {
                            Some((index, block.slot))
                        } else {
                            best
                        }
                    })
                    .map(|(index, _)| index);
            }
            if let Some(next) = next {
                *authorities = next;
            }
        }
        Ok(Finalized {
            finalized,
            pruned,
            best_changed: self.best().hash != old_best,
        })
    }

    /// Current verified finalized head (initially the trusted starting point).
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

    /// Accounted retained bytes, including distinct shared allocations once.
    pub fn retained_bytes(&self) -> usize {
        self.accounting(None, &[]).0
    }

    /// Number of distinct epoch records referenced by retained headers.
    pub fn epoch_records(&self) -> usize {
        self.accounting(None, &[]).1
    }

    /// Inline node, fork links and conservative B-tree index allocation overhead.
    pub const fn node_overhead() -> usize {
        core::mem::size_of::<VerifiedHeader>() + 16 * core::mem::size_of::<usize>() + 64
    }

    fn accounting(&self, incoming: Option<&VerifiedHeader>, removed: &[Hash]) -> (usize, usize) {
        let mut epochs = BTreeMap::new();
        let mut tickets = BTreeMap::new();
        // Preallocate the policy capacity so holes left by pruning cannot hide
        // retained slab storage. Eight words cover ForkTree's four Option<usize>
        // links; two more cover its flag, slab discriminant and alignment.
        let slot = core::mem::size_of::<VerifiedHeader>() + 10 * core::mem::size_of::<usize>();
        // Cover the partial B-tree root page and the containing structs too.
        let mut bytes = self
            .config
            .max_blocks
            .get()
            .saturating_mul(slot)
            .saturating_add(512 + core::mem::size_of::<Self>());
        for block in self
            .ancestry_order()
            .filter(|b| !removed.contains(&b.hash))
            .chain(incoming)
        {
            let node = (Self::node_overhead() - slot).saturating_add(block.encoded.capacity());
            bytes = bytes.saturating_add(node);
            let (id, cost) = block.post_state.epoch_allocation();
            if epochs.insert(id, ()).is_none() {
                bytes = bytes.saturating_add(cost);
            }
            if let Some((id, cost)) = block.post_state.tickets_allocation()
                && tickets.insert(id, ()).is_none()
            {
                bytes = bytes.saturating_add(cost);
            }
        }
        (bytes, epochs.len())
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
                self.get(&block.parent)
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
