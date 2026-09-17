// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;
use crate::jam::{
    state::LightState,
    test_support::{self, tiny_params, verify_and_insert},
    types::{SealingSequence, Ticket},
    verify::verified_genesis,
};
use alloc::vec;

/// The synthetic children below are identified by their extrinsic hash.
fn header(parent: u8, id: u8, slot: u32) -> Header {
    Header {
        extrinsic_hash: [id; 32],
        ..test_support::header([parent; 32], slot)
    }
}

fn root() -> VerifiedHeader {
    VerifiedHeader::assume_verified(
        header(255, 0, 0).encode(&tiny_params()),
        [255; 32],
        [0; 32],
        0,
        false,
        LightState::from_parts(
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
    )
}

fn config(capacity: usize) -> Config {
    Config {
        max_blocks: NonZeroUsize::new(capacity).unwrap(),
        max_bytes: usize::MAX,
        max_epoch_records: core::num::NonZeroUsize::new(8).unwrap(),
    }
}

/// `header` as a verified child with the hash `extrinsic_hash` and the slot
/// `slot`, on the post state of its retained parent (the root's if the parent
/// is unknown) with `extrinsic_hash` accumulated into the entropy.
fn child(tree: &HeaderTree, header: &Header, slot: u32) -> VerifiedHeader {
    let parent = tree.get(&header.parent).unwrap_or(tree.finalized());
    let mut post_state = parent.post_state().clone();
    let mut entropy = post_state.entropy();
    entropy.rotate_right(1);
    entropy[0] = header.extrinsic_hash;
    post_state.set_entropy(entropy);
    post_state.set_slot(header.slot);
    VerifiedHeader::assume_verified(
        header.encode(&tiny_params()),
        header.parent,
        header.extrinsic_hash,
        slot,
        false,
        post_state,
    )
}

fn tree(capacity: usize) -> HeaderTree {
    let tree = HeaderTree::new(tiny_params(), root(), config(capacity)).unwrap();
    check(&tree);
    tree
}

#[test]
fn constructor_checks_root_and_slab_before_allocating() {
    let root = root();
    let mut limits = config(4);
    limits.max_bytes = 0;
    assert!(matches!(
        HeaderTree::new(tiny_params(), root.clone(), limits),
        Err(InsertError::Full)
    ));
    limits.max_bytes = usize::MAX;
    let measured = HeaderTree::new(tiny_params(), root.clone(), limits)
        .unwrap()
        .retained_bytes();
    limits.max_bytes = measured - 1;
    assert!(matches!(
        HeaderTree::new(tiny_params(), root.clone(), limits),
        Err(InsertError::Full)
    ));
    limits.max_bytes = measured;
    let mut tree = HeaderTree::new(tiny_params(), root.clone(), limits).unwrap();
    assert_eq!(tree.retained_bytes(), measured);
    assert_eq!(tree.insert_verified(root.clone()), Ok(Insert::AlreadyKnown));
    limits.max_blocks = NonZeroUsize::new(usize::MAX).unwrap();
    limits.max_bytes = usize::MAX;
    assert!(matches!(
        HeaderTree::new(tiny_params(), root, limits),
        Err(InsertError::Full)
    ));
}

#[test]
fn byte_limit_rejects_atomically_and_charges_ticket_allocations_once() {
    let mut tree = tree(4);
    let initial = tree.retained_bytes();
    // Children of the root on its own post state share its allocations.
    let root_child = |id: u8, post_state: LightState| {
        VerifiedHeader::assume_verified(
            header(0, id, 1).encode(&tiny_params()),
            [0; 32],
            [id; 32],
            1,
            false,
            post_state,
        )
    };
    let child = root_child(1, tree.finalized().post_state().clone());
    tree.config.max_bytes = initial;
    assert_eq!(tree.insert_verified(child.clone()), Err(InsertError::Full));
    assert_eq!(tree.len(), 1);
    assert_eq!(tree.retained_bytes(), initial);
    // Measured on a clone, like the one inserted: no spare byte capacity.
    let exact = tree.accounting(Some(&child.clone()), &[]).0;
    tree.config.max_bytes = exact;
    tree.insert_verified(child.clone()).unwrap();
    assert_eq!(tree.retained_bytes(), exact);
    assert_eq!(tree.epoch_records(), 1);
    let shared = tree
        .accounting(Some(&root_child(2, child.post_state().clone())), &[])
        .0;
    let mut own_tickets = child.post_state().clone();
    own_tickets.set_pending_tickets(&[Ticket {
        id: [6; 32],
        attempt: 0,
    }]);
    assert_eq!(
        tree.accounting(Some(&root_child(2, own_tickets)), &[]).0 - shared,
        (core::mem::size_of::<Ticket>() + 2 * core::mem::size_of::<usize>())
            .next_multiple_of(core::mem::align_of::<usize>())
    );
}

#[test]
fn hundred_real_verified_markless_headers_share_one_dev_epoch() {
    // Dev epochs have only twelve slots: siblings let us retain 100 genuine
    // signatures in one epoch without changing the chain's parameters.
    let (params, root, headers, now) = HeaderTree::signed_markless_fixtures();
    let mut tree = HeaderTree::new(params, root, config(101)).unwrap();
    let before = tree.retained_bytes();
    for header in headers {
        verify_and_insert(&mut tree, header, now).unwrap();
    }
    let growth = (tree.retained_bytes() - before) / 100;
    let amortized =
        growth + core::mem::size_of::<VerifiedHeader>() + 10 * core::mem::size_of::<usize>();
    assert_eq!(tree.epoch_records(), 1);
    assert!(growth < 1024);
    assert!(amortized < 1024);
}

// Called before/after every insertion, including errors and duplicates.
fn check(tree: &HeaderTree) {
    let mut seen = Vec::new();
    for block in tree.ancestry_order() {
        assert!(!seen.contains(&block.hash()));
        if block.hash() != tree.finalized().hash() {
            assert!(
                seen.contains(&block.parent()),
                "dangling/out-of-order parent"
            );
        } else {
            assert!(seen.is_empty());
        }
        seen.push(block.hash());
        assert_eq!(tree.get(&block.hash()), Some(block));
        let ancestors: Vec<_> = tree.ancestors(&block.hash()).collect();
        assert_eq!(ancestors.first().copied(), Some(block));
        assert_eq!(ancestors.last().copied(), Some(tree.finalized()));
    }
    assert_eq!(seen.len(), tree.len());
    assert!(tree.len() <= tree.config.max_blocks.get());
    assert!(!tree.is_empty());
    assert_eq!(tree.finalized(), &tree.root);
    let leaves = tree.leaves();
    assert!(leaves.iter().any(|leaf| leaf.hash == tree.best().hash()));
    assert!(leaves.iter().all(|leaf| leaf.slot <= tree.best().slot()));
    for block in tree.ancestry_order() {
        let has_children = tree
            .ancestry_order()
            .skip(1)
            .any(|b| b.parent() == block.hash());
        assert_eq!(
            leaves.iter().any(|leaf| leaf.hash == block.hash()),
            !has_children
        );
    }
    assert_eq!(tree.ancestors(&[254; 32]).count(), 0);
    assert!(!tree.is_ancestor(&[254; 32], &[254; 32]));
}

/// Runs `insert` between two consistency checks. A failed or duplicate
/// insertion must leave the tree as it was.
fn atomic(
    tree: &mut HeaderTree,
    insert: impl FnOnce(&mut HeaderTree) -> Result<Insert, InsertError>,
) -> Result<Insert, InsertError> {
    check(tree);
    let before: Vec<_> = tree.ancestry_order().cloned().collect();
    let best = tree.best().hash();
    let root = tree.finalized().clone();
    let result = insert(tree);
    assert_eq!(tree.finalized(), &root);
    if result.is_err() || matches!(result, Ok(Insert::AlreadyKnown)) {
        assert_eq!(tree.ancestry_order().cloned().collect::<Vec<_>>(), before);
        assert_eq!(tree.best().hash(), best);
    }
    check(tree);
    result
}

/// Inserts the synthetic child `header`, verified at its own slot.
fn insert(tree: &mut HeaderTree, header: Header) -> Result<Insert, InsertError> {
    let slot = header.slot;
    atomic(tree, |tree| {
        tree.insert_verified(child(tree, &header, slot))
    })
}

/// Verifies and inserts a signed header.
fn insert_at(tree: &mut HeaderTree, header: Header, now: u64) -> Result<Insert, InsertError> {
    atomic(tree, |tree| verify_and_insert(tree, header, now))
}

fn add(tree: &mut HeaderTree, parent: u8, id: u8, slot: u32) -> Insert {
    insert(tree, header(parent, id, slot)).unwrap()
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
    assert_eq!(tree.best().hash(), [4; 32]);
    assert_eq!(
        tree.ancestors(&[4; 32])
            .map(|b| b.hash())
            .collect::<Vec<_>>(),
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
    assert_eq!(tree.best().hash(), [2; 32]);
    add(&mut tree, 3, 4, 4);
    assert_eq!(tree.best().hash(), [4; 32]);
    add(&mut tree, 2, 5, 4);
    assert_eq!(tree.best().hash(), [4; 32]);
    add(&mut tree, 0, 6, 10); // Late fork immediately becomes best.
    assert_eq!(tree.best().hash(), [6; 32]);
    assert!(!tree.is_ancestor(&[3; 32], &[5; 32]));
    assert_eq!(
        tree.get(&[4; 32]).unwrap().post_state().entropy(),
        [[4; 32], [3; 32], [0; 32], [0; 32]]
    );
    assert_eq!(
        tree.get(&[5; 32]).unwrap().post_state().entropy(),
        [[5; 32], [2; 32], [1; 32], [0; 32]]
    );
    assert_eq!(
        tree.get(&[5; 32]).unwrap().post_state().epoch().pending,
        root().post_state().epoch().pending
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
    assert_eq!(insert(&mut tree, header(1, 3, 3)), Err(InsertError::Full));
}

#[test]
fn full_linear_non_best_and_duplicate_insertions() {
    let mut tree = tree(3);
    add(&mut tree, 0, 1, 1);
    add(&mut tree, 1, 2, 2);
    assert_eq!(insert(&mut tree, header(2, 3, 3)), Err(InsertError::Full));
    assert_eq!(insert(&mut tree, header(0, 4, 1)), Err(InsertError::Full));
    assert_eq!(insert(&mut tree, header(0, 5, 2)), Err(InsertError::Full));
    assert_eq!(insert(&mut tree, header(0, 1, 1)), Ok(Insert::AlreadyKnown));
    let root_header = Header::decode(&tiny_params(), root().encoded()).unwrap();
    assert_eq!(
        insert(&mut tree, root_header.clone()),
        Ok(Insert::AlreadyKnown)
    );
    let mut root_only = self::tree(1);
    assert_eq!(
        insert(&mut root_only, header(0, 1, 1)),
        Err(InsertError::Full)
    );
    assert_eq!(
        insert(&mut root_only, root_header),
        Ok(Insert::AlreadyKnown)
    );
}

#[test]
fn errors_are_atomic_including_unverified_and_out_of_order_children() {
    let mut tree = tree(2);
    add(&mut tree, 0, 1, 1);
    assert_eq!(
        insert(&mut tree, header(99, 2, 2)),
        Err(InsertError::UnknownParent)
    );
    // An explicit parent other than the header's is rejected before anything else.
    assert_eq!(
        tree.verify([0; 32], header(1, 2, 2), 1_000),
        Err(InsertError::ParentMismatch)
    );
    assert_eq!(
        tree.verify([0; 32], header(1, 1, 1), 1_000),
        Err(InsertError::ParentMismatch)
    );
    assert_eq!(
        tree.verify([99; 32], header(99, 2, 2), 1_000),
        Err(InsertError::UnknownParent)
    );
    // The synthetic states are not valid Safrole states, so real verification fails.
    assert!(matches!(
        tree.verify([1; 32], header(1, 2, 2), 1_000),
        Err(InsertError::Verify(VerifyError::InvalidParentState(_)))
    ));
    assert_eq!(
        insert(&mut tree, header(1, 2, 1)),
        Err(InsertError::InvalidVerifiedSlot)
    );
    // Only `new` takes a trusted anchor.
    let anchor = verified_genesis(&tiny_params(), header(1, 2, 2), root().post_state().clone());
    assert_eq!(
        atomic(&mut tree, |tree| tree.insert_verified(anchor)),
        Err(InsertError::TrustedAnchor)
    );
    assert_eq!(insert(&mut tree, header(0, 1, 1)), Ok(Insert::AlreadyKnown));
}

#[test]
fn uses_verified_score_not_untrusted_header_slot() {
    let mut tree = tree(4);
    for (id, header_slot) in [(2, 100), (1, 200)] {
        let header = header(0, id, header_slot);
        atomic(&mut tree, |tree| {
            tree.insert_verified(child(tree, &header, u32::from(id)))
        })
        .unwrap();
    }
    assert_eq!(tree.best().hash(), [2; 32]);
}

#[test]
fn ten_times_bound_with_repeated_evictions_and_rejections() {
    let mut tree = tree(8);
    for id in 1..=80 {
        add(&mut tree, 0, id, u32::from(id));
        assert_eq!(tree.best().hash(), [id; 32]);
    }
    let mut linear = self::tree(8);
    for id in 1..=80 {
        let parent = linear.best().hash()[0];
        let result = insert(&mut linear, header(parent, id, u32::from(id)));
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
    let mut tree = HeaderTree::new(params, root.clone(), config(2)).unwrap();
    assert!(matches!(
        insert_at(&mut tree, child.clone(), 0),
        Err(InsertError::Verify(VerifyError::SlotInFuture))
    ));
    // Wrapping the child as an anchor does not get it in unverified.
    let anchor = verified_genesis(&tree.params, child.clone(), root.post_state().clone());
    assert_eq!(anchor.hash(), hash);
    assert_eq!(
        atomic(&mut tree, |tree| tree.insert_verified(anchor)),
        Err(InsertError::TrustedAnchor)
    );
    assert_eq!(
        insert_at(&mut tree, child.clone(), now).unwrap(),
        Insert::Inserted {
            hash,
            is_new_best: true,
            evicted: Vec::new(),
        }
    );
    // The tree keeps exactly what the verifier returns for the child.
    assert_eq!(
        tree.get(&hash),
        Some(&verify_header(&tree.params, &root, child.clone(), now).unwrap())
    );
    assert_eq!(tree.best().hash(), hash);
    assert_eq!(tree.len(), 2);
    // Known headers are not verified again, even at capacity and at a time
    // that would make verification fail.
    for time in [now, 0] {
        assert_eq!(
            insert_at(&mut tree, child.clone(), time).unwrap(),
            Insert::AlreadyKnown
        );
    }
    let root_header = Header::decode(&tree.params, root.encoded()).unwrap();
    assert_eq!(
        insert_at(&mut tree, root_header, now).unwrap(),
        Insert::AlreadyKnown
    );
    // The root is a trusted anchor: known, so not refused.
    assert!(root.is_anchor());
    assert_eq!(
        atomic(&mut tree, |tree| tree.insert_verified(root)),
        Ok(Insert::AlreadyKnown)
    );
}

#[test]
fn production_constructor_rejects_unsealed_and_malformed_seals() {
    let (params, root, child, now) = HeaderTree::signed_child_fixture();
    let mut tree = HeaderTree::new(params, root, config(2)).unwrap();
    let mut unsealed = child.clone();
    unsealed.seal = [0; 96];
    let mut malformed = child.clone();
    malformed.seal[70] ^= 1;
    let mut tampered = child.clone();
    tampered.prior_state_root[0] ^= 1;
    for header in [unsealed, malformed, tampered] {
        assert!(matches!(
            insert_at(&mut tree, header, now),
            Err(InsertError::Verify(VerifyError::BadSealSignature(_)))
        ));
    }
    assert!(matches!(
        insert_at(&mut tree, child, now),
        Ok(Insert::Inserted {
            is_new_best: true,
            ..
        })
    ));
}
