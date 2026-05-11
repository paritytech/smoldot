use super::*;
use crate::platform::DefaultPlatform;

fn dummy_runtime() -> Arc<Runtime> {
    Arc::new(Runtime {
        runtime: Err(RuntimeError::CodeNotFound),
        code_merkle_value: None,
        closest_ancestor_excluding: None,
        runtime_code: None,
        heap_pages: None,
    })
}

fn block(hash_byte: u8, height: u64) -> Block {
    Block {
        hash: [hash_byte; 32],
        height,
        scale_encoded_header: vec![],
    }
}

type TestPlat = Arc<DefaultPlatform>;

fn empty_unknown_tree() -> Tree<TestPlat> {
    Tree::FinalizedBlockRuntimeUnknown {
        tree: async_tree::AsyncTree::new(async_tree::Config {
            finalized_async_user_data: None,
            retry_after_failed: Duration::from_secs(4),
            blocks_capacity: 0,
        }),
    }
}

fn known_tree(finalized: Block) -> Tree<TestPlat> {
    Tree::FinalizedBlockRuntimeKnown {
        all_blocks_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
            0,
            Default::default(),
        ),
        pinned_blocks: BTreeMap::new(),
        finalized_block: finalized,
        tree: async_tree::AsyncTree::new(async_tree::Config {
            finalized_async_user_data: dummy_runtime(),
            retry_after_failed: Duration::from_secs(4),
            blocks_capacity: 0,
        }),
    }
}

#[test]
fn inserts_new_finalized_under_pre_warp_when_prev_differs() {
    let prev_finalized = block(0x01, 100);
    let new_finalized = block(0x02, 101);

    let result = build_warp_sync_tree::<TestPlat>(
        &known_tree(prev_finalized.clone()),
        new_finalized.clone(),
        dummy_runtime(),
        vec![],
    );

    assert_eq!(result.finalized_block.hash, prev_finalized.hash);
    assert_eq!(result.pre_warp_finalized_hash, Some(prev_finalized.hash));
    let in_tree: Vec<_> = result
        .tree
        .input_output_iter_unordered()
        .map(|b| b.user_data.hash)
        .collect();
    assert_eq!(in_tree, vec![new_finalized.hash]);
}

#[test]
fn skips_pre_warp_when_prev_finalized_equals_new() {
    let same = block(0x05, 200);

    let result = build_warp_sync_tree::<TestPlat>(
        &known_tree(same.clone()),
        same.clone(),
        dummy_runtime(),
        vec![],
    );

    assert_eq!(result.finalized_block.hash, same.hash);
    assert_eq!(result.pre_warp_finalized_hash, None);
    assert_eq!(result.tree.input_output_iter_unordered().count(), 0);
}

#[test]
fn skips_pre_warp_when_prev_unknown_has_no_input_finalized() {
    let new_finalized = block(0x07, 50);

    let result = build_warp_sync_tree::<TestPlat>(
        &empty_unknown_tree(),
        new_finalized.clone(),
        dummy_runtime(),
        vec![],
    );

    assert_eq!(result.finalized_block.hash, new_finalized.hash);
    assert_eq!(result.pre_warp_finalized_hash, None);
    assert_eq!(result.tree.input_output_iter_unordered().count(), 0);
}

#[test]
fn inserts_child_of_new_finalized() {
    let prev = block(0x01, 100);
    let new_finalized = block(0x02, 101);
    let child = block(0x03, 102);

    let result = build_warp_sync_tree::<TestPlat>(
        &known_tree(prev),
        new_finalized.clone(),
        dummy_runtime(),
        vec![WarpSyncTreeChild {
            block: child.clone(),
            parent_hash: new_finalized.hash,
            same_runtime_as_parent: true,
            is_new_best: true,
        }],
    );

    let hashes: Vec<_> = result
        .tree
        .input_output_iter_unordered()
        .map(|b| b.user_data.hash)
        .collect();
    assert!(hashes.contains(&new_finalized.hash));
    assert!(hashes.contains(&child.hash));
}

#[test]
fn tree_emits_block_then_finalized_for_new_finalized() {
    let prev = block(0x01, 100);
    let new_finalized = block(0x02, 101);
    let new_finalized_hash = new_finalized.hash;

    let mut result =
        build_warp_sync_tree::<TestPlat>(&known_tree(prev), new_finalized, dummy_runtime(), vec![]);

    match result.tree.try_advance_output() {
        Some(async_tree::OutputUpdate::Block(b)) => {
            assert_eq!(result.tree[b.index].hash, new_finalized_hash);
            assert!(b.is_new_best);
            // new_finalized is a root; runtime_service relies on this so the
            // Block notification's parent_hash falls back to the outer-finalized
            // (pre_warp_finalized) hash.
            assert_eq!(result.tree.parent(b.index), None);
        }
        _ => panic!("expected OutputUpdate::Block"),
    }

    match result.tree.try_advance_output() {
        Some(async_tree::OutputUpdate::Finalized {
            user_data,
            pruned_blocks,
            ..
        }) => {
            assert_eq!(user_data.hash, new_finalized_hash);
            assert!(pruned_blocks.is_empty());
        }
        _ => panic!("expected OutputUpdate::Finalized"),
    }
    // new_finalized has been pruned: tree is now empty.
    assert_eq!(result.tree.input_output_iter_unordered().count(), 0);

    assert!(result.tree.try_advance_output().is_none());
}

#[test]
fn tree_has_nothing_to_advance_without_pre_warp() {
    let new_finalized = block(0x07, 50);
    let mut result = build_warp_sync_tree::<TestPlat>(
        &empty_unknown_tree(),
        new_finalized,
        dummy_runtime(),
        vec![],
    );
    assert!(result.tree.try_advance_output().is_none());
}

#[test]
fn tree_emits_block_for_child_after_new_finalized_is_finalized() {
    let prev = block(0x01, 100);
    let new_finalized = block(0x02, 101);
    let new_finalized_hash = new_finalized.hash;
    let child = block(0x03, 102);
    let child_hash = child.hash;

    let mut result = build_warp_sync_tree::<TestPlat>(
        &known_tree(prev),
        new_finalized,
        dummy_runtime(),
        vec![WarpSyncTreeChild {
            block: child,
            parent_hash: new_finalized_hash,
            same_runtime_as_parent: true,
            is_new_best: true,
        }],
    );

    // Block(new_finalized) first — Finalized is gated on `reported:true`.
    match result.tree.try_advance_output() {
        Some(async_tree::OutputUpdate::Block(b)) => {
            assert_eq!(result.tree[b.index].hash, new_finalized_hash);
            assert!(b.is_new_best);
        }
        _ => panic!("expected Block(new_finalized)"),
    }

    // Then Finalized(new_finalized) — prunes new_finalized from the tree.
    // child is on the canonical line, so it's not in pruned_blocks.
    match result.tree.try_advance_output() {
        Some(async_tree::OutputUpdate::Finalized {
            user_data,
            pruned_blocks,
            ..
        }) => {
            assert_eq!(user_data.hash, new_finalized_hash);
            assert!(pruned_blocks.is_empty());
        }
        _ => panic!("expected Finalized(new_finalized)"),
    }
    // new_finalized has been pruned; child remains as a root.
    let remaining: Vec<_> = result
        .tree
        .input_output_iter_unordered()
        .map(|b| b.user_data.hash)
        .collect();
    assert_eq!(remaining, vec![child_hash]);

    // Only now Block(child) — its parent (new_finalized) has been pruned, so it's a root.
    match result.tree.try_advance_output() {
        Some(async_tree::OutputUpdate::Block(b)) => {
            assert_eq!(result.tree[b.index].hash, child_hash);
            assert!(b.is_new_best);
        }
        _ => panic!("expected Block(child)"),
    }

    assert!(result.tree.try_advance_output().is_none());
}
