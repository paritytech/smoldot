// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;
use crate::jam::{
    codec,
    finality::{Justification, Limits, precommit_payload},
    state::LightState,
    types::{EpochMark, SealingSequence},
};
use alloc::vec;
use ed25519_zebra::{SigningKey, VerificationKey};

fn setup() -> (HeaderTree, AuthoritySet, SigningKey) {
    setup_sized(6, 12)
}

fn setup_sized(validators: u16, epoch_len: u32) -> (HeaderTree, AuthoritySet, SigningKey) {
    let mut params = Params::from_protocol_parameters(&{
        let mut bytes = [0; 122];
        bytes[24] = 2;
        bytes
    })
    .unwrap();
    params.max_validators = validators;
    params.core_count = validators / 3;
    params.epoch_len = epoch_len;
    let key = SigningKey::from([1; 32]);
    let public: [u8; 32] = VerificationKey::from(&key).into();
    let authorities = AuthoritySet::from_checkpoint(
        &params,
        0,
        vec![public; validators as usize],
        vec![public; validators as usize],
    )
    .unwrap();
    let header = Header {
        parent: [0; 32],
        slot: 0,
        prior_state_root: [0; 32],
        extrinsic_hash: [0; 32],
        epoch_mark: None,
        tickets_mark: None,
        author_index: 0,
        entropy_source: [0; 96],
        offenders_mark: Vec::new(),
        seal: [0; 96],
    };
    let root = VerifiedHeader {
        hash: header.hash(&params),
        header,
        slot: 0,
        sealed_with_ticket: false,
        epoch_changed: false,
        post_state: LightState::from_parts(
            [[0; 32]; 4],
            vec![([0; 32], public); validators as usize],
            vec![([0; 32], public); validators as usize],
            SealingSequence::Keys(vec![[0; 32]; epoch_len as usize]),
            None,
            0,
        ),
    };
    let p = params.clone();
    // Header authentication has its own real-signature tests. Isolate pruning
    // here, while still using real hashes and signed GRANDPA proofs.
    let tree = HeaderTree::with_verifier(
        params,
        root,
        Config {
            max_blocks: NonZeroUsize::new(5).unwrap(),
            max_bytes: usize::MAX,
            max_epoch_records: core::num::NonZeroUsize::new(8).unwrap(),
        },
        move |parent, header| {
            let mut b = parent.clone();
            b.hash = header.hash(&p);
            b.slot = header.slot;
            b.post_state.set_slot(header.slot);
            if let Some(mark) = &header.epoch_mark {
                b.post_state
                    .enter_epoch(&p, true, &mark.validators)
                    .unwrap();
            }
            b.header = header;
            Ok(b)
        },
    );
    (tree, authorities, key)
}

fn insert(tree: &mut HeaderTree, parent: Hash, slot: u32, mark: bool) -> Hash {
    let mut header = tree.get(&parent).unwrap().header.clone();
    header.parent = parent;
    header.slot = slot;
    header.epoch_mark = mark.then(|| EpochMark {
        entropy: [0; 32],
        tickets_entropy: [0; 32],
        validators: vec![
            (
                [0; 32],
                VerificationKey::from(&SigningKey::from([1; 32])).into(),
            );
            tree.params.max_validators as usize
        ],
    });
    let hash = header.hash(&tree.params);
    tree.insert(parent, header, u64::MAX).unwrap();
    hash
}

fn proof(
    tree: &HeaderTree,
    authorities: &AuthoritySet,
    key: &SigningKey,
    hash: Hash,
) -> VerifiedFinality {
    let target = Final {
        hash,
        slot: tree.get(&hash).unwrap().slot,
    };
    let mut bytes = 1u64.to_le_bytes().to_vec();
    bytes.extend(authorities.set_id().to_le_bytes());
    bytes.extend(hash);
    bytes.extend(target.slot.to_le_bytes());
    bytes.extend(codec::encode_natural(1));
    bytes.extend(hash);
    bytes.extend(target.slot.to_le_bytes());
    bytes.extend(<[u8; 64]>::from(key.sign(&precommit_payload(
        &target,
        1,
        authorities.set_id(),
    ))));
    bytes.extend(<[u8; 32]>::from(VerificationKey::from(key)));
    bytes.extend(codec::encode_natural(0));
    let limits = Limits {
        max_bytes: 4096,
        max_ancestry_headers: 4,
        max_ancestry_steps: 20,
    };
    Justification::decode(&tree.params, &bytes, limits)
        .unwrap()
        .verify(
            &tree.params,
            authorities.set_id(),
            authorities.current(),
            &hash,
            limits,
            |hash| tree.get(hash).map(|b| &b.header),
        )
        .unwrap()
}

#[test]
fn finality_prunes_forks_preserves_descendants_and_selects_best() {
    let (mut tree, mut authorities, key) = setup();
    let root = tree.finalized().hash;
    let a = insert(&mut tree, root, 1, false);
    let fork = insert(&mut tree, root, 100, true);
    let b = insert(&mut tree, a, 2, false);
    let child = insert(&mut tree, b, 3, false);
    let proof = proof(&tree, &authorities, &key, b);
    let result = tree.finalize(&proof, &mut authorities).unwrap();
    assert_eq!(result.finalized, vec![a, b]);
    assert_eq!(result.pruned, vec![fork]);
    assert!(result.best_changed);
    assert_eq!(tree.finalized().hash, b);
    assert_eq!(tree.best().hash, child);
    assert_eq!(tree.len(), 2);
    assert_eq!(
        authorities.set_id(),
        0,
        "unfinalized fork mark cannot rotate authorities"
    );
    assert!(tree.get(&root).is_none());
    assert!(tree.get(&a).is_none());
    assert!(
        tree.finalize(&proof, &mut authorities)
            .unwrap()
            .finalized
            .is_empty()
    );
}

#[test]
fn epoch_transitions_cannot_be_skipped_and_failed_finalization_is_atomic() {
    let (mut tree, mut authorities, key) = setup();
    let root = tree.finalized().hash;
    let mark1 = insert(&mut tree, root, 12, true);
    let mark2 = insert(&mut tree, mark1, 24, true);
    let proof2 = proof(&tree, &authorities, &key, mark2);
    assert_eq!(
        tree.finalize(&proof2, &mut authorities).unwrap_err(),
        finality::Error::SkippedAuthorityTransition
    );
    assert_eq!(tree.finalized().hash, root);
    assert_eq!(authorities.set_id(), 0);
    assert_eq!(tree.len(), 3);
    let proof1 = proof(&tree, &authorities, &key, mark1);
    tree.finalize(&proof1, &mut authorities).unwrap();
    assert_eq!(authorities.set_id(), 1);
    assert!(
        tree.finalize(&proof2, &mut authorities).is_err(),
        "old authority proof must not advance new set"
    );
    let proof2 = proof(&tree, &authorities, &key, mark2);
    tree.finalize(&proof2, &mut authorities).unwrap();
    assert_eq!(authorities.set_id(), 2);
    assert_eq!(tree.len(), 1);
}

#[test]
fn sustained_root_advancement_stays_bounded() {
    let (mut tree, mut authorities, key) = setup();
    for slot in 1..=200 {
        let parent = tree.finalized().hash;
        let hash = insert(&mut tree, parent, slot, slot % 12 == 0);
        let proof = proof(&tree, &authorities, &key, hash);
        tree.finalize(&proof, &mut authorities).unwrap();
        assert_eq!(tree.len(), 1);
    }
    assert_eq!(authorities.set_id(), 16);
}

#[test]
fn full_parameter_retention_is_bounded_over_720_blocks() {
    let (mut tree, mut authorities, key) = setup_sized(1023, 600);
    let mut peak_nodes = 0;
    let mut peak_bytes = 0;
    let mut markless_growth = 0;
    let record = tree.finalized().post_state.epoch_allocation().1;
    for slot in 1..=720 {
        let parent = tree.best().hash;
        let before = tree.retained_bytes();
        let hash = insert(&mut tree, parent, slot, slot % 600 == 0);
        if slot % 600 != 0 {
            markless_growth = markless_growth.max(tree.retained_bytes() - before);
        }
        peak_nodes = peak_nodes.max(tree.len());
        let bytes = tree.retained_bytes();
        peak_bytes = peak_bytes.max(bytes);
        if slot % 3 == 0 {
            let proof = proof(&tree, &authorities, &key, hash);
            tree.finalize(&proof, &mut authorities).unwrap();
        }
    }
    assert_eq!(peak_nodes, 4);
    assert_eq!(tree.len(), 1);
    assert!(peak_bytes < 1024 * 1024);
    assert!(markless_growth < 2048);
    assert_eq!(tree.epoch_records(), 1);
    std::println!(
        "D13 full: 720 blocks, peak {peak_nodes} nodes, {peak_bytes} accounted bytes; incremental={markless_growth} bytes/node, epoch record={record} bytes"
    );
}

#[test]
fn epoch_forks_evict_and_finalize_records_atomically() {
    let (mut tree, mut authorities, key) = setup_sized(6, 12);
    tree.config.max_epoch_records = NonZeroUsize::new(3).unwrap();
    let root = tree.finalized().hash;
    let lowest = insert(&mut tree, root, 12, true);
    insert(&mut tree, root, 13, true);
    assert_eq!(tree.epoch_records(), 3);
    let best = insert(&mut tree, root, 14, true);
    assert!(tree.get(&lowest).is_none());
    assert_eq!(tree.epoch_records(), 3);
    let mut rejected = tree.get(&best).unwrap().header.clone();
    rejected.slot = 12;
    rejected.extrinsic_hash = [9; 32];
    let before: Vec<_> = tree.ancestry_order().cloned().collect();
    let bytes = tree.retained_bytes();
    assert_eq!(
        tree.insert(root, rejected, u64::MAX),
        Err(InsertError::Full)
    );
    assert_eq!(tree.ancestry_order().cloned().collect::<Vec<_>>(), before);
    assert_eq!(tree.retained_bytes(), bytes);
    let proof = proof(&tree, &authorities, &key, best);
    tree.finalize(&proof, &mut authorities).unwrap();
    assert_eq!(tree.epoch_records(), 1);
    assert_eq!(tree.len(), 1);
    assert!(tree.retained_bytes() < bytes);
}
