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
        post_state: LightState {
            entropy: [[0; 32]; 4],
            active: vec![([0; 32], public); validators as usize],
            pending: vec![([0; 32], public); validators as usize],
            sealing: SealingSequence::Keys(vec![[0; 32]; epoch_len as usize]),
            pending_tickets: None,
            slot: 0,
        },
    };
    let p = params.clone();
    // Header authentication has its own real-signature tests. Isolate pruning
    // here, while still using real hashes and signed GRANDPA proofs.
    let tree = HeaderTree::with_verifier(
        params,
        root,
        Config {
            max_blocks: NonZeroUsize::new(5).unwrap(),
        },
        move |parent, header| {
            let mut b = parent.clone();
            b.hash = header.hash(&p);
            b.slot = header.slot;
            b.post_state.slot = header.slot;
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
    for slot in 1..=720 {
        let parent = tree.best().hash;
        let hash = insert(&mut tree, parent, slot, slot % 600 == 0);
        peak_nodes = peak_nodes.max(tree.len());
        let bytes: usize = tree
            .ancestry_order()
            .map(|b| {
                core::mem::size_of_val(b)
                    + b.post_state.active.capacity() * 64
                    + b.post_state.pending.capacity() * 64
                    + match &b.post_state.sealing {
                        SealingSequence::Keys(keys) => keys.capacity() * 32,
                        SealingSequence::Tickets(tickets) => {
                            tickets.capacity() * core::mem::size_of_val(&tickets[0])
                        }
                    }
                    + b.header
                        .epoch_mark
                        .as_ref()
                        .map_or(0, |mark| mark.validators.capacity() * 64)
            })
            .sum();
        peak_bytes = peak_bytes.max(bytes);
        if slot % 3 == 0 {
            let proof = proof(&tree, &authorities, &key, hash);
            tree.finalize(&proof, &mut authorities).unwrap();
        }
    }
    assert_eq!(peak_nodes, 4);
    assert_eq!(tree.len(), 1);
    assert!(peak_bytes < 1024 * 1024);
    std::println!(
        "Full-sized state retention replay: 720 blocks, peak {peak_nodes} nodes, {peak_bytes} inline/vector bytes (not allocator/process RSS)"
    );
}
