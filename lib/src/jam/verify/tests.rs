// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;
use crate::jam::{
    crypto::VrfError,
    state::{LightState, StateError, ValidatorPair, fallback_key_sequence},
    types::{
        EpochMark, GenesisLightState, Hash, Header, SafroleState, SealingSequence, Ticket,
        ValidatorKey,
    },
};
use alloc::{vec, vec::Vec};
use ark_vrf::{
    ietf::Prover as _, reexports::ark_serialize::CanonicalSerialize as _, suites::bandersnatch,
};
use rand::{Rng as _, RngCore as _, SeedableRng as _};

/// 2033-05-18: after every synthetic and captured slot.
const NOW: u64 = 2_000_000_000;

fn tiny_params() -> Params {
    Params {
        epoch_len: 12,
        max_validators: 6,
        slot_seconds: 6,
        epoch_tail_start: 10,
        max_tickets_per_ext: 3,
        deposit_per_item: 10,
        deposit_per_byte: 1,
        deposit_per_account: 100,
        core_count: 2,
        min_turnaround_period: 32,
        max_accumulate_gas: 10_000_000,
        max_is_authorized_gas: 50_000_000,
        max_refine_gas: 1_000_000_000,
        block_gas_limit: 20_000_000,
        recent_block_count: 8,
        max_work_items: 16,
        max_dependencies: 8,
        max_lookup_anchor_age: 24,
        auth_window: 8,
        auth_queue_len: 80,
        rotation_period: 4,
        max_extrinsics: 128,
        availability_timeout: 5,
        max_authorizer_code_size: 64_000,
        max_input: 13_791_360,
        max_service_code_size: 4_000_000,
        max_imports: 3072,
        max_report_elective_data: 49_152,
        transfer_memo_size: 128,
        max_exports: 3072,
    }
}

// Synthetic validators and signing.

struct Validator {
    secret: bandersnatch::Secret,
    keys: ValidatorPair,
}

fn validators(seed: &[u8]) -> Vec<Validator> {
    (0..6_u8)
        .map(|i| {
            let secret = bandersnatch::Secret::from_seed(&[seed, &[i]].concat());
            let mut public = [0; 32];
            secret
                .public()
                .serialize_compressed(&mut public[..])
                .unwrap();
            let mut ed25519 = [i; 32];
            ed25519[..seed.len().min(31)].copy_from_slice(&seed[..seed.len().min(31)]);
            Validator {
                secret,
                keys: (public, ed25519),
            }
        })
        .collect()
}

fn pairs(set: &[Validator]) -> Vec<ValidatorPair> {
    set.iter().map(|v| v.keys).collect()
}

fn vrf_output(secret: &bandersnatch::Secret, context: &[u8]) -> Hash {
    let output = secret.output(bandersnatch::Input::new(context).unwrap());
    output.hash()[..32].try_into().unwrap()
}

fn vrf_sign(secret: &bandersnatch::Secret, context: &[u8], aux: &[u8]) -> [u8; 96] {
    let input = bandersnatch::Input::new(context).unwrap();
    let output = secret.output(input);
    let proof = secret.prove(input, output, aux);
    let mut signature = [0; 96];
    output.serialize_compressed(&mut signature[..32]).unwrap();
    proof.serialize_compressed(&mut signature[32..]).unwrap();
    signature
}

fn ticket_context(eta3: &Hash, attempt: u8) -> Vec<u8> {
    [b"jam_ticket_seal".as_slice(), eta3, &[attempt]].concat()
}

fn fallback_context(eta3: &Hash) -> Vec<u8> {
    [b"jam_fallback_seal".as_slice(), eta3].concat()
}

/// The unsigned, author-independent part of a header to build on a parent.
#[derive(Clone, Default)]
struct Draft {
    slot: u32,
    epoch_mark: Option<EpochMark>,
    tickets_mark: Option<Vec<Ticket>>,
}

fn draft(slot: u32) -> Draft {
    Draft {
        slot,
        ..Default::default()
    }
}

fn mark(parent: &VerifiedHeader, validators: &[ValidatorPair]) -> EpochMark {
    EpochMark {
        entropy: parent.post_state.entropy()[0],
        tickets_entropy: parent.post_state.entropy()[1],
        validators: validators.to_vec(),
    }
}

/// What the Gray Paper says a child at `slot` is sealed against: the set that
/// becomes active (the parent's *pending* set on an epoch change), `η3'`, and the
/// sealing sequence (the parent epoch's tickets mark when the epochs are
/// consecutive, else the fallback sequence over the new active set).
struct Expected {
    active: Vec<ValidatorPair>,
    eta3: Hash,
    sealing: SealingSequence,
}

fn expected(params: &Params, parent: &VerifiedHeader, slot: u32) -> Expected {
    let state = &parent.post_state;
    let epochs = (state.slot() / params.epoch_len, slot / params.epoch_len);
    if epochs.1 > epochs.0 {
        let active = state.epoch().pending.clone();
        let sealing = match state.pending_tickets() {
            Some(tickets) if epochs.1 == epochs.0 + 1 => SealingSequence::Tickets(tickets.to_vec()),
            _ => SealingSequence::Keys(
                fallback_key_sequence(params, &state.entropy()[1], &active).unwrap(),
            ),
        };
        Expected {
            active,
            eta3: state.entropy()[2],
            sealing,
        }
    } else {
        Expected {
            active: state.epoch().active.clone(),
            eta3: state.entropy()[3],
            sealing: state.epoch().sealing.clone(),
        }
    }
}

/// Picks the validator of `pool` that the sealing entry for `slot` designates and
/// returns it with its index into `active` and the seal context.
fn author<'a>(
    params: &Params,
    expected: &Expected,
    pool: &'a [Validator],
    slot: u32,
) -> (u16, &'a Validator, Vec<u8>) {
    let phase = usize::try_from(slot % params.epoch_len).unwrap();
    let (validator, context) = match &expected.sealing {
        SealingSequence::Keys(keys) => (
            pool.iter().find(|v| v.keys.0 == keys[phase]).unwrap(),
            fallback_context(&expected.eta3),
        ),
        SealingSequence::Tickets(tickets) => {
            let context = ticket_context(&expected.eta3, tickets[phase].attempt);
            let validator = pool
                .iter()
                .find(|v| vrf_output(&v.secret, &context) == tickets[phase].id)
                .unwrap();
            (validator, context)
        }
    };
    let index = expected
        .active
        .iter()
        .position(|keys| *keys == validator.keys)
        .unwrap();
    (u16::try_from(index).unwrap(), validator, context)
}

/// Seals `draft` on `parent` with `validator` at `author_index` under `context`.
fn seal_with(
    params: &Params,
    parent: &VerifiedHeader,
    draft: Draft,
    author_index: u16,
    validator: &Validator,
    context: &[u8],
) -> Header {
    let mut header = Header {
        parent: parent.hash,
        prior_state_root: [0x11; 32],
        extrinsic_hash: [0x22; 32],
        slot: draft.slot,
        epoch_mark: draft.epoch_mark,
        tickets_mark: draft.tickets_mark,
        author_index,
        entropy_source: [0; 96],
        offenders_mark: Vec::new(),
        seal: [0; 96],
    };
    let seal_output = vrf_output(&validator.secret, context);
    let entropy_context = [b"jam_entropy".as_slice(), &seal_output].concat();
    header.entropy_source = vrf_sign(&validator.secret, &entropy_context, &[]);
    let unsigned = header.encode_unsigned(params);
    header.seal = vrf_sign(&validator.secret, context, &unsigned);
    header
}

/// Seals `draft` on `parent` by the validator the Gray Paper designates.
fn seal(params: &Params, parent: &VerifiedHeader, draft: Draft, pool: &[Validator]) -> Header {
    let expected = expected(params, parent, draft.slot);
    let (index, validator, context) = author(params, &expected, pool, draft.slot);
    seal_with(params, parent, draft, index, validator, &context)
}

fn verify(
    params: &Params,
    parent: &VerifiedHeader,
    header: Header,
) -> Result<VerifiedHeader, VerifyError> {
    verify_header(params, parent, header, NOW)
}

fn extend(
    params: &Params,
    parent: &VerifiedHeader,
    draft: Draft,
    pool: &[Validator],
) -> VerifiedHeader {
    let header = seal(params, parent, draft, pool);
    verify(params, parent, header).unwrap()
}

/// A tickets mark for the epoch after `parent`'s: one ticket per slot, won by the
/// validators of `pool` (the parent's pending set) under the `η3'` of that epoch.
fn tickets_mark(params: &Params, parent: &VerifiedHeader, pool: &[Validator]) -> Vec<Ticket> {
    let eta3_next = parent.post_state.entropy()[2];
    (0..params.epoch_len)
        .map(|i| {
            let validator = &pool[usize::try_from(i).unwrap() % pool.len()];
            let attempt = u8::try_from(i % 3).unwrap();
            Ticket {
                id: vrf_output(&validator.secret, &ticket_context(&eta3_next, attempt)),
                attempt,
            }
        })
        .collect()
}

struct Sets {
    active: Vec<Validator>,
    pending: Vec<Validator>,
    next: Vec<Validator>,
    later: Vec<Validator>,
}

fn sets() -> Sets {
    Sets {
        active: validators(b"genesis active set"),
        pending: validators(b"genesis pending set"),
        next: validators(b"first epoch mark set"),
        later: validators(b"second epoch mark set"),
    }
}

fn all(sets: &Sets) -> Vec<&Validator> {
    [&sets.active, &sets.pending, &sets.next, &sets.later]
        .into_iter()
        .flatten()
        .collect()
}

fn genesis(params: &Params, sets: &Sets) -> VerifiedHeader {
    let entropy = [[0xa0; 32], [0xa1; 32], [0xa2; 32], [0xa3; 32]];
    let active = pairs(&sets.active);
    let sealing =
        SealingSequence::Keys(fallback_key_sequence(params, &entropy[2], &active).unwrap());
    let state = LightState::from_parts(entropy, active, pairs(&sets.pending), sealing, None, 0);
    let header = Header {
        parent: [0; 32],
        prior_state_root: [0; 32],
        extrinsic_hash: [0; 32],
        slot: 0,
        epoch_mark: None,
        tickets_mark: None,
        author_index: u16::MAX,
        entropy_source: [0; 96],
        offenders_mark: Vec::new(),
        seal: [0; 96],
    };
    let genesis = verified_genesis(params, header.clone(), state.clone());
    assert_eq!(genesis.hash, header.hash(params));
    assert_eq!(genesis.slot, 0);
    assert_eq!(genesis.post_state, state);
    assert!(!genesis.sealed_with_ticket && !genesis.epoch_changed);
    genesis
}

// Positive synthetic chains.

fn decoded(params: &Params, block: &VerifiedHeader) -> Header {
    Header::decode(params, &block.encoded).unwrap()
}

impl crate::jam::tree::HeaderTree {
    // Expose the signing harness without making the verifier's test module public.
    pub(crate) fn signed_child_fixture() -> (Params, VerifiedHeader, Header, u64) {
        let params = tiny_params();
        let sets = sets();
        let root = genesis(&params, &sets);
        let child = seal(&params, &root, draft(1), &sets.active);
        (params, root, child, NOW)
    }
}

impl crate::jam::tree::HeaderTree {
    pub(crate) fn signed_markless_fixtures() -> (Params, VerifiedHeader, Vec<Header>, u64) {
        let params = tiny_params();
        let sets = sets();
        let root = genesis(&params, &sets);
        let headers = (0u32..100)
            .map(|i| {
                let mut header = seal(&params, &root, draft(1), &sets.active);
                header.extrinsic_hash[..4].copy_from_slice(&i.to_le_bytes());
                let (_, validator, context) =
                    author(&params, &expected(&params, &root, 1), &sets.active, 1);
                header.seal = vrf_sign(
                    &validator.secret,
                    &context,
                    &header.encode_unsigned(&params),
                );
                header
            })
            .collect();
        (params, root, headers, NOW)
    }
}

#[test]
fn epoch_change_activates_pending_set_not_the_mark() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    assert_ne!(
        genesis.post_state.epoch().active,
        genesis.post_state.epoch().pending
    );

    let h1 = extend(&params, &genesis, draft(3), &sets.active);
    assert!(!h1.epoch_changed && !h1.sealed_with_ticket);
    assert_eq!(h1.post_state.epoch().active, pairs(&sets.active));
    assert_eq!(h1.post_state.epoch().pending, pairs(&sets.pending));
    assert_eq!(
        h1.post_state.entropy()[1..],
        genesis.post_state.entropy()[1..]
    );
    assert_ne!(h1.post_state.entropy()[0], genesis.post_state.entropy()[0]);
    assert_eq!(h1.post_state.slot(), 3);
    assert_eq!(
        h1.post_state.epoch().sealing,
        genesis.post_state.epoch().sealing
    );

    // First epoch change: the genesis *pending* set seals, the mark's set queues.
    let mut d2 = draft(12);
    d2.epoch_mark = Some(mark(&h1, &pairs(&sets.next)));
    let h2 = extend(&params, &h1, d2.clone(), &sets.pending);
    assert!(h2.epoch_changed && !h2.sealed_with_ticket);
    assert_eq!(h2.post_state.epoch().active, pairs(&sets.pending));
    assert_eq!(h2.post_state.epoch().pending, pairs(&sets.next));
    let eta = h1.post_state.entropy();
    assert_eq!(h2.post_state.entropy()[1..], [eta[0], eta[1], eta[2]]);
    assert_eq!(
        h2.post_state.epoch().sealing,
        SealingSequence::Keys(
            fallback_key_sequence(&params, &eta[1], &pairs(&sets.pending)).unwrap()
        )
    );
    assert_eq!(h2.post_state.pending_tickets(), None);
    let author_key =
        h2.post_state.epoch().active[usize::from(decoded(&params, &h2).author_index)].0;
    assert!(sets.pending.iter().any(|v| v.keys.0 == author_key));

    // The same header sealed as if the mark's set (or the old active set) had
    // become active is rejected.
    for wrong in [&sets.next, &sets.active] {
        let wrong_pairs = pairs(wrong);
        let sealing = fallback_key_sequence(&params, &eta[1], &wrong_pairs).unwrap();
        let wrong_expected = Expected {
            active: wrong_pairs,
            eta3: eta[2],
            sealing: SealingSequence::Keys(sealing),
        };
        let (index, validator, context) = author(&params, &wrong_expected, wrong, 12);
        let header = seal_with(&params, &h1, d2.clone(), index, validator, &context);
        assert!(matches!(
            verify(&params, &h1, header),
            Err(VerifyError::FallbackAuthorMismatch | VerifyError::BadSealSignature(_))
        ));
    }

    // Second epoch change: the mark's set from h2 seals, the new mark queues.
    let mut d3 = draft(24);
    d3.epoch_mark = Some(mark(&h2, &pairs(&sets.later)));
    let h3 = extend(&params, &h2, d3, &sets.next);
    assert_eq!(h3.post_state.epoch().active, pairs(&sets.next));
    assert_eq!(h3.post_state.epoch().pending, pairs(&sets.later));
    let h4 = extend(&params, &h3, draft(25), &sets.next);
    assert_eq!(h4.post_state.epoch().active, pairs(&sets.next));
    assert_eq!(h4.post_state.epoch().sealing, h3.post_state.epoch().sealing);
    assert_eq!(h4.hash, decoded(&params, &h4).hash(&params));
    assert_eq!(h4.parent, h3.hash);
}

#[test]
fn shrinking_and_growing_sets_use_post_rotation_author_bounds() {
    let mut params = tiny_params();
    params.core_count = 4;
    params.max_validators = 12;
    for grow in [false, true] {
        let mut sets = sets();
        if grow {
            sets.pending.extend(validators(b"larger pending"));
        } else {
            sets.active.extend(validators(b"larger active"));
            sets.next.extend(validators(b"larger next"));
        }
        let root = genesis(&params, &sets);
        root.post_state.validate(&params).unwrap();
        // Two rotations exercise both sizes in the active position, including
        // a smaller pending mark while twelve validators are active.
        let mut parent = root;
        for (slot, active, next) in [
            (12, &sets.pending, &sets.next),
            (24, &sets.next, &sets.later),
        ] {
            let draft = Draft {
                slot,
                epoch_mark: Some(mark(&parent, &pairs(next))),
                tickets_mark: None,
            };
            let expected = expected(&params, &parent, slot);
            let (_, signer, context) = author(&params, &expected, active, slot);
            let invalid = seal_with(
                &params,
                &parent,
                draft.clone(),
                u16::try_from(active.len()).unwrap(),
                signer,
                &context,
            );
            // The signature is authentic; only its index is outside the new set.
            assert!(
                crate::jam::crypto::bandersnatch_vrf_verify(
                    &signer.keys.0,
                    &context,
                    &invalid.encode_unsigned(&params),
                    &invalid.seal,
                )
                .is_ok()
            );
            assert_eq!(
                verify(&params, &parent, invalid),
                Err(VerifyError::AuthorIndexOutOfRange)
            );
            let child = extend(&params, &parent, draft, active);
            assert_eq!(child.post_state.epoch().active, pairs(active));
            assert_eq!(child.post_state.epoch().pending, pairs(next));
            child.post_state.validate(&params).unwrap();
            parent = child;
        }
    }
}

#[test]
fn epoch_marks_reject_illegal_variable_counts_before_rotation() {
    let mut params = tiny_params();
    params.core_count = 4;
    params.max_validators = 12;
    let sets = sets();
    let root = genesis(&params, &sets);
    for count in [0, 3, 5, 7, 13, 15] {
        let draft = Draft {
            slot: 12,
            epoch_mark: Some(mark(&root, &vec![sets.next[0].keys; count])),
            tickets_mark: None,
        };
        let header = seal(&params, &root, draft, &sets.pending);
        assert_eq!(
            verify(&params, &root, header),
            Err(VerifyError::EpochMarkLength)
        );
    }
}

#[test]
fn tickets_mark_seals_the_next_epoch() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    let tickets = tickets_mark(&params, &genesis, &sets.pending);

    let mut d1 = draft(10);
    d1.tickets_mark = Some(tickets.clone());
    let h1 = extend(&params, &genesis, d1, &sets.active);
    assert!(!h1.sealed_with_ticket);
    assert_eq!(h1.post_state.pending_tickets(), Some(tickets.as_slice()));
    assert_eq!(
        h1.post_state.epoch().sealing,
        genesis.post_state.epoch().sealing
    );

    let h2 = extend(&params, &h1, draft(11), &sets.active);
    assert_eq!(h2.post_state.pending_tickets(), Some(tickets.as_slice()));

    let mut d3 = draft(12);
    d3.epoch_mark = Some(mark(&h2, &pairs(&sets.next)));
    let h3 = extend(&params, &h2, d3, &sets.pending);
    assert!(h3.epoch_changed && h3.sealed_with_ticket);
    assert_eq!(
        h3.post_state.epoch().sealing,
        SealingSequence::Tickets(tickets.clone())
    );
    assert_eq!(h3.post_state.pending_tickets(), None);
    assert_eq!(h3.post_state.epoch().active, pairs(&sets.pending));

    let h4 = extend(&params, &h3, draft(17), &sets.pending);
    assert!(h4.sealed_with_ticket && !h4.epoch_changed);
    assert_eq!(
        h4.post_state.epoch().sealing,
        SealingSequence::Tickets(tickets)
    );

    // Without a tickets mark in the tail, the next epoch falls back to keys.
    let mut d5 = draft(24);
    d5.epoch_mark = Some(mark(&h4, &pairs(&sets.later)));
    let h5 = extend(&params, &h4, d5, &sets.next);
    assert!(h5.epoch_changed && !h5.sealed_with_ticket);
    assert!(matches!(
        h5.post_state.epoch().sealing,
        SealingSequence::Keys(_)
    ));
}

#[test]
fn pre_tail_saturated_anchor_verifies_fallback_next_epoch() {
    let params = tiny_params();
    let sets = sets();
    let base = genesis(&params, &sets);
    let parent = extend(&params, &base, draft(9), &sets.active);
    let keys = |pairs: &[ValidatorPair]| {
        pairs
            .iter()
            .map(|&(bandersnatch, ed25519)| ValidatorKey {
                bandersnatch,
                ed25519,
                bls: [0; 144],
                metadata: [0; 128],
            })
            .collect()
    };
    let mut accumulator = tickets_mark(&params, &parent, &sets.pending);
    accumulator.sort_by_key(|ticket| ticket.id);
    let anchor = GenesisLightState {
        safrole: SafroleState {
            pending_validators: keys(&parent.post_state.epoch().pending),
            epoch_root: [0; 144],
            sealing: parent.post_state.epoch().sealing.clone(),
            ticket_accumulator: accumulator,
        },
        entropy: parent.post_state.entropy(),
        active_validators: keys(&parent.post_state.epoch().active),
        slot: parent.slot,
    };
    let state = LightState::from_anchor(&params, &anchor).unwrap();
    assert_eq!(state, parent.post_state);
    assert_eq!(state.pending_tickets(), None);
    let anchored = verified_genesis(&params, decoded(&params, &parent), state);
    let mut d = draft(12);
    d.epoch_mark = Some(mark(&parent, &pairs(&sets.next)));
    let header = seal(&params, &parent, d, &sets.pending);
    let verified = verify(&params, &anchored, header.clone()).unwrap();
    assert!(!verified.sealed_with_ticket && verified.epoch_changed);
    assert_eq!(verified, verify(&params, &parent, header).unwrap());
}

#[test]
fn skipped_epoch_discards_tickets() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    let tickets = tickets_mark(&params, &genesis, &sets.pending);
    let mut d1 = draft(10);
    d1.tickets_mark = Some(tickets.clone());
    let h1 = extend(&params, &genesis, d1, &sets.active);

    let mut d2 = draft(24);
    d2.epoch_mark = Some(mark(&h1, &pairs(&sets.next)));
    let h2 = extend(&params, &h1, d2.clone(), &sets.pending);
    assert!(h2.epoch_changed && !h2.sealed_with_ticket);
    assert_eq!(h2.post_state.epoch().active, pairs(&sets.pending));
    assert_eq!(
        h2.post_state.epoch().sealing,
        SealingSequence::Keys(
            fallback_key_sequence(&params, &h1.post_state.entropy()[1], &pairs(&sets.pending))
                .unwrap()
        )
    );

    // Sealing the skipped-epoch header with the discarded tickets is rejected.
    let ticket_expected = Expected {
        active: pairs(&sets.pending),
        eta3: h1.post_state.entropy()[2],
        sealing: SealingSequence::Tickets(tickets),
    };
    let (index, validator, context) = author(&params, &ticket_expected, &sets.pending, 24);
    let header = seal_with(&params, &h1, d2, index, validator, &context);
    assert!(matches!(
        verify(&params, &h1, header),
        Err(VerifyError::FallbackAuthorMismatch | VerifyError::BadSealSignature(_))
    ));
}

#[test]
fn tickets_mark_position_rule() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    let tickets = tickets_mark(&params, &genesis, &sets.pending);
    let with_mark = |slot: u32| {
        let mut d = draft(slot);
        d.tickets_mark = Some(tickets.clone());
        d
    };
    let seal_on = |parent: &VerifiedHeader, d: Draft| seal(&params, parent, d, &sets.active);

    // Allowed: parent phase < Y <= phase, same epoch, including skipped slots.
    assert!(verify(&params, &genesis, seal_on(&genesis, with_mark(10))).is_ok());
    assert!(verify(&params, &genesis, seal_on(&genesis, with_mark(11))).is_ok());
    let h9 = extend(&params, &genesis, draft(9), &sets.active);
    assert!(verify(&params, &h9, seal_on(&h9, with_mark(11))).is_ok());

    // Not the first tail block: parent already in the tail.
    let h10 = extend(&params, &genesis, draft(10), &sets.active);
    assert_eq!(
        verify(&params, &h10, seal_on(&h10, with_mark(11))),
        Err(VerifyError::TicketsMarkUnexpected)
    );
    // Before the tail.
    assert_eq!(
        verify(&params, &genesis, seal_on(&genesis, with_mark(5))),
        Err(VerifyError::TicketsMarkUnexpected)
    );
    // On an epoch change, with and without the epoch mark.
    let mut d = with_mark(12);
    d.epoch_mark = Some(mark(&h9, &pairs(&sets.next)));
    assert_eq!(
        verify(&params, &h9, seal(&params, &h9, d, &sets.pending)),
        Err(VerifyError::TicketsMarkUnexpected)
    );
    assert_eq!(
        verify(
            &params,
            &h9,
            seal(&params, &h9, with_mark(12), &sets.pending)
        ),
        Err(VerifyError::EpochMarkMissing)
    );

    // Right position, wrong length.
    for len in [0, 11, 13] {
        let mut d = draft(10);
        d.tickets_mark = Some(vec![tickets[0].clone(); len]);
        assert_eq!(
            verify(&params, &genesis, seal_on(&genesis, d)),
            Err(VerifyError::TicketsMarkLength)
        );
    }
}

#[test]
fn slot_time_tolerance() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    let header = seal(&params, &genesis, draft(7), &sets.active);
    let start = JAM_COMMON_ERA + 7 * 6;
    assert!(verify_header(&params, &genesis, header.clone(), start - 6).is_ok());
    assert!(verify_header(&params, &genesis, header.clone(), start + 1_000_000).is_ok());
    assert_eq!(
        verify_header(&params, &genesis, header.clone(), start - 7),
        Err(VerifyError::SlotInFuture)
    );
    assert_eq!(
        verify_header(&params, &genesis, header.clone(), 0),
        Err(VerifyError::SlotInFuture)
    );
    assert!(verify_header(&params, &genesis, header, u64::MAX).is_ok());

    // Widened arithmetic: the largest slot and slot period start ~1.8e19 seconds
    // after the era, still in the future for a plausible clock (the time check
    // precedes everything that looks at the seal, so the broken seal is moot).
    let mut huge = params.clone();
    huge.slot_seconds = u32::MAX;
    let mut far = seal(&params, &genesis, draft(7), &sets.active);
    far.slot = u32::MAX;
    assert_eq!(
        verify_header(&huge, &genesis, far.clone(), JAM_COMMON_ERA + 1_000_000_000),
        Err(VerifyError::SlotInFuture)
    );
    assert_eq!(
        verify_header(&huge, &genesis, far, u64::MAX),
        Err(VerifyError::EpochMarkMissing)
    );
}

// Negative tests: one per `VerifyError` variant, in check order.

#[test]
fn rejects_invalid_parent_state() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    let header = seal(&params, &genesis, draft(1), &sets.active);

    let mut zero_epoch = params.clone();
    zero_epoch.epoch_len = 0;
    assert_eq!(
        verify_header(&zero_epoch, &genesis, header.clone(), NOW),
        Err(VerifyError::InvalidParentState(StateError::ZeroEpochLength))
    );
    let mut zero_validators = params.clone();
    zero_validators.max_validators = 0;
    assert_eq!(
        verify_header(&zero_validators, &genesis, header.clone(), NOW),
        Err(VerifyError::InvalidParentState(
            StateError::ZeroValidatorCount
        ))
    );
    let mut empty = genesis.clone();
    empty.post_state.epoch_mut().pending.clear();
    assert_eq!(
        verify(&params, &empty, header.clone()),
        Err(VerifyError::InvalidParentState(
            StateError::EmptyValidatorSet
        ))
    );
    let mut short = genesis.clone();
    short.post_state.epoch_mut().sealing = SealingSequence::Keys(Vec::new());
    assert_eq!(
        verify(&params, &short, header.clone()),
        Err(VerifyError::InvalidParentState(StateError::SealingLength))
    );
    let mut bad_tickets = genesis;
    bad_tickets.post_state.set_pending_tickets(&[Ticket {
        id: [0; 32],
        attempt: 0,
    }]);
    assert_eq!(
        verify(&params, &bad_tickets, header),
        Err(VerifyError::InvalidParentState(StateError::SealingLength))
    );
}

#[test]
fn rejects_wrong_parent() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    let mut header = seal(&params, &genesis, draft(1), &sets.active);
    header.parent[0] ^= 1;
    assert_eq!(
        verify(&params, &genesis, header),
        Err(VerifyError::ParentMismatch)
    );
}

#[test]
fn rejects_non_increasing_slot() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    let h5 = extend(&params, &genesis, draft(5), &sets.active);
    for slot in [0, 4, 5] {
        let header = seal(&params, &h5, draft(slot), &sets.active);
        assert_eq!(
            verify(&params, &h5, header),
            Err(VerifyError::SlotNotIncreasing)
        );
    }
}

#[test]
fn rejects_epoch_mark_errors() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);

    let header = seal(&params, &genesis, draft(12), &sets.pending);
    assert_eq!(
        verify(&params, &genesis, header),
        Err(VerifyError::EpochMarkMissing)
    );

    let mut d = draft(4);
    d.epoch_mark = Some(mark(&genesis, &pairs(&sets.next)));
    let header = seal(&params, &genesis, d, &sets.active);
    assert_eq!(
        verify(&params, &genesis, header),
        Err(VerifyError::EpochMarkUnexpected)
    );

    for len in [0, 5, 7] {
        let mut d = draft(12);
        let mut validators = pairs(&sets.next);
        validators.resize(len, ([0; 32], [0; 32]));
        d.epoch_mark = Some(mark(&genesis, &validators));
        let header = seal(&params, &genesis, d, &sets.pending);
        assert_eq!(
            verify(&params, &genesis, header),
            Err(VerifyError::EpochMarkLength)
        );
    }
}

#[test]
fn rejects_epoch_mark_entropy_mismatch() {
    rejects_epoch_entropy_mismatch(VerifyError::EpochMarkEntropyMismatch);
}

#[test]
fn rejects_epoch_mark_tickets_entropy_mismatch() {
    rejects_epoch_entropy_mismatch(VerifyError::EpochMarkTicketsEntropyMismatch);
}

fn rejects_epoch_entropy_mismatch(error: VerifyError) {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    for with_tickets in [false, true] {
        let mut d = draft(10);
        if with_tickets {
            d.tickets_mark = Some(tickets_mark(&params, &genesis, &sets.pending));
        }
        let parent = extend(&params, &genesis, d, &sets.active);
        // Consecutive and skipped epochs both use the prior state's entropy.
        for slot in [12, 24] {
            let mut d = draft(slot);
            d.epoch_mark = Some(mark(&parent, &pairs(&sets.next)));
            let good = seal(&params, &parent, d.clone(), &sets.pending);
            let verified = verify(&params, &parent, good.clone()).unwrap();
            assert_eq!(verified.sealed_with_ticket, with_tickets && slot == 12);

            let mark = d.epoch_mark.as_mut().unwrap();
            match error {
                VerifyError::EpochMarkEntropyMismatch => mark.entropy[0] ^= 1,
                VerifyError::EpochMarkTicketsEntropyMismatch => mark.tickets_entropy[0] ^= 1,
                _ => unreachable!(),
            }
            let expected = expected(&params, &parent, slot);
            let (index, validator, context) = author(&params, &expected, &sets.pending, slot);
            let bad = seal_with(&params, &parent, d, index, validator, &context);
            assert_eq!(bad.author_index, good.author_index);
            assert_ne!(bad.seal, good.seal);

            // Verify both signatures independently: only the mark field is wrong.
            let output = bandersnatch_vrf_verify(
                &validator.keys.0,
                &context,
                &bad.encode_unsigned(&params),
                &bad.seal,
            )
            .unwrap();
            let entropy_context = [b"jam_entropy".as_slice(), &output.0].concat();
            bandersnatch_vrf_verify(
                &validator.keys.0,
                &entropy_context,
                &[],
                &bad.entropy_source,
            )
            .unwrap();
            assert_eq!(verify(&params, &parent, bad), Err(error));
        }
    }
}

#[test]
fn rejects_author_errors() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    let good = seal(&params, &genesis, draft(2), &sets.active);
    assert!(verify(&params, &genesis, good.clone()).is_ok());

    for index in [6, 7, u16::MAX] {
        let mut header = good.clone();
        header.author_index = index;
        assert_eq!(
            verify(&params, &genesis, header),
            Err(VerifyError::AuthorIndexOutOfRange)
        );
    }

    let mut header = good.clone();
    header.author_index = (good.author_index + 1) % 6;
    assert_eq!(
        verify(&params, &genesis, header),
        Err(VerifyError::FallbackAuthorMismatch)
    );
}

#[test]
fn rejects_bad_seal_signature() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    let good = seal(&params, &genesis, draft(2), &sets.active);

    // Every mutation of the unsigned header not caught earlier breaks the seal.
    let mut header = good.clone();
    header.prior_state_root[0] ^= 1;
    assert_eq!(
        verify(&params, &genesis, header),
        Err(VerifyError::BadSealSignature(VrfError::VerificationFailed))
    );
    let mut header = good.clone();
    header.extrinsic_hash[31] ^= 1;
    assert_eq!(
        verify(&params, &genesis, header),
        Err(VerifyError::BadSealSignature(VrfError::VerificationFailed))
    );
    let mut header = good.clone();
    header.offenders_mark.push([9; 32]);
    assert_eq!(
        verify(&params, &genesis, header),
        Err(VerifyError::BadSealSignature(VrfError::VerificationFailed))
    );
    let mut header = good.clone();
    header.entropy_source[40] ^= 1;
    assert_eq!(
        verify(&params, &genesis, header),
        Err(VerifyError::BadSealSignature(VrfError::VerificationFailed))
    );
    for i in [0, 31, 32, 63, 64, 95] {
        let mut header = good.clone();
        header.seal[i] ^= 1;
        assert!(matches!(
            verify(&params, &genesis, header),
            Err(VerifyError::BadSealSignature(_))
        ));
    }
    let mut header = good.clone();
    header.seal = [0; 96];
    assert_eq!(
        verify(&params, &genesis, header),
        Err(VerifyError::BadSealSignature(VrfError::InvalidEncoding))
    );
    // Signed under the wrong entropy.
    let expected = expected(&params, &genesis, 2);
    let (index, validator, _) = author(&params, &expected, &sets.active, 2);
    let header = seal_with(
        &params,
        &genesis,
        draft(2),
        index,
        validator,
        &fallback_context(&[7; 32]),
    );
    assert_eq!(
        verify(&params, &genesis, header),
        Err(VerifyError::BadSealSignature(VrfError::VerificationFailed))
    );
}

#[test]
fn rejects_seal_ticket_mismatch() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    let tickets = tickets_mark(&params, &genesis, &sets.pending);
    let mut d1 = draft(10);
    d1.tickets_mark = Some(tickets.clone());
    let h1 = extend(&params, &genesis, d1, &sets.active);

    let mut d2 = draft(12);
    d2.epoch_mark = Some(mark(&h1, &pairs(&sets.next)));
    let expected = expected(&params, &h1, 12);
    let (index, winner, context) = author(&params, &expected, &sets.pending, 12);
    let good = seal_with(&params, &h1, d2.clone(), index, winner, &context);
    assert!(verify(&params, &h1, good).unwrap().sealed_with_ticket);

    // A valid seal by another validator of the epoch under the ticket's context:
    // the VRF verifies but its output is not the winning ticket.
    let other_index = (index + 1) % 6;
    let other = &sets.pending[usize::from(other_index)];
    assert_ne!(other.keys, winner.keys);
    let header = seal_with(&params, &h1, d2.clone(), other_index, other, &context);
    assert_eq!(
        verify(&params, &h1, header),
        Err(VerifyError::SealTicketMismatch)
    );

    // The winner signing with another attempt does not even verify.
    let wrong_attempt = ticket_context(&expected.eta3, (tickets[0].attempt + 1) % 3);
    let header = seal_with(&params, &h1, d2, index, winner, &wrong_attempt);
    assert_eq!(
        verify(&params, &h1, header),
        Err(VerifyError::BadSealSignature(VrfError::VerificationFailed))
    );
}

#[test]
fn rejects_bad_entropy_signature() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    let expected = expected(&params, &genesis, 2);
    let (index, validator, context) = author(&params, &expected, &sets.active, 2);
    let reseal = |header: &mut Header| {
        let unsigned = header.encode_unsigned(&params);
        header.seal = vrf_sign(&validator.secret, &context, &unsigned);
    };

    // Entropy source signed over the wrong seal output, the seal itself valid.
    let mut header = seal_with(&params, &genesis, draft(2), index, validator, &context);
    header.entropy_source = vrf_sign(&validator.secret, b"jam_entropy", &[]);
    reseal(&mut header);
    assert_eq!(
        verify(&params, &genesis, header.clone()),
        Err(VerifyError::BadEntropySignature(
            VrfError::VerificationFailed
        ))
    );

    // Entropy source signed by another validator over the right output.
    let other = &sets.active[usize::from((index + 1) % 6)];
    let seal_output = vrf_output(&validator.secret, &context);
    let entropy_context = [b"jam_entropy".as_slice(), &seal_output].concat();
    header.entropy_source = vrf_sign(&other.secret, &entropy_context, &[]);
    reseal(&mut header);
    assert_eq!(
        verify(&params, &genesis, header.clone()),
        Err(VerifyError::BadEntropySignature(
            VrfError::VerificationFailed
        ))
    );

    header.entropy_source = [0; 96];
    reseal(&mut header);
    assert_eq!(
        verify(&params, &genesis, header),
        Err(VerifyError::BadEntropySignature(VrfError::InvalidEncoding))
    );
}

#[test]
fn error_display_is_distinct() {
    let errors = [
        VerifyError::InvalidParentState(StateError::ZeroEpochLength),
        VerifyError::ParentMismatch,
        VerifyError::SlotNotIncreasing,
        VerifyError::SlotInFuture,
        VerifyError::EpochMarkMissing,
        VerifyError::EpochMarkUnexpected,
        VerifyError::EpochMarkLength,
        VerifyError::EpochMarkEntropyMismatch,
        VerifyError::EpochMarkTicketsEntropyMismatch,
        VerifyError::TicketsMarkUnexpected,
        VerifyError::TicketsMarkLength,
        VerifyError::AuthorIndexOutOfRange,
        VerifyError::FallbackAuthorMismatch,
        VerifyError::BadSealSignature(VrfError::VerificationFailed),
        VerifyError::SealTicketMismatch,
        VerifyError::BadEntropySignature(VrfError::InvalidEncoding),
    ];
    let texts: Vec<_> = errors.iter().map(|e| alloc::format!("{e}")).collect();
    for (i, text) in texts.iter().enumerate() {
        assert!(!text.is_empty());
        assert!(texts.iter().skip(i + 1).all(|other| other != text));
    }
}

// Fuzzing: `verify_header` is total over mutated headers.

fn mutate_bytes(rng: &mut rand::rngs::StdRng, bytes: &mut Vec<u8>) {
    for _ in 0..rng.gen_range(1..4) {
        match rng.gen_range(0..4) {
            0 if !bytes.is_empty() => {
                let i = rng.gen_range(0..bytes.len());
                bytes[i] ^= 1 << rng.gen_range(0..8);
            }
            1 if !bytes.is_empty() => {
                let i = rng.gen_range(0..bytes.len());
                bytes[i] = rng.r#gen();
            }
            2 => {
                let i = rng.gen_range(0..=bytes.len());
                bytes.insert(i, rng.r#gen());
            }
            _ if !bytes.is_empty() => {
                let i = rng.gen_range(0..bytes.len());
                bytes.remove(i);
            }
            _ => bytes.push(rng.r#gen()),
        }
    }
}

fn mutate_header(rng: &mut rand::rngs::StdRng, header: &mut Header, pool: &[ValidatorPair]) {
    match rng.gen_range(0..9) {
        0 => header.parent = rng.r#gen(),
        1 => header.slot = rng.r#gen::<u32>() >> rng.gen_range(0..32),
        2 => header.author_index = rng.gen_range(0..8),
        3 => {
            let len = rng.gen_range(0..8);
            header.epoch_mark = Some(EpochMark {
                entropy: rng.r#gen(),
                tickets_entropy: rng.r#gen(),
                validators: pool.iter().cycle().take(len).copied().collect(),
            });
        }
        4 => header.epoch_mark = None,
        5 => {
            let len = rng.gen_range(0..14);
            header.tickets_mark = Some(
                (0..len)
                    .map(|_| Ticket {
                        id: rng.r#gen(),
                        attempt: rng.gen_range(0..4),
                    })
                    .collect(),
            );
        }
        6 => header.tickets_mark = None,
        7 => header.seal[rng.gen_range(0..96)] ^= 1 << rng.gen_range(0..8),
        _ => header.entropy_source[rng.gen_range(0..96)] ^= 1 << rng.gen_range(0..8),
    }
}

#[test]
fn fuzzed_headers_never_panic() {
    let params = tiny_params();
    let sets = sets();
    let genesis = genesis(&params, &sets);
    let tickets = tickets_mark(&params, &genesis, &sets.pending);
    let mut d1 = draft(10);
    d1.tickets_mark = Some(tickets);
    let h1 = extend(&params, &genesis, d1, &sets.active);
    let mut d2 = draft(12);
    d2.epoch_mark = Some(mark(&h1, &pairs(&sets.next)));
    let h2 = extend(&params, &h1, d2, &sets.pending);
    let h3 = extend(&params, &h2, draft(13), &sets.pending);
    let seeds = [
        (&genesis, decoded(&params, &h1)),
        (&h1, decoded(&params, &h2)),
        (&h2, decoded(&params, &h3)),
    ];
    let pool: Vec<ValidatorPair> = all(&sets).into_iter().map(|v| v.keys).collect();
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xB3);
    let mut decoded = 0;
    let mut rejected = 0;
    for round in 0..3000 {
        let (parent, original) = &seeds[round % seeds.len()];
        let mut header = original.clone();
        if round % 2 == 0 {
            let mut bytes = header.encode(&params);
            mutate_bytes(&mut rng, &mut bytes);
            let Ok(mutated) = Header::decode(&params, &bytes) else {
                continue;
            };
            header = mutated;
            decoded += 1;
        } else {
            for _ in 0..rng.gen_range(1..3) {
                mutate_header(&mut rng, &mut header, &pool);
            }
        }
        let now = if rng.gen_bool(0.9) {
            NOW
        } else {
            rng.next_u64()
        };
        match verify_header(&params, parent, header, now) {
            Ok(verified) => assert_eq!(
                Header::decode(&params, &verified.encoded).unwrap(),
                *original
            ),
            Err(_) => rejected += 1,
        }
    }
    assert!(decoded > 100, "{decoded}");
    assert!(rejected > 1000, "{rejected}");

    // Degenerate parent states never panic either.
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xB4);
    for _ in 0..200 {
        let mut parent = genesis.clone();
        parent
            .post_state
            .epoch_mut()
            .active
            .truncate(rng.gen_range(0..7));
        parent
            .post_state
            .epoch_mut()
            .pending
            .truncate(rng.gen_range(0..7));
        parent
            .post_state
            .set_slot(rng.r#gen::<u32>() >> rng.gen_range(0..32));
        if rng.gen_bool(0.5) {
            parent.post_state.epoch_mut().sealing =
                SealingSequence::Keys(vec![rng.r#gen(); rng.gen_range(0..14)]);
        }
        let mut params = params.clone();
        if rng.gen_bool(0.2) {
            params.epoch_len = rng.gen_range(0..3);
        }
        let _ = verify_header(&params, &parent, seeds[0].1.clone(), NOW);
    }
}

// External A5 fixtures: PolkaJam's captured dev chain.

fn fixture_root() -> std::path::PathBuf {
    std::env::var_os("JAM_A5_FIXTURES")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/home/sebastian/work/repos/jam-light-client-planning/fixtures".into())
}

fn load_json(path: &std::path::Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap()
}

fn json_hex(value: &serde_json::Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn json_hash(value: &serde_json::Value) -> Hash {
    json_hex(value).try_into().unwrap()
}

fn json_pairs(value: &serde_json::Value) -> Vec<ValidatorPair> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (json_hash(&v["bandersnatch"]), json_hash(&v["ed25519"])))
        .collect()
}

fn json_sealing(value: &serde_json::Value) -> SealingSequence {
    match value["mode"].as_str().unwrap() {
        "fallback" => SealingSequence::Keys(
            value["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(json_hash)
                .collect(),
        ),
        "ticket" => SealingSequence::Tickets(
            value["tickets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| Ticket {
                    id: json_hash(&t["id"]),
                    attempt: u8::try_from(t["attempt"].as_u64().unwrap()).unwrap(),
                })
                .collect(),
        ),
        mode => panic!("{mode}"),
    }
}

/// Compares everything the light state tracks against a captured PolkaJam state.
fn assert_state(state: &LightState, expected: &serde_json::Value, what: &str) {
    let entropy: Vec<Hash> = expected["entropy"]
        .as_array()
        .unwrap()
        .iter()
        .map(json_hash)
        .collect();
    assert_eq!(state.entropy().as_slice(), entropy, "{what}: entropy");
    assert_eq!(
        state.epoch().active,
        json_pairs(&expected["active_validators"]),
        "{what}: active"
    );
    assert_eq!(
        state.epoch().pending,
        json_pairs(&expected["safrole"]["pending_validators"]),
        "{what}: pending"
    );
    assert_eq!(
        state.epoch().sealing,
        json_sealing(&expected["safrole"]["sealing"]),
        "{what}: sealing"
    );
    assert_eq!(
        u64::from(state.slot()),
        expected["slot"].as_u64().unwrap(),
        "{what}: slot"
    );
}

fn fixture_params(root: &std::path::Path) -> Params {
    let params = load_json(&root.join("params.json"));
    Params::from_protocol_parameters(&json_hex(&params["protocol_parameters"])).unwrap()
}

fn fixture_genesis(root: &std::path::Path, params: &Params) -> VerifiedHeader {
    let genesis = load_json(&root.join("genesis-state.json"));
    let header = Header::decode(params, &json_hex(&genesis["header_hex"])).unwrap();
    let state = fixture_anchor_state(params, &genesis["light_state"]);
    let state = LightState::from_anchor(params, &state).unwrap();
    assert_eq!(state.pending_tickets(), None);
    assert_state(&state, &genesis["light_state"], "genesis");
    let verified = verified_genesis(params, header, state);
    assert_eq!(verified.hash, json_hash(&genesis["header_hash"]));
    verified
}

fn fixture_anchor_state(params: &Params, state: &serde_json::Value) -> GenesisLightState {
    let items: Vec<([u8; 31], Vec<u8>)> = state["state_items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                json_hex(&item["key_hex"]).try_into().unwrap(),
                json_hex(&item["value_hex"]),
            )
        })
        .collect();
    GenesisLightState::from_state_items(
        params,
        items.iter().map(|(key, value)| (key, value.as_slice())),
    )
    .unwrap()
}

fn fixture_headers(root: &std::path::Path) -> Vec<serde_json::Value> {
    let mut paths: Vec<_> = std::fs::read_dir(root.join("headers"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    assert!(paths.len() >= 30, "{}", paths.len());
    paths.iter().map(|path| load_json(path)).collect()
}

#[test]
#[ignore = "requires external A5 fixtures; set JAM_A5_FIXTURES or use the planning checkout"]
fn a5_tail_anchor_replays_next_ticket_epoch() {
    let root = fixture_root();
    let params = fixture_params(&root);
    assert_eq!((params.epoch_len, params.epoch_tail_start), (12, 10));
    let fixtures = fixture_headers(&root);
    let epoch_len = usize::try_from(params.epoch_len).unwrap();
    // Select by captured protocol state, not the wall-clock slot of an old run.
    let anchor_index = fixtures
        .iter()
        .enumerate()
        .find_map(|(i, fixture)| {
            let slot = fixture["slot"].as_u64().unwrap();
            (slot % u64::from(params.epoch_len) == u64::from(params.epoch_len - 1)
                && fixtures.get(i + 1..i + 1 + epoch_len).is_some_and(|epoch| {
                    epoch.iter().enumerate().all(|(offset, header)| {
                        header["seal_mode"] == "ticket"
                            && header["slot"].as_u64().unwrap()
                                == slot + 1 + u64::try_from(offset).unwrap()
                    })
                }))
            .then_some(i)
        })
        .expect("capture must include a complete ticket epoch after a tail checkpoint");
    let anchor = fixture_anchor_state(&params, &fixtures[anchor_index]["post_light_state"]);
    assert_eq!(anchor.slot % params.epoch_len, 11);
    let accumulator = &anchor.safrole.ticket_accumulator;
    assert_eq!(accumulator.len(), 12);
    assert!(accumulator.windows(2).all(|pair| pair[0].id < pair[1].id));
    let mark_header = fixtures[..=anchor_index]
        .iter()
        .rev()
        .find_map(|fixture| {
            let header = Header::decode(&params, &json_hex(&fixture["header_hex"])).unwrap();
            (header.slot / params.epoch_len == anchor.slot / params.epoch_len
                && header.tickets_mark.is_some())
            .then_some(header)
        })
        .expect("captured tickets mark for checkpoint epoch");
    let winners = mark_header.tickets_mark.unwrap();
    let outside_in: Vec<_> = [0, 11, 1, 10, 2, 9, 3, 8, 4, 7, 5, 6]
        .into_iter()
        .map(|i| accumulator[i].clone())
        .collect();
    assert_eq!(outside_in, winners);
    let state = LightState::from_anchor(&params, &anchor).unwrap();
    assert_eq!(state.pending_tickets(), Some(winners.as_slice()));
    assert_state(
        &state,
        &fixtures[anchor_index]["post_light_state"],
        "tail anchor",
    );
    let header = Header::decode(&params, &json_hex(&fixtures[anchor_index]["header_hex"])).unwrap();
    let mut tip = verified_genesis(&params, header, state);
    let mut replay = fixture_genesis(&root, &params);
    for fixture in &fixtures[..=anchor_index] {
        let header = Header::decode(&params, &json_hex(&fixture["header_hex"])).unwrap();
        replay = verify(&params, &replay, header).unwrap();
    }
    assert_eq!(tip.hash, replay.hash);
    assert_eq!(tip.post_state, replay.post_state);
    for (i, fixture) in fixtures
        .iter()
        .enumerate()
        .take(anchor_index + 1 + epoch_len)
        .skip(anchor_index + 1)
    {
        let what = alloc::format!("anchored header {i:04}");
        assert_state(&tip.post_state, &fixture["parent_light_state"], &what);
        let header = Header::decode(&params, &json_hex(&fixture["header_hex"])).unwrap();
        tip = verify(&params, &tip, header.clone()).unwrap();
        replay = verify(&params, &replay, header).unwrap();
        assert_eq!(tip, replay, "{what}");
        assert_eq!(tip.hash, json_hash(&fixture["header_hash"]));
        assert!(tip.sealed_with_ticket);
        assert_eq!(tip.epoch_changed, i == anchor_index + 1);
        assert_eq!(
            tip.post_state.epoch().sealing,
            SealingSequence::Tickets(winners.clone())
        );
        assert_state(&tip.post_state, &fixture["post_light_state"], &what);
        let decoded = fixture_anchor_state(&params, &fixture["post_light_state"]);
        assert_eq!(
            tip.post_state,
            LightState::from_anchor(&params, &decoded).unwrap()
        );
    }
    assert_eq!(tip.slot % params.epoch_len, 11);
    std::println!(
        "anchor {anchor_index:04}: Z(accumulator) equals captured mark; verified all {epoch_len} ticket headers with matching states"
    );
}

#[test]
#[ignore = "requires external A5 fixtures; set JAM_A5_FIXTURES or use the planning checkout"]
fn a5_chain_replays_from_genesis() {
    let root = fixture_root();
    let params = fixture_params(&root);
    assert_eq!((params.epoch_len, params.epoch_tail_start), (12, 10));
    let mut tip = fixture_genesis(&root, &params);
    let transitions = load_json(&root.join("epoch-transitions.json"));
    let transitions = transitions.as_array().unwrap();
    let (mut epochs, mut ticket_marks, mut tickets, mut fallbacks) = (0, 0, 0, 0);
    for (i, fixture) in fixture_headers(&root).iter().enumerate() {
        let what = alloc::format!("header {i} slot {}", fixture["slot"]);
        let header = Header::decode(&params, &json_hex(&fixture["header_hex"])).unwrap();
        assert_state(&tip.post_state, &fixture["parent_light_state"], &what);
        let verified = verify_header(&params, &tip, header, NOW)
            .unwrap_or_else(|error| panic!("{what}: {error}"));
        assert_eq!(verified.hash, json_hash(&fixture["header_hash"]), "{what}");
        assert_eq!(
            u64::from(verified.slot),
            fixture["slot"].as_u64().unwrap(),
            "{what}"
        );
        assert_eq!(
            u64::from(decoded(&params, &verified).author_index),
            fixture["author_index"].as_u64().unwrap(),
            "{what}"
        );
        let ticket_sealed = fixture["seal_mode"] == "ticket";
        assert_eq!(verified.sealed_with_ticket, ticket_sealed, "{what}");
        assert_eq!(
            verified.epoch_changed,
            fixture["has_epoch_mark"].as_bool().unwrap(),
            "{what}"
        );
        assert_state(&verified.post_state, &fixture["post_light_state"], &what);
        assert_eq!(
            verified.post_state.epoch().active
                [usize::from(decoded(&params, &verified).author_index)]
            .0,
            json_hash(&fixture["author_bandersnatch"]),
            "{what}"
        );
        assert_eq!(
            verified.post_state.entropy()[3],
            json_hash(&fixture["eta3_used_for_seal"]),
            "{what}"
        );
        if ticket_sealed {
            tickets += 1;
        } else {
            fallbacks += 1;
        }

        if verified.epoch_changed {
            epochs += 1;
            let transition = transitions
                .iter()
                .find(|t| t["header_hash"] == fixture["header_hash"])
                .unwrap_or_else(|| panic!("{what}: not in epoch-transitions.json"));
            assert_eq!(transition["seal_mode"], fixture["seal_mode"]);
            assert_state(&tip.post_state, &transition["parent_light_state"], &what);
            assert_state(&verified.post_state, &transition["post_light_state"], &what);
            // PolkaJam's NextEpochDescriptor is (η1', η2', pending') after rotation.
            let header = decoded(&params, &verified);
            let mark = header.epoch_mark.as_ref().unwrap();
            assert_eq!(mark.entropy, verified.post_state.entropy()[1], "{what}");
            assert_eq!(
                mark.tickets_entropy,
                verified.post_state.entropy()[2],
                "{what}"
            );
            assert_eq!(
                mark.validators,
                verified.post_state.epoch().pending,
                "{what}"
            );
            assert_eq!(
                verified.post_state.epoch().active,
                tip.post_state.epoch().pending,
                "{what}"
            );
            assert_eq!(verified.post_state.pending_tickets(), None, "{what}");
        } else {
            assert_eq!(
                verified.post_state.epoch().active,
                tip.post_state.epoch().active,
                "{what}"
            );
            assert_eq!(
                verified.post_state.epoch().pending,
                tip.post_state.epoch().pending,
                "{what}"
            );
            assert_eq!(
                verified.post_state.epoch().sealing,
                tip.post_state.epoch().sealing,
                "{what}"
            );
        }
        if fixture["has_tickets_mark"].as_bool().unwrap() {
            ticket_marks += 1;
            assert_eq!(
                verified.post_state.pending_tickets(),
                decoded(&params, &verified).tickets_mark.as_deref(),
                "{what}"
            );
        } else if !verified.epoch_changed {
            assert_eq!(
                verified.post_state.pending_tickets(),
                tip.post_state.pending_tickets(),
                "{what}"
            );
        }
        tip = verified;
    }
    assert_eq!(epochs, transitions.len());
    assert!(
        epochs >= 3,
        "capture must span at least three epoch changes"
    );
    assert!(
        ticket_marks >= 2,
        "capture must include repeated winner selection"
    );
    assert!(
        fallbacks > 0 && tickets >= 12,
        "capture must exercise both sealing modes"
    );
    std::println!(
        "replayed {} captured headers: {epochs} epoch changes, {ticket_marks} tickets marks, {fallbacks} fallback and {tickets} ticket seals",
        fallbacks + tickets
    );
}

#[test]
#[ignore = "requires external A5 fixtures; set JAM_A5_FIXTURES or use the planning checkout"]
fn a5_mutated_headers_are_rejected_and_never_panic() {
    let root = fixture_root();
    let params = fixture_params(&root);
    let mut tip = fixture_genesis(&root, &params);
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xA5);
    let mut fuzzed = 0;
    for fixture in fixture_headers(&root) {
        let header = Header::decode(&params, &json_hex(&fixture["header_hex"])).unwrap();
        let start = JAM_COMMON_ERA + u64::from(header.slot) * 6;
        let check = |header: Header, now: u64| verify_header(&params, &tip, header, now);

        let mut bad = header.clone();
        bad.parent[5] ^= 1;
        assert_eq!(check(bad, NOW), Err(VerifyError::ParentMismatch));
        let mut bad = header.clone();
        bad.slot = tip.post_state.slot();
        assert_eq!(check(bad, NOW), Err(VerifyError::SlotNotIncreasing));
        assert_eq!(
            check(header.clone(), start - 7),
            Err(VerifyError::SlotInFuture)
        );
        assert!(check(header.clone(), start - 6).is_ok());
        let mut bad = header.clone();
        if header.epoch_mark.is_some() {
            bad.epoch_mark = None;
            assert_eq!(check(bad, NOW), Err(VerifyError::EpochMarkMissing));
        } else {
            bad.epoch_mark = Some(mark(&tip, &tip.post_state.epoch().pending));
            assert_eq!(check(bad, NOW), Err(VerifyError::EpochMarkUnexpected));
        }
        let mut bad = header.clone();
        if let Some(tickets) = &mut bad.tickets_mark {
            tickets.pop();
            assert_eq!(check(bad, NOW), Err(VerifyError::TicketsMarkLength));
        } else {
            bad.tickets_mark = Some(vec![
                Ticket {
                    id: [0; 32],
                    attempt: 0
                };
                12
            ]);
            assert!(matches!(
                check(bad, NOW),
                Err(VerifyError::TicketsMarkUnexpected | VerifyError::BadSealSignature(_))
            ));
        }
        let mut bad = header.clone();
        bad.author_index = 6;
        assert_eq!(check(bad, NOW), Err(VerifyError::AuthorIndexOutOfRange));
        let mut bad = header.clone();
        bad.author_index = (header.author_index + 1) % 6;
        let expected = if fixture["seal_mode"] == "ticket" {
            VerifyError::BadSealSignature(VrfError::VerificationFailed)
        } else {
            VerifyError::FallbackAuthorMismatch
        };
        assert_eq!(check(bad, NOW), Err(expected));
        let mut bad = header.clone();
        bad.seal[70] ^= 1;
        assert!(matches!(
            check(bad, NOW),
            Err(VerifyError::BadSealSignature(_))
        ));
        // The seal covers the entropy source, so without re-sealing (impossible
        // for captured headers) its corruption surfaces as a seal failure.
        let mut bad = header.clone();
        bad.entropy_source[70] ^= 1;
        assert_eq!(
            check(bad, NOW),
            Err(VerifyError::BadSealSignature(VrfError::VerificationFailed))
        );

        let bytes = header.encode(&params);
        for _ in 0..40 {
            let mut mutated = bytes.clone();
            mutate_bytes(&mut rng, &mut mutated);
            if let Ok(decoded) = Header::decode(&params, &mutated) {
                fuzzed += 1;
                assert!(decoded == header || check(decoded, NOW).is_err());
            }
        }
        tip = verify_header(&params, &tip, header, NOW).unwrap();
    }
    assert!(fuzzed > 200, "{fuzzed}");
    std::println!("rejected mutations of all captured headers; {fuzzed} decodable byte mutations");
}
