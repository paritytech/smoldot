// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;
use crate::jam::types::EpochMark;
use alloc::vec;
use ed25519_zebra::{SigningKey, VerificationKey};

fn warp_limits() -> WarpLimits {
    WarpLimits {
        max_fragments: 32,
        max_header_bytes: 256 * 1024,
        proof: Limits {
            max_bytes: 1024 * 1024,
            max_ancestry_headers: 64,
            max_ancestry_steps: 4096,
        },
    }
}

fn warp_bytes(params: &Params, fragments: &[WarpFragment]) -> Vec<u8> {
    let mut bytes = codec::encode_natural(u64::try_from(fragments.len()).unwrap());
    for fragment in fragments {
        bytes.extend(fragment.header.encode(params));
        bytes.extend(encode(&fragment.justification));
    }
    bytes
}

#[test]
fn warp_dense_indexes_skipped_epochs_and_atomic_rejections() {
    let params = params();
    let a = keys(1);
    let b = keys(11);
    let c = keys(21);
    let initial = AuthoritySet::from_checkpoint(&params, 0, public(&a), public(&a)).unwrap();
    let mut state = initial.clone();
    let mut chain = Vec::new();
    for (index, slot, signing, next) in [(0, 12, &a, &b), (1, 120, &a, &c), (2, 132, &b, &a)] {
        let mut h = header([0; 32], slot);
        mark(&mut h, next);
        let fragment = WarpFragment {
            justification: proof(&h, index, signing),
            header: h,
        };
        let before = state.clone();
        let mut bad = fragment.clone();
        bad.justification.set_id += 1;
        assert!(matches!(
            state.advance_warp(&params, &bad, limits()),
            Err(Error::WrongSetId { .. })
        ));
        let mut bad = fragment.clone();
        bad.header.epoch_mark = None;
        assert_eq!(
            state.advance_warp(&params, &bad, limits()),
            Err(Error::MissingEpochMark)
        );
        let mut bad = fragment.clone();
        bad.header.prior_state_root[0] ^= 1;
        assert_eq!(
            state.advance_warp(&params, &bad, limits()),
            Err(Error::TargetMismatch)
        );
        let mut bad = fragment.clone();
        bad.justification.precommits[0].signature[0] ^= 1;
        assert_eq!(
            state.advance_warp(&params, &bad, limits()),
            Err(Error::BadSignature)
        );
        assert_eq!(state, before);
        let (next, target) = state.advance_warp(&params, &fragment, limits()).unwrap();
        assert_eq!(target, final_(&fragment.header));
        state = next;
        chain.push(fragment);
    }
    assert_eq!(state.set_id(), 3);
    assert_eq!(state.current(), public(&c));
    assert!(matches!(
        initial.advance_warp(&params, &chain[1], limits()),
        Err(Error::WrongSetId { .. })
    ));
    let wire = warp_bytes(&params, &chain);
    let decoded = decode_warp_response(&params, &wire, &warp_limits()).unwrap();
    assert_eq!(decoded.len(), 3);
    let mut limits = warp_limits();
    limits.max_header_bytes = chain[0].header.encode(&params).len() - 1;
    assert_eq!(
        decode_warp_response(&params, &wire, &limits).unwrap_err(),
        Error::ResourceLimit
    );
    limits = warp_limits();
    limits.proof.max_bytes = encode(&chain[0].justification).len() - 1;
    assert_eq!(
        decode_warp_response(&params, &wire, &limits).unwrap_err(),
        Error::ResourceLimit
    );
    for end in 0..wire.len() {
        assert!(decode_warp_response(&params, &wire[..end], &warp_limits()).is_err());
    }
    let mut bad = wire.clone();
    bad[0] = 33;
    assert_eq!(
        decode_warp_response(&params, &bad, &warp_limits()).unwrap_err(),
        Error::Decode(DecodeError::LengthLimit)
    );
    for i in 0..wire.len() {
        let mut mutated = wire.clone();
        mutated[i] ^= 0x80;
        let _ = decode_warp_response(&params, &mutated, &warp_limits());
    }
    let mut trailing = wire;
    trailing.push(0);
    assert_eq!(
        decode_warp_response(&params, &trailing, &warp_limits()).unwrap_err(),
        Error::Decode(DecodeError::TrailingBytes)
    );
}

#[test]
fn warp_full_parameter_32_fragment_budget() {
    let mut params = params();
    params.max_validators = 1023;
    params.core_count = 341;
    params.epoch_len = 600;
    params.epoch_tail_start = 500;
    let keys: Vec<_> = (0..1023u32)
        .map(|index| {
            let mut seed = [42; 32];
            seed[..4].copy_from_slice(&index.to_le_bytes());
            SigningKey::from(seed)
        })
        .collect();
    let public = public(&keys);
    let mut state = AuthoritySet::from_checkpoint(&params, 0, public.clone(), public).unwrap();
    let mut chain = Vec::new();
    for index in 0..32 {
        let mut h = header([0; 32], (index + 1) * 600);
        mark(&mut h, &keys);
        chain.push(WarpFragment {
            justification: proof(&h, index, &keys),
            header: h,
        });
    }
    let bytes = warp_bytes(&params, &chain);
    assert!(bytes.len() <= 8 * 1024 * 1024);
    drop(chain);
    #[cfg(feature = "std")]
    let started = std::time::Instant::now();
    let decoded = decode_warp_response(&params, &bytes, &warp_limits()).unwrap();
    for fragment in decoded {
        state = state
            .advance_warp(&params, &fragment, warp_limits().proof)
            .unwrap()
            .0;
    }
    assert_eq!(state.set_id(), 32);
    #[cfg(feature = "std")]
    std::println!(
        "synthetic full-parameter warp: bytes={} bytes/fragment={} decode+verify/fragment={:?}",
        bytes.len(),
        (bytes.len() - 1) / 32,
        started.elapsed() / 32
    );
}

#[test]
fn d1_proofs_assembled_as_warp_are_not_live_ce153_captures() {
    use crate::jam::{
        chain_spec::JamChainSpec,
        state::LightState,
        verify::{verified_genesis, verify_header},
    };
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/polkajam-grandpa.json")).unwrap();
    let spec = JamChainSpec::from_json_bytes(fixture["spec"].to_string().as_bytes()).unwrap();
    let params = spec.params();
    let headers: Vec<_> = fixture["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| {
            Header::decode(
                params,
                &hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let mut chain = Vec::new();
    for value in fixture["justifications"].as_array().unwrap() {
        let justification = Justification::decode(
            params,
            &hex::decode(value.as_str().unwrap()).unwrap(),
            warp_limits().proof,
        )
        .unwrap();
        let header = headers
            .iter()
            .find(|h| h.hash(params) == justification.target().hash)
            .unwrap();
        if header.epoch_mark.is_some() {
            chain.push(WarpFragment {
                header: header.clone(),
                justification,
            });
        }
    }
    assert_eq!(chain.len(), 3);
    let bytes = warp_bytes(params, &chain);
    let decoded = decode_warp_response(params, &bytes, &warp_limits()).unwrap();
    // Prefix boundaries round-trip to exactly the source header/proof pairs.
    let mut offset = 1;
    for fragment in &decoded {
        let header = fragment.header.encode(params);
        let proof = encode(&fragment.justification);
        assert_eq!(&bytes[offset..offset + header.len()], header);
        offset += header.len();
        assert_eq!(&bytes[offset..offset + proof.len()], proof);
        offset += proof.len();
    }
    assert_eq!(offset, bytes.len());
    for index in 0..bytes.len() {
        let mut mutated = bytes.clone();
        mutated[index] ^= 0x80;
        let _ = decode_warp_response(params, &mutated, &warp_limits());
    }
    let mut authorities = AuthoritySet::from_genesis(params, spec.genesis_header()).unwrap();
    for fragment in &decoded {
        assert_eq!(
            fragment.header.hash(params),
            fragment.justification.target().hash
        );
        let (next, target) = authorities
            .advance_warp(params, fragment, warp_limits().proof)
            .unwrap();
        assert_eq!(target, *fragment.justification.target());
        authorities = next;
    }
    assert_eq!(authorities.set_id(), 3);
    let mut parent = verified_genesis(
        params,
        spec.genesis_header().clone(),
        LightState::from_anchor(params, spec.genesis_light_state()).unwrap(),
    );
    for h in headers {
        parent = verify_header(params, &parent, h, 1_900_000_000).unwrap();
    }
}

#[test]
fn captured_ce153_boundaries_authority_chain_and_mutations() {
    use crate::jam::chain_spec::JamChainSpec;
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/polkajam-warp.json")).unwrap();
    let spec = JamChainSpec::from_json_bytes(vector["spec"].to_string().as_bytes()).unwrap();
    let params = spec.params();
    let frame = hex::decode(vector["exchange"]["response_frame_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        usize::try_from(u32::from_le_bytes(frame[..4].try_into().unwrap())).unwrap(),
        frame.len() - 4
    );
    let bytes = &frame[4..];
    let fragments = decode_warp_response(params, bytes, &warp_limits()).unwrap();
    let records = vector["exchange"]["fragments"].as_array().unwrap();
    assert!(fragments.len() >= 3);
    assert_eq!(fragments.len(), records.len());
    let mut authorities = AuthoritySet::from_genesis(params, spec.genesis_header()).unwrap();
    let mut offset = codec::encode_natural(u64::try_from(fragments.len()).unwrap()).len();
    for (fragment, record) in fragments.iter().zip(records) {
        assert_eq!(
            offset,
            usize::try_from(record["start"].as_u64().unwrap()).unwrap()
        );
        let header = fragment.header.encode(params);
        assert_eq!(&bytes[offset..offset + header.len()], header);
        offset += header.len();
        assert_eq!(
            offset,
            usize::try_from(record["proof_start"].as_u64().unwrap()).unwrap()
        );
        let proof = encode(&fragment.justification);
        assert_eq!(&bytes[offset..offset + proof.len()], proof);
        offset += proof.len();
        assert_eq!(
            offset,
            usize::try_from(record["fragment_end"].as_u64().unwrap()).unwrap()
        );
        assert_eq!(
            hex::encode(fragment.header.hash(params)),
            record["hash"].as_str().unwrap()
        );
        assert_eq!(
            fragment.header.hash(params),
            fragment.justification.target().hash
        );
        let (next, target) = authorities
            .advance_warp(params, fragment, warp_limits().proof)
            .unwrap();
        assert_eq!(target, *fragment.justification.target());
        authorities = next;
    }
    assert_eq!(offset, bytes.len());
    assert_eq!(
        u64::from(authorities.set_id()),
        vector["inferred_set_id"].as_u64().unwrap()
    );
    let expected: Vec<_> = fragments
        .last()
        .unwrap()
        .header
        .epoch_mark
        .as_ref()
        .unwrap()
        .validators
        .iter()
        .map(|(_, key)| *key)
        .collect();
    assert_eq!(authorities.next(), expected);
    let expected: Vec<_> = fragments[fragments.len() - 2]
        .header
        .epoch_mark
        .as_ref()
        .unwrap()
        .validators
        .iter()
        .map(|(_, key)| *key)
        .collect();
    assert_eq!(authorities.current(), expected);
    for index in 0..bytes.len() {
        let mut mutated = bytes.to_vec();
        mutated[index] ^= 0x80;
        let _ = decode_warp_response(params, &mutated, &warp_limits());
    }
    for end in 0..bytes.len() {
        assert!(decode_warp_response(params, &bytes[..end], &warp_limits()).is_err());
    }
}

fn params() -> Params {
    let mut params = Params::from_protocol_parameters(&{
        let mut bytes = [0; 122];
        bytes[24] = 2;
        bytes
    })
    .unwrap();
    params.max_validators = 6;
    params.epoch_len = 12;
    params
}

fn limits() -> Limits {
    Limits {
        max_bytes: 65536,
        max_ancestry_headers: 32,
        max_ancestry_steps: 64,
    }
}

fn keys(start: u8) -> Vec<SigningKey> {
    (start..start + 6)
        .map(|seed| SigningKey::from([seed; 32]))
        .collect()
}

fn public(keys: &[SigningKey]) -> Vec<Ed25519Public> {
    keys.iter()
        .map(|key| VerificationKey::from(key).into())
        .collect()
}

/// Synthetic posterior state root of the block `hash`, so that a child's prior
/// state root and a vote's target root agree as on a real chain.
fn root(hash: &Hash) -> Hash {
    let mut root = *hash;
    for byte in &mut root {
        *byte ^= 0x5a;
    }
    root
}

fn header(parent: Hash, slot: u32) -> Header {
    Header {
        parent,
        slot,
        prior_state_root: root(&parent),
        extrinsic_hash: [0; 32],
        epoch_mark: None,
        tickets_mark: None,
        author_index: 0,
        entropy_source: [0; 96],
        offenders_mark: Vec::new(),
        seal: [0; 96],
    }
}

fn final_(header: &Header) -> Target {
    let hash = header.hash(&params());
    Target {
        hash,
        state_root: root(&hash),
        slot: header.slot,
    }
}

fn link(header: &Header) -> (Hash, Hash, Hash, u32) {
    (
        header.hash(&params()),
        header.parent,
        header.prior_state_root,
        header.slot,
    )
}

fn signed(target: Target, round: u64, set_id: u32, key: &SigningKey) -> Precommit {
    Precommit {
        signature: key.sign(&precommit_payload(&target, round, set_id)).into(),
        authority: VerificationKey::from(key).into(),
        target,
    }
}

fn proof(target: &Header, set_id: u32, keys: &[SigningKey]) -> Justification {
    Justification {
        round: 17,
        set_id,
        target: final_(target),
        ancestries: Vec::new(),
        precommits: keys
            .iter()
            .map(|key| signed(final_(target), 17, set_id, key))
            .collect(),
    }
}

fn encode(proof: &Justification) -> Vec<u8> {
    let mut out = proof.round.to_le_bytes().to_vec();
    out.extend(proof.set_id.to_le_bytes());
    out.extend(proof.target.hash);
    out.extend(proof.target.state_root);
    out.extend(proof.target.slot.to_le_bytes());
    out.extend(codec::encode_natural(
        u64::try_from(proof.precommits.len()).unwrap(),
    ));
    for vote in &proof.precommits {
        out.extend(vote.target.hash);
        out.extend(vote.target.state_root);
        out.extend(vote.target.slot.to_le_bytes());
        out.extend(vote.signature);
        out.extend(vote.authority);
    }
    out.extend(codec::encode_natural(
        u64::try_from(proof.ancestries.len()).unwrap(),
    ));
    for header in &proof.ancestries {
        out.extend(header.encode(&params()));
    }
    out
}

fn verify(
    proof: &Justification,
    target: &Header,
    authorities: &[Ed25519Public],
) -> Result<VerifiedFinality, Error> {
    proof.verify(
        &params(),
        7,
        authorities,
        &target.hash(&params()),
        limits(),
        |hash| (*hash == target.hash(&params())).then_some(link(target)),
    )
}

fn after_finalizing(
    state: &AuthoritySet,
    params: &Params,
    proof: &VerifiedFinality,
    header: &Header,
) -> Result<Option<AuthoritySet>, Error> {
    state.after_finalizing(
        params,
        proof,
        header.hash(params),
        header.slot,
        header
            .epoch_mark
            .as_ref()
            .map(|mark| mark.validators.as_slice()),
    )
}

#[test]
fn polkajam_payload_layout_and_signed_field_binding() {
    let target = Target {
        hash: [0xab; 32],
        state_root: [0xcd; 32],
        slot: 0x04030201,
    };
    let bytes = precommit_payload(&target, 0x0c0b0a0908070605, 0x100f0e0d);
    let mut expected = b"jam_grandpa_vote\x01".to_vec();
    expected.extend([0xab; 32]);
    expected.extend([0xcd; 32]);
    expected.extend(1u8..=16);
    assert_eq!(bytes, expected);
    assert_eq!(bytes.len(), 97);
    let keys = keys(1);
    let public = public(&keys);
    let h = header([0; 32], 1234);
    let original = proof(&h, 7, &keys[..5]);
    assert!(verify(&original, &h, &public).is_ok());
    let mut bad = original.clone();
    bad.round += 1;
    assert_eq!(verify(&bad, &h, &public).unwrap_err(), Error::BadSignature);
    let mut bad = original.clone();
    bad.set_id = 8;
    assert_eq!(
        bad.verify(&params(), 8, &public, &h.hash(&params()), limits(), |_| {
            Some(link(&h))
        })
        .unwrap_err(),
        Error::BadSignature
    );
    for field in [0, 1, 2] {
        let mut bad = original.clone();
        match field {
            0 => bad.precommits[0].target.hash[0] ^= 1,
            1 => bad.precommits[0].target.state_root[0] ^= 1,
            _ => bad.precommits[0].target.slot += 1,
        }
        assert_eq!(verify(&bad, &h, &public).unwrap_err(), Error::BadSignature);
    }
}

#[test]
fn distinct_set_target_signature_and_quorum_errors() {
    let keys = keys(1);
    let authorities = public(&keys);
    let h = header([0; 32], 123);
    let good = proof(&h, 7, &keys[..5]);
    assert!(verify(&good, &h, &authorities).is_ok());
    let mut bad = good.clone();
    bad.set_id = 8;
    assert_eq!(
        verify(&bad, &h, &authorities).unwrap_err(),
        Error::WrongSetId {
            expected: 7,
            received: 8
        }
    );
    let mut bad = good.clone();
    bad.target.hash[0] ^= 1;
    assert_eq!(
        verify(&bad, &h, &authorities).unwrap_err(),
        Error::TargetMismatch
    );
    assert_eq!(
        good.verify(
            &params(),
            7,
            &authorities,
            &good.target.hash,
            limits(),
            |_| None
        )
        .unwrap_err(),
        Error::UnknownTarget
    );
    let mut bad = good.clone();
    bad.target.slot += 1;
    assert_eq!(
        verify(&bad, &h, &authorities).unwrap_err(),
        Error::TargetSlotMismatch
    );
    let mut bad = good.clone();
    bad.precommits[0].signature[0] ^= 1;
    assert_eq!(
        verify(&bad, &h, &authorities).unwrap_err(),
        Error::BadSignature
    );
    let mut bad = good.clone();
    bad.precommits[0] = signed(final_(&h), 17, 7, &SigningKey::from([99; 32]));
    assert_eq!(
        verify(&bad, &h, &authorities).unwrap_err(),
        Error::UnknownAuthority
    );
    let mut bad = good.clone();
    bad.precommits.pop();
    assert_eq!(
        verify(&bad, &h, &authorities).unwrap_err(),
        Error::InsufficientWeight
    );
    bad.precommits.clear();
    assert_eq!(
        verify(&bad, &h, &authorities).unwrap_err(),
        Error::InsufficientWeight
    );
    assert_eq!(
        verify(&good, &h, &[]).unwrap_err(),
        Error::InvalidAuthorities
    );
}

#[test]
fn duplicates_never_multiply_vote_weight() {
    let keys = keys(1);
    let authorities = public(&keys);
    let h = header([0; 32], 123);
    let mut p = proof(&h, 7, &keys[..1]);
    p.precommits = vec![p.precommits[0].clone(); 4];
    assert_eq!(
        verify(&p, &h, &authorities).unwrap_err(),
        Error::InsufficientWeight
    );
    p.precommits.push(signed(final_(&h), 17, 7, &keys[1]));
    p.precommits.push(signed(final_(&h), 17, 7, &keys[2]));
    assert_eq!(
        verify(&p, &h, &authorities).unwrap_err(),
        Error::InsufficientWeight
    );
    p.precommits.push(signed(final_(&h), 17, 7, &keys[3]));
    assert_eq!(
        verify(&p, &h, &authorities).unwrap_err(),
        Error::InsufficientWeight
    );
    p.precommits.push(signed(final_(&h), 17, 7, &keys[4]));
    assert!(verify(&p, &h, &authorities).is_ok());
    let weighted = vec![
        authorities[0],
        authorities[0],
        authorities[0],
        authorities[1],
        authorities[1],
        authorities[2],
    ];
    assert!(verify(&proof(&h, 7, &keys[..2]), &h, &weighted).is_ok());
    assert_eq!(
        verify(&proof(&h, 7, &keys[..1]), &h, &weighted).unwrap_err(),
        Error::InsufficientWeight
    );
}

#[test]
fn null_and_other_small_order_keys_cannot_vote() {
    let keys = keys(1);
    let h = header([0; 32], 123);
    for weak in [[0; 32], {
        let mut k = [0; 32];
        k[0] = 1;
        k
    }] {
        let mut authorities = public(&keys);
        authorities[0] = weak;
        let mut p = proof(&h, 7, &keys[..5]);
        p.precommits[0].authority = weak;
        p.precommits[0].signature = [0; 64];
        p.precommits[0].signature[0] = 1;
        assert_eq!(
            verify(&p, &h, &authorities).unwrap_err(),
            Error::BadSignature
        );
        // Five remaining real keys suffice; the placeholder isn't removed from n.
        assert!(verify(&proof(&h, 7, &keys[1..]), &h, &authorities).is_ok());
        assert_eq!(
            verify(&proof(&h, 7, &keys[1..3]), &h, &authorities).unwrap_err(),
            Error::InsufficientWeight
        );
    }
}

#[test]
fn ancestry_routes_through_witnesses_and_retained_tree() {
    let keys = keys(1);
    let authorities = public(&keys);
    let h = header([0; 32], 12);
    let child = header(h.hash(&params()), 16);
    let grandchild = header(child.hash(&params()), 20);
    let sibling = header(h.hash(&params()), 17);
    let mut p = proof(&h, 7, &keys[..5]);
    p.precommits[1] = signed(final_(&grandchild), 17, 7, &keys[1]);
    p.precommits[2] = signed(final_(&sibling), 17, 7, &keys[2]);
    // A second (different) vote by one voter still contributes weight once.
    p.precommits.push(signed(final_(&child), 17, 7, &keys[1]));
    p.ancestries = vec![grandchild.clone(), sibling.clone(), child.clone()];
    let decoded = Justification::decode(&params(), &encode(&p), limits()).unwrap();
    assert!(verify(&decoded, &h, &authorities).is_ok());
    p.ancestries.clear();
    let headers = [&h, &child, &grandchild, &sibling];
    assert!(
        p.verify(
            &params(),
            7,
            &authorities,
            &h.hash(&params()),
            limits(),
            |hash| {
                headers
                    .iter()
                    .copied()
                    .find(|header| header.hash(&params()) == *hash)
                    .map(link)
            }
        )
        .is_ok()
    );
    assert_eq!(
        verify(&p, &h, &authorities).unwrap_err(),
        Error::InvalidAncestry
    );
}

#[test]
fn ancestry_rejects_wrong_slots_forks_unused_and_duplicate_headers() {
    let keys = keys(1);
    let authorities = public(&keys);
    let h = header([0; 32], 12);
    let child = header(h.hash(&params()), 16);
    let mut p = proof(&h, 7, &keys[..5]);
    p.precommits[1] = signed(final_(&child), 17, 7, &keys[1]);
    p.ancestries = vec![child.clone()];
    assert!(verify(&p, &h, &authorities).is_ok());
    let mut bad = p.clone();
    bad.ancestries.push(child.clone());
    assert_eq!(
        verify(&bad, &h, &authorities).unwrap_err(),
        Error::DuplicateAncestry
    );
    let mut bad = p.clone();
    bad.ancestries.push(header([99; 32], 18));
    assert_eq!(
        verify(&bad, &h, &authorities).unwrap_err(),
        Error::UnusedAncestry
    );
    let mut bad = p.clone();
    bad.ancestries.push(h.clone());
    assert_eq!(
        verify(&bad, &h, &authorities).unwrap_err(),
        Error::UnusedAncestry
    );
    for slot in [0, 12, 15, 17, u32::MAX] {
        let mut bad = p.clone();
        bad.precommits[1] = signed(
            Target {
                slot,
                ..final_(&child)
            },
            17,
            7,
            &keys[1],
        );
        assert_eq!(
            verify(&bad, &h, &authorities).unwrap_err(),
            Error::InvalidAncestry
        );
    }
    let fork = header([88; 32], 16);
    let mut bad = p.clone();
    bad.precommits[1] = signed(final_(&fork), 17, 7, &keys[1]);
    bad.ancestries = vec![fork];
    assert_eq!(
        verify(&bad, &h, &authorities).unwrap_err(),
        Error::InvalidAncestry
    );
    let low = header(h.hash(&params()), 11);
    bad.precommits[1] = signed(final_(&low), 17, 7, &keys[1]);
    bad.ancestries = vec![low];
    assert_eq!(
        verify(&bad, &h, &authorities).unwrap_err(),
        Error::InvalidAncestry
    );
    let mut bound = limits();
    bound.max_ancestry_steps = 0;
    assert_eq!(
        p.verify(
            &params(),
            7,
            &authorities,
            &h.hash(&params()),
            bound,
            |_| Some(link(&h))
        )
        .unwrap_err(),
        Error::ResourceLimit
    );
}

#[test]
fn same_hash_with_a_different_state_root_is_a_different_target() {
    // PolkaJam `AncestryChain::ancestry`: "Same block but a different posterior
    // state root is a different target". Every signature below is valid.
    let keys = keys(1);
    let authorities = public(&keys);
    let h = header([0; 32], 12);
    let other = Target {
        state_root: [0xee; 32],
        ..final_(&h)
    };
    assert_ne!(other, final_(&h));
    // Votes for (h, root) under a commit for (h, other root).
    let mut p = proof(&h, 7, &keys[..5]);
    p.target = other;
    assert_eq!(
        verify(&p, &h, &authorities).unwrap_err(),
        Error::InvalidAncestry
    );
    // One vote for (h, other root) under a commit for (h, root).
    let mut p = proof(&h, 7, &keys[..5]);
    p.precommits[0] = signed(other, 17, 7, &keys[0]);
    assert_eq!(
        verify(&p, &h, &authorities).unwrap_err(),
        Error::InvalidAncestry
    );
    // A vote for a child whose prior state root names another posterior root
    // of h: the walk reaches h's hash under the wrong root.
    let mut child = header(h.hash(&params()), 16);
    child.prior_state_root = [0xee; 32];
    let mut p = proof(&h, 7, &keys[..5]);
    p.precommits[1] = signed(final_(&child), 17, 7, &keys[1]);
    p.ancestries = vec![child.clone()];
    assert_eq!(
        verify(&p, &h, &authorities).unwrap_err(),
        Error::InvalidAncestry
    );
    p.ancestries.clear();
    assert_eq!(
        p.verify(
            &params(),
            7,
            &authorities,
            &h.hash(&params()),
            limits(),
            |hash| [&h, &child]
                .into_iter()
                .find(|header| header.hash(&params()) == *hash)
                .map(link)
        )
        .unwrap_err(),
        Error::InvalidAncestry
    );
    // The same proofs with matching roots verify, and the signed root is returned.
    let mut p = proof(&h, 7, &keys[..5]);
    let child = header(h.hash(&params()), 16);
    p.precommits[1] = signed(final_(&child), 17, 7, &keys[1]);
    p.ancestries = vec![child];
    assert_eq!(*verify(&p, &h, &authorities).unwrap().target(), final_(&h));
    // A warp fragment whose commit names another root of its own header.
    let mut marked = header([0; 32], 12);
    mark(&mut marked, &keys);
    let mut fragment = WarpFragment {
        justification: proof(&marked, 0, &keys[..5]),
        header: marked,
    };
    fragment.justification.target.state_root = [0xee; 32];
    let state = AuthoritySet::from_checkpoint(&params(), 0, public(&keys), public(&keys)).unwrap();
    assert_eq!(
        state.advance_warp(&params(), &fragment, limits()),
        Err(Error::InvalidAncestry)
    );
}

#[test]
fn repeated_target_must_keep_its_slot_even_after_ancestry_was_cached() {
    let keys = keys(1);
    let authorities = public(&keys);
    let h = header([0; 32], 12);
    let child = header(h.hash(&params()), 16);
    let mut p = proof(&h, 7, &keys[..5]);
    p.ancestries = vec![child.clone()];
    p.precommits[0] = signed(final_(&child), 17, 7, &keys[0]);
    p.precommits[1] = signed(
        Target {
            slot: 17,
            ..final_(&child)
        },
        17,
        7,
        &keys[1],
    );
    assert_eq!(
        verify(&p, &h, &authorities).unwrap_err(),
        Error::InvalidAncestry
    );
}

#[test]
fn decoder_checks_truncation_canonical_counts_and_budgets() {
    let keys = keys(1);
    let h = header([0; 32], 12);
    let child = header(h.hash(&params()), 16);
    let mut p = proof(&h, 7, &keys[..5]);
    p.precommits[0] = signed(final_(&child), 17, 7, &keys[0]);
    p.ancestries = vec![child];
    let bytes = encode(&p);
    for length in 0..bytes.len() {
        assert!(Justification::decode(&params(), &bytes[..length], limits()).is_err());
    }
    assert!(Justification::decode(&params(), &bytes, limits()).is_ok());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        Justification::decode(&params(), &trailing, limits()),
        Err(Error::Decode(DecodeError::TrailingBytes))
    ));
    let mut count = bytes.clone();
    // Round (8) ++ set id (4) ++ commit target (68) precede the precommit count.
    count[80] = 13;
    assert!(matches!(
        Justification::decode(&params(), &count, limits()),
        Err(Error::Decode(DecodeError::LengthLimit))
    ));
    let mut noncanonical = bytes.clone();
    noncanonical.splice(80..81, [0x80, 5]);
    assert!(matches!(
        Justification::decode(&params(), &noncanonical, limits()),
        Err(Error::Decode(DecodeError::NonCanonicalNatural))
    ));
    let mut bound = limits();
    bound.max_bytes = bytes.len() - 1;
    assert!(matches!(
        Justification::decode(&params(), &bytes, bound),
        Err(Error::ResourceLimit)
    ));
    bound = limits();
    bound.max_ancestry_headers = 0;
    assert!(matches!(
        Justification::decode(&params(), &bytes, bound),
        Err(Error::Decode(DecodeError::LengthLimit))
    ));
}

fn mark(header: &mut Header, keys: &[SigningKey]) {
    header.epoch_mark = Some(EpochMark {
        entropy: [0; 32],
        tickets_entropy: [0; 32],
        validators: public(keys).into_iter().map(|key| ([0; 32], key)).collect(),
    });
}

#[test]
fn authority_pipeline_changes_only_on_verified_finalization() {
    let a = keys(1);
    let b = keys(5);
    let c = keys(9);
    let d = keys(13);
    let original = AuthoritySet::from_checkpoint(&params(), 7, public(&a), public(&b)).unwrap();
    let mut h = header([0; 32], 120);
    mark(&mut h, &c);
    // An imported but unfinalized competing epoch mark has no effect.
    let mut fork = header([0; 32], 121);
    mark(&mut fork, &d);
    let verified = verify(&proof(&h, 7, &a[..5]), &h, original.current()).unwrap();
    assert_eq!(
        after_finalizing(&original, &params(), &verified, &fork),
        Err(Error::TargetMismatch)
    );
    let next = after_finalizing(&original, &params(), &verified, &h)
        .unwrap()
        .unwrap();
    assert_eq!(original.set_id(), 7);
    assert_eq!(original.current(), public(&a));
    assert_eq!(original.next(), public(&b));
    assert_eq!(next.set_id(), 8);
    assert_eq!(next.current(), public(&b));
    assert_eq!(next.next(), public(&c));
    let mut h2 = header(h.hash(&params()), 144);
    mark(&mut h2, &d);
    let p2 = proof(&h2, 8, &b[..5]);
    let v2 = p2
        .verify(
            &params(),
            8,
            next.current(),
            &h2.hash(&params()),
            limits(),
            |_| Some(link(&h2)),
        )
        .unwrap();
    let next2 = after_finalizing(&next, &params(), &v2, &h2)
        .unwrap()
        .unwrap();
    assert_eq!(next2.set_id(), 9);
    assert_eq!(next2.current(), public(&c));
    assert_eq!(next2.next(), public(&d));
    let wrong_snapshot =
        AuthoritySet::from_checkpoint(&params(), 7, public(&b), public(&c)).unwrap();
    assert_eq!(
        after_finalizing(&wrong_snapshot, &params(), &verified, &h),
        Err(Error::InvalidAuthorities)
    );
    assert!(matches!(
        after_finalizing(&next, &params(), &verified, &h),
        Err(Error::WrongSetId { .. })
    ));
}

#[test]
fn genesis_and_checkpoint_positions_need_no_round_state() {
    let a = keys(1);
    let b = keys(5);
    let c = keys(9);
    let mut genesis = header([0; 32], 0);
    assert_eq!(
        AuthoritySet::from_genesis(&params(), &genesis),
        Err(Error::MissingGenesisEpochMark)
    );
    mark(&mut genesis, &a);
    let from_genesis = AuthoritySet::from_genesis(&params(), &genesis).unwrap();
    assert_eq!(from_genesis.set_id(), 0);
    assert_eq!(from_genesis.current(), public(&a));
    assert_eq!(from_genesis.next(), public(&a));
    for slot in [120, 125, 12_000_000] {
        let snapshot = AuthoritySet::from_checkpoint(&params(), 7, public(&a), public(&b)).unwrap();
        let ordinary = header([0; 32], slot);
        let verified =
            verify(&proof(&ordinary, 7, &a[..5]), &ordinary, snapshot.current()).unwrap();
        assert_eq!(
            after_finalizing(&snapshot, &params(), &verified, &ordinary),
            Ok(None)
        );
        let mut transition = header(ordinary.hash(&params()), slot + 12);
        mark(&mut transition, &c);
        let verified = verify(
            &proof(&transition, 7, &a[..5]),
            &transition,
            snapshot.current(),
        )
        .unwrap();
        assert_eq!(
            after_finalizing(&snapshot, &params(), &verified, &transition)
                .unwrap()
                .unwrap()
                .set_id(),
            8
        );
    }
}

#[test]
fn variable_authority_sets_rotate_and_use_the_actual_quorum() {
    let mut params = params();
    params.core_count = 4;
    params.max_validators = 12;
    let all = [keys(1), keys(10)].concat();
    for (current_count, next_count) in [(6, 9), (9, 6)] {
        let snapshot = AuthoritySet::from_checkpoint(
            &params,
            7,
            public(&all[..current_count]),
            public(&all[..next_count]),
        )
        .unwrap();
        let mut h = header([0; 32], 12);
        mark(&mut h, &all);
        let quorum = current_count * 2 / 3 + 1;
        let valid = proof(&h, 7, &all[..quorum]);
        let verified = valid
            .verify(
                &params,
                7,
                snapshot.current(),
                &h.hash(&params),
                limits(),
                |_| Some(link(&h)),
            )
            .unwrap();
        let rotated = after_finalizing(&snapshot, &params, &verified, &h)
            .unwrap()
            .unwrap();
        assert_eq!(rotated.current(), public(&all[..next_count]));
        assert_eq!(rotated.next(), public(&all));
        let insufficient = proof(&h, 7, &all[..quorum - 1]);
        assert_eq!(
            insufficient
                .verify(
                    &params,
                    7,
                    snapshot.current(),
                    &h.hash(&params),
                    limits(),
                    |_| Some(link(&h))
                )
                .unwrap_err(),
            Error::InsufficientWeight
        );
    }
    for count in [0, 3, 5, 7, 13, 15] {
        for (current, next) in [
            (vec![[1; 32]; count], public(&all[..6])),
            (public(&all[..6]), vec![[1; 32]; count]),
        ] {
            assert_eq!(
                AuthoritySet::from_checkpoint(&params, 7, current, next),
                Err(Error::InvalidAuthorities)
            );
        }
    }
}

#[test]
fn authority_shape_and_overflow_fail_without_mutation() {
    let a = keys(1);
    for (current, next) in [
        (vec![], public(&a)),
        (public(&a), vec![]),
        (public(&a[..5]), public(&a)),
    ] {
        assert_eq!(
            AuthoritySet::from_checkpoint(&params(), 0, current, next),
            Err(Error::InvalidAuthorities)
        );
    }
    let snapshot =
        AuthoritySet::from_checkpoint(&params(), u32::MAX, public(&a), public(&a)).unwrap();
    let mut h = header([0; 32], 12);
    mark(&mut h, &a);
    let p = proof(&h, u32::MAX, &a[..5]);
    let verified = p
        .verify(
            &params(),
            u32::MAX,
            snapshot.current(),
            &h.hash(&params()),
            limits(),
            |_| Some(link(&h)),
        )
        .unwrap();
    assert_eq!(
        after_finalizing(&snapshot, &params(), &verified, &h),
        Err(Error::SetIdOverflow)
    );
    assert_eq!(snapshot.set_id(), u32::MAX);
}

#[test]
fn arbitrary_and_mutated_bytes_are_total() {
    use rand_chacha::{
        ChaCha20Rng,
        rand_core::{RngCore as _, SeedableRng as _},
    };
    let keys = keys(1);
    let authorities = public(&keys);
    let h = header([0; 32], 12);
    let bytes = encode(&proof(&h, 7, &keys[..5]));
    let mut rng = ChaCha20Rng::from_seed([42; 32]);
    for i in 0..1000 {
        let mut input = if i % 2 == 0 {
            bytes.clone()
        } else {
            vec![0; i % 700]
        };
        if i % 2 == 0 {
            let at = usize::try_from(rng.next_u32()).unwrap() % input.len();
            input[at] ^= 1;
        } else {
            rng.fill_bytes(&mut input);
        }
        if let Ok(decoded) = Justification::decode(&params(), &input, limits()) {
            let _ = verify(&decoded, &h, &authorities);
        }
    }
}

#[test]
fn captured_polkajam_proofs_advance_authenticated_headers_and_reject_mutations() {
    use crate::jam::{
        chain_spec::JamChainSpec,
        state::LightState,
        tree::{self, HeaderTree},
        verify::verified_genesis,
    };
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/polkajam-grandpa.json")).unwrap();
    let spec = JamChainSpec::from_json_bytes(fixture["spec"].to_string().as_bytes()).unwrap();
    let params = spec.params();
    let mut authorities = AuthoritySet::from_genesis(params, spec.genesis_header()).unwrap();
    let root = verified_genesis(
        params,
        spec.genesis_header().clone(),
        LightState::from_anchor(params, spec.genesis_light_state()).unwrap(),
    );
    let mut tree = HeaderTree::new(
        params.clone(),
        root,
        tree::Config {
            max_blocks: core::num::NonZeroUsize::new(64).unwrap(),
            max_bytes: usize::MAX,
            max_epoch_records: core::num::NonZeroUsize::new(8).unwrap(),
        },
    )
    .unwrap();
    for hex in fixture["headers"].as_array().unwrap() {
        let header = Header::decode(
            params,
            &hex::decode(hex.as_str().unwrap().trim_start_matches("0x")).unwrap(),
        )
        .unwrap();
        tree.insert(header.parent, header, 1_900_000_000).unwrap();
    }
    let limits = Limits {
        max_bytes: 1024 * 1024,
        max_ancestry_headers: 64,
        max_ancestry_steps: 1024,
    };
    for (index, hex) in fixture["justifications"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let proof =
            Justification::decode(params, &hex::decode(hex.as_str().unwrap()).unwrap(), limits)
                .unwrap();
        let verify = |proof: &Justification| {
            proof.verify(
                params,
                authorities.set_id(),
                authorities.current(),
                &proof.target.hash,
                limits,
                |hash| tree.get(hash).and_then(ancestry_link),
            )
        };
        if index == 0 {
            let mut bad = proof.clone();
            bad.set_id += 1;
            assert!(matches!(verify(&bad), Err(Error::WrongSetId { .. })));
            let mut bad = proof.clone();
            bad.precommits.truncate(1);
            assert_eq!(verify(&bad).unwrap_err(), Error::InsufficientWeight);
            let mut bad = proof.clone();
            bad.precommits[0].signature[0] ^= 1;
            assert_eq!(verify(&bad).unwrap_err(), Error::BadSignature);
            assert_eq!(
                proof
                    .verify(
                        params,
                        authorities.set_id(),
                        authorities.current(),
                        &proof.target.hash,
                        limits,
                        |_| None
                    )
                    .unwrap_err(),
                Error::UnknownTarget
            );
        }
        let verified = verify(&proof).unwrap();
        let before = tree.len();
        let result = tree.finalize(&verified, &mut authorities).unwrap();
        assert!(!result.finalized.is_empty());
        assert!(tree.len() < before);
        if [0, 2, 5, 17].contains(&index) {
            // Resume from authenticated non-genesis anchors: after a skipped
            // epoch jump, mid-epoch and immediately after authority changes.
            use crate::jam::types::{SafroleState, ValidatorKey};
            let root = tree.finalized().clone();
            let state = &root.post_state;
            let keys = |pairs: &[(super::super::types::BandersnatchPublic, Ed25519Public)]| {
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
            let mut accumulator = state.pending_tickets().unwrap_or_default().to_vec();
            accumulator.sort_by_key(|ticket| ticket.id);
            let safrole = SafroleState {
                pending_validators: keys(&state.epoch().pending),
                epoch_root: [0; 144],
                sealing: state.epoch().sealing.clone(),
                ticket_accumulator: accumulator,
            };
            let mut raw = fixture["spec"].clone();
            raw["checkpoint"] = serde_json::json!({
                "header": hex::encode(&root.encoded),
                "state": {"safrole":hex::encode(safrole.encode(params)),
                    "entropy":hex::encode(codec::encode_entropy(&state.entropy())),
                    "active_validators":hex::encode(codec::encode_active_validators(&keys(&state.epoch().active))),
                    "slot":hex::encode(state.slot().to_le_bytes())},
                "finality":{"set_id":authorities.set_id(),
                    "current":authorities.current().iter().map(hex::encode).collect::<Vec<_>>(),
                    "next":authorities.next().iter().map(hex::encode).collect::<Vec<_>>()}
            });
            let resumed = JamChainSpec::from_json_bytes(raw.to_string().as_bytes()).unwrap();
            let checkpoint = resumed.checkpoint().unwrap();
            assert_eq!(checkpoint.finality, authorities);
            let restored = LightState::from_anchor(params, &checkpoint.state).unwrap();
            assert_eq!(&restored, state);
            let descendants: Vec<_> = tree
                .ancestry_order()
                .skip(1)
                .map(|b| Header::decode(params, &b.encoded).unwrap())
                .collect();
            tree = HeaderTree::new(
                params.clone(),
                verified_genesis(params, checkpoint.header.clone(), restored),
                tree::Config {
                    max_blocks: core::num::NonZeroUsize::new(64).unwrap(),
                    max_bytes: usize::MAX,
                    max_epoch_records: core::num::NonZeroUsize::new(8).unwrap(),
                },
            )
            .unwrap();
            authorities = checkpoint.finality.clone();
            for header in descendants {
                tree.insert(header.parent, header, 1_900_000_000).unwrap();
            }
        }
    }
    assert_eq!(authorities.set_id(), 3);
    assert!(tree.len() <= 2);
}
