// Smoldot
// Copyright (C) 2026
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use alloc::vec::Vec;
use ark_vrf::{ietf::Prover as _, reexports::ark_ff::PrimeField as _};

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

#[test]
fn blake2b_vectors() {
    assert_eq!(
        blake2b_256(b""),
        bytes("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")
    );
    assert_eq!(
        blake2b_256(b"abc"),
        bytes("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319")
    );
}

#[test]
fn ed25519_rfc8032() {
    let public = bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = bytes(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ));
    assert!(ed25519_verify(&public, b"", &signature));
    assert!(!ed25519_verify(&public, b"x", &signature));
    for i in 0..64 {
        let mut bad = signature;
        bad[i] ^= 1;
        assert!(!ed25519_verify(&public, b"", &bad));
    }
    let mut bad = public;
    bad[0] ^= 1;
    assert!(!ed25519_verify(&bad, b"", &signature));
    assert!(!ed25519_verify(&public, b"", &[255; 64]));
}

#[test]
fn ed25519_rejects_noncanonical_points() {
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&identity);
    // RFC8032's cofactored equation does not itself exclude identity keys.
    assert!(ed25519_verify(&identity, b"message", &signature));
    let mut noncanonical = [255; 32];
    noncanonical[0] = 0xee; // y = p + 1, another ZIP-215 encoding of identity.
    noncanonical[31] = 0x7f;
    let mut negative_zero = identity;
    negative_zero[31] = 0x80;
    for bad in [noncanonical, negative_zero] {
        // Establish the acceptance difference from the existing ZIP-215 verifier.
        assert!(
            ed25519_zebra::VerificationKey::try_from(bad)
                .unwrap()
                .verify(&ed25519_zebra::Signature::from(signature), b"message")
                .is_ok()
        );
        assert!(!ed25519_verify(&bad, b"message", &signature));
        let mut bad_signature = signature;
        bad_signature[..32].copy_from_slice(&bad);
        assert!(!ed25519_verify(&identity, b"message", &bad_signature));
    }
}

fn signed() -> ([u8; 32], [u8; 96]) {
    let secret = bandersnatch::Secret::from_seed(b"smoldot JAM encoding regression");
    let input = bandersnatch::Input::new(b"context").unwrap();
    let output = secret.output(input);
    let proof = secret.prove(input, output, b"aux");
    let mut public = [0; 32];
    secret
        .public()
        .serialize_compressed(&mut public[..])
        .unwrap();
    let mut signature = [0; 96];
    output.serialize_compressed(&mut signature[..32]).unwrap();
    proof.serialize_compressed(&mut signature[32..]).unwrap();
    (public, signature)
}

#[test]
fn canonical_encodings() {
    let (public, signature) = signed();
    assert!(bandersnatch_vrf_verify(&public, b"context", b"aux", &signature).is_ok());
    for range in [0..32, 32..64, 64..96] {
        let mut bad = signature;
        bad[range].fill(255);
        assert_eq!(
            bandersnatch_vrf_verify(&public, b"context", b"aux", &bad),
            Err(VrfError::InvalidEncoding)
        );
    }
    // Adding the scalar modulus leaves ark-vrf's decoded challenge unchanged.
    let modulus = bandersnatch::ScalarField::MODULUS;
    let mut noncanonical = signature;
    let mut carry = 0u128;
    for (chunk, limb) in noncanonical[32..64].chunks_exact_mut(8).zip(modulus.0) {
        let sum =
            u128::from(u64::from_le_bytes(chunk.try_into().unwrap())) + u128::from(limb) + carry;
        chunk.copy_from_slice(&sum.to_le_bytes()[..8]);
        carry = sum >> 64;
    }
    assert_eq!(carry, 0);
    let reduced = bandersnatch::IetfProof::deserialize_compressed(&noncanonical[32..]).unwrap();
    let original = bandersnatch::IetfProof::deserialize_compressed(&signature[32..]).unwrap();
    assert_eq!(reduced.c, original.c);
    assert_eq!(
        bandersnatch_vrf_verify(&public, b"context", b"aux", &noncanonical),
        Err(VrfError::InvalidEncoding)
    );
    let mut identity = [0; 32];
    identity[0] = 1;
    // y=0 is a small-order point, y=1 is the identity, all-ones is invalid.
    for bad in [[0; 32], identity, [255; 32]] {
        assert_eq!(
            bandersnatch_vrf_verify(&bad, b"context", b"aux", &signature),
            Err(VrfError::InvalidEncoding)
        );
        let mut bad_signature = signature;
        bad_signature[..32].copy_from_slice(&bad);
        assert_eq!(
            bandersnatch_vrf_verify(&public, b"context", b"aux", &bad_signature),
            Err(VrfError::InvalidEncoding)
        );
    }
}

fn tampering(public: &[u8; 32], context: &[u8], aux: &[u8], signature: &[u8; 96]) {
    for i in 0..signature.len() {
        let mut bad = *signature;
        bad[i] ^= 1;
        assert!(bandersnatch_vrf_verify(public, context, aux, &bad).is_err());
    }
    for i in 0..public.len() {
        let mut bad = *public;
        bad[i] ^= 1;
        assert!(bandersnatch_vrf_verify(&bad, context, aux, signature).is_err());
    }
    let mut bad_context = context.to_vec();
    bad_context[0] ^= 1;
    assert!(bandersnatch_vrf_verify(public, &bad_context, aux, signature).is_err());
    let mut bad_aux = aux.to_vec();
    if let Some(first) = bad_aux.first_mut() {
        *first ^= 1;
    } else {
        bad_aux.push(1);
    }
    assert!(bandersnatch_vrf_verify(public, context, &bad_aux, signature).is_err());
}

#[test]
fn vrf_tampering() {
    let (public, signature) = signed();
    tampering(&public, b"context", b"aux", &signature);
}

/// External acceptance gate: fixtures stay outside the source tree.
#[test]
#[ignore = "requires external A5 fixtures; set JAM_A5_FIXTURES or use the planning checkout"]
fn a5_real_seals_and_entropy() {
    let root = std::env::var_os("JAM_A5_FIXTURES")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/home/sebastian/work/repos/jam-light-client-planning/fixtures".into());
    let mut paths: Vec<_> = std::fs::read_dir(root.join("headers"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    assert!(paths.len() >= 3);
    let mut fallback = 0;
    let mut tickets = 0;
    for path in &paths {
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let field = |name: &str| hex::decode(fixture[name].as_str().unwrap()).unwrap();
        let public: [u8; 32] = field("author_bandersnatch").try_into().unwrap();
        let seal: [u8; 96] = field("seal_signature_hex").try_into().unwrap();
        let entropy: [u8; 96] = field("entropy_signature_hex").try_into().unwrap();
        let header = field("header_hex");
        let aux = field("seal_aux_hex");
        assert_eq!(header, [aux.as_slice(), &seal].concat());
        assert_eq!(blake2b_256(&header).as_slice(), field("header_hash"));
        let entry = &fixture["sealing_entry"];
        let mut context = if entry.get("key").is_some() {
            fallback += 1;
            assert_eq!(public, bytes::<32>(entry["key"].as_str().unwrap()));
            b"jam_fallback_seal".to_vec()
        } else {
            tickets += 1;
            b"jam_ticket_seal".to_vec()
        };
        context.extend_from_slice(&field("eta3_used_for_seal"));
        if entry.get("key").is_none() {
            context.push(u8::try_from(entry["attempt"].as_u64().unwrap()).unwrap());
        }
        assert_eq!(context, field("seal_context_hex"));
        let output = bandersnatch_vrf_verify(&public, &context, &aux, &seal)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert_eq!(output.0.as_slice(), field("seal_vrf_output"));
        if entry.get("key").is_none() {
            assert_eq!(output.0, bytes::<32>(entry["id"].as_str().unwrap()));
        }
        tampering(&public, &context, &aux, &seal);
        let entropy_context = [b"jam_entropy".as_slice(), &output.0].concat();
        assert_eq!(entropy_context, field("entropy_context_hex"));
        assert!(field("entropy_aux_hex").is_empty());
        let output = bandersnatch_vrf_verify(&public, &entropy_context, &[], &entropy).unwrap();
        assert_eq!(output.0.as_slice(), field("entropy_vrf_output"));
        tampering(&public, &entropy_context, &[], &entropy);
    }
    assert!(fallback > 0 && tickets > 0);
    std::println!(
        "verified {} real seal/entropy pairs ({fallback} fallback, {tickets} ticket), hashes and 260 mutations per pair",
        paths.len()
    );
}
