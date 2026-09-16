// Smoldot
// Copyright (C) 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! Verification-only cryptographic primitives for Gray Paper 0.8.0.
//!
//! Context construction and author/slot authorization belong to the caller. This
//! module verifies single-signer IETF VRFs, not ring VRFs or header consensus.

use ark_vrf::{
    ietf::Verifier as _,
    reexports::ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
    suites::bandersnatch,
};

/// Computes unkeyed BLAKE2b with a 256-bit output (not truncated BLAKE2b-512).
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let hash = blake2_rfc::blake2b::blake2b(32, &[], data);
    let mut output = [0; 32];
    output.copy_from_slice(hash.as_bytes());
    output
}

/// First 32 bytes of the authenticated VRF output point's suite hash (`banderout`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfOutput(pub [u8; 32]);

/// An invalid encoding, input, or IETF VRF proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrfError {
    /// Noncanonical encoding, invalid curve point/subgroup, or identity key/output.
    InvalidEncoding,
    /// The suite could not map the context to an input point.
    InvalidInput,
    /// The proof does not authenticate the supplied key, context, and auxiliary data.
    VerificationFailed,
}

impl core::fmt::Display for VrfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidEncoding => "invalid Bandersnatch encoding",
            Self::InvalidInput => "invalid Bandersnatch input",
            Self::VerificationFailed => "Bandersnatch VRF verification failed",
        })
    }
}

impl core::error::Error for VrfError {}

/// Verifies a Bandersnatch IETF VRF and returns its authenticated output hash.
///
/// `context` is the full VRF input, including its JAM domain separator; `aux`
/// is the additional signed data (unsigned header for a seal, empty for entropy).
/// The signature is the compressed output point followed by the 64-byte proof.
/// Points are checked for prime-subgroup membership; encodings must be canonical.
pub fn bandersnatch_vrf_verify(
    public: &[u8; 32],
    context: &[u8],
    aux: &[u8],
    signature: &[u8; 96],
) -> Result<VrfOutput, VrfError> {
    let public: bandersnatch::Public = decode_canonical::<_, 32>(public)?;
    let output: bandersnatch::Output = decode_canonical::<_, 32>(&signature[..32])?;
    let proof: bandersnatch::IetfProof = decode_canonical::<_, 64>(&signature[32..])?;
    if public.0.is_zero() || output.0.is_zero() {
        return Err(VrfError::InvalidEncoding);
    }
    let input = bandersnatch::Input::new(context).ok_or(VrfError::InvalidInput)?;
    public
        .verify(input, output, aux, &proof)
        .map_err(|_| VrfError::VerificationFailed)?;
    let hash = output.hash();
    let mut bytes = [0; 32];
    bytes.copy_from_slice(&hash[..32]);
    Ok(VrfOutput(bytes))
}

fn decode_canonical<T: CanonicalDeserialize + CanonicalSerialize, const N: usize>(
    bytes: &[u8],
) -> Result<T, VrfError> {
    let value = T::deserialize_compressed(bytes).map_err(|_| VrfError::InvalidEncoding)?;
    // ark-vrf 0.2.2 reduces the challenge modulo the scalar field on decode.
    // Round-tripping also rejects any noncanonical compressed-point sign bits.
    let mut encoded = [0; N];
    value
        .serialize_compressed(encoded.as_mut_slice())
        .map_err(|_| VrfError::InvalidEncoding)?;
    if encoded != bytes {
        return Err(VrfError::InvalidEncoding);
    }
    Ok(value)
}

/// Verifies Ed25519 with canonical RFC8032 point encodings and Zebra's
/// cofactored verification equation, as permitted by RFC8032 section 5.1.7.
pub fn ed25519_verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let mut r = [0; 32];
    r.copy_from_slice(&signature[..32]);
    if !ed25519_point_is_canonical(public) || !ed25519_point_is_canonical(&r) {
        return false;
    }
    let Ok(public) = ed25519_zebra::VerificationKey::try_from(*public) else {
        return false;
    };
    public
        .verify(&ed25519_zebra::Signature::from(*signature), message)
        .is_ok()
}

fn ed25519_point_is_canonical(bytes: &[u8; 32]) -> bool {
    curve25519_dalek::edwards::CompressedEdwardsY(*bytes)
        .decompress()
        .is_some_and(|point| point.compress().as_bytes() == bytes)
}

#[cfg(test)]
mod tests;
