// Smoldot
// Copyright (C) 2026  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Implementation of the `ext_host_calls_*` elliptic curve host functions
//! defined in [RFC-0163](https://github.com/polkadot-fellows/RFCs/blob/main/text/0163-ec-host-functions.md).
//!
//! The wire format and semantics must stay byte-compatible with
//! `sp-crypto-ec-utils` in `polkadot-sdk`: values are encoded with `ArkScale`
//! set to not-validated and not-compressed, which is equivalent to arkworks'
//! `serialize_with_mode(.., Compress::No)` and
//! `deserialize_with_mode(.., Compress::No, Validate::No)`.
//!
//! Each function returns the encoded result, to be written to the output
//! buffer whose length is `out_len`, or the error code to return to the
//! runtime. Nothing must be written to the output buffer in the error case.

use alloc::vec::Vec;

use ark_bls12_381::Bls12_381;
use ark_ec::{
    CurveConfig, CurveGroup as _,
    pairing::{MillerLoopOutput, Pairing},
    short_weierstrass::{Affine as SWAffine, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, Projective as TEProjective, TECurveConfig},
};
use ark_ed_on_bls12_381_bandersnatch::EdwardsConfig;
use ark_ff::Zero as _;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

/// Error codes returned through the FFI boundary, as defined by
/// `sp-crypto-ec-utils`'s `utils::Error`. `0` means success.
pub(super) const ERROR_ENCODE: u32 = 1;
pub(super) const ERROR_DECODE: u32 = 2;
pub(super) const ERROR_LENGTH_MISMATCH: u32 = 3;
pub(super) const ERROR_DEGENERATE_POINT: u32 = 4;
pub(super) const ERROR_UNKNOWN: u32 = 255;

fn decode<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, u32> {
    T::deserialize_with_mode(bytes, Compress::No, Validate::No).map_err(|_| ERROR_DECODE)
}

fn encode<T: CanonicalSerialize>(value: &T, out_len: usize) -> Result<Vec<u8>, u32> {
    if value.serialized_size(Compress::No) > out_len {
        return Err(ERROR_ENCODE);
    }
    let mut out = Vec::with_capacity(value.serialized_size(Compress::No));
    value
        .serialize_with_mode(&mut out, Compress::No)
        .map_err(|_| ERROR_ENCODE)?;
    Ok(out)
}

/// Bandersnatch is an incomplete twisted Edwards curve: non-subgroup inputs
/// can produce a projective point with `z = 0` that has no affine
/// representative. The unconditional `into_affine()` would panic on it.
fn te_into_affine_safe<T: TECurveConfig>(point: TEProjective<T>) -> Result<TEAffine<T>, u32> {
    if point.z.is_zero() {
        return Err(ERROR_DEGENERATE_POINT);
    }
    Ok(point.into_affine())
}

fn mul_sw<T: SWCurveConfig>(base: &[u8], scalar: &[u8], out_len: usize) -> Result<Vec<u8>, u32> {
    let base = decode::<SWAffine<T>>(base)?;
    let scalar = decode::<Vec<u64>>(scalar)?;
    encode(&T::mul_affine(&base, &scalar).into_affine(), out_len)
}

fn msm_sw<T: SWCurveConfig>(bases: &[u8], scalars: &[u8], out_len: usize) -> Result<Vec<u8>, u32> {
    let bases = decode::<Vec<SWAffine<T>>>(bases)?;
    let scalars = decode::<Vec<T::ScalarField>>(scalars)?;
    let result = T::msm(&bases, &scalars).map_err(|_| ERROR_LENGTH_MISMATCH)?;
    encode(&result.into_affine(), out_len)
}

/// `ext_host_calls_ed_on_bls12_381_bandersnatch_mul_version_1`.
///
/// Multiplies an encoded twisted Edwards affine point by an encoded big
/// integer (a length-prefixed sequence of little-endian `u64` limbs, allowed
/// to be non-reduced).
pub(super) fn ed_on_bls12_381_bandersnatch_mul(
    base: &[u8],
    scalar: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, u32> {
    let base = decode::<TEAffine<EdwardsConfig>>(base)?;
    let scalar = decode::<Vec<u64>>(scalar)?;
    let result = <EdwardsConfig as TECurveConfig>::mul_affine(&base, &scalar);
    encode(&te_into_affine_safe(result)?, out_len)
}

/// `ext_host_calls_ed_on_bls12_381_bandersnatch_msm_version_1`.
///
/// Multi scalar multiplication over encoded `Vec<EdwardsAffine>` and
/// `Vec<ScalarField>` of equal lengths.
pub(super) fn ed_on_bls12_381_bandersnatch_msm(
    bases: &[u8],
    scalars: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, u32> {
    let bases = decode::<Vec<TEAffine<EdwardsConfig>>>(bases)?;
    let scalars = decode::<Vec<<EdwardsConfig as CurveConfig>::ScalarField>>(scalars)?;
    let result = <EdwardsConfig as TECurveConfig>::msm(&bases, &scalars)
        .map_err(|_| ERROR_LENGTH_MISMATCH)?;
    encode(&te_into_affine_safe(result)?, out_len)
}

/// `ext_host_calls_bls12_381_mul_g1_version_1`.
pub(super) fn bls12_381_mul_g1(base: &[u8], scalar: &[u8], out_len: usize) -> Result<Vec<u8>, u32> {
    mul_sw::<ark_bls12_381::g1::Config>(base, scalar, out_len)
}

/// `ext_host_calls_bls12_381_mul_g2_version_1`.
pub(super) fn bls12_381_mul_g2(base: &[u8], scalar: &[u8], out_len: usize) -> Result<Vec<u8>, u32> {
    mul_sw::<ark_bls12_381::g2::Config>(base, scalar, out_len)
}

/// `ext_host_calls_bls12_381_msm_g1_version_1`.
pub(super) fn bls12_381_msm_g1(
    bases: &[u8],
    scalars: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, u32> {
    msm_sw::<ark_bls12_381::g1::Config>(bases, scalars, out_len)
}

/// `ext_host_calls_bls12_381_msm_g2_version_1`.
pub(super) fn bls12_381_msm_g2(
    bases: &[u8],
    scalars: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, u32> {
    msm_sw::<ark_bls12_381::g2::Config>(bases, scalars, out_len)
}

/// `ext_host_calls_bls12_381_multi_miller_loop_version_1`.
///
/// Miller loop over encoded `Vec<G1Affine>` and `Vec<G2Affine>`, producing
/// an encoded target field element.
pub(super) fn bls12_381_multi_miller_loop(
    g1: &[u8],
    g2: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, u32> {
    let g1 = decode::<Vec<ark_bls12_381::G1Affine>>(g1)?;
    let g2 = decode::<Vec<ark_bls12_381::G2Affine>>(g2)?;
    let result = Bls12_381::multi_miller_loop(g1, g2);
    encode(&result.0, out_len)
}

/// `ext_host_calls_bls12_381_final_exponentiation_version_1`.
///
/// Takes an encoded target field element and writes the encoded result back
/// to the same buffer. Returns [`ERROR_UNKNOWN`] if the final exponentiation
/// has no result (zero input).
pub(super) fn bls12_381_final_exponentiation(in_out: &[u8]) -> Result<Vec<u8>, u32> {
    let target = decode::<ark_bls12_381::Fq12>(in_out)?;
    let result = Bls12_381::final_exponentiation(MillerLoopOutput(target)).ok_or(ERROR_UNKNOWN)?;
    encode(&result.0, in_out.len())
}
