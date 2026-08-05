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

use alloc::vec::Vec;

use ark_ec::{CurveGroup as _, twisted_edwards::TECurveConfig as _};
use ark_ed_on_bls12_381_bandersnatch::EdwardsConfig;
use ark_ff::Zero as _;
use ark_serialize::{
    CanonicalDeserialize as _, CanonicalSerialize as _, Compress, SerializationError, Validate,
};

/// Error codes returned through the FFI boundary, as defined by
/// `sp-crypto-ec-utils`'s `utils::Error`. `0` means success.
pub(super) const ERROR_ENCODE: u32 = 1;
pub(super) const ERROR_DECODE: u32 = 2;
pub(super) const ERROR_DEGENERATE_POINT: u32 = 4;

/// `ext_host_calls_ed_on_bls12_381_bandersnatch_mul_version_1`.
///
/// Multiplies an encoded twisted Edwards affine point by an encoded big
/// integer (a length-prefixed sequence of little-endian `u64` limbs, allowed
/// to be non-reduced).
///
/// Returns the encoded affine result, to be written to the output buffer of
/// size `out_len`, or the error code to return to the runtime. Nothing must
/// be written to the output buffer in the error case.
pub(super) fn ed_on_bls12_381_bandersnatch_mul(
    base: &[u8],
    scalar: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, u32> {
    let base = ark_ec::twisted_edwards::Affine::<EdwardsConfig>::deserialize_with_mode(
        base,
        Compress::No,
        Validate::No,
    )
    .map_err(|_| ERROR_DECODE)?;
    let scalar = Vec::<u64>::deserialize_with_mode(scalar, Compress::No, Validate::No)
        .map_err(|_| ERROR_DECODE)?;

    let result = EdwardsConfig::mul_affine(&base, &scalar);

    // Bandersnatch is an incomplete twisted Edwards curve: non-subgroup
    // inputs can produce a projective point with `z = 0` that has no affine
    // representative. The unconditional `into_affine()` would panic on it.
    if result.z.is_zero() {
        return Err(ERROR_DEGENERATE_POINT);
    }

    let affine = result.into_affine();
    if affine.serialized_size(Compress::No) > out_len {
        return Err(ERROR_ENCODE);
    }
    let mut out = Vec::with_capacity(affine.serialized_size(Compress::No));
    affine
        .serialize_with_mode(&mut out, Compress::No)
        .map_err(|_: SerializationError| ERROR_ENCODE)?;
    Ok(out)
}
