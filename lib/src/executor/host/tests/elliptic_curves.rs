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

use super::super::{
    Config, HeapPages, HostVm, HostVmPrototype, StorageProofSizeBehavior, elliptic_curves,
    vm::ExecHint,
};
use super::with_core_version_custom_sections;

// The test vectors below were generated with a standalone native program that
// replicates `utils::mul_te::<EdwardsConfig>` of `sp-crypto-ec-utils` from
// polkadot-sdk, using the `ark-scale` crate (usage: not-validated,
// not-compressed) for the encoding, `ark-ed-on-bls12-381-bandersnatch 0.5.0`
// for the math. They were NOT produced by the implementation under test.

/// Prime-order generator point, encoded.
const VEC1_BASE: &str = "18ae52a26618e7e1658499ad22c0792bf342be7b77113774c5340b2ccc32c129664197ccb667315e6064e4ee81ad8c3586d5dcba508b7d150f3e12da9e666c2a";
/// The 4-limb scalar 0x0102030405060708_0f0e0d0c0b0a0908_fedcba9876543210_123456789abcdef0, encoded.
const VEC1_SCALAR: &str =
    "0400000000000000f0debc9a785634121032547698badcfe08090a0b0c0d0e0f0807060504030201";
const VEC1_OUT: &str = "3135c94c10e168a08136dd6bf7090566a58f482e7d8dc627b5630b14828eaa4dda0af0d2d0be41293262c83e4189d4d297fc439df1f05a0b7e5c84dc55e2306c";

/// On-curve point with `y = 2` that is NOT in the prime-order subgroup, encoded.
const VEC2_BASE: &str = "5a1312770e4fb8da87cba77deca5a68f40a43669d174e7c49f8a95084a0a19270200000000000000000000000000000000000000000000000000000000000000";
/// The 1-limb scalar 7, encoded.
const VEC2_SCALAR: &str = "01000000000000000700000000000000";
const VEC2_OUT: &str = "d500fbbec1be3b9f86e58a52761e6f880e1ee7e6514ce22f1016d027d0ee9c2407169fcb265420615ccc18f7ca02aad28f30c6a5b876da03214bbcbd7e1f1d60";

/// `Fr::MODULUS` as 4 limbs, encoded. Multiplying the `y = 2` non-subgroup
/// point by it drives the projective result to `z = 0` (same construction as
/// the degenerate-point test in `sp-crypto-ec-utils`).
const VEC3_SCALAR: &str =
    "0400000000000000e1e77628b506fd747104197400878fff007668020276ce0c525f67cad469fb1c";

#[test]
fn mul_matches_upstream_vector() {
    let out = elliptic_curves::ed_on_bls12_381_bandersnatch_mul(
        &hex::decode(VEC1_BASE).unwrap(),
        &hex::decode(VEC1_SCALAR).unwrap(),
        64,
    )
    .unwrap();
    assert_eq!(out, hex::decode(VEC1_OUT).unwrap());
}

#[test]
fn mul_accepts_non_subgroup_base() {
    let out = elliptic_curves::ed_on_bls12_381_bandersnatch_mul(
        &hex::decode(VEC2_BASE).unwrap(),
        &hex::decode(VEC2_SCALAR).unwrap(),
        64,
    )
    .unwrap();
    assert_eq!(out, hex::decode(VEC2_OUT).unwrap());
}

#[test]
fn mul_degenerate_point_returns_error() {
    let result = elliptic_curves::ed_on_bls12_381_bandersnatch_mul(
        &hex::decode(VEC2_BASE).unwrap(),
        &hex::decode(VEC3_SCALAR).unwrap(),
        64,
    );
    assert_eq!(result, Err(elliptic_curves::ERROR_DEGENERATE_POINT));
}

#[test]
fn mul_output_buffer_too_small() {
    let result = elliptic_curves::ed_on_bls12_381_bandersnatch_mul(
        &hex::decode(VEC1_BASE).unwrap(),
        &hex::decode(VEC1_SCALAR).unwrap(),
        63,
    );
    assert_eq!(result, Err(elliptic_curves::ERROR_ENCODE));
}

#[test]
fn mul_output_buffer_larger_than_needed() {
    let out = elliptic_curves::ed_on_bls12_381_bandersnatch_mul(
        &hex::decode(VEC1_BASE).unwrap(),
        &hex::decode(VEC1_SCALAR).unwrap(),
        128,
    )
    .unwrap();
    assert_eq!(out, hex::decode(VEC1_OUT).unwrap());
}

#[test]
fn mul_malformed_inputs() {
    let base = hex::decode(VEC1_BASE).unwrap();
    let scalar = hex::decode(VEC1_SCALAR).unwrap();
    assert_eq!(
        elliptic_curves::ed_on_bls12_381_bandersnatch_mul(&base[..63], &scalar, 64),
        Err(elliptic_curves::ERROR_DECODE)
    );
    assert_eq!(
        elliptic_curves::ed_on_bls12_381_bandersnatch_mul(&base, &scalar[..39], 64),
        Err(elliptic_curves::ERROR_DECODE)
    );
}

const BASE_PTR: u64 = 1048576;
const SCALAR_PTR: u64 = 1048704;
const OUT_PTR: u64 = 1048832;
const OUT_LEN: u64 = 64;

fn wat_escape(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:02x}")).collect()
}

/// Builds a module whose `test` function calls the mul host function with the
/// given inputs, traps unless the returned code equals `expected_code`, and
/// returns the output buffer as the runtime call result.
fn module_calling_mul(base: &[u8], scalar: &[u8], expected_code: u32) -> Vec<u8> {
    let module = format!(
        r#"
        (module
            (import "env" "ext_host_calls_ed_on_bls12_381_bandersnatch_mul_version_1"
                (func $mul (param i64 i64 i64) (result i32)))
            (memory (export "memory") 17)
            (global (export "__heap_base") i32 (i32.const 1049600))
            (data (i32.const {BASE_PTR}) "{base_data}")
            (data (i32.const {SCALAR_PTR}) "{scalar_data}")
            (func (export "test") (param i32 i32) (result i64)
                (if (i32.ne
                        (call $mul
                            (i64.const {base_ptrsz})
                            (i64.const {scalar_ptrsz})
                            (i64.const {out_ptrsz}))
                        (i32.const {expected_code}))
                    (then unreachable))
                (i64.const {ret_ptrsz}))
        )
        "#,
        base_data = wat_escape(base),
        scalar_data = wat_escape(scalar),
        base_ptrsz = (base.len() as u64) << 32 | BASE_PTR,
        scalar_ptrsz = (scalar.len() as u64) << 32 | SCALAR_PTR,
        out_ptrsz = OUT_LEN << 32 | OUT_PTR,
        ret_ptrsz = OUT_LEN << 32 | OUT_PTR,
    );
    with_core_version_custom_sections(wat::parse_str(module).unwrap())
}

fn run_test_call(module_bytes: &[u8], exec_hint: ExecHint) -> Vec<u8> {
    let proto = HostVmPrototype::new(Config {
        allow_unresolved_imports: false,
        exec_hint,
        heap_pages: HeapPages::new(1024),
        module: module_bytes,
    })
    .unwrap();

    let mut vm = HostVm::from(
        proto
            .run(
                "test",
                StorageProofSizeBehavior::proof_recording_disabled(),
                &[],
            )
            .unwrap(),
    );
    loop {
        match vm {
            HostVm::ReadyToRun(r) => vm = r.run(),
            HostVm::Finished(v) => {
                let value = v.value().as_ref().to_vec();
                return value;
            }
            other => panic!("unexpected state: {other:?}"),
        }
    }
}

#[test]
fn runtime_call_computes_mul() {
    let module_bytes = module_calling_mul(
        &hex::decode(VEC1_BASE).unwrap(),
        &hex::decode(VEC1_SCALAR).unwrap(),
        0,
    );
    for exec_hint in ExecHint::available_engines() {
        let out = run_test_call(&module_bytes, exec_hint);
        assert_eq!(out, hex::decode(VEC1_OUT).unwrap());
    }
}

#[test]
fn runtime_call_degenerate_point_returns_code_4() {
    let module_bytes = module_calling_mul(
        &hex::decode(VEC2_BASE).unwrap(),
        &hex::decode(VEC3_SCALAR).unwrap(),
        elliptic_curves::ERROR_DEGENERATE_POINT,
    );
    for exec_hint in ExecHint::available_engines() {
        // The output buffer stays zeroed: the trap-unless-code-matches check
        // in the module passed, and nothing was written on the error path.
        let out = run_test_call(&module_bytes, exec_hint);
        assert_eq!(out, [0; 64]);
    }
}

#[test]
fn all_ec_host_functions_resolve_with_strict_imports() {
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
            (module
                (import "env" "ext_host_calls_bls12_381_multi_miller_loop_version_1"
                    (func (param i64 i64 i64) (result i32)))
                (import "env" "ext_host_calls_bls12_381_final_exponentiation_version_1"
                    (func (param i64) (result i32)))
                (import "env" "ext_host_calls_bls12_381_msm_g1_version_1"
                    (func (param i64 i64 i64) (result i32)))
                (import "env" "ext_host_calls_bls12_381_msm_g2_version_1"
                    (func (param i64 i64 i64) (result i32)))
                (import "env" "ext_host_calls_bls12_381_mul_g1_version_1"
                    (func (param i64 i64 i64) (result i32)))
                (import "env" "ext_host_calls_bls12_381_mul_g2_version_1"
                    (func (param i64 i64 i64) (result i32)))
                (import "env" "ext_host_calls_ed_on_bls12_381_bandersnatch_msm_version_1"
                    (func (param i64 i64 i64) (result i32)))
                (import "env" "ext_host_calls_ed_on_bls12_381_bandersnatch_mul_version_1"
                    (func (param i64 i64 i64) (result i32)))
                (import "env" "memory" (memory 0))
                (global (export "__heap_base") i32 (i32.const 0))
            )
            "#,
        )
        .unwrap(),
    );

    for exec_hint in ExecHint::available_engines() {
        HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();
    }
}
