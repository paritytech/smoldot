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
//! Tests for `ext_storage_exists_version_1` and `ext_default_child_storage_exists_version_1`.
//!
//! These host functions only need to know whether a value exists, which makes it possible to
//! answer them with [`StorageGet::value_from_proof`] even if the proof only contains the hash of
//! the value.

use core::iter;

use super::super::{Config, RuntimeCall, StorageGet, StorageProofSizeBehavior, run};
use crate::{
    executor::{host, storage_diff},
    trie, util,
};

/// Runtime whose functions all ignore their input.
///
/// - `exists` returns the result of `ext_storage_exists_version_1` on `abc` as one byte.
/// - `child_exists` is the same as `exists` but in the child trie `xyz`.
/// - `set_then_exists` writes `abc`, then does the same as `exists`.
/// - `read_empty` calls `ext_storage_read_version_1` on `abc` with an empty output buffer and
///   returns its result.
/// - `get` returns the result of `ext_storage_get_version_1` on `abc`.
const RUNTIME: &str = r#"
(module
    (import "env" "memory" (memory 16))
    (import "env" "ext_storage_set_version_1" (func $set (param i64 i64)))
    (import "env" "ext_storage_get_version_1" (func $get (param i64) (result i64)))
    (import "env" "ext_storage_read_version_1" (func $read (param i64 i64 i32) (result i64)))
    (import "env" "ext_storage_exists_version_1" (func $exists (param i64) (result i32)))
    (import "env" "ext_default_child_storage_exists_version_1"
        (func $child_exists (param i64 i64) (result i32)))
    (global (export "__heap_base") i32 (i32.const 1024))
    (data (i32.const 0) "abc")
    (data (i32.const 24) "v")
    (data (i32.const 32) "xyz")

    (func (export "exists") (param i32 i32) (result i64)
        (i32.store8 (i32.const 64) (call $exists (i64.const 0x0000000300000000)))
        (i64.const 0x0000000100000040))

    (func (export "child_exists") (param i32 i32) (result i64)
        (i32.store8 (i32.const 64)
            (call $child_exists (i64.const 0x0000000300000020) (i64.const 0x0000000300000000)))
        (i64.const 0x0000000100000040))

    (func (export "set_then_exists") (param i32 i32) (result i64)
        (call $set (i64.const 0x0000000300000000) (i64.const 0x0000000100000018))
        (i32.store8 (i32.const 64) (call $exists (i64.const 0x0000000300000000)))
        (i64.const 0x0000000100000040))

    (func (export "read_empty") (param i32 i32) (result i64)
        (call $read (i64.const 0x0000000300000000) (i64.const 0x0000000000000050) (i32.const 0)))

    (func (export "get") (param i32 i32) (result i64)
        (call $get (i64.const 0x0000000300000000)))
)
"#;

/// Starts calling `function_to_call` of [`RUNTIME`].
fn start(function_to_call: &str) -> RuntimeCall {
    let virtual_machine = host::HostVmPrototype::new(host::Config {
        module: host::tests::with_core_version_custom_sections(wat::parse_str(RUNTIME).unwrap()),
        heap_pages: host::HeapPages::new(1024),
        exec_hint: crate::executor::vm::ExecHint::ExecuteOnceWithNonDeterministicValidation,
        allow_unresolved_imports: false,
    })
    .unwrap();

    run(Config {
        virtual_machine,
        function_to_call,
        parameter: iter::empty::<&[u8]>(),
        storage_main_trie_changes: storage_diff::TrieDiff::empty(),
        storage_proof_size_behavior: StorageProofSizeBehavior::Unimplemented,
        max_log_level: 0,
        calculate_trie_changes: false,
        calculate_child_tries_roots_on_finish: false,
    })
    .unwrap()
}

/// Calls `function_to_call` of [`RUNTIME`]. Storage requests are answered as if `abc` had the
/// value `value` in the main trie and in the child trie `xyz`.
///
/// Returns the output of the call and, for each storage request, the value of
/// [`StorageGet::is_existence_check`].
fn run_call(function_to_call: &str, value: Option<&[u8]>) -> (Vec<u8>, Vec<bool>) {
    let mut execution = start(function_to_call);

    let mut existence_checks = Vec::new();

    loop {
        match execution {
            RuntimeCall::Finished(Ok(success)) => {
                return (
                    success.virtual_machine.value().as_ref().to_vec(),
                    existence_checks,
                );
            }
            RuntimeCall::Finished(Err(err)) => panic!("{err:?}"),
            RuntimeCall::StorageGet(req) => execution = answer(req, value, &mut existence_checks),
            _ => unreachable!(),
        }
    }
}

fn answer(req: StorageGet, value: Option<&[u8]>, existence_checks: &mut Vec<bool>) -> RuntimeCall {
    assert_eq!(req.key().as_ref(), b"abc");
    existence_checks.push(req.is_existence_check());
    req.inject_value(value.map(|v| (iter::once(v), host::TrieEntryVersion::V1)))
}

#[test]
fn exists_is_existence_check() {
    assert_eq!(run_call("exists", Some(b"foo")), (vec![1], vec![true]));
    assert_eq!(run_call("exists", None), (vec![0], vec![true]));
}

#[test]
fn child_exists_is_existence_check() {
    assert_eq!(
        run_call("child_exists", Some(b"foo")),
        (vec![1], vec![true])
    );
    assert_eq!(run_call("child_exists", None), (vec![0], vec![true]));
}

#[test]
fn exists_after_write_doesnt_query_storage() {
    assert_eq!(run_call("set_then_exists", None), (vec![1], vec![]));
}

#[test]
fn read_with_empty_buffer_isnt_existence_check() {
    // `Some(3)`, the full length of the value, which can't be known from its hash.
    assert_eq!(
        run_call("read_empty", Some(b"foo")),
        (vec![1, 3, 0, 0, 0], vec![false])
    );
}

#[test]
fn get_isnt_existence_check() {
    // `Some(b"foo")`
    assert_eq!(
        run_call("get", Some(b"foo")),
        (vec![1, 3 << 2, b'f', b'o', b'o'], vec![false])
    );
}

/// Builds a proof made of a single root node of key `key`, whose storage value is the hash
/// `value_hash`. The value itself isn't in the proof. Returns the proof and the trie root.
fn proof_with_hashed_value(key: &[u8], value_hash: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    let node = trie::trie_node::encode(trie::trie_node::Decoded {
        partial_key: trie::bytes_to_nibbles(key.iter().copied()),
        children: [None::<&[u8]>; 16],
        storage_value: trie::trie_node::StorageValue::Hashed(value_hash),
    })
    .unwrap()
    .fold(Vec::new(), |mut a, b| {
        a.extend_from_slice(b.as_ref());
        a
    });

    let trie_root: [u8; 32] = blake2_rfc::blake2b::blake2b(32, &[], &node)
        .as_bytes()
        .try_into()
        .unwrap();

    let mut proof = util::encode_scale_compact_usize(1).as_ref().to_vec();
    proof.extend_from_slice(util::encode_scale_compact_usize(node.len()).as_ref());
    proof.extend_from_slice(&node);
    (proof, trie_root)
}

/// Runs `function_to_call` of [`RUNTIME`], answering storage requests with
/// [`StorageGet::value_from_proof`] using the given proof.
fn run_call_with_proof(function_to_call: &str, proof: &[u8], trie_root: &[u8; 32]) -> Vec<u8> {
    let proof =
        trie::proof_decode::decode_and_verify_proof(trie::proof_decode::Config { proof }).unwrap();

    let mut execution = start(function_to_call);
    loop {
        match execution {
            RuntimeCall::Finished(Ok(success)) => {
                return success.virtual_machine.value().as_ref().to_vec();
            }
            RuntimeCall::StorageGet(req) => {
                let value = req.value_from_proof(&proof, trie_root).unwrap();
                execution = req.inject_value(value.map(|(v, vers)| (iter::once(v), vers)));
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn exists_answered_from_value_hash() {
    let (proof, trie_root) = proof_with_hashed_value(b"abc", &[0xaa; 32]);
    assert_eq!(run_call_with_proof("exists", &proof, &trie_root), [1]);
}

#[test]
fn exists_false_from_proof_of_absence() {
    let (proof, trie_root) = proof_with_hashed_value(b"abd", &[0xaa; 32]);
    assert_eq!(run_call_with_proof("exists", &proof, &trie_root), [0]);
}

#[test]
fn get_needs_value_not_only_hash() {
    let (proof, trie_root) = proof_with_hashed_value(b"abc", &[0xaa; 32]);
    let proof = trie::proof_decode::decode_and_verify_proof(trie::proof_decode::Config {
        proof: &proof[..],
    })
    .unwrap();

    for function in ["get", "read_empty"] {
        let RuntimeCall::StorageGet(req) = start(function) else {
            panic!()
        };
        assert!(req.value_from_proof(&proof, &trie_root).is_err());
    }
}
