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
//! These host functions only need to know whether a value exists, which is reported by
//! [`StorageGet::is_existence_check`] and answered with [`StorageGet::inject_existence`].

use core::iter;

use super::super::{Config, RuntimeCall, StorageGet, StorageProofSizeBehavior, run};
use crate::executor::{host, storage_diff};

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

/// Calls `function_to_call` of [`RUNTIME`]. Storage requests are answered as if `abc` had the
/// value `value` in the main trie and in the child trie `xyz`, using
/// [`StorageGet::inject_existence`] when possible.
///
/// Returns the output of the call and, for each storage request, the value of
/// [`StorageGet::is_existence_check`].
fn run_call(function_to_call: &str, value: Option<&[u8]>) -> (Vec<u8>, Vec<bool>) {
    let virtual_machine = host::HostVmPrototype::new(host::Config {
        module: host::tests::with_core_version_custom_sections(wat::parse_str(RUNTIME).unwrap()),
        heap_pages: host::HeapPages::new(1024),
        exec_hint: crate::executor::vm::ExecHint::ExecuteOnceWithNonDeterministicValidation,
        allow_unresolved_imports: false,
    })
    .unwrap();

    let mut execution = run(Config {
        virtual_machine,
        function_to_call,
        parameter: iter::empty::<&[u8]>(),
        storage_main_trie_changes: storage_diff::TrieDiff::empty(),
        storage_proof_size_behavior: StorageProofSizeBehavior::Unimplemented,
        max_log_level: 0,
        calculate_trie_changes: false,
        calculate_child_tries_roots_on_finish: false,
    })
    .unwrap();

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
    if req.is_existence_check() {
        req.inject_existence(value.is_some())
    } else {
        req.inject_value(value.map(|v| (iter::once(v), host::TrieEntryVersion::V1)))
    }
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

#[test]
#[should_panic]
fn inject_existence_panics_if_value_needed() {
    let virtual_machine = host::HostVmPrototype::new(host::Config {
        module: host::tests::with_core_version_custom_sections(wat::parse_str(RUNTIME).unwrap()),
        heap_pages: host::HeapPages::new(1024),
        exec_hint: crate::executor::vm::ExecHint::ExecuteOnceWithNonDeterministicValidation,
        allow_unresolved_imports: false,
    })
    .unwrap();

    let execution = run(Config {
        virtual_machine,
        function_to_call: "get",
        parameter: iter::empty::<&[u8]>(),
        storage_main_trie_changes: storage_diff::TrieDiff::empty(),
        storage_proof_size_behavior: StorageProofSizeBehavior::Unimplemented,
        max_log_level: 0,
        calculate_trie_changes: false,
        calculate_child_tries_roots_on_finish: false,
    })
    .unwrap();

    let RuntimeCall::StorageGet(req) = execution else {
        panic!()
    };
    let _ = req.inject_existence(true);
}
