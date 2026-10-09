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

//! Tests for `ext_storage_clear_prefix_version_2` and its child trie equivalents when some keys
//! under the prefix were written earlier in the same call and only exist in the pending storage
//! changes.
//!
//! As in Substrate, these keys must all be removed, and must not be counted in the returned
//! number of removed keys nor towards the limit. Only the keys of the storage are counted.

use core::{iter, ops};

use super::super::{Config, RuntimeCall, StorageChanges, StorageProofSizeBehavior, run};
use crate::{
    executor::{host, storage_diff},
    trie,
};
use alloc::collections::BTreeMap;

/// Runtime whose functions all take as input a SCALE-encoded `Option<u32>`, which is passed as
/// is as the limit of `ext_storage_clear_prefix_version_2` with the prefix `abc`.
///
/// - `clear` clears the prefix and returns the result of the clearing.
/// - `write_then_clear` writes `abc1` and `abc2`, then clears the prefix and returns the result
///   of the clearing.
/// - `clear_then_get` writes `abc1`, clears the prefix, then returns the value of `abc1`.
/// - `clear_then_next_key` writes `abc1`, clears the prefix, then returns the key that follows
///   `abc`.
/// - `child_clear_prefix_then_get` writes `abc1` in the child trie `xyz`, clears the prefix `abc`
///   of that child trie, then returns the value of `abc1` in the child trie.
/// - `child_kill_then_get` writes `abc1` in the child trie `xyz`, kills that child trie, then
///   returns the value of `abc1` in the child trie.
const RUNTIME: &str = r#"
(module
    (import "env" "memory" (memory 16))
    (import "env" "ext_storage_set_version_1" (func $set (param i64 i64)))
    (import "env" "ext_storage_get_version_1" (func $get (param i64) (result i64)))
    (import "env" "ext_storage_next_key_version_1" (func $next_key (param i64) (result i64)))
    (import "env" "ext_storage_clear_prefix_version_2"
        (func $clear_prefix (param i64 i64) (result i64)))
    (import "env" "ext_default_child_storage_set_version_1"
        (func $child_set (param i64 i64 i64)))
    (import "env" "ext_default_child_storage_get_version_1"
        (func $child_get (param i64 i64) (result i64)))
    (import "env" "ext_default_child_storage_clear_prefix_version_2"
        (func $child_clear_prefix (param i64 i64 i64) (result i64)))
    (import "env" "ext_default_child_storage_storage_kill_version_3"
        (func $child_kill (param i64 i64) (result i64)))
    (global (export "__heap_base") i32 (i32.const 1024))
    (data (i32.const 0) "abc")
    (data (i32.const 8) "abc1")
    (data (i32.const 16) "abc2")
    (data (i32.const 24) "v")
    (data (i32.const 32) "xyz")

    ;; Turns the input of the function into a pointer-size.
    (func $input (param $input_ptr i32) (param $input_len i32) (result i64)
        (i64.or
            (i64.shl (i64.extend_i32_u (local.get $input_len)) (i64.const 32))
            (i64.extend_i32_u (local.get $input_ptr))))

    ;; Clears `abc` using the input of the function as limit.
    (func $clear (param i32 i32) (result i64)
        (call $clear_prefix
            (i64.const 0x0000000300000000)
            (call $input (local.get 0) (local.get 1))))

    (func (export "clear") (param i32 i32) (result i64)
        (call $clear (local.get 0) (local.get 1)))

    (func (export "write_then_clear") (param i32 i32) (result i64)
        (call $set (i64.const 0x0000000400000008) (i64.const 0x0000000100000018))
        (call $set (i64.const 0x0000000400000010) (i64.const 0x0000000100000018))
        (call $clear (local.get 0) (local.get 1)))

    (func (export "clear_then_get") (param i32 i32) (result i64)
        (call $set (i64.const 0x0000000400000008) (i64.const 0x0000000100000018))
        (drop (call $clear (local.get 0) (local.get 1)))
        (call $get (i64.const 0x0000000400000008)))

    (func (export "clear_then_next_key") (param i32 i32) (result i64)
        (call $set (i64.const 0x0000000400000008) (i64.const 0x0000000100000018))
        (drop (call $clear (local.get 0) (local.get 1)))
        (call $next_key (i64.const 0x0000000300000000)))

    (func (export "child_clear_prefix_then_get") (param i32 i32) (result i64)
        (call $child_set
            (i64.const 0x0000000300000020) (i64.const 0x0000000400000008)
            (i64.const 0x0000000100000018))
        (drop (call $child_clear_prefix
            (i64.const 0x0000000300000020) (i64.const 0x0000000300000000)
            (call $input (local.get 0) (local.get 1))))
        (call $child_get (i64.const 0x0000000300000020) (i64.const 0x0000000400000008)))

    (func (export "child_kill_then_get") (param i32 i32) (result i64)
        (call $child_set
            (i64.const 0x0000000300000020) (i64.const 0x0000000400000008)
            (i64.const 0x0000000100000018))
        (drop (call $child_kill
            (i64.const 0x0000000300000020)
            (call $input (local.get 0) (local.get 1))))
        (call $child_get (i64.const 0x0000000300000020) (i64.const 0x0000000400000008)))
)
"#;

/// SCALE encoding of `None`, used as the limit.
const NO_LIMIT: &[u8] = &[0];

/// Calls `function_to_call` of [`RUNTIME`] with the given input, on top of the given main trie
/// storage and pending changes. All child tries are empty in the storage. Returns the output of
/// the call and the storage changes.
fn run_call(
    function_to_call: &str,
    input: &[u8],
    storage: &BTreeMap<Vec<u8>, Vec<u8>>,
    storage_main_trie_changes: storage_diff::TrieDiff,
) -> (Vec<u8>, StorageChanges) {
    let virtual_machine = host::HostVmPrototype::new(host::Config {
        module: with_runtime_version_custom_sections(wat::parse_str(RUNTIME).unwrap()),
        heap_pages: host::HeapPages::new(1024),
        exec_hint: crate::executor::vm::ExecHint::ExecuteOnceWithNonDeterministicValidation,
        allow_unresolved_imports: false,
    })
    .unwrap();

    let mut execution = run(Config {
        virtual_machine,
        function_to_call,
        parameter: iter::once(input),
        storage_main_trie_changes,
        storage_proof_size_behavior: StorageProofSizeBehavior::Unimplemented,
        max_log_level: 0,
        calculate_trie_changes: false,
    })
    .unwrap();

    loop {
        match execution {
            RuntimeCall::Finished(Ok(success)) => {
                return (
                    success.virtual_machine.value().as_ref().to_vec(),
                    success.storage_changes,
                );
            }
            RuntimeCall::Finished(Err(err)) => panic!("{err:?}"),
            RuntimeCall::StorageGet(req) => {
                let value = if req.child_trie().is_none() {
                    storage.get(req.key().as_ref())
                } else {
                    None
                };
                let value = value.map(|v| (iter::once(&v[..]), host::TrieEntryVersion::V0));
                execution = req.inject_value(value);
            }
            RuntimeCall::ClosestDescendantMerkleValue(req) => execution = req.resume_unknown(),
            RuntimeCall::NextKey(req) if req.child_trie().is_some() => {
                // Child tries are empty in the storage.
                execution = req.inject_key(None::<iter::Empty<_>>);
            }
            RuntimeCall::NextKey(req) => {
                assert!(!req.branch_nodes());
                let key = trie::nibbles_to_bytes_suffix_extend(req.key()).collect::<Vec<_>>();
                let prefix = trie::nibbles_to_bytes_suffix_extend(req.prefix()).collect::<Vec<_>>();
                let next_key = storage
                    .range::<[u8], _>((
                        if req.or_equal() {
                            ops::Bound::Included(&key[..])
                        } else {
                            ops::Bound::Excluded(&key[..])
                        },
                        ops::Bound::Unbounded,
                    ))
                    .next()
                    .map(|(k, _)| k)
                    .filter(|k| k.starts_with(&prefix));
                execution =
                    req.inject_key(next_key.map(|k| trie::bytes_to_nibbles(k.iter().copied())));
            }
            RuntimeCall::LogEmit(req) => execution = req.resume(),
            _ => unreachable!(),
        }
    }
}

/// Appends to `wasm` the custom sections holding the runtime version and runtime APIs, which
/// [`host::HostVmPrototype::new`] requires.
fn with_runtime_version_custom_sections(mut wasm: Vec<u8>) -> Vec<u8> {
    let mut runtime_version = Vec::new();
    for name in ["foo", "bar"] {
        runtime_version
            .extend_from_slice(crate::util::encode_scale_compact_usize(name.len()).as_ref());
        runtime_version.extend_from_slice(name.as_bytes());
    }
    // Authoring, spec and implementation versions.
    runtime_version.extend_from_slice(&[0; 12]);
    // No runtime APIs.
    runtime_version.extend_from_slice(crate::util::encode_scale_compact_usize(0).as_ref());
    // Transaction and state versions.
    runtime_version.extend_from_slice(&[0; 5]);

    for (name, content) in [
        (&b"runtime_version"[..], &runtime_version[..]),
        (b"runtime_apis", &[]),
    ] {
        let mut section = Vec::new();
        section.extend(crate::util::leb128::encode_usize(name.len()));
        section.extend_from_slice(name);
        section.extend_from_slice(content);
        wasm.push(0);
        wasm.extend(crate::util::leb128::encode_usize(section.len()));
        wasm.extend_from_slice(&section);
    }

    wasm
}

fn storage(keys: &[&[u8]]) -> BTreeMap<Vec<u8>, Vec<u8>> {
    keys.iter().map(|k| (k.to_vec(), b"x".to_vec())).collect()
}

#[test]
fn get_after_clear_doesnt_return_key_written_earlier() {
    let (output, _) = run_call(
        "clear_then_get",
        NO_LIMIT,
        &storage(&[]),
        storage_diff::TrieDiff::empty(),
    );
    // `None`
    assert_eq!(output, [0]);
}

#[test]
fn next_key_after_clear_skips_key_written_earlier() {
    let (output, _) = run_call(
        "clear_then_next_key",
        NO_LIMIT,
        &storage(&[b"abd"]),
        storage_diff::TrieDiff::empty(),
    );
    // `Some(b"abd")`
    assert_eq!(output, [1, 3 << 2, b'a', b'b', b'd']);
}

#[test]
fn keys_written_earlier_removed_but_not_counted() {
    // `abc2` is both in the storage and written during the call. It is counted once.
    let (output, changes) = run_call(
        "write_then_clear",
        NO_LIMIT,
        &storage(&[b"abc2", b"abc3", b"abd"]),
        storage_diff::TrieDiff::empty(),
    );
    // `AllRemoved(2)`
    assert_eq!(output, [0, 2, 0, 0, 0]);
    assert_eq!(changes.main_trie_diff_get(b"abc1"), Some(None));
    assert_eq!(changes.main_trie_diff_get(b"abc2"), Some(None));
    assert_eq!(changes.main_trie_diff_get(b"abc3"), Some(None));
    assert_eq!(changes.main_trie_diff_get(b"abd"), None);
}

#[test]
fn keys_written_earlier_dont_count_towards_limit() {
    // Limit of `Some(1)`. Both keys written during the call are removed, then one key of the
    // storage.
    let (output, changes) = run_call(
        "write_then_clear",
        &[1, 1, 0, 0, 0],
        &storage(&[b"abc2", b"abc3"]),
        storage_diff::TrieDiff::empty(),
    );
    // `SomeRemaining(1)`
    assert_eq!(output, [1, 1, 0, 0, 0]);
    assert_eq!(changes.main_trie_diff_get(b"abc1"), Some(None));
    assert_eq!(changes.main_trie_diff_get(b"abc2"), Some(None));
    assert_eq!(changes.main_trie_diff_get(b"abc3"), None);
}

#[test]
fn keys_written_by_previous_call_removed_but_not_counted() {
    let mut storage_main_trie_changes = storage_diff::TrieDiff::empty();
    storage_main_trie_changes.diff_insert(b"abc1".to_vec(), b"v".to_vec(), ());

    let (output, changes) = run_call(
        "clear",
        NO_LIMIT,
        &storage(&[b"abc2"]),
        storage_main_trie_changes,
    );
    // `AllRemoved(1)`
    assert_eq!(output, [0, 1, 0, 0, 0]);
    assert_eq!(changes.main_trie_diff_get(b"abc1"), Some(None));
    assert_eq!(changes.main_trie_diff_get(b"abc2"), Some(None));
}

#[test]
fn keys_written_earlier_removed_with_zero_limit() {
    let mut storage_main_trie_changes = storage_diff::TrieDiff::empty();
    storage_main_trie_changes.diff_insert(b"abc1".to_vec(), b"v".to_vec(), ());

    // Limit of `Some(0)`.
    let (output, changes) = run_call(
        "clear",
        &[1, 0, 0, 0, 0],
        &storage(&[b"abc2"]),
        storage_main_trie_changes,
    );
    // `SomeRemaining(0)`
    assert_eq!(output, [1, 0, 0, 0, 0]);
    assert_eq!(changes.main_trie_diff_get(b"abc1"), Some(None));
    assert_eq!(changes.main_trie_diff_get(b"abc2"), None);
}

fn check_child_trie_keys_written_earlier_removed(function_to_call: &str) {
    let (output, changes) = run_call(
        function_to_call,
        NO_LIMIT,
        &storage(&[]),
        storage_diff::TrieDiff::empty(),
    );
    // `None`
    assert_eq!(output, [0]);
    assert_eq!(
        changes
            .child_trie_storage_changes_iter_unordered(b"xyz")
            .collect::<Vec<_>>(),
        [(&b"abc1"[..], None)]
    );
    // The child trie is empty at the end of the call, so its root is removed from the main trie.
    assert_eq!(
        changes.main_trie_diff_get(&trie::default_child_trie_root_key(b"xyz")),
        Some(None)
    );
}

#[test]
fn child_trie_clear_prefix_removes_keys_written_earlier() {
    check_child_trie_keys_written_earlier_removed("child_clear_prefix_then_get");
}

#[test]
fn child_trie_kill_removes_keys_written_earlier() {
    check_child_trie_keys_written_earlier_removed("child_kill_then_get");
}
