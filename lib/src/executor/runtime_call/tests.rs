// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

#![cfg(test)]

//! [`execute_blocks`] reads various JSON files containing test fixtures and executes them.
//!
//! Each test fixture contains a block (header and body), plus the storage of its parent. The
//! test consists in executing the block, to make sure that the state trie root matches the one
//! calculated by smoldot.
//!
//! The other tests check which storage a runtime call accesses once it has finished, depending
//! on [`Config::calculate_child_tries_roots_on_finish`].

use core::{iter, ops};

use super::{Config, RuntimeCall, StorageProofSizeBehavior, run};
use crate::{executor::host, trie};
use alloc::collections::BTreeMap;

#[test]
fn execute_blocks() {
    // Tests ordered alphabetically.
    for (test_num, test_json) in [
        include_str!("./child-trie-create-multiple.json"),
        include_str!("./child-trie-create-one.json"),
        include_str!("./child-trie-destroy.json"),
        include_str!("./child-trie-read-basic.json"),
        // TODO: more tests?
    ]
    .into_iter()
    .enumerate()
    {
        // Decode the test JSON.
        let test_data = serde_json::from_str::<Test>(test_json).unwrap();

        // Turn the nice-looking data into something with better access times.
        let storage = {
            let mut storage = test_data
                .parent_storage
                .main_trie
                .iter()
                .map(|(key, value)| ((None, key.0.clone()), value.0.clone()))
                .collect::<BTreeMap<_, _>>();
            for (child_trie, child_trie_data) in &test_data.parent_storage.child_tries {
                for (key, value) in child_trie_data {
                    storage.insert((Some(child_trie.0.clone()), key.0.clone()), value.0.clone());
                }
            }
            storage
        };

        // Build the runtime.
        let virtual_machine = {
            let code = storage
                .get(&(None, b":code".to_vec()))
                .expect("no runtime code found");
            let heap_pages = crate::executor::storage_heap_pages_to_value(
                storage.get(&(None, b":heappages".to_vec())).map(|v| &v[..]),
            )
            .unwrap();

            host::HostVmPrototype::new(host::Config {
                module: code,
                heap_pages,
                exec_hint: crate::executor::vm::ExecHint::ExecuteOnceWithNonDeterministicValidation,
                allow_unresolved_imports: false,
            })
            .unwrap()
        };

        // The runtime indicates the version of the trie items of the parent storage.
        // While in principle each storage item could have a different version, in practice we
        // just assume they're all the same.
        let state_version = virtual_machine
            .runtime_version()
            .decode()
            .state_version
            .unwrap_or(host::TrieEntryVersion::V0);

        // Start executing `Core_execute_block`. This runtime call will verify at the end whether
        // the trie root hash of the block matches the one calculated by smoldot.
        let execution = run(Config {
            virtual_machine,
            function_to_call: "Core_execute_block",
            max_log_level: 3,
            storage_proof_size_behavior: StorageProofSizeBehavior::Unimplemented,
            storage_main_trie_changes: Default::default(),
            calculate_trie_changes: false,
            calculate_child_tries_roots_on_finish: false,
            parameter: {
                // Block header + number of extrinsics + extrinsics
                let encoded_body_len =
                    crate::util::encode_scale_compact_usize(test_data.block.body.len());
                iter::once(either::Right(either::Left(&test_data.block.header.0)))
                    .chain(iter::once(either::Right(either::Right(encoded_body_len))))
                    .chain(test_data.block.body.iter().map(|b| either::Left(&b.0)))
            },
        })
        .unwrap();

        if let Err(err) = run_to_completion(&storage, state_version, execution, |_| {}) {
            panic!("Error during test #{}: {:?}", test_num, err)
        }
    }
}

/// Runtime with a single function, `write_child_trie`, that writes three entries, `key0`,
/// `key1` and `key2`, to the default child trie `child`, and reads nothing.
fn child_trie_writer_runtime() -> host::HostVmPrototype {
    // A pointer-size, as passed to host functions: the size in the upper 32 bits.
    let module = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory 1))
        (import "env" "ext_default_child_storage_set_version_1"
            (func $child_storage_set (param i64 i64 i64)))
        (global (export "__heap_base") i32 (i32.const 1024))
        (data (i32.const 0) "child")
        (data (i32.const 8) "key0key1key2")
        (data (i32.const 32) "new value")
        (func (export "write_child_trie") (param i32 i32) (result i64)
            (call $child_storage_set
                (i64.const 0x0000000500000000) (i64.const 0x0000000400000008)
                (i64.const 0x0000000900000020))
            (call $child_storage_set
                (i64.const 0x0000000500000000) (i64.const 0x000000040000000c)
                (i64.const 0x0000000900000020))
            (call $child_storage_set
                (i64.const 0x0000000500000000) (i64.const 0x0000000400000010)
                (i64.const 0x0000000900000020))
            (i64.const 0))
    )
    "#,
    )
    .unwrap();

    host::HostVmPrototype::new(host::Config {
        module: with_runtime_version_custom_section(module),
        heap_pages: host::HeapPages::new(1024),
        exec_hint: crate::executor::vm::ExecHint::ExecuteOnceWithNonDeterministicValidation,
        allow_unresolved_imports: false,
    })
    .unwrap()
}

/// The storage of the parent block of [`child_trie_writer_runtime`]'s call: the child trie
/// `child` holds a single entry, `key3`, that the call never reads. Inserting `key0`, `key1`
/// and `key2` turns the leaf node of `key3` into a child of a new branch node.
fn child_trie_writer_parent_storage() -> Entries {
    let mut storage = BTreeMap::new();
    storage.insert(
        (Some(b"child".to_vec()), b"key3".to_vec()),
        b"existing value".to_vec(),
    );
    storage.insert(
        (None, trie::default_child_trie_root_key(b"child")),
        trie::trie_root(
            host::TrieEntryVersion::V0,
            trie::HashFunction::Blake2,
            &[(b"key3", b"existing value")],
        )
        .to_vec(),
    );
    storage
}

fn start_child_trie_writer(
    calculate_trie_changes: bool,
    calculate_child_tries_roots_on_finish: bool,
) -> RuntimeCall {
    run(Config {
        virtual_machine: child_trie_writer_runtime(),
        function_to_call: "write_child_trie",
        parameter: iter::empty::<&[u8]>(),
        max_log_level: 0,
        storage_proof_size_behavior: StorageProofSizeBehavior::proof_recording_disabled(),
        storage_main_trie_changes: Default::default(),
        calculate_trie_changes,
        calculate_child_tries_roots_on_finish,
    })
    .unwrap()
}

#[test]
fn child_tries_roots_not_calculated_on_finish() {
    // A full node executing this call never calculates the root of `child`, and the call proof
    // it generates for it holds only what the runtime has accessed: nothing. The call must then
    // access nothing either, as it would otherwise fail against that proof.
    let success = run_to_completion(
        &child_trie_writer_parent_storage(),
        host::TrieEntryVersion::V0,
        start_child_trie_writer(false, false),
        |access| panic!("storage accessed but never read by the runtime: {access}"),
    )
    .unwrap();

    assert!(success.virtual_machine.value().as_ref().is_empty());
    assert_eq!(
        success
            .storage_changes
            .child_trie_storage_changes_iter_unordered(b"child")
            .count(),
        3
    );
    assert!(
        success
            .storage_changes
            .main_trie_diff_get(&trie::default_child_trie_root_key(b"child"))
            .is_none()
    );
}

#[test]
fn child_tries_roots_calculated_on_finish() {
    let root_key = trie::default_child_trie_root_key(b"child");
    let parent_root = child_trie_writer_parent_storage()[&(None, root_key.clone())].clone();

    let mut roots = Vec::new();
    for (calculate_trie_changes, calculate_child_tries_roots_on_finish) in
        [(false, true), (true, true), (true, false)]
    {
        let mut accesses = Vec::new();
        let success = run_to_completion(
            &child_trie_writer_parent_storage(),
            host::TrieEntryVersion::V0,
            start_child_trie_writer(
                calculate_trie_changes,
                calculate_child_tries_roots_on_finish,
            ),
            |access| accesses.push(access),
        )
        .unwrap();

        // Calculating the new root needs the value of `key3`, which the runtime never read.
        assert!(
            accesses.contains(&"child trie 6368696c64, value of 0x6b657933".to_owned()),
            "{accesses:?}"
        );

        match success.storage_changes.main_trie_diff_get(&root_key) {
            Some(Some(root)) => roots.push(root.to_vec()),
            other => panic!("{other:?}"),
        }
    }

    // `calculate_trie_changes` requires these roots, and implies
    // `calculate_child_tries_roots_on_finish`. The root is the same either way.
    assert_eq!(roots[0].len(), 32);
    assert_ne!(roots[0], parent_root);
    assert!(roots.iter().all(|root| *root == roots[0]));
}

/// Storage entries: the child trie (`None` for the main trie) and key, and the value.
type Entries = BTreeMap<(Option<Vec<u8>>, Vec<u8>), Vec<u8>>;

/// Runs `execution` to its end, answering its storage accesses from `storage`. Calls
/// `on_access` with a description of each storage access.
fn run_to_completion(
    storage: &Entries,
    state_version: host::TrieEntryVersion,
    mut execution: RuntimeCall,
    mut on_access: impl FnMut(String),
) -> Result<super::Success, super::Error> {
    // Keys are printed as hexadecimal digits, one per nibble.
    let describe = |child_trie: Option<&[u8]>, what: &str, key: String| match child_trie {
        Some(child_trie) => format!("child trie {}, {what} 0x{key}", hex::encode(child_trie)),
        None => format!("main trie, {what} 0x{key}"),
    };
    let nibbles = |nibbles: &mut dyn Iterator<Item = trie::Nibble>| -> String {
        nibbles.map(|n| format!("{:x}", u8::from(n))).collect()
    };

    loop {
        match execution {
            RuntimeCall::Finished(result) => return result,
            RuntimeCall::SignatureVerification(sig) => execution = sig.verify_and_resume(),
            RuntimeCall::ClosestDescendantMerkleValue(req) => {
                on_access(describe(
                    req.child_trie().as_ref().map(|c| c.as_ref()),
                    "closest descendant Merkle value of",
                    nibbles(&mut req.key()),
                ));
                execution = req.resume_unknown()
            }
            RuntimeCall::StorageGet(get) => {
                on_access(describe(
                    get.child_trie().as_ref().map(|c| c.as_ref()),
                    "value of",
                    hex::encode(get.key().as_ref()),
                ));
                let value = storage
                    .get(&(
                        get.child_trie().map(|c| c.as_ref().to_owned()),
                        get.key().as_ref().to_owned(),
                    ))
                    .map(|v| (iter::once(&v[..]), state_version));
                execution = get.inject_value(value);
            }
            RuntimeCall::NextKey(req) => {
                on_access(describe(
                    req.child_trie().as_ref().map(|c| c.as_ref()),
                    "next key after",
                    nibbles(&mut req.key()),
                ));
                // Because `NextKey` might ask for branch nodes, and that we don't build the
                // trie in its entirety, we have to use an algorithm that finds the branch
                // nodes for us.
                let next_key = {
                    let mut search = trie::branch_search::BranchSearch::NextKey(
                        trie::branch_search::start_branch_search(trie::branch_search::Config {
                            key_before: req.key().collect::<Vec<_>>().into_iter(),
                            or_equal: req.or_equal(),
                            prefix: req.prefix().collect::<Vec<_>>().into_iter(),
                            no_branch_search: !req.branch_nodes(),
                        }),
                    );

                    loop {
                        match search {
                            trie::branch_search::BranchSearch::Found {
                                branch_trie_node_key,
                            } => break branch_trie_node_key,
                            trie::branch_search::BranchSearch::NextKey(bs_req) => {
                                let result = storage
                                    .range((
                                        if bs_req.or_equal() {
                                            ops::Bound::Included((
                                                req.child_trie().map(|c| c.as_ref().to_owned()),
                                                bs_req.key_before().collect::<Vec<_>>(),
                                            ))
                                        } else {
                                            ops::Bound::Excluded((
                                                req.child_trie().map(|c| c.as_ref().to_owned()),
                                                bs_req.key_before().collect::<Vec<_>>(),
                                            ))
                                        },
                                        ops::Bound::Unbounded,
                                    ))
                                    .next()
                                    .filter(|((trie, key), _)| {
                                        *trie == req.child_trie().map(|c| c.as_ref().to_owned())
                                            && key.starts_with(&bs_req.prefix().collect::<Vec<_>>())
                                    })
                                    .map(|((_, k), _)| k);

                                search = bs_req.inject(result.map(|k| k.iter().copied()));
                            }
                        }
                    }
                };

                execution = req.inject_key(next_key.map(|nk| nk.into_iter()));
            }
            RuntimeCall::LogEmit(log) => execution = log.resume(),
            RuntimeCall::OffchainStorageSet(_) | RuntimeCall::Offchain(_) => {
                unimplemented!()
            }
        }
    }
}

/// Appends to `wasm` the custom section holding the runtime version, which
/// [`host::HostVmPrototype::new`] requires.
fn with_runtime_version_custom_section(mut wasm: Vec<u8>) -> Vec<u8> {
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

// Serde structs used to decode the test fixtures.

#[derive(serde::Deserialize)]
struct Test {
    block: Block,
    #[serde(rename = "parentStorage")]
    parent_storage: Storage,
}

#[derive(serde::Deserialize)]
struct Block {
    header: HexString,
    body: Vec<HexString>,
}

#[derive(serde::Deserialize)]
struct Storage {
    #[serde(rename = "mainTrie")]
    main_trie: hashbrown::HashMap<HexString, HexString, fnv::FnvBuildHasher>,
    #[serde(rename = "childTries")]
    child_tries: hashbrown::HashMap<
        HexString,
        hashbrown::HashMap<HexString, HexString, fnv::FnvBuildHasher>,
        fnv::FnvBuildHasher,
    >,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct HexString(Vec<u8>);

impl<'a> serde::Deserialize<'a> for HexString {
    fn deserialize<D>(deserializer: D) -> Result<HexString, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let string = String::deserialize(deserializer)?;

        if string.is_empty() {
            return Ok(HexString(Vec::new()));
        }

        if !string.starts_with("0x") {
            return Err(serde::de::Error::custom(
                "hexadecimal string doesn't start with 0x",
            ));
        }

        let bytes = hex::decode(&string[2..]).map_err(serde::de::Error::custom)?;
        Ok(HexString(bytes))
    }
}
