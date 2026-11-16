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

//! The test in this module reads various JSON files containing test fixtures and executes them.
//!
//! Each test fixture contains a block (header and body), plus the storage of its parent. The
//! test consists in executing the block, to make sure that the state trie root matches the one
//! calculated by smoldot.

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
        let mut execution = run(Config {
            virtual_machine,
            function_to_call: "Core_execute_block",
            max_log_level: 3,
            storage_proof_size_behavior: StorageProofSizeBehavior::Unimplemented,
            storage_main_trie_changes: Default::default(),
            calculate_trie_changes: false,
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

        loop {
            match execution {
                RuntimeCall::Finished(Ok(_)) => break, // Test successful!
                RuntimeCall::Finished(Err(err)) => {
                    panic!("Error during test #{}: {:?}", test_num, err)
                }
                RuntimeCall::SignatureVerification(sig) => execution = sig.verify_and_resume(),
                RuntimeCall::ClosestDescendantMerkleValue(req) => execution = req.resume_unknown(),
                RuntimeCall::StorageGet(get) => {
                    let value = storage
                        .get(&(
                            get.child_trie().map(|c| c.as_ref().to_owned()),
                            get.key().as_ref().to_owned(),
                        ))
                        .map(|v| (iter::once(&v[..]), state_version));
                    execution = get.inject_value(value);
                }
                RuntimeCall::NextKey(req) => {
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
                                                && key.starts_with(
                                                    &bs_req.prefix().collect::<Vec<_>>(),
                                                )
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
}

/// As in Substrate, clearing a main trie prefix that starts with `:child_storage:` is ignored.
#[test]
fn clear_prefix_keeps_child_trie_root() {
    // `clear_root_key` clears the main trie prefix `:child_storage:default:xyz` without limit
    // and returns the result of the clearing.
    let wasm = wat::parse_str(
        r#"
        (module
            (import "env" "memory" (memory 16))
            (import "env" "ext_storage_clear_prefix_version_2"
                (func $clear_prefix (param i64 i64) (result i64)))
            (global (export "__heap_base") i32 (i32.const 1024))
            (data (i32.const 0) ":child_storage:default:xyz")
            ;; SCALE encoding of `None`, used as the limit.
            (data (i32.const 32) "\00")

            ;; The parameters are the 26 bytes at offset 0 and the byte at offset 32.
            (func (export "clear_root_key") (param i32 i32) (result i64)
                (call $clear_prefix
                    (i64.const 0x0000001A00000000)
                    (i64.const 0x0000000100000020)))
        )
        "#,
    )
    .unwrap();

    let virtual_machine = host::HostVmPrototype::new(host::Config {
        module: host::tests::with_core_version_custom_sections(wasm),
        heap_pages: host::HeapPages::new(1024),
        exec_hint: crate::executor::vm::ExecHint::ExecuteOnceWithNonDeterministicValidation,
        allow_unresolved_imports: false,
    })
    .unwrap();

    let mut execution = run(Config {
        virtual_machine,
        function_to_call: "clear_root_key",
        max_log_level: 0,
        storage_proof_size_behavior: StorageProofSizeBehavior::Unimplemented,
        storage_main_trie_changes: Default::default(),
        calculate_trie_changes: false,
        parameter: iter::empty::<Vec<u8>>(),
    })
    .unwrap();

    // The storage contains only the root of the child trie `xyz`.
    let root_key = trie::default_child_trie_root_key(b"xyz");

    let success = loop {
        match execution {
            RuntimeCall::Finished(Ok(success)) => break success,
            RuntimeCall::Finished(Err(err)) => panic!("{err:?}"),
            // Only requested if the clearing isn't ignored.
            RuntimeCall::NextKey(req) => {
                let key = trie::nibbles_to_bytes_suffix_extend(req.key()).collect::<Vec<_>>();
                let found = if req.or_equal() {
                    root_key >= key
                } else {
                    root_key > key
                };
                execution =
                    req.inject_key(found.then(|| trie::bytes_to_nibbles(root_key.iter().copied())));
            }
            _ => unreachable!(),
        }
    };

    // `AllRemoved(0)`
    assert_eq!(success.virtual_machine.value().as_ref(), [0, 0, 0, 0, 0]);
    assert_eq!(success.storage_changes.main_trie_diff_get(&root_key), None);
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
