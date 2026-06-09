// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

//! Wasm virtual machine, with automatic storage overlay.
//!
//! The code in this module builds upon the functionalities of the [`host`] module and
//! implements some of the host function calls. In other words, it is an easier-to-use version of
//! the [`host`] module.
//!
//! Most of the documentation of the [`host`] module also applies here.
//!
//! In addition to the functionalities provided by the [`host`] module, the `runtime_call` module:
//!
//! - Keeps track of the changes to the storage and off-chain storage made by the execution, and
//!   provides them at the end. Any storage access takes into account the intermediary list of
//!   changes.
//! - Automatically handles some externalities, such as calculating the Merkle root or storage
//!   transactions.
//!
//! These additional features considerably reduces the number of externals concepts to plug to
//! the virtual machine.

// TODO: more docs

use crate::{
    executor::{self, host, storage_diff, trie_root_calculator, vm},
    trie, util,
};

use alloc::{
    borrow::ToOwned as _,
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString as _},
    vec::Vec,
};
use core::{fmt, iter, ops};

pub use host::{
    Error as ErrorDetail, LogEmitInfo, LogEmitInfoHex, LogEmitInfoStr, StorageProofSizeBehavior,
};
pub use trie::{Nibble, TrieEntryVersion};

mod tests;

/// Configuration for [`run`].
pub struct Config<'a, TParams> {
    /// Virtual machine to be run.
    pub virtual_machine: host::HostVmPrototype,

    /// Name of the function to be called.
    pub function_to_call: &'a str,

    /// Parameter of the call, as an iterator of bytes. The concatenation of bytes forms the
    /// actual input.
    pub parameter: TParams,

    /// Initial state of [`Success::storage_changes`]. The changes made during this
    /// execution will be pushed over the value in this field.
    // TODO: consider accepting a different type
    // TODO: accept also child trie modifications
    pub storage_main_trie_changes: storage_diff::TrieDiff,

    /// Behavior if the `ext_storage_proof_size_storage_proof_size_version_1` host function is
    /// called.
    ///
    /// See the documentation of [`StorageProofSizeBehavior`].
    pub storage_proof_size_behavior: StorageProofSizeBehavior,

    /// Maximum log level of the runtime.
    ///
    /// > **Note**: This value is opaque from the point of the view of the client, and the runtime
    /// >           is free to interpret it the way it wants. However, usually values are: `0` for
    /// >           "off", `1` for "error", `2` for "warn", `3` for "info", `4` for "debug",
    /// >           and `5` for "trace".
    pub max_log_level: u32,

    /// If `true`, then [`StorageChanges::trie_changes_iter_ordered`] will return `Some`.
    /// Passing `None` requires fewer calculation and fewer storage accesses.
    pub calculate_trie_changes: bool,
}

/// Start running the WebAssembly virtual machine.
pub fn run(
    config: Config<impl Iterator<Item = impl AsRef<[u8]>> + Clone>,
) -> Result<RuntimeCall, (host::StartErr, host::HostVmPrototype)> {
    let state_trie_version = config
        .virtual_machine
        .runtime_version()
        .decode()
        .state_version
        .unwrap_or(TrieEntryVersion::V0);

    Ok(Inner {
        vm: config
            .virtual_machine
            .run_vectored(
                config.function_to_call,
                config.storage_proof_size_behavior,
                config.parameter,
            )?
            .into(),
        pending_storage_changes: PendingStorageChanges {
            trie_diffs: {
                let mut hm = hashbrown::HashMap::with_capacity_and_hasher(4, Default::default());
                hm.insert(None, config.storage_main_trie_changes);
                hm
            },
            stale_child_tries_root_hashes: hashbrown::HashSet::with_capacity_and_hasher(
                4,
                Default::default(),
            ),
            tries_changes: BTreeMap::new(),
            offchain_storage_changes: BTreeMap::new(),
        },
        state_trie_version,
        transactions_stack: Vec::new(),
        offchain_storage_changes: BTreeMap::new(),
        root_calculation: None,
        max_log_level: config.max_log_level,
        calculate_trie_changes: config.calculate_trie_changes,
    }
    .run())
}

/// Execution is successful.
#[derive(Debug)]
pub struct Success {
    /// Contains the output value of the runtime, and the virtual machine that was passed at
    /// initialization.
    pub virtual_machine: SuccessVirtualMachine,
    /// List of changes to the storage that the block performs.
    pub storage_changes: StorageChanges,
    /// State trie version indicated by the runtime. All the storage changes indicated by
    /// [`Success::storage_changes`] should store this version alongside with them.
    pub state_trie_version: TrieEntryVersion,
}

/// See [`Success::storage_changes`].
pub struct StorageChanges {
    /// The [`PendingStorageChanges`] that was built by the state machine. The changes are no
    /// longer pending.
    inner: PendingStorageChanges,

    /// See [`Config::calculate_trie_changes`].
    calculate_trie_changes: bool,
}

impl StorageChanges {
    /// Returns an empty [`StorageChanges`], as if the execution didn't modify anything.
    pub fn empty() -> StorageChanges {
        StorageChanges {
            inner: PendingStorageChanges {
                trie_diffs: hashbrown::HashMap::with_capacity_and_hasher(0, Default::default()),
                stale_child_tries_root_hashes: hashbrown::HashSet::with_capacity_and_hasher(
                    4,
                    Default::default(),
                ),
                tries_changes: BTreeMap::new(),
                offchain_storage_changes: BTreeMap::new(),
            },
            calculate_trie_changes: true,
        }
    }

    /// Returns the change, if any, at the given key of the main trie.
    ///
    /// Returns `None` if the runtime hasn't modified this entry in the main trie, and `Some(None)`
    /// if the runtime has removed the storage item of this entry.
    pub fn main_trie_diff_get(&self, key: &[u8]) -> Option<Option<&[u8]>> {
        self.inner
            .trie_diffs
            .get(&None)
            .and_then(|diff| diff.diff_get(key).map(|(v, _)| v))
    }

    /// Returns an iterator to all the entries of the main trie that are modified by this runtime
    /// call.
    ///
    /// Each value is either `Some` if the runtime overwrites this value, or `None` if it erases
    /// the underlying value.
    ///
    /// > **Note**: This function is equivalent to
    /// >           [`StorageChanges::storage_changes_iter_unordered`], except that it only returns
    /// >           changes made to the main trie.
    pub fn main_trie_storage_changes_iter_unordered(
        &self,
    ) -> impl Iterator<Item = (&[u8], Option<&[u8]>)> + Clone {
        self.inner
            .trie_diffs
            .get(&None)
            .into_iter()
            .flat_map(|list| list.diff_iter_unordered().map(|(k, v, ())| (k, v)))
    }

    /// Returns the list of all child tries whose content has been modified in some way.
    pub fn tries_with_storage_changes_unordered(&self) -> impl Iterator<Item = &[u8]> {
        self.inner.trie_diffs.keys().filter_map(|k| k.as_deref())
    }

    /// Returns an iterator to all the entries of the given child trie that are modified by this
    /// runtime call.
    ///
    /// Each value is either `Some` if the runtime overwrites this value, or `None` if it erases
    /// the underlying value.
    ///
    /// > **Note**: This function is equivalent to
    /// >           [`StorageChanges::storage_changes_iter_unordered`], except that it only returns
    /// >           changes made to the given child trie.
    pub fn child_trie_storage_changes_iter_unordered(
        &self,
        child_trie: &[u8],
    ) -> impl Iterator<Item = (&[u8], Option<&[u8]>)> + Clone {
        self.inner
            .trie_diffs
            .get(&Some(child_trie.to_vec())) // TODO: annoying unnecessary overhead
            .into_iter()
            .flat_map(|list| list.diff_iter_unordered().map(|(k, v, ())| (k, v)))
    }

    /// Returns an iterator to all the entries that are modified by this runtime call.
    ///
    /// Each value is either `Some` if the runtime overwrites this value, or `None` if it erases
    /// the underlying value.
    pub fn storage_changes_iter_unordered(
        &self,
    ) -> impl Iterator<Item = (Option<&[u8]>, &[u8], Option<&[u8]>)> + Clone {
        self.inner.trie_diffs.iter().flat_map(|(trie, list)| {
            list.diff_iter_unordered()
                .map(move |(k, v, ())| (trie.as_deref(), k, v))
        })
    }

    /// Returns an iterator over the list of all changes performed to the tries (main trie and
    /// child tries included).
    ///
    /// Returns `Some` if and only if [`Config::calculate_trie_changes`] was `true` or if the
    /// [`StorageChanges`] was created using [`StorageChanges::empty`].
    pub fn trie_changes_iter_ordered(
        &'_ self,
    ) -> Option<impl Iterator<Item = (Option<&'_ [u8]>, &'_ [Nibble], TrieChange<'_>)>> {
        if !self.calculate_trie_changes {
            return None;
        }

        Some(
            self.inner
                .tries_changes
                .iter()
                .map(|((child_trie, key), change)| {
                    let change = match change {
                        PendingStorageChangesTrieNode::Removed => TrieChange::Remove,
                        PendingStorageChangesTrieNode::InsertUpdate {
                            new_merkle_value,
                            partial_key,
                            children_merkle_values,
                        } => {
                            debug_assert!(key.ends_with(partial_key));

                            let new_storage_value = if key.len() % 2 == 0 {
                                let key_bytes =
                                    trie::nibbles_to_bytes_truncate(key.iter().copied())
                                        .collect::<Vec<_>>();
                                match self
                                    .inner
                                    .trie_diffs
                                    .get(child_trie)
                                    .and_then(|diff| diff.diff_get(&key_bytes))
                                {
                                    None => TrieChangeStorageValue::Unmodified,
                                    Some((new_value, ())) => {
                                        TrieChangeStorageValue::Modified { new_value }
                                    }
                                }
                            } else {
                                TrieChangeStorageValue::Unmodified
                            };

                            let children_merkle_values = <Box<[_; 16]>>::try_from(
                                children_merkle_values
                                    .iter()
                                    .map(|child| child.as_ref().map(|mv| &mv[..]))
                                    .collect::<Box<[_]>>(),
                            )
                            .unwrap();

                            TrieChange::InsertUpdate {
                                new_merkle_value,
                                partial_key,
                                children_merkle_values,
                                new_storage_value,
                            }
                        }
                    };

                    (child_trie.as_deref(), &key[..], change)
                }),
        )
    }

    /// Returns a diff of the main trie.
    // TODO: weird API, necessary to turn this object back to a value for Config::storage_changes
    pub fn into_main_trie_diff(mut self) -> storage_diff::TrieDiff {
        self.inner
            .trie_diffs
            .remove(&None)
            .unwrap_or(storage_diff::TrieDiff::empty())
    }
}

impl fmt::Debug for StorageChanges {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(trie_changes) = self.trie_changes_iter_ordered() {
            f.debug_map()
                .entries(trie_changes.map(|(child_trie, key, change)| {
                    let mut key_str = key
                        .iter()
                        .copied()
                        .map(|n| format!("{:x}", n))
                        .collect::<String>();
                    if key_str.is_empty() {
                        key_str = "∅".to_owned();
                    }

                    let key = match child_trie {
                        Some(ct) => format!(
                            "<{}>:{}",
                            if ct.is_empty() {
                                "∅".to_string()
                            } else {
                                hex::encode(ct)
                            },
                            key_str
                        ),
                        None => format!("<main>:{}", key_str),
                    };

                    (key, change)
                }))
                .finish()
        } else {
            f.debug_map()
                .entries(self.inner.trie_diffs.iter().flat_map(|(child_trie, diff)| {
                    diff.diff_iter_unordered().map(move |(key, value, _)| {
                        let mut key_str = key
                            .iter()
                            .copied()
                            .map(|n| format!("{:x}", n))
                            .collect::<String>();
                        if key_str.is_empty() {
                            key_str = "∅".to_owned();
                        }

                        let key = match child_trie {
                            Some(ct) => format!(
                                "<{}>:{}",
                                if ct.is_empty() {
                                    "∅".to_string()
                                } else {
                                    hex::encode(ct)
                                },
                                key_str
                            ),
                            None => format!("<main>:{}", key_str),
                        };

                        let change = if let Some(value) = value {
                            hex::encode(value)
                        } else {
                            "<deleted>".into()
                        };

                        (key, change)
                    })
                }))
                .finish()
        }
    }
}

#[derive(Clone)]
pub enum TrieChange<'a> {
    /// Trie node is either newly-created, or already existed and has a new Merkle value.
    InsertUpdate {
        /// New Merkle value associated to this trie node. Always inferior or equal to 32 bytes.
        new_merkle_value: &'a [u8],
        partial_key: &'a [Nibble],
        children_merkle_values: Box<[Option<&'a [u8]>; 16]>,
        /// Change to the storage value of that trie node.
        new_storage_value: TrieChangeStorageValue<'a>,
    },
    /// Trie node is removed.
    Remove,
}

impl<'a> fmt::Debug for TrieChange<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TrieChange::Remove => f.debug_tuple("Remove").finish(),
            TrieChange::InsertUpdate {
                new_merkle_value,
                partial_key,
                children_merkle_values,
                new_storage_value,
            } => f
                .debug_struct("InsertUpdate")
                .field("new_merkle_value", &hex::encode(new_merkle_value))
                .field(
                    "partial_key",
                    &partial_key
                        .iter()
                        .map(|n| format!("{:x}", n))
                        .collect::<String>(),
                )
                .field(
                    "children_merkle_values",
                    &children_merkle_values
                        .iter()
                        .map(|child| match child {
                            Some(child) => hex::encode(child),
                            None => "∅".to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                )
                .field("new_storage_value", new_storage_value)
                .finish(),
        }
    }
}

#[derive(Clone)]
pub enum TrieChangeStorageValue<'a> {
    Unmodified,
    Modified { new_value: Option<&'a [u8]> },
}

impl<'a> fmt::Debug for TrieChangeStorageValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TrieChangeStorageValue::Unmodified => f.debug_tuple("Unmodified").finish(),
            TrieChangeStorageValue::Modified { new_value: None } => {
                f.debug_tuple("Modified").field(&"<deleted>").finish()
            }
            TrieChangeStorageValue::Modified {
                new_value: Some(new_value),
            } => f
                .debug_tuple("Modified")
                .field(&hex::encode(new_value))
                .finish(),
        }
    }
}

/// Function execution has succeeded. Contains the return value of the call.
pub struct SuccessVirtualMachine(host::Finished);

impl SuccessVirtualMachine {
    /// Returns the value the called function has returned.
    pub fn value(&self) -> impl AsRef<[u8]> {
        self.0.value()
    }

    /// Turns the virtual machine back into a prototype.
    pub fn into_prototype(self) -> host::HostVmPrototype {
        self.0.into_prototype()
    }
}

impl fmt::Debug for SuccessVirtualMachine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SuccessVirtualMachine").finish()
    }
}

/// Error that can happen during the execution.
#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display("{detail}")]
pub struct Error {
    /// Exact error that happened.
    #[error(source)]
    pub detail: ErrorDetail,
    /// Prototype of the virtual machine that was passed through [`Config::virtual_machine`].
    pub prototype: host::HostVmPrototype,
}

/// Current state of the execution.
#[must_use]
pub enum RuntimeCall {
    /// Execution is over.
    Finished(Result<Success, Error>),
    /// Loading a storage value is required in order to continue.
    StorageGet(StorageGet),
    /// Obtaining the Merkle value of the closest descendant of a trie node is required in order
    /// to continue.
    ClosestDescendantMerkleValue(ClosestDescendantMerkleValue),
    /// Fetching the key that follows a given one is required in order to continue.
    NextKey(NextKey),
    /// Verifying whether a signature is correct is required in order to continue.
    SignatureVerification(SignatureVerification),
    /// Runtime would like to emit some log.
    LogEmit(LogEmit),
    /// Setting an offchain storage value is required in order to continue.
    ///
    /// Contrary to [`OffchainContext::StorageSet`], this variant is allowed to happen
    /// outside of offchain workers.
    OffchainStorageSet(OffchainStorageSet),
    /// Functions that can only be called within the context of an offchain worker.
    Offchain(OffchainContext),
}

impl RuntimeCall {
    /// Cancels execution of the virtual machine and returns back the prototype.
    pub fn into_prototype(self) -> host::HostVmPrototype {
        match self {
            RuntimeCall::Finished(Ok(inner)) => inner.virtual_machine.into_prototype(),
            RuntimeCall::Finished(Err(inner)) => inner.prototype,
            RuntimeCall::StorageGet(inner) => inner.inner.vm.into_prototype(),
            RuntimeCall::ClosestDescendantMerkleValue(inner) => inner.inner.vm.into_prototype(),
            RuntimeCall::NextKey(inner) => inner.inner.vm.into_prototype(),
            RuntimeCall::SignatureVerification(inner) => inner.inner.vm.into_prototype(),
            RuntimeCall::LogEmit(inner) => inner.inner.vm.into_prototype(),
            RuntimeCall::OffchainStorageSet(inner) => inner.inner.vm.into_prototype(),
            RuntimeCall::Offchain(inner) => inner.into_prototype(),
        }
    }
}

pub enum OffchainContext {
    /// Loading an offchain storage value is required in order to continue.
    StorageGet(OffchainStorageGet),
    /// Setting an offchain storage value is required in order to continue.
    ///
    /// Contrary to [`RuntimeCall::OffchainStorageSet`], this variant can only happen in offchain
    /// workers.
    StorageSet(OffchainStorageCompareSet),
    /// Timestamp for offchain worker.
    Timestamp(OffchainTimestamp),
    /// Random seed for offchain worker.
    RandomSeed(OffchainRandomSeed),
    /// Submit transaction from offchain worker.
    SubmitTransaction(OffchainSubmitTransaction),
}

impl OffchainContext {
    pub fn into_prototype(self) -> host::HostVmPrototype {
        match self {
            OffchainContext::StorageGet(inner) => inner.inner.vm.into_prototype(),
            OffchainContext::StorageSet(inner) => inner.inner.vm.into_prototype(),
            OffchainContext::Timestamp(inner) => inner.inner.vm.into_prototype(),
            OffchainContext::RandomSeed(inner) => inner.inner.vm.into_prototype(),
            OffchainContext::SubmitTransaction(inner) => inner.inner.vm.into_prototype(),
        }
    }
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet {
    inner: Inner,
}

impl StorageGet {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key(&self) -> impl AsRef<[u8]> {
        enum Three<A, B, C> {
            A(A),
            B(B),
            C(C),
        }

        impl<A: AsRef<[u8]>, B: AsRef<[u8]>, C: AsRef<[u8]>> AsRef<[u8]> for Three<A, B, C> {
            fn as_ref(&self) -> &[u8] {
                match self {
                    Three::A(a) => a.as_ref(),
                    Three::B(b) => b.as_ref(),
                    Three::C(c) => c.as_ref(),
                }
            }
        }

        match (&self.inner.vm, self.inner.root_calculation.as_ref()) {
            (host::HostVm::ExternalStorageGet(req), None) => Three::A(req.key()),
            (host::HostVm::ExternalStorageAppend(req), None) => Three::B(req.key()),
            (_, Some((_, trie_root_calculator::InProgress::StorageValue(value_request)))) => {
                // TODO: optimize?
                let key_nibbles = value_request.key().fold(Vec::new(), |mut a, b| {
                    a.extend_from_slice(b.as_ref());
                    a
                });
                debug_assert_eq!(key_nibbles.len() % 2, 0);
                Three::C(
                    trie::nibbles_to_bytes_suffix_extend(key_nibbles.into_iter())
                        .collect::<Vec<_>>(),
                )
            }

            // We only create a `StorageGet` if the state is one of the above.
            _ => unreachable!(),
        }
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        enum Three<A, B, C> {
            A(A),
            B(B),
            C(C),
        }

        impl<A: AsRef<[u8]>, B: AsRef<[u8]>, C: AsRef<[u8]>> AsRef<[u8]> for Three<A, B, C> {
            fn as_ref(&self) -> &[u8] {
                match self {
                    Three::A(a) => a.as_ref(),
                    Three::B(b) => b.as_ref(),
                    Three::C(c) => c.as_ref(),
                }
            }
        }

        match (&self.inner.vm, self.inner.root_calculation.as_ref()) {
            (host::HostVm::ExternalStorageGet(req), None) => req.child_trie().map(Three::A),
            (host::HostVm::ExternalStorageAppend(req), None) => req.child_trie().map(Three::B),
            (_, Some((child_trie, trie_root_calculator::InProgress::StorageValue(_)))) => {
                child_trie.as_ref().map(Three::C)
            }
            // We only create a `StorageGet` if the state is one of the above.
            _ => unreachable!(),
        }
    }

    /// Injects the corresponding storage value.
    pub fn inject_value(
        mut self,
        value: Option<(impl Iterator<Item = impl AsRef<[u8]>>, TrieEntryVersion)>,
    ) -> RuntimeCall {
        // TODO: update the implementation to not require the folding here
        let value = value.map(|(value, version)| {
            let value = value.fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });
            (value, version)
        });

        match (self.inner.vm, self.inner.root_calculation.take()) {
            (host::HostVm::ExternalStorageGet(req), None) => {
                // TODO: should actually report the offset and max_size in the API
                self.inner.vm = req.resume_full_value(value.as_ref().map(|(v, _)| &v[..]));
            }
            (host::HostVm::ExternalStorageAppend(req), None) => {
                // TODO: could be less overhead?
                let trie = self
                    .inner
                    .pending_storage_changes
                    .trie_diffs
                    .entry(req.child_trie().map(|ct| ct.as_ref().to_vec()))
                    .or_insert(storage_diff::TrieDiff::empty());

                // TODO: could be less overhead?
                let mut value = value.map(|(v, _)| v).unwrap_or_default();
                append_to_storage_value(&mut value, req.value().as_ref());
                trie.diff_insert(req.key().as_ref().to_vec(), value, ());

                self.inner.vm = req.resume();
            }
            (vm, Some((trie, trie_root_calculator::InProgress::StorageValue(value_request)))) => {
                self.inner.vm = vm;
                self.inner.root_calculation = Some((
                    trie,
                    value_request.inject_value(value.as_ref().map(|(v, vers)| (&v[..], *vers))),
                ));
            }

            // We only create a `StorageGet` if the state is one of the above.
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct NextKey {
    inner: Inner,

    /// If `Some`, ask for the key inside of this field rather than the one of `inner`.
    key_overwrite: Option<Vec<u8>>,

    /// Number of keys removed. Used only to implement clearing a prefix, otherwise stays at 0.
    keys_removed_so_far: u32,
}

impl NextKey {
    /// Returns the key whose next key must be passed back.
    pub fn key(&self) -> impl Iterator<Item = Nibble> {
        if let Some(key_overwrite) = &self.key_overwrite {
            return either::Left(trie::bytes_to_nibbles(key_overwrite.iter().copied()));
        }

        either::Right(
            match (&self.inner.vm, self.inner.root_calculation.as_ref()) {
                (host::HostVm::ExternalStorageNextKey(req), _) => {
                    either::Left(trie::bytes_to_nibbles(util::as_ref_iter(req.key())))
                }

                (_, Some((_, trie_root_calculator::InProgress::ClosestDescendant(req)))) => {
                    either::Right(req.key().flat_map(util::as_ref_iter))
                }

                // Note that in the case `ExternalStorageClearPrefix`, `key_overwrite` is
                // always `Some`.
                _ => unreachable!(),
            },
        )
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        enum Three<A, B, C> {
            A(A),
            B(B),
            C(C),
        }

        impl<A: AsRef<[u8]>, B: AsRef<[u8]>, C: AsRef<[u8]>> AsRef<[u8]> for Three<A, B, C> {
            fn as_ref(&self) -> &[u8] {
                match self {
                    Three::A(a) => a.as_ref(),
                    Three::B(b) => b.as_ref(),
                    Three::C(c) => c.as_ref(),
                }
            }
        }

        match (&self.inner.vm, self.inner.root_calculation.as_ref()) {
            (host::HostVm::ExternalStorageNextKey(req), _) => req.child_trie().map(Three::A),
            (_, Some((child_trie, _))) => child_trie.as_ref().map(Three::B),
            (host::HostVm::ExternalStorageClearPrefix(req), _) => req.child_trie().map(Three::C),
            _ => unreachable!(),
        }
    }

    /// If `true`, then the provided value must the one superior or equal to the requested key.
    /// If `false`, then the provided value must be strictly superior to the requested key.
    pub fn or_equal(&self) -> bool {
        (matches!(self.inner.vm, host::HostVm::ExternalStorageClearPrefix(_))
            && self.keys_removed_so_far == 0)
            || self.inner.root_calculation.is_some()
    }

    /// If `true`, then the search must include both branch nodes and storage nodes. If `false`,
    /// the search only covers storage nodes.
    pub fn branch_nodes(&self) -> bool {
        self.inner.root_calculation.is_some()
    }

    /// Returns the prefix the next key must start with. If the next key doesn't start with the
    /// given prefix, then `None` should be provided.
    pub fn prefix(&self) -> impl Iterator<Item = Nibble> {
        match (&self.inner.vm, self.inner.root_calculation.as_ref()) {
            (host::HostVm::ExternalStorageClearPrefix(req), _) => {
                either::Left(trie::bytes_to_nibbles(util::as_ref_iter(req.prefix())))
            }
            (_, Some(_)) => either::Right(either::Left(self.key())),
            _ => either::Right(either::Right(iter::empty())),
        }
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    /// Panics if the key passed as parameter doesn't start with the requested prefix.
    ///
    pub fn inject_key(mut self, key: Option<impl Iterator<Item = Nibble>>) -> RuntimeCall {
        match (self.inner.vm, self.inner.root_calculation.take()) {
            (host::HostVm::ExternalStorageNextKey(req), None) => {
                let key =
                    key.map(|key| trie::nibbles_to_bytes_suffix_extend(key).collect::<Vec<_>>());

                let trie = self
                    .inner
                    .pending_storage_changes
                    .trie_diffs
                    .get(&req.child_trie().map(|ct| ct.as_ref().to_owned())); // TODO: overhead

                let empty = storage_diff::TrieDiff::empty(); // TODO: weird
                let search = {
                    let req_key = req.key();
                    let requested_key = if let Some(key_overwrite) = &self.key_overwrite {
                        &key_overwrite[..]
                    } else {
                        req_key.as_ref()
                    };
                    // TODO: this code is a bit weird
                    trie.unwrap_or(&empty)
                        .storage_next_key(requested_key, key.as_deref(), false)
                };

                match search {
                    storage_diff::StorageNextKey::Found(k) => {
                        self.inner.vm = req.resume(k);
                    }
                    storage_diff::StorageNextKey::NextOf(next) => {
                        let key_overwrite = Some(next.to_owned());
                        self.inner.vm = host::HostVm::ExternalStorageNextKey(req);
                        return RuntimeCall::NextKey(NextKey {
                            inner: self.inner,
                            key_overwrite,
                            keys_removed_so_far: 0,
                        });
                    }
                }
            }

            (host::HostVm::ExternalStorageClearPrefix(req), None) => {
                // TODO: there's some trickiness regarding the behavior w.r.t keys only in the overlay; figure out

                if let Some(key) = key {
                    let key = trie::nibbles_to_bytes_suffix_extend(key).collect::<Vec<_>>();
                    assert!(key.starts_with(req.prefix().as_ref()));

                    // TODO: /!\ must clear keys from overlay as well

                    if req
                        .max_keys_to_remove()
                        .map_or(false, |max| self.keys_removed_so_far >= max)
                    {
                        self.inner.vm = req.resume(self.keys_removed_so_far, true);
                    } else {
                        // TODO: overhead
                        let trie = self
                            .inner
                            .pending_storage_changes
                            .trie_diffs
                            .entry(req.child_trie().map(|ct| ct.as_ref().to_vec()))
                            .or_insert(storage_diff::TrieDiff::empty());

                        trie.diff_insert_erase(key.clone(), ());
                        self.keys_removed_so_far += 1;
                        self.key_overwrite = Some(key); // TODO: might be expensive if lots of keys
                        self.inner.vm = req.into();

                        return RuntimeCall::NextKey(self);
                    }
                } else {
                    self.inner.vm = req.resume(self.keys_removed_so_far, false);
                }
            }

            (vm, Some((trie, trie_root_calculator::InProgress::ClosestDescendant(req)))) => {
                self.inner.vm = vm;
                self.inner.root_calculation = Some((trie, req.inject(key)));
            }

            // We only create a `NextKey` if the state is one of the above.
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Obtaining the Merkle value of the closest descendant of a trie node is required in order to
/// continue.
#[must_use]
pub struct ClosestDescendantMerkleValue {
    inner: Inner,
}

impl ClosestDescendantMerkleValue {
    /// Returns the key whose closest descendant Merkle value must be passed to
    /// [`ClosestDescendantMerkleValue::inject_merkle_value`].
    pub fn key(&self) -> impl Iterator<Item = Nibble> {
        let (_, trie_root_calculator::InProgress::ClosestDescendantMerkleValue(request)) =
            self.inner.root_calculation.as_ref().unwrap()
        else {
            unreachable!()
        };
        request.key().flat_map(util::as_ref_iter)
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        let (trie, trie_root_calculator::InProgress::ClosestDescendantMerkleValue(_)) =
            self.inner.root_calculation.as_ref().unwrap()
        else {
            unreachable!()
        };
        trie.as_ref()
    }

    /// Indicate that the value is unknown and resume the calculation.
    ///
    /// This function be used if you are unaware of the Merkle value. The algorithm will perform
    /// the calculation of this Merkle value manually, which takes more time.
    pub fn resume_unknown(mut self) -> RuntimeCall {
        let (trie, trie_root_calculator::InProgress::ClosestDescendantMerkleValue(request)) =
            self.inner.root_calculation.take().unwrap()
        else {
            unreachable!()
        };

        self.inner.root_calculation = Some((trie, request.resume_unknown()));
        self.inner.run()
    }

    /// Injects the corresponding Merkle value.
    ///
    /// `None` can be passed if there is no descendant or, in the case of a child trie read, in
    /// order to indicate that the child trie does not exist.
    pub fn inject_merkle_value(mut self, merkle_value: Option<&[u8]>) -> RuntimeCall {
        let (trie, trie_root_calculator::InProgress::ClosestDescendantMerkleValue(request)) =
            self.inner.root_calculation.take().unwrap()
        else {
            unreachable!()
        };

        self.inner.root_calculation = Some((
            trie,
            match merkle_value {
                Some(merkle_value) => request.inject_merkle_value(merkle_value),
                None => {
                    // We don't properly handle the situation where there's no descendant or no child
                    // trie.
                    request.resume_unknown()
                }
            },
        ));
        self.inner.run()
    }
}

/// Verifying whether a signature is correct is required in order to continue.
#[must_use]
pub struct SignatureVerification {
    inner: Inner,
}

impl SignatureVerification {
    /// Returns the message that the signature is expected to sign.
    pub fn message(&self) -> impl AsRef<[u8]> {
        match self.inner.vm {
            host::HostVm::SignatureVerification(ref sig) => sig.message(),
            _ => unreachable!(),
        }
    }

    /// Returns the signature.
    ///
    /// > **Note**: Be aware that this signature is untrusted input and might not be part of the
    /// >           set of valid signatures.
    pub fn signature(&self) -> impl AsRef<[u8]> {
        match self.inner.vm {
            host::HostVm::SignatureVerification(ref sig) => sig.signature(),
            _ => unreachable!(),
        }
    }

    /// Returns the public key the signature is against.
    ///
    /// > **Note**: Be aware that this public key is untrusted input and might not be part of the
    /// >           set of valid public keys.
    pub fn public_key(&self) -> impl AsRef<[u8]> {
        match self.inner.vm {
            host::HostVm::SignatureVerification(ref sig) => sig.public_key(),
            _ => unreachable!(),
        }
    }

    /// Verify the signature. Returns `true` if it is valid.
    pub fn is_valid(&self) -> bool {
        match self.inner.vm {
            host::HostVm::SignatureVerification(ref sig) => sig.is_valid(),
            _ => unreachable!(),
        }
    }

    /// Verify the signature and resume execution.
    pub fn verify_and_resume(mut self) -> RuntimeCall {
        match self.inner.vm {
            host::HostVm::SignatureVerification(sig) => self.inner.vm = sig.verify_and_resume(),
            _ => unreachable!(),
        }

        self.inner.run()
    }

    /// Resume the execution assuming that the signature is valid.
    ///
    /// > **Note**: You are strongly encouraged to call
    /// >           [`SignatureVerification::verify_and_resume`]. This function is meant to be
    /// >           used only in debugging situations.
    pub fn resume_success(mut self) -> RuntimeCall {
        match self.inner.vm {
            host::HostVm::SignatureVerification(sig) => self.inner.vm = sig.resume_success(),
            _ => unreachable!(),
        }

        self.inner.run()
    }

    /// Resume the execution assuming that the signature is invalid.
    ///
    /// > **Note**: You are strongly encouraged to call
    /// >           [`SignatureVerification::verify_and_resume`]. This function is meant to be
    /// >           used only in debugging situations.
    pub fn resume_failed(mut self) -> RuntimeCall {
        match self.inner.vm {
            host::HostVm::SignatureVerification(sig) => self.inner.vm = sig.resume_failed(),
            _ => unreachable!(),
        }

        self.inner.run()
    }
}

/// Loading an offchain storage value is required in order to continue.
#[must_use]
pub struct OffchainStorageGet {
    inner: Inner,
}

impl OffchainStorageGet {
    /// Returns the key whose value must be passed to [`OffchainStorageGet::inject_value`].
    pub fn key(&self) -> impl AsRef<[u8]> {
        match &self.inner.vm {
            host::HostVm::ExternalOffchainStorageGet(req) => req.key(),
            // We only create a `OffchainStorageGet` if the state is one of the above.
            _ => unreachable!(),
        }
    }

    /// Injects the corresponding storage value.
    pub fn inject_value(mut self, value: Option<impl AsRef<[u8]>>) -> RuntimeCall {
        match self.inner.vm {
            host::HostVm::ExternalOffchainStorageGet(req) => {
                self.inner.vm = req.resume(value.as_ref().map(|v| v.as_ref()));
            }
            // We only create a `OffchainStorageGet` if the state is one of the above.
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Setting the value of an offchain storage value is required.
#[must_use]
pub struct OffchainStorageSet {
    inner: Inner,
}

impl OffchainStorageSet {
    /// Returns the key whose value must be set.
    pub fn key(&self) -> impl AsRef<[u8]> {
        match &self.inner.vm {
            host::HostVm::Finished(_) => {
                self.inner
                    .offchain_storage_changes
                    .first_key_value()
                    .unwrap()
                    .0
            }
            // We only create a `OffchainStorageSet` if the state is one of the above.
            _ => unreachable!(),
        }
    }

    /// Returns the value to set.
    ///
    /// If `None` is returned, the key should be removed from the storage entirely.
    pub fn value(&self) -> Option<impl AsRef<[u8]>> {
        match &self.inner.vm {
            host::HostVm::Finished(_) => self
                .inner
                .offchain_storage_changes
                .first_key_value()
                .unwrap()
                .1
                .as_ref(),
            // We only create a `OffchainStorageSet` if the state is one of the above.
            _ => unreachable!(),
        }
    }

    /// Resumes execution after having set the value.
    pub fn resume(mut self) -> RuntimeCall {
        match self.inner.vm {
            host::HostVm::Finished(_) => {
                self.inner.offchain_storage_changes.pop_first();
            }
            // We only create a `OffchainStorageSet` if the state is one of the above.
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Setting the value of an offchain storage value is required.
#[must_use]
pub struct OffchainStorageCompareSet {
    inner: Inner,
}

impl OffchainStorageCompareSet {
    /// Returns the key whose value must be set.
    pub fn key(&self) -> impl AsRef<[u8]> {
        match &self.inner.vm {
            host::HostVm::ExternalOffchainStorageSet(req) => either::Left(req.key()),
            host::HostVm::Finished(_) => either::Right(
                self.inner
                    .offchain_storage_changes
                    .first_key_value()
                    .unwrap()
                    .0,
            ),
            // We only create a `OffchainStorageSet` if the state is one of the above.
            _ => unreachable!(),
        }
    }

    /// Returns the value to set.
    ///
    /// If `None` is returned, the key should be removed from the storage entirely.
    pub fn value(&self) -> Option<impl AsRef<[u8]>> {
        match &self.inner.vm {
            host::HostVm::ExternalOffchainStorageSet(req) => req.value().map(either::Left),
            host::HostVm::Finished(_) => self
                .inner
                .offchain_storage_changes
                .first_key_value()
                .unwrap()
                .1
                .as_ref()
                .map(either::Right),

            // We only create a `OffchainStorageSet` if the state is one of the above.
            _ => unreachable!(),
        }
    }

    /// Returns the value the current value should be compared against. The operation is a no-op if they don't compare equal.
    pub fn old_value(&self) -> Option<impl AsRef<[u8]>> {
        match &self.inner.vm {
            host::HostVm::ExternalOffchainStorageSet(req) => req.old_value(),
            host::HostVm::Finished(_) => None,
            // We only create a `OffchainStorageSet` if the state is one of the above.
            _ => unreachable!(),
        }
    }

    /// Resumes execution after having set the value. Must indicate whether a value was written.
    pub fn resume(mut self, replaced: bool) -> RuntimeCall {
        match self.inner.vm {
            host::HostVm::ExternalOffchainStorageSet(req) => {
                self.inner.vm = req.resume(replaced);
            }
            host::HostVm::Finished(_) => {
                self.inner.offchain_storage_changes.pop_first();
            }
            // We only create a `OffchainStorageSet` if the state is one of the above.
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Providing the current UNIX timestamp is required in order to continue.
#[must_use]
pub struct OffchainTimestamp {
    inner: Inner,
}

impl OffchainTimestamp {
    /// Resume execution by providing the current UNIX timestamp.
    pub fn inject_timestamp(mut self, value: u64) -> RuntimeCall {
        match self.inner.vm {
            host::HostVm::OffchainTimestamp(req) => {
                self.inner.vm = req.resume(value);
            }
            // We only create a `OffchainTimestamp` if the state is one of the above.
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Providing a random number is required in order to continue.
#[must_use]
pub struct OffchainRandomSeed {
    inner: Inner,
}

impl OffchainRandomSeed {
    /// Resume execution by providing a random number.
    pub fn inject_random_seed(mut self, value: [u8; 32]) -> RuntimeCall {
        match self.inner.vm {
            host::HostVm::OffchainRandomSeed(req) => {
                self.inner.vm = req.resume(value);
            }
            // We only create a `OffchainRandomSeed` if the state is one of the above.
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// The runtime requests submitting a transaction.
#[must_use]
pub struct OffchainSubmitTransaction {
    inner: Inner,
}

impl OffchainSubmitTransaction {
    /// Returns the SCALE-encoded transaction that must be submitted.
    pub fn transaction(&self) -> impl AsRef<[u8]> {
        match &self.inner.vm {
            host::HostVm::OffchainSubmitTransaction(req) => req.transaction(),
            // We only create a `OffchainSubmitTransaction` if the state is one of the above.
            _ => unreachable!(),
        }
    }

    /// Resume execution. Must indicate whether the transaction has been successfully submitted.
    pub fn resume(mut self, success: bool) -> RuntimeCall {
        match self.inner.vm {
            host::HostVm::OffchainSubmitTransaction(req) => {
                self.inner.vm = req.resume(success);
            }
            // We only create a `OffchainSubmitTransaction` if the state is one of the above.
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Report about a log entry being emitted.
///
/// Use [`LogEmit::info`] to obtain what must be printed.
#[must_use]
pub struct LogEmit {
    inner: Inner,
}

impl LogEmit {
    /// Returns the data that the runtime would like to print.
    pub fn info(&'_ self) -> LogEmitInfo<'_> {
        match &self.inner.vm {
            host::HostVm::LogEmit(req) => req.info(),
            // We only create a `LogEmit` if the inner state is `LogEmit`.
            _ => unreachable!(),
        }
    }

    /// Resume execution.
    pub fn resume(mut self) -> RuntimeCall {
        match self.inner.vm {
            host::HostVm::LogEmit(req) => {
                self.inner.vm = req.resume();
            }
            // We only create a `LogEmit` if the inner state is `LogEmit`.
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Implementation detail of the execution. Shared by all the variants of [`RuntimeCall`]
/// other than [`RuntimeCall::Finished`].
struct Inner {
    /// Virtual machine running the call.
    vm: host::HostVm,

    /// Pending changes to the storage that this execution performs.
    pending_storage_changes: PendingStorageChanges,

    /// Contains a copy of [`Inner::pending_storage_changes`] at the time when the transaction
    /// started. When the storage transaction ends, either the entry is silently discarded (to
    /// commit), or is written over [`Inner::pending_storage_changes`] (to rollback).
    ///
    /// Contains a `Vec` in case transactions are stacked.
    transactions_stack: Vec<PendingStorageChanges>,

    /// State trie version indicated by the runtime. All the storage changes that are performed
    /// use this version.
    state_trie_version: TrieEntryVersion,

    /// Pending changes to the off-chain storage that this execution performs.
    offchain_storage_changes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,

    /// Trie root calculation in progress. Contains the trie whose root is being calculated
    /// (`Some` for a child trie or `None` for the main trie) and the calculation state machine.
    root_calculation: Option<(Option<Vec<u8>>, trie_root_calculator::InProgress)>,

    /// Value provided by [`Config::max_log_level`].
    max_log_level: u32,

    /// See [`Config::calculate_trie_changes`].
    calculate_trie_changes: bool,
}

/// See [`Inner::pending_storage_changes`].
#[derive(Clone)]
struct PendingStorageChanges {
    /// For each trie, the values that have been written to it.
    trie_diffs: hashbrown::HashMap<Option<Vec<u8>>, storage_diff::TrieDiff, fnv::FnvBuildHasher>,

    /// List of tries (`None` for the main trie and `Some` for child tries) whose root hash must
    /// be recalculated (and for child tries stored into the main trie).
    /// This is necessary in order to populate [`PendingStorageChanges::tries_changes`].
    stale_child_tries_root_hashes: hashbrown::HashSet<Option<Vec<u8>>, fnv::FnvBuildHasher>,

    /// Changes to the trie nodes of all the tries.
    tries_changes: BTreeMap<(Option<Vec<u8>>, Vec<Nibble>), PendingStorageChangesTrieNode>,

    /// Changes to the off-chain storage committed by on-chain transactions.
    offchain_storage_changes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

/// See [`PendingStorageChanges::tries_changes`].
#[derive(Clone)]
enum PendingStorageChangesTrieNode {
    Removed,
    InsertUpdate {
        new_merkle_value: Vec<u8>,
        partial_key: Vec<Nibble>,
        children_merkle_values: Box<[Option<Vec<u8>>; 16]>,
    },
}

/// Writing and reading keys the main trie under this prefix obeys special rules.
const CHILD_STORAGE_SPECIAL_PREFIX: &[u8] = b":child_storage:";

impl Inner {
    /// Continues the execution.
    fn run(mut self) -> RuntimeCall {
        loop {
            match self.root_calculation.take() {
                None => {}
                Some((trie, trie_root_calculator::InProgress::ClosestDescendant(calc_req))) => {
                    self.root_calculation = Some((
                        trie,
                        trie_root_calculator::InProgress::ClosestDescendant(calc_req),
                    ));
                    return RuntimeCall::NextKey(NextKey {
                        inner: self,
                        key_overwrite: None,
                        keys_removed_so_far: 0,
                    });
                }
                Some((trie, trie_root_calculator::InProgress::StorageValue(calc_req))) => {
                    if calc_req
                        .key()
                        .fold(0, |count, slice| count + slice.as_ref().len())
                        % 2
                        == 0
                    {
                        self.root_calculation = Some((
                            trie,
                            trie_root_calculator::InProgress::StorageValue(calc_req),
                        ));
                        return RuntimeCall::StorageGet(StorageGet { inner: self });
                    } else {
                        // If the number of nibbles in the key is uneven, we are sure that
                        // there exists no storage value.
                        self.root_calculation = Some((trie, calc_req.inject_value(None)));
                        continue;
                    }
                }
                Some((
                    trie,
                    trie_root_calculator::InProgress::ClosestDescendantMerkleValue(calc_req),
                )) => {
                    self.root_calculation = Some((
                        trie,
                        trie_root_calculator::InProgress::ClosestDescendantMerkleValue(calc_req),
                    ));
                    return RuntimeCall::ClosestDescendantMerkleValue(
                        ClosestDescendantMerkleValue { inner: self },
                    );
                }
                Some((trie, trie_root_calculator::InProgress::TrieNodeInsertUpdateEvent(ev))) => {
                    self.pending_storage_changes.tries_changes.insert(
                        (trie.clone(), ev.key_as_vec()),
                        PendingStorageChangesTrieNode::InsertUpdate {
                            new_merkle_value: ev.merkle_value().to_owned(),
                            partial_key: ev.partial_key().to_owned(),
                            children_merkle_values: TryFrom::try_from(
                                ev.children_merkle_values()
                                    .map(|mv| mv.map(|mv| mv.to_owned()))
                                    .collect::<Vec<_>>()
                                    .into_boxed_slice(),
                            )
                            .unwrap(),
                        },
                    );

                    self.root_calculation = Some((trie, ev.resume()));
                    continue;
                }
                Some((trie, trie_root_calculator::InProgress::TrieNodeRemoveEvent(ev))) => {
                    self.pending_storage_changes.tries_changes.insert(
                        (trie.clone(), ev.key_as_vec()),
                        PendingStorageChangesTrieNode::Removed,
                    );

                    self.root_calculation = Some((trie, ev.resume()));
                    continue;
                }
                Some((trie, trie_root_calculator::InProgress::Finished { trie_root_hash })) => {
                    self.pending_storage_changes
                        .stale_child_tries_root_hashes
                        .remove(&trie);

                    // If we've finished calculating a child trie, update its entry in the
                    // main trie.
                    if let Some(child_trie) = &trie {
                        let main_trie_key = trie::default_child_trie_root_key(child_trie);

                        if trie_root_hash != trie::EMPTY_BLAKE2_TRIE_MERKLE_VALUE {
                            self.pending_storage_changes
                                .trie_diffs
                                .entry(None)
                                .or_default()
                                .diff_insert(main_trie_key, trie_root_hash.to_vec(), ());
                        } else {
                            self.pending_storage_changes
                                .trie_diffs
                                .entry(None)
                                .or_default()
                                .diff_insert_erase(main_trie_key, ());
                        }

                        self.pending_storage_changes
                            .stale_child_tries_root_hashes
                            .insert(None);
                    }

                    // Resume the VM execution only if the calculated trie is the one that was
                    // requested by the runtime.
                    if let host::HostVm::ExternalStorageRoot(req) = self.vm {
                        // Code below is a bit convoluted due to borrow checker issues.
                        let trie_match = match (req.child_trie(), trie) {
                            (None, None) => true,
                            (Some(a), Some(b)) if a.as_ref() == b => true,
                            _ => false,
                        };
                        if trie_match {
                            self.vm = req.resume(&trie_root_hash);
                        } else {
                            self.vm = host::HostVm::ExternalStorageRoot(req);
                        }
                    }

                    continue;
                }
            }

            // If the runtime requests the trie root hash of the main trie, we must first
            // recalculate the trie root hash of every single child trie that has been modified
            // since the previous trie root hash calculation.
            // This is also done if execution is finished, in order for the diff provided as
            // output to be accurate.
            {
                let trie_to_flush: Option<Option<either::Either<_, &[u8]>>> = match &self.vm {
                    host::HostVm::Finished(_) => {
                        if let Some(child_trie) = self
                            .pending_storage_changes
                            .stale_child_tries_root_hashes
                            .iter()
                            .find_map(|ct| ct.as_ref())
                        {
                            Some(Some(either::Right(child_trie)))
                        } else if self
                            .pending_storage_changes
                            .stale_child_tries_root_hashes
                            .contains(&None)
                            && self.calculate_trie_changes
                        {
                            Some(None)
                        } else {
                            None
                        }
                    }
                    host::HostVm::ExternalStorageRoot(req) => {
                        if let Some(child_trie) = req.child_trie() {
                            Some(Some(either::Left(child_trie)))
                        } else {
                            // Find any child trie in `pending_storage_changes`. If `None` is
                            // found, calculate the main trie.
                            // It is important to calculate the child tries before the main tries.
                            Some(
                                self.pending_storage_changes
                                    .stale_child_tries_root_hashes
                                    .iter()
                                    .find_map(|ct| ct.as_ref())
                                    .map(|t| either::Right(&t[..])),
                            )
                        }
                    }
                    _ => None,
                };

                if let Some(trie_to_flush) = trie_to_flush {
                    // Remove from `tries_changes` all the changes concerning this trie.
                    // TODO: O(n) and generally not optimized
                    {
                        let to_remove = self
                            .pending_storage_changes
                            .tries_changes
                            .range((
                                ops::Bound::Included((
                                    trie_to_flush
                                        .as_ref()
                                        .map(|t| AsRef::<[u8]>::as_ref(t).to_owned()),
                                    Vec::new(),
                                )),
                                ops::Bound::Unbounded,
                            ))
                            .take_while(|((ct, _), _)| {
                                ct.as_ref().map(|ct| &ct[..])
                                    == trie_to_flush.as_ref().map(AsRef::<[u8]>::as_ref)
                            })
                            .map(|(k, _)| k.clone())
                            .collect::<Vec<_>>();
                        for to_remove in to_remove {
                            self.pending_storage_changes
                                .tries_changes
                                .remove(&to_remove);
                        }
                    }

                    // TODO: don't clone?
                    let diff = match self
                        .pending_storage_changes
                        .trie_diffs
                        .get(&trie_to_flush.as_ref().map(|t| AsRef::<[u8]>::as_ref(&t).to_owned()))  // TODO: overhead
                    {
                        None => storage_diff::TrieDiff::empty(),
                        Some(diff) => diff.clone(),
                    };

                    debug_assert!(self.root_calculation.is_none()); // `Some` handled above.
                    self.root_calculation = Some((
                        trie_to_flush.map(|t| AsRef::<[u8]>::as_ref(&t).to_owned()),
                        trie_root_calculator::trie_root_calculator(trie_root_calculator::Config {
                            diff,
                            diff_trie_entries_version: self.state_trie_version,
                            max_trie_recalculation_depth_hint: 16, // TODO: ?!
                        }),
                    ));
                    continue;
                }
            }

            if matches!(self.vm, host::HostVm::Finished(_))
                && !self.offchain_storage_changes.is_empty()
            {
                return RuntimeCall::OffchainStorageSet(OffchainStorageSet { inner: self });
            }

            match self.vm {
                host::HostVm::ReadyToRun(r) => self.vm = r.run(),

                host::HostVm::Error { error, prototype } => {
                    return RuntimeCall::Finished(Err(Error {
                        detail: error,
                        prototype,
                    }));
                }

                host::HostVm::Finished(finished) => {
                    debug_assert!(self.transactions_stack.is_empty()); // Guaranteed by `host`.
                    debug_assert!(
                        self.pending_storage_changes
                            .stale_child_tries_root_hashes
                            .is_empty()
                            || (!self.calculate_trie_changes
                                && self
                                    .pending_storage_changes
                                    .stale_child_tries_root_hashes
                                    .len()
                                    == 1
                                && self
                                    .pending_storage_changes
                                    .stale_child_tries_root_hashes
                                    .contains(&None))
                    );
                    debug_assert!(self.offchain_storage_changes.is_empty());

                    return RuntimeCall::Finished(Ok(Success {
                        virtual_machine: SuccessVirtualMachine(finished),
                        storage_changes: StorageChanges {
                            inner: self.pending_storage_changes,
                            calculate_trie_changes: self.calculate_trie_changes,
                        },
                        state_trie_version: self.state_trie_version,
                    }));
                }

                host::HostVm::ExternalStorageGet(req) => {
                    let diff_search = self
                        .pending_storage_changes
                        .trie_diffs
                        .get(&req.child_trie().map(|ct| ct.as_ref().to_vec()))
                        .and_then(|diff| diff.diff_get(req.key().as_ref()));

                    if let Some((value_in_diff, _)) = diff_search {
                        self.vm = req.resume_full_value(value_in_diff);
                    } else {
                        self.vm = req.into();
                        return RuntimeCall::StorageGet(StorageGet { inner: self });
                    }
                }

                host::HostVm::ExternalStorageSet(req) => {
                    // Any attempt at writing a key that starts with `CHILD_STORAGE_SPECIAL_PREFIX`
                    // is silently ignored, as per spec.
                    if req.child_trie().is_none()
                        && req.key().as_ref().starts_with(CHILD_STORAGE_SPECIAL_PREFIX)
                    {
                        self.vm = req.resume();
                        continue;
                    }

                    // TOOD: to_owned overhead
                    self.pending_storage_changes
                        .stale_child_tries_root_hashes
                        .insert(req.child_trie().map(|ct| ct.as_ref().to_owned()));

                    let trie = self
                        .pending_storage_changes
                        .trie_diffs
                        .entry(req.child_trie().map(|ct| ct.as_ref().to_vec()))
                        .or_insert(storage_diff::TrieDiff::empty());

                    if let Some(value) = req.value() {
                        trie.diff_insert(req.key().as_ref(), value.as_ref(), ());
                    } else {
                        trie.diff_insert_erase(req.key().as_ref(), ());
                    }

                    self.vm = req.resume()
                }

                host::HostVm::ExternalStorageAppend(req) => {
                    // Any attempt at writing a key that starts with `CHILD_STORAGE_SPECIAL_PREFIX`
                    // is silently ignored, as per spec.
                    if req.child_trie().is_none()
                        && req.key().as_ref().starts_with(CHILD_STORAGE_SPECIAL_PREFIX)
                    {
                        self.vm = req.resume();
                        continue;
                    }

                    // TOOD: to_owned overhead
                    self.pending_storage_changes
                        .stale_child_tries_root_hashes
                        .insert(req.child_trie().map(|ct| ct.as_ref().to_owned()));

                    let trie = self
                        .pending_storage_changes
                        .trie_diffs
                        .entry(req.child_trie().map(|ct| ct.as_ref().to_vec()))
                        .or_insert(storage_diff::TrieDiff::empty());

                    let current_value = trie.diff_get(req.key().as_ref()).map(|(v, _)| v);

                    if let Some(current_value) = current_value {
                        let mut current_value = current_value.unwrap_or_default().to_vec();
                        append_to_storage_value(&mut current_value, req.value().as_ref());
                        trie.diff_insert(req.key().as_ref().to_vec(), current_value, ());
                        self.vm = req.resume();
                    } else {
                        self.vm = req.into();
                        return RuntimeCall::StorageGet(StorageGet { inner: self });
                    }
                }

                host::HostVm::ExternalStorageClearPrefix(req) => {
                    // Any attempt at clear a prefix that "intersects" (see code) with
                    // `CHILD_STORAGE_SPECIAL_PREFIX` is silently ignored, as per spec.
                    if req.child_trie().is_none()
                        && CHILD_STORAGE_SPECIAL_PREFIX.starts_with(req.prefix().as_ref())
                    {
                        self.vm = req.resume(0, false); // TODO: what's the correct return value for `some_keys_remain`?
                        continue;
                    }

                    // TODO: consider doing this only if at least one key was actually removed
                    // TOOD: to_owned overhead
                    self.pending_storage_changes
                        .stale_child_tries_root_hashes
                        .insert(req.child_trie().map(|ct| ct.as_ref().to_owned()));

                    let prefix = req.prefix().as_ref().to_owned();
                    self.vm = req.into();
                    return RuntimeCall::NextKey(NextKey {
                        inner: self,
                        key_overwrite: Some(prefix),
                        keys_removed_so_far: 0,
                    });
                }

                host::HostVm::ExternalStorageRoot(_) => {
                    // Handled above.
                    unreachable!()
                }

                host::HostVm::ExternalStorageNextKey(req) => {
                    self.vm = req.into();
                    return RuntimeCall::NextKey(NextKey {
                        inner: self,
                        key_overwrite: None,
                        keys_removed_so_far: 0,
                    });
                }

                host::HostVm::ExternalOffchainIndexSet(req) => {
                    self.pending_storage_changes
                        .offchain_storage_changes
                        .insert(
                            req.key().as_ref().to_vec(),
                            req.value().map(|v| v.as_ref().to_vec()),
                        );

                    self.vm = req.resume();
                }

                host::HostVm::ExternalOffchainStorageGet(req) => {
                    let current_value = self.offchain_storage_changes.get(req.key().as_ref());
                    match current_value {
                        Some(value) => self.vm = req.resume(value.as_ref().map(|v| &v[..])),
                        None => {
                            self.vm = req.into();
                            return RuntimeCall::Offchain(OffchainContext::StorageGet(
                                OffchainStorageGet { inner: self },
                            ));
                        }
                    }
                }

                host::HostVm::ExternalOffchainStorageSet(req) => {
                    self.vm = req.into();
                    return RuntimeCall::Offchain(OffchainContext::StorageSet(
                        OffchainStorageCompareSet { inner: self },
                    ));
                }

                host::HostVm::SignatureVerification(req) => {
                    self.vm = req.into();
                    return RuntimeCall::SignatureVerification(SignatureVerification {
                        inner: self,
                    });
                }

                host::HostVm::CallRuntimeVersion(req) => {
                    // TODO: make the user execute this ; see https://github.com/paritytech/smoldot/issues/144
                    // The code below compiles the provided WebAssembly runtime code, which is a
                    // relatively expensive operation (in the order of milliseconds).
                    // While it could be tempting to use a system cache, this function is expected
                    // to be called only right before runtime upgrades. Considering that runtime
                    // upgrades are quite uncommon and that a caching system is rather non-trivial
                    // to set up, the approach of recompiling every single time is preferred here.
                    // TODO: number of heap pages?! we use the default here, but not sure whether that's correct or if we have to take the current heap pages
                    let vm_prototype = match host::HostVmPrototype::new(host::Config {
                        module: req.wasm_code(),
                        heap_pages: executor::DEFAULT_HEAP_PAGES,
                        exec_hint: vm::ExecHint::ValidateAndExecuteOnce,
                        allow_unresolved_imports: false, // TODO: what is a correct value here?
                    }) {
                        Ok(w) => w,
                        Err(_) => {
                            self.vm = req.resume(Err(()));
                            continue;
                        }
                    };

                    self.vm = req.resume(Ok(vm_prototype.runtime_version().as_ref()));
                }

                host::HostVm::StartStorageTransaction(tx) => {
                    // TODO: this cloning is very expensive, but providing a more optimized implementation is very complicated
                    self.transactions_stack
                        .push(self.pending_storage_changes.clone());
                    self.vm = tx.resume();
                }

                host::HostVm::EndStorageTransaction { resume, rollback } => {
                    // The inner implementation guarantees that a storage transaction can only
                    // end if it has earlier been started.
                    debug_assert!(!self.transactions_stack.is_empty());
                    let rollback_diff = self.transactions_stack.pop().unwrap();

                    if rollback {
                        self.pending_storage_changes = rollback_diff;
                    }

                    self.vm = resume.resume();
                }

                host::HostVm::GetMaxLogLevel(resume) => {
                    self.vm = resume.resume(self.max_log_level);
                }

                host::HostVm::LogEmit(req) => {
                    self.vm = req.into();
                    return RuntimeCall::LogEmit(LogEmit { inner: self });
                }
                host::HostVm::OffchainTimestamp(req) => {
                    self.vm = req.into();
                    return RuntimeCall::Offchain(OffchainContext::Timestamp(OffchainTimestamp {
                        inner: self,
                    }));
                }
                host::HostVm::OffchainRandomSeed(req) => {
                    self.vm = req.into();
                    return RuntimeCall::Offchain(OffchainContext::RandomSeed(
                        OffchainRandomSeed { inner: self },
                    ));
                }
                host::HostVm::OffchainSubmitTransaction(req) => {
                    self.vm = req.into();
                    return RuntimeCall::Offchain(OffchainContext::SubmitTransaction(
                        OffchainSubmitTransaction { inner: self },
                    ));
                }
            }
        }
    }
}

/// Performs the action described by [`host::HostVm::ExternalStorageAppend`] on an
/// encoded storage value.
fn append_to_storage_value(value: &mut Vec<u8>, to_add: &[u8]) {
    let (curr_len, curr_len_encoded_size) =
        match util::nom_scale_compact_usize::<nom::error::Error<&[u8]>>(value) {
            Ok((rest, l)) => (l, value.len() - rest.len()),
            Err(_) => {
                value.clear();
                value.reserve(to_add.len() + 1);
                value.extend_from_slice(util::encode_scale_compact_usize(1).as_ref());
                value.extend_from_slice(to_add);
                return;
            }
        };

    // Note: we use `checked_add`, as it is possible that the storage entry erroneously starts
    // with `u64::MAX`.
    let new_len = match curr_len.checked_add(1) {
        Some(l) => l,
        None => {
            value.clear();
            value.reserve(to_add.len() + 1);
            value.extend_from_slice(util::encode_scale_compact_usize(1).as_ref());
            value.extend_from_slice(to_add);
            return;
        }
    };

    let new_len_encoded = util::encode_scale_compact_usize(new_len);

    let new_len_encoded_size = new_len_encoded.as_ref().len();
    debug_assert!(
        new_len_encoded_size == curr_len_encoded_size
            || new_len_encoded_size == curr_len_encoded_size + 1
    );

    value.reserve(to_add.len() + (new_len_encoded_size - curr_len_encoded_size));

    // Since `new_len_encoded_size` is either equal to `curr_len_encoded_size` or equal to
    // `curr_len_encoded_size + 1`, we simply use `insert(0, _)` in the latter case.
    if new_len_encoded_size != curr_len_encoded_size {
        value.insert(0, 0);
    }

    value[..new_len_encoded_size].copy_from_slice(new_len_encoded.as_ref());
    value.extend_from_slice(to_add);
}
