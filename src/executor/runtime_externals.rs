// Substrate-lite
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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

//! Builds upon the functionnalities of [`externals::ExternalsVm`] module and implements some of
//! the external calls.
//!
//! In details, this module:
//!
//! - Keeps track of the changes to the storage and offchain storage made by the execution, and
//!   provides them at the end. Any storage access takes into account the intermediary list of
//!   changes.
//! - Keeps track of the logs generated by the call and concatenates them into a [`String`].
//! - Automatically handles some externalities, such as calculating the Merkle root or storage
//!   transactions.

// TODO: more docs

use crate::{
    executor::{externals, vm},
    trie::calculate_root,
};

use alloc::{string::String, vec::Vec};
use core::{fmt, iter, slice};
use hashbrown::{HashMap, HashSet};

/// Configuration for [`run`].
pub struct Config<'a, TParams> {
    /// Virtual machine to be run.
    pub virtual_machine: externals::ExternalsVmPrototype,

    /// Name of the function to be called.
    pub function_to_call: &'a str,

    /// Parameter of the call, as an iterator of bytes. The concatenation of bytes forms the
    /// actual input.
    pub parameter: TParams,

    /// Optional cache of the trie root calculation to use. Must match the state of the storage at
    /// the start of the call, including [`Config::storage_top_trie_changes`].
    pub top_trie_root_calculation_cache: Option<calculate_root::CalculationCache>,

    /// Initial state of [`Success::storage_top_trie_changes`]. The changes made during this
    /// execution will be pushed over the value in this field.
    pub storage_top_trie_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,

    /// Initial state of [`Success::offchain_storage_changes`]. The changes made during this
    /// execution will be pushed over the value in this field.
    pub offchain_storage_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
}

/// Start running the WebAssembly virtual machine.
pub fn run(
    config: Config<impl Iterator<Item = impl AsRef<[u8]>> + Clone>,
) -> Result<RuntimeExternalsVm, externals::NewErr> {
    Ok(Inner {
        vm: config
            .virtual_machine
            .run_vectored(config.function_to_call, config.parameter)?
            .into(),
        top_trie_changes: config.storage_top_trie_changes,
        offchain_storage_changes: config.offchain_storage_changes,
        top_trie_root_calculation_cache: Some(
            config.top_trie_root_calculation_cache.unwrap_or_default(),
        ),
        root_calculation: None,
        logs: String::new(),
    }
    .run())
}

/// Execution is successful.
#[derive(Debug)]
pub struct Success {
    /// Contains the output value of the runtime, and the virtual machine that was passed at
    /// initialization.
    pub virtual_machine: SuccessVirtualMachine,
    /// List of changes to the storage top trie that the block performs.
    pub storage_top_trie_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
    /// List of changes to the offchain storage that this block performs.
    pub offchain_storage_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
    /// Cache used for calculating the top trie root.
    pub top_trie_root_calculation_cache: calculate_root::CalculationCache,
    /// Concatenation of all the log messages printed by the runtime.
    pub logs: String,
}

/// Function execution has succeeded. Contains the return value of the call.
pub struct SuccessVirtualMachine(externals::Finished);

impl SuccessVirtualMachine {
    /// Returns the value the called function has returned.
    pub fn value(&self) -> &[u8] {
        self.0.value()
    }

    /// Turns the virtual machine back into a prototype.
    pub fn into_prototype(self) -> externals::ExternalsVmPrototype {
        self.0.into_prototype()
    }
}

impl fmt::Debug for SuccessVirtualMachine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SuccessVirtualMachine").finish()
    }
}

/// Error that can happen during the execution.
#[derive(Debug, Clone, derive_more::Display)]
pub enum Error {
    /// Error while executing the Wasm virtual machine.
    #[display(fmt = "Error while executing Wasm VM: {}\n{:?}", error, logs)]
    WasmVm {
        /// Error that happened.
        error: externals::Error,
        /// Concatenation of all the log messages printed by the runtime.
        logs: String,
    },
    /// Size of the logs generated by the runtime exceeds the limit.
    LogsTooLong,
}

/// Current state of the execution.
#[must_use]
pub enum RuntimeExternalsVm {
    /// Execution is over.
    Finished(Result<Success, Error>),
    /// Loading a storage value is required in order to continue.
    StorageGet(StorageGet),
    /// Fetching the list of keys with a given prefix is required in order to continue.
    PrefixKeys(PrefixKeys),
    /// Fetching the key that follows a given one is required in order to continue.
    NextKey(NextKey),
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet {
    inner: Inner,
}

impl StorageGet {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key<'a>(&'a self) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
        match &self.inner.vm {
            externals::ExternalsVm::ExternalStorageGet(req) => {
                either::Either::Left(iter::once(either::Either::Left(req.key())))
            }
            externals::ExternalsVm::ExternalStorageAppend(req) => {
                either::Either::Left(iter::once(either::Either::Left(req.key())))
            }

            externals::ExternalsVm::ExternalStorageRoot(_) => {
                if let calculate_root::RootMerkleValueCalculation::StorageValue(value_request) =
                    self.inner.root_calculation.as_ref().unwrap()
                {
                    struct One(u8);
                    impl AsRef<[u8]> for One {
                        fn as_ref(&self) -> &[u8] {
                            slice::from_ref(&self.0)
                        }
                    }
                    either::Either::Right(value_request.key().map(One).map(either::Either::Right))
                } else {
                    // We only create a `StorageGet` if the state is `StorageValue`.
                    panic!()
                }
            }

            externals::ExternalsVm::ExternalStorageChangesRoot(_) => {
                either::Either::Left(iter::once(either::Either::Left(&b":changes_trie"[..])))
            }

            // We only create a `StorageGet` if the state is one of the above.
            _ => unreachable!(),
        }
    }

    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    ///
    /// This method is a shortcut for calling `key` and concatenating the returned slices.
    pub fn key_as_vec(&self) -> Vec<u8> {
        self.key().fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        })
    }

    /// Injects the corresponding storage value.
    // TODO: `value` parameter should be something like `Iterator<Item = impl AsRef<[u8]>`
    pub fn inject_value(mut self, value: Option<&[u8]>) -> RuntimeExternalsVm {
        match self.inner.vm {
            externals::ExternalsVm::ExternalStorageGet(req) => {
                // TODO: should actually report the offset and max_size in the API
                self.inner.vm = req.resume_full_value(value);
            }
            externals::ExternalsVm::ExternalStorageAppend(req) => {
                let mut value = value.map(|v| v.to_vec()).unwrap_or_default();
                // TODO: could be less overhead?
                append_to_storage_value(&mut value, req.value());
                self.inner
                    .top_trie_changes
                    .insert(req.key().to_vec(), Some(value.clone()));
                self.inner.vm = req.resume();
            }
            externals::ExternalsVm::ExternalStorageRoot(_) => {
                if let calculate_root::RootMerkleValueCalculation::StorageValue(value_request) =
                    self.inner.root_calculation.take().unwrap()
                {
                    self.inner.root_calculation = Some(value_request.inject(value));
                } else {
                    // We only create a `StorageGet` if the state is `StorageValue`.
                    panic!()
                }
            }
            externals::ExternalsVm::ExternalStorageChangesRoot(req) => {
                if value.is_none() {
                    self.inner.vm = req.resume(None);
                } else {
                    // TODO: this is probably one of the most complicated things to implement
                    todo!()
                }
            }

            // We only create a `StorageGet` if the state is one of the above.
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Fetching the list of keys with a given prefix is required in order to continue.
#[must_use]
pub struct PrefixKeys {
    inner: Inner,
}

impl PrefixKeys {
    /// Returns the prefix whose keys to load.
    pub fn prefix(&self) -> &[u8] {
        match &self.inner.vm {
            externals::ExternalsVm::ExternalStorageClearPrefix(req) => req.prefix(),
            externals::ExternalsVm::ExternalStorageRoot { .. } => &[],

            // We only create a `PrefixKeys` if the state is one of the above.
            _ => unreachable!(),
        }
    }

    /// Injects the list of keys.
    pub fn inject_keys(
        mut self,
        keys: impl Iterator<Item = impl AsRef<[u8]>>,
    ) -> RuntimeExternalsVm {
        match self.inner.vm {
            externals::ExternalsVm::ExternalStorageClearPrefix(req) => {
                // TODO: use prefix_remove_update once optimized
                //top_trie_root_calculation_cache.prefix_remove_update(storage_key);

                for key in keys {
                    self.inner
                        .top_trie_root_calculation_cache
                        .as_mut()
                        .unwrap()
                        .storage_value_update(key.as_ref(), false);
                    self.inner
                        .top_trie_changes
                        .insert(key.as_ref().to_vec(), None);
                }
                // TODO: O(n) complexity here
                for (key, value) in self.inner.top_trie_changes.iter_mut() {
                    if !key.starts_with(req.prefix()) {
                        continue;
                    }
                    if value.is_none() {
                        continue;
                    }
                    self.inner
                        .top_trie_root_calculation_cache
                        .as_mut()
                        .unwrap()
                        .storage_value_update(key, false);
                    *value = None;
                }
                self.inner.vm = req.resume();
            }

            externals::ExternalsVm::ExternalStorageRoot { .. } => {
                if let calculate_root::RootMerkleValueCalculation::AllKeys(all_keys) =
                    self.inner.root_calculation.take().unwrap()
                {
                    // TODO: overhead
                    let mut list = keys
                        .filter(|v| {
                            self.inner
                                .top_trie_changes
                                .get(v.as_ref())
                                .map_or(true, |v| v.is_some())
                        })
                        .map(|v| v.as_ref().to_vec())
                        .collect::<HashSet<_, fnv::FnvBuildHasher>>();
                    // TODO: slow to iterate over everything?
                    for (key, value) in self.inner.top_trie_changes.iter() {
                        if value.is_none() {
                            continue;
                        }
                        list.insert(key.clone());
                    }
                    self.inner.root_calculation =
                        Some(all_keys.inject(list.into_iter().map(|k| k.into_iter())));
                } else {
                    // We only create a `PrefixKeys` if the state is `AllKeys`.
                    panic!()
                }
            }

            // We only create a `PrefixKeys` if the state is one of the above.
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct NextKey {
    inner: Inner,

    /// If `Some`, ask for the key inside of this field rather than the one of `inner`. Used in
    /// corner-case situations where the key provided by the user has been erased from storage.
    key_overwrite: Option<Vec<u8>>,
}

impl NextKey {
    /// Returns the key whose next key must be passed back.
    pub fn key(&self) -> &[u8] {
        if let Some(key_overwrite) = &self.key_overwrite {
            return key_overwrite;
        }

        match &self.inner.vm {
            externals::ExternalsVm::ExternalStorageNextKey(req) => req.key(),
            _ => unreachable!(),
        }
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(mut self, key: Option<impl AsRef<[u8]>>) -> RuntimeExternalsVm {
        let key = key.as_ref().map(|k| k.as_ref());

        match self.inner.vm {
            externals::ExternalsVm::ExternalStorageNextKey(req) => {
                let requested_key = if let Some(key_overwrite) = &self.key_overwrite {
                    &key_overwrite[..]
                } else {
                    req.key()
                };

                if let Some(key) = key {
                    assert!(key > requested_key);
                }

                // The next key can be either the one passed by the user or one key in the current
                // pending storage changes that has been inserted during the execution.
                // As such, find the "next key" in the list of overlay changes.
                // TODO: not optimized in terms of searching time ; should really be a BTreeMap or something
                let in_overlay = self
                    .inner
                    .top_trie_changes
                    .iter()
                    .map(|(k, v)| (k, v.is_some()))
                    .filter(|(k, _)| &***k > requested_key)
                    .min_by_key(|(k, _)| *k);

                let outcome = match (key, in_overlay) {
                    (Some(a), Some((b, true))) if a <= &b[..] => Some(a),
                    (Some(a), Some((b, false))) if a < &b[..] => Some(a),
                    (Some(a), Some((b, false))) => {
                        debug_assert!(a >= &b[..]);
                        debug_assert_ne!(&b[..], requested_key);

                        // The next key according to the parent storage has been erased earlier in
                        // the block execution. It is necessary to ask the user again, this time
                        // for the key after the one that has been erased.
                        // This `clone()` is necessary, as `b` borrows from
                        // `self.inner.top_trie_changes`.
                        let key_overwrite = Some(b.clone());
                        self.inner.vm = externals::ExternalsVm::ExternalStorageNextKey(req);
                        return RuntimeExternalsVm::NextKey(NextKey {
                            inner: self.inner,
                            key_overwrite,
                        });
                    }
                    (Some(a), Some((b, true))) => {
                        debug_assert!(a >= &b[..]);
                        Some(&b[..])
                    }

                    (Some(a), None) => Some(a),
                    (None, Some((b, _))) => Some(&b[..]),
                    (None, None) => None,
                };

                self.inner.vm = req.resume(outcome.as_ref().map(|v| &v[..]));
            }

            // We only create a `NextKey` if the state is one of the above.
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Implementation detail of the execution. Shared by all the variants of [`RuntimeExternalsVm`]
/// other than [`RuntimeExternalsVm::Finished`].
struct Inner {
    /// Virtual machine running the call.
    vm: externals::ExternalsVm,

    /// Pending changes to the top storage trie that this execution performs.
    top_trie_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,

    /// Pending changes to the offchain storage that this execution performs.
    offchain_storage_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,

    /// Cache passed by the user. Always `Some` except when we are currently calculating the trie
    /// state root.
    top_trie_root_calculation_cache: Option<calculate_root::CalculationCache>,

    /// Trie root calculation in progress.
    root_calculation: Option<calculate_root::RootMerkleValueCalculation>,

    /// Concatenation of all the log messages generated by the runtime.
    logs: String,
}

impl Inner {
    /// Continues the execution.
    fn run(mut self) -> RuntimeExternalsVm {
        loop {
            match self.vm {
                externals::ExternalsVm::ReadyToRun(r) => self.vm = r.run(),

                externals::ExternalsVm::Error { error, .. } => {
                    return RuntimeExternalsVm::Finished(Err(Error::WasmVm {
                        error,
                        logs: self.logs,
                    }));
                }

                externals::ExternalsVm::Finished(finished) => {
                    return RuntimeExternalsVm::Finished(Ok(Success {
                        virtual_machine: SuccessVirtualMachine(finished),
                        storage_top_trie_changes: self.top_trie_changes,
                        offchain_storage_changes: self.offchain_storage_changes,
                        top_trie_root_calculation_cache: self
                            .top_trie_root_calculation_cache
                            .unwrap(),
                        logs: self.logs,
                    }));
                }

                externals::ExternalsVm::ExternalStorageGet(req) => {
                    if let Some(overlay) = self.top_trie_changes.get(req.key()) {
                        self.vm = req.resume_full_value(overlay.as_ref().map(|v| &v[..]));
                    } else {
                        self.vm = req.into();
                        return RuntimeExternalsVm::StorageGet(StorageGet { inner: self });
                    }
                }

                externals::ExternalsVm::ExternalStorageSet(req) => {
                    self.top_trie_root_calculation_cache
                        .as_mut()
                        .unwrap()
                        .storage_value_update(req.key(), req.value().is_some());
                    self.top_trie_changes
                        .insert(req.key().to_vec(), req.value().map(|v| v.to_vec()));
                    self.vm = req.resume();
                }

                externals::ExternalsVm::ExternalStorageAppend(req) => {
                    self.top_trie_root_calculation_cache
                        .as_mut()
                        .unwrap()
                        .storage_value_update(req.key(), true);

                    if let Some(current_value) = self.top_trie_changes.get(req.key()) {
                        let mut current_value = current_value.clone().unwrap_or_default();
                        append_to_storage_value(&mut current_value, req.value());
                        self.top_trie_changes
                            .insert(req.key().to_vec(), Some(current_value));
                        self.vm = req.resume();
                    } else {
                        self.vm = req.into();
                        return RuntimeExternalsVm::StorageGet(StorageGet { inner: self });
                    }
                }

                externals::ExternalsVm::ExternalStorageClearPrefix(req) => {
                    self.vm = req.into();
                    return RuntimeExternalsVm::PrefixKeys(PrefixKeys { inner: self });
                }

                externals::ExternalsVm::ExternalStorageRoot(req) => {
                    if self.root_calculation.is_none() {
                        self.root_calculation = Some(calculate_root::root_merkle_value(Some(
                            self.top_trie_root_calculation_cache.take().unwrap(),
                        )));
                    }

                    match self.root_calculation.take().unwrap() {
                        calculate_root::RootMerkleValueCalculation::Finished { hash, cache } => {
                            self.top_trie_root_calculation_cache = Some(cache);
                            self.vm = req.resume(&hash);
                        }
                        calculate_root::RootMerkleValueCalculation::AllKeys(keys) => {
                            self.vm = req.into();
                            self.root_calculation =
                                Some(calculate_root::RootMerkleValueCalculation::AllKeys(keys));
                            return RuntimeExternalsVm::PrefixKeys(PrefixKeys { inner: self });
                        }
                        calculate_root::RootMerkleValueCalculation::StorageValue(value_request) => {
                            self.vm = req.into();
                            // TODO: allocating a Vec, meh
                            if let Some(overlay) = self
                                .top_trie_changes
                                .get(&value_request.key().collect::<Vec<_>>())
                            {
                                self.root_calculation =
                                    Some(value_request.inject(overlay.as_ref()));
                            } else {
                                self.root_calculation =
                                    Some(calculate_root::RootMerkleValueCalculation::StorageValue(
                                        value_request,
                                    ));
                                return RuntimeExternalsVm::StorageGet(StorageGet { inner: self });
                            }
                        }
                    }
                }

                externals::ExternalsVm::ExternalStorageChangesRoot(req) => {
                    self.vm = req.into();
                    return RuntimeExternalsVm::StorageGet(StorageGet { inner: self });
                }

                externals::ExternalsVm::ExternalStorageNextKey(req) => {
                    self.vm = req.into();
                    return RuntimeExternalsVm::NextKey(NextKey {
                        inner: self,
                        key_overwrite: None,
                    });
                }

                externals::ExternalsVm::ExternalOffchainStorageSet(req) => {
                    self.offchain_storage_changes
                        .insert(req.key().to_vec(), req.value().map(|v| v.to_vec()));
                    self.vm = req.resume();
                }

                externals::ExternalsVm::CallRuntimeVersion(req) => {
                    // The code below compiles the provided WebAssembly runtime code, which is a
                    // relatively expensive operation (in the order of milliseconds).
                    // While it could be tempting to use a system cache, this function is expected
                    // to be called only right before runtime upgrades. Considering that runtime
                    // upgrades are quite uncommon and that a caching system is rather non-trivial
                    // to set up, the approach of recompiling every single time is preferred here.
                    // TODO: number of heap pages?! 1024 is default, but not sure whether that's correct or if we have to take the current heap pages
                    let vm_prototype = match externals::ExternalsVmPrototype::new(
                        req.wasm_code(),
                        1024,
                        vm::ExecHint::Oneshot,
                    ) {
                        Ok(w) => w,
                        Err(_) => {
                            self.vm = req.resume(Err(()));
                            continue;
                        }
                    };

                    match super::core_version(vm_prototype) {
                        Ok((version, _)) => {
                            // TODO: optimize
                            self.vm = req.resume(Ok(&parity_scale_codec::Encode::encode(&version)));
                        }
                        Err(_) => {
                            self.vm = req.resume(Err(()));
                        }
                    }
                }

                externals::ExternalsVm::StartStorageTransaction(tx) => {
                    self.vm = tx.resume();
                }

                externals::ExternalsVm::EndStorageTransaction { resume, rollback } => {
                    if rollback {
                        todo!() // TODO:
                    }

                    self.vm = resume.resume();
                }

                externals::ExternalsVm::LogEmit(req) => {
                    // We add a hardcoded limit to the logs generated by the runtime in order to
                    // make sure that there is no memory leak. In practice, the runtime should
                    // rarely log more than a few hundred bytes. This limit is hardcoded rather
                    // than configurable because it is not expected to be reachable unless
                    // something is very wrong.
                    // TODO: optimize somehow? don't create an intermediary String?
                    let message = req.to_string();
                    if self.logs.len().saturating_add(message.len()) >= 1024 * 1024 {
                        return RuntimeExternalsVm::Finished(Err(Error::LogsTooLong));
                    }

                    self.logs.push_str(&message);
                    self.vm = req.resume();
                }
            }
        }
    }
}

/// Performs the action described by [`externals::ExternalsVm::ExternalStorageAppend`] on an
/// encoded storage value.
// TODO: remove usage of parity_scale_codec
fn append_to_storage_value(value: &mut Vec<u8>, to_add: &[u8]) {
    let curr_len = match <parity_scale_codec::Compact<u64> as parity_scale_codec::Decode>::decode(
        &mut &value[..],
    ) {
        Ok(l) => l,
        Err(_) => {
            value.clear();
            parity_scale_codec::Encode::encode_to(&parity_scale_codec::Compact(1u64), value);
            value.extend_from_slice(to_add);
            return;
        }
    };

    // Note: we use `checked_add`, as it is possible that the storage entry erroneously starts
    // with `u64::max_value()`.
    let new_len = match curr_len.0.checked_add(1) {
        Some(l) => parity_scale_codec::Compact(l),
        None => {
            value.clear();
            parity_scale_codec::Encode::encode_to(&parity_scale_codec::Compact(1u64), value);
            value.extend_from_slice(to_add);
            return;
        }
    };

    let curr_len_encoded_size =
        <parity_scale_codec::Compact<u64> as parity_scale_codec::CompactLen<u64>>::compact_len(
            &curr_len.0,
        );
    let new_len_encoded_size =
        <parity_scale_codec::Compact<u64> as parity_scale_codec::CompactLen<u64>>::compact_len(
            &new_len.0,
        );
    debug_assert!(
        new_len_encoded_size == curr_len_encoded_size
            || new_len_encoded_size == curr_len_encoded_size + 1
    );

    for _ in 0..(new_len_encoded_size - curr_len_encoded_size) {
        value.insert(0, 0);
    }

    parity_scale_codec::Encode::encode_to(&new_len, &mut (&mut value[..new_len_encoded_size]));
    value.extend_from_slice(to_add);
}
