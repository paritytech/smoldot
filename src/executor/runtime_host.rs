// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
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

//! Wasm virtual machine, with automatic storage overlay and logs management.
//!
//! The code in this module builds upon the functionnalities of the [`host`] module and
//! implements some of the host function calls. In other words, it is an easier-to-use version of
//! the [`host`] module.
//!
//! Most of the documentation of the [`host`] module also applies here.
//!
//! In addition to the functionalities provided by the [`host`] module, the `runtime_host` module:
//!
//! - Keeps track of the changes to the storage and offchain storage made by the execution, and
//!   provides them at the end. Any storage access takes into account the intermediary list of
//!   changes.
//! - Keeps track of the logs generated by the call and concatenates them into a [`String`].
//! - Automatically handles some externalities, such as calculating the Merkle root or storage
//!   transactions.
//!
//! These additional features considerably reduces the number of externals concepts to plug to
//! the virtual machine.

// TODO: more docs

use crate::{
    executor::{self, host, vm},
    trie::calculate_root,
    util,
};

use alloc::{
    collections::BTreeMap,
    string::{String, ToString as _},
    vec::Vec,
};
use core::{fmt, iter};
use hashbrown::{hash_map::Entry, HashMap, HashSet};

/// Configuration for [`run`].
pub struct Config<'a, TParams> {
    /// Virtual machine to be run.
    pub virtual_machine: host::HostVmPrototype,

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
    pub storage_top_trie_changes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,

    /// Initial state of [`Success::offchain_storage_changes`]. The changes made during this
    /// execution will be pushed over the value in this field.
    pub offchain_storage_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
}

/// Start running the WebAssembly virtual machine.
pub fn run(
    config: Config<impl Iterator<Item = impl AsRef<[u8]>> + Clone>,
) -> Result<RuntimeHostVm, (host::StartErr, host::HostVmPrototype)> {
    Ok(Inner {
        vm: config
            .virtual_machine
            .run_vectored(config.function_to_call, config.parameter)?
            .into(),
        top_trie_changes: config.storage_top_trie_changes,
        top_trie_transaction_revert: None,
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
    pub storage_top_trie_changes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// List of changes to the offchain storage that this block performs.
    pub offchain_storage_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
    /// Cache used for calculating the top trie root.
    pub top_trie_root_calculation_cache: calculate_root::CalculationCache,
    /// Concatenation of all the log messages printed by the runtime.
    pub logs: String,
}

/// Function execution has succeeded. Contains the return value of the call.
pub struct SuccessVirtualMachine(host::Finished);

impl SuccessVirtualMachine {
    /// Returns the value the called function has returned.
    pub fn value(&'_ self) -> impl AsRef<[u8]> + '_ {
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
#[derive(Debug, derive_more::Display)]
#[display(fmt = "{}", detail)]
pub struct Error {
    /// Exact error that happened.
    pub detail: ErrorDetail,
    /// Prototype of the virtual machine that was passed through [`Config::virtual_machine`].
    pub prototype: host::HostVmPrototype,
}

/// See [`Error::detail`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum ErrorDetail {
    /// Error while executing the Wasm virtual machine.
    #[display(fmt = "Error while executing Wasm VM: {}\n{:?}", error, logs)]
    WasmVm {
        /// Error that happened.
        error: host::Error,
        /// Concatenation of all the log messages printed by the runtime.
        logs: String,
    },
    /// Size of the logs generated by the runtime exceeds the limit.
    LogsTooLong,
}

/// Current state of the execution.
#[must_use]
pub enum RuntimeHostVm {
    /// Execution is over.
    Finished(Result<Success, Error>),
    /// Loading a storage value is required in order to continue.
    StorageGet(StorageGet),
    /// Fetching the list of keys with a given prefix is required in order to continue.
    PrefixKeys(PrefixKeys),
    /// Fetching the key that follows a given one is required in order to continue.
    NextKey(NextKey),
}

impl RuntimeHostVm {
    /// Cancels execution of the virtual machine and returns back the prototype.
    pub fn into_prototype(self) -> host::HostVmPrototype {
        match self {
            RuntimeHostVm::Finished(Ok(inner)) => inner.virtual_machine.into_prototype(),
            RuntimeHostVm::Finished(Err(inner)) => inner.prototype,
            RuntimeHostVm::StorageGet(inner) => inner.inner.vm.into_prototype(),
            RuntimeHostVm::PrefixKeys(inner) => inner.inner.vm.into_prototype(),
            RuntimeHostVm::NextKey(inner) => inner.inner.vm.into_prototype(),
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
    pub fn key(&'_ self) -> impl Iterator<Item = impl AsRef<[u8]> + '_> + '_ {
        match &self.inner.vm {
            host::HostVm::ExternalStorageGet(req) => either::Left(iter::once(either::Left(
                either::Left(either::Left(req.key())),
            ))),
            host::HostVm::ExternalStorageAppend(req) => either::Left(iter::once(either::Left(
                either::Left(either::Right(req.key())),
            ))),

            host::HostVm::ExternalStorageRoot(_) => {
                if let calculate_root::RootMerkleValueCalculation::StorageValue(value_request) =
                    self.inner.root_calculation.as_ref().unwrap()
                {
                    either::Right(value_request.key().map(|v| [v]).map(either::Right))
                } else {
                    // We only create a `StorageGet` if the state is `StorageValue`.
                    panic!()
                }
            }

            host::HostVm::ExternalStorageChangesRoot(_) => either::Left(iter::once(either::Left(
                either::Right(&b":changes_trie"[..]),
            ))),

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
    pub fn inject_value(
        mut self,
        value: Option<impl Iterator<Item = impl AsRef<[u8]>>>,
    ) -> RuntimeHostVm {
        // TODO: update the implementation to not require the folding here
        let value = value.map(|i| {
            i.fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            })
        });

        match self.inner.vm {
            host::HostVm::ExternalStorageGet(req) => {
                // TODO: should actually report the offset and max_size in the API
                self.inner.vm = req.resume_full_value(value.as_ref().map(|v| &v[..]));
            }
            host::HostVm::ExternalStorageAppend(req) => {
                // TODO: could be less overhead?
                let mut value = value.unwrap_or_default();
                append_to_storage_value(&mut value, req.value().as_ref());
                self.inner
                    .top_trie_changes
                    .insert(req.key().as_ref().to_vec(), Some(value));
                self.inner.vm = req.resume();
            }
            host::HostVm::ExternalStorageRoot(_) => {
                if let calculate_root::RootMerkleValueCalculation::StorageValue(value_request) =
                    self.inner.root_calculation.take().unwrap()
                {
                    self.inner.root_calculation = Some(value_request.inject(value));
                } else {
                    // We only create a `StorageGet` if the state is `StorageValue`.
                    panic!()
                }
            }
            host::HostVm::ExternalStorageChangesRoot(req) => {
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
    pub fn prefix(&'_ self) -> impl AsRef<[u8]> + '_ {
        match &self.inner.vm {
            host::HostVm::ExternalStorageClearPrefix(req) => either::Left(req.prefix()),
            host::HostVm::ExternalStorageRoot { .. } => either::Right(&[]),

            // We only create a `PrefixKeys` if the state is one of the above.
            _ => unreachable!(),
        }
    }

    /// Injects the list of keys ordered lexicographically.
    pub fn inject_keys_ordered(
        mut self,
        keys: impl Iterator<Item = impl AsRef<[u8]>>,
    ) -> RuntimeHostVm {
        match self.inner.vm {
            host::HostVm::ExternalStorageClearPrefix(req) => {
                // TODO: use prefix_remove_update once optimized
                //top_trie_root_calculation_cache.prefix_remove_update(storage_key);

                // Grab the maximum number of keys to remove, and initialize a counter for the
                // number of keys removed so far.
                // While doing `keys.take(...)` would be more simple, we avoid doing so in order
                // to avoid converting the `u32` to a `usize`.
                let max_keys_to_remove = req.max_keys_to_remove();
                let mut keys_removed_so_far = 0u32;

                for key in keys {
                    // Enforce the maximum number of keys to remove.
                    if max_keys_to_remove.map_or(false, |max| keys_removed_so_far >= max) {
                        break;
                    }

                    self.inner
                        .top_trie_root_calculation_cache
                        .as_mut()
                        .unwrap()
                        .storage_value_update(key.as_ref(), false);

                    let previous_value = self
                        .inner
                        .top_trie_changes
                        .insert(key.as_ref().to_vec(), None);

                    if let Some(top_trie_transaction_revert) =
                        self.inner.top_trie_transaction_revert.as_mut()
                    {
                        if let Entry::Vacant(entry) =
                            top_trie_transaction_revert.entry(key.as_ref().to_vec())
                        {
                            entry.insert(previous_value);
                        }
                    }

                    // `wrapping_add` is used because the only way `keys_removed_so_far` can be
                    // equal to `u32::max_value()` at this point is when `max_keys_to_remove`
                    // is `None`.
                    keys_removed_so_far = keys_removed_so_far.wrapping_add(1);
                }

                // TODO: O(n) complexity here
                for (key, value) in self.inner.top_trie_changes.iter_mut() {
                    if !key.starts_with(req.prefix().as_ref()) {
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

            host::HostVm::ExternalStorageRoot { .. } => {
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
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        if let Some(key_overwrite) = &self.key_overwrite {
            return either::Left(key_overwrite);
        }

        match &self.inner.vm {
            host::HostVm::ExternalStorageNextKey(req) => either::Right(req.key()),
            _ => unreachable!(),
        }
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(mut self, key: Option<impl AsRef<[u8]>>) -> RuntimeHostVm {
        let key = key.as_ref().map(|k| k.as_ref());

        match self.inner.vm {
            host::HostVm::ExternalStorageNextKey(req) => {
                let req_key = req.key();
                let requested_key = if let Some(key_overwrite) = &self.key_overwrite {
                    &key_overwrite[..]
                } else {
                    req_key.as_ref()
                };

                if let Some(key) = key {
                    assert!(key > requested_key);
                }

                // The next key can be either the one passed by the user or one key in the current
                // pending storage changes that has been inserted during the execution.
                // As such, find the "next key" in the list of overlay changes.
                let in_overlay = self
                    .inner
                    .top_trie_changes
                    .range(requested_key.to_vec()..) // TODO: to_vec() :-/
                    .find(|(k, _)| &***k > requested_key)
                    .map(|(k, v)| (k, v.is_some()));

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
                        drop(req_key); // Solves borrowing errors.
                        self.inner.vm = host::HostVm::ExternalStorageNextKey(req);
                        return RuntimeHostVm::NextKey(NextKey {
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

                drop(req_key); // Solves borrowing errors.
                self.inner.vm = req.resume(outcome.as_ref().map(|v| &v[..]));
            }

            // We only create a `NextKey` if the state is one of the above.
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Implementation detail of the execution. Shared by all the variants of [`RuntimeHostVm`]
/// other than [`RuntimeHostVm::Finished`].
struct Inner {
    /// Virtual machine running the call.
    vm: host::HostVm,

    /// Pending changes to the top storage trie that this execution performs.
    top_trie_changes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,

    /// `Some` if and only if we're within a storage transaction. When changes are applied to
    /// [`Inner::top_trie_changes`], the reverse operation is added here.
    ///
    /// When the storage transaction ends, either this hash map is entirely discarded (to commit
    /// changes), or applied to [`Inner::top_trie_changes`] (to revert).
    top_trie_transaction_revert:
        Option<HashMap<Vec<u8>, Option<Option<Vec<u8>>>, fnv::FnvBuildHasher>>,

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
    fn run(mut self) -> RuntimeHostVm {
        loop {
            match self.vm {
                host::HostVm::ReadyToRun(r) => self.vm = r.run(),

                host::HostVm::Error { error, prototype } => {
                    return RuntimeHostVm::Finished(Err(Error {
                        detail: ErrorDetail::WasmVm {
                            error,
                            logs: self.logs,
                        },
                        prototype,
                    }));
                }

                host::HostVm::Finished(finished) => {
                    return RuntimeHostVm::Finished(Ok(Success {
                        virtual_machine: SuccessVirtualMachine(finished),
                        storage_top_trie_changes: self.top_trie_changes,
                        offchain_storage_changes: self.offchain_storage_changes,
                        top_trie_root_calculation_cache: self
                            .top_trie_root_calculation_cache
                            .unwrap(),
                        logs: self.logs,
                    }));
                }

                host::HostVm::ExternalStorageGet(req) => {
                    let change = self.top_trie_changes.get(req.key().as_ref());
                    if let Some(overlay) = change {
                        self.vm = req.resume_full_value(overlay.as_ref().map(|v| &v[..]));
                    } else {
                        self.vm = req.into();
                        return RuntimeHostVm::StorageGet(StorageGet { inner: self });
                    }
                }

                host::HostVm::ExternalStorageSet(req) => {
                    self.top_trie_root_calculation_cache
                        .as_mut()
                        .unwrap()
                        .storage_value_update(req.key().as_ref(), req.value().is_some());

                    let previous_value = self.top_trie_changes.insert(
                        req.key().as_ref().to_vec(),
                        req.value().map(|v| v.as_ref().to_vec()),
                    );

                    if let Some(top_trie_transaction_revert) =
                        self.top_trie_transaction_revert.as_mut()
                    {
                        if let Entry::Vacant(entry) =
                            top_trie_transaction_revert.entry(req.key().as_ref().to_vec())
                        {
                            entry.insert(previous_value);
                        }
                    }

                    self.vm = req.resume();
                }

                host::HostVm::ExternalStorageAppend(req) => {
                    self.top_trie_root_calculation_cache
                        .as_mut()
                        .unwrap()
                        .storage_value_update(req.key().as_ref(), true);

                    let current_value = self.top_trie_changes.get(req.key().as_ref());
                    if let Some(current_value) = current_value {
                        let mut current_value = current_value.clone().unwrap_or_default();
                        append_to_storage_value(&mut current_value, req.value().as_ref());
                        let previous_value = self
                            .top_trie_changes
                            .insert(req.key().as_ref().to_vec(), Some(current_value));
                        if let Some(top_trie_transaction_revert) =
                            self.top_trie_transaction_revert.as_mut()
                        {
                            if let Entry::Vacant(entry) =
                                top_trie_transaction_revert.entry(req.key().as_ref().to_vec())
                            {
                                entry.insert(previous_value);
                            }
                        }
                        self.vm = req.resume();
                    } else {
                        self.vm = req.into();
                        return RuntimeHostVm::StorageGet(StorageGet { inner: self });
                    }
                }

                host::HostVm::ExternalStorageClearPrefix(req) => {
                    self.vm = req.into();
                    return RuntimeHostVm::PrefixKeys(PrefixKeys { inner: self });
                }

                host::HostVm::ExternalStorageRoot(req) => {
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
                            return RuntimeHostVm::PrefixKeys(PrefixKeys { inner: self });
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
                                return RuntimeHostVm::StorageGet(StorageGet { inner: self });
                            }
                        }
                    }
                }

                host::HostVm::ExternalStorageChangesRoot(req) => {
                    self.vm = req.into();
                    return RuntimeHostVm::StorageGet(StorageGet { inner: self });
                }

                host::HostVm::ExternalStorageNextKey(req) => {
                    self.vm = req.into();
                    return RuntimeHostVm::NextKey(NextKey {
                        inner: self,
                        key_overwrite: None,
                    });
                }

                host::HostVm::ExternalOffchainStorageSet(req) => {
                    self.offchain_storage_changes.insert(
                        req.key().as_ref().to_vec(),
                        req.value().map(|v| v.as_ref().to_vec()),
                    );
                    self.vm = req.resume();
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
                    let vm_prototype = match host::HostVmPrototype::new(
                        req.wasm_code(),
                        executor::DEFAULT_HEAP_PAGES,
                        vm::ExecHint::Oneshot,
                    ) {
                        Ok(w) => w,
                        Err(_) => {
                            self.vm = req.resume(Err(()));
                            continue;
                        }
                    };

                    match super::core_version(vm_prototype) {
                        (Ok(version), _) => {
                            self.vm = req.resume(Ok(version.as_ref()));
                        }
                        (Err(_), _) => {
                            self.vm = req.resume(Err(()));
                        }
                    }
                }

                host::HostVm::StartStorageTransaction(tx) => {
                    self.top_trie_transaction_revert = Some(Default::default());
                    self.vm = tx.resume();
                }

                host::HostVm::EndStorageTransaction { resume, rollback } => {
                    // The inner implementation guarantees that a storage transaction can only
                    // end if it has earlier been started.
                    debug_assert!(self.top_trie_transaction_revert.is_some());

                    if rollback {
                        for (key, value) in self.top_trie_transaction_revert.take().unwrap() {
                            if let Some(value) = value {
                                let _ = self.top_trie_changes.insert(key, value);
                            } else {
                                let _ = self.top_trie_changes.remove(&key);
                            }
                        }

                        // TODO: very slow; do this properly
                        self.top_trie_root_calculation_cache = Some(Default::default());
                    }

                    self.top_trie_transaction_revert = None;
                    self.vm = resume.resume();
                }

                host::HostVm::LogEmit(req) => {
                    // We add a hardcoded limit to the logs generated by the runtime in order to
                    // make sure that there is no memory leak. In practice, the runtime should
                    // rarely log more than a few hundred bytes. This limit is hardcoded rather
                    // than configurable because it is not expected to be reachable unless
                    // something is very wrong.
                    // TODO: optimize somehow? don't create an intermediary String?
                    let message = req.to_string();
                    if self.logs.len().saturating_add(message.len()) >= 1024 * 1024 {
                        return RuntimeHostVm::Finished(Err(Error {
                            detail: ErrorDetail::LogsTooLong,
                            prototype: host::HostVm::LogEmit(req).into_prototype(),
                        }));
                    }

                    self.logs.push_str(&message);
                    self.vm = req.resume();
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
    // with `u64::max_value()`.
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

    for _ in 0..(new_len_encoded_size - curr_len_encoded_size) {
        value.insert(0, 0);
    }

    value[..new_len_encoded_size].copy_from_slice(new_len_encoded.as_ref());
    value.extend_from_slice(to_add);
}
