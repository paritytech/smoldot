// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Unsealed block execution.
//!
//! The [`execute_block`] verifies the validity of a block header and body by *executing* the
//! block. Executing the block consists in running the `Core_execute_block` function of the
//! runtime, passing as parameter the header and the body of the block. The runtime function is
//! then tasked with verifying the validity of its parameters and calling the external functions
//! that modify the state of the storage.
//!
//! The header passed to the runtime must not contain a seal.
//!
//! Executing the block does **not** verify the validity of the consensus-related aspects of the
//! block header. The runtime blindly assumes that the author of the block had indeed the rights
//! to craft the block.
//!
//! # Usage
//!
//! Calling [`execute_block`] returns a [`Verify`] enum containing the state of the verification.
//!
//! If the [`Verify`] is a [`Verify::Finished`], then the verification is over and the result can
//! be retrieved.
//! Otherwise, the verification process requires an information from the storage of the parent
//! block in order to continue.
//!

use crate::{executor, header, trie::calculate_root};

use core::{cmp, convert::TryFrom as _, iter, slice};
use hashbrown::{HashMap, HashSet};

/// Configuration for an unsealed block verification.
pub struct Config<'a, TBody> {
    /// Runtime used to check the new block. Must be built using the Wasm code found at the
    /// `:code` key of the parent block storage.
    pub parent_runtime: executor::WasmVmPrototype,

    /// Header of the block to verify, in SCALE encoding.
    ///
    /// The `parent_hash` field is the hash of the parent whose storage can be accessed through
    /// the other fields.
    ///
    /// Block headers typically contain a `Seal` item as their last digest log item. When calling
    /// the [`execute_block`] function, this header must **not** contain any `Seal` item.
    pub block_header: header::HeaderRef<'a>,

    /// Body of the block to verify.
    pub block_body: TBody,

    /// Optional cache corresponding to the storage trie root hash calculation.
    pub top_trie_root_calculation_cache: Option<calculate_root::CalculationCache>,
}

/// Block successfully verified.
pub struct Success {
    /// Runtime that was passed by [`Config`].
    pub parent_runtime: executor::WasmVmPrototype,
    /// List of changes to the storage top trie that the block performs.
    pub storage_top_trie_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
    /// List of changes to the offchain storage that this block performs.
    pub offchain_storage_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
    /// Cache used for calculating the top trie root.
    pub top_trie_root_calculation_cache: calculate_root::CalculationCache,
    /// Concatenation of all the log messages printed by the runtime.
    pub logs: String,
}

/// Error that can happen during the verification.
#[derive(Debug, Clone, derive_more::Display)]
pub enum Error {
    /// Error while executing the Wasm virtual machine.
    Trapped {
        /// Concatenation of all the log messages printed by the runtime.
        logs: String,
    },
    /// Output of `Core_execute_block` wasn't empty.
    NonEmptyOutput,
    /// Size of the logs generated by the runtime exceeds the limit.
    LogsTooLong,
}

/// Verifies whether a block is valid.
pub fn execute_block<'a>(
    config: Config<'a, impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone> + Clone>,
) -> Verify {
    let vm = config
        .parent_runtime
        .run_vectored("Core_execute_block", {
            // The `Code_execute_block` function expects a SCALE-encoded `(header, body)`
            // where `body` is a `Vec<Vec<u8>>`. We perform the encoding manually to avoid
            // performing redundant data copies.

            // TODO: zero-cost
            let encoded_body_len = parity_scale_codec::Encode::encode(
                &parity_scale_codec::Compact(u32::try_from(config.block_body.len()).unwrap()),
            );

            let body = config.block_body.flat_map(|ext| {
                // TODO: don't allocate
                let encoded_ext_len = parity_scale_codec::Encode::encode(
                    &parity_scale_codec::Compact(u32::try_from(ext.as_ref().len()).unwrap()),
                );

                iter::once(either::Either::Left(encoded_ext_len))
                    .chain(iter::once(either::Either::Right(ext)))
            });

            config
                .block_header
                .scale_encoding()
                .map(|b| either::Either::Right(either::Either::Left(b)))
                .chain(iter::once(either::Either::Right(either::Either::Right(
                    encoded_body_len,
                ))))
                .chain(body.map(either::Either::Left))
        })
        .unwrap()
        .into();

    VerifyInner {
        vm,
        top_trie_changes: Default::default(),
        offchain_storage_changes: Default::default(),
        top_trie_root_calculation_cache: Some(
            config.top_trie_root_calculation_cache.unwrap_or_default(),
        ),
        root_calculation: None,
        logs: String::new(),
    }
    .run()
}

/// Current state of the verification.
#[must_use]
pub enum Verify {
    /// Verification is over.
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
    inner: VerifyInner,
}

impl StorageGet {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key<'a>(&'a self) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
        match &self.inner.vm {
            executor::WasmVm::ExternalStorageGet(req) => {
                either::Either::Left(iter::once(either::Either::Left(req.key())))
            }
            executor::WasmVm::ExternalStorageAppend(req) => {
                either::Either::Left(iter::once(either::Either::Left(req.key())))
            }

            executor::WasmVm::ExternalStorageRoot(_) => {
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

            executor::WasmVm::ExternalStorageChangesRoot(_) => {
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
    pub fn inject_value(mut self, value: Option<&[u8]>) -> Verify {
        match self.inner.vm {
            executor::WasmVm::ExternalStorageGet(req) => {
                // TODO: should actually report the offset and max_size in the API
                self.inner.vm = req.resume_full_value(value);
            }
            executor::WasmVm::ExternalStorageAppend(req) => {
                let mut value = value.map(|v| v.to_vec()).unwrap_or_default();
                // TODO: could be less overhead?
                append_to_storage_value(&mut value, req.value());
                self.inner
                    .top_trie_changes
                    .insert(req.key().to_vec(), Some(value.clone()));
                self.inner.vm = req.resume();
            }
            executor::WasmVm::ExternalStorageRoot(_) => {
                if let calculate_root::RootMerkleValueCalculation::StorageValue(value_request) =
                    self.inner.root_calculation.take().unwrap()
                {
                    self.inner.root_calculation = Some(value_request.inject(value));
                } else {
                    // We only create a `StorageGet` if the state is `StorageValue`.
                    panic!()
                }
            }
            executor::WasmVm::ExternalStorageChangesRoot(req) => {
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
    inner: VerifyInner,
}

impl PrefixKeys {
    /// Returns the prefix whose keys to load.
    pub fn prefix(&self) -> &[u8] {
        match &self.inner.vm {
            executor::WasmVm::ExternalStorageClearPrefix(req) => req.prefix(),
            executor::WasmVm::ExternalStorageRoot { .. } => &[],

            // We only create a `PrefixKeys` if the state is one of the above.
            _ => unreachable!(),
        }
    }

    /// Injects the list of keys.
    pub fn inject_keys(mut self, keys: impl Iterator<Item = impl AsRef<[u8]>>) -> Verify {
        match self.inner.vm {
            executor::WasmVm::ExternalStorageClearPrefix(req) => {
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

            executor::WasmVm::ExternalStorageRoot { .. } => {
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
    inner: VerifyInner,

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
            executor::WasmVm::ExternalStorageNextKey(req) => req.key(),
            _ => unreachable!(),
        }
    }

    /// Injects the key.
    pub fn inject_key(mut self, key: Option<impl AsRef<[u8]>>) -> Verify {
        let key = key.as_ref().map(|k| k.as_ref());

        match self.inner.vm {
            executor::WasmVm::ExternalStorageNextKey(req) => {
                let requested_key = if let Some(key_overwrite) = &self.key_overwrite {
                    &key_overwrite[..]
                } else {
                    req.key()
                };

                // The next key can be either the one passed by the user or one key in the current
                // pending storage changes that has been inserted during the verification.
                // As such, find the "next key" in the list of overlay changes.
                // TODO: not optimized in terms of searching time ; should really be a BTreeMap or something
                let in_overlay_any = self
                    .inner
                    .top_trie_changes
                    .iter()
                    .map(|(k, v)| (k, v.is_some()))
                    .filter(|(k, _)| &***k > requested_key)
                    .min_by_key(|(k, _)| *k);

                let outcome = match (key, in_overlay_any) {
                    (Some(a), Some((b, true))) if a <= &b[..] => Some(a),
                    (Some(a), Some((b, false))) if a < &b[..] => Some(a),
                    (Some(a), Some((b, false))) => {
                        debug_assert!(a >= &b[..]);

                        // The next key according to the parent storage has been erased earlier in
                        // the block execution. It is necessary to ask the user again, this time
                        // for the key after the one that has been erased.
                        // This `clone()` is necessary, as `b` borrows from
                        // `self.inner.top_trie_changes`.
                        let key_overwrite = Some(b.clone());
                        self.inner.vm = executor::WasmVm::ExternalStorageNextKey(req);
                        return Verify::NextKey(NextKey {
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

/// Implementation detail of the verification. Shared by all the variants of [`Verify`] other
/// than [`Verify::Finished`].
struct VerifyInner {
    /// Virtual machine running the call.
    vm: executor::WasmVm,

    /// Pending changes to the top storage trie that this block performs.
    top_trie_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,

    /// Pending changes to the offchain storage that this block performs.
    offchain_storage_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,

    /// Cache passed by the user in the [`Config`]. Always `Some` except when we are currently
    /// calculating the trie state root.
    top_trie_root_calculation_cache: Option<calculate_root::CalculationCache>,

    /// Trie root calculation in progress.
    root_calculation: Option<calculate_root::RootMerkleValueCalculation>,

    /// Concatenation of all the log messages generated by the runtime.
    logs: String,
}

impl VerifyInner {
    /// Continues the verification.
    fn run(mut self) -> Verify {
        loop {
            match self.vm {
                executor::WasmVm::ReadyToRun(r) => self.vm = r.run(),

                executor::WasmVm::Error { .. } => {
                    // TODO: not the same as Trapped; report properly
                    return Verify::Finished(Err(Error::Trapped { logs: self.logs }));
                }

                executor::WasmVm::Finished(finished) => {
                    if !finished.value().is_empty() {
                        return Verify::Finished(Err(Error::NonEmptyOutput));
                    }

                    return Verify::Finished(Ok(Success {
                        parent_runtime: finished.into_prototype(),
                        storage_top_trie_changes: self.top_trie_changes,
                        offchain_storage_changes: self.offchain_storage_changes,
                        top_trie_root_calculation_cache: self
                            .top_trie_root_calculation_cache
                            .unwrap(),
                        logs: self.logs,
                    }));
                }

                executor::WasmVm::ExternalStorageGet(req) => {
                    if let Some(overlay) = self.top_trie_changes.get(req.key()) {
                        self.vm = req.resume_full_value(overlay.as_ref().map(|v| &v[..]));
                    } else {
                        self.vm = req.into();
                        return Verify::StorageGet(StorageGet { inner: self });
                    }
                }

                executor::WasmVm::ExternalStorageSet(req) => {
                    self.top_trie_root_calculation_cache
                        .as_mut()
                        .unwrap()
                        .storage_value_update(req.key(), req.value().is_some());
                    self.top_trie_changes
                        .insert(req.key().to_vec(), req.value().map(|v| v.to_vec()));
                    self.vm = req.resume();
                }

                executor::WasmVm::ExternalStorageAppend(req) => {
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
                        return Verify::StorageGet(StorageGet { inner: self });
                    }
                }

                executor::WasmVm::ExternalStorageClearPrefix(req) => {
                    self.vm = req.into();
                    return Verify::PrefixKeys(PrefixKeys { inner: self });
                }

                executor::WasmVm::ExternalStorageRoot(req) => {
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
                            return Verify::PrefixKeys(PrefixKeys { inner: self });
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
                                return Verify::StorageGet(StorageGet { inner: self });
                            }
                        }
                    }
                }

                executor::WasmVm::ExternalStorageChangesRoot(req) => {
                    self.vm = req.into();
                    return Verify::StorageGet(StorageGet { inner: self });
                }

                executor::WasmVm::ExternalStorageNextKey(req) => {
                    self.vm = req.into();
                    return Verify::NextKey(NextKey {
                        inner: self,
                        key_overwrite: None,
                    });
                }

                executor::WasmVm::ExternalOffchainStorageSet(req) => {
                    self.offchain_storage_changes
                        .insert(req.key().to_vec(), req.value().map(|v| v.to_vec()));
                    self.vm = req.resume();
                }

                executor::WasmVm::CallRuntimeVersion(req) => {
                    // The code below compiles the provided WebAssembly runtime code, which is a
                    // relatively expensive operation (in the order of milliseconds).
                    // While it could be tempting to use a system cache, this function is expected
                    // to be called only right before runtime upgrades. Considering that runtime
                    // upgrades are quite uncommon and that a caching system is rather non-trivial
                    // to set up, the approach of recompiling every single time is preferred here.
                    // TODO: number of heap pages?! 1024 is default, but not sure whether that's correct or if we have to take the current heap pages
                    let vm_prototype = match executor::WasmVmPrototype::new(req.wasm_code(), 1024) {
                        Ok(w) => w,
                        Err(_) => {
                            self.vm = req.resume(Err(()));
                            continue;
                        }
                    };

                    match executor::core_version(vm_prototype) {
                        Ok((version, _)) => {
                            // TODO: optimize
                            self.vm = req.resume(Ok(&parity_scale_codec::Encode::encode(&version)));
                        }
                        Err(_) => {
                            self.vm = req.resume(Err(()));
                        }
                    }
                }

                executor::WasmVm::LogEmit(req) => {
                    // We add a hardcoded limit to the logs generated by the runtime in order to
                    // make sure that there is no memory leak. In practice, the runtime should
                    // rarely log more than a few hundred bytes. This limit is hardcoded rather
                    // than configurable because it is not expected to be reachable unless
                    // something is very wrong.
                    // TODO: optimize somehow? don't create an intermediary String?
                    let message = req.to_string();
                    if self.logs.len().saturating_add(message.len()) >= 1024 * 1024 {
                        return Verify::Finished(Err(Error::LogsTooLong));
                    }

                    self.logs.push_str(&message);
                    self.vm = req.resume();
                }
            }
        }
    }
}

/// Performs the action described by [`executor::WasmVm::ExternalStorageAppend`] on an encoded
/// storage value.
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
