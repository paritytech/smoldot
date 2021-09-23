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

//! Background runtime download service.
//!
//! This service plugs on top of a [`sync_service`], listens for new best blocks and checks
//! whether the runtime has changed in any way. Its objective is to always provide an up-to-date
//! [`executor::host::HostVmPrototype`] ready to be called by other services.
//!
//! # Usage
//!
//! The runtime service lets user subscribe to best and finalized block updates, similar to
//! the [`sync_service`]. These subscriptions are implemented by subscribing to the underlying
//! [`sync_service`] and, for each notification, downloading the runtime code of the best or
//! finalized block. Therefore, these notifications always come with a delay compared to directly
//! using the [`sync_service`].
//!
//! Furthermore, if it isn't possible to download the runtime code of a block (for example because
//! peers refuse to answer or have already pruned the block) or if the runtime service already has
//! too many pending downloads, this block is simply skipped and not reported on the
//! subscriptions.
//!
//! Consequently, you are strongly encouraged to not use both the [`sync_service`] *and* the
//! [`RuntimeService`] of the same chain. They each provide a consistent view of the chain, but
//! this view isn't necessarily the same on both services.
//!
//! The main service offered by the runtime service is
//! [`RuntimeService::recent_best_block_runtime_call`], that performs a runtime call on the latest
//! reported best block or more recent.

use crate::{
    lossy_channel,
    sync_service::{self, StorageQueryError},
};

use futures::{
    lock::{Mutex, MutexGuard},
    prelude::*,
};
use smoldot::{
    chain::fork_tree,
    chain_spec, executor, header, metadata,
    network::protocol,
    trie::{self, proof_verify},
};
use std::{iter, mem, num::NonZeroUsize, pin::Pin, sync::Arc};

pub use crate::lossy_channel::Receiver as NotificationsReceiver;

/// Configuration for a runtime service.
pub struct Config<'a> {
    /// Name of the chain, for logging purposes.
    ///
    /// > **Note**: This name will be directly printed out. Any special character should already
    /// >           have been filtered out from this name.
    pub log_name: String,

    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(String, Pin<Box<dyn Future<Output = ()> + Send>>) + Send>,

    /// Service responsible for synchronizing the chain.
    pub sync_service: Arc<sync_service::SyncService>,

    /// Specification of the chain.
    pub chain_spec: &'a chain_spec::ChainSpec,

    /// Header of the genesis block of the chain, in SCALE encoding.
    ///
    /// > **Note**: This can be derived from a [`chain_spec::ChainSpec`]. While the
    /// >           [`RuntimeService::new`] function could in theory use the
    /// >           [`Config::chain_spec`] parameter to derive this value, doing so is quite
    /// >           expensive. We prefer to require this value from the upper layer instead, as
    /// >           it is most likely needed anyway.
    pub genesis_block_scale_encoded_header: Vec<u8>,
}

/// See [the module-level documentation](..).
pub struct RuntimeService {
    /// Target to use for the logs. See [`Config::log_name`].
    log_target: String,

    /// See [`Config::sync_service`].
    sync_service: Arc<sync_service::SyncService>,

    /// Fields behind a `Mutex`. Should only be locked for short-lived operations.
    guarded: Mutex<Guarded>,
}

impl RuntimeService {
    /// Initializes a new runtime service.
    ///
    /// The future returned by this function is expected to finish relatively quickly and is
    /// necessary only for locking purposes.
    pub async fn new(mut config: Config<'_>) -> Arc<Self> {
        // Target to use for all the logs of this service.
        let log_target = format!("runtime-{}", config.log_name);

        // Build the runtime of the genesis block.
        let genesis_runtime = {
            let code = config
                .chain_spec
                .genesis_storage()
                .find(|(k, _)| k == b":code")
                .map(|(_, v)| v.to_vec());
            let heap_pages = config
                .chain_spec
                .genesis_storage()
                .find(|(k, _)| k == b":heappages")
                .map(|(_, v)| v.to_vec());

            // Note that in the absolute we don't need to panic in case of a problem, and could
            // simply store an `Err` and continue running.
            // However, in practice, it seems more sane to detect problems in the genesis block.
            let mut runtime = SuccessfulRuntime::from_params(&log_target, &code, &heap_pages)
                .await
                .expect("invalid runtime at genesis block");

            // As documented in the `metadata` field, we must fill it using the genesis storage.
            let mut query = metadata::query_metadata(runtime.virtual_machine.take().unwrap());
            loop {
                match query {
                    metadata::Query::Finished(Ok(metadata), vm) => {
                        runtime.virtual_machine = Some(vm);
                        runtime.metadata = Some(metadata);
                        break;
                    }
                    metadata::Query::StorageGet(get) => {
                        let key = get.key_as_vec();
                        let value = config
                            .chain_spec
                            .genesis_storage()
                            .find(|(k, _)| &**k == key)
                            .map(|(_, v)| v);
                        query = get.inject_value(value.map(iter::once));
                    }
                    metadata::Query::Finished(Err(err), _) => {
                        panic!("Unable to generate genesis metadata: {}", err)
                    }
                }
            }

            debug_assert!(header::decode(&config.genesis_block_scale_encoded_header).is_ok());
            Runtime {
                runtime: Ok(runtime),
                runtime_code: code,
                heap_pages,
                num_blocks: NonZeroUsize::new(1).unwrap(),
            }
        };

        let mut runtimes = slab::Slab::with_capacity(4); // Usual len is `1`, rarely `2`.
        let genesis_runtime_index = runtimes.insert(genesis_runtime);

        let best_near_head_of_chain = config.sync_service.is_near_head_of_chain_heuristic().await;

        let runtime_service = Arc::new(RuntimeService {
            log_target,
            sync_service: config.sync_service,
            guarded: Mutex::new(Guarded {
                best_blocks_subscriptions: Vec::new(),
                runtime_version_subscriptions: Vec::new(),
                best_near_head_of_chain,
                runtimes,
                best_block_index: None,
                non_finalized_blocks: fork_tree::ForkTree::with_capacity(32),
                finalized_block: Block {
                    runtime: Ok(RuntimeDownloadState::Finished(genesis_runtime_index)),
                    hash: header::hash_from_scale_encoded_header(
                        &config.genesis_block_scale_encoded_header,
                    ),
                    header: config.genesis_block_scale_encoded_header,
                    sync_service_best_block_report_id: 1,
                },
                sync_service_finalized_index: None,
                sync_service_best_block_next_report_id: 2,
            }),
        });

        // Spawns a task that downloads the runtime code at every block to check whether it has
        // changed.
        //
        // This is strictly speaking not necessary as long as there is no active subscription.
        // However, in practice, there is most likely always going to be one. It is way easier to
        // always have a task active rather than create and destroy it.
        (config.tasks_executor)("runtime-download".into(), {
            let runtime_service = runtime_service.clone();
            async move {
                run_background(runtime_service).await;
            }
            .boxed()
        });

        runtime_service
    }

    /// Returns the current runtime version, plus an unlimited stream that produces one item every
    /// time the specs of the runtime of the best block are changed.
    ///
    /// The stream can generate an `Err(())` if the runtime in the best block is invalid.
    pub async fn subscribe_runtime_version(
        self: &Arc<RuntimeService>,
    ) -> (
        Result<executor::CoreVersion, RuntimeError>,
        NotificationsReceiver<Result<executor::CoreVersion, RuntimeError>>,
    ) {
        let (tx, rx) = lossy_channel::channel();
        let mut guarded = self.guarded.lock().await;
        guarded.runtime_version_subscriptions.push(tx);
        let current_version = guarded
            .best_block_runtime()
            .runtime
            .as_ref()
            .map(|r| r.runtime_spec.clone())
            .map_err(|err| err.clone());
        (current_version, rx)
    }

    /// Returns the runtime version of the block with the given hash.
    pub async fn runtime_version_of_block(
        self: &Arc<RuntimeService>,
        block_hash: &[u8; 32],
    ) -> Result<executor::CoreVersion, RuntimeVersionOfBlockError> {
        // TODO: restore
        /*// If the requested block is the best known block, optimize by
        // immediately returning the cached spec.
        {
            let guarded = self.guarded.lock().await;
            if guarded.runtime_block_hash == *block_hash {
                return guarded
                    .runtime
                    .as_ref()
                    .map(|r| r.runtime_spec.clone())
                    .map_err(|err| RuntimeVersionOfBlockError::InvalidRuntime(err.clone()));
            }
        }*/

        // Ask the network for the header of this block, as we need to know the state root.
        let state_root = {
            let result = self
                .sync_service
                .clone()
                .block_query(
                    *block_hash,
                    protocol::BlocksRequestFields {
                        header: true,
                        body: false,
                        justification: false,
                    },
                )
                .await;

            // Note that the `block_query` method guarantees that the header is present
            // and valid.
            let header = if let Ok(block) = result {
                block.header.unwrap()
            } else {
                return Err(RuntimeVersionOfBlockError::NetworkBlockRequest); // TODO: precise error
            };

            *header::decode(&header)
                .map_err(RuntimeVersionOfBlockError::InvalidBlockHeader)?
                .state_root
        };

        // Download the runtime code of this block.
        let code_query_result = self
            .sync_service
            .clone()
            .storage_query(
                block_hash,
                &state_root,
                iter::once(&b":code"[..]).chain(iter::once(&b":heappages"[..])),
            )
            .await;

        let (code, heap_pages) = {
            let mut results =
                code_query_result.map_err(RuntimeVersionOfBlockError::StorageQuery)?;
            let heap_pages = results.pop().unwrap();
            let code = results.pop().unwrap();
            (code, heap_pages)
        };

        SuccessfulRuntime::from_params(&self.log_target, &code, &heap_pages)
            .await
            .map(|r| r.runtime_spec)
            .map_err(RuntimeVersionOfBlockError::InvalidRuntime)
    }

    /// Returns the runtime version of the current best block.
    pub async fn best_block_runtime(
        self: &Arc<RuntimeService>,
    ) -> Result<executor::CoreVersion, RuntimeError> {
        let guarded = self.guarded.lock().await;
        guarded
            .best_block_runtime()
            .runtime
            .as_ref()
            .map(|r| r.runtime_spec.clone())
            .map_err(|err| err.clone())
    }

    /// Returns the SCALE-encoded header of the current best block, plus an unlimited stream that
    /// produces one item every time the best block is changed.
    ///
    /// This function is similar to [`sync_service::SyncService::subscribe_best`], except that
    /// it is called less often. Additionally, it is guaranteed that when a notification is sent
    /// out, calling [`RuntimeService::recent_best_block_runtime_call`] will operate on this
    /// block or more recent. In other words, if you call
    /// [`RuntimeService::recent_best_block_runtime_call`] and the stream of notifications is
    /// empty, you are guaranteed that the call has been performed on the best block.
    pub async fn subscribe_best(
        self: &Arc<RuntimeService>,
    ) -> (Vec<u8>, NotificationsReceiver<Vec<u8>>) {
        let (tx, rx) = lossy_channel::channel();
        let mut guarded = self.guarded.lock().await;
        guarded.best_blocks_subscriptions.push(tx);
        drop(guarded);
        let (current, _) = self.sync_service.subscribe_best().await; // TODO: not correct; should load from guarded
        (current, rx)
    }

    // TODO: doc
    pub fn recent_best_block_runtime_lock<'a: 'b, 'b>(
        self: &'a Arc<RuntimeService>,
    ) -> impl Future<Output = RuntimeLock<'a>> + 'b {
        async move {
            let guarded = self.guarded.lock().await;
            RuntimeLock {
                service: self,
                guarded,
            }
        }
    }

    /// Start performing a runtime call using the best block, or a recent best block.
    ///
    /// The [`RuntimeService`] maintains the code of the runtime of a recent best block locally,
    /// but doesn't know anything about the storage, which the runtime might have to access. In
    /// order to make this work, a "call proof" is performed on the network in order to obtain
    /// the storage values corresponding to this call.
    ///
    /// This method merely starts the runtime call process and returns a lock. While the lock is
    /// alive, the entire [`RuntimeService`] is frozen. **You are strongly encouraged to not
    /// perform any asynchronous operation while the lock is active.** The call must be driven
    /// forward using the methods on the [`RuntimeCallLock`].
    pub fn recent_best_block_runtime_call<'a: 'b, 'b>(
        self: &'a Arc<RuntimeService>,
        method: &'b str,
        parameter_vectored: impl Iterator<Item = impl AsRef<[u8]>> + Clone + 'b,
    ) -> impl Future<
        Output = Result<(RuntimeCallLock<'a>, executor::host::HostVmPrototype), RuntimeCallError>,
    > + 'b {
        // An `async move` has to be used because of borrowing issue.
        async move {
            // `guarded` should be kept locked as little as possible.
            // In order to handle the possibility a runtime upgrade happening during the operation,
            // every time `guarded` is locked, we compare the runtime version stored in
            // it with the value previously found. If there is a mismatch, the entire runtime call
            // is restarted from scratch.
            loop {
                // Get `runtime_block_hash`, `runtime_block_height` and `runtime_block_state_root`,
                // the hash, height, and state trie root of a recent best block that uses this runtime.
                let (spec_version, runtime_block_hash, runtime_block_header) = {
                    let guarded = self.guarded.lock().await;

                    let best_block = match guarded.best_block_index {
                        Some(idx) => guarded.non_finalized_blocks.get(idx).unwrap(),
                        None => &guarded.finalized_block,
                    };

                    (
                        guarded
                            .best_block_runtime()
                            .runtime
                            .as_ref()
                            .map_err(|err| RuntimeCallError::InvalidRuntime(err.clone()))?
                            .runtime_spec
                            .decode()
                            .spec_version,
                        best_block.hash,
                        best_block.header.clone(),
                    )
                };

                // Perform the call proof request.
                // Note that `guarded` is not locked.
                // TODO: there's no way to verify that the call proof is actually correct; we have to ban the peer and restart the whole call process if it turns out that it's not
                // TODO: also, an empty proof will be reported as an error right now, which is weird
                let call_proof = self
                    .sync_service
                    .clone()
                    .call_proof_query(
                        header::decode(&runtime_block_header).unwrap().number,
                        protocol::CallProofRequestConfig {
                            block_hash: runtime_block_hash,
                            method,
                            parameter_vectored: parameter_vectored.clone(),
                        },
                    )
                    .await
                    .map_err(RuntimeCallError::CallProof);

                // Lock `guarded_lock` again. `continue` if the runtime has changed
                // in-between.
                let mut guarded = self.guarded.lock().await;
                let runtime = guarded
                    .best_block_runtime_mut()
                    .runtime
                    .as_mut()
                    .map_err(|err| RuntimeCallError::InvalidRuntime(err.clone()))?;
                if runtime.runtime_spec.decode().spec_version != spec_version {
                    continue;
                }

                let virtual_machine = runtime.virtual_machine.take().unwrap();
                let lock = RuntimeCallLock {
                    guarded,
                    runtime_block_header,
                    call_proof,
                };

                break Ok((lock, virtual_machine));
            }
        }
    }

    /// Obtain the metadata of the runtime of the current best block.
    ///
    /// > **Note**: Keep in mind that this function is subject to race conditions. The runtime
    /// >           of the best block can change at any time. This method should ideally be called
    /// >           again after every runtime change.
    pub async fn metadata(self: Arc<RuntimeService>) -> Result<Vec<u8>, MetadataError> {
        // First, try the cache.
        {
            let guarded = self.guarded.lock().await;
            match guarded.best_block_runtime().runtime.as_ref() {
                Ok(runtime) => {
                    if let Some(metadata) = runtime.metadata.as_ref() {
                        return Ok(metadata.clone());
                    }
                }
                Err(err) => {
                    return Err(MetadataError::InvalidRuntime(err.clone()));
                }
            }
        }

        let (mut runtime_call_lock, virtual_machine) = self
            .recent_best_block_runtime_call("Metadata_metadata", iter::empty::<Vec<u8>>())
            .await
            .map_err(MetadataError::CallError)?;

        let mut query = metadata::query_metadata(virtual_machine);
        let (metadata_result, virtual_machine) = loop {
            match query {
                metadata::Query::Finished(Ok(metadata), virtual_machine) => {
                    runtime_call_lock
                        .guarded
                        .best_block_runtime_mut()
                        .runtime
                        .as_mut()
                        .unwrap()
                        .metadata = Some(metadata.clone());
                    break (Ok(metadata), virtual_machine);
                }
                metadata::Query::StorageGet(storage_get) => {
                    match runtime_call_lock.storage_entry(&storage_get.key_as_vec()) {
                        Ok(v) => query = storage_get.inject_value(v.map(iter::once)),
                        Err(err) => {
                            break (
                                Err(MetadataError::CallError(err)),
                                metadata::Query::StorageGet(storage_get).into_prototype(),
                            );
                        }
                    }
                }
                metadata::Query::Finished(Err(err), virtual_machine) => {
                    break (Err(MetadataError::MetadataQuery(err)), virtual_machine);
                }
            }
        };

        runtime_call_lock.unlock(virtual_machine);
        metadata_result
    }

    /// Returns true if it is believed that we are near the head of the chain.
    ///
    /// The way this method is implemented is opaque and cannot be relied on. The return value
    /// should only ever be shown to the user and not used for any meaningful logic.
    pub async fn is_near_head_of_chain_heuristic(&self) -> bool {
        // The runtime service adds a delay between the moment a best block is reported by the
        // sync service and the moment it is reported by the runtime service.
        // Because of this, any "far from head of chain" to "near head of chain" transition
        // must take that delay into account. The other way around ("near" to "far") is
        // unaffected.

        // If the sync service is far from the head, the runtime service is also far.
        if !self.sync_service.is_near_head_of_chain_heuristic().await {
            return false;
        }

        // If the sync service is near, report the result of `is_near_head_of_chain_heuristic()`
        // when called at the latest best block that the runtime service reported through its API,
        // to make sure that we don't report "near" while having reported only blocks that were
        // far.
        self.guarded.lock().await.best_near_head_of_chain
    }
}

/// See [`RuntimeService::recent_best_block_runtime_lock`].
#[must_use]
pub struct RuntimeLock<'a> {
    service: &'a Arc<RuntimeService>,
    guarded: MutexGuard<'a, Guarded>,
}

impl<'a> RuntimeLock<'a> {
    /// Returns the SCALE-encoded header of the block the call is being made against.
    ///
    /// Guaranteed to always be valid.
    pub fn block_scale_encoded_header(&self) -> &[u8] {
        match self.guarded.best_block_index {
            Some(idx) => &self.guarded.non_finalized_blocks.get(idx).unwrap().header,
            None => &self.guarded.finalized_block.header,
        }
    }

    /// Returns the hash of the block the call is being made against.
    pub fn block_hash(&self) -> &[u8; 32] {
        match self.guarded.best_block_index {
            Some(idx) => &self.guarded.non_finalized_blocks.get(idx).unwrap().hash,
            None => &self.guarded.finalized_block.hash,
        }
    }

    pub fn runtime(&self) -> &executor::host::HostVmPrototype {
        // TODO: don't unwrap?
        self.guarded
            .best_block_runtime()
            .runtime
            .as_ref()
            .unwrap()
            .virtual_machine
            .as_ref()
            .unwrap()
    }

    pub async fn start<'b>(
        mut self,
        method: &'b str,
        parameter_vectored: impl Iterator<Item = impl AsRef<[u8]>> + Clone + 'b,
    ) -> Result<(RuntimeCallLock<'a>, executor::host::HostVmPrototype), RuntimeCallError> {
        // TODO: DRY :-/ this whole thing is messy

        let block_number = header::decode(&self.block_scale_encoded_header())
            .unwrap()
            .number;
        let block_hash = *self.block_hash();

        // Perform the call proof request.
        // Note that `guarded` is not locked. // TODO: wait, no, guarded is locked
        // TODO: there's no way to verify that the call proof is actually correct; we have to ban the peer and restart the whole call process if it turns out that it's not
        // TODO: also, an empty proof will be reported as an error right now, which is weird
        let call_proof = self
            .service
            .sync_service
            .clone()
            .call_proof_query(
                block_number,
                protocol::CallProofRequestConfig {
                    block_hash,
                    method,
                    parameter_vectored: parameter_vectored.clone(),
                },
            )
            .await
            .map_err(RuntimeCallError::CallProof);

        let runtime = self
            .guarded
            .best_block_runtime_mut()
            .runtime
            .as_mut()
            .map_err(|err| RuntimeCallError::InvalidRuntime(err.clone()))?;

        let virtual_machine = runtime.virtual_machine.take().unwrap();
        let runtime_block_header = self.block_scale_encoded_header().to_owned(); // TODO: cloning :-/
        let lock = RuntimeCallLock {
            guarded: self.guarded,
            runtime_block_header,
            call_proof,
        };

        Ok((lock, virtual_machine))
    }
}

/// See [`RuntimeService::recent_best_block_runtime_call`].
#[must_use]
pub struct RuntimeCallLock<'a> {
    guarded: MutexGuard<'a, Guarded>,
    runtime_block_header: Vec<u8>,
    call_proof: Result<Vec<Vec<u8>>, RuntimeCallError>,
}

impl<'a> RuntimeCallLock<'a> {
    /// Returns the SCALE-encoded header of the block the call is being made against.
    pub fn block_scale_encoded_header(&self) -> &[u8] {
        &self.runtime_block_header
    }

    /// Returns the storage root of the block the call is being made against.
    pub fn block_storage_root(&self) -> &[u8; 32] {
        header::decode(&self.runtime_block_header)
            .unwrap()
            .state_root
    }

    /// Finds the given key in the call proof and returns the associated storage value.
    ///
    /// Returns an error if the key couldn't be found in the proof, meaning that the proof is
    /// invalid.
    // TODO: if proof is invalid, we should give the option to fetch another call proof
    pub fn storage_entry(&self, requested_key: &[u8]) -> Result<Option<&[u8]>, RuntimeCallError> {
        let call_proof = match &self.call_proof {
            Ok(p) => p,
            Err(err) => return Err(err.clone()),
        };

        match proof_verify::verify_proof(proof_verify::VerifyProofConfig {
            requested_key: &requested_key,
            trie_root_hash: self.block_storage_root(),
            proof: call_proof.iter().map(|v| &v[..]),
        }) {
            Ok(v) => Ok(v),
            Err(err) => Err(RuntimeCallError::StorageRetrieval(err)),
        }
    }

    /// Finds in the call proof the list of keys that match a certain prefix.
    ///
    /// Returns an error if not all the keys could be found in the proof, meaning that the proof
    /// is invalid.
    ///
    /// The keys returned are ordered lexicographically.
    // TODO: if proof is invalid, we should give the option to fetch another call proof
    pub fn storage_prefix_keys_ordered(
        &'_ self,
        prefix: &[u8],
    ) -> Result<impl Iterator<Item = impl AsRef<[u8]> + '_>, RuntimeCallError> {
        // TODO: this is sub-optimal as we iterate over the proof multiple times and do a lot of Vec allocations
        let mut to_find = vec![trie::bytes_to_nibbles(prefix.iter().copied()).collect::<Vec<_>>()];
        let mut output = Vec::new();

        let call_proof = match &self.call_proof {
            Ok(p) => p,
            Err(err) => return Err(err.clone()),
        };

        for key in mem::replace(&mut to_find, Vec::new()) {
            let node_info = proof_verify::trie_node_info(proof_verify::TrieNodeInfoConfig {
                requested_key: key.iter().cloned(),
                trie_root_hash: &self.block_storage_root(),
                proof: call_proof.iter().map(|v| &v[..]),
            })
            .map_err(RuntimeCallError::StorageRetrieval)?;

            if node_info.storage_value.is_some() {
                assert_eq!(key.len() % 2, 0);
                output.push(trie::nibbles_to_bytes_extend(key.iter().copied()).collect::<Vec<_>>());
            }

            match node_info.children {
                proof_verify::Children::None => {}
                proof_verify::Children::One(nibble) => {
                    let mut child = key.clone();
                    child.push(nibble);
                    to_find.push(child);
                }
                proof_verify::Children::Multiple { children_bitmap } => {
                    for nibble in trie::all_nibbles() {
                        if (children_bitmap & (1 << u8::from(nibble))) == 0 {
                            continue;
                        }

                        let mut child = key.clone();
                        child.push(nibble);
                        to_find.push(child);
                    }
                }
            }
        }

        // TODO: maybe we could iterate over the proof in an ordered way rather than sorting at the end
        output.sort();
        Ok(output.into_iter())
    }

    /// End the runtime call.
    ///
    /// This method **must** be called.
    pub fn unlock(mut self, vm: executor::host::HostVmPrototype) {
        let store_back = &mut self
            .guarded
            .best_block_runtime_mut()
            .runtime
            .as_mut()
            .unwrap()
            .virtual_machine;
        debug_assert!(store_back.is_none());
        *store_back = Some(vm);
    }
}

impl<'a> Drop for RuntimeCallLock<'a> {
    fn drop(&mut self) {
        if self
            .guarded
            .best_block_runtime_mut()
            .runtime
            .as_mut()
            .unwrap()
            .virtual_machine
            .is_none()
        {
            // The [`RuntimeCallLock`] has been destroyed without being properly unlocked.
            panic!()
        }
    }
}

/// Error when analyzing the runtime.
#[derive(Debug, derive_more::Display, Clone)]
pub enum RuntimeError {
    /// The `:code` key of the storage is empty..
    CodeNotFound,
    /// Error while parsing the `:heappages` storage value.
    InvalidHeapPages(executor::InvalidHeapPagesError),
    /// Error while compiling the runtime.
    Build(executor::host::NewErr),
    /// Error when determining the runtime specification.
    CoreVersion(executor::CoreVersionError),
}

/// Error that can happen when calling a runtime function.
#[derive(Debug, Clone, derive_more::Display)]
pub enum RuntimeCallError {
    /// Runtime of the best block isn't valid.
    #[display(fmt = "Runtime of the best block isn't valid: {}", _0)]
    InvalidRuntime(RuntimeError),
    /// Error while retrieving the storage item from other nodes.
    // TODO: change error type?
    #[display(fmt = "Error in call proof: {}", _0)]
    StorageRetrieval(proof_verify::Error),
    /// Error while retrieving the call proof from the network.
    #[display(fmt = "Error when retrieving the call proof: {}", _0)]
    CallProof(sync_service::CallProofQueryError),
}

impl RuntimeCallError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    pub fn is_network_problem(&self) -> bool {
        match self {
            RuntimeCallError::InvalidRuntime(_) => false,
            // TODO: as a temporary hack, we consider `TrieRootNotFound` as the remote not knowing about the requested block; see https://github.com/paritytech/substrate/pull/8046
            RuntimeCallError::StorageRetrieval(proof_verify::Error::TrieRootNotFound) => true,
            RuntimeCallError::StorageRetrieval(_) => false,
            RuntimeCallError::CallProof(err) => err.is_network_problem(),
        }
    }
}

/// Error that can happen when calling [`RuntimeService::metadata`].
#[derive(Debug, derive_more::Display)]
pub enum MetadataError {
    /// Error during the runtime call.
    #[display(fmt = "{}", _0)]
    CallError(RuntimeCallError),
    /// Runtime of the best block isn't valid.
    #[display(fmt = "Runtime of the best block isn't valid: {}", _0)]
    InvalidRuntime(RuntimeError),
    /// Error in the metadata-specific runtime API.
    #[display(fmt = "Error in the metadata-specific runtime API: {}", _0)]
    MetadataQuery(metadata::Error),
}

/// Error that can happen when calling [`RuntimeService::runtime_version_of_block`].
#[derive(Debug, derive_more::Display)]
pub enum RuntimeVersionOfBlockError {
    /// Runtime of the best block isn't valid.
    #[display(fmt = "Runtime of the best block isn't valid: {}", _0)]
    InvalidRuntime(RuntimeError),
    /// Error while performing the block request on the network.
    NetworkBlockRequest, // TODO: precise error
    /// Failed to decode the header of the block.
    #[display(fmt = "Failed to decode header of the block: {}", _0)]
    InvalidBlockHeader(header::Error),
    /// Error while querying the storage of the block.
    #[display(fmt = "Error while querying block storage: {}", _0)]
    StorageQuery(sync_service::StorageQueryError),
}

struct Guarded {
    /// List of senders that get notified when the runtime specs of the best block changes.
    /// Whenever [`Runtime::runtime`] is updated, one should emit an item on each
    /// sender.
    /// See [`RuntimeService::subscribe_runtime_version`].
    runtime_version_subscriptions:
        Vec<lossy_channel::Sender<Result<executor::CoreVersion, RuntimeError>>>,

    /// List of senders that get notified when the best block is updated.
    /// See [`RuntimeService::subscribe_best`].
    best_blocks_subscriptions: Vec<lossy_channel::Sender<Vec<u8>>>,

    /// Return value of calling [`sync_service::SyncService::is_near_head_of_chain_heuristic`]
    /// after the latest best block update.
    best_near_head_of_chain: bool,

    /// List of all compiled runtime. Referenced by the various blocks below.
    runtimes: slab::Slab<Runtime>,

    /// State of the finalized block reported through the public API of the runtime service.
    /// This doesn't necessarily match the one of the sync service.
    ///
    /// When not a temporary `Guarded`, The value of [`Block::runtime`] for this block is
    /// guaranteed to be [`RuntimeDownloadState::Finished`].
    finalized_block: Block,

    /// State of all the non-finalized blocks.
    non_finalized_blocks: fork_tree::ForkTree<Block>,

    /// Index within [`Guarded::non_finalized_blocks`] of the current best block. `None` if the
    /// best block is the finalized block.
    ///
    /// When not a temporary `Guarded`, the value of [`Block::runtime`] for this block is
    /// guaranteed to be [`RuntimeDownloadState::Finished`].
    best_block_index: Option<fork_tree::NodeIndex>,

    /// Index within [`Guarded::non_finalized_blocks`] of the finalized block according to the
    /// sync service. `None` if the sync service finalized block is the same as the runtime
    /// service's finalized block.
    ///
    /// If `Some` and when not a temporary `Guarded`, the value of [`Block::runtime`] for this
    /// block is guaranteed to **not** be [`RuntimeDownloadState::Finished`].
    sync_service_finalized_index: Option<fork_tree::NodeIndex>,

    /// Incremented by one and stored within [`Block::sync_service_best_block_report_id`].
    sync_service_best_block_next_report_id: u32,
}

impl Guarded {
    /// Might panic for temporary `Guarded`s.
    fn best_block_runtime_index(&self) -> usize {
        let best_block = if let Some(best_block_index) = self.best_block_index {
            self.non_finalized_blocks.get(best_block_index).unwrap()
        } else {
            &self.finalized_block
        };

        match best_block.runtime {
            Ok(RuntimeDownloadState::Finished(index)) => index,
            // It is guaranteed that the best block's runtime is always in the `Finished` state.
            _ => unreachable!(),
        }
    }

    /// Might panic for temporary `Guarded`s.
    fn best_block_runtime(&self) -> &Runtime {
        let index = self.best_block_runtime_index();
        &self.runtimes[index]
    }

    /// Might panic for temporary `Guarded`s.
    fn best_block_runtime_mut(&mut self) -> &mut Runtime {
        let index = self.best_block_runtime_index();
        &mut self.runtimes[index]
    }

    /// Might panic for temporary `Guarded`s.
    fn finalized_block_runtime_index(&self) -> usize {
        match self.finalized_block.runtime {
            Ok(RuntimeDownloadState::Finished(index)) => index,
            // It is guaranteed that the finalized block's runtime is always in the `Finished`
            // state.
            _ => unreachable!(),
        }
    }

    /// Might panic for temporary `Guarded`s.
    fn finalized_block_runtime(&self) -> &Runtime {
        let index = self.finalized_block_runtime_index();
        &self.runtimes[index]
    }

    /// Might panic for temporary `Guarded`s.
    fn finalized_block_runtime_mut(&mut self) -> &mut Runtime {
        let index = self.finalized_block_runtime_index();
        &mut self.runtimes[index]
    }
}

struct Block {
    /// Hash of the block in question.
    // TODO: redundant with `header`
    hash: [u8; 32],

    /// Header of the block in question.
    /// Guaranteed to always be valid for the runtime service best and finalized blocks. Otherwise,
    /// not guaranteed to be valid.
    header: Vec<u8>,

    /// Runtime information of that block. Shared amongst multiple different blocks.
    runtime: Result<RuntimeDownloadState, BlockRuntimeErr>,

    /// A block with a higher value here has been reported by the sync service as the best block
    /// more recently than a block with a lower value. `0` means never reported as best block.
    sync_service_best_block_report_id: u32,
}

#[derive(Debug)]
enum BlockRuntimeErr {
    /// The header of the block isn't valid, and as such its runtime couldn't be downloaded.
    ///
    /// > **Note**: It is possible for parachains to include blocks with invalid headers, as
    /// >           nothing actually enforces that a parachain's blocks must conform to a certain
    /// >           format.
    InvalidHeader,
}

enum RuntimeDownloadState {
    /// Index within [`Guarded::runtimes`] of this block's runtime.
    Finished(usize),

    /// Runtime is currently being downloaded. The future can be found in
    // [`Background::runtime_downloads`].
    Downloading {
        /// Identifier for this download. Can be found in [`Background::runtime_downloads`].
        /// Attributed from [`Background::next_download_id`]. Multiple different blocks can point
        /// to the same `download_id` when it is known that they point to the same runtime.
        download_id: u64,

        /// State trie root of the block. Necessary in case the download fails and gets restarted.
        state_root: [u8; 32],
    },

    /// Runtime hasn't started being downloaded from the network.
    Unknown {
        /// `true` if it is known that this runtime is the same as its parent's.
        /// If `true`, it is illegal for the parent to be in the state
        /// [`RuntimeDownloadState::Finished`] or [`RuntimeDownloadState::Downloading`].
        ///
        /// When in doubt, `false`.
        ///
        /// Value is irrelevant for the finalized block.
        same_as_parent: bool,

        /// State trie root of the block. Necessary in order to download the runtime.
        state_root: [u8; 32],
    },
}

struct Runtime {
    /// Number of blocks in [`Guarded`] that use this runtime (includes both finalized and
    /// non-finalized blocks).
    num_blocks: NonZeroUsize,

    /// Successfully-compiled runtime and all its information. Can contain an error if an error
    /// happened, including a problem when obtaining the runtime specs or the metadata. It is
    /// better to report to the user an error about for example the metadata not being extractable
    /// compared to returning an obsolete version.
    runtime: Result<SuccessfulRuntime, RuntimeError>,

    /// Undecoded storage value of `:code` corresponding to the [`Runtime::runtime`]
    /// field.
    ///
    /// Can be `None` if the storage is empty, in which case the runtime will have failed to
    /// build.
    // TODO: consider storing hash instead
    runtime_code: Option<Vec<u8>>,

    /// Undecoded storage value of `:heappages` corresponding to the
    /// [`Runtime::runtime`] field.
    ///
    /// Can be `None` if the storage is empty, in which case the runtime will have failed to
    /// build.
    // TODO: consider storing hash instead
    heap_pages: Option<Vec<u8>>,
}

struct SuccessfulRuntime {
    /// Cache of the metadata extracted from the runtime. `None` if unknown.
    ///
    /// This cache is filled lazily whenever it is requested through the public API.
    ///
    /// Note that building the metadata might require access to the storage, just like obtaining
    /// the runtime code. if the runtime code gets an update, we can reasonably assume that the
    /// network is able to serve us the storage of recent blocks, and thus the changes of being
    /// able to build the metadata are very high.
    ///
    /// If the runtime is the one found in the genesis storage, the metadata must have been been
    /// filled using the genesis storage as well. If we build the metadata of the genesis runtime
    /// lazily, chances are that the network wouldn't be able to serve the storage of blocks near
    /// the genesis.
    ///
    /// As documented in the smoldot metadata module, the metadata might access the storage, but
    /// we intentionally don't watch for changes in these storage keys to refresh the metadata.
    metadata: Option<Vec<u8>>,

    /// Runtime specs extracted from the runtime.
    runtime_spec: executor::CoreVersion,

    /// Virtual machine itself, to perform additional calls.
    ///
    /// Always `Some`, except for temporary extractions necessary to execute the VM.
    virtual_machine: Option<executor::host::HostVmPrototype>,
}

impl SuccessfulRuntime {
    async fn from_params(
        log_target: &str,
        code: &Option<Vec<u8>>,
        heap_pages: &Option<Vec<u8>>,
    ) -> Result<Self, RuntimeError> {
        // Since compiling the runtime is a CPU-intensive operation, we yield once before and
        // once after.
        super::yield_once().await;

        let vm = match executor::host::HostVmPrototype::new(
            code.as_ref().ok_or(RuntimeError::CodeNotFound)?,
            executor::storage_heap_pages_to_value(heap_pages.as_deref())
                .map_err(RuntimeError::InvalidHeapPages)?,
            executor::vm::ExecHint::CompileAheadOfTime,
        ) {
            Ok(vm) => vm,
            Err(error) => {
                log::warn!(
                    target: &log_target,
                    "Failed to compile best block runtime: {}",
                    error
                );
                return Err(RuntimeError::Build(error));
            }
        };

        // Since compiling the runtime is a CPU-intensive operation, we yield once before and
        // once after.
        super::yield_once().await;

        let (runtime_spec, vm) = match executor::core_version(vm) {
            (Ok(spec), vm) => (spec, vm),
            (Err(error), _) => {
                log::warn!(
                    target: &log_target,
                    "Failed to call Core_version on runtime: {}",
                    error
                );
                return Err(RuntimeError::CoreVersion(error));
            }
        };

        Ok(SuccessfulRuntime {
            metadata: None,
            runtime_spec,
            virtual_machine: Some(vm),
        })
    }
}

async fn run_background(original_runtime_service: Arc<RuntimeService>) {
    loop {
        // The buffer size should be large enough so that, if the CPU is busy, it doesn't
        // become full before the execution of the runtime service resumes.
        let subscription = original_runtime_service
            .sync_service
            .subscribe_all(16)
            .await;

        // In order to bootstrap the new runtime service, a fresh temporary runtime service is
        // created.
        // Later, when the `Guarded` contains at least a finalized runtime, it will be written
        // over the original runtime service.
        // TODO: if subscription.finalized is equal to current finalized, skip the whole process below?
        let mut background = Background {
            runtime_service: Arc::new(RuntimeService {
                log_target: original_runtime_service.log_target.clone(),
                sync_service: original_runtime_service.sync_service.clone(),
                guarded: Mutex::new(Guarded {
                    best_blocks_subscriptions: Vec::new(),
                    runtime_version_subscriptions: Vec::new(),
                    best_near_head_of_chain: false,
                    runtimes: slab::Slab::with_capacity(4),
                    best_block_index: None,
                    non_finalized_blocks: fork_tree::ForkTree::with_capacity(32),
                    finalized_block: Block {
                        runtime: match header::decode(
                            &subscription.finalized_block_scale_encoded_header,
                        ) {
                            Err(_) => Err(BlockRuntimeErr::InvalidHeader),
                            Ok(header) => Ok(RuntimeDownloadState::Unknown {
                                same_as_parent: false,
                                state_root: *header.state_root,
                            }),
                        },
                        hash: header::hash_from_scale_encoded_header(
                            &subscription.finalized_block_scale_encoded_header,
                        ),
                        header: subscription.finalized_block_scale_encoded_header,
                        sync_service_best_block_report_id: 1,
                    },
                    sync_service_finalized_index: None,
                    sync_service_best_block_next_report_id: 2,
                }),
            }),
            blocks_stream: subscription.new_blocks.boxed(),
            runtime_matches_best_block: false,
            next_download_id: 0,
            runtime_downloads: stream::FuturesUnordered::new(),
        };

        for block in subscription.non_finalized_blocks {
            background.insert_block(block).await;
        }

        background.start_necessary_downloads().await;

        // Inner loop. Process incoming events.
        loop {
            if !Arc::ptr_eq(&background.runtime_service, &original_runtime_service) {
                // The `Background` object is manipulating a temporary runtime service. Check if
                // it is possible to write to the original runtime service.
                let mut temporary_guarded = background.runtime_service.guarded.try_lock().unwrap();
                if matches!(
                    temporary_guarded.finalized_block.runtime,
                    Ok(RuntimeDownloadState::Finished(_))
                ) {
                    debug_assert!(!temporary_guarded.runtimes.is_empty());
                    debug_assert!(temporary_guarded
                        .best_block_index
                        .map_or(true, |idx| matches!(
                            temporary_guarded
                                .non_finalized_blocks
                                .get(idx)
                                .unwrap()
                                .runtime,
                            Ok(RuntimeDownloadState::Finished(_))
                        )));

                    let mut original_guarded = original_runtime_service.guarded.lock().await;
                    let merged_guarded = Guarded {
                        best_blocks_subscriptions: mem::take(
                            &mut original_guarded.best_blocks_subscriptions,
                        ),
                        runtime_version_subscriptions: mem::take(
                            &mut original_guarded.runtime_version_subscriptions,
                        ),
                        best_near_head_of_chain: mem::take(
                            &mut temporary_guarded.best_near_head_of_chain,
                        ),
                        runtimes: mem::take(&mut temporary_guarded.runtimes),
                        best_block_index: temporary_guarded.best_block_index,
                        non_finalized_blocks: mem::take(
                            &mut temporary_guarded.non_finalized_blocks,
                        ),
                        finalized_block: Block {
                            hash: temporary_guarded.finalized_block.hash,
                            header: mem::take(&mut temporary_guarded.finalized_block.header),
                            runtime: mem::replace(
                                &mut temporary_guarded.finalized_block.runtime,
                                Err(BlockRuntimeErr::InvalidHeader),
                            ),
                            sync_service_best_block_report_id: temporary_guarded
                                .finalized_block
                                .sync_service_best_block_report_id,
                        },
                        sync_service_finalized_index: temporary_guarded
                            .sync_service_finalized_index,
                        sync_service_best_block_next_report_id: temporary_guarded
                            .sync_service_best_block_next_report_id,
                    };
                    *original_guarded = merged_guarded;

                    drop(temporary_guarded);
                    background.runtime_service = original_runtime_service.clone();

                    // TODO: notify subscribers of the new best and finalized blocks
                }
            }

            futures::select! {
                notification = background.blocks_stream.next().fuse() => {
                    match notification {
                        None => return,
                        Some(sync_service::Notification::Block(new_block)) =>
                            background.insert_block(new_block).await,
                        Some(sync_service::Notification::Finalized { hash, best_block_hash }) => {
                            background.sync_service_finalize(hash, best_block_hash).await;
                        }
                    };

                    background.start_necessary_downloads().await;
                },
                (download_id, download_result) = background.runtime_downloads.select_next_some() => {
                    match download_result {
                        Ok((storage_code, storage_heap_pages)) => {
                            background.runtime_download_finished(download_id, storage_code, storage_heap_pages).await;
                        }
                        Err(err) => {
                            // TODO: logging
                            background.runtime_download_failure(download_id).await;
                        }
                    }

                    background.start_necessary_downloads().await;
                }
            }
        }
    }
}

struct Background {
    runtime_service: Arc<RuntimeService>,

    /// Stream of blocks updates coming from the sync service.
    /// Initially has a dummy value.
    blocks_stream: Pin<Box<dyn Stream<Item = sync_service::Notification> + Send>>,

    /// List of runtimes currently being downloaded from the network.
    /// For each item, the download id, storage value of `:code`, and storage value of
    /// `:heappages`.
    runtime_downloads: stream::FuturesUnordered<
        future::BoxFuture<
            'static,
            (
                u64,
                Result<(Option<Vec<u8>>, Option<Vec<u8>>), StorageQueryError>,
            ),
        >,
    >,

    /// Identifier to assign to the next download.
    next_download_id: u64,

    /// Set to `true` when we expect the runtime in `guarded` to match the runtime
    /// of the best block. Initially `false`, as `guarded` uses the genesis
    /// runtime.
    runtime_matches_best_block: bool,
}

impl Background {
    /// Injects into the state of `self` a completed runtime download.
    async fn runtime_download_finished(
        &mut self,
        download_id: u64,
        storage_code: Option<Vec<u8>>,
        storage_heap_pages: Option<Vec<u8>>,
    ) {
        let mut guarded = self.runtime_service.guarded.lock().await;
        let guarded = &mut *guarded;

        // Find the number of blocks that are bound to this download.
        debug_assert!(matches!(
            guarded.finalized_block.runtime,
            Ok(RuntimeDownloadState::Finished(_))
        ));
        let num_concerned_blocks = guarded
            .non_finalized_blocks
            .iter_unordered()
            .map(|(_, b)| b)
            .filter(|b| match b.runtime {
                Ok(RuntimeDownloadState::Downloading {
                    download_id: id, ..
                }) if id == download_id => true,
                _ => false,
            })
            .count();
        debug_assert_ne!(num_concerned_blocks, 0);

        // Try find the identifier of an existing runtime that has this code and heap pages. If
        // none is found, compile the runtime.
        // This search is `O(n)`, but considering the very low number of runtimes (most of the
        // time one, occasionally two), this shouldn't be a problem.
        // The runtime's `num_blocks` is also increased by `num_concerned_blocks` here.
        let runtime_index = if let Some((runtime_index, runtime)) = guarded
            .runtimes
            .iter_mut()
            .find(|(_, r)| r.runtime_code == storage_code && r.heap_pages == storage_heap_pages)
        {
            runtime.num_blocks =
                NonZeroUsize::new(runtime.num_blocks.get() + num_concerned_blocks).unwrap();
            runtime_index
        } else {
            let runtime = SuccessfulRuntime::from_params(
                &self.runtime_service.log_target,
                &storage_code,
                &storage_heap_pages,
            )
            .await;

            guarded.runtimes.insert(Runtime {
                num_blocks: NonZeroUsize::new(num_concerned_blocks).unwrap(),
                runtime,
                runtime_code: storage_code,
                heap_pages: storage_heap_pages,
            })
        };

        // Weight of the current runtime service best block, to check whether this successful
        // download updates the runtime service best block.
        let current_runtime_service_best_block_weight = match guarded.best_block_index {
            None => guarded.finalized_block.sync_service_best_block_report_id,
            Some(idx) => {
                guarded
                    .non_finalized_blocks
                    .get(idx)
                    .unwrap()
                    .sync_service_best_block_report_id
            }
        };

        // Update the blocks that were downloading this runtime.
        debug_assert!(matches!(
            guarded.finalized_block.runtime,
            Ok(RuntimeDownloadState::Finished(_))
        ));
        for index in guarded
            .non_finalized_blocks
            .iter_unordered()
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
        {
            if Some(index) == guarded.sync_service_finalized_index {
                // TODO: prune blocks
                // TODO: report new finalized block to subscribers
            }

            let block = guarded.non_finalized_blocks.get_mut(index).unwrap();
            match block.runtime {
                Ok(RuntimeDownloadState::Downloading {
                    download_id: id, ..
                }) if id == download_id => {
                    block.runtime = Ok(RuntimeDownloadState::Finished(runtime_index));
                }
                _ => {}
            }

            debug_assert_ne!(
                block.sync_service_best_block_report_id,
                current_runtime_service_best_block_weight
            );

            if block.sync_service_best_block_report_id > current_runtime_service_best_block_weight {
                guarded.best_block_index = Some(index);
                // TODO: report new best block to subscribers
            }
        }

        // Sanity check.
        debug_assert_eq!(
            guarded
                .runtimes
                .iter()
                .map(|(_, r)| r.num_blocks.get())
                .sum::<usize>(),
            guarded.non_finalized_blocks.len() + 1
        );
    }

    /// Injects into the state of `self` a failed runtime download.
    async fn runtime_download_failure(&mut self, download_id: u64) {
        let mut guarded = self.runtime_service.guarded.lock().await;
        let guarded = &mut *guarded;

        // Update the blocks that were downloading this runtime.
        match guarded.finalized_block.runtime {
            Ok(RuntimeDownloadState::Downloading {
                download_id: id,
                state_root,
            }) if id == download_id => {
                // Note: the value of `same_as_parent` is irrelevant for the finalized block.
                guarded.finalized_block.runtime = Ok(RuntimeDownloadState::Unknown {
                    state_root,
                    same_as_parent: false,
                });
            }
            _ => {}
        }
        for index in guarded
            .non_finalized_blocks
            .iter_unordered()
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
        {
            let block = guarded.non_finalized_blocks.get_mut(index).unwrap();
            match block.runtime {
                Ok(RuntimeDownloadState::Downloading {
                    state_root,
                    download_id: id,
                }) if id == download_id => {
                    block.runtime = Ok(RuntimeDownloadState::Unknown {
                        same_as_parent: todo!(), // TODO: not implemented
                        state_root,
                    });
                }
                _ => {}
            }
        }
    }

    /// Examines the state of `self` and starts downloading runtimes if necessary.
    async fn start_necessary_downloads(&mut self) {
        let runtime_service = self.runtime_service.clone(); // Solves borrow checking errors.
        let mut guarded = runtime_service.guarded.lock().await;

        self.start_necessary_download(&mut *guarded, None).await;
        if let Some(idx) = guarded.sync_service_finalized_index {
            self.start_necessary_download(&mut *guarded, Some(idx))
                .await;
        }

        // TODO: sync service best block
    }

    /// Starts downloading the runtime of the block with the given index, if necessary.
    async fn start_necessary_download(
        &'_ mut self,
        guarded: &'_ mut Guarded,
        block_index: Option<fork_tree::NodeIndex>,
    ) {
        let runtime = match block_index {
            None => &mut guarded.finalized_block.runtime,
            Some(idx) => &mut guarded.non_finalized_blocks.get_mut(idx).unwrap().runtime,
        };

        if let Ok(runtime) = runtime {
            if let RuntimeDownloadState::Unknown { state_root, .. } = *runtime {
                let download_id = self.next_download_id;
                self.next_download_id += 1;

                self.runtime_downloads.push(Box::pin({
                    let sync_service = self.runtime_service.sync_service.clone();
                    let block_hash = guarded.finalized_block.hash;
                    let log_target = self.runtime_service.log_target.clone();

                    async move {
                        let result = sync_service
                            .storage_query(
                                &block_hash,
                                &state_root,
                                iter::once(&b":code"[..]).chain(iter::once(&b":heappages"[..])),
                            )
                            .await;
                        let result = match result {
                            Ok(mut c) => {
                                let heap_pages = c.pop().unwrap();
                                let code = c.pop().unwrap();
                                Ok((code, heap_pages))
                            }
                            Err(error) => {
                                // TODO: log differently
                                log::log!(
                                    target: &log_target,
                                    if error.is_network_problem() {
                                        log::Level::Debug
                                    } else {
                                        log::Level::Warn
                                    },
                                    "Failed to download :code and :heappages of block: {}",
                                    error
                                );
                                Err(error)
                            }
                        };

                        (download_id, result)
                    }
                }));

                *runtime = RuntimeDownloadState::Downloading {
                    download_id,
                    state_root,
                };

                // TODO: update all children that have same as parent to point to the same download
            }
        }
    }

    /// Updates `self` with a new block received from the sync service.
    async fn insert_block(&mut self, new_block: sync_service::BlockNotification) {
        let mut guarded = self.runtime_service.guarded.lock().await;
        let guarded = &mut *guarded;

        // Find the parent of the new block in the list of blocks that we know.
        // It is guaranteed by the API of the sync service for the parent to have been
        // reported before.
        let parent_index = if new_block.parent_hash == guarded.finalized_block.hash {
            None
        } else {
            Some(
                guarded
                    .non_finalized_blocks
                    .find(|b| b.hash == new_block.parent_hash)
                    .unwrap(),
            )
        };

        // When this block is later inserted, value to use for `sync_service_best_block_report_id`.
        let sync_service_best_block_report_id = if new_block.is_new_best {
            let id = guarded.sync_service_best_block_next_report_id;
            guarded.sync_service_best_block_next_report_id += 1;
            id
        } else {
            0
        };

        // In order to fetch the runtime code (below), we need to know the state trie
        // root of the block, which is found in the block's header.
        // Try to decode the new block's header. Failures are handled gracefully by
        // inserting the block but not retrieving its runtime.
        let decoded_header = match header::decode(&new_block.scale_encoded_header) {
            Ok(h) => h,
            Err(err) => {
                guarded.non_finalized_blocks.insert(
                    parent_index,
                    Block {
                        runtime: Err(BlockRuntimeErr::InvalidHeader),
                        hash: header::hash_from_scale_encoded_header(
                            &new_block.scale_encoded_header,
                        ),
                        header: new_block.scale_encoded_header,
                        sync_service_best_block_report_id,
                    },
                );
                return;
            }
        };

        // Since https://github.com/paritytech/substrate/pull/9580 (Sept. 15th 2021),
        // the header contains a digest item indicating that the runtime environment
        // has changed since the parent.
        // However, as this is a recent addition, the absence of this digest item does
        // not necessarily mean that the runtime environment has not changed.
        // For this reason, we add `&& false`. This `&& false` can be removed in the
        // future.
        // TODO: remove `&& false`
        let runtime_environment_update =
            decoded_header.digest.has_runtime_environment_updated() && false;
        if !runtime_environment_update {
            // Runtime of the new block is the same as the parent.
            let parent_runtime = match parent_index {
                None => &guarded.finalized_block.runtime,
                Some(parent_index) => {
                    &guarded
                        .non_finalized_blocks
                        .get(parent_index)
                        .unwrap()
                        .runtime
                }
            };

            // It is possible, however, that the parent's runtime is unknown, in
            // which case we proceed with the rest of the function as if
            // `runtime_environment_update` was `true`.
            match *parent_runtime {
                Ok(RuntimeDownloadState::Unknown { .. }) | Err(_) => {}

                Ok(RuntimeDownloadState::Downloading { download_id, .. }) => {
                    guarded.non_finalized_blocks.insert(
                        parent_index,
                        Block {
                            runtime: Ok(RuntimeDownloadState::Downloading {
                                download_id,
                                state_root: *decoded_header.state_root,
                            }),
                            hash: header::hash_from_scale_encoded_header(
                                &new_block.scale_encoded_header,
                            ),
                            header: new_block.scale_encoded_header,
                            sync_service_best_block_report_id,
                        },
                    );
                    return;
                }

                Ok(RuntimeDownloadState::Finished(runtime_index)) => {
                    guarded.runtimes[runtime_index].num_blocks =
                        NonZeroUsize::new(guarded.runtimes[runtime_index].num_blocks.get() + 1)
                            .unwrap();
                    let inserted_index = guarded.non_finalized_blocks.insert(
                        parent_index,
                        Block {
                            runtime: Ok(RuntimeDownloadState::Finished(runtime_index)),
                            hash: header::hash_from_scale_encoded_header(
                                &new_block.scale_encoded_header,
                            ),
                            header: new_block.scale_encoded_header,
                            sync_service_best_block_report_id,
                        },
                    );

                    // Normally, the runtime service best block is updated to the sync service
                    // best block once the runtime has finished being downloaded.
                    // Since, in this situation, the runtime is "instantaneously downloaded", we
                    // perform the update immediately.
                    if new_block.is_new_best {
                        guarded.best_block_index = Some(inserted_index);
                        // TODO: report to subscribers
                    }

                    return;
                }
            }
        }

        // Insert the new runtime.
        guarded.non_finalized_blocks.insert(
            parent_index,
            Block {
                runtime: Ok(RuntimeDownloadState::Unknown {
                    same_as_parent: !runtime_environment_update,
                    state_root: *decoded_header.state_root,
                }),
                hash: header::hash_from_scale_encoded_header(&new_block.scale_encoded_header),
                header: new_block.scale_encoded_header,
                sync_service_best_block_report_id,
            },
        );
    }

    /// Updates `self` to take into account that the sync service has finalized the given block.
    async fn sync_service_finalize(
        &mut self,
        hash_to_finalize: [u8; 32],
        new_best_block_hash: [u8; 32],
    ) {
        let mut guarded = self.runtime_service.guarded.lock().await;
        let guarded = &mut *guarded;

        // Find the finalized block in the list of blocks that we know.
        // It is guaranteed by the API of the sync service for the block to have been
        // reported before.
        let finalized_node_index = guarded
            .non_finalized_blocks
            .find(|b| b.hash == hash_to_finalize)
            .unwrap();
        guarded.sync_service_finalized_index = Some(finalized_node_index);

        // Find the new best block in the list of blocks that we know.
        // It is guaranteed by the API of the sync service for the block to have been reported
        // before.
        // TODO: don't do that if best block didn't change
        let best_block_report_id = guarded.sync_service_best_block_next_report_id;
        guarded.sync_service_best_block_next_report_id += 1;

        let new_best_block_index = guarded
            .non_finalized_blocks
            .find(|b| b.hash == new_best_block_hash)
            .unwrap();

        guarded
            .non_finalized_blocks
            .get_mut(new_best_block_index)
            .unwrap()
            .sync_service_best_block_report_id = best_block_report_id;
    }

    /// Updates `self` to finalize the given block.
    // TODO: update
    async fn runtime_service_finalize(
        &mut self,
        hash_to_finalize: [u8; 32],
        new_best_block_hash: [u8; 32],
    ) {
        let mut guarded = self.runtime_service.guarded.lock().await;
        let guarded = &mut *guarded;

        // Find the finalized block in the list of blocks that we know.
        // It is guaranteed by the API of the sync service for the block to have been
        // reported before.
        let finalized_node_index = guarded
            .non_finalized_blocks
            .find(|b| b.hash == hash_to_finalize)
            .unwrap();

        // Find the new best block in the list of blocks that we know.
        // It is guaranteed by the API of the sync service for the block to have been reported
        // before.
        guarded.best_block_index = if new_best_block_hash == hash_to_finalize {
            None
        } else {
            Some(
                guarded
                    .non_finalized_blocks
                    .find(|b| b.hash == new_best_block_hash)
                    .unwrap(),
            )
        };

        // Remove from `non_finalized_blocks` the finalized block and all its ancestors.
        for pruned_block in guarded
            .non_finalized_blocks
            .prune_ancestors(finalized_node_index)
        {
            match pruned_block.user_data.runtime {
                Ok(RuntimeDownloadState::Finished(runtime_index)) => {
                    match NonZeroUsize::new(guarded.runtimes[runtime_index].num_blocks.get() - 1) {
                        Some(n) => guarded.runtimes[runtime_index].num_blocks = n,
                        None => {
                            guarded.runtimes.remove(runtime_index);
                        }
                    }
                }
                _ => {}
            }

            if pruned_block.index == finalized_node_index {
                debug_assert_eq!(pruned_block.user_data.hash, hash_to_finalize);
                debug_assert!(pruned_block.is_prune_target_ancestor);
                guarded.finalized_block = pruned_block.user_data;
            }
        }

        // Some sanity checks.
        debug_assert!(guarded
            .non_finalized_blocks
            .get(finalized_node_index)
            .is_none());
        debug_assert_eq!(guarded.finalized_block.hash, hash_to_finalize);
        debug_assert!(guarded.best_block_index.map_or(true, |idx| guarded
            .non_finalized_blocks
            .get(idx)
            .unwrap()
            .hash
            == new_best_block_hash));
        debug_assert_eq!(
            guarded
                .runtimes
                .iter()
                .map(|(_, r)| r.num_blocks.get())
                .sum::<usize>(),
            guarded.non_finalized_blocks.len() + 1
        );

        // TODO: need to report to subscribers
    }
}
