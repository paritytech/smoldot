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

//! Background runtime download service.
//!
//! This service plugs on top of a [`sync_service`], listens for new best blocks and checks
//! whether the runtime has changed in any way. Its objective is to always provide an up-to-date
//! [`executor::host::HostVmPrototype`] ready to be called by other services.
//!
//! # Usage
//!
//! The runtime service lets user subscribe to block updates, similar to the [`sync_service`].
//! These subscriptions are implemented by subscribing to the underlying [`sync_service`] and,
//! for each notification, checking whether the runtime has changed (thanks to the presence or
//! absence of a header digest item), and downloading the runtime code if necessary. Therefore,
//! these notifications might come with a delay compared to directly using the [`sync_service`].
//!
//! If it isn't possible to download the runtime code of a block (for example because peers refuse
//! to answer or have already pruned the block) or if the runtime service already has too many
//! pending downloads, this block is simply not reported on the subscriptions. The download will
//! be repeatedly tried until it succeeds.
//!
//! Consequently, you are strongly encouraged to not use both the [`sync_service`] *and* the
//! [`RuntimeService`] of the same chain. They each provide a consistent view of the chain, but
//! this view isn't necessarily the same on both services.
//!
//! The main service offered by the runtime service is
//! [`RuntimeService::recent_best_block_runtime_lock`], that performs a runtime call on the latest
//! reported best block or more recent.
//!
//! # Blocks pinning
//!
//! Blocks that are reported through [`RuntimeService::subscribe_all`] are automatically *pinned*.
//! If multiple subscriptions exist, each block is pinned once per subscription.
//!
//! As long as a block is pinned, the [`RuntimeService`] is guaranteed to keep in its internal
//! state the runtime of this block and its properties.
//!
//! Blocks must be manually unpinned by calling [`Subscription::unpin_block`].
//! Failing to do so is effectively a memory leak. If the number of pinned blocks becomes too
//! large, the subscription is force-killed by the [`RuntimeService`].
//!

use crate::{sync_service, Platform};

use futures::{
    channel::mpsc,
    lock::{Mutex, MutexGuard},
    prelude::*,
};
use itertools::Itertools as _;
use smoldot::{
    chain::async_tree,
    executor, header,
    informant::{BytesDisplay, HashDisplay},
    network::protocol,
    trie::{self, proof_verify},
};
use std::{collections::BTreeMap, iter, mem, pin::Pin, sync::Arc, time::Duration};

/// Configuration for a runtime service.
pub struct Config<TPlat: Platform> {
    /// Name of the chain, for logging purposes.
    ///
    /// > **Note**: This name will be directly printed out. Any special character should already
    /// >           have been filtered out from this name.
    pub log_name: String,

    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(String, future::BoxFuture<'static, ()>) + Send>,

    /// Service responsible for synchronizing the chain.
    pub sync_service: Arc<sync_service::SyncService<TPlat>>,

    /// Header of the genesis block of the chain, in SCALE encoding.
    pub genesis_block_scale_encoded_header: Vec<u8>,
}

/// Identifies a runtime currently pinned within a [`RuntimeService`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PinnedRuntimeId(u64);

/// See [the module-level documentation](..).
pub struct RuntimeService<TPlat: Platform> {
    /// Target to use for the logs. See [`Config::log_name`].
    log_target: String,

    /// See [`Config::sync_service`].
    sync_service: Arc<sync_service::SyncService<TPlat>>,

    /// Fields behind a `Mutex`. Should only be locked for short-lived operations.
    guarded: Arc<Mutex<Guarded<TPlat>>>,

    /// Handle to abort the background task.
    background_task_abort: future::AbortHandle,
}

impl<TPlat: Platform> RuntimeService<TPlat> {
    /// Initializes a new runtime service.
    ///
    /// The future returned by this function is expected to finish relatively quickly and is
    /// necessary only for locking purposes.
    pub async fn new(mut config: Config<TPlat>) -> Self {
        // Target to use for all the logs of this service.
        let log_target = format!("runtime-{}", config.log_name);

        let best_near_head_of_chain = config.sync_service.is_near_head_of_chain_heuristic().await;

        let tree = {
            let mut tree = async_tree::AsyncTree::new(async_tree::Config {
                finalized_async_user_data: None,
                retry_after_failed: Duration::from_secs(10),
            });
            let node_index = tree.input_insert_block(
                Block {
                    hash: header::hash_from_scale_encoded_header(
                        &config.genesis_block_scale_encoded_header,
                    ),
                    scale_encoded_header: config.genesis_block_scale_encoded_header,
                },
                None,
                false,
                true,
            );
            tree.input_finalize(node_index, node_index);

            GuardedInner::FinalizedBlockRuntimeUnknown { tree: Some(tree) }
        };

        let guarded = Arc::new(Mutex::new(Guarded {
            all_blocks_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                32,
                Default::default(),
            ), // TODO: capacity?
            next_subscription_id: 0,
            best_near_head_of_chain,
            tree,
            runtimes: slab::Slab::with_capacity(2),
            pinned_blocks: BTreeMap::new(),
            pinned_runtimes: hashbrown::HashMap::with_capacity_and_hasher(0, Default::default()), // TODO: capacity?
            next_pinned_runtime_id: 0,
        }));

        // Spawns a task that runs in the background and updates the content of the mutex.
        let background_task_abort;
        (config.tasks_executor)(log_target.clone(), {
            let log_target = log_target.clone();
            let sync_service = config.sync_service.clone();
            let guarded = guarded.clone();
            let (abortable, abort) = future::abortable(async move {
                run_background(log_target, sync_service, guarded).await;
            });
            background_task_abort = abort;
            abortable.map(|_| ()).boxed()
        });

        RuntimeService {
            log_target,
            sync_service: config.sync_service,
            guarded,
            background_task_abort,
        }
    }

    /// Returns the current runtime version, plus an unlimited stream that produces one item every
    /// time the specs of the runtime of the best block are changed.
    ///
    /// The future returned by this function waits until the runtime is available. This can take
    /// a long time.
    ///
    /// The stream can generate an `Err` if the runtime in the best block is invalid.
    ///
    /// The stream is infinite. In other words it is guaranteed to never return `None`.
    pub async fn subscribe_runtime_version(
        &self,
    ) -> (
        Result<executor::CoreVersion, RuntimeError>,
        stream::BoxStream<'static, Result<executor::CoreVersion, RuntimeError>>,
    ) {
        let mut master_stream = stream::unfold(self.guarded.clone(), |guarded| async move {
            let subscribe_all = Self::subscribe_all_inner(&guarded, 16, 32).await;

            // Map of runtimes by hash. Contains all non-finalized blocks runtimes.
            let mut non_finalized_headers =
                hashbrown::HashMap::<
                    [u8; 32],
                    Arc<Result<executor::CoreVersion, RuntimeError>>,
                    fnv::FnvBuildHasher,
                >::with_capacity_and_hasher(16, Default::default());

            let current_finalized_hash = header::hash_from_scale_encoded_header(
                &subscribe_all.finalized_block_scale_encoded_header,
            );
            subscribe_all
                .new_blocks
                .unpin_block(&current_finalized_hash)
                .await;

            non_finalized_headers.insert(
                current_finalized_hash,
                Arc::new(subscribe_all.finalized_block_runtime),
            );

            let mut current_best = None;
            for block in subscribe_all.non_finalized_blocks_ancestry_order {
                let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                subscribe_all.new_blocks.unpin_block(&hash).await;

                if let Some(new_runtime) = block.new_runtime {
                    non_finalized_headers.insert(hash, Arc::new(new_runtime));
                } else {
                    let parent_runtime = non_finalized_headers
                        .get(&block.parent_hash)
                        .unwrap()
                        .clone();
                    non_finalized_headers.insert(hash, parent_runtime);
                }

                if block.is_new_best {
                    debug_assert!(current_best.is_none());
                    current_best = Some(hash);
                }
            }
            let current_best = current_best.unwrap_or(current_finalized_hash);
            let current_best_runtime =
                (**non_finalized_headers.get(&current_best).unwrap()).clone();

            // Turns `subscribe_all.new_blocks` into a stream of headers.
            let substream = stream::unfold(
                (
                    subscribe_all.new_blocks,
                    non_finalized_headers,
                    current_finalized_hash,
                    current_best,
                ),
                |(
                    mut new_blocks,
                    mut non_finalized_headers,
                    mut current_finalized_hash,
                    mut current_best,
                )| async move {
                    loop {
                        match new_blocks.next().await? {
                            Notification::Block(block) => {
                                let hash = header::hash_from_scale_encoded_header(
                                    &block.scale_encoded_header,
                                );
                                new_blocks.unpin_block(&hash).await;

                                if let Some(new_runtime) = block.new_runtime {
                                    non_finalized_headers.insert(hash, Arc::new(new_runtime));
                                } else {
                                    let parent_runtime = non_finalized_headers
                                        .get(&block.parent_hash)
                                        .unwrap()
                                        .clone();
                                    non_finalized_headers.insert(hash, parent_runtime);
                                }

                                if block.is_new_best {
                                    let current_best_runtime =
                                        non_finalized_headers.get(&current_best).unwrap();
                                    let new_best_runtime =
                                        non_finalized_headers.get(&hash).unwrap();
                                    current_best = hash;

                                    if !Arc::ptr_eq(&current_best_runtime, new_best_runtime) {
                                        let runtime = (**new_best_runtime).clone();
                                        break Some((
                                            runtime,
                                            (
                                                new_blocks,
                                                non_finalized_headers,
                                                current_finalized_hash,
                                                current_best,
                                            ),
                                        ));
                                    }
                                }
                            }
                            Notification::Finalized {
                                hash,
                                pruned_blocks,
                                best_block_hash,
                            } => {
                                let current_best_runtime =
                                    non_finalized_headers.get(&current_best).unwrap().clone();
                                let new_best_runtime =
                                    non_finalized_headers.get(&best_block_hash).unwrap().clone();

                                // Clean up the headers we won't need anymore.
                                for pruned_block in pruned_blocks {
                                    let _was_in = non_finalized_headers.remove(&pruned_block);
                                    debug_assert!(_was_in.is_some());
                                }

                                let _ = non_finalized_headers
                                    .remove(&current_finalized_hash)
                                    .unwrap();
                                current_finalized_hash = hash;
                                current_best = best_block_hash;

                                if !Arc::ptr_eq(&current_best_runtime, &new_best_runtime) {
                                    let runtime = (*new_best_runtime).clone();
                                    break Some((
                                        runtime,
                                        (
                                            new_blocks,
                                            non_finalized_headers,
                                            current_finalized_hash,
                                            current_best,
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                },
            );

            // Prepend the current best block to the stream.
            let substream = stream::once(future::ready(current_best_runtime)).chain(substream);
            Some((substream, guarded))
        })
        .flatten()
        .boxed();

        // TODO: we don't dedup blocks; in other words the stream can produce the same block twice if the inner subscription drops

        // Now that we have a stream, extract the first element to be the first value.
        let first_value = master_stream.next().await.unwrap();
        (first_value, master_stream)
    }

    /// Returns the runtime version of the block with the given hash.
    ///
    /// The future returned by this function might take a long time.
    pub async fn runtime_version_of_block(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<executor::CoreVersion, RuntimeCallError> {
        // If the requested block is the best known block, optimize by
        // immediately returning the cached spec.
        // TODO: restore
        /*{
            let guarded = self.guarded.lock().await;
            if guarded.tree.as_ref().unwrap().best_block_hash() == block_hash {
                return guarded
                    .tree
                    .as_ref()
                    .unwrap()
                    .best_block_runtime()
                    .runtime
                    .as_ref()
                    .map(|r| r.runtime_spec.clone())
                    .map_err(|err| RuntimeCallError::InvalidRuntime(err.clone()));
            }
        }*/

        let (_, vm) = self.network_block_info(block_hash).await?;

        let (runtime_spec, _) = match executor::core_version(vm) {
            (Ok(spec), vm) => (spec, vm),
            (Err(error), _) => {
                log::warn!(
                    target: &self.log_target,
                    "Failed to call Core_version on runtime: {}",
                    error
                );
                return Err(RuntimeCallError::InvalidRuntime(RuntimeError::CoreVersion(
                    error,
                )));
            }
        };

        Ok(runtime_spec)
    }

    /// Downloads from the network the SCALE-encoded header and the runtime of the block with
    /// the given hash.
    async fn network_block_info(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<(Vec<u8>, executor::host::HostVmPrototype), RuntimeCallError> {
        // Ask the network for the header of this block, as we need to know the state root.
        let header = {
            let result = self
                .sync_service
                .clone()
                .block_query(
                    *block_hash,
                    protocol::BlocksRequestFields {
                        header: true,
                        body: false,
                        justifications: false,
                    },
                )
                .await;

            // Note that the `block_query` method guarantees that the header is present
            // and valid.
            if let Ok(block) = result {
                block.header.unwrap()
            } else {
                return Err(RuntimeCallError::NetworkBlockRequest); // TODO: precise error
            }
        };

        let state_root = *header::decode(&header)
            .map_err(RuntimeCallError::InvalidBlockHeader)?
            .state_root;

        // Download the runtime code of this block.
        let (code, heap_pages) = {
            let mut code_query_result = self
                .sync_service
                .clone()
                .storage_query(
                    block_hash,
                    &state_root,
                    iter::once(&b":code"[..]).chain(iter::once(&b":heappages"[..])),
                )
                .await
                .map_err(RuntimeCallError::StorageQuery)?;
            let heap_pages = code_query_result.pop().unwrap();
            let code = code_query_result.pop().unwrap();
            (code, heap_pages)
        };

        let vm = match executor::host::HostVmPrototype::new(
            code.as_ref()
                .ok_or(RuntimeError::CodeNotFound)
                .map_err(RuntimeCallError::InvalidRuntime)?,
            executor::storage_heap_pages_to_value(heap_pages.as_deref())
                .map_err(RuntimeError::InvalidHeapPages)
                .map_err(RuntimeCallError::InvalidRuntime)?,
            executor::vm::ExecHint::CompileAheadOfTime,
        ) {
            Ok(vm) => vm,
            Err(error) => {
                log::warn!(
                    target: &self.log_target,
                    "Failed to compile best block runtime: {}",
                    error
                );
                return Err(RuntimeCallError::InvalidRuntime(RuntimeError::Build(error)));
            }
        };

        Ok((header, vm))
    }

    /// Returns the runtime version of the current best block.
    ///
    /// The future returned by this function might take a long time.
    pub async fn best_block_runtime(&self) -> Result<executor::CoreVersion, RuntimeError> {
        self.subscribe_all(0, 0).await.finalized_block_runtime
    }

    /// Returns the SCALE-encoded header of the current finalized block, plus an unlimited stream
    /// that produces one item every time the finalized block is changed.
    ///
    /// This function only returns once the runtime of the current finalized block is known. This
    /// might take a long time.
    pub async fn subscribe_finalized(&self) -> (Vec<u8>, stream::BoxStream<'static, Vec<u8>>) {
        let mut master_stream = stream::unfold(self.guarded.clone(), |guarded| async move {
            let subscribe_all = Self::subscribe_all_inner(&guarded, 16, 48).await;

            // Map of block headers by hash. Contains all non-finalized blocks headers.
            let mut non_finalized_headers = hashbrown::HashMap::<
                [u8; 32],
                Vec<u8>,
                fnv::FnvBuildHasher,
            >::with_capacity_and_hasher(
                16, Default::default()
            );

            subscribe_all
                .new_blocks
                .unpin_block(&header::hash_from_scale_encoded_header(
                    &subscribe_all.finalized_block_scale_encoded_header,
                ))
                .await;

            for block in subscribe_all.non_finalized_blocks_ancestry_order {
                let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                subscribe_all.new_blocks.unpin_block(&hash).await;
                non_finalized_headers.insert(hash, block.scale_encoded_header);
            }

            // Turns `subscribe_all.new_blocks` into a stream of headers.
            let substream = stream::unfold(
                (subscribe_all.new_blocks, non_finalized_headers),
                |(mut new_blocks, mut non_finalized_headers)| async {
                    loop {
                        match new_blocks.next().await? {
                            Notification::Block(block) => {
                                let hash = header::hash_from_scale_encoded_header(
                                    &block.scale_encoded_header,
                                );
                                new_blocks.unpin_block(&hash).await;
                                non_finalized_headers.insert(hash, block.scale_encoded_header);
                            }
                            Notification::Finalized {
                                hash,
                                pruned_blocks,
                                ..
                            } => {
                                // Clean up the headers we won't need anymore.
                                for pruned_block in pruned_blocks {
                                    let _was_in = non_finalized_headers.remove(&pruned_block);
                                    debug_assert!(_was_in.is_some());
                                }

                                let header = non_finalized_headers.remove(&hash).unwrap();
                                break Some((header, (new_blocks, non_finalized_headers)));
                            }
                        }
                    }
                },
            );

            // Prepend the current finalized block to the stream.
            let substream = stream::once(future::ready(
                subscribe_all.finalized_block_scale_encoded_header,
            ))
            .chain(substream);

            Some((substream, guarded))
        })
        .flatten()
        .boxed();

        // TODO: we don't dedup blocks; in other words the stream can produce the same block twice if the inner subscription drops

        // Now that we have a stream, extract the first element to be the first value.
        let first_value = master_stream.next().await.unwrap();
        (first_value, master_stream)
    }

    /// Returns the SCALE-encoded header of the current best block, plus an unlimited stream that
    /// produces one item every time the best block is changed.
    ///
    /// This function only returns once the runtime of the current best block is known. This might
    /// take a long time.
    ///
    /// It is guaranteed that when a notification is sent out, calling
    /// [`RuntimeService::recent_best_block_runtime_lock`] will operate on this block or more
    /// recent. In other words, if you call [`RuntimeService::recent_best_block_runtime_lock`] and
    /// the stream of notifications is empty, you are guaranteed that the call has been performed
    /// on the best block.
    pub async fn subscribe_best(&self) -> (Vec<u8>, stream::BoxStream<'static, Vec<u8>>) {
        let mut master_stream = stream::unfold(self.guarded.clone(), |guarded| async move {
            let subscribe_all = Self::subscribe_all_inner(&guarded, 16, 48).await;

            // Map of block headers by hash. Contains all non-finalized blocks headers.
            let mut non_finalized_headers = hashbrown::HashMap::<
                [u8; 32],
                Vec<u8>,
                fnv::FnvBuildHasher,
            >::with_capacity_and_hasher(
                16, Default::default()
            );

            let current_finalized_hash = header::hash_from_scale_encoded_header(
                &subscribe_all.finalized_block_scale_encoded_header,
            );

            subscribe_all
                .new_blocks
                .unpin_block(&current_finalized_hash)
                .await;

            non_finalized_headers.insert(
                current_finalized_hash,
                subscribe_all.finalized_block_scale_encoded_header,
            );

            let mut current_best = None;
            for block in subscribe_all.non_finalized_blocks_ancestry_order {
                let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                subscribe_all.new_blocks.unpin_block(&hash).await;
                non_finalized_headers.insert(hash, block.scale_encoded_header);

                if block.is_new_best {
                    debug_assert!(current_best.is_none());
                    current_best = Some(hash);
                }
            }
            let current_best = current_best.unwrap_or(current_finalized_hash);
            let current_best_header = non_finalized_headers.get(&current_best).unwrap().clone();

            // Turns `subscribe_all.new_blocks` into a stream of headers.
            let substream = stream::unfold(
                (
                    subscribe_all.new_blocks,
                    non_finalized_headers,
                    current_finalized_hash,
                    current_best,
                ),
                |(
                    mut new_blocks,
                    mut non_finalized_headers,
                    mut current_finalized_hash,
                    mut current_best,
                )| async move {
                    loop {
                        match new_blocks.next().await? {
                            Notification::Block(block) => {
                                let hash = header::hash_from_scale_encoded_header(
                                    &block.scale_encoded_header,
                                );
                                new_blocks.unpin_block(&hash).await;
                                non_finalized_headers.insert(hash, block.scale_encoded_header);

                                if block.is_new_best {
                                    current_best = hash;
                                    let header =
                                        non_finalized_headers.get(&current_best).unwrap().clone();
                                    break Some((
                                        header,
                                        (
                                            new_blocks,
                                            non_finalized_headers,
                                            current_finalized_hash,
                                            current_best,
                                        ),
                                    ));
                                }
                            }
                            Notification::Finalized {
                                hash,
                                pruned_blocks,
                                best_block_hash,
                            } => {
                                // Clean up the headers we won't need anymore.
                                for pruned_block in pruned_blocks {
                                    let _was_in = non_finalized_headers.remove(&pruned_block);
                                    debug_assert!(_was_in.is_some());
                                }

                                let _ = non_finalized_headers
                                    .remove(&current_finalized_hash)
                                    .unwrap();
                                current_finalized_hash = hash;

                                if best_block_hash != current_best {
                                    current_best = best_block_hash;
                                    let header =
                                        non_finalized_headers.get(&current_best).unwrap().clone();
                                    break Some((
                                        header,
                                        (
                                            new_blocks,
                                            non_finalized_headers,
                                            current_finalized_hash,
                                            current_best,
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                },
            );

            // Prepend the current best block to the stream.
            let substream = stream::once(future::ready(current_best_header)).chain(substream);
            Some((substream, guarded))
        })
        .flatten()
        .boxed();

        // TODO: we don't dedup blocks; in other words the stream can produce the same block twice if the inner subscription drops

        // Now that we have a stream, extract the first element to be the first value.
        let first_value = master_stream.next().await.unwrap();
        (first_value, master_stream)
    }

    /// Subscribes to the state of the chain: the current state and the new blocks.
    ///
    /// This function only returns once the runtime of the current finalized block is known. This
    /// might take a long time.
    ///
    /// Contrary to [`RuntimeService::subscribe_best`], *all* new blocks are reported. Only up to
    /// `buffer_size` block notifications are buffered in the channel. If the channel is full
    /// when a new notification is attempted to be pushed, the channel gets closed.
    ///
    /// A maximum number of pinned blocks must be passed, indicating the maximum number of blocks
    /// that the runtime service will pin at the same time for this subscription. If this maximum
    /// is reached, the channel will get closed.
    ///
    /// The channel also gets closed if a gap in the finality happens, such as after a Grandpa
    /// warp syncing.
    ///
    /// See [`SubscribeAll`] for information about the return value.
    pub async fn subscribe_all(
        &self,
        buffer_size: usize,
        max_pinned_blocks: usize,
    ) -> SubscribeAll<TPlat> {
        Self::subscribe_all_inner(&self.guarded, buffer_size, max_pinned_blocks).await
    }

    async fn subscribe_all_inner(
        guarded: &Arc<Mutex<Guarded<TPlat>>>,
        buffer_size: usize,
        max_pinned_blocks: usize,
    ) -> SubscribeAll<TPlat> {
        // First, lock `guarded` and wait for the tree to be in `FinalizedBlockRuntimeKnown` mode.
        // This can take a long time.
        let mut guarded_lock = loop {
            let mut guarded_lock = guarded.lock().await;

            match &guarded_lock.tree {
                GuardedInner::FinalizedBlockRuntimeKnown { .. } => break guarded_lock,
                GuardedInner::FinalizedBlockRuntimeUnknown { .. } => {
                    let (tx, mut rx) = mpsc::channel(0);
                    let subscription_id = guarded_lock.next_subscription_id;
                    guarded_lock.next_subscription_id += 1;
                    guarded_lock
                        .all_blocks_subscriptions
                        .insert(subscription_id, (tx, 8));
                    drop(guarded_lock);
                    let _ = rx.next().await;
                }
            }
        };
        let mut guarded_lock = &mut *guarded_lock;

        let (mut tx, new_blocks_channel) = mpsc::channel(buffer_size);
        let subscription_id = guarded_lock.next_subscription_id;
        guarded_lock.next_subscription_id += 1;

        let non_finalized_blocks_ancestry_order: Vec<_> = match &guarded_lock.tree {
            GuardedInner::FinalizedBlockRuntimeKnown {
                tree,
                finalized_block,
            } => {
                guarded_lock.runtimes[*tree.finalized_async_user_data()].num_references += 1;
                guarded_lock.pinned_blocks.insert(
                    (subscription_id, finalized_block.hash),
                    (
                        *tree.finalized_async_user_data(),
                        finalized_block.scale_encoded_header.clone(),
                    ),
                );

                tree.input_iter_ancestry_order()
                    .filter_map(|block| {
                        let runtime_index = *block.async_op_user_data?;
                        let block_hash = block.user_data.hash;
                        let parent_runtime_index = tree
                            .parent(block.id)
                            .map_or(*tree.finalized_async_user_data(), |parent_idx| {
                                *tree.block_async_user_data(parent_idx).unwrap()
                            });

                        let parent_hash = *header::decode(&block.user_data.scale_encoded_header)
                            .unwrap()
                            .parent_hash; // TODO: correct? if yes, document
                        debug_assert!(
                            parent_hash == finalized_block.hash
                                || tree
                                    .input_iter_ancestry_order()
                                    .any(|b| parent_hash == b.user_data.hash
                                        && b.async_op_user_data.is_some())
                        );

                        guarded_lock.runtimes[runtime_index].num_references += 1;
                        guarded_lock.pinned_blocks.insert(
                            (subscription_id, block_hash),
                            (runtime_index, block.user_data.scale_encoded_header.clone()),
                        );

                        Some(BlockNotification {
                            is_new_best: block.is_output_best,
                            parent_hash,
                            scale_encoded_header: block.user_data.scale_encoded_header.clone(),
                            new_runtime: if runtime_index != parent_runtime_index {
                                Some(
                                    guarded_lock.runtimes[runtime_index]
                                        .runtime
                                        .as_ref()
                                        .map(|rt| rt.runtime_spec.clone())
                                        .map_err(|err| err.clone()),
                                )
                            } else {
                                None
                            },
                        })
                    })
                    .collect()
            }
            _ => unreachable!(),
        };

        debug_assert!(matches!(
            non_finalized_blocks_ancestry_order
                .iter()
                .filter(|b| b.is_new_best)
                .count(),
            0 | 1
        ));

        // If the requested maximum number of pinned blocks is too low, we pretend that this
        // maximum number was just enough by insert `0` remaining pinned blocks, but we also close
        // the subscription immediately to mimic the effects of not having enough pinned blocks
        // remaining.
        //
        // It could also in principle be possible to not insert in `all_blocks_subscriptions` at,
        // all but this would require cleaning up all the other modifications we've done to
        // guarded`. By inserting a closed channel, we reuse the same code as the one that purges
        // closed channels.
        guarded_lock
            .all_blocks_subscriptions
            .insert(subscription_id, {
                if let Some(pinned_remaining) =
                    max_pinned_blocks.checked_sub(1 + non_finalized_blocks_ancestry_order.len())
                {
                    (tx, pinned_remaining)
                } else {
                    tx.close_channel();
                    (tx, 0)
                }
            });

        SubscribeAll {
            finalized_block_scale_encoded_header: match &guarded_lock.tree {
                GuardedInner::FinalizedBlockRuntimeKnown {
                    finalized_block, ..
                } => finalized_block.scale_encoded_header.clone(),
                _ => unreachable!(),
            },
            finalized_block_runtime: if let GuardedInner::FinalizedBlockRuntimeKnown {
                tree, ..
            } = &guarded_lock.tree
            {
                guarded_lock.runtimes[*tree.finalized_async_user_data()]
                    .runtime
                    .as_ref()
                    .map(|rt| rt.runtime_spec.clone())
                    .map_err(|err| err.clone())
            } else {
                unreachable!()
            },
            non_finalized_blocks_ancestry_order,
            new_blocks: Subscription {
                subscription_id,
                channel: new_blocks_channel,
                guarded: guarded.clone(),
            },
        }
    }

    /// Unpins a block after it has been reported by a subscription.
    ///
    /// Has no effect if the [`SubscriptionId`] is not or no longer valid (as the runtime service
    /// can kill any subscription at any moment).
    ///
    /// # Panic
    ///
    /// Panics if the block hash has not been reported or has already been unpinned.
    ///
    #[track_caller]
    pub async fn unpin_block(&self, subscription_id: SubscriptionId, block_hash: &[u8; 32]) {
        Self::unpin_block_inner(&self.guarded, subscription_id, block_hash).await
    }

    #[track_caller]
    async fn unpin_block_inner(
        guarded: &Arc<Mutex<Guarded<TPlat>>>,
        subscription_id: SubscriptionId,
        block_hash: &[u8; 32],
    ) {
        let mut guarded_lock = guarded.lock().await;

        let (runtime_index, _scale_encoded_header) = match guarded_lock
            .pinned_blocks
            .remove(&(subscription_id.0, *block_hash))
        {
            Some(b) => b,
            None => {
                // Cold path.
                if guarded_lock
                    .all_blocks_subscriptions
                    .contains_key(&subscription_id.0)
                {
                    panic!("block already unpinned");
                } else {
                    return;
                }
            }
        };

        if guarded_lock.runtimes[runtime_index].num_references == 1 {
            guarded_lock.runtimes.remove(runtime_index);
        } else {
            guarded_lock.runtimes[runtime_index].num_references -= 1;
        }

        debug_assert_eq!(
            header::hash_from_scale_encoded_header(&_scale_encoded_header),
            *block_hash
        );

        let (_, pinned_remaining) = guarded_lock
            .all_blocks_subscriptions
            .get_mut(&subscription_id.0)
            .unwrap();
        *pinned_remaining += 1;
    }

    // TODO: doc
    pub async fn recent_best_block_runtime_lock<'a>(&'a self) -> RuntimeLock<'a, TPlat> {
        // TODO: clean up implementation
        let (_, mut notifs) = self.subscribe_best().await;

        let (guarded, block_index) = loop {
            let guarded = self.guarded.lock().await;
            match &guarded.tree {
                GuardedInner::FinalizedBlockRuntimeKnown { tree, .. } => {
                    let index = tree.best_block_index().map(|(idx, _)| idx);
                    break (guarded, index);
                }
                GuardedInner::FinalizedBlockRuntimeUnknown { .. } => {}
            };

            // Wait for the best block to change.
            drop::<MutexGuard<_>>(guarded);
            let _ = notifs.next().await;
        };

        RuntimeLock {
            service: self,
            guarded,
            inner: if let Some(block_index) = block_index {
                RuntimeLockInner::InTree { block_index }
            } else {
                RuntimeLockInner::Finalized
            },
        }
    }

    /// Lock the runtime service and prepare a call to a runtime entry point.
    ///
    /// The hash of the block passed as parameter corresponds to the block whose runtime to use
    /// to make the call. The block must be currently pinned in the context of the provided
    /// [`SubscriptionId`].
    ///
    /// # Panic
    ///
    /// Panics if the given block isn't currently pinned by the given subscription.
    ///
    pub async fn pinned_block_runtime_call_lock<'a>(
        &'a self,
        subscription_id: SubscriptionId,
        block_hash: &[u8; 32],
    ) -> RuntimeLock<'a, TPlat> {
        let guarded = self.guarded.lock().await;

        let (runtime_index, scale_encoded_header) = (*guarded
            .pinned_blocks
            .get(&(subscription_id.0, *block_hash))
            .unwrap())
        .clone();

        RuntimeLock {
            service: self,
            guarded,
            inner: RuntimeLockInner::OutOfTree {
                hash: *block_hash,
                scale_encoded_header,
                runtime_index,
            },
        }
    }

    /// Lock the runtime service and prepare a call to a runtime entry point.
    ///
    /// The hash of the block passed as parameter corresponds to the block whose runtime to use
    /// to make the call. The block must be currently pinned in the context of the provided
    /// [`SubscriptionId`].
    ///
    /// # Panic
    ///
    /// Panics if the given block isn't currently pinned by the given subscription.
    ///
    pub async fn pinned_runtime_call_lock<'a>(
        &'a self,
        _pinned_runtime_id: PinnedRuntimeId,
        _block_hash: [u8; 32],
        _block_number: u64,
        _block_state_trie_root_hash: [u8; 32],
    ) -> RuntimeLock<'a, TPlat> {
        todo!()
        /*let guarded = self.guarded.lock().await;

        let runtime_index = *guarded.pinned_runtimes.get(&pinned_runtime_id.0).unwrap();

        RuntimeLock {
            service: self,
            guarded,
            inner: RuntimeLockInner::OutOfTree {
                hash: block_hash,
                scale_encoded_header: todo!(),  // TODO: not implementable at the moment
                runtime_index,
            },
        }*/
    }

    /// Tries to find a runtime within the [`RuntimeService`] that has the given storage code and
    /// heap pages. If none is found, compiles the runtime and stores it within the
    /// [`RuntimeService`]. In both cases, it is kept pinned until it is unpinned with
    /// [`RuntimeService::unpin_runtime`].
    pub async fn compile_and_pin_runtime(
        &self,
        storage_code: Option<Vec<u8>>,
        storage_heap_pages: Option<Vec<u8>>,
    ) -> PinnedRuntimeId {
        let mut guarded = self.guarded.lock().await;

        // Try to find an existing identical runtime.
        let existing_runtime = guarded
            .runtimes
            .iter()
            .find(|(_, rt)| rt.runtime_code == storage_code && rt.heap_pages == storage_heap_pages)
            .map(|(id, _)| id);

        let runtime_index = if let Some(existing_runtime) = existing_runtime {
            existing_runtime
        } else {
            // No identical runtime was found. Try compiling the new runtime.
            let runtime = SuccessfulRuntime::from_storage(&storage_code, &storage_heap_pages).await;
            guarded.runtimes.insert(Runtime {
                num_references: 0, // Incremented below.
                heap_pages: storage_heap_pages,
                runtime_code: storage_code,
                runtime,
            })
        };

        guarded.runtimes[runtime_index].num_references += 1;

        let pinned_runtime_id = guarded.next_pinned_runtime_id;
        guarded.next_pinned_runtime_id += 1;

        let _previous_value = guarded
            .pinned_runtimes
            .insert(pinned_runtime_id, runtime_index);
        debug_assert!(_previous_value.is_none());

        PinnedRuntimeId(pinned_runtime_id)
    }

    /// Un-pins a previously-pinned runtime.
    ///
    /// # Panic
    ///
    /// Panics if the provided [`PinnedRuntimeId`] is stale or invalid.
    ///
    pub async fn unpin_runtime(&self, id: PinnedRuntimeId) {
        let mut guarded = self.guarded.lock().await;

        let runtime_index = guarded.pinned_runtimes.remove(&id.0).unwrap();
        if guarded.runtimes[runtime_index].num_references == 1 {
            guarded.runtimes.remove(runtime_index);
        } else {
            guarded.runtimes[runtime_index].num_references -= 1;
        }
    }

    /// Returns true if it is believed that we are near the head of the chain.
    ///
    /// The way this method is implemented is opaque and cannot be relied on. The return value
    /// should only ever be shown to the user and not used for any meaningful logic.
    pub async fn is_near_head_of_chain_heuristic(&self) -> bool {
        is_near_head_of_chain_heuristic(&self.sync_service, &self.guarded).await
    }
}

impl<TPlat: Platform> Drop for RuntimeService<TPlat> {
    fn drop(&mut self) {
        self.background_task_abort.abort();
    }
}

/// Return value of [`RuntimeService::subscribe_all`].
pub struct SubscribeAll<TPlat: Platform> {
    /// SCALE-encoded header of the finalized block at the time of the subscription.
    pub finalized_block_scale_encoded_header: Vec<u8>,

    /// If the runtime of the finalized block is known, contains the information about it.
    pub finalized_block_runtime: Result<executor::CoreVersion, RuntimeError>,

    /// List of all known non-finalized blocks at the time of subscription.
    ///
    /// Only one element in this list has [`BlockNotification::is_new_best`] equal to true.
    ///
    /// The blocks are guaranteed to be ordered so that parents are always found before their
    /// children.
    pub non_finalized_blocks_ancestry_order: Vec<BlockNotification>,

    /// Channel onto which new blocks are sent. The channel gets closed if it is full when a new
    /// block needs to be reported.
    pub new_blocks: Subscription<TPlat>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId(u64);

pub struct Subscription<TPlat: Platform> {
    subscription_id: u64,
    channel: mpsc::Receiver<Notification>,
    guarded: Arc<Mutex<Guarded<TPlat>>>,
}

impl<TPlat: Platform> Subscription<TPlat> {
    pub async fn next(&mut self) -> Option<Notification> {
        self.channel.next().await
    }

    /// Returns an opaque identifier that can be used to call [`RuntimeService::unpin_block`].
    pub fn id(&self) -> SubscriptionId {
        SubscriptionId(self.subscription_id)
    }

    /// Unpins a block after it has been reported.
    ///
    /// # Panic
    ///
    /// Panics if the block hash has not been reported or has already been unpinned.
    ///
    pub async fn unpin_block(&self, block_hash: &[u8; 32]) {
        RuntimeService::unpin_block_inner(
            &self.guarded,
            SubscriptionId(self.subscription_id),
            block_hash,
        )
        .await
    }
}

/// Notification about a new block or a new finalized block.
///
/// See [`RuntimeService::subscribe_all`].
#[derive(Debug, Clone)]
pub enum Notification {
    /// A non-finalized block has been finalized.
    Finalized {
        /// Blake2 hash of the header of the block that has been finalized.
        ///
        /// A block with this hash is guaranteed to have earlier been reported in a
        /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks_ancestry_order`]
        /// or in a [`Notification::Block`].
        ///
        /// It is also guaranteed that this block is a child of the previously-finalized block. In
        /// other words, if multiple blocks are finalized at the same time, only one
        /// [`Notification::Finalized`] is generated and contains the highest finalized block.
        ///
        /// If it is not possible for the [`RuntimeService`] to avoid a gap in the list of
        /// finalized blocks, then the [`SubscribeAll::new_blocks`] channel is force-closed.
        hash: [u8; 32],

        /// Hash of the header of the best block after the finalization.
        ///
        /// If the newly-finalized block is an ancestor of the current best block, then this field
        /// contains the hash of this current best block. Otherwise, the best block is now
        /// the non-finalized block with the given hash.
        ///
        /// A block with this hash is guaranteed to have earlier been reported in a
        /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks_ancestry_order`]
        /// or in a [`Notification::Block`].
        best_block_hash: [u8; 32],

        /// List of blake2 hashes of the headers of the blocks that have been discarded because
        /// they're not descendants of the newly-finalized block.
        ///
        /// This list contains all the siblings of the newly-finalized block and all their
        /// descendants.
        pruned_blocks: Vec<[u8; 32]>,
    },

    /// A new block has been added to the list of unfinalized blocks.
    Block(BlockNotification),
}

/// Notification about a new block.
///
/// See [`RuntimeService::subscribe_all`].
#[derive(Debug, Clone)]
pub struct BlockNotification {
    /// True if this block is considered as the best block of the chain.
    pub is_new_best: bool,

    /// SCALE-encoded header of the block.
    pub scale_encoded_header: Vec<u8>,

    /// Blake2 hash of the header of the parent of this block.
    ///
    ///
    /// A block with this hash is guaranteed to have earlier been reported in a
    /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks_ancestry_order`] or
    /// in a [`Notification::Block`].
    ///
    /// > **Note**: The header of a block contains the hash of its parent. When it comes to
    /// >           consensus algorithms such as Babe or Aura, the syncing code verifies that this
    /// >           hash, stored in the header, actually corresponds to a valid block. However,
    /// >           when it comes to parachain consensus, no such verification is performed.
    /// >           Contrary to the hash stored in the header, the value of this field is
    /// >           guaranteed to refer to a block that is known by the syncing service. This
    /// >           allows a subscriber of the state of the chain to precisely track the hierarchy
    /// >           of blocks, without risking to run into a problem in case of a block with an
    /// >           invalid header.
    pub parent_hash: [u8; 32],

    /// If the runtime of the block is different from its parent, contains the information about
    /// the new runtime.
    pub new_runtime: Option<Result<executor::CoreVersion, RuntimeError>>,
}

async fn is_near_head_of_chain_heuristic<TPlat: Platform>(
    sync_service: &sync_service::SyncService<TPlat>,
    guarded: &Mutex<Guarded<TPlat>>,
) -> bool {
    // The runtime service adds a delay between the moment a best block is reported by the
    // sync service and the moment it is reported by the runtime service.
    // Because of this, any "far from head of chain" to "near head of chain" transition
    // must take that delay into account. The other way around ("near" to "far") is
    // unaffected.

    // If the sync service is far from the head, the runtime service is also far.
    if !sync_service.is_near_head_of_chain_heuristic().await {
        return false;
    }

    // If the sync service is near, report the result of `is_near_head_of_chain_heuristic()`
    // when called at the latest best block that the runtime service reported through its API,
    // to make sure that we don't report "near" while having reported only blocks that were
    // far.
    guarded.lock().await.best_near_head_of_chain
}

/// See [`RuntimeService::recent_best_block_runtime_lock`].
#[must_use]
pub struct RuntimeLock<'a, TPlat: Platform> {
    service: &'a RuntimeService<TPlat>,
    guarded: MutexGuard<'a, Guarded<TPlat>>, // TODO: is the lock actually necessary? maybe we can just increase the reference count of the runtime instead, and clone the header+hash
    inner: RuntimeLockInner,
}

enum RuntimeLockInner {
    /// Call made against [`GuardedInner::FinalizedBlockRuntimeKnown::finalized_block`].
    Finalized,
    /// Block is found in the tree at the given index.
    InTree {
        /// Index of the block to make the call against.
        block_index: async_tree::NodeIndex,
    },
    /// Block information directly inlined in this enum.
    OutOfTree {
        scale_encoded_header: Vec<u8>,
        hash: [u8; 32],
        runtime_index: usize, // TODO: increase the num_references of this runtime beforehand?
    },
}

impl<'a, TPlat: Platform> RuntimeLock<'a, TPlat> {
    /// Returns the SCALE-encoded header of the block the call is being made against.
    ///
    /// Guaranteed to always be valid.
    pub fn block_scale_encoded_header(&self) -> &[u8] {
        match &self.inner {
            RuntimeLockInner::Finalized => match &self.guarded.tree {
                GuardedInner::FinalizedBlockRuntimeKnown {
                    finalized_block, ..
                } => &finalized_block.scale_encoded_header[..],
                _ => unreachable!(),
            },
            RuntimeLockInner::InTree { block_index } => match &self.guarded.tree {
                GuardedInner::FinalizedBlockRuntimeKnown { tree, .. } => {
                    &tree.block_user_data(*block_index).scale_encoded_header[..]
                }
                GuardedInner::FinalizedBlockRuntimeUnknown { tree: Some(tree) } => {
                    &tree.block_user_data(*block_index).scale_encoded_header[..]
                }
                _ => unreachable!(),
            },
            RuntimeLockInner::OutOfTree {
                scale_encoded_header,
                ..
            } => &scale_encoded_header[..],
        }
    }

    /// Returns the hash of the block the call is being made against.
    pub fn block_hash(&self) -> &[u8; 32] {
        match &self.inner {
            RuntimeLockInner::Finalized => match &self.guarded.tree {
                GuardedInner::FinalizedBlockRuntimeKnown {
                    finalized_block, ..
                } => &finalized_block.hash,
                _ => unreachable!(),
            },
            RuntimeLockInner::InTree { block_index } => match &self.guarded.tree {
                GuardedInner::FinalizedBlockRuntimeKnown { tree, .. } => {
                    &tree.block_user_data(*block_index).hash
                }
                GuardedInner::FinalizedBlockRuntimeUnknown { tree: Some(tree) } => {
                    &tree.block_user_data(*block_index).hash
                }
                _ => unreachable!(),
            },
            RuntimeLockInner::OutOfTree { hash, .. } => hash,
        }
    }

    pub async fn start<'b>(
        self,
        method: &'b str,
        parameter_vectored: impl Iterator<Item = impl AsRef<[u8]>> + Clone + 'b,
    ) -> Result<(RuntimeCallLock<'a, TPlat>, executor::host::HostVmPrototype), RuntimeCallError>
    {
        // TODO: DRY :-/ this whole thing is messy

        let block_number = header::decode(&self.block_scale_encoded_header())
            .unwrap()
            .number;
        let block_hash = *self.block_hash();
        let runtime_block_header = self.block_scale_encoded_header().to_owned(); // TODO: cloning :-/

        // Unlock `guarded` before doing anything that takes a long time, such as the
        // network request below.
        drop(self.guarded);

        // Perform the call proof request.
        // Note that `guarded` is not locked.
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

        let (guarded, virtual_machine) = {
            // Lock `guarded` again now that the call is finished.
            let mut guarded = self.service.guarded.lock().await;

            let runtime_index =
                if let RuntimeLockInner::OutOfTree { runtime_index, .. } = self.inner {
                    Some(runtime_index)
                } else {
                    // It is not guaranteed that the block is still in the tree after the storage
                    // proof has ended.
                    // TODO: solve this better than downloading the runtime below
                    match &guarded.tree {
                        GuardedInner::FinalizedBlockRuntimeKnown {
                            tree,
                            finalized_block,
                            ..
                        } => {
                            if finalized_block.hash == block_hash {
                                Some(*tree.finalized_async_user_data())
                            } else {
                                tree.input_iter_unordered()
                                    .find(|block| block.user_data.hash == block_hash)
                                    .map(|block| *block.async_op_user_data.unwrap())
                            }
                        }
                        GuardedInner::FinalizedBlockRuntimeUnknown { tree: Some(tree) } => tree
                            .input_iter_unordered()
                            .find(|block| block.user_data.hash == block_hash)
                            .map(|block| block.async_op_user_data.unwrap().unwrap()),
                        _ => unreachable!(),
                    }
                };

            match runtime_index {
                Some(runtime_index) => {
                    let virtual_machine = match guarded.runtimes[runtime_index].runtime.as_mut() {
                        Ok(r) => r.virtual_machine.take().unwrap(),
                        Err(err) => {
                            return Err(RuntimeCallError::InvalidRuntime(err.clone()));
                        }
                    };

                    (Some((guarded, runtime_index)), virtual_machine)
                }
                None => {
                    // TODO: remove by increasing the num_references of the runtime before unlocking guarded
                    let (_, virtual_machine) = self.service.network_block_info(&block_hash).await?;
                    (None, virtual_machine)
                }
            }
        };

        let lock = RuntimeCallLock {
            guarded,
            runtime_block_header,
            call_proof,
        };

        Ok((lock, virtual_machine))
    }
}

/// See [`RuntimeService::recent_best_block_runtime_lock`].
#[must_use]
pub struct RuntimeCallLock<'a, TPlat: Platform> {
    /// If `Some`, the virtual machine must be put back in the runtimes at the given index.
    guarded: Option<(MutexGuard<'a, Guarded<TPlat>>, usize)>,
    runtime_block_header: Vec<u8>,
    call_proof: Result<Vec<Vec<u8>>, RuntimeCallError>,
}

impl<'a, TPlat: Platform> RuntimeCallLock<'a, TPlat> {
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
        if let Some((guarded, runtime_index)) = &mut self.guarded {
            guarded.runtimes[*runtime_index]
                .runtime
                .as_mut()
                .unwrap()
                .virtual_machine = Some(vm);
        }
    }
}

impl<'a, TPlat: Platform> Drop for RuntimeCallLock<'a, TPlat> {
    fn drop(&mut self) {
        if let Some((guarded, runtime_index)) = &mut self.guarded {
            let vm = &guarded.runtimes[*runtime_index]
                .runtime
                .as_ref()
                .unwrap()
                .virtual_machine;

            if vm.is_none() {
                // The [`RuntimeCallLock`] has been destroyed without being properly unlocked.
                panic!()
            }
        }
    }
}

/// Error that can happen when calling a runtime function.
// TODO: clean up these errors
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
    /// Error while performing the block request on the network.
    NetworkBlockRequest, // TODO: precise error
    /// Failed to decode the header of the block.
    #[display(fmt = "Failed to decode header of the block: {}", _0)]
    InvalidBlockHeader(header::Error),
    /// Error while querying the storage of the block.
    #[display(fmt = "Error while querying block storage: {}", _0)]
    StorageQuery(sync_service::StorageQueryError),
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
            RuntimeCallError::InvalidBlockHeader(_) => false,
            RuntimeCallError::NetworkBlockRequest => true,
            RuntimeCallError::StorageQuery(err) => err.is_network_problem(),
        }
    }
}

/// Error when analyzing the runtime.
#[derive(Debug, derive_more::Display, Clone)]
pub enum RuntimeError {
    /// The `:code` key of the storage is empty.
    CodeNotFound,
    /// Error while parsing the `:heappages` storage value.
    InvalidHeapPages(executor::InvalidHeapPagesError),
    /// Error while compiling the runtime.
    Build(executor::host::NewErr),
    /// Error when determining the runtime specification.
    CoreVersion(executor::CoreVersionError),
}

struct Guarded<TPlat: Platform> {
    /// List of senders that get notified when new blocks arrive.
    /// See [`RuntimeService::subscribe_all`]. Alongside with each sender, the number of pinned
    /// blocks remaining for this subscription.
    ///
    /// Keys are assigned from [`Guarded::next_subscription_id`].
    all_blocks_subscriptions:
        hashbrown::HashMap<u64, (mpsc::Sender<Notification>, usize), fnv::FnvBuildHasher>,

    /// Identifier of the next subscription for [`Guarded::all_blocks_subscriptions`].
    next_subscription_id: u64,

    /// Return value of calling [`sync_service::SyncService::is_near_head_of_chain_heuristic`]
    /// after the latest best block update.
    best_near_head_of_chain: bool,

    /// List of runtimes referenced by the tree in [`GuardedInner`], by [`Guarded::pinned_blocks`],
    /// and by [`Guarded::pinned_runtimes`].
    runtimes: slab::Slab<Runtime>,

    /// Runtimes pinned by the API user.
    pinned_runtimes: hashbrown::HashMap<u64, usize, fnv::FnvBuildHasher>,

    /// Identifier of the next pinned runtime for [`Guarded::pinned_runtimes`].
    next_pinned_runtime_id: u64,

    /// Tree of blocks received from the sync service. Keeps track of which block has been
    /// reported to the outer API.
    tree: GuardedInner<TPlat>,

    /// List of pinned blocks.
    ///
    /// Every time a block is reported to the API user, it is inserted in this map. The block is
    /// inserted after it has been pushed in the channel, but before it is pulled. Therefore, if
    /// the channel is closed it is the background that needs to purge all blocks from this
    /// container that are no longer relevant.
    ///
    /// Keys are `(subscription_id, block_hash)`. Values are indices within [`Guarded::runtimes`]
    /// and block SCALE-encoded headers.
    // TODO: it seems quite expensive to clone this block header all the time
    pinned_blocks: BTreeMap<(u64, [u8; 32]), (usize, Vec<u8>)>,
}

enum GuardedInner<TPlat: Platform> {
    FinalizedBlockRuntimeKnown {
        /// Tree of blocks. Holds the state of the download of everything. Always `Some` when the
        /// `Mutex` is being locked. Temporarily switched to `None` during some operations.
        ///
        /// The asynchronous operation user data is a `usize` corresponding to the index within
        /// [`Guarded::runtimes`].
        tree: async_tree::AsyncTree<TPlat::Instant, Block, usize>,

        /// Finalized block. Outside of the tree.
        finalized_block: Block,
    },
    FinalizedBlockRuntimeUnknown {
        /// Tree of blocks. Holds the state of the download of everything. Always `Some` when the
        /// `Mutex` is being locked. Temporarily switched to `None` during some operations.
        ///
        /// The finalized block according to the [`async_tree::AsyncTree`] is actually a dummy.
        /// The "real" finalized block is a non-finalized block within this tree.
        ///
        /// The asynchronous operation user data is a `usize` corresponding to the index within
        /// [`Guarded::runtimes`]. The asynchronous operation user data is `None` for the dummy
        /// finalized block.
        // TODO: needs to be Option?
        // TODO: explain better
        tree: Option<async_tree::AsyncTree<TPlat::Instant, Block, Option<usize>>>,
    },
}

#[derive(Clone)]
struct Block {
    /// Hash of the block in question. Redundant with `header`, but the hash is so often needed
    /// that it makes sense to cache it.
    hash: [u8; 32],

    /// Header of the block in question.
    /// Guaranteed to always be valid for the output best and finalized blocks. Otherwise,
    /// not guaranteed to be valid.
    scale_encoded_header: Vec<u8>,
}

async fn run_background<TPlat: Platform>(
    log_target: String,
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    guarded: Arc<Mutex<Guarded<TPlat>>>,
) {
    loop {
        // The buffer size should be large enough so that, if the CPU is busy, it doesn't
        // become full before the execution of the runtime service resumes.
        let subscription = sync_service.subscribe_all(16, true).await;

        log::debug!(
            target: &log_target,
            "Worker <= Reset(finalized_block: {})",
            HashDisplay(&header::hash_from_scale_encoded_header(
                &subscription.finalized_block_scale_encoded_header
            ))
        );

        // Update the state of `guarded` with what we just grabbed.
        //
        // Note that the content of `guarded` is reset unconditionally.
        // It might seem like a good idea to only reset the content of `guarded` if the new
        // subscription has a different finalized block than currently. However, there is
        // absolutely no guarantee for the non-finalized blocks currently in the tree to be a
        // subset or superset of the non-finalized blocks in the new subscription.
        // Using the new subscription but keeping the existing tree could therefore result in
        // state inconsistencies.
        //
        // Additionally, the situation where a subscription is killed but the finalized block
        // didn't change should be extremely rare anyway.
        {
            let mut lock = guarded.lock().await;
            let lock = &mut *lock; // Solves borrow checking issues.

            lock.all_blocks_subscriptions.clear();
            lock.pinned_blocks.clear();
            // TODO: restore
            /*lock.best_near_head_of_chain =
            is_near_head_of_chain_heuristic(&sync_service, &guarded).await;*/

            lock.runtimes = slab::Slab::with_capacity(2); // TODO: hardcoded capacity

            // TODO: DRY below
            if let Some(finalized_block_runtime) = subscription.finalized_block_runtime {
                let finalized_block_hash = header::hash_from_scale_encoded_header(
                    &subscription.finalized_block_scale_encoded_header,
                );

                let storage_code_len = u64::try_from(
                    finalized_block_runtime
                        .storage_code
                        .as_ref()
                        .map_or(0, |v| v.len()),
                )
                .unwrap();

                let runtime = Runtime {
                    num_references: 1, // Added below.
                    runtime_code: finalized_block_runtime.storage_code,
                    heap_pages: finalized_block_runtime.storage_heap_pages,
                    runtime: SuccessfulRuntime::from_virtual_machine(
                        finalized_block_runtime.virtual_machine,
                    )
                    .await,
                };

                match &runtime.runtime {
                    Ok(runtime) => {
                        log::info!(
                            target: &log_target,
                            "Finalized block runtime ready. Spec version: {}. Size of `:code`: {}.",
                            runtime.runtime_spec.decode().spec_version,
                            BytesDisplay(storage_code_len)
                        );
                    }
                    Err(error) => {
                        log::warn!(
                            target: &log_target,
                            "Erroenous finalized block runtime. Size of `:code`: {}.\nError: {}\n\
                            This indicates an incompatibility between smoldot and the chain.",
                            BytesDisplay(storage_code_len),
                            error
                        );
                    }
                }

                lock.tree = GuardedInner::FinalizedBlockRuntimeKnown {
                    finalized_block: Block {
                        hash: finalized_block_hash,
                        scale_encoded_header: subscription.finalized_block_scale_encoded_header,
                    },
                    tree: {
                        let mut tree =
                            async_tree::AsyncTree::<_, Block, _>::new(async_tree::Config {
                                finalized_async_user_data: lock.runtimes.insert(runtime),
                                retry_after_failed: Duration::from_secs(10), // TODO: hardcoded
                            });

                        for block in subscription.non_finalized_blocks_ancestry_order {
                            let parent_index = if block.parent_hash == finalized_block_hash {
                                None
                            } else {
                                Some(
                                    tree.input_iter_unordered()
                                        .find(|b| b.user_data.hash == block.parent_hash)
                                        .unwrap()
                                        .id,
                                )
                            };

                            let same_runtime_as_parent =
                                same_runtime_as_parent(&block.scale_encoded_header);
                            let _ = tree.input_insert_block(
                                Block {
                                    hash: header::hash_from_scale_encoded_header(
                                        &block.scale_encoded_header,
                                    ),
                                    scale_encoded_header: block.scale_encoded_header,
                                },
                                parent_index,
                                same_runtime_as_parent,
                                block.is_new_best,
                            );
                        }

                        tree
                    },
                };
            } else {
                lock.tree = GuardedInner::FinalizedBlockRuntimeUnknown {
                    tree: Some({
                        let mut tree = async_tree::AsyncTree::new(async_tree::Config {
                            finalized_async_user_data: None,
                            retry_after_failed: Duration::from_secs(10), // TODO: hardcoded
                        });
                        let node_index = tree.input_insert_block(
                            Block {
                                hash: header::hash_from_scale_encoded_header(
                                    &subscription.finalized_block_scale_encoded_header,
                                ),
                                scale_encoded_header: subscription
                                    .finalized_block_scale_encoded_header,
                            },
                            None,
                            false,
                            true,
                        );
                        tree.input_finalize(node_index, node_index);

                        for block in subscription.non_finalized_blocks_ancestry_order {
                            let parent_index = tree
                                .input_iter_unordered()
                                .find(|b| b.user_data.hash == block.parent_hash)
                                .unwrap()
                                .id;

                            let same_runtime_as_parent =
                                same_runtime_as_parent(&block.scale_encoded_header);
                            let _ = tree.input_insert_block(
                                Block {
                                    hash: header::hash_from_scale_encoded_header(
                                        &block.scale_encoded_header,
                                    ),
                                    scale_encoded_header: block.scale_encoded_header,
                                },
                                Some(parent_index),
                                same_runtime_as_parent,
                                block.is_new_best,
                            );
                        }

                        tree
                    }),
                };
            }
        }

        // State machine containing all the state that will be manipulated below.
        let mut background = Background {
            log_target: log_target.clone(),
            sync_service: sync_service.clone(),
            guarded: guarded.clone(),
            blocks_stream: subscription.new_blocks.boxed(),
            wake_up_new_necessary_download: future::pending().boxed().fuse(),
            runtime_downloads: stream::FuturesUnordered::new(),
        };

        background.start_necessary_downloads().await;

        // Inner loop. Process incoming events.
        loop {
            futures::select! {
                _ = &mut background.wake_up_new_necessary_download => {
                    background.start_necessary_downloads().await;
                },
                notification = background.blocks_stream.next().fuse() => {
                    match notification {
                        None => break, // Break out of the inner loop in order to reset the background.
                        Some(sync_service::Notification::Block(new_block)) => {
                            log::debug!(
                                target: &log_target,
                                "Worker <= InputNewBlock(hash={}, parent={}, is_new_best={})",
                                HashDisplay(&header::hash_from_scale_encoded_header(&new_block.scale_encoded_header)),
                                HashDisplay(&new_block.parent_hash),
                                new_block.is_new_best
                            );

                            let near_head_of_chain = background.sync_service.is_near_head_of_chain_heuristic().await;

                            let mut guarded = background.guarded.lock().await;
                            let mut guarded = &mut *guarded;
                            // TODO: note that this code is never reached for parachains
                            if new_block.is_new_best {
                                guarded.best_near_head_of_chain = near_head_of_chain;
                            }

                            let same_runtime_as_parent = same_runtime_as_parent(&new_block.scale_encoded_header);

                            match &mut guarded.tree {
                                GuardedInner::FinalizedBlockRuntimeKnown {
                                    tree, finalized_block,
                                } => {
                                    let parent_index = if new_block.parent_hash == finalized_block.hash {
                                        if same_runtime_as_parent {
                                            guarded.runtimes[*tree.finalized_async_user_data()].num_references += 1;
                                        }
                                        None
                                    } else {
                                        let index = tree.input_iter_unordered().find(|block| block.user_data.hash == new_block.parent_hash).unwrap().id;
                                        if same_runtime_as_parent {
                                            if let Some(runtime_index) = tree.block_async_user_data(index) {
                                                guarded.runtimes[*runtime_index].num_references += 1;
                                            }
                                        }
                                        Some(index)
                                    };

                                    tree.input_insert_block(Block {
                                        hash: header::hash_from_scale_encoded_header(&new_block.scale_encoded_header),
                                        scale_encoded_header: new_block.scale_encoded_header,
                                    }, parent_index, same_runtime_as_parent, new_block.is_new_best);
                                }
                                GuardedInner::FinalizedBlockRuntimeUnknown { tree: Some(tree) } => {
                                    let parent_index = tree.input_iter_unordered().find(|block| block.user_data.hash == new_block.parent_hash).unwrap().id;
                                    if same_runtime_as_parent {
                                        if let Some(runtime_index) = tree.block_async_user_data(parent_index) {
                                            guarded.runtimes[runtime_index.unwrap()].num_references += 1;
                                        }
                                    }
                                    tree.input_insert_block(Block {
                                        hash: header::hash_from_scale_encoded_header(&new_block.scale_encoded_header),
                                        scale_encoded_header: new_block.scale_encoded_header,
                                    }, Some(parent_index), same_runtime_as_parent, new_block.is_new_best);
                                }
                                _ => unreachable!(),
                            }

                            background.advance_and_notify_subscribers(guarded);
                        },
                        Some(sync_service::Notification::Finalized { hash, best_block_hash }) => {
                            log::debug!(
                                target: &log_target,
                                "Worker <= InputFinalized(hash={}, best={})",
                                HashDisplay(&hash), HashDisplay(&best_block_hash)
                            );

                            background.finalize(hash, best_block_hash).await;
                        }
                    };

                    // TODO: process any other pending event from blocks_stream before doing that; otherwise we might start download for blocks that we don't care about because they're immediately overwritten by others
                    background.start_necessary_downloads().await;
                },
                (async_op_id, download_result) = background.runtime_downloads.select_next_some() => {
                    let mut guarded = background.guarded.lock().await;

                    let concerned_blocks = match &guarded.tree {
                        GuardedInner::FinalizedBlockRuntimeKnown {
                            tree, ..
                        } => either::Left(tree.async_op_blocks(async_op_id)),
                        GuardedInner::FinalizedBlockRuntimeUnknown { tree: Some(tree) } => {
                            either::Right(tree.async_op_blocks(async_op_id))
                        }
                        _ => unreachable!(),
                    }.format_with(", ", |block, fmt| fmt(&HashDisplay(&block.hash))).to_string();

                    match download_result {
                        Ok((storage_code, storage_heap_pages)) => {
                            log::debug!(
                                target: &log_target,
                                "Worker <= SuccessfulDownload(blocks=[{}])",
                                concerned_blocks
                            );

                            // TODO: the line below is a complete hack; the code that updates this value is never reached for parachains, and as such the line below is here to update this field
                            guarded.best_near_head_of_chain = true;
                            drop(guarded);

                            background.runtime_download_finished(async_op_id, storage_code, storage_heap_pages).await;
                        }
                        Err(error) => {
                            log::debug!(
                                target: &log_target,
                                "Worker <= FailedDownload(blocks=[{}], error={})",
                                concerned_blocks,
                                error
                            );
                            if !error.is_network_problem() {
                                log::warn!(
                                    target: &log_target,
                                    "Failed to download :code and :heappages of blocks {}: {}",
                                    concerned_blocks,
                                    error
                                );
                            }

                            match &mut guarded.tree {
                                GuardedInner::FinalizedBlockRuntimeKnown {
                                    tree, ..
                                } => {
                                    tree.async_op_failure(async_op_id, &TPlat::now());
                                }
                                GuardedInner::FinalizedBlockRuntimeUnknown { tree: Some(tree) } => {
                                    tree.async_op_failure(async_op_id, &TPlat::now());
                                }
                                _ => unreachable!(),
                            }

                            drop(guarded);
                        }
                    }

                    background.start_necessary_downloads().await;
                }
            }
        }
    }
}

#[derive(Debug, Clone, derive_more::Display)]
enum RuntimeDownloadError {
    StorageQuery(sync_service::StorageQueryError),
    InvalidHeader(header::Error),
}

impl RuntimeDownloadError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    fn is_network_problem(&self) -> bool {
        match self {
            RuntimeDownloadError::StorageQuery(err) => err.is_network_problem(),
            RuntimeDownloadError::InvalidHeader(_) => false,
        }
    }
}

struct Background<TPlat: Platform> {
    log_target: String,

    sync_service: Arc<sync_service::SyncService<TPlat>>,

    guarded: Arc<Mutex<Guarded<TPlat>>>,

    /// Stream of notifications coming from the sync service.
    blocks_stream: Pin<Box<dyn Stream<Item = sync_service::Notification> + Send>>,

    /// List of runtimes currently being downloaded from the network.
    /// For each item, the download id, storage value of `:code`, and storage value of
    /// `:heappages`.
    runtime_downloads: stream::FuturesUnordered<
        future::BoxFuture<
            'static,
            (
                async_tree::AsyncOpId,
                Result<(Option<Vec<u8>>, Option<Vec<u8>>), RuntimeDownloadError>,
            ),
        >,
    >,

    /// Future that wakes up when a new download to start is potentially ready.
    wake_up_new_necessary_download: future::Fuse<future::BoxFuture<'static, ()>>,
}

impl<TPlat: Platform> Background<TPlat> {
    /// Injects into the state of `self` a completed runtime download.
    async fn runtime_download_finished(
        &mut self,
        async_op_id: async_tree::AsyncOpId,
        storage_code: Option<Vec<u8>>,
        storage_heap_pages: Option<Vec<u8>>,
    ) {
        let mut guarded = self.guarded.lock().await;

        // Try to find an existing identical runtime.
        let existing_runtime = guarded
            .runtimes
            .iter()
            .find(|(_, rt)| rt.runtime_code == storage_code && rt.heap_pages == storage_heap_pages)
            .map(|(id, _)| id);

        let runtime_index = if let Some(existing_runtime) = existing_runtime {
            existing_runtime
        } else {
            // No identical runtime was found. Try compiling the new runtime.
            let runtime = SuccessfulRuntime::from_storage(&storage_code, &storage_heap_pages).await;
            match &runtime {
                Ok(runtime) => {
                    log::info!(
                        target: &self.log_target,
                        "Successfully compiled runtime. Spec version: {}. Size of `:code`: {}.",
                        runtime.runtime_spec.decode().spec_version,
                        BytesDisplay(u64::try_from(storage_code.as_ref().map_or(0, |v| v.len())).unwrap())
                    );
                }
                Err(error) => {
                    log::warn!(
                        target: &self.log_target,
                        "Failed to compile runtime. Size of `:code`: {}.\nError: {}\n\
                        This indicates an incompatibility between smoldot and the chain.",
                        BytesDisplay(u64::try_from(storage_code.as_ref().map_or(0, |v| v.len())).unwrap()),
                        error
                    );
                }
            }

            guarded.runtimes.insert(Runtime {
                num_references: 0, // Incremented below.
                heap_pages: storage_heap_pages,
                runtime_code: storage_code,
                runtime,
            })
        };

        let blocks = match &mut guarded.tree {
            GuardedInner::FinalizedBlockRuntimeKnown { tree, .. } => {
                tree.async_op_finished(async_op_id, runtime_index)
            }
            GuardedInner::FinalizedBlockRuntimeUnknown { tree: Some(tree) } => {
                tree.async_op_finished(async_op_id, Some(runtime_index))
            }
            _ => unreachable!(),
        };

        guarded.runtimes[runtime_index].num_references += blocks.len();

        if blocks.is_empty() {
            guarded.runtimes.retain(|_, rt| rt.num_references > 0);
        }

        self.advance_and_notify_subscribers(&mut guarded);
    }

    fn advance_and_notify_subscribers(&self, guarded: &mut Guarded<TPlat>) {
        loop {
            let all_blocks_notif = match &mut guarded.tree {
                GuardedInner::FinalizedBlockRuntimeKnown {
                    tree,
                    finalized_block,
                } => match tree.try_advance_output() {
                    None => break,
                    Some(async_tree::OutputUpdate::Finalized {
                        user_data: new_finalized,
                        best_block_index,
                        pruned_blocks,
                        former_finalized_async_op_user_data: former_finalized_runtime_index,
                        ..
                    }) => {
                        *finalized_block = new_finalized;
                        let best_block_hash = best_block_index
                            .map_or(finalized_block.hash, |idx| tree.block_user_data(idx).hash);

                        log::debug!(
                            target: &self.log_target,
                            "Worker => OutputFinalized(hash={}, best={})",
                            HashDisplay(&finalized_block.hash), HashDisplay(&best_block_hash)
                        );

                        guarded.runtimes[former_finalized_runtime_index].num_references -= 1;
                        for (_, _, runtime_index) in &pruned_blocks {
                            if let Some(runtime_index) = *runtime_index {
                                guarded.runtimes[runtime_index].num_references -= 1;
                            }
                        }

                        Notification::Finalized {
                            best_block_hash,
                            hash: finalized_block.hash,
                            pruned_blocks: pruned_blocks
                                .into_iter()
                                .map(|(_, b, _)| b.hash)
                                .collect(),
                        }
                    }
                    Some(async_tree::OutputUpdate::Block(block)) => {
                        let block_index = block.index;
                        let block_runtime_index = *block.async_op_user_data;
                        let block_hash = block.user_data.hash;
                        let scale_encoded_header = block.user_data.scale_encoded_header.clone();
                        let is_new_best = block.is_new_best;

                        let parent_runtime_index = tree
                            .parent(block_index)
                            .map_or(*tree.finalized_async_user_data(), |idx| {
                                *tree.block_async_user_data(idx).unwrap()
                            });

                        log::debug!(
                            target: &self.log_target,
                            "Worker => OutputNewBlock(hash={}, is_new_best={})",
                            HashDisplay(&tree.block_user_data(block_index).hash),
                            is_new_best
                        );

                        let notif = Notification::Block(BlockNotification {
                            parent_hash: tree
                                .parent(block_index)
                                .map_or(finalized_block.hash, |idx| tree.block_user_data(idx).hash),
                            is_new_best,
                            scale_encoded_header: scale_encoded_header.clone(),
                            new_runtime: if parent_runtime_index != block_runtime_index {
                                Some(
                                    guarded.runtimes[block_runtime_index]
                                        .runtime
                                        .as_ref()
                                        .map(|rt| rt.runtime_spec.clone())
                                        .map_err(|err| err.clone()),
                                )
                            } else {
                                None
                            },
                        });

                        let mut to_remove = Vec::new();
                        for (subscription_id, (sender, pinned_remaining)) in
                            guarded.all_blocks_subscriptions.iter_mut()
                        {
                            if *pinned_remaining == 0 {
                                to_remove.push(*subscription_id);
                                continue;
                            }

                            if sender.try_send(notif.clone()).is_ok() {
                                *pinned_remaining -= 1;
                                guarded.runtimes[block_runtime_index].num_references += 1;
                                guarded.pinned_blocks.insert(
                                    (*subscription_id, block_hash),
                                    (block_runtime_index, scale_encoded_header.clone()),
                                );
                            } else {
                                to_remove.push(*subscription_id);
                            }
                        }
                        for to_remove in to_remove {
                            guarded.all_blocks_subscriptions.remove(&to_remove);
                            let pinned_blocks = guarded
                                .pinned_blocks
                                .range((to_remove, [0; 32])..=(to_remove, [0xff; 32]))
                                .map(|((_, h), _)| *h)
                                .collect::<Vec<_>>();
                            for block in pinned_blocks {
                                guarded.pinned_blocks.remove(&(to_remove, block));
                            }
                        }

                        continue;
                    }
                },
                GuardedInner::FinalizedBlockRuntimeUnknown {
                    tree: tree @ Some(_),
                } => match tree.as_mut().unwrap().try_advance_output() {
                    None => break,
                    Some(async_tree::OutputUpdate::Block(_)) => continue,
                    Some(async_tree::OutputUpdate::Finalized {
                        user_data: new_finalized,
                        former_finalized_async_op_user_data,
                        best_block_index,
                        pruned_blocks,
                        ..
                    }) => {
                        debug_assert!(former_finalized_async_op_user_data.is_none());

                        // TODO: the two lines below are a hack to make the implementation of `subscribe_all` work and because the rest of this block doesn't properly report blocks
                        guarded.all_blocks_subscriptions.clear();
                        guarded.pinned_blocks.clear();

                        let best_block_hash = best_block_index.map_or(new_finalized.hash, |idx| {
                            tree.as_ref().unwrap().block_user_data(idx).hash
                        });
                        let new_finalized_hash = new_finalized.hash;

                        log::debug!(
                            target: &self.log_target,
                            "Worker => OutputFinalized(hash={}, best={})",
                            HashDisplay(&new_finalized_hash), HashDisplay(&best_block_hash)
                        );

                        guarded.tree = GuardedInner::FinalizedBlockRuntimeKnown {
                            tree: tree
                                .take()
                                .unwrap()
                                .map_async_op_user_data(|runtime_index| runtime_index.unwrap()),
                            finalized_block: new_finalized,
                        };

                        // TODO: doesn't report existing blocks /!\

                        for (_, _, runtime_index) in &pruned_blocks {
                            if let Some(Some(runtime_index)) = *runtime_index {
                                guarded.runtimes[runtime_index].num_references -= 1;
                            }
                        }

                        Notification::Finalized {
                            best_block_hash,
                            hash: new_finalized_hash,
                            pruned_blocks: pruned_blocks
                                .into_iter()
                                .map(|(_, b, _)| b.hash)
                                .collect(),
                        }
                    }
                },
                _ => unreachable!(),
            };

            let mut to_remove = Vec::new();
            for (subscription_id, (sender, _)) in guarded.all_blocks_subscriptions.iter_mut() {
                if sender.try_send(all_blocks_notif.clone()).is_err() {
                    to_remove.push(*subscription_id);
                }
            }
            for to_remove in to_remove {
                guarded.all_blocks_subscriptions.remove(&to_remove);
                let pinned_blocks = guarded
                    .pinned_blocks
                    .range((to_remove, [0; 32])..=(to_remove, [0xff; 32]))
                    .map(|((_, h), _)| *h)
                    .collect::<Vec<_>>();
                for block in pinned_blocks {
                    guarded.pinned_blocks.remove(&(to_remove, block));
                }
            }
        }
    }

    /// Examines the state of `self` and starts downloading runtimes if necessary.
    async fn start_necessary_downloads(&mut self) {
        let mut guarded = self.guarded.lock().await;
        let guarded = &mut *guarded;

        loop {
            // Don't download more than 2 runtimes at a time.
            if self.runtime_downloads.len() >= 2 {
                break;
            }

            // If there's nothing more to download, break out of the loop.
            let download_params = {
                let async_op = match &mut guarded.tree {
                    GuardedInner::FinalizedBlockRuntimeKnown { tree, .. } => {
                        tree.next_necessary_async_op(&TPlat::now())
                    }
                    GuardedInner::FinalizedBlockRuntimeUnknown { tree: Some(tree) } => {
                        tree.next_necessary_async_op(&TPlat::now())
                    }
                    _ => unreachable!(),
                };

                match async_op {
                    async_tree::NextNecessaryAsyncOp::Ready(dl) => dl,
                    async_tree::NextNecessaryAsyncOp::NotReady { when } => {
                        self.wake_up_new_necessary_download = if let Some(when) = when {
                            TPlat::sleep_until(when).boxed()
                        } else {
                            future::pending().boxed()
                        }
                        .fuse();
                        break;
                    }
                }
            };

            log::debug!(
                target: &self.log_target,
                "Worker => NewDownload(block={})",
                HashDisplay(&download_params.block_user_data.hash)
            );

            // Dispatches a runtime download task to `runtime_downloads`.
            self.runtime_downloads.push({
                let download_id = download_params.id;

                // In order to perform the download, we need to known the state root hash of the
                // block in question, which requires decoding the block. If the decoding fails,
                // we report that the asynchronous operation has failed with the hope that this
                // block gets pruned in the future.
                match header::decode(&download_params.block_user_data.scale_encoded_header) {
                    Ok(decoded_header) => {
                        let sync_service = self.sync_service.clone();
                        let block_hash = download_params.block_user_data.hash;
                        let state_root = *decoded_header.state_root;

                        Box::pin(async move {
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
                                Err(error) => Err(RuntimeDownloadError::StorageQuery(error)),
                            };

                            (download_id, result)
                        })
                    }
                    Err(error) => {
                        log::warn!(
                            target: &self.log_target,
                            "Failed to decode header from sync service: {}", error
                        );

                        Box::pin(async move {
                            (download_id, Err(RuntimeDownloadError::InvalidHeader(error)))
                        })
                    }
                }
            });
        }
    }

    /// Updates `self` to take into account that the sync service has finalized the given block.
    async fn finalize(&mut self, hash_to_finalize: [u8; 32], new_best_block_hash: [u8; 32]) {
        let mut guarded = self.guarded.lock().await;

        match &mut guarded.tree {
            GuardedInner::FinalizedBlockRuntimeKnown {
                tree,
                finalized_block,
            } => {
                // TODO: this if is a small hack because the sync service currently sends multiple identical finalized notifications
                if finalized_block.hash == hash_to_finalize {
                    return;
                }

                let node_to_finalize = tree
                    .input_iter_unordered()
                    .find(|block| block.user_data.hash == hash_to_finalize)
                    .unwrap()
                    .id;
                let new_best_block = tree
                    .input_iter_unordered()
                    .find(|block| block.user_data.hash == new_best_block_hash)
                    .unwrap()
                    .id;
                tree.input_finalize(node_to_finalize, new_best_block);
            }
            GuardedInner::FinalizedBlockRuntimeUnknown { tree: Some(tree) } => {
                let node_to_finalize = tree
                    .input_iter_unordered()
                    .find(|block| block.user_data.hash == hash_to_finalize)
                    .unwrap()
                    .id;
                let new_best_block = tree
                    .input_iter_unordered()
                    .find(|block| block.user_data.hash == new_best_block_hash)
                    .unwrap()
                    .id;
                tree.input_finalize(node_to_finalize, new_best_block);
            }
            _ => unreachable!(),
        }

        self.advance_and_notify_subscribers(&mut guarded);

        // Clean up unused runtimes to free up resources.
        guarded
            .runtimes
            .retain(|_, runtime| runtime.num_references > 0);
    }
}

struct Runtime {
    /// Number of items in [`Guarded::tree`], [`Guarded::pinned_blocks`], and
    /// [`Guarded::pinned_runtimes`] that reference this runtime.
    num_references: usize,

    /// Successfully-compiled runtime and all its information. Can contain an error if an error
    /// happened, including a problem when obtaining the runtime specs.
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
    /// Runtime specs extracted from the runtime.
    runtime_spec: executor::CoreVersion,

    /// Virtual machine itself, to perform additional calls.
    ///
    /// Always `Some`, except for temporary extractions necessary to execute the VM.
    virtual_machine: Option<executor::host::HostVmPrototype>,
}

impl SuccessfulRuntime {
    async fn from_storage(
        code: &Option<Vec<u8>>,
        heap_pages: &Option<Vec<u8>>,
    ) -> Result<Self, RuntimeError> {
        // Since compiling the runtime is a CPU-intensive operation, we yield once before.
        crate::util::yield_once().await;

        let vm = match executor::host::HostVmPrototype::new(
            code.as_ref().ok_or(RuntimeError::CodeNotFound)?,
            executor::storage_heap_pages_to_value(heap_pages.as_deref())
                .map_err(RuntimeError::InvalidHeapPages)?,
            executor::vm::ExecHint::CompileAheadOfTime,
        ) {
            Ok(vm) => vm,
            Err(error) => {
                return Err(RuntimeError::Build(error));
            }
        };

        Self::from_virtual_machine(vm).await
    }

    async fn from_virtual_machine(
        vm: executor::host::HostVmPrototype,
    ) -> Result<Self, RuntimeError> {
        // Since getting the runtime spec is a CPU-intensive operation, we yield once before.
        crate::util::yield_once().await;

        let (runtime_spec, vm) = match executor::core_version(vm) {
            (Ok(spec), vm) => (spec, vm),
            (Err(error), _) => {
                return Err(RuntimeError::CoreVersion(error));
            }
        };

        Ok(SuccessfulRuntime {
            runtime_spec,
            virtual_machine: Some(vm),
        })
    }
}

/// Returns `true` if the block can be assumed to have the same runtime as its parent.
fn same_runtime_as_parent(header: &[u8]) -> bool {
    match header::decode(header) {
        Ok(h) => !h.digest.has_runtime_environment_updated(),
        Err(_) => false,
    }
}
