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
//! The main service offered by the runtime service is [`RuntimeService::subscribe_all`], that
//! notifies about new blocks once their runtime is known.
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

use crate::{log, network_service, platform::PlatformRef, sync_service};

use alloc::{
    borrow::{Cow, ToOwned as _},
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    format,
    string::{String, ToString as _},
    sync::{Arc, Weak},
    vec::Vec,
};
use async_lock::Mutex;
use core::{cmp, fmt, iter, mem, num::NonZero, ops, pin::Pin, time::Duration};
use derive_more::derive;
use futures_channel::oneshot;
use futures_lite::FutureExt as _;
use futures_util::{Stream, StreamExt as _, future, stream};
use itertools::Itertools as _;
use rand::seq::IteratorRandom as _;
use rand_chacha::rand_core::SeedableRng as _;
use smoldot::{
    chain::async_tree,
    executor, header,
    informant::{BytesDisplay, HashDisplay},
    trie::{self, Nibble, proof_decode},
};

/// Configuration for a runtime service.
pub struct Config<TPlat: PlatformRef> {
    /// Name of the chain, for logging purposes.
    ///
    /// > **Note**: This name will be directly printed out. Any special character should already
    /// >           have been filtered out from this name.
    pub log_name: String,

    /// Access to the platform's capabilities.
    pub platform: TPlat,

    /// Service responsible for synchronizing the chain.
    pub sync_service: Arc<sync_service::SyncService<TPlat>>,

    /// Service responsible for accessing the networking of the chain.
    pub network_service: Arc<network_service::NetworkServiceChain<TPlat>>,

    /// Header of the genesis block of the chain, in SCALE encoding.
    pub genesis_block_scale_encoded_header: Vec<u8>,
}

/// Runtime currently pinned within a [`RuntimeService`].
///
/// Destroying this object automatically unpins the runtime.
#[derive(Clone)]
pub struct PinnedRuntime(Arc<Runtime>);

/// See [the module-level documentation](..).
pub struct RuntimeService<TPlat: PlatformRef> {
    /// Configuration of the background task. Used to restart the background task if necessary.
    background_task_config: BackgroundTaskConfig<TPlat>,

    /// Sender to send messages to the background task.
    to_background: Mutex<async_channel::Sender<ToBackground<TPlat>>>,
}

impl<TPlat: PlatformRef> RuntimeService<TPlat> {
    /// Initializes a new runtime service.
    pub fn new(config: Config<TPlat>) -> Self {
        // Target to use for all the logs of this service.
        let log_target = format!("runtime-{}", config.log_name);

        let background_task_config = BackgroundTaskConfig {
            log_target: log_target.clone(),
            platform: config.platform.clone(),
            sync_service: config.sync_service,
            network_service: config.network_service,
            genesis_block_scale_encoded_header: config.genesis_block_scale_encoded_header,
        };

        // Spawns a task that runs in the background and updates the content of the mutex.
        let to_background;
        config.platform.spawn_task(log_target.clone().into(), {
            let (tx, rx) = async_channel::bounded(16);
            let tx_weak = tx.downgrade();
            to_background = tx;
            let background_task_config = background_task_config.clone();
            run_background(background_task_config, rx, tx_weak)
        });

        RuntimeService {
            background_task_config,
            to_background: Mutex::new(to_background),
        }
    }

    /// Calls [`sync_service::SyncService::block_number_bytes`] on the sync service associated to
    /// this runtime service.
    pub fn block_number_bytes(&self) -> usize {
        self.background_task_config
            .sync_service
            .block_number_bytes()
    }

    /// Subscribes to the state of the chain: the current state and the new blocks.
    ///
    /// This function only returns once the runtime of the current finalized block is known. This
    /// might take a long time.
    ///
    /// Only up to `buffer_size` block notifications are buffered in the channel. If the channel
    /// is full when a new notification is attempted to be pushed, the channel gets closed.
    ///
    /// A maximum number of finalized or non-canonical (i.e. not part of the finalized chain)
    /// pinned blocks must be passed, indicating the maximum number of blocks that are finalized
    /// or non-canonical that the runtime service will pin at the same time for this subscription.
    /// If this maximum is reached, the channel will get closed. In situations where the subscriber
    /// is guaranteed to always properly unpin blocks, a value of `usize::MAX` can be
    /// passed in order to ignore this maximum.
    ///
    /// The channel also gets closed if a gap in the finality happens, such as after a Grandpa
    /// warp syncing.
    ///
    /// See [`SubscribeAll`] for information about the return value.
    pub async fn subscribe_all(
        &self,
        buffer_size: usize,
        max_pinned_blocks: NonZero<usize>,
    ) -> SubscribeAll<TPlat> {
        loop {
            let (result_tx, result_rx) = oneshot::channel();
            let _ = self
                .send_message_or_restart_service(ToBackground::SubscribeAll(
                    ToBackgroundSubscribeAll {
                        result_tx,
                        buffer_size,
                        max_pinned_blocks,
                    },
                ))
                .await;

            if let Ok(subscribe_all) = result_rx.await {
                break subscribe_all;
            }
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
    // TODO: add #[track_caller] once possible, see https://github.com/rust-lang/rust/issues/87417
    pub async fn unpin_block(&self, subscription_id: SubscriptionId, block_hash: [u8; 32]) {
        let (result_tx, result_rx) = oneshot::channel();
        let _ = self
            .to_background
            .lock()
            .await
            .send(ToBackground::UnpinBlock {
                result_tx,
                subscription_id,
                block_hash,
            })
            .await;
        match result_rx.await {
            Ok(Ok(())) => {
                // Background task has indicated success.
            }
            Err(_) => {
                // Background task has crashed. Subscription is stale. Function has no effect.
            }
            Ok(Err(_)) => {
                // Background task has indicated that the block has already been unpinned.
                panic!()
            }
        }
    }

    /// Returns the storage value and Merkle value of the `:code` key of the finalized block.
    ///
    /// Returns `None` if the runtime of the current finalized block is not known yet.
    // TODO: this function has a bad API but is hopefully temporary
    pub async fn finalized_runtime_storage_merkle_values(
        &self,
    ) -> Option<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<Nibble>>)> {
        let (result_tx, result_rx) = oneshot::channel();

        let _ = self
            .to_background
            .lock()
            .await
            .send(ToBackground::FinalizedRuntimeStorageMerkleValues { result_tx })
            .await;

        result_rx.await.unwrap_or(None)
    }

    /// Pins the runtime of a pinned block.
    ///
    /// The hash of the block passed as parameter corresponds to the block whose runtime is to
    /// be pinned. The block must be currently pinned in the context of the provided
    /// [`SubscriptionId`].
    ///
    /// Returns the pinned runtime, plus the state trie root hash and height of the block.
    ///
    /// Returns an error if the subscription is stale, meaning that it has been reset by the
    /// runtime service.
    pub async fn pin_pinned_block_runtime(
        &self,
        subscription_id: SubscriptionId,
        block_hash: [u8; 32],
    ) -> Result<(PinnedRuntime, [u8; 32], u64), PinPinnedBlockRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();

        let _ = self
            .to_background
            .lock()
            .await
            .send(ToBackground::PinPinnedBlockRuntime {
                result_tx,
                subscription_id,
                block_hash,
            })
            .await;

        match result_rx.await {
            Ok(result) => result.map(|(r, v, n)| (PinnedRuntime(r), v, n)),
            Err(_) => {
                // Background service has crashed. This means that the subscription is obsolete.
                Err(PinPinnedBlockRuntimeError::ObsoleteSubscription)
            }
        }
    }

    /// Performs a runtime call.
    ///
    /// The hash of the block passed as parameter corresponds to the block whose runtime to use
    /// to make the call. The block must be currently pinned in the context of the provided
    /// [`SubscriptionId`].
    ///
    /// Returns an error if the subscription is stale, meaning that it has been reset by the
    /// runtime service.
    pub async fn runtime_call(
        &self,
        pinned_runtime: PinnedRuntime,
        block_hash: [u8; 32],
        block_number: u64,
        block_state_trie_root_hash: [u8; 32],
        function_name: String,
        required_api_version: Option<(String, ops::RangeInclusive<u32>)>,
        parameters_vectored: Vec<u8>,
        total_attempts: u32,
        timeout_per_request: Duration,
        max_parallel: NonZero<u32>,
    ) -> Result<RuntimeCallSuccess, RuntimeCallError> {
        let (result_tx, result_rx) = oneshot::channel();

        self.send_message_or_restart_service(ToBackground::RuntimeCall {
            result_tx,
            pinned_runtime: pinned_runtime.0,
            block_hash,
            block_number,
            block_state_trie_root_hash,
            function_name,
            required_api_version,
            parameters_vectored,
            total_attempts,
            timeout_per_request,
            _max_parallel: max_parallel,
        })
        .await;

        match result_rx.await {
            Ok(result) => result,
            Err(_) => {
                // Background service has crashed.
                Err(RuntimeCallError::Crash)
            }
        }
    }

    /// Tries to find a runtime within the [`RuntimeService`] that has the given storage code and
    /// heap pages. If none is found, compiles the runtime and stores it within the
    /// [`RuntimeService`].
    pub async fn compile_and_pin_runtime(
        &self,
        storage_code: Option<Vec<u8>>,
        storage_heap_pages: Option<Vec<u8>>,
        code_merkle_value: Option<Vec<u8>>,
        closest_ancestor_excluding: Option<Vec<Nibble>>,
    ) -> Result<PinnedRuntime, CompileAndPinRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();

        let _ = self
            .send_message_or_restart_service(ToBackground::CompileAndPinRuntime {
                result_tx,
                storage_code,
                storage_heap_pages,
                code_merkle_value,
                closest_ancestor_excluding,
            })
            .await;

        Ok(PinnedRuntime(
            result_rx
                .await
                .map_err(|_| CompileAndPinRuntimeError::Crash)?,
        ))
    }

    /// Returns the runtime specification of the given runtime.
    pub async fn pinned_runtime_specification(
        &self,
        pinned_runtime: PinnedRuntime,
    ) -> Result<executor::CoreVersion, PinnedRuntimeSpecificationError> {
        match &pinned_runtime.0.runtime {
            Ok(rt) => Ok(rt.runtime_version().clone()),
            Err(error) => Err(PinnedRuntimeSpecificationError::InvalidRuntime(
                error.clone(),
            )),
        }
    }

    /// Returns true if it is believed that we are near the head of the chain.
    ///
    /// The way this method is implemented is opaque and cannot be relied on. The return value
    /// should only ever be shown to the user and not used for any meaningful logic.
    pub async fn is_near_head_of_chain_heuristic(&self) -> bool {
        let (result_tx, result_rx) = oneshot::channel();
        let _ = self
            .to_background
            .lock()
            .await
            .send(ToBackground::IsNearHeadOfChainHeuristic { result_tx })
            .await;
        result_rx.await.unwrap_or(false)
    }

    /// Sends a message to the background task. Restarts the background task if it has crashed.
    async fn send_message_or_restart_service(&self, message: ToBackground<TPlat>) {
        let mut lock = self.to_background.lock().await;

        if lock.is_closed() {
            let (tx, rx) = async_channel::bounded(16);
            let tx_weak = tx.downgrade();
            *lock = tx;

            self.background_task_config.platform.spawn_task(
                self.background_task_config.log_target.clone().into(),
                {
                    let background_task_config = self.background_task_config.clone();
                    let platform = background_task_config.platform.clone();
                    async move {
                        // Sleep for a bit in order to avoid infinite loops of repeated crashes.
                        background_task_config
                            .platform
                            .sleep(Duration::from_secs(2))
                            .await;
                        let log_target = background_task_config.log_target.clone();
                        log!(&platform, Debug, &log_target, "restart");
                        run_background(background_task_config, rx, tx_weak).await;
                        log!(&platform, Debug, &log_target, "shutdown");
                    }
                },
            );
        }

        // Note that the background task might have crashed again at this point already, and thus
        // errors are not impossible.
        let _ = lock.send(message).await;
    }
}

/// Return value of [`RuntimeService::subscribe_all`].
pub struct SubscribeAll<TPlat: PlatformRef> {
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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId(u64);

impl fmt::Debug for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

pub struct Subscription<TPlat: PlatformRef> {
    subscription_id: u64,
    channel: Pin<Box<async_channel::Receiver<Notification>>>,
    to_background: async_channel::Sender<ToBackground<TPlat>>,
}

impl<TPlat: PlatformRef> Subscription<TPlat> {
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
    pub async fn unpin_block(&self, block_hash: [u8; 32]) {
        let (result_tx, result_rx) = oneshot::channel();
        let _ = self
            .to_background
            .send(ToBackground::UnpinBlock {
                result_tx,
                subscription_id: SubscriptionId(self.subscription_id),
                block_hash,
            })
            .await;
        result_rx.await.unwrap().unwrap()
    }
}

/// Notification about a new block or a new finalized block.
///
/// See [`RuntimeService::subscribe_all`].
#[derive(Debug, Clone)]
pub enum Notification {
    /// A non-finalized block has been finalized.
    Finalized {
        /// BLAKE2 hash of the header of the block that has been finalized.
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

        /// If the current best block is pruned by the finalization, contains the updated hash
        /// of the best block after the finalization.
        ///
        /// If the newly-finalized block is an ancestor of the current best block, then this field
        /// contains the hash of this current best block. Otherwise, the best block is now
        /// the non-finalized block with the given hash.
        ///
        /// A block with this hash is guaranteed to have earlier been reported in a
        /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks_ancestry_order`]
        /// or in a [`Notification::Block`].
        best_block_hash_if_changed: Option<[u8; 32]>,

        /// List of BLAKE2 hashes of the headers of the blocks that have been discarded because
        /// they're not descendants of the newly-finalized block.
        ///
        /// This list contains all the siblings of the newly-finalized block and all their
        /// descendants.
        pruned_blocks: Vec<[u8; 32]>,
    },

    /// A new block has been added to the list of unfinalized blocks.
    Block(BlockNotification),

    /// The best block has changed to a different one.
    BestBlockChanged {
        /// Hash of the new best block.
        ///
        /// This can be either the hash of the latest finalized block or the hash of a
        /// non-finalized block.
        hash: [u8; 32],
    },
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

    /// BLAKE2 hash of the header of the parent of this block.
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

/// Successful runtime call.
#[derive(Debug)]
pub struct RuntimeCallSuccess {
    /// Output of the runtime call.
    pub output: Vec<u8>,

    /// Version of the API that was found. `Some` if and only if an API requirement was passed.
    pub api_version: Option<u32>,
}

/// See [`RuntimeService::pin_pinned_block_runtime`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum PinPinnedBlockRuntimeError {
    /// Subscription is dead.
    ObsoleteSubscription,

    /// Requested block isn't pinned by the subscription.
    BlockNotPinned,
}

/// See [`RuntimeService::pinned_runtime_specification`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum PinnedRuntimeSpecificationError {
    /// The runtime is invalid.
    InvalidRuntime(RuntimeError),
}

/// See [`RuntimeService::runtime_call`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum RuntimeCallError {
    /// The runtime of the requested block is invalid.
    InvalidRuntime(RuntimeError),

    /// API version required for the call isn't fulfilled.
    ApiVersionRequirementUnfulfilled,

    /// Runtime service has crashed while the call was in progress.
    ///
    /// This doesn't necessarily indicate that the call was responsible for this crash.
    Crash,

    /// Error during the execution of the runtime.
    ///
    /// There is no point in trying the same call again, as it would result in the same error.
    #[display("Error during the execution of the runtime: {_0}")]
    Execution(RuntimeCallExecutionError),

    /// Error trying to access the storage required for the runtime call.
    ///
    /// Because these errors are non-fatal, the operation is attempted multiple times, and as such
    /// there can be multiple errors.
    ///
    /// Trying the same call again might succeed.
    #[display("Error trying to access the storage required for the runtime call")]
    // TODO: better display?
    Inaccessible(#[error(not(source))] Vec<RuntimeCallInaccessibleError>),
}

/// See [`RuntimeCallError::Execution`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum RuntimeCallExecutionError {
    /// Failed to initialize the virtual machine.
    Start(executor::host::StartErr),
    /// Error during the execution of the virtual machine.
    Execution(executor::runtime_call::ErrorDetail),
    /// Virtual machine has called a host function that it is not allowed to call.
    ForbiddenHostFunction,
}

/// See [`RuntimeCallError::Inaccessible`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum RuntimeCallInaccessibleError {
    /// Failed to download the call proof from the network.
    Network(network_service::CallProofRequestError),
    /// Call proof downloaded from the network has an invalid format.
    InvalidCallProof(proof_decode::Error),
    /// One or more entries are missing from the downloaded call proof.
    MissingProofEntry,
    /// Failed to download a storage proof from the network.
    StorageRequest(network_service::StorageProofRequestError),
    /// Failed to download a child storage proof from the network.
    ChildStorageRequest(network_service::ChildStorageProofRequestError),
}

/// Error when analyzing the runtime.
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum RuntimeError {
    /// The `:code` key of the storage is empty.
    CodeNotFound,
    /// Error while parsing the `:heappages` storage value.
    #[display("Failed to parse `:heappages` storage value: {_0}")]
    InvalidHeapPages(executor::InvalidHeapPagesError),
    /// Error while compiling the runtime.
    #[display("{_0}")]
    Build(executor::host::NewErr),
}

/// Error potentially returned by [`RuntimeService::compile_and_pin_runtime`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum CompileAndPinRuntimeError {
    /// Background service has crashed while compiling this runtime. The crash might however not
    /// necessarily be caused by the runtime compilation.
    Crash,
}

/// Message towards the background task.
enum ToBackground<TPlat: PlatformRef> {
    SubscribeAll(ToBackgroundSubscribeAll<TPlat>),
    CompileAndPinRuntime {
        result_tx: oneshot::Sender<Arc<Runtime>>,
        storage_code: Option<Vec<u8>>,
        storage_heap_pages: Option<Vec<u8>>,
        code_merkle_value: Option<Vec<u8>>,
        closest_ancestor_excluding: Option<Vec<Nibble>>,
    },
    FinalizedRuntimeStorageMerkleValues {
        // TODO: overcomplicated
        result_tx: oneshot::Sender<Option<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<Nibble>>)>>,
    },
    IsNearHeadOfChainHeuristic {
        result_tx: oneshot::Sender<bool>,
    },
    UnpinBlock {
        result_tx: oneshot::Sender<Result<(), ()>>,
        subscription_id: SubscriptionId,
        block_hash: [u8; 32],
    },
    PinPinnedBlockRuntime {
        result_tx:
            oneshot::Sender<Result<(Arc<Runtime>, [u8; 32], u64), PinPinnedBlockRuntimeError>>,
        subscription_id: SubscriptionId,
        block_hash: [u8; 32],
    },
    RuntimeCall {
        result_tx: oneshot::Sender<Result<RuntimeCallSuccess, RuntimeCallError>>,
        pinned_runtime: Arc<Runtime>,
        block_hash: [u8; 32],
        block_number: u64,
        block_state_trie_root_hash: [u8; 32],
        function_name: String,
        required_api_version: Option<(String, ops::RangeInclusive<u32>)>,
        parameters_vectored: Vec<u8>,
        total_attempts: u32,
        timeout_per_request: Duration,
        _max_parallel: NonZero<u32>,
    },
}

struct ToBackgroundSubscribeAll<TPlat: PlatformRef> {
    result_tx: oneshot::Sender<SubscribeAll<TPlat>>,
    buffer_size: usize,
    max_pinned_blocks: NonZero<usize>,
}

#[derive(Clone)]
struct PinnedBlock {
    /// Reference-counted runtime of the pinned block.
    runtime: Arc<Runtime>,

    /// Hash of the trie root of the pinned block.
    state_trie_root_hash: [u8; 32],

    /// Height of the pinned block.
    block_number: u64,

    /// `true` if the block is non-finalized and part of the canonical chain.
    /// If `true`, then the block doesn't count towards the maximum number of pinned blocks of
    /// the subscription.
    block_ignores_limit: bool,
}

#[derive(Clone)]
struct Block {
    /// Hash of the block in question. Redundant with `header`, but the hash is so often needed
    /// that it makes sense to cache it.
    hash: [u8; 32],

    /// Height of the block.
    height: u64,

    /// Header of the block in question.
    /// Guaranteed to always be valid for the output best and finalized blocks. Otherwise,
    /// not guaranteed to be valid.
    scale_encoded_header: Vec<u8>,
}

#[derive(Clone)]
struct BackgroundTaskConfig<TPlat: PlatformRef> {
    log_target: String,
    platform: TPlat,
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
    genesis_block_scale_encoded_header: Vec<u8>,
}

async fn run_background<TPlat: PlatformRef>(
    config: BackgroundTaskConfig<TPlat>,
    to_background: async_channel::Receiver<ToBackground<TPlat>>,
    to_background_tx: async_channel::WeakSender<ToBackground<TPlat>>,
) {
    log!(
        &config.platform,
        Trace,
        &config.log_target,
        "start",
        genesis_block_hash = HashDisplay(&header::hash_from_scale_encoded_header(
            &config.genesis_block_scale_encoded_header
        ))
    );

    // State machine containing all the state that will be manipulated below.
    let mut background = {
        let tree = {
            let mut tree = async_tree::AsyncTree::new(async_tree::Config {
                finalized_async_user_data: None,
                retry_after_failed: Duration::from_secs(10),
                blocks_capacity: 32,
            });
            let node_index = tree.input_insert_block(
                Block {
                    hash: header::hash_from_scale_encoded_header(
                        &config.genesis_block_scale_encoded_header,
                    ),
                    height: 0,
                    scale_encoded_header: config.genesis_block_scale_encoded_header,
                },
                None,
                false,
                true,
            );
            tree.input_finalize(node_index);

            Tree::FinalizedBlockRuntimeUnknown { tree }
        };

        Background {
            log_target: config.log_target.clone(),
            platform: config.platform.clone(),
            sync_service: config.sync_service.clone(),
            network_service: config.network_service.clone(),
            to_background: Box::pin(to_background.clone()),
            to_background_tx: to_background_tx.clone(),
            next_subscription_id: 0,
            tree,
            runtimes: slab::Slab::with_capacity(2),
            pending_subscriptions: VecDeque::with_capacity(8),
            blocks_stream: None,
            runtime_downloads: stream::FuturesUnordered::new(),
            progress_runtime_call_requests: stream::FuturesUnordered::new(),
        }
    };

    // Inner loop. Process incoming events.
    loop {
        // Yield at every loop in order to provide better tasks granularity.
        futures_lite::future::yield_now().await;

        enum WakeUpReason<TPlat: PlatformRef> {
            MustSubscribe,
            StartDownload(async_tree::AsyncOpId, async_tree::NodeIndex),
            TreeAdvanceFinalizedKnown(async_tree::OutputUpdate<Block, Arc<Runtime>>),
            TreeAdvanceFinalizedUnknown(async_tree::OutputUpdate<Block, Option<Arc<Runtime>>>),
            StartPendingSubscribeAll(ToBackgroundSubscribeAll<TPlat>),
            Notification(sync_service::Notification),
            SyncServiceSubscriptionReset,
            ToBackground(ToBackground<TPlat>),
            ForegroundClosed,
            RuntimeDownloadFinished(
                async_tree::AsyncOpId,
                Result<
                    (
                        Option<Vec<u8>>,
                        Option<Vec<u8>>,
                        Option<Vec<u8>>,
                        Option<Vec<Nibble>>,
                    ),
                    RuntimeDownloadError,
                >,
            ),
            ProgressRuntimeCallRequest(ProgressRuntimeCallRequest),
        }

        // Wait for something to happen or for some processing to be necessary.
        let wake_up_reason: WakeUpReason<_> = {
            let finalized_block_known =
                matches!(background.tree, Tree::FinalizedBlockRuntimeKnown { .. });
            let num_runtime_downloads = background.runtime_downloads.len();
            let any_subscription = match &background.tree {
                Tree::FinalizedBlockRuntimeKnown {
                    all_blocks_subscriptions,
                    ..
                } => !all_blocks_subscriptions.is_empty(),
                Tree::FinalizedBlockRuntimeUnknown { .. } => false,
            };
            let any_pending_subscription = !background.pending_subscriptions.is_empty();
            async {
                if finalized_block_known {
                    if let Some(pending_subscription) = background.pending_subscriptions.pop_front()
                    {
                        WakeUpReason::StartPendingSubscribeAll(pending_subscription)
                    } else {
                        future::pending().await
                    }
                } else {
                    future::pending().await
                }
            }
            .or(async {
                if let Some(blocks_stream) = background.blocks_stream.as_mut() {
                    if !any_subscription && !any_pending_subscription {
                        WakeUpReason::SyncServiceSubscriptionReset
                    } else {
                        blocks_stream.next().await.map_or(
                            WakeUpReason::SyncServiceSubscriptionReset,
                            WakeUpReason::Notification,
                        )
                    }
                } else if any_subscription || any_pending_subscription {
                    // Only start subscribing to the sync service if there is any pending
                    // or active runtime service subscription.
                    // Note that subscriptions to the runtime service aren't destroyed when the
                    // sync service subscriptions is lost but when the sync service is
                    // resubscribed.
                    WakeUpReason::MustSubscribe
                } else {
                    future::pending().await
                }
            })
            .or(async {
                background
                    .to_background
                    .next()
                    .await
                    .map_or(WakeUpReason::ForegroundClosed, WakeUpReason::ToBackground)
            })
            .or(async {
                if !background.runtime_downloads.is_empty() {
                    let (async_op_id, download_result) =
                        background.runtime_downloads.select_next_some().await;
                    WakeUpReason::RuntimeDownloadFinished(async_op_id, download_result)
                } else {
                    future::pending().await
                }
            })
            .or(async {
                if !background.progress_runtime_call_requests.is_empty() {
                    let result = background
                        .progress_runtime_call_requests
                        .select_next_some()
                        .await;
                    WakeUpReason::ProgressRuntimeCallRequest(result)
                } else {
                    future::pending().await
                }
            })
            .or(async {
                loop {
                    // There might be a new runtime download to start.
                    // Don't download more than 2 runtimes at a time.
                    let wait = if num_runtime_downloads < 2 {
                        // Grab what to download. If there's nothing more to download, do nothing.
                        let async_op = match &mut background.tree {
                            Tree::FinalizedBlockRuntimeKnown { tree, .. } => {
                                tree.next_necessary_async_op(&background.platform.now())
                            }
                            Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                                tree.next_necessary_async_op(&background.platform.now())
                            }
                        };

                        match async_op {
                            async_tree::NextNecessaryAsyncOp::Ready(dl) => {
                                break WakeUpReason::StartDownload(dl.id, dl.block_index);
                            }
                            async_tree::NextNecessaryAsyncOp::NotReady { when } => {
                                if let Some(when) = when {
                                    either::Left(background.platform.sleep_until(when))
                                } else {
                                    either::Right(future::pending())
                                }
                            }
                        }
                    } else {
                        either::Right(future::pending())
                    };

                    match &mut background.tree {
                        Tree::FinalizedBlockRuntimeKnown { tree, .. } => {
                            match tree.try_advance_output() {
                                Some(update) => {
                                    break WakeUpReason::TreeAdvanceFinalizedKnown(update);
                                }
                                None => wait.await,
                            }
                        }
                        Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                            match tree.try_advance_output() {
                                Some(update) => {
                                    break WakeUpReason::TreeAdvanceFinalizedUnknown(update);
                                }
                                None => wait.await,
                            }
                        }
                    }
                }
            })
            .await
        };

        match wake_up_reason {
            WakeUpReason::StartDownload(download_id, block_index) => {
                let block = match &mut background.tree {
                    Tree::FinalizedBlockRuntimeKnown { tree, .. } => &tree[block_index],
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => &tree[block_index],
                };

                log!(
                    &background.platform,
                    Debug,
                    &background.log_target,
                    "block-runtime-download-start",
                    block_hash = HashDisplay(&block.hash)
                );

                // Dispatches a runtime download task to `runtime_downloads`.
                background.runtime_downloads.push(Box::pin({
                    let future = download_runtime(
                        background.sync_service.clone(),
                        block.hash,
                        &block.scale_encoded_header,
                    );

                    async move { (download_id, future.await) }
                }));
            }

            WakeUpReason::TreeAdvanceFinalizedKnown(async_tree::OutputUpdate::Finalized {
                user_data: new_finalized,
                best_output_block_updated,
                pruned_blocks,
                former_finalized_async_op_user_data: former_finalized_runtime,
                ..
            }) => {
                let Tree::FinalizedBlockRuntimeKnown {
                    tree,
                    finalized_block,
                    all_blocks_subscriptions,
                    pinned_blocks,
                } = &mut background.tree
                else {
                    unreachable!()
                };

                *finalized_block = new_finalized;
                let best_block_hash_if_changed = if best_output_block_updated {
                    Some(
                        tree.output_best_block_index()
                            .map_or(finalized_block.hash, |(idx, _)| tree[idx].hash),
                    )
                } else {
                    None
                };

                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "output-chain-finalized",
                    block_hash = HashDisplay(&finalized_block.hash),
                    best_block_hash = if let Some(best_block_hash) = best_block_hash_if_changed {
                        Cow::Owned(HashDisplay(&best_block_hash).to_string())
                    } else {
                        Cow::Borrowed("<unchanged>")
                    },
                    num_subscribers = all_blocks_subscriptions.len()
                );

                // The finalization might cause some runtimes in the list of runtimes
                // to have become unused. Clean them up.
                drop(former_finalized_runtime);
                background
                    .runtimes
                    .retain(|_, runtime| runtime.strong_count() > 0);

                let all_blocks_notif = Notification::Finalized {
                    best_block_hash_if_changed,
                    hash: finalized_block.hash,
                    pruned_blocks: pruned_blocks.iter().map(|(_, b, _)| b.hash).collect(),
                };

                let mut to_remove = Vec::new();
                for (subscription_id, (sender, finalized_pinned_remaining)) in
                    all_blocks_subscriptions.iter_mut()
                {
                    let count_limit = pruned_blocks.len() + 1;

                    if *finalized_pinned_remaining < count_limit {
                        to_remove.push(*subscription_id);
                        continue;
                    }

                    if sender.try_send(all_blocks_notif.clone()).is_err() {
                        to_remove.push(*subscription_id);
                        continue;
                    }

                    *finalized_pinned_remaining -= count_limit;

                    // Mark the finalized and pruned blocks as finalized or non-canonical.
                    for block in iter::once(&finalized_block.hash)
                        .chain(pruned_blocks.iter().map(|(_, b, _)| &b.hash))
                    {
                        if let Some(pin) = pinned_blocks.get_mut(&(*subscription_id, *block)) {
                            debug_assert!(pin.block_ignores_limit);
                            pin.block_ignores_limit = false;
                        }
                    }
                }
                for to_remove in to_remove {
                    all_blocks_subscriptions.remove(&to_remove);
                    let pinned_blocks_to_remove = pinned_blocks
                        .range((to_remove, [0; 32])..=(to_remove, [0xff; 32]))
                        .map(|((_, h), _)| *h)
                        .collect::<Vec<_>>();
                    for block in pinned_blocks_to_remove {
                        pinned_blocks.remove(&(to_remove, block));
                    }
                }
            }

            WakeUpReason::TreeAdvanceFinalizedKnown(async_tree::OutputUpdate::Block(block)) => {
                let Tree::FinalizedBlockRuntimeKnown {
                    tree,
                    finalized_block,
                    all_blocks_subscriptions,
                    pinned_blocks,
                } = &mut background.tree
                else {
                    unreachable!()
                };

                let block_index = block.index;
                let block_runtime = tree.block_async_user_data(block_index).unwrap().clone();
                let block_hash = tree[block_index].hash;
                let scale_encoded_header = tree[block_index].scale_encoded_header.clone();
                let is_new_best = block.is_new_best;

                let (block_number, state_trie_root_hash) = {
                    let decoded = header::decode(
                        &scale_encoded_header,
                        background.sync_service.block_number_bytes(),
                    )
                    .unwrap();
                    (decoded.number, *decoded.state_root)
                };

                let parent_runtime = tree
                    .parent(block_index)
                    .map_or(tree.output_finalized_async_user_data().clone(), |idx| {
                        tree.block_async_user_data(idx).unwrap().clone()
                    });

                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "output-chain-new-block",
                    block_hash = HashDisplay(&tree[block_index].hash),
                    is_new_best,
                    num_subscribers = all_blocks_subscriptions.len()
                );

                let notif = Notification::Block(BlockNotification {
                    parent_hash: tree
                        .parent(block_index)
                        .map_or(finalized_block.hash, |idx| tree[idx].hash),
                    is_new_best,
                    scale_encoded_header,
                    new_runtime: if !Arc::ptr_eq(&parent_runtime, &block_runtime) {
                        Some(
                            block_runtime
                                .runtime
                                .as_ref()
                                .map(|rt| rt.runtime_version().clone())
                                .map_err(|err| err.clone()),
                        )
                    } else {
                        None
                    },
                });

                let mut to_remove = Vec::new();
                for (subscription_id, (sender, _)) in all_blocks_subscriptions.iter_mut() {
                    if sender.try_send(notif.clone()).is_ok() {
                        let _prev_value = pinned_blocks.insert(
                            (*subscription_id, block_hash),
                            PinnedBlock {
                                runtime: block_runtime.clone(),
                                state_trie_root_hash,
                                block_number,
                                block_ignores_limit: true,
                            },
                        );
                        debug_assert!(_prev_value.is_none());
                    } else {
                        to_remove.push(*subscription_id);
                    }
                }
                for to_remove in to_remove {
                    all_blocks_subscriptions.remove(&to_remove);
                    let pinned_blocks_to_remove = pinned_blocks
                        .range((to_remove, [0; 32])..=(to_remove, [0xff; 32]))
                        .map(|((_, h), _)| *h)
                        .collect::<Vec<_>>();
                    for block in pinned_blocks_to_remove {
                        pinned_blocks.remove(&(to_remove, block));
                    }
                }
            }

            WakeUpReason::TreeAdvanceFinalizedKnown(
                async_tree::OutputUpdate::BestBlockChanged { best_block_index },
            ) => {
                let Tree::FinalizedBlockRuntimeKnown {
                    tree,
                    finalized_block,
                    all_blocks_subscriptions,
                    pinned_blocks,
                } = &mut background.tree
                else {
                    unreachable!()
                };

                let hash = best_block_index
                    .map_or(&*finalized_block, |idx| &tree[idx])
                    .hash;

                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "output-chain-best-block-update",
                    block_hash = HashDisplay(&hash),
                    num_subscribers = all_blocks_subscriptions.len()
                );

                let notif = Notification::BestBlockChanged { hash };

                let mut to_remove = Vec::new();
                for (subscription_id, (sender, _)) in all_blocks_subscriptions.iter_mut() {
                    if sender.try_send(notif.clone()).is_err() {
                        to_remove.push(*subscription_id);
                    }
                }
                for to_remove in to_remove {
                    all_blocks_subscriptions.remove(&to_remove);
                    let pinned_blocks_to_remove = pinned_blocks
                        .range((to_remove, [0; 32])..=(to_remove, [0xff; 32]))
                        .map(|((_, h), _)| *h)
                        .collect::<Vec<_>>();
                    for block in pinned_blocks_to_remove {
                        pinned_blocks.remove(&(to_remove, block));
                    }
                }
            }

            WakeUpReason::TreeAdvanceFinalizedUnknown(async_tree::OutputUpdate::Block(_))
            | WakeUpReason::TreeAdvanceFinalizedUnknown(
                async_tree::OutputUpdate::BestBlockChanged { .. },
            ) => {
                // Nothing to do.
                continue;
            }

            WakeUpReason::TreeAdvanceFinalizedUnknown(async_tree::OutputUpdate::Finalized {
                user_data: new_finalized,
                former_finalized_async_op_user_data,
                best_output_block_updated,
                ..
            }) => {
                let Tree::FinalizedBlockRuntimeUnknown { tree, .. } = &mut background.tree else {
                    unreachable!()
                };

                // Make sure that this is the first finalized block whose runtime is
                // known, otherwise there's a pretty big bug somewhere.
                debug_assert!(former_finalized_async_op_user_data.is_none());

                let best_block_hash_if_changed = if best_output_block_updated {
                    Some(
                        tree.output_best_block_index()
                            .map_or(new_finalized.hash, |(idx, _)| tree[idx].hash),
                    )
                } else {
                    None
                };
                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "output-chain-initialized",
                    finalized_block_hash = HashDisplay(&new_finalized.hash),
                    best_block_hash = if let Some(best_block_hash) = best_block_hash_if_changed {
                        Cow::Owned(HashDisplay(&best_block_hash).to_string())
                    } else {
                        Cow::Borrowed("<unchanged>")
                    },
                );

                // Substitute `tree` with a dummy empty tree just in order to extract
                // the value. The `tree` only contains "async op user datas" equal
                // to `Some` (they're inserted manually when a download finishes)
                // except for the finalized block which has now just been extracted.
                // We can safely unwrap() all these user datas.
                let new_tree = mem::replace(
                    tree,
                    async_tree::AsyncTree::new(async_tree::Config {
                        finalized_async_user_data: None,
                        retry_after_failed: Duration::new(0, 0),
                        blocks_capacity: 0,
                    }),
                )
                .map_async_op_user_data(|runtime_index| runtime_index.unwrap());

                // Change the state of `Background` to the "finalized runtime known" state.
                background.tree = Tree::FinalizedBlockRuntimeKnown {
                    all_blocks_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                        32,
                        Default::default(),
                    ), // TODO: capacity?
                    pinned_blocks: BTreeMap::new(),
                    tree: new_tree,
                    finalized_block: new_finalized,
                };
            }

            WakeUpReason::MustSubscribe => {
                // Subscription to the sync service must be recreated.

                // The buffer size should be large enough so that, if the CPU is busy, it
                // doesn't become full before the execution of the runtime service resumes.
                // Note that this `await` freezes the entire runtime service background task,
                // but the sync service guarantees that `subscribe_all` returns very quickly.
                let subscription = background.sync_service.subscribe_all(32, true).await;

                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "sync-service-subscribed",
                    finalized_block_hash = HashDisplay(&header::hash_from_scale_encoded_header(
                        &subscription.finalized_block_scale_encoded_header
                    )),
                    finalized_block_runtime_known = ?subscription.finalized_block_runtime.is_some()
                );

                // Update the state of `Background` with what we just grabbed.
                //
                // Note that the content of `Background` is reset unconditionally.
                // It might seem like a good idea to only reset the content of `Background` if the new
                // subscription has a different finalized block than currently. However, there is
                // absolutely no guarantee for the non-finalized blocks currently in the tree to be a
                // subset or superset of the non-finalized blocks in the new subscription.
                // Using the new subscription but keeping the existing tree could therefore result in
                // state inconsistencies.
                //
                // Additionally, the situation where a subscription is killed but the finalized block
                // didn't change should be extremely rare anyway.
                {
                    background.runtimes = slab::Slab::with_capacity(2); // TODO: hardcoded capacity

                    // TODO: DRY below
                    if let Some(finalized_block_runtime) = subscription.finalized_block_runtime {
                        let finalized_block_hash = header::hash_from_scale_encoded_header(
                            &subscription.finalized_block_scale_encoded_header,
                        );
                        let finalized_block_height = header::decode(
                            &subscription.finalized_block_scale_encoded_header,
                            background.sync_service.block_number_bytes(),
                        )
                        .unwrap()
                        .number; // TODO: consider feeding the information from the sync service?

                        let storage_code_len = u64::try_from(
                            finalized_block_runtime
                                .storage_code
                                .as_ref()
                                .map_or(0, |v| v.len()),
                        )
                        .unwrap();

                        let runtime = Arc::new(Runtime {
                            runtime_code: finalized_block_runtime.storage_code,
                            heap_pages: finalized_block_runtime.storage_heap_pages,
                            code_merkle_value: finalized_block_runtime.code_merkle_value,
                            closest_ancestor_excluding: finalized_block_runtime
                                .closest_ancestor_excluding,
                            runtime: Ok(finalized_block_runtime.virtual_machine),
                        });

                        match &runtime.runtime {
                            Ok(runtime) => {
                                log!(
                                    &background.platform,
                                    Info,
                                    &background.log_target,
                                    format!(
                                        "Finalized block runtime ready. Spec version: {}. \
                                        Size of `:code`: {}.",
                                        runtime.runtime_version().decode().spec_version,
                                        BytesDisplay(storage_code_len)
                                    )
                                );
                            }
                            Err(error) => {
                                log!(
                                    &background.platform,
                                    Warn,
                                    &background.log_target,
                                    format!(
                                        "Erronenous finalized block runtime. Size of \
                                        `:code`: {}.\nError: {}\nThis indicates an incompatibility \
                                        between smoldot and the chain.",
                                        BytesDisplay(storage_code_len),
                                        error
                                    )
                                );
                            }
                        }

                        background.tree = Tree::FinalizedBlockRuntimeKnown {
                            all_blocks_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                                32,
                                Default::default(),
                            ), // TODO: capacity?
                            pinned_blocks: BTreeMap::new(),
                            finalized_block: Block {
                                hash: finalized_block_hash,
                                height: finalized_block_height,
                                scale_encoded_header: subscription
                                    .finalized_block_scale_encoded_header,
                            },
                            tree: {
                                let mut tree =
                                    async_tree::AsyncTree::<_, Block, _>::new(async_tree::Config {
                                        finalized_async_user_data: runtime,
                                        retry_after_failed: Duration::from_secs(10), // TODO: hardcoded
                                        blocks_capacity: 32,
                                    });

                                for block in subscription.non_finalized_blocks_ancestry_order {
                                    let parent_index = if block.parent_hash == finalized_block_hash
                                    {
                                        None
                                    } else {
                                        Some(
                                            tree.input_output_iter_unordered()
                                                .find(|b| b.user_data.hash == block.parent_hash)
                                                .unwrap()
                                                .id,
                                        )
                                    };

                                    let same_runtime_as_parent = same_runtime_as_parent(
                                        &block.scale_encoded_header,
                                        background.sync_service.block_number_bytes(),
                                    );
                                    let _ = tree.input_insert_block(
                                        Block {
                                            hash: header::hash_from_scale_encoded_header(
                                                &block.scale_encoded_header,
                                            ),
                                            height: header::decode(
                                                &block.scale_encoded_header,
                                                background.sync_service.block_number_bytes(),
                                            )
                                            .unwrap()
                                            .number, // TODO: consider feeding the information from the sync service?
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
                        background.tree = Tree::FinalizedBlockRuntimeUnknown {
                            tree: {
                                let mut tree = async_tree::AsyncTree::new(async_tree::Config {
                                    finalized_async_user_data: None,
                                    retry_after_failed: Duration::from_secs(10), // TODO: hardcoded
                                    blocks_capacity: 32,
                                });
                                let node_index = tree.input_insert_block(
                                    Block {
                                        hash: header::hash_from_scale_encoded_header(
                                            &subscription.finalized_block_scale_encoded_header,
                                        ),
                                        height: header::decode(
                                            &subscription.finalized_block_scale_encoded_header,
                                            background.sync_service.block_number_bytes(),
                                        )
                                        .unwrap()
                                        .number, // TODO: consider feeding the information from the sync service?
                                        scale_encoded_header: subscription
                                            .finalized_block_scale_encoded_header,
                                    },
                                    None,
                                    false,
                                    true,
                                );
                                tree.input_finalize(node_index);

                                for block in subscription.non_finalized_blocks_ancestry_order {
                                    // TODO: O(n)
                                    let parent_index = tree
                                        .input_output_iter_unordered()
                                        .find(|b| b.user_data.hash == block.parent_hash)
                                        .unwrap()
                                        .id;

                                    let same_runtime_as_parent = same_runtime_as_parent(
                                        &block.scale_encoded_header,
                                        background.sync_service.block_number_bytes(),
                                    );
                                    let _ = tree.input_insert_block(
                                        Block {
                                            hash: header::hash_from_scale_encoded_header(
                                                &block.scale_encoded_header,
                                            ),
                                            height: header::decode(
                                                &block.scale_encoded_header,
                                                background.sync_service.block_number_bytes(),
                                            )
                                            .unwrap()
                                            .number, // TODO: consider feeding the information from the sync service?
                                            scale_encoded_header: block.scale_encoded_header,
                                        },
                                        Some(parent_index),
                                        same_runtime_as_parent,
                                        block.is_new_best,
                                    );
                                }

                                tree
                            },
                        };
                    }
                }

                background.blocks_stream = Some(Box::pin(subscription.new_blocks));
                background.runtime_downloads = stream::FuturesUnordered::new();
            }

            WakeUpReason::StartPendingSubscribeAll(pending_subscription) => {
                // A subscription is waiting to be started.

                // Extract the components of the `FinalizedBlockRuntimeKnown`.
                let (tree, finalized_block, pinned_blocks, all_blocks_subscriptions) =
                    match &mut background.tree {
                        Tree::FinalizedBlockRuntimeKnown {
                            tree,
                            finalized_block,
                            pinned_blocks,
                            all_blocks_subscriptions,
                        } => (
                            tree,
                            finalized_block,
                            pinned_blocks,
                            all_blocks_subscriptions,
                        ),
                        _ => unreachable!(),
                    };

                let (tx, new_blocks_channel) =
                    async_channel::bounded(pending_subscription.buffer_size);
                let subscription_id = background.next_subscription_id;
                debug_assert_eq!(
                    pinned_blocks
                        .range((subscription_id, [0; 32])..=(subscription_id, [0xff; 32]))
                        .count(),
                    0
                );
                background.next_subscription_id += 1;

                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "pending-runtime-service-subscriptions-process",
                    subscription_id
                );

                let decoded_finalized_block = header::decode(
                    &finalized_block.scale_encoded_header,
                    background.sync_service.block_number_bytes(),
                )
                .unwrap();

                let _prev_value = pinned_blocks.insert(
                    (subscription_id, finalized_block.hash),
                    PinnedBlock {
                        runtime: tree.output_finalized_async_user_data().clone(),
                        state_trie_root_hash: *decoded_finalized_block.state_root,
                        block_number: decoded_finalized_block.number,
                        block_ignores_limit: false,
                    },
                );
                debug_assert!(_prev_value.is_none());

                let mut non_finalized_blocks_ancestry_order =
                    Vec::with_capacity(tree.num_input_non_finalized_blocks());
                for block in tree.input_output_iter_ancestry_order() {
                    let runtime = match block.async_op_user_data {
                        Some(rt) => rt.clone(),
                        None => continue, // Runtime of that block not known yet, so it shouldn't be reported.
                    };

                    let block_hash = block.user_data.hash;
                    let parent_runtime = tree.parent(block.id).map_or(
                        tree.output_finalized_async_user_data().clone(),
                        |parent_idx| tree.block_async_user_data(parent_idx).unwrap().clone(),
                    );

                    let parent_hash = *header::decode(
                        &block.user_data.scale_encoded_header,
                        background.sync_service.block_number_bytes(),
                    )
                    .unwrap()
                    .parent_hash; // TODO: correct? if yes, document
                    debug_assert!(
                        parent_hash == finalized_block.hash
                            || tree
                                .input_output_iter_ancestry_order()
                                .any(|b| parent_hash == b.user_data.hash
                                    && b.async_op_user_data.is_some())
                    );

                    let decoded_header = header::decode(
                        &block.user_data.scale_encoded_header,
                        background.sync_service.block_number_bytes(),
                    )
                    .unwrap();

                    let _prev_value = pinned_blocks.insert(
                        (subscription_id, block_hash),
                        PinnedBlock {
                            runtime: runtime.clone(),
                            state_trie_root_hash: *decoded_header.state_root,
                            block_number: decoded_header.number,
                            block_ignores_limit: true,
                        },
                    );
                    debug_assert!(_prev_value.is_none());

                    non_finalized_blocks_ancestry_order.push(BlockNotification {
                        is_new_best: block.is_output_best,
                        parent_hash,
                        scale_encoded_header: block.user_data.scale_encoded_header.clone(),
                        new_runtime: if !Arc::ptr_eq(&runtime, &parent_runtime) {
                            Some(
                                runtime
                                    .runtime
                                    .as_ref()
                                    .map(|rt| rt.runtime_version().clone())
                                    .map_err(|err| err.clone()),
                            )
                        } else {
                            None
                        },
                    });
                }

                debug_assert!(matches!(
                    non_finalized_blocks_ancestry_order
                        .iter()
                        .filter(|b| b.is_new_best)
                        .count(),
                    0 | 1
                ));

                all_blocks_subscriptions.insert(
                    subscription_id,
                    (tx, pending_subscription.max_pinned_blocks.get() - 1),
                );

                let _ = pending_subscription.result_tx.send(SubscribeAll {
                    finalized_block_scale_encoded_header: finalized_block
                        .scale_encoded_header
                        .clone(),
                    finalized_block_runtime: tree
                        .output_finalized_async_user_data()
                        .runtime
                        .as_ref()
                        .map(|rt| rt.runtime_version().clone())
                        .map_err(|err| err.clone()),
                    non_finalized_blocks_ancestry_order,
                    new_blocks: Subscription {
                        subscription_id,
                        channel: Box::pin(new_blocks_channel),
                        to_background: background.to_background_tx.upgrade().unwrap(),
                    },
                });
            }

            WakeUpReason::SyncServiceSubscriptionReset => {
                // The sync service subscription has been or must be reset.
                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "sync-subscription-reset"
                );
                background.blocks_stream = None;
            }

            WakeUpReason::ForegroundClosed => {
                // Frontend and all subscriptions have shut down.
                log!(
                    &background.platform,
                    Debug,
                    &background.log_target,
                    "graceful-shutdown"
                );
                return;
            }

            WakeUpReason::ToBackground(ToBackground::SubscribeAll(msg)) => {
                // Foreground wants to subscribe.

                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "runtime-service-subscription-requested"
                );

                // In order to avoid potentially growing `pending_subscriptions` forever, we
                // remove senders that are closed. This is `O(n)`, but we expect this list to
                // be rather small.
                background
                    .pending_subscriptions
                    .retain(|s| !s.result_tx.is_canceled());
                background.pending_subscriptions.push_back(msg);
            }

            WakeUpReason::ToBackground(ToBackground::CompileAndPinRuntime {
                result_tx,
                storage_code,
                storage_heap_pages,
                code_merkle_value,
                closest_ancestor_excluding,
            }) => {
                // Foreground wants to compile the given runtime.

                // Try to find an existing identical runtime.
                let existing_runtime = background
                    .runtimes
                    .iter()
                    .filter_map(|(_, rt)| rt.upgrade())
                    .find(|rt| {
                        rt.runtime_code == storage_code && rt.heap_pages == storage_heap_pages
                    });

                let runtime = if let Some(existing_runtime) = existing_runtime {
                    log!(
                        &background.platform,
                        Trace,
                        &background.log_target,
                        "foreground-compile-and-pin-runtime-cache-hit"
                    );
                    existing_runtime
                } else {
                    // No identical runtime was found. Try compiling the new runtime.
                    let before_compilation = background.platform.now();
                    let runtime = compile_runtime(
                        &background.platform,
                        &background.log_target,
                        &storage_code,
                        &storage_heap_pages,
                    );
                    let compilation_duration = background.platform.now() - before_compilation;
                    log!(
                        &background.platform,
                        Debug,
                        &background.log_target,
                        "foreground-compile-and-pin-runtime-cache-miss",
                        ?compilation_duration,
                        compilation_success = runtime.is_ok()
                    );
                    let runtime = Arc::new(Runtime {
                        heap_pages: storage_heap_pages,
                        runtime_code: storage_code,
                        code_merkle_value,
                        closest_ancestor_excluding,
                        runtime,
                    });
                    background.runtimes.insert(Arc::downgrade(&runtime));
                    runtime
                };

                let _ = result_tx.send(runtime);
            }

            WakeUpReason::ToBackground(ToBackground::FinalizedRuntimeStorageMerkleValues {
                result_tx,
            }) => {
                // Foreground wants the finalized runtime storage Merkle values.

                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "foreground-finalized-runtime-storage-merkle-values"
                );

                let _ = result_tx.send(
                    if let Tree::FinalizedBlockRuntimeKnown { tree, .. } = &background.tree {
                        let runtime = &tree.output_finalized_async_user_data();
                        Some((
                            runtime.runtime_code.clone(),
                            runtime.code_merkle_value.clone(),
                            runtime.closest_ancestor_excluding.clone(),
                        ))
                    } else {
                        None
                    },
                );
            }

            WakeUpReason::ToBackground(ToBackground::IsNearHeadOfChainHeuristic { result_tx }) => {
                // Foreground wants to query whether we are at the head of the chain.

                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "foreground-is-near-head-of-chain-heuristic"
                );

                // If we aren't subscribed to the sync service yet, we notify that we are not
                // near the head of the chain.
                if background.blocks_stream.is_none() {
                    let _ = result_tx.send(false);
                    continue;
                }

                // Check whether any runtime has been downloaded yet. If not, we notify that
                // we're not near the head of the chain.
                let Tree::FinalizedBlockRuntimeKnown {
                    tree,
                    finalized_block,
                    ..
                } = &background.tree
                else {
                    let _ = result_tx.send(false);
                    continue;
                };

                // The runtime service head might be close to the sync service head, but if the
                // sync service is far away from the head of the chain, then the runtime service
                // is necessarily also far away.
                if !background
                    .sync_service
                    .is_near_head_of_chain_heuristic()
                    .await
                {
                    let _ = result_tx.send(false);
                    continue;
                }

                // If the input best block (i.e. what the sync service feeds us) is equal to
                // output finalized block (i.e. what the runtime service has downloaded), we are
                // at the very head of the chain.
                let Some(input_best) = tree.input_best_block_index() else {
                    let _ = result_tx.send(true);
                    continue;
                };

                // We consider ourselves as being at the head of the chain if the
                // distance between the output tree best (i.e. whose runtime has
                // been downloaded) and the input tree best (i.e. what the sync service
                // feeds us) is smaller than a certain number of blocks.
                // Note that the input best can have a smaller block height than the
                // output, for example in case of reorg.
                let is_near = tree[input_best].height.saturating_sub(
                    tree.output_best_block_index()
                        .map_or(finalized_block.height, |(idx, _)| tree[idx].height),
                ) <= 12;
                let _ = result_tx.send(is_near);
            }

            WakeUpReason::ToBackground(ToBackground::UnpinBlock {
                result_tx,
                subscription_id,
                block_hash,
            }) => {
                // Foreground wants a block unpinned.

                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "foreground-unpin-block",
                    subscription_id = subscription_id.0,
                    block_hash = HashDisplay(&block_hash)
                );

                if let Tree::FinalizedBlockRuntimeKnown {
                    all_blocks_subscriptions,
                    pinned_blocks,
                    ..
                } = &mut background.tree
                {
                    let block_ignores_limit = match pinned_blocks
                        .remove(&(subscription_id.0, block_hash))
                    {
                        Some(b) => b.block_ignores_limit,
                        None => {
                            // Cold path.Ò
                            if let Some((_, _)) = all_blocks_subscriptions.get(&subscription_id.0) {
                                let _ = result_tx.send(Err(()));
                            } else {
                                let _ = result_tx.send(Ok(()));
                            }
                            continue;
                        }
                    };

                    background.runtimes.retain(|_, rt| rt.strong_count() > 0);

                    if !block_ignores_limit {
                        let (_, finalized_pinned_remaining) = all_blocks_subscriptions
                            .get_mut(&subscription_id.0)
                            .unwrap();
                        *finalized_pinned_remaining += 1;
                    }
                }

                let _ = result_tx.send(Ok(()));
            }

            WakeUpReason::ToBackground(ToBackground::PinPinnedBlockRuntime {
                result_tx,
                subscription_id,
                block_hash,
            }) => {
                // Foreground wants to pin the runtime of a pinned block.

                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "foreground-pin-pinned-block-runtime",
                    subscription_id = subscription_id.0,
                    block_hash = HashDisplay(&block_hash)
                );

                let pinned_block = {
                    if let Tree::FinalizedBlockRuntimeKnown {
                        all_blocks_subscriptions,
                        pinned_blocks,
                        ..
                    } = &mut background.tree
                    {
                        match pinned_blocks.get(&(subscription_id.0, block_hash)) {
                            Some(v) => v.clone(),
                            None => {
                                // Cold path.
                                if let Some((_, _)) =
                                    all_blocks_subscriptions.get(&subscription_id.0)
                                {
                                    let _ = result_tx
                                        .send(Err(PinPinnedBlockRuntimeError::BlockNotPinned));
                                } else {
                                    let _ = result_tx.send(Err(
                                        PinPinnedBlockRuntimeError::ObsoleteSubscription,
                                    ));
                                }
                                continue;
                            }
                        }
                    } else {
                        let _ =
                            result_tx.send(Err(PinPinnedBlockRuntimeError::ObsoleteSubscription));
                        continue;
                    }
                };

                let _ = result_tx.send(Ok((
                    pinned_block.runtime.clone(),
                    pinned_block.state_trie_root_hash,
                    pinned_block.block_number,
                )));
            }

            WakeUpReason::ToBackground(ToBackground::RuntimeCall {
                result_tx,
                pinned_runtime,
                block_hash,
                block_number,
                block_state_trie_root_hash,
                function_name,
                required_api_version,
                parameters_vectored,
                total_attempts,
                timeout_per_request,
                _max_parallel: _, // TODO: unused /!\
            }) => {
                // Foreground wants to perform a runtime call.

                log!(
                    &background.platform,
                    Debug,
                    &background.log_target,
                    "foreground-runtime-call-start",
                    block_hash = HashDisplay(&block_hash),
                    block_number,
                    block_state_trie_root_hash = HashDisplay(&block_state_trie_root_hash),
                    function_name,
                    ?required_api_version,
                    parameters_vectored = HashDisplay(&parameters_vectored),
                    total_attempts,
                    ?timeout_per_request
                );

                let runtime = match &pinned_runtime.runtime {
                    Ok(rt) => rt.clone(),
                    Err(error) => {
                        // The runtime call can't succeed because smoldot was incapable of
                        // compiling the runtime.
                        log!(
                            &background.platform,
                            Trace,
                            &background.log_target,
                            "foreground-runtime-call-abort",
                            block_hash = HashDisplay(&block_hash),
                            error = "invalid-runtime"
                        );
                        let _ =
                            result_tx.send(Err(RuntimeCallError::InvalidRuntime(error.clone())));
                        continue;
                    }
                };

                let api_version =
                    if let Some((api_name, api_version_required)) = required_api_version {
                        let api_version_if_fulfilled = runtime
                            .runtime_version()
                            .decode()
                            .apis
                            .find_version(&api_name)
                            .filter(|api_version| api_version_required.contains(api_version));

                        let Some(api_version) = api_version_if_fulfilled else {
                            // API version required by caller isn't fulfilled.
                            log!(
                                &background.platform,
                                Trace,
                                &background.log_target,
                                "foreground-runtime-call-abort",
                                block_hash = HashDisplay(&block_hash),
                                error = "api-version-requirement-unfulfilled"
                            );
                            let _ = result_tx
                                .send(Err(RuntimeCallError::ApiVersionRequirementUnfulfilled));
                            continue;
                        };

                        Some(api_version)
                    } else {
                        None
                    };

                background
                    .progress_runtime_call_requests
                    .push(Box::pin(async move {
                        ProgressRuntimeCallRequest::Initialize(RuntimeCallRequest {
                            block_hash,
                            block_number,
                            block_state_trie_root_hash,
                            function_name,
                            api_version,
                            parameters_vectored,
                            runtime,
                            total_attempts,
                            timeout_per_request,
                            inaccessible_errors: Vec::with_capacity(cmp::min(
                                16,
                                usize::try_from(total_attempts).unwrap_or(usize::MAX),
                            )),
                            result_tx,
                        })
                    }));
            }

            WakeUpReason::ProgressRuntimeCallRequest(progress) => {
                let (mut operation, call_proof_and_sender) = match progress {
                    ProgressRuntimeCallRequest::StorageOnDemandStorageRequest {
                        result,
                        storage_request_sender,
                        mut state,
                    } => {
                        match result {
                            Ok(proof) => {
                                handle_storage_on_demand_progress(
                                    &background.platform,
                                    &background.log_target,
                                    &background.network_service,
                                    &background.sync_service,
                                    &mut background.progress_runtime_call_requests,
                                    state,
                                    Some(proof),
                                )
                                .await;
                            }
                            Err(error) => {
                                log!(
                                    &background.platform,
                                    Trace,
                                    &background.log_target,
                                    "storage-on-demand-request-fail",
                                    block_hash = HashDisplay(&state.block_hash),
                                    function_name = state.function_name,
                                    ?error
                                );
                                state.failed_attempts += 1;
                                state
                                    .inaccessible_errors
                                    .push(RuntimeCallInaccessibleError::StorageRequest(error));
                                background
                                    .network_service
                                    .ban_and_disconnect(
                                        storage_request_sender,
                                        network_service::BanSeverity::Low,
                                        "storage-proof-request-failed",
                                    )
                                    .await;
                                handle_storage_on_demand_progress(
                                    &background.platform,
                                    &background.log_target,
                                    &background.network_service,
                                    &background.sync_service,
                                    &mut background.progress_runtime_call_requests,
                                    state,
                                    None,
                                )
                                .await;
                            }
                        }
                        continue;
                    }
                    ProgressRuntimeCallRequest::StorageOnDemandChildStorageRequest {
                        result,
                        storage_request_sender,
                        mut state,
                    } => {
                        match result {
                            Ok(proof) => {
                                handle_storage_on_demand_progress(
                                    &background.platform,
                                    &background.log_target,
                                    &background.network_service,
                                    &background.sync_service,
                                    &mut background.progress_runtime_call_requests,
                                    state,
                                    Some(proof),
                                )
                                .await;
                            }
                            Err(error) => {
                                log!(
                                    &background.platform,
                                    Trace,
                                    &background.log_target,
                                    "storage-on-demand-child-request-fail",
                                    block_hash = HashDisplay(&state.block_hash),
                                    function_name = state.function_name,
                                    ?error
                                );
                                state.failed_attempts += 1;
                                state
                                    .inaccessible_errors
                                    .push(RuntimeCallInaccessibleError::ChildStorageRequest(error));
                                background
                                    .network_service
                                    .ban_and_disconnect(
                                        storage_request_sender,
                                        network_service::BanSeverity::Low,
                                        "child-storage-proof-request-failed",
                                    )
                                    .await;
                                handle_storage_on_demand_progress(
                                    &background.platform,
                                    &background.log_target,
                                    &background.network_service,
                                    &background.sync_service,
                                    &mut background.progress_runtime_call_requests,
                                    state,
                                    None,
                                )
                                .await;
                            }
                        }
                        continue;
                    }
                    ProgressRuntimeCallRequest::Initialize(operation) => {
                        // Check if parameters are too large for call proof request.
                        // If so, use storage-on-demand approach instead.
                        if operation.parameters_vectored.len()
                            > CALL_PROOF_REQUEST_PARAMETERS_SIZE_THRESHOLD
                        {
                            log!(
                                &background.platform,
                                Debug,
                                &background.log_target,
                                "foreground-runtime-call-storage-on-demand-start",
                                block_hash = HashDisplay(&operation.block_hash),
                                function_name = operation.function_name,
                                parameters_size = operation.parameters_vectored.len()
                            );

                            let state = StorageOnDemandState {
                                block_hash: operation.block_hash,
                                block_number: operation.block_number,
                                block_state_trie_root_hash: operation.block_state_trie_root_hash,
                                function_name: operation.function_name,
                                api_version: operation.api_version,
                                call: None,
                                runtime: Some(operation.runtime),
                                parameters_vectored: operation.parameters_vectored,
                                total_attempts: operation.total_attempts,
                                timeout_per_request: operation.timeout_per_request,
                                failed_attempts: 0,
                                inaccessible_errors: operation.inaccessible_errors,
                                result_tx: operation.result_tx,
                            };

                            handle_storage_on_demand_progress(
                                &background.platform,
                                &background.log_target,
                                &background.network_service,
                                &background.sync_service,
                                &mut background.progress_runtime_call_requests,
                                state,
                                None,
                            )
                            .await;
                            continue;
                        }
                        (operation, None)
                    }
                    ProgressRuntimeCallRequest::CallProofRequestDone {
                        result: Ok(proof),
                        call_proof_sender,
                        operation,
                    } => (operation, Some((proof, call_proof_sender))),
                    ProgressRuntimeCallRequest::CallProofRequestDone {
                        result: Err(error),
                        mut operation,
                        call_proof_sender,
                    } => {
                        log!(
                            &background.platform,
                            Trace,
                            &background.log_target,
                            "foreground-runtime-call-progress-fail",
                            block_hash = HashDisplay(&operation.block_hash),
                            function_name = operation.function_name,
                            parameters_vectored = HashDisplay(&operation.parameters_vectored),
                            remaining_attempts = usize::try_from(operation.total_attempts).unwrap()
                                - operation.inaccessible_errors.len()
                                - 1,
                            ?error
                        );
                        operation
                            .inaccessible_errors
                            .push(RuntimeCallInaccessibleError::Network(error));
                        background
                            .network_service
                            .ban_and_disconnect(
                                call_proof_sender,
                                network_service::BanSeverity::Low,
                                "call-proof-request-failed",
                            )
                            .await;
                        (operation, None)
                    }
                };

                // If the foreground is no longer interested in the result, abort now in order to
                // save resources.
                if operation.result_tx.is_canceled() {
                    continue;
                }

                // Process the call proof.
                if let Some((call_proof, call_proof_sender)) = call_proof_and_sender {
                    match runtime_call_single_attempt(
                        &background.platform,
                        operation.runtime.clone(),
                        &operation.function_name,
                        &operation.parameters_vectored,
                        &operation.block_state_trie_root_hash,
                        call_proof.decode(),
                    )
                    .await
                    {
                        (timing, Ok(output)) => {
                            // Execution finished successfully.
                            // This is the happy path.
                            log!(
                                &background.platform,
                                Debug,
                                &background.log_target,
                                "foreground-runtime-call-success",
                                block_hash = HashDisplay(&operation.block_hash),
                                function_name = operation.function_name,
                                parameters_vectored = HashDisplay(&operation.parameters_vectored),
                                output = HashDisplay(&output),
                                virtual_machine_call_duration = ?timing.virtual_machine_call_duration,
                                proof_access_duration = ?timing.proof_access_duration,
                            );
                            let _ = operation.result_tx.send(Ok(RuntimeCallSuccess {
                                output,
                                api_version: operation.api_version,
                            }));
                            continue;
                        }
                        (timing, Err(SingleRuntimeCallAttemptError::Execution(error))) => {
                            log!(
                                &background.platform,
                                Debug,
                                &background.log_target,
                                "foreground-runtime-call-fail",
                                block_hash = HashDisplay(&operation.block_hash),
                                function_name = operation.function_name,
                                parameters_vectored = HashDisplay(&operation.parameters_vectored),
                                ?error,
                                virtual_machine_call_duration = ?timing.virtual_machine_call_duration,
                                proof_access_duration = ?timing.proof_access_duration,
                            );
                            let _ = operation
                                .result_tx
                                .send(Err(RuntimeCallError::Execution(error)));
                            continue;
                        }
                        (timing, Err(SingleRuntimeCallAttemptError::Inaccessible(error))) => {
                            // This path is reached only if the call proof was invalid.
                            log!(
                                &background.platform,
                                Debug,
                                &background.log_target,
                                "foreground-runtime-call-progress-invalid-call-proof",
                                block_hash = HashDisplay(&operation.block_hash),
                                function_name = operation.function_name,
                                parameters_vectored = HashDisplay(&operation.parameters_vectored),
                                remaining_attempts = usize::try_from(operation.total_attempts)
                                    .unwrap()
                                    - operation.inaccessible_errors.len()
                                    - 1,
                                ?error,
                                virtual_machine_call_duration = ?timing.virtual_machine_call_duration,
                                proof_access_duration = ?timing.proof_access_duration,
                            );
                            operation.inaccessible_errors.push(error);
                            background
                                .network_service
                                .ban_and_disconnect(
                                    call_proof_sender,
                                    network_service::BanSeverity::High,
                                    "invalid-call-proof",
                                )
                                .await;
                        }
                    }
                }

                // If we have failed to obtain a valid proof several times, abort the runtime
                // call attempt altogether.
                if u32::try_from(operation.inaccessible_errors.len()).unwrap_or(u32::MAX)
                    >= operation.total_attempts
                {
                    // No log line is printed here because one is already printed earlier.
                    let _ = operation.result_tx.send(Err(RuntimeCallError::Inaccessible(
                        operation.inaccessible_errors,
                    )));
                    continue;
                }

                // This can be reached if the call proof was invalid or absent. We must start a
                // new call proof request.

                // Choose peer to query.
                // TODO: better peer selection
                // TODO: can there be a race condition where the sync service forgets that a peer has knowledge of a block? shouldn't we somehow cache the peers that know this block ahead of time or something?
                let Some(call_proof_target) = background
                    .sync_service
                    .peers_assumed_know_blocks(operation.block_number, &operation.block_hash)
                    .await
                    .choose(&mut rand_chacha::ChaCha20Rng::from_seed({
                        // TODO: hacky
                        let mut seed = [0; 32];
                        background.platform.fill_random_bytes(&mut seed);
                        seed
                    }))
                else {
                    // No peer knows this block. Returning with a failure.
                    log!(
                        &background.platform,
                        Debug,
                        &background.log_target,
                        "foreground-runtime-call-request-fail",
                        block_hash = HashDisplay(&operation.block_hash),
                        function_name = operation.function_name,
                        parameters_vectored = HashDisplay(&operation.parameters_vectored),
                        error = "no-peer-for-call-request"
                    );
                    let _ = operation.result_tx.send(Err(RuntimeCallError::Inaccessible(
                        operation.inaccessible_errors,
                    )));
                    continue;
                };

                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "foreground-runtime-call-request-start",
                    block_hash = HashDisplay(&operation.block_hash),
                    function_name = operation.function_name,
                    parameters_vectored = HashDisplay(&operation.parameters_vectored),
                    call_proof_target,
                );

                // Start the request.
                background.progress_runtime_call_requests.push(Box::pin({
                    let call_proof_request_future =
                        background.network_service.clone().call_proof_request(
                            call_proof_target.clone(),
                            network_service::CallProofRequestConfig {
                                block_hash: operation.block_hash,
                                method: Cow::Owned(operation.function_name.clone()), // TODO: overhead
                                parameter_vectored: iter::once(
                                    operation.parameters_vectored.clone(),
                                ), // TODO: overhead
                            },
                            operation.timeout_per_request,
                        );

                    async move {
                        let result = call_proof_request_future.await;
                        ProgressRuntimeCallRequest::CallProofRequestDone {
                            result,
                            operation,
                            call_proof_sender: call_proof_target,
                        }
                    }
                }));
            }

            WakeUpReason::Notification(sync_service::Notification::Block(new_block)) => {
                // Sync service has reported a new block.

                let same_runtime_as_parent = same_runtime_as_parent(
                    &new_block.scale_encoded_header,
                    background.sync_service.block_number_bytes(),
                );

                if same_runtime_as_parent {
                    log!(
                        &background.platform,
                        Trace,
                        &background.log_target,
                        "input-chain-new-block",
                        block_hash = HashDisplay(&header::hash_from_scale_encoded_header(
                            &new_block.scale_encoded_header
                        )),
                        parent_block_hash = HashDisplay(&new_block.parent_hash),
                        is_new_best = new_block.is_new_best,
                        same_runtime_as_parent = true
                    );
                } else {
                    log!(
                        &background.platform,
                        Debug,
                        &background.log_target,
                        "input-chain-new-block-runtime-upgrade",
                        block_hash = HashDisplay(&header::hash_from_scale_encoded_header(
                            &new_block.scale_encoded_header
                        )),
                        parent_block_hash = HashDisplay(&new_block.parent_hash),
                        is_new_best = new_block.is_new_best
                    );
                }

                match &mut background.tree {
                    Tree::FinalizedBlockRuntimeKnown {
                        tree,
                        finalized_block,
                        ..
                    } => {
                        let parent_index = if new_block.parent_hash == finalized_block.hash {
                            None
                        } else {
                            Some(
                                // TODO: O(n)
                                tree.input_output_iter_unordered()
                                    .find(|block| block.user_data.hash == new_block.parent_hash)
                                    .unwrap()
                                    .id,
                            )
                        };

                        tree.input_insert_block(
                            Block {
                                hash: header::hash_from_scale_encoded_header(
                                    &new_block.scale_encoded_header,
                                ),
                                height: header::decode(
                                    &new_block.scale_encoded_header,
                                    background.sync_service.block_number_bytes(),
                                )
                                .unwrap()
                                .number, // TODO: consider feeding the information from the sync service?
                                scale_encoded_header: new_block.scale_encoded_header,
                            },
                            parent_index,
                            same_runtime_as_parent,
                            new_block.is_new_best,
                        );
                    }
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                        // TODO: O(n)
                        let parent_index = tree
                            .input_output_iter_unordered()
                            .find(|block| block.user_data.hash == new_block.parent_hash)
                            .unwrap()
                            .id;
                        tree.input_insert_block(
                            Block {
                                hash: header::hash_from_scale_encoded_header(
                                    &new_block.scale_encoded_header,
                                ),
                                height: header::decode(
                                    &new_block.scale_encoded_header,
                                    background.sync_service.block_number_bytes(),
                                )
                                .unwrap()
                                .number, // TODO: consider feeding the information from the sync service?
                                scale_encoded_header: new_block.scale_encoded_header,
                            },
                            Some(parent_index),
                            same_runtime_as_parent,
                            new_block.is_new_best,
                        );
                    }
                }
            }

            WakeUpReason::Notification(sync_service::Notification::Finalized {
                hash,
                best_block_hash_if_changed,
                ..
            }) => {
                // Sync service has reported a finalized block.

                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "input-chain-finalized",
                    block_hash = HashDisplay(&hash),
                    best_block_hash = if let Some(best_block_hash) = best_block_hash_if_changed {
                        Cow::Owned(HashDisplay(&best_block_hash).to_string())
                    } else {
                        Cow::Borrowed("<unchanged>")
                    }
                );

                if let Some(best_block_hash) = best_block_hash_if_changed {
                    match &mut background.tree {
                        Tree::FinalizedBlockRuntimeKnown { tree, .. } => {
                            let new_best_block = tree
                                .input_output_iter_unordered()
                                .find(|block| block.user_data.hash == best_block_hash)
                                .unwrap()
                                .id;
                            tree.input_set_best_block(Some(new_best_block));
                        }
                        Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                            let new_best_block = tree
                                .input_output_iter_unordered()
                                .find(|block| block.user_data.hash == best_block_hash)
                                .unwrap()
                                .id;
                            tree.input_set_best_block(Some(new_best_block));
                        }
                    }
                }

                match &mut background.tree {
                    Tree::FinalizedBlockRuntimeKnown {
                        tree,
                        finalized_block,
                        ..
                    } => {
                        debug_assert_ne!(finalized_block.hash, hash);
                        let node_to_finalize = tree
                            .input_output_iter_unordered()
                            .find(|block| block.user_data.hash == hash)
                            .unwrap()
                            .id;
                        tree.input_finalize(node_to_finalize);
                    }
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                        let node_to_finalize = tree
                            .input_output_iter_unordered()
                            .find(|block| block.user_data.hash == hash)
                            .unwrap()
                            .id;
                        tree.input_finalize(node_to_finalize);
                    }
                }
            }

            WakeUpReason::Notification(sync_service::Notification::BestBlockChanged { hash }) => {
                // Sync service has reported a change in the best block.

                log!(
                    &background.platform,
                    Trace,
                    &background.log_target,
                    "input-chain-best-block-update",
                    block_hash = HashDisplay(&hash)
                );

                match &mut background.tree {
                    Tree::FinalizedBlockRuntimeKnown {
                        finalized_block,
                        tree,
                        ..
                    } => {
                        let idx = if hash == finalized_block.hash {
                            None
                        } else {
                            Some(
                                tree.input_output_iter_unordered()
                                    .find(|block| block.user_data.hash == hash)
                                    .unwrap()
                                    .id,
                            )
                        };
                        tree.input_set_best_block(idx);
                    }
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                        let idx = tree
                            .input_output_iter_unordered()
                            .find(|block| block.user_data.hash == hash)
                            .unwrap()
                            .id;
                        tree.input_set_best_block(Some(idx));
                    }
                }
            }

            WakeUpReason::RuntimeDownloadFinished(
                async_op_id,
                Ok((
                    storage_code,
                    storage_heap_pages,
                    code_merkle_value,
                    closest_ancestor_excluding,
                )),
            ) => {
                // A runtime has successfully finished downloading.

                let concerned_blocks = match &background.tree {
                    Tree::FinalizedBlockRuntimeKnown { tree, .. } => {
                        either::Left(tree.async_op_blocks(async_op_id))
                    }
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                        either::Right(tree.async_op_blocks(async_op_id))
                    }
                }
                .format_with(", ", |block, fmt| fmt(&HashDisplay(&block.hash)))
                .to_string();

                // Try to find an existing runtime identical to the one that has just been
                // downloaded. This loop is `O(n)`, but given that we expect this list to very
                // small (at most 1 or 2 elements), this is not a problem.
                let existing_runtime = background
                    .runtimes
                    .iter()
                    .filter_map(|(_, rt)| rt.upgrade())
                    .find(|rt| {
                        rt.runtime_code == storage_code && rt.heap_pages == storage_heap_pages
                    });

                // If no identical runtime was found, try compiling the runtime.
                let runtime = if let Some(existing_runtime) = existing_runtime {
                    log!(
                        &background.platform,
                        Debug,
                        &background.log_target,
                        "runtime-download-finish-compilation-cache-hit",
                        block_hashes = concerned_blocks,
                    );
                    existing_runtime
                } else {
                    let before_compilation = background.platform.now();
                    let runtime = compile_runtime(
                        &background.platform,
                        &background.log_target,
                        &storage_code,
                        &storage_heap_pages,
                    );
                    let compilation_duration = background.platform.now() - before_compilation;
                    log!(
                        &background.platform,
                        Debug,
                        &background.log_target,
                        "runtime-download-finish-compilation-cache-miss",
                        ?compilation_duration,
                        compilation_success = runtime.is_ok(),
                        block_hashes = concerned_blocks,
                    );
                    match &runtime {
                        Ok(runtime) => {
                            log!(
                                &background.platform,
                                Info,
                                &background.log_target,
                                format!(
                                    "Successfully compiled runtime. Spec version: {}. \
                                    Size of `:code`: {}.",
                                    runtime.runtime_version().decode().spec_version,
                                    BytesDisplay(
                                        u64::try_from(storage_code.as_ref().map_or(0, |v| v.len()))
                                            .unwrap()
                                    )
                                )
                            );
                        }
                        Err(error) => {
                            log!(
                                &background.platform,
                                Warn,
                                &background.log_target,
                                format!(
                                    "Failed to compile runtime. Size of `:code`: {}.\nError: {}\n\
                                    This indicates an incompatibility between smoldot and \
                                    the chain.",
                                    BytesDisplay(
                                        u64::try_from(storage_code.as_ref().map_or(0, |v| v.len()))
                                            .unwrap()
                                    ),
                                    error
                                )
                            );
                        }
                    }

                    let runtime = Arc::new(Runtime {
                        heap_pages: storage_heap_pages,
                        runtime_code: storage_code,
                        runtime,
                        code_merkle_value,
                        closest_ancestor_excluding,
                    });

                    background.runtimes.insert(Arc::downgrade(&runtime));
                    runtime
                };

                // Insert the runtime into the tree.
                match &mut background.tree {
                    Tree::FinalizedBlockRuntimeKnown { tree, .. } => {
                        tree.async_op_finished(async_op_id, runtime);
                    }
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                        tree.async_op_finished(async_op_id, Some(runtime));
                    }
                }
            }

            WakeUpReason::RuntimeDownloadFinished(async_op_id, Err(error)) => {
                // A runtime download has failed.

                let concerned_blocks = match &background.tree {
                    Tree::FinalizedBlockRuntimeKnown { tree, .. } => {
                        either::Left(tree.async_op_blocks(async_op_id))
                    }
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                        either::Right(tree.async_op_blocks(async_op_id))
                    }
                }
                .format_with(", ", |block, fmt| fmt(&HashDisplay(&block.hash)))
                .to_string();

                log!(
                    &background.platform,
                    Debug,
                    &background.log_target,
                    "runtime-download-error",
                    block_hashes = concerned_blocks,
                    ?error
                );
                if !error.is_network_problem() {
                    log!(
                        &background.platform,
                        Warn,
                        &background.log_target,
                        format!(
                            "Failed to download :code and :heappages of blocks {}: {}",
                            concerned_blocks, error
                        )
                    );
                }

                match &mut background.tree {
                    Tree::FinalizedBlockRuntimeKnown { tree, .. } => {
                        tree.async_op_failure(async_op_id, &background.platform.now());
                    }
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                        tree.async_op_failure(async_op_id, &background.platform.now());
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
enum RuntimeDownloadError {
    #[display("{_0}")]
    StorageQuery(sync_service::StorageQueryError),
    #[display("Couldn't decode header: {_0}")]
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

struct Background<TPlat: PlatformRef> {
    /// Target to use for all the logs of this service.
    log_target: String,

    /// See [`Config::platform`].
    platform: TPlat,

    /// See [`Config::sync_service`].
    sync_service: Arc<sync_service::SyncService<TPlat>>,

    /// See [`Config::network_service`].
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,

    /// Receiver for messages to the background task.
    to_background: Pin<Box<async_channel::Receiver<ToBackground<TPlat>>>>,

    /// Sending side of [`Background::to_background`].
    to_background_tx: async_channel::WeakSender<ToBackground<TPlat>>,

    /// Identifier of the next subscription for
    /// [`Tree::FinalizedBlockRuntimeKnown::all_blocks_subscriptions`].
    ///
    /// To avoid race conditions, subscription IDs are never used, even if we switch back to
    /// [`Tree::FinalizedBlockRuntimeUnknown`].
    next_subscription_id: u64,

    /// List of runtimes referenced by the tree in [`Tree`] and by
    /// [`Tree::FinalizedBlockRuntimeKnown::pinned_blocks`].
    ///
    /// Might contains obsolete values (i.e. stale `Weak`s) and thus must be cleaned from time to
    /// time.
    ///
    /// Because this list shouldn't contain many entries, it is acceptable to iterate over all
    /// the elements.
    runtimes: slab::Slab<Weak<Runtime>>,

    /// Tree of blocks received from the sync service. Keeps track of which block has been
    /// reported to the outer API.
    tree: Tree<TPlat>,

    /// List of subscription attempts started with
    /// [`Tree::FinalizedBlockRuntimeKnown::all_blocks_subscriptions`].
    ///
    /// When in the [`Tree::FinalizedBlockRuntimeKnown`] state, a [`SubscribeAll`] is constructed
    /// and sent back for each of these senders.
    /// When in the [`Tree::FinalizedBlockRuntimeUnknown`] state, the senders patiently wait here.
    pending_subscriptions: VecDeque<ToBackgroundSubscribeAll<TPlat>>,

    /// Stream of notifications coming from the sync service. `None` if not subscribed yet.
    blocks_stream: Option<Pin<Box<dyn Stream<Item = sync_service::Notification> + Send>>>,

    /// List of runtimes currently being downloaded from the network.
    /// For each item, the download id, storage value of `:code`, storage value of `:heappages`,
    /// and Merkle value and closest ancestor of `:code`.
    // TODO: use struct
    runtime_downloads: stream::FuturesUnordered<
        future::BoxFuture<
            'static,
            (
                async_tree::AsyncOpId,
                Result<
                    (
                        Option<Vec<u8>>,
                        Option<Vec<u8>>,
                        Option<Vec<u8>>,
                        Option<Vec<Nibble>>,
                    ),
                    RuntimeDownloadError,
                >,
            ),
        >,
    >,

    /// List of actions to perform to progress runtime calls requested by the frontend.
    progress_runtime_call_requests:
        stream::FuturesUnordered<future::BoxFuture<'static, ProgressRuntimeCallRequest>>,
}

enum Tree<TPlat: PlatformRef> {
    FinalizedBlockRuntimeKnown {
        /// Tree of blocks. Holds the state of the download of everything. Always `Some` when the
        /// `Mutex` is being locked. Temporarily switched to `None` during some operations.
        ///
        /// The asynchronous operation user data is a `usize` corresponding to the index within
        /// [`Background::runtimes`].
        tree: async_tree::AsyncTree<TPlat::Instant, Block, Arc<Runtime>>,

        /// Finalized block. Outside of the tree.
        finalized_block: Block,

        /// List of senders that get notified when new blocks arrive.
        /// See [`RuntimeService::subscribe_all`]. Alongside with each sender, the number of pinned
        /// finalized or non-canonical blocks remaining for this subscription.
        ///
        /// Keys are assigned from [`Background::next_subscription_id`].
        all_blocks_subscriptions: hashbrown::HashMap<
            u64,
            (async_channel::Sender<Notification>, usize),
            fnv::FnvBuildHasher,
        >,

        /// List of pinned blocks.
        ///
        /// Every time a block is reported to the API user, it is inserted in this map. The block
        /// is inserted after it has been pushed in the channel, but before it is pulled.
        /// Therefore, if the channel is closed it is the background that needs to purge all
        /// blocks from this container that are no longer relevant.
        ///
        /// Keys are `(subscription_id, block_hash)`. Values are indices within
        /// [`Background::runtimes`], state trie root hashes, block numbers, and whether the block
        /// is non-finalized and part of the canonical chain.
        pinned_blocks: BTreeMap<(u64, [u8; 32]), PinnedBlock>,
    },
    FinalizedBlockRuntimeUnknown {
        /// Tree of blocks. Holds the state of the download of everything. Always `Some` when the
        /// `Mutex` is being locked. Temporarily switched to `None` during some operations.
        ///
        /// The finalized block according to the [`async_tree::AsyncTree`] is actually a dummy.
        /// The "real" finalized block is a non-finalized block within this tree.
        ///
        /// The asynchronous operation user data is a `usize` corresponding to the index within
        /// [`Background::runtimes`]. The asynchronous operation user data is `None` for the dummy
        /// finalized block.
        // TODO: explain better
        tree: async_tree::AsyncTree<TPlat::Instant, Block, Option<Arc<Runtime>>>,
    },
}

/// Threshold in bytes above which we use the storage-on-demand approach instead of
/// call proof requests. This avoids exceeding protocol limits for large transactions.
const CALL_PROOF_REQUEST_PARAMETERS_SIZE_THRESHOLD: usize =
    smoldot::network::codec::LIGHT_PROTOCOL_REQUEST_MAX_SIZE.saturating_sub(1024);

/// See [`Background::progress_runtime_call_requests`].
enum ProgressRuntimeCallRequest {
    /// Must start the first call proof request.
    Initialize(RuntimeCallRequest),
    /// A call proof request has finished and the runtime call can be advanced.
    CallProofRequestDone {
        /// Outcome of the latest call proof request.
        result: Result<network_service::EncodedMerkleProof, network_service::CallProofRequestError>,
        /// Identity of the peer the call proof request was made against.
        call_proof_sender: network_service::PeerId,
        operation: RuntimeCallRequest,
    },
    /// Executing locally with storage-on-demand. Waiting for a storage proof request.
    StorageOnDemandStorageRequest {
        /// Outcome of the storage proof request.
        result:
            Result<network_service::EncodedMerkleProof, network_service::StorageProofRequestError>,
        /// Identity of the peer the storage request was made against.
        storage_request_sender: network_service::PeerId,
        /// State of the ongoing execution.
        state: StorageOnDemandState,
    },
    /// Executing locally with storage-on-demand. Waiting for a child storage proof request.
    StorageOnDemandChildStorageRequest {
        /// Outcome of the child storage proof request.
        result: Result<
            network_service::EncodedMerkleProof,
            network_service::ChildStorageProofRequestError,
        >,
        /// Identity of the peer the storage request was made against.
        storage_request_sender: network_service::PeerId,
        /// State of the ongoing execution.
        state: StorageOnDemandState,
    },
}

/// State of a runtime call being executed with storage fetched on demand.
struct StorageOnDemandState {
    block_hash: [u8; 32],
    block_number: u64,
    block_state_trie_root_hash: [u8; 32],
    function_name: String,
    api_version: Option<u32>,
    /// The runtime call in progress. `None` if we need to initialize it.
    call: Option<executor::runtime_call::RuntimeCall>,
    /// The runtime prototype, used to initialize the call if `call` is `None`.
    runtime: Option<executor::host::HostVmPrototype>,
    /// Parameters for initializing the call.
    parameters_vectored: Vec<u8>,
    total_attempts: u32,
    timeout_per_request: Duration,
    /// Number of failed storage requests so far.
    failed_attempts: u32,
    inaccessible_errors: Vec<RuntimeCallInaccessibleError>,
    result_tx: oneshot::Sender<Result<RuntimeCallSuccess, RuntimeCallError>>,
}

/// See [`ProgressRuntimeCallRequest`].
struct RuntimeCallRequest {
    block_hash: [u8; 32],
    block_number: u64,
    block_state_trie_root_hash: [u8; 32],
    function_name: String,
    /// Version of the API that was found. `Some` if and only if an API requirement was passed.
    api_version: Option<u32>,
    parameters_vectored: Vec<u8>,
    runtime: executor::host::HostVmPrototype,
    total_attempts: u32,
    timeout_per_request: Duration,
    inaccessible_errors: Vec<RuntimeCallInaccessibleError>,
    result_tx: oneshot::Sender<Result<RuntimeCallSuccess, RuntimeCallError>>,
}

struct Runtime {
    /// Successfully-compiled runtime and all its information. Can contain an error if an error
    /// happened, including a problem when obtaining the runtime specs.
    runtime: Result<executor::host::HostVmPrototype, RuntimeError>,

    /// Merkle value of the `:code` trie node.
    ///
    /// Can be `None` if the storage is empty, in which case the runtime will have failed to
    /// build.
    code_merkle_value: Option<Vec<u8>>,

    /// Closest ancestor of the `:code` key except for `:code` itself.
    closest_ancestor_excluding: Option<Vec<Nibble>>,

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

fn compile_runtime<TPlat: PlatformRef>(
    platform: &TPlat,
    log_target: &str,
    code: &Option<Vec<u8>>,
    heap_pages: &Option<Vec<u8>>,
) -> Result<executor::host::HostVmPrototype, RuntimeError> {
    // Parameters for `HostVmPrototype::new`.
    let module = code.as_ref().ok_or(RuntimeError::CodeNotFound)?;
    let heap_pages = executor::storage_heap_pages_to_value(heap_pages.as_deref())
        .map_err(RuntimeError::InvalidHeapPages)?;
    let exec_hint = executor::vm::ExecHint::CompileWithNonDeterministicValidation;

    // We try once with `allow_unresolved_imports: false`. If this fails due to unresolved
    // import, we try again but with `allowed_unresolved_imports: true`.
    // Having unresolved imports might cause errors later on, for example when validating
    // transactions or getting the parachain heads, but for now we continue the execution
    // and print a warning.
    match executor::host::HostVmPrototype::new(executor::host::Config {
        module,
        heap_pages,
        exec_hint,
        allow_unresolved_imports: false,
    }) {
        Ok(vm) => Ok(vm),
        Err(executor::host::NewErr::VirtualMachine(
            executor::vm::NewErr::UnresolvedFunctionImport {
                function,
                module_name,
            },
        )) => {
            match executor::host::HostVmPrototype::new(executor::host::Config {
                module,
                heap_pages,
                exec_hint,
                allow_unresolved_imports: true,
            }) {
                Ok(vm) => {
                    log!(
                        platform,
                        Warn,
                        log_target,
                        format!(
                            "Unresolved host function in runtime: `{}`:`{}`. Smoldot might \
                            encounter errors later on. Please report this issue in \
                            https://github.com/smol-dot/smoldot",
                            module_name, function
                        )
                    );

                    Ok(vm)
                }
                Err(executor::host::NewErr::VirtualMachine(
                    executor::vm::NewErr::UnresolvedFunctionImport { .. },
                )) => unreachable!(),
                Err(error) => {
                    // It's still possible that errors other than an unresolved host
                    // function happen.
                    Err(RuntimeError::Build(error))
                }
            }
        }
        Err(error) => Err(RuntimeError::Build(error)),
    }
}

/// Returns `true` if the block can be assumed to have the same runtime as its parent.
fn same_runtime_as_parent(header: &[u8], block_number_bytes: usize) -> bool {
    match header::decode(header, block_number_bytes) {
        Ok(h) => !h.digest.has_runtime_environment_updated(),
        Err(_) => false,
    }
}

fn download_runtime<TPlat: PlatformRef>(
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    block_hash: [u8; 32],
    scale_encoded_header: &[u8],
) -> impl Future<
    Output = Result<
        (
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<Nibble>>,
        ),
        RuntimeDownloadError,
    >,
> + use<TPlat> {
    // In order to perform the download, we need to known the state root hash of the
    // block in question, which requires decoding the block. If the decoding fails,
    // we report that the asynchronous operation has failed with the hope that this
    // block gets pruned in the future.
    let block_info = match header::decode(scale_encoded_header, sync_service.block_number_bytes()) {
        Ok(decoded_header) => Ok((*decoded_header.state_root, decoded_header.number)),
        Err(error) => Err(RuntimeDownloadError::InvalidHeader(error)),
    };

    async move {
        let (state_root, block_number) = block_info?;

        let mut storage_code = None;
        let mut storage_heap_pages = None;
        let mut code_merkle_value = None;
        let mut code_closest_ancestor_excluding = None;

        let mut query = sync_service
            .clone()
            .storage_query(
                block_number,
                block_hash,
                state_root,
                [
                    sync_service::StorageRequestItem {
                        key: b":code".to_vec(),
                        ty: sync_service::StorageRequestItemTy::ClosestDescendantMerkleValue,
                    },
                    sync_service::StorageRequestItem {
                        key: b":code".to_vec(),
                        ty: sync_service::StorageRequestItemTy::Value,
                    },
                    sync_service::StorageRequestItem {
                        key: b":heappages".to_vec(),
                        ty: sync_service::StorageRequestItemTy::Value,
                    },
                ]
                .into_iter(),
                3,
                Duration::from_secs(20),
                NonZero::<u32>::new(3).unwrap(),
            )
            .advance()
            .await;

        loop {
            match query {
                sync_service::StorageQueryProgress::Finished => {
                    break Ok((
                        storage_code,
                        storage_heap_pages,
                        code_merkle_value,
                        code_closest_ancestor_excluding,
                    ));
                }
                sync_service::StorageQueryProgress::Progress {
                    request_index: 0,
                    item:
                        sync_service::StorageResultItem::ClosestDescendantMerkleValue {
                            closest_descendant_merkle_value,
                            found_closest_ancestor_excluding,
                            ..
                        },
                    query: next,
                } => {
                    code_merkle_value = closest_descendant_merkle_value;
                    code_closest_ancestor_excluding = found_closest_ancestor_excluding;
                    query = next.advance().await;
                }
                sync_service::StorageQueryProgress::Progress {
                    request_index: 1,
                    item: sync_service::StorageResultItem::Value { value, .. },
                    query: next,
                } => {
                    storage_code = value;
                    query = next.advance().await;
                }
                sync_service::StorageQueryProgress::Progress {
                    request_index: 2,
                    item: sync_service::StorageResultItem::Value { value, .. },
                    query: next,
                } => {
                    storage_heap_pages = value;
                    query = next.advance().await;
                }
                sync_service::StorageQueryProgress::Progress { .. } => unreachable!(),
                sync_service::StorageQueryProgress::Error(error) => {
                    break Err(RuntimeDownloadError::StorageQuery(error));
                }
            }
        }
    }
}

/// Tries to perform a runtime call using the given call proof.
///
/// This function can have three possible outcomes: success, failure because the call proof is
/// invalid/incomplete, or failure because the execution fails.
///
/// This function is async in order to periodically yield during the execution.
async fn runtime_call_single_attempt<TPlat: PlatformRef>(
    platform: &TPlat,
    runtime: executor::host::HostVmPrototype,
    function_name: &str,
    parameters_vectored: &[u8],
    block_state_trie_root_hash: &[u8; 32],
    call_proof: &[u8],
) -> (
    SingleRuntimeCallTiming,
    Result<Vec<u8>, SingleRuntimeCallAttemptError>,
) {
    // Try to decode the proof. Succeed just means that the proof has the correct
    // encoding, and doesn't guarantee that the proof has all the necessary
    // entries.
    let call_proof = trie::proof_decode::decode_and_verify_proof(trie::proof_decode::Config {
        proof: call_proof,
    });

    // Keep track of the total time taken by the runtime call attempt.
    let mut timing = SingleRuntimeCallTiming {
        virtual_machine_call_duration: Duration::new(0, 0),
        proof_access_duration: Duration::new(0, 0),
    };

    // Attempt the runtime call.
    // If the call succeed, we interrupt the flow and `continue`.
    let runtime_call_duration_before = platform.now();
    let mut call = match executor::runtime_call::run(executor::runtime_call::Config {
        virtual_machine: runtime,
        function_to_call: function_name,
        parameter: iter::once(parameters_vectored),
        storage_proof_size_behavior:
            executor::runtime_call::StorageProofSizeBehavior::proof_recording_disabled(),
        storage_main_trie_changes: Default::default(),
        max_log_level: 0,
        calculate_trie_changes: false,
    }) {
        Ok(call) => call,
        Err((error, _)) => {
            // If starting the execution triggers an error, then the runtime call cannot
            // possibly succeed.
            // This can happen for example because the requested function doesn't exist.
            return (
                timing,
                Err(SingleRuntimeCallAttemptError::Execution(
                    RuntimeCallExecutionError::Start(error),
                )),
            );
        }
    };
    timing.virtual_machine_call_duration += platform.now() - runtime_call_duration_before;

    loop {
        let call_proof = match &call_proof {
            Ok(p) => p,
            Err(error) => {
                return (
                    timing,
                    Err(SingleRuntimeCallAttemptError::Inaccessible(
                        RuntimeCallInaccessibleError::InvalidCallProof(error.clone()),
                    )),
                );
            }
        };

        // Yield once at every iteration. This avoids monopolizing the CPU for
        // too long.
        futures_lite::future::yield_now().await;

        let child_trie = match call {
            executor::runtime_call::RuntimeCall::Finished(Ok(finished)) => {
                // Execution finished successfully.
                // This is the happy path.
                let output = finished.virtual_machine.value().as_ref().to_owned();
                return (timing, Ok(output));
            }
            executor::runtime_call::RuntimeCall::Finished(Err(error)) => {
                // Execution finished with an error.
                return (
                    timing,
                    Err(SingleRuntimeCallAttemptError::Execution(
                        RuntimeCallExecutionError::Execution(error.detail),
                    )),
                );
            }
            executor::runtime_call::RuntimeCall::StorageGet(ref get) => {
                get.child_trie().map(|c| c.as_ref().to_owned())
            }
            executor::runtime_call::RuntimeCall::ClosestDescendantMerkleValue(ref mv) => {
                mv.child_trie().map(|c| c.as_ref().to_owned())
            }
            executor::runtime_call::RuntimeCall::NextKey(ref nk) => {
                nk.child_trie().map(|c| c.as_ref().to_owned())
            }
            executor::runtime_call::RuntimeCall::SignatureVerification(r) => {
                let runtime_call_duration_before = platform.now();
                call = r.verify_and_resume();
                timing.virtual_machine_call_duration +=
                    platform.now() - runtime_call_duration_before;
                continue;
            }
            executor::runtime_call::RuntimeCall::LogEmit(r) => {
                // Logs are ignored.
                let runtime_call_duration_before = platform.now();
                call = r.resume();
                timing.virtual_machine_call_duration +=
                    platform.now() - runtime_call_duration_before;
                continue;
            }
            executor::runtime_call::RuntimeCall::Offchain(_) => {
                // Forbidden host function called.
                return (
                    timing,
                    Err(SingleRuntimeCallAttemptError::Execution(
                        RuntimeCallExecutionError::ForbiddenHostFunction,
                    )),
                );
            }
            executor::runtime_call::RuntimeCall::OffchainStorageSet(r) => {
                // Ignore offchain storage writes.
                let runtime_call_duration_before = platform.now();
                call = r.resume();
                timing.virtual_machine_call_duration +=
                    platform.now() - runtime_call_duration_before;
                continue;
            }
        };

        let proof_access_duration_before = platform.now();
        let trie_root = if let Some(child_trie) = child_trie {
            // TODO: allocation here, but probably not problematic
            const PREFIX: &[u8] = b":child_storage:default:";
            let mut key = Vec::with_capacity(PREFIX.len() + child_trie.len());
            key.extend_from_slice(PREFIX);
            key.extend_from_slice(child_trie.as_ref());
            match call_proof.storage_value(block_state_trie_root_hash, &key) {
                Err(_) => {
                    return (
                        timing,
                        Err(SingleRuntimeCallAttemptError::Inaccessible(
                            RuntimeCallInaccessibleError::MissingProofEntry,
                        )),
                    );
                }
                Ok(None) => None,
                Ok(Some((value, _))) => match <&[u8; 32]>::try_from(value) {
                    Ok(hash) => Some(hash),
                    Err(_) => {
                        return (
                            timing,
                            Err(SingleRuntimeCallAttemptError::Inaccessible(
                                RuntimeCallInaccessibleError::MissingProofEntry,
                            )),
                        );
                    }
                },
            }
        } else {
            Some(block_state_trie_root_hash)
        };

        match call {
            executor::runtime_call::RuntimeCall::StorageGet(get) => {
                let storage_value = if let Some(trie_root) = trie_root {
                    call_proof.storage_value(trie_root, get.key().as_ref())
                } else {
                    Ok(None)
                };
                let Ok(storage_value) = storage_value else {
                    return (
                        timing,
                        Err(SingleRuntimeCallAttemptError::Inaccessible(
                            RuntimeCallInaccessibleError::MissingProofEntry,
                        )),
                    );
                };
                timing.proof_access_duration += platform.now() - proof_access_duration_before;

                let runtime_call_duration_before = platform.now();
                call = get.inject_value(storage_value.map(|(val, vers)| (iter::once(val), vers)));
                timing.virtual_machine_call_duration +=
                    platform.now() - runtime_call_duration_before;
            }
            executor::runtime_call::RuntimeCall::ClosestDescendantMerkleValue(mv) => {
                let merkle_value = if let Some(trie_root) = trie_root {
                    call_proof.closest_descendant_merkle_value(trie_root, mv.key())
                } else {
                    Ok(None)
                };
                let Ok(merkle_value) = merkle_value else {
                    return (
                        timing,
                        Err(SingleRuntimeCallAttemptError::Inaccessible(
                            RuntimeCallInaccessibleError::MissingProofEntry,
                        )),
                    );
                };
                timing.proof_access_duration += platform.now() - proof_access_duration_before;

                let runtime_call_duration_before = platform.now();
                call = mv.inject_merkle_value(merkle_value);
                timing.virtual_machine_call_duration +=
                    platform.now() - runtime_call_duration_before;
            }
            executor::runtime_call::RuntimeCall::NextKey(nk) => {
                let next_key = if let Some(trie_root) = trie_root {
                    call_proof.next_key(
                        trie_root,
                        nk.key(),
                        nk.or_equal(),
                        nk.prefix(),
                        nk.branch_nodes(),
                    )
                } else {
                    Ok(None)
                };
                let Ok(next_key) = next_key else {
                    return (
                        timing,
                        Err(SingleRuntimeCallAttemptError::Inaccessible(
                            RuntimeCallInaccessibleError::MissingProofEntry,
                        )),
                    );
                };
                timing.proof_access_duration += platform.now() - proof_access_duration_before;

                let runtime_call_duration_before = platform.now();
                call = nk.inject_key(next_key);
                timing.virtual_machine_call_duration +=
                    platform.now() - runtime_call_duration_before;
            }
            _ => unreachable!(),
        }
    }
}

/// See [`runtime_call_single_attempt`].
#[derive(Debug, Clone)]
struct SingleRuntimeCallTiming {
    /// Time spent execution the virtual machine.
    virtual_machine_call_duration: Duration,
    /// Time spent accessing the call proof.
    proof_access_duration: Duration,
}

/// See [`runtime_call_single_attempt`].
#[derive(Debug, derive::Display, derive_more::Error, Clone)]
enum SingleRuntimeCallAttemptError {
    /// Error during the execution of the runtime.
    ///
    /// There is no point in trying the same call again, as it would result in the same error.
    #[display("Error during the execution of the runtime: {_0}")]
    Execution(RuntimeCallExecutionError),

    /// Error trying to access the storage required for the runtime call.
    ///
    /// Trying the same call again might succeed.
    #[display("Error trying to access the storage required for the runtime call: {_0}")]
    Inaccessible(RuntimeCallInaccessibleError),
}

/// Handles progress of a storage-on-demand runtime call execution.
///
/// This function executes the runtime locally and fetches storage values on-demand
/// via individual storage proof requests. This is used when the call proof request
/// would be too large (e.g., large transactions).
async fn handle_storage_on_demand_progress<TPlat: PlatformRef>(
    platform: &TPlat,
    log_target: &str,
    network_service: &Arc<network_service::NetworkServiceChain<TPlat>>,
    sync_service: &Arc<sync_service::SyncService<TPlat>>,
    progress_requests: &mut stream::FuturesUnordered<
        Pin<Box<dyn future::Future<Output = ProgressRuntimeCallRequest> + Send>>,
    >,
    mut state: StorageOnDemandState,
    storage_proof: Option<network_service::EncodedMerkleProof>,
) {
    // If the foreground is no longer interested, abort.
    if state.result_tx.is_canceled() {
        return;
    }

    // Initialize the runtime call if not already done.
    let call = if let Some(call) = state.call.take() {
        call
    } else {
        let runtime = state
            .runtime
            .take()
            .expect("runtime must be set for initialization");
        match executor::runtime_call::run(executor::runtime_call::Config {
            virtual_machine: runtime,
            function_to_call: &state.function_name,
            parameter: iter::once(&state.parameters_vectored[..]),
            storage_proof_size_behavior:
                executor::runtime_call::StorageProofSizeBehavior::proof_recording_disabled(),
            storage_main_trie_changes: Default::default(),
            max_log_level: 0,
            calculate_trie_changes: false,
        }) {
            Ok(call) => call,
            Err((error, _)) => {
                log!(
                    platform,
                    Debug,
                    log_target,
                    "storage-on-demand-start-fail",
                    block_hash = HashDisplay(&state.block_hash),
                    function_name = state.function_name,
                    ?error
                );
                let _ = state.result_tx.send(Err(RuntimeCallError::Execution(
                    RuntimeCallExecutionError::Start(error),
                )));
                return;
            }
        }
    };

    // If we have a storage proof from a previous request, inject the value.
    let mut call = if let Some(proof) = storage_proof {
        let decoded_proof =
            match trie::proof_decode::decode_and_verify_proof(trie::proof_decode::Config {
                proof: proof.decode(),
            }) {
                Ok(p) => Some(p),
                Err(error) => {
                    log!(
                        platform,
                        Debug,
                        log_target,
                        "storage-on-demand-invalid-proof",
                        block_hash = HashDisplay(&state.block_hash),
                        function_name = state.function_name,
                        ?error
                    );
                    state.failed_attempts += 1;
                    state
                        .inaccessible_errors
                        .push(RuntimeCallInaccessibleError::InvalidCallProof(error));
                    None
                }
            };

        // Inject the storage value based on the call state (only if proof was valid).
        if let Some(decoded_proof) = decoded_proof {
            inject_proof_into_call(call, &decoded_proof, &mut state)
        } else {
            call
        }
    } else {
        call
    };

    // Check if we've exceeded the maximum number of failed attempts.
    let Some(state) = check_too_many_attempts(platform, log_target, state) else {
        return;
    };

    // Run the call until it needs storage or finishes.
    loop {
        // Yield to avoid blocking for too long.
        futures_lite::future::yield_now().await;

        match call {
            executor::runtime_call::RuntimeCall::Finished(Ok(finished)) => {
                log!(
                    platform,
                    Debug,
                    log_target,
                    "storage-on-demand-success",
                    block_hash = HashDisplay(&state.block_hash),
                    function_name = state.function_name
                );
                let output = finished.virtual_machine.value().as_ref().to_owned();
                let _ = state.result_tx.send(Ok(RuntimeCallSuccess {
                    output,
                    api_version: state.api_version,
                }));
                return;
            }
            executor::runtime_call::RuntimeCall::Finished(Err(error)) => {
                log!(
                    platform,
                    Debug,
                    log_target,
                    "storage-on-demand-execution-error",
                    block_hash = HashDisplay(&state.block_hash),
                    function_name = state.function_name,
                    error = ?error.detail
                );
                let _ = state.result_tx.send(Err(RuntimeCallError::Execution(
                    RuntimeCallExecutionError::Execution(error.detail),
                )));
                return;
            }
            executor::runtime_call::RuntimeCall::StorageGet(ref get) => {
                let key = get.key().as_ref().to_vec();
                let child_trie = get.child_trie().map(|c| c.as_ref().to_vec());
                start_storage_request(
                    platform,
                    log_target,
                    network_service,
                    sync_service,
                    progress_requests,
                    state,
                    call,
                    key,
                    child_trie,
                )
                .await;
                return;
            }
            executor::runtime_call::RuntimeCall::ClosestDescendantMerkleValue(ref mv) => {
                let key: Vec<u8> = trie::nibbles_to_bytes_suffix_extend(mv.key()).collect();
                let child_trie = mv.child_trie().map(|c| c.as_ref().to_vec());
                start_storage_request(
                    platform,
                    log_target,
                    network_service,
                    sync_service,
                    progress_requests,
                    state,
                    call,
                    key,
                    child_trie,
                )
                .await;
                return;
            }
            executor::runtime_call::RuntimeCall::NextKey(ref nk) => {
                let key: Vec<u8> = trie::nibbles_to_bytes_suffix_extend(nk.key()).collect();
                let child_trie = nk.child_trie().map(|c| c.as_ref().to_vec());
                start_storage_request(
                    platform,
                    log_target,
                    network_service,
                    sync_service,
                    progress_requests,
                    state,
                    call,
                    key,
                    child_trie,
                )
                .await;
                return;
            }
            executor::runtime_call::RuntimeCall::SignatureVerification(r) => {
                call = r.verify_and_resume();
            }
            executor::runtime_call::RuntimeCall::LogEmit(r) => {
                call = r.resume();
            }
            executor::runtime_call::RuntimeCall::Offchain(_) => {
                let _ = state.result_tx.send(Err(RuntimeCallError::Execution(
                    RuntimeCallExecutionError::ForbiddenHostFunction,
                )));
                return;
            }
            executor::runtime_call::RuntimeCall::OffchainStorageSet(r) => {
                call = r.resume();
            }
        }
    }
}

/// Helper function to get the trie root for a child trie from a proof or the main trie.
///
/// Returns the child trie root hash if `child_trie` is Some, or the main trie root if None.
fn get_trie_root_for_child_or_main<'a>(
    proof: &'a proof_decode::DecodedTrieProof<impl AsRef<[u8]>>,
    block_state_trie_root_hash: &'a [u8; 32],
    child_trie: Option<&[u8]>,
) -> Result<Option<&'a [u8; 32]>, ()> {
    if let Some(child_trie) = child_trie {
        const PREFIX: &[u8] = b":child_storage:default:";
        let mut key = Vec::with_capacity(PREFIX.len() + child_trie.len());
        key.extend_from_slice(PREFIX);
        key.extend_from_slice(child_trie);
        match proof.storage_value(block_state_trie_root_hash, &key) {
            Err(_) => Err(()),
            Ok(None) => Ok(None),
            Ok(Some((value, _))) => match <&[u8; 32]>::try_from(value) {
                Ok(hash) => Ok(Some(hash)),
                Err(_) => Err(()),
            },
        }
    } else {
        Ok(Some(block_state_trie_root_hash))
    }
}

/// Injects a value from the decoded proof into the call.
fn inject_proof_into_call(
    call: executor::runtime_call::RuntimeCall,
    decoded_proof: &trie::proof_decode::DecodedTrieProof<impl AsRef<[u8]>>,
    state: &mut StorageOnDemandState,
) -> executor::runtime_call::RuntimeCall {
    match call {
        executor::runtime_call::RuntimeCall::StorageGet(get) => {
            let key: Vec<u8> = get.key().as_ref().to_vec();
            let child_trie = get.child_trie().map(|c| c.as_ref().to_vec());

            match get_trie_root_for_child_or_main(
                decoded_proof,
                &state.block_state_trie_root_hash,
                child_trie.as_deref(),
            ) {
                Ok(Some(trie_root)) => match decoded_proof.storage_value(trie_root, &key) {
                    Ok(value) => get.inject_value(value.map(|(val, vers)| (iter::once(val), vers))),
                    Err(_) => {
                        state.failed_attempts += 1;
                        state
                            .inaccessible_errors
                            .push(RuntimeCallInaccessibleError::MissingProofEntry);
                        executor::runtime_call::RuntimeCall::StorageGet(get)
                    }
                },
                Ok(None) => {
                    // Child trie doesn't exist, inject None
                    get.inject_value(None::<(iter::Empty<Vec<u8>>, _)>)
                }
                Err(_) => {
                    state.failed_attempts += 1;
                    state
                        .inaccessible_errors
                        .push(RuntimeCallInaccessibleError::MissingProofEntry);
                    executor::runtime_call::RuntimeCall::StorageGet(get)
                }
            }
        }
        executor::runtime_call::RuntimeCall::ClosestDescendantMerkleValue(mv) => {
            let child_trie = mv.child_trie().map(|c| c.as_ref().to_vec());
            match get_trie_root_for_child_or_main(
                decoded_proof,
                &state.block_state_trie_root_hash,
                child_trie.as_deref(),
            ) {
                Ok(Some(trie_root)) => {
                    match decoded_proof.closest_descendant_merkle_value(trie_root, mv.key()) {
                        Ok(value) => mv.inject_merkle_value(value),
                        Err(_) => {
                            state.failed_attempts += 1;
                            state
                                .inaccessible_errors
                                .push(RuntimeCallInaccessibleError::MissingProofEntry);
                            executor::runtime_call::RuntimeCall::ClosestDescendantMerkleValue(mv)
                        }
                    }
                }
                Ok(None) => mv.inject_merkle_value(None),
                Err(_) => {
                    state.failed_attempts += 1;
                    state
                        .inaccessible_errors
                        .push(RuntimeCallInaccessibleError::MissingProofEntry);
                    executor::runtime_call::RuntimeCall::ClosestDescendantMerkleValue(mv)
                }
            }
        }
        executor::runtime_call::RuntimeCall::NextKey(nk) => {
            let child_trie = nk.child_trie().map(|c| c.as_ref().to_vec());
            match get_trie_root_for_child_or_main(
                decoded_proof,
                &state.block_state_trie_root_hash,
                child_trie.as_deref(),
            ) {
                Ok(Some(trie_root)) => {
                    match decoded_proof.next_key(
                        trie_root,
                        nk.key(),
                        nk.or_equal(),
                        nk.prefix(),
                        nk.branch_nodes(),
                    ) {
                        Ok(next_key) => nk.inject_key(next_key),
                        Err(_) => {
                            state.failed_attempts += 1;
                            state
                                .inaccessible_errors
                                .push(RuntimeCallInaccessibleError::MissingProofEntry);
                            executor::runtime_call::RuntimeCall::NextKey(nk)
                        }
                    }
                }
                Ok(None) => nk.inject_key(None::<iter::Empty<trie::Nibble>>),
                Err(_) => {
                    state.failed_attempts += 1;
                    state
                        .inaccessible_errors
                        .push(RuntimeCallInaccessibleError::MissingProofEntry);
                    executor::runtime_call::RuntimeCall::NextKey(nk)
                }
            }
        }
        // Other variants don't need proof injection
        other => other,
    }
}

/// Checks if too many failed attempts have occurred.
/// Returns `None` if too many attempts (error sent), `Some(state)` to continue.
fn check_too_many_attempts<TPlat: PlatformRef>(
    platform: &TPlat,
    log_target: &str,
    state: StorageOnDemandState,
) -> Option<StorageOnDemandState> {
    if state.failed_attempts >= state.total_attempts {
        log!(
            platform,
            Debug,
            log_target,
            "storage-on-demand-fail",
            block_hash = HashDisplay(&state.block_hash),
            function_name = state.function_name,
            error = "too-many-failed-attempts"
        );
        let _ = state.result_tx.send(Err(RuntimeCallError::Inaccessible(
            state.inaccessible_errors,
        )));
        None
    } else {
        Some(state)
    }
}

/// Helper function to start a storage proof request.
async fn start_storage_request<TPlat: PlatformRef>(
    platform: &TPlat,
    log_target: &str,
    network_service: &Arc<network_service::NetworkServiceChain<TPlat>>,
    sync_service: &Arc<sync_service::SyncService<TPlat>>,
    progress_requests: &mut stream::FuturesUnordered<
        Pin<Box<dyn future::Future<Output = ProgressRuntimeCallRequest> + Send>>,
    >,
    mut state: StorageOnDemandState,
    call: executor::runtime_call::RuntimeCall,
    key: Vec<u8>,
    child_trie: Option<Vec<u8>>,
) {
    // Choose a peer to query.
    let Some(target) = sync_service
        .peers_assumed_know_blocks(state.block_number, &state.block_hash)
        .await
        .choose(&mut rand_chacha::ChaCha20Rng::from_seed({
            let mut seed = [0; 32];
            platform.fill_random_bytes(&mut seed);
            seed
        }))
    else {
        log!(
            platform,
            Debug,
            log_target,
            "storage-on-demand-no-peer",
            block_hash = HashDisplay(&state.block_hash),
            function_name = state.function_name
        );
        let _ = state.result_tx.send(Err(RuntimeCallError::Inaccessible(
            state.inaccessible_errors,
        )));
        return;
    };

    log!(
        platform,
        Trace,
        log_target,
        "storage-on-demand-request-start",
        block_hash = HashDisplay(&state.block_hash),
        function_name = state.function_name,
        key = HashDisplay(&key),
        target
    );

    // Store the call for when the request completes.
    state.call = Some(call);

    // Start the storage proof request (or child storage proof request for child tries).
    if let Some(child_trie) = child_trie {
        let child_storage_request_future = network_service.clone().child_storage_proof_request(
            target.clone(),
            smoldot::network::codec::ChildStorageProofRequestConfig {
                block_hash: state.block_hash,
                child_trie,
                keys: iter::once(key),
            },
            state.timeout_per_request,
        );

        progress_requests.push(Box::pin(async move {
            let result = child_storage_request_future.await;
            ProgressRuntimeCallRequest::StorageOnDemandChildStorageRequest {
                result,
                storage_request_sender: target,
                state,
            }
        }));
    } else {
        let storage_request_future = network_service.clone().storage_proof_request(
            target.clone(),
            smoldot::network::codec::StorageProofRequestConfig {
                block_hash: state.block_hash,
                keys: iter::once(key),
            },
            state.timeout_per_request,
        );

        progress_requests.push(Box::pin(async move {
            let result = storage_request_future.await;
            ProgressRuntimeCallRequest::StorageOnDemandStorageRequest {
                result,
                storage_request_sender: target,
                state,
            }
        }));
    }
}
