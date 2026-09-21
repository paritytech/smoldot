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

//! Background transactions service.
//!
//! The role of the [`TransactionsService`] is to manage the transactions that the user wants to
//! send out, and report about their status.
//!
//! The [`TransactionsService`] is most of the time idle. When the user wants to emit a
//! transaction on the network, it gets reported to the service, which then tries to send it to
//! the peers the node is currently connected to. Afterwards, the service will inspect the stream
//! of best and finalized blocks to find out whether the transaction has been included or not.
//!
//! # How watching transactions works
//!
//! Calling [`TransactionsService::submit_transaction`] returns a channel receiver that will contain
//! status updates about this transaction.
//!
//! In order to implement this, the [`TransactionsService`] will follow all the blocks that are
//! verified locally by the [`runtime_service::RuntimeService`] (see
//! [`runtime_service::RuntimeService::subscribe_all`]) and download from the network the body of
//! all the blocks in the best chain.
//!
//! When a block body download fails, it is ignored, in the hopes that the block will not be part
//! of the finalized chain. If the block body download of a finalized block fails, we enter "panic
//! mode" (not an actual Rust panic, just a way to describe the logic) and all watched
//! transactions are dropped.
//!
//! The same "panic mode" happens if there's an accidental gap in the chain, which will typically
//! happen if the [`runtime_service::RuntimeService`] is overwhelmed.
//!
//! If the channel returned by [`TransactionsService::submit_transaction`] is full, it will
//! automatically be closed so as to not block the transactions service if the receive is too slow
//! to be processed.
//!
//! # About duplicate unsigned transactions
//!
//! The Substrate and Polkadot runtimes support nonce-less unsigned transactions. In other words,
//! a user can submit the same transaction (the exact same bytes every time) as many time as they
//! want.
//!
//! While the chain can accept the same transaction multiple times over time, a Substrate node
//! will only allow submitting it *once at a time*. In other words, any given unsigned transaction
//! will never be included more than once in any given block. If you try to submit an unsigned
//! transaction while the same transaction is already pending, the Substrate node will ignore it
//! or return an error.
//!
//! Contrary to Substrate, the smoldot Wasm client can be used by multiple UIs at the same time.
//! When a UI submits an unsigned transaction, we don't want to do the same as Substrate and
//! refuse it if it is already pending, as it would make it possible for a UI to determine
//! whether another UI has already submitted this transaction, and thus allow communications
//! between UIs. Instead, the smoldot Wasm client return another sender to the same already-pending
//! transaction.
//!

use crate::{log, network_service, platform::PlatformRef, runtime_service, sync_service};

use alloc::{
    borrow::ToOwned as _,
    boxed::Box,
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec::Vec,
};
use core::{cmp, iter, num::NonZero, pin, time::Duration};
use futures_channel::oneshot;
use futures_lite::FutureExt as _;
use futures_util::stream::FuturesUnordered;
use futures_util::{FutureExt as _, StreamExt as _, future};
use itertools::Itertools as _;
use smoldot::{
    header,
    informant::HashDisplay,
    libp2p::peer_id::PeerId,
    network::codec,
    transactions::{light_pool, validate},
};

/// Configuration for a [`TransactionsService`].
pub struct Config<TPlat: PlatformRef> {
    /// Name of the chain, for logging purposes.
    ///
    /// > **Note**: This name will be directly printed out. Any special character should already
    /// >           have been filtered out from this name.
    pub log_name: String,

    /// Access to the platform's capabilities.
    pub platform: TPlat,

    /// Metrics of the chain.
    pub metrics: Arc<crate::metrics::ChainMetrics>,

    /// Service responsible for synchronizing the chain.
    pub sync_service: Arc<sync_service::SyncService<TPlat>>,

    /// Service responsible for synchronizing the chain.
    pub runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,

    /// Access to the network, and identifier of the chain to use to gossip transactions from the
    /// point of view of the network service.
    pub network_service: Arc<network_service::NetworkServiceChain<TPlat>>,

    /// Maximum number of pending transactions allowed in the service.
    ///
    /// Any extra transaction will lead to [`DropReason::MaxPendingTransactionsReached`].
    pub max_pending_transactions: NonZero<u32>,

    /// Maximum number of block body downloads that can be performed in parallel.
    ///
    /// > **Note**: This is the maximum number of *blocks* whose body is being download, not the
    /// >           number of block requests emitted on the network.
    pub max_concurrent_downloads: NonZero<u32>,

    /// Maximum number of transaction validations that can be performed in parallel.
    pub max_concurrent_validations: NonZero<u32>,
}

/// See [the module-level documentation](..).
pub struct TransactionsService<TPlat: PlatformRef> {
    /// Sending messages to the background task.
    to_background: async_lock::Mutex<async_channel::Sender<ToBackground>>,

    /// Configuration of the background task. Used in order to restart it if necessary.
    background_task_config: BackgroundTaskConfig<TPlat>,
}

impl<TPlat: PlatformRef> TransactionsService<TPlat> {
    /// Builds a new service.
    pub fn new(config: Config<TPlat>) -> Self {
        let log_target = format!("tx-service-{}", config.log_name);
        let (to_background, from_foreground) = async_channel::bounded(8);

        let background_task_config = BackgroundTaskConfig {
            log_target: log_target.clone(),
            platform: config.platform.clone(),
            metrics: config.metrics,
            sync_service: config.sync_service,
            runtime_service: config.runtime_service,
            network_service: config.network_service,
            max_concurrent_downloads: usize::try_from(config.max_concurrent_downloads.get())
                .unwrap_or(usize::MAX),
            max_pending_transactions: usize::try_from(config.max_pending_transactions.get())
                .unwrap_or(usize::MAX),
            max_concurrent_validations: usize::try_from(config.max_concurrent_validations.get())
                .unwrap_or(usize::MAX),
        };

        let task = Box::pin(background_task::<TPlat>(
            background_task_config.clone(),
            from_foreground,
        ));

        config.platform.spawn_task(log_target.clone().into(), {
            let platform = config.platform.clone();
            async move {
                task.await;
                log!(&platform, Debug, &log_target, "shutdown");
            }
        });

        TransactionsService {
            to_background: async_lock::Mutex::new(to_background),
            background_task_config,
        }
    }

    /// Adds a transaction to the service. The service will try to send it out as soon as
    /// possible.
    ///
    /// Must pass as parameter the SCALE-encoded transaction.
    ///
    /// The return value of this method is an object receives updates on the state of the
    /// transaction.
    ///
    /// If `detached` is `true`, then dropping the value returned does not cancel sending out
    /// the transaction. If `detached` is `false`, then it does.
    ///
    /// If this exact same transaction has already been submitted before, the transaction isn't
    /// added a second time. Instead, a second channel is created pointing to the already-existing
    /// transaction.
    pub async fn submit_and_watch_transaction(
        &self,
        transaction_bytes: Vec<u8>,
        channel_size: usize,
        detached: bool,
    ) -> TransactionWatcher {
        let (updates_report, rx) = async_channel::bounded(channel_size);

        self.send_to_background(ToBackground::SubmitTransaction {
            transaction_bytes,
            updates_report: Some((updates_report, detached)),
        })
        .await;

        TransactionWatcher {
            rx,
            has_yielded_drop_reason: false,
            _dummy_keep_alive: self.to_background.lock().await.clone(),
        }
    }

    /// Similar to [`TransactionsService::submit_and_watch_transaction`], but doesn't return any
    /// channel.
    pub async fn submit_transaction(&self, transaction_bytes: Vec<u8>) {
        self.send_to_background(ToBackground::SubmitTransaction {
            transaction_bytes,
            updates_report: None,
        })
        .await;
    }

    async fn send_to_background(&self, message: ToBackground) {
        let mut lock = self.to_background.lock().await;

        if lock.is_closed() {
            let log_target = self.background_task_config.log_target.clone();
            let (tx, rx) = async_channel::bounded(8);
            let platform = self.background_task_config.platform.clone();
            let task = background_task(self.background_task_config.clone(), rx);
            self.background_task_config.platform.spawn_task(
                log_target.clone().into(),
                async move {
                    // Sleep for a bit in order to avoid potential infinite loops
                    // of repeated crashing.
                    platform.sleep(Duration::from_secs(2)).await;
                    log!(&platform, Debug, &log_target, "restart");
                    task.await;
                    log!(&platform, Debug, &log_target, "shutdown");
                },
            );
            *lock = tx;
        }

        // Note that the background task might have crashed already at this point, so errors can
        // be expected.
        let _ = lock.send(message).await;
    }
}

/// Returned by [`TransactionsService::submit_and_watch_transaction`].
#[pin_project::pin_project]
pub struct TransactionWatcher {
    /// Channel connected to the background task.
    #[pin]
    rx: async_channel::Receiver<TransactionStatus>,
    /// `true` if a [`TransactionStatus::Dropped`] has already been yielded.
    has_yielded_drop_reason: bool,
    /// Dummy copy of [`TransactionsService::to_background`] that guarantees that the background
    /// stays alive.
    _dummy_keep_alive: async_channel::Sender<ToBackground>,
}

impl TransactionWatcher {
    /// Returns the next status update of the transaction.
    ///
    /// The last event is always a [`TransactionStatus::Dropped`], and then `None` is yielded
    /// repeatedly forever.
    pub async fn next(self: pin::Pin<&mut Self>) -> Option<TransactionStatus> {
        let mut this = self.project();
        if *this.has_yielded_drop_reason {
            debug_assert!(this.rx.is_closed() || this.rx.next().await.is_none());
            return None;
        }

        match this.rx.next().await {
            Some(update) => {
                if matches!(update, TransactionStatus::Dropped(_)) {
                    debug_assert!(!*this.has_yielded_drop_reason);
                    *this.has_yielded_drop_reason = true;
                }
                Some(update)
            }
            None => {
                *this.has_yielded_drop_reason = true;
                Some(TransactionStatus::Dropped(DropReason::Crashed))
            }
        }
    }
}

/// Update on the state of a transaction in the service.
///
/// > **Note**: Because this code isn't an *actual* transactions pool that leverages the runtime,
/// >           some variants (e.g. `Invalid`) are missing compared to the ones that can be found
/// >           in Substrate, as they can't possibly be generated by this implementation.
/// >           Additionally, an equivalent to the `Ready` state in Substrate is missing as it
/// >           is the default state.
#[derive(Debug, Clone)]
pub enum TransactionStatus {
    /// Transaction has been broadcasted to the given peers.
    Broadcast(Vec<PeerId>),

    /// Transaction is now known to be valid. If it ever becomes invalid in the future, a
    /// [`TransactionStatus::Dropped`] will be generated.
    Validated,

    /// The block in which a block is included has changed.
    IncludedBlockUpdate {
        /// If `Some`, the transaction is included in the block of the best chain with the given
        /// hash and at the given index. If `None`, the transaction isn't present in the best
        /// chain.
        block_hash: Option<([u8; 32], u32)>,
    },

    /// Transaction has been removed from the pool.
    ///
    /// This is always the last message sent back by the channel reporting the status.
    Dropped(DropReason),
}

/// See [`TransactionStatus::Dropped`].
// The generated `DropReasonKind` is the `reason` label of the
// `transactionsDroppedTotal` metric; the strum derives are explained on
// [`crate::metrics::MetricLabel`].
#[derive(Debug, Clone, strum::EnumDiscriminants)]
#[strum_discriminants(name(DropReasonKind))]
#[strum_discriminants(derive(strum::EnumIter, strum::IntoStaticStr))]
#[strum_discriminants(strum(serialize_all = "kebab-case"))]
pub enum DropReason {
    /// Transaction has been included in a finalized block.
    ///
    /// This is a success path.
    #[strum_discriminants(strum(disabled))]
    Finalized { block_hash: [u8; 32], index: u32 },

    /// Transaction has been dropped because there was a gap in the chain of blocks. It is
    /// impossible to know.
    GapInChain,

    /// Transaction has been dropped because the maximum number of transactions in the pool has
    /// been reached.
    MaxPendingTransactionsReached,

    /// Transaction has been dropped because it is invalid.
    Invalid(validate::TransactionValidityError),

    /// Transaction has been dropped because we have failed to validate it.
    ValidateError(ValidateTransactionError),

    /// Transaction service background task has crashed.
    ///
    /// Not counted in `transactionsDroppedTotal`: yielded outside the background task.
    #[strum_discriminants(strum(disabled))]
    Crashed,
}

/// Failed to check the validity of a transaction.
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum ValidateTransactionError {
    /// The runtime of the requested block is invalid.
    InvalidRuntime(runtime_service::RuntimeError),

    /// The runtime doesn't implement the API required to validate transactions.
    ApiVersionRequirementUnfulfilled,

    /// Runtime service has crashed while the call was in progress.
    Crash,

    /// Error during the execution of the runtime.
    ///
    /// There is no point in trying to validate the transaction call again, as it would result
    /// in the same error.
    #[display("Error during the execution of the runtime: {_0}")]
    Execution(runtime_service::RuntimeCallExecutionError),

    /// Error trying to access the storage required for the runtime call.
    ///
    /// Because these errors are non-fatal, the operation is attempted multiple times, and as such
    /// there can be multiple errors.
    ///
    /// Trying the same transaction again might succeed.
    #[display("Error trying to access the storage required for the runtime call")]
    // TODO: better display?
    Inaccessible(#[error(not(source))] Vec<runtime_service::RuntimeCallInaccessibleError>),

    /// Error while decoding the output of the runtime.
    OutputDecodeError(validate::DecodeError),
}

#[derive(Debug, Clone)]
enum InvalidOrError {
    Invalid(validate::TransactionValidityError),
    ValidateError(ValidateTransactionError),
}

#[derive(Debug, Clone)]
enum ValidationError {
    InvalidOrError(InvalidOrError),
    ObsoleteSubscription,
}

/// Message sent from the foreground service to the background.
enum ToBackground {
    SubmitTransaction {
        transaction_bytes: Vec<u8>,
        updates_report: Option<(async_channel::Sender<TransactionStatus>, bool)>,
    },
}

/// Configuration for [`background_task`].
#[derive(Clone)]
struct BackgroundTaskConfig<TPlat: PlatformRef> {
    log_target: String,
    platform: TPlat,
    metrics: Arc<crate::metrics::ChainMetrics>,
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
    max_concurrent_downloads: usize,
    max_pending_transactions: usize,
    max_concurrent_validations: usize,
}

/// Background task running in parallel of the front service.
async fn background_task<TPlat: PlatformRef>(
    config: BackgroundTaskConfig<TPlat>,
    from_foreground: async_channel::Receiver<ToBackground>,
) {
    let transactions_capacity = cmp::min(8, config.max_pending_transactions);
    let blocks_capacity = 32;
    let mut from_foreground = pin::pin!(from_foreground);

    let mut worker = Worker {
        platform: config.platform,
        metrics: config.metrics,
        sync_service: config.sync_service,
        runtime_service: config.runtime_service,
        network_service: config.network_service,
        pending_transactions: light_pool::LightPool::new(light_pool::Config {
            transactions_capacity,
            blocks_capacity,
            finalized_block_hash: [0; 32], // Dummy value. Pool is re-initialized below.
        }),
        block_downloads: FuturesUnordered::new(),
        validations_in_progress: FuturesUnordered::new(),
        next_reannounce: FuturesUnordered::new(),
        max_concurrent_downloads: config.max_concurrent_downloads,
        max_pending_transactions: config.max_pending_transactions,
    };

    // TODO: must periodically re-send transactions that aren't included in block yet

    'channels_rebuild: loop {
        // This loop is entered when it is necessary to rebuild the subscriptions with the runtime
        // service. This happens when there is a gap in the blocks, either intentionally (e.g.
        // after a Grandpa warp sync) or because the transactions service was too busy to process
        // the new blocks.
        let mut subscribe_all = {
            let sub_future = async {
                Some(
                    // The buffer size should be large enough so that, if the CPU is busy, it
                    // doesn't become full before the execution of the transactions service resumes.
                    // The maximum number of pinned block is ignored, as this maximum is a way to
                    // avoid malicious behaviors. This code is by definition not considered
                    // malicious.
                    worker
                        .runtime_service
                        .subscribe_all(32, NonZero::<usize>::new(usize::MAX).unwrap())
                        .await,
                )
            };

            // Because `runtime_service.subscribe_all()` might take a long time (potentially
            // forever), we need to process messages coming from the foreground in parallel.
            let from_foreground = &mut from_foreground;
            let metrics = worker.metrics.clone();
            let messages_process = async move {
                loop {
                    match from_foreground.next().await {
                        Some(ToBackground::SubmitTransaction {
                            updates_report: Some(updates_report),
                            ..
                        }) => {
                            metrics.transactions_dropped.inc(&DropReason::GapInChain);
                            let _ = updates_report
                                .0
                                .send(TransactionStatus::Dropped(DropReason::GapInChain))
                                .await;
                        }
                        Some(ToBackground::SubmitTransaction { .. }) => {}
                        None => break None,
                    }
                }
            };

            match sub_future.or(messages_process).await {
                Some(s) => s,
                None => return,
            }
        };

        let initial_finalized_block_hash = header::hash_from_scale_encoded_header(
            &subscribe_all.finalized_block_scale_encoded_header,
        );

        // Drop all pending transactions of the pool.
        for (_, pending) in worker.pending_transactions.transactions_iter_mut() {
            // TODO: only do this if transaction hasn't been validated yet
            worker
                .metrics
                .transactions_dropped
                .inc(&DropReason::GapInChain);
            pending.update_status(TransactionStatus::Dropped(DropReason::GapInChain));
        }

        // Reset the blocks tracking state machine.
        let dropped_transactions = worker
            .pending_transactions
            .transactions_iter()
            .map(|(tx_id, _)| {
                HashDisplay(worker.pending_transactions.scale_encoding(tx_id).unwrap())
            })
            .join(",");
        worker.pending_transactions = light_pool::LightPool::new(light_pool::Config {
            transactions_capacity,
            blocks_capacity,
            finalized_block_hash: initial_finalized_block_hash,
        });

        for block in subscribe_all.non_finalized_blocks_ancestry_order {
            let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
            worker.pending_transactions.add_block(
                hash,
                &block.parent_hash,
                Block {
                    scale_encoded_header: block.scale_encoded_header,
                    failed_downloads: 0,
                    downloading: false,
                },
            );
            if block.is_new_best {
                worker.set_best_block(&config.log_target, &hash);
            }
        }

        // Reset the other fields.
        worker.block_downloads.clear();
        worker.validations_in_progress.clear();
        worker.next_reannounce.clear();

        log!(
            &worker.platform,
            Debug,
            &config.log_target,
            "reset",
            new_finalized = HashDisplay(&initial_finalized_block_hash),
            subscription_id = ?subscribe_all.new_blocks.id(),
            dropped_transactions
        );

        loop {
            // If the finalized block moved in such a way that there would be blocks in the
            // pool whose height is inferior to `latest_finalized - 32`, then jump to
            // "catastrophic mode" and reset everything. This is to avoid the possibility of an
            // unreasonable memory consumption.
            if worker.pending_transactions.oldest_block_finality_lag() >= 32 {
                continue 'channels_rebuild;
            }

            // Try to find transactions whose status update channels have all been closed.
            while let Some(tx_id) = {
                let id = worker
                    .pending_transactions
                    .transactions_iter()
                    .find(|(_, tx)| {
                        !tx.status_update.iter().any(|s| !s.is_closed()) && !tx.detached
                    })
                    .map(|(id, _)| id);
                id
            } {
                worker.pending_transactions.remove_transaction(tx_id);
            }

            // Start the validation process of transactions that need to be validated.
            while worker.validations_in_progress.len() < config.max_concurrent_validations {
                // Find a transaction that needs to be validated.
                //
                // While this is an `O(n)` process, in practice we pick the first transaction not
                // currently being validated, and only `max_concurrent_validations` transactions
                // in the list don't match that criteria. Since `max_concurrent_validations`
                // should be pretty low, this search should complete very quickly.
                let to_start_validate = worker
                    .pending_transactions
                    .unvalidated_transactions()
                    .find(|(_, tx)| tx.validation_in_progress.is_none())
                    .map(|(tx_id, ..)| tx_id);
                let to_start_validate = match to_start_validate {
                    Some(tx_id) => tx_id,
                    None => break,
                };

                // Create the `Future` of the validation process.
                let validation_future = {
                    // Find which block to validate the transaction against.
                    let block_hash = *worker.pending_transactions.best_block_hash();

                    // It is possible for the current best block to be equal to the finalized
                    // block, in which case it will not be in the data structure and will already
                    // be unpinned in the runtime service.
                    // In that situation, we simply don't start any validation.
                    // TODO: is this problem worth solving? ^
                    let scale_encoded_header =
                        match worker.pending_transactions.block_user_data(&block_hash) {
                            Some(b) => b.scale_encoded_header.clone(),
                            None => break,
                        };

                    // Make copies of everything in order to move the values into the future.
                    let runtime_service = worker.runtime_service.clone();
                    let platform = worker.platform.clone();
                    let log_target = config.log_target.clone();
                    let relay_chain_sync_subscription_id = subscribe_all.new_blocks.id();
                    let scale_encoded_transaction = worker
                        .pending_transactions
                        .scale_encoding(to_start_validate)
                        .unwrap()
                        .to_owned();
                    // TODO: race condition /!\ the block could be pruned and unpinned before this future starts executing
                    async move {
                        let result = validate_transaction(
                            &platform,
                            &log_target,
                            &runtime_service,
                            relay_chain_sync_subscription_id,
                            block_hash,
                            &scale_encoded_header,
                            scale_encoded_transaction,
                            validate::TransactionSource::External,
                        )
                        .await;
                        (block_hash, result)
                    }
                };

                // The future that will receive the validation result is stored in the
                // `PendingTransaction`, while the future that executes the validation (and
                // yields `()`) is stored in `validations_in_progress`.
                let (result_tx, result_rx) = oneshot::channel();
                worker
                    .validations_in_progress
                    .push(Box::pin(validation_future.map(move |result| {
                        let _ = result_tx.send(result);
                        to_start_validate
                    })));
                let tx = worker
                    .pending_transactions
                    .transaction_user_data_mut(to_start_validate)
                    .unwrap();
                debug_assert!(tx.validation_in_progress.is_none());
                tx.validation_in_progress = Some(result_rx);
            }

            // Remove transactions that have been determined to be invalid.
            loop {
                // Note that we really would like to use a `while let` loop, but the Rust borrow
                // checker doesn't permit it.
                let (tx_id, _, error) = match worker
                    .pending_transactions
                    .invalid_transactions_finalized_block()
                    .next()
                {
                    Some(v) => v,
                    None => break,
                };

                // Clone the error because we need to unborrow `worker.pending_transactions`.
                let error = error.clone();

                let (tx_body, mut transaction) =
                    worker.pending_transactions.remove_transaction(tx_id);

                log!(
                    &worker.platform,
                    Debug,
                    &config.log_target,
                    "discarded",
                    tx_hash = HashDisplay(&blake2_hash(&tx_body)),
                    ?error
                );

                let reason = match error {
                    InvalidOrError::Invalid(err) => DropReason::Invalid(err),
                    InvalidOrError::ValidateError(err) => DropReason::ValidateError(err),
                };
                worker.metrics.transactions_dropped.inc(&reason);
                transaction.update_status(TransactionStatus::Dropped(reason));
            }

            // Start block bodies downloads that need to be started.
            while worker.block_downloads.len() < worker.max_concurrent_downloads {
                // TODO: prioritize best chain?
                let block_hash_number = worker
                    .pending_transactions
                    .missing_block_bodies()
                    .find(|(_, block)| {
                        // The transaction pool isn't aware of the fact that we're currently
                        // downloading a block's body. Skip when that is the case.
                        if block.downloading {
                            return false;
                        }

                        // Don't try again block downloads that have failed before.
                        if block.failed_downloads >= 1 {
                            // TODO: try downloading again if finalized or best chain
                            return false;
                        }

                        true
                    })
                    .map(|(hash, block)| {
                        // TODO: unwrap?! should only insert valid blocks in the worker
                        let decoded = header::decode(
                            &block.scale_encoded_header,
                            worker.sync_service.block_number_bytes(),
                        )
                        .unwrap();
                        (*hash, decoded.number)
                    });
                let (block_hash, block_number) = match block_hash_number {
                    Some(b) => b,
                    None => break,
                };

                // Actual download start.
                worker.block_downloads.push({
                    let download_future = worker.sync_service.clone().block_query(
                        block_number,
                        block_hash,
                        codec::BlocksRequestFields {
                            body: true,
                            header: true, // TODO: must be true in order to avoid an error being generated, fix this in sync service
                            justifications: false,
                        },
                        3,
                        Duration::from_secs(8),
                        NonZero::<u32>::new(3).unwrap(),
                    );

                    Box::pin(async move {
                        (
                            block_hash,
                            download_future.await.and_then(|b| b.body.ok_or(())),
                        )
                    })
                });

                worker
                    .pending_transactions
                    .block_user_data_mut(&block_hash)
                    .unwrap()
                    .downloading = true;

                log!(
                    &worker.platform,
                    Debug,
                    &config.log_target,
                    "blocks-download-started",
                    block = HashDisplay(&block_hash)
                );
            }

            // Remove finalized blocks from the pool when possible.
            for block in worker.pending_transactions.prune_finalized_with_body() {
                log!(
                    &worker.platform,
                    Debug,
                    &config.log_target,
                    "finalized",
                    block = HashDisplay(&block.block_hash),
                    body_transactions = block
                        .included_transactions
                        .iter()
                        .map(|tx| HashDisplay(&blake2_hash(&tx.scale_encoding)).to_string())
                        .join(", ")
                );

                // All blocks in `pending_transactions` are pinned within the runtime service.
                // Unpin them when they're removed.
                subscribe_all.new_blocks.unpin_block(block.block_hash).await;

                debug_assert!(!block.user_data.downloading);
                for mut tx in block.included_transactions {
                    // We assume that there's no more than 2<<32 transactions per block.
                    let body_index = u32::try_from(tx.index_in_block).unwrap();
                    tx.user_data
                        .update_status(TransactionStatus::Dropped(DropReason::Finalized {
                            block_hash: block.block_hash,
                            index: body_index,
                        }));
                    // `tx` is no longer in the pool.
                }
            }

            // Yield at every loop in order to provide better tasks granularity.
            futures_lite::future::yield_now().await;

            enum WakeUpReason {
                Notification(Option<runtime_service::Notification>),
                BlockDownloadFinished([u8; 32], Result<Vec<Vec<u8>>, ()>),
                MustMaybeReannounce(light_pool::TransactionId),
                MaybeValidated(light_pool::TransactionId),
                ForegroundMessage(Option<ToBackground>),
            }

            let wake_up_reason: WakeUpReason = {
                async { WakeUpReason::Notification(subscribe_all.new_blocks.next().await) }
                    .or(async {
                        if !worker.block_downloads.is_empty() {
                            let (block_hash, result) =
                                worker.block_downloads.select_next_some().await;
                            WakeUpReason::BlockDownloadFinished(block_hash, result)
                        } else {
                            future::pending().await
                        }
                    })
                    .or(async {
                        if !worker.next_reannounce.is_empty() {
                            WakeUpReason::MustMaybeReannounce(
                                worker.next_reannounce.select_next_some().await,
                            )
                        } else {
                            future::pending().await
                        }
                    })
                    .or(async {
                        if !worker.validations_in_progress.is_empty() {
                            WakeUpReason::MaybeValidated(
                                worker.validations_in_progress.select_next_some().await,
                            )
                        } else {
                            future::pending().await
                        }
                    })
                    .or(async { WakeUpReason::ForegroundMessage(from_foreground.next().await) })
                    .await
            };

            match wake_up_reason {
                WakeUpReason::Notification(Some(runtime_service::Notification::Block(
                    new_block,
                ))) => {
                    let hash =
                        header::hash_from_scale_encoded_header(&new_block.scale_encoded_header);
                    worker.pending_transactions.add_block(
                        header::hash_from_scale_encoded_header(&new_block.scale_encoded_header),
                        &new_block.parent_hash,
                        Block {
                            scale_encoded_header: new_block.scale_encoded_header,
                            failed_downloads: 0,
                            downloading: false,
                        },
                    );
                    if new_block.is_new_best {
                        worker.set_best_block(&config.log_target, &hash);
                    }
                }
                WakeUpReason::Notification(Some(runtime_service::Notification::Finalized {
                    hash,
                    best_block_hash_if_changed,
                    ..
                })) => {
                    if let Some(best_block_hash_if_changed) = best_block_hash_if_changed {
                        worker.set_best_block(&config.log_target, &best_block_hash_if_changed);
                    }
                    for pruned in worker.pending_transactions.set_finalized_block(&hash) {
                        log!(
                            &worker.platform,
                            Debug,
                            &config.log_target,
                            "pruned-block-discard",
                            block = HashDisplay(&pruned.0),
                        );

                        // All blocks in `pending_transactions` are pinned within the
                        // runtime service. Unpin them when they're removed.
                        subscribe_all.new_blocks.unpin_block(pruned.0).await;

                        // Note that we could in principle interrupt any on-going
                        // download of that block, but it is not worth the effort.
                    }
                }
                WakeUpReason::Notification(Some(
                    runtime_service::Notification::BestBlockChanged { hash },
                )) => {
                    worker.set_best_block(&config.log_target, &hash);
                }
                WakeUpReason::Notification(None) => continue 'channels_rebuild,

                WakeUpReason::BlockDownloadFinished(block_hash, mut block_body) => {
                    // A block body download has finished, successfully or not.
                    let block = match worker.pending_transactions.block_user_data_mut(&block_hash) {
                        Some(b) => b,
                        None => {
                            // It is possible that this block has been discarded because a sibling
                            // or uncle has been finalized. This is a normal situation.
                            continue;
                        }
                    };

                    debug_assert!(block.downloading);
                    block.downloading = false;

                    // Make sure that the downloaded body is the one of this block, otherwise
                    // we consider the download as failed.
                    if let Ok(body) = &block_body {
                        // TODO: unwrap the decoding?! is that correct?
                        if header::extrinsics_root(body)
                            != *header::decode(
                                &block.scale_encoded_header,
                                worker.sync_service.block_number_bytes(),
                            )
                            .unwrap()
                            .extrinsics_root
                        {
                            block_body = Err(());
                        }
                    }

                    if let Ok(block_body) = block_body {
                        let block_body_size = block_body.len();
                        let included_transactions = worker
                            .pending_transactions
                            .set_block_body(&block_hash, block_body.into_iter())
                            .collect::<Vec<_>>();

                        log!(
                            &worker.platform,
                            Debug,
                            &config.log_target,
                            "blocks-download-success",
                            block = HashDisplay(&block_hash),
                            included_transactions = included_transactions
                                .iter()
                                .map(|(id, _)| HashDisplay(&blake2_hash(
                                    worker.pending_transactions.scale_encoding(*id).unwrap()
                                ))
                                .to_string())
                                .join(", ")
                        );

                        for (tx_id, body_index) in included_transactions {
                            debug_assert!(body_index < block_body_size);
                            let tx = worker
                                .pending_transactions
                                .transaction_user_data_mut(tx_id)
                                .unwrap();
                            // We assume that there's no more than 2<<32 transactions per block.
                            let body_index = u32::try_from(body_index).unwrap();
                            tx.update_status(TransactionStatus::IncludedBlockUpdate {
                                block_hash: Some((block_hash, body_index)),
                            });
                        }
                    } else {
                        block.failed_downloads = block.failed_downloads.saturating_add(1);
                        log!(
                            &worker.platform,
                            Debug,
                            &config.log_target,
                            "blocks-download-failure",
                            block = HashDisplay(&block_hash)
                        );
                    }
                }

                WakeUpReason::MustMaybeReannounce(maybe_reannounce_tx_id) => {
                    // A transaction reannounce future has finished. This doesn't necessarily mean
                    // that a validation actually needs to be reannounced. The provided
                    // `maybe_reannounce_tx_id` is a hint as to which transaction might need to be
                    // reannounced, but without a strong guarantee.

                    // `continue` if transaction doesn't exist. False positive.
                    if worker
                        .pending_transactions
                        .transaction_user_data(maybe_reannounce_tx_id)
                        .is_none()
                    {
                        continue;
                    }

                    // Don't gossip the transaction if it hasn't been validated or is already
                    // included.
                    // TODO: if best block changes, we would need to reset all the re-announce period of all transactions, awkward!
                    // TODO: also, if this is false, then the transaction might never be re-announced ever again
                    if worker
                        .pending_transactions
                        .is_included_best_chain(maybe_reannounce_tx_id)
                        || !worker
                            .pending_transactions
                            .is_valid_against_best_block(maybe_reannounce_tx_id)
                    {
                        continue;
                    }

                    let now = worker.platform.now();
                    let tx = worker
                        .pending_transactions
                        .transaction_user_data_mut(maybe_reannounce_tx_id)
                        .unwrap();
                    if tx.when_reannounce > now {
                        continue;
                    }

                    // TODO: only announce if propagate is true

                    // Update transaction state for the next re-announce.
                    tx.when_reannounce = now + Duration::from_secs(5);
                    worker.next_reannounce.push({
                        let platform = worker.platform.clone();
                        Box::pin(async move {
                            platform.sleep(Duration::from_secs(5)).await;
                            maybe_reannounce_tx_id
                        })
                    });

                    // Perform the announce.
                    let peers_sent = worker
                        .network_service
                        .clone()
                        .announce_transaction(
                            worker
                                .pending_transactions
                                .scale_encoding(maybe_reannounce_tx_id)
                                .unwrap(),
                        )
                        .await;
                    log!(
                        &worker.platform,
                        Debug,
                        &config.log_target,
                        "announced-to-network",
                        transaction = HashDisplay(&blake2_hash(
                            worker
                                .pending_transactions
                                .scale_encoding(maybe_reannounce_tx_id)
                                .unwrap()
                        )),
                        peers = peers_sent.iter().join(", ")
                    );

                    // TODO: is this correct? and what should we do if announcing the same transaction multiple times? is it cumulative? `Broadcast` isn't super well documented
                    if !peers_sent.is_empty() {
                        worker
                            .pending_transactions
                            .transaction_user_data_mut(maybe_reannounce_tx_id)
                            .unwrap()
                            .update_status(TransactionStatus::Broadcast(peers_sent));
                    }
                }

                WakeUpReason::MaybeValidated(maybe_validated_tx_id) => {
                    // A transaction validation future has finished. This doesn't necessarily mean
                    // that a validation has actually finished. The provided
                    // `maybe_validated_tx_id` is a hint as to which transaction might have
                    // finished being validated, but without a strong guarantee.

                    // Try extract the validation result of this transaction, or `continue` if it
                    // is a false positive.
                    let (block_hash, validation_result) = match worker
                        .pending_transactions
                        .transaction_user_data_mut(maybe_validated_tx_id)
                    {
                        None => continue, // Normal. `maybe_validated_tx_id` is just a hint.
                        Some(tx) => match tx
                            .validation_in_progress
                            .as_mut()
                            .and_then(|f| f.now_or_never())
                        {
                            None => continue,               // Normal. `maybe_validated_tx_id` is just a hint.
                            Some(Err(_)) => unreachable!(), // Validations are never interrupted.
                            Some(Ok(result)) => {
                                tx.validation_in_progress = None;
                                result
                            }
                        },
                    };

                    let tx_hash = blake2_hash(
                        worker
                            .pending_transactions
                            .scale_encoding(maybe_validated_tx_id)
                            .unwrap(),
                    );

                    // The validation is made using the runtime service, while the state
                    // of the chain is tracked using the sync service. As such, it is
                    // possible for the validation to have been performed against a block
                    // that has already been finalized and removed from the pool.
                    if !worker.pending_transactions.has_block(&block_hash) {
                        log!(
                            &worker.platform,
                            Debug,
                            &config.log_target,
                            "transaction-validation-obsolete-block",
                            transaction = HashDisplay(&tx_hash),
                            block = HashDisplay(&block_hash)
                        );
                        continue;
                    }

                    let validation_result = match validation_result {
                        Ok(result) => {
                            log!(
                                &worker.platform,
                                Debug,
                                &config.log_target,
                                "transaction-validation-success",
                                transaction = HashDisplay(&tx_hash),
                                block = HashDisplay(&block_hash),
                                priority = result.priority,
                                longevity = result.longevity,
                                propagate = ?result.propagate,
                            );

                            log!(
                                &worker.platform,
                                Info,
                                &config.log_target,
                                format!(
                                    "Successfully validated transaction {}",
                                    HashDisplay(&tx_hash)
                                )
                            );

                            worker
                                .pending_transactions
                                .transaction_user_data_mut(maybe_validated_tx_id)
                                .unwrap_or_else(|| unreachable!())
                                .update_status(TransactionStatus::Validated);

                            // Schedule this transaction for announcement.
                            worker
                                .next_reannounce
                                .push(Box::pin(async move { maybe_validated_tx_id }));

                            Ok(result)
                        }
                        Err(ValidationError::ObsoleteSubscription) => {
                            // Runtime service subscription is obsolete. Throw away everything and
                            // rebuild it.
                            continue 'channels_rebuild;
                        }
                        Err(ValidationError::InvalidOrError(InvalidOrError::Invalid(error))) => {
                            log!(
                                &worker.platform,
                                Debug,
                                &config.log_target,
                                "transaction-validation-invalid-tx",
                                transaction = HashDisplay(&tx_hash),
                                block = HashDisplay(&block_hash),
                                ?error,
                            );

                            log!(
                                &worker.platform,
                                Warn,
                                &config.log_target,
                                format!(
                                    "Transaction {} invalid against block {}: {}",
                                    HashDisplay(&tx_hash),
                                    HashDisplay(&block_hash),
                                    error,
                                )
                            );

                            Err(InvalidOrError::Invalid(error))
                        }
                        Err(ValidationError::InvalidOrError(InvalidOrError::ValidateError(
                            error,
                        ))) => {
                            log!(
                                &worker.platform,
                                Debug,
                                &config.log_target,
                                "transaction-validation-error",
                                transaction = HashDisplay(&tx_hash),
                                block = HashDisplay(&block_hash),
                                ?error,
                            );

                            log!(
                                &worker.platform,
                                Warn,
                                &config.log_target,
                                format!(
                                    "Failed to validate transaction {}: {}",
                                    HashDisplay(&tx_hash),
                                    error
                                )
                            );

                            Err(InvalidOrError::ValidateError(error))
                        }
                    };

                    // No matter whether the validation is successful, we store the result in
                    // the transactions pool. This will later be picked up by the code that removes
                    // invalid transactions from the pool.
                    // TODO: shouldn't mark a transaction as invalid if it failed due to network errors
                    worker.pending_transactions.set_validation_result(
                        maybe_validated_tx_id,
                        &block_hash,
                        validation_result,
                    );
                }

                WakeUpReason::ForegroundMessage(None) => return,

                WakeUpReason::ForegroundMessage(Some(ToBackground::SubmitTransaction {
                    transaction_bytes,
                    updates_report,
                })) => {
                    // Handle the situation where the same transaction has already been
                    // submitted in the pool before.
                    let existing_tx_id = worker
                        .pending_transactions
                        .find_transaction(&transaction_bytes)
                        .next();
                    if let Some(existing_tx_id) = existing_tx_id {
                        let existing_tx = worker
                            .pending_transactions
                            .transaction_user_data_mut(existing_tx_id)
                            .unwrap();
                        if let Some((channel, detached)) = updates_report {
                            existing_tx.add_status_update(channel);
                            if detached {
                                existing_tx.detached = true;
                            }
                        }
                        continue;
                    }

                    // We intentionally limit the number of transactions in the pool,
                    // and immediately drop new transactions of this limit is reached.
                    if worker.pending_transactions.num_transactions()
                        >= worker.max_pending_transactions
                    {
                        worker
                            .metrics
                            .transactions_dropped
                            .inc(&DropReason::MaxPendingTransactionsReached);
                        if let Some((updates_report, _)) = updates_report {
                            let _ = updates_report.try_send(TransactionStatus::Dropped(
                                DropReason::MaxPendingTransactionsReached,
                            ));
                        }
                        continue;
                    }

                    // Success path. Inserting in pool.
                    worker.pending_transactions.add_unvalidated(
                        transaction_bytes,
                        PendingTransaction {
                            when_reannounce: worker.platform.now(),
                            detached: match &updates_report {
                                Some((_, true)) | None => true,
                                Some((_, false)) => false,
                            },
                            status_update: {
                                let mut vec = Vec::with_capacity(1);
                                if let Some((channel, _)) = updates_report {
                                    vec.push(channel);
                                }
                                vec
                            },
                            latest_status: None,
                            validation_in_progress: None,
                        },
                    );
                }
            }
        }
    }
}

/// Background worker running in parallel of the front service.
struct Worker<TPlat: PlatformRef> {
    /// Access to the platform's capabilities.
    platform: TPlat,

    /// Metrics of the chain.
    metrics: Arc<crate::metrics::ChainMetrics>,

    // How to download the bodies of blocks and synchronize the chain.
    sync_service: Arc<sync_service::SyncService<TPlat>>,

    /// How to validate transactions.
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,

    /// How to gossip transactions.
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,

    /// List of pending transactions.
    ///
    /// Contains all transactions that were submitted with
    /// [`TransactionsService::submit_transaction`] and their channel to send back their status.
    ///
    /// All the entries in this map represent transactions that we're trying to include on the
    /// network. It is normal to find entries where the status report channels are closed, as they
    /// still represent transactions that we're trying to include but whose status isn't
    /// interesting the frontend.
    ///
    /// All the blocks within this data structure are also pinned within the runtime service. They
    /// must be unpinned when they leave the data structure.
    pending_transactions: light_pool::LightPool<PendingTransaction<TPlat>, Block, InvalidOrError>,

    /// See [`Config::max_pending_transactions`].
    max_pending_transactions: usize,

    /// List of ongoing block body downloads.
    /// The output of the future is a block hash and a block body.
    block_downloads:
        FuturesUnordered<future::BoxFuture<'static, ([u8; 32], Result<Vec<Vec<u8>>, ()>)>>,

    /// List of transactions currently being validated.
    /// Returns the [`light_pool::TransactionId`] of the transaction that has finished being
    /// validated. The result can then be read from [`PendingTransaction::validation_in_progress`].
    /// Since transaction IDs can be reused, the returned ID might not correspond to a transaction
    /// or might correspond to the wrong transaction. This ID being returned is just a hint as to
    /// which transaction to check, and not an authoritative value.
    validations_in_progress:
        FuturesUnordered<future::BoxFuture<'static, light_pool::TransactionId>>,

    /// List of transactions that need to be reannounced.
    /// Returns the [`light_pool::TransactionId]` of the transaction that needs to be re-announced.
    /// Since transaction IDs can be reused, the returned ID might not correspond to a transaction
    /// or might correspond to the wrong transaction. This ID being returned is just a hint as to
    /// which transaction to check, not an authoritative value, and
    /// [`PendingTransaction::when_reannounce`] should be checked.
    next_reannounce: FuturesUnordered<future::BoxFuture<'static, light_pool::TransactionId>>,

    /// See [`Config::max_concurrent_downloads`]. Maximum number of elements in
    /// [`Worker::block_downloads`].
    max_concurrent_downloads: usize,
}

impl<TPlat: PlatformRef> Worker<TPlat> {
    /// Update the best block. Must have been previously inserted with
    /// [`light_pool::LightPool::add_block`].
    fn set_best_block(&mut self, log_target: &str, new_best_block_hash: &[u8; 32]) {
        let updates = self
            .pending_transactions
            .set_best_block(new_best_block_hash);

        // There might be entries in common between `retracted_transactions` and
        // `included_transactions`, in the case of a re-org where a transaction is part of both
        // the old and new best chain.
        // In that situation we need to first signal `Retracted`, then only `InBlock`.
        // Consequently, process `retracted_transactions` first.

        log!(
            &self.platform,
            Debug,
            &log_target,
            "best-chain-update",
            new_best_block = HashDisplay(new_best_block_hash),
            included_transactions = updates
                .included_transactions
                .iter()
                .map(|(id, _, _)| HashDisplay(&blake2_hash(
                    self.pending_transactions.scale_encoding(*id).unwrap()
                ))
                .to_string())
                .join(", "),
            retracted_transactions = updates
                .retracted_transactions
                .iter()
                .map(|(id, _, _)| HashDisplay(&blake2_hash(
                    self.pending_transactions.scale_encoding(*id).unwrap()
                ))
                .to_string())
                .join(", ")
        );

        for (tx_id, _, _) in updates.retracted_transactions {
            let tx = self
                .pending_transactions
                .transaction_user_data_mut(tx_id)
                .unwrap();
            tx.update_status(TransactionStatus::IncludedBlockUpdate { block_hash: None });
        }

        for (tx_id, block_hash, block_body_index) in updates.included_transactions {
            let tx = self
                .pending_transactions
                .transaction_user_data_mut(tx_id)
                .unwrap();
            // We assume that there's no more than 2<<32 transactions per block.
            let block_body_index = u32::try_from(block_body_index).unwrap();
            tx.update_status(TransactionStatus::IncludedBlockUpdate {
                block_hash: Some((block_hash, block_body_index)),
            });
        }
    }
}

struct Block {
    /// Header of the block, in SCALE encoding. Necessary in order to be able to validate blocks.
    scale_encoded_header: Vec<u8>,

    /// Number of previous downloads that have failed.
    failed_downloads: u8,

    /// `True` if the body of this block is currently being downloaded.
    downloading: bool,
}

struct PendingTransaction<TPlat: PlatformRef> {
    /// Earliest moment when to gossip the transaction on the network again.
    ///
    /// This should be interpreted as the moment before which to not reannounce, rather than the
    /// moment when to announce.
    ///
    /// In particular, this value might be long in the past, in case for example of a transaction
    /// that is not validated.
    when_reannounce: TPlat::Instant,

    /// List of channels that should receive changes to the transaction status.
    status_update: Vec<async_channel::Sender<TransactionStatus>>,

    /// If `false`, then dropping all the [`PendingTransaction::status_update`] channels will
    /// remove the transaction from the pool.
    detached: bool,

    /// Latest known status of the transaction. Used when a new sender is added to
    /// [`PendingTransaction::status_update`].
    latest_status: Option<TransactionStatus>,

    /// If `Some`, will receive the result of the validation of the transaction.
    validation_in_progress: Option<
        oneshot::Receiver<(
            [u8; 32],
            Result<validate::ValidTransaction, ValidationError>,
        )>,
    >,
}

impl<TPlat: PlatformRef> PendingTransaction<TPlat> {
    fn add_status_update(&mut self, channel: async_channel::Sender<TransactionStatus>) {
        if let Some(latest_status) = &self.latest_status {
            if channel.try_send(latest_status.clone()).is_err() {
                return;
            }
        }

        self.status_update.push(channel);
    }

    fn update_status(&mut self, status: TransactionStatus) {
        for n in 0..self.status_update.len() {
            let channel = self.status_update.swap_remove(n);
            if channel.try_send(status.clone()).is_ok() {
                self.status_update.push(channel);
            }
        }

        self.latest_status = Some(status);
    }
}

/// Actual transaction validation logic. Validates the transaction against the given block of the
/// [`runtime_service::RuntimeService`].
///
/// Returns the result of the validation, and the hash of the block it was validated against.
async fn validate_transaction<TPlat: PlatformRef>(
    platform: &TPlat,
    log_target: &str,
    relay_chain_sync: &Arc<runtime_service::RuntimeService<TPlat>>,
    relay_chain_sync_subscription_id: runtime_service::SubscriptionId,
    block_hash: [u8; 32],
    block_scale_encoded_header: &[u8],
    scale_encoded_transaction: impl AsRef<[u8]> + Clone,
    source: validate::TransactionSource,
) -> Result<validate::ValidTransaction, ValidationError> {
    // TODO: move somewhere else?
    log!(
        platform,
        Debug,
        &log_target,
        "transaction-validation-started",
        transaction = HashDisplay(&blake2_hash(scale_encoded_transaction.as_ref())),
        block = HashDisplay(&block_hash),
        block_height = header::decode(
            block_scale_encoded_header,
            relay_chain_sync.block_number_bytes()
        )
        .ok()
        .map(|h| format!("#{}", h.number))
        .unwrap_or_else(|| "unknown".to_owned())
    );

    let (pinned_runtime, block_state_root_hash, block_number) = match relay_chain_sync
        .pin_pinned_block_runtime(relay_chain_sync_subscription_id, block_hash)
        .await
    {
        Ok(r) => r,
        Err(runtime_service::PinPinnedBlockRuntimeError::ObsoleteSubscription) => {
            return Err(ValidationError::ObsoleteSubscription);
        }
        Err(runtime_service::PinPinnedBlockRuntimeError::BlockNotPinned) => unreachable!(),
    };

    let runtime_call_future = relay_chain_sync.runtime_call(
        pinned_runtime,
        block_hash,
        block_number,
        block_state_root_hash,
        validate::VALIDATION_FUNCTION_NAME.to_owned(),
        Some(("TaggedTransactionQueue".to_owned(), 3..=3)),
        validate::validate_transaction_runtime_parameters_v3(
            iter::once(scale_encoded_transaction.as_ref()),
            source,
            &block_hash,
        )
        .fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        }),
        3,
        Duration::from_secs(8),
        NonZero::<u32>::new(1).unwrap(),
    );

    let success = match runtime_call_future.await {
        Ok(output) => output,
        Err(runtime_service::RuntimeCallError::Execution(error)) => {
            return Err(ValidationError::InvalidOrError(
                InvalidOrError::ValidateError(ValidateTransactionError::Execution(error)),
            ));
        }
        Err(runtime_service::RuntimeCallError::Crash) => {
            return Err(ValidationError::InvalidOrError(
                InvalidOrError::ValidateError(ValidateTransactionError::Crash),
            ));
        }
        Err(runtime_service::RuntimeCallError::Inaccessible(errors)) => {
            return Err(ValidationError::InvalidOrError(
                InvalidOrError::ValidateError(ValidateTransactionError::Inaccessible(errors)),
            ));
        }
        Err(runtime_service::RuntimeCallError::InvalidRuntime(error)) => {
            return Err(ValidationError::InvalidOrError(
                InvalidOrError::ValidateError(ValidateTransactionError::InvalidRuntime(error)),
            ));
        }
        Err(runtime_service::RuntimeCallError::ApiVersionRequirementUnfulfilled) => {
            return Err(ValidationError::InvalidOrError(
                InvalidOrError::ValidateError(
                    ValidateTransactionError::ApiVersionRequirementUnfulfilled,
                ),
            ));
        }
    };

    match validate::decode_validate_transaction_return_value(&success.output) {
        Ok(Ok(decoded)) => Ok(decoded),
        Ok(Err(err)) => Err(ValidationError::InvalidOrError(InvalidOrError::Invalid(
            err,
        ))),
        Err(err) => Err(ValidationError::InvalidOrError(
            InvalidOrError::ValidateError(ValidateTransactionError::OutputDecodeError(err)),
        )),
    }
}

/// Utility. Calculates the BLAKE2 hash of the given bytes.
fn blake2_hash(bytes: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(blake2_rfc::blake2b::blake2b(32, &[], bytes).as_bytes()).unwrap()
}
