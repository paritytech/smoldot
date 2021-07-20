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
//! Calling [`TransactionsService::submit_extrinsic`] returns a channel receiver that will contain
//! status updates about this transaction.
//!
//! In order to implement this, the [`TransactionsService`] will follow all the blocks that are
//! verified locally by the [`sync_service::SyncService`] (see
//! [`sync_service::SyncService::subscribe_all`]) and download from the network the body of all
//! the blocks in the best chain.
//!
//! When a block body download fails, it is ignored, in the hopes that the block will not be part
//! of the finalized chain. If the block body download of a finalized block fails, we enter "panic
//! mode" (not an actual Rust panic, just a way to describe the logic) and all watched
//! transactions are dropped.
//!
//! The same "panic mode" happens if there's an accidental gap in the chain, which will typically
//! happen if the [`sync_service::SyncService`] is overwhelmed.
//!
//! If the channel returned by [`TransactionsService::submit_extrinsic`] is full, it will
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

use crate::{ffi, network_service, runtime_service, sync_service};

use futures::{channel::mpsc, lock::Mutex, prelude::*, stream::FuturesUnordered};
use smoldot::{
    header,
    informant::HashDisplay,
    libp2p::peer_id::PeerId,
    network::protocol,
    transactions::{light_pool, validate},
};
use std::{cmp, convert::TryFrom as _, iter, num::NonZeroU32, pin::Pin, sync::Arc, time::Duration};

/// Configuration for a [`TransactionsService`].
pub struct Config {
    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(String, Pin<Box<dyn Future<Output = ()> + Send>>) + Send>,

    /// Service responsible for synchronizing the chain.
    pub sync_service: Arc<sync_service::SyncService>,

    /// Service responsible for synchronizing the chain.
    pub runtime_service: Arc<runtime_service::RuntimeService>,

    /// Access to the network, and index of the chain to use to gossip transactions from the point
    /// of view of the network service.
    pub network_service: (Arc<network_service::NetworkService>, usize),

    /// Maximum number of pending transactions allowed in the service.
    ///
    /// Any extra transaction will lead to [`TransactionStatus::Dropped`].
    pub max_pending_transactions: NonZeroU32,

    /// Maximum number of block body downloads that can be performed in parallel.
    ///
    /// > **Note**: This is the maximum number of *blocks* whose body is being download, not the
    /// >           number of block requests emitted on the network.
    pub max_concurrent_downloads: NonZeroU32,

    /// Maximum number of transaction validations that can be performed in parallel.
    pub max_concurrent_validations: NonZeroU32,
}

/// See [the module-level documentation](..).
pub struct TransactionsService {
    /// Sending messages to the background task.
    to_background: Mutex<mpsc::Sender<ToBackground>>,
}

impl TransactionsService {
    /// Builds a new service.
    pub async fn new(mut config: Config) -> Self {
        let (to_background, from_foreground) = mpsc::channel(8);

        (config.tasks_executor)(
            "transactions-service".into(),
            Box::pin(background_task(
                config.sync_service,
                config.runtime_service,
                config.network_service.0,
                config.network_service.1,
                from_foreground,
                usize::try_from(config.max_concurrent_downloads.get())
                    .unwrap_or(usize::max_value()),
                usize::try_from(config.max_pending_transactions.get())
                    .unwrap_or(usize::max_value()),
                usize::try_from(config.max_concurrent_validations.get())
                    .unwrap_or(usize::max_value()),
            )),
        );

        TransactionsService {
            to_background: Mutex::new(to_background),
        }
    }

    /// Adds a transaction to the service. The service will try to send it out as soon as
    /// possible.
    ///
    /// Must pass as parameter the double-SCALE-encoded transaction.
    ///
    /// The return value of this method is a channel which will receive updates on the state
    /// of the extrinsic. The channel is closed when no new update is expected or if it becomes
    /// full.
    ///
    /// > **Note**: Dropping the value returned does not cancel sending out the extrinsic.
    ///
    /// If this exact same transaction has already been submitted before, the transaction isn't
    /// added a second time. Instead, a second channel is created pointing to the already-existing
    /// transaction.
    #[must_use = "Use `submit_extrinsic` instead if you don't need the return value"]
    pub async fn submit_and_watch_extrinsic(
        &self,
        transaction_bytes: Vec<u8>,
        channel_size: usize,
    ) -> mpsc::Receiver<TransactionStatus> {
        let (updates_report, rx) = mpsc::channel(channel_size);

        self.to_background
            .lock()
            .await
            .send(ToBackground::SubmitTransaction {
                transaction_bytes,
                updates_report: Some(updates_report),
            })
            .await
            .unwrap();

        rx
    }

    /// Similar to [`TransactionsService::submit_and_watch_extrinsic`], but doesn't return any
    /// channel.
    pub async fn submit_extrinsic(&self, transaction_bytes: Vec<u8>) {
        self.to_background
            .lock()
            .await
            .send(ToBackground::SubmitTransaction {
                transaction_bytes,
                updates_report: None,
            })
            .await
            .unwrap();
    }
}

/// Update on the state of an extrinsic in the service.
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

    /// Detected a block that is part of the best chain and that contains this transaction.
    ///
    /// Contains the hash of the block that contains the transaction.
    InBlock([u8; 32]),

    /// Can be sent after [`TransactionStatus::InBlock`] to notify that a re-org happened and the
    /// current best tree of blocks no longer contains the transaction.
    ///
    /// Contains the same block as was previously passed in [`TransactionStatus::InBlock`].
    Retracted([u8; 32]),

    /// Transaction has been dropped because the service was full, too slow, or generally
    /// encountered a problem.
    Dropped,

    /// Transaction has been included in a finalized block.
    Finalized([u8; 32]),
}

/// Message sent from the foreground service to the background.
enum ToBackground {
    SubmitTransaction {
        transaction_bytes: Vec<u8>,
        updates_report: Option<mpsc::Sender<TransactionStatus>>,
    },
}

/// Background task running in parallel of the front service.
async fn background_task(
    sync_service: Arc<sync_service::SyncService>,
    runtime_service: Arc<runtime_service::RuntimeService>,
    network_service: Arc<network_service::NetworkService>,
    network_chain_index: usize,
    mut from_foreground: mpsc::Receiver<ToBackground>,
    max_concurrent_downloads: usize,
    max_pending_transactions: usize,
    max_concurrent_validations: usize,
) {
    let mut worker = Worker {
        sync_service,
        runtime_service,
        network_service,
        network_chain_index,
        pending_transactions: light_pool::LightPool::new(light_pool::Config {
            transactions_capacity: cmp::min(8, max_pending_transactions),
            blocks_capacity: 32,
            finalized_block_hash: [0; 32], // Dummy value. Pool is re-initialized below.
        }),
        block_downloads: FuturesUnordered::new(),
        validations_in_progress: FuturesUnordered::new(),
        next_reannounce: FuturesUnordered::new(),
        max_concurrent_downloads,
        max_pending_transactions,
    };

    // TODO: must periodically re-send transactions that aren't included in block yet

    'channels_rebuild: loop {
        // This loop is entered when it is necessary to rebuild the subscriptions with the syncing
        // service. This happens when there is a gap in the blocks, either intentionally (e.g.
        // after a Grandpa warp sync) or because the transactions service was too busy to process
        // the new blocks.

        // Note that the new blocks subscription must be aquired before the finalized blocks
        // subscription. Otherwise, a block could be finalized between the moment we subscribe
        // to finalized blocks and the moment we subscribe to all blocks, which would lead to
        // trying to finalize a block that is unknown to us, which would be a state inconsistency.
        let (current_finalized_block_header, mut new_blocks_receiver) = {
            let subscribe_all = worker.sync_service.subscribe_all(32).await;
            (
                subscribe_all.finalized_block_scale_encoded_header,
                stream::iter(subscribe_all.non_finalized_blocks).chain(subscribe_all.new_blocks),
            )
        };
        let (_, mut best_block_receiver) = worker.sync_service.subscribe_best().await;
        let (_, mut finalized_block_receiver) = worker.sync_service.subscribe_finalized().await;
        let current_finalized_block_hash =
            header::hash_from_scale_encoded_header(&current_finalized_block_header);

        // Drop all pending transactions of the pool.
        for (_, pending) in worker.pending_transactions.transactions_iter_mut() {
            pending.update_status(TransactionStatus::Dropped);
        }
        worker
            .pending_transactions
            .clear_and_reset(current_finalized_block_hash);

        // Reset the other fields.
        worker.block_downloads.clear();
        worker.validations_in_progress.clear();
        worker.next_reannounce.clear();

        log::debug!(
            target: "tx-service",
            "Transactions watcher moved to finalized block {}.",
            HashDisplay(&current_finalized_block_hash),
        );

        loop {
            // If the finalized block moved in such a way that there would be blocks in the
            // pool whose height is inferior to `latest_finalized - 32`, then jump to
            // "catastrophic mode" and reset everything. This is to avoid the possibility of an
            // unreasonable memory consumption.
            if worker.pending_transactions.oldest_block_finality_lag() >= 32 {
                continue 'channels_rebuild;
            }

            // Start the validation process of transactions that need to be validated.
            while worker.validations_in_progress.len() < max_concurrent_validations {
                // Find a transaction that needs to be validated.
                //
                // While this looks like an `O(n)` process, in practice we pick the first
                // transaction not currently being validated, and only `max_concurrent_validations`
                // transactions in the list don't match that criteria. Since
                // `max_concurrent_validations` should be pretty low, this search should complete
                // very quickly.
                let to_start_validate = worker
                    .pending_transactions
                    .unvalidated_transactions()
                    .filter(|(_, tx)| tx.validation_in_progress.is_none())
                    .next()
                    .map(|(tx_id, ..)| tx_id);
                let to_start_validate = match to_start_validate {
                    Some(tx_id) => tx_id,
                    None => break,
                };

                // Create the `Future` of the validation process.
                let validation_future = {
                    let runtime_service = worker.runtime_service.clone();
                    let scale_encoded_transaction = worker
                        .pending_transactions
                        .double_scale_encoding(to_start_validate)
                        .unwrap()
                        .to_owned();
                    async move {
                        validate_transaction(
                            &runtime_service,
                            scale_encoded_transaction,
                            validate::TransactionSource::External,
                        )
                        .await
                    }
                };

                // The future with the actual result is stored in the `PendingTransaction`, while
                // the future that executes the validation is stored in `validations_in_progress`.
                let (to_execute, result_rx) = validation_future.remote_handle();
                worker
                    .validations_in_progress
                    .push(to_execute.map(move |()| to_start_validate).boxed());
                let tx = worker
                    .pending_transactions
                    .transaction_user_data_mut(to_start_validate)
                    .unwrap();
                debug_assert!(tx.validation_in_progress.is_none());
                tx.validation_in_progress = Some(result_rx);

                log::debug!(
                    target: "tx-service-validation",
                    "Starting for {}",
                    HashDisplay(&blake2_hash(worker.pending_transactions.double_scale_encoding(to_start_validate).unwrap()))
                );
            }

            // Start block bodies downloads that need to be started.
            while worker.block_downloads.len() < worker.max_concurrent_downloads {
                // TODO: prioritize best chain?
                let block_hash = worker
                    .pending_transactions
                    .missing_block_bodies()
                    .find(|(_, block)| {
                        // The transaction pool isn't aware of the fact that we're currently downloading
                        // a block's body. Skip when that is the case.
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
                    .map(|(b, _)| *b);
                let block_hash = match block_hash {
                    Some(b) => b,
                    None => break,
                };

                // Actual download start.
                worker.block_downloads.push({
                    let download_future = worker.sync_service.clone().block_query(
                        block_hash,
                        protocol::BlocksRequestFields {
                            body: true,
                            header: true, // TODO: must be true in order for the body to be verified; fix the sync_service to not require that
                            justification: false,
                        },
                    );

                    async move { (block_hash, download_future.await.map(|b| b.body.unwrap())) }
                        .boxed()
                });

                worker
                    .pending_transactions
                    .block_user_data_mut(&block_hash)
                    .unwrap()
                    .downloading = true;

                log::debug!(
                    target: "tx-service-blocks-download",
                    "Started download of {}",
                    HashDisplay(&block_hash)
                );
            }

            // Remove finalized blocks from the pool when possible.
            for block in worker.pending_transactions.prune_finalized_with_body() {
                debug_assert!(!block.user_data.downloading);
                for (_, mut tx) in block.included_transactions {
                    tx.update_status(TransactionStatus::Finalized(block.block_hash));
                    // `tx` is no longer in the pool.
                }
            }

            futures::select! {
                new_block = new_blocks_receiver.next().fuse() => {
                    if let Some(new_block) = new_block {
                        let hash = header::hash_from_scale_encoded_header(&new_block.scale_encoded_header);
                        worker.new_block(&new_block.scale_encoded_header, &new_block.parent_hash);
                        if new_block.is_new_best {
                            worker.set_best_block(&hash).await;
                        }
                    } else {
                        continue 'channels_rebuild;
                    }
                },

                finalized_block_header = finalized_block_receiver.next().fuse() => {
                    // It is possible that a block has been pushed to both the new blocks channel
                    // and the finalized block channel at the same time, but the finalized block
                    // channel is notified first. In order to fulfill the guarantee that all finalized
                    // blocks must have earlier been reported as new blocks, we first empty the new
                    // blocks receiver.
                    // TODO: really rethink the order of polling here in order to simplify it
                    while let Some(new_best_block) = best_block_receiver.next().now_or_never() {
                        let new_best_block = new_best_block.unwrap();
                        let hash = header::hash_from_scale_encoded_header(&new_best_block);
                        worker.set_best_block(&hash).await;
                    }
                    // TODO: DRY
                    while let Some(new_block) = new_blocks_receiver.next().now_or_never() {
                        if let Some(new_block) = new_block {
                            worker.new_block(&new_block.scale_encoded_header, &new_block.parent_hash);
                        } else {
                            continue 'channels_rebuild;
                        }
                    }

                    let finalized_hash =
                        header::hash_from_scale_encoded_header(&finalized_block_header.unwrap());
                    for _ in worker
                        .pending_transactions
                        .set_finalized_block(&finalized_hash)
                    {
                        // Nothing to do here.
                        // We could in principle interrupt any on-going download of that block,
                        // but it is not worth the effort.
                    }
                },

                download = worker.block_downloads.select_next_some() => {
                    // A block body download has finished, successfully or not.
                    let (block_hash, block_body) = download;

                    let mut block = match worker.pending_transactions.block_user_data_mut(&block_hash) {
                        Some(b) => b,
                        None => {
                            // It is possible that this block has been discarded because a sibling
                            // or uncle has been finalized. This is a normal situation.
                            continue
                        },
                    };

                    debug_assert!(block.downloading);
                    block.downloading = false;
                    if block_body.is_err() {
                        block.failed_downloads = block.failed_downloads.saturating_add(1);
                    }

                    log::debug!(
                        target: "tx-service-blocks-download",
                        "{} for {}",
                        if block_body.is_ok() { "Success" } else { "Failed" },
                        HashDisplay(&block_hash)
                    );

                    if let Ok(block_body) = block_body {
                        let included_transactions = worker
                            .pending_transactions
                            .set_block_body(&block_hash, block_body.into_iter())
                            .collect::<Vec<_>>();

                        for tx_id in included_transactions {
                            let tx = worker.pending_transactions.transaction_user_data_mut(tx_id).unwrap();
                            tx.update_status(TransactionStatus::InBlock(block_hash));
                        }
                    }
                },

                maybe_reannounce_tx_id = worker.next_reannounce.select_next_some() => {
                    // A transaction reannounce future has finished. This doesn't necessarily mean
                    // that a validation actually needs to be reannounced. The provided
                    // `maybe_reannounce_tx_id` is a hint as to which transaction might need to be
                    // reannounced, but without a strong guarantee.

                    // `continue` if transaction doesn't exist. False positive.
                    if worker.pending_transactions.transaction_user_data(maybe_reannounce_tx_id).is_none() {
                        continue;
                    }

                    // Don't gossip the transaction if it hasn't been validated.
                    // TODO: if best block changes, we would need to reset all the re-announce period of all transactions, awkward!
                    // TODO: also, if this is false, then the transaction might never be re-announced ever again
                    if !worker.pending_transactions.is_valid_against_best_block(maybe_reannounce_tx_id) {
                        continue;
                    }

                    let now = ffi::Instant::now();
                    let tx = worker.pending_transactions.transaction_user_data_mut(maybe_reannounce_tx_id).unwrap();
                    if tx.when_reannounce > now {
                        continue;
                    }

                    // TODO: only announce if propagate is true

                    // Update transaction state for the next re-announce.
                    tx.when_reannounce = now + Duration::from_secs(5);
                    worker.next_reannounce.push(async move {
                        ffi::Delay::new(Duration::from_secs(5)).await;
                        maybe_reannounce_tx_id
                    }.boxed());

                    // Perform the announce.
                    log::debug!(
                        target: "tx-service",
                        "Announcing {}",
                        HashDisplay(&blake2_hash(worker.pending_transactions.double_scale_encoding(maybe_reannounce_tx_id).unwrap()))
                    );
                    let peers_sent = worker.network_service
                        .clone()
                        .announce_transaction(
                            worker.network_chain_index,
                            &worker.pending_transactions.double_scale_encoding(maybe_reannounce_tx_id).unwrap()
                        )
                        .await;

                    // TODO: is this correct? and what should we do if announcing the same transaction multiple times? is it cumulative? `Broadcast` isn't super well documented
                    if !peers_sent.is_empty() {
                        worker.pending_transactions
                            .transaction_user_data_mut(maybe_reannounce_tx_id).unwrap()
                            .update_status(TransactionStatus::Broadcast(peers_sent));
                    }
                },

                maybe_validated_tx_id = worker.validations_in_progress.select_next_some() => {
                    // A transaction validation future has finished. This doesn't necessarily mean
                    // that a validation has actually finished. The provided
                    // `maybe_validated_tx_id` is a hint as to which transaction might have
                    // finished being validated, but without a strong guarantee.

                    // Try extract the validation result of this transaction, or `continue` if it
                    // is a false positive.
                    let validation_result = match worker.pending_transactions.transaction_user_data_mut(maybe_validated_tx_id) {
                        None => continue,  // Normal. `maybe_validated_tx_id` is just a hint.
                        Some(tx) => match tx.validation_in_progress.as_mut().and_then(|f| f.now_or_never()) {
                            None => continue,  // Normal. `maybe_validated_tx_id` is just a hint.
                            Some(result) => {
                                tx.validation_in_progress = None;
                                result
                            },
                        },
                    };

                    match validation_result {
                        Ok((block_hash, result)) => {
                            // The validation is made using the runtime service, while the state
                            // of the chain is tracked using the sync service. As such, it is
                            // possible for the validation to have been performed against a block
                            // that has already been finalized and removed from the pool.
                            if !worker.pending_transactions.has_block(&block_hash) {
                                log::debug!(
                                    target: "tx-service-validation",
                                    "Skipping success due to obsolete block {}",
                                    HashDisplay(&block_hash)
                                );
                                continue;
                            }

                            log::debug!(
                                target: "tx-service-validation",
                                "Success for {} at {}: {:?}",
                                HashDisplay(&blake2_hash(worker.pending_transactions.double_scale_encoding(maybe_validated_tx_id).unwrap())),
                                HashDisplay(&block_hash),
                                result
                            );

                            worker.pending_transactions.set_validation_result(maybe_validated_tx_id, &block_hash, result);

                            // Schedule this transaction for announcement.
                            worker.next_reannounce.push(async move {
                                maybe_validated_tx_id
                            }.boxed());
                        }
                        Err(error) => {
                            log::debug!(
                                target: "tx-service-validation",
                                "Failed for {}: {}",
                                HashDisplay(&blake2_hash(worker.pending_transactions.double_scale_encoding(maybe_validated_tx_id).unwrap())),
                                error
                            );

                            // Transaction couldn't be validated because of an error while
                            // executing the runtime. This most likely indicates a compatibility
                            // problem between smoldot and the runtime code. Drop the transaction.
                            log::warn!(target: "tx-service", "Failed to validate transaction: {}", error);
                            let mut tx = worker.pending_transactions.remove_transaction(maybe_validated_tx_id);
                            tx.update_status(TransactionStatus::Dropped);
                        }
                    }
                },

                message = from_foreground.next().fuse() => {
                    let message = match message {
                        Some(msg) => msg,
                        None => return,
                    };

                    match message {
                        ToBackground::SubmitTransaction {
                            transaction_bytes,
                            updates_report,
                        } => {
                            // Handle the situation where the same transaction has already been
                            // submitted in the pool before.
                            let existing_tx_id = worker.pending_transactions
                                .find_transaction(&transaction_bytes)
                                .next();
                            if let Some(existing_tx_id) = existing_tx_id {
                                let existing_tx = worker.pending_transactions
                                    .transaction_user_data_mut(existing_tx_id)
                                    .unwrap();
                                if let Some(updates_report) = updates_report {
                                    existing_tx.add_status_update(updates_report);
                                }
                                continue;
                            }

                            // We intentionally limit the number of transactions in the pool,
                            // and immediately drop new transactions of this limit is reached.
                            if worker.pending_transactions.num_transactions() >= worker.max_pending_transactions {
                                if let Some(mut updates_report) = updates_report {
                                    let _ = updates_report.try_send(TransactionStatus::Dropped);
                                }
                                continue;
                            }

                            // Success path. Inserting in pool.
                            worker
                                .pending_transactions
                                .add_unvalidated(transaction_bytes, PendingTransaction {
                                    when_reannounce: ffi::Instant::now(),
                                    status_update: {
                                        let mut vec = Vec::with_capacity(1);
                                        if let Some(updates_report) = updates_report {
                                            vec.push(updates_report);
                                        }
                                        vec
                                    },
                                    latest_status: None,
                                    validation_in_progress: None,
                                });
                        }
                    }
                }
            }
        }
    }
}

/// Background worker running in parallel of the front service.
struct Worker {
    // How to download the bodies of blocks and synchronize the chain.
    sync_service: Arc<sync_service::SyncService>,

    /// How to validate transactions.
    runtime_service: Arc<runtime_service::RuntimeService>,

    /// How to gossip transactions.
    network_service: Arc<network_service::NetworkService>,

    /// Which chain to use in combination with the [`Worker::network_service`].
    network_chain_index: usize,

    /// List of pending transactions.
    ///
    /// Contains all transactions that were submitted with
    /// [`TransactionsService::submit_extrinsic`] and their channel to send back their status.
    ///
    /// All the entries in this map represent transactions that we're trying to include on the
    /// network. It is normal to find entries where the status report channel is close, as they
    /// still represent transactions that we're trying to include but whose status isn't
    /// interesting us.
    pending_transactions: light_pool::LightPool<PendingTransaction, Block>,

    /// See [`Config::max_pending_transactions`].
    max_pending_transactions: usize,

    /// List of ongoing block body downloads.
    /// The output of the future is a block hash and a block body.
    block_downloads:
        FuturesUnordered<future::BoxFuture<'static, ([u8; 32], Result<Vec<Vec<u8>>, ()>)>>,

    /// List of transactions currently being validated.
    /// Returns the [`light_pool::TransactionId]` of the transaction that has finished being
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

impl Worker {
    /// Insert a new block in the worker when the sync service hears about it.
    fn new_block(&mut self, new_block_header: &Vec<u8>, parent_hash: &[u8; 32]) {
        self.pending_transactions.add_block(
            header::hash_from_scale_encoded_header(&new_block_header),
            parent_hash,
            Block {
                failed_downloads: 0,
                downloading: false,
            },
        );
    }

    /// Update the best block. Must have been previously inserted with [`Worker::new_block`].
    async fn set_best_block(&mut self, new_best_block_hash: &[u8; 32]) {
        let updates = self
            .pending_transactions
            .set_best_block(new_best_block_hash);

        // There might be entries in common between `retracted_transactions` and
        // `included_transactions`, in the case of a re-org where a transaction is part of both
        // the old and new best chain.
        // In that situation we need to first signal `Retracted`, then only `InBlock`.
        // Consequently, process `retracted_transactions` first.

        for (tx_id, hash) in updates.retracted_transactions {
            let tx = self
                .pending_transactions
                .transaction_user_data_mut(tx_id)
                .unwrap();
            tx.update_status(TransactionStatus::Retracted(hash));
        }

        for (tx_id, hash) in updates.included_transactions {
            let tx = self
                .pending_transactions
                .transaction_user_data_mut(tx_id)
                .unwrap();
            tx.update_status(TransactionStatus::InBlock(hash));
        }
    }
}

struct Block {
    /// Number of previous downloads that have failed.
    failed_downloads: u8,

    /// `True` if the body of this block is currently being downloaded.
    downloading: bool,
}

struct PendingTransaction {
    /// Earliest moment when to gossip the transaction on the network again.
    ///
    /// This should be interpreted as the moment before which to not reannounce, rather than the
    /// moment when to announce.
    ///
    /// In particular, this value might be long in the past, in case for example of a transaction
    /// that is not validated.
    when_reannounce: ffi::Instant,

    /// List of channels that should receive changes to the transaction status.
    status_update: Vec<mpsc::Sender<TransactionStatus>>,

    /// Latest known status of the transaction. Used when a new sender is added to
    /// [`PendingTransaction::status_update`].
    latest_status: Option<TransactionStatus>,

    /// If `Some`, will receive the result of the validation of the transaction.
    validation_in_progress: Option<
        future::RemoteHandle<
            Result<
                (
                    [u8; 32],
                    Result<validate::ValidTransaction, validate::TransactionValidityError>,
                ),
                ValidateTransactionError,
            >,
        >,
    >,
}

impl PendingTransaction {
    fn add_status_update(&mut self, mut channel: mpsc::Sender<TransactionStatus>) {
        if let Some(latest_status) = &self.latest_status {
            if channel.try_send(latest_status.clone()).is_err() {
                return;
            }
        }

        self.status_update.push(channel);
    }

    fn update_status(&mut self, status: TransactionStatus) {
        for n in 0..self.status_update.len() {
            let mut channel = self.status_update.swap_remove(n);
            if channel.try_send(status.clone()).is_ok() {
                self.status_update.push(channel);
            }
        }

        self.latest_status = Some(status);
    }
}

/// Actual transaction validation logic. Validates the transaction against a recent best block
/// of the [`runtime_service::RuntimeService`].
///
/// Returns the result of the validation, and the hash of the block it was validated against.
async fn validate_transaction(
    relay_chain_sync: &Arc<runtime_service::RuntimeService>,
    scale_encoded_transaction: impl AsRef<[u8]> + Clone,
    source: validate::TransactionSource,
) -> Result<
    (
        [u8; 32],
        Result<validate::ValidTransaction, validate::TransactionValidityError>,
    ),
    ValidateTransactionError,
> {
    let (runtime_call_lock, runtime) = relay_chain_sync
        .recent_best_block_runtime_call(
            validate::VALIDATION_FUNCTION_NAME,
            validate::validate_transaction_runtime_parameters(
                iter::once(scale_encoded_transaction.as_ref()),
                source,
            ),
        )
        .await
        .map_err(ValidateTransactionError::Call)?;

    let mut validation_in_progress = validate::validate_transaction(validate::Config {
        runtime,
        scale_encoded_header: runtime_call_lock.block_scale_encoded_header(),
        scale_encoded_transaction: iter::once(scale_encoded_transaction),
        source,
    });

    loop {
        match validation_in_progress {
            validate::Query::Finished {
                result: Ok(success),
                virtual_machine,
            } => {
                // TODO: provide hash as method of runtime_call_lock?
                let block_hash = header::hash_from_scale_encoded_header(
                    runtime_call_lock.block_scale_encoded_header(),
                );
                runtime_call_lock.unlock(virtual_machine);
                break Ok((block_hash, success));
            }
            validate::Query::Finished {
                result: Err(error),
                virtual_machine,
            } => {
                runtime_call_lock.unlock(virtual_machine);
                break Err(ValidateTransactionError::Validation(error));
            }
            validate::Query::StorageGet(get) => {
                let storage_value = match runtime_call_lock.storage_entry(&get.key_as_vec()) {
                    Ok(v) => v,
                    Err(err) => {
                        runtime_call_lock.unlock(validate::Query::StorageGet(get).into_prototype());
                        return Err(ValidateTransactionError::Call(err));
                    }
                };
                validation_in_progress = get.inject_value(storage_value.map(iter::once));
            }
            validate::Query::NextKey(_) => {
                todo!() // TODO:
            }
            validate::Query::PrefixKeys(prefix) => {
                // TODO: lots of allocations because I couldn't figure how to make this annoying borrow checker happy
                let rq_prefix = prefix.prefix().as_ref().to_owned();
                let result = runtime_call_lock
                    .storage_prefix_keys_ordered(&rq_prefix)
                    .map(|i| i.map(|v| v.as_ref().to_owned()).collect::<Vec<_>>());
                match result {
                    Ok(v) => validation_in_progress = prefix.inject_keys_ordered(v.into_iter()),
                    Err(err) => {
                        runtime_call_lock
                            .unlock(validate::Query::PrefixKeys(prefix).into_prototype());
                        return Err(ValidateTransactionError::Call(err));
                    }
                }
            }
        }
    }
}

/// See [`validate_transaction`].
#[derive(Debug, derive_more::Display)]
enum ValidateTransactionError {
    Call(runtime_service::RuntimeCallError),
    Validation(validate::Error),
}

/// Utility. Calculates the blake2 hash of the given bytes.
fn blake2_hash(bytes: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(blake2_rfc::blake2b::blake2b(32, &[], bytes).as_bytes()).unwrap()
}
