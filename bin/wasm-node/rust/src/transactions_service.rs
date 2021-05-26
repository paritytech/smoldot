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
//! The same "panic mode" happens if there's an accidental gap in the chain, which wills typically
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

use crate::{ffi, network_service, sync_service};

use futures::{channel::mpsc, lock::Mutex, prelude::*, stream::FuturesUnordered};
use smoldot::{
    chain::fork_tree, header, informant::HashDisplay, libp2p::peer_id::PeerId, network::protocol,
};
use std::{collections::HashMap, convert::TryFrom as _, iter, pin::Pin, sync::Arc, time::Duration};

/// Configuration for a [`TransactionsService`].
pub struct Config {
    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(Pin<Box<dyn Future<Output = ()> + Send>>) + Send>,

    /// Access to the network, and index of the chain to sync from the point of view of the
    /// network service.
    pub network_service: (Arc<network_service::NetworkService>, usize),

    /// Service responsible for synchronizing the chain.
    pub sync_service: Arc<sync_service::SyncService>,

    /// Maximum number of pending transactions allowed in the service.
    ///
    /// Any extra transaction will lead to [`TransactionStatus::Dropped`].
    pub max_pending_transactions: u32,

    /// Maximum number of block body downloads that can be performed in parallel.
    ///
    /// > **Note**: This is the maximum number of *blocks* whose body is being download, not the
    /// >           number of block requests emitted on the network.
    pub max_concurrent_downloads: u32,
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

        (config.tasks_executor)(Box::pin(background_task(
            config.network_service.0,
            config.network_service.1,
            config.sync_service,
            from_foreground,
            usize::try_from(config.max_concurrent_downloads).unwrap_or(usize::max_value()),
            usize::try_from(config.max_pending_transactions).unwrap_or(usize::max_value()),
        )));

        TransactionsService {
            to_background: Mutex::new(to_background),
        }
    }

    /// Adds a transaction to the service. The service will try to send it out as soon as
    /// possible.
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
    // Contains the hash of the block that contains the transaction.
    InBlock([u8; 32]),
    /// Can be sent after [`TransactionStatus::InBlock`] to notify that a re-org happened and the
    /// current best tree of blocks no longer contains the transaction.
    ///
    /// Contains the same block as was previously passed in [`TransactionStatus::InBlock`].
    Retracted([u8; 32]),
    /// Transaction has been dropped because the service was full or too slow.
    Dropped,
    /// Transaction has been included in a finalized block.
    Finalized([u8; 32]),
    /// Transaction is not in a finalized block, but is included in the 512th ancestor of the
    /// current best block. This can happen if finality has stalled or is simply not available
    /// on the chain.
    FinalityTimeout([u8; 32]),
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
    network_service: Arc<network_service::NetworkService>,
    network_chain_index: usize,
    sync_service: Arc<sync_service::SyncService>,
    mut from_foreground: mpsc::Receiver<ToBackground>,
    max_concurrent_downloads: usize,
    max_pending_transactions: usize,
) {
    let mut worker = Worker {
        sync_service,
        pending_transactions: HashMap::with_capacity_and_hasher(
            max_pending_transactions, // TODO: maybe not equal to max?
            Default::default(),
        ),
        blocks_tree: fork_tree::ForkTree::with_capacity(32),
        best_block_index: None,
        latest_finalized_block: (0, [0; 32]), // Initialized below.
        finalized_downloading_blocks: Vec::new(),
        block_downloads: FuturesUnordered::new(),
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
        let (_, mut finalized_block_receiver) = worker.sync_service.subscribe_finalized().await;

        worker.latest_finalized_block = (
            header::decode(&current_finalized_block_header)
                .unwrap()
                .number,
            header::hash_from_scale_encoded_header(&current_finalized_block_header),
        );
        worker.blocks_tree.clear();
        worker.best_block_index = None;

        // TODO: reset finalized_downloading_blocks too?

        // As explained above, this code is reached if there is a gap in the blocks.
        // Consequently, we drop all pending transactions.
        for pending in worker.pending_transactions.values_mut() {
            send_or_drop(&mut pending.status_update, TransactionStatus::Dropped);
        }
        worker.pending_transactions.clear();

        log::debug!(
            target: "tx-service",
            "Transactions watcher moved to finalized block {} (#{}).",
            HashDisplay(&worker.latest_finalized_block.1),
            worker.latest_finalized_block.0
        );

        loop {
            futures::select! {
                new_block = new_blocks_receiver.next().fuse() => {
                    if let Some(new_block) = new_block {
                        let hash = header::hash_from_scale_encoded_header(&new_block.scale_encoded_header);
                        worker.new_block(new_block.scale_encoded_header, &new_block.parent_hash);
                        if new_block.is_new_best {
                            worker.set_best_block(hash).await;
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
                    while let Some(new_block) = new_blocks_receiver.next().now_or_never() {
                        if let Some(new_block) = new_block {
                            let hash = header::hash_from_scale_encoded_header(&new_block.scale_encoded_header);
                            worker.new_block(new_block.scale_encoded_header, &new_block.parent_hash);
                            if new_block.is_new_best {
                                worker.set_best_block(hash).await;
                            }
                        } else {
                            continue 'channels_rebuild;
                        }
                    }

                    worker.new_finalized_block(finalized_block_header.unwrap()).await;
                },

                download = worker.block_downloads.select_next_some() => {
                    let (block_hash, block_body) = download;
                    worker.download_result(block_hash, block_body);
                },

                // TODO: refactor for performances
                (transaction_to_reannounce, _, _) = worker.pending_transactions.iter_mut()
                    .map(|(body, tx)| (&mut tx.when_reannounce).map(move |()| body))
                    .collect::<future::SelectAll<_>>().fuse() =>
                {
                    let transaction_to_reannounce = transaction_to_reannounce.to_owned();
                    let tx = worker.pending_transactions.get_mut(&transaction_to_reannounce)
                        .unwrap();

                    let peers_sent = network_service
                        .clone()
                        .announce_transaction(network_chain_index, &transaction_to_reannounce)
                        .await;

                    if !peers_sent.is_empty() {
                        send_or_drop(&mut tx.status_update, TransactionStatus::Broadcast(peers_sent));
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
                            if worker.pending_transactions.len() >= worker.max_pending_transactions {
                                if let Some(mut updates_report) = updates_report {
                                    let _ = updates_report.try_send(TransactionStatus::Dropped);
                                }
                                continue;
                            }

                            // TODO: move
                            /**/

                            let entry = worker
                                .pending_transactions
                                .entry(transaction_bytes)
                                .or_insert_with(|| PendingTransaction {
                                    when_reannounce: ffi::Delay::new(Duration::new(0, 0)),
                                    status_update: Vec::with_capacity(1),
                                });
                            if let Some(updates_report) = updates_report {
                                entry.status_update.push(updates_report);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Background worker running in parallel of the front service.
struct Worker {
    // How to download the bodies of blocks.
    sync_service: Arc<sync_service::SyncService>,

    /// All transactions that were submitted with [`TransactionsService::submit_extrinsic`] and
    /// their channel to send back their status.
    ///
    /// Keys are the transaction's body.
    ///
    /// Note that keys are untrusted data. It is important to use a random hashing algorithm in
    /// order to avoid possible collision attacks.
    ///
    /// All the entries in this map represent transactions that we're trying to include on the
    /// network. It is normal to find entries where the value is empty, as they still represent
    /// transactions that we're trying to include but whose status isn't interesting us.
    pending_transactions: HashMap<Vec<u8>, PendingTransaction, ahash::RandomState>,

    /// See [`Config::max_pending_transactions`].
    max_pending_transactions: usize,

    /// The transactions service maintains, in parallel of the sync service, a tree of all the
    /// non-finalized blocks. This is necessary in case of a re-org (i.e. the new best block is
    /// a nephew of the previous best block) in order to know which transactions that were present
    /// in the previous best chain are still present in the new best chain.
    // TODO: add a maximum size?
    blocks_tree: fork_tree::ForkTree<Block>,

    /// Index of the best block in [`Worker::blocks_tree`].
    /// `None` if the tree is empty or if the best block is also the latest finalized block.
    best_block_index: Option<fork_tree::NodeIndex>,

    /// Height and hash of the latest finalized block. Root of all the blocks in
    /// [`Worker::blocks_tree`].
    latest_finalized_block: (u64, [u8; 32]),

    /// List of blocks that have been finalized but whose body is still downloading.
    finalized_downloading_blocks: Vec<Block>,

    /// List of ongoing block body downloads.
    /// The output of the future is a block hash and a block body.
    block_downloads:
        FuturesUnordered<future::BoxFuture<'static, ([u8; 32], Result<Vec<Vec<u8>>, ()>)>>,

    /// See [`Config::max_concurrent_downloads`]. Maximum number of elements in
    /// [`Worker::block_downloads`].
    max_concurrent_downloads: usize,
}

struct Block {
    hash: [u8; 32],
    download_status: DownloadStatus,
}

enum DownloadStatus {
    /// Download hasn't been started yet.
    NotStarted,
    /// One of the futures in [`Worker::block_downloads`] is current downloading the body of this
    /// block.
    Downloading,
    /// Failed to download block body.
    /// This can legitimately happen if all the other nodes we are connected to have discarded
    /// this block.
    Failed,
    /// Successfully downloaded block body. Contains the list of extrinsics that we have sent
    /// out.
    Success(Vec<Vec<u8>>),
}

struct PendingTransaction {
    /// When to gossip the transaction on the network again.
    when_reannounce: ffi::Delay,
    status_update: Vec<mpsc::Sender<TransactionStatus>>,
}

impl Worker {
    /// Insert a new block in the worker when the sync service hears about it.
    fn new_block(&mut self, new_block_header: Vec<u8>, parent_hash: &[u8; 32]) {
        let new_block_hash = header::hash_from_scale_encoded_header(&new_block_header);
        debug_assert!(self
            .blocks_tree
            .find(|b| b.hash == new_block_hash)
            .is_none());

        let parent_index_in_tree = if *parent_hash == self.latest_finalized_block.1 {
            None
        } else {
            // The transactions service tracks all new blocks.
            // The parent of each new best block must therefore already be in the tree.
            Some(self.blocks_tree.find(|b| b.hash == *parent_hash).unwrap())
        };

        // TODO: only do this for best chain?
        let download_status = if !self.pending_transactions.is_empty() {
            if self.block_downloads.len() < self.max_concurrent_downloads {
                self.push_block_download(new_block_hash);
                DownloadStatus::Downloading
            } else {
                DownloadStatus::NotStarted
            }
        } else {
            DownloadStatus::NotStarted
        };

        self.blocks_tree.insert(
            parent_index_in_tree,
            Block {
                hash: new_block_hash,
                download_status,
            },
        );
    }

    /// Update the best block. Must have been inserted with [`Worker::new_block`].
    async fn set_best_block(&mut self, new_best_block_hash: [u8; 32]) {
        let new_best_block_index = self
            .blocks_tree
            .find(|b| b.hash == new_best_block_hash)
            .unwrap();

        // Iterate over all blocks on the tree and report the transaction status updates.
        let (old_best_to_common_ancestor, common_ancestor_to_new_best) =
            if let Some(old_best_index) = self.best_block_index {
                let (ascend, descend) = self
                    .blocks_tree
                    .ascend_and_descend(old_best_index, new_best_block_index);
                (either::Left(ascend), either::Left(descend))
            } else {
                let ascend = self.blocks_tree.node_to_root_path(new_best_block_index);
                let descend = iter::empty::<fork_tree::NodeIndex>();
                (either::Right(ascend), either::Right(descend))
            };

        // Iterate over the nodes that used to be part of the best chain but no longer are.
        for node_index in old_best_to_common_ancestor {
            let block_info = self.blocks_tree.get(node_index).unwrap();
            if let DownloadStatus::Success(transactions) = &block_info.download_status {
                for transaction in transactions {
                    let list = self.pending_transactions.get_mut(transaction).unwrap();
                    send_or_drop(
                        &mut list.status_update,
                        TransactionStatus::Retracted(block_info.hash),
                    );
                }
            }
        }

        // Iterate over the nodes that weren't part of the best chain but now are.
        let mut downloads_to_start = Vec::new();
        for node_index in common_ancestor_to_new_best {
            let block_info = self.blocks_tree.get(node_index).unwrap();
            match &block_info.download_status {
                DownloadStatus::NotStarted => {
                    if !self.pending_transactions.is_empty() {
                        downloads_to_start.push(node_index);
                    }
                }
                DownloadStatus::Failed | DownloadStatus::Downloading => {}
                DownloadStatus::Success(transactions) => {
                    for transaction in transactions {
                        let list = self.pending_transactions.get_mut(transaction).unwrap();
                        send_or_drop(
                            &mut list.status_update,
                            TransactionStatus::InBlock(block_info.hash),
                        );
                    }
                }
            }
        }

        for node_index in downloads_to_start {
            if self.block_downloads.len() >= self.max_concurrent_downloads {
                break;
            }

            let block_info = self.blocks_tree.get_mut(node_index).unwrap();
            block_info.download_status = DownloadStatus::Downloading;
            let hash = block_info.hash;
            self.push_block_download(hash);
        }

        self.best_block_index = Some(new_best_block_index);
    }

    async fn new_finalized_block(&mut self, finalized_block_header: Vec<u8>) {
        let finalized_block_hash = header::hash_from_scale_encoded_header(&finalized_block_header);

        // The finalized block must have been inserted in the tree earlier.
        let new_finalized_index = self
            .blocks_tree
            .find(|b| b.hash == finalized_block_hash)
            .unwrap();
        debug_assert!(self
            .blocks_tree
            .is_ancestor(new_finalized_index, self.best_block_index.unwrap()));

        // Remove nodes from the tree, either because they're not finalized or discarded.
        for pruned_node in self.blocks_tree.prune_ancestors(new_finalized_index) {
            if pruned_node.is_prune_target_ancestor {
                // Block has been removed from tree because it's finalized.
                match pruned_node.user_data.download_status {
                    DownloadStatus::NotStarted | DownloadStatus::Failed => {
                        // TODO: self.push_block_download(pruned_node.user_data.hash);
                    }
                    DownloadStatus::Downloading => {}
                    DownloadStatus::Success(transactions) => {
                        for transaction in transactions {
                            let mut list = self.pending_transactions.remove(&transaction).unwrap();
                            send_or_drop(
                                &mut list.status_update,
                                TransactionStatus::Finalized(pruned_node.user_data.hash),
                            );
                        }
                    }
                }

                // TODO: insert into finalized_downloading
            } else {
                // Block has been removed from tree because it's a sibling of a finalized block
                // and not itself finalized.
                // TODO: ?!
            }
        }
    }

    /// Inject the result of a download in the state machine.
    fn download_result(&mut self, block_hash: [u8; 32], block_body: Result<Vec<Vec<u8>>, ()>) {
        // TODO: what if finalized_downloading
        let index_in_tree = self.blocks_tree.find(|b| b.hash == block_hash).unwrap();

        debug_assert!(matches!(
            self.blocks_tree.get(index_in_tree).unwrap().download_status,
            DownloadStatus::Downloading
        ));

        self.blocks_tree
            .get_mut(index_in_tree)
            .unwrap()
            .download_status = match block_body {
            Ok(body) => {
                let transactions = body;

                todo!()
            }
            Err(()) => DownloadStatus::Failed,
        };
    }

    /// Inserts into `block_downloads` a future that downloads the body of the block with the
    /// given hash.
    fn push_block_download(&mut self, block_hash: [u8; 32]) {
        self.block_downloads.push({
            let download_future = self.sync_service.clone().block_query(
                block_hash,
                protocol::BlocksRequestFields {
                    body: true,
                    header: true, // TODO: must be true in order for the body to be verified; fix the sync_service to not require that
                    justification: false,
                },
            );

            async move { (block_hash, download_future.await.map(|b| b.body.unwrap())) }.boxed()
        });
    }
}

/// For each element in `channels`, tries to send the given item on it. If the channel is full or
/// disconnected, removes it from the list.
fn send_or_drop<T: Clone>(channels: &mut Vec<mpsc::Sender<T>>, item: T) {
    // Special-case if `channels.len() == 1` as 0 or 1 items is by far the most common situation.
    // This avoids cloning `T` unnecessarily.
    if channels.len() == 1 {
        if channels[0].try_send(item).is_err() {
            channels.clear();
        }
        return;
    }

    for n in 0..channels.len() {
        let mut channel = channels.swap_remove(n);
        if channel.try_send(item.clone()).is_ok() {
            channels.push(channel);
        }
    }
}
