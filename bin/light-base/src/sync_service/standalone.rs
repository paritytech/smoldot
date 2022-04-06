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

use super::{BlockNotification, FinalizedBlockRuntime, Notification, SubscribeAll, ToBackground};
use crate::{network_service, Platform};

use futures::{channel::mpsc, prelude::*};
use smoldot::{
    chain, header,
    informant::HashDisplay,
    libp2p,
    network::{self, protocol},
    sync::all,
    trie::proof_verify,
};
use std::{
    collections::HashMap,
    marker::PhantomData,
    num::{NonZeroU32, NonZeroU64},
    sync::Arc,
    time::Duration,
};

/// Starts a sync service background task to synchronize a standalone chain (relay chain or not).
pub(super) async fn start_standalone_chain<TPlat: Platform>(
    log_target: String,
    chain_information: chain::chain_information::ValidChainInformation,
    mut from_foreground: mpsc::Receiver<ToBackground>,
    network_service: Arc<network_service::NetworkService<TPlat>>,
    network_chain_index: usize,
    from_network_service: stream::BoxStream<'static, network_service::Event>,
) {
    let mut task = Task {
        sync: all::AllSync::new(all::Config {
            chain_information,
            sources_capacity: 32,
            blocks_capacity: {
                // This is the maximum number of blocks between two consecutive justifications.
                1024
            },
            max_disjoint_headers: 1024,
            max_requests_per_block: NonZeroU32::new(3).unwrap(),
            download_ahead_blocks: {
                // Verifying a block mostly consists in:
                //
                // - Verifying a sr25519 signature for each block, plus a VRF output when the
                // block is claiming a primary BABE slot.
                // - Verifying one ed25519 signature per authority for every justification.
                //
                // At the time of writing, the speed of these operations hasn't been benchmarked.
                // It is likely that it varies quite a bit between the various environments (the
                // different browser engines, and NodeJS).
                //
                // Assuming a maximum verification speed of 5k blocks/sec and a 95% latency of one
                // second, the number of blocks to download ahead of time in order to not block
                // is 5k.
                NonZeroU32::new(5000).unwrap()
            },
            full: None,
        }),
        network_up_to_date_best: true,
        network_up_to_date_finalized: true,
        known_finalized_runtime: None,
        pending_block_requests: stream::FuturesUnordered::new(),
        pending_grandpa_requests: stream::FuturesUnordered::new(),
        pending_storage_requests: stream::FuturesUnordered::new(),
        warp_sync_taking_long_time_warning: future::Either::Left(TPlat::sleep(
            Duration::from_secs(15),
        ))
        .fuse(),
        all_notifications: Vec::<mpsc::Sender<Notification>>::new(),
        log_target,
        network_service,
        network_chain_index,
        peers_source_id_map: HashMap::new(),
        platform: PhantomData,
    };

    // Necessary for the `select!` loop below.
    let mut from_network_service = from_network_service.fuse();

    // Main loop of the syncing logic.
    //
    // This loop contains some CPU-heavy operations (e.g. verifying justifications and warp sync
    // proofs) but also responding to messages sent by the foreground sync service. In order to
    // avoid long delays in responding to foreground messages, the CPU-heavy operations are split
    // into small chunks, and each iteration of the loop processes at most one of these chunks and
    // processes one foreground message.
    loop {
        // Try to perform some CPU-heavy operations.
        // If any CPU-heavy verification was performed, then `queue_empty` will be `false`, in
        // which case we will loop again as soon as possible.
        let queue_empty = {
            let mut queue_empty = true;

            // Start a networking request (block requests, warp sync requests, etc.) that the
            // syncing state machine would like to start.
            if task.start_next_request() {
                queue_empty = false;
            }

            // TODO: handle obsolete requests

            // The sync state machine can be in a few various states. At the time of writing:
            // idle, verifying header, verifying block, verifying grandpa warp sync proof,
            // verifying storage proof.
            // If the state is one of the "verifying" states, perform the actual verification
            // and set ̀`queue_empty` to `false`.
            let (task_update, has_done_verif) = task.process_one_verification_queue();
            task = task_update;

            if has_done_verif {
                queue_empty = false;

                // Since JavaScript/Wasm is single-threaded, executing many CPU-heavy operations
                // in a row would prevent all the other tasks in the background from running.
                // In order to provide a better granularity, we force a yield after each
                // verification.
                crate::util::yield_once().await;
            }

            queue_empty
        };

        // Processing the queue might have updated the best block of the syncing state machine.
        if !task.network_up_to_date_best {
            // The networking service needs to be kept up to date with what the local node
            // considers as the best block.
            // For some reason, first building the future then executing it solves a borrow
            // checker error.
            let fut = task.network_service.set_local_best_block(
                network_chain_index,
                task.sync.best_block_hash(),
                task.sync.best_block_number(),
            );
            fut.await;

            task.network_up_to_date_best = true;
        }

        // Processing the queue might have updated the finalized block of the syncing state
        // machine.
        if !task.network_up_to_date_finalized {
            // If the chain uses GrandPa, the networking has to be kept up-to-date with the
            // state of finalization for other peers to send back relevant gossip messages.
            // (code style) `grandpa_set_id` is extracted first in order to avoid borrowing
            // checker issues.
            let grandpa_set_id =
                if let chain::chain_information::ChainInformationFinalityRef::Grandpa {
                    after_finalized_block_authorities_set_id,
                    ..
                } = task.sync.as_chain_information().as_ref().finality
                {
                    Some(after_finalized_block_authorities_set_id)
                } else {
                    None
                };

            if let Some(set_id) = grandpa_set_id {
                let commit_finalized_height =
                    u32::try_from(task.sync.finalized_block_header().number).unwrap(); // TODO: unwrap :-/
                task.network_service
                    .set_local_grandpa_state(
                        network_chain_index,
                        network::service::GrandpaState {
                            set_id,
                            round_number: 1, // TODO:
                            commit_finalized_height,
                        },
                    )
                    .await;
            }

            task.network_up_to_date_finalized = true;
        }

        // Now waiting for some event to happen: a network event, a request from the frontend
        // of the sync service, or a request being finished.
        let response_outcome = futures::select! {
            network_event = from_network_service.next() => {
                // Something happened on the network.
                // We expect the networking channel to never close, so the event is unwrapped.
                task.inject_network_event(network_event.unwrap());
                continue;
            }

            message = from_foreground.next() => {
                // Received message from the front `SyncService`.
                let message = match message {
                    Some(m) => m,
                    None => {
                        // The channel with the frontend sync service has been closed.
                        // Closing the sync background task as a result.
                        return
                    },
                };

                task.process_foreground_message(message);
                continue;
            },

            (request_id, result) = task.pending_block_requests.select_next_some() => {
                // A block(s) request has been finished.
                // `result` is an error if the block request got cancelled by the sync state
                // machine.
                if let Ok(result) = result {
                    // Inject the result of the request into the sync state machine.
                    task.sync.blocks_request_response(
                        request_id,
                        result.map_err(|_| ()).map(|v| {
                            v.into_iter().filter_map(|block| {
                                Some(all::BlockRequestSuccessBlock {
                                    scale_encoded_header: block.header?,
                                    scale_encoded_justifications: block.justifications.unwrap_or(Vec::new()),
                                    scale_encoded_extrinsics: Vec::new(),
                                    user_data: (),
                                })
                            })
                        })
                    ).1

                } else {
                    // The sync state machine has emitted a `Action::Cancel` earlier, and is
                    // thus no longer interested in the response.
                    continue;
                }
            },

            (request_id, result) = task.pending_grandpa_requests.select_next_some() => {
                // A GrandPa warp sync request has been finished.
                // `result` is an error if the block request got cancelled by the sync state
                // machine.
                if let Ok(result) = result {
                    // Inject the result of the request into the sync state machine.
                    task.sync.grandpa_warp_sync_response(
                        request_id,
                        result.ok(),
                    ).1

                } else {
                    // The sync state machine has emitted a `Action::Cancel` earlier, and is
                    // thus no longer interested in the response.
                    continue;
                }
            },

            (request_id, result) = task.pending_storage_requests.select_next_some() => {
                // A storage request has been finished.
                // `result` is an error if the block request got cancelled by the sync state
                // machine.
                if let Ok(result) = result {
                    // Inject the result of the request into the sync state machine.
                    task.sync.storage_get_response(
                        request_id,
                        result.map(|list| list.into_iter()),
                    ).1

                } else {
                    // The sync state machine has emitted a `Action::Cancel` earlier, and is
                    // thus no longer interested in the response.
                    continue;
                }
            },

            () = &mut task.warp_sync_taking_long_time_warning => {
                log::warn!(
                    target: &task.log_target,
                    "GrandPa warp sync still in progress and taking a long time"
                );

                task.warp_sync_taking_long_time_warning =
                    future::Either::Left(TPlat::sleep(Duration::from_secs(15))).fuse();
                continue;
            },

            // If the list of CPU-heavy operations to perform is potentially non-empty, then we
            // wait for a future that is always instantly ready, in order to loop again and
            // perform the next CPU-heavy operation.
            // Note that if any of the other futures in that `select!` block is ready, then that
            // other ready future might take precedence (or not, it is pseudo-random). This
            // guarantees proper interleaving between CPU-heavy operations and responding to
            // other kind of events.
            () = if queue_empty { future::Either::Left(future::pending()) }
                 else { future::Either::Right(future::ready(())) } =>
            {
                continue;
            }
        };

        // `response_outcome` represents the way the state machine has changed as a
        // consequence of the response to a request.
        match response_outcome {
            all::ResponseOutcome::Outdated
            | all::ResponseOutcome::Queued
            | all::ResponseOutcome::NotFinalizedChain { .. }
            | all::ResponseOutcome::AllAlreadyInChain { .. } => {}
            all::ResponseOutcome::WarpSyncError { error } => {
                log::warn!(
                    target: &task.log_target,
                    "Error during GrandPa warp syncing: {}",
                    error
                );
            }
            all::ResponseOutcome::WarpSyncFinished {
                finalized_block_runtime,
                finalized_storage_code,
                finalized_storage_heap_pages,
            } => {
                let finalized_header = task.sync.finalized_block_header();
                log::info!(
                    target: &task.log_target,
                    "GrandPa warp sync finished to #{} ({})",
                    finalized_header.number,
                    HashDisplay(&finalized_header.hash())
                );

                task.warp_sync_taking_long_time_warning =
                    future::Either::Right(future::pending()).fuse();

                debug_assert!(task.known_finalized_runtime.is_none());
                task.known_finalized_runtime = Some(FinalizedBlockRuntime {
                    virtual_machine: finalized_block_runtime,
                    storage_code: finalized_storage_code,
                    storage_heap_pages: finalized_storage_heap_pages,
                });

                task.network_up_to_date_finalized = false;
                task.network_up_to_date_best = false;
                // Since there is a gap in the blocks, all active notifications to all blocks
                // must be cleared.
                task.all_notifications.clear();
            }
        }
    }
}

struct Task<TPlat: Platform> {
    /// Log target to use for all logs that are emitted.
    log_target: String,

    /// Main syncing state machine. Contains a list of peers, requests, and blocks, and manages
    /// everything about the non-finalized chain.
    ///
    /// For each request, we store a [`future::AbortHandle`] that can be used to abort the
    /// request if desired.
    sync: all::AllSync<future::AbortHandle, (libp2p::PeerId, protocol::Role), ()>,

    /// If `Some`, contains the runtime of the current finalized block.
    known_finalized_runtime: Option<FinalizedBlockRuntime>,

    /// For each networking peer, the index of the corresponding peer within the [`Task::sync`].
    peers_source_id_map: HashMap<libp2p::PeerId, all::SourceId>,

    /// `false` after the best block in the [`Task::sync`] has changed. Set back to `true`
    /// after the networking has been notified of this change.
    network_up_to_date_best: bool,
    /// `false` after the finalized block in the [`Task::sync`] has changed. Set back to `true`
    /// after the networking has been notified of this change.
    network_up_to_date_finalized: bool,

    /// All event subscribers that are interested in events about the chain.
    all_notifications: Vec<mpsc::Sender<Notification>>,

    /// Contains a `Delay` after which we print a warning about GrandPa warp sync taking a long
    /// time. Set to `Pending` after the warp sync has finished, so that future remains pending
    /// forever.
    warp_sync_taking_long_time_warning:
        future::Fuse<future::Either<TPlat::Delay, future::Pending<()>>>,

    /// Network service. Used to send out requests to peers.
    network_service: Arc<network_service::NetworkService<TPlat>>,
    /// Index within the network service of the chain we are interested in. Must be indicated to
    /// the network service whenever a request is started.
    network_chain_index: usize,

    /// List of block requests currently in progress.
    pending_block_requests: stream::FuturesUnordered<
        future::BoxFuture<
            'static,
            (
                all::RequestId,
                Result<
                    Result<Vec<protocol::BlockData>, network::service::BlocksRequestError>,
                    future::Aborted,
                >,
            ),
        >,
    >,

    /// List of grandpa warp sync requests currently in progress.
    pending_grandpa_requests: stream::FuturesUnordered<
        future::BoxFuture<
            'static,
            (
                all::RequestId,
                Result<
                    Result<
                        protocol::GrandpaWarpSyncResponse,
                        network::service::GrandpaWarpSyncRequestError,
                    >,
                    future::Aborted,
                >,
            ),
        >,
    >,

    /// List of storage requests currently in progress.
    pending_storage_requests: stream::FuturesUnordered<
        future::BoxFuture<
            'static,
            (
                all::RequestId,
                Result<Result<Vec<Option<Vec<u8>>>, ()>, future::Aborted>,
            ),
        >,
    >,

    platform: PhantomData<fn() -> TPlat>,
}

impl<TPlat: Platform> Task<TPlat> {
    /// Starts one network request if any is necessary.
    ///
    /// Returns `true` if a request has been started.
    fn start_next_request(&mut self) -> bool {
        // `desired_requests()` returns, in decreasing order of priority, the requests
        // that should be started in order for the syncing to proceed. The fact that multiple
        // requests are returned could be used to filter out undesired one. We use this
        // filtering to enforce a maximum of one ongoing request per source.
        let (source_id, _, mut request_detail) = match self
            .sync
            .desired_requests()
            .find(|(source_id, _, _)| self.sync.source_num_ongoing_requests(*source_id) == 0)
        {
            Some(v) => v,
            None => return false,
        };

        // Before inserting the request back to the syncing state machine, clamp the number
        // of blocks to the number of blocks we expect to receive.
        // This constant corresponds to the maximum number of blocks that nodes will answer
        // in one request. If this constant happens to be inaccurate, everything will still
        // work but less efficiently.
        request_detail.num_blocks_clamp(NonZeroU64::new(64).unwrap());

        match request_detail {
            all::RequestDetail::BlocksRequest {
                first_block_hash,
                first_block_height,
                ascending,
                num_blocks,
                request_headers,
                request_bodies,
                request_justification,
            } => {
                let peer_id = self.sync[source_id].0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                let block_request = self.network_service.clone().blocks_request(
                    peer_id,
                    self.network_chain_index,
                    network::protocol::BlocksRequestConfig {
                        start: if let Some(first_block_hash) = first_block_hash {
                            network::protocol::BlocksRequestConfigStart::Hash(first_block_hash)
                        } else {
                            network::protocol::BlocksRequestConfigStart::Number(first_block_height)
                        },
                        desired_count: NonZeroU32::new(
                            u32::try_from(num_blocks.get()).unwrap_or(u32::max_value()),
                        )
                        .unwrap(),
                        direction: if ascending {
                            network::protocol::BlocksRequestDirection::Ascending
                        } else {
                            network::protocol::BlocksRequestDirection::Descending
                        },
                        fields: network::protocol::BlocksRequestFields {
                            header: request_headers,
                            body: request_bodies,
                            justifications: request_justification,
                        },
                    },
                    Duration::from_secs(10),
                );

                let (block_request, abort) = future::abortable(block_request);
                let request_id = self.sync.add_request(source_id, request_detail, abort);

                self.pending_block_requests
                    .push(async move { (request_id, block_request.await) }.boxed());
            }

            all::RequestDetail::GrandpaWarpSync {
                sync_start_block_hash,
            } => {
                let peer_id = self.sync[source_id].0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                let grandpa_request = self.network_service.clone().grandpa_warp_sync_request(
                    peer_id,
                    self.network_chain_index,
                    sync_start_block_hash,
                    // The timeout needs to be long enough to potentially download the maximum
                    // response size of 16 MiB. Assuming a 128 kiB/sec connection, that's
                    // 128 seconds. Unfortunately, 128 seconds is way too large, and for
                    // pragmatic reasons we use a lower value.
                    Duration::from_secs(24),
                );

                let (grandpa_request, abort) = future::abortable(grandpa_request);
                let request_id = self.sync.add_request(source_id, request_detail, abort);

                self.pending_grandpa_requests
                    .push(async move { (request_id, grandpa_request.await) }.boxed());
            }

            all::RequestDetail::StorageGet {
                block_hash,
                state_trie_root,
                ref keys,
            } => {
                let peer_id = self.sync[source_id].0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                let storage_request = self.network_service.clone().storage_proof_request(
                    self.network_chain_index,
                    peer_id,
                    network::protocol::StorageProofRequestConfig {
                        block_hash,
                        keys: keys.clone().into_iter(),
                    },
                    Duration::from_secs(16),
                );

                let keys = keys.clone();
                let storage_request = async move {
                    if let Ok(outcome) = storage_request.await {
                        // TODO: lots of copying around
                        // TODO: log what happens
                        keys.iter()
                            .map(|key| {
                                proof_verify::verify_proof(proof_verify::VerifyProofConfig {
                                    proof: outcome.iter().map(|nv| &nv[..]),
                                    requested_key: key.as_ref(),
                                    trie_root_hash: &state_trie_root,
                                })
                                .map_err(|_| ())
                                .map(|v| v.map(|v| v.to_vec()))
                            })
                            .collect::<Result<Vec<_>, ()>>()
                    } else {
                        Err(())
                    }
                };

                let (storage_request, abort) = future::abortable(storage_request);
                let request_id = self.sync.add_request(source_id, request_detail, abort);

                self.pending_storage_requests
                    .push(async move { (request_id, storage_request.await) }.boxed());
            }
        }

        true
    }

    /// Verifies one block, or justification, or warp sync fragment, etc. that is queued for
    /// verification.
    ///
    /// Returns ̀`self` and a boolean indicating whether something has been processed.
    fn process_one_verification_queue(mut self) -> (Self, bool) {
        // Note that `process_one` moves out of `sync` and provides the value back in its
        // return value.
        match self.sync.process_one() {
            all::ProcessOne::AllSync(sync) => {
                // Nothing to do. Queue is empty.
                self.sync = sync;
                return (self, false);
            }

            all::ProcessOne::VerifyWarpSyncFragment(verify) => {
                // Grandpa warp sync fragment to verify.
                let sender_peer_id = verify.proof_sender().1 .0.clone(); // TODO: unnecessary cloning most of the time

                let (sync, result) = verify.perform();
                self.sync = sync;

                if let Err(err) = result {
                    log::warn!(
                        target: &self.log_target,
                        "Failed to verify warp sync fragment from {}: {}",
                        sender_peer_id,
                        err
                    );
                }
            }

            all::ProcessOne::VerifyHeader(verify) => {
                // Header to verify.
                let verified_hash = verify.hash();
                match verify.perform(TPlat::now_from_unix_epoch(), ()) {
                    all::HeaderVerifyOutcome::Success {
                        sync, is_new_best, ..
                    } => {
                        self.sync = sync;

                        log::debug!(
                            target: &self.log_target,
                            "Sync => HeaderVerified(hash={}, new_best={})",
                            HashDisplay(&verified_hash),
                            if is_new_best { "yes" } else { "no" }
                        );

                        if is_new_best {
                            self.network_up_to_date_best = false;
                        }

                        // Notify of the new block.
                        self.dispatch_all_subscribers({
                            // TODO: the code below is `O(n)` complexity
                            let header = self
                                .sync
                                .non_finalized_blocks_unordered()
                                .find(|h| h.hash() == verified_hash)
                                .unwrap();
                            Notification::Block(BlockNotification {
                                is_new_best,
                                scale_encoded_header: header.scale_encoding_vec(),
                                parent_hash: *header.parent_hash,
                            })
                        });
                    }

                    all::HeaderVerifyOutcome::Error { sync, error, .. } => {
                        self.sync = sync;

                        // TODO: print which peer sent the header
                        log::debug!(
                            target: &self.log_target,
                            "Sync => HeaderVerifyError(hash={}, error={:?})",
                            HashDisplay(&verified_hash),
                            error
                        );

                        log::warn!(
                            target: &self.log_target,
                            "Error while verifying header {}: {}",
                            HashDisplay(&verified_hash),
                            error
                        );
                    }
                }
            }

            all::ProcessOne::VerifyJustification(verify) => {
                // Justification to verify.
                match verify.perform() {
                    (
                        sync,
                        all::JustificationVerifyOutcome::NewFinalized {
                            updates_best_block,
                            finalized_blocks,
                            ..
                        },
                    ) => {
                        self.sync = sync;

                        log::debug!(
                            target: &self.log_target,
                            "Sync => JustificationVerified(finalized_blocks={})",
                            finalized_blocks.len(),
                        );

                        if updates_best_block {
                            self.network_up_to_date_best = false;
                        }
                        self.network_up_to_date_finalized = false;
                        self.known_finalized_runtime = None; // TODO: only do if there was no RuntimeUpdated log item
                        self.dispatch_all_subscribers(Notification::Finalized {
                            hash: self.sync.finalized_block_header().hash(),
                            best_block_hash: self.sync.best_block_hash(),
                        });
                    }

                    (sync, all::JustificationVerifyOutcome::Error(error)) => {
                        self.sync = sync;

                        // TODO: print which peer sent the justification
                        log::debug!(
                            target: &self.log_target,
                            "Sync => JustificationVerificationError(error={:?})",
                            error,
                        );

                        log::warn!(
                            target: &self.log_target,
                            "Error while verifying justification: {}",
                            error
                        );
                    }
                }
            }

            // Can't verify header and body in non-full mode.
            all::ProcessOne::VerifyBodyHeader(_) => unreachable!(),
        }

        (self, true)
    }

    /// Process a request coming from the foreground service.
    fn process_foreground_message(&mut self, message: ToBackground) {
        match message {
            ToBackground::IsNearHeadOfChainHeuristic { send_back } => {
                let _ = send_back.send(self.sync.is_near_head_of_chain_heuristic());
            }

            ToBackground::SubscribeAll {
                send_back,
                buffer_size,
                runtime_interest,
            } => {
                let (tx, new_blocks) = mpsc::channel(buffer_size.saturating_sub(1));
                self.all_notifications.push(tx);

                let non_finalized_blocks_ancestry_order = {
                    let best_hash = self.sync.best_block_hash();
                    self.sync
                        .non_finalized_blocks_ancestry_order()
                        .map(|h| {
                            let scale_encoding = h.scale_encoding_vec();
                            BlockNotification {
                                is_new_best: header::hash_from_scale_encoded_header(
                                    &scale_encoding,
                                ) == best_hash,
                                scale_encoded_header: scale_encoding,
                                parent_hash: *h.parent_hash,
                            }
                        })
                        .collect()
                };

                let _ = send_back.send(SubscribeAll {
                    finalized_block_scale_encoded_header: self
                        .sync
                        .finalized_block_header()
                        .scale_encoding_vec(),
                    finalized_block_runtime: if runtime_interest {
                        self.known_finalized_runtime.take()
                    } else {
                        None
                    },
                    non_finalized_blocks_ancestry_order,
                    new_blocks,
                });
            }

            ToBackground::PeersAssumedKnowBlock {
                send_back,
                block_number,
                block_hash,
            } => {
                let finalized_num = self.sync.finalized_block_header().number;
                let outcome = if block_number <= finalized_num {
                    self.sync
                        .sources()
                        .filter(|source_id| {
                            let source_best = self.sync.source_best_block(*source_id);
                            source_best.0 > block_number
                                || (source_best.0 == block_number && *source_best.1 == block_hash)
                        })
                        .map(|id| self.sync[id].0.clone())
                        .collect()
                } else {
                    // As documented, `knows_non_finalized_block` would panic if the
                    // block height was below the one of the known finalized block.
                    self.sync
                        .knows_non_finalized_block(block_number, &block_hash)
                        .map(|id| self.sync[id].0.clone())
                        .collect()
                };
                let _ = send_back.send(outcome);
            }

            ToBackground::SyncingPeers { send_back } => {
                let out = self
                    .sync
                    .sources()
                    .map(|src| {
                        let (peer_id, role) = self.sync[src].clone();
                        let (height, hash) = self.sync.source_best_block(src);
                        (peer_id, role, height, *hash)
                    })
                    .collect::<Vec<_>>();
                let _ = send_back.send(out);
            }

            ToBackground::SerializeChainInformation { send_back } => {
                let _ = send_back.send(Some(self.sync.as_chain_information().into()));
            }
        }
    }

    /// Updates the task with a new event coming from the network service.
    fn inject_network_event(&mut self, network_event: network_service::Event) {
        match network_event {
            network_service::Event::Connected {
                peer_id,
                role,
                chain_index,
                best_block_number,
                best_block_hash,
            } if chain_index == self.network_chain_index => {
                self.peers_source_id_map.insert(
                    peer_id.clone(),
                    self.sync
                        .add_source((peer_id, role), best_block_number, best_block_hash),
                );
            }

            network_service::Event::Disconnected {
                peer_id,
                chain_index,
            } if chain_index == self.network_chain_index => {
                let sync_source_id = self.peers_source_id_map.remove(&peer_id).unwrap();
                let (_, requests) = self.sync.remove_source(sync_source_id);

                // The `Disconnect` network event indicates that the main notifications substream
                // with that peer has been closed, not necessarily that the connection as a whole
                // has been closed. As such, the in-progress network requests might continue if
                // we don't abort them.
                for (_, abort) in requests {
                    abort.abort();
                }
            }

            network_service::Event::BlockAnnounce {
                chain_index,
                peer_id,
                announce,
            } if chain_index == self.network_chain_index => {
                let sync_source_id = *self.peers_source_id_map.get(&peer_id).unwrap();
                let decoded = announce.decode();

                match header::decode(&decoded.scale_encoded_header) {
                    Ok(decoded_header) => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync <= BlockAnnounce(sender={}, hash={}, is_best={}, parent_hash={})",
                            peer_id,
                            HashDisplay(&header::hash_from_scale_encoded_header(&decoded.scale_encoded_header)),
                            decoded.is_best,
                            HashDisplay(decoded_header.parent_hash)
                        );
                    }
                    Err(error) => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync <= BlockAnnounce(sender={}, hash={}, is_best={}, parent_hash=<unknown>)",
                            peer_id,
                            HashDisplay(&header::hash_from_scale_encoded_header(&decoded.scale_encoded_header)),
                            decoded.is_best,
                        );

                        log::debug!(
                            target: &self.log_target,
                            "Sync => InvalidBlockHeader(error={})",
                            error
                        );

                        log::warn!(
                            target: &self.log_target,
                            "Failed to decode header in block announce received from {}. Error: {}",
                            peer_id, error,
                        )
                    }
                }

                match self.sync.block_announce(
                    sync_source_id,
                    decoded.scale_encoded_header.to_owned(),
                    decoded.is_best,
                ) {
                    all::BlockAnnounceOutcome::HeaderVerify
                    | all::BlockAnnounceOutcome::AlreadyInChain => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync => Ok"
                        );
                    }
                    all::BlockAnnounceOutcome::Discarded => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync => Discarded"
                        );
                    }
                    all::BlockAnnounceOutcome::Disjoint {} => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync => Disjoint"
                        );
                    }
                    all::BlockAnnounceOutcome::TooOld {
                        announce_block_height,
                        ..
                    } => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync => TooOld"
                        );

                        log::warn!(
                            target: &self.log_target,
                            "Block announce header height (#{}) from {} is below finalized block",
                            announce_block_height,
                            peer_id
                        );
                    }
                    all::BlockAnnounceOutcome::NotFinalizedChain => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync => NotFinalized"
                        );

                        log::warn!(
                            target: &self.log_target,
                            "Block announce from {} isn't part of finalized chain",
                            peer_id
                        );
                    }
                    all::BlockAnnounceOutcome::InvalidHeader(_) => {
                        // Log messages are already printed above.
                    }
                }
            }

            network_service::Event::GrandpaCommitMessage {
                chain_index,
                message,
            } if chain_index == self.network_chain_index => {
                match self.sync.grandpa_commit_message(&message.as_encoded()) {
                    Ok(()) => {
                        // TODO: print more details
                        log::debug!(
                            target: &self.log_target,
                            "Sync => GrandpaCommitVerified"
                        );

                        self.network_up_to_date_finalized = false; // TODO: only do if commit message has been processed
                        self.known_finalized_runtime = None; // TODO: only do if commit message has been processed and if there was no RuntimeUpdated log item in the finalized blocks
                        self.network_up_to_date_best = false; // TODO: done in case finality changes the best block; make this clearer in the sync layer
                        self.dispatch_all_subscribers(Notification::Finalized {
                            hash: self.sync.finalized_block_header().hash(),
                            best_block_hash: self.sync.best_block_hash(),
                        });
                    }
                    Err(err) => {
                        log::warn!(
                            target: &self.log_target,
                            "Error when verifying GrandPa commit message: {}",
                            err
                        );
                    }
                }
            }

            _ => {
                // Different chain index.
            }
        }
    }

    /// Sends a notification to all the notification receivers.
    fn dispatch_all_subscribers(&mut self, notification: Notification) {
        // Elements in `all_notifications` are removed one by one and inserted back if the
        // channel is still open.
        for index in (0..self.all_notifications.len()).rev() {
            let mut subscription = self.all_notifications.swap_remove(index);
            if subscription.try_send(notification.clone()).is_err() {
                continue;
            }

            self.all_notifications.push(subscription);
        }
    }
}
