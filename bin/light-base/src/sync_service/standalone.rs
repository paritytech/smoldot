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
        best_block_updated: false,
        finalized_block_updated: false,
        known_finalized_runtime: None,
        pending_block_requests: stream::FuturesUnordered::new(),
        pending_grandpa_requests: stream::FuturesUnordered::new(),
        pending_storage_requests: stream::FuturesUnordered::new(),
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
    loop {
        // Start all networking requests (block requests, warp sync requests, etc.) that the
        // syncing state machine would like to start.
        task.start_requests();

        // TODO: handle obsolete requests

        // The syncing state machine holds a queue of things (blocks, justifications, warp sync
        // fragments, etc.) to verify. Process this queue now.
        task = task.process_verification_queue().await;

        // Processing the queue might have updated the best block of the syncing state machine.
        if task.best_block_updated {
            task.best_block_updated = false;

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
        }

        // Processing the queue might have updated the finalized block of the syncing state
        // machine.
        if task.finalized_block_updated {
            task.finalized_block_updated = false;

            task.dispatch_all_subscribers(Notification::Finalized {
                hash: task.sync.finalized_block_header().hash(),
                best_block_hash: task.sync.best_block_hash(),
            });

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
                                    scale_encoded_justification: block.justification,
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
        };

        // `response_outcome` represents the way the state machine has changed as a
        // consequence of the response to a request.
        match response_outcome {
            all::ResponseOutcome::Outdated
            | all::ResponseOutcome::Queued
            | all::ResponseOutcome::NotFinalizedChain { .. }
            | all::ResponseOutcome::AllAlreadyInChain { .. } => {}
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

                debug_assert!(task.known_finalized_runtime.is_none());
                task.known_finalized_runtime = Some(FinalizedBlockRuntime {
                    virtual_machine: finalized_block_runtime,
                    storage_code: finalized_storage_code,
                    storage_heap_pages: finalized_storage_heap_pages,
                });

                task.finalized_block_updated = true;
                task.best_block_updated = true;
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

    /// `true` after the best block in the [`Task::sync`] has changed. Reset to `false` after all
    /// the corresponding state updates have been performed.
    best_block_updated: bool,
    /// `true` after the finalized block in the [`Task::sync`] has changed. Reset to `false` after
    /// all the corresponding state updates have been performed.
    finalized_block_updated: bool,

    /// All event subscribers that are interested in events about the chain.
    all_notifications: Vec<mpsc::Sender<Notification>>,

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
    fn start_requests(&mut self) {
        loop {
            // `desired_requests()` returns, in decreasing order of priority, the requests
            // that should be started in order for the syncing to proceed. The fact that multiple
            // requests are returned could be used to filter out undesired one. We use this
            // filtering to enforce a maximum of one ongoing request per source.
            let (source_id, _, mut request_detail) =
                match self.sync.desired_requests().find(|(source_id, _, _)| {
                    self.sync.source_num_ongoing_requests(*source_id) == 0
                }) {
                    Some(v) => v,
                    None => break,
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
                                network::protocol::BlocksRequestConfigStart::Number(
                                    first_block_height,
                                )
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
                                justification: request_justification,
                            },
                        },
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
        }
    }

    /// Verifies all the blocks, justifications, warp sync fragments, etc. that are queued for
    /// verification.
    ///
    /// Returns ̀`self`.
    async fn process_verification_queue(mut self) -> Self {
        // The sync state machine can be in a few various states. At the time of writing:
        // idle, verifying header, verifying block, verifying grandpa warp sync proof,
        // verifying storage proof.
        // If the state is one of the "verifying" states, perform the actual verification and
        // loop again until the sync is in an idle state.
        loop {
            // Since this task is verifying blocks or warp sync fragments, which are heavy CPU-only
            // operation, it is very much possible for it to take a long time before having to wait
            // for some event. Since JavaScript/Wasm is single-threaded, this would prevent all
            // the other tasks in the background from running.
            // In order to provide a better granularity, we force a yield after each verification.
            crate::util::yield_once().await;

            // Note that `process_one` moves out of `sync` and provides the value back in its
            // return value.
            match self.sync.process_one() {
                all::ProcessOne::AllSync(sync) => {
                    // Nothing to do. Queue is empty.
                    self.sync = sync;
                    return self;
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

                            self.best_block_updated |= is_new_best;

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

                            continue;
                        }

                        all::HeaderVerifyOutcome::Error { sync, error, .. } => {
                            self.sync = sync;

                            // TODO: print which peer sent the header
                            log::debug!(
                                target: &self.log_target,
                                "Sync => HeaderVerifyError(hash={}, error={})",
                                HashDisplay(&verified_hash),
                                error
                            );

                            log::warn!(
                                target: &self.log_target,
                                "Error while verifying header {}: {}",
                                HashDisplay(&verified_hash),
                                error
                            );

                            continue;
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

                            self.best_block_updated |= updates_best_block;
                            self.finalized_block_updated = true;
                            self.known_finalized_runtime = None; // TODO: only do if there was no RuntimeUpdated log item
                            continue;
                        }

                        (sync, all::JustificationVerifyOutcome::Error(error)) => {
                            self.sync = sync;

                            // TODO: print which peer sent the justification
                            log::debug!(
                                target: &self.log_target,
                                "Sync => JustificationVerificationError(error={})",
                                error,
                            );

                            log::warn!(
                                target: &self.log_target,
                                "Error while verifying justification: {}",
                                error
                            );

                            continue;
                        }
                    }
                }

                // Can't verify header and body in non-full mode.
                all::ProcessOne::VerifyBodyHeader(_) => unreachable!(),
            }
        }
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

                log::debug!(
                    target: &self.log_target,
                    "Sync <= BlockAnnounce(sender={}, hash={}, is_best={})",
                    peer_id,
                    HashDisplay(&header::hash_from_scale_encoded_header(&decoded.scale_encoded_header)),
                    decoded.is_best
                );

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
                        // The block announce is verified.
                        unreachable!()
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

                        self.finalized_block_updated = true; // TODO: only do if commit message has been processed
                        self.known_finalized_runtime = None; // TODO: only do if commit message has been processed and if there was no RuntimeUpdated log item in the finalized blocks
                        self.best_block_updated = true; // TODO: done in case finality changes the best block; make this clearer in the sync layer
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
