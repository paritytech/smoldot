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

use super::{BlockNotification, Notification, SubscribeAll, ToBackground};
use crate::{ffi, network_service};

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
    convert::TryFrom as _,
    num::{NonZeroU32, NonZeroU64},
    sync::Arc,
};

pub(super) async fn start_standalone_chain(
    log_target: String,
    chain_information: chain::chain_information::ValidChainInformation,
    mut from_foreground: mpsc::Receiver<ToBackground>,
    network_service: Arc<network_service::NetworkService>,
    network_chain_index: usize,
    mut from_network_service: mpsc::Receiver<network_service::Event>,
) -> impl Future<Output = ()> {
    // TODO: implicit generics
    let mut sync = all::AllSync::<_, (libp2p::PeerId, protocol::Role), ()>::new(all::Config {
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
    });

    async move {
        // TODO: remove
        let mut peers_source_id_map = HashMap::new();

        // List of block requests currently in progress.
        let mut pending_block_requests = stream::FuturesUnordered::new();
        // List of grandpa warp sync requests currently in progress.
        let mut pending_grandpa_requests = stream::FuturesUnordered::new();
        // List of storage requests currently in progress.
        let mut pending_storage_requests = stream::FuturesUnordered::new();
        let mut all_notifications = Vec::<mpsc::Sender<Notification>>::new();

        let mut has_new_best = false;
        let mut has_new_finalized = false;

        // Main loop of the syncing logic.
        loop {
            loop {
                // `desired_requests()` returns, in decreasing order of priority, the requests
                // that should be started in order for the syncing to proceed. We simply pick the
                // first request, but enforce one ongoing request per source.
                let (source_id, _, mut request_detail) = match sync
                    .desired_requests()
                    .find(|(source_id, _, _)| sync.source_num_ongoing_requests(*source_id) == 0)
                {
                    Some(v) => v,
                    None => break,
                };

                // Before notifying the syncing of the request, clamp the number of blocks to the
                // number of blocks we expect to receive.
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
                        let peer_id = sync.source_user_data_mut(source_id).0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                        let block_request = network_service.clone().blocks_request(
                            peer_id,
                            network_chain_index,
                            network::protocol::BlocksRequestConfig {
                                start: if let Some(first_block_hash) = first_block_hash {
                                    network::protocol::BlocksRequestConfigStart::Hash(
                                        first_block_hash,
                                    )
                                } else {
                                    network::protocol::BlocksRequestConfigStart::Number(
                                        NonZeroU64::new(first_block_height).unwrap(), // TODO: unwrap?
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
                        let request_id = sync.add_request(source_id, request_detail, abort);

                        pending_block_requests
                            .push(async move { (request_id, block_request.await) });
                    }
                    all::RequestDetail::GrandpaWarpSync {
                        sync_start_block_hash,
                    } => {
                        let peer_id = sync.source_user_data_mut(source_id).0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                        let grandpa_request = network_service.clone().grandpa_warp_sync_request(
                            peer_id,
                            network_chain_index,
                            sync_start_block_hash,
                        );

                        let (grandpa_request, abort) = future::abortable(grandpa_request);
                        let request_id = sync.add_request(source_id, request_detail, abort);

                        pending_grandpa_requests
                            .push(async move { (request_id, grandpa_request.await) });
                    }
                    all::RequestDetail::StorageGet {
                        block_hash,
                        state_trie_root,
                        ref keys,
                    } => {
                        let peer_id = sync.source_user_data_mut(source_id).0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                        let storage_request = network_service.clone().storage_proof_request(
                            network_chain_index,
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
                                        proof_verify::verify_proof(
                                            proof_verify::VerifyProofConfig {
                                                proof: outcome.iter().map(|nv| &nv[..]),
                                                requested_key: key.as_ref(),
                                                trie_root_hash: &state_trie_root,
                                            },
                                        )
                                        .map_err(|_| ())
                                        .map(|v| v.map(|v| v.to_vec()))
                                    })
                                    .collect::<Result<Vec<_>, ()>>()
                            } else {
                                Err(())
                            }
                        };

                        let (storage_request, abort) = future::abortable(storage_request);
                        let request_id = sync.add_request(source_id, request_detail, abort);

                        pending_storage_requests
                            .push(async move { (request_id, storage_request.await) });
                    }
                }
            }

            // TODO: handle obsolete requests

            // The sync state machine can be in a few various states. At the time of writing:
            // idle, verifying header, verifying block, verifying grandpa warp sync proof,
            // verifying storage proof.
            // If the state is one of the "verifying" states, perform the actual verification and
            // loop again until the sync is in an idle state.
            loop {
                match sync.process_one() {
                    all::ProcessOne::AllSync(idle) => {
                        sync = idle;
                        break;
                    }
                    all::ProcessOne::VerifyWarpSyncFragment(verify) => {
                        let sender_peer_id = verify.proof_sender().1 .0.clone(); // TODO: unnecessary cloning most of the time

                        let (sync_out, result) = verify.perform();
                        sync = sync_out;

                        if let Err(err) = result {
                            log::warn!(
                                target: &log_target,
                                "Failed to verify warp sync fragment from {}: {}",
                                sender_peer_id,
                                err
                            );
                        }

                        // Verifying a fragment is rather expensive. We yield in order to not
                        // block the entire node.
                        crate::yield_once().await;
                    }
                    all::ProcessOne::VerifyHeader(verify) => {
                        let verified_hash = verify.hash();

                        // Verifying a block is rather expensive. We yield in order to not
                        // block the entire node.
                        crate::yield_once().await;

                        match verify.perform(ffi::unix_time(), ()) {
                            all::HeaderVerifyOutcome::Success {
                                sync: sync_out,
                                is_new_best,
                                is_new_finalized,
                                ..
                            } => {
                                log::debug!(
                                    target: &log_target,
                                    "Successfully verified header {} (new best: {})",
                                    HashDisplay(&verified_hash),
                                    if is_new_best { "yes" } else { "no" }
                                );

                                if is_new_best {
                                    has_new_best = true;
                                }
                                if is_new_finalized {
                                    // It is possible that finalizing this new block has modified
                                    // the best block as well.
                                    // TODO: ^ this is really a footgun; make it clearer in the syncing API
                                    has_new_best = true;
                                    has_new_finalized = true;
                                }

                                // Elements in `all_notifications` are removed one by one and
                                // inserted back if the channel is still open.
                                for index in (0..all_notifications.len()).rev() {
                                    let mut subscription = all_notifications.swap_remove(index);
                                    // TODO: the code below is `O(n)` complexity
                                    let header = sync_out
                                        .non_finalized_blocks_ancestry_order()
                                        .find(|h| h.hash() == verified_hash)
                                        .unwrap();
                                    let notification = Notification::Block(BlockNotification {
                                        is_new_best,
                                        scale_encoded_header: header.scale_encoding_vec(),
                                        parent_hash: *header.parent_hash,
                                    });

                                    if subscription.try_send(notification).is_err() {
                                        continue;
                                    }
                                    if is_new_finalized {
                                        if subscription
                                            .try_send(Notification::Finalized {
                                                hash: verified_hash,
                                                best_block_hash: sync_out.best_block_hash(),
                                            })
                                            .is_err()
                                        {
                                            continue;
                                        }
                                    }
                                    all_notifications.push(subscription);
                                }

                                sync = sync_out;
                                continue;
                            }
                            all::HeaderVerifyOutcome::Error {
                                sync: sync_out,
                                error,
                                ..
                            } => {
                                log::warn!(
                                    target: &log_target,
                                    "Error while verifying header {}: {}",
                                    HashDisplay(&verified_hash),
                                    error
                                );

                                sync = sync_out;
                                continue;
                            }
                        }
                    }

                    // Can't verify header and body in non-full mode.
                    all::ProcessOne::VerifyBodyHeader(_) => unreachable!(),
                }
            }

            // TODO: handle this differently
            if has_new_best {
                has_new_best = false;

                let fut = network_service.set_local_best_block(
                    network_chain_index,
                    sync.best_block_hash(),
                    sync.best_block_number(),
                );
                fut.await;

                // Since this task is verifying blocks, a heavy CPU-only operation, it is very
                // much possible for it to take a long time before having to wait for some event.
                // Since JavaScript/Wasm is single-threaded, this would prevent all the other
                // tasks in the background from running.
                // In order to provide a better granularity, we force a yield after each new serie
                // of verifications.
                crate::yield_once().await;
            }

            // TODO: handle this differently
            if has_new_finalized {
                has_new_finalized = false;

                // If the chain uses GrandPa, the networking has to be kept up-to-date with the
                // state of finalization for other peers to send back relevant gossip messages.
                // (code style) `grandpa_set_id` is extracted first in order to avoid borrowing
                // checker issues.
                let grandpa_set_id =
                    if let chain::chain_information::ChainInformationFinalityRef::Grandpa {
                        after_finalized_block_authorities_set_id,
                        ..
                    } = sync.as_chain_information().as_ref().finality
                    {
                        Some(after_finalized_block_authorities_set_id)
                    } else {
                        None
                    };
                if let Some(set_id) = grandpa_set_id {
                    let commit_finalized_height =
                        u32::try_from(sync.finalized_block_header().number).unwrap(); // TODO: unwrap :-/
                    network_service
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

                // Since this task is verifying blocks, a heavy CPU-only operation, it is very
                // much possible for it to take a long time before having to wait for some event.
                // Since JavaScript/Wasm is single-threaded, this would prevent all the other
                // tasks in the background from running.
                // In order to provide a better granularity, we force a yield after each new serie
                // of verifications.
                crate::yield_once().await;
            }

            // All requests have been started.
            // Now waiting for some event to happen: a network event, a request from the frontend
            // of the sync service, or a request being finished.
            let response_outcome = futures::select! {
                network_event = from_network_service.next() => {
                    // Something happened on the network.

                    let network_event = match network_event {
                        Some(m) => m,
                        None => {
                            // The channel from the network service has been closed. Closing the
                            // sync background task as well.
                            return
                        },
                    };

                    match network_event {
                        network_service::Event::Connected { peer_id, role, chain_index, best_block_number, best_block_hash }
                            if chain_index == network_chain_index =>
                        {
                            let id = sync.add_source((peer_id.clone(), role), best_block_number, best_block_hash);
                            peers_source_id_map.insert(peer_id, id);
                        },
                        network_service::Event::Disconnected { peer_id, chain_index }
                            if chain_index == network_chain_index =>
                        {
                            let id = peers_source_id_map.remove(&peer_id).unwrap();
                            let (_, requests) = sync.remove_source(id);
                            for (_, abort) in requests {
                                abort.abort();
                            }
                        },
                        network_service::Event::BlockAnnounce { chain_index, peer_id, announce }
                            if chain_index == network_chain_index =>
                        {
                            let id = *peers_source_id_map.get(&peer_id).unwrap();
                            let decoded = announce.decode();
                            // TODO: stupid to re-encode header
                            match sync.block_announce(id, decoded.header.scale_encoding_vec(), decoded.is_best) {
                                all::BlockAnnounceOutcome::HeaderVerify |
                                all::BlockAnnounceOutcome::AlreadyInChain => {
                                    log::debug!(
                                        target: &log_target,
                                        "Processed block announce from {}", peer_id
                                    );
                                },
                                all::BlockAnnounceOutcome::Discarded => {
                                    log::debug!(
                                        target: &log_target,
                                        "Processed block announce from {} (discarded)", peer_id
                                    );
                                },
                                all::BlockAnnounceOutcome::Disjoint {} => {
                                    log::debug!(
                                        target: &log_target,
                                        "Processed block announce from {} (disjoint)", peer_id
                                    );
                                },
                                all::BlockAnnounceOutcome::TooOld { announce_block_height, .. } => {
                                    log::warn!(
                                        target: &log_target,
                                        "Block announce header height (#{}) from {} is below finalized block",
                                        announce_block_height, peer_id
                                    );
                                },
                                all::BlockAnnounceOutcome::NotFinalizedChain => {
                                    log::warn!(
                                        target: &log_target,
                                        "Block announce from {} isn't part of finalized chain",
                                        peer_id
                                    );
                                },
                                all::BlockAnnounceOutcome::InvalidHeader(err) => {
                                    log::warn!(
                                        target: &log_target,
                                        "Failed to decode block announce header from {}: {}",
                                        peer_id, err
                                    );
                                },
                            }
                        },
                        network_service::Event::GrandpaCommitMessage { chain_index, message }
                            if chain_index == network_chain_index =>
                        {
                            match sync.grandpa_commit_message(&message.as_encoded()) {
                                Ok(()) => {
                                    has_new_finalized = true;
                                    has_new_best = true;  // TODO: done in case finality changes the best block; make this clearer in the sync layer

                                    // Elements in `all_notifications` are removed one by one and
                                    // inserted back if the channel is still open.
                                    for index in (0..all_notifications.len()).rev() {
                                        let mut subscription = all_notifications.swap_remove(index);
                                        if subscription
                                            .try_send(Notification::Finalized {
                                                hash: sync.finalized_block_header().hash(),
                                                best_block_hash: sync.best_block_hash(),
                                            })
                                            .is_err()
                                        {
                                            continue;
                                        }
                                        all_notifications.push(subscription);
                                    }
                                },
                                Err(err) => {
                                    log::warn!(
                                        target: &log_target,
                                        "Error when verifying GrandPa commit message: {}", err
                                    );
                                }
                            }
                        },
                        _ => {
                            // Different chain index.
                        }
                    }

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

                    match message {
                        ToBackground::IsNearHeadOfChainHeuristic { send_back } => {
                            let _ = send_back.send(sync.is_near_head_of_chain_heuristic());
                        }
                        ToBackground::SubscribeAll { send_back, buffer_size } => {
                            let (tx, new_blocks) = mpsc::channel(buffer_size.saturating_sub(1));
                            all_notifications.push(tx);
                            let _ = send_back.send(SubscribeAll {
                                finalized_block_scale_encoded_header: sync.finalized_block_header().scale_encoding_vec(),
                                non_finalized_blocks_ancestry_order: {
                                    let best_hash = sync.best_block_hash();
                                    sync.non_finalized_blocks_ancestry_order().map(|h| {
                                        let scale_encoding = h.scale_encoding_vec();
                                        BlockNotification {
                                            is_new_best: header::hash_from_scale_encoded_header(&scale_encoding) == best_hash,
                                            scale_encoded_header: scale_encoding,
                                            parent_hash: *h.parent_hash,
                                        }
                                    }).collect()
                                },
                                new_blocks,
                            });
                        }
                        ToBackground::PeersAssumedKnowBlock { send_back, block_number, block_hash } => {
                            let finalized_num = sync.finalized_block_header().number;
                            let outcome = if block_number <= finalized_num {
                                sync.sources()
                                    .filter(|source_id| {
                                        let source_best = sync.source_best_block(*source_id);
                                        source_best.0 > block_number ||
                                            (source_best.0 == block_number && *source_best.1 == block_hash)
                                    })
                                    .map(|id| sync.source_user_data(id).0.clone())
                                    .collect()
                            } else {
                                // As documented, `knows_non_finalized_block` would panic if the
                                // block height was below the one of the known finalized block.
                                sync.knows_non_finalized_block(block_number, &block_hash)
                                    .map(|id| sync.source_user_data(id).0.clone())
                                    .collect()
                            };
                            let _ = send_back.send(outcome);
                        }
                        ToBackground::SyncingPeers { send_back } => {
                            let out = sync.sources()
                                .map(|src| {
                                    let (peer_id, role) = sync.source_user_data(src).clone();
                                    let (height, hash) = sync.source_best_block(src);
                                    (peer_id, role, height, *hash)
                                })
                                .collect::<Vec<_>>();
                            let _ = send_back.send(out);
                        }
                    };

                    continue;
                },

                (request_id, result) = pending_block_requests.select_next_some() => {
                    // A block(s) request has been finished.
                    // `result` is an error if the block request got cancelled by the sync state
                    // machine.
                    if let Ok(result) = result {
                        // Inject the result of the request into the sync state machine.
                        sync.blocks_request_response(
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

                (request_id, result) = pending_grandpa_requests.select_next_some() => {
                    // A GrandPa warp sync request has been finished.
                    // `result` is an error if the block request got cancelled by the sync state
                    // machine.
                    if let Ok(result) = result {
                        // Inject the result of the request into the sync state machine.
                        sync.grandpa_warp_sync_response(
                            request_id,
                            result.ok(),
                        ).1

                    } else {
                        // The sync state machine has emitted a `Action::Cancel` earlier, and is
                        // thus no longer interested in the response.
                        continue;
                    }
                },

                (request_id, result) = pending_storage_requests.select_next_some() => {
                    // A storage request has been finished.
                    // `result` is an error if the block request got cancelled by the sync state
                    // machine.
                    if let Ok(result) = result {
                        // Inject the result of the request into the sync state machine.
                        sync.storage_get_response(
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
                all::ResponseOutcome::WarpSyncFinished => {
                    let finalized_header = sync.finalized_block_header();
                    log::info!(
                        target: &log_target,
                        "GrandPa warp sync finished to #{} ({})",
                        finalized_header.number,
                        HashDisplay(&finalized_header.hash())
                    );
                    has_new_finalized = true;
                    has_new_best = true;
                    // Since there is a gap in the blocks, all active notifications to all blocks
                    // must be cleared.
                    all_notifications.clear();
                }
            }
        }
    }
}
