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

use super::{
    BlockNotification, FinalizedBlockRuntime, Notification, SubscribeAll, ToBackground, paraheads,
};
use crate::{log, network_service, platform::PlatformRef, runtime_service, util};

use alloc::{borrow::Cow, boxed::Box, format, string::String, sync::Arc, vec::Vec};
use core::{cmp, iter, num::NonZero, pin::Pin, time::Duration};
use futures_channel::oneshot;
use futures_lite::FutureExt as _;
use futures_util::{StreamExt as _, future, stream};
use hashbrown::HashMap;
use smoldot::{
    chain, executor, header,
    informant::HashDisplay,
    libp2p,
    network::{self, codec},
    sync::{all, para},
    trie,
};

/// Starts a sync service background task to synchronize a parachain.
///
/// This implementation uses AllSync for block sync with Aura consensus verification,
/// and the paraheads service for relay-chain-based finalization.
pub(super) async fn start_parachain<TPlat: PlatformRef>(
    log_target: String,
    platform: TPlat,
    block_number_bytes: usize,
    relay_chain_sync: Arc<runtime_service::RuntimeService<TPlat>>,
    parachain_id: u32,
    mut from_foreground: Pin<Box<async_channel::Receiver<ToBackground>>>,
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
) {
    // Phase 1: Fetch the current finalized parachain head from the relay chain.
    let effective_chain_info = fetch_parachain_head_from_relay(
        &log_target,
        &platform,
        &relay_chain_sync,
        parachain_id,
        block_number_bytes,
    )
    .await;

    log!(
        &platform,
        Info,
        &log_target,
        format!(
            "Fetched parachain finalized head from relay chain at block #{}",
            effective_chain_info.as_ref().finalized_block_header.number
        )
    );

    // Phase 2: Download the parachain runtime from a P2P peer and determine Aura
    // consensus parameters. Retries indefinitely until successful.
    let effective_chain_info = loop {
        match bootstrap_parachain_consensus(
            &log_target,
            &platform,
            &network_service,
            &effective_chain_info,
            block_number_bytes,
        )
        .await
        {
            Ok(ci) => break ci,
            Err(err) => {
                log!(
                    &platform,
                    Warn,
                    &log_target,
                    format!("Failed to bootstrap parachain consensus: {err}. Retrying in 5s...")
                );
                platform.sleep(Duration::from_secs(5)).await;
            }
        }
    };

    // Phase 3: Spawn the paraheads background service that tracks relay chain
    // finalization and reports finalized parachain blocks.
    let (to_paraheads, from_paraheads) = async_channel::bounded(16);
    let from_paraheads = Box::pin(from_paraheads);

    let paraheads_log_target = format!("{log_target}-paraheads");
    platform.spawn_task(paraheads_log_target.clone().into(), {
        let platform = platform.clone();
        let relay_chain_sync = relay_chain_sync.clone();
        let finalized_header = effective_chain_info
            .as_ref()
            .finalized_block_header
            .scale_encoding_vec(block_number_bytes);
        let task = paraheads::start_paraheads(
            paraheads_log_target.clone(),
            platform.clone(),
            finalized_header,
            relay_chain_sync,
            parachain_id,
            from_paraheads,
        );

        async move {
            task.await;
            log!(
                &platform,
                Debug,
                &paraheads_log_target,
                "paraheads-shutdown"
            );
        }
    });

    // Set up the initial paraheads subscription future.
    let paraheads_subscribe_future: Option<future::BoxFuture<'static, super::SubscribeAll>> = {
        let to_paraheads = to_paraheads.clone();
        Some(Box::pin(async move {
            let (send_back, sub_rx) = oneshot::channel();
            let _ = to_paraheads
                .send(super::ToBackground::SubscribeAll {
                    send_back,
                    buffer_size: 32,
                    runtime_interest: false,
                })
                .await;
            sub_rx.await.unwrap()
        })
            as future::BoxFuture<'static, super::SubscribeAll>)
    };

    // Phase 4: Create AllSync with Aura consensus from the bootstrapped chain information.
    let mut task = Task {
        sync: Some(all::AllSync::new(all::Config {
            chain_information: effective_chain_info,
            block_number_bytes,
            // Parachain blocks include cumulus-specific seals that are
            // not known to smoldot's consensus verification.
            allow_unknown_consensus_engines: true,
            sources_capacity: 32,
            blocks_capacity: {
                // Maximum number of blocks between two finalizations.
                1024
            },
            max_disjoint_headers: 1024,
            max_requests_per_block: NonZero::<u32>::new(3).unwrap(),
            download_ahead_blocks: { NonZero::<u32>::new(5000).unwrap() },
            download_bodies: false,
            download_all_chain_information_storage_proofs: false,
            code_trie_node_hint: None,
        })),
        paraheads: to_paraheads,
        paraheads_subscribe_future,
        paraheads_notifications: None,
        pending_parachain_finalization: None,
        network_up_to_date_best: true,
        known_finalized_runtime: None,
        pending_requests: stream::FuturesUnordered::new(),
        all_notifications: Vec::<async_channel::Sender<Notification>>::new(),
        log_target,
        from_network_service: None,
        network_service,
        peers_source_id_map: HashMap::with_capacity_and_hasher(
            0,
            util::SipHasherBuild::new({
                let mut seed = [0; 16];
                platform.fill_random_bytes(&mut seed);
                seed
            }),
        ),
        platform,
    };

    // Phase 5: Main sync loop.
    loop {
        // Yield at every loop in order to provide better tasks granularity.
        futures_lite::future::yield_now().await;

        enum WakeUpReason {
            SyncProcess(all::ProcessOne<future::AbortHandle, (libp2p::PeerId, codec::Role), ()>),
            MustUpdateNetworkWithBestBlock,
            MustSubscribeNetworkEvents,
            NetworkEvent(network_service::Event),
            ForegroundMessage(ToBackground),
            ForegroundClosed,
            StartRequest(all::SourceId, all::DesiredRequest),
            ObsoleteRequest(all::RequestId),
            RequestFinished(all::RequestId, Result<RequestOutcome, future::Aborted>),
            ParaheadSubscribed(super::SubscribeAll),
            ParaheadNotification(super::Notification),
            ParaheadSubscriptionDead,
        }

        let wake_up_reason = {
            async {
                if let Some(from_network_service) = task.from_network_service.as_mut() {
                    match from_network_service.next().await {
                        Some(ev) => WakeUpReason::NetworkEvent(ev),
                        None => {
                            task.from_network_service = None;
                            WakeUpReason::MustSubscribeNetworkEvents
                        }
                    }
                } else {
                    WakeUpReason::MustSubscribeNetworkEvents
                }
            }
            .or(async {
                from_foreground.next().await.map_or(
                    WakeUpReason::ForegroundClosed,
                    WakeUpReason::ForegroundMessage,
                )
            })
            .or(async {
                if task.pending_requests.is_empty() {
                    future::pending::<()>().await
                }
                let (request_id, result) = task.pending_requests.select_next_some().await;
                WakeUpReason::RequestFinished(request_id, result)
            })
            .or(async { future::pending().await })
            .or(async {
                if !task.network_up_to_date_best {
                    WakeUpReason::MustUpdateNetworkWithBestBlock
                } else {
                    future::pending().await
                }
            })
            .or(async {
                if let Some(subscribe_future) = task.paraheads_subscribe_future.as_mut() {
                    WakeUpReason::ParaheadSubscribed(subscribe_future.await)
                } else {
                    future::pending().await
                }
            })
            .or(async {
                if let Some(notifications) = task.paraheads_notifications.as_mut() {
                    match notifications.recv().await {
                        Ok(notif) => WakeUpReason::ParaheadNotification(notif),
                        Err(_) => WakeUpReason::ParaheadSubscriptionDead,
                    }
                } else {
                    future::pending().await
                }
            })
            .or({
                let sync = &mut task.sync;
                async move {
                    let Some(s) = &sync else { unreachable!() };
                    if let Some((source_id, _, request_detail)) = s
                        .desired_requests()
                        .find(|(source_id, _, _)| s.source_num_ongoing_requests(*source_id) == 0)
                    {
                        return WakeUpReason::StartRequest(source_id, request_detail);
                    }

                    if let Some(request_id) = s.obsolete_requests().next() {
                        return WakeUpReason::ObsoleteRequest(request_id);
                    }

                    // TODO: eventually, process_one() shouldn't take ownership of the AllForks
                    match sync.take().unwrap_or_else(|| unreachable!()).process_one() {
                        all::ProcessOne::AllSync(idle) => {
                            *sync = Some(idle);
                            future::pending().await
                        }
                        other => WakeUpReason::SyncProcess(other),
                    }
                }
            })
            .await
        };

        match wake_up_reason {
            WakeUpReason::SyncProcess(all::ProcessOne::VerifyBlock(verify)) => {
                let verified_hash = verify.hash();
                match verify.verify_header(task.platform.now_from_unix_epoch()) {
                    all::HeaderVerifyOutcome::Success {
                        success,
                        is_new_best,
                        ..
                    } => {
                        let sync = task.sync.insert(success.finish(()));

                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "header-verify-success",
                            hash = HashDisplay(&verified_hash),
                            is_new_best = if is_new_best { "yes" } else { "no" }
                        );

                        if is_new_best {
                            task.network_up_to_date_best = false;
                        }

                        let (parent_hash, scale_encoded_header) = {
                            // TODO: the code below is `O(n)` complexity
                            let header = sync
                                .non_finalized_blocks_unordered()
                                .find(|h| h.hash(sync.block_number_bytes()) == verified_hash)
                                .unwrap();
                            (
                                *header.parent_hash,
                                header.scale_encoding_vec(sync.block_number_bytes()),
                            )
                        };

                        task.dispatch_all_subscribers({
                            Notification::Block(BlockNotification {
                                is_new_best,
                                scale_encoded_header,
                                parent_hash,
                            })
                        });

                        // After verifying a new block, try to apply any pending
                        // parachain finalization from the relay chain.
                        if let Some(pending_hash) = task.pending_parachain_finalization {
                            let sync = task.sync.as_mut().unwrap();
                            if let Ok(result) = sync.set_finalized_block(&pending_hash) {
                                task.pending_parachain_finalization = None;
                                if result.updates_best_block {
                                    task.network_up_to_date_best = false;
                                }
                                if result.finalized_blocks.iter().any(|b| {
                                    header::decode(&b.header, sync.block_number_bytes())
                                        .map(|h| h.digest.has_runtime_environment_updated())
                                        .unwrap_or(false)
                                }) {
                                    task.known_finalized_runtime = None;
                                }
                                task.dispatch_all_subscribers(Notification::Finalized {
                                    hash: pending_hash,
                                    best_block_hash_if_changed: if result.updates_best_block {
                                        Some(*task.sync.as_ref().unwrap().best_block_hash())
                                    } else {
                                        None
                                    },
                                    pruned_blocks: result.pruned_blocks,
                                });
                            }
                        }
                    }

                    all::HeaderVerifyOutcome::Error { sync, error, .. } => {
                        task.sync = Some(sync);

                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "header-verify-error",
                            hash = HashDisplay(&verified_hash),
                            ?error
                        );

                        log!(
                            &task.platform,
                            Warn,
                            &task.log_target,
                            format!(
                                "Error while verifying header {}: {}",
                                HashDisplay(&verified_hash),
                                error
                            )
                        );
                    }
                }
            }

            WakeUpReason::NetworkEvent(network_service::Event::Connected {
                peer_id,
                role,
                best_block_number,
                best_block_hash,
            }) => {
                task.peers_source_id_map.insert(
                    peer_id.clone(),
                    task.sync
                        .as_mut()
                        .unwrap_or_else(|| unreachable!())
                        .prepare_add_source(best_block_number, best_block_hash)
                        .add_source((peer_id, role), ()),
                );
            }

            WakeUpReason::NetworkEvent(network_service::Event::Disconnected { peer_id }) => {
                let sync_source_id = task.peers_source_id_map.remove(&peer_id).unwrap();
                let (_, requests) = task
                    .sync
                    .as_mut()
                    .unwrap_or_else(|| unreachable!())
                    .remove_source(sync_source_id);

                for (_, abort) in requests {
                    abort.abort();
                }
            }

            WakeUpReason::NetworkEvent(network_service::Event::BlockAnnounce {
                peer_id,
                announce,
            }) => {
                let sync_source_id = *task.peers_source_id_map.get(&peer_id).unwrap();
                let decoded = announce.decode();

                match task
                    .sync
                    .as_mut()
                    .unwrap_or_else(|| unreachable!())
                    .block_announce(
                        sync_source_id,
                        decoded.scale_encoded_header.to_owned(),
                        decoded.is_best,
                    ) {
                    all::BlockAnnounceOutcome::TooOld {
                        announce_block_height,
                        ..
                    } => {
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "block-announce",
                            sender = peer_id,
                            hash = HashDisplay(&header::hash_from_scale_encoded_header(
                                decoded.scale_encoded_header
                            )),
                            height = announce_block_height,
                            is_best = decoded.is_best,
                            outcome = "older-than-finalized-block",
                        );
                    }
                    all::BlockAnnounceOutcome::AlreadyVerified(known) => {
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "block-announce",
                            sender = peer_id,
                            hash = HashDisplay(known.hash()),
                            height = known.height(),
                            parent_hash = HashDisplay(known.parent_hash()),
                            is_best = decoded.is_best,
                            outcome = "already-verified",
                        );
                        known.update_source_and_block();
                    }
                    all::BlockAnnounceOutcome::AlreadyPending(known) => {
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "block-announce",
                            sender = peer_id,
                            hash = HashDisplay(known.hash()),
                            height = known.height(),
                            parent_hash = HashDisplay(known.parent_hash()),
                            is_best = decoded.is_best,
                            outcome = "already-pending",
                        );
                        known.update_source_and_block();
                    }
                    all::BlockAnnounceOutcome::Unknown(unknown) => {
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "block-announce",
                            sender = peer_id,
                            hash = HashDisplay(unknown.hash()),
                            height = unknown.height(),
                            parent_hash = HashDisplay(unknown.parent_hash()),
                            is_best = decoded.is_best,
                            outcome = "previously-unknown",
                        );
                        unknown.insert_and_update_source(());
                    }
                    all::BlockAnnounceOutcome::InvalidHeader(error) => {
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "block-announce",
                            sender = peer_id,
                            hash = HashDisplay(&header::hash_from_scale_encoded_header(
                                decoded.scale_encoded_header
                            )),
                            is_best = decoded.is_best,
                            outcome = "invalid-header",
                            ?error,
                        );
                        task.network_service
                            .ban_and_disconnect(
                                peer_id,
                                network_service::BanSeverity::High,
                                "bad-block-announce",
                            )
                            .await;
                    }
                }
            }

            WakeUpReason::MustSubscribeNetworkEvents => {
                debug_assert!(task.from_network_service.is_none());
                for (_, sync_source_id) in task.peers_source_id_map.drain() {
                    let (_, requests) = task
                        .sync
                        .as_mut()
                        .unwrap_or_else(|| unreachable!())
                        .remove_source(sync_source_id);
                    for (_, abort) in requests {
                        abort.abort();
                    }
                }
                task.from_network_service = Some(Box::pin(task.network_service.subscribe().await));
            }

            WakeUpReason::MustUpdateNetworkWithBestBlock => {
                let Some(sync) = &task.sync else {
                    unreachable!()
                };
                let fut = task
                    .network_service
                    .set_local_best_block(*sync.best_block_hash(), sync.best_block_number());
                fut.await;
                task.network_up_to_date_best = true;
            }

            WakeUpReason::ForegroundMessage(ToBackground::IsNearHeadOfChainHeuristic {
                send_back,
            }) => {
                let _ = send_back.send(
                    task.sync
                        .as_ref()
                        .unwrap_or_else(|| unreachable!())
                        .is_near_head_of_chain_heuristic(),
                );
            }

            WakeUpReason::ForegroundMessage(ToBackground::SubscribeAll {
                send_back,
                buffer_size,
                runtime_interest,
            }) => {
                let Some(sync) = &task.sync else {
                    unreachable!()
                };

                let (tx, new_blocks) = async_channel::bounded(buffer_size.saturating_sub(1));
                task.all_notifications.push(tx);

                let non_finalized_blocks_ancestry_order = {
                    sync.non_finalized_blocks_ancestry_order()
                        .map(|h| {
                            let scale_encoding = h.scale_encoding_vec(sync.block_number_bytes());
                            BlockNotification {
                                is_new_best: header::hash_from_scale_encoded_header(
                                    &scale_encoding,
                                ) == *sync.best_block_hash(),
                                scale_encoded_header: scale_encoding,
                                parent_hash: *h.parent_hash,
                            }
                        })
                        .collect()
                };

                let _ = send_back.send(SubscribeAll {
                    finalized_block_scale_encoded_header: sync.finalized_block_header().to_owned(),
                    finalized_block_runtime: if runtime_interest {
                        task.known_finalized_runtime.take()
                    } else {
                        None
                    },
                    non_finalized_blocks_ancestry_order,
                    new_blocks,
                });
            }

            WakeUpReason::ForegroundMessage(ToBackground::PeersAssumedKnowBlock {
                send_back,
                block_number,
                block_hash,
            }) => {
                let Some(sync) = &task.sync else {
                    unreachable!()
                };

                let outcome = if block_number <= sync.finalized_block_number() {
                    sync.sources()
                        .filter(|source_id| {
                            let source_best = sync.source_best_block(*source_id);
                            source_best.0 > block_number
                                || (source_best.0 == block_number && *source_best.1 == block_hash)
                        })
                        .map(|id| sync[id].0.clone())
                        .collect()
                } else {
                    sync.knows_non_finalized_block(block_number, &block_hash)
                        .map(|id| sync[id].0.clone())
                        .collect()
                };

                let _ = send_back.send(outcome);
            }

            WakeUpReason::ForegroundMessage(ToBackground::SyncingPeers { send_back }) => {
                let Some(sync) = &task.sync else {
                    unreachable!()
                };

                let out = sync
                    .sources()
                    .map(|src| {
                        let (peer_id, role) = sync[src].clone();
                        let (height, hash) = sync.source_best_block(src);
                        (peer_id, role, height, *hash)
                    })
                    .collect::<Vec<_>>();

                let _ = send_back.send(out);
            }

            WakeUpReason::ForegroundMessage(ToBackground::SerializeChainInformation {
                send_back,
            }) => {
                let _ = send_back.send(Some(
                    task.sync
                        .as_ref()
                        .unwrap_or_else(|| unreachable!())
                        .as_chain_information()
                        .into(),
                ));
            }

            WakeUpReason::ForegroundClosed => {
                return;
            }

            WakeUpReason::RequestFinished(_, Err(_)) => {
                // A request has been cancelled. Nothing to do.
            }

            WakeUpReason::RequestFinished(request_id, Ok(RequestOutcome::Block(Ok(v)))) => {
                task.sync
                    .as_mut()
                    .unwrap_or_else(|| unreachable!())
                    .blocks_request_response(
                        request_id,
                        v.into_iter().filter_map(|block| {
                            Some(all::BlockRequestSuccessBlock {
                                scale_encoded_header: block.header?,
                                scale_encoded_justifications: Vec::new(),
                                scale_encoded_extrinsics: Vec::new(),
                                user_data: (),
                            })
                        }),
                    );
            }

            WakeUpReason::RequestFinished(request_id, Ok(RequestOutcome::Block(Err(_)))) => {
                let Some(sync) = &mut task.sync else {
                    unreachable!()
                };

                let source_peer_id = sync[sync.request_source_id(request_id)].0.clone();

                task.network_service
                    .ban_and_disconnect(
                        source_peer_id,
                        network_service::BanSeverity::Low,
                        "failed-blocks-request",
                    )
                    .await;

                sync.remove_request(request_id);
            }

            WakeUpReason::RequestFinished(request_id, Ok(RequestOutcome::Storage(Ok(r)))) => {
                let Some(sync) = &mut task.sync else {
                    unreachable!()
                };
                sync.storage_get_response(request_id, r);
            }

            WakeUpReason::RequestFinished(request_id, Ok(RequestOutcome::Storage(Err(_)))) => {
                let Some(sync) = &mut task.sync else {
                    unreachable!()
                };

                task.network_service
                    .ban_and_disconnect(
                        sync[sync.request_source_id(request_id)].0.clone(),
                        network_service::BanSeverity::Low,
                        "failed-storage-request",
                    )
                    .await;

                sync.remove_request(request_id);
            }

            WakeUpReason::RequestFinished(request_id, Ok(RequestOutcome::CallProof(Ok(r)))) => {
                task.sync
                    .as_mut()
                    .unwrap_or_else(|| unreachable!())
                    .call_proof_response(request_id, r.decode().to_owned());
            }

            WakeUpReason::RequestFinished(request_id, Ok(RequestOutcome::CallProof(Err(_)))) => {
                let Some(sync) = &mut task.sync else {
                    unreachable!()
                };

                task.network_service
                    .ban_and_disconnect(
                        sync[sync.request_source_id(request_id)].0.clone(),
                        network_service::BanSeverity::Low,
                        "failed-call-proof-request",
                    )
                    .await;

                sync.remove_request(request_id);
            }

            WakeUpReason::ObsoleteRequest(request_id) => {
                let Some(sync) = &mut task.sync else {
                    unreachable!()
                };
                let abort_handle = sync.remove_request(request_id);
                abort_handle.abort();
            }

            WakeUpReason::StartRequest(
                source_id,
                all::DesiredRequest::BlocksRequest {
                    first_block_hash,
                    first_block_height,
                    num_blocks,
                    request_headers,
                    request_bodies,
                    request_justification: _,
                },
            ) => {
                let Some(sync) = &mut task.sync else {
                    unreachable!()
                };

                let num_blocks = NonZero::<u64>::new(cmp::min(64, num_blocks.get())).unwrap();
                let peer_id = sync[source_id].0.clone();

                let block_request = task.network_service.clone().blocks_request(
                    peer_id,
                    network::codec::BlocksRequestConfig {
                        start: network::codec::BlocksRequestConfigStart::Hash(first_block_hash),
                        desired_count: NonZero::<u32>::new(
                            u32::try_from(num_blocks.get()).unwrap_or(u32::MAX),
                        )
                        .unwrap(),
                        direction: network::codec::BlocksRequestDirection::Descending,
                        fields: network::codec::BlocksRequestFields {
                            header: request_headers,
                            body: request_bodies,
                            justifications: false,
                        },
                    },
                    Duration::from_secs(10),
                );

                let (block_request, abort) = future::abortable(block_request);
                let request_id = sync.add_request(
                    source_id,
                    all::RequestDetail::BlocksRequest {
                        first_block_hash,
                        first_block_height,
                        num_blocks,
                        request_headers,
                        request_bodies,
                        request_justification: false,
                    },
                    abort,
                );

                task.pending_requests.push(Box::pin(async move {
                    (request_id, block_request.await.map(RequestOutcome::Block))
                }));
            }

            WakeUpReason::StartRequest(
                source_id,
                all::DesiredRequest::StorageGetMerkleProof {
                    block_hash, keys, ..
                },
            ) => {
                let Some(sync) = &mut task.sync else {
                    unreachable!()
                };

                let peer_id = sync[source_id].0.clone();

                let storage_request = task.network_service.clone().storage_proof_request(
                    peer_id,
                    network::codec::StorageProofRequestConfig {
                        block_hash,
                        keys: keys.clone().into_iter(),
                    },
                    Duration::from_secs(16),
                );

                let storage_request = async move {
                    if let Ok(outcome) = storage_request.await {
                        Ok(outcome.decode().to_vec())
                    } else {
                        Err(())
                    }
                };

                let (storage_request, abort) = future::abortable(storage_request);
                let request_id = sync.add_request(
                    source_id,
                    all::RequestDetail::StorageGet { block_hash, keys },
                    abort,
                );

                task.pending_requests.push(Box::pin(async move {
                    (
                        request_id,
                        storage_request.await.map(RequestOutcome::Storage),
                    )
                }));
            }

            WakeUpReason::StartRequest(
                source_id,
                all::DesiredRequest::RuntimeCallMerkleProof {
                    block_hash,
                    function_name,
                    parameter_vectored,
                },
            ) => {
                let Some(sync) = &mut task.sync else {
                    unreachable!()
                };

                let peer_id = sync[source_id].0.clone();

                let call_proof_request = {
                    let network_service = task.network_service.clone();
                    let parameter_vectored = parameter_vectored.clone();
                    let function_name = function_name.clone();
                    async move {
                        let rq = network_service.call_proof_request(
                            peer_id,
                            network::codec::CallProofRequestConfig {
                                block_hash,
                                method: Cow::Borrowed(&*function_name),
                                parameter_vectored: iter::once(&parameter_vectored),
                            },
                            Duration::from_secs(16),
                        );

                        match rq.await {
                            Ok(p) => Ok(p),
                            Err(_) => Err(()),
                        }
                    }
                };

                let (call_proof_request, abort) = future::abortable(call_proof_request);
                let request_id = sync.add_request(
                    source_id,
                    all::RequestDetail::RuntimeCallMerkleProof {
                        block_hash,
                        function_name,
                        parameter_vectored,
                    },
                    abort,
                );

                task.pending_requests.push(Box::pin(async move {
                    (
                        request_id,
                        call_proof_request.await.map(RequestOutcome::CallProof),
                    )
                }));
            }

            // Paraheads integration: relay chain finalization
            WakeUpReason::ParaheadSubscribed(subscribe_all) => {
                task.paraheads_subscribe_future = None;

                log!(
                    &task.platform,
                    Debug,
                    &task.log_target,
                    "paraheads-subscribed",
                    finalized_hash = HashDisplay(&header::hash_from_scale_encoded_header(
                        &subscribe_all.finalized_block_scale_encoded_header
                    )),
                );

                // Try to apply the initial finalized parachain head.
                let finalized_hash = header::hash_from_scale_encoded_header(
                    &subscribe_all.finalized_block_scale_encoded_header,
                );
                let sync = task.sync.as_mut().unwrap();
                match sync.set_finalized_block(&finalized_hash) {
                    Ok(result) => {
                        task.pending_parachain_finalization = None;
                        if result.updates_best_block {
                            task.network_up_to_date_best = false;
                        }
                        if result.finalized_blocks.iter().any(|b| {
                            header::decode(&b.header, sync.block_number_bytes())
                                .map(|h| h.digest.has_runtime_environment_updated())
                                .unwrap_or(false)
                        }) {
                            task.known_finalized_runtime = None;
                        }
                        task.dispatch_all_subscribers(Notification::Finalized {
                            hash: finalized_hash,
                            best_block_hash_if_changed: if result.updates_best_block {
                                Some(*task.sync.as_ref().unwrap().best_block_hash())
                            } else {
                                None
                            },
                            pruned_blocks: result.pruned_blocks,
                        });
                    }
                    Err(_) => {
                        // Block not yet synced — store as pending.
                        task.pending_parachain_finalization = Some(finalized_hash);
                    }
                }

                task.paraheads_notifications = Some(subscribe_all.new_blocks);
            }

            WakeUpReason::ParaheadNotification(Notification::Finalized {
                hash,
                best_block_hash_if_changed: _,
                pruned_blocks: _,
            }) => {
                log!(
                    &task.platform,
                    Debug,
                    &task.log_target,
                    "paraheads-finalized",
                    hash = HashDisplay(&hash),
                );

                let sync = task.sync.as_mut().unwrap();
                match sync.set_finalized_block(&hash) {
                    Ok(result) => {
                        task.pending_parachain_finalization = None;
                        if result.updates_best_block {
                            task.network_up_to_date_best = false;
                        }
                        if result.finalized_blocks.iter().any(|b| {
                            header::decode(&b.header, sync.block_number_bytes())
                                .map(|h| h.digest.has_runtime_environment_updated())
                                .unwrap_or(false)
                        }) {
                            task.known_finalized_runtime = None;
                        }
                        task.dispatch_all_subscribers(Notification::Finalized {
                            hash,
                            best_block_hash_if_changed: if result.updates_best_block {
                                Some(*task.sync.as_ref().unwrap().best_block_hash())
                            } else {
                                None
                            },
                            pruned_blocks: result.pruned_blocks,
                        });
                    }
                    Err(_) => {
                        // Block not yet synced — store as pending.
                        task.pending_parachain_finalization = Some(hash);
                    }
                }
            }

            WakeUpReason::ParaheadNotification(
                Notification::Block(_) | Notification::BestBlockChanged { .. },
            ) => {
                // AllSync discovers blocks through the P2P network, not from
                // paraheads. We only use paraheads for finalization.
            }

            WakeUpReason::ParaheadSubscriptionDead => {
                log!(
                    &task.platform,
                    Debug,
                    &task.log_target,
                    "paraheads-subscription-reset"
                );
                task.paraheads_notifications = None;
                let to_paraheads = task.paraheads.clone();
                task.paraheads_subscribe_future = Some(Box::pin(async move {
                    let (send_back, sub_rx) = oneshot::channel();
                    let _ = to_paraheads
                        .send(super::ToBackground::SubscribeAll {
                            send_back,
                            buffer_size: 32,
                            runtime_interest: false,
                        })
                        .await;
                    sub_rx.await.unwrap()
                }));
            }

            // Unreachable variants - parachains don't use warp sync, finality proofs, or Grandpa
            WakeUpReason::NetworkEvent(
                network_service::Event::GrandpaNeighborPacket { .. }
                | network_service::Event::GrandpaCommitMessage { .. },
            )
            | WakeUpReason::SyncProcess(
                all::ProcessOne::AllSync(_)
                | all::ProcessOne::WarpSyncBuildRuntime(_)
                | all::ProcessOne::WarpSyncBuildChainInformation(_)
                | all::ProcessOne::WarpSyncFinished { .. }
                | all::ProcessOne::VerifyWarpSyncFragment(_)
                | all::ProcessOne::VerifyFinalityProof(_),
            )
            | WakeUpReason::StartRequest(_, all::DesiredRequest::WarpSync { .. }) => {
                unreachable!()
            }
        }
    }
}

struct Task<TPlat: PlatformRef> {
    log_target: String,
    platform: TPlat,

    /// Main syncing state machine. Always `Some`, except for temporary extraction.
    sync: Option<all::AllSync<future::AbortHandle, (libp2p::PeerId, codec::Role), ()>>,

    /// If `Some`, contains the runtime of the current finalized block.
    known_finalized_runtime: Option<FinalizedBlockRuntime>,

    /// For each networking peer, the index of the corresponding peer within the sync.
    peers_source_id_map: HashMap<libp2p::PeerId, all::SourceId, util::SipHasherBuild>,

    network_up_to_date_best: bool,

    /// Channel to the paraheads background service.
    paraheads: async_channel::Sender<super::ToBackground>,
    /// Future for subscribing to paraheads. `None` if already subscribed.
    paraheads_subscribe_future: Option<future::BoxFuture<'static, super::SubscribeAll>>,
    /// Notification stream from the paraheads service. `None` if not subscribed yet.
    paraheads_notifications: Option<async_channel::Receiver<super::Notification>>,
    /// Pending finalized parachain block hash from relay chain that hasn't been
    /// applied yet because the block wasn't synced at the time.
    pending_parachain_finalization: Option<[u8; 32]>,

    all_notifications: Vec<async_channel::Sender<Notification>>,

    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
    from_network_service: Option<Pin<Box<async_channel::Receiver<network_service::Event>>>>,

    pending_requests: stream::FuturesUnordered<
        future::BoxFuture<'static, (all::RequestId, Result<RequestOutcome, future::Aborted>)>,
    >,
}

enum RequestOutcome {
    Block(Result<Vec<codec::BlockData>, network_service::BlocksRequestError>),
    Storage(Result<Vec<u8>, ()>),
    CallProof(Result<network::service::EncodedMerkleProof, ()>),
}

impl<TPlat: PlatformRef> Task<TPlat> {
    fn dispatch_all_subscribers(&mut self, notification: Notification) {
        for index in (0..self.all_notifications.len()).rev() {
            let subscription = self.all_notifications.swap_remove(index);
            if subscription.try_send(notification.clone()).is_err() {
                if !subscription.is_closed() {
                    self.all_notifications.push(subscription);
                }
                continue;
            }

            self.all_notifications.push(subscription);
        }
    }
}

// Fetch the included parachain head from a finalized relay chain block.
async fn fetch_parachain_head_from_relay<TPlat: PlatformRef>(
    log_target: &str,
    platform: &TPlat,
    relay_chain_sync: &Arc<runtime_service::RuntimeService<TPlat>>,
    para_id: u32,
    block_number_bytes: usize,
) -> chain::chain_information::ValidChainInformation {
    let mut subscription = relay_chain_sync
        .subscribe_all(32, NonZero::<usize>::new(usize::MAX).unwrap())
        .await;

    log!(
        platform,
        Info,
        log_target,
        "Waiting for relay chain to finalize a block..."
    );

    loop {
        let finalized_hash = loop {
            match subscription.new_blocks.next().await {
                Some(runtime_service::Notification::Finalized { hash, .. }) => {
                    break hash;
                }
                Some(_) => continue,
                None => {
                    // Subscription died. Re-subscribe.
                    subscription = relay_chain_sync
                        .subscribe_all(32, NonZero::<usize>::new(usize::MAX).unwrap())
                        .await;
                    break header::hash_from_scale_encoded_header(
                        &subscription.finalized_block_scale_encoded_header,
                    );
                }
            }
        };

        log!(
            platform,
            Debug,
            log_target,
            format!(
                "Trying to fetch parachain head from relay block {}",
                HashDisplay(&finalized_hash)
            )
        );

        let pinned = relay_chain_sync
            .pin_pinned_block_runtime(subscription.new_blocks.id(), finalized_hash)
            .await;
        let (pinned_runtime, block_state_trie_root, block_number) = match pinned {
            Ok(v) => v,
            Err(_) => continue,
        };

        let call_result = relay_chain_sync
            .runtime_call(
                pinned_runtime,
                finalized_hash,
                block_number,
                block_state_trie_root,
                para::PERSISTED_VALIDATION_FUNCTION_NAME.to_owned(),
                None,
                para::persisted_validation_data_parameters(
                    para_id,
                    para::OccupiedCoreAssumption::TimedOut,
                )
                .fold(Vec::new(), |mut a, b| {
                    a.extend_from_slice(b.as_ref());
                    a
                }),
                6,
                Duration::from_secs(20),
                NonZero::<u32>::new(2).unwrap(),
            )
            .await;
        let success = match call_result {
            Ok(s) => s,
            Err(_) => continue,
        };

        let pvd = match para::decode_persisted_validation_data_return_value(
            &success.output,
            relay_chain_sync.block_number_bytes(),
        ) {
            Ok(Some(pvd)) => pvd,
            _ => continue,
        };

        let parachain_header_bytes = pvd.parent_head.to_vec();
        let decoded_header = header::decode(&parachain_header_bytes, block_number_bytes).unwrap();

        log!(
            platform,
            Info,
            log_target,
            format!(
                "Got parachain head from relay chain: block #{}, hash {}",
                decoded_header.number,
                HashDisplay(&header::hash_from_scale_encoded_header(
                    &parachain_header_bytes
                ))
            )
        );

        let chain_info = chain::chain_information::ChainInformation {
            finalized_block_header: Box::new(decoded_header.into()),
            consensus: chain::chain_information::ChainInformationConsensus::Unknown,
            finality: chain::chain_information::ChainInformationFinality::Outsourced,
        };

        return chain::chain_information::ValidChainInformation::try_from(chain_info)
            .expect("parachain head from relay chain must be valid");
    }
}

/// Downloads the parachain runtime from a P2P peer and determines Aura consensus parameters.
async fn bootstrap_parachain_consensus<TPlat: PlatformRef>(
    log_target: &str,
    platform: &TPlat,
    network_service: &Arc<network_service::NetworkServiceChain<TPlat>>,
    chain_info: &chain::chain_information::ValidChainInformation,
    block_number_bytes: usize,
) -> Result<chain::chain_information::ValidChainInformation, String> {
    let ci_ref = chain_info.as_ref();
    let state_root = *ci_ref.finalized_block_header.state_root;
    let block_hash = ci_ref.finalized_block_header.hash(block_number_bytes);

    log!(
        platform,
        Info,
        log_target,
        format!(
            "Bootstrapping parachain consensus from block #{} ({})",
            ci_ref.finalized_block_header.number,
            HashDisplay(&block_hash)
        )
    );

    // Wait for a peer to connect.
    let peer_id = {
        let mut from_network = Box::pin(network_service.subscribe().await);

        if let Some(peer) = network_service.peers_list().await.next() {
            peer
        } else {
            loop {
                match from_network.next().await {
                    Some(network_service::Event::Connected { peer_id, .. }) => break peer_id,
                    Some(_) => continue,
                    None => {
                        from_network = Box::pin(network_service.subscribe().await);
                    }
                }
            }
        }
    };

    log!(
        platform,
        Info,
        log_target,
        format!("Downloading parachain runtime from peer {peer_id}")
    );

    // Download :code and :heappages.
    let proof = network_service
        .clone()
        .storage_proof_request(
            peer_id.clone(),
            codec::StorageProofRequestConfig {
                block_hash,
                keys: [&b":code"[..], &b":heappages"[..]].into_iter(),
            },
            Duration::from_secs(60),
        )
        .await
        .map_err(|e| format!("Storage proof request failed: {e}"))?;

    let decoded_proof = trie::proof_decode::decode_and_verify_proof(trie::proof_decode::Config {
        proof: proof.decode().to_vec(),
    })
    .map_err(|e| format!("Failed to decode storage proof: {e}"))?;

    let code = decoded_proof
        .storage_value(&state_root, b":code")
        .map_err(|_| "Proof doesn't contain :code".to_owned())?
        .ok_or_else(|| "Runtime :code not found in storage".to_owned())?
        .0
        .to_vec();

    let heap_pages_raw = decoded_proof
        .storage_value(&state_root, b":heappages")
        .map_err(|_| "Proof doesn't contain :heappages".to_owned())?;

    let heap_pages = executor::storage_heap_pages_to_value(heap_pages_raw.map(|(v, _)| v))
        .map_err(|e| format!("Invalid :heappages value: {e}"))?;

    log!(
        platform,
        Info,
        log_target,
        format!(
            "Downloaded parachain runtime ({} bytes), compiling...",
            code.len()
        )
    );

    let mut vm = executor::host::HostVmPrototype::new(executor::host::Config {
        module: &code,
        heap_pages,
        exec_hint: executor::vm::ExecHint::CompileWithNonDeterministicValidation,
        allow_unresolved_imports: true,
    })
    .map_err(|e| format!("Failed to compile runtime: {e}"))?;

    // AuraApi_slot_duration
    let slot_duration = {
        let call_proof = network_service
            .clone()
            .call_proof_request(
                peer_id.clone(),
                codec::CallProofRequestConfig {
                    block_hash,
                    method: Cow::Borrowed("AuraApi_slot_duration"),
                    parameter_vectored: iter::empty::<Vec<u8>>(),
                },
                Duration::from_secs(16),
            )
            .await
            .map_err(|e| format!("AuraApi_slot_duration call proof request failed: {e}"))?;

        let decoded_call_proof =
            trie::proof_decode::decode_and_verify_proof(trie::proof_decode::Config {
                proof: call_proof.decode().to_vec(),
            })
            .map_err(|e| format!("Failed to decode slot_duration call proof: {e}"))?;

        let output = run_single_runtime_call(
            vm,
            "AuraApi_slot_duration",
            &decoded_call_proof,
            &state_root,
        )?;

        // Recompile the VM for the next call.
        vm = executor::host::HostVmPrototype::new(executor::host::Config {
            module: &code,
            heap_pages,
            exec_hint: executor::vm::ExecHint::CompileWithNonDeterministicValidation,
            allow_unresolved_imports: true,
        })
        .map_err(|e| format!("Failed to recompile runtime: {e}"))?;

        <[u8; 8]>::try_from(output.as_slice())
            .ok()
            .and_then(|b| NonZero::<u64>::new(u64::from_le_bytes(b)))
            .ok_or_else(|| "Failed to decode AuraApi_slot_duration output".to_owned())?
    };

    // AuraApi_authorities
    let authorities = {
        let call_proof = network_service
            .clone()
            .call_proof_request(
                peer_id,
                codec::CallProofRequestConfig {
                    block_hash,
                    method: Cow::Borrowed("AuraApi_authorities"),
                    parameter_vectored: iter::empty::<Vec<u8>>(),
                },
                Duration::from_secs(16),
            )
            .await
            .map_err(|e| format!("AuraApi_authorities call proof request failed: {e}"))?;

        let decoded_call_proof =
            trie::proof_decode::decode_and_verify_proof(trie::proof_decode::Config {
                proof: call_proof.decode().to_vec(),
            })
            .map_err(|e| format!("Failed to decode authorities call proof: {e}"))?;

        let output =
            run_single_runtime_call(vm, "AuraApi_authorities", &decoded_call_proof, &state_root)?;

        header::AuraAuthoritiesIter::decode(&output)
            .map_err(|_| "Failed to decode AuraApi_authorities output".to_owned())?
            .map(header::AuraAuthority::from)
            .collect::<Vec<_>>()
    };

    log!(
        platform,
        Info,
        log_target,
        format!(
            "Parachain uses Aura consensus (slot_duration={}ms, authorities={})",
            slot_duration,
            authorities.len()
        )
    );

    let new_chain_info = chain::chain_information::ChainInformation {
        finalized_block_header: Box::new(ci_ref.finalized_block_header.into()),
        consensus: chain::chain_information::ChainInformationConsensus::Aura {
            finalized_authorities_list: authorities,
            slot_duration,
        },
        finality: chain::chain_information::ChainInformationFinality::Outsourced,
    };

    chain::chain_information::ValidChainInformation::try_from(new_chain_info)
        .map_err(|e| format!("Invalid chain information: {e}"))
}

/// Runs a single runtime call, serving storage reads from the given proof.
fn run_single_runtime_call(
    vm: executor::host::HostVmPrototype,
    function_name: &str,
    proof: &trie::proof_decode::DecodedTrieProof<Vec<u8>>,
    state_root: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let mut call = executor::runtime_call::run(executor::runtime_call::Config {
        virtual_machine: vm,
        function_to_call: function_name,
        parameter: iter::empty::<Vec<u8>>(),
        storage_main_trie_changes: Default::default(),
        storage_proof_size_behavior:
            executor::runtime_call::StorageProofSizeBehavior::proof_recording_disabled(),
        max_log_level: 0,
        calculate_trie_changes: false,
    })
    .map_err(|(err, _)| format!("Failed to start {function_name}: {err}"))?;

    loop {
        match call {
            executor::runtime_call::RuntimeCall::Finished(Ok(success)) => {
                let output = success.virtual_machine.value().as_ref().to_vec();
                return Ok(output);
            }
            executor::runtime_call::RuntimeCall::Finished(Err(err)) => {
                return Err(format!("{function_name} execution error: {}", err.detail));
            }
            executor::runtime_call::RuntimeCall::StorageGet(get) => {
                let child_trie = get.child_trie().map(|c| c.as_ref().to_owned());
                let trie_root = if let Some(child_trie) = &child_trie {
                    const PREFIX: &[u8] = b":child_storage:default:";
                    let mut key = Vec::with_capacity(PREFIX.len() + child_trie.len());
                    key.extend_from_slice(PREFIX);
                    key.extend_from_slice(child_trie);
                    match proof.storage_value(state_root, &key) {
                        Ok(Some((value, _))) => match <&[u8; 32]>::try_from(value) {
                            Ok(hash) => Some(*hash),
                            Err(_) => {
                                return Err(format!("{function_name}: invalid child trie root"));
                            }
                        },
                        Ok(None) => None,
                        Err(_) => {
                            return Err(format!("{function_name}: proof missing child trie root"));
                        }
                    }
                } else {
                    Some(*state_root)
                };

                let storage_value = if let Some(trie_root) = &trie_root {
                    proof.storage_value(trie_root, get.key().as_ref())
                } else {
                    Ok(None)
                };
                let Ok(storage_value) = storage_value else {
                    return Err(format!("{function_name}: proof missing entry for key"));
                };
                call = get.inject_value(storage_value.map(|(val, vers)| (iter::once(val), vers)));
            }
            executor::runtime_call::RuntimeCall::ClosestDescendantMerkleValue(mv) => {
                let merkle_value = proof.closest_descendant_merkle_value(state_root, mv.key());
                let Ok(merkle_value) = merkle_value else {
                    return Err(format!("{function_name}: proof missing merkle value"));
                };
                call = mv.inject_merkle_value(merkle_value);
            }
            executor::runtime_call::RuntimeCall::NextKey(nk) => {
                let next_key = proof.next_key(
                    state_root,
                    nk.key(),
                    nk.or_equal(),
                    nk.prefix(),
                    nk.branch_nodes(),
                );
                let Ok(next_key) = next_key else {
                    return Err(format!("{function_name}: proof missing next key"));
                };
                call = nk.inject_key(next_key);
            }
            executor::runtime_call::RuntimeCall::SignatureVerification(sig) => {
                call = sig.verify_and_resume();
            }
            executor::runtime_call::RuntimeCall::LogEmit(log) => {
                call = log.resume();
            }
            executor::runtime_call::RuntimeCall::OffchainStorageSet(req) => {
                call = req.resume();
            }
            executor::runtime_call::RuntimeCall::Offchain(_) => {
                return Err(format!("{function_name}: forbidden offchain host function"));
            }
        }
    }
}
