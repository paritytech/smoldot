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
    BlockNotification, ConfigSubstrateCompatibleRuntimeCodeHint, FinalizedBlockRuntime,
    Notification, SubscribeAll, ToBackground,
};
use crate::{log, network_service, platform::PlatformRef, util};

use alloc::{
    borrow::{Cow, ToOwned as _},
    boxed::Box,
    format,
    string::String,
    sync::Arc,
    vec::Vec,
};
use core::{cmp, iter, num::NonZero, pin::Pin, time::Duration};
use futures_lite::FutureExt as _;
use futures_util::{FutureExt as _, StreamExt as _, future, stream};
use hashbrown::HashMap;
use smoldot::{
    chain, header,
    informant::HashDisplay,
    libp2p,
    network::{self, codec},
    sync::all,
};

/// Starts a sync service background task to synchronize a chain (relay chain or not) that is
/// built with Substrate.
pub(super) async fn start_substrate_compatible_chain<TPlat: PlatformRef>(
    log_target: String,
    platform: TPlat,
    chain_information: chain::chain_information::ValidChainInformation,
    block_number_bytes: usize,
    runtime_code_hint: Option<ConfigSubstrateCompatibleRuntimeCodeHint>,
    mut from_foreground: Pin<Box<async_channel::Receiver<ToBackground>>>,
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
) {
    let mut task = Task {
        sync: Some(all::AllSync::new(all::Config {
            chain_information,
            block_number_bytes,
            // Since this module doesn't verify block bodies, any block (even invalid) is accepted
            // as long as it comes from a legitimate validator. Consequently, validators could
            // perform attacks by sending completely invalid blocks. Passing `false` to this
            // option would tighten the definition of what a "legitimate" validator is, and thus
            // reduce the feasibility of attacks, but not in a significant way. Passing `true`,
            // on the other hand, allows supporting chains that use custom consensus engines,
            // which is considered worth the trade-off.
            allow_unknown_consensus_engines: true,
            sources_capacity: 32,
            blocks_capacity: {
                // This is the maximum number of blocks between two consecutive justifications.
                1024
            },
            max_disjoint_headers: 1024,
            max_requests_per_block: NonZero::<u32>::new(3).unwrap(),
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
                NonZero::<u32>::new(5000).unwrap()
            },
            download_bodies: false,
            download_all_chain_information_storage_proofs: false,
            code_trie_node_hint: runtime_code_hint.map(|hint| all::ConfigCodeTrieNodeHint {
                merkle_value: hint.merkle_value,
                storage_value: hint.storage_value,
                closest_ancestor_excluding: hint.closest_ancestor_excluding,
            }),
        })),
        network_up_to_date_best: true,
        network_up_to_date_finalized: true,
        known_finalized_runtime: None,
        pending_requests: stream::FuturesUnordered::new(),
        warp_sync_taking_long_time_warning: future::Either::Left(Box::pin(
            platform.sleep(Duration::from_secs(10)),
        ))
        .fuse(),
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

    // Main loop of the syncing logic.
    //
    // This loop contains some CPU-heavy operations (e.g. verifying finality proofs and warp sync
    // proofs) but also responding to messages sent by the foreground sync service. In order to
    // avoid long delays in responding to foreground messages, the CPU-heavy operations are split
    // into small chunks, and each iteration of the loop processes at most one of these chunks and
    // processes one foreground message.
    loop {
        // Yield at every loop in order to provide better tasks granularity.
        futures_lite::future::yield_now().await;

        // Now waiting for some event to happen: a network event, a request from the frontend
        // of the sync service, or a request being finished.
        enum WakeUpReason {
            SyncProcess(all::ProcessOne<future::AbortHandle, (libp2p::PeerId, codec::Role), ()>),
            MustUpdateNetworkWithBestBlock,
            MustUpdateNetworkWithFinalizedBlock,
            MustSubscribeNetworkEvents,
            NetworkEvent(network_service::Event),
            ForegroundMessage(ToBackground),
            ForegroundClosed,
            StartRequest(all::SourceId, all::DesiredRequest),
            ObsoleteRequest(all::RequestId),
            RequestFinished(all::RequestId, Result<RequestOutcome, future::Aborted>),
            WarpSyncTakingLongTimeWarning,
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
            .or(async {
                if !task.network_up_to_date_finalized {
                    WakeUpReason::MustUpdateNetworkWithFinalizedBlock
                } else {
                    future::pending().await
                }
            })
            .or(async {
                if !task.network_up_to_date_best {
                    WakeUpReason::MustUpdateNetworkWithBestBlock
                } else {
                    future::pending().await
                }
            })
            .or(async {
                (&mut task.warp_sync_taking_long_time_warning).await;
                task.warp_sync_taking_long_time_warning =
                    future::Either::Left(Box::pin(task.platform.sleep(Duration::from_secs(10))))
                        .fuse();
                WakeUpReason::WarpSyncTakingLongTimeWarning
            })
            .or({
                let sync = &mut task.sync;
                async move {
                    // `desired_requests()` returns, in decreasing order of priority, the requests
                    // that should be started in order for the syncing to proceed. The fact that
                    // multiple requests are returned could be used to filter out undesired one. We
                    // use this filtering to enforce a maximum of one ongoing request per source.
                    let Some(s) = &sync else { unreachable!() };
                    if let Some((source_id, _, request_detail)) = s
                        .desired_requests()
                        .find(|(source_id, _, _)| s.source_num_ongoing_requests(*source_id) == 0)
                    {
                        return WakeUpReason::StartRequest(source_id, request_detail);
                    }

                    // There might be requests that are no longer necessary for a reason or
                    // another.
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
            WakeUpReason::SyncProcess(all::ProcessOne::AllSync(_)) => {
                // Shouldn't be reachable.
                unreachable!()
            }

            WakeUpReason::SyncProcess(all::ProcessOne::WarpSyncBuildRuntime(req)) => {
                // Warp syncing compiles the runtime. The compiled runtime will later be yielded
                // in the `WarpSyncFinished` variant, which is then provided as an event.
                let before_instant = task.platform.now();
                // Because the runtime being compiled has been validated by 2/3rds of the
                // validators of the chain, we can assume that it is valid. Doing so significantly
                // increases the compilation speed.
                let (new_sync, error) =
                    req.build(all::ExecHint::CompileWithNonDeterministicValidation, true);
                let elapsed = task.platform.now() - before_instant;
                match error {
                    Ok(()) => {
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "warp-sync-runtime-build-success",
                            success = ?true,
                            duration = ?elapsed
                        );
                    }
                    Err(error) => {
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "warp-sync-runtime-build-error",
                            ?error
                        );
                        if !matches!(error, all::WarpSyncBuildRuntimeError::SourceMisbehavior(_)) {
                            log!(
                                &task.platform,
                                Debug,
                                &task.log_target,
                                format!(
                                    "Failed to compile runtime during warp syncing process: {}",
                                    error
                                )
                            );
                        }
                    }
                };
                task.sync = Some(new_sync);
            }

            WakeUpReason::SyncProcess(all::ProcessOne::WarpSyncBuildChainInformation(req)) => {
                let (new_sync, error) = req.build();
                match error {
                    Ok(()) => {
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "warp-sync-chain-information-build-success"
                        );
                    }
                    Err(error) => {
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "warp-sync-chain-information-build-error",
                            ?error
                        );
                        if !matches!(
                            error,
                            all::WarpSyncBuildChainInformationError::SourceMisbehavior(_)
                        ) {
                            log!(
                                &task.platform,
                                Warn,
                                &task.log_target,
                                format!(
                                    "Failed to build the chain information during warp syncing process: {}",
                                    error
                                )
                            );
                        }
                    }
                };
                task.sync = Some(new_sync);
            }

            WakeUpReason::SyncProcess(all::ProcessOne::WarpSyncFinished {
                sync,
                finalized_block_runtime,
                finalized_storage_code,
                finalized_storage_code_closest_ancestor_excluding,
                finalized_storage_heap_pages,
                finalized_storage_code_merkle_value,
                finalized_body: _,
            }) => {
                log!(
                    &task.platform,
                    Debug,
                    &task.log_target,
                    format!(
                        "GrandPa warp sync finished to #{} ({})",
                        sync.finalized_block_number(),
                        HashDisplay(sync.finalized_block_hash())
                    )
                );

                task.sync = Some(sync);

                task.warp_sync_taking_long_time_warning =
                    future::Either::Right(future::pending()).fuse();

                task.known_finalized_runtime = Some(FinalizedBlockRuntime {
                    virtual_machine: finalized_block_runtime,
                    storage_code: finalized_storage_code,
                    storage_heap_pages: finalized_storage_heap_pages,
                    code_merkle_value: finalized_storage_code_merkle_value,
                    closest_ancestor_excluding: finalized_storage_code_closest_ancestor_excluding,
                });

                task.network_up_to_date_finalized = false;
                task.network_up_to_date_best = false;
                // Since there is a gap in the blocks, all active notifications to all blocks
                // must be cleared.
                task.all_notifications.clear();
            }

            WakeUpReason::SyncProcess(all::ProcessOne::VerifyWarpSyncFragment(verify)) => {
                // Grandpa warp sync fragment to verify.
                let sender_if_still_connected = verify
                    .proof_sender()
                    .map(|(_, (peer_id, _))| peer_id.clone());

                let (sync, result) = verify.perform({
                    let mut seed = [0; 32];
                    task.platform.fill_random_bytes(&mut seed);
                    seed
                });
                task.sync = Some(sync);

                match result {
                    Ok((fragment_hash, fragment_number)) => {
                        // TODO: must call `set_local_grandpa_state` and `set_local_best_block` so that other peers notify us of neighbor packets
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "warp-sync-fragment-verify-success",
                            sender = sender_if_still_connected
                                .as_ref()
                                .map(|p| Cow::Owned(p.to_base58()))
                                .unwrap_or(Cow::Borrowed("<disconnected>")),
                            verified_hash = HashDisplay(&fragment_hash),
                            verified_height = fragment_number
                        );
                    }
                    Err(err) => {
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            format!(
                                "Failed to verify warp sync fragment from {}: {}{}",
                                sender_if_still_connected
                                    .as_ref()
                                    .map(|p| Cow::Owned(p.to_base58()))
                                    .unwrap_or(Cow::Borrowed("<disconnected>")),
                                err,
                                if matches!(err, all::VerifyFragmentError::JustificationVerify(_)) {
                                    ". This might be caused by a forced GrandPa authorities change having \
                                been enacted on the chain. If this is the case, please update the \
                                chain specification with a checkpoint past this forced change."
                                } else {
                                    ""
                                }
                            )
                        );
                        if let Some(sender_if_still_connected) = sender_if_still_connected {
                            task.network_service
                                .ban_and_disconnect(
                                    sender_if_still_connected,
                                    network_service::BanSeverity::High,
                                    "bad-warp-sync-fragment",
                                )
                                .await;
                        }
                    }
                }
            }

            WakeUpReason::SyncProcess(all::ProcessOne::VerifyBlock(verify)) => {
                // Header to verify.
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

                        // Notify of the new block.
                        task.dispatch_all_subscribers({
                            Notification::Block(BlockNotification {
                                is_new_best,
                                scale_encoded_header,
                                parent_hash,
                            })
                        });
                    }

                    all::HeaderVerifyOutcome::Error { sync, error, .. } => {
                        task.sync = Some(sync);

                        // TODO: print which peer sent the header
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

                        // TODO: ban peers that have announced the block
                        /*for peer_id in task.sync.knows_non_finalized_block(height, hash) {
                            task.network_service
                                .ban_and_disconnect(
                                    peer_id,
                                    network_service::BanSeverity::High,
                                    "bad-block",
                                )
                                .await;
                        }*/
                    }
                }
            }

            WakeUpReason::SyncProcess(all::ProcessOne::VerifyFinalityProof(verify)) => {
                // Finality proof to verify.
                let sender = verify.sender().1.0.clone();
                match verify.perform({
                    let mut seed = [0; 32];
                    task.platform.fill_random_bytes(&mut seed);
                    seed
                }) {
                    (
                        sync,
                        all::FinalityProofVerifyOutcome::NewFinalized {
                            updates_best_block,
                            finalized_blocks_newest_to_oldest,
                            pruned_blocks,
                        },
                    ) => {
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "finality-proof-verify-success",
                            finalized_blocks = finalized_blocks_newest_to_oldest.len(),
                            sender
                        );

                        if updates_best_block {
                            task.network_up_to_date_best = false;
                        }
                        task.network_up_to_date_finalized = false;
                        // Invalidate the cache of the runtime of the finalized blocks if any
                        // of the finalized blocks indicates that a runtime update happened.
                        if finalized_blocks_newest_to_oldest.iter().any(|b| {
                            header::decode(&b.header, sync.block_number_bytes())
                                .unwrap()
                                .digest
                                .has_runtime_environment_updated()
                        }) {
                            task.known_finalized_runtime = None;
                        }
                        task.dispatch_all_subscribers(Notification::Finalized {
                            hash: *sync.finalized_block_hash(),
                            best_block_hash_if_changed: if updates_best_block {
                                Some(*sync.best_block_hash())
                            } else {
                                None
                            },
                            pruned_blocks,
                        });

                        task.sync = Some(sync);
                    }

                    (
                        sync,
                        all::FinalityProofVerifyOutcome::AlreadyFinalized
                        | all::FinalityProofVerifyOutcome::GrandpaCommitPending,
                    ) => {
                        task.sync = Some(sync);
                    }

                    (sync, all::FinalityProofVerifyOutcome::JustificationError(error)) => {
                        task.sync = Some(sync);

                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "finality-proof-verify-error",
                            ?error,
                            sender,
                        );

                        // Errors of type `JustificationEngineMismatch` indicate that the chain
                        // uses a finality engine that smoldot doesn't recognize. This is a benign
                        // error that shouldn't lead to a ban.
                        if !matches!(
                            error,
                            all::JustificationVerifyError::JustificationEngineMismatch
                        ) {
                            log!(
                                &task.platform,
                                Warn,
                                &task.log_target,
                                format!("Error while verifying justification: {error}")
                            );

                            task.network_service
                                .ban_and_disconnect(
                                    sender,
                                    network_service::BanSeverity::High,
                                    "bad-justification",
                                )
                                .await;
                        }
                    }

                    (sync, all::FinalityProofVerifyOutcome::GrandpaCommitError(error)) => {
                        task.sync = Some(sync);

                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "finality-proof-verify-error",
                            ?error,
                            sender,
                        );

                        log!(
                            &task.platform,
                            Warn,
                            &task.log_target,
                            format!("Error while verifying GrandPa commit: {}", error)
                        );

                        task.network_service
                            .ban_and_disconnect(
                                sender,
                                network_service::BanSeverity::High,
                                "bad-grandpa-commit",
                            )
                            .await;
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

                // The `Disconnect` network event indicates that the main notifications substream
                // with that peer has been closed, not necessarily that the connection as a whole
                // has been closed. As such, the in-progress network requests might continue if
                // we don't abort them.
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

            WakeUpReason::NetworkEvent(network_service::Event::GrandpaNeighborPacket {
                peer_id,
                finalized_block_height,
            }) => {
                let sync_source_id = *task.peers_source_id_map.get(&peer_id).unwrap();
                task.sync
                    .as_mut()
                    .unwrap_or_else(|| unreachable!())
                    .update_source_finality_state(sync_source_id, finalized_block_height);
            }

            WakeUpReason::NetworkEvent(network_service::Event::GrandpaCommitMessage {
                peer_id,
                message,
            }) => {
                let sync_source_id = *task.peers_source_id_map.get(&peer_id).unwrap();
                match task
                    .sync
                    .as_mut()
                    .unwrap_or_else(|| unreachable!())
                    .grandpa_commit_message(sync_source_id, message.into_encoded())
                {
                    all::GrandpaCommitMessageOutcome::Queued => {
                        // TODO: print more details?
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "grandpa-commit-message-queued",
                            sender = peer_id
                        );
                    }
                    all::GrandpaCommitMessageOutcome::Discarded => {
                        log!(
                            &task.platform,
                            Debug,
                            &task.log_target,
                            "grandpa-commit-message-ignored",
                            sender = peer_id
                        );
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
                task.from_network_service = Some(Box::pin(
                    // As documented, `subscribe().await` is expected to return quickly.
                    task.network_service.subscribe().await,
                ));
            }

            WakeUpReason::MustUpdateNetworkWithBestBlock => {
                // The networking service needs to be kept up to date with what the local node
                // considers as the best block.
                // For some reason, first building the future then executing it solves a borrow
                // checker error.
                let Some(sync) = &task.sync else {
                    unreachable!()
                };

                let fut = task
                    .network_service
                    .set_local_best_block(*sync.best_block_hash(), sync.best_block_number());
                fut.await;

                task.network_up_to_date_best = true;
            }

            WakeUpReason::MustUpdateNetworkWithFinalizedBlock => {
                // If the chain uses GrandPa, the networking has to be kept up-to-date with the
                // state of finalization for other peers to send back relevant gossip messages.
                // (code style) `grandpa_set_id` is extracted first in order to avoid borrowing
                // checker issues.
                let Some(sync) = &mut task.sync else {
                    unreachable!()
                };

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
                    task.network_service
                        .set_local_grandpa_state(network::service::GrandpaState {
                            set_id,
                            round_number: 1, // TODO:
                            commit_finalized_height: sync.finalized_block_number(),
                        })
                        .await;
                }

                task.network_up_to_date_finalized = true;
            }

            WakeUpReason::ForegroundMessage(ToBackground::IsNearHeadOfChainHeuristic {
                send_back,
            }) => {
                // Frontend is querying something.
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
                // Frontend would like to subscribe to events.

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
                // Frontend queries the list of peers which are expected to know about a certain
                // block.
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
                    // As documented, `knows_non_finalized_block` would panic if the
                    // block height was below the one of the known finalized block.
                    sync.knows_non_finalized_block(block_number, &block_hash)
                        .map(|id| sync[id].0.clone())
                        .collect()
                };

                let _ = send_back.send(outcome);
            }

            WakeUpReason::ForegroundMessage(ToBackground::SyncingPeers { send_back }) => {
                // Frontend is querying the list of peers.
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
                // Frontend is querying the chain information.
                let _ = send_back.send(Some(
                    task.sync
                        .as_ref()
                        .unwrap_or_else(|| unreachable!())
                        .as_chain_information()
                        .into(),
                ));
            }

            WakeUpReason::ForegroundClosed => {
                // The channel with the frontend sync service has been closed.
                // Closing the sync background task as a result.
                return;
            }

            WakeUpReason::RequestFinished(_, Err(_)) => {
                // A request has been cancelled by the sync state machine. Nothing to do.
            }

            WakeUpReason::RequestFinished(request_id, Ok(RequestOutcome::Block(Ok(v)))) => {
                // Successful block request.
                task.sync
                    .as_mut()
                    .unwrap_or_else(|| unreachable!())
                    .blocks_request_response(
                        request_id,
                        v.into_iter().filter_map(|block| {
                            Some(all::BlockRequestSuccessBlock {
                                scale_encoded_header: block.header?,
                                scale_encoded_justifications: block
                                    .justifications
                                    .unwrap_or(Vec::new())
                                    .into_iter()
                                    .map(|j| all::Justification {
                                        engine_id: j.engine_id,
                                        justification: j.justification,
                                    })
                                    .collect(),
                                scale_encoded_extrinsics: Vec::new(),
                                user_data: (),
                            })
                        }),
                    );
            }

            WakeUpReason::RequestFinished(request_id, Ok(RequestOutcome::Block(Err(_)))) => {
                // Failed block request.
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

            WakeUpReason::RequestFinished(request_id, Ok(RequestOutcome::WarpSync(Ok(result)))) => {
                // Successful warp sync request.
                let decoded = result.decode();
                let fragments = decoded
                    .fragments
                    .into_iter()
                    .map(|f| all::WarpSyncFragment {
                        scale_encoded_header: f.scale_encoded_header.to_vec(),
                        scale_encoded_justification: f.scale_encoded_justification.to_vec(),
                    })
                    .collect();
                task.sync
                    .as_mut()
                    .unwrap_or_else(|| unreachable!())
                    .grandpa_warp_sync_response(request_id, fragments, decoded.is_finished);
            }

            WakeUpReason::RequestFinished(request_id, Ok(RequestOutcome::WarpSync(Err(_)))) => {
                // Failed warp sync request.
                let Some(sync) = &mut task.sync else {
                    unreachable!()
                };

                task.network_service
                    .ban_and_disconnect(
                        sync[sync.request_source_id(request_id)].0.clone(),
                        network_service::BanSeverity::Low,
                        "failed-warp-sync-request",
                    )
                    .await;

                sync.remove_request(request_id);
            }

            WakeUpReason::RequestFinished(request_id, Ok(RequestOutcome::Storage(Ok(r)))) => {
                // Storage proof request.
                let Some(sync) = &mut task.sync else {
                    unreachable!()
                };

                sync.storage_get_response(request_id, r);
            }

            WakeUpReason::RequestFinished(request_id, Ok(RequestOutcome::Storage(Err(_)))) => {
                // Storage proof request.
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
                // Successful call proof request.
                task.sync
                    .as_mut()
                    .unwrap_or_else(|| unreachable!())
                    .call_proof_response(request_id, r.decode().to_owned());
                // TODO: need help from networking service to avoid this to_owned
            }

            WakeUpReason::RequestFinished(request_id, Ok(RequestOutcome::CallProof(Err(_)))) => {
                // Failed call proof request.
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
                // We are no longer interested in the answer to that request.
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
                    request_justification,
                },
            ) => {
                let Some(sync) = &mut task.sync else {
                    unreachable!()
                };

                // Before inserting the request back to the syncing state machine, clamp the number
                // of blocks to the number of blocks we expect to receive.
                // This constant corresponds to the maximum number of blocks that nodes will answer
                // in one request. If this constant happens to be inaccurate, everything will still
                // work but less efficiently.
                let num_blocks = NonZero::<u64>::new(cmp::min(64, num_blocks.get())).unwrap();

                let peer_id = sync[source_id].0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                let block_request = task.network_service.clone().blocks_request(
                    peer_id,
                    network::codec::BlocksRequestConfig {
                        start: network::codec::BlocksRequestConfigStart::Hash(first_block_hash),
                        desired_count: NonZero::<u32>::new(
                            u32::try_from(num_blocks.get()).unwrap_or(u32::MAX),
                        )
                        .unwrap(),
                        // The direction is hardcoded based on the documentation of the syncing
                        // state machine.
                        direction: network::codec::BlocksRequestDirection::Descending,
                        fields: network::codec::BlocksRequestFields {
                            header: request_headers,
                            body: request_bodies,
                            justifications: request_justification,
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
                        request_justification,
                    },
                    abort,
                );

                task.pending_requests.push(Box::pin(async move {
                    (request_id, block_request.await.map(RequestOutcome::Block))
                }));
            }

            WakeUpReason::StartRequest(
                source_id,
                all::DesiredRequest::WarpSync {
                    sync_start_block_hash,
                },
            ) => {
                let Some(sync) = &mut task.sync else {
                    unreachable!()
                };

                let peer_id = sync[source_id].0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                let grandpa_request = task.network_service.clone().grandpa_warp_sync_request(
                    peer_id,
                    sync_start_block_hash,
                    // The timeout needs to be long enough to potentially download the maximum
                    // response size of 16 MiB. Assuming a 128 kiB/sec connection, that's
                    // 128 seconds. Unfortunately, 128 seconds is way too large, and for
                    // pragmatic reasons we use a lower value.
                    Duration::from_secs(24),
                );

                let (grandpa_request, abort) = future::abortable(grandpa_request);
                let request_id = sync.add_request(
                    source_id,
                    all::RequestDetail::WarpSync {
                        sync_start_block_hash,
                    },
                    abort,
                );

                task.pending_requests.push(Box::pin(async move {
                    (
                        request_id,
                        grandpa_request.await.map(RequestOutcome::WarpSync),
                    )
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

                let peer_id = sync[source_id].0.clone(); // TODO: why does this require cloning? weird borrow chk issue

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
                        // TODO: log what happens
                        Ok(outcome.decode().to_vec()) // TODO: no to_vec() here, needs some API change on the networking
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

                let peer_id = sync[source_id].0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                let call_proof_request = {
                    // TODO: all this copying is done because of lifetime requirements in NetworkService::call_proof_request; maybe check if it can be avoided
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

            WakeUpReason::WarpSyncTakingLongTimeWarning => {
                match task
                    .sync
                    .as_mut()
                    .unwrap_or_else(|| unreachable!())
                    .status()
                {
                    all::Status::Sync => {}
                    all::Status::WarpSyncFragments {
                        source: None,
                        finalized_block_hash,
                        finalized_block_number,
                    } => {
                        log!(
                            &task.platform,
                            Warn,
                            &task.log_target,
                            format!(
                                "GrandPa warp sync idle at block #{} (0x{})",
                                finalized_block_number,
                                HashDisplay(&finalized_block_hash)
                            ),
                        );
                    }
                    all::Status::WarpSyncFragments {
                        finalized_block_hash,
                        finalized_block_number,
                        ..
                    }
                    | all::Status::WarpSyncChainInformation {
                        finalized_block_hash,
                        finalized_block_number,
                    } => {
                        log!(
                            &task.platform,
                            Warn,
                            &task.log_target,
                            format!(
                                "GrandPa warp sync in progress. Block: #{} (0x{}).",
                                finalized_block_number,
                                HashDisplay(&finalized_block_hash)
                            )
                        );
                    }
                };
            }
        }
    }
}

struct Task<TPlat: PlatformRef> {
    /// Log target to use for all logs that are emitted.
    log_target: String,

    /// Access to the platform's capabilities.
    platform: TPlat,

    /// Main syncing state machine. Contains a list of peers, requests, and blocks, and manages
    /// everything about the non-finalized chain.
    ///
    /// For each request, we store a [`future::AbortHandle`] that can be used to abort the
    /// request if desired.
    ///
    /// Always `Some`, except for temporary extraction.
    sync: Option<all::AllSync<future::AbortHandle, (libp2p::PeerId, codec::Role), ()>>,

    /// If `Some`, contains the runtime of the current finalized block.
    known_finalized_runtime: Option<FinalizedBlockRuntime>,

    /// For each networking peer, the index of the corresponding peer within the [`Task::sync`].
    peers_source_id_map: HashMap<libp2p::PeerId, all::SourceId, util::SipHasherBuild>,

    /// `false` after the best block in the [`Task::sync`] has changed. Set back to `true`
    /// after the networking has been notified of this change.
    network_up_to_date_best: bool,
    /// `false` after the finalized block in the [`Task::sync`] has changed. Set back to `true`
    /// after the networking has been notified of this change.
    network_up_to_date_finalized: bool,

    /// All event subscribers that are interested in events about the chain.
    all_notifications: Vec<async_channel::Sender<Notification>>,

    /// Contains a `Delay` after which we print a warning about GrandPa warp sync taking a long
    /// time. Set to `Pending` after the warp sync has finished, so that future remains pending
    /// forever.
    warp_sync_taking_long_time_warning:
        future::Fuse<future::Either<Pin<Box<TPlat::Delay>>, future::Pending<()>>>,

    /// Chain of the network service. Used to send out requests to peers.
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
    /// Events coming from the networking service. `None` if not subscribed yet.
    from_network_service: Option<Pin<Box<async_channel::Receiver<network_service::Event>>>>,

    /// List of requests currently in progress.
    pending_requests: stream::FuturesUnordered<
        future::BoxFuture<'static, (all::RequestId, Result<RequestOutcome, future::Aborted>)>,
    >,
}

enum RequestOutcome {
    Block(Result<Vec<codec::BlockData>, network_service::BlocksRequestError>),
    WarpSync(
        Result<
            network::service::EncodedGrandpaWarpSyncResponse,
            network_service::WarpSyncRequestError,
        >,
    ),
    Storage(Result<Vec<u8>, ()>),
    CallProof(Result<network::service::EncodedMerkleProof, ()>),
}

impl<TPlat: PlatformRef> Task<TPlat> {
    /// Sends a notification to all the notification receivers.
    fn dispatch_all_subscribers(&mut self, notification: Notification) {
        // Elements in `all_notifications` are removed one by one and inserted back if the
        // channel is still open.
        for index in (0..self.all_notifications.len()).rev() {
            let subscription = self.all_notifications.swap_remove(index);
            if subscription.try_send(notification.clone()).is_err() {
                continue;
            }

            self.all_notifications.push(subscription);
        }
    }
}
