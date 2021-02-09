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

//! Background syncing service.
//!
//! The role of the [`SyncService`] is to do whatever necessary to obtain and stay up-to-date
//! with the best and the finalized blocks of a chain.
//!
//! The configuration of the chain to synchronize must be passed when creating a [`SyncService`],
//! after which it will spawn background tasks and use the networking service to stay
//! synchronized.
//!
//! Use [`SyncService::subscribe_best`] and [`SyncService::subscribe_finalized`] to get notified
//! about updates of the best and finalized blocks.

use crate::{ffi, network_service};

use futures::{
    channel::{mpsc, oneshot},
    lock::Mutex,
    prelude::*,
};
use smoldot::{chain, chain::sync::all, informant::HashDisplay, libp2p, network};
use std::{collections::HashMap, convert::TryFrom as _, num::NonZeroU32, pin::Pin, sync::Arc};

mod lossy_channel;

pub use lossy_channel::Receiver as NotificationsReceiver;

/// Configuration for a [`SyncService`].
pub struct Config {
    /// State of the finalized chain.
    pub chain_information: chain::chain_information::ChainInformation,

    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(Pin<Box<dyn Future<Output = ()> + Send>>) + Send>,

    /// Access to the network.
    pub network_service: Arc<network_service::NetworkService>,

    /// Receiver for events coming from the network, as returned by
    /// [`network_service::NetworkService::new`].
    pub network_events_receiver: mpsc::Receiver<network_service::Event>,
}

/// Identifier for a blocks request to be performed.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct BlocksRequestId(usize);

pub struct SyncService {
    /// Sender of messages towards the background task.
    to_background: Mutex<mpsc::Sender<ToBackground>>,
}

impl SyncService {
    pub async fn new(mut config: Config) -> Self {
        let (to_background, from_foreground) = mpsc::channel(16);

        (config.tasks_executor)(Box::pin(
            start_sync(
                config.chain_information,
                from_foreground,
                config.network_service,
                config.network_events_receiver,
            )
            .await,
        ));

        SyncService {
            to_background: Mutex::new(to_background),
        }
    }

    /// Returns a string representing the state of the chain using the
    /// [`smoldot::database::finalized_serialize`] module.
    pub async fn serialize_chain(&self) -> String {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .lock()
            .await
            .send(ToBackground::Serialize { send_back })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Returns the SCALE-encoded header of the current finalized block, alongside with a stream
    /// producing updates of the finalized block.
    ///
    /// Not all updates are necessarily reported. In particular, updates that weren't pulled from
    /// the `Stream` yet might get overwritten by newest updates.
    pub async fn subscribe_finalized(&self) -> (Vec<u8>, NotificationsReceiver<Vec<u8>>) {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .lock()
            .await
            .send(ToBackground::SubscribeFinalized { send_back })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Returns the SCALE-encoded header of the current best block, alongside with a stream
    /// producing updates of the best block.
    ///
    /// Not all updates are necessarily reported. In particular, updates that weren't pulled from
    /// the `Stream` yet might get overwritten by newest updates.
    pub async fn subscribe_best(&self) -> (Vec<u8>, NotificationsReceiver<Vec<u8>>) {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .lock()
            .await
            .send(ToBackground::SubscribeBest { send_back })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Returns `true` if the best block is known to be above the finalized block of the network.
    ///
    /// Also returns `false` if unknown.
    pub async fn is_above_network_finalized(&self) -> bool {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .lock()
            .await
            .send(ToBackground::IsAboveNetworkFinalized { send_back })
            .await
            .unwrap();

        rx.await.unwrap()
    }
}

async fn start_sync(
    chain_information: chain::chain_information::ChainInformation,
    mut from_foreground: mpsc::Receiver<ToBackground>,
    network_service: Arc<network_service::NetworkService>,
    mut from_network_service: mpsc::Receiver<network_service::Event>,
) -> impl Future<Output = ()> {
    // TODO: implicit generics
    let mut sync = all::AllSync::<(), libp2p::PeerId, ()>::new(all::Config {
        chain_information,
        sources_capacity: 32,
        source_selection_randomness_seed: rand::random(),
        blocks_request_granularity: NonZeroU32::new(128).unwrap(),
        blocks_capacity: {
            // This is the maximum number of blocks between two consecutive justifications.
            1024
        },
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
            5000
        },
        full: false,
    });

    async move {
        // TODO: remove
        let mut peers_source_id_map = HashMap::new();

        // List of block requests currently in progress.
        let mut pending_block_requests = stream::FuturesUnordered::new();

        // TODO: remove; should store the aborthandle in the TRq user data instead
        let mut pending_requests = HashMap::new();

        let mut finalized_notifications = Vec::<lossy_channel::Sender<Vec<u8>>>::new();
        let mut best_notifications = Vec::<lossy_channel::Sender<Vec<u8>>>::new();

        // If non-empty, contains a request that the sync state machine wants to start on a source.
        let mut requests_to_start = Vec::<all::Action>::with_capacity(16);

        // Main loop of the syncing logic.
        loop {
            // The sync state machine can be in a few various states. At the time of writing:
            // idle, verifying header, verifying block, verifying grandpa warp sync proof,
            // verifying storage proof.
            // If the state is one of the "verifying" states, perform the actual verification and
            // loop again until the sync is in an idle state.
            let mut sync_idle: all::Idle<_, _, _> = loop {
                match sync {
                    all::AllSync::Idle(idle) => break idle,
                    all::AllSync::HeaderVerify(verify) => {
                        match verify.perform(ffi::unix_time(), ()) {
                            all::HeaderVerifyOutcome::Success {
                                sync: sync_idle,
                                next_actions,
                                ..
                            } => {
                                requests_to_start.extend(next_actions);
                                sync = sync_idle.into();
                            }
                            all::HeaderVerifyOutcome::Error {
                                sync: sync_idle,
                                next_actions,
                                error,
                                ..
                            } => {
                                log::warn!(
                                    target: "sync-verify",
                                    "Error while verifying header: {}",
                                    error
                                );
                                requests_to_start.extend(next_actions);
                                sync = sync_idle.into();
                            }
                        }
                    }
                }
            };

            // `sync_idle` is now an `Idle` that has been extracted from `sync`.
            // All the code paths below will need to put back `sync_idle` into `sync` before
            // looping again.

            // Drain the content of `requests_to_start` to actually start the requests that have
            // been queued by the previous iteration of the main loop.
            // TODO: do this earlier, before the verifications
            for request in requests_to_start.drain(..) {
                match request {
                    all::Action::Start {
                        source_id,
                        request_id,
                        detail:
                            all::RequestDetail::BlocksRequest {
                                first_block,
                                ascending,
                                num_blocks,
                                request_headers,
                                request_bodies,
                                request_justification,
                            },
                    } => {
                        let peer_id = sync_idle.source_user_data_mut(source_id).clone();

                        println!("blocks request: {:?} {:?}", first_block, num_blocks); // TODO: remove
                        let block_request = network_service.clone().blocks_request(
                            peer_id.clone(),
                            network::protocol::BlocksRequestConfig {
                                start: match first_block {
                                    all::BlocksRequestFirstBlock::Hash(h) => {
                                        network::protocol::BlocksRequestConfigStart::Hash(h)
                                    }
                                    all::BlocksRequestFirstBlock::Number(n) => {
                                        network::protocol::BlocksRequestConfigStart::Number(n)
                                    }
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
                        pending_requests.insert(request_id, abort);

                        pending_block_requests
                            .push(async move { (request_id, block_request.await) });
                    }
                    all::Action::Start {
                        source_id,
                        request_id: id,
                        detail:
                            all::RequestDetail::GrandpaWarpSync {
                                local_finalized_block_height,
                            },
                    } => {
                        todo!()
                    }
                    all::Action::Start {
                        source_id,
                        request_id: id,
                        detail:
                            all::RequestDetail::StorageGet {
                                block_hash,
                                state_trie_root,
                                key,
                            },
                    } => todo!(),
                    all::Action::Cancel(request_id) => {
                        pending_requests.remove(&request_id).unwrap().abort();
                    }
                }
            }

            // The sync state machine is idle, and all requests have been started.
            // Now waiting for some event to happen: a network event, a request from the frontend
            // of the sync service, or a request being finished.
            futures::select! {
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
                        network_service::Event::Connected { peer_id, best_block_number, best_block_hash } => {
                            let (id, requests) = sync_idle.add_source(peer_id.clone(), best_block_number, best_block_hash);
                            peers_source_id_map.insert(peer_id, id);
                            requests_to_start.extend(requests);
                            sync = sync_idle.into();
                        },
                        network_service::Event::Disconnected(peer_id) => {
                            let id = peers_source_id_map.remove(&peer_id).unwrap();
                            let rq_list = sync_idle.remove_source(id);
                            // TODO:
                            /*for (_, rq) in rq_list {
                                rq.abort();
                            }*/
                            sync = sync_idle.into();
                        },
                        network_service::Event::BlockAnnounce { peer_id, announce } => {
                            let id = *peers_source_id_map.get(&peer_id).unwrap();
                            let decoded = announce.decode();
                            // TODO: stupid to re-encode
                            match sync_idle.block_announce(id, decoded.header.scale_encoding_vec(), decoded.is_best) {
                                all::BlockAnnounceOutcome::HeaderVerify(verify) => {
                                    sync = verify.into();
                                },
                                all::BlockAnnounceOutcome::TooOld(idle) => {
                                    sync = idle.into();
                                },
                                all::BlockAnnounceOutcome::AlreadyInChain(idle) => {
                                    sync = idle.into();
                                },
                                all::BlockAnnounceOutcome::NotFinalizedChain(idle) => {
                                    sync = idle.into();
                                },
                                all::BlockAnnounceOutcome::Disjoint { sync: sync_idle, next_actions, .. } => {
                                    requests_to_start.extend(next_actions);
                                    sync = sync_idle.into();
                                },
                                all::BlockAnnounceOutcome::InvalidHeader { sync: sync_idle, .. } => {
                                    sync = sync_idle.into();
                                },
                            }
                        },
                    }

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
                        ToBackground::Serialize { send_back } => {
                            let chain = sync_idle.as_chain_information();
                            let serialized = smoldot::database::finalized_serialize::encode_chain_information(chain);
                            let _ = send_back.send(serialized);
                        }
                        ToBackground::IsAboveNetworkFinalized { send_back } => {
                            // TODO: only optimistic syncing is implemented yet, hence false
                            let _ = send_back.send(false);
                        }
                        ToBackground::SubscribeFinalized { send_back } => {
                            let (tx, rx) = lossy_channel::channel();
                            finalized_notifications.push(tx);
                            let current = sync_idle.finalized_block_header().scale_encoding_vec();
                            let _ = send_back.send((current, rx));
                        }
                        ToBackground::SubscribeBest { send_back } => {
                            let (tx, rx) = lossy_channel::channel();
                            best_notifications.push(tx);
                            let current = sync_idle.best_block_header().scale_encoding_vec();
                            let _ = send_back.send((current, rx));
                        }
                    };

                    sync = sync_idle.into();
                },

                (request_id, result) = pending_block_requests.select_next_some() => {
                    pending_requests.remove(&request_id);

                    // A request (e.g. a block request, warp sync request, etc.) has been finished.
                    // `result` is an error if the block request got cancelled by the sync state
                    // machine.
                    if let Ok(result) = result {
                        // Inject the result of the request into the sync state machine.
                        let outcome = sync_idle.blocks_request_response(
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
                            }),
                            ffi::unix_time(),
                        );

                        match outcome {
                            all::BlocksRequestResponseOutcome::VerifyHeader(verify) => {
                                sync = verify.into();
                            },
                            all::BlocksRequestResponseOutcome::Queued { sync: sync_idle, next_actions } => {
                                requests_to_start.extend(next_actions);
                                sync = sync_idle.into();
                            },
                            all::BlocksRequestResponseOutcome::NotFinalizedChain { sync: sync_idle, next_actions, .. } => {
                                requests_to_start.extend(next_actions);
                                sync = sync_idle.into();
                            },
                            all::BlocksRequestResponseOutcome::Inconclusive { sync: sync_idle, next_actions, .. } => {
                                requests_to_start.extend(next_actions);
                                sync = sync_idle.into();
                            },
                            all::BlocksRequestResponseOutcome::AllAlreadyInChain { sync: sync_idle, next_actions, .. } => {
                                requests_to_start.extend(next_actions);
                                sync = sync_idle.into();
                            },
                        }
                    } else {
                        // The sync state machine has emitted a `Action::Cancel` earlier, and is
                        // thus no longer interested in the response.
                        sync = sync_idle.into();
                    }
                },
            }
        }
    }
}

enum ToBackground {
    /// See [`SyncService::serialize_chain`].
    Serialize { send_back: oneshot::Sender<String> },
    /// See [`SyncService::is_above_network_finalized`].
    IsAboveNetworkFinalized { send_back: oneshot::Sender<bool> },
    /// See [`SyncService::subscribe_finalized`].
    SubscribeFinalized {
        send_back: oneshot::Sender<(Vec<u8>, lossy_channel::Receiver<Vec<u8>>)>,
    },
    /// See [`SyncService::subscribe_best`].
    SubscribeBest {
        send_back: oneshot::Sender<(Vec<u8>, lossy_channel::Receiver<Vec<u8>>)>,
    },
}
