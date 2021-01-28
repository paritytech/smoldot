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

use crate::network_service;

use futures::{
    channel::{mpsc, oneshot},
    lock::Mutex,
    prelude::*,
};
use smoldot::{chain, chain::sync::all_forks, informant::HashDisplay, libp2p, network};
use std::{collections::HashMap, num::NonZeroU32, pin::Pin, sync::Arc};

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
}

async fn start_sync(
    chain_information: chain::chain_information::ChainInformation,
    mut from_foreground: mpsc::Receiver<ToBackground>,
    network_service: Arc<network_service::NetworkService>,
    mut from_network_service: mpsc::Receiver<network_service::Event>,
) -> impl Future<Output = ()> {
    let mut sync = all_forks::AllForksSync::<_, ()>::new(all_forks::Config {
        chain_information,
        sources_capacity: 32,
        blocks_capacity: {
            // This is the maximum number of blocks between two consecutive justifications.
            1024
        },
        full: false,
    });

    async move {
        let mut peers_source_id_map = HashMap::new();
        let mut pending_ancestry_searches = stream::FuturesUnordered::new();
        //let mut block_requests_finished = stream::FuturesUnordered::new();

        let mut finalized_notifications = Vec::<lossy_channel::Sender<Vec<u8>>>::new();
        let mut best_notifications = Vec::<lossy_channel::Sender<Vec<u8>>>::new();

        loop {
            /*while let Some(action) = sync.next_request_action() {
                match action {
                    optimistic::RequestAction::Start {
                        start,
                        block_height,
                        source,
                        num_blocks,
                        ..
                    } => {
                        let block_request = network_service.clone().blocks_request(
                            source.clone(),
                            network::protocol::BlocksRequestConfig {
                                start: network::protocol::BlocksRequestConfigStart::Number(
                                    block_height,
                                ),
                                desired_count: num_blocks,
                                direction: network::protocol::BlocksRequestDirection::Ascending,
                                fields: network::protocol::BlocksRequestFields {
                                    header: true,
                                    body: false,
                                    justification: true,
                                },
                            },
                        );

                        let (block_request, abort) = future::abortable(block_request);
                        let request_id = start.start(abort);
                        block_requests_finished
                            .push(async move { (request_id, block_request.await.map_err(|_| ())) });
                    }
                    optimistic::RequestAction::Cancel { user_data, .. } => {
                        user_data.abort();
                    }
                }
            }

            let mut verified_blocks = 0u64;

            // Verify blocks that have been fetched from queries.
            // TODO: tweak this mechanism of stopping sync from time to time
            while verified_blocks < 4096 {
                match sync.process_one(crate::ffi::unix_time()) {
                    optimistic::ProcessOne::Idle { sync: s } => {
                        sync = s;
                        break;
                    }

                    optimistic::ProcessOne::NewBest {
                        sync: s,
                        new_best_number,
                        new_best_hash,
                    } => {
                        sync = s;

                        log::debug!(
                            target: "sync-verify",
                            "New best block: #{} ({})",
                            new_best_number,
                            HashDisplay(&new_best_hash),
                        );

                        let scale_encoded_header = sync.best_block_header().scale_encoding_vec();
                        // TODO: remove expired senders
                        for notif in &mut best_notifications {
                            let _ = notif.send(scale_encoded_header.clone());
                        }
                    }

                    optimistic::ProcessOne::Reset {
                        sync: s,
                        reason,
                        previous_best_height,
                    } => {
                        sync = s;

                        log::warn!(
                            target: "sync-verify",
                            "Failed to verify block #{}: {}",
                            previous_best_height + 1,
                            reason
                        );

                        let scale_encoded_header = sync.best_block_header().scale_encoding_vec();
                        // TODO: remove expired senders
                        for notif in &mut best_notifications {
                            let _ = notif.send(scale_encoded_header.clone());
                        }
                    }

                    optimistic::ProcessOne::Finalized {
                        sync: s,
                        finalized_blocks,
                        ..
                    } => {
                        sync = s;
                        verified_blocks += 1;

                        log::debug!(
                            target: "sync-verify",
                            "Finalized {} block",
                            finalized_blocks.len()
                        );

                        let scale_encoded_header = finalized_blocks
                            .last()
                            .unwrap()
                            .header
                            .scale_encoding()
                            .fold(Vec::new(), |mut a, b| {
                                a.extend_from_slice(b.as_ref());
                                a
                            });

                        // TODO: remove expired senders
                        for notif in &mut best_notifications {
                            let _ = notif.send(scale_encoded_header.clone());
                        }

                        // TODO: remove expired senders
                        for notif in &mut finalized_notifications {
                            let _ = notif.send(scale_encoded_header.clone());
                        }
                    }

                    // Other variants can be produced if the sync state machine is configured for
                    // syncing the storage, which is not the case here.
                    _ => unreachable!(),
                }
            }

            // Since `process_one` is a CPU-heavy operation, looping until it is done can
            // take a long time. In order to avoid blocking the rest of the program in the
            // meanwhile, the `yield_once` function interrupts the current task and gives a
            // chance for other tasks to progress.
            crate::yield_once().await;*/

            futures::select! {
                network_event = from_network_service.next() => {
                    let network_event = match network_event {
                        Some(m) => m,
                        None => {
                            return
                        },
                    };

                    match network_event {
                        network_service::Event::Connected { peer_id, best_block_number, best_block_hash } => {
                            let id = sync.add_source(peer_id.clone(), best_block_number, best_block_hash).id();
                            peers_source_id_map.insert(peer_id.clone(), id);
                        },
                        network_service::Event::Disconnected(peer_id) => {
                            let id = peers_source_id_map.remove(&peer_id).unwrap();
                            sync.source_mut(id).unwrap().remove();
                            // TODO: update
                            /*let (_, rq_list) = sync.remove_source(id);
                            for (_, rq) in rq_list {
                                rq.abort();
                            }*/
                        },
                        network_service::Event::BlockAnnounce { peer_id, announce } => {
                            let source_id = *peers_source_id_map.get(&peer_id).unwrap();
                            let decoded = announce.decode();
                            // TODO: block header re-encoding
                            match sync.source_mut(source_id).unwrap().block_announce(decoded.header.scale_encoding().fold(Vec::new(), |mut a, b| { a.extend_from_slice(b.as_ref()); a }), decoded.is_best, crate::ffi::unix_time()) {
                                all_forks::BlockAnnounceOutcome::HeaderImported => {},
                                all_forks::BlockAnnounceOutcome::BlockBodyDownloadStart => {},
                                all_forks::BlockAnnounceOutcome::AncestrySearchStart { first_block_hash, num_blocks } => {
                                    println!("ancestry search: {:?} {:?}", first_block_hash, num_blocks);  // TODO: remove
                                    let (send_back, rx) = oneshot::channel();
                                    let send_result = to_foreground
                                        .send(FromBackground::RequestStart {
                                            target: peer_id.clone(),
                                            request: network::protocol::BlocksRequestConfig {
                                                start: network::protocol::BlocksRequestConfigStart::Hash(
                                                    first_block_hash
                                                ),
                                                desired_count: NonZeroU32::new(u32::try_from(num_blocks.get()).unwrap_or(u32::max_value())).unwrap(),
                                                direction: network::protocol::BlocksRequestDirection::Descending,
                                                fields: network::protocol::BlocksRequestFields {
                                                    header: true,
                                                    body: false,
                                                    justification: false,
                                                },
                                            },
                                            send_back,
                                        })
                                        .await;

                                    // If the channel is closed, the sync service has been closed too.
                                    if send_result.is_err() {
                                        return;
                                    }

                                    // TODO: use this abort
                                    let (rx, abort) = future::abortable(rx);

                                    pending_ancestry_searches.push(async move {
                                        rx.await.unwrap().map(|r| (source_id, r))
                                    });
                                },
                                all_forks::BlockAnnounceOutcome::TooOld => {},
                                all_forks::BlockAnnounceOutcome::AlreadyVerified => {},
                                all_forks::BlockAnnounceOutcome::NotFinalizedChain => {},
                                all_forks::BlockAnnounceOutcome::Queued => {},
                                all_forks::BlockAnnounceOutcome::InvalidHeader(error) => {},
                                all_forks::BlockAnnounceOutcome::HeaderVerifyError(error) => {},
                            }
                        },
                    };

                    match message {
                        ToBackground::Serialize { send_back } => {
                            let chain = sync.as_chain_information();
                            let serialized = smoldot::database::finalized_serialize::encode_chain_information(chain);
                            let _ = send_back.send(serialized);
                        }
                        ToBackground::SubscribeFinalized { send_back } => {
                            let (tx, rx) = lossy_channel::channel();
                            finalized_notifications.push(tx);
                            let current = sync.finalized_block_header().scale_encoding_vec();
                            let _ = send_back.send((current, rx));
                        }
                        ToBackground::SubscribeBest { send_back } => {
                            let (tx, rx) = lossy_channel::channel();
                            best_notifications.push(tx);
                            let current = sync.best_block_header().scale_encoding_vec();
                            let _ = send_back.send((current, rx));
                        }
                    }
                },

                result = pending_ancestry_searches.select_next_some() => {
                    // `result` is an error if the block request got cancelled by the sync state
                    // machine. In other words, if `result` is `Err`, the `sync` isn't interested
                    // by this request anymore and considers that it doesn't exist anymore.
                    if let Ok((source_id, request_result)) = result {
                        sync.ancestry_search_response(
                            crate::ffi::unix_time(),
                            source_id,
                            // It is possible for the remote to send back a block without a
                            // header. This situation is filtered out with the `flat_map`.
                            request_result.map(|r| r.into_iter().flat_map(|b| b.header))
                                .map_err(|_| ())
                        );
                    }
                    // TODO: restore
                    /*let result = result.map_err(|_| ()).and_then(|v| v);
                    let _ = sync.finish_request(request_id, result.map(|v| v.into_iter().map(|block| optimistic::RequestSuccessBlock {
                        scale_encoded_header: block.header.unwrap(), // TODO: don't unwrap
                        scale_encoded_justification: block.justification,
                        scale_encoded_extrinsics: Vec::new(),
                        user_data: (),
                    })).map_err(|()| optimistic::RequestFail::BlocksUnavailable));*/
                },

                // TODO: restore
                /*_ = async move {
                    if verified_blocks == 0 {
                        loop {
                            futures::pending!()
                        }
                    }
                }.fuse() => {}*/
            }
        }
    }
}

enum ToBackground {
    /// See [`SyncService::serialize_chain`].
    Serialize { send_back: oneshot::Sender<String> },
    /// See [`SyncService::subscribe_finalized`].
    SubscribeFinalized {
        send_back: oneshot::Sender<(Vec<u8>, lossy_channel::Receiver<Vec<u8>>)>,
    },
    /// See [`SyncService::subscribe_best`].
    SubscribeBest {
        send_back: oneshot::Sender<(Vec<u8>, lossy_channel::Receiver<Vec<u8>>)>,
    },
}
