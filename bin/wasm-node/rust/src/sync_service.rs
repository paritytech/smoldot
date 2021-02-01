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
    let mut sync: either::Either<_, (all_forks::SourceId, all_forks::HeaderVerify<_, _>)> =
        either::Left(all_forks::AllForksSync::<libp2p::PeerId, ()>::new(
            all_forks::Config {
                chain_information,
                sources_capacity: 32,
                blocks_capacity: {
                    // This is the maximum number of blocks between two consecutive justifications.
                    1024
                },
                // TODO: document
                max_disjoint_headers: 1024,
                max_requests_per_block: NonZeroU32::new(2).unwrap(),
                full: false,
            },
        ));

    async move {
        let mut peers_source_id_map = HashMap::new();
        let mut pending_ancestry_searches = stream::FuturesUnordered::new();
        let mut header_requests = stream::FuturesUnordered::new();

        let mut finalized_notifications = Vec::<lossy_channel::Sender<Vec<u8>>>::new();
        let mut best_notifications = Vec::<lossy_channel::Sender<Vec<u8>>>::new();

        let mut request_to_start = None::<(all_forks::SourceId, all_forks::Request)>;

        loop {
            let mut sync_inner = match sync {
                either::Left(s) => s,
                either::Right((source_id, verify)) => {
                    match verify.perform(crate::ffi::unix_time(), ()) {
                        all_forks::HeaderVerifyOutcome::Success {
                            sync: s,
                            next_request,
                        } => {
                            sync = either::Left(s);
                            debug_assert!(request_to_start.is_none());
                            request_to_start = next_request.map(|r| (source_id, r))
                        }
                        all_forks::HeaderVerifyOutcome::SuccessContinue { next_block } => {
                            sync = either::Right((source_id, next_block));
                        }
                        all_forks::HeaderVerifyOutcome::Error {
                            sync: s,
                            error,
                            next_request,
                            ..
                        } => {
                            log::warn!("Failed to verify header: {}", error);
                            sync = either::Left(s);
                            debug_assert!(request_to_start.is_none());
                            request_to_start = next_request.map(|r| (source_id, r))
                        }
                        all_forks::HeaderVerifyOutcome::ErrorContinue {
                            next_block, error, ..
                        } => {
                            log::warn!("Failed to verify header: {}", error);
                            sync = either::Right((source_id, next_block));
                        }
                    };

                    continue;
                }
            };

            match request_to_start.take() {
                None => {}
                Some((
                    source_id,
                    all_forks::Request::AncestrySearch {
                        first_block_hash,
                        num_blocks,
                    },
                )) => {
                    let peer_id = sync_inner
                        .source_mut(source_id)
                        .unwrap()
                        .user_data()
                        .clone();

                    println!("ancestry search: {:?} {:?}", first_block_hash, num_blocks); // TODO: remove
                    let block_request = network_service.clone().blocks_request(
                        peer_id.clone(),
                        network::protocol::BlocksRequestConfig {
                            start: network::protocol::BlocksRequestConfigStart::Hash(
                                first_block_hash,
                            ),
                            desired_count: NonZeroU32::new(
                                u32::try_from(num_blocks.get()).unwrap_or(u32::max_value()),
                            )
                            .unwrap(),
                            direction: network::protocol::BlocksRequestDirection::Descending,
                            fields: network::protocol::BlocksRequestFields {
                                header: true,
                                body: false,
                                justification: false,
                            },
                        },
                    );

                    // TODO: use this abort
                    let (block_request, abort) = future::abortable(block_request);

                    pending_ancestry_searches
                        .push(async move { block_request.await.unwrap().map(|r| (source_id, r)) });
                }
                Some((source_id, all_forks::Request::HeaderRequest { number, hash })) => {
                    let peer_id = sync_inner
                        .source_mut(source_id)
                        .unwrap()
                        .user_data()
                        .clone();

                    println!("header search: {:?} {:?}", number, hash); // TODO: remove
                    let block_request = network_service.clone().blocks_request(
                        peer_id.clone(),
                        network::protocol::BlocksRequestConfig {
                            start: network::protocol::BlocksRequestConfigStart::Hash(hash),
                            desired_count: NonZeroU32::new(1).unwrap(),
                            direction: network::protocol::BlocksRequestDirection::Ascending,
                            fields: network::protocol::BlocksRequestFields {
                                header: true,
                                body: false,
                                justification: false,
                            },
                        },
                    );

                    // TODO: use this abort
                    let (block_request, abort) = future::abortable(block_request);

                    header_requests
                        .push(async move { block_request.await.unwrap().map(|r| (source_id, r)) });
                }
                _ => todo!(),
            }

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
                            let (source, request) = sync_inner.add_source(peer_id.clone(), best_block_number, best_block_hash);
                            debug_assert!(request_to_start.is_none());
                            request_to_start = request.map(|r| (source.id(), r));
                            peers_source_id_map.insert(peer_id.clone(), source.id());
                            sync = either::Left(sync_inner);
                        },
                        network_service::Event::Disconnected(peer_id) => {
                            let id = peers_source_id_map.remove(&peer_id).unwrap();
                            sync_inner.source_mut(id).unwrap().remove();
                            // TODO: update
                            /*let (_, rq_list) = sync.remove_source(id);
                            for (_, rq) in rq_list {
                                rq.abort();
                            }*/
                            sync = either::Left(sync_inner);
                        },
                        network_service::Event::BlockAnnounce { peer_id, announce } => {
                            let source_id = *peers_source_id_map.get(&peer_id).unwrap();
                            let decoded = announce.decode();
                            // TODO: block header re-encoding
                            match sync_inner.block_announce(source_id, decoded.header.scale_encoding_vec(), decoded.is_best) {
                                all_forks::BlockAnnounceOutcome::HeaderVerify(verify) => {
                                    sync = either::Right((source_id, verify));
                                },
                                all_forks::BlockAnnounceOutcome::Disjoint { sync: s, next_request } => {
                                    sync = either::Left(s);
                                    debug_assert!(request_to_start.is_none());
                                    request_to_start = next_request.map(|r| (source_id, r));
                                },
                                all_forks::BlockAnnounceOutcome::TooOld(s) |
                                all_forks::BlockAnnounceOutcome::AlreadyInChain(s) |
                                all_forks::BlockAnnounceOutcome::NotFinalizedChain(s) |
                                all_forks::BlockAnnounceOutcome::InvalidHeader { sync: s, .. } => {
                                    sync = either::Left(s);
                                }
                            }
                        },
                    };
                }

                message = from_foreground.next() => {
                    let message = match message {
                        Some(m) => m,
                        None => {
                            return
                        },
                    };

                    match message {
                        ToBackground::Serialize { send_back } => {
                            let chain = sync_inner.as_chain_information();
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
                            let current = sync_inner.finalized_block_header().scale_encoding_vec();
                            let _ = send_back.send((current, rx));
                        }
                        ToBackground::SubscribeBest { send_back } => {
                            let (tx, rx) = lossy_channel::channel();
                            best_notifications.push(tx);
                            let current = sync_inner.best_block_header().scale_encoding_vec();
                            let _ = send_back.send((current, rx));
                        }
                    }

                    sync = either::Left(sync_inner);
                },

                result = pending_ancestry_searches.select_next_some() => {
                    // `result` is an error if the block request got cancelled by the sync state
                    // machine. In other words, if `result` is `Err`, the `sync` isn't interested
                    // by this request anymore and considers that it doesn't exist anymore.
                    if let Ok((source_id, request_result)) = result {
                        let outcome = sync_inner.ancestry_search_response(
                            source_id,
                            // It is possible for the remote to send back a block without a
                            // header. This situation is filtered out with the `flat_map`.
                            Ok(request_result.into_iter().flat_map(|b| b.header))
                        );

                        match outcome {
                            all_forks::AncestrySearchResponseOutcome::Verify(verify) => {
                                sync = either::Right((source_id, verify));
                            },
                            all_forks::AncestrySearchResponseOutcome::NotFinalizedChain { sync: s, next_request, .. } |
                            all_forks::AncestrySearchResponseOutcome::Inconclusive { sync: s, next_request } |
                            all_forks::AncestrySearchResponseOutcome::AllAlreadyInChain { sync: s, next_request } => {
                                sync = either::Left(s);
                                debug_assert!(request_to_start.is_none());
                                request_to_start = next_request.map(|r| (source_id, r));
                            },
                        }

                        // TODO:
                    } else {
                        sync = either::Left(sync_inner);
                    }
                },

                result = header_requests.select_next_some() => {
                    // TODO: call ancestry_search_response for a header request?
                    // `result` is an error if the block request got cancelled by the sync state
                    // machine. In other words, if `result` is `Err`, the `sync` isn't interested
                    // by this request anymore and considers that it doesn't exist anymore.
                    if let Ok((source_id, request_result)) = result {
                        let outcome = sync_inner.ancestry_search_response(
                            source_id,
                            // It is possible for the remote to send back a block without a
                            // header. This situation is filtered out with the `flat_map`.
                            Ok(request_result.into_iter().flat_map(|b| b.header))
                        );

                        match outcome {
                            all_forks::AncestrySearchResponseOutcome::Verify(verify) => {
                                sync = either::Right((source_id, verify));
                            },
                            all_forks::AncestrySearchResponseOutcome::NotFinalizedChain { sync: s, next_request, .. } |
                            all_forks::AncestrySearchResponseOutcome::Inconclusive { sync: s, next_request } |
                            all_forks::AncestrySearchResponseOutcome::AllAlreadyInChain { sync: s, next_request } => {
                                sync = either::Left(s);
                                debug_assert!(request_to_start.is_none());
                                request_to_start = next_request.map(|r| (source_id, r));
                            },
                        }

                        // TODO:
                    } else {
                        sync = either::Left(sync_inner);
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
