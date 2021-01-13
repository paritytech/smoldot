// Substrate-lite
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

use futures::{
    channel::{mpsc, oneshot},
    lock::Mutex,
    prelude::*,
};
use std::{collections::HashMap, num::NonZeroU32, pin::Pin};
use substrate_lite::{chain, chain::sync::optimistic, libp2p, network};

/// Configuration for a [`SyncService`].
pub struct Config {
    /// State of the finalized chain.
    pub chain_information: chain::chain_information::ChainInformation,

    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(Pin<Box<dyn Future<Output = ()> + Send>>) + Send>,
}

/// Event generated by [`SyncService::next_event`].
#[derive(Debug)]
pub enum Event {
    BlocksRequest {
        id: BlocksRequestId,
        target: libp2p::PeerId,
        request: network::protocol::BlocksRequestConfig,
    },
    /// Current best block has been updated.
    NewBest {
        /// Header of the new best block, in SCALE encoding.
        scale_encoded_header: Vec<u8>,
    },
    /// Current finalized block has been updated.
    NewFinalized {
        /// Header of the new finalized block, in SCALE encoding.
        scale_encoded_header: Vec<u8>,
    },
}

/// Identifier for a blocks request to be performed.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct BlocksRequestId(usize);

pub struct SyncService {
    /// Sender of messages towards the background task.
    to_background: Mutex<mpsc::Sender<ToBackground>>,

    /// Receiver of events sent by the background task.
    from_background: Mutex<mpsc::Receiver<FromBackground>>,

    /// For each emitted blocks request, an element is stored here.
    blocks_requests:
        Mutex<slab::Slab<oneshot::Sender<Result<Vec<network::protocol::BlockData>, ()>>>>,
}

impl SyncService {
    pub async fn new(mut config: Config) -> Self {
        let (to_foreground, from_background) = mpsc::channel(1024);
        let (to_background, from_foreground) = mpsc::channel(16);

        (config.tasks_executor)(Box::pin(
            start_sync(config.chain_information, from_foreground, to_foreground).await,
        ));

        SyncService {
            to_background: Mutex::new(to_background),
            from_background: Mutex::new(from_background),
            blocks_requests: Mutex::new(slab::Slab::new()),
        }
    }

    /// Registers a new source for blocks.
    pub async fn add_source(&self, peer_id: libp2p::PeerId, best_block_number: u64) {
        self.to_background
            .lock()
            .await
            .send(ToBackground::PeerConnected(peer_id, best_block_number))
            .await
            .unwrap()
    }

    /// Removes a source of blocks.
    pub async fn remove_source(&self, peer_id: libp2p::PeerId) {
        self.to_background
            .lock()
            .await
            .send(ToBackground::PeerDisconnected(peer_id))
            .await
            .unwrap()
    }

    /// Updates the best known block of the source.
    ///
    /// Has no effect if the previously-known best block is lower than the new one.
    pub async fn raise_source_best_block(&self, peer_id: libp2p::PeerId, best_block_number: u64) {
        self.to_background
            .lock()
            .await
            .send(ToBackground::PeerRaiseBest {
                peer_id,
                best_block_number,
            })
            .await
            .unwrap()
    }

    /// Sets the answer to a previously-emitted [`Event::BlocksRequest`].
    ///
    /// After this has been called, the `id` is no longer valid.
    ///
    /// # Panic
    ///
    /// Panics if the `id` is invalid.
    ///
    pub async fn answer_blocks_request(
        &self,
        id: BlocksRequestId,
        response: Result<Vec<network::protocol::BlockData>, ()>,
    ) {
        let _ = self
            .blocks_requests
            .lock()
            .await
            .remove(id.0)
            .send(response);
    }

    /// Returns a string representing the state of the chain using the
    /// [`substrate_lite::database::finalized_serialize`] module.
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

    /// Returns the next event that happened in the sync service.
    ///
    /// If this method is called multiple times simultaneously, the events will be distributed
    /// amongst the different calls in an unpredictable way.
    pub async fn next_event(&self) -> Event {
        loop {
            match self.from_background.lock().await.next().await.unwrap() {
                FromBackground::RequestStart {
                    target,
                    request,
                    send_back,
                } => {
                    let id = BlocksRequestId(self.blocks_requests.lock().await.insert(send_back));
                    return Event::BlocksRequest {
                        id,
                        target,
                        request,
                    };
                }
                FromBackground::NewBest {
                    scale_encoded_header,
                } => {
                    return Event::NewBest {
                        scale_encoded_header,
                    };
                }
                FromBackground::NewFinalized {
                    scale_encoded_header,
                } => {
                    return Event::NewFinalized {
                        scale_encoded_header,
                    };
                }
            }
        }
    }
}

async fn start_sync(
    chain_information: chain::chain_information::ChainInformation,
    mut from_foreground: mpsc::Receiver<ToBackground>,
    mut to_foreground: mpsc::Sender<FromBackground>,
) -> impl Future<Output = ()> {
    let mut sync = optimistic::OptimisticSync::<_, libp2p::PeerId, ()>::new(optimistic::Config {
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
        let mut peers_source_id_map = HashMap::new();
        let mut block_requests_finished = stream::FuturesUnordered::new();

        loop {
            while let Some(action) = sync.next_request_action() {
                match action {
                    optimistic::RequestAction::Start {
                        start,
                        block_height,
                        source,
                        num_blocks,
                        ..
                    } => {
                        let (send_back, rx) = oneshot::channel();

                        let send_result = to_foreground
                            .send(FromBackground::RequestStart {
                                target: source.clone(),
                                request: network::protocol::BlocksRequestConfig {
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
                                send_back,
                            })
                            .await;

                        // If the channel is closed, the sync service has been closed too.
                        if send_result.is_err() {
                            return;
                        }

                        let (rx, abort) = future::abortable(rx);
                        let request_id = start.start(abort);
                        block_requests_finished.push(rx.map(move |r| (request_id, r)));
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
                    optimistic::ProcessOne::NewBest { sync: s, .. }
                    | optimistic::ProcessOne::Reset { sync: s, .. } => {
                        sync = s;

                        let scale_encoded_header = sync.best_block_header().scale_encoding().fold(
                            Vec::new(),
                            |mut a, b| {
                                a.extend_from_slice(b.as_ref());
                                a
                            },
                        );
                        if to_foreground
                            .send(FromBackground::NewBest {
                                scale_encoded_header,
                            })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }

                    optimistic::ProcessOne::Finalized {
                        sync: s,
                        finalized_blocks,
                        ..
                    } => {
                        sync = s;
                        verified_blocks += 1;

                        let scale_encoded_header = finalized_blocks
                            .last()
                            .unwrap()
                            .header
                            .scale_encoding()
                            .fold(Vec::new(), |mut a, b| {
                                a.extend_from_slice(b.as_ref());
                                a
                            });

                        if to_foreground
                            .send(FromBackground::NewBest {
                                scale_encoded_header: scale_encoded_header.clone(),
                            })
                            .await
                            .is_err()
                        {
                            return;
                        }

                        if to_foreground
                            .send(FromBackground::NewFinalized {
                                scale_encoded_header,
                            })
                            .await
                            .is_err()
                        {
                            return;
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
            crate::yield_once().await;

            futures::select! {
                message = from_foreground.next() => {
                    let message = match message {
                        Some(m) => m,
                        None => {
                            return
                        },
                    };

                    match message {
                        ToBackground::PeerConnected(peer_id, best_block_number) => {
                            let id = sync.add_source(peer_id.clone(), best_block_number);
                            peers_source_id_map.insert(peer_id.clone(), id);
                        },
                        ToBackground::PeerDisconnected(peer_id) => {
                            let id = peers_source_id_map.remove(&peer_id).unwrap();
                            let (_, rq_list) = sync.remove_source(id);
                            for (_, rq) in rq_list {
                                rq.abort();
                            }
                        },
                        ToBackground::PeerRaiseBest { peer_id, best_block_number } => {
                            let id = *peers_source_id_map.get(&peer_id).unwrap();
                            sync.raise_source_best_block(id, best_block_number);
                        },
                        ToBackground::Serialize { send_back } => {
                            let chain = sync.as_chain_information();
                            let serialized = substrate_lite::database::finalized_serialize::encode_chain_information(chain);
                            let _ = send_back.send(serialized);
                        }
                    }
                },

                (request_id, result) = block_requests_finished.select_next_some() => {
                    // `result` is an error if the block request got cancelled by the sync state
                    // machine.
                    if let Ok(result) = result {
                        let result = result.map_err(|_| ()).and_then(|v| v);
                        let _ = sync.finish_request(request_id, result.map(|v| v.into_iter().map(|block| optimistic::RequestSuccessBlock {
                            scale_encoded_header: block.header.unwrap(), // TODO: don't unwrap
                            scale_encoded_justification: block.justification,
                            scale_encoded_extrinsics: Vec::new(),
                            user_data: (),
                        })).map_err(|()| optimistic::RequestFail::BlocksUnavailable));
                    }
                },

                _ = async move {
                    if verified_blocks == 0 {
                        loop {
                            futures::pending!()
                        }
                    }
                }.fuse() => {}
            }
        }
    }
}

enum ToBackground {
    PeerConnected(libp2p::PeerId, u64),
    PeerDisconnected(libp2p::PeerId),
    PeerRaiseBest {
        peer_id: libp2p::PeerId,
        best_block_number: u64,
    },
    /// See [`SyncService::serialize_chain`].
    Serialize {
        send_back: oneshot::Sender<String>,
    },
}

/// Messsage sent from the background task and dedicated to the main [`SyncService`]. Processed
/// in [`SyncService::next_event`].
enum FromBackground {
    /// A blocks request must be started.
    RequestStart {
        target: libp2p::PeerId,
        request: network::protocol::BlocksRequestConfig,
        send_back: oneshot::Sender<Result<Vec<network::protocol::BlockData>, ()>>, // TODO: proper error
    },
    /// Current best block has been updated.
    NewBest {
        /// Header of the new best block, in SCALE encoding.
        scale_encoded_header: Vec<u8>,
    },
    /// Current finalized block has been updated.
    NewFinalized {
        /// Header of the new finalized block, in SCALE encoding.
        scale_encoded_header: Vec<u8>,
    },
}
