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

//! Background synchronization service.
//!
//! The [`SyncService`] manages a background task dedicated to synchronizing the chain with the
//! network.
//! Importantly, its design is oriented towards the particular use case of the full node.

// TODO: doc
// TODO: re-review this once finished

use crate::network_service;

use core::{convert::TryFrom as _, num::NonZeroU32, pin::Pin};
use futures::{channel::mpsc, lock::Mutex, prelude::*};
use rand::seq::IteratorRandom as _;
use smoldot::{
    database::full_sqlite,
    executor, header, libp2p, network,
    sync::{all, optimistic},
};
use std::{collections::BTreeMap, num::NonZeroU64, sync::Arc, time::SystemTime};
use tracing::Instrument as _;

/// Configuration for a [`SyncService`].
pub struct Config {
    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(Pin<Box<dyn Future<Output = ()> + Send>>) + Send>,

    /// Database to use to read and write information about the chain.
    pub database: Arc<full_sqlite::SqliteFullDatabase>,

    /// Access to the network, and index of the chain to sync from the point of view of the
    /// network service.
    pub network_service: (Arc<network_service::NetworkService>, usize),

    /// Receiver for events coming from the network, as returned by
    /// [`network_service::NetworkService::new`].
    pub network_events_receiver: mpsc::Receiver<network_service::Event>,
}

/// Identifier for a blocks request to be performed.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct BlocksRequestId(usize);

/// Summary of the state of the [`SyncService`].
#[derive(Debug, Clone)]
pub struct SyncState {
    pub best_block_number: u64,
    pub best_block_hash: [u8; 32],
    pub finalized_block_number: u64,
    pub finalized_block_hash: [u8; 32],
}

/// Background task that verifies blocks and emits requests.
pub struct SyncService {
    /// State kept up-to-date with the background task.
    sync_state: Arc<Mutex<SyncState>>,
}

impl SyncService {
    /// Initializes the [`SyncService`] with the given configuration.
    #[tracing::instrument(skip(config))]
    pub async fn new(mut config: Config) -> Arc<Self> {
        let (to_database, messages_rx) = mpsc::channel(4);

        let finalized_block_hash = config.database.finalized_block_hash().unwrap();
        let best_block_hash = config.database.best_block_hash().unwrap();

        let sync_state = Arc::new(Mutex::new(SyncState {
            best_block_hash,
            best_block_number: header::decode(
                &config
                    .database
                    .block_scale_encoded_header(&best_block_hash)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap()
            .number,
            finalized_block_hash,
            finalized_block_number: header::decode(
                &config
                    .database
                    .block_scale_encoded_header(&finalized_block_hash)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap()
            .number,
        }));

        (config.tasks_executor)(Box::pin(start_sync(
            config.database.clone(),
            sync_state.clone(),
            config.network_service.0,
            config.network_service.1,
            config.network_events_receiver,
            to_database,
        )));

        (config.tasks_executor)(Box::pin(
            start_database_write(config.database, messages_rx).instrument(
                tracing::debug_span!(parent: None, "database-write", root = ?finalized_block_hash), // TDOO: better display
            ),
        ));

        Arc::new(SyncService { sync_state })
    }

    /// Returns a summary of the state of the service.
    ///
    /// > **Important**: This doesn't represent the content of the database.
    // TODO: maybe remove this in favour of the database; seems like a better idea
    #[tracing::instrument(skip(self))]
    pub async fn sync_state(&self) -> SyncState {
        self.sync_state.lock().await.clone()
    }
}

enum ToDatabase {
    FinalizedBlocks(Vec<optimistic::Block<()>>),
}

/// Returns the background task of the sync service.
#[tracing::instrument(skip(
    database,
    sync_state,
    network_service,
    from_network_service,
    to_database
))]
fn start_sync(
    database: Arc<full_sqlite::SqliteFullDatabase>,
    sync_state: Arc<Mutex<SyncState>>,
    network_service: Arc<network_service::NetworkService>,
    network_chain_index: usize,
    mut from_network_service: mpsc::Receiver<network_service::Event>,
    mut to_database: mpsc::Sender<ToDatabase>,
) -> impl Future<Output = ()> {
    // Holds, in parallel of the database, the storage of the latest finalized block.
    // At the time of writing, this state is stable around ~3MiB for Polkadot, meaning that it is
    // completely acceptable to hold it entirely in memory.
    // While reading the storage from the database is an option, doing so considerably slows down
    // the verification, and also makes it impossible to insert blocks in the database in
    // parallel of this verification.
    let mut finalized_block_storage: BTreeMap<Vec<u8>, Vec<u8>> = database
        .finalized_block_storage_top_trie(&database.finalized_block_hash().unwrap())
        .unwrap();

    let mut sync = all::AllSync::<(), libp2p::PeerId, ()>::new(all::Config {
        chain_information: database
            .to_chain_information(&database.finalized_block_hash().unwrap())
            .unwrap(),
        sources_capacity: 32,
        blocks_capacity: {
            // This is the maximum number of blocks between two consecutive justifications.
            1024
        },
        max_disjoint_headers: 1024,
        max_requests_per_block: NonZeroU32::new(3).unwrap(),
        download_ahead_blocks: {
            // Assuming a verification speed of 1k blocks/sec and a 95% latency of one second,
            // the number of blocks to download ahead of time in order to not block is 1000.
            1024
        },
        full: Some(all::ConfigFull {
            finalized_runtime: {
                // Builds the runtime of the finalized block.
                // Assumed to always be valid, otherwise the block wouldn't have been saved in the
                // database, hence the large number of unwraps here.
                let module = finalized_block_storage.get(&b":code"[..]).unwrap();
                let heap_pages = executor::storage_heap_pages_to_value(
                    finalized_block_storage
                        .get(&b":heappages"[..])
                        .map(|v| &v[..]),
                )
                .unwrap();
                executor::host::HostVmPrototype::new(
                    module,
                    heap_pages,
                    executor::vm::ExecHint::CompileAheadOfTime, // TODO: probably should be decided by the optimisticsync
                )
                .unwrap()
            },
        }),
    });

    async move {
        let mut peers_source_id_map = hashbrown::HashMap::<_, _, fnv::FnvBuildHasher>::default();
        let mut block_requests_finished = stream::FuturesUnordered::new();

        // TODO: remove; should store the aborthandle in the TRq user data instead
        let mut pending_requests = hashbrown::HashMap::<_, _, fnv::FnvBuildHasher>::default();

        loop {
            // Drain the content of `requests_to_start` to actually start the requests that have
            // been queued by the previous iteration of the main loop.
            //
            // Note that the code below assumes that the `source_id`s found in `requests_to_start`
            // still exist. This is only guaranteed to be case because we process
            // `requests_to_start` as soon as an entry is added and before disconnect events can
            // remove sources from the state machine.
            loop {
                let (source_id, mut request) =
                    match sync.desired_requests().choose(&mut rand::thread_rng()) {
                        Some(v) => v,
                        None => break,
                    };

                // Before notifying the syncing of the request, clamp the number of blocks to the
                // number of blocks we expect to receive.
                request.num_blocks_clamp(NonZeroU64::new(128).unwrap());

                let request_id = sync.add_request(source_id, request.clone(), ());

                match request {
                    all::RequestDetail::BlocksRequest {
                        first_block_hash,
                        first_block_height,
                        ascending,
                        num_blocks,
                        request_headers,
                        request_bodies,
                        request_justification,
                    } => {
                        let peer_id = sync.source_user_data_mut(source_id).clone();

                        let request = network_service.clone().blocks_request(
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

                        let (request, abort) = future::abortable(request);
                        pending_requests.insert(request_id, abort);

                        block_requests_finished.push(request.map(move |r| (request_id, r)));
                    }
                    all::RequestDetail::GrandpaWarpSync { .. }
                    | all::RequestDetail::StorageGet { .. } => {
                        // Not used in "full" mode.
                        unreachable!()
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
                let unix_time = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap();

                match sync.process_one() {
                    all::ProcessOne::AllSync(idle) => {
                        sync = idle;
                        break;
                    }
                    all::ProcessOne::VerifyWarpSyncFragment(_) => unreachable!(),
                    all::ProcessOne::VerifyBodyHeader(verify) => {
                        let mut verify = verify.start(unix_time, ());
                        loop {
                            match verify {
                                all::BlockVerification::Error {
                                    sync: sync_out,
                                    error,
                                    ..
                                } => {
                                    tracing::warn!(%error, "failed-block-verification");
                                    sync = sync_out;
                                    break;
                                }
                                all::BlockVerification::Finalized {
                                    sync: sync_out,
                                    finalized_blocks,
                                } => {
                                    // Processing has made a step forward.
                                    // There is nothing to do, but this is used to update the
                                    // best block shown on the informant.
                                    let mut lock = sync_state.lock().await;
                                    lock.best_block_hash = sync_out.best_block_hash();
                                    lock.best_block_number = sync_out.best_block_number();
                                    drop(lock);

                                    if let Some(last_finalized) = finalized_blocks.last() {
                                        let mut lock = sync_state.lock().await;
                                        lock.finalized_block_hash = last_finalized.header.hash();
                                        lock.finalized_block_number = last_finalized.header.number;
                                    }

                                    // TODO: maybe write in a separate task? but then we can't access the finalized storage immediately after?
                                    for block in &finalized_blocks {
                                        for (key, value) in &block.storage_top_trie_changes {
                                            if let Some(value) = value {
                                                finalized_block_storage
                                                    .insert(key.clone(), value.clone());
                                            } else {
                                                let _was_there =
                                                    finalized_block_storage.remove(key);
                                                // TODO: if a block inserts a new value, then removes it in the next block, the key will remain in `finalized_block_storage`; either solve this or document this
                                                // assert!(_was_there.is_some());
                                            }
                                        }
                                    }

                                    to_database
                                        .send(ToDatabase::FinalizedBlocks(finalized_blocks))
                                        .await
                                        .unwrap();

                                    sync = sync_out;
                                    break;
                                }
                                all::BlockVerification::Success {
                                    is_new_best: true,
                                    sync: sync_out,
                                    ..
                                } => {
                                    // Processing has made a step forward.
                                    // There is nothing to do, but this is used to update to best block
                                    // shown on the informant.
                                    let mut lock = sync_state.lock().await;
                                    lock.best_block_hash = sync_out.best_block_hash();
                                    lock.best_block_number = sync_out.best_block_number();
                                    drop(lock);

                                    sync = sync_out;
                                    break;
                                }
                                all::BlockVerification::Success { sync: sync_out, .. } => {
                                    sync = sync_out;
                                    break;
                                }

                                all::BlockVerification::FinalizedStorageGet(req) => {
                                    let value = finalized_block_storage
                                        .get(&req.key_as_vec())
                                        .map(|v| &v[..]);
                                    verify = req.inject_value(value);
                                }
                                all::BlockVerification::FinalizedStorageNextKey(req) => {
                                    // TODO: to_vec() :-/
                                    let req_key = req.key().as_ref().to_vec();
                                    // TODO: to_vec() :-/
                                    let next_key = finalized_block_storage
                                        .range(req.key().as_ref().to_vec()..)
                                        .find(move |(k, _)| k[..] > req_key[..])
                                        .map(|(k, _)| k);
                                    verify = req.inject_key(next_key);
                                }
                                all::BlockVerification::FinalizedStoragePrefixKeys(req) => {
                                    // TODO: to_vec() :-/
                                    let prefix = req.prefix().as_ref().to_vec();
                                    // TODO: to_vec() :-/
                                    let keys = finalized_block_storage
                                        .range(req.prefix().as_ref().to_vec()..)
                                        .take_while(|(k, _)| k.starts_with(&prefix))
                                        .map(|(k, _)| k);
                                    verify = req.inject_keys_ordered(keys);
                                }
                            }
                        }
                    }
                    all::ProcessOne::VerifyHeader(verify) => {
                        match verify.perform(unix_time, ()) {
                            all::HeaderVerifyOutcome::Success { sync: sync_out, .. } => {
                                sync = sync_out;
                                continue;
                            }
                            all::HeaderVerifyOutcome::Error {
                                sync: sync_out,
                                error,
                                ..
                            } => {
                                // TODO: print block info
                                tracing::warn!(%error, "failed-block-verification");

                                sync = sync_out;
                                continue;
                            }
                        }
                    }
                }
            }

            // Update the current best block, used for CLI-related purposes.
            {
                let mut lock = sync_state.lock().await;
                lock.best_block_hash = sync.best_block_hash();
                lock.best_block_number = sync.best_block_number();
            }

            futures::select! {
                network_event = from_network_service.next() => {
                    let network_event = match network_event {
                        Some(m) => m,
                        None => return,
                    };

                    match network_event {
                        network_service::Event::Connected { peer_id, chain_index, best_block_number, best_block_hash }
                            if chain_index == network_chain_index =>
                        {
                            let id = sync.add_source(peer_id.clone(), best_block_number, best_block_hash);
                            peers_source_id_map.insert(peer_id, id);
                        },
                        network_service::Event::Disconnected { peer_id, chain_index }
                            if chain_index == network_chain_index =>
                        {
                            let id = peers_source_id_map.remove(&peer_id).unwrap();
                            let (_, requests) = sync.remove_source(id);
                            for (request_id, _) in requests {
                                pending_requests.remove(&request_id).unwrap().abort();
                            }
                        },
                        network_service::Event::BlockAnnounce { chain_index, peer_id, announce }
                            if chain_index == network_chain_index =>
                        {
                            let id = *peers_source_id_map.get(&peer_id).unwrap();
                            let decoded = announce.decode();
                            // TODO: stupid to re-encode header
                            // TODO: log the outcome
                            match sync.block_announce(id, decoded.header.scale_encoding_vec(), decoded.is_best) {
                                all::BlockAnnounceOutcome::HeaderVerify => {},
                                all::BlockAnnounceOutcome::TooOld { .. } => {},
                                all::BlockAnnounceOutcome::AlreadyInChain => {},
                                all::BlockAnnounceOutcome::NotFinalizedChain => {},
                                all::BlockAnnounceOutcome::InvalidHeader(_) => {},
                                all::BlockAnnounceOutcome::Disjoint {} => {
                                },
                            }
                        },
                        _ => {
                            // Different chain index.
                        }
                    }
                },

                (request_id, result) = block_requests_finished.select_next_some() => {
                    // `result` is an error if the block request got cancelled by the sync state
                    // machine.
                    // TODO: clarify this piece of code
                    if let Ok(result) = result {
                        let result = result.map_err(|_| ());
                        let response_outcome = sync.blocks_request_response(request_id, result.map(|v| v.into_iter().map(|block| all::BlockRequestSuccessBlock {
                            scale_encoded_header: block.header.unwrap(), // TODO: don't unwrap
                            scale_encoded_extrinsics: block.body.unwrap(), // TODO: don't unwrap
                            scale_encoded_justification: block.justification,
                            user_data: (),
                        })));

                        match response_outcome {
                            all::ResponseOutcome::Queued
                            | all::ResponseOutcome::NotFinalizedChain { .. }
                            | all::ResponseOutcome::AllAlreadyInChain { .. } => {
                            }
                            all::ResponseOutcome::WarpSyncFinished { .. } => {
                                unreachable!()
                            }
                        }
                    }
                },
            }
        }
    }
}

/// Starts the task that writes blocks to the database.
#[tracing::instrument(skip(database, messages_rx))]
async fn start_database_write(
    database: Arc<full_sqlite::SqliteFullDatabase>,
    mut messages_rx: mpsc::Receiver<ToDatabase>,
) {
    loop {
        match messages_rx.next().await {
            None => break,
            Some(ToDatabase::FinalizedBlocks(finalized_blocks)) => {
                let span = tracing::trace_span!("blocks-db-write", len = finalized_blocks.len());
                let _enter = span.enter();

                let new_finalized_hash = finalized_blocks.last().map(|lf| lf.header.hash());

                for block in finalized_blocks {
                    // TODO: overhead for building the SCALE encoding of the header
                    let result = database.insert(
                        &block.header.scale_encoding().fold(Vec::new(), |mut a, b| {
                            a.extend_from_slice(b.as_ref());
                            a
                        }),
                        true, // TODO: is_new_best?
                        block.body.iter(),
                        block
                            .storage_top_trie_changes
                            .iter()
                            .map(|(k, v)| (k, v.as_ref())),
                    );

                    match result {
                        Ok(()) => {}
                        Err(full_sqlite::InsertError::Duplicate) => {} // TODO: this should be an error ; right now we silence them because non-finalized blocks aren't loaded from the database at startup, resulting in them being downloaded again
                        Err(err) => panic!("{}", err),
                    }
                }

                if let Some(new_finalized_hash) = new_finalized_hash {
                    database.set_finalized(&new_finalized_hash).unwrap();
                }
            }
        }
    }
}
