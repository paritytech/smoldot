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

//! Background network service.
//!
//! The [`NetworkService`] manages background tasks dedicated to connecting to other nodes.
//! Importantly, its design is oriented towards the particular use case of the light client.
//!
//! The [`NetworkService`] spawns one background task (using the [`Config::tasks_executor`]) for
//! each active connection.
//!
//! The objective of the [`NetworkService`] in general is to try stay connected as much as
//! possible to the nodes of the peer-to-peer network of the chain, and maintain open substreams
//! with them in order to send out requests (e.g. block requests) and notifications (e.g. block
//! announces).
//!
//! Connectivity to the network is performed in the background as an implementation detail of
//! the service. The public API only allows emitting requests and notifications towards the
//! already-connected nodes.
//!
//! An important part of the API is the list of channel receivers of [`Event`] returned by
//! [`NetworkService::new`]. These channels inform the foreground about updates to the network
//! connectivity.

use crate::platform::Platform;

use alloc::{
    boxed::Box,
    string::{String, ToString as _},
    sync::Arc,
    vec::Vec,
};
use core::{cmp, num::NonZeroUsize, pin::Pin, task::Poll, time::Duration};
use futures::{
    channel::{mpsc, oneshot},
    lock::Mutex,
    prelude::*,
};
use hashbrown::{hash_map, HashMap, HashSet};
use itertools::Itertools as _;
use smoldot::{
    header,
    informant::{BytesDisplay, HashDisplay},
    libp2p::{connection, multiaddr::Multiaddr, peer_id::PeerId, peers},
    network::{protocol, service},
};

pub use service::EncodedMerkleProof;

mod tasks;

/// Configuration for a [`NetworkService`].
pub struct Config {
    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(String, future::BoxFuture<'static, ()>) + Send>,

    /// Key to use for the encryption layer of all the connections. Gives the node its identity.
    pub noise_key: connection::NoiseKey,

    /// Number of event receivers returned by [`NetworkService::new`].
    pub num_events_receivers: usize,

    /// List of chains to connect to. Chains are later referred to by their index in this list.
    pub chains: Vec<ConfigChain>,
}

/// See [`Config::chains`].
///
/// Note that this configuration is intentionally missing a field containing the bootstrap
/// nodes of the chain. Bootstrap nodes are supposed to be added afterwards by calling
/// [`NetworkService::discover`].
pub struct ConfigChain {
    /// Name of the chain, for logging purposes.
    pub log_name: String,

    /// Hash of the genesis block of the chain. Sent to other nodes in order to determine whether
    /// the chains match.
    ///
    /// > **Note**: Be aware that this *must* be the *genesis* block, not any block known to be
    /// >           in the chain.
    pub genesis_block_hash: [u8; 32],

    /// Number of the finalized block at the time of the initialization.
    pub finalized_block_height: u64,

    /// Number and hash of the current best block. Can later be updated with
    /// [`NetworkService::set_local_best_block`].
    pub best_block: (u64, [u8; 32]),

    /// Identifier of the chain to connect to.
    ///
    /// Each blockchain has (or should have) a different "protocol id". This value identifies the
    /// chain, so as to not introduce conflicts in the networking messages.
    pub protocol_id: String,

    /// Number of bytes of the block number in the networking protocol.
    pub block_number_bytes: usize,

    /// If true, the chain uses the GrandPa networking protocol.
    pub has_grandpa_protocol: bool,
}

pub struct NetworkService<TPlat: Platform> {
    /// Struct shared between the foreground and background.
    shared: Arc<Shared<TPlat>>,

    /// List of handles that abort all the background tasks.
    abort_handles: Vec<future::AbortHandle>,
}

/// Struct shared between the foreground and background.
struct Shared<TPlat: Platform> {
    /// Fields protected by a mutex.
    guarded: Mutex<SharedGuarded<TPlat>>,

    /// Names of the various chains the network service connects to. Used only for logging
    /// purposes.
    log_chain_names: Vec<String>,

    /// Event to notify when the background task needs to be waken up.
    ///
    /// Waking up this event guarantees a full loop of the background task. In other words,
    /// if the event is notified while the background task is already awake, the background task
    /// will do an additional loop.
    wake_up_main_background_task: event_listener::Event,
}

struct SharedGuarded<TPlat: Platform> {
    /// Data structure holding the entire state of the networking.
    network: service::ChainNetwork<TPlat::Instant>,

    /// List of nodes that are considered as important for logging purposes.
    // TODO: should also detect whenever we fail to open a block announces substream with any of these peers
    important_nodes: HashSet<PeerId, fnv::FnvBuildHasher>,

    /// List of peer and chain index tuples for which no outbound slot should be assigned.
    ///
    /// The values are the moment when the ban expires.
    // TODO: use SipHasher
    slots_assign_backoff: HashMap<(PeerId, usize), TPlat::Instant, fnv::FnvBuildHasher>,

    messages_from_connections_tx:
        mpsc::Sender<(service::ConnectionId, service::ConnectionToCoordinator)>,

    messages_from_connections_rx:
        mpsc::Receiver<(service::ConnectionId, service::ConnectionToCoordinator)>,

    /// Channel where new tasks can be sent in order to be executed asynchronously.
    new_tasks_tx: mpsc::Sender<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,

    active_connections: HashMap<
        service::ConnectionId,
        mpsc::Sender<service::CoordinatorToConnection<TPlat::Instant>>,
        fnv::FnvBuildHasher,
    >,

    blocks_requests: HashMap<
        service::OutRequestId,
        oneshot::Sender<Result<Vec<protocol::BlockData>, service::BlocksRequestError>>,
        fnv::FnvBuildHasher,
    >,

    grandpa_warp_sync_requests: HashMap<
        service::OutRequestId,
        oneshot::Sender<
            Result<protocol::GrandpaWarpSyncResponse, service::GrandpaWarpSyncRequestError>,
        >,
        fnv::FnvBuildHasher,
    >,

    storage_proof_requests: HashMap<
        service::OutRequestId,
        oneshot::Sender<Result<service::EncodedMerkleProof, service::StorageProofRequestError>>,
        fnv::FnvBuildHasher,
    >,

    call_proof_requests: HashMap<
        service::OutRequestId,
        oneshot::Sender<Result<service::EncodedMerkleProof, service::CallProofRequestError>>,
        fnv::FnvBuildHasher,
    >,

    kademlia_discovery_operations:
        HashMap<service::KademliaOperationId, usize, fnv::FnvBuildHasher>,
}

impl<TPlat: Platform> NetworkService<TPlat> {
    /// Initializes the network service with the given configuration.
    ///
    /// Returns the networking service, plus a list of receivers on which events are pushed.
    /// All of these receivers must be polled regularly to prevent the networking service from
    /// slowing down.
    pub async fn new(mut config: Config) -> (Arc<Self>, Vec<stream::BoxStream<'static, Event>>) {
        let (event_senders, event_receivers): (Vec<_>, Vec<_>) = (0..config.num_events_receivers)
            .map(|_| mpsc::channel(16))
            .unzip();

        let num_chains = config.chains.len();
        let mut chains = Vec::with_capacity(num_chains);
        let mut log_chain_names = Vec::with_capacity(num_chains);

        for chain in config.chains {
            chains.push(service::ChainConfig {
                in_slots: 3,
                out_slots: 4,
                grandpa_protocol_config: if chain.has_grandpa_protocol {
                    // TODO: dummy values
                    Some(service::GrandpaState {
                        commit_finalized_height: chain.finalized_block_height,
                        round_number: 1,
                        set_id: 0,
                    })
                } else {
                    None
                },
                protocol_id: chain.protocol_id.clone(),
                block_number_bytes: chain.block_number_bytes,
                best_hash: chain.best_block.1,
                best_number: chain.best_block.0,
                genesis_hash: chain.genesis_block_hash,
                role: protocol::Role::Light,
                allow_inbound_block_requests: false,
            });

            log_chain_names.push(chain.log_name);
        }

        let mut abort_handles = Vec::new();

        let (messages_from_connections_tx, messages_from_connections_rx) = mpsc::channel(32);
        let (new_tasks_tx, mut new_tasks_rx) = mpsc::channel(8);

        let shared = Arc::new(Shared {
            guarded: Mutex::new(SharedGuarded {
                network: service::ChainNetwork::new(service::Config {
                    now: TPlat::now(),
                    chains,
                    connections_capacity: 32,
                    peers_capacity: 8,
                    max_addresses_per_peer: NonZeroUsize::new(5).unwrap(),
                    noise_key: config.noise_key,
                    handshake_timeout: Duration::from_secs(8),
                    randomness_seed: rand::random(),
                }),
                slots_assign_backoff: HashMap::with_capacity_and_hasher(32, Default::default()),
                important_nodes: HashSet::with_capacity_and_hasher(16, Default::default()),
                active_connections: HashMap::with_capacity_and_hasher(32, Default::default()),
                messages_from_connections_tx,
                messages_from_connections_rx,
                new_tasks_tx,
                blocks_requests: HashMap::with_capacity_and_hasher(8, Default::default()),
                grandpa_warp_sync_requests: HashMap::with_capacity_and_hasher(
                    8,
                    Default::default(),
                ),
                storage_proof_requests: HashMap::with_capacity_and_hasher(8, Default::default()),
                call_proof_requests: HashMap::with_capacity_and_hasher(8, Default::default()),
                kademlia_discovery_operations: HashMap::with_capacity_and_hasher(
                    2,
                    Default::default(),
                ),
            }),
            log_chain_names,
            wake_up_main_background_task: event_listener::Event::new(),
        });

        // Spawn main task that processes the network service.
        (config.tasks_executor)(
            "network-service".into(),
            Box::pin({
                let shared = shared.clone();
                let future = background_task(shared, event_senders);

                let (abortable, abort_handle) = future::abortable(future);
                abort_handles.push(abort_handle);
                abortable.map(|_| ())
            }),
        );

        // Spawn task starts a discovery request at a periodic interval.
        // This is done through a separate task due to ease of implementation.
        (config.tasks_executor)(
            "network-discovery".into(),
            Box::pin({
                let shared = shared.clone();
                let future = async move {
                    let mut next_discovery = Duration::from_secs(5);

                    loop {
                        TPlat::sleep(next_discovery).await;
                        next_discovery = cmp::min(next_discovery * 2, Duration::from_secs(120));

                        let mut guarded = shared.guarded.lock().await;
                        for chain_index in 0..shared.log_chain_names.len() {
                            let operation_id = guarded
                                .network
                                .start_kademlia_discovery_round(TPlat::now(), chain_index);

                            let _prev_value = guarded
                                .kademlia_discovery_operations
                                .insert(operation_id, chain_index);
                            debug_assert!(_prev_value.is_none());
                        }

                        // Starting requests has generated messages. Wake up the main task so that
                        // these messages are dispatched.
                        shared.wake_up_main_background_task.notify(1);
                    }
                };

                let (abortable, abort_handle) = future::abortable(future);
                abort_handles.push(abort_handle);
                abortable.map(|_| ())
            }),
        );

        // Spawn task dedicated to processing existing connections.
        (config.tasks_executor)(
            "connections".into(),
            Box::pin({
                let future = async move {
                    let mut connections = stream::FuturesUnordered::new();
                    loop {
                        futures::select! {
                            new_connec = new_tasks_rx.select_next_some() => {
                                connections.push(new_connec);
                            },
                            () = connections.select_next_some() => {},
                        }
                    }
                };

                let (abortable, abort_handle) = future::abortable(future);
                abort_handles.push(abort_handle);
                abortable.map(|_| ())
            }),
        );

        abort_handles.shrink_to_fit();
        let final_network_service = Arc::new(NetworkService {
            shared,
            abort_handles,
        });

        // Adjust the event receivers to keep the `final_network_service` alive.
        let event_receivers = event_receivers
            .into_iter()
            .map(|rx| {
                let mut final_network_service = Some(final_network_service.clone());
                rx.chain(stream::poll_fn(move |_| {
                    drop(final_network_service.take());
                    Poll::Ready(None)
                }))
                .boxed()
            })
            .collect();

        (final_network_service, event_receivers)
    }

    /// Sends a blocks request to the given peer.
    // TODO: more docs
    pub async fn blocks_request(
        self: Arc<Self>,
        target: PeerId, // TODO: takes by value because of future longevity issue
        chain_index: usize,
        config: protocol::BlocksRequestConfig,
        timeout: Duration,
    ) -> Result<Vec<protocol::BlockData>, BlocksRequestError> {
        let rx = {
            let mut guarded = self.shared.guarded.lock().await;

            // The call to `start_blocks_request` below panics if we have no active connection.
            if !guarded.network.can_start_requests(&target) {
                return Err(BlocksRequestError::NoConnection);
            }

            match &config.start {
                protocol::BlocksRequestConfigStart::Hash(hash) => {
                    log::debug!(
                        target: "network",
                        "Connection({}) <= BlocksRequest(chain={}, start={}, num={}, descending={:?}, header={:?}, body={:?}, justifications={:?})",
                        target, self.shared.log_chain_names[chain_index], HashDisplay(hash),
                        config.desired_count.get(),
                        matches!(config.direction, protocol::BlocksRequestDirection::Descending),
                        config.fields.header, config.fields.body, config.fields.justifications
                    );
                }
                protocol::BlocksRequestConfigStart::Number(number) => {
                    log::debug!(
                        target: "network",
                        "Connection({}) <= BlocksRequest(chain={}, start=#{}, num={}, descending={:?}, header={:?}, body={:?}, justifications={:?})",
                        target, self.shared.log_chain_names[chain_index], number,
                        config.desired_count.get(),
                        matches!(config.direction, protocol::BlocksRequestDirection::Descending),
                        config.fields.header, config.fields.body, config.fields.justifications
                    );
                }
            }

            let request_id = guarded.network.start_blocks_request(
                TPlat::now(),
                &target,
                chain_index,
                config,
                timeout,
            );

            self.shared.wake_up_main_background_task.notify(1);

            let (tx, rx) = oneshot::channel();
            guarded.blocks_requests.insert(request_id, tx);
            rx
        };

        let result = rx.await.unwrap();

        match &result {
            Ok(blocks) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => BlocksRequest(chain={}, num_blocks={}, block_data_total_size={})",
                    target,
                    self.shared.log_chain_names[chain_index],
                    blocks.len(),
                    BytesDisplay(blocks.iter().fold(0, |sum, block| {
                        let block_size = block.header.as_ref().map_or(0, |h| h.len()) +
                            block.body.as_ref().map_or(0, |b| b.iter().fold(0, |s, e| s + e.len())) +
                            block.justifications.as_ref().into_iter().flat_map(|l| l.iter()).fold(0, |s, j| s + j.1.len());
                        sum + u64::try_from(block_size).unwrap()
                    }))
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => BlocksRequest(chain={}, error={:?})",
                    target,
                    self.shared.log_chain_names[chain_index],
                    err
                );
            }
        }

        if !log::log_enabled!(log::Level::Debug) {
            match &result {
                Ok(_)
                | Err(service::BlocksRequestError::EmptyResponse)
                | Err(service::BlocksRequestError::NotVerifiable) => {}
                Err(service::BlocksRequestError::Request(err)) if !err.is_protocol_error() => {}
                Err(err) => {
                    log::warn!(
                        target: "network",
                        "Error in block request with {}. This might indicate an incompatibility. Error: {}",
                        target,
                        err
                    );
                }
            }
        }

        result.map_err(BlocksRequestError::Request)
    }

    /// Sends a grandpa warp sync request to the given peer.
    // TODO: more docs
    pub async fn grandpa_warp_sync_request(
        self: Arc<Self>,
        target: PeerId, // TODO: takes by value because of future longevity issue
        chain_index: usize,
        begin_hash: [u8; 32],
        timeout: Duration,
    ) -> Result<protocol::GrandpaWarpSyncResponse, GrandpaWarpSyncRequestError> {
        let rx = {
            let mut guarded = self.shared.guarded.lock().await;

            // The call to `start_grandpa_warp_sync_request` below panics if we have no
            // active connection.
            if !guarded.network.can_start_requests(&target) {
                return Err(GrandpaWarpSyncRequestError::NoConnection);
            }

            log::debug!(
                target: "network", "Connection({}) <= GrandpaWarpSyncRequest(chain={}, start={})",
                target, self.shared.log_chain_names[chain_index], HashDisplay(&begin_hash)
            );

            let request_id = guarded.network.start_grandpa_warp_sync_request(
                TPlat::now(),
                &target,
                chain_index,
                begin_hash,
                timeout,
            );

            self.shared.wake_up_main_background_task.notify(1);

            let (tx, rx) = oneshot::channel();
            guarded.grandpa_warp_sync_requests.insert(request_id, tx);
            rx
        };

        let result = rx.await.unwrap();

        match &result {
            Ok(response) => {
                // TODO: print total bytes size
                log::debug!(
                    target: "network",
                    "Connection({}) => GrandpaWarpSyncRequest(chain={}, num_fragments={}, finished={:?})",
                    target,
                    self.shared.log_chain_names[chain_index],
                    response.fragments.len(),
                    response.is_finished,
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => GrandpaWarpSyncRequest(chain={}, error={:?})",
                    target,
                    self.shared.log_chain_names[chain_index],
                    err,
                );
            }
        }

        result.map_err(GrandpaWarpSyncRequestError::Request)
    }

    pub async fn set_local_best_block(
        &self,
        chain_index: usize,
        best_hash: [u8; 32],
        best_number: u64,
    ) {
        self.shared
            .guarded
            .lock()
            .await
            .network
            .set_local_best_block(chain_index, best_hash, best_number)
    }

    pub async fn set_local_grandpa_state(
        &self,
        chain_index: usize,
        grandpa_state: service::GrandpaState,
    ) {
        log::debug!(
            target: "network",
            "Chain({}) <= SetLocalGrandpaState(set_id: {}, commit_finalized_height: {})",
            self.shared.log_chain_names[chain_index],
            grandpa_state.set_id,
            grandpa_state.commit_finalized_height,
        );

        // TODO: log the list of peers we sent the packet to

        self.shared
            .guarded
            .lock()
            .await
            .network
            .set_local_grandpa_state(chain_index, grandpa_state)
    }

    /// Sends a storage proof request to the given peer.
    // TODO: more docs
    pub async fn storage_proof_request(
        self: Arc<Self>,
        chain_index: usize,
        target: PeerId, // TODO: takes by value because of futures longevity issue
        config: protocol::StorageProofRequestConfig<impl Iterator<Item = impl AsRef<[u8]> + Clone>>,
        timeout: Duration,
    ) -> Result<service::EncodedMerkleProof, StorageProofRequestError> {
        let rx = {
            let mut guarded = self.shared.guarded.lock().await;

            // The call to `start_storage_proof_request` below panics if we have no active
            // connection.
            if !guarded.network.can_start_requests(&target) {
                return Err(StorageProofRequestError::NoConnection);
            }

            log::debug!(
                target: "network",
                "Connection({}) <= StorageProofRequest(chain={}, block={})",
                target,
                self.shared.log_chain_names[chain_index],
                HashDisplay(&config.block_hash)
            );

            let request_id = guarded.network.start_storage_proof_request(
                TPlat::now(),
                &target,
                chain_index,
                config,
                timeout,
            );

            self.shared.wake_up_main_background_task.notify(1);

            let (tx, rx) = oneshot::channel();
            guarded.storage_proof_requests.insert(request_id, tx);
            rx
        };

        let result = rx.await.unwrap();

        match &result {
            Ok(items) => {
                let decoded = items.decode();
                log::debug!(
                    target: "network",
                    "Connection({}) => StorageProofRequest(chain={}, num_elems={}, total_size={})",
                    target,
                    self.shared.log_chain_names[chain_index],
                    decoded.len(),
                    BytesDisplay(decoded.iter().fold(0, |a, b| a + u64::try_from(b.len()).unwrap()))
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => StorageProofRequest(chain={}, error={:?})",
                    target,
                    self.shared.log_chain_names[chain_index],
                    err
                );
            }
        }

        result.map_err(StorageProofRequestError::Request)
    }

    /// Sends a call proof request to the given peer.
    ///
    /// See also [`NetworkService::call_proof_request`].
    // TODO: more docs
    pub async fn call_proof_request<'a>(
        self: Arc<Self>,
        chain_index: usize,
        target: PeerId, // TODO: takes by value because of futures longevity issue
        config: protocol::CallProofRequestConfig<'a, impl Iterator<Item = impl AsRef<[u8]>>>,
        timeout: Duration,
    ) -> Result<EncodedMerkleProof, CallProofRequestError> {
        let rx = {
            let mut guarded = self.shared.guarded.lock().await;

            // The call to `start_call_proof_request` below panics if we have no active connection.
            if !guarded.network.can_start_requests(&target) {
                return Err(CallProofRequestError::NoConnection);
            }

            log::debug!(
                target: "network",
                "Connection({}) <= CallProofRequest({}, {}, {})",
                target,
                self.shared.log_chain_names[chain_index],
                HashDisplay(&config.block_hash),
                config.method
            );

            let request_id = guarded.network.start_call_proof_request(
                TPlat::now(),
                &target,
                chain_index,
                config,
                timeout,
            );

            self.shared.wake_up_main_background_task.notify(1);

            let (tx, rx) = oneshot::channel();
            guarded.call_proof_requests.insert(request_id, tx);
            rx
        };

        let result = rx.await.unwrap();

        match &result {
            Ok(items) => {
                let decoded = items.decode();
                log::debug!(
                    target: "network",
                    "Connection({}) => CallProofRequest({}, num_elems: {}, total_size: {})",
                    target,
                    self.shared.log_chain_names[chain_index],
                    decoded.len(),
                    BytesDisplay(decoded.iter().fold(0, |a, b| a + u64::try_from(b.len()).unwrap()))
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => CallProofRequest({}, {})",
                    target,
                    self.shared.log_chain_names[chain_index],
                    err
                );
            }
        }

        result.map_err(CallProofRequestError::Request)
    }

    /// Announces transaction to the peers we are connected to.
    ///
    /// Returns a list of peers that we have sent the transaction to. Can return an empty `Vec`
    /// if we didn't send the transaction to any peer.
    ///
    /// Note that the remote doesn't confirm that it has received the transaction. Because
    /// networking is inherently unreliable, successfully sending a transaction to a peer doesn't
    /// necessarily mean that the remote has received it. In practice, however, the likelihood of
    /// a transaction not being received are extremely low. This can be considered as known flaw.
    pub async fn announce_transaction(
        self: Arc<Self>,
        chain_index: usize,
        transaction: &[u8],
    ) -> Vec<PeerId> {
        let mut sent_peers = Vec::with_capacity(16); // TODO: capacity?

        // TODO: keep track of which peer knows about which transaction, and don't send it again

        let mut guarded = self.shared.guarded.lock().await;

        // TODO: collecting in a Vec :-/
        for peer in guarded
            .network
            .opened_transactions_substream(chain_index)
            .cloned()
            .collect::<Vec<_>>()
        {
            if guarded
                .network
                .announce_transaction(&peer, chain_index, transaction)
                .is_ok()
            {
                sent_peers.push(peer);
            };
        }

        self.shared.wake_up_main_background_task.notify(1);

        sent_peers
    }

    /// See [`service::ChainNetwork::send_block_announce`].
    pub async fn send_block_announce(
        self: Arc<Self>,
        target: &PeerId,
        chain_index: usize,
        scale_encoded_header: &[u8],
        is_best: bool,
    ) -> Result<(), QueueNotificationError> {
        let mut guarded = self.shared.guarded.lock().await;

        // The call to `send_block_announce` below panics if we have no active substream.
        if !guarded
            .network
            .can_send_block_announces(target, chain_index)
        {
            return Err(QueueNotificationError::NoConnection);
        }

        let result = guarded
            .network
            .send_block_announce(&target, chain_index, scale_encoded_header, is_best)
            .map_err(QueueNotificationError::Queue);

        self.shared.wake_up_main_background_task.notify(1);

        result
    }

    /// See [`service::ChainNetwork::discover`].
    ///
    /// The `important_nodes` parameter indicates whether these nodes are considered note-worthy
    /// and should have additional logging.
    pub async fn discover(
        &self,
        now: &TPlat::Instant,
        chain_index: usize,
        list: impl IntoIterator<Item = (PeerId, impl IntoIterator<Item = Multiaddr>)>,
        important_nodes: bool,
    ) {
        let mut guarded = self.shared.guarded.lock().await;

        for (peer_id, addrs) in list {
            if important_nodes {
                guarded.important_nodes.insert(peer_id.clone());
            }

            guarded.network.discover(now, chain_index, peer_id, addrs);
        }

        self.shared.wake_up_main_background_task.notify(1);
    }

    /// Returns a list of nodes (their [`PeerId`] and multiaddresses) that we know are part of
    /// the network.
    ///
    /// Nodes that are discovered might disappear over time. In other words, there is no guarantee
    /// that a node that has been added through [`NetworkService::discover`] will later be
    /// returned by [`NetworkService::discovered_nodes`].
    pub async fn discovered_nodes(
        &self,
        chain_index: usize,
    ) -> impl Iterator<Item = (PeerId, impl Iterator<Item = Multiaddr>)> {
        let guarded = self.shared.guarded.lock().await;
        guarded
            .network
            .discovered_nodes(chain_index)
            .map(|(peer_id, addresses)| {
                (
                    peer_id.clone(),
                    addresses.cloned().collect::<Vec<_>>().into_iter(),
                )
            })
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Returns an iterator to the list of [`PeerId`]s that we have an established connection
    /// with.
    pub async fn peers_list(&self) -> impl Iterator<Item = PeerId> {
        self.shared
            .guarded
            .lock()
            .await
            .network
            .peers_list()
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
    }
}

impl<TPlat: Platform> Drop for NetworkService<TPlat> {
    fn drop(&mut self) {
        for abort in &self.abort_handles {
            abort.abort();
        }
    }
}

/// Event that can happen on the network service.
#[derive(Debug, Clone)]
pub enum Event {
    Connected {
        peer_id: PeerId,
        chain_index: usize,
        role: protocol::Role,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    },
    Disconnected {
        peer_id: PeerId,
        chain_index: usize,
    },
    BlockAnnounce {
        peer_id: PeerId,
        chain_index: usize,
        announce: service::EncodedBlockAnnounce,
    },
    /// Received a GrandPa commit message from the network.
    GrandpaCommitMessage {
        peer_id: PeerId,
        chain_index: usize,
        message: service::EncodedGrandpaCommitMessage,
    },
}

/// Error returned by [`NetworkService::blocks_request`].
#[derive(Debug, derive_more::Display)]
pub enum BlocksRequestError {
    /// No established connection with the target.
    NoConnection,
    /// Error during the request.
    #[display(fmt = "{}", _0)]
    Request(service::BlocksRequestError),
}

/// Error returned by [`NetworkService::grandpa_warp_sync_request`].
#[derive(Debug, derive_more::Display)]
pub enum GrandpaWarpSyncRequestError {
    /// No established connection with the target.
    NoConnection,
    /// Error during the request.
    #[display(fmt = "{}", _0)]
    Request(service::GrandpaWarpSyncRequestError),
}

/// Error returned by [`NetworkService::storage_proof_request`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum StorageProofRequestError {
    /// No established connection with the target.
    NoConnection,
    /// Error during the request.
    #[display(fmt = "{}", _0)]
    Request(service::StorageProofRequestError),
}

/// Error returned by [`NetworkService::call_proof_request`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum CallProofRequestError {
    /// No established connection with the target.
    NoConnection,
    /// Error during the request.
    #[display(fmt = "{}", _0)]
    Request(service::CallProofRequestError),
}

impl CallProofRequestError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    pub fn is_network_problem(&self) -> bool {
        match self {
            CallProofRequestError::Request(err) => err.is_network_problem(),
            CallProofRequestError::NoConnection => true,
        }
    }
}

/// Error returned by [`NetworkService::send_block_announce`].
#[derive(Debug, derive_more::Display)]
pub enum QueueNotificationError {
    /// No established connection with the target.
    NoConnection,
    /// Error during the queuing.
    #[display(fmt = "{}", _0)]
    Queue(peers::QueueNotificationError),
}

async fn background_task<TPlat: Platform>(
    shared: Arc<Shared<TPlat>>,
    mut event_senders: Vec<mpsc::Sender<Event>>,
) {
    loop {
        // In order to guarantee that waking up `wake_up_background` will run an entirely
        // loop of `update_round`, we grab the listener at the start. If `wake_up_background`
        // is notified while `update_round` is running, the `notified.await` below will be
        // instantaneous.
        let notified = shared.wake_up_main_background_task.listen();
        update_round(&shared, &mut event_senders).await;
        notified.await;
    }
}

async fn update_round<TPlat: Platform>(
    shared: &Arc<Shared<TPlat>>,
    event_senders: &mut [mpsc::Sender<Event>],
) {
    let mut guarded = shared.guarded.lock().await;

    // Inject in the coordinator the messages that the connections have generated.
    loop {
        let (connection_id, message) =
            match guarded.messages_from_connections_rx.next().now_or_never() {
                Some(Some(v)) => v,
                _ => break,
            };

        guarded
            .network
            .inject_connection_message(connection_id, message);
    }

    // Process the events that the coordinator has generated.
    'events_loop: loop {
        let event = loop {
            let inner_event = match guarded.network.next_event(TPlat::now()) {
                Some(ev) => ev,
                None => break 'events_loop,
            };

            match inner_event {
                service::Event::Connected(peer_id) => {
                    log::debug!(target: "network", "Connected({})", peer_id);
                }
                service::Event::Disconnected {
                    peer_id,
                    chain_indices,
                } => {
                    log::debug!(target: "network", "Disconnected({})", peer_id);
                    if !chain_indices.is_empty() {
                        // TODO: properly implement when multiple chains
                        if chain_indices.len() == 1 {
                            log::debug!(
                                target: "network",
                                "Connection({}, {}) => ChainDisconnected",
                                peer_id,
                                &shared.log_chain_names[chain_indices[0]],
                            );

                            break Event::Disconnected {
                                peer_id,
                                chain_index: chain_indices[0],
                            };
                        } else {
                            todo!()
                        }
                    }
                }
                service::Event::BlockAnnounce {
                    chain_index,
                    peer_id,
                    announce,
                } => {
                    log::debug!(
                        target: "network",
                        "Connection({}, {}) => BlockAnnounce(best_hash={}, is_best={})",
                        peer_id,
                        &shared.log_chain_names[chain_index],
                        HashDisplay(&header::hash_from_scale_encoded_header(&announce.decode().scale_encoded_header)),
                        announce.decode().is_best
                    );
                    break Event::BlockAnnounce {
                        chain_index,
                        peer_id,
                        announce,
                    };
                }
                service::Event::ChainConnected {
                    peer_id,
                    chain_index,
                    role,
                    best_number,
                    best_hash,
                    slot_ty: _,
                } => {
                    log::debug!(
                        target: "network",
                        "Connection({}, {}) => ChainConnected(best_height={}, best_hash={})",
                        peer_id,
                        &shared.log_chain_names[chain_index],
                        best_number,
                        HashDisplay(&best_hash)
                    );
                    break Event::Connected {
                        peer_id,
                        chain_index,
                        role,
                        best_block_number: best_number,
                        best_block_hash: best_hash,
                    };
                }
                service::Event::ChainConnectAttemptFailed {
                    peer_id,
                    chain_index,
                    unassigned_slot_ty,
                    error,
                } => {
                    log::debug!(
                        target: "network",
                        "Connection({}, {}) => ChainConnectAttemptFailed(error={:?})",
                        &shared.log_chain_names[chain_index],
                        peer_id, error,
                    );
                    log::debug!(
                        target: "connections",
                        "{}Slots({}) ∌ {}",
                        match unassigned_slot_ty {
                            service::SlotTy::Inbound => "In",
                            service::SlotTy::Outbound => "Out",
                        },
                        &shared.log_chain_names[chain_index],
                        peer_id
                    );
                    guarded.unassign_slot_and_ban(chain_index, peer_id);
                    shared.wake_up_main_background_task.notify(1);
                }
                service::Event::ChainDisconnected {
                    peer_id,
                    chain_index,
                    unassigned_slot_ty,
                } => {
                    log::debug!(
                        target: "network",
                        "Connection({}, {}) => ChainDisconnected",
                        peer_id,
                        &shared.log_chain_names[chain_index],
                    );
                    log::debug!(
                        target: "connections",
                        "{}Slots({}) ∌ {}",
                        match unassigned_slot_ty {
                            service::SlotTy::Inbound => "In",
                            service::SlotTy::Outbound => "Out",
                        },
                        &shared.log_chain_names[chain_index],
                        peer_id
                    );
                    guarded.unassign_slot_and_ban(chain_index, peer_id.clone());
                    shared.wake_up_main_background_task.notify(1);
                    break Event::Disconnected {
                        peer_id,
                        chain_index,
                    };
                }
                service::Event::BlocksRequestResult {
                    request_id,
                    response,
                } => {
                    let _ = guarded
                        .blocks_requests
                        .remove(&request_id)
                        .unwrap()
                        .send(response);
                }
                service::Event::GrandpaWarpSyncRequestResult {
                    request_id,
                    response,
                } => {
                    let _ = guarded
                        .grandpa_warp_sync_requests
                        .remove(&request_id)
                        .unwrap()
                        .send(response);
                }
                service::Event::StorageProofRequestResult {
                    request_id,
                    response,
                } => {
                    let _ = guarded
                        .storage_proof_requests
                        .remove(&request_id)
                        .unwrap()
                        .send(response);
                }
                service::Event::CallProofRequestResult {
                    request_id,
                    response,
                } => {
                    let _ = guarded
                        .call_proof_requests
                        .remove(&request_id)
                        .unwrap()
                        .send(response);
                }
                service::Event::StateRequestResult { .. }
                | service::Event::KademliaFindNodeRequestResult { .. } => {
                    // We never start this kind of requests.
                    unreachable!()
                }
                service::Event::KademliaDiscoveryResult {
                    operation_id,
                    result,
                } => {
                    let chain_index = guarded
                        .kademlia_discovery_operations
                        .remove(&operation_id)
                        .unwrap();
                    match result {
                        Ok(nodes) => {
                            log::debug!(
                                target: "connections", "On chain {}, discovered: {}",
                                &shared.log_chain_names[chain_index],
                                nodes.iter().map(|(p, _)| p.to_string()).join(", ")
                            );

                            for (peer_id, addrs) in nodes {
                                guarded.network.discover(
                                    &TPlat::now(),
                                    chain_index,
                                    peer_id,
                                    addrs,
                                );
                            }
                        }
                        Err(error) => {
                            log::debug!(
                                target: "connections",
                                "Discovery => {:?}",
                                error
                            );

                            // No error is printed if the error is about the fact that we have
                            // 0 peers, as this tends to happen quite frequently at initialization
                            // and there is nothing that can be done against this error anyway.
                            // No error is printed either if the request fails due to a benign
                            // networking error such as an unresponsive peer.
                            match error {
                                service::DiscoveryError::NoPeer => {}
                                service::DiscoveryError::FindNode(
                                    service::KademliaFindNodeError::RequestFailed(err),
                                ) if !err.is_protocol_error() => {}
                                _ => {
                                    log::warn!(
                                        target: "connections",
                                        "Problem during discovery on {}: {}",
                                        &shared.log_chain_names[chain_index],
                                        error
                                    );
                                }
                            }
                        }
                    }
                }
                service::Event::InboundSlotAssigned {
                    peer_id,
                    chain_index,
                } => {
                    log::debug!(
                        target: "connections",
                        "InSlots({}) ∋ {}",
                        &shared.log_chain_names[chain_index],
                        peer_id
                    );
                }
                service::Event::IdentifyRequestIn {
                    peer_id,
                    request_id,
                } => {
                    log::debug!(
                        target: "network",
                        "Connection({}) => IdentifyRequest",
                        peer_id,
                    );
                    guarded.network.respond_identify(request_id, "smoldot");
                }
                service::Event::BlocksRequestIn { .. } => unreachable!(),
                service::Event::RequestInCancel { .. } => {
                    // All incoming requests are immediately answered.
                    unreachable!()
                }
                service::Event::GrandpaCommitMessage {
                    chain_index,
                    peer_id,
                    message,
                } => {
                    log::debug!(
                        target: "network",
                        "Connection(?, {}) => GrandpaCommitMessage(target_block_hash={})",
                        &shared.log_chain_names[chain_index],
                        HashDisplay(message.decode().message.target_hash),
                    );
                    break Event::GrandpaCommitMessage {
                        chain_index,
                        peer_id,
                        message,
                    };
                }
                service::Event::ProtocolError { peer_id, error } => {
                    // TODO: handle properly?
                    log::warn!(
                        target: "network",
                        "Connection({}) => ProtocolError(error={:?})",
                        peer_id,
                        error,
                    );

                    for chain_index in 0..guarded.network.num_chains() {
                        guarded.unassign_slot_and_ban(chain_index, peer_id.clone());
                    }
                    shared.wake_up_main_background_task.notify(1);
                }
            }
        };

        // Dispatch the event to the various senders.

        // Because the tasks processing the receivers might be waiting to acquire the lock, we
        // need to unlock the lock before sending. This guarantees that the sending finishes at
        // some point in the future.
        drop(guarded);

        // This little `if` avoids having to do `event.clone()` if we don't have to.
        if event_senders.len() == 1 {
            let _ = event_senders[0].send(event).await;
        } else {
            for sender in event_senders.iter_mut() {
                // For simplicity we don't get rid of closed senders because senders aren't
                // supposed to close, and that leaving closed senders in the list doesn't have any
                // consequence other than one extra iteration every time.
                let _ = sender.send(event.clone()).await;
            }
        }

        // Re-acquire lock to continue the function.
        guarded = shared.guarded.lock().await;
    }

    // TODO: doc
    for chain_index in 0..shared.log_chain_names.len() {
        let now = TPlat::now();

        // Clean up the content of `slots_assign_backoff`.
        // TODO: the background task should be woken up when the ban expires
        // TODO: O(n)
        guarded
            .slots_assign_backoff
            .retain(|_, expiration| *expiration > now);

        loop {
            let peer_id = guarded
                .network
                .slots_to_assign(chain_index)
                .filter(|peer_id| {
                    !guarded
                        .slots_assign_backoff
                        .contains_key(&((**peer_id).clone(), chain_index)) // TODO: spurious cloning
                })
                .next()
                .cloned();

            if let Some(peer_id) = peer_id {
                log::debug!(
                    target: "connections",
                    "OutSlots({}) ∋ {}",
                    &shared.log_chain_names[chain_index],
                    peer_id
                );

                guarded.network.assign_out_slot(chain_index, peer_id);
            } else {
                break;
            }
        }
    }

    // The networking service contains a list of connections that should be opened.
    // Grab this list and start opening a connection for each.
    // TODO: restore the rate limiting for connections openings
    loop {
        let start_connect = match guarded.network.next_start_connect(|| TPlat::now()) {
            Some(sc) => sc,
            None => break,
        };

        let is_important = guarded
            .important_nodes
            .contains(&start_connect.expected_peer_id);

        // Perform the connection process in a separate task.
        let task = tasks::connection_task(
            start_connect,
            shared.clone(),
            guarded.messages_from_connections_tx.clone(),
            is_important,
        );

        // Sending the new task might fail in case a shutdown is happening, in which case
        // we don't really care about the state of anything anymore.
        // The sending here is normally very quick.
        let _ = guarded.new_tasks_tx.send(Box::pin(task)).await;
    }

    // Pull messages that the coordinator has generated in destination to the various
    // connections.
    loop {
        let (connection_id, message) = match guarded.network.pull_message_to_connection() {
            Some(m) => m,
            None => break,
        };

        // Note that it is critical for the sending to not take too long here, in order to not
        // block the process of the network service.
        // In particular, if sending the message to the connection is blocked due to sending
        // a message on the connection-to-coordinator channel, this will result in a deadlock.
        // For this reason, the connection task is always ready to immediately accept a message
        // on the coordinator-to-connection channel.
        guarded
            .active_connections
            .get_mut(&connection_id)
            .unwrap()
            .send(message)
            .await
            .unwrap();
    }
}

impl<TPlat: Platform> SharedGuarded<TPlat> {
    fn unassign_slot_and_ban(&mut self, chain_index: usize, peer_id: PeerId) {
        self.network.unassign_slot(chain_index, &peer_id);

        let new_expiration = TPlat::now() + Duration::from_secs(20); // TODO: arbitrary constant
        match self.slots_assign_backoff.entry((peer_id, chain_index)) {
            hash_map::Entry::Occupied(e) if *e.get() < new_expiration => {
                *e.into_mut() = new_expiration;
            }
            hash_map::Entry::Occupied(_) => {}
            hash_map::Entry::Vacant(e) => {
                e.insert(new_expiration);
            }
        }
    }
}
