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

use crate::ffi;

use core::{cmp, fmt, num::NonZeroUsize, pin::Pin, task::Poll, time::Duration};
use futures::{channel::mpsc, prelude::*};
use itertools::Itertools as _;
use smoldot::{
    informant::HashDisplay,
    libp2p::{
        collection::{ConnectionError, HandshakeError},
        connection::{self, handshake},
        multiaddr::Multiaddr,
        peer_id::PeerId,
        read_write::ReadWrite,
    },
    network::{protocol, service},
};
use std::{collections::HashSet, sync::Arc};

/// Configuration for a [`NetworkService`].
pub struct Config {
    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(String, Pin<Box<dyn Future<Output = ()> + Send>>) + Send>,

    /// Key to use for the encryption layer of all the connections. Gives the node its identity.
    pub noise_key: connection::NoiseKey,

    /// Number of event receivers returned by [`NetworkService::new`].
    pub num_events_receivers: usize,

    /// List of chains to connect to. Chains are later referred to by their index in this list.
    pub chains: Vec<ConfigChain>,
}

/// See [`Config::chains`].
pub struct ConfigChain {
    /// Name of the chain, for logging purposes.
    pub log_name: String,

    /// List of node identities and addresses that are known to belong to the chain's peer-to-pee
    /// network.
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,

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

    /// If true, the chain uses the GrandPa networking protocol.
    pub has_grandpa_protocol: bool,
}

pub struct NetworkService {
    inner: Arc<NetworkServiceInner>,

    /// List of handles that abort all the background tasks.
    abort_handles: Vec<future::AbortHandle>,
}

struct NetworkServiceInner {
    /// Data structure holding the entire state of the networking.
    network: service::ChainNetwork<ffi::Instant>,

    /// List of nodes that are considered as important for logging purposes.
    // TODO: should also detect whenever we fail to open a block announces substream with any of these peers
    important_nodes: HashSet<PeerId, fnv::FnvBuildHasher>,

    /// Names of the various chains the network service connects to. Used only for logging
    /// purposes.
    log_chain_names: Vec<String>,
}

impl NetworkService {
    /// Initializes the network service with the given configuration.
    ///
    /// Returns the networking service, plus a list of receivers on which events are pushed.
    /// All of these receivers must be polled regularly to prevent the networking service from
    /// slowing down.
    pub async fn new(mut config: Config) -> (Arc<Self>, Vec<stream::BoxStream<'static, Event>>) {
        let (mut senders, receivers): (Vec<_>, Vec<_>) = (0..config.num_events_receivers)
            .map(|_| mpsc::channel(16))
            .unzip();

        let important_nodes = config
            .chains
            .iter()
            .flat_map(|chain| chain.bootstrap_nodes.iter())
            .map(|(peer_id, _)| peer_id.clone())
            .collect::<HashSet<_, _>>();

        let num_chains = config.chains.len();
        let mut chains = Vec::with_capacity(num_chains);
        // TODO: this `bootstrap_nodes` field is weird ; should we de-duplicate entry in known_nodes?
        let mut known_nodes = Vec::new();

        let mut log_chain_names = Vec::with_capacity(num_chains);

        for chain in config.chains {
            chains.push(service::ChainConfig {
                bootstrap_nodes: (known_nodes.len()
                    ..(known_nodes.len() + chain.bootstrap_nodes.len()))
                    .collect(),
                in_slots: 3,
                out_slots: 4,
                grandpa_protocol_config: if chain.has_grandpa_protocol {
                    // TODO: dummy values
                    Some(service::GrandpaState {
                        commit_finalized_height: u32::try_from(chain.finalized_block_height)
                            .unwrap(), // TODO: unwrap()?!
                        round_number: 1,
                        set_id: 0,
                    })
                } else {
                    None
                },
                protocol_id: chain.protocol_id.clone(),
                best_hash: chain.best_block.1,
                best_number: chain.best_block.0,
                genesis_hash: chain.genesis_block_hash,
                role: protocol::Role::Light,
                allow_inbound_block_requests: false,
            });

            known_nodes.extend(chain.bootstrap_nodes);
            log_chain_names.push(chain.log_name);
        }

        let mut abort_handles = Vec::new();

        let network_service = Arc::new(NetworkServiceInner {
            network: service::ChainNetwork::new(service::Config {
                now: ffi::Instant::now(),
                chains,
                known_nodes,
                connections_capacity: 32,
                peers_capacity: 8,
                max_addresses_per_peer: NonZeroUsize::new(5).unwrap(),
                noise_key: config.noise_key,
                handshake_timeout: Duration::from_secs(8),
                pending_api_events_buffer_size: NonZeroUsize::new(32).unwrap(),
                randomness_seed: rand::random(),
            }),
            important_nodes,
            log_chain_names,
        });

        // Spawn a task pulling events from the network and transmitting them to the event senders.
        (config.tasks_executor)(
            "network-events".into(),
            Box::pin({
                let network_service = network_service.clone();
                let future = async move {
                    loop {
                        let event = loop {
                            match network_service
                                .network
                                .next_event(ffi::Instant::now())
                                .await
                            {
                                service::Event::Connected(peer_id) => {
                                    log::info!(target: "network", "Connected to {}", peer_id);
                                }
                                service::Event::Disconnected {
                                    peer_id,
                                    chain_indices,
                                } => {
                                    log::info!(target: "network", "Disconnected from {} (chains: {:?})", peer_id, chain_indices);
                                    if !chain_indices.is_empty() {
                                        // TODO: properly implement when multiple chains
                                        if chain_indices.len() == 1 {
                                            log::debug!(
                                                target: "network",
                                                "Connection({}, {}) => ChainDisconnected",
                                                peer_id,
                                                &network_service.log_chain_names[chain_indices[0]],
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
                                        "Connection({}, {}) => BlockAnnounce({}, {}, is_best={})",
                                        peer_id,
                                        &network_service.log_chain_names[chain_index],
                                        chain_index,
                                        HashDisplay(&announce.decode().header.hash()),
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
                                } => {
                                    log::debug!(
                                        target: "network",
                                        "Connection({}, {}) => ChainConnected({}, {})",
                                        peer_id,
                                        &network_service.log_chain_names[chain_index],
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
                                    error,
                                } => {
                                    log::debug!(
                                        target: "network",
                                        "Connection({}, {}) => ChainConnectAttemptFailed: {}",
                                        &network_service.log_chain_names[chain_index],
                                        peer_id, error,
                                    );
                                }
                                service::Event::ChainDisconnected {
                                    peer_id,
                                    chain_index,
                                } => {
                                    log::debug!(
                                        target: "network",
                                        "Connection({}, {}) => ChainDisconnected",
                                        peer_id,
                                        &network_service.log_chain_names[chain_index],
                                    );
                                    break Event::Disconnected {
                                        peer_id,
                                        chain_index,
                                    };
                                }
                                service::Event::IdentifyRequestIn { peer_id, request } => {
                                    log::debug!(
                                        target: "network",
                                        "Connection({}) => IdentifyRequest",
                                        peer_id,
                                    );
                                    request.respond("smoldot").await;
                                }
                                service::Event::BlocksRequestIn { .. } => unreachable!(),
                                service::Event::GrandpaCommitMessage {
                                    chain_index,
                                    message,
                                } => {
                                    log::debug!(
                                        target: "network",
                                        "Connection(?, {}) => GrandpaCommitMessage({})",
                                        &network_service.log_chain_names[chain_index],
                                        HashDisplay(message.decode().message.target_hash),
                                    );
                                    break Event::GrandpaCommitMessage {
                                        chain_index,
                                        message,
                                    };
                                }
                                service::Event::ProtocolError { peer_id, error } => {
                                    // TODO: handle properly?
                                    log::warn!(
                                        target: "network",
                                        "Connection({}) => ProtocolError({})",
                                        peer_id,
                                        error,
                                    );
                                }
                            }
                        };

                        // Dispatch the event to the various senders.
                        // This little `if` avoids having to do `event.clone()` if we don't have to.
                        if senders.len() == 1 {
                            let _ = senders[0].send(event).await;
                        } else {
                            for sender in &mut senders {
                                let _ = sender.send(event.clone()).await;
                            }
                        }
                    }
                };

                let (abortable, abort_handle) = future::abortable(future);
                abort_handles.push(abort_handle);
                abortable.map(|_| ())
            }),
        );

        let (mut connec_tx, mut connec_rx) = mpsc::channel(8);

        // Spawn tasks dedicated to opening connections.
        // TODO: spawn multiple of these and tweak the `connection_task`, so that we limit ourselves to N simultaneous connection openings, to please some ISPs
        (config.tasks_executor)(
            "connections-open".into(),
            Box::pin({
                let network_service = network_service.clone();
                let future = async move {
                    loop {
                        let start_connect = network_service
                            .network
                            .next_start_connect(ffi::Instant::now())
                            .await;

                        let is_important_peer = network_service
                            .important_nodes
                            .contains(&start_connect.expected_peer_id);

                        // Convert the `multiaddr` (typically of the form `/ip4/a.b.c.d/tcp/d/ws`)
                        // into a `Future<dyn Output = Result<TcpStream, ...>>`.
                        let socket = {
                            log::debug!(
                                target: "connections",
                                "Pending({:?}, {}) started: {}",
                                start_connect.id, start_connect.expected_peer_id,
                                start_connect.multiaddr
                            );
                            ffi::Connection::connect(&start_connect.multiaddr.to_string())
                        };

                        // TODO: handle dialing timeout here

                        let network_service2 = network_service.clone();

                        // Sending the new connection might fail in case a shutdown is happening.
                        let _ = connec_tx
                            .send(Box::pin({
                                connection_task(
                                    socket,
                                    network_service2,
                                    start_connect.id,
                                    start_connect.timeout,
                                    start_connect.expected_peer_id,
                                    start_connect.multiaddr,
                                    is_important_peer,
                                )
                            }))
                            .await;
                    }
                };

                let (abortable, abort_handle) = future::abortable(future);
                abort_handles.push(abort_handle);
                abortable.map(|_| ())
            }),
        );

        // Spawn tasks dedicated to processing existing connections.
        (config.tasks_executor)(
            "connections".into(),
            Box::pin({
                let future = async move {
                    let mut connections = stream::FuturesUnordered::new();
                    loop {
                        futures::select! {
                            new_connec = connec_rx.select_next_some() => {
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

        // Spawn tasks dedicated to the Kademlia discovery and slots assignment.
        for chain_index in 0..num_chains {
            (config.tasks_executor)(
                "discovery".into(),
                Box::pin({
                    let network_service = network_service.clone();
                    let future = async move {
                        let mut next_discovery = Duration::from_secs(5);

                        loop {
                            ffi::Delay::new(next_discovery).await;
                            next_discovery = cmp::min(next_discovery * 2, Duration::from_secs(120));

                            match network_service
                                .network
                                .kademlia_discovery_round(ffi::Instant::now(), chain_index)
                                .await
                            {
                                Ok(insert) => {
                                    log::debug!(
                                        target: "connections", "On chain {}, discovered: {}",
                                        &network_service.log_chain_names[chain_index],
                                        insert.peer_ids().map(|p| p.to_string()).join(", ")
                                    );

                                    insert.insert(&ffi::Instant::now()).await;
                                }
                                Err(error) => {
                                    log::warn!(
                                        target: "connections",
                                        "Problem during discovery on {}: {}",
                                        &network_service.log_chain_names[chain_index],
                                        error
                                    );
                                }
                            }
                        }
                    };

                    let (abortable, abort_handle) = future::abortable(future);
                    abort_handles.push(abort_handle);
                    abortable.map(|_| ())
                }),
            );

            (config.tasks_executor)(
                "slots-assign".into(),
                Box::pin({
                    let network_service = network_service.clone();
                    let future = async move {
                        let mut next_round = Duration::from_millis(500);

                        loop {
                            let peer = network_service.network.assign_slots(chain_index).await;
                            if let Some(_peer_id) = peer {
                                // TODO: restore and log also the de-assignments
                                /*log::debug!(
                                    target: "connections",
                                    "Slots({}) ∋ {}",
                                    &network_service.log_chain_names[chain_index],
                                    peer_id
                                );*/
                            }

                            ffi::Delay::new(next_round).await;
                            next_round = cmp::min(next_round * 2, Duration::from_secs(5));
                        }
                    };

                    let (abortable, abort_handle) = future::abortable(future);
                    abort_handles.push(abort_handle);
                    abortable.map(|_| ())
                }),
            );
        }

        abort_handles.shrink_to_fit();
        let final_network_service = Arc::new(NetworkService {
            inner: network_service,
            abort_handles,
        });

        // Adjust the receivers to keep the `final_network_service` alive.
        let receivers = receivers
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

        (final_network_service, receivers)
    }

    /// Sends a blocks request to the given peer.
    // TODO: more docs
    pub async fn blocks_request(
        self: Arc<Self>,
        target: PeerId, // TODO: takes by value because of future longevity issue
        chain_index: usize,
        config: protocol::BlocksRequestConfig,
    ) -> Result<Vec<protocol::BlockData>, service::BlocksRequestError> {
        log::debug!(target: "network", "Connection({}) <= BlocksRequest({:?})", target, config);

        let result = self
            .inner
            .network
            .blocks_request(ffi::Instant::now(), &target, chain_index, config)
            .await;

        log::debug!(
            target: "network",
            "Connection({}) => BlocksRequest({:?})",
            target,
            result.as_ref().map(|b| b.len())
        );

        if !log::log_enabled!(log::Level::Debug) {
            match &result {
                Ok(_) | Err(service::BlocksRequestError::Request(_)) => {}
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

        result
    }

    /// Sends a grandpa warp sync request to the given peer.
    // TODO: more docs
    pub async fn grandpa_warp_sync_request(
        self: Arc<Self>,
        target: PeerId, // TODO: takes by value because of future longevity issue
        chain_index: usize,
        begin_hash: [u8; 32],
    ) -> Result<protocol::GrandpaWarpSyncResponse, service::GrandpaWarpSyncRequestError> {
        log::debug!(
            target: "network", "Connection({}) <= GrandpaWarpSyncRequest({})",
            target, HashDisplay(&begin_hash)
        );

        let result = self
            .inner
            .network
            .grandpa_warp_sync_request(ffi::Instant::now(), &target, chain_index, begin_hash)
            .await;

        if let Ok(response) = result.as_ref() {
            log::debug!(
                target: "network",
                "Connection({}) => GrandpaWarpSyncRequest(num_fragments: {:?}, finished: {:?})",
                target,
                response.fragments.len(),
                response.is_finished,
            );
        } else {
            log::debug!(
                target: "network",
                "Connection({}) => GrandpaWarpSyncRequest({:?})",
                target,
                result,
            );
        }

        result
    }

    pub async fn set_local_best_block(
        &self,
        chain_index: usize,
        best_hash: [u8; 32],
        best_number: u64,
    ) {
        self.inner
            .network
            .set_local_best_block(chain_index, best_hash, best_number)
            .await
    }

    pub async fn set_local_grandpa_state(
        &self,
        chain_index: usize,
        grandpa_state: service::GrandpaState,
    ) {
        log::debug!(
            target: "network",
            "Chain({}) <= SetLocalGrandpaState(set_id: {}, commit_finalized_height: {})",
            chain_index,
            grandpa_state.set_id,
            grandpa_state.commit_finalized_height,
        );

        // TODO: log the list of peers we sent the packet to

        self.inner
            .network
            .set_local_grandpa_state(chain_index, grandpa_state)
            .await
    }

    /// Sends a storage proof request to the given peer.
    // TODO: more docs
    pub async fn storage_proof_request(
        self: Arc<Self>,
        chain_index: usize,
        target: PeerId, // TODO: takes by value because of futures longevity issue
        config: protocol::StorageProofRequestConfig<impl Iterator<Item = impl AsRef<[u8]>>>,
    ) -> Result<Vec<Vec<u8>>, service::StorageProofRequestError> {
        log::debug!(
            target: "network",
            "Connection({}) <= StorageProofRequest({}, {})",
            target,
            HashDisplay(&config.block_hash),
            config.keys.size_hint().0
        );

        let result = self
            .inner
            .network
            .storage_proof_request(ffi::Instant::now(), &target, chain_index, config)
            .await;

        log::debug!(
            target: "network",
            "Connection({}) => StorageProofRequest({:?})",
            target,
            result.as_ref().map(|b| b.len())
        );

        result
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
    ) -> Result<Vec<Vec<u8>>, service::CallProofRequestError> {
        log::debug!(
            target: "network",
            "Connection({}) <= CallProofRequest({}, {})",
            target,
            HashDisplay(&config.block_hash),
            config.method
        );

        let result = self
            .inner
            .network
            .call_proof_request(ffi::Instant::now(), &target, chain_index, config)
            .await;

        log::debug!(
            target: "network",
            "Connection({}) => CallProofRequest({:?})",
            target,
            result.as_ref().map(|b| b.len())
        );

        result
    }

    /// Announces transaction to the peers we are connected to.
    ///
    /// Returns a list of peers that we have sent the transaction to. Can return an empty `Vec`
    /// if we didn't send the transaction to any peer.
    ///
    /// Note that the remote doesn't confirm that it has received the transaction. Because
    /// networking is inherently unreliable, successfully sending a transaction to a peer doesn't
    /// necessarily mean that the remote has received it. In practice, however, the likelyhood of
    /// a transaction not being received are extremely low. This can be considered as known flaw.
    pub async fn announce_transaction(
        self: Arc<Self>,
        chain_index: usize,
        transaction: &[u8],
    ) -> Vec<PeerId> {
        let mut sent_peers = Vec::with_capacity(16); // TODO: capacity?

        // TODO: keep track of which peer knows about which transaction, and don't send it again

        for target in self.peers_list().await {
            if self
                .inner
                .network
                .announce_transaction(&target, chain_index, &transaction)
                .await
                .is_ok()
            {
                sent_peers.push(target);
            };
        }

        sent_peers
    }

    /// Returns an iterator to the list of [`PeerId`]s that we have an established connection
    /// with.
    pub async fn peers_list(&self) -> impl Iterator<Item = PeerId> {
        self.inner.network.peers_list().await
    }
}

impl Drop for NetworkService {
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
        chain_index: usize,
        message: service::EncodedGrandpaCommitMessage,
    },
}

/// Asynchronous task managing a specific connection.
///
/// `is_important_peer` controls the log level used for problems that happen on this connection.
async fn connection_task(
    websocket: impl Future<Output = Result<Pin<Box<ffi::Connection>>, impl fmt::Display>>,
    network_service: Arc<NetworkServiceInner>,
    pending_id: service::PendingId,
    timeout: ffi::Instant,
    expected_peer_id: PeerId,
    attemped_multiaddr: Multiaddr,
    is_important_peer: bool,
) {
    // Finishing the ongoing connection process.
    let mut websocket = {
        let websocket = websocket.fuse();
        futures::pin_mut!(websocket);
        let mut timeout = ffi::Delay::new_at(timeout);

        let result = futures::select! {
            _ = timeout => Err(None),
            result = websocket => result.map_err(Some),
        };

        match (&result, is_important_peer) {
            (Ok(_), _) => {}
            (Err(None), true) => {
                log::warn!(
                    target: "connections",
                    "Timeout when trying to reach {} through {}",
                    expected_peer_id, attemped_multiaddr
                );
            }
            (Err(None), false) => {
                log::debug!(
                    target: "connections",
                    "Pending({:?}, {}) => Timeout ({})",
                    pending_id, expected_peer_id, attemped_multiaddr
                );
            }
            (Err(Some(err)), true) => {
                log::warn!(
                    target: "connections",
                    "Failed to reach {} through {}: {}",
                    expected_peer_id, attemped_multiaddr, err
                );
            }
            (Err(Some(err)), false) => {
                log::debug!(
                    target: "connections",
                    "Pending({:?}, {}) => Failed to reach ({}): {}",
                    pending_id, expected_peer_id, attemped_multiaddr, err
                );
            }
        }

        match result {
            Ok(ws) => ws,
            Err(_err) => {
                network_service
                    .network
                    .pending_outcome_err(pending_id, false) // TODO: should pass a proper value for `is_unreachable`, but an error is sometimes returned despite a timeout https://github.com/paritytech/smoldot/issues/1531
                    .await;
                return;
            }
        }
    };

    // Connection process is successful. Notify the network state machine.
    let id = network_service.network.pending_outcome_ok(pending_id).await;
    log::debug!(
        target: "connections",
        "Pending({:?}, {}) => Connection({:?}) through {}",
        pending_id,
        expected_peer_id,
        id,
        attemped_multiaddr
    );

    let mut write_buffer = vec![0; 4096];

    loop {
        let now = ffi::Instant::now();

        let mut read_write = ReadWrite {
            now,
            // `read_buffer()` isn't ready immediately if no data is available. If the reading
            // side is closed, then it will instantly produce `None`.
            incoming_buffer: websocket.read_buffer().now_or_never().unwrap_or(Some(&[])),
            outgoing_buffer: Some((&mut write_buffer, &mut [])), // TODO: this should be None if a previous read_write() produced None
            read_bytes: 0,
            written_bytes: 0,
            wake_up_after: None,
            wake_up_future: None,
        };

        match network_service
            .network
            .read_write(id, &mut read_write)
            .await
        {
            Ok(rw) => rw,
            Err(err) if is_important_peer => {
                log::warn!(
                    target: "connections", "Error in connection with {}: {}",
                    expected_peer_id, err
                );

                // For any handshake error other than "no protocol in common has been found",
                // it is likely that the cause is connecting to a port that isn't serving the
                // libp2p protocol.
                match err {
                    ConnectionError::Handshake(HandshakeError::Protocol(
                        handshake::HandshakeError::NoEncryptionProtocol,
                    ))
                    | ConnectionError::Handshake(HandshakeError::Protocol(
                        handshake::HandshakeError::NoMultiplexingProtocol,
                    ))
                    | ConnectionError::Handshake(HandshakeError::Timeout) => {}
                    ConnectionError::Handshake(_) => {
                        log::warn!(
                            target: "connections",
                            "Is {} the address of a libp2p port?",
                            attemped_multiaddr
                        );
                    }
                    _ => {}
                }

                return;
            }
            Err(err) => {
                log::debug!(target: "connections", "Connection({:?}, {}) => Closed: {}", id, expected_peer_id, err);
                return;
            }
        };

        let read_buffer_has_data = read_write.incoming_buffer.map_or(false, |b| !b.is_empty());
        let read_buffer_closed = read_write.incoming_buffer.is_none();
        let read_bytes = read_write.read_bytes;
        let written_bytes = read_write.written_bytes;
        let wake_up_after = read_write.wake_up_after;

        let wake_up_future = if let Some(wake_up_future) = read_write.wake_up_future.take() {
            future::Either::Left(wake_up_future)
        } else {
            future::Either::Right(future::pending())
        };

        drop(read_write);

        if written_bytes != 0 {
            websocket.send(&write_buffer[..written_bytes]);
        }

        websocket.advance_read_cursor(read_bytes);

        // Starting from here, we block (or not) the current task until more processing needs
        // to happen.

        // Future ready when the connection state machine requests more processing.
        let poll_after = if let Some(wake_up) = wake_up_after {
            if wake_up > now {
                let dur = wake_up - now;
                future::Either::Left(ffi::Delay::new(dur))
            } else {
                continue;
            }
        } else {
            future::Either::Right(future::pending())
        }
        .fuse();

        // Future that is woken up when new data is ready on the socket.
        let read_buffer_ready = if !(read_buffer_has_data && read_bytes == 0) && !read_buffer_closed
        {
            future::Either::Left(websocket.read_buffer())
        } else {
            future::Either::Right(future::pending())
        };

        // Wait until either some data is ready on the socket, or the connection state machine
        // has been requested to be polled again.
        futures::pin_mut!(read_buffer_ready);
        future::select(
            future::select(read_buffer_ready, wake_up_future),
            poll_after,
        )
        .await;
    }
}
