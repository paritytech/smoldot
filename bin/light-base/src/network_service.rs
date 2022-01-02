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

use crate::Platform;

use core::{cmp, num::NonZeroUsize, task::Poll, time::Duration};
use futures::{channel::mpsc, prelude::*};
use itertools::Itertools as _;
use smoldot::{
    informant::{BytesDisplay, HashDisplay},
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
    pub tasks_executor: Box<dyn FnMut(String, future::BoxFuture<'static, ()>) + Send>,

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

pub struct NetworkService<TPlat: Platform> {
    inner: Arc<NetworkServiceInner<TPlat>>,

    /// List of handles that abort all the background tasks.
    abort_handles: Vec<future::AbortHandle>,
}

struct NetworkServiceInner<TPlat: Platform> {
    /// Data structure holding the entire state of the networking.
    network: service::ChainNetwork<TPlat::Instant>,

    /// List of nodes that are considered as important for logging purposes.
    // TODO: should also detect whenever we fail to open a block announces substream with any of these peers
    important_nodes: HashSet<PeerId, fnv::FnvBuildHasher>,

    /// Names of the various chains the network service connects to. Used only for logging
    /// purposes.
    log_chain_names: Vec<String>,
}

impl<TPlat: Platform> NetworkService<TPlat> {
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
                now: TPlat::now(),
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
                            match network_service.network.next_event(TPlat::now()).await {
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

        let (connec_tx, mut connec_rx) = mpsc::channel(8);

        // Spawn tasks dedicated to opening connections.
        // Multiple tasks are spawned, and each task blocks during the connection process, in
        // order to limit the number of simultaneous connection attempts.
        for _ in 0..8 {
            (config.tasks_executor)(
                "connections-open".into(),
                Box::pin({
                    let network_service = network_service.clone();
                    let mut connec_tx = connec_tx.clone();
                    let future = async move {
                        loop {
                            let start_connect = network_service
                                .network
                                .next_start_connect(|| TPlat::now())
                                .await;

                            let is_bootnode = network_service
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
                                TPlat::connect(&start_connect.multiaddr.to_string())
                            };

                            // Perform the connection process.
                            let socket = {
                                let socket = socket.fuse();
                                futures::pin_mut!(socket);
                                let mut timeout = TPlat::sleep_until(start_connect.timeout).fuse();

                                let result = futures::select! {
                                    _ = timeout => Err(None),
                                    result = socket => result.map_err(Some),
                                };

                                match (&result, is_bootnode) {
                                    (Ok(_), _) => {}
                                    (Err(None), true) => {
                                        log::warn!(
                                            target: "connections",
                                            "Timeout when trying to reach bootnode {} through {}",
                                            start_connect.expected_peer_id, start_connect.multiaddr
                                        );
                                    }
                                    (Err(None), false) => {
                                        log::debug!(
                                            target: "connections",
                                            "Pending({:?}, {}) => Timeout ({})",
                                            start_connect.id, start_connect.expected_peer_id,
                                            start_connect.multiaddr
                                        );
                                    }
                                    (Err(Some(err)), true) if !err.is_bad_addr => {
                                        log::warn!(
                                            target: "connections",
                                            "Failed to reach bootnode {} through {}: {}",
                                            start_connect.expected_peer_id, start_connect.multiaddr,
                                            err.message
                                        );
                                    }
                                    (Err(Some(err)), _) => {
                                        log::debug!(
                                            target: "connections",
                                            "Pending({:?}, {}) => Failed to reach ({}): {}",
                                            start_connect.id, start_connect.expected_peer_id,
                                            start_connect.multiaddr, err.message
                                        );
                                    }
                                }

                                match result {
                                    Ok(ws) => ws,
                                    Err(err) => {
                                        network_service
                                            .network
                                            .pending_outcome_err(
                                                start_connect.id,
                                                err.map_or(false, |err| err.is_bad_addr),
                                            ) // TODO: should pass a proper value for `is_unreachable`, but an error is sometimes returned despite a timeout https://github.com/paritytech/smoldot/issues/1531
                                            .await;

                                        // After a failed connection attempt, wait for a bit
                                        // before trying again.
                                        TPlat::sleep(Duration::from_millis(500)).await;
                                        continue;
                                    }
                                }
                            };

                            // Connection process is successful. Notify the network state machine.
                            let id = network_service
                                .network
                                .pending_outcome_ok(start_connect.id)
                                .await;
                            log::debug!(
                                target: "connections",
                                "Pending({:?}, {}) => Connection({:?}) through {}",
                                start_connect.id,
                                start_connect.expected_peer_id,
                                id,
                                start_connect.multiaddr
                            );

                            let network_service2 = network_service.clone();
                            // Sending the new connection might fail in case a shutdown is
                            // happening.
                            let _ = connec_tx
                                .send(Box::pin({
                                    connection_task(
                                        socket,
                                        network_service2,
                                        id,
                                        start_connect.expected_peer_id,
                                        start_connect.multiaddr,
                                        is_bootnode,
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
        }

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
                            TPlat::sleep(next_discovery).await;
                            next_discovery = cmp::min(next_discovery * 2, Duration::from_secs(120));

                            match network_service
                                .network
                                .kademlia_discovery_round(TPlat::now(), chain_index)
                                .await
                            {
                                Ok(insert) => {
                                    log::debug!(
                                        target: "connections", "On chain {}, discovered: {}",
                                        &network_service.log_chain_names[chain_index],
                                        insert.discovered().map(|(p, _)| p.to_string()).join(", ")
                                    );

                                    insert.insert(&TPlat::now()).await;
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

                            TPlat::sleep(next_round).await;
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
        match &config.start {
            protocol::BlocksRequestConfigStart::Hash(hash) => {
                log::debug!(
                    target: "network",
                    "Connection({}) <= BlocksRequest(start: {}, num: {}, descending: {:?}, header: {:?}, body: {:?}, justifications: {:?})",
                    target, HashDisplay(hash), config.desired_count.get(),
                    matches!(config.direction, protocol::BlocksRequestDirection::Descending),
                    config.fields.header, config.fields.body, config.fields.justification
                );
            }
            protocol::BlocksRequestConfigStart::Number(number) => {
                log::debug!(
                    target: "network",
                    "Connection({}) <= BlocksRequest(start: #{}, num: {}, descending: {:?}, header: {:?}, body: {:?}, justifications: {:?})",
                    target, number, config.desired_count.get(),
                    matches!(config.direction, protocol::BlocksRequestDirection::Descending),
                    config.fields.header, config.fields.body, config.fields.justification
                );
            }
        }

        let result = self
            .inner
            .network
            .blocks_request(TPlat::now(), &target, chain_index, config)
            .await;

        match &result {
            Ok(blocks) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => BlocksRequest(num_blocks: {}, block_data_total_size: {})",
                    target,
                    blocks.len(),
                    BytesDisplay(blocks.iter().fold(0, |sum, block| {
                        let block_size = block.header.as_ref().map_or(0, |h| h.len()) +
                            block.body.as_ref().map_or(0, |b| b.iter().fold(0, |s, e| s + e.len())) +
                            block.justification.as_ref().map_or(0, |j| j.len());
                        sum + u64::try_from(block_size).unwrap()
                    }))
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => BlocksRequest({})",
                    target,
                    err
                );
            }
        }

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
            .grandpa_warp_sync_request(TPlat::now(), &target, chain_index, begin_hash)
            .await;

        match &result {
            Ok(response) => {
                // TODO: print total bytes size
                log::debug!(
                    target: "network",
                    "Connection({}) => GrandpaWarpSyncRequest(num_fragments: {}, finished: {:?})",
                    target,
                    response.fragments.len(),
                    response.is_finished,
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => GrandpaWarpSyncRequest({})",
                    target,
                    err,
                );
            }
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
            "Connection({}) <= StorageProofRequest(block: {})",
            target,
            HashDisplay(&config.block_hash)
        );

        let result = self
            .inner
            .network
            .storage_proof_request(TPlat::now(), &target, chain_index, config)
            .await;

        match &result {
            Ok(items) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => StorageProofRequest(num_elems: {}, total_size: {})",
                    target,
                    items.len(),
                    BytesDisplay(items.iter().fold(0, |a, b| a + u64::try_from(b.len()).unwrap()))
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => StorageProofRequest({})",
                    target,
                    err
                );
            }
        }

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
            .call_proof_request(TPlat::now(), &target, chain_index, config)
            .await;

        match &result {
            Ok(items) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => CallProofRequest(num_elems: {}, total_size: {})",
                    target,
                    items.len(),
                    BytesDisplay(items.iter().fold(0, |a, b| a + u64::try_from(b.len()).unwrap()))
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => CallProofRequest({})",
                    target,
                    err
                );
            }
        }

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
        chain_index: usize,
        message: service::EncodedGrandpaCommitMessage,
    },
}

/// Asynchronous task managing a specific connection.
///
/// `is_bootnode` controls the log level used for problems that happen on this connection.
async fn connection_task<TPlat: Platform>(
    mut websocket: TPlat::Connection,
    network_service: Arc<NetworkServiceInner<TPlat>>,
    id: service::ConnectionId,
    expected_peer_id: PeerId,
    attemped_multiaddr: Multiaddr,
    is_bootnode: bool,
) {
    let mut write_buffer = vec![0; 4096];

    loop {
        let now = TPlat::now();

        let mut read_write = ReadWrite {
            now: now.clone(),
            incoming_buffer: TPlat::read_buffer(&mut websocket),
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
            Err(err) if is_bootnode => {
                match err {
                    // Ungraceful termination.
                    ConnectionError::Established(_) | ConnectionError::Handshake(_) => {
                        log::warn!(
                            target: "connections", "Error in connection with bootnode {}: {}",
                            expected_peer_id, err
                        );
                    }
                    // Graceful termination.
                    ConnectionError::LocalShutdown | ConnectionError::Eof => {}
                }

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
        let wake_up_after = read_write.wake_up_after.clone();

        let wake_up_future = if let Some(wake_up_future) = read_write.wake_up_future.take() {
            future::Either::Left(wake_up_future)
        } else {
            future::Either::Right(future::pending())
        };

        drop(read_write);

        if written_bytes != 0 {
            TPlat::send(&mut websocket, &write_buffer[..written_bytes]);
        }

        TPlat::advance_read_cursor(&mut websocket, read_bytes);

        // Starting from here, we block (or not) the current task until more processing needs
        // to happen.

        // Future ready when the connection state machine requests more processing.
        let poll_after = if let Some(wake_up) = wake_up_after {
            if wake_up > now {
                let dur = wake_up - now;
                future::Either::Left(TPlat::sleep(dur))
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
            future::Either::Left(TPlat::wait_more_data(&mut websocket))
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
