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
//! The [`NetworkService`] spawns one background task (using [`PlatformRef::spawn_task`]) for
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
//! After a [`NetworkService`] is created, one can add chains using [`NetworkService::add_chain`].
//! If all references to a [`NetworkServiceChain`] are destroyed, the chain is automatically
//! purged.
//!
//! An important part of the API is the list of channel receivers of [`Event`] returned by
//! [`NetworkServiceChain::subscribe`]. These channels inform the foreground about updates to the
//! network connectivity.

use crate::{
    log,
    platform::{self, PlatformRef, address_parse},
};

use alloc::{
    borrow::ToOwned as _,
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec::{self, Vec},
};
use core::{cmp, mem, num::NonZero, pin::Pin, time::Duration};
use futures_channel::oneshot;
use futures_lite::FutureExt as _;
use futures_util::{StreamExt as _, future, stream};
use hashbrown::{HashMap, HashSet};
use rand::seq::IteratorRandom as _;
use rand_chacha::rand_core::SeedableRng as _;
use smoldot::{
    header,
    informant::{BytesDisplay, HashDisplay},
    libp2p::{
        connection,
        multiaddr::{self, Multiaddr},
        peer_id,
    },
    network::{basic_peering_strategy, codec, service},
};

pub use codec::{CallProofRequestConfig, Role};
pub use service::{ChainId, EncodedMerkleProof, PeerId, QueueNotificationError};

mod tasks;

/// Configuration for a [`NetworkService`].
pub struct Config<TPlat> {
    /// Access to the platform's capabilities.
    pub platform: TPlat,

    /// Value sent back for the agent version when receiving an identification request.
    pub identify_agent_version: String,

    /// Capacity to allocate for the list of chains.
    pub chains_capacity: usize,

    /// Maximum number of connections that the service can open simultaneously. After this value
    /// has been reached, a new connection can be opened after each
    /// [`Config::connections_open_pool_restore_delay`].
    pub connections_open_pool_size: u32,

    /// Delay after which the service can open a new connection.
    /// The delay is cumulative. If no connection has been opened for example for twice this
    /// duration, then two connections can be opened at the same time, up to a maximum of
    /// [`Config::connections_open_pool_size`].
    pub connections_open_pool_restore_delay: Duration,
}

/// See [`NetworkService::add_chain`].
///
/// Note that this configuration is intentionally missing a field containing the bootstrap
/// nodes of the chain. Bootstrap nodes are supposed to be added afterwards by calling
/// [`NetworkServiceChain::discover`].
pub struct ConfigChain {
    /// Name of the chain, for logging purposes.
    pub log_name: String,

    /// Number of "out slots" of this chain. We establish simultaneously gossip substreams up to
    /// this number of peers.
    pub num_out_slots: usize,

    /// Hash of the genesis block of the chain. Sent to other nodes in order to determine whether
    /// the chains match.
    ///
    /// > **Note**: Be aware that this *must* be the *genesis* block, not any block known to be
    /// >           in the chain.
    pub genesis_block_hash: [u8; 32],

    /// Number and hash of the current best block. Can later be updated with
    /// [`NetworkServiceChain::set_local_best_block`].
    pub best_block: (u64, [u8; 32]),

    /// Optional identifier to insert into the networking protocol names. Used to differentiate
    /// between chains with the same genesis hash.
    pub fork_id: Option<String>,

    /// Number of bytes of the block number in the networking protocol.
    pub block_number_bytes: usize,

    /// Must be `Some` if and only if the chain uses the GrandPa networking protocol. Contains the
    /// number of the finalized block at the time of the initialization.
    pub grandpa_protocol_finalized_block_height: Option<u64>,
}

pub struct NetworkService<TPlat: PlatformRef> {
    /// Channel connected to the background service.
    messages_tx: async_channel::Sender<ToBackground<TPlat>>,

    /// See [`Config::platform`].
    platform: TPlat,
}

impl<TPlat: PlatformRef> NetworkService<TPlat> {
    /// Initializes the network service with the given configuration.
    pub fn new(config: Config<TPlat>) -> Arc<Self> {
        let (main_messages_tx, main_messages_rx) = async_channel::bounded(4);

        let network = service::ChainNetwork::new(service::Config {
            chains_capacity: config.chains_capacity,
            connections_capacity: 32,
            handshake_timeout: Duration::from_secs(8),
            randomness_seed: {
                let mut seed = [0; 32];
                config.platform.fill_random_bytes(&mut seed);
                seed
            },
        });

        // Spawn main task that processes the network service.
        let (tasks_messages_tx, tasks_messages_rx) = async_channel::bounded(32);
        let task = Box::pin(background_task(BackgroundTask {
            randomness: rand_chacha::ChaCha20Rng::from_seed({
                let mut seed = [0; 32];
                config.platform.fill_random_bytes(&mut seed);
                seed
            }),
            identify_agent_version: config.identify_agent_version,
            tasks_messages_tx,
            tasks_messages_rx: Box::pin(tasks_messages_rx),
            peering_strategy: basic_peering_strategy::BasicPeeringStrategy::new(
                basic_peering_strategy::Config {
                    randomness_seed: {
                        let mut seed = [0; 32];
                        config.platform.fill_random_bytes(&mut seed);
                        seed
                    },
                    peers_capacity: 50, // TODO: ?
                    chains_capacity: config.chains_capacity,
                },
            ),
            network,
            connections_open_pool_size: config.connections_open_pool_size,
            connections_open_pool_restore_delay: config.connections_open_pool_restore_delay,
            num_recent_connection_opening: 0,
            next_recent_connection_restore: None,
            platform: config.platform.clone(),
            open_gossip_links: BTreeMap::new(),
            event_pending_send: None,
            event_senders: either::Left(Vec::new()),
            pending_new_subscriptions: Vec::new(),
            important_nodes: HashSet::with_capacity_and_hasher(16, Default::default()),
            main_messages_rx: Box::pin(main_messages_rx),
            messages_rx: stream::SelectAll::new(),
            blocks_requests: HashMap::with_capacity_and_hasher(8, Default::default()),
            grandpa_warp_sync_requests: HashMap::with_capacity_and_hasher(8, Default::default()),
            storage_proof_requests: HashMap::with_capacity_and_hasher(8, Default::default()),
            call_proof_requests: HashMap::with_capacity_and_hasher(8, Default::default()),
            child_storage_proof_requests: HashMap::with_capacity_and_hasher(8, Default::default()),
            chains_by_next_discovery: BTreeMap::new(),
        }));

        config.platform.spawn_task("network-service".into(), {
            let platform = config.platform.clone();
            async move {
                task.await;
                log!(&platform, Debug, "network", "shutdown");
            }
        });

        Arc::new(NetworkService {
            messages_tx: main_messages_tx,
            platform: config.platform,
        })
    }

    /// Adds a chain to the list of chains that the network service connects to.
    ///
    /// Returns an object representing the chain and that allows interacting with it. If all
    /// references to [`NetworkServiceChain`] are destroyed, the network service automatically
    /// purges that chain.
    pub fn add_chain(&self, config: ConfigChain) -> Arc<NetworkServiceChain<TPlat>> {
        let (messages_tx, messages_rx) = async_channel::bounded(32);

        // TODO: this code is hacky because we don't want to make `add_chain` async at the moment, because it's not convenient for lib.rs
        self.platform.spawn_task("add-chain-message-send".into(), {
            let config = service::ChainConfig {
                grandpa_protocol_config: config.grandpa_protocol_finalized_block_height.map(
                    |commit_finalized_height| service::GrandpaState {
                        commit_finalized_height,
                        round_number: 1,
                        set_id: 0,
                    },
                ),
                fork_id: config.fork_id.clone(),
                block_number_bytes: config.block_number_bytes,
                best_hash: config.best_block.1,
                best_number: config.best_block.0,
                genesis_hash: config.genesis_block_hash,
                role: Role::Light,
                allow_inbound_block_requests: false,
                user_data: Chain {
                    log_name: config.log_name,
                    block_number_bytes: config.block_number_bytes,
                    num_out_slots: config.num_out_slots,
                    num_references: NonZero::<usize>::new(1).unwrap(),
                    next_discovery_period: Duration::from_secs(2),
                    next_discovery_when: self.platform.now(),
                },
            };

            let messages_tx = self.messages_tx.clone();
            async move {
                let _ = messages_tx
                    .send(ToBackground::AddChain {
                        messages_rx,
                        config,
                    })
                    .await;
            }
        });

        Arc::new(NetworkServiceChain {
            _keep_alive_messages_tx: self.messages_tx.clone(),
            messages_tx,
            marker: core::marker::PhantomData,
        })
    }
}

pub struct NetworkServiceChain<TPlat: PlatformRef> {
    /// Copy of [`NetworkService::messages_tx`]. Used in order to maintain the network service
    /// background task alive.
    _keep_alive_messages_tx: async_channel::Sender<ToBackground<TPlat>>,

    /// Channel to send messages to the background task.
    messages_tx: async_channel::Sender<ToBackgroundChain>,

    /// Dummy to hold the `TPlat` type.
    marker: core::marker::PhantomData<TPlat>,
}

/// Severity of a ban. See [`NetworkServiceChain::ban_and_disconnect`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BanSeverity {
    Low,
    High,
}

impl<TPlat: PlatformRef> NetworkServiceChain<TPlat> {
    /// Subscribes to the networking events that happen on the given chain.
    ///
    /// Calling this function returns a `Receiver` that receives events about the chain.
    /// The new channel will immediately receive events about all the existing connections, so
    /// that it is able to maintain a coherent view of the network.
    ///
    /// Note that this function is `async`, but it should return very quickly.
    ///
    /// The `Receiver` **must** be polled continuously. When the channel is full, the networking
    /// connections will be back-pressured until the channel isn't full anymore.
    ///
    /// The `Receiver` never yields `None` unless the [`NetworkService`] crashes or is destroyed.
    /// If `None` is yielded and the [`NetworkService`] is still alive, you should call
    /// [`NetworkServiceChain::subscribe`] again to obtain a new `Receiver`.
    ///
    /// # Panic
    ///
    /// Panics if the given [`ChainId`] is invalid.
    ///
    // TODO: consider not killing the background until the channel is destroyed, as that would be a more sensical behaviour
    pub async fn subscribe(&self) -> async_channel::Receiver<Event> {
        let (tx, rx) = async_channel::bounded(128);

        self.messages_tx
            .send(ToBackgroundChain::Subscribe { sender: tx })
            .await
            .unwrap();

        rx
    }

    /// Starts asynchronously disconnecting the given peer. A [`Event::Disconnected`] will later be
    /// generated. Prevents a new gossip link with the same peer from being reopened for a
    /// little while.
    ///
    /// `reason` is a human-readable string printed in the logs.
    ///
    /// Due to race conditions, it is possible to reconnect to the peer soon after, in case the
    /// reconnection was already happening as the call to this function is still being processed.
    /// If that happens another [`Event::Disconnected`] will be delivered afterwards. In other
    /// words, this function guarantees that we will be disconnected in the future rather than
    /// guarantees that we will disconnect.
    pub async fn ban_and_disconnect(
        &self,
        peer_id: PeerId,
        severity: BanSeverity,
        reason: &'static str,
    ) {
        let _ = self
            .messages_tx
            .send(ToBackgroundChain::DisconnectAndBan {
                peer_id,
                severity,
                reason,
            })
            .await;
    }

    /// Sends a blocks request to the given peer.
    // TODO: more docs
    pub async fn blocks_request(
        self: Arc<Self>,
        target: PeerId,
        config: codec::BlocksRequestConfig,
        timeout: Duration,
    ) -> Result<Vec<codec::BlockData>, BlocksRequestError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackgroundChain::StartBlocksRequest {
                target: target.clone(),
                config,
                timeout,
                result: tx,
            })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Sends a grandpa warp sync request to the given peer.
    // TODO: more docs
    pub async fn grandpa_warp_sync_request(
        self: Arc<Self>,
        target: PeerId,
        begin_hash: [u8; 32],
        timeout: Duration,
    ) -> Result<service::EncodedGrandpaWarpSyncResponse, WarpSyncRequestError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackgroundChain::StartWarpSyncRequest {
                target: target.clone(),
                begin_hash,
                timeout,
                result: tx,
            })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    pub async fn set_local_best_block(&self, best_hash: [u8; 32], best_number: u64) {
        self.messages_tx
            .send(ToBackgroundChain::SetLocalBestBlock {
                best_hash,
                best_number,
            })
            .await
            .unwrap();
    }

    pub async fn set_local_grandpa_state(&self, grandpa_state: service::GrandpaState) {
        self.messages_tx
            .send(ToBackgroundChain::SetLocalGrandpaState { grandpa_state })
            .await
            .unwrap();
    }

    /// Sends a storage proof request to the given peer.
    // TODO: more docs
    pub async fn storage_proof_request(
        self: Arc<Self>,
        target: PeerId, // TODO: takes by value because of futures longevity issue
        config: codec::StorageProofRequestConfig<impl Iterator<Item = impl AsRef<[u8]> + Clone>>,
        timeout: Duration,
    ) -> Result<service::EncodedMerkleProof, StorageProofRequestError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackgroundChain::StartStorageProofRequest {
                target: target.clone(),
                config: codec::StorageProofRequestConfig {
                    block_hash: config.block_hash,
                    keys: config
                        .keys
                        .map(|key| key.as_ref().to_vec()) // TODO: to_vec() overhead
                        .collect::<Vec<_>>()
                        .into_iter(),
                },
                timeout,
                result: tx,
            })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Sends a call proof request to the given peer.
    ///
    /// See also [`NetworkServiceChain::call_proof_request`].
    // TODO: more docs
    pub async fn call_proof_request(
        self: Arc<Self>,
        target: PeerId, // TODO: takes by value because of futures longevity issue
        config: codec::CallProofRequestConfig<'_, impl Iterator<Item = impl AsRef<[u8]>>>,
        timeout: Duration,
    ) -> Result<EncodedMerkleProof, CallProofRequestError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackgroundChain::StartCallProofRequest {
                target: target.clone(),
                config: codec::CallProofRequestConfig {
                    block_hash: config.block_hash,
                    method: config.method.into_owned().into(),
                    parameter_vectored: config
                        .parameter_vectored
                        .map(|v| v.as_ref().to_vec()) // TODO: to_vec() overhead
                        .collect::<Vec<_>>()
                        .into_iter(),
                },
                timeout,
                result: tx,
            })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Sends a child storage proof request to the given peer.
    pub async fn child_storage_proof_request(
        self: Arc<Self>,
        target: PeerId,
        config: codec::ChildStorageProofRequestConfig<
            impl AsRef<[u8]> + Clone,
            impl Iterator<Item = impl AsRef<[u8]> + Clone>,
        >,
        timeout: Duration,
    ) -> Result<service::EncodedMerkleProof, ChildStorageProofRequestError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackgroundChain::StartChildStorageProofRequest {
                target: target.clone(),
                config: ChildStorageProofRequestConfigOwned {
                    block_hash: config.block_hash,
                    child_trie: config.child_trie.as_ref().to_vec(),
                    keys: config
                        .keys
                        .map(|key| key.as_ref().to_vec())
                        .collect::<Vec<_>>(),
                },
                timeout,
                result: tx,
            })
            .await
            .unwrap();

        rx.await.unwrap()
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
    pub async fn announce_transaction(self: Arc<Self>, transaction: &[u8]) -> Vec<PeerId> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackgroundChain::AnnounceTransaction {
                transaction: transaction.to_vec(), // TODO: ovheread
                result: tx,
            })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// See [`service::ChainNetwork::gossip_send_block_announce`].
    pub async fn send_block_announce(
        self: Arc<Self>,
        target: &PeerId,
        scale_encoded_header: &[u8],
        is_best: bool,
    ) -> Result<(), QueueNotificationError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackgroundChain::SendBlockAnnounce {
                target: target.clone(),                              // TODO: overhead
                scale_encoded_header: scale_encoded_header.to_vec(), // TODO: overhead
                is_best,
                result: tx,
            })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Marks the given peers as belonging to the given chain, and adds some addresses to these
    /// peers to the address book.
    ///
    /// The `important_nodes` parameter indicates whether these nodes are considered note-worthy
    /// and should have additional logging.
    pub async fn discover(
        &self,
        list: impl IntoIterator<Item = (PeerId, impl IntoIterator<Item = Multiaddr>)>,
        important_nodes: bool,
    ) {
        self.messages_tx
            .send(ToBackgroundChain::Discover {
                // TODO: overhead
                list: list
                    .into_iter()
                    .map(|(peer_id, addrs)| {
                        (peer_id, addrs.into_iter().collect::<Vec<_>>().into_iter())
                    })
                    .collect::<Vec<_>>()
                    .into_iter(),
                important_nodes,
            })
            .await
            .unwrap();
    }

    /// Returns a list of nodes (their [`PeerId`] and multiaddresses) that we know are part of
    /// the network.
    ///
    /// Nodes that are discovered might disappear over time. In other words, there is no guarantee
    /// that a node that has been added through [`NetworkServiceChain::discover`] will later be
    /// returned by [`NetworkServiceChain::discovered_nodes`].
    pub async fn discovered_nodes(
        &self,
    ) -> impl Iterator<Item = (PeerId, impl Iterator<Item = Multiaddr>)> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackgroundChain::DiscoveredNodes { result: tx })
            .await
            .unwrap();

        rx.await
            .unwrap()
            .into_iter()
            .map(|(peer_id, addrs)| (peer_id, addrs.into_iter()))
    }

    /// Returns an iterator to the list of [`PeerId`]s that we have an established connection
    /// with.
    pub async fn peers_list(&self) -> impl Iterator<Item = PeerId> {
        let (tx, rx) = oneshot::channel();
        self.messages_tx
            .send(ToBackgroundChain::PeersList { result: tx })
            .await
            .unwrap();
        rx.await.unwrap().into_iter()
    }
}

/// Event that can happen on the network service.
#[derive(Debug, Clone)]
pub enum Event {
    Connected {
        peer_id: PeerId,
        role: Role,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    },
    Disconnected {
        peer_id: PeerId,
    },
    BlockAnnounce {
        peer_id: PeerId,
        announce: service::EncodedBlockAnnounce,
    },
    GrandpaNeighborPacket {
        peer_id: PeerId,
        finalized_block_height: u64,
    },
    /// Received a GrandPa commit message from the network.
    GrandpaCommitMessage {
        peer_id: PeerId,
        message: service::EncodedGrandpaCommitMessage,
    },
}

/// Error returned by [`NetworkServiceChain::blocks_request`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum BlocksRequestError {
    /// No established connection with the target.
    NoConnection,
    /// Error during the request.
    #[display("{_0}")]
    Request(service::BlocksRequestError),
}

/// Error returned by [`NetworkServiceChain::grandpa_warp_sync_request`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum WarpSyncRequestError {
    /// No established connection with the target.
    NoConnection,
    /// Error during the request.
    #[display("{_0}")]
    Request(service::GrandpaWarpSyncRequestError),
}

/// Error returned by [`NetworkServiceChain::storage_proof_request`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum StorageProofRequestError {
    /// No established connection with the target.
    NoConnection,
    /// Storage proof request is too large and can't be sent.
    RequestTooLarge,
    /// Error during the request.
    #[display("{_0}")]
    Request(service::StorageProofRequestError),
}

/// Error returned by [`NetworkServiceChain::call_proof_request`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum CallProofRequestError {
    /// No established connection with the target.
    NoConnection,
    /// Call proof request is too large and can't be sent.
    RequestTooLarge,
    /// Error during the request.
    #[display("{_0}")]
    Request(service::CallProofRequestError),
}

impl CallProofRequestError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    pub fn is_network_problem(&self) -> bool {
        match self {
            CallProofRequestError::Request(err) => err.is_network_problem(),
            CallProofRequestError::RequestTooLarge => false,
            CallProofRequestError::NoConnection => true,
        }
    }
}

/// Error returned by [`NetworkServiceChain::child_storage_proof_request`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum ChildStorageProofRequestError {
    /// No established connection with the target.
    NoConnection,
    /// Child storage proof request is too large and can't be sent.
    RequestTooLarge,
    /// Error during the request.
    #[display("{_0}")]
    Request(service::StorageProofRequestError),
}

impl ChildStorageProofRequestError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    pub fn is_network_problem(&self) -> bool {
        match self {
            ChildStorageProofRequestError::Request(err) => err.is_network_problem(),
            ChildStorageProofRequestError::RequestTooLarge => false,
            ChildStorageProofRequestError::NoConnection => true,
        }
    }
}

/// Owned version of [`codec::ChildStorageProofRequestConfig`] for sending across channel.
struct ChildStorageProofRequestConfigOwned {
    block_hash: [u8; 32],
    child_trie: Vec<u8>,
    keys: Vec<Vec<u8>>,
}

enum ToBackground<TPlat: PlatformRef> {
    AddChain {
        messages_rx: async_channel::Receiver<ToBackgroundChain>,
        config: service::ChainConfig<Chain<TPlat>>,
    },
}

enum ToBackgroundChain {
    RemoveChain,
    Subscribe {
        sender: async_channel::Sender<Event>,
    },
    DisconnectAndBan {
        peer_id: PeerId,
        severity: BanSeverity,
        reason: &'static str,
    },
    // TODO: serialize the request before sending over channel
    StartBlocksRequest {
        target: PeerId, // TODO: takes by value because of future longevity issue
        config: codec::BlocksRequestConfig,
        timeout: Duration,
        result: oneshot::Sender<Result<Vec<codec::BlockData>, BlocksRequestError>>,
    },
    // TODO: serialize the request before sending over channel
    StartWarpSyncRequest {
        target: PeerId,
        begin_hash: [u8; 32],
        timeout: Duration,
        result:
            oneshot::Sender<Result<service::EncodedGrandpaWarpSyncResponse, WarpSyncRequestError>>,
    },
    // TODO: serialize the request before sending over channel
    StartStorageProofRequest {
        target: PeerId,
        config: codec::StorageProofRequestConfig<vec::IntoIter<Vec<u8>>>,
        timeout: Duration,
        result: oneshot::Sender<Result<service::EncodedMerkleProof, StorageProofRequestError>>,
    },
    // TODO: serialize the request before sending over channel
    StartCallProofRequest {
        target: PeerId, // TODO: takes by value because of futures longevity issue
        config: codec::CallProofRequestConfig<'static, vec::IntoIter<Vec<u8>>>,
        timeout: Duration,
        result: oneshot::Sender<Result<service::EncodedMerkleProof, CallProofRequestError>>,
    },
    // TODO: serialize the request before sending over channel
    StartChildStorageProofRequest {
        target: PeerId,
        config: ChildStorageProofRequestConfigOwned,
        timeout: Duration,
        result: oneshot::Sender<Result<service::EncodedMerkleProof, ChildStorageProofRequestError>>,
    },
    SetLocalBestBlock {
        best_hash: [u8; 32],
        best_number: u64,
    },
    SetLocalGrandpaState {
        grandpa_state: service::GrandpaState,
    },
    AnnounceTransaction {
        transaction: Vec<u8>,
        result: oneshot::Sender<Vec<PeerId>>,
    },
    SendBlockAnnounce {
        target: PeerId,
        scale_encoded_header: Vec<u8>,
        is_best: bool,
        result: oneshot::Sender<Result<(), QueueNotificationError>>,
    },
    Discover {
        list: vec::IntoIter<(PeerId, vec::IntoIter<Multiaddr>)>,
        important_nodes: bool,
    },
    DiscoveredNodes {
        result: oneshot::Sender<Vec<(PeerId, Vec<Multiaddr>)>>,
    },
    PeersList {
        result: oneshot::Sender<Vec<PeerId>>,
    },
}

struct BackgroundTask<TPlat: PlatformRef> {
    /// See [`Config::platform`].
    platform: TPlat,

    /// Random number generator.
    randomness: rand_chacha::ChaCha20Rng,

    /// Value provided through [`Config::identify_agent_version`].
    identify_agent_version: String,

    /// Channel to send messages to the background task.
    tasks_messages_tx:
        async_channel::Sender<(service::ConnectionId, service::ConnectionToCoordinator)>,

    /// Channel to receive messages destined to the background task.
    tasks_messages_rx: Pin<
        Box<async_channel::Receiver<(service::ConnectionId, service::ConnectionToCoordinator)>>,
    >,

    /// Data structure holding the entire state of the networking.
    network: service::ChainNetwork<
        Chain<TPlat>,
        async_channel::Sender<service::CoordinatorToConnection>,
        TPlat::Instant,
    >,

    /// All known peers and their addresses.
    peering_strategy: basic_peering_strategy::BasicPeeringStrategy<ChainId, TPlat::Instant>,

    /// See [`Config::connections_open_pool_size`].
    connections_open_pool_size: u32,

    /// See [`Config::connections_open_pool_restore_delay`].
    connections_open_pool_restore_delay: Duration,

    /// Every time a connection is opened, the value in this field is increased by one. After
    /// [`BackgroundTask::next_recent_connection_restore`] has yielded, the value is reduced by
    /// one.
    num_recent_connection_opening: u32,

    /// Delay after which [`BackgroundTask::num_recent_connection_opening`] is increased by one.
    next_recent_connection_restore: Option<Pin<Box<TPlat::Delay>>>,

    /// List of all open gossip links.
    // TODO: using this data structure unfortunately means that PeerIds are cloned a lot, maybe some user data in ChainNetwork is better? not sure
    open_gossip_links: BTreeMap<(ChainId, PeerId), OpenGossipLinkState>,

    /// List of nodes that are considered as important for logging purposes.
    // TODO: should also detect whenever we fail to open a block announces substream with any of these peers
    important_nodes: HashSet<PeerId, fnv::FnvBuildHasher>,

    /// Event about to be sent on the senders of [`BackgroundTask::event_senders`].
    event_pending_send: Option<(ChainId, Event)>,

    /// Sending events through the public API.
    ///
    /// Contains either senders, or a `Future` that is currently sending an event and will yield
    /// the senders back once it is finished.
    // TODO: sort by ChainId instead of using a Vec?
    event_senders: either::Either<
        Vec<(ChainId, async_channel::Sender<Event>)>,
        Pin<Box<dyn Future<Output = Vec<(ChainId, async_channel::Sender<Event>)>> + Send>>,
    >,

    /// Whenever [`NetworkServiceChain::subscribe`] is called, the new sender is added to this list.
    /// Once [`BackgroundTask::event_senders`] is ready, we properly initialize these senders.
    pending_new_subscriptions: Vec<(ChainId, async_channel::Sender<Event>)>,

    main_messages_rx: Pin<Box<async_channel::Receiver<ToBackground<TPlat>>>>,

    messages_rx:
        stream::SelectAll<Pin<Box<dyn stream::Stream<Item = (ChainId, ToBackgroundChain)> + Send>>>,

    blocks_requests: HashMap<
        service::SubstreamId,
        oneshot::Sender<Result<Vec<codec::BlockData>, BlocksRequestError>>,
        fnv::FnvBuildHasher,
    >,

    grandpa_warp_sync_requests: HashMap<
        service::SubstreamId,
        oneshot::Sender<Result<service::EncodedGrandpaWarpSyncResponse, WarpSyncRequestError>>,
        fnv::FnvBuildHasher,
    >,

    storage_proof_requests: HashMap<
        service::SubstreamId,
        oneshot::Sender<Result<service::EncodedMerkleProof, StorageProofRequestError>>,
        fnv::FnvBuildHasher,
    >,

    call_proof_requests: HashMap<
        service::SubstreamId,
        oneshot::Sender<Result<service::EncodedMerkleProof, CallProofRequestError>>,
        fnv::FnvBuildHasher,
    >,

    child_storage_proof_requests: HashMap<
        service::SubstreamId,
        oneshot::Sender<Result<service::EncodedMerkleProof, ChildStorageProofRequestError>>,
        fnv::FnvBuildHasher,
    >,

    /// All chains, indexed by the value of [`Chain::next_discovery_when`].
    chains_by_next_discovery: BTreeMap<(TPlat::Instant, ChainId), Pin<Box<TPlat::Delay>>>,
}

struct Chain<TPlat: PlatformRef> {
    log_name: String,

    // TODO: this field is a hack due to the fact that `add_chain` can't be `async`; should eventually be fixed after a lib.rs refactor
    num_references: NonZero<usize>,

    /// See [`ConfigChain::block_number_bytes`].
    // TODO: redundant with ChainNetwork? since we might not need to know this in the future i'm reluctant to add a getter to ChainNetwork
    block_number_bytes: usize,

    /// See [`ConfigChain::num_out_slots`].
    num_out_slots: usize,

    /// When the next discovery should be started for this chain.
    next_discovery_when: TPlat::Instant,

    /// After [`Chain::next_discovery_when`] is reached, the following discovery happens after
    /// the given duration.
    next_discovery_period: Duration,
}

#[derive(Clone)]
struct OpenGossipLinkState {
    role: Role,
    best_block_number: u64,
    best_block_hash: [u8; 32],
    /// `None` if unknown.
    finalized_block_height: Option<u64>,
}

async fn background_task<TPlat: PlatformRef>(mut task: BackgroundTask<TPlat>) {
    loop {
        // Yield at every loop in order to provide better tasks granularity.
        futures_lite::future::yield_now().await;

        enum WakeUpReason<TPlat: PlatformRef> {
            ForegroundClosed,
            Message(ToBackground<TPlat>),
            MessageForChain(ChainId, ToBackgroundChain),
            NetworkEvent(service::Event<async_channel::Sender<service::CoordinatorToConnection>>),
            CanAssignSlot(PeerId, ChainId),
            NextRecentConnectionRestore,
            CanStartConnect(PeerId),
            CanOpenGossip(PeerId, ChainId),
            MessageFromConnection {
                connection_id: service::ConnectionId,
                message: service::ConnectionToCoordinator,
            },
            MessageToConnection {
                connection_id: service::ConnectionId,
                message: service::CoordinatorToConnection,
            },
            EventSendersReady,
            StartDiscovery(ChainId),
        }

        let wake_up_reason = {
            let message_received = async {
                task.main_messages_rx
                    .next()
                    .await
                    .map_or(WakeUpReason::ForegroundClosed, WakeUpReason::Message)
            };
            let message_for_chain_received = async {
                // Note that when the last entry of `messages_rx` yields `None`, `messages_rx`
                // itself will yield `None`. For this reason, we can't use
                // `task.messages_rx.is_empty()` to determine whether `messages_rx` will
                // yield `None`.
                let Some((chain_id, message)) = task.messages_rx.next().await else {
                    future::pending().await
                };
                WakeUpReason::MessageForChain(chain_id, message)
            };
            let message_from_task_received = async {
                let (connection_id, message) = task.tasks_messages_rx.next().await.unwrap();
                WakeUpReason::MessageFromConnection {
                    connection_id,
                    message,
                }
            };
            let service_event = async {
                if let Some(event) = (task.event_pending_send.is_none()
                    && task.pending_new_subscriptions.is_empty())
                .then(|| task.network.next_event())
                .flatten()
                {
                    WakeUpReason::NetworkEvent(event)
                } else if let Some(start_connect) = {
                    let x = (task.num_recent_connection_opening < task.connections_open_pool_size)
                        .then(|| {
                            task.network
                                .unconnected_desired()
                                .choose(&mut task.randomness)
                                .cloned()
                        })
                        .flatten();
                    x
                } {
                    WakeUpReason::CanStartConnect(start_connect)
                } else if let Some((peer_id, chain_id)) = {
                    let x = task
                        .network
                        .connected_unopened_gossip_desired()
                        .choose(&mut task.randomness)
                        .map(|(peer_id, chain_id, _)| (peer_id.clone(), chain_id));
                    x
                } {
                    WakeUpReason::CanOpenGossip(peer_id, chain_id)
                } else if let Some((connection_id, message)) =
                    task.network.pull_message_to_connection()
                {
                    WakeUpReason::MessageToConnection {
                        connection_id,
                        message,
                    }
                } else {
                    'search: loop {
                        let mut earlier_unban = None;

                        for chain_id in task.network.chains().collect::<Vec<_>>() {
                            if task.network.gossip_desired_num(
                                chain_id,
                                service::GossipKind::ConsensusTransactions,
                            ) >= task.network[chain_id].num_out_slots
                            {
                                continue;
                            }

                            match task
                                .peering_strategy
                                .pick_assignable_peer(&chain_id, &task.platform.now())
                            {
                                basic_peering_strategy::AssignablePeer::Assignable(peer_id) => {
                                    break 'search WakeUpReason::CanAssignSlot(
                                        peer_id.clone(),
                                        chain_id,
                                    );
                                }
                                basic_peering_strategy::AssignablePeer::AllPeersBanned {
                                    next_unban,
                                } => {
                                    if earlier_unban.as_ref().map_or(true, |b| b > next_unban) {
                                        earlier_unban = Some(next_unban.clone());
                                    }
                                }
                                basic_peering_strategy::AssignablePeer::NoPeer => continue,
                            }
                        }

                        if let Some(earlier_unban) = earlier_unban {
                            task.platform.sleep_until(earlier_unban).await;
                        } else {
                            future::pending::<()>().await;
                        }
                    }
                }
            };
            let next_recent_connection_restore = async {
                if task.num_recent_connection_opening != 0
                    && task.next_recent_connection_restore.is_none()
                {
                    task.next_recent_connection_restore = Some(Box::pin(
                        task.platform
                            .sleep(task.connections_open_pool_restore_delay),
                    ));
                }
                if let Some(delay) = task.next_recent_connection_restore.as_mut() {
                    delay.await;
                    task.next_recent_connection_restore = None;
                    WakeUpReason::NextRecentConnectionRestore
                } else {
                    future::pending().await
                }
            };
            let finished_sending_event = async {
                if let either::Right(event_sending_future) = &mut task.event_senders {
                    let event_senders = event_sending_future.await;
                    task.event_senders = either::Left(event_senders);
                    WakeUpReason::EventSendersReady
                } else if task.event_pending_send.is_some()
                    || !task.pending_new_subscriptions.is_empty()
                {
                    WakeUpReason::EventSendersReady
                } else {
                    future::pending().await
                }
            };
            let start_discovery = async {
                let Some(mut next_discovery) = task.chains_by_next_discovery.first_entry() else {
                    future::pending().await
                };
                next_discovery.get_mut().await;
                let ((_, chain_id), _) = next_discovery.remove_entry();
                WakeUpReason::StartDiscovery(chain_id)
            };

            message_for_chain_received
                .or(message_received)
                .or(message_from_task_received)
                .or(service_event)
                .or(next_recent_connection_restore)
                .or(finished_sending_event)
                .or(start_discovery)
                .await
        };

        match wake_up_reason {
            WakeUpReason::ForegroundClosed => {
                // End the task.
                return;
            }
            WakeUpReason::Message(ToBackground::AddChain {
                messages_rx,
                config,
            }) => {
                // TODO: this is not a completely clean way of handling duplicate chains, because the existing chain might have a different best block and role and all ; also, multiple sync services will call set_best_block and set_finalized_block
                let chain_id = match task.network.add_chain(config) {
                    Ok(id) => id,
                    Err(service::AddChainError::Duplicate { existing_identical }) => {
                        task.network[existing_identical].num_references = task.network
                            [existing_identical]
                            .num_references
                            .checked_add(1)
                            .unwrap();
                        existing_identical
                    }
                };

                task.chains_by_next_discovery.insert(
                    (task.network[chain_id].next_discovery_when.clone(), chain_id),
                    Box::pin(
                        task.platform
                            .sleep_until(task.network[chain_id].next_discovery_when.clone()),
                    ),
                );

                task.messages_rx
                    .push(Box::pin(
                        messages_rx
                            .map(move |msg| (chain_id, msg))
                            .chain(stream::once(future::ready((
                                chain_id,
                                ToBackgroundChain::RemoveChain,
                            )))),
                    ) as Pin<Box<_>>);

                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "chain-added",
                    id = task.network[chain_id].log_name
                );
            }
            WakeUpReason::EventSendersReady => {
                // Dispatch the pending event, if any, to the various senders.

                // We made sure that the senders were ready before generating an event.
                let either::Left(event_senders) = &mut task.event_senders else {
                    unreachable!()
                };

                if let Some((event_to_dispatch_chain_id, event_to_dispatch)) =
                    task.event_pending_send.take()
                {
                    let mut event_senders = mem::take(event_senders);
                    task.event_senders = either::Right(Box::pin(async move {
                        // Elements in `event_senders` are removed one by one and inserted
                        // back if the channel is still open.
                        for index in (0..event_senders.len()).rev() {
                            let (event_sender_chain_id, event_sender) =
                                event_senders.swap_remove(index);
                            if event_sender_chain_id == event_to_dispatch_chain_id {
                                if event_sender.send(event_to_dispatch.clone()).await.is_err() {
                                    continue;
                                }
                            }
                            event_senders.push((event_sender_chain_id, event_sender));
                        }
                        event_senders
                    }));
                } else if !task.pending_new_subscriptions.is_empty() {
                    let pending_new_subscriptions = mem::take(&mut task.pending_new_subscriptions);
                    let mut event_senders = mem::take(event_senders);
                    // TODO: cloning :-/
                    let open_gossip_links = task.open_gossip_links.clone();
                    task.event_senders = either::Right(Box::pin(async move {
                        for (chain_id, new_subscription) in pending_new_subscriptions {
                            for ((link_chain_id, peer_id), state) in &open_gossip_links {
                                // TODO: optimize? this is O(n) by chain
                                if *link_chain_id != chain_id {
                                    continue;
                                }

                                let _ = new_subscription
                                    .send(Event::Connected {
                                        peer_id: peer_id.clone(),
                                        role: state.role,
                                        best_block_number: state.best_block_number,
                                        best_block_hash: state.best_block_hash,
                                    })
                                    .await;

                                if let Some(finalized_block_height) = state.finalized_block_height {
                                    let _ = new_subscription
                                        .send(Event::GrandpaNeighborPacket {
                                            peer_id: peer_id.clone(),
                                            finalized_block_height,
                                        })
                                        .await;
                                }
                            }

                            event_senders.push((chain_id, new_subscription));
                        }

                        event_senders
                    }));
                }
            }
            WakeUpReason::MessageFromConnection {
                connection_id,
                message,
            } => {
                task.network
                    .inject_connection_message(connection_id, message);
            }
            WakeUpReason::MessageForChain(chain_id, ToBackgroundChain::RemoveChain) => {
                if let Some(new_ref) =
                    NonZero::<usize>::new(task.network[chain_id].num_references.get() - 1)
                {
                    task.network[chain_id].num_references = new_ref;
                    continue;
                }

                for peer_id in task
                    .network
                    .gossip_connected_peers(chain_id, service::GossipKind::ConsensusTransactions)
                    .cloned()
                    .collect::<Vec<_>>()
                {
                    task.network
                        .gossip_close(
                            chain_id,
                            &peer_id,
                            service::GossipKind::ConsensusTransactions,
                        )
                        .unwrap();

                    let _was_in = task.open_gossip_links.remove(&(chain_id, peer_id));
                    debug_assert!(_was_in.is_some());
                }

                let _was_in = task
                    .chains_by_next_discovery
                    .remove(&(task.network[chain_id].next_discovery_when.clone(), chain_id));
                debug_assert!(_was_in.is_some());

                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "chain-removed",
                    id = task.network[chain_id].log_name
                );
                task.network.remove_chain(chain_id).unwrap();
                task.peering_strategy.remove_chain_peers(&chain_id);
            }
            WakeUpReason::MessageForChain(chain_id, ToBackgroundChain::Subscribe { sender }) => {
                task.pending_new_subscriptions.push((chain_id, sender));
            }
            WakeUpReason::MessageForChain(
                chain_id,
                ToBackgroundChain::DisconnectAndBan {
                    peer_id,
                    severity,
                    reason,
                },
            ) => {
                let ban_duration = Duration::from_secs(match severity {
                    BanSeverity::Low => 10,
                    BanSeverity::High => 40,
                });

                let had_slot = matches!(
                    task.peering_strategy.unassign_slot_and_ban(
                        &chain_id,
                        &peer_id,
                        task.platform.now() + ban_duration,
                    ),
                    basic_peering_strategy::UnassignSlotAndBan::Banned { had_slot: true }
                );

                if had_slot {
                    log!(
                        &task.platform,
                        Debug,
                        "network",
                        "slot-unassigned",
                        chain = &task.network[chain_id].log_name,
                        peer_id,
                        ?ban_duration,
                        reason = "user-ban",
                        user_reason = reason
                    );
                    task.network.gossip_remove_desired(
                        chain_id,
                        &peer_id,
                        service::GossipKind::ConsensusTransactions,
                    );
                }

                if task.network.gossip_is_connected(
                    chain_id,
                    &peer_id,
                    service::GossipKind::ConsensusTransactions,
                ) {
                    let _closed_result = task.network.gossip_close(
                        chain_id,
                        &peer_id,
                        service::GossipKind::ConsensusTransactions,
                    );
                    debug_assert!(_closed_result.is_ok());

                    log!(
                        &task.platform,
                        Debug,
                        "network",
                        "gossip-closed",
                        chain = &task.network[chain_id].log_name,
                        peer_id,
                    );

                    let _was_in = task.open_gossip_links.remove(&(chain_id, peer_id.clone()));
                    debug_assert!(_was_in.is_some());

                    debug_assert!(task.event_pending_send.is_none());
                    task.event_pending_send = Some((chain_id, Event::Disconnected { peer_id }));
                }
            }
            WakeUpReason::MessageForChain(
                chain_id,
                ToBackgroundChain::StartBlocksRequest {
                    target,
                    config,
                    timeout,
                    result,
                },
            ) => {
                match &config.start {
                    codec::BlocksRequestConfigStart::Hash(hash) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "blocks-request-started",
                            chain = task.network[chain_id].log_name, target,
                            start = HashDisplay(hash),
                            num = config.desired_count.get(),
                            descending = ?matches!(config.direction, codec::BlocksRequestDirection::Descending),
                            header = ?config.fields.header, body = ?config.fields.body,
                            justifications = ?config.fields.justifications
                        );
                    }
                    codec::BlocksRequestConfigStart::Number(number) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "blocks-request-started",
                            chain = task.network[chain_id].log_name, target, start = number,
                            num = config.desired_count.get(),
                            descending = ?matches!(config.direction, codec::BlocksRequestDirection::Descending),
                            header = ?config.fields.header, body = ?config.fields.body, justifications = ?config.fields.justifications
                        );
                    }
                }

                match task
                    .network
                    .start_blocks_request(&target, chain_id, config.clone(), timeout)
                {
                    Ok(substream_id) => {
                        task.blocks_requests.insert(substream_id, result);
                    }
                    Err(service::StartRequestError::NoConnection) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "blocks-request-error",
                            chain = task.network[chain_id].log_name,
                            target,
                            error = "NoConnection"
                        );
                        let _ = result.send(Err(BlocksRequestError::NoConnection));
                    }
                }
            }
            WakeUpReason::MessageForChain(
                chain_id,
                ToBackgroundChain::StartWarpSyncRequest {
                    target,
                    begin_hash,
                    timeout,
                    result,
                },
            ) => {
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "warp-sync-request-started",
                    chain = task.network[chain_id].log_name,
                    target,
                    start = HashDisplay(&begin_hash)
                );

                match task
                    .network
                    .start_grandpa_warp_sync_request(&target, chain_id, begin_hash, timeout)
                {
                    Ok(substream_id) => {
                        task.grandpa_warp_sync_requests.insert(substream_id, result);
                    }
                    Err(service::StartRequestError::NoConnection) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "warp-sync-request-error",
                            chain = task.network[chain_id].log_name,
                            target,
                            error = "NoConnection"
                        );
                        let _ = result.send(Err(WarpSyncRequestError::NoConnection));
                    }
                }
            }
            WakeUpReason::MessageForChain(
                chain_id,
                ToBackgroundChain::StartStorageProofRequest {
                    target,
                    config,
                    timeout,
                    result,
                },
            ) => {
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "storage-proof-request-started",
                    chain = task.network[chain_id].log_name,
                    target,
                    block_hash = HashDisplay(&config.block_hash)
                );

                match task.network.start_storage_proof_request(
                    &target,
                    chain_id,
                    config.clone(),
                    timeout,
                ) {
                    Ok(substream_id) => {
                        task.storage_proof_requests.insert(substream_id, result);
                    }
                    Err(service::StartRequestMaybeTooLargeError::NoConnection) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "storage-proof-request-error",
                            chain = task.network[chain_id].log_name,
                            target,
                            error = "NoConnection"
                        );
                        let _ = result.send(Err(StorageProofRequestError::NoConnection));
                    }
                    Err(service::StartRequestMaybeTooLargeError::RequestTooLarge) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "storage-proof-request-error",
                            chain = task.network[chain_id].log_name,
                            target,
                            error = "RequestTooLarge"
                        );
                        let _ = result.send(Err(StorageProofRequestError::RequestTooLarge));
                    }
                };
            }
            WakeUpReason::MessageForChain(
                chain_id,
                ToBackgroundChain::StartCallProofRequest {
                    target,
                    config,
                    timeout,
                    result,
                },
            ) => {
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "call-proof-request-started",
                    chain = task.network[chain_id].log_name,
                    target,
                    block_hash = HashDisplay(&config.block_hash),
                    function = config.method
                );
                // TODO: log parameter

                match task.network.start_call_proof_request(
                    &target,
                    chain_id,
                    config.clone(),
                    timeout,
                ) {
                    Ok(substream_id) => {
                        task.call_proof_requests.insert(substream_id, result);
                    }
                    Err(service::StartRequestMaybeTooLargeError::NoConnection) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "call-proof-request-error",
                            chain = task.network[chain_id].log_name,
                            target,
                            error = "NoConnection"
                        );
                        let _ = result.send(Err(CallProofRequestError::NoConnection));
                    }
                    Err(service::StartRequestMaybeTooLargeError::RequestTooLarge) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "call-proof-request-error",
                            chain = task.network[chain_id].log_name,
                            target,
                            error = "RequestTooLarge"
                        );
                        let _ = result.send(Err(CallProofRequestError::RequestTooLarge));
                    }
                };
            }
            WakeUpReason::MessageForChain(
                chain_id,
                ToBackgroundChain::StartChildStorageProofRequest {
                    target,
                    config,
                    timeout,
                    result,
                },
            ) => {
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "child-storage-proof-request-started",
                    chain = task.network[chain_id].log_name,
                    target,
                    block_hash = HashDisplay(&config.block_hash)
                );

                match task.network.start_child_storage_proof_request(
                    &target,
                    chain_id,
                    codec::ChildStorageProofRequestConfig {
                        block_hash: config.block_hash,
                        child_trie: &config.child_trie,
                        keys: config.keys.iter().map(|k| k.as_slice()),
                    },
                    timeout,
                ) {
                    Ok(substream_id) => {
                        task.child_storage_proof_requests
                            .insert(substream_id, result);
                    }
                    Err(service::StartRequestMaybeTooLargeError::NoConnection) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "child-storage-proof-request-error",
                            chain = task.network[chain_id].log_name,
                            target,
                            error = "NoConnection"
                        );
                        let _ = result.send(Err(ChildStorageProofRequestError::NoConnection));
                    }
                    Err(service::StartRequestMaybeTooLargeError::RequestTooLarge) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "child-storage-proof-request-error",
                            chain = task.network[chain_id].log_name,
                            target,
                            error = "RequestTooLarge"
                        );
                        let _ = result.send(Err(ChildStorageProofRequestError::RequestTooLarge));
                    }
                };
            }
            WakeUpReason::MessageForChain(
                chain_id,
                ToBackgroundChain::SetLocalBestBlock {
                    best_hash,
                    best_number,
                },
            ) => {
                task.network
                    .set_chain_local_best_block(chain_id, best_hash, best_number);
            }
            WakeUpReason::MessageForChain(
                chain_id,
                ToBackgroundChain::SetLocalGrandpaState { grandpa_state },
            ) => {
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "local-grandpa-state-announced",
                    chain = task.network[chain_id].log_name,
                    set_id = grandpa_state.set_id,
                    commit_finalized_height = grandpa_state.commit_finalized_height,
                );

                // TODO: log the list of peers we sent the packet to

                task.network
                    .gossip_broadcast_grandpa_state_and_update(chain_id, grandpa_state);
            }
            WakeUpReason::MessageForChain(
                chain_id,
                ToBackgroundChain::AnnounceTransaction {
                    transaction,
                    result,
                },
            ) => {
                // TODO: keep track of which peer knows about which transaction, and don't send it again

                let peers_to_send = task
                    .network
                    .gossip_connected_peers(chain_id, service::GossipKind::ConsensusTransactions)
                    .cloned()
                    .collect::<Vec<_>>();

                let mut peers_sent = Vec::with_capacity(peers_to_send.len());
                let mut peers_queue_full = Vec::with_capacity(peers_to_send.len());
                for peer in &peers_to_send {
                    match task
                        .network
                        .gossip_send_transaction(peer, chain_id, &transaction)
                    {
                        Ok(()) => peers_sent.push(peer.to_base58()),
                        Err(QueueNotificationError::QueueFull) => {
                            peers_queue_full.push(peer.to_base58())
                        }
                        Err(QueueNotificationError::NoConnection) => unreachable!(),
                    }
                }

                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "transaction-announced",
                    chain = task.network[chain_id].log_name,
                    transaction =
                        hex::encode(blake2_rfc::blake2b::blake2b(32, &[], &transaction).as_bytes()),
                    size = transaction.len(),
                    peers_sent = peers_sent.join(", "),
                    peers_queue_full = peers_queue_full.join(", "),
                );

                let _ = result.send(peers_to_send);
            }
            WakeUpReason::MessageForChain(
                chain_id,
                ToBackgroundChain::SendBlockAnnounce {
                    target,
                    scale_encoded_header,
                    is_best,
                    result,
                },
            ) => {
                // TODO: log who the announce was sent to
                let _ = result.send(task.network.gossip_send_block_announce(
                    &target,
                    chain_id,
                    &scale_encoded_header,
                    is_best,
                ));
            }
            WakeUpReason::MessageForChain(
                chain_id,
                ToBackgroundChain::Discover {
                    list,
                    important_nodes,
                },
            ) => {
                for (peer_id, addrs) in list {
                    if important_nodes {
                        task.important_nodes.insert(peer_id.clone());
                    }

                    // Note that we must call this function before `insert_address`, as documented
                    // in `basic_peering_strategy`.
                    task.peering_strategy
                        .insert_chain_peer(chain_id, peer_id.clone(), 30); // TODO: constant

                    for addr in addrs {
                        let _ =
                            task.peering_strategy
                                .insert_address(&peer_id, addr.into_bytes(), 10);
                        // TODO: constant
                    }
                }
            }
            WakeUpReason::MessageForChain(
                chain_id,
                ToBackgroundChain::DiscoveredNodes { result },
            ) => {
                // TODO: consider returning Vec<u8>s for the addresses?
                let _ = result.send(
                    task.peering_strategy
                        .chain_peers_unordered(&chain_id)
                        .map(|peer_id| {
                            let addrs = task
                                .peering_strategy
                                .peer_addresses(peer_id)
                                .map(|a| Multiaddr::from_bytes(a.to_owned()).unwrap())
                                .collect::<Vec<_>>();
                            (peer_id.clone(), addrs)
                        })
                        .collect::<Vec<_>>(),
                );
            }
            WakeUpReason::MessageForChain(chain_id, ToBackgroundChain::PeersList { result }) => {
                let _ = result.send(
                    task.network
                        .gossip_connected_peers(
                            chain_id,
                            service::GossipKind::ConsensusTransactions,
                        )
                        .cloned()
                        .collect(),
                );
            }
            WakeUpReason::StartDiscovery(chain_id) => {
                // Re-insert the chain in `chains_by_next_discovery`.
                let chain = &mut task.network[chain_id];
                chain.next_discovery_when = task.platform.now() + chain.next_discovery_period;
                chain.next_discovery_period =
                    cmp::min(chain.next_discovery_period * 2, Duration::from_secs(120));
                task.chains_by_next_discovery.insert(
                    (chain.next_discovery_when.clone(), chain_id),
                    Box::pin(
                        task.platform
                            .sleep(task.network[chain_id].next_discovery_period),
                    ),
                );

                let random_peer_id = {
                    let mut pub_key = [0; 32];
                    rand_chacha::rand_core::RngCore::fill_bytes(&mut task.randomness, &mut pub_key);
                    PeerId::from_public_key(&peer_id::PublicKey::Ed25519(pub_key))
                };

                // TODO: select target closest to the random peer instead
                let target = task
                    .network
                    .gossip_connected_peers(chain_id, service::GossipKind::ConsensusTransactions)
                    .next()
                    .cloned();

                if let Some(target) = target {
                    match task.network.start_kademlia_find_node_request(
                        &target,
                        chain_id,
                        &random_peer_id,
                        Duration::from_secs(20),
                    ) {
                        Ok(_) => {}
                        Err(service::StartRequestError::NoConnection) => unreachable!(),
                    };

                    log!(
                        &task.platform,
                        Debug,
                        "network",
                        "discovery-find-node-started",
                        chain = &task.network[chain_id].log_name,
                        request_target = target,
                        requested_peer_id = random_peer_id
                    );
                } else {
                    log!(
                        &task.platform,
                        Debug,
                        "network",
                        "discovery-skipped-no-peer",
                        chain = &task.network[chain_id].log_name
                    );
                }
            }
            WakeUpReason::NetworkEvent(service::Event::HandshakeFinished {
                peer_id,
                expected_peer_id,
                id,
            }) => {
                let remote_addr =
                    Multiaddr::from_bytes(task.network.connection_remote_addr(id)).unwrap(); // TODO: review this unwrap
                if let Some(expected_peer_id) = expected_peer_id.as_ref().filter(|p| **p != peer_id)
                {
                    log!(
                        &task.platform,
                        Debug,
                        "network",
                        "handshake-finished-peer-id-mismatch",
                        remote_addr,
                        expected_peer_id,
                        actual_peer_id = peer_id
                    );

                    let _was_in = task
                        .peering_strategy
                        .decrease_address_connections_and_remove_if_zero(
                            expected_peer_id,
                            remote_addr.as_ref(),
                        );
                    debug_assert!(_was_in.is_ok());
                    let _ = task.peering_strategy.increase_address_connections(
                        &peer_id,
                        remote_addr.into_bytes().to_vec(),
                        10,
                    );
                } else {
                    log!(
                        &task.platform,
                        Debug,
                        "network",
                        "handshake-finished",
                        remote_addr,
                        peer_id
                    );
                }
            }
            WakeUpReason::NetworkEvent(service::Event::PreHandshakeDisconnected {
                expected_peer_id: Some(_),
                ..
            })
            | WakeUpReason::NetworkEvent(service::Event::Disconnected { .. }) => {
                let (address, peer_id, handshake_finished) = match wake_up_reason {
                    WakeUpReason::NetworkEvent(service::Event::PreHandshakeDisconnected {
                        address,
                        expected_peer_id: Some(peer_id),
                        ..
                    }) => (address, peer_id, false),
                    WakeUpReason::NetworkEvent(service::Event::Disconnected {
                        address,
                        peer_id,
                        ..
                    }) => (address, peer_id, true),
                    _ => unreachable!(),
                };

                task.peering_strategy
                    .decrease_address_connections(&peer_id, &address)
                    .unwrap();
                let address = Multiaddr::from_bytes(address).unwrap();
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "connection-shutdown",
                    peer_id,
                    address,
                    ?handshake_finished
                );

                // Ban the peer in order to avoid trying over and over again the same address(es).
                // Even if the handshake was finished, it is possible that the peer simply shuts
                // down connections immediately after it has been opened, hence the ban.
                // Due to race conditions and peerid mismatches, it is possible that there is
                // another existing connection or connection attempt with that same peer. However,
                // it is not possible to be sure that we will reach 0 connections or connection
                // attempts, and thus we ban the peer every time.
                let ban_duration = Duration::from_secs(5);
                task.network.gossip_remove_desired_all(
                    &peer_id,
                    service::GossipKind::ConsensusTransactions,
                );
                for (&chain_id, what_happened) in task
                    .peering_strategy
                    .unassign_slots_and_ban(&peer_id, task.platform.now() + ban_duration)
                {
                    if matches!(
                        what_happened,
                        basic_peering_strategy::UnassignSlotsAndBan::Banned { had_slot: true }
                    ) {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "slot-unassigned",
                            chain = &task.network[chain_id].log_name,
                            peer_id,
                            ?ban_duration,
                            reason = "pre-handshake-disconnect"
                        );
                    }
                }
            }
            WakeUpReason::NetworkEvent(service::Event::PreHandshakeDisconnected {
                expected_peer_id: None,
                ..
            }) => {
                // This path can't be reached as we always set an expected peer id when creating
                // a connection.
                debug_assert!(false);
            }
            WakeUpReason::NetworkEvent(service::Event::PingOutSuccess {
                id,
                peer_id,
                ping_time,
            }) => {
                let remote_addr =
                    Multiaddr::from_bytes(task.network.connection_remote_addr(id)).unwrap(); // TODO: review this unwrap
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "pong",
                    peer_id,
                    remote_addr,
                    ?ping_time
                );
            }
            WakeUpReason::NetworkEvent(service::Event::BlockAnnounce {
                chain_id,
                peer_id,
                announce,
            }) => {
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "block-announce-received",
                    chain = &task.network[chain_id].log_name,
                    peer_id,
                    block_hash = HashDisplay(&header::hash_from_scale_encoded_header(
                        announce.decode().scale_encoded_header
                    )),
                    is_best = announce.decode().is_best
                );

                let decoded_announce = announce.decode();
                if decoded_announce.is_best {
                    let link = task
                        .open_gossip_links
                        .get_mut(&(chain_id, peer_id.clone()))
                        .unwrap();
                    if let Ok(decoded) = header::decode(
                        decoded_announce.scale_encoded_header,
                        task.network[chain_id].block_number_bytes,
                    ) {
                        link.best_block_hash = header::hash_from_scale_encoded_header(
                            decoded_announce.scale_encoded_header,
                        );
                        link.best_block_number = decoded.number;
                    }
                }

                debug_assert!(task.event_pending_send.is_none());
                task.event_pending_send =
                    Some((chain_id, Event::BlockAnnounce { peer_id, announce }));
            }
            WakeUpReason::NetworkEvent(service::Event::GossipConnected {
                peer_id,
                chain_id,
                role,
                best_number,
                best_hash,
                kind: service::GossipKind::ConsensusTransactions,
            }) => {
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "gossip-open-success",
                    chain = &task.network[chain_id].log_name,
                    peer_id,
                    best_number,
                    best_hash = HashDisplay(&best_hash)
                );

                let _prev_value = task.open_gossip_links.insert(
                    (chain_id, peer_id.clone()),
                    OpenGossipLinkState {
                        best_block_number: best_number,
                        best_block_hash: best_hash,
                        role,
                        finalized_block_height: None,
                    },
                );
                debug_assert!(_prev_value.is_none());

                debug_assert!(task.event_pending_send.is_none());
                task.event_pending_send = Some((
                    chain_id,
                    Event::Connected {
                        peer_id,
                        role,
                        best_block_number: best_number,
                        best_block_hash: best_hash,
                    },
                ));
            }
            WakeUpReason::NetworkEvent(service::Event::GossipOpenFailed {
                peer_id,
                chain_id,
                error,
                kind: service::GossipKind::ConsensusTransactions,
            }) => {
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "gossip-open-error",
                    chain = &task.network[chain_id].log_name,
                    peer_id,
                    ?error,
                );
                let ban_duration = Duration::from_secs(15);

                // Note that peer doesn't necessarily have an out slot, as this event might happen
                // as a result of an inbound gossip connection.
                let had_slot = if let service::GossipConnectError::GenesisMismatch { .. } = error {
                    matches!(
                        task.peering_strategy
                            .unassign_slot_and_remove_chain_peer(&chain_id, &peer_id),
                        basic_peering_strategy::UnassignSlotAndRemoveChainPeer::HadSlot
                    )
                } else {
                    matches!(
                        task.peering_strategy.unassign_slot_and_ban(
                            &chain_id,
                            &peer_id,
                            task.platform.now() + ban_duration,
                        ),
                        basic_peering_strategy::UnassignSlotAndBan::Banned { had_slot: true }
                    )
                };

                if had_slot {
                    log!(
                        &task.platform,
                        Debug,
                        "network",
                        "slot-unassigned",
                        chain = &task.network[chain_id].log_name,
                        peer_id,
                        ?ban_duration,
                        reason = "gossip-open-failed"
                    );
                    task.network.gossip_remove_desired(
                        chain_id,
                        &peer_id,
                        service::GossipKind::ConsensusTransactions,
                    );
                }
            }
            WakeUpReason::NetworkEvent(service::Event::GossipDisconnected {
                peer_id,
                chain_id,
                kind: service::GossipKind::ConsensusTransactions,
            }) => {
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "gossip-closed",
                    chain = &task.network[chain_id].log_name,
                    peer_id,
                );
                let ban_duration = Duration::from_secs(10);

                let _was_in = task.open_gossip_links.remove(&(chain_id, peer_id.clone()));
                debug_assert!(_was_in.is_some());

                // Note that peer doesn't necessarily have an out slot, as this event might happen
                // as a result of an inbound gossip connection.
                if matches!(
                    task.peering_strategy.unassign_slot_and_ban(
                        &chain_id,
                        &peer_id,
                        task.platform.now() + ban_duration,
                    ),
                    basic_peering_strategy::UnassignSlotAndBan::Banned { had_slot: true }
                ) {
                    log!(
                        &task.platform,
                        Debug,
                        "network",
                        "slot-unassigned",
                        chain = &task.network[chain_id].log_name,
                        peer_id,
                        ?ban_duration,
                        reason = "gossip-closed"
                    );
                    task.network.gossip_remove_desired(
                        chain_id,
                        &peer_id,
                        service::GossipKind::ConsensusTransactions,
                    );
                }

                debug_assert!(task.event_pending_send.is_none());
                task.event_pending_send = Some((chain_id, Event::Disconnected { peer_id }));
            }
            WakeUpReason::NetworkEvent(service::Event::RequestResult {
                substream_id,
                peer_id,
                chain_id,
                response: service::RequestResult::Blocks(response),
            }) => {
                match &response {
                    Ok(blocks) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "blocks-request-success",
                            chain = task.network[chain_id].log_name,
                            target = peer_id,
                            num_blocks = blocks.len(),
                            block_data_total_size =
                                BytesDisplay(blocks.iter().fold(0, |sum, block| {
                                    let block_size = block.header.as_ref().map_or(0, |h| h.len())
                                        + block
                                            .body
                                            .as_ref()
                                            .map_or(0, |b| b.iter().fold(0, |s, e| s + e.len()))
                                        + block
                                            .justifications
                                            .as_ref()
                                            .into_iter()
                                            .flat_map(|l| l.iter())
                                            .fold(0, |s, j| s + j.justification.len());
                                    sum + u64::try_from(block_size).unwrap()
                                }))
                        );
                    }
                    Err(error) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "blocks-request-error",
                            chain = task.network[chain_id].log_name,
                            target = peer_id,
                            ?error
                        );
                    }
                }

                match &response {
                    Ok(_) => {}
                    Err(service::BlocksRequestError::Request(err)) if !err.is_protocol_error() => {}
                    Err(err) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            format!(
                                "Error in block request with {}. This might indicate an \
                                incompatibility. Error: {}",
                                peer_id, err
                            )
                        );
                    }
                }

                let _ = task
                    .blocks_requests
                    .remove(&substream_id)
                    .unwrap()
                    .send(response.map_err(BlocksRequestError::Request));
            }
            WakeUpReason::NetworkEvent(service::Event::RequestResult {
                substream_id,
                peer_id,
                chain_id,
                response: service::RequestResult::GrandpaWarpSync(response),
            }) => {
                match &response {
                    Ok(response) => {
                        // TODO: print total bytes size
                        let decoded = response.decode();
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "warp-sync-request-success",
                            chain = task.network[chain_id].log_name,
                            target = peer_id,
                            num_fragments = decoded.fragments.len(),
                            is_finished = ?decoded.is_finished,
                        );
                    }
                    Err(error) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "warp-sync-request-error",
                            chain = task.network[chain_id].log_name,
                            target = peer_id,
                            ?error,
                        );
                    }
                }

                let _ = task
                    .grandpa_warp_sync_requests
                    .remove(&substream_id)
                    .unwrap()
                    .send(response.map_err(WarpSyncRequestError::Request));
            }
            WakeUpReason::NetworkEvent(service::Event::RequestResult {
                substream_id,
                peer_id,
                chain_id,
                response: service::RequestResult::StorageProof(response),
            }) => {
                match &response {
                    Ok(items) => {
                        let decoded = items.decode();
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "storage-proof-request-success",
                            chain = task.network[chain_id].log_name,
                            target = peer_id,
                            total_size = BytesDisplay(u64::try_from(decoded.len()).unwrap()),
                        );
                    }
                    Err(error) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "storage-proof-request-error",
                            chain = task.network[chain_id].log_name,
                            target = peer_id,
                            ?error
                        );
                    }
                }

                // Both regular storage proof and child storage proof use the same protocol,
                // so check both HashMaps for the request.
                if let Some(sender) = task.storage_proof_requests.remove(&substream_id) {
                    let _ = sender.send(response.map_err(StorageProofRequestError::Request));
                } else if let Some(sender) = task.child_storage_proof_requests.remove(&substream_id)
                {
                    let _ = sender.send(response.map_err(ChildStorageProofRequestError::Request));
                } else {
                    unreachable!()
                }
            }
            WakeUpReason::NetworkEvent(service::Event::RequestResult {
                substream_id,
                peer_id,
                chain_id,
                response: service::RequestResult::CallProof(response),
            }) => {
                match &response {
                    Ok(items) => {
                        let decoded = items.decode();
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "call-proof-request-success",
                            chain = task.network[chain_id].log_name,
                            target = peer_id,
                            total_size = BytesDisplay(u64::try_from(decoded.len()).unwrap())
                        );
                    }
                    Err(error) => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            "call-proof-request-error",
                            chain = task.network[chain_id].log_name,
                            target = peer_id,
                            ?error
                        );
                    }
                }

                let _ = task
                    .call_proof_requests
                    .remove(&substream_id)
                    .unwrap()
                    .send(response.map_err(CallProofRequestError::Request));
            }
            WakeUpReason::NetworkEvent(service::Event::RequestResult {
                peer_id: requestee_peer_id,
                chain_id,
                response: service::RequestResult::KademliaFindNode(Ok(nodes)),
                ..
            }) => {
                for (peer_id, mut addrs) in nodes {
                    // Make sure to not insert too many address for a single peer.
                    // While the .
                    if addrs.len() >= 10 {
                        addrs.truncate(10);
                    }

                    let mut valid_addrs = Vec::with_capacity(addrs.len());
                    for addr in addrs {
                        match Multiaddr::from_bytes(addr) {
                            Ok(a) => {
                                if platform::address_parse::multiaddr_to_address(&a)
                                    .ok()
                                    .map_or(false, |addr| {
                                        task.platform.supports_connection_type((&addr).into())
                                    })
                                {
                                    valid_addrs.push(a)
                                } else {
                                    log!(
                                        &task.platform,
                                        Debug,
                                        "network",
                                        "discovered-address-not-supported",
                                        chain = &task.network[chain_id].log_name,
                                        peer_id,
                                        addr = &a,
                                        obtained_from = requestee_peer_id
                                    );
                                }
                            }
                            Err((error, addr)) => {
                                log!(
                                    &task.platform,
                                    Debug,
                                    "network",
                                    "discovered-address-invalid",
                                    chain = &task.network[chain_id].log_name,
                                    peer_id,
                                    error,
                                    addr = hex::encode(&addr),
                                    obtained_from = requestee_peer_id
                                );
                            }
                        }
                    }

                    if !valid_addrs.is_empty() {
                        // Note that we must call this function before `insert_address`,
                        // as documented in `basic_peering_strategy`.
                        let insert_outcome =
                            task.peering_strategy
                                .insert_chain_peer(chain_id, peer_id.clone(), 30); // TODO: constant

                        if let basic_peering_strategy::InsertChainPeerResult::Inserted {
                            peer_removed,
                        } = insert_outcome
                        {
                            if let Some(peer_removed) = peer_removed {
                                log!(
                                    &task.platform,
                                    Debug,
                                    "network",
                                    "peer-purged-from-address-book",
                                    chain = &task.network[chain_id].log_name,
                                    peer_id = peer_removed,
                                );
                            }

                            log!(
                                &task.platform,
                                Debug,
                                "network",
                                "peer-discovered",
                                chain = &task.network[chain_id].log_name,
                                peer_id,
                                addrs = ?valid_addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(), // TODO: better formatting?
                                obtained_from = requestee_peer_id
                            );
                        }
                    }

                    for addr in valid_addrs {
                        let _insert_result =
                            task.peering_strategy
                                .insert_address(&peer_id, addr.into_bytes(), 10); // TODO: constant
                        debug_assert!(!matches!(
                            _insert_result,
                            basic_peering_strategy::InsertAddressResult::UnknownPeer
                        ));
                    }
                }
            }
            WakeUpReason::NetworkEvent(service::Event::RequestResult {
                peer_id,
                chain_id,
                response: service::RequestResult::KademliaFindNode(Err(error)),
                ..
            }) => {
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "discovery-find-node-error",
                    chain = &task.network[chain_id].log_name,
                    ?error,
                    find_node_target = peer_id,
                );

                // No error is printed if the request fails due to a benign networking error such
                // as an unresponsive peer.
                match error {
                    service::KademliaFindNodeError::RequestFailed(err)
                        if !err.is_protocol_error() => {}

                    service::KademliaFindNodeError::RequestFailed(
                        service::RequestError::Substream(
                            connection::established::RequestError::ProtocolNotAvailable,
                        ),
                    ) => {
                        // TODO: remove this warning in a long time
                        log!(
                            &task.platform,
                            Warn,
                            "network",
                            format!(
                                "Problem during discovery on {}: protocol not available. \
                                This might indicate that the version of Substrate used by \
                                the chain doesn't include \
                                <https://github.com/paritytech/substrate/pull/12545>.",
                                &task.network[chain_id].log_name
                            )
                        );
                    }
                    _ => {
                        log!(
                            &task.platform,
                            Debug,
                            "network",
                            format!(
                                "Problem during discovery on {}: {}",
                                &task.network[chain_id].log_name, error
                            )
                        );
                    }
                }
            }
            WakeUpReason::NetworkEvent(service::Event::RequestResult { .. }) => {
                // We never start any other kind of requests.
                unreachable!()
            }
            WakeUpReason::NetworkEvent(service::Event::GossipInDesired {
                peer_id,
                chain_id,
                kind: service::GossipKind::ConsensusTransactions,
            }) => {
                // The networking state machine guarantees that `GossipInDesired`
                // can't happen if we are already opening an out slot, which we do
                // immediately.
                // TODO: add debug_assert! ^
                if task
                    .network
                    .opened_gossip_undesired_by_chain(chain_id)
                    .count()
                    < 4
                {
                    log!(
                        &task.platform,
                        Debug,
                        "network",
                        "gossip-in-request",
                        chain = &task.network[chain_id].log_name,
                        peer_id,
                        outcome = "accepted"
                    );
                    task.network
                        .gossip_open(
                            chain_id,
                            &peer_id,
                            service::GossipKind::ConsensusTransactions,
                        )
                        .unwrap();
                } else {
                    log!(
                        &task.platform,
                        Debug,
                        "network",
                        "gossip-in-request",
                        chain = &task.network[chain_id].log_name,
                        peer_id,
                        outcome = "rejected",
                    );
                    task.network
                        .gossip_close(
                            chain_id,
                            &peer_id,
                            service::GossipKind::ConsensusTransactions,
                        )
                        .unwrap();
                }
            }
            WakeUpReason::NetworkEvent(service::Event::GossipInDesiredCancel { .. }) => {
                // Can't happen as we already instantaneously accept or reject gossip in requests.
                unreachable!()
            }
            WakeUpReason::NetworkEvent(service::Event::IdentifyRequestIn {
                peer_id,
                substream_id,
            }) => {
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "identify-request-received",
                    peer_id,
                );
                task.network
                    .respond_identify(substream_id, &task.identify_agent_version);
            }
            WakeUpReason::NetworkEvent(service::Event::BlocksRequestIn { .. }) => unreachable!(),
            WakeUpReason::NetworkEvent(service::Event::RequestInCancel { .. }) => {
                // All incoming requests are immediately answered.
                unreachable!()
            }
            WakeUpReason::NetworkEvent(service::Event::GrandpaNeighborPacket {
                chain_id,
                peer_id,
                state,
            }) => {
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "grandpa-neighbor-packet-received",
                    chain = &task.network[chain_id].log_name,
                    peer_id,
                    round_number = state.round_number,
                    set_id = state.set_id,
                    commit_finalized_height = state.commit_finalized_height,
                );

                task.open_gossip_links
                    .get_mut(&(chain_id, peer_id.clone()))
                    .unwrap()
                    .finalized_block_height = Some(state.commit_finalized_height);

                debug_assert!(task.event_pending_send.is_none());
                task.event_pending_send = Some((
                    chain_id,
                    Event::GrandpaNeighborPacket {
                        peer_id,
                        finalized_block_height: state.commit_finalized_height,
                    },
                ));
            }
            WakeUpReason::NetworkEvent(service::Event::GrandpaCommitMessage {
                chain_id,
                peer_id,
                message,
            }) => {
                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "grandpa-commit-message-received",
                    chain = &task.network[chain_id].log_name,
                    peer_id,
                    target_block_hash = HashDisplay(message.decode().target_hash),
                );

                debug_assert!(task.event_pending_send.is_none());
                task.event_pending_send =
                    Some((chain_id, Event::GrandpaCommitMessage { peer_id, message }));
            }
            WakeUpReason::NetworkEvent(service::Event::ProtocolError { peer_id, error }) => {
                // TODO: handle properly?
                log!(
                    &task.platform,
                    Warn,
                    "network",
                    "protocol-error",
                    peer_id,
                    ?error
                );

                // TODO: disconnect peer
            }
            WakeUpReason::CanAssignSlot(peer_id, chain_id) => {
                task.peering_strategy.assign_slot(&chain_id, &peer_id);

                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "slot-assigned",
                    chain = &task.network[chain_id].log_name,
                    peer_id
                );

                task.network.gossip_insert_desired(
                    chain_id,
                    peer_id,
                    service::GossipKind::ConsensusTransactions,
                );
            }
            WakeUpReason::NextRecentConnectionRestore => {
                task.num_recent_connection_opening =
                    task.num_recent_connection_opening.saturating_sub(1);
            }
            WakeUpReason::CanStartConnect(expected_peer_id) => {
                let Some(multiaddr) = task
                    .peering_strategy
                    .pick_address_and_add_connection(&expected_peer_id)
                else {
                    // There is no address for that peer in the address book.
                    task.network.gossip_remove_desired_all(
                        &expected_peer_id,
                        service::GossipKind::ConsensusTransactions,
                    );
                    let ban_duration = Duration::from_secs(10);
                    for (&chain_id, what_happened) in task.peering_strategy.unassign_slots_and_ban(
                        &expected_peer_id,
                        task.platform.now() + ban_duration,
                    ) {
                        if matches!(
                            what_happened,
                            basic_peering_strategy::UnassignSlotsAndBan::Banned { had_slot: true }
                        ) {
                            log!(
                                &task.platform,
                                Debug,
                                "network",
                                "slot-unassigned",
                                chain = &task.network[chain_id].log_name,
                                peer_id = expected_peer_id,
                                ?ban_duration,
                                reason = "no-address"
                            );
                        }
                    }
                    continue;
                };

                let multiaddr = match multiaddr::Multiaddr::from_bytes(multiaddr.to_owned()) {
                    Ok(a) => a,
                    Err((multiaddr::FromBytesError, addr)) => {
                        // Address is in an invalid format.
                        let _was_in = task
                            .peering_strategy
                            .decrease_address_connections_and_remove_if_zero(
                                &expected_peer_id,
                                &addr,
                            );
                        debug_assert!(_was_in.is_ok());
                        continue;
                    }
                };

                let address = address_parse::multiaddr_to_address(&multiaddr)
                    .ok()
                    .filter(|addr| {
                        task.platform.supports_connection_type(match &addr {
                            address_parse::AddressOrMultiStreamAddress::Address(addr) => {
                                From::from(addr)
                            }
                            address_parse::AddressOrMultiStreamAddress::MultiStreamAddress(
                                addr,
                            ) => From::from(addr),
                        })
                    });

                let Some(address) = address else {
                    // Address is in an invalid format or isn't supported by the platform.
                    let _was_in = task
                        .peering_strategy
                        .decrease_address_connections_and_remove_if_zero(
                            &expected_peer_id,
                            multiaddr.as_ref(),
                        );
                    debug_assert!(_was_in.is_ok());
                    continue;
                };

                // Each connection has its own individual Noise key.
                let noise_key = {
                    let mut noise_static_key = zeroize::Zeroizing::new([0u8; 32]);
                    task.platform.fill_random_bytes(&mut *noise_static_key);
                    let mut libp2p_key = zeroize::Zeroizing::new([0u8; 32]);
                    task.platform.fill_random_bytes(&mut *libp2p_key);
                    connection::NoiseKey::new(&libp2p_key, &noise_static_key)
                };

                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "connection-started",
                    expected_peer_id,
                    remote_addr = multiaddr,
                    local_peer_id =
                        peer_id::PublicKey::Ed25519(*noise_key.libp2p_public_ed25519_key())
                            .into_peer_id(),
                );

                task.num_recent_connection_opening += 1;

                let (coordinator_to_connection_tx, coordinator_to_connection_rx) =
                    async_channel::bounded(8);
                let task_name = format!("connection-{}", multiaddr);

                match address {
                    address_parse::AddressOrMultiStreamAddress::Address(address) => {
                        // As documented in the `PlatformRef` trait, `connect_stream` must
                        // return as soon as possible.
                        let connection = task.platform.connect_stream(address).await;

                        let (connection_id, connection_task) =
                            task.network.add_single_stream_connection(
                                task.platform.now(),
                                service::SingleStreamHandshakeKind::MultistreamSelectNoiseYamux {
                                    is_initiator: true,
                                    noise_key: &noise_key,
                                },
                                multiaddr.clone().into_bytes(),
                                Some(expected_peer_id.clone()),
                                coordinator_to_connection_tx,
                            );

                        task.platform.spawn_task(
                            task_name.into(),
                            tasks::single_stream_connection_task::<TPlat>(
                                connection,
                                multiaddr.to_string(),
                                task.platform.clone(),
                                connection_id,
                                connection_task,
                                coordinator_to_connection_rx,
                                task.tasks_messages_tx.clone(),
                            ),
                        );
                    }
                    address_parse::AddressOrMultiStreamAddress::MultiStreamAddress(
                        platform::MultiStreamAddress::WebRtc {
                            ip,
                            port,
                            remote_certificate_sha256,
                        },
                    ) => {
                        // We need to know the local TLS certificate in order to insert the
                        // connection, and as such we need to call `connect_multistream` here.
                        // As documented in the `PlatformRef` trait, `connect_multistream` must
                        // return as soon as possible.
                        let connection = task
                            .platform
                            .connect_multistream(platform::MultiStreamAddress::WebRtc {
                                ip,
                                port,
                                remote_certificate_sha256,
                            })
                            .await;

                        // Convert the SHA256 hashes into multihashes.
                        let local_tls_certificate_multihash = [18u8, 32]
                            .into_iter()
                            .chain(connection.local_tls_certificate_sha256.into_iter())
                            .collect();
                        let remote_tls_certificate_multihash = [18u8, 32]
                            .into_iter()
                            .chain(remote_certificate_sha256.iter().copied())
                            .collect();

                        let (connection_id, connection_task) =
                            task.network.add_multi_stream_connection(
                                task.platform.now(),
                                service::MultiStreamHandshakeKind::WebRtc {
                                    is_initiator: true,
                                    local_tls_certificate_multihash,
                                    remote_tls_certificate_multihash,
                                    noise_key: &noise_key,
                                },
                                multiaddr.clone().into_bytes(),
                                Some(expected_peer_id.clone()),
                                coordinator_to_connection_tx,
                            );

                        task.platform.spawn_task(
                            task_name.into(),
                            tasks::webrtc_multi_stream_connection_task::<TPlat>(
                                connection.connection,
                                multiaddr.to_string(),
                                task.platform.clone(),
                                connection_id,
                                connection_task,
                                coordinator_to_connection_rx,
                                task.tasks_messages_tx.clone(),
                            ),
                        );
                    }
                }
            }
            WakeUpReason::CanOpenGossip(peer_id, chain_id) => {
                task.network
                    .gossip_open(
                        chain_id,
                        &peer_id,
                        service::GossipKind::ConsensusTransactions,
                    )
                    .unwrap();

                log!(
                    &task.platform,
                    Debug,
                    "network",
                    "gossip-open-start",
                    chain = &task.network[chain_id].log_name,
                    peer_id,
                );
            }
            WakeUpReason::MessageToConnection {
                connection_id,
                message,
            } => {
                // Note that it is critical for the sending to not take too long here, in order to
                // not block the process of the network service.
                // In particular, if sending the message to the connection is blocked due to
                // sending a message on the connection-to-coordinator channel, this will result
                // in a deadlock.
                // For this reason, the connection task is always ready to immediately accept a
                // message on the coordinator-to-connection channel.
                let _send_result = task.network[connection_id].send(message).await;
                debug_assert!(_send_result.is_ok());
            }
        }
    }
}
