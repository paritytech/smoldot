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

use crate::libp2p::{
    connection,
    discovery::kademlia,
    multiaddr, peer_id,
    peers::{self, QueueNotificationError},
    PeerId,
};
use crate::network::protocol;
use crate::util;

use alloc::{
    collections::BTreeSet,
    format,
    string::{String, ToString as _},
    vec::Vec,
};
use core::{
    fmt, iter,
    num::NonZeroUsize,
    ops::{Add, Sub},
    task::Poll,
    time::Duration,
};
use futures::{
    lock::{Mutex, MutexGuard},
    prelude::*,
    task::AtomicWaker,
};
use rand::{Rng as _, RngCore as _, SeedableRng as _};

pub use crate::libp2p::{collection::ReadWrite, peers::ConnectionId};

/// Configuration for a [`ChainNetwork`].
pub struct Config {
    /// Capacity to initially reserve to the list of connections.
    pub connections_capacity: usize,

    /// Capacity to initially reserve to the list of peers.
    pub peers_capacity: usize,

    /// Seed for the randomness within the networking state machine.
    ///
    /// While this seed influences the general behaviour of the networking state machine, it
    /// notably isn't used when generating the ephemeral key used for the Diffie-Hellman
    /// handshake.
    /// This is a defensive measure against users passing a dummy seed instead of actual entropy.
    pub randomness_seed: [u8; 32],

    /// List of blockchain peer-to-peer networks to be connected to.
    ///
    /// > **Note**: As documented in [the module-level documentation](..), the [`ChainNetwork`]
    /// >           can connect to multiple blockchain networks at the same time.
    ///
    /// The order in which the chains are list is important. The index of each entry needs to be
    /// used later in order to refer to a specific chain.
    pub chains: Vec<ChainConfig>,

    // TODO: what about letting API users insert nodes later?
    pub known_nodes: Vec<(peer_id::PeerId, multiaddr::Multiaddr)>,

    /// Key used for the encryption layer.
    /// This is a Noise static key, according to the Noise specification.
    /// Signed using the actual libp2p key.
    pub noise_key: connection::NoiseKey,

    /// Number of events that can be buffered internally before connections are back-pressured.
    ///
    /// A good default value is 64.
    ///
    /// # Context
    ///
    /// The [`ChainNetwork`] maintains an internal buffer of the events returned by
    /// [`ChainNetwork::next_event`]. When [`ChainNetwork::read_write`] is called, an event might
    /// get pushed to this buffer. If this buffer is full, back-pressure will be applied to the
    /// connections in order to prevent new events from being pushed.
    ///
    /// This value is important if [`ChainNetwork::next_event`] is called at a slower than the
    /// calls to [`ChainNetwork::read_write`] generate events.
    pub pending_api_events_buffer_size: NonZeroUsize,
}

/// Configuration for a specific overlay network.
///
/// See [`Config::chains`].
pub struct ChainConfig {
    /// Identifier of the protocol, used on the wire to determine which chain messages refer to.
    ///
    /// > **Note**: This value is typically found in the specification of the chain (the
    /// >           "chain spec").
    pub protocol_id: String,

    /// List of node identities that are known to belong to this overlay network. The node
    /// identities are indices in [`Config::known_nodes`].
    pub bootstrap_nodes: Vec<usize>,

    /// If `Some`, the chain uses the GrandPa networking protocol.
    pub grandpa_protocol_config: Option<GrandpaState>,

    pub in_slots: u32,

    pub out_slots: u32,

    /// Hash of the best block according to the local node.
    pub best_hash: [u8; 32],
    /// Height of the best block according to the local node.
    pub best_number: u64,
    /// Hash of the genesis block (i.e. block number 0) according to the local node.
    pub genesis_hash: [u8; 32],
    pub role: protocol::Role,
}

#[derive(Debug, Copy, Clone)]
// TODO: link to some doc about how GrandPa works: what is a round, what is the set id, etc.
pub struct GrandpaState {
    pub round_number: u64,
    /// Set of authorities that will be used by the node to try finalize the children of the block
    /// of [`GrandpaState::commit_finalized_height`].
    pub set_id: u64,
    /// Height of the highest block considered final by the node.
    pub commit_finalized_height: u32,
}

/// Identifier of a pending connection requested by the network through a [`StartConnect`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingId(usize);

/// Data structure containing the list of all connections, pending or not, and their latest known
/// state. See also [the module-level documentation](..).
pub struct ChainNetwork<TNow> {
    /// Underlying data structure.
    inner: peers::Peers<multiaddr::Multiaddr, TNow>,

    /// Extra fields protected by a `Mutex`. Must only be locked around
    /// [`ChainNetwork::next_event`].
    guarded: Mutex<Guarded>,

    /// Extra fields protected by a `Mutex` and that relate to pending outgoing connections.
    pending: Mutex<PendingConnections>,

    /// For each item in [`ChainNetwork::chain_configs`], the corresponding Grandpa state.
    ///
    /// The `Vec` always has the same length as [`ChainNetwork::chain_configs`]. The `Option`
    /// is `None` if the chain doesn't use the Grandpa protocol.
    chain_grandpa_config: Mutex<Vec<Option<GrandpaState>>>,

    /// See [`Config::chains`].
    chain_configs: Vec<ChainConfig>,

    /// Generator for randomness.
    randomness: Mutex<rand_chacha::ChaCha20Rng>,

    /// Waker to wake up when [`ChainNetwork::next_start_connect`] should be called again by the
    /// user.
    next_start_connect_waker: AtomicWaker,
}

/// See [`ChainNetwork::guarded`].
struct Guarded {
    /// In the [`ChainNetwork::next_event`] function, an event is grabbed from the underlying
    /// [`peers::Peers`]. This event might lead to some asynchronous post-processing being
    /// needed. Because the user can interrupt the future returned by [`ChainNetwork::next_event`]
    /// at any point in time, this post-processing cannot be immediately performed, as the user
    /// could interrupt the future and lose the event. Instead, the necessary post-processing is
    /// stored in this field. This field is then processed before the next event is pulled.
    to_process_pre_event: Option<ToProcessPreEvent>,
}

/// See [`ChainNetwork::pending`].
struct PendingConnections {
    /// For each peer, the number of pending attempts.
    num_pending_per_peer: hashbrown::HashMap<PeerId, NonZeroUsize, ahash::RandomState>,

    /// Keys of this slab are [`PendingId`]s. Values are the parameters associated to that
    /// [`PendingId`].
    /// The entries here correspond to the entries in
    /// [`PendingConnections::num_pending_per_peer`].
    pending_ids: slab::Slab<(PeerId, multiaddr::Multiaddr)>,

    /// Combination of addresses that we assume could be dialed to reach a certain peer. When
    /// an address is attempted, it is immediately removed from this list. It is later added
    /// back if the dial is successful.
    ///
    /// Does not include "dialing" addresses. For example, no address should contain an outgoing
    /// TCP port.
    // TODO: never cleaned up until addresses are actually tried; the idea is to eventually use Kademlia k-buckets only
    // TODO: ideally we'd use a BTreeSet to optimize, but multiaddr has no min or max value
    potential_addresses: hashbrown::HashMap<PeerId, Vec<multiaddr::Multiaddr>, ahash::RandomState>,
}

/// See [`Guarded::to_process_pre_event`]
enum ToProcessPreEvent {
    AcceptNotificationsIn {
        id: peers::DesiredInNotificationId,
        handshake_back: Vec<u8>,
    },
    RefuseNotificationsIn {
        id: peers::DesiredInNotificationId,
    },
    NotificationsOut {
        id: peers::DesiredOutNotificationId,
        handshake: Vec<u8>,
    },
    QueueNotification {
        peer_id: PeerId,
        notifications_protocol_index: usize,
        notification: Vec<u8>,
    },
    SendGrandpaNeighborPacket {
        peer_id: PeerId,
        notifications_protocol_index: usize,
    },
}

// Update this when a new request response protocol is added.
const REQUEST_RESPONSE_PROTOCOLS_PER_CHAIN: usize = 4;
// Update this when a new notifications protocol is added.
const NOTIFICATIONS_PROTOCOLS_PER_CHAIN: usize = 3;

impl<TNow> ChainNetwork<TNow>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Initializes a new [`ChainNetwork`].
    pub fn new(config: Config) -> Self {
        // The order of protocols here is important, as it defines the values of `protocol_index`
        // to pass to libp2p or that libp2p produces.
        let notification_protocols = config
            .chains
            .iter()
            .flat_map(|chain| {
                iter::once(peers::NotificationProtocolConfig {
                    protocol_name: format!("/{}/block-announces/1", chain.protocol_id),
                    fallback_protocol_names: Vec::new(),
                    max_handshake_size: 1024 * 1024, // TODO: arbitrary
                    max_notification_size: 1024 * 1024,
                })
                .chain(iter::once(peers::NotificationProtocolConfig {
                    protocol_name: format!("/{}/transactions/1", chain.protocol_id),
                    fallback_protocol_names: Vec::new(),
                    max_handshake_size: 4,
                    max_notification_size: 16 * 1024 * 1024,
                }))
                .chain({
                    // The `has_grandpa_protocol` flag controls whether the chain uses GrandPa.
                    // Note, however, that GrandPa is technically left enabled (but unused) on all
                    // chains, in order to make the rest of the code of this module more
                    // comprehensible.
                    iter::once(peers::NotificationProtocolConfig {
                        protocol_name: "/paritytech/grandpa/1".to_string(),
                        fallback_protocol_names: Vec::new(),
                        max_handshake_size: 4,
                        max_notification_size: 1024 * 1024,
                    })
                })
            })
            .collect();

        // The order of protocols here is important, as it defines the values of `protocol_index`
        // to pass to libp2p or that libp2p produces.
        let request_response_protocols = iter::once(peers::ConfigRequestResponse {
            name: "/ipfs/id/1.0.0".into(),
            inbound_config: peers::ConfigRequestResponseIn::Empty,
            max_response_size: 4096,
            inbound_allowed: true,
            timeout: Duration::from_secs(20),
        })
        .chain(config.chains.iter().flat_map(|chain| {
            // TODO: limits are arbitrary
            iter::once(peers::ConfigRequestResponse {
                name: format!("/{}/sync/2", chain.protocol_id),
                inbound_config: peers::ConfigRequestResponseIn::Payload { max_size: 1024 },
                max_response_size: 10 * 1024 * 1024,
                // TODO: make this configurable
                inbound_allowed: false,
                timeout: Duration::from_secs(20),
            })
            .chain(iter::once(peers::ConfigRequestResponse {
                name: format!("/{}/light/2", chain.protocol_id),
                inbound_config: peers::ConfigRequestResponseIn::Payload {
                    max_size: 1024 * 512,
                },
                max_response_size: 10 * 1024 * 1024,
                // TODO: make this configurable
                inbound_allowed: false,
                timeout: Duration::from_secs(20),
            }))
            .chain(iter::once(peers::ConfigRequestResponse {
                name: format!("/{}/kad", chain.protocol_id),
                inbound_config: peers::ConfigRequestResponseIn::Payload { max_size: 1024 },
                max_response_size: 1024 * 1024,
                // TODO: `false` here means we don't insert ourselves in the DHT, which is the polite thing to do for as long as Kad isn't implemented
                inbound_allowed: false,
                timeout: Duration::from_secs(20),
            }))
            .chain(iter::once(peers::ConfigRequestResponse {
                name: format!("/{}/sync/warp", chain.protocol_id),
                inbound_config: peers::ConfigRequestResponseIn::Payload { max_size: 32 },
                max_response_size: 128 * 1024 * 1024, // TODO: this is way too large at the moment ; see https://github.com/paritytech/substrate/pull/8578
                // We don't support inbound warp sync requests (yet).
                inbound_allowed: false,
                timeout: Duration::from_secs(20),
            }))
        }))
        .collect();

        let mut randomness = rand_chacha::ChaCha20Rng::from_seed(config.randomness_seed);
        let inner_randomness_seed = randomness.sample(rand::distributions::Standard);

        let chain_grandpa_config = config
            .chains
            .iter()
            .map(|chain| chain.grandpa_protocol_config)
            .collect();

        let peers = {
            let k0 = randomness.next_u64();
            let k1 = randomness.next_u64();
            let k2 = randomness.next_u64();
            let k3 = randomness.next_u64();
            hashbrown::HashMap::with_capacity_and_hasher(
                config.peers_capacity,
                ahash::RandomState::with_seeds(k0, k1, k2, k3),
            )
        };

        let mut potential_addresses = {
            let k0 = randomness.next_u64();
            let k1 = randomness.next_u64();
            let k2 = randomness.next_u64();
            let k3 = randomness.next_u64();
            hashbrown::HashMap::with_capacity_and_hasher(
                0, // TODO:
                ahash::RandomState::with_seeds(k0, k1, k2, k3),
            )
        };

        let mut initial_desired_substreams = BTreeSet::new();

        for (node_index, (peer_id, multiaddr)) in config.known_nodes.into_iter().enumerate() {
            // Register membership of this peer on this chain.
            for (chain_index, chain) in config.chains.iter().enumerate() {
                if !chain.bootstrap_nodes.iter().any(|n| *n == node_index) {
                    continue;
                }

                for notifications_protocol in (0..NOTIFICATIONS_PROTOCOLS_PER_CHAIN)
                    .map(|n| n + NOTIFICATIONS_PROTOCOLS_PER_CHAIN * chain_index)
                {
                    initial_desired_substreams.insert((peer_id.clone(), notifications_protocol));
                }
            }

            // TODO: filter duplicates?
            potential_addresses
                .entry(peer_id)
                .or_insert(Vec::new())
                .push(multiaddr);
        }

        ChainNetwork {
            inner: peers::Peers::new(peers::Config {
                connections_capacity: config.connections_capacity,
                peers_capacity: config.peers_capacity,
                request_response_protocols,
                noise_key: config.noise_key,
                randomness_seed: inner_randomness_seed,
                pending_api_events_buffer_size: config.pending_api_events_buffer_size,
                notification_protocols,
                ping_protocol: "/ipfs/ping/1.0.0".into(),
                initial_desired_peers: Default::default(), // Empty
                initial_desired_substreams,
            }),
            guarded: Mutex::new(Guarded {
                to_process_pre_event: None,
            }),
            pending: Mutex::new(PendingConnections {
                num_pending_per_peer: peers,
                pending_ids: slab::Slab::with_capacity(config.peers_capacity),
                potential_addresses: potential_addresses,
            }),
            chain_grandpa_config: Mutex::new(chain_grandpa_config),
            chain_configs: config.chains,
            randomness: Mutex::new(randomness),
            next_start_connect_waker: AtomicWaker::new(),
        }
    }

    fn protocol_index(&self, chain_index: usize, protocol: usize) -> usize {
        1 + chain_index * REQUEST_RESPONSE_PROTOCOLS_PER_CHAIN + protocol
    }

    /// Returns the number of established TCP connections, both incoming and outgoing.
    // TODO: note about race
    pub async fn num_established_connections(&self) -> usize {
        // TODO: better impl
        self.peers_list().await.count()
    }

    /// Returns the number of chains. Always equal to the length of [`Config::chains`].
    pub fn num_chains(&self) -> usize {
        self.chain_configs.len()
    }

    /// Adds an incoming connection to the state machine.
    ///
    /// This connection hasn't finished handshaking and the [`PeerId`] of the remote isn't known
    /// yet.
    ///
    /// After this function has returned, you must process the connection with
    /// [`ChainNetwork::read_write`].
    ///
    /// The `remote_addr` is the address used to reach back the remote. In the case of TCP, it
    /// contains the TCP dialing port of the remote. The remote can ask, through the `identify`
    /// libp2p protocol, its own address, in which case we send it.
    pub async fn add_incoming_connection(&self, remote_addr: multiaddr::Multiaddr) -> ConnectionId {
        self.inner.add_incoming_connection(remote_addr).await
    }

    /// Update the state of the local node with regards to GrandPa rounds.
    ///
    /// Calling this method does two things:
    ///
    /// - Send on all the active GrandPa substreams a "neighbor packet" indicating the state of
    ///   the local node.
    /// - Update the neighbor packet that is automatically sent to peers when a GrandPa substream
    ///   gets opened.
    ///
    /// In other words, calling this function atomically informs all the present and future peers
    /// of the state of the local node regarding the GrandPa protocol.
    ///
    /// > **Note**: The information passed as parameter isn't validated in any way by this method.
    ///
    /// # Panic
    ///
    /// Panics if `chain_index` is out of range, or if the chain has GrandPa disabled.
    ///
    pub async fn set_local_grandpa_state(&self, chain_index: usize, grandpa_state: GrandpaState) {
        let mut chain_grandpa_configs = self.chain_grandpa_config.lock().await;

        // Bytes of the neighbor packet to send out.
        let packet = protocol::GrandpaNotificationRef::Neighbor(protocol::NeighborPacket {
            round_number: grandpa_state.round_number,
            set_id: grandpa_state.set_id,
            commit_finalized_height: grandpa_state.commit_finalized_height,
        })
        .scale_encoding()
        .fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        // Now sending out.
        let _ = self
            .inner
            .broadcast_notification(
                chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 2,
                packet.clone(),
            )
            .await;

        // Update the locally-stored state, but only after the notification has been broadcasted.
        // This way, if the user cancels the future while `broadcast_notification` is executing,
        // the whole operation is cancelled.
        *chain_grandpa_configs[chain_index].as_mut().unwrap() = grandpa_state;
    }

    /// Sends a blocks request to the given peer.
    // TODO: more docs
    pub async fn blocks_request(
        &self,
        now: TNow,
        target: &peer_id::PeerId,
        chain_index: usize,
        config: protocol::BlocksRequestConfig,
    ) -> Result<Vec<protocol::BlockData>, BlocksRequestError> {
        let request_data = protocol::build_block_request(config).fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        let response = self
            .inner
            .request(
                now,
                target,
                self.protocol_index(chain_index, 0),
                request_data,
            )
            .map_err(BlocksRequestError::Request)
            .await?;

        protocol::decode_block_response(&response).map_err(BlocksRequestError::Decode)
    }

    pub async fn grandpa_warp_sync_request(
        &self,
        now: TNow,
        target: &peer_id::PeerId,
        chain_index: usize,
        begin_hash: [u8; 32],
    ) -> Result<protocol::GrandpaWarpSyncResponse, GrandpaWarpSyncRequestError> {
        let request_data = begin_hash.to_vec();

        let response = self
            .inner
            .request(
                now,
                target,
                self.protocol_index(chain_index, 3),
                request_data,
            )
            .map_err(GrandpaWarpSyncRequestError::Request)
            .await?;

        protocol::decode_grandpa_warp_sync_response(&response)
            .map_err(GrandpaWarpSyncRequestError::Decode)
    }

    /// Sends a storage request to the given peer.
    // TODO: more docs
    pub async fn storage_proof_request(
        &self,
        now: TNow,
        target: &peer_id::PeerId,
        chain_index: usize,
        config: protocol::StorageProofRequestConfig<impl Iterator<Item = impl AsRef<[u8]>>>,
    ) -> Result<Vec<Vec<u8>>, StorageProofRequestError> {
        let request_data =
            protocol::build_storage_proof_request(config).fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });

        let response = self
            .inner
            .request(
                now,
                target,
                self.protocol_index(chain_index, 1),
                request_data,
            )
            .map_err(StorageProofRequestError::Request)
            .await?;

        protocol::decode_storage_proof_response(&response).map_err(StorageProofRequestError::Decode)
    }

    /// Sends a call proof request to the given peer.
    ///
    /// This request is similar to [`ChainNetwork::storage_proof_request`]. Instead of requesting
    /// specific keys, we request the list of all the keys that are accessed for a specific
    /// runtime call.
    ///
    /// There exists no guarantee that the proof is complete (i.e. that it contains all the
    /// necessary entries), as it is impossible to know this from just the proof itself. As such,
    /// this method is just an optimization. When performing the actual call, regular storage proof
    /// requests should be performed if the key is not present in the call proof response.
    pub async fn call_proof_request(
        &self,
        now: TNow,
        target: &peer_id::PeerId,
        chain_index: usize,
        config: protocol::CallProofRequestConfig<'_, impl Iterator<Item = impl AsRef<[u8]>>>,
    ) -> Result<Vec<Vec<u8>>, CallProofRequestError> {
        let request_data =
            protocol::build_call_proof_request(config).fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });

        let response = self
            .inner
            .request(
                now,
                target,
                self.protocol_index(chain_index, 1),
                request_data,
            )
            .map_err(CallProofRequestError::Request)
            .await?;

        protocol::decode_call_proof_response(&response).map_err(CallProofRequestError::Decode)
    }

    ///
    ///
    /// Must be passed the double-SCALE-encoded transaction.
    // TODO: -> broadcast_transaction
    pub async fn announce_transaction(
        &self,
        target: &peer_id::PeerId,
        chain_index: usize,
        extrinsic: &[u8],
    ) -> Result<(), QueueNotificationError> {
        let mut val = Vec::with_capacity(1 + extrinsic.len());
        val.extend_from_slice(util::encode_scale_compact_usize(1).as_ref());
        val.extend_from_slice(extrinsic);
        self.inner
            .queue_notification(
                target,
                chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 1,
                val,
            )
            .await
    }

    /// After calling [`ChainNetwork::next_start_connect`], notifies the [`ChainNetwork`] of the
    /// success of the dialing attempt.
    ///
    /// See also [`ChainNetwork::pending_outcome_err`].
    ///
    /// After this function has returned, you must process the connection with
    /// [`ChainNetwork::read_write`].
    ///
    /// # Panic
    ///
    /// Panics if the [`PendingId`] is invalid.
    ///
    pub async fn pending_outcome_ok(&self, id: PendingId) -> ConnectionId {
        let mut lock = self.pending.lock().await;
        let lock = &mut *lock; // Prevents borrow checker issues.

        // Don't remove the value in `pending_ids` yet, so that the state remains consistent if
        // the user cancels the future returned by `add_outgoing_connection`.
        let (expected_peer_id, multiaddr) = lock.pending_ids.get(id.0).unwrap();

        let connection_id = self
            .inner
            .add_outgoing_connection(expected_peer_id, multiaddr.clone())
            .await;

        // Update `lock.peers`.
        {
            let value = lock.num_pending_per_peer.get_mut(expected_peer_id).unwrap();
            if let Some(new_value) = NonZeroUsize::new(value.get() - 1) {
                *value = new_value;
            } else {
                lock.num_pending_per_peer.remove(expected_peer_id).unwrap();
            }
        }

        // Update `lock.potential_addresses`.
        if let Some(entry) = lock.potential_addresses.get_mut(expected_peer_id) {
            if !entry.iter().any(|a| *a == *multiaddr) {
                entry.push(multiaddr.clone());
            }
        }

        lock.pending_ids.remove(id.0);

        connection_id
    }

    /// After calling [`ChainNetwork::next_start_connect`], notifies the [`ChainNetwork`] of the
    /// failure of the dialing attempt.
    ///
    /// See also [`ChainNetwork::pending_outcome_ok`].
    ///
    /// # Panic
    ///
    /// Panics if the [`PendingId`] is invalid.
    ///
    pub async fn pending_outcome_err(&self, id: PendingId) {
        let mut lock = self.pending.lock().await;
        let (expected_peer_id, _) = lock.pending_ids.remove(id.0);

        // Update `lock.peers`.
        {
            let value = lock
                .num_pending_per_peer
                .get_mut(&expected_peer_id)
                .unwrap();
            if let Some(new_value) = NonZeroUsize::new(value.get() - 1) {
                *value = new_value;
            } else {
                lock.num_pending_per_peer.remove(&expected_peer_id).unwrap();
            }
        }

        self.next_start_connect_waker.wake();
    }

    /// Returns the next event produced by the service.
    ///
    /// This function should be called at a high enough rate that [`ChainNetwork::read_write`] can
    /// continue pushing events to the internal buffer of events. Failure to call this function
    /// often enough will lead to connections being back-pressured.
    /// See also [`Config::pending_api_events_buffer_size`].
    ///
    /// It is technically possible to call this function multiple times simultaneously, in which
    /// case the events will be distributed amongst the multiple calls in an unspecified way.
    /// Keep in mind that some [`Event`]s have logic attached to the order in which they are
    /// produced, and calling this function multiple times is therefore discouraged.
    // TODO: this `now` parameter, it's a hack
    pub async fn next_event(&'_ self, now: TNow) -> Event<'_, TNow> {
        let mut guarded = self.guarded.lock().await;
        let guarded = &mut *guarded;

        loop {
            // First, process `to_process_pre_event`.
            // We don't do `to_process_pre_event.take()` in order to handle the possibility where
            // the user cancels the future during an `await` point.
            match guarded.to_process_pre_event.as_mut() {
                None => {}
                Some(ToProcessPreEvent::AcceptNotificationsIn { id, handshake_back }) => {
                    // TODO: use Result
                    self.inner
                        .in_notification_accept(*id, handshake_back.clone())
                        .await;
                    guarded.to_process_pre_event = None;
                }
                Some(ToProcessPreEvent::RefuseNotificationsIn { id }) => {
                    self.inner.in_notification_refuse(*id).await;
                    guarded.to_process_pre_event = None;
                }
                Some(ToProcessPreEvent::NotificationsOut { id, handshake }) => {
                    self.inner
                        .open_out_notification(*id, now.clone(), handshake.clone())
                        .await;
                    guarded.to_process_pre_event = None;
                }
                Some(ToProcessPreEvent::QueueNotification {
                    peer_id,
                    notifications_protocol_index,
                    notification,
                }) => {
                    let _ = self
                        .inner
                        .queue_notification(
                            peer_id,
                            *notifications_protocol_index,
                            notification.clone(),
                        )
                        .await;
                    guarded.to_process_pre_event = None;
                }
                Some(ToProcessPreEvent::SendGrandpaNeighborPacket {
                    peer_id,
                    notifications_protocol_index,
                }) => {
                    // Grandpa notification has been opened. Send neighbor packet.
                    let chain_index =
                        *notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;
                    let grandpa_config = self.chain_grandpa_config.lock().await[chain_index]
                        .as_ref()
                        .unwrap()
                        .clone();
                    let notification =
                        protocol::GrandpaNotificationRef::Neighbor(protocol::NeighborPacket {
                            round_number: grandpa_config.round_number,
                            set_id: grandpa_config.set_id,
                            commit_finalized_height: grandpa_config.commit_finalized_height,
                        })
                        .scale_encoding()
                        .fold(Vec::new(), |mut a, b| {
                            a.extend_from_slice(b.as_ref());
                            a
                        });

                    // TODO: could cause issues if two parallel threads were both waiting on self.inner.next_event(), and the next two events close and reopen the substream; this would send the notification the "wrong" obsolete substream
                    guarded.to_process_pre_event = Some(ToProcessPreEvent::QueueNotification {
                        peer_id: peer_id.clone(),
                        notifications_protocol_index: *notifications_protocol_index,
                        notification,
                    });
                }
            }

            match self.inner.next_event().await {
                peers::Event::Connected {
                    peer_id,
                    num_peer_connections,
                    ..
                } if num_peer_connections.get() == 1 => {
                    return Event::Connected(peer_id);
                }
                peers::Event::Connected { .. } => {}

                peers::Event::Disconnected {
                    num_peer_connections,
                    peer_id,
                    peer_is_desired,
                } if num_peer_connections == 0 => {
                    if peer_is_desired {
                        self.next_start_connect_waker.wake();
                    }

                    return Event::Disconnected {
                        peer_id,
                        chain_indices: Vec::new(), // TODO: ?
                    };
                }
                peers::Event::Disconnected { .. } => {}

                peers::Event::RequestIn {
                    request_id,
                    peer_id,
                    connection_user_data: observed_addr,
                    protocol_index: 0,
                    request_payload,
                    ..
                } => {
                    // TODO: check that request_payload is empty
                    return Event::IdentifyRequestIn {
                        peer_id,
                        request: IdentifyRequestIn {
                            service: self,
                            request_id,
                            observed_addr,
                        },
                    };
                }
                // Only protocol 0 (identify) can receive requests at the moment.
                peers::Event::RequestIn { .. } => unreachable!(),
                peers::Event::RequestInCancel { .. } => {}

                peers::Event::NotificationsOutAccept {
                    peer_id,
                    notifications_protocol_index,
                    remote_handshake,
                } => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;
                    if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0 {
                        let remote_handshake =
                            match protocol::decode_block_announces_handshake(&remote_handshake) {
                                Ok(hs) => hs,
                                Err(err) => {
                                    // TODO: close the substream?
                                    return Event::ProtocolError {
                                        peer_id,
                                        error: ProtocolError::BadBlockAnnouncesHandshake(err),
                                    };
                                }
                            };

                        // TODO: compare genesis hash with ours

                        return Event::ChainConnected {
                            peer_id,
                            chain_index,
                            best_hash: *remote_handshake.best_hash,
                            best_number: remote_handshake.best_number,
                            role: remote_handshake.role,
                        };
                    } else if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 1
                    {
                        // Nothing to do.
                    } else if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 2
                    {
                        // Grandpa notification has been opened. Send neighbor packet.
                        // This isn't done immediately because of futures-cancellation-related
                        // concerns.
                        // TODO: could cause issues if two parallel threads were both waiting on self.inner.next_event(), and the next two events close and reopen the substream; this would send the notification the "wrong" obsolete substream
                        debug_assert!(guarded.to_process_pre_event.is_none());
                        guarded.to_process_pre_event =
                            Some(ToProcessPreEvent::SendGrandpaNeighborPacket {
                                peer_id,
                                notifications_protocol_index,
                            });
                    } else {
                        unreachable!()
                    }

                    // TODO:
                }
                peers::Event::DesiredOutNotification {
                    id,
                    notifications_protocol_index,
                    ..
                } => {
                    let chain_config = &self.chain_configs
                        [notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN];

                    let handshake = if notifications_protocol_index
                        % NOTIFICATIONS_PROTOCOLS_PER_CHAIN
                        == 0
                    {
                        protocol::encode_block_announces_handshake(
                            protocol::BlockAnnouncesHandshakeRef {
                                best_hash: &chain_config.best_hash,
                                best_number: chain_config.best_number,
                                genesis_hash: &chain_config.genesis_hash,
                                role: chain_config.role,
                            },
                        )
                        .fold(Vec::new(), |mut a, b| {
                            a.extend_from_slice(b.as_ref());
                            a
                        })
                    } else if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 1
                    {
                        Vec::new()
                    } else if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 2
                    {
                        chain_config.role.scale_encoding().to_vec()
                    } else {
                        unreachable!()
                    };

                    // Indicating the handshake isn't done immediately because of
                    // futures-cancellation-related concerns.
                    debug_assert!(guarded.to_process_pre_event.is_none());
                    guarded.to_process_pre_event =
                        Some(ToProcessPreEvent::NotificationsOut { id, handshake });
                }
                peers::Event::NotificationsOutClose {
                    notifications_protocol_index,
                    peer_id,
                } => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                    if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0 {
                        return Event::ChainDisconnected {
                            peer_id,
                            chain_index,
                        };
                    }

                    self.next_start_connect_waker.wake();
                }
                peers::Event::NotificationsInClose {
                    peer_id,
                    notifications_protocol_index,
                } => {
                    // TODO: ?
                }
                peers::Event::NotificationsIn {
                    notifications_protocol_index,
                    peer_id,
                    notification,
                } => {
                    // Don't report events about nodes we don't have an outbound substream with.
                    // TODO: think about possible race conditions regarding missing block
                    // announcements, as the remote will think we know it's at a certain block
                    // while we ignored its announcement ; it isn't problematic as long as blocks
                    // are generated continuously, as announcements will be generated periodically
                    // as well and the state will no longer mismatch
                    // TODO: restore ^

                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;
                    if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0 {
                        if let Err(err) = protocol::decode_block_announce(&notification) {
                            return Event::ProtocolError {
                                peer_id,
                                error: ProtocolError::BadBlockAnnounce(err),
                            };
                        }

                        return Event::BlockAnnounce {
                            chain_index,
                            peer_id,
                            announce: EncodedBlockAnnounce(notification),
                        };
                    } else if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 1
                    {
                        // TODO: transaction announce
                    } else if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 2
                    {
                        let decoded_notif =
                            match protocol::decode_grandpa_notification(&notification) {
                                Ok(n) => n,
                                Err(err) => {
                                    return Event::ProtocolError {
                                        peer_id,
                                        error: ProtocolError::BadGrandpaNotification(err),
                                    };
                                }
                            };

                        // Commit messages are the only type of message that is important for
                        // light clients. Anything else is presently ignored.
                        if let protocol::GrandpaNotificationRef::Commit(_) = decoded_notif {
                            return Event::GrandpaCommitMessage {
                                chain_index,
                                message: EncodedGrandpaCommitMessage(notification),
                            };
                        }
                    } else {
                        unreachable!()
                    }
                }
                peers::Event::DesiredInNotification {
                    peer_id,
                    handshake,
                    id: desired_in_notification_id,
                    notifications_protocol_index,
                } => {
                    // Remote requests to open a notifications substream.

                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                    if (notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN) == 0 {
                        if let Err(err) = protocol::decode_block_announces_handshake(&handshake) {
                            // Refusing the substream isn't done immediately because of
                            // futures-cancellation-related concerns.
                            debug_assert!(guarded.to_process_pre_event.is_none());
                            guarded.to_process_pre_event =
                                Some(ToProcessPreEvent::RefuseNotificationsIn {
                                    id: desired_in_notification_id,
                                });

                            return Event::ProtocolError {
                                peer_id,
                                error: ProtocolError::BadBlockAnnouncesHandshake(err),
                            };
                        }

                        let chain_config = &self.chain_configs[chain_index];
                        let handshake = protocol::encode_block_announces_handshake(
                            protocol::BlockAnnouncesHandshakeRef {
                                best_hash: &chain_config.best_hash,
                                best_number: chain_config.best_number,
                                genesis_hash: &chain_config.genesis_hash,
                                role: chain_config.role,
                            },
                        )
                        .fold(Vec::new(), |mut a, b| {
                            a.extend_from_slice(b.as_ref());
                            a
                        });

                        // Accepting the substream isn't done immediately because of
                        // futures-cancellation-related concerns.
                        debug_assert!(guarded.to_process_pre_event.is_none());
                        guarded.to_process_pre_event =
                            Some(ToProcessPreEvent::AcceptNotificationsIn {
                                id: desired_in_notification_id,
                                handshake_back: handshake,
                            });
                    } else if (notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN)
                        == 1
                    {
                        // Accepting the substream isn't done immediately because of
                        // futures-cancellation-related concerns.
                        debug_assert!(guarded.to_process_pre_event.is_none());
                        guarded.to_process_pre_event =
                            Some(ToProcessPreEvent::AcceptNotificationsIn {
                                id: desired_in_notification_id,
                                handshake_back: Vec::new(),
                            });
                    } else if (notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN)
                        == 2
                    {
                        // Grandpa substream.
                        let handshake = self.chain_configs[chain_index]
                            .role
                            .scale_encoding()
                            .to_vec();

                        // Accepting the substream isn't done immediately because of
                        // futures-cancellation-related concerns.
                        debug_assert!(guarded.to_process_pre_event.is_none());
                        guarded.to_process_pre_event =
                            Some(ToProcessPreEvent::AcceptNotificationsIn {
                                id: desired_in_notification_id,
                                handshake_back: handshake,
                            });
                    } else {
                        unreachable!()
                    }
                }
                peers::Event::DesiredInNotificationCancel { .. } => {}
            }
        }
    }

    /// Performs a round of Kademlia discovery.
    ///
    /// This future yields once a list of nodes on the network has been discovered, or a problem
    /// happened.
    pub async fn kademlia_discovery_round(
        &'_ self,
        now: TNow,
        chain_index: usize,
    ) -> Result<DiscoveryInsert<'_, TNow>, DiscoveryError> {
        let random_peer_id = {
            let mut randomness = self.randomness.lock().await;
            let pub_key = randomness.sample(rand::distributions::Standard);
            peer_id::PeerId::from_public_key(&peer_id::PublicKey::Ed25519(pub_key))
        };

        // TODO: implement Kademlia properly

        // Select a random peer to query.

        let request_data = kademlia::build_find_node_request(random_peer_id.as_bytes());
        if let Some(target) = self.inner.peers_list().await.next() {
            // TODO: better peer selection
            let response = self
                .inner
                .request(
                    now,
                    &target,
                    self.protocol_index(chain_index, 2),
                    request_data,
                )
                .await
                .map_err(DiscoveryError::RequestFailed)?;
            let decoded = kademlia::decode_find_node_response(&response)
                .map_err(DiscoveryError::DecodeError)?;
            Ok(DiscoveryInsert {
                service: self,
                outcome: decoded,
                chain_index,
            })
        } else {
            Err(DiscoveryError::NoPeer)
        }
    }

    /// Allocates a [`PendingId`] and returns a [`StartConnect`] indicating a multiaddress that
    /// the API user must try to dial.
    ///
    /// Later, the API user must use [`ChainNetwork::pending_outcome_ok`] or
    /// [`ChainNetwork::pending_outcome_err`] to report how the connection attempt went.
    ///
    /// If no outgoing connection is desired, the method waits until there is one.
    // TODO: document the timeout system
    // TODO: give more control, with number of slots and node choice
    pub async fn next_start_connect<'a>(&self) -> StartConnect {
        loop {
            let mut pending_lock = self.pending.lock().await;
            let pending = &mut *pending_lock; // Prevents borrow checker issues.

            // Ask the underlying state machine which nodes are desired but don't have any
            // associated connection attempt yet.
            // Since the underlying state machine is only made aware of connections in
            // `pending_outcome_ok`, we must filter out nodes that already have an associated
            // `PendingId`.
            let unfulfilled_desired_peers = self.inner.unfulfilled_desired_peers().await;

            for peer_id in unfulfilled_desired_peers {
                // TODO: allow more than one simultaneous dial per peer, and distribute the dials so that we don't just return the same peer multiple times in a row while there are other peers waiting
                let entry = match pending.num_pending_per_peer.entry(peer_id) {
                    hashbrown::hash_map::Entry::Occupied(_) => continue,
                    hashbrown::hash_map::Entry::Vacant(entry) => entry,
                };

                let multiaddr: multiaddr::Multiaddr = if let Some(potential_addresses) =
                    pending.potential_addresses.get_mut(entry.key())
                {
                    if potential_addresses.is_empty() {
                        continue;
                    }

                    let addr = potential_addresses.remove(0);
                    if potential_addresses.is_empty() {
                        pending.potential_addresses.remove(entry.key());
                    }
                    addr
                } else {
                    continue;
                };

                let pending_id = PendingId(
                    pending
                        .pending_ids
                        .insert((entry.key().clone(), multiaddr.clone())),
                );

                let start_connect = StartConnect {
                    expected_peer_id: entry.key().clone(),
                    id: pending_id,
                    multiaddr,
                };

                entry.insert(NonZeroUsize::new(1).unwrap());

                return start_connect;
            }

            // No valid desired peer has been found.
            // We register a waker, unlock the mutex, and wait until the waker is invoked.
            // The rest of the code of this state machine makes sure to invoke the waker when
            // there is a potential new desired peer or known address.
            // TODO: if `next_start_connect` is called multiple times simultaneously, all but the first will deadlock
            let mut pending_lock: Option<MutexGuard<_>> = Some(pending_lock);
            future::poll_fn(move |cx| {
                if let Some(_lock) = pending_lock.take() {
                    self.next_start_connect_waker.register(cx.waker());
                    drop(_lock);
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
        }
    }

    ///
    /// # Panic
    ///
    /// Panics if `connection_id` isn't a valid connection.
    ///
    pub async fn read_write<'a>(
        &self,
        connection_id: ConnectionId,
        now: TNow,
        incoming_buffer: Option<&[u8]>,
        outgoing_buffer: (&'a mut [u8], &'a mut [u8]),
    ) -> Result<ReadWrite<TNow>, peers::ConnectionError> {
        self.inner
            .read_write(connection_id, now, incoming_buffer, outgoing_buffer)
            .await
    }

    /// Returns an iterator to the list of [`PeerId`]s that we have an established connection
    /// with.
    pub async fn peers_list(&self) -> impl Iterator<Item = PeerId> {
        self.inner.peers_list().await
    }
}

/// User must start connecting to the given multiaddress.
///
/// Either [`ChainNetwork::pending_outcome_ok`] or [`ChainNetwork::pending_outcome_err`] must
/// later be called in order to inform of the outcome of the connection.
#[derive(Debug)]
#[must_use]
pub struct StartConnect {
    /// Identifier of this connection request. Must be passed back later.
    pub id: PendingId,
    /// Address to attempt to connect to.
    pub multiaddr: multiaddr::Multiaddr,
    /// [`PeerId`] that is expected to be reached with this connection attempt.
    pub expected_peer_id: PeerId,
}

/// Event generated by [`ChainNetwork::next_event`].
#[derive(Debug)]
pub enum Event<'a, TNow> {
    /// Established a transport-level connection (e.g. a TCP socket) with the given peer.
    Connected(peer_id::PeerId),

    /// A transport-level connection (e.g. a TCP socket) has been closed.
    ///
    /// This event is called unconditionally when a connection with the given peer has been
    /// closed. If `chain_indices` isn't empty, this event is also equivalent to one or more
    /// [`Event::ChainDisconnected`] events.
    Disconnected {
        peer_id: peer_id::PeerId,
        chain_indices: Vec<usize>,
    },

    ChainConnected {
        chain_index: usize,
        peer_id: peer_id::PeerId,
        /// Role the node reports playing on the network.
        role: protocol::Role,
        /// Height of the best block according to this node.
        best_number: u64,
        /// Hash of the best block according to this node.
        best_hash: [u8; 32],
    },
    ChainDisconnected {
        peer_id: peer_id::PeerId,
        chain_index: usize,
    },

    /// Received a new block announce from a peer.
    ///
    /// Can only happen after a [`Event::ChainConnected`] with the given `PeerId` and chain index
    /// combination has happened.
    BlockAnnounce {
        /// Identity of the sender of the block announce.
        peer_id: peer_id::PeerId,
        /// Index of the chain the block relates to.
        chain_index: usize,
        announce: EncodedBlockAnnounce,
    },

    /// Received a GrandPa commit message from the network.
    GrandpaCommitMessage {
        /// Index of the chain the commit message relates to.
        chain_index: usize,
        message: EncodedGrandpaCommitMessage,
    },

    /// Error in the protocol in a connection, such as failure to decode a message.
    // TODO: explain consequences
    ProtocolError {
        /// Peer that has caused the protocol error.
        peer_id: peer_id::PeerId,
        /// Error that happened.
        error: ProtocolError,
    },

    /// A remote has sent a request for identification information.
    ///
    /// You are strongly encouraged to call [`IdentifyRequestIn::respond`].
    IdentifyRequestIn {
        /// Remote that has sent the request.
        peer_id: PeerId,
        /// Object allowing sending back the answer.
        request: IdentifyRequestIn<'a, TNow>,
    },
    /*Transactions {
        peer_id: peer_id::PeerId,
        transactions: EncodedTransactions,
    }*/
}

/// Undecoded but valid block announce handshake.
pub struct EncodedBlockAnnounceHandshake(Vec<u8>);

impl EncodedBlockAnnounceHandshake {
    /// Returns the decoded version of the handshake.
    pub fn decode(&self) -> protocol::BlockAnnouncesHandshakeRef {
        protocol::decode_block_announces_handshake(&self.0).unwrap()
    }
}

impl fmt::Debug for EncodedBlockAnnounceHandshake {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.decode(), f)
    }
}

/// Undecoded but valid block announce.
#[derive(Clone)]
pub struct EncodedBlockAnnounce(Vec<u8>);

impl EncodedBlockAnnounce {
    /// Returns the decoded version of the announcement.
    pub fn decode(&self) -> protocol::BlockAnnounceRef {
        protocol::decode_block_announce(&self.0).unwrap()
    }
}

impl fmt::Debug for EncodedBlockAnnounce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.decode(), f)
    }
}

/// Undecoded but valid GrandPa commit message.
#[derive(Clone)]
pub struct EncodedGrandpaCommitMessage(Vec<u8>);

impl EncodedGrandpaCommitMessage {
    /// Returns the encoded bytes of the commit message.
    pub fn as_encoded(&self) -> &[u8] {
        // Skip the first byte because `self.0` is a `GrandpaNotificationRef`.
        &self.0[1..]
    }

    /// Returns the decoded version of the commit message.
    pub fn decode(&self) -> protocol::CommitMessageRef {
        match protocol::decode_grandpa_notification(&self.0) {
            Ok(protocol::GrandpaNotificationRef::Commit(msg)) => msg,
            _ => unreachable!(),
        }
    }
}

impl fmt::Debug for EncodedGrandpaCommitMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.decode(), f)
    }
}

/// Successfull outcome to [`ChainNetwork::kademlia_discovery_round`].
#[must_use]
pub struct DiscoveryInsert<'a, TNow> {
    service: &'a ChainNetwork<TNow>,
    outcome: Vec<(peer_id::PeerId, Vec<multiaddr::Multiaddr>)>,

    /// Index within [`Config::chains`] corresponding to the chain the nodes belong to.
    chain_index: usize,
}

impl<'a, TNow> DiscoveryInsert<'a, TNow>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Returns the list of [`peer_id::PeerId`]s that will be inserted.
    pub fn peer_ids(&self) -> impl Iterator<Item = &peer_id::PeerId> {
        self.outcome.iter().map(|(peer_id, _)| peer_id)
    }

    /// Insert the results in the [`ChainNetwork`].
    pub async fn insert(self) {
        let mut lock = self.service.pending.lock().await;
        let lock = &mut *lock; // Avoids borrow checker issues.

        let chain_index = self.chain_index;

        for (peer_id, addrs) in self.outcome {
            // TODO: hack
            // TODO: futures cancellation issue
            for protocol in (0..NOTIFICATIONS_PROTOCOLS_PER_CHAIN)
                .map(|n| n + chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN)
            {
                self.service
                    .inner
                    .set_peer_notifications_out_desired(&peer_id, protocol, true)
                    .await;
            }

            let existing_addrs = lock.potential_addresses.entry(peer_id).or_default();
            for addr in addrs {
                if !existing_addrs.iter().any(|a| *a == addr) {
                    existing_addrs.push(addr);
                }
            }
        }

        self.service.next_start_connect_waker.wake();
    }
}

/// See [`Event::IdentifyRequestIn`].
#[must_use]
pub struct IdentifyRequestIn<'a, TNow> {
    service: &'a ChainNetwork<TNow>,
    request_id: peers::RequestId,
    observed_addr: multiaddr::Multiaddr,
}

impl<'a, TNow> IdentifyRequestIn<'a, TNow>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Queue the response to send back. The future provided by [`ChainNetwork::read_write`] will
    /// automatically be woken up.
    ///
    /// Has no effect if the connection that sends the request no longer exists.
    pub async fn respond(self, agent_version: &str) {
        let response = {
            protocol::build_identify_response(protocol::IdentifyResponse {
                protocol_version: "/substrate/1.0", // TODO: same value as in Substrate
                agent_version,
                ed25519_public_key: self.service.inner.noise_key().libp2p_public_ed25519_key(),
                listen_addrs: iter::empty(), // TODO:
                observed_addr: &self.observed_addr,
                protocols: self
                    .service
                    .inner
                    .request_response_protocols()
                    .filter(|p| p.inbound_allowed)
                    .map(|p| &p.name[..])
                    .chain(
                        self.service
                            .inner
                            .notification_protocols()
                            .map(|p| &p.protocol_name[..]),
                    ),
            })
            .fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            })
        };

        let _ = self
            .service
            .inner
            .respond(self.request_id, Ok(response))
            .await;
    }
}

impl<'a, TNow> fmt::Debug for IdentifyRequestIn<'a, TNow> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("IdentifyRequestIn").finish()
    }
}

/// Error during [`ChainNetwork::kademlia_discovery_round`].
#[derive(Debug, derive_more::Display)]
pub enum DiscoveryError {
    NoPeer,
    RequestFailed(peers::RequestError),
    DecodeError(kademlia::DecodeFindNodeResponseError),
}

/// Error returned by [`ChainNetwork::blocks_request`].
#[derive(Debug, derive_more::Display)]
pub enum BlocksRequestError {
    Request(peers::RequestError),
    Decode(protocol::DecodeBlockResponseError),
}

/// Error returned by [`ChainNetwork::storage_proof_request`].
#[derive(Debug, derive_more::Display)]
pub enum StorageProofRequestError {
    Request(peers::RequestError),
    Decode(protocol::DecodeStorageProofResponseError),
}

/// Error returned by [`ChainNetwork::call_proof_request`].
#[derive(Debug, derive_more::Display)]
pub enum CallProofRequestError {
    Request(peers::RequestError),
    Decode(protocol::DecodeCallProofResponseError),
}

/// Error returned by [`ChainNetwork::grandpa_warp_sync_request`].
#[derive(Debug, derive_more::Display)]
pub enum GrandpaWarpSyncRequestError {
    Request(peers::RequestError),
    Decode(protocol::DecodeGrandpaWarpSyncResponseError),
}

/// See [`Event::ProtocolError`].
#[derive(Debug, derive_more::Display)]
pub enum ProtocolError {
    /// Error while decoding the handshake of the block announces substream.
    BadBlockAnnouncesHandshake(protocol::BlockAnnouncesHandshakeDecodeError),
    /// Error while decoding a received block announce.
    BadBlockAnnounce(protocol::DecodeBlockAnnounceError),
    /// Error while decoding a received Grandpa notification.
    BadGrandpaNotification(protocol::DecodeGrandpaNotificationError),
}
