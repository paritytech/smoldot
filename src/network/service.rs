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

use crate::header;
use crate::libp2p::{
    connection, multiaddr, peer_id,
    peers::{self, QueueNotificationError},
    PeerId,
};
use crate::network::{kademlia, protocol};
use crate::util::{self, SipHasherBuild};

use alloc::{
    collections::VecDeque,
    format,
    string::{String, ToString as _},
    vec::Vec,
};
use core::{
    fmt,
    hash::Hash,
    iter,
    num::NonZeroUsize,
    ops::{Add, Sub},
    time::Duration,
};
use rand::{Rng as _, SeedableRng as _};

pub use crate::libp2p::{
    collection::ReadWrite,
    peers::{
        ConnectionId, ConnectionToCoordinator, CoordinatorToConnection, InRequestId, InboundError,
        MultiStreamConnectionTask, MultiStreamHandshakeKind, OutRequestId,
        SingleStreamConnectionTask, SingleStreamHandshakeKind,
    },
};

mod addresses;

/// Configuration for a [`ChainNetwork`].
pub struct Config<TNow> {
    /// Time at the moment of the initialization of the service.
    pub now: TNow,

    /// Capacity to initially reserve to the list of connections.
    pub connections_capacity: usize,

    /// Capacity to initially reserve to the list of peers.
    pub peers_capacity: usize,

    /// Seed for the randomness within the networking state machine.
    ///
    /// While this seed influences the general behavior of the networking state machine, it
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

    /// Key used for the encryption layer.
    /// This is a Noise static key, according to the Noise specification.
    /// Signed using the actual libp2p key.
    pub noise_key: connection::NoiseKey,

    /// Amount of time after which a connection handshake is considered to have taken too long
    /// and must be aborted.
    pub handshake_timeout: Duration,

    /// Maximum number of addresses kept in memory per network identity.
    ///
    /// > **Note**: As the number of network identities kept in memory is capped, having a
    /// >           maximum number of addresses per peer ensures that the total number of
    /// >           addresses is capped as well.
    pub max_addresses_per_peer: NonZeroUsize,
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

    /// Number of bytes of the block number in the networking protocol.
    pub block_number_bytes: usize,

    /// If `Some`, the chain uses the GrandPa networking protocol.
    pub grandpa_protocol_config: Option<GrandpaState>,

    /// `true` if incoming block requests are allowed.
    pub allow_inbound_block_requests: bool,

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
    pub commit_finalized_height: u64,
}

/// Identifier of a pending connection requested by the network through a [`StartConnect`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingId(usize);

/// Identifier for a Kademlia iterative query.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KademliaOperationId(u64);

/// Data structure containing the list of all connections, pending or not, and their latest known
/// state. See also [the module-level documentation](..).
pub struct ChainNetwork<TNow> {
    /// Underlying data structure.
    inner: peers::Peers<multiaddr::Multiaddr, TNow>,

    /// See [`Config::handshake_timeout`].
    handshake_timeout: Duration,

    /// See [`Config::max_addresses_per_peer`].
    max_addresses_per_peer: NonZeroUsize,

    /// Contains an entry for each peer present in at least one k-bucket of a chain.
    kbuckets_peers: hashbrown::HashMap<PeerId, KBucketsPeer, SipHasherBuild>,

    /// Tuples of `(peer_id, chain_index)` that have been reported as open to the API user.
    ///
    /// This is a subset of the block announce notification protocol substreams that are open.
    /// Some substreams might have been opened and have been left out of this map if their
    /// handshake was invalid, or had a different genesis hash, or similar problem.
    open_chains: hashbrown::HashSet<(PeerId, usize), SipHasherBuild>,

    /// For each peer, the number of pending attempts.
    num_pending_per_peer: hashbrown::HashMap<PeerId, NonZeroUsize, SipHasherBuild>,

    /// Keys of this slab are [`PendingId`]s. Values are the parameters associated to that
    /// [`PendingId`].
    /// The entries here correspond to the entries in
    /// [`ChainNetwork::num_pending_per_peer`].
    pending_ids: slab::Slab<(PeerId, multiaddr::Multiaddr, TNow)>,

    /// Identifier to assign to the next Kademlia operation that is started.
    next_kademlia_operation_id: KademliaOperationId,

    /// Errors during a Kademlia operation that is yet to be reported to the user.
    pending_kademlia_errors: VecDeque<(KademliaOperationId, DiscoveryError)>,

    /// For each item in [`Config::chains`], the corresponding chain state.
    ///
    /// The `Vec` always has the same length as [`Config::chains`].
    chains: Vec<Chain<TNow>>,

    /// Generator for randomness.
    randomness: rand_chacha::ChaCha20Rng,

    in_requests_types: hashbrown::HashMap<InRequestId, InRequestTy, fnv::FnvBuildHasher>,

    // TODO: could be a user data in the request
    out_requests_types:
        hashbrown::HashMap<OutRequestId, (OutRequestTy, usize), fnv::FnvBuildHasher>,
}

struct Chain<TNow> {
    /// See [`ChainConfig`].
    chain_config: ChainConfig,

    // TODO: merge in_peers and out_peers into one hashmap<_, SlotTy>
    /// List of peers with an inbound slot attributed to them. Only includes peers the local node
    /// is connected to and who have opened a block announces substream with the local node.
    in_peers: hashbrown::HashSet<PeerId, SipHasherBuild>,

    /// List of peers with an outbound slot attributed to them. Can include peers not connected to
    /// the local node yet. The peers in this list are always marked as desired in the underlying
    /// state machine.
    out_peers: hashbrown::HashSet<PeerId, SipHasherBuild>,

    /// Kademlia k-buckets of this chain.
    ///
    /// Used in order to hold the list of peers that are known to be part of this chain.
    ///
    /// A peer is marked as "connected" in the k-buckets when a block announces substream is open
    /// and that the remote's handshake is valid (i.e. can be parsed and containing a correct
    /// genesis hash), and disconnected when it is closed or that the remote's handshake isn't
    /// satisfactory.
    kbuckets: kademlia::kbuckets::KBuckets<PeerId, (), TNow, 20>,
}

struct KBucketsPeer {
    /// Number of k-buckets containing this peer. Used to know when to remove this entry.
    num_references: NonZeroUsize,

    /// List of addresses known for this peer, and whether we currently have an outgoing connection
    /// to each of them. In this context, "connected" means "outgoing connection whose handshake is
    /// finished and is not shutting down".
    ///
    /// It is not possible to have multiple outgoing connections for a single address.
    /// Incoming connections are not taken into account at all.
    ///
    /// An address is marked as pending when there is a "pending connection" (see
    /// [`ChainNetwork::pending_ids`]) to it, or if there is an outgoing connection to it that is
    /// still handshaking.
    ///
    /// An address is marked as disconnected as soon as the shutting down is starting.
    ///
    /// Must never be empty.
    addresses: addresses::Addresses,
}

enum InRequestTy {
    Identify { observed_addr: multiaddr::Multiaddr },
    Blocks,
}

enum OutRequestTy {
    Blocks {
        checked: Option<protocol::BlocksRequestConfig>,
    },
    GrandpaWarpSync,
    State,
    StorageProof,
    CallProof,
    KademliaFindNode,
    KademliaDiscoveryFindNode(KademliaOperationId),
}

// Update this when a new request response protocol is added.
const REQUEST_RESPONSE_PROTOCOLS_PER_CHAIN: usize = 5;
// Update this when a new notifications protocol is added.
const NOTIFICATIONS_PROTOCOLS_PER_CHAIN: usize = 3;

impl<TNow> ChainNetwork<TNow>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Initializes a new [`ChainNetwork`].
    pub fn new(config: Config<TNow>) -> Self {
        // The order of protocols here is important, as it defines the values of `protocol_index`
        // to pass to libp2p or that libp2p produces.
        let notification_protocols = config
            .chains
            .iter()
            .flat_map(|chain| {
                iter::once(peers::NotificationProtocolConfig {
                    protocol_name: format!("/{}/block-announces/1", chain.protocol_id),
                    max_handshake_size: 1024 * 1024, // TODO: arbitrary
                    max_notification_size: 1024 * 1024,
                })
                .chain(iter::once(peers::NotificationProtocolConfig {
                    protocol_name: format!("/{}/transactions/1", chain.protocol_id),
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
        })
        .chain(config.chains.iter().flat_map(|chain| {
            // TODO: limits are arbitrary
            iter::once(peers::ConfigRequestResponse {
                name: format!("/{}/sync/2", chain.protocol_id),
                inbound_config: peers::ConfigRequestResponseIn::Payload { max_size: 1024 },
                max_response_size: 16 * 1024 * 1024,
                inbound_allowed: chain.allow_inbound_block_requests,
            })
            .chain(iter::once(peers::ConfigRequestResponse {
                name: format!("/{}/light/2", chain.protocol_id),
                inbound_config: peers::ConfigRequestResponseIn::Payload {
                    max_size: 1024 * 512,
                },
                max_response_size: 10 * 1024 * 1024,
                // TODO: make this configurable
                inbound_allowed: false,
            }))
            .chain(iter::once(peers::ConfigRequestResponse {
                name: format!("/{}/kad", chain.protocol_id),
                inbound_config: peers::ConfigRequestResponseIn::Payload { max_size: 1024 },
                max_response_size: 1024 * 1024,
                // TODO: `false` here means we don't insert ourselves in the DHT, which is the polite thing to do for as long as Kad isn't implemented
                inbound_allowed: false,
            }))
            .chain(iter::once(peers::ConfigRequestResponse {
                name: format!("/{}/sync/warp", chain.protocol_id),
                inbound_config: peers::ConfigRequestResponseIn::Payload { max_size: 32 },
                max_response_size: 16 * 1024 * 1024,
                // We don't support inbound warp sync requests (yet).
                inbound_allowed: false,
            }))
            .chain(iter::once(peers::ConfigRequestResponse {
                name: format!("/{}/state/2", chain.protocol_id),
                inbound_config: peers::ConfigRequestResponseIn::Payload { max_size: 1024 },
                max_response_size: 16 * 1024 * 1024,
                // We don't support inbound state requests (yet).
                inbound_allowed: false,
            }))
        }))
        .collect();

        let mut randomness = rand_chacha::ChaCha20Rng::from_seed(config.randomness_seed);

        let local_peer_id = PeerId::from_public_key(&peer_id::PublicKey::Ed25519(
            *config.noise_key.libp2p_public_ed25519_key(),
        ));

        let chains = config
            .chains
            .into_iter()
            .map(|chain| {
                Chain {
                    in_peers: hashbrown::HashSet::with_capacity_and_hasher(
                        usize::try_from(chain.in_slots).unwrap_or(0),
                        SipHasherBuild::new(randomness.gen()),
                    ),
                    out_peers: hashbrown::HashSet::with_capacity_and_hasher(
                        usize::try_from(chain.out_slots).unwrap_or(0),
                        SipHasherBuild::new(randomness.gen()),
                    ),
                    chain_config: chain,
                    kbuckets: kademlia::kbuckets::KBuckets::new(
                        local_peer_id.clone(),
                        Duration::from_secs(20), // TODO: hardcoded
                    ),
                }
            })
            .collect::<Vec<_>>();

        // Maximum number that each remote is allowed to open.
        // Note that this maximum doesn't have to be precise. There only needs to be *a* limit
        // that is not exaggerately large, and this limit shouldn't be too low as to cause
        // legitimate substreams to be refused.
        // According to the protocol, a remote can only open one substream of each protocol at
        // a time. However, we multiply this value by 2 in order to be generous. We also add 1
        // to account for the ping protocol.
        let max_inbound_substreams = chains.len()
            * (1 + REQUEST_RESPONSE_PROTOCOLS_PER_CHAIN + NOTIFICATIONS_PROTOCOLS_PER_CHAIN)
            * 2;

        ChainNetwork {
            inner: peers::Peers::new(peers::Config {
                connections_capacity: config.connections_capacity,
                peers_capacity: config.peers_capacity,
                max_inbound_substreams,
                request_response_protocols,
                noise_key: config.noise_key,
                randomness_seed: randomness.sample(rand::distributions::Standard),
                notification_protocols,
                ping_protocol: "/ipfs/ping/1.0.0".into(),
                handshake_timeout: config.handshake_timeout,
            }),
            open_chains: hashbrown::HashSet::with_capacity_and_hasher(
                config.peers_capacity * chains.len(),
                SipHasherBuild::new(randomness.gen()),
            ),
            kbuckets_peers: hashbrown::HashMap::with_capacity_and_hasher(
                config.peers_capacity,
                SipHasherBuild::new(randomness.gen()),
            ),
            num_pending_per_peer: hashbrown::HashMap::with_capacity_and_hasher(
                config.peers_capacity,
                SipHasherBuild::new(randomness.gen()),
            ),
            pending_ids: slab::Slab::with_capacity(config.peers_capacity),
            next_kademlia_operation_id: KademliaOperationId(0),
            pending_kademlia_errors: VecDeque::with_capacity(4),
            chains,
            handshake_timeout: config.handshake_timeout,
            max_addresses_per_peer: config.max_addresses_per_peer,
            out_requests_types: hashbrown::HashMap::with_capacity_and_hasher(
                config.peers_capacity,
                Default::default(),
            ),
            in_requests_types: hashbrown::HashMap::with_capacity_and_hasher(
                config.peers_capacity,
                Default::default(),
            ),
            randomness,
        }
    }

    fn protocol_index(&self, chain_index: usize, protocol: usize) -> usize {
        1 + chain_index * REQUEST_RESPONSE_PROTOCOLS_PER_CHAIN + protocol
    }

    /// Returns the number of established TCP connections, both incoming and outgoing.
    pub fn num_established_connections(&self) -> usize {
        // TODO: better impl
        self.peers_list().count()
    }

    /// Returns the number of peers we have a substream with.
    pub fn num_peers(&self, chain_index: usize) -> usize {
        self.inner
            .num_outgoing_substreams(self.protocol_index(chain_index, 0))
    }

    /// Returns the number of chains. Always equal to the length of [`Config::chains`].
    pub fn num_chains(&self) -> usize {
        self.chains.len()
    }

    /// Returns the value passed as [`ChainConfig::block_number_bytes`] for the given chain.
    ///
    /// # Panic
    ///
    /// Panics if `chain_index` is out of range.
    ///
    pub fn block_number_bytes(&self, chain_index: usize) -> usize {
        self.chains[chain_index].chain_config.block_number_bytes
    }

    /// Returns the Noise key originally passed as [`Config::noise_key`].
    pub fn noise_key(&self) -> &connection::NoiseKey {
        self.inner.noise_key()
    }

    /// Adds a single-stream incoming connection to the state machine.
    ///
    /// This connection hasn't finished handshaking and the [`PeerId`] of the remote isn't known
    /// yet.
    ///
    /// Must be passed the moment (as a `TNow`) when the connection as been established, in order
    /// to determine when the handshake timeout expires.
    ///
    /// The `remote_addr` is the address used to reach back the remote. In the case of TCP, it
    /// contains the TCP dialing port of the remote. The remote can ask, through the `identify`
    /// libp2p protocol, its own address, in which case we send it.
    pub fn add_single_stream_incoming_connection(
        &mut self,
        when_connected: TNow,
        handshake_kind: SingleStreamHandshakeKind,
        remote_addr: multiaddr::Multiaddr,
    ) -> (ConnectionId, SingleStreamConnectionTask<TNow>) {
        self.inner.add_single_stream_incoming_connection(
            when_connected,
            handshake_kind,
            remote_addr,
        )
    }

    pub fn pull_message_to_connection(
        &mut self,
    ) -> Option<(ConnectionId, CoordinatorToConnection<TNow>)> {
        self.inner.pull_message_to_connection()
    }

    /// Injects into the state machine a message generated by
    /// [`SingleStreamConnectionTask::pull_message_to_coordinator`] or
    /// [`MultiStreamConnectionTask::pull_message_to_coordinator`].
    pub fn inject_connection_message(
        &mut self,
        connection_id: ConnectionId,
        message: ConnectionToCoordinator,
    ) {
        self.inner.inject_connection_message(connection_id, message)
    }

    /// Modifies the best block of the local node. See [`ChainConfig::best_hash`] and
    /// [`ChainConfig::best_number`].
    ///
    /// # Panic
    ///
    /// Panics if `chain_index` is out of range.
    ///
    pub fn set_local_best_block(
        &mut self,
        chain_index: usize,
        best_hash: [u8; 32],
        best_number: u64,
    ) {
        let mut config = &mut self.chains[chain_index].chain_config;
        config.best_hash = best_hash;
        config.best_number = best_number;
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
    /// This function might generate a message destined to connections. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process these messages after it has
    /// returned.
    ///
    /// # Panic
    ///
    /// Panics if `chain_index` is out of range, or if the chain has GrandPa disabled.
    ///
    pub fn set_local_grandpa_state(&mut self, chain_index: usize, grandpa_state: GrandpaState) {
        // Bytes of the neighbor packet to send out.
        let packet = protocol::GrandpaNotificationRef::Neighbor(protocol::NeighborPacket {
            round_number: grandpa_state.round_number,
            set_id: grandpa_state.set_id,
            commit_finalized_height: grandpa_state.commit_finalized_height,
        })
        .scale_encoding(self.chains[chain_index].chain_config.block_number_bytes)
        .fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        // Now sending out.
        let _ = self
            .inner
            .broadcast_notification(chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 2, packet);

        // Update the locally-stored state, but only after the notification has been broadcasted.
        // This way, if the user cancels the future while `broadcast_notification` is executing,
        // the whole operation is cancelled.
        *self.chains[chain_index]
            .chain_config
            .grandpa_protocol_config
            .as_mut()
            .unwrap() = grandpa_state;
    }

    /// Sends a blocks request to the given peer.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    // TODO: more docs
    pub fn start_blocks_request(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        config: protocol::BlocksRequestConfig,
        timeout: Duration,
    ) -> OutRequestId {
        self.start_blocks_request_inner(now, target, chain_index, config, timeout, true)
    }

    /// Sends a blocks request to the given peer.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    // TODO: more docs
    pub fn start_blocks_request_unchecked(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        config: protocol::BlocksRequestConfig,
        timeout: Duration,
    ) -> OutRequestId {
        self.start_blocks_request_inner(now, target, chain_index, config, timeout, false)
    }

    fn start_blocks_request_inner(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        config: protocol::BlocksRequestConfig,
        timeout: Duration,
        checked: bool,
    ) -> OutRequestId {
        let request_data = protocol::build_block_request(
            self.chains[chain_index].chain_config.block_number_bytes,
            &config,
        )
        .fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        let id = self.inner.start_request(
            target,
            self.protocol_index(chain_index, 0),
            request_data,
            now + timeout,
        );

        let _prev_value = self.out_requests_types.insert(
            id,
            (
                OutRequestTy::Blocks {
                    checked: if checked { Some(config) } else { None },
                },
                chain_index,
            ),
        );
        debug_assert!(_prev_value.is_none());

        id
    }

    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    pub fn start_grandpa_warp_sync_request(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        begin_hash: [u8; 32],
        timeout: Duration,
    ) -> OutRequestId {
        let request_data = begin_hash.to_vec();

        let id = self.inner.start_request(
            target,
            self.protocol_index(chain_index, 3),
            request_data,
            now + timeout,
        );

        let _prev_value = self
            .out_requests_types
            .insert(id, (OutRequestTy::GrandpaWarpSync, chain_index));
        debug_assert!(_prev_value.is_none());

        id
    }

    /// Sends a state request to a peer.
    ///
    /// A state request makes it possible to download the storage of the chain at a given block.
    /// The response is not unverified by this function. In other words, the peer is free to send
    /// back erroneous data. It is the responsibility of the API user to verify the storage by
    /// calculating the state trie root hash and comparing it with the value stored in the
    /// block's header.
    ///
    /// Because response have a size limit, it is unlikely that a single request will return the
    /// entire storage of the chain at once. Instead, call this function multiple times, each call
    /// passing a `start_key` that follows the last key of the previous response.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    // TODO: does an empty response mean that `start_key` is the last key of the storage? unclear
    pub fn start_state_request_unchecked(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        block_hash: &[u8; 32],
        start_key: &[u8],
        timeout: Duration,
    ) -> OutRequestId {
        let request_data = protocol::build_state_request(protocol::StateRequest {
            block_hash,
            start_key,
        })
        .fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        let id = self.inner.start_request(
            target,
            self.protocol_index(chain_index, 4),
            request_data,
            now + timeout,
        );

        let _prev_value = self
            .out_requests_types
            .insert(id, (OutRequestTy::State, chain_index));
        debug_assert!(_prev_value.is_none());

        id
    }

    /// Sends a storage request to the given peer.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    // TODO: more docs
    pub fn start_storage_proof_request(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        config: protocol::StorageProofRequestConfig<impl Iterator<Item = impl AsRef<[u8]> + Clone>>,
        timeout: Duration,
    ) -> OutRequestId {
        let request_data =
            protocol::build_storage_proof_request(config).fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });

        let id = self.inner.start_request(
            target,
            self.protocol_index(chain_index, 1),
            request_data,
            now + timeout,
        );

        let _prev_value = self
            .out_requests_types
            .insert(id, (OutRequestTy::StorageProof, chain_index));
        debug_assert!(_prev_value.is_none());

        id
    }

    /// Sends a call proof request to the given peer.
    ///
    /// This request is similar to [`ChainNetwork::start_storage_proof_request`]. Instead of
    /// requesting specific keys, we request the list of all the keys that are accessed for a
    /// specific runtime call.
    ///
    /// There exists no guarantee that the proof is complete (i.e. that it contains all the
    /// necessary entries), as it is impossible to know this from just the proof itself. As such,
    /// this method is just an optimization. When performing the actual call, regular storage proof
    /// requests should be performed if the key is not present in the call proof response.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    pub fn start_call_proof_request(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        config: protocol::CallProofRequestConfig<'_, impl Iterator<Item = impl AsRef<[u8]>>>,
        timeout: Duration,
    ) -> OutRequestId {
        let request_data =
            protocol::build_call_proof_request(config).fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });

        let id = self.inner.start_request(
            target,
            self.protocol_index(chain_index, 1),
            request_data,
            now + timeout,
        );

        let _prev_value = self
            .out_requests_types
            .insert(id, (OutRequestTy::CallProof, chain_index));
        debug_assert!(_prev_value.is_none());

        id
    }

    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    // TODO: there this extra parameter in block announces that is unused on many chains but not always
    pub fn send_block_announce(
        &mut self,
        target: &PeerId,
        chain_index: usize,
        scale_encoded_header: &[u8],
        is_best: bool,
    ) -> Result<(), QueueNotificationError> {
        let buffers_to_send = protocol::encode_block_announce(protocol::BlockAnnounceRef {
            scale_encoded_header,
            is_best,
        });

        let notification = buffers_to_send.fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        self.inner.queue_notification(
            target,
            chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN,
            notification,
        )
    }

    /// Returns `true` if it is allowed to call [`ChainNetwork::send_block_announce`], in other
    /// words if there is an outbound block announces substream currently open with the target.
    ///
    /// If this function returns `false`, calling [`ChainNetwork::send_block_announce`] will
    /// panic.
    pub fn can_send_block_announces(&self, target: &PeerId, chain_index: usize) -> bool {
        self.inner
            .can_queue_notification(target, chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN)
    }

    /// Returns the list of peers for which we have a fully established notifications protocol of
    /// the given protocol.
    pub fn opened_transactions_substream(
        &'_ self,
        chain_index: usize,
    ) -> impl Iterator<Item = &'_ PeerId> + '_ {
        self.inner
            .opened_out_notifications(chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 1)
    }

    ///
    ///
    /// Must be passed the SCALE-encoded transaction.
    ///
    /// This function might generate a message destined connections. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    // TODO: -> broadcast_transaction
    pub fn announce_transaction(
        &mut self,
        target: &PeerId,
        chain_index: usize,
        extrinsic: &[u8],
    ) -> Result<(), QueueNotificationError> {
        let mut val = Vec::with_capacity(1 + extrinsic.len());
        val.extend_from_slice(util::encode_scale_compact_usize(1).as_ref());
        val.extend_from_slice(extrinsic);
        self.inner.queue_notification(
            target,
            chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 1,
            val,
        )
    }

    /// Inserts the given list of nodes into the list of known nodes held within the state machine.
    pub fn discover(
        &mut self,
        now: &TNow,
        chain_index: usize,
        peer_id: PeerId,
        discovered_addrs: impl IntoIterator<Item = multiaddr::Multiaddr>,
    ) {
        let kbuckets = &mut self.chains[chain_index].kbuckets;

        let mut discovered_addrs = discovered_addrs.into_iter().peekable();

        // Check whether there is any address in the iterator at all before inserting the
        // node in the buckets.
        if discovered_addrs.peek().is_none() {
            return;
        }

        let kbuckets_peer = match kbuckets.entry(&peer_id) {
            kademlia::kbuckets::Entry::LocalKey => return, // TODO: return some diagnostic?
            kademlia::kbuckets::Entry::Vacant(entry) => {
                match entry.insert((), now, kademlia::kbuckets::PeerState::Disconnected) {
                    Err(kademlia::kbuckets::InsertError::Full) => return, // TODO: return some diagnostic?
                    Ok((_, removed_entry)) => {
                        // `removed_entry` is the peer that was removed the k-buckets as the
                        // result of the new insertion. Purge it from `self.kbuckets_peers`
                        // if necessary.
                        if let Some((removed_peer_id, _)) = removed_entry {
                            match self.kbuckets_peers.entry(removed_peer_id) {
                                hashbrown::hash_map::Entry::Occupied(e)
                                    if e.get().num_references.get() == 1 =>
                                {
                                    e.remove();
                                }
                                hashbrown::hash_map::Entry::Occupied(e) => {
                                    let num_refs = &mut e.into_mut().num_references;
                                    *num_refs = NonZeroUsize::new(num_refs.get() - 1).unwrap();
                                }
                                hashbrown::hash_map::Entry::Vacant(_) => unreachable!(),
                            }
                        }

                        match self.kbuckets_peers.entry(peer_id) {
                            hashbrown::hash_map::Entry::Occupied(e) => {
                                let e = e.into_mut();
                                e.num_references = e.num_references.checked_add(1).unwrap();
                                e
                            }
                            hashbrown::hash_map::Entry::Vacant(e) => {
                                // The peer was not in the k-buckets, but it is possible that
                                // we already have existing connections to it.
                                let mut addresses = addresses::Addresses::with_capacity(
                                    self.max_addresses_per_peer.get(),
                                );

                                for connection_id in
                                    self.inner.established_peer_connections(&e.key())
                                {
                                    let state = self.inner.connection_state(connection_id);
                                    debug_assert!(state.established);
                                    // Because we mark addresses as disconnected when the
                                    // shutdown process starts, we ignore shutting down
                                    // connections.
                                    if state.shutting_down {
                                        continue;
                                    }
                                    if state.outbound {
                                        addresses
                                            .insert_discovered(self.inner[connection_id].clone());
                                        addresses.set_connected(&self.inner[connection_id]);
                                    }
                                }

                                for connection_id in
                                    self.inner.handshaking_peer_connections(&e.key())
                                {
                                    let state = self.inner.connection_state(connection_id);
                                    debug_assert!(!state.established);
                                    debug_assert!(state.outbound);
                                    // Because we mark addresses as disconnected when the
                                    // shutdown process starts, we ignore shutting down
                                    // connections.
                                    if state.shutting_down {
                                        continue;
                                    }
                                    addresses.insert_discovered(self.inner[connection_id].clone());
                                    addresses.set_pending(&self.inner[connection_id]);
                                }

                                // TODO: O(n)
                                for (_, (p, addr, _)) in &self.pending_ids {
                                    if p == e.key() {
                                        addresses.insert_discovered(addr.clone());
                                        addresses.set_pending(addr);
                                    }
                                }

                                e.insert(KBucketsPeer {
                                    num_references: NonZeroUsize::new(1).unwrap(),
                                    addresses,
                                })
                            }
                        }
                    }
                }
            }
            kademlia::kbuckets::Entry::Occupied(_) => {
                self.kbuckets_peers.get_mut(&peer_id).unwrap()
            }
        };

        for to_insert in discovered_addrs {
            if kbuckets_peer.addresses.len() >= self.max_addresses_per_peer.get() {
                continue;
            }

            kbuckets_peer.addresses.insert_discovered(to_insert);
        }

        // List of addresses must never be empty.
        debug_assert!(!kbuckets_peer.addresses.is_empty());
    }

    /// Returns a list of nodes (their [`PeerId`] and multiaddresses) that we know are part of
    /// the network.
    ///
    /// Nodes that are discovered might disappear over time. In other words, there is no guarantee
    /// that a node that has been added through [`ChainNetwork::discover`] will later be returned
    /// by [`ChainNetwork::discovered_nodes`].
    pub fn discovered_nodes(
        &'_ self,
        chain_index: usize,
    ) -> impl Iterator<Item = (&'_ PeerId, impl Iterator<Item = &'_ multiaddr::Multiaddr>)> + '_
    {
        let kbuckets = &self.chains[chain_index].kbuckets;
        kbuckets.iter_ordered().map(move |(peer_id, _)| {
            (
                peer_id,
                self.kbuckets_peers.get(peer_id).unwrap().addresses.iter(),
            )
        })
    }

    /// After calling [`ChainNetwork::next_start_connect`], notifies the [`ChainNetwork`] of the
    /// success of the dialing attempt.
    ///
    /// See also [`ChainNetwork::pending_outcome_err`].
    ///
    /// # Panic
    ///
    /// Panics if the [`PendingId`] is invalid.
    ///
    pub fn pending_outcome_ok_single_stream(
        &mut self,
        id: PendingId,
        handshake_kind: SingleStreamHandshakeKind,
    ) -> (ConnectionId, SingleStreamConnectionTask<TNow>) {
        // Don't remove the value in `pending_ids` yet, so that the state remains consistent if
        // the user cancels the future returned by `add_outgoing_connection`.
        let (expected_peer_id, multiaddr, when_connected) = self.pending_ids.get(id.0).unwrap();

        let (connection_id, connection_task) = self.inner.add_single_stream_outgoing_connection(
            when_connected.clone(),
            handshake_kind,
            expected_peer_id,
            multiaddr.clone(),
        );

        // Update `self.peers`.
        {
            let value = self.num_pending_per_peer.get_mut(expected_peer_id).unwrap();
            if let Some(new_value) = NonZeroUsize::new(value.get() - 1) {
                *value = new_value;
            } else {
                self.num_pending_per_peer.remove(expected_peer_id).unwrap();
            }
        }

        self.pending_ids.remove(id.0);

        (connection_id, connection_task)
    }

    /// After calling [`ChainNetwork::next_start_connect`], notifies the [`ChainNetwork`] of the
    /// success of the dialing attempt.
    ///
    /// See also [`ChainNetwork::pending_outcome_err`].
    ///
    /// # Panic
    ///
    /// Panics if the [`PendingId`] is invalid.
    ///
    pub fn pending_outcome_ok_multi_stream<TSubId>(
        &mut self,
        id: PendingId,
        handshake_kind: MultiStreamHandshakeKind,
    ) -> (ConnectionId, MultiStreamConnectionTask<TNow, TSubId>)
    where
        TSubId: Clone + PartialEq + Eq + Hash,
    {
        // Don't remove the value in `pending_ids` yet, so that the state remains consistent if
        // the user cancels the future returned by `add_outgoing_connection`.
        let (expected_peer_id, multiaddr, when_connected) = self.pending_ids.get(id.0).unwrap();

        let (connection_id, connection_task) = self.inner.add_multi_stream_outgoing_connection(
            when_connected.clone(),
            handshake_kind,
            expected_peer_id,
            multiaddr.clone(),
        );

        // Update `self.peers`.
        {
            let value = self.num_pending_per_peer.get_mut(expected_peer_id).unwrap();
            if let Some(new_value) = NonZeroUsize::new(value.get() - 1) {
                *value = new_value;
            } else {
                self.num_pending_per_peer.remove(expected_peer_id).unwrap();
            }
        }

        self.pending_ids.remove(id.0);

        (connection_id, connection_task)
    }

    /// After calling [`ChainNetwork::next_start_connect`], notifies the [`ChainNetwork`] of the
    /// failure of the dialing attempt.
    ///
    /// See also [`ChainNetwork::pending_outcome_ok_single_stream`] and
    /// [`ChainNetwork::pending_outcome_ok_multi_stream`].
    ///
    /// `is_unreachable` should be `true` if the address is invalid or unreachable and should
    /// thus never be attempted again unless it is re-discovered. It should be `false` if the
    /// address might only be temporarily unreachable, such as because of a timeout. If `false`
    /// is passed, the address might be attempted again in the future.
    ///
    /// # Panic
    ///
    /// Panics if the [`PendingId`] is invalid.
    ///
    pub fn pending_outcome_err(&mut self, id: PendingId, is_unreachable: bool) {
        let (expected_peer_id, multiaddr, _) = self.pending_ids.get(id.0).unwrap();
        let multiaddr = multiaddr.clone(); // Solves borrowck issues.

        let has_any_attempt_left = self
            .num_pending_per_peer
            .get(expected_peer_id)
            .unwrap()
            .get()
            != 1;

        // If the peer is completely unreachable, unassign all of its slots.
        if !has_any_attempt_left
            && self
                .inner
                .established_peer_connections(expected_peer_id)
                .count()
                == 0
        {
            let expected_peer_id = expected_peer_id.clone(); // Necessary for borrowck reasons.

            for chain_index in 0..self.chains.len() {
                // TODO: report as event or something
                self.unassign_slot(chain_index, &expected_peer_id);
            }
        }

        // Now update `self`.
        // For future-cancellation-safety reasons, this is done after all the asynchronous
        // operations.

        let (expected_peer_id, _, _) = self.pending_ids.remove(id.0);

        // Updates the addresses book.
        if let Some(KBucketsPeer { addresses, .. }) = self.kbuckets_peers.get_mut(&expected_peer_id)
        {
            if is_unreachable {
                // Do not remove last remaining address, in order to prevent the addresses
                // list from ever becoming empty.
                debug_assert!(!addresses.is_empty());
                if addresses.len() > 1 {
                    addresses.remove(&multiaddr);
                } else {
                    // TODO: remove peer from k-buckets instead?
                    addresses.set_disconnected(&multiaddr);
                }
            } else {
                addresses.set_disconnected(&multiaddr);

                // Shuffle the known addresses, otherwise the same address might get picked
                // again.
                addresses.shuffle();
            }
        }

        {
            let value = self
                .num_pending_per_peer
                .get_mut(&expected_peer_id)
                .unwrap();
            if let Some(new_value) = NonZeroUsize::new(value.get() - 1) {
                *value = new_value;
            } else {
                self.num_pending_per_peer.remove(&expected_peer_id).unwrap();
            }
        };
    }

    /// Returns the next event produced by the service.
    // TODO: this `now` parameter, it's a hack
    pub fn next_event(&mut self, now: TNow) -> Option<Event> {
        if let Some((kademlia_operation_id, error)) = self.pending_kademlia_errors.pop_front() {
            return Some(Event::KademliaDiscoveryResult {
                operation_id: kademlia_operation_id,
                result: Err(error),
            });
        }

        let event_to_return = loop {
            // Instead of simply calling `next_event()` from the inner state machine to grab the
            // inner event, we first call `fulfilled_undesired_outbound_substreams` and determine
            // whether there is any already-open or opening-in-progress substream to close. If so,
            // we perform the closing, then continue running the body of `next_event` but pretend
            // that the underlying state machine has generated an event corresponding to that
            // substream having been closed.
            let inner_event = {
                let event = loop {
                    let to_close = self
                        .inner
                        .fulfilled_undesired_outbound_substreams()
                        .next()
                        .map(|(peer_id, idx, _)| (peer_id.clone(), idx));
                    if let Some((peer_id, notifications_protocol_index)) = to_close {
                        let open_or_pending = self
                            .inner
                            .close_out_notification(&peer_id, notifications_protocol_index);
                        match open_or_pending {
                            peers::OpenOrPending::Pending => {
                                // Intentionally ignored, as it concerns a peer that is no longer
                                // desired, and thus didn't have a slot.
                            }
                            peers::OpenOrPending::Open => {
                                break Some(peers::Event::NotificationsOutClose {
                                    notifications_protocol_index,
                                    peer_id,
                                })
                            }
                        }
                    } else {
                        break None;
                    }
                };

                // No event due to closing substreams. Grab the "actual" inner event.
                match event {
                    Some(ev) => ev,
                    None => match self.inner.next_event() {
                        Some(ev) => ev,
                        None => break None,
                    },
                }
            };

            match inner_event {
                peers::Event::HandshakeFinished {
                    connection_id,
                    peer_id,
                    num_healthy_peer_connections,
                    expected_peer_id,
                } => {
                    let multiaddr = &self.inner[connection_id];

                    debug_assert_eq!(
                        self.inner.connection_state(connection_id).outbound,
                        expected_peer_id.is_some()
                    );

                    if let Some(expected_peer_id) = expected_peer_id.as_ref() {
                        if *expected_peer_id != peer_id {
                            if let Some(KBucketsPeer { addresses, .. }) =
                                self.kbuckets_peers.get_mut(expected_peer_id)
                            {
                                debug_assert!(!addresses.is_empty());
                                if addresses.len() > 1 {
                                    addresses.remove(multiaddr);
                                } else {
                                    // TODO: remove peer from k-buckets instead?
                                    addresses.set_disconnected(multiaddr);
                                }
                            }
                        }

                        // Mark the address as connected.
                        // Note that this is done only for outgoing connections.
                        if let Some(KBucketsPeer { addresses, .. }) =
                            self.kbuckets_peers.get_mut(&peer_id)
                        {
                            if *expected_peer_id != peer_id {
                                addresses.insert_discovered(multiaddr.clone());
                            }

                            addresses.set_connected(multiaddr);
                        }
                    }

                    if num_healthy_peer_connections.get() == 1 {
                        break Some(Event::Connected(peer_id));
                    }
                }

                peers::Event::Shutdown { .. } => {
                    // TODO:
                }

                peers::Event::StartShutdown {
                    connection_id,
                    peer:
                        peers::ShutdownPeer::Established {
                            peer_id,
                            num_healthy_peer_connections,
                        },
                    ..
                } if num_healthy_peer_connections == 0 => {
                    // TODO: O(n)
                    let chain_indices = self
                        .open_chains
                        .iter()
                        .filter(|(pid, _)| pid == &peer_id)
                        .map(|(_, c)| *c)
                        .collect::<Vec<_>>();

                    // Un-assign all the slots of that peer.
                    for idx in &chain_indices {
                        self.unassign_slot(*idx, &peer_id);
                    }

                    // Update the list of addresses of this peer.
                    if self.inner.connection_state(connection_id).outbound {
                        let address = &self.inner[connection_id];
                        if let Some(KBucketsPeer { addresses, .. }) =
                            self.kbuckets_peers.get_mut(&peer_id)
                        {
                            addresses.set_disconnected(&address);
                            debug_assert_eq!(addresses.iter_connected().count(), 0);
                        }
                    }

                    for idx in &chain_indices {
                        self.open_chains.remove(&(peer_id.clone(), *idx)); // TODO: cloning :-/
                    }

                    break Some(Event::Disconnected {
                        peer_id,
                        chain_indices,
                    });
                }
                peers::Event::StartShutdown {
                    connection_id,
                    peer: peers::ShutdownPeer::Established { peer_id, .. },
                    ..
                } => {
                    // Update the list of addresses of this peer.
                    if self.inner.connection_state(connection_id).outbound {
                        let address = &self.inner[connection_id];
                        if let Some(KBucketsPeer { addresses, .. }) =
                            self.kbuckets_peers.get_mut(&peer_id)
                        {
                            addresses.set_disconnected(&address);
                            debug_assert_ne!(addresses.iter_connected().count(), 0);
                        }
                    }
                }
                peers::Event::StartShutdown {
                    connection_id,
                    peer:
                        peers::ShutdownPeer::OutgoingHandshake {
                            expected_peer_id, ..
                        },
                    ..
                } => {
                    // Update the k-buckets.
                    let address = &self.inner[connection_id];
                    if let Some(KBucketsPeer { addresses, .. }) =
                        self.kbuckets_peers.get_mut(&expected_peer_id)
                    {
                        addresses.set_disconnected(&address);
                    }
                }
                peers::Event::StartShutdown {
                    peer: peers::ShutdownPeer::IngoingHandshake,
                    ..
                } => {}

                // Insubstantial error for diagnostic purposes.
                peers::Event::InboundError { peer_id, error, .. } => {
                    break Some(Event::ProtocolError {
                        peer_id,
                        error: ProtocolError::InboundError(error),
                    });
                }

                // Incoming requests of the "identify" protocol.
                peers::Event::RequestIn {
                    protocol_index: 0,
                    connection_id,
                    peer_id,
                    request_payload,
                    request_id,
                    ..
                } => {
                    if request_payload.is_empty() {
                        let observed_addr = self.inner[connection_id].clone();
                        let _prev_value = self
                            .in_requests_types
                            .insert(request_id, InRequestTy::Identify { observed_addr });
                        debug_assert!(_prev_value.is_none());

                        break Some(Event::IdentifyRequestIn {
                            peer_id,
                            request_id,
                        });
                    }

                    let _ = self.inner.respond_in_request(request_id, Err(()));
                    break Some(Event::ProtocolError {
                        peer_id,
                        error: ProtocolError::BadIdentifyRequest,
                    });
                }
                // Incoming requests of the "sync" protocol.
                peers::Event::RequestIn {
                    peer_id,
                    request_id,
                    protocol_index,
                    request_payload,
                    ..
                } if ((protocol_index - 1) % REQUEST_RESPONSE_PROTOCOLS_PER_CHAIN) == 0 => {
                    let chain_index = (protocol_index - 1) / REQUEST_RESPONSE_PROTOCOLS_PER_CHAIN;

                    match protocol::decode_block_request(
                        self.chains[chain_index].chain_config.block_number_bytes,
                        &request_payload,
                    ) {
                        Ok(config) => {
                            let _prev_value = self
                                .in_requests_types
                                .insert(request_id, InRequestTy::Blocks);
                            debug_assert!(_prev_value.is_none());

                            break Some(Event::BlocksRequestIn {
                                peer_id,
                                chain_index,
                                config,
                                request_id,
                            });
                        }
                        Err(error) => {
                            let _ = self.inner.respond_in_request(request_id, Err(()));
                            break Some(Event::ProtocolError {
                                peer_id,
                                error: ProtocolError::BadBlocksRequest(error),
                            });
                        }
                    }
                }
                // Protocols that receive requests are whitelisted, meaning that no other protocol
                // indices can reach here.
                peers::Event::RequestIn { .. } => unreachable!(),

                // Remote is no longer interested in the response.
                // We don't do anything yet. The obsolescence is detected when trying to answer
                // it.
                peers::Event::RequestInCancel { id, .. } => {
                    self.in_requests_types.remove(&id).unwrap();
                    break Some(Event::RequestInCancel { request_id: id });
                }

                // Successfully opened block announces substream.
                // The block announces substream is the main substream that determines whether
                // a "chain" is open.
                peers::Event::NotificationsOutResult {
                    peer_id,
                    notifications_protocol_index,
                    result: Ok(remote_handshake),
                } if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0 => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                    // Check validity of the handshake.
                    let remote_handshake = match protocol::decode_block_announces_handshake(
                        self.chains[chain_index].chain_config.block_number_bytes,
                        &remote_handshake,
                    ) {
                        Ok(hs) => hs,
                        Err(err) => {
                            // TODO: must close the substream and unassigned the slot
                            break Some(Event::ProtocolError {
                                error: ProtocolError::BadBlockAnnouncesHandshake(err),
                                peer_id,
                            });
                        }
                    };

                    // The desirability of the transactions and grandpa substreams is always equal
                    // to whether the block announces substream is open.
                    self.inner.set_peer_notifications_out_desired(
                        &peer_id,
                        chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 1,
                        peers::DesiredState::DesiredReset,
                    );
                    self.inner.set_peer_notifications_out_desired(
                        &peer_id,
                        chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 2,
                        peers::DesiredState::DesiredReset,
                    );

                    let slot_ty = {
                        let local_genesis = self.chains[chain_index].chain_config.genesis_hash;
                        let remote_genesis = *remote_handshake.genesis_hash;

                        if remote_genesis != local_genesis {
                            let unassigned_slot_ty =
                                self.unassign_slot(chain_index, &peer_id).unwrap();

                            break Some(Event::ChainConnectAttemptFailed {
                                peer_id,
                                chain_index,
                                unassigned_slot_ty,
                                error: NotificationsOutErr::GenesisMismatch {
                                    local_genesis,
                                    remote_genesis,
                                },
                            });
                        }

                        // Update the k-buckets to mark the peer as connected.
                        // Note that this is done after having made sure that the handshake
                        // was correct.
                        // TODO: should we not insert the entry in the k-buckets as well? seems important for incoming connections
                        if let Some(mut entry) = self.chains[chain_index]
                            .kbuckets
                            .entry(&peer_id)
                            .into_occupied()
                        {
                            entry.set_state(&now, kademlia::kbuckets::PeerState::Connected);
                        }

                        if self.chains[chain_index].in_peers.contains(&peer_id) {
                            SlotTy::Inbound
                        } else {
                            debug_assert!(self.chains[chain_index].out_peers.contains(&peer_id));
                            SlotTy::Outbound
                        }
                    };

                    let _was_inserted = self.open_chains.insert((peer_id.clone(), chain_index));
                    debug_assert!(_was_inserted);

                    let best_hash = *remote_handshake.best_hash;
                    let best_number = remote_handshake.best_number;
                    let role = remote_handshake.role;

                    break Some(Event::ChainConnected {
                        peer_id,
                        chain_index,
                        slot_ty,
                        best_hash,
                        best_number,
                        role,
                    });
                }

                // Successfully opened transactions substream.
                peers::Event::NotificationsOutResult {
                    notifications_protocol_index,
                    result: Ok(_),
                    ..
                } if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 1 => {
                    // Nothing to do.
                }

                peers::Event::Response {
                    request_id,
                    response,
                } => match self.out_requests_types.remove(&request_id).unwrap() {
                    (OutRequestTy::Blocks { checked }, chain_index) => {
                        let mut response =
                            response
                                .map_err(BlocksRequestError::Request)
                                .and_then(|payload| {
                                    protocol::decode_block_response(&payload)
                                        .map_err(BlocksRequestError::Decode)
                                });

                        if let (Some(config), &mut Ok(ref mut blocks)) = (checked, &mut response) {
                            if let Err(err) = check_blocks_response(
                                self.chains[chain_index].chain_config.block_number_bytes,
                                config,
                                blocks,
                            ) {
                                response = Err(err);
                            }
                        }

                        break Some(Event::BlocksRequestResult {
                            request_id,
                            response,
                        });
                    }
                    (OutRequestTy::GrandpaWarpSync, chain_index) => {
                        let response = response
                            .map_err(GrandpaWarpSyncRequestError::Request)
                            .and_then(|payload| {
                                protocol::decode_grandpa_warp_sync_response(
                                    &payload,
                                    self.chains[chain_index].chain_config.block_number_bytes,
                                )
                                .map_err(GrandpaWarpSyncRequestError::Decode)
                            });

                        break Some(Event::GrandpaWarpSyncRequestResult {
                            request_id,
                            response,
                        });
                    }
                    (OutRequestTy::State, _) => {
                        let response =
                            response
                                .map_err(StateRequestError::Request)
                                .and_then(|payload| {
                                    if let Err(err) = protocol::decode_state_response(&payload) {
                                        Err(StateRequestError::Decode(err))
                                    } else {
                                        Ok(EncodedStateResponse(payload))
                                    }
                                });

                        break Some(Event::StateRequestResult {
                            request_id,
                            response,
                        });
                    }
                    (OutRequestTy::StorageProof, _) => {
                        let response = response
                            .map_err(StorageProofRequestError::Request)
                            .and_then(|payload| {
                                if let Err(err) = protocol::decode_storage_or_call_proof_response(
                                    protocol::StorageOrCallProof::StorageProof,
                                    &payload,
                                ) {
                                    Err(StorageProofRequestError::Decode(err))
                                } else {
                                    Ok(EncodedMerkleProof(
                                        payload,
                                        protocol::StorageOrCallProof::StorageProof,
                                    ))
                                }
                            });

                        break Some(Event::StorageProofRequestResult {
                            request_id,
                            response,
                        });
                    }
                    (OutRequestTy::CallProof, _) => {
                        let response =
                            response
                                .map_err(CallProofRequestError::Request)
                                .and_then(|payload| {
                                    if let Err(err) =
                                        protocol::decode_storage_or_call_proof_response(
                                            protocol::StorageOrCallProof::CallProof,
                                            &payload,
                                        )
                                    {
                                        Err(CallProofRequestError::Decode(err))
                                    } else {
                                        Ok(EncodedMerkleProof(
                                            payload,
                                            protocol::StorageOrCallProof::CallProof,
                                        ))
                                    }
                                });

                        break Some(Event::CallProofRequestResult {
                            request_id,
                            response,
                        });
                    }
                    (OutRequestTy::KademliaFindNode, _) => {
                        let response = response
                            .map_err(KademliaFindNodeError::RequestFailed)
                            .and_then(|payload| {
                                protocol::decode_find_node_response(&payload)
                                    .map_err(KademliaFindNodeError::DecodeError)
                            });

                        break Some(Event::KademliaFindNodeRequestResult {
                            request_id,
                            response,
                        });
                    }
                    (OutRequestTy::KademliaDiscoveryFindNode(operation_id), _) => {
                        let result = response
                            .map_err(KademliaFindNodeError::RequestFailed)
                            .and_then(|payload| {
                                protocol::decode_find_node_response(&payload)
                                    .map_err(KademliaFindNodeError::DecodeError)
                            })
                            .map_err(DiscoveryError::FindNode);

                        break Some(Event::KademliaDiscoveryResult {
                            operation_id,
                            result,
                        });
                    }
                },

                // Successfully opened Grandpa substream.
                // Need to send a Grandpa neighbor packet in response.
                peers::Event::NotificationsOutResult {
                    peer_id,
                    notifications_protocol_index,
                    result: Ok(_),
                    ..
                } if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 2 => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                    let notification = {
                        let grandpa_config = *self.chains[chain_index]
                            .chain_config
                            .grandpa_protocol_config
                            .as_ref()
                            .unwrap();

                        protocol::GrandpaNotificationRef::Neighbor(protocol::NeighborPacket {
                            round_number: grandpa_config.round_number,
                            set_id: grandpa_config.set_id,
                            commit_finalized_height: grandpa_config.commit_finalized_height,
                        })
                        .scale_encoding(self.chains[chain_index].chain_config.block_number_bytes)
                        .fold(Vec::new(), |mut a, b| {
                            a.extend_from_slice(b.as_ref());
                            a
                        })
                    };

                    let _ = self.inner.queue_notification(
                        &peer_id,
                        notifications_protocol_index,
                        notification.clone(),
                    );
                }

                // Unrecognized protocol.
                peers::Event::NotificationsOutResult { result: Ok(_), .. } => unreachable!(),

                // Failed to open block announces substream.
                peers::Event::NotificationsOutResult {
                    notifications_protocol_index,
                    peer_id,
                    result: Err(error),
                } if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0 => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                    let unassigned_slot_ty = self.unassign_slot(chain_index, &peer_id).unwrap();

                    break Some(Event::ChainConnectAttemptFailed {
                        peer_id,
                        chain_index,
                        unassigned_slot_ty,
                        error: NotificationsOutErr::Substream(error),
                    });
                }

                // Other protocol.
                peers::Event::NotificationsOutResult { result: Err(_), .. } => {}

                // Remote closes our outbound block announces substream.
                peers::Event::NotificationsOutClose {
                    notifications_protocol_index,
                    peer_id,
                } if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0 => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                    // The desirability of the transactions and grandpa substreams is always equal
                    // to whether the block announces substream is open.
                    //
                    // These two calls modify `self.inner`, but they are still cancellation-safe
                    // as they can be repeated multiple times.
                    self.inner.set_peer_notifications_out_desired(
                        &peer_id,
                        chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 1,
                        peers::DesiredState::NotDesired,
                    );
                    self.inner.set_peer_notifications_out_desired(
                        &peer_id,
                        chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 2,
                        peers::DesiredState::NotDesired,
                    );

                    // The chain is now considered as closed.
                    // TODO: can was_open ever be false?
                    let was_open = self.open_chains.remove(&(peer_id.clone(), chain_index)); // TODO: cloning :(

                    if was_open {
                        // Update the k-buckets, marking the peer as disconnected.
                        let unassigned_slot_ty = {
                            let unassigned_slot_ty =
                                self.unassign_slot(chain_index, &peer_id).unwrap();

                            if let Some(mut entry) = self.chains[chain_index]
                                .kbuckets
                                .entry(&peer_id)
                                .into_occupied()
                            {
                                // Note that the state might have already be `Disconnected`, which
                                // can happen for example in case of a problem in the handshake
                                // sent back by the remote.
                                entry.set_state(&now, kademlia::kbuckets::PeerState::Disconnected);
                            }

                            unassigned_slot_ty
                        };

                        break Some(Event::ChainDisconnected {
                            chain_index,
                            peer_id,
                            unassigned_slot_ty,
                        });
                    }
                }

                // Other protocol.
                peers::Event::NotificationsOutClose {
                    peer_id,
                    notifications_protocol_index,
                    ..
                } => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                    // The state of notification substreams other than block announces must
                    // always match the state of the block announces.
                    // Therefore, if the peer is considered open, try to reopen the substream that
                    // has just been closed.
                    // TODO: cloning of peer_id :-/
                    if self.open_chains.contains(&(peer_id.clone(), chain_index)) {
                        self.inner.set_peer_notifications_out_desired(
                            &peer_id,
                            notifications_protocol_index,
                            peers::DesiredState::DesiredReset,
                        );
                    }
                }

                // Remote closes a block announce substream.
                peers::Event::NotificationsInClose {
                    peer_id,
                    notifications_protocol_index,
                    ..
                } if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0 => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                    // We unassign the inbound slot of the peer if it had one.
                    // If the peer had an outbound slot, then this does nothing.
                    if self.chains[chain_index].in_peers.remove(&peer_id) {
                        self.inner.set_peer_notifications_out_desired(
                            &peer_id,
                            notifications_protocol_index,
                            peers::DesiredState::NotDesired,
                        );
                    }
                }

                // Remote closes another substream.
                peers::Event::NotificationsInClose { .. } => {}

                // Received a block announce.
                peers::Event::NotificationsIn {
                    notifications_protocol_index,
                    peer_id,
                    notification,
                } if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0 => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                    // Don't report events about nodes we don't have an outbound substream with.
                    // TODO: think about possible race conditions regarding missing block
                    // announcements, as the remote will think we know it's at a certain block
                    // while we ignored its announcement ; it isn't problematic as long as blocks
                    // are generated continuously, as announcements will be generated periodically
                    // as well and the state will no longer mismatch
                    // TODO: cloning of peer_id :(
                    if !self.open_chains.contains(&(peer_id.clone(), chain_index)) {
                        continue;
                    }

                    let block_number_bytes =
                        self.chains[chain_index].chain_config.block_number_bytes;

                    // Check the format of the block announce.
                    if let Err(err) =
                        protocol::decode_block_announce(&notification, block_number_bytes)
                    {
                        break Some(Event::ProtocolError {
                            error: ProtocolError::BadBlockAnnounce(err),
                            peer_id,
                        });
                    }

                    break Some(Event::BlockAnnounce {
                        chain_index,
                        peer_id,
                        announce: EncodedBlockAnnounce {
                            message: notification,
                            block_number_bytes,
                        },
                    });
                }

                // Received transaction notification.
                peers::Event::NotificationsIn {
                    peer_id,
                    notifications_protocol_index,
                    ..
                } if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 1 => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                    // Don't report events about nodes we don't have an outbound substream with.
                    // TODO: cloning of peer_id :(
                    if !self.open_chains.contains(&(peer_id.clone(), chain_index)) {
                        continue;
                    }

                    // TODO: this is unimplemented
                }

                // Received Grandpa notification.
                peers::Event::NotificationsIn {
                    notifications_protocol_index,
                    peer_id,
                    notification,
                } if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 2 => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;
                    let block_number_bytes =
                        self.chains[chain_index].chain_config.block_number_bytes;

                    // Don't report events about nodes we don't have an outbound substream with.
                    // TODO: cloning of peer_id :(
                    if !self.open_chains.contains(&(peer_id.clone(), chain_index)) {
                        continue;
                    }

                    let decoded_notif = match protocol::decode_grandpa_notification(
                        &notification,
                        block_number_bytes,
                    ) {
                        Ok(n) => n,
                        Err(err) => {
                            break Some(Event::ProtocolError {
                                error: ProtocolError::BadGrandpaNotification(err),
                                peer_id,
                            });
                        }
                    };

                    // Commit messages are the only type of message that is important for
                    // light clients. Anything else is presently ignored.
                    if let protocol::GrandpaNotificationRef::Commit(_) = decoded_notif {
                        break Some(Event::GrandpaCommitMessage {
                            chain_index,
                            peer_id,
                            message: EncodedGrandpaCommitMessage {
                                message: notification,
                                block_number_bytes,
                            },
                        });
                    }
                }

                peers::Event::NotificationsIn { .. } => {
                    // Unrecognized notifications protocol.
                    unreachable!();
                }

                // Remote wants to open a block announces substream.
                // The block announces substream is the main substream that determines whether
                // a "chain" is open.
                peers::Event::NotificationsInOpen {
                    peer_id,
                    handshake,
                    id: substream_id,
                    notifications_protocol_index,
                } if (notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN) == 0 => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                    // Immediately reject the substream if the handshake fails to parse.
                    if let Err(err) = protocol::decode_block_announces_handshake(
                        self.chains[chain_index].chain_config.block_number_bytes,
                        &handshake,
                    ) {
                        self.inner.in_notification_refuse(substream_id);

                        break Some(Event::ProtocolError {
                            error: ProtocolError::BadBlockAnnouncesHandshake(err),
                            peer_id,
                        });
                    }

                    // If the peer doesn't already have an outbound slot, check whether we can
                    // allocate an inbound slot for it.
                    let has_out_slot = self.chains[chain_index].out_peers.contains(&peer_id);
                    if !has_out_slot
                        && self.chains[chain_index].in_peers.len()
                            >= usize::try_from(self.chains[chain_index].chain_config.in_slots)
                                .unwrap_or(usize::max_value())
                    {
                        // All in slots are occupied. Refuse the substream.
                        self.inner.in_notification_refuse(substream_id);
                        continue;
                    }

                    // At this point, accept the node can no longer fail.

                    // Generate the handshake to send back.
                    let handshake = {
                        let chain_config = &self.chains[chain_index].chain_config;
                        protocol::encode_block_announces_handshake(
                            protocol::BlockAnnouncesHandshakeRef {
                                best_hash: &chain_config.best_hash,
                                best_number: chain_config.best_number,
                                genesis_hash: &chain_config.genesis_hash,
                                role: chain_config.role,
                            },
                            chain_config.block_number_bytes,
                        )
                        .fold(Vec::new(), |mut a, b| {
                            a.extend_from_slice(b.as_ref());
                            a
                        })
                    };

                    self.inner.in_notification_accept(substream_id, handshake);

                    if !has_out_slot {
                        // TODO: future cancellation issue; if this future is cancelled, then trying to do the `in_notification_accept` again next time will panic
                        self.inner.set_peer_notifications_out_desired(
                            &peer_id,
                            notifications_protocol_index,
                            peers::DesiredState::DesiredReset,
                        );

                        // The state modification is done at the very end, to not have any
                        // future cancellation issue.
                        let _was_inserted =
                            self.chains[chain_index].in_peers.insert(peer_id.clone());
                        debug_assert!(_was_inserted);

                        break Some(Event::InboundSlotAssigned {
                            chain_index,
                            peer_id,
                        });
                    }
                }

                // Remote wants to open a transactions substream.
                peers::Event::NotificationsInOpen {
                    peer_id,
                    id: substream_id,
                    notifications_protocol_index,
                    ..
                } if (notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN) == 1 => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                    // Accept the substream only if the peer is "chain connected".
                    if self
                        .open_chains // TODO: clone :-/
                        .contains(&(peer_id.clone(), chain_index))
                    {
                        self.inner.in_notification_accept(substream_id, Vec::new());
                    } else {
                        self.inner.in_notification_refuse(substream_id);
                    }
                }

                // Remote wants to open a grandpa substream.
                peers::Event::NotificationsInOpen {
                    peer_id,
                    id: substream_id,
                    notifications_protocol_index,
                    ..
                } if (notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN) == 2 => {
                    let chain_index =
                        notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                    // Reject the substream if the this peer isn't "chain connected".
                    if !self
                        .open_chains // TODO: clone :-/
                        .contains(&(peer_id.clone(), chain_index))
                    {
                        self.inner.in_notification_refuse(substream_id);
                        continue;
                    }

                    // Peer is indeed connected. Accept the substream.

                    // Build the handshake to send back.
                    let handshake = {
                        self.chains[chain_index]
                            .chain_config
                            .role
                            .scale_encoding()
                            .to_vec()
                    };

                    self.inner.in_notification_accept(substream_id, handshake);
                }

                peers::Event::NotificationsInOpen { .. } => {
                    // Unrecognized notifications protocol.
                    unreachable!();
                }

                peers::Event::NotificationsInOpenCancel { .. } => {
                    // Because we always accept/refuse incoming notification substreams instantly,
                    // there's no possibility for a cancellation to happen.
                    unreachable!()
                }
            }
        };

        // Before returning the event, we check whether there is any desired outbound substream
        // to open.
        loop {
            // Note: we can't use a `while let` due to borrow checker errors.
            let (peer_id, notifications_protocol_index) = match self
                .inner
                .unfulfilled_desired_outbound_substream(false)
                .next()
            {
                Some((peer_id, idx)) => (peer_id.clone(), idx),
                None => break,
            };

            let chain_config = &self.chains
                [notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN]
                .chain_config;

            let handshake = if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0
            {
                protocol::encode_block_announces_handshake(
                    protocol::BlockAnnouncesHandshakeRef {
                        best_hash: &chain_config.best_hash,
                        best_number: chain_config.best_number,
                        genesis_hash: &chain_config.genesis_hash,
                        role: chain_config.role,
                    },
                    chain_config.block_number_bytes,
                )
                .fold(Vec::new(), |mut a, b| {
                    a.extend_from_slice(b.as_ref());
                    a
                })
            } else if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 1 {
                Vec::new()
            } else if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 2 {
                chain_config.role.scale_encoding().to_vec()
            } else {
                unreachable!()
            };

            self.inner.open_out_notification(
                &peer_id,
                notifications_protocol_index,
                now.clone(),
                handshake,
            );
        }

        event_to_return
    }

    /// Performs a round of Kademlia discovery.
    ///
    /// This future yields once a list of nodes on the network has been discovered, or a problem
    /// happened.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    pub fn start_kademlia_discovery_round(
        &'_ mut self,
        now: TNow,
        chain_index: usize,
    ) -> KademliaOperationId {
        let random_peer_id = {
            let pub_key = self.randomness.sample(rand::distributions::Standard);
            PeerId::from_public_key(&peer_id::PublicKey::Ed25519(pub_key))
        };

        let queried_peer = {
            let peer_id = self.chains[chain_index]
                .kbuckets
                .closest_entries(&random_peer_id)
                // TODO: instead of filtering by connectd only, connect to nodes if not connected
                // TODO: additionally, this only takes outgoing connections into account
                .find(|(peer_id, _)| {
                    self.kbuckets_peers
                        .get(peer_id)
                        .unwrap()
                        .addresses
                        .iter_connected()
                        .next()
                        .is_some()
                })
                .map(|(peer_id, _)| peer_id.clone());
            peer_id
        };

        let kademlia_operation_id = self.next_kademlia_operation_id;
        self.next_kademlia_operation_id.0 += 1;

        if let Some(queried_peer) = queried_peer {
            debug_assert!(self
                .inner
                .established_peer_connections(&queried_peer)
                .any(|cid| !self.inner.connection_state(cid).shutting_down));

            self.start_kademlia_find_node_inner(
                &queried_peer,
                now,
                chain_index,
                random_peer_id.as_bytes(),
                Some(kademlia_operation_id),
            );
        } else {
            self.pending_kademlia_errors
                .push_back((kademlia_operation_id, DiscoveryError::NoPeer))
        }

        kademlia_operation_id
    }

    /// Sends a Kademlia "find node" request to a single peer, and waits for it to answer.
    ///
    /// Returns an error if there is no active connection with that peer.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    pub fn start_kademlia_find_node(
        &mut self,
        target: &PeerId,
        now: TNow,
        chain_index: usize,
        close_to_key: &[u8],
    ) -> OutRequestId {
        self.start_kademlia_find_node_inner(target, now, chain_index, close_to_key, None)
    }

    fn start_kademlia_find_node_inner(
        &mut self,
        target: &PeerId,
        now: TNow,
        chain_index: usize,
        close_to_key: &[u8],
        part_of_operation: Option<KademliaOperationId>,
    ) -> OutRequestId {
        let request_data = protocol::build_find_node_request(close_to_key);
        // The timeout needs to be long enough to potentially download the maximum
        // response size of 1 MiB. Assuming a 128 kiB/sec connection, that's 8 seconds.
        let timeout = now + Duration::from_secs(8);

        let id = self.inner.start_request(
            target,
            self.protocol_index(chain_index, 2),
            request_data,
            timeout,
        );

        let _prev_value = self.out_requests_types.insert(
            id,
            (
                if let Some(operation_id) = part_of_operation {
                    OutRequestTy::KademliaDiscoveryFindNode(operation_id)
                } else {
                    OutRequestTy::KademliaFindNode
                },
                chain_index,
            ),
        );
        debug_assert!(_prev_value.is_none());

        id
    }

    /// Allocates a [`PendingId`] and returns a [`StartConnect`] indicating a multiaddress that
    /// the API user must try to dial.
    ///
    /// Later, the API user must use [`ChainNetwork::pending_outcome_ok_single_stream`],
    /// [`ChainNetwork::pending_outcome_ok_multi_stream`], or [`ChainNetwork::pending_outcome_err`]
    /// to report how the connection attempt went.
    ///
    /// The returned [`StartConnect`] contains the [`StartConnect::timeout`] field. It is the
    /// responsibility of the API user to ensure that [`ChainNetwork::pending_outcome_err`] is
    /// called if this timeout is reached.
    // TODO: give more control, with number of slots and node choice
    // TODO: this API with now is a bit hacky?
    pub fn next_start_connect(&mut self, now: impl FnOnce() -> TNow) -> Option<StartConnect<TNow>> {
        // Ask the underlying state machine which nodes are desired but don't have any
        // associated connection attempt yet.
        // Since the underlying state machine is only made aware of connections when
        // `pending_outcome_ok` is reached, we must filter out nodes that already have an
        // associated `PendingId`.
        let unfulfilled_desired_peers = self.inner.unfulfilled_desired_peers();

        for peer_id in unfulfilled_desired_peers {
            // TODO: allow more than one simultaneous dial per peer, and distribute the dials so that we don't just return the same peer multiple times in a row while there are other peers waiting
            // TODO: cloning the peer_id :-/
            let entry = match self.num_pending_per_peer.entry(peer_id.clone()) {
                hashbrown::hash_map::Entry::Occupied(_) => continue,
                hashbrown::hash_map::Entry::Vacant(entry) => entry,
            };

            // TODO: O(n)
            let multiaddr: multiaddr::Multiaddr = {
                let potential = self
                    .chains
                    .iter_mut()
                    .flat_map(|chain| chain.kbuckets.iter_mut_ordered())
                    .find(|(p, _)| **p == *entry.key())
                    .and_then(|(peer_id, _)| {
                        self.kbuckets_peers
                            .get_mut(peer_id)
                            .unwrap()
                            .addresses
                            .addr_to_pending()
                    });
                match potential {
                    Some(a) => a.clone(),
                    None => continue,
                }
            };

            let now = now();
            let pending_id = PendingId(self.pending_ids.insert((
                entry.key().clone(),
                multiaddr.clone(),
                now.clone(),
            )));

            let start_connect = StartConnect {
                expected_peer_id: entry.key().clone(),
                id: pending_id,
                multiaddr,
                timeout: now + self.handshake_timeout,
            };

            entry.insert(NonZeroUsize::new(1).unwrap());

            return Some(start_connect);
        }

        // No valid desired peer has been found.
        None
    }

    /// Returns `true` if if it possible to send requests (i.e. through
    /// [`ChainNetwork::start_grandpa_warp_sync_request`],
    /// [`ChainNetwork::start_blocks_request`], etc.) to the given peer.
    ///
    /// If `false` is returned, starting a request will panic.
    ///
    /// In other words, returns `true` if there exists an established connection non-shutting-down
    /// connection with the given peer.
    pub fn can_start_requests(&self, peer_id: &PeerId) -> bool {
        self.inner.can_start_requests(peer_id)
    }

    /// Returns an iterator to the list of [`PeerId`]s that we have an established connection
    /// with.
    pub fn peers_list(&self) -> impl Iterator<Item = &PeerId> {
        self.inner.peers_list()
    }

    // TODO: docs and appropriate naming
    pub fn slots_to_assign(&'_ self, chain_index: usize) -> impl Iterator<Item = &'_ PeerId> + '_ {
        let chain = &self.chains[chain_index];

        // Check if maximum number of slots is reached.
        if chain.out_peers.len()
            >= usize::try_from(chain.chain_config.out_slots).unwrap_or(usize::max_value())
        {
            return either::Right(iter::empty());
        }

        // TODO: return in some specific order?
        either::Left(
            chain
                .kbuckets
                .iter_ordered()
                .map(|(peer_id, _)| peer_id)
                .filter(|peer_id| {
                    // Don't assign slots to peers that already have a slot.
                    !chain.out_peers.contains(peer_id) && !chain.in_peers.contains(peer_id)
                }),
        )
    }

    // TODO: docs
    // TODO: when to call this?
    pub fn assign_out_slot(&mut self, chain_index: usize, peer_id: PeerId) {
        let chain = &mut self.chains[chain_index];

        // Check if maximum number of slots is reached.
        if chain.out_peers.len()
            >= usize::try_from(chain.chain_config.out_slots).unwrap_or(usize::max_value())
        {
            return; // TODO: return error?
        }

        // Don't assign slots to peers that already have a slot.
        if chain.out_peers.contains(&peer_id) || chain.in_peers.contains(&peer_id) {
            return; // TODO: return error?
        }

        self.inner.set_peer_notifications_out_desired(
            &peer_id,
            chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN,
            peers::DesiredState::DesiredReset, // TODO: ?
        );

        chain.out_peers.insert(peer_id);
    }

    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    pub fn respond_identify(&mut self, request_id: InRequestId, agent_version: &str) {
        let observed_addr = match self.in_requests_types.remove(&request_id) {
            Some(InRequestTy::Identify { observed_addr }) => observed_addr,
            _ => panic!(),
        };

        let response = {
            protocol::build_identify_response(protocol::IdentifyResponse {
                protocol_version: "/substrate/1.0", // TODO: same value as in Substrate
                agent_version,
                ed25519_public_key: *self.inner.noise_key().libp2p_public_ed25519_key(),
                listen_addrs: iter::empty(), // TODO:
                observed_addr,
                protocols: self
                    .inner
                    .request_response_protocols()
                    .filter(|p| p.inbound_allowed)
                    .map(|p| &p.name[..])
                    .chain(
                        self.inner
                            .notification_protocols()
                            .map(|p| &p.protocol_name[..]),
                    ),
            })
            .fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            })
        };

        let _ = self.inner.respond_in_request(request_id, Ok(response));
    }

    /// Queue the response to send back.
    ///
    /// Pass `None` in order to deny the request. Do this if blocks aren't available locally.
    ///
    /// Has no effect if the connection that sends the request no longer exists.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    pub fn respond_blocks(
        &mut self,
        request_id: InRequestId,
        response: Option<Vec<protocol::BlockData>>,
    ) {
        match self.in_requests_types.remove(&request_id) {
            Some(InRequestTy::Blocks) => {}
            _ => panic!(),
        };

        let response = if let Some(response) = response {
            Ok(
                protocol::build_block_response(response).fold(Vec::new(), |mut a, b| {
                    a.extend_from_slice(b.as_ref());
                    a
                }),
            )
        } else {
            Err(())
        };

        let _ = self.inner.respond_in_request(request_id, response);
    }

    /// Removes the slot assignment of the given peer, if any.
    pub fn unassign_slot(&mut self, chain_index: usize, peer_id: &PeerId) -> Option<SlotTy> {
        self.inner.set_peer_notifications_out_desired(
            peer_id,
            chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN,
            peers::DesiredState::NotDesired,
        );

        let was_in_out = self.chains[chain_index].out_peers.remove(peer_id);
        let was_in_in = self.chains[chain_index].in_peers.remove(peer_id);

        match (was_in_in, was_in_out) {
            (true, false) => Some(SlotTy::Inbound),
            (false, true) => Some(SlotTy::Outbound),
            (false, false) => None,
            (true, true) => {
                unreachable!()
            }
        }
    }
}

/// User must start connecting to the given multiaddress.
///
/// One of [`ChainNetwork::pending_outcome_ok_single_stream`],
/// [`ChainNetwork::pending_outcome_ok_multi_stream`], or [`ChainNetwork::pending_outcome_err`]
/// must later be called in order to inform of the outcome of the connection.
#[derive(Debug)]
#[must_use]
pub struct StartConnect<TNow> {
    /// Identifier of this connection request. Must be passed back later.
    pub id: PendingId,
    /// Address to attempt to connect to.
    pub multiaddr: multiaddr::Multiaddr,
    /// [`PeerId`] that is expected to be reached with this connection attempt.
    pub expected_peer_id: PeerId,
    /// When the attempt should be considered as a failure. You must call
    /// [`ChainNetwork::pending_outcome_err`] if this moment is reached.
    pub timeout: TNow,
}

/// Event generated by [`ChainNetwork::next_event`].
#[derive(Debug)]
pub enum Event {
    /// Established a transport-level connection (e.g. a TCP socket) with the given peer.
    Connected(PeerId),

    /// A transport-level connection (e.g. a TCP socket) has been closed.
    ///
    /// This event is called unconditionally when a connection with the given peer has been
    /// closed. If `chain_indices` isn't empty, this event is also equivalent to one or more
    /// [`Event::ChainDisconnected`] events.
    Disconnected {
        peer_id: PeerId,
        chain_indices: Vec<usize>,
    },

    ChainConnected {
        chain_index: usize,
        peer_id: PeerId,
        /// Type of the slot that the peer has.
        slot_ty: SlotTy,
        /// Role the node reports playing on the network.
        role: protocol::Role,
        /// Height of the best block according to this node.
        best_number: u64,
        /// Hash of the best block according to this node.
        best_hash: [u8; 32],
    },
    ChainDisconnected {
        peer_id: PeerId,
        chain_index: usize,
        /// Type of the slot that the peer had and no longer has.
        unassigned_slot_ty: SlotTy,
    },

    /// An attempt has been made to open the given chain, but a problem happened.
    ChainConnectAttemptFailed {
        chain_index: usize,
        peer_id: PeerId,
        /// Problem that happened.
        error: NotificationsOutErr,
        /// Type of the slot that the peer had and no longer has.
        unassigned_slot_ty: SlotTy,
    },

    BlocksRequestResult {
        request_id: OutRequestId,
        response: Result<Vec<protocol::BlockData>, BlocksRequestError>,
    },

    GrandpaWarpSyncRequestResult {
        request_id: OutRequestId,
        response: Result<protocol::GrandpaWarpSyncResponse, GrandpaWarpSyncRequestError>,
    },

    StateRequestResult {
        request_id: OutRequestId,
        response: Result<EncodedStateResponse, StateRequestError>,
    },

    StorageProofRequestResult {
        request_id: OutRequestId,
        response: Result<EncodedMerkleProof, StorageProofRequestError>,
    },

    CallProofRequestResult {
        request_id: OutRequestId,
        response: Result<EncodedMerkleProof, CallProofRequestError>,
    },

    KademliaFindNodeRequestResult {
        request_id: OutRequestId,
        response: Result<Vec<(peer_id::PeerId, Vec<multiaddr::Multiaddr>)>, KademliaFindNodeError>,
    },

    /// The given peer has opened a block announces substream with the local node, and an inbound
    /// slot has been assigned locally to this peer.
    ///
    /// A [`Event::ChainConnected`] or [`Event::ChainConnectAttemptFailed`] will later be
    /// generated for this peer.
    InboundSlotAssigned {
        chain_index: usize,
        peer_id: PeerId,
    },

    /// Received a new block announce from a peer.
    ///
    /// Can only happen after a [`Event::ChainConnected`] with the given `PeerId` and chain index
    /// combination has happened.
    BlockAnnounce {
        /// Identity of the sender of the block announce.
        peer_id: PeerId,
        /// Index of the chain the block relates to.
        chain_index: usize,
        announce: EncodedBlockAnnounce,
    },

    /// Received a GrandPa commit message from the network.
    GrandpaCommitMessage {
        /// Identity of the sender of the message.
        peer_id: PeerId,
        /// Index of the chain the commit message relates to.
        chain_index: usize,
        message: EncodedGrandpaCommitMessage,
    },

    /// Error in the protocol in a connection, such as failure to decode a message. This event
    /// doesn't have any consequence on the health of the connection, and is purely for diagnostic
    /// purposes.
    ProtocolError {
        /// Peer that has caused the protocol error.
        peer_id: PeerId,
        /// Error that happened.
        error: ProtocolError,
    },

    /// A remote has sent a request for identification information.
    ///
    /// You are strongly encouraged to call [`ChainNetwork::respond_identify`].
    IdentifyRequestIn {
        /// Remote that has sent the request.
        peer_id: PeerId,
        /// Identifier of the request. Necessary to send back the answer.
        request_id: InRequestId,
    },
    /// A remote has sent a request for blocks.
    ///
    /// Can only happen for chains where [`ChainConfig::allow_inbound_block_requests`] is `true`.
    ///
    /// You are strongly encouraged to call [`ChainNetwork::respond_blocks`].
    BlocksRequestIn {
        /// Remote that has sent the request.
        peer_id: PeerId,
        /// Index of the chain concerned by the request.
        chain_index: usize,
        /// Information about the request.
        config: protocol::BlocksRequestConfig,
        /// Identifier of the request. Necessary to send back the answer.
        request_id: InRequestId,
    },

    RequestInCancel {
        request_id: InRequestId,
    },

    KademliaDiscoveryResult {
        operation_id: KademliaOperationId,
        result: Result<Vec<(PeerId, Vec<multiaddr::Multiaddr>)>, DiscoveryError>,
    },
    /*Transactions {
        peer_id: PeerId,
        transactions: EncodedTransactions,
    }*/
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SlotTy {
    Inbound,
    Outbound,
}

/// Error that can happen when trying to open an outbound notifications substream.
#[derive(Debug, Clone, derive_more::Display)]
pub enum NotificationsOutErr {
    /// Error in the underlying protocol.
    #[display(fmt = "{}", _0)]
    Substream(peers::NotificationsOutErr),
    /// Mismatch between the genesis hash of the remote and the local genesis hash.
    #[display(fmt = "Mismatch between the genesis hash of the remote and the local genesis hash")]
    GenesisMismatch {
        /// Hash of the genesis block of the chain according to the local node.
        local_genesis: [u8; 32],
        /// Hash of the genesis block of the chain according to the remote node.
        remote_genesis: [u8; 32],
    },
}

/// Undecoded but valid block announce handshake.
pub struct EncodedBlockAnnounceHandshake {
    handshake: Vec<u8>,
    block_number_bytes: usize,
}

impl EncodedBlockAnnounceHandshake {
    /// Returns the decoded version of the handshake.
    pub fn decode(&self) -> protocol::BlockAnnouncesHandshakeRef {
        protocol::decode_block_announces_handshake(self.block_number_bytes, &self.handshake)
            .unwrap()
    }
}

impl fmt::Debug for EncodedBlockAnnounceHandshake {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.decode(), f)
    }
}

/// Undecoded but valid block announce.
#[derive(Clone)]
pub struct EncodedBlockAnnounce {
    message: Vec<u8>,
    block_number_bytes: usize,
}

impl EncodedBlockAnnounce {
    /// Returns the decoded version of the announcement.
    pub fn decode(&self) -> protocol::BlockAnnounceRef {
        protocol::decode_block_announce(&self.message, self.block_number_bytes).unwrap()
    }
}

impl fmt::Debug for EncodedBlockAnnounce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.decode(), f)
    }
}

/// Undecoded but valid Merkle proof.
#[derive(Clone)]
pub struct EncodedMerkleProof(Vec<u8>, protocol::StorageOrCallProof);

impl EncodedMerkleProof {
    /// Returns the decoded version of the proof.
    pub fn decode(&self) -> Vec<&[u8]> {
        protocol::decode_storage_or_call_proof_response(self.1, &self.0).unwrap()
    }
}

impl fmt::Debug for EncodedMerkleProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.decode(), f)
    }
}

/// Undecoded but valid GrandPa commit message.
#[derive(Clone)]
pub struct EncodedGrandpaCommitMessage {
    message: Vec<u8>,
    block_number_bytes: usize,
}

impl EncodedGrandpaCommitMessage {
    /// Returns the encoded bytes of the commit message.
    pub fn into_encoded(mut self) -> Vec<u8> {
        // Skip the first byte because `self.message` is a `GrandpaNotificationRef`.
        self.message.remove(0);
        self.message
    }

    /// Returns the encoded bytes of the commit message.
    pub fn as_encoded(&self) -> &[u8] {
        // Skip the first byte because `self.message` is a `GrandpaNotificationRef`.
        &self.message[1..]
    }

    /// Returns the decoded version of the commit message.
    pub fn decode(&self) -> protocol::CommitMessageRef {
        match protocol::decode_grandpa_notification(&self.message, self.block_number_bytes) {
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

/// Undecoded but valid state response.
#[derive(Clone)]
pub struct EncodedStateResponse(Vec<u8>);

impl EncodedStateResponse {
    /// Returns the decoded version of the state response.
    pub fn decode(&self) -> Vec<protocol::StateResponseEntry> {
        match protocol::decode_state_response(&self.0) {
            Ok(r) => r,
            Err(_) => unreachable!(),
        }
    }
}

impl fmt::Debug for EncodedStateResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.decode(), f)
    }
}

/// Error during [`ChainNetwork::start_kademlia_discovery_round`].
#[derive(Debug, derive_more::Display)]
pub enum DiscoveryError {
    /// Not currently connected to any other node.
    NoPeer,
    /// Error during the request.
    #[display(fmt = "{}", _0)]
    FindNode(KademliaFindNodeError),
}

/// Error during [`ChainNetwork::start_kademlia_find_node`].
#[derive(Debug, derive_more::Display)]
pub enum KademliaFindNodeError {
    /// Error during the request.
    #[display(fmt = "{}", _0)]
    RequestFailed(peers::RequestError),
    /// Failed to decode the response.
    #[display(fmt = "Response decoding error: {}", _0)]
    DecodeError(protocol::DecodeFindNodeResponseError),
}

/// Error returned by [`ChainNetwork::start_blocks_request`].
#[derive(Debug, derive_more::Display)]
pub enum BlocksRequestError {
    /// Error while waiting for the response from the peer.
    #[display(fmt = "{}", _0)]
    Request(peers::RequestError),
    /// Error while decoding the response returned by the peer.
    #[display(fmt = "Response decoding error: {}", _0)]
    Decode(protocol::DecodeBlockResponseError),
    /// Block request doesn't request headers, and as such its validity cannot be verified.
    NotVerifiable,
    /// Response returned by the remote doesn't contain any entry.
    EmptyResponse,
    /// Start of the response doesn't correspond to the requested start.
    InvalidStart,
    /// Error at a specific index in the response.
    #[display(fmt = "Error in response at offset {}: {}", index, error)]
    Entry {
        /// Index in the response where the problem happened.
        index: usize,
        /// Problem in question.
        error: BlocksRequestResponseEntryError,
    },
}

/// See [`BlocksRequestError`].
#[derive(Debug, derive_more::Display)]
pub enum BlocksRequestResponseEntryError {
    /// One of the requested fields is missing from the block.
    MissingField,
    /// The header has an extrinsics root that doesn't match the body. Can only happen if both the
    /// header and body were requested.
    #[display(fmt = "The header has an extrinsics root that doesn't match the body")]
    InvalidExtrinsicsRoot {
        /// Extrinsics root that was calculated from the body.
        calculated: [u8; 32],
        /// Extrinsics root found in the header.
        in_header: [u8; 32],
    },
    /// The header has an invalid format.
    InvalidHeader,
    /// The hash of the header doesn't match the hash provided by the remote.
    InvalidHash,
}

/// Error returned by [`ChainNetwork::start_storage_proof_request`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum StorageProofRequestError {
    #[display(fmt = "{}", _0)]
    Request(peers::RequestError),
    #[display(fmt = "Response decoding error: {}", _0)]
    Decode(protocol::DecodeStorageCallProofResponseError),
}

/// Error returned by [`ChainNetwork::start_call_proof_request`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum CallProofRequestError {
    #[display(fmt = "{}", _0)]
    Request(peers::RequestError),
    #[display(fmt = "Response decoding error: {}", _0)]
    Decode(protocol::DecodeStorageCallProofResponseError),
}

impl CallProofRequestError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    pub fn is_network_problem(&self) -> bool {
        match self {
            CallProofRequestError::Request(_) => true,
            CallProofRequestError::Decode(_) => false,
        }
    }
}

/// Error returned by [`ChainNetwork::start_grandpa_warp_sync_request`].
#[derive(Debug, derive_more::Display)]
pub enum GrandpaWarpSyncRequestError {
    #[display(fmt = "{}", _0)]
    Request(peers::RequestError),
    #[display(fmt = "Response decoding error: {}", _0)]
    Decode(protocol::DecodeGrandpaWarpSyncResponseError),
}

/// Error returned by [`ChainNetwork::start_state_request_unchecked`].
#[derive(Debug, derive_more::Display)]
pub enum StateRequestError {
    #[display(fmt = "{}", _0)]
    Request(peers::RequestError),
    #[display(fmt = "Response decoding error: {}", _0)]
    Decode(protocol::DecodeStateResponseError),
}

/// See [`Event::ProtocolError`].
#[derive(Debug, derive_more::Display)]
pub enum ProtocolError {
    /// Error in an incoming substream.
    #[display(fmt = "Error in an incoming substream: {}", _0)]
    InboundError(InboundError),
    /// Error while decoding the handshake of the block announces substream.
    #[display(
        fmt = "Error while decoding the handshake of the block announces substream: {}",
        _0
    )]
    BadBlockAnnouncesHandshake(protocol::BlockAnnouncesHandshakeDecodeError),
    /// Error while decoding a received block announce.
    #[display(fmt = "Error while decoding a received block announce: {}", _0)]
    BadBlockAnnounce(protocol::DecodeBlockAnnounceError),
    /// Error while decoding a received Grandpa notification.
    #[display(fmt = "Error while decoding a received Grandpa notification: {}", _0)]
    BadGrandpaNotification(protocol::DecodeGrandpaNotificationError),
    /// Received an invalid identify request.
    BadIdentifyRequest,
    /// Error while decoding a received blocks request.
    #[display(fmt = "Error while decoding a received blocks request: {}", _0)]
    BadBlocksRequest(protocol::DecodeBlockRequestError),
}

fn check_blocks_response(
    block_number_bytes: usize,
    config: protocol::BlocksRequestConfig,
    result: &mut [protocol::BlockData],
) -> Result<(), BlocksRequestError> {
    if !config.fields.header {
        return Err(BlocksRequestError::NotVerifiable);
    }

    if result.is_empty() {
        return Err(BlocksRequestError::EmptyResponse);
    }

    // Verify validity of all the blocks.
    for (block_index, block) in result.iter_mut().enumerate() {
        if block.header.is_none() {
            return Err(BlocksRequestError::Entry {
                index: block_index,
                error: BlocksRequestResponseEntryError::MissingField,
            });
        }

        if block
            .header
            .as_ref()
            .map_or(false, |h| header::decode(h, block_number_bytes).is_err())
        {
            return Err(BlocksRequestError::Entry {
                index: block_index,
                error: BlocksRequestResponseEntryError::InvalidHeader,
            });
        }

        match (block.body.is_some(), config.fields.body) {
            (false, true) => {
                return Err(BlocksRequestError::Entry {
                    index: block_index,
                    error: BlocksRequestResponseEntryError::MissingField,
                });
            }
            (true, false) => {
                block.body = None;
            }
            _ => {}
        }

        // Note: the presence of a justification isn't checked and can't be checked, as not
        // all blocks have a justification in the first place.

        if block.header.as_ref().map_or(false, |h| {
            header::hash_from_scale_encoded_header(&h) != block.hash
        }) {
            return Err(BlocksRequestError::Entry {
                index: block_index,
                error: BlocksRequestResponseEntryError::InvalidHash,
            });
        }

        if let (Some(header), Some(body)) = (&block.header, &block.body) {
            let decoded_header = header::decode(header, block_number_bytes).unwrap();
            let expected = header::extrinsics_root(&body[..]);
            if expected != *decoded_header.extrinsics_root {
                return Err(BlocksRequestError::Entry {
                    index: block_index,
                    error: BlocksRequestResponseEntryError::InvalidExtrinsicsRoot {
                        calculated: expected,
                        in_header: *decoded_header.extrinsics_root,
                    },
                });
            }
        }
    }

    match config.start {
        protocol::BlocksRequestConfigStart::Hash(hash) if result[0].hash != hash => {
            return Err(BlocksRequestError::InvalidStart);
        }
        protocol::BlocksRequestConfigStart::Number(n)
            if header::decode(result[0].header.as_ref().unwrap(), block_number_bytes)
                .unwrap()
                .number
                != n =>
        {
            return Err(BlocksRequestError::InvalidStart)
        }
        _ => {}
    }

    Ok(())
}
