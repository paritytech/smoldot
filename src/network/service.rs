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

use crate::libp2p::{connection, multiaddr, peer_id, peers, PeerId};
use crate::network::{kademlia, protocol};
use crate::util::SipHasherBuild;

use alloc::{
    collections::VecDeque,
    format,
    string::{String, ToString as _},
    vec::Vec,
};
use core::{
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
mod notifications;
mod requests_responses;

pub use notifications::{
    EncodedBlockAnnounce, EncodedBlockAnnounceHandshake, EncodedGrandpaCommitMessage, GrandpaState,
    NotificationsOutErr,
};

pub use requests_responses::{
    BlocksRequestError, BlocksRequestResponseEntryError, CallProofRequestError, DiscoveryError,
    EncodedGrandpaWarpSyncResponse, EncodedMerkleProof, EncodedStateResponse,
    GrandpaWarpSyncRequestError, KademliaFindNodeError, KademliaOperationId, RequestResult,
    StateRequestError, StorageProofRequestError,
};

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

/// Identifier of a pending connection requested by the network through a [`StartConnect`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingId(usize);

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

// Update this when a new notifications protocol is added.
const NOTIFICATIONS_PROTOCOLS_PER_CHAIN: usize = 3;

impl<TNow> ChainNetwork<TNow>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Initializes a new [`ChainNetwork`].
    pub fn new(config: Config<TNow>) -> Self {
        let notification_protocols = notifications::protocols(config.chains.iter());
        let request_response_protocols = requests_responses::protocols(config.chains.iter());

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
            * (1 + requests_responses::REQUEST_RESPONSE_PROTOCOLS_PER_CHAIN
                + NOTIFICATIONS_PROTOCOLS_PER_CHAIN)
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
        1 + chain_index * requests_responses::REQUEST_RESPONSE_PROTOCOLS_PER_CHAIN + protocol
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

    /// Adds a multi-stream incoming connection to the state machine.
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
    pub fn add_multi_stream_incoming_connection<TSubId>(
        &mut self,
        when_connected: TNow,
        handshake_kind: MultiStreamHandshakeKind,
        remote_addr: multiaddr::Multiaddr,
    ) -> (ConnectionId, MultiStreamConnectionTask<TNow, TSubId>)
    where
        TSubId: Clone + PartialEq + Eq + Hash,
    {
        self.inner
            .add_multi_stream_incoming_connection(when_connected, handshake_kind, remote_addr)
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
    /// `is_bad_address` should be `true` if the address is invalid or definitely unreachable and
    /// should thus not be attempted again. If `false` is passed, the address might be attempted
    /// again.
    ///
    /// # Panic
    ///
    /// Panics if the [`PendingId`] is invalid.
    ///
    pub fn pending_outcome_err(&mut self, id: PendingId, is_bad_address: bool) {
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
            if is_bad_address {
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
                                // TODO: refactor to directly call on_notifications_out_close, making the code more readable
                                break Some(peers::Event::NotificationsOutClose {
                                    notifications_protocol_index,
                                    peer_id,
                                });
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

                // Incoming requests.
                peers::Event::RequestIn {
                    peer_id,
                    connection_id,
                    request_id,
                    protocol_index,
                    request_payload,
                    ..
                } => {
                    break Some(self.on_request_in(
                        request_id,
                        peer_id,
                        connection_id,
                        protocol_index,
                        request_payload,
                    ))
                }

                // Remote is no longer interested in the response.
                peers::Event::RequestInCancel { id, .. } => {
                    break Some(self.on_request_in_cancel(id))
                }

                peers::Event::NotificationsOutResult {
                    peer_id,
                    notifications_protocol_index,
                    result,
                } => {
                    if let Some(event) = self.on_notifications_out_result(
                        &now,
                        peer_id,
                        notifications_protocol_index,
                        result,
                    ) {
                        return Some(event);
                    }
                }

                peers::Event::Response {
                    request_id,
                    response,
                } => break Some(self.on_response(request_id, response)),

                peers::Event::NotificationsOutClose {
                    notifications_protocol_index,
                    peer_id,
                } => {
                    if let Some(event) =
                        self.on_notifications_out_close(&now, peer_id, notifications_protocol_index)
                    {
                        return Some(event);
                    }
                }

                peers::Event::NotificationsInClose {
                    peer_id,
                    notifications_protocol_index,
                    ..
                } => {
                    if let Some(event) =
                        self.on_notifications_in_close(peer_id, notifications_protocol_index)
                    {
                        return Some(event);
                    }
                }

                peers::Event::NotificationsIn {
                    notifications_protocol_index,
                    peer_id,
                    notification,
                } => {
                    if let Some(event) =
                        self.on_notification_in(peer_id, notifications_protocol_index, notification)
                    {
                        break Some(event);
                    }
                }

                peers::Event::NotificationsInOpen {
                    peer_id,
                    handshake,
                    id,
                    notifications_protocol_index,
                } => {
                    if let Some(event) = self.on_notifications_in_open(
                        id,
                        peer_id,
                        notifications_protocol_index,
                        handshake,
                    ) {
                        break Some(event);
                    }
                }

                peers::Event::NotificationsInOpenCancel { id } => {
                    if let Some(event) = self.on_notifications_in_open_cancel(id) {
                        break Some(event);
                    }
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
                    !chain.out_peers.contains(*peer_id) && !chain.in_peers.contains(*peer_id)
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

    RequestResult {
        request_id: OutRequestId,
        response: RequestResult,
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
