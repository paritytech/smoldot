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
    self, connection, discovery::kademlia, multiaddr, peer_id, PeerId, QueueNotificationError,
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
    task::{Poll, Waker},
    time::Duration,
};
use futures::{lock::Mutex, prelude::*};
use rand::{Rng as _, RngCore as _, SeedableRng as _};

/// Identifier of a pending connection requested by the network through a [`StartConnect`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingId(usize);

/// Identifier of a connection spawned by the [`ChainNetwork`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(usize);

pub struct Peerset {
    /// Mapping of index within [`Peerset::peers`] by network identity.
    ///
    /// Because the `PeerId`s are "untrusted input", a randomized hasher is used to avoid
    /// potential hashmap collision attacks.
    peers_by_id: hashbrown::HashMap<PeerId, usize, ahash::RandomState>,

    /// List of all members of the peer-to-peer network that are known.
    peers: slab::Slab<Peer>,

    /// Collection of (`peer_index`, `connection_index`), where `peer_index` and
    /// `connection_index` are respectively the index of a peer in [`Peerset::peers`] and the
    /// index of a connection in [`Peerset::connections`].
    peers_connections: BTreeSet<(usize, usize)>,

    /// Collection of (`chain_index`, `peer_index`).
    // TODO: more doc
    peers_chain_memberships: BTreeSet<(usize, usize)>,

    /// Collection of `(peer_index, chain_index)`.
    peers_open_chains: BTreeSet<(usize, usize)>,

    /// Collection of `(peer_index, overlay_network_index)`.
    peers_missing_out_substreams: BTreeSet<(usize, usize)>,

    /// All connections, both pending and established.
    ///
    /// This list is a superset of the list in [`ChainNetwork::libp2p`].
    connections: slab::Slab<Connection>,
}

impl Peerset {
    pub fn new() -> Self {
        let mut randomness = rand_chacha::ChaCha20Rng::from_seed(config.randomness_seed);

        let mut peers_by_id = {
            let k0 = randomness.next_u64();
            let k1 = randomness.next_u64();
            let k2 = randomness.next_u64();
            let k3 = randomness.next_u64();
            hashbrown::HashMap::with_capacity_and_hasher(
                config.peers_capacity,
                ahash::RandomState::with_seeds(k0, k1, k2, k3),
            )
        };

        let mut peers = slab::Slab::with_capacity(config.peers_capacity);
        let mut peers_chain_memberships = BTreeSet::new();

        for (peer_id, multiaddr) in config.known_nodes {
            let peer_index = match peers_by_id.entry(peer_id) {
                hashbrown::hash_map::Entry::Occupied(entry) => *entry.get(),
                hashbrown::hash_map::Entry::Vacant(entry) => {
                    let known_addresses = {
                        let k0 = randomness.next_u64();
                        let k1 = randomness.next_u64();
                        let k2 = randomness.next_u64();
                        let k3 = randomness.next_u64();
                        hashbrown::HashMap::with_capacity_and_hasher(
                            0,
                            ahash::RandomState::with_seeds(k0, k1, k2, k3),
                        )
                    };

                    let peer_index = peers.insert(Peer {
                        peer_id: entry.key().clone(),
                        known_addresses,
                    });

                    // Register membership of this peer on this chain.
                    for chain_index in 0..config.chains.len() {
                        peers_chain_memberships.insert((chain_index, peer_index));
                    }

                    entry.insert(peer_index);
                    peer_index
                }
            };

            peers[peer_index]
                .known_addresses
                .entry(multiaddr)
                .or_insert(None);
        }

        Peerset {
            peers,
            peers_by_id,
            peers_connections: BTreeSet::new(),
            peers_open_chains: BTreeSet::new(),
            peers_missing_out_substreams: BTreeSet::new(),
            peers_chain_memberships,
            connections: slab::Slab::with_capacity(config.connections_capacity),
        }
    }

    /// Adds an incoming connection to the state machine.
    ///
    /// This connection hasn't finished handshaking and the [`PeerId`] of the remote isn't known
    /// yet.
    #[must_use]
    pub async fn add_incoming_connection(
        &mut self,
        local_listen_address: &multiaddr::Multiaddr,
        remote_addr: multiaddr::Multiaddr,
    ) -> ConnectionId {
        let local_connections_entry = self.connections.vacant_entry();

        let inner_id = self
            .libp2p
            .insert(false, local_connections_entry.key())
            .await;

        local_connections_entry.insert(Connection {
            address: remote_addr,
            peer_id: todo!(), // TODO: `None` or something
            reached: Some(ConnectionReached { inner_id }),
        });

        ConnectionId(inner_id)
    }

    /// Returns the "main" established connection with a certain peer.
    ///
    /// Returns `None` if this [`PeerId`] is unknown, or if there isn't any active connection
    /// with it.
    pub fn peer_main_established(&self, peer_id: &PeerId) -> Option<libp2p::ConnectionId> {
        let peer_index = *self.peers_by_id.get(peer_id)?;

        let inner_id = self
            .peers_connections
            .range((peer_index, usize::min_value())..=(peer_index, usize::max_value()))
            .filter_map(|(_, connection_index)| {
                self.connections
                    .get(*connection_index)
                    .unwrap()
                    .reached
                    .as_ref()
            })
            .next()?
            .inner_id;

        Some(inner_id)
    }

    pub fn notifications_in_state(&mut self, connection_id: ConnectionId) {

    }

    pub fn notifications_out_state(&mut self, connection_id: ConnectionId) {

    }
}

/// See [`Peerset::peers`].
struct Peer {
    /// Identity of this peer.
    peer_id: PeerId,

    /// List of addresses that we assume could be dialed to reach the peer.
    ///
    /// If the value is `Some`, a connection using that address can be found at the given index
    /// in [`Peerset::connections`].
    ///
    /// Does not include "dialing" addresses. For example, no address should contain an outgoing
    /// TCP port.
    known_addresses: hashbrown::HashMap<multiaddr::Multiaddr, Option<usize>, ahash::RandomState>,
}

/// See [`Peerset::connections`].
struct Connection {
    /// [`PeerId`] of the remote, or *expected* [`PeerId`] (which might end up being different
    /// from the actual) if the handshake isn't finished yet.
    peer_id: PeerId,

    /// Address on the other side of the connection.
    ///
    /// Will be found in [`Peer::known_addresses`] if and only if the connection is outbound.
    address: multiaddr::Multiaddr,

    /// `Some` if the connection with the remote has been reached. Contains extra fields.
    reached: Option<ConnectionReached>,
}

/// See [`Connection::reached`].
struct ConnectionReached {
    /// Identifier of this connection according to [`ChainNetwork::libp2p`].
    ///
    /// Since [`libp2p::ConnectionId`] are never re-used, .
    inner_id: libp2p::ConnectionId,
}
