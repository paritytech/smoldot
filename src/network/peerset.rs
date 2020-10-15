// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Data structure storing a networking state. Helper for managing connectivity to overlay
//! networks.
//!
//! The [`Peerset`] is a data structure that holds a list of node identities ([`PeerId`]s) and a
//! list of overlay networks. Each [`PeerId`] is associated with:
//!
//! - A list of active inbound connections.
//! - A list of [`Multiaddr`]s onto which the node is believed to be reachable.
//!   - For each multiaddr, optionally an active connection or pending dialing attempt.
//! - A list of overlay networks the node is believed to belong to.
//!   - For each overlay network the node belongs to, TODO
//!
//! > **Note**: The [`Peerset`] does *do* anything by itself, such as opening new connections. It
//! >           is purely a data structure that helps organize and maintain information about the
//! >           network.
//!
//! # Usage
//!
//! The [`Peerset`] must be initialized with a list of overlay networks the node is interested in.
//!
//! It is assumed that some discovery mechanism, not covered by this module, is in place in order
//! to discover the identities and addresses of nodes that belong to these various overlay
//! networks.
//! When this discovery mechanism discovers a node that is part of an overlay network, insert it
//! in the [`Peerset`] by calling [`Peerset::insert`].
//!

// TODO: finish documentation

use crate::network::libp2p::peer_id::PeerId;

use ahash::RandomState;
use alloc::collections::BTreeSet;
use hashbrown::HashMap;
use parity_multiaddr::Multiaddr;

/// Configuration for a [`Peerset`].
#[derive(Debug)]
pub struct Config {
    /// Capacity to reserve for containers having a number of peers.
    pub peers_capacity: usize,

    /// Number of overlay networks managed by the [`Peerset`]. The overlay networks are numbered
    /// from 0 to this value excluded.
    pub num_overlay_networks: usize,

    /// Seed for the randomness used to decide how peers are chosen.
    pub randomness_seed: [u8; 32],
}

/// See the [module-level documentation](self).
pub struct Peerset<TPeer, TConn, TPending> {
    /// Same as [`Config::num_overlay_networks`].
    num_overlay_networks: usize,

    peer_ids: HashMap<PeerId, usize, RandomState>,

    peers: slab::Slab<Peer<TPeer>>,

    pending: slab::Slab<Connection<TPending>>,

    connections: slab::Slab<Connection<TConn>>,

    /// Container that holds tuples of `(peer_index, connection_index)`. Contains the combinations
    /// of connections associated to a certain peer.
    peer_connections: BTreeSet<(usize, usize)>,

    /// Container that holds tuples of `(overlay_index, peer_index)`.
    /// Contains combinations where the peer belongs to the overlay network.
    overlay_peers: BTreeSet<(usize, usize)>,

    /// Container that holds tuples of `(peer_index, overlay_index)`.
    /// Contains combinations where the peer belongs to the overlay network.
    peers_overlays: BTreeSet<(usize, usize)>,

    /// Container that holds tuples of `(overlay_index, peer_index)` where `overlay_index` is an
    /// index in [`Peerset::overlay_networks`] and `peer_index` is an index in [`Peerset::peers`].
    /// Only contains combinations where the peer belongs to the overlay network and is connected
    /// to the local node through this overlay network.
    overlay_peers_connected: BTreeSet<(usize, usize)>,

    /// Container that holds tuples of `(overlay_index, peer_index)` where `overlay_index` is an
    /// index in [`Peerset::overlay_networks`] and `peer_index` is an index in [`Peerset::peers`].
    /// Only contains combinations where the peer belongs to the overlay network but is not
    /// connected to the local node through this overlay network.
    overlay_peers_disconnected: BTreeSet<(usize, usize)>,
}

struct Peer<TPeer> {
    peer_id: PeerId,
    user_data: TPeer,
    addresses: Vec<Multiaddr>,
    connected: bool,
}

struct Connection<TConn> {
    peer_index: usize,
    user_data: TConn,
    inbound: bool,
}

impl<TPeer, TConn, TPending> Peerset<TPeer, TConn, TPending> {
    /// Creates a [`Peerset`] with the given configuration.
    pub fn new(config: Config) -> Self {
        Peerset {
            num_overlay_networks: config.num_overlay_networks,
            // TODO: randomness seed
            peer_ids: HashMap::with_capacity_and_hasher(config.peers_capacity, Default::default()),
            peers: slab::Slab::with_capacity(config.peers_capacity),
            pending: slab::Slab::with_capacity(config.peers_capacity * 2), // TODO: correct capacity?
            connections: slab::Slab::with_capacity(config.peers_capacity * 2),
            peer_connections: BTreeSet::new(),
            overlay_peers: BTreeSet::new(),
            peers_overlays: BTreeSet::new(),
            overlay_peers_connected: BTreeSet::new(),
            overlay_peers_disconnected: BTreeSet::new(),
        }
    }

    /// Returns the list of nodes that belong to the given overlay network.
    ///
    /// # Panic
    ///
    /// Panics if `overlay_network_index` is out of range.
    ///
    pub fn overlay_network_nodes(
        &self,
        overlay_network_index: usize,
    ) -> impl Iterator<Item = &PeerId> {
        assert!(overlay_network_index < self.num_overlay_networks);
        self.overlay_peers
            .range((overlay_network_index, 0)..=(overlay_network_index, usize::max_value()))
            .map(move |(_, id)| &self.peers[*id].peer_id)
    }

    /// Gives access to a pending connection within the [`Peerset`].
    pub fn pending_mut(&mut self, id: PendingId) -> Option<PendingMut<TPeer, TConn, TPending>> {
        if self.pending.contains(id.0) {
            Some(PendingMut { peerset: self, id })
        } else {
            None
        }
    }

    /// Gives access to a connection within the [`Peerset`].
    pub fn connection_mut(
        &mut self,
        id: ConnectionId,
    ) -> Option<ConnectionMut<TPeer, TConn, TPending>> {
        if self.connections.contains(id.0) {
            Some(ConnectionMut { peerset: self, id })
        } else {
            None
        }
    }

    /// Gives access to the state of the node with the given identity.
    pub fn node_mut(&mut self, peer_id: PeerId) -> NodeMut<TPeer, TConn, TPending> {
        if let Some(peer_index) = self.peer_ids.get(&peer_id).cloned() {
            NodeMut::Known(NodeMutKnown {
                peerset: self,
                peer_index,
            })
        } else {
            NodeMut::Unknown(NodeMutUnknown {
                peerset: self,
                peer_id,
            })
        }
    }
}

/// Identifier for a connection in a [`Peerset`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(usize);

/// Access to a connection in the [`Peerset`].
pub struct ConnectionMut<'a, TPeer, TConn, TPending> {
    peerset: &'a mut Peerset<TPeer, TConn, TPending>,
    id: ConnectionId,
}

impl<'a, TPeer, TConn, TPending> ConnectionMut<'a, TPeer, TConn, TPending> {
    /// [`PeerId`] the connection is connected to.
    pub fn peer_id(&self) -> &PeerId {
        let index = self.peerset.connections[self.id.0].peer_index;
        &self.peerset.peers[index].peer_id
    }

    /// Returns true if the connection is inbound.
    pub fn is_inbound(&self) -> bool {
        self.peerset.connections[self.id.0].inbound
    }

    /// Gives access to the user data associated with the connection.
    pub fn user_data_mut(&mut self) -> &mut TConn {
        &mut self.peerset.connections[self.id.0].user_data
    }

    /// Gives access to the user data associated with the connection.
    pub fn into_user_data(self) -> &'a mut TConn {
        &mut self.peerset.connections[self.id.0].user_data
    }

    /// Removes the connection from the data structure.
    pub fn remove(self) -> TConn {
        let connection = self.peerset.connections.remove(self.id.0);
        let _was_in = self
            .peerset
            .peer_connections
            .remove(&(connection.peer_index, self.id.0));
        debug_assert!(_was_in);
        connection.user_data
    }
}

/// Identifier for a pending connection in a [`Peerset`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PendingId(usize);

/// Access to a connection in the [`Peerset`].
pub struct PendingMut<'a, TPeer, TConn, TPending> {
    peerset: &'a mut Peerset<TPeer, TConn, TPending>,
    id: PendingId,
}

impl<'a, TPeer, TConn, TPending> PendingMut<'a, TPeer, TConn, TPending> {
    /// [`PeerId`] the connection is trying to connected to.
    pub fn peer_id(&self) -> &PeerId {
        let index = self.peerset.pending[self.id.0].peer_index;
        &self.peerset.peers[index].peer_id
    }

    /// Gives access to the user data associated with the connection.
    pub fn user_data_mut(&mut self) -> &mut TPending {
        &mut self.peerset.pending[self.id.0].user_data
    }

    /// Gives access to the user data associated with the connection.
    pub fn into_user_data(self) -> &'a mut TPending {
        &mut self.peerset.pending[self.id.0].user_data
    }

    /// Removes the pending connection from the data structure.
    pub fn remove(self) -> TPending {
        // TODO: remove from everywhere?
        self.peerset.pending.remove(self.id.0).user_data
    }
}

/// Access to a node in the [`PeerSet`].
pub enum NodeMut<'a, TPeer, TConn, TPending> {
    /// Node is already known to the data structure.
    Known(NodeMutKnown<'a, TPeer, TConn, TPending>),
    /// Node isn't known by the data structure.
    Unknown(NodeMutUnknown<'a, TPeer, TConn, TPending>),
}

impl<'a, TPeer, TConn, TPending> NodeMut<'a, TPeer, TConn, TPending> {
    /// If [`NodeMut::Unknown`], calls the passed closure in order to obtain a user data and
    /// inserts the node in the data structure.
    pub fn or_insert_with(
        self,
        insert: impl FnOnce() -> TPeer,
    ) -> NodeMutKnown<'a, TPeer, TConn, TPending> {
        match self {
            NodeMut::Known(k) => k,
            NodeMut::Unknown(k) => k.insert(insert()),
        }
    }

    /// Shortcut for `or_insert_with(Default::default)`.
    pub fn or_default(self) -> NodeMutKnown<'a, TPeer, TConn, TPending>
    where
        TPeer: Default,
    {
        self.or_insert_with(Default::default)
    }
}

/// Access to a node is already known to the data structure.
pub struct NodeMutKnown<'a, TPeer, TConn, TPending> {
    peerset: &'a mut Peerset<TPeer, TConn, TPending>,
    peer_index: usize,
}

impl<'a, TPeer, TConn, TPending> NodeMutKnown<'a, TPeer, TConn, TPending> {
    /// Adds in the data structure an inbound connection with this node.
    pub fn add_inbound_connection(&mut self, connection: TConn) -> ConnectionId {
        let index = self.peerset.connections.insert(Connection {
            peer_index: self.peer_index,
            user_data: connection,
            inbound: true,
        });

        let _newly_inserted = self
            .peerset
            .peer_connections
            .insert((self.peer_index, index));
        debug_assert!(_newly_inserted);

        ConnectionId(index)
    }

    /// Adds an address to the list of addresses the node is reachable through.
    ///
    /// Has no effect if this address is already in the list.
    pub fn add_known_address(&mut self, address: Multiaddr) {
        let list = &mut self.peerset.peers[self.peer_index].addresses;
        if list.iter().any(|a| *a == address) {
            return;
        }

        list.push(address);
    }

    /// Adds the node to an overlay network.
    ///
    /// Has no effect if this node is already in this overlay network.
    ///
    /// # Panic
    ///
    /// Panics if `overlay_network_index` is out of range.
    ///
    pub fn add_to_overlay(&mut self, overlay_network_index: usize) {
        assert!(overlay_network_index < self.peerset.num_overlay_networks);
        self.peerset
            .peers_overlays
            .insert((self.peer_index, overlay_network_index));
        self.peerset
            .overlay_peers
            .insert((overlay_network_index, self.peer_index));
    }

    /// Removes the node from an overlay network.
    ///
    /// Returns `true` if the node was indeed part of this overlay network.
    ///
    /// # Panic
    ///
    /// Panics if `overlay_network_index` is out of range.
    ///
    pub fn remove_from_overlay(&mut self, overlay_network_index: usize) -> bool {
        assert!(overlay_network_index < self.peerset.num_overlay_networks);
        let was_in1 = self
            .peerset
            .peers_overlays
            .remove(&(self.peer_index, overlay_network_index));
        let was_in2 = self
            .peerset
            .overlay_peers
            .remove(&(overlay_network_index, self.peer_index));
        debug_assert_eq!(was_in1, was_in2);
        was_in1
    }

    /// Gives access to the user data associated with the node.
    pub fn user_data_mut(&mut self) -> &mut TPeer {
        &mut self.peerset.peers[self.peer_index].user_data
    }

    /// Gives access to the user data associated with the node.
    pub fn into_user_data(self) -> &'a mut TPeer {
        &mut self.peerset.peers[self.peer_index].user_data
    }
}

/// Access to a node that isn't known to the data structure.
pub struct NodeMutUnknown<'a, TPeer, TConn, TPending> {
    peerset: &'a mut Peerset<TPeer, TConn, TPending>,
    peer_id: PeerId,
}

impl<'a, TPeer, TConn, TPending> NodeMutUnknown<'a, TPeer, TConn, TPending> {
    /// Inserts the node into the data structure. Returns a [`NodeMutKnown`] for that node.
    pub fn insert(self, user_data: TPeer) -> NodeMutKnown<'a, TPeer, TConn, TPending> {
        let peer_index = self.peerset.peers.insert(Peer {
            peer_id: self.peer_id.clone(),
            user_data,
            addresses: Vec::new(),
            connected: true,
        });

        let _was_in = self.peerset.peer_ids.insert(self.peer_id, peer_index);
        debug_assert!(_was_in.is_none());

        NodeMutKnown {
            peerset: self.peerset,
            peer_index,
        }
    }
}
