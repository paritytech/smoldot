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
    peer_ids: HashMap<PeerId, usize, RandomState>,

    peers: slab::Slab<Peer<TPeer>>,

    pending: slab::Slab<Connection<TPending>>,

    connections: slab::Slab<Connection<TConn>>,

    /// Container that holds tuples of `(peer_index, connection_index)`. Contains the combinations
    /// of connections associated to a certain peer.
    peer_connections: BTreeSet<(usize, usize)>,

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
            // TODO: randomness seed
            peer_ids: HashMap::with_capacity_and_hasher(config.peers_capacity, Default::default()),
            peers: slab::Slab::with_capacity(config.peers_capacity),
            pending: slab::Slab::with_capacity(config.peers_capacity * 2), // TODO: correct capacity?
            connections: slab::Slab::with_capacity(config.peers_capacity * 2),
            peer_connections: BTreeSet::new(),
            overlay_peers_connected: BTreeSet::new(),
            overlay_peers_disconnected: BTreeSet::new(),
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

/// Access to a node in the [`PeerSet`].
pub enum NodeMut<'a, TPeer, TConn, TPending> {
    /// Node is already known to the data structure.
    Known(NodeMutKnown<'a, TPeer, TConn, TPending>),
    /// Node isn't known by the data structure.
    Unknown(NodeMutUnknown<'a, TPeer, TConn, TPending>),
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
