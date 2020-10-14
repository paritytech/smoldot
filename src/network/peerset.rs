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

//! Helpers for managing connectivity to overlay networks.
//!
//! The [`Peerset`] is a data structure that holds a list of node identities ([`PeerId`]s) and a
//! list of overlay networks. Each [`PeerId`] is associated with:
//!
//! - A list of [`Multiaddr`]s onto which the node is believed to be reachable.
//! - One or more overlay networks the node is believed to belong to.
//! - For each overlay network the node belongs to, a boolean indicating whether there exists an
//! active substream between this node and the local node. This boolean doesn't entail any *actual*
//! connectivity, and exists only for the [`Peerset`] to provide convenient and optimized APIs
//! that filter nodes based on this value.
//! - An opaque user data of type `TPeer`. The actual type is at the discretion of the user.
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
//! Whenever a TCP connection is established with a certain peer, query the [`Peerset`] for the
//! list of overlay protocols it belongs to and try to open notification substreams with it.
//!
//! Additionally, whenever a notifications protocol substream is established or lost with a
//! certain peer, set the appropriate connectivity flag in the [`Peerset`].
//!
//! In parallel, the [`Peerset`] can be asked for a list of node identities .
//!

// TODO: finish documentation

use crate::network::libp2p::peer_id::PeerId;

use ahash::AHasher;
use alloc::collections::BTreeSet;
use hashbrown::HashMap;
use parity_multiaddr::Multiaddr;

/// Configuration for a [`Peerset`].
#[derive(Debug)]
pub struct Config {
    /// Capacity to reserve for containers having a number of peers.
    pub peers_capacity: usize,

    /// Seed for the randomness used to decide how peers are chosen.
    pub randomness_seed: [u8; 32],
}

/// See the [module-level documentation](self).
pub struct Peerset<TPeer, TNet> {
    peer_ids: HashMap<PeerId, usize, AHasher>,

    peers: slab::Slab<Peer<TPeer>>,

    overlay_networks: slab::Slab<TNet>,

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

impl<TPeer, TNet> Peerset<TPeer, TNet> {
    pub fn new(config: Config) -> Self {
        Peerset {
            // TODO: randomness seed
            peer_ids: HashMap::with_capacity_and_hasher(config.peers_capacity, Default::default()),
            peers: slab::Slab::with_capacity(config.peers_capacity),
            overlay_networks: slab::Slab::new(), // TODO: with_capacity
            overlay_peers_connected: BTreeSet::new(),
            overlay_peers_disconnected: BTreeSet::new(),
        }
    }

    pub fn node_mut(&mut self, peer_id: PeerId) -> NodeMut<TPeer, TNet> {
        todo!()
    }
}

/// Access to a node in the [`PeerSet`].
pub enum NodeMut<'a, TPeer, TNet> {
    Known(NodeMutKnown<'a, TPeer, TNet>),
    Unknown(NodeMutUnknown<'a, TPeer, TNet>),
}

pub struct NodeMutKnown<'a, TPeer, TNet> {
    peerset: &'a mut Peerset<TPeer, TNet>,
}

pub struct NodeMutUnknown<'a, TPeer, TNet> {
    peerset: &'a mut Peerset<TPeer, TNet>,
}

impl<'a, TPeer, TNet> NodeMutUnknown<'a, TPeer, TNet> {
    pub fn add_to_overlay(self, overlay: usize) -> NodeMutKnown<'a, TPeer, TNet> {
        // TODO:
        NodeMutKnown {
            peerset: self.peerset,
        }
    }
}
