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
//! - One or more overlay networks the node is known to belong to.
//! - For each overlay network the node belongs to, a flag indicating whether there exists an
//! active substream between this node and the local node. This flag doesn't entail any *actual*
//! connectivity, and exists only for the [`Peerset`] to provide convenient and optimized APIs
//! that filter nodes based on this flag.
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
use hashbrown::HashMap;
use parity_multiaddr::Multiaddr;

/// Configuration for a [`Peerset`].
#[derive(Debug)]
pub struct Config {
    /// Seed for the randomness used to decide how peers are chosen.
    pub randomness_seed: [u8; 32],
}

/// See the [module-level documentation](self).
pub struct Peerset<TPeer, TNet> {
    peers: HashMap<PeerId, Peer<TPeer>, AHasher>,
    overlay_networks: slab::Slab<TNet>,
}

struct Peer<TPeer> {
    user_data: TPeer,
    addresses: Vec<Multiaddr>,
    connected: bool,
}

impl<TPeer, TNet> Peerset<TPeer, TNet> {
    pub fn new(config: Config) -> Self {
        // TODO: with capacity
        // TODO: randomness seed
        Peerset {
            peers: HashMap::with_capacity_and_hasher(0, Default::default()),
            overlay_networks: slab::Slab::new(),
        }
    }
}
