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

// TODO: documentation

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
