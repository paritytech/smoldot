// Smoldot
// Copyright (C) 2026  Parity Technologies (UK) Ltd.
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

//! Simple slot assignment algorithm for Bitswap protocol.
//!
//! The strategy tries to open Bitswap substerams with all connected peers. In case a substream can't
//! be opened (for example, the remote doesn't support Bitswap protocol) or the peer misbehaves,
//! the peer is banned for a certain period of time, preventing it from being returned as
//! a candidate for a Bitswap connection.
//!
//! The strategy user must update its state when:
//!  1) A connection is established with a peer — by calling
//!     [`BitswapPeeringStrategy::increase_peer_connections`]
//!  2) A connection is terminated with a peer — by calling
//!     [`BitswapPeeringStrategy::decrease_peer_connections`]
//!
//! [`BitswapPeeringStrategy`] contains all currently connected peers, identified by [`PeerId`].
//!
//! Each peer can be in one of these three states:
//!
//! - Normal.
//! - Banned until a certain instant represented by `TInstant`.
//! - Has a slot.
//!
//! "Normal" and "banned" peers represent the potential peers to connect to over Bitswap protocol,
//! while "slot" represent pending or established Bitswap protocol connection.
//!
//! Use [`BitswapPeeringStrategy::pick_assignable_peer`] in order to get a randomly-chosen
//! candidate for slot assignment from the peers that don't currently have a slot assigned and are
//! not banned. Use [`BitswapPeeringStrategy::assign_slot`] to assign a slot.
//!
//! If a Bitswap connection fails to be established with a certain peer, or if the peer misbehaves,
//! use [`BitswapPeeringStrategy::unassign_slot_and_ban`] to ban the peer, preventing it from
//! obtaining a slot for a provided amount of time.

pub use crate::libp2p::PeerId;

#[derive(Debug)]
struct BitswapPeeringStrategy<TInstant> {
    /// Contains all the `PeerId`s used throughout the collection.
    peer_ids: slab::Slab<PeerId>,

    /// Contains all the keys of [`BitswapPeeringStrategy::peer_ids`] indexed differently.
    peer_ids_indices: hashbrown::HashMap<PeerId, usize, util::SipHasherBuild>,

    /// Peers with their state and number of connections.
    /// Key is the index of the peer in `peer_ids`, value is `(state, number_of_connections)`.
    peers: hashbrown::HashMap<usize, (PeerState<TInstant>, u32), fnv::FnvBuildHasher>,

    /// Peers ordered by state. Used for slot allocation.
    peers_by_state: BTreeSet<(PeerState<TInstant>, usize)>,

    /// Random number generator used to select peers to assign slots to and remove addresses/peers.
    randomness: ChaCha20Rng,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
enum PeerState<TInstant> {
    Assignable,
    Banned { expires: TInstant },
    Slot,
}

impl<TInstant> BitswapPeeringStrategy<TInstant>
where
    TInstant: PartialOrd + Ord + Eq + Clone,
{
    /// Creates a new empty [`BitswapPeeringStrategy`].
    ///
    /// Must be passed a seed for randomness used
    /// in [`BitswapPeeringStrategy::pick_assignable_peer`].
    pub fn new(randomness_seed: [u8; 32]) -> Self {
        todo!();
    }

    /// Increase the number of connections of the given peer. If the peer is not known yet it is
    /// automatically inserted.
    ///
    /// # Panic
    ///
    /// Panics if the number of connections exceeds [`u32::MAX`].
    pub fn increase_peer_connections(&mut self, peer_id: &PeerId) {
        todo!();
    }

    /// Decrease the number of connections of the given peer. If the number of connections drops to
    /// 0, the peer is removed.
    ///
    /// Returns an error if the peer is not known to the data structure (i.e., if the number of
    /// connections is 0).
    pub fn decrease_peer_connections(
        &mut self,
        peer_id: &PeerId,
    ) -> Result<(), DecreasePeerConnectionsError> {
        todo!();
    }

    /// Randomly select a peer that is not banned and doesn't have a slot assigned to it.
    ///
    /// A `TInstant` must be provider in order to determine if the past bans have expired.
    pub fn pick_assignable_peer(&mut self, now: &TInstant) -> AssignablePeer<'_, TInstant> {
        todo!();
    }

    /// Assign a slot to the peer.
    ///
    /// A slot is assigned even if the peer is banned. API users that call this function are
    /// expected to be aware of that.
    ///
    /// Returns an error if the peer is not known to the data structure.
    pub fn assign_slot(&mut self, peer_id: &PeerId) -> Result<(), AssignSlotError> {
        todo!();
    }

    /// Unassign slot and ban the peer until the given instant.
    ///
    /// If the peer was already banned, the new ban expiration is `max(existing_ban, when_unban)`.
    ///
    /// Returns what this function did.
    pub fn unassign_slot_and_ban(
        &mut self,
        peer_id: &PeerId,
        when_unban: TInstant,
    ) -> UnassignSlotAndBan {
        todo!();
    }
}
