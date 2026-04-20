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
//! The strategy tries to open Bitswap substreams with all connected peers. In case a substream can't
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

// TODO: We might want to preserve banned peers in the struct even if the number of connections
//       drops to 0, so the ban is not reset when the peer disconnects.

// TODO: This is overly simplified strategy not acceptable for release in smoldot, because it
//       blindly opens Bitswap substreams to all connected peers on all chains. We can do better by
//       lazily starting allocating Bitswap slots only to peers of the chain once the first Bitswap
//       request is received through the RPC endpoint dedicated to this chain.

// TODO: There is no reason for Bitswap connections to be opened to peers that are already
//       connected. Instead, we should initiate network connections to peers sourced from the DHT
//       specifically for Bitswap protocol. This way we can find peers supporting Bitswap protocol
//       even if all the already connected peers do not support Bitswap.

use crate::util;
use alloc::collections::BTreeSet;
use core::ops;
use rand::seq::IteratorRandom as _;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore as _, SeedableRng as _},
};

pub use crate::libp2p::PeerId;

#[derive(Debug)]
pub struct BitswapPeeringStrategy<TInstant> {
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

/// Configuration passed to [`BitswapPeeringStrategy::new`].
pub struct Config {
    /// Seed used for the randomness for choosing peers to connect to.
    pub randomness_seed: [u8; 32],

    /// Number of peers to initially reserve memory for.
    pub peers_capacity: usize,
}

impl<TInstant> BitswapPeeringStrategy<TInstant>
where
    TInstant: PartialOrd + Ord + Eq + Clone,
{
    /// Creates a new empty [`BitswapPeeringStrategy`].
    ///
    /// Must be passed a seed for randomness used
    /// in [`BitswapPeeringStrategy::pick_assignable_peer`].
    pub fn new(config: Config) -> Self {
        let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

        BitswapPeeringStrategy {
            peer_ids: slab::Slab::with_capacity(config.peers_capacity),
            peer_ids_indices: hashbrown::HashMap::with_capacity_and_hasher(
                config.peers_capacity,
                util::SipHasherBuild::new({
                    let mut seed = [0; 16];
                    randomness.fill_bytes(&mut seed);
                    seed
                }),
            ),
            peers: hashbrown::HashMap::with_hasher(fnv::FnvBuildHasher::default()),
            peers_by_state: BTreeSet::new(),
            randomness,
        }
    }

    /// Increase the number of connections of the given peer. If the peer is not known yet it is
    /// automatically inserted.
    ///
    /// # Panic
    ///
    /// Panics if the number of connections exceeds [`u32::MAX`].
    pub fn increase_peer_connections(&mut self, peer_id: &PeerId) {
        let peer_id_index = self.get_or_insert_peer_index(peer_id);

        match self.peers.get_mut(&peer_id_index) {
            Some((_, num_connections)) => {
                *num_connections = num_connections
                    .checked_add(1)
                    .unwrap_or_else(|| panic!("overflow in number of connections"));
            }
            None => {
                self.peers.insert(peer_id_index, (PeerState::Assignable, 1));
                let _was_inserted = self
                    .peers_by_state
                    .insert((PeerState::Assignable, peer_id_index));
                debug_assert!(_was_inserted);
            }
        }
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
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            return Err(DecreasePeerConnectionsError::UnknownPeer);
        };

        let (state, num_connections) = self
            .peers
            .get_mut(&peer_id_index)
            .unwrap_or_else(|| unreachable!());

        *num_connections -= 1;

        if *num_connections == 0 {
            let state = state.clone();
            self.peers.remove(&peer_id_index);
            let _was_removed = self.peers_by_state.remove(&(state, peer_id_index));
            debug_assert!(_was_removed);

            let peer_id = self.peer_ids.remove(peer_id_index);
            let _was_in = self.peer_ids_indices.remove(&peer_id);
            debug_assert_eq!(_was_in, Some(peer_id_index));
        }

        Ok(())
    }

    /// Randomly select a peer that is not banned and doesn't have a slot assigned to it.
    ///
    /// A `TInstant` must be provider in order to determine if the past bans have expired.
    pub fn pick_assignable_peer(&mut self, now: &TInstant) -> AssignablePeer<'_, TInstant> {
        if let Some((_, peer_id_index)) = self
            .peers_by_state
            .range(
                (PeerState::Assignable, usize::MIN)
                    ..=(
                        PeerState::Banned {
                            expires: now.clone(),
                        },
                        usize::MAX,
                    ),
            )
            .choose(&mut self.randomness)
        {
            return AssignablePeer::Assignable(&self.peer_ids[*peer_id_index]);
        }

        if let Some((state, _)) = self
            .peers_by_state
            .range((
                ops::Bound::Excluded((
                    PeerState::Banned {
                        expires: now.clone(),
                    },
                    usize::MAX,
                )),
                ops::Bound::Excluded((PeerState::Slot, usize::MIN)),
            ))
            .next()
        {
            let PeerState::Banned { expires } = state else {
                unreachable!()
            };
            AssignablePeer::AllPeersBanned {
                next_unban: expires,
            }
        } else {
            AssignablePeer::NoPeer
        }
    }

    /// Assign a slot to the peer.
    ///
    /// A slot is assigned even if the peer is banned. API users that call this function are
    /// expected to be aware of that.
    ///
    /// Returns an error if the peer is not known to the data structure.
    pub fn assign_slot(&mut self, peer_id: &PeerId) -> Result<(), AssignSlotError> {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            return Err(AssignSlotError::UnknownPeer);
        };

        let (state, _) = self
            .peers
            .get_mut(&peer_id_index)
            .unwrap_or_else(|| unreachable!());

        let _was_removed = self.peers_by_state.remove(&(state.clone(), peer_id_index));
        debug_assert!(_was_removed);

        *state = PeerState::Slot;

        let _was_inserted = self.peers_by_state.insert((PeerState::Slot, peer_id_index));
        debug_assert!(_was_inserted);

        Ok(())
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
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            return UnassignSlotAndBan::UnknownPeer;
        };

        let (state, _) = self
            .peers
            .get_mut(&peer_id_index)
            .unwrap_or_else(|| unreachable!());

        let return_value = match state {
            PeerState::Banned { expires } if *expires >= when_unban => {
                // Ban is already long enough. Nothing to do.
                return UnassignSlotAndBan::Banned { had_slot: false };
            }
            PeerState::Banned { .. } => UnassignSlotAndBan::Banned { had_slot: false },
            PeerState::Assignable => UnassignSlotAndBan::Banned { had_slot: false },
            PeerState::Slot => UnassignSlotAndBan::Banned { had_slot: true },
        };

        let _was_in = self.peers_by_state.remove(&(state.clone(), peer_id_index));
        debug_assert!(_was_in);

        *state = PeerState::Banned {
            expires: when_unban,
        };

        let _was_inserted = self.peers_by_state.insert((state.clone(), peer_id_index));
        debug_assert!(_was_inserted);

        return_value
    }

    /// Finds the index of the given [`PeerId`] in [`BitswapPeeringStrategy::peer_ids`], or inserts
    /// one if there is none.
    fn get_or_insert_peer_index(&mut self, peer_id: &PeerId) -> usize {
        debug_assert_eq!(self.peer_ids.len(), self.peer_ids_indices.len());

        match self.peer_ids_indices.raw_entry_mut().from_key(peer_id) {
            hashbrown::hash_map::RawEntryMut::Occupied(occupied_entry) => *occupied_entry.get(),
            hashbrown::hash_map::RawEntryMut::Vacant(vacant_entry) => {
                let idx = self.peer_ids.insert(peer_id.clone());
                vacant_entry.insert(peer_id.clone(), idx);
                idx
            }
        }
    }
}

/// See [`BitswapPeeringStrategy::decrease_peer_connections`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum DecreasePeerConnectionsError {
    /// Peer isn't known to the collection.
    UnknownPeer,
}

/// See [`BitswapPeeringStrategy::pick_assignable_peer`].
pub enum AssignablePeer<'a, TInstant> {
    /// An assignable peer was found. Note that the peer wasn't assigned yet.
    Assignable(&'a PeerId),
    /// No peer was found as all known un-assigned peers are currently in the "banned" state.
    AllPeersBanned {
        /// Instant when the first peer will be unbanned.
        next_unban: &'a TInstant,
    },
    /// No un-assigned peer was found.
    NoPeer,
}

/// See [`BitswapPeeringStrategy::assign_slot`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum AssignSlotError {
    /// Peer isn't known to the collection.
    UnknownPeer,
}

/// See [`BitswapPeeringStrategy::unassign_slot_and_ban`].
pub enum UnassignSlotAndBan {
    /// Peer isn't known to the collection.
    UnknownPeer,
    /// Peer has been banned (or ban was extended).
    Banned {
        /// `true` if the peer had a slot before this call.
        had_slot: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libp2p::peer_id::PublicKey;

    fn make_peer(n: u8) -> PeerId {
        PeerId::from_public_key(&PublicKey::Ed25519([n; 32]))
    }

    fn new_strategy() -> BitswapPeeringStrategy<u64> {
        BitswapPeeringStrategy::new(Config {
            randomness_seed: [0; 32],
            peers_capacity: 0,
        })
    }

    #[test]
    fn new_strategy_is_empty() {
        let mut s = new_strategy();
        assert!(matches!(s.pick_assignable_peer(&0), AssignablePeer::NoPeer));
    }

    #[test]
    fn increase_adds_peer() {
        let mut s = new_strategy();
        let peer = make_peer(1);
        s.increase_peer_connections(&peer);
        assert!(matches!(
            s.pick_assignable_peer(&0),
            AssignablePeer::Assignable(_)
        ));
    }

    #[test]
    fn increase_twice_same_peer() {
        let mut s = new_strategy();
        let peer = make_peer(1);
        s.increase_peer_connections(&peer);
        s.increase_peer_connections(&peer);
        // One decrease should not remove the peer.
        s.decrease_peer_connections(&peer).unwrap();
        assert!(matches!(
            s.pick_assignable_peer(&0),
            AssignablePeer::Assignable(_)
        ));
    }

    #[test]
    fn decrease_unknown_peer_errors() {
        let mut s = new_strategy();
        let peer = make_peer(1);
        assert!(matches!(
            s.decrease_peer_connections(&peer),
            Err(DecreasePeerConnectionsError::UnknownPeer)
        ));
    }

    #[test]
    fn decrease_to_zero_removes_peer() {
        let mut s = new_strategy();
        let peer = make_peer(1);
        s.increase_peer_connections(&peer);
        s.decrease_peer_connections(&peer).unwrap();
        assert!(matches!(s.pick_assignable_peer(&0), AssignablePeer::NoPeer));
    }

    #[test]
    fn assign_slot() {
        let mut s = new_strategy();
        let peer = make_peer(1);
        s.increase_peer_connections(&peer);
        s.assign_slot(&peer).unwrap();
        // Slotted peer should not be returned as assignable.
        assert!(matches!(s.pick_assignable_peer(&0), AssignablePeer::NoPeer));
    }

    #[test]
    fn assign_slot_unknown_peer_errors() {
        let mut s = new_strategy();
        let peer = make_peer(1);
        assert!(matches!(
            s.assign_slot(&peer),
            Err(AssignSlotError::UnknownPeer)
        ));
    }

    #[test]
    fn unassign_slot_and_ban_with_slot() {
        let mut s = new_strategy();
        let peer = make_peer(1);
        s.increase_peer_connections(&peer);
        s.assign_slot(&peer).unwrap();
        assert!(matches!(
            s.unassign_slot_and_ban(&peer, 100),
            UnassignSlotAndBan::Banned { had_slot: true }
        ));
    }

    #[test]
    fn ban_assignable_peer() {
        let mut s = new_strategy();
        let peer = make_peer(1);
        s.increase_peer_connections(&peer);
        assert!(matches!(
            s.unassign_slot_and_ban(&peer, 100),
            UnassignSlotAndBan::Banned { had_slot: false }
        ));
    }

    #[test]
    fn ban_unknown_peer() {
        let mut s = new_strategy();
        let peer = make_peer(1);
        assert!(matches!(
            s.unassign_slot_and_ban(&peer, 100),
            UnassignSlotAndBan::UnknownPeer
        ));
    }

    #[test]
    fn ban_extension_keeps_longer_ban() {
        let mut s = new_strategy();
        let peer = make_peer(1);
        s.increase_peer_connections(&peer);
        s.unassign_slot_and_ban(&peer, 200);
        // Shorter ban should not reduce the existing ban.
        s.unassign_slot_and_ban(&peer, 100);
        // Peer should still be banned at time 150 (original ban was until 200).
        assert!(matches!(
            s.pick_assignable_peer(&150),
            AssignablePeer::AllPeersBanned { .. }
        ));
    }

    #[test]
    fn ban_extension_extends_shorter_ban() {
        let mut s = new_strategy();
        let peer = make_peer(1);
        s.increase_peer_connections(&peer);
        s.unassign_slot_and_ban(&peer, 100);
        // Longer ban should extend.
        s.unassign_slot_and_ban(&peer, 200);
        // Peer should still be banned at time 150.
        assert!(matches!(
            s.pick_assignable_peer(&150),
            AssignablePeer::AllPeersBanned { .. }
        ));
    }

    #[test]
    fn banned_peer_not_picked() {
        let mut s = new_strategy();
        let peer = make_peer(1);
        s.increase_peer_connections(&peer);
        s.unassign_slot_and_ban(&peer, 100);
        // Before ban expires, peer should not be assignable.
        assert!(matches!(
            s.pick_assignable_peer(&50),
            AssignablePeer::AllPeersBanned { .. }
        ));
    }

    #[test]
    fn banned_peer_picked_after_expiry() {
        let mut s = new_strategy();
        let peer = make_peer(1);
        s.increase_peer_connections(&peer);
        s.unassign_slot_and_ban(&peer, 100);
        // At or after ban expiry, peer should be assignable.
        assert!(matches!(
            s.pick_assignable_peer(&100),
            AssignablePeer::Assignable(_)
        ));
    }

    #[test]
    fn all_peers_banned_returns_next_unban() {
        let mut s = new_strategy();
        let peer1 = make_peer(1);
        let peer2 = make_peer(2);
        s.increase_peer_connections(&peer1);
        s.increase_peer_connections(&peer2);
        s.unassign_slot_and_ban(&peer1, 200);
        s.unassign_slot_and_ban(&peer2, 300);
        match s.pick_assignable_peer(&150) {
            AssignablePeer::AllPeersBanned { next_unban } => {
                assert_eq!(*next_unban, 200);
            }
            _ => panic!("expected AllPeersBanned"),
        }
    }

    #[test]
    fn multiple_peers_picks_only_assignable() {
        let mut s = new_strategy();
        let peer1 = make_peer(1);
        let peer2 = make_peer(2);
        let peer3 = make_peer(3);
        s.increase_peer_connections(&peer1);
        s.increase_peer_connections(&peer2);
        s.increase_peer_connections(&peer3);

        // Ban peer1, assign slot to peer2 — only peer3 should be pickable.
        s.unassign_slot_and_ban(&peer1, 1000);
        s.assign_slot(&peer2).unwrap();

        match s.pick_assignable_peer(&0) {
            AssignablePeer::Assignable(p) => assert_eq!(*p, peer3),
            _ => panic!("expected Assignable(peer3)"),
        }
    }

    #[test]
    fn peer_state_ordering() {
        // The BTreeSet range queries rely on this ordering.
        assert!(PeerState::<u64>::Assignable < PeerState::Banned { expires: 0 });
        assert!(PeerState::<u64>::Banned { expires: 5 } < PeerState::Banned { expires: 7 });
        assert!(PeerState::<u64>::Banned { expires: u64::MAX } < PeerState::Slot);
    }
}
