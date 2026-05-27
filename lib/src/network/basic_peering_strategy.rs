// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

//! Basic address book and slots assignments algorithm.
//!
//! The [`BasicPeeringStrategy`] contains a collection of network identities, identified by
//! a [`PeerId`]. Each network identity is associated to one or more chains, identified by a
//! `TChainId`.
//!
//! Each network-identity-chain association can be in one of these three states:
//!
//! - Normal.
//! - Banned until a certain instant represented by `TInstant`.
//! - Has a slot.
//!
//! "Normal" and "banned" network-identity-chain associations represent the potential peers to
//! connect to, while "slot" represent pending or established gossip slots.
//!
//! Use [`BasicPeeringStrategy::pick_assignable_peer`] in order to assign a slot to a
//! randomly-chosen network-identity that doesn't currently have one.
//!
//! If a gossip slot fails to be established with a certain peer, or if the peer misbehaves,
//! use [`BasicPeeringStrategy::unassign_slot_and_ban`] to ban the peer, preventing it from
//! obtaining a slot for a certain amount of time.
//!
//! Each network identity that is associated with at least one chain is associated with zero or
//! more addresses. It is not possible to insert addresses to peers that aren't associated to at
//! least one chain. The number of active connections of each address is also tracked.
//!
//! There exists a limit to the number of peers per chain and the number of addresses per peer,
//! guaranteeing that the data structure only uses a bounded amount of memory. If these limits
//! are reached, peers and addresses are removed randomly. Peers that have a slot and at least one
//! connected address are never removed.
//!

use crate::util;
use alloc::{
    borrow::ToOwned as _,
    collections::{BTreeMap, BTreeSet, btree_map},
    vec::Vec,
};
use core::{hash::Hash, iter, ops};
use rand::seq::IteratorRandom as _;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore as _, SeedableRng as _},
};

pub use crate::libp2p::PeerId;

#[derive(Debug)]
pub struct BasicPeeringStrategy<TChainId, TInstant> {
    /// Contains all the `PeerId`s used throughout the collection.
    peer_ids: slab::Slab<PeerId>,

    /// Contains all the keys of [`BasicPeeringStrategy::peer_ids`] indexed differently.
    peer_ids_indices: hashbrown::HashMap<PeerId, usize, util::SipHasherBuild>,

    /// List of all known addresses, indexed by `peer_id_index`, with the number of connections to
    /// each address. The addresses are not intended to be in a particular order.
    addresses: BTreeMap<(usize, Vec<u8>), u32>,

    /// List of all chains throughout the collection.
    ///
    /// > **Note**: In principle this field is completely unnecessary. In practice, however, we
    /// >           can't use `BTreeMap::range` with `TChainId`s because we don't know the minimum
    /// >           and maximum values of a `TChainId`. In order to bypass this problem,
    /// >           `TChainId`s are instead refered to as a `usize`.
    chains: slab::Slab<TChainId>,

    /// Contains all the keys of [`BasicPeeringStrategy::chains`] indexed differently.
    /// While a dumber hasher is in principle enough, we use a `SipHasherBuild` "just in case"
    /// as we don't know the properties of `TChainId`.
    chains_indices: hashbrown::HashMap<TChainId, usize, util::SipHasherBuild>,

    /// Collection of
    /// Keys are `(peer_id_index, chain_id_index)`.
    peers_chains: BTreeMap<(usize, usize), PeerChainState<TInstant>>,

    /// Entries are `(chain_id_index, state, peer_id_index)`.
    peers_chains_by_state: BTreeSet<(usize, PeerChainState<TInstant>, usize)>,

    /// Random number generator used to select peers to assign slots to and remove addresses/peers.
    randomness: ChaCha20Rng,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
enum PeerChainState<TInstant> {
    Assignable,
    Banned { expires: TInstant },
    Slot,
}

/// Configuration passed to [`BasicPeeringStrategy::new`].
pub struct Config {
    /// Seed used for the randomness for choosing peers and addresses to connect to or remove.
    pub randomness_seed: [u8; 32],

    /// Number of peers, all chains together, to initially reserve memory for.
    pub peers_capacity: usize,

    /// Number of chains to initially reserve memory for.
    pub chains_capacity: usize,
}

impl<TChainId, TInstant> BasicPeeringStrategy<TChainId, TInstant>
where
    TChainId: PartialOrd + Ord + Eq + Hash + Clone,
    TInstant: PartialOrd + Ord + Eq + Clone,
{
    /// Creates a new empty [`BasicPeeringStrategy`].
    ///
    /// Must be passed a seed for randomness used
    /// in [`BasicPeeringStrategy::pick_assignable_peer`].
    pub fn new(config: Config) -> Self {
        let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

        BasicPeeringStrategy {
            peer_ids: slab::Slab::with_capacity(config.peers_capacity),
            peer_ids_indices: hashbrown::HashMap::with_capacity_and_hasher(
                config.peers_capacity,
                util::SipHasherBuild::new({
                    let mut seed = [0; 16];
                    randomness.fill_bytes(&mut seed);
                    seed
                }),
            ),
            addresses: BTreeMap::new(),
            chains: slab::Slab::with_capacity(config.chains_capacity),
            chains_indices: hashbrown::HashMap::with_capacity_and_hasher(
                config.chains_capacity,
                util::SipHasherBuild::new({
                    let mut seed = [0; 16];
                    randomness.fill_bytes(&mut seed);
                    seed
                }),
            ),
            peers_chains: BTreeMap::new(),
            peers_chains_by_state: BTreeSet::new(),
            randomness,
        }
    }

    /// Removes all the chain assignments for the given chain.
    ///
    /// If a peer isn't assigned to any chain anymore and doesn't have any connected address,
    /// all of its addresses are also removed from the collection.
    pub fn remove_chain_peers(&mut self, chain: &TChainId) {
        let Some(chain_index) = self.chains_indices.remove(chain) else {
            // Chain didn't exist.
            return;
        };
        self.chains.remove(chain_index);

        let chain_peers = {
            let mut in_chain_and_after_chain = self.peers_chains_by_state.split_off(&(
                chain_index,
                PeerChainState::Assignable,
                usize::MIN,
            ));
            let mut after_chain = in_chain_and_after_chain.split_off(&(
                chain_index + 1,
                PeerChainState::Assignable,
                usize::MIN,
            ));
            self.peers_chains_by_state.append(&mut after_chain);
            in_chain_and_after_chain
        };

        for (_, _, peer_id_index) in chain_peers {
            let _was_in = self.peers_chains.remove(&(peer_id_index, chain_index));
            debug_assert!(_was_in.is_some());
            self.try_clean_up_peer_id(peer_id_index);
        }
    }

    /// Inserts a chain-peer combination to the collection, indicating that the given peer belongs
    /// to the given chain.
    ///
    /// Has no effect if the peer is already assigned to the given chain, in which case
    /// [`InsertChainPeerResult::Duplicate`] is returned.
    ///
    /// A maximum number of peers per chain must be provided. If the peer is inserted and the
    /// limit is exceeded, a peer (other than the one that has just been inserted) that belongs
    /// to the given chain is randomly chosen and removed. Peers that have slots assigned to them
    /// are never removed.
    pub fn insert_chain_peer(
        &mut self,
        chain: TChainId,
        peer_id: PeerId,
        max_peers_per_chain: usize,
    ) -> InsertChainPeerResult {
        let peer_id_index = self.get_or_insert_peer_index(&peer_id);
        let chain_index = self.get_or_insert_chain_index(&chain);

        if let btree_map::Entry::Vacant(entry) =
            self.peers_chains.entry((peer_id_index, chain_index))
        {
            let peer_to_remove = if self
                .peers_chains_by_state
                .range(
                    (chain_index, PeerChainState::Assignable, usize::MIN)
                        ..=(chain_index, PeerChainState::Slot, usize::MAX),
                )
                .count()
                >= max_peers_per_chain
            {
                self.peers_chains_by_state
                    .range(
                        (chain_index, PeerChainState::Assignable, usize::MIN)
                            ..(chain_index, PeerChainState::Slot, usize::MIN),
                    )
                    .choose(&mut self.randomness)
                    .map(|(_, _, peer_index)| *peer_index)
            } else {
                None
            };

            let _was_inserted = self.peers_chains_by_state.insert((
                chain_index,
                PeerChainState::Assignable,
                peer_id_index,
            ));
            debug_assert!(_was_inserted);

            entry.insert(PeerChainState::Assignable);

            let peer_removed = if let Some(peer_to_remove) = peer_to_remove {
                let peer_id_to_remove = self.peer_ids[peer_to_remove].clone();
                let state = self
                    .peers_chains
                    .remove(&(peer_to_remove, chain_index))
                    .unwrap_or_else(|| unreachable!());
                debug_assert!(!matches!(state, PeerChainState::Slot));
                let _was_removed =
                    self.peers_chains_by_state
                        .remove(&(chain_index, state, peer_to_remove));
                debug_assert!(_was_removed);
                self.try_clean_up_peer_id(peer_to_remove);
                Some(peer_id_to_remove)
            } else {
                None
            };

            InsertChainPeerResult::Inserted { peer_removed }
        } else {
            InsertChainPeerResult::Duplicate
        }
    }

    /// Removes a peer-chain associated previously inserted with
    /// [`BasicPeeringStrategy::insert_chain_peer`].
    ///
    /// Has no effect if the peer-chain association didn't exist.
    ///
    /// If the peer isn't assigned to any chain anymore and doesn't have any connected address,
    /// all of its addresses are also removed from the collection.
    pub fn unassign_slot_and_remove_chain_peer(
        &mut self,
        chain: &TChainId,
        peer_id: &PeerId,
    ) -> UnassignSlotAndRemoveChainPeer<TInstant> {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            // If the `PeerId` is unknown, it means it wasn't assigned in the first place.
            return UnassignSlotAndRemoveChainPeer::NotAssigned;
        };

        let Some(&chain_index) = self.chains_indices.get(chain) else {
            // If the `TChainId` is unknown, it means the peer wasn't assigned in the first place.
            return UnassignSlotAndRemoveChainPeer::NotAssigned;
        };

        if let Some(state) = self.peers_chains.remove(&(peer_id_index, chain_index)) {
            let _was_removed =
                self.peers_chains_by_state
                    .remove(&(chain_index, state.clone(), peer_id_index));
            debug_assert!(_was_removed);

            self.try_clean_up_peer_id(peer_id_index);
            self.try_clean_up_chain(chain_index);

            match state {
                PeerChainState::Assignable => UnassignSlotAndRemoveChainPeer::Assigned {
                    ban_expiration: None,
                },
                PeerChainState::Banned { expires } => UnassignSlotAndRemoveChainPeer::Assigned {
                    ban_expiration: Some(expires),
                },
                PeerChainState::Slot => UnassignSlotAndRemoveChainPeer::HadSlot,
            }
        } else {
            UnassignSlotAndRemoveChainPeer::NotAssigned
        }
    }

    /// Returns the list of all peers that are known to belong to the given chain, in other
    /// words peers added through [`BasicPeeringStrategy::insert_chain_peer`].
    ///
    /// The order of the yielded elements is unspecified.
    pub fn chain_peers_unordered(&self, chain: &TChainId) -> impl Iterator<Item = &PeerId> {
        let Some(&chain_index) = self.chains_indices.get(chain) else {
            // If the `TChainId` is unknown, it means that it doesn't have any peer.
            return either::Right(iter::empty());
        };

        either::Left(
            self.peers_chains_by_state
                .range(
                    (chain_index, PeerChainState::Assignable, usize::MIN)
                        ..=(chain_index, PeerChainState::Slot, usize::MAX),
                )
                .map(|(_, _, p)| &self.peer_ids[*p]),
        )
    }

    /// Inserts a new address for the given peer.
    ///
    /// If the address wasn't known yet, its number of connections is set to zero.
    ///
    /// If the peer doesn't belong to any chain (see [`BasicPeeringStrategy::insert_chain_peer`]),
    /// then this function has no effect, unless the peer has at least one connected address. This
    /// is to avoid accidentally collecting addresses for peers that will never be removed and
    /// create a memory leak. For this reason, you most likely want to call
    /// [`BasicPeeringStrategy::insert_chain_peer`] before calling this function.
    ///
    /// A maximum number of addresses that are maintained for this peer must be passed as
    /// parameter. If this number is exceeded, an address with zero connections (other than
    /// the one passed as parameter) is randomly removed.
    pub fn insert_address(
        &mut self,
        peer_id: &PeerId,
        address: Vec<u8>,
        max_addresses: usize,
    ) -> InsertAddressResult {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            return InsertAddressResult::UnknownPeer;
        };

        match self.insert_address_inner(peer_id_index, address, max_addresses, 0, false) {
            InsertAddressConnectionsResult::AlreadyKnown => InsertAddressResult::AlreadyKnown,
            InsertAddressConnectionsResult::Inserted { address_removed } => {
                InsertAddressResult::Inserted { address_removed }
            }
        }
    }

    /// Increases the number of connections of the given address. If the address isn't known, it
    /// is inserted.
    ///
    /// Contrary to [`BasicPeeringStrategy::insert_address`], the address is inserted anyway if
    /// the `PeerId` isn't known.
    ///
    /// > **Note**: Use this function if you establish a connection and accidentally reach a
    /// >           certain [`PeerId`].
    ///
    /// # Panic
    ///
    /// Panics if the number of connections is equal to `u32::MAX`.
    ///
    pub fn increase_address_connections(
        &mut self,
        peer_id: &PeerId,
        address: Vec<u8>,
        max_addresses: usize,
    ) -> InsertAddressConnectionsResult {
        let peer_id_index = self.get_or_insert_peer_index(peer_id);
        self.insert_address_inner(peer_id_index, address, max_addresses, 1, true)
    }

    fn insert_address_inner(
        &mut self,
        peer_id_index: usize,
        address: Vec<u8>,
        max_addresses: usize,
        initial_num_connections: u32,
        increase_if_present: bool,
    ) -> InsertAddressConnectionsResult {
        match self.addresses.entry((peer_id_index, address.clone())) {
            btree_map::Entry::Vacant(entry) => {
                entry.insert(initial_num_connections);

                let address_removed = {
                    let num_addresses = self
                        .addresses
                        .range((peer_id_index, Vec::new())..=(peer_id_index + 1, Vec::new()))
                        .count();

                    if num_addresses >= max_addresses {
                        // TODO: is it a good idea to choose the address randomly to remove? maybe there should be a sorting system with best addresses first?
                        self.addresses
                            .range((peer_id_index, Vec::new())..=(peer_id_index + 1, Vec::new()))
                            .filter(|((_, a), n)| **n == 0 && *a != address)
                            .choose(&mut self.randomness)
                            .map(|((_, a), _)| a.clone())
                    } else {
                        None
                    }
                };

                if let Some(address_removed) = address_removed.as_ref() {
                    self.addresses
                        .remove(&(peer_id_index, address_removed.clone()));
                }

                InsertAddressConnectionsResult::Inserted { address_removed }
            }
            btree_map::Entry::Occupied(entry) => {
                let entry = entry.into_mut();
                if increase_if_present {
                    *entry = entry
                        .checked_add(1)
                        .unwrap_or_else(|| panic!("overflow in number of connections"));
                }

                InsertAddressConnectionsResult::AlreadyKnown
            }
        }
    }

    /// Returns the list of all addresses that have been inserted for the given peer.
    pub fn peer_addresses(&self, peer_id: &PeerId) -> impl Iterator<Item = &[u8]> {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            // If the `PeerId` is unknown, it means it doesn't have any address.
            return either::Right(iter::empty());
        };

        either::Left(
            self.addresses
                .range((peer_id_index, Vec::new())..(peer_id_index + 1, Vec::new()))
                .map(|((_, a), _)| &a[..]),
        )
    }

    /// Chooses a [`PeerId`] that is known to belong to the given chain, that is not banned, and
    /// that doesn't have a slot assigned to it.
    ///
    /// A `TInstant` must be provided in order to determine whether past bans have expired.
    ///
    /// If multiple peers can be assigned a slot, the one returned is chosen randomly. Calling
    /// this function multiple times might return different peers.
    /// For this reason, this function requires `&mut self`.
    ///
    /// Note that this function might return a peer for which no address is present. While this is
    /// often not desirable, it is preferable to keep the API simple and straight-forward rather
    /// than try to be smart about function behaviours.
    pub fn pick_assignable_peer(
        &mut self,
        chain: &TChainId,
        now: &TInstant,
    ) -> AssignablePeer<'_, TInstant> {
        self.pick_assignable_peer_filtered(chain, now, |_| true)
    }

    /// Same as [`BasicPeeringStrategy::pick_assignable_peer`], except that only peers for which
    /// `filter` returns `true` are taken into account. The [`AssignablePeer::AllPeersBanned`] and
    /// [`AssignablePeer::NoPeer`] return values thus concern only the filtered subset of peers.
    pub fn pick_assignable_peer_filtered(
        &mut self,
        chain: &TChainId,
        now: &TInstant,
        mut filter_fn: impl FnMut(&PeerId) -> bool,
    ) -> AssignablePeer<'_, TInstant> {
        let Some(&chain_index) = self.chains_indices.get(chain) else {
            return AssignablePeer::NoPeer;
        };

        if let Some((_, _, peer_id_index)) = self
            .peers_chains_by_state
            .range(
                (chain_index, PeerChainState::Assignable, usize::MIN)
                    ..=(
                        chain_index,
                        PeerChainState::Banned {
                            expires: now.clone(),
                        },
                        usize::MAX,
                    ),
            )
            .filter(|(_, _, peer_id_index)| filter_fn(&self.peer_ids[*peer_id_index]))
            .choose(&mut self.randomness)
        {
            return AssignablePeer::Assignable(&self.peer_ids[*peer_id_index]);
        }

        if let Some((_, state, _)) = self
            .peers_chains_by_state
            .range((
                ops::Bound::Excluded((
                    chain_index,
                    PeerChainState::Banned {
                        expires: now.clone(),
                    },
                    usize::MAX,
                )),
                ops::Bound::Excluded((chain_index, PeerChainState::Slot, usize::MIN)),
            ))
            .filter(|(_, _, peer_id_index)| filter_fn(&self.peer_ids[*peer_id_index]))
            .next()
        {
            let PeerChainState::Banned { expires } = state else {
                unreachable!()
            };
            AssignablePeer::AllPeersBanned {
                next_unban: expires,
            }
        } else {
            AssignablePeer::NoPeer
        }
    }

    /// Assigns a slot to the given peer on the given chain.
    ///
    /// Acts as an implicit call to [`BasicPeeringStrategy::insert_chain_peer`].
    ///
    /// A slot is assigned even if the peer is banned. API users that call this function are
    /// expected to be aware of that.
    pub fn assign_slot(&mut self, chain: &TChainId, peer_id: &PeerId) {
        let peer_id_index = self.get_or_insert_peer_index(peer_id);
        let chain_index = self.get_or_insert_chain_index(chain);

        match self.peers_chains.entry((peer_id_index, chain_index)) {
            btree_map::Entry::Occupied(e) => {
                let _was_removed = self.peers_chains_by_state.remove(&(
                    chain_index,
                    e.get().clone(),
                    peer_id_index,
                ));
                debug_assert!(_was_removed);
                *e.into_mut() = PeerChainState::Slot;
            }
            btree_map::Entry::Vacant(e) => {
                e.insert(PeerChainState::Slot);
            }
        }

        let _was_inserted =
            self.peers_chains_by_state
                .insert((chain_index, PeerChainState::Slot, peer_id_index));
        debug_assert!(_was_inserted);
    }

    /// Unassign the slot that has been assigned to the given peer and bans the peer, preventing
    /// it from being assigned a slot on this chain for a certain amount of time.
    ///
    /// Has no effect if the peer isn't assigned to the given chain.
    ///
    /// If the peer was already banned, the new ban expiration is `max(existing_ban, when_unban)`.
    ///
    /// Returns what this function did.
    pub fn unassign_slot_and_ban(
        &mut self,
        chain: &TChainId,
        peer_id: &PeerId,
        when_unban: TInstant,
    ) -> UnassignSlotAndBan<TInstant> {
        let (Some(&peer_id_index), Some(&chain_index)) = (
            self.peer_ids_indices.get(peer_id),
            self.chains_indices.get(chain),
        ) else {
            return UnassignSlotAndBan::NotAssigned;
        };

        if let Some(state) = self.peers_chains.get_mut(&(peer_id_index, chain_index)) {
            let return_value = match state {
                PeerChainState::Banned { expires } if *expires >= when_unban => {
                    // Ban is already long enough. Nothing to do.
                    return UnassignSlotAndBan::AlreadyBanned {
                        when_unban: expires.clone(),
                        ban_extended: false,
                    };
                }
                PeerChainState::Banned { .. } => UnassignSlotAndBan::AlreadyBanned {
                    when_unban: when_unban.clone(),
                    ban_extended: true,
                },
                PeerChainState::Assignable => UnassignSlotAndBan::Banned { had_slot: false },
                PeerChainState::Slot => UnassignSlotAndBan::Banned { had_slot: true },
            };

            let _was_in =
                self.peers_chains_by_state
                    .remove(&(chain_index, state.clone(), peer_id_index));
            debug_assert!(_was_in);

            *state = PeerChainState::Banned {
                expires: when_unban,
            };

            let _was_inserted =
                self.peers_chains_by_state
                    .insert((chain_index, state.clone(), peer_id_index));
            debug_assert!(_was_inserted);

            return_value
        } else {
            UnassignSlotAndBan::NotAssigned
        }
    }

    /// Unassigns all the slots that have been assigned to the given peer and bans the peer,
    /// preventing it from being assigned a slot for all of the chains it had a slot on for a
    /// certain amount of time.
    ///
    /// Has no effect on chains the peer isn't assigned to.
    ///
    /// If the peer was already banned, the new ban expiration is `max(existing_ban, when_unban)`.
    ///
    /// Returns an iterator to the list of chains where the peer is now banned, and the details
    /// of what has happened.
    ///
    /// > **Note**: This function is a shortcut for calling
    /// >           [`BasicPeeringStrategy::unassign_slot_and_ban`] for all existing chains.
    pub fn unassign_slots_and_ban(
        &'_ mut self,
        peer_id: &PeerId,
        when_unban: TInstant,
    ) -> UnassignSlotsAndBanIter<'_, TChainId, TInstant> {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            return UnassignSlotsAndBanIter {
                chains: &self.chains,
                peers_chains_by_state: &mut self.peers_chains_by_state,
                inner_iter: None,
                peer_id_index: 0,
                when_unban,
            };
        };

        UnassignSlotsAndBanIter {
            chains: &self.chains,
            peers_chains_by_state: &mut self.peers_chains_by_state,
            inner_iter: Some(
                self.peers_chains
                    .range_mut((peer_id_index, usize::MIN)..=(peer_id_index, usize::MAX))
                    .fuse(),
            ),
            peer_id_index,
            when_unban,
        }
    }

    /// Picks an address from the list with zero connections, and sets the number of connections
    /// to one. Returns `None` if no such address is available.
    pub fn pick_address_and_add_connection(&mut self, peer_id: &PeerId) -> Option<&[u8]> {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            // If the `PeerId` is unknown, it means it doesn't have any address.
            return None;
        };

        // TODO: could be optimized further by removing filter() and adjusting the set
        if let Some(((_, address), num_connections)) = self
            .addresses
            .range_mut((peer_id_index, Vec::new())..(peer_id_index + 1, Vec::new()))
            .filter(|(_, num_connections)| **num_connections == 0)
            .choose(&mut self.randomness)
        {
            *num_connections = 1;
            return Some(address);
        }

        None
    }

    /// Removes one connection from the given address.
    ///
    /// Returns an error if the address isn't known to the data structure, or if there was no
    /// connection.
    pub fn decrease_address_connections(
        &mut self,
        peer_id: &PeerId,
        address: &[u8],
    ) -> Result<(), DecreaseAddressConnectionsError> {
        self.decrease_address_connections_inner(peer_id, address, false)
    }

    /// Removes one connection from the given address. If this decreases the number of connections
    /// from one to zero, the address is removed entirely.
    ///
    /// Returns an error if the address isn't known to the data structure, or if there was no
    /// connection.
    pub fn decrease_address_connections_and_remove_if_zero(
        &mut self,
        peer_id: &PeerId,
        address: &[u8],
    ) -> Result<(), DecreaseAddressConnectionsError> {
        self.decrease_address_connections_inner(peer_id, address, true)
    }

    fn decrease_address_connections_inner(
        &mut self,
        peer_id: &PeerId,
        address: &[u8],
        remove_if_reaches_zero: bool,
    ) -> Result<(), DecreaseAddressConnectionsError> {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            // If the `PeerId` is unknown, it means it doesn't have any address.
            return Err(DecreaseAddressConnectionsError::UnknownAddress);
        };

        let Some(num_connections) = self.addresses.get_mut(&(peer_id_index, address.to_owned()))
        else {
            return Err(DecreaseAddressConnectionsError::UnknownAddress);
        };

        if *num_connections == 0 {
            return Err(DecreaseAddressConnectionsError::NotConnected);
        }

        *num_connections -= 1;

        if *num_connections != 0 {
            return Ok(());
        }

        if remove_if_reaches_zero {
            self.addresses.remove(&(peer_id_index, address.to_owned()));
        }

        self.try_clean_up_peer_id(peer_id_index);
        Ok(())
    }

    /// Finds the index of the given `TChainId` in [`BasicPeeringStrategy::chains`], or inserts
    /// one if there is none.
    fn get_or_insert_chain_index(&mut self, chain: &TChainId) -> usize {
        debug_assert_eq!(self.chains.len(), self.chains_indices.len());

        match self.chains_indices.raw_entry_mut().from_key(chain) {
            hashbrown::hash_map::RawEntryMut::Occupied(occupied_entry) => *occupied_entry.get(),
            hashbrown::hash_map::RawEntryMut::Vacant(vacant_entry) => {
                let idx = self.chains.insert(chain.clone());
                vacant_entry.insert(chain.clone(), idx);
                idx
            }
        }
    }

    /// Check if the given `TChainId` is still used within the collection. If no, removes it from
    /// [`BasicPeeringStrategy::chains`].
    fn try_clean_up_chain(&mut self, chain_index: usize) {
        if self
            .peers_chains_by_state
            .range(
                (chain_index, PeerChainState::Assignable, usize::MIN)
                    ..=(chain_index, PeerChainState::Slot, usize::MAX),
            )
            .next()
            .is_some()
        {
            return;
        }

        // Chain is unused. We can remove it.
        let chain_id = self.chains.remove(chain_index);
        let _was_in = self.chains_indices.remove(&chain_id);
        debug_assert_eq!(_was_in, Some(chain_index));
    }

    /// Finds the index of the given [`PeerId`] in [`BasicPeeringStrategy::peer_ids`], or inserts
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

    /// Check if the given [`PeerId`] is still used within the collection. If no, removes it from
    /// [`BasicPeeringStrategy::peer_ids`].
    fn try_clean_up_peer_id(&mut self, peer_id_index: usize) {
        if self
            .peers_chains
            .range((peer_id_index, usize::MIN)..=(peer_id_index, usize::MAX))
            .next()
            .is_some()
        {
            return;
        }

        if self
            .addresses
            .range((peer_id_index, Vec::new())..(peer_id_index + 1, Vec::new()))
            .any(|(_, num_connections)| *num_connections >= 1)
        {
            return;
        }

        // PeerId is unused. We can remove it.
        let peer_id = self.peer_ids.remove(peer_id_index);
        let _was_in = self.peer_ids_indices.remove(&peer_id);
        debug_assert_eq!(_was_in, Some(peer_id_index));
        for address in self
            .addresses
            .range((peer_id_index, Vec::new())..(peer_id_index + 1, Vec::new()))
            .map(|((_, a), _)| a.clone())
            .collect::<Vec<_>>()
        {
            let _was_removed = self.addresses.remove(&(peer_id_index, address));
            debug_assert!(_was_removed.is_some());
        }
    }
}

/// See [`BasicPeeringStrategy::decrease_address_connections`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum DecreaseAddressConnectionsError {
    /// Address isn't known to the collection.
    UnknownAddress,
    /// The address didn't have any connection.
    NotConnected,
}

/// See [`BasicPeeringStrategy::pick_assignable_peer`].
pub enum AssignablePeer<'a, TInstant> {
    /// An assignal peer was found. Note that the peer wasn't assigned yet.
    Assignable(&'a PeerId),
    /// No peer was found as all known un-assigned peers are currently in the "banned" state.
    AllPeersBanned {
        /// Instant when the first peer will be unbanned.
        next_unban: &'a TInstant,
    },
    /// No un-assigned peer was found.
    NoPeer,
}

/// See [`BasicPeeringStrategy::insert_chain_peer`].
pub enum InsertChainPeerResult {
    /// Peer-chain association has been successfully inserted.
    Inserted {
        /// If the maximum number of peers is reached, an old peer might have been removed. If so,
        /// this contains the peer.
        peer_removed: Option<PeerId>,
    },
    /// Peer-chain association was already inserted.
    Duplicate,
}

/// See [`BasicPeeringStrategy::insert_address`].
pub enum InsertAddressResult {
    /// Address has been successfully inserted.
    Inserted {
        /// If the maximum number of addresses is reached, an old address might have been
        /// removed. If so, this contains the address.
        address_removed: Option<Vec<u8>>,
    },
    /// Address was already known.
    AlreadyKnown,
    /// The peer isn't associated to any chain, and as such the address was not inserted.
    UnknownPeer,
}

/// See [`BasicPeeringStrategy::increase_address_connections`].
pub enum InsertAddressConnectionsResult {
    /// Address has been inserted.
    Inserted {
        /// If the maximum number of addresses is reached, an old address might have been
        /// removed. If so, this contains the address.
        address_removed: Option<Vec<u8>>,
    },
    /// Address was already known.
    AlreadyKnown,
}

/// See [`BasicPeeringStrategy::unassign_slot_and_ban`].
pub enum UnassignSlotAndBan<TInstant> {
    /// Peer wasn't assigned to the given chain.
    NotAssigned,
    /// Peer was already banned.
    AlreadyBanned {
        /// When the peer is unbanned.
        when_unban: TInstant,
        /// `true` if the ban has been extended, in other words if the value of `when_unban` was
        /// superior to the existing ban.
        ban_extended: bool,
    },
    /// Peer wasn't banned and is now banned.
    Banned {
        /// `true` if the peer had a slot on the chain.
        had_slot: bool,
    },
}

impl<TInstant> UnassignSlotAndBan<TInstant> {
    /// Returns `true` for [`UnassignSlotAndBan::Banned`] where `had_slot` is `true`.
    pub fn had_slot(&self) -> bool {
        matches!(self, UnassignSlotAndBan::Banned { had_slot: true })
    }
}

/// See [`BasicPeeringStrategy::unassign_slot_and_remove_chain_peer`].
pub enum UnassignSlotAndRemoveChainPeer<TInstant> {
    /// Peer wasn't assigned to the given chain.
    NotAssigned,
    /// Peer was assigned to the given chain but didn't have a slot or was banned.
    Assigned {
        /// `Some` if the peer was banned. Contains the ban expiration.
        ban_expiration: Option<TInstant>,
    },
    /// Peer was assigned to the given chain and had a slot.
    HadSlot,
}

/// See [`BasicPeeringStrategy::unassign_slots_and_ban`].
pub struct UnassignSlotsAndBanIter<'a, TChainId, TInstant>
where
    TInstant: PartialOrd + Ord + Eq + Clone,
{
    /// Same field as in [`BasicPeeringStrategy`].
    chains: &'a slab::Slab<TChainId>,
    /// Same field as in [`BasicPeeringStrategy`].
    peers_chains_by_state: &'a mut BTreeSet<(usize, PeerChainState<TInstant>, usize)>,
    /// Iterator within [`BasicPeeringStrategy::peers_chains`].
    inner_iter:
        Option<iter::Fuse<btree_map::RangeMut<'a, (usize, usize), PeerChainState<TInstant>>>>,
    /// Parameter passed to [`BasicPeeringStrategy::unassign_slots_and_ban`]. Dummy value when
    /// [`UnassignSlotsAndBanIter::inner_iter`] is `None`.
    peer_id_index: usize,
    /// Parameter passed to [`BasicPeeringStrategy::unassign_slots_and_ban`].
    when_unban: TInstant,
}

/// See [`BasicPeeringStrategy::unassign_slots_and_ban`].
pub enum UnassignSlotsAndBan<TInstant> {
    /// Peer was already banned.
    AlreadyBanned {
        /// When the peer is unbanned.
        when_unban: TInstant,
        /// `true` if the ban has been extended, in other words if the value of `when_unban` was
        /// superior to the existing ban.
        ban_extended: bool,
    },
    /// Peer wasn't banned and is now banned.
    Banned {
        /// `true` if the peer had a slot on the chain.
        had_slot: bool,
    },
}

impl<'a, TChainId, TInstant> Iterator for UnassignSlotsAndBanIter<'a, TChainId, TInstant>
where
    TInstant: PartialOrd + Ord + Eq + Clone,
{
    type Item = (&'a TChainId, UnassignSlotsAndBan<TInstant>);

    fn next(&mut self) -> Option<Self::Item> {
        let inner_iter = self.inner_iter.as_mut()?;
        let (&(_, chain_index), state) = inner_iter.next()?;

        let return_value = match state {
            PeerChainState::Banned { expires } if *expires >= self.when_unban => {
                // Ban is already long enough. Nothing to do.
                return Some((
                    &self.chains[chain_index],
                    UnassignSlotsAndBan::AlreadyBanned {
                        when_unban: expires.clone(),
                        ban_extended: false,
                    },
                ));
            }
            PeerChainState::Banned { .. } => UnassignSlotsAndBan::AlreadyBanned {
                when_unban: self.when_unban.clone(),
                ban_extended: true,
            },
            PeerChainState::Assignable => UnassignSlotsAndBan::Banned { had_slot: false },
            PeerChainState::Slot => UnassignSlotsAndBan::Banned { had_slot: true },
        };

        let _was_in =
            self.peers_chains_by_state
                .remove(&(chain_index, state.clone(), self.peer_id_index));
        debug_assert!(_was_in);

        *state = PeerChainState::Banned {
            expires: self.when_unban.clone(),
        };

        let _was_inserted =
            self.peers_chains_by_state
                .insert((chain_index, state.clone(), self.peer_id_index));
        debug_assert!(_was_inserted);

        Some((&self.chains[chain_index], return_value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner_iter
            .as_ref()
            .map_or((0, Some(0)), |inner| inner.size_hint())
    }
}

impl<'a, TChainId, TInstant> iter::FusedIterator for UnassignSlotsAndBanIter<'a, TChainId, TInstant> where
    TInstant: PartialOrd + Ord + Eq + Clone
{
}

impl<'a, TChainId, TInstant> Drop for UnassignSlotsAndBanIter<'a, TChainId, TInstant>
where
    TInstant: PartialOrd + Ord + Eq + Clone,
{
    fn drop(&mut self) {
        // Note that this is safe because `UnassignSlotsAndBanIter` is a `FusedIterator`.
        while let Some(_) = self.next() {}
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AssignablePeer, BasicPeeringStrategy, Config, InsertAddressConnectionsResult,
        InsertAddressResult, InsertChainPeerResult,
    };
    use crate::network::service::{PeerId, peer_id::PublicKey};
    use core::time::Duration;

    #[test]
    fn peer_state_ordering() {
        // The implementation above relies on the properties tested here.
        use super::PeerChainState;
        assert!(PeerChainState::Assignable < PeerChainState::Banned { expires: 0 });
        assert!(PeerChainState::Banned { expires: 5 } < PeerChainState::Banned { expires: 7 });
        assert!(PeerChainState::Banned { expires: u32::MAX } < PeerChainState::Slot);
    }

    #[test]
    fn pick_assignable_peer_filtered_restricts_to_subset() {
        let mut bps = BasicPeeringStrategy::<u32, Duration>::new(Config {
            randomness_seed: [0; 32],
            peers_capacity: 0,
            chains_capacity: 0,
        });

        let bootnode = PeerId::from_public_key(&PublicKey::Ed25519([1; 32]));
        let discovered = PeerId::from_public_key(&PublicKey::Ed25519([2; 32]));
        for p in [&bootnode, &discovered] {
            assert!(matches!(
                bps.insert_chain_peer(0, p.clone(), usize::MAX),
                InsertChainPeerResult::Inserted { peer_removed: None }
            ));
        }

        // Filtering to the bootnode only ever yields the bootnode, regardless of randomness.
        for _ in 0..20 {
            assert!(matches!(
                bps.pick_assignable_peer_filtered(&0, &Duration::ZERO, |p| *p == bootnode),
                AssignablePeer::Assignable(p) if *p == bootnode
            ));
        }

        // A filter excluding every peer reports no assignable peer even though peers exist...
        assert!(matches!(
            bps.pick_assignable_peer_filtered(&0, &Duration::ZERO, |_| false),
            AssignablePeer::NoPeer
        ));
        // ...whereas the unfiltered pick still finds one.
        assert!(matches!(
            bps.pick_assignable_peer(&0, &Duration::ZERO),
            AssignablePeer::Assignable(_)
        ));
    }

    #[test]
    fn addresses_removed_when_peer_has_no_chain_association() {
        let mut bps = BasicPeeringStrategy::<u32, Duration>::new(Config {
            randomness_seed: [0; 32],
            peers_capacity: 0,
            chains_capacity: 0,
        });

        let peer_id = PeerId::from_public_key(&PublicKey::Ed25519([0; 32]));

        assert!(matches!(
            bps.insert_chain_peer(0, peer_id.clone(), usize::MAX),
            InsertChainPeerResult::Inserted { peer_removed: None }
        ));

        assert!(matches!(
            bps.insert_address(&peer_id, Vec::new(), usize::MAX),
            InsertAddressResult::Inserted {
                address_removed: None
            }
        ));

        assert_eq!(bps.peer_addresses(&peer_id).count(), 1);
        bps.unassign_slot_and_remove_chain_peer(&0, &peer_id);
        assert_eq!(bps.peer_addresses(&peer_id).count(), 0);
    }

    #[test]
    fn addresses_not_removed_if_connected_when_peer_has_no_chain_association() {
        let mut bps = BasicPeeringStrategy::<u32, Duration>::new(Config {
            randomness_seed: [0; 32],
            peers_capacity: 0,
            chains_capacity: 0,
        });

        let peer_id = PeerId::from_public_key(&PublicKey::Ed25519([0; 32]));

        assert!(matches!(
            bps.insert_chain_peer(0, peer_id.clone(), usize::MAX),
            InsertChainPeerResult::Inserted { peer_removed: None }
        ));

        assert!(matches!(
            bps.increase_address_connections(&peer_id, Vec::new(), usize::MAX),
            InsertAddressConnectionsResult::Inserted {
                address_removed: None
            }
        ));

        assert!(matches!(
            bps.insert_address(&peer_id, vec![1], usize::MAX),
            InsertAddressResult::Inserted {
                address_removed: None
            }
        ));

        assert_eq!(bps.peer_addresses(&peer_id).count(), 2);
        bps.unassign_slot_and_remove_chain_peer(&0, &peer_id);
        assert_eq!(bps.peer_addresses(&peer_id).count(), 2);

        bps.decrease_address_connections(&peer_id, &[]).unwrap();
        assert_eq!(bps.peer_addresses(&peer_id).count(), 0);
    }

    #[test]
    fn address_not_inserted_when_peer_has_no_chain_association() {
        let mut bps = BasicPeeringStrategy::<u32, Duration>::new(Config {
            randomness_seed: [0; 32],
            peers_capacity: 0,
            chains_capacity: 0,
        });

        let peer_id = PeerId::from_public_key(&PublicKey::Ed25519([0; 32]));

        assert!(matches!(
            bps.insert_address(&peer_id, Vec::new(), usize::MAX),
            InsertAddressResult::UnknownPeer
        ));

        assert_eq!(bps.peer_addresses(&peer_id).count(), 0);
    }

    #[test]
    fn address_connections_inserted_when_peer_has_no_chain_association() {
        let mut bps = BasicPeeringStrategy::<u32, Duration>::new(Config {
            randomness_seed: [0; 32],
            peers_capacity: 0,
            chains_capacity: 0,
        });

        let peer_id = PeerId::from_public_key(&PublicKey::Ed25519([0; 32]));

        assert!(matches!(
            bps.increase_address_connections(&peer_id, Vec::new(), usize::MAX),
            InsertAddressConnectionsResult::Inserted { .. }
        ));

        assert_eq!(bps.peer_addresses(&peer_id).count(), 1);
    }

    // TODO: more tests
}
