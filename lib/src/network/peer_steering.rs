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

//! Peer steering of a light client, the port of the `peer_steering` module of the full node's
//! statement protocol.
//!
//! The steering keeps the statement links of a chain aligned with the peers needed to cover the
//! subscribed topics. It keeps three sets of peers: the peers with an open statement substream,
//! the needed peers, and the reserved peers, the ones that the caller holds desired under the
//! statement gossip kind. Each refresh moves the reserved set toward the needed one.
//! [`PeerSteering::peers_to_reserve`] lists the needed peers to mark as desired, which dials
//! them and keeps their statement substream open. [`PeerSteering::peers_to_release`] lists the
//! reserved peers no longer needed. A refresh releases at most a fifth of the connected peers,
//! so that the set converges over several refreshes rather than churning at once. The cover of
//! the topics comes from the peers topology through
//! [`PeerSteering::update_peers_needing_connections`].
//!
//! Besides the cover, [`RANDOM_SLOTS`] links go to peers chosen at random among the known
//! statement peers, so that an attacker who surrounds a topic with peers of its own never holds
//! every link.
//!
//! A peer that refuses a link, or that the caller bans, is left alone until its ban ends, so
//! that it is not opened again at once. Statements keep flowing over the statement substreams
//! that follow the block announces substreams of the gossip peers. The steering reserves such
//! a peer like any other, and releasing it leaves its substream to the block announces
//! substream.
//!
//! The full node scores each link by the statements the peer delivers and drops the lowest
//! scores first. A light client validates statements outside of the network service, so the
//! links are dropped longest-held first.

use crate::util;
use alloc::vec::Vec;
use rand::seq::IteratorRandom as _;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore as _, SeedableRng as _},
};

pub use crate::libp2p::PeerId;

/// Upper bound, as a percent of the connected peers, on how many of them a single refresh
/// releases. Capping the churn lets the reserved set converge toward the needed one step by
/// step instead of dropping every unneeded link at once.
const MAX_DISCONNECT_PERCENT: usize = 20;

/// Number of links held with peers chosen at random rather than by topic.
pub const RANDOM_SLOTS: usize = 1;

/// Configuration passed to [`PeerSteering::new`].
pub struct Config {
    /// Seed used for the randomness of the hash maps and of the random slots.
    pub randomness_seed: [u8; 32],
}

/// Keeps the reserved statement peers aligned with the peers needed to cover the subscribed
/// topics.
///
/// The connected set is fed by the statement substream events, the needed and reserved sets by
/// the caller.
#[derive(Debug)]
pub struct PeerSteering<TNow> {
    /// Peers with an open statement substream.
    connected: hashbrown::HashMap<PeerId, ConnectedPeer, util::SipHasherBuild>,
    /// Monotonic counter handing each new connection its sequence.
    next_connection_seq: u64,
    /// Peers needed: the cover of the topics plus the peers of the random slots.
    desired: hashbrown::HashSet<PeerId, util::SipHasherBuild>,
    /// Peers that the caller holds desired under the statement gossip kind.
    reserved: hashbrown::HashSet<PeerId, util::SipHasherBuild>,
    /// Peers holding the random slots, at most [`RANDOM_SLOTS`].
    random: Vec<PeerId>,
    /// Peers not to be opened, with the end of their ban.
    banned: hashbrown::HashMap<PeerId, TNow, util::SipHasherBuild>,
    randomness: ChaCha20Rng,
}

/// The state of one connected peer.
#[derive(Debug)]
struct ConnectedPeer {
    /// Sequence at which the peer connected.
    seq: u64,
}

impl<TNow> PeerSteering<TNow>
where
    TNow: Clone + Ord,
{
    /// Builds a new steering with no connected, needed or reserved peer.
    pub fn new(config: Config) -> Self {
        let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);
        let mut hasher = || {
            util::SipHasherBuild::new({
                let mut seed = [0; 16];
                randomness.fill_bytes(&mut seed);
                seed
            })
        };

        PeerSteering {
            connected: hashbrown::HashMap::with_hasher(hasher()),
            next_connection_seq: 0,
            desired: hashbrown::HashSet::with_hasher(hasher()),
            reserved: hashbrown::HashSet::with_hasher(hasher()),
            random: Vec::with_capacity(RANDOM_SLOTS),
            banned: hashbrown::HashMap::with_hasher(hasher()),
            randomness,
        }
    }

    // === Connection events ===

    /// Record that the statement substream to `peer` opened.
    pub fn on_substream_opened(&mut self, peer: PeerId) {
        if !self.connected.contains_key(&peer) {
            self.connected.insert(
                peer,
                ConnectedPeer {
                    seq: self.next_connection_seq,
                },
            );
            self.next_connection_seq += 1;
        }
    }

    /// Record that the statement substream to `peer` closed. A random slot held by the peer is
    /// freed.
    pub fn on_substream_closed(&mut self, peer: &PeerId) {
        self.connected.remove(peer);
        self.random.retain(|p| p != peer);
    }

    /// Record that `peer` refused a link or was banned: it is not returned by
    /// [`PeerSteering::peers_to_reserve`] before `until`, and it frees its random slot.
    pub fn ban(&mut self, peer: PeerId, until: TNow) {
        self.on_substream_closed(&peer);
        self.banned.insert(peer, until);
    }

    // === Reserved set ===

    /// Replace the set of peers that the caller holds desired under the statement gossip kind.
    ///
    /// The caller drops that desire on its own when a link fails or closes, so it hands the
    /// set over at every refresh.
    pub fn update_reserved_peers(&mut self, peers: impl IntoIterator<Item = PeerId>) {
        self.reserved.clear();
        self.reserved.extend(peers);
    }

    // === Coverage target ===

    /// Replace the set of peers needed to cover the subscribed topics, and fill the random
    /// slots left empty from `candidates`. Bans that ended as of `now` are forgotten.
    pub fn update_peers_needing_connections<'a>(
        &mut self,
        peers: impl IntoIterator<Item = PeerId>,
        candidates: impl Iterator<Item = &'a PeerId>,
        now: &TNow,
    ) {
        self.banned.retain(|_, until| *until > *now);
        self.desired.clear();
        self.desired.extend(peers);

        // A random peer that the cover now needs, or that got banned, frees its slot. With no
        // cover there is nothing to protect, so the random slots go as well.
        self.random.retain(|p| {
            !self.desired.is_empty() && !self.desired.contains(p) && !self.banned.contains_key(p)
        });
        if !self.desired.is_empty() && self.random.len() < RANDOM_SLOTS {
            let picked = candidates
                .filter(|p| {
                    !self.desired.contains(*p)
                        && !self.banned.contains_key(*p)
                        && !self.random.contains(*p)
                })
                .choose_multiple(&mut self.randomness, RANDOM_SLOTS - self.random.len());
            self.random.extend(picked.into_iter().cloned());
        }

        self.desired.extend(self.random.iter().cloned());
    }

    /// Whether `peer` is needed, for the cover or for a random slot.
    pub fn is_desired(&self, peer: &PeerId) -> bool {
        self.desired.contains(peer)
    }

    // === Reconciliation ===

    /// Needed peers outside the reserved set and without a ban.
    pub fn peers_to_reserve(&self) -> Vec<PeerId> {
        self.desired
            .iter()
            .filter(|peer| !self.reserved.contains(*peer) && !self.banned.contains_key(*peer))
            .cloned()
            .collect()
    }

    /// Reserved peers no longer needed. A peer without an open substream is released at once.
    /// The connected ones go at most a fifth of the connected peers per refresh, and at least
    /// one, so that the set converges step by step. The longest-connected peers go first,
    /// spreading the disconnects across peers.
    pub fn peers_to_release(&self) -> Vec<PeerId> {
        let limit = (self.connected.len() * MAX_DISCONNECT_PERCENT / 100).max(1);
        let mut to_release = Vec::new();
        let mut to_disconnect: Vec<(u64, &PeerId)> = Vec::new();
        for peer in self
            .reserved
            .iter()
            .filter(|peer| !self.desired.contains(*peer))
        {
            match self.connected.get(peer) {
                Some(entry) => to_disconnect.push((entry.seq, peer)),
                None => to_release.push(peer.clone()),
            }
        }
        to_disconnect.sort();
        to_disconnect.truncate(limit);
        to_release.extend(to_disconnect.into_iter().map(|(_, peer)| peer.clone()));
        to_release
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, PeerSteering, RANDOM_SLOTS};
    use crate::libp2p::{PeerId, peer_id::PublicKey};
    use core::{iter, time::Duration};

    fn steering() -> PeerSteering<Duration> {
        PeerSteering::new(Config {
            randomness_seed: [0; 32],
        })
    }

    fn peer(seed: u8) -> PeerId {
        PeerId::from_public_key(&PublicKey::Ed25519([seed; 32]))
    }

    fn update(steering: &mut PeerSteering<Duration>, peers: impl IntoIterator<Item = PeerId>) {
        steering.update_peers_needing_connections(peers, iter::empty(), &Duration::ZERO);
    }

    #[test]
    fn substream_events_maintain_the_connected_set() {
        let mut steering = steering();

        steering.on_substream_opened(peer(1));
        steering.on_substream_opened(peer(2));
        assert_eq!(steering.connected.len(), 2);

        steering.on_substream_closed(&peer(1));
        assert_eq!(steering.connected.keys().collect::<Vec<_>>(), [&peer(2)]);
    }

    /// Opens a substream to each peer and marks it reserved, as a completed refresh leaves it.
    fn connect_reserved(
        steering: &mut PeerSteering<Duration>,
        seeds: impl IntoIterator<Item = u8>,
    ) {
        for seed in seeds {
            steering.on_substream_opened(peer(seed));
            steering.reserved.insert(peer(seed));
        }
    }

    #[test]
    fn reserves_desired_and_releases_undesired() {
        let mut steering = steering();
        // peer(1) is reserved and desired; peer(2) is reserved but undesired; peer(3) is desired
        // but not reserved; peer(4) is connected on its own and undesired.
        connect_reserved(&mut steering, [1, 2]);
        steering.on_substream_opened(peer(4));
        update(&mut steering, [peer(1), peer(3)]);

        assert_eq!(steering.peers_to_reserve(), vec![peer(3)]);
        assert_eq!(steering.peers_to_release(), vec![peer(2)]);
    }

    #[test]
    fn desired_peer_connected_on_its_own_is_reserved() {
        let mut steering = steering();
        steering.on_substream_opened(peer(1));
        update(&mut steering, [peer(1)]);

        assert_eq!(steering.peers_to_reserve(), vec![peer(1)]);
    }

    #[test]
    fn converged_set_has_no_work() {
        let mut steering = steering();
        connect_reserved(&mut steering, [1, 2]);
        update(&mut steering, [peer(1), peer(2)]);

        assert!(steering.peers_to_reserve().is_empty());
        assert!(steering.peers_to_release().is_empty());
    }

    #[test]
    fn unconnected_reserved_peers_are_released_at_once() {
        let mut steering = steering();
        connect_reserved(&mut steering, [1, 2, 3, 4, 5]);
        steering.update_reserved_peers((1..=7).map(peer));

        // The two idle peers go in full, plus one connected peer under the cap.
        let release = steering.peers_to_release();
        assert_eq!(release.len(), 3);
        assert!(release.contains(&peer(6)));
        assert!(release.contains(&peer(7)));
        assert!(release.contains(&peer(1)));
    }

    #[test]
    fn disconnects_are_capped_at_twenty_percent() {
        let mut steering = steering();
        connect_reserved(&mut steering, 1..=10);

        assert!(steering.peers_to_reserve().is_empty());
        // Two of ten connected peers, the longest-connected, with none desired.
        assert_eq!(steering.peers_to_release(), vec![peer(1), peer(2)]);
    }

    #[test]
    fn disconnects_drop_the_longest_connected_not_the_lowest_peer_id() {
        let mut steering = steering();
        // Connect the high peer ids first, so connection age and peer id rank disagree.
        connect_reserved(&mut steering, [10u8, 9, 1, 2]);

        // peer(10) connected first, so it is dropped before the lower-id peers.
        assert_eq!(steering.peers_to_release(), vec![peer(10)]);
    }

    #[test]
    fn capped_disconnects_drain_over_successive_refreshes() {
        let mut steering = steering();
        connect_reserved(&mut steering, 1..=10);

        let mut dropped = Vec::new();
        while !steering.connected.is_empty() {
            let release = steering.peers_to_release();
            assert!(release.len() <= 2, "each refresh drops at most a fifth");
            for peer in release {
                assert!(!dropped.contains(&peer), "no peer dropped twice");
                dropped.push(peer.clone());
                steering.reserved.remove(&peer);
                steering.on_substream_closed(&peer);
            }
        }

        assert_eq!(dropped.len(), 10);
    }

    #[test]
    fn banned_peers_wait_for_the_end_of_their_ban() {
        let mut steering = steering();
        let until = Duration::from_secs(10);
        steering.on_substream_opened(peer(1));
        steering.ban(peer(1), until);
        assert!(steering.connected.is_empty());

        steering.update_peers_needing_connections([peer(1)], iter::empty(), &Duration::ZERO);
        assert!(steering.peers_to_reserve().is_empty());
        steering.update_peers_needing_connections([peer(1)], iter::empty(), &until);
        assert_eq!(steering.peers_to_reserve(), vec![peer(1)]);
    }

    #[test]
    fn random_slots_add_to_the_cover_and_refill_when_their_link_closes() {
        let mut steering = steering();
        let known = (1..=20).map(peer).collect::<Vec<_>>();
        let candidates = || known.iter();

        steering.update_peers_needing_connections([peer(1)], candidates(), &Duration::ZERO);
        let random = steering.random.clone();
        assert_eq!(random.len(), RANDOM_SLOTS);
        assert!(!random.contains(&peer(1)));
        assert_eq!(steering.peers_to_reserve().len(), 1 + RANDOM_SLOTS);

        // The slot stays with its peer across refreshes, and a closed link frees it.
        steering.update_peers_needing_connections([peer(1)], candidates(), &Duration::ZERO);
        assert_eq!(steering.random, random);
        steering.on_substream_closed(&random[0]);
        steering.update_peers_needing_connections([peer(1)], candidates(), &Duration::ZERO);
        assert_eq!(steering.random.len(), RANDOM_SLOTS);
        assert!(steering.is_desired(&steering.random[0]));

        // The slot survives a refresh without candidates, and goes with the cover.
        update(&mut steering, [peer(1)]);
        assert_eq!(steering.peers_to_reserve().len(), 1 + RANDOM_SLOTS);
        update(&mut steering, []);
        assert!(steering.random.is_empty());
        assert!(steering.peers_to_reserve().is_empty());
    }
}
