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
//! subscribed topics. It tracks the open links and the needed peers.
//! [`PeerSteering::peers_to_connect`] and [`PeerSteering::peers_to_disconnect`] decide how to
//! align the former with the latter, the needed peers without a link and the linked peers no
//! longer needed, closing at most a fifth of the links per refresh so that
//! the set converges over several refreshes rather than churning at once. The caller applies
//! that decision by marking the peers as desired under the statement gossip kind, or by
//! removing them. The cover of the topics comes from the peers topology through
//! [`PeerSteering::update_peers_needing_connections`].
//!
//! Besides the cover, [`RANDOM_SLOTS`] links go to peers chosen at random among the known
//! statement peers, so that an attacker who surrounds a topic with peers of its own never holds
//! every link.
//!
//! A peer that refuses a link, or that the caller bans, is left alone until its ban ends, so
//! that it is not opened again at once. Statements keep flowing over the statement substreams
//! that follow the block announces substreams of the gossip peers, which the steering never
//! touches.
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

/// Upper bound, as a percent of the open links, on how many links a single refresh closes.
/// Capping the churn lets the linked set converge toward the needed one step by step instead of
/// dropping every unneeded link at once.
const MAX_DISCONNECT_PERCENT: usize = 20;

/// Number of links held with peers chosen at random rather than by topic.
pub const RANDOM_SLOTS: usize = 1;

/// Configuration passed to [`PeerSteering::new`].
pub struct Config {
    /// Seed used for the randomness of the hash maps and of the random slots.
    pub randomness_seed: [u8; 32],
}

/// Keeps the statement links aligned with the peers needed to cover the subscribed topics.
///
/// The linked set is fed by the statement link events, the needed set by the caller.
#[derive(Debug)]
pub struct PeerSteering<TNow> {
    /// Peers with an open statement link.
    connected: hashbrown::HashMap<PeerId, ConnectedPeer, util::SipHasherBuild>,
    /// Monotonic counter handing each new link its sequence.
    next_connection_seq: u64,
    /// Peers needed: the cover of the topics plus the peers of the random slots.
    desired: hashbrown::HashSet<PeerId, util::SipHasherBuild>,
    /// Peers holding the random slots, at most [`RANDOM_SLOTS`].
    random: Vec<PeerId>,
    /// Peers not to be opened, with the end of their ban.
    banned: hashbrown::HashMap<PeerId, TNow, util::SipHasherBuild>,
    randomness: ChaCha20Rng,
}

/// The state of one open link.
#[derive(Debug)]
struct ConnectedPeer {
    /// Sequence at which the link opened.
    seq: u64,
}

impl<TNow> PeerSteering<TNow>
where
    TNow: Clone + Ord,
{
    /// Builds a new steering with no link and no needed peer.
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
            random: Vec::with_capacity(RANDOM_SLOTS),
            banned: hashbrown::HashMap::with_hasher(hasher()),
            randomness,
        }
    }

    // === Link events ===

    /// Record that the statement link to `peer` opened.
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

    /// Record that the statement link to `peer` closed. A random slot held by the peer is
    /// freed.
    pub fn on_substream_closed(&mut self, peer: &PeerId) {
        self.connected.remove(peer);
        self.random.retain(|p| p != peer);
    }

    /// Record that `peer` refused a link or was banned: it is not returned by
    /// [`PeerSteering::peers_to_connect`] before `until`, and it frees its link and random slot.
    pub fn ban(&mut self, peer: PeerId, until: TNow) {
        self.on_substream_closed(&peer);
        self.banned.insert(peer, until);
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

    /// Needed peers without an open link and without a ban.
    pub fn peers_to_connect(&self) -> Vec<PeerId> {
        self.desired
            .iter()
            .filter(|peer| !self.connected.contains_key(*peer) && !self.banned.contains_key(*peer))
            .cloned()
            .collect()
    }

    /// Linked peers no longer needed, capped at a fifth of the open links
    /// (at least one while any remain) so that the set converges step by step. The
    /// longest-held links go first, spreading the disconnects across peers.
    pub fn peers_to_disconnect(&self) -> Vec<PeerId> {
        let limit = (self.connected.len() * MAX_DISCONNECT_PERCENT / 100).max(1);
        let mut peers: Vec<(u64, &PeerId)> = self
            .connected
            .iter()
            .filter(|(peer, _)| !self.desired.contains(*peer))
            .map(|(peer, entry)| (entry.seq, peer))
            .collect();
        peers.sort();
        peers.truncate(limit);
        peers.into_iter().map(|(_, peer)| peer.clone()).collect()
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
        assert_eq!(steering.peers_to_disconnect(), vec![peer(2)]);
    }

    #[test]
    fn connects_desired_and_disconnects_undesired() {
        let mut steering = steering();
        // peer(1) is connected and desired; peer(2) is connected but undesired; peer(3) is
        // desired but not connected.
        steering.on_substream_opened(peer(1));
        steering.on_substream_opened(peer(2));
        update(&mut steering, [peer(1), peer(3)]);

        assert_eq!(steering.peers_to_connect(), vec![peer(3)]);
        assert_eq!(steering.peers_to_disconnect(), vec![peer(2)]);
    }

    #[test]
    fn converged_set_has_no_work() {
        let mut steering = steering();
        steering.on_substream_opened(peer(1));
        steering.on_substream_opened(peer(2));
        update(&mut steering, [peer(1), peer(2)]);

        assert!(steering.peers_to_connect().is_empty());
        assert!(steering.peers_to_disconnect().is_empty());
    }

    #[test]
    fn disconnects_are_capped_at_twenty_percent() {
        let mut steering = steering();
        for seed in 1..=10 {
            steering.on_substream_opened(peer(seed));
        }

        assert!(steering.peers_to_connect().is_empty());
        // Two of ten connected peers, the longest-connected, with none desired.
        assert_eq!(steering.peers_to_disconnect(), vec![peer(1), peer(2)]);
    }

    #[test]
    fn disconnects_drop_the_longest_connected_not_the_lowest_peer_id() {
        let mut steering = steering();
        // Connect the high peer ids first, so connection age and peer id rank disagree.
        for seed in [10u8, 9, 1, 2] {
            steering.on_substream_opened(peer(seed));
        }

        // peer(10) connected first, so it is dropped before the lower-id peers.
        assert_eq!(steering.peers_to_disconnect(), vec![peer(10)]);
    }

    #[test]
    fn capped_disconnects_drain_over_successive_refreshes() {
        let mut steering = steering();
        for seed in 1..=10 {
            steering.on_substream_opened(peer(seed));
        }

        let mut dropped = Vec::new();
        while !steering.connected.is_empty() {
            let disconnect = steering.peers_to_disconnect();
            assert!(disconnect.len() <= 2, "each refresh drops at most a fifth");
            for peer in disconnect {
                assert!(!dropped.contains(&peer), "no peer dropped twice");
                dropped.push(peer.clone());
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
        assert!(steering.peers_to_connect().is_empty());
        steering.update_peers_needing_connections([peer(1)], iter::empty(), &until);
        assert_eq!(steering.peers_to_connect(), vec![peer(1)]);
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
        assert_eq!(steering.peers_to_connect().len(), 1 + RANDOM_SLOTS);

        // The slot stays with its peer across refreshes, and a closed link frees it.
        steering.update_peers_needing_connections([peer(1)], candidates(), &Duration::ZERO);
        assert_eq!(steering.random, random);
        steering.on_substream_closed(&random[0]);
        steering.update_peers_needing_connections([peer(1)], candidates(), &Duration::ZERO);
        assert_eq!(steering.random.len(), RANDOM_SLOTS);
        assert!(steering.is_desired(&steering.random[0]));

        // The slot survives a refresh without candidates, and goes with the cover.
        update(&mut steering, [peer(1)]);
        assert_eq!(steering.peers_to_connect().len(), 1 + RANDOM_SLOTS);
        update(&mut steering, []);
        assert!(steering.random.is_empty());
        assert!(steering.peers_to_connect().is_empty());
    }
}
