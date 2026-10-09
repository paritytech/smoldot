// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

//! Event-fed local view of the statement peers of a chain, the light client's port of the
//! `peers_topology` module of the full node's statement protocol.
//!
//! Every peer is mapped into the 32-byte topic key space by the blake2b-256 hash of its
//! [`PeerId`], and the distance to a topic is the XOR of the two keys. The full nodes keep a
//! topic on the `replication_factor` peers closest to it, so a light client that connects to
//! one of the closest known peers for a topic is likely to reach a holder of that topic.
//!
//! The topology is built from peers learned through discovery, Identify and statement
//! substreams, and remembers them after they disconnect, so that a peer close to a topic can be
//! connected again later. It computes XOR distances locally over that learned peer set and
//! never issues a topic-specific lookup, so that nobody learns which topics the local node
//! subscribes to.
//!
//! A light client is never a replica of a topic, so the affinity oracle and the routing of
//! statements between replicas of the full node have no counterpart here.

use crate::util;
use alloc::vec::Vec;
use core::{cmp::Reverse, num::NonZeroUsize, ops::Add, time::Duration};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore as _, SeedableRng as _},
};

pub use crate::libp2p::PeerId;

/// A point in the 32-byte key space shared by topics and hashed peer ids.
pub type Key = [u8; 32];

/// Evict a disconnected peer unseen by any event for this long.
const PEER_STALENESS_TTL: Duration = Duration::from_secs(2 * 60 * 60);

/// Hard cap on the known peers. Bounds memory when discovery outruns staleness eviction.
const MAX_KNOWN_PEERS: usize = 8192;

/// Configuration passed to [`PeersTopology::new`].
pub struct Config {
    /// Seed used for the randomness of the hash map holding the peers.
    pub randomness_seed: [u8; 32],

    /// Number of statement peers responsible for storing a topic, the replication factor of
    /// the full nodes.
    pub replication_factor: NonZeroUsize,
}

#[derive(Debug)]
struct PeerInfo<TNow> {
    supports_protocol: bool,
    /// The statement substream to the peer is open.
    connected: bool,
    /// Cached `peer_key`. The peer id never changes and hashing is costly.
    key: Key,
    /// Time of the most recent event observing this peer, the eviction key for both staleness
    /// and the capacity backstop.
    last_seen: TNow,
}

/// Local view of the statement peers of a chain. See the [module documentation](self).
///
/// Events only add peers. The caller runs [`PeersTopology::evict`] periodically to drop stale
/// peers and to hold the cap on the known peers.
#[derive(Debug)]
pub struct PeersTopology<TNow> {
    replication_factor: NonZeroUsize,
    /// Known remote peers, evicted by [`PeersTopology::evict`] once stale or over
    /// `MAX_KNOWN_PEERS`.
    discovered: hashbrown::HashMap<PeerId, PeerInfo<TNow>, util::SipHasherBuild>,
}

impl<TNow> PeersTopology<TNow>
where
    TNow: Clone + Ord + Add<Duration, Output = TNow>,
{
    /// Builds a new topology that knows no peer.
    pub fn new(config: Config) -> Self {
        let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

        PeersTopology {
            replication_factor: config.replication_factor,
            discovered: hashbrown::HashMap::with_hasher(util::SipHasherBuild::new({
                let mut seed = [0; 16];
                randomness.fill_bytes(&mut seed);
                seed
            })),
        }
    }

    /// Record that a FindNode response listed `peers`.
    pub fn on_peers_discovered(&mut self, peers: impl IntoIterator<Item = PeerId>, now: &TNow) {
        for peer in peers {
            self.get_or_insert_peer(peer, now);
        }
    }

    /// Record statement protocol support from the Identify response.
    ///
    /// Peers that do not support the statement protocol remain known but are excluded from
    /// the candidates for a topic.
    pub fn on_peer_identified(
        &mut self,
        peer: PeerId,
        supports_statement_protocol: bool,
        now: &TNow,
    ) {
        self.get_or_insert_peer(peer, now).supports_protocol = supports_statement_protocol;
    }

    /// Record that the statement substream to `peer` opened.
    ///
    /// An open substream implies statement protocol support.
    pub fn on_substream_opened(&mut self, peer: PeerId, now: &TNow) {
        let info = self.get_or_insert_peer(peer, now);
        info.supports_protocol = true;
        info.connected = true;
    }

    /// Record that the statement substream to `peer` closed.
    pub fn on_substream_closed(&mut self, peer: PeerId, now: &TNow) {
        if let Some(info) = self.discovered.get_mut(&peer) {
            info.connected = false;
            info.last_seen = now.clone().max(info.last_seen.clone());
        }
    }

    /// Number of known remote peers, including peers without confirmed statement protocol
    /// support.
    pub fn known_peers_count(&self) -> usize {
        self.discovered.len()
    }

    /// Closest known statement peers for `topic`.
    ///
    /// "Closest" is computed over the locally learned statement peers, not by querying the
    /// network for the true global closest peers.
    #[cfg(test)]
    fn closest_known(&self, topic: &Key, limit: usize) -> Vec<PeerId> {
        self.closest_known_keyed(topic, limit)
            .into_iter()
            .map(|(peer, _)| peer)
            .collect()
    }

    /// Local-only connection candidates for `topics`: a small set of peers, chosen greedily,
    /// covering every topic, each topic being covered by any of its `replication_factor`
    /// closest known peers.
    ///
    /// Only the locally learned topology is used, avoiding network lookups that would reveal
    /// the topics. The result does not depend on which peers are connected.
    pub fn peers_for_topics(&self, topics: &[Key]) -> Vec<PeerId> {
        let mut uncovered = topics
            .iter()
            .map(|topic| {
                let pool = self.closest_known_keyed(topic, self.replication_factor.get());
                (topic, pool)
            })
            .collect::<Vec<_>>();

        // A selected peer covers every topic whose pool holds it, so it never comes up again and
        // each round covers at least one more topic.
        let mut selected = Vec::new();
        while let Some(best_peer) = best_candidate(&uncovered) {
            uncovered.retain(|(_, pool)| !pool_contains(pool, &best_peer));
            selected.push(best_peer);
        }
        selected
    }

    /// Evict disconnected peers unseen for `PEER_STALENESS_TTL` as of `now`, plus any excess
    /// over `MAX_KNOWN_PEERS`, least recently seen first.
    /// Returns whether the candidates for a topic changed.
    pub fn evict(&mut self, now: &TNow) -> bool {
        let mut changed = false;
        loop {
            let over_cap = self.discovered.len() > MAX_KNOWN_PEERS;
            let Some((victim, last_seen)) = self
                .discovered
                .iter()
                .filter(|(_, info)| !info.connected)
                .min_by_key(|(_, info)| &info.last_seen)
                .map(|(peer, info)| (peer.clone(), info.last_seen.clone()))
            else {
                return changed;
            };
            if !over_cap && last_seen + PEER_STALENESS_TTL > *now {
                return changed;
            }
            if let Some(info) = self.discovered.remove(&victim) {
                changed |= info.supports_protocol;
            }
        }
    }

    /// Insert `peer` if absent, refresh its `last_seen`, and return its record.
    ///
    /// An event delivered late, with a `now` older than the last one, leaves `last_seen` alone.
    fn get_or_insert_peer(&mut self, peer: PeerId, now: &TNow) -> &mut PeerInfo<TNow> {
        let info = self
            .discovered
            .entry(peer)
            .or_insert_with_key(|peer| PeerInfo {
                supports_protocol: false,
                connected: false,
                key: peer_key(peer),
                last_seen: now.clone(),
            });
        info.last_seen = now.clone().max(info.last_seen.clone());
        info
    }

    /// `closest_known` paired with each peer's key, so callers that compute further distances
    /// reuse the key instead of looking it up again.
    fn closest_known_keyed(&self, topic: &Key, limit: usize) -> Vec<(PeerId, Key)> {
        let mut candidates = self
            .discovered
            .iter()
            .filter(|(_, info)| info.supports_protocol)
            .map(|(peer, info)| (xor_distance(topic, &info.key), peer, info.key))
            .collect::<Vec<_>>();
        candidates.sort_unstable();
        candidates
            .into_iter()
            .take(limit)
            .map(|(_, peer, key)| (peer.clone(), key))
            .collect()
    }
}

/// The peer covering the most uncovered topics, breaking ties by the smallest distance to any
/// topic it covers, then by the smallest peer id.
fn best_candidate(uncovered: &[(&Key, Vec<(PeerId, Key)>)]) -> Option<PeerId> {
    uncovered
        .iter()
        .flat_map(|(_, pool)| pool)
        .map(|(peer, key)| {
            let (covered_count, best_distance) = uncovered
                .iter()
                .filter(|(_, pool)| pool_contains(pool, peer))
                .map(|(topic, _)| xor_distance(topic, key))
                .fold((0usize, [u8::MAX; 32]), |(count, best), distance| {
                    (count + 1, best.min(distance))
                });
            (Reverse(covered_count), best_distance, peer)
        })
        .min()
        .map(|(_, _, peer)| peer.clone())
}

fn pool_contains(pool: &[(PeerId, Key)], peer: &PeerId) -> bool {
    pool.iter().any(|(candidate, _)| candidate == peer)
}

/// Map a peer id into the 32-byte topic key space, the same way as the full nodes.
///
/// The keys need not match the SHA-256 Kademlia keys because the topology never queries
/// Kademlia by topic.
fn peer_key(peer: &PeerId) -> Key {
    <[u8; 32]>::try_from(blake2_rfc::blake2b::blake2b(32, &[], peer.as_bytes()).as_bytes())
        .expect("blake2b output is 32 bytes; qed")
}

fn xor_distance(a: &Key, b: &Key) -> Key {
    core::array::from_fn(|i| a[i] ^ b[i])
}

#[cfg(test)]
mod tests {
    use super::{Config, MAX_KNOWN_PEERS, PEER_STALENESS_TTL, PeersTopology, peer_key};
    use crate::libp2p::{PeerId, peer_id::PublicKey};
    use core::{num::NonZeroUsize, time::Duration};

    fn topology(replication_factor: usize) -> PeersTopology<Duration> {
        PeersTopology::new(Config {
            randomness_seed: [0; 32],
            replication_factor: NonZeroUsize::new(replication_factor).unwrap(),
        })
    }

    /// A deterministic peer whose Ed25519 key is 32 bytes of `seed`. Its bytes are the identity
    /// multihash of the protobuf encoding of that key, accepted by the full node as well.
    fn peer(seed: u8) -> PeerId {
        PeerId::from_public_key(&PublicKey::Ed25519([seed; 32]))
    }

    /// A topic whose 32 bytes are all `n`.
    fn topic(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn dht_peer(topology: &mut PeersTopology<Duration>, peer: PeerId, now: Duration) {
        topology.on_peers_discovered([peer.clone()], &now);
        topology.on_peer_identified(peer, true, &now);
    }

    #[test]
    fn lifecycle_mutators_are_idempotent_and_filter_protocol_support() {
        let mut topology = topology(2);
        let now = Duration::ZERO;

        dht_peer(&mut topology, peer(2), now);
        dht_peer(&mut topology, peer(2), now);
        topology.on_peers_discovered([peer(3)], &now);
        topology.on_peer_identified(peer(3), false, &now);

        assert_eq!(topology.known_peers_count(), 2);
        assert_eq!(topology.closest_known(&topic(9), 10), vec![peer(2)]);
        assert_eq!(topology.peers_for_topics(&[topic(9)]), vec![peer(2)]);

        topology.on_peer_identified(peer(2), false, &now);
        assert!(topology.closest_known(&topic(9), 10).is_empty());
        assert!(topology.peers_for_topics(&[topic(9)]).is_empty());
        assert_eq!(topology.known_peers_count(), 2);

        // An open substream implies support, and closing it keeps the peer known.
        topology.on_substream_opened(peer(3), &now);
        assert_eq!(topology.closest_known(&topic(9), 10), vec![peer(3)]);
        topology.on_substream_closed(peer(3), &now);
        assert_eq!(topology.closest_known(&topic(9), 10), vec![peer(3)]);
        assert_eq!(topology.known_peers_count(), 2);
    }

    #[test]
    fn eviction_drops_stale_peers_and_bounds_known_peers() {
        let mut topology = topology(2);
        let start = Duration::from_secs(1);

        dht_peer(&mut topology, peer(2), start);
        topology.on_peers_discovered([peer(3)], &start);
        assert!(!topology.evict(&(start + PEER_STALENESS_TTL - Duration::from_secs(1))));
        assert_eq!(topology.known_peers_count(), 2);

        // Re-seeing peer 2 keeps it past the moment peer 3 goes stale. Dropping peer 3, which
        // never confirmed support, leaves the candidates unchanged.
        dht_peer(&mut topology, peer(2), start + Duration::from_secs(1));
        assert!(!topology.evict(&(start + PEER_STALENESS_TTL)));
        assert_eq!(topology.known_peers_count(), 1);
        assert!(topology.evict(&(start + PEER_STALENESS_TTL + Duration::from_secs(1))));
        assert_eq!(topology.known_peers_count(), 0);

        // A connected peer outlives the TTL, and an event with an older `now` leaves
        // `last_seen` in place.
        topology.on_substream_opened(peer(2), &start);
        dht_peer(&mut topology, peer(3), start);
        topology.on_peers_discovered([peer(3)], &Duration::ZERO);
        assert!(topology.evict(&(start + PEER_STALENESS_TTL)));
        assert_eq!(topology.closest_known(&topic(9), 10), vec![peer(2)]);
        topology.on_substream_closed(peer(2), &(start + PEER_STALENESS_TTL));
        assert!(topology.evict(&(start + 2 * PEER_STALENESS_TTL)));
        assert_eq!(topology.known_peers_count(), 0);

        // Over the cap, the least recently seen peers go first.
        let numbered = |n: u32| {
            let mut key = [0; 32];
            key[..4].copy_from_slice(&n.to_be_bytes());
            PeerId::from_public_key(&PublicKey::Ed25519(key))
        };
        for n in 0..(MAX_KNOWN_PEERS + 50) as u32 {
            dht_peer(
                &mut topology,
                numbered(n),
                start + Duration::from_secs(n.into()),
            );
        }
        dht_peer(
            &mut topology,
            numbered(0),
            start + Duration::from_secs(1 << 20),
        );
        assert!(topology.evict(&start));
        assert_eq!(topology.known_peers_count(), MAX_KNOWN_PEERS);
        let known = topology.closest_known(&topic(9), MAX_KNOWN_PEERS);
        assert!(known.contains(&numbered(0)));
        assert!(!known.contains(&numbered(1)));
        assert!(!known.contains(&numbered(50)));
        assert!(known.contains(&numbered(51)));
    }

    #[test]
    fn queries_match_a_full_node() {
        // Hash computed by a full node from the bytes of `peer(2)`.
        assert_eq!(
            hex::encode(peer_key(&peer(2))),
            "f95abd8fe9f05189865904405fab05419f373b132feec4ae65eb48682588badf"
        );

        // Answers of the peers topology of a full node fed with the same peers: the seeds of
        // the seven closest peers to each topic, then the seeds of the cover of all the topics.
        // The tests of the full node use other peer bytes, a raw identity multihash of 32 bytes
        // of `seed`, so their expected values differ from these.
        type Vector = (
            core::ops::RangeInclusive<u8>,
            usize,
            &'static [u8],
            &'static [&'static [u8]],
            &'static [u8],
        );
        let vectors: [Vector; 3] = [
            (
                2..=30,
                2,
                &[1, 9, 17],
                &[
                    &[15, 7, 12, 21, 4, 5, 13],
                    &[15, 7, 21, 4, 12, 13, 5],
                    &[12, 21, 4, 15, 7, 16, 27],
                ],
                &[15, 12],
            ),
            (
                2..=30,
                20,
                &[1, 9, 17],
                &[
                    &[15, 7, 12, 21, 4, 5, 13],
                    &[15, 7, 21, 4, 12, 13, 5],
                    &[12, 21, 4, 15, 7, 16, 27],
                ],
                &[15],
            ),
            (
                2..=200,
                20,
                &[1, 9, 17, 42, 200],
                &[
                    &[166, 15, 33, 7, 69, 66, 174],
                    &[66, 174, 121, 44, 123, 46, 59],
                    &[94, 196, 64, 12, 68, 45, 51],
                    &[137, 138, 13, 109, 67, 141, 84],
                    &[100, 93, 90, 135, 187, 73, 102],
                ],
                &[166, 100, 137],
            ),
        ];

        for (seeds, replication_factor, topics, closest, cover) in vectors {
            let mut topology = topology(replication_factor);
            for seed in seeds.clone() {
                dht_peer(&mut topology, peer(seed), Duration::ZERO);
            }
            let seed_of = |p: PeerId| seeds.clone().find(|s| peer(*s) == p).unwrap();

            for (topic_seed, expected) in topics.iter().zip(closest) {
                let actual = topology.closest_known(&topic(*topic_seed), 7);
                assert_eq!(
                    actual.into_iter().map(seed_of).collect::<Vec<_>>(),
                    *expected,
                    "closest to topic {topic_seed}"
                );
            }

            let topics = topics.iter().map(|t| topic(*t)).collect::<Vec<_>>();
            let actual = topology.peers_for_topics(&topics);
            assert_eq!(actual.into_iter().map(seed_of).collect::<Vec<_>>(), cover);
        }
    }
}
