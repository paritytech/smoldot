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

//! Tests of the gossip links state machine, with two [`ChainNetwork`]s talking to each other
//! over an in-memory encrypted byte pipe, the same way `collection::tests` does.

use super::{
    ChainConfig, ChainId, ChainNetwork, Config, ConnectionId, Event, GossipKind,
    NotificationsOutErr, OpenGossipError, PeerId, RemoveChainError, SingleStreamConnectionTask,
    SingleStreamHandshakeKind, established, peer_id,
};
use crate::libp2p::{connection::noise::NoiseKey, read_write::ReadWrite};
use crate::network::codec::{self, Role};
use alloc::vec::Vec;
use core::{cmp, mem, time::Duration};

/// Maximum size of the byte pipe between the two connection tasks.
const BUF: usize = 65536;

/// Asserts how many events of the given side match the pattern. The short form names the side
/// and the event variant without their type.
macro_rules! assert_count {
    ($events:expr, $side:ident, $event:ident, $expected:expr) => {
        assert_count!($events, Side::$side, Event::$event { .. }, $expected)
    };
    ($events:expr, $side:expr, $pattern:pat, $expected:expr) => {
        assert_eq!(
            $events
                .iter()
                .filter(|(s, e)| *s == $side && matches!(e, $pattern))
                .count(),
            $expected
        )
    };
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Side {
    Alice,
    Bob,
}

/// A single node: a [`ChainNetwork`] with one chain plus its one connection task.
struct Node {
    network: ChainNetwork<(), (), Duration>,
    chain_id: ChainId,
    task: Option<SingleStreamConnectionTask<Duration>>,
    conn_id: ConnectionId,
    /// [`PeerId`] of the other side.
    remote: PeerId,
}

/// Two nodes (Alice the initiator, Bob the responder) connected by an encrypted byte pipe. Bytes
/// written by Alice's connection task are read by Bob's and vice versa.
struct Harness {
    alice: Node,
    bob: Node,
    /// Bytes written by Alice, waiting to be read by Bob.
    a2b: Vec<u8>,
    /// Bytes written by Bob, waiting to be read by Alice.
    b2a: Vec<u8>,
    now: Duration,
    /// Last `wake_up_after` requested by each side's connection task.
    wake_a: Option<Duration>,
    wake_b: Option<Duration>,
}

fn peer_id_of(noise_key: &NoiseKey) -> PeerId {
    PeerId::from_public_key(&peer_id::PublicKey::Ed25519(
        *noise_key.libp2p_public_ed25519_key(),
    ))
}

fn make_node(
    is_initiator: bool,
    noise_key: &NoiseKey,
    remote_noise_key: &NoiseKey,
    seed: [u8; 32],
    enable_statement_protocol: bool,
) -> Node {
    let mut network = ChainNetwork::<(), (), Duration>::new(Config {
        connections_capacity: 1,
        chains_capacity: 1,
        randomness_seed: seed,
        handshake_timeout: Duration::from_secs(10),
    });

    let chain_id = network
        .add_chain(ChainConfig {
            user_data: (),
            genesis_hash: [1; 32],
            fork_id: None,
            block_number_bytes: 4,
            grandpa_protocol_config: None,
            allow_inbound_block_requests: false,
            best_hash: [1; 32],
            best_number: 0,
            role: Role::Light,
            enable_statement_protocol,
        })
        .unwrap();

    let remote = peer_id_of(remote_noise_key);

    // The expected `PeerId` is what registers the connection under the peer, the way the light
    // client always dials.
    let (conn_id, task) = network.add_single_stream_connection(
        Duration::ZERO,
        SingleStreamHandshakeKind::MultistreamSelectNoiseYamux {
            is_initiator,
            noise_key,
        },
        Vec::new(),
        Some(remote.clone()),
        (),
    );

    Node {
        network,
        chain_id,
        task: Some(task),
        conn_id,
        remote,
    }
}

impl Harness {
    /// Builds the two nodes and runs the connection handshake to completion.
    fn connected(alice_statement_protocol: bool, bob_statement_protocol: bool) -> Self {
        let alice_key = NoiseKey::new(&[1; 32], &[2; 32]);
        let bob_key = NoiseKey::new(&[3; 32], &[4; 32]);
        let mut harness = Harness {
            alice: make_node(
                true,
                &alice_key,
                &bob_key,
                [7; 32],
                alice_statement_protocol,
            ),
            bob: make_node(false, &bob_key, &alice_key, [9; 32], bob_statement_protocol),
            a2b: Vec::new(),
            b2a: Vec::new(),
            now: Duration::ZERO,
            wake_a: None,
            wake_b: None,
        };

        let events = harness.pump();
        assert_count!(events, Alice, HandshakeFinished, 1);
        assert_count!(events, Bob, HandshakeFinished, 1);
        harness
    }

    fn node(&mut self, side: Side) -> &mut Node {
        match side {
            Side::Alice => &mut self.alice,
            Side::Bob => &mut self.bob,
        }
    }

    /// Delivers all pending coordinator->connection messages for the given side.
    fn deliver_coord_to_conn(&mut self, side: Side) -> bool {
        let now = self.now;
        let node = self.node(side);
        let mut progress = false;
        while let Some((_cid, msg)) = node.network.pull_message_to_connection() {
            if let Some(task) = node.task.as_mut() {
                task.inject_coordinator_message(&now, msg);
            }
            progress = true;
        }
        progress
    }

    /// Pulls all connection->coordinator messages for the given side and injects them into its
    /// coordinator. Does not call `next_event`.
    fn drain_conn_to_coord(&mut self, side: Side) -> bool {
        let node = self.node(side);
        let mut progress = false;
        loop {
            let Some(task) = node.task.take() else {
                break;
            };
            let (task_back, msg) = task.pull_message_to_coordinator();
            node.task = task_back;
            match msg {
                Some(m) => {
                    node.network.inject_connection_message(node.conn_id, m);
                    progress = true;
                }
                None => break,
            }
            if node.task.is_none() {
                break;
            }
        }
        progress
    }

    fn read_write(&mut self, side: Side) -> bool {
        let now = self.now;
        let (task, incoming, outgoing, wake) = match side {
            Side::Alice => (
                self.alice.task.as_mut(),
                &mut self.b2a,
                &mut self.a2b,
                &mut self.wake_a,
            ),
            Side::Bob => (
                self.bob.task.as_mut(),
                &mut self.a2b,
                &mut self.b2a,
                &mut self.wake_b,
            ),
        };
        // A reset task must not read or write again. Its remaining messages are exchanged with
        // the coordinator until it exits.
        let Some(task) = task.filter(|t| !t.is_reset_called()) else {
            return false;
        };
        let out_len_before = outgoing.len();
        let mut rw = ReadWrite {
            now,
            incoming_buffer: mem::take(incoming),
            expected_incoming_bytes: Some(0),
            read_bytes: 0,
            write_bytes_queued: outgoing.len(),
            write_bytes_queueable: Some(BUF - outgoing.len()),
            write_buffers: vec![mem::take(outgoing)],
            wake_up_after: *wake,
        };
        task.read_write(&mut rw);
        let read = rw.read_bytes;
        *wake = rw.wake_up_after;
        *incoming = rw.incoming_buffer;
        *outgoing = rw.write_buffers.drain(..).flatten().collect();
        read != 0 || outgoing.len() != out_len_before
    }

    /// Pulls every pending event of the given side, answering each [`Event::GossipInDesired`]
    /// with a link of its own, the way the light client does.
    fn next_events(&mut self, side: Side) -> Vec<Event<()>> {
        let node = self.node(side);
        let mut events = Vec::new();
        while let Some(event) = node.network.next_event() {
            if let Event::GossipInDesired {
                peer_id,
                chain_id,
                kind,
            } = &event
            {
                node.network.gossip_open(*chain_id, peer_id, *kind).unwrap();
            }
            events.push(event);
        }
        events
    }

    /// Runs the system until nothing more happens and returns every event produced along the
    /// way. When neither side can make byte progress but a connection task has asked to be
    /// woken up, time is advanced to that instant. Advancing is bounded so that idle-but-alive
    /// connections, which keep asking to be woken for pings, don't loop forever.
    fn pump(&mut self) -> Vec<(Side, Event<()>)> {
        let mut events = Vec::new();
        let ceiling = self.now + Duration::from_millis(100);
        let mut idle_advances = 0u32;
        loop {
            let mut progress = false;
            progress |= self.deliver_coord_to_conn(Side::Alice);
            progress |= self.deliver_coord_to_conn(Side::Bob);
            progress |= self.read_write(Side::Alice);
            progress |= self.read_write(Side::Bob);
            progress |= self.drain_conn_to_coord(Side::Alice);
            progress |= self.drain_conn_to_coord(Side::Bob);
            for side in [Side::Alice, Side::Bob] {
                for event in self.next_events(side) {
                    events.push((side, event));
                    progress = true;
                }
            }
            if progress {
                idle_advances = 0;
                continue;
            }

            let next_wake = [self.wake_a, self.wake_b].into_iter().flatten().min();
            match next_wake {
                Some(w)
                    if idle_advances < 100
                        && cmp::max(self.now, w) + Duration::from_nanos(1) <= ceiling =>
                {
                    self.now = cmp::max(self.now, w) + Duration::from_nanos(1);
                    idle_advances += 1;
                }
                _ => break,
            }
        }
        events
    }

    /// Resets the connection task of the given side, the way a dropped socket does, and runs
    /// the shutdown to completion. Returns every event produced along the way.
    fn reset(&mut self, side: Side) -> Vec<(Side, Event<()>)> {
        self.node(side).task.as_mut().unwrap().reset();
        let events = self.pump();
        assert!(self.node(side).task.is_none(), "reset task didn't exit");
        events
    }

    /// Opens a gossip link from Alice to Bob, accepted by Bob, and returns the events produced
    /// along the way.
    fn open_gossip_link(&mut self) -> Vec<(Side, Event<()>)> {
        self.alice
            .network
            .gossip_open(
                self.alice.chain_id,
                &self.alice.remote,
                GossipKind::ConsensusTransactions,
            )
            .unwrap();
        let events = self.pump();
        assert_count!(events, Alice, GossipConnected, 1);
        assert_count!(events, Bob, GossipConnected, 1);
        events
    }
}

/// Opening a gossip link reports on both sides.
#[test]
fn gossip_link_opens() {
    let mut harness = Harness::connected(false, false);
    harness.open_gossip_link();
    assert!(harness.alice.network.gossip_is_connected(
        harness.alice.chain_id,
        &harness.alice.remote,
        GossipKind::ConsensusTransactions
    ));
    assert!(harness.bob.network.gossip_is_connected(
        harness.bob.chain_id,
        &harness.bob.remote,
        GossipKind::ConsensusTransactions
    ));
}

/// Without a statement link, the statement substream follows the block announces substream.
#[test]
fn statement_substream_follows_block_announces() {
    let mut harness = Harness::connected(true, true);
    let bob = harness.alice.remote.clone();
    let chain_id = harness.alice.chain_id;

    let events = harness.open_gossip_link();
    assert_count!(events, Alice, StatementProtocolConnected, 1);
    assert!(
        harness
            .alice
            .network
            .gossip_is_connected(chain_id, &bob, GossipKind::Statement)
    );

    harness
        .alice
        .network
        .gossip_close(chain_id, &bob, GossipKind::ConsensusTransactions)
        .unwrap();
    assert!(
        !harness
            .alice
            .network
            .gossip_is_connected(chain_id, &bob, GossipKind::Statement)
    );

    let events = harness.pump();
    assert_count!(events, Bob, GossipDisconnected, 1);
    assert_count!(events, Alice, StatementProtocolDisconnected, 0);
}

/// Losing the connection on one side ends that side's gossip link with one event. The other
/// side is never told, the way a dropped socket looks from the outside.
#[test]
fn gossip_link_lost_with_connection() {
    let mut harness = Harness::connected(false, false);
    harness.open_gossip_link();

    let events = harness.reset(Side::Alice);
    assert_count!(events, Alice, GossipDisconnected, 1);
    assert_count!(events, Bob, GossipDisconnected, 0);
}

/// Opening a statement link needs no block announces substream, and reports through the
/// statement events only.
#[test]
fn statement_link_opens_without_block_announces() {
    let mut harness = Harness::connected(true, true);
    let alice = harness.bob.remote.clone();
    let bob = harness.alice.remote.clone();

    // Bob accepts the inbound statement substream because it desires Alice under that kind.
    harness.bob.network.gossip_insert_desired(
        harness.bob.chain_id,
        alice.clone(),
        GossipKind::Statement,
    );
    harness
        .alice
        .network
        .gossip_open(harness.alice.chain_id, &bob, GossipKind::Statement)
        .unwrap();

    let events = harness.pump();
    assert_count!(
        events,
        Side::Alice,
        Event::StatementProtocolConnected {
            version: codec::StatementProtocolVersion::V2,
            ..
        },
        1
    );
    assert_count!(events, Alice, GossipConnected, 0);
    assert_count!(events, Bob, GossipConnected, 0);

    let alice_network = &harness.alice.network;
    assert!(alice_network.gossip_is_connected(harness.alice.chain_id, &bob, GossipKind::Statement));
    assert!(!alice_network.gossip_is_connected(
        harness.alice.chain_id,
        &bob,
        GossipKind::ConsensusTransactions
    ));
    assert!(
        alice_network
            .gossip_connected_peers(harness.alice.chain_id, GossipKind::Statement)
            .any(|p| *p == bob)
    );
    assert_eq!(
        alice_network
            .gossip_connected_peers(harness.alice.chain_id, GossipKind::ConsensusTransactions)
            .count(),
        0
    );

    // Bob opens its own statement substream, as a peer does once it is gossip-connected.
    // Without it, Bob drops Alice's notifications the way it drops block announces from a peer
    // it has no outbound substream with.
    harness
        .bob
        .network
        .gossip_open(harness.bob.chain_id, &alice, GossipKind::Statement)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Bob, StatementProtocolConnected, 1);

    // The statement substream is usable on its own.
    let filter = codec::AffinityFilter::new(0, 0.01, 8);
    harness
        .alice
        .network
        .send_topic_affinity(&bob, harness.alice.chain_id, &filter)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Bob, StatementTopicAffinityReceived, 1);

    assert!(matches!(
        harness
            .alice
            .network
            .gossip_open(harness.alice.chain_id, &bob, GossipKind::Statement),
        Err(OpenGossipError::AlreadyOpened)
    ));
}

/// A peer without the statement protocol makes the link fail after the V2 to V1 fallback, and
/// the peer goes back to the list of desired peers to open.
#[test]
fn statement_link_refused_by_unsupported_protocol() {
    let mut harness = Harness::connected(true, false);
    let bob = harness.alice.remote.clone();
    let chain_id = harness.alice.chain_id;

    harness
        .alice
        .network
        .gossip_insert_desired(chain_id, bob.clone(), GossipKind::Statement);
    assert!(
        harness
            .alice
            .network
            .connected_unopened_gossip_desired()
            .any(|(p, c, k)| *p == bob && c == chain_id && k == GossipKind::Statement)
    );

    harness
        .alice
        .network
        .gossip_open(chain_id, &bob, GossipKind::Statement)
        .unwrap();
    assert_eq!(
        harness
            .alice
            .network
            .connected_unopened_gossip_desired()
            .count(),
        0
    );

    let events = harness.pump();
    assert_count!(
        events,
        Side::Alice,
        Event::StatementProtocolOpenFailed {
            error: NotificationsOutErr::Substream(
                established::NotificationsOutErr::ProtocolNotAvailable
            ),
            ..
        },
        1
    );
    assert_count!(events, Alice, StatementProtocolConnected, 0);
    assert!(!harness.alice.network.gossip_link_exists(
        chain_id.0,
        harness.alice.network.peers_by_peer_id[&bob],
        GossipKind::Statement
    ));
    assert!(
        harness
            .alice
            .network
            .connected_unopened_gossip_desired()
            .any(|(p, c, k)| *p == bob && c == chain_id && k == GossipKind::Statement)
    );
}

/// A peer that supports the statement protocol but refuses a statement-only substream, which is
/// what a full node without slots for it does, makes the link fail without a retry.
#[test]
fn statement_link_refused_by_peer_policy() {
    let mut harness = Harness::connected(true, true);
    let bob = harness.alice.remote.clone();
    let chain_id = harness.alice.chain_id;

    harness
        .alice
        .network
        .gossip_open(chain_id, &bob, GossipKind::Statement)
        .unwrap();

    let events = harness.pump();
    assert_count!(events, Alice, StatementProtocolOpenFailed, 1);
    assert_count!(
        events,
        Side::Alice,
        Event::StatementProtocolOpenFailed {
            error: NotificationsOutErr::Substream(
                established::NotificationsOutErr::RefusedHandshake
            ),
            ..
        },
        1
    );
    assert_count!(events, Alice, StatementProtocolConnected, 0);
    assert!(
        !harness
            .alice
            .network
            .gossip_is_connected(chain_id, &bob, GossipKind::Statement)
    );
    assert!(matches!(
        harness
            .alice
            .network
            .gossip_close(chain_id, &bob, GossipKind::Statement),
        Err(super::CloseGossipError::NotOpen)
    ));
}

/// The remote closing the statement substream ends the link with an event and no reopen.
#[test]
fn statement_link_closed_by_remote() {
    let mut harness = Harness::connected(true, true);
    let alice = harness.bob.remote.clone();
    let bob = harness.alice.remote.clone();
    let chain_id = harness.alice.chain_id;

    harness.bob.network.gossip_insert_desired(
        harness.bob.chain_id,
        alice.clone(),
        GossipKind::Statement,
    );
    harness
        .alice
        .network
        .gossip_insert_desired(chain_id, bob.clone(), GossipKind::Statement);
    harness
        .alice
        .network
        .gossip_open(chain_id, &bob, GossipKind::Statement)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Alice, StatementProtocolConnected, 1);

    harness
        .bob
        .network
        .gossip_close(harness.bob.chain_id, &alice, GossipKind::Statement)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Alice, StatementProtocolDisconnected, 1);
    assert_count!(events, Alice, StatementProtocolConnected, 0);
    assert!(!harness.alice.network.gossip_link_exists(
        chain_id.0,
        harness.alice.network.peers_by_peer_id[&bob],
        GossipKind::Statement
    ));
    assert!(
        harness
            .alice
            .network
            .connected_unopened_gossip_desired()
            .any(|(p, c, k)| *p == bob && c == chain_id && k == GossipKind::Statement)
    );
}

/// With both kinds on one peer, closing the block announces link keeps the statement link, on
/// both sides, and the statement substream still carries notifications.
#[test]
fn statement_link_survives_block_announces_close() {
    let mut harness = Harness::connected(true, true);
    let alice = harness.bob.remote.clone();
    let bob = harness.alice.remote.clone();
    let chain_id = harness.alice.chain_id;

    let events = harness.open_gossip_link();
    assert_count!(events, Alice, StatementProtocolConnected, 1);
    assert_count!(events, Bob, StatementProtocolConnected, 1);

    harness
        .alice
        .network
        .gossip_insert_desired(chain_id, bob.clone(), GossipKind::Statement);
    harness.bob.network.gossip_insert_desired(
        harness.bob.chain_id,
        alice.clone(),
        GossipKind::Statement,
    );
    // The existing statement substreams anchor the links: nothing is left to open.
    assert_eq!(
        harness
            .alice
            .network
            .connected_unopened_gossip_desired()
            .count(),
        0
    );

    harness
        .alice
        .network
        .gossip_close(chain_id, &bob, GossipKind::ConsensusTransactions)
        .unwrap();
    assert!(
        harness
            .alice
            .network
            .gossip_is_connected(chain_id, &bob, GossipKind::Statement)
    );

    let events = harness.pump();
    assert_count!(events, Bob, GossipDisconnected, 1);
    assert_count!(events, Alice, StatementProtocolDisconnected, 0);
    assert_count!(events, Bob, StatementProtocolDisconnected, 0);
    // The statement substreams stayed open rather than being closed and reopened.
    assert_count!(events, Alice, StatementProtocolConnected, 0);
    assert_count!(events, Bob, StatementProtocolConnected, 0);
    assert!(harness.bob.network.gossip_is_connected(
        harness.bob.chain_id,
        &alice,
        GossipKind::Statement
    ));

    let filter = codec::AffinityFilter::new(0, 0.01, 8);
    harness
        .alice
        .network
        .send_topic_affinity(&bob, chain_id, &filter)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Bob, StatementTopicAffinityReceived, 1);
}

/// Opening a statement link on a peer whose statement substream follows the block announces
/// substream turns that substream into the anchor of the link.
#[test]
fn opening_statement_link_adopts_following_substream() {
    let mut harness = Harness::connected(true, true);
    let alice = harness.bob.remote.clone();
    let bob = harness.alice.remote.clone();
    let chain_id = harness.alice.chain_id;

    harness.open_gossip_link();
    harness.bob.network.gossip_insert_desired(
        harness.bob.chain_id,
        alice.clone(),
        GossipKind::Statement,
    );

    assert!(matches!(
        harness
            .alice
            .network
            .gossip_open(chain_id, &bob, GossipKind::Statement),
        Err(OpenGossipError::AlreadyOpened)
    ));
    assert!(
        harness
            .alice
            .network
            .opened_gossip_undesired()
            .any(|(p, c, k)| *p == bob && c == chain_id && k == GossipKind::Statement)
    );

    harness
        .alice
        .network
        .gossip_close(chain_id, &bob, GossipKind::ConsensusTransactions)
        .unwrap();
    assert!(
        harness
            .alice
            .network
            .gossip_is_connected(chain_id, &bob, GossipKind::Statement)
    );

    let events = harness.pump();
    assert_count!(events, Bob, GossipDisconnected, 1);
    assert_count!(events, Alice, StatementProtocolDisconnected, 0);
    assert_count!(events, Alice, StatementProtocolConnected, 0);

    let filter = codec::AffinityFilter::new(0, 0.01, 8);
    harness
        .alice
        .network
        .send_topic_affinity(&bob, chain_id, &filter)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Bob, StatementTopicAffinityReceived, 1);

    harness
        .alice
        .network
        .gossip_close(chain_id, &bob, GossipKind::Statement)
        .unwrap();
    assert_eq!(harness.alice.network.opened_gossip_undesired().count(), 0);
}

/// A block announces link opened on top of a statement link reuses the statement substream.
#[test]
fn block_announces_link_reuses_statement_link() {
    let mut harness = Harness::connected(true, true);
    let alice = harness.bob.remote.clone();
    let bob = harness.alice.remote.clone();
    let chain_id = harness.alice.chain_id;

    harness.bob.network.gossip_insert_desired(
        harness.bob.chain_id,
        alice.clone(),
        GossipKind::Statement,
    );
    harness
        .alice
        .network
        .gossip_open(chain_id, &bob, GossipKind::Statement)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Alice, StatementProtocolConnected, 1);

    let events = harness.open_gossip_link();
    assert_count!(events, Alice, StatementProtocolConnected, 0);
    assert_count!(events, Alice, StatementProtocolDisconnected, 0);
    assert!(
        harness
            .alice
            .network
            .gossip_is_connected(chain_id, &bob, GossipKind::Statement)
    );
    assert!(matches!(
        harness
            .alice
            .network
            .gossip_open(chain_id, &bob, GossipKind::Statement),
        Err(OpenGossipError::AlreadyOpened)
    ));

    harness
        .alice
        .network
        .gossip_close(chain_id, &bob, GossipKind::ConsensusTransactions)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Bob, GossipDisconnected, 1);
    assert_count!(events, Alice, StatementProtocolDisconnected, 0);
    assert!(
        harness
            .alice
            .network
            .gossip_is_connected(chain_id, &bob, GossipKind::Statement)
    );
}

/// Removing a peer from the desired peers of every chain keeps its statement link as an
/// undesired but open link, the same way the per-chain removal does.
#[test]
fn removing_desire_from_all_chains_keeps_statement_link() {
    let mut harness = Harness::connected(true, true);
    let alice = harness.bob.remote.clone();
    let bob = harness.alice.remote.clone();
    let chain_id = harness.alice.chain_id;

    harness.bob.network.gossip_insert_desired(
        harness.bob.chain_id,
        alice.clone(),
        GossipKind::Statement,
    );
    harness
        .alice
        .network
        .gossip_insert_desired(chain_id, bob.clone(), GossipKind::Statement);
    harness
        .alice
        .network
        .gossip_open(chain_id, &bob, GossipKind::Statement)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Alice, StatementProtocolConnected, 1);

    harness
        .alice
        .network
        .gossip_remove_desired_all(&bob, GossipKind::Statement);
    assert!(
        harness
            .alice
            .network
            .opened_gossip_undesired()
            .any(|(p, c, k)| *p == bob && c == chain_id && k == GossipKind::Statement)
    );

    harness
        .bob
        .network
        .gossip_close(harness.bob.chain_id, &alice, GossipKind::Statement)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Alice, StatementProtocolDisconnected, 1);
    assert_count!(events, Alice, StatementProtocolConnected, 0);
    assert_eq!(harness.alice.network.opened_gossip_undesired().count(), 0);
}

/// Removing a chain refuses while a statement link is open, and forgets a pending one.
#[test]
fn remove_chain_forgets_statement_links() {
    let mut harness = Harness::connected(true, true);
    let alice = harness.bob.remote.clone();
    let bob = harness.alice.remote.clone();
    let chain_id = harness.alice.chain_id;

    harness.bob.network.gossip_insert_desired(
        harness.bob.chain_id,
        alice.clone(),
        GossipKind::Statement,
    );
    harness
        .alice
        .network
        .gossip_open(chain_id, &bob, GossipKind::Statement)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Alice, StatementProtocolConnected, 1);
    assert!(matches!(
        harness.alice.network.remove_chain(chain_id),
        Err(RemoveChainError::InUse)
    ));

    harness
        .alice
        .network
        .gossip_close(chain_id, &bob, GossipKind::Statement)
        .unwrap();
    harness.pump();

    harness
        .alice
        .network
        .gossip_open(chain_id, &bob, GossipKind::Statement)
        .unwrap();
    assert_eq!(harness.alice.network.opened_gossip_undesired().count(), 1);
    harness.alice.network.remove_chain(chain_id).unwrap();
    assert_eq!(harness.alice.network.opened_gossip_undesired().count(), 0);
}

/// Statements from a peer are dropped until the outbound statement substream is open, even
/// when the peer is desired under the statement kind.
#[test]
fn statements_need_an_open_outbound_substream() {
    let mut harness = Harness::connected(true, true);
    let alice = harness.bob.remote.clone();
    let bob = harness.alice.remote.clone();
    let chain_id = harness.alice.chain_id;

    // Alice accepts Bob's inbound statement substream because it desires Bob, but doesn't
    // open its own substream yet.
    harness
        .alice
        .network
        .gossip_insert_desired(chain_id, bob.clone(), GossipKind::Statement);
    harness
        .bob
        .network
        .gossip_open(harness.bob.chain_id, &alice, GossipKind::Statement)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Bob, StatementProtocolConnected, 1);
    assert_count!(events, Alice, StatementProtocolConnected, 0);

    let filter = codec::AffinityFilter::new(0, 0.01, 8);
    harness
        .bob
        .network
        .send_topic_affinity(&alice, harness.bob.chain_id, &filter)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Alice, StatementTopicAffinityReceived, 0);

    harness
        .alice
        .network
        .gossip_open(chain_id, &bob, GossipKind::Statement)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Alice, StatementProtocolConnected, 1);

    harness
        .bob
        .network
        .send_topic_affinity(&alice, harness.bob.chain_id, &filter)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Alice, StatementTopicAffinityReceived, 1);
}

/// Losing the connection ends the statement link with one event, and the peer waits for a
/// new connection rather than a new open.
#[test]
fn statement_link_lost_with_connection() {
    let mut harness = Harness::connected(true, true);
    let alice = harness.bob.remote.clone();
    let bob = harness.alice.remote.clone();
    let chain_id = harness.alice.chain_id;

    harness.bob.network.gossip_insert_desired(
        harness.bob.chain_id,
        alice.clone(),
        GossipKind::Statement,
    );
    harness
        .alice
        .network
        .gossip_insert_desired(chain_id, bob.clone(), GossipKind::Statement);
    harness
        .alice
        .network
        .gossip_open(chain_id, &bob, GossipKind::Statement)
        .unwrap();
    let events = harness.pump();
    assert_count!(events, Alice, StatementProtocolConnected, 1);

    let events = harness.reset(Side::Alice);
    assert_count!(events, Alice, StatementProtocolDisconnected, 1);
    assert_count!(events, Alice, StatementProtocolConnected, 0);
    assert_count!(events, Alice, Disconnected, 1);
    assert_eq!(
        harness
            .alice
            .network
            .connected_unopened_gossip_desired()
            .count(),
        0
    );
    assert!(
        harness
            .alice
            .network
            .unconnected_desired()
            .any(|p| *p == bob)
    );
}

/// Closing the statement link leaves the block announces link alone.
#[test]
fn closing_statement_link_keeps_block_announces() {
    let mut harness = Harness::connected(true, true);
    let bob = harness.alice.remote.clone();
    let chain_id = harness.alice.chain_id;

    harness.open_gossip_link();
    harness
        .alice
        .network
        .gossip_close(chain_id, &bob, GossipKind::Statement)
        .unwrap();
    assert!(harness.alice.network.gossip_is_connected(
        chain_id,
        &bob,
        GossipKind::ConsensusTransactions
    ));
    assert!(
        !harness
            .alice
            .network
            .gossip_is_connected(chain_id, &bob, GossipKind::Statement)
    );

    let events = harness.pump();
    assert_count!(events, Alice, GossipDisconnected, 0);
    assert_count!(events, Bob, GossipDisconnected, 0);
}

/// A peer desired under both kinds gets its statement link from the block announces link, so
/// there is nothing left to open for the statement kind.
#[test]
fn block_announces_link_anchors_desired_statement_link() {
    let mut harness = Harness::connected(true, true);
    let bob = harness.alice.remote.clone();
    let chain_id = harness.alice.chain_id;

    harness.alice.network.gossip_insert_desired(
        chain_id,
        bob.clone(),
        GossipKind::ConsensusTransactions,
    );
    harness
        .alice
        .network
        .gossip_insert_desired(chain_id, bob.clone(), GossipKind::Statement);
    assert_eq!(
        harness
            .alice
            .network
            .connected_unopened_gossip_desired()
            .count(),
        2
    );

    let events = harness.open_gossip_link();
    assert_count!(events, Alice, StatementProtocolConnected, 1);
    assert_eq!(
        harness
            .alice
            .network
            .connected_unopened_gossip_desired()
            .count(),
        0
    );
    assert!(matches!(
        harness
            .alice
            .network
            .gossip_open(chain_id, &bob, GossipKind::Statement),
        Err(OpenGossipError::AlreadyOpened)
    ));
}
