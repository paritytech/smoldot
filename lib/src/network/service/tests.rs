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
    ChainConfig, ChainId, ChainNetwork, Config, ConnectionId, Event, GossipKind, PeerId,
    SingleStreamConnectionTask, SingleStreamHandshakeKind, peer_id,
};
use crate::libp2p::{connection::noise::NoiseKey, read_write::ReadWrite};
use crate::network::codec::Role;
use alloc::vec::Vec;
use core::{cmp, mem, time::Duration};

/// Maximum size of the byte pipe between the two connection tasks.
const BUF: usize = 65536;

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
    /// [`PeerId`] of the other side, known once the handshake has finished.
    remote: Option<PeerId>,
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

    // The expected `PeerId` is what registers the connection under the peer, the way the light
    // client always dials.
    let (conn_id, task) = network.add_single_stream_connection(
        Duration::ZERO,
        SingleStreamHandshakeKind::MultistreamSelectNoiseYamux {
            is_initiator,
            noise_key,
        },
        Vec::new(),
        Some(peer_id_of(remote_noise_key)),
        (),
    );

    Node {
        network,
        chain_id,
        task: Some(task),
        conn_id,
        remote: None,
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

        harness.pump();
        assert!(harness.alice.remote.is_some(), "Alice handshake");
        assert!(harness.bob.remote.is_some(), "Bob handshake");
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
        let Some(task) = task else {
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

    fn next_events(&mut self, side: Side) -> Vec<Event<()>> {
        let node = self.node(side);
        let mut events = Vec::new();
        while let Some(event) = node.network.next_event() {
            if let Event::HandshakeFinished { peer_id, .. } = &event {
                node.remote = Some(peer_id.clone());
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

    /// Runs the system, answering every [`Event::GossipInDesired`] with a
    /// [`GossipKind::ConsensusTransactions`] link of its own, the way the light client does.
    fn pump_accepting_gossip(&mut self) -> Vec<(Side, Event<()>)> {
        let mut all_events = Vec::new();
        loop {
            let events = self.pump();
            if events.is_empty() {
                break;
            }
            for (side, event) in &events {
                if let Event::GossipInDesired {
                    peer_id,
                    chain_id,
                    kind,
                } = event
                {
                    self.node(*side)
                        .network
                        .gossip_open(*chain_id, peer_id, *kind)
                        .unwrap();
                }
            }
            all_events.extend(events);
        }
        all_events
    }

    /// Resets the connection task of the given side, the way a dropped socket does, and runs
    /// the shutdown to completion. Returns every event produced along the way.
    fn reset(&mut self, side: Side) -> Vec<(Side, Event<()>)> {
        self.node(side).task.as_mut().unwrap().reset();

        // A reset task must not read or write again, so its messages are exchanged by hand
        // until the coordinator acknowledges the shutdown and the task exits.
        let mut events = Vec::new();
        for _ in 0..16 {
            if self.node(side).task.is_none() {
                break;
            }
            self.drain_conn_to_coord(side);
            for event in self.next_events(side) {
                events.push((side, event));
            }
            self.deliver_coord_to_conn(side);
        }
        assert!(self.node(side).task.is_none(), "reset task didn't exit");

        events.extend(self.pump());
        events
    }

    /// Alice's [`PeerId`], as seen by Bob.
    fn alice_id(&self) -> PeerId {
        self.bob.remote.clone().unwrap()
    }

    /// Bob's [`PeerId`], as seen by Alice.
    fn bob_id(&self) -> PeerId {
        self.alice.remote.clone().unwrap()
    }

    /// Opens a [`GossipKind::ConsensusTransactions`] link from Alice to Bob, accepted by Bob,
    /// and returns the events produced along the way.
    fn open_block_announces_link(&mut self) -> Vec<(Side, Event<()>)> {
        let bob = self.bob_id();
        self.alice
            .network
            .gossip_open(self.alice.chain_id, &bob, GossipKind::ConsensusTransactions)
            .unwrap();
        let events = self.pump_accepting_gossip();
        assert!(count(&events, Side::Alice, is_gossip_connected) == 1);
        assert!(count(&events, Side::Bob, is_gossip_connected) == 1);
        events
    }
}

fn count(
    events: &[(Side, Event<()>)],
    side: Side,
    predicate: impl Fn(&Event<()>) -> bool,
) -> usize {
    events
        .iter()
        .filter(|(s, e)| *s == side && predicate(e))
        .count()
}

fn is_gossip_connected(event: &Event<()>) -> bool {
    matches!(event, Event::GossipConnected { .. })
}

fn is_gossip_disconnected(event: &Event<()>) -> bool {
    matches!(event, Event::GossipDisconnected { .. })
}

fn is_statement_connected(event: &Event<()>) -> bool {
    matches!(event, Event::StatementProtocolConnected { .. })
}

/// Opening a block announces link reports on both sides.
#[test]
fn block_announces_link_opens() {
    let mut harness = Harness::connected(false, false);
    let alice = harness.alice_id();
    let bob = harness.bob_id();

    harness.open_block_announces_link();
    assert!(harness.alice.network.gossip_is_connected(
        harness.alice.chain_id,
        &bob,
        GossipKind::ConsensusTransactions
    ));
    assert!(harness.bob.network.gossip_is_connected(
        harness.bob.chain_id,
        &alice,
        GossipKind::ConsensusTransactions
    ));
}

/// The statement substream opens after the block announces substream and closes with it.
#[test]
fn statement_substream_follows_block_announces() {
    let mut harness = Harness::connected(true, true);
    let bob = harness.bob_id();
    let chain_id = harness.alice.chain_id;

    let events = harness.open_block_announces_link();
    assert_eq!(count(&events, Side::Alice, is_statement_connected), 1);

    harness
        .alice
        .network
        .gossip_close(chain_id, &bob, GossipKind::ConsensusTransactions)
        .unwrap();
    let events = harness.pump();
    assert_eq!(count(&events, Side::Bob, is_gossip_disconnected), 1);
}

/// Losing the connection ends the block announces link with one event.
#[test]
fn block_announces_link_lost_with_connection() {
    let mut harness = Harness::connected(false, false);
    harness.open_block_announces_link();

    let events = harness.reset(Side::Alice);
    assert_eq!(count(&events, Side::Alice, is_gossip_disconnected), 1);
}
