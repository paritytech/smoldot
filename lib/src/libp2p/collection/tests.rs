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

#![cfg(test)]

use super::{
    Config, ConnectionId, Event, InboundTy, MultiStreamConnectionTask, MultiStreamHandshakeKind,
    Network, SingleStreamConnectionTask, SingleStreamHandshakeKind, SubstreamFate, SubstreamId,
};
use crate::libp2p::{connection::noise::NoiseKey, read_write::ReadWrite};
use alloc::{collections::BTreeMap, vec::Vec};
use core::{cmp, mem, time::Duration};

/// Maximum size of the byte pipe between the two connection tasks.
const BUF: usize = 65536;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Side {
    Alice,
    Bob,
}

/// A single node: a coordinator (`Network`) plus its one connection task.
struct Node {
    network: Network<(), Duration>,
    task: Option<SingleStreamConnectionTask<Duration>>,
    conn_id: ConnectionId,
}

/// Two nodes (Alice, initiator; Bob, responder) connected by an encrypted byte pipe. Bytes
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

fn make_node(is_initiator: bool, noise_key: &NoiseKey, seed: [u8; 32]) -> Node {
    let mut network = Network::<(), Duration>::new(Config {
        randomness_seed: seed,
        capacity: 1,
        max_inbound_substreams: 64,
        max_protocol_name_len: 256,
        handshake_timeout: Duration::from_secs(10),
        ping_protocol: "/ping/1.0.0".to_string(),
    });

    let (conn_id, task) = network.insert_single_stream(
        Duration::ZERO,
        SingleStreamHandshakeKind::MultistreamSelectNoiseYamux {
            is_initiator,
            noise_key,
        },
        16,
        (),
    );

    Node {
        network,
        task: Some(task),
        conn_id,
    }
}

impl Harness {
    fn new() -> Self {
        let alice_key = NoiseKey::new(&[1; 32], &[2; 32]);
        let bob_key = NoiseKey::new(&[3; 32], &[4; 32]);
        Harness {
            alice: make_node(true, &alice_key, [7; 32]),
            bob: make_node(false, &bob_key, [9; 32]),
            a2b: Vec::new(),
            b2a: Vec::new(),
            now: Duration::ZERO,
            wake_a: None,
            wake_b: None,
        }
    }

    fn pass_time(&mut self, amount: Duration) {
        self.now += amount;
    }

    /// Delivers all pending coordinator->connection messages for the given side.
    fn deliver_coord_to_conn(&mut self, side: Side) -> bool {
        let mut progress = false;
        loop {
            let node = match side {
                Side::Alice => &mut self.alice,
                Side::Bob => &mut self.bob,
            };
            let Some((_cid, msg)) = node.network.pull_message_to_connection() else {
                break;
            };
            if let Some(task) = node.task.as_mut() {
                task.inject_coordinator_message(&self.now, msg);
            }
            progress = true;
        }
        progress
    }

    /// Pulls all connection->coordinator messages for the given side and injects them into its
    /// coordinator. Does not call `next_event`.
    fn drain_conn_to_coord(&mut self, side: Side) -> bool {
        let mut progress = false;
        loop {
            let node = match side {
                Side::Alice => &mut self.alice,
                Side::Bob => &mut self.bob,
            };
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

    fn read_write_alice(&mut self) -> bool {
        let Some(task) = self.alice.task.as_mut() else {
            return false;
        };
        let out_len_before = self.a2b.len();
        let mut rw = ReadWrite {
            now: self.now,
            incoming_buffer: mem::take(&mut self.b2a),
            expected_incoming_bytes: Some(0),
            read_bytes: 0,
            write_bytes_queued: self.a2b.len(),
            write_bytes_queueable: Some(BUF - self.a2b.len()),
            write_buffers: vec![mem::take(&mut self.a2b)],
            wake_up_after: self.wake_a,
        };
        task.read_write(&mut rw);
        let read = rw.read_bytes;
        self.wake_a = rw.wake_up_after;
        self.b2a = rw.incoming_buffer;
        self.a2b = rw.write_buffers.drain(..).flatten().collect();
        read != 0 || self.a2b.len() != out_len_before
    }

    fn read_write_bob(&mut self) -> bool {
        let Some(task) = self.bob.task.as_mut() else {
            return false;
        };
        let out_len_before = self.b2a.len();
        let mut rw = ReadWrite {
            now: self.now,
            incoming_buffer: mem::take(&mut self.a2b),
            expected_incoming_bytes: Some(0),
            read_bytes: 0,
            write_bytes_queued: self.b2a.len(),
            write_bytes_queueable: Some(BUF - self.b2a.len()),
            write_buffers: vec![mem::take(&mut self.b2a)],
            wake_up_after: self.wake_b,
        };
        task.read_write(&mut rw);
        let read = rw.read_bytes;
        self.wake_b = rw.wake_up_after;
        self.a2b = rw.incoming_buffer;
        self.b2a = rw.write_buffers.drain(..).flatten().collect();
        read != 0 || self.b2a.len() != out_len_before
    }

    /// Runs the system until nothing more happens. The `deliver_*` flags control whether pending
    /// coordinator->connection messages are delivered to each side; holding them back is what
    /// lets a test keep a message "in flight". Returns every event produced along the way.
    ///
    /// When neither side can make byte progress but a connection task has asked to be woken up
    /// (`wake_up_after`, e.g. a substream that wants to be re-polled), time is advanced to that
    /// instant, mirroring the driver loop in `established::tests`. Advancing is bounded so that
    /// idle-but-alive connections (which keep asking to be woken for pings) don't loop forever.
    fn pump(&mut self, deliver_alice: bool, deliver_bob: bool) -> Vec<(Side, Event<()>)> {
        let mut events = Vec::new();
        let ceiling = self.now + Duration::from_millis(100);
        // Number of consecutive time-advances that produced no progress. A connection task that
        // is idle-but-alive keeps asking to be re-polled "as soon as possible"; once a handful of
        // such advances change nothing, there is genuinely nothing left to do.
        let mut idle_advances = 0u32;
        loop {
            let mut progress = false;
            if deliver_alice {
                progress |= self.deliver_coord_to_conn(Side::Alice);
            }
            if deliver_bob {
                progress |= self.deliver_coord_to_conn(Side::Bob);
            }
            progress |= self.read_write_alice();
            progress |= self.read_write_bob();
            progress |= self.drain_conn_to_coord(Side::Alice);
            progress |= self.drain_conn_to_coord(Side::Bob);
            while let Some(e) = self.alice.network.next_event() {
                events.push((Side::Alice, e));
                progress = true;
            }
            while let Some(e) = self.bob.network.next_event() {
                events.push((Side::Bob, e));
                progress = true;
            }
            if progress {
                idle_advances = 0;
                continue;
            }

            // Stalled. Advance time to the earliest requested wake-up, so that connection tasks
            // that requested an immediate re-poll (`wake_up_asap`) can make progress. Give up once
            // we'd cross the ceiling (keeps future ping timers from looping forever) or once a
            // handful of advances in a row have changed nothing (idle-but-alive spinning).
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
}

/// Reproduces issue #3304: a duplicate `RejectInNotifications` produced when the coordinator's
/// reject crosses a remote-initiated death of the inbound notifications substream.
///
/// Real-world sequence encoded here:
///  1. Bob opens an outbound notifications substream to Alice.
///  2. Alice negotiates it and reports `NotificationsInOpen` (substream in `NotificationsInWait`).
///  3. Alice's API rejects it, but the reject message is *not yet* delivered to Alice's task.
///  4. Bob's open handshake times out, so Bob resets the substream. Alice processes the reset,
///     removes the substream from its yamux, and reports `NotificationsInOpenCancel` (pushing one
///     ack entry into `notifications_in_close_acknowledgments`).
///  5. The held-back reject (msg #1) is delivered and consumes that single ack entry.
///  6. The coordinator processes the `NotificationsInOpenCancel`, finds its records already gone
///     (removed in step 3), and re-sends a second `RejectInNotifications` (msg #2).
///  7. Msg #2 finds the ack queue empty and calls `reject_in_notifications_substream` on a
///     substream that no longer exists in yamux -> panic before the fix.
#[test]
fn reject_in_notifications_double_send_after_remote_reset() {
    let mut harness = Harness::new();

    // Complete the connection handshake on both sides.
    let events = harness.pump(true, true);
    assert!(
        events
            .iter()
            .any(|(s, e)| *s == Side::Alice && matches!(e, Event::HandshakeFinished { .. }))
    );
    assert!(
        events
            .iter()
            .any(|(s, e)| *s == Side::Bob && matches!(e, Event::HandshakeFinished { .. }))
    );

    // Bob opens an outbound notifications substream. Its open handshake times out after 1s.
    let bob_sub = harness.bob.network.open_out_notifications(
        harness.bob.conn_id,
        "/test-notif/1.0.0".to_string(),
        Duration::from_secs(1),
        b"hello".to_vec(),
        1024,
    );

    // Alice negotiates the inbound substream and must accept the protocol name.
    let events = harness.pump(true, true);
    let alice_inbound = events
        .iter()
        .find_map(|(side, ev)| match ev {
            Event::InboundNegotiated {
                substream_id,
                protocol_name,
                ..
            } if *side == Side::Alice => {
                assert_eq!(protocol_name, "/test-notif/1.0.0");
                Some(*substream_id)
            }
            _ => None,
        })
        .expect("Alice should report InboundNegotiated");
    harness.alice.network.accept_inbound(
        alice_inbound,
        InboundTy::Notifications {
            max_handshake_size: 1024,
        },
    );

    // Alice reads Bob's handshake and reports the substream as open-in-wait.
    let events = harness.pump(true, true);
    let s: SubstreamId = events
        .iter()
        .find_map(|(side, ev)| match ev {
            Event::NotificationsInOpen { substream_id, .. } if *side == Side::Alice => {
                Some(*substream_id)
            }
            _ => None,
        })
        .expect("Alice should report NotificationsInOpen");

    // Step 3: Alice rejects the substream. The reject message is now queued in Alice's coordinator
    // but is deliberately NOT delivered to Alice's connection task yet.
    harness.alice.network.reject_in_notifications(s);

    // Step 4: advance past Bob's 1s open-handshake timeout (but before the hardcoded first ping at
    // 2s) and let Bob reset the substream. Alice processes the reset and produces the outgoing
    // NotificationsInOpenCancel. Crucially, Alice's coordinator->connection messages (the held-back
    // reject #1) are NOT delivered during this phase.
    harness.pass_time(Duration::from_millis(1500));
    let events_reset = harness.pump(false, true);

    // Bob observes the failure of the substream he opened, since he reset it on timeout.
    assert!(events_reset.iter().any(|(side, ev)| *side == Side::Bob
        && matches!(
            ev,
            Event::NotificationsOutResult { substream_id, result: Err(_) }
                if *substream_id == bob_sub
        )));

    // Steps 5-7: now deliver Alice's coordinator messages in order: reject #1 consumes the single
    // ack entry, then the re-sent reject #2 hits the already-removed substream.
    // Without the fix, this panics in `reject_in_notifications_substream` via yamux index_mut.
    let events_final = harness.pump(true, true);

    // The duplicate reject must be a silent no-op: the connection survives the crossing on both
    // sides rather than being torn down.
    assert!(
        !events_reset
            .iter()
            .chain(&events_final)
            .any(|(_, ev)| { matches!(ev, Event::StartShutdown { .. } | Event::Shutdown { .. }) })
    );
}

/// Same crossing as [`reject_in_notifications_double_send_after_remote_reset`], but with the
/// accept + close pair of messages instead of a duplicate reject.
///
/// Sequence:
///  1. Bob opens an outbound notifications substream to Alice.
///  2. Alice negotiates it and reports `NotificationsInOpen` (substream in `NotificationsInWait`).
///  3. Alice's API accepts the substream, then immediately requests its closing. Both the
///     `AcceptInNotifications` and `CloseInNotifications` messages are queued in Alice's
///     coordinator but *not yet* delivered to Alice's task.
///  4. Bob's open handshake times out, so Bob resets the substream. Alice processes the reset,
///     removes the substream from its yamux, and reports `NotificationsInOpenCancel` (pushing one
///     ack entry into `notifications_in_close_acknowledgments`).
///  5. The coordinator reinterprets the cancel as `NotificationsInClose` (state was
///     `RequestedClosing`) and sends no further message: two messages are in flight for a single
///     ack entry.
///  6. The held-back accept (msg #1) is delivered and consumes that single ack entry.
///  7. The held-back close (msg #2) finds the ack queue empty and calls
///     `close_in_notifications_substream` on a substream that no longer exists in yamux -> panic.
#[test]
fn close_in_notifications_crossing_remote_reset() {
    let mut harness = Harness::new();

    // Complete the connection handshake on both sides.
    let events = harness.pump(true, true);
    assert!(
        events
            .iter()
            .any(|(s, e)| *s == Side::Alice && matches!(e, Event::HandshakeFinished { .. }))
    );
    assert!(
        events
            .iter()
            .any(|(s, e)| *s == Side::Bob && matches!(e, Event::HandshakeFinished { .. }))
    );

    // Bob opens an outbound notifications substream. Its open handshake times out after 1s.
    let bob_sub = harness.bob.network.open_out_notifications(
        harness.bob.conn_id,
        "/test-notif/1.0.0".to_string(),
        Duration::from_secs(1),
        b"hello".to_vec(),
        1024,
    );

    // Alice negotiates the inbound substream and must accept the protocol name.
    let events = harness.pump(true, true);
    let alice_inbound = events
        .iter()
        .find_map(|(side, ev)| match ev {
            Event::InboundNegotiated {
                substream_id,
                protocol_name,
                ..
            } if *side == Side::Alice => {
                assert_eq!(protocol_name, "/test-notif/1.0.0");
                Some(*substream_id)
            }
            _ => None,
        })
        .expect("Alice should report InboundNegotiated");
    harness.alice.network.accept_inbound(
        alice_inbound,
        InboundTy::Notifications {
            max_handshake_size: 1024,
        },
    );

    // Alice reads Bob's handshake and reports the substream as open-in-wait.
    let events = harness.pump(true, true);
    let s: SubstreamId = events
        .iter()
        .find_map(|(side, ev)| match ev {
            Event::NotificationsInOpen { substream_id, .. } if *side == Side::Alice => {
                Some(*substream_id)
            }
            _ => None,
        })
        .expect("Alice should report NotificationsInOpen");

    // Step 3: Alice accepts the substream and immediately requests its closing. Both messages are
    // now queued in Alice's coordinator but deliberately NOT delivered to Alice's task yet.
    harness
        .alice
        .network
        .accept_in_notifications(s, b"hi".to_vec(), 1024);
    harness
        .alice
        .network
        .start_close_in_notifications(s, Duration::from_secs(5));

    // Step 4: advance past Bob's 1s open-handshake timeout (but before the hardcoded first ping at
    // 2s) and let Bob reset the substream. Alice processes the reset and produces the outgoing
    // NotificationsInOpenCancel. Crucially, Alice's coordinator->connection messages (the held-back
    // accept and close) are NOT delivered during this phase.
    harness.pass_time(Duration::from_millis(1500));
    let events_reset = harness.pump(false, true);

    // Bob observes the failure of the substream he opened, since he reset it on timeout.
    assert!(events_reset.iter().any(|(side, ev)| *side == Side::Bob
        && matches!(
            ev,
            Event::NotificationsOutResult { substream_id, result: Err(_) }
                if *substream_id == bob_sub
        )));

    // Step 5: the coordinator reinterprets the cancel as a NotificationsInClose event, since the
    // substream was already accepted.
    assert!(events_reset.iter().any(|(side, ev)| *side == Side::Alice
        && matches!(
            ev,
            Event::NotificationsInClose { substream_id, .. } if *substream_id == s
        )));

    // Steps 6-7: now deliver Alice's coordinator messages in order: the accept consumes the single
    // ack entry, then the close hits the already-removed substream.
    // Without a guard, this panics in `close_in_notifications_substream`.
    let events_final = harness.pump(true, true);

    // The stale close must be a silent no-op: the connection survives the crossing on both sides
    // rather than being torn down.
    assert!(
        !events_reset
            .iter()
            .chain(&events_final)
            .any(|(_, ev)| { matches!(ev, Event::StartShutdown { .. } | Event::Shutdown { .. }) })
    );
}

/// A single node of the multi-stream (WebRTC-like) harness: a coordinator plus its one
/// multi-stream connection task.
struct MultiNode {
    network: Network<(), Duration>,
    task: Option<MultiStreamConnectionTask<Duration, u32>>,
    conn_id: ConnectionId,
}

/// A simulated WebRTC data channel: one byte buffer per direction, plus whether each side's
/// endpoint is still alive.
struct MultiChannel {
    /// Bytes written by Alice on this channel, waiting to be read by Bob.
    a2b: Vec<u8>,
    /// Bytes written by Bob on this channel, waiting to be read by Alice.
    b2a: Vec<u8>,
    alice_open: bool,
    bob_open: bool,
}

/// Two nodes connected by simulated WebRTC data channels. Contrary to the single-stream
/// [`Harness`], there is no single byte pipe: each substream is its own pair of byte buffers, and
/// the harness plays the role of the platform (opening channels on demand and propagating
/// resets).
struct MultiHarness {
    alice: MultiNode,
    bob: MultiNode,
    channels: BTreeMap<u32, MultiChannel>,
    next_channel_id: u32,
    now: Duration,
    wake_a: Option<Duration>,
    wake_b: Option<Duration>,
}

fn make_multi_node(
    is_initiator: bool,
    noise_key: &NoiseKey,
    seed: [u8; 32],
    local_tls_certificate_multihash: Vec<u8>,
    remote_tls_certificate_multihash: Vec<u8>,
) -> MultiNode {
    let mut network = Network::<(), Duration>::new(Config {
        randomness_seed: seed,
        capacity: 1,
        max_inbound_substreams: 64,
        max_protocol_name_len: 256,
        handshake_timeout: Duration::from_secs(10),
        ping_protocol: "/ping/1.0.0".to_string(),
    });

    let (conn_id, task) = network.insert_multi_stream(
        Duration::ZERO,
        MultiStreamHandshakeKind::WebRtc {
            is_initiator,
            noise_key,
            local_tls_certificate_multihash,
            remote_tls_certificate_multihash,
        },
        16,
        (),
    );

    MultiNode {
        network,
        task: Some(task),
        conn_id,
    }
}

impl MultiHarness {
    fn new() -> Self {
        let alice_key = NoiseKey::new(&[1; 32], &[2; 32]);
        let bob_key = NoiseKey::new(&[3; 32], &[4; 32]);
        // The TLS certificate fingerprints only feed the Noise prologue; any value works as long
        // as both sides agree on the pair. SHA-256 multihash format (0x12 0x20 + 32 bytes).
        let fp_alice = [&[0x12u8, 0x20][..], &[0xaa; 32][..]].concat();
        let fp_bob = [&[0x12u8, 0x20][..], &[0xbb; 32][..]].concat();

        let mut harness = MultiHarness {
            alice: make_multi_node(true, &alice_key, [7; 32], fp_alice.clone(), fp_bob.clone()),
            bob: make_multi_node(false, &bob_key, [9; 32], fp_bob, fp_alice),
            channels: BTreeMap::new(),
            next_channel_id: 0,
            now: Duration::ZERO,
            wake_a: None,
            wake_b: None,
        };

        // The Noise handshake runs over the substream that a side has itself opened (see
        // `opened_substream` in `collection/multi_stream.rs`). For the two state machines to talk
        // to each other, the harness registers one shared channel as locally-opened on both
        // sides, mimicking the negotiated handshake data channel of a real WebRTC connection.
        let id = harness.alloc_channel();
        harness.alice.task.as_mut().unwrap().add_substream(id, true);
        harness.bob.task.as_mut().unwrap().add_substream(id, true);

        harness
    }

    fn alloc_channel(&mut self) -> u32 {
        let id = self.next_channel_id;
        self.next_channel_id += 1;
        self.channels.insert(
            id,
            MultiChannel {
                a2b: Vec::new(),
                b2a: Vec::new(),
                alice_open: true,
                bob_open: true,
            },
        );
        id
    }

    /// Simulates the abrupt death of a data channel, e.g. the remote closing the
    /// `RTCDataChannel`: the platform on both sides observes the closure and notifies its state
    /// machine.
    fn kill_channel(&mut self, chan_id: u32) {
        assert!(self.channels.remove(&chan_id).is_some());
        if let Some(task) = self.alice.task.as_mut() {
            task.reset_substream(&chan_id);
        }
        if let Some(task) = self.bob.task.as_mut() {
            task.reset_substream(&chan_id);
        }
    }

    /// Delivers all pending coordinator->connection messages for the given side.
    fn deliver_coord_to_conn(&mut self, side: Side) -> bool {
        let mut progress = false;
        loop {
            let node = match side {
                Side::Alice => &mut self.alice,
                Side::Bob => &mut self.bob,
            };
            let Some((_cid, msg)) = node.network.pull_message_to_connection() else {
                break;
            };
            if let Some(task) = node.task.as_mut() {
                task.inject_coordinator_message(&self.now, msg);
            }
            progress = true;
        }
        progress
    }

    /// Pulls all connection->coordinator messages for the given side and injects them into its
    /// coordinator. Does not call `next_event`.
    fn drain_conn_to_coord(&mut self, side: Side) -> bool {
        let mut progress = false;
        loop {
            let node = match side {
                Side::Alice => &mut self.alice,
                Side::Bob => &mut self.bob,
            };
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

    /// Opens new channels for every outbound substream that either state machine desires,
    /// mirroring the platform opening WebRTC data channels on demand.
    fn open_desired_substreams(&mut self) -> bool {
        let mut progress = false;
        for side in [Side::Alice, Side::Bob] {
            loop {
                let (node, peer) = match side {
                    Side::Alice => (&mut self.alice, &mut self.bob),
                    Side::Bob => (&mut self.bob, &mut self.alice),
                };
                let (Some(task), Some(peer_task)) = (node.task.as_mut(), peer.task.as_mut()) else {
                    break;
                };
                if task.desired_outbound_substreams() == 0 {
                    break;
                }
                let id = self.next_channel_id;
                self.next_channel_id += 1;
                task.add_substream(id, true);
                peer_task.add_substream(id, false);
                self.channels.insert(
                    id,
                    MultiChannel {
                        a2b: Vec::new(),
                        b2a: Vec::new(),
                        alice_open: true,
                        bob_open: true,
                    },
                );
                progress = true;
            }
        }
        progress
    }

    /// Reads/writes one side's endpoint of one channel.
    fn channel_read_write(&mut self, side: Side, chan_id: u32) -> bool {
        let (node, wake) = match side {
            Side::Alice => (&mut self.alice, &mut self.wake_a),
            Side::Bob => (&mut self.bob, &mut self.wake_b),
        };
        let Some(task) = node.task.as_mut() else {
            return false;
        };
        let Some(chan) = self.channels.get_mut(&chan_id) else {
            return false;
        };
        let (open, incoming_buf, outgoing_buf) = match side {
            Side::Alice => (&mut chan.alice_open, &mut chan.b2a, &mut chan.a2b),
            Side::Bob => (&mut chan.bob_open, &mut chan.a2b, &mut chan.b2a),
        };
        if !*open {
            return false;
        }

        let out_len_before = outgoing_buf.len();
        let mut rw = ReadWrite {
            now: self.now,
            incoming_buffer: mem::take(incoming_buf),
            expected_incoming_bytes: Some(0),
            read_bytes: 0,
            write_bytes_queued: outgoing_buf.len(),
            write_bytes_queueable: Some(BUF - outgoing_buf.len()),
            write_buffers: vec![mem::take(outgoing_buf)],
            wake_up_after: *wake,
        };
        let fate = task.substream_read_write(&chan_id, &mut rw);
        let read = rw.read_bytes;
        *wake = rw.wake_up_after;
        *incoming_buf = rw.incoming_buffer;
        *outgoing_buf = rw.write_buffers.drain(..).flatten().collect();

        let mut progress = read != 0 || outgoing_buf.len() != out_len_before;
        if matches!(fate, SubstreamFate::Reset) {
            *open = false;
            progress = true;
        }
        progress
    }

    /// Propagates channel resets to the surviving side, mimicking the remote observing the death
    /// of a WebRTC data channel. The reset is only delivered once the survivor has consumed all
    /// the bytes that were in flight (e.g. the final Noise handshake message).
    fn propagate_resets(&mut self) -> bool {
        let mut progress = false;
        let mut to_remove = Vec::new();
        for (&id, chan) in self.channels.iter_mut() {
            match (chan.alice_open, chan.bob_open) {
                (false, false) => to_remove.push(id),
                (false, true) if chan.a2b.is_empty() => {
                    if let Some(task) = self.bob.task.as_mut() {
                        task.reset_substream(&id);
                    }
                    chan.bob_open = false;
                    to_remove.push(id);
                    progress = true;
                }
                (true, false) if chan.b2a.is_empty() => {
                    if let Some(task) = self.alice.task.as_mut() {
                        task.reset_substream(&id);
                    }
                    chan.alice_open = false;
                    to_remove.push(id);
                    progress = true;
                }
                _ => {}
            }
        }
        for id in to_remove {
            self.channels.remove(&id);
        }
        progress
    }

    /// Same as [`Harness::pump`], for the multi-stream harness.
    fn pump(&mut self, deliver_alice: bool, deliver_bob: bool) -> Vec<(Side, Event<()>)> {
        let mut events = Vec::new();
        let ceiling = self.now + Duration::from_millis(100);
        let mut idle_advances = 0u32;
        loop {
            let mut progress = false;
            if deliver_alice {
                progress |= self.deliver_coord_to_conn(Side::Alice);
            }
            if deliver_bob {
                progress |= self.deliver_coord_to_conn(Side::Bob);
            }
            progress |= self.open_desired_substreams();
            let chan_ids: Vec<u32> = self.channels.keys().copied().collect();
            for id in chan_ids {
                progress |= self.channel_read_write(Side::Alice, id);
                progress |= self.channel_read_write(Side::Bob, id);
            }
            progress |= self.propagate_resets();
            progress |= self.drain_conn_to_coord(Side::Alice);
            progress |= self.drain_conn_to_coord(Side::Bob);
            while let Some(e) = self.alice.network.next_event() {
                events.push((Side::Alice, e));
                progress = true;
            }
            while let Some(e) = self.bob.network.next_event() {
                events.push((Side::Bob, e));
                progress = true;
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
}

/// Contrary to yamux connections, multi-stream connections open their ping substream eagerly,
/// and the inbound side surfaces its negotiation to the API like any other protocol.
fn accept_ping_inbounds(harness: &mut MultiHarness, events: &[(Side, Event<()>)]) {
    for (side, ev) in events {
        if let Event::InboundNegotiated {
            substream_id,
            protocol_name,
            ..
        } = ev
        {
            if protocol_name == "/ping/1.0.0" {
                let node = match side {
                    Side::Alice => &mut harness.alice,
                    Side::Bob => &mut harness.bob,
                };
                node.network.accept_inbound(*substream_id, InboundTy::Ping);
            }
        }
    }
}

/// Multi-stream (WebRTC) variant of
/// [`reject_in_notifications_double_send_after_remote_reset`]: the same coordinator crossing, but
/// the duplicate reject must hit `established::MultiStream::reject_in_notifications_substream`
/// after the substream has been removed from its maps by the reset.
///
/// Contrary to yamux, a remote-initiated substream death is not carried by the connection's byte
/// stream: it materializes as the platform observing the closure of the data channel and calling
/// `reset_substream` (a graceful `FIN` would not trigger the crossing, since an unaccepted
/// notifications substream back-pressures its channel and never reads the `FIN`).
#[test]
fn multi_stream_reject_in_notifications_double_send_after_remote_reset() {
    let mut harness = MultiHarness::new();

    // Complete the connection handshake on both sides.
    let events = harness.pump(true, true);
    assert!(
        events
            .iter()
            .any(|(s, e)| *s == Side::Alice && matches!(e, Event::HandshakeFinished { .. }))
    );
    assert!(
        events
            .iter()
            .any(|(s, e)| *s == Side::Bob && matches!(e, Event::HandshakeFinished { .. }))
    );
    accept_ping_inbounds(&mut harness, &events);

    // Bob opens an outbound notifications substream. The data channel that will carry it is the
    // next one that the harness allocates.
    let notif_channel = harness.next_channel_id;
    let bob_sub = harness.bob.network.open_out_notifications(
        harness.bob.conn_id,
        "/test-notif/1.0.0".to_string(),
        Duration::from_secs(10),
        b"hello".to_vec(),
        1024,
    );

    // Alice negotiates the inbound substream and must accept the protocol name.
    let events = harness.pump(true, true);
    assert_eq!(harness.next_channel_id, notif_channel + 1);
    accept_ping_inbounds(&mut harness, &events);
    let alice_inbound = events
        .iter()
        .find_map(|(side, ev)| match ev {
            Event::InboundNegotiated {
                substream_id,
                protocol_name,
                ..
            } if *side == Side::Alice && protocol_name == "/test-notif/1.0.0" => {
                Some(*substream_id)
            }
            _ => None,
        })
        .expect("Alice should report InboundNegotiated");
    harness.alice.network.accept_inbound(
        alice_inbound,
        InboundTy::Notifications {
            max_handshake_size: 1024,
        },
    );

    // Alice reads Bob's handshake and reports the substream as open-in-wait.
    let events = harness.pump(true, true);
    accept_ping_inbounds(&mut harness, &events);
    let s: SubstreamId = events
        .iter()
        .find_map(|(side, ev)| match ev {
            Event::NotificationsInOpen { substream_id, .. } if *side == Side::Alice => {
                Some(*substream_id)
            }
            _ => None,
        })
        .expect("Alice should report NotificationsInOpen");

    // Alice rejects the substream. The reject message is now queued in Alice's coordinator but is
    // deliberately NOT delivered to Alice's connection task yet.
    harness.alice.network.reject_in_notifications(s);

    // The data channel carrying the substream abruptly dies (in the real world: the remote closes
    // or resets the `RTCDataChannel`). Alice's state machine removes the substream from its maps
    // and produces the outgoing NotificationsInOpenCancel. The held-back reject #1 is NOT
    // delivered during this phase.
    harness.kill_channel(notif_channel);
    let events_reset = harness.pump(false, true);

    // Bob observes the failure of the substream he opened, since its channel was killed.
    assert!(events_reset.iter().any(|(side, ev)| *side == Side::Bob
        && matches!(
            ev,
            Event::NotificationsOutResult { substream_id, result: Err(_) }
                if *substream_id == bob_sub
        )));

    // Deliver Alice's coordinator messages in order: reject #1 consumes the single ack entry,
    // then the re-sent reject #2 hits the already-removed substream. Without the fix, this panics
    // in `MultiStream::reject_in_notifications_substream` when unwrapping the map lookup.
    let events_final = harness.pump(true, true);

    // The duplicate reject must be a silent no-op: the connection survives the crossing on both
    // sides rather than being torn down.
    assert!(
        !events_reset
            .iter()
            .chain(&events_final)
            .any(|(_, ev)| { matches!(ev, Event::StartShutdown { .. } | Event::Shutdown { .. }) })
    );
}

/// Same crossing as [`close_in_notifications_crossing_remote_reset`], on a multi-stream
/// connection: the accept + close pair of messages is in flight while the remote resets the
/// substream, so the single ack entry is consumed by the accept and the close hits a substream
/// that no longer exists in the state machine.
#[test]
fn multi_stream_close_in_notifications_crossing_remote_reset() {
    let mut harness = MultiHarness::new();

    // Complete the connection handshake on both sides.
    let events = harness.pump(true, true);
    assert!(
        events
            .iter()
            .any(|(s, e)| *s == Side::Alice && matches!(e, Event::HandshakeFinished { .. }))
    );
    assert!(
        events
            .iter()
            .any(|(s, e)| *s == Side::Bob && matches!(e, Event::HandshakeFinished { .. }))
    );
    accept_ping_inbounds(&mut harness, &events);

    // Bob opens an outbound notifications substream. The data channel that will carry it is the
    // next one that the harness allocates.
    let notif_channel = harness.next_channel_id;
    let bob_sub = harness.bob.network.open_out_notifications(
        harness.bob.conn_id,
        "/test-notif/1.0.0".to_string(),
        Duration::from_secs(10),
        b"hello".to_vec(),
        1024,
    );

    // Alice negotiates the inbound substream and must accept the protocol name.
    let events = harness.pump(true, true);
    assert_eq!(harness.next_channel_id, notif_channel + 1);
    accept_ping_inbounds(&mut harness, &events);
    let alice_inbound = events
        .iter()
        .find_map(|(side, ev)| match ev {
            Event::InboundNegotiated {
                substream_id,
                protocol_name,
                ..
            } if *side == Side::Alice && protocol_name == "/test-notif/1.0.0" => {
                Some(*substream_id)
            }
            _ => None,
        })
        .expect("Alice should report InboundNegotiated");
    harness.alice.network.accept_inbound(
        alice_inbound,
        InboundTy::Notifications {
            max_handshake_size: 1024,
        },
    );

    // Alice reads Bob's handshake and reports the substream as open-in-wait.
    let events = harness.pump(true, true);
    accept_ping_inbounds(&mut harness, &events);
    let s: SubstreamId = events
        .iter()
        .find_map(|(side, ev)| match ev {
            Event::NotificationsInOpen { substream_id, .. } if *side == Side::Alice => {
                Some(*substream_id)
            }
            _ => None,
        })
        .expect("Alice should report NotificationsInOpen");

    // Alice accepts the substream and immediately requests its closing. Both messages are now
    // queued in Alice's coordinator but deliberately NOT delivered to Alice's task yet.
    harness
        .alice
        .network
        .accept_in_notifications(s, b"hi".to_vec(), 1024);
    harness
        .alice
        .network
        .start_close_in_notifications(s, Duration::from_secs(5));

    // The data channel carrying the substream abruptly dies. Alice's state machine removes the
    // substream from its maps and produces the outgoing NotificationsInOpenCancel. The held-back
    // accept and close are NOT delivered during this phase.
    harness.kill_channel(notif_channel);
    let events_reset = harness.pump(false, true);

    // Bob observes the failure of the substream he opened, since its channel was killed.
    assert!(events_reset.iter().any(|(side, ev)| *side == Side::Bob
        && matches!(
            ev,
            Event::NotificationsOutResult { substream_id, result: Err(_) }
                if *substream_id == bob_sub
        )));

    // The coordinator reinterprets the cancel as a NotificationsInClose event, since the substream
    // was already accepted.
    assert!(events_reset.iter().any(|(side, ev)| *side == Side::Alice
        && matches!(
            ev,
            Event::NotificationsInClose { substream_id, .. } if *substream_id == s
        )));

    // Deliver Alice's coordinator messages in order: the accept consumes the single ack entry,
    // then the close hits the already-removed substream. Without a guard, this panics in
    // `MultiStream::close_in_notifications_substream` when unwrapping the map lookup.
    let events_final = harness.pump(true, true);

    // The stale close must be a silent no-op: the connection survives the crossing on both sides
    // rather than being torn down.
    assert!(
        !events_reset
            .iter()
            .chain(&events_final)
            .any(|(_, ev)| { matches!(ev, Event::StartShutdown { .. } | Event::Shutdown { .. }) })
    );
}
