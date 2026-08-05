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
    Config, ConnectionId, Event, InboundTy, Network, SingleStreamConnectionTask,
    SingleStreamHandshakeKind, SubstreamId,
};
use crate::libp2p::{connection::noise::NoiseKey, read_write::ReadWrite};
use alloc::vec::Vec;
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
