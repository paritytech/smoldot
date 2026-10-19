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

//! Tests of [`ChainNetwork`] against a peer over an in-memory encrypted byte pipe, the same way
//! `collection::tests` does.

use super::{
    ChainConfig, ChainId, ChainNetwork, Config, ConnectionId, Event, GossipKind,
    NotificationsOutErr, PeerId, SingleStreamConnectionTask, SingleStreamHandshakeKind,
    established, peer_id,
};
use crate::libp2p::{connection::noise::NoiseKey, read_write::ReadWrite};
use crate::network::codec::{self, Role};
use alloc::vec::Vec;
use core::{cmp, mem, time::Duration};

/// Maximum size of the byte pipe between the two connection tasks.
const BUF: usize = 65536;

/// A single node: a [`ChainNetwork`] with one chain plus its one connection task.
struct Node {
    network: ChainNetwork<(), (), Duration>,
    chain_id: ChainId,
    task: Option<SingleStreamConnectionTask<Duration>>,
    conn_id: ConnectionId,
    /// [`PeerId`] of the other side.
    remote: PeerId,
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

/// How Bob answers a transactions substream in [`secondary_substream_exchange`].
#[derive(Clone, Copy)]
enum SecondaryReply {
    /// Close it before the handshake, like a full node without a slot for the light client.
    Refuse,
    Accept,
}

/// Alice is a light client (`ChainNetwork`) that opens a gossip link with Bob. Bob is a bare
/// libp2p node that accepts the block announces substream and answers the transactions
/// substreams with `replies`, in order, refusing past the end. If `reopen_on_event` is set, Alice
/// calls `gossip_reopen_secondaries` on every [`Event::GossipSecondaryClosed`].
///
/// Returns how many transactions substreams Bob saw, the error of each
/// [`Event::GossipSecondaryClosed`] Alice got, and Alice.
fn secondary_substream_exchange(
    replies: &[SecondaryReply],
    reopen_on_event: bool,
) -> (usize, Vec<Option<NotificationsOutErr>>, Node) {
    use crate::libp2p::collection;
    use alloc::collections::BTreeMap;

    let alice_key = NoiseKey::new(&[1; 32], &[2; 32]);
    let bob_key = NoiseKey::new(&[3; 32], &[4; 32]);
    let mut alice = make_node(true, &alice_key, &bob_key, [7; 32], false);
    let bob_peer_id = alice.remote.clone();

    let mut bob_network = collection::Network::<(), Duration>::new(collection::Config {
        randomness_seed: [9; 32],
        capacity: 1,
        max_inbound_substreams: 64,
        max_protocol_name_len: 256,
        handshake_timeout: Duration::from_secs(10),
        ping_protocol: "/ipfs/ping/1.0.0".to_string(),
    });
    let (bob_conn_id, bob_task) = bob_network.insert_single_stream(
        Duration::ZERO,
        SingleStreamHandshakeKind::MultistreamSelectNoiseYamux {
            is_initiator: false,
            noise_key: &bob_key,
        },
        16,
        (),
    );
    let mut bob_task = Some(bob_task);

    let block_announces_name =
        codec::encode_protocol_name_string(codec::ProtocolName::BlockAnnounces {
            genesis_hash: [1; 32],
            fork_id: None,
        });
    let transactions_name = codec::encode_protocol_name_string(codec::ProtocolName::Transactions {
        genesis_hash: [1; 32],
        fork_id: None,
    });
    let bob_handshake = codec::encode_block_announces_handshake(
        codec::BlockAnnouncesHandshakeRef {
            role: Role::Full,
            best_number: 0,
            best_hash: &[1; 32],
            genesis_hash: &[1; 32],
        },
        4,
    )
    .fold(Vec::new(), |mut acc, chunk| {
        acc.extend_from_slice(chunk.as_ref());
        acc
    });

    fn read_write(
        task: &mut SingleStreamConnectionTask<Duration>,
        incoming: &mut Vec<u8>,
        outgoing: &mut Vec<u8>,
        now: Duration,
        wake: &mut Option<Duration>,
    ) -> bool {
        if task.is_reset_called() {
            return false;
        }
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

    let mut a2b = Vec::new();
    let mut b2a = Vec::new();
    let mut now = Duration::ZERO;
    let mut wake_a = None;
    let mut wake_b = None;
    let ceiling = Duration::from_millis(100);
    let mut idle_advances = 0u32;
    let mut bob_protocols: BTreeMap<collection::SubstreamId, String> = BTreeMap::new();
    let mut opens = 0usize;
    let mut errors = Vec::new();

    loop {
        let mut progress = false;

        while let Some((_, msg)) = alice.network.pull_message_to_connection() {
            if let Some(task) = alice.task.as_mut() {
                task.inject_coordinator_message(&now, msg);
            }
            progress = true;
        }
        while let Some((_, msg)) = bob_network.pull_message_to_connection() {
            if let Some(task) = bob_task.as_mut() {
                task.inject_coordinator_message(&now, msg);
            }
            progress = true;
        }

        if let Some(task) = alice.task.as_mut() {
            progress |= read_write(task, &mut b2a, &mut a2b, now, &mut wake_a);
        }
        if let Some(task) = bob_task.as_mut() {
            progress |= read_write(task, &mut a2b, &mut b2a, now, &mut wake_b);
        }

        loop {
            let Some(task) = alice.task.take() else { break };
            let (task_back, msg) = task.pull_message_to_coordinator();
            alice.task = task_back;
            match msg {
                Some(m) => {
                    alice.network.inject_connection_message(alice.conn_id, m);
                    progress = true;
                }
                None => break,
            }
            if alice.task.is_none() {
                break;
            }
        }
        loop {
            let Some(task) = bob_task.take() else { break };
            let (task_back, msg) = task.pull_message_to_coordinator();
            bob_task = task_back;
            match msg {
                Some(m) => {
                    bob_network.inject_connection_message(bob_conn_id, m);
                    progress = true;
                }
                None => break,
            }
            if bob_task.is_none() {
                break;
            }
        }

        while let Some(event) = alice.network.next_event() {
            progress = true;
            match event {
                Event::HandshakeFinished { .. } => alice
                    .network
                    .gossip_open(
                        alice.chain_id,
                        &bob_peer_id,
                        GossipKind::ConsensusTransactions,
                    )
                    .unwrap(),
                Event::GossipSecondaryClosed { error, .. } => {
                    errors.push(error);
                    if reopen_on_event {
                        alice
                            .network
                            .gossip_reopen_secondaries(alice.chain_id, &bob_peer_id)
                            .unwrap();
                    }
                }
                _ => {}
            }
        }
        while let Some(event) = bob_network.next_event() {
            progress = true;
            match event {
                collection::Event::InboundNegotiated {
                    substream_id,
                    protocol_name,
                    ..
                } => {
                    if protocol_name == "/ipfs/ping/1.0.0" {
                        bob_network.accept_inbound(substream_id, collection::InboundTy::Ping);
                    } else if protocol_name == block_announces_name
                        || protocol_name == transactions_name
                    {
                        bob_protocols.insert(substream_id, protocol_name);
                        bob_network.accept_inbound(
                            substream_id,
                            collection::InboundTy::Notifications {
                                max_handshake_size: 1024,
                            },
                        );
                    } else {
                        bob_network.reject_inbound(substream_id);
                    }
                }
                collection::Event::NotificationsInOpen { substream_id, .. } => {
                    if bob_protocols.get(&substream_id) == Some(&block_announces_name) {
                        bob_network.accept_in_notifications(
                            substream_id,
                            bob_handshake.clone(),
                            1024 * 1024,
                        );
                        continue;
                    }
                    opens += 1;
                    // A regression that reopens on its own would loop forever otherwise.
                    assert!(
                        opens <= replies.len() + 1,
                        "transactions substream reopened without a call"
                    );
                    match replies
                        .get(opens - 1)
                        .copied()
                        .unwrap_or(SecondaryReply::Refuse)
                    {
                        SecondaryReply::Refuse => bob_network.reject_in_notifications(substream_id),
                        SecondaryReply::Accept => {
                            bob_network.accept_in_notifications(substream_id, Vec::new(), 1024)
                        }
                    }
                }
                _ => {}
            }
        }

        if progress {
            idle_advances = 0;
            continue;
        }

        // Like `Harness::pump`: when nothing moves, advance time to the earliest requested
        // wake-up, bounded so that pings don't keep the loop alive forever.
        let next_wake = [wake_a, wake_b].into_iter().flatten().min();
        match next_wake {
            Some(w)
                if idle_advances < 100 && cmp::max(now, w) + Duration::from_nanos(1) <= ceiling =>
            {
                now = cmp::max(now, w) + Duration::from_nanos(1);
                idle_advances += 1;
            }
            _ => break,
        }
    }

    (opens, errors, alice)
}

/// Issue #3412: a peer that refuses the transactions substream, as a full node without a slot
/// for the light client does, is not asked again on its own. The refusal is reported once, and
/// the gossip link stays open.
#[test]
fn secondary_substream_refusal_is_reported_not_reopened() {
    let (opens, errors, alice) = secondary_substream_exchange(&[SecondaryReply::Refuse], false);
    assert_eq!(opens, 1);
    assert!(matches!(
        errors.as_slice(),
        [Some(NotificationsOutErr::Substream(
            established::NotificationsOutErr::RefusedHandshake
        ))]
    ));
    assert!(alice.network.gossip_is_connected(
        alice.chain_id,
        &alice.remote,
        GossipKind::ConsensusTransactions
    ));
}

/// After an [`Event::GossipSecondaryClosed`], `gossip_reopen_secondaries` opens the missing
/// substream again, and nothing more happens once the peer accepts it.
#[test]
fn gossip_reopen_secondaries_opens_the_missing_substream() {
    let (opens, errors, _) =
        secondary_substream_exchange(&[SecondaryReply::Refuse, SecondaryReply::Accept], true);
    assert_eq!(opens, 2);
    assert_eq!(errors.len(), 1);
}
