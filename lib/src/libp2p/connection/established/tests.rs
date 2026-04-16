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
    BitswapOutOpenErr, Config, Event, InboundError, InboundTy, NotificationsOutErr, RequestError,
    SingleStream,
};
use crate::libp2p::read_write::ReadWrite;
use core::{cmp, mem, time::Duration};

struct TwoEstablished {
    alice: SingleStream<Duration, ()>,
    bob: SingleStream<Duration, ()>,
    alice_to_bob_buffer: Vec<u8>,
    bob_to_alice_buffer: Vec<u8>,

    alice_to_bob_buffer_size: usize,
    bob_to_alice_buffer_size: usize,

    /// Time that has elapsed since an unspecified epoch.
    now: Duration,

    /// Next time Alice or Bob needs to be polled.
    wake_up_after: Option<Duration>,
}

/// Performs a handshake between two peers, and returns the established connection objects.
fn perform_handshake(
    mut alice_to_bob_buffer_size: usize,
    mut bob_to_alice_buffer_size: usize,
    alice_config: Config<Duration>,
    bob_config: Config<Duration>,
) -> TwoEstablished {
    use super::super::{NoiseKey, single_stream_handshake};

    assert_ne!(alice_to_bob_buffer_size, 0);
    assert_ne!(bob_to_alice_buffer_size, 0);

    let alice_key = NoiseKey::new(&rand::random(), &rand::random());
    let bob_key = NoiseKey::new(&rand::random(), &rand::random());

    let mut alice =
        single_stream_handshake::Handshake::noise_yamux(&alice_key, &rand::random(), true);
    let mut bob = single_stream_handshake::Handshake::noise_yamux(&bob_key, &rand::random(), false);

    let mut alice_to_bob_buffer = Vec::new();
    let mut bob_to_alice_buffer = Vec::new();

    while !matches!(
        (&alice, &bob),
        (
            single_stream_handshake::Handshake::Success { .. },
            single_stream_handshake::Handshake::Success { .. }
        )
    ) {
        match alice {
            single_stream_handshake::Handshake::Success { .. } => {}
            single_stream_handshake::Handshake::Healthy(nego) => {
                let mut read_write = ReadWrite {
                    now: Duration::new(0, 0),
                    incoming_buffer: bob_to_alice_buffer,
                    expected_incoming_bytes: Some(0),
                    read_bytes: 0,
                    write_bytes_queued: alice_to_bob_buffer.len(),
                    write_bytes_queueable: Some(
                        alice_to_bob_buffer_size - alice_to_bob_buffer.len(),
                    ),
                    write_buffers: vec![mem::take(&mut alice_to_bob_buffer)],
                    wake_up_after: None,
                };

                alice = nego.read_write(&mut read_write).unwrap();
                bob_to_alice_buffer = read_write.incoming_buffer;
                alice_to_bob_buffer.extend(
                    read_write
                        .write_buffers
                        .drain(..)
                        .flat_map(|b| b.into_iter()),
                );
                bob_to_alice_buffer_size = cmp::max(
                    bob_to_alice_buffer_size,
                    read_write.expected_incoming_bytes.unwrap_or(0),
                );
            }
        }

        match bob {
            single_stream_handshake::Handshake::Success { .. } => {}
            single_stream_handshake::Handshake::Healthy(nego) => {
                let mut read_write = ReadWrite {
                    now: Duration::new(0, 0),
                    incoming_buffer: alice_to_bob_buffer,
                    expected_incoming_bytes: Some(0),
                    read_bytes: 0,
                    write_bytes_queued: bob_to_alice_buffer.len(),
                    write_bytes_queueable: Some(
                        bob_to_alice_buffer_size - bob_to_alice_buffer.len(),
                    ),
                    write_buffers: vec![mem::take(&mut bob_to_alice_buffer)],
                    wake_up_after: None,
                };

                bob = nego.read_write(&mut read_write).unwrap();
                alice_to_bob_buffer = read_write.incoming_buffer;
                bob_to_alice_buffer.extend(
                    read_write
                        .write_buffers
                        .drain(..)
                        .flat_map(|b| b.into_iter()),
                );
                alice_to_bob_buffer_size = cmp::max(
                    alice_to_bob_buffer_size,
                    read_write.expected_incoming_bytes.unwrap_or(0),
                );
            }
        }
    }

    let mut connections = TwoEstablished {
        alice: match alice {
            single_stream_handshake::Handshake::Success { connection, .. } => {
                connection.into_connection(alice_config)
            }
            _ => unreachable!(),
        },
        bob: match bob {
            single_stream_handshake::Handshake::Success { connection, .. } => {
                connection.into_connection(bob_config)
            }
            _ => unreachable!(),
        },
        alice_to_bob_buffer,
        bob_to_alice_buffer,
        alice_to_bob_buffer_size,
        bob_to_alice_buffer_size,
        now: Duration::new(0, 0),
        wake_up_after: None,
    };

    for _ in 0..2 {
        let (connections_update, event) = connections.run_until_event();
        connections = connections_update;
        match event {
            either::Left(Event::InboundNegotiated { id, .. }) => {
                connections.alice.accept_inbound(id, InboundTy::Ping, ());
            }
            either::Right(Event::InboundNegotiated { id, .. }) => {
                connections.bob.accept_inbound(id, InboundTy::Ping, ());
            }
            _ev => unreachable!("{:?}", _ev),
        }
    }

    connections
}

impl TwoEstablished {
    fn pass_time(&mut self, amount: Duration) {
        self.now += amount;
    }

    fn run_until_event(mut self) -> (Self, either::Either<Event<()>, Event<()>>) {
        loop {
            let mut alice_read_write = ReadWrite {
                now: self.now,
                incoming_buffer: self.bob_to_alice_buffer,
                expected_incoming_bytes: Some(0),
                read_bytes: 0,
                write_bytes_queued: self.alice_to_bob_buffer.len(),
                write_bytes_queueable: Some(
                    self.alice_to_bob_buffer_size - self.alice_to_bob_buffer.len(),
                ),
                write_buffers: vec![mem::take(&mut self.alice_to_bob_buffer)],
                wake_up_after: self.wake_up_after,
            };

            let (new_alice, alice_event) = self.alice.read_write(&mut alice_read_write).unwrap();
            self.bob_to_alice_buffer = alice_read_write.incoming_buffer;
            self.alice = new_alice;
            let alice_read_bytes = alice_read_write.read_bytes;
            let alice_written_bytes = alice_read_write.write_bytes_queued;
            self.alice_to_bob_buffer.extend(
                alice_read_write
                    .write_buffers
                    .drain(..)
                    .flat_map(|b| b.into_iter()),
            );
            self.bob_to_alice_buffer_size = cmp::max(
                self.bob_to_alice_buffer_size,
                alice_read_write.expected_incoming_bytes.unwrap_or(0),
            );
            self.wake_up_after = alice_read_write.wake_up_after;

            if let Some(event) = alice_event {
                return (self, either::Left(event));
            }

            let mut bob_read_write = ReadWrite {
                now: self.now,
                incoming_buffer: self.alice_to_bob_buffer,
                expected_incoming_bytes: Some(0),
                read_bytes: 0,
                write_bytes_queued: self.bob_to_alice_buffer.len(),
                write_bytes_queueable: Some(
                    self.bob_to_alice_buffer_size - self.bob_to_alice_buffer.len(),
                ),
                write_buffers: vec![mem::take(&mut self.bob_to_alice_buffer)],
                wake_up_after: self.wake_up_after,
            };

            let (new_bob, bob_event) = self.bob.read_write(&mut bob_read_write).unwrap();
            self.alice_to_bob_buffer = bob_read_write.incoming_buffer;
            self.bob = new_bob;
            let bob_read_bytes = bob_read_write.read_bytes;
            let bob_written_bytes = bob_read_write.write_bytes_queued;
            self.bob_to_alice_buffer.extend(
                bob_read_write
                    .write_buffers
                    .drain(..)
                    .flat_map(|b| b.into_iter()),
            );
            self.alice_to_bob_buffer_size = cmp::max(
                self.alice_to_bob_buffer_size,
                bob_read_write.expected_incoming_bytes.unwrap_or(0),
            );
            self.wake_up_after = bob_read_write.wake_up_after;

            if let Some(event) = bob_event {
                return (self, either::Right(event));
            }

            if bob_read_bytes != 0
                || bob_written_bytes != 0
                || alice_read_bytes != 0
                || alice_written_bytes != 0
            {
                continue;
            }

            // Nothing more will happen immediately. Advance time before looping again.
            if let Some(wake_up_after) = self.wake_up_after.take() {
                self.now = wake_up_after + Duration::new(0, 1); // TODO: adding 1 ns is a hack
            } else {
                // TODO: what to do here?! nothing more will happen
                panic!();
            }
        }
    }
}

#[test]
fn handshake_works() {
    fn test_with_buffer_sizes(size1: usize, size2: usize) {
        let config = Config {
            first_out_ping: Duration::new(0, 0),
            max_inbound_substreams: 64,
            substreams_capacity: 16,
            max_protocol_name_len: 128,
            ping_interval: Duration::from_secs(20),
            ping_protocol: "ping".to_owned(),
            ping_timeout: Duration::from_secs(20),
            randomness_seed: [0; 32],
        };

        perform_handshake(size1, size2, config.clone(), config);
    }

    test_with_buffer_sizes(256, 256);
    // TODO: doesn't work
    /*test_with_buffer_sizes(1, 1);
    test_with_buffer_sizes(1, 2048);
    test_with_buffer_sizes(2048, 1);*/
}

#[test]
#[ignore] // TODO: un-ignore
fn successful_request() {
    let config = Config {
        first_out_ping: Duration::new(60, 0),
        max_inbound_substreams: 64,
        substreams_capacity: 16,
        max_protocol_name_len: 128,
        ping_interval: Duration::from_secs(20),
        ping_protocol: "ping".to_owned(),
        ping_timeout: Duration::from_secs(20),
        randomness_seed: [0; 32],
    };

    let mut connections = perform_handshake(256, 256, config.clone(), config);

    let substream_id = connections.alice.add_request(
        "test-request-protocol".to_owned(),
        Some(b"request payload".to_vec()),
        Duration::from_secs(5),
        1024,
        (),
    );

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, protocol_name }) => {
            assert_eq!(protocol_name, "test-request-protocol");
            connections.bob.accept_inbound(
                id,
                InboundTy::Request {
                    request_max_size: Some(1024 * 1024),
                },
                (),
            );
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::RequestIn { id, request }) => {
            assert_eq!(request, b"request payload");
            connections
                .bob
                .respond_in_request(id, Ok(b"response payload".to_vec()))
                .unwrap();
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (_, event) = connections.run_until_event();
    match event {
        either::Left(Event::Response { id, response, .. }) => {
            assert_eq!(id, substream_id);
            assert_eq!(response.unwrap(), b"response payload".to_vec());
        }
        _ev => unreachable!("{:?}", _ev),
    }
}

#[test]
fn refused_request() {
    let config = Config {
        first_out_ping: Duration::new(60, 0),
        max_inbound_substreams: 64,
        substreams_capacity: 16,
        max_protocol_name_len: 128,
        ping_interval: Duration::from_secs(20),
        ping_protocol: "ping".to_owned(),
        ping_timeout: Duration::from_secs(20),
        randomness_seed: [0; 32],
    };

    let mut connections = perform_handshake(256, 256, config.clone(), config);

    let substream_id = connections.alice.add_request(
        "test-request-protocol".to_owned(),
        Some(b"request payload".to_vec()),
        Duration::from_secs(5),
        1024,
        (),
    );

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, protocol_name }) => {
            assert_eq!(protocol_name, "test-request-protocol");
            connections.bob.accept_inbound(
                id,
                InboundTy::Request {
                    request_max_size: Some(1024 * 1024),
                },
                (),
            );
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::RequestIn { id, request }) => {
            assert_eq!(request, b"request payload");
            connections.bob.respond_in_request(id, Err(())).unwrap();
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (_, event) = connections.run_until_event();
    match event {
        either::Left(Event::Response { id, response, .. }) => {
            assert_eq!(id, substream_id);
            assert!(matches!(response, Err(RequestError::SubstreamClosed)));
        }
        _ev => unreachable!("{:?}", _ev),
    }
}

#[test]
fn request_protocol_not_supported() {
    let alice_config = Config {
        first_out_ping: Duration::new(60, 0),
        max_inbound_substreams: 64,
        substreams_capacity: 16,
        max_protocol_name_len: 128,
        ping_interval: Duration::from_secs(20),
        ping_protocol: "ping".to_owned(),
        ping_timeout: Duration::from_secs(20),
        randomness_seed: [0; 32],
    };

    let bob_config = Config {
        ..alice_config.clone()
    };

    let mut connections = perform_handshake(256, 256, alice_config, bob_config);

    let substream_id = connections.alice.add_request(
        "test-request-protocol".to_owned(),
        Some(b"request payload".to_vec()),
        Duration::from_secs(5),
        1024,
        (),
    );

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, protocol_name }) => {
            assert_eq!(protocol_name, "test-request-protocol");
            connections.bob.reject_inbound(id);
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (_, event) = connections.run_until_event();
    match event {
        either::Left(Event::Response { id, response, .. }) => {
            assert_eq!(id, substream_id);
            assert!(matches!(response, Err(RequestError::ProtocolNotAvailable)));
        }
        either::Right(Event::InboundError(InboundError::NegotiationError(_))) => {}
        _ev => unreachable!("{:?}", _ev),
    }
}

#[test]
fn request_timeout() {
    let config = Config {
        first_out_ping: Duration::new(60, 0),
        max_inbound_substreams: 64,
        substreams_capacity: 16,
        max_protocol_name_len: 128,
        ping_interval: Duration::from_secs(20),
        ping_protocol: "ping".to_owned(),
        ping_timeout: Duration::from_secs(20),
        randomness_seed: [0; 32],
    };

    let mut connections = perform_handshake(256, 256, config.clone(), config);

    let substream_id = connections.alice.add_request(
        "test-request-protocol".to_owned(),
        Some(b"request payload".to_vec()),
        Duration::from_secs(5),
        1024,
        (),
    );

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, protocol_name }) => {
            assert_eq!(protocol_name, "test-request-protocol");
            connections.bob.accept_inbound(
                id,
                InboundTy::Request {
                    request_max_size: Some(1024 * 1024),
                },
                (),
            );
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::RequestIn { request, .. }) => {
            assert_eq!(request, b"request payload");
            // Don't answer.
        }
        _ev => unreachable!("{:?}", _ev),
    }

    connections.pass_time(Duration::from_secs(6));

    let (_, event) = connections.run_until_event();
    match event {
        either::Left(Event::Response { id, response, .. }) => {
            assert_eq!(id, substream_id);
            assert!(matches!(response, Err(RequestError::Timeout)));
        }
        _ev => unreachable!("{:?}", _ev),
    }
}

#[test]
fn outbound_substream_works() {
    let config = Config {
        first_out_ping: Duration::new(60, 0),
        max_inbound_substreams: 64,
        substreams_capacity: 16,
        max_protocol_name_len: 128,
        ping_interval: Duration::from_secs(20),
        ping_protocol: "ping".to_owned(),
        ping_timeout: Duration::from_secs(20),
        randomness_seed: [0; 32],
    };

    let mut connections = perform_handshake(256, 256, config.clone(), config);

    let substream_id = connections.alice.open_notifications_substream(
        "test-notif-protocol".to_owned(),
        b"hello".to_vec(),
        1024,
        connections.now + Duration::from_secs(5),
        (),
    );

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, protocol_name }) => {
            assert_eq!(protocol_name, "test-notif-protocol");
            connections.bob.accept_inbound(
                id,
                InboundTy::Notifications {
                    max_handshake_size: 1024,
                },
                (),
            );
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::NotificationsInOpen { id, handshake }) => {
            assert_eq!(handshake, b"hello");
            connections
                .bob
                .accept_in_notifications_substream(id, b"hello back".to_vec(), 4 * 1024);
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let notifications_to_send = vec![
        b"notif 1".to_vec(),
        b"notif 2".to_vec(),
        b"notif 3".to_vec(),
    ];
    let mut notifications_to_receive = notifications_to_send.clone();

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Left(Event::NotificationsOutResult {
            id,
            result: Ok(handshake),
        }) => {
            assert_eq!(id, substream_id);
            assert_eq!(handshake, b"hello back");
            for notif in notifications_to_send {
                connections.alice.write_notification_unbounded(id, notif);
            }
        }
        _ev => unreachable!("{:?}", _ev),
    }

    while !notifications_to_receive.is_empty() {
        let (connections_update, event) = connections.run_until_event();
        connections = connections_update;
        match event {
            either::Right(Event::NotificationIn { notification, .. }) => {
                let pos = notifications_to_receive
                    .iter()
                    .position(|n| *n == notification)
                    .unwrap();
                notifications_to_receive.remove(pos);
            }
            _ev => unreachable!("{:?}", _ev),
        }
    }
}

#[test]
fn outbound_substream_open_timeout() {
    let config = Config {
        first_out_ping: Duration::new(60, 0),
        max_inbound_substreams: 64,
        substreams_capacity: 16,
        max_protocol_name_len: 128,
        ping_interval: Duration::from_secs(20),
        ping_protocol: "ping".to_owned(),
        ping_timeout: Duration::from_secs(20),
        randomness_seed: [0; 32],
    };

    let mut connections = perform_handshake(256, 256, config.clone(), config);

    let substream_id = connections.alice.open_notifications_substream(
        "test-notif-protocol".to_owned(),
        b"hello".to_vec(),
        1024,
        connections.now + Duration::from_secs(5),
        (),
    );

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, protocol_name }) => {
            assert_eq!(protocol_name, "test-notif-protocol");
            connections.bob.accept_inbound(
                id,
                InboundTy::Notifications {
                    max_handshake_size: 1024,
                },
                (),
            );
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::NotificationsInOpen { handshake, .. }) => {
            assert_eq!(handshake, b"hello");
            // Don't answer.
        }
        _ev => unreachable!("{:?}", _ev),
    }

    connections.pass_time(Duration::from_secs(10));

    let (_, event) = connections.run_until_event();
    match event {
        either::Left(Event::NotificationsOutResult { id, result, .. }) => {
            assert_eq!(id, substream_id);
            assert!(matches!(result, Err((NotificationsOutErr::Timeout, _))));
        }
        _ev => unreachable!("{:?}", _ev),
    }
}

#[test]
fn outbound_substream_refuse() {
    let config = Config {
        first_out_ping: Duration::new(60, 0),
        max_inbound_substreams: 64,
        substreams_capacity: 16,
        max_protocol_name_len: 128,
        ping_interval: Duration::from_secs(20),
        ping_protocol: "ping".to_owned(),
        ping_timeout: Duration::from_secs(20),
        randomness_seed: [0; 32],
    };

    let mut connections = perform_handshake(256, 256, config.clone(), config);

    let substream_id = connections.alice.open_notifications_substream(
        "test-notif-protocol".to_owned(),
        b"hello".to_vec(),
        1024,
        connections.now + Duration::from_secs(5),
        (),
    );

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, protocol_name }) => {
            assert_eq!(protocol_name, "test-notif-protocol");
            connections.bob.accept_inbound(
                id,
                InboundTy::Notifications {
                    max_handshake_size: 1024,
                },
                (),
            );
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::NotificationsInOpen { id, handshake }) => {
            assert_eq!(handshake, b"hello");
            connections.bob.reject_in_notifications_substream(id);
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (_, event) = connections.run_until_event();
    match event {
        either::Left(Event::NotificationsOutResult {
            id,
            result: Err((NotificationsOutErr::RefusedHandshake, _)),
            ..
        }) => {
            assert_eq!(id, substream_id);
        }
        _ev => unreachable!("{:?}", _ev),
    }
}

#[test]
#[ignore] // TODO: un-ignore
fn outbound_substream_close_demanded() {
    let config = Config {
        first_out_ping: Duration::new(60, 0),
        max_inbound_substreams: 64,
        substreams_capacity: 16,
        max_protocol_name_len: 128,
        ping_interval: Duration::from_secs(20),
        ping_protocol: "ping".to_owned(),
        ping_timeout: Duration::from_secs(20),
        randomness_seed: [0; 32],
    };

    let mut connections = perform_handshake(256, 256, config.clone(), config);

    let substream_id = connections.alice.open_notifications_substream(
        "test-notif-protocol".to_owned(),
        b"hello".to_vec(),
        1024,
        connections.now + Duration::from_secs(5),
        (),
    );

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, protocol_name }) => {
            assert_eq!(protocol_name, "test-notif-protocol");
            connections.bob.accept_inbound(
                id,
                InboundTy::Notifications {
                    max_handshake_size: 1024,
                },
                (),
            );
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::NotificationsInOpen { id, handshake }) => {
            assert_eq!(handshake, b"hello");
            connections
                .bob
                .accept_in_notifications_substream(id, b"hello back".to_vec(), 4 * 1024);
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Left(Event::NotificationsOutResult {
            id,
            result: Ok(handshake),
        }) => {
            assert_eq!(id, substream_id);
            assert_eq!(handshake, b"hello back");
            connections
                .alice
                .write_notification_unbounded(id, b"notif".to_vec());
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::NotificationIn { id, notification }) => {
            assert_eq!(notification, b"notif");
            connections
                .bob
                .close_in_notifications_substream(id, Duration::from_secs(100))
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Left(Event::NotificationsOutCloseDemanded { id }) => {
            connections.alice.close_out_notifications_substream(id);
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (_, event) = connections.run_until_event();
    match event {
        either::Right(Event::NotificationsInClose {
            outcome: Ok(()), ..
        }) => {}
        _ev => unreachable!("{:?}", _ev),
    }
}

// TODO: more tests

fn default_config() -> Config<Duration> {
    Config {
        first_out_ping: Duration::new(60, 0),
        max_inbound_substreams: 64,
        substreams_capacity: 16,
        max_protocol_name_len: 128,
        ping_interval: Duration::from_secs(20),
        ping_protocol: "ping".to_owned(),
        ping_timeout: Duration::from_secs(20),
        randomness_seed: [0; 32],
    }
}

#[test]
fn bitswap_outbound_negotiation_success() {
    let config = default_config();
    let mut connections = perform_handshake(256, 256, config.clone(), config);

    let substream_id = connections.alice.open_bitswap_substream(());

    // Bob receives the inbound negotiation.
    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, protocol_name }) => {
            assert_eq!(protocol_name, "/ipfs/bitswap/1.2.0");
            connections.bob.accept_inbound(id, InboundTy::Bitswap, ());
        }
        _ev => unreachable!("{:?}", _ev),
    }

    // Bob reports the inbound Bitswap substream opened.
    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::BitswapInOpen { .. }) => {}
        _ev => unreachable!("{:?}", _ev),
    }

    // Alice gets the outbound open result.
    let (_, event) = connections.run_until_event();
    match event {
        either::Left(Event::BitswapOutOpenResult { id, result: Ok(()) }) => {
            assert_eq!(id, substream_id);
        }
        _ev => unreachable!("{:?}", _ev),
    }
}

#[test]
fn bitswap_outbound_rejected() {
    let config = default_config();
    let mut connections = perform_handshake(256, 256, config.clone(), config);

    let substream_id = connections.alice.open_bitswap_substream(());

    // Bob rejects the inbound negotiation.
    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, .. }) => {
            connections.bob.reject_inbound(id);
        }
        _ev => unreachable!("{:?}", _ev),
    }

    // Alice gets ProtocolNotAvailable.
    let (_, event) = connections.run_until_event();
    match event {
        either::Left(Event::BitswapOutOpenResult {
            id,
            result: Err((BitswapOutOpenErr::ProtocolNotAvailable, _)),
        }) => {
            assert_eq!(id, substream_id);
        }
        _ev => unreachable!("{:?}", _ev),
    }
}

#[test]
fn bitswap_send_and_receive_message() {
    let config = default_config();
    let mut connections = perform_handshake(4096, 4096, config.clone(), config);

    let substream_id = connections.alice.open_bitswap_substream(());

    // Bob accepts.
    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, .. }) => {
            connections.bob.accept_inbound(id, InboundTy::Bitswap, ());
        }
        _ev => unreachable!("{:?}", _ev),
    }

    // Drain BitswapInOpen event on Bob's side.
    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::BitswapInOpen { .. }) => {}
        _ev => unreachable!("{:?}", _ev),
    }

    // Drain BitswapOutOpenResult on Alice's side.
    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Left(Event::BitswapOutOpenResult { result: Ok(()), .. }) => {}
        _ev => unreachable!("{:?}", _ev),
    }

    // Alice sends a Bitswap message.
    let message = b"test bitswap message payload".to_vec();
    connections
        .alice
        .write_bitswap_message_unbounded(substream_id, message.clone());

    // Bob receives the message.
    let (_, event) = connections.run_until_event();
    match event {
        either::Right(Event::BitswapIn {
            message: received, ..
        }) => {
            assert_eq!(received, message);
        }
        _ev => unreachable!("{:?}", _ev),
    }
}

#[test]
fn bitswap_close_outbound_after_open() {
    let config = default_config();
    let mut connections = perform_handshake(4096, 4096, config.clone(), config);

    let substream_id = connections.alice.open_bitswap_substream(());

    // Bob accepts.
    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, .. }) => {
            connections.bob.accept_inbound(id, InboundTy::Bitswap, ());
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::BitswapInOpen { .. }) => {}
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Left(Event::BitswapOutOpenResult { result: Ok(()), .. }) => {}
        _ev => unreachable!("{:?}", _ev),
    }

    // Alice closes the outbound substream.
    connections.alice.close_out_bitswap_substream(substream_id);

    // Bob should see the inbound close (as an error, since Bitswap has no graceful close).
    let (_, event) = connections.run_until_event();
    match event {
        either::Right(Event::BitswapInClose {
            outcome: Err(_), ..
        }) => {}
        _ev => unreachable!("{:?}", _ev),
    }
}

#[test]
fn bitswap_queued_bytes_tracking() {
    let config = default_config();
    let mut connections = perform_handshake(4096, 4096, config.clone(), config);

    let substream_id = connections.alice.open_bitswap_substream(());

    // Bob accepts.
    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, .. }) => {
            connections.bob.accept_inbound(id, InboundTy::Bitswap, ());
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::BitswapInOpen { .. }) => {}
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Left(Event::BitswapOutOpenResult { result: Ok(()), .. }) => {}
        _ev => unreachable!("{:?}", _ev),
    }

    assert_eq!(
        connections
            .alice
            .bitswap_substream_queued_bytes(substream_id),
        0
    );

    // Queue a message and verify bytes are tracked.
    let message = vec![0u8; 100];
    connections
        .alice
        .write_bitswap_message_unbounded(substream_id, message);

    // Queued bytes should be > 0 (message + LEB128 length prefix).
    assert!(
        connections
            .alice
            .bitswap_substream_queued_bytes(substream_id)
            > 0
    );
}

#[test]
fn bitswap_multiple_messages() {
    let config = default_config();
    let mut connections = perform_handshake(8192, 8192, config.clone(), config);

    let substream_id = connections.alice.open_bitswap_substream(());

    // Bob accepts.
    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::InboundNegotiated { id, .. }) => {
            connections.bob.accept_inbound(id, InboundTy::Bitswap, ());
        }
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::BitswapInOpen { .. }) => {}
        _ev => unreachable!("{:?}", _ev),
    }

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Left(Event::BitswapOutOpenResult { result: Ok(()), .. }) => {}
        _ev => unreachable!("{:?}", _ev),
    }

    // Send multiple messages.
    let messages = vec![
        b"message one".to_vec(),
        b"message two".to_vec(),
        b"message three".to_vec(),
    ];
    for msg in &messages {
        connections
            .alice
            .write_bitswap_message_unbounded(substream_id, msg.clone());
    }

    // Receive all messages (order preserved).
    let mut received = Vec::new();
    for _ in 0..messages.len() {
        let (connections_update, event) = connections.run_until_event();
        connections = connections_update;
        match event {
            either::Right(Event::BitswapIn { message, .. }) => {
                received.push(message);
            }
            _ev => unreachable!("{:?}", _ev),
        }
    }

    assert_eq!(received, messages);
}
