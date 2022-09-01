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

use super::{Config, ConfigRequestResponse, ConfigRequestResponseIn, Event, SingleStream};
use crate::libp2p::read_write::ReadWrite;
use std::time::Duration;

struct TwoEstablished {
    alice: SingleStream<Duration, (), ()>,
    bob: SingleStream<Duration, (), ()>,
    alice_to_bob_buffer: Vec<u8>,
    bob_to_alice_buffer: Vec<u8>,

    /// Time that has elapsed since an unspecified epoch.
    now: Duration,

    /// Next time Alice or Bob needs to be polled.
    wake_up_after: Option<Duration>,
}

/// Performs a handshake between two peers, and returns the established connection objects.
fn perform_handshake(
    alice_to_bob_buffer_size: usize,
    bob_to_alice_buffer_size: usize,
    alice_config: Config<Duration>,
    bob_config: Config<Duration>,
) -> TwoEstablished {
    use super::super::{handshake, NoiseKey};

    assert_ne!(alice_to_bob_buffer_size, 0);
    assert_ne!(bob_to_alice_buffer_size, 0);

    let mut alice = handshake::Handshake::new(true);
    let mut bob = handshake::Handshake::new(false);

    let alice_key = NoiseKey::new(&rand::random());
    let bob_key = NoiseKey::new(&rand::random());

    let mut alice_to_bob_buffer = Vec::with_capacity(alice_to_bob_buffer_size);
    let mut bob_to_alice_buffer = Vec::with_capacity(bob_to_alice_buffer_size);

    while !matches!(
        (&alice, &bob),
        (
            handshake::Handshake::Success { .. },
            handshake::Handshake::Success { .. }
        )
    ) {
        match alice {
            handshake::Handshake::Success { .. } => {}
            handshake::Handshake::NoiseKeyRequired(key_req) => {
                alice = key_req.resume(&alice_key).into()
            }
            handshake::Handshake::Healthy(nego) => {
                let alice_to_bob_buffer_len = alice_to_bob_buffer.len();
                if alice_to_bob_buffer_len < alice_to_bob_buffer.capacity() {
                    let cap = alice_to_bob_buffer.capacity();
                    alice_to_bob_buffer.resize(cap, 0);
                }
                let mut read_write = ReadWrite {
                    now: Duration::new(0, 0),
                    incoming_buffer: Some(&bob_to_alice_buffer),
                    outgoing_buffer: Some((
                        &mut alice_to_bob_buffer[alice_to_bob_buffer_len..],
                        &mut [],
                    )),
                    read_bytes: 0,
                    written_bytes: 0,
                    wake_up_after: None,
                };

                alice = nego.read_write(&mut read_write).unwrap();
                let (read_bytes, written_bytes) = (read_write.read_bytes, read_write.written_bytes);
                for _ in 0..read_bytes {
                    bob_to_alice_buffer.remove(0);
                }
                alice_to_bob_buffer.truncate(alice_to_bob_buffer_len + written_bytes);
            }
        }

        match bob {
            handshake::Handshake::Success { .. } => {}
            handshake::Handshake::NoiseKeyRequired(key_req) => {
                bob = key_req.resume(&bob_key).into()
            }
            handshake::Handshake::Healthy(nego) => {
                let bob_to_alice_buffer_len = bob_to_alice_buffer.len();
                if bob_to_alice_buffer_len < bob_to_alice_buffer.capacity() {
                    let cap = bob_to_alice_buffer.capacity();
                    bob_to_alice_buffer.resize(cap, 0);
                }
                let mut read_write = ReadWrite {
                    now: Duration::new(0, 0),
                    incoming_buffer: Some(&alice_to_bob_buffer),
                    outgoing_buffer: Some((
                        &mut bob_to_alice_buffer[bob_to_alice_buffer_len..],
                        &mut [],
                    )),
                    read_bytes: 0,
                    written_bytes: 0,
                    wake_up_after: None,
                };

                bob = nego.read_write(&mut read_write).unwrap();
                let (read_bytes, written_bytes) = (read_write.read_bytes, read_write.written_bytes);
                for _ in 0..read_bytes {
                    alice_to_bob_buffer.remove(0);
                }
                bob_to_alice_buffer.truncate(bob_to_alice_buffer_len + written_bytes);
            }
        }
    }

    TwoEstablished {
        alice: match alice {
            handshake::Handshake::Success { connection, .. } => {
                connection.into_connection(alice_config)
            }
            _ => unreachable!(),
        },
        bob: match bob {
            handshake::Handshake::Success { connection, .. } => {
                connection.into_connection(bob_config)
            }
            _ => unreachable!(),
        },
        alice_to_bob_buffer,
        bob_to_alice_buffer,
        now: Duration::new(0, 0),
        wake_up_after: None,
    }
}

impl TwoEstablished {
    fn run_until_event(mut self) -> (Self, either::Either<Event<(), ()>, Event<(), ()>>) {
        loop {
            let alice_to_bob_buffer_len = self.alice_to_bob_buffer.len();
            if alice_to_bob_buffer_len < self.alice_to_bob_buffer.capacity() {
                let cap = self.alice_to_bob_buffer.capacity();
                self.alice_to_bob_buffer.resize(cap, 0);
            }
            let mut alice_read_write = ReadWrite {
                now: self.now,
                incoming_buffer: Some(&self.bob_to_alice_buffer),
                outgoing_buffer: Some((
                    &mut self.alice_to_bob_buffer[alice_to_bob_buffer_len..],
                    &mut [],
                )),
                read_bytes: 0,
                written_bytes: 0,
                wake_up_after: self.wake_up_after,
            };

            let (new_alice, alice_event) = self.alice.read_write(&mut alice_read_write).unwrap();
            self.alice = new_alice;
            let (alice_read_bytes, alice_written_bytes) =
                (alice_read_write.read_bytes, alice_read_write.written_bytes);
            self.wake_up_after = alice_read_write.wake_up_after;
            for _ in 0..alice_read_bytes {
                self.bob_to_alice_buffer.remove(0);
            }
            self.alice_to_bob_buffer
                .truncate(alice_to_bob_buffer_len + alice_written_bytes);

            if let Some(event) = alice_event {
                return (self, either::Left(event));
            }

            let bob_to_alice_buffer_len = self.bob_to_alice_buffer.len();
            if bob_to_alice_buffer_len < self.bob_to_alice_buffer.capacity() {
                let cap = self.bob_to_alice_buffer.capacity();
                self.bob_to_alice_buffer.resize(cap, 0);
            }
            let mut bob_read_write = ReadWrite {
                now: self.now,
                incoming_buffer: Some(&self.alice_to_bob_buffer),
                outgoing_buffer: Some((
                    &mut self.bob_to_alice_buffer[bob_to_alice_buffer_len..],
                    &mut [],
                )),
                read_bytes: 0,
                written_bytes: 0,
                wake_up_after: self.wake_up_after,
            };

            let (new_bob, bob_event) = self.bob.read_write(&mut bob_read_write).unwrap();
            self.bob = new_bob;
            let (bob_read_bytes, bob_written_bytes) =
                (bob_read_write.read_bytes, bob_read_write.written_bytes);
            self.wake_up_after = bob_read_write.wake_up_after;
            for _ in 0..bob_read_bytes {
                self.alice_to_bob_buffer.remove(0);
            }
            self.bob_to_alice_buffer
                .truncate(bob_to_alice_buffer_len + bob_written_bytes);

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
            notifications_protocols: Vec::new(),
            request_protocols: Vec::new(),
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
fn successful_request() {
    let config = Config {
        first_out_ping: Duration::new(60, 0),
        notifications_protocols: Vec::new(),
        request_protocols: vec![ConfigRequestResponse {
            inbound_allowed: true,
            inbound_config: ConfigRequestResponseIn::Payload { max_size: 128 },
            max_response_size: 1024,
            name: "test-request-protocol".to_owned(),
        }],
        ping_interval: Duration::from_secs(20),
        ping_protocol: "ping".to_owned(),
        ping_timeout: Duration::from_secs(20),
        randomness_seed: [0; 32],
    };

    let mut connections = perform_handshake(256, 256, config.clone(), config);

    let substream_id =
        connections
            .alice
            .add_request(0, b"request payload".to_vec(), Duration::from_secs(5), ());

    let (connections_update, event) = connections.run_until_event();
    connections = connections_update;
    match event {
        either::Right(Event::RequestIn {
            id,
            protocol_index: 0,
            request,
        }) => {
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

// TODO: more tests
