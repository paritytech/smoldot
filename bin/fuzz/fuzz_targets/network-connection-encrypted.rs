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

#![no_main]

use smoldot::libp2p::{
    connection::{
        established::{Config, ConfigRequestResponse, ConfigRequestResponseIn, Event},
        handshake, noise,
    },
    read_write::ReadWrite,
};

use core::{iter, time::Duration};

// This fuzzing target simulates an incoming or outgoing connection whose handshake has succeeded.
// The remote endpoint of that connection sends the fuzzing data to smoldot after it has been
// encrypted. Encrypting the fuzzing data means that the fuzzing test will not trigger payload
// decode failures. The data that smoldot sends back on that connection is silently discarded and
// doesn't influence the behaviour of this fuzzing test.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut data = data;

    // We use the first element of ̀`data` to determine whether we have opened the connection
    // or whether the remote has opened it.
    let local_is_initiator = {
        if data.is_empty() {
            return;
        }
        let is_initiator = (data[0] % 2) == 0;
        data = &data[1..];
        is_initiator
    };

    let mut local = handshake::Handshake::new(local_is_initiator);
    let mut remote = handshake::Handshake::new(!local_is_initiator);

    // Note that the noise keys and randomness are constant rather than being derived from the
    // fuzzing data. This is because we're not here to fuzz the cryptographic code (which we
    // assume is working well) but everything around it (decoding frames, allocating buffers,
    // etc.).
    let local_key = noise::NoiseKey::new(&[0; 32]);
    let remote_key = noise::NoiseKey::new(&[1; 32]);

    // Store the data that the local has emitted but the remote hasn't received yet, and vice
    // versa.
    let mut local_to_remote_buffer = Vec::with_capacity(8192);
    let mut remote_to_local_buffer = Vec::with_capacity(8192);

    // Perform handshake.
    while !matches!(
        (&local, &remote),
        (
            handshake::Handshake::Success { .. },
            handshake::Handshake::Success { .. }
        )
    ) {
        match local {
            handshake::Handshake::Success { .. } => {}
            handshake::Handshake::NoiseKeyRequired(key_req) => {
                local = key_req.resume(&local_key).into()
            }
            handshake::Handshake::Healthy(nego) => {
                let local_to_remote_buffer_len = local_to_remote_buffer.len();
                if local_to_remote_buffer_len < local_to_remote_buffer.capacity() {
                    let cap = local_to_remote_buffer.capacity();
                    local_to_remote_buffer.resize(cap, 0);
                }
                let mut read_write = ReadWrite {
                    now: Duration::new(0, 0),
                    incoming_buffer: Some(&remote_to_local_buffer),
                    outgoing_buffer: Some((
                        &mut local_to_remote_buffer[local_to_remote_buffer_len..],
                        &mut [],
                    )),
                    read_bytes: 0,
                    written_bytes: 0,
                    wake_up_after: None,
                };

                local = nego.read_write(&mut read_write).unwrap();
                let (read_bytes, written_bytes) = (read_write.read_bytes, read_write.written_bytes);
                for _ in 0..read_bytes {
                    remote_to_local_buffer.remove(0);
                }
                local_to_remote_buffer.truncate(local_to_remote_buffer_len + written_bytes);
            }
        }

        match remote {
            handshake::Handshake::Success { .. } => {}
            handshake::Handshake::NoiseKeyRequired(key_req) => {
                remote = key_req.resume(&remote_key).into()
            }
            handshake::Handshake::Healthy(nego) => {
                let remote_to_local_buffer_len = remote_to_local_buffer.len();
                if remote_to_local_buffer_len < remote_to_local_buffer.capacity() {
                    let cap = remote_to_local_buffer.capacity();
                    remote_to_local_buffer.resize(cap, 0);
                }
                let mut read_write = ReadWrite {
                    now: Duration::new(0, 0),
                    incoming_buffer: Some(&local_to_remote_buffer),
                    outgoing_buffer: Some((
                        &mut remote_to_local_buffer[remote_to_local_buffer_len..],
                        &mut [],
                    )),
                    read_bytes: 0,
                    written_bytes: 0,
                    wake_up_after: None,
                };

                remote = nego.read_write(&mut read_write).unwrap();
                let (read_bytes, written_bytes) = (read_write.read_bytes, read_write.written_bytes);
                for _ in 0..read_bytes {
                    local_to_remote_buffer.remove(0);
                }
                remote_to_local_buffer.truncate(remote_to_local_buffer_len + written_bytes);
            }
        }
    }

    // Handshake successful.
    // Turn `local` and `remote` into state machines corresponding to the established connection.
    let mut local = match local {
        handshake::Handshake::Success { connection, .. } => connection
            .into_connection::<_, (), ()>(Config {
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
            }),
        _ => unreachable!(),
    };
    let mut remote = match remote {
        handshake::Handshake::Success { connection, .. } => connection.into_noise_state_machine(),
        _ => unreachable!(),
    };

    // From this point on we will just discard the data sent by `local`.
    // Reset the buffer and fill it with zeroes.
    local_to_remote_buffer = vec![0; 8192];

    // We now encrypt the fuzzing data and add it to the buffer to send to the remote. This is
    // done all in one go.
    {
        // Need to find the size that the encrypted data will occupy. This is done in a rather
        // inefficient way because this is a test.
        let mut size = 4096;
        while remote.encrypt_size_conv(size) < data.len() {
            size *= 2;
        }
        let mut encrypted = vec![0; size];
        let (read, written) = remote.encrypt(iter::once(data), (&mut encrypted, &mut []));
        assert_eq!(read, data.len());
        remote_to_local_buffer.extend_from_slice(&encrypted[..written]);
    }

    // Now send the data to the connection.
    loop {
        let mut local_read_write = ReadWrite {
            now: Duration::new(0, 0),
            incoming_buffer: Some(&remote_to_local_buffer),
            outgoing_buffer: Some((&mut local_to_remote_buffer, &mut [])),
            read_bytes: 0,
            written_bytes: 0,
            wake_up_after: None,
        };

        let local_event = match local.read_write(&mut local_read_write) {
            Ok((new_local, local_event)) => {
                local = new_local;
                local_event
            }
            Err(_) => return, // Invalid data. Counts as fuzzing success.
        };

        let (local_read_bytes, local_written_bytes) =
            (local_read_write.read_bytes, local_read_write.written_bytes);

        for _ in 0..local_read_bytes {
            remote_to_local_buffer.remove(0);
        }

        // Process some of the events in order to drive the fuzz test as far as possible.
        match local_event {
            None => {}
            Some(Event::RequestIn { id, .. }) => {
                let _ = local.respond_in_request(id, Ok(b"dummy response".to_vec()));
                continue;
            }
            Some(Event::NotificationsInOpen { id, .. }) => {
                local.accept_in_notifications_substream(id, b"dummy handshake".to_vec(), ());
                continue;
            }

            Some(_) => continue,
        }

        if local_read_bytes != 0 || local_written_bytes != 0 {
            continue;
        }

        // Nothing more will happen. Test successful.
        break;
    }
});
