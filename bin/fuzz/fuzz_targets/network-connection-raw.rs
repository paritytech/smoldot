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

use core::time::Duration;

// This fuzzing target simulates an incoming or outgoing connection. The remote endpoint of that
// connection sends the fuzzing data to smoldot. The data that smoldot sends back on that
// connection is silently discarded and doesn't influence the behaviour of this fuzzing test.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut data = data;

    // Note that the noise key and randomness are constant rather than being derived from the
    // fuzzing data. This is because we're not here to fuzz the cryptographic code (which we
    // assume is working well) but everything around it (decoding frames, allocating buffers,
    // etc.).
    let mut collection =
        smoldot::libp2p::collection::Network::new(smoldot::libp2p::collection::Config {
            randomness_seed: [0; 32],
            capacity: 0,
            max_inbound_substreams: 10,
            notification_protocols: Vec::new(),
            request_response_protocols: Vec::new(),
            // This timeout doesn't matter as we pass dummy time values.
            handshake_timeout: Duration::from_secs(5),
            ping_protocol: "ping".into(),
            noise_key: smoldot::libp2p::connection::NoiseKey::new(&[0; 32]),
        });

    // We use the first element of ̀`data` to determine whether we have opened the connection
    // or whether the remote has opened it.
    let is_initiator = {
        if data.is_empty() {
            return;
        }
        let is_initiator = (data[0] % 2) == 0;
        data = &data[1..];
        is_initiator
    };

    let (_id, mut task) = collection.insert_single_stream(Duration::new(0, 0), is_initiator, ());

    let mut out_buffer = vec![0; 4096];

    loop {
        let mut read_write = smoldot::libp2p::read_write::ReadWrite {
            now: Duration::new(0, 0),
            incoming_buffer: Some(data),
            outgoing_buffer: Some((&mut out_buffer, &mut [])),
            read_bytes: 0,
            written_bytes: 0,
            wake_up_after: None,
        };
        task.read_write(&mut read_write);

        let read_bytes = read_write.read_bytes;
        let written_bytes = read_write.written_bytes;
        data = &data[read_bytes..];

        // We need to call `pull_message_to_coordinator()`, as the connection state machine might
        // refuse to process more incoming data before events have been pulled.
        let (task_update, event) = task.pull_message_to_coordinator();
        match task_update {
            Some(t) => task = t,
            None => break,
        }

        if event.is_none() && read_bytes == 0 && written_bytes == 0 {
            // Stop the test.
            break;
        }
    }
});
