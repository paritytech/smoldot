// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
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

use crate::cli;

use async_std::net::TcpStream;
use futures::prelude::*;
use smoldot::{
    libp2p::{
        async_rw_with_buffers,
        connection::{handshake, NoiseKey},
    },
    network::service::ReadWrite,
};
use std::time::{Duration, Instant};

/// Runs the "node info" command.
pub async fn run(cli_options: cli::CliOptionsNodeInfo) {
    // Try to establish the TCP connection.
    let mut tcp_socket = futures::select! {
        result = TcpStream::connect(&cli_options.address).fuse() => {
            match result {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    async_rw_with_buffers::WithBuffers::new(s)
                },
                Err(err) => {
                    panic!("Failed to reach {}: {}", cli_options.address, err);
                }
            }
        },
        _ = futures_timer::Delay::new(Duration::from_secs(10)).fuse() => {
            panic!("Timeout when trying to reach {}", cli_options.address);
        }
    };

    // Generate a new random noise key.
    let noise_key = if let Some(node_key) = cli_options.node_key {
        NoiseKey::new(node_key.as_ref())
    } else {
        NoiseKey::new(&rand::random())
    };

    let mut handshake = handshake::Handshake::new(true);
    let (remote_peer_id, connection_prototype) = loop {
        match handshake {
            handshake::Handshake::Healthy(healthy) => {
                let (read_buffer, write_buffer) = match tcp_socket.buffers() {
                    Ok(b) => b,
                    Err(error) => {
                        panic!("Disconnected by remote during handshake: {}", error);
                    }
                };

                let read_write = ReadWrite {
                    now: Instant::now(),
                    incoming_buffer: read_buffer.map(|b| b.0),
                    outgoing_buffer: write_buffer,
                    read_bytes: 0,
                    written_bytes: 0,
                    wake_up_after: None,
                    wake_up_future: None,
                };

                match healthy.read_write(&mut read_write) {
                    Ok(handshake_update) => {
                        handshake = handshake_update;
                    }
                    Err(err) => {
                        panic!("Error during handshake with remote: {}", err)
                    }
                }
            }
            handshake::Handshake::NoiseKeyRequired(noise_key_req) => {
                handshake = noise_key_req.resume(&noise_key).into();
            }
            handshake::Handshake::Success {
                remote_peer_id,
                connection,
            } => break (remote_peer_id, connection),
        }
    };

    println!("Remove identity is: {}", remote_peer_id);

    //handshake.
}
