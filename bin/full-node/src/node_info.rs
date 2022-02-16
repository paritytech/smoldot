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

use crate::cli;

use async_std::net::TcpStream;
use futures::prelude::*;
use smoldot::{
    libp2p::{
        async_std_connection,
        connection::{established, handshake, NoiseKey},
    },
    network::protocol,
};
use std::time::{Duration, Instant};

/// Runs the "node info" command.
pub async fn run(cli_options: cli::CliOptionsNodeInfo) {
    // Try to establish the TCP connection.
    let mut tcp_socket = futures::select! {
        result = TcpStream::connect(&cli_options.address).fuse() => {
            match result {
                Ok(s) => {
                    async_std_connection::RunOutcome::Ready(
                        async_std_connection::ConnectionTask::new(s),
                    )
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

    // Generate the noise key.
    let noise_key = if let Some(node_key) = cli_options.libp2p_key {
        NoiseKey::new(&node_key)
    } else {
        NoiseKey::new(&rand::random())
    };

    let mut handshake = handshake::Handshake::new(true);
    let (remote_peer_id, connection_prototype, mut tcp_socket) = loop {
        match (handshake, tcp_socket) {
            (
                handshake::Handshake::Healthy(healthy),
                async_std_connection::RunOutcome::Ready(mut ready),
            ) => {
                match healthy.read_write(&mut ready.read_write(Instant::now())) {
                    Ok(handshake_update) => handshake = handshake_update,
                    Err(err) => {
                        panic!("Error during handshake with remote: {}", err)
                    }
                };

                tcp_socket = ready.resume().await;
            }
            (_, async_std_connection::RunOutcome::IoError(err)) => {
                panic!("Error during handshake with remote: {}", err)
            }
            (handshake_update, async_std_connection::RunOutcome::TimerNeeded(timer)) => {
                handshake = handshake_update;

                let now = Instant::now();
                let when = *timer.when();
                tcp_socket = timer
                    .resume(if when <= now {
                        future::Either::Left(future::ready(()))
                    } else {
                        future::Either::Right(futures_timer::Delay::new(when - now))
                    })
                    .await;
            }
            (handshake::Handshake::NoiseKeyRequired(noise_key_req), tcp_socket_update) => {
                handshake = noise_key_req.resume(&noise_key).into();
                tcp_socket = tcp_socket_update;
            }
            (
                handshake::Handshake::Success {
                    remote_peer_id,
                    connection,
                },
                tcp_socket_update,
            ) => break (remote_peer_id, connection, tcp_socket_update),
        }
    };

    println!("Remote identity is: {}", remote_peer_id);

    let mut established = connection_prototype.into_connection::<_, (), ()>(established::Config {
        notifications_protocols: Vec::new(),
        first_out_ping: Instant::now(),
        ping_interval: Duration::from_secs(60),
        ping_protocol: "/ipfs/ping/1.0.0".into(),
        ping_timeout: Duration::from_secs(10),
        randomness_seed: rand::random(),
        request_protocols: vec![established::ConfigRequestResponse {
            name: "/ipfs/id/1.0.0".into(),
            inbound_config: established::ConfigRequestResponseIn::Empty,
            max_response_size: 4096,
            inbound_allowed: false,
        }],
    });

    let _ = established.add_request(0, Vec::new(), Instant::now() + Duration::from_secs(20), ());

    let identify = 'outer: loop {
        match tcp_socket {
            async_std_connection::RunOutcome::Ready(mut ready) => {
                loop {
                    let event = match established.read_write(&mut ready.read_write(Instant::now()))
                    {
                        Ok((established_update, event)) => {
                            established = established_update;
                            event
                        }
                        Err(err) => {
                            panic!("Error during connection with remote: {}", err)
                        }
                    };

                    match event {
                        Some(established::Event::Response { response, .. }) => {
                            match protocol::decode_identify_response(&response.unwrap()) {
                                Ok(identify) => break 'outer identify,
                                Err(err) => panic!("Failed to decode remote identify: {}", err),
                            }
                        }
                        Some(_) => {}
                        None => break,
                    }
                }

                tcp_socket = ready.resume().await;
            }
            async_std_connection::RunOutcome::IoError(err) => {
                panic!("Error during connection with remote: {}", err)
            }
            async_std_connection::RunOutcome::TimerNeeded(timer) => {
                let now = Instant::now();
                let when = *timer.when();
                tcp_socket = timer
                    .resume(if when <= now {
                        future::Either::Left(future::ready(()))
                    } else {
                        future::Either::Right(futures_timer::Delay::new(when - now))
                    })
                    .await;
            }
        }
    };

    // TODO: print nicer?
    println!("Remote identification: {:?}", identify);

    // TODO: open a substream for each supported `/block-announces/` protocol and find the best block of the node
}
