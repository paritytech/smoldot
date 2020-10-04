// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![recursion_limit = "512"]

// TODO: temporary binary to try the networking alone

use core::iter;
use futures::prelude::*;
use std::time::Instant;
use substrate_lite::network::libp2p::connection;

fn main() {
    env_logger::init();
    futures::executor::block_on(async_main())
}

async fn async_main() {
    let tcp_socket = async_std::net::TcpStream::connect("127.0.0.1:30333")
        .await
        .unwrap();

    let noise_key = connection::NoiseKey::new(&rand::random());

    let mut read_buffer = vec![0; 4096];
    let mut read_buffer_ready = 0;
    let mut write_buffer = vec![0; 4096];
    let mut write_buffer_offset = 0;
    let mut write_buffer_ready = 0;

    let mut connection = connection::Handshake::new(true);
    let connection = loop {
        match connection {
            connection::Handshake::Healthy(handshake) => {
                let (new_state, read, written) = handshake
                    .read_write(
                        &read_buffer[..read_buffer_ready],
                        if write_buffer_ready == 0 {
                            debug_assert_eq!(write_buffer_offset, 0);
                            debug_assert!(!write_buffer.is_empty());
                            &mut write_buffer
                        } else {
                            &mut []
                        },
                    )
                    .unwrap();

                if write_buffer_ready == 0 {
                    write_buffer_ready = written;
                    debug_assert_eq!(write_buffer_offset, 0);
                }

                // TODO: ugly
                for _ in 0..read {
                    read_buffer.remove(0);
                }
                read_buffer.resize(4096, 0);
                read_buffer_ready -= read;

                if read != 0 {
                    connection = new_state;
                    continue;
                }

                let mut tcp_socket_ref1 = &tcp_socket;
                let mut tcp_socket_ref2 = &tcp_socket;

                futures::select! {
                    read = async {
                        if read_buffer_ready == 0 {
                            tcp_socket_ref1.read(&mut read_buffer).await.expect("read error")
                        } else {
                            loop { futures::pending!() }
                        }
                    }.fuse() => {
                        if read == 0 {
                            panic!() // TODO:
                        }
                        read_buffer_ready = read;
                    }
                    written = async {
                        if write_buffer_ready != 0 {
                            debug_assert_ne!(write_buffer_ready, write_buffer_offset);
                            tcp_socket_ref2
                                .write(&write_buffer[..write_buffer_ready][write_buffer_offset..])
                                .await
                                .expect("write error")
                        } else {
                            loop { futures::pending!() }
                        }
                    }.fuse() => {
                        write_buffer_offset += written;
                        if write_buffer_offset == write_buffer_ready {
                            write_buffer_offset = 0;
                            write_buffer_ready = 0;
                        }
                    }
                }

                connection = new_state;
            }
            connection::Handshake::NoiseKeyRequired(key) => {
                connection = key.resume(&noise_key).into()
            }
            connection::Handshake::Success {
                remote_peer_id,
                connection,
            } => {
                println!("Id = {}", remote_peer_id);
                break connection;
            }
        }
    };

    println!("Connected!");

    let mut connection = connection.into_connection::<_, (), (), _, _>(connection::Config {
        in_request_protocols: iter::once("/ipfs/ping/1.0.0"),
        in_notifications_protocols: iter::once("/dot/block-announces/1"), // TODO:
    });

    connection.add_request(Instant::now(), "/dot/sync/2", vec![0x1, 0x2, 0x3, 0x4], ());

    loop {
        let read_write = connection
            .read_write(
                Instant::now(),
                Some(&read_buffer[..read_buffer_ready]),
                if write_buffer_ready == 0 {
                    debug_assert_eq!(write_buffer_offset, 0);
                    debug_assert!(!write_buffer.is_empty());
                    &mut write_buffer
                } else {
                    &mut []
                },
            )
            .unwrap();

        if write_buffer_ready == 0 {
            write_buffer_ready = read_write.written_bytes;
            debug_assert_eq!(write_buffer_offset, 0);
        }

        // TODO: ugly
        for _ in 0..read_write.read_bytes {
            read_buffer.remove(0);
        }
        read_buffer.resize(4096, 0);
        read_buffer_ready -= read_write.read_bytes;

        if read_write.read_bytes != 0 {
            connection = read_write.connection;
            continue;
        }

        let mut tcp_socket_ref1 = &tcp_socket;
        let mut tcp_socket_ref2 = &tcp_socket;

        futures::select! {
            read = async {
                if read_buffer_ready == 0 {
                    tcp_socket_ref1.read(&mut read_buffer).await.expect("read error")
                } else {
                    loop { futures::pending!() }
                }
            }.fuse() => {
                if read == 0 {
                    panic!() // TODO:
                }
                read_buffer_ready = read;
            }
            written = async {
                if write_buffer_ready != 0 {
                    debug_assert_ne!(write_buffer_ready, write_buffer_offset);
                    tcp_socket_ref2
                        .write(&write_buffer[..write_buffer_ready][write_buffer_offset..])
                        .await
                        .expect("write error")
                } else {
                    loop { futures::pending!() }
                }
            }.fuse() => {
                write_buffer_offset += written;
                if write_buffer_offset == write_buffer_ready {
                    write_buffer_offset = 0;
                    write_buffer_ready = 0;
                }
            }
        }

        connection = read_write.connection;
    }
}
