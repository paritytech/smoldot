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
use substrate_lite::network::{libp2p::connection, request_response, with_buffers};

fn main() {
    env_logger::init();
    futures::executor::block_on(async_main())
}

async fn async_main() {
    let tcp_socket = with_buffers::WithBuffers::new(
        async_std::net::TcpStream::connect("p2p.cc1-4.polkadot.network:30100")
            .await
            .unwrap(),
    );
    futures::pin_mut!(tcp_socket);

    let noise_key = connection::NoiseKey::new(&rand::random());

    let mut connection = connection::handshake::Handshake::new(true);
    let connection = loop {
        match connection {
            connection::handshake::Handshake::Healthy(handshake) => {
                // TODO: shouldn't unwrap here
                let (read_buffer, write_buffer) = tcp_socket.buffers().unwrap();

                let (new_state, num_read, num_written) = handshake
                    .read_write(
                        read_buffer.map(|b| b.0).unwrap_or(&[]),
                        write_buffer.unwrap().0,
                    )
                    .unwrap();

                tcp_socket.advance(num_read, num_written);

                if num_read != 0 || num_written != 0 {
                    connection = new_state;
                    continue;
                }

                tcp_socket.as_mut().process().await;
                connection = new_state;
            }
            connection::handshake::Handshake::NoiseKeyRequired(key) => {
                connection = key.resume(&noise_key).into()
            }
            connection::handshake::Handshake::Success {
                remote_peer_id,
                connection,
            } => {
                println!("Id = {}", remote_peer_id);
                break connection;
            }
        }
    };

    println!("Connected!");

    let mut connection =
        connection.into_connection::<_, (), (), _, _>(connection::established::Config {
            in_request_protocols: iter::once("/ipfs/ping/1.0.0"),
            in_notifications_protocols: iter::once("/dot/block-announces/1"), // TODO:
            randomness_seed: rand::random(),
        });

    let request = request_response::build_block_request(request_response::BlocksRequestConfig {
        start: request_response::BlocksRequestConfigStart::Number(
            core::num::NonZeroU64::new(1).unwrap(),
        ),
        desired_count: core::num::NonZeroU32::new(u32::max_value()).unwrap(),
        direction: request_response::BlocksRequestDirection::Ascending,
        fields: request_response::BlocksRequestFields {
            header: true,
            body: true,
            justification: false,
        },
    })
    .fold(Vec::new(), |mut a, b| {
        a.extend_from_slice(b.as_ref());
        a
    });

    let id = connection.add_request(Instant::now(), "/dot/sync/2", request, ());
    println!("start request on {:?}", id);

    loop {
        // TODO: shouldn't unwrap here
        let (read_buffer, write_buffer) = tcp_socket.buffers().unwrap();

        let read_write = connection
            .read_write(
                Instant::now(),
                read_buffer.map(|b| b.0),
                write_buffer.unwrap().0,
            )
            .unwrap();

        tcp_socket.advance(read_write.read_bytes, read_write.written_bytes);

        if let Some(event) = read_write.event {
            println!("event: {:?}", event);
        }

        if read_write.read_bytes != 0 || read_write.written_bytes != 0 {
            connection = read_write.connection;
            continue;
        }

        tcp_socket.as_mut().process().await;
        connection = read_write.connection;
    }
}
