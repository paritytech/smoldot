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

use core::{iter, pin::Pin, time::Duration};
use futures::{
    channel::{mpsc, oneshot},
    lock::Mutex,
    prelude::*,
};
use std::{sync::Arc, time::Instant};
use substrate_lite::network::{
    libp2p::{connection, peer_id::PeerId},
    request_response, with_buffers,
};

/// Configuration for a [`NetworkService`].
pub struct Config {
    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(Pin<Box<dyn Future<Output = ()> + Send>>)>,
}

pub enum Event {
    Connected(PeerId),
}

pub struct NetworkService {
    to_background: Mutex<mpsc::Sender<ToBackground>>,
    from_background: Mutex<mpsc::Receiver<FromBackground>>,
}

impl NetworkService {
    pub fn new(mut config: Config) -> Arc<Self> {
        let (to_foreground, from_background) = mpsc::channel(16); // TODO: size
        let (to_background, from_foreground) = mpsc::channel(16); // TODO: size

        // TODO: temporary for testing
        (config.tasks_executor)(Box::pin(task(to_foreground, from_foreground)));

        Arc::new(NetworkService {
            to_background: Mutex::new(to_background),
            from_background: Mutex::new(from_background),
        })
    }

    // TODO: proper error type
    pub async fn blocks_request(
        self: &Arc<Self>,
        target: PeerId,
        config: request_response::BlocksRequestConfig,
    ) -> Result<Vec<request_response::BlockData>, ()> {
        let mut to_background = self.to_background.lock().await;

        let (send_back, receive_result) = oneshot::channel();

        to_background
            .send(ToBackground::BlocksRequest {
                target,
                config,
                send_back,
            })
            .await
            .unwrap();

        receive_result.await.unwrap()
    }

    pub async fn next_event(&self) -> Event {
        match self.from_background.lock().await.next().await.unwrap() {
            FromBackground::Connected(peer_id) => Event::Connected(peer_id),
            FromBackground::Disconnected(peer_id) => todo!(),
        }
    }
}

enum ToBackground {
    BlocksRequest {
        target: PeerId,
        config: request_response::BlocksRequestConfig,
        send_back: oneshot::Sender<Result<Vec<request_response::BlockData>, ()>>,
    },
}

enum FromBackground {
    Connected(PeerId),
    Disconnected(PeerId),
}

// TODO: this function is temporary
async fn task(
    mut to_foreground: mpsc::Sender<FromBackground>,
    mut from_foreground: mpsc::Receiver<ToBackground>,
) {
    /*let mut peerset = substrate_lite::network::peerset::Peerset::new(substrate_lite::network::peerset::Config {
        randomness_seed: [0; 32],
    });*/

    // peerset.insert("/dns/p2p.cc1-0.polkadot.network/tcp/30100/p2p/12D3KooWEdsXX9657ppNqqrRuaCHFvuNemasgU5msLDwSJ6WqsKc");
    // peerset.insert("/dns/p2p.cc1-1.polkadot.network/tcp/30100/p2p/12D3KooWAtx477KzC8LwqLjWWUG6WF4Gqp2eNXmeqAG98ehAMWYH");
    // peerset.insert("/dns/p2p.cc1-2.polkadot.network/tcp/30100/p2p/12D3KooWAGCCPZbr9UWGXPtBosTZo91Hb5M3hU8v6xbKgnC5LVao");
    // peerset.insert("/dns/p2p.cc1-3.polkadot.network/tcp/30100/p2p/12D3KooWJ4eyPowiVcPU46pXuE2cDsiAmuBKXnFcFPapm4xKFdMJ");
    // peerset.insert("/dns/p2p.cc1-4.polkadot.network/tcp/30100/p2p/12D3KooWNMUcqwSj38oEq1zHeGnWKmMvrCFnpMftw7JzjAtRj2rU");
    // peerset.insert("/dns/p2p.cc1-5.polkadot.network/tcp/30100/p2p/12D3KooWDs6LnpmWDWgZyGtcLVr3E75CoBxzg1YZUPL5Bb1zz6fM");
    // peerset.insert("/dns/cc1-0.parity.tech/tcp/30333/p2p/12D3KooWSz8r2WyCdsfWHgPyvD8GKQdJ1UAiRmrcrs8sQB3fe2KU");
    // peerset.insert("/dns/cc1-1.parity.tech/tcp/30333/p2p/12D3KooWFN2mhgpkJsDBuNuE5427AcDrsib8EoqGMZmkxWwx3Md4");

    /*while num_outgoing_connected_pending < 25 {
        if let Some(node) = peerset.overlay(0).unwrap().random_disconnected() {
            for address in node.addresses() {

            }

            node.connect();
        }
    }*/

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
                to_foreground
                    .send(FromBackground::Connected(remote_peer_id))
                    .await
                    .unwrap();
                break connection;
            }
        }
    };

    println!("Connected!");

    let mut connection = connection.into_connection::<_, oneshot::Sender<_>, (), _, _>(
        connection::established::Config {
            in_request_protocols: iter::once("/ipfs/ping/1.0.0"),
            in_notifications_protocols: iter::once("/dot/block-announces/1"), // TODO:
            randomness_seed: rand::random(),
        },
    );

    let mut poll_after = futures_timer::Delay::new(Duration::from_secs(3600));

    loop {
        // TODO: shouldn't unwrap here
        let (read_buffer, write_buffer) = tcp_socket.buffers().unwrap();

        let now = Instant::now();

        let read_write = connection
            .read_write(now, read_buffer.map(|b| b.0), write_buffer.unwrap().0)
            .unwrap();
        connection = read_write.connection;

        if let Some(wake_up) = read_write.wake_up_after {
            if wake_up > now {
                let dur = wake_up - now;
                poll_after = futures_timer::Delay::new(dur);
            } else {
                poll_after = futures_timer::Delay::new(Duration::from_secs(0));
            }
        } else {
            poll_after = futures_timer::Delay::new(Duration::from_secs(3600));
        }

        tcp_socket.advance(read_write.read_bytes, read_write.written_bytes);

        match read_write.event {
            Some(connection::established::Event::Response {
                response,
                user_data,
                ..
            }) => {
                if let Ok(response) = response {
                    let decoded = request_response::decode_block_response(&response).unwrap();
                    let _ = user_data.send(Ok(decoded));
                } else {
                    let _ = user_data.send(Err(()));
                }
            }
            _ => {}
        }

        if read_write.read_bytes != 0 || read_write.written_bytes != 0 {
            continue;
        }

        futures::select! {
            _ = tcp_socket.as_mut().process().fuse() => {},
            timeout = poll_after.fuse() => {
                // Nothing to do, but guarantees that we loop again.
            },
            message = from_foreground.select_next_some().fuse() => {
                match message {
                    ToBackground::BlocksRequest { target, config, send_back } => {
                        let start = config.start.clone();
                        let request = request_response::build_block_request(config)
                            .fold(Vec::new(), |mut a, b| {
                                a.extend_from_slice(b.as_ref());
                                a
                            });
                        let id = connection.add_request(Instant::now(), "/dot/sync/2", request, send_back);
                        println!("start request on {:?} for blocks starting at {:?}", id, start);
                    }
                }
            }
        }
    }
}
