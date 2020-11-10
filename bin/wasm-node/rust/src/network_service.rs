// Substrate-lite
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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

//! Background network service.
//!
//! The [`NetworkService`] manages background tasks dedicated to connecting to other nodes.
//! Importantly, its design is oriented towards the particular use case of the full node.
//!
//! The [`NetworkService`] spawns one background task (using the [`Config::tasks_executor`]) for
//! each active TCP socket, plus one for each TCP listening socket. Messages are exchanged between
//! the service and these background tasks.

// TODO: doc
// TODO: re-review this once finished

use crate::ffi;

use core::pin::Pin;
use futures::prelude::*;
use std::{io, sync::Arc};
use substrate_lite::network::{
    connection,
    multiaddr::{Multiaddr, Protocol},
    peer_id::PeerId,
    peerset, protocol,
};

/// Configuration for a [`NetworkService`].
pub struct Config {
    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(Pin<Box<dyn Future<Output = ()> + Send>>) + Send>,

    /// List of node identities and addresses that are known to belong to the chain's peer-to-pee
    /// network.
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
}

pub struct NetworkService {
    /// Key used for the encryption layer.
    /// This is a Noise static key, according to the Noise specifications.
    /// Signed using the actual libp2p key.
    noise_key: Arc<connection::NoiseKey>,

    /// Holds the state of all the known nodes of the network, and of all the connections (pending
    /// or not).
    peerset: peerset::Peerset<(), (), ()>,
}

impl NetworkService {
    /// Initializes the network service with the given configuration.
    pub async fn new(config: Config) -> Result<Arc<Self>, InitError> {
        // The peerset, created below, is a data structure that helps keep track of the state of
        // the current peers and connections.
        let mut peerset = peerset::Peerset::new(peerset::Config {
            randomness_seed: rand::random(),
            peers_capacity: 50,
            num_overlay_networks: 1,
        });

        // Add to overlay #0 the nodes known to belong to the network.
        for (peer_id, address) in config.bootstrap_nodes {
            let mut node = peerset.node_mut(peer_id).or_default();
            node.add_known_address(address);
            node.add_to_overlay(0);
        }

        Ok(Arc::new(NetworkService {
            noise_key: Arc::new(connection::NoiseKey::new(&rand::random())),
            peerset,
        }))
    }

    /// Sends a blocks request to the given peer.
    // TODO: more docs
    // TODO: proper error type
    pub async fn blocks_request(
        self: &Arc<Self>,
        target: PeerId,
        config: protocol::BlocksRequestConfig,
    ) -> Result<Vec<protocol::BlockData>, ()> {
        todo!()
    }

    /// Returns the next event that happens in the network service.
    ///
    /// If this method is called multiple times simultaneously, the events will be distributed
    /// amongst the different calls in an unpredictable way.
    pub async fn next_event(&self) -> Event {
        self.fill_out_slots().await;

        todo!()
    }

    /// Spawns new outgoing connections in order to fill empty outgoing slots.
    ///
    /// Must be passed as parameter an existing lock to a [`Guarded`].
    async fn fill_out_slots<'a>(&self, guarded: &mut MutexGuard<'a, Guarded>) {
        // Solves borrow checking errors regarding the borrow of multiple different fields at the
        // same time.
        let guarded = &mut **guarded;

        // TODO: very wip
        while let Some(mut node) = guarded.peerset.random_not_connected(0) {
            // TODO: collecting into a Vec, annoying
            for address in node.known_addresses().cloned().collect::<Vec<_>>() {
                let url = match multiaddr_to_url(&address) {
                    Ok(url) => url,
                    Err(()) => {
                        node.remove_known_address(&address).unwrap();
                        continue;
                    }
                };

                let (tx, rx) = mpsc::channel(8);
                let connection_id = node.add_outbound_attempt(address.clone(), tx);
                (guarded.tasks_executor)(Box::pin(connection_task(
                    url,
                    true,
                    self.noise_key.clone(),
                    connection_id,
                    self.to_foreground.clone(),
                    rx,
                )));
            }

            break;
        }
    }
}

/// Event that can happen on the network service.
pub enum Event {
    Connected(PeerId),
    Disconnected(PeerId),
}

/// Error when initializing the network service.
#[derive(Debug, derive_more::Display)]
pub enum InitError {
    // TODO: add variants or remove error altogether
}

async fn connection_task(url: String, is_initiator: bool, noise_key: Arc<connection::NoiseKey>) {}

/// Returns the URL that corresponds to the given multiaddress. Returns an error if the
/// multiaddress protocols aren't supported.
fn multiaddr_to_url(addr: &Multiaddr) -> Result<String, ()> {
    let mut iter = addr.iter();
    let proto1 = iter.next().ok_or(())?;
    let proto2 = iter.next().ok_or(())?;
    let proto3 = iter.next().ok_or(())?;

    if iter.next().is_some() {
        return Err(());
    }

    match (proto1, proto2, proto3) {
        (Protocol::Ip4(ip), Protocol::Tcp(port), Protocol::Ws(url)) => {
            Ok(format!("ws://{}:{}/{}", ip, port, url))
        }
        (Protocol::Ip6(ip), Protocol::Tcp(port), Protocol::Ws(url)) => {
            Ok(format!("ws://[{}]:{}/{}", ip, port, url))
        }
        (Protocol::Ip4(ip), Protocol::Tcp(port), Protocol::Wss(url)) => {
            Ok(format!("wss://{}:{}/{}", ip, port, url))
        }
        (Protocol::Ip6(ip), Protocol::Tcp(port), Protocol::Wss(url)) => {
            Ok(format!("wss://[{}]:{}/{}", ip, port, url))
        }
        (Protocol::Dns(domain), Protocol::Tcp(port), Protocol::Ws(url))
        | (Protocol::Dns4(domain), Protocol::Tcp(port), Protocol::Ws(url))
        | (Protocol::Dns6(domain), Protocol::Tcp(port), Protocol::Ws(url)) => {
            Ok(format!("ws://{}:{}/{}", domain, port, url))
        }
        (Protocol::Dns(domain), Protocol::Tcp(port), Protocol::Wss(url))
        | (Protocol::Dns4(domain), Protocol::Tcp(port), Protocol::Wss(url))
        | (Protocol::Dns6(domain), Protocol::Tcp(port), Protocol::Wss(url)) => {
            Ok(format!("wss://{}:{}/{}", domain, port, url))
        }
        _ => Err(()),
    }
}

/// Drives the handshake of the given connection.
///
/// # Panic
///
/// Panics if the `tcp_socket` is closed in the writing direction.
///
async fn perform_handshake(
    tcp_socket: &mut ffi::WebSocket,
    noise_key: &connection::NoiseKey,
    is_initiator: bool,
) -> Result<(connection::established::ConnectionPrototype, PeerId), HandshakeError> {
    let mut handshake = connection::handshake::Handshake::new(is_initiator);

    // Delay that triggers after we consider the remote is considered unresponsive.
    // The constant here has been chosen arbitrary.
    let timeout = futures_timer::Delay::new(Duration::from_secs(20));
    futures::pin_mut!(timeout);

    loop {
        match handshake {
            connection::handshake::Handshake::Success {
                remote_peer_id,
                connection,
            } => {
                break Ok((connection, remote_peer_id));
            }
            connection::handshake::Handshake::NoiseKeyRequired(key) => {
                handshake = key.resume(noise_key).into()
            }
            connection::handshake::Handshake::Healthy(healthy) => {
                let (read_buffer, write_buffer) = match tcp_socket.buffers() {
                    Ok(v) => v,
                    Err(_) => return Err(HandshakeError::Io),
                };

                // Update the handshake state machine with the received data, and writes in the
                // write buffer..
                let (new_state, num_read, num_written) = {
                    let read_buffer = read_buffer.ok_or(HandshakeError::UnexpectedEof)?.0;
                    // `write_buffer` can only be `None` if `close` has been manually called,
                    // which never happens.
                    let write_buffer = write_buffer.unwrap();
                    healthy.read_write(read_buffer, write_buffer)?
                };
                handshake = new_state;
                tcp_socket.advance(num_read, num_written);

                if num_read != 0 || num_written != 0 {
                    continue;
                }

                // Wait either for something to happen on the socket, or for the timeout to
                // trigger.
                {
                    let process_future = tcp_socket.as_mut().process();
                    futures::pin_mut!(process_future);
                    match future::select(process_future, &mut timeout).await {
                        future::Either::Left(_) => {}
                        future::Either::Right(_) => return Err(HandshakeError::Timeout),
                    }
                }
            }
        }
    }
}

#[derive(Debug, derive_more::Display, derive_more::From)]
enum HandshakeError {
    Io,
    Timeout,
    UnexpectedEof,
    Protocol(connection::handshake::HandshakeError),
}
