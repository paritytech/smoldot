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

//! Networking service. Handles a collection of libp2p TCP connections.
//!
//! # Usage
//!
//! The main data structure in this module is [`Network`], which holds the state of all active
//! and pending libp2p connections to other nodes. The second most important data structure is
//! [`Connection`], which holds the state of a single active connection.
//!
//! The [`Network`] requires [`Connection`] to be spawned. The [`Network`] only holds the latest
//! known state of the various [`Connection`]s associated to it. The state of the [`Network`] and
//! its [`Connection`] isn't performed automatically, and must be performed by the user by
//! exchanging [`ConnectionToService`] and [`ServiceToConnection`] messages between the two.
//!
//! This separation between [`Network`] and [`Connection`] makes it possible to call
//! [`Connection::read_write`] in parallel for multiple different connections. Only the
//! synchronization with the [`Network`] needs to be single-threaded.

use crate::network::{connection, peerset, protocol, Multiaddr, PeerId};

use alloc::sync::Arc;
use core::mem;

/// Configuration for a [`Network`].
pub struct Config<TPeer> {
    /// Addresses to listen for incoming connections.
    pub listen_addresses: Vec<Multiaddr>,

    /// List of node identities and addresses that are known to belong to the chain's peer-to-pee
    /// network.
    pub bootstrap_nodes: Vec<(TPeer, PeerId, Multiaddr)>,

    /// Hash of the genesis block of the chain. Sent to other nodes in order to determine whether
    /// the chain matches between the local and remote node.
    pub genesis_block_hash: [u8; 32],

    /// Number and hash of the current best block. Can later be updated with // TODO: which function?
    pub best_block: (u64, [u8; 32]),

    /// Identifier of the chain to connect to.
    ///
    /// Each blockchain has (or should have) a different "protocol id". This value identifies the
    /// chain, so as to not introduce conflicts in the networking messages.
    pub protocol_id: String,

    /// Key used for the encryption layer.
    /// This is a Noise static key, according to the Noise specifications.
    /// Signed using the actual libp2p key.
    pub noise_key: connection::NoiseKey,
}

/// Identifier of a [`Connection`] spawned by the [`Network`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(peerset::ConnectionId);

/// Data structure containing the list of all connections, pending or not, and their latest known
/// state. See also [the module-level documentation](..).
pub struct Network<TNow, TPeer, TConn, TPending, TSub, TPendingSub, TRq> {
    /// Holds the state of all the known nodes of the network, and of all the connections (pending
    /// or not).
    peerset: peerset::Peerset<TPeer, TConn, TPending, TSub, TPendingSub>,

    /// See [`Config::protocol_id`].
    protocol_id: String,

    /// See [`Config::genesis_block_hash`].
    genesis_block_hash: [u8; 32],

    /// See [`Config::best_block`].
    best_block: (u64, [u8; 32]),

    /// See [`Config::noise_key`].
    noise_key: Arc<connection::NoiseKey>,
}

impl<TNow, TPeer, TConn, TPending, TSub, TPendingSub, TRq>
    Network<TNow, TPeer, TConn, TPending, TSub, TPendingSub, TRq>
{
    /// Initializes a new network data structure.
    pub fn new(config: Config<TPeer>) -> Self {
        // The peerset, created below, is a data structure that helps keep track of the state of
        // the current peers and connections.
        let peerset = peerset::Peerset::new(peerset::Config {
            randomness_seed: rand::random(),
            peers_capacity: 50,
            num_overlay_networks: 1,
        });

        // Add to overlay #0 the nodes known to belong to the network.
        for (user_data, peer_id, address) in config.bootstrap_nodes {
            let mut node = peerset.node_mut(peer_id).or_insert_with(move || user_data);
            node.add_known_address(address);
            node.add_to_overlay(0);
        }

        Network {
            peerset,
            genesis_block_hash: config.genesis_block_hash,
            best_block: config.best_block,
            protocol_id: config.protocol_id,
            noise_key: Arc::new(config.noise_key),
        }
    }

    /// Returns the number of established TCP connections, both incoming and outgoing.
    pub async fn num_established_connections(&self) -> usize {
        self.peerset.num_established_connections()
    }

    pub fn add_incoming_connection(
        &mut self,
        local_listen_address: &Multiaddr,
        remote_addr: Multiaddr,
        user_data: TConn,
    ) -> Connection<TNow, TPeer, TConn, TPending, TSub, TPendingSub, TRq> {
        todo!()
    }

    /// Sends a request to the given peer.
    // TODO: more docs
    // TODO: proper error type
    pub fn start_request(
        &mut self,
        target: PeerId,
        protocol: String,
        request_data: Vec<u8>,
    ) -> Result<Vec<protocol::BlockData>, ()> {
        let connection = match self.peerset.node_mut(target) {
            peerset::NodeMut::Known(n) => n.connections().next().ok_or(())?,
            peerset::NodeMut::Unknown(n) => return Err(()),
        };

        let (send_back, receive_result) = oneshot::channel();

        // TODO: is awaiting here a good idea? if the background task is stuck, we block the entire `Guarded`
        // It is possible for the channel to be closed, if the background task has ended but the
        // frontend hasn't processed this yet.
        guarded
            .peerset
            .connection_mut(connection)
            .unwrap()
            .into_user_data()
            .send(ToConnection::BlocksRequest {
                config,
                protocol,
                send_back,
            })
            .await
            .map_err(|_| ())?;

        // Wait for the result of the request. Can take a long time (i.e. several seconds).
        match receive_result.await {
            Ok(r) => r,
            Err(_) => Err(()),
        }
    }

    /// Inform the [`Network`] of a message coming from a [`Connection`] and returned in a
    /// [`ReadWrite::message`].
    pub fn connection_message(&mut self, message: ConnectionToService) -> Option<Event> {
        match message.inner {
            ConnectionToServiceInner::HandshakeError { .. } => {
                self.peerset
                    .pending_mut(message.id)
                    .unwrap()
                    .remove_and_purge_address();
            }
            ConnectionToServiceInner::HandshakeSuccess { peer_id, accept_tx } => {
                let id = self
                    .peerset
                    .pending_mut(message.id)
                    .unwrap()
                    .into_established(|tx| tx)
                    .id();
                accept_tx.send(id).unwrap();
                return Event::Connected(peer_id);
            }
            ConnectionToServiceInner::Disconnected => {
                let connection = self.peerset.connection_mut(message.id).unwrap();
                let peer_id = connection.peer_id().clone(); // TODO: clone :(
                connection.remove();
                return Event::Disconnected(peer_id);
            }
            ConnectionToServiceInner::NotificationsOpenResult { result, protocol } => todo!(),
            ConnectionToServiceInner::NotificationsCloseResult { protocol } => todo!(),

            ConnectionToServiceInner::NotificationsInOpen { protocol } => todo!(),

            ConnectionToServiceInner::NotificationsInClose { protocol } => todo!(),
        }
    }

    pub fn next(&mut self) -> Option<Event> {}
}

/// Event generated by [`Network::next`].
#[derive(Debug)]
pub enum Event {
    Connected(PeerId),
    Disconnected(PeerId),
}

pub struct Pending {}

impl Pending {
    pub fn reached(self) -> Connection {
        todo!()
    }
}

pub struct Connection<TNow, TPeer, TConn, TPending, TSub, TPendingSub, TRq> {
    inner: ConnectionInner<TNow, TPeer, TConn, TPending, TSub, TPendingSub, TRq>,

    id: ConnectionId,

    /// Clone of [`Network::noise_key`].
    noise_key: Arc<connection::NoiseKey>,
}

enum ConnectionInner<TNow, TPeer, TConn, TPending, TSub, TPendingSub, TRq> {
    Dead,
    Handshake {
        /// Current state of the handshake.
        handshake: connection::handshake::HealthyHandshake,
        /// When the handshake will be considered failed.
        timeout: TNow,
    },
    Established(connection::established::Established<TNow, (), ()>),
}

impl<TNow, TPeer, TConn, TPending, TSub, TPendingSub, TRq>
    Connection<TNow, TPeer, TConn, TPending, TSub, TPendingSub, TRq>
{
    pub fn service_message(&mut self, message: ServiceToConnection) {
        todo!()
    }

    pub fn read_write<'a>(
        &mut self,
        now: TNow,
        mut incoming_buffer: Option<&[u8]>,
        mut outgoing_buffer: (&'a mut [u8], &'a mut [u8]),
    ) -> ReadWrite<TNow, TPeer, TConn, TPending, TSub, TPendingSub, TRq> {
        let mut total_read = 0;
        let mut total_written = 0;

        let message = 'outer_loop: loop {
            match mem::replace(&mut self.inner, ConnectionInner::Dead) {
                ConnectionInner::Handshake { handshake, timeout } => {
                    // TODO: check timeout

                    let (mut result, num_read, num_written) =
                        match handshake.read_write(incoming_buffer, outgoing_buffer) {
                            Ok(r) => r,
                            Err(_) => todo!(),
                        };

                    total_read += num_read;
                    total_written += num_written;

                    loop {
                        match result {
                            connection::handshake::Handshake::Healthy(handshake) => {
                                self.inner = ConnectionInner::Handshake { handshake, timeout };
                                if num_read == 0 && num_written == 0 {
                                    break 'outer_loop None;
                                } else {
                                    break;
                                }
                            }
                            connection::handshake::Handshake::Success {
                                remote_peer_id,
                                connection,
                            } => {
                                self.inner = ConnectionInner::Established(connection);
                                break 'outer_loop Some(ConnectionToService {
                                    id: self.id,
                                    inner: ConnectionToServiceInner::HandshakeSuccess {
                                        peer_id: remote_peer_id,
                                    },
                                });
                            }
                            connection::handshake::Handshake::NoiseKeyRequired(key) => {
                                result = key.resume(&self.noise_key);
                            }
                        }
                    }
                }
                ConnectionInner::Established(_) => todo!(),
                ConnectionInner::Dead => break,
            }
        };

        ReadWrite {
            read_bytes: total_read,
            written_bytes: total_written,
            wake_up_after: None,
            message,
        }
    }
}

/// Outcome of calling [`Connection::read_write`].
pub struct ReadWrite<TNow, TPeer, TConn, TPending, TSub, TPendingSub, TRq> {
    /// Number of bytes at the start of the incoming buffer that have been processed. These bytes
    /// should no longer be present the next time [`Connection::read_write`] is called.
    pub read_bytes: usize,

    /// Number of bytes written to the outgoing buffer. These bytes should be sent out to the
    /// remote. The rest of the outgoing buffer is left untouched.
    pub written_bytes: usize,

    /// If `Some`, [`Connection::read_write`] should be called again when the point in time
    /// reaches the value in the `Option`.
    pub wake_up_after: Option<TNow>,

    /// If `Some`, this message must be reported to the [`Network`] by calling
    /// [`Network::connection_message`].
    pub message: Option<ConnectionToService>,

    /// If true, this [`Connection`] is now useless and can be dropped.
    // TODO: must do clean shut down of TCP connection first
    pub ended: bool,
}

/// Message to be reported to the [`Network`] by calling [`Network::connection_message`].
pub struct ConnectionToService {
    id: ConnectionId,
    inner: ConnectionToServiceInner,
}

enum ConnectionToServiceInner {
    /// Handshake phased has failed. The connection is now dead.
    HandshakeError(connection::handshake::HandshakeError),

    /// Handshake has succeeded. Must be answered with a
    /// [`ServiceToConnectionInner::PostHandshake`] message.
    HandshakeSuccess { peer_id: PeerId },

    /// Connection has closed.
    ///
    /// This only concerns connections onto which the handshake had succeeded. For connections on
    /// which the handshake hadn't succeeded, a [`FromBackground::HandshakeError`] is emitted
    /// instead.
    Disconnected,

    /// Response to a [`ToConnection::OpenOutNotifications`].
    NotificationsOpenResult {
        /// Outcome of the opening. If `Ok`, the notifications protocol is now open. If `Err`, it
        /// is still closed.
        result: Result<(), ()>,
        // TODO: shouldn't pass protocol by String, ideally
        protocol: String,
    },

    /// Response to a [`ToConnection::CloseOutNotifications`].
    ///
    /// Contrary to [`FromBackground::NotificationsOpenResult`], a closing request never fails.
    NotificationsCloseResult {
        // TODO: shouldn't pass protocol by String, ideally
        protocol: String,
    },

    /// The remote opened a notifications substream.
    ///
    /// A [`ToConnection::NotificationsInAccept`] or [`ToConnection::NotificationsInReject`] must
    /// be sent back.
    NotificationsInOpen {
        // TODO: shouldn't pass protocol by String, ideally
        protocol: String,
    },

    /// The remote closed a notifications substream.
    ///
    /// This does not cancel any previously-sent [`FromBackground::NotificationsInOpen`]. Instead,
    /// the response sent to a previously-sent [`FromBackground::NotificationsInOpen`] will be
    /// ignored.
    NotificationsInClose {
        // TODO: shouldn't pass protocol by String, ideally
        protocol: String,
    },
}

pub struct ServiceToConnection {
    inner: ServiceToConnectionInner,
}

enum ServiceToConnectionInner {
    /// Must be sent in response to a [`ConnectionToServiceInner::HandshakeSuccess`].
    PostHandshake {
        /// True if the connection should continue. False if the connection should be dropped.
        accepted: bool,
    },

    /// Start a block request. See [`NetworkService::blocks_request`].
    Request { protocol: String, bytes: Vec<u8> },
    OpenOutNotifications {
        // TODO: shouldn't pass protocol by String, ideally
        protocol: String,
        /// Handshake to initially send to the remote.
        handshake: Vec<u8>,
    },
    CloseOutNotifications {
        // TODO: shouldn't pass protocol by String, ideally
        protocol: String,
    },
    NotificationsInAccept {
        // TODO: shouldn't pass protocol by String, ideally
        protocol: String,
    },
    NotificationsInReject {
        // TODO: shouldn't pass protocol by String, ideally
        protocol: String,
    },
}
