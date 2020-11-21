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

//! Collection of libp2p connections.
//!
//! The [`Network`] struct in this module is a collection of libp2p connections. It uses internal
//! buffering and interior mutability in order to provide a convenient-to-use API based around
//! notifications protocols and request-response protocols.

use crate::network::{connection, peerset, Multiaddr, PeerId};

use alloc::sync::Arc;
use core::{num::NonZeroUsize, task::Context};
use futures::{
    channel::{mpsc, oneshot},
    lock::{Mutex, MutexGuard},
}; // TODO: no_std-ize
use rand::{Rng as _, SeedableRng as _};
use rand_chacha::ChaCha20Core;

/// Configuration for a [`Network`].
pub struct Config<TPeer> {
    /// Seed for the randomness within the networking state machine.
    ///
    /// While this seed influences the general behaviour of the networking state machine, it
    /// notably isn't used when generating the ephemeral key used for the Diffie-Hellman
    /// handshake.
    /// This is a defensive measure against users passing a dummy seed instead of actual entropy.
    pub randomness_seed: [u8; 32],

    /// Addresses to listen for incoming connections.
    pub listen_addresses: Vec<Multiaddr>,

    pub overlay_networks: Vec<OverlayNetwork<TPeer>>,

    pub known_nodes: Vec<(TPeer, PeerId, Multiaddr)>,

    /// Key used for the encryption layer.
    /// This is a Noise static key, according to the Noise specifications.
    /// Signed using the actual libp2p key.
    pub noise_key: connection::NoiseKey,

    /// Number of events that can be buffered internally before connections are back-pressured.
    ///
    /// A good default value is 64.
    ///
    /// # Context
    ///
    /// The [`Network`] maintains an internal buffer of the events returned by
    /// [`Network::next_event`]. When [`Network::read_write`] is called, an event might get pushed
    /// to this buffer. If this buffer is full, back-pressure will be applied to the connections
    /// in order to prevent new events from being pushed.
    ///
    /// This value is important if [`Network::next_event`] is called at a slower than the calls to
    /// [`Network::read_write`] generate events.
    pub pending_api_events_buffer_size: NonZeroUsize,
}

/// Configuration for a specific overlay network.
///
/// See [`Config::overlay_networks`].
pub struct OverlayNetwork<TPeer> {
    /// Name of the protocol negotiated on the wire.
    pub name: String,

    /// Optional alternative names for this protocol. Can represent different versions.
    pub fallback_names: Vec<String>,

    /// List of node identities that are known to belong to this overlay network.
    pub bootstrap_nodes: Vec<PeerId>,

    pub in_slots: u32,

    pub out_slots: u32,
}

/// Identifier of a pending connection requested by the network through a [`Event::StartConnect`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingId(peerset::ConnectionId);

/// Identifier of a [`Connection`] spawned by the [`Network`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(peerset::ConnectionId);

/// Data structure containing the list of all connections, pending or not, and their latest known
/// state. See also [the module-level documentation](..).
pub struct Network<TNow, TPeer, TConn> {
    /// Fields behind a mutex.
    guarded: Mutex<Guarded<TNow, TPeer, TConn>>,

    /// See [`Config::noise_key`].
    noise_key: connection::NoiseKey,

    /// Generator for randomness seeds given to the established connections.
    // TODO: what if children use ChaCha20 as well? is that safe?
    randomness_seeds: Mutex<ChaCha20Core>,

    /// Receiver connected to [`Guarded::events_tx`].
    events_rx: Mutex<mpsc::Receiver<Event>>,
}

/// Fields of [`Network`] behind a mutex.
struct Guarded<TNow, TPeer, TConn> {
    /// Sender connected to [`Network::events_rx`].
    events_tx: mpsc::Sender<Event>,

    /// Holds the state of all the known nodes of the network, and of all the connections (pending
    /// or not).
    peerset: peerset::Peerset<
        TPeer,
        Arc<
            Mutex<(
                connection::established::Established<
                    TNow,
                    oneshot::Sender<Result<Vec<u8>, ()>>,
                    (),
                >,
                TConn,
            )>,
        >,
        Arc<Mutex<Option<(connection::handshake::HealthyHandshake, TNow, TConn)>>>,
        (),
        (),
    >,
}

impl<TNow, TPeer, TConn> Network<TNow, TPeer, TConn> {
    /// Initializes a new network data structure.
    pub fn new(config: Config<TPeer>) -> Self {
        let (events_tx, events_rx) = mpsc::channel(config.pending_api_events_buffer_size.get() - 1);

        let peerset = peerset::Peerset::new(peerset::Config {
            randomness_seed: config.randomness_seed,
            peers_capacity: 50, // TODO: ?
            num_overlay_networks: config.overlay_networks.len(),
        });

        // Add to overlay #0 the nodes known to belong to the network.
        // TODO: update code
        for (user_data, peer_id, address) in config.bootstrap_nodes {
            let mut node = peerset.node_mut(peer_id).or_insert_with(move || user_data);
            node.add_known_address(address);
            node.add_to_overlay(0);
        }

        Network {
            noise_key: config.noise_key,
            events_rx: Mutex::new(events_rx),
            guarded: Mutex::new(Guarded { peerset, events_tx }),
            randomness_seeds: Mutex::new(ChaCha20Core::from_seed(config.randomness_seed)),
        }
    }

    /// Returns the number of established TCP connections, both incoming and outgoing.
    pub async fn num_established_connections(&self) -> usize {
        self.guarded
            .lock()
            .await
            .peerset
            .num_established_connections()
    }

    pub fn add_incoming_connection(
        &self,
        local_listen_address: &Multiaddr,
        remote_addr: Multiaddr,
        user_data: TConn,
    ) -> ConnectionId {
        todo!()
    }

    /// Sends a request to the given peer.
    // TODO: more docs
    // TODO: proper error type
    pub async fn request(
        &self,
        target: PeerId,
        protocol: String,
        request_data: Vec<u8>,
    ) -> Result<Vec<u8>, ()> {
        let connection = {
            let guarded = self.guarded.lock().await;

            let connection = match guarded.peerset.node_mut(target) {
                peerset::NodeMut::Known(n) => n.connections().next().ok_or(())?,
                peerset::NodeMut::Unknown(n) => return Err(()),
            };

            // TODO: is awaiting here a good idea? if the background task is stuck, we block the entire `Guarded`
            // It is possible for the channel to be closed, if the background task has ended but the
            // frontend hasn't processed this yet.
            guarded
                .peerset
                .connection_mut(connection)
                .unwrap()
                .into_user_data()
                .clone()
        };

        let connection = connection.lock().await;

        let (send_back, receive_result) = oneshot::channel();

        // TODO:
        // match connection.0 {}
        todo!();

        // Wait for the result of the request. Can take a long time (i.e. several seconds).
        match receive_result.await {
            Ok(r) => r,
            Err(_) => Err(()),
        }
    }

    /// After a [`Event::StartConnect`], notifies the [`Network`] of the success of the dialing
    /// attempt.
    ///
    /// See also [`Network::pending_outcome_err`].
    ///
    /// # Panic
    ///
    /// Panics if the [`PendingId`] is invalid.
    ///
    // TODO: timeout?
    pub async fn pending_outcome_ok(&self, id: PendingId, user_data: TConn) -> ConnectionId {
        // TODO: wrong ; pending in the peerset means "in TCP or during handshake"
        let guarded = self.guarded.lock().await;
        let conn = guarded
            .peerset
            .pending_mut(id)
            .unwrap()
            .into_established(move |_| {
                Arc::new(Mutex::new((
                    connection::handshake::HealthyHandshake::new(true),
                    todo!(), // TODO: must keep same timeout as TCP handshake
                    user_data,
                )))
            });
        ConnectionId(conn.id())
    }

    /// After a [`Event::StartConnect`], notifies the [`Network`] of the failure of the dialing
    /// attempt.
    ///
    /// See also [`Network::pending_outcome_ok`].
    ///
    /// # Panic
    ///
    /// Panics if the [`PendingId`] is invalid.
    ///
    // TODO: timeout?
    pub async fn pending_outcome_err(&self, id: PendingId) {
        let mut guarded = self.guarded.lock().await;
        guarded
            .peerset
            .pending_mut(id)
            .unwrap()
            .remove_and_purge_address();
    }

    /// Returns the next event produced by the service.
    ///
    /// This function should be called at a high enough rate that [`Network::read_write`] can
    /// continue pushing events to the internal buffer of events. Failure to call this function
    /// often enough will lead to connections being back-pressured.
    /// See also [`Config::pending_api_events_buffer_size`].
    ///
    /// It is technically possible to call this function multiple times simultaneously, in which
    /// case the events will be distributed amongst the multiple calls in an unspecified way.
    /// Keep in mind that some [`Event`]s have logic attached to the order in which they are
    /// produced, and calling this function multiple times is therefore discouraged.
    pub async fn next_event(&self) -> Event {
        self.fill_out_slots(&mut self.guarded.lock().await).await;
        let events_rx = self.events_rx.lock().await;
        events_rx.next().await
    }

    ///
    /// # Panic
    ///
    /// Panics if `connection_id` isn't a valid connection.
    ///
    pub async fn read_write<'a>(
        &self,
        connection_id: ConnectionId,
        now: TNow,
        mut incoming_buffer: Option<&[u8]>,
        mut outgoing_buffer: (&'a mut [u8], &'a mut [u8]),
        cx: &mut Context<'_>,
    ) -> ReadWrite<TNow, TPeer, TConn> {
        let mut total_read = 0;
        let mut total_written = 0;

        'outer_loop: loop {
            let mut guarded = self.guarded.lock().await;
            match guarded
                .peerset
                .pending_or_connection_mut(connection_id.0)
                .unwrap()
            {
                peerset::PendingOrConnectionMut::Pending(pending) => {
                    let pending = pending.user_data_mut().clone();
                    drop(guarded);

                    let pending = pending.lock().await;

                    let (mut handshake, timeout, user_data) = pending.take().unwrap();

                    // TODO: check timeout

                    let is_idle = {
                        let (result, num_read, num_written) =
                            match handshake.read_write(incoming_buffer, outgoing_buffer) {
                                Ok(r) => r,
                                Err(_) => todo!(),
                            };
                        total_read += num_read;
                        total_written += num_written;
                        handshake = result;
                        num_read == 0 && num_written == 0
                    };

                    loop {
                        match handshake {
                            connection::handshake::Handshake::Healthy(updated_handshake) => {
                                handshake = updated_handshake;
                                if is_idle {
                                    pending = Some((handshake, timeout, user_data));
                                    break 'outer_loop None;
                                } else {
                                    break;
                                }
                            }
                            connection::handshake::Handshake::Success {
                                remote_peer_id,
                                connection,
                            } => {
                                let randomness_seed = self.randomness_seeds.lock().await.gen();

                                let mut guarded = self.guarded.lock().await;
                                let pending = guarded.peerset.pending_mut(connection_id).unwrap();
                                if pending.peer_id() != remote_peer_id {
                                    pending.remove_and_purge_address();
                                    continue;
                                }

                                pending.into_established(|_| {
                                    Arc::new(Mutex::new(connection.into_connection(
                                        connection::established::Config {
                                            in_notifications_protocols: todo!(),
                                            in_request_protocols: todo!(),
                                            randomness_seed,
                                            ping_protocol: todo!(),
                                        },
                                    )))
                                });

                                // TODO: notify external API
                            }
                            connection::handshake::Handshake::NoiseKeyRequired(key) => {
                                handshake = key.resume(&self.noise_key);
                            }
                        }
                    }
                }
                peerset::PendingOrConnectionMut::Connection(established) => {
                    let established = established.user_data_mut().clone();
                    drop(guarded);

                    let established = established.lock().await;

                    // TODO:
                    todo!()
                }
            }
        }

        ReadWrite {
            read_bytes: total_read,
            written_bytes: total_written,
            wake_up_after: None,
        }
    }

    /// Spawns new outgoing connections in order to fill empty outgoing slots.
    ///
    /// Must be passed as parameter an existing lock to a [`Guarded`].
    async fn fill_out_slots<'a>(
        &self,
        guarded: &mut MutexGuard<'a, Guarded<TNow, TPeer, TConn>>,
    ) -> Option<Event> {
        // Solves borrow checking errors regarding the borrow of multiple different fields at the
        // same time.
        let guarded = &mut **guarded;

        // TODO: limit number of slots

        for overlay_network_index in 0..1 {
            // TODO: num overlay networks ^
            // Grab nodes for which we have an established outgoing connections but haven't yet
            // opened a substream to.
            /*while let Some(node) = guarded
                .peerset
                .random_connected_closed_node(overlay_network_index)
            {
                let connection_id = node.connections().next().unwrap();
                let mut connection = guarded.peerset.connection_mut(connection_id).unwrap();
                // It is possible for the channel to be closed if the task has shut down. This will
                // be processed by `next_event` when detected.
                let _ = connection
                    .user_data_mut()
                    .send(ToConnection::OpenOutNotifications {
                        protocol: format!("/{}/block-announces/1", self.protocol_id),
                        handshake: protocol::encode_block_announces_handshake(
                            protocol::BlockAnnouncesHandshakeRef {
                                best_hash: &self.best_block.1,
                                best_number: self.best_block.0,
                                genesis_hash: &self.genesis_block_hash,
                                role: protocol::Role::Full, // TODO:
                            },
                        )
                        .fold(Vec::new(), |mut a, b| {
                            a.extend_from_slice(b.as_ref());
                            a
                        }),
                    })
                    .await;
                connection.add_pending_substream(0, ());
            }*/

            // TODO: very wip
            while let Some(mut node) = guarded.peerset.random_not_connected(overlay_network_index) {
                if let Some(multiaddr) = node.known_addresses().next() {
                    let multiaddr = multiaddr.clone();
                    let id = node.add_outbound_attempt(multiaddr.clone(), ());
                    return Some(Event::StartConnect { id, multiaddr });
                }
            }
        }

        None
    }
}

/// Event generated by [`Network::next_event`].
#[derive(Debug)]
pub enum Event {
    Connected(PeerId),
    Disconnected(PeerId),

    /// User must start connecting to the given multiaddress.
    ///
    /// Either [`Network::pending_outcome_ok`] or [`Network::pending_outcome_err`] must later be
    /// called in order to inform of the outcome of the connection.
    StartConnect {
        id: PendingId,
        multiaddr: Multiaddr,
    },
}

/// Outcome of calling [`Connection::read_write`].
pub struct ReadWrite<TNow, TPeer, TConn> {
    /// Number of bytes at the start of the incoming buffer that have been processed. These bytes
    /// should no longer be present the next time [`Connection::read_write`] is called.
    pub read_bytes: usize,

    /// Number of bytes written to the outgoing buffer. These bytes should be sent out to the
    /// remote. The rest of the outgoing buffer is left untouched.
    pub written_bytes: usize,

    /// If `Some`, [`Connection::read_write`] should be called again when the point in time
    /// reaches the value in the `Option`.
    pub wake_up_after: Option<TNow>,
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
