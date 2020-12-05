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
use core::{
    iter,
    num::NonZeroUsize,
    ops::{Add, Sub},
    task::{Context, Waker},
    time::Duration,
};
use futures::{
    channel::{mpsc, oneshot},
    lock::{Mutex, MutexGuard},
    prelude::*,
}; // TODO: no_std-ize
use rand::Rng as _;
use rand_chacha::{rand_core::SeedableRng as _, ChaCha20Rng};

pub use connection::established::ConfigRequestResponse;

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

    pub overlay_networks: Vec<OverlayNetwork>,

    pub request_response_protocols: Vec<ConfigRequestResponse>,

    /// Name of the ping protocol on the network.
    pub ping_protocol: String,

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
pub struct OverlayNetwork {
    /// Name of the protocol negotiated on the wire.
    pub protocol_name: String,

    /// Optional alternative names for this protocol. Can represent different versions.
    ///
    /// Negotiated in order in which they are passed.
    pub fallback_protocol_names: Vec<String>,

    /// Maximum size, in bytes, of the handshake that can be received.
    pub max_handshake_size: usize,

    /// List of node identities that are known to belong to this overlay network. The node
    /// identities are indices in [`Config::known_nodes`].
    pub bootstrap_nodes: Vec<usize>,

    pub in_slots: u32,

    pub out_slots: u32,
}

/// Identifier of a pending connection requested by the network through a [`Event::StartConnect`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingId(peerset::ConnectionId);

/// Identifier of a connection spawned by the [`Network`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(peerset::ConnectionId);

/// Data structure containing the list of all connections, pending or not, and their latest known
/// state. See also [the module-level documentation](..).
pub struct Network<TNow, TPeer, TConn> {
    /// Fields behind a mutex.
    guarded: Mutex<Guarded<TNow, TPeer, TConn>>,

    /// See [`Config::noise_key`].
    noise_key: connection::NoiseKey,

    /// See [`Config::overlay_networks`].
    overlay_networks: Vec<OverlayNetwork>,

    /// See [`Config::request_response_protocols`].
    request_response_protocols: Vec<ConfigRequestResponse>,

    /// See [`Config::ping_protocol`].
    ping_protocol: String,

    /// Generator for randomness seeds given to the established connections.
    // TODO: what if children use ChaCha20 as well? is that safe?
    randomness_seeds: Mutex<ChaCha20Rng>,

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
                Option<
                    connection::established::Established<
                        TNow,
                        oneshot::Sender<Result<Vec<u8>, RequestError>>,
                        usize,
                    >,
                >,
                TConn,
                Option<Waker>,
            )>,
        >,
        Arc<Mutex<Option<(connection::handshake::HealthyHandshake, TConn)>>>,
        connection::established::SubstreamId,
        connection::established::SubstreamId,
    >,
}

impl<TNow, TPeer, TConn> Network<TNow, TPeer, TConn>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Initializes a new network data structure.
    pub fn new(config: Config<TPeer>) -> Self {
        let (events_tx, events_rx) = mpsc::channel(config.pending_api_events_buffer_size.get() - 1);

        let mut peerset = peerset::Peerset::new(peerset::Config {
            randomness_seed: config.randomness_seed,
            peers_capacity: 50, // TODO: ?
            num_overlay_networks: config.overlay_networks.len(),
        });

        let mut ids = Vec::with_capacity(config.known_nodes.len());
        for (user_data, peer_id, multiaddr) in config.known_nodes {
            ids.push(peer_id.clone());
            let mut node = peerset.node_mut(peer_id).or_insert_with(move || user_data);
            node.add_known_address(multiaddr);
        }

        for (overlay_network_index, overlay_network) in config.overlay_networks.iter().enumerate() {
            for bootstrap_node in &overlay_network.bootstrap_nodes {
                // TODO: cloning :(
                peerset
                    .node_mut(ids[*bootstrap_node].clone())
                    .into_known()
                    .unwrap()
                    .add_to_overlay(overlay_network_index);
            }
        }

        Network {
            noise_key: config.noise_key,
            overlay_networks: config.overlay_networks,
            request_response_protocols: config.request_response_protocols,
            ping_protocol: config.ping_protocol,
            events_rx: Mutex::new(events_rx),
            guarded: Mutex::new(Guarded { peerset, events_tx }),
            randomness_seeds: Mutex::new(ChaCha20Rng::from_seed(config.randomness_seed)),
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

    /// Returns an iterator to the list of [`PeerId`]s that we have an established connection
    /// with.
    pub async fn peers_list_lock(&self) -> impl Iterator<Item = PeerId> {
        // TODO: actually hold the lock so that we don't allocate a Vec
        let lock = self.guarded.lock().await;
        // TODO: what about duplicate PeerIds? should they be automatically deduplicated like here? decide and document
        // TODO: wrong hashing algorithm
        lock.peerset
            .connections_peer_ids()
            .map(|(_, peer_id)| peer_id.clone())
            .collect::<hashbrown::HashSet<_, fnv::FnvBuildHasher>>()
            .into_iter()
    }

    // TODO: document and improve API
    pub async fn add_addresses(
        &self,
        or_insert: impl FnOnce() -> TPeer,
        overlay_network_index: usize,
        peer_id: PeerId,
        addrs: impl IntoIterator<Item = Multiaddr>,
    ) {
        let mut lock = self.guarded.lock().await;
        let mut node = lock.peerset.node_mut(peer_id).or_insert_with(or_insert);
        for addr in addrs {
            node.add_known_address(addr);
        }
        node.add_to_overlay(overlay_network_index);
    }

    pub fn add_incoming_connection(
        &self,
        local_listen_address: &Multiaddr,
        remote_addr: Multiaddr,
        user_data: TConn,
    ) -> ConnectionId {
        todo!()
    }

    pub async fn connection_peer_id(&self, id: ConnectionId) -> PeerId {
        // TODO: cloning :-/
        self.guarded.lock().await.peerset.connection_mut(id.0).unwrap().peer_id().clone()
    }

    /// Sends a request to the given peer.
    // TODO: more docs
    pub async fn request(
        &self,
        now: TNow,
        target: PeerId,
        protocol_index: usize,
        request_data: Vec<u8>,
    ) -> Result<Vec<u8>, RequestError> {
        let connection = {
            let mut guarded = self.guarded.lock().await;

            let connection = match guarded.peerset.node_mut(target) {
                peerset::NodeMut::Known(n) => {
                    n.connections().next().ok_or(RequestError::NotConnected)?
                }
                peerset::NodeMut::Unknown(_) => return Err(RequestError::NotConnected),
            };

            guarded
                .peerset
                .connection_mut(connection)
                .unwrap()
                .into_user_data()
                .clone()
        };

        let mut connection_lock = connection.lock().await;

        let (send_back, receive_result) = oneshot::channel();
        connection_lock
            .0
            .as_mut()
            .ok_or(RequestError::ConnectionClosed)?
            .add_request(now, protocol_index, request_data, send_back);
        if let Some(waker) = connection_lock.2.take() {
            waker.wake();
        }

        // Make sure to unlock the connection before waiting for the result.
        drop(connection_lock);
        // The `Arc` to the connection should also be dropped, so that the channel gets dropped
        // if the connection is removed from the peerset.
        drop(connection);

        // Wait for the result of the request. Can take a long time (i.e. several seconds).
        match receive_result.await {
            Ok(r) => r,
            Err(_) => Err(RequestError::ConnectionClosed),
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
        let conn = self
            .guarded
            .lock()
            .await
            .peerset
            .pending_mut(id.0)
            .unwrap()
            .user_data_mut()
            .clone();

        let mut conn = conn.try_lock().unwrap();
        assert!(conn.is_none());
        *conn = Some((
            connection::handshake::HealthyHandshake::new(true),
            user_data,
        ));
        ConnectionId(id.0)
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
            .pending_mut(id.0)
            .unwrap()
            .remove_and_purge_address();
    }

    // TODO: futures cancellation concerns T_T
    pub async fn accept_notifications_in(
        &self,
        id: ConnectionId,
        overlay_network_index: usize,
        handshake: Vec<u8>,
    ) {
        let mut guarded = self.guarded.lock().await;

        let mut substream_id = None;

        let mut connection = guarded.peerset.connection_mut(id.0).unwrap();

        connection.confirm_substream(
            overlay_network_index,
            peerset::SubstreamDirection::In,
            |id| {
                substream_id = Some(id);
                id
            },
        );

        let connection_arc = connection.user_data_mut().clone();
        drop(connection);
        drop(guarded);

        let mut connection = connection_arc.lock().await;

        if let Some(waker) = connection.2.take() {
            waker.wake();
        }

        connection
            .0
            .as_mut()
            .unwrap()
            .accept_in_notifications_substream(
                substream_id.unwrap(),
                handshake,
                overlay_network_index,
            );
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
        if let Some(event) = self.fill_out_slots(&mut self.guarded.lock().await).await {
            return event;
        }

        let mut events_rx = self.events_rx.lock().await;
        events_rx.select_next_some().await
    }

    ///
    /// # Panic
    ///
    /// Panics if `connection_id` isn't a valid connection.
    ///
    // TODO: document the `write_close` thing
    // TODO: futures cancellation concerns T_T
    pub async fn read_write<'a>(
        &self,
        connection_id: ConnectionId,
        now: TNow,
        incoming_buffer: Option<&[u8]>,
        outgoing_buffer: (&'a mut [u8], &'a mut [u8]),
        cx: &mut Context<'_>,
    ) -> Result<ReadWrite<TNow>, ConnectionError> {
        let mut total_read = 0;
        let mut total_written = 0;
        let mut wake_up_after = None;

        let mut guarded = self.guarded.lock().await;
        match guarded
            .peerset
            .pending_or_connection_mut(connection_id.0)
            .unwrap()
        {
            peerset::PendingOrConnectionMut::Pending(mut pending) => {
                let pending = pending.user_data_mut().clone();
                drop(guarded);

                let mut pending = pending.lock().await;

                let incoming_buffer = match incoming_buffer {
                    Some(b) => b,
                    None => {
                        let mut guarded = self.guarded.lock().await;
                        guarded
                            .peerset
                            .pending_mut(connection_id.0)
                            .unwrap()
                            .remove_and_purge_address();

                        debug_assert_eq!(total_read, 0);
                        return Ok(ReadWrite {
                            read_bytes: total_read,
                            written_bytes: total_written,
                            wake_up_after: None,
                            write_close: true,
                        });
                    }
                };

                let (handshake, user_data) = pending.take().unwrap();

                // TODO: check timeout

                let (mut result, is_idle) = {
                    let (result, num_read, num_written) =
                        match handshake.read_write(incoming_buffer, outgoing_buffer) {
                            Ok(rw) => rw,
                            Err(err) => {
                                let mut guarded = self.guarded.lock().await;
                                let pending = guarded.peerset.pending_mut(connection_id.0).unwrap();
                                pending.remove_and_purge_address();
                                return Err(ConnectionError::Handshake(err));
                            }
                        };
                    total_read += num_read;
                    total_written += num_written;
                    (result, num_read == 0 && num_written == 0)
                };

                loop {
                    match result {
                        connection::handshake::Handshake::Healthy(updated_handshake) => {
                            *pending = Some((updated_handshake, user_data));
                            break;
                        }
                        connection::handshake::Handshake::Success {
                            remote_peer_id,
                            connection,
                        } => {
                            let mut guarded = self.guarded.lock().await;
                            let pending = guarded.peerset.pending_mut(connection_id.0).unwrap();
                            if *pending.peer_id() != remote_peer_id {
                                pending.remove_and_purge_address();
                                return Err(ConnectionError::PeerIdMismatch);
                            }

                            pending.into_established({
                                let config = self.build_connection_config().await;
                                let waker = cx.waker().clone();
                                move |_| {
                                    let established = connection.into_connection(config);
                                    Arc::new(Mutex::new((
                                        Some(established),
                                        user_data,
                                        Some(waker),
                                    )))
                                }
                            });

                            guarded
                                .events_tx
                                .send(Event::Connected(remote_peer_id))
                                .await
                                .unwrap();

                            cx.waker().wake_by_ref();
                            break;
                        }
                        connection::handshake::Handshake::NoiseKeyRequired(key) => {
                            result = key.resume(&self.noise_key).into();
                        }
                    }
                }
            }
            peerset::PendingOrConnectionMut::Connection(mut established) => {
                let established = established.user_data_mut().clone();
                drop(guarded);

                let mut established = established.lock().await;
                let established = &mut *established;

                // Update the `core::task::Waker` if necessary.
                match established.2 {
                    Some(ref w) if w.will_wake(cx.waker()) => {}
                    _ => established.2 = Some(cx.waker().clone()),
                }

                let read_write_result =
                    established
                        .0
                        .take()
                        .unwrap()
                        .read_write(now, incoming_buffer, outgoing_buffer);

                let read_write = match read_write_result {
                    Ok(rw) => rw,
                    Err(err) => {
                        let mut guarded = self.guarded.lock().await;
                        let peer_id = {
                            let c = guarded.peerset.connection_mut(connection_id.0).unwrap();
                            let peer_id = c.peer_id().clone();
                            c.remove();
                            peer_id
                        };

                        // TODO: only send if last connection
                        guarded
                            .events_tx
                            .send(Event::Disconnected(peer_id))
                            .await
                            .unwrap();

                        return Err(ConnectionError::Established(err));
                    }
                };

                total_read += read_write.read_bytes;
                total_written += read_write.written_bytes;
                debug_assert!(wake_up_after.is_none());
                wake_up_after = read_write.wake_up_after;
                established.0 = Some(read_write.connection);

                // TODO: finish here

                match read_write.event {
                    None => {}
                    Some(connection::established::Event::RequestIn {
                        id,
                        protocol_index,
                        request,
                    }) => todo!(),
                    Some(connection::established::Event::Response {
                        response,
                        user_data: send_back,
                        ..
                    }) => {
                        let _ = send_back.send(response.map_err(RequestError::Connection));
                    }
                    Some(connection::established::Event::NotificationsInOpen {
                        id,
                        protocol_index: overlay_network_index,
                        handshake,
                    }) => {
                        let mut guarded = self.guarded.lock().await;

                        guarded
                            .peerset
                            .connection_mut(connection_id.0)
                            .unwrap()
                            .add_pending_substream(
                                overlay_network_index,
                                peerset::SubstreamDirection::In,
                                id,
                            );

                        guarded
                            .events_tx
                            .send(Event::NotificationsInOpen {
                                id: connection_id,
                                overlay_network_index,
                                remote_handshake: handshake,
                            })
                            .await
                            .unwrap();
                    }
                    Some(connection::established::Event::NotificationIn { id, notification }) => {
                        let overlay_network_index = *established
                            .0
                            .as_mut()
                            .unwrap()
                            .notifications_substream_user_data_mut(id)
                            .unwrap();

                        let mut guarded = self.guarded.lock().await;
                        guarded
                            .events_tx
                            .send(Event::NotificationsIn {
                                id: connection_id,
                                overlay_network_index,
                                notification,
                            })
                            .await
                            .unwrap();
                    }
                    Some(connection::established::Event::NotificationsOutAccept {
                        id,
                        remote_handshake,
                    }) => {
                        let overlay_network_index = *established
                            .0
                            .as_mut()
                            .unwrap()
                            .notifications_substream_user_data_mut(id)
                            .unwrap();

                        let mut guarded = self.guarded.lock().await;

                        guarded
                            .peerset
                            .connection_mut(connection_id.0)
                            .unwrap()
                            .confirm_substream(
                                overlay_network_index,
                                peerset::SubstreamDirection::Out,
                                |id| id,
                            );

                        guarded
                            .events_tx
                            .send(Event::NotificationsOutAccept {
                                id: connection_id,
                                overlay_network_index,
                                remote_handshake,
                            })
                            .await
                            .unwrap();
                    }
                    Some(connection::established::Event::NotificationsOutReject {
                        id,
                        user_data: overlay_network_index,
                    }) => {
                        let mut guarded = self.guarded.lock().await;

                        let expected_id = guarded
                            .peerset
                            .connection_mut(connection_id.0)
                            .unwrap()
                            .remove_pending_substream(
                                overlay_network_index,
                                peerset::SubstreamDirection::Out,
                            );
                        debug_assert_eq!(id, expected_id);

                        guarded
                            .events_tx
                            .send(Event::NotificationsOutReject {
                                id: connection_id,
                                overlay_network_index,
                            })
                            .await
                            .unwrap();
                    }
                    Some(connection::established::Event::NotificationsOutCloseDemanded { id }) => {
                        todo!()
                    }
                }
            }
        }

        Ok(ReadWrite {
            read_bytes: total_read,
            written_bytes: total_written,
            wake_up_after,
            write_close: false, // TODO:
        })
    }

    async fn build_connection_config(&self) -> connection::established::Config {
        let randomness_seed = self.randomness_seeds.lock().await.gen();
        connection::established::Config {
            notifications_protocols: self
                .overlay_networks
                .iter()
                .flat_map(|net| {
                    let max_handshake_size = net.max_handshake_size;
                    iter::once(&net.protocol_name)
                        .chain(net.fallback_protocol_names.iter())
                        .map(move |name| {
                            connection::established::ConfigNotifications {
                                name: name.clone(), // TODO: cloning :-/
                                max_handshake_size,
                            }
                        })
                })
                .collect(),
            request_protocols: self.request_response_protocols.clone(),
            randomness_seed,
            ping_protocol: self.ping_protocol.clone(), // TODO: cloning :-/
        }
    }

    pub async fn open_next_substream(&'_ self) -> Option<SubstreamOpen<'_, TNow, TPeer, TConn>> {
        let mut guarded = self.guarded.lock().await;

        for overlay_network_index in 0..guarded.peerset.num_overlay_networks() {
            // Grab node for which we have an established outgoing connections but haven't yet
            // opened a substream to.
            if let Some(node) = guarded
                .peerset
                .random_connected_closed_node(overlay_network_index)
            {
                let connection_id = node.connections().next().unwrap();
                let mut peerset_entry = guarded.peerset.connection_mut(connection_id).unwrap();
                return Some(SubstreamOpen {
                    network: self,
                    connection: peerset_entry.user_data_mut().clone(),
                    connection_id,
                    overlay_network_index,
                });
            }
        }

        None
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

        for overlay_network_index in 0..guarded.peerset.num_overlay_networks() {
            // TODO: very wip
            while let Some(mut node) = guarded.peerset.random_not_connected(overlay_network_index) {
                let first_addr = node.known_addresses().cloned().next();
                if let Some(multiaddr) = first_addr {
                    let id =
                        node.add_outbound_attempt(multiaddr.clone(), Arc::new(Mutex::new(None)));
                    return Some(Event::StartConnect {
                        id: PendingId(id),
                        multiaddr,
                    });
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

    NotificationsOutAccept {
        id: ConnectionId,
        // TODO: what if fallback?
        overlay_network_index: usize,
        remote_handshake: Vec<u8>,
    },

    NotificationsOutReject {
        id: ConnectionId,
        // TODO: what if fallback?
        overlay_network_index: usize,
    },

    ///
    NotificationsInOpen {
        id: ConnectionId,
        overlay_network_index: usize,
        remote_handshake: Vec<u8>,
    },

    ///
    NotificationsIn {
        id: ConnectionId,
        overlay_network_index: usize,
        notification: Vec<u8>,
    },
}

/// Outcome of calling [`Network::read_write`].
pub struct ReadWrite<TNow> {
    /// Number of bytes at the start of the incoming buffer that have been processed. These bytes
    /// should no longer be present the next time [`Network::read_write`] is called.
    pub read_bytes: usize,

    /// Number of bytes written to the outgoing buffer. These bytes should be sent out to the
    /// remote. The rest of the outgoing buffer is left untouched.
    pub written_bytes: usize,

    /// If `Some`, [`Network::read_write`] should be called again when the point in time
    /// reaches the value in the `Option`.
    pub wake_up_after: Option<TNow>,

    /// If `true`, the writing side the connection must be closed. Will always remain to `true`
    /// after it has been set.
    ///
    /// If, after calling [`Network::read_write`], the returned [`ReadWrite`] contains `true` here,
    /// and the inbound buffer is `None`, then the [`ConnectionId`] is now invalid.
    pub write_close: bool,
}

pub enum ConnectionError {
    Established(connection::established::Error),
    Handshake(connection::handshake::HandshakeError),
    PeerIdMismatch,
}

pub struct SubstreamOpen<'a, TNow, TPeer, TConn> {
    network: &'a Network<TNow, TPeer, TConn>,
    connection_id: peerset::ConnectionId,
    connection: Arc<
        Mutex<(
            Option<
                connection::established::Established<
                    TNow,
                    oneshot::Sender<Result<Vec<u8>, RequestError>>,
                    usize,
                >,
            >,
            TConn,
            Option<Waker>,
        )>,
    >,

    /// Index of the overlay network whose notifications substream to open.
    overlay_network_index: usize,
}

impl<'a, TNow, TPeer, TConn> SubstreamOpen<'a, TNow, TPeer, TConn>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Returns the index of the overlay network whose notifications substream to open.
    pub fn overlay_network_index(&self) -> usize {
        self.overlay_network_index
    }

    // TODO: futures cancellation concerns T_T
    pub async fn open(self, now: TNow, handshake: impl Into<Vec<u8>>) {
        let mut connection = self.connection.lock().await;

        let substream_id = if let Some(established) = connection.0.as_mut() {
            Some(established.open_notifications_substream(
                now,
                self.overlay_network_index,
                handshake.into(),
                self.overlay_network_index,
            ))
        } else {
            None
        };

        if let Some(waker) = connection.2.take() {
            waker.wake();
        }

        drop(connection);

        if let Some(substream_id) = substream_id {
            let mut guarded = self.network.guarded.lock().await;
            let mut peerset_entry = guarded.peerset.connection_mut(self.connection_id).unwrap();
            peerset_entry.add_pending_substream(
                self.overlay_network_index,
                peerset::SubstreamDirection::Out,
                substream_id,
            );
        }
    }
}

#[derive(Debug, derive_more::Display)]
pub enum RequestError {
    /// Not connected to target.
    NotConnected,
    /// Connection has been unexpectedly closed by the remote during the request.
    ConnectionClosed,
    /// Error in the context of the connection.
    Connection(connection::established::RequestError),
}
