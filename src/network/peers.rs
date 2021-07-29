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

//! Network of peers.
//!
//! The [`Peers`] state machine builds on top of the [`libp2p`] module and provides an
//! abstraction over the network based on network identities (i.e. [`PeerId`]s). In other words,
//! one can use the [`Peers`] struct to determine who to be connected to and through which
//! notification protocols, and the state machine will try to open or re-open connections with
//! these peers.

use crate::libp2p::{self, Multiaddr, PeerId};

use alloc::{collections::BTreeSet, string::String, sync::Arc, vec::Vec};
use core::{
    cmp, iter, mem,
    num::NonZeroU32,
    ops::{Add, Sub},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use futures::{
    channel::{mpsc, oneshot},
    lock::{Mutex, MutexGuard},
    prelude::*,
}; // TODO: no_std-ize
use rand::Rng as _;
use rand_chacha::{rand_core::SeedableRng as _, ChaCha20Rng};

pub use libp2p::ConnectionId;

pub struct Peers<TNow> {
    inner: libp2p::Network<usize, TNow>,

    guarded: Mutex<Guarded>,
}

impl<TNow> Peers<TNow>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
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
        loop {
            // The objective of the block of code below is to retrieve the next event that
            // happened on the underlying libp2p state machine by calling
            // `self.inner.next_event()`.
            //
            // After an event has been grabbed from `self.inner`, some modifications will need to
            // be performed in `self.guarded`. Since it can take a lot of time to retrieve an
            // event, and since other methods of `ChainNetwork` need to lock `self.guarded`, it
            // is undesirable to keep `self.guarded` locked while waiting for the
            // `self.inner.next_event()` future to finish.
            //
            // A naive solution would be to grab an event from `self.inner` then lock
            // `self.guarded` immediately after. Unfortunately, the user can technically call
            // `next_event` multiple times simultaneously. If that is done, we want to avoid a
            // situation where task A retrieves an event, then task B retrieves an event, then
            // task B locks `self.guarded` before task A could. Some kind of locking must be
            // performed to prevent this.
            //
            // Additionally, `guarded` contains some fields, such as `to_process_pre_event`, that
            // need to be processed ahead of events. Because processing these fields requires
            // using `await`, this processing can be interrupted by the user, and as such no event
            // should be grabbed in that situation.
            //
            // For all these reasons, the logic of the code below is as follows:
            //
            // - First, asynchronously lock `self.guarded`.
            // - After `self.guarded` is locked, if some of its fields require ahead-of-events
            // processing, continue with `maybe_inner_event` equal to `None`.
            // - Otherwise, and while `self.guarded` is still locked, try to immediately grab an
            // event with `self.inner.next_event()`.
            // - If no such event is immediately available, register the task waker and release
            // the lock. Once the waker is invoked (meaning that an event should be available),
            // go back to step 1 (locking `self.guarded`).
            // - If an event is available, continue with `maybe_inner_event` equal to `Some`.
            //
            let (mut guarded, maybe_inner_event) = {
                let next_event_future = self.inner.next_event();
                futures::pin_mut!(next_event_future);

                let mut lock_acq_future = self.guarded.lock();
                future::poll_fn(move |cx| {
                    let lock = match lock_acq_future.poll_unpin(cx) {
                        Poll::Ready(l) => l,
                        Poll::Pending => return Poll::Pending,
                    };

                    if lock.to_process_pre_event.is_some() {
                        return Poll::Ready((lock, None));
                    }

                    match next_event_future.poll_unpin(cx) {
                        Poll::Ready(event) => Poll::Ready((lock, Some(event))),
                        Poll::Pending => {
                            lock_acq_future = self.guarded.lock();
                            Poll::Pending
                        }
                    }
                })
                .await
            };
            let mut guarded = &mut *guarded; // Avoid borrow checker issues.

            // If `maybe_inner_event` is `None`, that means some ahead-of-events processing needs
            // to be performed. No event has been grabbed from `self.inner`.
            let inner_event: libp2p::Event<_> = match maybe_inner_event {
                Some(ev) => ev,
                None => {
                    // We can't use `take()` because the call to `accept_notifications_in` might
                    // be interrupted by the user. The field is set to `None` only after the call
                    // has succeeded.
                    match guarded.to_process_pre_event.as_ref().unwrap() {
                        ToProcessPreEvent::AcceptNotificationsIn {
                            connection_id,
                            overlay_network_index,
                            handshake,
                        } => {
                            self.inner
                                .accept_notifications_in(
                                    *connection_id,
                                    *overlay_network_index,
                                    handshake.clone(), // TODO: clone? :-/
                                )
                                .await;
                        }
                        ToProcessPreEvent::QueueNotification {
                            connection_id,
                            overlay_network_index,
                            packet,
                        } => {
                            let _ = self
                                .inner
                                .queue_notification(
                                    *connection_id,
                                    *overlay_network_index,
                                    packet.clone(),
                                ) // TODO: clone? :-/
                                .await;
                        }
                    }

                    guarded.to_process_pre_event = None;
                    continue;
                }
            };

            // An event has been grabbed and is ready to be processed. `self.guarded` is still
            // locked from before the event has been grabbed.
            // In order to avoid futures cancellation issues, no `await` should be used below. If
            // something requires asynchronous processing, it should instead be written to
            // `self.to_process_pre_event`.
            debug_assert!(guarded.to_process_pre_event.is_none());

            match inner_event {
                libp2p::Event::HandshakeFinished {
                    id,
                    peer_id,
                    user_data,
                } => {
                    guarded.connections_peer_index[user_data];
                }
                libp2p::Event::Shutdown {
                    id,
                    out_overlay_network_indices,
                    in_overlay_network_indices,
                    user_data,
                } => {
                    todo!()
                }

                libp2p::Event::RequestIn {
                    id,
                    substream_id,
                    protocol_index,
                    request_payload,
                    user_data,
                } => {}

                libp2p::Event::NotificationsOutAccept {
                    id,
                    overlay_network_index,
                    remote_handshake,
                    user_data,
                } => {
                    let peer_index = guarded.connections_peer_index[user_data].unwrap();
                    let _inserted = guarded
                        .peers_notifications_out
                        .insert((peer_index, overlay_network_index));
                    debug_assert!(_inserted);
                }

                libp2p::Event::NotificationsOutClose {
                    id,
                    overlay_network_index,
                    user_data,
                } => {
                    let peer_index = guarded.connections_peer_index[user_data].unwrap();
                    let _was_in = guarded
                        .peers_notifications_out
                        .remove(&(peer_index, overlay_network_index));
                    debug_assert!(_was_in);
                }

                libp2p::Event::NotificationsInOpen {
                    id,
                    overlay_network_index,
                    remote_handshake,
                    user_data,
                } => {}

                libp2p::Event::NotificationsIn {
                    id,
                    overlay_network_index,
                    notification,
                    user_data,
                } => {}

                libp2p::Event::NotificationsInClose {
                    id,
                    overlay_network_index,
                    user_data,
                } => {}
            }
        }
    }

    /// Adds an incoming connection to the state machine.
    ///
    /// This connection hasn't finished handshaking and the [`PeerId`] of the remote isn't known
    /// yet.
    ///
    /// After this function has returned, you must process the connection with
    /// [`Peers::read_write`].
    #[must_use]
    pub async fn add_incoming_connection(
        &self,
        local_listen_address: &Multiaddr,
        remote_addr: Multiaddr,
    ) -> ConnectionId {
        self.inner.insert(false, ()).await
    }

    /// Pops a request for a new connection made by the [`Peers`].
    ///
    /// After this method has returned, the [`Peers`] state machine will assume that the user is
    /// trying to establish the connection that was returned. It is possible to "refuse" a certain
    /// connection request by calling [`Peers::pending_outcome_err`] immediately after.
    ///
    /// If no request is available, waits until there is one.
    // TODO: well, complicated, because we would like the outside to handle known multiaddresses
    #[must_use]
    pub async fn next_connection_open(&self) {
        todo!()
    }

    /// After calling [`ChainNetwork::fill_out_slots`], notifies the [`ChainNetwork`] of the
    /// success of the dialing attempt.
    ///
    /// See also [`ChainNetwork::pending_outcome_err`].
    ///
    /// After this function has returned, you must process the connection with
    /// [`ChainNetwork::read_write`].
    ///
    /// # Panic
    ///
    /// Panics if the [`PendingId`] is invalid.
    ///
    #[must_use]
    pub async fn pending_outcome_ok(&self, id: PendingId) -> ConnectionId {
        todo!()
    }

    /// After calling [`ChainNetwork::fill_out_slots`], notifies the [`ChainNetwork`] of the
    /// failure of the dialing attempt.
    ///
    /// See also [`ChainNetwork::pending_outcome_ok`].
    ///
    /// # Panic
    ///
    /// Panics if the [`PendingId`] is invalid.
    ///
    pub async fn pending_outcome_err(&self, id: PendingId) {
        todo!()
    }

    pub async fn set_peer_desired(&self, peer_id: &PeerId, desired: bool) {
        let mut guarded = self.guarded.lock().await;
        let peer_index = guarded.peer_index_or_insert(peer_id);
        guarded.peers[peer_index].desired = desired;
    }

    pub async fn set_peer_notifications_out_desired(
        &self,
        peer_id: &PeerId,
        notification_protocols: impl Iterator<Item = usize>,
        new_desired_state: OutNotificationsState,
    ) {
        todo!()
    }

    /// Returns the list of peers whose desired status is TODO: but which couldn't be reached.
    pub async fn unreachable_peers(&'_ self) -> impl Iterator<Item = PeerId> {}

    pub async fn in_notification_accept(
        &self,
        id: DesiredInNotificationId,
        handshake_back: Vec<u8>,
    ) {
        todo!()
    }

    pub async fn in_notification_refuse(&self, id: DesiredInNotificationId) {
        todo!()
    }

    pub async fn queue_notification(
        &self,
        peer: &PeerId,
        overlay_network_index: usize,
        notification: impl Into<Vec<u8>>,
    ) -> Result<(), QueueNotificationError> {
        todo!()
    }

    ///
    /// # Panic
    ///
    /// Panics if `connection_id` isn't a valid connection.
    ///
    // TODO: document the `write_close` thing
    pub async fn read_write<'a>(
        &self,
        connection_id: ConnectionId,
        now: TNow,
        incoming_buffer: Option<&[u8]>,
        outgoing_buffer: (&'a mut [u8], &'a mut [u8]),
    ) -> Result<ReadWrite<TNow>, ConnectionError> {
        self.inner
            .read_write(connection_id, now, incoming_buffer, outgoing_buffer)
            .await
    }
}

pub enum OutNotificationsState {
    Closed,
    Open,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DesiredInNotificationId;

pub enum Event {
    /// Established a new connection to the given peer.
    Connected {
        /// Identity of the peer on the other side of the connection.
        peer_id: PeerId,

        /// Address of the connection.
        address: Multiaddr, // TODO: Endpoint or something instead

        /// Number of other established connections with the same peer, including the one that
        /// has just been established.
        num_peer_connections: NonZeroU32,
    },

    /// Handshake of the given connection has completed.
    ///
    /// This event can only happen once per connection.
    Disconnected {
        /// Identity of the peer on the other side of the connection.
        peer_id: PeerId,

        /// Number of other established connections with the same peer remaining after the
        /// disconnection.
        num_peer_connections: u32,
    },

    /// Received a request from a request-response protocol.
    RequestIn {
        peer_id: PeerId,
        /// Substream on which the request has been received. Must be passed back when providing
        /// the response.
        substream_id: established::SubstreamId,
        protocol_index: usize,
        request_payload: Vec<u8>,
    },

    DesiredInNotification {
        id: DesiredInNotificationId,
        peer_id: PeerId,
        handshake: Vec<u8>,
    },

    /// A handshaking outbound substream has been accepted by the remote.
    NotificationsOutAccept {
        peer_id: PeerId,
        // TODO: what if fallback?
        overlay_network_index: usize,
        /// Handshake sent in return by the remote.
        remote_handshake: Vec<u8>,
    },

    /// A previously open outbound substream has been closed by the remote, or a handshaking
    /// outbound substream has been denied by the remote.
    NotificationsOutClose {
        peer_id: PeerId,
        overlay_network_index: usize,
    },

    // TODO: needs a notifications in cancel event? tricky
    /// Received a notification on a notifications substream of a connection.
    NotificationsIn {
        peer_id: PeerId,
        overlay_network_index: usize,
        notification: Vec<u8>,
    },

    NotificationsInClose {
        peer_id: PeerId,
        overlay_network_index: usize,
    },
}

/// Error potentially returned by [`Peers::queue_notification`].
#[derive(Debug, derive_more::Display)]
pub enum QueueNotificationError {
    /// Not connected to target.
    NotConnected,
    /// No substream with the given target of the given protocol.
    NoSubstream,
    /// Queue of notifications with that peer is full.
    QueueFull,
}

struct Guarded {
    /// In the [`Peers::next_event`] function, an event is grabbed from the underlying
    /// [`Peers::inner`]. This event might lead to some asynchronous post-processing being needed.
    /// Because the user can interrupt the future returned by [`Peers::next_event`] at any point
    /// in time, this post-processing cannot be immediately performed, as the user could could
    /// interrupt the future and lose the event. Instead, the necessary post-processing is stored
    /// in this field. This field is then processed before the next event is pulled.
    to_process_pre_event: Option<ToProcessPreEvent>,

    connections_peer_index: slab::Slab<Option<usize>>,

    peer_indices: hashbrown::HashMap<PeerId, usize, ahash::RandomState>,

    peers: slab::Slab<Peer>,

    peers_desired: BTreeSet<(usize, usize)>,

    peers_notifications_out: BTreeSet<(usize, usize)>,
}

impl Guarded {
    fn peer_index_or_insert(&mut self, peer_id: &PeerId) -> usize {
        if let Some(idx) = self.peer_indices.get(peer_id) {
            return *idx;
        }

        todo!()
    }
}

/// See [`Guarded::to_process_pre_event`]
enum ToProcessPreEvent {
    AcceptNotificationsIn {
        connection_id: libp2p::ConnectionId,
        overlay_network_index: usize,
        handshake: Vec<u8>,
    },
    QueueNotification {
        connection_id: libp2p::ConnectionId,
        overlay_network_index: usize,
        packet: Vec<u8>,
    },
}

struct Peer {
    desired: bool,
}
