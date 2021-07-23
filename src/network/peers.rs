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

use crate::libp2p::{self, Multiaddr, PeerId};

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
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

pub struct Peers<TConn, TNow> {
    inner: libp2p::Network<TConn, TNow>,
}

impl<TConn, TNow> Peers<TConn, TNow>
where
    TConn: Clone,
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
    pub async fn next_event(&self) -> Event<TConn> {
        let mut events_rx = self.events_rx.lock().await;
        events_rx.next().await.unwrap()
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

    pub fn set_peer_desired(
        &self,
        peer_id: &PeerId,
        notification_protocols: impl Iterator<Item = usize>,
        new_desired_state: OutNotificationsState,
    ) {
    }

    pub fn desired_in_notifications(&self) -> impl Iterator<Item = DesiredInNotification> {}

    pub async fn queue_notification(
        &self,
        peer: &PeerId,
        overlay_network_index: usize,
        notification: impl Into<Vec<u8>>,
    ) -> Result<(), QueueNotificationError> {
        todo!()
    }
}

pub enum OutNotificationsState {
    Closed,
    Open,
}

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

    /// A handshaking outbound substream has been accepted by the remote.
    NotificationsOutAccept {
        peer_id: PeerId,
        // TODO: what if fallback?
        overlay_network_index: usize,
        /// Handshake sent in return by the remote.
        remote_handshake: Vec<u8>,
        /// Copy of the user data provided when creating the connection.
        user_data: TConn,
    },

    /// A previously open outbound substream has been closed by the remote, or a handshaking
    /// outbound substream has been denied by the remote.
    NotificationsOutClose {
        peer_id: PeerId,
        overlay_network_index: usize,
        /// Copy of the user data provided when creating the connection.
        user_data: TConn,
    },

    ///
    NotificationsInOpen {
        peer_id: PeerId,
        overlay_network_index: usize,
        remote_handshake: Vec<u8>,
        /// Copy of the user data provided when creating the connection.
        user_data: TConn,
    },

    // TODO: needs a notifications in cancel event? tricky
    /// Received a notification on a notifications substream of a connection.
    NotificationsIn {
        peer_id: PeerId,
        overlay_network_index: usize,
        notification: Vec<u8>,
        /// Copy of the user data provided when creating the connection.
        user_data: TConn,
    },

    NotificationsInClose {
        peer_id: PeerId,
        overlay_network_index: usize,
        /// Copy of the user data provided when creating the connection.
        user_data: TConn,
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
