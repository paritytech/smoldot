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

use crate::network::{connection, libp2p, protocol, Multiaddr, PeerId};

use alloc::sync::Arc;
use core::{num::NonZeroUsize, task::Context};
use futures::{
    lock::{Mutex, MutexGuard},
}; // TODO: no_std-ize

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

    /// List of blockchain peer-to-peer networks to be connected to.
    ///
    /// > **Note**: As documented in [the module-level documentation](..), the [`ChainNetwork`]
    /// >           can connect to multiple blockchain networks at the same time.
    ///
    /// The order in which the chains are list is important. The index of each entry needs to be
    /// used later in order to refer to a specific chain.
    pub chains: Vec<ChainConfig<TPeer>>,

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
pub struct ChainConfig<TPeer> {
    /// Identifier of the protocol, used on the wire to determine which chain messages refer to.
    ///
    /// > **Note**: This value is typically found in the specifications of the chain (the
    /// >           "chain specs").
    pub protocol_id: String,

    /// List of node identities that are known to belong to this overlay network.
    pub bootstrap_nodes: Vec<PeerId>,

    pub in_slots: u32,

    pub out_slots: u32,
}

/// Identifier of a pending connection requested by the network through a [`Event::StartConnect`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingId(libp2p::ConnectionId);

/// Identifier of a [`Connection`] spawned by the [`Network`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(libp2p::ConnectionId);

/// Data structure containing the list of all connections, pending or not, and their latest known
/// state. See also [the module-level documentation](..).
pub struct ChainNetwork<TNow, TPeer, TConn> {
    /// Underlying data structure that manages the state of the connections and substreams.
    libp2p: libp2p::Network<TNow, TPeer, TConn>,

    /// For each chain passed in [`Config::chains`], contains the [`ChainConfig::protocol_id`].
    /// Never modified.
    protocol_ids: Vec<String>,
}

impl<TNow, TPeer, TConn> ChainNetwork<TNow, TPeer, TConn> {
    /// Initializes a new [`ChainNetwork`].
    pub fn new(config: Config<TPeer>) -> Self {
        ChainNetwork {
            libp2p: todo!(),
            protocol_ids: config.chains.into_iter().map(|c| c.protocol_id).collect(),
        }
    }

    /// Returns the number of established TCP connections, both incoming and outgoing.
    pub async fn num_established_connections(&self) -> usize {
        self.libp2p.num_established_connections()
    }

    pub fn add_incoming_connection(
        &self,
        local_listen_address: &Multiaddr,
        remote_addr: Multiaddr,
        user_data: TConn,
    ) -> ConnectionId {
        todo!()
    }

    /// Sends a blocks request to the given peer.
    // TODO: more docs
    // TODO: proper error type
    pub async fn blocks_request(
        &self,
        target: PeerId,
        chain_index: usize,
        config: protocol::BlocksRequestConfig,
    ) -> Result<Vec<protocol::BlockData>, ()> {
        let request_data = protocol::build_block_request(config).fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });
        let protocol = format!("/{}/sync/2", &self.protocol_ids[chain_index]);
        let response = self.libp2p.request(target, protocol, request_data).await?; // TODO: correct protocol
        protocol::decode_block_response(&response).map_err(|_| ())
    }

    pub async fn announce_transaction(&self, transaction: Vec<u8>) {

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
        self.libp2p
            .read_write(connection_id.0, incoming_buffer, outgoing_buffer, cx)
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
