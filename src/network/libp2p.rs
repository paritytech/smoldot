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

//! Collection of connections and connection attempts.
//!
//! This module provides the [`Network`] data structure that contains a collection of currently
//! open connections, both in handshake mode or not, and pending outgoing connection attempts.
//!
//! This module provides a multithreading-friendly API. All methods accept `&self` rather than
//! `&mut self`, making it possible to use the [`Network`] multiple times from multiple different
//! threads simultaneously.
//!
//! > **Note**: The process power required to encode and decode the encrypted networking
//! >           communications is usually the main CPU consumption reason in a Substrate/Polkadot
//! >           client. In order to avoid running into a bottleneck when the number of peers is
//! >           high, it is recommmended for the user to distribute the various sockets between
//! >           multiple tasks (themselves distributed between multiple CPU cores), and share the
//! >           [`Network`] object between all these tasks.

use alloc::{collections::BTreeSet, sync::Arc};
use connection::NoiseKey;
use core::sync::atomic::{AtomicUsize, Ordering};
use futures::lock::Mutex;
use hashbrown::HashMap;
use multiaddr::Multiaddr;
use peer_id::PeerId;

#[doc(inline)]
pub use parity_multiaddr as multiaddr;

pub mod connection;
pub mod peer_id;

/// Configuration for creating a [`Network`].
pub struct Config {
    /// Key to use during the connection handshakes. Not the same thing as the libp2p key, but
    /// instead contains a signature made using the libp2p private key.
    pub noise_key: NoiseKey,

    /// Capacity to pre-allocate for the containers containing the list of connections. Should
    /// contain an estimate of the total number of connections.
    pub connections_capacity: usize,
}

pub struct Network<TProto, TRqUd, TNow> {
    /// Identifier to allocate for the next connection.
    next_connection_id: atomic::Atomic<u64>,

    /// Identifier to allocate for the next request, either incoming or outgoing.
    next_request_id: atomic::Atomic<u64>,

    /// Number of incoming connections. Used for [`Network::num_incoming_connections`].
    /// Increased/decreased when entries are added to/removed from the list of connections.
    num_incoming_connections: AtomicUsize,

    /// List of connections by peer.
    /// This container is semantically similar to a `HashMap<PeerId, Vec<ConnectionId>>`, except
    /// that the memory fragmentation of having an inner `Vec` is avoided, and that there is no
    /// risk of HashDoS attacks.
    /// Considering that the elements in a `BTreeSet` are ordered, all the [`ConnectionId`]s
    /// belonging to the same [`PeerId`] follow each other in the container.
    peers: Mutex<BTreeSet<(PeerId, u64)>>,

    /// List of connections. Includes active connections, handshaking connections, and pending
    /// connections.
    /// Considering that identifiers are allocated locally, there is no risk of HashDoS attack.
    /// The values are wrapped within an `Arc<Mutex<>>`. In order to avoid locking the `Mutex` on
    /// the `HashMap` for too long, accessing the connections must be done by first cloning the
    /// `Arc`.
    connections: Mutex<HashMap<u64, Arc<Mutex<Connection>>, fnv::FnvBuildHasher>>,

    // TODO: remove
    tmp: core::marker::PhantomData<(TProto, TRqUd, TNow)>,
}

enum Connection {
    Pending {
        target: Multiaddr,
    },
    Handshaking {
        connection: connection::handshake::HealthyHandshake,
    },
    Active {
        // TODO: connection: connection::Connection<>,
    },
}

impl<TProto, TRqUd, TNow> Network<TProto, TRqUd, TNow> {
    /// Initializes a new networking state machine.
    pub fn new(config: Config) -> Self {
        Network {
            next_connection_id: atomic::Atomic::new(0),
            next_request_id: atomic::Atomic::new(0),
            num_incoming_connections: AtomicUsize::new(0),
            // Note: `BTreeSet` doesn't have any `with_capacity` method.
            peers: Mutex::new(BTreeSet::new()),
            connections: Mutex::new(HashMap::with_capacity_and_hasher(
                config.connections_capacity,
                Default::default(),
            )),
            tmp: core::marker::PhantomData,
        }
    }

    /// Feeds data coming from a socket through `incoming_data`, updates the internal state
    /// machine, and writes data destined to the socket to `outgoing_buffer`.
    ///
    /// `incoming_data` should be `None` if the remote has closed their writing side.
    ///
    /// The returned structure contains the number of bytes read and written from/to the two
    /// buffers. Call this method in a loop until these two values are both 0 and
    /// [`ReadWrite::event`] is `None`.
    ///
    /// If the remote isn't ready to accept new data, pass an empty slice as `outgoing_buffer`.
    ///
    /// The current time must be passed via the `now` parameter.
    ///
    /// This method is `async` but will only block if synchronization with other tasks is
    /// necessary.
    // TODO: comment about `now` monotonicity w.r.t. multiple threads
    // TODO: comment about async-ness of the function
    // TODO: comment about raciness?
    pub async fn read_write(
        &self,
        connection: ConnectionId,
        now: TNow,
        incoming_data: Option<&[u8]>,
        outgoing_buffer: &mut [u8],
    ) -> ReadWrite<TProto, TRqUd, TNow> {
        let connection = {
            let connecs = self.connections.lock().await;
            connecs.get(&connection.0).unwrap().clone() // TODO: don't unwrap
        };

        let mut connection = connection.lock().await;

        match &mut *connection {
            Connection::Pending { .. } => todo!(), // TODO: invalid id
            Connection::Handshaking { connection } => {
                // TODO: this seems incorrect w.r.t handling closure
                if let Some(incoming_data) = incoming_data {
                    //connection.inject_data(incoming_data);
                    todo!()
                }
            }
            Connection::Active { .. } => todo!(),
        }

        todo!()
    }

    /// Destroys an existing connection.
    ///
    /// Call this method if the remote has sent a `RST` or other similar message indicating that
    /// the connection should immediately shut down.
    ///
    /// Returns an error if no connection with this identifier exists.
    pub fn reset_connection(
        &self,
        connection: ConnectionId,
    ) -> Result<Event<TProto, TRqUd, TNow>, ()> {
        // TODO: decrease num_incoming_connections if necessary

        todo!()
    }

    /// Returns the number of connections that have been added with
    /// [`Network::add_incoming_connection`] and that are still open.
    ///
    /// This method is inherently subject to race conditions, as it is possible for a separate
    /// thread to add a new incoming connection or close an existing connection at the same time
    /// as it is being called.
    ///
    /// > **Note**: This method is meant to be used in order to refuse new incoming connections
    /// >           when above a certain limit. As a consequence of the API, this cannot always be
    /// >           strictly enforced. However this isn't considered a problem. If there exists
    /// >           `N` concurrent threads potentially accepting new connections, and that the
    /// >           limit is `L`, it is possible for the number of connections to reach
    /// >           `L + N - 1`. Since `N` is usually `1`, that `L` is usually a high number, and
    /// >           that `L` is usually a value chosen arbitrarily, this problem isn't actually
    /// >           one.
    pub fn num_incoming_connections(&self) -> usize {
        self.num_incoming_connections.load(Ordering::Relaxed)
    }

    /// Adds a new connection to the state machine.
    ///
    /// Call this method when for example a TCP listening socket has received a new incoming
    /// socket.
    ///
    /// This method allocates a new [`ConnectionId`] to be used with [`Network::read_write`].
    ///
    /// > **Note**: If filtering is desired based for example on the IP address on the incoming
    /// >           connection (e.g. banning a certain range of IP addresses), it should be done
    /// >           prior to calling this method.
    ///
    /// This method is `async` but will only block if synchronization with other tasks is
    /// necessary.
    pub async fn add_incoming_connection(&self, remote_send_back: Multiaddr) -> ConnectionId {
        let handshake = connection::handshake::HealthyHandshake::new(false);

        self.num_incoming_connections
            .fetch_add(1, Ordering::Relaxed);

        todo!()
    }

    /// Notifies the network of the outcome of an outgoing dialing attempt.
    ///
    /// Call this method in response to a [`Event::StartDial`] in order to notify the [`Network`]
    /// of the success of the dialing attempt.
    ///
    /// This method is `async` but will only block if synchronization with other tasks is
    /// necessary.
    pub async fn resolve_pending_connection_success(
        &self,
        id: PendingConnectionId,
    ) -> ConnectionId {
        todo!()
    }

    /// Notifies the network of the outcome of an outgoing dialing attempt.
    ///
    /// Call this method in response to a [`Event::StartDial`] in order to notify the [`Network`]
    /// of the failure of the dialing attempt.
    ///
    /// This method is `async` but will only block if synchronization with other tasks is
    /// necessary.
    pub async fn resolve_pending_connection_failure(
        &self,
        id: PendingConnectionId,
    ) -> Option<Event<TProto, TRqUd, TNow>> {
        todo!()
    }

    /// Sends a notification to the given [`PeerId`].
    // TODO: finish API and doc
    pub async fn write_notification(&self, target: &PeerId, protocol: &TProto, message: &[u8]) {
        todo!()
    }

    /// Sends a request to the given [`PeerId`] using the given protocol.
    ///
    /// Immediately returns an error if there isn't any active connection with this [`PeerId`]
    /// or if sending this request would exceed the limits enforced by the protocol.
    ///
    /// `user_data` is an opaque user data that is later provided back in the
    /// [`Event::RequestOutDone`] event.
    ///
    /// The returned [`OutRequestId`] can be used to cancel the request with
    /// [`Network::cancel_request`].
    ///
    /// This method is `async` but will only block if synchronization with other tasks is
    /// necessary.
    pub async fn send_request(
        &self,
        target: &PeerId,
        protocol: &TProto,
        user_data: TRqUd,
        request: Vec<u8>,
    ) -> Result<OutRequestId, ()> {
        todo!()
    }

    /// Cancels a request previously started using [`Network::start_request`].
    ///
    /// Returns the user data originally passed to [`Network::start_request`], or `None` if the
    /// ID of the request isn't valid.
    ///
    /// Due to its nature, this method is inherently subject to race conditions. It is possible
    /// for a [`Event::RequestOutDone`] event to be emitted on a separate task at the same time as
    /// this method is being called. It is strongly encouraged to not call `unwrap()` on this
    /// `Option` unless only one task is ever used to drive the networking.
    ///
    /// This method is `async` but will only block if synchronization with other tasks is
    /// necessary.
    pub async fn cancel_request(&self, request: OutRequestId) -> Option<TRqUd> {
        todo!()
    }

    /// Answers a request received through a [`Event::RequestIn`].
    ///
    /// Returns `Ok` if there was a request with this identifier. Returns an error if there was
    /// no such request.
    ///
    /// Due to its nature, this method is inherently subject to race conditions. It is for example
    /// possible for the remote to disconnect at the same time as this method is called. If that
    /// happens, an `Err` might be returned. As such, it is strongly encouraged to not call
    /// `unwrap()` on the returned `Result`.
    ///
    /// This method is `async` but will only block if synchronization with other tasks is
    /// necessary.
    pub async fn answer_request(&self, request: InRequestId, response: Vec<u8>) -> Result<(), ()> {
        todo!()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingConnectionId(u64);

/// Identifier for a request started locally.
///
/// Considering the racy nature of the API, the identifiers are guaranteed to never be reused.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutRequestId(u64);

/// Identifier for a request received from a remote.
///
/// Considering the racy nature of the API, the identifiers are guaranteed to never be reused.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InRequestId(u64);

/// Outcome of [`Network::read_write`].
#[must_use]
// TODO: Debug
pub struct ReadWrite<TProto, TRqUd, TNow> {
    /// Number of bytes at the start of the incoming buffer that have been processed. These bytes
    /// should no longer be present the next time [`Network::read_write`] is called.
    pub read_bytes: usize,

    /// Number of bytes written to the outgoing buffer. These bytes should be sent out to the
    /// remote. The rest of the outgoing buffer is left untouched.
    pub written_bytes: usize,

    /// If `Some`, [`Network::read_write`] should be called again when the point in time
    /// reaches the value in the `Option`.
    pub wake_up_after: Option<TNow>,

    /// Event that has happened as a consequence of the read/write operation.
    pub event: Option<Event<TProto, TRqUd, TNow>>,
}

/// Event happening on the [`Network`].
#[must_use]
pub enum Event<TProto, TRqUd, TNow> {
    /// An attempt to dial the given [`Multiaddr`] should be started.
    ///
    /// This is only emitted for [`Multiaddr`]esses that represent a stateful connection, such
    /// as with the TCP or WebSocket protocols.
    ///
    /// Either [`Network::resolve_pending_connection_success`] or
    /// [`Network::resolve_pending_connection_failure`] must later be called with the result
    /// of the attempt.
    // TODO: timeouts? should they be handled by the user or by the Network?
    StartDial {
        /// Identifier newly generated by the [`Network`] for the dialing attempt.
        id: PendingConnectionId,
        /// Target of the dialing attempt.
        target: Multiaddr,

        // TODO: remove
        _tmp: core::marker::PhantomData<TNow>,
    },

    /// No longer connected to the node with the given identity.
    Disconnected {
        /// Identity of the node the network is no longer connected to.
        peer_id: PeerId,
        requests_in_interrupt: Vec<InRequestId>,
        requests_out_interrupt: Vec<OutRequestId>,
    },

    /// A request sent from a remote has been received.
    ///
    /// > **Note**: Supposing that the remote uses the same implementation, it is as if
    /// >           [`Network::send_request`] had been called by the remote.
    RequestIn {
        /// Unique identifier of this request.
        id: InRequestId,
        /// Sender of the request.
        source: PeerId,
        /// Name of the protocol used for the request.
        protocol: TProto,
        /// Bytes of the request. Interpreting these bytes is out of scope of this module.
        request: Vec<u8>,
    },

    /// A request started using [`Network::send_request`] is finished, either successfully or with
    /// an error.
    ///
    /// If using multiple tasks, be aware that it is possible for this event to be emitted right
    /// before [`Network::cancel_request`] is called.
    RequestOutDone {
        /// Identifier of the request data originally returned by [`Network::start_request`].
        id: OutRequestId,
        /// User data originally passed to [`Network::start_request`].
        user_data: TRqUd,
        result: Result<Vec<u8>, ()>, // TODO: proper error
    },

    OverlayJoin {
        peer_id: PeerId,
        protocol: TProto,
    },

    OverlayLeave {
        peer_id: PeerId,
        protocol: TProto,
    },
}
