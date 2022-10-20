// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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
//! abstraction over the network based on network identities (i.e. [`PeerId`]s). One can set the
//! list of peers to be connected to and through which notification protocols, and the [`Peers`]
//! struct will try to open or re-open connections with these peers. Once connected, one can use
//! the [`Peers`] to send request or notifications with these peers.
//!
//! # Detailed usage
//!
//! The [`Peers`] struct contains six different collections:
//!
//! - A list, decided by the API user, of peers that are marked as "desired".
//! - A list, decided by the API user, of `(peer_id, notification_protocol)` tuples that are
//! marked as "desired".
//! - A list of connections identified by [`ConnectionId`]s.
//! - A list of requests for inbound substreams, identified by a [`SubstreamId`]. When a peer
//! desires to open a notification substream with the local node, a [`SubstreamId`] is generated.
//! The API user must answer by either accepting or refusing the request.
//! - A list of requests that have been received, identified by a [`InRequestId`]. The API user
//! must answer by calling [`Peers::respond_in_request`]. Requests can automatically become
//! obsolete if the remote decides to withdraw their request or the connection closes. A request
//! becoming obsolete does *not* invalidate its [`InRequestId`].
//!

use crate::libp2p::{self, collection, PeerId};
use crate::util::SipHasherBuild;

use alloc::{
    collections::{btree_map, BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use core::{
    hash::Hash,
    iter,
    num::NonZeroU32,
    ops::{self, Add, Sub},
    time::Duration,
};
use rand::{Rng as _, SeedableRng as _};

pub use collection::{
    ConfigRequestResponse, ConfigRequestResponseIn, ConnectionId, ConnectionToCoordinator,
    CoordinatorToConnection, MultiStreamConnectionTask, MultiStreamHandshakeKind,
    NotificationProtocolConfig, NotificationsInClosedErr, NotificationsOutErr, ReadWrite,
    RequestError, SingleStreamConnectionTask, SingleStreamHandshakeKind, SubstreamId,
};

/// Configuration for a [`Peers`].
pub struct Config {
    /// Seed for the randomness within the networking state machine.
    pub randomness_seed: [u8; 32],

    /// Capacity to initially reserve to the list of connections.
    pub connections_capacity: usize,

    /// Capacity to initially reserve to the list of peers.
    pub peers_capacity: usize,

    /// Maximum number of substreams that each remote can have simultaneously opened on each
    /// connection.
    ///
    /// If there exists multiple connections with the same remote, the limit is enforced for
    /// each connection separately.
    ///
    /// > **Note**: This limit is necessary in order to avoid DoS attacks where a remote opens too
    /// >           many substreams.
    pub max_inbound_substreams: usize,

    pub notification_protocols: Vec<NotificationProtocolConfig>,

    pub request_response_protocols: Vec<ConfigRequestResponse>,

    /// Name of the ping protocol on the network.
    pub ping_protocol: String,

    /// Amount of time after which a connection handshake is considered to have taken too long
    /// and must be aborted.
    pub handshake_timeout: Duration,

    /// Key used for the encryption layer.
    /// This is a Noise static key, according to the Noise specification.
    /// Signed using the actual libp2p key.
    pub noise_key: libp2p::connection::NoiseKey,
}

pub struct Peers<TConn, TNow> {
    /// Underlying state machine that manages connections.
    inner: collection::Network<Connection<TConn>, TNow>,

    /// List of all peer identities known to the state machine.
    peers: slab::Slab<Peer>,

    /// For each known peer, the corresponding index within [`Peers::peers`].
    ///
    /// We split the list of peers in two in order to avoid doing extensive hash map lookups when
    /// it's not necessary.
    peer_indices: hashbrown::HashMap<PeerId, usize, SipHasherBuild>,

    /// List of all peers (as indices within [`Peers::peers`]) that are desired or have a substream
    /// marked as desired but for which no non-shutting-down established or handshaking connection
    /// exists.
    unfulfilled_desired_peers: hashbrown::HashSet<usize, fnv::FnvBuildHasher>,

    /// List of all established connections, as a tuple of `(peer_index, connection_id)`.
    /// `peer_index` is the index in [`Peers::peers`]. Includes all connections even if they are
    /// still handshaking or shutting down.
    ///
    /// Note that incoming handshaking connections are never in this list, as their expected
    /// peer id isn't known before the end of the handshake.
    connections_by_peer: BTreeSet<(usize, collection::ConnectionId)>,

    /// Keys are combinations of `(peer_index, notifications_protocol_index)`. Contains all the
    /// inbound notification substreams that are either pending or accepted. Used in order to
    /// prevent a peer from opening multiple inbound substreams.
    peers_notifications_in: BTreeSet<(usize, usize)>,

    /// For each inner notification protocol substream, the connection id and the
    /// `notifications_protocol_index`.
    ///
    /// This applies to both inbound and outbound notification substreams, both pending and
    /// established.
    // TODO: this could be a user data in `collection`
    inner_notification_substreams: hashbrown::HashMap<
        collection::SubstreamId,
        (collection::ConnectionId, usize),
        fnv::FnvBuildHasher,
    >,

    /// Keys are combinations of `(peer_index, notifications_protocol_index)`. Values are the
    /// state of the corresponding outbound notifications substream.
    peers_notifications_out: BTreeMap<(usize, usize), NotificationsOutState>,

    /// Subset of [`Peers::peers_notifications_out`]. Only contains entries that are desired
    /// and not open, and for which there exists a non-shutting down established connection with
    /// the peer.
    /// Keys are combinations of `(peer_index, notifications_protocol_index)`. Values indicate
    /// whether the substream is in the `ClosedByRemote` state.
    unfulfilled_desired_outbound_substreams:
        hashbrown::HashMap<(usize, usize), bool, fnv::FnvBuildHasher>,

    /// Subset of [`Peers::peers_notifications_out`]. Only contains entries that are not desired
    /// and open or pending.
    /// Keys are combinations of `(peer_index, notifications_protocol_index)`. Values are the
    /// state of the corresponding outbound notifications substream.
    fulfilled_undesired_outbound_substreams:
        hashbrown::HashMap<(usize, usize), OpenOrPending, fnv::FnvBuildHasher>,
}

/// See [`Peers::peers_notifications_out`].
///
/// Note that the state where `desired` is `true` and `open` is `Closed` means that the remote
/// has refused or has closed the substream.
struct NotificationsOutState {
    desired: bool,
    open: NotificationsOutOpenState,
}

enum NotificationsOutOpenState {
    NotOpen,
    ClosedByRemote,
    Opening(collection::SubstreamId),
    Open(collection::SubstreamId),
}

/// See [`Peers::peers`]
struct Peer {
    peer_id: PeerId,
    desired: bool,
}

struct Connection<TConn> {
    /// Index in [`Peers::peers`] of the peer this connection is connected to.
    ///
    /// - If the handshake is finished, contains the actual peer.
    /// - If the handshake is in progress and the connection is outbound, contains the *expected*
    /// peer, which might not be the same as the actual.
    /// - If the handshake is in progress and the connection is inbound, contains `None`.
    peer_index: Option<usize>,

    /// `true` if the connection is outgoing.
    outbound: bool,

    /// Opaque data decided by the API user.
    user_data: TConn,
}

impl<TConn, TNow> Peers<TConn, TNow>
where
    TConn: Clone,
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Creates a new [`Peers`].
    pub fn new(config: Config) -> Self {
        let mut randomness = rand_chacha::ChaCha20Rng::from_seed(config.randomness_seed);

        Peers {
            inner_notification_substreams: hashbrown::HashMap::with_capacity_and_hasher(
                config.notification_protocols.len() * config.peers_capacity,
                Default::default(),
            ),
            inner: collection::Network::new(collection::Config {
                capacity: config.connections_capacity,
                noise_key: config.noise_key,
                max_inbound_substreams: config.max_inbound_substreams,
                notification_protocols: config.notification_protocols,
                request_response_protocols: config.request_response_protocols,
                ping_protocol: config.ping_protocol,
                handshake_timeout: config.handshake_timeout,
                randomness_seed: randomness.sample(rand::distributions::Standard),
            }),
            connections_by_peer: BTreeSet::new(),
            peer_indices: hashbrown::HashMap::with_capacity_and_hasher(
                config.peers_capacity,
                SipHasherBuild::new(randomness.sample(rand::distributions::Standard)),
            ),
            peers: slab::Slab::with_capacity(config.peers_capacity),
            unfulfilled_desired_peers: hashbrown::HashSet::with_capacity_and_hasher(
                config.peers_capacity,
                Default::default(),
            ),
            peers_notifications_out: BTreeMap::new(),
            unfulfilled_desired_outbound_substreams: hashbrown::HashMap::with_capacity_and_hasher(
                config.peers_capacity,
                Default::default(),
            ),
            fulfilled_undesired_outbound_substreams: hashbrown::HashMap::with_capacity_and_hasher(
                config.peers_capacity,
                Default::default(),
            ),
            peers_notifications_in: BTreeSet::new(),
        }
    }

    /// Returns the list the overlay networks originally passed as
    /// [`Config::notification_protocols`].
    pub fn notification_protocols(
        &self,
    ) -> impl ExactSizeIterator<Item = &NotificationProtocolConfig> {
        self.inner.notification_protocols()
    }

    /// Returns the list the request-response protocols originally passed as
    /// [`Config::request_response_protocols`].
    pub fn request_response_protocols(
        &self,
    ) -> impl ExactSizeIterator<Item = &ConfigRequestResponse> {
        self.inner.request_response_protocols()
    }

    /// Returns the Noise key originally passed as [`Config::noise_key`].
    pub fn noise_key(&self) -> &libp2p::connection::NoiseKey {
        self.inner.noise_key()
    }

    /// Pulls a message that must be sent to a connection.
    ///
    /// The message must be passed to [`SingleStreamConnectionTask::inject_coordinator_message`]
    /// or [`MultiStreamConnectionTask::inject_coordinator_message`] in the appropriate connection.
    ///
    /// This function guarantees that the [`ConnectionId`] always refers to a connection that
    /// is still alive, in the sense that [`SingleStreamConnectionTask::inject_coordinator_message`]
    /// or [`MultiStreamConnectionTask::inject_coordinator_message`] has never returned `None`.
    pub fn pull_message_to_connection(
        &mut self,
    ) -> Option<(ConnectionId, CoordinatorToConnection<TNow>)> {
        self.inner.pull_message_to_connection()
    }

    /// Injects into the state machine a message generated by
    /// [`SingleStreamConnectionTask::pull_message_to_coordinator`] or
    /// [`MultiStreamConnectionTask::pull_message_to_coordinator`].
    ///
    /// This message is queued and is later processed in [`Peers::next_event`]. This means that
    /// it is [`Peers::next_event`] and not [`Peers::inject_connection_message`] that updates
    /// the internals of the state machine according to the content of the message. For example,
    /// if a [`SingleStreamConnectionTask`] sends a message to the coordinator indicating that a
    /// notifications substream has been closed, the coordinator will still believe that it is
    /// open until [`Peers::next_event`] processes this message and at the same time returns a
    /// corresponding [`Event`]. Processing messages directly in
    /// [`Peers::inject_connection_message`] would introduce "race conditions" where the API user
    /// can't be sure in which state a connection or a substream is.
    pub fn inject_connection_message(
        &mut self,
        connection_id: ConnectionId,
        message: ConnectionToCoordinator,
    ) {
        self.inner.inject_connection_message(connection_id, message)
    }

    /// Returns the next event produced by the service.
    pub fn next_event(&mut self) -> Option<Event<TConn>> {
        loop {
            let event = match self.inner.next_event() {
                Some(ev) => ev,
                None => return None,
            };

            match event {
                collection::Event::HandshakeFinished {
                    id: connection_id,
                    peer_id,
                } => {
                    let actual_peer_index = self.peer_index_or_insert(&peer_id);
                    let peer_id = self.peers[actual_peer_index].peer_id.clone();

                    let expected_peer_id = if let Some(expected_peer_index) =
                        self.inner[connection_id].peer_index
                    {
                        debug_assert!(!self
                            .unfulfilled_desired_peers
                            .contains(&expected_peer_index));

                        if expected_peer_index != actual_peer_index {
                            let _was_in = self
                                .connections_by_peer
                                .remove(&(expected_peer_index, connection_id));
                            debug_assert!(_was_in);
                            let _inserted = self
                                .connections_by_peer
                                .insert((actual_peer_index, connection_id));
                            debug_assert!(_inserted);
                            self.inner[connection_id].peer_index = Some(actual_peer_index);

                            self.unfulfilled_desired_peers.remove(&actual_peer_index);

                            // We might have to insert the expected peer back in
                            // `unfulfilled_desired_peers` if it is desired.
                            if (self.peers[expected_peer_index].desired
                                || self
                                    .peers_notifications_out
                                    .range(
                                        (expected_peer_index, usize::min_value())
                                            ..=(expected_peer_index, usize::max_value()),
                                    )
                                    .any(|(_, state)| state.desired))
                                && !self
                                    .connections_by_peer
                                    .range(
                                        (expected_peer_index, ConnectionId::min_value())
                                            ..=(expected_peer_index, ConnectionId::max_value()),
                                    )
                                    .map(|(_, connection_id)| *connection_id)
                                    .any(|connection_id| {
                                        !self.inner.connection_state(connection_id).shutting_down
                                    })
                            {
                                self.unfulfilled_desired_peers.insert(expected_peer_index);
                            }
                        }

                        Some(self.peers[actual_peer_index].peer_id.clone())
                    } else {
                        let _inserted = self
                            .connections_by_peer
                            .insert((actual_peer_index, connection_id));
                        debug_assert!(_inserted);
                        self.inner[connection_id].peer_index = Some(actual_peer_index);
                        self.unfulfilled_desired_peers.remove(&actual_peer_index);
                        None
                    };

                    for ((_, notifications_protocol_index), state) in self
                        .peers_notifications_out
                        .range(
                            (actual_peer_index, usize::min_value())
                                ..=(actual_peer_index, usize::max_value()),
                        )
                        .filter(|(_, state)| {
                            state.desired
                                && matches!(
                                    state.open,
                                    NotificationsOutOpenState::NotOpen
                                        | NotificationsOutOpenState::ClosedByRemote
                                )
                        })
                    {
                        let _prev_value = self.unfulfilled_desired_outbound_substreams.insert(
                            (actual_peer_index, *notifications_protocol_index),
                            match state.open {
                                NotificationsOutOpenState::NotOpen => false,
                                NotificationsOutOpenState::ClosedByRemote => true,
                                _ => unreachable!(),
                            },
                        );
                        debug_assert!(_prev_value.is_none());
                    }

                    let num_healthy_peer_connections = {
                        let num = self
                            .connections_by_peer
                            .range(
                                (actual_peer_index, collection::ConnectionId::min_value())
                                    ..=(actual_peer_index, collection::ConnectionId::max_value()),
                            )
                            .filter(|(_, connection_id)| {
                                let state = self.inner.connection_state(*connection_id);
                                state.established && !state.shutting_down
                            })
                            .count();
                        NonZeroU32::new(u32::try_from(num).unwrap()).unwrap()
                    };

                    return Some(Event::HandshakeFinished {
                        connection_id,
                        num_healthy_peer_connections,
                        peer_id,
                        expected_peer_id,
                    });
                }

                collection::Event::StartShutdown { id, .. }
                | collection::Event::PingOutFailed { id } => {
                    // We react to ougoing ping failures by shutting down the connection. For this
                    // reason, a shutdown initiated by the remote and an outgoing ping failure
                    // share almost the same code.
                    let reason = match event {
                        collection::Event::StartShutdown { reason, .. } => {
                            ShutdownCause::Connection(reason)
                        }
                        collection::Event::PingOutFailed { .. } => {
                            // A `PingOutFailed` doesn't by itself cause a disconnect. The reason
                            // why it's handled the same way as `StartShutdown` is because we
                            // voluntarily call `start_shutdown` here.
                            self.inner.start_shutdown(id);
                            ShutdownCause::OutPingTimeout
                        }
                        _ => unreachable!(),
                    };

                    let connection_state = self.inner.connection_state(id);
                    debug_assert!(connection_state.shutting_down);

                    let peer = if let Some(peer_index) = self.inner[id].peer_index {
                        let peer_id = self.peers[peer_index].peer_id.clone();

                        // We might have to insert the peer back in `unfulfilled_desired_peers` if
                        // it is desired.
                        if (self.peers[peer_index].desired
                            || self
                                .peers_notifications_out
                                .range(
                                    (peer_index, usize::min_value())
                                        ..=(peer_index, usize::max_value()),
                                )
                                .any(|(_, state)| state.desired))
                            && !self
                                .connections_by_peer
                                .range(
                                    (peer_index, ConnectionId::min_value())
                                        ..=(peer_index, ConnectionId::max_value()),
                                )
                                .map(|(_, connection_id)| *connection_id)
                                .any(|connection_id| {
                                    !self.inner.connection_state(connection_id).shutting_down
                                })
                        {
                            self.unfulfilled_desired_peers.insert(peer_index);
                        }

                        if connection_state.established {
                            let num_healthy_peer_connections = {
                                let num = self
                                    .connections_by_peer
                                    .range(
                                        (peer_index, collection::ConnectionId::min_value())
                                            ..=(peer_index, collection::ConnectionId::max_value()),
                                    )
                                    .filter(|(_, connection_id)| {
                                        let state = self.inner.connection_state(*connection_id);
                                        state.established && !state.shutting_down
                                    })
                                    .count();
                                u32::try_from(num).unwrap()
                            };

                            if num_healthy_peer_connections == 0 {
                                for ((_, notifications_protocol_index), _) in self
                                    .peers_notifications_out
                                    .range(
                                        (peer_index, usize::min_value())
                                            ..=(peer_index, usize::max_value()),
                                    )
                                    .filter(|(_, state)| {
                                        state.desired
                                            && matches!(
                                                state.open,
                                                NotificationsOutOpenState::NotOpen
                                                    | NotificationsOutOpenState::ClosedByRemote
                                            )
                                    })
                                {
                                    let _was_in = self
                                        .unfulfilled_desired_outbound_substreams
                                        .remove(&(peer_index, *notifications_protocol_index));
                                    debug_assert!(_was_in.is_some());
                                }
                            }

                            ShutdownPeer::Established {
                                peer_id,
                                num_healthy_peer_connections,
                            }
                        } else {
                            ShutdownPeer::OutgoingHandshake {
                                expected_peer_id: peer_id,
                            }
                        }
                    } else {
                        debug_assert!(!connection_state.established);
                        ShutdownPeer::IngoingHandshake
                    };

                    return Some(Event::StartShutdown {
                        connection_id: id,
                        peer,
                        reason,
                    });
                }

                collection::Event::Shutdown {
                    id: connection_id,
                    was_established,
                    user_data:
                        Connection {
                            peer_index: Some(expected_peer_index),
                            user_data,
                            ..
                        },
                } => {
                    // `expected_peer_index` is `None` iff the connection was an incoming
                    // connection whose handshake isn't finished yet.

                    let _was_in = self
                        .connections_by_peer
                        .remove(&(expected_peer_index, connection_id));
                    debug_assert!(_was_in);

                    let peer_id = self.peers[expected_peer_index].peer_id.clone();

                    let num_healthy_peer_connections = {
                        let num = self
                            .connections_by_peer
                            .range(
                                (expected_peer_index, collection::ConnectionId::min_value())
                                    ..=(expected_peer_index, collection::ConnectionId::max_value()),
                            )
                            .filter(|(_, connection_id)| {
                                let state = self.inner.connection_state(*connection_id);
                                state.established && !state.shutting_down
                            })
                            .count();
                        u32::try_from(num).unwrap()
                    };

                    self.try_clean_up_peer(expected_peer_index);

                    return Some(Event::Shutdown {
                        connection_id,
                        peer: if was_established {
                            ShutdownPeer::Established {
                                num_healthy_peer_connections,
                                peer_id,
                            }
                        } else {
                            ShutdownPeer::OutgoingHandshake {
                                expected_peer_id: peer_id,
                            }
                        },
                        user_data,
                    });
                }

                collection::Event::Shutdown {
                    id: connection_id,
                    user_data:
                        Connection {
                            peer_index: None,
                            user_data,
                            outbound,
                            ..
                        },
                    ..
                } => {
                    // Connection was incoming but its handshake wasn't finished yet.
                    debug_assert!(!outbound);
                    return Some(Event::Shutdown {
                        connection_id,
                        peer: ShutdownPeer::IngoingHandshake,
                        user_data,
                    });
                }

                collection::Event::InboundError {
                    id: connection_id,
                    error,
                } => {
                    let peer_id = {
                        let peer_index = self.inner[connection_id].peer_index.unwrap();
                        self.peers[peer_index].peer_id.clone()
                    };

                    return Some(Event::InboundError {
                        peer_id,
                        connection_id,
                        error: InboundError::Connection(error),
                    });
                }

                collection::Event::Response {
                    substream_id,
                    response,
                } => {
                    return Some(Event::Response {
                        request_id: OutRequestId(substream_id),
                        response,
                    });
                }

                collection::Event::RequestIn {
                    id: connection_id,
                    substream_id,
                    protocol_index,
                    request_payload,
                } => {
                    let peer_id = {
                        // Incoming requests can only happen if the connection is no longer
                        // handshaking, in which case `peer_index` is guaranteed to be `Some`.
                        let peer_index = self.inner[connection_id].peer_index.unwrap();
                        self.peers[peer_index].peer_id.clone()
                    };

                    return Some(Event::RequestIn {
                        peer_id,
                        connection_id,
                        protocol_index,
                        request_id: InRequestId(substream_id),
                        request_payload,
                    });
                }

                collection::Event::RequestInCancel { substream_id } => {
                    return Some(Event::RequestInCancel {
                        id: InRequestId(substream_id),
                    })
                }

                collection::Event::NotificationsOutResult {
                    substream_id,
                    result,
                } => {
                    let (connection_id, notifications_protocol_index) = *self
                        .inner_notification_substreams
                        .get(&substream_id)
                        .unwrap();
                    let peer_index = self.inner[connection_id].peer_index.unwrap();
                    let notification_out = self
                        .peers_notifications_out
                        .get_mut(&(peer_index, notifications_protocol_index))
                        .unwrap();
                    let desired = notification_out.desired;

                    debug_assert!(matches!(
                        notification_out.open,
                        NotificationsOutOpenState::Opening(_)
                    ));

                    if result.is_ok() {
                        notification_out.open = NotificationsOutOpenState::Open(substream_id);
                    } else {
                        notification_out.open = NotificationsOutOpenState::ClosedByRemote;
                        self.inner_notification_substreams
                            .remove(&substream_id)
                            .unwrap();

                        // Update the map entries.
                        if !desired {
                            self.peers_notifications_out
                                .remove(&(peer_index, notifications_protocol_index));
                            debug_assert!(!self
                                .unfulfilled_desired_outbound_substreams
                                .contains_key(&(peer_index, notifications_protocol_index)));
                            let _was_in = self
                                .fulfilled_undesired_outbound_substreams
                                .remove(&(peer_index, notifications_protocol_index));
                            debug_assert!(matches!(_was_in, Some(OpenOrPending::Pending)));
                        } else {
                            if self
                                .connections_by_peer
                                .range(
                                    (peer_index, ConnectionId::min_value())
                                        ..=(peer_index, ConnectionId::max_value()),
                                )
                                .any(|(_, connection_id)| {
                                    let state = self.inner.connection_state(*connection_id);
                                    state.established && !state.shutting_down
                                })
                            {
                                let _prev_value = self
                                    .unfulfilled_desired_outbound_substreams
                                    .insert((peer_index, notifications_protocol_index), true);
                                debug_assert!(_prev_value.is_none());
                            }

                            debug_assert!(!self
                                .fulfilled_undesired_outbound_substreams
                                .contains_key(&(peer_index, notifications_protocol_index)));
                        }
                    }

                    return Some(Event::NotificationsOutResult {
                        peer_id: self.peers[peer_index].peer_id.clone(),
                        notifications_protocol_index,
                        result,
                    });
                }

                collection::Event::NotificationsOutCloseDemanded { substream_id }
                | collection::Event::NotificationsOutReset { substream_id } => {
                    // If the remote asks the substream to be closed, we immediately respond
                    // accordingly without asking the higher level user. This is an opinionated
                    // decision that could be changed in the future.
                    if let collection::Event::NotificationsOutCloseDemanded { .. } = event {
                        self.inner.close_out_notifications(substream_id);
                    }

                    let (connection_id, notifications_protocol_index) = self
                        .inner_notification_substreams
                        .remove(&substream_id)
                        .unwrap();
                    let peer_index = self.inner[connection_id].peer_index.unwrap();
                    let notification_out = self
                        .peers_notifications_out
                        .get_mut(&(peer_index, notifications_protocol_index))
                        .unwrap();

                    debug_assert!(matches!(
                        notification_out.open,
                        NotificationsOutOpenState::Open(_)
                    ));
                    notification_out.open = NotificationsOutOpenState::ClosedByRemote;

                    // Update the maps.
                    if !notification_out.desired {
                        self.peers_notifications_out
                            .remove(&(peer_index, notifications_protocol_index));
                        debug_assert!(!self
                            .unfulfilled_desired_outbound_substreams
                            .contains_key(&(peer_index, notifications_protocol_index)));
                        let _was_in = self
                            .fulfilled_undesired_outbound_substreams
                            .remove(&(peer_index, notifications_protocol_index));
                        debug_assert!(matches!(_was_in, Some(OpenOrPending::Open)));
                    } else {
                        if self
                            .connections_by_peer
                            .range(
                                (peer_index, ConnectionId::min_value())
                                    ..=(peer_index, ConnectionId::max_value()),
                            )
                            .any(|(_, connection_id)| {
                                let state = self.inner.connection_state(*connection_id);
                                state.established && !state.shutting_down
                            })
                        {
                            let _prev_value = self
                                .unfulfilled_desired_outbound_substreams
                                .insert((peer_index, notifications_protocol_index), true);
                            debug_assert!(_prev_value.is_none());
                        }

                        debug_assert!(!self
                            .fulfilled_undesired_outbound_substreams
                            .contains_key(&(peer_index, notifications_protocol_index)));
                    }

                    return Some(Event::NotificationsOutClose {
                        peer_id: self.peers[peer_index].peer_id.clone(),
                        notifications_protocol_index,
                    });
                }

                collection::Event::NotificationsInOpen {
                    id: connection_id,
                    substream_id,
                    notifications_protocol_index,
                    remote_handshake: handshake,
                    ..
                } => {
                    // Incoming substreams can only happen if the connection is no longer
                    // handshaking, in which case `peer_index` is guaranteed to be `Some`.
                    let peer_index = self.inner[connection_id].peer_index.unwrap();

                    // If this peer has already opened an inbound notifications substream in the
                    // past, forbid any additional one.
                    if !self
                        .peers_notifications_in
                        .insert((peer_index, notifications_protocol_index))
                    {
                        self.inner.reject_in_notifications(substream_id);
                        return Some(Event::InboundError {
                            connection_id,
                            peer_id: self.peers[peer_index].peer_id.clone(),
                            error: InboundError::DuplicateNotificationsSubstream {
                                notifications_protocol_index,
                            },
                        });
                    }

                    let _was_in = self
                        .inner_notification_substreams
                        .insert(substream_id, (connection_id, notifications_protocol_index));
                    debug_assert!(_was_in.is_none());

                    return Some(Event::NotificationsInOpen {
                        id: substream_id,
                        peer_id: self.peers[peer_index].peer_id.clone(),
                        notifications_protocol_index,
                        handshake,
                    });
                }

                collection::Event::NotificationsIn {
                    substream_id,
                    notification,
                } => {
                    let (connection_id, notifications_protocol_index) = *self
                        .inner_notification_substreams
                        .get(&substream_id)
                        .unwrap();

                    let peer_id = {
                        // Incoming notifications can only happen if the connection is no longer
                        // handshaking, in which case `peer_index` is guaranteed to be `Some`.
                        let peer_index = self.inner[connection_id].peer_index.unwrap();
                        self.peers[peer_index].peer_id.clone()
                    };

                    return Some(Event::NotificationsIn {
                        peer_id,
                        notifications_protocol_index,
                        notification,
                    });
                }

                collection::Event::NotificationsInOpenCancel { substream_id } => {
                    let (connection_id, notifications_protocol_index) = self
                        .inner_notification_substreams
                        .remove(&substream_id)
                        .unwrap();

                    let peer_index = {
                        // Incoming substreams can only happen if the connection is no longer
                        // handshaking, in which case `peer_index` is guaranteed to be `Some`.
                        self.inner[connection_id].peer_index.unwrap()
                    };

                    let _was_in = self
                        .peers_notifications_in
                        .remove(&(peer_index, notifications_protocol_index));
                    assert!(_was_in);

                    return Some(Event::NotificationsInOpenCancel { id: substream_id });
                }

                collection::Event::NotificationsInClose {
                    substream_id,
                    outcome,
                } => {
                    let (connection_id, notifications_protocol_index) = self
                        .inner_notification_substreams
                        .remove(&substream_id)
                        .unwrap();

                    let peer_index = {
                        // Incoming substreams can only happen if the connection is no longer
                        // handshaking, in which case `peer_index` is guaranteed to be `Some`.
                        self.inner[connection_id].peer_index.unwrap()
                    };

                    let _was_in = self
                        .peers_notifications_in
                        .remove(&(peer_index, notifications_protocol_index));
                    assert!(_was_in);

                    return Some(Event::NotificationsInClose {
                        peer_id: self.peers[peer_index].peer_id.clone(),
                        notifications_protocol_index,
                        outcome,
                    });
                }

                collection::Event::PingOutSuccess { .. } => {
                    // We don't care about or report successful pings at the moment.
                }
            }
        }
    }

    /// Inserts a single-stream incoming connection in the state machine.
    ///
    /// This connection hasn't finished handshaking and the [`PeerId`] of the remote isn't known
    /// yet.
    ///
    /// Must be passed the moment (as a `TNow`) when the connection as been established, in order
    /// to determine when the handshake timeout expires.
    pub fn add_single_stream_incoming_connection(
        &mut self,
        when_connected: TNow,
        handshake_kind: SingleStreamHandshakeKind,
        user_data: TConn,
    ) -> (ConnectionId, SingleStreamConnectionTask<TNow>) {
        self.inner.insert_single_stream(
            when_connected,
            handshake_kind,
            false,
            Connection {
                peer_index: None,
                user_data,
                outbound: false,
            },
        )
    }

    /// Inserts a single-stream outgoing connection in the state machine.
    ///
    /// This connection hasn't finished handshaking, and the [`PeerId`] of the remote isn't known
    /// yet, but it is expected to be in `unfulfilled_desired_peers`. After this function has been
    /// called, the provided `expected_peer_id` will no longer be part of the return value of
    /// [`Peers::unfulfilled_desired_peers`].
    ///
    /// Must be passed the moment (as a `TNow`) when the connection as been established, in order
    /// to determine when the handshake timeout expires.
    pub fn add_single_stream_outgoing_connection(
        &mut self,
        when_connected: TNow,
        handshake_kind: SingleStreamHandshakeKind,
        expected_peer_id: &PeerId,
        user_data: TConn,
    ) -> (ConnectionId, SingleStreamConnectionTask<TNow>) {
        let peer_index = self.peer_index_or_insert(expected_peer_id);

        self.unfulfilled_desired_peers.remove(&peer_index);

        let (connection_id, connection_task) = self.inner.insert_single_stream(
            when_connected,
            handshake_kind,
            true,
            Connection {
                peer_index: Some(peer_index),
                user_data,
                outbound: true,
            },
        );

        let _inserted = self.connections_by_peer.insert((peer_index, connection_id));
        debug_assert!(_inserted);

        (connection_id, connection_task)
    }

    /// Inserts a multi-stream outgoing connection in the state machine.
    ///
    /// This connection hasn't finished handshaking, and the [`PeerId`] of the remote isn't known
    /// yet, but it is expected to be in `unfulfilled_desired_peers`. After this function has been
    /// called, the provided `expected_peer_id` will no longer be part of the return value of
    /// [`Peers::unfulfilled_desired_peers`].
    ///
    /// Must be passed the moment (as a `TNow`) when the connection as been established, in order
    /// to determine when the handshake timeout expires.
    pub fn add_multi_stream_outgoing_connection<TSubId>(
        &mut self,
        when_connected: TNow,
        handshake_kind: MultiStreamHandshakeKind,
        expected_peer_id: &PeerId,
        user_data: TConn,
    ) -> (ConnectionId, MultiStreamConnectionTask<TNow, TSubId>)
    where
        TSubId: Clone + PartialEq + Eq + Hash,
    {
        let peer_index = self.peer_index_or_insert(expected_peer_id);

        self.unfulfilled_desired_peers.remove(&peer_index);

        let (connection_id, connection_task) = self.inner.insert_multi_stream(
            when_connected,
            handshake_kind,
            Connection {
                peer_index: Some(peer_index),
                user_data,
                outbound: true,
            },
        );

        let _inserted = self.connections_by_peer.insert((peer_index, connection_id));
        debug_assert!(_inserted);

        (connection_id, connection_task)
    }

    /// Returns all the non-handshaking connections that are connected to the given peer. The list
    /// also includes connections that are shutting down.
    pub fn established_peer_connections(
        &'_ self,
        peer_id: &PeerId,
    ) -> impl Iterator<Item = ConnectionId> + '_ {
        let peer_index = match self.peer_indices.get(peer_id) {
            Some(idx) => *idx,
            None => return either::Right(iter::empty()),
        };

        either::Left(
            self.connections_by_peer
                .range(
                    (peer_index, ConnectionId::min_value())
                        ..=(peer_index, ConnectionId::max_value()),
                )
                .map(|(_, connection_id)| *connection_id)
                .filter(move |connection_id| {
                    self.inner.connection_state(*connection_id).established
                }),
        )
    }

    /// Returns all the handshaking connections that are expected to reach the given peer. The
    /// list also includes connections that are shutting down.
    pub fn handshaking_peer_connections(
        &'_ self,
        peer_id: &PeerId,
    ) -> impl Iterator<Item = ConnectionId> + '_ {
        let peer_index = match self.peer_indices.get(peer_id) {
            Some(idx) => *idx,
            None => return either::Right(iter::empty()),
        };

        either::Left(
            self.connections_by_peer
                .range(
                    (peer_index, ConnectionId::min_value())
                        ..=(peer_index, ConnectionId::max_value()),
                )
                .map(|(_, connection_id)| *connection_id)
                .filter(move |connection_id| {
                    !self.inner.connection_state(*connection_id).established
                }),
        )
    }

    /// Returns the list of peers for which we have a fully established notifications protocol of
    /// the given protocol.
    pub fn opened_out_notifications(
        &'_ self,
        notifications_protocol_index: usize,
    ) -> impl Iterator<Item = &'_ PeerId> + '_ {
        // TODO: this is O(n)
        self.peers_notifications_out
            .iter()
            .filter(move |((_, idx), _)| *idx == notifications_protocol_index)
            .filter(|(_, state)| matches!(state.open, NotificationsOutOpenState::Open(_)))
            .map(|((peer_idx, _), _)| &self.peers[*peer_idx].peer_id)
    }

    /// Returns the state of the given connection.
    ///
    /// # Panic
    ///
    /// Panics if the identifier is invalid or corresponds to a connection that has already
    /// entirely shut down.
    ///
    pub fn connection_state(&self, connection_id: ConnectionId) -> ConnectionState {
        let inner_state = self.inner.connection_state(connection_id);

        ConnectionState {
            established: inner_state.established,
            shutting_down: inner_state.shutting_down,
            outbound: self.inner[connection_id].outbound,
        }
    }

    /// Returns the list of [`PeerId`]s that have been marked as desired, but that don't have any
    /// associated connection. An associated connection is either a fully established connection
    /// with that peer, or an outgoing connection that is still handshaking but expects to reach
    /// that peer.
    pub fn unfulfilled_desired_peers(&'_ self) -> impl Iterator<Item = &'_ PeerId> + '_ {
        self.unfulfilled_desired_peers
            .iter()
            .map(move |idx| &self.peers[*idx].peer_id)
    }

    /// Sets the "desired" flag of the given [`PeerId`].
    ///
    /// When a peer is marked as "desired" and there isn't any pending or established connection
    /// towards it, it is returned when calling [`Peers::unfulfilled_desired_peers`].
    pub fn set_peer_desired(&mut self, peer_id: &PeerId, desired: bool) {
        let peer_index = self.peer_index_or_insert(peer_id);
        self.peers[peer_index].desired = desired;

        if desired {
            // Insert in `unfulfilled_desired_peers` if there is no non-shutting-down established
            // or handshaking connection of that peer.
            if !self
                .connections_by_peer
                .range(
                    (peer_index, ConnectionId::min_value())
                        ..=(peer_index, ConnectionId::max_value()),
                )
                .map(|(_, connection_id)| *connection_id)
                .any(|connection_id| !self.inner.connection_state(connection_id).shutting_down)
            {
                self.unfulfilled_desired_peers.insert(peer_index);
            }
        } else {
            // Remove from `unfulfilled_desired_peers` if there no desired notifications
            // substream.
            // Note that the peer is not necessarily expected to be in `unfulfilled_desired_peers`.
            if !self
                .peers_notifications_out
                .range((peer_index, usize::min_value())..=(peer_index, usize::max_value()))
                .any(|(_, state)| state.desired)
            {
                self.unfulfilled_desired_peers.remove(&peer_index);
            }

            self.try_clean_up_peer(peer_index);
        }
    }

    /// Sets the given combinations of notification protocol and [`PeerId`] as "desired".
    ///
    /// When a peer is marked as "desired" and there isn't any pending or established connection
    /// towards it, it is returned when calling [`Peers::unfulfilled_desired_peers`].
    ///
    /// When a combination of network protocol and [`PeerId`] is marked as "desired", it will
    /// be returned by [`Peers::unfulfilled_desired_outbound_substream`].
    ///
    /// When a combination of network protocol and [`PeerId`] is no longer marked as "desired", it
    /// will be returned by [`Peers::fulfilled_undesired_outbound_substreams`].
    ///
    /// This function might generate a message destined to a connection. Use
    /// [`Peers::pull_message_to_connection`] to process these messages after it has returned.
    pub fn set_peer_notifications_out_desired(
        &mut self,
        peer_id: &PeerId,
        notification_protocol: usize,
        new_desired_state: DesiredState,
    ) {
        let peer_index = self.peer_index_or_insert(peer_id);

        let current_state = self
            .peers_notifications_out
            .entry((peer_index, notification_protocol));

        if matches!(
            new_desired_state,
            DesiredState::Desired | DesiredState::DesiredReset
        ) {
            // Do nothing if it was already desired.
            match (&current_state, new_desired_state) {
                (btree_map::Entry::Occupied(e), DesiredState::Desired) if e.get().desired => return,
                _ => {}
            }

            let current_state = current_state.or_insert(NotificationsOutState {
                desired: true,
                open: NotificationsOutOpenState::NotOpen,
            });
            current_state.desired = true;

            if matches!(new_desired_state, DesiredState::DesiredReset)
                && matches!(
                    current_state.open,
                    NotificationsOutOpenState::ClosedByRemote
                )
            {
                current_state.open = NotificationsOutOpenState::NotOpen;
            }

            // Add to `unfulfilled_desired_outbound_substreams` if there exists a connection.
            if matches!(
                current_state.open,
                NotificationsOutOpenState::NotOpen | NotificationsOutOpenState::ClosedByRemote
            ) {
                if self
                    .connections_by_peer
                    .range(
                        (peer_index, ConnectionId::min_value())
                            ..=(peer_index, ConnectionId::max_value()),
                    )
                    .any(|(_, connection_id)| {
                        let state = self.inner.connection_state(*connection_id);
                        state.established && !state.shutting_down
                    })
                {
                    let _prev_value = self.unfulfilled_desired_outbound_substreams.insert(
                        (peer_index, notification_protocol),
                        match current_state.open {
                            NotificationsOutOpenState::NotOpen => false,
                            NotificationsOutOpenState::ClosedByRemote => true,
                            _ => unreachable!(),
                        },
                    );
                    debug_assert!(_prev_value.is_none());
                }
            }

            // Remove substream from `fulfilled_undesired_outbound_substreams`, as it is
            // no longer undesired.
            if matches!(
                current_state.open,
                NotificationsOutOpenState::Open(_) | NotificationsOutOpenState::Opening(_)
            ) {
                let _was_in = self
                    .fulfilled_undesired_outbound_substreams
                    .remove(&(peer_index, notification_protocol));
                debug_assert!(_was_in.is_some());
            }

            // Insert in `unfulfilled_desired_peers` if there is no non-shutting-down established
            // or handshaking connection of that peer.
            if !self
                .connections_by_peer
                .range(
                    (peer_index, ConnectionId::min_value())
                        ..=(peer_index, ConnectionId::max_value()),
                )
                .map(|(_, connection_id)| *connection_id)
                .any(|connection_id| !self.inner.connection_state(connection_id).shutting_down)
            {
                self.unfulfilled_desired_peers.insert(peer_index);
            }
        } else {
            // Do nothing if not desired.
            let mut current_state = match current_state {
                btree_map::Entry::Occupied(e) => e,
                _ => return,
            };
            if !current_state.get().desired {
                return;
            }

            current_state.get_mut().desired = false;

            // Remove substream from `unfulfilled_desired_outbound_substreams`, as it is no longer
            // desired.
            if matches!(
                current_state.get().open,
                NotificationsOutOpenState::NotOpen | NotificationsOutOpenState::ClosedByRemote
            ) {
                let _was_in = self
                    .unfulfilled_desired_outbound_substreams
                    .remove(&(peer_index, notification_protocol));
                debug_assert_eq!(
                    _was_in.is_some(),
                    self.connections_by_peer
                        .range(
                            (peer_index, ConnectionId::min_value())
                                ..=(peer_index, ConnectionId::max_value()),
                        )
                        .any(|(_, connection_id)| {
                            let state = self.inner.connection_state(*connection_id);
                            state.established && !state.shutting_down
                        })
                );
            }

            // Insert substream into `fulfilled_undesired_outbound_substreams`, as it is
            // now undesired.
            if matches!(
                current_state.get().open,
                NotificationsOutOpenState::Open(_) | NotificationsOutOpenState::Opening(_)
            ) {
                let _pre_value = self.fulfilled_undesired_outbound_substreams.insert(
                    (peer_index, notification_protocol),
                    match current_state.get().open {
                        NotificationsOutOpenState::Open(_) => OpenOrPending::Open,
                        NotificationsOutOpenState::Opening(_) => OpenOrPending::Pending,
                        _ => unreachable!(),
                    },
                );
                debug_assert!(_pre_value.is_none());
            }

            // Clean up the entry altogether if it is no longer needed.
            if matches!(
                current_state.get().open,
                NotificationsOutOpenState::NotOpen | NotificationsOutOpenState::ClosedByRemote
            ) {
                current_state.remove();
            }

            // Remove from `unfulfilled_desired_peers` if the peer is not desired and there is no
            // desired notifications substream.
            // Note that the peer is not necessarily expected to be in `unfulfilled_desired_peers`.
            if !self.peers[peer_index].desired
                && !self
                    .peers_notifications_out
                    .range((peer_index, usize::min_value())..=(peer_index, usize::max_value()))
                    .any(|(_, state)| state.desired)
            {
                self.unfulfilled_desired_peers.remove(&peer_index);
            }

            self.try_clean_up_peer(peer_index);
        }
    }

    /// Responds to a [`Event::NotificationsInOpen`] by accepting the request for an inbound
    /// substream.
    ///
    /// This function might generate a message destined to a connection. Use
    /// [`Peers::pull_message_to_connection`] to process these messages after it has returned.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid, for example if it was yielded in a
    /// [`Event::NotificationsInOpenCancel`].
    ///
    pub fn in_notification_accept(&mut self, id: SubstreamId, handshake_back: Vec<u8>) {
        self.inner.accept_in_notifications(id, handshake_back);
    }

    /// Responds to a [`Event::NotificationsInOpen`] by refusing the request for an inbound
    /// substream.
    ///
    /// This function might generate a message destined to a connection. Use
    /// [`Peers::pull_message_to_connection`] to process these messages after it has returned.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid, for example if it was yielded in a
    /// [`Event::NotificationsInOpenCancel`].
    ///
    pub fn in_notification_refuse(&mut self, id: SubstreamId) {
        self.inner.reject_in_notifications(id);

        let (connection_id, notifications_protocol_index) =
            self.inner_notification_substreams.remove(&id).unwrap();
        let peer_index = self.inner[connection_id].peer_index.unwrap();

        let _was_in = self
            .peers_notifications_in
            .remove(&(peer_index, notifications_protocol_index));
        debug_assert!(_was_in);
    }

    /// Returns the list of peer-substream combinations marked as desired where there exists a
    /// non-shutting-down connection to this peer but the desired substream hasn't been opened yet.
    ///
    /// If `include_already_tried`, this function returns substreams that were attempted before
    /// and have been refused by the remote.
    ///
    /// Use [`Peers::open_out_notification`] to actually open a substream.
    pub fn unfulfilled_desired_outbound_substream(
        &'_ self,
        include_already_tried: bool,
    ) -> impl Iterator<Item = (&'_ PeerId, usize)> + '_ {
        self.unfulfilled_desired_outbound_substreams
            .iter()
            .filter(move |((_, _), already_tried)| **already_tried == include_already_tried)
            .map(|((peer_index, notifications_protocol_index), _)| {
                (
                    &self.peers[*peer_index].peer_id,
                    *notifications_protocol_index,
                )
            })
    }

    /// Open a new outgoing substream to the given peer. The peer-protocol combination must have
    /// been marked as desired, and a non-shutting-down connection must exist with the current
    /// peer.
    ///
    /// Must be passed the current moment in time in order to determine when the operation of
    /// opening the substream times out.
    ///
    /// Use [`Peers::unfulfilled_desired_outbound_substream`] in order to determine which
    /// substreams should be opened.
    ///
    /// This function might generate a message destined to a connection. Use
    /// [`Peers::pull_message_to_connection`] to process these messages after it has returned.
    ///
    /// # Panic
    ///
    /// Panics if this combination of peer-protocol isn't desired.
    /// Panics if there is no established non-shutting-down connection with the given peer.
    /// Panics if there is already an outgoing substream with this peer-protocol combination.
    ///
    pub fn open_out_notification(
        &mut self,
        peer_id: &PeerId,
        notifications_protocol_index: usize,
        now: TNow,
        handshake: Vec<u8>,
    ) {
        let peer_index = self.peer_index_or_insert(peer_id);
        let connection_id = self.connection_id_for_peer(peer_id).unwrap();

        let notif_state = self
            .peers_notifications_out
            .entry((peer_index, notifications_protocol_index))
            .or_insert(NotificationsOutState {
                desired: true,
                open: NotificationsOutOpenState::NotOpen,
            });

        assert!(notif_state.desired);
        assert!(matches!(
            notif_state.open,
            NotificationsOutOpenState::NotOpen | NotificationsOutOpenState::ClosedByRemote
        ));

        let substream_id = self.inner.open_out_notifications(
            connection_id,
            notifications_protocol_index,
            now,
            handshake,
        );

        let _prev_value = self
            .inner_notification_substreams
            .insert(substream_id, (connection_id, notifications_protocol_index));
        debug_assert!(_prev_value.is_none());

        let _was_in = self
            .unfulfilled_desired_outbound_substreams
            .remove(&(peer_index, notifications_protocol_index));
        debug_assert!(_was_in.is_some());

        notif_state.open = NotificationsOutOpenState::Opening(substream_id);
    }

    /// Returns the list of peer-substream combinations not marked as desired but where there
    /// exists an open substream or a substream currently being opened.
    ///
    /// Use [`Peers::close_out_notification`] to actually close the substream.
    pub fn fulfilled_undesired_outbound_substreams(
        &'_ self,
    ) -> impl Iterator<Item = (&'_ PeerId, usize, OpenOrPending)> + '_ {
        self.fulfilled_undesired_outbound_substreams.iter().map(
            |((peer_index, notifications_protocol_index), open_or_pending)| {
                (
                    &self.peers[*peer_index].peer_id,
                    *notifications_protocol_index,
                    *open_or_pending,
                )
            },
        )
    }

    /// Close an existing outgoing substream to the given peer, or cancel opening an outgoing
    /// substream.
    ///
    /// Use [`Peers::fulfilled_undesired_outbound_substreams`] in order to determine which
    /// substreams should be closed. However, this function can be used to close any substream
    /// even if it marked as desired. If it is marked as desired, the substream will subsequently
    /// be returned by [`Peers::unfulfilled_desired_outbound_substream`].
    ///
    /// This function might generate a message destined to a connection. Use
    /// [`Peers::pull_message_to_connection`] to process these messages after it has returned.
    ///
    /// Returns whether the substream was open or still being opened.
    ///
    /// > **Note**: This function does *not* generate a [`Event::NotificationsOutResult`] or
    /// >           [`Event::NotificationsOutClose`] event. Calling this function is equivalent
    /// >           to such an event being instantaneously generated.
    ///
    /// # Panic
    ///
    /// Panics if this combination of peer-protocol isn't open or opening.
    ///
    pub fn close_out_notification(
        &mut self,
        peer_id: &PeerId,
        notifications_protocol_index: usize,
    ) -> OpenOrPending {
        let peer_index = *self.peer_indices.get(peer_id).unwrap();

        let mut entry = match self
            .peers_notifications_out
            .entry((peer_index, notifications_protocol_index))
        {
            btree_map::Entry::Occupied(e) => e,
            btree_map::Entry::Vacant(_) => panic!(),
        };

        let open_or_pending = match entry.get_mut().open {
            NotificationsOutOpenState::NotOpen | NotificationsOutOpenState::ClosedByRemote => {
                panic!()
            }
            NotificationsOutOpenState::Open(substream_id)
            | NotificationsOutOpenState::Opening(substream_id) => {
                let open_or_pending = match entry.get_mut().open {
                    NotificationsOutOpenState::Open(_) => OpenOrPending::Open,
                    NotificationsOutOpenState::Opening(_) => OpenOrPending::Pending,
                    _ => unreachable!(),
                };

                self.inner.close_out_notifications(substream_id);
                entry.get_mut().open = NotificationsOutOpenState::NotOpen;

                if entry.get().desired {
                    if self
                        .connections_by_peer
                        .range(
                            (peer_index, ConnectionId::min_value())
                                ..=(peer_index, ConnectionId::max_value()),
                        )
                        .any(|(_, connection_id)| {
                            let state = self.inner.connection_state(*connection_id);
                            state.established && !state.shutting_down
                        })
                    {
                        let _prev_value = self
                            .unfulfilled_desired_outbound_substreams
                            .insert((peer_index, notifications_protocol_index), false);
                        debug_assert!(_prev_value.is_none());
                    }
                } else {
                    let _was_in = self
                        .fulfilled_undesired_outbound_substreams
                        .remove(&(peer_index, notifications_protocol_index));
                    debug_assert_eq!(_was_in, Some(open_or_pending));
                }

                // Clean up the data structure.
                if !entry.get_mut().desired {
                    entry.remove();
                }

                open_or_pending
            }
        };

        self.try_clean_up_peer(peer_index);

        open_or_pending
    }

    /// Adds a notification to the queue of notifications to send to the given peer.
    ///
    /// It is invalid to call this on a [`PeerId`] before a successful
    /// [`Event::NotificationsOutResult`] has been yielded.
    ///
    /// Each substream maintains a queue of notifications to be sent to the remote. This method
    /// attempts to push a notification to this queue.
    ///
    /// An error is also returned if the queue exceeds a certain size in bytes, for two reasons:
    ///
    /// - Since the content of the queue is transferred at a limited rate, each notification
    /// pushed at the end of the queue will take more time than the previous one to reach the
    /// destination. Once the queue reaches a certain size, the time it would take for
    /// newly-pushed notifications to reach the destination would start being unreasonably large.
    ///
    /// - If the remote deliberately applies back-pressure on the substream, it is undesirable to
    /// increase the memory usage of the local node.
    ///
    /// Similarly, the queue being full is a normal situation and notification protocols should
    /// be designed in such a way that discarding notifications shouldn't have a too negative
    /// impact.
    ///
    /// Regardless of the success of this function, no guarantee exists about the successful
    /// delivery of notifications.
    ///
    /// This function generates a message destined to the connection. Use
    /// [`Peers::pull_message_to_connection`] to process these messages after it has returned.
    ///
    /// # Panics
    ///
    /// Panics if there is no fully-open outbound substream with that peer-protocol combination.
    /// This can be checked using [`Peers::can_queue_notification`].
    ///
    pub fn queue_notification(
        &mut self,
        target: &PeerId,
        notifications_protocol_index: usize,
        notification: impl Into<Vec<u8>>,
    ) -> Result<(), QueueNotificationError> {
        let peer_index = *self.peer_indices.get(target).unwrap();

        let substream_id = match self
            .peers_notifications_out
            .get(&(peer_index, notifications_protocol_index))
            .map(|state| &state.open)
        {
            None
            | Some(
                NotificationsOutOpenState::Opening(_)
                | NotificationsOutOpenState::NotOpen
                | NotificationsOutOpenState::ClosedByRemote,
            ) => {
                panic!()
            }
            Some(NotificationsOutOpenState::Open(s_id)) => s_id,
        };

        let result = self.inner.queue_notification(*substream_id, notification);

        match result {
            Ok(()) => Ok(()),
            Err(collection::QueueNotificationError::QueueFull) => {
                Err(QueueNotificationError::QueueFull)
            }
        }
    }

    /// Returns `true` if it is allowed to call [`Peers::queue_notification`], in other words if
    /// there is an outbound notifications substream currently open with the target.
    ///
    /// If this function returns `false`, calling [`Peers::queue_notification`] will panic.
    pub fn can_queue_notification(
        &self,
        target: &PeerId,
        notifications_protocol_index: usize,
    ) -> bool {
        let peer_index = match self.peer_indices.get(target) {
            Some(idx) => *idx,
            None => return false,
        };

        match self
            .peers_notifications_out
            .get(&(peer_index, notifications_protocol_index))
            .map(|state| &state.open)
        {
            Some(NotificationsOutOpenState::Open(_)) => true,
            None
            | Some(
                NotificationsOutOpenState::Opening(_)
                | NotificationsOutOpenState::NotOpen
                | NotificationsOutOpenState::ClosedByRemote,
            ) => false,
        }
    }

    /// Equivalent to calling [`Peers::queue_notification`] for all peers an outbound
    /// notifications substream is open with.
    ///
    /// Individual errors that would have occurred when calling [`Peers::queue_notification`] are
    /// silently discarded.
    ///
    /// This function might generate messages destined to connections. Use
    /// [`Peers::pull_message_to_connection`] to process these messages after it has returned.
    // TODO: consider returning the peers we successfully sent to
    pub fn broadcast_notification(
        &mut self,
        notifications_protocol_index: usize,
        notification: impl Into<Vec<u8>>,
    ) {
        let notification = notification.into();

        // TODO: implement this better; this is O(n)
        for ((_, notif_proto_index), state) in self.peers_notifications_out.iter() {
            if *notif_proto_index != notifications_protocol_index {
                continue;
            }

            if let NotificationsOutOpenState::Open(substream_id) = &state.open {
                let _ = self
                    .inner
                    .queue_notification(*substream_id, notification.clone());
            }
        }
    }

    /// Sends a request to the given peer.
    ///
    /// A [`Event::Response`] event will later be generated containing the result of the request.
    ///
    /// It is invalid to start a request on a peer before an [`Event::HandshakeFinished`] event
    /// has been generated, or after a [`Event::StartShutdown`] event has been generated where
    /// [`ShutdownPeer::Established::num_healthy_peer_connections`] is 0.
    ///
    /// Returns a newly-allocated identifier for this request.
    ///
    /// This function generates a message destined to a connection. Use
    /// [`Peers::pull_message_to_connection`] to process these messages after it has returned.
    ///
    /// # Requests
    ///
    /// A request consists in:
    ///
    /// - Opening a substream on an established connection with the target.
    /// - Negotiating the requested protocol (`protocol_index`) on this substream using the
    ///   *multistream-select* protocol.
    /// - Sending the request (`request_data` parameter), prefixed with its length.
    /// - Waiting for the response (prefixed with its length), which is then returned.
    ///
    /// An error happens if the connection closes while the request is in progress, if the remote
    /// doesn't support the given protocol, if the request or response doesn't respect the protocol
    /// limits (see [`ConfigRequestResponse`]), or if the remote takes too much time to answer.
    ///
    /// The timeout is the time between the moment the substream is opened and the moment the
    /// response is sent back. If the emitter doesn't send the request or if the receiver doesn't
    /// answer during this time window, the request is considered failed.
    ///
    /// # Panic
    ///
    /// Panics if `protocol_index` isn't a valid index in [`Config::request_response_protocols`].
    /// Panics if there is no open connection with the target or if all connections are shutting
    /// down. Use [`Peers::can_start_requests`] to check if this is the case.
    ///
    #[track_caller]
    pub fn start_request(
        &mut self,
        target: &PeerId,
        protocol_index: usize,
        request_data: Vec<u8>,
        timeout: TNow,
    ) -> OutRequestId {
        let target_connection_id = match self.connection_id_for_peer(target) {
            Some(id) => id,
            None => panic!(), // As documented.
        };

        OutRequestId(self.inner.start_request(
            target_connection_id,
            protocol_index,
            request_data,
            timeout,
        ))
    }

    /// Returns `true` if if it possible to send requests (i.e. through [`Peers::start_request`])
    /// to the given peer.
    ///
    /// If `false` is returned, then starting a request will panic.
    ///
    /// In other words, returns `true` if there exists an established connection non-shutting-down
    /// connection with the given peer.
    pub fn can_start_requests(&self, peer_id: &PeerId) -> bool {
        self.established_peer_connections(peer_id).any(|c| {
            let state = self.connection_state(c);
            debug_assert!(state.established); // Guaranteed by `established_peer_connections`.
            !state.shutting_down
        })
    }

    /// Responds to a previously-emitted [`Event::RequestIn`].
    ///
    /// # Panic
    ///
    /// Panics if the [`InRequestId`] is invalid. Note that these ids remain valid forever until
    /// [`Peers::respond_in_request`] is called or a [`Event::RequestInCancel`] is generated.
    ///
    pub fn respond_in_request(&mut self, id: InRequestId, response: Result<Vec<u8>, ()>) {
        self.inner.respond_in_request(id.0, response)
    }

    /// Returns an iterator to the list of [`PeerId`]s that we have an established connection
    /// with.
    pub fn peers_list(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(peer_index, _)| {
                self.connections_by_peer
                    .range(
                        (*peer_index, ConnectionId::min_value())
                            ..=(*peer_index, ConnectionId::max_value()),
                    )
                    .any(|(_, connection_id)| {
                        // Note that connections that are shutting down are still counted,
                        // as we report the disconnected event only at the end of the
                        // shutdown.
                        self.inner.connection_state(*connection_id).established
                    })
            })
            .map(|(_, p)| &p.peer_id)
    }

    /// Returns the number of connections we have a substream with.
    pub fn num_outgoing_substreams(&self, notifications_protocol_index: usize) -> usize {
        // TODO: O(n)
        self.peers_notifications_out
            .iter()
            .filter(|((_, idx), state)| {
                *idx == notifications_protocol_index
                    && matches!(state.open, NotificationsOutOpenState::Open(_))
            })
            .count()
    }

    /// Picks the connection to use to send requests or notifications to the given peer.
    ///
    /// This function tries to find a connection that is established and not shutting down.
    fn connection_id_for_peer(&self, target: &PeerId) -> Option<ConnectionId> {
        let peer_index = match self.peer_indices.get(target) {
            Some(i) => *i,
            None => return None,
        };

        for (_, connection_id) in self.connections_by_peer.range(
            (peer_index, collection::ConnectionId::min_value())
                ..=(peer_index, collection::ConnectionId::max_value()),
        ) {
            let state = self.inner.connection_state(*connection_id);
            if !state.established {
                continue;
            }

            if state.shutting_down {
                continue;
            }

            return Some(*connection_id);
        }

        None
    }

    fn peer_index_or_insert(&mut self, peer_id: &PeerId) -> usize {
        if let Some(idx) = self.peer_indices.get(peer_id) {
            return *idx;
        }

        let index = self.peers.insert(Peer {
            desired: false,
            peer_id: peer_id.clone(),
        });

        self.peer_indices.insert(peer_id.clone(), index);
        index
    }

    /// Checks the state of the given `peer_index`. If there is no difference between this peer's
    /// state and the default state, removes the peer from the data structure altogether.
    ///
    /// # Panic
    ///
    /// Panics if the given `peer_index` is invalid.
    ///
    fn try_clean_up_peer(&mut self, peer_index: usize) {
        if self.peers[peer_index].desired {
            return;
        }

        if self
            .connections_by_peer
            .range(
                (peer_index, collection::ConnectionId::min_value())
                    ..=(peer_index, collection::ConnectionId::max_value()),
            )
            .count()
            != 0
        {
            return;
        }

        if self
            .peers_notifications_out
            .range((peer_index, usize::min_value())..=(peer_index, usize::max_value()))
            .count()
            != 0
        {
            return;
        }

        let peer_id = self.peers.remove(peer_index).peer_id;
        let _index = self.peer_indices.remove(&peer_id).unwrap();
        debug_assert_eq!(_index, peer_index);
    }
}

impl<TConn, TNow> ops::Index<ConnectionId> for Peers<TConn, TNow> {
    type Output = TConn;
    fn index(&self, id: ConnectionId) -> &TConn {
        &self.inner[id].user_data
    }
}

impl<TConn, TNow> ops::IndexMut<ConnectionId> for Peers<TConn, TNow> {
    fn index_mut(&mut self, id: ConnectionId) -> &mut TConn {
        &mut self.inner[id].user_data
    }
}

/// See [`Peers::connection_state`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ConnectionState {
    /// If `true`, the connection has finished its handshaking phase.
    pub established: bool,

    /// If `true`, the connection is shutting down.
    pub shutting_down: bool,

    /// `true` if the connection is outgoing.
    pub outbound: bool,
}

/// See [`Event::RequestIn`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InRequestId(collection::SubstreamId);

/// See [`Peers::start_request`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutRequestId(collection::SubstreamId);

/// Event happening over the network. See [`Peers::next_event`].
// TODO: in principle we could return `&PeerId` instead of `PeerId` most of the time, but this causes many borrow checker issues in the upper layer and I'm not motivated enough to deal with that
#[derive(Debug)]
pub enum Event<TConn> {
    /// Connection has finished its handshake.
    ///
    /// Only generated for single-stream connections. The handshake of multi-stream connections is
    /// considered to be already finished.
    HandshakeFinished {
        /// Identifier of the connection that has finished its handshake.
        connection_id: ConnectionId,

        /// Identity of the peer on the other side of the connection.
        peer_id: PeerId,

        /// Identity of the peer that was expected to be reached.
        ///
        /// Always `Some` for outgoing connections and always `None` for incoming connections.
        expected_peer_id: Option<PeerId>,

        /// Number of established not-shutting-down connections with the same peer, including the
        /// one that has just been established.
        num_healthy_peer_connections: NonZeroU32,
    },

    StartShutdown {
        /// Identifier of the connection that has started shutting down.
        connection_id: ConnectionId,

        /// State of the connection and identity of the remote.
        peer: ShutdownPeer,

        /// Reason for the shutdown.
        reason: ShutdownCause,
    },

    /// A connection has stopped.
    Shutdown {
        /// Identifier of the connection that has started shutting down.
        connection_id: ConnectionId,
        /// State of the connection and identity of the remote.
        peer: ShutdownPeer,
        /// User data that was associated to this connection.
        user_data: TConn,
    },

    /// Received an incoming substream, but this substream has produced an error.
    ///
    /// > **Note**: This event exists only for diagnostic purposes. No action is expected in
    /// >           return.
    InboundError {
        /// Peer which opened the substream.
        peer_id: PeerId,
        /// Identifier of the connection on which the problem happened.
        connection_id: ConnectionId,
        /// Error that happened.
        error: InboundError,
    },

    /// Outcome of a request started using [`Peers::start_request`].
    ///
    /// All requests always lead to an outcome, even if the connection has been closed while the
    /// request was in progress.
    Response {
        /// Identifier for this request. Was returned by [`Peers::start_request`].
        request_id: OutRequestId,
        response: Result<Vec<u8>, RequestError>,
    },

    /// Received a request from a request-response protocol.
    RequestIn {
        /// Identifier for this request. Must be passed back when calling
        /// [`Peers::respond_in_request`].
        request_id: InRequestId,
        /// Peer which sent the request.
        peer_id: PeerId,
        /// Identifier of the connection that has sent the request.
        connection_id: ConnectionId,
        /// Request-response protocol the request is about.
        protocol_index: usize,
        /// Payload of the request, opaque to this state machine.
        ///
        /// > **Note**: Keep in mind that this data is untrusted.
        request_payload: Vec<u8>,
    },

    /// A previously-emitted [`Event::RequestIn`] is now obsolete.
    ///
    /// The [`InRequestId`] is now considered dead, and calling [`Peers::respond_in_request`] is
    /// now invalid.
    RequestInCancel {
        /// Identifier for this request.
        id: InRequestId,
    },

    /// A peer would like to open a notifications substream with the local node, in order to
    /// send notifications.
    ///
    /// Only one inbound notifications substream can exist per peer and per protocol. Any
    /// additional one will be automatically refused.
    NotificationsInOpen {
        /// Identifier for this request. Must be passed back when calling
        /// [`Peers::in_notification_accept`] or [`Peers::in_notification_refuse`].
        id: SubstreamId,
        /// Peer which tries to open an inbound substream.
        peer_id: PeerId,
        /// Notifications protocol the substream is about.
        notifications_protocol_index: usize,
        /// Handshake of the request sent by the peer. Opaque to this state machine.
        ///
        /// > **Note**: Keep in mind that this data is untrusted.
        handshake: Vec<u8>,
    },

    /// A previously-emitted [`Event::NotificationsInOpen`] is now obsolete. The [`SubstreamId`]
    /// is no longer valid.
    NotificationsInOpenCancel {
        /// Identifier for this request.
        id: SubstreamId,
    },

    /// A handshaking outbound substream has been accepted by the remote.
    ///
    /// Will happen for combinations of [`PeerId`] and notification protocols that have been
    /// marked as desired. Can also happen for other combinations, if there were marked as desired
    /// in the past but no longer are.
    ///
    /// If `Ok`, it is now possible to send notifications on this substream.
    ///
    /// > **Note**: No event if generated when [`Peers::close_out_notification`] is called.
    NotificationsOutResult {
        /// Peer the substream is open with.
        peer_id: PeerId,
        /// Notifications protocol the substream is about.
        notifications_protocol_index: usize,
        /// If `Ok`, contains the handshake sent back by the remote. Its interpretation is out of
        /// scope of this module.
        /// If `Err`, the state machine will *not* automatically try to re-open a substream again.
        /// Use [`Peers::set_peer_notifications_out_desired`] with [`DesiredState::DesiredReset`]
        /// in order to try again.
        result: Result<Vec<u8>, NotificationsOutErr>,
    },

    /// A previously open outbound substream has been closed by the remote. Can only happen after
    /// a corresponding successful [`Event::NotificationsOutResult`] event has been emitted in the
    /// past.
    ///
    /// > **Note**: No event if generated when [`Peers::close_out_notification`] is called.
    NotificationsOutClose {
        /// Peer the substream is no longer open with.
        peer_id: PeerId,
        /// Notifications protocol the substream is about.
        notifications_protocol_index: usize,
    },

    /// Received a notification on a notifications substream of a connection.
    NotificationsIn {
        /// Peer that sent the notification.
        peer_id: PeerId,
        /// Notifications protocol the substream is about.
        notifications_protocol_index: usize,
        /// Payload of the notification. Opaque to this state machine.
        ///
        /// > **Note**: Keep in mind that this data is untrusted.
        notification: Vec<u8>,
    },

    /// Remote has closed a previously-open inbound notifications substream.
    NotificationsInClose {
        /// Peer the substream is no longer with.
        peer_id: PeerId,
        /// Notifications protocol the substream is about.
        notifications_protocol_index: usize,
        /// If `Ok`, the substream has been closed gracefully. If `Err`, a problem happened.
        outcome: Result<(), NotificationsInClosedErr>,
    },
}

/// See [`Event::StartShutdown`] and [`Event::Shutdown`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownPeer {
    /// Connection was fully established.
    Established {
        /// Identity of the peer on the other side of the connection.
        peer_id: PeerId,

        /// Number of other established not-shutting-down connections with the same peer remaining
        /// after the disconnection.
        num_healthy_peer_connections: u32,
    },

    /// Connection was still handshaking and was incoming.
    IngoingHandshake,

    /// Connection was still handshaking and was outgoing.
    OutgoingHandshake {
        /// Identity of the peer that was expected to be reached after the handshake.
        expected_peer_id: PeerId,
    },
}

/// Reason why a connection is shutting down. See [`Event::StartShutdown`].
#[derive(Debug, derive_more::Display)]
pub enum ShutdownCause {
    /// Problem on the connection level.
    #[display(fmt = "{}", _0)]
    Connection(collection::ShutdownCause),
    /// Remote hasn't responded in time to a ping.
    OutPingTimeout,
}

/// Error that can happen while processing an inbound substream.
#[derive(Debug, Clone, derive_more::Display)]
pub enum InboundError {
    /// Error at the connection level.
    Connection(collection::InboundError),
    /// Refused a notifications substream because we already have an existing substream of that
    /// protocol.
    DuplicateNotificationsSubstream {
        /// Notifications protocol the substream is about.
        notifications_protocol_index: usize,
    },
}

/// See [`Peers::set_peer_notifications_out_desired`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DesiredState {
    /// Substream is no longer desired. Close any existing substream.
    NotDesired,
    /// Substream is now desired. If the state was already "desired" and the peer has refused this
    /// substream in the past, do nothing.
    Desired,
    /// Substream is now desired. If the peer has refused this substream in the past, try to open
    /// one again.
    DesiredReset,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OpenOrPending {
    Open,
    Pending,
}

/// Error potentially returned by [`Peers::in_notification_accept`].
#[derive(Debug, derive_more::Display)]
pub enum InNotificationAcceptError {
    /// The request is now obsolete, either because the connection has been shut down or the
    /// remote has canceled their request.
    Obsolete,
}

/// Error potentially returned by [`Peers::queue_notification`].
#[derive(Debug, derive_more::Display)]
pub enum QueueNotificationError {
    /// Queue of notifications with that peer is full.
    QueueFull,
}
