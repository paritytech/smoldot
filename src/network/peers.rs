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
//! abstraction over the network based on network identities (i.e. [`PeerId`]s). One can set the
//! list of peers to be connected to and through which notification protocols, and the [`Peers`]
//! struct will try to open or re-open connections with these peers. Once connected, one can use
//! the [`Peers`] to send request or notifications with these peers.
//!
//! # Detailed usage
//!
//! The [`Peers`] struct contains six different collections:
//!
//! - A list of peers that are marked as "desired".
//! - A list of `(peer_id, notification_protocol)` tuples that are marked as "desired".
//! - A list of connections identified by [`ConnectionId`]s.
//! - A list of requests for inbound substreams, identified by a [`DesiredInNotificationId`].
//! When a peer desired to open a notification substream with the local node, a
//! [`DesiredInNotificationId`] is generated. The API user must answer by either accepting or
//! refusing the request. The requests can automatically become obsolete if the remote decides
//! to withdraw their request or the connection closes. A request becoming obsolete does *not*
//! invalidate its [`DesiredInNotificationId`].
//! - A list of requests for outbound substreams emitted by the local node, identified by a
//! [`DesiredOutNotificationId`]. Must be responded using [`Peers::open_out_notification`].
//! - A list of requests that have been received, identified by a [`RequestId`]. The API user
//! must answer by calling [`Peers::respond`]. Requests can automatically become obsolete if the
//! remote decides to withdraw their request or the connection closes. A request becoming obsolete
//! does *not* invalidate its [`RequestId`].
//!

use crate::libp2p::{self, PeerId};

use alloc::{
    collections::{btree_map, BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use core::{
    convert::TryFrom as _,
    iter,
    num::{NonZeroU32, NonZeroUsize},
    ops::{Add, Sub},
    task::Poll,
    time::Duration,
};
use futures::{
    lock::{Mutex, MutexGuard},
    prelude::*,
}; // TODO: no_std-ize
use rand::{Rng as _, SeedableRng as _};

/// Configuration for a [`Peers`].
pub struct Config {
    /// Seed for the randomness within the networking state machine.
    pub randomness_seed: [u8; 32],

    /// Capacity to initially reserve to the list of connections.
    pub connections_capacity: usize,

    /// Capacity to initially reserve to the list of peers.
    pub peers_capacity: usize,

    pub overlay_networks: Vec<libp2p::OverlayNetworkConfig>,

    pub request_response_protocols: Vec<libp2p::ConfigRequestResponse>,

    /// Name of the ping protocol on the network.
    pub ping_protocol: String,

    /// Key used for the encryption layer.
    /// This is a Noise static key, according to the Noise specification.
    /// Signed using the actual libp2p key.
    pub noise_key: libp2p::connection::NoiseKey,

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

    // TODO: don't use BTreeSet
    pub initial_desired_peers: BTreeSet<PeerId>,

    // TODO: don't use BTreeSet
    pub initial_desired_substreams: BTreeSet<(PeerId, usize)>,
}

pub use libp2p::ConnectionId;

pub struct Peers<TNow> {
    inner: libp2p::Network<usize, TNow>,

    guarded: Mutex<Guarded>,
}

impl<TNow> Peers<TNow>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Creates a new [`Peers`].
    pub fn new(config: Config) -> Self {
        let mut randomness = rand_chacha::ChaCha20Rng::from_seed(config.randomness_seed);

        let mut peer_indices = {
            hashbrown::HashMap::with_capacity_and_hasher(
                config.peers_capacity,
                ahash::RandomState::with_seeds(
                    randomness.sample(rand::distributions::Standard),
                    randomness.sample(rand::distributions::Standard),
                    randomness.sample(rand::distributions::Standard),
                    randomness.sample(rand::distributions::Standard),
                ),
            )
        };

        let mut peers = slab::Slab::with_capacity(config.peers_capacity);

        let mut peers_notifications_out = BTreeMap::new();

        for peer_id in config.initial_desired_peers {
            if let hashbrown::hash_map::Entry::Vacant(entry) = peer_indices.entry(peer_id) {
                let peer_index = peers.insert(Peer {
                    desired: true,
                    peer_id: entry.key().clone(),
                });

                entry.insert(peer_index);
            }
        }

        for (peer_id, notification_protocol) in config.initial_desired_substreams {
            let peer_index = match peer_indices.entry(peer_id) {
                hashbrown::hash_map::Entry::Occupied(entry) => *entry.into_mut(),
                hashbrown::hash_map::Entry::Vacant(entry) => {
                    let peer_index = peers.insert(Peer {
                        desired: true,
                        peer_id: entry.key().clone(),
                    });

                    *entry.insert(peer_index)
                }
            };

            peers_notifications_out
                .entry((peer_index, notification_protocol))
                .or_insert(NotificationsOutState::Desired);
        }

        let connections_peer_index = slab::Slab::with_capacity(config.connections_capacity);

        Peers {
            inner: libp2p::Network::new(libp2p::Config {
                capacity: config.connections_capacity,
                noise_key: config.noise_key,
                overlay_networks: config.overlay_networks,
                request_response_protocols: config.request_response_protocols,
                ping_protocol: config.ping_protocol,
                randomness_seed: randomness.sample(rand::distributions::Standard),
                pending_api_events_buffer_size: config.pending_api_events_buffer_size,
            }),
            guarded: Mutex::new(Guarded {
                to_process_pre_event: None,
                connections_peer_index,
                connections_by_peer: BTreeSet::new(),
                peer_indices,
                peers,
                peers_notifications_out,
                requests_in: slab::Slab::new(), // TODO: capacity?
                desired_in_notifications: slab::Slab::new(), // TODO: capacity?
                desired_out_notifications: slab::Slab::new(), // TODO: capacity?
            }),
        }
    }

    /// Returns the Noise key originalled passed as [`Config::noise_key`].
    pub fn noise_key(&self) -> &libp2p::connection::NoiseKey {
        self.inner.noise_key()
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
                    match guarded.to_process_pre_event.as_mut().unwrap() {
                        ToProcessPreEvent::StartOutSubstreamOpen {
                            peer_id,
                            connection_id,
                            notification_protocols_indices: notifications_protocol_indices,
                        } if !notifications_protocol_indices.is_empty() => {
                            let notifications_protocol_index =
                                notifications_protocol_indices.pop().unwrap();

                            let id = DesiredOutNotificationId(
                                guarded
                                    .desired_out_notifications
                                    .insert((*connection_id, notifications_protocol_index)),
                            );

                            return Event::DesiredOutNotification {
                                id,
                                peer_id: peer_id.clone(),
                                notifications_protocol_index,
                            };
                        }
                        ToProcessPreEvent::StartOutSubstreamOpen { .. } => {}
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
                    // TODO: compare with expected
                    let peer_index = guarded.peer_index_or_insert(&peer_id);
                    guarded.connections_by_peer.insert((peer_id.clone(), id));
                    guarded.connections_peer_index[user_data] = Some(peer_index);

                    let num_peer_connections = {
                        // TODO: cloning
                        let num = guarded
                            .connections_by_peer
                            .range(
                                (peer_id.clone(), libp2p::ConnectionId::min_value())
                                    ..=(peer_id.clone(), libp2p::ConnectionId::max_value()),
                            )
                            .count();
                        NonZeroU32::new(u32::try_from(num).unwrap()).unwrap()
                    };

                    if num_peer_connections.get() == 1 {
                        let notification_protocols_indices = guarded
                            .peers_notifications_out
                            .range(
                                (peer_index, usize::min_value())..=(peer_index, usize::max_value()),
                            )
                            .map(|((_, index), _)| *index)
                            .collect::<Vec<_>>();

                        debug_assert!(guarded.to_process_pre_event.is_none());
                        guarded.to_process_pre_event =
                            Some(ToProcessPreEvent::StartOutSubstreamOpen {
                                peer_id: peer_id.clone(),
                                connection_id: id,
                                notification_protocols_indices,
                            });
                    }

                    return Event::Connected {
                        num_peer_connections,
                        peer_id,
                    };
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
                } => {
                    let request_id = RequestId(guarded.requests_in.insert((id, substream_id)));
                    let peer_id = {
                        let peer_index = guarded.connections_peer_index[user_data].unwrap();
                        guarded.peers[peer_index].peer_id.clone()
                    };

                    return Event::RequestIn {
                        peer_id,
                        protocol_index,
                        request_id,
                        request_payload,
                    };
                }

                libp2p::Event::NotificationsOutAccept {
                    id,
                    notifications_protocol_index,
                    remote_handshake,
                    user_data,
                } => {
                    let peer_index = guarded.connections_peer_index[user_data].unwrap();
                    match guarded
                        .peers_notifications_out
                        .entry((peer_index, notifications_protocol_index))
                    {
                        btree_map::Entry::Vacant(_) => {
                            // User marked this substream as desired in the past, but no longer
                            // does.
                            todo!()
                        }
                        btree_map::Entry::Occupied(entry) => match entry.into_mut() {
                            st @ NotificationsOutState::Desired => {
                                *st = NotificationsOutState::DesiredOpen
                            }
                            NotificationsOutState::DesiredOpen => unreachable!(),
                            NotificationsOutState::DesiredRefused => unreachable!(),
                        },
                    }

                    return Event::NotificationsOutAccept {
                        peer_id: guarded.peers[peer_index].peer_id.clone(),
                        notifications_protocol_index,
                        remote_handshake,
                    };
                }

                libp2p::Event::NotificationsOutClose {
                    id,
                    notifications_protocol_index,
                    user_data,
                } => {
                    let peer_index = guarded.connections_peer_index[user_data].unwrap();
                    match guarded
                        .peers_notifications_out
                        .entry((peer_index, notifications_protocol_index))
                    {
                        btree_map::Entry::Vacant(_) => {}
                        btree_map::Entry::Occupied(entry) => match entry.into_mut() {
                            // TODO: not implemented
                            _ => {}
                        },
                    }

                    // TODO: report
                    /*return Event::NotificationsOutClose {
                        peer_id: guarded.peers[peer_index].peer_id.clone(),
                        notifications_protocol_index,
                    };*/
                }

                libp2p::Event::NotificationsInOpen {
                    id: connection_id,
                    notifications_protocol_index,
                    remote_handshake: handshake,
                    user_data,
                } => {
                    let desired_notif_id = DesiredInNotificationId(
                        guarded
                            .desired_in_notifications
                            .insert(Some((connection_id, notifications_protocol_index))),
                    );

                    let peer_id = {
                        let peer_index = guarded.connections_peer_index[user_data].unwrap();
                        guarded.peers[peer_index].peer_id.clone()
                    };

                    return Event::DesiredInNotification {
                        id: desired_notif_id,
                        peer_id,
                        notifications_protocol_index,
                        handshake,
                    };
                }

                libp2p::Event::NotificationsIn {
                    notifications_protocol_index,
                    notification,
                    user_data,
                    ..
                } => {
                    let peer_id = {
                        let peer_index = guarded.connections_peer_index[user_data].unwrap();
                        guarded.peers[peer_index].peer_id.clone()
                    };

                    return Event::NotificationsIn {
                        peer_id,
                        notifications_protocol_index,
                        notification,
                    };
                }

                libp2p::Event::NotificationsInClose {
                    notifications_protocol_index,
                    user_data,
                    ..
                } => {
                    // TODO: does this event also mean a NotificationsInOpen is no longer valid?
                    let peer_id = {
                        let peer_index = guarded.connections_peer_index[user_data].unwrap();
                        guarded.peers[peer_index].peer_id.clone()
                    };

                    // TODO: don't report back if there's still an in substream with the same proto

                    return Event::NotificationsInClose {
                        peer_id,
                        notifications_protocol_index,
                    };
                }
            }
        }
    }

    /// Inserts an incoming connection in the state machine.
    ///
    /// This connection hasn't finished handshaking and the [`PeerId`] of the remote isn't known
    /// yet.
    ///
    /// After this function has returned, you must process the connection with
    /// [`Peers::read_write`].
    #[must_use]
    pub async fn add_incoming_connection(&self) -> ConnectionId {
        // A slab entry is first reserved without being inserted, so that the state remains
        // consistent if the user cancels the returned future.
        let mut guarded = self.guarded.lock().await;
        let entry = guarded.connections_peer_index.vacant_entry();
        let connection_id = self.inner.insert(false, entry.key()).await;
        entry.insert(None);
        connection_id
    }

    /// Inserts an outgoing connection in the state machine.
    ///
    /// This connection hasn't finished handshaking, and the [`PeerId`] of the remote isn't known
    /// yet, but it is expected to be `unfulfilled_desired_peers`. After this function has been
    /// called, the provided `expected_peer_id` will no longer be part of the return value of
    /// [`Peers::unfulfilled_desired_peers`].
    ///
    /// After this function has returned, you must process the connection with
    /// [`Peers::read_write`].
    #[must_use]
    pub async fn add_outgoing_connection(&self, expected_peer_id: &PeerId) -> ConnectionId {
        // A slab entry is first reserved without being inserted, so that the state remains
        // consistent if the user cancels the returned future.
        let mut guarded = self.guarded.lock().await;
        let entry = guarded.connections_peer_index.vacant_entry();
        let connection_id = self.inner.insert(true, entry.key()).await;
        entry.insert(None);
        connection_id

        // TODO: finish
    }

    /// Returns the list of [`PeerId`]s that have been marked as desired, but that don't have any
    /// associated connection. An associated connection is either a fully established connection
    /// with that peer, or an outgoing connection that is still handshaking but expects to reach
    /// that peer.
    #[must_use]
    pub async fn unfulfilled_desired_peers(&self) -> impl Iterator<Item = PeerId> {
        let guarded = self.guarded.lock().await;

        // TODO: complexity of this method is too damn high

        let mut desired = guarded
            .peers
            .iter()
            .filter(|(_, p)| p.desired)
            .map(|(_, p)| p.peer_id.clone())
            .collect::<BTreeSet<_>>();

        for ((_, peer_index), state) in &guarded.peers_notifications_out {
            match state {
                NotificationsOutState::Desired => {}
                NotificationsOutState::DesiredOpen | NotificationsOutState::DesiredRefused => {
                    continue
                }
            };

            desired.insert(guarded.peers[*peer_index].peer_id.clone());
        }

        // TODO: unfinished, must remove the pending connections
        /*for _ in guarded.connections_by_peer.range(()) {

        }*/

        desired.into_iter()
    }

    /// Sets the "desired" flag of the given [`PeerId`].
    ///
    /// When a peer is marked as "desired" and there isn't any pending or established connection
    /// towards it, it is returned when calling [`Peers::unfulfilled_desired_peers`].
    pub async fn set_peer_desired(&self, peer_id: &PeerId, desired: bool) {
        let mut guarded = self.guarded.lock().await;
        let peer_index = guarded.peer_index_or_insert(peer_id);
        guarded.peers[peer_index].desired = desired;
    }

    /// Sets the given combinations of notification protocol and [`PeerId`] as "desired".
    ///
    /// When a peer is marked as "desired" and there isn't any pending or established connection
    /// towards it, it is returned when calling [`Peers::unfulfilled_desired_peers`].
    ///
    /// When a combination of network protocol and [`PeerId`] is marked as "desired", the state
    /// machine will try to maintain open an outbound substream. If the remote refuses the
    /// substream, it will be returned when calling [`Peers::refused_notifications_out`].
    pub async fn set_peer_notifications_out_desired(
        &self,
        peer_id: &PeerId,
        notification_protocols: impl Iterator<Item = usize>,
        new_desired_state: bool,
    ) {
        let mut guarded = self.guarded.lock().await;
        let peer_index = guarded.peer_index_or_insert(peer_id);
        for notification_protocol in notification_protocols {
            if new_desired_state {
                guarded
                    .peers_notifications_out
                    .entry((peer_index, notification_protocol))
                    .or_insert(NotificationsOutState::Desired);
                // TODO: create a new out desired notification thing
            } else {
                let removed = guarded
                    .peers_notifications_out
                    .remove(&(peer_index, notification_protocol));
                match removed {
                    Some(NotificationsOutState::Desired) => {}
                    Some(NotificationsOutState::DesiredOpen) => {
                        // TODO: must start closing it
                        todo!()
                    }
                    Some(NotificationsOutState::DesiredRefused) => {}
                    None => {}
                }
            }
        }
    }

    /// Returns the combinations of notification and [`PeerId`] that are marked as "desired", but
    /// where the remote has refused the request for a notifications substream.
    pub async fn refused_notifications_out(&self) -> impl Iterator<Item = (PeerId, usize)> {
        iter::empty() // TODO: /!\
    }

    /// Responds to an [`Event::DesiredInNotification`] by accepting the request for an inbound
    /// substream.
    ///
    /// If `Ok` is returned, the substream is now considered open. If `Err` is returned, then
    /// that substream request was obsolete and no substream has been opened.
    ///
    /// # Panic
    ///
    /// Panics if the [`DesiredInNotificationId`] is invalid. Note that these ids remain valid
    /// forever until [`Peers::in_notification_accept`] or [`Peers::in_notification_refuse`] is
    /// called.
    ///
    pub async fn in_notification_accept(
        &self,
        id: DesiredInNotificationId,
        handshake_back: Vec<u8>,
    ) -> Result<(), ()> {
        let mut guarded = self.guarded.lock().await;
        assert!(guarded.desired_in_notifications.contains(id.0));

        let (connection_id, overlay_network_index) =
            match guarded.desired_in_notifications.get(id.0).unwrap() {
                Some(v) => *v,
                None => {
                    guarded.desired_in_notifications.remove(id.0);
                    return Err(());
                }
            };

        self.inner
            .accept_notifications_in(connection_id, overlay_network_index, handshake_back)
            .await;

        guarded.desired_in_notifications.remove(id.0);
        Ok(())
    }

    /// Responds to an [`Event::DesiredInNotification`] by refusing the request for an inbound
    /// substream.
    ///
    /// # Panic
    ///
    /// Panics if the [`DesiredInNotificationId`] is invalid. Note that these ids remain valid
    /// forever until [`Peers::in_notification_accept`] or [`Peers::in_notification_refuse`] is
    /// called.
    ///
    pub async fn in_notification_refuse(&self, id: DesiredInNotificationId) {
        let mut guarded = self.guarded.lock().await;
        assert!(guarded.desired_in_notifications.contains(id.0));
        guarded.desired_in_notifications.remove(id.0);

        todo!()
    }

    /// Responds to an [`Event::DesiredOutNotification`] by indicating the handshake to send to
    /// th remote.
    ///
    /// # Panic
    ///
    /// Panics if the [`DesiredOutNotificationId`] is invalid. Note that these ids remain valid
    /// forever until [`Peers::open_out_notification`] is called.
    ///
    pub async fn open_out_notification(
        &self,
        id: DesiredOutNotificationId,
        now: TNow,
        handshake: Vec<u8>,
    ) {
        let mut guarded = self.guarded.lock().await;

        // TODO: rename overlay network index
        let (connection_id, overlay_network_index) =
            *guarded.desired_out_notifications.get(id.0).unwrap();

        self.inner
            .open_notifications_substream(connection_id, overlay_network_index, now, handshake)
            .await;

        // Only remove from the list at the end, in case the user cancels the future returned by
        // `open_notifications_substream`.
        guarded.desired_out_notifications.remove(id.0);
    }

    // TODO: document
    pub async fn queue_notification(
        &self,
        target: &PeerId,
        notifications_protocol_index: usize,
        notification: impl Into<Vec<u8>>,
    ) -> Result<(), QueueNotificationError> {
        let target = {
            let guarded = self.guarded.lock().await;
            match self.connection_id_for_peer(&guarded, target).await {
                Some(id) => id,
                None => return Err(QueueNotificationError::NotConnected),
            }
        };

        let result = self
            .inner
            .queue_notification(target, notifications_protocol_index, notification)
            .await;

        match result {
            Ok(()) => Ok(()),
            Err(libp2p::QueueNotificationError::InvalidConnection) => {
                Err(QueueNotificationError::NotConnected)
            } // TODO: better handling of this situation?
            Err(libp2p::QueueNotificationError::NoSubstream) => {
                Err(QueueNotificationError::NoSubstream)
            } // TODO: better handling of this situation?
            Err(libp2p::QueueNotificationError::QueueFull) => {
                Err(QueueNotificationError::QueueFull)
            }
        }
    }

    /// Equivalent to calling [`Peers::queue_notification`] for all peers an outbound
    /// notifications substream is open with.
    ///
    /// Individual errors that would have occured when calling [`Peers::queue_notification`] are
    /// silently discarded.
    // TODO: consider returning the peers we successfully sent to
    pub async fn broadcast_notification(
        &self,
        notifications_protocol_index: usize,
        notification: impl Into<Vec<u8>>,
    ) {
        //todo!()
    }

    /// Sends a request to the given peer, and waits for a response.
    ///
    /// This consists in:
    ///
    /// - Opening a substream on an established connection with the target.
    /// - Negotiating the requested protocol (`protocol_index`) on this substream using the
    ///   *multistream-select* protocol.
    /// - Sending the request (`request_data` parameter), prefixed with its length.
    /// - Waiting for the response (prefixed with its length), which is then returned.
    ///
    /// An error happens if there is no suitable connection for that request, if the connection
    /// closes while the request is in progress, if the request or response doesn't respect
    /// the protocol limits (see [`ConfigRequestResponse`]), or if the remote takes too much time
    /// to answer.
    ///
    /// As the API of this module is inherently subject to race conditions, it is never possible
    /// to guarantee that this function will succeed. [`RequestError::ConnectionClosed`] should
    /// be handled by retrying the same request again.
    ///
    /// > **Note**: This function doesn't return before the remote has answered. It is strongly
    /// >           recommended to await the returned `Future` in the background, and not block
    /// >           any important task on this.
    ///
    /// # Panic
    ///
    /// Panics if `protocol_index` isn't a valid index in [`Config::request_response_protocols`].
    ///
    pub async fn request(
        &self,
        now: TNow,
        target: &PeerId,
        protocol_index: usize,
        request_data: Vec<u8>,
        // TODO: bad error type
    ) -> Result<Vec<u8>, libp2p::RequestError> {
        let target = {
            let guarded = self.guarded.lock().await;
            match self.connection_id_for_peer(&guarded, target).await {
                Some(id) => id,
                None => return Err(libp2p::RequestError::InvalidConnection), // TODO: no, change error type
            }
        };

        self.inner
            .request(now, target, protocol_index, request_data)
            .await
    }

    /// Responds to a previously-emitted [`Event::RequestIn`].
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid. Note that these ids remain valid forever until
    /// [`Peers::respond`] is called.
    ///
    pub async fn respond(&self, id: RequestId, response: Result<Vec<u8>, ()>) {
        let mut guarded = self.guarded.lock().await;

        debug_assert!(guarded.requests_in.contains(id.0));

        // First copy the content of `guarded.requests_in`, so that the state stays consistent if
        // the user cancels the future of `respond_in_request`.
        let (connection_id, substream_id) = *guarded.requests_in.get(id.0).unwrap();

        self.inner
            .respond_in_request(connection_id, substream_id, response)
            .await;

        guarded.requests_in.remove(id.0);
    }

    ///
    /// # Panic
    ///
    /// Panics if `connection_id` isn't a valid connection.
    ///
    // TODO: document
    pub async fn read_write<'a>(
        &self,
        connection_id: ConnectionId,
        now: TNow,
        incoming_buffer: Option<&[u8]>,
        outgoing_buffer: (&'a mut [u8], &'a mut [u8]),
    ) -> Result<libp2p::ReadWrite<TNow>, libp2p::ConnectionError> {
        self.inner
            .read_write(connection_id, now, incoming_buffer, outgoing_buffer)
            .await
    }

    /// Returns an iterator to the list of [`PeerId`]s that we have an established connection
    /// with.
    pub async fn peers_list(&self) -> impl Iterator<Item = PeerId> {
        // TODO: not correct lol, as peers includes peers without any connection
        let guarded = self.guarded.lock().await;
        guarded
            .peers
            .iter()
            .map(|(_, p)| p.peer_id.clone())
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Picks the connection to use to send requests or notifications to the given peer.
    async fn connection_id_for_peer(
        &self,
        guarded: &MutexGuard<'_, Guarded>,
        target: &PeerId,
    ) -> Option<libp2p::ConnectionId> {
        // TODO: stupid cloning
        for (_, connection_id) in guarded.connections_by_peer.range(
            (target.clone(), libp2p::ConnectionId::min_value())
                ..=(target.clone(), libp2p::ConnectionId::max_value()),
        ) {
            return Some(*connection_id);
        }

        None
    }
}

/// See [`Event::DesiredInNotification`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DesiredInNotificationId(usize);

/// See [`Event::DesiredOutNotification`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DesiredOutNotificationId(usize);

/// See [`Event::RequestIn`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(usize);

/// Event happening over the network. See [`Peers::next_event`].
#[derive(Debug)]
pub enum Event {
    /// Established a new connection to the given peer.
    Connected {
        /// Identity of the peer on the other side of the connection.
        peer_id: PeerId,

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

        /// `true` if the peer is marked as desired. If this is `true` and `num_peer_connections`
        /// is `0`, then calling [`Peers::unfulfilled_desired_peers`] will now return this peer.
        ///
        /// > **Note**: Keep in mind that everything is subject to race conditions. For example,
        /// >           a parallel thread might at the same time remove the "desired" marker of
        /// >           this peer, or an incoming connection might at the same time finish
        /// >           negotiating a new connection with this peer. When sharing the [`Peers`]
        /// >           between multiple threads, there is no guarantee that
        /// >           [`Peers::unfulfilled_desired_peers`] will in fact return this peer.
        peer_is_desired: bool,

        /// Number of other established connections with the same peer remaining after the
        /// disconnection.
        num_peer_connections: u32,
    },

    /// Received a request from a request-response protocol.
    RequestIn {
        /// Identifier for this request. Must be passed back when calling [`Peers::respond`].
        request_id: RequestId,
        /// Peer which sent the request.
        peer_id: PeerId,
        /// Request-response protocol the request is about.
        protocol_index: usize,
        /// Payload of the request, opaque to this state machine.
        ///
        /// > **Note**: Keep in mind that this data is untrusted.
        request_payload: Vec<u8>,
    },

    /// A previously-emitted [`RequestIn`] is now obsolete. This event is for informative purpose
    /// and does **not** invalidate the [`RequestIn`].
    RequestInCancel {
        /// Identifier for this request.
        id: RequestId,
    },

    /// A peer would like to open a notifications substream with the local node, in order to
    /// send notifications.
    DesiredInNotification {
        /// Identifier for this request. Must be passed back when calling
        /// [`Peers::in_notification_accept`] or [`Peers::in_notification_refuse`].
        id: DesiredInNotificationId,
        /// Peer which tries to open an inbound substream.
        peer_id: PeerId,
        /// Notifications protocol the substream is about.
        notifications_protocol_index: usize,
        /// Handshake of the request sent by the peer. Opaque to this state machine.
        ///
        /// > **Note**: Keep in mind that this data is untrusted.
        handshake: Vec<u8>,
    },

    /// A previously-emitted [`DesiredInNotificationId`] is now obsolete. This event is for
    /// informative purpose and does **not** invalidate the [`DesiredInNotificationId`]. Use
    /// [`Peers::in_notification_refuse`] if you no longer care about this request.
    DesiredInNotificationCancel {
        /// Identifier for this request.
        id: DesiredInNotificationId,
    },

    /// Local node would like to open a notifications substream with the given peer. This can only
    /// happen if the combination of peer and notification protocol was marked as desired.
    DesiredOutNotification {
        /// Identifier for this request. Must be passed back when calling
        /// [`Peers::open_out_notification`].
        id: DesiredOutNotificationId,
        /// Peer which tries to open an outbound substream.
        peer_id: PeerId,
        /// Notifications protocol the substream is about.
        notifications_protocol_index: usize,
    },

    /// A handshaking outbound substream has been accepted by the remote.
    ///
    /// Can only happen for combinations of [`PeerId`] and notification protocols that have been
    /// marked as desired.
    NotificationsOutAccept {
        /// Peer the substream is open with.
        peer_id: PeerId,
        /// Notifications protocol the substream is about.
        notifications_protocol_index: usize,
        /// Handshake sent in return by the remote.
        remote_handshake: Vec<u8>,
    },

    /// A previously open outbound substream has been closed by the remote. Can only happen after
    /// a corresponding [`Event::NotificationsOutAccept`] event has been emitted in the past.
    ///
    /// This combination of [`PeerId`] and notification protocol will now be returned when calling
    /// [`Peers::refused_notifications_out`].
    NotificationsOutClose {
        /// Peer the subtream is no longer open with.
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

    /// List of all peer identities known to the state machine.
    // TODO: never cleaned up
    peers: slab::Slab<Peer>,

    /// For each known peer, the corresponding index within [`Guarded::peers`].
    // TODO: never cleaned up
    peer_indices: hashbrown::HashMap<PeerId, usize, ahash::RandomState>,

    /// Each connection stored in [`Peers::inner`] has a `usize` user data that is an index within
    /// this slab. The items are indices within [`Guarded::peers`], or `None` if the handshake of
    /// the connection isn't finished yet.
    connections_peer_index: slab::Slab<Option<usize>>,

    connections_by_peer: BTreeSet<(PeerId, libp2p::ConnectionId)>,

    /// Keys are combinations of `(peer_index, notifications_protocol_index)`. Values are the
    /// state of the corresponding outbound notifications substream.
    peers_notifications_out: BTreeMap<(usize, usize), NotificationsOutState>,

    /// Each [`DesiredInNotificationId`] points to this slab.
    // TODO: doc
    desired_in_notifications: slab::Slab<Option<(libp2p::ConnectionId, usize)>>,

    /// Each [`DesiredOutNotificationId`] points to this slab.
    // TODO: doc
    desired_out_notifications: slab::Slab<(libp2p::ConnectionId, usize)>,

    /// Each [`RequestIn`] points to this slab. Contains the arguments to pass when calling
    /// [`libp2p::Network::respond_in_request`].
    requests_in: slab::Slab<(ConnectionId, libp2p::connection::established::SubstreamId)>,
}

impl Guarded {
    fn peer_index_or_insert(&mut self, peer_id: &PeerId) -> usize {
        if let Some(idx) = self.peer_indices.get(peer_id) {
            return *idx;
        }

        todo!()
    }
}

enum NotificationsOutState {
    Desired,
    DesiredOpen,
    DesiredRefused,
}

/// See [`Guarded::to_process_pre_event`]
enum ToProcessPreEvent {
    StartOutSubstreamOpen {
        peer_id: PeerId,
        connection_id: libp2p::ConnectionId,
        notification_protocols_indices: Vec<usize>,
    },
}

struct Peer {
    peer_id: PeerId,
    desired: bool,
}
