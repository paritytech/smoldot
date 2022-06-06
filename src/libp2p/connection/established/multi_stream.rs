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

// TODO: needs docs

use super::{
    super::super::read_write::ReadWrite, substream, Config, ConfigNotifications,
    ConfigRequestResponse, ConfigRequestResponseIn, Event, SubstreamId, SubstreamIdInner,
};
use crate::util;

use alloc::{boxed::Box, collections::VecDeque, string::String, vec, vec::Vec};
use core::{
    fmt,
    hash::Hash,
    iter,
    ops::{Add, Sub},
    time::Duration,
};
use rand::{Rng as _, SeedableRng as _};

/// State machine of a fully-established connection where substreams are handled externally.
pub struct MultiStream<TNow, TSubId, TRqUd, TNotifUd> {
    /// Events that should be yielded from [`MultiStream::read_write`] as soon as possible.
    // TODO: is this necessary?
    pending_events: VecDeque<Event<TRqUd, TNotifUd>>,

    /// List of all open substreams, both inbound and outbound.
    ///
    /// There are two substreams namespaces: "out substreams", used for API purposes when it comes
    /// to notifications and requests, and "in substreams", used for API purposes when it comes to
    /// raw data sent/received on a substream. When the user for example resets an "in substream",
    /// the "out substream" remains valid.
    in_substreams: hashbrown::HashMap<
        TSubId,
        (substream::Substream<TNow, TRqUd, TNotifUd>, u32),
        util::SipHasherBuild,
    >,

    out_in_substreams_map: hashbrown::HashMap<u32, TSubId, fnv::FnvBuildHasher>,

    next_out_substream_id: u32,

    /// List of outgoing substreams that aren't opened yet.
    ///
    /// Everytime an outgoing substream is opened, an item is pulled from this list.
    ///
    /// Does not include the ping substream.
    desired_out_substreams: VecDeque<(substream::Substream<TNow, TRqUd, TNotifUd>, u32)>,

    /// Substream used for outgoing pings.
    ///
    /// Initially contains `None` as the substream for pings isn't opened yet.
    ///
    /// Because of the API of [`substream::Substream`] concerning pings, there is no need to
    /// handle situations where the substream fails to negotiate, as this is handled by making
    /// outgoing pings error. This substream is therefore constant.
    ///
    /// It is possible, however, that the remote resets the ping substream. In other words, this
    /// substream might not be found in [`Inner::yamux`]. When that happens, all outgoing pings
    /// are immediately considered as failed.
    ping_substream: Option<TSubId>,
    /// When to start the next ping attempt.
    next_ping: TNow,
    /// Source of randomness to generate ping payloads.
    ///
    /// Note that we use ChaCha20 because the rest of the code base also uses ChaCha20. This avoids
    /// unnecessary code being included in the binary and reduces the binary size.
    ping_payload_randomness: rand_chacha::ChaCha20Rng,

    /// See [`Config::request_protocols`].
    request_protocols: Vec<ConfigRequestResponse>,
    /// See [`Config::notifications_protocols`].
    notifications_protocols: Vec<ConfigNotifications>,
    /// See [`Config::ping_protocol`].
    ping_protocol: String,
    /// See [`Config::ping_interval`].
    ping_interval: Duration,
    /// See [`Config::ping_timeout`].
    ping_timeout: Duration,

    /// Buffer used for intermediary data. When it is necessary, data is first copied here before
    /// being turned into a `Vec`.
    ///
    /// While in theory this intermediary buffer could be shared between multiple different
    /// connections, since data present in this buffer isn't always zero-ed, it could be possible
    /// for a bug to cause data destined for connection A to be sent to connection B. Sharing this
    /// buffer is too dangerous.
    // TODO: remove; needs a lot of refactoring of noise and yamux
    intermediary_buffer: Box<[u8]>,
}

impl<TNow, TSubId, TRqUd, TNotifUd> MultiStream<TNow, TSubId, TRqUd, TNotifUd>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
    TSubId: Clone + PartialEq + Eq + Hash,
{
    /// Creates a new connection from the given configuration.
    pub fn new(self, config: Config<TNow>) -> MultiStream<TNow, TSubId, TRqUd, TNotifUd> {
        // TODO: check conflicts between protocol names?

        let num_expected_substreams =
            config.request_protocols.len() + config.notifications_protocols.len() * 2 + 1;

        let mut randomness = rand_chacha::ChaCha20Rng::from_seed(config.randomness_seed);

        MultiStream {
            pending_events: Default::default(),
            in_substreams: hashbrown::HashMap::with_capacity_and_hasher(
                num_expected_substreams,
                util::SipHasherBuild::new(randomness.sample(rand::distributions::Standard)),
            ),
            out_in_substreams_map: hashbrown::HashMap::with_capacity_and_hasher(
                num_expected_substreams,
                Default::default(),
            ),
            next_out_substream_id: 0,
            desired_out_substreams: VecDeque::with_capacity(num_expected_substreams),
            ping_substream: None,
            next_ping: config.first_out_ping,
            ping_payload_randomness: randomness,
            request_protocols: config.request_protocols,
            notifications_protocols: config.notifications_protocols,
            ping_protocol: config.ping_protocol,
            ping_interval: config.ping_interval,
            ping_timeout: config.ping_timeout,
            intermediary_buffer: vec![0u8; 2048].into_boxed_slice(),
        }
    }

    /// Returns the number of new outbound substreams that the state machine would like to see
    /// opened.
    ///
    /// This value doesn't change automatically over time but only after a call to
    /// [`MultiStream::substream_read_write`], [`MultiStream::inject_coordinator_message`],
    /// [`MultiStream::add_substream`], or [`MultiStream::reset_substream`].
    ///
    /// Note that the user is expected to track the number of substreams that are currently being
    /// opened. For example, if this function returns 2 and there are already 2 substreams
    /// currently being opened, then there is no need to open any additional one.
    pub fn desired_outbound_substreams(&self) -> u32 {
        u32::try_from(self.desired_out_substreams.len())
            .unwrap_or(u32::max_value())
            .saturating_add(if self.ping_substream.is_none() { 1 } else { 0 })
    }

    /// Notifies the state machine that a new substream has been opened.
    ///
    /// `inbound` indicates whether the substream has been opened by the remote (`true`) or
    /// locally (`false`).
    ///
    /// If `inbound` is `false`, then the value returned by
    /// [`MultiStream::desired_outbound_substreams`] will decrease by one.
    ///
    /// # Panic
    ///
    /// Panics if there already exists a substream with an identical identifier.
    ///
    pub fn add_substream(&mut self, id: TSubId, inbound: bool) {
        let (substream, out_substream_id) = if inbound {
            let out_substream_id = self.next_out_substream_id;
            self.next_out_substream_id += 1;

            let supported_protocols = self
                .request_protocols
                .iter()
                .filter(|p| p.inbound_allowed)
                .map(|p| p.name.clone())
                .chain(self.notifications_protocols.iter().map(|p| p.name.clone()))
                .chain(iter::once(self.ping_protocol.clone()))
                .collect::<Vec<_>>();

            (
                substream::Substream::ingoing(supported_protocols),
                out_substream_id,
            )
        } else if self.ping_substream.is_none() {
            let out_substream_id = self.next_out_substream_id;
            self.next_out_substream_id += 1;

            self.ping_substream = Some(id.clone());

            (
                substream::Substream::ping_out(self.ping_protocol.clone()),
                out_substream_id,
            )
        } else if let Some(desired) = self.desired_out_substreams.pop_front() {
            desired
        } else {
            // TODO: reset the new substream
            todo!()
        };

        let previous_value = self.in_substreams.insert(id, (substream, out_substream_id));
        if previous_value.is_some() {
            // There is already a substream with that identifier. This is forbidden by the API of
            // this function.
            panic!()
        }
    }

    /// Returns a list of substreams that the state machine would like to see reset. The user is
    /// encouraged to call [`MultiStream::substream_read_write`] with this list of
    /// substream.
    ///
    /// This value doesn't change automatically over time but only after a call to
    /// [`MultiStream::substream_read_write`], [`MultiStream::inject_coordinator_message`],
    /// [`MultiStream::add_substream`], or [`MultiStream::reset_substream`].
    ///
    /// > **Note**: An example situation is: a notification is queued, which leads to a message
    /// >           being sent to a connection task, which, once injected, leads to a notifications
    /// >           substream being "ready" because it needs to send more data.
    pub fn ready_substreams(&self) -> impl Iterator<Item = &TSubId> {
        iter::empty() // TODO:
    }

    /// Immediately destroys the substream with the given identifier.
    ///
    /// The given identifier is now considered invalid by the state machine.
    ///
    /// # Panic
    ///
    /// Panics if there is no substream with that identifier.
    ///
    pub fn reset_substream(&mut self, substream_id: &TSubId) {
        let (substream, out_substream_id) = self.in_substreams.remove(substream_id).unwrap();

        if Some(substream_id) == self.ping_substream.as_ref() {
            self.ping_substream = None;
        }

        let maybe_event = substream.reset();
        if let Some(event) = maybe_event {
            self.on_substream_event(out_substream_id, event);
        }
    }

    /// Reads/writes data on the substream.
    ///
    /// If the method returns `true`, then the substream is now considered dead according to the
    /// state machine and its identifier is now invalid. If the reading or writing side of the
    /// substream was still open, then the user should reset that substream.
    ///
    /// # Panic
    ///
    /// Panics if there is no substream with that identifier.
    ///
    pub fn substream_read_write(
        &mut self,
        substream_id: &TSubId,
        read_write: &'_ mut ReadWrite<'_, TNow>,
    ) -> bool {
        loop {
            // TODO: not great to remove then insert back the substream
            let (substream_id, (mut substream, out_substream_id)) =
                self.in_substreams.remove_entry(substream_id).unwrap();

            // Reading/writing the ping substream is used to queue new outgoing pings.
            if Some(&substream_id) == self.ping_substream.as_ref() {
                if read_write.now >= self.next_ping {
                    let payload = self
                        .ping_payload_randomness
                        .sample(rand::distributions::Standard);
                    substream.queue_ping(&payload, read_write.now.clone() + self.ping_timeout);
                    self.next_ping = read_write.now.clone() + self.ping_interval;
                }

                read_write.wake_up_after(&self.next_ping);
            }

            let (mut substream_update, event) = substream.read_write(read_write);

            match (event, substream_update.as_mut()) {
                (None, _) => {}
                (Some(substream::Event::InboundNegotiated(protocol)), Some(substream)) => {
                    if protocol == self.ping_protocol {
                        substream.set_inbound_ty(substream::InboundTy::Ping);
                    } else if let Some(protocol_index) = self
                        .request_protocols
                        .iter()
                        .position(|p| p.name == protocol)
                    {
                        substream.set_inbound_ty(substream::InboundTy::Request {
                            protocol_index,
                            request_max_size: if let ConfigRequestResponseIn::Payload { max_size } =
                                self.request_protocols[protocol_index].inbound_config
                            {
                                Some(max_size)
                            } else {
                                None
                            },
                        });
                    } else if let Some(protocol_index) = self
                        .notifications_protocols
                        .iter()
                        .position(|p| p.name == protocol)
                    {
                        substream.set_inbound_ty(substream::InboundTy::Notifications {
                            protocol_index,
                            max_handshake_size: self.notifications_protocols[protocol_index]
                                .max_handshake_size,
                        });
                    } else {
                        unreachable!();
                    }

                    // TODO: a bit crappy to put this insert here; DRY
                    self.in_substreams
                        .insert(substream_id, (substream_update.unwrap(), out_substream_id));
                    continue;
                }
                (Some(substream::Event::InboundNegotiated(_)), None) => {}
                (Some(other), _) => self.on_substream_event(out_substream_id, other),
            }

            break if let Some(substream_update) = substream_update {
                self.in_substreams
                    .insert(substream_id, (substream_update, out_substream_id));
                false
            } else {
                if Some(&substream_id) == self.ping_substream.as_ref() {
                    self.ping_substream = None;
                }
                true
            };
        }
    }

    /// Turns an event from the [`substream`] module into an [`Event`] and adds it to the queue.
    ///
    /// # Panics
    ///
    /// Intentionally panics on [`substream::Event::InboundNegotiated`]. Please handle this
    /// variant separately.
    ///
    fn on_substream_event(&mut self, substream_id: u32, event: substream::Event<TRqUd, TNotifUd>) {
        self.pending_events.push_back(match event {
            substream::Event::InboundNegotiated(_) => panic!(),
            substream::Event::InboundError(error) => Event::InboundError(error),
            substream::Event::RequestIn {
                protocol_index,
                request,
            } => Event::RequestIn {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                protocol_index,
                request,
            },
            substream::Event::Response {
                response,
                user_data,
            } => Event::Response {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                response,
                user_data,
            },
            substream::Event::NotificationsInOpen {
                protocol_index,
                handshake,
            } => Event::NotificationsInOpen {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                protocol_index,
                handshake,
            },
            substream::Event::NotificationsInOpenCancel => Event::NotificationsInOpenCancel {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
            },
            substream::Event::NotificationIn { notification } => Event::NotificationIn {
                notification,
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
            },
            substream::Event::NotificationsInClose { outcome } => Event::NotificationsInClose {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                outcome,
            },
            substream::Event::NotificationsOutResult { result } => Event::NotificationsOutResult {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                result,
            },
            substream::Event::NotificationsOutCloseDemanded => {
                Event::NotificationsOutCloseDemanded {
                    id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                }
            }
            substream::Event::NotificationsOutReset { user_data } => Event::NotificationsOutReset {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                user_data,
            },
            substream::Event::PingOutSuccess => Event::PingOutSuccess,
            substream::Event::PingOutError { .. } => {
                // Because ping events are automatically generated by the external API without any
                // guarantee, it is safe to merge multiple failed pings into one.
                Event::PingOutFailed
            }
        });
    }

    /// Sends a request to the remote.
    ///
    /// Must pass the index of the protocol within [`Config::request_protocols`].
    ///
    /// This method only inserts the request into the connection object. Use
    /// [`MultiStream::read_write`] in order to actually send out the request.
    ///
    /// Assuming that the remote is using the same implementation, an [`Event::RequestIn`] will
    /// be generated on its side.
    ///
    /// After the remote has sent back a response, an [`Event::Response`] event will be generated
    /// locally. The `user_data` parameter will be passed back.
    ///
    /// The timeout is the time between the moment the substream is opened and the moment the
    /// response is sent back. If the emitter doesn't send the request or if the receiver doesn't
    /// answer during this time window, the request is considered failed.
    pub fn add_request(
        &mut self,
        protocol_index: usize,
        request: Vec<u8>,
        timeout: TNow,
        user_data: TRqUd,
    ) -> SubstreamId {
        let has_length_prefix = match self.request_protocols[protocol_index].inbound_config {
            ConfigRequestResponseIn::Payload { max_size } => {
                // TODO: turn this assert into something that can't panic?
                assert!(request.len() <= max_size);
                true
            }
            ConfigRequestResponseIn::Empty => {
                // TODO: turn this assert into something that can't panic?
                assert!(request.is_empty());
                false
            }
        };

        let substream_id = self.next_out_substream_id;
        self.next_out_substream_id += 1;

        self.desired_out_substreams.push_back((
            substream::Substream::request_out(
                self.request_protocols[protocol_index].name.clone(), // TODO: clone :-/
                timeout,
                if has_length_prefix {
                    Some(request)
                } else {
                    None
                },
                self.request_protocols[protocol_index].max_response_size,
                user_data,
            ),
            substream_id,
        ));

        // TODO: ? do this? substream.reserve_window(128 * 1024 * 1024 + 128); // TODO: proper max size

        SubstreamId(SubstreamIdInner::MultiStream(substream_id))
    }

    /// Returns the user data associated to a notifications substream.
    ///
    /// Returns `None` if the substream doesn't exist or isn't a notifications substream.
    pub fn notifications_substream_user_data_mut(
        &mut self,
        id: SubstreamId,
    ) -> Option<&mut TNotifUd> {
        let id = match id.0 {
            SubstreamIdInner::MultiStream(id) => id,
            _ => return None,
        };

        let inner_substream_id = self.out_in_substreams_map.get(&id).unwrap();

        self.in_substreams
            .get_mut(inner_substream_id)
            .unwrap()
            .0
            .notifications_substream_user_data_mut()
    }

    /// Opens a outgoing substream with the given protocol, destined for a stream of
    /// notifications.
    ///
    /// Must pass the index of the protocol within [`Config::notifications_protocols`].
    ///
    /// The remote must first accept (or reject) the substream before notifications can be sent
    /// on it.
    ///
    /// This method only inserts the opening handshake into the connection object. Use
    /// [`MultiStream::read_write`] in order to actually send out the request.
    ///
    /// Assuming that the remote is using the same implementation, an
    /// [`Event::NotificationsInOpen`] will be generated on its side.
    ///
    pub fn open_notifications_substream(
        &mut self,
        now: TNow,
        protocol_index: usize,
        handshake: Vec<u8>,
        user_data: TNotifUd,
    ) -> SubstreamId {
        let max_handshake_size = self.notifications_protocols[protocol_index].max_handshake_size;

        // TODO: turn this assert into something that can't panic?
        assert!(handshake.len() <= max_handshake_size);

        let timeout = now + Duration::from_secs(20); // TODO:

        let substream_id = self.next_out_substream_id;
        self.next_out_substream_id += 1;

        self.desired_out_substreams.push_back((
            substream::Substream::notifications_out(
                timeout,
                self.notifications_protocols[protocol_index].name.clone(), // TODO: clone :-/,
                handshake,
                max_handshake_size,
                user_data,
            ),
            substream_id,
        ));

        SubstreamId(SubstreamIdInner::MultiStream(substream_id))
    }

    /// Accepts an inbound notifications protocol. Must be called in response to a
    /// [`Event::NotificationsInOpen`].
    ///
    /// # Panic
    ///
    /// Panics if the substream id is not valid or the substream is of the wrong type.
    ///
    pub fn accept_in_notifications_substream(
        &mut self,
        substream_id: SubstreamId,
        handshake: Vec<u8>,
        user_data: TNotifUd,
    ) {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::MultiStream(id) => id,
            _ => panic!(),
        };

        let inner_substream_id = self.out_in_substreams_map.get(&substream_id).unwrap();

        let max_notification_size = 16 * 1024 * 1024; // TODO: hack
                                                      // TODO: self.notifications_protocols[protocol_index].max_notification_size;
        self.in_substreams
            .get_mut(inner_substream_id)
            .unwrap()
            .0
            .accept_in_notifications_substream(handshake, max_notification_size, user_data);
    }

    /// Rejects an inbound notifications protocol. Must be called in response to a
    /// [`Event::NotificationsInOpen`].
    ///
    /// # Panic
    ///
    /// Panics if the substream id is not valid or the substream is of the wrong type.
    ///
    pub fn reject_in_notifications_substream(&mut self, substream_id: SubstreamId) {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::MultiStream(id) => id,
            _ => panic!(),
        };

        // TODO: can panic if pending event hasn't been processed
        let inner_substream_id = self.out_in_substreams_map.get(&substream_id).unwrap();

        self.in_substreams
            .get_mut(inner_substream_id)
            .unwrap()
            .0
            .reject_in_notifications_substream();
    }

    /// Queues a notification to be written out on the given substream.
    ///
    /// # About back-pressure
    ///
    /// This method unconditionally queues up data. You must be aware that the remote, however,
    /// can decide to delay indefinitely the sending of that data, which can potentially lead to
    /// an unbounded increase in memory.
    ///
    /// As such, you are encouraged to call this method only if the amount of queued data (as
    /// determined by calling [`MultiStream::notification_substream_queued_bytes`]) is below a
    /// certain threshold. If above, the notification should be silently discarded.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to a notifications substream, or if the
    /// notifications substream isn't in the appropriate state.
    ///
    pub fn write_notification_unbounded(
        &mut self,
        substream_id: SubstreamId,
        notification: Vec<u8>,
    ) {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::MultiStream(id) => id,
            _ => panic!(),
        };

        let inner_substream_id = self.out_in_substreams_map.get(&substream_id).unwrap();

        self.in_substreams
            .get_mut(inner_substream_id)
            .unwrap()
            .0
            .write_notification_unbounded(notification);
    }

    /// Returns the number of bytes waiting to be sent out on that substream.
    ///
    /// See the documentation of [`MultiStream::write_notification_unbounded`] for context.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to a notifications substream, or if the
    /// notifications substream isn't in the appropriate state.
    ///
    pub fn notification_substream_queued_bytes(&self, substream_id: SubstreamId) -> usize {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::MultiStream(id) => id,
            _ => panic!(),
        };

        let inner_substream_id = self.out_in_substreams_map.get(&substream_id).unwrap();

        self.in_substreams
            .get(inner_substream_id)
            .unwrap()
            .0
            .notification_substream_queued_bytes()
    }

    /// Closes a notifications substream opened after a successful
    /// [`Event::NotificationsOutResult`] or that was accepted using
    /// [`MultiStream::accept_in_notifications_substream`].
    ///
    /// In the case of an outbound substream, this can be done even when in the negotiation phase,
    /// in other words before the remote has accepted/refused the substream.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to a notifications substream, or if the
    /// notifications substream isn't in the appropriate state.
    ///
    pub fn close_notifications_substream(&mut self, substream_id: SubstreamId) {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::MultiStream(id) => id,
            _ => panic!(),
        };

        let inner_substream_id = self.out_in_substreams_map.get(&substream_id).unwrap();

        self.in_substreams
            .get_mut(inner_substream_id)
            .unwrap()
            .0
            .close_notifications_substream();
    }

    /// Responds to an incoming request. Must be called in response to a [`Event::RequestIn`].
    ///
    /// Passing an `Err` corresponds, on the other side, to a [`RequestError::SubstreamClosed`].
    ///
    /// Returns an error if the [`SubstreamId`] is invalid.
    pub fn respond_in_request(
        &mut self,
        substream_id: SubstreamId,
        response: Result<Vec<u8>, ()>,
    ) -> Result<(), substream::RespondInRequestError> {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::MultiStream(id) => id,
            _ => return Err(substream::RespondInRequestError::SubstreamClosed),
        };

        let inner_substream_id = self.out_in_substreams_map.get(&substream_id).unwrap();

        self.in_substreams
            .get_mut(inner_substream_id)
            .ok_or(substream::RespondInRequestError::SubstreamClosed)?
            .0
            .respond_in_request(response)
    }
}

impl<TNow, TSubId, TRqUd, TNotifUd> fmt::Debug for MultiStream<TNow, TSubId, TRqUd, TNotifUd> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Established").finish()
    }
}
