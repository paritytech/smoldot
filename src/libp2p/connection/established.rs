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

//! State machine handling a single TCP or WebSocket libp2p connection.
//!
//! # About resources allocation and back-pressure
//!
//! In order to avoid DoS attacks, it is important, in networking code, to make sure that the
//! amount of memory allocated directly or indirectly by a connection stays bounded.
//!
//! The situations in the [`Established`] that lead to an increase in memory consumption are:
//!
//! 1- On incoming or outgoing substreams.
//! 2- When sending a request or receiving a response in a request-response protocol.
//! 3- When sending a notification.
//! 4- When receiving a request and sending back a response.
//! 5- When receiving a notification.
//! // TODO: 6- on Yamux ping frames
//!
//! In order to solve 1-, there exists a maximum number of simultaneous substreams allowed by the
//! protocol, thereby guaranteeing that the memory consumption doesn't exceed a certain bound.
//! Since receiving a request and a response is a one-time process that occupies an entire
//! substream, allocations referenced by points 2- and 4- are also bounded thanks to this limit.
//! Request-response protocols enforce a limit to the size of the request and response, again
//! guaranteeing a bound on the memory consumption.
//!
//! In order to solve 3-, always use [`Established::notification_substream_queued_bytes`] in order
//! to check the current amount of buffered data before calling
//! [`Established::write_notification_unbounded`]. See the documentation of
//! [`Established::write_notification_unbounded`] for more details.
//!
//! In order to solve 5-, // TODO: .
//!

// TODO: expand docs ^

use super::{super::read_write::ReadWrite, noise, yamux};

use alloc::{boxed::Box, collections::VecDeque, string::String, vec, vec::Vec};
use core::{
    fmt, iter,
    ops::{Add, Sub},
    time::Duration,
};
use rand::{Rng as _, SeedableRng as _};

pub mod substream;

pub use substream::{
    InboundError, NotificationsInClosedErr, NotificationsOutErr, RequestError,
    RespondInRequestError,
};

/// State machine of a fully-established connection.
pub struct Established<TNow, TRqUd, TNotifUd> {
    /// Encryption layer applied directly on top of the incoming data and outgoing data.
    /// In addition to the cipher state, also contains a buffer of data received from the socket,
    /// decoded but yet to be parsed.
    // TODO: move this decoded-data buffer here
    encryption: noise::Noise,

    /// Extra fields. Segregated in order to solve borrowing questions.
    inner: Inner<TNow, TRqUd, TNotifUd>,
}

/// Extra fields. Segregated in order to solve borrowing questions.
struct Inner<TNow, TRqUd, TNotifUd> {
    /// Events that should be yielded from [`Established::read_write`] as soon as possible.
    // TODO: remove this field; it is necessary because of limitations in the yamux implementation
    pending_events: VecDeque<Event<TRqUd, TNotifUd>>,

    /// State of the various substreams of the connection.
    /// Consists in a collection of substreams, each of which holding a [`substream::Substream`]
    /// object, or `None` if the substream has been reset.
    /// Also includes, for each substream, a collection of buffers whose data is to be written
    /// out.
    yamux: yamux::Yamux<Option<substream::Substream<TNow, TRqUd, TNotifUd>>>,

    /// Substream in [`Inner::yamux`] used for outgoing pings.
    ///
    /// Because of the API of [`substream::Substream`] concerning pings, there is no need to
    /// handle situations where the substream fails to negotiate, as this is handled by making
    /// outgoing pings error. This substream is therefore constant.
    ///
    /// It is possible, however, that the remote resets the ping substream. In other words, this
    /// substream might not be found in [`Inner::yamux`]. When that happens, all outgoing pings
    /// are immediately considered as failed.
    outgoing_pings: yamux::SubstreamId,
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

impl<TNow, TRqUd, TNotifUd> Established<TNow, TRqUd, TNotifUd>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Reads data coming from the socket, updates the internal state machine, and writes data
    /// destined to the socket through the [`ReadWrite`].
    ///
    /// In order to avoid unnecessary memory allocations, only one [`Event`] is returned at a time.
    /// Consequently, this method returns as soon as an event is available, even if the buffers
    /// haven't finished being read. Call this method in a loop until the number of bytes read and
    /// written are both 0, and the returned [`Event`] is `None`.
    ///
    /// If an error is returned, the socket should be entirely shut down.
    // TODO: in case of error, we're supposed to first send a yamux goaway frame
    // TODO: consider exposing an API more similar to the one of substream::Substream::read_write?
    pub fn read_write(
        mut self,
        read_write: &'_ mut ReadWrite<'_, TNow>,
    ) -> Result<
        (
            Established<TNow, TRqUd, TNotifUd>,
            Option<Event<TRqUd, TNotifUd>>,
        ),
        Error,
    > {
        if let Some(event) = self.inner.pending_events.pop_front() {
            return Ok((self, Some(event)));
        }

        // First, update all the internal substreams.
        // This doesn't read data from `read_write`, but can potential write out data.
        {
            let read_bytes_before = read_write.read_bytes;
            let out = self.update_all(read_write);
            debug_assert_eq!(read_bytes_before, read_write.read_bytes);
            if let Some(event) = out {
                return Ok((self, Some(event)));
            }
        }

        // Start any outgoing peer if necessary.
        if read_write.now >= self.inner.next_ping {
            self.queue_ping(read_write.now.clone() + self.inner.ping_timeout);
            self.inner.next_ping = read_write.now.clone() + self.inner.ping_interval;
        }
        read_write.wake_up_after(&self.inner.next_ping);

        // Decoding the incoming data.
        loop {
            if let Some(event) = self.inner.pending_events.pop_front() {
                return Ok((self, Some(event)));
            }

            // Transfer data from `incoming_data` to the internal buffer in `self.encryption`.
            if let Some(incoming_data) = read_write.incoming_buffer.as_mut() {
                let num_read = self
                    .encryption
                    .inject_inbound_data(*incoming_data)
                    .map_err(Error::Noise)?;
                read_write.advance_read(num_read);
            } else {
                read_write.close_write();
                return Ok((self, None));
            }

            // Ask the Yamux state machine to decode the buffer present in `self.encryption`.
            let yamux_decode = self
                .inner
                .yamux
                .incoming_data(self.encryption.decoded_inbound_data())
                .map_err(Error::Yamux)?;
            self.inner.yamux = yamux_decode.yamux;

            // TODO: it is possible that the yamux reading is blocked on writing

            // Analyze how Yamux has parsed the data.
            // This still contains references to the data in `self.encryption`.
            match yamux_decode.detail {
                None if yamux_decode.bytes_read == 0 => break,
                None => {
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);
                }

                Some(yamux::IncomingDataDetail::IncomingSubstream) => {
                    // Receive a request from the remote for a new incoming substream.
                    // These requests are automatically accepted.
                    // TODO: add a limit to the number of substreams

                    let supported_protocols = self
                        .inner
                        .request_protocols
                        .iter()
                        .filter(|p| p.inbound_allowed)
                        .map(|p| p.name.clone())
                        .chain(
                            self.inner
                                .notifications_protocols
                                .iter()
                                .map(|p| p.name.clone()),
                        )
                        .chain(iter::once(self.inner.ping_protocol.clone()))
                        .collect::<Vec<_>>();

                    self.inner
                        .yamux
                        .accept_pending_substream(Some(substream::Substream::ingoing(
                            supported_protocols,
                        )));
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);
                }

                Some(yamux::IncomingDataDetail::StreamReset {
                    substream_id,
                    user_data: substream_ty,
                }) => {
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);
                    if let Some(event) = substream_ty.unwrap().reset() {
                        return Ok((
                            self,
                            Some(Self::pass_through_substream_event(substream_id, event)),
                        ));
                    }
                }

                Some(yamux::IncomingDataDetail::StreamClosed {
                    user_data: state_machine,
                    ..
                }) => {
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);

                    let state_machine = match state_machine {
                        Some(ud) => ud.unwrap(),
                        None => {
                            // None here means that only the read side of the substream has been
                            // closed by the remote. This substream will be processed at the next
                            // iteration of the loop.
                            // TODO: actually do this
                            continue;
                        }
                    };

                    // If this is reached, then both sides of the substream have been closed.
                    // Querying the substream again for events.
                    // TODO: consider refactoring yamux to keep the substream until removed manually?

                    let mut substream_read_write = ReadWrite {
                        now: read_write.now.clone(),
                        incoming_buffer: None,
                        outgoing_buffer: None,
                        read_bytes: 0,
                        written_bytes: 0,
                        wake_up_after: None,
                    };

                    let (_, _event) = state_machine.read_write(&mut substream_read_write);

                    if let Some(wake_up_after) = substream_read_write.wake_up_after {
                        read_write.wake_up_after(&wake_up_after);
                    }

                    // TODO: finish here
                }

                Some(yamux::IncomingDataDetail::DataFrame {
                    mut start_offset,
                    substream_id,
                }) => {
                    while start_offset != yamux_decode.bytes_read {
                        // Data belonging to a substream has been decoded.
                        let data = &self.encryption.decoded_inbound_data()
                            [start_offset..yamux_decode.bytes_read];

                        let (num_read, event) = Self::process_substream(
                            &mut self.inner,
                            substream_id,
                            read_write,
                            data,
                        );

                        start_offset += num_read;

                        if let Some(event) = event {
                            self.inner.pending_events.push_back(event);
                        }

                        // It might be that the substream has been closed in `process_substream`.
                        if self.inner.yamux.substream_by_id_mut(substream_id).is_none() {
                            break;
                        }
                    }

                    // Discard this data in `self.encryption`.
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);
                }
            };
        }

        // The yamux state machine contains the data that needs to be written out.
        // Try to flush it.
        loop {
            let bytes_out = self
                .encryption
                .encrypt_size_conv(read_write.outgoing_buffer_available());
            if bytes_out == 0 {
                break;
            }

            let mut buffers = self.inner.yamux.extract_out(bytes_out);
            let mut buffers = buffers.buffers().peekable();
            if buffers.peek().is_none() {
                break;
            }

            let (_read, written) = self.encryption.encrypt(
                buffers,
                match read_write.outgoing_buffer.as_mut() {
                    Some((a, b)) => (a, b),
                    None => (&mut [], &mut []),
                },
            );
            debug_assert!(_read <= bytes_out);
            read_write.advance_write(written);
        }

        Ok((self, None))
    }

    /// Updates all the inner substreams. This doesn't read from `read_write`.
    ///
    /// Optionally returns an event that happened as a result of writing out data or of the
    /// passage of time.
    fn update_all(&mut self, read_write: &mut ReadWrite<TNow>) -> Option<Event<TRqUd, TNotifUd>> {
        for substream_id in self
            .inner
            .yamux
            .user_datas()
            .map(|(id, _)| id)
            .collect::<Vec<_>>()
        {
            let (_num_read, event) =
                Self::process_substream(&mut self.inner, substream_id, read_write, &[]);
            debug_assert_eq!(_num_read, 0);
            if let Some(event) = event {
                return Some(event);
            }
        }

        None
    }

    /// Advances a single substream.
    ///
    /// Returns the number of bytes that have been read from `in_data`, and optionally returns an
    /// event to yield to the user.
    ///
    /// If the substream wants to wake up at a certain time or after a certain future,
    /// `outer_read_write` will be updated to also wake up at that moment.
    ///
    /// This function does **not** read incoming data from `outer_read_write`. Instead, the data
    /// destined to the substream is found in `in_data`.
    ///
    /// # Panic
    ///
    /// Panics if the substream has its read point closed and `in_data` isn't empty.
    ///
    fn process_substream(
        inner: &mut Inner<TNow, TRqUd, TNotifUd>,
        substream_id: yamux::SubstreamId,
        outer_read_write: &mut ReadWrite<TNow>,
        in_data: &[u8],
    ) -> (usize, Option<Event<TRqUd, TNotifUd>>) {
        let mut total_read = 0;

        loop {
            let mut substream = inner.yamux.substream_by_id_mut(substream_id).unwrap();

            let read_is_closed = substream.is_remote_closed();
            let write_is_closed = substream.is_closed();

            let mut substream_read_write = ReadWrite {
                now: outer_read_write.now.clone(),
                incoming_buffer: if read_is_closed {
                    assert!(in_data.is_empty());
                    None
                } else {
                    Some(&in_data[total_read..])
                },
                outgoing_buffer: if !write_is_closed {
                    Some((&mut inner.intermediary_buffer, &mut []))
                } else {
                    None
                },
                read_bytes: 0,
                written_bytes: 0,
                wake_up_after: None,
            };

            let (substream_update, event) = substream
                .user_data()
                .take()
                .unwrap()
                .read_write(&mut substream_read_write);

            total_read += substream_read_write.read_bytes;
            if let Some(wake_up_after) = substream_read_write.wake_up_after {
                outer_read_write.wake_up_after(&wake_up_after);
            }

            let closed_after = substream_read_write.outgoing_buffer.is_none();
            let written_bytes = substream_read_write.written_bytes;
            if written_bytes != 0 {
                debug_assert!(!write_is_closed);
                substream.write(inner.intermediary_buffer[..written_bytes].to_vec());
            }
            if !write_is_closed && closed_after {
                // TODO: use return value
                // TODO: substream.close();
            }

            match substream_update {
                Some(s) => *substream.user_data() = Some(s),
                None => {
                    // TODO: only reset if not already closed
                    inner
                        .yamux
                        .substream_by_id_mut(substream_id)
                        .unwrap()
                        .reset();
                }
            };

            let event_to_yield = match event {
                None => None,
                Some(substream::Event::InboundNegotiated(protocol)) => {
                    let substream = inner
                        .yamux
                        .substream_by_id_mut(substream_id)
                        .unwrap()
                        .into_user_data()
                        .as_mut()
                        .unwrap();

                    if protocol == inner.ping_protocol {
                        substream.set_inbound_ty(substream::InboundTy::Ping);
                    } else if let Some(protocol_index) = inner
                        .request_protocols
                        .iter()
                        .position(|p| p.name == protocol)
                    {
                        substream.set_inbound_ty(substream::InboundTy::Request {
                            protocol_index,
                            request_max_size: if let ConfigRequestResponseIn::Payload { max_size } =
                                inner.request_protocols[protocol_index].inbound_config
                            {
                                Some(max_size)
                            } else {
                                None
                            },
                        });
                    } else if let Some(protocol_index) = inner
                        .notifications_protocols
                        .iter()
                        .position(|p| p.name == protocol)
                    {
                        substream.set_inbound_ty(substream::InboundTy::Notifications {
                            protocol_index,
                            max_handshake_size: inner.notifications_protocols[protocol_index]
                                .max_handshake_size,
                        });
                    } else {
                        unreachable!();
                    }

                    continue;
                }
                Some(other) => Some(Self::pass_through_substream_event(substream_id, other)),
            };

            break (total_read, event_to_yield);
        }
    }

    /// Turns an event from the [`substream`] module into an [`Event`].
    ///
    /// # Panics
    ///
    /// Intentionally panics on [`substream::Event::InboundNegotiated`]. Please handle this
    /// variant separately.
    ///
    fn pass_through_substream_event(
        substream_id: yamux::SubstreamId,
        event: substream::Event<TRqUd, TNotifUd>,
    ) -> Event<TRqUd, TNotifUd> {
        match event {
            substream::Event::InboundNegotiated(_) => panic!(),
            substream::Event::InboundError(error) => Event::InboundError(error),
            substream::Event::RequestIn {
                protocol_index,
                request,
            } => Event::RequestIn {
                id: SubstreamId(substream_id),
                protocol_index,
                request,
            },
            substream::Event::Response {
                response,
                user_data,
            } => Event::Response {
                id: SubstreamId(substream_id),
                response,
                user_data,
            },
            substream::Event::NotificationsInOpen {
                protocol_index,
                handshake,
            } => Event::NotificationsInOpen {
                id: SubstreamId(substream_id),
                protocol_index,
                handshake,
            },
            substream::Event::NotificationsInOpenCancel => Event::NotificationsInOpenCancel {
                id: SubstreamId(substream_id),
            },
            substream::Event::NotificationIn { notification } => Event::NotificationIn {
                notification,
                id: SubstreamId(substream_id),
            },
            substream::Event::NotificationsInClose { outcome } => Event::NotificationsInClose {
                id: SubstreamId(substream_id),
                outcome,
            },
            substream::Event::NotificationsOutResult { result } => Event::NotificationsOutResult {
                id: SubstreamId(substream_id),
                result,
            },
            substream::Event::NotificationsOutCloseDemanded => {
                Event::NotificationsOutCloseDemanded {
                    id: SubstreamId(substream_id),
                }
            }
            substream::Event::NotificationsOutReset { user_data } => Event::NotificationsOutReset {
                id: SubstreamId(substream_id),
                user_data,
            },
            substream::Event::PingOutSuccess => Event::PingOutSuccess,
            substream::Event::PingOutError { .. } => {
                // Because ping events are automatically generated by the external API without any
                // guarantee, it is safe to merge multiple failed pings into one.
                Event::PingOutFailed
            }
        }
    }

    /// Sends a request to the remote.
    ///
    /// Must pass the index of the protocol within [`Config::request_protocols`].
    ///
    /// This method only inserts the request into the connection object. Use
    /// [`Established::read_write`] in order to actually send out the request.
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
        let has_length_prefix = match self.inner.request_protocols[protocol_index].inbound_config {
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

        let substream = self
            .inner
            .yamux
            .open_substream(Some(substream::Substream::request_out(
                self.inner.request_protocols[protocol_index].name.clone(), // TODO: clone :-/
                timeout,
                if has_length_prefix {
                    Some(request)
                } else {
                    None
                },
                self.inner.request_protocols[protocol_index].max_response_size,
                user_data,
            )));

        // TODO: ? do this? substream.reserve_window(128 * 1024 * 1024 + 128); // TODO: proper max size

        SubstreamId(substream.id())
    }

    /// Returns the user data associated to a notifications substream.
    ///
    /// Returns `None` if the substream doesn't exist or isn't a notifications substream.
    pub fn notifications_substream_user_data_mut(
        &mut self,
        id: SubstreamId,
    ) -> Option<&mut TNotifUd> {
        self.inner
            .yamux
            .substream_by_id_mut(id.0)?
            .into_user_data()
            .as_mut()
            .unwrap()
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
    /// [`Established::read_write`] in order to actually send out the request.
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
        let max_handshake_size =
            self.inner.notifications_protocols[protocol_index].max_handshake_size;

        // TODO: turn this assert into something that can't panic?
        assert!(handshake.len() <= max_handshake_size);

        let timeout = now + Duration::from_secs(20); // TODO:

        let substream =
            self.inner
                .yamux
                .open_substream(Some(substream::Substream::notifications_out(
                    timeout,
                    self.inner.notifications_protocols[protocol_index]
                        .name
                        .clone(), // TODO: clone :-/,
                    handshake,
                    max_handshake_size,
                    user_data,
                )));

        SubstreamId(substream.id())
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
        let max_notification_size = 16 * 1024 * 1024; // TODO: hack
                                                      // TODO: self.inner.notifications_protocols[protocol_index].max_notification_size;
        self.inner
            .yamux
            .substream_by_id_mut(substream_id.0)
            .unwrap()
            .into_user_data()
            .as_mut()
            .unwrap()
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
        self.inner
            .yamux
            .substream_by_id_mut(substream_id.0)
            .unwrap()
            .into_user_data()
            .as_mut()
            .unwrap()
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
    /// determined by calling [`Established::notification_substream_queued_bytes`]) is below a
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
        self.inner
            .yamux
            .substream_by_id_mut(substream_id.0)
            .unwrap()
            .into_user_data()
            .as_mut()
            .unwrap()
            .write_notification_unbounded(notification);
    }

    /// Returns the number of bytes waiting to be sent out on that substream.
    ///
    /// See the documentation of [`Established::write_notification_unbounded`] for context.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to a notifications substream, or if the
    /// notifications substream isn't in the appropriate state.
    ///
    pub fn notification_substream_queued_bytes(&self, substream_id: SubstreamId) -> usize {
        let substream = self.inner.yamux.substream_by_id(substream_id.0).unwrap();
        let already_queued = substream.queued_bytes();
        let from_substream = substream
            .into_user_data()
            .as_ref()
            .unwrap()
            .notification_substream_queued_bytes();
        already_queued + from_substream
    }

    /// Closes a notifications substream opened after a successful
    /// [`Event::NotificationsOutResult`] or that was accepted using
    /// [`Established::accept_in_notifications_substream`].
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
        self.inner
            .yamux
            .substream_by_id_mut(substream_id.0)
            .unwrap()
            .into_user_data()
            .as_mut()
            .unwrap()
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
    ) -> Result<(), RespondInRequestError> {
        self.inner
            .yamux
            .substream_by_id_mut(substream_id.0)
            .ok_or(RespondInRequestError::SubstreamClosed)?
            .into_user_data()
            .as_mut()
            .unwrap()
            .respond_in_request(response)
    }

    /// Queues an outgoing ping. Must be passed the moment when this ping will be considered as
    /// failed.
    fn queue_ping(&mut self, timeout: TNow) {
        // It might be that the remote has reset the ping substream, in which case the out ping
        // substream no longer exists and we immediately consider the ping as failed.
        if let Some(substream) = self
            .inner
            .yamux
            .substream_by_id_mut(self.inner.outgoing_pings)
        {
            let payload = self
                .inner
                .ping_payload_randomness
                .sample(rand::distributions::Standard);
            substream
                .into_user_data()
                .as_mut()
                .unwrap()
                .queue_ping(&payload, timeout);
        } else {
            self.inner.pending_events.push_back(Event::PingOutFailed);
        }
    }
}

impl<TNow, TRqUd, TNotifUd> fmt::Debug for Established<TNow, TRqUd, TNotifUd>
where
    TRqUd: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map()
            .entries(self.inner.yamux.user_datas())
            .finish()
    }
}

/// Identifier of a request or a notifications substream.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubstreamId(yamux::SubstreamId);

impl SubstreamId {
    /// Returns the value that compares inferior or equal to all possible values.
    pub fn min_value() -> Self {
        Self(yamux::SubstreamId::min_value())
    }

    /// Returns the value that compares superior or equal to all possible values.
    pub fn max_value() -> Self {
        Self(yamux::SubstreamId::max_value())
    }
}

/// Event that happened on the connection. See [`Established::read_write`].
#[must_use]
#[derive(Debug)]
pub enum Event<TRqUd, TNotifUd> {
    /// Received an incoming substream, but this substream has produced an error.
    ///
    /// > **Note**: This event exists only for diagnostic purposes. No action is expected in
    /// >           return.
    InboundError(InboundError),

    /// Received a request in the context of a request-response protocol.
    RequestIn {
        /// Identifier of the request. Needs to be provided back when answering the request.
        id: SubstreamId,
        /// Index of the request-response protocol the request was sent on.
        ///
        /// The index refers to the position of the protocol in [`Config::request_protocols`].
        protocol_index: usize,
        /// Bytes of the request. Its interpretation is out of scope of this module.
        request: Vec<u8>,
    },

    /// Received a response to a previously emitted request on a request-response protocol.
    Response {
        /// Bytes of the response. Its interpretation is out of scope of this module.
        response: Result<Vec<u8>, RequestError>,
        /// Identifier of the request. Value that was returned by [`Established::add_request`].
        id: SubstreamId,
        /// Value that was passed to [`Established::add_request`].
        user_data: TRqUd,
    },

    /// Remote has opened an inbound notifications substream.
    ///
    /// Either [`Established::accept_in_notifications_substream`] or
    /// [`Established::reject_in_notifications_substream`] must be called in the near future in
    /// order to accept or reject this substream.
    NotificationsInOpen {
        /// Identifier of the substream. Needs to be provided back when accept or rejecting the
        /// substream.
        id: SubstreamId,
        /// Index of the notifications protocol concerned by the substream.
        ///
        /// The index refers to the position of the protocol in
        /// [`Config::notifications_protocols`].
        protocol_index: usize,
        /// Handshake sent by the remote. Its interpretation is out of scope of this module.
        handshake: Vec<u8>,
    },
    /// Remote has canceled an inbound notifications substream opening.
    ///
    /// This can only happen after [`Event::NotificationsInOpen`].
    /// [`Established::accept_in_notifications_substream`] or
    /// [`Established::reject_in_notifications_substream`] should not be called on this substream.
    NotificationsInOpenCancel {
        /// Identifier of the substream.
        id: SubstreamId,
    },
    /// Remote has sent a notification on an inbound notifications substream. Can only happen
    /// after the substream has been accepted.
    // TODO: give a way to back-pressure notifications
    NotificationIn {
        /// Identifier of the substream.
        id: SubstreamId,
        /// Notification sent by the remote.
        notification: Vec<u8>,
    },
    /// Remote has closed an inbound notifications substream.Can only happen
    /// after the substream has been accepted.
    NotificationsInClose {
        /// Identifier of the substream.
        id: SubstreamId,
        /// If `Ok`, the substream has been closed gracefully. If `Err`, a problem happened.
        outcome: Result<(), NotificationsInClosedErr>,
    },

    /// Outcome of trying to open a substream with [`Established::open_notifications_substream`].
    ///
    /// If `Ok`, it is now possible to send notifications on this substream.
    /// If `Err`, the substream no longer exists.
    NotificationsOutResult {
        /// Identifier of the substream. Value that was returned by
        /// [`Established::open_notifications_substream`].
        id: SubstreamId,
        /// If `Ok`, contains the handshake sent back by the remote. Its interpretation is out of
        /// scope of this module.
        result: Result<Vec<u8>, (NotificationsOutErr, TNotifUd)>,
    },
    /// Remote has closed an outgoing notifications substream, meaning that it demands the closing
    /// of the substream.
    NotificationsOutCloseDemanded {
        /// Identifier of the substream. Value that was returned by
        /// [`Established::open_notifications_substream`].
        id: SubstreamId,
    },
    /// Remote has reset an outgoing notifications substream. The substream is instantly closed.
    NotificationsOutReset {
        /// Identifier of the substream. Value that was returned by
        /// [`Established::open_notifications_substream`].
        id: SubstreamId,
        /// Value that was passed to [`Established::open_notifications_substream`].
        user_data: TNotifUd,
    },

    /// An outgoing ping has succeeded. This event is generated automatically over time.
    PingOutSuccess,
    /// An outgoing ping has failed. This event is generated automatically over time.
    PingOutFailed,
}

/// Error during a connection. The connection should be shut down.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// Error in the noise cipher. Data has most likely been corrupted.
    Noise(noise::CipherError),
    /// Error in the Yamux multiplexing protocol.
    Yamux(yamux::Error),
}

/// Successfully negotiated connection. Ready to be turned into a [`Established`].
pub struct ConnectionPrototype {
    encryption: noise::Noise,
}

impl ConnectionPrototype {
    /// Builds a new [`ConnectionPrototype`] of a connection using the Noise and Yamux protocols.
    pub(crate) fn from_noise_yamux(encryption: noise::Noise) -> Self {
        ConnectionPrototype { encryption }
    }

    /// Turns this prototype into an actual connection.
    pub fn into_connection<TNow, TRqUd, TNotifUd>(
        self,
        config: Config<TNow>,
    ) -> Established<TNow, TRqUd, TNotifUd>
    where
        TNow: Clone + Ord,
    {
        // TODO: check conflicts between protocol names?

        let mut randomness = rand_chacha::ChaCha20Rng::from_seed(config.randomness_seed);

        let mut yamux = yamux::Yamux::new(yamux::Config {
            is_initiator: self.encryption.is_initiator(),
            capacity: 64, // TODO: ?
            randomness_seed: randomness.sample(rand::distributions::Standard),
        });

        let outgoing_pings = yamux
            .open_substream(Some(substream::Substream::ping_out(
                config.ping_protocol.clone(),
            )))
            .id();

        Established {
            encryption: self.encryption,
            inner: Inner {
                pending_events: Default::default(),
                yamux,
                outgoing_pings,
                next_ping: config.first_out_ping,
                ping_payload_randomness: randomness,
                request_protocols: config.request_protocols,
                notifications_protocols: config.notifications_protocols,
                ping_protocol: config.ping_protocol,
                ping_interval: config.ping_interval,
                ping_timeout: config.ping_timeout,
                intermediary_buffer: vec![0u8; 2048].into_boxed_slice(),
            },
        }
    }
}

impl fmt::Debug for ConnectionPrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ConnectionPrototype").finish()
    }
}

/// Configuration to turn a [`ConnectionPrototype`] into a [`Established`].
// TODO: this struct isn't zero-cost, but making it zero-cost is kind of hard and annoying
#[derive(Debug, Clone)]
pub struct Config<TNow> {
    /// List of request-response protocols supported for incoming substreams.
    pub request_protocols: Vec<ConfigRequestResponse>,
    /// List of notifications protocols supported for incoming substreams.
    pub notifications_protocols: Vec<ConfigNotifications>,
    /// Name of the ping protocol on the network.
    pub ping_protocol: String,
    /// When to start the first outgoing ping.
    pub first_out_ping: TNow,
    /// Interval between two consecutive outgoing ping attempts.
    pub ping_interval: Duration,
    /// Time after which an outgoing ping is considered failed.
    pub ping_timeout: Duration,
    /// Entropy used for the randomness specific to this connection.
    pub randomness_seed: [u8; 32],
}

/// Configuration for a request-response protocol.
#[derive(Debug, Clone)]
pub struct ConfigRequestResponse {
    /// Name of the protocol transferred on the wire.
    pub name: String,

    /// Configuration related to sending out requests through this protocol.
    ///
    /// > **Note**: This is used even if `inbound_allowed` is `false` when performing outgoing
    /// >           requests.
    pub inbound_config: ConfigRequestResponseIn,

    pub max_response_size: usize,

    /// If true, incoming substreams are allowed to negotiate this protocol.
    pub inbound_allowed: bool,
}

/// See [`ConfigRequestResponse::inbound_config`].
#[derive(Debug, Clone)]
pub enum ConfigRequestResponseIn {
    /// Request must be completely empty, not even a length prefix.
    Empty,
    /// Request must contain a length prefix plus a potentially empty payload.
    Payload {
        /// Maximum allowed size for the payload in bytes.
        max_size: usize,
    },
}

/// Configuration for a notifications protocol.
#[derive(Debug, Clone)]
pub struct ConfigNotifications {
    /// Name of the protocol transferred on the wire.
    pub name: String,

    /// Maximum size, in bytes, of the handshake that can be received.
    pub max_handshake_size: usize,

    /// Maximum size, in bytes, of a notification that can be received.
    pub max_notification_size: usize,
}
