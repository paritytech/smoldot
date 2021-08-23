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
//! // TODO: 6- on yamux ping frames
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

use crate::util::leb128;

use super::{super::read_write::ReadWrite, multistream_select, noise, yamux};

use alloc::{string::String, vec::Vec};
use core::{
    fmt, iter,
    ops::{Add, Sub},
    time::Duration,
};

pub mod substream;

pub use substream::RequestError;

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
    /// State of the various substreams of the connection.
    /// Consists in a collection of substreams, each of which holding a [`Substream`] object, or
    /// `None` if the substream has been reset.
    /// Also includes, for each substream, a collection of buffers whose data is to be written
    /// out.
    yamux: yamux::Yamux<Option<substream::Substream<TNow, TRqUd, TNotifUd>>>,

    /// See [`Config::request_protocols`].
    request_protocols: Vec<ConfigRequestResponse>,
    /// See [`Config::notifications_protocols`].
    notifications_protocols: Vec<ConfigNotifications>,
    /// See [`Config::ping_protocol`].
    ping_protocol: String,
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
    pub fn read_write<'a>(
        mut self,
        read_write: &'_ mut ReadWrite<'_, TNow>,
    ) -> Result<
        (
            Established<TNow, TRqUd, TNotifUd>,
            Option<Event<TRqUd, TNotifUd>>,
        ),
        Error,
    > {
        // First, update all the internal substreams.
        // This doesn't read data from `read_write`, but can potential write out data.
        {
            let read_bytes_before = read_write.read_bytes;
            if let Some(event) = self.update_all(read_write) {
                debug_assert_eq!(read_bytes_before, read_write.read_bytes);
                return Ok((self, Some(event)));
            }
            debug_assert_eq!(read_bytes_before, read_write.read_bytes);
        }

        // Decoding the incoming data.
        loop {
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

            // TODO: handle incoming_data being None

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
                    let nego =
                        multistream_select::InProgress::new(multistream_select::Config::Listener {
                            supported_protocols: self
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
                                .collect::<Vec<_>>()
                                .into_iter(),
                        });
                    self.inner
                        .yamux
                        .accept_pending_substream(Substream::InboundNegotiating(nego));
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);
                }

                Some(yamux::IncomingDataDetail::StreamReset {
                    substream_id,
                    user_data: substream_ty,
                }) => {
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);
                    if let Some(event) = substream_ty.reset() {
                        return Ok((self, Some(event)));
                    }
                }

                Some(yamux::IncomingDataDetail::StreamClosed {
                    substream_id,
                    user_data,
                }) => {
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);

                    let user_data = match user_data {
                        Some(ud) => ud,
                        None => {
                            match self
                                .inner
                                .yamux
                                .substream_by_id(substream_id)
                                .unwrap()
                                .into_user_data()
                            {
                                Substream::NotificationsOut { .. } => {
                                    // TODO: report to user
                                    todo!()
                                }
                                _ => {}
                            }

                            self.inner
                                .yamux
                                .substream_by_id(substream_id)
                                .unwrap()
                                .close()
                                .unwrap()
                        }
                    };

                    // TODO: finish here
                }

                Some(yamux::IncomingDataDetail::DataFrame {
                    start_offset,
                    substream_id,
                }) => {
                    // Data belonging to a substream has been decoded.
                    let data = &self.encryption.decoded_inbound_data()
                        [start_offset..yamux_decode.bytes_read];

                    let substream = self.inner.yamux.substream_by_id(substream_id).unwrap();

                    let mut substream_read_write = ReadWrite {
                        now: read_write.now,
                        incoming_buffer: Some(data),
                        outgoing_buffer: if substream.is_closed() { None } else { todo!() },
                        read_bytes: 0,
                        written_bytes: 0,
                        wake_up_after: None,
                        wake_up_future: None,
                    };

                    let event = substream.user_data().read_write(&mut substream_read_write);

                    if substream_read_write.outgoing_buffer.is_none() {
                        substream.close().unwrap();
                    }

                    if let Some(wake_up_after) = substream_read_write.wake_up_after {
                        read_write.wake_up_after(&wake_up_after);
                    }
                    if let Some(future) = substream_read_write.wake_up_future {
                        read_write.wake_up_when_boxed(future);
                    }

                    // Now that the Yamux parsing has been processed, discard this data in
                    // `self.encryption`.
                    self.encryption
                        .consume_inbound_data(substream_read_write.read_bytes);

                    if let Some(event) = event {
                        return Ok((self, Some(event)));
                    }

                    // TODO: correct?
                    if yamux_decode.bytes_read == 0 {
                        break;
                    }
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
        for (_, substream) in self.inner.yamux.user_datas_mut() {
            let mut substream_read_write = ReadWrite {
                now: read_write.now,
                incoming_buffer: Some(&[]), // TODO: what if substream closed?
                outgoing_buffer: todo!(),   // TODO:
                read_bytes: 0,
                written_bytes: 0,
                wake_up_after: None,
                wake_up_future: None,
            };

            let (substream_update, event) = substream
                .take()
                .unwrap()
                .read_write(&mut substream_read_write);
            *substream = Some(substream_update);

            debug_assert_eq!(substream_read_write.read_bytes, 0);
            if let Some(wake_up_after) = substream_read_write.wake_up_after {
                read_write.wake_up_after(&wake_up_after);
            }
            if let Some(wake_up_future) = substream_read_write.wake_up_future {
                read_write.wake_up_when_boxed(wake_up_future);
            }

            if let Some(event) = event {
                return Some(event);
            }
        }

        None
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
    pub fn add_request(
        &mut self,
        now: TNow,
        protocol_index: usize,
        request: Vec<u8>,
        user_data: TRqUd,
    ) -> SubstreamId {
        let mut negotiation =
            multistream_select::InProgress::new(multistream_select::Config::Dialer {
                requested_protocol: self.inner.request_protocols[protocol_index].name.clone(), // TODO: clone :-/
            });

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

        let (new_state, _, out_buffer) = negotiation.read_write_vec(&[]).unwrap();
        match new_state {
            multistream_select::Negotiation::InProgress(n) => negotiation = n,
            _ => unreachable!(),
        }

        let timeout = now + self.inner.request_protocols[protocol_index].timeout;

        if self
            .inner
            .next_timeout
            .as_ref()
            .map_or(true, |t| *t > timeout)
        {
            self.inner.next_timeout = Some(timeout.clone());
        }

        let mut substream = self
            .inner
            .yamux
            .open_substream(Substream::RequestOutNegotiating {
                timeout,
                negotiation,
                request: if has_length_prefix {
                    Some(request)
                } else {
                    None
                },
                user_data,
            });

        substream.reserve_window(128 * 1024 * 1024 + 128); // TODO: proper max size
        substream.write(out_buffer);

        SubstreamId(substream.id())
    }

    /// Returns the user dat associated to a notifications substream.
    ///
    /// Returns `None` if the substream doesn't exist or isn't a notifications substream.
    pub fn notifications_substream_user_data_mut(
        &mut self,
        id: SubstreamId,
    ) -> Option<&mut TNotifUd> {
        self.inner
            .yamux
            .substream_by_id(id.0)?
            .into_user_data()
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
        let mut negotiation =
            multistream_select::InProgress::new(multistream_select::Config::Dialer {
                requested_protocol: self.inner.notifications_protocols[protocol_index]
                    .name
                    .clone(), // TODO: clone :-/
            });

        // TODO: turn this assert into something that can't panic?
        assert!(
            handshake.len()
                <= self.inner.notifications_protocols[protocol_index].max_handshake_size
        );

        let (new_state, _, out_buffer) = negotiation.read_write_vec(&[]).unwrap();
        match new_state {
            multistream_select::Negotiation::InProgress(n) => negotiation = n,
            _ => unreachable!(),
        }

        let timeout = now + Duration::from_secs(20); // TODO:

        if self
            .inner
            .next_timeout
            .as_ref()
            .map_or(true, |t| *t > timeout)
        {
            self.inner.next_timeout = Some(timeout.clone());
        }

        let mut substream =
            self.inner
                .yamux
                .open_substream(Substream::NotificationsOutNegotiating {
                    timeout,
                    negotiation,
                    handshake,
                    user_data,
                });

        substream.write(out_buffer);

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
        self.inner
            .yamux
            .substream_by_id(substream_id.0)
            .unwrap()
            .accept_in_notifications_substream(handshake, user_data);
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
            .substream_by_id(substream_id.0)
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
    pub fn write_notification_unbounded(&mut self, id: SubstreamId, notification: Vec<u8>) {
        let mut substream = self.inner.yamux.substream_by_id(id.0).unwrap();
        if !matches!(substream.user_data(), Substream::NotificationsOut { .. }) {
            panic!()
        }
        substream.write(leb128::encode_usize(notification.len()).collect());
        substream.write(notification)
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
    // TODO: shouldn't require `&mut self`
    pub fn notification_substream_queued_bytes(&mut self, id: SubstreamId) -> usize {
        let mut substream = self.inner.yamux.substream_by_id(id.0).unwrap();
        if !matches!(substream.user_data(), Substream::NotificationsOut { .. }) {
            panic!()
        }
        substream.queued_bytes()
    }

    /// Closes a notifications substream opened with [`Established::open_notifications_substream`].
    ///
    /// This can be done even when in the negotiation phase, in other words before the remote has
    /// accepted/refused the substream.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to a notifications substream, or if the
    /// notifications substream isn't in the appropriate state.
    ///
    pub fn close_notifications_substream(&mut self, id: SubstreamId) {
        let mut substream = self.inner.yamux.substream_by_id(id.0).unwrap();
        if !matches!(
            substream.user_data(),
            Substream::NotificationsOutNegotiating { .. }
                | Substream::NotificationsOutHandshakeRecv { .. }
                | Substream::NotificationsOut { .. }
        ) {
            panic!()
        }
        *substream.user_data() = Substream::NotificationsOutClosed;
        substream.close();
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
        let mut substream = self
            .inner
            .yamux
            .substream_by_id(substream_id.0)
            .ok_or(RespondInRequestError::SubstreamClosed)?;

        match substream.user_data() {
            Substream::RequestInSend => {
                if let Ok(response) = response {
                    substream.write(leb128::encode_usize(response.len()).collect());
                    substream.write(response);
                }

                // TODO: proper state transition
                *substream.user_data() = Substream::NegotiationFailed;

                substream.close();
                Ok(())
            }
            _ => panic!(),
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

/// Event that happened on the connection. See [`Established::read_write`].
#[must_use]
#[derive(Debug)]
pub enum Event<TRqUd, TNotifUd> {
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
        /// Index of the notifications protocol concerned by the substream.
        ///
        /// The index refers to the position of the protocol in
        /// [`Config::notifications_protocols`].
        protocol_index: usize,
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

    /// Remote has accepted a substream opened with [`Established::open_notifications_substream`].
    ///
    /// It is now possible to send notifications on this substream.
    NotificationsOutAccept {
        /// Identifier of the substream. Value that was returned by
        /// [`Established::open_notifications_substream`].
        id: SubstreamId,
        /// Handshake sent back by the remote. Its interpretation is out of scope of this module.
        remote_handshake: Vec<u8>,
    },

    /// Remote has rejected a substream opened with [`Established::open_notifications_substream`].
    NotificationsOutReject {
        /// Identifier of the substream. Value that was returned by
        /// [`Established::open_notifications_substream`].
        id: SubstreamId,
        /// Value that was passed to [`Established::open_notifications_substream`].
        user_data: TNotifUd,
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
}

/// Error during a connection. The connection should be shut down.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// Error in the noise cipher. Data has most likely been corrupted.
    Noise(noise::CipherError),
    /// Error in the yamux multiplexing protocol.
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
        config: Config,
    ) -> Established<TNow, TRqUd, TNotifUd> {
        // TODO: check conflicts between protocol names?

        let yamux = yamux::Yamux::new(yamux::Config {
            is_initiator: self.encryption.is_initiator(),
            capacity: 64, // TODO: ?
            randomness_seed: config.randomness_seed,
        });

        Established {
            encryption: self.encryption,
            inner: Inner {
                yamux,
                next_timeout: None,
                request_protocols: config.request_protocols,
                notifications_protocols: config.notifications_protocols,
                ping_protocol: config.ping_protocol,
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
pub struct Config {
    /// List of request-response protocols supported for incoming substreams.
    pub request_protocols: Vec<ConfigRequestResponse>,
    /// List of notifications protocols supported for incoming substreams.
    pub notifications_protocols: Vec<ConfigNotifications>,
    /// Name of the ping protocol on the network.
    pub ping_protocol: String,
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

    /// Timeout between the moment the substream is opened and the moment the response is sent
    /// back. If the emitter doesn't send the request or if the receiver doesn't answer during
    /// this time window, the request is considered failed.
    pub timeout: Duration,
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

/// Error potentially returned by [`Established::respond_in_request`].
#[derive(Debug, derive_more::Display)]
pub enum RespondInRequestError {
    /// The substream has already been closed.
    SubstreamClosed,
}
