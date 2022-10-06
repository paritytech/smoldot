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

//! Individual substream within an established connection.
//!
//! This module contains the [`Substream`] struct, a state machine containing the state of a
//! single substream. When the remote sends data on that substream, or when the remote is ready to
//! accept more data on that substream, the state machine can be updated by calling
//! [`Substream::read_write`]. This optionally produces an event that indicates what happened on
//! the substream as a result of the call.

use crate::libp2p::{connection::multistream_select, read_write};
use crate::util::leb128;

use alloc::{
    collections::VecDeque,
    string::String,
    vec::{self, Vec},
};
use core::cmp;
use core::{fmt, num::NonZeroUsize};

/// State machine containing the state of a single substream of an established connection.
pub struct Substream<TNow, TRqUd, TNotifUd> {
    inner: SubstreamInner<TNow, TRqUd, TNotifUd>,
}

// TODO: remove `protocol_index` fields?
enum SubstreamInner<TNow, TRqUd, TNotifUd> {
    /// Protocol negotiation in progress in an incoming substream.
    InboundNegotiating(multistream_select::InProgress<vec::IntoIter<String>, String>),
    /// Protocol negotiation in an incoming substream has finished, and an
    /// [`Event::InboundNegotiated`] has been emitted. Now waiting for the remote to indicate the
    /// type of substream.
    InboundNegotiatingApiWait,
    /// Incoming substream has failed to negotiate a protocol. Waiting for a close from the remote.
    /// In order to save a round-trip time, the remote might assume that the protocol negotiation
    /// has succeeded. As such, it might send additional data on this substream that should be
    /// ignored.
    InboundFailed,

    /// Negotiating a protocol for a notifications protocol substream.
    NotificationsOutNegotiating {
        /// When the opening will time out in the absence of response.
        timeout: TNow,
        /// State of the protocol negotiation.
        negotiation: multistream_select::InProgress<vec::IntoIter<String>, String>,
        /// Maximum allowed size for the remote's handshake.
        max_handshake_size: usize,
        /// Bytes of the handshake to send after the substream is open.
        handshake_out: Vec<u8>,
        /// Data passed by the user to [`Substream::notifications_out`].
        user_data: TNotifUd,
    },
    /// Failure to negotiate an outbound notifications substream.
    NotificationsOutNegotiationFailed,
    /// A notifications protocol has been negotiated on a substream. Either a successful handshake
    /// or an abrupt closing is now expected.
    NotificationsOutHandshakeRecv {
        /// Buffer for the incoming handshake.
        handshake_in: leb128::FramedInProgress,
        /// Handshake payload to write out.
        handshake_out: VecDeque<u8>,
        /// Data passed by the user to [`Substream::notifications_out`].
        user_data: TNotifUd,
    },
    /// A notifications protocol has been negotiated, and the remote accepted it. Can now send
    /// notifications.
    NotificationsOut {
        /// Notifications to write out.
        notifications: VecDeque<u8>,
        /// Data passed by the user to [`Substream::notifications_out`].
        user_data: TNotifUd,
    },
    /// A notifications protocol has been closed. Waiting for the remote to close it as well.
    NotificationsOutClosed,

    /// A notifications protocol has been negotiated on an incoming substream. A handshake from
    /// the remote is expected.
    NotificationsInHandshake {
        /// Buffer for the incoming handshake.
        handshake: leb128::FramedInProgress,
        /// Protocol that was negotiated.
        protocol_index: usize,
    },
    /// A handshake on a notifications protocol has been received. Now waiting for an action from
    /// the API user.
    NotificationsInWait {
        /// Protocol that was negotiated.
        protocol_index: usize,
    },
    /// API user has refused an incoming substream. Waiting for a close from the remote.
    /// In order to save a round-trip time, the remote might assume that the protocol negotiation
    /// has succeeded. As such, it might send additional data on this substream that should be
    /// ignored.
    NotificationsInRefused,
    /// A notifications protocol has been negotiated on a substream. Remote can now send
    /// notifications.
    NotificationsIn {
        /// If true, the local node wants to shut down the substream.
        close_desired: bool,
        /// Buffer for the next notification.
        next_notification: leb128::FramedInProgress,
        /// Handshake payload to write out.
        handshake: VecDeque<u8>,
        /// Protocol that was negotiated.
        protocol_index: usize,
        /// Maximum size, in bytes, allowed for each notification.
        max_notification_size: usize,
        /// Data passed by the user to [`Substream::accept_in_notifications_substream`].
        user_data: TNotifUd,
    },
    /// An inbound notifications protocol was open, but then the remote closed its writing side.
    NotificationsInClosed,

    /// Negotiating a protocol for an outgoing request.
    RequestOutNegotiating {
        /// When the request will time out in the absence of response.
        timeout: TNow,
        /// State of the protocol negotiation.
        negotiation: multistream_select::InProgress<vec::IntoIter<String>, String>,
        /// Bytes of the request to send after the substream is open.
        request: VecDeque<u8>,
        /// Maximum allowed size for the response.
        max_response_size: usize,
        /// Data passed by the user to [`Substream::request_out`].
        user_data: TRqUd,
    },
    /// Outgoing request has been sent out or is queued for send out, and a response from the
    /// remote is now expected. Substream has been closed.
    RequestOut {
        /// When the request will time out in the absence of response.
        timeout: TNow,
        /// Request payload to write out.
        request: VecDeque<u8>,
        /// Data passed by the user to [`Substream::request_out`].
        user_data: TRqUd,
        /// Buffer for the incoming response.
        response: leb128::FramedInProgress,
    },

    /// A request-response protocol has been negotiated on an inbound substream. A request is now
    /// expected.
    RequestInRecv {
        /// Buffer for the incoming request.
        request: leb128::FramedInProgress,
        /// Protocol that was negotiated.
        protocol_index: usize,
    },
    /// Similar to [`SubstreamInner::RequestInRecv`], but doesn't expect any length prefix.
    RequestInRecvNoLengthPrefix {
        /// Buffer for the incoming request.
        request: Vec<u8>,
        /// Maxium allowed size for the request.
        max_request_size: usize,
        /// Protocol that was negotiated.
        protocol_index: usize,
    },
    /// A request has been sent by the remote. API user must now send back the response.
    RequestInApiWait { has_length_prefix: bool },
    /// A request has been sent by the remote. Sending back the response.
    RequestInRespond {
        /// Response being sent back.
        response: VecDeque<u8>,
    },

    /// Inbound ping substream. Waiting for the ping payload to be received.
    PingIn {
        payload_in: arrayvec::ArrayVec<u8, 32>,
        payload_out: VecDeque<u8>,
    },

    /// Negotiating a protocol for an outgoing ping substream.
    ///
    /// Note that the negotiation process doesn't have any timeout. Individual outgoing ping
    /// requests *will* time out.
    PingOutNegotiating {
        /// State of the protocol negotiation.
        negotiation: multistream_select::InProgress<vec::IntoIter<String>, String>,
        /// Payload of the queued pings that remains to write out. Since the substream is still
        /// negotiating, no ping has been sent out, and this is thus always equal to 32 times the
        /// number of queued pings.
        outgoing_payload: VecDeque<u8>,
        /// FIFO queue of pings waiting to be answered. For each ping, when the ping will time
        /// out, or `None` if the timeout has already occurred.
        queued_pings: smallvec::SmallVec<[Option<TNow>; 1]>,
    },
    /// Failed to negotiate a protocol for an outgoing ping substream.
    PingOutFailed {
        /// FIFO queue of pings that will immediately fail.
        queued_pings: smallvec::SmallVec<[Option<TNow>; 1]>,
    },
    /// Outbound ping substream.
    PingOut {
        /// Payload of the queued pings that remains to write out.
        outgoing_payload: VecDeque<u8>,
        /// Data waiting to be received from the remote. Any mismatch will cause an error.
        /// Contains even the data that is still queued in `outgoing_payload`.
        expected_payload: VecDeque<u8>,
        /// FIFO queue of pings waiting to be answered. For each ping, when the ping will time
        /// out, or `None` if the timeout has already occurred.
        queued_pings: smallvec::SmallVec<[Option<TNow>; 1]>,
    },
}

impl<TNow, TRqUd, TNotifUd> Substream<TNow, TRqUd, TNotifUd>
where
    TNow: Clone + Ord,
{
    /// Initializes an new `ingoing` substream.
    ///
    /// After the remote has requested a protocol, an [`Event::InboundNegotiated`] event will be
    /// generated, after which [`Substream::set_inbound_ty`] must be called in order to indicate
    /// the nature of the negotiated protocol.
    /// A [`Event::InboundError`] can also be generated, either before or after the
    /// [`Event::InboundNegotiated`], but always before any [`Event::NotificationsInOpen`].
    ///
    /// If [`InboundTy::Notifications`] is passed, then a [`Event::NotificationsInOpen`] will be
    /// generated (unless an error happens, in which case [`Event::InboundError`]).
    /// In response, the API user must call either [`Substream::accept_in_notifications_substream`]
    /// or [`Substream::reject_in_notifications_substream`]. Before one of these two methods is
    /// called, it is possible for an [`Event::NotificationsInOpenCancel`] to be generated, in
    /// which case the inbound request is canceled and the substream closed.
    /// After [`Substream::accept_in_notifications_substream`] is called, zero or more
    /// [`Event::NotificationIn`] will be generated, until a [`Event::NotificationsInClose`] which
    /// indicates the end of the substream.
    ///
    /// If [`InboundTy::Request`] is passed, then a [`Event::RequestIn`] will be generated, after
    /// which the API user must call [`Substream::respond_in_request`]. An [`Event::InboundError`]
    /// can happen at any point.
    ///
    /// This flow is also true if you call [`Substream::reset`] at any point.
    pub fn ingoing(supported_protocols: Vec<String>) -> Self {
        let negotiation =
            multistream_select::InProgress::new(multistream_select::Config::Listener {
                supported_protocols: supported_protocols.into_iter(),
            });

        Substream {
            inner: SubstreamInner::InboundNegotiating(negotiation),
        }
    }

    /// Initializes an outgoing notifications substream.
    ///
    /// After the remote has sent back a handshake or after an error occurred, an
    /// [`Event::NotificationsOutResult`] event will be generated locally.
    ///
    /// If this event contains an `Ok`, then [`Substream::write_notification_unbounded`],
    /// [`Substream::notification_substream_queued_bytes`] and
    /// [`Substream::close_notifications_substream`] can be used, and
    /// [`Event::NotificationsOutCloseDemanded`] and [`Event::NotificationsOutReset`] can be
    /// generated.
    pub fn notifications_out(
        timeout: TNow,
        requested_protocol: String,
        handshake: Vec<u8>,
        max_handshake_size: usize,
        user_data: TNotifUd,
    ) -> Self {
        // TODO: check `handshake < max_handshake_size`?

        let negotiation = multistream_select::InProgress::new(multistream_select::Config::Dialer {
            requested_protocol,
        });

        Substream {
            inner: SubstreamInner::NotificationsOutNegotiating {
                timeout,
                negotiation,
                max_handshake_size,
                handshake_out: handshake,
                user_data,
            },
        }
    }

    /// Initializes an outgoing request substream.
    ///
    /// After the remote has sent back a response or after an error occurred, an [`Event::Response`]
    /// event will be generated locally. The `user_data` parameter will be passed back.
    ///
    /// If `has_length_prefix` is `true`, then the request is prefixed by its length as an LEB128.
    pub fn request_out(
        requested_protocol: String,
        timeout: TNow,
        has_length_prefix: bool,
        request: Vec<u8>,
        max_response_size: usize,
        user_data: TRqUd,
    ) -> Self {
        let negotiation = multistream_select::InProgress::new(multistream_select::Config::Dialer {
            requested_protocol,
        });

        let request_payload = if has_length_prefix {
            leb128::encode_usize(request.len())
                .chain(request.into_iter())
                .collect::<VecDeque<_>>()
        } else {
            request.into_iter().collect()
        };

        Substream {
            inner: SubstreamInner::RequestOutNegotiating {
                timeout,
                negotiation,
                request: request_payload,
                max_response_size,
                user_data,
            },
        }

        // TODO: somehow do substream.reserve_window(128 * 1024 * 1024 + 128); // TODO: proper max size
    }

    /// Initializes an outgoing ping substream.
    ///
    /// Call [`Substream::queue_ping`] in order to queue an outgoing ping on this substream. This
    /// can be done at any time, even immediately after this function has returned.
    ///
    /// The substream will attempt to negotiate the ping protocol. No event is reported if the
    /// protocol fails to negotiate. Instead, outgoing pings will be transparently failing.
    ///
    /// > Note: At the time of the writing of this comment, no API method exists to close an
    /// >       outgoing ping substream.
    pub fn ping_out(ping_protocol_name: String) -> Self {
        let negotiation = multistream_select::InProgress::new(multistream_select::Config::Dialer {
            requested_protocol: ping_protocol_name,
        });

        Substream {
            inner: SubstreamInner::PingOutNegotiating {
                negotiation,
                outgoing_payload: VecDeque::with_capacity(32),
                queued_pings: smallvec::SmallVec::new(),
            },
        }
    }

    /// Returns the user data associated to a request substream.
    ///
    /// Returns `None` if the substream isn't a request substream.
    pub fn request_substream_user_data_mut(&mut self) -> Option<&mut TRqUd> {
        match &mut self.inner {
            SubstreamInner::RequestOutNegotiating { user_data, .. } => Some(user_data),
            SubstreamInner::RequestOut { user_data, .. } => Some(user_data),
            _ => None,
        }
    }

    /// Returns the user data associated to a notifications substream.
    ///
    /// Returns `None` if the substream isn't a notifications substream.
    pub fn notifications_substream_user_data_mut(&mut self) -> Option<&mut TNotifUd> {
        match &mut self.inner {
            SubstreamInner::NotificationsOutNegotiating { user_data, .. } => Some(user_data),
            SubstreamInner::NotificationsOutHandshakeRecv { user_data, .. } => Some(user_data),
            SubstreamInner::NotificationsOut { user_data, .. } => Some(user_data),
            SubstreamInner::NotificationsIn { user_data, .. } => Some(user_data),
            _ => None,
        }
    }

    /// Reads data coming from the socket, updates the internal state machine, and writes data
    /// destined to the socket through the [`read_write::ReadWrite`].
    ///
    /// If both the reading side and the writing side are closed and no other event can happen, or
    /// if at any point a protocol error happens, then `None` is returned. In that case, the
    /// substream must be reset if it is not closed.
    pub fn read_write(
        self,
        read_write: &'_ mut read_write::ReadWrite<'_, TNow>,
    ) -> (Option<Self>, Option<Event<TRqUd, TNotifUd>>) {
        let (me, event) = self.read_write2(read_write);
        (me.map(|inner| Substream { inner }), event)
    }

    fn read_write2(
        self,
        read_write: &'_ mut read_write::ReadWrite<'_, TNow>,
    ) -> (
        Option<SubstreamInner<TNow, TRqUd, TNotifUd>>,
        Option<Event<TRqUd, TNotifUd>>,
    ) {
        match self.inner {
            SubstreamInner::InboundNegotiating(nego) => match nego.read_write(read_write) {
                Ok(multistream_select::Negotiation::InProgress(nego)) => {
                    (Some(SubstreamInner::InboundNegotiating(nego)), None)
                }
                Ok(multistream_select::Negotiation::Success(protocol)) => (
                    Some(SubstreamInner::InboundNegotiatingApiWait),
                    Some(Event::InboundNegotiated(protocol)),
                ),
                Ok(multistream_select::Negotiation::NotAvailable) => {
                    (Some(SubstreamInner::InboundFailed), None)
                }
                Err(err) => (
                    None,
                    Some(Event::InboundError(InboundError::NegotiationError(err))),
                ),
            },
            SubstreamInner::InboundNegotiatingApiWait => {
                (Some(SubstreamInner::InboundNegotiatingApiWait), None)
            }
            SubstreamInner::InboundFailed => {
                // Substream is an inbound substream that has failed to negotiate a
                // protocol. The substream is expected to close soon, but the remote might
                // have been eagerly sending data (assuming that the negotiation would
                // succeed), which should be silently discarded.
                read_write.discard_all_incoming();
                read_write.close_write();
                if read_write.is_dead() {
                    (None, None)
                } else {
                    (Some(SubstreamInner::InboundFailed), None)
                }
            }

            SubstreamInner::NotificationsOutNegotiating {
                negotiation,
                timeout,
                max_handshake_size,
                handshake_out,
                user_data,
            } => {
                if timeout < read_write.now {
                    return (
                        Some(SubstreamInner::NotificationsOutNegotiationFailed),
                        Some(Event::NotificationsOutResult {
                            result: Err((NotificationsOutErr::Timeout, user_data)),
                        }),
                    );
                }

                read_write.wake_up_after(&timeout);

                match negotiation.read_write(read_write) {
                    Ok(multistream_select::Negotiation::InProgress(nego)) => (
                        Some(SubstreamInner::NotificationsOutNegotiating {
                            negotiation: nego,
                            timeout,
                            max_handshake_size,
                            handshake_out,
                            user_data,
                        }),
                        None,
                    ),
                    Ok(multistream_select::Negotiation::Success(_)) => {
                        let handshake_out = {
                            let handshake_len = handshake_out.len();
                            leb128::encode_usize(handshake_len)
                                .chain(handshake_out.into_iter())
                                .collect::<VecDeque<_>>()
                        };

                        (
                            Some(SubstreamInner::NotificationsOutHandshakeRecv {
                                handshake_in: leb128::FramedInProgress::new(max_handshake_size),
                                handshake_out,
                                user_data,
                            }),
                            None,
                        )
                    }
                    Ok(multistream_select::Negotiation::NotAvailable) => (
                        Some(SubstreamInner::NotificationsOutNegotiationFailed),
                        Some(Event::NotificationsOutResult {
                            result: Err((NotificationsOutErr::ProtocolNotAvailable, user_data)),
                        }),
                    ),
                    Err(err) => (
                        None,
                        Some(Event::NotificationsOutResult {
                            result: Err((NotificationsOutErr::NegotiationError(err), user_data)),
                        }),
                    ),
                }
            }
            SubstreamInner::NotificationsOutNegotiationFailed => {
                // Substream has failed to negotiate a protocol. The substream is expected to
                // close soon.
                read_write.discard_all_incoming();
                read_write.close_write();
                (
                    if read_write.is_dead() {
                        None
                    } else {
                        Some(SubstreamInner::NotificationsOutNegotiationFailed)
                    },
                    None,
                )
            }
            SubstreamInner::NotificationsOutHandshakeRecv {
                handshake_in,
                mut handshake_out,
                user_data,
            } => {
                read_write.write_from_vec_deque(&mut handshake_out);

                let incoming_buffer = match read_write.incoming_buffer {
                    Some(buf) => buf,
                    None => {
                        return (
                            Some(SubstreamInner::NotificationsOutNegotiationFailed),
                            Some(Event::NotificationsOutResult {
                                result: Err((NotificationsOutErr::RefusedHandshake, user_data)),
                            }),
                        );
                    }
                };

                // Don't actually process incoming data before handshake is sent out, in order to
                // not accidentally perform a state transition.
                if !handshake_out.is_empty() {
                    return (
                        Some(SubstreamInner::NotificationsOutHandshakeRecv {
                            handshake_in,
                            handshake_out,
                            user_data,
                        }),
                        None,
                    );
                }

                match handshake_in.update(incoming_buffer) {
                    Ok((num_read, leb128::Framed::Finished(remote_handshake))) => {
                        read_write.advance_read(num_read);

                        (
                            Some(SubstreamInner::NotificationsOut {
                                notifications: VecDeque::new(),
                                user_data,
                            }),
                            Some(Event::NotificationsOutResult {
                                result: Ok(remote_handshake),
                            }),
                        )
                    }
                    Ok((num_read, leb128::Framed::InProgress(handshake_in))) => {
                        read_write.advance_read(num_read);
                        (
                            Some(SubstreamInner::NotificationsOutHandshakeRecv {
                                handshake_in,
                                handshake_out,
                                user_data,
                            }),
                            None,
                        )
                    }
                    Err(err) => (
                        None,
                        Some(Event::NotificationsOutResult {
                            result: Err((NotificationsOutErr::HandshakeRecvError(err), user_data)),
                        }),
                    ),
                }
            }
            SubstreamInner::NotificationsOut {
                mut notifications,
                user_data,
            } => {
                // Receiving data on an outgoing substream is forbidden by the protocol.
                read_write.discard_all_incoming();
                read_write.write_from_vec_deque(&mut notifications);
                (
                    Some(SubstreamInner::NotificationsOut {
                        notifications,
                        user_data,
                    }),
                    None,
                )
            }
            SubstreamInner::NotificationsOutClosed => {
                read_write.discard_all_incoming();
                read_write.close_write();
                (
                    if read_write.is_dead() {
                        None
                    } else {
                        Some(SubstreamInner::NotificationsOutClosed)
                    },
                    None,
                )
            }

            SubstreamInner::RequestOutNegotiating {
                negotiation,
                timeout,
                request,
                max_response_size,
                user_data,
            } => {
                // Note that this might trigger timeouts for requests whose response is available
                // in `incoming_buffer`. This is intentional, as from the perspective of
                // `read_write` the response arrived after the timeout. It is the responsibility
                // of the user to call `read_write` in an appropriate way for this to not happen.
                if timeout < read_write.now {
                    read_write.close_write();
                    return (
                        None,
                        Some(Event::Response {
                            response: Err(RequestError::Timeout),
                            user_data,
                        }),
                    );
                }
                read_write.wake_up_after(&timeout);

                match negotiation.read_write(read_write) {
                    Ok(multistream_select::Negotiation::InProgress(nego)) => (
                        Some(SubstreamInner::RequestOutNegotiating {
                            negotiation: nego,
                            timeout,
                            request,
                            max_response_size,
                            user_data,
                        }),
                        None,
                    ),
                    Ok(multistream_select::Negotiation::Success(_)) => (
                        Some(SubstreamInner::RequestOut {
                            timeout,
                            request,
                            user_data,
                            response: leb128::FramedInProgress::new(max_response_size),
                        }),
                        None,
                    ),
                    Ok(multistream_select::Negotiation::NotAvailable) => (
                        None,
                        Some(Event::Response {
                            user_data,
                            response: Err(RequestError::ProtocolNotAvailable),
                        }),
                    ),
                    Err(err) => (
                        None,
                        Some(Event::Response {
                            user_data,
                            response: Err(RequestError::NegotiationError(err)),
                        }),
                    ),
                }
            }
            SubstreamInner::RequestOut {
                timeout,
                mut request,
                user_data,
                response,
            } => {
                // Note that this might trigger timeouts for requests whose response is available
                // in `incoming_buffer`. This is intentional, as from the perspective of
                // `read_write` the response arrived after the timeout. It is the responsibility
                // of the user to call `read_write` in an appropriate way for this to not happen.
                if timeout < read_write.now {
                    read_write.close_write();
                    return (
                        None,
                        Some(Event::Response {
                            response: Err(RequestError::Timeout),
                            user_data,
                        }),
                    );
                }

                read_write.wake_up_after(&timeout);

                read_write.write_from_vec_deque(&mut request);
                if request.is_empty() {
                    read_write.close_write();
                }

                let incoming_buffer = match read_write.incoming_buffer {
                    Some(buf) => buf,
                    None => {
                        read_write.close_write();
                        return (
                            None,
                            Some(Event::Response {
                                user_data,
                                response: Err(RequestError::SubstreamClosed),
                            }),
                        );
                    }
                };

                match response.update(incoming_buffer) {
                    Ok((num_read, leb128::Framed::Finished(response))) => {
                        read_write.advance_read(num_read);
                        read_write.close_write();
                        (
                            None,
                            Some(Event::Response {
                                user_data,
                                response: Ok(response),
                            }),
                        )
                    }
                    Ok((num_read, leb128::Framed::InProgress(response))) => {
                        read_write.advance_read(num_read);
                        (
                            Some(SubstreamInner::RequestOut {
                                timeout,
                                request,
                                user_data,
                                response,
                            }),
                            None,
                        )
                    }
                    Err(err) => (
                        None,
                        Some(Event::Response {
                            user_data,
                            response: Err(RequestError::ResponseLebError(err)),
                        }),
                    ),
                }
            }

            SubstreamInner::RequestInRecv {
                request,
                protocol_index,
            } => {
                let incoming_buffer = match read_write.incoming_buffer {
                    Some(buf) => buf,
                    None => {
                        return (
                            None,
                            Some(Event::InboundError(InboundError::RequestInExpectedEof)),
                        );
                    }
                };

                match request.update(incoming_buffer) {
                    Ok((num_read, leb128::Framed::Finished(request))) => {
                        read_write.advance_read(num_read);
                        (
                            Some(SubstreamInner::RequestInApiWait {
                                has_length_prefix: true,
                            }),
                            Some(Event::RequestIn {
                                protocol_index,
                                request,
                            }),
                        )
                    }
                    Ok((num_read, leb128::Framed::InProgress(request))) => {
                        read_write.advance_read(num_read);
                        (
                            Some(SubstreamInner::RequestInRecv {
                                request,
                                protocol_index,
                            }),
                            None,
                        )
                    }
                    Err(err) => (
                        None,
                        Some(Event::InboundError(InboundError::RequestInLebError(err))),
                    ),
                }
            }
            SubstreamInner::RequestInRecvNoLengthPrefix {
                mut request,
                protocol_index,
                max_request_size,
            } => {
                let incoming_buffer = match read_write.incoming_buffer {
                    Some(buf) => buf,
                    None => {
                        // Success.
                        return (
                            Some(SubstreamInner::RequestInApiWait {
                                has_length_prefix: false,
                            }),
                            Some(Event::RequestIn {
                                protocol_index,
                                request,
                            }),
                        );
                    }
                };

                if request.len().saturating_add(incoming_buffer.len()) > max_request_size {
                    return (
                        None,
                        Some(Event::InboundError(
                            InboundError::RequestInNoLenPrefixTooLarge,
                        )),
                    );
                }

                request.extend_from_slice(incoming_buffer);
                read_write.advance_read(incoming_buffer.len());

                (
                    Some(SubstreamInner::RequestInRecvNoLengthPrefix {
                        request,
                        protocol_index,
                        max_request_size,
                    }),
                    None,
                )
            }
            SubstreamInner::RequestInApiWait { has_length_prefix } => (
                Some(SubstreamInner::RequestInApiWait { has_length_prefix }),
                None,
            ),
            SubstreamInner::RequestInRespond { mut response } => {
                read_write.write_from_vec_deque(&mut response);
                if response.is_empty() {
                    read_write.close_write();
                    (None, None)
                } else {
                    (Some(SubstreamInner::RequestInRespond { response }), None)
                }
            }

            SubstreamInner::NotificationsInHandshake {
                handshake,
                protocol_index,
            } => {
                let incoming_buffer = match read_write.incoming_buffer {
                    Some(buf) => buf,
                    None => {
                        read_write.close_write();
                        return (
                            None,
                            Some(Event::InboundError(
                                InboundError::NotificationsInUnexpectedEof { protocol_index },
                            )),
                        );
                    }
                };

                match handshake.update(incoming_buffer) {
                    Ok((num_read, leb128::Framed::Finished(handshake))) => {
                        read_write.advance_read(num_read);
                        (
                            Some(SubstreamInner::NotificationsInWait { protocol_index }),
                            Some(Event::NotificationsInOpen {
                                protocol_index,
                                handshake,
                            }),
                        )
                    }
                    Ok((num_read, leb128::Framed::InProgress(handshake))) => {
                        read_write.advance_read(num_read);
                        (
                            Some(SubstreamInner::NotificationsInHandshake {
                                handshake,
                                protocol_index,
                            }),
                            None,
                        )
                    }
                    Err(error) => (
                        None,
                        Some(Event::InboundError(InboundError::NotificationsInError {
                            error,
                            protocol_index,
                        })),
                    ),
                }
            }
            SubstreamInner::NotificationsInWait { protocol_index } => {
                // Incoming data isn't processed, potentially back-pressuring it.
                if read_write.incoming_buffer.is_some() {
                    (
                        Some(SubstreamInner::NotificationsInWait { protocol_index }),
                        None,
                    )
                } else {
                    (
                        Some(SubstreamInner::NotificationsInRefused),
                        Some(Event::NotificationsInOpenCancel),
                    )
                }
            }
            SubstreamInner::NotificationsInRefused => {
                read_write.discard_all_incoming();
                read_write.close_write();
                (
                    if read_write.is_dead() {
                        None
                    } else {
                        Some(SubstreamInner::NotificationsInRefused)
                    },
                    None,
                )
            }
            SubstreamInner::NotificationsIn {
                close_desired,
                mut next_notification,
                mut handshake,
                protocol_index,
                max_notification_size,
                user_data,
            } => {
                read_write.write_from_vec_deque(&mut handshake);

                let incoming_buffer = match read_write.incoming_buffer {
                    Some(buf) => buf,
                    None => {
                        read_write.close_write();
                        return (
                            Some(SubstreamInner::NotificationsInClosed),
                            Some(Event::NotificationsInClose { outcome: Ok(()) }),
                        );
                    }
                };

                match next_notification.update(incoming_buffer) {
                    Ok((num_read, leb128::Framed::Finished(notification))) => {
                        read_write.advance_read(num_read);

                        (
                            Some(SubstreamInner::NotificationsIn {
                                close_desired,
                                next_notification: leb128::FramedInProgress::new(
                                    max_notification_size,
                                ),
                                handshake,
                                protocol_index,
                                max_notification_size,
                                user_data,
                            }),
                            Some(Event::NotificationIn { notification }),
                        )
                    }
                    Ok((num_read, leb128::Framed::InProgress(next))) => {
                        read_write.advance_read(num_read);
                        next_notification = next;

                        (
                            Some(SubstreamInner::NotificationsIn {
                                close_desired,
                                next_notification,
                                handshake,
                                protocol_index,
                                max_notification_size,
                                user_data,
                            }),
                            None,
                        )
                    }
                    Err(error) => (
                        Some(SubstreamInner::NotificationsInClosed),
                        Some(Event::NotificationsInClose {
                            outcome: Err(NotificationsInClosedErr::ProtocolError(error)),
                        }),
                    ),
                }
            }
            SubstreamInner::NotificationsInClosed => {
                read_write.discard_all_incoming();
                read_write.close_write();
                (
                    if read_write.is_dead() {
                        None
                    } else {
                        Some(SubstreamInner::NotificationsInClosed)
                    },
                    None,
                )
            }

            SubstreamInner::PingIn {
                mut payload_in,
                mut payload_out,
            } => {
                // Inbound ping substream.
                // The ping protocol consists in sending 32 bytes of data, which the remote has
                // to send back. The `payload` field contains these 32 bytes being received.
                while read_write.incoming_buffer_available() != 0
                    && read_write.outgoing_buffer_available() != 0
                {
                    let available = payload_in.remaining_capacity();
                    payload_in.extend(read_write.incoming_bytes_iter().take(available));
                    if payload_in.is_full() {
                        payload_out.extend(payload_in.iter().copied());
                        payload_in.clear();
                    }
                    read_write.write_from_vec_deque(&mut payload_out);
                }

                (
                    Some(SubstreamInner::PingIn {
                        payload_in,
                        payload_out,
                    }),
                    None,
                )
            }

            SubstreamInner::PingOutNegotiating {
                negotiation,
                mut queued_pings,
                mut outgoing_payload,
            } => {
                for timeout in queued_pings.iter_mut() {
                    if timeout.as_ref().map_or(false, |t| *t < read_write.now) {
                        *timeout = None;
                        return (
                            Some(SubstreamInner::PingOutNegotiating {
                                negotiation,
                                outgoing_payload,
                                queued_pings,
                            }),
                            Some(Event::PingOutError {
                                num_pings: NonZeroUsize::new(1).unwrap(),
                            }),
                        );
                    }

                    if let Some(timeout) = timeout {
                        read_write.wake_up_after(timeout);
                    }
                }

                while queued_pings.get(0).map_or(false, |p| p.is_none()) {
                    queued_pings.remove(0);
                    for _ in 0..32 {
                        outgoing_payload.pop_front();
                    }
                }

                match negotiation.read_write(read_write) {
                    Ok(multistream_select::Negotiation::InProgress(nego)) => (
                        Some(SubstreamInner::PingOutNegotiating {
                            negotiation: nego,
                            outgoing_payload,
                            queued_pings,
                        }),
                        None,
                    ),
                    Ok(multistream_select::Negotiation::Success(_)) => (
                        Some(SubstreamInner::PingOut {
                            outgoing_payload: outgoing_payload.clone(),
                            expected_payload: outgoing_payload,
                            queued_pings,
                        }),
                        None,
                    ),
                    Ok(multistream_select::Negotiation::NotAvailable) => {
                        (Some(SubstreamInner::PingOutFailed { queued_pings }), None)
                    }
                    Err(_) => (Some(SubstreamInner::PingOutFailed { queued_pings }), None),
                }
            }
            SubstreamInner::PingOutFailed { mut queued_pings } => {
                read_write.close_write();
                if !queued_pings.is_empty() {
                    queued_pings.remove(0);
                    (
                        Some(SubstreamInner::PingOutFailed { queued_pings }),
                        Some(Event::PingOutError {
                            num_pings: NonZeroUsize::new(1).unwrap(),
                        }),
                    )
                } else {
                    (Some(SubstreamInner::PingOutFailed { queued_pings }), None)
                }
            }
            SubstreamInner::PingOut {
                mut queued_pings,
                mut outgoing_payload,
                mut expected_payload,
            } => {
                read_write.write_from_vec_deque(&mut outgoing_payload);

                // We check the timeouts before checking the incoming data, as otherwise pings
                // might succeed after their timeout.
                for timeout in queued_pings.iter_mut() {
                    if timeout.as_ref().map_or(false, |t| *t < read_write.now) {
                        *timeout = None;
                        return (
                            Some(SubstreamInner::PingOut {
                                expected_payload,
                                outgoing_payload,
                                queued_pings,
                            }),
                            Some(Event::PingOutError {
                                num_pings: NonZeroUsize::new(1).unwrap(),
                            }),
                        );
                    }

                    if let Some(timeout) = timeout {
                        read_write.wake_up_after(timeout);
                    }
                }

                for actual_byte in read_write.incoming_bytes_iter() {
                    if expected_payload.pop_front() != Some(actual_byte) {
                        return (Some(SubstreamInner::PingOutFailed { queued_pings }), None);
                    }

                    // When a ping has been fully answered is determined based on the number of
                    // bytes in `expected_payload`.
                    if expected_payload.len() % 32 == 0 {
                        debug_assert!(!queued_pings.is_empty()); // `expected_payload.pop_front()` should have returned `None` above otherwise
                        if queued_pings.remove(0).is_some() {
                            return (
                                Some(SubstreamInner::PingOut {
                                    expected_payload,
                                    outgoing_payload,
                                    queued_pings,
                                }),
                                Some(Event::PingOutSuccess),
                            );
                        }
                    }
                }

                (
                    Some(SubstreamInner::PingOut {
                        expected_payload,
                        outgoing_payload,
                        queued_pings,
                    }),
                    None,
                )
            }
        }
    }

    pub fn reset(self) -> Option<Event<TRqUd, TNotifUd>> {
        match self.inner {
            SubstreamInner::InboundNegotiating(_) => None,
            SubstreamInner::InboundNegotiatingApiWait => None,
            SubstreamInner::InboundFailed => None,
            SubstreamInner::RequestOutNegotiating { user_data, .. }
            | SubstreamInner::RequestOut { user_data, .. } => Some(Event::Response {
                user_data,
                response: Err(RequestError::SubstreamReset),
            }),
            SubstreamInner::NotificationsInHandshake { .. } => None,
            SubstreamInner::NotificationsInWait { .. } => Some(Event::NotificationsInOpenCancel),
            SubstreamInner::NotificationsIn { .. } => Some(Event::NotificationsInClose {
                outcome: Err(NotificationsInClosedErr::SubstreamReset),
            }),
            SubstreamInner::NotificationsInRefused => None,
            SubstreamInner::NotificationsInClosed => None,
            SubstreamInner::NotificationsOutNegotiating { user_data, .. }
            | SubstreamInner::NotificationsOutHandshakeRecv { user_data, .. } => {
                Some(Event::NotificationsOutResult {
                    result: Err((NotificationsOutErr::SubstreamReset, user_data)),
                })
            }
            SubstreamInner::NotificationsOutNegotiationFailed => None,
            SubstreamInner::NotificationsOut { user_data, .. } => {
                Some(Event::NotificationsOutReset { user_data })
            }
            SubstreamInner::NotificationsOutClosed { .. } => None,
            SubstreamInner::PingIn { .. } => None,
            SubstreamInner::RequestInRecv { .. } => None,
            SubstreamInner::RequestInRecvNoLengthPrefix { .. } => None,
            SubstreamInner::RequestInApiWait { .. } => None,
            SubstreamInner::RequestInRespond { .. } => None,
            SubstreamInner::PingOut { queued_pings, .. }
            | SubstreamInner::PingOutNegotiating { queued_pings, .. }
            | SubstreamInner::PingOutFailed { queued_pings, .. } => {
                NonZeroUsize::new(queued_pings.len())
                    .map(|num_pings| Event::PingOutError { num_pings })
            }
        }
    }

    /// Accepts an inbound notifications protocol. Must be called in response to a
    /// [`Event::NotificationsInOpen`].
    ///
    /// # Panic
    ///
    /// Panics if this substream is not of the correct type.
    ///
    pub fn accept_in_notifications_substream(
        &mut self,
        handshake: Vec<u8>,
        max_notification_size: usize,
        user_data: TNotifUd,
    ) {
        match &mut self.inner {
            SubstreamInner::NotificationsInWait { protocol_index } => {
                let protocol_index = *protocol_index;

                self.inner = SubstreamInner::NotificationsIn {
                    close_desired: false,
                    next_notification: leb128::FramedInProgress::new(max_notification_size),
                    handshake: {
                        let handshake_len = handshake.len();
                        leb128::encode_usize(handshake_len)
                            .chain(handshake.into_iter())
                            .collect::<VecDeque<_>>()
                    },
                    protocol_index,
                    max_notification_size,
                    user_data,
                }
            }
            _ => {} // TODO: too defensive, should be panic!()
        }
    }

    /// Rejects an inbound notifications protocol. Must be called in response to a
    /// [`Event::NotificationsInOpen`].
    ///
    /// # Panic
    ///
    /// Panics if this substream is not of the correct type.
    ///
    pub fn reject_in_notifications_substream(&mut self) {
        match &mut self.inner {
            SubstreamInner::NotificationsInWait { .. } => {
                self.inner = SubstreamInner::NotificationsInRefused;
            }
            _ => panic!(),
        }
    }

    /// Queues a notification to be written out on the given substream.
    ///
    /// # Panic
    ///
    /// Panics if the substream isn't a notifications substream, or if the notifications substream
    /// isn't in the appropriate state.
    ///
    pub fn write_notification_unbounded(&mut self, notification: Vec<u8>) {
        match &mut self.inner {
            SubstreamInner::NotificationsOut { notifications, .. } => {
                // TODO: expensive copying?
                notifications.extend(leb128::encode_usize(notification.len()));
                notifications.extend(notification.into_iter());
            }
            _ => panic!(),
        }
    }

    /// Returns the number of bytes waiting to be sent out on that substream.
    ///
    /// See the documentation of [`Substream::write_notification_unbounded`] for context.
    ///
    /// # Panic
    ///
    /// Panics if the substream isn't a notifications substream, or if the notifications substream
    /// isn't in the appropriate state.
    ///
    pub fn notification_substream_queued_bytes(&self) -> usize {
        match &self.inner {
            SubstreamInner::NotificationsOut { notifications, .. } => notifications.len(),
            _ => panic!(),
        }
    }

    /// Closes a notifications substream opened after a successful
    /// [`Event::NotificationsOutResult`] or that was accepted using
    /// [`Substream::accept_in_notifications_substream`].
    ///
    /// In the case of an outbound substream, this can be done even when in the negotiation phase,
    /// in other words before the remote has accepted/refused the substream.
    ///
    /// In the case of an inbound substream, notifications can continue to be received. Calling
    /// this function only asynchronously signals to the remote that the substream should be
    /// closed. It does not enforce the closing.
    ///
    /// # Panic
    ///
    /// Panics if the substream isn't a notifications substream, or if the notifications substream
    /// isn't in the appropriate state.
    ///
    pub fn close_notifications_substream(&mut self) {
        match &mut self.inner {
            SubstreamInner::NotificationsOutNegotiating { .. }
            | SubstreamInner::NotificationsOutHandshakeRecv { .. }
            | SubstreamInner::NotificationsOut { .. } => {
                self.inner = SubstreamInner::NotificationsOutClosed;
            }
            SubstreamInner::NotificationsIn { close_desired, .. } if !*close_desired => {
                *close_desired = true
            }
            _ => panic!(),
        };
    }

    /// Queues a ping on the given substream. Must be passed a randomly-generated payload of 32
    /// bytes, the time after which this ping is considered as failed.
    ///
    /// # Panic
    ///
    /// Panics if the substream isn't an outgoing ping substream.
    ///
    pub fn queue_ping(&mut self, payload: &[u8; 32], timeout: TNow) {
        match &mut self.inner {
            SubstreamInner::PingOut { queued_pings, .. }
            | SubstreamInner::PingOutNegotiating { queued_pings, .. }
            | SubstreamInner::PingOutFailed { queued_pings, .. } => {
                queued_pings.push(Some(timeout));
            }
            _ => panic!(),
        }

        match &mut self.inner {
            SubstreamInner::PingOut {
                outgoing_payload,
                expected_payload,
                ..
            } => {
                outgoing_payload.extend(payload.iter().copied());
                expected_payload.extend(payload.iter().copied());
            }
            SubstreamInner::PingOutNegotiating {
                outgoing_payload, ..
            } => {
                outgoing_payload.extend(payload.iter().copied());
            }
            SubstreamInner::PingOutFailed { .. } => {}
            _ => panic!(),
        }
    }

    /// Responds to an incoming request. Must be called in response to a [`Event::RequestIn`].
    ///
    /// Passing an `Err` corresponds, on the other side, to a [`RequestError::SubstreamClosed`].
    pub fn respond_in_request(
        &mut self,
        response: Result<Vec<u8>, ()>,
    ) -> Result<(), RespondInRequestError> {
        match &mut self.inner {
            SubstreamInner::RequestInApiWait { has_length_prefix } => {
                self.inner = SubstreamInner::RequestInRespond {
                    response: if let Ok(response) = response {
                        if *has_length_prefix {
                            let response_len = response.len();
                            leb128::encode_usize(response_len)
                                .chain(response.into_iter())
                                .collect()
                        } else {
                            response.into_iter().collect()
                        }
                    } else {
                        // An error is indicated by closing the substream without even sending
                        // back the length of the response.
                        VecDeque::new()
                    },
                };

                Ok(())
            }
            // TODO: handle substream closed
            _ => panic!(),
        }
    }

    /// Call after an [`Event::InboundNegotiated`] has been emitted in order to indicate the type
    /// of the protocol.
    ///
    /// # Panic
    ///
    /// Panics if the substream is not in the correct state.
    ///
    pub fn set_inbound_ty(&mut self, ty: InboundTy) {
        assert!(matches!(
            self.inner,
            SubstreamInner::InboundNegotiatingApiWait
        ));

        match ty {
            InboundTy::Ping => {
                self.inner = SubstreamInner::PingIn {
                    payload_in: Default::default(),
                    payload_out: VecDeque::with_capacity(32),
                }
            }
            InboundTy::Notifications {
                protocol_index,
                max_handshake_size,
            } => {
                self.inner = SubstreamInner::NotificationsInHandshake {
                    protocol_index,
                    handshake: leb128::FramedInProgress::new(max_handshake_size),
                }
            }
            InboundTy::Request {
                protocol_index,
                request_max_size,
                has_length_prefix,
            } => {
                if has_length_prefix {
                    self.inner = SubstreamInner::RequestInRecv {
                        protocol_index,
                        request: leb128::FramedInProgress::new(request_max_size),
                    };
                } else {
                    self.inner = SubstreamInner::RequestInRecvNoLengthPrefix {
                        protocol_index,
                        request: Vec::with_capacity(cmp::min(request_max_size, 1024)),
                        max_request_size: request_max_size,
                    };
                }
            }
        }
    }
}

impl<TNow, TRqUd, TNotifUd> fmt::Debug for Substream<TNow, TRqUd, TNotifUd>
where
    TRqUd: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.inner {
            SubstreamInner::InboundFailed => f.debug_tuple("incoming-negotiation-failed").finish(),
            SubstreamInner::InboundNegotiating(_) => f.debug_tuple("incoming-negotiating").finish(),
            SubstreamInner::InboundNegotiatingApiWait => {
                f.debug_tuple("incoming-negotiated-api-wait").finish()
            }
            SubstreamInner::NotificationsOutNegotiating { .. } => {
                f.debug_tuple("notifications-out-negotiating").finish()
            }
            SubstreamInner::NotificationsOutHandshakeRecv { .. } => {
                f.debug_tuple("notifications-out-handshake-recv").finish()
            }
            SubstreamInner::NotificationsOutNegotiationFailed { .. } => f
                .debug_tuple("notifications-out-negotiation-failed")
                .finish(),
            SubstreamInner::NotificationsOut { .. } => f.debug_tuple("notifications-out").finish(),
            SubstreamInner::NotificationsOutClosed { .. } => {
                f.debug_tuple("notifications-out-closed").finish()
            }
            SubstreamInner::NotificationsInHandshake { protocol_index, .. } => f
                .debug_tuple("notifications-in-handshake")
                .field(protocol_index)
                .finish(),
            SubstreamInner::NotificationsInWait { .. } => {
                f.debug_tuple("notifications-in-wait").finish()
            }
            SubstreamInner::NotificationsIn { .. } => f.debug_tuple("notifications-in").finish(),
            SubstreamInner::NotificationsInRefused => {
                f.debug_tuple("notifications-in-refused").finish()
            }
            SubstreamInner::NotificationsInClosed => {
                f.debug_tuple("notifications-in-closed").finish()
            }
            SubstreamInner::RequestOutNegotiating { user_data, .. }
            | SubstreamInner::RequestOut { user_data, .. } => {
                f.debug_tuple("request-out").field(&user_data).finish()
            }
            SubstreamInner::RequestInRecv { protocol_index, .. }
            | SubstreamInner::RequestInRecvNoLengthPrefix { protocol_index, .. } => {
                f.debug_tuple("request-in").field(protocol_index).finish()
            }
            SubstreamInner::RequestInRespond { .. } => f.debug_tuple("request-in-respond").finish(),
            SubstreamInner::RequestInApiWait { .. } => f.debug_tuple("request-in").finish(),
            SubstreamInner::PingIn { .. } => f.debug_tuple("ping-in").finish(),
            SubstreamInner::PingOutNegotiating { .. } => {
                f.debug_tuple("ping-out-negotiating").finish()
            }
            SubstreamInner::PingOutFailed { .. } => f.debug_tuple("ping-out-failed").finish(),
            SubstreamInner::PingOut { .. } => f.debug_tuple("ping-out").finish(),
        }
    }
}

/// Event that happened on the connection. See [`Substream::read_write`].
#[must_use]
#[derive(Debug)]
pub enum Event<TRqUd, TNotifUd> {
    /// Error while receiving an inbound substream.
    InboundError(InboundError),

    /// An inbound substream has successfully negotiated a protocol. Call
    /// [`Substream::set_inbound_ty`] in order to resume.
    InboundNegotiated(String),

    /// Received a request in the context of a request-response protocol.
    RequestIn {
        /// Index of the request-response protocol the request was sent on.
        protocol_index: usize,
        /// Bytes of the request. Its interpretation is out of scope of this module.
        request: Vec<u8>,
    },

    /// Received a response to a previously emitted request on a request-response protocol.
    Response {
        /// Bytes of the response. Its interpretation is out of scope of this module.
        response: Result<Vec<u8>, RequestError>,
        /// Value that was passed to [`Substream::request_out`].
        user_data: TRqUd,
    },

    /// Remote has opened an inbound notifications substream.
    ///
    /// Either [`Substream::accept_in_notifications_substream`] or
    /// [`Substream::reject_in_notifications_substream`] must be called in the near future in
    /// order to accept or reject this substream.
    NotificationsInOpen {
        /// Index of the notifications protocol concerned by the substream.
        protocol_index: usize,
        /// Handshake sent by the remote. Its interpretation is out of scope of this module.
        handshake: Vec<u8>,
    },
    /// Remote has canceled an inbound notifications substream opening.
    ///
    /// This can only happen after [`Event::NotificationsInOpen`].
    /// [`Substream::accept_in_notifications_substream`] or
    /// [`Substream::reject_in_notifications_substream`] should not be called on this substream.
    NotificationsInOpenCancel,
    /// Remote has sent a notification on an inbound notifications substream. Can only happen
    /// after the substream has been accepted.
    // TODO: give a way to back-pressure notifications
    NotificationIn {
        /// Notification sent by the remote.
        notification: Vec<u8>,
    },
    /// Remote has closed an inbound notifications substream opening. No more notifications will
    /// be received.
    ///
    /// This can only happen after the substream has been accepted.
    NotificationsInClose {
        /// If `Ok`, the substream has been closed gracefully. If `Err`, a problem happened.
        outcome: Result<(), NotificationsInClosedErr>,
    },

    /// Remote has accepted or refused a substream opened with [`Substream::notifications_out`].
    ///
    /// If `Ok`, it is now possible to send notifications on this substream.
    NotificationsOutResult {
        /// If `Ok`, contains the handshake sent back by the remote. Its interpretation is out of
        /// scope of this module.
        result: Result<Vec<u8>, (NotificationsOutErr, TNotifUd)>,
    },
    /// Remote has closed an outgoing notifications substream, meaning that it demands the closing
    /// of the substream.
    NotificationsOutCloseDemanded,
    /// Remote has reset an outgoing notifications substream. The substream is instantly closed.
    NotificationsOutReset {
        /// Value that was passed to [`Substream::notifications_out`].
        user_data: TNotifUd,
    },

    /// A ping has been successfully answered by the remote.
    PingOutSuccess,
    /// Remote has failed to answer one or more pings.
    PingOutError {
        /// Number of pings that the remote has failed to answer.
        num_pings: NonZeroUsize,
    },
}

/// Type of inbound protocol.
pub enum InboundTy {
    Ping,
    Request {
        protocol_index: usize,
        /// Whether the incoming request is prefixed by its length as a LEB128.
        has_length_prefix: bool,
        /// Maximum allowed size of the request.
        /// Does not include the length prefix, if any.
        request_max_size: usize,
    },
    Notifications {
        protocol_index: usize,
        max_handshake_size: usize,
    },
}

/// Error that can happen while processing an inbound substream.
#[derive(Debug, Clone, derive_more::Display)]
pub enum InboundError {
    /// Error during protocol negotiation.
    #[display(fmt = "Protocol negotiation error: {}", _0)]
    NegotiationError(multistream_select::Error),
    /// Error while receiving an inbound request.
    #[display(fmt = "Error receiving inbound request: {}", _0)]
    RequestInLebError(leb128::FramedError),
    /// Unexpected end of file while receiving an inbound request.
    RequestInExpectedEof,
    /// Inbound request with no length prefix is too large.
    RequestInNoLenPrefixTooLarge,
    /// Error while receiving an inbound notifications substream handshake.
    #[display(
        fmt = "Error while receiving an inbound notifications substream handshake: {}",
        error
    )]
    NotificationsInError {
        /// Error that happened.
        error: leb128::FramedError,
        /// Index of the protocol that was passed in the [`InboundTy::Notifications`].
        protocol_index: usize,
    },
    /// Unexpected end of file while receiving an inbound notifications substream handshake.
    #[display(
        fmt = "Unexpected end of file while receiving an inbound notifications substream handshake"
    )]
    NotificationsInUnexpectedEof {
        /// Index of the protocol that was passed in the [`InboundTy::Notifications`].
        protocol_index: usize,
    },
}

/// Error that can happen during a request in a request-response scheme.
#[derive(Debug, Clone, derive_more::Display)]
pub enum RequestError {
    /// Remote hasn't answered in time.
    Timeout,
    /// Remote doesn't support this protocol.
    ProtocolNotAvailable,
    /// Remote has decided to close the substream. This most likely indicates that the remote
    /// is unwilling the respond to the request.
    SubstreamClosed,
    /// Remote has decided to `RST` the substream. This most likely indicates that the remote has
    /// detected a protocol error.
    SubstreamReset,
    /// Error during protocol negotiation.
    #[display(fmt = "Protocol negotiation error: {}", _0)]
    NegotiationError(multistream_select::Error),
    /// Error while receiving the response.
    #[display(fmt = "Error while receiving response: {}", _0)]
    ResponseLebError(leb128::FramedError),
}

impl RequestError {
    /// Returns `true` if the error is caused by a faulty behavior by the remote. Returns `false`
    /// if the error can happen in normal situations.
    pub fn is_protocol_error(&self) -> bool {
        match self {
            RequestError::Timeout => false, // Remote is likely overloaded.
            RequestError::ProtocolNotAvailable => true,
            RequestError::SubstreamClosed => false,
            RequestError::SubstreamReset => true,
            RequestError::NegotiationError(_) => true,
            RequestError::ResponseLebError(_) => true,
        }
    }
}

/// Error potentially returned by [`Substream::respond_in_request`].
#[derive(Debug, derive_more::Display)]
pub enum RespondInRequestError {
    /// The substream has already been closed.
    SubstreamClosed,
}

/// Error that can happen when trying to open an outbound notifications substream.
#[derive(Debug, Clone, derive_more::Display)]
pub enum NotificationsOutErr {
    /// Remote took too long to perform the handshake.
    Timeout,
    /// Remote has refused the handshake by closing the substream.
    RefusedHandshake,
    /// Remote has indicated that it doesn't support the requested protocol.
    ProtocolNotAvailable,
    /// Error during the multistream-select handshake.
    #[display(fmt = "Protocol negotiation error: {}", _0)]
    NegotiationError(multistream_select::Error),
    /// Substream has been reset during the negotiation.
    SubstreamReset,
    /// Error while receiving the remote's handshake.
    #[display(fmt = "Error while receiving remote handshake: {}", _0)]
    HandshakeRecvError(leb128::FramedError),
}

/// Reason why an inbound notifications substream has been closed.
#[derive(Debug, Clone, derive_more::Display)]
pub enum NotificationsInClosedErr {
    /// Error in the protocol.
    #[display(fmt = "Error while receiving notification: {}", _0)]
    ProtocolError(leb128::FramedError),
    /// Substream has been reset.
    SubstreamReset,
}
