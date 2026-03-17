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

use alloc::{borrow::ToOwned as _, collections::VecDeque, string::String, vec::Vec};
use core::{
    fmt, mem,
    num::NonZero,
    ops::{Add, Sub},
    time::Duration,
};

/// State machine containing the state of a single substream of an established connection.
pub struct Substream<TNow> {
    inner: SubstreamInner<TNow>,
}

enum SubstreamInner<TNow> {
    /// Protocol negotiation in progress in an incoming substream.
    InboundNegotiating(multistream_select::InProgress<String>, bool),
    /// Protocol negotiation in an incoming substream is in progress, and an
    /// [`Event::InboundNegotiated`] has been emitted. Now waiting for the API user to indicate
    /// whether the protocol is supported and if so the type of substream.
    InboundNegotiatingApiWait(multistream_select::ListenerAcceptOrDeny<String>),
    /// Protocol negotiation in an incoming substream is in progress, and the API user has
    /// indicated that the given protocol is supported. Finishing the handshake before switching
    /// to a different state.
    InboundNegotiatingAccept(multistream_select::InProgress<String>, InboundTy),
    /// Incoming substream has failed to negotiate a protocol. Waiting for a close from the remote.
    /// In order to save a round-trip time, the remote might assume that the protocol negotiation
    /// has succeeded. As such, it might send additional data on this substream that should be
    /// ignored.
    InboundFailed,

    /// Failure to negotiate an outbound notifications substream.
    NotificationsOutNegotiationFailed,
    /// A notifications protocol is being negotiated or has been negotiated on a substream. Either
    /// a successful handshake or an abrupt closing is now expected.
    NotificationsOutHandshakeRecv {
        /// When the opening will time out in the absence of response.
        timeout: TNow,
        /// State of the protocol negotiation. `None` if the handshake has already finished.
        negotiation: Option<multistream_select::InProgress<String>>,
        /// Size of the remote handshake, if known. If `Some`, we have already extracted the length
        /// from the incoming buffer.
        handshake_in_size: Option<usize>,
        /// Maximum allowed size of the remote handshake.
        handshake_in_max_size: usize,
        /// Handshake payload to write out.
        handshake_out: VecDeque<u8>,
    },
    /// A notifications protocol has been negotiated, and the remote accepted it. Can now send
    /// notifications.
    NotificationsOut {
        /// Notifications to write out.
        notifications: VecDeque<u8>,
        /// If `true`, we have reported a [`Event::NotificationsOutCloseDemanded`] event in the
        /// past and shouldn't report one again.
        close_demanded_by_remote: bool,
    },
    /// A notifications protocol has been closed. Waiting for the remote to close it as well.
    NotificationsOutClosed,

    /// A notifications protocol has been negotiated on an incoming substream. A handshake from
    /// the remote is expected.
    NotificationsInHandshake {
        /// Size of the handshake, if known. If `Some`, we have already extracted the length
        /// from the incoming buffer.
        handshake_size: Option<usize>,
        /// Maximum allowed size of the handshake.
        handshake_max_size: usize,
    },
    /// A handshake on a notifications protocol has been received. Now waiting for an action from
    /// the API user.
    NotificationsInWait,
    /// API user has refused an incoming substream. Waiting for a close from the remote.
    /// In order to save a round-trip time, the remote might assume that the protocol negotiation
    /// has succeeded. As such, it might send additional data on this substream that should be
    /// ignored.
    NotificationsInRefused,
    /// A notifications protocol has been negotiated on a substream. Remote can now send
    /// notifications.
    NotificationsIn {
        /// If `Some`, the local node wants to shut down the substream. If the given timeout is
        /// reached, the closing is forced.
        close_desired_timeout: Option<TNow>,
        /// Size of the next notification, if known. If `Some`, we have already extracted the
        /// length from the incoming buffer.
        next_notification_size: Option<usize>,
        /// Handshake payload to write out.
        handshake: VecDeque<u8>,
        /// Maximum size, in bytes, allowed for each notification.
        max_notification_size: usize,
    },
    /// An inbound notifications protocol was open, but then the remote closed its writing side.
    NotificationsInClosed,

    /// Outgoing request.
    RequestOut {
        /// When the request will time out in the absence of response.
        timeout: TNow,
        /// State of the protocol negotiation. `None` if the negotiation has finished.
        negotiation: Option<multistream_select::InProgress<String>>,
        /// Request payload to write out.
        request: VecDeque<u8>,
        /// Size of the response, if known. If `Some`, we have already extracted the length
        /// from the incoming buffer.
        response_size: Option<usize>,
        /// Maximum allowed size of the response.
        response_max_size: usize,
    },

    /// A request-response protocol has been negotiated on an inbound substream. A request is now
    /// expected.
    RequestInRecv {
        /// Size of the request, if known. If `Some`, we have already extracted the length
        /// from the incoming buffer.
        request_size: Option<usize>,
        /// Maximum allowed size of the request.
        request_max_size: usize,
    },
    /// Similar to [`SubstreamInner::RequestInRecv`], but doesn't expect any request body.
    /// Immediately reports an event and switches to [`SubstreamInner::RequestInApiWait`].
    RequestInRecvEmpty,
    /// A request has been sent by the remote. API user must now send back the response.
    RequestInApiWait,
    /// A request has been sent by the remote. Sending back the response.
    RequestInRespond {
        /// Response being sent back.
        response: VecDeque<u8>,
    },

    /// Inbound ping substream. Waiting for the ping payload to be received.
    PingIn { payload_out: VecDeque<u8> },

    /// Failed to negotiate a protocol for an outgoing ping substream.
    PingOutFailed {
        /// FIFO queue of pings that will immediately fail.
        queued_pings: smallvec::SmallVec<[Option<(TNow, Duration)>; 1]>,
    },
    /// Outbound ping substream.
    PingOut {
        /// State of the protocol negotiation. `None` if the handshake is already finished.
        negotiation: Option<multistream_select::InProgress<String>>,
        /// Payload of the queued pings that remains to write out.
        outgoing_payload: VecDeque<u8>,
        /// Data waiting to be received from the remote. Any mismatch will cause an error.
        /// Contains even the data that is still queued in `outgoing_payload`.
        expected_payload: VecDeque<Vec<u8>>,
        /// FIFO queue of pings waiting to be answered. For each ping, when the ping was queued
        /// and after how long it will time out, or `None` if the timeout has already occurred.
        queued_pings: smallvec::SmallVec<[Option<(TNow, Duration)>; 1]>,
    },
}

impl<TNow> Substream<TNow>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Initializes an new `ingoing` substream.
    ///
    /// After the remote has requested a protocol, an [`Event::InboundNegotiated`] event will be
    /// generated, after which [`Substream::accept_inbound`] or [`Substream::reject_inbound`] must
    /// be called in order to indicate whether the protocol is accepted, and if so the nature of
    /// the negotiated protocol.
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
    pub fn ingoing(max_protocol_name_len: usize) -> Self {
        let negotiation =
            multistream_select::InProgress::new(multistream_select::Config::Listener {
                max_protocol_name_len,
            });

        Substream {
            inner: SubstreamInner::InboundNegotiating(negotiation, false),
        }
    }

    /// Initializes an outgoing notifications substream.
    ///
    /// After the remote has sent back a handshake or after an error occurred, an
    /// [`Event::NotificationsOutResult`] event will be generated locally.
    ///
    /// If this event contains an `Ok`, then [`Substream::write_notification_unbounded`],
    /// [`Substream::notification_substream_queued_bytes`] and
    /// [`Substream::close_out_notifications_substream`] can be used, and
    /// [`Event::NotificationsOutCloseDemanded`] and [`Event::NotificationsOutReset`] can be
    /// generated.
    pub fn notifications_out(
        timeout: TNow,
        requested_protocol: String,
        handshake: Vec<u8>,
        max_handshake_size: usize,
    ) -> Self {
        // TODO: check `handshake < max_handshake_size`?

        let negotiation = multistream_select::InProgress::new(multistream_select::Config::Dialer {
            requested_protocol,
        });

        let handshake_out = {
            let handshake_len = handshake.len();
            leb128::encode_usize(handshake_len)
                .chain(handshake)
                .collect::<VecDeque<_>>()
        };

        Substream {
            inner: SubstreamInner::NotificationsOutHandshakeRecv {
                timeout,
                negotiation: Some(negotiation),
                handshake_in_size: None,
                handshake_in_max_size: max_handshake_size,
                handshake_out,
            },
        }
    }

    /// Initializes an outgoing request substream.
    ///
    /// After the remote has sent back a response or after an error occurred, an [`Event::Response`]
    /// event will be generated locally. The `user_data` parameter will be passed back.
    ///
    /// If the `request` is `None`, then nothing at all will be written out, not even a length
    /// prefix. If the `request` is `Some`, then a length prefix will be written out. Consequently,
    /// `Some(&[])` writes a single `0` for the request.
    pub fn request_out(
        requested_protocol: String,
        timeout: TNow,
        request: Option<Vec<u8>>,
        max_response_size: usize,
    ) -> Self {
        let negotiation = multistream_select::InProgress::new(multistream_select::Config::Dialer {
            requested_protocol,
        });

        let request_payload = if let Some(request) = request {
            let request_len = request.len();
            leb128::encode_usize(request_len)
                .chain(request)
                .collect::<VecDeque<_>>()
        } else {
            VecDeque::new()
        };

        Substream {
            inner: SubstreamInner::RequestOut {
                timeout,
                negotiation: Some(negotiation),
                request: request_payload,
                response_size: None,
                response_max_size: max_response_size,
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
            inner: SubstreamInner::PingOut {
                negotiation: Some(negotiation),
                outgoing_payload: VecDeque::with_capacity(32),
                expected_payload: VecDeque::with_capacity(32),
                queued_pings: smallvec::SmallVec::new(),
            },
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
        read_write: &mut read_write::ReadWrite<TNow>,
    ) -> (Option<Self>, Option<Event>) {
        let (me, event) = self.read_write2(read_write);
        (me.map(|inner| Substream { inner }), event)
    }

    fn read_write2(
        self,
        read_write: &mut read_write::ReadWrite<TNow>,
    ) -> (Option<SubstreamInner<TNow>>, Option<Event>) {
        match self.inner {
            SubstreamInner::InboundNegotiating(nego, was_rejected_already) => {
                match nego.read_write(read_write) {
                    Ok(multistream_select::Negotiation::InProgress(nego)) => (
                        Some(SubstreamInner::InboundNegotiating(
                            nego,
                            was_rejected_already,
                        )),
                        None,
                    ),
                    Ok(multistream_select::Negotiation::ListenerAcceptOrDeny(accept_deny)) => {
                        // TODO: maybe avoid cloning the protocol name?
                        let protocol = accept_deny.requested_protocol().to_owned();
                        (
                            Some(SubstreamInner::InboundNegotiatingApiWait(accept_deny)),
                            Some(Event::InboundNegotiated(protocol)),
                        )
                    }
                    Ok(multistream_select::Negotiation::Success) => {
                        // Unreachable, as we expect a `ListenerAcceptOrDeny`.
                        unreachable!()
                    }
                    Ok(multistream_select::Negotiation::NotAvailable) => {
                        // Unreachable in listener mode.
                        unreachable!()
                    }
                    Err(_) if was_rejected_already => {
                        // If the negotiation was already rejected once, it is likely that the
                        // multistream-select protocol error is due to the fact that the remote
                        // assumes that the multistream-select negotiation always succeeds. As such,
                        // we treat this situation as "negotiation has failed gracefully".
                        (Some(SubstreamInner::InboundFailed), None)
                    }
                    Err(err) => (
                        None,
                        Some(Event::InboundError {
                            error: InboundError::NegotiationError(err),
                            was_accepted: false,
                        }),
                    ),
                }
            }
            SubstreamInner::InboundNegotiatingApiWait(accept_deny) => (
                Some(SubstreamInner::InboundNegotiatingApiWait(accept_deny)),
                None,
            ),
            SubstreamInner::InboundNegotiatingAccept(nego, inbound_ty) => {
                match nego.read_write(read_write) {
                    Ok(multistream_select::Negotiation::InProgress(nego)) => (
                        Some(SubstreamInner::InboundNegotiatingAccept(nego, inbound_ty)),
                        None,
                    ),
                    Ok(multistream_select::Negotiation::ListenerAcceptOrDeny(_)) => {
                        // Can't be reached again, as we have already accepted the protocol.
                        unreachable!()
                    }
                    Ok(multistream_select::Negotiation::Success) => match inbound_ty {
                        InboundTy::Ping => (
                            Some(SubstreamInner::PingIn {
                                payload_out: VecDeque::with_capacity(32),
                            }),
                            None,
                        ),
                        InboundTy::Notifications { max_handshake_size } => (
                            Some(SubstreamInner::NotificationsInHandshake {
                                handshake_size: None,
                                handshake_max_size: max_handshake_size,
                            }),
                            None,
                        ),
                        InboundTy::Request { request_max_size } => {
                            if let Some(request_max_size) = request_max_size {
                                (
                                    Some(SubstreamInner::RequestInRecv {
                                        request_max_size,
                                        request_size: None,
                                    }),
                                    None,
                                )
                            } else {
                                (Some(SubstreamInner::RequestInRecvEmpty), None)
                            }
                        }
                    },
                    Ok(multistream_select::Negotiation::NotAvailable) => {
                        // Unreachable in listener mode.
                        unreachable!()
                    }
                    Err(err) => (
                        None,
                        Some(Event::InboundError {
                            error: InboundError::NegotiationError(err),
                            was_accepted: true,
                        }),
                    ),
                }
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
                timeout,
                mut negotiation,
                mut handshake_in_size,
                handshake_in_max_size,
                mut handshake_out,
            } => {
                if timeout < read_write.now {
                    read_write.wake_up_asap();
                    return (
                        Some(SubstreamInner::NotificationsOutNegotiationFailed),
                        Some(Event::NotificationsOutResult {
                            result: Err(NotificationsOutErr::Timeout),
                        }),
                    );
                }

                if let Some(extracted_negotiation) = negotiation.take() {
                    match extracted_negotiation.read_write(read_write) {
                        Ok(multistream_select::Negotiation::InProgress(nego)) => {
                            negotiation = Some(nego)
                        }
                        Ok(multistream_select::Negotiation::ListenerAcceptOrDeny(_)) => {
                            // Never happens when dialing.
                            unreachable!()
                        }
                        Ok(multistream_select::Negotiation::Success) => {}
                        Ok(multistream_select::Negotiation::NotAvailable) => {
                            read_write.wake_up_asap();
                            return (
                                Some(SubstreamInner::NotificationsOutNegotiationFailed),
                                Some(Event::NotificationsOutResult {
                                    result: Err(NotificationsOutErr::ProtocolNotAvailable),
                                }),
                            );
                        }
                        Err(err) => {
                            return (
                                None,
                                Some(Event::NotificationsOutResult {
                                    result: Err(NotificationsOutErr::NegotiationError(err)),
                                }),
                            );
                        }
                    }
                }

                if negotiation
                    .as_ref()
                    .map_or(true, |n| n.can_write_protocol_data())
                {
                    read_write.write_from_vec_deque(&mut handshake_out);
                }

                if negotiation.is_none() {
                    if read_write.expected_incoming_bytes.is_none() {
                        read_write.wake_up_asap();
                        return (
                            Some(SubstreamInner::NotificationsOutNegotiationFailed),
                            Some(Event::NotificationsOutResult {
                                result: Err(NotificationsOutErr::RefusedHandshake),
                            }),
                        );
                    }

                    // Don't actually process incoming data before handshake is sent out, in order
                    // to not accidentally perform a state transition.
                    if !handshake_out.is_empty() {
                        return (
                            Some(SubstreamInner::NotificationsOutHandshakeRecv {
                                timeout,
                                negotiation,
                                handshake_in_size,
                                handshake_in_max_size,
                                handshake_out,
                            }),
                            None,
                        );
                    }

                    if let Some(handshake_in_size) = handshake_in_size {
                        match read_write.incoming_bytes_take(handshake_in_size) {
                            Ok(Some(remote_handshake)) => {
                                read_write.wake_up_asap();
                                return (
                                    Some(SubstreamInner::NotificationsOut {
                                        notifications: VecDeque::new(),
                                        close_demanded_by_remote: false,
                                    }),
                                    Some(Event::NotificationsOutResult {
                                        result: Ok(remote_handshake),
                                    }),
                                );
                            }
                            Ok(None) => {}
                            Err(read_write::IncomingBytesTakeError::ReadClosed) => {
                                read_write.wake_up_asap();
                                return (
                                    Some(SubstreamInner::NotificationsOutNegotiationFailed),
                                    Some(Event::NotificationsOutResult {
                                        result: Err(NotificationsOutErr::RefusedHandshake),
                                    }),
                                );
                            }
                        }
                    } else {
                        match read_write.incoming_bytes_take_leb128(handshake_in_max_size) {
                            Ok(Some(s)) => handshake_in_size = Some(s),
                            Ok(None) => {}
                            Err(error) => return (
                                None,
                                Some(Event::Response {
                                    response: Err(match error {
                                        read_write::IncomingBytesTakeLeb128Error::InvalidLeb128 => {
                                            RequestError::ResponseInvalidLeb128
                                        }
                                        read_write::IncomingBytesTakeLeb128Error::ReadClosed => {
                                            RequestError::SubstreamClosed
                                        }
                                        read_write::IncomingBytesTakeLeb128Error::TooLarge => {
                                            RequestError::ResponseTooLarge
                                        }
                                    }),
                                }),
                            ),
                        }
                    }
                }

                read_write.wake_up_after(&timeout);

                (
                    Some(SubstreamInner::NotificationsOutHandshakeRecv {
                        timeout,
                        negotiation,
                        handshake_in_size,
                        handshake_in_max_size,
                        handshake_out,
                    }),
                    None,
                )
            }
            SubstreamInner::NotificationsOut {
                mut notifications,
                close_demanded_by_remote,
            } => {
                // Receiving data on an outgoing substream is forbidden by the protocol.
                read_write.discard_all_incoming();
                read_write.write_from_vec_deque(&mut notifications);

                // If this debug assertion fails, it means that `expected_incoming_bytes` was `None` in
                // the past then became `Some` again.
                debug_assert!(
                    !close_demanded_by_remote || read_write.expected_incoming_bytes.is_none()
                );

                if !close_demanded_by_remote && read_write.expected_incoming_bytes.is_none() {
                    read_write.wake_up_asap();
                    return (
                        Some(SubstreamInner::NotificationsOut {
                            notifications,
                            close_demanded_by_remote: true,
                        }),
                        Some(Event::NotificationsOutCloseDemanded),
                    );
                }

                (
                    Some(SubstreamInner::NotificationsOut {
                        notifications,
                        close_demanded_by_remote,
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

            SubstreamInner::RequestOut {
                timeout,
                mut negotiation,
                mut request,
                mut response_size,
                response_max_size,
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
                        }),
                    );
                }

                if let Some(extracted_nego) = negotiation.take() {
                    match extracted_nego.read_write(read_write) {
                        Ok(multistream_select::Negotiation::InProgress(nego)) => {
                            negotiation = Some(nego)
                        }
                        Ok(multistream_select::Negotiation::ListenerAcceptOrDeny(_)) => {
                            // Never happens when dialing.
                            unreachable!()
                        }
                        Ok(multistream_select::Negotiation::Success) => {}
                        Ok(multistream_select::Negotiation::NotAvailable) => {
                            return (
                                None,
                                Some(Event::Response {
                                    response: Err(RequestError::ProtocolNotAvailable),
                                }),
                            );
                        }
                        Err(err) => {
                            return (
                                None,
                                Some(Event::Response {
                                    response: Err(RequestError::NegotiationError(err)),
                                }),
                            );
                        }
                    }
                }

                if negotiation
                    .as_ref()
                    .map_or(true, |n| n.can_write_protocol_data())
                {
                    if request.is_empty() {
                        read_write.close_write();
                    } else {
                        read_write.write_from_vec_deque(&mut request);
                    }
                }

                if negotiation.is_none() {
                    if let Some(response_size) = response_size {
                        match read_write.incoming_bytes_take(response_size) {
                            Ok(Some(response)) => {
                                return (
                                    None,
                                    Some(Event::Response {
                                        response: Ok(response),
                                    }),
                                );
                            }
                            Ok(None) => {}
                            Err(read_write::IncomingBytesTakeError::ReadClosed) => {
                                return (
                                    None,
                                    Some(Event::Response {
                                        response: Err(RequestError::SubstreamClosed),
                                    }),
                                );
                            }
                        }
                    } else {
                        match read_write.incoming_bytes_take_leb128(response_max_size) {
                            Ok(Some(s)) => response_size = Some(s),
                            Ok(None) => {}
                            Err(error) => return (
                                None,
                                Some(Event::Response {
                                    response: Err(match error {
                                        read_write::IncomingBytesTakeLeb128Error::InvalidLeb128 => {
                                            RequestError::ResponseInvalidLeb128
                                        }
                                        read_write::IncomingBytesTakeLeb128Error::ReadClosed => {
                                            RequestError::SubstreamClosed
                                        }
                                        read_write::IncomingBytesTakeLeb128Error::TooLarge => {
                                            RequestError::ResponseTooLarge
                                        }
                                    }),
                                }),
                            ),
                        }
                    }
                }

                read_write.wake_up_after(&timeout);

                (
                    Some(SubstreamInner::RequestOut {
                        timeout,
                        negotiation,
                        request,
                        response_size,
                        response_max_size,
                    }),
                    None,
                )
            }

            SubstreamInner::RequestInRecv {
                mut request_size,
                request_max_size,
            } => {
                if let Some(request_size) = request_size {
                    match read_write.incoming_bytes_take(request_size) {
                        Ok(Some(request)) => {
                            return (
                                Some(SubstreamInner::RequestInApiWait),
                                Some(Event::RequestIn { request }),
                            );
                        }
                        Ok(None) => {}
                        Err(read_write::IncomingBytesTakeError::ReadClosed) => {
                            return (
                                None,
                                Some(Event::InboundError {
                                    error: InboundError::SubstreamClosed,
                                    was_accepted: true,
                                }),
                            );
                        }
                    }
                } else {
                    match read_write.incoming_bytes_take_leb128(request_max_size) {
                        Ok(Some(s)) => request_size = Some(s),
                        Ok(None) => {}
                        Err(error) => {
                            return (
                                None,
                                Some(Event::InboundError {
                                    error: InboundError::RequestInLebError(error),
                                    was_accepted: true,
                                }),
                            );
                        }
                    }
                }

                (
                    Some(SubstreamInner::RequestInRecv {
                        request_max_size,
                        request_size,
                    }),
                    None,
                )
            }
            SubstreamInner::RequestInRecvEmpty => (
                Some(SubstreamInner::RequestInApiWait),
                Some(Event::RequestIn {
                    request: Vec::new(),
                }),
            ),
            SubstreamInner::RequestInApiWait => (Some(SubstreamInner::RequestInApiWait), None),
            SubstreamInner::RequestInRespond { mut response } => {
                if response.is_empty() {
                    read_write.close_write();
                    (None, None)
                } else {
                    read_write.write_from_vec_deque(&mut response);
                    (Some(SubstreamInner::RequestInRespond { response }), None)
                }
            }

            SubstreamInner::NotificationsInHandshake {
                handshake_max_size,
                mut handshake_size,
            } => {
                if let Some(handshake_size) = handshake_size {
                    match read_write.incoming_bytes_take(handshake_size) {
                        Ok(Some(handshake)) => {
                            return (
                                Some(SubstreamInner::NotificationsInWait),
                                Some(Event::NotificationsInOpen { handshake }),
                            );
                        }
                        Ok(None) => {}
                        Err(read_write::IncomingBytesTakeError::ReadClosed) => {
                            return (
                                None,
                                Some(Event::InboundError {
                                    error: InboundError::SubstreamClosed,
                                    was_accepted: true,
                                }),
                            );
                        }
                    }
                } else {
                    match read_write.incoming_bytes_take_leb128(handshake_max_size) {
                        Ok(Some(s)) => handshake_size = Some(s),
                        Ok(None) => {}
                        Err(error) => {
                            return (
                                None,
                                Some(Event::InboundError {
                                    error: InboundError::NotificationsInError { error },
                                    was_accepted: true,
                                }),
                            );
                        }
                    }
                }

                (
                    Some(SubstreamInner::NotificationsInHandshake {
                        handshake_max_size,
                        handshake_size,
                    }),
                    None,
                )
            }
            SubstreamInner::NotificationsInWait => {
                // Incoming data isn't processed, potentially back-pressuring it.
                if read_write.expected_incoming_bytes.is_some() {
                    (Some(SubstreamInner::NotificationsInWait), None)
                } else {
                    read_write.wake_up_asap();
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
                close_desired_timeout,
                mut next_notification_size,
                mut handshake,
                max_notification_size,
            } => {
                read_write.write_from_vec_deque(&mut handshake);

                if close_desired_timeout
                    .as_ref()
                    .map_or(false, |timeout| *timeout <= read_write.now)
                {
                    read_write.wake_up_asap();
                    return (
                        Some(SubstreamInner::NotificationsInClosed),
                        Some(Event::NotificationsInClose {
                            outcome: Err(NotificationsInClosedErr::CloseDesiredTimeout),
                        }),
                    );
                }

                if close_desired_timeout.is_some() && handshake.is_empty() {
                    read_write.close_write();
                }

                let mut notification = None;

                if let Some(sz) = next_notification_size {
                    match read_write.incoming_bytes_take(sz) {
                        Ok(Some(notif)) => {
                            read_write.wake_up_asap();
                            notification = Some(notif);
                            next_notification_size = None;
                        }
                        Ok(None) => {}
                        Err(read_write::IncomingBytesTakeError::ReadClosed) => {
                            read_write.wake_up_asap();
                            return (
                                Some(SubstreamInner::NotificationsInClosed),
                                Some(Event::NotificationsInClose {
                                    outcome: Err(NotificationsInClosedErr::SubstreamClosed),
                                }),
                            );
                        }
                    }
                } else {
                    match read_write.incoming_bytes_take_leb128(max_notification_size) {
                        Ok(Some(s)) => next_notification_size = Some(s),
                        Ok(None) => {}
                        Err(error) => {
                            read_write.wake_up_asap();
                            return (
                                Some(SubstreamInner::NotificationsInClosed),
                                Some(Event::NotificationsInClose {
                                    outcome: Err(NotificationsInClosedErr::ProtocolError(error)),
                                }),
                            );
                        }
                    }
                }

                (
                    Some(SubstreamInner::NotificationsIn {
                        close_desired_timeout,
                        next_notification_size,
                        handshake,
                        max_notification_size,
                    }),
                    notification.map(|n| Event::NotificationIn { notification: n }),
                )
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

            SubstreamInner::PingIn { mut payload_out } => {
                // Inbound ping substream.
                // The ping protocol consists in sending 32 bytes of data, which the remote has
                // to send back.
                read_write.write_from_vec_deque(&mut payload_out);
                if payload_out.is_empty() {
                    if let Ok(Some(ping)) = read_write.incoming_bytes_take(32) {
                        payload_out.extend(ping);
                    }
                }

                (Some(SubstreamInner::PingIn { payload_out }), None)
            }

            SubstreamInner::PingOutFailed { mut queued_pings } => {
                read_write.close_write();
                if !queued_pings.is_empty() {
                    queued_pings.remove(0);
                    read_write.wake_up_asap();
                    (
                        Some(SubstreamInner::PingOutFailed { queued_pings }),
                        Some(Event::PingOutError {
                            num_pings: NonZero::<usize>::new(1).unwrap(),
                        }),
                    )
                } else {
                    (Some(SubstreamInner::PingOutFailed { queued_pings }), None)
                }
            }
            SubstreamInner::PingOut {
                mut negotiation,
                mut queued_pings,
                mut outgoing_payload,
                mut expected_payload,
            } => {
                if let Some(extracted_negotiation) = negotiation.take() {
                    match extracted_negotiation.read_write(read_write) {
                        Ok(multistream_select::Negotiation::InProgress(nego)) => {
                            negotiation = Some(nego)
                        }
                        Ok(multistream_select::Negotiation::ListenerAcceptOrDeny(_)) => {
                            // Never happens when dialing.
                            unreachable!()
                        }
                        Ok(multistream_select::Negotiation::Success) => {}
                        Ok(multistream_select::Negotiation::NotAvailable) => {
                            read_write.wake_up_asap();
                            return (Some(SubstreamInner::PingOutFailed { queued_pings }), None);
                        }
                        Err(_) => {
                            read_write.wake_up_asap();
                            return (Some(SubstreamInner::PingOutFailed { queued_pings }), None);
                        }
                    }
                }

                if negotiation
                    .as_ref()
                    .map_or(true, |n| n.can_write_protocol_data())
                {
                    read_write.write_from_vec_deque(&mut outgoing_payload);
                }

                // We check the timeouts before checking the incoming data, as otherwise pings
                // might succeed after their timeout.
                for timeout in queued_pings.iter_mut() {
                    if timeout.as_ref().map_or(false, |(when_started, timeout)| {
                        (read_write.now.clone() - when_started.clone()) >= *timeout
                    }) {
                        *timeout = None;
                        read_write.wake_up_asap();
                        return (
                            Some(SubstreamInner::PingOut {
                                negotiation,
                                expected_payload,
                                outgoing_payload,
                                queued_pings,
                            }),
                            Some(Event::PingOutError {
                                num_pings: NonZero::<usize>::new(1).unwrap(),
                            }),
                        );
                    }

                    if let Some((when_started, timeout)) = timeout {
                        read_write.wake_up_after(&(when_started.clone() + *timeout));
                    }
                }

                if negotiation.is_none() {
                    if let Ok(Some(pong)) = read_write.incoming_bytes_take(32) {
                        if expected_payload
                            .pop_front()
                            .map_or(true, |expected| pong != *expected)
                        {
                            read_write.wake_up_asap();
                            return (Some(SubstreamInner::PingOutFailed { queued_pings }), None);
                        }
                        if let Some((when_started, _)) = queued_pings.remove(0) {
                            return (
                                Some(SubstreamInner::PingOut {
                                    negotiation,
                                    expected_payload,
                                    outgoing_payload,
                                    queued_pings,
                                }),
                                Some(Event::PingOutSuccess {
                                    ping_time: read_write.now.clone() - when_started,
                                }),
                            );
                        }
                    }
                }

                (
                    Some(SubstreamInner::PingOut {
                        negotiation,
                        expected_payload,
                        outgoing_payload,
                        queued_pings,
                    }),
                    None,
                )
            }
        }
    }

    pub fn reset(self) -> Option<Event> {
        match self.inner {
            SubstreamInner::InboundNegotiating(_, _) => None,
            SubstreamInner::InboundNegotiatingAccept(_, _) => None,
            SubstreamInner::InboundNegotiatingApiWait(_) => Some(Event::InboundNegotiatedCancel),
            SubstreamInner::InboundFailed => None,
            SubstreamInner::RequestOut { .. } => Some(Event::Response {
                response: Err(RequestError::SubstreamReset),
            }),
            SubstreamInner::NotificationsInHandshake { .. } => None,
            SubstreamInner::NotificationsInWait { .. } => Some(Event::NotificationsInOpenCancel),
            SubstreamInner::NotificationsIn { .. } => Some(Event::NotificationsInClose {
                outcome: Err(NotificationsInClosedErr::SubstreamReset),
            }),
            SubstreamInner::NotificationsInRefused => None,
            SubstreamInner::NotificationsInClosed => None,
            SubstreamInner::NotificationsOutHandshakeRecv { .. } => {
                Some(Event::NotificationsOutResult {
                    result: Err(NotificationsOutErr::SubstreamReset),
                })
            }
            SubstreamInner::NotificationsOutNegotiationFailed => None,
            SubstreamInner::NotificationsOut { .. } => Some(Event::NotificationsOutReset),
            SubstreamInner::NotificationsOutClosed { .. } => None,
            SubstreamInner::PingIn { .. } => None,
            SubstreamInner::RequestInRecv { .. } => None,
            SubstreamInner::RequestInRecvEmpty { .. } => None,
            SubstreamInner::RequestInApiWait => None,
            SubstreamInner::RequestInRespond { .. } => None,
            SubstreamInner::PingOut { queued_pings, .. }
            | SubstreamInner::PingOutFailed { queued_pings, .. } => {
                NonZero::<usize>::new(queued_pings.len())
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
    ) {
        if let SubstreamInner::NotificationsInWait = &mut self.inner {
            self.inner = SubstreamInner::NotificationsIn {
                close_desired_timeout: None,
                next_notification_size: None,
                handshake: {
                    let handshake_len = handshake.len();
                    leb128::encode_usize(handshake_len)
                        .chain(handshake)
                        .collect::<VecDeque<_>>()
                },
                max_notification_size,
            }
        }

        // TODO: too defensive, should be } else { panic!() }
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
                notifications.extend(notification);
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

    /// Closes a outgoing notifications substream opened after a successful
    /// [`Event::NotificationsOutResult`].
    ///
    /// This can be done even when in the negotiation phase, in other words before the remote has
    /// accepted/refused the substream.
    ///
    /// # Panic
    ///
    /// Panics if the substream isn't a notifications substream, or if the notifications substream
    /// isn't in the appropriate state.
    ///
    pub fn close_out_notifications_substream(&mut self) {
        match &mut self.inner {
            SubstreamInner::NotificationsOutHandshakeRecv { .. }
            | SubstreamInner::NotificationsOut { .. } => {
                self.inner = SubstreamInner::NotificationsOutClosed;
            }
            _ => panic!(),
        };
    }

    /// Closes an ingoing notifications substream that was accepted using
    /// [`Substream::accept_in_notifications_substream`].
    ///
    /// Notifications can continue to be received. Calling this function only asynchronously
    /// signals to the remote that the substream should be closed. The closing is enforced only
    /// after the given timeout elapses.
    ///
    /// # Panic
    ///
    /// Panics if the substream isn't a notifications substream, or if the notifications substream
    /// isn't in the appropriate state.
    ///
    pub fn close_in_notifications_substream(&mut self, timeout: TNow) {
        match &mut self.inner {
            SubstreamInner::NotificationsIn {
                close_desired_timeout,
                ..
            } if close_desired_timeout.is_none() => {
                *close_desired_timeout = Some(timeout);
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
    pub fn queue_ping(&mut self, payload: &[u8; 32], now: TNow, timeout: Duration) {
        match &mut self.inner {
            SubstreamInner::PingOut { queued_pings, .. }
            | SubstreamInner::PingOutFailed { queued_pings, .. } => {
                queued_pings.push(Some((now, timeout)));
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
                expected_payload.push_back(payload.to_vec());
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
            SubstreamInner::RequestInApiWait => {
                self.inner = SubstreamInner::RequestInRespond {
                    response: if let Ok(response) = response {
                        let response_len = response.len();
                        leb128::encode_usize(response_len).chain(response).collect()
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

    /// Call after an [`Event::InboundNegotiated`] has been emitted in order to accept the protocol
    /// name and indicate the type of the protocol.
    ///
    /// # Panic
    ///
    /// Panics if the substream is not in the correct state.
    ///
    pub fn accept_inbound(&mut self, ty: InboundTy) {
        match mem::replace(&mut self.inner, SubstreamInner::InboundFailed) {
            SubstreamInner::InboundNegotiatingApiWait(accept_deny) => {
                self.inner = SubstreamInner::InboundNegotiatingAccept(accept_deny.accept(), ty)
            }
            _ => panic!(),
        }
    }

    /// Call after an [`Event::InboundNegotiated`] has been emitted in order to reject the
    /// protocol name as not supported.
    ///
    /// # Panic
    ///
    /// Panics if the substream is not in the correct state.
    ///
    pub fn reject_inbound(&mut self) {
        match mem::replace(&mut self.inner, SubstreamInner::InboundFailed) {
            SubstreamInner::InboundNegotiatingApiWait(accept_deny) => {
                self.inner = SubstreamInner::InboundNegotiating(accept_deny.reject(), true)
            }
            _ => panic!(),
        }
    }
}

impl<TNow> fmt::Debug for Substream<TNow> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.inner {
            SubstreamInner::InboundFailed => f.debug_tuple("incoming-negotiation-failed").finish(),
            SubstreamInner::InboundNegotiating(_, _) => {
                f.debug_tuple("incoming-negotiating").finish()
            }
            SubstreamInner::InboundNegotiatingAccept(_, _) => {
                f.debug_tuple("incoming-negotiating-after-accept").finish()
            }
            SubstreamInner::InboundNegotiatingApiWait(..) => {
                f.debug_tuple("incoming-negotiated-api-wait").finish()
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
            SubstreamInner::NotificationsInHandshake { .. } => {
                f.debug_tuple("notifications-in-handshake").finish()
            }
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
            SubstreamInner::RequestOut { .. } => f.debug_tuple("request-out").finish(),
            SubstreamInner::RequestInRecv { .. } | SubstreamInner::RequestInRecvEmpty { .. } => {
                f.debug_tuple("request-in").finish()
            }
            SubstreamInner::RequestInRespond { .. } => f.debug_tuple("request-in-respond").finish(),
            SubstreamInner::RequestInApiWait => f.debug_tuple("request-in").finish(),
            SubstreamInner::PingIn { .. } => f.debug_tuple("ping-in").finish(),
            SubstreamInner::PingOutFailed { .. } => f.debug_tuple("ping-out-failed").finish(),
            SubstreamInner::PingOut { .. } => f.debug_tuple("ping-out").finish(),
        }
    }
}

/// Event that happened on the connection. See [`Substream::read_write`].
#[must_use]
#[derive(Debug)]
pub enum Event {
    /// Error while receiving an inbound substream.
    InboundError {
        error: InboundError,
        was_accepted: bool,
    },

    /// An inbound substream has successfully negotiated a protocol. Call
    /// [`Substream::accept_inbound`] or [`Substream::reject_inbound`] in order to resume.
    InboundNegotiated(String),

    /// An inbound substream that had successfully negotiated a protocol got abruptly closed
    /// while waiting for the call to [`Substream::accept_inbound`] or
    /// [`Substream::reject_inbound`].
    InboundNegotiatedCancel,

    /// Received a request in the context of a request-response protocol.
    RequestIn {
        /// Bytes of the request. Its interpretation is out of scope of this module.
        request: Vec<u8>,
    },

    /// Received a response to a previously emitted request on a request-response protocol.
    Response {
        /// Bytes of the response. Its interpretation is out of scope of this module.
        response: Result<Vec<u8>, RequestError>,
    },

    /// Remote has opened an inbound notifications substream.
    ///
    /// Either [`Substream::accept_in_notifications_substream`] or
    /// [`Substream::reject_in_notifications_substream`] must be called in the near future in
    /// order to accept or reject this substream.
    NotificationsInOpen {
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
        result: Result<Vec<u8>, NotificationsOutErr>,
    },
    /// Remote has closed an outgoing notifications substream, meaning that it demands the closing
    /// of the substream.
    NotificationsOutCloseDemanded,
    /// Remote has reset an outgoing notifications substream. The substream is instantly closed.
    NotificationsOutReset,

    /// A ping has been successfully answered by the remote.
    PingOutSuccess {
        /// Time between sending the ping and receiving the pong.
        ping_time: Duration,
    },
    /// Remote has failed to answer one or more pings.
    PingOutError {
        /// Number of pings that the remote has failed to answer.
        num_pings: NonZero<usize>,
    },
}

/// Type of inbound protocol.
pub enum InboundTy {
    Ping,
    Request {
        /// Maximum allowed size of the request.
        /// If `None`, then no data is expected on the substream, not even the length of the
        /// request.
        // TODO: use a proper enum
        request_max_size: Option<usize>,
    },
    Notifications {
        max_handshake_size: usize,
    },
}

/// Error that can happen while processing an inbound substream.
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub enum InboundError {
    /// Error during protocol negotiation.
    #[display("Protocol negotiation error: {_0}")]
    NegotiationError(multistream_select::Error),
    /// Error while receiving an inbound request.
    #[display("Error receiving inbound request: {_0}")]
    RequestInLebError(read_write::IncomingBytesTakeLeb128Error),
    /// Substream has been unexpectedly closed.
    #[display("Substream unexpectedly closed")]
    SubstreamClosed,
    /// Unexpected end of file while receiving an inbound request.
    RequestInExpectedEof,
    /// Error while receiving an inbound notifications substream handshake.
    #[display("Error while receiving an inbound notifications substream handshake: {error}")]
    NotificationsInError {
        /// Error that happened.
        error: read_write::IncomingBytesTakeLeb128Error,
    },
    /// Unexpected end of file while receiving an inbound notifications substream handshake.
    #[display(
        "Unexpected end of file while receiving an inbound notifications substream handshake"
    )]
    NotificationsInUnexpectedEof,
}

/// Error that can happen during a request in a request-response scheme.
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
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
    #[display("Protocol negotiation error: {_0}")]
    NegotiationError(multistream_select::Error),
    /// Invalid LEB128 number when receiving the response.
    ResponseInvalidLeb128,
    /// Number of bytes decoded is larger than expected when receiving the response.
    ResponseTooLarge,
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
            RequestError::ResponseInvalidLeb128 => true,
            RequestError::ResponseTooLarge => true,
        }
    }
}

/// Error potentially returned by [`Substream::respond_in_request`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum RespondInRequestError {
    /// The substream has already been closed.
    SubstreamClosed,
}

/// Error that can happen when trying to open an outbound notifications substream.
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub enum NotificationsOutErr {
    /// Remote took too long to perform the handshake.
    Timeout,
    /// Remote has refused the handshake by closing the substream.
    RefusedHandshake,
    /// Remote has indicated that it doesn't support the requested protocol.
    ProtocolNotAvailable,
    /// Error during the multistream-select handshake.
    #[display("Protocol negotiation error: {_0}")]
    NegotiationError(multistream_select::Error),
    /// Substream has been reset during the negotiation.
    SubstreamReset,
    /// Error while receiving the remote's handshake.
    #[display("Error while receiving remote handshake: {_0}")]
    HandshakeRecvError(read_write::IncomingBytesTakeLeb128Error),
}

/// Reason why an inbound notifications substream has been closed.
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub enum NotificationsInClosedErr {
    /// Error in the protocol.
    #[display("Error while receiving notification: {_0}")]
    ProtocolError(read_write::IncomingBytesTakeLeb128Error),
    /// Substream has been closed.
    SubstreamClosed,
    /// Substream has been reset.
    SubstreamReset,
    /// Substream has been force-closed because the graceful timeout has been reached.
    CloseDesiredTimeout,
}
