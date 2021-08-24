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

use crate::libp2p::{connection::multistream_select, read_write};
use crate::util::leb128;

use alloc::{
    collections::VecDeque,
    string::String,
    vec::{self, Vec},
};
use core::fmt;

/// State machine containing the state of a single substream of an established connection.
// TODO: remove `protocol_index` fields?
// TODO: hide enum variants
pub enum Substream<TNow, TRqUd, TNotifUd> {
    /// Temporary transition state.
    Poisoned,

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
    NegotiationFailed,

    /// Negotiating a protocol for a notifications protocol substream.
    NotificationsOutNegotiating {
        /// When the opening will time out in the absence of response.
        timeout: TNow,
        /// State of the protocol negotiation.
        negotiation: multistream_select::InProgress<vec::IntoIter<String>, String>,
        /// Bytes of the handshake to send after the substream is open.
        handshake_out: Vec<u8>,
        /// Data passed by the user to [`Substream::notifications_out`].
        user_data: TNotifUd,
    },
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

    /// Negotiating a protocol for an outgoing request.
    RequestOutNegotiating {
        /// When the request will time out in the absence of response.
        timeout: TNow,
        /// State of the protocol negotiation.
        negotiation: multistream_select::InProgress<vec::IntoIter<String>, String>,
        /// Bytes of the request to send after the substream is open.
        ///
        /// If `None`, nothing should be sent on the substream at all, not even the length prefix.
        /// This contrasts with `Some(empty_vec)` where a `0` length prefix must be sent.
        request: Option<Vec<u8>>,
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
    /// Similar to [`Substream::RequestInRecv`], but doesn't expect any request body. Immediately
    /// reports an event and switches to [`Substream::RequestInApiWait`].
    RequestInRecvEmpty {
        /// Protocol that was negotiated.
        protocol_index: usize,
    },
    /// A request has been sent by the remote. API user must now send back the response.
    RequestInApiWait,
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
}

impl<TNow, TRqUd, TNotifUd> Substream<TNow, TRqUd, TNotifUd>
where
    TNow: Clone + Ord,
{
    /// Initializes an new ingoing substream.
    // TODO: detail events that can happen
    pub fn ingoing(supported_protocols: Vec<String>) -> Self {
        let negotiation =
            multistream_select::InProgress::new(multistream_select::Config::Listener {
                supported_protocols: supported_protocols.into_iter(),
            });

        Substream::InboundNegotiating(negotiation)
    }

    /// Initializes an outgoing notifications substream.
    // TODO: detail the events that can happen
    pub fn notifications_out(
        timeout: TNow,
        requested_protocol: String,
        handshake: Vec<u8>,
        user_data: TNotifUd,
    ) -> Self {
        let negotiation = multistream_select::InProgress::new(multistream_select::Config::Dialer {
            requested_protocol,
        });

        Substream::NotificationsOutNegotiating {
            timeout,
            negotiation,
            handshake_out: handshake,
            user_data,
        }
    }

    /// Initializes an outgoing request substream.
    ///
    /// After the remote has sent back a response, an [`Event::Response`] event will be generated
    /// locally. The `user_data` parameter will be passed back.
    ///
    /// If the `request` is `None`, then nothing at all will be written out, not even a length
    /// prefix. If the `request` is `Some`, then a length prefix will be written out. Consequently,
    /// `Some(&[])` writes a single `0` for the request.
    pub fn request_out(
        requested_protocol: String,
        timeout: TNow,
        request: Option<Vec<u8>>,
        user_data: TRqUd,
    ) -> Self {
        let negotiation = multistream_select::InProgress::new(multistream_select::Config::Dialer {
            requested_protocol,
        });

        Substream::RequestOutNegotiating {
            timeout,
            negotiation,
            request,
            user_data,
        }

        // TODO: somehow do substream.reserve_window(128 * 1024 * 1024 + 128); // TODO: proper max size
    }

    /// Returns the user data associated to a notifications substream.
    ///
    /// Returns `None` if the substream isn't a notifications substream.
    pub fn notifications_substream_user_data_mut(&mut self) -> Option<&mut TNotifUd> {
        match self {
            Substream::NotificationsOutNegotiating { user_data, .. } => Some(user_data),
            Substream::NotificationsOutHandshakeRecv { user_data, .. } => Some(user_data),
            Substream::NotificationsOut { user_data, .. } => Some(user_data),
            Substream::NotificationsIn { user_data, .. } => Some(user_data),
            _ => None,
        }
    }

    /// Reads data coming from the socket, updates the internal state machine, and writes data
    /// destined to the socket through the [`read_write::ReadWrite`].
    ///
    /// If a protocol error happens, an `Err(())` is returned. In that case, the substream must be
    /// reset.
    pub fn read_write<'a>(
        self,
        read_write: &'_ mut read_write::ReadWrite<'_, TNow>,
    ) -> (Result<Self, ()>, Option<Event<TRqUd, TNotifUd>>) {
        match self {
            Substream::Poisoned => unreachable!(),
            Substream::InboundNegotiating(nego) => match nego.read_write(read_write) {
                Ok(multistream_select::Negotiation::InProgress(nego)) => {
                    return (Ok(Substream::InboundNegotiating(nego)), None);
                }
                Ok(multistream_select::Negotiation::Success(protocol)) => (
                    Ok(Substream::InboundNegotiatingApiWait),
                    Some(Event::InboundNegotiated(protocol)),
                ),
                Ok(multistream_select::Negotiation::NotAvailable) => {
                    read_write.close_write(); // TODO: unclear how multistream-select adjusts the read_write
                    (Ok(Substream::NegotiationFailed), None)
                }
                Err(_) => (Err(()), None),
            },
            Substream::InboundNegotiatingApiWait => {
                (Ok(Substream::InboundNegotiatingApiWait), None)
            }
            Substream::NegotiationFailed => {
                // Substream is an inbound substream that has failed to negotiate a
                // protocol. The substream is expected to close soon, but the remote might
                // have been eagerly sending data (assuming that the negotiation would
                // succeed), which should be silently discarded.
                read_write.discard_all_incoming();
                read_write.close_write();
                (Ok(Substream::NegotiationFailed), None)
            }
            Substream::NotificationsOutNegotiating {
                negotiation,
                timeout,
                handshake_out,
                user_data,
            } => {
                if timeout < read_write.now {
                    // TODO: report that it's a timeout and not a rejection
                    return (
                        Ok(Substream::NegotiationFailed),
                        Some(Event::NotificationsOutReject { user_data }),
                    );
                }

                read_write.wake_up_after(&timeout);

                match negotiation.read_write(read_write) {
                    Ok(multistream_select::Negotiation::InProgress(nego)) => (
                        Ok(Substream::NotificationsOutNegotiating {
                            negotiation: nego,
                            timeout,
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
                            Ok(Substream::NotificationsOutHandshakeRecv {
                                handshake_in: leb128::FramedInProgress::new(10 * 1024), // TODO: proper max size
                                handshake_out,
                                user_data,
                            }),
                            None,
                        )
                    }
                    _ => {
                        // TODO: differentiate between actual error and protocol unavailable?
                        (Err(()), Some(Event::NotificationsOutReject { user_data }))
                    }
                }
            }
            Substream::NotificationsOutHandshakeRecv {
                handshake_in,
                mut handshake_out,
                user_data,
            } => {
                read_write.write_from_vec_deque(&mut handshake_out);

                let incoming_buffer = match read_write.incoming_buffer {
                    Some(buf) => buf,
                    None => {
                        read_write.close_write();
                        // TODO: transition
                        return (
                            Ok(Substream::NegotiationFailed),
                            Some(Event::NotificationsOutReject { user_data }),
                        );
                    }
                };

                // Don't actually process incoming data before handshake is sent out, in order to
                // not accidentally perform a state transition.
                if !handshake_out.is_empty() {
                    return (
                        Ok(Substream::NotificationsOutHandshakeRecv {
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
                            Ok(Substream::NotificationsOut {
                                notifications: VecDeque::new(),
                                user_data,
                            }),
                            Some(Event::NotificationsOutAccept { remote_handshake }),
                        )
                    }
                    Ok((num_read, leb128::Framed::InProgress(handshake_in))) => {
                        read_write.advance_read(num_read);
                        (
                            Ok(Substream::NotificationsOutHandshakeRecv {
                                handshake_in,
                                handshake_out,
                                user_data,
                            }),
                            None,
                        )
                    }
                    Err(_) => {
                        todo!() // TODO: report to user and all
                    }
                }
            }
            Substream::NotificationsOut {
                mut notifications,
                user_data,
            } => {
                // Receiving data on an outgoing substream is forbidden by the protocol.
                read_write.discard_all_incoming();
                read_write.write_from_vec_deque(&mut notifications);
                (
                    Ok(Substream::NotificationsOut {
                        notifications,
                        user_data,
                    }),
                    None,
                )
            }
            Substream::NotificationsOutClosed => {
                read_write.close_write();
                read_write.discard_all_incoming();
                (Ok(Substream::NotificationsOutClosed), None)
            }
            Substream::RequestOutNegotiating {
                negotiation,
                timeout,
                request,
                user_data,
            } => {
                // Note that this might trigger timeouts for requests whose response is available
                // in `incoming_buffer`. This is intentional, as from the perspective of
                // `read_write` the response arrived after the timeout. It is the responsibility
                // of the user to call `read_write` in an appropriate way for this to not happen.
                if timeout < read_write.now {
                    read_write.close_write();
                    return (
                        Ok(Substream::NegotiationFailed),
                        Some(Event::Response {
                            response: Err(RequestError::Timeout),
                            user_data,
                        }),
                    );
                }

                read_write.wake_up_after(&timeout);

                match negotiation.read_write(read_write) {
                    Ok(multistream_select::Negotiation::InProgress(nego)) => (
                        Ok(Substream::RequestOutNegotiating {
                            negotiation: nego,
                            timeout,
                            request,
                            user_data,
                        }),
                        None,
                    ),
                    Ok(multistream_select::Negotiation::Success(_)) => {
                        let request_payload = if let Some(request) = request {
                            let request_len = request.len();
                            leb128::encode_usize(request_len)
                                .chain(request.into_iter())
                                .collect::<VecDeque<_>>()
                        } else {
                            VecDeque::new()
                        };

                        (
                            Ok(Substream::RequestOut {
                                timeout,
                                request: request_payload,
                                user_data,
                                response: leb128::FramedInProgress::new(128 * 1024 * 1024), // TODO: proper max size
                            }),
                            None,
                        )
                    }
                    Ok(multistream_select::Negotiation::NotAvailable) => (
                        Err(()),
                        Some(Event::Response {
                            user_data,
                            response: Err(RequestError::ProtocolNotAvailable),
                        }),
                    ),
                    Err(err) => (
                        Err(()),
                        Some(Event::Response {
                            user_data,
                            response: Err(RequestError::NegotiationError(err)),
                        }),
                    ),
                }
            }
            Substream::RequestOut {
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
                        Ok(Substream::NegotiationFailed), // TODO: proper transition
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
                            Ok(Substream::NegotiationFailed),
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
                        (
                            Ok(Substream::NegotiationFailed), // TODO: proper state transition
                            Some(Event::Response {
                                user_data,
                                response: Ok(response),
                            }),
                        )
                    }
                    Ok((num_read, leb128::Framed::InProgress(response))) => {
                        read_write.advance_read(num_read);
                        (
                            Ok(Substream::RequestOut {
                                timeout,
                                request,
                                user_data,
                                response,
                            }),
                            None,
                        )
                    }
                    Err(err) => (
                        Err(()),
                        Some(Event::Response {
                            user_data,
                            response: Err(RequestError::ResponseLebError(err)),
                        }),
                    ),
                }
            }
            Substream::RequestInRecv {
                request,
                protocol_index,
            } => {
                let incoming_buffer = match read_write.incoming_buffer {
                    Some(buf) => buf,
                    None => {
                        read_write.close_write();
                        panic!(); // TODO: return
                    }
                };

                match request.update(&incoming_buffer) {
                    Ok((num_read, leb128::Framed::Finished(request))) => {
                        read_write.advance_read(num_read);
                        (
                            Ok(Substream::RequestInApiWait),
                            Some(Event::RequestIn {
                                protocol_index,
                                request,
                            }),
                        )
                    }
                    Ok((num_read, leb128::Framed::InProgress(request))) => {
                        read_write.advance_read(num_read);
                        (
                            Ok(Substream::RequestInRecv {
                                request,
                                protocol_index,
                            }),
                            None,
                        )
                    }
                    Err(_err) => {
                        // TODO: report to user
                        todo!()
                        // (Err(()), ...)
                    }
                }
            }
            Substream::RequestInRecvEmpty { protocol_index } => (
                Ok(Substream::RequestInApiWait),
                Some(Event::RequestIn {
                    protocol_index,
                    request: Vec::new(),
                }),
            ),
            Substream::RequestInApiWait => (Ok(Substream::RequestInApiWait), None),
            Substream::RequestInRespond { mut response } => {
                read_write.write_from_vec_deque(&mut response);
                if response.is_empty() {
                    read_write.close_write();
                }
                (Ok(Substream::RequestInRespond { response }), None)
            }
            Substream::NotificationsInHandshake {
                handshake,
                protocol_index,
            } => {
                let incoming_buffer = match read_write.incoming_buffer {
                    Some(buf) => buf,
                    None => {
                        read_write.close_write();
                        return (
                            Ok(Substream::NegotiationFailed), // TODO: proper transition
                            Some(Event::NotificationsInOpenCancel { protocol_index }),
                        );
                    }
                };

                match handshake.update(incoming_buffer) {
                    Ok((num_read, leb128::Framed::Finished(handshake))) => {
                        read_write.advance_read(num_read);
                        (
                            Ok(Substream::NotificationsInWait { protocol_index }),
                            Some(Event::NotificationsInOpen {
                                protocol_index,
                                handshake,
                            }),
                        )
                    }
                    Ok((num_read, leb128::Framed::InProgress(handshake))) => {
                        read_write.advance_read(num_read);
                        (
                            Ok(Substream::NotificationsInHandshake {
                                handshake,
                                protocol_index,
                            }),
                            None,
                        )
                    }
                    Err(_) => (Err(()), None),
                }
            }
            Substream::NotificationsInWait { protocol_index } => {
                // TODO: what to do with data?
                read_write.discard_all_incoming();
                return (Ok(Substream::NotificationsInWait { protocol_index }), None);
            }
            Substream::NotificationsInRefused => {
                read_write.discard_all_incoming();
                read_write.close_write();
                (Ok(Substream::NotificationsInRefused), None)
            }
            Substream::NotificationsIn {
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
                            Ok(Substream::NegotiationFailed), // TODO: proper transitio
                            Some(Event::NotificationsOutReject { user_data }),
                        );
                    }
                };

                match next_notification.update(incoming_buffer) {
                    Ok((num_read, leb128::Framed::Finished(notification))) => {
                        read_write.advance_read(num_read);

                        (
                            Ok(Substream::NotificationsIn {
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
                            Ok(Substream::NotificationsIn {
                                next_notification,
                                handshake,
                                protocol_index,
                                max_notification_size,
                                user_data,
                            }),
                            None,
                        )
                    }
                    Err(_) => {
                        // TODO: report to user; there's no corresponding event yet
                        (Err(()), None)
                    }
                }
            }
            Substream::PingIn {
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
                        payload_out.extend(payload_in.iter().cloned());
                        payload_in.clear();
                    }
                    read_write.write_from_vec_deque(&mut payload_out);
                }

                (
                    Ok(Substream::PingIn {
                        payload_in,
                        payload_out,
                    }),
                    None,
                )
            }
        }
    }

    pub fn reset(self) -> Option<Event<TRqUd, TNotifUd>> {
        match self {
            Substream::Poisoned => unreachable!(),
            Substream::InboundNegotiating(_) => None,
            Substream::InboundNegotiatingApiWait => None,
            Substream::NegotiationFailed => None,
            Substream::RequestOutNegotiating { user_data, .. }
            | Substream::RequestOut { user_data, .. } => Some(Event::Response {
                user_data,
                response: Err(RequestError::SubstreamReset),
            }),
            Substream::NotificationsInHandshake { .. } => None,
            Substream::NotificationsInWait { protocol_index, .. } => {
                Some(Event::NotificationsInOpenCancel { protocol_index })
            }
            Substream::NotificationsIn { .. } => {
                // TODO: report to user
                None
            }
            Substream::NotificationsInRefused => None,
            Substream::NotificationsOutNegotiating { user_data, .. }
            | Substream::NotificationsOutHandshakeRecv { user_data, .. } => {
                Some(Event::NotificationsOutReject { user_data })
            }
            Substream::PingIn { .. } => None,
            Substream::NotificationsOut { user_data, .. } => {
                Some(Event::NotificationsOutReset { user_data })
            }
            Substream::NotificationsOutClosed { .. } => None,
            Substream::RequestInRecv { .. } => None,
            Substream::RequestInRecvEmpty { .. } => None,
            Substream::RequestInApiWait => None,
            Substream::RequestInRespond { .. } => None,
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
        match self {
            Substream::NotificationsInWait { protocol_index } => {
                let protocol_index = *protocol_index;

                *self = Substream::NotificationsIn {
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
            _ => return, // TODO: too defensive, should be panic!()
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
        match self {
            Substream::NotificationsInWait { .. } => {
                *self = Substream::NotificationsInRefused;
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
        match self {
            Substream::NotificationsOut { notifications, .. } => {
                // TODO: expensive copying?
                notifications.extend(leb128::encode_usize(notification.len()));
                notifications.extend(notification.into_iter())
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
        match self {
            Substream::NotificationsOut { notifications, .. } => notifications.len(),
            _ => panic!(),
        }
    }

    /// Closes a notifications substream opened after an [`Event::NotificationsOutAccept`] or that
    /// was accepted using [`Substream::accept_in_notifications_substream`].
    ///
    /// In the case of an outbound substream, this can be done even when in the negotiation phase,
    /// in other words before the remote has accepted/refused the substream.
    ///
    /// # Panic
    ///
    /// Panics if the substream isn't a notifications substream, or if the notifications substream
    /// isn't in the appropriate state.
    ///
    pub fn close_notifications_substream(&mut self) {
        if !matches!(
            self,
            Substream::NotificationsOutNegotiating { .. }
                | Substream::NotificationsOutHandshakeRecv { .. }
                | Substream::NotificationsOut { .. }
                | Substream::NotificationsIn { .. }
        ) {
            panic!()
        }

        *self = Substream::NotificationsOutClosed; // TODO: not correct for notifs in
    }

    /// Responds to an incoming request. Must be called in response to a [`Event::RequestIn`].
    ///
    /// Passing an `Err` corresponds, on the other side, to a [`RequestError::SubstreamClosed`].
    pub fn respond_in_request(
        &mut self,
        response: Result<Vec<u8>, ()>,
    ) -> Result<(), RespondInRequestError> {
        match self {
            Substream::RequestInApiWait => {
                *self = Substream::RequestInRespond {
                    response: if let Ok(response) = response {
                        let response_len = response.len();
                        leb128::encode_usize(response_len)
                            .chain(response.into_iter())
                            .collect()
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
        assert!(matches!(*self, Substream::InboundNegotiatingApiWait));

        match ty {
            InboundTy::Ping => {
                *self = Substream::PingIn {
                    payload_in: Default::default(),
                    payload_out: VecDeque::with_capacity(32),
                }
            }
            InboundTy::Notifications {
                protocol_index,
                max_handshake_size,
            } => {
                *self = Substream::NotificationsInHandshake {
                    protocol_index,
                    handshake: leb128::FramedInProgress::new(max_handshake_size),
                }
            }
            InboundTy::Request {
                protocol_index,
                request_max_size,
            } => {
                if let Some(request_max_size) = request_max_size {
                    *self = Substream::RequestInRecv {
                        protocol_index,
                        request: leb128::FramedInProgress::new(request_max_size),
                    };
                } else {
                    *self = Substream::RequestInRecvEmpty { protocol_index };
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
        match self {
            Substream::Poisoned => f.debug_tuple("poisoned").finish(),
            Substream::NegotiationFailed => f.debug_tuple("incoming-negotiation-failed").finish(),
            Substream::InboundNegotiating(_) => f.debug_tuple("incoming-negotiating").finish(),
            Substream::InboundNegotiatingApiWait => {
                f.debug_tuple("incoming-negotiated-api-wait").finish()
            }
            Substream::NotificationsOutNegotiating { .. } => {
                todo!() // TODO:
            }
            Substream::NotificationsOutHandshakeRecv { .. } => {
                todo!() // TODO:
            }
            Substream::NotificationsOut { .. } => f.debug_tuple("notifications-out").finish(),
            Substream::NotificationsOutClosed { .. } => {
                f.debug_tuple("notifications-out-closed").finish()
            }
            Substream::NotificationsInHandshake { protocol_index, .. } => f
                .debug_tuple("notifications-in-handshake")
                .field(protocol_index)
                .finish(),
            Substream::NotificationsInWait { .. } => {
                todo!() // TODO:
            }
            Substream::NotificationsIn { .. } => f.debug_tuple("notifications-in").finish(),
            Substream::NotificationsInRefused => f.debug_tuple("notifications-in-refused").finish(),
            Substream::RequestOutNegotiating { user_data, .. }
            | Substream::RequestOut { user_data, .. } => {
                f.debug_tuple("request-out").field(&user_data).finish()
            }
            Substream::RequestInRecv { protocol_index, .. }
            | Substream::RequestInRecvEmpty { protocol_index, .. } => {
                f.debug_tuple("request-in").field(protocol_index).finish()
            }
            Substream::RequestInRespond { .. } => f.debug_tuple("request-in-respond").finish(),
            Substream::RequestInApiWait => f.debug_tuple("request-in").finish(),
            Substream::PingIn { .. } => f.debug_tuple("ping-in").finish(),
        }
    }
}

/// Event that happened on the connection. See [`Substream::read_write`].
#[must_use]
#[derive(Debug)]
pub enum Event<TRqUd, TNotifUd> {
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
    NotificationsInOpenCancel {
        /// Index of the notifications protocol concerned by the substream.
        protocol_index: usize,
    },

    /// Remote has sent a notification on an inbound notifications substream. Can only happen
    /// after the substream has been accepted.
    // TODO: give a way to back-pressure notifications
    NotificationIn {
        /// Notification sent by the remote.
        notification: Vec<u8>,
    },

    /// Remote has accepted a substream opened with [`Substream::notifications_out`].
    ///
    /// It is now possible to send notifications on this substream.
    NotificationsOutAccept {
        /// Handshake sent back by the remote. Its interpretation is out of scope of this module.
        remote_handshake: Vec<u8>,
    },

    /// Remote has rejected a substream opened with [`Substream::notifications_out`].
    NotificationsOutReject {
        /// Value that was passed to [`Substream::notifications_out`].
        user_data: TNotifUd,
    },

    /// Remote has closed an outgoing notifications substream, meaning that it demands the closing
    /// of the substream.
    NotificationsOutCloseDemanded,

    /// Remote has reset an outgoing notifications substream. The substream is instantly closed.
    NotificationsOutReset {
        /// Value that was passed to [`Substream::notifications_out`].
        user_data: TNotifUd,
    },
}

/// Type of inbound protocol.
pub enum InboundTy {
    Ping,
    Request {
        protocol_index: usize,
        /// Maximum allowed size of the request.
        /// If `None`, then no data is expected on the substream, not even the length of the
        /// request.
        request_max_size: Option<usize>,
    },
    Notifications {
        protocol_index: usize,
        max_handshake_size: usize,
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
    /// Remote has decided to RST the substream. This most likely indicates that the remote has
    /// detected a protocol error.
    SubstreamReset,
    /// Error during protocol negotiation.
    NegotiationError(multistream_select::Error),
    /// Error while receiving the response.
    ResponseLebError(leb128::FramedError),
}

/// Error potentially returned by [`Substream::respond_in_request`].
#[derive(Debug, derive_more::Display)]
pub enum RespondInRequestError {
    /// The substream has already been closed.
    SubstreamClosed,
}
