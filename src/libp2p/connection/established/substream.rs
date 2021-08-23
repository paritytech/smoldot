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

use alloc::vec;
use core::{fmt, mem};

pub enum Substream<TNow, TRqUd, TNotifUd> {
    /// Temporary transition state.
    Poisoned,

    /// Protocol negotiation in progress in an incoming substream.
    InboundNegotiating(multistream_select::InProgress<vec::IntoIter<String>, String>),
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
        handshake: Vec<u8>,
        /// Data passed by the user to [`Established::open_notifications_substream`].
        user_data: TNotifUd,
    },
    /// A notifications protocol has been negotiated on a substream. Either a successful handshake
    /// or an abrupt closing is now expected.
    NotificationsOutHandshakeRecv {
        /// Buffer for the incoming handshake.
        handshake: leb128::FramedInProgress,
        /// Data passed by the user to [`Established::open_notifications_substream`].
        user_data: TNotifUd,
    },
    /// A notifications protocol has been negotiated, and the remote accepted it. Can now send
    /// notifications.
    NotificationsOut {
        /// Data passed by the user to [`Established::open_notifications_substream`].
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
        /// Protocol that was negotiated.
        protocol_index: usize,
        /// Data passed by the user to [`Established::accept_in_notifications_substream`].
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
        /// Data passed by the user to [`Established::add_request`].
        user_data: TRqUd,
    },
    /// Outgoing request has been sent out or is queued for send out, and a response from the
    /// remote is now expected. Substream has been closed.
    RequestOut {
        /// When the request will time out in the absence of response.
        timeout: TNow,
        /// Data passed by the user to [`Established::add_request`].
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
    /// A request has been sent by the remote. API user must now send back the response.
    RequestInSend,

    /// Inbound ping substream. Waiting for the ping payload to be received.
    PingIn(arrayvec::ArrayVec<u8, 32>),
}

impl<TNow, TRqUd, TNotifUd> Substream<TNow, TRqUd, TNotifUd> {
    /// Initializes an outgoing notifications substream.
    pub fn notifications_out(timeout: TNow, handshake: Vec<u8>, user_data: TNotifUd) -> Self {
        // TODO: ?!
        let mut negotiation =
            multistream_select::InProgress::new(multistream_select::Config::Dialer {
                requested_protocol: self.inner.notifications_protocols[protocol_index]
                    .name
                    .clone(), // TODO: clone :-/
            });

        Substream::NotificationsOutNegotiating {
            timeout,
            negotiation,
            handshake,
            user_data,
        }
    }

    /// Returns the user dat associated to a notifications substream.
    ///
    /// Returns `None` if the substream isn't a notifications substream.
    pub fn notifications_substream_user_data_mut(&mut self) -> Option<&mut TNotifUd> {
        match self {
            Substream::NotificationsOutNegotiating { user_data, .. } => Some(user_data),
            Substream::NotificationsOutHandshakeRecv { user_data, .. } => Some(user_data),
            Substream::NotificationsOut { user_data } => Some(user_data),
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
        mut self,
        read_write: &'_ mut read_write::ReadWrite<'_, TNow>,
    ) -> (Result<Self, ()>, Option<Event<TRqUd, TNotifUd>>) {
        match self {
            Substream::Poisoned => unreachable!(),
            Substream::InboundNegotiating(nego) => match nego.read_write(read_write) {
                Ok(multistream_select::Negotiation::InProgress(nego)) => {
                    return (Ok(Substream::InboundNegotiating(nego)), None);
                }
                Ok((multistream_select::Negotiation::Success(protocol), num_read, out_buffer)) => {
                    substream.write(out_buffer);
                    data = &data[num_read..];
                    if protocol == self.ping_protocol {
                        *substream.user_data() = Substream::PingIn(Default::default());
                    } else if let Some(protocol_index) = self
                        .request_protocols
                        .iter()
                        .position(|p| p.name == protocol)
                    {
                        if let ConfigRequestResponseIn::Payload { max_size } =
                            self.request_protocols[protocol_index].inbound_config
                        {
                            *substream.user_data() = Substream::RequestInRecv {
                                protocol_index,
                                request: leb128::FramedInProgress::new(max_size),
                            };
                        } else {
                            // TODO: make sure that data is empty?
                            *substream.user_data() = Substream::RequestInSend;
                            return Some(Event::RequestIn {
                                id: substream_id,
                                protocol_index,
                                request: Vec::new(),
                            });
                        }
                    } else if let Some(protocol_index) = self
                        .notifications_protocols
                        .iter()
                        .position(|p| p.name == protocol)
                    {
                        *substream.user_data() = Substream::NotificationsInHandshake {
                            protocol_index,
                            handshake: leb128::FramedInProgress::new(
                                self.notifications_protocols[protocol_index].max_handshake_size,
                            ),
                        };
                    } else {
                        unreachable!()
                    }
                }
                Ok(multistream_select::Negotiation::NotAvailable) => {
                    read_write.close(); // TODO: unclear how multistream-select adjusts the read_write
                    (Ok(Substream::NegotiationFailed), None)
                }
                Err(_) => (Err(()), None),
            },
            Substream::NegotiationFailed => {
                // Substream is an inbound substream that has failed to negotiate a
                // protocol. The substream is expected to close soon, but the remote might
                // have been eagerly sending data (assuming that the negotiation would
                // succeed), which should be silently discarded.
                debug_assert!(read_write.outgoing_buffer.is_none());
                read_write.discard_all_incoming();
                (Ok(Substream::NegotiationFailed), None)
            }
            Substream::NotificationsOutNegotiating {
                negotiation,
                timeout,
                handshake,
                user_data,
            } => {
                if timeout < read_write.now {
                    // TODO: report that it's a timeout and not a rejection
                    return (Ok(self), Some(Event::NotificationsOutReject { user_data }));
                }

                read_write.wake_up_when(timeout);

                match negotiation.read_write(read_write) {
                    Ok(multistream_select::Negotiation::InProgress(nego)) => {
                        return (
                            Substream::NotificationsOutNegotiating {
                                negotiation: nego,
                                timeout,
                                handshake,
                                user_data,
                            },
                            None,
                        );
                    }
                    Ok(multistream_select::Negotiation::Success(_)) => {
                        substream.write(leb128::encode_usize(handshake.len()).collect());
                        substream.write(handshake);
                        *substream.user_data() = Substream::NotificationsOutHandshakeRecv {
                            handshake: leb128::FramedInProgress::new(10 * 1024), // TODO: proper max size
                            user_data,
                        };
                    }
                    _ => {
                        // TODO: differentiate between actual error and protocol unavailable?
                        substream.reset();
                        return Some(Event::NotificationsOutReject {
                            id: substream_id,
                            user_data,
                        });
                    }
                }
            }
            Substream::NotificationsOutHandshakeRecv {
                handshake,
                user_data,
            } => {
                match handshake.update(&data) {
                    Ok((num_read, leb128::Framed::Finished(remote_handshake))) => {
                        if num_read != data.len() {
                            todo!() // TODO:
                        }

                        *substream.user_data() = Substream::NotificationsOut { user_data };
                        return Some(Event::NotificationsOutAccept {
                            id: substream_id,
                            remote_handshake,
                        });
                    }
                    Ok((num_read, leb128::Framed::InProgress(handshake))) => {
                        debug_assert_ne!(num_read, 0);
                        data = &data[num_read..];
                        *substream.user_data() = Substream::NotificationsOutHandshakeRecv {
                            handshake,
                            user_data,
                        };
                    }
                    Err(_) => {
                        todo!() // TODO: report to user and all
                    }
                }
            }
            Substream::NotificationsOut { user_data } => {
                // Receiving data on an outgoing substream is forbidden by the protocol.
                read_write.discard_all_incoming();
                return Ok((Substream::NotificationsOut { user_data }, None));
            }
            Substream::NotificationsOutClosed => {
                read_write.discard_all_incoming();
                return Ok((Substream::NotificationsOutClosed, None));
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
                    Event::Response {
                        response: Err(RequestError::Timeout),
                        user_data,
                    }
                }

                read_write.wake_up_when(timeout);

                // TODO: ?!
                let incoming_buffer = match read_write.incoming_buffer {
                    Some(buf) => buf,
                    None => {
                        read_write.close_write();
                        return Ok((
                            self,
                            Some(Event::Response {
                                user_data,
                                response: Err(RequestError::SubstreamClosed),
                            }),
                        ));
                    }
                };

                match negotiation.read_write(read_write) {
                    Ok(multistream_select::Negotiation::InProgress(nego)) => {
                        return Ok((
                            Substream::RequestOutNegotiating {
                                negotiation: nego,
                                timeout,
                                request,
                                user_data,
                            },
                            None,
                        ));
                    }
                    Ok((multistream_select::Negotiation::Success(_), num_read, out_buffer)) => {
                        substream.write(out_buffer);
                        data = &data[num_read..];
                        if let Some(request) = request {
                            substream.write(leb128::encode_usize(request.len()).collect());
                            substream.write(request);
                        }
                        *substream.user_data() = Substream::RequestOut {
                            timeout,
                            user_data,
                            response: leb128::FramedInProgress::new(128 * 1024 * 1024), // TODO: proper max size
                        };
                        let _already_closed = substream.close();
                        debug_assert!(_already_closed.is_none());
                    }
                    Ok((multistream_select::Negotiation::NotAvailable, ..)) => {
                        substream.reset();
                        return Some(Event::Response {
                            user_data,
                            response: Err(RequestError::ProtocolNotAvailable),
                        });
                    }
                    Err(err) => {
                        substream.reset();
                        return Some(Event::Response {
                            user_data,
                            response: Err(RequestError::NegotiationError(err)),
                        });
                    }
                }
            }
            Substream::RequestOut {
                timeout,
                user_data,
                response,
            } => {
                // Note that this might trigger timeouts for requests whose response is available
                // in `incoming_buffer`. This is intentional, as from the perspective of
                // `read_write` the response arrived after the timeout. It is the responsibility
                // of the user to call `read_write` in an appropriate way for this to not happen.
                if timeout < read_write.now {
                    Event::Response {
                        response: Err(RequestError::Timeout),
                        user_data,
                    }
                }

                read_write.wake_up_when(timeout);

                let incoming_buffer = match read_write.incoming_buffer {
                    Some(buf) => buf,
                    None => {
                        read_write.close_write();
                        return Ok((
                            self,
                            Some(Event::Response {
                                id: SubstreamId(substream_id),
                                user_data,
                                response: Err(RequestError::SubstreamClosed),
                            }),
                        ));
                    }
                };

                match response.update(&data) {
                    Ok((_num_read, leb128::Framed::Finished(response))) => {
                        // TODO: proper state transition
                        *substream.user_data() = Substream::NegotiationFailed;
                        return Some(Event::Response {
                            id: substream_id,
                            user_data,
                            response: Ok(response),
                        });
                    }
                    Ok((num_read, leb128::Framed::InProgress(response))) => {
                        debug_assert_eq!(num_read, data.len());
                        data = &data[num_read..];
                        *substream.user_data() = Substream::RequestOut {
                            timeout,
                            user_data,
                            response,
                        };
                    }
                    Err(err) => {
                        substream.reset();
                        return Some(Event::Response {
                            id: substream_id,
                            user_data,
                            response: Err(RequestError::ResponseLebError(err)),
                        });
                    }
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
                        return Ok((
                            Substream::RequestInSend,
                            Some(Event::RequestIn {
                                id: substream_id,
                                protocol_index,
                                request,
                            }),
                        ));
                    }
                    Ok((num_read, leb128::Framed::InProgress(request))) => {
                        read_write.advance_read(num_read);
                        return Ok((
                            Substream::RequestInRecv {
                                request,
                                protocol_index,
                            },
                            None,
                        ));
                    }
                    Err(_err) => {
                        substream.reset();
                        // TODO: report to user
                        todo!()
                    }
                }
            }
            Substream::NotificationsInHandshake {
                handshake,
                protocol_index,
            } => {
                let incoming_buffer = match read_write.incoming_buffer {
                    Some(buf) => buf,
                    None => {
                        read_write.close_write();
                        return Ok((
                            self,
                            Some(Event::NotificationsInOpenCancel {
                                protocol_index,
                            }),
                        ));
                    }
                };

                match handshake.update(incoming_buffer) {
                    Ok((num_read, leb128::Framed::Finished(handshake))) => {
                        read_write.advance_read(num_read);
                        *substream.user_data() = Substream::NotificationsInWait { protocol_index };
                        return Some(Event::NotificationsInOpen {
                            id: substream_id,
                            protocol_index,
                            handshake,
                        });
                    }
                    Ok((num_read, leb128::Framed::InProgress(handshake))) => {
                        read_write.advance_read(num_read);
                        return Ok((
                            Substream::NotificationsInHandshake {
                                handshake,
                                protocol_index,
                            },
                            None,
                        ));
                    }
                    Err(_) => {
                        substream.reset();
                    }
                }
            }
            Substream::NotificationsInWait { protocol_index } => {
                // TODO: what to do with data?
                read_write.discard_all_incoming();
                return Ok((Substream::NotificationsInWait { protocol_index }, None));
            }
            Substream::NotificationsIn {
                mut next_notification,
                protocol_index,
                user_data,
            } => {
                // TODO: rewrite this block to support sending one notification at a time

                let mut notification = None;
                let max_notification_size =
                    self.notifications_protocols[protocol_index].max_notification_size;

                loop {
                    match next_notification.update(&data) {
                        Ok((num_read, leb128::Framed::Finished(notif))) => {
                            data = &data[num_read..];
                            next_notification =
                                leb128::FramedInProgress::new(max_notification_size);
                            //assert!(notification.is_none()); // TODO: outside API doesn't support multiple notifications
                            notification = Some(notif);
                        }
                        Ok((num_read, leb128::Framed::InProgress(next))) => {
                            debug_assert_eq!(num_read, data.len());
                            next_notification = next;
                            break;
                        }
                        Err(_) => {
                            substream.reset();
                            // TODO: report to user; there's no corresponding event yet
                            return None;
                        }
                    }
                }

                *substream.user_data() = Substream::NotificationsIn {
                    next_notification,
                    protocol_index,
                    user_data,
                };

                if let Some(notification) = notification {
                    return Some(Event::NotificationIn {
                        id: substream_id,
                        notification,
                    });
                }
            }
            Substream::PingIn(mut payload) => {
                // Inbound ping substream.
                // The ping protocol consists in sending 32 bytes of data, which the
                // remote has to send back.
                // The `payload` field contains these 32 bytes being received.
                // TODO: re-do
                while read_write.incoming_buffer_available() > 0 {
                    debug_assert!(payload.len() < 32);

                    payload.extend(read_write.incoming_bytes_iter());

                    if payload.len() == 32 {
                        substream.write(payload.to_vec());
                        payload.clear();
                    }
                }

                return Ok((Substream::PingIn(payload), None));
            }
            _ => todo!("other substream kind"),
        };
    }

    pub fn reset(mut self) -> Option<Event<TRqUd, TNotifUd>> {
        match self {
            Substream::Poisoned => unreachable!(),
            Substream::InboundNegotiating(_) => None,
            Substream::NegotiationFailed => None,
            Substream::RequestOutNegotiating { user_data, .. }
            | Substream::RequestOut { user_data, .. } => Some(Event::Response {
                id: SubstreamId(substream_id),
                user_data,
                response: Err(RequestError::SubstreamReset),
            }),
            Substream::RequestInRecv { .. } => None,
            Substream::NotificationsInHandshake { .. } => None,
            Substream::NotificationsInWait { protocol_index, .. } => {
                Some(Event::NotificationsInOpenCancel {
                    id: SubstreamId(substream_id),
                    protocol_index,
                })
            }
            Substream::NotificationsIn { .. } => {
                // TODO: report to user
                None
            }
            Substream::NotificationsInRefused => None,
            Substream::NotificationsOutNegotiating { user_data, .. }
            | Substream::NotificationsOutHandshakeRecv { user_data, .. } => {
                Some(Event::NotificationsOutReject {
                    id: SubstreamId(substream_id),
                    user_data,
                })
            }
            Substream::PingIn(_) => None,
            Substream::NotificationsOut { user_data, .. } => Some(Event::NotificationsOutReset {
                id: SubstreamId(substream_id),
                user_data,
            }),
            Substream::NotificationsOutClosed { .. } => None,
            Substream::RequestInSend => None,
        }
    }

    /// Accepts an inbound notifications protocol. Must be called in response to a
    /// [`Event::NotificationsInOpen`].
    ///
    /// # Panic
    ///
    /// Panics if this substream is not of the correct type.
    ///
    pub fn accept_in_notifications_substream(&mut self, handshake: Vec<u8>, user_data: TNotifUd) {
        match self {
            Substream::NotificationsInWait { protocol_index } => {
                let protocol_index = *protocol_index;
                let max_notification_size =
                    self.inner.notifications_protocols[protocol_index].max_notification_size;

                substream.write(leb128::encode_usize(handshake.len()).collect());
                substream.write(handshake);

                *self = Substream::NotificationsIn {
                    next_notification: leb128::FramedInProgress::new(max_notification_size),
                    protocol_index,
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
                if substream.close().is_none() {
                    *self = Substream::NotificationsInRefused;
                }
            }
            _ => panic!(),
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
            Substream::RequestInRecv { protocol_index, .. } => {
                f.debug_tuple("request-in").field(protocol_index).finish()
            }
            Substream::RequestInSend => {
                todo!() // TODO:
            }
            Substream::PingIn(_) => f.debug_tuple("ping-in").finish(),
        }
    }
}

/// Event that happened on the connection. See [`Substream::read_write`].
#[must_use]
#[derive(Debug)]
pub enum Event<TRqUd, TNotifUd> {
    /// Received a request in the context of a request-response protocol.
    RequestIn {
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
        /// Value that was passed to [`Established::add_request`].
        user_data: TRqUd,
    },

    /// Remote has opened an inbound notifications substream.
    ///
    /// Either [`Established::accept_in_notifications_substream`] or
    /// [`Established::reject_in_notifications_substream`] must be called in the near future in
    /// order to accept or reject this substream.
    NotificationsInOpen {
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
        /// Notification sent by the remote.
        notification: Vec<u8>,
    },

    /// Remote has accepted a substream opened with [`Established::open_notifications_substream`].
    ///
    /// It is now possible to send notifications on this substream.
    NotificationsOutAccept {
        /// Handshake sent back by the remote. Its interpretation is out of scope of this module.
        remote_handshake: Vec<u8>,
    },

    /// Remote has rejected a substream opened with [`Established::open_notifications_substream`].
    NotificationsOutReject {
        /// Value that was passed to [`Established::open_notifications_substream`].
        user_data: TNotifUd,
    },

    /// Remote has closed an outgoing notifications substream, meaning that it demands the closing
    /// of the substream.
    NotificationsOutCloseDemanded,

    /// Remote has reset an outgoing notifications substream. The substream is instantly closed.
    NotificationsOutReset {
        /// Value that was passed to [`Established::open_notifications_substream`].
        user_data: TNotifUd,
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
