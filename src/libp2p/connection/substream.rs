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

use crate::util::leb128;

use super::{multistream_select, noise, yamux};

use alloc::vec::{self, Vec};
use core::{
    cmp, fmt, iter, mem,
    ops::{Add, Sub},
    time::Duration,
};

pub struct Substream<TNow, TRqUd, TNotifUd>(SubstreamInner<TNow, TRqUd, TNotifUd>);

impl<TNow, TRqUd, TNotifUd> Substream<TNow, TRqUd, TNotifUd> {
    /// Initializes a new `Substreams` that tracks a substream opened by the remote.
    // TODO: `Vec` overhead
    pub fn inbound(supported_protocols: impl Into<Vec<String>>) -> Self {
        let nego = multistream_select::InProgress::new(multistream_select::Config::Listener {
            supported_protocols: supported_protocols.into().into_iter(),
        });

        Substream(SubstreamInner::InboundNegotiating(nego))
    }

    /// Closes a notifications substream.
    ///
    /// # Panic
    ///
    /// Panics if the substream isn't a notifications substream.
    ///
    // TODO: inbound? outbound?
    pub fn close_notifications_substream(&mut self) {
        if !matches!(self.0, SubstreamInner::NotificationsOut { .. }) {
            panic!()
        }

        self.0 = SubstreamInner::NotificationsOutClosed;
    }

    /// Returns `true` if the substream is an outbound notifications substream.
    pub fn is_outbound_notifications_substream(&self) -> bool {
        matches!(self.0, SubstreamInner::NotificationsOut { .. })
    }

    /// Returns the user data associated to the substream if it is a notifications substream.
    ///
    /// Returns `None` if the substream isn't a notifications substream.
    pub fn notifications_substream_user_data_mut(&mut self) -> Option<&mut TNotifUd> {
        match &mut self.0 {
            SubstreamInner::NotificationsOutNegotiating { user_data, .. } => Some(user_data),
            SubstreamInner::NotificationsOutHandshakeRecv { user_data, .. } => Some(user_data),
            SubstreamInner::NotificationsOut { user_data } => Some(user_data),
            SubstreamInner::NotificationsIn { user_data, .. } => Some(user_data),
            _ => None,
        }
    }

    /// If the substream has received an inbound request and is waiting for the user to indicate
    /// which respond to send back, transitions it to "response has been sent back".
    ///
    /// Returns an error if the substream is in the wrong state.
    pub fn respond_in_request(&mut self) -> Result<(), ()> {
        match self.0 {
            SubstreamInner::RequestInSend => {
                // TODO: proper state transition
                self.0 = SubstreamInner::NegotiationFailed;

                // TODO:
                //substream.close();
                Ok(())
            }
            _ => Err(()),
        }
    }

    pub fn on_remote_reset(self) -> Option<Event<TRqUd, TNotifUd>> {
        match self.0 {
            SubstreamInner::InboundNegotiating(_) => None,
            SubstreamInner::NegotiationFailed => None,
            SubstreamInner::RequestOutNegotiating { user_data, .. }
            | SubstreamInner::RequestOut { user_data, .. } => Some(Event::Response {
                user_data,
                response: Err(RequestError::SubstreamReset),
            }),
            SubstreamInner::RequestInRecv { .. } => None,
            SubstreamInner::NotificationsInHandshake { .. } => None,
            SubstreamInner::NotificationsInWait { protocol_index, .. } => {
                Some(Event::NotificationsInOpenCancel { protocol_index })
            }
            SubstreamInner::NotificationsIn { .. } => {
                // TODO: report to user
                None
            }
            SubstreamInner::NotificationsOutNegotiating { user_data, .. }
            | SubstreamInner::NotificationsOutHandshakeRecv { user_data, .. } => {
                Some(Event::NotificationsOutReject { user_data })
            }
            SubstreamInner::PingIn(_) => None,
            SubstreamInner::NotificationsOut { user_data, .. } => {
                Some(Event::NotificationsOutReset { user_data })
            }
            SubstreamInner::NotificationsOutClosed { .. } => None,
            SubstreamInner::RequestInSend => None,
        }
    }

    pub fn inject_data(mut self, mut data: &[u8]) -> InjectDataOutcome<TRqUd, TNotifUd> {
        let mut write_out = Vec::new();

        while !data.is_empty() {
            match self.0 {
                SubstreamInner::InboundNegotiating(nego) => match nego.read_write_vec(data) {
                    Ok((multistream_select::Negotiation::InProgress(nego), read, out_buffer)) => {
                        debug_assert_eq!(read, data.len());
                        data = &data[read..];
                        write_out.push(out_buffer);
                        self.0 = SubstreamInner::InboundNegotiating(nego);
                    }
                    Ok((
                        multistream_select::Negotiation::Success(protocol),
                        num_read,
                        out_buffer,
                    )) => {
                        write_out.push(out_buffer);
                        data = &data[num_read..];
                        if protocol == self.ping_protocol {
                            self.0 = SubstreamInner::PingIn(Default::default());
                        } else {
                            if let Some(protocol_index) = self
                                .request_protocols
                                .iter()
                                .position(|p| p.name == protocol)
                            {
                                if let ConfigRequestResponseIn::Payload { max_size } =
                                    self.request_protocols[protocol_index].inbound_config
                                {
                                    self.0 = SubstreamInner::RequestInRecv {
                                        protocol_index,
                                        request: leb128::FramedInProgress::new(max_size),
                                    };
                                } else {
                                    // TODO: make sure that data is empty?
                                    self.0 = SubstreamInner::RequestInSend;
                                    return Some(Event::RequestIn {
                                        protocol_index,
                                        request: Vec::new(),
                                    });
                                }
                            } else if let Some(protocol_index) = self
                                .notifications_protocols
                                .iter()
                                .position(|p| p.name == protocol)
                            {
                                self.0 = SubstreamInner::NotificationsInHandshake {
                                    protocol_index,
                                    handshake: leb128::FramedInProgress::new(
                                        self.notifications_protocols[protocol_index]
                                            .max_handshake_size,
                                    ),
                                };
                            } else {
                                unreachable!()
                            }
                        }
                    }
                    Ok((multistream_select::Negotiation::NotAvailable, num_read, out_buffer)) => {
                        data = &data[num_read..];
                        write_out.push(out_buffer);
                        self.0 = SubstreamInner::NegotiationFailed;
                        substream.close();
                    }
                    Err(_) => {
                        substream.reset();
                    }
                },
                SubstreamInner::NegotiationFailed => {
                    // Substream is an inbound substream that has failed to negotiate a
                    // protocol. The substream is expected to close soon, but the remote might
                    // have been eagerly sending data (assuming that the negotiation would
                    // succeed), which should be silently discarded.
                    data = &[];
                    self.0 = SubstreamInner::NegotiationFailed;
                }
                SubstreamInner::NotificationsOutNegotiating {
                    negotiation,
                    timeout,
                    handshake,
                    user_data,
                } => {
                    match negotiation.read_write_vec(data) {
                        Ok((
                            multistream_select::Negotiation::InProgress(nego),
                            read,
                            out_buffer,
                        )) => {
                            debug_assert_eq!(read, data.len());
                            data = &data[read..];
                            write_out.push(out_buffer);
                            self.0 = SubstreamInner::NotificationsOutNegotiating {
                                negotiation: nego,
                                timeout,
                                handshake,
                                user_data,
                            };
                        }
                        Ok((multistream_select::Negotiation::Success(_), num_read, out_buffer)) => {
                            write_out.push(out_buffer);
                            data = &data[num_read..];
                            write_out.push(leb128::encode_usize(handshake.len()).collect());
                            write_out.push(handshake);
                            self.0 = SubstreamInner::NotificationsOutHandshakeRecv {
                                handshake: leb128::FramedInProgress::new(10 * 1024), // TODO: proper max size
                                user_data,
                            };
                        }
                        _err => todo!("{:?}", _err), // TODO:
                    }
                }
                SubstreamInner::NotificationsOutHandshakeRecv {
                    handshake,
                    user_data,
                } => {
                    match handshake.update(&data) {
                        Ok((num_read, leb128::Framed::Finished(remote_handshake))) => {
                            if num_read != data.len() {
                                todo!() // TODO:
                            }

                            self.0 = SubstreamInner::NotificationsOut { user_data };
                            return Some(Event::NotificationsOutAccept { remote_handshake });
                        }
                        Ok((num_read, leb128::Framed::InProgress(handshake))) => {
                            data = &data[num_read..];
                            self.0 = SubstreamInner::NotificationsOutHandshakeRecv {
                                handshake,
                                user_data,
                            };
                        }
                        Err(_) => {
                            todo!() // TODO: report to user and all
                        }
                    }
                }
                SubstreamInner::NotificationsOut { user_data } => {
                    // Receiving data on an outgoing substream is forbidden by the protocol.
                    data = &[];
                    self.0 = SubstreamInner::NotificationsOut { user_data };
                }
                SubstreamInner::NotificationsOutClosed => {
                    data = &[];
                    self.0 = SubstreamInner::NotificationsOutClosed;
                }
                SubstreamInner::RequestOutNegotiating {
                    negotiation,
                    timeout,
                    request,
                    user_data,
                } => {
                    match negotiation.read_write_vec(data) {
                        Ok((
                            multistream_select::Negotiation::InProgress(nego),
                            _read,
                            out_buffer,
                        )) => {
                            debug_assert_eq!(_read, data.len());
                            data = &data[_read..];
                            write_out.push(out_buffer);
                            self.0 = SubstreamInner::RequestOutNegotiating {
                                negotiation: nego,
                                timeout,
                                request,
                                user_data,
                            };
                        }
                        Ok((multistream_select::Negotiation::Success(_), num_read, out_buffer)) => {
                            write_out.push(out_buffer);
                            data = &data[num_read..];
                            if let Some(request) = request {
                                write_out.push(leb128::encode_usize(request.len()).collect());
                                write_out.push(request);
                            }
                            self.0 = SubstreamInner::RequestOut {
                                timeout,
                                user_data,
                                response: leb128::FramedInProgress::new(10 * 1024 * 1024), // TODO: proper max size
                            };
                            let _already_closed = substream.close();
                            debug_assert!(_already_closed.is_none());
                            substream = self.yamux.substream_by_id(substream_id).unwrap();
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
                SubstreamInner::RequestOut {
                    timeout,
                    user_data,
                    response,
                } => {
                    match response.update(&data) {
                        Ok((_num_read, leb128::Framed::Finished(response))) => {
                            // TODO: proper state transition
                            self.0 = SubstreamInner::NegotiationFailed;
                            return Some(Event::Response {
                                user_data,
                                response: Ok(response),
                            });
                        }
                        Ok((num_read, leb128::Framed::InProgress(response))) => {
                            debug_assert_eq!(num_read, data.len());
                            data = &data[num_read..];
                            self.0 = SubstreamInner::RequestOut {
                                timeout,
                                user_data,
                                response,
                            };
                        }
                        Err(err) => {
                            substream.reset();
                            return Some(Event::Response {
                                user_data,
                                response: Err(RequestError::ResponseLebError(err)),
                            });
                        }
                    }
                }
                SubstreamInner::RequestInRecv {
                    request,
                    protocol_index,
                } => {
                    match request.update(&data) {
                        Ok((_num_read, leb128::Framed::Finished(request))) => {
                            self.0 = SubstreamInner::RequestInSend;
                            return Some(Event::RequestIn {
                                protocol_index,
                                request,
                            });
                        }
                        Ok((num_read, leb128::Framed::InProgress(request))) => {
                            debug_assert_eq!(num_read, data.len());
                            data = &data[num_read..];
                            self.0 = SubstreamInner::RequestInRecv {
                                request,
                                protocol_index,
                            };
                        }
                        Err(_err) => {
                            substream.reset();
                            // TODO: report to user
                            todo!()
                        }
                    }
                }
                SubstreamInner::NotificationsInHandshake {
                    handshake,
                    protocol_index,
                } => match handshake.update(&data) {
                    Ok((num_read, leb128::Framed::Finished(handshake))) => {
                        self.0 = SubstreamInner::NotificationsInWait { protocol_index };
                        debug_assert_eq!(num_read, data.len());
                        return Some(Event::NotificationsInOpen {
                            protocol_index,
                            handshake,
                        });
                    }
                    Ok((num_read, leb128::Framed::InProgress(handshake))) => {
                        data = &data[num_read..];
                        self.0 = SubstreamInner::NotificationsInHandshake {
                            handshake,
                            protocol_index,
                        };
                    }
                    Err(_) => {
                        substream.reset();
                    }
                },
                SubstreamInner::NotificationsInWait { protocol_index } => {
                    // TODO: what to do with data?
                    data = &data[data.len()..];
                    self.0 = SubstreamInner::NotificationsInWait { protocol_index };
                }
                SubstreamInner::NotificationsIn {
                    mut next_notification,
                    protocol_index,
                    user_data,
                } => {
                    // TODO: rewrite this block to support sending one notification at a
                    // time

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
                                // TODO: report to user and all ; this is just a dummy
                                next_notification =
                                    leb128::FramedInProgress::new(max_notification_size);
                                break;
                            }
                        }
                    }

                    self.0 = SubstreamInner::NotificationsIn {
                        next_notification,
                        protocol_index,
                        user_data,
                    };

                    return Some(Event::NotificationIn {
                        notification: notification.unwrap(),
                    });
                }
                SubstreamInner::PingIn(mut payload) => {
                    // Inbound ping substream.
                    // The ping protocol consists in sending 32 bytes of data, which the
                    // remote has to send back.
                    // The `payload` field contains these 32 bytes being received.
                    while !data.is_empty() {
                        debug_assert!(payload.len() < 32);
                        payload.push(data[0]);
                        data = &data[1..];

                        if payload.len() == 32 {
                            substream.write(payload.to_vec());
                            payload.clear();
                        }
                    }

                    self.0 = SubstreamInner::PingIn(payload);
                }
                _ => todo!("other substream kind"),
            };
        }

        None
    }
}

impl<TNow, TRqUd, TNotifUd> fmt::Debug for Substream<TNow, TRqUd, TNotifUd>
where
    TRqUd: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            SubstreamInner::NegotiationFailed => {
                f.debug_tuple("incoming-negotiation-failed").finish()
            }
            SubstreamInner::InboundNegotiating(_) => f.debug_tuple("incoming-negotiating").finish(),
            SubstreamInner::NotificationsOutNegotiating { .. } => {
                todo!() // TODO:
            }
            SubstreamInner::NotificationsOutHandshakeRecv { .. } => {
                todo!() // TODO:
            }
            SubstreamInner::NotificationsOut { .. } => f.debug_tuple("notifications-out").finish(),
            SubstreamInner::NotificationsOutClosed { .. } => {
                f.debug_tuple("notifications-out-closed").finish()
            }
            SubstreamInner::NotificationsInHandshake { protocol_index, .. } => f
                .debug_tuple("notifications-in-handshake")
                .field(protocol_index)
                .finish(),
            SubstreamInner::NotificationsInWait { .. } => {
                todo!() // TODO:
            }
            SubstreamInner::NotificationsIn { .. } => f.debug_tuple("notifications-in").finish(),
            SubstreamInner::RequestOutNegotiating { user_data, .. }
            | SubstreamInner::RequestOut { user_data, .. } => {
                f.debug_tuple("request-out").field(&user_data).finish()
            }
            SubstreamInner::RequestInRecv { protocol_index, .. } => {
                f.debug_tuple("request-in").field(protocol_index).finish()
            }
            SubstreamInner::RequestInSend => {
                todo!() // TODO:
            }
            SubstreamInner::PingIn(_) => f.debug_tuple("ping-in").finish(),
        }
    }
}

pub struct InjectDataOutcome<TRqUd, TNotifUd> {
    pub event: Option<Event<TRqUd, TNotifUd>>,
    /// List of buffers to queue for writing on the substream.
    pub write_out: Vec<Vec<u8>>,
}

/// Event that happened on the connection. See [`ReadWrite::event`].
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

enum SubstreamInner<TNow, TRqUd, TNotifUd> {
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
    PingIn(arrayvec::ArrayVec<[u8; 32]>),
}
