// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! State machine handling a single TCP or WebSocket libp2p connection.
//!
//! This state machine tries to negotiate and apply the noise and yamux protocols on top of the
//! connection.

use crate::network::leb128;

use core::{
    convert::TryFrom as _,
    fmt, iter, mem,
    ops::{Add, Sub},
    time::Duration,
};
use libp2p::PeerId;

pub use noise::{NoiseKey, UnsignedNoiseKey};

pub mod multistream_select;
pub mod noise;
pub mod yamux;

mod tests;

// TODO: needs a timeout for the handshake

pub struct Connection<TNow, TRqUd, TNotifUd, TProtoList, TProto> {
    /// Encryption layer applied directly on top of the incoming data and outgoing data.
    /// In addition to the cipher state, also contains a buffer of data received from the socket,
    /// decoded but yet to be parsed.
    // TODO: move this decoded-data buffer here
    encryption: noise::Noise,
    /// State of the various substreams of the connection.
    /// Consists in a collection of substreams, each of which holding a [`Substream`] object.
    /// Also includes, for each substream, a collection of buffers whose data is to be written
    /// out.
    yamux: yamux::Connection<Substream<TNow, TRqUd, TProtoList, TProto>>,

    /// List of request-response protocols.
    in_request_protocols: TProtoList,
    /// List of notifications protocols.
    in_notifications_protocols: TProtoList,

    marker: core::marker::PhantomData<TNotifUd>, // TODO: remove
}

enum Substream<TNow, TRqUd, TProtoList, TProto> {
    /// Temporary transition state.
    Poisoned,
    /// Protocol negotiation is still in progress on this substream.
    Negotiating(multistream_select::InProgress<iter::Chain<TProtoList, TProtoList>, TProto>),
    NotificationsOut,
    /// A notifications protocol has been negotiated on an incoming substream. A handshake from
    /// the remote is expected.
    NotificationsInHandshake {
        /// Buffer for the incoming handshake.
        handshake: leb128::Framed,
        /// Protocol that was negotiated.
        protocol: TProto,
    },
    /// A handshake on a notifications protocol has been received. Now waiting for an action from
    /// the API user.
    NotificationsInWait,
    /// Negotiating a protocol for an outgoing request.
    RequestOutNegotiating {
        /// When the request will time out in the absence of response.
        timeout: TNow,
        negotiation: multistream_select::InProgress<TProtoList, TProto>,
        request: Vec<u8>,
        /// Data passed by the user to [`Connection::add_request`].
        user_data: TRqUd,
    },
    /// Outgoing request has been sent out or is queued for send out, and a response from the
    /// remote is now expected.
    RequestOut {
        /// When the request will time out in the absence of response.
        timeout: TNow,
        /// Data passed by the user to [`Connection::add_request`].
        user_data: TRqUd,
        /// Buffer for the incoming response.
        response: leb128::Framed,
    },
    /// A request-response protocol has been negotiated on an inbound substream. A request is now
    /// expected.
    RequestInRecv {
        /// Buffer for the incoming request.
        request: leb128::Framed,
        /// Protocol that was negotiated.
        protocol: TProto,
    },
    RequestInSend,
}

impl<TNow, TRqUd, TNotifUd, TProtoList, TProto>
    Connection<TNow, TRqUd, TNotifUd, TProtoList, TProto>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
    TProtoList: Iterator<Item = TProto> + Clone,
    TProto: AsRef<str>,
{
    /// Reads data coming from the socket from `incoming_data`, updates the internal state machine,
    /// and writes data destined to the socket to `outgoing_buffer`.
    ///
    /// `incoming_data` should be `None` if the remote has closed their writing side.
    ///
    /// The returned structure contains the number of bytes read and written from/to the two
    /// buffers. In order to avoid unnecessary memory allocations, only one [`Event`] is returned
    /// at a time. Consequently, this method returns as soon as an event is available, even if the
    /// buffers haven't finished being read. Call this method in a loop until these two values are
    /// both 0 and [`ReadWrite::event`] is `None`.
    ///
    /// If the remote isn't ready to accept new data, pass an empty slice as `outgoing_buffer`.
    ///
    /// The current time must be passed via the `now` parameter. This is used internally in order
    /// to keep track of ping times and timeouts. The returned structure optionally contains a
    /// `TNow` representing the moment after which this method should be called again.
    ///
    /// If an error is returned, the socket should be entirely shut down.
    pub fn read_write(
        mut self,
        now: TNow,
        mut incoming_data: Option<&[u8]>,
        mut outgoing_buffer: &mut [u8],
    ) -> Result<ReadWrite<TNow, TRqUd, TNotifUd, TProtoList, TProto>, Error> {
        let mut total_read = 0;
        let mut total_written = 0;

        // TODO: need to check timeouts

        // Decoding the incoming data.
        loop {
            // Transfer data from `incoming_data` to the internal buffer in `self.encryption`.
            if let Some(incoming_data) = incoming_data.as_mut() {
                let num_read = self
                    .encryption
                    .inject_inbound_data(*incoming_data)
                    .map_err(Error::Noise)?;
                total_read += num_read;
                *incoming_data = &incoming_data[num_read..];
            }

            // TODO: handle incoming_data being None

            // Ask the Yamux state machine to decode the buffer present in `self.encryption`.
            let yamux_decode = self
                .yamux
                .incoming_data(self.encryption.decoded_inbound_data())
                .map_err(|err| Error::Yamux(err))?;
            self.yamux = yamux_decode.yamux;

            // TODO: it is possible that the yamux reading is blocked on writing

            // Analyze how Yamux has parsed the data.
            // This still contains references to the data in `self.encryption`.
            let (mut data, mut substream) = match yamux_decode.detail {
                None => {
                    if yamux_decode.bytes_read == 0 {
                        break;
                    }
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);
                    continue;
                }

                Some(yamux::IncomingDataDetail::IncomingSubstream) => {
                    // Receive a request from the remote for a new incoming substream.
                    // These requests are automatically accepted.
                    // TODO: add a limit to the number of substreams
                    let nego =
                        multistream_select::InProgress::new(multistream_select::Config::Listener {
                            supported_protocols: self
                                .in_request_protocols
                                .clone()
                                .chain(self.in_notifications_protocols.clone()),
                        });
                    self.yamux
                        .accept_pending_substream(Substream::Negotiating(nego));
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);
                    continue;
                }

                Some(yamux::IncomingDataDetail::DataFrame {
                    start_offset,
                    substream_id,
                }) => {
                    // Data belonging to a substream has been decoded.
                    let data = &self.encryption.decoded_inbound_data()
                        [start_offset..yamux_decode.bytes_read];
                    let substream = self.yamux.substream_by_id(substream_id).unwrap();
                    (data, substream)
                }
            };

            while !data.is_empty() {
                match mem::replace(substream.user_data(), Substream::Poisoned) {
                    Substream::Poisoned => unreachable!("poisoned"), // TODO: remove cause
                    Substream::Negotiating(nego) => {
                        match nego.read_write_vec(data) {
                            Ok((
                                multistream_select::Negotiation::InProgress(nego),
                                _read,
                                out_buffer,
                            )) => {
                                debug_assert_eq!(_read, data.len());
                                data = &data[_read..];
                                substream.write(out_buffer);
                                *substream.user_data() = Substream::Negotiating(nego);
                            }
                            Ok((
                                multistream_select::Negotiation::Success(protocol),
                                num_read,
                                out_buffer,
                            )) => {
                                substream.write(out_buffer);
                                data = &data[num_read..];
                                println!("negotiated {:?}", protocol.as_ref());
                                let is_request_response = self
                                    .in_request_protocols
                                    .clone()
                                    .any(|p| AsRef::as_ref(&p) == AsRef::as_ref(&protocol));
                                if is_request_response {
                                    *substream.user_data() = Substream::RequestInRecv {
                                        protocol,
                                        request: leb128::Framed::new(10 * 1024 * 1024), // TODO: proper size
                                    };
                                } else {
                                    *substream.user_data() = Substream::NotificationsInHandshake {
                                        protocol,
                                        handshake: leb128::Framed::new(10 * 1024 * 1024), // TODO: proper size
                                    };
                                }
                            }
                            Err(_) => {
                                substream.reset();
                                break;
                            }
                            _ => todo!("other state"),
                        }
                    }
                    Substream::RequestOutNegotiating {
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
                                substream.write(out_buffer);
                                *substream.user_data() = Substream::RequestOutNegotiating {
                                    negotiation: nego,
                                    timeout,
                                    request,
                                    user_data,
                                };
                            }
                            Ok((
                                multistream_select::Negotiation::Success(protocol),
                                num_read,
                                out_buffer,
                            )) => {
                                substream.write(out_buffer);
                                data = &data[num_read..];
                                println!("negotiated {:?}", protocol.as_ref());
                                // TODO: better code for the length
                                substream.write(parity_scale_codec::Encode::encode(
                                    &parity_scale_codec::Compact(
                                        u64::try_from(request.len()).unwrap(),
                                    ),
                                ));
                                substream.write(request);
                                *substream.user_data() = Substream::RequestOut {
                                    timeout,
                                    user_data,
                                    response: leb128::Framed::new(10 * 1024 * 1024), // TODO: proper max size
                                };
                            }
                            Err(_) => {
                                let substream_id = substream.id();
                                substream.reset();
                                return Ok(ReadWrite {
                                    connection: self,
                                    read_bytes: total_read,
                                    written_bytes: total_written,
                                    wake_up_after: None, // TODO:
                                    event: Some(Event::Response {
                                        id: SubstreamId(substream_id),
                                        user_data,
                                        response: Err(()),
                                    }),
                                });
                            }
                            _ => todo!("other state"),
                        }
                    }
                    Substream::RequestOut {
                        timeout,
                        user_data,
                        mut response,
                    } => {
                        let num_read = response.inject_data(&data).unwrap(); // TODO: don't unwrap
                        data = &data[num_read..];
                        if let Some(response) = response.take_frame() {
                            let substream_id = substream.id();
                            // TODO: state transition
                            return Ok(ReadWrite {
                                connection: self,
                                read_bytes: total_read,
                                written_bytes: total_written,
                                wake_up_after: None, // TODO:
                                event: Some(Event::Response {
                                    id: SubstreamId(substream_id),
                                    user_data,
                                    response: Ok(response.into()),
                                }),
                            });
                        }
                        todo!()
                    }
                    Substream::RequestInRecv {
                        mut request,
                        protocol,
                    } => {
                        data = &data[data.len()..];
                        *substream.user_data() = Substream::RequestInRecv { request, protocol };
                        // TODO:
                        /*let num_read = request.inject_data(&data).unwrap(); // TODO: don't unwrap
                        if let Some(request) = request.take_frame() {
                            let substream_id = substream.id();
                            // TODO: state transition
                            return Ok(ReadWrite {
                                connection: self,
                                read_bytes: total_read,
                                written_bytes: total_written,
                                wake_up_after: None, // TODO:
                                event: Some(Event::RequestIn {
                                    id: SubstreamId(substream_id),
                                    protocol,
                                    request: request.into(),
                                }),
                            });
                        }
                        todo!()*/
                    }
                    Substream::NotificationsInHandshake {
                        mut handshake,
                        protocol,
                    } => {
                        let num_read = handshake.inject_data(&data).unwrap(); // TODO: don't unwrap
                        data = &data[num_read..];
                        if let Some(handshake) = handshake.take_frame() {
                            let substream_id = substream.id();
                            *substream.user_data() = Substream::NotificationsInWait;
                            return Ok(ReadWrite {
                                connection: self,
                                read_bytes: total_read,
                                written_bytes: total_written,
                                wake_up_after: None, // TODO:
                                event: Some(Event::NotificationsInOpen {
                                    id: SubstreamId(substream_id),
                                    protocol,
                                    handshake: handshake.into(),
                                }),
                            });
                        }
                        *substream.user_data() = Substream::NotificationsInHandshake {
                            handshake,
                            protocol,
                        };
                    }
                    Substream::NotificationsInWait => {
                        // TODO: what to do with data?
                        data = &data[data.len()..];
                        *substream.user_data() = Substream::NotificationsInWait;
                    }
                    _ => todo!("other substream kind"),
                }
            }

            // Now that the Yamux parsing has been processed, discard this data in
            // `self.encryption` and loop again, or stop looping if no more data is decodable.
            if yamux_decode.bytes_read == 0 {
                break;
            }
            self.encryption
                .consume_inbound_data(yamux_decode.bytes_read);
        }

        // The yamux state machine contains the data that needs to be written out.
        // Try to flush it.
        loop {
            let bytes_out = self.encryption.encrypt_size_conv(outgoing_buffer.len());
            if bytes_out == 0 {
                break;
            }

            let mut buffers = self.yamux.extract_out(bytes_out);
            let mut buffers = buffers.buffers().peekable();
            if buffers.peek().is_none() {
                break;
            }

            let (_read, written) = self.encryption.encrypt(buffers, &mut outgoing_buffer);
            debug_assert!(_read <= bytes_out);
            total_written += written;
            outgoing_buffer = &mut outgoing_buffer[written..];
        }

        Ok(ReadWrite {
            connection: self,
            read_bytes: total_read,
            written_bytes: total_written,
            wake_up_after: None,
            event: None, // TODO:
        })
    }

    /// Sends a request to the remote.
    ///
    /// This method only inserts the request into the connection object. Use
    /// [`Connection::read_write`] in order to actually send out the request.
    ///
    /// Assuming that the remote is using the same implementation, an [`Event::RequestIn`] will
    /// be generated on its side.
    ///
    /// After the remote has sent back a response, an [`Event::Response`] event will be generated
    /// locally. The `user_data` parameter will be passed back.
    pub fn add_request(
        &mut self,
        now: TNow,
        protocol: TProto,
        request: Vec<u8>,
        user_data: TRqUd,
    ) -> SubstreamId {
        let mut negotiation =
            multistream_select::InProgress::new(multistream_select::Config::Dialer {
                requested_protocol: protocol,
            });

        let (new_state, _, out_buffer) = negotiation.read_write_vec(&[]).unwrap();
        match new_state {
            multistream_select::Negotiation::InProgress(n) => negotiation = n,
            _ => unreachable!(),
        }

        let mut substream = self.yamux.open_substream(Substream::RequestOutNegotiating {
            timeout: now + Duration::from_secs(20), // TODO:
            negotiation,
            request,
            user_data,
        });

        substream.write(out_buffer);

        SubstreamId(substream.id())
    }

    /// Opens a outgoing substream with the given protocol, destined for a stream of
    /// notifications.
    ///
    /// The remote must first accept (or reject) the substream before notifications can be sent
    /// on it.
    ///
    /// This method only inserts the opening handshake into the connection object. Use
    /// [`Connection::read_write`] in order to actually send out the request.
    ///
    /// Assuming that the remote is using the same implementation, an
    /// [`Event::NotificationsInOpen`] will be generated on its side.
    ///
    pub fn open_notifications_substream(
        &mut self,
        now: TNow,
        protocol: TProto,
        handshake: Vec<u8>,
    ) -> SubstreamId {
        todo!("open_notifications_substream")
    }
}

impl<TNow, TRqUd, TNotifUd, TProtoList, TProto> fmt::Debug
    for Connection<TNow, TRqUd, TNotifUd, TProtoList, TProto>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: show substreams list
        f.debug_struct("Connection").finish()
    }
}

/// Identifier of a request or a notifications substream.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubstreamId(yamux::SubstreamId);

/// Outcome of [`Connection::read_write`].
#[must_use]
#[derive(Debug)]
pub struct ReadWrite<TNow, TRqUd, TNotifUd, TProtoList, TProto> {
    /// Connection object yielded back.
    pub connection: Connection<TNow, TRqUd, TNotifUd, TProtoList, TProto>,

    /// Number of bytes at the start of the incoming buffer that have been processed. These bytes
    /// should no longer be present the next time [`Connection::read_write`] is called.
    pub read_bytes: usize,

    /// Number of bytes written to the outgoing buffer. These bytes should be sent out to the
    /// remote. The rest of the outgoing buffer is left untouched.
    pub written_bytes: usize,

    /// If `Some`, [`Connection::read_write`] should be called again when the point in time
    /// reaches the value in the `Option`.
    pub wake_up_after: Option<TNow>,

    /// Event that happened on the connection.
    pub event: Option<Event<TRqUd, TNotifUd, TProto>>,
}

/// Event that happened on the connection. See [`ReadWrite::event`].
#[must_use]
#[derive(Debug)]
pub enum Event<TRqUd, TNotifUd, TProto> {
    /// No more outgoing data will be emitted. The local writing side of the connection should be
    /// closed.
    // TODO: remove?
    EndOfData,
    /// Received a request in the context of a request-response protocol.
    RequestIn {
        /// Identifier of the request. Needs to be provided back when answering the request.
        id: SubstreamId,
        /// Protocol the request was sent on.
        protocol: TProto,
        /// Bytes of the request. Its interpretation is out of scope of this module.
        request: Vec<u8>,
    },
    /// Received a response to a previously emitted request on a request-response protocol.
    Response {
        /// Bytes of the response. Its interpretation is out of scope of this module.
        // TODO: error type
        response: Result<Vec<u8>, ()>,
        /// Identifier of the request. Value that was returned by [`Connection::add_request`].
        id: SubstreamId,
        /// Value that was passed to [`Connection::add_request`].
        user_data: TRqUd,
    },
    NotificationsInOpen {
        /// Identifier of the substream. Needs to be provided back when accept or rejecting the
        /// substream.
        id: SubstreamId,
        /// Protocol concerned by the substream.
        protocol: TProto,
        /// Handshake sent by the remote. Its interpretation is out of scope of this module.
        handshake: Vec<u8>,
    },
    /// Remote has accepted a substream opened with [`Connection::open_notifications_substream`].
    ///
    /// It is now possible to send notifications on this substream.
    NotificationsOutAccept {
        /// Identifier of the substream. Value that was returned by
        /// [`Connection::open_notifications_substream`].
        id: SubstreamId,
        /// Value that was passed to [`Connection::open_notifications_substream`].
        user_data: TNotifUd,
        /// Handshake sent back by the remote. Its interpretation is out of scope of this module.
        remote_handshake: Vec<u8>,
    },
    /// Remote has rejected a substream opened with [`Connection::open_notifications_substream`].
    NotificationsOutReject {
        /// Identifier of the substream. Value that was returned by
        /// [`Connection::open_notifications_substream`].
        id: SubstreamId,
        /// Value that was passed to [`Connection::open_notifications_substream`].
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

/// Successfully negotiated connection. Ready to be turned into a [`Connection`].
pub struct ConnectionPrototype {
    encryption: noise::Noise,
}

impl ConnectionPrototype {
    /// Turns this prototype into an actual connection.
    pub fn into_connection<TNow, TRqUd, TNotifUd, TProtoList, TProto>(
        self,
        config: Config<TProtoList>,
    ) -> Connection<TNow, TRqUd, TNotifUd, TProtoList, TProto> {
        let yamux = yamux::Connection::new(yamux::Config {
            is_initiator: self.encryption.is_initiator(),
            capacity: 64, // TODO: ?
            randomness_seed: config.randomness_seed,
        });

        Connection {
            encryption: self.encryption,
            yamux,
            in_request_protocols: config.in_request_protocols,
            in_notifications_protocols: config.in_notifications_protocols,
            marker: core::marker::PhantomData,
        }
    }
}

impl fmt::Debug for ConnectionPrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ConnectionPrototype").finish()
    }
}

/// Configuration to turn a [`ConnectionPrototype`] into a [`Connection`].
pub struct Config<TProtoList> {
    /// List of request-response protocols supported for incoming substreams.
    pub in_request_protocols: TProtoList,
    /// List of notifications protocols supported for incoming substreams.
    pub in_notifications_protocols: TProtoList,
    /// Seed used for the randomness specific to this connection.
    pub randomness_seed: (u64, u64),
}

/// Current state of a connection handshake.
#[derive(Debug, derive_more::From)]
pub enum Handshake {
    /// Connection handshake in progress.
    Healthy(HealthyHandshake),
    /// Connection handshake has reached the noise handshake, and it is necessary to know the
    /// noise key in order to proceed.
    NoiseKeyRequired(NoiseKeyRequired),
    /// Handshake has succeeded. Connection is now open.
    Success {
        /// Network identity of the remote.
        remote_peer_id: PeerId,
        /// Prototype for the connection.
        connection: ConnectionPrototype,
    },
}

impl Handshake {
    /// Shortcut for [`HealthyHandshake::new`] wrapped in a [`Connection`].
    pub fn new(is_initiator: bool) -> Self {
        HealthyHandshake::new(is_initiator).into()
    }
}

/// Connection handshake in progress.
pub struct HealthyHandshake {
    state: HandshakeState,
}

enum HandshakeState {
    NegotiatingEncryptionProtocol {
        negotiation: multistream_select::InProgress<iter::Once<&'static str>, &'static str>,
        is_initiator: bool,
    },
    NegotiatingEncryption {
        handshake: noise::HandshakeInProgress,
    },
    NegotiatingMultiplexing {
        peer_id: PeerId,
        encryption: noise::Noise,
        negotiation: multistream_select::InProgress<iter::Once<&'static str>, &'static str>,
    },
}

impl HealthyHandshake {
    /// Initializes a new state machine.
    ///
    /// Must pass [`Endpoint::Dialer`] if the connection has been opened by the local machine,
    /// and [`Endpoint::Listener`] if it has been opened by the remote.
    pub fn new(is_initiator: bool) -> Self {
        let negotiation = multistream_select::InProgress::new(if is_initiator {
            multistream_select::Config::Dialer {
                requested_protocol: noise::PROTOCOL_NAME,
            }
        } else {
            multistream_select::Config::Listener {
                supported_protocols: iter::once(noise::PROTOCOL_NAME),
            }
        });

        HealthyHandshake {
            state: HandshakeState::NegotiatingEncryptionProtocol {
                negotiation,
                is_initiator,
            },
        }
    }

    /// Feeds data coming from a socket through `incoming_data`, updates the internal state
    /// machine, and writes data destined to the socket to `outgoing_buffer`.
    ///
    /// On success, returns the new state of the negotiation, plus the number of bytes that have
    /// been read from `incoming_data` and the number of bytes that have been written to
    /// `outgoing_buffer`.
    ///
    /// An error is returned if the protocol is being violated by the remote. When that happens,
    /// the connection should be closed altogether.
    ///
    /// If the remote isn't ready to accept new data, pass an empty slice as `outgoing_buffer`.
    pub fn read_write(
        mut self,
        mut incoming_buffer: &[u8],
        mut outgoing_buffer: &mut [u8],
    ) -> Result<(Handshake, usize, usize), HandshakeError> {
        let mut total_read = 0;
        let mut total_written = 0;

        loop {
            match self.state {
                HandshakeState::NegotiatingEncryptionProtocol {
                    negotiation,
                    is_initiator,
                } => {
                    let (updated, num_read, num_written) = negotiation
                        .read_write(incoming_buffer, outgoing_buffer)
                        .map_err(HandshakeError::MultistreamSelect)?;
                    total_read += num_read;
                    total_written += num_written;
                    // TODO: what to do with these warnings here? the warnings are legit, but removing these lines below would be error-prone for the future
                    incoming_buffer = &incoming_buffer[num_read..];
                    outgoing_buffer = &mut outgoing_buffer[num_written..];

                    match updated {
                        multistream_select::Negotiation::InProgress(updated) => {
                            self.state = HandshakeState::NegotiatingEncryptionProtocol {
                                negotiation: updated,
                                is_initiator,
                            };
                            break;
                        }
                        multistream_select::Negotiation::Success(_) => {
                            return Ok((
                                Handshake::NoiseKeyRequired(NoiseKeyRequired { is_initiator }),
                                total_read,
                                total_written,
                            ));
                        }
                        multistream_select::Negotiation::NotAvailable => {
                            return Err(HandshakeError::NoEncryptionProtocol);
                        }
                    }
                }

                HandshakeState::NegotiatingEncryption { handshake } => {
                    let (updated, num_read, num_written) = handshake
                        .read_write(incoming_buffer, &mut outgoing_buffer)
                        .map_err(HandshakeError::NoiseHandshake)?;
                    total_read += num_read;
                    total_written += num_written;
                    incoming_buffer = &incoming_buffer[num_read..];
                    outgoing_buffer = &mut outgoing_buffer[num_written..];

                    match updated {
                        noise::NoiseHandshake::Success {
                            cipher,
                            remote_peer_id,
                        } => {
                            let negotiation =
                                multistream_select::InProgress::new(if cipher.is_initiator() {
                                    multistream_select::Config::Dialer {
                                        requested_protocol: yamux::PROTOCOL_NAME,
                                    }
                                } else {
                                    multistream_select::Config::Listener {
                                        supported_protocols: iter::once(yamux::PROTOCOL_NAME),
                                    }
                                });

                            self.state = HandshakeState::NegotiatingMultiplexing {
                                peer_id: remote_peer_id,
                                encryption: cipher,
                                negotiation,
                            };
                        }
                        noise::NoiseHandshake::InProgress(updated) => {
                            self.state =
                                HandshakeState::NegotiatingEncryption { handshake: updated };
                            break;
                        }
                    };
                }

                HandshakeState::NegotiatingMultiplexing {
                    negotiation,
                    mut encryption,
                    peer_id,
                } => {
                    let num_read = encryption
                        .inject_inbound_data(incoming_buffer)
                        .map_err(HandshakeError::Noise)?;
                    total_read += incoming_buffer.len();
                    incoming_buffer = &incoming_buffer[num_read..];

                    let mut buffer = vec![0; encryption.encrypt_size_conv(outgoing_buffer.len())];

                    let (updated, read_num, written_interm) = negotiation
                        .read_write(encryption.decoded_inbound_data(), &mut buffer)
                        .map_err(HandshakeError::MultistreamSelect)?;
                    encryption.consume_inbound_data(read_num);
                    let (_read, written) =
                        encryption.encrypt(iter::once(&buffer[..written_interm]), outgoing_buffer);
                    debug_assert_eq!(_read, written_interm);
                    outgoing_buffer = &mut outgoing_buffer[written..];
                    total_written += written;

                    match updated {
                        multistream_select::Negotiation::InProgress(updated) => {
                            self.state = HandshakeState::NegotiatingMultiplexing {
                                negotiation: updated,
                                encryption,
                                peer_id,
                            };
                            break;
                        }
                        multistream_select::Negotiation::Success(_) => {
                            return Ok((
                                Handshake::Success {
                                    connection: ConnectionPrototype { encryption },
                                    remote_peer_id: peer_id,
                                },
                                total_read,
                                total_written,
                            ));
                        }
                        multistream_select::Negotiation::NotAvailable => {
                            return Err(HandshakeError::NoMultiplexingProtocol)
                        }
                    }
                }
            }
        }

        Ok((Handshake::Healthy(self), total_read, total_written))
    }
}

impl fmt::Debug for HealthyHandshake {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HealthyHandshake").finish()
    }
}

/// Connection handshake has reached the noise handshake, and it is necessary to know the noise
/// key in order to proceed.
pub struct NoiseKeyRequired {
    is_initiator: bool,
}

impl NoiseKeyRequired {
    /// Turn this [`NoiseKeyRequired`] back into a [`Healthy`] by indicating the noise key.
    pub fn resume(self, noise_key: &NoiseKey) -> HealthyHandshake {
        HealthyHandshake {
            state: HandshakeState::NegotiatingEncryption {
                handshake: noise::HandshakeInProgress::new(noise_key, self.is_initiator),
            },
        }
    }
}

impl fmt::Debug for NoiseKeyRequired {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("NoiseKeyRequired").finish()
    }
}

/// Error during a connection handshake. The connection should be shut down.
#[derive(Debug, derive_more::Display)]
pub enum HandshakeError {
    /// Protocol error during a multistream-select negotiation.
    MultistreamSelect(multistream_select::Error),
    /// Protocol error during the noise handshake.
    NoiseHandshake(noise::HandshakeError),
    /// No encryption protocol in common with the remote.
    ///
    /// The remote is behaving correctly but isn't compatible with the local node.
    NoEncryptionProtocol,
    /// No multiplexing protocol in common with the remote.
    ///
    /// The remote is behaving correctly but isn't compatible with the local node.
    NoMultiplexingProtocol,
    /// Error in the noise cipher. Data has most likely been corrupted.
    Noise(noise::CipherError),
}
