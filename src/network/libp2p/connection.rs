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

use core::{
    fmt, iter,
    ops::{Add, Sub},
    time::Duration,
};
use libp2p::PeerId;

pub use noise::{NoiseKey, UnsignedNoiseKey};

mod multistream_select;
mod noise;
mod substream;
mod yamux;

// TODO: needs a timeout for the handshake

pub struct Connection<TNow> {
    encryption: noise::Noise,
    yamux: yamux::Connection<Substream>,
    marker: core::marker::PhantomData<TNow>, // TODO: remove
}

struct Substream {
    /// Specialization for that substream.
    ty: SubstreamTy,
}

enum SubstreamTy {
    /// Protocol negotiation is still in progress on this substream.
    Negotiating(multistream_select::InProgress<iter::Once<&'static str>, &'static str>),
    NotificationsOut,
    NotificationsIn,
    RequestOut,
    RequestIn,
}

impl<TNow> Connection<TNow>
where
    TNow: Clone + Add<Duration> + Sub<TNow, Output = Duration> + Ord,
{
    /// Reads data coming from the socket from `incoming_data`, updates the internal state machine,
    /// and writes data destined to the socket to `outgoing_buffer`.
    ///
    /// `incoming_data` should be `None` if the remote has closed their writing side.
    ///
    /// The returned structure contains the number of bytes read and written from/to the two
    /// buffers. Call this method in a loop until these two values are both 0 and
    /// [`ReadWrite::event`] is `None`.
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
    ) -> Result<ReadWrite<TNow>, Error> {
        let mut total_read = 0;

        if let Some(incoming_data) = incoming_data.as_mut() {
            let num_read = self
                .encryption
                .inject_inbound_data(*incoming_data)
                .map_err(Error::Noise)?;
            total_read += incoming_data.len();
            *incoming_data = &incoming_data[num_read..];
        }

        /*loop {
            let mut buffer = encryption.prepare_buffer_encryption(destination);
            let (updated, written_interm) = negotiation.write_out(&mut *buffer);
            let written = buffer.finish(written_interm);
            destination = &mut destination[written..];
            total_written += written;

            self.state = match updated {
                multistream_select::Negotiation::InProgress(updated) => {
                    HandshakeState::NegotiatingMultiplexing {
                        encryption,
                        negotiation: updated,
                        peer_id,
                    }
                }
                multistream_select::Negotiation::Success(_) => {
                    return (
                        Handshake::Success {
                            connection: Connection { encryption },
                            remote_peer_id: peer_id,
                        },
                        total_written,
                    );
                }
                multistream_select::Negotiation::NotAvailable => todo!(), // TODO: ?!
            };

            if written == 0 {
                break;
            }
        }*/

        todo!()
    }

    /// Send a request to the remote.
    ///
    /// Assuming that the remote is using the same implementation, an [`Event::RequestIn`] will
    /// be generated on their side.
    ///
    /// After the remote has sent back a response, a [`Event::Response`] event will be generated
    /// locally.
    // TODO: pass protocol
    // TODO: finish docs
    pub fn start_request(&mut self, request: Vec<u8>) {
        todo!()
    }
}

impl<TNow> fmt::Debug for Connection<TNow> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: better debug
        f.debug_struct("Connection").finish()
    }
}

/// Outcome of [`Connection::read_write`].
#[must_use]
#[derive(Debug)]
pub struct ReadWrite<TNow> {
    /// Connection object yielded back.
    pub connection: Connection<TNow>,

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
    pub event: Option<Event>,
}

/// Event that happened on the connection. See [`ReadWrite::event`].
#[must_use]
#[derive(Debug)]
pub enum Event {
    /// No more outgoing data will be emitted. The local writing side of the connection should be
    /// closed.
    // TODO: remove?
    EndOfData,
    /// Received a request in the context of a request-response protocol.
    RequestIn {
        // TODO: protocol: ...
        /// Bytes of the request. Its interpretation is out of scope of this module.
        request: Vec<u8>,
    },
    /// Received a response to a previously emitted request on a request-response protocol.
    Response {
        // TODO: user_data: ...
        /// Bytes of the response. Its interpretation is out of scope of this module.
        response: Vec<u8>,
    },
}

#[derive(derive_more::From)]
pub enum Handshake {
    Healthy(HealthyHandshake),
    /// Connection handshake has reached the noise handshake, and it is necessary to know the
    /// noise key in order to proceed.
    NoiseKeyRequired(NoiseKeyRequired),
    Success {
        remote_peer_id: PeerId,
        connection: Connection<std::time::Instant>, // TODO: no for generic
    },
}

impl Handshake {
    /// Shortcut for [`HealthyHandshake::new`] wrapped in a [`Connection`].
    pub fn new(is_initiator: bool) -> Self {
        HealthyHandshake::new(is_initiator).into()
    }
}

pub struct HealthyHandshake {
    is_initiator: bool,
    state: HandshakeState,
}

enum HandshakeState {
    NegotiatingEncryptionProtocol {
        negotiation: multistream_select::InProgress<iter::Once<&'static str>, &'static str>,
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
            is_initiator,
            state: HandshakeState::NegotiatingEncryptionProtocol { negotiation },
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
                HandshakeState::NegotiatingEncryptionProtocol { negotiation } => {
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
                            };
                            break;
                        }
                        multistream_select::Negotiation::Success(_) => {
                            return Ok((
                                Handshake::NoiseKeyRequired(NoiseKeyRequired {
                                    is_initiator: self.is_initiator,
                                }),
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
                                multistream_select::InProgress::new(if self.is_initiator {
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

                    let mut buffer =
                        vec![0; encryption.encrypt_in_size_for_out(outgoing_buffer.len())];

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
                                    connection: Connection {
                                        encryption,
                                        yamux: yamux::Connection::new(),
                                        marker: core::marker::PhantomData,
                                    },
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

pub struct NoiseKeyRequired {
    is_initiator: bool,
}

impl NoiseKeyRequired {
    /// Turn this [`NoiseKeyRequired`] back into a [`Healthy`] by indicating the noise key.
    pub fn resume(self, noise_key: &NoiseKey) -> HealthyHandshake {
        HealthyHandshake {
            is_initiator: self.is_initiator,
            state: HandshakeState::NegotiatingEncryption {
                handshake: noise::HandshakeInProgress::new(noise_key, self.is_initiator),
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum InjectDataOutcome<'c, 'd> {
    ReceivedIdentity(PeerId),
    /// Received a ping request from the remote and answered it.
    Ping,
    /// Received a pong from the remote.
    Pong,
    RequestIn {
        protocol_name: &'c str,
        request: &'d [u8],
    },
}

/// Error during a connection. The connection should be shut down.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// Error in the noise cipher. Data has most likely been corrupted.
    Noise(noise::CipherError),
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

#[cfg(test)]
mod tests {
    use super::{Handshake, NoiseKey};

    #[test]
    fn handshake_basic_works() {
        fn test_with_buffer_sizes(size1: usize, size2: usize) {
            let key1 = NoiseKey::new(&rand::random());
            let key2 = NoiseKey::new(&rand::random());

            let mut handshake1 = Handshake::new(true);
            let mut handshake2 = Handshake::new(false);

            let mut buf_1_to_2 = Vec::new();
            let mut buf_2_to_1 = Vec::new();

            while !matches!(
                (&handshake1, &handshake2),
                (Handshake::Success { .. }, Handshake::Success { .. })
            ) {
                match handshake1 {
                    Handshake::Success { .. } => {}
                    Handshake::NoiseKeyRequired(req) => handshake1 = req.resume(&key1).into(),
                    Handshake::Healthy(nego) => {
                        if buf_1_to_2.is_empty() {
                            buf_1_to_2.resize(size1, 0);
                            let (updated, num_read, written) =
                                nego.read_write(&buf_2_to_1, &mut buf_1_to_2).unwrap();
                            handshake1 = updated;
                            for _ in 0..num_read {
                                buf_2_to_1.remove(0);
                            }
                            buf_1_to_2.truncate(written);
                        } else {
                            let (updated, num_read, _) =
                                nego.read_write(&buf_2_to_1, &mut []).unwrap();
                            handshake1 = updated;
                            for _ in 0..num_read {
                                buf_2_to_1.remove(0);
                            }
                        }
                    }
                }

                match handshake2 {
                    Handshake::Success { .. } => {}
                    Handshake::NoiseKeyRequired(req) => handshake2 = req.resume(&key2).into(),
                    Handshake::Healthy(nego) => {
                        if buf_2_to_1.is_empty() {
                            buf_2_to_1.resize(size2, 0);
                            let (updated, num_read, written) =
                                nego.read_write(&buf_1_to_2, &mut buf_2_to_1).unwrap();
                            handshake2 = updated;
                            for _ in 0..num_read {
                                buf_1_to_2.remove(0);
                            }
                            buf_2_to_1.truncate(written);
                        } else {
                            let (updated, num_read, _) =
                                nego.read_write(&buf_1_to_2, &mut []).unwrap();
                            handshake2 = updated;
                            for _ in 0..num_read {
                                buf_1_to_2.remove(0);
                            }
                        }
                    }
                }
            }
        }

        test_with_buffer_sizes(256, 256);
        // TODO: not passing
        //test_with_buffer_sizes(1, 1);
        //test_with_buffer_sizes(1, 2048);
        //test_with_buffer_sizes(2048, 1);
    }
}
