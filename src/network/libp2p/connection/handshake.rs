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

//! State machine handling the handshake with a TCP or WebSocket libp2p connection.
//!
//! This state machine tries to negotiate and apply the noise and yamux protocols on top of the
//! connection.

use super::{
    multistream_select,
    noise::{self, NoiseKey},
    yamux, ConnectionPrototype,
};

use core::{fmt, iter};
use libp2p::PeerId;

mod tests;

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
                                    connection: ConnectionPrototype::from_noise_yamux(encryption),
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
