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

//! State machine handling the handshake with a TCP or WebSocket libp2p connection.
//!
//! A connection handshake consists of three steps:
//!
//! - A multistream-select negotiation to negotiate the encryption protocol. Only the noise
//! protocol is supported at the moment.
//! - A noise protocol handshake, where public keys are exchanged and symmetric encryption is
//! initialized.
//! - A multistream-select negotiation to negotiate the yamux protocol. Only the yamux protocol is
//! supported at the moment. This negotiation is performed on top of the noise cipher.
//!
//! This entire handshake requires in total either three or five TCP packets (not including the
//! TCP handshake), depending on the strategy used for the multistream-select protocol.

// TODO: finish commenting on the number of round trips

use super::{
    super::peer_id::PeerId,
    super::read_write::ReadWrite,
    established::ConnectionPrototype,
    multistream_select,
    noise::{self, NoiseKey},
    yamux,
};

use alloc::{boxed::Box, vec};
use core::{fmt, iter};

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
    /// Shortcut for [`HealthyHandshake::new`] wrapped in a [`Handshake`].
    pub fn new(is_initiator: bool) -> Self {
        HealthyHandshake::new(is_initiator).into()
    }
}

/// Connection handshake in progress.
pub struct HealthyHandshake {
    state: NegotiationState,
}

enum NegotiationState {
    EncryptionProtocol {
        negotiation: multistream_select::InProgress<iter::Once<&'static str>, &'static str>,
        is_initiator: bool,
    },
    Encryption {
        handshake: Box<noise::HandshakeInProgress>,
    },
    Multiplexing {
        peer_id: PeerId,
        encryption: noise::Noise,
        negotiation: multistream_select::InProgress<iter::Once<&'static str>, &'static str>,
    },
}

impl HealthyHandshake {
    /// Initializes a new state machine.
    ///
    /// Must pass `true` if the connection has been opened by the local machine, or `false` if it
    /// has been opened by the remote.
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
            state: NegotiationState::EncryptionProtocol {
                negotiation,
                is_initiator,
            },
        }
    }

    /// Feeds data coming from a socket and writes back data to send up.
    ///
    /// On success, returns the new state of the negotiation.
    ///
    /// An error is returned if the protocol is being violated by the remote. When that happens,
    /// the connection should be closed altogether.
    pub fn read_write<TNow>(
        mut self,
        read_write: &mut ReadWrite<'_, TNow>,
    ) -> Result<Handshake, HandshakeError> {
        loop {
            match self.state {
                NegotiationState::EncryptionProtocol {
                    negotiation,
                    is_initiator,
                } => {
                    // Earliest point of the handshake. The encryption is being negotiated.
                    // Delegating read/write to the negotiation.
                    let updated = negotiation
                        .read_write(read_write)
                        .map_err(HandshakeError::MultistreamSelect)?;

                    return match updated {
                        multistream_select::Negotiation::InProgress(updated) => {
                            Ok(Handshake::Healthy(HealthyHandshake {
                                state: NegotiationState::EncryptionProtocol {
                                    negotiation: updated,
                                    is_initiator,
                                },
                            }))
                        }
                        multistream_select::Negotiation::Success(_) => {
                            // Reached the point where the Noise key is required in order to
                            // continue. This Noise key is requested from the user.
                            Ok(Handshake::NoiseKeyRequired(NoiseKeyRequired {
                                is_initiator,
                            }))
                        }
                        multistream_select::Negotiation::NotAvailable => {
                            Err(HandshakeError::NoEncryptionProtocol)
                        }
                    };
                }

                NegotiationState::Encryption { handshake } => {
                    // Delegating read/write to the Noise handshake state machine.
                    let updated = handshake.read_write(read_write).map_err(|err| {
                        debug_assert!(!matches!(err, noise::HandshakeError::WriteClosed));
                        HandshakeError::NoiseHandshake(err)
                    })?;

                    match updated {
                        noise::NoiseHandshake::Success {
                            cipher,
                            remote_peer_id,
                        } => {
                            // Encryption layer has been successfully negotiated. Start the
                            // handshake for the multiplexing protocol negotiation.
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

                            self.state = NegotiationState::Multiplexing {
                                peer_id: remote_peer_id,
                                encryption: cipher,
                                negotiation,
                            };

                            continue;
                        }
                        noise::NoiseHandshake::InProgress(updated) => {
                            return Ok(Handshake::Healthy(HealthyHandshake {
                                state: NegotiationState::Encryption {
                                    handshake: Box::new(updated),
                                },
                            }));
                        }
                    };
                }

                NegotiationState::Multiplexing {
                    negotiation,
                    mut encryption,
                    peer_id,
                } => {
                    // During the multiplexing protocol negotiation, all exchanges have to go
                    // through the Noise cipher.

                    if read_write.incoming_buffer.is_none() {
                        return Err(HandshakeError::MultistreamSelect(
                            multistream_select::Error::ReadClosed,
                        ));
                    }
                    if read_write.outgoing_buffer.is_none() {
                        return Err(HandshakeError::MultistreamSelect(
                            multistream_select::Error::WriteClosed,
                        ));
                    }

                    // TODO: explain
                    let num_read = encryption
                        .inject_inbound_data(read_write.incoming_buffer.unwrap())
                        .map_err(HandshakeError::Noise)?;
                    assert_eq!(num_read, read_write.incoming_buffer_available()); // TODO: not necessarily true; situation is a bit complicated; see noise module
                    read_write.advance_read(num_read);

                    // Allocate a temporary buffer where to put the unencrypted data that should
                    // later be encrypted and written out.
                    // The size of this buffer is equal to the maximum possible size of
                    // unencrypted data that will lead to `outgoing_buffer.len()` encrypted bytes.
                    let mut out_intermediary =
                        vec![
                            0;
                            encryption.encrypt_size_conv(read_write.outgoing_buffer_available())
                        ];

                    // Continue the multistream-select negotiation, writing to `out_intermediary`.
                    let (updated, decrypted_read_num, written_interm) = {
                        let mut interm_read_write = ReadWrite {
                            now: 0,
                            incoming_buffer: Some(encryption.decoded_inbound_data()),
                            outgoing_buffer: Some((&mut out_intermediary, &mut [])),
                            read_bytes: 0,
                            written_bytes: 0,
                            wake_up_after: None,
                            wake_up_future: None,
                        };
                        let updated = negotiation
                            .read_write(&mut interm_read_write)
                            .map_err(HandshakeError::MultistreamSelect)?;
                        (
                            updated,
                            interm_read_write.read_bytes,
                            interm_read_write.written_bytes,
                        )
                    };

                    // TODO: explain
                    encryption.consume_inbound_data(decrypted_read_num);

                    // Encrypt the content of `out_intermediary`, writing it to `outgoing_buffer`.
                    // It is guaranteed that `out_intermediary` will be entirely consumed and can
                    // thus be thrown away.
                    let (_unencrypted_read, encrypted_written) = {
                        if let Some(outgoing_buffer) = read_write.outgoing_buffer.as_mut() {
                            encryption.encrypt(
                                iter::once(&out_intermediary[..written_interm]),
                                (outgoing_buffer.0, outgoing_buffer.1),
                            )
                        } else {
                            (0, 0)
                        }
                    };
                    read_write.advance_write(encrypted_written);
                    debug_assert_eq!(_unencrypted_read, written_interm);

                    return match updated {
                        multistream_select::Negotiation::InProgress(updated) => {
                            Ok(Handshake::Healthy(HealthyHandshake {
                                state: NegotiationState::Multiplexing {
                                    negotiation: updated,
                                    encryption,
                                    peer_id,
                                },
                            }))
                        }
                        multistream_select::Negotiation::Success(_) => Ok(Handshake::Success {
                            connection: ConnectionPrototype::from_noise_yamux(encryption),
                            remote_peer_id: peer_id,
                        }),
                        multistream_select::Negotiation::NotAvailable => {
                            Err(HandshakeError::NoMultiplexingProtocol)
                        }
                    };
                }
            }
        }
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
    /// Turn this [`NoiseKeyRequired`] back into a [`HealthyHandshake`] by indicating the noise key.
    pub fn resume(self, noise_key: &NoiseKey) -> HealthyHandshake {
        HealthyHandshake {
            state: NegotiationState::Encryption {
                handshake: Box::new(noise::HandshakeInProgress::new(
                    noise_key,
                    self.is_initiator,
                )),
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
