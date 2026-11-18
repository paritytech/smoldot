// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

//! Noise protocol libp2p layer.
//!
//! The [noise protocol](https://noiseprotocol.org/) is a standard framework for building
//! cryptographic protocols. Libp2p uses the noise protocol to provide an encryption layer on
//! top of which data is exchanged.
//!
//! # Protocol details
//!
//! Libp2p uses [the XX pattern](https://noiseexplorer.com/patterns/XX/). The handshake consists
//! of three packets:
//!
//! - The initiator generates an ephemeral key pair and sends the public key to the responder.
//! - The responder generates its own ephemeral key pair and sends the public key to the
//! initiator. Afterwards, the responder derives a shared secret and uses it to encrypt all
//! further communications. Now encrypted, the responder also sends back its static noise public
//! key (represented with the [`NoiseKey`] type of this module), its libp2p public key, and a
//! signature of the static noise public key made using its libp2p private key.
//! - The initiator, after having received the ephemeral key from the remote, derives the same
//! shared secret. It sends its own static noise public key, libp2p public key, and signature.
//!
//! After these three packets, the initiator and responder derive another shared secret using
//! both the static and ephemeral keys, which is then used to encrypt communications. Note that
//! the libp2p key isn't used in the key derivation.
//!
//! # Usage
//!
//! While this is out of scope of this module, the noise protocol must typically first be
//! negotiated using the *multistream-select* protocol. The name of the protocol is given by
//! the [`PROTOCOL_NAME`] constant.
//!
//! In order to use noise on top of a connection which has agreed to use noise, create a
//! [`HandshakeInProgress`], passing a [`NoiseKey`]. This [`NoiseKey`] is typically generated at
//! startup and doesn't need to be persisted after a restart.
//!
//! Use [`HandshakeInProgress::read_write`] when data is received from the wire or when the remote
//! is ready to receive more data. At every call, a [`NoiseHandshake`] is returned, potentially
//! indicating the end of the handshake.
//!
//! If the handshake is finished, a [`NoiseHandshake::Success`] is returned, containing the
//! [`PeerId`] of the remote, which is known to be legitimate, and a [`Noise`] object through
//! which all further communications should go through.
//!

// # Q&A
//
// ## Why not use a library such as `snow`?
//
// Snow suffers from a variety of problems:
//
// - It doesn't support `no_std`.
// - It uses outdated versions of dependencies.
// - It doesn't allow writing a single Noise message onto two consecutive buffers.
// - It doesn't support encoding a Noise message already present in the output buffer.
// - It isn't really maintained.
// - It doesn't give control over its random number generator.
//

use crate::{
    libp2p::{
        peer_id::{PeerId, PublicKey, SignatureVerifyFailed},
        read_write::{self, ReadWrite},
    },
    util::protobuf,
};

use alloc::{boxed::Box, collections::VecDeque, vec, vec::Vec};
use core::{cmp, fmt, iter, mem, ops};

/// Name of the protocol, typically used when negotiated it using *multistream-select*.
pub const PROTOCOL_NAME: &str = "/noise";

/// The noise key is the key exchanged during the noise handshake. It is **not** the same as the
/// libp2p key. The libp2p key is used only to sign the noise public key, while the ECDH is
/// performed with the noise key.
///
/// From the point of view of the noise protocol specification, this [`NoiseKey`] corresponds to
/// the static key. The noise key is typically generated at startup and doesn't have to be
/// persisted on disk, contrary to the libp2p key which is typically persisted after a restart.
///
/// In order to generate a [`NoiseKey`], two things are needed:
///
/// - A public/private key, also represented as [`UnsignedNoiseKey`].
/// - A signature of this public key made using the libp2p private key.
///
/// The signature requires access to the libp2p private key. As such, there are two possible
/// ways to create a [`NoiseKey`]:
///
/// - The easier way, by passing the libp2p private key to [`NoiseKey::new`].
/// - The slightly more complex way, by first creating an [`UnsignedNoiseKey`], then passing a
/// a signature. This second method doesn't require direct access to the private key but only
/// to a method of signing a message, which makes it for example possible to use a hardware
/// device.
///
pub struct NoiseKey {
    private_key: zeroize::Zeroizing<x25519_dalek::StaticSecret>,
    public_key: x25519_dalek::PublicKey,
    /// Handshake to encrypt then send on the wire.
    handshake_message: Vec<u8>,
    /// Ed25519 public key used for the signature in the handshake message.
    libp2p_public_ed25519_key: [u8; 32],
}

impl NoiseKey {
    /// Turns a libp2p private key and a Noise static private key into a [`NoiseKey`].
    pub fn new(libp2p_ed25519_private_key: &[u8; 32], noise_static_private_key: &[u8; 32]) -> Self {
        let unsigned = UnsignedNoiseKey::from_private_key(noise_static_private_key);

        let (libp2p_public_key, signature) = {
            // Creating a `SecretKey` can fail only if the length isn't 32 bytes.
            let secret = ed25519_zebra::SigningKey::from(*libp2p_ed25519_private_key);
            let public = ed25519_zebra::VerificationKey::from(&secret);
            // TODO: use sign_prehashed or sign_vectored (https://github.com/dalek-cryptography/ed25519-dalek/pull/143) to not allocate Vec
            let signature = secret.sign(&unsigned.payload_to_sign_as_vec());
            (public, signature)
        };

        unsigned.sign(libp2p_public_key.into(), signature.into())
    }

    /// Returns the libp2p public key associated to the signature contained in this noise key.
    pub fn libp2p_public_ed25519_key(&self) -> &[u8; 32] {
        &self.libp2p_public_ed25519_key
    }
}

/// Prototype for a [`NoiseKey`].
///
/// This type is provided for situations where the user has access to some signing mechanism,
/// such as a hardware device, but not directly to the private key.
///
/// For simple cases, prefer using [`NoiseKey::new`].
pub struct UnsignedNoiseKey {
    private_key: Option<zeroize::Zeroizing<x25519_dalek::StaticSecret>>,
    public_key: x25519_dalek::PublicKey,
}

impl UnsignedNoiseKey {
    /// Turns a private key into an [`UnsignedNoiseKey`].
    pub fn from_private_key(private_key: &[u8; 32]) -> Self {
        let private_key = zeroize::Zeroizing::new(x25519_dalek::StaticSecret::from(*private_key));
        let public_key = x25519_dalek::PublicKey::from(&*private_key);
        UnsignedNoiseKey {
            private_key: Some(private_key),
            public_key,
        }
    }

    /// Returns the data that has to be signed.
    pub fn payload_to_sign(&self) -> impl Iterator<Item = impl AsRef<[u8]>> {
        [
            &b"noise-libp2p-static-key:"[..],
            &self.public_key.as_bytes()[..],
        ]
        .into_iter()
    }

    /// Returns the data that has to be signed.
    ///
    /// This method is a more convenient equivalent to
    /// [`UnsignedNoiseKey::payload_to_sign_as_vec`].
    pub fn payload_to_sign_as_vec(&self) -> Vec<u8> {
        self.payload_to_sign().fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        })
    }

    /// Turns this [`UnsignedNoiseKey`] into a [`NoiseKey`] after signing it using the libp2p
    /// private key.
    pub fn sign(mut self, libp2p_public_ed25519_key: [u8; 32], signature: [u8; 64]) -> NoiseKey {
        let libp2p_pubkey_protobuf =
            PublicKey::Ed25519(libp2p_public_ed25519_key).to_protobuf_encoding();

        let handshake_message = {
            // Protobuf message format can be found here:
            // https://github.com/libp2p/specs/tree/master/noise#the-libp2p-handshake-payload

            // The capacity is arbitrary but large enough to avoid Vec reallocations.
            let mut msg = Vec::with_capacity(32 + libp2p_pubkey_protobuf.len() + signature.len());

            for slice in protobuf::bytes_tag_encode(1, &libp2p_pubkey_protobuf) {
                msg.extend_from_slice(slice.as_ref());
            }

            for slice in protobuf::bytes_tag_encode(2, &signature) {
                msg.extend_from_slice(slice.as_ref());
            }

            msg
        };

        NoiseKey {
            public_key: self.public_key,
            private_key: self.private_key.take().unwrap(),
            libp2p_public_ed25519_key,
            handshake_message,
        }
    }
}

/// Configuration for a Noise handshake.
pub struct Config<'a> {
    /// Key to use during the handshake.
    pub key: &'a NoiseKey,

    /// Secret key to use for that specific handshake. Must be randomly generated. Must never be
    /// re-used between multiple handshakes.
    pub ephemeral_secret_key: &'a [u8; 32],

    /// `true` if this side of the connection must initiate the Noise handshake. `false` if it's
    /// the remote.
    pub is_initiator: bool,

    /// Prologue data. The prologue data must be identical on both sides of the handshake,
    /// otherwise it will fail.
    ///
    /// See <https://noiseprotocol.org/noise.html#prologue>.
    ///
    /// > **Note**: If a certain protocol specification doesn't mention any prologue, it probably
    /// >           means that this prologue is empty.
    pub prologue: &'a [u8],
}

/// State of the noise encryption/decryption cipher.
pub struct Noise {
    /// See [`Config::is_initiator`].
    is_initiator: bool,

    /// Cipher used to encrypt outgoing data.
    out_cipher_state: CipherState,

    /// Cipher used to decrypt incoming data.
    in_cipher_state: CipherState,

    /// Size in bytes of the next message to receive. `None` if unknown. If `Some`, the libp2p
    /// length prefix has already been stripped from the incoming stream.
    next_in_message_size: Option<u16>,

    /// Buffer of data containing data that has been decrypted.
    rx_buffer_decrypted: Vec<u8>,

    /// Value of [`ReadWrite::expected_incoming_bytes`] of the inner stream the last time that
    /// [`Noise::read_write`] was called. Encrypted data will be read until the length of
    /// [`Noise::rx_buffer_decrypted`] reaches the value in this field.
    inner_stream_expected_incoming_bytes: usize,
}

impl Noise {
    /// Returns the value that was provided as [`Config::is_initiator`].
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Feeds data coming from a socket and outputs data to write to the socket.
    ///
    /// Returns an object that implements `Deref<Target = ReadWrite>`. This object represents the
    /// decrypted stream of data.
    ///
    /// An error is returned if the protocol is being violated by the remote or if the nonce
    /// overflows. When that happens, the connection should be closed altogether.
    pub fn read_write<'a, TNow: Clone>(
        &'a mut self,
        outer_read_write: &'a mut ReadWrite<TNow>,
    ) -> Result<InnerReadWrite<'a, TNow>, CipherError> {
        // Try to pull data from `outer_read_write` to decrypt it.
        while self.rx_buffer_decrypted.is_empty()
            || self.inner_stream_expected_incoming_bytes > self.rx_buffer_decrypted.len()
        {
            // TODO: what if EOF in the middle of a message?
            if let Some(next_in_message_size) = self.next_in_message_size {
                if let Ok(Some(encrypted_message)) =
                    outer_read_write.incoming_bytes_take(usize::from(next_in_message_size))
                {
                    self.next_in_message_size = None;

                    // Read and decrypt the message.
                    // TODO: decipher progressively, based on the inner `expected_incoming_bytes` value
                    self.in_cipher_state.read_chachapoly_message_to_vec_append(
                        &[],
                        &encrypted_message,
                        &mut self.rx_buffer_decrypted,
                    )?;
                } else {
                    break;
                }
            } else if let Ok(Some(next_frame_length)) =
                outer_read_write.incoming_bytes_take_array::<2>()
            {
                self.next_in_message_size = Some(u16::from_be_bytes(next_frame_length));
            } else {
                break;
            }
        }

        // Check ahead of time if writing out a message would panic.
        if self.out_cipher_state.nonce_has_overflowed {
            return Err(CipherError::NonceOverflow);
        }

        Ok(InnerReadWrite {
            inner_read_write: ReadWrite {
                now: outer_read_write.now.clone(),
                incoming_buffer: mem::take(&mut self.rx_buffer_decrypted),
                read_bytes: 0,
                expected_incoming_bytes: if outer_read_write.expected_incoming_bytes.is_some()
                    || !outer_read_write.incoming_buffer.is_empty()
                {
                    Some(self.inner_stream_expected_incoming_bytes)
                } else {
                    None
                },
                write_buffers: Vec::new(),
                write_bytes_queued: 0,
                write_bytes_queueable: outer_read_write.write_bytes_queueable.map(
                    |outer_writable| cmp::min(outer_writable.saturating_sub(16 + 2), 65535 - 16),
                ),
                wake_up_after: outer_read_write.wake_up_after.clone(),
            },
            noise: self,
            outer_read_write,
        })
    }
}

impl fmt::Debug for Noise {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Noise").finish()
    }
}

/// Stream of decrypted data. See [`Noise::read_write`].
pub struct InnerReadWrite<'a, TNow: Clone> {
    noise: &'a mut Noise,
    outer_read_write: &'a mut ReadWrite<TNow>,
    inner_read_write: ReadWrite<TNow>,
}

impl<'a, TNow: Clone> ops::Deref for InnerReadWrite<'a, TNow> {
    type Target = ReadWrite<TNow>;

    fn deref(&self) -> &Self::Target {
        &self.inner_read_write
    }
}

impl<'a, TNow: Clone> ops::DerefMut for InnerReadWrite<'a, TNow> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner_read_write
    }
}

impl<'a, TNow: Clone> Drop for InnerReadWrite<'a, TNow> {
    fn drop(&mut self) {
        self.outer_read_write.wake_up_after = self.inner_read_write.wake_up_after.clone();
        self.noise.rx_buffer_decrypted = mem::take(&mut self.inner_read_write.incoming_buffer);
        self.noise.inner_stream_expected_incoming_bytes =
            self.inner_read_write.expected_incoming_bytes.unwrap_or(0);

        // It is possible that the inner stream processes some bytes of `self.rx_buffer_decrypted`
        // and expects to be called again while no bytes was pulled from the outer `ReadWrite`.
        // If that happens, the API user will not call `read_write` again and we will have a stall.
        // For this reason, if the inner stream has read some bytes, we make sure that the outer
        // `ReadWrite` wakes up as soon as possible.
        if self.inner_read_write.read_bytes != 0 {
            self.outer_read_write.wake_up_asap();
        }

        // Encrypt the data, transferring it from the inner `ReadWrite` to the outer `ReadWrite`.
        if self
            .inner_read_write
            .write_buffers
            .iter()
            .any(|b| !b.is_empty())
        {
            self.outer_read_write
                .write_buffers
                .reserve(2 + self.inner_read_write.write_buffers.len() * 2);

            // We push a dummy buffer to `outer_read_write.write_buffers`. This dummy buffer
            // will later be overwritten with the actual message length.
            let message_length_prefix_index = self.outer_read_write.write_buffers.len();
            self.outer_read_write.write_buffers.push(Vec::new());

            // Encrypt the message.
            // `write_chachapoly_message` returns an error if the nonce has overflowed. It has
            // been checked in the body of `read_write` that this can't happen.
            let mut total_size = 0;
            for encrypted_buffer in self
                .noise
                .out_cipher_state
                .write_chachapoly_message(&[], self.inner_read_write.write_buffers.drain(..))
                .unwrap_or_else(|_| unreachable!())
            {
                total_size += encrypted_buffer.len();
                self.outer_read_write.write_buffers.push(encrypted_buffer);
            }

            // Now write the message length.
            let message_length_prefix = u16::try_from(total_size).unwrap().to_be_bytes().to_vec();
            self.outer_read_write.write_buffers[message_length_prefix_index] =
                message_length_prefix;

            // Properly update the outer `ReadWrite`.
            self.outer_read_write.write_bytes_queued += total_size + 2;
            *self
                .outer_read_write
                .write_bytes_queueable
                .as_mut()
                .unwrap() -= total_size + 2;
        }
    }
}

/// State of a Noise handshake.
#[derive(Debug)]
pub enum NoiseHandshake {
    /// Handshake still in progress. More data needs to be sent or received.
    InProgress(HandshakeInProgress),
    /// Noise handshake has successfully completed.
    Success {
        /// Object to use to encrypt and decrypt all further communications.
        cipher: Noise,
        /// [`PeerId`] of the remote.
        remote_peer_id: PeerId,
    },
}

/// Handshake still in progress. More data needs to be sent or received.
pub struct HandshakeInProgress(Box<HandshakeInProgressInner>);

/// The actual fields are wrapped within a `Box` because we move the `HandshakeInProgress`
/// frequently.
struct HandshakeInProgressInner {
    /// See [`Config::is_initiator`].
    is_initiator: bool,

    /// Queued data that should be sent out as soon as possible.
    pending_out_data: VecDeque<u8>,

    /// Size of the next message being received, if already known.
    ///
    /// If `Some`, the libp2p size prefix has already been extracted from the incoming buffer.
    /// If `None`, this hasn't been done yet.
    next_in_message_size: Option<u16>,

    /// Progression of the handshake.
    ///
    /// Every time a message is sent out or buffered in
    /// [`HandshakeInProgressInner::pending_out_data`], this is increased by 1.
    num_buffered_or_transmitted_messages: u8,

    /// A single cipher is used during the handshake, as each side takes turn to send data rather
    /// than both at the same time.
    cipher_state: CipherState,

    /// Product of the diffie-hellmans between the various keys that are exchanged. Used to
    /// initialize the ciphers once the handshake is over.
    ///
    /// Corresponds to the `ck` field of the `SymmetricState` in the Noise specification.
    /// See <https://noiseprotocol.org/noise.html#the-symmetricstate-object>.
    chaining_key: zeroize::Zeroizing<[u8; 32]>,

    /// Hash that maintains the state of the data that we've sent out or received. Used as the
    /// associated data whenever we produce or verify a frame during the handshake.
    ///
    /// Corresponds to the `h` field of the `SymmetricState` in the Noise specification.
    /// See <https://noiseprotocol.org/noise.html#the-symmetricstate-object>.
    hash: zeroize::Zeroizing<[u8; 32]>,

    /// Local ephemeral key. Generate for this handshake specifically.
    ///
    /// Corresponds to the `e` field of the `HandshakeState` in the Noise specification.
    /// See <https://noiseprotocol.org/noise.html#the-handshakestate-object>.
    local_ephemeral_private_key: zeroize::Zeroizing<x25519_dalek::StaticSecret>,

    /// Local static key. Corresponds to a [`NoiseKey`].
    ///
    /// Corresponds to the `s` field of the `HandshakeState` in the Noise specification.
    /// See <https://noiseprotocol.org/noise.html#the-handshakestate-object>.
    local_static_private_key: zeroize::Zeroizing<x25519_dalek::StaticSecret>,

    /// Public key corresponding to [`HandshakeInProgressInner::local_static_private_key`].
    local_static_public_key: x25519_dalek::PublicKey,

    /// Ephemeral public key of the remote. Initially set to `0`s, then set to the correct value
    /// once it's been received.
    ///
    /// Corresponds to the `re` field of the `HandshakeState` in the Noise specification.
    /// See <https://noiseprotocol.org/noise.html#the-handshakestate-object>.
    remote_ephemeral_public_key: x25519_dalek::PublicKey,

    /// Static public key of the remote. Initially set to `0`s, then set to the correct value
    /// once it's been received.
    ///
    /// Corresponds to the `rs` field of the `HandshakeState` in the Noise specification.
    /// See <https://noiseprotocol.org/noise.html#the-handshakestate-object>.
    remote_static_public_key: x25519_dalek::PublicKey,

    /// Libp2p public key of the remote. Initially `None`, then set to the correct value once
    /// we've received it.
    remote_public_key: Option<PublicKey>,

    /// Libp2p-specific additional handshake message to encrypt then send to the remote.
    libp2p_handshake_message: Vec<u8>,
}

impl NoiseHandshake {
    /// Shortcut function that calls [`HandshakeInProgress::new`] and wraps it into a
    /// [`NoiseHandshake`].
    pub fn new(config: Config) -> Self {
        NoiseHandshake::InProgress(HandshakeInProgress::new(config))
    }
}

impl HandshakeInProgress {
    /// Initializes a new noise handshake state machine.
    pub fn new(config: Config) -> Self {
        // Generate a new ephemeral key for this handshake.
        // TODO: is it zeroize-safe to call `from([u8; 32])`?
        let local_ephemeral_private_key = zeroize::Zeroizing::new(
            x25519_dalek::StaticSecret::from(*config.ephemeral_secret_key),
        );

        // Initialize the hash.
        let mut hash = zeroize::Zeroizing::new([0u8; 32]);

        // InitializeSymmetric(protocol_name).
        {
            const PROTOCOL_NAME: &[u8] = b"Noise_XX_25519_ChaChaPoly_SHA256";
            if PROTOCOL_NAME.len() <= hash.len() {
                hash[..PROTOCOL_NAME.len()].copy_from_slice(PROTOCOL_NAME);
                hash[PROTOCOL_NAME.len()..].fill(0);
            } else {
                let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
                sha2::Digest::update(&mut hasher, PROTOCOL_NAME);
                sha2::Digest::finalize_into(
                    hasher,
                    sha2::digest::generic_array::GenericArray::from_mut_slice(&mut *hash),
                );
            }
        }
        let chaining_key = hash.clone();

        // Perform MixHash(prologue).
        mix_hash(&mut hash, config.prologue);

        HandshakeInProgress(Box::new(HandshakeInProgressInner {
            cipher_state: CipherState {
                key: zeroize::Zeroizing::new([0; 32]),
                nonce: 0,
                nonce_has_overflowed: false,
            },
            chaining_key,
            hash,
            local_ephemeral_private_key,
            local_static_private_key: config.key.private_key.clone(),
            local_static_public_key: config.key.public_key,
            remote_ephemeral_public_key: x25519_dalek::PublicKey::from([0; 32]),
            remote_static_public_key: x25519_dalek::PublicKey::from([0; 32]),
            remote_public_key: None,
            is_initiator: config.is_initiator,
            pending_out_data: VecDeque::with_capacity(usize::from(u16::MAX) + 2),
            next_in_message_size: None,
            num_buffered_or_transmitted_messages: 0,
            libp2p_handshake_message: config.key.handshake_message.clone(),
        }))
    }

    /// Feeds data coming from a socket and outputs data to write to the socket.
    ///
    /// On success, returns the new state of the negotiation.
    ///
    /// An error is returned if the protocol is being violated by the remote. When that happens,
    /// the connection should be closed altogether.
    pub fn read_write<TNow>(
        mut self,
        read_write: &mut ReadWrite<TNow>,
    ) -> Result<NoiseHandshake, HandshakeError> {
        loop {
            // Write out the data currently buffered waiting to be written out.
            // If we didn't finish writing our payload, don't do anything more and return now.
            // Don't even read the data from the remote.
            read_write.write_from_vec_deque(&mut self.0.pending_out_data);
            if !self.0.pending_out_data.is_empty() {
                if read_write.write_bytes_queueable.is_none() {
                    return Err(HandshakeError::WriteClosed);
                }
                return Ok(NoiseHandshake::InProgress(self));
            }

            // If the handshake has finished, we return successfully here.
            if self.0.num_buffered_or_transmitted_messages == 3 {
                debug_assert!(self.0.pending_out_data.is_empty());
                debug_assert!(self.0.next_in_message_size.is_none());

                // Perform the `Split()`.
                let HkdfOutput {
                    output1: init_to_resp,
                    output2: resp_to_init,
                } = hkdf(&self.0.chaining_key, &[]);
                let (out_key, in_key) = match self.0.is_initiator {
                    true => (init_to_resp, resp_to_init),
                    false => (resp_to_init, init_to_resp),
                };
                return Ok(NoiseHandshake::Success {
                    cipher: Noise {
                        is_initiator: self.0.is_initiator,
                        out_cipher_state: CipherState {
                            key: out_key,
                            nonce: 0,
                            nonce_has_overflowed: false,
                        },
                        in_cipher_state: CipherState {
                            key: in_key,
                            nonce: 0,
                            nonce_has_overflowed: false,
                        },
                        rx_buffer_decrypted: Vec::with_capacity(65535 - 16),
                        next_in_message_size: None,
                        inner_stream_expected_incoming_bytes: 0,
                    },
                    remote_peer_id: {
                        // The logic of this module guarantees that `remote_peer_id` has
                        // been set during the handshake.
                        self.0
                            .remote_public_key
                            .take()
                            .unwrap_or_else(|| unreachable!())
                            .into_peer_id()
                    },
                });
            }

            // If the handshake is in a phase where we need to send out more data, queue said
            // data to `pending_out_data` and continue.
            match (
                self.0.num_buffered_or_transmitted_messages,
                self.0.is_initiator,
            ) {
                (0, true) => {
                    // Send `e`, the ephemeral local public key.

                    // Process `e`.
                    let local_ephemeral_public_key =
                        x25519_dalek::PublicKey::from(&*self.0.local_ephemeral_private_key);
                    self.0
                        .pending_out_data
                        .extend(local_ephemeral_public_key.as_bytes());
                    mix_hash(&mut self.0.hash, local_ephemeral_public_key.as_bytes());

                    // Call MixHash(&[]) to process the empty payload.
                    mix_hash(&mut self.0.hash, &[]);

                    // Add the libp2p message length.
                    let len = u16::try_from(self.0.pending_out_data.len())
                        .unwrap()
                        .to_be_bytes();
                    self.0.pending_out_data.push_front(len[1]);
                    self.0.pending_out_data.push_front(len[0]);

                    // Message is now fully queued.
                    self.0.num_buffered_or_transmitted_messages += 1;
                    continue;
                }
                (1, false) => {
                    // Send `e, ee, s, es` and the libp2p-specific handshake.

                    // Process `e`.
                    let local_ephemeral_public_key =
                        x25519_dalek::PublicKey::from(&*self.0.local_ephemeral_private_key);
                    self.0
                        .pending_out_data
                        .extend(local_ephemeral_public_key.as_bytes());
                    mix_hash(&mut self.0.hash, local_ephemeral_public_key.as_bytes());

                    // Process `ee`. Call MixKey(DH(e, re)).
                    let HkdfOutput {
                        output1: chaining_key_update,
                        output2: key_update,
                    } = hkdf(
                        &self.0.chaining_key,
                        self.0
                            .local_ephemeral_private_key
                            .diffie_hellman(&self.0.remote_ephemeral_public_key)
                            .as_bytes(),
                    );
                    self.0.chaining_key = chaining_key_update;
                    self.0.cipher_state.key = key_update;
                    self.0.cipher_state.nonce = 0;

                    // Process `s`. Append EncryptAndHash(s.public_key) to the buffer.
                    let encrypted_static_public_key = self
                        .0
                        .cipher_state
                        .write_chachapoly_message_to_vec(
                            &*self.0.hash,
                            self.0.local_static_public_key.as_bytes(),
                        )
                        .unwrap();
                    self.0
                        .pending_out_data
                        .extend(encrypted_static_public_key.iter().copied());
                    mix_hash(&mut self.0.hash, &encrypted_static_public_key);

                    // Process `es`. Call MixKey(DH(s, re)).
                    let HkdfOutput {
                        output1: chaining_key_update,
                        output2: key_update,
                    } = hkdf(
                        &self.0.chaining_key,
                        self.0
                            .local_static_private_key
                            .diffie_hellman(&self.0.remote_ephemeral_public_key)
                            .as_bytes(),
                    );
                    self.0.chaining_key = chaining_key_update;
                    self.0.cipher_state.key = key_update;
                    self.0.cipher_state.nonce = 0;

                    // Add the libp2p handshake message.
                    let encrypted_libp2p_handshake = self
                        .0
                        .cipher_state
                        .write_chachapoly_message_to_vec(
                            &*self.0.hash,
                            &self.0.libp2p_handshake_message,
                        )
                        .unwrap();
                    self.0
                        .pending_out_data
                        .extend(encrypted_libp2p_handshake.iter().copied());
                    mix_hash(&mut self.0.hash, &encrypted_libp2p_handshake);

                    // Add the libp2p message length.
                    let len = u16::try_from(self.0.pending_out_data.len())
                        .unwrap()
                        .to_be_bytes();
                    self.0.pending_out_data.push_front(len[1]);
                    self.0.pending_out_data.push_front(len[0]);

                    // Message is now fully queued.
                    self.0.num_buffered_or_transmitted_messages += 1;
                    continue;
                }
                (2, true) => {
                    // Send `s, se` and the libp2p-specific handshake.

                    // Process `s`. Append EncryptAndHash(s.public_key) to the buffer.
                    let encrypted_static_public_key = self
                        .0
                        .cipher_state
                        .write_chachapoly_message_to_vec(
                            &*self.0.hash,
                            self.0.local_static_public_key.as_bytes(),
                        )
                        .unwrap();
                    self.0
                        .pending_out_data
                        .extend(encrypted_static_public_key.iter().copied());
                    mix_hash(&mut self.0.hash, &encrypted_static_public_key);

                    // Process `se`. Call MixKey(DH(s, re)).
                    let HkdfOutput {
                        output1: chaining_key_update,
                        output2: key_update,
                    } = hkdf(
                        &self.0.chaining_key,
                        self.0
                            .local_static_private_key
                            .diffie_hellman(&self.0.remote_ephemeral_public_key)
                            .as_bytes(),
                    );
                    self.0.chaining_key = chaining_key_update;
                    self.0.cipher_state.key = key_update;
                    self.0.cipher_state.nonce = 0;

                    // Add the libp2p handshake message.
                    let encrypted_libp2p_handshake = self
                        .0
                        .cipher_state
                        .write_chachapoly_message_to_vec(
                            &*self.0.hash,
                            &self.0.libp2p_handshake_message,
                        )
                        .unwrap();
                    self.0
                        .pending_out_data
                        .extend(encrypted_libp2p_handshake.iter().copied());
                    mix_hash(&mut self.0.hash, &encrypted_libp2p_handshake);

                    // Add the libp2p message length.
                    let len = u16::try_from(self.0.pending_out_data.len())
                        .unwrap()
                        .to_be_bytes();
                    self.0.pending_out_data.push_front(len[1]);
                    self.0.pending_out_data.push_front(len[0]);

                    // Message is now fully queued.
                    self.0.num_buffered_or_transmitted_messages += 1;
                    continue;
                }
                _ => {}
            }

            // Since we have no more data to write out, and that the handshake isn't finished yet,
            // the next step is necessarily receiving a message sent by the remote.

            // Grab the size of the next message, either from `self` or by extracting 2 bytes from
            // the incoming buffer.
            let next_in_message_size =
                if let Some(next_in_message_size) = self.0.next_in_message_size {
                    next_in_message_size
                } else {
                    match read_write.incoming_bytes_take(2) {
                        Ok(Some(size_buffer)) => *self.0.next_in_message_size.insert(
                            u16::from_be_bytes(<[u8; 2]>::try_from(&size_buffer[..2]).unwrap()),
                        ),
                        Ok(None) => {
                            // Not enough data in incoming buffer.
                            return Ok(NoiseHandshake::InProgress(self));
                        }
                        Err(read_write::IncomingBytesTakeError::ReadClosed) => {
                            return Err(HandshakeError::ReadClosed);
                        }
                    }
                };

            // Extract the message from the incoming buffer.
            let available_message =
                match read_write.incoming_bytes_take(usize::from(next_in_message_size)) {
                    Ok(Some(available_message)) => {
                        self.0.next_in_message_size = None;
                        available_message
                    }
                    Ok(None) => {
                        // Not enough data in incoming buffer.
                        return Ok(NoiseHandshake::InProgress(self));
                    }
                    Err(read_write::IncomingBytesTakeError::ReadClosed) => {
                        return Err(HandshakeError::ReadClosed);
                    }
                };

            // How to parse the message depends on the current handshake phase.
            match (
                self.0.num_buffered_or_transmitted_messages,
                self.0.is_initiator,
            ) {
                (0, false) => {
                    // Receive `e` message from the remote.
                    self.0.remote_ephemeral_public_key = x25519_dalek::PublicKey::from(*{
                        // Because the remote hasn't authenticated us at this point, sending more
                        // data than what the protocol specifies is forbidden.
                        let mut parser =
                            nom::combinator::all_consuming::<_, (&[u8], nom::error::ErrorKind), _>(
                                nom::combinator::map(nom::bytes::streaming::take(32u32), |k| {
                                    <&[u8; 32]>::try_from(k).unwrap()
                                }),
                            );
                        match nom::Parser::parse(&mut parser, &available_message) {
                            Ok((_, out)) => out,
                            Err(_) => {
                                return Err(HandshakeError::PayloadDecode(PayloadDecodeError));
                            }
                        }
                    });
                    mix_hash(
                        &mut self.0.hash,
                        self.0.remote_ephemeral_public_key.as_bytes(),
                    );

                    // Call MixHash(&[]) to process the empty payload.
                    mix_hash(&mut self.0.hash, &[]);

                    // Message has been fully processed.
                    self.0.num_buffered_or_transmitted_messages += 1;
                    continue;
                }
                (1, true) => {
                    // Receive `e, ee, s, es` and the libp2p-specific handshake from the remote.
                    let (
                        remote_ephemeral_public_key,
                        remote_static_public_key_encrypted,
                        libp2p_handshake_encrypted,
                    ) = {
                        // Because the remote hasn't fully authenticated us at this point, sending
                        // more data than what the protocol specifies is forbidden.
                        let mut parser =
                            nom::combinator::all_consuming::<_, (&[u8], nom::error::ErrorKind), _>(
                                (
                                    nom::combinator::map(nom::bytes::streaming::take(32u32), |k| {
                                        <&[u8; 32]>::try_from(k).unwrap()
                                    }),
                                    nom::combinator::map(nom::bytes::streaming::take(48u32), |k| {
                                        <&[u8; 48]>::try_from(k).unwrap()
                                    }),
                                    nom::combinator::rest,
                                ),
                            );
                        match nom::Parser::parse(&mut parser, &available_message) {
                            Ok((_, out)) => out,
                            Err(_) => {
                                return Err(HandshakeError::PayloadDecode(PayloadDecodeError));
                            }
                        }
                    };

                    // Process `e`.
                    self.0.remote_ephemeral_public_key =
                        x25519_dalek::PublicKey::from(*remote_ephemeral_public_key);
                    mix_hash(
                        &mut self.0.hash,
                        self.0.remote_ephemeral_public_key.as_bytes(),
                    );

                    // Process `ee`. Call MixKey(DH(e, re)).
                    let HkdfOutput {
                        output1: chaining_key_update,
                        output2: key_update,
                    } = hkdf(
                        &self.0.chaining_key,
                        self.0
                            .local_ephemeral_private_key
                            .diffie_hellman(&self.0.remote_ephemeral_public_key)
                            .as_bytes(),
                    );
                    self.0.chaining_key = chaining_key_update;
                    self.0.cipher_state.key = key_update;
                    self.0.cipher_state.nonce = 0;

                    // Process `s`.
                    self.0.remote_static_public_key = x25519_dalek::PublicKey::from(
                        self.0
                            .cipher_state
                            .read_chachapoly_message_to_array(
                                &*self.0.hash,
                                remote_static_public_key_encrypted,
                            )
                            .map_err(HandshakeError::Cipher)?,
                    );
                    mix_hash(&mut self.0.hash, remote_static_public_key_encrypted);

                    // Process `es`. Call MixKey(DH(e, rs)).
                    let HkdfOutput {
                        output1: chaining_key_update,
                        output2: key_update,
                    } = hkdf(
                        &self.0.chaining_key,
                        self.0
                            .local_ephemeral_private_key
                            .diffie_hellman(&self.0.remote_static_public_key)
                            .as_bytes(),
                    );
                    self.0.chaining_key = chaining_key_update;
                    self.0.cipher_state.key = key_update;
                    self.0.cipher_state.nonce = 0;

                    // Process the libp2p-specific handshake.
                    self.0.remote_public_key = Some({
                        let libp2p_handshake_decrypted = self
                            .0
                            .cipher_state
                            .read_chachapoly_message_to_vec(
                                &*self.0.hash,
                                libp2p_handshake_encrypted,
                            )
                            .map_err(HandshakeError::Cipher)?;
                        let (libp2p_key, libp2p_signature) = {
                            let mut parser =
                                nom::combinator::all_consuming::<
                                    _,
                                    (&[u8], nom::error::ErrorKind),
                                    _,
                                >(protobuf::message_decode! {
                                    #[required] key = 1 => protobuf::bytes_tag_decode,
                                    #[required] sig = 2 => protobuf::bytes_tag_decode,
                                });
                            match nom::Parser::parse(&mut parser, &libp2p_handshake_decrypted) {
                                Ok((_, out)) => (out.key, out.sig),
                                Err(_) => {
                                    return Err(HandshakeError::PayloadDecode(PayloadDecodeError));
                                }
                            }
                        };
                        let remote_public_key = PublicKey::from_protobuf_encoding(libp2p_key)
                            .map_err(|_| HandshakeError::InvalidKey)?;
                        remote_public_key
                            .verify(
                                &[
                                    &b"noise-libp2p-static-key:"[..],
                                    &self.0.remote_static_public_key.as_bytes()[..],
                                ]
                                .concat(),
                                libp2p_signature,
                            )
                            .map_err(HandshakeError::SignatureVerificationFailed)?;
                        remote_public_key
                    });
                    mix_hash(&mut self.0.hash, libp2p_handshake_encrypted);

                    // Message has been fully processed.
                    self.0.num_buffered_or_transmitted_messages += 1;
                    continue;
                }
                (2, false) => {
                    // Receive `s, se` and the libp2p-specific handshake from the remote.
                    let (remote_static_public_key_encrypted, libp2p_handshake_encrypted) = {
                        // The noise and libp2p-noise specifications clearly define a noise
                        // handshake message and a noise transport message as two different things.
                        // While the remote could in theory send post-handshake
                        // application-specific data in this message, in practice it is forbidden.
                        let mut parser =
                            nom::combinator::all_consuming::<_, (&[u8], nom::error::ErrorKind), _>(
                                (
                                    nom::combinator::map(nom::bytes::streaming::take(48u32), |k| {
                                        <&[u8; 48]>::try_from(k).unwrap()
                                    }),
                                    nom::combinator::rest,
                                ),
                            );
                        match nom::Parser::parse(&mut parser, &available_message) {
                            Ok((_, out)) => out,
                            Err(_) => {
                                return Err(HandshakeError::PayloadDecode(PayloadDecodeError));
                            }
                        }
                    };

                    // Process `s`.
                    self.0.remote_static_public_key = x25519_dalek::PublicKey::from(
                        self.0
                            .cipher_state
                            .read_chachapoly_message_to_array(
                                &*self.0.hash,
                                remote_static_public_key_encrypted,
                            )
                            .map_err(HandshakeError::Cipher)?,
                    );
                    mix_hash(&mut self.0.hash, remote_static_public_key_encrypted);

                    // Process `se`. Call MixKey(DH(e, rs)).
                    let HkdfOutput {
                        output1: chaining_key_update,
                        output2: key_update,
                    } = hkdf(
                        &self.0.chaining_key,
                        self.0
                            .local_ephemeral_private_key
                            .clone()
                            .diffie_hellman(&self.0.remote_static_public_key)
                            .as_bytes(),
                    );
                    self.0.chaining_key = chaining_key_update;
                    self.0.cipher_state.key = key_update;
                    self.0.cipher_state.nonce = 0;

                    // Process the libp2p-specific handshake.
                    self.0.remote_public_key = Some({
                        let libp2p_handshake_decrypted = self
                            .0
                            .cipher_state
                            .read_chachapoly_message_to_vec(
                                &*self.0.hash,
                                libp2p_handshake_encrypted,
                            )
                            .map_err(HandshakeError::Cipher)?;
                        let (libp2p_key, libp2p_signature) = {
                            let mut parser =
                                nom::combinator::all_consuming::<
                                    _,
                                    (&[u8], nom::error::ErrorKind),
                                    _,
                                >(protobuf::message_decode! {
                                    #[required] key = 1 => protobuf::bytes_tag_decode,
                                    #[required] sig = 2 => protobuf::bytes_tag_decode,
                                });
                            match nom::Parser::parse(&mut parser, &libp2p_handshake_decrypted) {
                                Ok((_, out)) => (out.key, out.sig),
                                Err(_) => {
                                    return Err(HandshakeError::PayloadDecode(PayloadDecodeError));
                                }
                            }
                        };
                        let remote_public_key = PublicKey::from_protobuf_encoding(libp2p_key)
                            .map_err(|_| HandshakeError::InvalidKey)?;
                        remote_public_key
                            .verify(
                                &[
                                    &b"noise-libp2p-static-key:"[..],
                                    &self.0.remote_static_public_key.as_bytes()[..],
                                ]
                                .concat(),
                                libp2p_signature,
                            )
                            .map_err(HandshakeError::SignatureVerificationFailed)?;
                        remote_public_key
                    });
                    mix_hash(&mut self.0.hash, libp2p_handshake_encrypted);

                    // Message has been fully processed.
                    self.0.num_buffered_or_transmitted_messages += 1;
                    continue;
                }
                _ => {
                    // Any other state was handled earlier in the function.
                    unreachable!()
                }
            }
        }
    }
}

impl fmt::Debug for HandshakeInProgress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HandshakeInProgress").finish()
    }
}

/// Potential error during the noise handshake.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum HandshakeError {
    /// Reading side of the connection is closed. The handshake can't proceed further.
    ReadClosed,
    /// Writing side of the connection is closed. The handshake can't proceed further.
    WriteClosed,
    /// Error in the decryption state machine.
    #[display("Cipher error: {_0}")]
    Cipher(CipherError),
    /// Failed to decode the payload as the libp2p-extension-to-noise payload.
    #[display("Failed to decode payload as the libp2p-extension-to-noise payload: {_0}")]
    PayloadDecode(PayloadDecodeError),
    /// Key passed as part of the payload failed to decode into a libp2p public key.
    InvalidKey,
    /// Signature of the noise public key by the libp2p key failed.
    #[display("Signature of the noise public key by the libp2p key failed.")]
    SignatureVerificationFailed(SignatureVerifyFailed),
}

/// Error while encrypting data.
#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display("Error while encrypting the Noise payload")]
pub enum EncryptError {
    /// The nonce has overflowed because too many messages have been exchanged. This error is a
    /// normal situation and will happen given sufficient time.
    NonceOverflow,
}

/// Error while decoding data.
#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display("Error while decrypting the Noise payload")]
pub enum CipherError {
    /// Message is too small. This is likely caused by a bug either in this code or in the remote's
    /// code.
    MissingHmac,
    /// Authentication data doesn't match what is expected.
    HmacInvalid,
    /// The nonce has overflowed because too many messages have been exchanged. This error is a
    /// normal situation and will happen given sufficient time.
    NonceOverflow,
}

/// Error while decoding the handshake.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub struct PayloadDecodeError;

struct CipherState {
    key: zeroize::Zeroizing<[u8; 32]>,
    nonce: u64,
    nonce_has_overflowed: bool,
}

impl CipherState {
    /// Accepts a list of input buffers, and returns output buffers that contain the encrypted data
    /// and the HMAC will be written.
    ///
    /// Does *not* include the libp2p-specific message length prefix.
    fn write_chachapoly_message(
        &mut self,
        associated_data: &[u8],
        decrypted_buffers: impl Iterator<Item = Vec<u8>>,
    ) -> Result<impl Iterator<Item = Vec<u8>>, EncryptError> {
        if self.nonce_has_overflowed {
            return Err(EncryptError::NonceOverflow);
        }

        let (mut cipher, mac) = self.prepare(associated_data);
        let associated_data_len = associated_data.len();

        // Increment the nonce by 1. This is done ahead of time in order to be sure that the same
        // nonce is never re-used even if the API user drops the returned iterator before it ends.
        (self.nonce, self.nonce_has_overflowed) = self.nonce.overflowing_add(1);

        // The difficulty in this function implementation is that the cipher operates on 64 bytes
        // blocks (in other words, the data passed to them must have a size multiple of 64), and
        // unfortunately the input buffers might be weirdly aligned.
        // To overcome this, when there's an alignment issue, we copy the data to a contiguous
        // slice.

        // Each input buffer is encrypted in place as much as possible. Due to alignment issues,
        // each input buffer is split in three parts: the data that is appended to the previous
        // buffer's data in order to align it, the data that can be encrypted in place, and the
        // data that must be prepanded to the start of the next buffer.
        // Furthermore, note that the third part of the last buffer can always be encrypted in
        // place.

        // The implementation below requires `decrypted_buffers` to be peekable.
        let mut decrypted_buffers = decrypted_buffers.peekable();
        // Counter for total input decrypted data increased when iterating over the input.
        // Necessary at the very end of the calculation.
        let mut total_decrypted_data = 0;
        // Data that was copied from the end of the previous buffer.
        // TODO: ideally we would avoid copying the end of the previous buffer, and instead only copy the start of the next one, but this means that we couldn't return concrete `Vec`s anymore, and this API change is complicated
        let mut overlapping_data = Vec::new();
        // `None` if the HMAC has already been returned from the iterator.
        let mut mac = Some(mac);

        // Iterator being returned.
        Ok(iter::from_fn(move || {
            loop {
                debug_assert!(overlapping_data.len() < 64);

                // Return if iterator has finished.
                let Some(mac_deref) = mac.as_mut() else {
                    return None;
                };

                if !overlapping_data.is_empty() {
                    // Copy data from the start of the next buffer to the end
                    // of `overlapping_data`.
                    if let Some(next_buffer) = decrypted_buffers.peek_mut() {
                        let missing_data_for_full_frame = 64 - overlapping_data.len();
                        if next_buffer.len() >= missing_data_for_full_frame {
                            // Enough data in next buffer to fill a frame in `overlapping_data`.
                            // Extract data from the next buffer.
                            overlapping_data
                                .extend_from_slice(&next_buffer[..missing_data_for_full_frame]);
                            next_buffer.copy_within(missing_data_for_full_frame.., 0);
                            next_buffer.truncate(next_buffer.len() - missing_data_for_full_frame);

                            // Encrypt `overlapping_data` in place and return it.
                            chacha20::cipher::StreamCipher::apply_keystream(
                                &mut cipher,
                                &mut overlapping_data,
                            );
                            poly1305::universal_hash::UniversalHash::update_padded(
                                mac_deref,
                                &overlapping_data,
                            );
                            debug_assert_eq!(overlapping_data.len(), 64);
                            total_decrypted_data += 64;
                            return Some(mem::take(&mut overlapping_data));
                        } else {
                            // Not enough data in next buffer to fill `overlapping_data`.
                            // Copy the data and continue looping.
                            overlapping_data.extend_from_slice(next_buffer);
                            let _ = decrypted_buffers.next();
                        }
                    } else {
                        // Input is empty. `overlapping_data` is the last buffer.
                        chacha20::cipher::StreamCipher::apply_keystream(
                            &mut cipher,
                            &mut overlapping_data,
                        );
                        poly1305::universal_hash::UniversalHash::update_padded(
                            mac_deref,
                            &overlapping_data,
                        );
                        total_decrypted_data += overlapping_data.len();
                        return Some(mem::take(&mut overlapping_data));
                    }
                } else if let Some(mut buffer) = decrypted_buffers.next() {
                    // Number of bytes of `next_buffer` that can be encrypted in place.
                    let encryptable_in_place = 64 * (buffer.len() / 64);

                    // Perform the encryption.
                    chacha20::cipher::StreamCipher::apply_keystream(
                        &mut cipher,
                        &mut buffer[..encryptable_in_place],
                    );
                    poly1305::universal_hash::UniversalHash::update_padded(
                        mac_deref,
                        &buffer[..encryptable_in_place],
                    );

                    // Copy the non-encryptable-in-place data to `overlapping_data`.
                    if encryptable_in_place != buffer.len() {
                        overlapping_data.reserve(64);
                        overlapping_data.extend_from_slice(&buffer[encryptable_in_place..]);
                        buffer.truncate(encryptable_in_place);
                    }

                    // And return.
                    total_decrypted_data += encryptable_in_place;
                    return Some(buffer);
                } else {
                    // No more encrypted data to return.

                    // Update the MAC with the length of the associated data and input data.
                    let mut block =
                        poly1305::universal_hash::generic_array::GenericArray::default();
                    block[..8].copy_from_slice(
                        &u64::try_from(associated_data_len).unwrap().to_le_bytes(),
                    );
                    block[8..].copy_from_slice(
                        &u64::try_from(total_decrypted_data).unwrap().to_le_bytes(),
                    );
                    poly1305::universal_hash::UniversalHash::update(mac_deref, &[block]);

                    // Return the HMAC.
                    let mac_bytes =
                        poly1305::universal_hash::UniversalHash::finalize(mac.take().unwrap())
                            .to_vec();
                    return Some(mac_bytes);
                }
            }
        }))
    }

    /// Creates a ChaCha20-Poly1305 frame as a `Vec`.
    ///
    /// Does *not* include the libp2p-specific message length prefix.
    fn write_chachapoly_message_to_vec(
        &mut self,
        associated_data: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, EncryptError> {
        Ok(self
            .write_chachapoly_message(associated_data, iter::once(data.to_vec()))?
            .fold(Vec::new(), |mut a, b| {
                if a.is_empty() {
                    b
                } else {
                    a.extend_from_slice(&b);
                    a
                }
            }))
    }

    /// Highly-specific function when the message to decode is 32 bytes.
    fn read_chachapoly_message_to_array(
        &mut self,
        associated_data: &[u8],
        message_data: &[u8; 48],
    ) -> Result<[u8; 32], CipherError> {
        let mut out = [0; 32];
        self.read_chachapoly_message_to_slice(associated_data, message_data, &mut out)?;
        Ok(out)
    }

    fn read_chachapoly_message_to_vec(
        &mut self,
        associated_data: &[u8],
        message_data: &[u8],
    ) -> Result<Vec<u8>, CipherError> {
        let mut destination = vec![0; message_data.len().saturating_sub(16)];
        self.read_chachapoly_message_to_slice(associated_data, message_data, &mut destination)?;
        Ok(destination)
    }

    fn read_chachapoly_message_to_vec_append(
        &mut self,
        associated_data: &[u8],
        message_data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        let len_before = out.len();
        out.resize(len_before + message_data.len().saturating_sub(16), 0);
        let result = self.read_chachapoly_message_to_slice(
            associated_data,
            message_data,
            &mut out[len_before..],
        );
        if result.is_err() {
            out.truncate(len_before);
        }
        result
    }

    fn read_chachapoly_message_to_slice(
        &mut self,
        associated_data: &[u8],
        message_data: &[u8],
        destination: &mut [u8],
    ) -> Result<(), CipherError> {
        debug_assert_eq!(destination.len(), message_data.len() - 16);

        if self.nonce_has_overflowed {
            return Err(CipherError::NonceOverflow);
        }

        // Messages that are missing a HMAC are invalid.
        if message_data.len() < 16 {
            return Err(CipherError::MissingHmac);
        }

        let (mut cipher, mut mac) = self.prepare(associated_data);

        poly1305::universal_hash::UniversalHash::update_padded(
            &mut mac,
            &message_data[..message_data.len() - 16],
        );

        // Update the MAC with the length of the associated data and input data.
        let mut block = poly1305::universal_hash::generic_array::GenericArray::default();
        block[..8].copy_from_slice(&u64::try_from(associated_data.len()).unwrap().to_le_bytes());
        block[8..].copy_from_slice(
            &u64::try_from(message_data.len() - 16)
                .unwrap()
                .to_le_bytes(),
        );
        poly1305::universal_hash::UniversalHash::update(&mut mac, &[block]);

        // Compare the calculated MAC with the one in the payload.
        // This is done in constant time.
        let obtained_mac_bytes = &message_data[message_data.len() - 16..];
        if poly1305::universal_hash::UniversalHash::verify(
            mac,
            poly1305::universal_hash::generic_array::GenericArray::from_slice(obtained_mac_bytes),
        )
        .is_err()
        {
            return Err(CipherError::HmacInvalid);
        }

        // Only after the MAC has been verified, we copy the data and decrypt it.
        // This function returns an error if the cipher stream is exhausted. Because we recreate
        // a cipher stream every time we encode a message, and a message is maximum 2^16 bytes,
        // this can't happen.
        chacha20::cipher::StreamCipher::apply_keystream_b2b(
            &mut cipher,
            &message_data[..message_data.len() - 16],
            destination,
        )
        .unwrap_or_else(|_| unreachable!());

        // Increment the nonce by 1.
        (self.nonce, self.nonce_has_overflowed) = self.nonce.overflowing_add(1);

        Ok(())
    }

    fn prepare(&self, associated_data: &[u8]) -> (chacha20::ChaCha20, poly1305::Poly1305) {
        let mut cipher = {
            let nonce = {
                let mut out = [0; 12];
                out[4..].copy_from_slice(&self.nonce.to_le_bytes());
                out
            };

            <chacha20::ChaCha20 as chacha20::cipher::KeyIvInit>::new(
                chacha20::cipher::generic_array::GenericArray::from_slice(&self.key[..]),
                chacha20::cipher::generic_array::GenericArray::from_slice(&nonce[..]),
            )
        };

        let mut mac = {
            let mut mac_key = zeroize::Zeroizing::new([0u8; 32]);
            chacha20::cipher::StreamCipher::apply_keystream(&mut cipher, &mut *mac_key);
            chacha20::cipher::StreamCipherSeek::seek(&mut cipher, 64);
            <poly1305::Poly1305 as poly1305::universal_hash::KeyInit>::new(
                poly1305::universal_hash::generic_array::GenericArray::from_slice(&*mac_key),
            )
        };

        poly1305::universal_hash::UniversalHash::update_padded(&mut mac, associated_data);

        (cipher, mac)
    }
}

// Implementation of `MixHash`. See <https://noiseprotocol.org/noise.html#the-symmetricstate-object>.
fn mix_hash(hash: &mut [u8; 32], data: &[u8]) {
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut hasher, *hash);
    sha2::Digest::update(&mut hasher, data);
    sha2::Digest::finalize_into(
        hasher,
        sha2::digest::generic_array::GenericArray::from_mut_slice(hash),
    );
}

// Implementation of `HKDF`. See <https://noiseprotocol.org/noise.html#hash-functions>.
//
// Contrary to the version in the Noise specification, this always returns 2 outputs. The third
// output version is never used in this module.
fn hkdf(chaining_key: &[u8; 32], input_key_material: &[u8]) -> HkdfOutput {
    fn hmac_hash<'a>(
        key: &[u8; 32],
        data: impl IntoIterator<Item = &'a [u8]>,
    ) -> zeroize::Zeroizing<[u8; 32]> {
        // Formula is: `H(K XOR opad, H(K XOR ipad, text))`
        // See <https://www.ietf.org/rfc/rfc2104.txt>.
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];

        // Algorithm says that we have to zero-extend `key` to 64 bits, then XOR `ipad` and `opad`
        // with that zero-extended `key`. Given that XOR'ing with 0 is a no-op, we don't care with
        // that and just XOR the key without zero-extending it.
        for n in 0..key.len() {
            ipad[n] ^= key[n];
            opad[n] ^= key[n];
        }

        let intermediary_result = {
            let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
            sha2::Digest::update(&mut hasher, ipad);
            for data in data {
                sha2::Digest::update(&mut hasher, data);
            }
            sha2::Digest::finalize(hasher)
        };

        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, opad);
        sha2::Digest::update(&mut hasher, intermediary_result);

        let mut output = zeroize::Zeroizing::new([0; 32]);
        sha2::Digest::finalize_into(
            hasher,
            sha2::digest::generic_array::GenericArray::from_mut_slice(&mut *output),
        );
        output
    }

    let temp_key = hmac_hash(chaining_key, [input_key_material]);
    let output1 = hmac_hash(&temp_key, [&[0x01][..]]);
    let output2 = hmac_hash(&temp_key, [&*output1, &[0x02][..]]);
    HkdfOutput { output1, output2 }
}

/// Output of the [`hkdf`] function.
struct HkdfOutput {
    output1: zeroize::Zeroizing<[u8; 32]>,
    output2: zeroize::Zeroizing<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use core::{cmp, mem};

    use super::{Config, NoiseHandshake, NoiseKey, ReadWrite};

    #[test]
    fn handshake_basic_works() {
        fn test_with_buffer_sizes(mut size1: usize, mut size2: usize) {
            let key1 = NoiseKey::new(&rand::random(), &rand::random());
            let key2 = NoiseKey::new(&rand::random(), &rand::random());

            let mut handshake1 = NoiseHandshake::new(Config {
                key: &key1,
                is_initiator: true,
                prologue: &[],
                ephemeral_secret_key: &rand::random(),
            });
            let mut handshake2 = NoiseHandshake::new(Config {
                key: &key2,
                is_initiator: false,
                prologue: &[],
                ephemeral_secret_key: &rand::random(),
            });

            let mut buf_1_to_2 = Vec::new();
            let mut buf_2_to_1 = Vec::new();

            while !matches!(
                (&handshake1, &handshake2),
                (
                    NoiseHandshake::Success { .. },
                    NoiseHandshake::Success { .. }
                )
            ) {
                match handshake1 {
                    NoiseHandshake::Success { .. } => {}
                    NoiseHandshake::InProgress(nego) => {
                        let mut read_write = ReadWrite {
                            now: 0,
                            incoming_buffer: buf_2_to_1,
                            expected_incoming_bytes: Some(0),
                            read_bytes: 0,
                            write_bytes_queued: buf_1_to_2.len(),
                            write_bytes_queueable: Some(size1 - buf_1_to_2.len()),
                            write_buffers: vec![mem::take(&mut buf_1_to_2)],
                            wake_up_after: None,
                        };
                        handshake1 = nego.read_write(&mut read_write).unwrap();
                        buf_2_to_1 = read_write.incoming_buffer;
                        buf_1_to_2.extend(
                            read_write
                                .write_buffers
                                .drain(..)
                                .flat_map(|b| b.into_iter()),
                        );
                        size2 = cmp::max(size2, read_write.expected_incoming_bytes.unwrap_or(0));
                    }
                }

                match handshake2 {
                    NoiseHandshake::Success { .. } => {}
                    NoiseHandshake::InProgress(nego) => {
                        let mut read_write = ReadWrite {
                            now: 0,
                            incoming_buffer: buf_1_to_2,
                            expected_incoming_bytes: Some(0),
                            read_bytes: 0,
                            write_bytes_queued: buf_2_to_1.len(),
                            write_bytes_queueable: Some(size2 - buf_2_to_1.len()),
                            write_buffers: vec![mem::take(&mut buf_2_to_1)],
                            wake_up_after: None,
                        };
                        handshake2 = nego.read_write(&mut read_write).unwrap();
                        buf_1_to_2 = read_write.incoming_buffer;
                        buf_2_to_1.extend(
                            read_write
                                .write_buffers
                                .drain(..)
                                .flat_map(|b| b.into_iter()),
                        );
                        size1 = cmp::max(size1, read_write.expected_incoming_bytes.unwrap_or(0));
                    }
                }
            }
        }

        test_with_buffer_sizes(256, 256);
        test_with_buffer_sizes(1, 1);
        test_with_buffer_sizes(1, 2048);
        test_with_buffer_sizes(2048, 1);
    }
}
