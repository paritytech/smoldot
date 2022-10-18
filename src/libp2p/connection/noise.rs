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
//! Use [`Noise::encrypt`] in order to send out data to the remote, and
//! [`Noise::inject_inbound_data`] when data is received.
// TODO: review this last sentence, as this API might change after some experience with it

use crate::{
    libp2p::{
        peer_id::{PeerId, PublicKey, SignatureVerifyFailed},
        read_write::ReadWrite,
    },
    util::protobuf,
};

use alloc::{boxed::Box, collections::VecDeque, vec, vec::Vec};
use core::{cmp, fmt};

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
    key: snow::Keypair,
    /// Handshake to encrypt then send on the wire.
    handshake_message: Vec<u8>,
    /// Ed25519 public key used for the signature in the handshake message.
    libp2p_public_ed25519_key: [u8; 32],
}

impl NoiseKey {
    /// Generates a new private and public key pair signed with the given libp2p Ed25519 key.
    pub fn new(libp2p_ed25519_private_key: &[u8; 32]) -> Self {
        let unsigned = UnsignedNoiseKey::random();

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
    key: snow::Keypair,
}

impl UnsignedNoiseKey {
    /// Generates a new private and public key pair.
    pub fn random() -> Self {
        UnsignedNoiseKey {
            // TODO: can panic if there's no RNG
            key: snow::Builder::new(noise_params())
                .generate_keypair()
                .unwrap(),
        }
    }

    /// Returns the data that has to be signed.
    pub fn payload_to_sign(&'_ self) -> impl Iterator<Item = impl AsRef<[u8]> + '_> + '_ {
        [&b"noise-libp2p-static-key:"[..], &self.key.public[..]].into_iter()
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
    pub fn sign(self, libp2p_public_ed25519_key: [u8; 32], signature: [u8; 64]) -> NoiseKey {
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
            key: self.key,
            libp2p_public_ed25519_key,
            handshake_message,
        }
    }
}

/// Configuration for a Noise handshake.
pub struct Config<'a> {
    /// Key to use during the handshake.
    pub key: &'a NoiseKey,

    /// `true` if this side of the handshake has initiated the connection or substream onto which
    /// the handshake is performed.
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
    inner: snow::TransportState,

    /// Buffer of data containing data received on the wire, before decryption. Always either
    /// empty or contains a partial frame (including the two bytes of length prefix). Frames,
    /// once full, are immediately decoded and moved to `rx_buffer_decrypted`.
    rx_buffer_encrypted: Vec<u8>,

    /// Buffer of data containing data received on the wire, after decryption.
    rx_buffer_decrypted: Vec<u8>,
}

impl Noise {
    /// Feeds data received from the wire.
    // TODO: document or redesign the return value; at the moment is can different from payload.len() only if the decrypted buffer is full
    pub fn inject_inbound_data(&mut self, mut payload: &[u8]) -> Result<usize, CipherError> {
        // As a reminder, noise frames consist of two bytes of length (big endian) followed with
        // the message of that length destined to the `snow` library.

        let mut total_read = 0;

        loop {
            // Buffering up too much data in the output buffer should be avoided. As such, past
            // a certain threshold, return early and refuse to read more.
            // TODO: is this a good idea?
            // TODO: should be configurable value
            if self.rx_buffer_decrypted.len() >= 65536 * 4 {
                return Ok(total_read);
            }

            // Try to construct the length prefix in `rx_buffer_encrypted` by moving bytes from
            // `payload`.
            while self.rx_buffer_encrypted.len() < 2 {
                if payload.is_empty() {
                    return Ok(total_read);
                }

                self.rx_buffer_encrypted.push(payload[0]);
                payload = &payload[1..];
                total_read += 1;
            }

            // Length of the frame currently being received.
            let expected_len = usize::from(u16::from_be_bytes(
                <[u8; 2]>::try_from(&self.rx_buffer_encrypted[..2]).unwrap(),
            ));

            // If there isn't enough data available for the full frame, copy the partial frame
            // to `rx_buffer_encrypted` and return early.
            if self.rx_buffer_encrypted.len() + payload.len() < expected_len + 2 {
                self.rx_buffer_encrypted.extend_from_slice(payload);
                total_read += payload.len();
                return Ok(total_read);
            }

            // Construct the encrypted slice of data to decode.
            let to_decode_slice = if self.rx_buffer_encrypted.len() == 2 {
                // If the entirety of the frame is in `payload`, decode it from there without
                // moving data.
                debug_assert!(payload.len() >= expected_len);
                let decode = &payload[..expected_len];
                payload = &payload[expected_len..];
                total_read += expected_len;
                decode
            } else {
                // Otherwise, copy the rest of the frame to `rx_buffer_encrypted`.
                let remains = expected_len - (self.rx_buffer_encrypted.len() - 2);
                self.rx_buffer_encrypted
                    .extend_from_slice(&payload[..remains]);
                payload = &payload[remains..];
                total_read += remains;
                &self.rx_buffer_encrypted[2..]
            };

            // Allocate the space to decode to.
            // Each frame consists of the payload plus 16 bytes of authentication data, therefore
            // the payload size is `expected_len - 16`.
            // We use `saturating_sub` in order to avoid panicking in case the `expected_len` is
            // invalid. An invalid `expected_len` should trigger an error when decoding the
            // message below.
            let len_before = self.rx_buffer_decrypted.len();
            self.rx_buffer_decrypted
                .resize(len_before + expected_len.saturating_sub(16), 0);

            // Finally decoding the data.
            let written = self
                .inner
                .read_message(to_decode_slice, &mut self.rx_buffer_decrypted[len_before..])
                .map_err(CipherError)?;
            self.rx_buffer_decrypted.truncate(len_before + written);

            // Clear the now-decoded frame.
            self.rx_buffer_encrypted.clear();
        }
    }

    /// Returns true if the local side has opened the connection.
    pub fn is_initiator(&self) -> bool {
        self.inner.is_initiator()
    }

    // TODO: if rx_buffer_decrypted becomes a VecDeque, this leads to a potentially weird API
    //       where calling consume_inbound_data can lead to decoded_inbound_data to provide more
    //       data
    pub fn decoded_inbound_data(&self) -> &[u8] {
        &self.rx_buffer_decrypted
    }

    pub fn consume_inbound_data(&mut self, n: usize) {
        // TODO: be smarter than copying
        self.rx_buffer_decrypted = self.rx_buffer_decrypted[n..].to_vec();
    }

    /// Reads data from `payload` and writes it to `destination`. Returns, in order, the number
    /// of bytes read from `payload` and the number of bytes written to `destination`. The data
    /// written out is always slightly larger than the data read, in order to add the
    /// [`HMAC`](https://en.wikipedia.org/wiki/HMAC)s.
    ///
    /// This function returns only after the input bytes are fully consumed or the output buffer
    /// is full.
    ///
    /// The number of bytes read and written is only a function of the size of the input and of
    /// the available output. Use [`Noise::encrypt_size_conv`] to determine the maximum payload
    /// size that fits a certain output buffers.
    ///
    /// > **Note**: Because each message has a prefix and a suffix, you are encouraged to batch
    /// >           as much data as possible into `payload` before calling this function.
    pub fn encrypt<'a>(
        &mut self,
        mut payload: impl Iterator<Item = impl AsRef<[u8]>>,
        destination: (&'a mut [u8], &'a mut [u8]),
    ) -> (usize, usize) {
        // TODO: The API exposes `payload` as an iterator of buffers rather than a single
        //       contiguous buffer. The reason is that, theoretically speaking, the underlying
        //       implementation should be able to read bytes from an iterator. Rather than
        //       providing an API whose usage might force an overhead, the overhead is instead
        //       moved to the body of this method, while keeping in mind that this overhead can
        //       be fixed later.

        // The three possible paths below are: the iterator is empty, the iterator contains
        // exactly one buffer, the iterator contains two or more buffers.

        let first_buf = match payload.next() {
            Some(b) => b,
            None => return (0, 0),
        };

        if let Some(next) = payload.next() {
            let mut buf = first_buf.as_ref().to_vec();
            buf.extend_from_slice(next.as_ref());
            let payload = payload.fold(buf, |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });
            self.encrypt_inner(&payload, destination)
        } else {
            self.encrypt_inner(first_buf.as_ref(), destination)
        }
    }

    fn encrypt_inner<'a>(
        &mut self,
        mut payload: &[u8],
        mut destination: (&'a mut [u8], &'a mut [u8]),
    ) -> (usize, usize) {
        let mut total_read = 0;
        let mut total_written = 0;

        // At least 18 bytes must be available in `destination` in order to fit an entire noise
        // frame. The check is for 19 because it doesn't make sense to send an empty frame.
        // TODO: this is error-prone ^ as a user might accidentally have a maximum buffer size that is < 19
        while destination.0.len() + destination.1.len() >= 19 {
            let in_len = cmp::min(
                payload.len(),
                cmp::min(65536, destination.0.len() + destination.1.len() - 18),
            );
            if in_len == 0 {
                debug_assert!(payload.is_empty());
                break;
            }

            let out_len = in_len + 2 + 16;

            if out_len <= destination.0.len() {
                let written = self
                    .inner
                    .write_message(&payload[..in_len], &mut destination.0[2..in_len + 2 + 16])
                    .unwrap();
                debug_assert_eq!(written, in_len + 16);

                let len_bytes = u16::try_from(written).unwrap().to_be_bytes();
                destination.0[..2].copy_from_slice(&len_bytes);

                total_read += in_len;
                payload = &payload[in_len..];
                total_written += written + 2;
                destination.0 = &mut destination.0[written + 2..];

                if destination.0.is_empty() {
                    destination = (destination.1, &mut []);
                }
            } else {
                debug_assert!(out_len <= destination.0.len() + destination.1.len());
                let mut intermediary_buffer = vec![0; out_len];
                let _written = self
                    .inner
                    .write_message(&payload[..in_len], &mut intermediary_buffer[2..])
                    .unwrap();
                debug_assert_eq!(_written + 2, out_len);

                let len_bytes = u16::try_from(out_len - 2).unwrap().to_be_bytes();
                intermediary_buffer[..2].copy_from_slice(&len_bytes);

                total_read += in_len;
                payload = &payload[in_len..];
                total_written += out_len;

                destination
                    .0
                    .copy_from_slice(&intermediary_buffer[..destination.0.len()]);
                destination.1[..out_len - destination.0.len()]
                    .copy_from_slice(&intermediary_buffer[destination.0.len()..]);
                destination = (&mut destination.1[out_len - destination.0.len()..], &mut []);
            }
        }

        (total_read, total_written)
    }

    /// Returns the size of unencrypted data that fits a buffer of encrypted data.
    // TODO: doc
    pub fn encrypt_size_conv(&self, out_size: usize) -> usize {
        let mut total = 0;
        let mut dest_len = out_size;
        while dest_len >= 19 {
            let in_len = cmp::min(65536, dest_len - 18);
            total += in_len;
            dest_len -= in_len + 18;
        }
        total
    }
}

impl fmt::Debug for Noise {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Noise").finish()
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
pub struct HandshakeInProgress {
    /// Underlying noise state machine.
    ///
    /// Libp2p always uses the XX handshake.
    ///
    /// While the `snow` library ensures that the emitted and received messages respect the
    /// handshake according to the noise specification, libp2p extends this noise specification
    /// with a payload that must be transmitted on the second and third messages of the exchange.
    /// This payload must contain a signature of the noise key made using the libp2p key and can
    /// be found in the `tx_payload` field.
    inner: snow::HandshakeState,

    /// Unencrypted payload to send as part of the handshake.
    /// If the payload has already been sent, contains `None`.
    /// If the payload hasn't been sent yet, contains the index of the call to
    /// [`snow::HandshakeState::write_message`] that must contain the payload.
    tx_payload: Option<(u8, Box<[u8]>)>,

    /// State of the remote payload reception.
    rx_payload: RxPayload,

    /// Number of messages remaining to be received. Used to know whether an incoming packet is
    /// still part of the handshake or not.
    rx_messages_remain: u8,

    /// Buffer of data containing data received on the wire, before decryption.
    rx_buffer_encrypted: Vec<u8>,

    /// Buffer of data containing data waiting to be sent on the wire, after encryption. Includes
    /// the length prefixes.
    tx_buffer_encrypted: VecDeque<u8>,
}

enum RxPayload {
    /// Remote payload has been received.
    Received(PeerId),
    /// Index of the call to [`snow::HandshakeState::read_message`], from now, that is expected
    /// to contains the payload.
    NthMessage(u8),
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
        let inner = {
            let builder = snow::Builder::new(noise_params())
                .local_private_key(&config.key.key.private)
                .prologue(&config.prologue);
            if config.is_initiator {
                builder.build_initiator()
            } else {
                builder.build_responder()
            }
            .unwrap()
        };

        // Configure according to the XX handshake.
        let (tx_payload, rx_payload, rx_messages_remain) = if config.is_initiator {
            let tx = Some((1, config.key.handshake_message.clone().into_boxed_slice()));
            let rx = RxPayload::NthMessage(0);
            (tx, rx, 1)
        } else {
            let tx = Some((0, config.key.handshake_message.clone().into_boxed_slice()));
            let rx = RxPayload::NthMessage(1);
            (tx, rx, 2)
        };

        let mut handshake = HandshakeInProgress {
            inner,
            tx_payload,
            rx_payload,
            rx_messages_remain,
            rx_buffer_encrypted: Vec::with_capacity(65536 + 2),
            tx_buffer_encrypted: VecDeque::new(),
        };

        handshake.update_message_write();
        handshake
    }

    /// Calls [`snow::HandshakeState::write_message`] if necessary, updates all the internal state,
    /// and puts the message into `tx_buffer_encrypted`.
    fn update_message_write(&mut self) {
        if self.inner.is_handshake_finished() || !self.inner.is_my_turn() {
            return;
        }

        debug_assert!(self.tx_buffer_encrypted.is_empty());

        let payload = match &mut self.tx_payload {
            None => None,
            Some((n, _)) if *n != 0 => {
                *n -= 1;
                None
            }
            opt @ Some(_) => {
                let (_n, payload) = opt.take().unwrap();
                debug_assert_eq!(_n, 0);
                Some(payload)
            }
        };

        self.tx_buffer_encrypted.resize(512, 0);
        debug_assert!(self.tx_buffer_encrypted.as_slices().1.is_empty());
        let written = self
            .inner
            .write_message(
                payload.as_ref().map(|p| &p[..]).unwrap_or(&[]),
                self.tx_buffer_encrypted.as_mut_slices().0,
            )
            .unwrap();
        assert!(written < self.tx_buffer_encrypted.len()); // be sure that the message has fit into `out`.
        self.tx_buffer_encrypted.truncate(written);

        // Handshake must also be prefixed with two bytes indicating its length.
        // The message is guaranteed by the Noise specs to not be more than 64kiB.
        let length_bytes = u16::try_from(self.tx_buffer_encrypted.len())
            .unwrap()
            .to_be_bytes();
        self.tx_buffer_encrypted.push_front(length_bytes[1]);
        self.tx_buffer_encrypted.push_front(length_bytes[0]);
    }

    /// Try to turn this [`HandshakeInProgress`] into a [`NoiseHandshake::Success`] if possible.
    fn try_finish(self) -> NoiseHandshake {
        if !self.tx_buffer_encrypted.is_empty() {
            return NoiseHandshake::InProgress(self);
        }

        if !self.inner.is_handshake_finished() {
            return NoiseHandshake::InProgress(self);
        }

        // `into_transport_mode()` can only panic if `!is_handshake_finished()`.
        let cipher = self.inner.into_transport_mode().unwrap();

        let remote_peer_id = match self.rx_payload {
            RxPayload::Received(peer_id) => peer_id,
            // Since `is_handshake_finished()` has returned true, all messages have been
            // exchanged. As such, the remote payload cannot be in a "still waiting to come"
            // situation other than because of logic error within the code.
            RxPayload::NthMessage(_) => unreachable!(),
        };

        // If `rx_buffer_encrypted` wasn't empty, that would mean there would still be a handshake
        // message to decode, which shouldn't be possible given that the handshake is finished.
        debug_assert!(self.rx_buffer_encrypted.is_empty());

        NoiseHandshake::Success {
            cipher: Noise {
                inner: cipher,
                rx_buffer_encrypted: self.rx_buffer_encrypted,
                rx_buffer_decrypted: Vec::new(), // TODO: with_capacity
            },
            remote_peer_id,
        }
    }

    /// Feeds data coming from a socket and outputs data to write to the socket.
    ///
    /// On success, returns the new state of the negotiation.
    ///
    /// An error is returned if the protocol is being violated by the remote. When that happens,
    /// the connection should be closed altogether.
    pub fn read_write<TNow>(
        mut self,
        read_write: &mut ReadWrite<'_, TNow>,
    ) -> Result<NoiseHandshake, HandshakeError> {
        'outer_loop: loop {
            // Copy data from `self.tx_buffer_encrypted` to `read_write`.
            loop {
                debug_assert!(
                    !self.tx_buffer_encrypted.as_slices().0.is_empty()
                        || self.tx_buffer_encrypted.as_slices().1.is_empty()
                );

                let to_write = self.tx_buffer_encrypted.as_slices().0;
                if !to_write.is_empty() && read_write.outgoing_buffer.is_none() {
                    return Err(HandshakeError::WriteClosed);
                }

                let to_write_len = cmp::min(to_write.len(), read_write.outgoing_buffer_available());
                if to_write_len == 0 {
                    break;
                }

                read_write.write_out(&to_write[..to_write_len]);
                for _ in 0..to_write_len {
                    self.tx_buffer_encrypted.pop_front().unwrap();
                }
            }

            // Check if incoming data is still part of the handshake.
            // If not, return now without reading anything more.
            if self.rx_messages_remain == 0 {
                break;
            }

            // The remaining of the body requires reading from `read_write`. As such, error if
            // the reading side is closed.
            if read_write.incoming_buffer.is_none() {
                return Err(HandshakeError::ReadClosed);
            }

            // Handshake message must start with two bytes of length.
            // Copy bytes one by one from payload until we reach a length of two.
            while self.rx_buffer_encrypted.len() < 2 {
                if read_write.incoming_buffer_available() == 0 {
                    break 'outer_loop;
                }

                self.rx_buffer_encrypted
                    .push(read_write.read_bytes::<1>()[0]);
            }

            // Decoding the first two bytes, which are the length of the handshake message.
            let expected_len =
                u16::from_be_bytes(<[u8; 2]>::try_from(&self.rx_buffer_encrypted[..2]).unwrap());
            debug_assert!(
                expected_len == 0 || self.rx_buffer_encrypted.len() < 2 + usize::from(expected_len)
            );

            // Copy as much data as possible from `payload` to `self.rx_buffer_encrypted`, without
            // copying more than the handshake message.
            let to_copy = cmp::min(
                usize::from(expected_len) + 2 - self.rx_buffer_encrypted.len(),
                read_write.incoming_buffer_available(),
            );
            self.rx_buffer_encrypted
                .extend(read_write.incoming_bytes_iter().take(to_copy));
            debug_assert!(self.rx_buffer_encrypted.len() <= usize::from(expected_len) + 2);

            // Return early if the entire handshake message has not been received yet.
            if self.rx_buffer_encrypted.len() < usize::from(expected_len) + 2 {
                break;
            }

            // Entire handshake message has been received.
            // Decoding the potential payload into `decoded_payload`.
            let decoded_payload = {
                // The decrypted payload can only ever be smaller than the encrypted message. As
                // such, we allocate a buffer of size equal to the encrypted message.
                let mut decoded = vec![0; usize::from(expected_len)];
                match self
                    .inner
                    .read_message(&self.rx_buffer_encrypted[2..], &mut decoded)
                {
                    Err(err) => {
                        return Err(HandshakeError::Cipher(CipherError(err)));
                    }
                    Ok(n) => {
                        debug_assert!(n <= decoded.len());
                        decoded.truncate(n);
                    }
                }
                decoded
            };

            // Data in `rx_buffer_encrypted` has been fully decoded and can be thrown away.
            self.rx_buffer_encrypted.clear();
            self.rx_messages_remain -= 1;

            // Check and update the status of the payload reception.
            let payload_expected = match &mut self.rx_payload {
                RxPayload::NthMessage(0) => true,
                RxPayload::NthMessage(n) => {
                    *n -= 1;
                    false
                }
                RxPayload::Received(_) => false,
            };

            if payload_expected {
                // The decoded handshake is a protobuf message.
                // See https://github.com/libp2p/specs/tree/master/noise#the-libp2p-handshake-payload
                let (identity_key, identity_sig) = {
                    let mut parser =
                        nom::combinator::all_consuming::<_, _, nom::error::Error<&[u8]>, _>(
                            nom::combinator::complete(protobuf::message_decode! {
                                key = 1 => protobuf::bytes_tag_decode,
                                sig = 2 => protobuf::bytes_tag_decode,
                            }),
                        );
                    match nom::Finish::finish(parser(&decoded_payload)) {
                        Ok((_, out)) => (out.key, out.sig),
                        Err(_) => return Err(HandshakeError::PayloadDecode(PayloadDecodeError)),
                    }
                };

                let remote_public_key = PublicKey::from_protobuf_encoding(identity_key)
                    .map_err(|_| HandshakeError::InvalidKey)?;

                // Assuming that the libp2p+noise specifications are well-designed, the payload
                // will only arrive after `get_remote_static` is `Some`. Since we have already
                // checked that the payload arrives when it is supposed to, this can never panic.
                let remote_noise_static = self.inner.get_remote_static().unwrap();
                // TODO: don't use concat() in order to not allocate a Vec
                remote_public_key
                    .verify(
                        &[b"noise-libp2p-static-key:", remote_noise_static].concat(),
                        identity_sig,
                    )
                    .map_err(HandshakeError::SignatureVerificationFailed)?;

                self.rx_payload = RxPayload::Received(remote_public_key.into_peer_id());
            } else if !decoded_payload.is_empty() {
                return Err(HandshakeError::UnexpectedPayload);
            };

            // Now that a message has been received, check if it's the turn of the local node to
            // send something. This puts more data in `tx_buffer_encrypted`.
            self.update_message_write();
        }

        // Call `try_finish` to check whether the handshake has finished.
        Ok(self.try_finish())
    }
}

impl fmt::Debug for HandshakeInProgress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HandshakeInProgress").finish()
    }
}

/// Returns the Noise configuration.
//
// Note that we don't use `lazy_static` because of `no_std` compatibility.
// TODO: do this at compilation time, ideally
fn noise_params() -> snow::params::NoiseParams {
    "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap()
}

/// Potential error during the noise handshake.
#[derive(Debug, derive_more::Display)]
pub enum HandshakeError {
    /// Reading side of the connection is closed. The handshake can't proceed further.
    ReadClosed,
    /// Writing side of the connection is closed. The handshake can't proceed further.
    WriteClosed,
    /// Error in the decryption state machine.
    #[display(fmt = "Cipher error: {}", _0)]
    Cipher(CipherError),
    /// Failed to decode the payload as the libp2p-extension-to-noise payload.
    #[display(
        fmt = "Failed to decode payload as the libp2p-extension-to-noise payload: {}",
        _0
    )]
    PayloadDecode(PayloadDecodeError),
    /// Key passed as part of the payload failed to decode into a libp2p public key.
    InvalidKey,
    /// Received a payload as part of a handshake message when none was expected.
    UnexpectedPayload,
    /// Signature of the noise public key by the libp2p key failed.
    #[display(fmt = "Signature of the noise public key by the libp2p key failed.")]
    SignatureVerificationFailed(SignatureVerifyFailed),
}

/// Error while decoding data.
#[derive(Debug, derive_more::Display)]
#[display(fmt = "Error while decrypting the Noise payload")]
pub struct CipherError(snow::Error);

/// Error while decoding the handshake.
#[derive(Debug, derive_more::Display)]
pub struct PayloadDecodeError;

#[cfg(test)]
mod tests {
    use super::{Config, NoiseHandshake, NoiseKey, ReadWrite};

    #[test]
    fn handshake_basic_works() {
        fn test_with_buffer_sizes(size1: usize, size2: usize) {
            let key1 = NoiseKey::new(&rand::random());
            let key2 = NoiseKey::new(&rand::random());

            let mut handshake1 = NoiseHandshake::new(Config {
                key: &key1,
                is_initiator: true,
                prologue: &[],
            });
            let mut handshake2 = NoiseHandshake::new(Config {
                key: &key2,
                is_initiator: false,
                prologue: &[],
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
                        if buf_1_to_2.is_empty() {
                            buf_1_to_2.resize(size1, 0);

                            let mut read_write = ReadWrite {
                                now: 0,
                                incoming_buffer: Some(&buf_2_to_1),
                                outgoing_buffer: Some((&mut buf_1_to_2, &mut [])),
                                read_bytes: 0,
                                written_bytes: 0,
                                wake_up_after: None,
                            };

                            handshake1 = nego.read_write(&mut read_write).unwrap();
                            let (read_bytes, written_bytes) =
                                (read_write.read_bytes, read_write.written_bytes);
                            for _ in 0..read_bytes {
                                buf_2_to_1.remove(0);
                            }
                            buf_1_to_2.truncate(written_bytes);
                        } else {
                            let mut read_write = ReadWrite {
                                now: 0,
                                incoming_buffer: Some(&buf_2_to_1),
                                outgoing_buffer: Some((&mut buf_1_to_2, &mut [])),
                                read_bytes: 0,
                                written_bytes: 0,
                                wake_up_after: None,
                            };
                            handshake1 = nego.read_write(&mut read_write).unwrap();
                            for _ in 0..read_write.read_bytes {
                                buf_2_to_1.remove(0);
                            }
                        }
                    }
                }

                match handshake2 {
                    NoiseHandshake::Success { .. } => {}
                    NoiseHandshake::InProgress(nego) => {
                        if buf_2_to_1.is_empty() {
                            buf_2_to_1.resize(size2, 0);

                            let mut read_write = ReadWrite {
                                now: 0,
                                incoming_buffer: Some(&buf_1_to_2),
                                outgoing_buffer: Some((&mut buf_2_to_1, &mut [])),
                                read_bytes: 0,
                                written_bytes: 0,
                                wake_up_after: None,
                            };

                            handshake2 = nego.read_write(&mut read_write).unwrap();
                            let (read_bytes, written_bytes) =
                                (read_write.read_bytes, read_write.written_bytes);
                            for _ in 0..read_bytes {
                                buf_1_to_2.remove(0);
                            }
                            buf_2_to_1.truncate(written_bytes);
                        } else {
                            let mut read_write = ReadWrite {
                                now: 0,
                                incoming_buffer: Some(&buf_1_to_2),
                                outgoing_buffer: Some((&mut buf_2_to_1, &mut [])),
                                read_bytes: 0,
                                written_bytes: 0,
                                wake_up_after: None,
                            };
                            handshake2 = nego.read_write(&mut read_write).unwrap();
                            for _ in 0..read_write.read_bytes {
                                buf_1_to_2.remove(0);
                            }
                        }
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
