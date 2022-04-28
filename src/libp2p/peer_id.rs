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

use alloc::{string::String, vec::Vec};
use core::{cmp, fmt, hash, str::FromStr};
use prost::Message as _;
use sha2::Digest as _;

use super::multihash;

mod keys_proto {
    include!(concat!(env!("OUT_DIR"), "/keys_proto.rs"));
}

/// Public key of a node's identity.
///
/// Libp2p specifies multiple different possible algorithms, but only Ed25519 support is
/// mandatory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// An Ed25519 public key.
    Ed25519([u8; 32]),
}

impl PublicKey {
    /// Encode the public key into a Protobuf structure for storage or
    /// exchange with other nodes.
    pub fn to_protobuf_encoding(&self) -> Vec<u8> {
        let public_key = match self {
            PublicKey::Ed25519(key) => keys_proto::PublicKey {
                r#type: keys_proto::KeyType::Ed25519 as i32,
                data: key.to_vec(),
            },
        };

        let mut buf = Vec::with_capacity(public_key.encoded_len());
        public_key.encode(&mut buf).unwrap();
        buf
    }

    /// Decode a public key from a Protobuf structure, e.g. read from storage
    /// or received from another node.
    pub fn from_protobuf_encoding(bytes: &[u8]) -> Result<PublicKey, FromProtobufEncodingError> {
        let pubkey = keys_proto::PublicKey::decode(bytes)
            .map_err(|_| FromProtobufEncodingError::ProtobufDecodeError)?;

        let key_type = keys_proto::KeyType::from_i32(pubkey.r#type)
            .ok_or(FromProtobufEncodingError::UnknownAlgorithm)?;

        match key_type {
            keys_proto::KeyType::Ed25519 => {
                let pubkey = <&[u8; 32]>::try_from(&pubkey.data[..])
                    .map_err(|_| FromProtobufEncodingError::BadEd25519Key)?;
                Ok(PublicKey::Ed25519(*pubkey))
            }
            keys_proto::KeyType::Rsa
            | keys_proto::KeyType::Secp256k1
            | keys_proto::KeyType::Ecdsa => Err(FromProtobufEncodingError::UnsupportedAlgorithm),
        }
    }

    /// Convert the [`PublicKey`] into the corresponding [`PeerId`].
    pub fn into_peer_id(self) -> PeerId {
        self.into()
    }

    /// Verifies whether the given signature is valid for the given message using `self` as the
    /// public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignatureVerifyFailed> {
        let PublicKey::Ed25519(public_key) = self;
        let public_key = ed25519_zebra::VerificationKey::try_from(*public_key)
            .map_err(|_| SignatureVerifyFailed())?;
        let signature =
            ed25519_zebra::Signature::try_from(signature).map_err(|_| SignatureVerifyFailed())?;
        public_key
            .verify(&signature, message)
            .map_err(|_| SignatureVerifyFailed())?;
        Ok(())
    }
}

/// Error potentially returned by [`PublicKey::from_protobuf_encoding`].
#[derive(Debug, derive_more::Display)]
pub enum FromProtobufEncodingError {
    /// Error decoding the Protobuf message.
    ProtobufDecodeError,
    /// Public key algorithm unknown.
    UnknownAlgorithm,
    /// Ed25519 key doesn't have a correct length.
    BadEd25519Key,
    /// Algorithms other than Ed25519 aren't supported.
    UnsupportedAlgorithm,
}

/// Call to [`PublicKey::verify`] has failed. No reason is provided for security reasons.
#[derive(Debug, derive_more::Display)]
pub struct SignatureVerifyFailed();

/// Public keys with byte-lengths smaller than `MAX_INLINE_KEY_LENGTH` will be
/// automatically used as the peer id using an identity multihash.
const MAX_INLINE_KEY_LENGTH: usize = 42;

/// Identifier of a node of the network.
///
/// The data is a multihash of the public key of the peer.
#[derive(Clone, Eq)]
pub struct PeerId {
    /// Always contains a valid multihash.
    multihash: Vec<u8>,
}

impl PeerId {
    /// Builds the [`PeerId`] corresponding to a public key.
    pub fn from_public_key(key: &PublicKey) -> PeerId {
        let key_enc = key.to_protobuf_encoding();

        let out = if key_enc.len() <= MAX_INLINE_KEY_LENGTH {
            let mut out = Vec::with_capacity(key_enc.len() + 8);
            for slice in multihash::MultihashRef::identity(&key_enc).as_bytes() {
                out.extend_from_slice(slice.as_ref())
            }
            out
        } else {
            let mut out = Vec::with_capacity(34);
            out.push(0x12);
            out.push(0x32);

            let mut hasher = sha2::Sha256::new();
            hasher.update(&key_enc);
            out.extend_from_slice(hasher.finalize().as_slice());

            out
        };

        PeerId { multihash: out }
    }

    /// Checks whether `data` is a valid [`PeerId`].
    ///
    /// In case of error, returns the bytes passed as parameter in addition to the error.
    pub fn from_bytes(data: Vec<u8>) -> Result<PeerId, (FromBytesError, Vec<u8>)> {
        let result = match multihash::MultihashRef::from_bytes(&data) {
            Ok(hash) => {
                // For a PeerId to be valid, it must use either the "identity" multihash code (0x0)
                // or the "sha256" multihash code (0x12).
                if hash.hash_algorithm_code() == 0 {
                    if let Err(err) = PublicKey::from_protobuf_encoding(hash.data()) {
                        Err(FromBytesError::InvalidPublicKey(err))
                    } else {
                        Ok(())
                    }
                } else if hash.hash_algorithm_code() == 0x12 {
                    Ok(())
                } else {
                    Err(FromBytesError::InvalidMultihashAlgorithm)
                }
            }
            Err(err) => Err(FromBytesError::DecodeError(err)),
        };

        match result {
            Ok(()) => Ok(PeerId { multihash: data }),
            Err(err) => Err((err, data)),
        }
    }

    /// Returns a raw bytes representation of this `PeerId`.
    pub fn into_bytes(self) -> Vec<u8> {
        self.multihash
    }

    /// Returns a raw bytes representation of this `PeerId`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.multihash
    }

    /// Returns a base-58 encoded string of this `PeerId`.
    pub fn to_base58(&self) -> String {
        bs58::encode(self.as_bytes()).into_string()
    }
}

impl<'a> From<&'a PublicKey> for PeerId {
    fn from(public_key: &'a PublicKey) -> PeerId {
        PeerId::from_public_key(public_key)
    }
}

impl From<PublicKey> for PeerId {
    fn from(public_key: PublicKey) -> PeerId {
        PeerId::from_public_key(&public_key)
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_base58().fmt(f)
    }
}

impl cmp::PartialOrd for PeerId {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl cmp::Ord for PeerId {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let lhs: &[u8] = self.as_ref();
        let rhs: &[u8] = other.as_ref();
        lhs.cmp(rhs)
    }
}

impl hash::Hash for PeerId {
    fn hash<H>(&self, state: &mut H)
    where
        H: hash::Hasher,
    {
        let digest = self.as_ref() as &[u8];
        hash::Hash::hash(digest, state);
    }
}

impl TryFrom<Vec<u8>> for PeerId {
    type Error = (); // TODO: proper error

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        PeerId::from_bytes(value).map_err(|_| ())
    }
}

impl PartialEq<PeerId> for PeerId {
    fn eq(&self, other: &PeerId) -> bool {
        let self_digest = self.as_ref() as &[u8];
        let other_digest = other.as_ref() as &[u8];
        self_digest == other_digest
    }
}

impl AsRef<[u8]> for PeerId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl FromStr for PeerId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(Bs58DecodeError)
            .map_err(ParseError::Bs58)?;
        PeerId::from_bytes(bytes).map_err(|(err, _)| ParseError::NotPeerId(err))
    }
}

/// Error when turning bytes into a [`PeerId`].
#[derive(Debug, derive_more::Display)]
pub enum FromBytesError {
    /// Failed to decode bytes into a multihash.
    DecodeError(multihash::FromBytesError),
    /// The algorithm used in the multihash isn't identity or SHA-256.
    InvalidMultihashAlgorithm,
    /// Multihash uses the identity algorithm, but the data isn't a valid public key.
    InvalidPublicKey(FromProtobufEncodingError),
}

/// Error when parsing a string to a [`PeerId`].
#[derive(Debug, derive_more::Display)]
pub enum ParseError {
    /// Error decoding the Base58 encoding.
    Bs58(Bs58DecodeError),
    /// Decoded bytes aren't a valid [`PeerId`].
    NotPeerId(FromBytesError),
}

/// Error when decoding Base58 encoding.
#[derive(Debug, derive_more::Display, derive_more::From)]
pub struct Bs58DecodeError(bs58::decode::Error);
