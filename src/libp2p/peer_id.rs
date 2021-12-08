// Copyright 2019-2021 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use alloc::{string::String, vec::Vec};
use core::{cmp, fmt, hash, str::FromStr};
use prost::Message as _;

mod keys_proto {
    include!(concat!(env!("OUT_DIR"), "/keys_proto.rs"));
}

/// Public key of a node's identity.
///
/// Libp2p specifies multiple different possible algorithms, but only ed25519 support is
/// mandatory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// An ed25519 public key.
    Ed25519([u8; 32]),
}

impl PublicKey {
    /// Encode the public key into a protobuf structure for storage or
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

    /// Decode a public key from a protobuf structure, e.g. read from storage
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
    /// Error decoding the protobuf message.
    ProtobufDecodeError,
    /// Public key algorithm unknown.
    UnknownAlgorithm,
    /// Ed25519 key doesn't have a correct length.
    BadEd25519Key,
    /// Algorithms other than ed25519 aren't supported.
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
    multihash: Vec<u8>,
}

impl PeerId {
    /// Builds the [`PeerId`] corresponding to a public key.
    pub fn from_public_key(key: &PublicKey) -> PeerId {
        let key_enc = key.to_protobuf_encoding();

        let out = if key_enc.len() <= MAX_INLINE_KEY_LENGTH {
            let mut out = Vec::with_capacity(key_enc.len() + 8);
            out.push(0x0);
            out.extend_from_slice(crate::util::encode_scale_compact_usize(key_enc.len()).as_ref());
            out.extend_from_slice(&key_enc);
            out
        } else {
            let mut out = Vec::with_capacity(34);
            out.push(0x12);
            out.push(0x32);
            out.extend_from_slice(&key_enc);
            out
        };

        PeerId { multihash: out }
    }

    /// Checks whether `data` is a valid [`PeerId`].
    ///
    /// In case of error, returns the bytes passed as parameter in addition to the error.
    pub fn from_bytes(data: Vec<u8>) -> Result<PeerId, (FromBytesError, Vec<u8>)> {
        let result =
            match nom::combinator::all_consuming(multihash::<nom::error::Error<&[u8]>>)(&data) {
                Ok((_, Some(public_key))) => {
                    if let Err(err) = PublicKey::from_protobuf_encoding(public_key) {
                        Err(FromBytesError::InvalidPublicKey(err))
                    } else {
                        Ok(())
                    }
                }
                Ok((_, None)) => Ok(()),
                Err(_) => Err(FromBytesError::DecodeError),
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

    /// Checks whether the public key passed as parameter matches the public key of this `PeerId`.
    ///
    /// Returns `None` if this `PeerId`s hash algorithm is not supported when encoding the
    /// given public key, otherwise `Some` boolean as the result of an equality check.
    pub fn is_public_key(&self, _public_key: &PublicKey) -> Option<bool> {
        todo!() // TODO: /!\

        /*match nom::combinator::all_consuming(multihash::<nom::error::Error<&[u8]>>)(&self.multihash) {
            Ok((_, Some(self_public_key))) => {
                self_public_key == encoded
            }
            Ok((_, None)) => None,  // TODO: fixme
            Err(_) => unreachable!(),
        }*/
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
        f.debug_tuple("PeerId").field(&self.to_base58()).finish()
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
        hash::Hash::hash(digest, state)
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
        PeerId::from_bytes(bytes).map_err(|_| ParseError::Multihash)
    }
}

/// Error when turning bytes into a [`PeerId`].
#[derive(Debug, derive_more::Display)]
pub enum FromBytesError {
    /// Failed to decode bytes into a multihash.
    DecodeError,
    /// Multihash uses the identity algorithm, but the data isn't a valid public key.
    InvalidPublicKey(FromProtobufEncodingError),
}

/// Error when parsing a string to a [`PeerId`].
#[derive(Debug, derive_more::Display)]
pub enum ParseError {
    /// Error decoding the base58 encoding.
    Bs58(Bs58DecodeError),
    /// Decoded bytes aren't a valid [`PeerId`].
    Multihash, // TODO: proper error
}

/// Error when decoding base58 encoding.
#[derive(Debug, derive_more::Display, derive_more::From)]
pub struct Bs58DecodeError(bs58::decode::Error);

/// Parses a multihash. Returns the protobuf-encoded public key, if available.
// TODO: fix visibility of this
pub(super) fn multihash<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], Option<&'a [u8]>, E> {
    nom::branch::alt((
        nom::combinator::map(
            nom::sequence::preceded(
                nom::bytes::complete::tag([0x0]),
                nom::combinator::verify(
                    nom::multi::length_data(crate::util::nom_scale_compact_usize),
                    |bytes: &[u8]| bytes.len() > MAX_INLINE_KEY_LENGTH,
                ),
            ),
            Some,
        ),
        nom::combinator::map(
            nom::sequence::preceded(
                nom::bytes::complete::tag([0x12, 0x32]),
                nom::bytes::complete::take(32_u32),
            ),
            |_| None,
        ),
    ))(bytes)
}
