// Smoldot
// Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
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

//! CID is a data type for referencing content in IPFS, including Bitswap protocol.
//!
//! See <https://github.com/multiformats/cid/blob/master/README.md>.
//!
//! For simplicity, we support only CIDv1 version used in Substrate Bitswap server implementation
//! (without support for CIDv0).
//!
//! # Binary representation of CIDv1
//!
//! cidv1 ::= <leb128(cid_version)><leb128(codec)><leb128(mh_type)><leb128(mh_len)><hash_digest>
//!
//! Subparts of the CIDv1 binary representation we are interested in are _CID prefix_ & _mulihash_
//! correspondingly:
//!
//! cid_prefix ::= <leb128(cid_version)><leb128(codec)><leb128(mh_type)><leb128(mh_len)>
//! multihash ::= <leb128(mh_type)><leb128(mh_len)><hash_digest>
//!
//! Here `leb128()` means LEB128 varint encoded values.
//!
//! In Bitswap requests, complete `cidv1` of requested data block is sent, while the Bitswap
//! responses only include the `cid_prefix`. This means we should manually compute the hash digest
//! identified by `mh_type` in order to recover the complete CID and match the recived data block to
//! the request (request and response messages are sent asynchronously in Bitswap through
//! independent substreams).

use alloc::vec::Vec;
use base32::Alphabet;
use blake2_rfc::blake2b::blake2b;
use core::{fmt, str::FromStr};
use sha2::{Digest as _, Sha256};

/// CID: IPFS Content Identifier.
///
/// We don't need to access individual fields of CID so keep it in the binary form, yet check that
/// it is valid upon construction.
//
// TODO: binary representation is unambiguous, because unsigned varint is unambiguous, but can
//       we receive non-canonical leb128 as input from RPC? Currently such input won't work because
//       it will fail to compare equal with CID prefix + digest returned by remote peers over
//       Bitswap protocol.
//
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cid(Vec<u8>);

impl Cid {
    /// Create new CID from the binary representation, checking the representation is valid.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ParseError> {
        let _ = decode_cid(&bytes)?;

        Ok(Cid(bytes))
    }

    /// Extract CID prefix.
    pub fn prefix(&self) -> CidPrefix {
        let decoded = decode_cid(&self.0).expect("Cid is always valid; qed");
        let prefix_len = self.0.len() - decoded.digest.len();

        CidPrefix(self.0[..prefix_len].to_vec())
    }
}

impl FromStr for Cid {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let bytes = multibase_base32_decode(s)?;

        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for Cid {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&multibase_base32_encode(&self.0))
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// CID prefix: everything in a CID except the hash digest.
///
/// Binary representation: `<leb128(cid_version)><leb128(codec)><leb128(mh_type)><leb128(mh_len)>`
///
/// In Bitswap block responses, only the CID prefix is sent alongside the data block. The receiver
/// must compute the hash digest to recover the full CID and match the response to a request.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CidPrefix(Vec<u8>);

impl CidPrefix {
    /// Create new CID prefix from the binary representation, checking the representation is valid.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ParseError> {
        let _ = decode_cid_prefix(&bytes)?;

        Ok(CidPrefix(bytes))
    }

    /// Return the multihash algorithm type used in this prefix.
    pub fn multihash_type(&self) -> MultihashType {
        // Prefix was validated at construction time, so this cannot fail.
        decode_cid_prefix(&self.0)
            .expect("CidPrefix is always valid; qed")
            .mh_type
    }

    /// Build full CID from this prefix and hash digest.
    pub fn with_digest(self, digest: &[u8; 32]) -> Cid {
        // We don't need to check the `mh_len` is correct because it was checked upon construction.
        let mut bytes = self.0;
        bytes.extend_from_slice(digest);

        Cid(bytes)
    }

    /// Build full CID from thhi prefix, calculating the missing digest.
    pub fn with_digest_of(self, bytes: &[u8]) -> Cid {
        let digest = self.multihash_type().digest(bytes);

        self.with_digest(&digest)
    }
}

/// Multihash algorithm types supported.
///
/// See <https://github.com/multiformats/multicodec/blob/master/table.csv>.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultihashType {
    /// SHA-256 (code 0x12).
    Sha2_256 = 0x12,
    /// BLAKE2b-256 (code 0xb220).
    Blake2b256 = 0xb220,
}

impl MultihashType {
    pub fn digest(&self, bytes: &[u8]) -> [u8; 32] {
        match self {
            MultihashType::Sha2_256 => Sha256::digest(bytes).into(),
            MultihashType::Blake2b256 => blake2b(32, &[], bytes)
                .as_bytes()
                .to_owned()
                .try_into()
                .expect("correct size passed to constructor; qed"),
        }
    }

    fn from_code(code: u64) -> Option<Self> {
        match code {
            0x12 => Some(MultihashType::Sha2_256),
            0xb220 => Some(MultihashType::Blake2b256),
            _ => None,
        }
    }
}

/// Error when parsing string/binary [`Cid`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum ParseError {
    /// The CID binary representation is invalid.
    DecodeError,
    /// Unsupported multibase codec. Only base32 is supported.
    UnsupportedMultibase,
    /// Invalid characters in base32 string.
    InvalidMultibase,
    /// Unsupported CID version. Only CIDv1 is supported.
    UnsupportedCidVersion,
    /// Unsupported multihash code. Only sha2-256 & blake2b-256 are supported.
    UnsupportedMultihash,
    /// Invalid multihash digest size of {_0} bytes. Must be 32 bytes for sha2-256 / blake2b-256.
    InvalidDigestSize(#[error(not(source))] usize),
}

/// Decode multibase string encoded with base32 codec. Note that the string must start from
/// multibase codec identifier for base32, which is character 'b'.
///
/// Base32 encoding itself is specified in
/// [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648.html).
fn multibase_base32_decode(string: &str) -> Result<Vec<u8>, ParseError> {
    let Some(base32) = string.strip_prefix('b') else {
        return Err(ParseError::UnsupportedMultibase);
    };

    base32::decode(Alphabet::Rfc4648Lower { padding: false }, base32)
        .ok_or(ParseError::InvalidMultibase)
}

/// Encode data as multibase with base32 codec. Note that the output will start from base32 codec
/// identifier, which is character 'b'.
///
/// Base32 encoding itself is specified in
/// [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648.html).
fn multibase_base32_encode(data: &[u8]) -> String {
    format!(
        "b{}",
        base32::encode(Alphabet::Rfc4648Lower { padding: false }, data)
    )
}

#[derive(Debug)]
#[allow(unused)]
struct DecodedCid<'a> {
    codec: u64,
    mh_type: MultihashType,
    digest: &'a [u8; 32],
}

fn decode_cid<'a>(bytes: &'a [u8]) -> Result<DecodedCid<'a>, ParseError> {
    match nom::Parser::parse(
        &mut nom::combinator::all_consuming(parse_cid::<nom::error::Error<&[u8]>>),
        bytes,
    ) {
        Ok((_rest, (version, codec, mh_type, digest))) => {
            debug_assert!(_rest.is_empty());

            if version != 1 {
                return Err(ParseError::UnsupportedCidVersion);
            }

            let mh_type =
                MultihashType::from_code(mh_type).ok_or(ParseError::UnsupportedMultihash)?;

            let digest: &[u8; 32] = digest
                .try_into()
                .map_err(|_| ParseError::InvalidDigestSize(digest.len()))?;

            Ok(DecodedCid {
                codec,
                mh_type,
                digest,
            })
        }
        Err(_) => Err(ParseError::DecodeError),
    }
}

#[derive(Debug)]
#[allow(unused)]
struct DecodedCidPrefix {
    codec: u64,
    mh_type: MultihashType,
    // We only support 32-byte hash digests.
}

fn decode_cid_prefix(bytes: &[u8]) -> Result<DecodedCidPrefix, ParseError> {
    match nom::Parser::parse(
        &mut nom::combinator::all_consuming(parse_cid_prefix::<nom::error::Error<&[u8]>>),
        bytes,
    ) {
        Ok((_rest, (version, codec, mh_type, mh_len))) => {
            debug_assert!(_rest.is_empty());

            if version != 1 {
                return Err(ParseError::UnsupportedCidVersion);
            }

            let mh_type =
                MultihashType::from_code(mh_type).ok_or(ParseError::UnsupportedMultihash)?;

            if mh_len != 32 {
                return Err(ParseError::InvalidDigestSize(mh_len));
            }

            Ok(DecodedCidPrefix { codec, mh_type })
        }
        Err(_) => Err(ParseError::DecodeError),
    }
}

fn parse_cid<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], (u64, u64, u64, &'a [u8]), E> {
    nom::Parser::parse(
        &mut (
            crate::util::leb128::nom_leb128_u64,
            crate::util::leb128::nom_leb128_u64,
            crate::util::leb128::nom_leb128_u64,
            nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
        ),
        bytes,
    )
}

fn parse_cid_prefix<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], (u64, u64, u64, usize), E> {
    nom::Parser::parse(
        &mut (
            crate::util::leb128::nom_leb128_u64,
            crate::util::leb128::nom_leb128_u64,
            crate::util::leb128::nom_leb128_u64,
            crate::util::leb128::nom_leb128_usize,
        ),
        bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build valid CIDv1 prefix: version=1, codec=0x55 (raw), sha2-256.
    fn sample_prefix_bytes() -> Vec<u8> {
        vec![0x01, 0x55, 0x12, 0x20]
    }

    /// Full CIDv1 built from `sample_prefix_bytes` with zero hash digest.
    fn sample_cid_bytes() -> Vec<u8> {
        let mut bytes = sample_prefix_bytes();
        bytes.extend_from_slice(&[0u8; 32]);
        bytes
    }

    #[test]
    fn cid_from_bytes_valid() {
        assert!(Cid::from_bytes(sample_cid_bytes()).is_ok());
    }

    #[test]
    fn cid_from_bytes_rejects_prefix_only() {
        // A prefix without the digest is not a valid CID.
        assert!(Cid::from_bytes(sample_prefix_bytes()).is_err());
    }

    #[test]
    fn cid_from_bytes_rejects_empty() {
        assert!(Cid::from_bytes(vec![]).is_err());
    }

    #[test]
    fn cid_from_bytes_rejects_truncated() {
        // Only version and codec, missing mh_type, mh_len, and digest.
        assert!(Cid::from_bytes(vec![0x01, 0x55]).is_err());
    }

    #[test]
    fn cid_from_bytes_rejects_unsupported_version() {
        let mut bytes = vec![0x02, 0x55, 0x12, 0x20];
        bytes.extend_from_slice(&[0u8; 32]);
        assert!(Cid::from_bytes(bytes).is_err());
    }

    #[test]
    fn cid_from_bytes_rejects_unsupported_multihash() {
        // mh_type = 0x00, which is not sha2-256 or blake2b-256.
        let mut bytes = vec![0x01, 0x55, 0x00, 0x20];
        bytes.extend_from_slice(&[0u8; 32]);
        assert!(Cid::from_bytes(bytes).is_err());
    }

    #[test]
    fn cid_from_bytes_rejects_wrong_digest_size() {
        // mh_len = 16 with only 16 bytes of digest.
        let mut bytes = vec![0x01, 0x55, 0x12, 0x10];
        bytes.extend_from_slice(&[0u8; 16]);
        assert!(Cid::from_bytes(bytes).is_err());
    }

    #[test]
    fn cid_from_bytes_rejects_trailing_bytes() {
        // Valid CID followed by an extra byte.
        let mut bytes = sample_cid_bytes();
        bytes.push(0xff);
        assert!(Cid::from_bytes(bytes).is_err());
    }

    #[test]
    fn cid_prefix_from_bytes_valid() {
        let prefix = CidPrefix::from_bytes(sample_prefix_bytes()).unwrap();
        assert_eq!(prefix.multihash_type(), MultihashType::Sha2_256);
    }

    #[test]
    fn cid_prefix_from_bytes_rejects_full_cid() {
        // A full CID has trailing digest bytes which should make prefix parsing fail.
        let result = CidPrefix::from_bytes(sample_cid_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn cid_prefix_from_bytes_rejects_empty() {
        assert!(CidPrefix::from_bytes(vec![]).is_err());
    }

    #[test]
    fn cid_prefix_from_bytes_rejects_truncated() {
        // Only version and codec, missing mh_type and mh_len.
        assert!(CidPrefix::from_bytes(vec![0x01, 0x55]).is_err());
    }

    #[test]
    fn cid_prefix_from_bytes_rejects_unsupported_version() {
        // Version 2, which is not supported.
        assert!(CidPrefix::from_bytes(vec![0x02, 0x55, 0x12, 0x20]).is_err());
    }

    #[test]
    fn cid_prefix_from_bytes_rejects_unsupported_multihash() {
        // mh_type = 0x00, which is not sha2-256 or blake2b-256.
        assert!(CidPrefix::from_bytes(vec![0x01, 0x55, 0x00, 0x20]).is_err());
    }

    #[test]
    fn cid_prefix_from_bytes_rejects_wrong_digest_size() {
        // mh_len = 16 instead of 32.
        assert!(CidPrefix::from_bytes(vec![0x01, 0x55, 0x12, 0x10]).is_err());
    }

    #[test]
    fn cid_prefix_from_cid_roundtrip() {
        let cid = Cid::from_bytes(sample_cid_bytes()).unwrap();
        let prefix = cid.prefix();
        assert_eq!(prefix.0, sample_prefix_bytes());
        assert_eq!(prefix.multihash_type(), MultihashType::Sha2_256);
        assert_eq!(prefix.with_digest(&[0; 32]), cid);
    }

    #[test]
    fn cid_prefix_blake2b256() {
        // CIDv1 with blake2b-256: version=1, codec=0x55, mh_type=0xb220, mh_len=32.
        // 0xb220 in LEB128 is [0xa0, 0xe4, 0x02].
        let prefix_bytes: Vec<u8> = vec![0x01, 0x55, 0xa0, 0xe4, 0x02, 0x20];
        let prefix = CidPrefix::from_bytes(prefix_bytes).unwrap();
        assert_eq!(prefix.multihash_type(), MultihashType::Blake2b256);
    }

    #[test]
    fn cid_prefix_from_cid_blake2b256() {
        // Build a full CID with blake2b-256.
        let mut cid_bytes: Vec<u8> = vec![0x01, 0x55, 0xa0, 0xe4, 0x02, 0x20];
        cid_bytes.extend_from_slice(&[0u8; 32]);
        let cid = Cid::from_bytes(cid_bytes).unwrap();
        let prefix = cid.prefix();
        assert_eq!(prefix.multihash_type(), MultihashType::Blake2b256);
        assert_eq!(prefix.0, vec![0x01, 0x55, 0xa0, 0xe4, 0x02, 0x20]);
    }
}
