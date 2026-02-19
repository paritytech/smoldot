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

use base32::Alphabet;
use core::{fmt, str::FromStr};

/// IPFS Content Identifier.
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
}

impl FromStr for Cid {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let bytes = multibase_base32_decode(s)?;

        Self::from_bytes(bytes)
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
