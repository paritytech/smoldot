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

use alloc::{string::String, vec::Vec};
use core::fmt;

/// Decoded version of an SS58 address.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Decoded<P> {
    /// Identifier indicating which chain is concerned.
    ///
    /// The mapping between chains and this prefix can be found in this central registry:
    /// <https://github.com/paritytech/ss58-registry/blob/main/ss58-registry.json>.
    pub chain_prefix: ChainPrefix,

    /// Public key of the account.
    pub public_key: P,
}

/// Identifier indicating which chain is concerned.
///
/// The mapping between chains and this prefix can be found in this central registry:
/// <https://github.com/paritytech/ss58-registry/blob/main/ss58-registry.json>.
///
/// This prefix is a 14 bits unsigned integer.
//
// Implementation note: the `u16` is guaranteed to be only up to 14 bits long. The upper two bits
// are always 0.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ChainPrefix(u16);

impl fmt::Debug for ChainPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl TryFrom<u16> for ChainPrefix {
    type Error = PrefixTooLargeError;

    fn try_from(prefix: u16) -> Result<Self, Self::Error> {
        if (prefix >> 14) == 0 {
            Ok(ChainPrefix(prefix))
        } else {
            Err(PrefixTooLargeError())
        }
    }
}

/// Integer is too large to be a valid prefix
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub struct PrefixTooLargeError();

impl From<u8> for ChainPrefix {
    fn from(prefix: u8) -> ChainPrefix {
        ChainPrefix(u16::from(prefix))
    }
}

impl From<ChainPrefix> for u16 {
    fn from(prefix: ChainPrefix) -> u16 {
        prefix.0
    }
}

/// Turns a decoded SS58 address into a string.
pub fn encode(decoded: Decoded<impl AsRef<[u8]>>) -> String {
    let prefix = decoded.chain_prefix.0;
    let public_key = decoded.public_key.as_ref();

    let mut bytes = Vec::with_capacity(2 + public_key.len() + 2);

    if prefix < 64 {
        bytes.push(prefix as u8);
    } else {
        // This encoding is plain weird.
        bytes.push(((prefix & 0b0000_0000_1111_1100) as u8) >> 2 | 0b01000000);
        bytes.push(((prefix >> 8) as u8) | ((prefix & 0b0000_0000_0000_0011) as u8) << 6);
    }

    bytes.extend_from_slice(public_key);

    let checksum = calculate_checksum(&bytes);
    bytes.extend_from_slice(&checksum);

    bs58::encode(&bytes).into_string()
}

/// Decodes an SS58 address from a string.
pub fn decode(encoded: &str) -> Result<Decoded<impl AsRef<[u8]>>, DecodeError> {
    let mut bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|err| DecodeError::InvalidBs58(Bs58DecodeError(err)))?;

    if bytes.len() < 4 {
        return Err(DecodeError::TooShort);
    }

    // Verify the checksum.
    let expected_checksum = calculate_checksum(&bytes[..bytes.len() - 2]);
    if expected_checksum[..] != bytes[bytes.len() - 2..] {
        return Err(DecodeError::InvalidChecksum);
    }
    bytes.truncate(bytes.len() - 2);

    // Grab and remove the prefix.
    let (prefix_len, chain_prefix) = if bytes[0] < 64 {
        (1, ChainPrefix(u16::from(bytes[0])))
    } else if bytes[0] < 128 {
        let prefix = u16::from_be_bytes([bytes[1] & 0b00111111, (bytes[0] << 2) | (bytes[1] >> 6)]);
        (2, ChainPrefix(prefix))
    } else {
        return Err(DecodeError::InvalidPrefix);
    };

    // Rather than remove the prefix from the beginning of `bytes`, we adjust the `AsRef`
    // implementation to skip the prefix.
    let public_key = {
        struct Adjust(Vec<u8>, usize);
        impl AsRef<[u8]> for Adjust {
            fn as_ref(&self) -> &[u8] {
                &self.0[self.1..]
            }
        }
        Adjust(bytes, prefix_len)
    };

    Ok(Decoded {
        chain_prefix,
        public_key,
    })
}

/// Error while decoding an SS58 address.
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub enum DecodeError {
    /// SS58 is too short to possibly be valid.
    TooShort,
    /// Invalid SS58 prefix encoding.
    InvalidPrefix,
    /// Invalid Base58 format.
    #[display("{_0}")]
    InvalidBs58(Bs58DecodeError),
    /// Calculated checksum doesn't match the one provided.
    InvalidChecksum,
}

/// Error when decoding Base58 encoding.
#[derive(Debug, Clone, derive_more::Display, derive_more::Error, derive_more::From)]
// TODO: bs58 doesn't implement the Error trait; remove not(source) at some point
pub struct Bs58DecodeError(#[error(not(source))] bs58::decode::Error);

fn calculate_checksum(data: &[u8]) -> [u8; 2] {
    let mut hasher = blake2_rfc::blake2b::Blake2b::new(64);
    hasher.update(b"SS58PRE");
    hasher.update(data);

    let hash = hasher.finalize();
    *<&[u8; 2]>::try_from(&hash.as_bytes()[..2]).unwrap_or_else(|_| unreachable!())
}

#[cfg(test)]
mod tests {
    #[test]
    fn alice_polkadot() {
        let encoded = "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5";

        let decoded = super::decode(encoded).unwrap();
        assert_eq!(u16::from(decoded.chain_prefix), 0);
        assert_eq!(
            decoded.public_key.as_ref(),
            &[
                212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44,
                133, 88, 133, 76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125
            ][..]
        );

        assert_eq!(super::encode(decoded), encoded);
    }

    #[test]
    fn sora_default_seed_phrase() {
        let encoded = "cnT6GtrVo7AYsRc2LgfTgW8Gu4gpZpxhaaKMm7zH8Ry14pJ8b";

        let decoded = super::decode(encoded).unwrap();
        assert_eq!(u16::from(decoded.chain_prefix), 69);
        assert_eq!(
            decoded.public_key.as_ref(),
            &[
                70, 235, 221, 239, 140, 217, 187, 22, 125, 195, 8, 120, 215, 17, 59, 126, 22, 142,
                111, 6, 70, 190, 255, 215, 125, 105, 211, 155, 173, 118, 180, 122
            ][..]
        );

        assert_eq!(super::encode(decoded), encoded);
    }
}
