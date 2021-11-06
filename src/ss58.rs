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

//! SS58 is the Substrate-specific human-readable format for public and private keys.
//!
//! Substrate-based chains make frequent use of asynchronous cryptography. The identity of a user,
//! be it an account address, a validator, or else, consists of a public key (also sometimes known
//! as a verification key). A user can prove their identity by generating a signature using the
//! private key (also sometimes known as a signing key) corresponding to that public key.
//!
//! A private key and a public key consist of 32 bytes of data. This poses a problem when it comes
//! to end user experience. It is common for (human) users to have to manually copy a private or
//! public key (using a pencil or their keyboard), and making a mistake could have catastrophic
//! outcomes. It would be unwise to display keys and ask users to input keys as, for example,
//! hexadecimal, because it is easy to make a copying mistake.
//!
//! For this reason, Substrate-based chains make sure of a format named SS58. SS58 consists in two
//! things:
//!
//! - A human-readable format for public keys.
//! - A human-readable format for private keys.
//!
//! ## Public keys
//!
//! Examples:
//!
//! - `5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY`
//! - `12bzRJfh7arnnfPPUZHeJUaE62QLEwhK48QnH9LXeK2m1iZU`
//!
//! The format for public keys consists in:
//!
//! > base58(concat(prefix, 32-bytes-public-key, checksum))
//!
//! The prefix, also known as network identifier, also known as an address type is one or more
//! bytes identifying which blockchain network the address corresponds to. This is used for
//! UX-related purposes in order to prevent end users from using an address on a different
//! blockchain than the one the address was generated for.
//!
//! A registry of existing network identifiers can be found
//! [here](https://wiki.polkadot.network/docs/build-ss58-registry).
//!
//! The checksum is verified when the human-readable format is turned into a public key. Its
//! presence of a checksum guarantees that simple copying mistakes will be caught.
//!
//! ## Private keys
//!
//! Examples:
//!
//! - `cry opinion donkey dolphin tobacco version pilot sponsor canal page vote main`
//! - `canoe gravity deputy pottery glass cousin era cube double rather clutch crazy//Foo//Bar`
//! - `//Alice`
//!
//! The human-readable format for private keys is also called a secret string.
//!
//! The format for private keys consists in:
//!
//! - An optional [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) seed
//! phrase. If it is missing, then the [`DEFAULT_SEED_PHRASE`] is automatically used instead.
//!
//! - An optional derivation path. When using one `/`, this is called a *soft* derivation. When
//! using two `/`, this is called a *hard* derivation. Soft derivations are reversible and can
//! only be performed on public keys. Hard derivations are not reversible and can only be
//! performed on private keys.
//!
//! - An optional password. The private key format can contain a `///password` suffix, in which
//! case `password` will be used when decoding the BIP39 phrase. See the BIP39 specification. If
//! no password is provided, then the empty string (`""`) is used.
//!

use alloc::{string::String, vec::Vec};

// TODO: unclear what purpose soft derivations serve
// TODO: merge with keystore module?

// TODO: need decoding of public keys as well

/// Default seed phrase used when decoding a private key in case no seed is provided.
///
/// This seed phrase is publicly-known and is meant to be used to create keys for testing purposes
/// only.
pub const DEFAULT_SEED_PHRASE: &str =
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

/// Decodes a human-readable private key.
pub fn decode_private_key(key: &str) -> Result<[u8; 64], ParsePrivateKeyError> {
    let parsed = parse_private_key(key)?;

    // TODO: does building the sr25519 key lead to the same key as with ed25519?
    let mini_key = schnorrkel::MiniSecretKey::from_bytes(&parsed.seed).unwrap();

    let mut secret_key = mini_key
        .expand_to_keypair(schnorrkel::ExpansionMode::Ed25519)
        .secret
        .clone();

    for junction in parsed.path {
        secret_key = match junction {
            DeriveJunction::Soft(_) => todo!(), // TODO: return error
            DeriveJunction::Hard(cc) => secret_key
                .hard_derive_mini_secret_key(Some(schnorrkel::derive::ChainCode(cc)), b"")
                .0
                .expand(schnorrkel::ExpansionMode::Ed25519),
        };
    }

    Ok(secret_key.to_bytes())
}

/// Turns a human-readable private key into a seed and a derivation path.
pub fn parse_private_key(key: &str) -> Result<ParsedPrivateKey, ParsePrivateKeyError> {
    let parse_result: Result<_, nom::Err<nom::error::Error<&str>>> =
        nom::combinator::all_consuming(nom::sequence::tuple((
            nom::branch::alt((
                nom::combinator::map(
                    nom::combinator::map_opt(
                        nom::sequence::preceded(
                            nom::bytes::complete::tag("0x"),
                            nom::character::complete::hex_digit0,
                        ),
                        |hex| <[u8; 32]>::try_from(hex::decode(hex).ok()?).ok(),
                    ),
                    either::Left,
                ),
                nom::combinator::map(nom::bytes::complete::take_till(|c| c == '/'), either::Right),
            )),
            nom::multi::many0(nom::branch::alt((
                nom::combinator::map(
                    nom::sequence::preceded(
                        nom::bytes::complete::tag("/"),
                        nom::bytes::complete::take_till1(|c| c == '/'),
                    ),
                    |code| DeriveJunction::from_components(false, code),
                ),
                nom::combinator::map(
                    nom::sequence::preceded(
                        nom::bytes::complete::tag("//"),
                        nom::bytes::complete::take_till1(|c| c == '/'),
                    ),
                    |code| DeriveJunction::from_components(true, code),
                ),
            ))),
            nom::combinator::opt(nom::sequence::preceded(
                nom::bytes::complete::tag("///"),
                |s| Ok(("", s)),
            )),
        )))(key);

    match parse_result {
        Ok((_, (either::Left(seed), path, _password))) => {
            // TODO: what if there's a password? do we just ignore it?
            Ok(ParsedPrivateKey { seed, path })
        }
        Ok((_, (either::Right(phrase), path, password))) => {
            let phrase = if phrase.is_empty() {
                DEFAULT_SEED_PHRASE
            } else {
                phrase
            };

            Ok(ParsedPrivateKey {
                seed: bip39_to_seed(phrase, password.unwrap_or(""))
                    .map_err(ParsePrivateKeyError::Bip39Decode)?,
                path,
            })
        }
        Err(_) => Err(ParsePrivateKeyError::InvalidFormat),
    }
}

/// Successful outcome of [`parse_private_key`].
pub struct ParsedPrivateKey {
    /// Base seed phrase. Must be derived through [`ParsedPrivateKey::path`] to obtain the final
    /// result.
    pub seed: [u8; 32],

    /// Derivation path found in the secret phrase.
    pub path: Vec<DeriveJunction>,
}

/// Error in [`parse_private_key`].
#[derive(Debug, derive_more::Display)]
pub enum ParsePrivateKeyError {
    /// Couldn't parse the string in any meaningful way.
    InvalidFormat,
    /// Failed to decode the provided BIP39 seed phrase.
    Bip39Decode(Bip39ToSeedError),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DeriveJunction {
    Soft([u8; 32]),
    Hard([u8; 32]),
}

impl DeriveJunction {
    fn from_components(hard: bool, code: &str) -> DeriveJunction {
        // The algorithm here is the same as in Substrate, but way more readable.
        let mut chain_code = [0; 32];
        if let Ok(n) = str::parse::<u64>(code) {
            chain_code[..8].copy_from_slice(&n.to_le_bytes());
        } else {
            // For some reason, a SCALE-compact-encoded length prefix is added in front of
            // the path.
            let code = code.as_bytes();
            let code_len_prefix = crate::util::encode_scale_compact_usize(code.len());
            let code_len_prefix = code_len_prefix.as_ref();

            if code_len_prefix.len() + code.len() > 32 {
                let mut hash = blake2_rfc::blake2b::Blake2b::new(32);
                hash.update(code_len_prefix);
                hash.update(code);
                chain_code.copy_from_slice(hash.finalize().as_bytes());
            } else {
                chain_code[..code_len_prefix.len()].copy_from_slice(code_len_prefix);
                chain_code[code_len_prefix.len()..][..code.len()].copy_from_slice(code);
            }
        }

        if hard {
            DeriveJunction::Hard(chain_code)
        } else {
            DeriveJunction::Soft(chain_code)
        }
    }
}

/// Turns a BIP39 seed phrase into a 32 bytes cryptographic seed.
// TODO: zeroize the return value?
pub fn bip39_to_seed(phrase: &str, password: &str) -> Result<[u8; 32], Bip39ToSeedError> {
    let parsed = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase)
        .map_err(|err| Bip39ToSeedError::WrongMnemonic(Bip39DecodeError(err)))?;

    // Note that the `bip39` implementation of turning the mnemonic to a seed isn't conformant
    // to the BIP39 specification. Instead, we do it manually.

    // `to_entropy_array()` returns the entropy as an array where only the first `entropy_len`
    // bytes are meaningful. `entropy_len` depends on the number of words provided.
    let (entropy, entropy_len) = parsed.to_entropy_array();

    if entropy_len < 16 || entropy_len > 32 || entropy_len % 4 != 0 {
        return Err(Bip39ToSeedError::BadWordsCount);
    }

    let mut salt = String::with_capacity(8 + password.len());
    salt.push_str("mnemonic");
    salt.push_str(password);

    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(
        &entropy[..entropy_len],
        salt.as_bytes(),
        2048,
        &mut seed,
    );

    // TODO: salt.zeroize();

    // The seed is truncated to 32 bytes.
    Ok(<[u8; 32]>::try_from(&seed[..32]).unwrap())
}

/// Failed to decode BIP39 mnemonic phrase.
#[derive(Debug, derive_more::Display)]
pub enum Bip39ToSeedError {
    /// Invalid BIP39 mnemonic phrase.
    WrongMnemonic(Bip39DecodeError),
    /// Number of mnemonic phrase words isn't supported by the SS58 format.
    BadWordsCount,
}

/// Invalid BIP39 mnemonic phrase.
#[derive(Debug, derive_more::Display)]
pub struct Bip39DecodeError(bip39::Error);

#[cfg(test)]
mod tests {
    #[test]
    fn empty_matches() {
        assert_eq!(
            super::decode_private_key("").unwrap(),
            [
                5, 214, 85, 132, 99, 13, 22, 205, 74, 246, 208, 190, 193, 15, 52, 187, 80, 74, 93,
                203, 98, 219, 162, 18, 45, 73, 245, 166, 99, 118, 61, 10, 253, 25, 12, 206, 116,
                223, 53, 100, 50, 180, 16, 189, 100, 104, 35, 9, 214, 222, 219, 39, 199, 104, 69,
                218, 243, 136, 85, 124, 186, 195, 202, 52
            ]
        );
    }

    #[test]
    fn default_seed_is_correct() {
        assert_eq!(
            super::decode_private_key(
                "bottom drive obey lake curtain smoke basket hold race lonely fit walk"
            )
            .unwrap(),
            super::decode_private_key("").unwrap(),
        );

        assert_eq!(
            super::decode_private_key(
                "bottom drive obey lake curtain smoke basket hold race lonely fit walk//smoldot rules//125"
            )
            .unwrap(),
            super::decode_private_key("//smoldot rules//125").unwrap(),
        );
    }

    #[test]
    fn alice_matches() {
        assert_eq!(
            super::decode_private_key("//Alice").unwrap(),
            [
                51, 166, 243, 9, 63, 21, 138, 113, 9, 246, 121, 65, 11, 239, 26, 12, 84, 22, 129,
                69, 224, 206, 203, 77, 240, 6, 193, 194, 255, 251, 31, 9, 146, 90, 34, 93, 151,
                170, 0, 104, 45, 106, 89, 185, 91, 24, 120, 12, 16, 215, 3, 35, 54, 232, 143, 52,
                66, 180, 35, 97, 244, 166, 96, 17,
            ]
        );
    }

    #[test]
    fn hex_seed_matches() {
        assert_eq!(
            super::decode_private_key(
                "0x0000000000000000000000000000000000000000000000000000000000000000"
            )
            .unwrap(),
            [
                202, 168, 53, 120, 27, 21, 199, 112, 111, 101, 183, 31, 122, 88, 200, 7, 171, 54,
                15, 174, 214, 68, 15, 178, 62, 15, 76, 82, 233, 48, 222, 10, 10, 106, 133, 234,
                166, 66, 218, 200, 53, 66, 75, 93, 124, 141, 99, 124, 0, 64, 140, 122, 115, 218,
                103, 43, 127, 73, 133, 33, 66, 11, 109, 211
            ]
        );
    }

    #[test]
    fn multi_derivation_and_password() {
        assert_eq!(
            super::decode_private_key("strong isolate job basic auto frozen want garlic autumn height riot desert//foo//2//baz///my_password").unwrap(),
            [144, 209, 243, 24, 75, 220, 185, 255, 47, 39, 160, 1, 179, 74, 230, 178, 26, 1, 64, 139, 194, 14, 123, 204, 213, 105, 88, 17, 142, 68, 198, 10, 101, 57, 5, 124, 59, 208, 57, 242, 223, 43, 140, 191, 21, 56, 88, 79, 192, 241, 237, 195, 169, 103, 244, 249, 36, 90, 106, 10, 109, 40, 29, 73]
        );
    }
}
