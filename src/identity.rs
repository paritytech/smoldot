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
//! For this reason, Substrate-defines two human-readable formats:
//!
//! - A human-readable format for public keys.
//! - A human-readable format for private keys, named SS58.
//!
//! These formats unfortunately do not mention which asynchronous cryptographic algorithm (e.g.
//! ed25519 or sr25519) is used for the public and private keys. This must be deduced from the
//! context.
//!
//! ## Public keys (SS58)
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
//! phrase. If it is missing, then the [`seed_phrase::DEFAULT_SEED_PHRASE`] is automatically used
//! instead.
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

pub mod keystore;
pub mod seed_phrase;

// TODO: implement ss58
