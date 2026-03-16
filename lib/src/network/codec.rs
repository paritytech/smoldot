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

//! Encoding and decoding of messages of the protocols used by Polkadot/Substrate.

// TODO: expand docs

use alloc::{borrow::Cow, string::String};
use core::{fmt, iter};

// Implementation note: each protocol goes into a different sub-module whose content is
// re-exported here.

mod block_announces;
mod block_request;
mod grandpa;
mod grandpa_warp_sync;
mod identify;
mod kademlia;
mod state_request;
mod statement;
mod storage_call_proof;

pub use self::block_announces::*;
pub use self::block_request::*;
pub use self::grandpa::*;
pub use self::grandpa_warp_sync::*;
pub use self::identify::*;
pub use self::kademlia::*;
pub use self::state_request::*;
pub use self::statement::*;
pub use self::storage_call_proof::*;

/// Name of a protocol that is part of the Substrate/Polkadot networking.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum ProtocolName<'a> {
    Identify,
    Ping,
    BlockAnnounces {
        genesis_hash: [u8; 32],
        fork_id: Option<&'a str>,
    },
    Transactions {
        genesis_hash: [u8; 32],
        fork_id: Option<&'a str>,
    },
    Grandpa {
        genesis_hash: [u8; 32],
        fork_id: Option<&'a str>,
    },
    Sync {
        genesis_hash: [u8; 32],
        fork_id: Option<&'a str>,
    },
    Light {
        genesis_hash: [u8; 32],
        fork_id: Option<&'a str>,
    },
    Kad {
        genesis_hash: [u8; 32],
        fork_id: Option<&'a str>,
    },
    SyncWarp {
        genesis_hash: [u8; 32],
        fork_id: Option<&'a str>,
    },
    State {
        genesis_hash: [u8; 32],
        fork_id: Option<&'a str>,
    },
    Statement {
        genesis_hash: [u8; 32],
        fork_id: Option<&'a str>,
    },
}

impl<'a> fmt::Debug for ProtocolName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<'a> fmt::Display for ProtocolName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for chunk in encode_protocol_name(*self) {
            f.write_str(chunk.as_ref())?;
        }
        Ok(())
    }
}

/// Turns a [`ProtocolName`] into its string version. Returns a list of objects that, when
/// concatenated together, forms the string version of the [`ProtocolName`].
pub fn encode_protocol_name(protocol: ProtocolName) -> impl Iterator<Item = impl AsRef<str>> {
    let (genesis_hash, fork_id, base_protocol_name) = match protocol {
        ProtocolName::Identify => return either::Left(iter::once(Cow::Borrowed("/ipfs/id/1.0.0"))),
        ProtocolName::Ping => return either::Left(iter::once(Cow::Borrowed("/ipfs/ping/1.0.0"))),
        ProtocolName::BlockAnnounces {
            genesis_hash,
            fork_id,
        } => (genesis_hash, fork_id, "block-announces/1"),
        ProtocolName::Transactions {
            genesis_hash,
            fork_id,
        } => (genesis_hash, fork_id, "transactions/1"),
        ProtocolName::Grandpa {
            genesis_hash,
            fork_id,
        } => (genesis_hash, fork_id, "grandpa/1"),
        ProtocolName::Sync {
            genesis_hash,
            fork_id,
        } => (genesis_hash, fork_id, "sync/2"),
        ProtocolName::Light {
            genesis_hash,
            fork_id,
        } => (genesis_hash, fork_id, "light/2"),
        ProtocolName::Kad {
            genesis_hash,
            fork_id,
        } => (genesis_hash, fork_id, "kad"),
        ProtocolName::SyncWarp {
            genesis_hash,
            fork_id,
        } => (genesis_hash, fork_id, "sync/warp"),
        ProtocolName::State {
            genesis_hash,
            fork_id,
        } => (genesis_hash, fork_id, "state/2"),
        ProtocolName::Statement {
            genesis_hash,
            fork_id,
        } => (genesis_hash, fork_id, "statement/1"),
    };

    let genesis_hash = hex::encode(genesis_hash);

    if let Some(fork_id) = fork_id {
        either::Right(either::Right(
            [
                Cow::Borrowed("/"),
                Cow::Owned(genesis_hash),
                Cow::Borrowed("/"),
                Cow::Borrowed(fork_id),
                Cow::Borrowed("/"),
                Cow::Borrowed(base_protocol_name),
            ]
            .into_iter(),
        ))
    } else {
        either::Right(either::Left(
            [
                Cow::Borrowed("/"),
                Cow::Owned(genesis_hash),
                Cow::Borrowed("/"),
                Cow::Borrowed(base_protocol_name),
            ]
            .into_iter(),
        ))
    }
}

/// Turns a [`ProtocolName`] into a string.
pub fn encode_protocol_name_string(protocol: ProtocolName) -> String {
    encode_protocol_name(protocol).fold(String::with_capacity(128), |mut a, b| {
        a.push_str(b.as_ref());
        a
    })
}

/// Decodes a protocol name into its components.
///
/// Returns an error if the protocol name isn't recognized.
pub fn decode_protocol_name(name: &'_ str) -> Result<ProtocolName<'_>, ()> {
    nom::Parser::parse(
        &mut nom::combinator::all_consuming(nom::branch::alt((
            nom::combinator::map(nom::bytes::complete::tag("/ipfs/id/1.0.0"), |_| {
                ProtocolName::Identify
            }),
            nom::combinator::map(nom::bytes::complete::tag("/ipfs/ping/1.0.0"), |_| {
                ProtocolName::Ping
            }),
            nom::combinator::map(
                (
                    nom::bytes::complete::tag("/"),
                    genesis_hash,
                    nom::bytes::complete::tag("/"),
                    protocol_ty,
                ),
                |(_, genesis_hash, _, protocol_ty)| {
                    protocol_ty_to_real_protocol(protocol_ty, genesis_hash, None)
                },
            ),
            nom::combinator::map(
                (
                    nom::bytes::complete::tag("/"),
                    genesis_hash,
                    nom::bytes::complete::tag("/"),
                    nom::bytes::complete::take_until("/"),
                    nom::bytes::complete::tag("/"),
                    protocol_ty,
                ),
                |(_, genesis_hash, _, fork_id, _, protocol_ty)| {
                    protocol_ty_to_real_protocol(protocol_ty, genesis_hash, Some(fork_id))
                },
            ),
        ))),
        name,
    )
    .map(|(_, parse_result)| parse_result)
    .map_err(|_| ())
}

fn genesis_hash(name: &str) -> nom::IResult<&str, [u8; 32]> {
    nom::Parser::parse(
        &mut nom::combinator::map_opt(nom::bytes::complete::take(64u32), |hash| {
            hex::decode(hash)
                .ok()
                .map(|hash| <[u8; 32]>::try_from(hash).unwrap_or_else(|_| unreachable!()))
        }),
        name,
    )
}

enum ProtocolTy {
    BlockAnnounces,
    Transactions,
    Grandpa,
    Sync,
    Light,
    Kad,
    SyncWarp,
    State,
    Statement,
}

fn protocol_ty(name: &str) -> nom::IResult<&str, ProtocolTy> {
    nom::Parser::parse(
        &mut nom::branch::alt((
            nom::combinator::map(nom::bytes::complete::tag("block-announces/1"), |_| {
                ProtocolTy::BlockAnnounces
            }),
            nom::combinator::map(nom::bytes::complete::tag("transactions/1"), |_| {
                ProtocolTy::Transactions
            }),
            nom::combinator::map(nom::bytes::complete::tag("grandpa/1"), |_| {
                ProtocolTy::Grandpa
            }),
            nom::combinator::map(nom::bytes::complete::tag("sync/2"), |_| ProtocolTy::Sync),
            nom::combinator::map(nom::bytes::complete::tag("light/2"), |_| ProtocolTy::Light),
            nom::combinator::map(nom::bytes::complete::tag("kad"), |_| ProtocolTy::Kad),
            nom::combinator::map(nom::bytes::complete::tag("sync/warp"), |_| {
                ProtocolTy::SyncWarp
            }),
            nom::combinator::map(nom::bytes::complete::tag("state/2"), |_| ProtocolTy::State),
            nom::combinator::map(nom::bytes::complete::tag("statement/1"), |_| {
                ProtocolTy::Statement
            }),
        )),
        name,
    )
}

fn protocol_ty_to_real_protocol(
    ty: ProtocolTy,
    genesis_hash: [u8; 32],
    fork_id: Option<&'_ str>,
) -> ProtocolName<'_> {
    match ty {
        ProtocolTy::BlockAnnounces => ProtocolName::BlockAnnounces {
            genesis_hash,
            fork_id,
        },
        ProtocolTy::Transactions => ProtocolName::Transactions {
            genesis_hash,
            fork_id,
        },
        ProtocolTy::Grandpa => ProtocolName::Grandpa {
            genesis_hash,
            fork_id,
        },
        ProtocolTy::Sync => ProtocolName::Sync {
            genesis_hash,
            fork_id,
        },
        ProtocolTy::Light => ProtocolName::Light {
            genesis_hash,
            fork_id,
        },
        ProtocolTy::Kad => ProtocolName::Kad {
            genesis_hash,
            fork_id,
        },
        ProtocolTy::SyncWarp => ProtocolName::SyncWarp {
            genesis_hash,
            fork_id,
        },
        ProtocolTy::State => ProtocolName::State {
            genesis_hash,
            fork_id,
        },
        ProtocolTy::Statement => ProtocolName::Statement {
            genesis_hash,
            fork_id,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_to_string(protocol: ProtocolName) -> String {
        encode_protocol_name(protocol)
            .map(|s| s.as_ref().to_owned())
            .collect::<Vec<_>>()
            .join("")
    }

    #[test]
    fn statement_protocol_name_roundtrip() {
        let genesis_hash = [0xab; 32];
        let protocol = ProtocolName::Statement {
            genesis_hash,
            fork_id: None,
        };

        let encoded = encode_to_string(protocol);
        let decoded = decode_protocol_name(&encoded).unwrap();

        assert!(matches!(
            decoded,
            ProtocolName::Statement { genesis_hash: gh, fork_id: None }
            if gh == genesis_hash
        ));
    }

    #[test]
    fn statement_protocol_name_roundtrip_with_fork() {
        let genesis_hash = [0xab; 32];
        let protocol = ProtocolName::Statement {
            genesis_hash,
            fork_id: Some("polkadot"),
        };

        let encoded = encode_to_string(protocol);
        let decoded = decode_protocol_name(&encoded).unwrap();

        assert!(matches!(
            decoded,
            ProtocolName::Statement { genesis_hash: gh, fork_id: Some("polkadot") }
            if gh == genesis_hash
        ));
    }
}
