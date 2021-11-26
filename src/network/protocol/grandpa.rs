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

// TODO: document all this

use crate::finality::{grandpa::commit::decode, justification::decode::PrecommitRef};

use alloc::vec::Vec;
use core::iter;
use nom::Finish as _;

pub use crate::finality::grandpa::commit::decode::{CommitMessageRef, UnsignedPrecommitRef};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrandpaNotificationRef<'a> {
    Vote(VoteMessageRef<'a>),
    Commit(CommitMessageRef<'a>), // TODO: consider weaker type, since in different module
    Neighbor(NeighborPacket),
    CatchUpRequest(CatchUpRequest),
    CatchUp(CatchUpRef<'a>),
}

impl<'a> GrandpaNotificationRef<'a> {
    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(&self) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone {
        match self {
            GrandpaNotificationRef::Neighbor(n) => {
                iter::once(either::Left(&[2u8])).chain(n.scale_encoding().map(either::Right))
            }
            _ => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteMessageRef<'a> {
    pub round_number: u64,
    pub set_id: u64,
    pub message: MessageRef<'a>,
    pub signature: &'a [u8; 64],
    pub authority_public_key: &'a [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageRef<'a> {
    Prevote(UnsignedPrevoteRef<'a>),
    Precommit(UnsignedPrecommitRef<'a>),
    PrimaryPropose(PrimaryProposeRef<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedPrevoteRef<'a> {
    pub target_hash: &'a [u8; 32],
    pub target_number: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimaryProposeRef<'a> {
    pub target_hash: &'a [u8; 32],
    pub target_number: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborPacket {
    pub round_number: u64,
    pub set_id: u64,
    pub commit_finalized_height: u32,
}

impl NeighborPacket {
    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(&self) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone {
        iter::once(either::Right(either::Left([1u8])))
            .chain(iter::once(either::Left(self.round_number.to_le_bytes())))
            .chain(iter::once(either::Left(self.set_id.to_le_bytes())))
            .chain(iter::once(either::Right(either::Right(
                self.commit_finalized_height.to_le_bytes(),
            ))))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchUpRequest {
    pub round_number: u64,
    pub set_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchUpRef<'a> {
    pub set_id: u64,
    pub round_number: u64,
    pub prevotes: Vec<PrevoteRef<'a>>,
    pub precommits: Vec<PrecommitRef<'a>>,
    pub base_hash: &'a [u8; 32],
    pub base_number: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrevoteRef<'a> {
    /// Hash of the block concerned by the pre-vote.
    pub target_hash: &'a [u8; 32],
    /// Height of the block concerned by the pre-vote.
    pub target_number: u32,

    /// Ed25519 signature made with [`PrevoteRef::authority_public_key`].
    pub signature: &'a [u8; 64],

    /// Authority that signed the pre-vote. Must be part of the authority set for the
    /// justification to be valid.
    pub authority_public_key: &'a [u8; 32],
}

/// Attempt to decode the given SCALE-encoded Grandpa notification.
pub fn decode_grandpa_notification(
    scale_encoded: &[u8],
) -> Result<GrandpaNotificationRef, DecodeGrandpaNotificationError> {
    match nom::combinator::all_consuming(grandpa_notification)(scale_encoded).finish() {
        Ok((_, notif)) => Ok(notif),
        Err(err) => Err(DecodeGrandpaNotificationError(err.code)),
    }
}

/// Error potentially returned by [`decode_grandpa_notification`].
#[derive(Debug, derive_more::Display)]
#[display(fmt = "Failed to decode a Grandpa notification")]
pub struct DecodeGrandpaNotificationError(nom::error::ErrorKind);

// Nom combinators below.

fn grandpa_notification(bytes: &[u8]) -> nom::IResult<&[u8], GrandpaNotificationRef> {
    nom::error::context(
        "grandpa_notification",
        nom::branch::alt((
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::complete::tag(&[0]), vote_message),
                GrandpaNotificationRef::Vote,
            ),
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::complete::tag(&[1]), |s| {
                    decode::decode_partial_grandpa_commit(s)
                        .map(|(a, b)| (b, a))
                        .map_err(|_| {
                            nom::Err::Failure(nom::error::make_error(
                                s,
                                nom::error::ErrorKind::Verify,
                            ))
                        })
                }),
                GrandpaNotificationRef::Commit,
            ),
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::complete::tag(&[2]), neighbor_packet),
                GrandpaNotificationRef::Neighbor,
            ),
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::complete::tag(&[3]), catch_up_request),
                GrandpaNotificationRef::CatchUpRequest,
            ),
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::complete::tag(&[4]), catch_up),
                GrandpaNotificationRef::CatchUp,
            ),
        )),
    )(bytes)
}

fn vote_message(bytes: &[u8]) -> nom::IResult<&[u8], VoteMessageRef> {
    nom::error::context(
        "vote_message",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::number::complete::le_u64,
                nom::number::complete::le_u64,
                message,
                nom::bytes::complete::take(64u32),
                nom::bytes::complete::take(32u32),
            )),
            |(round_number, set_id, message, signature, authority_public_key)| VoteMessageRef {
                round_number,
                set_id,
                message,
                signature: <&[u8; 64]>::try_from(signature).unwrap(),
                authority_public_key: <&[u8; 32]>::try_from(authority_public_key).unwrap(),
            },
        ),
    )(bytes)
}

fn message(bytes: &[u8]) -> nom::IResult<&[u8], MessageRef> {
    nom::error::context(
        "message",
        nom::branch::alt((
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::complete::tag(&[0]), unsigned_prevote),
                MessageRef::Prevote,
            ),
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::complete::tag(&[1]), unsigned_precommit),
                MessageRef::Precommit,
            ),
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::complete::tag(&[2]), primary_propose),
                MessageRef::PrimaryPropose,
            ),
        )),
    )(bytes)
}

fn unsigned_prevote(bytes: &[u8]) -> nom::IResult<&[u8], UnsignedPrevoteRef> {
    nom::error::context(
        "unsigned_prevote",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::bytes::complete::take(32u32),
                nom::number::complete::le_u32,
            )),
            |(target_hash, target_number)| UnsignedPrevoteRef {
                target_hash: <&[u8; 32]>::try_from(target_hash).unwrap(),
                target_number,
            },
        ),
    )(bytes)
}

fn unsigned_precommit(bytes: &[u8]) -> nom::IResult<&[u8], UnsignedPrecommitRef> {
    nom::error::context(
        "unsigned_precommit",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::bytes::complete::take(32u32),
                nom::number::complete::le_u32,
            )),
            |(target_hash, target_number)| UnsignedPrecommitRef {
                target_hash: <&[u8; 32]>::try_from(target_hash).unwrap(),
                target_number,
            },
        ),
    )(bytes)
}

fn primary_propose(bytes: &[u8]) -> nom::IResult<&[u8], PrimaryProposeRef> {
    nom::error::context(
        "primary_propose",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::bytes::complete::take(32u32),
                nom::number::complete::le_u32,
            )),
            |(target_hash, target_number)| PrimaryProposeRef {
                target_hash: <&[u8; 32]>::try_from(target_hash).unwrap(),
                target_number,
            },
        ),
    )(bytes)
}

fn neighbor_packet(bytes: &[u8]) -> nom::IResult<&[u8], NeighborPacket> {
    nom::error::context(
        "neighbor_packet",
        nom::combinator::map(
            nom::sequence::preceded(
                nom::bytes::complete::tag(&[1]),
                nom::sequence::tuple((
                    nom::number::complete::le_u64,
                    nom::number::complete::le_u64,
                    nom::number::complete::le_u32,
                )),
            ),
            |(round_number, set_id, commit_finalized_height)| NeighborPacket {
                round_number,
                set_id,
                commit_finalized_height,
            },
        ),
    )(bytes)
}

fn catch_up_request(bytes: &[u8]) -> nom::IResult<&[u8], CatchUpRequest> {
    nom::error::context(
        "catch_up_request",
        nom::combinator::map(
            nom::sequence::tuple((nom::number::complete::le_u64, nom::number::complete::le_u64)),
            |(round_number, set_id)| CatchUpRequest {
                round_number,
                set_id,
            },
        ),
    )(bytes)
}

fn catch_up(bytes: &[u8]) -> nom::IResult<&[u8], CatchUpRef> {
    nom::error::context(
        "catch_up",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::number::complete::le_u64,
                nom::number::complete::le_u64,
                nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
                    nom::multi::many_m_n(num_elems, num_elems, prevote)
                }),
                nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
                    nom::multi::many_m_n(num_elems, num_elems, |s| {
                        crate::finality::justification::decode::PrecommitRef::decode_partial(s)
                            .map(|(a, b)| (b, a))
                            .map_err(|_| {
                                nom::Err::Failure(nom::error::make_error(
                                    s,
                                    nom::error::ErrorKind::Verify,
                                ))
                            })
                    })
                }),
                nom::bytes::complete::take(32u32),
                nom::number::complete::le_u32,
            )),
            |(set_id, round_number, prevotes, precommits, base_hash, base_number)| CatchUpRef {
                set_id,
                round_number,
                prevotes,
                precommits,
                base_hash: <&[u8; 32]>::try_from(base_hash).unwrap(),
                base_number,
            },
        ),
    )(bytes)
}

fn prevote(bytes: &[u8]) -> nom::IResult<&[u8], PrevoteRef> {
    nom::error::context(
        "prevote",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::bytes::complete::take(32u32),
                nom::number::complete::le_u32,
                nom::bytes::complete::take(64u32),
                nom::bytes::complete::take(32u32),
            )),
            |(target_hash, target_number, signature, authority_public_key)| PrevoteRef {
                target_hash: <&[u8; 32]>::try_from(target_hash).unwrap(),
                target_number,
                signature: <&[u8; 64]>::try_from(signature).unwrap(),
                authority_public_key: <&[u8; 32]>::try_from(authority_public_key).unwrap(),
            },
        ),
    )(bytes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn basic_decode_neighbor() {
        let actual = super::decode_grandpa_notification(&[
            2, 1, 87, 14, 0, 0, 0, 0, 0, 0, 162, 13, 0, 0, 0, 0, 0, 0, 49, 231, 77, 0,
        ])
        .unwrap();

        let expected = super::GrandpaNotificationRef::Neighbor(super::NeighborPacket {
            round_number: 3671,
            set_id: 3490,
            commit_finalized_height: 5105457,
        });

        assert_eq!(actual, expected);
    }
}
