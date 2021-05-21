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

use alloc::vec::Vec;
use core::convert::TryFrom as _;

/// Attempt to decode the given SCALE-encoded Grandpa commit.
pub fn decode_grandpa_commit(scale_encoded: &[u8]) -> Result<CommitMessageRef, Error> {
    match nom::combinator::all_consuming(commit_message)(scale_encoded) {
        Ok((_, commit)) => Ok(commit),
        Err(err) => Err(Error(err)),
    }
}

/// Attempt to decode the given SCALE-encoded commit.
///
/// Contrary to [`decode_grandpa_commit`], doesn't return an error if the slice is too long but
/// returns the remainder.
pub fn decode_partial_grandpa_commit(
    scale_encoded: &[u8],
) -> Result<(CommitMessageRef, &[u8]), Error> {
    match commit_message(scale_encoded) {
        Ok((remainder, commit)) => Ok((commit, remainder)),
        Err(err) => Err(Error(err)),
    }
}

/// Error potentially returned by [`decode_grandpa_commit`].
#[derive(Debug, derive_more::Display)]
pub struct Error<'a>(nom::Err<nom::error::Error<&'a [u8]>>);

// TODO: document and explain
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitMessageRef<'a> {
    pub round_number: u64,
    pub set_id: u64,
    pub message: CompactCommitRef<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactCommitRef<'a> {
    pub target_hash: &'a [u8; 32],
    pub target_number: u32,
    // TODO: don't use Vec
    pub precommits: Vec<UnsignedPrecommitRef<'a>>,

    /// List of ed25519 signatures and public keys.
    // TODO: refactor
    // TODO: don't use Vec
    pub auth_data: Vec<(&'a [u8; 64], &'a [u8; 32])>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedPrecommitRef<'a> {
    pub target_hash: &'a [u8; 32],
    pub target_number: u32,
}

fn commit_message(bytes: &[u8]) -> nom::IResult<&[u8], CommitMessageRef> {
    nom::error::context(
        "commit_message",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::number::complete::le_u64,
                nom::number::complete::le_u64,
                compact_commit,
            )),
            |(round_number, set_id, message)| CommitMessageRef {
                round_number,
                set_id,
                message,
            },
        ),
    )(bytes)
}

fn compact_commit(bytes: &[u8]) -> nom::IResult<&[u8], CompactCommitRef> {
    nom::error::context(
        "compact_commit",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::bytes::complete::take(32u32),
                nom::number::complete::le_u32,
                nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
                    nom::multi::many_m_n(num_elems, num_elems, unsigned_precommit)
                }),
                nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
                    nom::multi::many_m_n(
                        num_elems,
                        num_elems,
                        nom::combinator::map(
                            nom::sequence::tuple((
                                nom::bytes::complete::take(64u32),
                                nom::bytes::complete::take(32u32),
                            )),
                            |(sig, pubkey)| {
                                (
                                    <&[u8; 64]>::try_from(sig).unwrap(),
                                    <&[u8; 32]>::try_from(pubkey).unwrap(),
                                )
                            },
                        ),
                    )
                }),
            )),
            |(target_hash, target_number, precommits, auth_data)| CompactCommitRef {
                target_hash: <&[u8; 32]>::try_from(target_hash).unwrap(),
                target_number,
                precommits,
                auth_data,
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

#[cfg(test)]
mod tests {
    #[test]
    fn decode() {
        super::decode_grandpa(&[
            7, 181, 6, 0, 0, 0, 0, 0, 41, 241, 171, 236, 144, 172, 25, 157, 240, 109, 238, 59, 160,
            115, 76, 8, 195, 253, 109, 240, 108, 170, 63, 120, 149, 47, 143, 149, 22, 64, 88, 210,
            0, 158, 4, 0, 20, 41, 241, 171, 236, 144, 172, 25, 157, 240, 109, 238, 59, 160, 115,
            76, 8, 195, 253, 109, 240, 108, 170, 63, 120, 149, 47, 143, 149, 22, 64, 88, 210, 0,
            158, 4, 0, 13, 247, 129, 120, 204, 170, 120, 173, 41, 241, 213, 234, 121, 111, 20, 38,
            193, 94, 99, 139, 57, 30, 71, 209, 236, 222, 165, 123, 70, 139, 71, 65, 36, 142, 39,
            13, 94, 240, 44, 174, 150, 85, 149, 223, 166, 82, 210, 103, 40, 129, 102, 26, 212, 116,
            231, 209, 163, 107, 49, 82, 229, 197, 82, 8, 28, 21, 28, 17, 203, 114, 51, 77, 38, 215,
            7, 105, 227, 175, 123, 191, 243, 128, 26, 78, 45, 202, 43, 9, 183, 204, 224, 175, 141,
            216, 19, 7, 41, 241, 171, 236, 144, 172, 25, 157, 240, 109, 238, 59, 160, 115, 76, 8,
            195, 253, 109, 240, 108, 170, 63, 120, 149, 47, 143, 149, 22, 64, 88, 210, 0, 158, 4,
            0, 62, 37, 145, 44, 21, 192, 120, 229, 236, 113, 122, 56, 193, 247, 45, 210, 184, 12,
            62, 220, 253, 147, 70, 133, 85, 18, 90, 167, 201, 118, 23, 107, 184, 187, 3, 104, 170,
            132, 17, 18, 89, 77, 156, 145, 242, 8, 185, 88, 74, 87, 21, 52, 247, 101, 57, 154, 163,
            5, 130, 20, 15, 230, 8, 3, 104, 13, 39, 130, 19, 249, 8, 101, 138, 73, 161, 2, 90, 127,
            70, 108, 25, 126, 143, 182, 250, 187, 94, 98, 34, 10, 123, 215, 95, 134, 12, 171, 41,
            241, 171, 236, 144, 172, 25, 157, 240, 109, 238, 59, 160, 115, 76, 8, 195, 253, 109,
            240, 108, 170, 63, 120, 149, 47, 143, 149, 22, 64, 88, 210, 0, 158, 4, 0, 125, 172, 79,
            71, 1, 38, 137, 128, 232, 95, 70, 104, 217, 95, 7, 58, 28, 114, 182, 216, 171, 56, 231,
            218, 199, 244, 220, 122, 6, 225, 5, 175, 172, 47, 198, 61, 84, 42, 75, 66, 62, 90, 243,
            18, 58, 36, 108, 235, 132, 103, 136, 38, 164, 164, 237, 164, 41, 225, 152, 157, 146,
            237, 24, 11, 142, 89, 54, 135, 0, 234, 137, 226, 191, 137, 34, 204, 158, 75, 134, 214,
            101, 29, 28, 104, 154, 13, 87, 129, 63, 151, 104, 219, 170, 222, 207, 113, 41, 241,
            171, 236, 144, 172, 25, 157, 240, 109, 238, 59, 160, 115, 76, 8, 195, 253, 109, 240,
            108, 170, 63, 120, 149, 47, 143, 149, 22, 64, 88, 210, 0, 158, 4, 0, 68, 192, 211, 142,
            239, 33, 55, 222, 165, 127, 203, 155, 217, 170, 61, 95, 206, 74, 74, 19, 123, 60, 67,
            142, 80, 18, 175, 40, 136, 156, 151, 224, 191, 157, 91, 187, 39, 185, 249, 212, 158,
            73, 197, 90, 54, 222, 13, 76, 181, 134, 69, 3, 165, 248, 94, 196, 68, 186, 80, 218, 87,
            162, 17, 11, 222, 166, 244, 167, 39, 211, 178, 57, 146, 117, 214, 238, 136, 23, 136,
            31, 16, 89, 116, 113, 220, 29, 39, 241, 68, 41, 90, 214, 251, 147, 60, 122, 41, 241,
            171, 236, 144, 172, 25, 157, 240, 109, 238, 59, 160, 115, 76, 8, 195, 253, 109, 240,
            108, 170, 63, 120, 149, 47, 143, 149, 22, 64, 88, 210, 0, 158, 4, 0, 58, 187, 123, 135,
            2, 157, 81, 197, 40, 200, 218, 52, 253, 193, 119, 104, 190, 246, 221, 225, 175, 195,
            177, 218, 209, 175, 83, 119, 98, 175, 196, 48, 67, 76, 59, 223, 13, 202, 48, 1, 10, 99,
            200, 201, 123, 29, 89, 131, 120, 70, 162, 235, 11, 191, 96, 57, 83, 51, 217, 199, 35,
            50, 174, 2, 247, 45, 175, 46, 86, 14, 79, 15, 34, 251, 92, 187, 4, 173, 29, 127, 238,
            133, 10, 171, 35, 143, 208, 20, 193, 120, 118, 158, 126, 58, 155, 132, 0,
        ])
        .unwrap();
    }
}
