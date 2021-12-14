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

// TODO: needs documentation

use crate::util;

pub struct MultihashRef<'a>(u32, &'a [u8]);

impl<'a> MultihashRef<'a> {
    pub fn identity(data: &'a [u8]) -> Self {
        MultihashRef(0, data)
    }

    pub fn hash_algorithm_code(&self) -> u32 {
        self.0
    }

    pub fn data(&self) -> &'a [u8] {
        self.1
    }

    /// Checks whether `data` is a valid [`MultihashRef`].
    ///
    /// In case of error, returns the bytes passed as parameter in addition to the error.
    pub fn from_bytes(data: &'a [u8]) -> Result<MultihashRef, FromBytesError> {
        match nom::combinator::all_consuming(multihash::<nom::error::Error<&[u8]>>)(&data) {
            Ok((_rest, multihash)) => {
                debug_assert!(_rest.is_empty());
                Ok(multihash)
            }
            Err(_) => Err(FromBytesError::DecodeError),
        }
    }

    /// Returns an iterator to a list of buffers that, when concatenated together, form the
    /// binary representation of this multihash.
    pub fn as_bytes(&'_ self) -> impl Iterator<Item = impl AsRef<[u8]> + '_> + '_ {
        let code = util::leb128::encode(self.0).collect::<arrayvec::ArrayVec<u8, 40>>(); // TODO: actual length?
        let len = util::leb128::encode_usize(self.1.len()).collect::<arrayvec::ArrayVec<u8, 40>>(); // TODO: actual length?
        [either::Left(code), either::Left(len), either::Right(self.1)].into_iter()
    }
}

/// Error when turning bytes into a [`MultihashRef`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum FromBytesError {
    /// The multihash is invalid.
    DecodeError,
}

fn multihash<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], MultihashRef<'a>, E> {
    nom::combinator::map(
        nom::sequence::tuple((
            nom::combinator::map_opt(crate::util::leb128::nom_leb128_usize, |c| {
                u32::try_from(c).ok()
            }),
            nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
        )),
        |(code, data)| MultihashRef(code, data),
    )(bytes)
}
