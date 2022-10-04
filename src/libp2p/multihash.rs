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

//! A multihash is a small data structure containing a code (an integer) and data. The format of
//! the data depends on the code.
//!
//! See <https://github.com/multiformats/multihash>

use alloc::vec::Vec;
use core::fmt;

use crate::util;

/// A multihash made of a code and a slice of data.
///
/// This type is a *reference* to a multihash stored somewhere else, such as in a `Vec<u8>`. You
/// are supposed to store a `MultihashRef` for long term usage. Instead, store a `Vec<u8>` for
/// example. The `MultihashRef` can be constructed from that `Vec<u8>` if it needs decoding.
pub struct MultihashRef<'a>(u32, &'a [u8]);

impl<'a> MultihashRef<'a> {
    /// Builds a multihash from the "identity" hash algorithm code and the provided data.
    ///
    /// Calling [`MultihashRef::data`] on the returned value will always yield back the same data
    /// as was passed as parameter.
    pub fn identity(data: &'a [u8]) -> Self {
        MultihashRef(0, data)
    }

    /// Returns the code stored in this multihash.
    pub fn hash_algorithm_code(&self) -> u32 {
        self.0
    }

    /// Returns the data stored in this multihash.
    pub fn data(&self) -> &'a [u8] {
        self.1
    }

    /// Checks whether `input` is a valid multihash.
    pub fn from_bytes(input: &'a [u8]) -> Result<MultihashRef, FromBytesError> {
        match nom::combinator::all_consuming(multihash::<nom::error::Error<&[u8]>>)(input) {
            Ok((_rest, multihash)) => {
                debug_assert!(_rest.is_empty());
                Ok(multihash)
            }
            Err(_) => Err(FromBytesError::DecodeError),
        }
    }

    /// Checks whether `input` is a valid multihash.
    ///
    /// Contrary to [`MultihashRef::from_bytes`], doesn't return an error if the slice is too long
    /// but returns the remainder.
    pub fn from_bytes_partial(input: &'a [u8]) -> Result<(MultihashRef, &'a [u8]), FromBytesError> {
        match multihash::<nom::error::Error<&[u8]>>(input) {
            Ok((rest, multihash)) => Ok((multihash, rest)),
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

    /// Turns this multihash into a `Vec<u8>`.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 + 7 + self.1.len());
        for slice in self.as_bytes() {
            out.extend_from_slice(slice.as_ref());
        }
        out
    }
}

/// Error when turning bytes into a [`MultihashRef`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum FromBytesError {
    /// The multihash is invalid.
    DecodeError,
}

impl<'a> fmt::Debug for MultihashRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<'a> fmt::Display for MultihashRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base58 = bs58::encode(&self.to_vec()).into_string();
        write!(f, "{}", base58)
    }
}

impl<'a> TryFrom<&'a [u8]> for MultihashRef<'a> {
    type Error = FromBytesError;

    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(input)
    }
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
