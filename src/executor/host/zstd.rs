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

use alloc::borrow::Cow;
use core::convert::TryFrom as _;
use std::io::Read as _;

/// A runtime blob beginning with this prefix should first be decompressed with zstandard
/// compression.
///
/// This differs from the Wasm magic bytes, so real Wasm blobs will not have this prefix.
pub(super) const ZSTD_PREFIX: [u8; 8] = [82, 188, 83, 118, 70, 219, 142, 5];

/// If the given blob starts with [`ZSTD_PREFIX`], decompresses it. Otherwise, passes it through.
///
/// The output data shall not be larger than `max_allowed`, to avoid potential zip bombs.
pub(super) fn zstd_decode_if_necessary(
    data: &[u8],
    max_allowed: usize,
) -> Result<Cow<[u8]>, Error> {
    if data.starts_with(&ZSTD_PREFIX) {
        Ok(Cow::Owned(zstd_decode(
            &data[ZSTD_PREFIX.len()..],
            max_allowed,
        )?))
    } else if data.len() > max_allowed {
        Err(Error::TooLarge)
    } else {
        Ok(Cow::Borrowed(data))
    }
}

/// Decompresses the given blob of zstd-compressed data.
///
/// The output data shall not be larger than `max_allowed`, to avoid potential zip bombs.
fn zstd_decode(mut data: &[u8], max_allowed: usize) -> Result<Vec<u8>, Error> {
    // Guess that the output is going to be around 3 times larger than the input.
    let mut out_buf = Vec::with_capacity(data.len() * 3);

    ruzstd::streaming_decoder::StreamingDecoder::new(&mut data)
        .map_err(|_| Error::InvalidZstd)?
        .take(u64::try_from(max_allowed).unwrap().saturating_add(1))
        .read_to_end(&mut out_buf)
        .map_err(|_| Error::InvalidZstd)?;

    if out_buf.len() <= max_allowed {
        Ok(out_buf)
    } else {
        Err(Error::TooLarge)
    }
}

/// Error possibly returned when decoding a zstd-compressed Wasm blob.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// The data is zstandard-compressed, but the data is in an invalid format.
    InvalidZstd,
    /// The size of the code exceeds the maximum allowed length.
    TooLarge,
}
