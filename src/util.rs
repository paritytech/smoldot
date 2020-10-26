// Substrate-lite
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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

//! Internal module. Contains functions that aren't Substrate/Polkadot-specific and should ideally
//! be found in third party libraries, but that aren't worth a third-party library.

use core::convert::TryFrom as _;

/// Decodes a SCALE-encoded `Option`.
///
/// > **Note**: When using this function outside of a `nom` "context", you might have to explicit
/// >           the type of `E`. Use `nom::Err<(&[u8], nom::error::ErrorKind)>`.
pub(crate) fn nom_option_decode<'a, O, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
    inner_decode: impl Fn(&'a [u8]) -> nom::IResult<&'a [u8], O, E>,
) -> nom::IResult<&'a [u8], Option<O>, E> {
    nom::branch::alt((
        nom::combinator::map(nom::bytes::complete::tag(&[0]), |_| None),
        nom::combinator::map(
            nom::sequence::preceded(nom::bytes::complete::tag(&[1]), inner_decode),
            Some,
        ),
    ))(bytes)
}

/// Decodes a SCALE-compact-encoded usize.
///
/// > **Note**: When using this function outside of a `nom` "context", you might have to explicit
/// >           the type of `E`. Use `nom::Err<(&[u8], nom::error::ErrorKind)>`.
pub(crate) fn nom_scale_compact_usize<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], usize, E> {
    if bytes.is_empty() {
        return Err(nom::Err::Error(nom::error::make_error(
            bytes,
            nom::error::ErrorKind::Eof,
        )));
    }

    match bytes[0] & 0b11 {
        0b00 => {
            let value = bytes[0] >> 2;
            Ok((&bytes[1..], usize::from(value)))
        }
        0b01 => {
            if bytes.len() < 2 {
                return Err(nom::Err::Error(nom::error::make_error(
                    bytes,
                    nom::error::ErrorKind::Eof,
                )));
            }

            let byte0 = u16::from(bytes[0] >> 2);
            let byte1 = u16::from(bytes[1]);
            let value = (byte1 << 6) | byte0;
            Ok((&bytes[2..], usize::from(value)))
        }
        0b10 => {
            if bytes.len() < 4 {
                return Err(nom::Err::Error(nom::error::make_error(
                    bytes,
                    nom::error::ErrorKind::Eof,
                )));
            }

            let byte0 = u32::from(bytes[0] >> 2);
            let byte1 = u32::from(bytes[1]);
            let byte2 = u32::from(bytes[2]);
            let byte3 = u32::from(bytes[3]);
            let value = (byte3 << 22) | (byte2 << 14) | (byte1 << 6) | byte0;
            let value = match usize::try_from(value) {
                Ok(v) => v,
                Err(_) => todo!(), // TODO:
            };
            Ok((&bytes[4..], value))
        }
        0b11 => todo!(), // TODO:
        _ => unreachable!(),
    }
}
