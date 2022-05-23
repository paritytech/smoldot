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

//! Internal module. Contains functions that aren't Substrate/Polkadot-specific and should ideally
//! be found in third party libraries, but that aren't worth a third-party library.

use core::str;

pub(crate) mod leb128;

/// Implementation of the `BuildHasher` trait for the sip hasher.
///
/// Contrary to the one in the standard library, a seed is explicitly passed here, making the
/// hashing predictable. This is a good thing for tests and no-std compatibility.
pub struct SipHasherBuild([u8; 16]);

impl SipHasherBuild {
    pub fn new(seed: [u8; 16]) -> SipHasherBuild {
        SipHasherBuild(seed)
    }
}

impl core::hash::BuildHasher for SipHasherBuild {
    type Hasher = siphasher::sip::SipHasher;

    fn build_hasher(&self) -> Self::Hasher {
        siphasher::sip::SipHasher::new_with_key(&self.0)
    }
}

/// Returns a parser that decodes a SCALE-encoded `Option`.
///
/// > **Note**: When using this function outside of a `nom` "context", you might have to explicit
/// >           the type of `E`. Use `nom::Err<nom::error::Error>`.
pub(crate) fn nom_option_decode<'a, O, E: nom::error::ParseError<&'a [u8]>>(
    inner_decode: impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], O, E>,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], Option<O>, E> {
    nom::branch::alt((
        nom::combinator::map(nom::bytes::complete::tag(&[0]), |_| None),
        nom::combinator::map(
            nom::sequence::preceded(nom::bytes::complete::tag(&[1]), inner_decode),
            Some,
        ),
    ))
}

/// Decodes a SCALE-encoded vector of bytes.
pub(crate) fn nom_bytes_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], &'a [u8], E> {
    nom::multi::length_data(crate::util::nom_scale_compact_usize)(bytes)
}

/// Decodes a SCALE-encoded string.
pub(crate) fn nom_string_decode<
    'a,
    E: nom::error::ParseError<&'a [u8]> + nom::error::FromExternalError<&'a [u8], str::Utf8Error>,
>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], &'a str, E> {
    nom::combinator::map_res(
        nom::multi::length_data(crate::util::nom_scale_compact_usize),
        str::from_utf8,
    )(bytes)
}

/// Decodes a SCALE-encoded boolean.
pub(crate) fn nom_bool_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], bool, E> {
    nom::branch::alt((
        nom::combinator::map(nom::bytes::complete::tag(&[0]), |_| false),
        nom::combinator::map(nom::bytes::complete::tag(&[1]), |_| true),
    ))(bytes)
}

macro_rules! decode_scale_compact {
    ($fn_name:ident, $num_ty:ty) => {
/// Decodes a SCALE-compact-encoded integer.
///
/// > **Note**: When using this function outside of a `nom` "context", you might have to explicit
/// >           the type of `E`. Use `nom::error::Error<&[u8]>`.
pub(crate) fn $fn_name<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], $num_ty, E> {
    if bytes.is_empty() {
        return Err(nom::Err::Error(nom::error::make_error(
            bytes,
            nom::error::ErrorKind::Eof,
        )));
    }

    match bytes[0] & 0b11 {
        0b00 => {
            let value = bytes[0] >> 2;
            Ok((&bytes[1..], <$num_ty>::from(value)))
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
            Ok((&bytes[2..], <$num_ty>::from(value)))
        }
        0b10 => {
            if bytes.len() < 4 {
                return Err(nom::Err::Error(nom::error::make_error(
                    bytes,
                    nom::error::ErrorKind::Eof,
                )));
            }

            // The code below uses `checked_shl` because using plain `<<` sometimes panics with
            // "attempt to shift left with overflow", even though it is mathematically impossible
            // for this to happen. I strongly suspect a miscompilation when using `<<` instead of
            // `checked_sub`, but haven't managed to isolate the problem in a reproducible case.
            let byte0 = u32::from(bytes[0] >> 2);
            let byte1 = u32::from(bytes[1]).checked_shl(6).unwrap();
            let byte2 = u32::from(bytes[2]).checked_shl(14).unwrap();
            let byte3 = u32::from(bytes[3]).checked_shl(22).unwrap();

            let value = byte3 | byte2 | byte1 | byte0;
            let value = match <$num_ty>::try_from(value) {
                Ok(v) => v,
                Err(_) => {
                    return Err(nom::Err::Error(nom::error::make_error(
                        bytes,
                        nom::error::ErrorKind::Satisfy,
                    )))
                }
            };
            Ok((&bytes[4..], value))
        }
        0b11 => {
            let num_bytes = usize::from(bytes[0] >> 2) + 4;

            if bytes.len() < num_bytes + 1 {
                return Err(nom::Err::Error(nom::error::make_error(
                    bytes,
                    nom::error::ErrorKind::Eof,
                )));
            }

            // Value is invalid if highest byte is 0.
            if bytes[num_bytes] == 0 {
                return Err(nom::Err::Error(nom::error::make_error(
                    bytes,
                    nom::error::ErrorKind::Satisfy,
                )));
            }

            let mut out_value = 0;
            let mut shift = 0u32;
            for byte_index in 1..=num_bytes {
                out_value |= match <$num_ty>::from(1u8)
                    .checked_shl(shift)
                    .and_then(|shl| <$num_ty>::from(bytes[byte_index]).checked_mul(shl))
                {
                    Some(v) => v,
                    None => {
                        // Overflow. The SCALE-encoded value is too large to fit a `usize`.
                        return Err(nom::Err::Error(nom::error::make_error(
                            bytes,
                            nom::error::ErrorKind::Satisfy,
                        )));
                    }
                };

                // Overflows aren't properly handled because `out_value` is expected to overflow
                // way sooner than `shift`.
                shift += 8;
            }

            Ok((&bytes[num_bytes + 1..], out_value))
        }
        _ => unreachable!(),
    }
}
    };
}

decode_scale_compact!(nom_scale_compact_usize, usize);
decode_scale_compact!(nom_scale_compact_u64, u64);

macro_rules! encode_scale_compact {
    ($fn_name:ident, $num_ty:ty) => {
        /// Returns a buffer containing the SCALE-compact encoding of the parameter.
        pub(crate) fn $fn_name(mut value: $num_ty) -> impl AsRef<[u8]> + Clone {
            const MAX_BITS: usize = 1 + (<$num_ty>::BITS as usize) / 8;
            let mut array = arrayvec::ArrayVec::<u8, MAX_BITS>::new();

            if value < 64 {
                array.push(u8::try_from(value).unwrap() << 2);
            } else if value < (1 << 14) {
                array.push((u8::try_from(value & 0b111111).unwrap() << 2) | 0b01);
                array.push(u8::try_from((value >> 6) & 0xff).unwrap());
            } else if value < (1 << 30) {
                array.push((u8::try_from(value & 0b111111).unwrap() << 2) | 0b10);
                array.push(u8::try_from((value >> 6) & 0xff).unwrap());
                array.push(u8::try_from((value >> 14) & 0xff).unwrap());
                array.push(u8::try_from((value >> 22) & 0xff).unwrap());
            } else {
                array.push(0);
                while value != 0 {
                    array.push(u8::try_from(value & 0xff).unwrap());
                    value >>= 8;
                }
                array[0] = (u8::try_from(array.len() - 1 - 4).unwrap() << 2) | 0b11;
            }

            array
        }
    };
}

encode_scale_compact!(encode_scale_compact_u64, u64);
encode_scale_compact!(encode_scale_compact_usize, usize);
