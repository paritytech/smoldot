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

use super::leb128;
use alloc::vec::Vec;
use core::{iter, str};

pub(crate) fn bool_tag_encode(
    field: u64,
    bool_value: bool,
) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone {
    // Note that booleans aren't documented. However, the source code of the official Java
    // protobuf library encodes them as 1 or 0.
    // See <https://github.com/protocolbuffers/protobuf/blob/520c601c99012101c816b6ccc89e8d6fc28fdbb8/java/core/src/main/java/com/google/protobuf/CodedOutputStream.java#L447>
    varint_zigzag_tag_encode(field, if bool_value { 1 } else { 0 }).map(|b| [b])
}

pub(crate) fn uint32_tag_encode(
    field: u64,
    value: u32,
) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone {
    varint_zigzag_tag_encode(field, u64::from(value)).map(|b| [b])
}

pub(crate) fn enum_tag_encode(
    field: u64,
    enum_value: u64,
) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone {
    varint_zigzag_tag_encode(field, enum_value).map(|b| [b])
}

pub(crate) fn message_tag_encode<'a>(
    field: u64,
    inner_message: impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a,
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
    // We have to buffer the inner message into a `Vec` in order to determine its length. The
    // alternative would have been to require a `Clone` bound on the inner message iterator, but
    // that would be overly restrictive.

    // A relatively high initial capacity is used in order to avoid many reallocations. The actual
    // value is arbitrary.
    let inner_message = inner_message.fold(Vec::with_capacity(1024), |mut a, b| {
        a.extend_from_slice(b.as_ref());
        a
    });

    tag_encode(field, 2)
        .chain(leb128::encode_usize(inner_message.len()))
        .map(|v| either::Right([v]))
        .chain(iter::once(either::Left(inner_message)))
}

pub(crate) fn bytes_tag_encode<'a>(
    field: u64,
    data: impl AsRef<[u8]> + Clone + 'a,
) -> impl Iterator<Item = impl AsRef<[u8]> + Clone + 'a> + Clone + 'a {
    // Protobuf only allows 2 GiB of data.
    debug_assert!(data.as_ref().len() <= 2 * 1024 * 1024 * 1024);
    delimited_tag_encode(field, data)
}

pub(crate) fn string_tag_encode<'a>(
    field: u64,
    data: impl AsRef<str> + Clone + 'a,
) -> impl Iterator<Item = impl AsRef<[u8]> + Clone + 'a> + Clone + 'a {
    #[derive(Clone)]
    struct Wrapper<T>(T);
    impl<T: AsRef<str>> AsRef<[u8]> for Wrapper<T> {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref().as_bytes()
        }
    }

    bytes_tag_encode(field, Wrapper(data))
}

pub(crate) fn tag_encode(field: u64, wire_ty: u8) -> impl Iterator<Item = u8> + Clone {
    leb128::encode((field << 3) | u64::from(wire_ty))
}

pub(crate) fn varint_zigzag_tag_encode(field: u64, value: u64) -> impl Iterator<Item = u8> + Clone {
    tag_encode(field, 0).chain(leb128::encode(value))
}

pub(crate) fn delimited_tag_encode<'a>(
    field: u64,
    data: impl AsRef<[u8]> + Clone + 'a,
) -> impl Iterator<Item = impl AsRef<[u8]> + Clone + 'a> + Clone + 'a {
    tag_encode(field, 2)
        .chain(leb128::encode_usize(data.as_ref().len()))
        .map(|v| either::Right([v]))
        .chain(iter::once(either::Left(data)))
}

/// Decodes a Protobuf tag. On success, returns the field number and wire type.
pub(crate) fn tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], (u64, u8), E> {
    nom::combinator::map(leb128::nom_leb128_u64, |num| {
        let wire_ty = u8::try_from(num & 0b111).unwrap();
        let field = num >> 3;
        (field, wire_ty)
    })(bytes)
}

/// Decodes a Protobuf tag of the given field number, and value where the data type is `uint32`.
pub(crate) fn uint32_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], u32, E> {
    nom::combinator::map_opt(varint_zigzag_tag_decode, |num| u32::try_from(num).ok())(bytes)
}

/// Decodes a Protobuf tag and value where the data type is `bool`.
///
/// > **Note**: The implementation decodes any non-zero value as `true`, meaning that multiple
/// >           different encoded messages can be decoded to `true`. This is important to take
/// >           into consideration if determinism is desired.
pub(crate) fn bool_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], bool, E> {
    nom::combinator::map(varint_zigzag_tag_decode, |n| {
        // Note that booleans are undocumented. However, the official Java library interprets
        // 0 as false and any other value as true.
        // See <https://github.com/protocolbuffers/protobuf/blob/520c601c99012101c816b6ccc89e8d6fc28fdbb8/java/core/src/main/java/com/google/protobuf/BinaryReader.java#L206>
        // or <https://github.com/protocolbuffers/protobuf/blob/520c601c99012101c816b6ccc89e8d6fc28fdbb8/java/core/src/main/java/com/google/protobuf/CodedInputStream.java#L788>
        n != 0
    })(bytes)
}

/// Decodes a Protobuf tag and value where the data type is "enum".
pub(crate) fn enum_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], u64, E> {
    varint_zigzag_tag_decode(bytes)
}

/// Decodes a Protobuf tag and value where the data type is a sub-message.
pub(crate) fn message_tag_decode<'a, O, E: nom::error::ParseError<&'a [u8]>>(
    inner_message_parser: impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], O, E>,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], O, E> {
    nom::combinator::map_parser(delimited_tag_decode, inner_message_parser)
}

/// Decodes a Protobuf tag and value where the data type is "string".
pub(crate) fn string_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], &'a str, E> {
    nom::combinator::map_opt(delimited_tag_decode, |bytes| {
        if bytes.len() > 2 * 1024 * 1024 * 1024 {
            return None;
        }
        str::from_utf8(bytes).ok()
    })(bytes)
}

/// Decodes a Protobuf tag and value where the data type is "bytes".
pub(crate) fn bytes_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], &'a [u8], E> {
    nom::combinator::verify(delimited_tag_decode, |bytes: &[u8]| {
        bytes.len() <= 2 * 1024 * 1024 * 1024
    })(bytes)
}

/// Decodes a Protobuf tag  and value where the wire type is `varint` or "zigzag".
pub(crate) fn varint_zigzag_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], u64, E> {
    nom::sequence::preceded(
        nom::combinator::verify(tag_decode, move |(_, ty)| *ty == 0),
        leb128::nom_leb128_u64,
    )(bytes)
}

/// Decodes a Protobuf tag and value where the wire type is "delimited".
pub(crate) fn delimited_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], &'a [u8], E> {
    nom::sequence::preceded(
        nom::combinator::verify(tag_decode, move |(_, ty)| *ty == 2),
        nom::multi::length_data(leb128::nom_leb128_usize),
    )(bytes)
}

/// Decodes a Protobuf tag and value and discards them.
pub(crate) fn tag_value_skip_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], (), E> {
    nom::combinator::flat_map(tag_decode, |(_, wire_ty)| {
        move |inner_bytes| match wire_ty {
            0 => nom::combinator::map(leb128::nom_leb128_u64, |_| ())(inner_bytes),
            5 => nom::combinator::map(nom::bytes::complete::take(4u32), |_| ())(inner_bytes),
            1 => nom::combinator::map(nom::bytes::complete::take(8u32), |_| ())(inner_bytes),
            2 => nom::combinator::map(nom::multi::length_data(leb128::nom_leb128_usize), |_| ())(
                inner_bytes,
            ),
            _ => Err(nom::Err::Error(nom::error::ParseError::from_error_kind(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    })(bytes)
}

/// Decodes a Protobuf message.
///
/// Importantly, this does **not** expect a Protobuf tag in front of the message. If the message
/// is part of another message, you must wrap this macro call around [`message_tag_decode`].
///
/// This macro expects a list of fields, each field has one of the three following formats:
///
/// ```ignore
/// field_name = num => parser
/// #[optional] field_name = num => parser
/// #[repeated] field_name = num => parser
/// ```
///
/// `field_name` must be an identifier, `num` the field number according to the Protobuf
/// definition, and `parser` an inner parser that parses a Protobuf tag and value.
/// If `#[optional]` is provided, then the value produced by `parser` is wrapped around an
/// `Option`, and the decoding of the message will succeed even if the field is missing.
/// If `#[repeated(max = n)]` is provided, then the value produced by `parser` is wrapped
/// around a `Vec`, and the field can be provided multiple times in the message. No more than
/// `n` items can be added to the `Vec` before the decoding fails.
/// Note that `num` and `n` (the maximum number of items in a `Vec`) can be expressions.
/// It is not possible to pass both `#[optional]` and `#[repeated]` at the same time.
///
/// The macro produces a `nom` parser that outputs an anonymous struct whose field correspond
/// to the provided field names.
///
/// # Example
///
/// ```ignore
/// let _parser = nom::combinator::all_consuming::<_, _, nom::error::Error<&[u8]>, _>(
///     nom::combinator::complete(protobuf::message_decode! {
///         #[repeated(max = 4)] entries = 1 => protobuf::message_decode!{
///             state_root = 1 => protobuf::bytes_tag_decode(1),
///             #[repeated(max = 10)] entries = 2 => protobuf::message_tag_decode(2, protobuf::message_decode!{
///                 key = 1 => protobuf::bytes_tag_decode(1),
///                 value = 2 => protobuf::bytes_tag_decode(2),
///             }),
///             #[optional] complete = 3 => protobuf::bool_tag_decode(3),
///         }
///     }),
/// );
/// ```
///
// TODO: maybe optional should be default?
macro_rules! message_decode {
    ($($(#[$($attrs:tt)*])* $field_name:ident = $field_num:expr => $parser:expr),*,) => {
        $crate::util::protobuf::message_decode!($($(#[$($attrs)*])* $field_name = $field_num => $parser),*)
    };
    ($($(#[$($attrs:tt)*])* $field_name:ident = $field_num:expr => $parser:expr),*) => {{
        #[allow(non_camel_case_types)]
        struct Out<$($field_name),*> {
            $($field_name: $field_name,)*
        }

        |mut input| {
            #[allow(non_camel_case_types)]
            struct InProgress<$($field_name),*> {
                $($field_name: $crate::util::protobuf::message_decode_helper_ty!($field_name; $($($attrs)*)*),)*
            }

            let mut in_progress = InProgress {
                $($field_name: Default::default(),)*
            };

            loop {
                // Note: it might be tempting to write `input: &[u8]` as the closure parameter
                // instead, but this causes lifetime issues for some reason.
                if <[u8]>::is_empty(input) {
                    break;
                }

                let (_, (field_num, _wire_ty)) = $crate::util::protobuf::tag_decode(input)?;

                $(if field_num == $field_num {
                    let (rest, value) = nom::Parser::<&[u8], _, _>::parse(&mut $parser, input)?;

                    if input == rest {
                        // The field parser didn't consume any byte. This will lead
                        // to an infinite loop. Return an error to prevent this from
                        // happening.
                        return core::result::Result::Err(nom::Err::Error(
                            nom::error::ParseError::<&[u8]>::from_error_kind(rest, nom::error::ErrorKind::Alt)
                        ));
                    }

                    $crate::util::protobuf::message_decode_helper_store!(input, value => in_progress.$field_name; $($($attrs)*)*);
                    input = rest;
                    continue;
                })*

                // Fields with an unrecognized number are deliberately ignored. This is
                // a fundamental feature of protobuf in order to make protocol upgrades
                // easier.
                let (rest, ()) = $crate::util::protobuf::tag_value_skip_decode(input)?;
                debug_assert!(input != rest);
                input = rest;
            }

            let out = Out {
                $($field_name: $crate::util::protobuf::message_decode_helper_unwrap!(in_progress.$field_name; $($($attrs)*)*)?,)*
            };

            Ok((input, out))
        }
    }};
}

macro_rules! message_decode_helper_ty {
    ($ty:ty;) => { Option<$ty> };
    ($ty:ty; optional) => { Option<$ty> };
    ($ty:ty; repeated(max = $max:expr)) => { Vec<$ty> };
}

macro_rules! message_decode_helper_store {
    ($input_data:expr, $value:expr => $dest:expr;) => {
        if $dest.is_some() {
            // Make sure that the field is only found once in the message.
            return core::result::Result::Err(nom::Err::Error(
                nom::error::ParseError::<&[u8]>::from_error_kind(
                    $input_data,
                    nom::error::ErrorKind::Many1,
                ),
            ));
        }
        $dest = Some($value);
    };
    ($input_data:expr, $value:expr => $dest:expr; optional) => {
        if $dest.is_some() {
            // Make sure that the field is only found once in the message.
            return core::result::Result::Err(nom::Err::Error(
                nom::error::ParseError::<&[u8]>::from_error_kind(
                    $input_data,
                    nom::error::ErrorKind::Many1,
                ),
            ));
        }
        $dest = Some($value);
    };
    ($input_data:expr, $value:expr => $dest:expr; repeated(max = $max:expr)) => {
        if $dest.len() >= usize::try_from($max).unwrap_or(usize::max_value()) {
            return core::result::Result::Err(nom::Err::Error(
                nom::error::ParseError::<&[u8]>::from_error_kind(
                    $input_data,
                    nom::error::ErrorKind::Many1,
                ),
            ));
        }
        $dest.push($value);
    };
}

macro_rules! message_decode_helper_unwrap {
    ($value:expr;) => {
        $value.ok_or_else(|| {
            nom::Err::Error(nom::error::ParseError::<&[u8]>::from_error_kind(
                &[][..],
                nom::error::ErrorKind::NoneOf,
            ))
        })
    };
    ($value:expr; optional) => {
        Ok($value)
    };
    ($value:expr; repeated(max = $max:expr)) => {
        Ok($value)
    };
}

pub(crate) use {
    message_decode, message_decode_helper_store, message_decode_helper_ty,
    message_decode_helper_unwrap,
};

#[cfg(test)]
mod tests {
    #[test]
    fn encode_decode_bool() {
        let encoded = super::bool_tag_encode(504, true).fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        assert_eq!(&encoded, &[192, 31, 1]);

        let decoded = super::bool_tag_decode::<nom::error::Error<&[u8]>>(&encoded)
            .unwrap()
            .1;
        assert!(decoded);
    }

    #[test]
    fn encode_decode_uint32() {
        let encoded = super::uint32_tag_encode(8670, 93701).fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        assert_eq!(&encoded, &[240, 157, 4, 133, 220, 5]);

        let decoded = super::uint32_tag_decode::<nom::error::Error<&[u8]>>(&encoded)
            .unwrap()
            .1;
        assert_eq!(decoded, 93701);
    }

    #[test]
    fn encode_decode_enum() {
        let encoded = super::enum_tag_encode(107, 935237).fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        assert_eq!(&encoded, &[216, 6, 197, 138, 57]);

        let decoded = super::enum_tag_decode::<nom::error::Error<&[u8]>>(&encoded)
            .unwrap()
            .1;
        assert_eq!(decoded, 935237);
    }

    #[test]
    fn encode_decode_string() {
        let encoded = super::string_tag_encode(490, "hello world").fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        assert_eq!(
            &encoded,
            &[210, 30, 11, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]
        );

        let decoded = super::string_tag_decode::<nom::error::Error<&[u8]>>(&encoded)
            .unwrap()
            .1;
        assert_eq!(decoded, "hello world");
    }

    #[test]
    fn encode_decode_bytes() {
        let encoded = super::bytes_tag_encode(2, b"test").fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        assert_eq!(&encoded, &[18, 4, 116, 101, 115, 116]);

        let decoded = super::bytes_tag_decode::<nom::error::Error<&[u8]>>(&encoded)
            .unwrap()
            .1;
        assert_eq!(decoded, b"test");
    }

    #[test]
    fn large_values_dont_crash() {
        // Payload starts with a LEB128 that corresponds to a very very large field identifier.
        let encoded = (0..256).map(|_| 129).collect::<Vec<_>>();
        assert!(super::tag_value_skip_decode::<nom::error::Error<&[u8]>>(&encoded).is_err());
    }
}
