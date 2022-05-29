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

pub(crate) fn tag_encode(field: u64, wire_ty: u8) -> impl Iterator<Item = u8> + Clone {
    leb128::encode((field << 3) | u64::from(wire_ty))
}

pub(crate) fn bool_tag_encode(
    field: u64,
    bool_value: bool,
) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone {
    // TODO: unclear; bools are undocumented
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
    data: impl AsRef<[u8]> + 'a,
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
    // Protobuf only allows 2 GiB of data.
    debug_assert!(data.as_ref().len() <= 2 * 1024 * 1024 * 1024);
    delimited_tag_encode(field, data)
}

pub(crate) fn string_tag_encode<'a>(
    field: u64,
    data: impl AsRef<str> + 'a,
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
    struct Wrapper<T>(T);
    impl<T: AsRef<str>> AsRef<[u8]> for Wrapper<T> {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref().as_bytes()
        }
    }

    bytes_tag_encode(field, Wrapper(data))
}

pub(crate) fn varint_zigzag_tag_encode(field: u64, value: u64) -> impl Iterator<Item = u8> + Clone {
    tag_encode(field, 0).chain(leb128::encode(value))
}

pub(crate) fn delimited_tag_encode<'a>(
    field: u64,
    data: impl AsRef<[u8]> + 'a,
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
    tag_encode(field, 2)
        .chain(leb128::encode_usize(data.as_ref().len()))
        .map(|v| either::Right([v]))
        .chain(iter::once(either::Left(data)))
}

/// Decodes a protobuf message.
///
/// Must be passed a list of parsers that will parse a tag and value (such as for example
/// [`uint32_tag_decode`] or [`string_tag_decode`]) as a tuple, similar to the `alt` or `tuple`
/// combinators of nom.
///
/// Contrary to the built-in nom combinators, this combinator follows protobuf-specific rules,
/// namely that fields can be in any order and that unknown fields are allowed.
///
/// If you pass as parameter a tuple `(a, b, c)`, the parser will be able to parse
/// `((a_output,), (b_output,), (c_output,))` but also
/// `((a_output,), Vec<b_output>, Option<c_output>)` or any combination of `(,)`, `Vec` or
/// `Option` for each of the parameters.
/// This makes it possible to parse messages with `repeated` or `optional` fields.
pub(crate) fn message_decode<'a, O, E, F: MessageDecodeFields<'a, O, E>>(
    mut fields: F,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], O, E> {
    move |bytes| fields.decode(bytes)
}

/// Decodes a protobuf tag. On success, returns the field number and wire type.
pub(crate) fn tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], (u64, u8), E> {
    // TODO: don't use usize but u64, for consistency between platforms
    nom::combinator::map_opt(leb128::nom_leb128_usize, |num| {
        let wire_ty = u8::try_from(num & 0b111).unwrap();
        let field = u64::try_from(num >> 3).ok()?;
        Some((field, wire_ty))
    })(bytes)
}

/// Decodes a protobuf tag of the given field number, and value where the data type is "uint32".
pub(crate) fn uint32_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    field: u64,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], u32, E> {
    nom::combinator::map_opt(varint_zigzag_tag_decode(field), |num| {
        u32::try_from(num).ok()
    })
}

/// Decodes a protobuf tag of the given field number, and value where the data type is "uint64".
pub(crate) fn uint64_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    field: u64,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], u64, E> {
    varint_zigzag_tag_decode(field)
}

/// Decodes a protobuf tag of the given field number, and value where the data type is "bool".
pub(crate) fn bool_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    field: u64,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], bool, E> {
    nom::combinator::map_opt(varint_zigzag_tag_decode(field), |n| match n {
        // TODO: it's unclear whether this is correct, as bools are undocumented
        0 => Some(false),
        1 => Some(true),
        _ => None,
    })
}

/// Decodes a protobuf tag of the given field number, and value where the data type is "enum".
pub(crate) fn enum_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    field: u64,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], u64, E> {
    varint_zigzag_tag_decode(field)
}

/// Decodes a protobuf tag of the given field number, and value where the data type is a
/// sub-message.
pub(crate) fn message_tag_decode<'a, O, E: nom::error::ParseError<&'a [u8]>>(
    field: u64,
    inner_message_parser: impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], O, E>,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], O, E> {
    nom::combinator::map_parser(delimited_tag_decode(field), inner_message_parser)
}

/// Decodes a protobuf tag of the given field number, and value where the data type is "string".
pub(crate) fn string_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    field: u64,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], &'a str, E> {
    nom::combinator::map_opt(delimited_tag_decode(field), |bytes| {
        if bytes.len() > 2 * 1024 * 1024 * 1024 {
            return None;
        }
        str::from_utf8(bytes).ok()
    })
}

/// Decodes a protobuf tag of the given field number, and value where the data type is "bytes".
pub(crate) fn bytes_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    field: u64,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], &'a [u8], E> {
    nom::combinator::verify(delimited_tag_decode(field), |bytes: &[u8]| {
        bytes.len() <= 2 * 1024 * 1024 * 1024
    })
}

/// Decodes a protobuf tag of the given field number, and value where the wire type is "varint"
/// or "zigzag".
pub(crate) fn varint_zigzag_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    field: u64,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], u64, E> {
    nom::sequence::preceded(
        nom::combinator::verify(tag_decode, move |(f, ty)| *f == field && *ty == 0),
        // TODO: don't decode usize but u64, for consistency between platforms
        nom::combinator::map_opt(leb128::nom_leb128_usize, |n| u64::try_from(n).ok()),
    )
}

/// Decodes a protobuf tag of the given field number, and value where the wire type is "delimited".
pub(crate) fn delimited_tag_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    field: u64,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], &'a [u8], E> {
    nom::sequence::preceded(
        nom::combinator::verify(tag_decode, move |(f, ty)| *f == field && *ty == 2),
        nom::multi::length_data(leb128::nom_leb128_usize),
    )
}

/// Decodes a protobuf tag and value and discards them.
pub(crate) fn tag_value_skip_decode<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], (), E> {
    nom::combinator::flat_map(tag_decode, |(_, wire_ty)| {
        move |inner_bytes| match wire_ty {
            0 => nom::combinator::map(leb128::nom_leb128_usize, |_| ())(inner_bytes),
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

/// Helper trait for [`message_decode`].
pub(crate) trait MessageDecodeFields<'a, O, E> {
    fn decode(&mut self, bytes: &'a [u8]) -> nom::IResult<&'a [u8], O, E>;
}

macro_rules! message_decode_fields {
    ($(($field:ident $out:ident),)*) => {
        impl<'a, $($field,)* $($out,)* Err: nom::error::ParseError<&'a [u8]>> MessageDecodeFields<'a, ($($out,)*), Err> for ($($field,)*)
        where
            $($field: nom::Parser<&'a [u8], <$out>::Item, Err>,)*
            $($out: MessageDecodeFieldOutput,)*
        {
            #[allow(nonstandard_style)]
            fn decode(&mut self, mut bytes: &'a [u8]) -> nom::IResult<&'a [u8], ($($out,)*), Err> {
                let mut out: ($(<$out as MessageDecodeFieldOutput>::Init,)*) = Default::default();
                let ($($field,)*) = self;

                loop {
                    let mut err = None::<Err>;
                    let ($($out,)*) = &mut out;

                    // Try to parse each field one by one.
                    // If a field parses successfully, we `continue` the loop.
                    // Note that it is slightly inefficient to parse the tag over and over again,
                    // but this overhead is in practice most likely negligible and getting rid of
                    // it would likely make the API much more convoluted.
                    $(
                        match nom::Parser::parse($field, bytes) {
                            Ok((rest, out)) => {
                                bytes = rest;
                                <$out as MessageDecodeFieldOutput>::append($out, out);
                                continue;
                            }
                            Err(nom::Err::Error(e)) => {
                                err = Some(match err {
                                    Some(err) => nom::error::ParseError::or(err, e),
                                    None => e,
                                });
                            }
                            Err(err) => return Err(err),
                        };
                    )*

                    // If we reach here, none of the parsers has matched the given tag.
                    // Skip the field as it might simply be unknown.
                    match tag_value_skip_decode(bytes) {
                        Ok((rest, ())) => {
                            bytes = rest;
                            continue;
                        }
                        Err(try_skip_err) => {
                            // Failed to parse a tag and value, meaning that the protobuf message
                            // might be invalid, but most likely simply indicates EOF.
                            let ($($out,)*) = out;
                            if let ($(Some($out),)*) = ($(MessageDecodeFieldOutput::finish($out),)*) {
                                return Ok((bytes, ($($out,)*)))
                            }

                            if let Some(err) = err {
                                return Err(nom::Err::Error(nom::error::ParseError::append(bytes, nom::error::ErrorKind::Alt, err)));
                            }

                            return Err(try_skip_err)
                        }
                    }
                }
            }
        }
    }
}

macro_rules! message_decode_fields_recurse {
    (($first:ident $first_out:ident), $(($field:ident $out:ident),)*) => {
        message_decode_fields!(($first $first_out), $(($field $out),)*);
        message_decode_fields_recurse!($(($field $out),)*);
    };
    () => {};
}

message_decode_fields_recurse!((A Ao), (B Bo), (C Co), (D Do), (E Eo), (F Fo), (G Go), (H Ho), (I Io),);

pub(crate) trait MessageDecodeFieldOutput: Sized {
    type Init: Default;
    type Item;

    fn append(value: &mut Self::Init, other: Self::Item);
    fn finish(value: Self::Init) -> Option<Self>;
}

impl<T> MessageDecodeFieldOutput for (T,) {
    type Init = Option<T>;
    type Item = T;

    fn append(value: &mut Option<T>, other: T) {
        // As documented in the protobuf spec, a later value supercedes an earlier one. A duplicate
        // field intentionally isn't an error.
        *value = Some(other);
    }

    fn finish(value: Option<T>) -> Option<(T,)> {
        value.map(|v| (v,))
    }
}

impl<T> MessageDecodeFieldOutput for Vec<T> {
    type Init = Vec<T>;
    type Item = T;

    fn append(value: &mut Vec<T>, other: T) {
        value.push(other);
    }

    fn finish(value: Vec<T>) -> Option<Vec<T>> {
        Some(value)
    }
}

impl<T> MessageDecodeFieldOutput for Option<T> {
    type Init = Option<T>;
    type Item = T;

    fn append(value: &mut Option<T>, other: T) {
        // As documented in the protobuf spec, a later value supercedes an earlier one. A duplicate
        // field intentionally isn't an error.
        *value = Some(other);
    }

    fn finish(value: Option<T>) -> Option<Option<T>> {
        Some(value)
    }
}
