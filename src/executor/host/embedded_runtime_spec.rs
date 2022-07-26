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

//! Wasm runtimes can optionally contain a custom section (as defined in the official WebAssembly
//! core specification).
//!
//! This module is dedicated to finding this section.

// TODO: there is a small quirk in that the `apis` field is always empty when the runtime spec is in a custom version; deal with this by either removing all references to the `apis` field, or thoroughly documenting that quirk

use super::super::CoreVersion;

/// Tries to find the custom section containing the runtime specification and checks its validity.
pub fn find_embedded_runtime_spec(
    binary_wasm_module: &[u8],
) -> Result<Option<CoreVersion>, FindEmbeddedRuntimeSpecError> {
    let section_content = match find_encoded_embedded_runtime_spec(binary_wasm_module) {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(None),
        Err(err) => return Err(FindEmbeddedRuntimeSpecError::FindSection(err)),
    };

    match super::super::decode(section_content) {
        Ok(_) => Ok(Some(CoreVersion(section_content.to_vec()))),
        Err(()) => Err(FindEmbeddedRuntimeSpecError::Decode),
    }
}

/// Error returned by [`find_encoded_embedded_runtime_spec`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum FindEmbeddedRuntimeSpecError {
    /// Error while finding the custom section.
    #[display(fmt = "{}", _0)]
    FindSection(FindEncodedEmbeddedRuntimeSpecError),
    /// Error while decoding the runtime specification.
    Decode,
}

/// Tries to find the custom section containing the runtime specification.
///
/// This function does not attempt to decode the content of the custom section.
pub fn find_encoded_embedded_runtime_spec(
    binary_wasm_module: &[u8],
) -> Result<Option<&[u8]>, FindEncodedEmbeddedRuntimeSpecError> {
    // A Wasm binary file contains two magic numbers followed with a list of sections.
    match nom::combinator::all_consuming(nom::combinator::complete(wasm_module_with_custom(
        b"runtime_version",
    )))(binary_wasm_module)
    {
        Ok((_, content)) => Ok(content),
        Err(_) => Err(FindEncodedEmbeddedRuntimeSpecError::FailedToParse),
    }
}

/// Error returned by [`find_encoded_embedded_runtime_spec`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum FindEncodedEmbeddedRuntimeSpecError {
    /// Failed to parse Wasm binary.
    FailedToParse,
}

/// Parses a Wasm module, and returns the content of the first custom section with the given name,
/// if any is found.
///
/// If multiple custom sections exist with that name, all but the first are ignored.
fn wasm_module_with_custom<'a>(
    desired_section_name: &'a [u8],
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], Option<&'a [u8]>> {
    nom::sequence::preceded(
        nom::sequence::tuple((
            nom::bytes::complete::tag(b"\0asm"),
            nom::bytes::complete::tag(&[0x1, 0x0, 0x0, 0x0]),
        )),
        nom::multi::fold_many0(
            section,
            || None,
            move |prev_found, maybe_found| {
                let (found_name, found_content) = match maybe_found {
                    Some(f) => f,
                    None => return prev_found,
                };

                if prev_found.is_some() {
                    return prev_found;
                }

                if found_name == desired_section_name {
                    Some(found_content)
                } else {
                    None
                }
            },
        ),
    )
}

/// Parses a Wasm section. If it is a custom section, returns its name and content.
fn section<'a>(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Option<(&'a [u8], &'a [u8])>> {
    nom::branch::alt((
        nom::combinator::map(
            nom::combinator::map_parser(
                nom::sequence::preceded(
                    nom::bytes::complete::tag(&[0]),
                    nom::multi::length_data(nom::combinator::map_opt(
                        crate::util::leb128::nom_leb128_u64,
                        |n| u32::try_from(n).ok(),
                    )),
                ),
                nom::sequence::tuple((
                    nom::multi::length_data(nom::combinator::map_opt(
                        crate::util::leb128::nom_leb128_u64,
                        |n| u32::try_from(n).ok(),
                    )),
                    nom::combinator::rest,
                )),
            ),
            |(name, content)| Some((name, content)),
        ),
        nom::combinator::map(
            nom::sequence::tuple((
                nom::number::complete::u8,
                nom::multi::length_data(nom::combinator::map_opt(
                    crate::util::leb128::nom_leb128_u64,
                    |n| u32::try_from(n).ok(),
                )),
            )),
            |_| None,
        ),
    ))(bytes)
}
