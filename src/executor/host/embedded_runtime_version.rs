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
//! This module is dedicated to finding the custom sections containing the runtime version.

use super::super::{CoreVersion, CoreVersionApisRefIter};

/// Tries to find the custom section containing the runtime version and checks its validity.
pub fn find_embedded_runtime_version(
    binary_wasm_module: &[u8],
) -> Result<Option<CoreVersion>, FindEmbeddedRuntimeVersionError> {
    let (runtime_version_content, runtime_apis_content) =
        match find_encoded_embedded_runtime_version_apis(binary_wasm_module) {
            Ok((Some(v), Some(a))) => (v, a),
            Ok((None, None)) => return Ok(None),
            Ok(_) => return Err(FindEmbeddedRuntimeVersionError::CustomSectionsPresenceMismatch),
            Err(err) => return Err(FindEmbeddedRuntimeVersionError::FindSections(err)),
        };

    let mut decoded_runtime_version = match super::super::decode(runtime_version_content) {
        Ok(d) => d,
        Err(()) => return Err(FindEmbeddedRuntimeVersionError::RuntimeVersionDecode),
    };

    decoded_runtime_version.apis =
        match CoreVersionApisRefIter::from_slice_no_length(runtime_apis_content) {
            Ok(d) => d,
            Err(()) => return Err(FindEmbeddedRuntimeVersionError::RuntimeApisDecode),
        };

    Ok(Some(CoreVersion(
        decoded_runtime_version.scale_encoding_vec(),
    )))
}

/// Error returned by [`find_embedded_runtime_version`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum FindEmbeddedRuntimeVersionError {
    /// Error while finding the custom section.
    #[display(fmt = "{}", _0)]
    FindSections(FindEncodedEmbeddedRuntimeVersionApisError),
    /// Only one of the two desired custom sections is present.
    CustomSectionsPresenceMismatch,
    /// Error while decoding the runtime version.
    RuntimeVersionDecode,
    /// Error while decoding the runtime APIs.
    RuntimeApisDecode,
}

/// Tries to find the custom sections containing the runtime version and APIs.
///
/// This function does not attempt to decode the content of the custom sections.
pub fn find_encoded_embedded_runtime_version_apis(
    binary_wasm_module: &[u8],
) -> Result<(Option<&[u8]>, Option<&[u8]>), FindEncodedEmbeddedRuntimeVersionApisError> {
    // TODO: don't traverse twice, not efficient
    let runtime_version = match nom::combinator::all_consuming(nom::combinator::complete(
        wasm_module_with_custom(b"runtime_version"),
    ))(binary_wasm_module)
    {
        Ok((_, content)) => content,
        Err(_) => return Err(FindEncodedEmbeddedRuntimeVersionApisError::FailedToParse),
    };

    let runtime_apis = match nom::combinator::all_consuming(nom::combinator::complete(
        wasm_module_with_custom(b"runtime_apis"),
    ))(binary_wasm_module)
    {
        Ok((_, content)) => content,
        Err(_) => return Err(FindEncodedEmbeddedRuntimeVersionApisError::FailedToParse),
    };

    Ok((runtime_version, runtime_apis))
}

/// Error returned by [`find_encoded_embedded_runtime_version_apis`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum FindEncodedEmbeddedRuntimeVersionApisError {
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
