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

use crate::executor::host;

use alloc::vec::Vec;
use core::{fmt, ops, str};

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

    let mut decoded_runtime_version = match decode(runtime_version_content) {
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
    let mut parser =
        nom::combinator::all_consuming(nom::combinator::complete(nom::sequence::preceded(
            nom::sequence::tuple((
                nom::bytes::complete::tag(b"\0asm"),
                nom::bytes::complete::tag(&[0x1, 0x0, 0x0, 0x0]),
            )),
            nom::multi::fold_many0(
                wasm_section,
                || (None, None),
                move |prev_found, in_section| {
                    match (prev_found, in_section) {
                        // Not a custom section.
                        (prev_found, None) => prev_found,

                        // We found a custom section with a name that interests us, but we already
                        // parsed a custom section with that same name earlier. Continue with the
                        // value that was parsed earlier.
                        (prev_found @ (Some(_), _), Some((b"runtime_version", _))) => prev_found,
                        (prev_found @ (_, Some(_)), Some((b"runtime_apis", _))) => prev_found,

                        // Found a custom section that interests us, and we didn't find one
                        // before.
                        ((None, prev_rt_apis), Some((b"runtime_version", content))) => {
                            (Some(content), prev_rt_apis)
                        }
                        ((prev_rt_version, None), Some((b"runtime_apis", content))) => {
                            (prev_rt_version, Some(content))
                        }

                        // Found a custom section with a name that doesn't interest us.
                        (prev_found, Some(_)) => prev_found,
                    }
                },
            ),
        )));

    let (runtime_version, runtime_apis) = match parser(binary_wasm_module) {
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

/// Error while executing `Core_version`.
#[derive(Debug, derive_more::Display, Clone)]
pub enum CoreVersionError {
    /// Error while decoding the output.
    Decode,
    /// Error while starting the execution of the `Core_version` function.
    #[display(
        fmt = "Error while starting the execution of the `Core_version` function: {}",
        _0
    )]
    Start(host::StartErr),
    /// Error during the execution of the `Core_version` function.
    #[display(
        fmt = "Error during the execution of the `Core_version` function: {}",
        _0
    )]
    Run(host::Error),
    /// `Core_version` used a host function that is forbidden in this context.
    ForbiddenHostFunction,
}

/// Buffer storing the SCALE-encoded core version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreVersion(Vec<u8>);

impl CoreVersion {
    pub fn from_slice(input: Vec<u8>) -> Result<Self, Vec<u8>> {
        if decode(&input).is_err() {
            return Err(input);
        }

        Ok(CoreVersion(input))
    }

    pub fn decode(&self) -> CoreVersionRef {
        decode(&self.0).unwrap()
    }
}

impl AsRef<[u8]> for CoreVersion {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Runtime specification, once decoded.
// TODO: explain these fields
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreVersionRef<'a> {
    pub spec_name: &'a str,
    pub impl_name: &'a str,
    pub authoring_version: u32,
    pub spec_version: u32,
    pub impl_version: u32,

    /// List of "API"s that the runtime supports.
    ///
    /// Each API corresponds to a certain list of runtime entry points.
    ///
    /// This field can thus be used in order to determine which runtime entry points are
    /// available.
    pub apis: CoreVersionApisRefIter<'a>,

    /// Arbitrary version number corresponding to the transactions encoding version.
    ///
    /// Whenever this version number changes, all transactions encoding generated earlier are
    /// invalidated and should be regenerated.
    ///
    /// Older versions of Substrate didn't provide this field. `None` if the field is missing.
    pub transaction_version: Option<u32>,

    /// Version number of the state trie encoding version.
    ///
    /// Version 0 corresponds to a different trie encoding than version 1.
    ///
    /// This field has been added to Substrate on 24th December 2021. Older versions of Substrate
    /// didn't provide this field, in which case it will contain `None`.
    ///
    /// `None` should be interpreted the same way as `Some(0)`.
    pub state_version: Option<u8>,
}

impl<'a> CoreVersionRef<'a> {
    /// Returns the SCALE encoding of this data structure.
    pub fn scale_encoding_vec(&self) -> Vec<u8> {
        // See https://spec.polkadot.network/#defn-rt-core-version

        let num_apis = self.apis.clone().count();

        // Reserve enough capacity for the various calls to `extend` below.
        // This is only a reasonable estimate, as we assume 2 bytes for the SCALE-compact-encoded
        // lengths. In the case of very very very long names, the capacity might be too low.
        let mut out = Vec::<u8>::with_capacity(
            2 + self.spec_name.len() + 2 + self.impl_name.len() + 4 + 4 + 4 + num_apis * 12 + 4 + 1,
        );

        out.extend(crate::util::encode_scale_compact_usize(self.spec_name.len()).as_ref());
        out.extend(self.spec_name.as_bytes());

        out.extend(crate::util::encode_scale_compact_usize(self.impl_name.len()).as_ref());
        out.extend(self.impl_name.as_bytes());

        out.extend(self.authoring_version.to_le_bytes());
        out.extend(self.spec_version.to_le_bytes());
        out.extend(self.impl_version.to_le_bytes());

        out.extend(crate::util::encode_scale_compact_usize(num_apis).as_ref());
        for api in self.apis.clone() {
            out.extend(api.name_hash);
            out.extend(api.version.to_le_bytes());
        }

        if let Some(transaction_version) = self.transaction_version {
            out.extend(transaction_version.to_le_bytes());
        }

        // TODO: it's not supposed to be allowed to have a CoreVersionRef with a state_version but no transaction_version; the CoreVersionRef struct lets you do that because it was initially designed only for decoding
        if let Some(state_version) = self.state_version {
            out.extend(state_version.to_le_bytes());
        }

        out
    }
}

/// Iterator to a list of APIs. See [`CoreVersionRef::apis`].
#[derive(Clone)]
pub struct CoreVersionApisRefIter<'a> {
    inner: &'a [u8],
}

impl<'a> CoreVersionApisRefIter<'a> {
    /// Decodes a SCALE-encoded list of APIs.
    ///
    /// The input slice isn't expected to contain the number of APIs.
    pub fn from_slice_no_length(input: &'a [u8]) -> Result<Self, ()> {
        let result: Result<_, nom::Err<nom::error::Error<&[u8]>>> =
            nom::combinator::all_consuming(nom::combinator::complete(nom::combinator::map(
                nom::combinator::recognize(nom::multi::fold_many0(
                    core_version_api,
                    || {},
                    |(), _| (),
                )),
                |inner| CoreVersionApisRefIter { inner },
            )))(input);

        match result {
            Ok((_, me)) => Ok(me),
            Err(_) => Err(()),
        }
    }

    /// Returns `true` if this iterator contains the API with the given name and its version is in
    /// the provided range.
    ///
    /// > **Note**: If you start iterating (for example by calling `next()`) then call this
    /// >           function, the search will only be performed on the rest of the iterator,
    /// >           which is typically not what you want. Preferably always call this function
    /// >           on a fresh iterator.
    pub fn contains(&self, api_name: &str, version_number: impl ops::RangeBounds<u32>) -> bool {
        self.contains_hashed(&hash_api_name(api_name), version_number)
    }

    /// Similar to [`CoreVersionApisRefIter::contains`], but allows passing the hash of the
    /// API name instead of its unhashed version.
    pub fn contains_hashed(
        &self,
        api_name_hash: &[u8; 8],
        version_number: impl ops::RangeBounds<u32>,
    ) -> bool {
        self.clone()
            .any(|api| api.name_hash == *api_name_hash && version_number.contains(&api.version))
    }
}

impl<'a> Iterator for CoreVersionApisRefIter<'a> {
    type Item = CoreVersionApi;

    fn next(&mut self) -> Option<Self::Item> {
        if self.inner.is_empty() {
            return None;
        }

        match core_version_api::<nom::error::Error<&[u8]>>(self.inner) {
            Ok((rest, item)) => {
                self.inner = rest;
                Some(item)
            }

            // The content is always checked to be valid before creating a
            // `CoreVersionApisRefIter`.
            Err(_) => unreachable!(),
        }
    }
}

impl<'a> PartialEq for CoreVersionApisRefIter<'a> {
    fn eq(&self, other: &Self) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        loop {
            match (a.next(), b.next()) {
                (Some(a), Some(b)) if a == b => {}
                (None, None) => return true,
                _ => return false,
            }
        }
    }
}

impl<'a> Eq for CoreVersionApisRefIter<'a> {}

impl<'a> fmt::Debug for CoreVersionApisRefIter<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// Hashes the name of an API in order to be able to compare it to [`CoreVersionApi::name_hash`].
pub fn hash_api_name(api_name: &str) -> [u8; 8] {
    let result = blake2_rfc::blake2b::blake2b(8, &[], api_name.as_bytes());
    result.as_bytes().try_into().unwrap()
}

/// One API that the runtime supports.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoreVersionApi {
    /// BLAKE2 hash of length 8 of the name of the API.
    ///
    /// > **Note**: Available APIs can be found by searching for `decl_runtime_apis!` in the
    /// >           Substrate code base. The value stored in this field is the BLAKE2 hash of
    /// >           length 8 of the trait name declared within `decl_runtime_apis!`.
    pub name_hash: [u8; 8],

    /// Version of the module. Typical values are `1`, `2`, `3`, ...
    pub version: u32,
}

fn decode(scale_encoded: &[u8]) -> Result<CoreVersionRef, ()> {
    // See https://spec.polkadot.network/#defn-rt-core-version
    let result: nom::IResult<_, _> =
        nom::combinator::all_consuming(nom::combinator::complete(nom::combinator::map(
            nom::sequence::tuple((
                crate::util::nom_string_decode,
                crate::util::nom_string_decode,
                nom::number::complete::le_u32,
                nom::number::complete::le_u32,
                nom::number::complete::le_u32,
                core_version_apis,
                nom::branch::alt((
                    nom::combinator::map(nom::number::complete::le_u32, Some),
                    nom::combinator::map(nom::combinator::eof, |_| None),
                )),
                nom::branch::alt((
                    nom::combinator::map(nom::number::complete::u8, Some),
                    nom::combinator::map(nom::combinator::eof, |_| None),
                )),
            )),
            |(
                spec_name,
                impl_name,
                authoring_version,
                spec_version,
                impl_version,
                apis,
                transaction_version,
                state_version,
            )| CoreVersionRef {
                spec_name,
                impl_name,
                authoring_version,
                spec_version,
                impl_version,
                apis,
                transaction_version,
                state_version,
            },
        )))(scale_encoded);

    match result {
        Ok((_, out)) => Ok(out),
        Err(nom::Err::Error(_) | nom::Err::Failure(_)) => Err(()),
        Err(_) => unreachable!(),
    }
}

fn core_version_apis<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], CoreVersionApisRefIter, E> {
    nom::combinator::map(
        nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
            nom::combinator::recognize(nom::multi::fold_many_m_n(
                num_elems,
                num_elems,
                core_version_api,
                || {},
                |(), _| (),
            ))
        }),
        |inner| CoreVersionApisRefIter { inner },
    )(bytes)
}

fn core_version_api<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], CoreVersionApi, E> {
    nom::combinator::map(
        nom::sequence::tuple((
            nom::bytes::complete::take(8u32),
            nom::number::complete::le_u32,
        )),
        move |(name, version)| CoreVersionApi {
            name_hash: <[u8; 8]>::try_from(name).unwrap(),
            version,
        },
    )(bytes)
}

/// Parses a Wasm section. If it is a custom section, returns its name and content.
fn wasm_section<'a>(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Option<(&'a [u8], &'a [u8])>> {
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
