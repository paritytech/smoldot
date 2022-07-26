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

//! WebAssembly runtime code execution.
//!
//! WebAssembly (often abbreviated *Wasm*) plays a big role in Substrate/Polkadot. The storage of
//! each block in the chain has a special key named `:code` which contains the WebAssembly code
//! of what we call *the runtime*.
//!
//! The runtime is a program (in WebAssembly) that decides, amongst other things, whether
//! transactions are valid and how to apply them on the storage, and whether blocks themselves are
//! valid.
//!
//! This module contains everything necessary to execute runtime code. The highest-level
//! sub-module is [`runtime_host`].

use alloc::vec::Vec;
use core::{fmt, ops, str};

mod allocator; // TODO: make public after refactoring
pub mod host;
pub mod read_only_runtime_host;
pub mod runtime_host;
pub mod storage_diff;
pub mod vm;

/// Default number of heap pages if the storage doesn't specify otherwise.
///
/// # Context
///
/// In order to initialize a [`host::HostVmPrototype`], one needs to pass a certain number of
/// heap pages that are available to the runtime.
///
/// This number is normally found in the storage, at the key `:heappages`. But if it is not
/// specified, then the value of this constant must be used.
pub const DEFAULT_HEAP_PAGES: vm::HeapPages = vm::HeapPages::new(2048);

/// Converts a value of the key `:heappages` found in the storage to an actual number of heap
/// pages.
pub fn storage_heap_pages_to_value(
    storage_value: Option<&[u8]>,
) -> Result<vm::HeapPages, InvalidHeapPagesError> {
    if let Some(storage_value) = storage_value {
        let bytes =
            <[u8; 8]>::try_from(storage_value).map_err(|_| InvalidHeapPagesError::WrongLen)?;
        let num = u64::from_le_bytes(bytes);
        let num = u32::try_from(num).map_err(|_| InvalidHeapPagesError::TooLarge)?;
        Ok(vm::HeapPages::from(num))
    } else {
        Ok(DEFAULT_HEAP_PAGES)
    }
}

/// Error potentially returned by [`storage_heap_pages_to_value`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum InvalidHeapPagesError {
    /// Storage value has the wrong length.
    WrongLen,
    /// Number of heap pages is too large.
    TooLarge,
}

// TODO: consider moving all the core-version-related code in host

/// Runs the `Core_version` function using the given virtual machine prototype, and returns
/// the output.
///
/// All host functions are forbidden.
// TODO: this function is probably not needed
pub fn core_version(
    vm_proto: host::HostVmPrototype,
) -> (Result<CoreVersion, CoreVersionError>, host::HostVmPrototype) {
    let mut vm: host::HostVm = match vm_proto.run_no_param("Core_version") {
        Ok(vm) => vm.into(),
        Err((err, prototype)) => return (Err(CoreVersionError::Start(err)), prototype),
    };

    loop {
        match vm {
            host::HostVm::ReadyToRun(r) => vm = r.run(),
            host::HostVm::Finished(finished) => {
                if decode(finished.value().as_ref()).is_err() {
                    return (Err(CoreVersionError::Decode), finished.into_prototype());
                }

                let version = finished.value().as_ref().to_vec();
                return (Ok(CoreVersion(version)), finished.into_prototype());
            }

            // Emitted log lines are ignored.
            host::HostVm::GetMaxLogLevel(resume) => {
                vm = resume.resume(0); // Off
            }
            host::HostVm::LogEmit(log) => vm = log.resume(),

            host::HostVm::Error { prototype, error } => {
                return (Err(CoreVersionError::Run(error)), prototype)
            }

            // Since there are potential ambiguities we don't allow any storage access
            // or anything similar. The last thing we want is to have an infinite
            // recursion of runtime calls.
            other => {
                return (
                    Err(CoreVersionError::ForbiddenHostFunction),
                    other.into_prototype(),
                )
            }
        }
    }
}

/// Error while executing [`core_version`].
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

/// Iterator to a list of APIs. See [`CoreVersionRef::apis`].
#[derive(Clone)]
pub struct CoreVersionApisRefIter<'a> {
    inner: &'a [u8],
}

impl<'a> CoreVersionApisRefIter<'a> {
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

impl<'a> ExactSizeIterator for CoreVersionApisRefIter<'a> {}

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
    let result: nom::IResult<_, _> =
        nom::combinator::all_consuming(nom::combinator::complete(nom::combinator::map(
            nom::sequence::tuple((
                crate::util::nom_string_decode,
                crate::util::nom_string_decode,
                nom::number::complete::le_u32,
                nom::number::complete::le_u32,
                nom::number::complete::le_u32,
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
                ),
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
