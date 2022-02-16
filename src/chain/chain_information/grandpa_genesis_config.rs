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

use crate::{
    executor::{self, host, vm},
    header,
};

use alloc::{borrow::ToOwned as _, vec::Vec};
use core::num::NonZeroU64;

/// Grandpa configuration of a chain, as extracted from the genesis block.
///
/// The way a chain configures Grandpa is either:
///
/// - Stored at the predefined `:grandpa_authorities` key of the storage.
/// - Retreived by calling the `GrandpaApi_grandpa_authorities` function of the runtime.
///
/// The latter method is soft-deprecated in favour of the former. Both methods are still
/// supported.
///
/// > **Note**: Pragmatically speaking, Polkadot, Westend, and any newer chain use the former
/// >           method. Kusama only supports the latter.
///
#[derive(Debug, Clone)]
pub struct GrandpaGenesisConfiguration {
    /// Authorities of the authorities set 0. These are the authorities that finalize block #1.
    pub initial_authorities: Vec<header::GrandpaAuthority>,
}

impl GrandpaGenesisConfiguration {
    /// Retrieves the configuration from the storage of the genesis block.
    ///
    /// Must be passed a closure that returns the storage value corresponding to the given key in
    /// the genesis block storage.
    pub fn from_genesis_storage(
        mut genesis_storage_access: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    ) -> Result<Self, FromGenesisStorageError> {
        let encoded_list = if let Some(mut list) = genesis_storage_access(b":grandpa_authorities") {
            // When in the storage, the encoded list of authorities starts with a version number.
            if list.first() != Some(&1) {
                return Err(FromGenesisStorageError::UnknownEncodingVersionNumber);
            }
            list.remove(0);
            list
        } else {
            let wasm_code =
                genesis_storage_access(b":code").ok_or(FromGenesisStorageError::RuntimeNotFound)?;
            let heap_pages = executor::storage_heap_pages_to_value(
                genesis_storage_access(b":heappages").as_deref(),
            )
            .map_err(FromGenesisStorageError::HeapPagesDecode)?;
            let vm = host::HostVmPrototype::new(host::Config {
                module: &wasm_code,
                heap_pages,
                exec_hint: vm::ExecHint::Oneshot,
                allow_unresolved_imports: false,
            })
            .map_err(FromGenesisStorageError::VmInitialization)?;
            Self::from_virtual_machine_prototype(vm, genesis_storage_access)
                .map_err(FromGenesisStorageError::VmError)?
        };

        decode_config(&encoded_list).map_err(|()| FromGenesisStorageError::OutputDecode)
    }

    fn from_virtual_machine_prototype(
        vm: host::HostVmPrototype,
        mut genesis_storage_access: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    ) -> Result<Vec<u8>, FromVmPrototypeError> {
        // TODO: DRY with the babe config; put a helper in the executor module
        let mut vm: host::HostVm = vm
            .run_no_param("GrandpaApi_grandpa_authorities")
            .map_err(|(err, proto)| FromVmPrototypeError::VmStart(err, proto))?
            .into();

        Ok(loop {
            match vm {
                host::HostVm::ReadyToRun(r) => vm = r.run(),
                host::HostVm::Finished(data) => {
                    break data.value().as_ref().to_owned();
                }
                host::HostVm::Error { .. } => return Err(FromVmPrototypeError::Trapped),

                host::HostVm::ExternalStorageGet(rq) => {
                    let value = genesis_storage_access(rq.key().as_ref());
                    vm = rq.resume_full_value(value.as_ref().map(|v| &v[..]));
                }

                host::HostVm::GetMaxLogLevel(resume) => {
                    vm = resume.resume(0); // Off
                }
                host::HostVm::LogEmit(rq) => vm = rq.resume(),

                _ => return Err(FromVmPrototypeError::HostFunctionNotAllowed),
            }
        })
    }
}

/// Error when retrieving the Grandpa configuration.
#[derive(Debug, derive_more::Display)]
pub enum FromGenesisStorageError {
    /// Runtime couldn't be found in the genesis storage.
    RuntimeNotFound,
    /// Failed to decode heap pages from the genesis storage.
    HeapPagesDecode(executor::InvalidHeapPagesError),
    /// Version number of the encoded authorities list isn't recognized.
    UnknownEncodingVersionNumber,
    /// Error while decoding the SCALE-encoded list.
    OutputDecode,
    /// Error when initializing the virtual machine.
    VmInitialization(host::NewErr),
    /// Error while executing the runtime.
    VmError(FromVmPrototypeError),
}

impl FromGenesisStorageError {
    /// Returns `true` if this error is about an invalid function.
    pub fn is_function_not_found(&self) -> bool {
        match self {
            FromGenesisStorageError::VmError(err) => err.is_function_not_found(),
            _ => false,
        }
    }
}

/// Error when retrieving the Grandpa configuration.
#[derive(Debug, derive_more::Display)]
pub enum FromVmPrototypeError {
    /// Error when initializing the virtual machine.
    #[display(fmt = "{}", _0)]
    VmStart(host::StartErr, host::HostVmPrototype),
    /// Crash while running the virtual machine.
    Trapped,
    /// Virtual machine tried to call a host function that isn't valid in this context.
    HostFunctionNotAllowed,
}

impl FromVmPrototypeError {
    /// Returns `true` if this error is about an invalid function.
    pub fn is_function_not_found(&self) -> bool {
        matches!(
            self,
            FromVmPrototypeError::VmStart(
                host::StartErr::VirtualMachine(vm::StartErr::FunctionNotFound,),
                _
            ) | FromVmPrototypeError::VmStart(
                host::StartErr::VirtualMachine(vm::StartErr::NotAFunction,),
                _
            )
        )
    }
}

fn decode_config(scale_encoded: &[u8]) -> Result<GrandpaGenesisConfiguration, ()> {
    let result: nom::IResult<_, _> = nom::combinator::all_consuming(nom::combinator::flat_map(
        crate::util::nom_scale_compact_usize,
        |num_elems| {
            nom::multi::fold_many_m_n(
                num_elems,
                num_elems,
                nom::sequence::tuple((
                    nom::bytes::complete::take(32u32),
                    nom::combinator::map_opt(nom::number::complete::le_u64, NonZeroU64::new),
                )),
                move || GrandpaGenesisConfiguration {
                    initial_authorities: Vec::with_capacity(num_elems),
                },
                |mut acc, (public_key, weight)| {
                    acc.initial_authorities.push(header::GrandpaAuthority {
                        public_key: <[u8; 32]>::try_from(public_key).unwrap(),
                        weight,
                    });
                    acc
                },
            )
        },
    ))(scale_encoded);

    match result {
        Ok((_, out)) => Ok(out),
        Err(nom::Err::Error(_)) | Err(nom::Err::Failure(_)) => Err(()),
        Err(_) => unreachable!(),
    }
}
