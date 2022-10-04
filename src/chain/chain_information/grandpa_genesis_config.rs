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
    executor::{host, vm},
    header,
};

use alloc::vec::Vec;
use core::num::NonZeroU64;

/// Grandpa configuration of a chain, as extracted from the genesis block.
///
/// The way a chain configures Grandpa is either:
///
/// - Stored at the predefined `:grandpa_authorities` key of the storage.
/// - Retrieved by calling the `GrandpaApi_grandpa_authorities` function of the runtime.
///
/// The latter method is soft-deprecated in favor of the former. Both methods are still
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
    /// Retrieves the configuration from the given virtual machine prototype.
    ///
    /// Must be passed a closure that returns the storage value corresponding to the given key in
    /// the genesis block storage.
    ///
    /// Returns back the same virtual machine prototype as was passed as parameter.
    pub fn from_virtual_machine_prototype(
        vm: host::HostVmPrototype,
        mut genesis_storage_access: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    ) -> (Result<Self, FromVmPrototypeError>, host::HostVmPrototype) {
        if let Some(mut encoded) = genesis_storage_access(b":grandpa_authorities") {
            // When in the storage, the encoded list of authorities starts with a version number.
            if encoded.first() != Some(&1) {
                return (Err(FromVmPrototypeError::UnknownEncodingVersionNumber), vm);
            }
            encoded.remove(0);

            let list = match decode_config(&encoded) {
                Ok(l) => Ok(l),
                Err(_) => Err(FromVmPrototypeError::OutputDecode),
            };

            return (list, vm);
        }

        let mut vm: host::HostVm = match vm.run_no_param("GrandpaApi_grandpa_authorities") {
            Ok(vm) => vm.into(),
            Err((err, proto)) => return (Err(FromVmPrototypeError::VmStart(err)), proto),
        };

        loop {
            match vm {
                host::HostVm::ReadyToRun(r) => vm = r.run(),
                host::HostVm::Finished(finished) => {
                    let list = match decode_config(finished.value().as_ref()) {
                        Ok(l) => Ok(l),
                        Err(_) => Err(FromVmPrototypeError::OutputDecode),
                    };

                    break (list, finished.into_prototype());
                }
                host::HostVm::Error { prototype, .. } => {
                    return (Err(FromVmPrototypeError::Trapped), prototype)
                }

                host::HostVm::ExternalStorageGet(rq) => {
                    let value = genesis_storage_access(rq.key().as_ref());
                    vm = rq.resume_full_value(value.as_ref().map(|v| &v[..]));
                }

                host::HostVm::GetMaxLogLevel(resume) => {
                    vm = resume.resume(0); // Off
                }
                host::HostVm::LogEmit(rq) => vm = rq.resume(),

                other => {
                    let vm_prototype = other.into_prototype();
                    return (
                        Err(FromVmPrototypeError::HostFunctionNotAllowed),
                        vm_prototype,
                    );
                }
            }
        }
    }
}

/// Error when retrieving the Grandpa configuration.
#[derive(Debug, derive_more::Display)]
pub enum FromVmPrototypeError {
    /// Error when initializing the virtual machine.
    #[display(fmt = "{}", _0)]
    VmStart(host::StartErr),
    /// Crash while running the virtual machine.
    Trapped,
    /// Virtual machine tried to call a host function that isn't valid in this context.
    HostFunctionNotAllowed,
    /// Version number of the encoded authorities list isn't recognized.
    UnknownEncodingVersionNumber,
    /// Error while decoding the SCALE-encoded list.
    OutputDecode,
}

impl FromVmPrototypeError {
    /// Returns `true` if this error is about an invalid function.
    pub fn is_function_not_found(&self) -> bool {
        matches!(
            self,
            FromVmPrototypeError::VmStart(host::StartErr::VirtualMachine(
                vm::StartErr::FunctionNotFound | vm::StartErr::NotAFunction
            ))
        )
    }
}

fn decode_config(scale_encoded: &[u8]) -> Result<GrandpaGenesisConfiguration, ()> {
    let result: nom::IResult<_, _> = nom::combinator::all_consuming(nom::combinator::complete(
        nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
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
        }),
    ))(scale_encoded);

    match result {
        Ok((_, out)) => Ok(out),
        Err(nom::Err::Error(_) | nom::Err::Failure(_)) => Err(()),
        Err(_) => unreachable!(),
    }
}
