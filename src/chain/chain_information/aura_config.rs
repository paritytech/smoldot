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

//! This module allows retrieving the current Aura configuration of the chain.
//!
//! It can be used on any block.

use crate::{
    executor::{host, vm},
    header,
};

use alloc::vec::Vec;
use core::num::NonZeroU64;

/// Aura configuration of a chain, as extracted from a block.
///
/// The way a chain configures Aura is stored in its runtime.
#[derive(Debug, Clone)]
pub struct AuraConfiguration {
    /// List of authorities that can validate block #1.
    pub authorities_list: Vec<header::AuraAuthority>,

    /// Duration, in milliseconds, of a slot.
    pub slot_duration: NonZeroU64,
}

impl AuraConfiguration {
    /// Retrieves the configuration from the given virtual machine prototype.
    ///
    /// Must be passed a closure that returns the storage value corresponding to the given key in
    /// the block storage.
    ///
    /// Returns back the same virtual machine prototype as was passed as parameter.
    pub fn from_virtual_machine_prototype(
        vm: host::HostVmPrototype,
        mut storage_access: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    ) -> (Result<Self, FromVmPrototypeError>, host::HostVmPrototype) {
        let mut vm: host::HostVm = match vm.run_no_param("AuraApi_slot_duration") {
            Ok(vm) => vm.into(),
            Err((err, proto)) => return (Err(FromVmPrototypeError::VmStart(err)), proto),
        };

        let (slot_duration, vm_prototype) = loop {
            match vm {
                host::HostVm::ReadyToRun(r) => vm = r.run(),
                host::HostVm::Finished(finished) => {
                    let convert_attempt = <[u8; 8]>::try_from(finished.value().as_ref());
                    let vm_prototype = finished.into_prototype();

                    let slot_duration = match convert_attempt {
                        Ok(val) => match NonZeroU64::new(u64::from_le_bytes(val)) {
                            Some(val) => val,
                            None => {
                                return (Err(FromVmPrototypeError::BadSlotDuration), vm_prototype)
                            }
                        },
                        Err(_) => {
                            return (Err(FromVmPrototypeError::BadSlotDuration), vm_prototype)
                        }
                    };

                    break (slot_duration, vm_prototype);
                }
                host::HostVm::Error { prototype, .. } => {
                    return (Err(FromVmPrototypeError::Trapped), prototype)
                }

                host::HostVm::ExternalStorageGet(req) => {
                    let value = storage_access(req.key().as_ref());
                    vm = req.resume_full_value(value.as_ref().map(|v| &v[..]));
                }

                host::HostVm::GetMaxLogLevel(resume) => {
                    vm = resume.resume(0); // Off
                }
                host::HostVm::LogEmit(req) => vm = req.resume(),

                other => {
                    let prototype = other.into_prototype();
                    return (Err(FromVmPrototypeError::HostFunctionNotAllowed), prototype);
                }
            }
        };

        let mut vm: host::HostVm = match vm_prototype.run_no_param("AuraApi_authorities") {
            Ok(vm) => vm.into(),
            Err((err, proto)) => return (Err(FromVmPrototypeError::VmStart(err)), proto),
        };

        let (authorities_list, vm_prototype) = loop {
            match vm {
                host::HostVm::ReadyToRun(r) => vm = r.run(),
                host::HostVm::Finished(finished) => {
                    let authorities_list =
                        match header::AuraAuthoritiesIter::decode(finished.value().as_ref()) {
                            Ok(iter) => {
                                Ok(iter.map(header::AuraAuthority::from).collect::<Vec<_>>())
                            }
                            Err(_) => Err(FromVmPrototypeError::AuthoritiesListDecodeError),
                        };

                    match authorities_list {
                        Ok(l) => break (l, finished.into_prototype()),
                        Err(err) => return (Err(err), finished.into_prototype()),
                    }
                }
                host::HostVm::Error { prototype, .. } => {
                    return (Err(FromVmPrototypeError::Trapped), prototype)
                }

                host::HostVm::ExternalStorageGet(req) => {
                    let value = storage_access(req.key().as_ref());
                    vm = req.resume_full_value(value.as_ref().map(|v| &v[..]));
                }

                host::HostVm::GetMaxLogLevel(resume) => {
                    vm = resume.resume(0); // Off
                }
                host::HostVm::LogEmit(req) => vm = req.resume(),

                other => {
                    let prototype = other.into_prototype();
                    return (Err(FromVmPrototypeError::HostFunctionNotAllowed), prototype);
                }
            }
        };

        let outcome = AuraConfiguration {
            authorities_list,
            slot_duration,
        };

        (Ok(outcome), vm_prototype)
    }
}

/// Error when retrieving the Aura configuration.
#[derive(Debug, derive_more::Display)]
pub enum FromVmPrototypeError {
    /// Error when starting the virtual machine.
    #[display(fmt = "{}", _0)]
    VmStart(host::StartErr),
    /// Crash while running the virtual machine.
    Trapped,
    /// Virtual machine tried to call a host function that isn't valid in this context.
    HostFunctionNotAllowed,
    /// Error while decoding the output of the virtual machine for `AuraApi_slot_duration`.
    BadSlotDuration,
    /// Failed to decode the list of authorities returned by `AuraApi_authorities`.
    AuthoritiesListDecodeError,
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
