// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
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

use alloc::vec::Vec;
use core::{convert::TryFrom as _, num::NonZeroU64};
use parity_scale_codec::DecodeAll as _;

/// BABE configuration of a chain, as extracted from the genesis block.
///
/// The way a chain configures BABE is stored in its runtime.
#[derive(Debug, Clone)]
pub struct BabeGenesisConfiguration {
    pub slots_per_epoch: NonZeroU64,
    pub epoch0_configuration: header::BabeNextConfig,
    pub epoch0_information: header::BabeNextEpoch,
}

impl BabeGenesisConfiguration {
    /// Retrieves the configuration from the storage of the genesis block.
    ///
    /// Must be passed a closure that returns the storage value corresponding to the given key in
    /// the genesis block storage.
    pub fn from_genesis_storage(
        mut genesis_storage_access: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    ) -> Result<Self, FromGenesisStorageError> {
        let wasm_code =
            genesis_storage_access(b":code").ok_or(FromGenesisStorageError::RuntimeNotFound)?;
        let heap_pages = if let Some(bytes) = genesis_storage_access(b":heappages") {
            u64::from_le_bytes(
                <[u8; 8]>::try_from(&bytes[..])
                    .map_err(FromGenesisStorageError::HeapPagesDecode)?,
            )
        } else {
            executor::DEFAULT_HEAP_PAGES
        };
        let vm = host::HostVmPrototype::new(&wasm_code, heap_pages, vm::ExecHint::Oneshot)
            .map_err(FromGenesisStorageError::VmInitialization)?;
        let (cfg, _) = Self::from_virtual_machine_prototype(vm, genesis_storage_access)
            .map_err(FromGenesisStorageError::VmError)?;
        Ok(cfg)
    }

    /// Retrieves the configuration from the given virtual machine prototype.
    ///
    /// Must be passed a closure that returns the storage value corresponding to the given key in
    /// the genesis block storage.
    ///
    /// Returns back the same virtual machine prototype as was passed as parameter.
    pub fn from_virtual_machine_prototype(
        vm: host::HostVmPrototype,
        mut genesis_storage_access: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    ) -> Result<(Self, host::HostVmPrototype), FromVmPrototypeError> {
        let mut vm: host::HostVm = vm
            .run_no_param("BabeApi_configuration")
            .map_err(FromVmPrototypeError::VmStart)?
            .into();

        let (inner, vm_prototype) = loop {
            match vm {
                host::HostVm::ReadyToRun(r) => vm = r.run(),
                host::HostVm::Finished(finished) => {
                    break match OwnedGenesisConfiguration::decode_all(finished.value()) {
                        Ok(cfg) => (cfg, finished.into_prototype()),
                        Err(err) => return Err(FromVmPrototypeError::OutputDecode(err)),
                    };
                }
                host::HostVm::Error { .. } => return Err(FromVmPrototypeError::Trapped),

                host::HostVm::ExternalStorageGet(req) => {
                    let value = genesis_storage_access(req.key());
                    vm = req.resume_full_value(value.as_ref().map(|v| &v[..]));
                }

                host::HostVm::LogEmit(req) => vm = req.resume(),

                _ => return Err(FromVmPrototypeError::HostFunctionNotAllowed),
            }
        };

        let epoch0_information = header::BabeNextEpoch {
            randomness: inner.randomness,
            authorities: inner
                .genesis_authorities
                .iter()
                .map(|(public_key, weight)| header::BabeAuthority {
                    public_key: *public_key,
                    weight: *weight,
                })
                .collect(),
        };

        let epoch0_configuration = header::BabeNextConfig {
            c: inner.c,
            allowed_slots: inner.allowed_slots,
        };

        let outcome = BabeGenesisConfiguration {
            slots_per_epoch: inner.epoch_length,
            epoch0_configuration,
            epoch0_information,
        };

        Ok((outcome, vm_prototype))
    }
}

/// Error when retrieving the BABE configuration.
#[derive(Debug, derive_more::Display)]
pub enum FromGenesisStorageError {
    /// Runtime couldn't be found in the genesis storage.
    RuntimeNotFound,
    /// Number of heap pages couldn't be found in the genesis storage.
    HeapPagesNotFound,
    /// Failed to decode heap pages from the genesis storage.
    HeapPagesDecode(core::array::TryFromSliceError),
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

/// Error when retrieving the BABE configuration.
#[derive(Debug, derive_more::Display)]
pub enum FromVmPrototypeError {
    /// Error when starting the virtual machine.
    VmStart(host::StartErr),
    /// Crash while running the virtual machine.
    Trapped,
    /// Virtual machine tried to call a host function that isn't valid in this context.
    HostFunctionNotAllowed,
    /// Error while decoding the output of the virtual machine.
    OutputDecode(parity_scale_codec::Error),
}

impl FromVmPrototypeError {
    /// Returns `true` if this error is about an invalid function.
    pub fn is_function_not_found(&self) -> bool {
        match self {
            FromVmPrototypeError::VmStart(host::StartErr::VirtualMachine(
                vm::StartErr::FunctionNotFound,
            ))
            | FromVmPrototypeError::VmStart(host::StartErr::VirtualMachine(
                vm::StartErr::NotAFunction,
            )) => true,
            _ => false,
        }
    }
}

// TODO: don't use scale_codec?
#[derive(Debug, Clone, PartialEq, Eq, parity_scale_codec::Encode, parity_scale_codec::Decode)]
struct OwnedGenesisConfiguration {
    slot_duration: u64,
    epoch_length: NonZeroU64,
    c: (u64, u64),
    genesis_authorities: Vec<([u8; 32], u64)>,
    randomness: [u8; 32],
    allowed_slots: header::BabeAllowedSlots,
}
