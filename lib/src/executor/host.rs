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

//! Wasm virtual machine specific to the Substrate/Polkadot Runtime Environment.
//!
//! Contrary to [`VirtualMachine`](super::vm::VirtualMachine), this code is not just a generic
//! Wasm virtual machine, but is aware of the Substrate/Polkadot runtime environment. The host
//! functions that the Wasm code calls are automatically resolved and either handled or notified
//! to the user of this module.
//!
//! Any host function that requires pure CPU computations (for example building or verifying
//! a cryptographic signature) is directly handled by the code in this module. Other host
//! functions (for example accessing the state or printing a message) are instead handled by
//! interrupting the virtual machine and waiting for the user of this module to handle the call.
//!
//! > **Note**: The `ext_offchain_random_seed_version_1` and `ext_offchain_timestamp_version_1`
//! >           functions, which requires the host to respectively produce a random seed and
//! >           return the current time, must also be handled by the user. While these functions
//! >           could theoretically be handled directly by this module, it might be useful for
//! >           testing purposes to have the possibility to return a deterministic value.
//!
//! Contrary to most programs, runtime code doesn't have a singe `main` or `start` function.
//! Instead, it exposes several entry points. Which one to call indicates which action it has to
//! perform. Not all entry points are necessarily available on all runtimes.
//!
//! # Runtime requirements
//!
//! See the [documentation of the `vm` module](super::vm) for details about the requirements a
//! runtime must adhere to.
//!
//! In addition to the requirements described there, the WebAssembly runtime code can also be
//! zstandard-compressed and must also export a global symbol named `__heap_base`.
//! More details below.
//!
//! ## `Zstandard` compression
//!
//! The runtime code passed as parameter to [`HostVmPrototype::new`] can be compressed using the
//! [`zstd`](https://en.wikipedia.org/wiki/Zstandard) algorithm.
//!
//! If the code starts with the magic bytes `[82, 188, 83, 118, 70, 219, 142, 5]`, then it is
//! assumed that the rest of the data is a zstandard-compressed WebAssembly module.
//!
//! ## Runtime version
//!
//! Wasm files can contain so-called custom sections. A runtime can contain two custom sections
//! whose names are `"runtime_version"` and `"runtime_apis"`, in which case they must contain a
//! so-called runtime version.
//!
//! The runtime version contains important field that identifies a runtime.
//!
//! If no `"runtime_version"` and `"runtime_apis"` custom sections can be found, the
//! `Core_version` entry point is used as a fallback in order to obtain the runtime version. This
//! fallback mechanism is maintained for backwards compatibility purposes, but is considered
//! deprecated.
//!
//! ## Memory allocations
//!
//! One of the instructions available in WebAssembly code is
//! [the `memory.grow` instruction](https://webassembly.github.io/spec/core/bikeshed/#-hrefsyntax-instr-memorymathsfmemorygrow),
//! which allows increasing the size of the memory.
//!
//! WebAssembly code is normally intended to perform its own heap-management logic internally, and
//! use the `memory.grow` instruction if more memory is needed.
//!
//! In order to minimize the size of the runtime binary, and in order to accommodate for the API of
//! the host functions that return a buffer of variable length, the Substrate/Polkadot runtimes,
//! however, do not perform their heap management internally. Instead, they use the
//! `ext_allocator_malloc_version_1` and `ext_allocator_free_version_1` host functions for this
//! purpose. Calling `memory.grow` is forbidden.
//!
//! The runtime code must export a global symbol named `__heap_base` of type `i32`. Any memory
//! whose offset is below the value of `__heap_base` can be used at will by the program, while
//! any memory above `__heap_base` but below `__heap_base + heap_pages` (where `heap_pages` is
//! the value passed as parameter to [`HostVmPrototype::new`]) is available for use by the
//! implementation of `ext_allocator_malloc_version_1`.
//!
//! ## Entry points
//!
//! All entry points that can be called from the host (using, for example,
//! [`HostVmPrototype::run`]) have the same signature:
//!
//! ```ignore
//! (func $runtime_entry(param $data i32) (param $len i32) (result i64))
//! ```
//!
//! In order to call into the runtime, one must write a buffer of data containing the input
//! parameters into the Wasm virtual machine's memory, then pass a pointer and length of this
//! buffer as the parameters of the entry point.
//!
//! The function returns a 64 bits number. The 32 less significant bits represent a pointer to the
//! Wasm virtual machine's memory, and the 32 most significant bits a length. This pointer and
//! length designate a buffer containing the actual return value.
//!
//! ## Host functions
//!
//! The list of host functions available to the runtime is long and isn't documented here. See
//! the official specification for details.
//!
//! # Usage
//!
//! The first step is to create a [`HostVmPrototype`] object from the WebAssembly code. Creating
//! this object performs some initial steps, such as parsing and compiling the WebAssembly code.
//! You are encouraged to maintain a cache of [`HostVmPrototype`] objects (one instance per
//! WebAssembly byte code) in order to avoid performing these operations too often.
//!
//! To start calling the runtime, create a [`HostVm`] by calling [`HostVmPrototype::run`].
//!
//! While the Wasm runtime code has side-effects (such as storing values in the storage), the
//! [`HostVm`] itself is a pure state machine with no side effects.
//!
//! At any given point, you can examine the [`HostVm`] in order to know in which state the
//! execution currently is.
//! In case of a [`HostVm::ReadyToRun`] (which initially is the case when you create the
//! [`HostVm`]), you can execute the Wasm code by calling [`ReadyToRun::run`].
//! No background thread of any kind is used, and calling [`ReadyToRun::run`] directly performs
//! the execution of the Wasm code. If you need parallelism, you are encouraged to spawn a
//! background thread yourself and call this function from there.
//! [`ReadyToRun::run`] tries to make the execution progress as much as possible, and returns
//! the new state of the virtual machine once that is done.
//!
//! If the runtime has finished, or has crashed, or wants to perform an operation with side
//! effects, then the [`HostVm`] determines what to do next. For example, for
//! [`HostVm::ExternalStorageGet`], you must load a value from the storage and pass it back by
//! calling [`ExternalStorageGet::resume`].
//!
//! The Wasm execution is fully deterministic, and the outcome of the execution only depends on
//! the inputs. There is, for example, no implicit injection of randomness or of the current time.
//!
//! ## Example
//!
//! ```
//! use smoldot::executor::host::{
//!     Config, HeapPages, HostVm, HostVmPrototype, StorageProofSizeBehavior
//! };
//!
//! # let wasm_binary_code: &[u8] = return;
//!
//! // Start executing a function on the runtime.
//! let mut vm: HostVm = {
//!     let prototype = HostVmPrototype::new(Config {
//!         module: &wasm_binary_code,
//!         heap_pages: HeapPages::from(2048),
//!         exec_hint: smoldot::executor::vm::ExecHint::ValidateAndExecuteOnce,
//!         allow_unresolved_imports: false
//!     }).unwrap();
//!     prototype.run_no_param(
//!         "Core_version",
//!         StorageProofSizeBehavior::proof_recording_disabled()
//!     ).unwrap().into()
//! };
//!
//! // We need to answer the calls that the runtime might perform.
//! loop {
//!     match vm {
//!         // Calling `runner.run()` is what actually executes WebAssembly code and updates
//!         // the state.
//!         HostVm::ReadyToRun(runner) => vm = runner.run(),
//!
//!         HostVm::Finished(finished) => {
//!             // `finished.value()` here is an opaque blob of bytes returned by the runtime.
//!             // In the case of a call to `"Core_version"`, we know that it must be empty.
//!             assert!(finished.value().as_ref().is_empty());
//!             println!("Success!");
//!             break;
//!         },
//!
//!         // Errors can happen if the WebAssembly code panics or does something wrong.
//!         // In a real-life situation, the host should obviously not panic in these situations.
//!         HostVm::Error { .. } => {
//!             panic!("Error while executing code")
//!         },
//!
//!         // All the other variants correspond to function calls that the runtime might perform.
//!         // `ExternalStorageGet` is shown here as an example.
//!         HostVm::ExternalStorageGet(req) => {
//!             println!("Runtime requires the storage value at {:?}", req.key().as_ref());
//!             // Injects the value into the virtual machine and updates the state.
//!             vm = req.resume(None); // Just a stub
//!         }
//!         _ => unimplemented!()
//!     }
//! }
//! ```

use super::{allocator, vm};
use crate::{trie, util};

use alloc::{borrow::ToOwned as _, boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::{fmt, iter, str};
use functions::HostFunction;

pub mod runtime_version;

pub use runtime_version::{
    CoreVersion, CoreVersionApisFromSliceErr, CoreVersionError, CoreVersionRef,
    FindEncodedEmbeddedRuntimeVersionApisError,
};
pub use trie::TrieEntryVersion;
pub use vm::HeapPages;
pub use zstd::Error as ModuleFormatError;

mod functions;
mod tests;
mod zstd;

/// Configuration for [`HostVmPrototype::new`].
pub struct Config<TModule> {
    /// Bytes of the WebAssembly module.
    ///
    /// The module can be either directly Wasm bytecode, or zstandard-compressed.
    pub module: TModule,

    /// Number of pages of heap available to the virtual machine.
    ///
    /// See the module-level documentation for an explanation.
    pub heap_pages: HeapPages,

    /// Hint used by the implementation to decide which kind of virtual machine to use.
    pub exec_hint: vm::ExecHint,

    /// If `true`, no [`vm::NewErr::UnresolvedFunctionImport`] error will be returned if the
    /// module trying to import functions that aren't recognized by the implementation. Instead,
    /// a [`Error::UnresolvedFunctionCalled`] error will be generated if the module tries to call
    /// an unresolved function.
    pub allow_unresolved_imports: bool,
}

/// Behavior if the `ext_storage_proof_size_storage_proof_size_version_1` host function is called.
///
/// When authoring a block or executing a block, this host function is expected to return the
/// current size of the proof. Smoldot unfortunately can't implement this due to the fact that
/// the proof generation algorithm is completely unspecified. For this reason, you should
/// use [`StorageProofSizeBehavior::Unimplemented`]. However, for testing purposes, using
/// `StorageProofSizeBehavior::ConstantReturnValue(0)` is acceptable.
///
/// In situations other than authoring or executing a block, use the value returned by
/// [`StorageProofSizeBehavior::proof_recording_disabled`].
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageProofSizeBehavior {
    /// The host function is unimplemented. An error is returned if it is called.
    Unimplemented,
    /// The host function returns the given value.
    ConstantReturnValue(u64),
}

impl StorageProofSizeBehavior {
    /// Returns the behavior to employ when proof recording is disabled, as defined in the
    /// specification.
    pub fn proof_recording_disabled() -> Self {
        StorageProofSizeBehavior::ConstantReturnValue(u64::MAX)
    }
}

/// Prototype for an [`HostVm`].
///
/// > **Note**: This struct implements `Clone`. Cloning a [`HostVmPrototype`] allocates memory
/// >           necessary for the clone to run.
#[derive(Clone)]
pub struct HostVmPrototype {
    /// Fields that are kept as is even during the execution.
    common: Box<VmCommon>,

    /// Inner virtual machine prototype.
    vm_proto: vm::VirtualMachinePrototype,
}

/// Fields that are kept as is even during the execution.
#[derive(Clone)]
struct VmCommon {
    /// Runtime version of this runtime.
    ///
    /// Always `Some`, except at initialization.
    runtime_version: Option<CoreVersion>,

    /// Initial value of the `__heap_base` global in the Wasm module. Used to initialize the memory
    /// allocator.
    heap_base: u32,

    /// List of functions that the Wasm code imports.
    ///
    /// The keys of this list (i.e. the `usize` indices) have been passed to the virtual machine
    /// executor. Whenever the Wasm code invokes a host function, we obtain its index, and look
    /// within this list to know what to do.
    registered_functions: Arc<[FunctionImport]>,

    /// Value of `heap_pages` passed to [`HostVmPrototype::new`].
    heap_pages: HeapPages,

    /// Total number of pages of Wasm memory. This is equal to `heap_base / 64k` (rounded up) plus
    /// `heap_pages`.
    memory_total_pages: HeapPages,
}

impl HostVmPrototype {
    /// Creates a new [`HostVmPrototype`]. Parses and potentially JITs the module.
    pub fn new(config: Config<impl AsRef<[u8]>>) -> Result<Self, NewErr> {
        // The maximum allowed size for the decompressed Wasm code needs to be the same amongst
        // all implementations.
        // See <https://github.com/paritytech/substrate/blob/f9d10fabe04d598d68f8b097cc4905adbb1ad630/primitives/maybe-compressed-blob/src/lib.rs#L37>.
        // Hopefully, this value doesn't get changed without the Substrate team informing everyone.
        let module_bytes = zstd::zstd_decode_if_necessary(config.module.as_ref(), 50 * 1024 * 1024)
            .map_err(NewErr::BadFormat)?;

        // Try to find the runtime version as Wasm custom sections.
        // An error is returned if the sections have a wrong format, in which case we fail the
        // initialization. `Ok(None)` can also be returned, in which case the sections are
        // missing, and we will instead try to retrieve the version through a runtime call later
        // down this function.
        // In the case of `CustomSectionsPresenceMismatch`, indicating that one section is present
        // but not the other, we must ignore the custom sections. This is necessary due to some
        // historical accidents.
        let runtime_version = match runtime_version::find_embedded_runtime_version(&module_bytes) {
            Ok(Some(r)) => Some(r),
            Ok(None) => None,
            Err(
                runtime_version::FindEmbeddedRuntimeVersionError::CustomSectionsPresenceMismatch,
            ) => None,
            Err(runtime_version::FindEmbeddedRuntimeVersionError::FindSections(err)) => {
                return Err(NewErr::RuntimeVersion(
                    FindEmbeddedRuntimeVersionError::FindSections(err),
                ));
            }
            Err(runtime_version::FindEmbeddedRuntimeVersionError::RuntimeApisDecode(err)) => {
                return Err(NewErr::RuntimeVersion(
                    FindEmbeddedRuntimeVersionError::RuntimeApisDecode(err),
                ));
            }
            Err(runtime_version::FindEmbeddedRuntimeVersionError::RuntimeVersionDecode) => {
                return Err(NewErr::RuntimeVersion(
                    FindEmbeddedRuntimeVersionError::RuntimeVersionDecode,
                ));
            }
        };

        // Initialize the virtual machine.
        // Each symbol requested by the Wasm runtime will be put in `registered_functions`. Later,
        // when a function is invoked, the Wasm virtual machine will pass indices within that
        // array.
        let (mut vm_proto, registered_functions) = {
            let mut registered_functions = Vec::new();
            let vm_proto = vm::VirtualMachinePrototype::new(vm::Config {
                module_bytes: &module_bytes[..],
                exec_hint: config.exec_hint,
                // This closure is called back for each function that the runtime imports.
                symbols: &mut |mod_name, f_name, signature| {
                    if mod_name != "env" {
                        return Err(());
                    }

                    let id = registered_functions.len();
                    registered_functions.push(match HostFunction::by_name(f_name) {
                        Some(f) if f.signature() == *signature => FunctionImport::Resolved(f),
                        Some(_) | None if !config.allow_unresolved_imports => {
                            // TODO: return a better error if there is a signature mismatch
                            return Err(());
                        }
                        Some(_) | None => FunctionImport::Unresolved {
                            name: f_name.to_owned(),
                            module: mod_name.to_owned(),
                        },
                    });
                    Ok(id)
                },
            })?;
            (vm_proto, registered_functions.into())
        };

        // In the runtime environment, Wasm blobs must export a global symbol named
        // `__heap_base` indicating where the memory allocator is allowed to allocate memory.
        let heap_base = vm_proto
            .global_value("__heap_base")
            .map_err(|_| NewErr::HeapBaseNotFound)?;

        let memory_total_pages = if heap_base == 0 {
            config.heap_pages
        } else {
            HeapPages::new((heap_base - 1) / (64 * 1024)) + config.heap_pages + HeapPages::new(1)
        };

        if vm_proto
            .memory_max_pages()
            .map_or(false, |max| max < memory_total_pages)
        {
            return Err(NewErr::MemoryMaxSizeTooLow);
        }

        let mut host_vm_prototype = HostVmPrototype {
            vm_proto,
            common: Box::new(VmCommon {
                runtime_version,
                heap_base,
                registered_functions,
                heap_pages: config.heap_pages,
                memory_total_pages,
            }),
        };

        // Call `Core_version` if no runtime version is known yet.
        if host_vm_prototype.common.runtime_version.is_none() {
            let mut vm: HostVm = match host_vm_prototype.run_no_param(
                "Core_version",
                StorageProofSizeBehavior::proof_recording_disabled(),
            ) {
                Ok(vm) => vm.into(),
                Err((err, _)) => return Err(NewErr::CoreVersion(CoreVersionError::Start(err))),
            };

            loop {
                match vm {
                    HostVm::ReadyToRun(r) => vm = r.run(),
                    HostVm::Finished(finished) => {
                        let version =
                            match CoreVersion::from_slice(finished.value().as_ref().to_vec()) {
                                Ok(v) => v,
                                Err(_) => {
                                    return Err(NewErr::CoreVersion(CoreVersionError::Decode));
                                }
                            };

                        host_vm_prototype = finished.into_prototype();
                        host_vm_prototype.common.runtime_version = Some(version);
                        break;
                    }

                    // Emitted log lines are ignored.
                    HostVm::GetMaxLogLevel(resume) => {
                        vm = resume.resume(0); // Off
                    }
                    HostVm::LogEmit(log) => vm = log.resume(),

                    HostVm::Error { error, .. } => {
                        return Err(NewErr::CoreVersion(CoreVersionError::Run(error)));
                    }

                    // Getting the runtime version is a very core operation, and very few
                    // external calls are allowed.
                    _ => return Err(NewErr::CoreVersion(CoreVersionError::ForbiddenHostFunction)),
                }
            }
        }

        // Success!
        debug_assert!(host_vm_prototype.common.runtime_version.is_some());
        Ok(host_vm_prototype)
    }

    /// Returns the number of heap pages that were passed to [`HostVmPrototype::new`].
    pub fn heap_pages(&self) -> HeapPages {
        self.common.heap_pages
    }

    /// Returns the runtime version found in the module.
    pub fn runtime_version(&self) -> &CoreVersion {
        self.common
            .runtime_version
            .as_ref()
            .unwrap_or_else(|| unreachable!())
    }

    /// Starts the VM, calling the function passed as parameter.
    ///
    /// See the documentation of [`StorageProofSizeBehavior`] for an explanation of
    /// the `storage_proof_size_behavior` parameter.
    pub fn run(
        self,
        function_to_call: &str,
        storage_proof_size_behavior: StorageProofSizeBehavior,
        data: &[u8],
    ) -> Result<ReadyToRun, (StartErr, Self)> {
        self.run_vectored(
            function_to_call,
            storage_proof_size_behavior,
            iter::once(data),
        )
    }

    /// Same as [`HostVmPrototype::run`], except that the function doesn't need any parameter.
    ///
    /// See the documentation of [`StorageProofSizeBehavior`] for an explanation of
    /// the `storage_proof_size_behavior` parameter.
    pub fn run_no_param(
        self,
        function_to_call: &str,
        storage_proof_size_behavior: StorageProofSizeBehavior,
    ) -> Result<ReadyToRun, (StartErr, Self)> {
        self.run_vectored(
            function_to_call,
            storage_proof_size_behavior,
            iter::empty::<Vec<u8>>(),
        )
    }

    /// Same as [`HostVmPrototype::run`], except that the function parameter can be passed as
    /// a list of buffers. All the buffers will be concatenated in memory.
    ///
    /// See the documentation of [`StorageProofSizeBehavior`] for an explanation of
    /// the `storage_proof_size_behavior` parameter.
    pub fn run_vectored(
        mut self,
        function_to_call: &str,
        storage_proof_size_behavior: StorageProofSizeBehavior,
        data: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
    ) -> Result<ReadyToRun, (StartErr, Self)> {
        // Determine the total length of `data`.
        let mut data_len_u32: u32 = 0;
        for data in data.clone() {
            let len = match u32::try_from(data.as_ref().len()) {
                Ok(v) => v,
                Err(_) => return Err((StartErr::DataSizeOverflow, self)),
            };
            data_len_u32 = match data_len_u32.checked_add(len) {
                Some(v) => v,
                None => return Err((StartErr::DataSizeOverflow, self)),
            };
        }

        // Initialize the state of the memory allocator. This is the allocator that is used in
        // order to allocate space for the input data, and also later used when the Wasm code
        // requests variable-length data.
        let mut allocator = allocator::FreeingBumpHeapAllocator::new(self.common.heap_base);

        // Prepare the virtual machine for execution.
        let mut vm = self.vm_proto.prepare();

        // Write the input data in the VM's memory using the allocator.
        let data_ptr = match allocator.allocate(
            &mut MemAccess {
                vm: MemAccessVm::Prepare(&mut vm),
                memory_total_pages: self.common.memory_total_pages,
            },
            data_len_u32,
        ) {
            Ok(p) => p,
            Err(_) => {
                self.vm_proto = vm.into_prototype();
                return Err((StartErr::DataSizeOverflow, self));
            }
        };

        // While the allocator has reserved memory, it might have reserved more memory than its
        // current size.
        if let Some(to_grow) = ((data_ptr + data_len_u32).saturating_sub(1) / (64 * 1024) + 1)
            .checked_sub(u32::from(vm.memory_size()))
        {
            // If the memory can't be grown, it indicates a bug in the allocator.
            vm.grow_memory(HeapPages::from(to_grow))
                .unwrap_or_else(|_| unreachable!());
        }

        // Writing the input data into the VM.
        let mut data_ptr_iter = data_ptr;
        for data in data {
            let data = data.as_ref();
            vm.write_memory(data_ptr_iter, data)
                .unwrap_or_else(|_| unreachable!());
            data_ptr_iter = data_ptr_iter
                .checked_add(u32::try_from(data.len()).unwrap_or_else(|_| unreachable!()))
                .unwrap_or_else(|| unreachable!());
        }

        // Now start executing the function. We pass as parameter the location and size of the
        // input data.
        let vm = match vm.start(
            function_to_call,
            &[
                vm::WasmValue::I32(i32::from_ne_bytes(data_ptr.to_ne_bytes())),
                vm::WasmValue::I32(i32::from_ne_bytes(data_len_u32.to_ne_bytes())),
            ],
        ) {
            Ok(vm) => vm,
            Err((error, vm_proto)) => {
                self.vm_proto = vm_proto;
                return Err((error.into(), self));
            }
        };

        Ok(ReadyToRun {
            resume_value: None,
            inner: Box::new(Inner {
                common: self.common,
                vm,
                storage_transaction_depth: 0,
                signatures_batch_verification: None,
                allocator,
                storage_proof_size_behavior,
            }),
        })
    }
}

impl fmt::Debug for HostVmPrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("HostVmPrototype").finish()
    }
}

/// Running virtual machine.
#[must_use]
#[derive(derive_more::From, Debug)]
pub enum HostVm {
    /// Wasm virtual machine is ready to be run. Call [`ReadyToRun::run`] to make progress.
    #[from]
    ReadyToRun(ReadyToRun),
    /// Function execution has succeeded. Contains the return value of the call.
    ///
    /// The trie root hash of all the child tries must be recalculated and written to the main trie
    /// similar to when a [`ExternalStorageRoot`] with a `child_trie` of `None` is generated. See
    /// the documentation of [`ExternalStorageRoot`].
    #[from]
    Finished(Finished),
    /// The Wasm blob did something that doesn't conform to the runtime environment.
    Error {
        /// Virtual machine ready to be used again.
        prototype: HostVmPrototype,
        /// Error that happened.
        error: Error,
    },
    /// Must load an storage value.
    #[from]
    ExternalStorageGet(ExternalStorageGet),
    /// Must set an storage value.
    #[from]
    ExternalStorageSet(ExternalStorageSet),
    /// See documentation of [`ExternalStorageAppend`].
    #[from]
    ExternalStorageAppend(ExternalStorageAppend),
    /// Must remove all the storage values starting with a certain prefix.
    #[from]
    ExternalStorageClearPrefix(ExternalStorageClearPrefix),
    /// Must provide the trie root hash of the storage and write the trie root hash of child tries
    /// to the main trie.
    #[from]
    ExternalStorageRoot(ExternalStorageRoot),
    /// Need to provide the storage key that follows a specific one.
    #[from]
    ExternalStorageNextKey(ExternalStorageNextKey),
    /// Must set off-chain index value.
    #[from]
    ExternalOffchainIndexSet(ExternalOffchainIndexSet),
    /// Must load an offchain storage value.
    #[from]
    ExternalOffchainStorageGet(ExternalOffchainStorageGet),
    /// Must set value of an off-chain storage entry.
    #[from]
    ExternalOffchainStorageSet(ExternalOffchainStorageSet),
    /// Need to provide the current timestamp.
    #[from]
    OffchainTimestamp(OffchainTimestamp),
    /// Must return random seed.
    #[from]
    OffchainRandomSeed(OffchainRandomSeed),
    /// Submit a transaction from offchain worker.
    #[from]
    OffchainSubmitTransaction(OffchainSubmitTransaction),
    /// Need to verify whether a signature is valid.
    #[from]
    SignatureVerification(SignatureVerification),
    /// Need to call `Core_version` on the given Wasm code and return the raw output (i.e.
    /// still SCALE-encoded), or an error if the call has failed.
    #[from]
    CallRuntimeVersion(CallRuntimeVersion),
    /// Declares the start of a storage transaction. See [`HostVm::EndStorageTransaction`].
    #[from]
    StartStorageTransaction(StartStorageTransaction),
    /// Ends a storage transaction. All changes made to the storage (e.g. through a
    /// [`HostVm::ExternalStorageSet`]) since the previous
    /// [`HostVm::StartStorageTransaction`] must be rolled back if `rollback` is true.
    ///
    /// Guaranteed by the code in this module to never happen if no transaction is in progress.
    /// If the runtime attempts to end a non-existing transaction, an [`HostVm::Error`] is
    /// generated instead.
    EndStorageTransaction {
        /// Object used to resume execution.
        resume: EndStorageTransaction,
        /// If true, changes must be rolled back.
        rollback: bool,
    },
    /// Need to provide the maximum log level.
    #[from]
    GetMaxLogLevel(GetMaxLogLevel),
    /// Runtime has emitted a log entry.
    #[from]
    LogEmit(LogEmit),
}

impl HostVm {
    /// Cancels execution of the virtual machine and returns back the prototype.
    pub fn into_prototype(self) -> HostVmPrototype {
        match self {
            HostVm::ReadyToRun(inner) => inner.inner.into_prototype(),
            HostVm::Finished(inner) => inner.inner.into_prototype(),
            HostVm::Error { prototype, .. } => prototype,
            HostVm::ExternalStorageGet(inner) => inner.inner.into_prototype(),
            HostVm::ExternalStorageSet(inner) => inner.inner.into_prototype(),
            HostVm::ExternalStorageAppend(inner) => inner.inner.into_prototype(),
            HostVm::ExternalStorageClearPrefix(inner) => inner.inner.into_prototype(),
            HostVm::ExternalStorageRoot(inner) => inner.inner.into_prototype(),
            HostVm::ExternalStorageNextKey(inner) => inner.inner.into_prototype(),
            HostVm::ExternalOffchainIndexSet(inner) => inner.inner.into_prototype(),
            HostVm::ExternalOffchainStorageGet(inner) => inner.inner.into_prototype(),
            HostVm::ExternalOffchainStorageSet(inner) => inner.inner.into_prototype(),
            HostVm::OffchainTimestamp(inner) => inner.inner.into_prototype(),
            HostVm::OffchainRandomSeed(inner) => inner.inner.into_prototype(),
            HostVm::OffchainSubmitTransaction(inner) => inner.inner.into_prototype(),
            HostVm::SignatureVerification(inner) => inner.inner.into_prototype(),
            HostVm::CallRuntimeVersion(inner) => inner.inner.into_prototype(),
            HostVm::StartStorageTransaction(inner) => inner.inner.into_prototype(),
            HostVm::EndStorageTransaction { resume, .. } => resume.inner.into_prototype(),
            HostVm::GetMaxLogLevel(inner) => inner.inner.into_prototype(),
            HostVm::LogEmit(inner) => inner.inner.into_prototype(),
        }
    }
}

/// Virtual machine is ready to run.
pub struct ReadyToRun {
    inner: Box<Inner>,
    resume_value: Option<vm::WasmValue>,
}

impl ReadyToRun {
    /// Runs the virtual machine until something important happens.
    ///
    /// > **Note**: This is when the actual CPU-heavy computation happens.
    pub fn run(mut self) -> HostVm {
        loop {
            match self.run_once() {
                HostVm::ReadyToRun(r) => self = r,
                other => return other,
            }
        }
    }

    fn run_once(mut self) -> HostVm {
        // `vm::ExecOutcome::Interrupted` is by far the variant that requires the most
        // handling code. As such, special-case all other variants before.
        let (id, params) = match self.inner.vm.run(self.resume_value) {
            Ok(vm::ExecOutcome::Interrupted { id, params }) => (id, params),

            Ok(vm::ExecOutcome::Finished {
                return_value: Ok(Some(vm::WasmValue::I64(ret))),
            }) => {
                // Wasm virtual machine has successfully returned.

                if self.inner.storage_transaction_depth > 0 {
                    return HostVm::Error {
                        prototype: self.inner.into_prototype(),
                        error: Error::FinishedWithPendingTransaction,
                    };
                }

                // Turn the `i64` into a `u64`, not changing any bit.
                let ret = u64::from_ne_bytes(ret.to_ne_bytes());

                // According to the runtime environment specification, the return value is two
                // consecutive I32s representing the length and size of the SCALE-encoded
                // return value.
                let value_size = u32::try_from(ret >> 32).unwrap_or_else(|_| unreachable!());
                let value_ptr = u32::try_from(ret & 0xffff_ffff).unwrap_or_else(|_| unreachable!());

                if value_size.saturating_add(value_ptr)
                    <= u32::from(self.inner.vm.memory_size()) * 64 * 1024
                {
                    return HostVm::Finished(Finished {
                        inner: self.inner,
                        value_ptr,
                        value_size,
                    });
                }
                let error = Error::ReturnedPtrOutOfRange {
                    pointer: value_ptr,
                    size: value_size,
                    memory_size: u32::from(self.inner.vm.memory_size()) * 64 * 1024,
                };

                return HostVm::Error {
                    prototype: self.inner.into_prototype(),
                    error,
                };
            }

            Ok(vm::ExecOutcome::Finished {
                return_value: Ok(return_value),
            }) => {
                // The Wasm function has successfully returned, but the specs require that it
                // returns a `i64`.
                return HostVm::Error {
                    prototype: self.inner.into_prototype(),
                    error: Error::BadReturnValue {
                        actual: return_value.map(|v| v.ty()),
                    },
                };
            }

            Ok(vm::ExecOutcome::Finished {
                return_value: Err(err),
            }) => {
                return HostVm::Error {
                    error: Error::Trap(err),
                    prototype: self.inner.into_prototype(),
                };
            }

            Err(vm::RunErr::BadValueTy { .. }) => {
                // Tried to inject back the value returned by a host function, but it doesn't
                // match what the Wasm code expects. Given that we check the host function
                // signatures at initialization, this indicates a bug in this implementation.
                unreachable!()
            }

            Err(vm::RunErr::Poisoned) => {
                // Can only happen if there's a bug somewhere.
                unreachable!()
            }
        };

        // The Wasm code has called an host_fn. The `id` is a value that we passed
        // at initialization, and corresponds to an index in `registered_functions`.
        let host_fn = match self.inner.common.registered_functions.get(id) {
            Some(FunctionImport::Resolved(f)) => *f,
            Some(FunctionImport::Unresolved { name, module }) => {
                return HostVm::Error {
                    error: Error::UnresolvedFunctionCalled {
                        function: name.clone(),
                        module_name: module.clone(),
                    },
                    prototype: self.inner.into_prototype(),
                };
            }
            None => unreachable!(),
        };

        // Passed a parameter index. Produces an `impl AsRef<[u8]>`.
        macro_rules! expect_pointer_size {
            ($num:expr) => {{
                let val = match &params[$num] {
                    vm::WasmValue::I64(v) => u64::from_ne_bytes(v.to_ne_bytes()),
                    // The signatures are checked at initialization and the Wasm VM ensures that
                    // the proper parameter types are provided.
                    _ => unreachable!(),
                };

                let len = u32::try_from(val >> 32).unwrap_or_else(|_| unreachable!());
                let ptr = u32::try_from(val & 0xffffffff).unwrap_or_else(|_| unreachable!());

                let result = self.inner.vm.read_memory(ptr, len);
                match result {
                    Ok(v) => v,
                    Err(vm::OutOfBoundsError) => {
                        drop(result);
                        return HostVm::Error {
                            error: Error::ParamOutOfRange {
                                function: host_fn.name(),
                                param_num: $num,
                                pointer: ptr,
                                length: len,
                            },
                            prototype: self.inner.into_prototype(),
                        };
                    }
                }
            }};
        }

        macro_rules! expect_pointer_size_raw {
            ($num:expr) => {{
                let val = match &params[$num] {
                    vm::WasmValue::I64(v) => u64::from_ne_bytes(v.to_ne_bytes()),
                    // The signatures are checked at initialization and the Wasm VM ensures that
                    // the proper parameter types are provided.
                    _ => unreachable!(),
                };

                let len = u32::try_from(val >> 32).unwrap_or_else(|_| unreachable!());
                let ptr = u32::try_from(val & 0xffffffff).unwrap_or_else(|_| unreachable!());

                if len.saturating_add(ptr) > u32::from(self.inner.vm.memory_size()) * 64 * 1024 {
                    return HostVm::Error {
                        error: Error::ParamOutOfRange {
                            function: host_fn.name(),
                            param_num: $num,
                            pointer: ptr,
                            length: len,
                        },
                        prototype: self.inner.into_prototype(),
                    };
                }

                (ptr, len)
            }};
        }

        macro_rules! expect_pointer_constant_size {
            ($num:expr, $size:expr) => {{
                let ptr = match params[$num] {
                    vm::WasmValue::I32(v) => u32::from_ne_bytes(v.to_ne_bytes()),
                    // The signatures are checked at initialization and the Wasm VM ensures that
                    // the proper parameter types are provided.
                    _ => unreachable!(),
                };

                let result = self.inner.vm.read_memory(ptr, $size);
                match result {
                    Ok(v) => {
                        *<&[u8; $size]>::try_from(v.as_ref()).unwrap_or_else(|_| unreachable!())
                    }
                    Err(vm::OutOfBoundsError) => {
                        drop(result);
                        return HostVm::Error {
                            error: Error::ParamOutOfRange {
                                function: host_fn.name(),
                                param_num: $num,
                                pointer: ptr,
                                length: $size,
                            },
                            prototype: self.inner.into_prototype(),
                        };
                    }
                }
            }};
        }

        macro_rules! expect_pointer_constant_size_raw {
            ($num:expr, $size:expr) => {{
                let ptr = match params[$num] {
                    vm::WasmValue::I32(v) => u32::from_ne_bytes(v.to_ne_bytes()),
                    // The signatures are checked at initialization and the Wasm VM ensures that
                    // the proper parameter types are provided.
                    _ => unreachable!(),
                };

                if u32::saturating_add($size, ptr)
                    > u32::from(self.inner.vm.memory_size()) * 64 * 1024
                {
                    return HostVm::Error {
                        error: Error::ParamOutOfRange {
                            function: host_fn.name(),
                            param_num: $num,
                            pointer: ptr,
                            length: $size,
                        },
                        prototype: self.inner.into_prototype(),
                    };
                }

                ptr
            }};
        }

        macro_rules! expect_u32 {
            ($num:expr) => {{
                match &params[$num] {
                    vm::WasmValue::I32(v) => u32::from_ne_bytes(v.to_ne_bytes()),
                    // The signatures are checked at initialization and the Wasm VM ensures that
                    // the proper parameter types are provided.
                    _ => unreachable!(),
                }
            }};
        }

        macro_rules! expect_offchain_storage_kind {
            ($num:expr) => {{
                match &params[$num] {
                    // `0` indicates `StorageKind::PERSISTENT`, the only kind of offchain
                    // storage that is available.
                    vm::WasmValue::I32(0) => true,
                    // `1` indicates `StorageKind::LOCAL`, which is valid but has never been
                    // implemented in Substrate.
                    vm::WasmValue::I32(1) => false,
                    vm::WasmValue::I32(_) => {
                        return HostVm::Error {
                            error: Error::ParamDecodeError,
                            prototype: self.inner.into_prototype(),
                        };
                    }
                    // The signatures are checked at initialization and the Wasm VM ensures that
                    // the proper parameter types are provided.
                    _ => unreachable!(),
                }
            }};
        }

        macro_rules! expect_state_version {
            ($num:expr) => {{
                match &params[$num] {
                    vm::WasmValue::I32(0) => TrieEntryVersion::V0,
                    vm::WasmValue::I32(1) => TrieEntryVersion::V1,
                    vm::WasmValue::I32(_) => {
                        return HostVm::Error {
                            error: Error::ParamDecodeError,
                            prototype: self.inner.into_prototype(),
                        };
                    }
                    // The signatures are checked at initialization and the Wasm VM ensures that
                    // the proper parameter types are provided.
                    _ => unreachable!(),
                }
            }};
        }

        // TODO: implement all functions and remove this macro
        macro_rules! host_fn_not_implemented {
            () => {{
                return HostVm::Error {
                    error: Error::HostFunctionNotImplemented {
                        function: host_fn.name(),
                    },
                    prototype: self.inner.into_prototype(),
                };
            }};
        }

        // Handle the function calls.
        // Some of these enum variants simply change the state of `self`, while most of them
        // instead return an `ExternalVm` to the user.
        match host_fn {
            HostFunction::ext_storage_set_version_1 => {
                let (key_ptr, key_size) = expect_pointer_size_raw!(0);
                let (value_ptr, value_size) = expect_pointer_size_raw!(1);
                HostVm::ExternalStorageSet(ExternalStorageSet {
                    key_ptr,
                    key_size,
                    child_trie_ptr_size: None,
                    value: Some((value_ptr, value_size)),
                    inner: self.inner,
                })
            }
            HostFunction::ext_storage_get_version_1 => {
                let (key_ptr, key_size) = expect_pointer_size_raw!(0);
                HostVm::ExternalStorageGet(ExternalStorageGet {
                    key_ptr,
                    key_size,
                    child_trie_ptr_size: None,
                    calling: id,
                    value_out_ptr: None,
                    offset: 0,
                    max_size: u32::MAX,
                    inner: self.inner,
                })
            }
            HostFunction::ext_storage_read_version_1 => {
                let (key_ptr, key_size) = expect_pointer_size_raw!(0);
                let (value_out_ptr, value_out_size) = expect_pointer_size_raw!(1);
                let offset = expect_u32!(2);
                HostVm::ExternalStorageGet(ExternalStorageGet {
                    key_ptr,
                    key_size,
                    child_trie_ptr_size: None,
                    calling: id,
                    value_out_ptr: Some(value_out_ptr),
                    offset,
                    max_size: value_out_size,
                    inner: self.inner,
                })
            }
            HostFunction::ext_storage_clear_version_1 => {
                let (key_ptr, key_size) = expect_pointer_size_raw!(0);
                HostVm::ExternalStorageSet(ExternalStorageSet {
                    key_ptr,
                    key_size,
                    child_trie_ptr_size: None,
                    value: None,
                    inner: self.inner,
                })
            }
            HostFunction::ext_storage_exists_version_1 => {
                let (key_ptr, key_size) = expect_pointer_size_raw!(0);
                HostVm::ExternalStorageGet(ExternalStorageGet {
                    key_ptr,
                    key_size,
                    child_trie_ptr_size: None,
                    calling: id,
                    value_out_ptr: None,
                    offset: 0,
                    max_size: 0,
                    inner: self.inner,
                })
            }
            HostFunction::ext_storage_clear_prefix_version_1 => {
                let (prefix_ptr, prefix_size) = expect_pointer_size_raw!(0);
                HostVm::ExternalStorageClearPrefix(ExternalStorageClearPrefix {
                    prefix_ptr_size: Some((prefix_ptr, prefix_size)),
                    child_trie_ptr_size: None,
                    inner: self.inner,
                    max_keys_to_remove: None,
                    calling: id,
                })
            }
            HostFunction::ext_storage_clear_prefix_version_2 => {
                let (prefix_ptr, prefix_size) = expect_pointer_size_raw!(0);

                let max_keys_to_remove = {
                    let input = expect_pointer_size!(1);
                    let parsing_result: Result<_, nom::Err<(&[u8], nom::error::ErrorKind)>> =
                        nom::Parser::parse(
                            &mut nom::combinator::all_consuming(util::nom_option_decode(
                                nom::number::streaming::le_u32,
                            )),
                            input.as_ref(),
                        )
                        .map(|(_, parse_result)| parse_result);

                    match parsing_result {
                        Ok(val) => Ok(val),
                        Err(_) => Err(()),
                    }
                };

                let max_keys_to_remove = match max_keys_to_remove {
                    Ok(l) => l,
                    Err(()) => {
                        return HostVm::Error {
                            error: Error::ParamDecodeError,
                            prototype: self.inner.into_prototype(),
                        };
                    }
                };

                HostVm::ExternalStorageClearPrefix(ExternalStorageClearPrefix {
                    prefix_ptr_size: Some((prefix_ptr, prefix_size)),
                    child_trie_ptr_size: None,
                    inner: self.inner,
                    max_keys_to_remove,
                    calling: id,
                })
            }
            HostFunction::ext_storage_root_version_1 => {
                HostVm::ExternalStorageRoot(ExternalStorageRoot {
                    inner: self.inner,
                    calling: id,
                    child_trie_ptr_size: None,
                })
            }
            HostFunction::ext_storage_root_version_2 => {
                // The `ext_storage_root_version_2` host function gets passed as parameter the
                // state version of the runtime. This is in fact completely unnecessary as the
                // same information is found in the runtime specification, and this parameter
                // should be considered as a historical accident. We verify that the version
                // provided as parameter is the same as the one in the specification.
                let version_param = expect_state_version!(0);
                let version_spec = self
                    .inner
                    .common
                    .runtime_version
                    .as_ref()
                    .unwrap_or_else(|| unreachable!())
                    .decode()
                    .state_version
                    .unwrap_or(TrieEntryVersion::V0);

                if version_param != version_spec {
                    return HostVm::Error {
                        error: Error::StateVersionMismatch {
                            parameter: version_param,
                            specification: version_spec,
                        },
                        prototype: self.inner.into_prototype(),
                    };
                }

                HostVm::ExternalStorageRoot(ExternalStorageRoot {
                    inner: self.inner,
                    calling: id,
                    child_trie_ptr_size: None,
                })
            }
            HostFunction::ext_storage_changes_root_version_1 => {
                // The changes trie is an obsolete attempt at having a second trie containing, for
                // each storage item, the latest block height where this item has been modified.
                // When this function returns `None`, it indicates that the changes trie is
                // disabled. While this function used to be called by the runtimes of
                // Westend/Polkadot/Kusama (and maybe others), it has never returned anything else
                // but `None`. The entire changes trie mechanism was ultimately removed in
                // October 2021.
                // This function is no longer called by recent runtimes, but must be preserved for
                // backwards compatibility.
                self.inner.alloc_write_and_return_pointer_size(
                    HostFunction::ext_storage_changes_root_version_1.name(),
                    iter::once(&[0][..]),
                )
            }
            HostFunction::ext_storage_next_key_version_1 => {
                let (key_ptr, key_size) = expect_pointer_size_raw!(0);
                HostVm::ExternalStorageNextKey(ExternalStorageNextKey {
                    key_ptr,
                    key_size,
                    child_trie_ptr_size: None,
                    inner: self.inner,
                })
            }
            HostFunction::ext_storage_append_version_1 => {
                let (key_ptr, key_size) = expect_pointer_size_raw!(0);
                let (value_ptr, value_size) = expect_pointer_size_raw!(1);
                HostVm::ExternalStorageAppend(ExternalStorageAppend {
                    key_ptr,
                    key_size,
                    value_ptr,
                    value_size,
                    inner: self.inner,
                })
            }
            HostFunction::ext_storage_start_transaction_version_1 => {
                // TODO: a maximum depth is important in order to prevent a malicious runtime from crashing the client, but the depth needs to be the same as in Substrate; figure out
                self.inner.storage_transaction_depth += 1;
                HostVm::StartStorageTransaction(StartStorageTransaction { inner: self.inner })
            }
            HostFunction::ext_storage_rollback_transaction_version_1 => {
                if self.inner.storage_transaction_depth == 0 {
                    return HostVm::Error {
                        error: Error::NoActiveTransaction,
                        prototype: self.inner.into_prototype(),
                    };
                }

                self.inner.storage_transaction_depth -= 1;
                HostVm::EndStorageTransaction {
                    resume: EndStorageTransaction { inner: self.inner },
                    rollback: true,
                }
            }
            HostFunction::ext_storage_commit_transaction_version_1 => {
                if self.inner.storage_transaction_depth == 0 {
                    return HostVm::Error {
                        error: Error::NoActiveTransaction,
                        prototype: self.inner.into_prototype(),
                    };
                }

                self.inner.storage_transaction_depth -= 1;
                HostVm::EndStorageTransaction {
                    resume: EndStorageTransaction { inner: self.inner },
                    rollback: false,
                }
            }
            HostFunction::ext_storage_proof_size_storage_proof_size_version_1 => {
                match self.inner.storage_proof_size_behavior {
                    StorageProofSizeBehavior::ConstantReturnValue(value) => {
                        HostVm::ReadyToRun(ReadyToRun {
                            inner: self.inner,
                            resume_value: Some(vm::WasmValue::I64(i64::from_ne_bytes(
                                value.to_ne_bytes(),
                            ))),
                        })
                    }
                    StorageProofSizeBehavior::Unimplemented => HostVm::Error {
                        error: Error::HostFunctionNotImplemented {
                            function: host_fn.name(),
                        },
                        prototype: self.inner.into_prototype(),
                    },
                }
            }
            HostFunction::ext_default_child_storage_get_version_1 => {
                let (child_trie_ptr, child_trie_size) = expect_pointer_size_raw!(0);
                let (key_ptr, key_size) = expect_pointer_size_raw!(1);
                HostVm::ExternalStorageGet(ExternalStorageGet {
                    key_ptr,
                    key_size,
                    child_trie_ptr_size: Some((child_trie_ptr, child_trie_size)),
                    calling: id,
                    value_out_ptr: None,
                    offset: 0,
                    max_size: u32::MAX,
                    inner: self.inner,
                })
            }
            HostFunction::ext_default_child_storage_read_version_1 => {
                let (child_trie_ptr, child_trie_size) = expect_pointer_size_raw!(0);
                let (key_ptr, key_size) = expect_pointer_size_raw!(1);
                let (value_out_ptr, value_out_size) = expect_pointer_size_raw!(2);
                let offset = expect_u32!(3);
                HostVm::ExternalStorageGet(ExternalStorageGet {
                    key_ptr,
                    key_size,
                    child_trie_ptr_size: Some((child_trie_ptr, child_trie_size)),
                    calling: id,
                    value_out_ptr: Some(value_out_ptr),
                    offset,
                    max_size: value_out_size,
                    inner: self.inner,
                })
            }
            HostFunction::ext_default_child_storage_storage_kill_version_1 => {
                let (child_trie_ptr, child_trie_size) = expect_pointer_size_raw!(0);
                HostVm::ExternalStorageClearPrefix(ExternalStorageClearPrefix {
                    prefix_ptr_size: None,
                    child_trie_ptr_size: Some((child_trie_ptr, child_trie_size)),
                    inner: self.inner,
                    max_keys_to_remove: None,
                    calling: id,
                })
            }
            HostFunction::ext_default_child_storage_storage_kill_version_2
            | HostFunction::ext_default_child_storage_storage_kill_version_3 => {
                let (child_trie_ptr, child_trie_size) = expect_pointer_size_raw!(0);

                let max_keys_to_remove = {
                    let input = expect_pointer_size!(1);
                    let parsing_result: Result<_, nom::Err<(&[u8], nom::error::ErrorKind)>> =
                        nom::Parser::parse(
                            &mut nom::combinator::all_consuming(util::nom_option_decode(
                                nom::number::streaming::le_u32,
                            )),
                            input.as_ref(),
                        )
                        .map(|(_, parse_result)| parse_result);

                    match parsing_result {
                        Ok(val) => Ok(val),
                        Err(_) => Err(()),
                    }
                };

                let max_keys_to_remove = match max_keys_to_remove {
                    Ok(l) => l,
                    Err(()) => {
                        return HostVm::Error {
                            error: Error::ParamDecodeError,
                            prototype: self.inner.into_prototype(),
                        };
                    }
                };

                HostVm::ExternalStorageClearPrefix(ExternalStorageClearPrefix {
                    prefix_ptr_size: None,
                    child_trie_ptr_size: Some((child_trie_ptr, child_trie_size)),
                    inner: self.inner,
                    max_keys_to_remove,
                    calling: id,
                })
            }
            HostFunction::ext_default_child_storage_clear_prefix_version_1 => {
                let (child_trie_ptr, child_trie_size) = expect_pointer_size_raw!(0);
                let (prefix_ptr, prefix_size) = expect_pointer_size_raw!(1);
                HostVm::ExternalStorageClearPrefix(ExternalStorageClearPrefix {
                    prefix_ptr_size: Some((prefix_ptr, prefix_size)),
                    child_trie_ptr_size: Some((child_trie_ptr, child_trie_size)),
                    inner: self.inner,
                    max_keys_to_remove: None,
                    calling: id,
                })
            }
            HostFunction::ext_default_child_storage_clear_prefix_version_2 => {
                let (child_trie_ptr, child_trie_size) = expect_pointer_size_raw!(0);
                let (prefix_ptr, prefix_size) = expect_pointer_size_raw!(1);

                let max_keys_to_remove = {
                    let input = expect_pointer_size!(2);
                    let parsing_result: Result<_, nom::Err<(&[u8], nom::error::ErrorKind)>> =
                        nom::Parser::parse(
                            &mut nom::combinator::all_consuming(util::nom_option_decode(
                                nom::number::streaming::le_u32,
                            )),
                            input.as_ref(),
                        )
                        .map(|(_, parse_result)| parse_result);

                    match parsing_result {
                        Ok(val) => Ok(val),
                        Err(_) => Err(()),
                    }
                };

                let max_keys_to_remove = match max_keys_to_remove {
                    Ok(l) => l,
                    Err(()) => {
                        return HostVm::Error {
                            error: Error::ParamDecodeError,
                            prototype: self.inner.into_prototype(),
                        };
                    }
                };

                HostVm::ExternalStorageClearPrefix(ExternalStorageClearPrefix {
                    prefix_ptr_size: Some((prefix_ptr, prefix_size)),
                    child_trie_ptr_size: Some((child_trie_ptr, child_trie_size)),
                    inner: self.inner,
                    max_keys_to_remove,
                    calling: id,
                })
            }
            HostFunction::ext_default_child_storage_set_version_1 => {
                let (child_trie_ptr, child_trie_size) = expect_pointer_size_raw!(0);
                let (key_ptr, key_size) = expect_pointer_size_raw!(1);
                let (value_ptr, value_size) = expect_pointer_size_raw!(2);
                HostVm::ExternalStorageSet(ExternalStorageSet {
                    key_ptr,
                    key_size,
                    child_trie_ptr_size: Some((child_trie_ptr, child_trie_size)),
                    value: Some((value_ptr, value_size)),
                    inner: self.inner,
                })
            }
            HostFunction::ext_default_child_storage_clear_version_1 => {
                let (child_trie_ptr, child_trie_size) = expect_pointer_size_raw!(0);
                let (key_ptr, key_size) = expect_pointer_size_raw!(1);
                HostVm::ExternalStorageSet(ExternalStorageSet {
                    key_ptr,
                    key_size,
                    child_trie_ptr_size: Some((child_trie_ptr, child_trie_size)),
                    value: None,
                    inner: self.inner,
                })
            }
            HostFunction::ext_default_child_storage_exists_version_1 => {
                let (child_trie_ptr, child_trie_size) = expect_pointer_size_raw!(0);
                let (key_ptr, key_size) = expect_pointer_size_raw!(1);
                HostVm::ExternalStorageGet(ExternalStorageGet {
                    key_ptr,
                    key_size,
                    child_trie_ptr_size: Some((child_trie_ptr, child_trie_size)),
                    calling: id,
                    value_out_ptr: None,
                    offset: 0,
                    max_size: 0,
                    inner: self.inner,
                })
            }
            HostFunction::ext_default_child_storage_next_key_version_1 => {
                let (child_trie_ptr, child_trie_size) = expect_pointer_size_raw!(0);
                let (key_ptr, key_size) = expect_pointer_size_raw!(1);
                HostVm::ExternalStorageNextKey(ExternalStorageNextKey {
                    key_ptr,
                    key_size,
                    child_trie_ptr_size: Some((child_trie_ptr, child_trie_size)),
                    inner: self.inner,
                })
            }
            HostFunction::ext_default_child_storage_root_version_1 => {
                let (child_trie_ptr, child_trie_size) = expect_pointer_size_raw!(0);
                HostVm::ExternalStorageRoot(ExternalStorageRoot {
                    inner: self.inner,
                    calling: id,
                    child_trie_ptr_size: Some((child_trie_ptr, child_trie_size)),
                })
            }
            HostFunction::ext_default_child_storage_root_version_2 => {
                let (child_trie_ptr, child_trie_size) = expect_pointer_size_raw!(0);

                // The `ext_default_child_storage_root_version_2` host function gets passed as
                // parameter the state version of the runtime. This is in fact completely
                // unnecessary as the same information is found in the runtime specification, and
                // this parameter should be considered as a historical accident. We verify that the
                // version provided as parameter is the same as the one in the specification.
                let version_param = expect_state_version!(1);
                let version_spec = self
                    .inner
                    .common
                    .runtime_version
                    .as_ref()
                    .unwrap_or_else(|| unreachable!())
                    .decode()
                    .state_version
                    .unwrap_or(TrieEntryVersion::V0);

                if version_param != version_spec {
                    return HostVm::Error {
                        error: Error::StateVersionMismatch {
                            parameter: version_param,
                            specification: version_spec,
                        },
                        prototype: self.inner.into_prototype(),
                    };
                }

                HostVm::ExternalStorageRoot(ExternalStorageRoot {
                    inner: self.inner,
                    calling: id,
                    child_trie_ptr_size: Some((child_trie_ptr, child_trie_size)),
                })
            }
            HostFunction::ext_crypto_ed25519_public_keys_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_ed25519_generate_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_ed25519_sign_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_ed25519_verify_version_1
            | HostFunction::ext_crypto_ed25519_batch_verify_version_1 => {
                let is_batch_verification = matches!(
                    host_fn,
                    HostFunction::ext_crypto_ed25519_batch_verify_version_1
                );

                if is_batch_verification && self.inner.signatures_batch_verification.is_none() {
                    return HostVm::Error {
                        error: Error::BatchVerifyWithoutStarting,
                        prototype: self.inner.into_prototype(),
                    };
                }

                let (message_ptr, message_size) = expect_pointer_size_raw!(1);
                HostVm::SignatureVerification(SignatureVerification {
                    algorithm: SignatureVerificationAlgorithm::Ed25519,
                    signature_ptr: expect_pointer_constant_size_raw!(0, 64),
                    public_key_ptr: expect_pointer_constant_size_raw!(2, 32),
                    message_ptr,
                    message_size,
                    inner: self.inner,
                    is_batch_verification,
                })
            }
            HostFunction::ext_crypto_sr25519_public_keys_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_sr25519_generate_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_sr25519_sign_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_sr25519_verify_version_1
            | HostFunction::ext_crypto_sr25519_batch_verify_version_1 => {
                let is_batch_verification = matches!(
                    host_fn,
                    HostFunction::ext_crypto_sr25519_batch_verify_version_1
                );

                if is_batch_verification && self.inner.signatures_batch_verification.is_none() {
                    return HostVm::Error {
                        error: Error::BatchVerifyWithoutStarting,
                        prototype: self.inner.into_prototype(),
                    };
                }

                let (message_ptr, message_size) = expect_pointer_size_raw!(1);
                HostVm::SignatureVerification(SignatureVerification {
                    algorithm: SignatureVerificationAlgorithm::Sr25519V1,
                    signature_ptr: expect_pointer_constant_size_raw!(0, 64),
                    public_key_ptr: expect_pointer_constant_size_raw!(2, 32),
                    message_ptr,
                    message_size,
                    inner: self.inner,
                    is_batch_verification,
                })
            }
            HostFunction::ext_crypto_sr25519_verify_version_2 => {
                let (message_ptr, message_size) = expect_pointer_size_raw!(1);
                HostVm::SignatureVerification(SignatureVerification {
                    algorithm: SignatureVerificationAlgorithm::Sr25519V2,
                    signature_ptr: expect_pointer_constant_size_raw!(0, 64),
                    public_key_ptr: expect_pointer_constant_size_raw!(2, 32),
                    message_ptr,
                    message_size,
                    inner: self.inner,
                    is_batch_verification: false,
                })
            }
            HostFunction::ext_crypto_ecdsa_generate_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_ecdsa_sign_version_1 => {
                // NOTE: safe to unwrap here because we supply the nn to blake2b fn
                let data = <[u8; 32]>::try_from(
                    blake2_rfc::blake2b::blake2b(32, &[], expect_pointer_size!(0).as_ref())
                        .as_bytes(),
                )
                .unwrap_or_else(|_| unreachable!());
                let message = libsecp256k1::Message::parse(&data);

                if let Ok(sc) =
                    libsecp256k1::SecretKey::parse(&expect_pointer_constant_size!(1, 32))
                {
                    let (sig, ri) = libsecp256k1::sign(&message, &sc);

                    // NOTE: the function returns 2 slices: signature (64 bytes) and recovery ID (1 byte; AS A SLICE)
                    self.inner.alloc_write_and_return_pointer(
                        host_fn.name(),
                        [&sig.serialize()[..], &[ri.serialize()]].into_iter(),
                    )
                } else {
                    HostVm::Error {
                        error: Error::ParamDecodeError,
                        prototype: self.inner.into_prototype(),
                    }
                }
            }
            HostFunction::ext_crypto_ecdsa_public_keys_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_ecdsa_verify_version_1
            | HostFunction::ext_crypto_ecdsa_batch_verify_version_1 => {
                let is_batch_verification = matches!(
                    host_fn,
                    HostFunction::ext_crypto_ecdsa_batch_verify_version_1
                );

                if is_batch_verification && self.inner.signatures_batch_verification.is_none() {
                    return HostVm::Error {
                        error: Error::BatchVerifyWithoutStarting,
                        prototype: self.inner.into_prototype(),
                    };
                }

                let (message_ptr, message_size) = expect_pointer_size_raw!(1);
                HostVm::SignatureVerification(SignatureVerification {
                    algorithm: SignatureVerificationAlgorithm::Ecdsa,
                    signature_ptr: expect_pointer_constant_size_raw!(0, 65),
                    public_key_ptr: expect_pointer_constant_size_raw!(2, 33),
                    message_ptr,
                    message_size,
                    inner: self.inner,
                    is_batch_verification,
                })
            }
            HostFunction::ext_crypto_ecdsa_verify_version_2 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_ecdsa_sign_prehashed_version_1 => {
                // TODO: seems misimplemented, see https://spec.polkadot.network/#id-ext_crypto_ecdsa_sign_prehashed
                let message = libsecp256k1::Message::parse(&expect_pointer_constant_size!(0, 32));

                if let Ok(sc) =
                    libsecp256k1::SecretKey::parse(&expect_pointer_constant_size!(1, 32))
                {
                    let (sig, ri) = libsecp256k1::sign(&message, &sc);

                    // NOTE: the function returns 2 slices: signature (64 bytes) and recovery ID (1 byte; AS A SLICE)
                    self.inner.alloc_write_and_return_pointer(
                        host_fn.name(),
                        [&sig.serialize()[..], &[ri.serialize()]].into_iter(),
                    )
                } else {
                    HostVm::Error {
                        error: Error::ParamDecodeError,
                        prototype: self.inner.into_prototype(),
                    }
                }
            }
            HostFunction::ext_crypto_ecdsa_verify_prehashed_version_1 => {
                HostVm::SignatureVerification(SignatureVerification {
                    algorithm: SignatureVerificationAlgorithm::EcdsaPrehashed,
                    signature_ptr: expect_pointer_constant_size_raw!(0, 65),
                    public_key_ptr: expect_pointer_constant_size_raw!(2, 33),
                    message_ptr: expect_pointer_constant_size_raw!(1, 32),
                    message_size: 32,
                    inner: self.inner,
                    is_batch_verification: false,
                })
            }

            HostFunction::ext_crypto_secp256k1_ecdsa_recover_version_1
            | HostFunction::ext_crypto_secp256k1_ecdsa_recover_version_2 => {
                let sig = expect_pointer_constant_size!(0, 65);
                let msg = expect_pointer_constant_size!(1, 32);
                let is_v2 = matches!(
                    host_fn,
                    HostFunction::ext_crypto_secp256k1_ecdsa_recover_version_2
                );

                let result = {
                    let rs = if is_v2 {
                        libsecp256k1::Signature::parse_standard_slice(&sig[0..64])
                    } else {
                        libsecp256k1::Signature::parse_overflowing_slice(&sig[0..64])
                    };

                    if let Ok(rs) = rs {
                        let v = libsecp256k1::RecoveryId::parse(if sig[64] > 26 {
                            sig[64] - 27
                        } else {
                            sig[64]
                        });

                        if let Ok(v) = v {
                            let pubkey = libsecp256k1::recover(
                                &libsecp256k1::Message::parse_slice(&msg)
                                    .unwrap_or_else(|_| unreachable!()),
                                &rs,
                                &v,
                            );

                            if let Ok(pubkey) = pubkey {
                                let mut res = Vec::with_capacity(65);
                                res.push(0);
                                res.extend_from_slice(&pubkey.serialize()[1..65]);
                                res
                            } else {
                                vec![1, 2]
                            }
                        } else {
                            vec![1, 1]
                        }
                    } else {
                        vec![1, 0]
                    }
                };

                self.inner
                    .alloc_write_and_return_pointer_size(host_fn.name(), iter::once(&result))
            }
            HostFunction::ext_crypto_secp256k1_ecdsa_recover_compressed_version_1
            | HostFunction::ext_crypto_secp256k1_ecdsa_recover_compressed_version_2 => {
                let sig = expect_pointer_constant_size!(0, 65);
                let msg = expect_pointer_constant_size!(1, 32);
                let is_v2 = matches!(
                    host_fn,
                    HostFunction::ext_crypto_secp256k1_ecdsa_recover_compressed_version_2
                );

                let result = {
                    let rs = if is_v2 {
                        libsecp256k1::Signature::parse_standard_slice(&sig[0..64])
                    } else {
                        libsecp256k1::Signature::parse_overflowing_slice(&sig[0..64])
                    };

                    if let Ok(rs) = rs {
                        let v = libsecp256k1::RecoveryId::parse(if sig[64] > 26 {
                            sig[64] - 27
                        } else {
                            sig[64]
                        });

                        if let Ok(v) = v {
                            let pubkey = libsecp256k1::recover(
                                &libsecp256k1::Message::parse_slice(&msg)
                                    .unwrap_or_else(|_| unreachable!()),
                                &rs,
                                &v,
                            );

                            if let Ok(pubkey) = pubkey {
                                let mut res = Vec::with_capacity(34);
                                res.push(0);
                                res.extend_from_slice(&pubkey.serialize_compressed());
                                res
                            } else {
                                vec![1, 2]
                            }
                        } else {
                            vec![1, 1]
                        }
                    } else {
                        vec![1, 0]
                    }
                };

                self.inner
                    .alloc_write_and_return_pointer_size(host_fn.name(), iter::once(&result))
            }
            HostFunction::ext_crypto_start_batch_verify_version_1 => {
                if self.inner.signatures_batch_verification.is_some() {
                    return HostVm::Error {
                        error: Error::AlreadyBatchVerify,
                        prototype: self.inner.into_prototype(),
                    };
                }

                self.inner.signatures_batch_verification = Some(true);

                HostVm::ReadyToRun(ReadyToRun {
                    resume_value: None,
                    inner: self.inner,
                })
            }
            HostFunction::ext_crypto_finish_batch_verify_version_1 => {
                let Some(outcome) = self.inner.signatures_batch_verification.take() else {
                    return HostVm::Error {
                        error: Error::NoBatchVerify,
                        prototype: self.inner.into_prototype(),
                    };
                };

                HostVm::ReadyToRun(ReadyToRun {
                    resume_value: Some(vm::WasmValue::I32(if outcome { 1 } else { 0 })),
                    inner: self.inner,
                })
            }
            HostFunction::ext_hashing_keccak_256_version_1 => {
                let hash =
                    <sha3::Keccak256 as sha3::Digest>::digest(expect_pointer_size!(0).as_ref());
                self.inner
                    .alloc_write_and_return_pointer(host_fn.name(), iter::once(&hash))
            }
            HostFunction::ext_hashing_keccak_512_version_1 => {
                let hash =
                    <sha3::Keccak512 as sha3::Digest>::digest(expect_pointer_size!(0).as_ref());
                self.inner
                    .alloc_write_and_return_pointer(host_fn.name(), iter::once(&hash))
            }
            HostFunction::ext_hashing_sha2_256_version_1 => {
                let hash = <sha2::Sha256 as sha2::Digest>::digest(expect_pointer_size!(0).as_ref());
                self.inner
                    .alloc_write_and_return_pointer(host_fn.name(), iter::once(&hash))
            }
            HostFunction::ext_hashing_blake2_128_version_1 => {
                let out = {
                    let data = expect_pointer_size!(0);
                    blake2_rfc::blake2b::blake2b(16, &[], data.as_ref())
                };

                self.inner
                    .alloc_write_and_return_pointer(host_fn.name(), iter::once(out.as_bytes()))
            }
            HostFunction::ext_hashing_blake2_256_version_1 => {
                let out = {
                    let data = expect_pointer_size!(0);
                    blake2_rfc::blake2b::blake2b(32, &[], data.as_ref())
                };

                self.inner
                    .alloc_write_and_return_pointer(host_fn.name(), iter::once(out.as_bytes()))
            }
            HostFunction::ext_hashing_twox_64_version_1 => {
                let r0 = {
                    let data = expect_pointer_size!(0);
                    twox_hash::XxHash64::oneshot(0, data.as_ref())
                };

                self.inner
                    .alloc_write_and_return_pointer(host_fn.name(), iter::once(&r0.to_le_bytes()))
            }
            HostFunction::ext_hashing_twox_128_version_1 => {
                let [r0, r1] = {
                    let data = expect_pointer_size!(0);
                    let data = data.as_ref();
                    [
                        twox_hash::XxHash64::oneshot(0, data),
                        twox_hash::XxHash64::oneshot(1, data),
                    ]
                };

                self.inner.alloc_write_and_return_pointer(
                    host_fn.name(),
                    iter::once(&r0.to_le_bytes()).chain(iter::once(&r1.to_le_bytes())),
                )
            }
            HostFunction::ext_hashing_twox_256_version_1 => {
                let [r0, r1, r2, r3] = {
                    let data = expect_pointer_size!(0);
                    let data = data.as_ref();
                    [
                        twox_hash::XxHash64::oneshot(0, data),
                        twox_hash::XxHash64::oneshot(1, data),
                        twox_hash::XxHash64::oneshot(2, data),
                        twox_hash::XxHash64::oneshot(3, data),
                    ]
                };

                self.inner.alloc_write_and_return_pointer(
                    host_fn.name(),
                    iter::once(&r0.to_le_bytes())
                        .chain(iter::once(&r1.to_le_bytes()))
                        .chain(iter::once(&r2.to_le_bytes()))
                        .chain(iter::once(&r3.to_le_bytes())),
                )
            }
            HostFunction::ext_offchain_index_set_version_1 => {
                let (key_ptr, key_size) = expect_pointer_size_raw!(0);
                let (value_ptr, value_size) = expect_pointer_size_raw!(1);
                HostVm::ExternalOffchainIndexSet(ExternalOffchainIndexSet {
                    key_ptr,
                    key_size,
                    value: Some((value_ptr, value_size)),
                    inner: self.inner,
                })
            }
            HostFunction::ext_offchain_index_clear_version_1 => {
                let (key_ptr, key_size) = expect_pointer_size_raw!(0);
                HostVm::ExternalOffchainIndexSet(ExternalOffchainIndexSet {
                    key_ptr,
                    key_size,
                    value: None,
                    inner: self.inner,
                })
            }
            HostFunction::ext_offchain_is_validator_version_1 => HostVm::ReadyToRun(ReadyToRun {
                inner: self.inner,
                resume_value: Some(vm::WasmValue::I32(1)), // TODO: ask the API user
            }),
            HostFunction::ext_offchain_submit_transaction_version_1 => {
                let (tx_ptr, tx_size) = expect_pointer_size_raw!(0);
                HostVm::OffchainSubmitTransaction(OffchainSubmitTransaction {
                    inner: self.inner,
                    calling: id,
                    tx_ptr,
                    tx_size,
                })
            }
            HostFunction::ext_offchain_network_state_version_1 => {
                host_fn_not_implemented!()
            }
            HostFunction::ext_offchain_timestamp_version_1 => {
                HostVm::OffchainTimestamp(OffchainTimestamp { inner: self.inner })
            }
            HostFunction::ext_offchain_sleep_until_version_1 => {
                host_fn_not_implemented!()
            }
            HostFunction::ext_offchain_random_seed_version_1 => {
                HostVm::OffchainRandomSeed(OffchainRandomSeed {
                    inner: self.inner,
                    calling: id,
                })
            }
            HostFunction::ext_offchain_local_storage_set_version_1 => {
                if expect_offchain_storage_kind!(0) {
                    let (key_ptr, key_size) = expect_pointer_size_raw!(1);
                    let (value_ptr, value_size) = expect_pointer_size_raw!(2);
                    HostVm::ExternalOffchainStorageSet(ExternalOffchainStorageSet {
                        key_ptr,
                        key_size,
                        value: Some((value_ptr, value_size)),
                        old_value: None,
                        inner: self.inner,
                    })
                } else {
                    HostVm::ReadyToRun(ReadyToRun {
                        inner: self.inner,
                        resume_value: None,
                    })
                }
            }
            HostFunction::ext_offchain_local_storage_compare_and_set_version_1 => {
                if expect_offchain_storage_kind!(0) {
                    let (key_ptr, key_size) = expect_pointer_size_raw!(1);
                    let (old_value_ptr, old_value_size) = expect_pointer_size_raw!(2);
                    let (value_ptr, value_size) = expect_pointer_size_raw!(3);
                    HostVm::ExternalOffchainStorageSet(ExternalOffchainStorageSet {
                        key_ptr,
                        key_size,
                        value: Some((value_ptr, value_size)),
                        old_value: Some((old_value_ptr, old_value_size)),
                        inner: self.inner,
                    })
                } else {
                    HostVm::ReadyToRun(ReadyToRun {
                        inner: self.inner,
                        resume_value: Some(vm::WasmValue::I32(0)),
                    })
                }
            }
            HostFunction::ext_offchain_local_storage_get_version_1 => {
                if expect_offchain_storage_kind!(0) {
                    let (key_ptr, key_size) = expect_pointer_size_raw!(1);
                    HostVm::ExternalOffchainStorageGet(ExternalOffchainStorageGet {
                        key_ptr,
                        key_size,
                        calling: id,
                        inner: self.inner,
                    })
                } else {
                    // Write a SCALE-encoded `None`.
                    self.inner
                        .alloc_write_and_return_pointer_size(host_fn.name(), iter::once(&[0]))
                }
            }
            HostFunction::ext_offchain_local_storage_clear_version_1 => {
                if expect_offchain_storage_kind!(0) {
                    let (key_ptr, key_size) = expect_pointer_size_raw!(1);
                    HostVm::ExternalOffchainStorageSet(ExternalOffchainStorageSet {
                        key_ptr,
                        key_size,
                        value: None,
                        old_value: None,
                        inner: self.inner,
                    })
                } else {
                    HostVm::ReadyToRun(ReadyToRun {
                        inner: self.inner,
                        resume_value: None,
                    })
                }
            }
            HostFunction::ext_offchain_http_request_start_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_offchain_http_request_add_header_version_1 => {
                host_fn_not_implemented!()
            }
            HostFunction::ext_offchain_http_request_write_body_version_1 => {
                host_fn_not_implemented!()
            }
            HostFunction::ext_offchain_http_response_wait_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_offchain_http_response_headers_version_1 => {
                host_fn_not_implemented!()
            }
            HostFunction::ext_offchain_http_response_read_body_version_1 => {
                host_fn_not_implemented!()
            }
            HostFunction::ext_trie_blake2_256_root_version_1
            | HostFunction::ext_trie_blake2_256_root_version_2
            | HostFunction::ext_trie_keccak_256_root_version_1
            | HostFunction::ext_trie_keccak_256_root_version_2 => {
                let state_version = if matches!(
                    host_fn,
                    HostFunction::ext_trie_blake2_256_root_version_2
                        | HostFunction::ext_trie_keccak_256_root_version_2
                ) {
                    expect_state_version!(1)
                } else {
                    TrieEntryVersion::V0
                };

                let result = {
                    let input = expect_pointer_size!(0);
                    let parsing_result: Result<_, nom::Err<(&[u8], nom::error::ErrorKind)>> =
                        nom::Parser::parse(
                            &mut nom::combinator::all_consuming(nom::combinator::flat_map(
                                crate::util::nom_scale_compact_usize,
                                |num_elems| {
                                    nom::multi::many_m_n(
                                        num_elems,
                                        num_elems,
                                        (
                                            nom::combinator::flat_map(
                                                crate::util::nom_scale_compact_usize,
                                                nom::bytes::streaming::take,
                                            ),
                                            nom::combinator::flat_map(
                                                crate::util::nom_scale_compact_usize,
                                                nom::bytes::streaming::take,
                                            ),
                                        ),
                                    )
                                },
                            )),
                            input.as_ref(),
                        )
                        .map(|(_, parse_result)| parse_result);

                    match parsing_result {
                        Ok(elements) => Ok(trie::trie_root(
                            state_version,
                            if matches!(
                                host_fn,
                                HostFunction::ext_trie_blake2_256_root_version_1
                                    | HostFunction::ext_trie_blake2_256_root_version_2
                            ) {
                                trie::HashFunction::Blake2
                            } else {
                                trie::HashFunction::Keccak256
                            },
                            &elements[..],
                        )),
                        Err(_) => Err(()),
                    }
                };

                match result {
                    Ok(out) => self
                        .inner
                        .alloc_write_and_return_pointer(host_fn.name(), iter::once(&out)),
                    Err(()) => HostVm::Error {
                        error: Error::ParamDecodeError,
                        prototype: self.inner.into_prototype(),
                    },
                }
            }
            HostFunction::ext_trie_blake2_256_ordered_root_version_1
            | HostFunction::ext_trie_blake2_256_ordered_root_version_2
            | HostFunction::ext_trie_keccak_256_ordered_root_version_1
            | HostFunction::ext_trie_keccak_256_ordered_root_version_2 => {
                let state_version = if matches!(
                    host_fn,
                    HostFunction::ext_trie_blake2_256_ordered_root_version_2
                        | HostFunction::ext_trie_keccak_256_ordered_root_version_2
                ) {
                    expect_state_version!(1)
                } else {
                    TrieEntryVersion::V0
                };

                let result = {
                    let input = expect_pointer_size!(0);
                    let parsing_result: Result<_, nom::Err<(&[u8], nom::error::ErrorKind)>> =
                        nom::Parser::parse(
                            &mut nom::combinator::all_consuming(nom::combinator::flat_map(
                                crate::util::nom_scale_compact_usize,
                                |num_elems| {
                                    nom::multi::many_m_n(
                                        num_elems,
                                        num_elems,
                                        nom::combinator::flat_map(
                                            crate::util::nom_scale_compact_usize,
                                            nom::bytes::streaming::take,
                                        ),
                                    )
                                },
                            )),
                            input.as_ref(),
                        )
                        .map(|(_, parse_result)| parse_result);

                    match parsing_result {
                        Ok(elements) => Ok(trie::ordered_root(
                            state_version,
                            if matches!(
                                host_fn,
                                HostFunction::ext_trie_blake2_256_ordered_root_version_1
                                    | HostFunction::ext_trie_blake2_256_ordered_root_version_2
                            ) {
                                trie::HashFunction::Blake2
                            } else {
                                trie::HashFunction::Keccak256
                            },
                            &elements[..],
                        )),
                        Err(_) => Err(()),
                    }
                };

                match result {
                    Ok(out) => self
                        .inner
                        .alloc_write_and_return_pointer(host_fn.name(), iter::once(&out)),
                    Err(()) => HostVm::Error {
                        error: Error::ParamDecodeError,
                        prototype: self.inner.into_prototype(),
                    },
                }
            }
            HostFunction::ext_trie_blake2_256_verify_proof_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_trie_blake2_256_verify_proof_version_2 => host_fn_not_implemented!(),
            HostFunction::ext_trie_keccak_256_verify_proof_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_trie_keccak_256_verify_proof_version_2 => host_fn_not_implemented!(),
            HostFunction::ext_misc_print_num_version_1 => {
                let num = match params[0] {
                    vm::WasmValue::I64(v) => u64::from_ne_bytes(v.to_ne_bytes()),
                    // The signatures are checked at initialization and the Wasm VM ensures that
                    // the proper parameter types are provided.
                    _ => unreachable!(),
                };

                HostVm::LogEmit(LogEmit {
                    inner: self.inner,
                    log_entry: LogEmitInner::Num(num),
                })
            }
            HostFunction::ext_misc_print_utf8_version_1 => {
                let (str_ptr, str_size) = expect_pointer_size_raw!(0);

                let utf8_check = str::from_utf8(
                    self.inner
                        .vm
                        .read_memory(str_ptr, str_size)
                        .unwrap_or_else(|_| unreachable!())
                        .as_ref(),
                )
                .map(|_| ());
                if let Err(error) = utf8_check {
                    return HostVm::Error {
                        error: Error::Utf8Error {
                            function: host_fn.name(),
                            param_num: 2,
                            error,
                        },
                        prototype: self.inner.into_prototype(),
                    };
                }

                HostVm::LogEmit(LogEmit {
                    inner: self.inner,
                    log_entry: LogEmitInner::Utf8 { str_ptr, str_size },
                })
            }
            HostFunction::ext_misc_print_hex_version_1 => {
                let (data_ptr, data_size) = expect_pointer_size_raw!(0);
                HostVm::LogEmit(LogEmit {
                    inner: self.inner,
                    log_entry: LogEmitInner::Hex {
                        data_ptr,
                        data_size,
                    },
                })
            }
            HostFunction::ext_misc_runtime_version_version_1 => {
                let (wasm_blob_ptr, wasm_blob_size) = expect_pointer_size_raw!(0);
                HostVm::CallRuntimeVersion(CallRuntimeVersion {
                    inner: self.inner,
                    wasm_blob_ptr,
                    wasm_blob_size,
                })
            }
            HostFunction::ext_allocator_malloc_version_1 => {
                let size = expect_u32!(0);

                let ptr = match self.inner.alloc(host_fn.name(), size) {
                    Ok(p) => p,
                    Err(error) => {
                        return HostVm::Error {
                            error,
                            prototype: self.inner.into_prototype(),
                        };
                    }
                };

                let ptr_i32 = i32::from_ne_bytes(ptr.to_ne_bytes());
                HostVm::ReadyToRun(ReadyToRun {
                    resume_value: Some(vm::WasmValue::I32(ptr_i32)),
                    inner: self.inner,
                })
            }
            HostFunction::ext_allocator_free_version_1 => {
                let pointer = expect_u32!(0);
                match self.inner.allocator.deallocate(
                    &mut MemAccess {
                        vm: MemAccessVm::Running(&mut self.inner.vm),
                        memory_total_pages: self.inner.common.memory_total_pages,
                    },
                    pointer,
                ) {
                    Ok(()) => {}
                    Err(_) => {
                        return HostVm::Error {
                            error: Error::FreeError { pointer },
                            prototype: self.inner.into_prototype(),
                        };
                    }
                };

                HostVm::ReadyToRun(ReadyToRun {
                    resume_value: None,
                    inner: self.inner,
                })
            }
            HostFunction::ext_logging_log_version_1 => {
                let log_level = expect_u32!(0);

                let (target_str_ptr, target_str_size) = expect_pointer_size_raw!(1);
                let target_utf8_check = str::from_utf8(
                    self.inner
                        .vm
                        .read_memory(target_str_ptr, target_str_size)
                        .unwrap_or_else(|_| unreachable!())
                        .as_ref(),
                )
                .map(|_| ());
                if let Err(error) = target_utf8_check {
                    return HostVm::Error {
                        error: Error::Utf8Error {
                            function: host_fn.name(),
                            param_num: 1,
                            error,
                        },
                        prototype: self.inner.into_prototype(),
                    };
                }

                let (msg_str_ptr, msg_str_size) = expect_pointer_size_raw!(2);
                let msg_utf8_check = str::from_utf8(
                    self.inner
                        .vm
                        .read_memory(msg_str_ptr, msg_str_size)
                        .unwrap_or_else(|_| unreachable!())
                        .as_ref(),
                )
                .map(|_| ());
                if let Err(error) = msg_utf8_check {
                    return HostVm::Error {
                        error: Error::Utf8Error {
                            function: host_fn.name(),
                            param_num: 2,
                            error,
                        },
                        prototype: self.inner.into_prototype(),
                    };
                }

                HostVm::LogEmit(LogEmit {
                    inner: self.inner,
                    log_entry: LogEmitInner::Log {
                        log_level,
                        target_str_ptr,
                        target_str_size,
                        msg_str_ptr,
                        msg_str_size,
                    },
                })
            }
            HostFunction::ext_logging_max_level_version_1 => {
                HostVm::GetMaxLogLevel(GetMaxLogLevel { inner: self.inner })
            }
            HostFunction::ext_panic_handler_abort_on_panic_version_1 => {
                let message = {
                    let message_bytes = expect_pointer_size!(0);
                    str::from_utf8(message_bytes.as_ref()).map(|msg| msg.to_owned())
                };

                match message {
                    Ok(message) => HostVm::Error {
                        error: Error::AbortOnPanic { message },
                        prototype: self.inner.into_prototype(),
                    },
                    Err(error) => HostVm::Error {
                        error: Error::Utf8Error {
                            function: host_fn.name(),
                            param_num: 0,
                            error,
                        },
                        prototype: self.inner.into_prototype(),
                    },
                }
            }
            HostFunction::ext_transaction_index_index_version_1 => {
                // TODO: this is currently a no-op; because not all the parameters are verified, this might lead to consensus issues
                let _tx_ptr = expect_pointer_size_raw!(0);
                HostVm::ReadyToRun(ReadyToRun {
                    inner: self.inner,
                    resume_value: None,
                })
            }
            HostFunction::ext_transaction_index_renew_version_1 => {
                // TODO: this is currently a no-op; because not all the parameters are verified, this might lead to consensus issues
                let _tx_ptr = expect_pointer_size_raw!(0);
                HostVm::ReadyToRun(ReadyToRun {
                    inner: self.inner,
                    resume_value: None,
                })
            }
        }
    }
}

impl fmt::Debug for ReadyToRun {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ReadyToRun").finish()
    }
}

/// Function execution has succeeded. Contains the return value of the call.
///
/// The trie root hash of all the child tries must be recalculated and written to the main trie
/// similar to when a [`ExternalStorageRoot`] with a `child_trie` of `None` is generated. See the
/// documentation of [`ExternalStorageRoot`].
pub struct Finished {
    inner: Box<Inner>,

    /// Pointer to the value returned by the VM. Guaranteed to be in range.
    value_ptr: u32,
    /// Size of the value returned by the VM. Guaranteed to be in range.
    value_size: u32,
}

impl Finished {
    /// Returns the value the called function has returned.
    pub fn value(&self) -> impl AsRef<[u8]> {
        self.inner
            .vm
            .read_memory(self.value_ptr, self.value_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// Turns the virtual machine back into a prototype.
    pub fn into_prototype(self) -> HostVmPrototype {
        self.inner.into_prototype()
    }
}

impl fmt::Debug for Finished {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Finished").finish()
    }
}

/// Must provide the value of a storage entry.
pub struct ExternalStorageGet {
    inner: Box<Inner>,

    /// Function currently being called by the Wasm code. Refers to an index within
    /// [`VmCommon::registered_functions`]. Guaranteed to be [`FunctionImport::Resolved`].
    calling: usize,

    /// Used only for the `ext_storage_read_version_1` function. Stores the pointer where the
    /// output should be stored.
    value_out_ptr: Option<u32>,

    /// Pointer to the key whose value must be loaded. Guaranteed to be in range.
    key_ptr: u32,
    /// Size of the key whose value must be loaded. Guaranteed to be in range.
    key_size: u32,
    /// Pointer and size to the default child trie. `None` if main trie. Guaranteed to be in range.
    child_trie_ptr_size: Option<(u32, u32)>,
    /// Offset within the value that the Wasm VM requires.
    offset: u32,
    /// Maximum size that the Wasm VM would accept.
    max_size: u32,
}

impl ExternalStorageGet {
    /// Returns the key whose value must be provided back with [`ExternalStorageGet::resume`].
    pub fn key(&self) -> impl AsRef<[u8]> {
        self.inner
            .vm
            .read_memory(self.key_ptr, self.key_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        if let Some((child_trie_ptr, child_trie_size)) = self.child_trie_ptr_size {
            let child_trie = self
                .inner
                .vm
                .read_memory(child_trie_ptr, child_trie_size)
                .unwrap_or_else(|_| unreachable!());
            Some(child_trie)
        } else {
            None
        }
    }

    /// Offset within the value that is requested.
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Maximum size of the value to pass back.
    ///
    /// > **Note**: This can be 0 if we only want to know whether a value exists.
    pub fn max_size(&self) -> u32 {
        self.max_size
    }

    /// Same as [`ExternalStorageGet::resume`], but passes the full value, without taking the
    /// offset and maximum size into account.
    ///
    /// This is a convenient function that automatically applies the offset and maximum size, to
    /// use when the full storage value is already present in memory.
    pub fn resume_full_value(self, value: Option<&[u8]>) -> HostVm {
        if let Some(value) = value {
            if usize::try_from(self.offset).unwrap_or_else(|_| unreachable!()) < value.len() {
                let value_slice =
                    &value[usize::try_from(self.offset).unwrap_or_else(|_| unreachable!())..];
                if usize::try_from(self.max_size).unwrap_or_else(|_| unreachable!())
                    < value_slice.len()
                {
                    let value_slice = &value_slice
                        [..usize::try_from(self.max_size).unwrap_or_else(|_| unreachable!())];
                    self.resume(Some((value_slice, value.len())))
                } else {
                    self.resume(Some((value_slice, value.len())))
                }
            } else {
                self.resume(Some((&[], value.len())))
            }
        } else {
            self.resume(None)
        }
    }

    /// Writes the storage value in the Wasm VM's memory and prepares the virtual machine to
    /// resume execution.
    ///
    /// The value to provide must be the value of that key starting at the offset returned by
    /// [`ExternalStorageGet::offset`]. If the offset is out of range, an empty slice must be
    /// passed.
    ///
    /// If `Some`, the total size of the value, without taking [`ExternalStorageGet::offset`] or
    /// [`ExternalStorageGet::max_size`] into account, must additionally be provided.
    ///
    /// If [`ExternalStorageGet::child_trie`] returns `Some` but the child trie doesn't exist,
    /// then `None` must be provided.
    ///
    /// The value must not be longer than what [`ExternalStorageGet::max_size`] returns.
    ///
    /// # Panic
    ///
    /// Panics if the value is longer than what [`ExternalStorageGet::max_size`] returns.
    ///
    pub fn resume(self, value: Option<(&[u8], usize)>) -> HostVm {
        self.resume_vectored(
            value
                .as_ref()
                .map(|(value, size)| (iter::once(&value[..]), *size)),
        )
    }

    /// Similar to [`ExternalStorageGet::resume`], but allows passing the value as a list of
    /// buffers whose concatenation forms the actual value.
    ///
    /// If `Some`, the total size of the value, without taking [`ExternalStorageGet::offset`] or
    /// [`ExternalStorageGet::max_size`] into account, must additionally be provided.
    ///
    /// # Panic
    ///
    /// See [`ExternalStorageGet::resume`].
    ///
    pub fn resume_vectored(
        mut self,
        value: Option<(impl Iterator<Item = impl AsRef<[u8]>> + Clone, usize)>,
    ) -> HostVm {
        let host_fn = match self.inner.common.registered_functions[self.calling] {
            FunctionImport::Resolved(f) => f,
            FunctionImport::Unresolved { .. } => unreachable!(),
        };

        match host_fn {
            HostFunction::ext_storage_get_version_1
            | HostFunction::ext_default_child_storage_get_version_1 => {
                if let Some((value, value_total_len)) = value {
                    // Writing `Some(value)`.
                    debug_assert_eq!(
                        value.clone().fold(0, |a, b| a + b.as_ref().len()),
                        value_total_len
                    );
                    let value_len_enc = util::encode_scale_compact_usize(value_total_len);
                    self.inner.alloc_write_and_return_pointer_size(
                        host_fn.name(),
                        iter::once(&[1][..])
                            .chain(iter::once(value_len_enc.as_ref()))
                            .map(either::Left)
                            .chain(value.map(either::Right)),
                    )
                } else {
                    // Write a SCALE-encoded `None`.
                    self.inner
                        .alloc_write_and_return_pointer_size(host_fn.name(), iter::once(&[0]))
                }
            }
            HostFunction::ext_storage_read_version_1
            | HostFunction::ext_default_child_storage_read_version_1 => {
                let outcome = if let Some((value, value_total_len)) = value {
                    let mut remaining_max_allowed =
                        usize::try_from(self.max_size).unwrap_or_else(|_| unreachable!());
                    let mut offset = self.value_out_ptr.unwrap_or_else(|| unreachable!());
                    for value in value {
                        let value = value.as_ref();
                        assert!(value.len() <= remaining_max_allowed);
                        remaining_max_allowed -= value.len();
                        self.inner
                            .vm
                            .write_memory(offset, value)
                            .unwrap_or_else(|_| unreachable!());
                        offset += u32::try_from(value.len()).unwrap_or_else(|_| unreachable!());
                    }

                    // Note: the https://github.com/paritytech/substrate/pull/7084 PR has changed
                    // the meaning of this return value.
                    Some(
                        u32::try_from(value_total_len).unwrap_or_else(|_| unreachable!())
                            - self.offset,
                    )
                } else {
                    None
                };

                return self.inner.alloc_write_and_return_pointer_size(
                    host_fn.name(),
                    if let Some(outcome) = outcome {
                        either::Left(
                            iter::once(either::Left([1u8]))
                                .chain(iter::once(either::Right(outcome.to_le_bytes()))),
                        )
                    } else {
                        either::Right(iter::once(either::Left([0u8])))
                    },
                );
            }
            HostFunction::ext_storage_exists_version_1
            | HostFunction::ext_default_child_storage_exists_version_1 => {
                HostVm::ReadyToRun(ReadyToRun {
                    inner: self.inner,
                    resume_value: Some(if value.is_some() {
                        vm::WasmValue::I32(1)
                    } else {
                        vm::WasmValue::I32(0)
                    }),
                })
            }
            _ => unreachable!(),
        }
    }
}

impl fmt::Debug for ExternalStorageGet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalStorageGet").finish()
    }
}

/// Must set the value of a storage entry.
///
/// If [`ExternalStorageSet::child_trie`] return `None` and [`ExternalStorageSet::key`]
/// returns a key that starts with `:child_storage:`, then the write must be silently ignored.
///
/// If [`ExternalStorageSet::child_trie`] and [`ExternalStorageSet::value`] return `Some` and the
/// child trie doesn't exist, it must implicitly be created.
/// If [`ExternalStorageSet::child_trie`] returns `Some` and [`ExternalStorageSet::value`]
/// returns `None` and this is the last entry in the child trie, it must implicitly be destroyed.
pub struct ExternalStorageSet {
    inner: Box<Inner>,

    /// Pointer to the key whose value must be set. Guaranteed to be in range.
    key_ptr: u32,
    /// Size of the key whose value must be set. Guaranteed to be in range.
    key_size: u32,
    /// Pointer and size to the default child trie key. `None` if main trie. Guaranteed to be
    /// in range.
    child_trie_ptr_size: Option<(u32, u32)>,

    /// Pointer and size of the value to set. `None` for clearing. Guaranteed to be in range.
    value: Option<(u32, u32)>,
}

impl ExternalStorageSet {
    /// Returns the key whose value must be set.
    pub fn key(&self) -> impl AsRef<[u8]> {
        self.inner
            .vm
            .read_memory(self.key_ptr, self.key_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// If `Some`, write to the given child trie. If `None`, write to the main trie.
    ///
    /// If [`ExternalStorageSet::value`] returns `Some` and the child trie doesn't exist, it must
    /// implicitly be created.
    /// If [`ExternalStorageSet::value`] returns `None` and this is the last entry in the child
    /// trie, it must implicitly be destroyed.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        match &self.child_trie_ptr_size {
            Some((ptr, size)) => {
                let child_trie = self
                    .inner
                    .vm
                    .read_memory(*ptr, *size)
                    .unwrap_or_else(|_| unreachable!());
                Some(child_trie)
            }
            None => None,
        }
    }

    /// Returns the value to set.
    ///
    /// If `None` is returned, the key should be removed from the storage entirely.
    pub fn value(&self) -> Option<impl AsRef<[u8]>> {
        self.value.map(|(ptr, size)| {
            self.inner
                .vm
                .read_memory(ptr, size)
                .unwrap_or_else(|_| unreachable!())
        })
    }

    /// Returns the state trie version indicated by the runtime.
    ///
    /// This information should be stored alongside with the storage value and is necessary in
    /// order to properly build the trie and thus the trie root node hash.
    pub fn state_trie_version(&self) -> TrieEntryVersion {
        self.inner
            .common
            .runtime_version
            .as_ref()
            .unwrap_or_else(|| unreachable!())
            .decode()
            .state_version
            .unwrap_or(TrieEntryVersion::V0)
    }

    /// Resumes execution after having set the value.
    pub fn resume(self) -> HostVm {
        HostVm::ReadyToRun(ReadyToRun {
            inner: self.inner,
            resume_value: None,
        })
    }
}

impl fmt::Debug for ExternalStorageSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalStorageSet").finish()
    }
}

/// Must load a storage value, treat it as if it was a SCALE-encoded container, and put `value`
/// at the end of the container, increasing the number of elements.
///
/// If [`ExternalStorageAppend::child_trie`] return `Some` and the child trie doesn't exist, it
/// must implicitly be created.
///
/// If [`ExternalStorageAppend::child_trie`] return `None` and [`ExternalStorageAppend::key`]
/// returns a key that starts with `:child_storage:`, then the write must be silently ignored.
///
/// If there isn't any existing value of if the existing value isn't actually a SCALE-encoded
/// container, store a 1-size container with the `value`.
///
/// # Details
///
/// The SCALE encoding encodes containers as a SCALE-compact-encoded length followed with the
/// SCALE-encoded items one after the other. For example, a container of two elements is stored
/// as the number `2` followed with the two items.
///
/// This change consists in taking an existing value and assuming that it is a SCALE-encoded
/// container. This can be done as decoding a SCALE-compact-encoded number at the start of
/// the existing encoded value. One most then increments that number and puts `value` at the
/// end of the encoded value.
///
/// It is not necessary to decode `value` as is assumed that is already encoded in the same
/// way as the other items in the container.
pub struct ExternalStorageAppend {
    inner: Box<Inner>,

    /// Pointer to the key whose value must be set. Guaranteed to be in range.
    key_ptr: u32,
    /// Size of the key whose value must be set. Guaranteed to be in range.
    key_size: u32,

    /// Pointer to the value to append. Guaranteed to be in range.
    value_ptr: u32,
    /// Size of the value to append. Guaranteed to be in range.
    value_size: u32,
}

impl ExternalStorageAppend {
    /// Returns the key whose value must be set.
    pub fn key(&self) -> impl AsRef<[u8]> {
        self.inner
            .vm
            .read_memory(self.key_ptr, self.key_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// If `Some`, write to the given child trie. If `None`, write to the main trie.
    ///
    /// If this returns `Some` and the child trie doesn't exist, it must implicitly be created.
    ///
    /// > **Note**: At the moment, this function always returns None, as there is no host function
    /// >           that appends to a child trie storage.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        // Note that there is no equivalent of this host function for child tries.
        None::<&'static [u8]>
    }

    /// Returns the value to append.
    pub fn value(&self) -> impl AsRef<[u8]> {
        self.inner
            .vm
            .read_memory(self.value_ptr, self.value_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// Resumes execution after having set the value.
    pub fn resume(self) -> HostVm {
        HostVm::ReadyToRun(ReadyToRun {
            inner: self.inner,
            resume_value: None,
        })
    }
}

impl fmt::Debug for ExternalStorageAppend {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalStorageAppend").finish()
    }
}

/// Must remove from the storage keys which start with a certain prefix. Use
/// [`ExternalStorageClearPrefix::max_keys_to_remove`] to determine the maximum number of keys
/// to remove.
///
/// If [`ExternalStorageClearPrefix::child_trie`] returns `Some` and all the entries of the child
/// trie are removed, the child trie must implicitly be destroyed.
///
/// If [`ExternalStorageClearPrefix::child_trie`] return `None` and the prefix returned by
/// [`ExternalStorageClearPrefix::prefix`] intersects with `:child_storage:`, then the clearing
/// must be silently ignored.
pub struct ExternalStorageClearPrefix {
    inner: Box<Inner>,
    /// Function currently being called by the Wasm code. Refers to an index within
    /// [`VmCommon::registered_functions`]. Guaranteed to be [`FunctionImport::Resolved`].
    calling: usize,

    /// Pointer and size to the prefix. `None` if `&[]`. Guaranteed to be in range.
    prefix_ptr_size: Option<(u32, u32)>,
    /// Pointer and size to the default child trie. `None` if main trie. Guaranteed to be in range.
    child_trie_ptr_size: Option<(u32, u32)>,

    /// Maximum number of keys to remove.
    max_keys_to_remove: Option<u32>,
}

impl ExternalStorageClearPrefix {
    /// Returns the prefix whose keys must be removed.
    pub fn prefix(&self) -> impl AsRef<[u8]> {
        if let Some((prefix_ptr, prefix_size)) = self.prefix_ptr_size {
            either::Left(
                self.inner
                    .vm
                    .read_memory(prefix_ptr, prefix_size)
                    .unwrap_or_else(|_| unreachable!()),
            )
        } else {
            either::Right(&[][..])
        }
    }

    /// If `Some`, write to the given child trie. If `None`, write to the main trie.
    ///
    /// If [`ExternalStorageClearPrefix::child_trie`] returns `Some` and all the entries of the
    /// child trie are removed, the child trie must implicitly be destroyed.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        if let Some((child_trie_ptr, child_trie_size)) = self.child_trie_ptr_size {
            let child_trie = self
                .inner
                .vm
                .read_memory(child_trie_ptr, child_trie_size)
                .unwrap_or_else(|_| unreachable!());
            Some(child_trie)
        } else {
            None
        }
    }

    /// Returns the maximum number of keys to remove. `None` means "infinity".
    pub fn max_keys_to_remove(&self) -> Option<u32> {
        self.max_keys_to_remove
    }

    /// Resumes execution after having cleared the values.
    ///
    /// Must be passed how many keys have been cleared, and whether some keys remaining to be
    /// cleared.
    pub fn resume(self, num_cleared: u32, some_keys_remain: bool) -> HostVm {
        let host_fn = match self.inner.common.registered_functions[self.calling] {
            FunctionImport::Resolved(f) => f,
            FunctionImport::Unresolved { .. } => unreachable!(),
        };

        match host_fn {
            HostFunction::ext_storage_clear_prefix_version_1
            | HostFunction::ext_default_child_storage_clear_prefix_version_1
            | HostFunction::ext_default_child_storage_storage_kill_version_1 => {
                HostVm::ReadyToRun(ReadyToRun {
                    inner: self.inner,
                    resume_value: None,
                })
            }
            HostFunction::ext_default_child_storage_storage_kill_version_2 => {
                HostVm::ReadyToRun(ReadyToRun {
                    inner: self.inner,
                    resume_value: Some(vm::WasmValue::I32(if some_keys_remain { 0 } else { 1 })),
                })
            }
            HostFunction::ext_storage_clear_prefix_version_2
            | HostFunction::ext_default_child_storage_clear_prefix_version_2
            | HostFunction::ext_default_child_storage_storage_kill_version_3 => {
                self.inner.alloc_write_and_return_pointer_size(
                    host_fn.name(),
                    [
                        either::Left(if some_keys_remain { [1u8] } else { [0u8] }),
                        either::Right(num_cleared.to_le_bytes()),
                    ]
                    .into_iter(),
                )
            }
            _ => unreachable!(),
        }
    }
}

impl fmt::Debug for ExternalStorageClearPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalStorageClearPrefix").finish()
    }
}

/// Must provide the trie root hash of the storage and write the trie root hash of child tries
/// to the main trie.
///
/// If [`ExternalStorageRoot::child_trie`] returns `Some` and the child trie is non-empty, the
/// trie root hash of the child trie must also be written to the main trie at the key
/// `concat(":child_storage:default:", child_trie)`.
/// If [`ExternalStorageRoot::child_trie`] returns `Some` and the child trie is empty, the entry
/// in the main trie at the key `concat(":child_storage:default:", child_trie)` must be removed.
///
/// If [`ExternalStorageRoot::child_trie`] returns `None`, the same operation as above must be
/// done for every single child trie that has been modified in one way or the other during the
/// runtime call.
pub struct ExternalStorageRoot {
    inner: Box<Inner>,

    /// Function currently being called by the Wasm code. Refers to an index within
    /// [`VmCommon::registered_functions`]. Guaranteed to be [`FunctionImport::Resolved`].
    calling: usize,

    /// Pointer and size of the child trie, if any. Guaranteed to be in range.
    child_trie_ptr_size: Option<(u32, u32)>,
}

impl ExternalStorageRoot {
    /// Returns the child trie whose root hash must be provided. `None` for the main trie.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        if let Some((ptr, size)) = self.child_trie_ptr_size {
            let child_trie = self
                .inner
                .vm
                .read_memory(ptr, size)
                .unwrap_or_else(|_| unreachable!());
            Some(child_trie)
        } else {
            None
        }
    }

    /// Writes the trie root hash to the Wasm VM and prepares it for resume.
    ///
    /// If [`ExternalStorageRoot::child_trie`] returns `Some` but the child trie doesn't exist,
    /// the root hash of an empty trie must be provided.
    pub fn resume(self, hash: &[u8; 32]) -> HostVm {
        let host_fn = match self.inner.common.registered_functions[self.calling] {
            FunctionImport::Resolved(f) => f,
            FunctionImport::Unresolved { .. } => unreachable!(),
        };

        self.inner
            .alloc_write_and_return_pointer_size(host_fn.name(), iter::once(hash))
    }
}

impl fmt::Debug for ExternalStorageRoot {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalStorageRoot").finish()
    }
}

/// Must provide the storage key that follows, in lexicographic order, a specific one.
pub struct ExternalStorageNextKey {
    inner: Box<Inner>,

    /// Pointer to the key whose follow-up must be found. Guaranteed to be in range.
    key_ptr: u32,
    /// Size of the key whose follow-up must be found. Guaranteed to be in range.
    key_size: u32,
    /// Pointer and size of the child trie, if any. Guaranteed to be in range.
    child_trie_ptr_size: Option<(u32, u32)>,
}

impl ExternalStorageNextKey {
    /// Returns the key whose following key must be returned.
    pub fn key(&self) -> impl AsRef<[u8]> {
        self.inner
            .vm
            .read_memory(self.key_ptr, self.key_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        if let Some((child_trie_ptr, child_trie_size)) = self.child_trie_ptr_size {
            let child_trie = self
                .inner
                .vm
                .read_memory(child_trie_ptr, child_trie_size)
                .unwrap_or_else(|_| unreachable!());
            Some(child_trie)
        } else {
            None
        }
    }

    /// Writes the follow-up key in the Wasm VM memory and prepares it for execution.
    ///
    /// Must be passed `None` if the key is the last one in the storage or if
    /// [`ExternalStorageNextKey`] returns `Some` and the child trie doesn't exist.
    pub fn resume(self, follow_up: Option<&[u8]>) -> HostVm {
        let key = self
            .inner
            .vm
            .read_memory(self.key_ptr, self.key_size)
            .unwrap_or_else(|_| unreachable!());

        match follow_up {
            Some(next) => {
                debug_assert!(key.as_ref() < next);

                let value_len_enc = util::encode_scale_compact_usize(next.len());
                drop(key);
                self.inner.alloc_write_and_return_pointer_size(
                    HostFunction::ext_storage_next_key_version_1.name(), // TODO: no
                    iter::once(&[1][..])
                        .chain(iter::once(value_len_enc.as_ref()))
                        .chain(iter::once(next)),
                )
            }
            None => {
                // Write a SCALE-encoded `None`.
                drop(key);
                self.inner.alloc_write_and_return_pointer_size(
                    HostFunction::ext_storage_next_key_version_1.name(), // TODO: no
                    iter::once(&[0]),
                )
            }
        }
    }
}

impl fmt::Debug for ExternalStorageNextKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalStorageNextKey").finish()
    }
}

/// Must verify whether a signature is correct.
pub struct SignatureVerification {
    inner: Box<Inner>,
    /// Which cryptographic algorithm.
    algorithm: SignatureVerificationAlgorithm,
    /// Pointer to the signature. The size of the signature depends on the algorithm. Guaranteed
    /// to be in range.
    signature_ptr: u32,
    /// Pointer to the public key. The size of the public key depends on the algorithm. Guaranteed
    /// to be in range.
    public_key_ptr: u32,
    /// Pointer to the message. Guaranteed to be in range.
    message_ptr: u32,
    /// Size of the message. Guaranteed to be in range.
    message_size: u32,
    /// `true` if the host function is a batch verification function.
    is_batch_verification: bool,
}

enum SignatureVerificationAlgorithm {
    Ed25519,
    Sr25519V1,
    Sr25519V2,
    Ecdsa,
    EcdsaPrehashed,
}

impl SignatureVerification {
    /// Returns the message that the signature is expected to sign.
    pub fn message(&self) -> impl AsRef<[u8]> {
        self.inner
            .vm
            .read_memory(self.message_ptr, self.message_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// Returns the signature.
    ///
    /// > **Note**: Be aware that this signature is untrusted input and might not be part of the
    /// >           set of valid signatures.
    pub fn signature(&self) -> impl AsRef<[u8]> {
        let signature_size = match self.algorithm {
            SignatureVerificationAlgorithm::Ed25519 => 64,
            SignatureVerificationAlgorithm::Sr25519V1 => 64,
            SignatureVerificationAlgorithm::Sr25519V2 => 64,
            SignatureVerificationAlgorithm::Ecdsa => 65,
            SignatureVerificationAlgorithm::EcdsaPrehashed => 65,
        };

        self.inner
            .vm
            .read_memory(self.signature_ptr, signature_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// Returns the public key the signature is against.
    ///
    /// > **Note**: Be aware that this public key is untrusted input and might not be part of the
    /// >           set of valid public keys.
    pub fn public_key(&self) -> impl AsRef<[u8]> {
        let public_key_size = match self.algorithm {
            SignatureVerificationAlgorithm::Ed25519 => 32,
            SignatureVerificationAlgorithm::Sr25519V1 => 32,
            SignatureVerificationAlgorithm::Sr25519V2 => 32,
            SignatureVerificationAlgorithm::Ecdsa => 33,
            SignatureVerificationAlgorithm::EcdsaPrehashed => 33,
        };

        self.inner
            .vm
            .read_memory(self.public_key_ptr, public_key_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// Verify the signature. Returns `true` if it is valid.
    pub fn is_valid(&self) -> bool {
        match self.algorithm {
            SignatureVerificationAlgorithm::Ed25519 => {
                let public_key =
                    ed25519_zebra::VerificationKey::try_from(self.public_key().as_ref());

                if let Ok(public_key) = public_key {
                    let signature = ed25519_zebra::Signature::from(
                        <[u8; 64]>::try_from(self.signature().as_ref())
                            .unwrap_or_else(|_| unreachable!()),
                    );
                    public_key
                        .verify(&signature, self.message().as_ref())
                        .is_ok()
                } else {
                    false
                }
            }
            SignatureVerificationAlgorithm::Sr25519V1 => {
                schnorrkel::PublicKey::from_bytes(self.public_key().as_ref()).map_or(false, |pk| {
                    pk.verify_simple_preaudit_deprecated(
                        b"substrate",
                        self.message().as_ref(),
                        self.signature().as_ref(),
                    )
                    .is_ok()
                })
            }
            SignatureVerificationAlgorithm::Sr25519V2 => {
                let Ok(signature) = schnorrkel::Signature::from_bytes(self.signature().as_ref())
                else {
                    return false;
                };
                schnorrkel::PublicKey::from_bytes(self.public_key().as_ref()).map_or(false, |pk| {
                    pk.verify_simple(b"substrate", self.message().as_ref(), &signature)
                        .is_ok()
                })
            }
            SignatureVerificationAlgorithm::Ecdsa => {
                // NOTE: safe to unwrap here because we supply the nn to blake2b fn
                let data = <[u8; 32]>::try_from(
                    blake2_rfc::blake2b::blake2b(32, &[], self.message().as_ref()).as_bytes(),
                )
                .unwrap_or_else(|_| unreachable!());
                let message = libsecp256k1::Message::parse(&data);

                // signature (64 bytes) + recovery ID (1 byte)
                let sig_bytes = self.signature();
                libsecp256k1::Signature::parse_standard_slice(&sig_bytes.as_ref()[..64])
                    .and_then(|sig| {
                        libsecp256k1::RecoveryId::parse(sig_bytes.as_ref()[64])
                            .and_then(|ri| libsecp256k1::recover(&message, &sig, &ri))
                    })
                    .map_or(false, |actual| {
                        self.public_key().as_ref()[..] == actual.serialize_compressed()[..]
                    })
            }
            SignatureVerificationAlgorithm::EcdsaPrehashed => {
                // We can safely unwrap, as the size is checked when the `SignatureVerification`
                // is constructed.
                let message = libsecp256k1::Message::parse(
                    &<[u8; 32]>::try_from(self.message().as_ref())
                        .unwrap_or_else(|_| unreachable!()),
                );

                // signature (64 bytes) + recovery ID (1 byte)
                let sig_bytes = self.signature();
                if let Ok(sig) =
                    libsecp256k1::Signature::parse_standard_slice(&sig_bytes.as_ref()[..64])
                {
                    if let Ok(ri) = libsecp256k1::RecoveryId::parse(sig_bytes.as_ref()[64]) {
                        if let Ok(actual) = libsecp256k1::recover(&message, &sig, &ri) {
                            self.public_key().as_ref()[..] == actual.serialize_compressed()[..]
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        }
    }

    /// Verify the signature and resume execution.
    pub fn verify_and_resume(self) -> HostVm {
        let success = self.is_valid();
        self.resume(success)
    }

    /// Resume the execution assuming that the signature is valid.
    ///
    /// > **Note**: You are strongly encouraged to call
    /// >           [`SignatureVerification::verify_and_resume`]. This function is meant to be
    /// >           used only in debugging situations.
    pub fn resume_success(self) -> HostVm {
        self.resume(true)
    }

    /// Resume the execution assuming that the signature is invalid.
    ///
    /// > **Note**: You are strongly encouraged to call
    /// >           [`SignatureVerification::verify_and_resume`]. This function is meant to be
    /// >           used only in debugging situations.
    pub fn resume_failed(self) -> HostVm {
        self.resume(false)
    }

    fn resume(mut self, success: bool) -> HostVm {
        debug_assert!(
            !self.is_batch_verification || self.inner.signatures_batch_verification.is_some()
        );
        if self.is_batch_verification && !success {
            self.inner.signatures_batch_verification = Some(false);
        }

        // All signature-related host functions work the same way in terms of return value.
        HostVm::ReadyToRun(ReadyToRun {
            resume_value: Some(vm::WasmValue::I32(if success { 1 } else { 0 })),
            inner: self.inner,
        })
    }
}

impl fmt::Debug for SignatureVerification {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SignatureVerification")
            .field("message", &self.message().as_ref())
            .field("signature", &self.signature().as_ref())
            .field("public_key", &self.public_key().as_ref())
            .finish()
    }
}

/// Must provide the runtime version obtained by calling the `Core_version` entry point of a Wasm
/// blob.
pub struct CallRuntimeVersion {
    inner: Box<Inner>,

    /// Pointer to the wasm code whose runtime version must be provided. Guaranteed to be in range.
    wasm_blob_ptr: u32,
    /// Size of the wasm code whose runtime version must be provided. Guaranteed to be in range.
    wasm_blob_size: u32,
}

impl CallRuntimeVersion {
    /// Returns the Wasm code whose runtime version must be provided.
    pub fn wasm_code(&self) -> impl AsRef<[u8]> {
        self.inner
            .vm
            .read_memory(self.wasm_blob_ptr, self.wasm_blob_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// Writes the SCALE-encoded runtime version to the memory and prepares for execution.
    ///
    /// If an error happened during the execution (such as an invalid Wasm binary code), pass
    /// an `Err`.
    pub fn resume(self, scale_encoded_runtime_version: Result<&[u8], ()>) -> HostVm {
        if let Ok(scale_encoded_runtime_version) = scale_encoded_runtime_version {
            self.inner.alloc_write_and_return_pointer_size(
                HostFunction::ext_misc_runtime_version_version_1.name(),
                iter::once(either::Left([1]))
                    .chain(iter::once(either::Right(either::Left(
                        util::encode_scale_compact_usize(scale_encoded_runtime_version.len()),
                    ))))
                    .chain(iter::once(either::Right(either::Right(
                        scale_encoded_runtime_version,
                    )))),
            )
        } else {
            self.inner.alloc_write_and_return_pointer_size(
                HostFunction::ext_misc_runtime_version_version_1.name(),
                iter::once([0]),
            )
        }
    }
}

impl fmt::Debug for CallRuntimeVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("CallRuntimeVersion").finish()
    }
}

/// Must set off-chain index value.
pub struct ExternalOffchainIndexSet {
    inner: Box<Inner>,

    /// Pointer to the key whose value must be set. Guaranteed to be in range.
    key_ptr: u32,
    /// Size of the key whose value must be set. Guaranteed to be in range.
    key_size: u32,

    /// Pointer and size of the value to set. `None` for clearing. Guaranteed to be in range.
    value: Option<(u32, u32)>,
}

impl ExternalOffchainIndexSet {
    /// Returns the key whose value must be set.
    pub fn key(&self) -> impl AsRef<[u8]> {
        self.inner
            .vm
            .read_memory(self.key_ptr, self.key_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// Returns the value to set.
    ///
    /// If `None` is returned, the key should be removed from the storage entirely.
    pub fn value(&self) -> Option<impl AsRef<[u8]>> {
        if let Some((ptr, size)) = self.value {
            Some(
                self.inner
                    .vm
                    .read_memory(ptr, size)
                    .unwrap_or_else(|_| unreachable!()),
            )
        } else {
            None
        }
    }

    /// Resumes execution after having set the value.
    pub fn resume(self) -> HostVm {
        HostVm::ReadyToRun(ReadyToRun {
            inner: self.inner,
            resume_value: None,
        })
    }
}

impl fmt::Debug for ExternalOffchainIndexSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalOffchainIndexSet").finish()
    }
}

/// Must set the value of the off-chain storage.
pub struct ExternalOffchainStorageSet {
    inner: Box<Inner>,

    /// Pointer to the key whose value must be set. Guaranteed to be in range.
    key_ptr: u32,
    /// Size of the key whose value must be set. Guaranteed to be in range.
    key_size: u32,

    /// Pointer and size of the value to set. `None` for clearing. Guaranteed to be in range.
    value: Option<(u32, u32)>,

    /// Pointer and size of the old value to compare. Guaranteed to be in range.
    old_value: Option<(u32, u32)>,
}

impl ExternalOffchainStorageSet {
    /// Returns the key whose value must be set.
    pub fn key(&self) -> impl AsRef<[u8]> {
        self.inner
            .vm
            .read_memory(self.key_ptr, self.key_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// Returns the value to set.
    ///
    /// If `None` is returned, the key should be removed from the storage entirely.
    pub fn value(&self) -> Option<impl AsRef<[u8]>> {
        if let Some((ptr, size)) = self.value {
            Some(
                self.inner
                    .vm
                    .read_memory(ptr, size)
                    .unwrap_or_else(|_| unreachable!()),
            )
        } else {
            None
        }
    }

    /// Returns the value the current value should be compared against. The operation is a no-op if they don't compare equal.
    pub fn old_value(&self) -> Option<impl AsRef<[u8]>> {
        if let Some((ptr, size)) = self.old_value {
            Some(
                self.inner
                    .vm
                    .read_memory(ptr, size)
                    .unwrap_or_else(|_| unreachable!()),
            )
        } else {
            None
        }
    }

    /// Resumes execution after having set the value. Must indicate whether a value was written.
    pub fn resume(self, replaced: bool) -> HostVm {
        if self.old_value.is_some() {
            HostVm::ReadyToRun(ReadyToRun {
                inner: self.inner,
                resume_value: Some(vm::WasmValue::I32(if replaced { 1 } else { 0 })),
            })
        } else {
            HostVm::ReadyToRun(ReadyToRun {
                inner: self.inner,
                resume_value: None,
            })
        }
    }
}

impl fmt::Debug for ExternalOffchainStorageSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalOffchainStorageSet").finish()
    }
}

/// Must get the value of the off-chain storage.
pub struct ExternalOffchainStorageGet {
    inner: Box<Inner>,

    /// Function currently being called by the Wasm code. Refers to an index within
    /// [`VmCommon::registered_functions`]. Guaranteed to be [`FunctionImport::Resolved`].
    calling: usize,

    /// Pointer to the key whose value must be loaded. Guaranteed to be in range.
    key_ptr: u32,
    /// Size of the key whose value must be loaded. Guaranteed to be in range.
    key_size: u32,
}

impl ExternalOffchainStorageGet {
    /// Returns the key whose value must be loaded.
    pub fn key(&self) -> impl AsRef<[u8]> {
        self.inner
            .vm
            .read_memory(self.key_ptr, self.key_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// Resumes execution after having set the value.
    pub fn resume(self, value: Option<&[u8]>) -> HostVm {
        let host_fn = match self.inner.common.registered_functions[self.calling] {
            FunctionImport::Resolved(f) => f,
            FunctionImport::Unresolved { .. } => unreachable!(),
        };

        if let Some(value) = value {
            let value_len_enc = util::encode_scale_compact_usize(value.len());
            self.inner.alloc_write_and_return_pointer_size(
                host_fn.name(),
                iter::once(&[1][..])
                    .chain(iter::once(value_len_enc.as_ref()))
                    .map(either::Left)
                    .chain(iter::once(value).map(either::Right)),
            )
        } else {
            // Write a SCALE-encoded `None`.
            self.inner
                .alloc_write_and_return_pointer_size(host_fn.name(), iter::once(&[0]))
        }
    }
}

impl fmt::Debug for ExternalOffchainStorageGet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalOffchainStorageGet").finish()
    }
}

/// Must return the current UNIX timestamp.
pub struct OffchainTimestamp {
    inner: Box<Inner>,
}

impl OffchainTimestamp {
    /// Resumes execution after having set the value.
    pub fn resume(self, value: u64) -> HostVm {
        HostVm::ReadyToRun(ReadyToRun {
            inner: self.inner,
            resume_value: Some(vm::WasmValue::I64(i64::from_ne_bytes(value.to_ne_bytes()))),
        })
    }
}

impl fmt::Debug for OffchainTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("OffchainTimestamp").finish()
    }
}

/// Must provide a randomly-generate number.
pub struct OffchainRandomSeed {
    inner: Box<Inner>,

    /// Function currently being called by the Wasm code. Refers to an index within
    /// [`VmCommon::registered_functions`]. Guaranteed to be [`FunctionImport::Resolved`].
    calling: usize,
}

impl OffchainRandomSeed {
    /// Resumes execution after having set the value.
    pub fn resume(self, value: [u8; 32]) -> HostVm {
        let host_fn = match self.inner.common.registered_functions[self.calling] {
            FunctionImport::Resolved(f) => f,
            FunctionImport::Unresolved { .. } => unreachable!(),
        };
        self.inner
            .alloc_write_and_return_pointer(host_fn.name(), iter::once(value))
    }
}

impl fmt::Debug for OffchainRandomSeed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("OffchainRandomSeed").finish()
    }
}

/// Must submit an off-chain transaction.
pub struct OffchainSubmitTransaction {
    inner: Box<Inner>,

    /// Function currently being called by the Wasm code. Refers to an index within
    /// [`VmCommon::registered_functions`]. Guaranteed to be [`FunctionImport::Resolved`].
    calling: usize,

    /// Pointer to the transaction whose value must be set. Guaranteed to be in range.
    tx_ptr: u32,

    /// Size of the transaction whose value must be set. Guaranteed to be in range.
    tx_size: u32,
}

impl OffchainSubmitTransaction {
    /// Returns the SCALE-encoded transaction to submit to the chain.
    pub fn transaction(&self) -> impl AsRef<[u8]> {
        self.inner
            .vm
            .read_memory(self.tx_ptr, self.tx_size)
            .unwrap_or_else(|_| unreachable!())
    }

    /// Resumes execution after having submitted the transaction.
    pub fn resume(self, success: bool) -> HostVm {
        let host_fn = match self.inner.common.registered_functions[self.calling] {
            FunctionImport::Resolved(f) => f,
            FunctionImport::Unresolved { .. } => unreachable!(),
        };

        self.inner.alloc_write_and_return_pointer_size(
            host_fn.name(),
            if success {
                iter::once(&[0x00])
            } else {
                iter::once(&[0x01])
            },
        )
    }
}

impl fmt::Debug for OffchainSubmitTransaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("OffchainSubmitTransaction").finish()
    }
}

/// Report about a log entry being emitted.
///
/// Use [`LogEmit::info`] to obtain what must be printed.
pub struct LogEmit {
    inner: Box<Inner>,
    log_entry: LogEmitInner,
}

enum LogEmitInner {
    Num(u64),
    Utf8 {
        /// Pointer to the string. Guaranteed to be in range and to be UTF-8.
        str_ptr: u32,
        /// Size of the string. Guaranteed to be in range and to be UTF-8.
        str_size: u32,
    },
    Hex {
        /// Pointer to the data. Guaranteed to be in range.
        data_ptr: u32,
        /// Size of the data. Guaranteed to be in range.
        data_size: u32,
    },
    Log {
        /// Log level. Arbitrary number indicated by runtime, but typically in the `1..=5` range.
        log_level: u32,
        /// Pointer to the string of the log target. Guaranteed to be in range and to be UTF-8.
        target_str_ptr: u32,
        /// Size of the string of the log target. Guaranteed to be in range and to be UTF-8.
        target_str_size: u32,
        /// Pointer to the string of the log message. Guaranteed to be in range and to be UTF-8.
        msg_str_ptr: u32,
        /// Size of the string of the log message. Guaranteed to be in range and to be UTF-8.
        msg_str_size: u32,
    },
}

impl LogEmit {
    /// Returns the data that the runtime would like to print.
    pub fn info(&'_ self) -> LogEmitInfo<'_> {
        match self.log_entry {
            LogEmitInner::Num(n) => LogEmitInfo::Num(n),
            LogEmitInner::Utf8 { str_ptr, str_size } => LogEmitInfo::Utf8(LogEmitInfoStr {
                data: Box::new(
                    self.inner
                        .vm
                        .read_memory(str_ptr, str_size)
                        .unwrap_or_else(|_| unreachable!()),
                ),
            }),
            LogEmitInner::Hex {
                data_ptr,
                data_size,
            } => LogEmitInfo::Hex(LogEmitInfoHex {
                data: Box::new(
                    self.inner
                        .vm
                        .read_memory(data_ptr, data_size)
                        .unwrap_or_else(|_| unreachable!()),
                ),
            }),
            LogEmitInner::Log {
                msg_str_ptr,
                msg_str_size,
                target_str_ptr,
                target_str_size,
                log_level,
            } => LogEmitInfo::Log {
                log_level,
                target: LogEmitInfoStr {
                    data: Box::new(
                        self.inner
                            .vm
                            .read_memory(target_str_ptr, target_str_size)
                            .unwrap_or_else(|_| unreachable!()),
                    ),
                },
                message: LogEmitInfoStr {
                    data: Box::new(
                        self.inner
                            .vm
                            .read_memory(msg_str_ptr, msg_str_size)
                            .unwrap_or_else(|_| unreachable!()),
                    ),
                },
            },
        }
    }

    /// Resumes execution.
    pub fn resume(self) -> HostVm {
        HostVm::ReadyToRun(ReadyToRun {
            inner: self.inner,
            resume_value: None,
        })
    }
}

impl fmt::Debug for LogEmit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LogEmit")
            .field("info", &self.info())
            .finish()
    }
}

/// Detail about what a [`LogEmit`] should output. See [`LogEmit::info`].
#[derive(Debug)]
pub enum LogEmitInfo<'a> {
    /// Must output a single number.
    Num(u64),
    /// Must output a UTF-8 string.
    Utf8(LogEmitInfoStr<'a>),
    /// Must output the hexadecimal encoding of the given buffer.
    Hex(LogEmitInfoHex<'a>),
    /// Must output a log line.
    Log {
        /// Log level. Arbitrary number indicated by runtime, but typically in the `1..=5` range.
        log_level: u32,
        /// "Target" of the log. Arbitrary string indicated by the runtime. Typically indicates
        /// the subsystem which has emitted the log line.
        target: LogEmitInfoStr<'a>,
        /// Actual log message being emitted.
        message: LogEmitInfoStr<'a>,
    },
}

/// See [`LogEmitInfo`]. Use the `AsRef` trait implementation to retrieve the buffer.
pub struct LogEmitInfoHex<'a> {
    // TODO: don't use a Box once Rust supports type Foo = impl Trait;
    data: Box<dyn AsRef<[u8]> + Send + Sync + 'a>,
}

impl<'a> AsRef<[u8]> for LogEmitInfoHex<'a> {
    fn as_ref(&self) -> &[u8] {
        (*self.data).as_ref()
    }
}

impl<'a> fmt::Debug for LogEmitInfoHex<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.as_ref(), f)
    }
}

impl<'a> fmt::Display for LogEmitInfoHex<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&hex::encode(self.as_ref()), f)
    }
}

/// See [`LogEmitInfo`]. Use the `AsRef` trait implementation to retrieve the string.
pub struct LogEmitInfoStr<'a> {
    // TODO: don't use a Box once Rust supports type Foo = impl Trait;
    data: Box<dyn AsRef<[u8]> + Send + Sync + 'a>,
}

impl<'a> AsRef<str> for LogEmitInfoStr<'a> {
    fn as_ref(&self) -> &str {
        let data = (*self.data).as_ref();
        // The creator of `LogEmitInfoStr` always makes sure that the string is indeed UTF-8
        // before creating it.
        str::from_utf8(data).unwrap_or_else(|_| unreachable!())
    }
}

impl<'a> fmt::Debug for LogEmitInfoStr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.as_ref(), f)
    }
}

impl<'a> fmt::Display for LogEmitInfoStr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.as_ref(), f)
    }
}

/// Queries the maximum log level.
pub struct GetMaxLogLevel {
    inner: Box<Inner>,
}

impl GetMaxLogLevel {
    /// Resumes execution after indicating the maximum log level.
    ///
    /// 0 means off, 1 means error, 2 means warn, 3 means info, 4 means debug, 5 means trace.
    pub fn resume(self, max_level: u32) -> HostVm {
        HostVm::ReadyToRun(ReadyToRun {
            inner: self.inner,
            resume_value: Some(vm::WasmValue::I32(i32::from_ne_bytes(
                max_level.to_ne_bytes(),
            ))),
        })
    }
}

impl fmt::Debug for GetMaxLogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("GetMaxLogLevel").finish()
    }
}

/// Declares the start of a transaction.
pub struct StartStorageTransaction {
    inner: Box<Inner>,
}

impl StartStorageTransaction {
    /// Resumes execution after having acknowledged the event.
    pub fn resume(self) -> HostVm {
        HostVm::ReadyToRun(ReadyToRun {
            inner: self.inner,
            resume_value: None,
        })
    }
}

impl fmt::Debug for StartStorageTransaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("StartStorageTransaction").finish()
    }
}

/// Declares the end of a transaction.
pub struct EndStorageTransaction {
    inner: Box<Inner>,
}

impl EndStorageTransaction {
    /// Resumes execution after having acknowledged the event.
    pub fn resume(self) -> HostVm {
        HostVm::ReadyToRun(ReadyToRun {
            inner: self.inner,
            resume_value: None,
        })
    }
}

impl fmt::Debug for EndStorageTransaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("EndStorageTransaction").finish()
    }
}

#[derive(Clone)]
enum FunctionImport {
    Resolved(HostFunction),
    Unresolved { module: String, name: String },
}

/// Running virtual machine. Shared between all the variants in [`HostVm`].
struct Inner {
    /// Inner lower-level virtual machine.
    vm: vm::VirtualMachine,

    /// The depth of storage transaction started with `ext_storage_start_transaction_version_1`.
    storage_transaction_depth: u32,

    /// The host provides a "batch signature verification" mechanism, where the runtime can start
    /// verifying multiple signatures at once. This mechanism is deprecated, but is emulated
    /// through a simple field.
    ///
    /// Contains `Some` if and only if the runtime is currently within a batch signatures
    /// verification. If `Some`, contains `true` if all the signatures have been verified
    /// successfully so far.
    signatures_batch_verification: Option<bool>,

    /// Memory allocator in order to answer the calls to `malloc` and `free`.
    allocator: allocator::FreeingBumpHeapAllocator,

    /// Value passed as parameter.
    storage_proof_size_behavior: StorageProofSizeBehavior,

    /// Fields that are kept as is even during the execution.
    common: Box<VmCommon>,
}

impl Inner {
    /// Uses the memory allocator to allocate some memory for the given data, writes the data in
    /// memory, and returns an [`HostVm`] ready for the Wasm `host_fn` return.
    ///
    /// The data is passed as a list of chunks. These chunks will be laid out linearly in memory.
    ///
    /// The function name passed as parameter is used for error-reporting reasons.
    ///
    /// # Panic
    ///
    /// Must only be called while the Wasm is handling an `host_fn`.
    ///
    fn alloc_write_and_return_pointer_size(
        mut self: Box<Self>,
        function_name: &'static str,
        data: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
    ) -> HostVm {
        let mut data_len = 0u32;
        for chunk in data.clone() {
            data_len =
                data_len.saturating_add(u32::try_from(chunk.as_ref().len()).unwrap_or(u32::MAX));
        }

        let dest_ptr = match self.alloc(function_name, data_len) {
            Ok(p) => p,
            Err(error) => {
                return HostVm::Error {
                    error,
                    prototype: self.into_prototype(),
                };
            }
        };

        let mut ptr_iter = dest_ptr;
        for chunk in data {
            let chunk = chunk.as_ref();
            self.vm
                .write_memory(ptr_iter, chunk)
                .unwrap_or_else(|_| unreachable!());
            ptr_iter += u32::try_from(chunk.len()).unwrap_or(u32::MAX);
        }

        let ret_val = (u64::from(data_len) << 32) | u64::from(dest_ptr);
        let ret_val = i64::from_ne_bytes(ret_val.to_ne_bytes());

        ReadyToRun {
            inner: self,
            resume_value: Some(vm::WasmValue::I64(ret_val)),
        }
        .into()
    }

    /// Uses the memory allocator to allocate some memory for the given data, writes the data in
    /// memory, and returns an [`HostVm`] ready for the Wasm `host_fn` return.
    ///
    /// The data is passed as a list of chunks. These chunks will be laid out linearly in memory.
    ///
    /// The function name passed as parameter is used for error-reporting reasons.
    ///
    /// # Panic
    ///
    /// Must only be called while the Wasm is handling an `host_fn`.
    ///
    fn alloc_write_and_return_pointer(
        mut self: Box<Self>,
        function_name: &'static str,
        data: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
    ) -> HostVm {
        let mut data_len = 0u32;
        for chunk in data.clone() {
            data_len =
                data_len.saturating_add(u32::try_from(chunk.as_ref().len()).unwrap_or(u32::MAX));
        }

        let dest_ptr = match self.alloc(function_name, data_len) {
            Ok(p) => p,
            Err(error) => {
                return HostVm::Error {
                    error,
                    prototype: self.into_prototype(),
                };
            }
        };

        let mut ptr_iter = dest_ptr;
        for chunk in data {
            let chunk = chunk.as_ref();
            self.vm
                .write_memory(ptr_iter, chunk)
                .unwrap_or_else(|_| unreachable!());
            ptr_iter += u32::try_from(chunk.len()).unwrap_or(u32::MAX);
        }

        let ret_val = i32::from_ne_bytes(dest_ptr.to_ne_bytes());
        ReadyToRun {
            inner: self,
            resume_value: Some(vm::WasmValue::I32(ret_val)),
        }
        .into()
    }

    /// Uses the memory allocator to allocate some memory.
    ///
    /// The function name passed as parameter is used for error-reporting reasons.
    ///
    /// # Panic
    ///
    /// Must only be called while the Wasm is handling an `host_fn`.
    ///
    fn alloc(&mut self, function_name: &'static str, size: u32) -> Result<u32, Error> {
        // Use the allocator to decide where the value will be written.
        let dest_ptr = match self.allocator.allocate(
            &mut MemAccess {
                vm: MemAccessVm::Running(&mut self.vm),
                memory_total_pages: self.common.memory_total_pages,
            },
            size,
        ) {
            Ok(p) => p,
            Err(_) => {
                return Err(Error::OutOfMemory {
                    function: function_name,
                    requested_size: size,
                });
            }
        };

        // Unfortunately this function doesn't stop here.
        // We lie to the allocator. The allocator thinks that there are `self.memory_total_pages`
        // allocated and available, while in reality it can be less.
        // The allocator might thus allocate memory at a location above the current memory size.
        // To handle this, we grow the memory.

        // Offset of the memory page where the last allocated byte is found.
        let last_byte_memory_page = HeapPages::new((dest_ptr + size - 1) / (64 * 1024));

        // Grow the memory more if necessary.
        // Please note the `=`. For example if we write to page 0, we want to have at least 1 page
        // allocated.
        let current_num_pages = self.vm.memory_size();
        debug_assert!(current_num_pages <= self.common.memory_total_pages);
        if current_num_pages <= last_byte_memory_page {
            // For now, we grow the memory just enough to fit.
            // TODO: do better
            // Note the order of operations: we add 1 at the end to avoid a potential overflow
            // in case `last_byte_memory_page` is the maximum possible value.
            let to_grow = last_byte_memory_page - current_num_pages + HeapPages::new(1);

            // We check at initialization that the virtual machine is capable of growing up to
            // `memory_total_pages`, meaning that this can't panic.
            self.vm
                .grow_memory(to_grow)
                .unwrap_or_else(|_| unreachable!());
        }

        Ok(dest_ptr)
    }

    /// Turns the virtual machine back into a prototype.
    fn into_prototype(self) -> HostVmPrototype {
        HostVmPrototype {
            vm_proto: self.vm.into_prototype(),
            common: self.common,
        }
    }
}

/// Error that can happen when initializing a VM.
#[derive(Debug, derive_more::From, derive_more::Display, derive_more::Error, Clone)]
pub enum NewErr {
    /// Error in the format of the runtime code.
    #[display("{_0}")]
    BadFormat(ModuleFormatError),
    /// Error while initializing the virtual machine.
    #[display("{_0}")]
    VirtualMachine(vm::NewErr),
    /// Error while finding the runtime-version-related sections in the Wasm blob.
    #[display("Error in runtime spec Wasm sections: {_0}")]
    RuntimeVersion(FindEmbeddedRuntimeVersionError),
    /// Error while calling `Core_version` to determine the runtime version.
    #[display("Error while calling Core_version: {_0}")]
    CoreVersion(CoreVersionError),
    /// Couldn't find the `__heap_base` symbol in the Wasm code.
    HeapBaseNotFound,
    /// Maximum size of the Wasm memory found in the module is too low to provide the requested
    /// number of heap pages.
    MemoryMaxSizeTooLow,
}

/// Error while determining .
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum FindEmbeddedRuntimeVersionError {
    /// Error while finding the custom section.
    #[display("{_0}")]
    FindSections(FindEncodedEmbeddedRuntimeVersionApisError),
    /// Error while decoding the runtime version.
    RuntimeVersionDecode,
    /// Error while decoding the runtime APIs.
    #[display("{_0}")]
    RuntimeApisDecode(CoreVersionApisFromSliceErr),
}

/// Error that can happen when starting a VM.
#[derive(Debug, Clone, derive_more::From, derive_more::Display, derive_more::Error)]
pub enum StartErr {
    /// Error while starting the virtual machine.
    #[display("{_0}")]
    VirtualMachine(vm::StartErr),
    /// The size of the input data is too large.
    DataSizeOverflow,
}

/// Reason why the Wasm blob isn't conforming to the runtime environment.
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub enum Error {
    /// Error in the Wasm code execution.
    #[display("{_0}")]
    Trap(vm::Trap),
    /// Runtime has called the `ext_panic_handler_abort_on_panic_version_1` host function.
    #[display("Runtime has aborted: {message:?}")]
    AbortOnPanic {
        /// Message generated by the runtime.
        message: String,
    },
    /// A non-`i64` value has been returned by the Wasm entry point.
    #[display("A non-I64 value has been returned: {actual:?}")]
    BadReturnValue {
        /// Type that has actually gotten returned. `None` for "void".
        actual: Option<vm::ValueType>,
    },
    /// The pointer and size returned by the Wasm entry point function are invalid.
    #[display("The pointer and size returned by the function are invalid")]
    ReturnedPtrOutOfRange {
        /// Pointer that got returned.
        pointer: u32,
        /// Size that got returned.
        size: u32,
        /// Size of the virtual memory.
        memory_size: u32,
    },
    /// Called a function that is unknown to the host.
    ///
    /// > **Note**: Can only happen if `allow_unresolved_imports` was `true`.
    #[display("Called unresolved function `{module_name}`:`{function}`")]
    UnresolvedFunctionCalled {
        /// Name of the function that was unresolved.
        function: String,
        /// Name of module associated with the unresolved function.
        module_name: String,
    },
    /// Failed to decode a SCALE-encoded parameter.
    ParamDecodeError,
    /// One parameter is expected to point to a buffer, but the pointer is out
    /// of range of the memory of the Wasm VM.
    #[display(
        "Bad pointer for parameter of index {param_num} of {function}: 0x{pointer:x}, \
        len = 0x{length:x}"
    )]
    ParamOutOfRange {
        /// Name of the function being called where a type mismatch happens.
        function: &'static str,
        /// Index of the invalid parameter. The first parameter has index 0.
        param_num: usize,
        /// Pointer passed as parameter.
        pointer: u32,
        /// Expected length of the buffer.
        ///
        /// Depending on the function, this can either be an implicit length
        /// or a length passed as parameter.
        length: u32,
    },
    /// One parameter is expected to point to a UTF-8 string, but the buffer
    /// isn't valid UTF-8.
    #[display("UTF-8 error for parameter of index {param_num} of {function}: {error}")]
    Utf8Error {
        /// Name of the function being called where a type mismatch happens.
        function: &'static str,
        /// Index of the invalid parameter. The first parameter has index 0.
        param_num: usize,
        /// Decoding error that happened.
        #[error(source)]
        error: core::str::Utf8Error,
    },
    /// Called `ext_storage_rollback_transaction_version_1` or
    /// `ext_storage_commit_transaction_version_1` but no transaction was in progress.
    #[display("Attempted to end a transaction while none is in progress")]
    NoActiveTransaction,
    /// Execution has finished while a transaction started with
    /// `ext_storage_start_transaction_version_1` was still in progress.
    #[display("Execution returned with a pending storage transaction")]
    FinishedWithPendingTransaction,
    /// Error when allocating memory for a return type.
    #[display("Out of memory allocating 0x{requested_size:x} bytes during {function}")]
    OutOfMemory {
        /// Name of the function being called.
        function: &'static str,
        /// Size of the requested allocation.
        requested_size: u32,
    },
    /// Called `ext_allocator_free_version_1` with an invalid pointer.
    #[display("Bad pointer passed to ext_allocator_free_version_1: 0x{pointer:x}")]
    FreeError {
        /// Pointer that was expected to be freed.
        pointer: u32,
    },
    /// Mismatch between the state trie version provided as parameter and the state trie version
    /// found in the runtime specification.
    #[display(
        "Mismatch between the state trie version provided as parameter ({parameter:?}) and \
        the state trie version found in the runtime specification ({specification:?})."
    )]
    StateVersionMismatch {
        /// The version passed as parameter.
        parameter: TrieEntryVersion,
        /// The version in the specification.
        specification: TrieEntryVersion,
    },
    /// Called `ext_default_child_storage_root_version_1` or
    /// `ext_default_child_storage_root_version_2` on a child trie that doesn't exist.
    #[display(
        "Called `ext_default_child_storage_root_version_1` or
        `ext_default_child_storage_root_version_2` on a child trie that doesn't exist."
    )]
    ChildStorageRootTrieDoesntExist,
    /// Runtime has tried to perform a signature batch verification before initiating a batch
    /// verification.
    BatchVerifyWithoutStarting,
    /// Runtime has tried to initiate a batch signatures verification while there was already one
    /// in progress.
    AlreadyBatchVerify,
    /// Runtime has tried to finish a batch signatures verification while none is in progress.
    NoBatchVerify,
    /// The host function isn't implemented.
    // TODO: this variant should eventually disappear as all functions are implemented
    #[display("Host function not implemented: {function}")]
    HostFunctionNotImplemented {
        /// Name of the function being called.
        function: &'static str,
    },
}

// Glue between the `allocator` module and the `vm` module.
//
// The allocator believes that there are `memory_total_pages` pages available and allocated, where
// `memory_total_pages` is equal to `heap_base + heap_pages`, while in reality, because we grow
// memory lazily, there might be fewer.
struct MemAccess<'a> {
    vm: MemAccessVm<'a>,
    memory_total_pages: HeapPages,
}

enum MemAccessVm<'a> {
    Prepare(&'a mut vm::Prepare),
    Running(&'a mut vm::VirtualMachine),
}

impl<'a> allocator::Memory for MemAccess<'a> {
    fn read_le_u64(&self, ptr: u32) -> Result<u64, allocator::Error> {
        if (ptr + 8) > u32::from(self.memory_total_pages) * 64 * 1024 {
            return Err(allocator::Error::Other);
        }

        // Note that this function (`read_le_u64`) really should take ̀`&mut self` but that is
        // unfortunately not the case, meaning that we can't "just" grow the memory if trying
        // to access an out of bound location.
        //
        // Additionally, the value being read can in theory overlap between an allocated and
        // non-allocated parts of the memory, making this more complicated.

        // Offset of the memory page where the first byte of the value will be read.
        let accessed_memory_page_start = HeapPages::new(ptr / (64 * 1024));
        // Offset of the memory page where the last byte of the value will be read.
        let accessed_memory_page_end = HeapPages::new((ptr + 7) / (64 * 1024));
        // Number of pages currently allocated.
        let current_num_pages = match self.vm {
            MemAccessVm::Prepare(ref vm) => vm.memory_size(),
            MemAccessVm::Running(ref vm) => vm.memory_size(),
        };
        debug_assert!(current_num_pages <= self.memory_total_pages);

        if accessed_memory_page_end < current_num_pages {
            // This is the simple case: the memory access is in bounds.
            match self.vm {
                MemAccessVm::Prepare(ref vm) => {
                    let bytes = vm.read_memory(ptr, 8).unwrap_or_else(|_| unreachable!());
                    Ok(u64::from_le_bytes(
                        <[u8; 8]>::try_from(bytes.as_ref()).unwrap_or_else(|_| unreachable!()),
                    ))
                }
                MemAccessVm::Running(ref vm) => {
                    let bytes = vm.read_memory(ptr, 8).unwrap_or_else(|_| unreachable!());
                    Ok(u64::from_le_bytes(
                        <[u8; 8]>::try_from(bytes.as_ref()).unwrap_or_else(|_| unreachable!()),
                    ))
                }
            }
        } else if accessed_memory_page_start < current_num_pages {
            // Memory access is partially in bounds. This is the most complicated situation.
            match self.vm {
                MemAccessVm::Prepare(ref vm) => {
                    let partial_bytes = vm
                        .read_memory(ptr, u32::from(current_num_pages) * 64 * 1024 - ptr)
                        .unwrap_or_else(|_| unreachable!());
                    let partial_bytes = partial_bytes.as_ref();
                    debug_assert!(partial_bytes.len() < 8);

                    let mut out = [0; 8];
                    out[..partial_bytes.len()].copy_from_slice(partial_bytes);
                    Ok(u64::from_le_bytes(out))
                }
                MemAccessVm::Running(ref vm) => {
                    let partial_bytes = vm
                        .read_memory(ptr, u32::from(current_num_pages) * 64 * 1024 - ptr)
                        .unwrap_or_else(|_| unreachable!());
                    let partial_bytes = partial_bytes.as_ref();
                    debug_assert!(partial_bytes.len() < 8);

                    let mut out = [0; 8];
                    out[..partial_bytes.len()].copy_from_slice(partial_bytes);
                    Ok(u64::from_le_bytes(out))
                }
            }
        } else {
            // Everything out bounds. Memory is zero.
            Ok(0)
        }
    }

    fn write_le_u64(&mut self, ptr: u32, val: u64) -> Result<(), allocator::Error> {
        if (ptr + 8) > u32::from(self.memory_total_pages) * 64 * 1024 {
            return Err(allocator::Error::Other);
        }

        let bytes = val.to_le_bytes();

        // Offset of the memory page where the last byte of the value will be written.
        let written_memory_page = HeapPages::new((ptr + 7) / (64 * 1024));

        // Grow the memory more if necessary.
        // Please note the `<=`. For example if we write to page 0, we want to have at least 1 page
        // allocated.
        let current_num_pages = match self.vm {
            MemAccessVm::Prepare(ref vm) => vm.memory_size(),
            MemAccessVm::Running(ref vm) => vm.memory_size(),
        };
        debug_assert!(current_num_pages <= self.memory_total_pages);
        if current_num_pages <= written_memory_page {
            // For now, we grow the memory just enough to fit.
            // TODO: do better
            // Note the order of operations: we add 1 at the end to avoid a potential overflow
            // in case `written_memory_page` is the maximum possible value.
            let to_grow = written_memory_page - current_num_pages + HeapPages::new(1);

            // We check at initialization that the virtual machine is capable of growing up to
            // `memory_total_pages`, meaning that this can't panic.
            match self.vm {
                MemAccessVm::Prepare(ref mut vm) => {
                    vm.grow_memory(to_grow).unwrap_or_else(|_| unreachable!())
                }
                MemAccessVm::Running(ref mut vm) => {
                    vm.grow_memory(to_grow).unwrap_or_else(|_| unreachable!())
                }
            }
        }

        match self.vm {
            MemAccessVm::Prepare(ref mut vm) => vm
                .write_memory(ptr, &bytes)
                .unwrap_or_else(|_| unreachable!()),
            MemAccessVm::Running(ref mut vm) => vm
                .write_memory(ptr, &bytes)
                .unwrap_or_else(|_| unreachable!()),
        }
        Ok(())
    }

    fn size(&self) -> u32 {
        // Lie to the allocator to pretend that `memory_total_pages` are available.
        u32::from(self.memory_total_pages)
            .saturating_mul(64)
            .saturating_mul(1024)
    }
}
