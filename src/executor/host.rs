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
//! use smoldot::executor::host::{Config, HeapPages, HostVm, HostVmPrototype};
//!
//! # let wasm_binary_code: &[u8] = return;
//!
//! // Start executing a function on the runtime.
//! let mut vm: HostVm = {
//!     let prototype = HostVmPrototype::new(Config {
//!         module: &wasm_binary_code,
//!         heap_pages: HeapPages::from(2048),
//!         exec_hint: smoldot::executor::vm::ExecHint::Oneshot,
//!         allow_unresolved_imports: false
//!     }).unwrap();
//!     prototype.run_no_param("Core_version").unwrap().into()
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

use alloc::{
    borrow::ToOwned as _,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};
use core::{fmt, hash::Hasher as _, iter, str};
use sha2::Digest as _;
use tiny_keccak::Hasher as _;

pub mod runtime_version;

pub use runtime_version::{CoreVersion, CoreVersionError, CoreVersionRef};
pub use vm::HeapPages;
pub use zstd::Error as ModuleFormatError;

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

/// Prototype for an [`HostVm`].
///
/// > **Note**: This struct implements `Clone`. Cloning a [`HostVmPrototype`] allocates memory
/// >           necessary for the clone to run.
// TODO: this behaviour ^ interacts with zero-ing memory when resetting from a vm to a prototype; figure out and clarify
pub struct HostVmPrototype {
    /// Original module used to instantiate the prototype.
    ///
    /// > **Note**: Cloning this object is cheap.
    module: vm::Module,

    /// Runtime version of this runtime.
    ///
    /// Always `Some`, except at initialization.
    runtime_version: Option<CoreVersion>,

    /// Inner virtual machine prototype.
    vm_proto: vm::VirtualMachinePrototype,

    /// Initial value of the `__heap_base` global in the Wasm module. Used to initialize the memory
    /// allocator.
    heap_base: u32,

    /// List of functions that the Wasm code imports.
    ///
    /// The keys of this `Vec` (i.e. the `usize` indices) have been passed to the virtual machine
    /// executor. Whenever the Wasm code invokes a host function, we obtain its index, and look
    /// within this `Vec` to know what to do.
    registered_functions: Vec<FunctionImport>,

    /// Value of `heap_pages` passed to [`HostVmPrototype::new`].
    heap_pages: HeapPages,

    /// Values passed to [`HostVmPrototype::new`].
    allow_unresolved_imports: bool,

    /// Total number of pages of Wasm memory. This is equal to `heap_base / 64k` (rounded up) plus
    /// `heap_pages`.
    memory_total_pages: HeapPages,
}

impl HostVmPrototype {
    /// Creates a new [`HostVmPrototype`]. Parses and potentially JITs the module.
    pub fn new(config: Config<impl AsRef<[u8]>>) -> Result<Self, NewErr> {
        // TODO: configurable maximum allowed size? a uniform value is important for consensus
        let module = zstd::zstd_decode_if_necessary(config.module.as_ref(), 50 * 1024 * 1024)
            .map_err(NewErr::BadFormat)?;
        let runtime_version = runtime_version::find_embedded_runtime_version(&module)
            .ok()
            .flatten(); // TODO: return error instead of using `ok()`? unclear
        let module = vm::Module::new(module, config.exec_hint).map_err(vm::NewErr::ModuleError)?;
        Self::from_module(
            module,
            config.heap_pages,
            config.allow_unresolved_imports,
            runtime_version,
        )
    }

    fn from_module(
        module: vm::Module,
        heap_pages: HeapPages,
        allow_unresolved_imports: bool,
        runtime_version: Option<CoreVersion>,
    ) -> Result<Self, NewErr> {
        // Initialize the virtual machine.
        // Each symbol requested by the Wasm runtime will be put in `registered_functions`. Later,
        // when a function is invoked, the Wasm virtual machine will pass indices within that
        // array.
        let (mut vm_proto, registered_functions) = {
            let mut registered_functions = Vec::new();
            let vm_proto = vm::VirtualMachinePrototype::new(
                &module,
                // This closure is called back for each function that the runtime imports.
                |mod_name, f_name, _signature| {
                    if mod_name != "env" {
                        return Err(());
                    }

                    let id = registered_functions.len();
                    registered_functions.push(match HostFunction::by_name(f_name) {
                        Some(f) => FunctionImport::Resolved(f),
                        None if !allow_unresolved_imports => return Err(()),
                        None => FunctionImport::Unresolved {
                            name: f_name.to_owned(),
                            module: mod_name.to_owned(),
                        },
                    });
                    Ok(id)
                },
            )?;
            registered_functions.shrink_to_fit();
            (vm_proto, registered_functions)
        };

        // In the runtime environment, Wasm blobs must export a global symbol named
        // `__heap_base` indicating where the memory allocator is allowed to allocate memory.
        let heap_base = vm_proto
            .global_value("__heap_base")
            .map_err(|_| NewErr::HeapBaseNotFound)?;

        let memory_total_pages = if heap_base == 0 {
            heap_pages
        } else {
            HeapPages::new((heap_base - 1) / (64 * 1024)) + heap_pages + HeapPages::new(1)
        };

        if vm_proto
            .memory_max_pages()
            .map_or(false, |max| max < memory_total_pages)
        {
            return Err(NewErr::MemoryMaxSizeTooLow);
        }

        let mut host_vm_prototype = HostVmPrototype {
            module,
            runtime_version,
            vm_proto,
            heap_base,
            registered_functions,
            heap_pages,
            allow_unresolved_imports,
            memory_total_pages,
        };

        // Call `Core_version` if no runtime version is known yet.
        if host_vm_prototype.runtime_version.is_none() {
            let mut vm: HostVm = match host_vm_prototype.run_no_param("Core_version") {
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
                                    return Err(NewErr::CoreVersion(CoreVersionError::Decode))
                                }
                            };

                        host_vm_prototype = finished.into_prototype();
                        host_vm_prototype.runtime_version = Some(version);
                        break;
                    }

                    // Emitted log lines are ignored.
                    HostVm::GetMaxLogLevel(resume) => {
                        vm = resume.resume(0); // Off
                    }
                    HostVm::LogEmit(log) => vm = log.resume(),

                    HostVm::Error { error, .. } => {
                        return Err(NewErr::CoreVersion(CoreVersionError::Run(error)))
                    }

                    // Getting the runtime version is a very core operation, and very few
                    // external calls are allowed.
                    _ => return Err(NewErr::CoreVersion(CoreVersionError::ForbiddenHostFunction)),
                }
            }
        }

        // Success!
        debug_assert!(host_vm_prototype.runtime_version.is_some());
        Ok(host_vm_prototype)
    }

    /// Returns the number of heap pages that were passed to [`HostVmPrototype::new`].
    pub fn heap_pages(&self) -> HeapPages {
        self.heap_pages
    }

    /// Returns the runtime version found in the module.
    pub fn runtime_version(&self) -> &CoreVersion {
        self.runtime_version.as_ref().unwrap()
    }

    /// Starts the VM, calling the function passed as parameter.
    pub fn run(self, function_to_call: &str, data: &[u8]) -> Result<ReadyToRun, (StartErr, Self)> {
        self.run_vectored(function_to_call, iter::once(data))
    }

    /// Same as [`HostVmPrototype::run`], except that the function doesn't need any parameter.
    pub fn run_no_param(self, function_to_call: &str) -> Result<ReadyToRun, (StartErr, Self)> {
        self.run_vectored(function_to_call, iter::empty::<Vec<u8>>())
    }

    /// Same as [`HostVmPrototype::run`], except that the function parameter can be passed as
    /// a list of buffers. All the buffers will be concatenated in memory.
    pub fn run_vectored(
        mut self,
        function_to_call: &str,
        data: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
    ) -> Result<ReadyToRun, (StartErr, Self)> {
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

        // Now create the actual virtual machine. We pass as parameter `heap_base` as the location
        // of the input data.
        let mut vm = match self.vm_proto.start(
            vm::HeapPages::new(1 + (data_len_u32 + self.heap_base) / (64 * 1024)), // TODO: `data_len_u32 + ` is a hack for the start value; solve with https://github.com/paritytech/smoldot/issues/132
            function_to_call,
            &[
                vm::WasmValue::I32(i32::from_ne_bytes(self.heap_base.to_ne_bytes())),
                vm::WasmValue::I32(i32::from_ne_bytes(data_len_u32.to_ne_bytes())),
            ],
        ) {
            Ok(vm) => vm,
            Err((error, vm_proto)) => {
                self.vm_proto = vm_proto;
                return Err((error.into(), self));
            }
        };

        // Now writing the input data into the VM.
        let mut after_input_data = self.heap_base;
        for data in data {
            let data = data.as_ref();
            vm.write_memory(after_input_data, data).unwrap();
            after_input_data = after_input_data
                .checked_add(u32::try_from(data.len()).unwrap())
                .unwrap();
        }

        // Initialize the state of the memory allocator. This is the allocator that is later used
        // when the Wasm code requests variable-length data.
        let allocator = allocator::FreeingBumpHeapAllocator::new(after_input_data);

        Ok(ReadyToRun {
            resume_value: None,
            inner: Inner {
                module: self.module,
                runtime_version: self.runtime_version,
                vm,
                heap_base: self.heap_base,
                heap_pages: self.heap_pages,
                allow_unresolved_imports: self.allow_unresolved_imports,
                memory_total_pages: self.memory_total_pages,
                registered_functions: self.registered_functions,
                storage_transaction_depth: 0,
                allocator,
            },
        })
    }
}

impl Clone for HostVmPrototype {
    fn clone(&self) -> Self {
        // The `from_module` function returns an error if the format of the module is invalid.
        // Since we have successfully called `from_module` with that same `module` earlier, it
        // is assumed that errors cannot happen.
        Self::from_module(
            self.module.clone(),
            self.heap_pages,
            self.allow_unresolved_imports,
            self.runtime_version.clone(),
        )
        .unwrap()
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
    /// Need to provide the trie root of the storage.
    #[from]
    ExternalStorageRoot(ExternalStorageRoot),
    /// Need to provide the storage key that follows a specific one.
    #[from]
    ExternalStorageNextKey(ExternalStorageNextKey),
    /// Must the set value of an off-chain storage entry.
    #[from]
    ExternalOffchainStorageSet(ExternalOffchainStorageSet),
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
            HostVm::ExternalOffchainStorageSet(inner) => inner.inner.into_prototype(),
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
    inner: Inner,
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
                let value_size = u32::try_from(ret >> 32).unwrap();
                let value_ptr = u32::try_from(ret & 0xffff_ffff).unwrap();

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
                }
            }

            Err(vm::RunErr::BadValueTy { .. }) => {
                // Tried to inject back the value returned by a host function, but it doesn't
                // match what the Wasm code expects.
                // TODO: check signatures at initialization instead?
                return HostVm::Error {
                    prototype: self.inner.into_prototype(),
                    error: Error::ReturnValueTypeMismatch,
                };
            }

            Err(vm::RunErr::Poisoned) => {
                // Can only happen if there's a bug somewhere.
                unreachable!()
            }
        };

        // The Wasm code has called an host_fn. The `id` is a value that we passed
        // at initialization, and corresponds to an index in `registered_functions`.
        let host_fn = match self.inner.registered_functions.get_mut(id) {
            Some(FunctionImport::Resolved(f)) => *f,
            Some(FunctionImport::Unresolved { name, module }) => {
                debug_assert!(self.inner.allow_unresolved_imports);
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

        // Check that the actual number of parameters matches the expected number.
        // This is done ahead of time in order to not forget.
        let expected_params_num = host_fn.num_parameters();
        if params.len() != expected_params_num {
            return HostVm::Error {
                error: Error::ParamsCountMismatch {
                    function: host_fn.name(),
                    expected: expected_params_num,
                    actual: params.len(),
                },
                prototype: self.inner.into_prototype(),
            };
        }

        // Passed a parameter index. Produces an `impl AsRef<[u8]>`.
        macro_rules! expect_pointer_size {
            ($num:expr) => {{
                let val = match &params[$num] {
                    vm::WasmValue::I64(v) => u64::from_ne_bytes(v.to_ne_bytes()),
                    v => {
                        return HostVm::Error {
                            error: Error::WrongParamTy {
                                function: host_fn.name(),
                                param_num: $num,
                                expected: vm::ValueType::I64,
                                actual: v.ty(),
                            },
                            prototype: self.inner.into_prototype(),
                        }
                    }
                };

                let len = u32::try_from(val >> 32).unwrap();
                let ptr = u32::try_from(val & 0xffffffff).unwrap();

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
                    v => {
                        return HostVm::Error {
                            error: Error::WrongParamTy {
                                function: host_fn.name(),
                                param_num: $num,
                                expected: vm::ValueType::I64,
                                actual: v.ty(),
                            },
                            prototype: self.inner.into_prototype(),
                        };
                    }
                };

                let len = u32::try_from(val >> 32).unwrap();
                let ptr = u32::try_from(val & 0xffffffff).unwrap();

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
                    v => {
                        return HostVm::Error {
                            error: Error::WrongParamTy {
                                function: host_fn.name(),
                                param_num: $num,
                                expected: vm::ValueType::I32,
                                actual: v.ty(),
                            },
                            prototype: self.inner.into_prototype(),
                        }
                    }
                };

                let result = self.inner.vm.read_memory(ptr, $size);
                match result {
                    Ok(v) => *<&[u8; $size]>::try_from(v.as_ref()).unwrap(),
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

        macro_rules! expect_u32 {
            ($num:expr) => {{
                match &params[$num] {
                    vm::WasmValue::I32(v) => u32::from_ne_bytes(v.to_ne_bytes()),
                    v => {
                        return HostVm::Error {
                            error: Error::WrongParamTy {
                                function: host_fn.name(),
                                param_num: $num,
                                expected: vm::ValueType::I32,
                                actual: v.ty(),
                            },
                            prototype: self.inner.into_prototype(),
                        }
                    }
                }
            }};
        }

        macro_rules! expect_state_version {
            ($num:expr) => {{
                match &params[$num] {
                    vm::WasmValue::I32(0) => trie::TrieEntryVersion::V0,
                    vm::WasmValue::I32(1) => trie::TrieEntryVersion::V1,
                    vm::WasmValue::I32(_) => {
                        return HostVm::Error {
                            error: Error::ParamDecodeError,
                            prototype: self.inner.into_prototype(),
                        }
                    }
                    v => {
                        return HostVm::Error {
                            error: Error::WrongParamTy {
                                function: host_fn.name(),
                                param_num: $num,
                                expected: vm::ValueType::I32,
                                actual: v.ty(),
                            },
                            prototype: self.inner.into_prototype(),
                        }
                    }
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
                    value: Some((value_ptr, value_size)),
                    inner: self.inner,
                })
            }
            HostFunction::ext_storage_get_version_1 => {
                let (key_ptr, key_size) = expect_pointer_size_raw!(0);
                HostVm::ExternalStorageGet(ExternalStorageGet {
                    key_ptr,
                    key_size,
                    calling: id,
                    value_out_ptr: None,
                    offset: 0,
                    max_size: u32::max_value(),
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
                    value: None,
                    inner: self.inner,
                })
            }
            HostFunction::ext_storage_exists_version_1 => {
                let (key_ptr, key_size) = expect_pointer_size_raw!(0);
                HostVm::ExternalStorageGet(ExternalStorageGet {
                    key_ptr,
                    key_size,
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
                    prefix_ptr,
                    prefix_size,
                    inner: self.inner,
                    max_keys_to_remove: None,
                    is_v2: false,
                })
            }
            HostFunction::ext_storage_clear_prefix_version_2 => {
                let (prefix_ptr, prefix_size) = expect_pointer_size_raw!(0);

                let max_keys_to_remove = {
                    let input = expect_pointer_size!(1);
                    let parsing_result: Result<_, nom::Err<(&[u8], nom::error::ErrorKind)>> =
                        nom::combinator::all_consuming(util::nom_option_decode(
                            nom::number::complete::le_u32,
                        ))(input.as_ref())
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
                    prefix_ptr,
                    prefix_size,
                    inner: self.inner,
                    max_keys_to_remove,
                    is_v2: true,
                })
            }
            HostFunction::ext_storage_root_version_1 => {
                HostVm::ExternalStorageRoot(ExternalStorageRoot { inner: self.inner })
            }
            HostFunction::ext_storage_root_version_2 => {
                let state_version = expect_state_version!(0);
                match state_version {
                    trie::TrieEntryVersion::V0 => {
                        HostVm::ExternalStorageRoot(ExternalStorageRoot { inner: self.inner })
                    }
                    trie::TrieEntryVersion::V1 => host_fn_not_implemented!(), // TODO: https://github.com/paritytech/smoldot/issues/1967
                }
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
            HostFunction::ext_storage_child_set_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_storage_child_get_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_storage_child_read_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_storage_child_clear_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_storage_child_storage_kill_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_storage_child_exists_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_storage_child_clear_prefix_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_storage_child_root_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_storage_child_next_key_version_1 => host_fn_not_implemented!(),
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
            HostFunction::ext_default_child_storage_get_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_default_child_storage_read_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_default_child_storage_storage_kill_version_1 => {
                host_fn_not_implemented!()
            }
            HostFunction::ext_default_child_storage_storage_kill_version_2 => {
                host_fn_not_implemented!()
            }
            HostFunction::ext_default_child_storage_storage_kill_version_3 => {
                host_fn_not_implemented!()
            }
            HostFunction::ext_default_child_storage_clear_prefix_version_1 => {
                host_fn_not_implemented!()
            }
            HostFunction::ext_default_child_storage_clear_prefix_version_2 => {
                host_fn_not_implemented!()
            }
            HostFunction::ext_default_child_storage_set_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_default_child_storage_clear_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_default_child_storage_exists_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_default_child_storage_next_key_version_1 => {
                host_fn_not_implemented!()
            }
            HostFunction::ext_default_child_storage_root_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_default_child_storage_root_version_2 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_ed25519_public_keys_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_ed25519_generate_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_ed25519_sign_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_ed25519_verify_version_1 => {
                let success = {
                    let public_key = ed25519_zebra::VerificationKey::try_from(
                        expect_pointer_constant_size!(2, 32),
                    );
                    if let Ok(public_key) = public_key {
                        let signature =
                            ed25519_zebra::Signature::from(expect_pointer_constant_size!(0, 64));
                        let message = expect_pointer_size!(1);
                        public_key.verify(&signature, message.as_ref()).is_ok()
                    } else {
                        false
                    }
                };

                HostVm::ReadyToRun(ReadyToRun {
                    resume_value: Some(vm::WasmValue::I32(if success { 1 } else { 0 })),
                    inner: self.inner,
                })
            }
            HostFunction::ext_crypto_sr25519_public_keys_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_sr25519_generate_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_sr25519_sign_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_sr25519_verify_version_1 => {
                let success = {
                    // The `unwrap()` below can only panic if the input is the wrong length, which
                    // we know can't happen.
                    let signing_public_key =
                        schnorrkel::PublicKey::from_bytes(&expect_pointer_constant_size!(2, 32))
                            .unwrap();

                    let signature = expect_pointer_constant_size!(0, 64);
                    let message = expect_pointer_size!(1);

                    signing_public_key
                        .verify_simple_preaudit_deprecated(
                            b"substrate",
                            message.as_ref(),
                            &signature,
                        )
                        .is_ok()
                };

                HostVm::ReadyToRun(ReadyToRun {
                    resume_value: Some(vm::WasmValue::I32(if success { 1 } else { 0 })),
                    inner: self.inner,
                })
            }
            HostFunction::ext_crypto_sr25519_verify_version_2 => {
                let success = {
                    // The two `unwrap()`s below can only panic if the input is the wrong
                    // length, which we know can't happen.
                    let signing_public_key =
                        schnorrkel::PublicKey::from_bytes(&expect_pointer_constant_size!(2, 32))
                            .unwrap();
                    let signature =
                        schnorrkel::Signature::from_bytes(&expect_pointer_constant_size!(0, 64))
                            .unwrap();

                    signing_public_key
                        .verify_simple(b"substrate", expect_pointer_size!(1).as_ref(), &signature)
                        .is_ok()
                };

                HostVm::ReadyToRun(ReadyToRun {
                    resume_value: Some(vm::WasmValue::I32(if success { 1 } else { 0 })),
                    inner: self.inner,
                })
            }
            HostFunction::ext_crypto_ecdsa_generate_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_crypto_ecdsa_sign_version_1 => {
                // NOTE: safe to unwrap here because we supply the nn to blake2b fn
                let data = <[u8; 32]>::try_from(
                    blake2_rfc::blake2b::blake2b(32, &[], expect_pointer_size!(0).as_ref())
                        .as_bytes(),
                )
                .unwrap();
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
            HostFunction::ext_crypto_ecdsa_verify_version_1 => {
                let success = {
                    // NOTE: safe to unwrap here because we supply the nn to blake2b fn
                    let data = <[u8; 32]>::try_from(
                        blake2_rfc::blake2b::blake2b(32, &[], expect_pointer_size!(0).as_ref())
                            .as_bytes(),
                    )
                    .unwrap();
                    let message = libsecp256k1::Message::parse(&data);

                    // signature (64 bytes) + recovery ID (1 byte)
                    let sig_bytes = expect_pointer_constant_size!(0, 65);
                    if let Ok(sig) = libsecp256k1::Signature::parse_standard_slice(&sig_bytes[..64])
                    {
                        if let Ok(ri) = libsecp256k1::RecoveryId::parse(sig_bytes[64]) {
                            if let Ok(actual) = libsecp256k1::recover(&message, &sig, &ri) {
                                expect_pointer_constant_size!(2, 33)[..]
                                    == actual.serialize_compressed()[..]
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };

                HostVm::ReadyToRun(ReadyToRun {
                    resume_value: Some(vm::WasmValue::I32(if success { 1 } else { 0 })),
                    inner: self.inner,
                })
            }
            HostFunction::ext_crypto_ecdsa_sign_prehashed_version_1 => {
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
                let success = {
                    let message =
                        libsecp256k1::Message::parse(&expect_pointer_constant_size!(0, 32));

                    // signature (64 bytes) + recovery ID (1 byte)
                    let sig_bytes = expect_pointer_constant_size!(0, 65);
                    if let Ok(sig) = libsecp256k1::Signature::parse_standard_slice(&sig_bytes[..64])
                    {
                        if let Ok(ri) = libsecp256k1::RecoveryId::parse(sig_bytes[64]) {
                            if let Ok(actual) = libsecp256k1::recover(&message, &sig, &ri) {
                                expect_pointer_constant_size!(2, 33)[..]
                                    == actual.serialize_compressed()[..]
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };

                HostVm::ReadyToRun(ReadyToRun {
                    resume_value: Some(vm::WasmValue::I32(if success { 1 } else { 0 })),
                    inner: self.inner,
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
                        } as u8);

                        if let Ok(v) = v {
                            let pubkey = libsecp256k1::recover(
                                &libsecp256k1::Message::parse_slice(&msg).unwrap(),
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
                        } as u8);

                        if let Ok(v) = v {
                            let pubkey = libsecp256k1::recover(
                                &libsecp256k1::Message::parse_slice(&msg).unwrap(),
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
                HostVm::ReadyToRun(ReadyToRun {
                    resume_value: None,
                    inner: self.inner,
                })
            }
            HostFunction::ext_crypto_finish_batch_verify_version_1 => {
                // This function is a dummy implementation. After `ext_crypto_start_batch_verify`
                // has been called, the runtime is supposed to call
                // `ext_crypto_ed25519_batch_verify`, `ext_crypto_sr25519_batch_verify`, or
                // `ext_crypto_ecdsa_batch_verify`, then retrieve the result using
                // `ext_crypto_finish_batch_verify`. However, none of the three
                // `<algo>_batch_verify` functions is supported by smoldot at the moment.
                // Thus, if the runtime calls `ext_crypto_finish_batch_verify`, then it
                // necessarily means that the batch is empty, and thus we always return success.
                // At the moment, batch signatures verification isn't enabled on any production
                // chain.
                // Once support for any of the `<algo>_batch_verify` function is added, this
                // implementation should of course change.
                HostVm::ReadyToRun(ReadyToRun {
                    resume_value: Some(vm::WasmValue::I32(1)),
                    inner: self.inner,
                })
            }
            HostFunction::ext_hashing_keccak_256_version_1 => {
                let mut keccak = tiny_keccak::Keccak::v256();
                keccak.update(expect_pointer_size!(0).as_ref());
                let mut out = [0u8; 32];
                keccak.finalize(&mut out);

                self.inner
                    .alloc_write_and_return_pointer(host_fn.name(), iter::once(&out))
            }
            HostFunction::ext_hashing_sha2_256_version_1 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(expect_pointer_size!(0));

                self.inner.alloc_write_and_return_pointer(
                    host_fn.name(),
                    iter::once(hasher.finalize().as_slice()),
                )
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
                let mut h0 = twox_hash::XxHash::with_seed(0);
                {
                    let data = expect_pointer_size!(0);
                    h0.write(data.as_ref());
                }
                let r0 = h0.finish();

                self.inner
                    .alloc_write_and_return_pointer(host_fn.name(), iter::once(&r0.to_le_bytes()))
            }
            HostFunction::ext_hashing_twox_128_version_1 => {
                let mut h0 = twox_hash::XxHash::with_seed(0);
                let mut h1 = twox_hash::XxHash::with_seed(1);
                {
                    let data = expect_pointer_size!(0);
                    let data = data.as_ref();
                    h0.write(data);
                    h1.write(data);
                }
                let r0 = h0.finish();
                let r1 = h1.finish();

                self.inner.alloc_write_and_return_pointer(
                    host_fn.name(),
                    iter::once(&r0.to_le_bytes()).chain(iter::once(&r1.to_le_bytes())),
                )
            }
            HostFunction::ext_hashing_twox_256_version_1 => {
                let mut h0 = twox_hash::XxHash::with_seed(0);
                let mut h1 = twox_hash::XxHash::with_seed(1);
                let mut h2 = twox_hash::XxHash::with_seed(2);
                let mut h3 = twox_hash::XxHash::with_seed(3);
                {
                    let data = expect_pointer_size!(0);
                    let data = data.as_ref();
                    h0.write(data);
                    h1.write(data);
                    h2.write(data);
                    h3.write(data);
                }
                let r0 = h0.finish();
                let r1 = h1.finish();
                let r2 = h2.finish();
                let r3 = h3.finish();

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
                HostVm::ExternalOffchainStorageSet(ExternalOffchainStorageSet {
                    key_ptr,
                    key_size,
                    value: Some((value_ptr, value_size)),
                    inner: self.inner,
                })
            }
            HostFunction::ext_offchain_index_clear_version_1 => {
                let (key_ptr, key_size) = expect_pointer_size_raw!(0);
                HostVm::ExternalOffchainStorageSet(ExternalOffchainStorageSet {
                    key_ptr,
                    key_size,
                    value: None,
                    inner: self.inner,
                })
            }
            HostFunction::ext_offchain_is_validator_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_offchain_submit_transaction_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_offchain_network_state_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_offchain_timestamp_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_offchain_sleep_until_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_offchain_random_seed_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_offchain_local_storage_set_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_offchain_local_storage_compare_and_set_version_1 => {
                host_fn_not_implemented!()
            }
            HostFunction::ext_offchain_local_storage_get_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_offchain_local_storage_clear_version_1 => host_fn_not_implemented!(),
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
            HostFunction::ext_sandbox_instantiate_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_sandbox_invoke_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_sandbox_memory_new_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_sandbox_memory_get_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_sandbox_memory_set_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_sandbox_memory_teardown_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_sandbox_instance_teardown_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_sandbox_get_global_val_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_trie_blake2_256_root_version_1
            | HostFunction::ext_trie_blake2_256_root_version_2 => {
                let state_version =
                    if matches!(host_fn, HostFunction::ext_trie_blake2_256_root_version_2) {
                        expect_state_version!(1)
                    } else {
                        trie::TrieEntryVersion::V0
                    };

                let result = {
                    let input = expect_pointer_size!(0);
                    let parsing_result: Result<_, nom::Err<(&[u8], nom::error::ErrorKind)>> =
                        nom::combinator::all_consuming(nom::combinator::flat_map(
                            crate::util::nom_scale_compact_usize,
                            |num_elems| {
                                nom::multi::many_m_n(
                                    num_elems,
                                    num_elems,
                                    nom::sequence::tuple((
                                        nom::combinator::flat_map(
                                            crate::util::nom_scale_compact_usize,
                                            nom::bytes::complete::take,
                                        ),
                                        nom::combinator::flat_map(
                                            crate::util::nom_scale_compact_usize,
                                            nom::bytes::complete::take,
                                        ),
                                    )),
                                )
                            },
                        ))(input.as_ref())
                        .map(|(_, parse_result)| parse_result);

                    match parsing_result {
                        Ok(elements) => Ok(trie::trie_root(state_version, &elements[..])),
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
            | HostFunction::ext_trie_blake2_256_ordered_root_version_2 => {
                let state_version = if matches!(
                    host_fn,
                    HostFunction::ext_trie_blake2_256_ordered_root_version_2
                ) {
                    expect_state_version!(1)
                } else {
                    trie::TrieEntryVersion::V0
                };

                let result = {
                    let input = expect_pointer_size!(0);
                    let parsing_result: Result<_, nom::Err<(&[u8], nom::error::ErrorKind)>> =
                        nom::combinator::all_consuming(nom::combinator::flat_map(
                            crate::util::nom_scale_compact_usize,
                            |num_elems| {
                                nom::multi::many_m_n(
                                    num_elems,
                                    num_elems,
                                    nom::combinator::flat_map(
                                        crate::util::nom_scale_compact_usize,
                                        nom::bytes::complete::take,
                                    ),
                                )
                            },
                        ))(input.as_ref())
                        .map(|(_, parse_result)| parse_result);

                    match parsing_result {
                        Ok(elements) => Ok(trie::ordered_root(state_version, &elements[..])),
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
            HostFunction::ext_trie_keccak_256_ordered_root_version_1 => host_fn_not_implemented!(),
            HostFunction::ext_trie_keccak_256_ordered_root_version_2 => host_fn_not_implemented!(),
            HostFunction::ext_misc_print_num_version_1 => {
                let num = match params[0] {
                    vm::WasmValue::I64(v) => u64::from_ne_bytes(v.to_ne_bytes()),
                    v => {
                        return HostVm::Error {
                            error: Error::WrongParamTy {
                                function: host_fn.name(),
                                param_num: 0,
                                expected: vm::ValueType::I64,
                                actual: v.ty(),
                            },
                            prototype: self.inner.into_prototype(),
                        }
                    }
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
                        .unwrap()
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
                        }
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
                        vm: &mut self.inner.vm,
                        memory_total_pages: self.inner.memory_total_pages,
                    },
                    pointer,
                ) {
                    Ok(()) => {}
                    Err(_) => {
                        return HostVm::Error {
                            error: Error::FreeError { pointer },
                            prototype: self.inner.into_prototype(),
                        }
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
                        .unwrap()
                        .as_ref(),
                )
                .map(|_| ());
                if let Err(error) = target_utf8_check {
                    return HostVm::Error {
                        error: Error::Utf8Error {
                            function: host_fn.name(),
                            param_num: 2,
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
                        .unwrap()
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
                        _log_level: log_level,
                        _target_str_ptr: target_str_ptr,
                        _target_str_size: target_str_size,
                        msg_str_ptr,
                        msg_str_size,
                    },
                })
            }
            HostFunction::ext_logging_max_level_version_1 => {
                HostVm::GetMaxLogLevel(GetMaxLogLevel { inner: self.inner })
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
pub struct Finished {
    inner: Inner,

    /// Pointer to the value returned by the VM. Guaranteed to be in range.
    value_ptr: u32,
    /// Size of the value returned by the VM. Guaranteed to be in range.
    value_size: u32,
}

impl Finished {
    /// Returns the value the called function has returned.
    pub fn value(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner
            .vm
            .read_memory(self.value_ptr, self.value_size)
            .unwrap()
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
    inner: Inner,

    /// Function currently being called by the Wasm code. Refers to an index within
    /// [`Inner::registered_functions`]. Guaranteed to be [`FunctionImport::Resolved`̀].
    calling: usize,

    /// Used only for the `ext_storage_read_version_1` function. Stores the pointer where the
    /// output should be stored.
    value_out_ptr: Option<u32>,

    /// Pointer to the key whose value must be loaded. Guaranteed to be in range.
    key_ptr: u32,
    /// Size of the key whose value must be loaded. Guaranteed to be in range.
    key_size: u32,
    /// Offset within the value that the Wasm VM requires.
    offset: u32,
    /// Maximum size that the Wasm VM would accept.
    max_size: u32,
}

impl ExternalStorageGet {
    /// Returns the key whose value must be provided back with [`ExternalStorageGet::resume`].
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner
            .vm
            .read_memory(self.key_ptr, self.key_size)
            .unwrap()
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
            if usize::try_from(self.offset).unwrap() < value.len() {
                let value_slice = &value[usize::try_from(self.offset).unwrap()..];
                if usize::try_from(self.max_size).unwrap() < value_slice.len() {
                    let value_slice = &value_slice[..usize::try_from(self.max_size).unwrap()];
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
        let host_fn = match self.inner.registered_functions[self.calling] {
            FunctionImport::Resolved(f) => f,
            FunctionImport::Unresolved { .. } => unreachable!(),
        };

        match host_fn {
            HostFunction::ext_storage_get_version_1 => {
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
            HostFunction::ext_storage_read_version_1 => {
                let outcome = if let Some((value, value_total_len)) = value {
                    let mut remaining_max_allowed = usize::try_from(self.max_size).unwrap();
                    let mut offset = self.value_out_ptr.unwrap();
                    for value in value {
                        let value = value.as_ref();
                        assert!(value.len() <= remaining_max_allowed);
                        remaining_max_allowed -= value.len();
                        self.inner.vm.write_memory(offset, value).unwrap();
                        offset += u32::try_from(value.len()).unwrap();
                    }

                    // Note: the https://github.com/paritytech/substrate/pull/7084 PR has changed
                    // the meaning of this return value.
                    Some(u32::try_from(value_total_len).unwrap() - self.offset)
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
            HostFunction::ext_storage_exists_version_1 => HostVm::ReadyToRun(ReadyToRun {
                inner: self.inner,
                resume_value: Some(if value.is_some() {
                    vm::WasmValue::I32(1)
                } else {
                    vm::WasmValue::I32(0)
                }),
            }),
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
pub struct ExternalStorageSet {
    inner: Inner,

    /// Pointer to the key whose value must be set. Guaranteed to be in range.
    key_ptr: u32,
    /// Size of the key whose value must be set. Guaranteed to be in range.
    key_size: u32,

    /// Pointer and size of the value to set. `None` for clearing. Guaranteed to be in range.
    value: Option<(u32, u32)>,
}

impl ExternalStorageSet {
    /// Returns the key whose value must be set.
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner
            .vm
            .read_memory(self.key_ptr, self.key_size)
            .unwrap()
    }

    /// Returns the value to set.
    ///
    /// If `None` is returned, the key should be removed from the storage entirely.
    pub fn value(&'_ self) -> Option<impl AsRef<[u8]> + '_> {
        if let Some((ptr, size)) = self.value {
            Some(self.inner.vm.read_memory(ptr, size).unwrap())
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

impl fmt::Debug for ExternalStorageSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalStorageSet").finish()
    }
}

/// Must load a storage value, treat it as if it was a SCALE-encoded container, and put `value`
/// at the end of the container, increasing the number of elements.
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
    inner: Inner,

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
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner
            .vm
            .read_memory(self.key_ptr, self.key_size)
            .unwrap()
    }

    /// Returns the value to append.
    pub fn value(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner
            .vm
            .read_memory(self.value_ptr, self.value_size)
            .unwrap()
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
pub struct ExternalStorageClearPrefix {
    inner: Inner,

    /// Pointer to the prefix to remove. Guaranteed to be in range.
    prefix_ptr: u32,
    /// Size of the prefix to remove. Guaranteed to be in range.
    prefix_size: u32,

    /// Maximum number of keys to remove.
    max_keys_to_remove: Option<u32>,

    /// `true` if version 2 of the function is called, `false` for version 1.
    is_v2: bool,
}

impl ExternalStorageClearPrefix {
    /// Returns the prefix whose keys must be removed.
    pub fn prefix(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner
            .vm
            .read_memory(self.prefix_ptr, self.prefix_size)
            .unwrap()
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
        if self.is_v2 {
            self.inner.alloc_write_and_return_pointer_size(
                HostFunction::ext_storage_clear_prefix_version_2.name(),
                [
                    either::Left(if some_keys_remain { [1u8] } else { [0u8] }),
                    either::Right(num_cleared.to_le_bytes()),
                ]
                .into_iter(),
            )
        } else {
            HostVm::ReadyToRun(ReadyToRun {
                inner: self.inner,
                resume_value: None,
            })
        }
    }
}

impl fmt::Debug for ExternalStorageClearPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalStorageClearPrefix").finish()
    }
}

/// Must provide the trie root hash of the storage.
pub struct ExternalStorageRoot {
    inner: Inner,
}

impl ExternalStorageRoot {
    /// Writes the trie root hash to the Wasm VM and prepares it for resume.
    pub fn resume(self, hash: &[u8; 32]) -> HostVm {
        self.inner.alloc_write_and_return_pointer_size(
            HostFunction::ext_storage_root_version_1.name(),
            iter::once(hash),
        )
    }
}

impl fmt::Debug for ExternalStorageRoot {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalStorageRoot").finish()
    }
}

/// Must provide the storage key that follows, in lexicographic order, a specific one.
pub struct ExternalStorageNextKey {
    inner: Inner,

    /// Pointer to the key whose value must be set. Guaranteed to be in range.
    key_ptr: u32,
    /// Size of the key whose value must be set. Guaranteed to be in range.
    key_size: u32,
}

impl ExternalStorageNextKey {
    /// Returns the key whose following key must be returned.
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner
            .vm
            .read_memory(self.key_ptr, self.key_size)
            .unwrap()
    }

    /// Writes the follow-up key in the Wasm VM memory and prepares it for execution.
    ///
    /// Must be passed `None` if the key is the last one in the storage.
    pub fn resume(self, follow_up: Option<&[u8]>) -> HostVm {
        if let Some(follow_up) = follow_up {
            let value_len_enc = util::encode_scale_compact_usize(follow_up.len());
            self.inner.alloc_write_and_return_pointer_size(
                HostFunction::ext_storage_next_key_version_1.name(),
                iter::once(&[1][..])
                    .chain(iter::once(value_len_enc.as_ref()))
                    .chain(iter::once(follow_up)),
            )
        } else {
            // Write a SCALE-encoded `None`.
            self.inner.alloc_write_and_return_pointer_size(
                HostFunction::ext_storage_next_key_version_1.name(),
                iter::once(&[0]),
            )
        }
    }
}

impl fmt::Debug for ExternalStorageNextKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalStorageNextKey").finish()
    }
}

/// Must provide the runtime version obtained by calling the `Core_version` entry point of a Wasm
/// blob.
pub struct CallRuntimeVersion {
    inner: Inner,

    /// Pointer to the wasm code whose runtime version must be provided. Guaranteed to be in range.
    wasm_blob_ptr: u32,
    /// Size of the wasm code whose runtime version must be provided. Guaranteed to be in range.
    wasm_blob_size: u32,
}

impl CallRuntimeVersion {
    /// Returns the Wasm code whose runtime version must be provided.
    pub fn wasm_code(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner
            .vm
            .read_memory(self.wasm_blob_ptr, self.wasm_blob_size)
            .unwrap()
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

/// Must set the value of the off-chain storage.
pub struct ExternalOffchainStorageSet {
    inner: Inner,

    /// Pointer to the key whose value must be set. Guaranteed to be in range.
    key_ptr: u32,
    /// Size of the key whose value must be set. Guaranteed to be in range.
    key_size: u32,

    /// Pointer and size of the value to set. `None` for clearing. Guaranteed to be in range.
    value: Option<(u32, u32)>,
}

impl ExternalOffchainStorageSet {
    /// Returns the key whose value must be set.
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner
            .vm
            .read_memory(self.key_ptr, self.key_size)
            .unwrap()
    }

    /// Returns the value to set.
    ///
    /// If `None` is returned, the key should be removed from the storage entirely.
    pub fn value(&'_ self) -> Option<impl AsRef<[u8]> + '_> {
        if let Some((ptr, size)) = self.value {
            Some(self.inner.vm.read_memory(ptr, size).unwrap())
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

impl fmt::Debug for ExternalOffchainStorageSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ExternalOffchainStorageSet").finish()
    }
}

/// Report about a log entry being emitted.
///
/// Use the implementation of [`fmt::Display`] to obtain the log entry. For example, you can
/// call [`alloc::string::ToString::to_string`] to turn it into a `String`.
pub struct LogEmit {
    inner: Inner,
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
        _log_level: u32,
        /// Pointer to the string of the log target. Guaranteed to be in range and to be UTF-8.
        _target_str_ptr: u32,
        /// Size of the string of the log target. Guaranteed to be in range and to be UTF-8.
        _target_str_size: u32,
        /// Pointer to the string of the log message. Guaranteed to be in range and to be UTF-8.
        msg_str_ptr: u32,
        /// Size of the string of the log message. Guaranteed to be in range and to be UTF-8.
        msg_str_size: u32,
    },
}

impl LogEmit {
    /// Resumes execution after having set the value.
    pub fn resume(self) -> HostVm {
        HostVm::ReadyToRun(ReadyToRun {
            inner: self.inner,
            resume_value: None,
        })
    }
}

impl fmt::Display for LogEmit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.log_entry {
            LogEmitInner::Num(num) => write!(f, "{}", num),
            LogEmitInner::Utf8 { str_ptr, str_size } => {
                let str = self.inner.vm.read_memory(str_ptr, str_size).unwrap();
                let str = str::from_utf8(str.as_ref()).unwrap();
                write!(f, "{}", str)
            }
            LogEmitInner::Hex {
                data_ptr,
                data_size,
            } => {
                let data = self.inner.vm.read_memory(data_ptr, data_size).unwrap();
                write!(f, "{}", hex::encode(data.as_ref()))
            }
            LogEmitInner::Log {
                msg_str_ptr,
                msg_str_size,
                ..
            } => {
                let str = self
                    .inner
                    .vm
                    .read_memory(msg_str_ptr, msg_str_size)
                    .unwrap();
                let str = str::from_utf8(str.as_ref()).unwrap();
                // TODO: don't just ignore the target and log level? better log representation? more control?
                write!(f, "{}", str)
            }
        }
    }
}

impl fmt::Debug for LogEmit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LogEmit")
            .field("message", &self.to_string())
            .finish()
    }
}

/// Queries the maximum log level.
pub struct GetMaxLogLevel {
    inner: Inner,
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
    inner: Inner,
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
    inner: Inner,
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

enum FunctionImport {
    Resolved(HostFunction),
    Unresolved { module: String, name: String },
}

/// Running virtual machine. Shared between all the variants in [`HostVm`].
struct Inner {
    /// See [`HostVmPrototype::module`].
    module: vm::Module,

    /// See [`HostVmPrototype::runtime_version`].
    runtime_version: Option<CoreVersion>,

    /// Inner lower-level virtual machine.
    vm: vm::VirtualMachine,

    /// Initial value of the `__heap_base` global in the Wasm module. Used to initialize the memory
    /// allocator in case we need to rebuild the VM.
    heap_base: u32,

    /// Value of `heap_pages` passed to [`HostVmPrototype::new`].
    heap_pages: HeapPages,

    /// See [`HostVmPrototype::memory_total_pages`].
    memory_total_pages: HeapPages,

    /// Value passed to [`HostVmPrototype::new`].
    allow_unresolved_imports: bool,

    /// The depth of storage transaction started with `ext_storage_start_transaction_version_1`.
    storage_transaction_depth: u32,

    /// See [`HostVmPrototype::registered_functions`].
    registered_functions: Vec<FunctionImport>,

    /// Memory allocator in order to answer the calls to `malloc` and `free`.
    allocator: allocator::FreeingBumpHeapAllocator,
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
        mut self,
        function_name: &'static str,
        data: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
    ) -> HostVm {
        let mut data_len = 0u32;
        for chunk in data.clone() {
            data_len = data_len
                .saturating_add(u32::try_from(chunk.as_ref().len()).unwrap_or(u32::max_value()));
        }

        let dest_ptr = match self.alloc(function_name, data_len) {
            Ok(p) => p,
            Err(error) => {
                return HostVm::Error {
                    error,
                    prototype: self.into_prototype(),
                }
            }
        };

        let mut ptr_iter = dest_ptr;
        for chunk in data {
            let chunk = chunk.as_ref();
            self.vm.write_memory(ptr_iter, chunk).unwrap();
            ptr_iter += u32::try_from(chunk.len()).unwrap_or(u32::max_value());
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
        mut self,
        function_name: &'static str,
        data: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
    ) -> HostVm {
        let mut data_len = 0u32;
        for chunk in data.clone() {
            data_len = data_len
                .saturating_add(u32::try_from(chunk.as_ref().len()).unwrap_or(u32::max_value()));
        }

        let dest_ptr = match self.alloc(function_name, data_len) {
            Ok(p) => p,
            Err(error) => {
                return HostVm::Error {
                    error,
                    prototype: self.into_prototype(),
                }
            }
        };

        let mut ptr_iter = dest_ptr;
        for chunk in data {
            let chunk = chunk.as_ref();
            self.vm.write_memory(ptr_iter, chunk).unwrap();
            ptr_iter += u32::try_from(chunk.len()).unwrap_or(u32::max_value());
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
                vm: &mut self.vm,
                memory_total_pages: self.memory_total_pages,
            },
            size,
        ) {
            Ok(p) => p,
            Err(_) => {
                return Err(Error::OutOfMemory {
                    function: function_name,
                    requested_size: size,
                })
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
        debug_assert!(current_num_pages <= self.memory_total_pages);
        if current_num_pages <= last_byte_memory_page {
            // For now, we grow the memory just enough to fit.
            // TODO: do better
            // Note the order of operations: we add 1 at the end to avoid a potential overflow
            // in case `last_byte_memory_page` is the maximum possible value.
            let to_grow = last_byte_memory_page - current_num_pages + HeapPages::new(1);

            // We check at initialization that the virtual machine is capable of growing up to
            // `memory_total_pages`, meaning that this `unwrap` can't panic.
            self.vm.grow_memory(to_grow).unwrap();
        }

        Ok(dest_ptr)
    }

    /// Turns the virtual machine back into a prototype.
    fn into_prototype(self) -> HostVmPrototype {
        HostVmPrototype {
            module: self.module,
            runtime_version: self.runtime_version,
            vm_proto: self.vm.into_prototype(),
            heap_base: self.heap_base,
            registered_functions: self.registered_functions,
            heap_pages: self.heap_pages,
            allow_unresolved_imports: self.allow_unresolved_imports,
            memory_total_pages: self.memory_total_pages,
        }
    }
}

/// Error that can happen when initializing a VM.
#[derive(Debug, derive_more::From, derive_more::Display, Clone)]
pub enum NewErr {
    /// Error while initializing the virtual machine.
    #[display(fmt = "{}", _0)]
    VirtualMachine(vm::NewErr),
    /// Error in the format of the runtime code.
    #[display(fmt = "{}", _0)]
    BadFormat(ModuleFormatError),
    /// Error while calling `Core_version` to determine the runtime version.
    #[display(fmt = "Error while calling Core_version: {}", _0)]
    CoreVersion(CoreVersionError),
    /// Couldn't find the `__heap_base` symbol in the Wasm code.
    HeapBaseNotFound,
    /// Maximum size of the Wasm memory found in the module is too low to provide the requested
    /// number of heap pages.
    MemoryMaxSizeTooLow,
}

/// Error that can happen when starting a VM.
#[derive(Debug, Clone, derive_more::From, derive_more::Display)]
pub enum StartErr {
    /// Error while starting the virtual machine.
    #[display(fmt = "{}", _0)]
    VirtualMachine(vm::StartErr),
    /// The size of the input data is too large.
    DataSizeOverflow,
}

/// Reason why the Wasm blob isn't conforming to the runtime environment.
#[derive(Debug, Clone, derive_more::Display)]
pub enum Error {
    /// Error in the Wasm code execution.
    #[display(fmt = "{}", _0)]
    Trap(vm::Trap),
    /// A non-`i64` value has been returned by the Wasm entry point.
    #[display(fmt = "A non-I64 value has been returned: {:?}", actual)]
    BadReturnValue {
        /// Type that has actually gotten returned. `None` for "void".
        actual: Option<vm::ValueType>,
    },
    /// The pointer and size returned by the Wasm entry point function are invalid.
    #[display(fmt = "The pointer and size returned by the function are invalid")]
    ReturnedPtrOutOfRange {
        /// Pointer that got returned.
        pointer: u32,
        /// Size that got returned.
        size: u32,
        /// Size of the virtual memory.
        memory_size: u32,
    },
    /// An `host_fn` wants to returns a certain value, but the Wasm code expects a different one.
    // TODO: indicate function and actual/expected types
    ReturnValueTypeMismatch,
    /// Called a function that is unknown to the host.
    ///
    /// > **Note**: Can only happen if `allow_unresolved_imports` was `true`.
    #[display(fmt = "Called unresolved function `{}`:`{}`", module_name, function)]
    UnresolvedFunctionCalled {
        /// Name of the function that was unresolved.
        function: String,
        /// Name of module associated with the unresolved function.
        module_name: String,
    },
    /// Mismatch between the number of parameters expected and the actual number.
    #[display(
        fmt = "Mismatch in parameters count: {}, expected = {}, actual = {}",
        function,
        expected,
        actual
    )]
    ParamsCountMismatch {
        /// Name of the function being called whose number of parameters mismatches.
        function: &'static str,
        /// Expected number of parameters.
        expected: usize,
        /// Number of parameters that have been passed.
        actual: usize,
    },
    /// Failed to decode a SCALE-encoded parameter.
    ParamDecodeError,
    /// The type of one of the parameters is wrong.
    #[display(
        fmt = "Type mismatch in parameter of index {}: {}, expected = {:?}, actual = {:?}",
        param_num,
        function,
        expected,
        actual
    )]
    WrongParamTy {
        /// Name of the function being called where a type mismatch happens.
        function: &'static str,
        /// Index of the invalid parameter. The first parameter has index 0.
        param_num: usize,
        /// Type of the value that was expected.
        expected: vm::ValueType,
        /// Type of the value that got passed.
        actual: vm::ValueType,
    },
    /// One parameter is expected to point to a buffer, but the pointer is out
    /// of range of the memory of the Wasm VM.
    #[display(
        fmt = "Bad pointer for parameter of index {} of {}: 0x{:x}, len = 0x{:x}",
        param_num,
        function,
        pointer,
        length
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
    #[display(
        fmt = "UTF-8 error for parameter of index {} of {}: {}",
        param_num,
        function,
        error
    )]
    Utf8Error {
        /// Name of the function being called where a type mismatch happens.
        function: &'static str,
        /// Index of the invalid parameter. The first parameter has index 0.
        param_num: usize,
        /// Decoding error that happened.
        error: core::str::Utf8Error,
    },
    /// Called `ext_storage_rollback_transaction_version_1` or
    /// `ext_storage_commit_transaction_version_1` but no transaction was in progress.
    #[display(fmt = "Attempted to end a transaction while none is in progress")]
    NoActiveTransaction,
    /// Execution has finished while a transaction started with
    /// `ext_storage_start_transaction_version_1` was still in progress.
    #[display(fmt = "Execution returned with a pending storage transaction")]
    FinishedWithPendingTransaction,
    /// Error when allocating memory for a return type.
    #[display(
        fmt = "Out of memory allocating 0x{:x} bytes during {}",
        requested_size,
        function
    )]
    OutOfMemory {
        /// Name of the function being called.
        function: &'static str,
        /// Size of the requested allocation.
        requested_size: u32,
    },
    /// Called `ext_allocator_free_version_1` with an invalid pointer.
    #[display(
        fmt = "Bad pointer passed to ext_allocator_free_version_1: 0x{:x}",
        pointer
    )]
    FreeError {
        /// Pointer that was expected to be freed.
        pointer: u32,
    },
    /// The host function isn't implemented.
    // TODO: this variant should eventually disappear as all functions are implemented
    #[display(fmt = "Host function not implemented: {}", function)]
    HostFunctionNotImplemented {
        /// Name of the function being called.
        function: &'static str,
    },
}

macro_rules! externalities {
    ($($ext:ident,)*) => {
        /// List of possible externalities.
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        #[allow(non_camel_case_types)]
        enum HostFunction {
            $(
                $ext,
            )*
        }

        impl HostFunction {
            fn by_name(name: &str) -> Option<Self> {
                $(
                    if name == stringify!($ext) {
                        return Some(HostFunction::$ext);
                    }
                )*
                None
            }

            fn name(&self) -> &'static str {
                match self {
                    $(
                        HostFunction::$ext => stringify!($ext),
                    )*
                }
            }
        }
    };
}

externalities! {
    ext_storage_set_version_1,
    ext_storage_get_version_1,
    ext_storage_read_version_1,
    ext_storage_clear_version_1,
    ext_storage_exists_version_1,
    ext_storage_clear_prefix_version_1,
    ext_storage_clear_prefix_version_2,
    ext_storage_root_version_1,
    ext_storage_root_version_2,
    ext_storage_changes_root_version_1,
    ext_storage_next_key_version_1,
    ext_storage_append_version_1,
    ext_storage_child_set_version_1,
    ext_storage_child_get_version_1,
    ext_storage_child_read_version_1,
    ext_storage_child_clear_version_1,
    ext_storage_child_storage_kill_version_1,
    ext_storage_child_exists_version_1,
    ext_storage_child_clear_prefix_version_1,
    ext_storage_child_root_version_1,
    ext_storage_child_next_key_version_1,
    ext_storage_start_transaction_version_1,
    ext_storage_rollback_transaction_version_1,
    ext_storage_commit_transaction_version_1,
    ext_default_child_storage_get_version_1,
    ext_default_child_storage_read_version_1,
    ext_default_child_storage_storage_kill_version_1,
    ext_default_child_storage_storage_kill_version_2,
    ext_default_child_storage_storage_kill_version_3,
    ext_default_child_storage_clear_prefix_version_1,
    ext_default_child_storage_clear_prefix_version_2,
    ext_default_child_storage_set_version_1,
    ext_default_child_storage_clear_version_1,
    ext_default_child_storage_exists_version_1,
    ext_default_child_storage_next_key_version_1,
    ext_default_child_storage_root_version_1,
    ext_default_child_storage_root_version_2,
    ext_crypto_ed25519_public_keys_version_1,
    ext_crypto_ed25519_generate_version_1,
    ext_crypto_ed25519_sign_version_1,
    ext_crypto_ed25519_verify_version_1,
    ext_crypto_sr25519_public_keys_version_1,
    ext_crypto_sr25519_generate_version_1,
    ext_crypto_sr25519_sign_version_1,
    ext_crypto_sr25519_verify_version_1,
    ext_crypto_sr25519_verify_version_2,
    ext_crypto_ecdsa_generate_version_1,
    ext_crypto_ecdsa_sign_version_1,
    ext_crypto_ecdsa_public_keys_version_1,
    ext_crypto_ecdsa_verify_version_1,
    ext_crypto_ecdsa_sign_prehashed_version_1,
    ext_crypto_ecdsa_verify_prehashed_version_1,
    ext_crypto_secp256k1_ecdsa_recover_version_1,
    ext_crypto_secp256k1_ecdsa_recover_version_2,
    ext_crypto_secp256k1_ecdsa_recover_compressed_version_1,
    ext_crypto_secp256k1_ecdsa_recover_compressed_version_2,
    ext_crypto_start_batch_verify_version_1,
    ext_crypto_finish_batch_verify_version_1,
    ext_hashing_keccak_256_version_1,
    ext_hashing_sha2_256_version_1,
    ext_hashing_blake2_128_version_1,
    ext_hashing_blake2_256_version_1,
    ext_hashing_twox_64_version_1,
    ext_hashing_twox_128_version_1,
    ext_hashing_twox_256_version_1,
    ext_offchain_index_set_version_1,
    ext_offchain_index_clear_version_1,
    ext_offchain_is_validator_version_1,
    ext_offchain_submit_transaction_version_1,
    ext_offchain_network_state_version_1,
    ext_offchain_timestamp_version_1,
    ext_offchain_sleep_until_version_1,
    ext_offchain_random_seed_version_1,
    ext_offchain_local_storage_set_version_1,
    ext_offchain_local_storage_compare_and_set_version_1,
    ext_offchain_local_storage_get_version_1,
    ext_offchain_local_storage_clear_version_1,
    ext_offchain_http_request_start_version_1,
    ext_offchain_http_request_add_header_version_1,
    ext_offchain_http_request_write_body_version_1,
    ext_offchain_http_response_wait_version_1,
    ext_offchain_http_response_headers_version_1,
    ext_offchain_http_response_read_body_version_1,
    ext_sandbox_instantiate_version_1,
    ext_sandbox_invoke_version_1,
    ext_sandbox_memory_new_version_1,
    ext_sandbox_memory_get_version_1,
    ext_sandbox_memory_set_version_1,
    ext_sandbox_memory_teardown_version_1,
    ext_sandbox_instance_teardown_version_1,
    ext_sandbox_get_global_val_version_1,
    ext_trie_blake2_256_root_version_1,
    ext_trie_blake2_256_root_version_2,
    ext_trie_blake2_256_ordered_root_version_1,
    ext_trie_blake2_256_ordered_root_version_2,
    ext_trie_keccak_256_ordered_root_version_1,
    ext_trie_keccak_256_ordered_root_version_2,
    ext_misc_print_num_version_1,
    ext_misc_print_utf8_version_1,
    ext_misc_print_hex_version_1,
    ext_misc_runtime_version_version_1,
    ext_allocator_malloc_version_1,
    ext_allocator_free_version_1,
    ext_logging_log_version_1,
    ext_logging_max_level_version_1,
}

impl HostFunction {
    fn num_parameters(&self) -> usize {
        match *self {
            HostFunction::ext_storage_set_version_1 => 2,
            HostFunction::ext_storage_get_version_1 => 1,
            HostFunction::ext_storage_read_version_1 => 3,
            HostFunction::ext_storage_clear_version_1 => 1,
            HostFunction::ext_storage_exists_version_1 => 1,
            HostFunction::ext_storage_clear_prefix_version_1 => 1,
            HostFunction::ext_storage_clear_prefix_version_2 => 2,
            HostFunction::ext_storage_root_version_1 => 0,
            HostFunction::ext_storage_root_version_2 => 1,
            HostFunction::ext_storage_changes_root_version_1 => 1,
            HostFunction::ext_storage_next_key_version_1 => 1,
            HostFunction::ext_storage_append_version_1 => 2,
            HostFunction::ext_storage_child_set_version_1 => todo!(),
            HostFunction::ext_storage_child_get_version_1 => todo!(),
            HostFunction::ext_storage_child_read_version_1 => todo!(),
            HostFunction::ext_storage_child_clear_version_1 => todo!(),
            HostFunction::ext_storage_child_storage_kill_version_1 => todo!(),
            HostFunction::ext_storage_child_exists_version_1 => todo!(),
            HostFunction::ext_storage_child_clear_prefix_version_1 => todo!(),
            HostFunction::ext_storage_child_root_version_1 => todo!(),
            HostFunction::ext_storage_child_next_key_version_1 => todo!(),
            HostFunction::ext_storage_start_transaction_version_1 => 0,
            HostFunction::ext_storage_rollback_transaction_version_1 => 0,
            HostFunction::ext_storage_commit_transaction_version_1 => 0,
            HostFunction::ext_default_child_storage_get_version_1 => todo!(),
            HostFunction::ext_default_child_storage_read_version_1 => todo!(),
            HostFunction::ext_default_child_storage_storage_kill_version_1 => todo!(),
            HostFunction::ext_default_child_storage_storage_kill_version_2 => todo!(),
            HostFunction::ext_default_child_storage_storage_kill_version_3 => todo!(),
            HostFunction::ext_default_child_storage_clear_prefix_version_1 => todo!(),
            HostFunction::ext_default_child_storage_clear_prefix_version_2 => todo!(),
            HostFunction::ext_default_child_storage_set_version_1 => todo!(),
            HostFunction::ext_default_child_storage_clear_version_1 => todo!(),
            HostFunction::ext_default_child_storage_exists_version_1 => todo!(),
            HostFunction::ext_default_child_storage_next_key_version_1 => todo!(),
            HostFunction::ext_default_child_storage_root_version_1 => todo!(),
            HostFunction::ext_default_child_storage_root_version_2 => todo!(),
            HostFunction::ext_crypto_ed25519_public_keys_version_1 => todo!(),
            HostFunction::ext_crypto_ed25519_generate_version_1 => todo!(),
            HostFunction::ext_crypto_ed25519_sign_version_1 => todo!(),
            HostFunction::ext_crypto_ed25519_verify_version_1 => 3,
            HostFunction::ext_crypto_sr25519_public_keys_version_1 => todo!(),
            HostFunction::ext_crypto_sr25519_generate_version_1 => todo!(),
            HostFunction::ext_crypto_sr25519_sign_version_1 => todo!(),
            HostFunction::ext_crypto_sr25519_verify_version_1 => 3,
            HostFunction::ext_crypto_sr25519_verify_version_2 => 3,
            HostFunction::ext_crypto_ecdsa_generate_version_1 => todo!(),
            HostFunction::ext_crypto_ecdsa_sign_version_1 => 2,
            HostFunction::ext_crypto_ecdsa_public_keys_version_1 => todo!(),
            HostFunction::ext_crypto_ecdsa_verify_version_1 => 3,
            HostFunction::ext_crypto_ecdsa_sign_prehashed_version_1 => 2,
            HostFunction::ext_crypto_ecdsa_verify_prehashed_version_1 => 3,
            HostFunction::ext_crypto_secp256k1_ecdsa_recover_version_1 => 2,
            HostFunction::ext_crypto_secp256k1_ecdsa_recover_version_2 => 2,
            HostFunction::ext_crypto_secp256k1_ecdsa_recover_compressed_version_1 => 2,
            HostFunction::ext_crypto_secp256k1_ecdsa_recover_compressed_version_2 => 2,
            HostFunction::ext_crypto_start_batch_verify_version_1 => 0,
            HostFunction::ext_crypto_finish_batch_verify_version_1 => 0,
            HostFunction::ext_hashing_keccak_256_version_1 => 1,
            HostFunction::ext_hashing_sha2_256_version_1 => todo!(),
            HostFunction::ext_hashing_blake2_128_version_1 => 1,
            HostFunction::ext_hashing_blake2_256_version_1 => 1,
            HostFunction::ext_hashing_twox_64_version_1 => 1,
            HostFunction::ext_hashing_twox_128_version_1 => 1,
            HostFunction::ext_hashing_twox_256_version_1 => 1,
            HostFunction::ext_offchain_index_set_version_1 => 2,
            HostFunction::ext_offchain_index_clear_version_1 => 1,
            HostFunction::ext_offchain_is_validator_version_1 => todo!(),
            HostFunction::ext_offchain_submit_transaction_version_1 => todo!(),
            HostFunction::ext_offchain_network_state_version_1 => todo!(),
            HostFunction::ext_offchain_timestamp_version_1 => todo!(),
            HostFunction::ext_offchain_sleep_until_version_1 => todo!(),
            HostFunction::ext_offchain_random_seed_version_1 => todo!(),
            HostFunction::ext_offchain_local_storage_set_version_1 => todo!(),
            HostFunction::ext_offchain_local_storage_compare_and_set_version_1 => todo!(),
            HostFunction::ext_offchain_local_storage_get_version_1 => todo!(),
            HostFunction::ext_offchain_local_storage_clear_version_1 => todo!(),
            HostFunction::ext_offchain_http_request_start_version_1 => todo!(),
            HostFunction::ext_offchain_http_request_add_header_version_1 => todo!(),
            HostFunction::ext_offchain_http_request_write_body_version_1 => todo!(),
            HostFunction::ext_offchain_http_response_wait_version_1 => todo!(),
            HostFunction::ext_offchain_http_response_headers_version_1 => todo!(),
            HostFunction::ext_offchain_http_response_read_body_version_1 => todo!(),
            HostFunction::ext_sandbox_instantiate_version_1 => todo!(),
            HostFunction::ext_sandbox_invoke_version_1 => todo!(),
            HostFunction::ext_sandbox_memory_new_version_1 => todo!(),
            HostFunction::ext_sandbox_memory_get_version_1 => todo!(),
            HostFunction::ext_sandbox_memory_set_version_1 => todo!(),
            HostFunction::ext_sandbox_memory_teardown_version_1 => todo!(),
            HostFunction::ext_sandbox_instance_teardown_version_1 => todo!(),
            HostFunction::ext_sandbox_get_global_val_version_1 => todo!(),
            HostFunction::ext_trie_blake2_256_root_version_1 => 1,
            HostFunction::ext_trie_blake2_256_root_version_2 => 2,
            HostFunction::ext_trie_blake2_256_ordered_root_version_1 => 1,
            HostFunction::ext_trie_blake2_256_ordered_root_version_2 => 2,
            HostFunction::ext_trie_keccak_256_ordered_root_version_1 => todo!(),
            HostFunction::ext_trie_keccak_256_ordered_root_version_2 => todo!(),
            HostFunction::ext_misc_print_num_version_1 => 1,
            HostFunction::ext_misc_print_utf8_version_1 => 1,
            HostFunction::ext_misc_print_hex_version_1 => 1,
            HostFunction::ext_misc_runtime_version_version_1 => 1,
            HostFunction::ext_allocator_malloc_version_1 => 1,
            HostFunction::ext_allocator_free_version_1 => 1,
            HostFunction::ext_logging_log_version_1 => 3,
            HostFunction::ext_logging_max_level_version_1 => 0,
        }
    }
}

// Glue between the `allocator` module and the `vm` module.
//
// The allocator believes that there are `memory_total_pages` pages available and allocated, where
// `memory_total_pages` is equal to `heap_base + heap_pages`, while in reality, because we grow
// memory lazily, there might be fewer.
struct MemAccess<'a> {
    vm: &'a mut vm::VirtualMachine,
    memory_total_pages: HeapPages,
}

impl<'a> allocator::Memory for MemAccess<'a> {
    fn read_le_u64(&self, ptr: u32) -> Result<u64, allocator::Error> {
        if (ptr + 8) > u32::from(self.memory_total_pages) * 64 * 1024 {
            return Err(allocator::Error::Other("out of bounds access"));
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
        let current_num_pages = self.vm.memory_size();
        debug_assert!(current_num_pages <= self.memory_total_pages);

        if accessed_memory_page_end < current_num_pages {
            // This is the simple case: the memory access is in bounds.
            let bytes = self.vm.read_memory(ptr, 8).unwrap();
            Ok(u64::from_le_bytes(
                <[u8; 8]>::try_from(bytes.as_ref()).unwrap(),
            ))
        } else if accessed_memory_page_start < current_num_pages {
            // Memory access is partially in bounds. This is the most complicated situation.
            let partial_bytes = self
                .vm
                .read_memory(ptr, u32::from(current_num_pages) * 64 * 1024 - ptr)
                .unwrap();
            let partial_bytes = partial_bytes.as_ref();
            debug_assert!(partial_bytes.len() < 8);

            let mut out = [0; 8];
            out[..partial_bytes.len()].copy_from_slice(partial_bytes);
            Ok(u64::from_le_bytes(out))
        } else {
            // Everything out bounds. Memory is zero.
            Ok(0)
        }
    }

    fn write_le_u64(&mut self, ptr: u32, val: u64) -> Result<(), allocator::Error> {
        if (ptr + 8) > u32::from(self.memory_total_pages) * 64 * 1024 {
            return Err(allocator::Error::Other("out of bounds access"));
        }

        let bytes = val.to_le_bytes();

        // Offset of the memory page where the last byte of the value will be written.
        let written_memory_page = HeapPages::new((ptr + 7) / (64 * 1024));

        // Grow the memory more if necessary.
        // Please note the `=`. For example if we write to page 0, we want to have at least 1 page
        // allocated.
        let current_num_pages = self.vm.memory_size();
        debug_assert!(current_num_pages <= self.memory_total_pages);
        if current_num_pages <= written_memory_page {
            // For now, we grow the memory just enough to fit.
            // TODO: do better
            // Note the order of operations: we add 1 at the end to avoid a potential overflow
            // in case `written_memory_page` is the maximum possible value.
            let to_grow = written_memory_page - current_num_pages + HeapPages::new(1);

            // We check at initialization that the virtual machine is capable of growing up to
            // `memory_total_pages`, meaning that this `unwrap` can't panic.
            self.vm.grow_memory(to_grow).unwrap();
        }

        self.vm.write_memory(ptr, &bytes).unwrap();
        Ok(())
    }

    fn size(&self) -> u32 {
        // Lie to the allocator to pretend that `memory_total_pages` are available.
        u32::from(self.memory_total_pages)
            .saturating_mul(64)
            .saturating_mul(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::HostVm;

    #[test]
    fn is_send() {
        fn req<T: Send>() {}
        req::<HostVm>();
    }
}
