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

use alloc::{borrow::ToOwned as _, vec::Vec};
use core::{fmt, iter, str};

pub mod runtime_version;

pub use host_function::HostFunction;
pub use host_vm::*;
pub use runtime_version::{CoreVersion, CoreVersionError, CoreVersionRef};
pub use vm::HeapPages;
pub use zstd::Error as ModuleFormatError;

mod host_function;
mod host_vm;
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
