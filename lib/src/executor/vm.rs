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

//! General-purpose WebAssembly virtual machine.
//!
//! Contains code related to running a WebAssembly virtual machine. Contrary to
//! (`HostVm`)[`super::host::HostVm`], this module isn't aware of any of the host
//! functions available to Substrate runtimes. It only contains the code required to run a virtual
//! machine, with some adjustments explained below.
//!
//! # Usage
//!
//! Call [`VirtualMachinePrototype::new`] in order to parse and/or compile some WebAssembly code.
//! One of the parameters of this function is a function that is passed the name of functions
//! imported by the Wasm code, and must return an opaque `usize`. This `usize` doesn't have any
//! meaning, but will later be passed back to the user through [`ExecOutcome::Interrupted::id`]
//! when the corresponding function is called.
//!
//! Use [`VirtualMachinePrototype::prepare`] then [`Prepare::start`] in order to start executing
//! a function exported through an `(export)` statement.
//!
//! Call [`VirtualMachine::run`] on the [`VirtualMachine`] returned by `start` in order to run the
//! WebAssembly code. The `run` method returns either if the function being called returns, or if
//! the WebAssembly code calls a host function. In the latter case, [`ExecOutcome::Interrupted`]
//! is returned and the virtual machine is now paused. Once the logic of the host function has
//! been executed, call `run` again, passing the return value of that host function.
//!
//! # About imported vs exported memory
//!
//! WebAssembly supports, in theory, addressing multiple different memory objects. The WebAssembly
//! module can declare memory in two ways:
//!
//! - Either by exporting a memory object in the `(export)` section under the name `memory`.
//! - Or by importing a memory object in its `(import)` section.
//!
//! The virtual machine in this module supports both variants. However, no more than one memory
//! object can be exported or imported, and it is illegal to not use any memory.
//!
//! The first variant used to be the default model when compiling to WebAssembly, but the second
//! variant (importing memory objects) is preferred nowadays.
//!
//! # Wasm features
//!
//! The WebAssembly specification is a moving one. The specification as it was when it launched
//! in 2017 is commonly referred to as "the MVP" (minimum viable product). Since then, various
//! extensions have been added to the WebAssembly format.
//!
//! The code in this module, however, doesn't allow any of the feature that were added post-MVP.
//! Trying to use WebAssembly code that uses one of these features will result in an error.
//!

mod interpreter;

// This list of targets matches the one in the `Cargo.toml` file.
#[cfg(all(
    any(
        all(
            target_arch = "x86_64",
            any(
                target_os = "windows",
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos"
            )
        ),
        all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "s390x", target_os = "linux", target_env = "gnu")
    ),
    feature = "wasmtime"
))]
mod jit;

mod tests;

use alloc::{string::String, vec::Vec};
use core::{fmt, iter};
use smallvec::SmallVec;

/// Configuration to pass to [`VirtualMachinePrototype::new`].
pub struct Config<'a> {
    /// Encoded wasm bytecode.
    pub module_bytes: &'a [u8],

    /// Hint about how to execute the WebAssembly code.
    pub exec_hint: ExecHint,

    /// Called for each import that the module has. It must assign a number to each import, or
    /// return an error if the import can't be resolved. When the VM calls one of these functions,
    /// this number will be returned back in order for the user to know how to handle the call.
    pub symbols: &'a mut dyn FnMut(&str, &str, &Signature) -> Result<usize, ()>,
}

/// Virtual machine ready to start executing a function.
///
/// > **Note**: This struct implements `Clone`. Cloning a [`VirtualMachinePrototype`] allocates
/// >           memory necessary for the clone to run.
#[derive(Clone)]
pub struct VirtualMachinePrototype {
    inner: VirtualMachinePrototypeInner,
}

#[derive(Clone)]
enum VirtualMachinePrototypeInner {
    #[cfg(all(
        any(
            all(
                target_arch = "x86_64",
                any(
                    target_os = "windows",
                    all(target_os = "linux", target_env = "gnu"),
                    target_os = "macos"
                )
            ),
            all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
            all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
        ),
        feature = "wasmtime"
    ))]
    Jit(jit::JitPrototype),
    Interpreter(interpreter::InterpreterPrototype),
}

impl VirtualMachinePrototype {
    /// Creates a new process state machine from the given module. This method notably allocates
    /// the memory necessary for the virtual machine to run.
    ///
    ///
    /// See [the module-level documentation](..) for an explanation of the parameters.
    pub fn new(config: Config) -> Result<Self, NewErr> {
        Ok(VirtualMachinePrototype {
            inner: match config.exec_hint {
                #[cfg(all(
                    any(
                        all(
                            target_arch = "x86_64",
                            any(
                                target_os = "windows",
                                all(target_os = "linux", target_env = "gnu"),
                                target_os = "macos"
                            )
                        ),
                        all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                        all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                    ),
                    feature = "wasmtime"
                ))]
                ExecHint::ValidateAndCompile => VirtualMachinePrototypeInner::Jit(
                    jit::JitPrototype::new(config.module_bytes, config.symbols)?,
                ),
                #[cfg(not(all(
                    any(
                        all(
                            target_arch = "x86_64",
                            any(
                                target_os = "windows",
                                all(target_os = "linux", target_env = "gnu"),
                                target_os = "macos"
                            )
                        ),
                        all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                        all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                    ),
                    feature = "wasmtime"
                )))]
                ExecHint::ValidateAndCompile => VirtualMachinePrototypeInner::Interpreter(
                    interpreter::InterpreterPrototype::new(
                        config.module_bytes,
                        interpreter::CompilationMode::Eager,
                        config.symbols,
                    )?,
                ),
                ExecHint::ValidateAndExecuteOnce | ExecHint::Untrusted => {
                    VirtualMachinePrototypeInner::Interpreter(
                        interpreter::InterpreterPrototype::new(
                            config.module_bytes,
                            interpreter::CompilationMode::Eager,
                            config.symbols,
                        )?,
                    )
                }
                ExecHint::CompileWithNonDeterministicValidation
                | ExecHint::ExecuteOnceWithNonDeterministicValidation => {
                    VirtualMachinePrototypeInner::Interpreter(
                        interpreter::InterpreterPrototype::new(
                            config.module_bytes,
                            interpreter::CompilationMode::Lazy,
                            config.symbols,
                        )?,
                    )
                }
                ExecHint::ForceWasmi { lazy_validation } => {
                    VirtualMachinePrototypeInner::Interpreter(
                        interpreter::InterpreterPrototype::new(
                            config.module_bytes,
                            if lazy_validation {
                                interpreter::CompilationMode::Lazy
                            } else {
                                interpreter::CompilationMode::Eager
                            },
                            config.symbols,
                        )?,
                    )
                }

                #[cfg(all(
                    any(
                        all(
                            target_arch = "x86_64",
                            any(
                                target_os = "windows",
                                all(target_os = "linux", target_env = "gnu"),
                                target_os = "macos"
                            )
                        ),
                        all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                        all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                    ),
                    feature = "wasmtime"
                ))]
                ExecHint::ForceWasmtime => VirtualMachinePrototypeInner::Jit(
                    jit::JitPrototype::new(config.module_bytes, config.symbols)?,
                ),
            },
        })
    }

    /// Returns the value of a global that the module exports.
    ///
    /// The global variable must be a `i32`, otherwise an error is returned. Negative values are
    /// silently reinterpreted as an unsigned integer.
    pub fn global_value(&mut self, name: &str) -> Result<u32, GlobalValueErr> {
        match &mut self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            VirtualMachinePrototypeInner::Jit(inner) => inner.global_value(name),
            VirtualMachinePrototypeInner::Interpreter(inner) => inner.global_value(name),
        }
    }

    /// Returns the maximum number of pages that the memory can have.
    ///
    /// `None` if there is no limit.
    pub fn memory_max_pages(&self) -> Option<HeapPages> {
        match &self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            VirtualMachinePrototypeInner::Jit(inner) => inner.memory_max_pages(),
            VirtualMachinePrototypeInner::Interpreter(inner) => inner.memory_max_pages(),
        }
    }

    /// Prepares the prototype for running a function.
    ///
    /// This preliminary step is necessary as it allows reading and writing memory before starting
    /// the actual execution..
    pub fn prepare(self) -> Prepare {
        match self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            VirtualMachinePrototypeInner::Jit(inner) => Prepare {
                inner: PrepareInner::Jit(inner.prepare()),
            },
            VirtualMachinePrototypeInner::Interpreter(inner) => Prepare {
                inner: PrepareInner::Interpreter(inner.prepare()),
            },
        }
    }
}

impl fmt::Debug for VirtualMachinePrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            VirtualMachinePrototypeInner::Jit(inner) => fmt::Debug::fmt(inner, f),
            VirtualMachinePrototypeInner::Interpreter(inner) => fmt::Debug::fmt(inner, f),
        }
    }
}

pub struct Prepare {
    inner: PrepareInner,
}

enum PrepareInner {
    #[cfg(all(
        any(
            all(
                target_arch = "x86_64",
                any(
                    target_os = "windows",
                    all(target_os = "linux", target_env = "gnu"),
                    target_os = "macos"
                )
            ),
            all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
            all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
        ),
        feature = "wasmtime"
    ))]
    Jit(jit::Prepare),
    Interpreter(interpreter::Prepare),
}

impl Prepare {
    /// Turns back this virtual machine into a prototype.
    pub fn into_prototype(self) -> VirtualMachinePrototype {
        VirtualMachinePrototype {
            inner: match self.inner {
                #[cfg(all(
                    any(
                        all(
                            target_arch = "x86_64",
                            any(
                                target_os = "windows",
                                all(target_os = "linux", target_env = "gnu"),
                                target_os = "macos"
                            )
                        ),
                        all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                        all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                    ),
                    feature = "wasmtime"
                ))]
                PrepareInner::Jit(inner) => {
                    VirtualMachinePrototypeInner::Jit(inner.into_prototype())
                }
                PrepareInner::Interpreter(inner) => {
                    VirtualMachinePrototypeInner::Interpreter(inner.into_prototype())
                }
            },
        }
    }

    /// Returns the size of the memory, in bytes.
    pub fn memory_size(&self) -> HeapPages {
        match &self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            PrepareInner::Jit(inner) => inner.memory_size(),
            PrepareInner::Interpreter(inner) => inner.memory_size(),
        }
    }

    /// Copies the given memory range into a `Vec<u8>`.
    ///
    /// Returns an error if the range is invalid or out of range.
    pub fn read_memory(
        &self,
        offset: u32,
        size: u32,
    ) -> Result<impl AsRef<[u8]>, OutOfBoundsError> {
        Ok(match &self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            PrepareInner::Jit(inner) => either::Left(inner.read_memory(offset, size)?),
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            PrepareInner::Interpreter(inner) => either::Right(inner.read_memory(offset, size)?),
            #[cfg(not(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            )))]
            PrepareInner::Interpreter(inner) => inner.read_memory(offset, size)?,
        })
    }

    /// Write the data at the given memory location.
    ///
    /// Returns an error if the range is invalid or out of range.
    pub fn write_memory(&mut self, offset: u32, value: &[u8]) -> Result<(), OutOfBoundsError> {
        match &mut self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            PrepareInner::Jit(inner) => inner.write_memory(offset, value),
            PrepareInner::Interpreter(inner) => inner.write_memory(offset, value),
        }
    }

    /// Increases the size of the memory by the given number of pages.
    ///
    /// Returns an error if the size of the memory can't be expanded more. This can be known ahead
    /// of time by using [`VirtualMachinePrototype::memory_max_pages`].
    pub fn grow_memory(&mut self, additional: HeapPages) -> Result<(), OutOfBoundsError> {
        match &mut self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            PrepareInner::Jit(inner) => inner.grow_memory(additional),
            PrepareInner::Interpreter(inner) => inner.grow_memory(additional),
        }
    }

    /// Turns this prototype into an actual virtual machine. This requires choosing which function
    /// to execute.
    pub fn start(
        self,
        function_name: &str,
        params: &[WasmValue],
    ) -> Result<VirtualMachine, (StartErr, VirtualMachinePrototype)> {
        Ok(VirtualMachine {
            inner: match self.inner {
                #[cfg(all(
                    any(
                        all(
                            target_arch = "x86_64",
                            any(
                                target_os = "windows",
                                all(target_os = "linux", target_env = "gnu"),
                                target_os = "macos"
                            )
                        ),
                        all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                        all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                    ),
                    feature = "wasmtime"
                ))]
                PrepareInner::Jit(inner) => match inner.start(function_name, params) {
                    Ok(vm) => VirtualMachineInner::Jit(vm),
                    Err((err, proto)) => {
                        return Err((
                            err,
                            VirtualMachinePrototype {
                                inner: VirtualMachinePrototypeInner::Jit(proto),
                            },
                        ));
                    }
                },
                PrepareInner::Interpreter(inner) => match inner.start(function_name, params) {
                    Ok(vm) => VirtualMachineInner::Interpreter(vm),
                    Err((err, proto)) => {
                        return Err((
                            err,
                            VirtualMachinePrototype {
                                inner: VirtualMachinePrototypeInner::Interpreter(proto),
                            },
                        ));
                    }
                },
            },
        })
    }
}

impl fmt::Debug for Prepare {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            PrepareInner::Jit(inner) => fmt::Debug::fmt(inner, f),
            PrepareInner::Interpreter(inner) => fmt::Debug::fmt(inner, f),
        }
    }
}

pub struct VirtualMachine {
    inner: VirtualMachineInner,
}

enum VirtualMachineInner {
    #[cfg(all(
        any(
            all(
                target_arch = "x86_64",
                any(
                    target_os = "windows",
                    all(target_os = "linux", target_env = "gnu"),
                    target_os = "macos"
                )
            ),
            all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
            all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
        ),
        feature = "wasmtime"
    ))]
    Jit(jit::Jit),
    Interpreter(interpreter::Interpreter),
}

impl VirtualMachine {
    /// Starts or continues execution of this thread.
    ///
    /// If this is the first call you call [`run`](VirtualMachine::run) for this thread, then you
    /// must pass a value of `None`.
    /// If, however, you call this function after a previous call to [`run`](VirtualMachine::run)
    /// that was interrupted by a host function call, then you must pass back the outcome of
    /// that call.
    pub fn run(&mut self, value: Option<WasmValue>) -> Result<ExecOutcome, RunErr> {
        match &mut self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            VirtualMachineInner::Jit(inner) => inner.run(value),
            VirtualMachineInner::Interpreter(inner) => inner.run(value),
        }
    }

    /// Returns the size of the memory, in bytes.
    ///
    /// > **Note**: This can change over time if the Wasm code uses the `grow` opcode.
    pub fn memory_size(&self) -> HeapPages {
        match &self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            VirtualMachineInner::Jit(inner) => inner.memory_size(),
            VirtualMachineInner::Interpreter(inner) => inner.memory_size(),
        }
    }

    /// Copies the given memory range into a `Vec<u8>`.
    ///
    /// Returns an error if the range is invalid or out of range.
    pub fn read_memory(
        &self,
        offset: u32,
        size: u32,
    ) -> Result<impl AsRef<[u8]>, OutOfBoundsError> {
        Ok(match &self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            VirtualMachineInner::Jit(inner) => either::Left(inner.read_memory(offset, size)?),
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            VirtualMachineInner::Interpreter(inner) => {
                either::Right(inner.read_memory(offset, size)?)
            }
            #[cfg(not(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            )))]
            VirtualMachineInner::Interpreter(inner) => inner.read_memory(offset, size)?,
        })
    }

    /// Write the data at the given memory location.
    ///
    /// Returns an error if the range is invalid or out of range.
    pub fn write_memory(&mut self, offset: u32, value: &[u8]) -> Result<(), OutOfBoundsError> {
        match &mut self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            VirtualMachineInner::Jit(inner) => inner.write_memory(offset, value),
            VirtualMachineInner::Interpreter(inner) => inner.write_memory(offset, value),
        }
    }

    /// Increases the size of the memory by the given number of pages.
    ///
    /// Returns an error if the size of the memory can't be expanded more. This can be known ahead
    /// of time by using [`VirtualMachinePrototype::memory_max_pages`].
    pub fn grow_memory(&mut self, additional: HeapPages) -> Result<(), OutOfBoundsError> {
        match &mut self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            VirtualMachineInner::Jit(inner) => inner.grow_memory(additional),
            VirtualMachineInner::Interpreter(inner) => inner.grow_memory(additional),
        }
    }

    /// Turns back this virtual machine into a prototype.
    pub fn into_prototype(self) -> VirtualMachinePrototype {
        VirtualMachinePrototype {
            inner: match self.inner {
                #[cfg(all(
                    any(
                        all(
                            target_arch = "x86_64",
                            any(
                                target_os = "windows",
                                all(target_os = "linux", target_env = "gnu"),
                                target_os = "macos"
                            )
                        ),
                        all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                        all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                    ),
                    feature = "wasmtime"
                ))]
                VirtualMachineInner::Jit(inner) => {
                    VirtualMachinePrototypeInner::Jit(inner.into_prototype())
                }
                VirtualMachineInner::Interpreter(inner) => {
                    VirtualMachinePrototypeInner::Interpreter(inner.into_prototype())
                }
            },
        }
    }
}

impl fmt::Debug for VirtualMachine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.inner {
            #[cfg(all(
                any(
                    all(
                        target_arch = "x86_64",
                        any(
                            target_os = "windows",
                            all(target_os = "linux", target_env = "gnu"),
                            target_os = "macos"
                        )
                    ),
                    all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                    all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
                ),
                feature = "wasmtime"
            ))]
            VirtualMachineInner::Jit(inner) => fmt::Debug::fmt(inner, f),
            VirtualMachineInner::Interpreter(inner) => fmt::Debug::fmt(inner, f),
        }
    }
}

/// Hint used by the implementation to decide which kind of virtual machine to use.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExecHint {
    /// The WebAssembly code will be instantiated once and run many times.
    /// If possible, compile this WebAssembly code ahead of time.
    ValidateAndCompile,

    /// The WebAssembly code will be instantiated once and run many times.
    /// Contrary to [`ExecHint::ValidateAndCompile`], the WebAssembly code isn't fully validated
    /// ahead of time, meaning that invalid WebAssembly modules might successfully be compiled,
    /// which is an undesirable property in some contexts.
    CompileWithNonDeterministicValidation,

    /// The WebAssembly code is expected to be only run once.
    ///
    /// > **Note**: This isn't a hard requirement but a hint.
    ValidateAndExecuteOnce,

    /// The WebAssembly code will be instantiated once and run many times.
    /// Contrary to [`ExecHint::ValidateAndExecuteOnce`], the WebAssembly code isn't fully
    /// validated ahead of time, meaning that invalid WebAssembly modules might successfully be
    /// compiled, which is an undesirable property in some contexts.
    ExecuteOnceWithNonDeterministicValidation,

    /// The WebAssembly code running through this VM is untrusted.
    Untrusted,

    /// Forces using the `wasmi` backend.
    ///
    /// This variant is useful for testing purposes.
    ForceWasmi {
        /// If `true`, lazy validation is enabled. This leads to a faster initialization time,
        /// but can also successfully validate invalid modules, which is an undesirable property
        /// in some contexts.
        lazy_validation: bool,
    },
    /// Forces using the `wasmtime` backend.
    ///
    /// This variant is useful for testing purposes.
    #[cfg(all(
        any(
            all(
                target_arch = "x86_64",
                any(
                    target_os = "windows",
                    all(target_os = "linux", target_env = "gnu"),
                    target_os = "macos"
                )
            ),
            all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
            all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
        ),
        feature = "wasmtime"
    ))]
    ForceWasmtime,
}

impl ExecHint {
    /// Returns an iterator of all the [`ExecHint`] values corresponding to execution engines.
    ///
    /// > **Note**: This function is most useful for testing purposes.
    pub fn available_engines() -> impl Iterator<Item = ExecHint> {
        iter::once(ExecHint::ForceWasmi {
            lazy_validation: false,
        })
        .chain(Self::force_wasmtime_if_available())
    }

    /// Returns `ForceWasmtime` if it is available on the current platform, and `None` otherwise.
    pub fn force_wasmtime_if_available() -> Option<ExecHint> {
        #[cfg(all(
            any(
                all(
                    target_arch = "x86_64",
                    any(
                        target_os = "windows",
                        all(target_os = "linux", target_env = "gnu"),
                        target_os = "macos"
                    )
                ),
                all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
            ),
            feature = "wasmtime"
        ))]
        fn value() -> Option<ExecHint> {
            Some(ExecHint::ForceWasmtime)
        }
        #[cfg(not(all(
            any(
                all(
                    target_arch = "x86_64",
                    any(
                        target_os = "windows",
                        all(target_os = "linux", target_env = "gnu"),
                        target_os = "macos"
                    )
                ),
                all(target_arch = "aarch64", all(target_os = "linux", target_env = "gnu")),
                all(target_arch = "s390x", all(target_os = "linux", target_env = "gnu"))
            ),
            feature = "wasmtime"
        )))]
        fn value() -> Option<ExecHint> {
            None
        }
        value()
    }
}

/// Number of heap pages available to the Wasm code.
///
/// Each page is `64kiB`.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, derive_more::Add, derive_more::Sub,
)]
pub struct HeapPages(u32);

impl HeapPages {
    pub const fn new(v: u32) -> Self {
        HeapPages(v)
    }
}

impl From<u32> for HeapPages {
    fn from(v: u32) -> Self {
        HeapPages(v)
    }
}

impl From<HeapPages> for u32 {
    fn from(v: HeapPages) -> Self {
        v.0
    }
}

/// Low-level Wasm function signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    params: SmallVec<[ValueType; 8]>,
    ret_ty: Option<ValueType>,
}

// TODO: figure out how to optimize so that we can use this macro in a const context
#[macro_export]
macro_rules! signature {
    (($($param:expr),* $(,)?) => ()) => {
        $crate::executor::vm::Signature::from_components(smallvec::smallvec!($($param),*), None)
    };
    (($($param:expr),* $(,)?) => $ret:expr) => {
        $crate::executor::vm::Signature::from_components(smallvec::smallvec!($($param),*), Some($ret))
    };
}

impl Signature {
    /// Creates a [`Signature`] from the given parameter types and return type.
    pub fn new(
        params: impl Iterator<Item = ValueType>,
        ret_ty: impl Into<Option<ValueType>>,
    ) -> Signature {
        Signature {
            params: params.collect(),
            ret_ty: ret_ty.into(),
        }
    }

    // TODO: find a way to remove? it is used only by the signature! macro
    #[doc(hidden)]
    pub(crate) fn from_components(
        params: SmallVec<[ValueType; 8]>,
        ret_ty: Option<ValueType>,
    ) -> Self {
        Signature { params, ret_ty }
    }

    /// Returns a list of all the types of the parameters.
    pub fn parameters(&self) -> impl ExactSizeIterator<Item = &ValueType> {
        self.params.iter()
    }

    /// Returns the type of the return type of the function. `None` means "void".
    pub fn return_type(&self) -> Option<&ValueType> {
        self.ret_ty.as_ref()
    }
}

impl<'a> From<&'a Signature> for wasmi::FuncType {
    fn from(sig: &'a Signature) -> Self {
        wasmi::FuncType::new(
            sig.params
                .iter()
                .copied()
                .map(wasmi::core::ValType::from)
                .collect::<Vec<_>>(),
            sig.ret_ty.map(wasmi::core::ValType::from),
        )
    }
}

impl From<Signature> for wasmi::FuncType {
    fn from(sig: Signature) -> wasmi::FuncType {
        wasmi::FuncType::from(&sig)
    }
}

impl<'a> TryFrom<&'a wasmi::FuncType> for Signature {
    type Error = UnsupportedTypeError;

    fn try_from(sig: &'a wasmi::FuncType) -> Result<Self, Self::Error> {
        if sig.results().len() > 1 {
            return Err(UnsupportedTypeError);
        }

        Ok(Signature {
            params: sig
                .params()
                .iter()
                .copied()
                .map(ValueType::try_from)
                .collect::<Result<_, _>>()?,
            ret_ty: sig
                .results()
                .first()
                .copied()
                .map(ValueType::try_from)
                .transpose()?,
        })
    }
}

#[cfg(all(
    any(
        all(
            target_arch = "x86_64",
            any(
                target_os = "windows",
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos"
            )
        ),
        all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "s390x", target_os = "linux", target_env = "gnu")
    ),
    feature = "wasmtime"
))]
impl<'a> TryFrom<&'a wasmtime::FuncType> for Signature {
    type Error = UnsupportedTypeError;

    fn try_from(sig: &'a wasmtime::FuncType) -> Result<Self, Self::Error> {
        if sig.results().len() > 1 {
            return Err(UnsupportedTypeError);
        }

        Ok(Signature {
            params: sig
                .params()
                .map(ValueType::try_from)
                .collect::<Result<_, _>>()?,
            ret_ty: sig.results().next().map(ValueType::try_from).transpose()?,
        })
    }
}

impl TryFrom<wasmi::FuncType> for Signature {
    type Error = UnsupportedTypeError;

    fn try_from(sig: wasmi::FuncType) -> Result<Self, Self::Error> {
        Signature::try_from(&sig)
    }
}

/// Value that a Wasm function can accept or produce.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum WasmValue {
    /// A 32-bits integer. There is no fundamental difference between signed and unsigned
    /// integer, and the signed-ness should be determined depending on the context.
    I32(i32),
    /// A 32-bits integer. There is no fundamental difference between signed and unsigned
    /// integer, and the signed-ness should be determined depending on the context.
    I64(i64),
}

/// Type of a value passed as parameter or returned by a function.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ValueType {
    /// A 32-bits integer. Used for both signed and unsigned integers.
    I32,
    /// A 64-bits integer. Used for both signed and unsigned integers.
    I64,
}

impl WasmValue {
    /// Returns the type corresponding to this value.
    pub fn ty(&self) -> ValueType {
        match self {
            WasmValue::I32(_) => ValueType::I32,
            WasmValue::I64(_) => ValueType::I64,
        }
    }

    /// Unwraps [`WasmValue::I32`] into its value.
    pub fn into_i32(self) -> Option<i32> {
        if let WasmValue::I32(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// Unwraps [`WasmValue::I64`] into its value.
    pub fn into_i64(self) -> Option<i64> {
        if let WasmValue::I64(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

impl TryFrom<wasmi::Val> for WasmValue {
    type Error = UnsupportedTypeError;

    fn try_from(val: wasmi::Val) -> Result<Self, Self::Error> {
        match val {
            wasmi::Val::I32(v) => Ok(WasmValue::I32(v)),
            wasmi::Val::I64(v) => Ok(WasmValue::I64(v)),
            _ => Err(UnsupportedTypeError),
        }
    }
}

impl<'a> TryFrom<&'a wasmi::Val> for WasmValue {
    type Error = UnsupportedTypeError;

    fn try_from(val: &'a wasmi::Val) -> Result<Self, Self::Error> {
        match val {
            wasmi::Val::I32(v) => Ok(WasmValue::I32(*v)),
            wasmi::Val::I64(v) => Ok(WasmValue::I64(*v)),
            _ => Err(UnsupportedTypeError),
        }
    }
}

impl From<WasmValue> for wasmi::Val {
    fn from(val: WasmValue) -> Self {
        match val {
            WasmValue::I32(v) => wasmi::Val::I32(v),
            WasmValue::I64(v) => wasmi::Val::I64(v),
        }
    }
}

#[cfg(all(
    any(
        all(
            target_arch = "x86_64",
            any(
                target_os = "windows",
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos"
            )
        ),
        all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "s390x", target_os = "linux", target_env = "gnu")
    ),
    feature = "wasmtime"
))]
impl From<WasmValue> for wasmtime::Val {
    fn from(val: WasmValue) -> Self {
        match val {
            WasmValue::I32(v) => wasmtime::Val::I32(v),
            WasmValue::I64(v) => wasmtime::Val::I64(v),
        }
    }
}

#[cfg(all(
    any(
        all(
            target_arch = "x86_64",
            any(
                target_os = "windows",
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos"
            )
        ),
        all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "s390x", target_os = "linux", target_env = "gnu")
    ),
    feature = "wasmtime"
))]
impl<'a> TryFrom<&'a wasmtime::Val> for WasmValue {
    type Error = UnsupportedTypeError;

    fn try_from(val: &'a wasmtime::Val) -> Result<Self, Self::Error> {
        match val {
            wasmtime::Val::I32(v) => Ok(WasmValue::I32(*v)),
            wasmtime::Val::I64(v) => Ok(WasmValue::I64(*v)),
            _ => Err(UnsupportedTypeError),
        }
    }
}

impl From<ValueType> for wasmi::core::ValType {
    fn from(ty: ValueType) -> wasmi::core::ValType {
        match ty {
            ValueType::I32 => wasmi::core::ValType::I32,
            ValueType::I64 => wasmi::core::ValType::I64,
        }
    }
}

impl TryFrom<wasmi::core::ValType> for ValueType {
    type Error = UnsupportedTypeError;

    fn try_from(val: wasmi::core::ValType) -> Result<Self, Self::Error> {
        match val {
            wasmi::core::ValType::I32 => Ok(ValueType::I32),
            wasmi::core::ValType::I64 => Ok(ValueType::I64),
            _ => Err(UnsupportedTypeError),
        }
    }
}

#[cfg(all(
    any(
        all(
            target_arch = "x86_64",
            any(
                target_os = "windows",
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos"
            )
        ),
        all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "s390x", target_os = "linux", target_env = "gnu")
    ),
    feature = "wasmtime"
))]
impl TryFrom<wasmtime::ValType> for ValueType {
    type Error = UnsupportedTypeError;

    fn try_from(val: wasmtime::ValType) -> Result<Self, Self::Error> {
        match val {
            wasmtime::ValType::I32 => Ok(ValueType::I32),
            wasmtime::ValType::I64 => Ok(ValueType::I64),
            _ => Err(UnsupportedTypeError),
        }
    }
}

/// Error used in the conversions between VM implementation and the public API.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub struct UnsupportedTypeError;

/// Outcome of the [`run`](VirtualMachine::run) function.
#[derive(Debug)]
pub enum ExecOutcome {
    /// The execution has finished.
    ///
    /// The state machine is now in a poisoned state, and calling [`run`](VirtualMachine::run)
    /// will return [`RunErr::Poisoned`].
    Finished {
        /// Return value of the function.
        return_value: Result<Option<WasmValue>, Trap>,
    },

    /// The virtual machine has been paused due to a call to a host function.
    ///
    /// This variant contains the identifier of the host function that is expected to be
    /// called, and its parameters. When you call [`run`](VirtualMachine::run) again, you must
    /// pass back the outcome of calling that function.
    ///
    /// > **Note**: The type of the return value of the function is called is not specified, as the
    /// >           user is supposed to know it based on the identifier. It is an error to call
    /// >           [`run`](VirtualMachine::run) with a value of the wrong type.
    Interrupted {
        /// Identifier of the function to call. Corresponds to the value provided at
        /// initialization when resolving imports.
        id: usize,

        /// Parameters of the function call.
        params: Vec<WasmValue>,
    },
}

/// Opaque error that happened during execution, such as an `unreachable` instruction.
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
#[display("{_0}")]
pub struct Trap(#[error(not(source))] String);

/// Error that can happen when initializing a [`VirtualMachinePrototype`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum NewErr {
    /// Error while compiling the WebAssembly code.
    ///
    /// Contains an opaque error message.
    #[display("{_0}")]
    InvalidWasm(#[error(not(source))] String),
    /// Error while instantiating the WebAssembly module.
    ///
    /// Contains an opaque error message.
    #[display("{_0}")]
    Instantiation(#[error(not(source))] String),
    /// Failed to resolve a function imported by the module.
    #[display("Unresolved function `{module_name}`:`{function}`")]
    UnresolvedFunctionImport {
        /// Name of the function that was unresolved.
        function: String,
        /// Name of module associated with the unresolved function.
        module_name: String,
    },
    /// Smoldot doesn't support wasm runtime that have a start function. It is unclear whether
    /// this is allowed in the Substrate/Polkadot specification.
    #[display("Start function not supported")]
    // TODO: figure this out
    StartFunctionNotSupported,
    /// If a "memory" symbol is provided, it must be a memory.
    #[display("If a \"memory\" symbol is provided, it must be a memory.")]
    MemoryIsntMemory,
    /// Wasm module imports a memory that isn't named "memory".
    MemoryNotNamedMemory,
    /// Wasm module doesn't contain any memory.
    NoMemory,
    /// Wasm module both imports and exports a memory.
    TwoMemories,
    /// Failed to allocate memory for the virtual machine.
    CouldntAllocateMemory,
    /// The Wasm module requires importing a global or a table, which isn't supported.
    ImportTypeNotSupported,
}

/// Error that can happen when calling [`Prepare::start`].
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub enum StartErr {
    /// Couldn't find the requested function.
    #[display("Function to start was not found.")]
    FunctionNotFound,
    /// The requested function has been found in the list of exports, but it is not a function.
    #[display("Symbol to start is not a function.")]
    NotAFunction,
    /// The requested function has a signature that isn't supported.
    #[display("Function to start uses unsupported signature.")]
    SignatureNotSupported,
    /// The types of the provided parameters don't match the signature.
    #[display("The types of the provided parameters don't match the signature.")]
    InvalidParameters,
}

/// Error while reading memory.
#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display("Out of bounds when accessing virtual machine memory")]
pub struct OutOfBoundsError;

/// Error that can happen when resuming the execution of a function.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum RunErr {
    /// The state machine is poisoned.
    #[display("State machine is poisoned")]
    Poisoned,
    /// Passed a wrong value back.
    #[display("Expected value of type {expected:?} but got {obtained:?} instead")]
    BadValueTy {
        /// Type of the value that was expected.
        expected: Option<ValueType>,
        /// Type of the value that was actually passed.
        obtained: Option<ValueType>,
    },
}

/// Error that can happen when calling [`VirtualMachinePrototype::global_value`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum GlobalValueErr {
    /// Couldn't find requested symbol.
    NotFound,
    /// Requested symbol isn't a `u32`.
    Invalid,
}
