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

//! Implements the API documented [in the parent module](..).

use super::{
    ExecOutcome, GlobalValueErr, HeapPages, ModuleError, NewErr, OutOfBoundsError, RunErr,
    Signature, StartErr, Trap, ValueType, WasmValue,
};

use alloc::{borrow::ToOwned as _, boxed::Box, format, string::ToString as _, sync::Arc, vec::Vec};
use core::{cell::RefCell, fmt};

/// See [`super::Module`].
#[derive(Clone)]
pub struct Module {
    // Note: an `Arc` is used in order to expose the same API as wasmtime does. If in the future
    // wasmtime happened to no longer use internal reference counting, this `Arc` should be
    // removed.
    inner: Arc<wasmi::Module>,
}

impl Module {
    /// See [`super::Module::new`].
    pub fn new(module_bytes: impl AsRef<[u8]>) -> Result<Self, ModuleError> {
        let module = wasmi::Module::from_buffer(module_bytes.as_ref())
            .map_err(|err| ModuleError(err.to_string()))?;

        Ok(Module {
            inner: Arc::new(module),
        })
    }
}

/// See [`super::VirtualMachinePrototype`].
pub struct InterpreterPrototype {
    /// Original module, with resolved imports.
    module: wasmi::ModuleRef,

    /// Memory of the module instantiation.
    memory: wasmi::MemoryRef,

    /// Table of the indirect function calls.
    ///
    /// In Wasm, function pointers are in reality indices in a table called
    /// `__indirect_function_table`. This is this table, if it exists.
    indirect_table: Option<wasmi::TableRef>,
}

impl InterpreterPrototype {
    /// See [`super::VirtualMachinePrototype::new`].
    pub fn new(
        module: &Module,
        mut symbols: impl FnMut(&str, &str, &Signature) -> Result<usize, ()>,
    ) -> Result<Self, NewErr> {
        struct ImportResolve<'a> {
            functions: RefCell<&'a mut dyn FnMut(&str, &str, &Signature) -> Result<usize, ()>>,
            import_memory: RefCell<&'a mut Option<wasmi::MemoryRef>>,
        }

        impl<'a> wasmi::ImportResolver for ImportResolve<'a> {
            fn resolve_func(
                &self,
                module_name: &str,
                field_name: &str,
                signature: &wasmi::Signature,
            ) -> Result<wasmi::FuncRef, wasmi::Error> {
                let closure = &mut **self.functions.borrow_mut();
                let conv_signature = match TryFrom::try_from(signature) {
                    Ok(i) => i,
                    Err(_) => {
                        return Err(wasmi::Error::Instantiation(format!(
                            "Function with unsupported signature `{}`:`{}`",
                            module_name, field_name
                        )))
                    }
                };
                let index = match closure(module_name, field_name, &conv_signature) {
                    Ok(i) => i,
                    Err(_) => {
                        return Err(wasmi::Error::Host(Box::new(NewErrWrapper(
                            NewErr::UnresolvedFunctionImport {
                                module_name: module_name.to_owned(),
                                function: field_name.to_owned(),
                            },
                        ))))
                    }
                };

                Ok(wasmi::FuncInstance::alloc_host(signature.clone(), index))
            }

            fn resolve_global(
                &self,
                _module_name: &str,
                _field_name: &str,
                _global_type: &wasmi::GlobalDescriptor,
            ) -> Result<wasmi::GlobalRef, wasmi::Error> {
                Err(wasmi::Error::Instantiation(
                    "Importing globals is not supported yet".to_owned(),
                ))
            }

            fn resolve_memory(
                &self,
                module_name: &str,
                field_name: &str,
                memory_type: &wasmi::MemoryDescriptor,
            ) -> Result<wasmi::MemoryRef, wasmi::Error> {
                if module_name != "env" || field_name != "memory" {
                    return Err(wasmi::Error::Host(Box::new(NewErrWrapper(
                        NewErr::MemoryNotNamedMemory,
                    ))));
                }

                // Considering that the memory can only be "env":"memory", and that each
                // import has a unique name, this block can't be reached more than once.
                debug_assert!(self.import_memory.borrow().is_none());

                let memory = wasmi::MemoryInstance::alloc(
                    wasmi::memory_units::Pages(memory_type.initial() as usize),
                    memory_type
                        .maximum()
                        .map(|hp| wasmi::memory_units::Pages(hp as usize)),
                )?;
                **self.import_memory.borrow_mut() = Some(memory.clone());
                Ok(memory)
            }

            fn resolve_table(
                &self,
                _module_name: &str,
                _field_name: &str,
                _table_type: &wasmi::TableDescriptor,
            ) -> Result<wasmi::TableRef, wasmi::Error> {
                Err(wasmi::Error::Instantiation(
                    "Importing tables is not supported yet".to_owned(),
                ))
            }
        }

        // Wasmi provides an `Error::Host` variant that contains a ̀`Box<dyn wasmi::HostError>`
        // that can be downcasted to anything.
        // Unfortunately the `HostError` trait must be implemented manually, and in order to not
        // have a leaky abstraction we don't implement it directly on `NewErr` but on a wrapper
        // type.
        #[derive(Debug, derive_more::Display)]
        struct NewErrWrapper(NewErr);
        impl wasmi::HostError for NewErrWrapper {}

        let mut import_memory = None;
        let not_started = {
            let resolver = ImportResolve {
                functions: RefCell::new(&mut symbols),
                import_memory: RefCell::new(&mut import_memory),
            };

            match wasmi::ModuleInstance::new(&module.inner, &resolver) {
                Ok(m) => m,
                Err(wasmi::Error::Host(err)) if err.is::<NewErrWrapper>() => {
                    let underlying = err.downcast::<NewErrWrapper>().unwrap();
                    return Err(underlying.0);
                }
                Err(err) => return Err(NewErr::ModuleError(ModuleError(err.to_string()))),
            }
        };
        // TODO: explain `assert_no_start`
        let module = not_started.assert_no_start();

        let memory = if let Some(import_memory) = import_memory {
            if module
                .export_by_name("memory")
                .map_or(false, |m| m.as_memory().is_some())
            {
                return Err(NewErr::TwoMemories);
            }

            import_memory
        } else if let Some(mem) = module.export_by_name("memory") {
            if let Some(mem) = mem.as_memory() {
                mem.clone()
            } else {
                return Err(NewErr::MemoryIsntMemory);
            }
        } else {
            return Err(NewErr::NoMemory);
        };

        let indirect_table = if let Some(tbl) = module.export_by_name("__indirect_function_table") {
            if let Some(tbl) = tbl.as_table() {
                Some(tbl.clone())
            } else {
                return Err(NewErr::IndirectTableIsntTable);
            }
        } else {
            None
        };

        Ok(InterpreterPrototype {
            module,
            memory,
            indirect_table,
        })
    }

    /// See [`super::VirtualMachinePrototype::global_value`].
    pub fn global_value(&self, name: &str) -> Result<u32, GlobalValueErr> {
        let value = self
            .module
            .export_by_name(name)
            .ok_or(GlobalValueErr::NotFound)?
            .as_global()
            .ok_or(GlobalValueErr::Invalid)?
            .get();

        match value {
            wasmi::RuntimeValue::I32(v) => match u32::try_from(v) {
                Ok(v) => Ok(v),
                Err(_) => Err(GlobalValueErr::Invalid),
            },
            _ => Err(GlobalValueErr::Invalid),
        }
    }

    /// See [`super::VirtualMachinePrototype::memory_max_pages`].
    pub fn memory_max_pages(&self) -> Option<HeapPages> {
        self.memory
            .maximum()
            .and_then(|hp| u32::try_from(hp.0).ok()) // An overflow in the maximum leads to returning `None`
            .map(|hp| HeapPages(hp))
    }

    /// See [`super::VirtualMachinePrototype::start`].
    pub fn start(
        self,
        min_memory_pages: HeapPages,
        function_name: &str,
        params: &[WasmValue],
    ) -> Result<Interpreter, (StartErr, Self)> {
        let min_memory_pages = match usize::try_from(min_memory_pages.0) {
            Ok(hp) => hp,
            Err(_) => return Err((StartErr::RequiredMemoryTooLarge, self)),
        };

        if let Some(to_grow) = min_memory_pages.checked_sub(self.memory.current_size().0) {
            if self
                .memory
                .grow(wasmi::memory_units::Pages(to_grow))
                .is_err()
            {
                return Err((StartErr::RequiredMemoryTooLarge, self));
            }
        }

        let execution = match self.module.export_by_name(function_name) {
            Some(wasmi::ExternVal::Func(f)) => {
                // Try to convert the signature of the function to call, in order to make sure
                // that the type of parameters and return value are supported.
                if Signature::try_from(f.signature()).is_err() {
                    return Err((StartErr::SignatureNotSupported, self));
                }

                wasmi::FuncInstance::invoke_resumable(
                    &f,
                    params
                        .iter()
                        .map(|v| wasmi::RuntimeValue::from(*v))
                        .collect::<Vec<_>>(),
                )
                .map_err(|err| Trap(err.to_string()))
            }
            None => return Err((StartErr::FunctionNotFound, self)),
            _ => return Err((StartErr::NotAFunction, self)),
        };

        Ok(Interpreter {
            _module: self.module,
            memory: self.memory,
            execution: Some(execution),
            interrupted: false,
            indirect_table: self.indirect_table,
        })
    }
}

// The fields related to `wasmi` do not implement `Send` because they use `std::rc::Rc`. `Rc`
// does not implement `Send` because incrementing/decrementing the reference counter from
// multiple threads simultaneously would be racy. It is however perfectly sound to move all the
// instances of `Rc`s at once between threads, which is what we're doing here.
//
// This importantly means that we should never return a `Rc` (even by reference) across the API
// boundary.
//
// For this reason, it would also be unsafe to implement `Clone` on `InterpreterPrototype`. A
// user could clone the `InterpreterPrototype` and send it to another thread, which would be
// undefined behaviour.
// TODO: really annoying to have to use unsafe code
unsafe impl Send for InterpreterPrototype {}

impl fmt::Debug for InterpreterPrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("InterpreterPrototype").finish()
    }
}

/// See [`super::VirtualMachine`].
pub struct Interpreter {
    /// Original module, with resolved imports.
    _module: wasmi::ModuleRef,

    /// Memory of the module instantiation.
    memory: wasmi::MemoryRef,

    /// Table of the indirect function calls.
    ///
    /// In Wasm, function pointers are in reality indices in a table called
    /// `__indirect_function_table`. This is this table, if it exists.
    indirect_table: Option<wasmi::TableRef>,

    /// Execution context of this virtual machine. This notably holds the program counter, state
    /// of the stack, and so on.
    ///
    /// This field is an `Option` because we need to be able to temporarily extract it.
    /// If `None`, the state machine is in a poisoned state and cannot run any code anymore.
    /// Can contain an `Err` if the initialization failed, in which case the execution must
    /// return an error immediately.
    execution: Option<Result<wasmi::FuncInvocation<'static>, Trap>>,

    /// If false, then one must call `execution.start_execution()` instead of `resume_execution()`.
    /// This is a particularity of the Wasm interpreter that we don't want to expose in our API.
    interrupted: bool,
}

impl Interpreter {
    /// See [`super::VirtualMachine::run`].
    pub fn run(&mut self, value: Option<WasmValue>) -> Result<ExecOutcome, RunErr> {
        let value = value.map(wasmi::RuntimeValue::from);

        struct DummyExternals;
        impl wasmi::Externals for DummyExternals {
            fn invoke_index(
                &mut self,
                index: usize,
                args: wasmi::RuntimeArgs,
            ) -> Result<Option<wasmi::RuntimeValue>, wasmi::Trap> {
                Err(wasmi::TrapKind::Host(Box::new(Interrupt {
                    index,
                    args: args.as_ref().to_vec(),
                }))
                .into())
            }
        }

        #[derive(Debug)]
        struct Interrupt {
            index: usize,
            args: Vec<wasmi::RuntimeValue>,
        }
        impl fmt::Display for Interrupt {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "Interrupt")
            }
        }
        impl wasmi::HostError for Interrupt {}

        let mut execution = match self.execution.take() {
            Some(Ok(e)) => e,
            Some(Err(err)) => {
                return Ok(ExecOutcome::Finished {
                    return_value: Err(err),
                })
            }
            None => return Err(RunErr::Poisoned),
        };

        // Since the signature of the function is checked at initialization to be supported, it is
        // guaranteed that the conversions below won't panic.

        let result = if self.interrupted {
            let expected_ty = execution
                .resumable_value_type()
                .map(|v| ValueType::try_from(v).unwrap());
            let obtained_ty = value
                .as_ref()
                .map(|v| ValueType::try_from(v.value_type()).unwrap());
            if expected_ty != obtained_ty {
                return Err(RunErr::BadValueTy {
                    expected: expected_ty,
                    obtained: obtained_ty,
                });
            }
            execution.resume_execution(value, &mut DummyExternals)
        } else {
            if value.is_some() {
                return Err(RunErr::BadValueTy {
                    expected: None,
                    obtained: value
                        .as_ref()
                        .map(|v| ValueType::try_from(v.value_type()).unwrap()),
                });
            }
            self.interrupted = true;
            execution.start_execution(&mut DummyExternals)
        };

        match result {
            Ok(return_value) => Ok(ExecOutcome::Finished {
                return_value: Ok(return_value.map(|r| WasmValue::try_from(r).unwrap())),
            }),
            Err(wasmi::ResumableError::AlreadyStarted) => unreachable!(),
            Err(wasmi::ResumableError::NotResumable) => unreachable!(),
            Err(wasmi::ResumableError::Trap(ref trap)) if trap.kind().is_host() => {
                let interrupt: &Interrupt = match trap.kind() {
                    wasmi::TrapKind::Host(err) => match err.downcast_ref() {
                        Some(e) => e,
                        None => unreachable!(),
                    },
                    _ => unreachable!(),
                };
                self.execution = Some(Ok(execution));
                Ok(ExecOutcome::Interrupted {
                    id: interrupt.index,
                    params: interrupt
                        .args
                        .iter()
                        .cloned()
                        .map(TryFrom::try_from)
                        .collect::<Result<_, _>>()
                        .unwrap(),
                })
            }
            Err(wasmi::ResumableError::Trap(err)) => Ok(ExecOutcome::Finished {
                return_value: Err(Trap(err.to_string())),
            }),
        }
    }

    /// See [`super::VirtualMachine::memory_size`].
    pub fn memory_size(&self) -> HeapPages {
        // Being a 32bits platform, it's impossible that the vm has a number of currently
        // allocated pages that can't fit in 32bits, so this unwrap can't fail.
        HeapPages(u32::try_from(self.memory.current_size().0).unwrap())
    }

    /// See [`super::VirtualMachine::read_memory`].
    pub fn read_memory(
        &'_ self,
        offset: u32,
        size: u32,
    ) -> Result<impl AsRef<[u8]> + '_, OutOfBoundsError> {
        let offset = usize::try_from(offset).map_err(|_| OutOfBoundsError)?;

        let max = offset
            .checked_add(size.try_into().map_err(|_| OutOfBoundsError)?)
            .ok_or(OutOfBoundsError)?;

        enum AccessOffset<T> {
            Enabled {
                access: T,
                offset: usize,
                max: usize,
            },
            Empty,
        }

        impl<T: AsRef<[u8]>> AsRef<[u8]> for AccessOffset<T> {
            fn as_ref(&self) -> &[u8] {
                if let AccessOffset::Enabled {
                    access,
                    offset,
                    max,
                } = self
                {
                    &access.as_ref()[*offset..*max]
                } else {
                    &[]
                }
            }
        }

        let access = self.memory.direct_access();
        if max > access.as_ref().len() {
            return Err(OutOfBoundsError);
        }

        Ok(AccessOffset::Enabled {
            access,
            offset,
            max,
        })
    }

    /// See [`super::VirtualMachine::write_memory`].
    pub fn write_memory(&mut self, offset: u32, value: &[u8]) -> Result<(), OutOfBoundsError> {
        self.memory.set(offset, value).map_err(|_| OutOfBoundsError)
    }

    /// See [`super::VirtualMachine::write_memory`].
    pub fn grow_memory(&mut self, additional: HeapPages) -> Result<(), OutOfBoundsError> {
        self.memory
            .grow(wasmi::memory_units::Pages(
                usize::try_from(additional.0).unwrap(),
            ))
            .map_err(|_| OutOfBoundsError)?;

        Ok(())
    }

    /// See [`super::VirtualMachine::into_prototype`].
    pub fn into_prototype(self) -> InterpreterPrototype {
        // TODO: zero the memory

        InterpreterPrototype {
            module: self._module,
            memory: self.memory,
            indirect_table: self.indirect_table,
        }
    }
}

// The fields related to `wasmi` do not implement `Send` because they use `std::rc::Rc`. `Rc`
// does not implement `Send` because incrementing/decrementing the reference counter from
// multiple threads simultaneously would be racy. It is however perfectly sound to move all the
// instances of `Rc`s at once between threads, which is what we're doing here.
//
// This importantly means that we should never return a `Rc` (even by reference) across the API
// boundary.
// TODO: really annoying to have to use unsafe code
unsafe impl Send for Interpreter {}

impl fmt::Debug for Interpreter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Interpreter").finish()
    }
}
