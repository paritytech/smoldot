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
    Signature, StartErr, Trap, WasmValue,
};

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::{
    fmt, mem, slice,
    task::{Context, Poll, Waker},
};
use parking_lot::Mutex;

use futures::{
    future::{self, Future},
    task, FutureExt as _,
};

/// See [`super::Module`].
#[derive(Clone)]
pub struct Module {
    inner: wasmtime::Module,
}

impl Module {
    /// See [`super::Module::new`].
    pub fn new(module_bytes: impl AsRef<[u8]>) -> Result<Self, NewErr> {
        let mut config = wasmtime::Config::new();
        config.cranelift_nan_canonicalization(true);
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);
        config.async_support(true);
        // The default value of `wasm_backtrace_details` is `Environment`, which reads the
        // `WASMTIME_BACKTRACE_DETAILS` environment variable to determine whether or not to keep
        // debug info. However we don't want any of the behaviour of our code to rely on any
        // environment variables whatsoever. Whether to use `Enable` or `Disable` below isn't
        // very important, so long as it is not `Environment`.
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
        let engine = wasmtime::Engine::new(&config)
            .map_err(|err| NewErr::ModuleError(ModuleError(err.to_string())))?;

        let inner = wasmtime::Module::from_binary(&engine, module_bytes.as_ref())
            .map_err(|err| NewErr::ModuleError(ModuleError(err.to_string())))?;

        Ok(Module { inner })
    }
}

/// See [`super::VirtualMachinePrototype`].
pub struct JitPrototype {
    store: wasmtime::Store<()>,

    /// Instanciated Wasm VM.
    instance: wasmtime::Instance,

    /// Shared between the "outside" and the external functions. See [`Shared`].
    shared: Arc<Mutex<Shared>>,

    /// Reference to the memory used by the module, if any.
    // TODO: shouldn't be an Option? just return error if no memory?
    memory: Option<wasmtime::Memory>,

    /// Reference to the table of indirect functions, in case we need to access it.
    /// `None` if the module doesn't export such table.
    indirect_table: Option<wasmtime::Table>,
}

impl JitPrototype {
    /// See [`super::VirtualMachinePrototype::new`].
    pub fn new(
        module: &Module,
        mut symbols: impl FnMut(&str, &str, &Signature) -> Result<usize, ()>,
    ) -> Result<Self, NewErr> {
        let mut store = wasmtime::Store::new(module.inner.engine(), ());

        let mut imported_memory = None;
        let shared = Arc::new(Mutex::new(Shared::Poisoned));

        // Building the list of symbols that the Wasm VM is able to use.
        let imports = {
            let mut imports = Vec::with_capacity(module.inner.imports().len());
            for import in module.inner.imports() {
                match import.ty() {
                    wasmtime::ExternType::Func(f) => {
                        let name = match import.name() {
                            Some(name) => name,
                            None => {
                                return Err(NewErr::ModuleError(ModuleError(format!(
                                    "unresolved unnamed import in module `{}`",
                                    import.module()
                                ))))
                            }
                        };

                        let function_index =
                            match symbols(import.module(), name, &TryFrom::try_from(&f).unwrap())
                                .ok()
                            {
                                Some(idx) => idx,
                                None => {
                                    return Err(NewErr::UnresolvedFunctionImport {
                                        module_name: import.module().to_owned(),
                                        function: name.to_owned(),
                                    })
                                }
                            };

                        let shared = shared.clone();

                        imports.push(wasmtime::Extern::Func(wasmtime::Func::new_async(
                            &mut store,
                            f.clone(),
                            move |mut caller, params, ret_val| {
                                // This closure is executed whenever the Wasm VM calls a
                                // host function.
                                // While a function call is in progress, only this closure can
                                // have access to the `wasmtime::Store`. For this reason, we use
                                // a small communication protocol with the outside.

                                // Transition `shared` from `OutsideFunctionCall` to
                                // `EnteredFunctionCall`.
                                {
                                    let mut shared_lock = shared.try_lock().unwrap();
                                    match mem::replace(&mut *shared_lock, Shared::Poisoned) {
                                        Shared::OutsideFunctionCall { memory } => {
                                            *shared_lock = Shared::EnteredFunctionCall {
                                                function_index,
                                                parameters: params
                                                    .iter()
                                                    .map(TryFrom::try_from)
                                                    .collect::<Result<_, _>>()
                                                    .unwrap(),
                                                in_interrupted_waker: None, // Filled below
                                                memory_pointer: memory.data_ptr(&caller) as usize,
                                                memory_size: memory.data_size(&mut caller),
                                            };
                                        }
                                        _ => unreachable!(),
                                    }
                                }

                                // Return a future that is ready whenever `Shared` contains
                                // `Return`.
                                let shared = shared.clone();
                                Box::new(future::poll_fn(move |cx| {
                                    let mut shared_lock = shared.try_lock().unwrap();
                                    match *shared_lock {
                                        Shared::EnteredFunctionCall {
                                            ref mut in_interrupted_waker,
                                            ..
                                        }
                                        | Shared::WithinFunctionCall {
                                            ref mut in_interrupted_waker,
                                            ..
                                        } => {
                                            *in_interrupted_waker = Some(cx.waker().clone());
                                            Poll::Pending
                                        }
                                        Shared::MemoryGrowRequired {
                                            ref memory,
                                            additional,
                                        } => {
                                            // The outer call has made sure that `additional`
                                            // would fit.
                                            memory.grow(&mut caller, additional).unwrap();
                                            *shared_lock = Shared::WithinFunctionCall {
                                                in_interrupted_waker: Some(cx.waker().clone()),
                                                memory_pointer: memory.data_ptr(&caller) as usize,
                                                memory_size: memory.data_size(&caller),
                                            };
                                            Poll::Pending
                                        }
                                        Shared::Return {
                                            ref mut return_value,
                                            memory,
                                        } => {
                                            if let Some(returned) = return_value.take() {
                                                assert_eq!(ret_val.len(), 1);
                                                ret_val[0] = From::from(returned);
                                            } else {
                                                assert!(ret_val.is_empty());
                                            }

                                            *shared_lock = Shared::OutsideFunctionCall {
                                                memory: memory.clone(),
                                            };
                                            Poll::Ready(Ok(()))
                                        }
                                        _ => unreachable!(),
                                    }
                                }))
                            },
                        )));
                    }
                    wasmtime::ExternType::Global(_)
                    | wasmtime::ExternType::Table(_)
                    | wasmtime::ExternType::Instance(_)
                    | wasmtime::ExternType::Module(_) => {
                        return Err(NewErr::ModuleError(ModuleError(
                            "global/table/instance/module imports not supported".to_string(),
                        )));
                    }
                    wasmtime::ExternType::Memory(m) => {
                        // TODO: check name and all?
                        // TODO: proper error instead of asserting?
                        assert!(imported_memory.is_none());
                        imported_memory = Some(
                            wasmtime::Memory::new(&mut store, m)
                                .map_err(|_| NewErr::CouldntAllocateMemory)?,
                        );
                        imports.push(wasmtime::Extern::Memory(
                            imported_memory.as_ref().unwrap().clone(),
                        ));
                    }
                };
            }
            imports
        };

        // Note: we assume that `new_async` is instantaneous, which it seems to be. It's actually
        // unclear why this function is async at all, as all it is supposed to do in synchronous.
        // Future versions of `wasmtime` might break this assumption.
        let instance = wasmtime::Instance::new_async(&mut store, &module.inner, &imports)
            .now_or_never()
            .unwrap()
            .unwrap(); // TODO: don't unwrap

        let exported_memory = if let Some(mem) = instance.get_export(&mut store, "memory") {
            if let Some(mem) = mem.into_memory() {
                Some(mem)
            } else {
                return Err(NewErr::MemoryIsntMemory);
            }
        } else {
            None
        };

        let memory = match (exported_memory, imported_memory) {
            (Some(_), Some(_)) => todo!(),
            (Some(m), None) => Some(m),
            (None, Some(m)) => Some(m),
            (None, None) => None,
        };

        let indirect_table =
            if let Some(tbl) = instance.get_export(&mut store, "__indirect_function_table") {
                if let Some(tbl) = tbl.into_table() {
                    Some(tbl)
                } else {
                    return Err(NewErr::IndirectTableIsntTable);
                }
            } else {
                None
            };

        Ok(JitPrototype {
            store,
            instance,
            shared,
            memory,
            indirect_table,
        })
    }

    /// See [`super::VirtualMachinePrototype::global_value`].
    pub fn global_value(&mut self, name: &str) -> Result<u32, GlobalValueErr> {
        match self.instance.get_export(&mut self.store, name) {
            Some(wasmtime::Extern::Global(g)) => match g.get(&mut self.store) {
                wasmtime::Val::I32(v) => Ok(u32::from_ne_bytes(v.to_ne_bytes())),
                _ => Err(GlobalValueErr::Invalid),
            },
            _ => Err(GlobalValueErr::NotFound),
        }
    }

    /// See [`super::VirtualMachinePrototype::memory_max_pages`].
    pub fn memory_max_pages(&self) -> Option<HeapPages> {
        if let Some(memory) = &self.memory {
            let num = memory.ty(&self.store).maximum()?;
            match u32::try_from(num) {
                Ok(n) => Some(HeapPages::new(n)),
                // If `num` doesn't fit in a `u32`, we return `None` to mean "infinite".
                Err(_) => None,
            }
        } else {
            None
        }
    }

    /// See [`super::VirtualMachinePrototype::start`].
    pub fn start(
        mut self,
        function_name: &str,
        params: &[WasmValue],
    ) -> Result<Jit, (StartErr, Self)> {
        // Try to start executing `_start`.
        let start_function = match self.instance.get_export(&mut self.store, function_name) {
            Some(export) => match export.into_func() {
                Some(f) => f,
                None => return Err((StartErr::NotAFunction, self)),
            },
            None => return Err((StartErr::FunctionNotFound, self)),
        };

        // Try to convert the signature of the function to call, in order to make sure
        // that the type of parameters and return value are supported.
        if Signature::try_from(&start_function.ty(&self.store)).is_err() {
            return Err((StartErr::SignatureNotSupported, self));
        }

        // Update `shared` in preparation for the call.
        *self.shared.try_lock().unwrap() = Shared::BeforeFirstRun {
            memory_pointer: self.memory.as_ref().unwrap().data_ptr(&self.store) as usize, // TODO: unwrap()?!
            memory_size: self.memory.as_ref().unwrap().data_size(&self.store), // TODO: unwrap()?!
        };

        // Now starting the function call.
        let function_call = {
            let params = params.iter().map(|v| (*v).into()).collect::<Vec<_>>();
            let mut store = self.store;
            Box::pin(async move {
                let mut result = []; // TODO: correct len
                let outcome = start_function
                    .call_async(&mut store, &params, &mut result)
                    .await;

                // Execution resumes here when the Wasm code has finished, gracefully or not.
                match outcome {
                    Ok(()) => {
                        // The signature of the function has been chedek earlier, and as such it
                        // is guaranteed that it has only one return value.
                        assert!(result.len() == 0 || result.len() == 1);
                        let ret = result.get(0).map(|v| TryFrom::try_from(v).unwrap());
                        (store, Ok(ret))
                    }
                    Err(err) => {
                        // The type of error is from the `anyhow` library. By using
                        // `to_string()` we avoid having to deal with it.
                        (store, Err(err.to_string()))
                    }
                }
            })
        };

        Ok(Jit {
            inner: JitInner::Executing(function_call),
            instance: self.instance,
            shared: self.shared,
            memory: self.memory,
            indirect_table: self.indirect_table,
        })
    }
}

// TODO: revisit this
// The fields related to `wasmtime` do not implement `Send` because they use `std::rc::Rc`. `Rc`
// does not implement `Send` because incrementing/decrementing the reference counter from
// multiple threads simultaneously would be racy. It is however perfectly sound to move all the
// instances of `Rc`s at once between threads, which is what we're doing here.
//
// This importantly means that we should never return a `Rc` (even by reference) across the API
// boundary.
// TODO: really annoying to have to use unsafe code
unsafe impl Send for JitPrototype {}

impl fmt::Debug for JitPrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("JitPrototype").finish()
    }
}

/// Data shared between the external API and the functions that `wasmtime` directly invokes.
///
/// The flow is as follows:
///
/// - `wasmtime` calls a function that has access to a `Arc<Mutex<Shared>>`. The `Shared` is in
/// the [`Shared::OutsideFunctionCall`] state.
/// - This function stores its information (`function_index` and `parameters`) in the `Shared`
/// and returns `Poll::Pending`.
/// - This `Pending` gets propagated to the body of [`Jit::run`], which was calling `wasmtime`.
/// [`Jit::run`] reads `function_index` and `parameters` to determine what happened.
/// - Later, the return value is stored in `return_value`, and execution is resumed.
/// - The function called by `wasmtime` reads `return_value` and returns `Poll::Ready`.
///
enum Shared {
    Poisoned,
    BeforeFirstRun {
        memory_pointer: usize,
        memory_size: usize,
    },
    OutsideFunctionCall {
        memory: wasmtime::Memory,
    },
    EnteredFunctionCall {
        /// Index of the function currently being called.
        function_index: usize,

        memory_pointer: usize,
        memory_size: usize,

        /// Parameters of the function currently being called.
        parameters: Vec<WasmValue>,

        /// Waker that `wasmtime` has passed to the future that is waiting for `return_value`.
        /// This value is most likely not very useful, because [`Jit::run`] always polls the outer
        /// future whenever the inner future is known to be ready.
        /// However, it would be completely legal for `wasmtime` to not poll the inner future if the
        /// waker that it has passed (the one stored here) wasn't waken up.
        /// This field therefore exists in order to future-proof against this possible optimization
        /// that `wasmtime` might perform in the future.
        in_interrupted_waker: Option<Waker>,
    },
    WithinFunctionCall {
        memory_pointer: usize,
        memory_size: usize,

        /// Waker that `wasmtime` has passed to the future that is waiting for `return_value`.
        /// This value is most likely not very useful, because [`Jit::run`] always polls the outer
        /// future whenever the inner future is known to be ready.
        /// However, it would be completely legal for `wasmtime` to not poll the inner future if the
        /// waker that it has passed (the one stored here) wasn't waken up.
        /// This field therefore exists in order to future-proof against this possible optimization
        /// that `wasmtime` might perform in the future.
        in_interrupted_waker: Option<Waker>,
    },
    MemoryGrowRequired {
        memory: wasmtime::Memory,
        additional: u64,
    },
    Return {
        /// Value to return to the Wasm code.
        return_value: Option<WasmValue>,
        memory: wasmtime::Memory,
    },
}

/// See [`super::VirtualMachine`].
pub struct Jit {
    inner: JitInner,

    /// Instanciated Wasm VM.
    instance: wasmtime::Instance,

    /// Shared between the "outside" and the external functions. See [`Shared`].
    shared: Arc<Mutex<Shared>>,

    /// See [`JitPrototype::memory`].
    memory: Option<wasmtime::Memory>,

    /// See [`JitPrototype::indirect_table`].
    indirect_table: Option<wasmtime::Table>,
}

enum JitInner {
    /// `Future` that drives the execution. Contains an invocation of
    /// `wasmtime::Func::call_async`.
    Executing(
        future::LocalBoxFuture<'static, (wasmtime::Store<()>, Result<Option<WasmValue>, String>)>,
    ),
    /// Execution has finished and future has returned `Poll::Ready` in the past.
    Done(wasmtime::Store<()>),
}

impl Jit {
    /// See [`super::VirtualMachine::run`].
    pub fn run(&mut self, value: Option<WasmValue>) -> Result<ExecOutcome, RunErr> {
        let function_call = match &mut self.inner {
            JitInner::Executing(f) => f,
            JitInner::Done(_) => return Err(RunErr::Poisoned),
        };

        // TODO: check value type

        // Update `shared`
        {
            let mut shared_lock = self.shared.try_lock().unwrap();
            match mem::replace(&mut *shared_lock, Shared::Poisoned) {
                Shared::BeforeFirstRun { .. } => {
                    // TODO: check that value is None
                    *shared_lock = Shared::OutsideFunctionCall {
                        memory: self.memory.as_ref().unwrap().clone(), // TODO: unwrap()?!
                    };
                }
                Shared::WithinFunctionCall {
                    in_interrupted_waker,
                    ..
                } => {
                    *shared_lock = Shared::Return {
                        return_value: value,
                        memory: self.memory.as_ref().unwrap().clone(), // TODO: unwrap()?!
                    };

                    if let Some(waker) = in_interrupted_waker {
                        waker.wake();
                    }
                }
                _ => unreachable!(),
            }
        }

        // Resume the coroutine execution.
        // The `Future` is polled with a no-op waker. We are in total control of when the
        // execution might be able to progress, hence the lack of need for a waker.
        match Future::poll(
            function_call.as_mut(),
            &mut Context::from_waker(task::noop_waker_ref()),
        ) {
            Poll::Ready((store, Ok(val))) => {
                self.inner = JitInner::Done(store);
                Ok(ExecOutcome::Finished {
                    // Since we verify at initialization that the signature of the function to
                    // call is supported, it is guaranteed that the type of this return value is
                    // supported too.
                    return_value: Ok(val),
                })
            }
            Poll::Ready((store, Err(err))) => {
                self.inner = JitInner::Done(store);
                Ok(ExecOutcome::Finished {
                    return_value: Err(Trap(err)),
                })
            }
            Poll::Pending => {
                let mut shared_lock = self.shared.try_lock().unwrap();
                match mem::replace(&mut *shared_lock, Shared::Poisoned) {
                    Shared::EnteredFunctionCall {
                        function_index,
                        parameters,
                        memory_pointer,
                        memory_size,
                        in_interrupted_waker,
                    } => {
                        *shared_lock = Shared::WithinFunctionCall {
                            memory_pointer,
                            memory_size,
                            in_interrupted_waker,
                        };

                        Ok(ExecOutcome::Interrupted {
                            id: function_index,
                            params: parameters,
                        })
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    /// See [`super::VirtualMachine::memory_size`].
    pub fn memory_size(&self) -> HeapPages {
        let shared_lock = self.shared.try_lock().unwrap();
        match *shared_lock {
            Shared::BeforeFirstRun { memory_size, .. }
            | Shared::WithinFunctionCall { memory_size, .. } => {
                HeapPages::new(u32::try_from(memory_size).unwrap())
            }
            _ => unreachable!(),
        }
    }

    /// See [`super::VirtualMachine::read_memory`].
    pub fn read_memory(
        &'_ self,
        offset: u32,
        size: u32,
    ) -> Result<impl AsRef<[u8]> + '_, OutOfBoundsError> {
        let (memory_pointer, memory_size) = match *self.shared.try_lock().unwrap() {
            Shared::BeforeFirstRun {
                memory_pointer,
                memory_size,
            }
            | Shared::WithinFunctionCall {
                memory_pointer,
                memory_size,
                ..
            } => (memory_pointer, memory_size),
            _ => unreachable!(),
        };

        let start = usize::try_from(offset).map_err(|_| OutOfBoundsError)?;
        let end = start
            .checked_add(usize::try_from(size).map_err(|_| OutOfBoundsError)?)
            .ok_or(OutOfBoundsError)?;

        if end > memory_size {
            return Err(OutOfBoundsError);
        }

        unsafe {
            let memory_slice = slice::from_raw_parts(memory_pointer as *mut u8, memory_size);
            Ok(&memory_slice[start..end])
        }
    }

    /// See [`super::VirtualMachine::write_memory`].
    pub fn write_memory(&mut self, offset: u32, value: &[u8]) -> Result<(), OutOfBoundsError> {
        let shared_lock = self.shared.try_lock().unwrap();
        match *shared_lock {
            Shared::BeforeFirstRun {
                memory_pointer,
                memory_size,
            }
            | Shared::WithinFunctionCall {
                memory_pointer,
                memory_size,
                ..
            } => {
                let start = usize::try_from(offset).map_err(|_| OutOfBoundsError)?;
                let end = start.checked_add(value.len()).ok_or(OutOfBoundsError)?;

                if end > memory_size {
                    return Err(OutOfBoundsError);
                }

                if !value.is_empty() {
                    unsafe {
                        let memory_slice =
                            slice::from_raw_parts_mut(memory_pointer as *mut u8, memory_size);
                        memory_slice[start..end].copy_from_slice(value);
                    }
                }
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    /// See [`super::VirtualMachine::grow_memory`].
    pub fn grow_memory(&mut self, additional: HeapPages) -> Result<(), OutOfBoundsError> {
        // TODO: must check whether additional is within bounds

        let memory = match self.memory.as_ref() {
            Some(m) => m.clone(),
            None => return Err(OutOfBoundsError),
        };

        let mut shared_lock = self.shared.try_lock().unwrap();
        match mem::replace(&mut *shared_lock, Shared::Poisoned) {
            Shared::BeforeFirstRun { .. } => {
                todo!()
            }
            Shared::WithinFunctionCall { .. } => {
                *shared_lock = Shared::MemoryGrowRequired {
                    memory,
                    additional: u64::from(u32::from(additional)),
                }
            }
            _ => unreachable!(),
        }

        // TODO: must resume execution for the growth to happen /!\

        Ok(())
    }

    /// See [`super::VirtualMachine::into_prototype`].
    pub fn into_prototype(self) -> JitPrototype {
        let store = match self.inner {
            JitInner::Done(store) => store,
            JitInner::Executing(_) => todo!(), // TODO: how do we handle if the coroutine was within a host function?
        };

        // TODO: necessary?
        /*// Zero-ing the memory.
        if let Some(memory) = &self.memory {
            // Soundness: the documentation of wasmtime precisely explains what is safe or not.
            // Basically, we are safe as long as we are sure that we don't potentially grow the
            // buffer (which would invalidate the buffer pointer).
            unsafe {
                for byte in memory.data_mut() {
                    *byte = 0;
                }
            }
        }*/

        JitPrototype {
            store,
            instance: self.instance,
            shared: self.shared,
            memory: self.memory,
            indirect_table: self.indirect_table,
        }
    }
}

// The fields related to `wasmtime` do not implement `Send` because they use `std::rc::Rc`. `Rc`
// does not implement `Send` because incrementing/decrementing the reference counter from
// multiple threads simultaneously would be racy. It is however perfectly sound to move all the
// instances of `Rc`s at once between threads, which is what we're doing here.
//
// This importantly means that we should never return a `Rc` (even by reference) across the API
// boundary.
// TODO: really annoying to have to use unsafe code
unsafe impl Send for Jit {}

impl fmt::Debug for Jit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Jit").finish()
    }
}
