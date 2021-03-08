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

//! Implements the API documented [in the parent module](..).

use super::{
    ExecOutcome, GlobalValueErr, HeapPages, ModuleError, NewErr, OutOfBoundsError, RunErr,
    Signature, StartErr, Trap, ValueType, WasmValue,
};

use alloc::{
    borrow::ToOwned as _,
    boxed::Box,
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec::Vec,
};
use core::{
    cell::RefCell,
    convert::{TryFrom, TryInto as _},
    fmt,
};

/// This module uses external functions that the environment (i.e. browser or NodeJS) must
/// implement.
///
/// This functions ressemble the functions of the `WebAssembly` w3c specifications.
/// See <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/WebAssembly>.
/// However, due notably to the requirement that Wasm functions execution be asynchronous, there
/// exists some significant differences. Make sure to carefully read the documentation.
// TODO: properly document functions
#[link(wasm_import_module = "javascript_wasm_vm")]
extern "C" {
    fn new_module(module_ptr: *const u8, module_size: usize, num_imports: *mut u32) -> i32;

    /// Returns 1 if the `import_num`th import of the module identified by `module_id` is a
    /// function. Returns 0 if it is a memory.
    fn module_import_is_fn(module_id: i32, import_num: u32) -> i32;

    /// Returns the length of the name in bytes of the name of the module of the import
    /// represented by `module_id` and `import_num`.
    fn module_import_module_len(module_id: i32, import_num: u32) -> i32;

    /// Writes in `out` the name in bytes of the name of the module of the import represented by
    /// `module_id` and `import_num`.
    fn module_import_module(module_id: i32, import_num: u32, out: *mut u8);

    /// Returns the length of the name in bytes of the name of the import represented by
    /// `module_id` and `import_num`.
    fn module_import_name_len(module_id: i32, import_num: u32) -> i32;

    /// Writes in `out` the name in bytes of the name of the import represented by `module_id` and
    /// `import_num`.
    fn module_import_name(module_id: i32, import_num: u32, out: *mut u8);

    /// Permits freeing the memory associated with the given module. The passed `module_id` is no
    /// longer considered valid.
    ///
    /// > **Note**: This doesn't mean that the module must be destroyed now, only that we will no
    /// >           longer reference it. It is likely for this function to be called while there
    /// >           is one or more instances using that module.
    fn destroy_module(module_id: i32);

    fn new_instance(module_id: i32, imports_ptr: *const u32) -> i32;

    fn instance_push_i32(instance_id: i32, value: i32);

    fn instance_push_i64(instance_id: i32, value: i64);

    fn instance_start(instance_id: i32, function_name_ptr: *const u8, function_name_size: usize);

    fn instance_resume(instance_id: i32);

    fn destroy_instance(instance_id: i32);

    /// Fetch from the given instance the value of the export whose name is passed as parameter.
    /// The export must be of type `i32`.
    ///
    /// The export name is a UTF-8 string found in the memory at offset `name_ptr` and with
    /// length `name_size`.
    ///
    /// Must return 0 to indicate success. The value of the global must have been written at the
    /// address designated by `out`.
    /// Must return 1 if the export wasn't found. Must return 2 if the export isn't a global
    /// value of type `i32`.
    fn global_value(instance_id: i32, name_ptr: *const u8, name_size: usize, out: *mut u32) -> i32;

    /// Must return the current size of the memory in bytes of the given instance.
    fn memory_size(instance_id: i32) -> u32;

    /// Must read `size` bytes from the memory of the instance starting at `offset` and write
    /// them to `out`.
    fn read_memory(instance_id: i32, offset: u32, size: u32, out: *mut u8);

    /// Must write `size` bytes into the memory of the instance starting at `offset`. The data
    /// can be found in `data`.
    fn write_memory(instance_id: i32, offset: u32, size: u32, data: *const u8);
}

/// See [`super::Module`].
#[derive(Clone)]
pub struct Module {
    /// The value returned by the environment when creating the module.
    external_identifier: i32,
    /// Number of imports made by the module.
    num_imports: u32,
}

impl Module {
    /// See [`super::Module::new`].
    pub fn new(module_bytes: impl AsRef<[u8]>) -> Result<Self, NewErr> {
        let module_bytes = module_bytes.as_ref();

        let mut num_imports = 0u32;
        let external_identifier =
            unsafe { new_module(module_bytes.as_ptr(), module_bytes.len(), &mut num_imports) };

        Ok(Module {
            external_identifier,
            num_imports,
        })
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        unsafe {
            destroy_module(self.external_identifier);
        }
    }
}

/// See [`super::VirtualMachinePrototype`].
pub struct JsVmPrototype {
    // The value returned by the environment when creating the instance.
    external_identifier: InstanceRaii,
}

impl JsVmPrototype {
    /// See [`super::VirtualMachinePrototype::new`].
    pub fn new(
        module: &Module,
        heap_pages: HeapPages,
        mut symbols: impl FnMut(&str, &str) -> Result<usize, ()>,
    ) -> Result<Self, NewErr> {
        let mut imports = Vec::with_capacity(usize::try_from(module.num_imports).unwrap());

        for import_num in 0..module.num_imports {
            let module_name = unsafe {
                let len = usize::try_from(module_import_module_len(
                    module.external_identifier,
                    import_num,
                ))
                .unwrap();
                let mut out = Vec::<u8>::with_capacity(len);
                module_import_module(
                    module.external_identifier,
                    import_num,
                    out.as_mut_ptr() as *mut u8,
                );
                out.set_len(len);
                String::from_utf8(out).unwrap()
            };

            let name = unsafe {
                let len = usize::try_from(module_import_name_len(
                    module.external_identifier,
                    import_num,
                ))
                .unwrap();
                let mut out = Vec::<u8>::with_capacity(len);
                module_import_name(
                    module.external_identifier,
                    import_num,
                    out.as_mut_ptr() as *mut u8,
                );
                out.set_len(len);
                String::from_utf8(out).unwrap()
            };

            let is_function =
                unsafe { module_import_is_fn(module.external_identifier, import_num) != 0 };

            if is_function {
                let index = match symbols(&module_name, &name) {
                    Ok(i) => i,
                    Err(_) => {
                        return Err(NewErr::ModuleError(ModuleError(format!(
                            "Couldn't resolve `{}`:`{}`",
                            module_name, name
                        ))))
                    }
                };

                imports.push(u32::try_from(index).unwrap());
            } else {
                imports.push(heap_pages.0);
            }
        }

        let external_identifier =
            InstanceRaii(unsafe { new_instance(module.external_identifier, imports.as_ptr()) });

        Ok(JsVmPrototype {
            external_identifier,
        })
    }

    /// See [`super::VirtualMachinePrototype::global_value`].
    pub fn global_value(&self, name: &str) -> Result<u32, GlobalValueErr> {
        unsafe {
            let mut out = 0u32;
            let ret = global_value(
                self.external_identifier.0,
                name.as_bytes().as_ptr(),
                name.as_bytes().len(),
                &mut out as *mut u32,
            );

            if ret == 0 {
                Ok(out)
            } else if ret == 1 {
                Err(GlobalValueErr::NotFound)
            } else if ret == 2 {
                Err(GlobalValueErr::Invalid)
            } else {
                unreachable!()
            }
        }
    }

    /// See [`super::VirtualMachinePrototype::start`].
    pub fn start(
        self,
        function_name: &str,
        params: &[WasmValue],
    ) -> Result<JsVm, (StartErr, Self)> {
        unsafe {
            for param in params {
                match *param {
                    WasmValue::I32(value) => instance_push_i32(self.external_identifier.0, value),
                    WasmValue::I64(value) => instance_push_i64(self.external_identifier.0, value),
                }
            }

            // TODO: error handling
            instance_start(
                self.external_identifier.0,
                function_name.as_bytes().as_ptr(),
                function_name.as_bytes().len(),
            );
        }

        Ok(JsVm {
            external_identifier: self.external_identifier,
        })
    }
}

impl fmt::Debug for JsVmPrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("JsVmPrototype").finish()
    }
}

/// See [`super::VirtualMachine`].
pub struct JsVm {
    // The value returned by the environment when creating the instance.
    external_identifier: InstanceRaii,
}

impl JsVm {
    /// See [`super::VirtualMachine::run`].
    pub fn run(&mut self, value: Option<WasmValue>) -> Result<ExecOutcome, RunErr> {
        unsafe {
            match value {
                Some(WasmValue::I32(value)) => instance_push_i32(self.external_identifier.0, value),
                Some(WasmValue::I64(value)) => instance_push_i64(self.external_identifier.0, value),
                None => {}
            }

            instance_resume(self.external_identifier.0);

            todo!()
        }
    }

    /// See [`super::VirtualMachine::memory_size`].
    pub fn memory_size(&self) -> u32 {
        // Because the child Wasm instance is free to resize its memory while it is executing,
        // we need to re-query it every single time.
        unsafe { memory_size(self.external_identifier.0) }
    }

    /// See [`super::VirtualMachine::read_memory`].
    pub fn read_memory(
        &'_ self,
        offset: u32,
        size: u32,
    ) -> Result<impl AsRef<[u8]> + '_, OutOfBoundsError> {
        if offset + size > self.memory_size() {
            return Err(OutOfBoundsError);
        }

        unsafe {
            let mut out = Vec::<u8>::with_capacity(usize::try_from(size).unwrap());
            read_memory(self.external_identifier.0, offset, size, out.as_mut_ptr());
            out.set_len(usize::try_from(size).unwrap());
            Ok(out)
        }
    }

    /// See [`super::VirtualMachine::write_memory`].
    pub fn write_memory(&mut self, offset: u32, value: &[u8]) -> Result<(), OutOfBoundsError> {
        let value_len = u32::try_from(value.len()).unwrap();
        if offset + value_len > self.memory_size() {
            return Err(OutOfBoundsError);
        }

        unsafe {
            write_memory(
                self.external_identifier.0,
                offset,
                value_len,
                value.as_ptr(),
            );
        }

        Ok(())
    }

    /// See [`super::VirtualMachine::into_prototype`].
    pub fn into_prototype(self) -> JsVmPrototype {
        // TODO: interrupt the current execution?
        // TODO: zero the memory

        JsVmPrototype {
            external_identifier: self.external_identifier,
        }
    }
}

impl fmt::Debug for JsVm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("JsVm").finish()
    }
}

struct InstanceRaii(i32);

impl Drop for InstanceRaii {
    fn drop(&mut self) {
        unsafe {
            destroy_instance(self.0);
        }
    }
}
