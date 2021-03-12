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
    vec,
    vec::Vec,
};
use core::{
    cell::RefCell,
    convert::{TryFrom, TryInto as _},
    fmt, str,
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
    /// Parses the Wasm byte code found in the buffer represented by `module_ptr` and
    /// `module_size`.
    ///
    /// On success, must return 0 and write in `id_out` a "module id" (used in all the other
    /// module-related functions of these bindings) and in `num_imports` the number of elements
    /// that the Wasm module needs to import from the environment. These imports will later be
    /// queried with [`module_import_is_fn`], [`module_import_module_len`],
    /// [`module_import_module`], [`module_import_name_len`] and [`module_import_name`].
    ///
    /// On error, must return non-zero.
    fn new_module(
        module_ptr: *const u8,
        module_size: usize,
        id_out: *mut i32,
        num_imports: *mut u32,
    ) -> i32;

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

    /// Initializes a new instance from the given module.
    ///
    /// The list of imports is found in a buffer represented by `imports_ptr`. The size of the
    /// buffer is always `4 * num_imports`.
    ///
    /// On success, must return 0 and write in `id_out` an "instance id" (used in all the other
    /// instance-related functions of these bindings).
    ///
    /// On error, must return non-zero.
    fn new_instance(module_id: i32, imports_ptr: *const u32, id_out: *mut i32) -> i32;

    /// The given instance must be configured to start executing the given function.
    ///
    /// The content of the buffer designated by `params_ptr` and `params_size` contains the SCALE
    /// encoding of a `Vec<WasmValue>`, where `WasmValue` is defined like this:
    ///
    /// ```no_run
    /// enum WasmValue {
    ///     I32(i32),
    ///     I64(i64),
    /// }
    /// ```
    ///
    /// No actual execution should take place until [`instance_resume`] is called.
    ///
    /// If the instance was executing another function, the execution must be interrupted.
    ///
    /// The returned value should be:
    ///
    /// - 0 on success.
    /// - 1 if the function doesn't exist.
    /// - 2 if the requested function isn't actually a function.
    /// - 3 if the signature of the function doesn't match the parameters.
    ///
    fn instance_init(
        instance_id: i32,
        function_name_ptr: *const u8,
        function_name_size: usize,
        params_ptr: *const u8,
        params_size: usize,
    ) -> i32;

    /// Must execute the given instance until something happens (a host function is called, or the
    /// function being called finishes executing), then return.
    ///
    /// This function is always called after [`instance_init`]. If this is the first time
    /// [`instance_resume`] is called after [`instance_init`], then the `return_value_ptr` and
    /// `return_value_size` parameters should be ignored. If the instance has been interrupted by
    /// a host function call, they designate a buffer that contains the return value of the host
    /// function.
    ///
    /// The content of the buffer designated by `return_value_ptr` and `return_value_size`
    /// contains the SCALE encoding of an `Option<WasmValue>`. See [`instance_init`] for a
    /// definition of `WasmValue`.
    ///
    /// Must write in the buffer designated by `out_ptr` and `out_size` the SCALE encoding of the
    /// `Ret` enum defined as such:
    ///
    /// ```no_run
    /// enum Ret {
    ///     Finished {
    ///         return_value: Result<Option<WasmValue>, String>,
    ///     },
    ///     Interrupted {
    ///         id: u32,
    ///         params: Vec<WasmValue>,
    ///     },
    /// }
    /// ```
    fn instance_resume(
        instance_id: i32,
        return_value_ptr: *const u8,
        return_value_size: usize,
        out_ptr: *mut u8,
        out_size: usize,
    );

    /// Permits freeing the memory associated with the given instance. The passed `instance_id` is
    /// no longer considered valid.
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
    ///
    /// > **Note**: This can be called while an instance has been interrupted by a host
    /// >           function call.
    fn read_memory(instance_id: i32, offset: u32, size: u32, out: *mut u8);

    /// Must write `size` bytes into the memory of the instance starting at `offset`. The data
    /// can be found in `data`.
    ///
    /// > **Note**: This can be called while an instance has been interrupted by a host
    /// >           function call.
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

        let mut external_identifier = 0i32;
        let mut num_imports = 0u32;
        let ret_code = unsafe {
            new_module(
                module_bytes.as_ptr(),
                module_bytes.len(),
                &mut external_identifier,
                &mut num_imports,
            )
        };

        match ret_code {
            0 => Ok(Module {
                external_identifier,
                num_imports,
            }),
            _ => Err(NewErr::ModuleError(ModuleError("<unknown>".to_string()))),
        }
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

        let mut external_identifier = 0;
        let ret_code = unsafe {
            new_instance(
                module.external_identifier,
                imports.as_ptr(),
                &mut external_identifier,
            )
        };

        match ret_code {
            0 => Ok(JsVmPrototype {
                external_identifier: InstanceRaii(external_identifier),
            }),
            _ => Err(NewErr::ModuleError(ModuleError("<unknown>".to_string()))),
        }
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
            let mut params_buffer = Vec::with_capacity(params.len() * 9 + 2);
            params_buffer
                .extend_from_slice(crate::util::encode_scale_compact_usize(params.len()).as_ref());

            for param in params {
                match *param {
                    WasmValue::I32(value) => {
                        params_buffer.push(0);
                        params_buffer.extend_from_slice(&value.to_le_bytes());
                    }
                    WasmValue::I64(value) => {
                        params_buffer.push(1);
                        params_buffer.extend_from_slice(&value.to_le_bytes());
                    }
                }
            }

            let ret_code = instance_init(
                self.external_identifier.0,
                function_name.as_bytes().as_ptr(),
                function_name.as_bytes().len(),
                params_buffer.as_ptr(),
                params_buffer.len(),
            );

            match ret_code {
                0 => Ok(JsVm {
                    external_identifier: self.external_identifier,
                    // TODO: don't zero
                    // TODO: put in JsVmPrototype too
                    instance_resume_buffer: vec![0; 1024],
                }),
                1 => return Err((StartErr::FunctionNotFound, self)),
                2 => return Err((StartErr::NotAFunction, self)),
                3 => return Err((StartErr::SignatureNotSupported, self)),
                _ => panic!(),
            }
        }
    }
}

impl fmt::Debug for JsVmPrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("JsVmPrototype").finish()
    }
}

/// See [`super::VirtualMachine`].
pub struct JsVm {
    /// The value returned by the environment when creating the instance.
    external_identifier: InstanceRaii,
    /// Buffer written by [`instance_resume`]. In this struct in order to be re-used across
    /// invocations.
    instance_resume_buffer: Vec<u8>,
}

impl JsVm {
    /// See [`super::VirtualMachine::run`].
    pub fn run(&mut self, value: Option<WasmValue>) -> Result<ExecOutcome, RunErr> {
        unsafe {
            let mut ret_val_buffer = Vec::with_capacity(10);
            match value {
                None => {
                    ret_val_buffer.push(0);
                }
                Some(WasmValue::I32(value)) => {
                    ret_val_buffer.push(1);
                    ret_val_buffer.push(0);
                    ret_val_buffer.extend_from_slice(&value.to_le_bytes());
                }
                Some(WasmValue::I64(value)) => {
                    ret_val_buffer.push(1);
                    ret_val_buffer.push(1);
                    ret_val_buffer.extend_from_slice(&value.to_le_bytes());
                }
            }

            instance_resume(
                self.external_identifier.0,
                ret_val_buffer.as_ptr(),
                ret_val_buffer.len(),
                self.instance_resume_buffer.as_mut_ptr(),
                self.instance_resume_buffer.len(),
            );

            // Decode the value written by the outside.
            let mut parser = nom::branch::alt((
                nom::combinator::map(
                    nom::sequence::preceded(
                        nom::bytes::complete::tag(&[0]),
                        crate::util::nom_result_decode(
                            crate::util::nom_option_decode(nom::branch::alt((
                                nom::combinator::map(
                                    nom::sequence::preceded(
                                        nom::bytes::complete::tag(&[0]),
                                        nom::number::complete::le_i32,
                                    ),
                                    WasmValue::I32,
                                ),
                                nom::combinator::map(
                                    nom::sequence::preceded(
                                        nom::bytes::complete::tag(&[1]),
                                        nom::number::complete::le_i64,
                                    ),
                                    WasmValue::I64,
                                ),
                            ))),
                            nom::combinator::map(
                                nom::combinator::map_res(
                                    nom::multi::length_data(crate::util::nom_scale_compact_usize),
                                    str::from_utf8,
                                ),
                                |msg| Trap(msg.to_owned()),
                            ),
                        ),
                    ),
                    |return_value| ExecOutcome::Finished { return_value },
                ),
                nom::combinator::map(
                    nom::sequence::preceded(
                        nom::bytes::complete::tag(&[1]),
                        nom::sequence::tuple((
                            nom::number::complete::le_u32,
                            nom::combinator::flat_map(
                                crate::util::nom_scale_compact_usize,
                                |num_elems| {
                                    nom::multi::many_m_n(
                                        num_elems,
                                        num_elems,
                                        nom::branch::alt((
                                            nom::combinator::map(
                                                nom::sequence::preceded(
                                                    nom::bytes::complete::tag(&[0]),
                                                    nom::number::complete::le_i32,
                                                ),
                                                WasmValue::I32,
                                            ),
                                            nom::combinator::map(
                                                nom::sequence::preceded(
                                                    nom::bytes::complete::tag(&[1]),
                                                    nom::number::complete::le_i64,
                                                ),
                                                WasmValue::I64,
                                            ),
                                        )),
                                    )
                                },
                            ),
                        )),
                    ),
                    |(id, params)| ExecOutcome::Interrupted {
                        id: usize::try_from(id).unwrap(),
                        params,
                    },
                ),
            ));

            let result: Result<_, nom::Err<nom::error::Error<&[u8]>>> =
                parser(&self.instance_resume_buffer);
            match result {
                Ok((_, out)) => Ok(out),
                Err(_) => panic!(),
            }
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
