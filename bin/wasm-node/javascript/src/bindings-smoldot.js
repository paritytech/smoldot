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

//! Exports a function that provides bindings for the bindings found in the smoldot library
//! (i.e. the content of `src`).
//!
//! In order to use this code, call the function passing an object, then fill the `instance` field
//! of that object with the Wasm instance.
//!
//! Because it makes use of `Atomics.wait`, the code in this module must itself be run within a
//! worker.

import { Buffer } from 'buffer';
import { Worker, workerOnMessage, postMessage } from './compat-nodejs.js';
import Websocket from 'websocket';
import { default as now } from 'performance-now';

// Decodes a SCALE-compact-encoded integer.
//
// Returns an object of the form `{ offsetAfter: ..., value: ... }`.
const decodeScaleCompactInt = (memory, offset) => {
    const buffer = Buffer.from(memory);
    const firstByte = buffer.readUInt8(offset);
    if ((firstByte & 0b11) == 0b00) {
        return {
            offsetAfter: offset + 1,
            value: (firstByte >> 2)
        };
    } else if ((firstByte & 0b11) == 0b01) {
        const byte0 = (firstByte >> 2);
        const byte1 = buffer.readUInt8(offset + 1);
        return {
            offsetAfter: offset + 2,
            value: (byte1 << 6) | byte0
        };
    } else if ((firstByte & 0b11) == 0b10) {
        const byte0 = (firstByte >> 2);
        const byte1 = buffer.readUInt8(offset + 1);
        const byte2 = buffer.readUInt8(offset + 2);
        const byte3 = buffer.readUInt8(offset + 3);
        return {
            offsetAfter: offset + 4,
            value: (byte3 << 22) | (byte2 << 14) | (byte1 << 6) | byte0
        };
    } else {
        throw "unimplemented"; // TODO:
    }
}

// Decodes a SCALE-encoded `WasmValue`.
//
// Returns an object of the form `{ offsetAfter: ..., value: ... }`.
const decodeWasmValue = (memory, offset) => {
    const buffer = Buffer.from(memory);
    const ty = buffer.readUInt8(offset);
    if (ty == 0) {
        const value = buffer.readInt32LE(offset + 1);
        return {
            offsetAfter: offset + 5,
            value
        };
    } else {
        const value = buffer.readInt64LE(offset + 1);
        return {
            offsetAfter: offset + 9,
            value
        };
    }
};

// Decodes a SCALE-encoded `Vec<WasmValue>`. Returns the decoded value.
const decodeVecWasmValue = (memory, offset) => {
    const { offsetAfter, value: numElems } = decodeScaleCompactInt(memory, offset);

    let out = [];
    let currentOffset = offsetAfter;
    for (let i = 0; i < numElems; ++i) {
        const { offsetAfter, value } = decodeWasmValue(memory, currentOffset);
        currentOffset = offsetAfter;
        out.push(value);
    }

    return out;
};

export default (config) => {
    // 
    let wasmModules = {};
    let wasmInstances = {};

    let nextIdAlloc = 0;

    return {
        new_module: (module_ptr, module_size, numImportsOutPtr) => {
            const moduleBytes = Buffer.from(config.instance.exports.memory.buffer)
                .subarray(module_ptr, module_ptr + module_size);
            // TODO: consider making this async
            // TODO: must handle errors
            const compiledModule = new WebAssembly.Module(moduleBytes);
            const numImports = WebAssembly.Module.imports(compiledModule).length;
            Buffer.from(config.instance.exports.memory.buffer).writeUInt32LE(numImports, numImportsOutPtr);

            const id = nextIdAlloc;
            nextIdAlloc += 1;
            wasmModules[id] = compiledModule;
            return id;
        },
        module_import_is_fn: (moduleId, importNum) => {
            const kind = WebAssembly.Module.imports(wasmModules[moduleId])[importNum].kind;
            if (kind == 'function') {
                return 1;
            } else if (kind == 'memory') {
                return 0;
            } else {
                throw "Unknown kind: " + kind;
            }
        },
        module_import_module_len: (moduleId, importNum) => {
            const str = WebAssembly.Module.imports(wasmModules[moduleId])[importNum].module;
            return Buffer.byteLength(str, 'utf8');
        },
        module_import_module: (moduleId, importNum, outPtr) => {
            const str = WebAssembly.Module.imports(wasmModules[moduleId])[importNum].module;
            Buffer.from(config.instance.exports.memory.buffer).write(str, outPtr);
        },
        module_import_name_len: (moduleId, importNum) => {
            const str = WebAssembly.Module.imports(wasmModules[moduleId])[importNum].name;
            return Buffer.byteLength(str, 'utf8');
        },
        module_import_name: (moduleId, importNum, outPtr) => {
            const str = WebAssembly.Module.imports(wasmModules[moduleId])[importNum].name;
            Buffer.from(config.instance.exports.memory.buffer).write(str, outPtr);
        },
        destroy_module: (id) => {
            wasmModules[id] = undefined;
        },
        new_instance: (moduleId, importsPtr) => {
            const requestedImports = WebAssembly.Module.imports(wasmModules[moduleId])
                .map((_, i) => Buffer.from(config.instance.exports.memory.buffer)
                    .readUInt32LE(importsPtr + 4 * i));

            // A `SharedArrayBuffer` is shared between this module and the worker, used to
            // communicate between the two.
            //
            // The first four bytes are used to determine who has ownership of the content of the
            // buffer. If 0, then it's this module. If 1, then it's the worker. Each side reads
            // the content of the buffer, then writes it, then switches the first four bytes and
            // uses `Atomics.notify` to wake up the other side.
            const communicationsSab = new SharedArrayBuffer(512);

            const id = nextIdAlloc;
            nextIdAlloc += 1;

            // TODO: don't assume postMessage
            postMessage({
                kind: 'spawn-vm-worker',
                data: {
                    id,
                    workerMessage: {
                        module: wasmModules[moduleId],
                        requestedImports,
                        communicationsSab,
                    }
                }
            });

            wasmInstances[id] = {
                communicationsSab: Buffer.from(communicationsSab),
                int32Array: new Int32Array(communicationsSab)
            };
            return id;
        },
        instance_init: (instanceId, functionNamePtr, functionNameSize, paramsPtr, paramsSize) => {
            const functionName = Buffer.from(config.instance.exports.memory.buffer)
                .toString('utf8', functionNamePtr, functionNamePtr + functionNameSize);
            const params = decodeVecWasmValue(config.instance.exports.memory.buffer, paramsPtr);
            // TODO: don't assume postMessage
            postMessage({
                kind: 'send-vm-worker',
                data: {
                    id: instanceId,
                    message: { functionName, params }
                }
            });

            const instance = wasmInstances[instanceId];
            instance.int32Array[0] = 1;
            Atomics.wait(instance.int32Array, 0, 1);

            return instance.communicationsSab.readUInt8(4);
        },
        instance_resume: (instanceId, returnValuePtr, returnValueSize, outPtr, outSize) => {
            const instance = wasmInstances[instanceId];
            const selfMemory = Buffer.from(config.instance.exports.memory.buffer);

            // Write the return value to the shared array.
            selfMemory.copy(instance.communicationsSab, 4, returnValuePtr, returnValuePtr + returnValueSize);
            instance.int32Array[0] = 1;

            // Wait for the child Wasm to execute.
            Atomics.notify(instance.int32Array, 0);
            Atomics.wait(instance.int32Array, 0, 1);

            // As a response, the child worker answers with the SCALE-encoded output to copy back
            // to `outPtr`/`outSize`.
            const outCopySize = (instance.communicationsSab.length - 4) > outSize ?
                outSize : (instance.communicationsSab.length - 4);
            instance.communicationsSab.copy(selfMemory, outPtr, 4, 4 + outCopySize);
        },
        destroy_instance: (instanceId) => {
            wasmInstances[instanceId].worker.terminate();
            wasmInstances[instanceId] = undefined;
        },
        global_value: (instanceId, name_ptr, name_size, out) => {
            const name = Buffer.from(config.instance.exports.memory.buffer)
                .toString('utf8', name_ptr, name_ptr + name_size);
            // TODO: wasmInstances[instanceId].exports[name]
        },
        memory_size: (instanceId) => {
            // TODO:
        },
        read_memory: (instanceId, offset, size, outPtr) => {
            // TODO:
        },
        write_memory: (instanceId, offset, size, dataPtr) => {
            // TODO:
        }
    };
}
