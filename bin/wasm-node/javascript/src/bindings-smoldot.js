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

// Encodes a number in its SCALE-compact encoding.
//
// Returns an object of the form `{ offsetAfter: ... }`.
const encodeScaleCompactUsize = (value, bufferOut, bufferOutOffset) => {
    if (value < 64) {
        bufferOut.writeUInt8(value << 2, bufferOutOffset);
        return { offsetAfter: bufferOutOffset + 1 };

    } else if (value < (1 << 14)) {
        bufferOut.writeUInt8(((value & 0b111111) << 2) | 0b01, bufferOutOffset);
        bufferOut.writeUInt8((value >> 6) & 0xff, bufferOutOffset + 2);
        return { offsetAfter: bufferOutOffset + 1 };

    } else if (value < (1 << 30)) {
        bufferOut.writeUInt8(((value & 0b111111) << 2) | 0b10, bufferOutOffset);
        bufferOut.writeUInt8((value >> 6) & 0xff, bufferOutOffset + 1);
        bufferOut.writeUInt8((value >> 14) & 0xff, bufferOutOffset + 2);
        bufferOut.writeUInt8((value >> 22) & 0xff, bufferOutOffset + 3);
        return { offsetAfter: bufferOutOffset + 4 };

    } else {
        let off = 1;
        while (value != 0) {
            bufferOut.writeUInt8(value & 0xff, bufferOutOffset + off);
            off += 1;
            value >>= 8;
        }
        bufferOut.writeUInt8(((off - 1 - 4) << 2) | 0b11, bufferOutOffset);
    }
};

export default (config) => {
    // 
    let wasmModules = {};
    let wasmInstances = {};

    let nextIdAlloc = 0;

    return {
        new_module: (module_ptr, module_size, idOut, numImportsOutPtr) => {
            const moduleBytes = Buffer.from(config.instance.exports.memory.buffer)
                .subarray(module_ptr, module_ptr + module_size);
            let compiledModule;
            try {
                compiledModule = new WebAssembly.Module(moduleBytes);
            } catch (error) {
                return 1;
            }
            const numImports = WebAssembly.Module.imports(compiledModule).length;
            Buffer.from(config.instance.exports.memory.buffer).writeUInt32LE(numImports, numImportsOutPtr);

            const id = nextIdAlloc;
            Buffer.from(config.instance.exports.memory.buffer).writeUInt32LE(id, idOut);
            nextIdAlloc += 1;
            wasmModules[id] = compiledModule;
            return 0;
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

        new_instance: (moduleId, importsPtr, idOut) => {
            // A `SharedArrayBuffer` is shared between this module and the worker, used to
            // communicate between the two.
            // See the documentation of the worker for more information.
            // The size of the buffer is arbitrary. Notably, memory transfers (reading and
            // writing memory) are notably done through this buffer, and if it is too small, these
            // transfers require multiple iterations.
            const communicationsSab = new SharedArrayBuffer(1024);
            const communicationsSabBuffer = Buffer.from(communicationsSab);
            const int32Array = new Int32Array(communicationsSab);
            int32Array[0] = 1;
            int32Array[1] = 0xdeadbeef; // Garbage data to make sure everything is correctly overwritten.

            // Assign the identifier for this instance.
            // Note that this `id` might not end up being used if initialization fails below.
            const id = nextIdAlloc;
            nextIdAlloc += 1;

            // Ask the parent to spawn a worker with the given parameters.
            config.startVmWorker(id, {
                module: wasmModules[moduleId],
                requestedImports: WebAssembly.Module.imports(wasmModules[moduleId])
                    .map((_, i) => Buffer.from(config.instance.exports.memory.buffer)
                        .readUInt32LE(importsPtr + 4 * i)),
                communicationsSab,
            });

            // Wait for the worker to have spawned and send us an `InitializationResult` message
            // back.
            Atomics.wait(int32Array, 0, 1);
            if (communicationsSabBuffer.readUInt8(4) != 0)
                throw 'State mismatch: expected InitializationResult';

            // Analyze this `InitializationResult` message.
            const retCode = communicationsSabBuffer.readUInt8(5);
            if (retCode == 0) {
                // Initialization successful.
                Buffer.from(config.instance.exports.memory.buffer).writeUInt32LE(id, idOut);
                wasmInstances[id] = {
                    communicationsSab: communicationsSabBuffer,
                    int32Array,
                };
            } else {
                config.terminateVmWorker(id);
            }
            return retCode;
        },

        instance_init: (instanceId, infoPtr, infoSize) => {
            const instance = wasmInstances[instanceId];

            // Send a `StartFunction` message to the worker.
            instance.communicationsSab.writeUInt8(1, 4);  // `StartFunction`
            // The buffer in `infoPtr`/`infoSize` matches (intentionally) the body of the
            // `StartFunction` message.
            Buffer.from(config.instance.exports.memory.buffer)
                .copy(instance.communicationsSab, 5, infoPtr, infoPtr + infoSize);

            // Wait for the child Wasm to execute.
            instance.int32Array[0] = 1;
            Atomics.notify(instance.int32Array, 0);
            Atomics.wait(instance.int32Array, 0, 1);

            // The value in the `StartResult` matches what `instance_init` returns.
            if (instance.communicationsSab.readUInt8(4) != 2)
                throw 'State mismatch: expected StartResult';
            return instance.communicationsSab.readUInt8(5);
        },

        instance_resume: (instanceId, returnValuePtr, returnValueSize, outPtr, outSize) => {
            const instance = wasmInstances[instanceId];
            const selfMemory = Buffer.from(config.instance.exports.memory.buffer);

            // Write the return value to the shared array.
            instance.communicationsSab.writeUInt8(5, 4);  // `Resume`
            selfMemory.copy(instance.communicationsSab, 5, returnValuePtr, returnValuePtr + returnValueSize);

            // Wait for the child Wasm to execute.
            instance.int32Array[0] = 1;
            Atomics.notify(instance.int32Array, 0);
            Atomics.wait(instance.int32Array, 0, 1);

            // Make sure to not go beyond `outSize`.
            // TODO: we're copying too much data here
            const outCopySize = (instance.communicationsSab.length - 4) > outSize ?
                outSize : (instance.communicationsSab.length - 4);
            const retMessageTy = instance.communicationsSab.readUInt8(4);
            if (retMessageTy == 3) { // Finished
                selfMemory.writeUInt8(0, outPtr);
            } else if (retMessageTy == 4) { // Interrupted
                selfMemory.writeUInt8(1, outPtr);
            } else {
                throw 'Expected Interrupted or Finished';
            }
            instance.communicationsSab.copy(selfMemory, outPtr + 1, 5, 5 + outCopySize);
        },

        destroy_instance: (instanceId) => {
            config.terminateVmWorker(instanceId);
            wasmInstances[instanceId] = undefined;
        },

        global_value: (instanceId, namePtr, nameSize, outPtr) => {
            const instance = wasmInstances[instanceId];
            const selfMemory = Buffer.from(config.instance.exports.memory.buffer);

            // Write the message destined to the worker.
            instance.communicationsSab.writeUInt8(12, 4);  // `GetGlobal`
            // Note that `namePtr`/`nameSize` already include the SCALE-compact length of the name.
            selfMemory.copy(instance.communicationsSab, 5, namePtr, namePtr + nameSize);

            // Wait for the child Wasm to execute.
            instance.int32Array[0] = 1;
            Atomics.notify(instance.int32Array, 0);
            Atomics.wait(instance.int32Array, 0, 1);

            const retMessageTy = instance.communicationsSab.readUInt8(4);
            if (retMessageTy == 13) {
                const globalValue = instance.communicationsSab.readUInt32LE(5);
                selfMemory.writeUint32LE(globalValue, outPtr);
                return 0;
            } else if (retMessageTy == 14) {
                return instance.communicationsSab.readUInt8(5);
            } else {
                throw 'Expected GetGlobalOk or GetGlobalErr';
            }
        },

        memory_size: (instanceId) => {
            const instance = wasmInstances[instanceId];
            instance.communicationsSab.writeUInt8(10, 4);  // `MemorySize`

            // Wait for the child Wasm to execute.
            instance.int32Array[0] = 1;
            Atomics.notify(instance.int32Array, 0);
            Atomics.wait(instance.int32Array, 0, 1);

            if (instance.communicationsSab.readUInt8(4) != 11)
                throw 'Expected MemorySizeResult';
            return instance.communicationsSab.readUInt32LE(5);
        },

        read_memory: (instanceId, offset, size, outPtr) => {
            const instance = wasmInstances[instanceId];
            const selfMemory = Buffer.from(config.instance.exports.memory.buffer);

            // Because the size of `communicationsSab` might be too small to fit the entire
            // data, we need to cap the write to a certain limit.
            const sizeLimit = instance.communicationsSab.byteLength - 9;

            while (size > 0) {
                const sizeIter = size > sizeLimit ? sizeLimit : size;

                instance.communicationsSab.writeUInt8(8, 4);  // `ReadMemory`
                instance.communicationsSab.writeUInt32LE(offset, 5);
                instance.communicationsSab.writeUInt32LE(sizeIter, 9);

                // Wait for the child Wasm to execute.
                instance.int32Array[0] = 1;
                Atomics.notify(instance.int32Array, 0);
                Atomics.wait(instance.int32Array, 0, 1);

                if (instance.communicationsSab.readUInt8(4) != 9)
                    throw 'Expected ReadMemoryResult';

                instance.communicationsSab.copy(selfMemory, outPtr, 5, 5 + sizeIter);

                size -= sizeIter;
                outPtr += sizeIter;
                offset += sizeIter;
            }
        },

        write_memory: (instanceId, offset, size, dataPtr) => {
            const instance = wasmInstances[instanceId];
            const selfMemory = Buffer.from(config.instance.exports.memory.buffer);

            // Because the size of `communicationsSab` might be too small to fit the entire
            // data, we need to cap the write to a certain limit.
            const sizeLimit = instance.communicationsSab.byteLength - 11;

            while (size > 0) {
                const sizeIter = size > sizeLimit ? sizeLimit : size;

                instance.communicationsSab.writeUInt8(6, 4);  // `WriteMemory`
                instance.communicationsSab.writeUInt32LE(offset, 5);
                const { offsetAfter } = encodeScaleCompactUsize(sizeIter, instance.communicationsSab, 9);
                selfMemory.copy(instance.communicationsSab, offsetAfter, dataPtr, dataPtr + sizeIter);

                // Wait for the child Wasm to execute.
                instance.int32Array[0] = 1;
                Atomics.notify(instance.int32Array, 0);
                Atomics.wait(instance.int32Array, 0, 1);

                if (instance.communicationsSab.readUInt8(4) != 7)
                    throw 'Expected WriteMemoryOk';

                size -= sizeIter;
                dataPtr += sizeIter;
                offset += sizeIter;
            }
        }
    };
}
