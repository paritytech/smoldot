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

import { Buffer } from 'buffer';
import { Worker, workerOnMessage } from './compat-nodejs.js';
import Websocket from 'websocket';
import { default as now } from 'performance-now';
import { net } from './compat-nodejs.js';

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

            // The actual execution of Smoldot is performed in a worker thread.
            //
            // The line of code below (`new Worker(...)`) is designed to hopefully work across all
            // platforms. It should work in NodeJS, browsers, webpack
            // (https://webpack.js.org/guides/web-workers/), and parcel
            // (https://github.com/parcel-bundler/parcel/pull/5846)
            const worker = new Worker(new URL('./bindings-smoldot-worker.js', import.meta.url));
            const returnValueSharedArrayBuffer = new SharedArrayBuffer(512);

            const id = nextIdAlloc;
            nextIdAlloc += 1;
            wasmInstances[id] = {
                returnValueSharedArrayBuffer: new Int32Array(returnValueSharedArrayBuffer),
                valuesStack: [],
                worker: worker
            };

            worker.onmessage = (messageFromWorker) => {

            };

            worker.postMessage({
                module: WebAssembly.Module.imports(wasmModules[moduleId]),
                requestedImports: requestedImports,
                returnValueSharedArrayBuffer: returnValueSharedArrayBuffer,
            });

            return id;
        },
        instance_push_i32: (instanceId, value) => {
            wasmInstances[instanceId].valuesStack.push(value);
        },
        instance_push_i64: (instanceId, value) => {
            console.log(value);
            wasmInstances[instanceId].valuesStack.push(value);
        },
        instance_start: (instanceId, functionNamePtr, functionNameSize) => {
            const functionName = Buffer.from(config.instance.exports.memory.buffer)
                .toString('utf8', functionNamePtr, functionNamePtr + functionNameSize);
            wasmInstances[instanceId].worker.postMessage({
                functionName: functionName,
                params: wasmInstances[instanceId].valuesStack
            });
            wasmInstances[instanceId].valuesStack = [];
        },
        instance_resume: (instanceId) => {
            Atomics.store(wasmInstances[instanceId].returnValueSharedArrayBuffer, 0, 1);
            Atomics.notify(wasmInstances[instanceId].returnValueSharedArrayBuffer, 0);
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
