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

import { Buffer } from 'buffer';
import * as compat from './compat-nodejs.js';
import { default as smoldot_js_builder } from './bindings-smoldot-js.js';
import { default as wasi_builder } from './bindings-wasi.js';

import { default as wasm_base64 } from './autogen/wasm.js';

// This variable represents the state of the worker, and serves three different purposes:
//
// - At initialization, it is set to `null`.
// - Once the first message, containing the configuration, has been received from the parent, it
//   becomes an array filled with JSON-RPC requests that are received while the Wasm VM is still
//   initializing.
// - After the Wasm VM has finished initialization, contains the `WebAssembly.Instance` object.
//
let state = null;

const startInstance = async (config) => {
  // The actual Wasm bytecode is base64-decoded from a constant found in a different file.
  // This is suboptimal compared to using `instantiateStreaming`, but it is the most
  // cross-platform cross-bundler approach.
  const wasmBytecode = new Uint8Array(Buffer.from(wasm_base64, 'base64'));

  // Used to bind with the smoldot-js bindings. See the `bindings-smoldot-js.js` file.
  const smoldotJsConfig = {
    logCallback: (level, target, message) => {
      // `compat.postMessage` is the same as `postMessage`, but works across environments.
      compat.postMessage({ kind: 'log', level, target, message });
    },
    jsonRpcCallback: (data, chainIndex, userData) => {
      // `compat.postMessage` is the same as `postMessage`, but works across environments.
      compat.postMessage({ kind: 'jsonrpc', data, chainIndex, userData });
    },
    forbidTcp: config.forbidTcp,
    forbidWs: config.forbidWs,
    forbidWss: config.forbidWss,
  };

  const { bindings: smoldotJsBindings } = smoldot_js_builder(smoldotJsConfig);

  // Used to bind with the Wasi bindings. See the `bindings-wasi.js` file.
  const wasiConfig = {};

  // Start the Wasm virtual machine.
  // The Rust code defines a list of imports that must be fulfilled by the environment. The second
  // parameter provides their implementations.
  const result = await WebAssembly.instantiate(wasmBytecode, {
    // The functions with the "smoldot" prefix are specific to smoldot.
    "smoldot": smoldotJsBindings,
    // As the Rust code is compiled for wasi, some more wasi-specific imports exist.
    "wasi_snapshot_preview1": wasi_builder(wasiConfig),
  });

  smoldotJsConfig.instance = result.instance;
  wasiConfig.instance = result.instance;

  // Write the chain specifications into memory and call `init`.
  // The logic below is a bit complicated due to the necessity to pass a list of strings through
  // the FFI layer. See the documentation of `init` in the Rust code.
  let chainSpecsPointersContent = [];
  for (let chainSpec of config.chainSpecs) {
    if (Object.prototype.toString.call(chainSpec) !== '[object String]')
      throw new SmoldotError('chain spec must be a string');

    const chainSpecLen = Buffer.byteLength(chainSpec, 'utf8');
    const chainSpecPtr = result.instance.exports.alloc(chainSpecLen);
    Buffer.from(result.instance.exports.memory.buffer)
      .write(chainSpec, chainSpecPtr);
    chainSpecsPointersContent.push(chainSpecPtr);
    chainSpecsPointersContent.push(chainSpecLen);
  }
  const chainSpecsPointersPtr = result.instance.exports.alloc(chainSpecsPointersContent.length * 4);
  for (let idx in chainSpecsPointersContent) {
    Buffer.from(result.instance.exports.memory.buffer)
      .writeUInt32LE(chainSpecsPointersContent[idx], chainSpecsPointersPtr + idx * 4);
  }
  // Start initialization of smoldot.
  result.instance.exports.init(
    chainSpecsPointersPtr, chainSpecsPointersContent.length * 4,
    config.maxLogLevel
  );

  // Smoldot has finished initializing.
  // Since this function is an asynchronous function, it is possible that messages have been
  // received from the parent while it was executing. These messages are now handled.
  // Note that this same code is duplicated below.
  state.forEach((message) => {
    if (message.ty == 'request') {
      const len = Buffer.byteLength(message.request, 'utf8');
      const ptr = result.instance.exports.alloc(len);
      Buffer.from(result.instance.exports.memory.buffer).write(message.request, ptr);
      result.instance.exports.json_rpc_send(ptr, len, message.chainIndex, message.userData);
    } else if (message.ty == 'unsubscribeAll') {
      result.instance.exports.json_rpc_unsubscribe_all(message.userData);
      // `compat.postMessage` is the same as `postMessage`, but works across environments.
      compat.postMessage({ kind: 'unsubscribeAllConfirmation', userData: message.userData });
    } else
      throw new Error('unrecognized message type');
  });

  state = result.instance;
};

// `compat.setOnMessage` is the same as `onmessage = ...`, but works across environments.
compat.setOnMessage((message) => {
  // What to do depends on the type of `state`.
  // See the documentation of the `state` variable for information.
  if (state == null) {
    // First ever message received by the worker. Always contains the initial configuration.
    state = [];
    startInstance(message) // Note that `startInstance` is `async`.

  } else if (Array.isArray(state)) {
    // A JSON-RPC request has been received while the Wasm VM is still initializing. Queue it
    // for when initialization is over.
    state.push(message);

  } else {
    // Everything is already initialized. Process the message synchronously.
    // Note that this same code is duplicated above.
    if (message.ty == 'request') {
      const len = Buffer.byteLength(message.request, 'utf8');
      const ptr = state.exports.alloc(len);
      Buffer.from(state.exports.memory.buffer).write(message.request, ptr);
      state.exports.json_rpc_send(ptr, len, message.chainIndex, message.userData);
    } else if (message.ty == 'unsubscribeAll') {
      state.exports.json_rpc_unsubscribe_all(message.userData);
      // `compat.postMessage` is the same as `postMessage`, but works across environments.
      compat.postMessage({ kind: 'unsubscribeAllConfirmation', userData: message.userData });
    } else
      throw new Error('unrecognized message type');
  }
});
