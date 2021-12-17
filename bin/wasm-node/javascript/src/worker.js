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
import { default as pako } from 'pako';
import * as compat from './compat-nodejs.js';
import { default as smoldot_light_builder } from './bindings-smoldot-light.js';
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

// Inject a message coming from `index.js` to a running Wasm VM.
const injectMessage = (instance, message) => {
  if (message.ty == 'request') {
    const len = Buffer.byteLength(message.request, 'utf8');
    const ptr = instance.exports.alloc(len) >>> 0;
    Buffer.from(instance.exports.memory.buffer).write(message.request, ptr);
    instance.exports.json_rpc_send(ptr, len, message.chainId);

  } else if (message.ty == 'addChain') {
    // Write the chain specification into memory.
    const chainSpecLen = Buffer.byteLength(message.chainSpec, 'utf8');
    const chainSpecPtr = instance.exports.alloc(chainSpecLen) >>> 0;
    Buffer.from(instance.exports.memory.buffer)
      .write(message.chainSpec, chainSpecPtr);

    // Write the database content into memory.
    const databaseContentLen = Buffer.byteLength(message.databaseContent, 'utf8');
    const databaseContentPtr = instance.exports.alloc(databaseContentLen) >>> 0;
    Buffer.from(instance.exports.memory.buffer)
      .write(message.databaseContent, databaseContentPtr);

    // Write the potential relay chains into memory.
    const potentialRelayChainsLen = message.potentialRelayChains.length;
    const potentialRelayChainsPtr = instance.exports.alloc(potentialRelayChainsLen * 4) >>> 0;
    for (let idx in message.potentialRelayChains) {
      Buffer.from(instance.exports.memory.buffer)
        .writeUInt32LE(message.potentialRelayChains[idx], potentialRelayChainsPtr + idx * 4);
    }

    // `add_chain` unconditionally allocates a chain id. If an error occurs, however, this chain
    // id will refer to an *erroneous* chain. `chain_is_ok` is used below to determine whether it
    // has succeeeded or not.
    // Note that `add_chain` properly de-allocates buffers even if it failed.
    const chainId = instance.exports.add_chain(
      chainSpecPtr, chainSpecLen,
      databaseContentPtr, databaseContentLen,
      message.jsonRpcRunning,
      potentialRelayChainsPtr, potentialRelayChainsLen
    );

    if (instance.exports.chain_is_ok(chainId) != 0) {
      compat.postMessage({ kind: 'chainAddedOk', chainId });
    } else {
      const errorMsgLen = instance.exports.chain_error_len(chainId) >>> 0;
      const errorMsgPtr = instance.exports.chain_error_ptr(chainId) >>> 0;
      const errorMsg = Buffer.from(instance.exports.memory.buffer)
        .toString('utf8', errorMsgPtr, errorMsgPtr + errorMsgLen);
      instance.exports.remove_chain(chainId);
      compat.postMessage({ kind: 'chainAddedErr', error: new Error(errorMsg) });
    }

  } else if (message.ty == 'removeChain') {
    instance.exports.remove_chain(message.chainId);
    // `compat.postMessage` is the same as `postMessage`, but works across environments.
    compat.postMessage({ kind: 'chainRemoved' });

  } else if (message.ty == 'databaseContent') {
    // The value of `maxUtf8BytesSize` is guaranteed (by `index.js`) to always fit in 32 bits, in
    // other words, that `maxUtf8BytesSize < (1 << 32)`.
    // We need to perform a conversion in such a way that the the bits of the output of
    // `ToInt32(converted)`, when interpreted as u32, is equal to `maxUtf8BytesSize`.
    // See ToInt32 here: https://tc39.es/ecma262/#sec-toint32
    // Note that the code below has been tested against example values. Please be very careful
    // if you decide to touch it. Ideally it would be unit-tested, but since it concerns the FFI
    // layer between JS and Rust, writing unit tests would be extremely complicated.
    const twoPower31 = (1 << 30) * 2;  // `1 << 31` in JavaScript doesn't give the value that you expect.
    const converted = (message.maxUtf8BytesSize >= twoPower31) ?
      (message.maxUtf8BytesSize - (twoPower31 * 2)) : message.maxUtf8BytesSize;
    instance.exports.database_content(message.chainId, converted);

  } else
    throw new Error('unrecognized message type');
};

const startInstance = async (config) => {
  // The actual Wasm bytecode is base64-decoded then gzip-decoded from a constant found in a
  // different file.
  // This is suboptimal compared to using `instantiateStreaming`, but it is the most
  // cross-platform cross-bundler approach.
  const wasmBytecode = pako.inflate(new Uint8Array(Buffer.from(wasm_base64, 'base64')));

  // Used to bind with the smoldot-light bindings. See the `bindings-smoldot-light.js` file.
  const smoldotJsConfig = {
    logCallback: (level, target, message) => {
      // `compat.postMessage` is the same as `postMessage`, but works across environments.
      compat.postMessage({ kind: 'log', level, target, message });
    },
    jsonRpcCallback: (data, chainId) => {
      // `compat.postMessage` is the same as `postMessage`, but works across environments.
      compat.postMessage({ kind: 'jsonrpc', data, chainId });
    },
    databaseContentCallback: (data, chainId) => {
      // `compat.postMessage` is the same as `postMessage`, but works across environments.
      compat.postMessage({ kind: 'databaseContent', data, chainId });
    },
    forbidTcp: config.forbidTcp,
    forbidWs: config.forbidWs,
    forbidNonLocalWs: config.forbidNonLocalWs,
    forbidWss: config.forbidWss,
  };

  const { bindings: smoldotJsBindings } = smoldot_light_builder(smoldotJsConfig);

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

  // Start initialization of smoldot.
  result.instance.exports.init(config.maxLogLevel);

  // Smoldot has finished initializing.
  // Since this function is an asynchronous function, it is possible that messages have been
  // received from the parent while it was executing. These messages are now handled.
  state.forEach((message) => {
    injectMessage(result.instance, message);
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
    injectMessage(state, message);
  }
});

// Periodically send a ping message to the outside, as a way to report liveness.
setInterval(() => {
  // `compat.postMessage` is the same as `postMessage`, but works across environments.
  compat.postMessage({ kind: 'livenessPing' });
}, 2500);
