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

import { Buffer } from 'buffer';
import * as instance from './raw-instance.js';
import { SmoldotWasmInstance } from './bindings.js';

/**
 * Contains the initial configuration of the worker.
 *
 * This message is only ever sent once, and it is always the first ever message sent to the
 * worker.
 */
 export interface Config {
  logCallback: (level: number, target: string, message: string) => void
  maxLogLevel: number;
  enableCurrentTask: boolean;
  cpuRateLimit: number,
  forbidTcp: boolean;
  forbidWs: boolean;
  forbidNonLocalWs: boolean;
  forbidWss: boolean;
}

export interface Worker {
  request: (request: string, chainId: number) => void
  addChain: (chainSpec: string, databaseContent: string, potentialRelayChains: number[], jsonRpcCallback?: (response: string) => void) => Promise<{ success: true, chainId: number } | { success: false, error: string }>
  removeChain: (chainId: number) => void
  databaseContent: (chainId: number, maxUtf8BytesSize: number) => Promise<string>
}

export function start(configMessage: Config): Worker {

// This variable represents the state of the worker, and serves two different purposes:
//
// - At initialization, it is a Promise containing the Wasm VM is still initializing.
// - After the Wasm VM has finished initialization, contains the `WebAssembly.Instance` object.
//
let state: { initialized: false, promise: Promise<SmoldotWasmInstance> } | { initialized: true, instance: SmoldotWasmInstance };

  // Contains the information of each chain that is currently alive.
  let chains: Map<number, {
    jsonRpcCallback?: (response: string) => void,
    databasePromises: DatabasePromise[],
  }> = new Map();

    // Start initialization of the Wasm VM.
    const config: instance.Config = {
      logCallback: (level, target, message) => {
        configMessage.logCallback(level, target, message)
      },
      jsonRpcCallback: (data, chainId) => {
        const cb = chains.get(chainId)?.jsonRpcCallback;
        if (cb) cb(data);
      },
      databaseContentCallback: (data, chainId) => {
        const promises = chains.get(chainId)?.databasePromises!;
        (promises.shift() as DatabasePromise).resolve(data);
      },
      currentTaskCallback: (_taskName) => {
        // TODO: do something here?
      },
      cpuRateLimit: configMessage.cpuRateLimit,
      forbidTcp: configMessage.forbidTcp,
      forbidWs: configMessage.forbidWs,
      forbidNonLocalWs: configMessage.forbidNonLocalWs,
      forbidWss: configMessage.forbidWss,
    };

    state = { initialized: false, promise: instance.startInstance(config).then((instance) => {
      // `config.cpuRateLimit` is a floating point that should be between 0 and 1, while the value
      // to pass as parameter must be between `0` and `2^32-1`.
      // The few lines of code below should handle all possible values of `number`, including
      // infinites and NaN.
      let cpuRateLimit = Math.round(config.cpuRateLimit * 4294967295);  // `2^32 - 1`
      if (cpuRateLimit < 0) cpuRateLimit = 0;
      if (cpuRateLimit > 4294967295) cpuRateLimit = 4294967295;
      if (!Number.isFinite(cpuRateLimit)) cpuRateLimit = 4294967295; // User might have passed NaN

      // Smoldot requires an initial call to the `init` function in order to do its internal
      // configuration.
      instance.exports.init(configMessage.maxLogLevel, configMessage.enableCurrentTask ? 1 : 0, cpuRateLimit);

      state = { initialized: true, instance };
      return instance;
    }) };

async function queueOperation<T>(operation: (instance: SmoldotWasmInstance) => T): Promise<T> {
  // What to do depends on the type of `state`.
  // See the documentation of the `state` variable for information.
  if (!state.initialized) {
    // A message has been received while the Wasm VM is still initializing. Queue it for when
    // initialization is over.
    return state.promise.then((instance) => operation(instance))

  } else {
    // Everything is already initialized. Process the message synchronously.
    return operation(state.instance)
  }
}

return {
  request: (request: string, chainId: number) => {
    // Because `request` is passed as parameter an identifier returned by `addChain`, it is
    // always the case that the Wasm instance is already initialized. The only possibility for
    // it to not be the case is if the user completely invented the `chainId`.
    if (!state.initialized)
      throw new Error("Internal error");

    const len = Buffer.byteLength(request, 'utf8');
    const ptr = state.instance.exports.alloc(len) >>> 0;
    Buffer.from(state.instance.exports.memory.buffer).write(request, ptr);
    state.instance.exports.json_rpc_send(ptr, len, chainId);
  },

  addChain: (chainSpec: string, databaseContent: string, potentialRelayChains: number[], jsonRpcCallback?: (response: string) => void): Promise<{ success: true, chainId: number } | { success: false, error: string }> => {
    return queueOperation((instance) => {
      // Write the chain specification into memory.
      const chainSpecLen = Buffer.byteLength(chainSpec, 'utf8');
      const chainSpecPtr = instance.exports.alloc(chainSpecLen) >>> 0;
      Buffer.from(instance.exports.memory.buffer)
        .write(chainSpec, chainSpecPtr);

      // Write the database content into memory.
      const databaseContentLen = Buffer.byteLength(databaseContent, 'utf8');
      const databaseContentPtr = instance.exports.alloc(databaseContentLen) >>> 0;
      Buffer.from(instance.exports.memory.buffer)
        .write(databaseContent, databaseContentPtr);

      // Write the potential relay chains into memory.
      const potentialRelayChainsLen = potentialRelayChains.length;
      const potentialRelayChainsPtr = instance.exports.alloc(potentialRelayChainsLen * 4) >>> 0;
      for (let idx = 0; idx < potentialRelayChains.length; ++idx) {
        Buffer.from(instance.exports.memory.buffer)
          .writeUInt32LE(potentialRelayChains[idx]!, potentialRelayChainsPtr + idx * 4);
      }

      // `add_chain` unconditionally allocates a chain id. If an error occurs, however, this chain
      // id will refer to an *erroneous* chain. `chain_is_ok` is used below to determine whether it
      // has succeeeded or not.
      // Note that `add_chain` properly de-allocates buffers even if it failed.
      const chainId = instance.exports.add_chain(
        chainSpecPtr, chainSpecLen,
        databaseContentPtr, databaseContentLen,
        !!jsonRpcCallback ? 1 : 0,
        potentialRelayChainsPtr, potentialRelayChainsLen
      );

      if (instance.exports.chain_is_ok(chainId) != 0) {
        if (chains.has(chainId)) // Sanity check.
          throw 'Unexpected reuse of a chain ID';
        chains.set(chainId, {
          jsonRpcCallback,
          databasePromises: new Array()
        });
        return { success: true, chainId };
      } else {
        const errorMsgLen = instance.exports.chain_error_len(chainId) >>> 0;
        const errorMsgPtr = instance.exports.chain_error_ptr(chainId) >>> 0;
        const errorMsg = Buffer.from(instance.exports.memory.buffer)
          .toString('utf8', errorMsgPtr, errorMsgPtr + errorMsgLen);
        instance.exports.remove_chain(chainId);
        return { success: false, error: errorMsg };
      }
    })
  },

  removeChain: (chainId: number) => {
    // Because `removeChain` is passed as parameter an identifier returned by `addChain`, it is
    // always the case that the Wasm instance is already initialized. The only possibility for
    // it to not be the case is if the user completely invented the `chainId`.
    if (!state.initialized)
      throw new Error("Internal error");

    // Removing the chain synchronously avoids having to deal with race conditions such as a
    // JSON-RPC response corresponding to a chain that is going to be deleted but hasn't been yet.
    // These kind of race conditions are already delt with within smoldot.
    chains.delete(chainId);
    state.instance.exports.remove_chain(chainId);
  },

  databaseContent: (chainId: number, maxUtf8BytesSize: number): Promise<string> => {
    // Because `databaseContent` is passed as parameter an identifier returned by `addChain`, it
    // is always the case that the Wasm instance is already initialized. The only possibility for
    // it to not be the case is if the user completely invented the `chainId`.
    if (!state.initialized)
      throw new Error("Internal error");

    const databaseContentPromises = chains.get(chainId)?.databasePromises!;
    const promise: Promise<string> = new Promise((resolve, reject) => {
      databaseContentPromises.push({ resolve, reject });
    });

    // The value of `maxUtf8BytesSize` is guaranteed (by `index.js`) to always fit in 32 bits, in
    // other words, that `maxUtf8BytesSize < (1 << 32)`.
    // We need to perform a conversion in such a way that the the bits of the output of
    // `ToInt32(converted)`, when interpreted as u32, is equal to `maxUtf8BytesSize`.
    // See ToInt32 here: https://tc39.es/ecma262/#sec-toint32
    // Note that the code below has been tested against example values. Please be very careful
    // if you decide to touch it. Ideally it would be unit-tested, but since it concerns the FFI
    // layer between JS and Rust, writing unit tests would be extremely complicated.
    const twoPower31 = (1 << 30) * 2;  // `1 << 31` in JavaScript doesn't give the value that you expect.
    const converted = (maxUtf8BytesSize >= twoPower31) ?
      (maxUtf8BytesSize - (twoPower31 * 2)) : maxUtf8BytesSize;
    state.instance.exports.database_content(chainId, converted);

    return promise;
  }
}

}

interface DatabasePromise {
  resolve: (data: string) => void,
  reject: (error: Error) => void,
}
