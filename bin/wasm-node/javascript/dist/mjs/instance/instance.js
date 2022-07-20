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
import * as buffer from './buffer.js';
import * as instance from './raw-instance.js';
import { CrashError } from '../client.js';
export { ConnectionError } from './raw-instance.js';
export function start(configMessage, platformBindings) {
    // This variable represents the state of the instance, and serves two different purposes:
    //
    // - At initialization, it is a Promise containing the Wasm VM is still initializing.
    // - After the Wasm VM has finished initialization, contains the `WebAssembly.Instance` object.
    //
    let state;
    const crashError = {};
    const currentTask = { name: null };
    const printError = { printError: true };
    // Contains the information of each chain that is currently alive.
    let chains = new Map();
    // Start initialization of the Wasm VM.
    const config = {
        onWasmPanic: (message) => {
            // TODO: consider obtaining a backtrace here
            crashError.error = new CrashError(message);
            if (!printError.printError)
                return;
            console.error("Smoldot has panicked" +
                (currentTask.name ? (" while executing task `" + currentTask.name + "`") : "") +
                ". This is a bug in smoldot. Please open an issue at " +
                "https://github.com/paritytech/smoldot/issues with the following message:\n" +
                message);
        },
        logCallback: (level, target, message) => {
            configMessage.logCallback(level, target, message);
        },
        jsonRpcCallback: (data, chainId) => {
            const cb = chains.get(chainId)?.jsonRpcCallback;
            if (cb)
                cb(data);
        },
        databaseContentCallback: (data, chainId) => {
            const promises = chains.get(chainId)?.databasePromises;
            promises.shift().resolve(data);
        },
        currentTaskCallback: (taskName) => {
            currentTask.name = taskName;
        },
        cpuRateLimit: configMessage.cpuRateLimit,
    };
    state = {
        initialized: false, promise: instance.startInstance(config, platformBindings).then((instance) => {
            // `config.cpuRateLimit` is a floating point that should be between 0 and 1, while the value
            // to pass as parameter must be between `0` and `2^32-1`.
            // The few lines of code below should handle all possible values of `number`, including
            // infinites and NaN.
            let cpuRateLimit = Math.round(config.cpuRateLimit * 4294967295); // `2^32 - 1`
            if (cpuRateLimit < 0)
                cpuRateLimit = 0;
            if (cpuRateLimit > 4294967295)
                cpuRateLimit = 4294967295;
            if (!Number.isFinite(cpuRateLimit))
                cpuRateLimit = 4294967295; // User might have passed NaN
            // Smoldot requires an initial call to the `init` function in order to do its internal
            // configuration.
            instance.exports.init(configMessage.maxLogLevel, configMessage.enableCurrentTask ? 1 : 0, cpuRateLimit);
            state = { initialized: true, instance };
            return instance;
        })
    };
    async function queueOperation(operation) {
        // What to do depends on the type of `state`.
        // See the documentation of the `state` variable for information.
        if (!state.initialized) {
            // A message has been received while the Wasm VM is still initializing. Queue it for when
            // initialization is over.
            return state.promise.then((instance) => operation(instance));
        }
        else {
            // Everything is already initialized. Process the message synchronously.
            return operation(state.instance);
        }
    }
    return {
        request: (request, chainId) => {
            // Because `request` is passed as parameter an identifier returned by `addChain`, it is
            // always the case that the Wasm instance is already initialized. The only possibility for
            // it to not be the case is if the user completely invented the `chainId`.
            if (!state.initialized)
                throw new Error("Internal error");
            if (crashError.error)
                throw crashError.error;
            try {
                const encoded = new TextEncoder().encode(request);
                const ptr = state.instance.exports.alloc(encoded.length) >>> 0;
                new Uint8Array(state.instance.exports.memory.buffer).set(encoded, ptr);
                state.instance.exports.json_rpc_send(ptr, encoded.length, chainId);
            }
            catch (_error) {
                console.assert(crashError.error);
                throw crashError.error;
            }
        },
        addChain: (chainSpec, databaseContent, potentialRelayChains, jsonRpcCallback) => {
            return queueOperation((instance) => {
                if (crashError.error)
                    throw crashError.error;
                try {
                    // Write the chain specification into memory.
                    const chainSpecEncoded = new TextEncoder().encode(chainSpec);
                    const chainSpecPtr = instance.exports.alloc(chainSpecEncoded.length) >>> 0;
                    new Uint8Array(instance.exports.memory.buffer).set(chainSpecEncoded, chainSpecPtr);
                    // Write the database content into memory.
                    const databaseContentEncoded = new TextEncoder().encode(databaseContent);
                    const databaseContentPtr = instance.exports.alloc(databaseContentEncoded.length) >>> 0;
                    new Uint8Array(instance.exports.memory.buffer).set(databaseContentEncoded, databaseContentPtr);
                    // Write the potential relay chains into memory.
                    const potentialRelayChainsLen = potentialRelayChains.length;
                    const potentialRelayChainsPtr = instance.exports.alloc(potentialRelayChainsLen * 4) >>> 0;
                    for (let idx = 0; idx < potentialRelayChains.length; ++idx) {
                        buffer.writeUInt32LE(new Uint8Array(instance.exports.memory.buffer), potentialRelayChainsPtr + idx * 4, potentialRelayChains[idx]);
                    }
                    // `add_chain` unconditionally allocates a chain id. If an error occurs, however, this chain
                    // id will refer to an *erroneous* chain. `chain_is_ok` is used below to determine whether it
                    // has succeeeded or not.
                    // Note that `add_chain` properly de-allocates buffers even if it failed.
                    const chainId = instance.exports.add_chain(chainSpecPtr, chainSpecEncoded.length, databaseContentPtr, databaseContentEncoded.length, !!jsonRpcCallback ? 1 : 0, potentialRelayChainsPtr, potentialRelayChainsLen);
                    if (instance.exports.chain_is_ok(chainId) != 0) {
                        console.assert(!chains.has(chainId));
                        chains.set(chainId, {
                            jsonRpcCallback,
                            databasePromises: new Array()
                        });
                        return { success: true, chainId };
                    }
                    else {
                        const errorMsgLen = instance.exports.chain_error_len(chainId) >>> 0;
                        const errorMsgPtr = instance.exports.chain_error_ptr(chainId) >>> 0;
                        const errorMsg = buffer.utf8BytesToString(new Uint8Array(instance.exports.memory.buffer), errorMsgPtr, errorMsgLen);
                        instance.exports.remove_chain(chainId);
                        return { success: false, error: errorMsg };
                    }
                }
                catch (_error) {
                    console.assert(crashError.error);
                    throw crashError.error;
                }
            });
        },
        removeChain: (chainId) => {
            // Because `removeChain` is passed as parameter an identifier returned by `addChain`, it is
            // always the case that the Wasm instance is already initialized. The only possibility for
            // it to not be the case is if the user completely invented the `chainId`.
            if (!state.initialized)
                throw new Error("Internal error");
            if (crashError.error)
                throw crashError.error;
            // Removing the chain synchronously avoids having to deal with race conditions such as a
            // JSON-RPC response corresponding to a chain that is going to be deleted but hasn't been yet.
            // These kind of race conditions are already delt with within smoldot.
            console.assert(chains.has(chainId));
            chains.delete(chainId);
            try {
                state.instance.exports.remove_chain(chainId);
            }
            catch (_error) {
                console.assert(crashError.error);
                throw crashError.error;
            }
        },
        databaseContent: (chainId, maxUtf8BytesSize) => {
            // Because `databaseContent` is passed as parameter an identifier returned by `addChain`, it
            // is always the case that the Wasm instance is already initialized. The only possibility for
            // it to not be the case is if the user completely invented the `chainId`.
            if (!state.initialized)
                throw new Error("Internal error");
            if (crashError.error)
                throw crashError.error;
            console.assert(chains.has(chainId));
            const databaseContentPromises = chains.get(chainId)?.databasePromises;
            const promise = new Promise((resolve, reject) => {
                databaseContentPromises.push({ resolve, reject });
            });
            // Cap `maxUtf8BytesSize` and set a default value.
            const twoPower32 = (1 << 30) * 4; // `1 << 31` and `1 << 32` in JavaScript don't give the value that you expect.
            const maxSize = maxUtf8BytesSize || (twoPower32 - 1);
            const cappedMaxSize = (maxSize >= twoPower32) ? (twoPower32 - 1) : maxSize;
            // The value of `maxUtf8BytesSize` is guaranteed to always fit in 32 bits, in
            // other words, that `maxUtf8BytesSize < (1 << 32)`.
            // We need to perform a conversion in such a way that the the bits of the output of
            // `ToInt32(converted)`, when interpreted as u32, is equal to `maxUtf8BytesSize`.
            // See ToInt32 here: https://tc39.es/ecma262/#sec-toint32
            // Note that the code below has been tested against example values. Please be very careful
            // if you decide to touch it. Ideally it would be unit-tested, but since it concerns the FFI
            // layer between JS and Rust, writing unit tests would be extremely complicated.
            const twoPower31 = (1 << 30) * 2; // `1 << 31` in JavaScript doesn't give the value that you expect.
            const converted = (cappedMaxSize >= twoPower31) ?
                (cappedMaxSize - twoPower32) : cappedMaxSize;
            try {
                state.instance.exports.database_content(chainId, converted);
                return promise;
            }
            catch (_error) {
                console.assert(crashError.error);
                throw crashError.error;
            }
        },
        startShutdown: () => {
            return queueOperation((instance) => {
                // `startShutdown` is a bit special in its handling of crashes.
                // Shutting down will lead to `onWasmPanic` being called at some point, possibly during
                // the call to `start_shutdown` itself. As such, we move into "don't print errors anymore"
                // mode even before calling `start_shutdown`.
                //
                // Furthermore, if a crash happened in the past, there is no point in throwing an
                // exception when the user wants the shutdown to happen.
                if (crashError.error)
                    return;
                try {
                    printError.printError = false;
                    instance.exports.start_shutdown();
                }
                catch (_error) {
                }
            });
        }
    };
}
