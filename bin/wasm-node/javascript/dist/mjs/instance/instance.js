// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
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
import { AlreadyDestroyedError } from '../client.js';
export { ConnectionError } from './raw-instance.js';
/**
 * Thrown in case the underlying client encounters an unexpected crash.
 *
 * This is always an internal bug in smoldot and is never supposed to happen.
 */
export class CrashError extends Error {
    constructor(message) {
        super(message);
    }
}
/**
 * Thrown in case a malformed JSON-RPC request is sent.
 */
export class MalformedJsonRpcError extends Error {
    constructor() {
        super("JSON-RPC request is malformed");
    }
}
/**
 * Thrown in case the buffer of JSON-RPC requests is full and cannot accept any more request.
 */
export class QueueFullError extends Error {
    constructor() {
        super("JSON-RPC requests queue is full");
    }
}
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
            for (const chain of Array.from(chains.values())) {
                for (const promise of chain.jsonRpcResponsesPromises) {
                    promise.reject(crashError.error);
                }
                chain.jsonRpcResponsesPromises = [];
            }
        },
        logCallback: (level, target, message) => {
            configMessage.logCallback(level, target, message);
        },
        jsonRpcResponsesNonEmptyCallback: (chainId) => {
            // Notify every single promise found in `jsonRpcResponsesPromises`.
            const promises = chains.get(chainId).jsonRpcResponsesPromises;
            while (promises.length !== 0) {
                promises.shift().resolve();
            }
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
            const [periodicallyYield, unregisterCallback] = platformBindings.registerShouldPeriodicallyYield((newValue) => {
                if (state.initialized && !crashError.error) {
                    try {
                        state.instance.exports.set_periodically_yield(newValue ? 1 : 0);
                    }
                    catch (_error) { }
                }
            });
            instance.exports.init(configMessage.maxLogLevel, configMessage.enableCurrentTask ? 1 : 0, cpuRateLimit, periodicallyYield ? 1 : 0);
            state = { initialized: true, instance, unregisterCallback };
            return instance;
        })
    };
    function queueOperation(operation) {
        return __awaiter(this, void 0, void 0, function* () {
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
        });
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
            let retVal;
            try {
                const encoded = new TextEncoder().encode(request);
                const ptr = state.instance.exports.alloc(encoded.length) >>> 0;
                new Uint8Array(state.instance.exports.memory.buffer).set(encoded, ptr);
                retVal = state.instance.exports.json_rpc_send(ptr, encoded.length, chainId) >>> 0;
            }
            catch (_error) {
                console.assert(crashError.error);
                throw crashError.error;
            }
            switch (retVal) {
                case 0: break;
                case 1: throw new MalformedJsonRpcError();
                case 2: throw new QueueFullError();
                default: throw new Error("Internal error: unknown json_rpc_send error code: " + retVal);
            }
        },
        nextJsonRpcResponse: (chainId) => __awaiter(this, void 0, void 0, function* () {
            // Because `nextJsonRpcResponse` is passed as parameter an identifier returned by `addChain`,
            // it is always the case that the Wasm instance is already initialized. The only possibility
            // for it to not be the case is if the user completely invented the `chainId`.
            if (!state.initialized)
                throw new Error("Internal error");
            while (true) {
                if (crashError.error)
                    throw crashError.error;
                // Try to pop a message from the queue.
                try {
                    const mem = new Uint8Array(state.instance.exports.memory.buffer);
                    const responseInfo = state.instance.exports.json_rpc_responses_peek(chainId) >>> 0;
                    const ptr = buffer.readUInt32LE(mem, responseInfo) >>> 0;
                    const len = buffer.readUInt32LE(mem, responseInfo + 4) >>> 0;
                    // `len === 0` means "queue is empty" according to the API.
                    // In that situation, queue the resolve/reject.
                    if (len !== 0) {
                        const message = buffer.utf8BytesToString(mem, ptr, len);
                        state.instance.exports.json_rpc_responses_pop(chainId);
                        return message;
                    }
                }
                catch (_error) {
                    console.assert(crashError.error);
                    throw crashError.error;
                }
                // If no message is available, wait for one to be.
                yield new Promise((resolve, reject) => {
                    chains.get(chainId).jsonRpcResponsesPromises.push({ resolve: () => resolve(undefined), reject });
                });
            }
        }),
        addChain: (chainSpec, databaseContent, potentialRelayChains, disableJsonRpc) => {
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
                    const chainId = instance.exports.add_chain(chainSpecPtr, chainSpecEncoded.length, databaseContentPtr, databaseContentEncoded.length, disableJsonRpc ? 0 : 1, potentialRelayChainsPtr, potentialRelayChainsLen);
                    if (instance.exports.chain_is_ok(chainId) != 0) {
                        console.assert(!chains.has(chainId));
                        chains.set(chainId, {
                            jsonRpcResponsesPromises: new Array()
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
            for (const { reject } of chains.get(chainId).jsonRpcResponsesPromises) {
                reject(new AlreadyDestroyedError());
            }
            chains.delete(chainId);
            try {
                state.instance.exports.remove_chain(chainId);
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
                if (state.initialized)
                    state.unregisterCallback();
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
