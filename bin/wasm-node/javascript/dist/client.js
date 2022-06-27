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
import { workerOnMessage, workerOnError, workerTerminate } from './compat/index.js';
import spawnWorker from './worker/spawn.js';
/**
 * Thrown in case of a problem when initializing the chain.
 */
export class AddChainError extends Error {
    constructor(message) {
        super(message);
        this.name = "AddChainError";
    }
}
/**
 * Thrown in case the API user tries to use a chain or client that has already been destroyed.
 */
export class AlreadyDestroyedError extends Error {
    constructor() {
        super();
        this.name = "AlreadyDestroyedError";
    }
}
/**
 * Thrown when trying to send a JSON-RPC message to a chain whose JSON-RPC system hasn't been
 * enabled.
 */
export class JsonRpcDisabledError extends Error {
    constructor() {
        super();
        this.name = "JsonRpcDisabledError";
    }
}
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
 * Initializes a new client. This is a pre-requisite to connecting to a blockchain.
 *
 * Can never fail.
 *
 * @param options Configuration of the client. Defaults to `{}`.
 */
export function start(options) {
    options = options || {};
    const logCallback = options.logCallback || ((level, target, message) => {
        // The first parameter of the methods of `console` has some printf-like substitution
        // capabilities. We don't really need to use this, but not using it means that the logs might
        // not get printed correctly if they contain `%`.
        if (level <= 1) {
            console.error("[%s] %s", target, message);
        }
        else if (level == 2) {
            console.warn("[%s] %s", target, message);
        }
        else if (level == 3) {
            console.info("[%s] %s", target, message);
        }
        else if (level == 4) {
            console.debug("[%s] %s", target, message);
        }
        else {
            console.trace("[%s] %s", target, message);
        }
    });
    // The actual execution of Smoldot is performed in a worker thread.
    // Because this specific line of code is a bit sensitive, it is done in a separate file.
    const worker = spawnWorker();
    let workerError = null;
    // Whenever an `addChain` or `removeChain` message is sent to the worker, a corresponding entry
    // is pushed to this array. The worker needs to send back a confirmation, which pops the first
    // element of this array. In the case of `addChain`, additional fields are stored in this array
    // to finish the initialization of the chain.
    let pendingConfirmations = [];
    // Contains the information of each chain that is currently.
    // Entries are instantly removed when the user desires to remove a chain even before the worker
    // has confirmed the removal. Doing so avoids a race condition where the worker sends back a
    // database content or a JSON-RPC response/notification even though we've already sent a
    // `removeChain` message to it.
    //
    // This map is also used in general as a way to check whether a chain still exists.
    let chains = new Map();
    // For each chain object returned by `addChain`, the associated internal chain id.
    //
    // Immediately cleared when `remove()` is called on a chain.
    let chainIds = new WeakMap();
    // The worker periodically reports the name of the task it is currently in. This makes it
    // possible, when the worker is frozen, to know which task it was in when frozen.
    const workerCurrentTask = { name: null };
    // The worker periodically sends a message of kind 'livenessPing' in order to notify that it is
    // still alive.
    // If this liveness ping isn't received for a long time, an error is reported in the logs.
    // The first check is delayed in order to account for the fact that the worker has to perform
    // an expensive initialization step when initializing the Wasm VM.
    let livenessTimeout = null;
    const resetLivenessTimeout = () => {
        if (livenessTimeout !== null)
            globalThis.clearTimeout(livenessTimeout);
        livenessTimeout = globalThis.setTimeout(() => {
            livenessTimeout = null;
            if (workerError)
                return; // The unresponsiveness is due to a crash. No need to print more warnings.
            console.warn("Smoldot appears unresponsive" +
                (workerCurrentTask.name ? (" while executing task `" + workerCurrentTask.name + "`") : "") +
                ". Please open an issue at https://github.com/paritytech/smoldot/issues. If you have a " +
                "debugger available, please pause execution, generate a stack trace of the thread " +
                "that isn't the main execution thread, and paste it in the issue. Please also include " +
                "any other log found in the console or elsewhere.");
        }, 10000);
    };
    globalThis.setTimeout(() => resetLivenessTimeout(), 15000);
    // The worker can send us messages whose type is identified through a `kind` field.
    workerOnMessage(worker, (message) => {
        switch (message.kind) {
            case 'jsonrpc': {
                const cb = chains.get(message.chainId)?.jsonRpcCallback;
                if (cb)
                    cb(message.data);
                break;
            }
            case 'chainAddedOk': {
                const expected = pendingConfirmations.shift();
                const chainId = message.chainId;
                if (chains.has(chainId)) // Sanity check.
                    throw 'Unexpected reuse of a chain ID';
                chains.set(chainId, {
                    jsonRpcCallback: expected.jsonRpcCallback,
                    databasePromises: new Array()
                });
                // `expected` was pushed by the `addChain` method.
                // Resolve the promise that `addChain` returned to the user.
                const newChain = {
                    sendJsonRpc: (request) => {
                        if (workerError)
                            throw workerError;
                        if (!chains.has(chainId))
                            throw new AlreadyDestroyedError();
                        if (!(chains.get(chainId)?.jsonRpcCallback))
                            throw new JsonRpcDisabledError();
                        if (request.length >= 8 * 1024 * 1024)
                            return;
                        postMessage(worker, { ty: 'request', request, chainId });
                    },
                    databaseContent: (maxUtf8BytesSize) => {
                        if (workerError)
                            return Promise.reject(workerError);
                        const databaseContentPromises = chains.get(chainId)?.databasePromises;
                        if (!databaseContentPromises)
                            return Promise.reject(new AlreadyDestroyedError());
                        const promise = new Promise((resolve, reject) => {
                            databaseContentPromises.push({ resolve, reject });
                        });
                        const twoPower32 = (1 << 30) * 4; // `1 << 31` and `1 << 32` in JavaScript don't give the value that you expect.
                        const maxSize = maxUtf8BytesSize || (twoPower32 - 1);
                        const cappedMaxSize = (maxSize >= twoPower32) ? (twoPower32 - 1) : maxSize;
                        postMessage(worker, { ty: 'databaseContent', chainId, maxUtf8BytesSize: cappedMaxSize });
                        return promise;
                    },
                    remove: () => {
                        if (workerError)
                            throw workerError;
                        // Because the `removeChain` message is asynchronous, it is possible for a JSON-RPC
                        // response or database content concerning that `chainId` to arrive after the `remove`
                        // function has returned. We solve that by removing the information immediately.
                        if (!chains.delete(chainId))
                            throw new AlreadyDestroyedError();
                        console.assert(chainIds.has(newChain));
                        chainIds.delete(newChain);
                        postMessage(worker, { ty: 'removeChain', chainId });
                    },
                };
                chainIds.set(newChain, chainId);
                expected.resolve(newChain);
                break;
            }
            case 'chainAddedErr': {
                const expected = pendingConfirmations.shift();
                // `expected` was pushed by the `addChain` method.
                // Reject the promise that `addChain` returned to the user.
                expected.reject(new AddChainError(message.error));
                break;
            }
            case 'databaseContent': {
                const promises = chains.get(message.chainId)?.databasePromises;
                if (promises)
                    promises.shift().resolve(message.data);
                break;
            }
            case 'log': {
                logCallback(message.level, message.target, message.message);
                break;
            }
            case 'livenessPing': {
                resetLivenessTimeout();
                break;
            }
            case 'currentTask': {
                workerCurrentTask.name = message.taskName;
                break;
            }
            default: {
                // Exhaustive check.
                const _exhaustiveCheck = message;
                return _exhaustiveCheck;
            }
        }
    });
    workerOnError(worker, (error) => {
        // A worker error should only happen in case of a critical error as the result of a bug
        // somewhere. Consequently, nothing is really in place to cleanly report the error.
        const errorToString = error.toString();
        console.error("Smoldot has panicked" +
            (workerCurrentTask.name ? (" while executing task `" + workerCurrentTask.name + "`") : "") +
            ". This is a bug in smoldot. Please open an issue at " +
            "https://github.com/paritytech/smoldot/issues with the following message:\n" +
            errorToString);
        workerError = new CrashError(errorToString);
        // Reject all promises returned by `addChain`.
        for (var pending of pendingConfirmations) {
            if (pending.ty == 'chainAdded')
                pending.reject(workerError);
        }
        pendingConfirmations = [];
        // Reject all promises for database contents.
        for (const chain of chains) {
            for (const promise of chain[1].databasePromises) {
                promise.reject(workerError);
            }
        }
        chains.clear();
    });
    // The first message expected by the worker contains the configuration.
    postMessage(worker, {
        // Maximum level of log entries sent by the client.
        // 0 = Logging disabled, 1 = Error, 2 = Warn, 3 = Info, 4 = Debug, 5 = Trace
        maxLogLevel: options.maxLogLevel || 3,
        enableCurrentTask: true,
        cpuRateLimit: options.cpuRateLimit || 1.0,
        forbidTcp: options.forbidTcp || false,
        forbidWs: options.forbidWs || false,
        forbidNonLocalWs: options.forbidNonLocalWs || false,
        forbidWss: options.forbidWss || false,
    });
    return {
        addChain: (options) => {
            if (workerError)
                throw workerError;
            // Passing a JSON object for the chain spec is an easy mistake, so we provide a more
            // readable error.
            if (!(typeof options.chainSpec === 'string'))
                throw new Error("Chain specification must be a string");
            let potentialRelayChainsIds = [];
            if (!!options.potentialRelayChains) {
                for (const chain of options.potentialRelayChains) {
                    // The content of `options.potentialRelayChains` are supposed to be chains earlier
                    // returned by `addChain`.
                    const id = chainIds.get(chain);
                    if (id === undefined) // It is possible for `id` to be missing if it has earlier been removed.
                        continue;
                    potentialRelayChainsIds.push(id);
                }
            }
            // Build a promise that will be resolved or rejected after the chain has been added.
            // TODO: because of https://github.com/microsoft/TypeScript/issues/11498 we need to define the callbacks as possibly null, and go through `unknown`
            let chainAddedPromiseResolve;
            let chainAddedPromiseReject;
            const chainAddedPromise = new Promise((resolve, reject) => {
                chainAddedPromiseResolve = resolve;
                chainAddedPromiseReject = reject;
            });
            pendingConfirmations.push({
                ty: 'chainAdded',
                reject: chainAddedPromiseReject,
                resolve: chainAddedPromiseResolve,
                jsonRpcCallback: options.jsonRpcCallback,
            });
            postMessage(worker, {
                ty: 'addChain',
                chainSpec: options.chainSpec,
                databaseContent: typeof options.databaseContent === 'string' ? options.databaseContent : "",
                potentialRelayChains: potentialRelayChainsIds,
                jsonRpcRunning: !!options.jsonRpcCallback,
            });
            return chainAddedPromise;
        },
        terminate: () => {
            if (workerError)
                return Promise.reject(workerError);
            workerError = new AlreadyDestroyedError();
            if (livenessTimeout !== null)
                globalThis.clearTimeout(livenessTimeout);
            return workerTerminate(worker);
        }
    };
}
// Separate function in order to enforce types.
function postMessage(worker, message) {
    worker.postMessage(message);
}
