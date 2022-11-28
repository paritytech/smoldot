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
import { MalformedJsonRpcError, start as startInstance } from './instance/instance.js';
export { MalformedJsonRpcError, QueueFullError, CrashError } from './instance/instance.js';
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
// This function is similar to the `start` function found in `index.ts`, except with an extra
// parameter containing the platform-specific bindings.
// Contrary to the one within `index.js`, this function is not supposed to be directly used.
export function start(options, platformBindings) {
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
    // For each chain object returned by `addChain`, the associated internal chain id.
    //
    // Immediately cleared when `remove()` is called on a chain.
    let chainIds = new WeakMap();
    // If `Client.terminate()̀  is called, this error is set to a value.
    // All the functions of the public API check if this contains a value.
    let alreadyDestroyedError = null;
    const instance = startInstance({
        // Maximum level of log entries sent by the client.
        // 0 = Logging disabled, 1 = Error, 2 = Warn, 3 = Info, 4 = Debug, 5 = Trace
        maxLogLevel: options.maxLogLevel || 3,
        logCallback,
        // `enableCurrentTask` adds a small performance hit, but adds some additional information to
        // crash reports. Whether this should be enabled is very opiniated and not that important. At
        // the moment, we enable it all the time, except if the user has logging disabled altogether.
        enableCurrentTask: options.maxLogLevel ? options.maxLogLevel >= 1 : true,
        cpuRateLimit: options.cpuRateLimit || 1.0,
    }, platformBindings);
    return {
        addChain: (options) => __awaiter(this, void 0, void 0, function* () {
            if (alreadyDestroyedError)
                throw alreadyDestroyedError;
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
            const outcome = yield instance.addChain(options.chainSpec, typeof options.databaseContent === 'string' ? options.databaseContent : "", potentialRelayChainsIds, !!options.disableJsonRpc);
            if (!outcome.success)
                throw new AddChainError(outcome.error);
            const chainId = outcome.chainId;
            const wasDestroyed = { destroyed: false };
            // `expected` was pushed by the `addChain` method.
            // Resolve the promise that `addChain` returned to the user.
            const newChain = {
                sendJsonRpc: (request) => {
                    if (alreadyDestroyedError)
                        throw alreadyDestroyedError;
                    if (wasDestroyed.destroyed)
                        throw new AlreadyDestroyedError();
                    if (options.disableJsonRpc)
                        throw new JsonRpcDisabledError();
                    if (request.length >= 64 * 1024 * 1024) {
                        throw new MalformedJsonRpcError();
                    }
                    ;
                    instance.request(request, chainId);
                },
                nextJsonRpcResponse: () => {
                    if (alreadyDestroyedError)
                        return Promise.reject(alreadyDestroyedError);
                    if (wasDestroyed.destroyed)
                        return Promise.reject(new AlreadyDestroyedError());
                    if (options.disableJsonRpc)
                        return Promise.reject(new JsonRpcDisabledError());
                    return instance.nextJsonRpcResponse(chainId);
                },
                remove: () => {
                    if (alreadyDestroyedError)
                        throw alreadyDestroyedError;
                    if (wasDestroyed.destroyed)
                        throw new AlreadyDestroyedError();
                    wasDestroyed.destroyed = true;
                    console.assert(chainIds.has(newChain));
                    chainIds.delete(newChain);
                    instance.removeChain(chainId);
                },
            };
            chainIds.set(newChain, chainId);
            return newChain;
        }),
        terminate: () => __awaiter(this, void 0, void 0, function* () {
            if (alreadyDestroyedError)
                throw alreadyDestroyedError;
            alreadyDestroyedError = new AlreadyDestroyedError();
            instance.startShutdown();
        })
    };
}
