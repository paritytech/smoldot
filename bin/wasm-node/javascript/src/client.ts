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
import * as messages from './worker/messages.js';
import spawnWorker from './worker/spawn.js';

/**
 * Thrown in case of a problem when initializing the chain.
 */
export class AddChainError extends Error {
  constructor(message: string) {
    super(message);
  }
}

/**
 * Thrown in case the API user tries to use a chain or client that has already been destroyed.
 */
export class AlreadyDestroyedError extends Error {
}

/**
 * Thrown when trying to send a JSON-RPC message to a chain whose JSON-RPC system hasn't been
 * enabled.
 */
export class JsonRpcDisabledError extends Error {
}

/**
 * Thrown in case the underlying client encounters an unexpected crash.
 *
 * This is always an internal bug in smoldot and is never supposed to happen.
 */
export class CrashError extends Error {
  constructor(message: string) {
    super(message);
  }
}

/**
 * Client with zero or more active connections to blockchains.
 */
export interface Client {
  /**
   * Connects to a chain.
   *
   * Throws an exception if the chain specification isn't valid, or if the chain specification
   * concerns a parachain but no corresponding relay chain can be found.
   *
   * Smoldot will automatically de-duplicate chains if multiple identical chains are added, in
   * order to save resources. In other words, it is not a problem to call `addChain` multiple
   * times with the same chain specifications and obtain multiple `SmoldotChain`.
   * When the same client is used for multiple different purposes, you are in fact strongly
   * encouraged to trust smoldot and not attempt to de-duplicate chains yourself, as determining
   * whether two chains are identical is complicated and might have security implications.
   *
   * Smoldot tries to distribute CPU resources equally between all active `SmoldotChain` objects.
   *
   * @param options Configuration of the chain to add.
   *
   * @throws {AddChainError} If the chain can't be added.
   * @throws {AlreadyDestroyedError} If the client has been terminated earlier.
   * @throws {CrashError} If the background client has crashed.
   */
  addChain(options: AddChainOptions): Promise<Chain>;

  /**
   * Terminates the client.
   *
   * Afterwards, trying to use the client or any of its chains again will lead to an exception
   * being thrown.
   *
   * @throws {AlreadyDestroyedError} If the client has already been terminated earlier.
   * @throws {CrashError} If the background client has crashed.
   */
  terminate(): Promise<void>;
}

/**
 * Active connection to a blockchain.
 */
export interface Chain {
  /**
   * Enqueues a JSON-RPC request that the client will process as soon as possible.
   *
   * The response will be sent back using the callback passed when adding the chain.
   *
   * See <https://www.jsonrpc.org/specification> for a specification of the JSON-RPC format. Only
   * version 2 is supported.
   * Be aware that some requests will cause notifications to be sent back using the same callback
   * as the responses.
   *
   * No response is generated if the request isn't a valid JSON-RPC request or if the request is
   * unreasonably large (8 MiB at the time of writing of this comment). The request is then
   * silently discarded.
   * If, however, the request is a valid JSON-RPC request but that concerns an unknown method, a
   * error response is properly generated.
   *
   * Two JSON-RPC APIs are supported by smoldot:
   *
   * - The "legacy" one, documented here: <https://polkadot.js.org/docs/substrate/rpc>
   * - The more recent one: <https://github.com/paritytech/json-rpc-interface-spec>
   *
   * @param rpc JSON-encoded RPC request.
   *
   * @throws {AlreadyDestroyedError} If the chain has been removed or the client has been terminated.
   * @throws {JsonRpcDisabledError} If no JSON-RPC callback was passed in the options of the chain.
   * @throws {CrashError} If the background client has crashed.
   */
  sendJsonRpc(rpc: string): void;

  /**
   * Serializes the important information about the state of the chain so that it can be provided
   * back in the {AddChainOptions.databaseContent} when the chain is recreated.
   *
   * The content of the string is opaque and shouldn't be decoded.
   *
   * A parameter can be passed to indicate the maximum length of the returned value (in number
   * of bytes this string would occupy in the UTF-8 encoding). The higher this limit is the more
   * information can be included. This parameter is optional, and not passing any value means
   * "unbounded".
   *
   * @throws {AlreadyDestroyedError} If the chain has been removed or the client has been terminated.
   * @throws {CrashError} If the background client has crashed.
   */
  databaseContent(maxUtf8BytesSize?: number): Promise<string>;

  /**
   * Disconnects from the blockchain.
   *
   * The JSON-RPC callback will no longer be called.
   *
   * Trying to use the chain again will lead to an exception being thrown.
   *
   * If this chain is a relay chain, then all parachains that use it will continue to work. Smoldot
   * automatically keeps alive all relay chains that have an active parachains. There is no need
   * to track parachains and relaychains, or to destroy them in the correct order, as this is
   * handled automatically.
   *
   * @throws {AlreadyDestroyedError} If the chain has been removed or the client has been terminated.
   * @throws {CrashError} If the background client has crashed.
   */
  remove(): void;
}

/**
 * @param JSON-RPC-formatted response.
 */
export type JsonRpcCallback = (response: string) => void;

/**
 * @param level How important this message is. 1 = Error, 2 = Warn, 3 = Info, 4 = Debug, 5 = Trace
 * @param target Name of the sub-system that the message concerns.
 * @param message Human-readable message that developers can use to figure out what is happening.
 */
export type LogCallback = (level: number, target: string, message: string) => void;

/**
 * Configuration of a client.
 */
export interface ClientOptions {
  /**
   * Callback that the client will invoke in order to report a log event.
   */
  logCallback?: LogCallback;

  /**
   * The client will never call the callback with a value of `level` superior to this value.
   * Defaults to 3.
   *
   * While this filtering could be done directly by the `logCallback`, passing a maximum log level
   * leads to better performances as the client doesn't even need to generate a `message` when it
   * knows that this message isn't interesting.
   */
  maxLogLevel?: number;

  /**
   * If `true`, then the client will never open any TCP connection.
   * Defaults to `false`.
   *
   * This option can be used in order to mimic an environment where the TCP protocol isn't
   * supported (e.g. browsers) from an environment where TCP is supported (e.g. NodeJS).
   *
   * This option has no effect in environments where the TCP protocol isn't supported anyway.
   */
  forbidTcp?: boolean;

  /**
   * If `true`, then the client will never open any non-secure WebSocket connection.
   * Defaults to `false`.
   *
   * This option can be used in order to mimic an environment where non-secure WebSocket
   * connections aren't supported (e.g. web pages) from an environment where they are supported
   * (e.g. NodeJS).
   *
   * This option has no effect in environments where non-secure WebSocket connections aren't
   * supported anyway.
   */
  forbidWs?: boolean;

  /**
   * If `true`, then the client will never open any non-secure WebSocket connection to addresses
   * other than `localhost` or `127.0.0.1`.
   * Defaults to `false`.
   *
   * This option is similar to `forbidWs`, except that connections to `localhost` and `127.0.0.1`
   * do not take the value of this option into account.
   *
   * This option can be used in order to mimic an environment where non-secure WebSocket
   * connections aren't supported (e.g. web pages) from an environment where they are supported
   * (e.g. NodeJS).
   *
   * This option has no effect in environments where non-secure WebSocket connections aren't
   * supported anyway.
   */
  forbidNonLocalWs?: boolean;

  /**
   * If `true`, then the client will never open any secure WebSocket connection.
   * Defaults to `false`.
   *
   * This option exists of the sake of completeness. All environments support secure WebSocket
   * connections.
   */
  forbidWss?: boolean;
}

/**
 * Configuration of a blockchain.
 */
export interface AddChainOptions {
  /**
   * JSON-encoded specification of the chain.
   *
   * The specification of the chain can be generated from a Substrate node by calling
   * `<client> build-spec --raw > spec.json`. Only "raw" chain specifications are supported by
   * smoldot at the moment.
   *
   * If the chain specification contains a `relay_chain` field, then smoldot will try to match
   * the value in `relay_chain` with the value in `id` of the chains in `potentialRelayChains`.
   */
  chainSpec: string;

  /**
   * Content of the database of this chain. Can be obtained with {Client.databaseContent}.
   *
   * Smoldot reserves the right to change its database format, making previous databases
   * incompatible. For this reason, no error is generated if the content of the database is invalid
   * and/or can't be decoded.
   *
   * Important: please note that using a malicious database content can lead to a security
   * vulnerability. This database content is considered by smoldot as trusted input. It is the
   * responsibility of the API user to make sure that the value passed in this field comes from
   * the same source of trust as the chain specification that was used when retrieving this
   * database content.
   */
  databaseContent?: string;

  /**
   * If `chainSpec` concerns a parachain, contains the list of chains whose `id` smoldot will try
   * to match with the parachain's `relay_chain`.
   * Defaults to `[]`.
   *
   * Must contain exactly the objects that were returned by previous calls to `addChain`. The
   * library uses a `WeakMap` in its implementation in order to identify chains.
   *
   * The primary way smoldot determines which relay chain is associated to a parachain is by
   * inspecting the chain specification of that parachain (i.e. the `chainSpec` field).
   *
   * This poses a problem in situations where the same client is shared between multiple different
   * applications: multiple applications could add mutiple different chains with the same `id`,
   * creating an ambiguity, or an application could register malicious chains with small variations
   * of a popular chain's `id` and try to benefit from a typo in a legitimate application's
   * `relay_chain`.
   *
   * These problems can be solved by using this parameter to segregate multiple different uses of
   * the same client. To use it, pass the list of all chains that the same application has
   * previously added to the client. By doing so, you are guaranteed that the chains of multiple
   * different applications can't interact in any way (good or bad), while still benefiting from
   * the de-duplication of resources that smoldot performs in `addChain`.
   *
   * When multiple different parachains use the same relay chain, it is important to be sure that
   * they are indeed using the same relay chain, and not accidentally using different ones. For
   * this reason, this parameter is a list of potential relay chains in which only one chain
   * should match, rather than a single `SmoldotChain` corresponding to the relay chain.
   */
  potentialRelayChains?: Chain[];

  /**
   * Callback invoked by smoldot in response to calling `sendJsonRpc`.
   */
  jsonRpcCallback?: JsonRpcCallback;
}

/**
 * Initializes a new client. This is a pre-requisite to connecting to a blockchain.
 *
 * Can never fail.
 *
 * @param options Configuration of the client. Defaults to `{}`.
 */
export function start(options?: ClientOptions): Client {
  options = options || {};

  const logCallback = options.logCallback || ((level, target, message) => {
    // The first parameter of the methods of `console` has some printf-like substitution
    // capabilities. We don't really need to use this, but not using it means that the logs might
    // not get printed correctly if they contain `%`.
    if (level <= 1) {
      console.error("[%s] %s", target, message);
    } else if (level == 2) {
      console.warn("[%s] %s", target, message);
    } else if (level == 3) {
      console.info("[%s] %s", target, message);
    } else if (level == 4) {
      console.debug("[%s] %s", target, message);
    } else {
      console.trace("[%s] %s", target, message);
    }
  });

  // The actual execution of Smoldot is performed in a worker thread.
  // Because this specific line of code is a bit sensitive, it is done in a separate file.
  const worker = spawnWorker();
  let workerError: null | Error = null;

  // Whenever an `addChain` or `removeChain` message is sent to the worker, a corresponding entry
  // is pushed to this array. The worker needs to send back a confirmation, which pops the first
  // element of this array. In the case of `addChain`, additional fields are stored in this array
  // to finish the initialization of the chain.
  let pendingConfirmations: PendingConfirmation[] = [];

  // Contains the information of each chain that is currently.
  // Entries are instantly removed when the user desires to remove a chain even before the worker
  // has confirmed the removal. Doing so avoids a race condition where the worker sends back a
  // database content or a JSON-RPC response/notification even though we've already sent a
  // `removeChain` message to it.
  //
  // This map is also used in general as a way to check whether a chain still exists.
  let chains: Map<number, {
    jsonRpcCallback?: JsonRpcCallback,
    databasePromises: DatabasePromise[],
  }> = new Map();

  // For each chain object returned by `addChain`, the associated internal chain id.
  //
  // Immediately cleared when `remove()` is called on a chain.
  let chainIds: WeakMap<Chain, number> = new WeakMap();

  // The worker periodically sends a message of kind 'livenessPing' in order to notify that it is
  // still alive.
  // If this liveness ping isn't received for a long time, an error is reported in the logs.
  // The first check is delayed in order to account for the fact that the worker has to perform
  // an expensive initialization step when initializing the Wasm VM.
  let livenessTimeout: null | ReturnType<typeof globalThis.setTimeout> = null;
  const resetLivenessTimeout = () => {
    if (livenessTimeout !== null)
      globalThis.clearTimeout(livenessTimeout);
    livenessTimeout = globalThis.setTimeout(() => {
      livenessTimeout = null;
      console.warn(
        "Smoldot appears unresponsive. Please open an issue at " +
        "https://github.com/paritytech/smoldot/issues. If you have a debugger available, " +
        "please pause execution, generate a stack trace of the thread that isn't the main " +
        "execution thread, and paste it in the issue. Please also include any other log found " +
        "in the console or elsewhere."
      );
    }, 10000);
  };
  globalThis.setTimeout(() => resetLivenessTimeout(), 15000);

  // The worker can send us messages whose type is identified through a `kind` field.
  workerOnMessage(worker, (message: messages.FromWorker): void => {
    switch (message.kind) {
      case 'jsonrpc': {
        const cb = chains.get(message.chainId)?.jsonRpcCallback;
        if (cb) cb(message.data);
        break;
      }

      case 'chainAddedOk': {
        const expected = pendingConfirmations.shift()!;
        const chainId = message.chainId;

        if (chains.has(chainId)) // Sanity check.
          throw 'Unexpected reuse of a chain ID';
        chains.set(chainId, {
          jsonRpcCallback: expected.jsonRpcCallback,
          databasePromises: new Array()
        });

        // `expected` was pushed by the `addChain` method.
        // Resolve the promise that `addChain` returned to the user.
        const newChain: Chain = {
          sendJsonRpc: (request) => {
            if (workerError)
              throw workerError;
            if (!chains.has(chainId))
              throw new AlreadyDestroyedError();
            if (!(chains.get(chainId)?.jsonRpcCallback))
              throw new JsonRpcDisabledError();
            if (request.length >= 8 * 1024 * 1024)
              return;
            worker.postMessage({ ty: 'request', request, chainId });
          },
          databaseContent: (maxUtf8BytesSize) => {
            if (workerError)
              return Promise.reject(workerError);

            const databaseContentPromises = chains.get(chainId)?.databasePromises;
            if (!databaseContentPromises)
              return Promise.reject(new AlreadyDestroyedError());

            // TODO: because of https://github.com/microsoft/TypeScript/issues/11498 we need to define the callbacks as possibly null, and go through `unknown`
            let resolve;
            let reject;
            const promise: Promise<string> = new Promise((res, rej) => {
              resolve = res;
              reject = rej;
            });
            databaseContentPromises.push({
              resolve: resolve as unknown as (data: string) => void,
              reject: reject as unknown as (error: Error) => void,
            });

            const twoPower32 = (1 << 30) * 4;  // `1 << 31` and `1 << 32` in JavaScript don't give the value that you expect.
            const maxSize = maxUtf8BytesSize || (twoPower32 - 1);
            const cappedMaxSize = (maxSize >= twoPower32) ? (twoPower32 - 1) : maxSize;

            worker.postMessage({ ty: 'databaseContent', chainId, maxUtf8BytesSize: cappedMaxSize });

            return promise;
          },
          remove: () => {
            if (workerError)
              throw workerError;
            if (!chains.has(chainId))
              throw new AlreadyDestroyedError();
            worker.postMessage({ ty: 'removeChain', chainId });
            // Because the `removeChain` message is asynchronous, it is possible for a JSON-RPC
            // response or database content concerning that `chainId` to arrive after the `remove`
            // function has returned. We solve that by removing the information immediately.
            chains.delete(chainId);
            chainIds.delete(newChain);
          },
        };

        chainIds.set(newChain, chainId);
        expected.resolve(newChain);
        break;
      }

      case 'chainAddedErr': {
        const expected = pendingConfirmations.shift()!;
        // `expected` was pushed by the `addChain` method.
        // Reject the promise that `addChain` returned to the user.
        expected.reject(message.error as AddChainError);
        break;
      }

      case 'databaseContent': {
        const promises = chains.get(message.chainId)?.databasePromises;
        if (promises) (promises.shift() as DatabasePromise).resolve(message.data);
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

      default: {
        // Exhaustive check.
        const _exhaustiveCheck: never = message;
        return _exhaustiveCheck;
      }
    }
  });

  workerOnError(worker, (error) => {
    // A worker error should only happen in case of a critical error as the result of a bug
    // somewhere. Consequently, nothing is really in place to cleanly report the error.
    console.error(
      "Smoldot has panicked. This is a bug in smoldot. Please open an issue at " +
      "https://github.com/paritytech/smoldot/issues with the following message:"
    );
    console.error(error);
    workerError = new CrashError(error.toString());

    // Reject all promises returned by `addChain`.
    for (var pending of pendingConfirmations) {
      if (pending.ty == 'chainAdded')
        pending.reject(workerError);
    }
    pendingConfirmations = [];

    // Reject all promises for database contents.
    for (const chain of chains) {
      for (const promise of chain[1].databasePromises) {
        promise.reject(workerError)
      }
    }
    chains.clear();
  });

  // The first message expected by the worker contains the configuration.
  worker.postMessage({
    // Maximum level of log entries sent by the client.
    // 0 = Logging disabled, 1 = Error, 2 = Warn, 3 = Info, 4 = Debug, 5 = Trace
    maxLogLevel: options.maxLogLevel || 3,
    forbidTcp: options.forbidTcp,
    forbidWs: options.forbidWs,
    forbidNonLocalWs: options.forbidNonLocalWs,
    forbidWss: options.forbidWss,
  });

  return {
    addChain: (options: AddChainOptions): Promise<Chain> => {
      if (workerError)
        throw workerError;

      let potentialRelayChainsIds = [];
      if (!!options.potentialRelayChains) {
        for (const chain of options.potentialRelayChains) {
          // The content of `options.potentialRelayChains` are supposed to be chains earlier
          // returned by `addChain`.
          const id = chainIds.get(chain);
          if (id === null) // It is possible for `id` to be null if it has earlier been removed.
            continue;
          potentialRelayChainsIds.push(id);
        }
      }

      // Build a promise that will be resolved or rejected after the chain has been added.
      // TODO: because of https://github.com/microsoft/TypeScript/issues/11498 we need to define the callbacks as possibly null, and go through `unknown`
      let chainAddedPromiseResolve;
      let chainAddedPromiseReject;
      const chainAddedPromise: Promise<Chain> = new Promise((resolve, reject) => {
        chainAddedPromiseResolve = resolve;
        chainAddedPromiseReject = reject;
      });

      pendingConfirmations.push({
        ty: 'chainAdded',
        reject: chainAddedPromiseReject as unknown as (error: AddChainError) => void,
        resolve: chainAddedPromiseResolve as unknown as (c: Chain) => void,
        jsonRpcCallback: options.jsonRpcCallback,
      });

      worker.postMessage({
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
        return Promise.reject(workerError)
      workerError = new AlreadyDestroyedError();

      if (livenessTimeout !== null)
        globalThis.clearTimeout(livenessTimeout)

      return workerTerminate(worker)
    }
  }
}

interface PendingConfirmation {
  ty: 'chainAdded',
  resolve: (c: Chain) => void,
  reject: (error: AddChainError) => void,
  jsonRpcCallback?: JsonRpcCallback,
}

interface DatabasePromise {
  resolve: (data: string) => void,
  reject: (error: Error) => void,
}
