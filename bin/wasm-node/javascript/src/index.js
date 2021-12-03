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

import { Worker, workerOnError, workerOnMessage, workerTerminate } from './compat-nodejs.js';
export * from './health.js';

export class AlreadyDestroyedError extends Error {
}

export class AddChainError extends Error {
  constructor(message) {
    super(message);
  }
}

export class JsonRpcDisabledError extends Error {
}

export class CrashError extends Error {
  constructor(message) {
    super(message);
  }
}

export function start(config) {
  config = config || {};

  const logCallback = config.logCallback || ((level, target, message) => {
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
  //
  // The line of code below (`new Worker(...)`) is designed to hopefully work across all
  // platforms and bundlers. See the README.md for more context.
  const worker = new Worker(new URL('./worker.js', import.meta.url));
  let workerError = null;

  // Whenever an `addChain` or `removeChain` message is sent to the worker, a corresponding entry
  // is pushed to this array. The worker needs to send back a confirmation, which pops the first
  // element of this array. In the case of `addChain`, additional fields are stored in this array
  // to finish the initialization of the chain.
  let pendingConfirmations = [];

  // For each chain that is currently running, contains the callback to use to send back JSON-RPC
  // responses corresponding to this chain.
  // Entries are instantly removed when the user desires to remove a chain even before the worker
  // has confirmed the removal. Doing so avoids a race condition where the worker sends back a
  // JSON-RPC response even though we've already sent a `removeChain` message to it.
  let chainsJsonRpcCallbacks = new Map();

  // For each chain that is currently running, contains the promises corresponding to the database
  // retrieval requests.
  // Entries are instantly removed when the user desires to remove a chain even before the worker
  // has confirmed the removal. Doing so avoids a race condition where the worker sends back a
  // database content even though we've already sent a `removeChain` message to it.
  let chainsDatabaseContentPromises = new Map();

  // The worker periodically sends a message of kind 'livenessPing' in order to notify that it is
  // still alive.
  // If this liveness ping isn't received for a long time, an error is reported in the logs.
  // The first check is delayed in order to account for the fact that the worker has to perform
  // an expensive initialization step when initializing the Wasm VM.
  let livenessTimeout = null;
  const resetLivenessTimeout = () => {
    if (livenessTimeout !== null)
      clearTimeout(livenessTimeout);
    livenessTimeout = setTimeout(() => {
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
  setTimeout(() => resetLivenessTimeout(), 15000);

  // The worker can send us messages whose type is identified through a `kind` field.
  workerOnMessage(worker, (message) => {
    if (message.kind == 'jsonrpc') {
      const cb = chainsJsonRpcCallbacks.get(message.chainId);
      if (cb) cb(message.data);

    } else if (message.kind == 'chainAddedOk') {
      const expected = pendingConfirmations.shift();
      let chainId = message.chainId; // Later set to null when the chain is removed.

      if (chainsJsonRpcCallbacks.has(chainId) || chainsDatabaseContentPromises.has(chainId)) // Sanity check.
        throw 'Unexpected reuse of a chain ID';
      chainsJsonRpcCallbacks.set(chainId, expected.jsonRpcCallback);
      chainsDatabaseContentPromises.set(chainId, new Array());

      // `expected` was pushed by the `addChain` method.
      // Resolve the promise that `addChain` returned to the user.
      expected.resolve({
        sendJsonRpc: (request) => {
          if (workerError)
            throw workerError;
          if (chainId === null)
            throw new AlreadyDestroyedError();
          if (!chainsJsonRpcCallbacks.has(chainId))
            throw new JsonRpcDisabledError();
          worker.postMessage({ ty: 'request', request, chainId });
        },
        databaseContent: () => {
          if (workerError)
            return Promise.reject(workerError);
          if (chainId === null)
            return Promise.reject(new AlreadyDestroyedError());
          let resolve;
          let reject;
          const promise = new Promise((res, rej) => {
            resolve = res;
            reject = rej;
          });
          chainsDatabaseContentPromises.get(chainId).push({ resolve, reject });
          worker.postMessage({ ty: 'databaseContent', chainId });
          return promise;
        },
        remove: () => {
          if (workerError)
            throw workerError;
          if (chainId === null)
            throw new AlreadyDestroyedError();
          pendingConfirmations.push({ ty: 'chainRemoved', chainId });
          worker.postMessage({ ty: 'removeChain', chainId });
          // Because the `removeChain` message is asynchronous, it is possible for a JSON-RPC
          // response or database content concerning that `chainId` to arrive after the `remove`
          // function has returned. We solve that by removing the callback immediately.
          chainsJsonRpcCallbacks.delete(chainId);
          chainsDatabaseContentPromises.delete(chainId);
          chainId = null;
        },
        // Hacky internal method that later lets us access the `chainId` of this chain for
        // implementation reasons.
        __internal_smoldot_id: () => chainId,
      });

    } else if (message.kind == 'chainAddedErr') {
      const expected = pendingConfirmations.shift();
      // `expected` was pushed by the `addChain` method.
      // Reject the promise that `addChain` returned to the user.
      expected.reject(new AddChainError(message.error));

    } else if (message.kind == 'chainRemoved') {
      pendingConfirmations.shift();

    } else if (message.kind == 'databaseContent') {
      const promises = chainsDatabaseContentPromises.get(message.chainId);
      if (promises) promises.shift().resolve(message.data);

    } else if (message.kind == 'log') {
      logCallback(message.level, message.target, message.message);

    } else if (message.kind == 'livenessPing') {
      resetLivenessTimeout();

    } else {
      console.error('Unknown message type', message);
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
    chainsDatabaseContentPromises.forEach((chain) => {
      chain.forEach((promise) => promise.reject(workerError));
    });
    chainsDatabaseContentPromises.clear();
  });

  // The first message expected by the worker contains the configuration.
  worker.postMessage({
    // Maximum level of log entries sent by the client.
    // 0 = Logging disabled, 1 = Error, 2 = Warn, 3 = Info, 4 = Debug, 5 = Trace
    maxLogLevel: config.maxLogLevel || 3,
    forbidTcp: config.forbidTcp,
    forbidWs: config.forbidWs,
    forbidWss: config.forbidWss,
  });

  return {
    addChain: (options) => {
      if (workerError)
        throw workerError;

      let potentialRelayChainsIds = [];
      if (!!options.potentialRelayChains) {
        for (const chain of options.potentialRelayChains) {
          // The content of `options.potentialRelayChains` are supposed to be chains earlier
          // returned by `addChain`. The hacky `__internal_smoldot_id` method lets us obtain the
          // internal ID of these chains.
          const id = chain.__internal_smoldot_id();
          if (id === null) // It is possible for `id` to be null if it has earlier been removed.
            continue;
          potentialRelayChainsIds.push(id);
        }
      }

      // Build a promise that will be resolved or rejected after the chain has been added.
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
        clearTimeout(livenessTimeout)

      return workerTerminate(worker)
    }
  }
}
