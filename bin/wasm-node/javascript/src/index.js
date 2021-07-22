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

import { Worker, workerOnError, workerOnMessage } from './compat-nodejs.js';

export class SmoldotError extends Error {
  constructor(message) {
    super(message);
  }
}

function remove(arr, item) {
  const idx = arr.indexOf(item);
  if (idx > -1) {
      arr.splice(idx, 1);
  }
  return arr;
}

export async function start(config) {
  config = config || {};

  // Counter used to generate health request ids
  let nextHealthRequestId = 1;

  const logCallback = config.logCallback || ((level, target, message) => {
    if (level <= 1) {
      console.error("[" + target + "]", message);
    } else if (level == 2) {
      console.warn("[" + target + "]", message);
    } else if (level == 3) {
      console.info("[" + target + "]", message);
    } else if (level == 4) {
      console.debug("[" + target + "]", message);
    } else {
      console.trace("[" + target + "]", message);
    }
  });

  // The actual execution of Smoldot is performed in a worker thread.
  //
  // The line of code below (`new Worker(...)`) is designed to hopefully work across all
  // platforms. It should work in NodeJS, browsers, webpack
  // (https://webpack.js.org/guides/web-workers/), and parcel
  // (https://github.com/parcel-bundler/parcel/pull/5846)
  const worker = new Worker(new URL('./worker.js', import.meta.url));
  let workerError = null;

  // Pending health requests - their ids and the their promise resolve and reject funtions
  // [{ requestId: <n>, resolve: fn(), reject: fn() }, /* ... */ }]
  let healthRequestCallbacks =  [];

  // Whenever an `addChain` or `removeChain` message is sent to the worker, a corresponding entry
  // is pushed to this array. The worker needs to send back a confirmation, which pops the first
  // element of this array. In the case of `addChain`, additional fields are stored in this array
  // to finish the initialization of the chain.
  const pendingConfirmations = [];

  // For each chain that is currently running, contains the callback to use to send back JSON-RPC
  // responses corresponding to this chain.
  // Entries are instantly removed when the user desires to remove a chain even before the worker
  // has confirmed the removal. Doing so avoids a race condition where the worker sends back a
  // JSON-RPC response even though we've already sent a `removeChain` message to it.
  const chainsJsonRpcCallbacks = {};

  // The worker can send us messages whose type is identified through a `kind` field.
  workerOnMessage(worker, (message) => {
    if (message.kind == 'jsonrpc') {

      // check if this was a response to a health request first
      const msgdata = JSON.parse(message.data);
      if (msgdata.id && msgdata.id.startsWith('health:')) {
        const request = healthRequestCallbacks.find(r => r.requestId === msgdata.id);
        if (request) {
          // reject it if it was an error response
          if (msgdata.error) {
            remove(healthRequestCallbacks, request);
            return request.reject(new Error(msgdata.error));
          }

          // or resolve it
          remove(healthRequestCallbacks, request);
          return request.resolve(msgdata.result);
        }
      } else if (msgdata.id && msgdata.id.startsWith('user:')) {
        const cb = chainsJsonRpcCallbacks[message.chainId];
        // strip the namespace off
        msgdata.id = msgdata.id.slice('user:'.length);
        // Convert the id back to a number if it looks like one - polkadotjs
        // expects number ids
        if (/^[0-9]+$/.test(msgdata.id)) {
          msgdata.id = Number(msgdata.id);
        }
        if (cb) cb(JSON.stringify(msgdata));
      }

    } else if (message.kind == 'chainAddedOk') {
      const expected = pendingConfirmations.pop();
      const chainId = message.chainId;

      if (!!chainsJsonRpcCallbacks[chainId]) // Sanity check.
        throw 'Unexpected reuse of a chain ID';
      chainsJsonRpcCallbacks[chainId] = expected.jsonRpcCallback;

      // `expected` was pushed by the `addChain` method.
      // Resolve the promise that `addChain` returned to the user.
      expected.resolve({
        health: () => {
          // craft a new system_health messsage
          const id = 'health:' + nextHealthRequestId;
          nextHealthRequestId += 1;
          const request = JSON.stringify({ id, jsonrpc: "2.0", method: "system_health", params: [] });
          let hrResolve, hrReject;
          const hrPromise = new Promise((resolve, reject) => {
            hrResolve = resolve;
            hrReject = reject;
          });

          // track the new message
          healthRequestCallbacks.push({
            chainId,
            requestId: id,
            resolve: hrResolve,
            reject: hrReject
          });

          // send it
          worker.postMessage({ ty: 'request', request, chainId });
          return hrPromise;
        },
        sendJsonRpc: (request) => {
          if (workerError)
            throw workerError;
          if (!chainsJsonRpcCallbacks[message.chainId])
            throw new SmoldotError('Chain isn\'t capable of serving JSON-RPC requests');

          let parsed;
          try {
            parsed = JSON.parse(request);
          } catch {
            return;
          }

          const newId = 'user:' + parsed.id;
          parsed.id = newId;

          worker.postMessage({ ty: 'request', request: JSON.stringify(parsed), chainId });
        },
        remove: () => {
          if (workerError)
            throw workerError;
          pendingConfirmations.push({ ty: 'chainRemoved', chainId });
          worker.postMessage({ ty: 'removeChain', chainId });
          // clean up pending healthRequestCallbacks for this chain
          healthRequestCallbacks = healthRequestCallbacks.filter(r => r.chainId !== chainId);
          // Because the `removeChain` message is asynchronous, it is possible for a JSON-RPC
          // response concerning that `chainId` to arrive after the `remove` function has
          // returned. We solve that by removing the callback immediately.
          delete chainsJsonRpcCallbacks[message.chainId];
        },
        // Hacky internal method that later lets us access the `chainId` of this chain for
        // implementation reasons.
        __internal_smoldot_id: () => chainId,
      });

    } else if (message.kind == 'chainAddedErr') {
      const expected = pendingConfirmations.pop();
      // `expected` was pushed by the `addChain` method.
      // Reject the promise that `addChain` returned to the user.
      expected.reject(message.error);

    } else if (message.kind == 'chainRemoved') {
      pendingConfirmations.pop();

    } else if (message.kind == 'log') {
      logCallback(message.level, message.target, message.message);

    } else {
      console.error('Unknown message type', message);
    }
  });

  workerOnError(worker, (error) => {
    // A worker error should only happen in case of a critical error as the result of a bug
    // somewhere. Consequently, nothing is really in place to cleanly report the error.
    console.error(error);
    workerError = error;

    // Reject all promises returned by `addChain`.
    for (var pending of pendingConfirmations) {
      if (pending.ty == 'chainAdded')
        pending.reject(error);
    }
    pendingConfirmations = [];
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
        for (var chain of options.potentialRelayChains) {
          // The content of `options.potentialRelayChains` are supposed to be chains earlier
          // returned by `addChain`. The hacky `__internal_smoldot_id` method lets us obtain the
          // internal ID of these chains.
          const id = chain.__internal_smoldot_id();
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
        potentialRelayChains: potentialRelayChainsIds,
        jsonRpcRunning: !!options.jsonRpcCallback,
      });

      return chainAddedPromise;
    },
    terminate: () => {
      worker.terminate();
      if (!workerError)
        workerError = new Error("terminate() has been called");
    }
  }
}
