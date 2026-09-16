// Smoldot
// Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
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

// Host-agnostic JSON-RPC helper library, imported directly by shared test
// bodies (`import { createRpc } from "./rpc.js"`). It needs only a started
// smoldot `client`; the smoldot `Chain` API (`addChain`, `sendJsonRpc`,
// `jsonRpcResponses`) is identical across the Node and browser builds, so
// nothing here is host-specific. A relative sibling import resolves on both
// hosts — Node loads `shared/rpc.js` from disk; the browser host serves it at
// `/shared/rpc.js` via Playwright request interception.
//
// Each added chain gets a FIFO message queue fed by a background drain of the
// chain's `jsonRpcResponses` async iterator. The read helpers drain the queue
// front-to-back and discard messages that don't match (callers are sequenced so
// nothing needed is dropped).

export function createRpc(client) {
  let nextId = 1;
  const stores = new Map(); // chain -> { q: [] }

  // Adds a chain and starts draining its responses into a per-chain FIFO.
  async function addChain(opts) {
    const chain = await client.addChain(opts);
    const store = { q: [] };
    stores.set(chain, store);
    (async () => {
      try {
        for await (const raw of chain.jsonRpcResponses) store.q.push(JSON.parse(raw));
      } catch (_) {
        // chain removed / client terminated
      }
    })();
    return chain;
  }

  // Resolves with the next queued message for `chain`, or `undefined` at the
  // deadline. Polling keeps the implementation portable (no host timers/waiters).
  async function take(chain, deadlineMs) {
    const store = stores.get(chain);
    if (!store) throw new Error("rpc.take on a chain that was never added via this rpc");
    while (store.q.length === 0) {
      if (Date.now() >= deadlineMs) return undefined;
      await new Promise((r) => setTimeout(r, 25));
    }
    return store.q.shift();
  }

  function sendRpc(chain, method, params = []) {
    const id = nextId++;
    chain.sendJsonRpc(
      JSON.stringify({ jsonrpc: "2.0", id: id.toString(), method, params }),
    );
    return id;
  }

  // Drains messages applying `predicate`; returns the first non-`undefined`
  // predicate result, or `undefined` at the deadline.
  async function readJsonRpcUntil(chain, predicate, deadlineMs) {
    while (Date.now() < deadlineMs) {
      const msg = await take(chain, deadlineMs);
      if (msg === undefined) return undefined;
      const out = predicate(msg);
      if (out !== undefined) return out;
    }
    return undefined;
  }

  async function sendRpcAndWait(chain, method, params = [], timeoutMs = 60000) {
    const id = sendRpc(chain, method, params).toString();
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const msg = await take(chain, deadline);
      if (msg === undefined) break;
      if (msg.id === id) {
        if (msg.error) {
          const error = new Error(`RPC error for ${method}: ${JSON.stringify(msg.error)}`);
          // Carried alongside the message so a body can act on the code rather than parse it.
          error.rpcError = msg.error;
          throw error;
        }
        return msg.result;
      }
    }
    throw new Error(`Timed out waiting for ${method} response after ${timeoutMs}ms`);
  }

  async function waitForJsonRpcMatch(chain, predicate, timeoutMs = 60000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const msg = await take(chain, deadline);
      if (msg === undefined) break;
      if (predicate(msg)) return msg;
    }
    throw new Error("Timed out waiting for matching response");
  }

  return {
    addChain,
    sendRpc,
    readJsonRpcUntil,
    sendRpcAndWait,
    waitForJsonRpcMatch,
  };
}
