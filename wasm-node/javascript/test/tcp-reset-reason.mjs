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

// A failed TCP dial must be reported to the client as a connection reset that
// carries the socket error, and well before the 4 second handshake timeout.

import test from 'ava';
import * as fs from 'node:fs';
import * as net from 'node:net';
import { start } from "../dist/mjs/index-nodejs.js";

const westendSpec = JSON.parse(fs.readFileSync('./test/westend.json', 'utf8'));
const peerId = "12D3KooWSz8r2WyCdsfWHgPyvD8GKQdJ1UAiRmrcrs8sQB3fe2KU";

// Starts a client whose only bootnode is `address` and resolves with the
// reason of the first `connections` `reset` log line for it, or rejects after
// `timeoutMs`.
function firstResetReason(address, timeoutMs) {
  return new Promise((resolve, reject) => {
    const spec = { ...westendSpec, bootNodes: [address] };
    let client;
    const timer = setTimeout(() => {
      client?.terminate();
      reject(new Error(`no reset reported within ${timeoutMs}ms`));
    }, timeoutMs);
    client = start({
      maxLogLevel: 5,
      logCallback: (_level, target, message) => {
        if (target !== "connections" || !message.startsWith("reset;")) return;
        const m = message.match(/reason=(.*)$/);
        clearTimeout(timer);
        client.terminate();
        resolve(m ? m[1] : "");
      },
    });
    client.addChain({ chainSpec: JSON.stringify(spec) }).catch(reject);
  });
}

// A port that nothing listens on: bind, read the port, close.
function closedPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

test('refused TCP connection is reported with ECONNREFUSED before the handshake timeout', async t => {
  const port = await closedPort();
  const started = Date.now();
  const reason = await firstResetReason(`/ip4/127.0.0.1/tcp/${port}/p2p/${peerId}`, 3000);
  t.true(reason.includes('ECONNREFUSED'), reason);
  t.true(Date.now() - started < 3000);
});

test('unresolvable TCP hostname is reported with ENOTFOUND before the handshake timeout', async t => {
  const started = Date.now();
  const reason = await firstResetReason(`/dns/does-not-exist.invalid/tcp/30333/p2p/${peerId}`, 3000);
  t.true(reason.includes('ENOTFOUND'), reason);
  t.true(Date.now() - started < 3000);
});

// `localhost` usually resolves to both `::1` and `127.0.0.1`. When every address is refused,
// NodeJS emits an `AggregateError` with an empty `message`; the reason must come from its causes.
test('multi-address TCP connection refused everywhere is reported with ECONNREFUSED', async t => {
  const port = await closedPort();
  const started = Date.now();
  const reason = await firstResetReason(`/dns/localhost/tcp/${port}/p2p/${peerId}`, 3000);
  t.true(reason.includes('ECONNREFUSED'), reason);
  t.true(Date.now() - started < 3000);
});

// Same as above, over WebSocket: the `ws` library wraps the identical NodeJS socket error.
test('multi-address WebSocket connection refused everywhere is reported with ECONNREFUSED', async t => {
  const port = await closedPort();
  const started = Date.now();
  const reason = await firstResetReason(`/dns/localhost/tcp/${port}/ws/p2p/${peerId}`, 3000);
  t.true(reason.includes('ECONNREFUSED'), reason);
  t.true(Date.now() - started < 3000);
});
