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

import test from 'ava';
import * as fs from 'node:fs';
import { start } from "../dist/mjs/index-nodejs.js";

const westendSpec = fs.readFileSync('./test/westend.json', 'utf8');

test('invalid chain spec throws error', async t => {
  const client = start({ logCallback: () => { } });
  await client
    .addChain({
      chainSpec: "invalid chain spec",
    })
    .then((chain) => t.fail())
    .catch(() => t.pass())
    .then(() => client.terminate());
});

test('system_name works', async t => {
  const client = start({ logCallback: () => { } });
  await client
    .addChain({ chainSpec: westendSpec })
    .then((chain) => {
      chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"system_name","params":[]}');
      return chain;
    })
    .then(async (chain) => {
      const response = await chain.nextJsonRpcResponse();
      t.assert(response === '{"jsonrpc":"2.0","id":1,"result":"smoldot-light-wasm"}');
      t.pass();
    })
    .then(() => client.terminate());
});

// An exception thrown by JavaScript code called from within the Wasm (such as a platform
// binding, or, here, the `logCallback`) unwinds through the Wasm frames without the Rust code
// being aware of it, leaving the instance unusable. This test verifies that the client detects
// this situation and turns it into a proper crash, instead of silently leaving a broken client
// behind. See <https://github.com/paritytech/smoldot/issues/3302>.
test('exception thrown from a callback crashes the client cleanly', async t => {
  // `logCallback` is called synchronously from within the Wasm, making it a stand-in for
  // any JavaScript binding that throws (like the platform `connect()` in #3302).
  let throwRequested = false;
  const client = start({
    maxLogLevel: 4,  // Debug logs, so that background tasks emit log lines frequently.
    logCallback: () => {
      if (throwRequested)
        throw new Error("boom from logCallback");
    }
  });

  // Arm the throw only after `addChain`, so that it fires from within the background
  // execution of tasks rather than from `addChain` itself, which handles errors on its own.
  const chain = await client.addChain({ chainSpec: westendSpec });
  const pendingResponse = chain.nextJsonRpcResponse();
  throwRequested = true;

  // No request was sent, so this promise settles only if the crash releases it.
  // If the exception were swallowed, the test would fail by timing out.
  await t.throwsAsync(pendingResponse);

  // A crashed client reports the original exception as the cause, not a generic error.
  await t.throwsAsync(
    client.addChain({ chainSpec: westendSpec }),
    { message: /boom from logCallback/ }
  );
});
