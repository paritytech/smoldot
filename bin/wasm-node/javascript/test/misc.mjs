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

test('too large json-rpc requests rejected', async t => {
  let promiseResolve;
  let promiseReject;
  const promise = new Promise((resolve, reject) => { promiseResolve = resolve; promiseReject = reject; });

  // Generate a very long string. We start with a length of 1 and double for every iteration.
  // Thus the final length of the string is `2^i` where `i` is the number of iterations.
  let veryLongString = 'a';
  for (let i = 0; i < 27; ++i) {
    veryLongString += veryLongString;
  }

  const client = start({ logCallback: () => { } });
  await client
    .addChain({
      chainSpec: westendSpec,
      jsonRpcCallback: (resp) => { promiseReject(resp) }
    })
    .then((chain) => {
      // The test succeeds if a certain time passes without a response.
      setTimeout(() => promiseResolve(), 2000);
      // We use `JSON.stringify` in order to be certain that the request is valid JSON.
      chain.sendJsonRpc(JSON.stringify({ "jsonrpc": "2.0", "id": 1, "method": "foo", "params": [veryLongString] }));
    })
    .then(() => promise)
    .then(() => t.pass())
    .then(() => client.terminate());
});
