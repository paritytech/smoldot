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

import test from 'ava';
import * as fs from 'fs';
import { start } from "../src/index.js";

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
  let promiseResolve;
  const promise = new Promise((resolve, reject) => promiseResolve = resolve);

  const client = start({ logCallback: () => { } });
  await client
    .addChain({
      chainSpec: westendSpec,
      jsonRpcCallback: (resp) => {
        if (resp == '{"jsonrpc":"2.0","id":1,"result":"smoldot-light-wasm"}') {
          promiseResolve();
        }
      }
    })
    .then((chain) => {
      chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"system_name","params":[]}', 0, 0);
    })
    .then(() => promise)
    .then(() => t.pass())
    .then(() => client.terminate());
});
