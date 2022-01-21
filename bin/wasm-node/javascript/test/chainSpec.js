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
import { start } from "../dist/index.js";

const westendSpec = fs.readFileSync('./test/westend.json', 'utf8');

test('chainSpec_chainName works', async t => {
  let promiseResolve;
  let promiseReject;
  const promise = new Promise((resolve, reject) => { promiseResolve = resolve; promiseReject = reject; });

  const client = start({ logCallback: () => { } });
  await client
    .addChain({
      chainSpec: westendSpec,
      jsonRpcCallback: (resp) => {
        const parsed = JSON.parse(resp);
        if (parsed.result == "Westend")
          promiseResolve();
        else
          promiseReject(resp);
      }
    })
    .then((chain) => {
      chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"chainSpec_unstable_chainName","params":[]}', 0, 0);
    })
    .then(() => promise)
    .then(() => t.pass())
    .then(() => client.terminate());
});

test('chainSpec_unstable_genesisHash works', async t => {
  let promiseResolve;
  let promiseReject;
  const promise = new Promise((resolve, reject) => { promiseResolve = resolve; promiseReject = reject; });

  const client = start({ logCallback: () => { } });
  await client
    .addChain({
      chainSpec: westendSpec,
      jsonRpcCallback: (resp) => {
        const parsed = JSON.parse(resp);
        if (parsed.result.toLowerCase() == "0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e")
          promiseResolve();
        else
          promiseReject(resp);
      }
    })
    .then((chain) => {
      chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"chainSpec_unstable_genesisHash","params":[]}', 0, 0);
    })
    .then(() => promise)
    .then(() => t.pass())
    .then(() => client.terminate());
});

test('chainSpec_unstable_properties works', async t => {
  let promiseResolve;
  let promiseReject;
  const promise = new Promise((resolve, reject) => { promiseResolve = resolve; promiseReject = reject; });

  const client = start({ logCallback: () => { } });
  await client
    .addChain({
      chainSpec: westendSpec,
      jsonRpcCallback: (resp) => {
        const parsed = JSON.parse(resp);
        if (parsed.result.ss58Format == 42 && parsed.result.tokenDecimals == 12 && parsed.result.tokenSymbol == "WND")
          promiseResolve();
        else
          promiseReject(resp);
      }
    })
    .then((chain) => {
      chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"chainSpec_unstable_properties","params":[]}', 0, 0);
    })
    .then(() => promise)
    .then(() => t.pass())
    .then(() => client.terminate());
});
