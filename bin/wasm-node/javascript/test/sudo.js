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
import * as fs from 'fs';
import { start } from "../dist/index.js";

const westendSpec = fs.readFileSync('./test/westend.json', 'utf8');

test('sudo_unstable_p2pDiscover is available', async t => {
  let promiseResolve;
  let promiseReject;
  const promise = new Promise((resolve, reject) => { promiseResolve = resolve; promiseReject = reject; });

  const client = start({ logCallback: () => { } });
  await client
    .addChain({
      chainSpec: westendSpec,
      jsonRpcCallback: (resp) => {
        const parsed = JSON.parse(resp);
        if (parsed.id == 1 && parsed.result === null)
          promiseResolve();
        else
          promiseReject(resp);
      }
    })
    .then((chain) => {
      chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"sudo_unstable_p2pDiscover","params":["/ip4/1.2.3.4/tcp/30333/p2p/12D3KooWDmQPkBvQGg9wjBdFThtWj3QCDVQyHJ1apfWrHvjwbYS8"]}', 0, 0);
    })
    .then(() => promise)
    .then(() => t.pass())
    .then(() => client.terminate());
});

test('sudo_unstable_p2pDiscover returns error on invalid multiaddr', async t => {
  let promiseResolve;
  let promiseReject;
  const promise = new Promise((resolve, reject) => { promiseResolve = resolve; promiseReject = reject; });

  const client = start({ logCallback: () => { } });
  await client
    .addChain({
      chainSpec: westendSpec,
      jsonRpcCallback: (resp) => {
        const parsed = JSON.parse(resp);
        if (parsed.id == 1 && !!parsed.error)
          promiseResolve();
        else
          promiseReject(resp);
      }
    })
    .then((chain) => {
      chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"sudo_unstable_p2pDiscover","params":["/hello/world"]}', 0, 0);
    })
    .then(() => promise)
    .then(() => t.pass())
    .then(() => client.terminate());
});

test('sudo_unstable_p2pDiscover returns error if multiaddr doesn\'t end with /p2p', async t => {
  let promiseResolve;
  let promiseReject;
  const promise = new Promise((resolve, reject) => { promiseResolve = resolve; promiseReject = reject; });

  const client = start({ logCallback: () => { } });
  await client
    .addChain({
      chainSpec: westendSpec,
      jsonRpcCallback: (resp) => {
        const parsed = JSON.parse(resp);
        if (parsed.id == 1 && !!parsed.error)
          promiseResolve();
        else
          promiseReject(resp);
      }
    })
    .then((chain) => {
      chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"sudo_unstable_p2pDiscover","params":["/ip4/127.0.0.1/tcp/30333/ws"]}', 0, 0);
    })
    .then(() => promise)
    .then(() => t.pass())
    .then(() => client.terminate());
});

test('sudo_unstable_version works', async t => {
  let promiseResolve;
  let promiseReject;
  const promise = new Promise((resolve, reject) => { promiseResolve = resolve; promiseReject = reject; });

  const client = start({ logCallback: () => { } });
  await client
    .addChain({
      chainSpec: westendSpec,
      jsonRpcCallback: (resp) => {
        const parsed = JSON.parse(resp);
        if (parsed.result.includes("smoldot"))
          promiseResolve();
        else
          promiseReject(resp);
      }
    })
    .then((chain) => {
      chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"sudo_unstable_version","params":[]}', 0, 0);
    })
    .then(() => promise)
    .then(() => t.pass())
    .then(() => client.terminate());
});
