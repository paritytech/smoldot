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

test('chainHead_unstable_follow works', async t => {
  const client = start({ logCallback: () => { } });
  await client
    .addChain({ chainSpec: westendSpec })
    .then((chain) => {
      chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"chainHead_unstable_follow","params":[false]}');
      return chain;
    })
    .then(async (chain) => {
      // Subscription response.
      await chain.nextJsonRpcResponse();
      return chain;
    })
    .then(async (chain) => {
      const parsed = JSON.parse(await chain.nextJsonRpcResponse());
      if (parsed.params.result.event == "initialized") {
        if (parsed.params.result.finalizedBlockHash.toLowerCase() == "0x9d34c5a7a8ad8d73c7690a41f7a9d1a7c46e21dc8fb1638aee6ef07f45b65158" && !parsed.params.result.finalizedBlockRuntime)
          t.pass();
        else
          t.fail(response);
      }
      return chain;
    })
    .then(() => client.terminate());
});

test('chainHead_unstable_unfollow works', async t => {
  const client = start({ logCallback: () => { } });
  await client
    .addChain({ chainSpec: westendSpec })
    .then((chain) => {
      chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"chainHead_unstable_follow","params":[false]}');
      return chain;
    })
    .then(async (chain) => {
      const parsed = JSON.parse(await chain.nextJsonRpcResponse());
      t.assert(parsed.id === 1);
      chain.sendJsonRpc('{"jsonrpc":"2.0","id":2,"method":"chainHead_unstable_unfollow","params":[' + JSON.stringify(parsed.result) + ']}');
      return chain;
    })
    .then(async (chain) => {
      while (true) {
        const parsed = JSON.parse(await chain.nextJsonRpcResponse());
        if (parsed.id === 2 && parsed.result === null) {
          t.pass();
          break;
        }
      }
    })
    .then(() => client.terminate());
});

test('chainHead_unstable_body works', async t => {
  const client = start({ logCallback: () => { } });
  await client
    .addChain({ chainSpec: westendSpec })
    .then((chain) => {
      chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"chainHead_unstable_follow","params":[false]}');
      return chain;
    })
    .then(async (chain) => {
      const parsed = JSON.parse(await chain.nextJsonRpcResponse());
      t.assert(parsed.id === 1);
      return [chain, parsed.result];
    })
    .then(async ([chain, followSubscription]) => {
      const parsed = JSON.parse(await chain.nextJsonRpcResponse());
      t.assert(parsed.method == "chainHead_unstable_followEvent" && parsed.params.subscription == followSubscription);
      if (parsed.params.result.event == "initialized") {
        if (parsed.params.result.finalizedBlockHash.toLowerCase() != "0x9d34c5a7a8ad8d73c7690a41f7a9d1a7c46e21dc8fb1638aee6ef07f45b65158")
          t.fail(parsed);
        chain.sendJsonRpc(JSON.stringify({ "jsonrpc": "2.0", "id": 1, "method": "chainHead_unstable_body", "params": [followSubscription, parsed.params.result.finalizedBlockHash] }));
      }
      return chain;
    })
    .then(async (chain) => {
      while (true) {
        const parsed = JSON.parse(await chain.nextJsonRpcResponse());
        if (parsed.method == "chainHead_unstable_bodyEvent" && parsed.params.result.event == "inaccessible") {
          t.pass();
          break;
        }
      }
    })
    .then(() => client.terminate());
});
