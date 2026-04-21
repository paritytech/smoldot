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

// Regression test for #3202: parachain cold start (no databaseContent) must
// produce a chainHead_v1_follow `initialized` event with a non-null
// `finalizedBlockRuntime`.
//
// Requires network connectivity. Run from wasm-node/javascript/:
//   node test/parachain-cold-start.mjs
//
// Before the fix, the bootstrap downloaded and compiled the runtime but
// discarded it, so `initialized` never arrived.

import * as fs from 'node:fs';
import { start } from '../dist/mjs/index-nodejs.js';

const TIMEOUT_MS = Number.parseInt(process.env.SMOLDOT_TIMEOUT_MS ?? '180000', 10);

const relaySpec = fs.readFileSync(
  new URL('../../../demo-chain-specs/westend2.json', import.meta.url),
  'utf8',
);
const paraSpec = fs.readFileSync(
  new URL('../../../demo-chain-specs/westend2_asset_hub.json', import.meta.url),
  'utf8',
);

const client = start({ maxLogLevel: 3, logCallback: () => {} });

const relay = await client.addChain({ chainSpec: relaySpec });
const para = await client.addChain({
  chainSpec: paraSpec,
  potentialRelayChains: [relay],
});

para.sendJsonRpc(
  '{"jsonrpc":"2.0","id":1,"method":"chainHead_v1_follow","params":[true]}',
);

// Subscription response
const sub = JSON.parse(await para.nextJsonRpcResponse());
if (!sub.result) {
  console.error('FAIL: no subscription id', sub);
  process.exit(1);
}

const deadline = Date.now() + TIMEOUT_MS;

while (Date.now() < deadline) {
  const msg = await Promise.race([
    para.nextJsonRpcResponse(),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('timeout')), deadline - Date.now()),
    ),
  ]);

  const parsed = JSON.parse(msg);
  if (parsed.params?.result?.event === 'initialized') {
    const runtime = parsed.params.result.finalizedBlockRuntime;
    if (runtime && runtime.spec?.specName) {
      console.log(
        `PASS: initialized event received, spec=${runtime.spec.specName} v${runtime.spec.specVersion}`,
      );
      client.terminate();
      process.exit(0);
    } else {
      console.error('FAIL: initialized event has no runtime', JSON.stringify(parsed, null, 2));
      client.terminate();
      process.exit(1);
    }
  }
}

console.error(`FAIL: no initialized event within ${TIMEOUT_MS}ms`);
client.terminate();
process.exit(1);
