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

import {
  createSmoldotClient,
  addChainFromSpec,
  sendRpc,
  readJsonRpcUntil,
  report,
} from "./helpers.js";

const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const paraSpecPath = process.env.PARA_CHAIN_SPEC;
const requiredBlocks = Number.parseInt(process.env.REQUIRED_BLOCKS, 10);

if (!relaySpecPath || !paraSpecPath || !Number.isFinite(requiredBlocks)) {
  console.error(
    "Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, REQUIRED_BLOCKS",
  );
  process.exit(1);
}

const client = createSmoldotClient();
let relay;
let para;
let passed = true;

try {
  relay = await addChainFromSpec(client, relaySpecPath);
  report("addChain relay", true);

  para = await addChainFromSpec(client, paraSpecPath, {
    potentialRelayChains: [relay],
  });
  report("addChain parachain", true);

  const followReqId = sendRpc(para, "chainHead_v1_follow", [false]).toString();
  const subId = await readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.id === followReqId) {
        if (msg.error)
          throw new Error(
            `chainHead_v1_follow failed: ${JSON.stringify(msg.error)}`,
          );
        return msg.result;
      }
      return undefined;
    },
    Date.now() + 30_000,
  );
  if (typeof subId !== "string" || !subId) {
    throw new Error(`Unexpected follow subscription id: ${JSON.stringify(subId)}`);
  }
  report("chainHead_v1_follow accepted", true, `subId=${subId}`);

  const initialBlocks = new Set();
  let newBlocks = 0;
  await readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.method !== "chainHead_v1_followEvent") return undefined;
      if (msg.params?.subscription !== subId) return undefined;
      const result = msg.params.result;
      if (result?.event === "initialized") {
        for (const h of result.finalizedBlockHashes ?? []) initialBlocks.add(h);
      } else if (result?.event === "newBlock" && !initialBlocks.has(result.blockHash)) {
        if (++newBlocks >= requiredBlocks) return true;
      } else if (result?.event === "stop") {
        throw new Error("chainHead follow stopped unexpectedly");
      }
      return undefined;
    },
    Date.now() + 120_000,
  );

  const ok = newBlocks >= requiredBlocks;
  report(
    "smoldot saw new parachain blocks",
    ok,
    `count=${newBlocks}/${requiredBlocks}`,
  );
  if (!ok) passed = false;
} catch (e) {
  report("smoke", false, e.message);
  passed = false;
} finally {
  try {
    await client.terminate();
  } catch (_) {}
}

if (!passed || process.exitCode) {
  process.exit(1);
}
