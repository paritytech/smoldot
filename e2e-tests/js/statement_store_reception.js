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
  sendRpcAndWait,
  report,
  readJsonRpcUntil,
} from "./helpers.js";

const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const paraSpecPath = process.env.PARA_CHAIN_SPEC;
const topicAHex = process.env.TOPIC_A;
const stmtAHex = process.env.STATEMENT_A_HEX;
const stmtBHex = process.env.STATEMENT_B_HEX;
const LISTEN_MS = Number.parseInt(process.env.LISTEN_MS || "60000", 10);

if (!relaySpecPath || !paraSpecPath || !topicAHex || !stmtAHex || !stmtBHex) {
  console.error(
    "Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, TOPIC_A, STATEMENT_A_HEX, STATEMENT_B_HEX",
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
    statementStore: {},
    potentialRelayChains: [relay],
  });
  report("addChain parachain with statementStore", true);

  const subReqId = sendRpc(para, "statement_subscribeStatement", [
    { matchAny: [topicAHex] },
  ]).toString();

  const subId = await readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.id === subReqId) {
        if (msg.error)
          throw new Error(
            `statement_subscribeStatement failed: ${JSON.stringify(msg.error)}`,
          );
        return msg.result;
      }
      return undefined;
    },
    Date.now() + 20_000,
  );
  if (typeof subId !== "string" || subId.length === 0) {
    throw new Error(`Unexpected subscription id: ${JSON.stringify(subId)}`);
  }
  report("statement_subscribeStatement accepted", true, `subId=${subId}`);

  // Wait until smoldot is connected to both collators. The dedup assertion
  // below is only meaningful if both peers are pushing the same statements.
  const peerDeadline = Date.now() + 60_000;
  let peers = 0;
  while (Date.now() < peerDeadline) {
    const health = await sendRpcAndWait(para, "system_health");
    peers = health?.peers ?? 0;
    if (peers >= 2) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  if (peers < 2) {
    throw new Error(`smoldot only connected to ${peers} peers (expected >= 2)`);
  }
  report("smoldot connected to both collators", true, `peers=${peers}`);

  // Listen for notifications. The statements were submitted on collator-0
  // before this process started, so they arrive via statement-store gossip
  // once smoldot peers with the collators.
  let countA = 0;
  let countB = 0;
  let countOther = 0;
  const listenDeadline = Date.now() + LISTEN_MS;

  await readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.method !== "statement_statement") return undefined;
      if (msg.params?.subscription !== subId) return undefined;
      const result = msg.params.result;
      if (result?.event !== "newStatements") return undefined;
      const stmts = result.data?.statements ?? [];
      for (const s of stmts) {
        if (s === stmtAHex) countA += 1;
        else if (s === stmtBHex) countB += 1;
        else countOther += 1;
      }
      return undefined;
    },
    listenDeadline,
  );

  const ok = countA === 1 && countB === 0 && countOther === 0;
  report(
    "reception: stmt_A received exactly once, stmt_B never, no stray statements",
    ok,
    `countA=${countA}, countB=${countB}, other=${countOther}`,
  );
  if (!ok) passed = false;

  // Unsubscribe as a best-effort cleanup. Terminating the client implicitly
  // removes the subscription; we don't fail the test on the RPC round-trip
  // since pending notifications may delay the response past our budget.
  try {
    sendRpc(para, "statement_unsubscribeStatement", [subId]);
  } catch (_) {}
} catch (e) {
  report("statement_store_reception", false, e.message);
  passed = false;
} finally {
  try {
    await client.terminate();
  } catch (_) {}
}

if (!passed || process.exitCode) {
  process.exit(1);
}
