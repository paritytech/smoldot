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
  report,
  readJsonRpcUntil,
  waitForMessage,
} from "./helpers.js";

const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const paraSpecPath = process.env.PARA_CHAIN_SPEC;
const topicAHex = process.env.TOPIC_A;
const stmtAHex = process.env.STATEMENT_A_HEX;
const stmtBHex = process.env.STATEMENT_B_HEX;
const SYNC_PATH = process.env.SYNC_PATH;
const LISTEN_MS = Number.parseInt(process.env.LISTEN_MS || "10000", 10);

if (
  !relaySpecPath ||
  !paraSpecPath ||
  !topicAHex ||
  !stmtAHex ||
  !stmtBHex ||
  !SYNC_PATH
) {
  console.error(
    "Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, TOPIC_A, STATEMENT_A_HEX, STATEMENT_B_HEX, SYNC_PATH",
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

  // Block until Rust signals that smoldot is peered with both collators at
  // the statement-store level. The listen window below only makes sense
  // after that point: both peers push stmt_A during their initial sync.
  await waitForMessage(SYNC_PATH, "READY");
  report("Rust signalled READY", true);

  let countA = 0;
  let countB = 0;
  let countOther = 0;
  let firstAms = null;
  let firstBms = null;
  let firstOtherMs = null;
  const listenStart = Date.now();
  const listenDeadline = listenStart + LISTEN_MS;

  await readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.method !== "statement_statement") return undefined;
      if (msg.params?.subscription !== subId) return undefined;
      const result = msg.params.result;
      if (result?.event !== "newStatements") return undefined;
      const stmts = result.data?.statements ?? [];
      const elapsed = Date.now() - listenStart;
      for (const s of stmts) {
        if (s === stmtAHex) {
          countA += 1;
          if (firstAms === null) firstAms = elapsed;
        } else if (s === stmtBHex) {
          countB += 1;
          if (firstBms === null) firstBms = elapsed;
        } else {
          countOther += 1;
          if (firstOtherMs === null) firstOtherMs = elapsed;
        }
      }
      return undefined;
    },
    listenDeadline,
  );

  const ok = countA === 1 && countB === 0 && countOther === 0;
  report(
    "reception: stmt_A received exactly once, stmt_B never, no stray statements",
    ok,
    `stmt_A first=${firstAms}ms count=${countA} | ` +
      `stmt_B first=${firstBms}ms count=${countB} | ` +
      `other first=${firstOtherMs}ms count=${countOther}`,
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
}

// Finish as soon as the result is known
process.exit(passed && !process.exitCode ? 0 : 1);
