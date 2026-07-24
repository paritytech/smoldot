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

// Statement-store ping/pong test body — runs on either host via the ctx
// abstraction. A single smoldot client exercises both gossip directions in
// one session:
//   1. Subscribe to topic_B early, so the stmt_B push during the initial
//      statement-store sync is not missed.
//   2. Wait for Rust to signal READY (smoldot is peered and stmt_B is in
//      both collators' stores).
//   3. PONG: wait for stmt_B to arrive on the subscription.
//   4. PING: submit stmt_A, assert {status:"new"}.
//   5. Wait for Rust to signal DONE — it does so only after alice has
//      observed stmt_A via gossip. Outbound gossip is asynchronous, so the
//      client must stay alive until then; tearing it down earlier can abort
//      the in-flight propagation Rust is asserting on.

import { createRpc } from "./rpc.js";

export const fileInputs = ["RELAY_CHAIN_SPEC", "PARA_CHAIN_SPEC"];
export const envInputs = ["STATEMENT_A_HEX", "STATEMENT_B_HEX", "TOPIC_B"];

export default async function statementStoreBrowser(ctx) {
  const { report, env, files } = ctx;
  const rpc = createRpc(ctx.client);

  const stmtAHex = env.STATEMENT_A_HEX;
  const stmtBHex = env.STATEMENT_B_HEX;
  const topicBHex = env.TOPIC_B;
  if (!files.RELAY_CHAIN_SPEC || !files.PARA_CHAIN_SPEC || !stmtAHex || !stmtBHex || !topicBHex) {
    throw new Error(
      "Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, STATEMENT_A_HEX, STATEMENT_B_HEX, TOPIC_B",
    );
  }

  // The relay chain is only needed as the para's anchor; no JSON-RPC is ever
  // sent to it, so it bypasses `createRpc` (whose response drain would have
  // nothing to read from a `disableJsonRpc` chain anyway).
  const relay = await ctx.client.addChain({
    chainSpec: files.RELAY_CHAIN_SPEC,
    disableJsonRpc: true,
  });
  report("addChain relay", true);

  const para = await rpc.addChain({
    chainSpec: files.PARA_CHAIN_SPEC,
    statementStore: {},
    potentialRelayChains: [relay],
  });
  report("addChain parachain with statementStore", true);

  // Subscribe early so the stmt_B push during initial sync is not missed.
  const subReqId = rpc
    .sendRpc(para, "statement_subscribeStatement", [{ matchAny: [topicBHex] }])
    .toString();
  const subId = await rpc.readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.id === subReqId) {
        if (msg.error)
          throw new Error(`statement_subscribeStatement failed: ${JSON.stringify(msg.error)}`);
        return msg.result;
      }
      return undefined;
    },
    Date.now() + 30_000,
  );
  if (typeof subId !== "string" || subId.length === 0) {
    throw new Error(`Unexpected subscription id: ${JSON.stringify(subId)}`);
  }
  report("subscribe to topic_B", true, `subId=${subId}`);

  await ctx.waitSync("READY");
  report("Rust signalled READY", true);

  // PONG first, PING second — the order matters with the lossy rpc helpers:
  // stmt_B is typically pushed during the initial statement-store sync and
  // sits queued by the time READY arrives. `sendRpcAndWait` discards every
  // non-matching queued message while hunting for its response, so issuing
  // the ping first would silently swallow the pong notification (smoldot
  // never re-notifies a statement it already knows).

  // PONG: wait for stmt_B on the subscription; other statements are ignored.
  const pong = await rpc.readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.method !== "statement_statement") return undefined;
      if (msg.params?.subscription !== subId) return undefined;
      const r = msg.params.result;
      if (r?.event !== "newStatements") return undefined;
      return (r.data?.statements ?? []).includes(stmtBHex) ? true : undefined;
    },
    Date.now() + 120_000,
  );
  const pongOk = pong === true;
  report("pong: stmt_B received via subscription", pongOk);
  if (!pongOk) {
    throw new Error("stmt_B never arrived on the topic_B subscription");
  }

  // PING: submit stmt_A.
  const submitResult = await rpc.sendRpcAndWait(para, "statement_submit", [stmtAHex], 30_000);
  const pingOk = submitResult?.status === "new";
  report("ping: statement_submit returned status=new", pingOk, JSON.stringify(submitResult));
  if (!pingOk) {
    throw new Error(`statement_submit did not return status "new": ${JSON.stringify(submitResult)}`);
  }

  // Keep smoldot alive until Rust confirms alice observed stmt_A via gossip.
  await ctx.waitSync("DONE", 240_000);
  report("Rust signalled DONE", true);
}
