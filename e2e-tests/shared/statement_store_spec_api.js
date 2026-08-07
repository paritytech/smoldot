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

// Statement-store `statement_unstable_*` test body — runs on either host via the
// ctx abstraction. Walks the whole subscription lifecycle: subscribe, turn down
// the filters the specification doesn't define, attach a `matchAll` filter,
// collect its `replayDone`, assert that only matching statements arrive and that
// they carry the filter id, submit a statement of our own, then detach the filter
// and close the subscription.

import { createRpc } from "./rpc.js";

export const fileInputs = ["RELAY_CHAIN_SPEC", "PARA_CHAIN_SPEC"];
export const envInputs = [
  "TOPIC_A",
  "STATEMENT_A_HEX",
  "STATEMENT_B_HEX",
  "STATEMENT_C_HEX",
  "LISTEN_MS",
];

/// Sends `method` and resolves with the whole response object, error included.
async function sendAndTakeResponse(rpc, chain, method, params) {
  const id = rpc.sendRpc(chain, method, params).toString();
  const response = await rpc.readJsonRpcUntil(
    chain,
    (msg) => (msg.id === id ? msg : undefined),
    Date.now() + 20_000,
  );
  if (response === undefined) throw new Error(`Timed out waiting for ${method}`);
  return response;
}

export default async function statementStoreSpecApi(ctx) {
  const { report, env, files } = ctx;
  const rpc = createRpc(ctx.client);

  const topicAHex = env.TOPIC_A;
  const stmtAHex = env.STATEMENT_A_HEX;
  const stmtBHex = env.STATEMENT_B_HEX;
  const stmtCHex = env.STATEMENT_C_HEX;
  const listenMs = Number.parseInt(env.LISTEN_MS || "10000", 10);

  if (
    !files.RELAY_CHAIN_SPEC ||
    !files.PARA_CHAIN_SPEC ||
    !topicAHex ||
    !stmtAHex ||
    !stmtBHex ||
    !stmtCHex
  ) {
    throw new Error(
      "Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, TOPIC_A, STATEMENT_A_HEX, " +
        "STATEMENT_B_HEX, STATEMENT_C_HEX",
    );
  }

  const relay = await rpc.addChain({ chainSpec: files.RELAY_CHAIN_SPEC });
  report("addChain relay", true);

  const para = await rpc.addChain({
    chainSpec: files.PARA_CHAIN_SPEC,
    statementStore: {},
    potentialRelayChains: [relay],
  });
  report("addChain parachain with statementStore", true);

  const subscribeResponse = await sendAndTakeResponse(rpc, para, "statement_unstable_subscribe", []);
  if (subscribeResponse.error) {
    throw new Error(`statement_unstable_subscribe failed: ${JSON.stringify(subscribeResponse.error)}`);
  }
  const subId = subscribeResponse.result;
  if (typeof subId !== "string" || subId.length === 0) {
    throw new Error(`Unexpected subscription id: ${JSON.stringify(subId)}`);
  }
  report("statement_unstable_subscribe accepted", true, `subId=${subId}`);

  // Rejections first: a filter is attached afterwards, and every read discards
  // the messages it doesn't match, so this must happen before statements flow.
  const badEncoding = await sendAndTakeResponse(rpc, para, "statement_unstable_submit", ["0xffff"]);
  const badEncodingOk = badEncoding.error?.code === -32602;
  report(
    "submit rejects bytes that don't decode into a statement",
    badEncodingOk,
    JSON.stringify(badEncoding.error ?? badEncoding.result),
  );
  if (!badEncodingOk) throw new Error("expected error -32602 for an undecodable statement");

  const unknownSub = await sendAndTakeResponse(rpc, para, "statement_unstable_add_filter", [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "any",
  ]);
  const unknownSubOk = unknownSub.error?.code === -32801;
  report(
    "add_filter on an unknown subscription is refused",
    unknownSubOk,
    JSON.stringify(unknownSub.error ?? unknownSub.result),
  );
  if (!unknownSubOk) throw new Error("expected error -32801 for an unknown subscription");

  const matchAny = await sendAndTakeResponse(rpc, para, "statement_unstable_add_filter", [
    subId,
    { matchAny: [topicAHex] },
  ]);
  const matchAnyOk = matchAny.error?.code === -32602;
  report(
    "add_filter rejects a matchAny filter",
    matchAnyOk,
    JSON.stringify(matchAny.error ?? matchAny.result),
  );
  if (!matchAnyOk) throw new Error("expected error -32602 for a matchAny filter");

  const emptyMatchAll = await sendAndTakeResponse(rpc, para, "statement_unstable_add_filter", [
    subId,
    { matchAll: [] },
  ]);
  const emptyMatchAllOk = emptyMatchAll.error?.code === -32602;
  report(
    "add_filter rejects an empty matchAll filter",
    emptyMatchAllOk,
    JSON.stringify(emptyMatchAll.error ?? emptyMatchAll.result),
  );
  if (!emptyMatchAllOk) throw new Error("expected error -32602 for an empty matchAll filter");

  const addFilter = await sendAndTakeResponse(rpc, para, "statement_unstable_add_filter", [
    subId,
    { matchAll: [topicAHex] },
  ]);
  if (addFilter.error) {
    throw new Error(`statement_unstable_add_filter failed: ${JSON.stringify(addFilter.error)}`);
  }
  const filterId = addFilter.result;
  if (typeof filterId !== "string" || filterId.length === 0) {
    throw new Error(`Unexpected filter id: ${JSON.stringify(filterId)}`);
  }
  report("statement_unstable_add_filter accepted", true, `filterId=${filterId}`);

  // A light client holds no statement store, so the replay covers nothing and
  // completes immediately. Seeing `replayStatements` would mean smoldot claims a
  // store it doesn't have.
  const replayDone = await rpc.readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.method !== "statement_unstable_subscribeEvent") return undefined;
      if (msg.params?.subscription !== subId) return undefined;
      const result = msg.params.result;
      if (result?.event === "replayStatements") {
        throw new Error("a light client must not report replayStatements");
      }
      if (result?.event === "replayDone" && result.filterId === filterId) return true;
      return undefined;
    },
    Date.now() + 20_000,
  );
  report("replayDone received for the new filter", replayDone === true);
  if (replayDone !== true) throw new Error("replayDone was not received");

  // Block until Rust signals that smoldot is peered with both collators at the
  // statement-store level. Both already hold stmt_A and push it once they learn
  // about our topic affinity.
  await ctx.waitSync("READY");
  report("Rust signalled READY", true);

  let countA = 0;
  let countB = 0;
  let countOther = 0;
  let badFilterIds = 0;
  let stopped = false;
  const listenDeadline = Date.now() + listenMs;

  await rpc.readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.method !== "statement_unstable_subscribeEvent") return undefined;
      if (msg.params?.subscription !== subId) return undefined;
      const result = msg.params.result;
      if (result?.event === "stop") {
        stopped = true;
        return true;
      }
      if (result?.event !== "newStatements") return undefined;
      for (const item of result.statements ?? []) {
        if (item.statement === stmtAHex) countA += 1;
        else if (item.statement === stmtBHex) countB += 1;
        else countOther += 1;
        // Every reported statement matches the only attached filter.
        if (!Array.isArray(item.filterIds) || !item.filterIds.includes(filterId)) {
          badFilterIds += 1;
        }
      }
      return undefined;
    },
    listenDeadline,
  );

  const ok = countA === 1 && countB === 0 && countOther === 0 && badFilterIds === 0 && !stopped;
  const detail =
    `stmt_A count=${countA} | stmt_B count=${countB} | other count=${countOther} | ` +
    `items missing the filter id=${badFilterIds} | stopped=${stopped}`;
  report("newStatements: stmt_A once with its filter id, stmt_B never", ok, detail);
  if (!ok) throw new Error(`newStatements assertion failed: ${detail}`);

  // Submitted only now that the counting window is closed, and on a topic the
  // attached filter doesn't cover, so a statement gossiped back to us can't be
  // mistaken for one of the statements counted above. Rust then checks that bob
  // received it, which is what proves the broadcast left smoldot.
  const submit = await sendAndTakeResponse(rpc, para, "statement_unstable_submit", [stmtCHex]);
  const submitOk = !submit.error && submit.result?.status === "new";
  report("submit broadcasts a valid statement", submitOk, JSON.stringify(submit.error ?? submit.result));
  if (!submitOk) throw new Error(`unexpected submit response: ${JSON.stringify(submit)}`);

  const removeFilter = await sendAndTakeResponse(rpc, para, "statement_unstable_remove_filter", [
    subId,
    filterId,
  ]);
  const removeOk = !removeFilter.error && removeFilter.result === null;
  report("statement_unstable_remove_filter answers null", removeOk);
  if (!removeOk) throw new Error(`unexpected remove_filter response: ${JSON.stringify(removeFilter)}`);

  // Removing a filter that is no longer attached is a no-op, not an error.
  const removeAgain = await sendAndTakeResponse(rpc, para, "statement_unstable_remove_filter", [
    subId,
    filterId,
  ]);
  const removeAgainOk = !removeAgain.error && removeAgain.result === null;
  report("statement_unstable_remove_filter is idempotent", removeAgainOk);
  if (!removeAgainOk) throw new Error("removing a filter twice must not fail");

  const unsubscribe = await sendAndTakeResponse(rpc, para, "statement_unstable_unsubscribe", [subId]);
  const unsubscribeOk = !unsubscribe.error && unsubscribe.result === null;
  report("statement_unstable_unsubscribe answers null", unsubscribeOk);
  if (!unsubscribeOk) throw new Error(`unexpected unsubscribe response: ${JSON.stringify(unsubscribe)}`);
}
