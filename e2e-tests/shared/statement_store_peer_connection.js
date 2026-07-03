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

// Statement-store peer-connection test body — runs on either host via the ctx
// abstraction. Subscribes to all statements and asserts every expected hash
// eventually arrives while the Rust side drives peer churn + submissions.

import { createRpc } from "./rpc.js";

export const fileInputs = ["RELAY_CHAIN_SPEC", "PARA_CHAIN_SPEC"];

export default async function statementStorePeerConnection(ctx) {
  const { report, env, files } = ctx;
  const rpc = createRpc(ctx.client);

  const stmtHexes = (env.STATEMENT_HEXES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const listenMs = Number.parseInt(env.LISTEN_MS || "300000", 10);

  if (!files.RELAY_CHAIN_SPEC || !files.PARA_CHAIN_SPEC || stmtHexes.length === 0) {
    throw new Error("Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, STATEMENT_HEXES");
  }

  const relay = await rpc.addChain({ chainSpec: files.RELAY_CHAIN_SPEC });
  report("addChain relay", true);

  const para = await rpc.addChain({
    chainSpec: files.PARA_CHAIN_SPEC,
    statementStore: {},
    potentialRelayChains: [relay],
  });
  report("addChain parachain with statementStore", true);

  // Subscribe to all statements so the full nodes know our interest.
  const subReqId = rpc.sendRpc(para, "statement_subscribeStatement", ["any"]).toString();

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
    Date.now() + 20_000,
  );
  if (typeof subId !== "string" || subId.length === 0) {
    throw new Error(`Unexpected subscription id: ${JSON.stringify(subId)}`);
  }
  report("statement_subscribeStatement accepted", true, `subId=${subId}`);

  // Record the first time each expected hash is seen. Rust drives the churn +
  // submissions; this side just confirms each statement lands eventually.
  const seen = new Map(stmtHexes.map((h) => [h, null]));
  const listenDeadline = Date.now() + listenMs;

  await rpc.readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.method !== "statement_statement") return undefined;
      if (msg.params?.subscription !== subId) return undefined;
      const result = msg.params.result;
      if (result?.event !== "newStatements") return undefined;
      const stmts = result.data?.statements ?? [];
      for (const s of stmts) {
        if (seen.has(s) && seen.get(s) === null) {
          seen.set(s, Date.now());
          ctx.log(`[received] ${s.slice(0, 18)}…`);
        }
      }
      // Stop listening once every expected hash has been seen.
      if ([...seen.values()].every((v) => v !== null)) {
        return true;
      }
      return undefined;
    },
    listenDeadline,
  );

  const missing = [...seen.entries()]
    .filter(([, t]) => t === null)
    .map(([h]) => h);
  const ok = missing.length === 0;
  report(
    "peer_connection: all expected statements received",
    ok,
    ok ? `received=${seen.size}` : `missing=${missing.length}: ${missing.join(", ")}`,
  );

  try {
    rpc.sendRpc(para, "statement_unsubscribeStatement", [subId]);
  } catch (_) {}

  if (!ok) {
    throw new Error(`missing ${missing.length} expected statements: ${missing.join(", ")}`);
  }
}
