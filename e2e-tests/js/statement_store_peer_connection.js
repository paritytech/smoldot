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

import { createClient, addChainFromSpec, sendRpc, report } from "./helpers.js";

const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const paraSpecPath = process.env.PARA_CHAIN_SPEC;
const stmtHexes = (process.env.STATEMENT_HEXES || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);
const READY_FD_PATH = process.env.READY_FD_PATH;
const LISTEN_MS = Number.parseInt(process.env.LISTEN_MS || "300000", 10);
const PEER_SETTLE_MS = Number.parseInt(
  process.env.PEER_SETTLE_MS || "15000",
  10,
);

if (
  !relaySpecPath ||
  !paraSpecPath ||
  stmtHexes.length === 0 ||
  !READY_FD_PATH
) {
  console.error(
    "Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, STATEMENT_HEXES, READY_FD_PATH",
  );
  process.exit(1);
}

async function drainUntil(chain, predicate, deadlineMs) {
  while (Date.now() < deadlineMs) {
    const remaining = deadlineMs - Date.now();
    let raw;
    try {
      raw = await Promise.race([
        chain.nextJsonRpcResponse(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error("timeout")), remaining),
        ),
      ]);
    } catch (_) {
      return undefined;
    }
    const msg = JSON.parse(raw);
    const out = predicate(msg);
    if (out !== undefined) return out;
  }
  return undefined;
}

const client = createClient();
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

  // Subscribe to all statements so the full nodes know our interest.
  const subReqId = sendRpc(para, "statement_subscribeStatement", [
    "any",
  ]).toString();

  const subId = await drainUntil(
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

  await new Promise((r) => setTimeout(r, PEER_SETTLE_MS));

  const fs = await import("node:fs/promises");
  await fs.writeFile(READY_FD_PATH, "READY\n");
  report("signalled READY", true, READY_FD_PATH);

  // Record the first time we see each expected hash. Rust will drive the
  // churn + submissions; we just confirm each statement lands eventually.
  const seen = new Map(stmtHexes.map((h) => [h, null]));
  const listenDeadline = Date.now() + LISTEN_MS;

  await drainUntil(
    para,
    (msg) => {
      if (msg.method !== "statement_statement") return undefined;
      if (msg.params?.subscription !== subId) return undefined;
      const result = msg.params.result;
      if (result?.event !== "newStatements") return undefined;
      const stmts = result.data?.statements ?? [];
      for (const s of stmts) {
        const h = s.toLowerCase();
        if (seen.has(h) && seen.get(h) === null) {
          seen.set(h, Date.now());
          console.error(`[received] ${h.slice(0, 18)}…`);
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
    ok
      ? `received=${seen.size}`
      : `missing=${missing.length}: ${missing.join(", ")}`,
  );
  if (!ok) passed = false;

  try {
    sendRpc(para, "statement_unsubscribeStatement", [subId]);
  } catch (_) {}
} catch (e) {
  report("statement_store_peer_connection", false, e.message);
  passed = false;
} finally {
  try {
    await client.terminate();
  } catch (_) {}
}

if (!passed || process.exitCode) {
  process.exit(1);
}
