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

// Submits each case in PARITY_CASES to smoldot and checks its answer against the one a
// full node already gave for the same statement. Rust submits to the full node first and
// passes the answers in, so nothing has to travel back from here — the PASS/FAIL of each
// case is the whole result.
//
// Answers are shaped `{"result": <value>}` or `{"errorCode": <number>}` on both sides.
// A rejection keeps only its code: the messages are free-form and differ between
// implementations without saying anything about the outcome.

import { createRpc } from "./rpc.js";

export const fileInputs = ["RELAY_CHAIN_SPEC", "PARA_CHAIN_SPEC"];
export const envInputs = ["PARITY_CASES"];

// Statements are gossiped, not synced, so peers are all this needs.
const PEER_SETTLE_MS = 10_000;
const MAX_RETRIES = 10;
const RETRY_DELAY_MS = 5_000;

/// Key-sorted JSON, so comparing two answers doesn't depend on field order.
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

/// Submits once, normalizing both outcomes into the shape Rust uses.
async function submitOnce(rpc, para, hex) {
  try {
    return { result: await rpc.sendRpcAndWait(para, "statement_submit", [hex]) };
  } catch (error) {
    // Only a rejection is an outcome worth comparing; a timeout or a transport failure says
    // nothing about the statement and has to keep propagating.
    if (!error.rpcError) throw error;
    return { errorCode: error.rpcError.code };
  }
}

export default async function statementStoreSubmitParity(ctx) {
  const { report, env, files } = ctx;
  const rpc = createRpc(ctx.client);

  const cases = JSON.parse(env.PARITY_CASES);
  if (!files.RELAY_CHAIN_SPEC || !files.PARA_CHAIN_SPEC || !cases.length) {
    throw new Error("Required inputs: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, PARITY_CASES");
  }

  const relay = await rpc.addChain({ chainSpec: files.RELAY_CHAIN_SPEC });
  const para = await rpc.addChain({
    chainSpec: files.PARA_CHAIN_SPEC,
    statementStore: {},
    potentialRelayChains: [relay],
  });
  report("addChain parachain with statementStore", true);

  await new Promise((r) => setTimeout(r, PEER_SETTLE_MS));

  for (const testCase of cases) {
    let actual = await submitOnce(rpc, para, testCase.hex);

    // A statement that reached no peer is answered with an error while gossip is still
    // settling. Only cases expected to succeed are worth waiting on; for the rest the first
    // answer is already the final one.
    for (let attempt = 1; testCase.retry && attempt < MAX_RETRIES; attempt++) {
      if (actual.result?.status === "new") break;
      ctx.log(`${testCase.name}: got ${JSON.stringify(actual)}, retrying in 5s...`);
      await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
      actual = await submitOnce(rpc, para, testCase.hex);
    }

    const matchesFullNode = canonical(actual) === canonical(testCase.fullNode);
    const ok =
      canonical(actual) === canonical(testCase.expected) &&
      matchesFullNode === testCase.mustMatch;

    report(
      `${testCase.name} (${testCase.mustMatch ? "must match full node" : testCase.why})`,
      ok,
      `smoldot=${JSON.stringify(actual)} fullNode=${JSON.stringify(testCase.fullNode)}` +
        (ok ? "" : ` expected smoldot=${JSON.stringify(testCase.expected)}`),
    );
  }
}
