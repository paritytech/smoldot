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

// Submits statements to a light node, comparing each answer with the one Rust expects.

import { createRpc } from "./rpc.js";

export const fileInputs = ["RELAY_CHAIN_SPEC", "PARA_CHAIN_SPEC", "PARITY_CASES"];

const PEER_SETTLE_MS = 10_000;
const MAX_RETRIES = 10;
const RETRY_DELAY_MS = 5_000;

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
  const { report, files } = ctx;
  const rpc = createRpc(ctx.client);

  if (!files.RELAY_CHAIN_SPEC || !files.PARA_CHAIN_SPEC || !files.PARITY_CASES) {
    throw new Error("Required inputs: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, PARITY_CASES");
  }
  const cases = JSON.parse(files.PARITY_CASES);
  if (!Array.isArray(cases) || cases.length === 0) {
    throw new Error("PARITY_CASES holds no case to compare");
  }

  const relay = await rpc.addChain({ chainSpec: files.RELAY_CHAIN_SPEC });
  const para = await rpc.addChain({
    chainSpec: files.PARA_CHAIN_SPEC,
    statementStore: {},
    potentialRelayChains: [relay],
  });
  report("addChain parachain with statementStore", true);

  await new Promise((r) => setTimeout(r, PEER_SETTLE_MS));

  // Once one case has waited out the full retry budget without reaching a peer, the rest would
  // only repeat that wait: peers are demonstrably not settling.
  let peersSettling = true;

  for (const testCase of cases) {
    // A statement that reached no peer is answered with an error while gossip is still settling,
    // so only the cases expected to succeed are worth waiting on. For the rest the first answer is
    // already the final one.
    const retry = peersSettling && testCase.expected.result?.status === "new";
    let actual;
    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      actual = await submitOnce(rpc, para, testCase.hex);
      if (!retry || actual.result?.status === "new") break;
      if (attempt === MAX_RETRIES - 1) {
        peersSettling = false;
        break;
      }
      ctx.log(
        `${testCase.name}: got ${JSON.stringify(actual)}, retrying in ${RETRY_DELAY_MS}ms...`,
      );
      await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
    }

    const ok = canonical(actual) === canonical(testCase.expected);
    report(
      `${testCase.name} (${testCase.why ?? "must match full node"})`,
      ok,
      `smoldot=${JSON.stringify(actual)} fullNode=${JSON.stringify(testCase.fullNode)}` +
        (ok ? "" : ` expected smoldot=${JSON.stringify(testCase.expected)}`),
    );
  }
}
