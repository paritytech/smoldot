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

// Statement-store submission test body — runs on either host via the ctx
// abstraction. Submits a pre-signed statement and asserts smoldot accepts it
// as new. Gossip to the collators happens asynchronously after the body
// returns; the runner awaits `ctx.cleanup()` (→ `client.terminate()`), which
// keeps smoldot alive long enough for that propagation — the Rust side
// asserts on the statement reaching the full nodes.

import { createRpc } from "./rpc.js";

export const fileInputs = ["RELAY_CHAIN_SPEC", "PARA_CHAIN_SPEC"];
export const envInputs = ["STATEMENT_HEX"];

// Wait for smoldot to establish peer connections before submitting.
// statement_submit is a pure gossip operation — no chain sync needed.
const PEER_SETTLE_MS = 10_000;
const MAX_RETRIES = 10;

export default async function statementStoreSubmission(ctx) {
  const { report, env, files } = ctx;
  const rpc = createRpc(ctx.client);

  const statementHex = env.STATEMENT_HEX;
  if (!files.RELAY_CHAIN_SPEC || !files.PARA_CHAIN_SPEC || !statementHex) {
    throw new Error("Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, STATEMENT_HEX");
  }

  const relay = await rpc.addChain({ chainSpec: files.RELAY_CHAIN_SPEC });
  report("addChain relay", true);

  const para = await rpc.addChain({
    chainSpec: files.PARA_CHAIN_SPEC,
    statementStore: {},
    potentialRelayChains: [relay],
  });
  report("addChain parachain with statementStore", true);

  await new Promise((r) => setTimeout(r, PEER_SETTLE_MS));

  let submitResult;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    submitResult = await rpc.sendRpcAndWait(para, "statement_submit", [statementHex]);

    // Smoldot returns {"status":"new"} on success
    if (submitResult?.status === "new") break;
    if (attempt < MAX_RETRIES - 1) {
      ctx.log(
        `statement_submit attempt ${attempt + 1} returned: ${JSON.stringify(submitResult)}, retrying in 5s...`,
      );
      await new Promise((r) => setTimeout(r, 5000));
    }
  }

  const ok = submitResult?.status === "new";
  report("statement_submit accepted", ok, JSON.stringify(submitResult));
  if (!ok) {
    throw new Error(`statement_submit never returned status "new": ${JSON.stringify(submitResult)}`);
  }
}
