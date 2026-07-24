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

// Smoke test body — runs identically on the Node host (TCP) and the browser
// host (WebRTC). Its only import is the host-agnostic `shared/rpc.js` helper
// library (a relative sibling that resolves on both hosts); everything
// host-specific goes through `ctx` (see hosts/node/ctx.js and
// hosts/browser/ctx.js for the two builders) and all inputs arrive pre-resolved
// in `ctx.env` / `ctx.files`.

import { createRpc } from "./rpc.js";
import { hexToBytes, decodeHeader } from "./codec.js";

// Env var values that name files; the runner reads each into `ctx.files[NAME]`
// (string contents, or null if unset).
export const fileInputs = [
  "RELAY_CHAIN_SPEC",
  "PARA_CHAIN_SPEC",
  "SMOLDOT_DB_RELAY",
  "SMOLDOT_DB_PARA",
];

export const envInputs = ["REQUIRED_BLOCKS", "EXPECTED_INITIAL_FINALIZED"];

export default async function smoke(ctx) {
  const { report, env, files } = ctx;
  const { addChain, sendRpc, readJsonRpcUntil, sendRpcAndWait } = createRpc(ctx.client);

  const requiredBlocks = Number.parseInt(env.REQUIRED_BLOCKS, 10);
  const expectedInitialFinalized = Number.parseInt(
    env.EXPECTED_INITIAL_FINALIZED ?? "0",
    10,
  );

  if (!files.RELAY_CHAIN_SPEC || !files.PARA_CHAIN_SPEC || !Number.isFinite(requiredBlocks)) {
    throw new Error("Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, REQUIRED_BLOCKS");
  }

  const relay = await addChain({
    chainSpec: files.RELAY_CHAIN_SPEC,
    databaseContent: files.SMOLDOT_DB_RELAY ?? undefined,
  });
  report("addChain relay", true);

  const para = await addChain({
    chainSpec: files.PARA_CHAIN_SPEC,
    databaseContent: files.SMOLDOT_DB_PARA ?? undefined,
    potentialRelayChains: [relay],
  });
  report("addChain parachain", true);

  // Assert smoldot's first reported finalized block ≥ expected. Uses
  // chainHead_v1: subscribe on the relay, wait for the `initialized` event
  // (which fires only after warp sync) and decode the newest finalized
  // header's number. Legacy `chain_getFinalizedHead` would race the
  // warp-sync gate — smoldot blocks legacy RPCs until the gate opens.
  if (expectedInitialFinalized > 0) {
    const relayFollowReqId = sendRpc(relay, "chainHead_v1_follow", [false]).toString();
    const relaySubId = await readJsonRpcUntil(
      relay,
      (msg) => {
        if (msg.id === relayFollowReqId) {
          if (msg.error)
            throw new Error(`relay chainHead_v1_follow failed: ${JSON.stringify(msg.error)}`);
          return msg.result;
        }
        return undefined;
      },
      Date.now() + 30_000,
    );
    if (typeof relaySubId !== "string" || !relaySubId) {
      throw new Error("Unexpected relay follow subscription id");
    }
    const finalizedHash = await readJsonRpcUntil(
      relay,
      (msg) => {
        if (msg.method !== "chainHead_v1_followEvent") return undefined;
        if (msg.params?.subscription !== relaySubId) return undefined;
        const r = msg.params.result;
        if (r?.event === "initialized") {
          const hashes = r.finalizedBlockHashes ?? [];
          return hashes[hashes.length - 1];
        }
        if (r?.event === "stop") throw new Error("relay chainHead follow stopped");
        return undefined;
      },
      Date.now() + 120_000,
    );
    if (typeof finalizedHash !== "string") {
      throw new Error("relay chainHead never reported initialized");
    }
    const headerHex = await sendRpcAndWait(
      relay,
      "chainHead_v1_header",
      [relaySubId, finalizedHash],
      30_000,
    );
    const { number } = decodeHeader(headerHex);
    const ok = number >= expectedInitialFinalized;
    report(
      "relay finalized at-or-past expected_initial_finalized",
      ok,
      `finalized=#${number} expected=#${expectedInitialFinalized}`,
    );
    if (!ok)
      throw new Error(
        `relay finalized #${number} below expected_initial_finalized #${expectedInitialFinalized}`,
      );
  }

  const followReqId = sendRpc(para, "chainHead_v1_follow", [false]).toString();
  const subId = await readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.id === followReqId) {
        if (msg.error)
          throw new Error(`chainHead_v1_follow failed: ${JSON.stringify(msg.error)}`);
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

  // Skip the initial `newBlock` burst (replay of already-known blocks); the
  // first `bestBlockChanged` marks its end. Otherwise a warm-started smoldot
  // would satisfy the threshold from cached state alone.
  let burstDone = false;
  let newBlocks = 0;
  await readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.method !== "chainHead_v1_followEvent") return undefined;
      if (msg.params?.subscription !== subId) return undefined;
      const result = msg.params.result;
      if (result?.event === "bestBlockChanged") {
        burstDone = true;
      } else if (result?.event === "newBlock" && burstDone) {
        if (++newBlocks >= requiredBlocks) return true;
      } else if (result?.event === "stop") {
        throw new Error("chainHead follow stopped unexpectedly");
      }
      return undefined;
    },
    Date.now() + 180_000,
  );

  const ok = newBlocks >= requiredBlocks;
  report("smoldot saw new parachain blocks", ok, `count=${newBlocks}/${requiredBlocks}`);
  if (!ok) throw new Error(`only saw ${newBlocks}/${requiredBlocks} new parachain blocks`);

  // Node host only: dump the persisted databaseContent for snapshot generation.
  // The browser host never sets SMOLDOT_DB_DUMP_DIR, so this is skipped there.
  if (env.SMOLDOT_DB_DUMP_DIR) {
    const relayDb = await sendRpcAndWait(relay, "chainHead_unstable_finalizedDatabase", [], 30_000);
    const paraDb = await sendRpcAndWait(para, "chainHead_unstable_finalizedDatabase", [], 30_000);
    await ctx.dumpDb({ "relay.json": relayDb, "para.json": paraDb });
    report("dumped smoldot databaseContent", true, env.SMOLDOT_DB_DUMP_DIR);
  }
}
