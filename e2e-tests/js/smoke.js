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

import * as fs from "node:fs";
import {
  createSmoldotClient,
  addChainFromSpec,
  readDbContentIfSet,
  sendRpc,
  readJsonRpcUntil,
  sendRpcAndWait,
  report,
} from "./helpers.js";

const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const paraSpecPath = process.env.PARA_CHAIN_SPEC;
const requiredBlocks = Number.parseInt(process.env.REQUIRED_BLOCKS, 10);
const expectedInitialFinalized = Number.parseInt(process.env.EXPECTED_INITIAL_FINALIZED ?? "0", 10);
const dbDumpDir = process.env.SMOLDOT_DB_DUMP_DIR;

if (!relaySpecPath || !paraSpecPath || !Number.isFinite(requiredBlocks)) {
  console.error(
    "Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, REQUIRED_BLOCKS",
  );
  process.exit(1);
}

// Decodes the block number from a hex SCALE-encoded substrate header.
// Layout: parent_hash (32 B) | compact-encoded number | rest. The compact
// modes 0/1/2 cover block numbers up to 2^30; that's the only range we'll
// ever assert against.
function decodeHeaderNumber(hexStr) {
  const stripped = hexStr.startsWith("0x") ? hexStr.slice(2) : hexStr;
  const bytes = Buffer.from(stripped, "hex");
  if (bytes.length < 33) throw new Error(`header hex too short: ${bytes.length} bytes`);
  const off = 32;
  const b0 = bytes[off];
  const mode = b0 & 0b11;
  if (mode === 0) return b0 >>> 2;
  if (mode === 1) return (b0 | (bytes[off + 1] << 8)) >>> 2;
  if (mode === 2) {
    return (
      (b0 | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24)) >>> 2
    );
  }
  throw new Error(`compact mode 3 not supported in decodeHeaderNumber`);
}

const client = createSmoldotClient();
let relay;
let para;
let passed = true;

try {
  const relayDbContent = readDbContentIfSet("SMOLDOT_DB_RELAY");
  const paraDbContent = readDbContentIfSet("SMOLDOT_DB_PARA");

  relay = await addChainFromSpec(client, relaySpecPath, {
    databaseContent: relayDbContent,
  });
  report("addChain relay", true);

  para = await addChainFromSpec(client, paraSpecPath, {
    databaseContent: paraDbContent,
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
            throw new Error(
              `relay chainHead_v1_follow failed: ${JSON.stringify(msg.error)}`,
            );
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
    const num = decodeHeaderNumber(headerHex);
    const ok = num >= expectedInitialFinalized;
    report(
      "relay finalized at-or-past expected_initial_finalized",
      ok,
      `finalized=#${num} expected=#${expectedInitialFinalized}`,
    );
    if (!ok)
      throw new Error(
        `relay finalized #${num} below expected_initial_finalized #${expectedInitialFinalized}`,
      );
  }

  const followReqId = sendRpc(para, "chainHead_v1_follow", [false]).toString();
  const subId = await readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.id === followReqId) {
        if (msg.error)
          throw new Error(
            `chainHead_v1_follow failed: ${JSON.stringify(msg.error)}`,
          );
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
  report(
    "smoldot saw new parachain blocks",
    ok,
    `count=${newBlocks}/${requiredBlocks}`,
  );
  if (!ok) passed = false;

  if (passed && dbDumpDir) {
    fs.mkdirSync(dbDumpDir, { recursive: true });
    const relayDb = await sendRpcAndWait(
      relay,
      "chainHead_unstable_finalizedDatabase",
      [],
      30_000,
    );
    const paraDb = await sendRpcAndWait(
      para,
      "chainHead_unstable_finalizedDatabase",
      [],
      30_000,
    );
    fs.writeFileSync(`${dbDumpDir}/relay.json`, relayDb);
    fs.writeFileSync(`${dbDumpDir}/para.json`, paraDb);
    report("dumped smoldot databaseContent", true, dbDumpDir);
  }
} catch (e) {
  report("smoke", false, e.message);
  passed = false;
}

// Finish as soon as the result is known
process.exit(passed && !process.exitCode ? 0 : 1);
