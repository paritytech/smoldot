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

// Restarting a parachain with a saved database must not download `:code` again
// when the runtime hasn't changed. Saves the parachain database, then re-adds
// the parachain three times with checks on `runtimeCodeDownloadsTotal`:
// - unchanged database: no download;
// - wrong `:code` Merkle value: one download;
// - corrupted `:code`: the hint is dropped after the failure, one download.
//
// See <https://github.com/paritytech/smoldot/issues/3204>.

import { createRpc } from "./rpc.js";

export const fileInputs = ["RELAY_CHAIN_SPEC", "PARA_CHAIN_SPEC"];

const SYNC_TIMEOUT_MS = 180_000;

async function downloads(sendRpcAndWait, chain) {
  const { metrics } = await sendRpcAndWait(chain, "sudo_unstable_metrics", [], 30_000);
  const metric = metrics.find((m) => m.name === "runtimeCodeDownloadsTotal");
  if (!metric) throw new Error("runtimeCodeDownloadsTotal missing from sudo_unstable_metrics");
  return metric.entries[0].value;
}

export default async function parachainWarmStart(ctx) {
  const { report, log, files } = ctx;
  const rpc = createRpc(ctx.client);
  const { sendRpcAndWait } = rpc;

  if (!files.RELAY_CHAIN_SPEC || !files.PARA_CHAIN_SPEC) {
    throw new Error("Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC");
  }

  const relay = await rpc.addChain({ chainSpec: files.RELAY_CHAIN_SPEC });
  const addPara = async (databaseContent) => {
    const para = await rpc.addChain({
      chainSpec: files.PARA_CHAIN_SPEC,
      potentialRelayChains: [relay],
      databaseContent,
    });
    // Legacy JSON-RPC calls are held until the parachain is synced.
    await sendRpcAndWait(para, "chain_getFinalizedHead", [], SYNC_TIMEOUT_MS);
    return para;
  };

  let para = await addPara(undefined);
  report("parachain synced without database", true, `runtimeCodeDownloadsTotal ${await downloads(sendRpcAndWait, para)}`);

  const database = await sendRpcAndWait(para, "chainHead_unstable_finalizedDatabase", [], 30_000);
  const saved = JSON.parse(database);
  report(
    "database contains the runtime and its Merkle value",
    typeof saved.runtimeCode === "string" && typeof saved.codeMerkleValue === "string" &&
      typeof saved.codeClosestAncestor === "string",
    `runtimeCode ${saved.runtimeCode?.length ?? 0} chars, codeMerkleValue ${saved.codeMerkleValue}`,
  );

  const restart = async (label, databaseContent, check, expected) => {
    para.remove();
    const start = Date.now();
    para = await addPara(databaseContent);
    const count = await downloads(sendRpcAndWait, para);
    log(`${label}: synced in ${Date.now() - start}ms`);
    report(label, check(count), `runtimeCodeDownloadsTotal ${count}, expected ${expected}`);
  };

  await restart("restart with database: no download", database, (n) => n === 0, "0");

  await restart(
    "restart with wrong Merkle value: download",
    JSON.stringify({ ...saved, codeMerkleValue: "00".repeat(32) }),
    (n) => n === 1,
    "1",
  );

  await restart(
    "restart with corrupted runtime: download",
    JSON.stringify({ ...saved, runtimeCode: btoa("not a runtime").replace(/=+$/, "") }),
    (n) => n === 1,
    "1",
  );
}
