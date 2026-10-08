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

// Legacy runtime calls at new blocks must not download a runtime the client
// already holds. Once both chains are synced, sends `state_call` and
// `state_getRuntimeVersion` at ROUNDS successive best blocks of each chain and
// checks with `sudo_unstable_metrics` that `runtimeCodeDownloadsTotal` does
// not move, and that `runtimeCacheHitsTotal` goes up by at least one per
// block, meaning the runtime already in memory was reused.
//
// See <https://github.com/paritytech/smoldot/issues/3396>.

import { createRpc } from "./rpc.js";

export const fileInputs = ["RELAY_CHAIN_SPEC", "PARA_CHAIN_SPEC"];

export const envInputs = ["ROUNDS"];

const NEW_BLOCK_TIMEOUT_MS = 120_000;

async function runtimeMetrics(sendRpcAndWait, chain) {
  const { metrics } = await sendRpcAndWait(chain, "sudo_unstable_metrics", [], 30_000);
  const value = (name) => {
    const metric = metrics.find((m) => m.name === name);
    if (!metric) throw new Error(`${name} missing from sudo_unstable_metrics`);
    return metric.entries[0].value;
  };
  return {
    downloads: value("runtimeCodeDownloadsTotal"),
    cacheHits: value("runtimeCacheHitsTotal"),
  };
}

async function waitForNewBestBlock(sendRpcAndWait, chain, previous) {
  const deadline = Date.now() + NEW_BLOCK_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const hash = await sendRpcAndWait(chain, "chain_getBlockHash", [], 30_000);
    if (hash !== previous) return hash;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`no new best block within ${NEW_BLOCK_TIMEOUT_MS}ms`);
}

async function checkChain(ctx, rpc, label, chain, rounds) {
  const { report, log } = ctx;
  const { sendRpcAndWait } = rpc;

  const before = await runtimeMetrics(sendRpcAndWait, chain);
  let hash = await sendRpcAndWait(chain, "chain_getBlockHash", [], 30_000);
  const specVersions = new Set();

  for (let round = 1; round <= rounds; round++) {
    hash = await waitForNewBestBlock(sendRpcAndWait, chain, hash);
    await sendRpcAndWait(chain, "state_call", ["Core_version", "0x", hash], 60_000);
    const runtimeVersion = await sendRpcAndWait(chain, "state_getRuntimeVersion", [hash], 60_000);
    specVersions.add(runtimeVersion.specVersion);
    log(`${label}: round ${round} at ${hash}: specVersion ${runtimeVersion.specVersion}`);
  }

  report(`${label}: runtime unchanged during the test`, specVersions.size === 1, [...specVersions].join(","));

  const after = await runtimeMetrics(sendRpcAndWait, chain);
  report(
    `${label}: no runtime download`,
    after.downloads === before.downloads,
    `runtimeCodeDownloadsTotal ${before.downloads} -> ${after.downloads} over ${rounds} blocks`,
  );
  report(
    `${label}: runtime reused from memory`,
    after.cacheHits - before.cacheHits >= rounds,
    `runtimeCacheHitsTotal ${before.cacheHits} -> ${after.cacheHits} over ${rounds} blocks`,
  );
}

export default async function runtimeNoRedownload(ctx) {
  const { report, env, files } = ctx;
  const rpc = createRpc(ctx.client);

  const rounds = Number.parseInt(env.ROUNDS ?? "3", 10);
  if (!files.RELAY_CHAIN_SPEC || !files.PARA_CHAIN_SPEC || !Number.isFinite(rounds)) {
    throw new Error("Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC");
  }

  const relay = await rpc.addChain({ chainSpec: files.RELAY_CHAIN_SPEC });
  const para = await rpc.addChain({
    chainSpec: files.PARA_CHAIN_SPEC,
    potentialRelayChains: [relay],
  });
  report("addChain relay and parachain", true);

  // Legacy JSON-RPC calls are held until the chain is synced, so this returns
  // once the runtime has been downloaded by the sync services.
  await rpc.sendRpcAndWait(relay, "chain_getFinalizedHead", [], 180_000);
  await rpc.sendRpcAndWait(para, "chain_getFinalizedHead", [], 180_000);
  report("both chains synced", true);

  await checkChain(ctx, rpc, "relay", relay, rounds);
  await checkChain(ctx, rpc, "parachain", para, rounds);
}
