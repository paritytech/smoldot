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

// Peer discovery from a single `bootnodes_p256` entry, driven by `tests/jam_discovery.rs`.

import {
  addJamChain,
  bootnodeAddress,
  followChain,
  nodeRpc,
  peerTracker,
  slotOfHeaderHex,
  waitOrFail,
} from "./jam.js";

export const fileInputs = ["JAM_CHAIN_SPEC"];
export const envInputs = ["JAM_RPC_URL", "JAM_NODE0_BOOTNODE"];

/** Non-bootnode candidates: the spec's genesis C(8), or a verified live read. */
const VALIDATOR_SOURCES = ["genesis", "discovered"];

export default async function jamDiscovery(ctx) {
  const { files, env, report, log } = ctx;
  if (!files.JAM_CHAIN_SPEC || !env.JAM_RPC_URL || !env.JAM_NODE0_BOOTNODE) {
    throw new Error("JAM_CHAIN_SPEC, JAM_RPC_URL and JAM_NODE0_BOOTNODE required");
  }
  const node = nodeRpc(env.JAM_RPC_URL);
  const spec = JSON.parse(files.JAM_CHAIN_SPEC);
  const NODE0_ADDRESS = bootnodeAddress(env.JAM_NODE0_BOOTNODE);
  spec["bootnodes_p256"] = [env.JAM_NODE0_BOOTNODE];
  const timings = {};
  const until = (what, check, timeoutMs) => waitOrFail(ctx, what, check, timeoutMs);

  const peers = peerTracker(ctx.clientLogs);
  const t0 = Date.now();
  const chain = await addJamChain(ctx.client, spec);
  // Blocks and finalized events across re-follows (a warp join stops the
  // first follow), and the latest block.
  const follow = await followChain(ctx, chain, { maxStops: 3, stopCheck: "the follow stops at most three times" });
  const run = { blockCount: 0, finalityCount: 0, latest: undefined, latestSlot: undefined };
  const live = async () => {
    await follow.update(async (event) => {
      if (event.event === "stop") {
        run.latest = undefined;
      } else if (event.event === "newBlock") {
        run.blockCount += 1;
        const previous = run.latest;
        run.latest = event.blockHash;
        // Keep only the newest block pinned, for its header.
        if (previous) await follow.request("jamHead_unstable_unpin", [previous]).catch(() => {});
      } else if (event.event === "finalized") {
        run.finalityCount += 1;
      }
    });
    if (run.latest) {
      const header = await follow.request("jamHead_unstable_header", run.latest).catch(() => null);
      if (header) run.latestSlot = slotOfHeaderHex(header);
    }
    peers.update();
    return run;
  };

  // 1. Fresh client: blocks, verified finality, the active set read, and both
  //    slots connected: jam0 as bootnode, one other validator.
  let firstBlock;
  let firstFinality;
  await until("blocks, finality, a C(8) read and two connected slots", async () => {
    const state = await live();
    if (firstBlock === undefined && state.blockCount > 0) firstBlock = Date.now();
    if (firstFinality === undefined && state.finalityCount > 0) firstFinality = Date.now();
    const connected = peers.connected();
    return state.blockCount > 0 && state.finalityCount > 0 && peers.refreshes.length > 0 &&
      connected.some((peer) => peer.source === "bootnode" && peer.address === NODE0_ADDRESS) &&
      connected.some((peer) => VALIDATOR_SOURCES.includes(peer.source) && peer.address !== NODE0_ADDRESS);
  }, 240_000);
  const firstRefresh = peers.refreshes[0];
  report("the first C(8) read lists six validators", firstRefresh.validators === 6, JSON.stringify(firstRefresh));
  report("jam0 is the bootnode; five validators are discovered", firstRefresh.discovered === 5, `${firstRefresh.discovered}`);
  timings.firstBlockMs = firstBlock - t0;
  timings.firstFinalityMs = firstFinality - t0;
  timings.firstRefreshMs = firstRefresh.at - t0;
  timings.secondSlotConnectedMs = Date.now() - t0;
  report("jam0 connected as bootnode and a second validator connected", true,
    peers.connected().map((p) => `${p.source} ${p.address}`).join(", "));

  // At the tip: the client's latest slot matches the node's best slot.
  await until("the client at the node tip", async () => {
    const state = await live();
    const best = await node.bestBlock().catch(() => undefined);
    return state.latestSlot !== undefined && best !== undefined && best.slot - state.latestSlot <= 1;
  }, 60_000);
  report("the client is at the node tip", true, `slot ${run.latestSlot}`);

  // 2. jam0 dies.
  const before = { blockCount: run.blockCount, finalityCount: run.finalityCount };
  const killRequested = Date.now();
  await ctx.sendSync("AT_TIP");
  await ctx.waitSync("KILLED", 120_000);
  const killed = Date.now();
  timings.killMs = killed - killRequested;

  let firstBlockAfterKill;
  let firstFinalityAfterKill;
  const track = async () => {
    const state = await live();
    if (firstBlockAfterKill === undefined && state.blockCount > before.blockCount) firstBlockAfterKill = Date.now();
    if (firstFinalityAfterKill === undefined && state.finalityCount > before.finalityCount) firstFinalityAfterKill = Date.now();
    return state;
  };
  await until("two connected validators other than jam0", async () => {
    await track();
    const connected = peers.connected();
    return connected.length >= 2 && new Set(connected.map((peer) => peer.address)).size === connected.length &&
      connected.every((peer) => VALIDATOR_SOURCES.includes(peer.source) && peer.address !== NODE0_ADDRESS);
  }, 120_000);
  timings.twoValidatorsAfterKillMs = Date.now() - killed;
  report("two validators other than jam0 are connected after the kill", true,
    peers.connected().map((p) => `${p.source} ${p.address}`).join(", "));

  const continued = await until("three verified headers and two finalized events after the kill", async () => {
    const state = await track();
    return state.blockCount >= before.blockCount + 3 && state.finalityCount >= before.finalityCount + 2 &&
      { blockCount: state.blockCount, finalityCount: state.finalityCount };
  }, 120_000);
  timings.firstBlockAfterKillMs = firstBlockAfterKill - killed;
  timings.firstFinalityAfterKillMs = firstFinalityAfterKill - killed;
  report("three verified headers and two finalized events after the kill", true,
    `+${continued.blockCount - before.blockCount} blocks, +${continued.finalityCount - before.finalityCount} finalized`);

  // 3. jam0 comes back and is eventually used again.
  await ctx.sendSync("CONTINUED");
  await ctx.waitSync("STARTED", 180_000);
  const started = Date.now();
  await until("jam0 connected again as bootnode", async () => {
    await live();
    return peers.connected().some((peer) => peer.source === "bootnode" && peer.address === NODE0_ADDRESS);
  }, 420_000);
  timings.node0UsedAgainMs = Date.now() - started;
  report("jam0 is connected again as bootnode after its restart", true, `${timings.node0UsedAgainMs} ms`);

  const settled = await live();
  report("headers keep arriving", settled.blockCount > continued.blockCount,
    `${continued.blockCount} -> ${settled.blockCount} headers`);
  log(JSON.stringify({
    timings,
    blocks: settled.blockCount,
    finalized: settled.finalityCount,
    refollows: follow.stops,
    refreshes: peers.refreshes.map((entry) => ({ ...entry, at: entry.at - t0 })),
  }));
}
