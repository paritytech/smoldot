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

// A fresh client joins a restored aged chain, driven by `tests/jam_aged.rs`.

import {
  addJamChain,
  followChain,
  hashOfHeaderHex,
  installJamWireCapture,
  must,
  nodeRpc,
  waitOrFail,
} from "./jam.js";

export const fileInputs = ["JAM_CHAIN_SPEC"];
export const envInputs = ["JAM_RPC_URL", "JAM_AGED_BOUND_MS"];

export default async function jamAged(ctx) {
  const { files, env, log } = ctx;
  if (!files.JAM_CHAIN_SPEC || !env.JAM_RPC_URL) throw new Error("JAM_CHAIN_SPEC and JAM_RPC_URL required");
  const node = nodeRpc(env.JAM_RPC_URL);
  const spec = JSON.parse(files.JAM_CHAIN_SPEC);
  const genesis = hashOfHeaderHex(spec.genesis_header);
  const boundMs = Number(env.JAM_AGED_BOUND_MS ?? 180000);
  if (!Number.isSafeInteger(boundMs) || boundMs < 1) throw new Error("Invalid JAM_AGED_BOUND_MS");

  // Before any connection exists, so every session is recorded.
  const wire = installJamWireCapture();
  const finalizedBeforeConnect = await node.finalizedBlock();
  const started = Date.now();
  const chain = await addJamChain(ctx.client, spec);
  const follow = await followChain(ctx, chain, { maxStops: 1, stopCheck: "no repeated stop after the warp" });

  let imported = 0, firstMs, firstAt, best, finalized = 0, root;
  const reachedTip = `the fresh client reaches the node's best block within ${boundMs} ms`;
  const reached = await waitOrFail(ctx, reachedTip, async () => {
    let hashes = [];
    await follow.update((event) => {
      if (event.event === "stop") hashes = [];
      if (event.event === "initialized") root = event.finalizedBlockHashes[0];
      if (event.event === "newBlock") {
        imported++;
        firstAt ??= event.t;
        firstMs ??= event.t - started;
        hashes.push(event.blockHash);
      }
      if (event.event === "bestBlockChanged") best = event.bestBlockHash;
      if (event.event === "finalized") finalized++;
    });
    if (hashes.length) await follow.request("jamHead_unstable_unpin", hashes);
    const live = await node.bestBlock();
    return best === live.hash;
  }, boundMs, 100);
  must(ctx, reachedTip, reached, `best ${best}`);
  const elapsedMs = Date.now() - started;

  const requestsToTip = wire.requests.slice();
  const requestHash = (r) => [...r.bytes.slice(5, 37)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const ascendingBatches = requestsToTip.filter((r) => r.bytes[0] === 128 && r.bytes[37] === 0).length;
  const logs = ctx.clientLogs;
  const applied = logs.find((e) => e.message.startsWith("jam-warp-applied"));
  const connect = logs.find((e) => e.message === "jam-connect");
  const setId = Number(applied?.message.match(/set_id[=:]\s*(\d+)/)?.[1]);
  const rootSlot = Number(applied?.message.match(/(?:root_slot|slot)[=:]\s*(\d+)/)?.[1]);
  must(ctx, "jam-warp-applied with set id >= 3", applied && Number.isInteger(setId) && setId >= 3, applied?.message);
  must(ctx, "first newBlock within 5 seconds of connecting", connect && firstAt - connect.t <= 5000,
    connect ? `${firstAt - connect.t} ms` : "no jam-connect");
  must(ctx, "warp catch-up used at most two ascending CE 128 batches", ascendingBatches <= 2, `${ascendingBatches}`);

  const finalizedAfterWarp = await node.finalizedBlock();
  must(ctx, "the node's RPC has finalized the join root", rootSlot <= finalizedAfterWarp.slot,
    `root slot ${rootSlot}, RPC finalized ${finalizedAfterWarp.slot}`);
  let appliedRoot = finalizedAfterWarp;
  while (appliedRoot.slot > rootSlot) appliedRoot = await node.parent(appliedRoot.hash);
  const appliedHash = appliedRoot.hash.slice(2);
  must(ctx, "the follow re-initialized at the finalized join head", appliedRoot.slot === rootSlot && root === appliedRoot.hash,
    `root ${root}, RPC block at slot ${rootSlot}: ${appliedRoot.hash}`);

  const descending = requestsToTip.filter((r) => r.bytes[0] === 128 && r.bytes[37] === 1);
  const joinBlocksFetched = descending.length === 1
    ? new DataView(Uint8Array.from(descending[0].bytes).buffer).getUint32(38, true)
    : undefined;
  must(ctx, "the join fetches only F: one descending CE 128 request, max 1, at F",
    descending.length === 1 && requestHash(descending[0]) === appliedHash && joinBlocksFetched === 1,
    `${descending.length} descending request(s), max ${joinBlocksFetched}: ` + JSON.stringify(descending.map((r) => ({
      connection: r.connection, at: requestHash(r).slice(0, 12),
      max: new DataView(Uint8Array.from(r.bytes).buffer).getUint32(38, true), afterApplyMs: r.t - applied.t,
    }))));
  const selection = descending[0];
  const servingConnection = wire.connections.find((c) => c.id === selection.connection);
  // F is the latest UP0 final processed when the join head is selected. It
  // may be newer than this connection's initial final, but cannot come from a
  // different connection or an advertisement received after selection.
  const frozen = logs.find((e) => e.message.startsWith("jam-warp-join-selected;"));
  const advertisementRevision = Number(frozen?.message.match(/advertisement[=:]\s*(\d+)/)?.[1]);
  const frozenSlot = Number(frozen?.message.match(/slot[=:]\s*(\d+)/)?.[1]);
  const selectedFinal = servingConnection?.finals[advertisementRevision - 1];
  must(ctx, "frozen join F matches its exact serving-connection UP0 advertisement",
    Number.isSafeInteger(advertisementRevision) && advertisementRevision >= 1
    && advertisementRevision <= selection.finalsSeen && servingConnection?.initialFinal
    && selectedFinal && selectedFinal.slot === frozenSlot && frozenSlot === rootSlot
    && selectedFinal.hash === requestHash(selection),
    frozen?.message);
  const fragmentFinality = /fragment_finality[=:]\s*true/.test(applied.message);
  must(ctx, "the join head has fragment finality or a CE 130 on its serving connection",
    fragmentFinality || requestsToTip.some((r) => r.connection === selection.connection && r.bytes[0] === 130
      && requestHash(r) === appliedHash),
    `fragment_finality=${fragmentFinality}`);
  // The read is at F itself, against the posterior state root F's justification signs.
  const stateRequests = requestsToTip.filter((r) => r.bytes[0] === 129);
  must(ctx, "join state reads are bound to frozen F and its serving connection",
    stateRequests.length > 0 && stateRequests.every((r) => r.connection === selection.connection
      && r.t >= selection.t && requestHash(r) === appliedHash),
    `${stateRequests.length} CE 129 request(s)`);
  const stateResponses = Number(applied.message.match(/state_responses[=:]\s*(\d+)/)?.[1]);
  must(ctx, "the join needs at most two CE 129 responses", Number.isInteger(stateResponses) && stateResponses >= 1
    && stateResponses <= 2, `${stateResponses}`);
  const finalityAfterWarp = "a finalized event follows the warp";
  const finalitySeen = await waitOrFail(ctx, finalityAfterWarp, () => {
    finalized = chain.events.filter((e) => e.event === "finalized").length;
    return finalized > 0;
  }, 30000);
  must(ctx, finalityAfterWarp, finalitySeen, `${finalized}`);

  const aged = {
    genesis, firstNewBlockMs: firstMs, timeToTipMs: elapsedMs, imported,
    blocksPerSecond: imported * 1000 / elapsedMs, finalizedEvents: finalized, boundMs, best,
    setId, rootSlot, root, appliedRootHash: appliedRoot.hash, finalizedBeforeConnect, finalizedAfterWarp,
    advertisementRevision, selectedFinal, fragmentFinality, stateResponses, joinBlocksFetched,
    stateReadAt: appliedRoot.hash, stops: follow.stops, ascendingBatches, firstBlockAfterConnectMs: firstAt - connect.t,
    connections: wire.connections.length,
  };
  log("aged: " + JSON.stringify(aged));
}
