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

// The aged join of D7 (GRANDPA warp sync), D2 (verified state reads) and D14
// (ascending catch-up): a fresh client joins a GRANDPA network restored from
// the aged snapshot by `tests/jam_aged.rs` (finalized head far from genesis,
// many set changes behind it) and must reach the node's tip within the bound.
// Checked from the client's log lines, its follow events, the WebTransport
// requests it made, and the node's RPC:
//
// - the warp applies at set id >= 3 and the follow re-initializes at the
//   finalized join head F, which the node's RPC has finalized;
// - F is the latest UP0 final the serving connection advertised before
//   selection, frozen for the join;
// - the join fetches only F (one descending CE 128 request, max 1, at F) and
//   reads its state at F on the same connection (one or two CE 129 responses);
// - F's finality comes from the warp fragment or a CE 130 on that connection;
// - at most two ascending CE 128 batches reach the tip, the first block comes
//   within 5 s of connecting, and a finalized event follows.

import { addJamChain, hashOfHeaderHex, installJamWireCapture, nodeRpc, waitFor } from "./jam.js";

export const fileInputs = ["JAM_CHAIN_SPEC"];
export const envInputs = ["JAM_RPC_URL", "JAM_AGED_BOUND_MS"];

export default async function jamAged(ctx) {
  const { files, env, report, log } = ctx;
  if (!files.JAM_CHAIN_SPEC || !env.JAM_RPC_URL) throw new Error("JAM_CHAIN_SPEC and JAM_RPC_URL required");
  const node = nodeRpc(env.JAM_RPC_URL);
  const spec = JSON.parse(files.JAM_CHAIN_SPEC);
  const genesis = hashOfHeaderHex(spec.genesis_header);
  const boundMs = Number(env.JAM_AGED_BOUND_MS ?? 180000);
  if (!Number.isSafeInteger(boundMs) || boundMs < 1) throw new Error("Invalid JAM_AGED_BOUND_MS");
  const must = (name, ok, detail) => {
    report(name, !!ok, detail === undefined ? undefined : String(detail));
    if (!ok) throw new Error(name);
  };

  // Before any connection exists, so every session is recorded.
  const wire = installJamWireCapture();
  const finalizedBeforeConnect = await node.finalizedBlock();
  const started = Date.now();
  const chain = await addJamChain(ctx.client, spec);
  let subscription = await chain.request("chainHead_v1_follow", [false]);

  let cursor = 0, imported = 0, firstMs, firstAt, best, finalized = 0, stops = 0, root;
  const reached = await waitFor(async () => {
    const batch = chain.events.slice(cursor);
    cursor += batch.length;
    const hashes = [];
    for (const event of batch) {
      if (event.event === "stop") {
        if (++stops > 1) must("no repeated stop after the warp", false, `${stops} stops`);
      }
      if (event.event === "initialized") root = event.finalizedBlockHashes[0];
      if (event.event === "newBlock") {
        imported++;
        firstAt ??= event.t;
        firstMs ??= event.t - started;
        if (event.subscription === subscription) hashes.push(event.blockHash);
      }
      if (event.event === "bestBlockChanged") best = event.bestBlockHash;
      if (event.event === "finalized") finalized++;
    }
    if (batch.some((e) => e.event === "stop" && e.subscription === subscription)) {
      subscription = await chain.request("chainHead_v1_follow", [false]);
    } else if (hashes.length) {
      await chain.request("chainHead_v1_unpin", [subscription, hashes]);
    }
    const live = await node.bestBlock();
    return best === live.hash;
  }, boundMs, 100);
  must(`the fresh client reaches the node's best block within ${boundMs} ms`, reached, `best ${best}`);
  const elapsedMs = Date.now() - started;

  const requestsToTip = wire.requests.slice();
  const requestHash = (r) => [...r.bytes.slice(5, 37)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const ascendingBatches = requestsToTip.filter((r) => r.bytes[0] === 128 && r.bytes[37] === 0).length;
  const logs = ctx.clientLogs;
  const applied = logs.find((e) => e.message.startsWith("jam-warp-applied"));
  const connect = logs.find((e) => e.message === "jam-connect");
  const setId = Number(applied?.message.match(/set_id[=:]\s*(\d+)/)?.[1]);
  const rootSlot = Number(applied?.message.match(/(?:root_slot|slot)[=:]\s*(\d+)/)?.[1]);
  must("jam-warp-applied with set id >= 3", applied && Number.isInteger(setId) && setId >= 3, applied?.message);
  must("first newBlock within 5 seconds of connecting", connect && firstAt - connect.t <= 5000,
    connect ? `${firstAt - connect.t} ms` : "no jam-connect");
  must("warp catch-up used at most two ascending CE 128 batches", ascendingBatches <= 2, `${ascendingBatches}`);

  const finalizedAfterWarp = await node.finalizedBlock();
  must("the node's RPC has finalized the join root", rootSlot <= finalizedAfterWarp.slot,
    `root slot ${rootSlot}, RPC finalized ${finalizedAfterWarp.slot}`);
  let appliedRoot = finalizedAfterWarp;
  while (appliedRoot.slot > rootSlot) appliedRoot = await node.parent(appliedRoot.hash);
  const appliedHash = appliedRoot.hash.slice(2);
  must("the follow re-initialized at the finalized join head", appliedRoot.slot === rootSlot && root === appliedRoot.hash,
    `root ${root}, RPC block at slot ${rootSlot}: ${appliedRoot.hash}`);

  const descending = requestsToTip.filter((r) => r.bytes[0] === 128 && r.bytes[37] === 1);
  const joinBlocksFetched = descending.length === 1
    ? new DataView(Uint8Array.from(descending[0].bytes).buffer).getUint32(38, true)
    : undefined;
  must("the join fetches only F: one descending CE 128 request, max 1, at F",
    descending.length === 1 && requestHash(descending[0]) === appliedHash && joinBlocksFetched === 1,
    `${descending.length} descending request(s), max ${joinBlocksFetched}: ` + JSON.stringify(descending.map((r) => ({
      connection: r.connection, at: requestHash(r).slice(0, 12),
      max: new DataView(Uint8Array.from(r.bytes).buffer).getUint32(38, true), afterApplyMs: r.t - applied.t,
    }))));
  const selection = descending[0];
  const servingConnection = wire.connections.find((c) => c.id === selection.connection);
  // Policy: freeze the latest UP0 final processed at chain_done. It may be
  // newer than this connection's initial final, but cannot come from a
  // different connection or an advertisement received after selection.
  const frozen = logs.find((e) => e.message.startsWith("jam-warp-join-selected;"));
  const advertisementRevision = Number(frozen?.message.match(/advertisement[=:]\s*(\d+)/)?.[1]);
  const frozenSlot = Number(frozen?.message.match(/slot[=:]\s*(\d+)/)?.[1]);
  const selectedFinal = servingConnection?.finals[advertisementRevision - 1];
  must("frozen join F matches its exact serving-connection UP0 advertisement",
    Number.isSafeInteger(advertisementRevision) && advertisementRevision >= 1
    && advertisementRevision <= selection.finalsSeen && servingConnection?.initialFinal
    && selectedFinal && selectedFinal.slot === frozenSlot && frozenSlot === rootSlot
    && selectedFinal.hash === requestHash(selection),
    frozen?.message);
  const fragmentFinality = /fragment_finality[=:]\s*true/.test(applied.message);
  must("the join head has fragment finality or a CE 130 on its serving connection",
    fragmentFinality || requestsToTip.some((r) => r.connection === selection.connection && r.bytes[0] === 130
      && requestHash(r) === appliedHash),
    `fragment_finality=${fragmentFinality}`);
  // Since D15 (pin move) the read is at F itself, against the posterior root F's justification signs.
  const stateRequests = requestsToTip.filter((r) => r.bytes[0] === 129);
  must("join state reads are bound to frozen F and its serving connection",
    stateRequests.length > 0 && stateRequests.every((r) => r.connection === selection.connection
      && r.t >= selection.t && requestHash(r) === appliedHash),
    `${stateRequests.length} CE 129 request(s)`);
  const stateResponses = Number(applied.message.match(/state_responses[=:]\s*(\d+)/)?.[1]);
  must("the join needs at most two CE 129 responses", Number.isInteger(stateResponses) && stateResponses >= 1
    && stateResponses <= 2, `${stateResponses}`);
  const finalitySeen = await waitFor(() => {
    finalized = chain.events.filter((e) => e.event === "finalized").length;
    return finalized > 0;
  }, 30000);
  must("a finalized event follows the warp", finalitySeen, `${finalized}`);

  const aged = {
    genesis, firstNewBlockMs: firstMs, timeToTipMs: elapsedMs, imported,
    blocksPerSecond: imported * 1000 / elapsedMs, finalizedEvents: finalized, boundMs, best,
    setId, rootSlot, root, appliedRootHash: appliedRoot.hash, finalizedBeforeConnect, finalizedAfterWarp,
    advertisementRevision, selectedFinal, fragmentFinality, stateResponses, joinBlocksFetched,
    stateReadAt: appliedRoot.hash, stops, ascendingBatches, firstBlockAfterConnectMs: firstAt - connect.t,
    connections: wire.connections.length,
  };
  log("aged: " + JSON.stringify(aged));
}
