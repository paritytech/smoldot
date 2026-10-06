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

// Live GRANDPA finality across a jam0 restart, driven by `tests/jam_finality.rs`.

import {
  addJamChain,
  blake2b256,
  bytesToHex,
  delay,
  followChain,
  hashOfHeaderHex,
  installJamWireCapture,
  must,
  stateKey,
  waitOrFail,
} from "./jam.js";
import { hexToBytes } from "./codec.js";

export const fileInputs = ["JAM_CHAIN_SPEC"];
export const envInputs = ["JAM_FINALITY_FIXTURE_EXPORT", "JAM_POLKAJAM_COMMIT"];

export default async function jamFinality(ctx) {
  const { files, env, report, log } = ctx;
  if (!files.JAM_CHAIN_SPEC) throw new Error("JAM_CHAIN_SPEC required");
  const spec = JSON.parse(files.JAM_CHAIN_SPEC);

  // Before any connection exists, so every CE 130 exchange is recorded.
  const { proofs } = installJamWireCapture();
  const chain = await addJamChain(ctx.client, spec);
  const follow = await followChain(ctx, chain, {
    maxStops: 0,
    stopCheck: "follow survives root advancement (no stop event)",
  });

  const headers = {};
  let retainedPin;
  const collect = () => follow.update(async (event) => {
    if (event.event !== "newBlock") return;
    const header = await follow.request("jamHead_unstable_header", event.blockHash);
    if (!header) must(ctx, "jamHead_unstable_header answers every new block", false, event.blockHash);
    headers[event.blockHash] = header;
    if (!retainedPin) retainedPin = event.blockHash;
    else await follow.request("jamHead_unstable_unpin", [event.blockHash]);
  });
  const finalized = () => chain.events.filter((e) => e.event === "finalized");
  const waitUntil = (what, condition, timeoutMs) =>
    waitOrFail(ctx, what, async () => { await collect(); return condition(); }, timeoutMs, 500);

  await waitUntil("the client finalizes in authority set 3",
    () => ctx.clientLogs.some((l) => /jam-finalized/.test(l.message) && /set_id=3\b/.test(l.message)), 210_000);
  report("the client finalizes in authority set 3", true,
    ctx.clientLogs.find((l) => /jam-finalized/.test(l.message) && /set_id=3\b/.test(l.message)).message);
  report("at least 3 finalized events", finalized().length >= 3, `${finalized().length}`);
  report("CE 130 justifications were captured", proofs.length > 0, `${proofs.length}`);
  const before = finalized().at(-1).finalizedBlockHashes.at(-1);
  const pinned = await follow.request("jamHead_unstable_header", retainedPin);
  report("the first pinned header survives removal of old tree ancestors", pinned === headers[retainedPin], retainedPin);
  log("Verified three authority sets; Rust restarts jam0 while finality advances");

  // Keep consuming while Rust kills jam0, waits 12 s and starts it again.
  await ctx.sendSync("THREE_SETS");
  let restarted = false;
  const restartedSignal = ctx.waitSync("RESTARTED", 180_000).then(() => { restarted = true; });
  while (!restarted) {
    await collect();
    await Promise.race([restartedSignal, delay(500)]);
  }
  await restartedSignal;

  await waitUntil("finality advances after the jam0 restart",
    () => finalized().at(-1)?.finalizedBlockHashes.at(-1) !== before, 90_000);
  report("finality advances after the jam0 restart", true);
  await waitUntil("at least 20 finalized events", () => finalized().length >= 20, 90_000);
  report("at least 20 finalized events", true, `${finalized().length}`);
  await collect();
  report("the follow never stopped", !chain.events.some((e) => e.event === "stop"));
  log(`${Object.keys(headers).length} headers, ${finalized().length} finalized events, ${proofs.length} captured proofs`);

  if (env.JAM_FINALITY_FIXTURE_EXPORT) {
    const fixture = buildFixture({ ctx, spec, headers, finalized: finalized(), proofs, commit: env.JAM_POLKAJAM_COMMIT });
    await ctx.dumpDb({
      "fixture.json": JSON.stringify(fixture, null, 2) + "\n",
      "capture.json": JSON.stringify({ headers, proofs, events: chain.events, logs: ctx.clientLogs }, null, 2),
    });
    report("fixture handed to Rust", true, `${fixture.headers.length} headers, ${fixture.justifications.length} justifications`);
  }
}

/**
 * The committed `lib/src/jam/finality/fixtures/polkajam-grandpa.json` shape:
 * captured header and CE 130 payload bytes exactly as received, checked here
 * (frame lengths, hashes, ancestry) and kept only for targets the client
 * finalized. The spec keeps the four genesis state items the client reads.
 */
function buildFixture({ ctx, spec, headers, finalized, proofs, commit }) {
  const check = (name, ok, detail) => must(ctx, `fixture: ${name}`, ok, detail);
  const fixtureSpec = JSON.parse(JSON.stringify(spec));
  fixtureSpec.genesis_state = Object.fromEntries(Object.entries(spec.genesis_state)
    .filter(([key]) => [4, 6, 8, 11].some((index) => key === stateKey(index))));
  check("spec keeps four genesis state items", Object.keys(fixtureSpec.genesis_state).length === 4);

  const slotOf = (encoded) => new DataView(hexToBytes(encoded).buffer).getUint32(96, true);
  const sorted = Object.entries(headers).sort(([, a], [, b]) => slotOf(a) - slotOf(b));
  const known = new Set([hashOfHeaderHex(spec.genesis_header)]);
  for (const [hash, encoded] of sorted) {
    const bytes = hexToBytes(encoded);
    if ("0x" + bytesToHex(blake2b256(bytes)) !== hash) check("captured header hashes to its hash", false, hash);
    if (!known.has("0x" + bytesToHex(bytes.subarray(0, 32)))) check("captured parent is present", false, hash);
    known.add(hash);
  }
  check("captured headers hash and link", true, `${sorted.length}`);

  const finalizedHashes = new Set(finalized.flatMap((event) => event.finalizedBlockHashes));
  const kept = new Map();
  for (const { request, response } of proofs) {
    const frame = hexToBytes(response);
    const view = new DataView(frame.buffer);
    if (frame.length < 4 || view.getUint32(0, true) === 0) continue;
    if (view.getUint32(0, true) !== frame.length - 4) check("one complete CE 130 frame", false, `${frame.length}`);
    const payload = frame.subarray(4);
    // round (8) ++ set id (4) ++ target hash (32) ++ posterior state root (32) ++ slot (4)
    if (payload.length < 80) check("justification payload is at least 80 bytes", false, `${payload.length}`);
    const hash = "0x" + bytesToHex(payload.subarray(12, 44));
    if (bytesToHex(hexToBytes(request).subarray(5, 37)) !== hash.slice(2)) check("CE 130 request targets the justified hash", false, hash);
    if (finalizedHashes.has(hash)) kept.set(hash, payload);
  }
  const u32 = (bytes, at) => new DataView(bytes.buffer, bytes.byteOffset).getUint32(at, true);
  const justifications = [...kept.values()].sort((a, b) => u32(a, 76) - u32(b, 76));
  check("retain at least twenty verified live proofs", justifications.length >= 20, `${justifications.length}`);
  check("proofs span three authority sets", new Set(justifications.map((bytes) => u32(bytes, 8))).size >= 3);
  return {
    polkajam_commit: commit,
    description: "Live FinalityMode::Grandpa capture; three or more authority sets and node0 restart. Headers and CE130 payloads are unmodified network bytes.",
    spec: fixtureSpec,
    headers: sorted.map(([, encoded]) => encoded),
    justifications: justifications.map((bytes) => bytesToHex(bytes)),
  };
}
