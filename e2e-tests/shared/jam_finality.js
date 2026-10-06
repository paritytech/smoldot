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

// Live GRANDPA acceptance of D1 (GRANDPA finality) on a fresh six-validator
// network spawned by `tests/jam_finality.rs`: the client verifies three
// authority sets, a pinned header survives tree pruning, and finality keeps
// advancing while Rust kills jam0 and starts it again. The follow must never
// stop. With `JAM_FINALITY_FIXTURE_EXPORT=1` the body also builds the D1
// fixture (captured headers and CE 130 payloads, unmodified) and hands it to
// Rust through `ctx.dumpDb`.
//
// Sync labels: body → Rust `THREE_SETS`; Rust → body `RESTARTED`.

import {
  addJamChain,
  blake2b256,
  bytesToHex,
  delay,
  hashOfHeaderHex,
  installProofCapture,
  stateKey,
} from "./jam.js";
import { hexToBytes } from "./codec.js";

export const fileInputs = ["JAM_CHAIN_SPEC"];
export const envInputs = ["JAM_FINALITY_FIXTURE_EXPORT", "JAM_POLKAJAM_COMMIT"];

export default async function jamFinality(ctx) {
  const { files, env, report, log } = ctx;
  if (!files.JAM_CHAIN_SPEC) throw new Error("JAM_CHAIN_SPEC required");
  const spec = JSON.parse(files.JAM_CHAIN_SPEC);

  // Before any connection exists, so every CE 130 exchange is recorded.
  const proofs = installProofCapture();
  const chain = await addJamChain(ctx.client, spec);
  const subscription = await chain.request("chainHead_v1_follow", [false]);

  const headers = {};
  let cursor = 0;
  let retainedPin;
  const collect = async () => {
    for (; cursor < chain.events.length; cursor += 1) {
      const event = chain.events[cursor];
      if (event.event === "stop") {
        report("follow survives root advancement (no stop event)", false, JSON.stringify(event));
        throw new Error("follow must survive root advancement");
      }
      if (event.event === "newBlock") {
        const header = await chain.request("chainHead_v1_header", [subscription, event.blockHash]);
        if (!header) {
          report("chainHead_v1_header answers every new block", false, event.blockHash);
          throw new Error(`no header for ${event.blockHash}`);
        }
        headers[event.blockHash] = header;
        if (!retainedPin) retainedPin = event.blockHash;
        else await chain.request("chainHead_v1_unpin", [subscription, [event.blockHash]]);
      }
    }
  };
  const finalized = () => chain.events.filter((e) => e.event === "finalized");
  const waitUntil = async (what, condition, timeoutMs) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await collect();
      if (condition()) return;
      await delay(500);
    }
    report(what, false, `timed out after ${timeoutMs / 1000}s`);
    throw new Error(`timed out waiting for ${what}`);
  };

  await waitUntil("the client finalizes in authority set 3",
    () => ctx.clientLogs.some((l) => /jam-finalized/.test(l.message) && /set_id=3\b/.test(l.message)), 210_000);
  report("the client finalizes in authority set 3", true,
    ctx.clientLogs.find((l) => /jam-finalized/.test(l.message) && /set_id=3\b/.test(l.message)).message);
  report("at least 3 finalized events", finalized().length >= 3, `${finalized().length}`);
  report("CE 130 justifications were captured", proofs.length > 0, `${proofs.length}`);
  const before = finalized().at(-1).finalizedBlockHashes.at(-1);
  const pinned = await chain.request("chainHead_v1_header", [subscription, retainedPin]);
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
    const fixture = buildFixture({ spec, headers, finalized: finalized(), proofs, report, commit: env.JAM_POLKAJAM_COMMIT });
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
function buildFixture({ spec, headers, finalized, proofs, report, commit }) {
  const must = (name, ok, detail) => {
    report(`fixture: ${name}`, ok, detail);
    if (!ok) throw new Error(`fixture: ${name}`);
  };
  const fixtureSpec = JSON.parse(JSON.stringify(spec));
  fixtureSpec.genesis_state = Object.fromEntries(Object.entries(spec.genesis_state)
    .filter(([key]) => [4, 6, 8, 11].some((index) => key === stateKey(index))));
  must("spec keeps four genesis state items", Object.keys(fixtureSpec.genesis_state).length === 4);

  const slotOf = (encoded) => new DataView(hexToBytes(encoded).buffer).getUint32(96, true);
  const sorted = Object.entries(headers).sort(([, a], [, b]) => slotOf(a) - slotOf(b));
  const known = new Set([hashOfHeaderHex(spec.genesis_header)]);
  for (const [hash, encoded] of sorted) {
    const bytes = hexToBytes(encoded);
    if ("0x" + bytesToHex(blake2b256(bytes)) !== hash) must("captured header hashes to its hash", false, hash);
    if (!known.has("0x" + bytesToHex(bytes.subarray(0, 32)))) must("captured parent is present", false, hash);
    known.add(hash);
  }
  must("captured headers hash and link", true, `${sorted.length}`);

  const finalizedHashes = new Set(finalized.flatMap((event) => event.finalizedBlockHashes));
  const kept = new Map();
  for (const { request, response } of proofs) {
    const frame = hexToBytes(response);
    const view = new DataView(frame.buffer);
    if (frame.length < 4 || view.getUint32(0, true) === 0) continue;
    if (view.getUint32(0, true) !== frame.length - 4) must("one complete CE 130 frame", false, `${frame.length}`);
    const payload = frame.subarray(4);
    // round (8) ++ set id (4) ++ target hash (32) ++ posterior state root (32) ++ slot (4)
    if (payload.length < 80) must("justification payload is at least 80 bytes", false, `${payload.length}`);
    const hash = "0x" + bytesToHex(payload.subarray(12, 44));
    if (bytesToHex(hexToBytes(request).subarray(5, 37)) !== hash.slice(2)) must("CE 130 request targets the justified hash", false, hash);
    if (finalizedHashes.has(hash)) kept.set(hash, payload);
  }
  const u32 = (bytes, at) => new DataView(bytes.buffer, bytes.byteOffset).getUint32(at, true);
  const justifications = [...kept.values()].sort((a, b) => u32(a, 76) - u32(b, 76));
  must("retain at least twenty verified live proofs", justifications.length >= 20, `${justifications.length}`);
  must("proofs span three authority sets", new Set(justifications.map((bytes) => u32(bytes, 8))).size >= 3);
  return {
    polkajam_commit: commit,
    description: "Live FinalityMode::Grandpa capture; three or more authority sets and node0 restart. Headers and CE130 payloads are unmodified network bytes.",
    spec: fixtureSpec,
    headers: sorted.map(([, encoded]) => encoded),
    justifications: justifications.map((bytes) => bytesToHex(bytes)),
  };
}
