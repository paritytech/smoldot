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

// The JAM browser gate of C2 (browser end-to-end test and CI gate), on a Dummy
// (no finality) PolkaJam network spawned by `tests/jam_follow.rs`:
//
//   1. positive - follow the live network: initialized anchor, >= 5 newBlock
//                 within 5 slots, parent links, bestBlockChanged, and
//                 chainHead_v1_header hashing to the reported hash;
//   2. restart  - Rust kills jam0 and starts it again on its database; a new
//                 block must link to a pre-restart hash;
//   3. unfollow - chainHead_v1_unfollow resolves and the event stream stops;
//   4. negative - a second client whose spec carries a corrupted genesis
//                 authority set gets its own anchor, is refused by the
//                 network, and never sees a newBlock;
//   5. final    - Dummy-specific wire facts (typed NoData for CE 153, no
//                 CE 129, no live C(8) read) and no finalized event at all.
//
// Sync labels: body → Rust `POSITIVE_DONE`, `RESTART_READY`; Rust → body
// `KILLED`, `RESTARTED`.

import {
  addJamChain,
  corruptGenesisAuthorities,
  delay,
  hashOfHeaderHex,
  installJamWireCapture,
  waitFor,
} from "./jam.js";

export const fileInputs = ["JAM_CHAIN_SPEC"];

const SLOT_SECONDS = 6;

export default async function jamFollow(ctx) {
  const { files, log } = ctx;
  if (!files.JAM_CHAIN_SPEC) throw new Error("JAM_CHAIN_SPEC required");
  const check = (phase, name, passed, detail) => {
    ctx.report(`[${phase}] ${name}`, !!passed, detail === undefined ? undefined : String(detail));
    return !!passed;
  };
  const phase = async (name, body) => {
    const started = Date.now();
    log(`phase ${name}: start`);
    try {
      await body();
    } catch (error) {
      check(name, `${name} phase completed without an unexpected error`, false, error?.stack ?? String(error));
    }
    log(`phase ${name}: done in ${Date.now() - started}ms`);
  };

  // Before any connection exists, so every session is recorded.
  const wire = installJamWireCapture();

  const spec = JSON.parse(files.JAM_CHAIN_SPEC);
  const { spec: wrongSpec } = corruptGenesisAuthorities(spec);
  const genesisHash = hashOfHeaderHex(spec.genesis_header);
  const wrongGenesisHash = hashOfHeaderHex(wrongSpec.genesis_header);

  if (typeof WebTransport !== "function") {
    check("positive", "WebTransport is available in the page", false, "the browser does not expose WebTransport");
    throw new Error("WebTransport is unavailable; the negative path cannot be faked and the run is aborted");
  }
  check("positive", "WebTransport is available in the page", true);
  check("positive", "spec genesis hash is derived from the generated spec", genesisHash !== wrongGenesisHash,
    `${genesisHash} vs corrupted ${wrongGenesisHash}`);

  const main = await addJamChain(ctx.client, spec);
  let sub;
  let initialized;
  let newBlocks = [];

  await phase("positive", async () => {
    sub = await main.request("chainHead_v1_follow", [false]);
    check("positive", "chainHead_v1_follow returns a subscription id", typeof sub === "string" && sub.length > 0, sub);

    initialized = await waitFor(() => main.events.find((e) => e.event === "initialized"), 30_000);
    check("positive", "initialized event received", !!initialized);
    check("positive", "initialized anchor equals the spec genesis hash",
      initialized?.finalizedBlockHashes?.[0] === genesisHash, initialized?.finalizedBlockHashes?.[0]);

    await waitFor(() => {
      newBlocks = main.events.filter((e) => e.event === "newBlock");
      return newBlocks.length >= 5;
    }, 60_000);
    check("positive", "at least 5 newBlock events received", newBlocks.length >= 5, `received ${newBlocks.length}`);
    if (newBlocks.length >= 5) {
      const spanMs = newBlocks[4].t - newBlocks[0].t;
      check("positive", `5th newBlock within 5 slots (${5 * SLOT_SECONDS}s) of the first`,
        spanMs <= 5 * SLOT_SECONDS * 1000, `${spanMs}ms`);
    }

    const known = new Set(initialized ? initialized.finalizedBlockHashes : []);
    let parentFailure = null;
    for (const block of newBlocks) {
      if (!known.has(block.parentBlockHash)) {
        parentFailure = `${block.blockHash} has unreported parent ${block.parentBlockHash}`;
        break;
      }
      known.add(block.blockHash);
    }
    check("positive", "every newBlock parent is a previously reported hash or the anchor",
      !parentFailure, parentFailure || `${newBlocks.length} blocks linked`);

    const firstNewBlock = newBlocks[0];
    const bestAfterBlock = firstNewBlock
      && main.events.find((e) => e.event === "bestBlockChanged" && e.t >= firstNewBlock.t);
    check("positive", "bestBlockChanged received after the first newBlock", !!bestAfterBlock,
      bestAfterBlock ? bestAfterBlock.bestBlockHash : "none");

    const target = newBlocks.at(-1)?.blockHash ?? genesisHash;
    const headerHex = await main.request("chainHead_v1_header", [sub, target]);
    check("positive", "chainHead_v1_header returns hexadecimal bytes",
      typeof headerHex === "string" && /^0x(?:[0-9a-fA-F]{2})+$/.test(headerHex),
      typeof headerHex === "string" ? `${headerHex.length} chars` : String(headerHex));
    check("positive", "blake2b-256 of the header bytes equals the requested hash",
      typeof headerHex === "string" && hashOfHeaderHex(headerHex) === target,
      typeof headerHex === "string" ? `${hashOfHeaderHex(headerHex)} vs ${target}` : "no header");
  });

  await phase("restart", async () => {
    await ctx.sendSync("POSITIVE_DONE");
    await ctx.waitSync("KILLED", 120_000);
    // Only pre-restart *block* hashes are accepted as catch-up parents. The
    // anchor is excluded so that a re-sync from genesis cannot make this pass
    // vacuously; the positive phase guarantees >= 5 blocks.
    const eventsBeforeRestart = main.events.length;
    const preRestartHashes = new Set();
    const preRestartAnchors = new Set();
    for (const entry of main.events) {
      if (entry.event === "initialized") entry.finalizedBlockHashes.forEach((hash) => preRestartAnchors.add(hash));
      if (entry.event === "newBlock") preRestartHashes.add(entry.blockHash);
    }
    check("restart", "pre-restart block hashes are available as catch-up parents",
      preRestartHashes.size >= 5, `${preRestartHashes.size} block hashes`);
    const restartStarted = Date.now();
    await ctx.sendSync("RESTART_READY");
    await ctx.waitSync("RESTARTED", 180_000);

    const firstAfterRestart = await waitFor(
      () => main.events.slice(eventsBeforeRestart).find((e) => e.event === "newBlock"), 60_000);
    check("restart", "a newBlock arrives within 60s of the jam0 restart",
      !!firstAfterRestart, firstAfterRestart ? `after ${firstAfterRestart.t - restartStarted}ms` : "timeout");
    const parent = firstAfterRestart?.parentBlockHash;
    check("restart", "the newBlock parent links to a pre-restart reported block (not just the anchor)",
      !!parent && preRestartHashes.has(parent),
      parent
        ? `${parent} (pre-restart block: ${preRestartHashes.has(parent)}, anchor: ${preRestartAnchors.has(parent)})`
        : "no post-restart newBlock");

    const bestAfterRestart = await waitFor(() => main.events.slice(eventsBeforeRestart)
      .find((e) => e.event === "bestBlockChanged" && firstAfterRestart && e.t >= firstAfterRestart.t), 30_000);
    check("restart", "bestBlockChanged follows the post-restart newBlock", !!bestAfterRestart,
      bestAfterRestart ? bestAfterRestart.bestBlockHash : "none");
  });

  await phase("unfollow", async () => {
    const before = main.events.length;
    const result = await main.request("chainHead_v1_unfollow", [sub]);
    check("unfollow", "chainHead_v1_unfollow resolves", result === null || result === undefined, JSON.stringify(result));
    await delay(2500);
    check("unfollow", "no follow events arrive in the 2s after unfollow",
      main.events.length === before, `${before} -> ${main.events.length}`);
  });

  // What this phase does and does not establish: see `corruptGenesisAuthorities`
  // in jam.js. The Dummy network refuses the unknown genesis hash with NoData;
  // a GRANDPA network refuses the altered set 0 while warping.
  const negativeClient = ctx.startClient({}, "negative");
  let negative;
  await phase("negative", async () => {
    negative = await addJamChain(negativeClient.client, wrongSpec);
    await negative.request("chainHead_v1_follow", [false]);
    const negativeInitialized = await waitFor(
      () => negative.events.find((e) => e.event === "initialized"), 30_000);
    check("negative", "the corrupted spec still loads and anchors at its own genesis hash",
      negativeInitialized?.finalizedBlockHashes?.[0] === wrongGenesisHash,
      negativeInitialized?.finalizedBlockHashes?.[0]);

    const drop = await waitFor(() => {
      const entries = negativeClient.logs;
      const rejected = entries.find((e) => e.message.startsWith("jam-warp-rejected"));
      if (rejected) return { signature: `jam-warp-rejected: ${rejected.message}` };
      const connectIndex = entries.findIndex((e) => e.message === "jam-connect");
      const reconnectIndex = entries.findIndex((e, index) => index > connectIndex && e.message === "jam-reconnect");
      if (connectIndex >= 0 && reconnectIndex > connectIndex) {
        return { signature: `NoData reconnect: ${entries[connectIndex].t} -> ${entries[reconnectIndex].t}` };
      }
      return undefined;
    }, 90_000);
    check("negative", "corrupted authority set is rejected within 90s", !!drop,
      drop ? drop.signature : "neither jam-warp-rejected nor a jam-connect/jam-reconnect pair observed");
  });

  await phase("final", async () => {
    const logs = ctx.clientLogs;
    check("positive", "Dummy CE153 terminates with typed NoData",
      wire.requests.some((r) => r.bytes[0] === 153)
      && logs.some((e) => e.message.startsWith("jam-warp-fragmentless;") && e.message.includes("reason=NoData")));
    check("positive", "Dummy makes zero CE129 requests",
      wire.requests.every((r) => r.bytes[0] !== 129));
    // D3 (peer discovery) reads the active set only after a verified finality
    // advance, which a Dummy network never produces. Since D18 (zombienet demo)
    // the pool starts with the spec's bootnodes and its genesis C(8)
    // validators, so slots may hold either; a `discovered` peer, a CE 129
    // discovery read or a pool merge would mean a live read happened.
    // `jam_discovery` covers GRANDPA.
    const assigned = logs.filter((e) => e.message.startsWith("jam-slot-assigned;"));
    const sources = [...new Set(assigned.map((e) => /source=([a-z]+)/.exec(e.message)?.[1]))];
    check("positive", "Dummy reads no live C(8): every slot assignment comes from the spec (bootnode or genesis), none from a live discovery read",
      assigned.length > 0 && sources.every((source) => source === "bootnode" || source === "genesis")
      && !logs.some((e) => /^jam-(discovery-read-started|pool-changed)/.test(e.message)),
      `${assigned.length} assignment(s), sources ${sources.join("+")}`);
    check("positive", "no finalized event after initialized for the whole session",
      !main.events.some((e) => e.event === "finalized"), `${main.events.length} events`);
    check("negative", "no newBlock is ever emitted under the corrupted authority set",
      !(negative?.events ?? []).some((e) => e.event === "newBlock"), `${negative?.events.length ?? 0} events`);
    log(`wire: ${wire.connections.length} connection(s), ${wire.requests.length} request(s); ` +
      `genesis ${genesisHash}, corrupted ${wrongGenesisHash}`);
  });
}
