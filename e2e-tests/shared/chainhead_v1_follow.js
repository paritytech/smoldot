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

// chainHead_v1_follow conformance + regression test body — runs on either
// host via the ctx abstraction.
//
// Subscribes the para chain (or the relay chain when no para spec is given),
// validates the spec invariants of every event, and on resubscribe (after
// `stop` or explicit unfollow) reports a regression if the new initial
// finalized number is below the previous subscription's last finalized number.

import { createRpc } from "./rpc.js";
import { decodeHeader } from "./codec.js";

export const fileInputs = [
  "RELAY_CHAIN_SPEC",
  "PARA_CHAIN_SPEC",
  "SMOLDOT_DB_RELAY",
  "SMOLDOT_DB_PARA",
];

// Multiplexes a smoldot chain's JSON-RPC stream. One pump loop classifies each
// message into either a `chainHead_v1_followEvent` (queued by subId, awaited
// via nextEvent) or an id-bearing response (resolved against pending requests
// via request). Without this, calling chainHead_v1_header from inside the
// event loop would drop events arriving between request and response.
//
// NOTE: the mux is the sole consumer of this chain's responses — the chain
// must be added via `client.addChain` directly, NOT via `createRpc`'s
// `addChain` (whose background drain would steal the mux's messages).
class JsonRpcMux {
  constructor(chain) {
    this.chain = chain;
    this.nextId = 1;
    this.eventQueues = new Map();
    this.eventWaiters = new Map();
    this.pendingById = new Map();
    this.errors = [];
    this._loop();
  }

  async _loop() {
    while (true) {
      let raw;
      try {
        raw = await this.chain.nextJsonRpcResponse();
      } catch (e) {
        this.errors.push(e);
        return;
      }
      let msg;
      try {
        msg = JSON.parse(raw);
      } catch (e) {
        this.errors.push(new Error(`malformed JSON: ${raw}`));
        continue;
      }
      if (msg.method === "chainHead_v1_followEvent") {
        const sub = msg.params?.subscription;
        if (!sub) continue;
        const waiters = this.eventWaiters.get(sub);
        if (waiters && waiters.length > 0) {
          waiters.shift()(msg.params.result);
        } else {
          if (!this.eventQueues.has(sub)) this.eventQueues.set(sub, []);
          this.eventQueues.get(sub).push(msg.params.result);
        }
      } else if (msg.id != null) {
        const resolver = this.pendingById.get(msg.id);
        if (resolver) {
          this.pendingById.delete(msg.id);
          resolver(msg);
        }
      }
    }
  }

  nextEvent(subId, timeoutMs) {
    const q = this.eventQueues.get(subId);
    if (q && q.length > 0) return Promise.resolve(q.shift());
    return new Promise((resolve, reject) => {
      const wrapped = (val) => {
        clearTimeout(timer);
        resolve(val);
      };
      const timer = setTimeout(() => {
        const waiters = this.eventWaiters.get(subId);
        if (waiters) {
          const idx = waiters.indexOf(wrapped);
          if (idx >= 0) waiters.splice(idx, 1);
        }
        reject(new Error(`timeout waiting for event on ${subId} after ${timeoutMs}ms`));
      }, timeoutMs);
      if (!this.eventWaiters.has(subId)) this.eventWaiters.set(subId, []);
      this.eventWaiters.get(subId).push(wrapped);
    });
  }

  request(method, params, timeoutMs) {
    const id = (this.nextId++).toString();
    this.chain.sendJsonRpc(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingById.delete(id);
        reject(new Error(`timeout waiting for ${method} response`));
      }, timeoutMs);
      this.pendingById.set(id, (msg) => {
        clearTimeout(timer);
        if (msg.error) {
          reject(new Error(`${method}: ${JSON.stringify(msg.error)}`));
        } else {
          resolve(msg.result);
        }
      });
    });
  }
}

// Spec-conformance + regression validator for one chainHead_v1_follow stream.
// State is per-subscription; counters accumulate across subscriptions via
// `beginNewSubscription`. Violations push into `violations` and are surfaced
// at the end so a single test can collect several before exiting.
class ChainHeadValidator {
  constructor(opts) {
    this.withRuntime = opts.withRuntime;
    this.minNewBlocks = opts.minNewBlocks;
    this.minFinalized = opts.minFinalized;
    this.finalizedAtLaunch = opts.finalizedAtLaunch;
    this.chainLabel = opts.chainLabel
    this.initialLagTolerance = opts.initialLagTolerance;
    this.log = opts.log;
    this.subscriptionCount = 0;
    this.counters = {
      initialized: 0,
      newBlock: 0,
      bestBlockChanged: 0,
      finalized: 0,
      stop: 0,
    };
    this.violations = [];
    this.regressions = [];
    this.previousSub = null;
    this._resetSubState();
  }

  _resetSubState() {
    for (const k of Object.keys(this.counters)) this.counters[k] = 0;
    this.subLabel = `sub#${this.subscriptionCount}`;
    this.knownHashes = new Set();
    this.parents = new Map();
    this.heights = new Map();
    this.currentBest = null;
    this.initialFinalizedHash = null;
    this.lastFinalizedHash = null;
    this.lastFinalizedNumber = null;
    this.initialFinalizedNumber = null;
    this.initialized = false;
    this.stopped = false;
  }

  beginNewSubscription() {
    if (this.initialized) {
      this.previousSub = {
        lastFinalizedHash: this.lastFinalizedHash,
        lastFinalizedNumber: this.lastFinalizedNumber,
        initialFinalizedNumber: this.initialFinalizedNumber,
      };
    }
    this.subscriptionCount += 1;
    this._resetSubState();
  }

  violation(msg) {
    const full = `[${this.subLabel}] ${msg}`;
    this.violations.push(full);
    this.log(`VIOLATION ${full}`);
  }

  regression(msg) {
    const full = `[${this.subLabel}] ${msg}`;
    this.regressions.push(full);
    this.log(`REGRESSION ${full}`);
  }

  onEvent(event) {
    if (this.stopped) {
      this.violation(`event ${event.event} arrived after stop`);
      return;
    }
    switch (event.event) {
      case "initialized":
        this._onInitialized(event);
        break;
      case "newBlock":
        this._onNewBlock(event);
        break;
      case "bestBlockChanged":
        this._onBestBlockChanged(event);
        break;
      case "finalized":
        this._onFinalized(event);
        break;
      case "stop":
        this.stopped = true;
        this.counters.stop += 1;
        break;
      default:
        if (typeof event.event === "string" && event.event.startsWith("operation")) {
          this.violation(`unexpected operation event: ${event.event}`);
        } else {
          this.violation(`unknown event kind: ${JSON.stringify(event.event)}`);
        }
    }
  }

  _onInitialized(event) {
    if (this.initialized) {
      this.violation("duplicate initialized event");
      return;
    }
    const hashes = event.finalizedBlockHashes;
    if (!Array.isArray(hashes) || hashes.length === 0) {
      this.violation("initialized.finalizedBlockHashes empty");
      return;
    }
    if (this.withRuntime && !event.finalizedBlockRuntime) {
      this.violation("initialized.finalizedBlockRuntime missing with withRuntime=true");
    }
    if (!this.withRuntime && event.finalizedBlockRuntime != null) {
      this.violation("initialized.finalizedBlockRuntime present with withRuntime=false");
    }
    for (const h of hashes) this.knownHashes.add(h);
    this.initialFinalizedHash = hashes[hashes.length - 1];
    this.lastFinalizedHash = this.initialFinalizedHash;
    this.initialized = true;
    this.counters.initialized += 1;
  }

  _onNewBlock(event) {
    if (!this.initialized) {
      this.violation(`newBlock before initialized: ${event.blockHash}`);
      return;
    }
    if (this.knownHashes.has(event.blockHash)) {
      this.violation(`duplicate newBlock: ${event.blockHash}`);
      return;
    }
    if (!this.knownHashes.has(event.parentBlockHash)) {
      this.violation(
        `newBlock parent unknown: parent=${event.parentBlockHash} block=${event.blockHash}`,
      );
      return;
    }
    if (!this.withRuntime && event.newRuntime != null) {
      this.violation(`newBlock.newRuntime present with withRuntime=false: ${event.blockHash}`);
    }
    this.knownHashes.add(event.blockHash);
    this.parents.set(event.blockHash, event.parentBlockHash);
    this.counters.newBlock += 1;
  }

  _onBestBlockChanged(event) {
    if (!this.initialized) {
      this.violation(`bestBlockChanged before initialized: ${event.bestBlockHash}`);
      return;
    }
    if (!this.knownHashes.has(event.bestBlockHash)) {
      this.violation(`bestBlockChanged hash unknown: ${event.bestBlockHash}`);
      return;
    }
    this.currentBest = event.bestBlockHash;
    this.counters.bestBlockChanged += 1;
  }

  _onFinalized(event) {
    if (!this.initialized) {
      this.violation("finalized before initialized");
      return;
    }
    const finalizedHashes = event.finalizedBlockHashes ?? [];
    const prunedHashes = event.prunedBlockHashes ?? [];
    if (finalizedHashes.length === 0) {
      this.violation("finalized.finalizedBlockHashes empty");
      return;
    }
    for (const h of finalizedHashes) {
      if (!this.knownHashes.has(h)) {
        this.violation(`finalized hash unknown: ${h}`);
        return;
      }
    }
    for (const h of prunedHashes) {
      if (!this.knownHashes.has(h)) {
        this.violation(`pruned hash unknown: ${h}`);
        return;
      }
    }
    // Chain check: the first finalized's parent must be the previous last finalized;
    // every subsequent block must chain to its predecessor in the list.
    let prev = this.lastFinalizedHash;
    for (const h of finalizedHashes) {
      const parent = this.parents.get(h);
      if (parent && parent !== prev) {
        this.violation(
          `finalized chain break: ${h} parent=${parent} expected=${prev}`,
        );
        // Record once; state still advances to the tip below so we don't
        // re-flag the same gap on every later event.
        break;
      }
      prev = h;
    }
    for (const h of prunedHashes) {
      this.knownHashes.delete(h);
      this.parents.delete(h);
      this.heights.delete(h);
    }
    this.lastFinalizedHash = finalizedHashes[finalizedHashes.length - 1];
    this.counters.finalized += 1;
  }

  recordInitialFinalizedNumber(n) {
    this.initialFinalizedNumber = n;
    this.lastFinalizedNumber = n;
    this.heights.set(this.initialFinalizedHash, n);
    if (
      this.previousSub &&
      this.previousSub.lastFinalizedNumber != null &&
      n < this.previousSub.lastFinalizedNumber
    ) {
      this.regression(
        `new initial finalized #${n} < previous last finalized #${this.previousSub.lastFinalizedNumber}`,
      );
    }
    if (
      this.finalizedAtLaunch > 0 &&
      n + this.initialLagTolerance < this.finalizedAtLaunch
    ) {
      this.regression(
        `initial finalized #${n} lags more than ${this.initialLagTolerance} behind ${this.chainLabel} finalized at launch #${this.finalizedAtLaunch}`,
      );
    }
  }

  setHeight(hash, n) {
    this.heights.set(hash, n);
    if (hash === this.lastFinalizedHash) {
      this.lastFinalizedNumber = n;
    }
  }

  thresholdsMet() {
    return (
      this.counters.newBlock >= this.minNewBlocks &&
      this.counters.finalized >= this.minFinalized
    );
  }
}

// Returns `null` when smoldot reports the block as not available (spec-legal:
// the block is part of the announced chain but smoldot has no header for it
// at this moment — transient pin/unpin state). Caller skips height tracking
// and the parent-hash cross-check for that block.
async function fetchBlockHeader(mux, subId, hash) {
  const headerHex = await mux.request("chainHead_v1_header", [subId, hash], 30_000);
  if (headerHex == null) return null;
  return decodeHeader(headerHex);
}

async function populateHeader(mux, subId, validator, hash, announcedParent) {
  if (!hash || validator.heights.has(hash)) return;
  const header = await fetchBlockHeader(mux, subId, hash);
  if (header == null) return;
  validator.setHeight(hash, header.number);
  if (announcedParent != null && announcedParent !== header.parentHash) {
    validator.violation(
      `announced parent ${shortHash(announcedParent)} for block ${shortHash(hash)} #${header.number} mismatches header parent ${shortHash(header.parentHash)}`,
    );
  }
}

function shortHash(h) {
  if (!h) return "<none>";
  if (!h.startsWith("0x") || h.length < 12) return h;
  return `${h.slice(0, 6)}…${h.slice(-4)}`;
}

function heightStr(validator, hash) {
  const h = validator.heights.get(hash);
  return h != null ? `#${h}` : "#?";
}

function logEvent(log, label, event, validator) {
  const name = event.event.padEnd(16);
  switch (event.event) {
    case "initialized": {
      const last = validator.initialFinalizedHash;
      log(`[${label}] ${name} ${heightStr(validator, last)} ${shortHash(last)}`);
      break;
    }
    case "newBlock":
      log(
        `[${label}] ${name} ${heightStr(validator, event.blockHash)} ${shortHash(event.blockHash)} parent=${shortHash(event.parentBlockHash)}`,
      );
      break;
    case "bestBlockChanged":
      log(
        `[${label}] ${name} ${heightStr(validator, event.bestBlockHash)} ${shortHash(event.bestBlockHash)}`,
      );
      break;
    case "finalized": {
      const f = event.finalizedBlockHashes ?? [];
      const p = event.prunedBlockHashes ?? [];
      const last = f[f.length - 1];
      log(
        `[${label}] ${name} ${heightStr(validator, last)} ${shortHash(last)} finalized_cnt=${f.length} pruned_cnt=${p.length}`,
      );
      break;
    }
    case "stop":
      log(`[${label}] ${name}`);
      break;
    default:
      break;
  }
}

async function followSubscription(mux, withRuntime) {
  const subId = await mux.request("chainHead_v1_follow", [withRuntime], 30_000);
  if (typeof subId !== "string" || !subId) {
    throw new Error(`Unexpected follow subscription id: ${JSON.stringify(subId)}`);
  }
  return subId;
}

async function runSubscription(log, mux, validator, subId, perSubDeadline, isDone) {
  // First event must be `initialized`.
  const first = await mux.nextEvent(subId, perSubDeadline - Date.now());
  validator.onEvent(first);
  if (first.event !== "initialized") {
    throw new Error(`first event was ${first.event}, expected initialized`);
  }
  const initialHeader = await fetchBlockHeader(mux, subId, validator.initialFinalizedHash);
  if (initialHeader != null) {
    validator.recordInitialFinalizedNumber(initialHeader.number);
  } else {
    log(
      `[${validator.subLabel}] chainHead_v1_header returned null for initial finalized; number-based checks for this sub skipped`,
    );
  }
  logEvent(log, validator.subLabel, first, validator);

  while (!validator.stopped && Date.now() < perSubDeadline) {
    if (isDone()) return { reason: "done" };
    let ev;
    try {
      ev = await mux.nextEvent(subId, Math.max(1, perSubDeadline - Date.now()));
    } catch (e) {
      return { reason: "per_sub_timeout" };
    }
    validator.onEvent(ev);
    switch (ev.event) {
      case "newBlock":
        await populateHeader(mux, subId, validator, ev.blockHash, ev.parentBlockHash);
        break;
      case "bestBlockChanged":
        await populateHeader(mux, subId, validator, ev.bestBlockHash, null);
        break;
      case "finalized": {
        const f = ev.finalizedBlockHashes ?? [];
        await populateHeader(mux, subId, validator, f[f.length - 1], null);
        break;
      }
      default:
        break;
    }
    logEvent(log, validator.subLabel, ev, validator);
  }

  if (validator.stopped) return { reason: "stop" };
  if (isDone()) return { reason: "done" };
  return { reason: "per_sub_timeout" };
}

export default async function chainheadV1Follow(ctx) {
  const { report, env, files, log } = ctx;
  const rpc = createRpc(ctx.client);

  const withRuntime = (env.WITH_RUNTIME ?? "true") === "true";
  const minNewBlocks = Number.parseInt(env.MIN_NEW_BLOCKS ?? "5", 10);
  const minFinalized = Number.parseInt(env.MIN_FINALIZED_EVENTS ?? "2", 10);
  const testResubscribe = (env.TEST_RESUBSCRIBE ?? "true") === "true";
  const overallTimeoutMs = Number.parseInt(env.OVERALL_TIMEOUT_MS ?? "300000", 10);
  const perSubTimeoutMs = Number.parseInt(env.PER_SUB_TIMEOUT_MS ?? "180000", 10);
  const relayBestAtLaunch = Number.parseInt(env.RELAY_BEST_AT_LAUNCH ?? "0", 10);
  const relayFinalizedAtLaunch = Number.parseInt(env.RELAY_FINALIZED_AT_LAUNCH ?? "0", 10);
  const paraBestAtLaunch = Number.parseInt(env.PARA_BEST_AT_LAUNCH ?? "0", 10);
  const paraFinalizedAtLaunch = Number.parseInt(env.PARA_FINALIZED_AT_LAUNCH ?? "0", 10);
  const initialLagTolerance = Number.parseInt(env.INITIAL_LAG_TOLERANCE ?? "50", 10);
  const relayOnly = !files.PARA_CHAIN_SPEC;

  if (!files.RELAY_CHAIN_SPEC) {
    throw new Error("Required env vars: RELAY_CHAIN_SPEC (PARA_CHAIN_SPEC optional; if unset, runs relay-only)");
  }

  log(
    `network at launch: relay best=#${relayBestAtLaunch} finalized=#${relayFinalizedAtLaunch} | para best=#${paraBestAtLaunch} finalized=#${paraFinalizedAtLaunch} (lag tolerance=${initialLagTolerance})`,
  );

  let relay;
  let target;
  if (relayOnly) {
    // Relay-only: the relay chain is the muxed target, so add it via the
    // client directly — `createRpc`'s background drain would compete with
    // the mux for its responses.
    relay = await ctx.client.addChain({
      chainSpec: files.RELAY_CHAIN_SPEC,
      databaseContent: files.SMOLDOT_DB_RELAY ?? undefined,
    });
    report("addChain relay", true);
    target = relay;
  } else {
    // The relay chain goes through `createRpc` (used only for the db dump at
    // the end). The para chain is added via the client directly: its responses
    // are consumed exclusively by the mux, and `createRpc`'s background drain
    // would compete with it.
    relay = await rpc.addChain({
      chainSpec: files.RELAY_CHAIN_SPEC,
      databaseContent: files.SMOLDOT_DB_RELAY ?? undefined,
    });
    report("addChain relay", true);

    const para = await ctx.client.addChain({
      chainSpec: files.PARA_CHAIN_SPEC,
      databaseContent: files.SMOLDOT_DB_PARA ?? undefined,
      potentialRelayChains: [relay],
    });
    report("addChain parachain", true);
    target = para;
  }

  const mux = new JsonRpcMux(target);
  const validator = new ChainHeadValidator({
    withRuntime,
    minNewBlocks,
    minFinalized,
    finalizedAtLaunch: relayOnly ? relayFinalizedAtLaunch : paraFinalizedAtLaunch,
    chainLabel: relayOnly ? "relay" : "para",
    initialLagTolerance,
    log,
  });

  const overallDeadline = Date.now() + overallTimeoutMs;

  // Phase 1: primary subscription. Auto-resubscribe on `stop` until thresholds met or budget gone.
  validator.beginNewSubscription();
  let subId = await followSubscription(mux, withRuntime);
  report("chainHead_v1_follow accepted", true, `subId=${subId}`);
  let result;
  do {
    if (result?.reason === "stop") {
      log(`[${validator.subLabel}] received stop, resubscribing`);
      validator.beginNewSubscription();
      subId = await followSubscription(mux, withRuntime);
    }
    result = await runSubscription(
      log,
      mux,
      validator,
      subId,
      Math.min(Date.now() + perSubTimeoutMs, overallDeadline),
      () => validator.thresholdsMet(),
    );
  } while (result.reason === "stop" && Date.now() < overallDeadline);

  const primaryOk = validator.thresholdsMet();
  report(
    "primary subscription thresholds met",
    primaryOk,
    `newBlock=${validator.counters.newBlock}/${minNewBlocks} finalized=${validator.counters.finalized}/${minFinalized}`,
  );

  // Phase 2: explicit resubscribe. Same thresholds; counters reset per sub.
  if (testResubscribe && primaryOk && Date.now() < overallDeadline) {
    try {
      await mux.request("chainHead_v1_unfollow", [subId], 30_000);
      report("chainHead_v1_unfollow accepted", true, `subId=${subId}`);
    } catch (e) {
      report("chainHead_v1_unfollow accepted", false, e.message);
    }
    validator.beginNewSubscription();
    let phase2SubId = await followSubscription(mux, withRuntime);
    report("chainHead_v1_follow after unfollow accepted", true, `subId=${phase2SubId}`);
    let phase2Result;
    do {
      if (phase2Result?.reason === "stop") {
        log(`[${validator.subLabel}] received stop, resubscribing`);
        validator.beginNewSubscription();
        phase2SubId = await followSubscription(mux, withRuntime);
      }
      phase2Result = await runSubscription(
        log,
        mux,
        validator,
        phase2SubId,
        Math.min(Date.now() + perSubTimeoutMs, overallDeadline),
        () => validator.thresholdsMet(),
      );
    } while (phase2Result.reason === "stop" && Date.now() < overallDeadline);
    const phase2Ok = validator.thresholdsMet();
    report(
      "resubscribe phase thresholds met",
      phase2Ok,
      `newBlock=${validator.counters.newBlock}/${minNewBlocks} finalized=${validator.counters.finalized}/${minFinalized}`,
    );
  }

  const reportList = (name, items) => {
    const suffix = `${items.length} issue${items.length === 1 ? "" : "s"}`;
    report(name, items.length === 0, suffix);
    for (const item of items) log(`  ${item}`);
  };
  reportList("no spec violations", validator.violations);
  reportList("no regressions", validator.regressions);

  if (env.SMOLDOT_DB_DUMP_DIR && validator.violations.length === 0) {
    try {
      if (relayOnly) {
        // Relay is the muxed chain here; there is no parachain.
        const relayDb = await mux.request("chainHead_unstable_finalizedDatabase", [], 30_000);
        await ctx.dumpDb({ "relay.json": relayDb });
      } else {
        // Relay has no mux, so use the rpc helper directly. Para is muxed.
        const relayDb = await rpc.sendRpcAndWait(
          relay,
          "chainHead_unstable_finalizedDatabase",
          [],
          30_000,
        );
        const paraDb = await mux.request("chainHead_unstable_finalizedDatabase", [], 30_000);
        await ctx.dumpDb({ "relay.json": relayDb, "para.json": paraDb });
      }
      report("dumped smoldot databaseContent", true, env.SMOLDOT_DB_DUMP_DIR);
    } catch (e) {
      report("dumped smoldot databaseContent", false, e.message);
    }
  }

  const exitOk =
    validator.violations.length === 0 && validator.regressions.length === 0 && primaryOk;
  if (!exitOk) {
    throw new Error(
      `chainhead_v1_follow failed: violations=${validator.violations.length} regressions=${validator.regressions.length} thresholds_met=${primaryOk}`,
    );
  }
}
