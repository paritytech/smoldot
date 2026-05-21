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

// chainHead_v1_follow conformance + regression driver.
//
// Subscribes the para chain (withRuntime=true), validates the spec invariants
// of every event, and on resubscribe (after `stop` or explicit unfollow)
// reports a regression if the new initial finalized number is below the
// previous subscription's last finalized number.

import * as fs from "node:fs";
import {
  createSmoldotClient,
  addChainFromSpec,
  readDbContentIfSet,
  sendRpc,
  report,
} from "./helpers.js";

const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const paraSpecPath = process.env.PARA_CHAIN_SPEC;
const withRuntime = (process.env.WITH_RUNTIME ?? "true") === "true";
const minNewBlocks = Number.parseInt(process.env.MIN_NEW_BLOCKS ?? "5", 10);
const minFinalized = Number.parseInt(process.env.MIN_FINALIZED_EVENTS ?? "2", 10);
const testResubscribe = (process.env.TEST_RESUBSCRIBE ?? "true") === "true";
const overallTimeoutMs = Number.parseInt(process.env.OVERALL_TIMEOUT_MS ?? "300000", 10);
const perSubTimeoutMs = Number.parseInt(process.env.PER_SUB_TIMEOUT_MS ?? "180000", 10);
const relayBestAtLaunch = Number.parseInt(process.env.RELAY_BEST_AT_LAUNCH ?? "0", 10);
const relayFinalizedAtLaunch = Number.parseInt(process.env.RELAY_FINALIZED_AT_LAUNCH ?? "0", 10);
const paraBestAtLaunch = Number.parseInt(process.env.PARA_BEST_AT_LAUNCH ?? "0", 10);
const paraFinalizedAtLaunch = Number.parseInt(process.env.PARA_FINALIZED_AT_LAUNCH ?? "0", 10);
const initialLagTolerance = Number.parseInt(process.env.INITIAL_LAG_TOLERANCE ?? "50", 10);

if (!relaySpecPath || !paraSpecPath) {
  console.error("Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC");
  process.exit(1);
}

// Decodes the block number from a hex SCALE-encoded substrate header.
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
  throw new Error("compact mode 3 not supported");
}

// Multiplexes a smoldot chain's JSON-RPC stream. One pump loop classifies each
// message into either a `chainHead_v1_followEvent` (queued by subId, awaited
// via nextEvent) or an id-bearing response (resolved against pending requests
// via request). Without this, calling chainHead_v1_header from inside the
// event loop would drop events arriving between request and response.
class JsonRpcMux {
  constructor(chain) {
    this.chain = chain;
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
    const id = sendRpc(this.chain, method, params).toString();
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
    this.counters = {
      subscriptions: 0,
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
    this.subLabel = `sub#${this.counters.subscriptions}`;
    this.knownHashes = new Set();
    this.parents = new Map();
    this.heights = new Map();
    this.initializedHashes = [];
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
    this.counters.subscriptions += 1;
    this._resetSubState();
  }

  violation(msg) {
    const full = `[${this.subLabel}] ${msg}`;
    this.violations.push(full);
    console.error(`VIOLATION ${full}`);
  }

  regression(msg) {
    const full = `[${this.subLabel}] ${msg}`;
    this.regressions.push(full);
    console.error(`REGRESSION ${full}`);
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
    for (const h of hashes) this.knownHashes.add(h);
    this.initializedHashes = [...hashes];
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
    this.knownHashes.add(event.blockHash);
    this.parents.set(event.blockHash, event.parentBlockHash);
    const parentHeight = this.heights.get(event.parentBlockHash);
    if (parentHeight != null) {
      this.heights.set(event.blockHash, parentHeight + 1);
    }
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
        return;
      }
      prev = h;
    }
    for (const h of prunedHashes) {
      this.knownHashes.delete(h);
      this.parents.delete(h);
      this.heights.delete(h);
    }
    this.lastFinalizedHash = finalizedHashes[finalizedHashes.length - 1];
    const lastFinalizedHeight = this.heights.get(this.lastFinalizedHash);
    if (lastFinalizedHeight != null) {
      this.lastFinalizedNumber = lastFinalizedHeight;
    }
    this.counters.finalized += 1;
  }

  recordInitialFinalizedNumber(n) {
    this.initialFinalizedNumber = n;
    this.lastFinalizedNumber = n;
    // Seed heights for the contiguous chain ending at the last initialized hash.
    for (let i = this.initializedHashes.length - 1, h = n; i >= 0; i--, h--) {
      this.heights.set(this.initializedHashes[i], h);
    }
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
      paraFinalizedAtLaunch > 0 &&
      n + initialLagTolerance < paraFinalizedAtLaunch
    ) {
      this.regression(
        `initial finalized #${n} lags more than ${initialLagTolerance} behind para finalized at launch #${paraFinalizedAtLaunch}`,
      );
    }
  }

  recordLastFinalizedNumber(n) {
    this.lastFinalizedNumber = n;
  }

  thresholdsMet() {
    return (
      this.counters.newBlock >= minNewBlocks && this.counters.finalized >= minFinalized
    );
  }
}

async function fetchBlockNumber(mux, subId, hash) {
  const headerHex = await mux.request("chainHead_v1_header", [subId, hash], 30_000);
  return decodeHeaderNumber(headerHex);
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

function logEvent(label, event, validator) {
  const name = event.event.padEnd(16);
  switch (event.event) {
    case "initialized": {
      const last = validator.initialFinalizedHash;
      console.log(`[${label}] ${name} ${heightStr(validator, last)} ${shortHash(last)}`);
      break;
    }
    case "newBlock":
      console.log(
        `[${label}] ${name} ${heightStr(validator, event.blockHash)} ${shortHash(event.blockHash)} parent=${shortHash(event.parentBlockHash)}`,
      );
      break;
    case "bestBlockChanged":
      console.log(
        `[${label}] ${name} ${heightStr(validator, event.bestBlockHash)} ${shortHash(event.bestBlockHash)}`,
      );
      break;
    case "finalized": {
      const f = event.finalizedBlockHashes ?? [];
      const p = event.prunedBlockHashes ?? [];
      const last = f[f.length - 1];
      console.log(
        `[${label}] ${name} ${heightStr(validator, last)} ${shortHash(last)} finalized_cnt=${f.length} pruned_cnt=${p.length}`,
      );
      break;
    }
    case "stop":
      console.log(`[${label}] ${name}`);
      break;
    default:
      break;
  }
}

async function followSubscription(chain, mux) {
  const subId = await mux.request("chainHead_v1_follow", [withRuntime], 30_000);
  if (typeof subId !== "string" || !subId) {
    throw new Error(`Unexpected follow subscription id: ${JSON.stringify(subId)}`);
  }
  return subId;
}

async function runSubscription(chain, mux, validator, subId, perSubDeadline) {
  // First event must be `initialized`.
  const first = await mux.nextEvent(subId, perSubDeadline - Date.now());
  validator.onEvent(first);
  if (first.event !== "initialized") {
    throw new Error(`first event was ${first.event}, expected initialized`);
  }
  const initialNumber = await fetchBlockNumber(mux, subId, validator.initialFinalizedHash);
  validator.recordInitialFinalizedNumber(initialNumber);
  logEvent(validator.subLabel, first, validator);

  // Drain events until thresholds met, stop, or timeout.
  while (!validator.stopped && Date.now() < perSubDeadline) {
    if (validator.thresholdsMet()) break;
    let ev;
    try {
      ev = await mux.nextEvent(subId, Math.max(1, perSubDeadline - Date.now()));
    } catch (e) {
      return { reason: "per_sub_timeout", lastFinalizedHash: validator.lastFinalizedHash };
    }
    validator.onEvent(ev);
    logEvent(validator.subLabel, ev, validator);
  }

  // Fetch the final last-finalized number while the sub may still be alive.
  if (!validator.stopped) {
    try {
      const n = await fetchBlockNumber(mux, subId, validator.lastFinalizedHash);
      validator.recordLastFinalizedNumber(n);
    } catch (e) {
      console.error(`[${validator.subLabel}] failed to fetch last finalized number: ${e.message}`);
    }
  }
  if (validator.stopped) {
    return { reason: "stop" };
  }
  if (validator.thresholdsMet()) {
    return { reason: "thresholds_met" };
  }
  return { reason: "per_sub_timeout" };
}

const client = createSmoldotClient();
let relay;
let para;
let exitOk = false;

try {
  const relayDbContent = readDbContentIfSet("SMOLDOT_DB_RELAY");
  const paraDbContent = readDbContentIfSet("SMOLDOT_DB_PARA");

  console.log(
    `network at launch: relay best=#${relayBestAtLaunch} finalized=#${relayFinalizedAtLaunch} | para best=#${paraBestAtLaunch} finalized=#${paraFinalizedAtLaunch} (lag tolerance=${initialLagTolerance})`,
  );

  relay = await addChainFromSpec(client, relaySpecPath, { databaseContent: relayDbContent });
  report("addChain relay", true);

  para = await addChainFromSpec(client, paraSpecPath, {
    databaseContent: paraDbContent,
    potentialRelayChains: [relay],
  });
  report("addChain parachain", true);

  const mux = new JsonRpcMux(para);
  const validator = new ChainHeadValidator({ withRuntime });
  const overallDeadline = Date.now() + overallTimeoutMs;

  // Phase 1: primary subscription.
  validator.beginNewSubscription();
  let subId = await followSubscription(para, mux);
  report("chainHead_v1_follow accepted", true, `subId=${subId}`);
  let result = await runSubscription(
    para,
    mux,
    validator,
    subId,
    Math.min(Date.now() + perSubTimeoutMs, overallDeadline),
  );

  // Soft-recover from any `stop` events: resubscribe and continue counting.
  while (result.reason === "stop" && Date.now() < overallDeadline) {
    console.log(`[${validator.subLabel}] received stop, resubscribing`);
    validator.beginNewSubscription();
    subId = await followSubscription(para, mux);
    result = await runSubscription(
      para,
      mux,
      validator,
      subId,
      Math.min(Date.now() + perSubTimeoutMs, overallDeadline),
    );
  }

  const primaryOk = validator.thresholdsMet();
  report(
    "primary subscription thresholds met",
    primaryOk,
    `newBlock=${validator.counters.newBlock}/${minNewBlocks} finalized=${validator.counters.finalized}/${minFinalized}`,
  );

  // Phase 2: explicit resubscribe.
  if (testResubscribe && primaryOk && Date.now() < overallDeadline) {
    try {
      await mux.request("chainHead_v1_unfollow", [subId], 30_000);
      report("chainHead_v1_unfollow accepted", true, `subId=${subId}`);
    } catch (e) {
      report("chainHead_v1_unfollow accepted", false, e.message);
    }
    validator.beginNewSubscription();
    const newSubId = await followSubscription(para, mux);
    report("chainHead_v1_follow after unfollow accepted", true, `subId=${newSubId}`);
    const reducedNewBlocks = Math.max(1, Math.floor(minNewBlocks / 2));
    const reducedFinalized = Math.max(1, Math.floor(minFinalized / 2));
    const origCounters = { ...validator.counters };
    const origThresholds = validator.thresholdsMet.bind(validator);
    validator.thresholdsMet = () =>
      validator.counters.newBlock - origCounters.newBlock >= reducedNewBlocks &&
      validator.counters.finalized - origCounters.finalized >= reducedFinalized;
    const phase2Result = await runSubscription(
      para,
      mux,
      validator,
      newSubId,
      Math.min(Date.now() + perSubTimeoutMs, overallDeadline),
    );
    validator.thresholdsMet = origThresholds;
    const phase2Ok =
      validator.counters.newBlock - origCounters.newBlock >= reducedNewBlocks &&
      validator.counters.finalized - origCounters.finalized >= reducedFinalized;
    report(
      "resubscribe phase thresholds met",
      phase2Ok,
      `delta_newBlock=${validator.counters.newBlock - origCounters.newBlock}/${reducedNewBlocks} delta_finalized=${validator.counters.finalized - origCounters.finalized}/${reducedFinalized} reason=${phase2Result.reason}`,
    );
  }

  // Final reporting.
  report(
    "no spec violations",
    validator.violations.length === 0,
    validator.violations.length === 0
      ? `subs=${validator.counters.subscriptions}`
      : validator.violations.join(" | "),
  );
  report(
    "no regressions",
    validator.regressions.length === 0,
    validator.regressions.length === 0
      ? `subs=${validator.counters.subscriptions}`
      : validator.regressions.join(" | "),
  );
  report(
    "event counters",
    true,
    JSON.stringify(validator.counters),
  );

  exitOk =
    validator.violations.length === 0 &&
    validator.regressions.length === 0 &&
    primaryOk;
} catch (e) {
  report("chainhead_v1_follow_test", false, e.message);
}

process.exit(exitOk && !process.exitCode ? 0 : 1);
