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

// Bulletin `bitswap_unstable_stream` test body — runs on either host via the
// ctx abstraction. Exercises the subscription-based batch API: happy path,
// input validation (duplicates / too many / empty), per-CID error fan-out,
// cancellation semantics, and the cold-start wholesale rejection.

import { createRpc } from "./rpc.js";
import { errorCode, hexToBytes, isHexString, sha256Hex } from "./codec.js";

const ERR_INVALID_PARAMS = -32602;
const ERR_TOO_MANY_CIDS = -32801;
const ERR_EMPTY_CIDS = -32802;
const ERR_DUPLICATE_CIDS = -32803;
const ERR_FAIL = -32810;
const ERR_FAIL_RETRY = -32811;
const ERR_FAIL_BACKOFF = -32812;

export const fileInputs = ["RELAY_CHAIN_SPEC", "BULLETIN_CHAIN_SPEC"];

export default async function bulletinBatch(ctx) {
  const { report, env, files } = ctx;
  const rpc = createRpc(ctx.client);

  const missingCid = env.MISSING_CID;
  const payloadsJson = env.PAYLOADS_JSON;
  const maxCidsStr = env.MAX_CIDS;
  if (
    !files.RELAY_CHAIN_SPEC ||
    !files.BULLETIN_CHAIN_SPEC ||
    !missingCid ||
    !payloadsJson ||
    !maxCidsStr
  ) {
    throw new Error(
      "Required env vars: RELAY_CHAIN_SPEC, BULLETIN_CHAIN_SPEC, MISSING_CID, PAYLOADS_JSON, MAX_CIDS",
    );
  }
  const payloads = JSON.parse(payloadsJson);
  const maxCids = Number.parseInt(maxCidsStr, 10);

  let failed = false;
  const check = (name, ok, detail) => {
    report(name, ok, detail);
    if (!ok) failed = true;
  };

  const relay = await rpc.addChain({ chainSpec: files.RELAY_CHAIN_SPEC });
  const bulletin = await rpc.addChain({
    chainSpec: files.BULLETIN_CHAIN_SPEC,
    potentialRelayChains: [relay],
  });

  const t = { rpc, chain: bulletin, check, payloads, missingCid, maxCids };

  // MUST be first: relies on the freshly-created smoldot client having no
  // Bitswap peers connected yet, which exercises the wholesale Have-broadcast
  // failure path (top-level `-32812 FailRetryBackoff`).
  await runStreamColdStartRejectsWholesale(t);
  await runStreamHappy(t);
  await runStreamDedup(t);
  await runStreamTooMany(t);
  await runStreamEmpty(t);
  await runStreamPerCidErrors(t);
  await runStreamMixed(t);
  await runStreamUnstreamSuppressesStreamDone(t);

  if (failed) throw new Error("one or more bulletin_batch checks failed");
}

// ---------- stream tests ----------

// Asserts that on a freshly-created smoldot client (no Bitswap peers yet),
// `bitswap_unstable_stream` rejects the subscription with the top-level
// `-32812 FailRetryBackoff` error. A successful subscription is also
// accepted in case the peer set happened to be up by the time the broadcast
// was issued; per-CID fan-out for wholesale broadcast failure is a
// regression and is reported as such.
//
// MUST run before any other stream test: subsequent tests use
// `subscribeWithRetry`, which absorbs the cold-start -32812 transparently.
// We want the raw cold-start path observable.
//
// Subscribes via `sendRpcAndWait` DIRECTLY (no `subscribeWithRetry`) so the
// top-level error is observable rather than silently retried away.
async function runStreamColdStartRejectsWholesale({ rpc, chain, check, payloads }) {
  const cids = [payloads[0].cid];
  let subscription;
  try {
    subscription = await rpc.sendRpcAndWait(chain, "bitswap_unstable_stream", [cids], 30_000);
  } catch (err) {
    const code = errorCode(err);
    if (code === ERR_FAIL_BACKOFF) {
      check("st-cold-open", true, `top-level FailRetryBackoff on cold start as expected`);
    } else {
      check(
        "st-cold-open",
        false,
        `expected top-level ${ERR_FAIL_BACKOFF}, got ${code} (${err.message})`,
      );
    }
    return;
  }
  // Subscription opened — peers must have been ready. Drain to streamDone and
  // accept the streamItem outcome. A streamItemError(-32812 / -32811) here
  // would be the regressed per-CID fan-out path, which is now a bug.
  const deadline = Date.now() + 60_000;
  const collected = [];
  let sawStreamDone = false;
  while (!sawStreamDone) {
    const got = await rpc.readJsonRpcUntil(
      chain,
      (msg) => streamEventResult(msg, subscription),
      deadline,
    );
    if (got === undefined) {
      check("st-cold-open", false, `timed out before streamDone (collected ${collected.length})`);
      return;
    }
    switch (got.event) {
      case "streamItem":
        collected.push({ kind: "ok", cid: got.cid });
        break;
      case "streamItemError":
        collected.push({ kind: "err", cid: got.cid, code: got.code });
        break;
      case "streamDone":
        sawStreamDone = true;
        break;
      default:
        check("st-cold-open", false, `unknown event: ${JSON.stringify(got)}`);
        return;
    }
  }
  if (collected.length !== cids.length) {
    check(
      "st-cold-open",
      false,
      `streamDone after ${collected.length} per-CID events, expected ${cids.length}`,
    );
    return;
  }
  const entry = collected[0];
  if (entry.kind === "ok") {
    check("st-cold-open", true, "got streamItem immediately (peer set was already up)");
  } else {
    check(
      "st-cold-open",
      false,
      `unexpected per-CID error on opened subscription (wholesale failure should now be top-level): code=${entry.code}`,
    );
  }
}

async function runStreamHappy({ rpc, chain, check, payloads }) {
  const cids = payloads.map((p) => p.cid);
  try {
    const events = await streamCollectWithRetry(rpc, chain, cids);
    const checkErr = await verifyStreamMap(events, payloads);
    check("st-happy", checkErr === null, checkErr ?? `${cids.length} events`);
  } catch (err) {
    check("st-happy", false, err.message);
  }
}

async function runStreamDedup({ rpc, chain, check, payloads }) {
  const cids = [payloads[0].cid, payloads[0].cid];
  try {
    await rpc.sendRpcAndWait(chain, "bitswap_unstable_stream", [cids]);
    check("st-dedup", false, "expected DuplicateCids rejection at subscription, got success");
  } catch (err) {
    const code = errorCode(err);
    const ok = code === ERR_DUPLICATE_CIDS;
    check("st-dedup", ok, ok ? `code ${code}` : `expected ${ERR_DUPLICATE_CIDS}, got ${code}`);
  }
}

async function runStreamTooMany({ rpc, chain, check, payloads, maxCids }) {
  const cids = Array(maxCids + 1).fill(payloads[0].cid);
  try {
    await rpc.sendRpcAndWait(chain, "bitswap_unstable_stream", [cids]);
    check("st-too-many", false, "expected TooManyCids rejection at subscription, got success");
  } catch (err) {
    const code = errorCode(err);
    const ok = code === ERR_TOO_MANY_CIDS;
    check("st-too-many", ok, ok ? `code ${code}` : `expected ${ERR_TOO_MANY_CIDS}, got ${code}`);
  }
}

async function runStreamEmpty({ rpc, chain, check }) {
  try {
    await rpc.sendRpcAndWait(chain, "bitswap_unstable_stream", [[]]);
    check("st-empty", false, "expected EmptyCids rejection, got success");
  } catch (err) {
    const code = errorCode(err);
    const ok = code === ERR_EMPTY_CIDS;
    check("st-empty", ok, ok ? `code ${code}` : `expected ${ERR_EMPTY_CIDS}, got ${code}`);
  }
}

async function runStreamPerCidErrors({ rpc, chain, check, payloads, missingCid }) {
  const valid = payloads[0];
  const cids = [valid.cid, "not-a-cid", missingCid];
  try {
    const events = await streamCollect(rpc, chain, cids);
    const okEntry = events.get(valid.cid);
    const invalidEntry = events.get("not-a-cid");
    const missingEntry = events.get(missingCid);
    if (!okEntry || !isHexString(okEntry.value)) {
      check("st-per-cid-errors", false, `valid slot expected streamItem hex, got ${JSON.stringify(okEntry)}`);
      return;
    }
    const okBytes = await verifyHexAgainstPayload(okEntry.value, valid);
    if (okBytes !== null) {
      check("st-per-cid-errors", false, `valid slot bytes mismatch: ${okBytes}`);
      return;
    }
    if (!isErrEntry(invalidEntry) || invalidEntry.code !== ERR_INVALID_PARAMS) {
      check("st-per-cid-errors", false, `invalid-cid expected ${ERR_INVALID_PARAMS}, got ${JSON.stringify(invalidEntry)}`);
      return;
    }
    if (!isErrEntry(missingEntry) || missingEntry.code !== ERR_FAIL) {
      check("st-per-cid-errors", false, `missing-cid expected ${ERR_FAIL}, got ${JSON.stringify(missingEntry)}`);
      return;
    }
    check("st-per-cid-errors", true, `Ok, ${invalidEntry.code}, ${missingEntry.code}`);
  } catch (err) {
    check("st-per-cid-errors", false, err.message);
  }
}

async function runStreamMixed({ rpc, chain, check, payloads }) {
  const fullOnly = payloads.filter((p) => !p.on_partial);
  if (fullOnly.length === 0) {
    check("st-mixed", true, "skipped (no full-only payloads)");
    return;
  }
  const cids = fullOnly.map((p) => p.cid);
  try {
    const events = await streamCollectWithRetry(rpc, chain, cids);
    const checkErr = await verifyStreamMap(events, fullOnly);
    check("st-mixed", checkErr === null, checkErr ?? `${cids.length} events`);
  } catch (err) {
    check("st-mixed", false, err.message);
  }
}

// Asserts that calling `bitswap_unstable_unstream` mid-stream prevents the
// `streamDone` event from being emitted (per spec: cancellation is silent).
async function runStreamUnstreamSuppressesStreamDone({ rpc, chain, check, payloads }) {
  const cids = payloads.map((p) => p.cid);
  try {
    const subscription = await subscribeWithRetry(rpc, chain, cids, 60_000);

    // Wait for at least one event so we know the subscription is live.
    const firstEventDeadline = Date.now() + 60_000;
    const firstEvent = await rpc.readJsonRpcUntil(
      chain,
      (msg) => streamEventResult(msg, subscription),
      firstEventDeadline,
    );
    if (firstEvent === undefined) {
      check("st-unstream-silence", false, "timed out waiting for first event");
      return;
    }
    if (firstEvent.event === "streamDone") {
      // Single-CID streams may complete before unstream fires; the assertion is moot.
      check("st-unstream-silence", true, "stream completed before unstream had a chance");
      return;
    }

    // Cancel.
    try {
      await rpc.sendRpcAndWait(chain, "bitswap_unstable_unstream", [subscription], 5_000);
    } catch (err) {
      check("st-unstream-silence", false, `unstream failed: ${err.message}`);
      return;
    }

    // Poll for a small window and assert no streamDone arrives.
    const silentUntil = Date.now() + 1_000;
    const ghost = await rpc.readJsonRpcUntil(
      chain,
      (msg) => {
        const res = streamEventResult(msg, subscription);
        return res && res.event === "streamDone" ? res : undefined;
      },
      silentUntil,
    );
    if (ghost === undefined) {
      check("st-unstream-silence", true, "no streamDone after unstream");
    } else {
      check("st-unstream-silence", false, `unexpected streamDone after unstream: ${JSON.stringify(ghost)}`);
    }
  } catch (err) {
    check("st-unstream-silence", false, err.message);
  }
}

// ---------- subscription helpers ----------

// Wraps `streamCollect`. The cold-start "no peers yet" case is handled at
// subscription time by `subscribeWithRetry` (top-level `-32812`). This
// wrapper additionally handles the rarer mid-stream case where every
// per-CID outcome came back as a transient/retryable error
// (`-32811 FailRetry` / `-32812 FailRetryBackoff`) — in that case, back off
// and re-subscribe.
async function streamCollectWithRetry(rpc, chain, cids, totalBudgetMs = 180_000) {
  const deadline = Date.now() + totalBudgetMs;
  let attempt = 0;
  while (true) {
    attempt += 1;
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error(`bitswap_unstable_stream timed out after ${totalBudgetMs}ms`);
    }
    const events = await streamCollect(rpc, chain, cids, remaining);
    const allRetryable = [...events.values()].every(
      (e) => isErrEntry(e) && (e.code === ERR_FAIL_BACKOFF || e.code === ERR_FAIL_RETRY),
    );
    if (!allRetryable) return events;
    const backoff = Math.min(5_000, 500 * 2 ** Math.min(attempt - 1, 3));
    await new Promise((r) => setTimeout(r, backoff));
  }
}

// Subscribes via bitswap_unstable_stream, collects events until `streamDone`,
// then asserts that exactly `cids.length` per-CID events arrived before the
// done marker. Returns a Map<cid, { value?, code?, message? }>. Arrival order
// is not asserted (per spec).
async function streamCollect(rpc, chain, cids, totalBudgetMs = 180_000) {
  const subscription = await subscribeWithRetry(rpc, chain, cids, totalBudgetMs);
  const collected = new Map();
  const deadline = Date.now() + totalBudgetMs;
  let sawStreamDone = false;
  while (!sawStreamDone) {
    const got = await rpc.readJsonRpcUntil(
      chain,
      (msg) => streamEventResult(msg, subscription),
      deadline,
    );
    if (got === undefined) {
      throw new Error(`stream timed out: collected ${collected.size}/${cids.length} events`);
    }
    switch (got.event) {
      case "streamItem":
        collected.set(got.cid, { value: got.value });
        break;
      case "streamItemError":
        collected.set(got.cid, { code: got.code, message: got.message });
        break;
      case "streamDone":
        sawStreamDone = true;
        break;
      default:
        throw new Error(`unknown stream event: ${JSON.stringify(got)}`);
    }
  }
  if (collected.size !== cids.length) {
    throw new Error(`streamDone arrived after ${collected.size}/${cids.length} per-CID events`);
  }
  return collected;
}

function streamEventResult(msg, subscription) {
  if (
    msg.method === "bitswap_unstable_streamEvent" &&
    msg.params &&
    msg.params.subscription === subscription
  ) {
    return msg.params.result;
  }
  return undefined;
}

async function subscribeWithRetry(rpc, chain, cids, totalBudgetMs) {
  const deadline = Date.now() + totalBudgetMs;
  let attempt = 0;
  while (true) {
    attempt += 1;
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error(`bitswap_unstable_stream timed out after ${totalBudgetMs}ms`);
    }
    try {
      return await rpc.sendRpcAndWait(
        chain,
        "bitswap_unstable_stream",
        [cids],
        Math.min(60_000, remaining),
      );
    } catch (err) {
      const code = errorCode(err);
      if (code === ERR_FAIL_BACKOFF || code === ERR_FAIL_RETRY) {
        const backoff = Math.min(5_000, 500 * 2 ** Math.min(attempt - 1, 3));
        await new Promise((r) => setTimeout(r, backoff));
        continue;
      }
      throw err;
    }
  }
}

// ---------- verification helpers ----------

// Asserts the collected stream map contains every expected payload by CID,
// with bytes matching size and sha256. Order-agnostic.
async function verifyStreamMap(events, expectedPayloads) {
  if (events.size !== expectedPayloads.length) {
    return `expected ${expectedPayloads.length} events, got ${events.size}`;
  }
  for (const p of expectedPayloads) {
    const entry = events.get(p.cid);
    if (entry === undefined) {
      return `missing event for cid ${p.cid} (${p.label})`;
    }
    if (!entry.value || !isHexString(entry.value)) {
      return `${p.label}: expected streamItem hex, got ${JSON.stringify(entry)}`;
    }
    const mismatch = await verifyHexAgainstPayload(entry.value, p);
    if (mismatch !== null) {
      return `${p.label}: ${mismatch}`;
    }
  }
  return null;
}

async function verifyHexAgainstPayload(hex, payload) {
  const bytes = hexToBytes(hex);
  if (bytes.length !== payload.size) {
    return `size ${bytes.length} != ${payload.size}`;
  }
  const sha = await sha256Hex(bytes);
  if (sha !== payload.sha256) {
    return `sha256 mismatch (got ${sha.slice(0, 12)}…, expected ${payload.sha256.slice(0, 12)}…)`;
  }
  return null;
}

function isErrEntry(v) {
  return typeof v === "object" && v !== null && typeof v.code === "number";
}
