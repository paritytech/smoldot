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

import { webcrypto } from "node:crypto";
import {
  addChainFromSpec,
  createSmoldotClient,
  readJsonRpcUntil,
  report,
  sendRpcAndWait,
} from "./helpers.js";

const ERR_INVALID_PARAMS = -32602;
const ERR_FAIL = -32810;
const ERR_FAIL_RETRY = -32811;
const ERR_FAIL_BACKOFF = -32812;

const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const bulletinSpecPath = process.env.BULLETIN_CHAIN_SPEC;
const missingCid = process.env.MISSING_CID;
const payloadsJson = process.env.PAYLOADS_JSON;
const maxCidsStr = process.env.MAX_CIDS;
if (!relaySpecPath || !bulletinSpecPath || !missingCid || !payloadsJson || !maxCidsStr) {
  console.error(
    "Required env vars: RELAY_CHAIN_SPEC, BULLETIN_CHAIN_SPEC, MISSING_CID, PAYLOADS_JSON, MAX_CIDS",
  );
  process.exit(1);
}
const payloads = JSON.parse(payloadsJson);
const maxCids = Number.parseInt(maxCidsStr, 10);

const client = createSmoldotClient();
let exitCode = 0;
try {
  const relay = await addChainFromSpec(client, relaySpecPath);
  const bulletin = await addChainFromSpec(client, bulletinSpecPath, {
    potentialRelayChains: [relay],
  });

  // ===== getMany section =====
  await runGetManyHappy(bulletin);
  await runGetManyDedup(bulletin);
  await runGetManyTooMany(bulletin);
  await runGetManyPerCidErrors(bulletin);
  await runGetManyMixed(bulletin);

  // ===== stream section =====
  await runStreamHappy(bulletin);
  await runStreamDedup(bulletin);
  await runStreamTooMany(bulletin);
  await runStreamPerCidErrors(bulletin);
  await runStreamMixed(bulletin);
} catch (err) {
  console.error(`bulletin_batch error: ${err?.stack || err}`);
  exitCode = 1;
} finally {
  try {
    await client.terminate();
  } catch (_) {}
}

if (exitCode || process.exitCode) {
  process.exit(exitCode || 1);
}

// ---------- getMany tests ----------

async function runGetManyHappy(chain) {
  const cids = payloads.map((p) => p.cid);
  try {
    const result = await getManyWithRetry(chain, cids);
    const checkErr = await verifyGetManyResult(result, payloads);
    report("gm-happy", checkErr === null, checkErr ?? `${cids.length} entries`);
  } catch (err) {
    report("gm-happy", false, err.message);
  }
}

async function runGetManyDedup(chain) {
  const cids = [payloads[0].cid, payloads[0].cid];
  try {
    await sendRpcAndWait(chain, "bitswap_v1_getMany", [cids]);
    report("gm-dedup", false, "expected DuplicateCids rejection, got success");
  } catch (err) {
    const code = errorCode(err);
    const variant = errorVariant(err);
    const ok = code === ERR_INVALID_PARAMS && variant === "DuplicateCids";
    report(
      "gm-dedup",
      ok,
      ok ? `code ${code} variant ${variant}` : `expected ${ERR_INVALID_PARAMS}/DuplicateCids, got ${code}/${variant}`,
    );
  }
}

async function runGetManyTooMany(chain) {
  // parse_and_dedup() checks length BEFORE deduping, so identical CIDs work as
  // long as the array length exceeds MAX_CIDS_PER_REQUEST.
  const cids = Array(maxCids + 1).fill(payloads[0].cid);
  try {
    await sendRpcAndWait(chain, "bitswap_v1_getMany", [cids]);
    report("gm-too-many", false, "expected TooManyCids rejection, got success");
  } catch (err) {
    const code = errorCode(err);
    const variant = errorVariant(err);
    const ok = code === ERR_INVALID_PARAMS && variant === "TooManyCids";
    report(
      "gm-too-many",
      ok,
      ok ? `code ${code} variant ${variant}` : `expected ${ERR_INVALID_PARAMS}/TooManyCids, got ${code}/${variant}`,
    );
  }
}

async function runGetManyPerCidErrors(chain) {
  const valid = payloads[0];
  const cids = [valid.cid, "not-a-cid", missingCid];
  try {
    const result = await getManyWithRetry(chain, cids);
    if (!Array.isArray(result) || result.length !== 3) {
      report("gm-per-cid-errors", false, `expected 3-entry array, got ${JSON.stringify(result)}`);
      return;
    }
    const [tup0, tup1, tup2] = result;
    if (tup0[0] !== valid.cid || !isHexString(tup0[1])) {
      report("gm-per-cid-errors", false, `slot 0 expected Ok hex, got ${JSON.stringify(tup0)}`);
      return;
    }
    const okBytes = await verifyHexAgainstPayload(tup0[1], valid);
    if (okBytes !== null) {
      report("gm-per-cid-errors", false, `slot 0 bytes mismatch: ${okBytes}`);
      return;
    }
    if (tup1[0] !== "not-a-cid" || !isErrObject(tup1[1]) || tup1[1].code !== ERR_INVALID_PARAMS) {
      report("gm-per-cid-errors", false, `slot 1 expected ${ERR_INVALID_PARAMS}, got ${JSON.stringify(tup1)}`);
      return;
    }
    if (tup2[0] !== missingCid || !isErrObject(tup2[1]) || tup2[1].code !== ERR_FAIL) {
      report("gm-per-cid-errors", false, `slot 2 expected ${ERR_FAIL}, got ${JSON.stringify(tup2)}`);
      return;
    }
    report("gm-per-cid-errors", true, `Ok, ${tup1[1].code}, ${tup2[1].code}`);
  } catch (err) {
    report("gm-per-cid-errors", false, err.message);
  }
}

async function runGetManyMixed(chain) {
  const fullOnly = payloads.filter((p) => !p.on_partial);
  if (fullOnly.length === 0) {
    report("gm-mixed", true, "skipped (no full-only payloads)");
    return;
  }
  const cids = fullOnly.map((p) => p.cid);
  try {
    const result = await getManyWithRetry(chain, cids);
    const checkErr = await verifyGetManyResult(result, fullOnly);
    report("gm-mixed", checkErr === null, checkErr ?? `${cids.length} entries`);
  } catch (err) {
    report("gm-mixed", false, err.message);
  }
}

// ---------- stream tests ----------

async function runStreamHappy(chain) {
  const cids = payloads.map((p) => p.cid);
  try {
    const events = await streamCollect(chain, cids);
    const checkErr = await verifyStreamMap(events, payloads);
    report("st-happy", checkErr === null, checkErr ?? `${cids.length} events`);
  } catch (err) {
    report("st-happy", false, err.message);
  }
}

async function runStreamDedup(chain) {
  const cids = [payloads[0].cid, payloads[0].cid];
  try {
    await sendRpcAndWait(chain, "bitswap_v1_stream", [cids]);
    report("st-dedup", false, "expected DuplicateCids rejection at subscription, got success");
  } catch (err) {
    const code = errorCode(err);
    const variant = errorVariant(err);
    const ok = code === ERR_INVALID_PARAMS && variant === "DuplicateCids";
    report(
      "st-dedup",
      ok,
      ok ? `code ${code} variant ${variant}` : `expected ${ERR_INVALID_PARAMS}/DuplicateCids, got ${code}/${variant}`,
    );
  }
}

async function runStreamTooMany(chain) {
  const cids = Array(maxCids + 1).fill(payloads[0].cid);
  try {
    await sendRpcAndWait(chain, "bitswap_v1_stream", [cids]);
    report("st-too-many", false, "expected TooManyCids rejection at subscription, got success");
  } catch (err) {
    const code = errorCode(err);
    const variant = errorVariant(err);
    const ok = code === ERR_INVALID_PARAMS && variant === "TooManyCids";
    report(
      "st-too-many",
      ok,
      ok ? `code ${code} variant ${variant}` : `expected ${ERR_INVALID_PARAMS}/TooManyCids, got ${code}/${variant}`,
    );
  }
}

async function runStreamPerCidErrors(chain) {
  const valid = payloads[0];
  const cids = [valid.cid, "not-a-cid", missingCid];
  try {
    const events = await streamCollect(chain, cids);
    const okEntry = events.get(valid.cid);
    const invalidEntry = events.get("not-a-cid");
    const missingEntry = events.get(missingCid);
    if (!okEntry || !isHexString(okEntry)) {
      report("st-per-cid-errors", false, `valid slot expected Ok hex, got ${JSON.stringify(okEntry)}`);
      return;
    }
    const okBytes = await verifyHexAgainstPayload(okEntry, valid);
    if (okBytes !== null) {
      report("st-per-cid-errors", false, `valid slot bytes mismatch: ${okBytes}`);
      return;
    }
    if (!isErrObject(invalidEntry) || invalidEntry.code !== ERR_INVALID_PARAMS) {
      report("st-per-cid-errors", false, `invalid-cid expected ${ERR_INVALID_PARAMS}, got ${JSON.stringify(invalidEntry)}`);
      return;
    }
    if (!isErrObject(missingEntry) || missingEntry.code !== ERR_FAIL) {
      report("st-per-cid-errors", false, `missing-cid expected ${ERR_FAIL}, got ${JSON.stringify(missingEntry)}`);
      return;
    }
    report("st-per-cid-errors", true, `Ok, ${invalidEntry.code}, ${missingEntry.code}`);
  } catch (err) {
    report("st-per-cid-errors", false, err.message);
  }
}

async function runStreamMixed(chain) {
  const fullOnly = payloads.filter((p) => !p.on_partial);
  if (fullOnly.length === 0) {
    report("st-mixed", true, "skipped (no full-only payloads)");
    return;
  }
  const cids = fullOnly.map((p) => p.cid);
  try {
    const events = await streamCollect(chain, cids);
    const checkErr = await verifyStreamMap(events, fullOnly);
    report("st-mixed", checkErr === null, checkErr ?? `${cids.length} events`);
  } catch (err) {
    report("st-mixed", false, err.message);
  }
}

// ---------- subscription helper ----------

/// Subscribes via bitswap_v1_stream, collects exactly `cids.length` events,
/// then politely unsubscribes. Returns a Map<cid, blockResult>. The order in
/// which events arrive is not asserted (per spec, arrival order, not input
/// order).
async function streamCollect(chain, cids, totalBudgetMs = 180_000) {
  const subscription = await subscribeWithRetry(chain, cids, totalBudgetMs);
  const collected = new Map();
  const deadline = Date.now() + totalBudgetMs;
  while (collected.size < cids.length) {
    const got = await readJsonRpcUntil(
      chain,
      (msg) => {
        if (
          msg.method === "bitswap_v1_streamEvent" &&
          msg.params &&
          msg.params.subscription === subscription
        ) {
          return msg.params.result;
        }
        return undefined;
      },
      deadline,
    );
    if (got === undefined) {
      throw new Error(
        `stream timed out: collected ${collected.size}/${cids.length} events`,
      );
    }
    const [cid, blockResult] = got;
    collected.set(cid, blockResult);
  }
  // Polite cancel; we don't assert on the response.
  try {
    await sendRpcAndWait(chain, "bitswap_v1_unstream", [subscription], 10_000);
  } catch (_) {}
  return collected;
}

async function subscribeWithRetry(chain, cids, totalBudgetMs) {
  const deadline = Date.now() + totalBudgetMs;
  let attempt = 0;
  while (true) {
    attempt += 1;
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error(`bitswap_v1_stream timed out after ${totalBudgetMs}ms`);
    }
    try {
      return await sendRpcAndWait(chain, "bitswap_v1_stream", [cids], Math.min(60_000, remaining));
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

// ---------- getMany helper ----------

/// Same retry strategy as bulletin_fetch.js's `bitswapGetWithRetry`: retry on
/// transient FailRetry / FailRetryBackoff while smoldot's peer set warms up.
async function getManyWithRetry(chain, cids, totalBudgetMs = 180_000) {
  const deadline = Date.now() + totalBudgetMs;
  let attempt = 0;
  while (true) {
    attempt += 1;
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error(`bitswap_v1_getMany timed out after ${totalBudgetMs}ms`);
    }
    try {
      return await sendRpcAndWait(chain, "bitswap_v1_getMany", [cids], Math.min(60_000, remaining));
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

/// Asserts a `bitswap_v1_getMany` response is an array of `[cid, hex]` tuples
/// in input order, and each tuple's hex content matches the corresponding
/// payload. Returns null on success, or a string explaining the first
/// mismatch.
async function verifyGetManyResult(result, expectedPayloads) {
  if (!Array.isArray(result) || result.length !== expectedPayloads.length) {
    return `expected ${expectedPayloads.length}-entry array, got ${JSON.stringify(result)}`;
  }
  for (let i = 0; i < expectedPayloads.length; i++) {
    const tup = result[i];
    const p = expectedPayloads[i];
    if (!Array.isArray(tup) || tup.length !== 2 || tup[0] !== p.cid) {
      return `slot ${i}: expected cid ${p.cid}, got ${JSON.stringify(tup)}`;
    }
    if (!isHexString(tup[1])) {
      return `slot ${i}: expected Ok hex, got ${JSON.stringify(tup[1])}`;
    }
    const mismatch = await verifyHexAgainstPayload(tup[1], p);
    if (mismatch !== null) {
      return `slot ${i} (${p.label}): ${mismatch}`;
    }
  }
  return null;
}

/// Asserts the collected `bitswap_v1_streamEvent` map contains every expected
/// payload by CID, with bytes matching size and sha256. Order-agnostic.
async function verifyStreamMap(events, expectedPayloads) {
  if (events.size !== expectedPayloads.length) {
    return `expected ${expectedPayloads.length} events, got ${events.size}`;
  }
  for (const p of expectedPayloads) {
    const blockResult = events.get(p.cid);
    if (blockResult === undefined) {
      return `missing event for cid ${p.cid} (${p.label})`;
    }
    if (!isHexString(blockResult)) {
      return `${p.label}: expected Ok hex, got ${JSON.stringify(blockResult)}`;
    }
    const mismatch = await verifyHexAgainstPayload(blockResult, p);
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

function isHexString(v) {
  return typeof v === "string" && v.startsWith("0x");
}

function isErrObject(v) {
  return typeof v === "object" && v !== null && typeof v.code === "number";
}

function errorCode(err) {
  const m = /"code":(-?\d+)/.exec(err.message ?? "");
  return m ? Number.parseInt(m[1], 10) : null;
}

function errorVariant(err) {
  const m = /"variant":"([^"]+)"/.exec(err.message ?? "");
  return m ? m[1] : null;
}

function hexToBytes(hex) {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (stripped.length % 2 !== 0) {
    throw new Error(`odd-length hex: ${stripped.length}`);
  }
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function sha256Hex(bytes) {
  const digest = await webcrypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
