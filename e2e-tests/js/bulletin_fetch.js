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
if (!relaySpecPath || !bulletinSpecPath || !missingCid || !payloadsJson) {
  console.error(
    "Required env vars: RELAY_CHAIN_SPEC, BULLETIN_CHAIN_SPEC, MISSING_CID, PAYLOADS_JSON",
  );
  process.exit(1);
}
const payloads = JSON.parse(payloadsJson);

const client = createSmoldotClient();
let exitCode = 0;
try {
  const relay = await addChainFromSpec(client, relaySpecPath);
  const bulletin = await addChainFromSpec(client, bulletinSpecPath, {
    potentialRelayChains: [relay],
  });

  for (const payload of payloads) {
    try {
      // Given
      const cid = payload.cid;

      // When
      const hex = await bitswapGetWithRetry(bulletin, cid);

      // Then
      const bytes = hexToBytes(hex);
      const sha = await sha256Hex(bytes);
      const ok = bytes.length === payload.size && sha === payload.sha256;
      report(
        `known-${payload.label}`,
        ok,
        ok ? `${bytes.length} bytes` : `size/sha256 mismatch`,
      );
    } catch (err) {
      report(`known-${payload.label}`, false, err.message);
    }
  }

  try {
    // Given
    const cid = missingCid;

    // When
    const hex = await bitswapGetWithRetry(bulletin, cid);

    // Then
    report(
      "missing-not-found",
      false,
      `expected error ${ERR_FAIL}, got success (${hex.length / 2} bytes)`,
    );
  } catch (err) {
    const code = errorCode(err);
    report(
      "missing-not-found",
      code === ERR_FAIL,
      code === ERR_FAIL ? `code ${code}` : `expected ${ERR_FAIL}, got ${code}`,
    );
  }

  try {
    // Given
    const cid = "not-a-cid";

    // When
    await bitswapGetWithRetry(bulletin, cid);

    // Then
    report(
      "missing-invalid-cid",
      false,
      `expected error ${ERR_INVALID_PARAMS}, got success`,
    );
  } catch (err) {
    const code = errorCode(err);
    report(
      "missing-invalid-cid",
      code === ERR_INVALID_PARAMS,
      code === ERR_INVALID_PARAMS
        ? `code ${code}`
        : `expected ${ERR_INVALID_PARAMS}, got ${code}`,
    );
  }

  for (const payload of payloads.filter((p) => !p.on_partial)) {
    try {
      // Given
      const cid = payload.cid;

      // When
      const hex = await bitswapGetWithRetry(bulletin, cid);

      // Then
      const bytes = hexToBytes(hex);
      const sha = await sha256Hex(bytes);
      const ok = bytes.length === payload.size && sha === payload.sha256;
      report(
        `mixed-${payload.label}`,
        ok,
        ok ? `${bytes.length} bytes` : `size/sha256 mismatch`,
      );
    } catch (err) {
      report(`mixed-${payload.label}`, false, err.message);
    }
  }
} catch (err) {
  console.error(`bulletin_fetch error: ${err?.stack || err}`);
  exitCode = 1;
} finally {
  try {
    await client.terminate();
  } catch (_) {}
}

if (exitCode || process.exitCode) {
  process.exit(exitCode || 1);
}

// Retries the transient BlockRequestFailed/Timeout and NoPeers/QueueFull
// errors smoldot returns while its peer set is warming up.
async function bitswapGetWithRetry(chain, cid, totalBudgetMs = 180_000) {
  const deadline = Date.now() + totalBudgetMs;
  let attempt = 0;
  while (true) {
    attempt += 1;
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error(`bitswap_v1_get timed out after ${totalBudgetMs}ms`);
    }
    try {
      return await sendRpcAndWait(chain, "bitswap_v1_get", [cid], Math.min(60_000, remaining));
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

function errorCode(err) {
  const m = /"code":(-?\d+)/.exec(err.message ?? "");
  return m ? Number.parseInt(m[1], 10) : null;
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
