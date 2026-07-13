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

// Bulletin `bitswap_unstable_get` test body — runs on either host via the ctx
// abstraction. Fetches known payloads by CID (checking size + sha256), the
// legacy `bitswap_v1_get` alias, and the error paths for missing/invalid CIDs.

import { createRpc } from "./rpc.js";
import { errorCode, hexToBytes, sha256Hex } from "./codec.js";

const ERR_INVALID_PARAMS = -32602;
const ERR_FAIL = -32810;
const ERR_FAIL_RETRY = -32811;
const ERR_FAIL_BACKOFF = -32812;

export const fileInputs = ["RELAY_CHAIN_SPEC", "BULLETIN_CHAIN_SPEC"];
export const envInputs = ["MISSING_CID", "PAYLOADS_JSON"];

export default async function bulletinFetch(ctx) {
  const { report, env, files } = ctx;
  const rpc = createRpc(ctx.client);

  const missingCid = env.MISSING_CID;
  const payloadsJson = env.PAYLOADS_JSON;
  if (!files.RELAY_CHAIN_SPEC || !files.BULLETIN_CHAIN_SPEC || !missingCid || !payloadsJson) {
    throw new Error(
      "Required env vars: RELAY_CHAIN_SPEC, BULLETIN_CHAIN_SPEC, MISSING_CID, PAYLOADS_JSON",
    );
  }
  const payloads = JSON.parse(payloadsJson);
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

  for (const payload of payloads) {
    try {
      // Given
      const cid = payload.cid;

      // When
      const hex = await bitswapGetWithRetry(rpc, bulletin, cid);

      // Then
      const bytes = hexToBytes(hex);
      const sha = await sha256Hex(bytes);
      const ok = bytes.length === payload.size && sha === payload.sha256;
      check(`known-${payload.label}`, ok, ok ? `${bytes.length} bytes` : `size/sha256 mismatch`);
    } catch (err) {
      check(`known-${payload.label}`, false, err.message);
    }
  }

  // Alias coverage: the legacy `bitswap_v1_get` name must still resolve via
  // the macro alias to the same handler.
  if (payloads.length > 0) {
    const payload = payloads[0];
    try {
      const hex = await bitswapGetWithRetry(rpc, bulletin, payload.cid, 180_000, "bitswap_v1_get");
      const bytes = hexToBytes(hex);
      const sha = await sha256Hex(bytes);
      const ok = bytes.length === payload.size && sha === payload.sha256;
      check(
        "alias-v1-get",
        ok,
        ok ? `${bytes.length} bytes via bitswap_v1_get alias` : `size/sha256 mismatch via alias`,
      );
    } catch (err) {
      check("alias-v1-get", false, err.message);
    }
  }

  try {
    // Given
    const cid = missingCid;

    // When
    const hex = await bitswapGetWithRetry(rpc, bulletin, cid);

    // Then
    check("missing-not-found", false, `expected error ${ERR_FAIL}, got success (${hex.length / 2} bytes)`);
  } catch (err) {
    const code = errorCode(err);
    check(
      "missing-not-found",
      code === ERR_FAIL,
      code === ERR_FAIL ? `code ${code}` : `expected ${ERR_FAIL}, got ${code}`,
    );
  }

  try {
    // Given
    const cid = "not-a-cid";

    // When
    await bitswapGetWithRetry(rpc, bulletin, cid);

    // Then
    check("missing-invalid-cid", false, `expected error ${ERR_INVALID_PARAMS}, got success`);
  } catch (err) {
    const code = errorCode(err);
    check(
      "missing-invalid-cid",
      code === ERR_INVALID_PARAMS,
      code === ERR_INVALID_PARAMS ? `code ${code}` : `expected ${ERR_INVALID_PARAMS}, got ${code}`,
    );
  }

  for (const payload of payloads.filter((p) => !p.on_partial)) {
    try {
      // Given
      const cid = payload.cid;

      // When
      const hex = await bitswapGetWithRetry(rpc, bulletin, cid);

      // Then
      const bytes = hexToBytes(hex);
      const sha = await sha256Hex(bytes);
      const ok = bytes.length === payload.size && sha === payload.sha256;
      check(`mixed-${payload.label}`, ok, ok ? `${bytes.length} bytes` : `size/sha256 mismatch`);
    } catch (err) {
      check(`mixed-${payload.label}`, false, err.message);
    }
  }

  if (failed) throw new Error("one or more bulletin_fetch checks failed");
}

// Retries the transient BlockRequestFailed/Timeout and NoPeers/QueueFull
// errors smoldot returns while its peer set is warming up. `method` lets us
// exercise both the canonical `bitswap_unstable_get` and the legacy
// `bitswap_v1_get` alias.
async function bitswapGetWithRetry(
  rpc,
  chain,
  cid,
  totalBudgetMs = 180_000,
  method = "bitswap_unstable_get",
) {
  const deadline = Date.now() + totalBudgetMs;
  let attempt = 0;
  while (true) {
    attempt += 1;
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error(`${method} timed out after ${totalBudgetMs}ms`);
    }
    try {
      return await rpc.sendRpcAndWait(chain, method, [cid], Math.min(60_000, remaining));
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
