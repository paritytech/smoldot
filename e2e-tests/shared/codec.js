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

// Host-agnostic byte/hash/header helpers shared by the test bodies. Like
// `shared/rpc.js`, this is a relative sibling import that resolves on both
// hosts (Node loads it from disk, the browser host serves it via Playwright
// request interception). No Node-only APIs: hashing goes through
// `globalThis.crypto.subtle`, which exists in Node ≥ 18 and in browsers.

// Hex → bytes without Node's Buffer.
export function hexToBytes(hex) {
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

export function isHexString(v) {
  return typeof v === "string" && v.startsWith("0x");
}

export async function sha256Hex(bytes) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Decodes a hex SCALE-encoded substrate header and returns its parent hash
// and block number. Header layout: parent_hash (32 B) | compact-encoded
// number | state_root (32 B) | extrinsics_root (32 B) | digest. Compact
// modes 0/1/2 cover block numbers up to 2^30, the only range asserted here.
export function decodeHeader(hexStr) {
  const bytes = hexToBytes(hexStr);
  if (bytes.length < 33) throw new Error(`header hex too short: ${bytes.length} bytes`);
  const parentHash =
    "0x" + [...bytes.subarray(0, 32)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const off = 32;
  const b0 = bytes[off];
  const mode = b0 & 0b11;
  let number;
  if (mode === 0) number = b0 >>> 2;
  else if (mode === 1) number = (b0 | (bytes[off + 1] << 8)) >>> 2;
  else if (mode === 2) {
    number =
      (b0 | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24)) >>> 2;
  } else {
    throw new Error("compact mode 3 not supported");
  }
  return { number, parentHash };
}

// Extracts the numeric JSON-RPC error code from an error thrown by
// `sendRpcAndWait` (whose message embeds the raw error object).
export function errorCode(err) {
  const m = /"code":(-?\d+)/.exec(err.message ?? "");
  return m ? Number.parseInt(m[1], 10) : null;
}
