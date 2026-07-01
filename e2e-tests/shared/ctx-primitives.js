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

// The single source of truth for the `ctx` primitives that every shared test
// body runs against. These are the genuinely host-specific seam — host factories
// (hosts/node/ctx.js, hosts/browser/ctx.js) must return an object carrying these
// keys, and both runners call `assertCtx` after building the ctx (and after any
// `prepareCtx` extension) so drift — a renamed key, a missing host capability, a
// typo'd extension — fails loudly at startup instead of as a mid-test
// "x is not a function".
//
// JSON-RPC is deliberately NOT here: it is host-agnostic and lives in
// `shared/rpc.js`, which bodies import directly and build with
// `createRpc(ctx.client)`.

export const CTX_KEYS = [
  // Which host built this ctx, so a host-agnostic `prepareCtx` can branch on the
  // rare occasion it must.
  "host",
  // The started smoldot client (Node build / browser build w/ forbidTcp).
  "client",
  // Pre-resolved inputs (the sandbox can't read env/disk itself).
  "env",
  "files",
  // Host-specific output sinks and capabilities.
  "report",
  "log",
  "waitSync",
  "dumpDb",
  "cleanup",
];

// Throws if `ctx` is missing any required key. Extra keys (a test's own helpers
// added via `prepareCtx`) are allowed — only the required surface is checked.
export function assertCtx(ctx) {
  if (!ctx || typeof ctx !== "object") {
    throw new Error("ctx is not an object");
  }
  const missing = CTX_KEYS.filter((k) => !(k in ctx));
  if (missing.length) {
    throw new Error(`ctx is missing required keys: ${missing.join(", ")}`);
  }
}
