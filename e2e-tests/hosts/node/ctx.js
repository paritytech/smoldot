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

// Node host: builds the `ctx` a shared test body runs against. Uses the smoldot
// Node build over TCP. The host-specific seams are: client start (no
// `forbidTcp`), `report`/`log` sinks, `waitSync` (polls the SyncFile on disk)
// and `dumpDb` (writes files). JSON-RPC is not host-specific — bodies import it
// from `shared/rpc.js` and build it with `createRpc(ctx.client)`.

import * as fs from "node:fs";
import { start } from "smoldot";

// PASS/FAIL accounting for the Node host. Sets `process.exitCode` on failure so
// the generic runner can exit non-zero.
function report(name, passed, detail) {
  const suffix = detail ? `: ${detail}` : "";
  const ts = new Date().toISOString();
  if (passed) {
    console.log(`[${ts}] PASS: ${name}${suffix}`);
  } else {
    console.log(`[${ts}] FAIL: ${name}${suffix}`);
    process.exitCode = 1;
  }
}

// Polls the Rust → JS sync file until a line equals `expected`. Pair with
// `SyncFile` on the Rust side.
async function waitForMessage(path, expected, timeoutMs = 120_000, pollMs = 100) {
  const fsp = await import("node:fs/promises");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const contents = await fsp.readFile(path, "utf8").catch(() => "");
    if (contents.split("\n").some((line) => line.trim() === expected)) return;
    await new Promise((r) => setTimeout(r, pollMs));
  }
  throw new Error(`Timed out waiting for sync message "${expected}" at ${path}`);
}

// export async function makeNodeCtx({ fileInputs = [] } = {}) {
export async function makeNodeCtx({ env, files }) {
  const maxLogLevel = Number.parseInt(env.SMOLDOT_LOG_LEVEL || "3", 10);
  const client = start({
    maxLogLevel,
    logCallback: (level, target, message) => {
      const labels = { 1: "ERROR", 2: "WARN", 3: "INFO", 4: "DEBUG", 5: "TRACE" };
      const label = labels[level] ?? `L${level}`;
      console.error(`[${new Date().toISOString()}] [${label}] [${target}] ${message}`);
    },
  });

  return {
    host: "node",
    client,
    env,
    files,
    report,
    log: (m) => console.error(m),
    waitSync: (label, timeoutMs = 120_000) => {
      const p = env.SYNC_PATH;
      if (!p) throw new Error("waitSync called but SYNC_PATH is not set");
      return waitForMessage(p, label, timeoutMs);
    },
    dumpDb: (filesObj) => {
      const dir = env.SMOLDOT_DB_DUMP_DIR;
      if (!dir) return;
      fs.mkdirSync(dir, { recursive: true });
      for (const [name, content] of Object.entries(filesObj)) {
        fs.writeFileSync(`${dir}/${name}`, content);
      }
    },
    cleanup: async () => {
      await client.terminate().catch(() => {});
    },
  };
}
