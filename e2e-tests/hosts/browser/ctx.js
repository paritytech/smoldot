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

// Browser host: builds the `ctx` a shared test body runs against, INSIDE the
// page. Mirrors hosts/node/ctx.js but uses the smoldot browser build (already on
// `window.__smoldot` via page/index.html) with `forbidTcp: true` (→ WebRTC) and
// bridges `waitSync` back to Node through the `window.__waitSync` exposed
// function. JSON-RPC is not host-specific — bodies import it from
// `shared/rpc.js` and build it with `createRpc(ctx.client)`.
//
// Served at /browser/ctx.js and imported inside a single page.evaluate by
// hosts/browser/run.js.


function report(name, passed, detail) {
  const suffix = detail ? `: ${detail}` : "";
  if (passed) {
    console.log(`PASS: ${name}${suffix}`);
  } else {
    console.log(`FAIL: ${name}${suffix}`);
    window.__failed = true;
  }
}

export async function makeBrowserCtx({ env, files }) {
  const maxLogLevel = Number.parseInt(env.SMOLDOT_LOG_LEVEL || "3", 10);
  const client = window.__smoldot.start({
    maxLogLevel,
    forbidTcp: true,
    forbidWs: true,
    forbidWss: true,
    logCallback: (level, target, message) => {
      const labels = { 1: "ERROR", 2: "WARN", 3: "INFO", 4: "DEBUG", 5: "TRACE" };
      const label = labels[level] ?? `L${level}`;
      console.log(`[smoldot [${label}]][${target}] ${message}`);
    },
  });

  return {
    host: "browser",
    client,
    env,
    files,
    report,
    log: (m) => console.log(m),
    waitSync: (label, timeoutMs = 120_000) => {
      if (typeof window.__waitSync !== "function") {
        throw new Error("waitSync called but SYNC_PATH was not set on the Rust side");
      }
      return window.__waitSync(label, timeoutMs);
    },
    cleanup: async () => {
      await client.terminate().catch(() => {});
    },
    // Browsers can't write to disk; DB-dump is a Node-host-only capability.
    //
    // Writing to disk is only used by the generate-snapshot capability
    // which is used to create files which later will be used by both node and browser tests.
    dumpDb: async () => {},
  };
}
