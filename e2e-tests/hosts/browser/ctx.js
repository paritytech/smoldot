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
// `window.__smoldot` via page/index.html) with `forbidTcp: true` (→ WebRTC, and
// WebTransport for JAM chains) and bridges `waitSync` back to Node through the
// `window.__waitSync` exposed function. JSON-RPC is not host-specific — bodies
// import it from `shared/rpc.js` and build it with `createRpc(ctx.client)`.
//
// Browser-only extras on top of the ctx contract, used by the JAM bodies:
// `clientLogs` (every log line of `client`, newest last, bounded), `startClient`
// (a second client with its own `logs`, terminated by `cleanup`) and
// `sendSync(label)` (the body → Rust direction of the SyncFile, read by
// `SyncFile::wait_for_js`).
//
// Served at /browser/ctx.js and imported inside a single page.evaluate by
// hosts/browser/run.js.

const MAX_CAPTURED_LOGS = 50_000;
const MAX_CAPTURED_MESSAGE_CHARS = 400;

function report(name, passed, detail) {
  const suffix = detail ? `: ${detail}` : "";
  if (passed) {
    console.log(`PASS: ${name}${suffix}`);
  } else {
    console.log(`FAIL: ${name}${suffix}`);
    window.__failed = true;
  }
}

// Starts a smoldot client whose log lines are printed and kept in `logs`.
function startCapturing(options, prefix) {
  const logs = [];
  const client = window.__smoldot.start({
    ...options,
    logCallback: (level, target, message) => {
      const labels = { 1: "ERROR", 2: "WARN", 3: "INFO", 4: "DEBUG", 5: "TRACE" };
      const label = labels[level] ?? `L${level}`;
      console.log(`${prefix}[smoldot [${label}]][${target}] ${message}`);
      logs.push({
        t: Date.now(),
        level,
        target: String(target),
        message: String(message).slice(0, MAX_CAPTURED_MESSAGE_CHARS),
      });
      if (logs.length > MAX_CAPTURED_LOGS) logs.splice(0, logs.length - MAX_CAPTURED_LOGS);
    },
  });
  return { client, logs };
}

export async function makeBrowserCtx({ env, files }) {
  const maxLogLevel = Number.parseInt(env.SMOLDOT_LOG_LEVEL || "3", 10);
  const main = startCapturing({
    maxLogLevel,
    forbidTcp: true,
    forbidWs: true,
    forbidWss: true,
  }, "");
  const extra = [];

  return {
    host: "browser",
    client: main.client,
    clientLogs: main.logs,
    startClient: (options = {}, name = `client${extra.length + 2}`) => {
      const started = startCapturing({ maxLogLevel, ...options }, `[${name}]`);
      extra.push(started.client);
      return started;
    },
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
    sendSync: (label) => {
      if (typeof window.__sendSync !== "function") {
        throw new Error("sendSync called but SYNC_PATH was not set on the Rust side");
      }
      return window.__sendSync(label);
    },
    cleanup: async () => {
      for (const client of extra) await client.terminate().catch(() => {});
      await main.client.terminate().catch(() => {});
    },
    // Browsers can't write to disk: Node writes the files for the page, into
    // `SMOLDOT_DB_DUMP_DIR` as the Node host does; a no-op when it is unset.
    dumpDb: async (filesObj) => {
      if (typeof window.__dumpDb === "function") await window.__dumpDb(filesObj);
    },
  };
}
