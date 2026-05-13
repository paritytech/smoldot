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

// Browser sanity check for smoldot statement-store.
//   1. Page loads, imports `index-browser.js`, exposes `window.__smoldot`.
//   2. Page starts smoldot, adds the chains, subscribes to topic_B.
//   3. Node waits for the harness to write READY into SYNC_PATH — that means
//      smoldot has peered and stmt_B is already in both collators' stores so
//      they will push it during initial statement-store sync.
//   4. PING: page submits stmt_A through smoldot, asserts {status:"new"}.
//   5. PONG: page waits for stmt_B to arrive on its subscription.

import { chromium } from "playwright";
import path from "node:path";
import url from "node:url";
import fs from "node:fs/promises";
import {
  report,
  requireEnv,
  waitForSyncMessage,
  startStaticServer,
} from "./helpers.js";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));

requireEnv([
  "RELAY_CHAIN_SPEC",
  "PARA_CHAIN_SPEC",
  "STATEMENT_A_HEX",
  "STATEMENT_B_HEX",
  "TOPIC_B",
  "SYNC_PATH",
]);

const pageDir = path.join(__dirname, "page");
const smoldotPkgDir = path.resolve(
  __dirname,
  "..",
  "..",
  "wasm-node",
  "javascript",
);

const server = await startStaticServer(pageDir, smoldotPkgDir);
const port = server.address().port;
const pageUrl = `http://127.0.0.1:${port}/`;

const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
page.on("console", (m) => console.error(`[browser:${m.type()}] ${m.text()}`));
page.on("pageerror", (e) => console.error(`[browser:pageerror] ${e.message}`));

let passed = true;

try {
  await page.goto(pageUrl);
  await page.waitForFunction(() => window.__ready === true, { timeout: 30_000 });
  report("smoldot browser bundle loaded", true);

  const relaySpec = await fs.readFile(process.env.RELAY_CHAIN_SPEC, "utf8");
  const paraSpec = await fs.readFile(process.env.PARA_CHAIN_SPEC, "utf8");

  // Phase 1: start smoldot, addChain, subscribe. Stash the handles on
  // `window.__t` so subsequent evaluates can reuse the same client.
  const subscriptionId = await page.evaluate(
    async ([relaySpec, paraSpec, topicBHex]) => {
      const log = (s) => console.log(s);

      const client = window.__smoldot.start({
        maxLogLevel: 3,
        forbidTcp: true,
        logCallback: (level, target, message) => {
          log(`[smoldot L${level}][${target}] ${message}`);
        },
      });

      const relay = await client.addChain({
        chainSpec: relaySpec,
        disableJsonRpc: true,
      });
      const para = await client.addChain({
        chainSpec: paraSpec,
        potentialRelayChains: [relay],
        statementStore: {},
      });

      const buf = [];
      const waiters = [];
      (async () => {
        try {
          for await (const raw of para.jsonRpcResponses) {
            buf.push(JSON.parse(raw));
            for (const w of waiters.splice(0)) w();
          }
        } catch (_) {}
      })();

      const waitForResponse = (predicate, timeoutMs) =>
        new Promise((resolve, reject) => {
          const deadline = Date.now() + timeoutMs;
          const tryMatch = () => {
            for (let i = 0; i < buf.length; i++) {
              if (predicate(buf[i])) {
                const hit = buf[i];
                buf.splice(i, 1);
                return resolve(hit);
              }
            }
            if (Date.now() >= deadline) return reject(new Error("timeout"));
            waiters.push(tryMatch);
            setTimeout(tryMatch, Math.min(500, deadline - Date.now()));
          };
          tryMatch();
        });

      let nextId = 1;
      const send = (method, params) => {
        const id = String(nextId++);
        para.sendJsonRpc(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
        return id;
      };

      // Subscribe early so we don't miss stmt_B pushed during initial sync.
      const subReqId = send("statement_subscribeStatement", [
        { matchAny: [topicBHex] },
      ]);
      const subResp = await waitForResponse((m) => m.id === subReqId, 30_000);
      if (subResp.error) {
        throw new Error(`subscribe failed: ${JSON.stringify(subResp.error)}`);
      }

      window.__t = { client, para, send, waitForResponse };
      return subResp.result;
    },
    [relaySpec, paraSpec, process.env.TOPIC_B],
  );
  report("subscribe to topic_B", true, `subId=${subscriptionId}`);

  // Phase 2: wait for the harness to confirm smoldot is peered and stmt_B
  // is in both collators' stores.
  await waitForSyncMessage(process.env.SYNC_PATH, "READY", 120_000);
  report("Rust signalled READY", true);

  // Phase 3: ping (submit stmt_A) + pong (await stmt_B notification).
  const result = await page.evaluate(
    async ([stmtAHex, stmtBHex, subscriptionId]) => {
      const { send, waitForResponse, client } = window.__t;

      const id = send("statement_submit", [stmtAHex]);
      const resp = await waitForResponse((m) => m.id === id, 30_000);
      if (resp.error) {
        return { stage: "ping", error: JSON.stringify(resp.error) };
      }
      if (resp.result?.status !== "new") {
        return { stage: "ping", got: resp.result };
      }

      await waitForResponse((m) => {
        if (m.method !== "statement_statement") return false;
        if (m.params?.subscription !== subscriptionId) return false;
        const r = m.params.result;
        if (r?.event !== "newStatements") return false;
        return (r.data?.statements ?? []).includes(stmtBHex);
      }, 120_000);

      return { stage: "ok" };
    },
    [process.env.STATEMENT_A_HEX, process.env.STATEMENT_B_HEX, subscriptionId],
  );

  if (result.stage === "ping") {
    report("ping: statement_submit returned status=new", false, JSON.stringify(result));
    passed = false;
  } else if (result.stage === "ok") {
    report("ping: statement_submit returned status=new", true);
    report("pong: stmt_B received via subscription", true);
  } else {
    report("browser ping-pong", false, JSON.stringify(result));
    passed = false;
  }

  if (passed) {
    // Phase 4: keep smoldot alive so its outbound gossip of stmt_A actually
    // reaches the collators. The harness signals DONE once alice has observed
    // stmt_A; only then is it safe to tear the client down.
    await waitForSyncMessage(process.env.SYNC_PATH, "DONE", 240_000);
    report("Rust signalled DONE", true);
    await page.evaluate(() => window.__t.client.terminate().catch(() => {}));
  }
} catch (e) {
  report("browser test", false, e.stack || e.message || String(e));
  passed = false;
} finally {
  await browser.close().catch(() => {});
  server.close();
}

if (!passed || process.exitCode) {
  process.exit(1);
}
