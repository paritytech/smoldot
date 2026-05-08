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

import { chromium } from "playwright";
import path from "node:path";
import url from "node:url";
import fs from "node:fs/promises";
import {
  report,
  startStaticServer,
} from "./helpers.js";

async function readDbContentIfSet(envVar) {
  const path = process.env[envVar];
  if (!path) return undefined;
  return await fs.readFile(path, "utf8");
}
  
const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const paraSpecPath = process.env.PARA_CHAIN_SPEC;
const requiredBlocks = Number.parseInt(process.env.REQUIRED_BLOCKS, 10);
const expectedInitialFinalized = Number.parseInt(process.env.EXPECTED_INITIAL_FINALIZED ?? "0", 10);
const dbDumpDir = process.env.SMOLDOT_DB_DUMP_DIR;

if (!relaySpecPath || !paraSpecPath || !Number.isFinite(requiredBlocks)) {
  console.error(
    "Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, REQUIRED_BLOCKS",
  );
  process.exit(1);
}

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));

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

  const relaySpec = await fs.readFile(relaySpecPath, "utf8");
  const paraSpec = await fs.readFile(paraSpecPath, "utf8");

  const relayDbContent = await readDbContentIfSet("SMOLDOT_DB_RELAY");
  const paraDbContent = await readDbContentIfSet("SMOLDOT_DB_PARA");

  const dbDump = !!dbDumpDir;

  const result = await page.evaluate(
    async ([relaySpec, paraSpec, relayDbContent, paraDbContent, expectedInitialFinalized, requiredBlocks, dbDump]) => {

      let nextId = 1;
       function sendRpc(chain, method, params = []) {
        const id = nextId++;
        const request = JSON.stringify({
          jsonrpc: "2.0",
          id: id.toString(),
          method,
          params,
        });
        chain.sendJsonRpc(request);
        return id;
      }

       async function readJsonRpcUntil(chain, predicate, deadlineMs) {
        while (Date.now() < deadlineMs) {
          const remaining = deadlineMs - Date.now();
          let raw;
          try {
            raw = await Promise.race([
              chain.nextJsonRpcResponse(),
              new Promise((_, reject) =>
                setTimeout(() => reject(new Error("timeout")), remaining),
              ),
            ]);
          } catch (_) {
            return undefined;
          }
          const msg = JSON.parse(raw);
          const out = predicate(msg);
          if (out !== undefined) return out;
        }
        return undefined;
      }

       async function sendRpcAndWait(chain, method, params = [], timeoutMs = 60000) {
        const id = sendRpc(chain, method, params);
        const idStr = id.toString();
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
          const raw = await Promise.race([
            chain.nextJsonRpcResponse(),
            new Promise((_, reject) =>
              setTimeout(
                () => reject(new Error(`Timed out waiting for ${method} response`)),
                Math.max(1, deadline - Date.now()),
              ),
            ),
          ]);
          const response = JSON.parse(raw);
          if (response.id === idStr) {
            if (response.error) {
              throw new Error(`RPC error for ${method}: ${JSON.stringify(response.error)}`);
            }
            return response.result;
          }
        }
        throw new Error(`Timed out waiting for ${method} response after ${timeoutMs}ms`);
      }

       function report(name, passed, detail) {
        const suffix = detail ? `: ${detail}` : "";
        const ts = new Date().toISOString();
        if (passed) {
          console.log(`[${ts}] PASS: ${name}${suffix}`);
        } else {
          console.log(`[${ts}] FAIL: ${name}${suffix}`);
          // process.exitCode = 1;
        }
      }

      function decodeHeaderNumber(hexStr) {
        const stripped = hexStr.startsWith("0x") ? hexStr.slice(2) : hexStr;

        // const bytes = Buffer.from(stripped, "hex");
        // if (bytes.length < 33) throw new Error(`header hex too short: ${bytes.length} bytes`);
        const bytes = new Uint8Array(stripped.length / 2);
        for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(stripped.substr(i*2, 2), 16);
        const off = 32;
        const b0 = bytes[off];
        const mode = b0 & 0b11;
        if (mode === 0) return b0 >>> 2;
        if (mode === 1) return (b0 | (bytes[off + 1] << 8)) >>> 2;
        if (mode === 2) {
          return (
            (b0 | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24)) >>> 2
          );
        }
        throw new Error(`compact mode 3 not supported in decodeHeaderNumber`);
      }

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
        databaseContent: relayDbContent
      });
      const para = await client.addChain({
        chainSpec: paraSpec,
        databaseContent: paraDbContent,
        potentialRelayChains: [relay],
      });
      
      if (expectedInitialFinalized > 0) {
        const relayFollowReqId = sendRpc(relay, "chainHead_v1_follow", [false]).toString();
        const relaySubId = await readJsonRpcUntil(
          relay,
          (msg) => {
            if (msg.id === relayFollowReqId) {
              if (msg.error)
                throw new Error(
                  `relay chainHead_v1_follow failed: ${JSON.stringify(msg.error)}`,
                );
              return msg.result;
            }
            return undefined;
          },
          Date.now() + 30_000,
        );
        if (typeof relaySubId !== "string" || !relaySubId) {
          throw new Error("Unexpected relay follow subscription id");
        }
        const finalizedHash = await readJsonRpcUntil(
          relay,
          (msg) => {
            if (msg.method !== "chainHead_v1_followEvent") return undefined;
            if (msg.params?.subscription !== relaySubId) return undefined;
            const r = msg.params.result;
            if (r?.event === "initialized") {
              const hashes = r.finalizedBlockHashes ?? [];
              return hashes[hashes.length - 1];
            }
            if (r?.event === "stop") throw new Error("relay chainHead follow stopped");
            return undefined;
          },
          Date.now() + 120_000,
        );
        if (typeof finalizedHash !== "string") {
          throw new Error("relay chainHead never reported initialized");
        }
        const headerHex = await sendRpcAndWait(
          relay,
          "chainHead_v1_header",
          [relaySubId, finalizedHash],
          30_000,
        );
        const num = decodeHeaderNumber(headerHex);
        const ok = num >= expectedInitialFinalized;
        report(
          "relay finalized at-or-past expected_initial_finalized",
          ok,
          `finalized=#${num} expected=#${expectedInitialFinalized}`,
        );
        if (!ok)
          throw new Error(
            `relay finalized #${num} below expected_initial_finalized #${expectedInitialFinalized}`,
          );
      }

      const followReqId = sendRpc(para, "chainHead_v1_follow", [false]).toString();
      const subId = await readJsonRpcUntil(
        para,
        (msg) => {
          if (msg.id === followReqId) {
            if (msg.error)
              throw new Error(
                `chainHead_v1_follow failed: ${JSON.stringify(msg.error)}`,
              );
            return msg.result;
          }
          return undefined;
        },
        Date.now() + 30_000,
      );
      if (typeof subId !== "string" || !subId) {
        throw new Error(`Unexpected follow subscription id: ${JSON.stringify(subId)}`);
      }
      report("chainHead_v1_follow accepted", true, `subId=${subId}`);

      const initialBlocks = new Set();
      let newBlocks = 0;
      await readJsonRpcUntil(
        para,
        (msg) => {
          if (msg.method !== "chainHead_v1_followEvent") return undefined;
          if (msg.params?.subscription !== subId) return undefined;
          const result = msg.params.result;
          if (result?.event === "initialized") {
            for (const h of result.finalizedBlockHashes ?? []) initialBlocks.add(h);
          } else if (result?.event === "newBlock" && !initialBlocks.has(result.blockHash)) {
            if (++newBlocks >= requiredBlocks) return true;
          } else if (result?.event === "stop") {
            throw new Error("chainHead follow stopped unexpectedly");
          }
          return undefined;
        },
        Date.now() + 180_000,
      );

      const ok = newBlocks >= requiredBlocks;
      report(
        "smoldot saw new parachain blocks",
        ok,
        `count=${newBlocks}/${requiredBlocks}`,
      );

      let relayDbDump;
      let paraDbDump;
      if (ok && dbDump) {
        relayDbDump = await sendRpcAndWait(
          relay,
          "chainHead_unstable_finalizedDatabase",
          [],
          30_000,
        );
        paraDbDump = await sendRpcAndWait(
          para,
          "chainHead_unstable_finalizedDatabase",
          [],
          30_000,
        );
        report("dumped smoldot databaseContent", true, dbDump);
      }

      return { ok, relayDbDump, paraDbDump };
    },
    [relaySpec, paraSpec, relayDbContent, paraDbContent, expectedInitialFinalized, requiredBlocks, dbDump],
  );

  let { ok, relayDbDump, paraDbDump } = result;
  if (!ok) passed = false;
  if (passed && dbDumpDir) {
    await fs.mkdir(dbDumpDir, { recursive: true });
    await fs.writeFile(`${dbDumpDir}/relay.json`, relayDbDump);
    await fs.writeFile(`${dbDumpDir}/para.json`, paraDbDump);
    report("dumped smoldot databaseContent", true, dbDumpDir);
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
