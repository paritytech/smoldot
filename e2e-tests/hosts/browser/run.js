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

// Generic browser-host runner. Selects the shared test module by TEST_NAME,
// resolves file/env inputs in Node, then runs the body inside headless Chrome
// against a browser `ctx`. Invoked from Rust via `run_shared_test`.

import { chromium } from "playwright";
import path from "node:path";
import url from "node:url";
import fs from "node:fs/promises";
import { waitForSyncMessage } from "../sync_file.js";
import { commonEnvInputs } from "../../shared/ctx-primitives.js";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));

const testName = process.env.TEST_NAME;
if (!testName) {
  console.error("TEST_NAME env var is required");
  process.exit(1);
}

const pageDir = path.join(__dirname, "page");
const smoldotPkgDir = path.resolve(__dirname, "..", "..", "..", "wasm-node", "javascript");
const sharedDir = path.resolve(__dirname, "..", "..", "shared");

// The page's assets — the smoldot browser bundle (/smoldot/*), the shared test
// modules (/shared/*) and the browser ctx builder (/browser/*) — are fulfilled
// from disk by Playwright request interception (page.route below); no HTTP
// server or port is needed. `localhost` keeps the page a secure context.
const MOUNTS = [
  { prefix: "/smoldot/", dir: smoldotPkgDir },
  { prefix: "/shared/", dir: sharedDir },
  { prefix: "/browser/", dir: __dirname },
];
const pageUrl = "http://localhost/";

// Resolve inputs in Node (the browser sandbox can't read disk or env).
const mod = await import(new URL(`../../shared/${testName}.js`, import.meta.url));
const fileInputs = mod.fileInputs ?? [];
const files = {};
for (const name of fileInputs) {
  const p = process.env[name];
  files[name] = p ? await fs.readFile(p, "utf8") : null;
}
// Same allowlist as the browser host, so `ctx.env` is identical across hosts
const env = {};
for (const name of [...commonEnvInputs, ...(mod.envInputs ?? [])]) {
  if (process.env[name] !== undefined) env[name] = process.env[name];
}

// Detect an optional per-test, host-specific extension in Node (the browser
// sandbox can't stat disk). If present it is served at /browser/prepare/<name>.js
// and imported inside the page below.
let hasHostPrepare = false;
try {
  await fs.stat(path.join(__dirname, "prepare", `${testName}.js`));
  hasHostPrepare = true;
} catch {}

const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
page.on("console", (m) => console.error(`[browser:${m.type()}] ${m.text()}`));
page.on("pageerror", (e) => console.error(`[browser:pageerror] ${e.message}`));

// Bridge the SyncFile into the page so a shared body's `ctx.waitSync(label)`
// works in the sandbox: Node polls the file and resolves back into the browser.
if (process.env.SYNC_PATH) {
  await page.exposeFunction("__waitSync", (label, timeoutMs) =>
    waitForSyncMessage(process.env.SYNC_PATH, label, timeoutMs).then(() => true),
  );
}

// Fulfill the page and its module/wasm assets from disk; nothing hits the network.
await page.route("**/*", async (route) => {
  const { pathname } = new URL(route.request().url());
  let file;
  if (pathname === "/" || pathname === "/index.html") {
    file = path.join(pageDir, "index.html");
  } else {
    const mount = MOUNTS.find((m) => pathname.startsWith(m.prefix));
    if (!mount) return route.fulfill({ status: 404, body: "not found" });
    const root = path.resolve(mount.dir);
    file = path.resolve(root, pathname.slice(mount.prefix.length));
    // Reject traversal that escapes the mount root.
    if (file !== root && !file.startsWith(root + path.sep)) {
      return route.fulfill({ status: 403, body: "forbidden" });
    }
  }
  // `route.fulfill({ path })` infers the content-type from the extension and
  // throws if the file is missing → translate that into a 404.
  try {
    await route.fulfill({ path: file });
  } catch {
    await route.fulfill({ status: 404, body: "not found" });
  }
});

let passed = true;
try {
  await page.goto(pageUrl);
  await page.waitForFunction(() => window.__ready === true, { timeout: 30_000 });

  // The whole test body runs in a single evaluate. Mid-test Rust handshakes
  // work via the exposed __waitSync, so no multi-evaluate state stashing.
  const failed = await page.evaluate(
    async ({ testName, env, files, hasHostPrepare }) => {
      const { makeBrowserCtx } = await import("/browser/ctx.js");
      const { assertCtx } = await import("/shared/ctx-primitives.js");
      const mod = await import(`/shared/${testName}.js`);
      let ctx = await makeBrowserCtx({ env, files });
      // Per-test, host-agnostic extension (the common case).
      if (mod.prepareCtx) ctx = await mod.prepareCtx(ctx);
      // Optional per-test, host-specific extension (rare), served from Node.
      if (hasHostPrepare) {
        const prep = await import(`/browser/prepare/${testName}.js`);
        ctx = await prep.default(ctx);
      }
      assertCtx(ctx);
      window.__failed = false;
      try {
        await mod.default(ctx);
      } catch (e) {
        console.log(`FAIL: ${testName}: ${e.stack || e.message || String(e)}`);
        window.__failed = true;
      } finally {
        await ctx.cleanup?.();
      }
      return window.__failed === true;
    },
    { testName, env, files, hasHostPrepare },
  );

  if (failed) passed = false;
} catch (e) {
  console.error(`run-browser error: ${e.stack || e.message || String(e)}`);
  passed = false;
} finally {
  await browser.close().catch(() => {});
}

process.exit(passed ? 0 : 1);
