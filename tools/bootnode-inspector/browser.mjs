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

// Runs the browser build of smoldot inside headless Chromium (via Playwright)
// so that WebRTC bootnode addresses can be dialed. One page per smoldot
// client; the page serves `node_modules/smoldot` from disk and relays log
// lines and JSON-RPC responses back to Node through exposed functions.

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
// `smoldot`'s package.json is not exported, so walk up from the entry point
// to the directory whose package.json names the package (dist/cjs has one too).
const smoldotDir = (() => {
  let dir = path.dirname(require.resolve("smoldot"));
  for (;;) {
    const pkg = path.join(dir, "package.json");
    if (fs.existsSync(pkg) && JSON.parse(fs.readFileSync(pkg, "utf8")).name === "smoldot") return dir;
    const parent = path.dirname(dir);
    if (parent === dir) throw new Error("smoldot package directory not found");
    dir = parent;
  }
})();

const PAGE_HTML = `<!doctype html><html><head><meta charset="utf-8"></head><body><script type="module">
import * as smoldot from "/smoldot/dist/mjs/index-browser.js";
const chains = [];
window.__start = (maxLogLevel) => {
  window.__client = smoldot.start({
    maxLogLevel,
    logCallback: (level, target, message) => {
      if (typeof window.__log === "function") window.__log(level, target, message);
    },
  });
};
window.__addChain = async (chainSpec, relayIndex) => {
  const chain = await window.__client.addChain({
    chainSpec,
    potentialRelayChains: relayIndex == null ? undefined : [chains[relayIndex]],
  });
  const index = chains.push(chain) - 1;
  (async () => {
    while (true) {
      let raw;
      try { raw = await chain.nextJsonRpcResponse(); } catch { return; }
      if (typeof window.__rpc === "function") window.__rpc(index, raw);
    }
  })();
  return index;
};
window.__send = (index, json) => chains[index].sendJsonRpc(json);
window.__terminate = () => window.__client.terminate();
window.__ready = true;
</script></body></html>`;

// Returns `null` when Playwright or a Chromium build is not available.
export async function createBrowserHost() {
  let chromium;
  try {
    ({ chromium } = await import("playwright"));
  } catch {
    return null;
  }
  let browser;
  try {
    browser = await chromium.launch();
  } catch {
    return null;
  }
  const context = await browser.newContext();
  // Context-level bindings exist in every page before its first script runs,
  // unlike per-page exposeFunction, which raced with smoldot's first log line.
  const handlers = new Map();
  await context.exposeBinding("__log", (source, level, target, message) => {
    handlers.get(source.page)?.log(level, target, message);
  });
  await context.exposeBinding("__rpc", (source, index, raw) => {
    handlers.get(source.page)?.rpc(index, raw);
  });

  return {
    name: "browser",
    async startClient({ maxLogLevel, logCallback }) {
      const page = await context.newPage();
      const queues = new Map();
      const waiters = new Map();
      handlers.set(page, {
        log: logCallback,
        rpc: (index, raw) => {
          const w = waiters.get(index);
          if (w && w.length > 0) w.shift().resolve(raw);
          else {
            if (!queues.has(index)) queues.set(index, []);
            queues.get(index).push(raw);
          }
        },
      });
      await page.route("**/*", async (route) => {
        const { pathname } = new URL(route.request().url());
        if (pathname === "/") return route.fulfill({ contentType: "text/html", body: PAGE_HTML });
        if (!pathname.startsWith("/smoldot/")) return route.fulfill({ status: 404, body: "" });
        const file = path.resolve(smoldotDir, pathname.slice("/smoldot/".length));
        if (!file.startsWith(smoldotDir + path.sep) || !fs.existsSync(file)) {
          return route.fulfill({ status: 404, body: "" });
        }
        return route.fulfill({ path: file });
      });
      await page.goto("http://localhost/");
      await page.waitForFunction(() => window.__ready === true, { timeout: 30_000 });
      await page.evaluate((lvl) => window.__start(lvl), maxLogLevel);

      let closed = false;
      return {
        async addChain({ chainSpec, potentialRelayChains }) {
          const relayIndex = potentialRelayChains?.[0]?.index ?? null;
          const index = await page.evaluate(
            ([spec, relay]) => window.__addChain(spec, relay),
            [chainSpec, relayIndex],
          );
          return {
            index,
            sendJsonRpc(json) {
              page.evaluate(([i, j]) => window.__send(i, j), [index, json]).catch(() => {});
            },
            nextJsonRpcResponse() {
              const q = queues.get(index);
              if (q && q.length > 0) return Promise.resolve(q.shift());
              if (closed) return Promise.reject(new Error("client terminated"));
              return new Promise((resolve, reject) => {
                if (!waiters.has(index)) waiters.set(index, []);
                waiters.get(index).push({ resolve, reject });
              });
            },
          };
        },
        async terminate() {
          closed = true;
          // Settle pending readers the way the Node build does: it throws once
          // the client is gone. Without this a reader loop never finishes.
          for (const list of waiters.values()) {
            for (const w of list.splice(0)) w.reject(new Error("client terminated"));
          }
          try {
            await Promise.race([
              page.evaluate(() => window.__terminate()),
              new Promise((r) => setTimeout(r, 5_000)),
            ]);
          } catch {
            // page may already be gone
          }
          await page.close().catch(() => {});
          handlers.delete(page);
        },
      };
    },
    async close() {
      await browser.close().catch(() => {});
    },
  };
}
