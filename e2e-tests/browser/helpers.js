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

// Node-side helpers for the browser tests.

import http from "node:http";
import path from "node:path";
import fs from "node:fs/promises";

export function report(name, passed, detail) {
  const suffix = detail ? `: ${detail}` : "";
  if (passed) {
    console.log(`PASS: ${name}${suffix}`);
  } else {
    console.log(`FAIL: ${name}${suffix}`);
    process.exitCode = 1;
  }
}

export function requireEnv(names) {
  const missing = names.filter((n) => !process.env[n]);
  if (missing.length > 0) {
    console.error(`Required env vars: ${missing.join(", ")}`);
    process.exit(1);
  }
}

/// Polls `path` until a line equals `expected`. Pair with `SyncFile` on the Rust side.
export async function waitForSyncMessage(filePath, expected, timeoutMs = 120_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const contents = await fs.readFile(filePath, "utf8").catch(() => "");
    if (contents.split("\n").some((line) => line.trim() === expected)) {
      return;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(
    `Timed out waiting for sync message "${expected}" at ${filePath}`,
  );
}

/// Starts a tiny HTTP server that serves files from `pageDir` at `/` and from
/// `smoldotPkgDir` at `/smoldot/`. Returns the server (already listening on a
/// random local port).
export function startStaticServer(pageDir, smoldotPkgDir) {
  const server = http.createServer(async (req, res) => {
    try {
      const reqPath = decodeURIComponent(req.url.split("?")[0]);
      let filePath;
      if (reqPath === "/" || reqPath === "/index.html") {
        filePath = path.join(pageDir, "index.html");
      } else if (reqPath.startsWith("/smoldot/")) {
        filePath = path.join(smoldotPkgDir, reqPath.slice("/smoldot/".length));
      } else {
        res.statusCode = 404;
        res.end("not found");
        return;
      }
      const resolved = path.resolve(filePath);
      if (
        !resolved.startsWith(path.resolve(pageDir)) &&
        !resolved.startsWith(path.resolve(smoldotPkgDir))
      ) {
        res.statusCode = 403;
        res.end("forbidden");
        return;
      }
      const data = await fs.readFile(resolved);
      res.setHeader("Content-Type", contentTypeFor(resolved));
      res.end(data);
    } catch (e) {
      res.statusCode = 500;
      res.end(String(e));
    }
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function contentTypeFor(filePath) {
  switch (path.extname(filePath)) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
    case ".mjs":
      return "application/javascript; charset=utf-8";
    case ".wasm":
      return "application/wasm";
    default:
      return "application/octet-stream";
  }
}
