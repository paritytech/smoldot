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

import * as fs from "node:fs";
import { start } from "smoldot";

export function createSmoldotClient() {
  const maxLogLevel = Number.parseInt(process.env.SMOLDOT_LOG_LEVEL || "3", 10);
  return start({
    maxLogLevel,
    logCallback: (level, target, message) => {
      const labels = { 1: "ERROR", 2: "WARN", 3: "INFO", 4: "DEBUG", 5: "TRACE" };
      const label = labels[level] ?? `L${level}`;
      console.error(`[${new Date().toISOString()}] [${label}] [${target}] ${message}`);
    },
  });
}

export async function addChainFromSpec(client, specPath, opts = {}) {
  const chainSpec = fs.readFileSync(specPath, "utf8");
  return client.addChain({ chainSpec, ...opts });
}

export function readDbContentIfSet(envVar) {
  const path = process.env[envVar];
  if (!path) return undefined;
  return fs.readFileSync(path, "utf8");
}

let nextId = 1;

export function sendRpc(chain, method, params = []) {
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

export async function sendRpcAndWait(chain, method, params = [], timeoutMs = 60000) {
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

export async function waitForJsonRpcMatch(chain, predicate, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const raceResult = await Promise.race([
      chain.nextJsonRpcResponse(),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error("Timed out waiting for JSON-RPC response")),
          Math.max(1, deadline - Date.now()),
        ),
      ),
    ]);
    const parsed = JSON.parse(raceResult);
    if (predicate(parsed)) {
      return parsed;
    }
  }
  throw new Error("Timed out waiting for matching response");
}

/// Polls the Rust→JS sync file at `path` until a line equals `expected`,
/// or throws on timeout. Pair with `SyncFile` on the Rust side.
export async function waitForMessage(path, expected, timeoutMs = 120_000, pollMs = 100) {
  const fs = await import("node:fs/promises");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const contents = await fs.readFile(path, "utf8").catch(() => "");
    if (contents.split("\n").some((line) => line.trim() === expected)) {
      return;
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
  throw new Error(`Timed out waiting for sync message "${expected}" at ${path}`);
}

export async function readJsonRpcUntil(chain, predicate, deadlineMs) {
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

export function report(name, passed, detail) {
  const suffix = detail ? `: ${detail}` : "";
  const ts = new Date().toISOString();
  if (passed) {
    console.log(`[${ts}] PASS: ${name}${suffix}`);
  } else {
    console.log(`[${ts}] FAIL: ${name}${suffix}`);
    process.exitCode = 1;
  }
}
