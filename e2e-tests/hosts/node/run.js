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

// Generic Node-host runner. Selects the shared test module by TEST_NAME, builds
// a Node `ctx`, and runs the body. Invoked from Rust via `run_shared_test`.

import { stat, readFile } from "node:fs/promises";
import { makeNodeCtx } from "./ctx.js";
import { assertCtx, commonEnvInputs } from "../../shared/ctx-primitives.js";

const testName = process.env.TEST_NAME;
if (!testName) {
  console.error("TEST_NAME env var is required");
  process.exit(1);
}

async function fileExists(url) {
  try {
    await stat(url);
    return true;
  } catch {
    return false;
  }
}

const mod = await import(new URL(`../../shared/${testName}.js`, import.meta.url));
const fileInputs = mod.fileInputs ?? [];
const files = {};
for (const name of fileInputs) {
  const p = process.env[name];
  files[name] = p ? await readFile(p, "utf8") : null;
}
// Same allowlist as the browser host, so `ctx.env` is identical across hosts
const env = {};
for (const name of [...commonEnvInputs, ...(mod.envInputs ?? [])]) {
  if (process.env[name] !== undefined) env[name] = process.env[name];
}
const base = await makeNodeCtx({ env, files });

// Per-test, host-agnostic extension (the common case): the body may export a
// `prepareCtx` that returns an augmented ctx built from base primitives.
let ctx = mod.prepareCtx ? await mod.prepareCtx(base) : base;

// Optional per-test, host-specific extension (rare): hosts/node/prepare/<name>.js,
// auto-discovered only when it exists, so the common case writes no host file.
const hostPrepUrl = new URL(`./prepare/${testName}.js`, import.meta.url);
if (await fileExists(hostPrepUrl)) {
  const prep = await import(hostPrepUrl);
  ctx = await prep.default(ctx);
}

assertCtx(ctx);

let ok = true;
try {
  await mod.default(ctx);
} catch (e) {
  ctx.report(testName, false, e.stack || e.message || String(e));
  ok = false;
} finally {
  await ctx.cleanup?.();
}

process.exit(ok && !process.exitCode ? 0 : 1);
