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

// Node-side helpers for the browser host. The page's assets are served by
// Playwright request interception (see hosts/browser/run.js), so the only
// remaining helper is the SyncFile poller backing `ctx.waitSync`.

import fs from "node:fs/promises";

/// Polls `filePath` until a line equals `expected`. Pair with `SyncFile` on the
/// Rust side.
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
