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

// Periodic `sudo_unstable_metrics` sampler. Host-agnostic: it only needs, per
// chain, a `request(method, params, timeoutMs) -> Promise<result>` function
// that is safe to call concurrently with whatever else the test is doing on
// that chain (`JsonRpcMux.request` or `rpc.sendRpcOutOfBand` both qualify;
// `rpc.sendRpcAndWait` does NOT — it drains and discards queued messages).
//
// The resulting dump is a flat sample list; `render_metrics_html.mjs` turns it
// into graphs. Counters are cumulative, so consumers diff consecutive samples
// for rates.

const REQUEST_TIMEOUT_MS = 10_000;

// `targets`: [{ chain: "relay", request: (method, params, timeoutMs) => Promise }].
// Returns { stop: async () => dump }. Samples are taken sequentially within a
// tick so the sampler never has more than one request in flight.
export function startMetricsSampler({ targets, intervalMs = 5000, log = () => {} }) {
  const startedAt = Date.now();
  const samples = [];
  let stopped = false;
  let timer = null;
  let wake = null;

  const tick = async () => {
    for (const { chain, request } of targets) {
      if (stopped) return;
      try {
        const result = await request("sudo_unstable_metrics", [], REQUEST_TIMEOUT_MS);
        samples.push({ t: Date.now(), chain, metrics: result.metrics });
      } catch (e) {
        // Keep sampling; a failed poll is a data point, not a test failure.
        samples.push({ t: Date.now(), chain, error: String(e?.message ?? e) });
      }
    }
  };

  const done = (async () => {
    while (!stopped) {
      await tick();
      if (stopped) break;
      await new Promise((resolve) => {
        wake = resolve;
        timer = setTimeout(resolve, intervalMs);
      });
      wake = null;
    }
  })();

  return {
    stop: async () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      if (wake) wake();
      await done;
      const errors = samples.filter((s) => s.error).length;
      log(`metrics sampler: ${samples.length} samples collected (${errors} failed polls)`);
      return {
        version: 1,
        startedAt: new Date(startedAt).toISOString(),
        intervalMs,
        chains: targets.map((t) => t.chain),
        samples,
      };
    },
  };
}
