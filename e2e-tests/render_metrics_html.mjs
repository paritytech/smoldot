#!/usr/bin/env node
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

// Renders a metrics dump (produced by shared/metrics_sampler.js polling
// `sudo_unstable_metrics`) into a single self-contained HTML report with
// SVG line charts. No dependencies; works offline.
//
//   node render_metrics_html.mjs <dump.json> [out.html]

import * as fs from "node:fs";

const [dumpPath, outArg] = process.argv.slice(2);
if (!dumpPath) {
  console.error("usage: node render_metrics_html.mjs <dump.json> [out.html]");
  process.exit(1);
}
const dump = JSON.parse(fs.readFileSync(dumpPath, "utf8"));
const outPath = outArg ?? dumpPath.replace(/\.json$/, "") + ".html";

// ---------------------------------------------------------------- series prep

const okSamples = dump.samples.filter((s) => !s.error);
const failedPolls = dump.samples.length - okSamples.length;
if (okSamples.length === 0) {
  console.error("dump contains no successful samples; nothing to render");
  process.exit(1);
}
const t0 = Math.min(...okSamples.map((s) => s.t));
const tEnd = Math.max(...okSamples.map((s) => s.t));
const chains = dump.chains ?? [...new Set(okSamples.map((s) => s.chain))];

const metricKey = (name, labels) =>
  `${name}|${Object.entries(labels ?? {}).sort().map(([k, v]) => `${k}=${v}`).join(",")}`;

// chain -> [{ t, values: Map<key, number> }] sorted by t
const indexed = new Map(
  chains.map((chain) => [
    chain,
    okSamples
      .filter((s) => s.chain === chain)
      .sort((a, b) => a.t - b.t)
      .map((s) => {
        const values = new Map();
        for (const m of s.metrics) {
          for (const e of m.entries) values.set(metricKey(m.name, e.labels), e.value);
        }
        return { t: s.t, values };
      }),
  ]),
);

// Gauge: value at each sample. Missing -> null (gap).
function gaugeSeries(chain, name, labels) {
  const key = metricKey(name, labels);
  return indexed.get(chain).map((s) => ({ t: s.t, v: s.values.get(key) ?? null }));
}

// Counter rate: delta / elapsed seconds between consecutive samples, placed at
// the right edge. Negative deltas (restart) -> null.
function rateSeries(chain, name, labels) {
  const key = metricKey(name, labels);
  const rows = indexed.get(chain);
  const out = [];
  for (let i = 1; i < rows.length; i++) {
    const a = rows[i - 1].values.get(key);
    const b = rows[i].values.get(key);
    const dt = (rows[i].t - rows[i - 1].t) / 1000;
    out.push({
      t: rows[i].t,
      v: a == null || b == null || b < a || dt <= 0 ? null : (b - a) / dt,
    });
  }
  return out;
}

// Per-interval mean: (deltaNum / deltaDen), null when the denominator didn't move.
function meanSeries(chain, numName, numLabels, denName, denLabels) {
  const nk = metricKey(numName, numLabels);
  const dk = metricKey(denName, denLabels);
  const rows = indexed.get(chain);
  const out = [];
  for (let i = 1; i < rows.length; i++) {
    const dn = (rows[i].values.get(nk) ?? NaN) - (rows[i - 1].values.get(nk) ?? NaN);
    const dd = (rows[i].values.get(dk) ?? NaN) - (rows[i - 1].values.get(dk) ?? NaN);
    out.push({ t: rows[i].t, v: !Number.isFinite(dn) || !(dd > 0) || dn < 0 ? null : dn / dd });
  }
  return out;
}

function lastValue(chain, name, labels) {
  const rows = indexed.get(chain);
  if (rows.length === 0) return null;
  return rows[rows.length - 1].values.get(metricKey(name, labels)) ?? null;
}

// Sum of a metric's entries across all label values, at the last sample.
function lastValueSum(chain, name) {
  const rows = indexed.get(chain);
  if (rows.length === 0) return null;
  let sum = null;
  for (const [key, value] of rows[rows.length - 1].values) {
    if (key.startsWith(`${name}|`)) sum = (sum ?? 0) + value;
  }
  return sum;
}

// Distinct values of `labelKey` seen for a metric across the whole dump, first-seen order.
function labelValues(chain, name, labelKey) {
  const seen = new Set();
  for (const row of indexed.get(chain)) {
    for (const key of row.values.keys()) {
      if (!key.startsWith(`${name}|`)) continue;
      for (const pair of key.slice(name.length + 1).split(",")) {
        const [k, v] = pair.split("=");
        if (k === labelKey && v) seen.add(v);
      }
    }
  }
  return [...seen];
}

// ------------------------------------------------------------- chart configs

// Categorical slots (reference dataviz palette, order is the CVD mechanism).
const SLOTS = [
  { light: "#2a78d6", dark: "#3987e5" },
  { light: "#eb6834", dark: "#d95926" },
  { light: "#1baf7a", dark: "#199e70" },
  { light: "#eda100", dark: "#c98500" },
];
const PROTOCOLS = ["blocks", "warp-sync", "storage-proof", "call-proof"];

const charts = [];
function addChart(cfg) {
  const nonEmpty = cfg.series.filter((s) => s.points.some((p) => p.v != null));
  if (nonEmpty.length > 0) charts.push({ ...cfg, series: nonEmpty });
}

for (const chain of chains) {
  // The warp gauges read 0 until warp sync first sets them; treat 0 as "no
  // data" so an unused gauge doesn't drag the height scale to zero.
  const warpGauge = (name) =>
    gaugeSeries(chain, name).map((p) => ({ t: p.t, v: p.v === 0 ? null : p.v }));
  addChart({
    group: chain,
    title: "Block height",
    unit: "block",
    zeroBase: false,
    series: [
      { name: "best", slot: 0, points: gaugeSeries(chain, "syncBestBlockHeight") },
      { name: "finalized", slot: 1, points: gaugeSeries(chain, "syncFinalizedBlockHeight") },
      { name: "warp", slot: 2, points: warpGauge("syncWarpSyncHeight") },
      { name: "warpTarget", slot: 3, points: warpGauge("syncWarpSyncTargetHeight") },
    ],
  });
  addChart({
    group: chain,
    title: "Gossip peers connected",
    unit: "peer",
    zeroBase: true,
    series: [{ name: "peers", slot: 0, points: gaugeSeries(chain, "networkGossipPeersConnected") }],
  });
  addChart({
    group: chain,
    title: "Request rate",
    unit: "req/s",
    zeroBase: true,
    series: PROTOCOLS.map((p, i) => ({
      name: p,
      slot: i,
      points: rateSeries(chain, "networkRequestsTotal", { protocol: p, outcome: "success" }),
    })),
  });
  addChart({
    group: chain,
    title: "Request failure rate",
    unit: "req/s",
    zeroBase: true,
    series: PROTOCOLS.map((p, i) => ({
      name: p,
      slot: i,
      points: rateSeries(chain, "networkRequestsTotal", { protocol: p, outcome: "failure" }),
    })),
  });
  addChart({
    group: chain,
    title: "Mean request duration",
    unit: "s",
    zeroBase: true,
    series: PROTOCOLS.map((p, i) => ({
      name: p,
      slot: i,
      points: meanSeries(
        chain,
        "networkRequestSecondsTotal", { protocol: p },
        "networkRequestsTotal", { protocol: p, outcome: "success" },
      ),
    })),
  });
  // Warp progress relative to the observed gap; the absolute height/target
  // ratio starts near 100% whenever the checkpoint is recent.
  {
    const warp = warpGauge("syncWarpSyncHeight");
    const target = warpGauge("syncWarpSyncTargetHeight");
    const w0 = warp.find((p) => p.v != null)?.v;
    const progress = warp.map((p, i) => {
      const tv = target[i]?.v;
      const denom = tv != null && w0 != null ? tv - w0 : 0;
      return {
        t: p.t,
        v: p.v != null && denom > 0 ? Math.min(100, ((p.v - w0) / denom) * 100) : null,
      };
    });
    addChart({
      group: chain,
      title: "Warp sync progress",
      unit: "%",
      zeroBase: true,
      series: [{ name: "progress", slot: 0, points: progress }],
    });
  }
  addChart({
    group: chain,
    title: "Runtime compilations (cumulative)",
    unit: "",
    zeroBase: true,
    series: [
      { name: "compilations", slot: 0, points: gaugeSeries(chain, "runtimeCompilationsTotal") },
      { name: "errors", slot: 1, points: gaugeSeries(chain, "runtimeCompilationErrorsTotal") },
      { name: "cacheHits", slot: 2, points: gaugeSeries(chain, "runtimeCacheHitsTotal") },
    ],
  });
  addChart({
    group: chain,
    title: "Runtime compilation time (cumulative)",
    unit: "s",
    zeroBase: true,
    series: [
      { name: "compileTime", slot: 0, points: gaugeSeries(chain, "runtimeCompilationSecondsTotal") },
    ],
  });
}

// Peer bans by reason, one chart per chain. Reasons that fired become stacked
// bands (top 3 plus "other"); a ban-free run shows a flat zero line instead.
for (const chain of chains) {
  const reasons = labelValues(chain, "networkPeerBansTotal", "reason");
  const sumOf = (list) => {
    const parts = list.map((r) => gaugeSeries(chain, "networkPeerBansTotal", { reason: r }));
    return parts[0].map((p, i) => ({
      t: p.t,
      v: parts.reduce((sum, sr) => sum + (sr[i].v ?? 0), 0),
    }));
  };
  const active = reasons
    .map((r) => ({ r, last: lastValue(chain, "networkPeerBansTotal", { reason: r }) ?? 0 }))
    .filter((x) => x.last > 0)
    .sort((a, b) => b.last - a.last);
  let series, stacked;
  if (active.length === 0) {
    if (reasons.length === 0) continue; // metric absent from the dump
    series = [{ name: "total", slot: 0, points: sumOf(reasons) }];
    stacked = false;
  } else {
    const named = active.length > 4 ? active.slice(0, 3) : active;
    series = named.map((x, i) => ({
      name: x.r,
      slot: i,
      points: gaugeSeries(chain, "networkPeerBansTotal", { reason: x.r }),
    }));
    const rest = active.slice(named.length);
    if (rest.length > 0) {
      series.push({ name: "other", slot: 3, points: sumOf(rest.map((x) => x.r)) });
    }
    stacked = true;
  }
  addChart({
    group: chain,
    title: "Peer bans (cumulative)",
    unit: "ban",
    zeroBase: true,
    stacked,
    series,
  });
}

// Process-wide connection churn (identical in every chain's snapshot).
addChart({
  group: "network",
  title: "Connection churn",
  unit: "conn/s",
  zeroBase: true,
  series: [
    { name: "started", slot: 0, points: rateSeries(chains[0], "networkConnectionsStartedTotal") },
    { name: "handshaken", slot: 1, points: rateSeries(chains[0], "networkConnectionsHandshakesFinishedTotal") },
    { name: "shutdown", slot: 2, points: rateSeries(chains[0], "networkConnectionsShutdownsTotal") },
  ],
});

// Process-wide discovery drops.
addChart({
  group: "network",
  title: "Discovery addresses dropped (cumulative)",
  unit: "addr",
  zeroBase: true,
  stacked: true,
  series: ["peer-id-mismatch", "not-supported", "invalid"].map((r, i) => ({
    name: r,
    slot: i,
    points: gaugeSeries(chains[0], "networkDiscoveryAddressesDroppedTotal", { reason: r }),
  })),
});

// ------------------------------------------------------------------ stat tiles

const tiles = [];
for (const chain of chains) {
  tiles.push({ label: `${chain} finalized`, value: lastValue(chain, "syncFinalizedBlockHeight") });
  tiles.push({ label: `${chain} peers`, value: lastValue(chain, "networkGossipPeersConnected") });
  const bans = lastValueSum(chain, "networkPeerBansTotal");
  const verifyErr =
    (lastValue(chain, "syncBlocksVerifiedTotal", { outcome: "failure" }) ?? 0) +
    (lastValue(chain, "syncFinalityProofsVerifiedTotal", { outcome: "failure" }) ?? 0);
  tiles.push({ label: `${chain} peer bans`, value: bans, bad: bans > 0 });
  tiles.push({ label: `${chain} verify errors`, value: verifyErr, bad: verifyErr > 0 });
}

// ------------------------------------------------------------------ rendering

const W = 620, H = 240, M = { l: 56, r: 96, t: 12, b: 26 };
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function niceTicks(min, max, n = 4) {
  if (min === max) { min -= 1; max += 1; }
  const span = max - min;
  const step0 = span / n;
  const mag = 10 ** Math.floor(Math.log10(step0));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => span / s <= n) ?? 10 * mag;
  const lo = Math.floor(min / step) * step;
  const ticks = [];
  for (let v = lo; v <= max + step * 1e-9; v += step) if (v >= min - step * 1e-9) ticks.push(v);
  return ticks;
}

function fmtVal(v, unit) {
  if (v == null) return "—";
  if (unit === "%") return `${v.toFixed(1)}%`;
  if (unit === "s") {
    if (v === 0) return "0s";
    return v >= 1 ? `${v.toFixed(2)}s` : `${(v * 1000).toFixed(0)}ms`;
  }
  if (Math.abs(v) >= 1e6) return `${(v / 1e6).toFixed(2)}M`;
  if (Math.abs(v) >= 1e4) return `${(v / 1e3).toFixed(1)}k`;
  if (Number.isInteger(v)) return v.toLocaleString("en-US");
  return v.toFixed(2);
}
const fmtElapsed = (t) => {
  const s = Math.round((t - t0) / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
};

let chartSeq = 0;
function renderChart(cfg) {
  const id = `c${chartSeq++}`;
  // Stacked mode: filled bands between running-sum boundaries; nulls count as 0.
  // Assumes index-aligned timestamps across series.
  let bands = null;
  if (cfg.stacked) {
    const n = Math.max(...cfg.series.map((s) => s.points.length));
    const base = new Array(n).fill(0);
    bands = cfg.series.map((s) => {
      const low = [...base];
      for (let i = 0; i < n; i++) base[i] += s.points[i]?.v ?? 0;
      return { s, low, high: [...base] };
    });
  }
  const pts = bands
    ? bands[bands.length - 1].high
    : cfg.series.flatMap((s) => s.points.filter((p) => p.v != null).map((p) => p.v));
  let yMin = cfg.zeroBase ? 0 : Math.min(...pts);
  let yMax = Math.max(...pts);
  if (!cfg.zeroBase) { const pad = (yMax - yMin || 1) * 0.08; yMin -= pad; yMax += pad; }
  if (yMax === yMin) yMax = yMin + 1;
  const yTicks = niceTicks(yMin, yMax);
  yMin = Math.min(yMin, yTicks[0]);
  yMax = Math.max(yMax, yTicks[yTicks.length - 1]);
  const x = (t) => M.l + ((t - t0) / Math.max(1, tEnd - t0)) * (W - M.l - M.r);
  const y = (v) => M.t + (1 - (v - yMin) / (yMax - yMin)) * (H - M.t - M.b);

  let svg = "";
  for (const tv of yTicks) {
    svg += `<line class="grid" x1="${M.l}" x2="${W - M.r}" y1="${y(tv)}" y2="${y(tv)}"/>`;
    svg += `<text class="tick" x="${M.l - 6}" y="${y(tv) + 3}" text-anchor="end">${fmtVal(tv, cfg.unit)}</text>`;
  }
  const xTickCount = 5;
  for (let i = 0; i <= xTickCount; i++) {
    const t = t0 + ((tEnd - t0) * i) / xTickCount;
    svg += `<text class="tick" x="${x(t)}" y="${H - 8}" text-anchor="middle">${fmtElapsed(t)}</text>`;
  }
  svg += `<line class="axis" x1="${M.l}" x2="${W - M.r}" y1="${H - M.b}" y2="${H - M.b}"/>`;

  const endLabels = [];
  if (bands) {
    const times = cfg.series[0].points.map((p) => p.t);
    const edge = (arr) => arr.map((v, i) => `${x(times[i]).toFixed(1)},${y(v).toFixed(1)}`);
    for (const b of bands) {
      const top = edge(b.high);
      const bottom = edge(b.low).reverse();
      svg += `<path d="M${top.join(" L")} L${bottom.join(" L")} Z" fill="var(--s${b.s.slot})"/>`;
    }
    for (const b of bands.slice(0, -1)) {
      svg += `<polyline points="${edge(b.high).join(" ")}" fill="none" stroke="var(--surface)" stroke-width="2"/>`;
    }
    const last = times.length - 1;
    for (const b of bands) {
      if (cfg.series.length > 1 && b.high[last] > b.low[last]) {
        endLabels.push({
          slot: b.s.slot,
          name: b.s.name,
          y: (y(b.low[last]) + y(b.high[last])) / 2,
        });
      }
    }
  }
  if (!bands) cfg.series.forEach((s) => {
    // Split into segments at nulls so gaps stay gaps.
    let seg = [];
    const segs = [];
    for (const p of s.points) {
      if (p.v == null) { if (seg.length) segs.push(seg); seg = []; }
      else seg.push(`${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`);
    }
    if (seg.length) segs.push(seg);
    for (const sg of segs) {
      if (sg.length === 1) {
        const [px, py] = sg[0].split(",");
        svg += `<circle cx="${px}" cy="${py}" r="2.5" fill="var(--s${s.slot})"/>`;
      } else {
        svg += `<polyline class="line" points="${sg.join(" ")}" style="stroke:var(--s${s.slot})"/>`;
      }
    }
    // Direct end labels so identity isn't color-alone.
    const last = [...s.points].reverse().find((p) => p.v != null);
    if (last && cfg.series.length > 1) endLabels.push({ slot: s.slot, name: s.name, y: y(last.v) });
  });
  // De-overlap end labels: sort by anchor, push each at least 12px below the
  // previous one, then clamp the stack back into the plot area.
  endLabels.sort((a, b) => a.y - b.y);
  for (let i = 1; i < endLabels.length; i++) {
    endLabels[i].y = Math.max(endLabels[i].y, endLabels[i - 1].y + 12);
  }
  const overflow = endLabels.length ? endLabels[endLabels.length - 1].y - (H - M.b - 4) : 0;
  if (overflow > 0) {
    for (let i = endLabels.length - 1; i >= 0; i--) {
      endLabels[i].y -= overflow;
      if (i > 0 && endLabels[i].y < endLabels[i - 1].y + 12) endLabels[i - 1].y = endLabels[i].y - 12;
    }
  }
  for (const l of endLabels) {
    svg += `<circle cx="${W - M.r + 6}" cy="${l.y}" r="3" fill="var(--s${l.slot})"/>`;
    const short = l.name.length > 13 ? `${l.name.slice(0, 12)}…` : l.name;
    svg += `<text class="endlbl" x="${W - M.r + 12}" y="${l.y + 3}">${esc(short)}</text>`;
  }

  svg += `<line id="${id}-x" class="crosshair" y1="${M.t}" y2="${H - M.b}" x1="-10" x2="-10"/>`;
  svg += `<rect class="hit" x="${M.l}" y="${M.t}" width="${W - M.l - M.r}" height="${H - M.t - M.b}" data-chart="${id}"/>`;

  const hover = {
    unit: cfg.unit, t0, tEnd, ml: M.l, mr: M.r, w: W,
    series: cfg.series.map((s) => ({ name: s.name, slot: s.slot, points: s.points })),
  };

  const tableRows = (() => {
    const times = [...new Set(cfg.series.flatMap((s) => s.points.map((p) => p.t)))].sort((a, b) => a - b);
    const head = `<tr><th>t</th>${cfg.series.map((s) => `<th>${esc(s.name)}</th>`).join("")}</tr>`;
    const rows = times.map((t) => {
      const cells = cfg.series
        .map((s) => fmtVal(s.points.find((p) => p.t === t)?.v ?? null, cfg.unit))
        .map((v) => `<td>${v}</td>`).join("");
      return `<tr><td>${fmtElapsed(t)}</td>${cells}</tr>`;
    });
    return head + rows.join("");
  })();

  return `<figure class="chart">
  <figcaption>${esc(cfg.title)}${cfg.unit ? ` <span class="unit">(${esc(cfg.unit)})</span>` : ""}</figcaption>
  ${cfg.series.length > 1 || cfg.stacked ? `<div class="legend">${cfg.series.map((s) => `<span><i style="background:var(--s${s.slot})"></i>${esc(s.name)}</span>`).join("")}</div>` : ""}
  <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(cfg.title)}">${svg}</svg>
  <div class="tooltip" id="${id}-tip" hidden></div>
  <script type="application/json" id="${id}-data">${JSON.stringify(hover)}</script>
  <details><summary>Data</summary><div class="tablewrap"><table>${tableRows}</table></div></details>
</figure>`;
}

const groups = [...new Set(charts.map((c) => c.group))];
const sections = groups
  .map((g) => `<h2>${esc(g)}</h2><div class="grid">${charts.filter((c) => c.group === g).map(renderChart).join("\n")}</div>`)
  .join("\n");

const tileHtml = tiles
  .filter((t) => t.value != null)
  .map((t) => `<div class="tile${t.bad ? " bad" : ""}"><div class="v">${fmtVal(t.value)}</div><div class="l">${esc(t.label)}</div></div>`)
  .join("");

const durationMin = ((tEnd - t0) / 60000).toFixed(1);
const html = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>smoldot metrics — ${esc(dump.startedAt ?? "")}</title>
<style>
:root {
  color-scheme: light;
  --surface: #fcfcfb; --page: #f9f9f7;
  --ink: #0b0b0b; --ink2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --border: rgba(11,11,11,0.10);
  --bad: #d03b3b;
  --s0: #2a78d6; --s1: #eb6834; --s2: #1baf7a; --s3: #eda100;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --surface: #1a1a19; --page: #0d0d0d;
    --ink: #ffffff; --ink2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --border: rgba(255,255,255,0.10);
    --bad: #d03b3b;
    --s0: #3987e5; --s1: #d95926; --s2: #199e70; --s3: #c98500;
  }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 24px; background: var(--page); color: var(--ink);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
h1 { font-size: 18px; margin: 0 0 4px; }
h2 { font-size: 15px; margin: 28px 0 10px; color: var(--ink2); text-transform: capitalize; }
.meta { color: var(--muted); font-size: 12px; margin-bottom: 16px; }
.tiles { display: flex; flex-wrap: wrap; gap: 10px; margin: 14px 0 6px; }
.tile { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  padding: 10px 14px; min-width: 118px; }
.tile .v { font-size: 20px; font-weight: 600; }
.tile.bad .v { color: var(--bad); }
.tile .l { font-size: 11px; color: var(--muted); }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(430px, 1fr)); gap: 14px; }
.chart { margin: 0; background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: 12px 12px 8px; position: relative; }
.chart figcaption { font-size: 13px; font-weight: 600; margin-bottom: 2px; }
.chart .unit { color: var(--muted); font-weight: 400; }
.legend { display: flex; flex-wrap: wrap; gap: 10px; font-size: 11px; color: var(--ink2); margin: 2px 0 4px; }
.legend i { display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin-right: 4px; }
svg { width: 100%; height: auto; display: block; }
.grid-line, .grid { stroke: var(--grid); stroke-width: 1; }
.axis { stroke: var(--axis); stroke-width: 1; }
.tick, .endlbl { fill: var(--muted); font-size: 11px; font-family: inherit; }
.endlbl { fill: var(--ink2); }
.line { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
.crosshair { stroke: var(--axis); stroke-width: 1; stroke-dasharray: 3 3; }
.hit { fill: transparent; }
.tooltip { position: absolute; pointer-events: none; background: var(--surface);
  border: 1px solid var(--border); border-radius: 6px; padding: 6px 9px; font-size: 11px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.18); white-space: nowrap; z-index: 2; }
.tooltip .trow i { display: inline-block; width: 8px; height: 8px; border-radius: 2px; margin-right: 5px; }
.tooltip .tval { float: right; margin-left: 12px; font-variant-numeric: tabular-nums; }
details { margin-top: 6px; font-size: 11px; color: var(--ink2); }
.tablewrap { max-height: 200px; overflow: auto; margin-top: 4px; }
table { border-collapse: collapse; font-variant-numeric: tabular-nums; width: 100%; }
th, td { text-align: right; padding: 2px 8px; border-bottom: 1px solid var(--grid); }
th:first-child, td:first-child { text-align: left; }
</style>
<h1>smoldot metrics</h1>
<div class="meta">started ${esc(dump.startedAt ?? "?")} · ${durationMin} min · ${okSamples.length} samples every ${(dump.intervalMs ?? 0) / 1000}s${failedPolls ? ` · ${failedPolls} failed polls` : ""} · source: ${esc(dumpPath)}</div>
<div class="tiles">${tileHtml}</div>
${sections}
<script>
const fmtVal = ${fmtVal.toString()};
const t0 = ${t0};
const fmtElapsed = ${fmtElapsed.toString()};
document.querySelectorAll(".hit").forEach((hit) => {
  const id = hit.dataset.chart;
  const cfg = JSON.parse(document.getElementById(id + "-data").textContent);
  const tip = document.getElementById(id + "-tip");
  const cross = document.getElementById(id + "-x");
  const svg = hit.closest("svg");
  const fig = hit.closest("figure");
  const times = [...new Set(cfg.series.flatMap((s) => s.points.map((p) => p.t)))].sort((a, b) => a - b);
  const xOf = (t) => cfg.ml + ((t - cfg.t0) / Math.max(1, cfg.tEnd - cfg.t0)) * (cfg.w - cfg.ml - cfg.mr);
  hit.addEventListener("mousemove", (ev) => {
    const rect = svg.getBoundingClientRect();
    const sx = ((ev.clientX - rect.left) / rect.width) * cfg.w;
    let best = times[0];
    for (const t of times) if (Math.abs(xOf(t) - sx) < Math.abs(xOf(best) - sx)) best = t;
    cross.setAttribute("x1", xOf(best)); cross.setAttribute("x2", xOf(best));
    const rows = cfg.series.map((s) => {
      const p = s.points.find((q) => q.t === best);
      return '<div class="trow"><i style="background:var(--s' + s.slot + ')"></i>' + s.name +
        '<span class="tval">' + fmtVal(p ? p.v : null, cfg.unit) + "</span></div>";
    }).join("");
    tip.innerHTML = "<div>" + fmtElapsed(best) + "</div>" + rows;
    tip.hidden = false;
    const fr = fig.getBoundingClientRect();
    let lx = ev.clientX - fr.left + 14;
    if (lx + tip.offsetWidth > fr.width - 8) lx = ev.clientX - fr.left - tip.offsetWidth - 14;
    tip.style.left = lx + "px";
    tip.style.top = (ev.clientY - fr.top + 12) + "px";
  });
  hit.addEventListener("mouseleave", () => {
    tip.hidden = true;
    cross.setAttribute("x1", -10); cross.setAttribute("x2", -10);
  });
});
</script>
`;

fs.writeFileSync(outPath, html);
console.log(`metrics report: ${outPath}`);
