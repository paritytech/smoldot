// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Spawns parachain-phase-breakdown.mjs N times and aggregates phase timings.
// Use to measure warm/cold phase variance.
//
// Env vars:
//   SMOLDOT_REPRO_RUNS     — number of runs (default 5)
//   SMOLDOT_RELAY_SPEC_PATH, SMOLDOT_PARA_SPEC_PATH — forwarded to child probe

import { spawn } from 'node:child_process';

const RUNS = Number.parseInt(process.env.SMOLDOT_REPRO_RUNS ?? '5', 10);

function runChildProbe(index) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['./scripts/parachain-phase-breakdown.mjs'], {
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      // Echo to parent so we can see progress.
      process.stdout.write(chunk);
    });
    child.stderr.pipe(process.stderr);

    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`run ${index} exited with code ${code}`));
        return;
      }
      const line = stdout.split('\n').reverse().find((l) => l.startsWith('PHASES_JSON '));
      if (!line) {
        reject(new Error(`run ${index} did not emit PHASES_JSON`));
        return;
      }
      try {
        const payload = JSON.parse(line.slice('PHASES_JSON '.length));
        resolve(payload);
      } catch (err) {
        reject(new Error(`run ${index} PHASES_JSON parse failed: ${err}`));
      }
    });
  });
}

// Phase keys we report variance for (both cold & warm share the schema, null means not hit).
const REPORT_KEYS = [
  'addChainRelayMs',
  'addChainParaMs',
  'relayRuntimeReadyMs',
  'paraWarmStartingMs',
  'paraHeadFromRelayMs',
  'paraBootstrapStartMs',
  'paraRuntimeVerifyMs',
  'paraRuntimeDownloadMs',
  'paraRuntimeCompiledMs',
  'paraConsensusRestoredMs',
  'paraConsensusBootstrapMs',
  'paraRuntimeReadyMs',
  'paraDbReadyMs',
];

const DERIVED_KEYS = [
  'paraBootstrapToVerifyMs',
  'paraVerifyToCompileMs',
  'paraBootstrapToCompileMs',
  'paraCompileToRuntimeReadyMs',
  'paraRuntimeReadyToDbReadyMs',
  'paraVerifyToConsensusMs',
  'paraDownloadToBootstrappedMs',
];

function summarize(values) {
  const finite = values.filter((v) => Number.isFinite(v));
  if (finite.length === 0) return null;
  const sorted = [...finite].sort((a, b) => a - b);
  const sum = finite.reduce((a, b) => a + b, 0);
  const avg = sum / finite.length;
  const median = sorted[Math.floor(sorted.length / 2)];
  return {
    n: finite.length,
    minMs: sorted[0],
    maxMs: sorted[sorted.length - 1],
    medianMs: Math.round(median),
    avgMs: Number(avg.toFixed(1)),
    values: finite,
  };
}

function aggregatePhase(runs, phaseName) {
  const table = {};
  for (const key of REPORT_KEYS) {
    table[key] = summarize(runs.map((r) => r[phaseName].phases[key]));
  }
  for (const key of DERIVED_KEYS) {
    table[key] = summarize(runs.map((r) => r[phaseName].phases.derived[key]));
  }
  table.totalMs = summarize(runs.map((r) => r[phaseName].totalMs));
  return table;
}

function renderTable(agg) {
  const rows = [];
  for (const [k, v] of Object.entries(agg)) {
    if (!v) {
      rows.push([k, '—']);
      continue;
    }
    rows.push([k, `avg ${v.avgMs} ms   median ${v.medianMs} ms   min ${v.minMs}   max ${v.maxMs}   n=${v.n}`]);
  }
  const keyWidth = Math.max(...rows.map((r) => r[0].length));
  return rows.map(([k, v]) => `  ${k.padEnd(keyWidth)}  ${v}`).join('\n');
}

async function main() {
  const runs = [];
  for (let i = 0; i < RUNS; i++) {
    process.stdout.write(`\n=== BENCHMARK RUN ${i + 1} / ${RUNS} ===\n`);
    const payload = await runChildProbe(i);
    runs.push(payload);
  }

  process.stdout.write('\n\n=== AGGREGATE — COLD PHASE ===\n');
  const coldAgg = aggregatePhase(runs, 'cold');
  process.stdout.write(renderTable(coldAgg) + '\n');

  process.stdout.write('\n=== AGGREGATE — WARM PHASE ===\n');
  const warmAgg = aggregatePhase(runs, 'warm');
  process.stdout.write(renderTable(warmAgg) + '\n');

  process.stdout.write('\nAGGREGATE_JSON ' + JSON.stringify({ runs: RUNS, cold: coldAgg, warm: warmAgg }) + '\n');
}

main().catch((error) => {
  process.stderr.write(String(error?.stack ?? error) + '\n');
  process.exitCode = 1;
});
