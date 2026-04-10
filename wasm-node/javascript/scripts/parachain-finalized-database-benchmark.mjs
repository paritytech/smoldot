// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

import { spawn } from 'node:child_process';

const RUNS = Number.parseInt(process.env.SMOLDOT_REPRO_RUNS ?? '3', 10);

function summarize(values) {
  if (values.length === 0) {
    return null;
  }

  return {
    avgMs: Number((values.reduce((total, value) => total + value, 0) / values.length).toFixed(1)),
    minMs: Math.min(...values),
    maxMs: Math.max(...values),
    valuesMs: values,
  };
}

function runProbe(index) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['./scripts/parachain-finalized-database-probe.mjs'], {
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      process.stdout.write(chunk);
    });
    child.stderr.pipe(process.stderr);

    child.on('error', reject);
    child.on('close', (code, signal) => {
      if (code !== 0) {
        reject(new Error(`probe ${index} exited with code ${code} signal ${signal ?? 'none'}`));
        return;
      }

      const coldLine = stdout
        .split('\n')
        .find((line) => line.startsWith('COLD_SUMMARY '));
      const warmLine = stdout
        .split('\n')
        .find((line) => line.startsWith('WARM_SUMMARY '));

      if (!coldLine || !warmLine) {
        reject(new Error(`probe ${index} did not print both summary lines`));
        return;
      }

      resolve({
        index,
        cold: JSON.parse(coldLine.slice('COLD_SUMMARY '.length)),
        warm: JSON.parse(warmLine.slice('WARM_SUMMARY '.length)),
      });
    });
  });
}

async function main() {
  const runs = [];

  for (let index = 1; index <= RUNS; index += 1) {
    console.log(`BENCHMARK_RUN_START ${JSON.stringify({ index, total: RUNS })}`);
    const run = await runProbe(index);
    runs.push(run);
    console.log(`BENCHMARK_RUN_SUMMARY ${JSON.stringify({
      index,
      coldTotalMs: run.cold.totalMs,
      coldParaDbReadyMs: run.cold.paraDbReadyMs,
      warmTotalMs: run.warm.totalMs,
      warmParaDbReadyMs: run.warm.paraDbReadyMs,
      warmParaReadyRatio: run.warm.paraReadyRatio,
    })}`);
  }

  console.log(`BENCHMARK_SUMMARY ${JSON.stringify({
    runs: runs.length,
    coldTotal: summarize(runs.map((run) => run.cold.totalMs)),
    coldParaDbReady: summarize(runs.map((run) => run.cold.paraDbReadyMs)),
    warmTotal: summarize(runs.map((run) => run.warm.totalMs)),
    warmParaDbReady: summarize(runs.map((run) => run.warm.paraDbReadyMs)),
  })}`);
}

main().catch((error) => {
  process.stderr.write(String(error?.stack ?? error) + '\n');
  process.exitCode = 1;
});
