// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Phase-breakdown diagnostic for the parachain warm-restart path.
//
// Runs a cold start (empty databaseContent) followed by a warm start (DB
// saved from the cold run) and prints a per-phase timing table. Uses
// smoldot's logCallback to capture phase-marker log lines with arrival
// timestamps.
//
// Output is a table per phase plus a PHASES_JSON line that scripts can parse.

import * as fs from 'node:fs';
import { start } from '../dist/mjs/index-nodejs.js';

const relaySpecPath = process.env.SMOLDOT_RELAY_SPEC_PATH
  ?? '../../../demo-chain-specs/ksmcc3.json';
const paraSpecPath = process.env.SMOLDOT_PARA_SPEC_PATH
  ?? '../../../demo-chain-specs/ksmcc3_asset_hub.json';
const TIMEOUT_MS = Number.parseInt(process.env.SMOLDOT_REPRO_TIMEOUT_MS ?? '300000', 10);
const RPC_TIMEOUT_MS = Number.parseInt(process.env.SMOLDOT_REPRO_RPC_TIMEOUT_MS ?? '30000', 10);
const POLL_MS = Number.parseInt(process.env.SMOLDOT_REPRO_POLL_MS ?? '1000', 10);
const LOG_LEVEL = Number.parseInt(process.env.SMOLDOT_REPRO_LOG_LEVEL ?? '3', 10);

const relaySpec = fs.readFileSync(new URL(relaySpecPath, import.meta.url), 'utf8');
const paraSpec = fs.readFileSync(new URL(paraSpecPath, import.meta.url), 'utf8');

// Phase markers. Each entry: [phaseKey, targetSubstring, messageSubstring].
// A marker fires the first time all three match a log line (case sensitive).
// The fired timestamp is recorded under phaseKey in the phase timeline.
const MARKERS = [
  ['relay_chain_init',        'smoldot',            'Chain initialization complete for '],
  ['relay_waiting_for_block', 'sync-service-',      'Waiting for relay chain to finalize a block'],
  ['relay_runtime_ready',     'runtime-',           'Finalized block runtime ready'],
  ['para_warm_starting',      'sync-service-',      'Warm-starting parachain from restored database state'],
  ['para_head_from_relay',    'sync-service-',      'Fetched parachain finalized head from relay chain'],
  ['para_bootstrap_start',    'sync-service-',      'Bootstrapping parachain consensus from block'],
  ['para_runtime_verify',     'sync-service-',      'Verifying block-bound restored parachain runtime hint'],
  ['para_runtime_download',   'sync-service-',      'Downloading parachain runtime from peer'],
  ['para_runtime_compiled',   'sync-service-',      'Compiled '],
  ['para_consensus_restored', 'sync-service-',      'Using restored parachain consensus state'],
  ['para_consensus_bootstrap','sync-service-',      'Parachain uses Aura consensus'],
];

// Second pass: disambiguate entries whose target substring matches multiple
// chains (relay + parachain). We key on the *para* chain's sync-service
// target so that `sync-service-ksmcc3` (relay) doesn't count as a parachain
// phase. The parachain log target is the second `sync-service-` seen.
function classifyTarget(target, relayChainTarget, paraChainTarget) {
  if (target === relayChainTarget) return 'relay';
  if (target === paraChainTarget) return 'para';
  return 'unknown';
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function timeout(ms, label) {
  return new Promise((_, reject) => {
    setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
}

async function nextMessage(chain, timeoutMs, label) {
  return JSON.parse(await Promise.race([
    chain.nextJsonRpcResponse(),
    timeout(timeoutMs, label),
  ]));
}

async function rpcCall(chain, id, method, params, timeoutMs) {
  chain.sendJsonRpc(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
  while (true) {
    const message = await nextMessage(chain, timeoutMs, `${method} response`);
    if (message.id === id) {
      if (message.error) throw new Error(`${method} error: ${JSON.stringify(message.error)}`);
      return message.result;
    }
  }
}

async function startFollow(chain, id, timeoutMs) {
  chain.sendJsonRpc(JSON.stringify({
    jsonrpc: '2.0', id, method: 'chainHead_v1_follow', params: [true],
  }));
  while (true) {
    const message = await nextMessage(chain, timeoutMs, 'chainHead_v1_follow response');
    if (message.id === id) {
      if (message.error) throw new Error(`chainHead_v1_follow error: ${JSON.stringify(message.error)}`);
      return message.result;
    }
  }
}

async function waitForFinalizedDatabase(chain, idBase, label, timeoutMs) {
  const startedAt = Date.now();
  let attempt = 0;
  while (true) {
    try {
      const result = await rpcCall(
        chain, idBase + attempt,
        'chainHead_unstable_finalizedDatabase', [], RPC_TIMEOUT_MS,
      );
      const text = typeof result === 'string' ? result : '';
      if (text.length > 0) {
        return { readyMs: Date.now() - startedAt, bytes: Buffer.byteLength(text, 'utf8'), text };
      }
    } catch {
      // poll
    }
    if (Date.now() - startedAt > timeoutMs) {
      throw new Error(`${label} finalized database timed out after ${timeoutMs}ms`);
    }
    attempt += 1;
    await sleep(POLL_MS);
  }
}

async function runPhase({ name, relayDb, paraDb }) {
  const events = [];
  const phaseStartedAt = Date.now();

  const client = start({
    maxLogLevel: LOG_LEVEL,
    logCallback: (level, target, message) => {
      events.push({ at: Date.now() - phaseStartedAt, level, target, message });
      // Preserve default logging behavior so runs remain observable.
      const stream = level <= 2 ? process.stderr : process.stdout;
      stream.write(`[${target}] ${message}\n`);
    },
  });

  try {
    const relayAddStart = Date.now();
    const relay = await client.addChain({
      chainSpec: relaySpec,
      databaseContent: relayDb || '',
    });
    const relayAddMs = Date.now() - relayAddStart;

    const paraAddStart = Date.now();
    const para = await client.addChain({
      chainSpec: paraSpec,
      databaseContent: paraDb || '',
      potentialRelayChains: [relay],
    });
    const paraAddMs = Date.now() - paraAddStart;

    const [relayFollowSubscription, paraFollowSubscription] = await Promise.all([
      startFollow(relay, 10, RPC_TIMEOUT_MS),
      startFollow(para, 20, RPC_TIMEOUT_MS),
    ]);

    const [relayDatabase, paraDatabase] = await Promise.all([
      waitForFinalizedDatabase(relay, 1000, `${name}:relay`, TIMEOUT_MS),
      waitForFinalizedDatabase(para, 2000, `${name}:para`, TIMEOUT_MS),
    ]);

    return {
      totalMs: Date.now() - phaseStartedAt,
      relayAddMs,
      paraAddMs,
      relayFollowSubscription,
      paraFollowSubscription,
      relayDatabase,
      paraDatabase,
      events,
    };
  } finally {
    client.terminate();
  }
}

function extractPhases({ events, paraDbReadyMs, relayDbReadyMs, relayAddMs, paraAddMs }) {
  // Identify chain log-targets from init messages so we can classify
  // sync-service- and runtime- events to relay vs parachain.
  // Relay emits "Chain initialization complete for X."; parachain emits
  // "Parachain initialization complete for Y." — accept both.
  const initTargets = events
    .filter((e) => e.target === 'smoldot'
      && /(Chain|Parachain) initialization complete for /.test(e.message))
    .map((e) => {
      const match = e.message.match(/(?:Chain|Parachain) initialization complete for ([^.]+)\./);
      return match ? match[1].trim() : null;
    })
    .filter(Boolean);

  const relayChainId = initTargets[0];
  const paraChainId = initTargets[1];
  const relaySyncTarget = relayChainId ? `sync-service-${relayChainId}` : null;
  const paraSyncTarget = paraChainId ? `sync-service-${paraChainId}` : null;
  const relayRuntimeTarget = relayChainId ? `runtime-${relayChainId}` : null;
  const paraRuntimeTarget = paraChainId ? `runtime-${paraChainId}` : null;

  const firstMatch = (predicate) => events.find(predicate);

  const phases = {
    addChainRelayMs: relayAddMs,
    addChainParaMs: paraAddMs,
    relayChainId,
    paraChainId,
    relayWaitingMs: firstMatch((e) => e.target === relaySyncTarget
      && e.message.startsWith('Waiting for relay chain to finalize a block'))?.at ?? null,
    relayRuntimeReadyMs: firstMatch((e) => e.target === relayRuntimeTarget
      && e.message.startsWith('Finalized block runtime ready'))?.at ?? null,
    paraWarmStartingMs: firstMatch((e) => e.target === paraSyncTarget
      && e.message.startsWith('Warm-starting parachain from restored database state'))?.at ?? null,
    paraHeadFromRelayMs: firstMatch((e) => e.target === paraSyncTarget
      && e.message.startsWith('Fetched parachain finalized head from relay chain'))?.at ?? null,
    paraBootstrapStartMs: firstMatch((e) => e.target === paraSyncTarget
      && e.message.startsWith('Bootstrapping parachain consensus from block'))?.at ?? null,
    paraRuntimeVerifyMs: firstMatch((e) => e.target === paraSyncTarget
      && e.message.startsWith('Verifying block-bound restored parachain runtime hint'))?.at ?? null,
    paraRuntimeDownloadMs: firstMatch((e) => e.target === paraSyncTarget
      && e.message.startsWith('Downloading parachain runtime from peer'))?.at ?? null,
    paraRuntimeCompiledMs: firstMatch((e) => e.target === paraSyncTarget
      && e.message.startsWith('Compiled '))?.at ?? null,
    paraConsensusRestoredMs: firstMatch((e) => e.target === paraSyncTarget
      && e.message.startsWith('Using restored parachain consensus state'))?.at ?? null,
    paraConsensusBootstrapMs: firstMatch((e) => e.target === paraSyncTarget
      && e.message.startsWith('Parachain uses Aura consensus'))?.at ?? null,
    paraRuntimeReadyMs: firstMatch((e) => e.target === paraRuntimeTarget
      && e.message.startsWith('Finalized block runtime ready'))?.at ?? null,
    paraDbReadyMs,
    relayDbReadyMs,
  };

  // Derived spans (only when both endpoints exist).
  const span = (from, to) =>
    from !== null && to !== null ? to - from : null;

  phases.derived = {
    addChainTotalMs: relayAddMs + paraAddMs,
    paraBootstrapToVerifyMs: span(phases.paraBootstrapStartMs, phases.paraRuntimeVerifyMs),
    paraVerifyToCompileMs: span(phases.paraRuntimeVerifyMs, phases.paraRuntimeCompiledMs),
    paraBootstrapToCompileMs: span(phases.paraBootstrapStartMs, phases.paraRuntimeCompiledMs),
    paraCompileToRuntimeReadyMs: span(phases.paraRuntimeCompiledMs, phases.paraRuntimeReadyMs),
    paraRuntimeReadyToDbReadyMs: span(phases.paraRuntimeReadyMs, phases.paraDbReadyMs),
    // For warm path specifically:
    paraVerifyToConsensusMs: span(phases.paraRuntimeVerifyMs, phases.paraConsensusRestoredMs),
    // For cold path specifically:
    paraDownloadToBootstrappedMs: span(phases.paraRuntimeDownloadMs, phases.paraConsensusBootstrapMs),
  };

  return phases;
}

function formatTable(rows) {
  const keyWidth = Math.max(...rows.map((r) => r[0].length));
  const valWidth = Math.max(...rows.map((r) => String(r[1]).length));
  return rows
    .map(([k, v]) => `  ${k.padEnd(keyWidth)}  ${String(v).padStart(valWidth)}`)
    .join('\n');
}

function renderPhaseTable(phases) {
  const fmt = (v) => v === null || v === undefined ? '—' : `${v} ms`;
  return formatTable([
    ['addChain(relay)', fmt(phases.addChainRelayMs)],
    ['addChain(para)', fmt(phases.addChainParaMs)],
    ['relay: waiting for finalized block', fmt(phases.relayWaitingMs)],
    ['relay: runtime ready', fmt(phases.relayRuntimeReadyMs)],
    ['para: warm-starting from restored DB', fmt(phases.paraWarmStartingMs)],
    ['para: head from relay (cold path)', fmt(phases.paraHeadFromRelayMs)],
    ['para: bootstrap start', fmt(phases.paraBootstrapStartMs)],
    ['para: verifying restored runtime (warm)', fmt(phases.paraRuntimeVerifyMs)],
    ['para: downloading runtime (cold)', fmt(phases.paraRuntimeDownloadMs)],
    ['para: runtime compiled', fmt(phases.paraRuntimeCompiledMs)],
    ['para: consensus restored (warm)', fmt(phases.paraConsensusRestoredMs)],
    ['para: consensus bootstrapped (cold)', fmt(phases.paraConsensusBootstrapMs)],
    ['para: runtime service ready', fmt(phases.paraRuntimeReadyMs)],
    ['para: finalizedDatabase RPC ready', fmt(phases.paraDbReadyMs)],
    ['— derived —', ''],
    ['bootstrap → runtime compiled', fmt(phases.derived.paraBootstrapToCompileMs)],
    ['verify → compiled (warm)', fmt(phases.derived.paraVerifyToCompileMs)],
    ['compiled → runtime service ready', fmt(phases.derived.paraCompileToRuntimeReadyMs)],
    ['runtime ready → DB RPC ready', fmt(phases.derived.paraRuntimeReadyToDbReadyMs)],
  ]);
}

async function main() {
  console.log('=== COLD PHASE ===');
  const cold = await runPhase({ name: 'cold', relayDb: '', paraDb: '' });
  const coldPhases = extractPhases({
    events: cold.events,
    paraDbReadyMs: cold.totalMs,
    relayDbReadyMs: cold.relayDatabase.readyMs,
    relayAddMs: cold.relayAddMs,
    paraAddMs: cold.paraAddMs,
  });
  console.log('\n[COLD PHASE TIMELINE — ms from phase start]');
  console.log(renderPhaseTable(coldPhases));
  console.log('');

  console.log('=== WARM PHASE ===');
  const warm = await runPhase({
    name: 'warm',
    relayDb: cold.relayDatabase.text,
    paraDb: cold.paraDatabase.text,
  });
  const warmPhases = extractPhases({
    events: warm.events,
    paraDbReadyMs: warm.totalMs,
    relayDbReadyMs: warm.relayDatabase.readyMs,
    relayAddMs: warm.relayAddMs,
    paraAddMs: warm.paraAddMs,
  });
  console.log('\n[WARM PHASE TIMELINE — ms from phase start]');
  console.log(renderPhaseTable(warmPhases));
  console.log('');

  console.log('PHASES_JSON ' + JSON.stringify({
    cold: { totalMs: cold.totalMs, phases: coldPhases },
    warm: { totalMs: warm.totalMs, phases: warmPhases },
  }));
}

main().catch((error) => {
  process.stderr.write(String(error?.stack ?? error) + '\n');
  process.exitCode = 1;
});
