// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

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
  chain.sendJsonRpc(JSON.stringify({
    jsonrpc: '2.0',
    id,
    method,
    params,
  }));

  while (true) {
    const message = await nextMessage(chain, timeoutMs, `${method} response`);
    if (message.id === id) {
      if (message.error) {
        throw new Error(`${method} error: ${JSON.stringify(message.error)}`);
      }
      return message.result;
    }
  }
}

async function startFollow(chain, id, timeoutMs) {
  chain.sendJsonRpc(JSON.stringify({
    jsonrpc: '2.0',
    id,
    method: 'chainHead_v1_follow',
    params: [true],
  }));

  while (true) {
    const message = await nextMessage(chain, timeoutMs, 'chainHead_v1_follow response');
    if (message.id === id) {
      if (message.error) {
        throw new Error(`chainHead_v1_follow error: ${JSON.stringify(message.error)}`);
      }
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
        chain,
        idBase + attempt,
        'chainHead_unstable_finalizedDatabase',
        [],
        RPC_TIMEOUT_MS,
      );
      const text = typeof result === 'string' ? result : '';
      if (text.length > 0) {
        return {
          readyMs: Date.now() - startedAt,
          bytes: Buffer.byteLength(text, 'utf8'),
          text,
        };
      }
    } catch {
      // Keep polling until the finalized database becomes available.
    }

    if (Date.now() - startedAt > timeoutMs) {
      throw new Error(`${label} finalized database timed out after ${timeoutMs}ms`);
    }

    attempt += 1;
    await sleep(POLL_MS);
  }
}

async function runPhase({ name, relayDb, paraDb }) {
  const client = start({ maxLogLevel: LOG_LEVEL });
  const phaseStartedAt = Date.now();

  try {
    const relay = await client.addChain({
      chainSpec: relaySpec,
      databaseContent: relayDb || '',
    });

    const para = await client.addChain({
      chainSpec: paraSpec,
      databaseContent: paraDb || '',
      potentialRelayChains: [relay],
    });

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
      relayFollowSubscription,
      paraFollowSubscription,
      relayDatabase,
      paraDatabase,
    };
  } finally {
    client.terminate();
  }
}

async function main() {
  const cold = await runPhase({ name: 'cold', relayDb: '', paraDb: '' });
console.log(`COLD_SUMMARY ${JSON.stringify({
  totalMs: cold.totalMs,
  relayFollowSubscription: cold.relayFollowSubscription,
  paraFollowSubscription: cold.paraFollowSubscription,
  relayDbReadyMs: cold.relayDatabase.readyMs,
  paraDbReadyMs: cold.paraDatabase.readyMs,
  relayDbBytes: cold.relayDatabase.bytes,
    paraDbBytes: cold.paraDatabase.bytes,
  })}`);

  const warm = await runPhase({
    name: 'warm',
    relayDb: cold.relayDatabase.text,
    paraDb: cold.paraDatabase.text,
  });
console.log(`WARM_SUMMARY ${JSON.stringify({
  totalMs: warm.totalMs,
  relayFollowSubscription: warm.relayFollowSubscription,
  paraFollowSubscription: warm.paraFollowSubscription,
  relayDbReadyMs: warm.relayDatabase.readyMs,
  paraDbReadyMs: warm.paraDatabase.readyMs,
    relayDbBytes: warm.relayDatabase.bytes,
    paraDbBytes: warm.paraDatabase.bytes,
    relayReadyRatio: Number((warm.relayDatabase.readyMs / cold.relayDatabase.readyMs).toFixed(3)),
    paraReadyRatio: Number((warm.paraDatabase.readyMs / cold.paraDatabase.readyMs).toFixed(3)),
  })}`);
}

main().catch((error) => {
  process.stderr.write(String(error?.stack ?? error) + '\n');
  process.exitCode = 1;
});
