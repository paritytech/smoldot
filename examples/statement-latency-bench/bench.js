#!/usr/bin/env node
import { parseArgs } from "node:util";
import { randomBytes } from "node:crypto";
import { start } from "smoldot";
import { loadChainSpec, spliceBootnodes } from "./chainspec.js";
import { getKeypair } from "./keypair.js";
import { SmoldotRpc } from "./smoldot-rpc.js";
import { runClient } from "./client.js";
import { FailureKind, fail, reportResults } from "./stats.js";

const LEVEL = { ERROR: 1, WARN: 2, INFO: 3, DEBUG: 4, TRACE: 5 };
const LEVEL_LABEL = { 1: "ERROR", 2: "WARN", 3: "INFO", 4: "DEBUG", 5: "TRACE" };

function makeLogger(maxLevel) {
  const emit = (lvl, msg) => {
    if (lvl > maxLevel) return;
    const stream = lvl <= LEVEL.WARN ? process.stderr : process.stdout;
    stream.write(`[${LEVEL_LABEL[lvl]}] ${msg}\n`);
  };
  return {
    error: (msg) => emit(LEVEL.ERROR, msg),
    warn: (msg) => emit(LEVEL.WARN, msg),
    info: (msg) => emit(LEVEL.INFO, msg),
    debug: (msg) => emit(LEVEL.DEBUG, msg),
    trace: (msg) => emit(LEVEL.TRACE, msg),
    forSmoldot: (lvl, target, message) => emit(lvl, `[${target}] ${message}`),
  };
}

function parseMessagesPattern(pattern) {
  return pattern.split(",").map((part) => {
    const [c, s] = part.trim().split(":");
    if (c === undefined || s === undefined) {
      throw new Error(`Invalid pattern '${part}'. Expected 'count:size'`);
    }
    const count = Number.parseInt(c, 10);
    const size = Number.parseInt(s, 10);
    if (!Number.isFinite(count) || !Number.isFinite(size)) {
      throw new Error(`Invalid count/size in pattern '${part}'`);
    }
    return [count, size];
  });
}

function parseFlags(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      "chain-spec": { type: "string" },
      "relay-chain-spec": { type: "string" },
      bootnodes: { type: "string" },
      "false-positive-rate": { type: "string", default: "0.01" },
      "num-clients": { type: "string", default: "100" },
      "num-rounds": { type: "string", default: "1" },
      "messages-pattern": { type: "string", default: "5:512" },
      "receive-timeout-ms": { type: "string", default: "5000" },
      "interval-ms": { type: "string", default: "10000" },
      "statement-expiry-ms": { type: "string", default: "600000" },
      "warmup-ms": { type: "string", default: "15000" },
      "fail-fast": { type: "boolean", default: false },
      "log-level": { type: "string", default: "info" },
    },
    strict: true,
  });

  if (!values["chain-spec"]) {
    throw new Error("--chain-spec is required");
  }

  const numClients = Number.parseInt(values["num-clients"], 10);
  const numRounds = Number.parseInt(values["num-rounds"], 10);
  if (!(numClients > 0)) throw new Error(`--num-clients must be > 0`);
  if (!(numRounds > 0)) throw new Error(`--num-rounds must be > 0`);

  return {
    chainSpecPath: values["chain-spec"],
    relayChainSpecPath: values["relay-chain-spec"],
    bootnodes: values.bootnodes ? values.bootnodes.split(",").map((b) => b.trim()).filter(Boolean) : [],
    falsePositiveRate: Number.parseFloat(values["false-positive-rate"]),
    numClients,
    numRounds,
    messagesPattern: parseMessagesPattern(values["messages-pattern"]),
    receiveTimeoutMs: Number.parseInt(values["receive-timeout-ms"], 10),
    intervalMs: Number.parseInt(values["interval-ms"], 10),
    statementExpiryMs: Number.parseInt(values["statement-expiry-ms"], 10),
    warmupMs: Number.parseInt(values["warmup-ms"], 10),
    failFast: values["fail-fast"],
    logLevel: LEVEL[values["log-level"].toUpperCase()] ?? LEVEL.INFO,
  };
}

function logConfiguration(log, args) {
  const pattern = args.messagesPattern.map(([c, s]) => `${c}x${s}B`).join(", ");
  log.info(
    `Starting Statement Store Latency Benchmark: ` +
      `chain_spec=${args.chainSpecPath} ` +
      (args.relayChainSpecPath ? `relay_chain_spec=${args.relayChainSpecPath} ` : "") +
      `bootnodes=${args.bootnodes.length} ` +
      `clients=${args.numClients} rounds=${args.numRounds} ` +
      `interval=${args.intervalMs}ms pattern=[${pattern}]`,
  );
}

async function spawnClient({ clientId, args, parachainSpec, relaySpec, log }) {
  const smoldot = start({
    maxLogLevel: 3,
    logCallback: (lvl, target, msg) => log.forSmoldot(lvl, target, msg),
  });

  const chains = [];
  let relayChain = null;
  if (relaySpec) {
    relayChain = await smoldot.addChain({ chainSpec: relaySpec, disableJsonRpc: true });
    chains.push(relayChain);
  }

  const parachain = await smoldot.addChain({
    chainSpec: parachainSpec,
    potentialRelayChains: relayChain ? [relayChain] : [],
    statementStore: { falsePositiveRate: args.falsePositiveRate },
  });
  chains.push(parachain);

  const rpc = new SmoldotRpc(parachain, {
    onUnexpected: (e) => log.warn(`client ${clientId} rpc: ${e.message}`),
  });

  return {
    smoldot,
    chains,
    rpc,
    cleanup: async () => {
      rpc.stop();
      try {
        for (const c of chains) c.remove();
      } catch {}
      try {
        await smoldot.terminate();
      } catch {}
    },
  };
}

async function main() {
  let args;
  try {
    args = parseFlags(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`Error: ${e.message}\n`);
    process.exit(2);
  }

  const log = makeLogger(args.logLevel);
  const testRunId = randomBytes(8).readBigUInt64LE(0).toString();

  logConfiguration(log, args);

  const parachainSpecRaw = await loadChainSpec(args.chainSpecPath);
  const parachainSpec = spliceBootnodes(parachainSpecRaw, args.bootnodes);
  const relaySpec = args.relayChainSpecPath ? await loadChainSpec(args.relayChainSpecPath) : null;

  log.info(`Spawning ${args.numClients} client tasks... ${testRunId}`);

  const abortController = new AbortController();
  const handles = [];
  for (let clientId = 0; clientId < args.numClients; clientId++) {
    handles.push((async () => {
      let resources;
      try {
        resources = await spawnClient({ clientId, args, parachainSpec, relaySpec, log });
      } catch (e) {
        return {
          successes: [],
          failures: [
            fail(log, clientId, null, FailureKind.TaskPanicked, `failed to start smoldot: ${e.message}`),
          ],
        };
      }

      try {
        const pair = await getKeypair(clientId);
        const config = {
          clientId,
          neighbourId: (clientId + 1) % args.numClients,
          numClients: args.numClients,
          numRounds: args.numRounds,
          testRunId,
          messagesPattern: args.messagesPattern,
          receiveTimeoutMs: args.receiveTimeoutMs,
          intervalMs: args.intervalMs,
          statementExpiryMs: args.statementExpiryMs,
          failFast: args.failFast,
        };

        // Best-effort warm-up: smoldot has no JSON-RPC signal for "I have a
        // statement-store peer". A fixed sleep is a coarse heuristic; tune via
        // --warmup-ms per network.
        await new Promise((r) => setTimeout(r, args.warmupMs));

        const result = await runClient({
          config,
          rpc: resources.rpc,
          pair,
          abortSignal: abortController.signal,
          log,
        });

        if (args.failFast && result.failures.length > 0) {
          abortController.abort();
        }

        return result;
      } catch (e) {
        return {
          successes: [],
          failures: [
            fail(log, clientId, null, FailureKind.TaskPanicked, e?.message ?? String(e)),
          ],
        };
      } finally {
        await resources.cleanup();
      }
    })());
  }

  const results = await Promise.all(handles);
  const allSuccesses = [];
  const allFailures = [];
  for (const r of results) {
    allSuccesses.push(...r.successes);
    allFailures.push(...r.failures);
  }

  reportResults(log, allSuccesses, allFailures, args.numClients, args.numRounds);

  if (allFailures.length > 0 && allSuccesses.length === 0) {
    process.exit(1);
  }
}

main().catch((e) => {
  process.stderr.write(`fatal: ${e?.stack ?? e}\n`);
  process.exit(1);
});
