#!/usr/bin/env node
import { parseArgs } from "node:util";
import { randomBytes } from "node:crypto";
import { fork } from "node:child_process";
import { fileURLToPath } from "node:url";
import { start } from "smoldot";
import { loadChainSpec } from "./chainspec.js";
import { getKeypair } from "./keypair.js";
import { SmoldotRpc } from "./smoldot-rpc.js";
import { runClient } from "./client.js";
import { FailureKind, fail, reportResults } from "./stats.js";

const LEVEL = { ERROR: 1, WARN: 2, INFO: 3, DEBUG: 4, TRACE: 5 };
const LEVEL_LABEL = { 1: "ERROR", 2: "WARN", 3: "INFO", 4: "DEBUG", 5: "TRACE" };

function makeLogger(maxLevel, prefix = "") {
  const emit = (lvl, msg) => {
    if (lvl > maxLevel) return;
    const stream = lvl <= LEVEL.WARN ? process.stderr : process.stdout;
    stream.write(`${prefix}[${LEVEL_LABEL[lvl]}] ${msg}\n`);
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
      "parachain-spec": { type: "string" },
      "relay-chain-spec": { type: "string" },
      "false-positive-rate": { type: "string", default: "0.01" },
      "num-clients": { type: "string", default: "100" },
      "num-rounds": { type: "string", default: "1" },
      "messages-pattern": { type: "string", default: "5:512" },
      "receive-timeout-ms": { type: "string", default: "5000" },
      "interval-ms": { type: "string", default: "10000" },
      "statement-expiry-ms": { type: "string", default: "600000" },
      "warmup-ms": { type: "string", default: "15000" },
      workers: { type: "string", default: "1" },
      "fail-fast": { type: "boolean", default: false },
      "log-level": { type: "string", default: "info" },
    },
    strict: true,
  });

  if (!values["parachain-spec"]) {
    throw new Error("--parachain-spec is required");
  }
  if (!values["relay-chain-spec"]) {
    throw new Error("--relay-chain-spec is required");
  }

  const numClients = Number.parseInt(values["num-clients"], 10);
  const numRounds = Number.parseInt(values["num-rounds"], 10);
  const workers = Number.parseInt(values["workers"], 10);
  if (!(numClients > 0)) throw new Error(`--num-clients must be > 0`);
  if (!(numRounds > 0)) throw new Error(`--num-rounds must be > 0`);
  if (!(workers > 0)) throw new Error(`--workers must be > 0`);
  if (workers > numClients) throw new Error(`--workers (${workers}) cannot exceed --num-clients (${numClients})`);

  return {
    parachainSpecSource: values["parachain-spec"],
    relayChainSpecSource: values["relay-chain-spec"],
    falsePositiveRate: Number.parseFloat(values["false-positive-rate"]),
    numClients,
    numRounds,
    workers,
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
      `parachain_spec=${args.parachainSpecSource} ` +
      `relay_chain_spec=${args.relayChainSpecSource} ` +
      `clients=${args.numClients} rounds=${args.numRounds} ` +
      `workers=${args.workers} ` +
      `interval=${args.intervalMs}ms pattern=[${pattern}]`,
  );
}

async function spawnClient({ clientId, args, parachainSpec, relaySpec, log }) {
  const debugClientId =
    process.env.BENCH_DEBUG_CLIENT !== undefined
      ? Number.parseInt(process.env.BENCH_DEBUG_CLIENT, 10)
      : null;
  const isDebugClient = debugClientId !== null && debugClientId === clientId;

  const smoldot = start({
    maxLogLevel: isDebugClient ? 4 : 2,
    logCallback: (lvl, target, msg) => {
      if (isDebugClient) {
        log.forSmoldot(lvl, `c${clientId}/${target}`, msg);
        return;
      }
      if (
        target.startsWith("json-rpc-") &&
        msg.includes("statement_subscribeStatement")
      )
        return;
      if (
        target.startsWith("sync-service-") &&
        msg.startsWith("Error while verifying justification")
      )
        return;
      log.forSmoldot(lvl, target, msg);
    },
  });

  const relayChain = await smoldot.addChain({ chainSpec: relaySpec, disableJsonRpc: true });
  const parachain = await smoldot.addChain({
    chainSpec: parachainSpec,
    potentialRelayChains: [relayChain],
    statementStore: { falsePositiveRate: args.falsePositiveRate },
  });
  const chains = [relayChain, parachain];

  const rpc = new SmoldotRpc(parachain, {
    onUnexpected: (e) => log.warn(`client ${clientId} rpc: ${e.message}`),
  });

  // Optional periodic peer-health probe per client. Enable with
  // BENCH_HEALTH_INTERVAL_MS=<ms>. Useful to compare succeeding vs
  // failing clients' connectivity over the run.
  const healthIntervalMs = Number.parseInt(
    process.env.BENCH_HEALTH_INTERVAL_MS ?? "0",
    10,
  );
  let healthTimer = null;
  if (healthIntervalMs > 0) {
    healthTimer = setInterval(async () => {
      try {
        const h = await rpc.request("system_health", []);
        log.info(
          `client ${clientId} health: peers=${h.peers} syncing=${h.isSyncing} shouldHavePeers=${h.shouldHavePeers}`,
        );
      } catch (e) {
        log.warn(`client ${clientId} health probe failed: ${e.message}`);
      }
    }, healthIntervalMs);
  }

  return {
    smoldot,
    chains,
    rpc,
    cleanup: async () => {
      if (healthTimer) clearInterval(healthTimer);
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

// Run a contiguous range [clientStart, clientEnd) of clients in this process.
// Used both by single-process mode (range = [0, numClients)) and by each
// child worker.
//
// `barrier` synchronises the start of round 1 across all clients (and across
// workers when multi-worker). After warmup each client calls `barrier.arrive()`
// then awaits `barrier.waitStart()` before entering the round loop. Subsequent
// rounds are paced independently by `intervalMs` in `runClient`.
async function runWorker({ args, clientStart, clientEnd, testRunId, log, barrier }) {
  const [parachainSpec, relaySpec] = await Promise.all([
    loadChainSpec(args.parachainSpecSource),
    loadChainSpec(args.relayChainSpecSource),
  ]);

  const abortController = new AbortController();
  const handles = [];

  for (let clientId = clientStart; clientId < clientEnd; clientId++) {
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

        // Synchronise round 1 across all clients globally. Without this each
        // client enters round 1 as soon as its own warmup completes, drifts on
        // round-1 receive timeouts, and senders end up emitting statements for
        // round N+k while receivers are still subscribed for round N.
        barrier.arrive();
        await barrier.waitStart();

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
  const successes = [];
  const failures = [];
  for (const r of results) {
    successes.push(...r.successes);
    failures.push(...r.failures);
  }
  return { successes, failures };
}

// Compute [start, end) for worker `i` of `total`, splitting `n` clients
// evenly with the remainder distributed across the first `n % total` workers.
function workerRange(i, total, n) {
  const base = Math.floor(n / total);
  const rem = n % total;
  const start = i * base + Math.min(i, rem);
  const size = base + (i < rem ? 1 : 0);
  return [start, start + size];
}

// Barrier that releases once all `expected` participants have arrived. In
// multi-worker mode, the parent uses one of these to gate the children, and
// each child uses one of these locally over its own clients before reporting
// "ready" up to the parent.
function makeBarrier(expected, onAllArrived) {
  let arrived = 0;
  let releaseStart;
  const startPromise = new Promise((r) => { releaseStart = r; });
  return {
    arrive: () => {
      arrived += 1;
      if (arrived === expected && onAllArrived) onAllArrived();
    },
    waitStart: () => startPromise,
    release: () => releaseStart(),
  };
}

async function runAsParent(args, log) {
  const testRunId = randomBytes(8).readBigUInt64LE(0).toString();
  logConfiguration(log, args);
  log.info(`Spawning ${args.numClients} client tasks... ${testRunId}`);

  if (args.workers === 1) {
    const barrier = makeBarrier(args.numClients, () => {
      log.info(`All ${args.numClients} clients ready; starting round 1`);
      barrier.release();
    });
    const { successes, failures } = await runWorker({
      args,
      clientStart: 0,
      clientEnd: args.numClients,
      testRunId,
      log,
      barrier,
    });
    reportResults(log, successes, failures, args.numClients, args.numRounds);
    process.exit(failures.length > 0 && successes.length === 0 ? 1 : 0);
  }

  // Multi-worker: fork one child process per worker. Each child runs its own
  // event loop and its own slice of clients in-process.
  const selfPath = fileURLToPath(import.meta.url);
  const childResults = [];

  const childProcs = [];
  const childPromises = [];
  // Round-1 barrier across workers: each child sends `worker-ready` once all
  // its local clients have warmed up; once every child has reported, the
  // parent broadcasts `start` and all clients begin round 1 simultaneously.
  const workerBarrier = makeBarrier(args.workers, () => {
    log.info(`All ${args.workers} workers ready; starting round 1`);
    for (const c of childProcs) c.send({ type: "start" });
  });
  for (let i = 0; i < args.workers; i++) {
    const [start, end] = workerRange(i, args.workers, args.numClients);
    log.info(`Forking worker ${i + 1}/${args.workers}: clients [${start}, ${end})`);
    const child = fork(selfPath, process.argv.slice(2), {
      env: {
        ...process.env,
        BENCH_WORKER_ID: String(i),
        BENCH_WORKER_COUNT: String(args.workers),
        BENCH_TEST_RUN_ID: testRunId,
        BENCH_CLIENT_START: String(start),
        BENCH_CLIENT_END: String(end),
      },
      stdio: ["inherit", "inherit", "inherit", "ipc"],
    });
    childProcs.push(child);

    childPromises.push(
      new Promise((resolve, reject) => {
        let result = null;
        child.on("message", (msg) => {
          if (!msg) return;
          if (msg.type === "worker-ready") workerBarrier.arrive();
          else if (msg.type === "result") result = msg;
        });
        child.on("exit", (code) => {
          if (result) {
            childResults.push(result);
            resolve();
          } else {
            reject(new Error(`worker ${i} exited with code ${code} without sending a result`));
          }
        });
        child.on("error", reject);
      }),
    );
  }

  // If any worker fails, kill the rest so they don't outlive the parent
  // holding smoldot peers / sockets.
  try {
    await Promise.all(childPromises);
  } catch (e) {
    for (const c of childProcs) {
      if (c.exitCode === null && c.signalCode === null) {
        try { c.kill("SIGTERM"); } catch {}
      }
    }
    await Promise.allSettled(childPromises);
    throw e;
  }

  const successes = [];
  const failures = [];
  for (const r of childResults) {
    successes.push(...r.successes);
    failures.push(...r.failures);
  }
  reportResults(log, successes, failures, args.numClients, args.numRounds);
  process.exit(failures.length > 0 && successes.length === 0 ? 1 : 0);
}

async function runAsChild(args) {
  const workerId = Number.parseInt(process.env.BENCH_WORKER_ID, 10);
  const clientStart = Number.parseInt(process.env.BENCH_CLIENT_START, 10);
  const clientEnd = Number.parseInt(process.env.BENCH_CLIENT_END, 10);
  const testRunId = process.env.BENCH_TEST_RUN_ID;

  const log = makeLogger(args.logLevel, `[w${workerId}] `);

  // Local barrier across this worker's clients: when all have warmed up, tell
  // the parent. Then wait for the parent's `start` broadcast (issued once
  // every worker has reported ready) and release the local clients.
  const localCount = clientEnd - clientStart;
  const barrier = makeBarrier(localCount, () => {
    process.send({ type: "worker-ready" });
  });
  process.on("message", (msg) => {
    if (msg && msg.type === "start") barrier.release();
  });

  const { successes, failures } = await runWorker({
    args,
    clientStart,
    clientEnd,
    testRunId,
    log,
    barrier,
  });

  if (typeof process.send === "function") {
    await new Promise((resolve) =>
      process.send({ type: "result", successes, failures }, undefined, undefined, resolve),
    );
  }
  process.exit(0);
}

async function main() {
  let args;
  try {
    args = parseFlags(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`Error: ${e.message}\n`);
    process.exit(2);
  }

  if (process.env.BENCH_WORKER_ID !== undefined) {
    await runAsChild(args);
    return;
  }

  const log = makeLogger(args.logLevel);
  await runAsParent(args, log);
}

main().catch((e) => {
  process.stderr.write(`fatal: ${e?.stack ?? e}\n`);
  process.exit(1);
});
