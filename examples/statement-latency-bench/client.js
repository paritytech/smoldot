import { blake2AsU8a } from "@polkadot/util-crypto";
import { u8aToHex } from "@polkadot/util";
import { encodeStatement, expiryFromParts } from "./statement.js";
import { FailureKind, fail } from "./stats.js";

// BoundedVec<Topic, ConstU32<128>> on the statement_subscribeStatement filter side.
const MAX_TOPICS = 128;

const enc = new TextEncoder();

function generateTopic(testRunId, clientId, round, msgIdx) {
  const s = `${testRunId}-${clientId}-${round}-${msgIdx}`;
  return blake2AsU8a(enc.encode(s), 256);
}

function u32LeBytes(n) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n >>> 0, true);
  return out;
}

function messagesPerClient(pattern) {
  return pattern.reduce((sum, [count]) => sum + count, 0);
}

function isLeader(clientId) {
  return clientId === 0;
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error("aborted"));
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(new Error("aborted"));
      },
      { once: true },
    );
  });
}

// Calls `fn(signal)` and aborts the signal after `ms` so the callee can
// clean up (e.g. remove its waiter from a subscription queue). Rethrows the
// callee's error as a `timeout` Error if the abort was the cause.
function withTimeout(fn, ms) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new Error("timeout")), ms);
  return Promise.resolve(fn(ctrl.signal))
    .catch((e) => {
      if (ctrl.signal.aborted) throw new Error("timeout");
      throw e;
    })
    .finally(() => clearTimeout(timer));
}

async function executeRound({ round, config, rpc, pair, log, sequenceCounter }) {
  const {
    clientId,
    neighbourId,
    numRounds,
    testRunId,
    messagesPattern,
    receiveTimeoutMs,
    statementExpiryMs,
  } = config;

  const expectedCount = messagesPerClient(messagesPattern);
  if (expectedCount > MAX_TOPICS) {
    return fail(
      log,
      clientId,
      [round, numRounds],
      FailureKind.TooManyTopics,
      `max ${MAX_TOPICS}, got ${expectedCount}`,
    );
  }

  const roundStart = performance.now();

  const expectedTopics = [];
  for (let idx = 0; idx < expectedCount; idx++) {
    expectedTopics.push(u8aToHex(generateTopic(testRunId, neighbourId, round, idx)));
  }

  let subscription;
  try {
    subscription = await rpc.subscribe("statement_subscribeStatement", [
      { matchAny: expectedTopics },
    ]);
  } catch (e) {
    return fail(
      log,
      clientId,
      [round, numRounds],
      FailureKind.SubscribeFailed,
      e.message,
    );
  }

  let sentCount = 0;
  try {
    for (const [count, size] of messagesPattern) {
      for (let i = 0; i < count; i++) {
        const topic = generateTopic(testRunId, clientId, round, sentCount);
        const channel = blake2AsU8a(u32LeBytes(sentCount), 256);
        const expiryTs = Math.floor((Date.now() + statementExpiryMs) / 1000);
        // Monotonic per-client sequence across rounds; combined with the
        // expiry timestamp this makes the (timestamp, sequence) priority key
        // unique within the statement store.
        sequenceCounter.value += 1;
        const sequence = sequenceCounter.value;
        const expiry = expiryFromParts(expiryTs, sequence);
        const data = new Uint8Array(size); // zero-filled, matching the Rust bench

        const hex = encodeStatement({ pair, expiry, channel, topic, data });

        let result;
        try {
          result = await rpc.request("statement_submit", [hex]);
        } catch (e) {
          return fail(
            log,
            clientId,
            [round, numRounds],
            FailureKind.SubmitFailed,
            e.message,
          );
        }

        sentCount += 1;
        if (isLeader(clientId)) {
          log.debug(
            `Round ${round}/${numRounds}. Sent ${sentCount} statement(s): ${JSON.stringify(result)}`,
          );
        }
      }
    }

    const sendDuration = (performance.now() - roundStart) / 1000;

    let receivedCount = 0;
    while (receivedCount < expectedCount) {
      let payload;
      try {
        payload = await withTimeout((signal) => subscription.next(signal), receiveTimeoutMs);
      } catch (e) {
        return fail(
          log,
          clientId,
          [round, numRounds],
          FailureKind.PropagationTimeout,
          `received ${receivedCount}/${expectedCount} after ${receiveTimeoutMs}ms`,
        );
      }

      if (payload === null) {
        return fail(
          log,
          clientId,
          [round, numRounds],
          FailureKind.SubscriptionClosed,
          `received ${receivedCount}/${expectedCount}`,
        );
      }

      if (payload?.event === "newStatements" && Array.isArray(payload.data?.statements)) {
        const batch = payload.data.statements.length;
        receivedCount += batch;
        if (isLeader(clientId)) {
          log.debug(
            `Round ${round}/${numRounds}. Received ${receivedCount} statement(s) (batch of ${batch})`,
          );
        }
      } else {
        return fail(
          log,
          clientId,
          [round, numRounds],
          FailureKind.SubscriptionStreamError,
          `received ${receivedCount}/${expectedCount}, unexpected payload: ${JSON.stringify(payload)}`,
        );
      }
    }

    const fullLatency = (performance.now() - roundStart) / 1000;
    const receiveDuration = fullLatency - sendDuration;

    if (isLeader(clientId)) {
      log.debug(
        `Round ${round}/${numRounds} complete. ` +
          `Send: ${sendDuration.toFixed(3)}s, ` +
          `Receive: ${receiveDuration.toFixed(3)}s, ` +
          `Total: ${fullLatency.toFixed(3)}s`,
      );
    }

    return {
      round,
      sent_count: sentCount,
      received_count: receivedCount,
      send_duration_secs: sendDuration,
      receive_duration_secs: receiveDuration,
      full_latency_secs: fullLatency,
    };
  } finally {
    try {
      await rpc.unsubscribe("statement_unsubscribeStatement", subscription.id);
    } catch (e) {
      // best-effort; if the subscription is already gone we don't care
      log.debug(`Client ${clientId}: unsubscribe failed: ${e.message}`);
    }
  }
}

export async function runClient({ config, rpc, pair, abortSignal, log }) {
  const successes = [];
  const failures = [];
  const sequenceCounter = { value: 0 };

  for (let round = 1; round <= config.numRounds; round++) {
    if (abortSignal?.aborted) {
      // Another client failed and triggered fail-fast; this client itself
      // hasn't necessarily failed, but it's cancelled.
      failures.push(FailureKind.PeerFailed);
      break;
    }

    const roundStart = performance.now();
    const result = await executeRound({ round, config, rpc, pair, log, sequenceCounter });

    if (typeof result === "string") {
      failures.push(result);
      if (config.failFast) break;
    } else {
      successes.push(result);
    }

    if (round < config.numRounds) {
      const elapsedMs = performance.now() - roundStart;
      if (elapsedMs < config.intervalMs) {
        try {
          await sleep(config.intervalMs - elapsedMs, abortSignal);
        } catch (e) {
          if (abortSignal?.aborted) {
            failures.push(FailureKind.PeerFailed);
          } else {
            failures.push(
              fail(log, config.clientId, [round, config.numRounds], FailureKind.TaskPanicked, `inter-round sleep failed: ${e.message}`),
            );
          }
          break;
        }
      } else if (isLeader(config.clientId)) {
        log.warn(
          `Client ${config.clientId}: Round ${round} took longer (${Math.round(elapsedMs)}ms) than target (${config.intervalMs}ms)`,
        );
      }
    }
  }

  return { successes, failures };
}
