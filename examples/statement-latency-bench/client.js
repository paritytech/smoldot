import { blake2AsU8a } from "@polkadot/util-crypto";
import { u8aToHex } from "@polkadot/util";
import { encodeStatement, expiryFromParts } from "./statement.js";
import { FailureKind, fail } from "./stats.js";

const MAX_TOPICS = 128; // bench.rs:249 — BoundedVec<Topic, ConstU32<128>> on the subscribe side

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

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("timeout")), ms);
  });
  return Promise.race([promise.then((v) => v), timeout]).finally(() =>
    clearTimeout(timer),
  );
}

async function executeRound({ round, config, rpc, pair, log }) {
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
        const sequence = (sentCount + 1) * round;
        const expiry = expiryFromParts(expiryTs, sequence);
        const data = new Uint8Array(size); // zero-filled; bench.rs:283 does the same

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
        payload = await withTimeout(subscription.next(), receiveTimeoutMs);
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
    } catch {
      // best-effort; if the subscription is already gone we don't care
    }
  }
}

export async function runClient({ config, rpc, pair, abortSignal, log }) {
  const successes = [];
  const failures = [];

  // Apply jitter to distribute submission load (bench.rs:423-424).
  const submissionJitter = (config.clientId * 7) % 1000;
  await sleep(submissionJitter, abortSignal).catch(() => {});

  for (let round = 1; round <= config.numRounds; round++) {
    if (abortSignal?.aborted) {
      failures.push(FailureKind.PeerFailed);
      break;
    }

    const roundStart = performance.now();
    const result = await executeRound({ round, config, rpc, pair, log });

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
        } catch {
          failures.push(FailureKind.PeerFailed);
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
