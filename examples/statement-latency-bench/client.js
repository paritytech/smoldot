import { blake2AsU8a } from "@polkadot/util-crypto";
import { u8aToHex } from "@polkadot/util";
import { decodeStatement, encodePayload, encodeStatement, expiryFromParts } from "./statement.js";
import { FailureKind, fail } from "./stats.js";

// BoundedVec<Topic, ConstU32<128>> on the statement_subscribeStatement filter side.
const MAX_TOPICS = 128;

const enc = new TextEncoder();

// Topic of message `msgIdx` of a client. It depends on the round only with --topics-per-round.
function generateTopic(config, clientId, round, msgIdx) {
  const s = config.topicsPerRound
    ? `${config.testRunId}-${clientId}-${round}-${msgIdx}`
    : `${config.testRunId}-${clientId}-${msgIdx}`;
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

// Collects the statements of the neighbour that arrive on one subscription, by round and
// message index. Without a subscription it stays empty, which stands for a failed subscribe.
class Receiver {
  constructor({ subscription, topics, clientId, log, error = null }) {
    this.subscription = subscription;
    this.topics = topics;
    this.clientId = clientId;
    this.log = log;
    this.byRound = new Map(); // round -> Set of message indexes
    this.seenIdx = new Set();
    // Failure kind and detail once the subscription can deliver nothing more.
    this.error = error;
    this.wake = null;
    if (subscription) this.#pump();
  }

  countRound(round) {
    return this.byRound.get(round)?.size ?? 0;
  }

  // Resolves once `expected` statements of `round` arrived, the subscription ended, or
  // `timeoutMs` passed.
  async waitRound(round, expected, timeoutMs) {
    const deadline = performance.now() + timeoutMs;
    while (this.countRound(round) < expected && !this.error) {
      const left = deadline - performance.now();
      if (left <= 0) break;
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, left);
        this.wake = () => {
          clearTimeout(timer);
          resolve();
        };
      });
    }
  }

  async #pump() {
    for (;;) {
      const payload = await this.subscription.next();
      if (payload === null) {
        this.error ??= [FailureKind.SubscriptionClosed, "subscription closed"];
      } else if (payload?.event === "newStatements" && Array.isArray(payload.data?.statements)) {
        for (const hex of payload.data.statements) this.#record(hex);
      } else {
        this.error = [
          FailureKind.SubscriptionStreamError,
          `unexpected payload: ${JSON.stringify(payload)}`,
        ];
      }
      this.wake?.();
      if (this.error) return;
    }
  }

  #record(hex) {
    let statement;
    try {
      statement = decodeStatement(hex);
    } catch (e) {
      this.log.warn(`Client ${this.clientId}: undecodable statement: ${e.message}`);
      return;
    }
    const { topic, round, msgIdx } = statement;
    if (this.topics[msgIdx] !== topic) {
      this.log.warn(`Client ${this.clientId}: statement on a foreign topic ${topic}`);
      return;
    }
    let indexes = this.byRound.get(round);
    if (!indexes) this.byRound.set(round, (indexes = new Set()));
    if (indexes.has(msgIdx)) return;
    indexes.add(msgIdx);
    this.seenIdx.add(msgIdx);
  }
}

// Subscribes to the topics that the neighbour uses in `round`. A failed subscribe is logged and
// gives a receiver that stays empty and carries the failure.
async function openReceiver({ config, rpc, round, log }) {
  const { clientId, neighbourId, numRounds, messagesPattern } = config;
  const expectedCount = messagesPerClient(messagesPattern);
  const roundInfo = config.topicsPerRound ? [round, numRounds] : null;

  const topics = [];
  for (let idx = 0; idx < expectedCount; idx++) {
    topics.push(u8aToHex(generateTopic(config, neighbourId, round, idx)));
  }
  const failed = (kind, detail) => {
    const error = [fail(log, clientId, roundInfo, kind, detail), detail];
    return new Receiver({ subscription: null, topics, clientId, log, error });
  };

  if (expectedCount > MAX_TOPICS) {
    return failed(FailureKind.TooManyTopics, `max ${MAX_TOPICS}, got ${expectedCount}`);
  }
  try {
    const subscription = await rpc.subscribe("statement_subscribeStatement", [
      { matchAny: topics },
    ]);
    return new Receiver({ subscription, topics, clientId, log });
  } catch (e) {
    return failed(FailureKind.SubscribeFailed, e.message);
  }
}

async function closeReceiver({ receiver, rpc, config, log }) {
  if (!receiver.subscription) return;
  try {
    await rpc.unsubscribe("statement_unsubscribeStatement", receiver.subscription.id);
  } catch (e) {
    // best-effort; if the subscription is already gone we don't care
    log.debug(`Client ${config.clientId}: unsubscribe failed: ${e.message}`);
  }
}

// Adds the statements that `receiver` expected and got in `rounds` to the delivery record.
function addDelivery(delivery, receiver, rounds) {
  const expectedCount = receiver.topics.length;
  for (const round of rounds) {
    const got = receiver.countRound(round);
    delivery.expected += expectedCount;
    delivery.arrived += got;
    if (got < expectedCount) delivery.gaps.push([round, expectedCount - got]);
  }
  if (rounds.length === 0) return;
  for (let idx = 0; idx < expectedCount; idx++) {
    if (!receiver.seenIdx.has(idx)) delivery.silentTopics.push(receiver.topics[idx]);
  }
}

// Work of a client before round 1. Without --topics-per-round it opens the subscription that
// the client keeps for the whole run.
export async function prepareClient({ config, rpc, log }) {
  if (config.topicsPerRound) return {};
  return { receiver: await openReceiver({ config, rpc, round: 0, log }) };
}

async function executeRound({ round, config, rpc, pair, log, sequenceCounter, receiver }) {
  const { clientId, numRounds, messagesPattern, receiveTimeoutMs, statementExpiryMs } = config;

  const expectedCount = messagesPerClient(messagesPattern);
  const roundStart = performance.now();

  let sentCount = 0;
  for (const [count, size] of messagesPattern) {
    for (let i = 0; i < count; i++) {
      const topic = generateTopic(config, clientId, round, sentCount);
      // With fixed topics a statement has no channel, so that the statement of a later round
      // does not replace it. It stays in the stores until its expiry and can still arrive late.
      const channel = config.topicsPerRound ? blake2AsU8a(u32LeBytes(sentCount), 256) : undefined;
      const expiryTs = Math.floor((Date.now() + statementExpiryMs) / 1000);
      // Monotonic per-client sequence across rounds; combined with the
      // expiry timestamp this makes the (timestamp, sequence) priority key
      // unique within the statement store.
      sequenceCounter.value += 1;
      const sequence = sequenceCounter.value;
      const expiry = expiryFromParts(expiryTs, sequence);
      const data = encodePayload(round, sentCount, size);

      const hex = encodeStatement({ pair, expiry, channel, topic, data });

      let result;
      try {
        result = await rpc.request("statement_submit", [hex]);
        if (result?.status !== "new") throw new Error(JSON.stringify(result));
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
      if (config.isLeader) {
        log.debug(
          `Round ${round}/${numRounds}. Sent ${sentCount} statement(s): ${JSON.stringify(result)}`,
        );
      }
    }
  }

  const sendDuration = (performance.now() - roundStart) / 1000;

  await receiver.waitRound(round, expectedCount, receiveTimeoutMs);
  const receivedCount = receiver.countRound(round);
  if (receivedCount < expectedCount) {
    const [kind, detail] = receiver.error ?? [
      FailureKind.PropagationTimeout,
      `after ${receiveTimeoutMs}ms`,
    ];
    return fail(
      log,
      clientId,
      [round, numRounds],
      kind,
      `received ${receivedCount}/${expectedCount}, ${detail}`,
    );
  }

  const fullLatency = (performance.now() - roundStart) / 1000;
  const receiveDuration = fullLatency - sendDuration;

  if (config.isLeader) {
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
}

// Delivery record of a client that expected `rounds` rounds and received nothing.
export function emptyDelivery(config, rounds = 0) {
  return {
    clientId: config.clientId,
    expected: rounds * messagesPerClient(config.messagesPattern),
    arrived: 0,
    // Statements that arrived after the receive timeout of their round.
    late: 0,
    silentTopics: [],
    // [round, missing statements] for every round with a loss.
    gaps: [],
  };
}

export async function runClient({ config, rpc, pair, abortSignal, log, prepared }) {
  const successes = [];
  const failures = [];
  const sequenceCounter = { value: 0 };
  const delivery = emptyDelivery(config);
  // Statements counted at the end of their own round.
  let arrivedInTime = 0;
  const roundsRun = [];

  for (let round = 1; round <= config.numRounds; round++) {
    if (abortSignal?.aborted) {
      // Another client failed and triggered fail-fast; this client itself
      // hasn't necessarily failed, but it's cancelled.
      failures.push(FailureKind.PeerFailed);
      break;
    }

    const roundStart = performance.now();
    roundsRun.push(round);
    const receiver = prepared.receiver ?? (await openReceiver({ config, rpc, round, log }));
    const result = receiver.subscription
      ? await executeRound({ round, config, rpc, pair, log, sequenceCounter, receiver })
      : receiver.error[0];
    arrivedInTime += receiver.countRound(round);
    if (config.topicsPerRound) {
      // Counted before the unsubscribe, which could let a statement in after the timeout.
      addDelivery(delivery, receiver, [round]);
      await closeReceiver({ receiver, rpc, config, log });
    }

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
      } else if (config.isLeader) {
        log.warn(
          `Client ${config.clientId}: Round ${round} took longer (${Math.round(elapsedMs)}ms) than target (${config.intervalMs}ms)`,
        );
      }
    }
  }

  if (prepared.receiver) {
    await closeReceiver({ receiver: prepared.receiver, rpc, config, log });
    addDelivery(delivery, prepared.receiver, roundsRun);
  }
  delivery.late = delivery.arrived - arrivedInTime;

  return { successes, failures, delivery };
}
