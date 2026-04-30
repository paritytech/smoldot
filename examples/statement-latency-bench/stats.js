// Closed set of failure categories. Mirrors bench.rs:118-129.
export const FailureKind = {
  TooManyTopics: "Too many topics",
  SubscribeFailed: "Failed to open RPC subscription",
  SubmitFailed: "Failed to submit statement via RPC",
  PropagationTimeout: "Statement propagation timeout",
  SubscriptionClosed: "Subscription closed by server",
  SubscriptionStreamError: "Subscription stream error",
  PeerFailed: "Peer failed; stopping early",
  TaskPanicked: "Task panicked",
};

// Logs the failure with bench.rs's wording and returns the kind so callers can
// `return fail(...)`. Mirrors bench.rs:148-161.
export function fail(log, clientId, roundInfo, kind, detail) {
  const prefix = roundInfo ? `Round ${roundInfo[0]}/${roundInfo[1]}: ` : "";
  log.warn(`Client ${clientId}: ${prefix}${kind} (${detail})`);
  return kind;
}

function calcStats(values) {
  const arr = Array.from(values);
  const min = arr.reduce((a, b) => Math.min(a, b), Infinity);
  const max = arr.reduce((a, b) => Math.max(a, b), -Infinity);
  const avg = arr.reduce((a, b) => a + b, 0) / arr.length;
  return { min, avg, max };
}

function f3(n) {
  return n.toFixed(3);
}

export function reportResults(log, successes, failures, numClients, numRounds) {
  if (failures.length > 0) {
    const counts = new Map();
    for (const k of failures) counts.set(k, (counts.get(k) ?? 0) + 1);
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const errorsStr = sorted.map(([k, c]) => `${k} (${c})`).join("; ");
    log.warn(
      `Benchmark Failed: failed_clients=${failures.length} total_clients=${numClients} errors=[${errorsStr}]`,
    );
  }

  if (successes.length > 0) {
    const send = calcStats(successes.map((s) => s.send_duration_secs));
    const receive = calcStats(successes.map((s) => s.receive_duration_secs));
    const latency = calcStats(successes.map((s) => s.full_latency_secs));
    log.info(
      `Benchmark Results: ` +
        `send_min=${f3(send.min)}s send_avg=${f3(send.avg)}s send_max=${f3(send.max)}s ` +
        `receive_min=${f3(receive.min)}s receive_avg=${f3(receive.avg)}s receive_max=${f3(receive.max)}s ` +
        `latency_min=${f3(latency.min)}s latency_avg=${f3(latency.avg)}s latency_max=${f3(latency.max)}s`,
    );
  }

  const roundsWithAnySuccess = new Set(successes.map((s) => s.round)).size;
  log.info(
    `Benchmark Finished: rounds_with_any_success=${roundsWithAnySuccess} ` +
      `total_rounds=${numRounds} total_clients=${numClients}`,
  );
}
