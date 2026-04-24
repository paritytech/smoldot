// Single cold-startup measurement. Spawned as a fresh Node subprocess per
// iteration by the Rust bench runner. Prints exactly one line of the form:
//   RESULT {"initialized_ms":<number>}
// and exits 0 on success, non-zero on any failure.
//
// Measured window: `performance.now()` just before `start()` through the first
// chainHead_v1_follow notification with event === "initialized".
//
// Env vars:
//   RELAY_CHAIN_SPEC   path to relay chain spec (required)
//   PARA_CHAIN_SPEC    path to parachain chain spec (optional — omit for relay-only)
//   TARGET             "relay" | "para" (default: "para" if PARA_CHAIN_SPEC set, else "relay")
//   WITH_RUNTIME       "true" | "false" (default: "true")
//   TIMEOUT_MS         overall timeout (default: 120000)
//   SMOLDOT_LOG_LEVEL  smoldot maxLogLevel (default: 2 — warnings only)

import * as fs from "node:fs";
import { start } from "smoldot";

const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const paraSpecPath = process.env.PARA_CHAIN_SPEC || "";
const target = process.env.TARGET || (paraSpecPath ? "para" : "relay");
const withRuntime = (process.env.WITH_RUNTIME || "true") === "true";
const timeoutMs = Number.parseInt(process.env.TIMEOUT_MS || "120000", 10);

if (!relaySpecPath) {
  console.error("RELAY_CHAIN_SPEC is required");
  process.exit(1);
}
if (target === "para" && !paraSpecPath) {
  console.error("TARGET=para requires PARA_CHAIN_SPEC");
  process.exit(1);
}

const relaySpec = fs.readFileSync(relaySpecPath, "utf8");
const paraSpec = paraSpecPath ? fs.readFileSync(paraSpecPath, "utf8") : null;

// Mark the start just before handing control to smoldot. Reading chain-spec
// files off disk is excluded — that is not what we are benchmarking.
const tStart = performance.now();

const client = start({
  maxLogLevel: Number.parseInt(process.env.SMOLDOT_LOG_LEVEL || "2", 10),
  logCallback: (level, t, m) => {
    const labels = { 1: "ERROR", 2: "WARN", 3: "INFO", 4: "DEBUG", 5: "TRACE" };
    console.error(`[${labels[level] ?? `L${level}`}] [${t}] ${m}`);
  },
});

let exitCode = 1;
try {
  const relay = await client.addChain({ chainSpec: relaySpec });
  const chain =
    target === "relay"
      ? relay
      : await client.addChain({
          chainSpec: paraSpec,
          potentialRelayChains: [relay],
        });

  const followReqId = "1";
  chain.sendJsonRpc(
    JSON.stringify({
      jsonrpc: "2.0",
      id: followReqId,
      method: "chainHead_v1_follow",
      params: [withRuntime],
    }),
  );

  // Drain responses until we see an "initialized" notification for our
  // subscription. `subId` is set once the follow response arrives.
  let subId = null;
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const remaining = deadline - Date.now();
    let raw;
    try {
      raw = await Promise.race([
        chain.nextJsonRpcResponse(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error("deadline")), remaining),
        ),
      ]);
    } catch (_) {
      break;
    }
    const msg = JSON.parse(raw);
    if (msg.id === followReqId) {
      if (msg.error) {
        throw new Error(
          `chainHead_v1_follow failed: ${JSON.stringify(msg.error)}`,
        );
      }
      subId = msg.result;
      continue;
    }
    if (
      subId !== null &&
      msg.params?.subscription === subId &&
      msg.params.result?.event === "initialized"
    ) {
      const tInit = performance.now();
      const initializedMs = tInit - tStart;
      console.log(`RESULT ${JSON.stringify({ initialized_ms: initializedMs })}`);
      exitCode = 0;
      break;
    }
  }

  if (exitCode !== 0) {
    console.error(`Timed out waiting for "initialized" after ${timeoutMs}ms`);
  }
} catch (e) {
  console.error(`cold_startup error: ${e?.message ?? e}`);
} finally {
  try {
    await client.terminate();
  } catch (_) {}
}

process.exit(exitCode);
