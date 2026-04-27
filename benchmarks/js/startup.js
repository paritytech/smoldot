// Single startup measurement (cold or warm). Spawned as a fresh Node
// subprocess per iteration by the Rust bench runner. Prints exactly one line:
//   RESULT {"finalized_ms":<n>,"phases":{...},"block":{...}}
// and exits 0 on success, non-zero on any failure.
//
// Cold vs warm is selected by env: when LOAD_DB_DIR is set, smoldot is given
// a pre-saved `databaseContent` per chain so it skips warp-sync and resumes
// from the snapshot.
//
// Measured window: `performance.now()` just before `start()` through
// polkadot-api `client.getFinalizedBlock()` resolving — i.e. the first
// finalized block usable by an app sitting on top of smoldot. Matches
// wasm-node/javascript/bench/time-to-initialized.mjs.
//
// Env vars:
//   RELAY_CHAIN_SPEC   path to relay chain spec (required)
//   PARA_CHAIN_SPEC    path to parachain chain spec (optional — omit for relay-only)
//   TARGET             "relay" | "para" (default: "para" if PARA_CHAIN_SPEC set, else "relay")
//   LOAD_DB_DIR        dir containing <chainId>.db files (optional — switches to warm mode)
//   TIMEOUT_MS         overall timeout (default: 120000)
//   SMOLDOT_LOG_LEVEL  smoldot maxLogLevel (default: 2 — warnings only)

import * as fs from "node:fs";
import * as path from "node:path";
import { start } from "smoldot";
import { createClient } from "polkadot-api";
import { getSmProvider } from "polkadot-api/sm-provider";

const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const paraSpecPath = process.env.PARA_CHAIN_SPEC || "";
const target = process.env.TARGET || (paraSpecPath ? "para" : "relay");
const loadDir = process.env.LOAD_DB_DIR || "";
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
const paraSpec = target === "para" ? fs.readFileSync(paraSpecPath, "utf8") : null;

// Warm mode only: pre-load `<chainId>.db` blobs we'll pass to addChain.
const relayDb = loadDir ? loadDb(JSON.parse(relaySpec).id) : undefined;
const paraDb = loadDir && paraSpec ? loadDb(JSON.parse(paraSpec).id) : undefined;

function loadDb(id) {
  const p = path.join(loadDir, `${id}.db`);
  if (!fs.existsSync(p)) {
    // Fail fast — warm bench without a DB is meaningless.
    console.error(`missing DB file for chain '${id}' at ${p}`);
    process.exit(1);
  }
  return fs.readFileSync(p, "utf8");
}

// Mark the start just before handing control to smoldot. File reads above
// are excluded — they are not what we are benchmarking.
const tStart = performance.now();

const smoldot = start({
  maxLogLevel: Number.parseInt(process.env.SMOLDOT_LOG_LEVEL || "2", 10),
  logCallback: (level, t, m) => {
    const labels = { 1: "ERROR", 2: "WARN", 3: "INFO", 4: "DEBUG", 5: "TRACE" };
    console.error(`[${labels[level] ?? `L${level}`}] [${t}] ${m}`);
  },
});

let exitCode = 1;
let client;
try {
  const tBeforeRelay = performance.now();
  const relay = await smoldot.addChain({
    chainSpec: relaySpec,
    databaseContent: relayDb,
  });
  const tAfterRelay = performance.now();

  let tBeforePara = tAfterRelay;
  let tAfterPara = tAfterRelay;
  const chain =
    target === "relay"
      ? relay
      : await (async () => {
          tBeforePara = performance.now();
          const p = await smoldot.addChain({
            chainSpec: paraSpec,
            potentialRelayChains: [relay],
            databaseContent: paraDb,
          });
          tAfterPara = performance.now();
          return p;
        })();

  // Wrap the smoldot Chain so polkadot-api's `client.destroy()` doesn't call
  // `chain.remove()` — we own teardown via `smoldot.terminate()` in `finally`.
  const provider = {
    sendJsonRpc: (req) => chain.sendJsonRpc(req),
    nextJsonRpcResponse: () => chain.nextJsonRpcResponse(),
    remove: () => {},
  };

  const tBeforeWait = performance.now();
  client = createClient(getSmProvider(() => provider));
  const block = await Promise.race([
    client.getFinalizedBlock(),
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error(`getFinalizedBlock timeout after ${timeoutMs}ms`)),
        timeoutMs,
      ),
    ),
  ]);
  const tFinalized = performance.now();

  const phases = {
    add_chain_relay_ms: tAfterRelay - tBeforeRelay,
    wait_finalized_ms: tFinalized - tBeforeWait,
  };
  if (target === "para") {
    phases.add_chain_para_ms = tAfterPara - tBeforePara;
  }
  const result = {
    finalized_ms: tFinalized - tStart,
    phases,
    block: { number: block.number, hash: block.hash },
  };
  console.log(`RESULT ${JSON.stringify(result)}`);
  exitCode = 0;
} catch (e) {
  console.error(`startup error: ${e?.message ?? e}`);
} finally {
  try {
    if (client) client.destroy();
  } catch (_) {}
  try {
    await smoldot.terminate();
  } catch (_) {}
}

process.exit(exitCode);
