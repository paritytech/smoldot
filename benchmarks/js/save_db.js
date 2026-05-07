// Save-DB step for the warm-startup benchmark.
//
// Spawns smoldot, adds the chain(s), waits for chainHead_v1_follow
// `initialized`, then calls `chainHead_unstable_finalizedDatabase` on each
// chain and writes the returned blob to `$SAVE_DB_DIR/<chainId>.db`.
//
// Env vars:
//   RELAY_CHAIN_SPEC   path to relay chain spec (required)
//   PARA_CHAIN_SPEC    path to parachain chain spec (required if TARGET=para)
//   TARGET             "relay" | "para"   (default: "para" if PARA set else "relay")
//   SAVE_DB_DIR        dir to write <id>.db files (required)
//   TIMEOUT_MS         overall timeout (default 180000)
//   SMOLDOT_LOG_LEVEL  default 2

import * as fs from "node:fs";
import * as path from "node:path";
import { start } from "smoldot";

const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const paraSpecPath = process.env.PARA_CHAIN_SPEC || "";
const target = process.env.TARGET || (paraSpecPath ? "para" : "relay");
const saveDir = process.env.SAVE_DB_DIR;
const timeoutMs = Number.parseInt(process.env.TIMEOUT_MS || "180000", 10);

if (!relaySpecPath || !saveDir) {
  console.error("RELAY_CHAIN_SPEC and SAVE_DB_DIR are required");
  process.exit(1);
}
if (target === "para" && !paraSpecPath) {
  console.error("TARGET=para requires PARA_CHAIN_SPEC");
  process.exit(1);
}

fs.mkdirSync(saveDir, { recursive: true });

const relaySpec = fs.readFileSync(relaySpecPath, "utf8");
// Only read para spec when target=para. Zombienet always passes PARA_CHAIN_SPEC
// but we don't need it for relay-only saves.
const paraSpec = target === "para" ? fs.readFileSync(paraSpecPath, "utf8") : null;
const relayId = JSON.parse(relaySpec).id;
const paraId = paraSpec ? JSON.parse(paraSpec).id : null;

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

  // Wait until each chain we plan to dump has finalized at least one block
  // past `chainHead_v1_follow`'s `initialized` event. The initial finalized
  // header is racy on cold start (smoldot's `subscribe_all` can return the
  // chain-spec checkpoint while warp-sync chain-information-build is still
  // pending), so dumping immediately after `initialized` may snapshot
  // genesis. A single post-init `finalized` event proves smoldot has
  // advanced its own finality and the dump is non-stale.
  const deadline = Date.now() + timeoutMs;
  const gates = [waitForFreshFinalized(relay, relayId, deadline)];
  if (target === "para") gates.push(waitForFreshFinalized(chain, paraId, deadline));
  await Promise.all(gates);

  // Save DBs for every chain smoldot needs on a warm restart. Target=relay
  // uses only the relay. Target=para needs both (smoldot needs the relay to
  // resolve the parachain's finality).
  await dumpDb(relay, relayId);
  if (target === "para") await dumpDb(chain, paraId);

  console.log(`SAVED ${JSON.stringify({ relay: relayId, para: target === "para" ? paraId : null })}`);
  exitCode = 0;
} catch (e) {
  console.error(`save_db error: ${e?.message ?? e}`);
} finally {
  try {
    await client.terminate();
  } catch (_) {}
}

process.exit(exitCode);

async function waitForFreshFinalized(chain, label, deadline) {
  const followReqId = `follow-${label}`;
  chain.sendJsonRpc(
    JSON.stringify({
      jsonrpc: "2.0",
      id: followReqId,
      method: "chainHead_v1_follow",
      params: [true],
    }),
  );

  let subId = null;
  let initialHashes = null;

  while (Date.now() < deadline) {
    const raw = await nextMsg(chain, deadline);
    if (!raw) break;
    const msg = JSON.parse(raw);

    if (msg.id === followReqId) {
      if (msg.error) throw new Error(`[${label}] follow failed: ${JSON.stringify(msg.error)}`);
      subId = msg.result;
      continue;
    }
    if (!subId || msg.params?.subscription !== subId) continue;

    const ev = msg.params.result;
    if (ev?.event === "initialized") {
      initialHashes = new Set(ev.finalizedBlockHashes ?? []);
      console.error(
        `[save_db] ${label}: initialized at ${[...initialHashes].join(",")}; waiting for first post-init finalized event`,
      );
      continue;
    }
    if (ev?.event === "finalized" && initialHashes) {
      const fresh = (ev.finalizedBlockHashes ?? []).find((h) => !initialHashes.has(h));
      if (fresh) {
        console.error(`[save_db] ${label}: advanced past init (new finalized ${fresh})`);
        return;
      }
    }
  }
  throw new Error(`[${label}] timed out waiting for first post-init finalized event`);
}

async function nextMsg(chain, deadline) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) return null;
  try {
    return await Promise.race([
      chain.nextJsonRpcResponse(),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("deadline")), remaining),
      ),
    ]);
  } catch (_) {
    return null;
  }
}

async function dumpDb(chain, id) {
  const reqId = `save-${id}`;
  chain.sendJsonRpc(
    JSON.stringify({
      jsonrpc: "2.0",
      id: reqId,
      method: "chainHead_unstable_finalizedDatabase",
      params: [],
    }),
  );
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const raw = await nextMsg(chain, deadline);
    if (!raw) break;
    const msg = JSON.parse(raw);
    if (msg.id === reqId) {
      if (msg.error) throw new Error(`finalizedDatabase failed: ${JSON.stringify(msg.error)}`);
      const out = path.join(saveDir, `${id}.db`);
      fs.writeFileSync(out, msg.result);
      console.error(`[save_db] ${id}: ${msg.result.length} bytes → ${out}`);
      return;
    }
  }
  throw new Error(`timed out dumping DB for ${id}`);
}
