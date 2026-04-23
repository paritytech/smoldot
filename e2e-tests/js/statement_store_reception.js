import { createClient, addChainFromSpec, sendRpc, report } from "./helpers.js";

const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const paraSpecPath = process.env.PARA_CHAIN_SPEC;
const topicAHex = process.env.TOPIC_A;
const stmtAHex = process.env.STATEMENT_A_HEX;
const stmtBHex = process.env.STATEMENT_B_HEX;
const READY_FD_PATH = process.env.READY_FD_PATH;
const LISTEN_MS = Number.parseInt(process.env.LISTEN_MS || "60000", 10);
const PEER_SETTLE_MS = Number.parseInt(
  process.env.PEER_SETTLE_MS || "15000",
  10,
);

if (
  !relaySpecPath ||
  !paraSpecPath ||
  !topicAHex ||
  !stmtAHex ||
  !stmtBHex ||
  !READY_FD_PATH
) {
  console.error(
    "Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, TOPIC_A, STATEMENT_A_HEX, STATEMENT_B_HEX, READY_FD_PATH",
  );
  process.exit(1);
}

const norm = (h) => h.toLowerCase();
const normA = norm(stmtAHex);
const normB = norm(stmtBHex);

async function drainUntil(chain, predicate, deadlineMs) {
  while (Date.now() < deadlineMs) {
    const remaining = deadlineMs - Date.now();
    let raw;
    try {
      raw = await Promise.race([
        chain.nextJsonRpcResponse(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error("timeout")), remaining),
        ),
      ]);
    } catch (_) {
      return undefined;
    }
    const msg = JSON.parse(raw);
    const out = predicate(msg);
    if (out !== undefined) return out;
  }
  return undefined;
}

const client = createClient();
let relay;
let para;
let passed = true;

try {
  relay = await addChainFromSpec(client, relaySpecPath);
  report("addChain relay", true);

  para = await addChainFromSpec(client, paraSpecPath, {
    statementStore: {},
    potentialRelayChains: [relay],
  });
  report("addChain parachain with statementStore", true);

  // Subscribe immediately so the affinity filter is in place before peers
  // negotiate the statement protocol.
  const subReqId = sendRpc(para, "statement_subscribeStatement", [
    { matchAny: [topicAHex] },
  ]).toString();

  const subId = await drainUntil(
    para,
    (msg) => {
      if (msg.id === subReqId) {
        if (msg.error)
          throw new Error(
            `statement_subscribeStatement failed: ${JSON.stringify(msg.error)}`,
          );
        return msg.result;
      }
      return undefined;
    },
    Date.now() + 20_000,
  );
  if (typeof subId !== "string" || subId.length === 0) {
    throw new Error(`Unexpected subscription id: ${JSON.stringify(subId)}`);
  }
  report("statement_subscribeStatement accepted", true, `subId=${subId}`);

  // Give smoldot time to peer with both collators before we signal readiness.
  await new Promise((r) => setTimeout(r, PEER_SETTLE_MS));

  // Signal Rust we're ready to receive statements.
  const fs = await import("node:fs/promises");
  await fs.writeFile(READY_FD_PATH, "READY\n");
  report("signalled READY", true, READY_FD_PATH);

  // Listen for notifications for LISTEN_MS after READY.
  let countA = 0;
  let countB = 0;
  let countOther = 0;
  const listenDeadline = Date.now() + LISTEN_MS;

  await drainUntil(
    para,
    (msg) => {
      if (msg.method !== "statement_statement") return undefined;
      if (msg.params?.subscription !== subId) return undefined;
      const result = msg.params.result;
      if (result?.event !== "newStatements") return undefined;
      const stmts = result.data?.statements ?? [];
      for (const s of stmts) {
        const h = norm(s);
        if (h === normA) countA += 1;
        else if (h === normB) countB += 1;
        else countOther += 1;
      }
      return undefined;
    },
    listenDeadline,
  );

  const ok = countA === 1 && countB === 0 && countOther === 0;
  report(
    "reception: stmt_A received exactly once, stmt_B never, no stray statements",
    ok,
    `countA=${countA}, countB=${countB}, other=${countOther}`,
  );
  if (!ok) passed = false;

  // Unsubscribe as a best-effort cleanup. Terminating the client implicitly
  // removes the subscription; we don't fail the test on the RPC round-trip
  // since pending notifications may delay the response past our budget.
  try {
    sendRpc(para, "statement_unsubscribeStatement", [subId]);
  } catch (_) {}
} catch (e) {
  report("statement_store_reception", false, e.message);
  passed = false;
} finally {
  try {
    await client.terminate();
  } catch (_) {}
}

if (!passed || process.exitCode) {
  process.exit(1);
}
