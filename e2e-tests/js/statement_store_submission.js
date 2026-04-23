import {
  createClient,
  addChainFromSpec,
  sendRpc,
  sendRpcAndWait,
  waitForResponse,
  report,
} from "./helpers.js";

const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const paraSpecPath = process.env.PARA_CHAIN_SPEC;
const statementHex = process.env.STATEMENT_HEX;

if (!relaySpecPath || !paraSpecPath || !statementHex) {
  console.error(
    "Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, STATEMENT_HEX",
  );
  process.exit(1);
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

  // Wait for smoldot to establish peer connections before submitting.
  // statement_submit is a pure gossip operation — no chain sync needed.
  const PEER_SETTLE_MS = 10_000;
  await new Promise((r) => setTimeout(r, PEER_SETTLE_MS));

  const MAX_RETRIES = 10;
  let submitResult;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    submitResult = await sendRpcAndWait(para, "statement_submit", [
      statementHex,
    ]);

    // Smoldot returns {"status":"new"} on success
    if (submitResult?.status === "new") break;
    if (attempt < MAX_RETRIES - 1) {
      console.error(
        `statement_submit attempt ${attempt + 1} returned: ${JSON.stringify(submitResult)}, retrying in 5s...`,
      );
      await new Promise((r) => setTimeout(r, 5000));
    }
  }

  report(
    "statement_submit accepted",
    submitResult?.status === "new",
    JSON.stringify(submitResult),
  );
} catch (e) {
  report("statement_store_submission", false, e.message);
  passed = false;
} finally {
  try {
    await client.terminate();
  } catch (_) {}
}

if (!passed || process.exitCode) {
  process.exit(1);
}
