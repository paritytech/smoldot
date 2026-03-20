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

  const SYNC_TIMEOUT_MS = 120_000;
  sendRpc(para, "chainHead_v1_follow", [true]);

  await waitForResponse(
    para,
    (msg) => msg.params?.result?.event === "initialized",
    SYNC_TIMEOUT_MS,
  );
  report("parachain sync (initialized)", true);

  await waitForResponse(
    para,
    (msg) => msg.params?.result?.event === "newBlock",
    SYNC_TIMEOUT_MS,
  );
  report("parachain sync (newBlock)", true);

  const MAX_RETRIES = 5;
  let submitResult;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    submitResult = await sendRpcAndWait(para, "statement_submit", [
      statementHex,
    ]);
    if (submitResult?.ok_broadcast != null) break;
    if (attempt < MAX_RETRIES - 1) {
      console.error(
        `statement_submit attempt ${attempt + 1} returned: ${JSON.stringify(submitResult)}, retrying...`,
      );
      await new Promise((r) => setTimeout(r, 3000));
    }
  }

  report(
    "statement_submit returns ok_broadcast",
    submitResult?.ok_broadcast != null,
    JSON.stringify(submitResult),
  );

  if (submitResult?.ok_broadcast) {
    report(
      "statement_submit sent count",
      typeof submitResult.ok_broadcast.sent === "number",
      JSON.stringify(submitResult.ok_broadcast),
    );
  }
} catch (e) {
  report("light_node_submission", false, e.message);
  passed = false;
} finally {
  try {
    await client.terminate();
  } catch (_) {}
}

if (!passed || process.exitCode) {
  process.exit(1);
}
