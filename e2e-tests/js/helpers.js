import * as fs from "node:fs";
import { start } from "smoldot";

export function createClient() {
  return start({
    maxLogLevel: 3,
    logCallback: (level, target, message) => {
      const labels = { 1: "ERROR", 2: "WARN", 3: "INFO" };
      const label = labels[level] || "TRACE";
      console.error(`[${label}] [${target}] ${message}`);
    },
  });
}

export async function addChainFromSpec(client, specPath, opts = {}) {
  const chainSpec = fs.readFileSync(specPath, "utf8");
  return client.addChain({ chainSpec, ...opts });
}

let nextId = 1;

export function sendRpc(chain, method, params = []) {
  const id = nextId++;
  const request = JSON.stringify({
    jsonrpc: "2.0",
    id: id.toString(),
    method,
    params,
  });
  chain.sendJsonRpc(request);
  return id;
}

export async function sendRpcAndWait(chain, method, params = []) {
  const id = sendRpc(chain, method, params);
  const idStr = id.toString();
  while (true) {
    const response = JSON.parse(await chain.nextJsonRpcResponse());
    if (response.id === idStr) {
      if (response.error) {
        throw new Error(`RPC error: ${JSON.stringify(response.error)}`);
      }
      return response.result;
    }
  }
}

export async function waitForResponse(chain, predicate, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const raceResult = await Promise.race([
      chain.nextJsonRpcResponse(),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error("Timed out waiting for JSON-RPC response")),
          Math.max(1, deadline - Date.now()),
        ),
      ),
    ]);
    const parsed = JSON.parse(raceResult);
    if (predicate(parsed)) {
      return parsed;
    }
  }
  throw new Error("Timed out waiting for matching response");
}

export function report(name, passed, detail) {
  if (passed) {
    console.log(`PASS: ${name}`);
  } else {
    console.log(`FAIL: ${name}: ${detail}`);
    process.exitCode = 1;
  }
}
