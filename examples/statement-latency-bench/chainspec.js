import { readFile } from "node:fs/promises";

// Accepts an http(s) URL or a local file path. Bootnodes are expected to be
// embedded in the spec already (the canonical source is the paritytech/chainspecs
// repo and smoldot's bundled demo-chain-specs/, both of which ship bootnodes
// inside the spec).
const FETCH_TIMEOUT_MS = 30000;

export async function loadChainSpec(source) {
  if (/^https?:\/\//i.test(source)) {
    // Time out hung HTTP servers rather than blocking startup forever.
    const res = await fetch(source, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (!res.ok) {
      throw new Error(`Failed to fetch ${source}: ${res.status} ${res.statusText}`);
    }
    return await res.text();
  }
  return await readFile(source, "utf8");
}
