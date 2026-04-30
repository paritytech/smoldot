import { readFile } from "node:fs/promises";

// Accepts an http(s) URL or a local file path. Bootnodes are expected to be
// embedded in the spec already (the canonical source is the paritytech/chainspecs
// repo and smoldot's bundled demo-chain-specs/, both of which ship bootnodes
// inside the spec).
export async function loadChainSpec(source) {
  if (/^https?:\/\//i.test(source)) {
    const res = await fetch(source);
    if (!res.ok) {
      throw new Error(`Failed to fetch ${source}: ${res.status} ${res.statusText}`);
    }
    return await res.text();
  }
  return await readFile(source, "utf8");
}
