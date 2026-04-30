import { readFile } from "node:fs/promises";

export async function loadChainSpec(path) {
  return await readFile(path, "utf8");
}

// `AddChainOptions.chainSpec` has no separate bootnodes field; bootnodes must
// be embedded in the spec JSON. We append rather than replace so any bootnodes
// already in the spec (e.g. public ones) keep working alongside CLI-provided ones.
export function spliceBootnodes(specJson, bootnodes) {
  if (!bootnodes?.length) return specJson;
  const spec = JSON.parse(specJson);
  const existing = Array.isArray(spec.bootNodes) ? spec.bootNodes : [];
  spec.bootNodes = [...existing, ...bootnodes];
  return JSON.stringify(spec);
}
