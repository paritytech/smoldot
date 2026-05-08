// Smoldot
// Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import {
  createSmoldotClient,
  addChainFromSpec,
  sendRpc,
  readJsonRpcUntil,
  report,
} from "./helpers.js";

const relaySpecPath = process.env.RELAY_CHAIN_SPEC;
const validatorBPeerId = process.env.VALIDATOR_B_PEER_ID;

if (!relaySpecPath || !validatorBPeerId) {
  console.error(
    "Required env vars: RELAY_CHAIN_SPEC, VALIDATOR_B_PEER_ID",
  );
  process.exit(1);
}

// Polls `system_peers` until the target peer-id is present, with a deadline.
// `system_peers` only lists *gossip-connected* peers, so seeing the target
// here proves smoldot reached B at the substrate level — which can only
// happen if Kademlia first surfaced B's multiaddr from A.
async function waitForPeer(chain, targetPeerId, deadline) {
  while (Date.now() < deadline) {
    const reqId = sendRpc(chain, "system_peers", []).toString();
    const peers = await readJsonRpcUntil(
      chain,
      (msg) => {
        if (msg.id !== reqId) return undefined;
        if (msg.error) {
          throw new Error(`system_peers failed: ${JSON.stringify(msg.error)}`);
        }
        return msg.result ?? [];
      },
      Math.min(deadline, Date.now() + 5_000),
    );
    if (peers === undefined) continue;
    if (Array.isArray(peers) && peers.some((p) => p.peerId === targetPeerId)) {
      return peers;
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  return null;
}

const client = createSmoldotClient();
let relay;
let passed = true;

try {
  relay = await addChainFromSpec(client, relaySpecPath);
  report("addChain relay", true);

  // Allow up to 3 minutes for: connect to A → Identify → Kademlia FindNode
  // → discover B's multiaddr → connect to B → open block-announces gossip.
  // The slowest step in practice is the discovery round timer.
  const peers = await waitForPeer(
    relay,
    validatorBPeerId,
    Date.now() + 180_000,
  );
  const ok = peers !== null;
  report(
    "smoldot reached validator-b via Kademlia discovery",
    ok,
    ok
      ? `peers=${peers.map((p) => p.peerId).join(",")}`
      : `target=${validatorBPeerId} not in system_peers within deadline`,
  );
  if (!ok) passed = false;
} catch (e) {
  report("reserved_peer_discovery", false, e.message);
  passed = false;
} finally {
  try {
    await client.terminate();
  } catch (_) {}
}

if (!passed || process.exitCode) {
  process.exit(1);
}
