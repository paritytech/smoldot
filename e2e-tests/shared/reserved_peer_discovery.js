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

// Kademlia discovery test body — runs on either host via the ctx abstraction.
// Asserts that smoldot reaches a target node whose multiaddr is NOT in the
// chain spec `bootNodes`, i.e. that it was discovered through the DHT.

import { createRpc } from "./rpc.js";

export const fileInputs = ["RELAY_CHAIN_SPEC"];

const DISCOVERY_TIMEOUT_MS = 180_000;

export default async function reservedPeerDiscovery(ctx) {
  const { report, env, files } = ctx;
  const rpc = createRpc(ctx.client);

  const requiredPeerId = env.REQUIRED_PEER_ID;
  if (!files.RELAY_CHAIN_SPEC || !requiredPeerId) {
    throw new Error("Required env vars: RELAY_CHAIN_SPEC, REQUIRED_PEER_ID");
  }

  const relay = await rpc.addChain({ chainSpec: files.RELAY_CHAIN_SPEC });
  report("addChain relay", true);

  const peers = await waitForPeer(rpc, relay, requiredPeerId, Date.now() + DISCOVERY_TIMEOUT_MS);
  const ok = peers !== null;
  report(
    "smoldot reached the required node via Kademlia discovery",
    ok,
    ok
      ? `peers=${peers.map((p) => p.peerId).join(",")}`
      : `target=${requiredPeerId} not in system_peers within deadline`,
  );
  if (!ok) {
    throw new Error(`peer ${requiredPeerId} not discovered within ${DISCOVERY_TIMEOUT_MS}ms`);
  }
}

// Polls `system_peers` until the target peer-id is present, with a deadline.
// `system_peers` only lists *gossip-connected* peers, so seeing the target
// here proves smoldot reached the target at the substrate level — which
// can only happen if Kademlia first surfaced its multiaddr from another
// peer.
async function waitForPeer(rpc, chain, targetPeerId, deadline) {
  while (Date.now() < deadline) {
    const reqId = rpc.sendRpc(chain, "system_peers", []).toString();
    const peers = await rpc.readJsonRpcUntil(
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
