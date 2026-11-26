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

// Bootnode rotation test body. Smoldot starts with a single bootnode in the
// chain spec. Once it has found other nodes and is synced, it must free the
// bootnode's gossip slot and keep it free.

import { createRpc } from "./rpc.js";

export const fileInputs = ["RELAY_CHAIN_SPEC"];
export const envInputs = ["BOOTNODE_PEER_ID"];

const CONNECT_TIMEOUT_MS = 120_000;
// Sync, discovery, then up to a few 30s rotation rounds.
const ROTATION_TIMEOUT_MS = 240_000;
// Shorter than the 300s ban of a rotated bootnode.
const STAY_OUT_MS = 60_000;
const MIN_PEERS_AFTER = 3;

export default async function bootnodeRotation(ctx) {
  const { report, env, files } = ctx;
  const rpc = createRpc(ctx.client);

  const bootnode = env.BOOTNODE_PEER_ID;
  if (!files.RELAY_CHAIN_SPEC || !bootnode) {
    throw new Error("Required env vars: RELAY_CHAIN_SPEC, BOOTNODE_PEER_ID");
  }

  const relay = await rpc.addChain({ chainSpec: files.RELAY_CHAIN_SPEC });
  report("addChain relay", true);

  const connected = await pollPeers(
    rpc,
    relay,
    (peers) => peers.some((p) => p.peerId === bootnode),
    Date.now() + CONNECT_TIMEOUT_MS,
  );
  report("bootnode connected", connected !== null);
  if (connected === null) {
    throw new Error(`bootnode ${bootnode} never in system_peers`);
  }

  const rotated = await pollPeers(
    rpc,
    relay,
    (peers) =>
      peers.length >= MIN_PEERS_AFTER && !peers.some((p) => p.peerId === bootnode),
    Date.now() + ROTATION_TIMEOUT_MS,
  );
  report(
    "bootnode slot rotated to a discovered node",
    rotated !== null,
    rotated !== null ? `peers=${rotated.map((p) => p.peerId).join(",")}` : "",
  );
  if (rotated === null) {
    throw new Error(`bootnode ${bootnode} still in system_peers after ${ROTATION_TIMEOUT_MS}ms`);
  }

  const back = await pollPeers(
    rpc,
    relay,
    (peers) => peers.some((p) => p.peerId === bootnode),
    Date.now() + STAY_OUT_MS,
  );
  report("bootnode stays out of the slots", back === null);
  if (back !== null) {
    throw new Error(`bootnode ${bootnode} back in system_peers`);
  }
}

// Polls `system_peers`, which lists the gossip-connected peers, until `done`
// returns true. Returns the peers, or null at the deadline.
async function pollPeers(rpc, chain, done, deadline) {
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
    if (Array.isArray(peers) && done(peers)) {
      return peers;
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  return null;
}
