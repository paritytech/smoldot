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

// Statement-store peer steering test body. Every entry of TARGETS is a full
// node with the topic it is the closest peer to and a statement that only it
// holds. The body picks a node outside smoldot's gossip peers, subscribes to
// its topic and asserts that the statement arrives, which takes a statement
// link opened by the steering.

import { createRpc } from "./rpc.js";

export const fileInputs = ["RELAY_CHAIN_SPEC", "PARA_CHAIN_SPEC"];
export const envInputs = ["TARGETS"];

// Gossip slots smoldot keeps per chain.
const GOSSIP_SLOTS = 4;

export default async function statementStorePeerSteering(ctx) {
  const { report, env, files } = ctx;
  const rpc = createRpc(ctx.client);

  if (!files.RELAY_CHAIN_SPEC || !files.PARA_CHAIN_SPEC || !env.TARGETS) {
    throw new Error("Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC, TARGETS");
  }
  const targets = JSON.parse(env.TARGETS);

  const relay = await rpc.addChain({ chainSpec: files.RELAY_CHAIN_SPEC });
  const para = await rpc.addChain({
    chainSpec: files.PARA_CHAIN_SPEC,
    statementStore: {},
    potentialRelayChains: [relay],
  });
  report("addChain relay and parachain with statementStore", true);

  const gossipPeers = async () =>
    new Set((await rpc.sendRpcAndWait(para, "system_peers", [])).map((peer) => peer.peerId));
  const names = (peers) =>
    targets
      .filter((t) => peers.has(t.peerId))
      .map((t) => t.name)
      .join(",");

  // Wait for the gossip slots to fill, so that the chosen node stays outside them.
  let peers = new Set();
  const slotsDeadline = Date.now() + 120_000;
  while (Date.now() < slotsDeadline) {
    peers = await gossipPeers();
    if (peers.size >= GOSSIP_SLOTS) break;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  const target = targets.find((t) => !peers.has(t.peerId));
  const targetOk = peers.size > 0 && target !== undefined;
  report(
    "a full node stays outside the gossip peers",
    targetOk,
    `gossip=${names(peers)} target=${target?.name}`,
  );
  if (!targetOk) throw new Error("no full node outside the gossip peers");

  const subReqId = rpc
    .sendRpc(para, "statement_subscribeStatement", [{ matchAny: [target.topic] }])
    .toString();

  let received = false;
  const start = Date.now();
  await rpc.readJsonRpcUntil(
    para,
    (msg) => {
      if (msg.id === subReqId && msg.error) {
        throw new Error(`statement_subscribeStatement failed: ${JSON.stringify(msg.error)}`);
      }
      if (msg.method !== "statement_statement") return undefined;
      const statements = msg.params?.result?.data?.statements ?? [];
      if (!statements.includes(target.statement)) return undefined;
      received = true;
      return true;
    },
    start + 120_000,
  );

  // A node that got a gossip slot in the meantime could have delivered without the steering.
  const peersAfter = await gossipPeers();
  report(
    "the statement held by a full node outside the gossip peers arrives",
    received,
    `after=${Date.now() - start}ms target=${target.name} gossipAfter=${names(peersAfter)}`,
  );
  if (!received) throw new Error(`statement of ${target.name} never arrived`);
}
