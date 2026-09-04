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

// `lifecycle_unstable_follow` test body. Subscribes on the relay chain and the
// parachain, records every state notification until both chains report
// `ready`, and checks the sequence:
//
// - the first notification of each chain is `connecting`
// - the relay chain reports `syncing` with `at < target` before `ready` when
//   EXPECT_WARP_SYNC is "true", and `at` never decreases
// - the parachain never reports `syncing`
// - at `ready`, `hasPeers` is true and `health` is `ok`
// - after `unfollow`, a new `follow` starts with a `ready` snapshot
//
// See <https://github.com/paritytech/smoldot/issues/3301>.

import { createRpc } from "./rpc.js";

export const fileInputs = [
  "RELAY_CHAIN_SPEC",
  "PARA_CHAIN_SPEC",
  "SMOLDOT_DB_RELAY",
  "SMOLDOT_DB_PARA",
];

export const envInputs = ["EXPECT_WARP_SYNC", "OVERALL_TIMEOUT_MS"];

const NOTIFICATION = "lifecycle_unstable_followEvent";

function describe(state) {
  const phase =
    state.phase.kind === "syncing"
      ? `syncing ${state.phase.at}/${state.phase.target}`
      : state.phase.kind;
  const health =
    state.health.kind === "stalled" ? `stalled(${state.health.reason})` : state.health.kind;
  return `${phase} hasPeers=${state.hasPeers} health=${health}`;
}

// Checks the recorded states of one chain and reports the results.
function checkStates(report, label, states, { expectWarpSync, allowSyncing }) {
  report(`${label}: received at least one state`, states.length > 0, `${states.length} states`);
  if (states.length === 0) return;

  report(`${label}: first state is connecting`, states[0].phase.kind === "connecting", describe(states[0]));

  const last = states[states.length - 1];
  report(`${label}: reaches ready`, last.phase.kind === "ready", describe(last));
  report(`${label}: has peers when ready`, last.hasPeers, describe(last));
  report(`${label}: health is ok when ready`, last.health.kind === "ok", describe(last));

  const syncing = states.filter((s) => s.phase.kind === "syncing");
  if (allowSyncing) {
    if (expectWarpSync) {
      const withGap = syncing.filter((s) => s.phase.at < s.phase.target);
      report(
        `${label}: reports syncing progress before ready`,
        withGap.length > 0,
        `${syncing.length} syncing states, ${withGap.length} with at < target`,
      );
    }
    let monotonic = true;
    for (let i = 1; i < syncing.length; i++) {
      if (syncing[i].phase.at < syncing[i - 1].phase.at) monotonic = false;
    }
    report(`${label}: syncing height never decreases`, monotonic, `${syncing.length} syncing states`);
    const readyIndex = states.findIndex((s) => s.phase.kind === "ready");
    const syncingAfterReady = states.slice(readyIndex + 1).some((s) => s.phase.kind === "syncing");
    report(`${label}: no syncing after ready`, !syncingAfterReady);
  } else {
    report(`${label}: never reports syncing`, syncing.length === 0, `${syncing.length} syncing states`);
  }

  const unknownPhase = states.filter((s) => !["connecting", "syncing", "ready"].includes(s.phase.kind));
  report(`${label}: only known phases`, unknownPhase.length === 0);
}

export default async function lifecycle(ctx) {
  const { report, env, files, log } = ctx;
  const rpc = createRpc(ctx.client);

  const expectWarpSync = (env.EXPECT_WARP_SYNC ?? "false") === "true";
  const overallTimeoutMs = Number.parseInt(env.OVERALL_TIMEOUT_MS ?? "240000", 10);

  if (!files.RELAY_CHAIN_SPEC || !files.PARA_CHAIN_SPEC) {
    throw new Error("Required env vars: RELAY_CHAIN_SPEC, PARA_CHAIN_SPEC");
  }

  const relay = await rpc.addChain({
    chainSpec: files.RELAY_CHAIN_SPEC,
    databaseContent: files.SMOLDOT_DB_RELAY ?? undefined,
  });
  report("addChain relay", true);
  const para = await rpc.addChain({
    chainSpec: files.PARA_CHAIN_SPEC,
    databaseContent: files.SMOLDOT_DB_PARA ?? undefined,
    potentialRelayChains: [relay],
  });
  report("addChain parachain", true);

  const chains = [
    { label: "relay", chain: relay, subId: null, states: [], allowSyncing: true },
    { label: "para", chain: para, subId: null, states: [], allowSyncing: false },
  ];

  for (const c of chains) {
    c.subId = await rpc.sendRpcAndWait(c.chain, "lifecycle_unstable_follow", [], 30_000);
    report(`${c.label}: lifecycle_unstable_follow accepted`, typeof c.subId === "string" && c.subId !== "");
  }

  // Poll both chains in turn until each has reported `ready` with peers, or the deadline
  // passes. `hasPeers` is sampled by smoldot about once per second, so on a fast local
  // network `ready` can arrive before the first sample: allow a grace period for it.
  const deadline = Date.now() + overallTimeoutMs;
  const peersGraceMs = 10_000;
  const last = (c) => c.states[c.states.length - 1];
  const isReady = (c) => c.states.length > 0 && last(c).phase.kind === "ready";
  const isSettled = (c) => isReady(c) && last(c).hasPeers;
  let allReadyAt = null;
  while (Date.now() < deadline && !chains.every(isSettled)) {
    if (chains.every(isReady)) {
      allReadyAt ??= Date.now();
      if (Date.now() - allReadyAt > peersGraceMs) break;
    }
    for (const c of chains) {
      const state = await rpc.readJsonRpcUntil(
        c.chain,
        (msg) =>
          msg.method === NOTIFICATION && msg.params?.subscription === c.subId
            ? msg.params.result
            : undefined,
        Date.now() + 250,
      );
      if (state !== undefined) {
        c.states.push(state);
        log(`[${c.label}] ${describe(state)}`);
      }
    }
  }

  for (const c of chains) {
    checkStates(report, c.label, c.states, { expectWarpSync, allowSyncing: c.allowSyncing });
  }

  // Unfollow, then follow again: the new subscription must start with the current state.
  for (const c of chains) {
    if (!isReady(c)) continue;
    await rpc.sendRpcAndWait(c.chain, "lifecycle_unstable_unfollow", [c.subId], 30_000);
    report(`${c.label}: lifecycle_unstable_unfollow accepted`, true);
    const newSubId = await rpc.sendRpcAndWait(c.chain, "lifecycle_unstable_follow", [], 30_000);
    const snapshot = await rpc.readJsonRpcUntil(
      c.chain,
      (msg) =>
        msg.method === NOTIFICATION && msg.params?.subscription === newSubId
          ? msg.params.result
          : undefined,
      Date.now() + 30_000,
    );
    report(
      `${c.label}: resubscribe snapshot is ready`,
      snapshot !== undefined && snapshot.phase.kind === "ready",
      snapshot ? describe(snapshot) : "no snapshot received",
    );
  }

  if (!chains.every(isReady)) {
    throw new Error(
      `lifecycle: not all chains reached ready within ${overallTimeoutMs}ms: ${chains
        .map((c) => `${c.label}=${c.states.length ? describe(c.states[c.states.length - 1]) : "no state"}`)
        .join(", ")}`,
    );
  }
}
