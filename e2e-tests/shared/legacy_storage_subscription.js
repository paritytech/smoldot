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
// `state_subscribeStorage` must report only the keys whose value changed, like
// a full node. Once the relay chain is synced, opens two subscriptions:
// - `changing`: `:code`, `System::Number` and a key that doesn't exist.
// - `constant`: `:code` and the key that doesn't exist.
// Checks that the first notification of each subscription has all its keys,
// that the next ROUNDS notifications of `changing` only have `System::Number`,
// and that `constant` gets no notification after its first one.
//
// See <https://github.com/paritytech/smoldot/issues/3413>.

import { createRpc } from "./rpc.js";

export const fileInputs = ["RELAY_CHAIN_SPEC"];

export const envInputs = ["ROUNDS"];

const CODE_KEY = "0x3a636f6465";
const SYSTEM_NUMBER_KEY =
  "0x26aa394eea5630e07c48ae0c9558cef702a5c1b19ab7a04f536c519aca4983ac";
const ABSENT_KEY = "0x0000e2e7e5";
const NOTIFICATIONS_TIMEOUT_MS = 180_000;

const keysOf = (notification) =>
  notification.changes.map(([key]) => key.toLowerCase()).sort();

const sameKeys = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());

export default async function legacyStorageSubscription(ctx) {
  const { report, log, env, files } = ctx;
  const rpc = createRpc(ctx.client);

  const rounds = Number.parseInt(env.ROUNDS ?? "3", 10);
  if (!files.RELAY_CHAIN_SPEC || !Number.isFinite(rounds)) {
    throw new Error("Required env vars: RELAY_CHAIN_SPEC");
  }

  const relay = await rpc.addChain({ chainSpec: files.RELAY_CHAIN_SPEC });

  // Legacy JSON-RPC calls are held until the chain is synced.
  await rpc.sendRpcAndWait(relay, "chain_getFinalizedHead", [], 180_000);
  report("relay chain synced", true);

  // Subscribed out of band so that notifications arriving before the second
  // response stay in the queue.
  const changingKeys = [CODE_KEY, SYSTEM_NUMBER_KEY, ABSENT_KEY];
  const constantKeys = [CODE_KEY, ABSENT_KEY];
  const [changingId, constantId] = await Promise.all([
    rpc.sendRpcOutOfBand(relay, "state_subscribeStorage", [changingKeys], 30_000),
    rpc.sendRpcOutOfBand(relay, "state_subscribeStorage", [constantKeys], 30_000),
  ]);
  report("state_subscribeStorage", true, `changing ${changingId}, constant ${constantId}`);

  const received = new Map([
    [changingId, []],
    [constantId, []],
  ]);
  await rpc.readJsonRpcUntil(
    relay,
    (msg) => {
      if (msg.method !== "state_storage") return undefined;
      const list = received.get(msg.params.subscription);
      if (!list) return undefined;
      list.push(msg.params.result);
      log(
        `${msg.params.subscription === changingId ? "changing" : "constant"}: ` +
          `block ${msg.params.result.block} keys ${keysOf(msg.params.result).join(",")}`,
      );
      return received.get(changingId).length > rounds ? true : undefined;
    },
    Date.now() + NOTIFICATIONS_TIMEOUT_MS,
  );

  const changing = received.get(changingId);
  const constant = received.get(constantId);

  report(
    `changing: received ${rounds + 1} notifications`,
    changing.length > rounds,
    `${changing.length} received`,
  );
  report(
    "changing: first notification has all keys",
    changing.length > 0 && sameKeys(keysOf(changing[0]), changingKeys),
    changing.length > 0 ? keysOf(changing[0]).join(",") : "none",
  );
  const later = changing.slice(1);
  report(
    "changing: later notifications only have the changed key",
    later.length > 0 && later.every((n) => sameKeys(keysOf(n), [SYSTEM_NUMBER_KEY])),
    later.map((n) => keysOf(n).join(",")).join(" | "),
  );
  const absent = changing.length > 0
    ? changing[0].changes.find(([key]) => key.toLowerCase() === ABSENT_KEY)
    : undefined;
  report("changing: absent key reported as null", absent !== undefined && absent[1] === null);

  report(
    "constant: exactly one notification",
    constant.length === 1,
    `${constant.length} received`,
  );
  report(
    "constant: first notification has all keys",
    constant.length > 0 && sameKeys(keysOf(constant[0]), constantKeys),
    constant.length > 0 ? keysOf(constant[0]).join(",") : "none",
  );
}
