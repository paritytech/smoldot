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

// Tests for the already-reset check in `remote-instance.ts`: commands arriving
// from the server (the wasm side) for a connection or stream that was already
// reset locally must be dropped, never forwarded to `eventCallback`.
// Regression coverage for stream id 0 — the first substream of every WebRTC
// connection — which a truthiness test (`message.streamId && ...`) exempted
// from the check.
//
// No wasm and no browser involved: the test plays the server end of the
// `MessagePort` protocol by hand.

import test from "ava";
import { connectToInstanceServer } from "../dist/mjs/internals/remote-instance.js";

// Sets up a client connected to a hand-driven fake server. Returns the
// captured events, the client `Instance` (whose `streamOpened`/`streamReset`
// stand in for what `client.ts` reports when the platform fires callbacks),
// and helpers to post server messages.
async function setup() {
  const { port1, port2 } = new MessageChannel();
  const events = [];

  const instancePromise = connectToInstanceServer({
    wasmModule: Promise.resolve({}),
    forbidTcp: false,
    forbidWs: false,
    forbidNonLocalWs: false,
    forbidWss: false,
    forbidWebRtc: false,
    maxLogLevel: 3,
    cpuRateLimit: 1,
    portToServer: port1,
    eventCallback: (event) => events.push(event),
  });

  const serverPort = await new Promise((resolve) => {
    port2.onmessage = (msg) => resolve(msg.data.serverToClient);
  });
  const instance = await instancePromise;

  // Unknown message types fall through the switch and reach `eventCallback`
  // untouched, which makes a posted sentinel a reliable "all previous
  // messages processed" barrier.
  let flushCount = 0;
  const flush = async () => {
    const ty = `__test_flush_${flushCount++}`;
    serverPort.postMessage({ ty });
    while (!events.some((e) => e.ty === ty)) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  };

  // Open ports keep the Node event loop alive; close them so ava can exit.
  const close = () => {
    port1.close();
    port2.close();
    serverPort.close();
  };

  return { events, instance, serverPort, flush, close };
}

// Opens connection 1 with the given stream ids reported open, then reset ids
// reported reset again — mirroring platform callbacks reaching client.ts.
async function withConnection({ instance, serverPort, flush }, openIds, resetIds) {
  serverPort.postMessage({
    ty: "new-connection",
    connectionId: 1,
    address: { ty: "websocket", url: "ws://127.0.0.1:1" },
  });
  await flush();
  for (const id of openIds) instance.streamOpened(1, id, "outbound");
  for (const id of resetIds) instance.streamReset(1, id, "test reset");
}

async function sendReaches(t, streamId, openIds, resetIds) {
  const ctx = await setup();
  await withConnection(ctx, openIds, resetIds);
  ctx.serverPort.postMessage({
    ty: "stream-send",
    connectionId: 1,
    streamId,
    data: [new Uint8Array([1, 2, 3])],
  });
  await ctx.flush();
  ctx.close();
  return ctx.events.some((e) => e.ty === "stream-send" && e.streamId === streamId);
}

test("stream-send for a live stream reaches the callback", async (t) => {
  t.true(await sendReaches(t, 3, [3], []));
});

test("stream-send for a reset stream is dropped", async (t) => {
  t.false(await sendReaches(t, 3, [3], [3]));
});

test("stream-send for reset stream 0 is dropped", async (t) => {
  t.false(await sendReaches(t, 0, [0], [0]));
});

test("stream-send-close for reset stream 0 is dropped", async (t) => {
  const ctx = await setup();
  await withConnection(ctx, [0], [0]);
  ctx.serverPort.postMessage({
    ty: "stream-send-close",
    connectionId: 1,
    streamId: 0,
  });
  await ctx.flush();
  ctx.close();
  t.false(ctx.events.some((e) => e.ty === "stream-send-close"));
});
