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

// Tests for the stream-liveness check in `remote-instance.ts`: commands for a
// connection or substream that was already reset locally must be dropped,
// while commands for anything still live must get through.
//
// Stream id 0 is the interesting case, because it means two different things.
// It is the first substream of a multi-stream connection, and it is also what
// the wasm side reports for a single-stream connection, which has no substreams
// at all. Both directions of that ambiguity are covered below.
//
// No wasm and no browser involved: the test plays the server end of the
// `MessagePort` protocol by hand.

import test from "ava";
import { connectToInstanceServer } from "../dist/mjs/internals/remote-instance.js";

const WEBSOCKET_ADDRESS = { ty: "websocket", url: "ws://127.0.0.1:1" };
const WEBRTC_ADDRESS = {
  ty: "webrtc",
  targetPort: 1,
  ipVersion: "4",
  targetIp: "127.0.0.1",
  remoteTlsCertificateSha256: new Uint8Array(32),
};

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

// Opens connection 1 at the given address with the given substream ids
// reported open, then reset ids reported reset again — mirroring platform
// callbacks reaching client.ts.
async function withConnection({ instance, serverPort, flush }, address, openIds, resetIds) {
  serverPort.postMessage({ ty: "new-connection", connectionId: 1, address });
  await flush();
  for (const id of openIds) instance.streamOpened(1, id, "outbound");
  for (const id of resetIds) instance.streamReset(1, id, "test reset");
}

async function commandReaches(ty, { address, streamId, openIds = [], resetIds = [] }) {
  const ctx = await setup();
  await withConnection(ctx, address, openIds, resetIds);
  const message = ty === "stream-send"
    ? { ty, connectionId: 1, streamId, data: [new Uint8Array([1, 2, 3])] }
    : { ty, connectionId: 1, streamId };
  ctx.serverPort.postMessage(message);
  await ctx.flush();
  ctx.close();
  return ctx.events.some((e) => e.ty === ty && e.streamId === streamId);
}

const sendReaches = (opts) => commandReaches("stream-send", opts);
const sendCloseReaches = (opts) => commandReaches("stream-send-close", opts);

// Single-stream connections have no substreams, so `streamOpened` is never called for them and
// the live-substream set stays empty forever. The wasm side nonetheless reports stream id 0 for
// every write. Checking that 0 against the empty set would drop every write on the connection,
// which is issue #3342: the peer receives nothing, so it replies with nothing, and the libp2p
// handshake times out.

test("stream-send on a single-stream connection reaches the callback", async (t) => {
  t.true(await sendReaches({ address: WEBSOCKET_ADDRESS, streamId: 0 }));
});

test("stream-send-close on a single-stream connection reaches the callback", async (t) => {
  t.true(await sendCloseReaches({ address: WEBSOCKET_ADDRESS, streamId: 0 }));
});

test("stream-send on a reset single-stream connection is dropped", async (t) => {
  const ctx = await setup();
  await withConnection(ctx, WEBSOCKET_ADDRESS, [], []);
  ctx.instance.connectionReset(1, "test reset");
  ctx.serverPort.postMessage({
    ty: "stream-send",
    connectionId: 1,
    streamId: 0,
    data: [new Uint8Array([1, 2, 3])],
  });
  await ctx.flush();
  ctx.close();
  t.false(ctx.events.some((e) => e.ty === "stream-send"));
});

// Multi-stream connections do have substreams, reported open by the platform. A command for a
// substream that was already reset locally must be dropped, including for substream 0, which
// carries the Noise handshake. That is #3326.

test("stream-send for a live substream reaches the callback", async (t) => {
  t.true(await sendReaches({ address: WEBRTC_ADDRESS, streamId: 3, openIds: [3] }));
});

test("stream-send for a reset substream is dropped", async (t) => {
  t.false(await sendReaches({ address: WEBRTC_ADDRESS, streamId: 3, openIds: [3], resetIds: [3] }));
});

test("stream-send for reset substream 0 is dropped", async (t) => {
  t.false(await sendReaches({ address: WEBRTC_ADDRESS, streamId: 0, openIds: [0], resetIds: [0] }));
});

test("stream-send-close for reset substream 0 is dropped", async (t) => {
  t.false(await sendCloseReaches({ address: WEBRTC_ADDRESS, streamId: 0, openIds: [0], resetIds: [0] }));
});

test("stream-send for a never-opened substream is dropped", async (t) => {
  t.false(await sendReaches({ address: WEBRTC_ADDRESS, streamId: 0 }));
});
