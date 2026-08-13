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

// Tests for the stream-liveness check in `remote-instance.ts`.
//
// Commands for a connection or substream that was already reset locally must be
// dropped, while commands for anything still live must get through. Stream id 0
// is the interesting case, because it means two different things. It is the
// first substream of a multi-stream connection, and it is also what the wasm
// side reports for a single-stream connection, which has no substreams at all.
// Both directions of that ambiguity are covered below.
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
const PAYLOAD = [new Uint8Array([1, 2, 3])];

/**
 * Connects a client to a hand-driven fake server.
 *
 * The returned `instance` is the client `Instance`. Calling `streamOpened` and
 * `streamReset` on it stands in for what `client.ts` reports when the platform
 * fires the matching callbacks.
 */
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
  // untouched, which makes a posted sentinel a reliable "all previous messages
  // processed" barrier.
  let flushCount = 0;
  const flush = async () => {
    const ty = `__test_flush_${flushCount++}`;
    serverPort.postMessage({ ty });
    while (!events.some((e) => e.ty === ty)) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  };

  // Open ports keep the Node event loop alive. Close them so ava can exit.
  const close = () => {
    port1.close();
    port2.close();
    serverPort.close();
  };

  return { events, instance, serverPort, flush, close };
}

/**
 * Opens connection 1 at the given address, then reports substreams open and reset on it.
 *
 * Reporting mirrors the platform callbacks that reach `client.ts`.
 */
async function withConnection({ instance, serverPort, flush }, address, openIds = [], resetIds = []) {
  serverPort.postMessage({ ty: "new-connection", connectionId: 1, address });
  await flush();
  for (const id of openIds) instance.streamOpened(1, id, "outbound");
  for (const id of resetIds) instance.streamReset(1, id, "test reset");
}

const reached = (ctx, ty, streamId) =>
  ctx.events.some((e) => e.ty === ty && e.streamId === streamId);

// A single-stream connection has no substreams, so `streamOpened` is never
// called for it and the live-substream set stays empty forever. The wasm side
// nonetheless reports stream id 0 for every write. Checking that 0 against the
// empty set drops every write on the connection, which is issue #3342. The peer
// then receives nothing, so it answers nothing, and the handshake times out.

test("stream-send on a single-stream connection works", async (t) => {
  // Given
  const ctx = await setup();
  await withConnection(ctx, WEBSOCKET_ADDRESS);

  // When
  ctx.serverPort.postMessage({ ty: "stream-send", connectionId: 1, streamId: 0, data: PAYLOAD });
  await ctx.flush();

  // Then
  t.true(reached(ctx, "stream-send", 0));
  ctx.close();
});

test("stream-send-close on a single-stream connection works", async (t) => {
  // Given
  const ctx = await setup();
  await withConnection(ctx, WEBSOCKET_ADDRESS);

  // When
  ctx.serverPort.postMessage({ ty: "stream-send-close", connectionId: 1, streamId: 0 });
  await ctx.flush();

  // Then
  t.true(reached(ctx, "stream-send-close", 0));
  ctx.close();
});

test("stream-send on a reset single-stream connection fails", async (t) => {
  // Given
  const ctx = await setup();
  await withConnection(ctx, WEBSOCKET_ADDRESS);
  ctx.instance.connectionReset(1, "test reset");

  // When
  ctx.serverPort.postMessage({ ty: "stream-send", connectionId: 1, streamId: 0, data: PAYLOAD });
  await ctx.flush();

  // Then
  t.false(reached(ctx, "stream-send", 0));
  ctx.close();
});

// A multi-stream connection does have substreams, reported open by the
// platform. A command for a substream that was already reset locally must be
// dropped, including for substream 0, which carries the Noise handshake.

test("stream-send for a live substream works", async (t) => {
  // Given
  const ctx = await setup();
  await withConnection(ctx, WEBRTC_ADDRESS, [3]);

  // When
  ctx.serverPort.postMessage({ ty: "stream-send", connectionId: 1, streamId: 3, data: PAYLOAD });
  await ctx.flush();

  // Then
  t.true(reached(ctx, "stream-send", 3));
  ctx.close();
});

test("stream-send for a reset substream fails", async (t) => {
  // Given
  const ctx = await setup();
  await withConnection(ctx, WEBRTC_ADDRESS, [3], [3]);

  // When
  ctx.serverPort.postMessage({ ty: "stream-send", connectionId: 1, streamId: 3, data: PAYLOAD });
  await ctx.flush();

  // Then
  t.false(reached(ctx, "stream-send", 3));
  ctx.close();
});

test("stream-send for reset substream 0 fails", async (t) => {
  // Given
  const ctx = await setup();
  await withConnection(ctx, WEBRTC_ADDRESS, [0], [0]);

  // When
  ctx.serverPort.postMessage({ ty: "stream-send", connectionId: 1, streamId: 0, data: PAYLOAD });
  await ctx.flush();

  // Then
  t.false(reached(ctx, "stream-send", 0));
  ctx.close();
});

test("stream-send-close for reset substream 0 fails", async (t) => {
  // Given
  const ctx = await setup();
  await withConnection(ctx, WEBRTC_ADDRESS, [0], [0]);

  // When
  ctx.serverPort.postMessage({ ty: "stream-send-close", connectionId: 1, streamId: 0 });
  await ctx.flush();

  // Then
  t.false(reached(ctx, "stream-send-close", 0));
  ctx.close();
});

test("stream-send for a never-opened substream fails", async (t) => {
  // Given
  const ctx = await setup();
  await withConnection(ctx, WEBRTC_ADDRESS);

  // When
  ctx.serverPort.postMessage({ ty: "stream-send", connectionId: 1, streamId: 0, data: PAYLOAD });
  await ctx.flush();

  // Then
  t.false(reached(ctx, "stream-send", 0));
  ctx.close();
});
