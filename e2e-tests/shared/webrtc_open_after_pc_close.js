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

// Regression test for <https://github.com/paritytech/smoldot/issues/3325>:
// an `RTCPeerConnection` can move to the `closed` state before the
// `connectionstatechange` event reporting it is dispatched. Until that event
// runs, smoldot still believes the connection is alive and can ask to open a
// substream; `createDataChannel()` then used to throw an uncaught
// `InvalidStateError` (connection-level twin of #3322).
//
// The body injects that fault, then runs the plain smoke test unchanged. On
// one connection: after a few outbound channels have been created (so the
// injection lands inside smoldot's substream-opening burst), the peer
// connection is closed for real — `signalingState` flips to `"closed"`
// synchronously. Browsers dispatch no events at all for a locally-closed
// connection, so the injection also synthesizes the late notification: after
// a couple of seconds it invokes smoldot's `connectionstatechange` handler,
// which reads the (genuinely closed) connection state and resets the
// connection. Everything smoldot does in between happens on a closed
// connection it believes is alive. Without the `signalingState` guard in
// `openOutSubstream` the next substream request crashes the client; with it
// the request is dropped, the synthesized event resets the connection, and
// smoldot must recover and sync normally.
//
// A wrapped `signalingState` getter counts smoldot consulting the guard
// inside the window, proving the race was actually exercised.
//
// Browser-only: the fault lives in browser-only code
// (`no-auto-bytecode-browser.ts`) and Node has no `RTCPeerConnection`. The
// globals it patches only exist inside the page, so they are touched inside
// the function body (not at module top level), keeping the module importable
// by the Node runner, which reads only the re-exports below.

import smoke from "./smoke.js";

export { fileInputs, envInputs } from "./smoke.js";

// Close the connection after this many outbound channels, so the injection
// lands mid-burst and smoldot's next `openOutSubstream` hits the window.
const CLOSE_AFTER_CHANNELS = 3;
// How long smoldot is left believing the closed connection is alive before
// the synthesized `connectionstatechange` notification is delivered.
const EVENT_DELAY_MS = 2000;
// How many connections to sabotage. One is enough to prove the point and
// leaves the rest of the network usable for syncing.
const MAX_INJECTED_PCS = 1;

export default async function webrtcOpenAfterPcClose(ctx) {
  if (ctx.host !== "browser") {
    throw new Error(
      `webrtc_open_after_pc_close is browser-only (WebRTC), got host "${ctx.host}"`,
    );
  }

  const OrigPC = RTCPeerConnection;
  const proto = OrigPC.prototype;
  const origCreate = proto.createDataChannel;
  const origClose = proto.close;
  const origSignaling = Object.getOwnPropertyDescriptor(proto, "signalingState");
  const origStateChange = Object.getOwnPropertyDescriptor(
    proto,
    "onconnectionstatechange",
  );

  let injectedPcs = 0;
  let guardReads = 0;

  const armPc = (pc) => {
    const record = { stateHandler: null, injected: false, delivered: false };
    let channelsCreated = 0;

    // Keep hold of whatever handler smoldot assigns, so the synthesized late
    // notification below can invoke it (or skip, if smoldot detached it).
    Object.defineProperty(pc, "onconnectionstatechange", {
      configurable: true,
      get: () => record.stateHandler,
      set: (handler) => {
        record.stateHandler = handler;
        origStateChange.set.call(pc, handler);
      },
    });

    // After the Nth outbound channel, close the connection for real —
    // `signalingState` leaves `"stable"` synchronously — and schedule the
    // late notification. Browsers fire no events for a local `close()`, so
    // the "event still pending" window of the real bug is modeled by
    // invoking smoldot's handler ourselves after EVENT_DELAY_MS; the handler
    // reads the genuinely-closed connection state and resets the connection.
    Object.defineProperty(pc, "createDataChannel", {
      configurable: true,
      value: (...args) => {
        const channel = origCreate.apply(pc, args);
        channelsCreated += 1;
        if (
          !record.injected &&
          injectedPcs < MAX_INJECTED_PCS &&
          channelsCreated >= CLOSE_AFTER_CHANNELS
        ) {
          injectedPcs += 1;
          record.injected = true;
          queueMicrotask(() => {
            origClose.call(pc);
            setTimeout(() => {
              if (record.delivered) return;
              const handler = record.stateHandler;
              if (handler === null) return;
              record.delivered = true;
              handler.call(pc, new Event("connectionstatechange"));
            }, EVENT_DELAY_MS);
          });
        }
        return channel;
      },
    });

    // Count smoldot observing the closed state inside the window. With the
    // fix, the guard in `openOutSubstream` performs exactly this read before
    // dropping the request; without the fix nothing reads it and the native
    // `createDataChannel` throws.
    Object.defineProperty(pc, "signalingState", {
      configurable: true,
      get: () => {
        const value = origSignaling.get.call(pc);
        if (record.injected && !record.delivered && value === "closed") {
          guardReads += 1;
        }
        return value;
      },
    });
  };

  globalThis.RTCPeerConnection = class extends OrigPC {
    constructor(...args) {
      super(...args);
      armPc(this);
    }
  };

  try {
    await smoke(ctx);
  } finally {
    // Both faults must actually have been exercised, otherwise the run proves
    // nothing. Reported even on failure so a mis-wired run fails loudly
    // instead of degrading into a plain smoke test.
    ctx.report(
      "peer connection force-closed mid-burst",
      injectedPcs > 0,
      `${injectedPcs} connections`,
    );
    ctx.report(
      "substream open attempted on closed connection",
      guardReads > 0,
      `${guardReads} guarded opens`,
    );
  }
}
