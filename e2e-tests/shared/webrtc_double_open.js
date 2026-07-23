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

// Regression test for <https://github.com/paritytech/smoldot/issues/3305>:
// browsers can deliver the `open` event of an `RTCDataChannel` more than once,
// and reporting the same stream id twice made the wasm panic with
// "same stream_id used multiple times in connection_stream_opened".
//
// The body injects that fault, then runs the plain smoke test unchanged: after
// each data channel delivers its genuine `open` event, a second `open` event is
// dispatched on the same channel from a separate task. This replays what the
// browser itself does when it double-fires (MDN: the event fires when the
// transport "is opened or reopened") through the real event machinery — real
// channel, real dispatch path, `readyState === "open"` — so smoldot's handler
// cannot tell it apart from a native duplicate. Channels are intercepted at
// creation (`createDataChannel` for outbound, `ondatachannel` for inbound),
// before smoldot attaches its handlers. The test passes iff smoldot still syncs
// normally under that fault.
//
// Browser-only: the fault lives in browser-only code
// (`no-auto-bytecode-browser.ts`) and Node has no `RTCDataChannel`. The globals
// it patches only exist inside the page, so they are touched inside the
// function body (not at module top level), keeping the module importable by the
// Node runner, which reads only the re-exports below.

import smoke from "./smoke.js";

export { fileInputs, envInputs } from "./smoke.js";

export default async function webrtcDoubleOpen(ctx) {
  if (ctx.host !== "browser") {
    throw new Error(
      `webrtc_double_open is browser-only (WebRTC), got host "${ctx.host}"`,
    );
  }

  let duplicatesDelivered = 0;

  const arm = (channel) => {
    channel.addEventListener("open", function once() {
      channel.removeEventListener("open", once);
      setTimeout(() => {
        // The channel may have been closed and its handlers detached in the
        // meantime; a duplicate `open` on a dead channel is not the scenario.
        if (channel.readyState !== "open") return;
        duplicatesDelivered += 1;
        channel.dispatchEvent(new Event("open"));
      }, 0);
    });
  };

  const origCreate = RTCPeerConnection.prototype.createDataChannel;
  RTCPeerConnection.prototype.createDataChannel = function (...args) {
    const channel = origCreate.apply(this, args);
    arm(channel);
    return channel;
  };

  const dcDesc = Object.getOwnPropertyDescriptor(
    RTCPeerConnection.prototype,
    "ondatachannel",
  );
  Object.defineProperty(RTCPeerConnection.prototype, "ondatachannel", {
    configurable: true,
    get: dcDesc.get,
    set(handler) {
      if (handler === null) {
        dcDesc.set.call(this, null);
        return;
      }
      dcDesc.set.call(this, (event) => {
        arm(event.channel);
        handler.call(this, event);
      });
    },
  });

  try {
    await smoke(ctx);
  } finally {
    // The fault must actually have been exercised, otherwise the run proves
    // nothing. Reported even on failure so a mis-wired run fails loudly instead
    // of degrading into a plain smoke test.
    ctx.report(
      "duplicate RTCDataChannel open events delivered",
      duplicatesDelivered > 0,
      `${duplicatesDelivered} substreams`,
    );
  }
}
