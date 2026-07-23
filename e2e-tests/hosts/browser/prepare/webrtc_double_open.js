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

// Browser-host fault injection for issue #3305: after each `RTCDataChannel`
// delivers its genuine `open` event, dispatch a second `open` event on the
// same channel from a separate task. This replays what the browser itself
// does when it double-fires (MDN: the event fires when the transport "is
// opened or reopened") through the real event machinery — real channel, real
// dispatch path, `readyState === "open"` — so smoldot's handler cannot tell
// it apart from a native duplicate. Channels are intercepted at creation
// (`createDataChannel` for outbound, `ondatachannel` for inbound), before
// smoldot attaches its handlers.

export default async function prepare(ctx) {
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

  const innerCleanup = ctx.cleanup;
  return {
    ...ctx,
    // Checked by the shared body so a run without this extension fails
    // loudly instead of degrading into a plain smoke test.
    webrtcDoubleOpenArmed: true,
    cleanup: async () => {
      // The fault must actually have been exercised, otherwise the run
      // proves nothing.
      ctx.report(
        "duplicate RTCDataChannel open events delivered",
        duplicatesDelivered > 0,
        `${duplicatesDelivered} substreams`,
      );
      await innerCleanup?.();
    },
  };
}
