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

// Regression test for <https://github.com/paritytech/smoldot/issues/3322>:
// an `RTCDataChannel` can leave the `open` state before its `close` event is
// dispatched. Until that event runs (and reports the reset through
// `onStreamReset`), smoldot still believes the stream is writable and can
// issue a send, which used to throw an uncaught
// `InvalidStateError: RTCDataChannel.readyState is not 'open'`.
//
// The body injects that fault, then runs the plain smoke test unchanged. For
// the first few data channels: right after smoldot's `open` handler returns
// (so smoldot has been told the stream is open and writable), the channel is
// closed for real — `readyState` leaves `"open"` synchronously — and delivery
// of the resulting `close`/`error` event to smoldot's handler is delayed by a
// couple of seconds. smoldot's first write on a fresh substream (the
// multistream-select negotiation) is issued on a later task than the `open`
// event, so it lands inside that window and hits a genuinely non-open channel
// through the real `send` path. Without the `readyState` guard in
// `no-auto-bytecode-browser.ts` the browser throws and the client crashes;
// with it the write is dropped, the delayed `close` event resets the stream,
// and smoldot must recover and sync normally.
//
// Channels are intercepted at creation (`createDataChannel` for outbound,
// `ondatachannel` for inbound), before smoldot attaches its handlers. The
// first negotiated channel (the connection handshake) is left alone so the
// connection itself survives. A wrapped `readyState` getter counts smoldot
// consulting the guard inside the window, proving the race was actually
// exercised and not silently missed.
//
// Browser-only: the fault lives in browser-only code
// (`no-auto-bytecode-browser.ts`) and Node has no `RTCDataChannel`. The
// globals it patches only exist inside the page, so they are touched inside
// the function body (not at module top level), keeping the module importable
// by the Node runner, which reads only the re-exports below.

import smoke from "./smoke.js";

export { fileInputs, envInputs } from "./smoke.js";

// How many channels to force-close. Bounded so that, past the injection
// phase, substream churn stops and the client can sync unimpeded.
const MAX_INJECTED = 8;
// How long delivery of the `close`/`error` event is withheld from smoldot.
// This is the window during which smoldot believes a dead stream is writable.
const EVENT_DELAY_MS = 2000;

export default async function webrtcSendAfterClose(ctx) {
  if (ctx.host !== "browser") {
    throw new Error(
      `webrtc_send_after_close is browser-only (WebRTC), got host "${ctx.host}"`,
    );
  }

  const proto = RTCDataChannel.prototype;
  const origOpen = Object.getOwnPropertyDescriptor(proto, "onopen");
  const origClose = Object.getOwnPropertyDescriptor(proto, "onclose");
  const origError = Object.getOwnPropertyDescriptor(proto, "onerror");
  const origReadyState = Object.getOwnPropertyDescriptor(proto, "readyState");
  const origCloseFn = proto.close;

  let injected = 0;
  let guardReads = 0;

  const arm = (channel) => {
    // One record per armed channel: the handlers smoldot currently has
    // assigned (so a later `= null` cancels a pending delayed delivery) and
    // the injection state.
    const record = {
      openHandler: null,
      closeHandler: null,
      errorHandler: null,
      injected: false,
      delivered: false,
    };

    // After smoldot's `open` handler has told the wasm that the stream is
    // open and writable, close the channel for real. `readyState` leaves
    // `"open"` synchronously; smoldot's first write arrives on a later task
    // and finds a non-open channel.
    Object.defineProperty(channel, "onopen", {
      configurable: true,
      get: () => record.openHandler,
      set: (handler) => {
        record.openHandler = handler;
        origOpen.set.call(
          channel,
          handler === null
            ? null
            : (event) => {
                record.openHandler?.call(channel, event);
                if (
                  injected < MAX_INJECTED &&
                  origReadyState.get.call(channel) === "open"
                ) {
                  injected += 1;
                  record.injected = true;
                  origCloseFn.call(channel);
                }
              },
        );
      },
    });

    // Withhold the `close`/`error` event of an injected channel for
    // EVENT_DELAY_MS. If smoldot has since reset the stream itself (it
    // assigns `null` to the handler), the delivery is dropped, mirroring the
    // real handler-detach semantics. Deliver at most once.
    const wrapTeardownHandler = (desc, field) => {
      Object.defineProperty(
        channel,
        field === "closeHandler" ? "onclose" : "onerror",
        {
          configurable: true,
          get: () => record[field],
          set: (handler) => {
            record[field] = handler;
            desc.set.call(
              channel,
              handler === null
                ? null
                : (event) => {
                    if (!record.injected) {
                      record[field]?.call(channel, event);
                      return;
                    }
                    setTimeout(() => {
                      if (record.delivered) return;
                      const current = record[field];
                      if (current === null) return;
                      record.delivered = true;
                      current.call(channel, event);
                    }, EVENT_DELAY_MS);
                  },
            );
          },
        },
      );
    };
    wrapTeardownHandler(origClose, "closeHandler");
    wrapTeardownHandler(origError, "errorHandler");

    // Count smoldot observing a non-open state inside the window. With the
    // fix, the guard in `send` performs exactly this read before dropping the
    // data; without the fix nothing reads it and the native `send` throws.
    Object.defineProperty(channel, "readyState", {
      configurable: true,
      get: () => {
        const value = origReadyState.get.call(channel);
        if (record.injected && !record.delivered && value !== "open") {
          guardReads += 1;
        }
        return value;
      },
    });
  };

  const origCreate = RTCPeerConnection.prototype.createDataChannel;
  RTCPeerConnection.prototype.createDataChannel = function (...args) {
    const channel = origCreate.apply(this, args);
    // The negotiated channel carries the connection handshake; killing it
    // would tear down the whole connection rather than a single substream.
    if (args[1]?.negotiated !== true) arm(channel);
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
    // Both faults must actually have been exercised, otherwise the run proves
    // nothing. Reported even on failure so a mis-wired run fails loudly
    // instead of degrading into a plain smoke test.
    ctx.report(
      "channels force-closed after open",
      injected > 0,
      `${injected} substreams`,
    );
    ctx.report(
      "send attempted while channel not open",
      guardReads > 0,
      `${guardReads} guarded sends`,
    );
  }
}
