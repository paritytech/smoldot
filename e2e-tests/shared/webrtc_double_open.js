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
// browsers can deliver the `open` event of an `RTCDataChannel` more than
// once, and reporting the same stream id twice made the wasm panic with
// "same stream_id used multiple times in connection_stream_opened".
//
// The body is the smoke test unchanged; the scenario comes from the
// browser-host prepare extension (hosts/browser/prepare/webrtc_double_open.js)
// which dispatches a second genuine `open` event on every data channel after
// the real one, replaying the browser's double-fire through the real event
// machinery. The test passes iff smoldot still syncs normally under that
// fault.
//
// Browser-only: the fault lives in browser-only code
// (`no-auto-bytecode-browser.ts`) and Node has no `RTCDataChannel`. The
// guards below make a mis-wired run fail loudly instead of passing as a
// plain smoke test.

import smoke from "./smoke.js";

export { fileInputs, envInputs } from "./smoke.js";

export default async function webrtcDoubleOpen(ctx) {
  if (ctx.host !== "browser") {
    throw new Error(
      `webrtc_double_open only makes sense on the browser host (WebRTC), got host "${ctx.host}"`,
    );
  }
  if (ctx.webrtcDoubleOpenArmed !== true) {
    throw new Error(
      "fault injection is not armed: hosts/browser/prepare/webrtc_double_open.js did not run",
    );
  }
  return smoke(ctx);
}
