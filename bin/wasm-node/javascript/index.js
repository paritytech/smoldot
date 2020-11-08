// Substrate-lite
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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

const fs = require('fs');
var source = fs.readFileSync('../../../target/wasm32-unknown-unknown/release/substrate_lite_js.wasm');

var typedArray = new Uint8Array(source);

var module;
WebAssembly.instantiate(typedArray, {
  "substrate-lite": {
    unix_time_ms: () => Math.round(Date.now()),
    monotonic_clock_ms: () => performance.now(),
    start_timer: (id, ms) => setTimeout(module.exports.timer_finished(id), ms),  // TODO:
    fill_random: (ptr, len) => crypto.randomFillSync(new Uint8Array()),
  }
}).then(result => {
    module = result.instance;
});
