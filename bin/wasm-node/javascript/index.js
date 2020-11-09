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

const Buffer = require('buffer/').Buffer;  // Note: the trailing slash is important in order to use the NodeJS core module named "buffer".
const W3CWebSocket = require('websocket').w3cwebsocket;

// TODO: this should all be tested

// TODO: see https://www.npmjs.com/package/websocket#client-example-using-the-w3c-websocket-api

var module;
WebAssembly.instantiate(new Uint8Array(Buffer.from(require('./autogen/wasm.js'), 'base64')), {
  // The Rust code defines a list of imports that must be fulfilled by the environment.
  // This object provides their implementations.
  "substrate-lite": {
    unix_time_ms: () => Math.round(Date.now()),
    monotonic_clock_ms: () => performance.now(),
    start_timer: (id, ms) => setTimeout(module.exports.timer_finished(id), ms),  // TODO:
    fill_random: (ptr, len) => crypto.randomFillSync(new Uint8Array()),  // TODO: browserify
  }
}).then(result => {
    module = result.instance;
    console.log(module.exports.test());
});

console.log('test');
