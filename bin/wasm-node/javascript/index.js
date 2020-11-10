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
const crypto = require('crypto-browserify');
const W3CWebSocket = require('websocket').w3cwebsocket;

// TODO: this should all be tested

// TODO: see https://www.npmjs.com/package/websocket#client-example-using-the-w3c-websocket-api

var module;
var memory;

// List of environment variables. An array of strings.
// Example usage: `let env_vars = ["RUST_BACKTRACE=1"];`
let env_vars = [];

WebAssembly.instantiate(new Uint8Array(Buffer.from(require('./autogen/wasm.js'), 'base64')), {
  // The Rust code defines a list of imports that must be fulfilled by the environment.
  // This object provides their implementations.
  "substrate-lite": {
    throw: (ptr, len) => {
      let message = Buffer.from(module.exports.memory.buffer)
        .toString('utf8', ptr, ptr + len);
      console.error("Throwed: " + message);  // TODO: keep or not?
      throw message;
    },
    unix_time_ms: () => Math.round(Date.now()),
    monotonic_clock_ms: () => performance.now(),
    start_timer: (id, ms) => {
      setTimeout(() => {
        module.exports.timer_finished(id);
      }, ms)
    },
  },

  // As the Rust code is compiled for wasi, some more wasi-specific imports exist.
  wasi_snapshot_preview1: {
    // Need to fill the buffer described by `ptr` and `len` with random data.
    // This data will be used in order to generate secrets. Do not use a dummy implementation!
    random_get: (ptr, len) => {
      crypto.randomFillSync(new Uint8Array(module.exports.memory.buffer), ptr, len);
      return 0;
    },

    // Writing to a file descriptor is used in order to write to stdout/stderr.
    fd_write: (fd, addr, num, out_ptr) => {
      // Only stdout and stderr are open for writing.
      if (fd != 1 && fd != 2) {
        return 8;
      }

      let mem = Buffer.from(module.exports.memory.buffer);

      // `fd_write` passes a buffer containing itself a list of pointers and lengths to the actual
      // buffers. See writev(2).
      let to_write = new String("");
      let total_length = 0;
      for (let i = 0; i < num; i++) {
        let buf = mem.readInt32LE(addr + 4 * i * 2);
        let buf_len = mem.readInt32LE(addr + 4 * (i * 2 + 1));
        to_write += mem.toString('utf8', buf, buf + buf_len);
        total_length += buf_len;
      }

      // TODO: keep this line?
      console.log(to_write);

      // Need to write in `out_ptr` how much data was "written".
      mem.writeInt32LE(total_length, out_ptr);
      return 0;
    },
  
    // It's unclear how to properly implement yielding, but a no-op works fine as well.
    sched_yield: () => {
      return 0;
    },

    // Used by Rust in catastrophic situations, such as a double panic.
    proc_exit: (ret_code) => {
      // This should ideally also clean up all resources (such as WebSockets and active timers),
      // but it is assumed that this function isn't going to be called anyway.
      throw "proc_exit called: " + ret_code;
    },

    // Return the number of environment variables and the total size of all environment variables.
    // This is called in order to initialize buffers before `environ_get`.
    environ_sizes_get: (argc_out, argv_buf_size_out) => {
      let total_len = 0;
      env_vars.forEach(e => total_len += Buffer.byteLength(e, 'utf8') + 1); // +1 for trailing \0

      let mem = Buffer.from(module.exports.memory.buffer);
      mem.writeInt32LE(env_vars.length, argc_out);
      mem.writeInt32LE(total_len, argv_buf_size_out);
      return 0;
    },

    // Write the environment variables to the given pointers.
    // `argv` must be written with a list of pointers to environment variables, and `argv_buf` is
    // a buffer where to actually write the environment variables.
    environ_get: (argv, argv_buf) => {
      let mem = Buffer.from(module.exports.memory.buffer);

      let argv_pos = 0;
      let argv_buf_pos = 0;

      env_vars.forEach(env_var => {
        let env_var_len = Buffer.byteLength(e, 'utf8');

        mem.writeInt32LE(argv_buf + argv_buf_pos, argv + argv_pos);
        argv_pos += 4;

        mem.write(env_var, argv_buf + argv_buf_pos, env_var_len, 'utf8');
        argv_buf_pos += env_var_len;
        mem.writeUInt8(0, argv_buf + argv_buf_pos);
        argv_buf_pos += 1;
      });

      return 0;
    },
  },
}).then(result => {
  module = result.instance;

  let chain_specs = require('atob')(require('./example_chain.js')); // TODO: just an example; remove both example_chain.js and the atob dependency

  let chain_specs_len = Buffer.byteLength(chain_specs, 'utf8');
  let chain_specs_ptr = module.exports.alloc(chain_specs_len);
  Buffer.from(module.exports.memory.buffer)
    .write(chain_specs, chain_specs_ptr);

  module.exports.init(chain_specs_ptr, chain_specs_len, 0, 0);
});

// TODO: add catch()
