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

import { Buffer } from 'buffer';
import { default as now } from 'performance-now';
import { default as randombytes } from 'randombytes';
import Websocket from 'websocket';

import { default as wasm_base64 } from './autogen/wasm.js';

export async function start(chain_specs, json_rpc_callback) {
  var module;

  // List of environment variables to feed to the Rust program. An array of strings.
  // Example usage: `let env_vars = ["RUST_BACKTRACE=1", "RUST_LOG=foo"];`
  let env_vars = [];

  // Used below to store the list of all WebSockets.
  // The indices within this array are chosen by the Rust code.
  let websockets = {};

  // The actual Wasm bytecode is base64-decoded from a constant found in a different file.
  // This is suboptimal compared to using `instantiateStreaming`, but it is the most
  // cross-platform cross-bundler approach.
  let wasm_bytecode = new Uint8Array(Buffer.from(wasm_base64, 'base64'));

  // Start the Wasm virtual machine.
  // The Rust code defines a list of imports that must be fulfilled by the environment. The second
  // parameter provides their implementations.
  let result = await WebAssembly.instantiate(wasm_bytecode, {
    // The functions with the "substrate-lite" prefix are specific to substrate-lite.
    "substrate-lite": {
      // Must throw an error. A human-readable message can be found in the WebAssembly memory in the
      // given buffer.
      throw: (ptr, len) => {
        let message = Buffer.from(module.exports.memory.buffer).toString('utf8', ptr, ptr + len);
        throw message;
      },

      // Used by the Rust side to emit a JSON-RPC response or subscription notification.
      json_rpc_respond: (ptr, len) => {
        let message = Buffer.from(module.exports.memory.buffer).toString('utf8', ptr, ptr + len);
        if (json_rpc_callback) {
          json_rpc_callback(message);
        }
      },

      // Must return the UNIX time in milliseconds.
      unix_time_ms: () => Date.now(),

      // Must return the value of a monotonic clock in milliseconds.
      monotonic_clock_ms: () => now(),

      // Must call `timer_finished` after the given number of milliseconds has elapsed.
      start_timer: (id, ms) => {
        setTimeout(() => {
          module.exports.timer_finished(id);
        }, ms)
      },

      // Must create a new WebSocket object. This implementation stores the created object in
      // `websockets`.
      websocket_new: (id, url_ptr, url_len) => {
        try {
          let url = Buffer.from(module.exports.memory.buffer)
            .toString('utf8', url_ptr, url_ptr + url_len);

          if (!!websockets[id]) {
            throw "internal error: WebSocket already allocated";
          }

          let websocket = new Websocket.w3cwebsocket(url);
          websocket.binaryType = 'arraybuffer';

          websocket.onopen = () => {
            module.exports.websocket_open(id);
          };
          websocket.onclose = () => {
            module.exports.websocket_closed(id);
          };
          websocket.onmessage = (msg) => {
            let message = Buffer.from(msg.data);
            let ptr = module.exports.alloc(message.length);
            message.copy(Buffer.from(module.exports.memory.buffer), ptr);
            module.exports.websocket_message(id, ptr, message.length);
          };

          websockets[id] = websocket;
          return 0;

        } catch (error) {
          return 1;
        }
      },

      // Must close and destroy the WebSocket object.
      websocket_close: (id) => {
        let websocket = websockets[id];
        websocket.onopen = null;
        websocket.onclose = null;
        websocket.onmessage = null;
        websocket.onerror = null;
        websocket.close();
        websockets[id] = undefined;
      },

      // Must queue the data found in the WebAssembly memory at the given pointer. It is assumed
      // that this function is called only when the WebSocket is in an open state.
      websocket_send: (id, ptr, len) => {
        let data = Buffer.from(module.exports.memory.buffer).slice(ptr, ptr + len);
        websockets[id].send(data);
      }
    },

    // As the Rust code is compiled for wasi, some more wasi-specific imports exist.
    wasi_snapshot_preview1: {
      // Need to fill the buffer described by `ptr` and `len` with random data.
      // This data will be used in order to generate secrets. Do not use a dummy implementation!
      random_get: (ptr, len) => {
        let bytes = randombytes(len);
        bytes.copy(Buffer.from(module.exports.memory.buffer), ptr);
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
          let buf = mem.readUInt32LE(addr + 4 * i * 2);
          let buf_len = mem.readUInt32LE(addr + 4 * (i * 2 + 1));
          to_write += mem.toString('utf8', buf, buf + buf_len);
          total_length += buf_len;
        }

        // Note that it is questionnable to use `console.log` from within a library. However this
        // simply reflects the usage of `println!` in the Rust code. In other words, it is
        // `println!` that shouldn't be used in the first place. The harm of not showing text
        // printed with `println!` at all is greater than the harm possibly caused by accidentally
        // leaving a `println!` in the code.
        console.log(to_write);

        // Need to write in `out_ptr` how much data was "written".
        mem.writeUInt32LE(total_length, out_ptr);
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
        mem.writeUInt32LE(env_vars.length, argc_out);
        mem.writeUInt32LE(total_len, argv_buf_size_out);
        return 0;
      },

      // Write the environment variables to the given pointers.
      // `argv` is a pointer to a buffer that must be overwritten with a list of pointers to
      // environment variables, and `argv_buf` is a pointer to a buffer where to actually store the
      // environment variables.
      // The sizes of the buffers were determined by calling `environ_sizes_get`.
      environ_get: (argv, argv_buf) => {
        let mem = Buffer.from(module.exports.memory.buffer);

        let argv_pos = 0;
        let argv_buf_pos = 0;

        env_vars.forEach(env_var => {
          let env_var_len = Buffer.byteLength(e, 'utf8');

          mem.writeUInt32LE(argv_buf + argv_buf_pos, argv + argv_pos);
          argv_pos += 4;

          mem.write(env_var, argv_buf + argv_buf_pos, env_var_len, 'utf8');
          argv_buf_pos += env_var_len;
          mem.writeUInt8(0, argv_buf + argv_buf_pos);
          argv_buf_pos += 1;
        });

        return 0;
      },
    },
  });

  module = result.instance;

  let chain_specs_len = Buffer.byteLength(chain_specs, 'utf8');
  let chain_specs_ptr = module.exports.alloc(chain_specs_len);
  Buffer.from(module.exports.memory.buffer)
    .write(chain_specs, chain_specs_ptr);

  module.exports.init(chain_specs_ptr, chain_specs_len, 0, 0);

  return {
    send_json_rpc: (request) => {
      let len = Buffer.byteLength(request, 'utf8');
      let ptr = module.exports.alloc(len);
      Buffer.from(module.exports.memory.buffer).write(request, ptr);
      module.exports.json_rpc_send(ptr, len);
    }
  }
}
