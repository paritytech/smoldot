"use strict";
// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
Object.defineProperty(exports, "__esModule", { value: true });
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
//! Exports a function that provides bindings for the Wasi interface.
//!
//! These bindings can then be used by the Wasm virtual machine to invoke Wasi-related functions.
//! See <https://wasi.dev/>.
//!
//! In order to use this code, call the function passing an object, then fill the `instance` field
//! of that object with the Wasm instance.
const buffer = require("./buffer.js");
exports.default = (config) => {
    // Buffers holding temporary data being written by the Rust code to respectively stdout and
    // stderr.
    let stdoutBuffer = "";
    let stderrBuffer = "";
    return {
        // Need to fill the buffer described by `ptr` and `len` with random data.
        // This data will be used in order to generate secrets. Do not use a dummy implementation!
        random_get: (ptr, len) => {
            const instance = config.instance;
            ptr >>>= 0;
            len >>>= 0;
            const baseBuffer = new Uint8Array(instance.exports.memory.buffer)
                .slice(ptr, ptr + len);
            for (let iter = 0; iter < len; iter += 65536) {
                // `baseBuffer.slice` automatically saturates at the end of the buffer
                config.getRandomValues(baseBuffer.slice(iter, iter + 65536));
            }
            return 0;
        },
        // Writing to a file descriptor is used in order to write to stdout/stderr.
        fd_write: (fd, addr, num, outPtr) => {
            const instance = config.instance;
            outPtr >>>= 0;
            // Only stdout and stderr are open for writing.
            if (fd != 1 && fd != 2) {
                return 8;
            }
            const mem = new Uint8Array(instance.exports.memory.buffer);
            // `fd_write` passes a buffer containing itself a list of pointers and lengths to the
            // actual buffers. See writev(2).
            let toWrite = "";
            let totalLength = 0;
            for (let i = 0; i < num; i++) {
                const buf = buffer.readUInt32LE(mem, addr + 4 * i * 2);
                const bufLen = buffer.readUInt32LE(mem, addr + 4 * (i * 2 + 1));
                toWrite += buffer.utf8BytesToString(mem, buf, bufLen);
                totalLength += bufLen;
            }
            const flushBuffer = (string) => {
                // As documented in the documentation of `println!`, lines are always split by a
                // single `\n` in Rust.
                while (true) {
                    const index = string.indexOf('\n');
                    if (index != -1) {
                        // Note that it is questionnable to use `console.log` from within a
                        // library. However this simply reflects the usage of `println!` in the
                        // Rust code. In other words, it is `println!` that shouldn't be used in
                        // the first place. The harm of not showing text printed with `println!`
                        // at all is greater than the harm possibly caused by accidentally leaving
                        // a `println!` in the code.
                        console.log(string.substring(0, index));
                        string = string.substring(index + 1);
                    }
                    else {
                        return string;
                    }
                }
            };
            // Append the newly-written data to either `stdout_buffer` or `stderr_buffer`, and
            // print their content if necessary.
            if (fd == 1) {
                stdoutBuffer += toWrite;
                stdoutBuffer = flushBuffer(stdoutBuffer);
            }
            else if (fd == 2) {
                stderrBuffer += toWrite;
                stderrBuffer = flushBuffer(stderrBuffer);
            }
            // Need to write in `out_ptr` how much data was "written".
            buffer.writeUInt32LE(mem, outPtr, totalLength);
            return 0;
        },
        // It's unclear how to properly implement yielding, but a no-op works fine as well.
        sched_yield: () => {
            return 0;
        },
        // Used by Rust in catastrophic situations, such as a double panic.
        proc_exit: (retCode) => {
            config.onProcExit(retCode);
        },
        // Return the number of environment variables and the total size of all environment
        // variables. This is called in order to initialize buffers before `environ_get`.
        environ_sizes_get: (argcOut, argvBufSizeOut) => {
            const instance = config.instance;
            argcOut >>>= 0;
            argvBufSizeOut >>>= 0;
            let totalLen = 0;
            config.envVars.forEach(e => totalLen += new TextEncoder().encode(e).length + 1); // +1 for trailing \0
            const mem = new Uint8Array(instance.exports.memory.buffer);
            buffer.writeUInt32LE(mem, argcOut, config.envVars.length);
            buffer.writeUInt32LE(mem, argvBufSizeOut, totalLen);
            return 0;
        },
        // Write the environment variables to the given pointers.
        // `argv` is a pointer to a buffer that must be overwritten with a list of pointers to
        // environment variables, and `argvBuf` is a pointer to a buffer where to actually store
        // the environment variables.
        // The sizes of the buffers were determined by calling `environ_sizes_get`.
        environ_get: (argv, argvBuf) => {
            const instance = config.instance;
            argv >>>= 0;
            argvBuf >>>= 0;
            const mem = new Uint8Array(instance.exports.memory.buffer);
            let argvPos = 0;
            let argvBufPos = 0;
            config.envVars.forEach(envVar => {
                const encoded = new TextEncoder().encode(envVar);
                buffer.writeUInt32LE(mem, argv + argvPos, argvBuf + argvBufPos);
                argvPos += 4;
                mem.set(encoded, argvBuf + argvBufPos);
                argvBufPos += encoded.length;
                buffer.writeUInt8(mem, argvBuf + argvBufPos, 0);
                argvBufPos += 1;
            });
            return 0;
        },
    };
};
