// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

//! Exports a function that provides bindings for the bindings found in the Rust part of the code.
//!
//! In order to use this code, call the function passing an object, then fill the `instance` field
//! of that object with the Wasm instance.

import { Buffer } from 'buffer';
import * as compat from '../compat/index.js';
import * as connection from './connection.js';
import type { SmoldotWasmInstance } from './bindings.js';

export interface Config {
    instance?: SmoldotWasmInstance,
    logCallback: (level: number, target: string, message: string) => void,
    jsonRpcCallback: (response: string, chainId: number) => void,
    databaseContentCallback: (data: string, chainId: number) => void,
    currentTaskCallback?: (taskName: string | null) => void,
    forbidTcp: boolean,
    forbidWs: boolean,
    forbidNonLocalWs: boolean,
    forbidWss: boolean,
}

export default function (config: Config): compat.WasmModuleImports {
    // Used below to store the list of all connections.
    // The indices within this array are chosen by the Rust code.
    let connections: Record<number, connection.Connection> = {};

    return {
        // Must exit with an error. A human-readable message can be found in the WebAssembly
        // memory in the given buffer.
        panic: (ptr: number, len: number) => {
            const instance = config.instance!;

            ptr >>>= 0;
            len >>>= 0;

            const message = Buffer.from(instance.exports.memory.buffer).toString('utf8', ptr, ptr + len);
            throw new Error(message);
        },

        // Used by the Rust side to emit a JSON-RPC response or subscription notification.
        json_rpc_respond: (ptr: number, len: number, chainId: number) => {
            const instance = config.instance!;

            ptr >>>= 0;
            len >>>= 0;

            let message = Buffer.from(instance.exports.memory.buffer).toString('utf8', ptr, ptr + len);
            if (config.jsonRpcCallback) {
                config.jsonRpcCallback(message, chainId);
            }
        },

        // Used by the Rust side in response to asking for the database content of a chain.
        database_content_ready: (ptr: number, len: number, chainId: number) => {
            const instance = config.instance!;

            ptr >>>= 0;
            len >>>= 0;

            let content = Buffer.from(instance.exports.memory.buffer).toString('utf8', ptr, ptr + len);
            if (config.databaseContentCallback) {
                config.databaseContentCallback(content, chainId);
            }
        },

        // Used by the Rust side to emit a log entry.
        // See also the `max_log_level` parameter in the configuration.
        log: (level: number, targetPtr: number, targetLen: number, messagePtr: number, messageLen: number) => {
            const instance = config.instance!;

            targetPtr >>>= 0;
            targetLen >>>= 0;
            messagePtr >>>= 0;
            messageLen >>>= 0;

            if (config.logCallback) {
                let target = Buffer.from(instance.exports.memory.buffer)
                    .toString('utf8', targetPtr, targetPtr + targetLen);
                let message = Buffer.from(instance.exports.memory.buffer)
                    .toString('utf8', messagePtr, messagePtr + messageLen);
                config.logCallback(level, target, message);
            }
        },

        // Must return the UNIX time in milliseconds.
        unix_time_ms: () => Date.now(),

        // Must return the value of a monotonic clock in milliseconds.
        monotonic_clock_ms: () => compat.performanceNow(),

        // Must call `timer_finished` after the given number of milliseconds has elapsed.
        start_timer: (id: number, ms: number) => {
            const instance = config.instance!;

            // In both NodeJS and browsers, if `setTimeout` is called with a value larger than
            // 2147483647, the delay is for some reason instead set to 1.
            // As mentioned in the documentation of `start_timer`, it is acceptable to end the
            // timer before the given number of milliseconds has passed.
            if (ms > 2147483647)
                ms = 2147483647;

            // In browsers, `setTimeout` works as expected when `ms` equals 0. However, NodeJS
            // requires a minimum of 1 millisecond (if `0` is passed, it is automatically replaced
            // with `1`) and wants you to use `setImmediate` instead.
            if (ms == 0 && typeof setImmediate === "function") {
                setImmediate(() => {
                    instance.exports.timer_finished(id);
                })
            } else {
                setTimeout(() => {
                    instance.exports.timer_finished(id);
                }, ms)
            }
        },

        // Must create a new connection object. This implementation stores the created object in
        // `connections`.
        connection_new: (connectionId: number, addrPtr: number, addrLen: number, errorPtrPtr: number) => {
            const instance = config.instance!;

            addrPtr >>>= 0;
            addrLen >>>= 0;
            errorPtrPtr >>>= 0;

            if (!!connections[connectionId]) {
                throw new Error("internal error: connection already allocated");
            }

            try {
                const address = Buffer.from(instance.exports.memory.buffer)
                    .toString('utf8', addrPtr, addrPtr + addrLen);

                const connec = connection.connect({
                    address,
                    forbidTcp: config.forbidTcp,
                    forbidWs: config.forbidWs,
                    forbidNonLocalWs: config.forbidNonLocalWs,
                    forbidWss: config.forbidWss,
                    onOpen: () => {
                        instance.exports.connection_open_single_stream(connectionId);
                    },
                    onClose: (message: string) => {
                        const len = Buffer.byteLength(message, 'utf8');
                        const ptr = instance.exports.alloc(len) >>> 0;
                        Buffer.from(instance.exports.memory.buffer).write(message, ptr);
                        instance.exports.connection_closed(connectionId, ptr, len);
                    },
                    onMessage: (message: Buffer) => {
                        const ptr = instance.exports.alloc(message.length) >>> 0;
                        message.copy(Buffer.from(instance.exports.memory.buffer), ptr);
                        instance.exports.stream_message(connectionId, 0, ptr, message.length);
                    }
                });

                connections[connectionId] = connec;
                return 0;

            } catch (error) {
                const isBadAddress = error instanceof connection.ConnectionError;
                let errorStr = "Unknown error";
                if (error instanceof Error) {
                    errorStr = error.toString();
                }
                const mem = Buffer.from(instance.exports.memory.buffer);
                const len = Buffer.byteLength(errorStr, 'utf8');
                const ptr = instance.exports.alloc(len) >>> 0;
                mem.write(errorStr, ptr);
                mem.writeUInt32LE(ptr, errorPtrPtr);
                mem.writeUInt32LE(len, errorPtrPtr + 4);
                mem.writeUInt8(isBadAddress ? 1 : 0, errorPtrPtr + 8);
                return 1;
            }
        },

        // Must close and destroy the connection object.
        connection_close: (connectionId: number) => {
            const connection = connections[connectionId]!;
            connection.close();
            delete connections[connectionId];
        },

        // Opens a new substream on a multi-stream connection
        connection_stream_open: (_connectionId: number) => {
            // Given that multi-stream connections are never opened at the moment, this function
            // should never be called.
        },

        // Must queue the data found in the WebAssembly memory at the given pointer. It is assumed
        // that this function is called only when the connection is in an open state.
        stream_send: (connectionId: number, _streamId: number, ptr: number, len: number) => {
            const instance = config.instance!;

            ptr >>>= 0;
            len >>>= 0;

            const data = Buffer.from(instance.exports.memory.buffer).slice(ptr, ptr + len);
            const connection = connections[connectionId]!;
            connection.send(data);
        },

        current_task_entered: (ptr: number, len: number) => {
            const instance = config.instance!;

            ptr >>>= 0;
            len >>>= 0;

            const taskName = Buffer.from(instance.exports.memory.buffer).toString('utf8', ptr, ptr + len);
            if (config.currentTaskCallback)
                config.currentTaskCallback(taskName);
        },

        current_task_exit: () => {
            if (config.currentTaskCallback)
                config.currentTaskCallback(null);
        }
    };
}
