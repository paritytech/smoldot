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
import { w3cwebsocket } from 'websocket';
import now from 'performance-now';
import * as compat from '../compat/index.js';
import { SmoldotWasmInstance } from './bindings.js';

export interface Config {
    instance?: SmoldotWasmInstance,
    logCallback: (level: number, target: string, message: string) => void,
    jsonRpcCallback: (response: string, chainId: number) => void,
    databaseContentCallback: (data: string, chainId: number) => void,
    forbidTcp: boolean,
    forbidWs: boolean,
    forbidNonLocalWs: boolean,
    forbidWss: boolean,
}

class ConnectionError extends Error {
    constructor(message: string) {
        super(message);
    }
}

interface TcpWrapped {
    ty: 'tcp',
    socket: compat.NodeJsSocket,
}

interface WebSocketWrapped {
    ty: 'websocket',
    socket: w3cwebsocket,
}

export default (config: Config): WebAssembly.ModuleImports => {
    // Used below to store the list of all connections.
    // The indices within this array are chosen by the Rust code.
    let connections: Record<number, TcpWrapped | WebSocketWrapped> = {};

    return {
        // Must exit with an error. A human-readable message can be found in the WebAssembly
        // memory in the given buffer.
        panic: (ptr: number, len: number) => {
            const instance = config.instance as SmoldotWasmInstance;

            ptr >>>= 0;
            len >>>= 0;

            const message = Buffer.from(instance.exports.memory.buffer).toString('utf8', ptr, ptr + len);
            throw new Error(message);
        },

        // Used by the Rust side to emit a JSON-RPC response or subscription notification.
        json_rpc_respond: (ptr: number, len: number, chainId: number) => {
            const instance = config.instance as SmoldotWasmInstance;

            ptr >>>= 0;
            len >>>= 0;

            let message = Buffer.from(instance.exports.memory.buffer).toString('utf8', ptr, ptr + len);
            if (config.jsonRpcCallback) {
                config.jsonRpcCallback(message, chainId);
            }
        },

        // Used by the Rust side in response to asking for the database content of a chain.
        database_content_ready: (ptr: number, len: number, chainId: number) => {
            const instance = config.instance as SmoldotWasmInstance;

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
            const instance = config.instance as SmoldotWasmInstance;

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
        monotonic_clock_ms: () => now(),

        // Must call `timer_finished` after the given number of milliseconds has elapsed.
        start_timer: (id: number, ms: number) => {
            const instance = config.instance as SmoldotWasmInstance;

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
        connection_new: (id: number, addr_ptr: number, addr_len: number, error_ptr_ptr: number) => {
            const instance = config.instance as SmoldotWasmInstance;

            addr_ptr >>>= 0;
            addr_len >>>= 0;
            error_ptr_ptr >>>= 0;

            if (!!connections[id]) {
                throw new Error("internal error: connection already allocated");
            }

            try {
                const addr = Buffer.from(instance.exports.memory.buffer)
                    .toString('utf8', addr_ptr, addr_ptr + addr_len);

                let connection: TcpWrapped | WebSocketWrapped;

                // Attempt to parse the multiaddress.
                // Note: peers can decide of the content of `addr`, meaning that it shouldn't be
                // trusted.
                const wsParsed = addr.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)\/(ws|wss)$/);
                const tcpParsed = addr.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)$/);

                if (wsParsed != null) {
                    let proto = 'wss';
                    if (wsParsed[4] == 'ws') {
                        proto = 'ws';
                    }
                    if (
                        (proto == 'ws' && config.forbidWs) ||
                        (proto == 'ws' && wsParsed[2] != 'localhost' && wsParsed[2] != '127.0.0.1' && config.forbidNonLocalWs) ||
                        (proto == 'wss' && config.forbidWss)
                    ) {
                        throw new ConnectionError('Connection type not allowed');
                    }

                    let url: string;
                    if (wsParsed[1] == 'ip6') {
                        url = proto + "://[" + wsParsed[2] + "]:" + wsParsed[3];
                    } else {
                        url = proto + "://" + wsParsed[2] + ":" + wsParsed[3];
                    }

                    connection = {
                        ty: 'websocket',
                        socket: new w3cwebsocket(url)
                    };
                    connection.socket.binaryType = 'arraybuffer';

                    connection.socket.onopen = () => {
                        instance.exports.connection_open(id);
                    };
                    connection.socket.onclose = (event) => {
                        const message = "Error code " + event.code + (!!event.reason ? (": " + event.reason) : "");
                        const len = Buffer.byteLength(message, 'utf8');
                        const ptr = instance.exports.alloc(len) >>> 0;
                        Buffer.from(instance.exports.memory.buffer).write(message, ptr);
                        instance.exports.connection_closed(id, ptr, len);
                    };
                    connection.socket.onmessage = (msg) => {
                        const message = Buffer.from(msg.data as ArrayBuffer);
                        const ptr = instance.exports.alloc(message.length) >>> 0;
                        message.copy(Buffer.from(instance.exports.memory.buffer), ptr);
                        instance.exports.connection_message(id, ptr, message.length);
                    };

                } else if (tcpParsed != null) {
                    // `net` module will be missing when we're not in NodeJS.
                    if (!compat.isTcpAvailable() || config.forbidTcp) {
                        throw new ConnectionError('TCP connections not available');
                    }

                    const socket = compat.createTcpConnection({
                        host: tcpParsed[2],
                        port: parseInt(tcpParsed[3], 10),
                    });

                    connection = { ty: 'tcp', socket };
                    connection.socket.setNoDelay();

                    connection.socket.on('connect', () => {
                        if (socket.destroyed) return;
                        instance.exports.connection_open(id);
                    });
                    connection.socket.on('close', (hasError) => {
                        if (socket.destroyed) return;
                        // NodeJS doesn't provide a reason why the closing happened, but only
                        // whether it was caused by an error.
                        const message = hasError ? "Error" : "Closed gracefully";
                        const len = Buffer.byteLength(message, 'utf8');
                        const ptr = instance.exports.alloc(len) >>> 0;
                        Buffer.from(instance.exports.memory.buffer).write(message, ptr);
                        instance.exports.connection_closed(id, ptr, len);
                    });
                    connection.socket.on('error', () => { });
                    connection.socket.on('data', (message) => {
                        if (socket.destroyed) return;
                        const ptr = instance.exports.alloc(message.length) >>> 0;
                        message.copy(Buffer.from(instance.exports.memory.buffer), ptr);
                        instance.exports.connection_message(id, ptr, message.length);
                    });

                } else {
                    throw new ConnectionError('Unrecognized multiaddr format');
                }

                connections[id] = connection;
                return 0;

            } catch (error) {
                const isBadAddress = error instanceof ConnectionError;
                let errorStr = "Unknown error";
                if (error instanceof Error) {
                    errorStr = error.toString();
                }
                const mem = Buffer.from(instance.exports.memory.buffer);
                const len = Buffer.byteLength(errorStr, 'utf8');
                const ptr = instance.exports.alloc(len) >>> 0;
                mem.write(errorStr, ptr);
                mem.writeUInt32LE(ptr, error_ptr_ptr);
                mem.writeUInt32LE(len, error_ptr_ptr + 4);
                mem.writeUInt8(isBadAddress ? 1 : 0, error_ptr_ptr + 8);
                return 1;
            }
        },

        // Must close and destroy the connection object.
        connection_close: (id: number) => {
            let connection = connections[id];
            if (connection.ty == 'websocket') {
                // WebSocket
                // We can't set these fields to null because the TypeScript definitions don't
                // allow it, but we can set them to dummy values.
                connection.socket.onopen = () => { };
                connection.socket.onclose = () => { };
                connection.socket.onmessage = () => { };
                connection.socket.onerror = () => { };
                connection.socket.close();
            } else {
                // TCP
                connection.socket.destroy();
            }
            delete connections[id];
        },

        // Must queue the data found in the WebAssembly memory at the given pointer. It is assumed
        // that this function is called only when the connection is in an open state.
        connection_send: (id: number, ptr: number, len: number) => {
            const instance = config.instance as SmoldotWasmInstance;

            ptr >>>= 0;
            len >>>= 0;

            let data = Buffer.from(instance.exports.memory.buffer).slice(ptr, ptr + len);
            let connection = connections[id];
            if (connection.ty == 'websocket') {
                // WebSocket
                connection.socket.send(data);
            } else {
                // TCP
                connection.socket.write(data);
            }
        }
    };
}
