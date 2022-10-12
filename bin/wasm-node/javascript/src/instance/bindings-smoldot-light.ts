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

import * as buffer from './buffer.js';
import type { SmoldotWasmInstance } from './bindings.js';

export interface Config {
    instance?: SmoldotWasmInstance,

    /**
     * Returns the number of milliseconds since an arbitrary epoch.
     */
    performanceNow: () => number,

    /**
     * Tries to open a new connection using the given configuration.
     *
     * @see Connection
     * @throws {@link ConnectionError} If the multiaddress couldn't be parsed or contains an invalid protocol.
     */
    connect(config: ConnectionConfig): Connection;
    
    /**
     * Closure to call when the Wasm instance calls `panic`.
     *
     * This callback will always be invoked from within a binding called the Wasm instance.
     */
    onPanic: (message: string) => never,
    
    logCallback: (level: number, target: string, message: string) => void,
    jsonRpcResponsesNonEmptyCallback: (chainId: number) => void,
    currentTaskCallback?: (taskName: string | null) => void,
}

/**
 * Connection to a remote node.
 *
 * At any time, a connection can be in one of the three following states:
 *
 * - `Opening` (initial state)
 * - `Open`
 * - `Closed`
 *
 * When in the `Opening` or `Open` state, the connection can transition to the `Closed` state
 * if the remote closes the connection or refuses the connection altogether. When that
 * happens, `config.onClosed` is called. Once in the `Closed` state, the connection cannot
 * transition back to another state.
 *
 * Initially in the `Opening` state, the connection can transition to the `Open` state if the
 * remote accepts the connection. When that happens, `config.onOpen` is called.
 *
 * When in the `Open` state, the connection can receive messages. When a message is received,
 * `config.onMessage` is called.
 *
 * @see connect
 */
 export interface Connection {
    /**
     * Transitions the connection or one of its substreams to the `Closed` state.
     *
     * If the connection is of type "single-stream", the whole connection must be shut down.
     * If the connection is of type "multi-stream", a `streamId` can be provided, in which case
     * only the given substream is shut down.
     *
     * The `config.onClose` or `config.onStreamClose` callbacks are **not** called.
     *
     * The transition is performed in the background.
     * If the whole connection is to be shut down, none of the callbacks passed to the `Config`
     * must be called again. If only a substream is shut down, the `onStreamClose` and `onMessage`
     * callbacks must not be called again with that substream.
     */
    close(streamId?: number): void;

    /**
     * Queues data to be sent on the given connection.
     *
     * The connection must currently be in the `Open` state.
     *
     * The `streamId` must be provided if and only if the connection is of type "multi-stream".
     * It indicates which substream to send the data on.
     */
    send(data: Uint8Array, streamId?: number): void;

    /**
     * Start opening an additional outbound substream on the given connection.
     *
     * The state of the connection must be `Open`. This function must only be called for
     * connections of type "multi-stream".
     *
     * The `onStreamOpened` callback must later be called with an outbound direction.
     */
    openOutSubstream(): void;
}

/**
 * Configuration for a connection.
 *
 * @see connect
 */
export interface ConnectionConfig {
    /**
     * Multiaddress in string format that describes which node to try to connect to.
     *
     * Note that this address shouldn't be trusted. The value in this field might have been chosen
     * by a potentially malicious peer.
     */
    address: string,

    /**
     * Callback called when the connection transitions from the `Opening` to the `Open` state.
     *
     * Must only be called once per connection.
     */
    onOpen: (info:
        { type: 'single-stream', handshake: 'multistream-select-noise-yamux' } |
        { type: 'multi-stream', handshake: 'webrtc', 
            localTlsCertificateMultihash: Uint8Array,
            remoteTlsCertificateMultihash: Uint8Array,
        }
    ) => void;

    /**
     * Callback called when the connection transitions to the `Closed` state.
     *
     * It it **not** called if `Connection.close` is manually called by the API user.
     */
    onConnectionClose: (message: string) => void;

    /**
     * Callback called when a new substream has been opened.
     *
     * This function must only be called for connections of type "multi-stream".
     */
    onStreamOpened: (streamId: number, direction: 'inbound' | 'outbound') => void;

    /**
     * Callback called when a stream transitions to the `Closed` state.
     *
     * It it **not** called if `Connection.closeStream` is manually called by the API user.
     *
     * This function must only be called for connections of type "multi-stream".
     */
    onStreamClose: (streamId: number) => void;

    /**
     * Callback called when a message sent by the remote has been received.
     *
     * Can only happen while the connection is in the `Open` state.
     *
     * The `streamId` parameter must be provided if and only if the connection is of type
     * "multi-stream".
     */
    onMessage: (message: Uint8Array, streamId?: number) => void;
}

/**
 * Emitted by `connect` if the multiaddress couldn't be parsed or contains an invalid protocol.
 *
 * @see connect
 */
export class ConnectionError extends Error {
    constructor(message: string) {
        super(message);
    }
}

export default function (config: Config): { imports: WebAssembly.ModuleImports, killAll: () => void } {
    // Used below to store the list of all connections.
    // The indices within this array are chosen by the Rust code.
    let connections: Record<number, Connection> = {};

    // Object containing a boolean indicating whether the `killAll` function has been invoked by
    // the user.
    const killedTracked = { killed: false };

    const killAll = () => {
        killedTracked.killed = true;
        // TODO: kill timers as well?
        for (const connection in connections) {
            connections[connection]!.close()
            delete connections[connection]
        }
    };

    const imports = {
        // Must exit with an error. A human-readable message can be found in the WebAssembly
        // memory in the given buffer.
        panic: (ptr: number, len: number) => {
            const instance = config.instance!;

            ptr >>>= 0;
            len >>>= 0;

            const message = buffer.utf8BytesToString(new Uint8Array(instance.exports.memory.buffer), ptr, len);
            config.onPanic(message);
        },

        // Used by the Rust side to notify that a JSON-RPC response or subscription notification
        // is available in the queue of JSON-RPC responses.
        json_rpc_responses_non_empty: (chainId: number) => {
            if (killedTracked.killed) return;
            config.jsonRpcResponsesNonEmptyCallback(chainId);
        },

        // Used by the Rust side to emit a log entry.
        // See also the `max_log_level` parameter in the configuration.
        log: (level: number, targetPtr: number, targetLen: number, messagePtr: number, messageLen: number) => {
            if (killedTracked.killed) return;

            const instance = config.instance!;

            targetPtr >>>= 0;
            targetLen >>>= 0;
            messagePtr >>>= 0;
            messageLen >>>= 0;

            if (config.logCallback) {
                const mem = new Uint8Array(instance.exports.memory.buffer);
                let target = buffer.utf8BytesToString(mem, targetPtr, targetLen);
                let message = buffer.utf8BytesToString(mem, messagePtr, messageLen);
                config.logCallback(level, target, message);
            }
        },

        // Must return the UNIX time in milliseconds.
        unix_time_ms: () => Date.now(),

        // Must return the value of a monotonic clock in milliseconds.
        monotonic_clock_ms: () => config.performanceNow(),

        // Must call `timer_finished` after the given number of milliseconds has elapsed.
        start_timer: (id: number, ms: number) => {
            if (killedTracked.killed) return;

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
                    if (killedTracked.killed) return;
                    try {
                        instance.exports.timer_finished(id);
                    } catch(_error) {}
                })
            } else {
                setTimeout(() => {
                    if (killedTracked.killed) return;
                    try {
                        instance.exports.timer_finished(id);
                    } catch(_error) {}
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
                if (killedTracked.killed)
                    throw new Error("killAll invoked");

                const address = buffer.utf8BytesToString(new Uint8Array(instance.exports.memory.buffer), addrPtr, addrLen);

                const connec = config.connect({
                    address,
                    onOpen: (info) => {
                        if (killedTracked.killed) return;
                        try {
                            switch (info.type) {
                                case 'single-stream': {
                                    instance.exports.connection_open_single_stream(connectionId, 0);
                                    break
                                }
                                case 'multi-stream': {
                                    const bufferLen = 1 + info.localTlsCertificateMultihash.length + info.remoteTlsCertificateMultihash.length;
                                    const ptr = instance.exports.alloc(bufferLen) >>> 0;
                                    const mem = new Uint8Array(instance.exports.memory.buffer);
                                    buffer.writeUInt8(mem, ptr, 0);
                                    mem.set(info.localTlsCertificateMultihash, ptr + 1)
                                    mem.set(info.remoteTlsCertificateMultihash, ptr + 1 + info.localTlsCertificateMultihash.length)
                                    instance.exports.connection_open_multi_stream(connectionId, ptr, bufferLen);
                                    break
                                }
                            }
                        } catch(_error) {}
                    },
                    onConnectionClose: (message: string) => {
                        if (killedTracked.killed) return;
                        try {
                            const encoded = new TextEncoder().encode(message)
                            const ptr = instance.exports.alloc(encoded.length) >>> 0;
                            new Uint8Array(instance.exports.memory.buffer).set(encoded, ptr);
                            instance.exports.connection_closed(connectionId, ptr, encoded.length);
                        } catch(_error) {}
                    },
                    onMessage: (message: Uint8Array, streamId?: number) => {
                        if (killedTracked.killed) return;
                        try {
                            const ptr = instance.exports.alloc(message.length) >>> 0;
                            new Uint8Array(instance.exports.memory.buffer).set(message, ptr)
                            instance.exports.stream_message(connectionId, streamId || 0, ptr, message.length);
                        } catch(_error) {}
                    },
                    onStreamOpened: (streamId: number, direction: 'inbound' | 'outbound') => {
                        if (killedTracked.killed) return;
                        try {
                            instance.exports.connection_stream_opened(
                                connectionId,
                                streamId,
                                direction === 'outbound' ? 1 : 0
                            );
                        } catch(_error) {}
                    },
                    onStreamClose: (streamId: number) => {
                        if (killedTracked.killed) return;
                        try {
                            instance.exports.stream_closed(connectionId, streamId);
                        } catch(_error) {}
                    }
                
                });

                connections[connectionId] = connec;
                return 0;

            } catch (error) {
                const isBadAddress = error instanceof ConnectionError;
                let errorStr = "Unknown error";
                if (error instanceof Error) {
                    errorStr = error.toString();
                }
                const mem = new Uint8Array(instance.exports.memory.buffer);
                const encoded = new TextEncoder().encode(errorStr)
                const ptr = instance.exports.alloc(encoded.length) >>> 0;
                mem.set(encoded, ptr);
                buffer.writeUInt32LE(mem, errorPtrPtr, ptr);
                buffer.writeUInt32LE(mem, errorPtrPtr + 4, encoded.length);
                buffer.writeUInt8(mem, errorPtrPtr + 8, isBadAddress ? 1 : 0);
                return 1;
            }
        },

        // Must close and destroy the connection object.
        connection_close: (connectionId: number) => {
            if (killedTracked.killed) return;
            const connection = connections[connectionId]!;
            connection.close();
            delete connections[connectionId];
        },

        // Opens a new substream on a multi-stream connection.
        connection_stream_open: (connectionId: number) => {
            const connection = connections[connectionId]!;
            connection.openOutSubstream()
        },

        // Closes a substream on a multi-stream connection.
        connection_stream_close: (connectionId: number, streamId: number) => {
            const connection = connections[connectionId]!;
            connection.close(streamId)
        },

        // Must queue the data found in the WebAssembly memory at the given pointer. It is assumed
        // that this function is called only when the connection is in an open state.
        stream_send: (connectionId: number, streamId: number, ptr: number, len: number) => {
            if (killedTracked.killed) return;
    
            const instance = config.instance!;

            ptr >>>= 0;
            len >>>= 0;

            const data = new Uint8Array(instance.exports.memory.buffer).slice(ptr, ptr + len);
            const connection = connections[connectionId]!;
            connection.send(data, streamId);  // TODO: docs says the streamId is provided only for multi-stream connections, but here it's always provided
        },

        current_task_entered: (ptr: number, len: number) => {
            if (killedTracked.killed) return;

            const instance = config.instance!;

            ptr >>>= 0;
            len >>>= 0;

            const taskName = buffer.utf8BytesToString(new Uint8Array(instance.exports.memory.buffer), ptr, len);
            if (config.currentTaskCallback)
                config.currentTaskCallback(taskName);
        },

        current_task_exit: () => {
            if (killedTracked.killed) return;
            if (config.currentTaskCallback)
                config.currentTaskCallback(null);
        }
    };

    return { imports, killAll }
}
