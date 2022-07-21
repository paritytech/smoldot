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

import { Client, ClientOptions, start as innerStart } from './client.js'
import { Connection, ConnectionError, ConnectionConfig } from './instance/instance.js';

export {
    AddChainError,
    AddChainOptions,
    AlreadyDestroyedError,
    Chain,
    Client,
    ClientOptions,
    CrashError,
    JsonRpcCallback,
    JsonRpcDisabledError,
    LogCallback
} from './client.js';

/**
 * Initializes a new client. This is a pre-requisite to connecting to a blockchain.
 *
 * Can never fail.
 *
 * @param options Configuration of the client. Defaults to `{}`.
 */
export function start(options?: ClientOptions): Client {
    options = options || {};

    return innerStart(options || {}, {
        base64DecodeAndZlibInflate: async (input) => {
            const buffer = trustedBase64Decode(input);

            // This code has been copy-pasted from the official streams draft specification.
            // At the moment, it is found here: https://wicg.github.io/compression/#example-deflate-compress
            const ds = new DecompressionStream('deflate');
            const writer = ds.writable.getWriter();
            writer.write(buffer);
            writer.close();
            const output = [];
            const reader = ds.readable.getReader();
            let totalSize = 0;
            while (true) {
                const { value, done } = await reader.read();
                if (done)
                    break;
                output.push(value);
                totalSize += value.byteLength;
            }
            const concatenated = new Uint8Array(totalSize);
            let offset = 0;
            for (const array of output) {
                concatenated.set(array, offset);
                offset += array.byteLength;
            }
            return concatenated;
        },
        performanceNow: () => {
            return performance.now()
        },
        getRandomValues: (buffer) => {
            const crypto = globalThis.crypto;
            if (!crypto)
                throw new Error('randomness not available');
            crypto.getRandomValues(buffer);
        },
        connect: (config) => {
            return connect(config, options?.forbidTcp || false, options?.forbidWs || false, options?.forbidNonLocalWs || false, options?.forbidWss || false)
        }
    })
}

/**
 * Decodes a base64 string.
 *
 * The input is assumed to be correct.
 */
 function trustedBase64Decode(base64: string): Uint8Array {
    // This code is a bit sketchy due to the fact that we decode into a string, but it seems to
    // work.
    const binaryString = atob(base64);
    const size = binaryString.length;
    const bytes = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

/**
 * Tries to open a new connection using the given configuration.
 *
 * @see Connection
 * @throws ConnectionError If the multiaddress couldn't be parsed or contains an invalid protocol.
 */
function connect(config: ConnectionConfig, forbidTcp: boolean, forbidWs: boolean, forbidNonLocalWs: boolean, forbidWss: boolean): Connection {
    let connection: TcpWrapped | WebSocketWrapped;

    // Attempt to parse the multiaddress.
    // TODO: remove support for `/wss` in a long time (https://github.com/paritytech/smoldot/issues/1940)
    const wsParsed = config.address.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)\/(ws|wss|tls\/ws)$/);
    const tcpParsed = config.address.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)$/);

    if (wsParsed != null) {
        const proto = (wsParsed[4] == 'ws') ? 'ws' : 'wss';
        if (
            (proto == 'ws' && forbidWs) ||
            (proto == 'ws' && wsParsed[2] != 'localhost' && wsParsed[2] != '127.0.0.1' && forbidNonLocalWs) ||
            (proto == 'wss' && forbidWss)
        ) {
            throw new ConnectionError('Connection type not allowed');
        }

        const url = (wsParsed[1] == 'ip6') ?
            (proto + "://[" + wsParsed[2] + "]:" + wsParsed[3]) :
            (proto + "://" + wsParsed[2] + ":" + wsParsed[3]);

        connection = {
            ty: 'websocket',
            socket: new WebSocket(url)
        };
        connection.socket.binaryType = 'arraybuffer';

        connection.socket.onopen = () => {
            config.onOpen({ type: 'single-stream' });
        };
        connection.socket.onclose = (event) => {
            const message = "Error code " + event.code + (!!event.reason ? (": " + event.reason) : "");
            config.onConnectionClose(message);
        };
        connection.socket.onmessage = (msg) => {
            config.onMessage(new Uint8Array(msg.data as ArrayBuffer));
        };

    } else if (tcpParsed != null) {
        // `net` module will be missing when we're not in NodeJS.
        if (forbidTcp) {
            throw new ConnectionError('TCP connections not available');
        }

        const socket = {
            destroyed: false,
            inner: Deno.connect({
                hostname: tcpParsed[2],
                port: parseInt(tcpParsed[3]!, 10),
            })
        };

        connection = { ty: 'tcp', socket };

        socket.inner = socket.inner.then((established) => {
            // TODO: at the time of writing of this comment, `setNoDelay` is still unstable
            //established.setNoDelay();

            if (socket.destroyed)
                return established;
            config.onOpen({ type: 'single-stream' });

            // Spawns an asynchronous task that continuously reads from the socket.
            // Every time data is read, the task re-executes itself in order to continue reading.
            // The task ends automatically if an EOF or error is detected, which should also happen
            // if the user calls `close()`.
            const read = async (readBuffer: Uint8Array): Promise<void> => {
                if (socket.destroyed)
                    return;
                let outcome: null | number | string = null;
                try {
                    outcome = await established.read(readBuffer);
                } catch (error) {
                    // The type of `error` is unclear, but we assume that it implements `Error`
                    outcome = (error as Error).toString()
                }
                if (socket.destroyed)
                    return;
                if (typeof outcome !== 'number' || outcome === null) {
                    // The socket is reported closed, but `socket.destroyed` is still `false` (see
                    // check above). As such, we must inform the inner layers.
                    socket.destroyed = true;
                    config.onConnectionClose(outcome === null ? "EOF when reading socket" : outcome);
                    return;
                }
                console.assert(outcome !== 0); // `read` guarantees to return a non-zero value.
                config.onMessage(readBuffer.slice(0, outcome));
                return read(readBuffer)
            }
                ; read(new Uint8Array(1024));

            return established;
        });

    } else {
        throw new ConnectionError('Unrecognized multiaddr format');
    }

    return {
        close: (): void => {
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
                connection.socket.destroyed = true;
                connection.socket.inner.then((connec) => connec.close());
            }
        },

        send: (data: Uint8Array): void => {
            if (connection.ty == 'websocket') {
                // WebSocket
                connection.socket.send(data);
            } else {
                // TCP
                // TODO: at the moment, sending data doesn't have any back-pressure mechanism; as such, we just buffer data indefinitely
                let dataCopy = Uint8Array.from(data)  // Deep copy of the data
                const socket = connection.socket;
                connection.socket.inner = connection.socket.inner.then(async (c) => {
                    while (dataCopy.length > 0) {
                        if (socket.destroyed)
                            return c;
                        let outcome: number | string;
                        try {
                            outcome = await c.write(dataCopy);
                        } catch (error) {
                            // The type of `error` is unclear, but we assume that it implements `Error`
                            outcome = (error as Error).toString()
                        }
                        if (typeof outcome !== 'number') {
                            // The socket is reported closed, but `socket.destroyed` is still
                            // `false` (see check above). As such, we must inform the inner layers.
                            socket.destroyed = true;
                            config.onConnectionClose(outcome);
                            return c;
                        }
                        // Note that, contrary to `read`, it is possible for `outcome` to be 0.
                        // This happen if the write had to be interrupted, and the only thing
                        // we have to do is try writing again.
                        dataCopy = dataCopy.slice(outcome);
                    }
                    return c;
                });
            }
        },

        openOutSubstream: () => { throw new Error('Wrong connection type') }
    };
}

interface TcpWrapped {
    ty: 'tcp',
    socket: TcpConnection,
}

interface WebSocketWrapped {
    ty: 'websocket',
    socket: WebSocket,
}

interface TcpConnection {
    // `Promise` that resolves when the connection is ready to accept more data to send, or when
    // the connection is closed. Check `destroyed` in order to know whether the connection
    // is closed.
    inner: Promise<Deno.TcpConn>,
    destroyed: boolean,
}



// Deno type definitions copy-pasted below, filtered to keep only what is necessary.
// The code below is under MIT license.

/*
MIT License

Copyright 2018-2022 the Deno authors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// Original can be found here: https://github.com/denoland/deno/blob/main/cli/dts/lib.deno.ns.d.ts
declare namespace Deno {
    export interface Reader {
        /** Reads up to `p.byteLength` bytes into `p`. It resolves to the number of
         * bytes read (`0` < `n` <= `p.byteLength`) and rejects if any error
         * encountered. Even if `read()` resolves to `n` < `p.byteLength`, it may
         * use all of `p` as scratch space during the call. If some data is
         * available but not `p.byteLength` bytes, `read()` conventionally resolves
         * to what is available instead of waiting for more.
         *
         * When `read()` encounters end-of-file condition, it resolves to EOF
         * (`null`).
         *
         * When `read()` encounters an error, it rejects with an error.
         *
         * Callers should always process the `n` > `0` bytes returned before
         * considering the EOF (`null`). Doing so correctly handles I/O errors that
         * happen after reading some bytes and also both of the allowed EOF
         * behaviors.
         *
         * Implementations should not retain a reference to `p`.
         *
         * Use `itereateReader` from from https://deno.land/std/streams/conversion.ts to
         * turn a Reader into an AsyncIterator.
         */
        read(p: Uint8Array): Promise<number | null>;
    }

    export interface ReaderSync {
        /** Reads up to `p.byteLength` bytes into `p`. It resolves to the number
         * of bytes read (`0` < `n` <= `p.byteLength`) and rejects if any error
         * encountered. Even if `readSync()` returns `n` < `p.byteLength`, it may use
         * all of `p` as scratch space during the call. If some data is available
         * but not `p.byteLength` bytes, `readSync()` conventionally returns what is
         * available instead of waiting for more.
         *
         * When `readSync()` encounters end-of-file condition, it returns EOF
         * (`null`).
         *
         * When `readSync()` encounters an error, it throws with an error.
         *
         * Callers should always process the `n` > `0` bytes returned before
         * considering the EOF (`null`). Doing so correctly handles I/O errors that happen
         * after reading some bytes and also both of the allowed EOF behaviors.
         *
         * Implementations should not retain a reference to `p`.
         *
         * Use `iterateReaderSync()` from from https://deno.land/std/streams/conversion.ts
         * to turn a ReaderSync into an Iterator.
         */
        readSync(p: Uint8Array): number | null;
    }

    export interface Writer {
        /** Writes `p.byteLength` bytes from `p` to the underlying data stream. It
         * resolves to the number of bytes written from `p` (`0` <= `n` <=
         * `p.byteLength`) or reject with the error encountered that caused the
         * write to stop early. `write()` must reject with a non-null error if
         * would resolve to `n` < `p.byteLength`. `write()` must not modify the
         * slice data, even temporarily.
         *
         * Implementations should not retain a reference to `p`.
         */
        write(p: Uint8Array): Promise<number>;
    }

    export interface WriterSync {
        /** Writes `p.byteLength` bytes from `p` to the underlying data
         * stream. It returns the number of bytes written from `p` (`0` <= `n`
         * <= `p.byteLength`) and any error encountered that caused the write to
         * stop early. `writeSync()` must throw a non-null error if it returns `n` <
         * `p.byteLength`. `writeSync()` must not modify the slice data, even
         * temporarily.
         *
         * Implementations should not retain a reference to `p`.
         */
        writeSync(p: Uint8Array): number;
    }

    export interface Closer {
        close(): void;
    }
}

// Original can be found here: https://github.com/denoland/deno/blob/main/ext/net/lib.deno_net.d.ts
declare namespace Deno {
    export interface NetAddr {
        transport: "tcp" | "udp";
        hostname: string;
        port: number;
    }

    export interface UnixAddr {
        transport: "unix" | "unixpacket";
        path: string;
    }

    export type Addr = NetAddr | UnixAddr;

    export interface Conn extends Reader, Writer, Closer {
        /** The local address of the connection. */
        readonly localAddr: Addr;
        /** The remote address of the connection. */
        readonly remoteAddr: Addr;
        /** The resource ID of the connection. */
        readonly rid: number;
        /** Shuts down (`shutdown(2)`) the write side of the connection. Most
         * callers should just use `close()`. */
        closeWrite(): Promise<void>;

        readonly readable: ReadableStream<Uint8Array>;
        readonly writable: WritableStream<Uint8Array>;
    }

    export interface ConnectOptions {
        /** The port to connect to. */
        port: number;
        /** A literal IP address or host name that can be resolved to an IP address.
         * If not specified, defaults to `127.0.0.1`. */
        hostname?: string;
        transport?: "tcp";
    }

    /**
     * Connects to the hostname (default is "127.0.0.1") and port on the named
     * transport (default is "tcp"), and resolves to the connection (`Conn`).
     *
     * ```ts
     * const conn1 = await Deno.connect({ port: 80 });
     * const conn2 = await Deno.connect({ hostname: "192.0.2.1", port: 80 });
     * const conn3 = await Deno.connect({ hostname: "[2001:db8::1]", port: 80 });
     * const conn4 = await Deno.connect({ hostname: "golang.org", port: 80, transport: "tcp" });
     * ```
     *
     * Requires `allow-net` permission for "tcp". */
    export function connect(options: ConnectOptions): Promise<TcpConn>;

    export interface TcpConn extends Conn {
        /**
         * **UNSTABLE**: new API, see https://github.com/denoland/deno/issues/13617.
         *
         * Enable/disable the use of Nagle's algorithm. Defaults to true.
         */
        setNoDelay(nodelay?: boolean): void;
        /**
         * **UNSTABLE**: new API, see https://github.com/denoland/deno/issues/13617.
         *
         * Enable/disable keep-alive functionality.
         */
        setKeepAlive(keepalive?: boolean): void;
    }
}

// Original can be found here: https://github.com/denoland/deno/blob/main/ext/web/lib.deno_web.d.ts
/**
 * An API for decompressing a stream of data.
 *
 * @example
 * ```ts
 * const input = await Deno.open("./file.txt.gz");
 * const output = await Deno.create("./file.txt");
 *
 * await input.readable
 *   .pipeThrough(new DecompressionStream("gzip"))
 *   .pipeTo(output.writable);
 * ```
 */
declare class DecompressionStream {
    /**
     * Creates a new `DecompressionStream` object which decompresses a stream of
     * data.
     *
     * Throws a `TypeError` if the format passed to the constructor is not
     * supported.
     */
    constructor(format: string);

    readonly readable: ReadableStream<Uint8Array>;
    readonly writable: WritableStream<Uint8Array>;
}
