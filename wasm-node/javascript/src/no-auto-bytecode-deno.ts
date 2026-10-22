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

import { Client, ClientOptionsWithBytecode } from './public-types.js'
import { start as innerStart, Connection, ConnectionConfig } from './internals/client.js'

export {
    AddChainError,
    AddChainOptions,
    AlreadyDestroyedError,
    Chain,
    Client,
    ClientOptions,
    ClientOptionsWithBytecode,
    ConnectionAddress,
    SmoldotBytecode,
    CrashError,
    QueueFullError,
    JsonRpcDisabledError,
    LogCallback
} from './public-types.js';

/**
 * Initializes a new client. This is a pre-requisite to connecting to a blockchain.
 *
 * Can never fail.
 *
 * @param options Configuration of the client.
 */
export function startWithBytecode(options: ClientOptionsWithBytecode): Client {
    options.forbidWebRtc = true;

    return innerStart(options || {}, options.bytecode, {
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
            return connect(config)
        }
    })
}

/**
 * Tries to open a new connection using the given configuration.
 *
 * @see Connection
 * @throws {@link ConnectionError} If the multiaddress couldn't be parsed or contains an invalid protocol.
 */
function connect(config: ConnectionConfig): Connection {
    if (config.address.ty === "websocket") {
        const socket = new WebSocket(config.address.url);
        socket.binaryType = 'arraybuffer';

        const bufferedAmountCheck = { quenedUnreportedBytes: 0, nextTimeout: 10 };
        const checkBufferedAmount = () => {
            if (socket.readyState != 1)
                return;
            // Note that we might expect `bufferedAmount` to always be <= the sum of the lengths
            // of all the data that has been sent, but that might not be the case. For this
            // reason, we use `bufferedAmount` as a hint rather than a correct value.
            const bufferedAmount = socket.bufferedAmount;
            let wasSent = bufferedAmountCheck.quenedUnreportedBytes - bufferedAmount;
            if (wasSent < 0) wasSent = 0;
            bufferedAmountCheck.quenedUnreportedBytes -= wasSent;
            if (bufferedAmountCheck.quenedUnreportedBytes != 0) {
                setTimeout(checkBufferedAmount, bufferedAmountCheck.nextTimeout);
                bufferedAmountCheck.nextTimeout *= 2;
                if (bufferedAmountCheck.nextTimeout > 500)
                    bufferedAmountCheck.nextTimeout = 500;
            }
            // Note: it is important to call `onWritableBytes` at the very end, as it might
            // trigger a call to `send`.
            if (wasSent != 0)
                config.onWritableBytes(wasSent);
        };

        socket.onopen = () => {
            config.onWritableBytes(1024 * 1024);
        };
        socket.onclose = (event) => {
            const message = "Error code " + event.code + (!!event.reason ? (": " + event.reason) : "");
            config.onConnectionReset(message);
        };
        socket.onmessage = (msg) => {
            config.onMessage(new Uint8Array(msg.data as ArrayBuffer));
        };

        return {
            reset: (): void => {
                // We can't set these fields to null because the TypeScript definitions don't
                // allow it, but we can set them to dummy values.
                socket.onopen = () => { };
                socket.onclose = () => { };
                socket.onmessage = () => { };
                socket.onerror = () => { };
                socket.close();
            },
            send: (data: Array<Uint8Array>): void => {
                // The WebSocket library that we use seems to spontaneously transition connections
                // to the "closed" state but not call the `onclosed` callback immediately. Calling
                // `send` on that object throws an exception. In order to avoid panicking smoldot,
                // we thus absorb any exception thrown here.
                // See also <https://github.com/paritytech/smoldot/issues/2937>.
                try {
                    if (bufferedAmountCheck.quenedUnreportedBytes == 0) {
                        bufferedAmountCheck.nextTimeout = 10;
                        setTimeout(checkBufferedAmount, 10);
                    }
                    for (const buffer of data) {
                        bufferedAmountCheck.quenedUnreportedBytes += buffer.length;
                    }
                    socket.send(new Blob(data));
                } catch (_error) { }
            },
            closeSend: (): void => { throw new Error('Wrong connection type') },
            openOutSubstream: () => { throw new Error('Wrong connection type') }
        };

    } else if (config.address.ty === "tcp") {
        const socket = {
            destroyed: false,
            inner: Deno.connect({
                hostname: config.address.hostname,
                port: config.address.port,
            }).catch((error) => {
                socket.destroyed = true;
                config.onConnectionReset(error.toString());
                return null;
            })
        };

        socket.inner = socket.inner.then((established) => {
            if (socket.destroyed)
                return established;

            established?.setNoDelay();
            config.onWritableBytes(1024 * 1024);

            // Spawns an asynchronous task that continuously reads from the socket.
            // Every time data is read, the task re-executes itself in order to continue reading.
            // The task ends automatically if an EOF or error is detected, which should also happen
            // if the user calls `close()`.
            const read = async (readBuffer: Uint8Array): Promise<void> => {
                if (socket.destroyed || established === null)
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
                    config.onConnectionReset(outcome === null ? "EOF when reading socket" : outcome);
                    return;
                }
                console.assert(outcome !== 0); // `read` guarantees to return a non-zero value.
                config.onMessage(readBuffer.slice(0, outcome));
                return read(readBuffer)
            }
                ; read(new Uint8Array(32768));

            return established;
        });

        return {
            reset: (): void => {
                socket.destroyed = true;
                socket.inner.then((connec) => connec!.close());
            },

            send: (data: Array<Uint8Array>): void => {
                let dataCopy = data.map((buf) => Uint8Array.from(buf));  // Deep copy of the data
                socket.inner = socket.inner.then(async (c) => {
                    for (let buffer of dataCopy) {
                        while (buffer.length > 0) {
                            if (socket.destroyed || c === null)
                                return c;
                            let outcome: number | string;
                            try {
                                outcome = await c.write(buffer);
                                config.onWritableBytes(buffer.length);
                            } catch (error) {
                                // The type of `error` is unclear, but we assume that it
                                // implements `Error`
                                outcome = (error as Error).toString()
                            }
                            if (typeof outcome !== 'number') {
                                // The socket is reported closed, but `socket.destroyed` is still
                                // `false` (see check above). As such, we must inform the
                                // inner layers.
                                socket.destroyed = true;
                                config.onConnectionReset(outcome);
                                return c;
                            }
                            // Note that, contrary to `read`, it is possible for `outcome` to be 0.
                            // This happen if the write had to be interrupted, and the only thing
                            // we have to do is try writing again.
                            buffer = buffer.slice(outcome);
                        }
                    }
                    return c;
                });
            },

            closeSend: (): void => {
                socket.inner = socket.inner.then(async (c) => {
                    await c?.closeWrite();
                    return c;
                });
            },

            openOutSubstream: () => { throw new Error('Wrong connection type') }
        };

    } else {
        // Should never happen, as we tweak the options to refuse connection types that
        // we don't support.
        throw new Error();
    }
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
         * Enable/disable the use of Nagle's algorithm.
         *
         * @param [noDelay=true]
         */
        setNoDelay(noDelay?: boolean): void;
        /** Enable/disable keep-alive functionality. */
        setKeepAlive(keepAlive?: boolean): void;
    }
}
