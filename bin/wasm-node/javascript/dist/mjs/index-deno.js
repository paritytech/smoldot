// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
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
import { start as innerStart } from './client.js';
import { ConnectionError } from './instance/instance.js';
export { AddChainError, AlreadyDestroyedError, CrashError, MalformedJsonRpcError, QueueFullError, JsonRpcDisabledError } from './client.js';
/**
 * Initializes a new client. This is a pre-requisite to connecting to a blockchain.
 *
 * Can never fail.
 *
 * @param options Configuration of the client. Defaults to `{}`.
 */
export function start(options) {
    options = options || {};
    return innerStart(options || {}, {
        trustedBase64DecodeAndZlibInflate: (input) => __awaiter(this, void 0, void 0, function* () {
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
                const { value, done } = yield reader.read();
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
        }),
        registerShouldPeriodicallyYield: (_callback) => {
            return [true, () => { }];
        },
        performanceNow: () => {
            return performance.now();
        },
        getRandomValues: (buffer) => {
            const crypto = globalThis.crypto;
            if (!crypto)
                throw new Error('randomness not available');
            crypto.getRandomValues(buffer);
        },
        connect: (config) => {
            return connect(config, (options === null || options === void 0 ? void 0 : options.forbidTcp) || false, (options === null || options === void 0 ? void 0 : options.forbidWs) || false, (options === null || options === void 0 ? void 0 : options.forbidNonLocalWs) || false, (options === null || options === void 0 ? void 0 : options.forbidWss) || false);
        }
    });
}
/**
 * Decodes a base64 string.
 *
 * The input is assumed to be correct.
 */
function trustedBase64Decode(base64) {
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
 * @throws {@link ConnectionError} If the multiaddress couldn't be parsed or contains an invalid protocol.
 */
function connect(config, forbidTcp, forbidWs, forbidNonLocalWs, forbidWss) {
    let connection;
    // Attempt to parse the multiaddress.
    // TODO: remove support for `/wss` in a long time (https://github.com/paritytech/smoldot/issues/1940)
    const wsParsed = config.address.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)\/(ws|wss|tls\/ws)$/);
    const tcpParsed = config.address.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)$/);
    if (wsParsed != null) {
        const proto = (wsParsed[4] == 'ws') ? 'ws' : 'wss';
        if ((proto == 'ws' && forbidWs) ||
            (proto == 'ws' && wsParsed[2] != 'localhost' && wsParsed[2] != '127.0.0.1' && forbidNonLocalWs) ||
            (proto == 'wss' && forbidWss)) {
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
            config.onOpen({ type: 'single-stream', handshake: 'multistream-select-noise-yamux' });
        };
        connection.socket.onclose = (event) => {
            const message = "Error code " + event.code + (!!event.reason ? (": " + event.reason) : "");
            config.onConnectionReset(message);
        };
        connection.socket.onmessage = (msg) => {
            config.onMessage(new Uint8Array(msg.data));
        };
    }
    else if (tcpParsed != null) {
        // `net` module will be missing when we're not in NodeJS.
        if (forbidTcp) {
            throw new ConnectionError('TCP connections not available');
        }
        const socket = {
            destroyed: false,
            inner: Deno.connect({
                hostname: tcpParsed[2],
                port: parseInt(tcpParsed[3], 10),
            })
        };
        connection = { ty: 'tcp', socket };
        socket.inner = socket.inner.then((established) => {
            // TODO: at the time of writing of this comment, `setNoDelay` is still unstable
            //established.setNoDelay();
            if (socket.destroyed)
                return established;
            config.onOpen({ type: 'single-stream', handshake: 'multistream-select-noise-yamux' });
            // Spawns an asynchronous task that continuously reads from the socket.
            // Every time data is read, the task re-executes itself in order to continue reading.
            // The task ends automatically if an EOF or error is detected, which should also happen
            // if the user calls `close()`.
            const read = (readBuffer) => __awaiter(this, void 0, void 0, function* () {
                if (socket.destroyed)
                    return;
                let outcome = null;
                try {
                    outcome = yield established.read(readBuffer);
                }
                catch (error) {
                    // The type of `error` is unclear, but we assume that it implements `Error`
                    outcome = error.toString();
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
                return read(readBuffer);
            });
            read(new Uint8Array(1024));
            return established;
        });
    }
    else {
        throw new ConnectionError('Unrecognized multiaddr format');
    }
    return {
        reset: () => {
            if (connection.ty == 'websocket') {
                // WebSocket
                // We can't set these fields to null because the TypeScript definitions don't
                // allow it, but we can set them to dummy values.
                connection.socket.onopen = () => { };
                connection.socket.onclose = () => { };
                connection.socket.onmessage = () => { };
                connection.socket.onerror = () => { };
                connection.socket.close();
            }
            else {
                // TCP
                connection.socket.destroyed = true;
                connection.socket.inner.then((connec) => connec.close());
            }
        },
        send: (data) => {
            if (connection.ty == 'websocket') {
                // WebSocket
                // The WebSocket library that we use seems to spontaneously transition connections
                // to the "closed" state but not call the `onclosed` callback immediately. Calling
                // `send` on that object throws an exception. In order to avoid panicking smoldot,
                // we thus absorb any exception thrown here.
                // See also <https://github.com/paritytech/smoldot/issues/2937>.
                try {
                    connection.socket.send(data);
                }
                catch (_error) { }
            }
            else {
                // TCP
                // TODO: at the moment, sending data doesn't have any back-pressure mechanism; as such, we just buffer data indefinitely
                let dataCopy = Uint8Array.from(data); // Deep copy of the data
                const socket = connection.socket;
                connection.socket.inner = connection.socket.inner.then((c) => __awaiter(this, void 0, void 0, function* () {
                    while (dataCopy.length > 0) {
                        if (socket.destroyed)
                            return c;
                        let outcome;
                        try {
                            outcome = yield c.write(dataCopy);
                        }
                        catch (error) {
                            // The type of `error` is unclear, but we assume that it implements `Error`
                            outcome = error.toString();
                        }
                        if (typeof outcome !== 'number') {
                            // The socket is reported closed, but `socket.destroyed` is still
                            // `false` (see check above). As such, we must inform the inner layers.
                            socket.destroyed = true;
                            config.onConnectionReset(outcome);
                            return c;
                        }
                        // Note that, contrary to `read`, it is possible for `outcome` to be 0.
                        // This happen if the write had to be interrupted, and the only thing
                        // we have to do is try writing again.
                        dataCopy = dataCopy.slice(outcome);
                    }
                    return c;
                }));
            }
        },
        openOutSubstream: () => { throw new Error('Wrong connection type'); }
    };
}
