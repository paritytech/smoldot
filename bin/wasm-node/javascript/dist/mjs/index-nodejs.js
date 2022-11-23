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
// Note: if you modify these imports, please test both the ModuleJS and CommonJS generated
// bindings. JavaScript being JavaScript, some libraries (such as `websocket`) have issues working
// with both at the same time.
import { start as innerStart } from './client.js';
import { ConnectionError } from './instance/instance.js';
import { WebSocket } from 'ws';
import { inflate } from 'pako';
import { performance } from 'node:perf_hooks';
import { createConnection as nodeCreateConnection } from 'node:net';
import { randomFillSync } from 'node:crypto';
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
        trustedBase64DecodeAndZlibInflate: (input) => {
            return Promise.resolve(inflate(Buffer.from(input, 'base64')));
        },
        registerShouldPeriodicallyYield: (_callback) => {
            return [true, () => { }];
        },
        performanceNow: () => {
            return performance.now();
        },
        getRandomValues: (buffer) => {
            if (buffer.length >= 65536)
                throw new Error('getRandomValues buffer too large');
            randomFillSync(buffer);
        },
        connect: (config) => {
            return connect(config, (options === null || options === void 0 ? void 0 : options.forbidTcp) || false, (options === null || options === void 0 ? void 0 : options.forbidWs) || false, (options === null || options === void 0 ? void 0 : options.forbidNonLocalWs) || false, (options === null || options === void 0 ? void 0 : options.forbidWss) || false);
        }
    });
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
        const socket = new WebSocket(url);
        socket.binaryType = 'arraybuffer';
        socket.onopen = () => {
            config.onOpen({ type: 'single-stream', handshake: 'multistream-select-noise-yamux' });
        };
        socket.onclose = (event) => {
            const message = "Error code " + event.code + (!!event.reason ? (": " + event.reason) : "");
            config.onConnectionReset(message);
            socket.onopen = () => { };
            socket.onclose = () => { };
            socket.onmessage = () => { };
            socket.onerror = () => { };
        };
        socket.onerror = (event) => {
            config.onConnectionReset(event.message);
            socket.onopen = () => { };
            socket.onclose = () => { };
            socket.onmessage = () => { };
            socket.onerror = () => { };
        };
        socket.onmessage = (msg) => {
            config.onMessage(new Uint8Array(msg.data));
        };
        connection = { ty: 'websocket', socket };
    }
    else if (tcpParsed != null) {
        // `net` module will be missing when we're not in NodeJS.
        if (forbidTcp) {
            throw new ConnectionError('TCP connections not available');
        }
        const socket = nodeCreateConnection({
            host: tcpParsed[2],
            port: parseInt(tcpParsed[3], 10),
        });
        connection = { ty: 'tcp', socket };
        connection.socket.setNoDelay();
        connection.socket.on('connect', () => {
            if (socket.destroyed)
                return;
            config.onOpen({ type: 'single-stream', handshake: 'multistream-select-noise-yamux' });
        });
        connection.socket.on('close', (hasError) => {
            if (socket.destroyed)
                return;
            // NodeJS doesn't provide a reason why the closing happened, but only
            // whether it was caused by an error.
            const message = hasError ? "Error" : "Closed gracefully";
            config.onConnectionReset(message);
        });
        connection.socket.on('error', () => { });
        connection.socket.on('data', (message) => {
            if (socket.destroyed)
                return;
            config.onMessage(new Uint8Array(message.buffer));
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
                connection.socket.destroy();
            }
        },
        send: (data) => {
            if (connection.ty == 'websocket') {
                // WebSocket
                connection.socket.send(data);
            }
            else {
                // TCP
                connection.socket.write(data);
            }
        },
        openOutSubstream: () => { throw new Error('Wrong connection type'); }
    };
}
