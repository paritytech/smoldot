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
/// <reference lib="dom" />
import { start as innerStart } from './client.js';
import { ConnectionError } from './instance/instance.js';
import { inflate } from 'pako';
export { AddChainError, AlreadyDestroyedError, CrashError, JsonRpcDisabledError } from './client.js';
/**
 * Initializes a new client. This is a pre-requisite to connecting to a blockchain.
 *
 * Can never fail.
 *
 * @param options Configuration of the client. Defaults to `{}`.
 */
export function start(options) {
    options = options || {};
    return innerStart(options, {
        base64DecodeAndZlibInflate: (input) => {
            return Promise.resolve(inflate(trustedBase64Decode(input)));
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
            return connect(config, (options === null || options === void 0 ? void 0 : options.forbidWs) || false, (options === null || options === void 0 ? void 0 : options.forbidNonLocalWs) || false, (options === null || options === void 0 ? void 0 : options.forbidWss) || false);
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
 * @throws ConnectionError If the multiaddress couldn't be parsed or contains an invalid protocol.
 */
function connect(config, forbidWs, forbidNonLocalWs, forbidWss) {
    let connection;
    // Attempt to parse the multiaddress.
    // TODO: remove support for `/wss` in a long time (https://github.com/paritytech/smoldot/issues/1940)
    const wsParsed = config.address.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)\/(ws|wss|tls\/ws)$/);
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
        connection = new WebSocket(url);
        connection.binaryType = 'arraybuffer';
        connection.onopen = () => {
            config.onOpen({ type: 'single-stream' });
        };
        connection.onclose = (event) => {
            const message = "Error code " + event.code + (!!event.reason ? (": " + event.reason) : "");
            config.onConnectionClose(message);
        };
        connection.onmessage = (msg) => {
            config.onMessage(new Uint8Array(msg.data));
        };
    }
    else {
        throw new ConnectionError('Unrecognized multiaddr format');
    }
    return {
        close: () => {
            connection.onopen = null;
            connection.onclose = null;
            connection.onmessage = null;
            connection.onerror = null;
            connection.close();
        },
        send: (data) => {
            connection.send(data);
        },
        openOutSubstream: () => { throw new Error('Wrong connection type'); }
    };
}
