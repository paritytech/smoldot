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

import { Buffer } from 'buffer';
import Websocket from 'websocket';
import * as compat from '../compat/index.js';

import type { Socket as TcpSocket } from 'node:net';

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
     * Transitions the connection to the `Closed` state.
     *
     * The `config.onClose` callback is **not** called.
     *
     * The transition is performed in the background.
     * None of the callbacks passed to the `Config` will be called again.
     */
    close(): void;

    /**
     * Queues data to be sent on the given connection.
     *
     * The connection must currently be in the `Open` state.
     */
    send(data: Buffer): void;
}

/**
 * Configuration for a connection.
 *
 * @see connect
 */
export interface Config {
    /**
     * Multiaddress in string format that describes which node to try to connect to.
     */
    address: string,

    forbidTcp: boolean,
    forbidWs: boolean,
    forbidNonLocalWs: boolean,
    forbidWss: boolean,

    /**
     * Callback called when the connection transitions from the `Opening` to the `Open` state.
     */
    onOpen: () => void;

    /**
     * Callback called when the connection transitions to the `Closed` state.
     *
     * It it **not** called if `Connection.close` is manually called by the API user.
     */
    onClose: (message: string) => void;

    /**
     * Callback called when a message sent by the remote has been received.
     *
     * Can only happen while the connection is in the `Open` state.
     */
    onMessage: (message: Buffer) => void;
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

/**
 * Tries to open a new connection using the given configuration.
 *
 * @see Connection
 * @throws ConnectionError If the multiaddress couldn't be parsed or contains an invalid protocol.
 */
export function connect(config: Config): Connection {
    let connection: TcpWrapped | WebSocketWrapped;

    // Attempt to parse the multiaddress.
    // Note: peers can decide of the content of `addr`, meaning that it shouldn't be
    // trusted.
    const wsParsed = config.address.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)\/(ws|wss)$/);
    const tcpParsed = config.address.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)$/);

    if (wsParsed != null) {
        const proto = (wsParsed[4] == 'ws') ? 'ws' : 'wss';
        if (
            (proto == 'ws' && config.forbidWs) ||
            (proto == 'ws' && wsParsed[2] != 'localhost' && wsParsed[2] != '127.0.0.1' && config.forbidNonLocalWs) ||
            (proto == 'wss' && config.forbidWss)
        ) {
            throw new ConnectionError('Connection type not allowed');
        }

        const url = (wsParsed[1] == 'ip6') ?
            (proto + "://[" + wsParsed[2] + "]:" + wsParsed[3]) :
            (proto + "://" + wsParsed[2] + ":" + wsParsed[3]);

        connection = {
            ty: 'websocket',
            socket: new Websocket.w3cwebsocket(url)
        };
        connection.socket.binaryType = 'arraybuffer';

        connection.socket.onopen = () => {
            config.onOpen();
        };
        connection.socket.onclose = (event) => {
            const message = "Error code " + event.code + (!!event.reason ? (": " + event.reason) : "");
            config.onClose(message);
        };
        connection.socket.onmessage = (msg) => {
            config.onMessage(Buffer.from(msg.data as ArrayBuffer));
        };

    } else if (tcpParsed != null) {
        // `net` module will be missing when we're not in NodeJS.
        if (!compat.isTcpAvailable() || config.forbidTcp) {
            throw new ConnectionError('TCP connections not available');
        }

        const socket = compat.createConnection({
            host: tcpParsed[2],
            port: parseInt(tcpParsed[3]!, 10),
        });

        connection = { ty: 'tcp', socket };
        connection.socket.setNoDelay();

        connection.socket.on('connect', () => {
            if (socket.destroyed) return;
            config.onOpen();
        });
        connection.socket.on('close', (hasError) => {
            if (socket.destroyed) return;
            // NodeJS doesn't provide a reason why the closing happened, but only
            // whether it was caused by an error.
            const message = hasError ? "Error" : "Closed gracefully";
            config.onClose(message);
        });
        connection.socket.on('error', () => { });
        connection.socket.on('data', (message) => {
            if (socket.destroyed) return;
            config.onMessage(message);
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
                connection.socket.destroy();
            }
        },

        send: (data: Buffer): void => {
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

interface TcpWrapped {
    ty: 'tcp',
    socket: TcpSocket,
}

interface WebSocketWrapped {
    ty: 'websocket',
    socket: Websocket.w3cwebsocket,
}
