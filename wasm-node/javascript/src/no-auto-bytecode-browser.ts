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

import { Client, ClientOptionsWithBytecode } from './public-types.js'
import { start as innerStart } from './internals/client.js'
import { connect } from './internals/browser-connect.js'

export {
    AddChainError,
    AddChainOptions,
    AlreadyDestroyedError,
    Chain,
    Client,
    ClientOptions,
    ClientOptionsWithBytecode,
    SmoldotBytecode,
    CrashError,
    JsonRpcDisabledError,
    QueueFullError,
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
    options.forbidTcp = true;

    // Browsers only expose the WebRTC API on `Window`, it doesn't exist in worker global
    // scopes, and consequently there is no way to open WebRTC connections from here.
    if (typeof RTCPeerConnection === 'undefined')
        options.forbidWebRtc = true;

    // When in a secure context, browsers refuse to open non-secure WebSocket connections to
    // non-localhost. There is an exception if the page is localhost, in which case all connections
    // are allowed.
    // Detecting this ahead of time is better for the overall health of the client, as it will
    // avoid storing in memory addresses that it knows it can't connect to.
    // The condition below is a hint, and false-positives or false-negatives are not fundamentally
    // an issue.
    if ((typeof isSecureContext === 'boolean' && isSecureContext) && typeof location !== 'undefined') {
        const hostname = location.hostname;
        if (hostname !== 'localhost' && hostname !== '127.0.0.1' && hostname !== '[::1]' && hostname !== '::1') {
            options.forbidNonLocalWs = true;
        }
    }

    return innerStart(options, options.bytecode, {
        performanceNow: () => {
            return performance.now()
        },
        getRandomValues: (buffer) => {
            const crypto = globalThis.crypto;
            if (!crypto)
                throw new Error('randomness not available');

            // Browsers have this completely undocumented behavior (it's not even part of a spec)
            // that for some reason `getRandomValues` can't be called on arrayviews back by
            // `SharedArrayBuffer`s and they throw an exception if you try.
            if (buffer.buffer instanceof ArrayBuffer)
                crypto.getRandomValues(buffer);
            else {
                const tmpArray = new Uint8Array(buffer.length);
                crypto.getRandomValues(tmpArray);
                buffer.set(tmpArray);
            }
        },
        connect: (config) => {
            return connect(config)
        }
    })
}
