// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
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

// This file launches a WebSocket server that exposes JSON-RPC functions.

import * as smoldot from '../src/index.js';
import { default as websocket } from 'websocket';
import * as http from 'http';
import * as process from 'process';
import * as fs from 'fs';

// Adjust these chain specs for the chain you want to connect to.
const chainSpec = fs.readFileSync('../../westend.json', 'utf8');
const parachainSpec = fs.readFileSync('../../westend-westmint.json', 'utf8');

const client = smoldot.start({
    maxLogLevel: 3,  // Can be increased for more verbosity
    forbidTcp: false,
    forbidWs: false,
    forbidWss: false,
});

// Pre-load smoldot with the relay chain spec.
// We call `addChain` again with the same chain spec again every time a new WebSocket connection
// is established, but smoldot will de-duplicate them and only connect to the chain once.
// By calling it now, we let smoldot start syncing that chain in the background even before a
// WebSocket connection has been established.
client
    .then(client => client.addChain({ chainSpec }))
    .catch((error) => {
        console.error("Error while adding chain: " + error);
        process.exit(1);
    });

// Start the WebSocket server listening on port 9944.
let server = http.createServer(function (request, response) {
    response.writeHead(404);
    response.end();
});
server.listen(9944, function () {
    console.log('Server is listening on port 9944');
    console.log('Visit https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944%2Frelay (relay chain) or https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944%2Fparachain (parachain)');
});
let wsServer = new websocket.server({
    httpServer: server,
    autoAcceptConnections: false,
});

wsServer.on('request', function (request) {
    // Received a new incoming WebSocket connection.

    // Depending on the URL, we add either Westend or Westend+Westmint to smoldot.
    // `chain` will contain a `Promise` that yields either `{ relay }` or `{ relay, para }`, where
    // `relay` and `para` are of type `SmoldotChain`.
    let chain;
    if (request.resource == '/relay') {
        chain = client.then(async client => {
            return {
                relay: await client.addChain({
                    chainSpec,
                    jsonRpcCallback: (resp) => {
                        connection.sendUTF(resp);
                    },
                })
            };
        });

    } else if (request.resource == '/parachain') {
        chain = client.then(async client => {
            const relay = await client.addChain({
                chainSpec,
            });

            const para = await client.addChain({
                chainSpec: parachainSpec,
                jsonRpcCallback: (resp) => {
                    connection.sendUTF(resp);
                },
                potentialRelayChains: [relay]
            });

            return { relay, para };
        });
    } else {
        request.reject(404);
        return;
    }

    const connection = request.accept(request.requestedProtocols[0], request.origin);
    console.log((new Date()) + ' Connection accepted.');

    chain
        .catch((error) => {
            console.error("Error while adding chain: " + error);
            connection.close(400);
        });

    // Receiving a message from the connection. This is a JSON-RPC request.
    connection.on('message', function (message) {
        if (message.type === 'utf8') {
            chain
                .then(chain => {
                    if (chain.para)
                        chain.para.sendJsonRpc(message.utf8Data);
                    else
                        chain.relay.sendJsonRpc(message.utf8Data);
                })
                .catch((error) => {
                    console.error("Error during JSON-RPC request: " + error);
                    process.exit(1);
                });
        } else {
            connection.close(400);
        }
    });

    // When the connection closes, remove the chains that have been added.
    connection.on('close', function (reasonCode, description) {
        console.log((new Date()) + ' Peer ' + connection.remoteAddress + ' disconnected.');
        chain.then(chain => {
            chain.relay.remove();
            if (chain.para)
                chain.para.remove();
        }).catch(() => { });
    });
});
