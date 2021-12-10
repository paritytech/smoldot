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
const westend = fs.readFileSync('../../westend.json', 'utf8');
const westmint = fs.readFileSync('../../westend-westmint.json', 'utf8');
const adz = fs.readFileSync('../../westend-adz.json', 'utf8');
const polkadot = fs.readFileSync('../../polkadot.json', 'utf8');
const kusama = fs.readFileSync('../../kusama.json', 'utf8');
const statemine = fs.readFileSync('../../kusama-statemine.json', 'utf8');
const rococo = fs.readFileSync('../../rococo.json', 'utf8');

const client = smoldot.start({
    maxLogLevel: 3,  // Can be increased for more verbosity
    forbidTcp: false,
    forbidWs: false,
    forbidNonLocalWs: false,
    forbidWss: false,
    logCallback: (level, target, message) => {
        // As incredible as it seems, there is currently no better way to print the current time
        // formatted in a certain way.
        const now = new Date();
        const hours = ("0" + now.getHours()).slice(-2);
        const minutes = ("0" + now.getMinutes()).slice(-2);
        const seconds = ("0" + now.getSeconds()).slice(-2);
        const milliseconds = ("00" + now.getMilliseconds()).slice(-3);
        console.log(
            "[%s:%s:%s.%s] [%s] %s",
            hours, minutes, seconds, milliseconds, target, message
        );
    }
});

// Pre-load smoldot with the relay chain spec.
// We call `addChain` again with the same chain spec again every time a new WebSocket connection
// is established, but smoldot will de-duplicate them and only connect to the chain once.
// By calling it now, we let smoldot start syncing that chain in the background even before a
// WebSocket connection has been established.
client
    .addChain({ chainSpec: westend })
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
    console.log('Visit one of:');
    console.log('- https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944%2Fwestend');
    console.log('- https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944%2Fwestmint');
    console.log('- https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944%2Fadz');
    console.log('- https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944%2Fkusama');
    console.log('- https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944%2Fstatemine');
    console.log('- https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944%2Fpolkadot');
    console.log('- https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944%2Frococo');
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
    if (request.resource == '/westend') {
        chain = (async () => {
            return {
                relay: await client.addChain({
                    chainSpec: westend,
                    jsonRpcCallback: (resp) => {
                        connection.sendUTF(resp);
                    },
                })
            };
        })();

    } else if (request.resource == '/westmint') {
        chain = (async () => {
            const relay = await client.addChain({
                chainSpec: westend,
            });

            const para = await client.addChain({
                chainSpec: westmint,
                jsonRpcCallback: (resp) => {
                    connection.sendUTF(resp);
                },
                potentialRelayChains: [relay]
            });

            return { relay, para };
        })();
    } else if (request.resource == '/adz') {
        chain = (async () => {
            const relay = await client.addChain({
                chainSpec: westend,
            });

            const para = await client.addChain({
                chainSpec: adz,
                jsonRpcCallback: (resp) => {
                    connection.sendUTF(resp);
                },
                potentialRelayChains: [relay]
            });

            return { relay, para };
        })();
    } else if (request.resource == '/kusama') {
        chain = (async () => {
            return {
                relay: await client.addChain({
                    chainSpec: kusama,
                    jsonRpcCallback: (resp) => {
                        connection.sendUTF(resp);
                    },
                })
            };
        })();
    } else if (request.resource == '/statemine') {
        chain = (async () => {
            const relay = await client.addChain({
                chainSpec: kusama,
            });

            const para = await client.addChain({
                chainSpec: statemine,
                jsonRpcCallback: (resp) => {
                    connection.sendUTF(resp);
                },
                potentialRelayChains: [relay]
            });

            return { relay, para };
        })();
    } else if (request.resource == '/polkadot') {
        chain = (async () => {
            return {
                relay: await client.addChain({
                    chainSpec: polkadot,
                    jsonRpcCallback: (resp) => {
                        connection.sendUTF(resp);
                    },
                })
            };
        })();
    } else if (request.resource == '/rococo') {
        chain = (async () => {
            return {
                relay: await client.addChain({
                    chainSpec: rococo,
                    jsonRpcCallback: (resp) => {
                        connection.sendUTF(resp);
                    },
                })
            };
        })();
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
