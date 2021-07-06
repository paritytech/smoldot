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
// Adjust these chain specs for the chain you want to connect to.
import * as fs from 'fs';

const chainSpec = fs.readFileSync('../../westend.json', 'utf8');

const client = smoldot.start({
    maxLogLevel: 3,  // Can be increased for more verbosity
    forbidTcp: false,
    forbidWs: false,
    forbidWss: false,
});

// Pre-load smoldot with the chain spec.
client.then(client => client.addChain({ chainSpec }));

let server = http.createServer(function (request, response) {
    response.writeHead(404);
    response.end();
});

server.listen(9944, function () {
    console.log('Server is listening on port 9944');
    console.log('Visit https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944');
});

let wsServer = new websocket.server({
    httpServer: server,
    autoAcceptConnections: false,
});

wsServer.on('request', function (request) {
    const connection = request.accept(request.requestedProtocols[0], request.origin);
    console.log((new Date()) + ' Connection accepted.');

    const chain = client.then(client => {
        client.addChain({
            chainSpec,
            jsonRpcCallback: (resp) => {
                connection.sendUTF(resp);
            },
        })
            .catch((error) => {
                console.error(error);
                process.exit(1);
            })
    });

    connection.on('message', function (message) {
        if (message.type === 'utf8') {
            chain.then(chain => chain.sendJsonRpc(message.utf8Data));
        } else {
            throw "Unsupported type: " + message.type;
        }
    });

    connection.on('close', function (reasonCode, description) {
        console.log((new Date()) + ' Peer ' + connection.remoteAddress + ' disconnected.');
        chain.remove();
    });
});
