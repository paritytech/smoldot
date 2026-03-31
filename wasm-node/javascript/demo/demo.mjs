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

// This file launches a WebSocket server that exposes JSON-RPC functions.

import * as smoldot from '../dist/mjs/index-nodejs.js';
import { WebSocketServer } from 'ws';
import process from 'node:process';
import * as fs from 'node:fs';
import { Worker } from 'node:worker_threads';

// List of files containing chains available to the user.
// The first item has a specific role in that we always connect to it at initialization.
const chainSpecsFiles = [
    '../../demo-chain-specs/ksmcc3.json',
    '../../demo-chain-specs/ksmcc3_asset_hub.json',
    '../../demo-chain-specs/ksmcc3_bridge_hub.json',
    '../../demo-chain-specs/ksmcc3_coretime.json',
    '../../demo-chain-specs/ksmcc3_encointer.json',
    '../../demo-chain-specs/ksmcc3_people.json',
    '../../demo-chain-specs/paseo.json',
    '../../demo-chain-specs/paseo_asset_hub.json',
    '../../demo-chain-specs/paseo_coretime.json',
    '../../demo-chain-specs/paseo_people.json',
    '../../demo-chain-specs/polkadot.json',
    '../../demo-chain-specs/polkadot_asset_hub.json',
    '../../demo-chain-specs/polkadot_bridge_hub.json',
    '../../demo-chain-specs/polkadot_collectives.json',
    '../../demo-chain-specs/polkadot_coretime.json',
    '../../demo-chain-specs/polkadot_people.json',
    '../../demo-chain-specs/rococo_v2_2.json',
    '../../demo-chain-specs/rococo_v2_2_asset_hub.json',
    '../../demo-chain-specs/rococo_v2_2_bridge_hub.json',
    '../../demo-chain-specs/rococo_v2_2_people.json',
    '../../demo-chain-specs/westend2.json',
    '../../demo-chain-specs/westend2_asset_hub.json',
    '../../demo-chain-specs/westend2_bridge_hub.json',
    '../../demo-chain-specs/westend2_collectives.json',
    '../../demo-chain-specs/westend2_coretime.json',
    '../../demo-chain-specs/westend2_people.json',
];

// Load all the files in a single map.
const chainSpecsById = {};
let firstChainSpecId = null;
for (const file of chainSpecsFiles) {
    const content = fs.readFileSync(file, 'utf8');
    const decoded = JSON.parse(content);
    if (!firstChainSpecId)
        firstChainSpecId = decoded.id;
    chainSpecsById[decoded.id] = {
        chainSpec: content,
        relayChain: decoded.relay_chain,
    };
}

const { port1, port2 } = new MessageChannel();
const worker = new Worker("./demo/demo-worker.mjs");
worker.on('error', (err) => { console.log("Worker error: \n" + err.message + "\n" + err.stack) });
worker.postMessage(port2, [port2]);

const client = smoldot.start({
    portToWorker: port1,
    maxLogLevel: process.stdout.isTTY ? 3 : 4,  // Can be modified manually for more verbosity
    forbidTcp: false,
    forbidWs: false,
    forbidNonLocalWs: false,
    forbidWss: false,
    cpuRateLimit: 0.5,
    logCallback: (_level, target, message) => {
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

// Try to open a database, expecting it to fail in most situations.
let defaultChainDb = "";
try {
    defaultChainDb = fs.readFileSync('database.json', { encoding: 'utf-8' });
} catch (error) { }

// Note that We call `addChain` again with the same chain spec again every time a new WebSocket
// connection is established, but smoldot will de-duplicate them and only connect to the chain
// once. By calling it now, we let smoldot start syncing that chain in the background even before
// a WebSocket connection has been established.
const defaultChain = client
    .addChain({
        chainSpec: chainSpecsById[firstChainSpecId].chainSpec,
        databaseContent: defaultChainDb
    })
    .catch((error) => {
        console.error("Error while adding chain: " + error);
        process.exit(1);
    });

// Catch SIGINT in order to call `remove` and `terminate`. This is mostly a way to test whether
// these two functions work as intended or if they crash/panic.
process.on("SIGINT", () => {
    defaultChain
        .then((chain) => chain.remove())
        .then(() => client.terminate())
        .then(() => process.exit(0))
});

// Uncomment if you want to test the database.
/*defaultChain.then(async (chain) => {
    while (true) {
        chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"chainHead_unstable_finalizedDatabase","params":[]}');
        const jsonResponse = JSON.parse(await chain.nextJsonRpcResponse());
        fs.writeFileSync('database.json', jsonResponse.result);
        await new Promise((resolve) => setTimeout(resolve, 5000));
    }
});*/

// Start the WebSocket server listening on port 9944.
let wsServer = new WebSocketServer({
    port: 9944
});

console.log('JSON-RPC server now listening on port 9944');
console.log('Please visit one of:');
for (const chainId in chainSpecsById) {
    console.log('- ' + chainId + ': https://ipfs.io/ipns/dotapps.io/?rpc=ws%3A%2F%2F127.0.0.1%3A9944%2F' + chainId);
}
console.log('');

wsServer.on('connection', function (connection, request) {
    // Received a new incoming WebSocket connection.

    // Note that we don't care too much about sanitizing input as this is just a demo.
    const chainCfg = chainSpecsById[request.url.substring(1)];

    if (!chainCfg) {
        connection.close();
        return;
    }

    console.log('(demo) New JSON-RPC client connected: ' + request.socket.remoteAddress + '.');

    // Start loading the chain.
    let chain = (async () => {
        if (chainCfg.relayChain) {
            if (!chainSpecsById[chainCfg.relayChain])
                throw new Error("Couldn't find relay chain: " + chainCfg.relayChain);

            const relay = await client.addChain({
                chainSpec: chainSpecsById[chainCfg.relayChain].chainSpec,
                disableJsonRpc: true
            });

            const para = await client.addChain({
                chainSpec: chainCfg.chainSpec,
                potentialRelayChains: [relay]
            });

            (async () => {
                try {
                    for await (const response of para.jsonRpcResponses) {
                        connection.send(response);
                    }
                } catch (_error) { }
            })()

            return { relay, para };
        } else {
            const relay = await client.addChain({
                chainSpec: chainCfg.chainSpec,
            });

            (async () => {
                try {
                    for await (const response of relay.jsonRpcResponses) {
                        connection.send(response);
                    }
                } catch (_error) { }
            })()

            return {
                relay,
            };
        }
    })().catch((error) => {
        console.error("(demo) Error while adding chain: " + error);
        connection.close(1011); // Internal server error
    });

    // Receiving a message from the connection. This is a JSON-RPC request.
    connection.on('message', function (data, isBinary) {
        if (!isBinary) {
            const message = data.toString('utf8');
            chain
                .then(chain => {
                    if (chain.para)
                        chain.para.sendJsonRpc(message);
                    else
                        chain.relay.sendJsonRpc(message);
                })
                .catch((error) => {
                    console.error("(demo) Error during JSON-RPC request: " + error);
                    process.exit(1);
                });
        } else {
            connection.close(1002); // Protocol error
        }
    });

    // When the connection closes, remove the chains that have been added.
    connection.on('close', function (reasonCode, description) {
        console.log("(demo) JSON-RPC client " + request.socket.remoteAddress + ' disconnected.');
        chain.then(chain => {
            chain.relay.remove();
            if (chain.para)
                chain.para.remove();
        }).catch(() => { });
    });
});
