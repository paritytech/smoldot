// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Polls `sudo_unstable_syncStatus` every 2s and prints the sync progress.
// Usage (from wasm-node/javascript):
//     npm run sync-progress              # uses polkadot by default
//     npm run sync-progress -- ksmcc3    # pass the chain id as argv[2]

import * as smoldot from '../dist/mjs/index-nodejs.js';
import * as fs from 'node:fs';
import process from 'node:process';

const chainId = process.argv[2] || 'polkadot';
const chainSpecPath = `../../demo-chain-specs/${chainId}.json`;
const chainSpec = fs.readFileSync(chainSpecPath, 'utf8');

const client = smoldot.start({
    maxLogLevel: 2, // keep logs quiet; bump to 3/4 if you want details
    logCallback: () => {},
});

const chain = await client.addChain({ chainSpec });

// Route JSON-RPC responses by id.
const pending = new Map();
let nextId = 1;
function rpc(method, params = []) {
    const id = nextId++;
    chain.sendJsonRpc(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
    return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
}

(async () => {
    try {
        for await (const raw of chain.jsonRpcResponses) {
            const msg = JSON.parse(raw);
            if (msg.id && pending.has(msg.id)) {
                const { resolve, reject } = pending.get(msg.id);
                pending.delete(msg.id);
                if (msg.error) reject(new Error(JSON.stringify(msg.error)));
                else resolve(msg.result);
            }
        }
    } catch (_) {}
})();

console.log(`Chain: ${chainId}. Polling sudo_unstable_syncStatus every 2s. Ctrl-C to stop.\n`);

const startedAt = Date.now();
const interval = setInterval(async () => {
    try {
        const { currentBlock, highestBlock } = await rpc('sudo_unstable_syncStatus');
        const pct = highestBlock > 0 ? (currentBlock / highestBlock) * 100 : 0;
        const elapsed = Math.round((Date.now() - startedAt) / 1000);
        const bar = '#'.repeat(Math.round(pct / 5)).padEnd(20, '.');
        process.stdout.write(
            `\r[${bar}] ${pct.toFixed(2)}%  ${currentBlock}/${highestBlock}  t+${elapsed}s    `
        );
    } catch (err) {
        console.error('\nrpc error:', err.message);
    }
}, 2000);

process.on('SIGINT', async () => {
    clearInterval(interval);
    console.log('\nShutting down…');
    await chain.remove();
    await client.terminate();
    process.exit(0);
});
