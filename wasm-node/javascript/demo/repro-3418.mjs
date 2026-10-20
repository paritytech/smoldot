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

// Reproduces the link loss of the paced reopening of refused secondary substreams (#3418).
//
// As a block announces link opens, a polkadot-sdk node can refuse two of its secondary
// substreams at the same moment: on a relay chain, transactions and GRANDPA. The light client
// reopens only the first one at once and the other 5.5 s later, and the node closes the link 5 s
// after the refusals. When GRANDPA is the one left waiting, nothing finalizes until the light
// client reconnects, 10 s later.
//
// This runs fresh light clients against one relay chain node, one after another, until a link
// shows that, then prints its events and exits with 1. Exits with 0 if no attempt does.
//
//     npm ci && npm run build && node demo/repro-3418.mjs <node RPC URL> <node p2p TCP multiaddr>
//
// The chain spec, with a fresh checkpoint, comes from the node (`sync_state_genSyncSpec`), and its
// boot nodes are replaced by the node. Every TCP connection to anything but the node is refused
// before any DNS lookup, and WebSocket and WebRTC are forbidden: the light client talks to that
// node only. Environment: REPRO_ATTEMPTS (60), REPRO_SECONDS (10) per attempt: a link that is
// lost is lost about 6 s into an attempt.

import * as smoldot from '../dist/mjs/index-nodejs.js';
import * as net from 'node:net';
import process from 'node:process';

const [rpcUrl, nodeAddr] = process.argv.slice(2);
const target = nodeAddr?.match(/^\/ip4\/([^/]+)\/tcp\/(\d+)\/p2p\/\w+$/);
if (!rpcUrl || !target) {
    console.error('usage: node demo/repro-3418.mjs <node RPC URL> </ip4/<address>/tcp/<port>/p2p/<peer id>>');
    process.exit(2);
}
const attempts = Number(process.env.REPRO_ATTEMPTS ?? 60);
const seconds = Number(process.env.REPRO_SECONDS ?? 10);

// The chain spec, before the connections are pinned: the RPC is another port.
const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: 1, jsonrpc: '2.0', method: 'sync_state_genSyncSpec', params: [true] }),
});
const { result: spec, error } = await response.json();
if (!spec)
    throw new Error(`sync_state_genSyncSpec: ${JSON.stringify(error)}`);
spec.bootNodes = [nodeAddr];
const chainSpec = JSON.stringify(spec);

// Only the node: `createConnection` and every other TCP dial go through `Socket.connect`.
const allowed = `${target[1]}:${target[2]}`;
let refusedDials = 0;
const realConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
    const first = args[0];
    const options = Array.isArray(first) ? first[0] : first !== null && typeof first === 'object' ? first : { port: first, host: args[1] };
    if (`${options.host}:${options.port}` === allowed)
        return realConnect.apply(this, args);
    refusedDials++;
    process.nextTick(() => this.destroy(Object.assign(new Error('connect ECONNREFUSED (not the node)'), { code: 'ECONNREFUSED' })));
    return this;
};

// The block announces links of a run, from smoldot's debug log.
function linksOf(lines) {
    const links = [];
    for (const { t, message } of lines) {
        const link = links.at(-1);
        if (message.startsWith('gossip-open-success;'))
            links.push({ open: t, refusals: [], grandpa: null, closed: null, mismatches: 0, lines: [] });
        else if (!link || link.closed !== null)
            continue;
        else if (message.startsWith('gossip-secondary-closed;'))
            link.refusals.push(t);
        else if (/^grandpa-(neighbor-packet|commit-message)-received;/.test(message))
            link.grandpa ??= t;
        else if (message.includes('JustificationEngineMismatch'))
            link.mismatches++;
        else if (message.startsWith('gossip-closed;'))
            link.closed = t;
        if (/^(gossip-|grandpa-)/.test(message) || (message.includes('JustificationEngineMismatch') && links.at(-1).mismatches <= 2))
            links.at(-1).lines.push(`${t.toFixed(3)} ${message.replace(/12D3KooW\w+/g, (id) => `${id.slice(0, 12)}…`)}`);
    }
    return links;
}

const refusedAtOpen = (link) => link.refusals.filter((t) => t - link.open <= 1);
const lost = (link) => refusedAtOpen(link).length >= 2 && link.closed !== null && Math.abs(link.closed - refusedAtOpen(link).at(-1) - 5) <= 0.5;

console.log(`${attempts} attempts of ${seconds} s against ${nodeAddr}, one at a time`);
for (let attempt = 1; attempt <= attempts; attempt++) {
    const lines = [];
    const t0 = Date.now();
    const client = smoldot.start({
        maxLogLevel: 4,
        forbidWs: true,
        forbidWss: true,
        forbidWebRtc: true,
        logCallback: (_level, _target, message) => lines.push({ t: (Date.now() - t0) / 1000, message }),
    });
    const chain = await client.addChain({ chainSpec });
    chain.sendJsonRpc(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'chainHead_v1_follow', params: [false] }));
    let initialized = null;
    (async () => {
        for (;;) {
            const event = JSON.parse(await chain.nextJsonRpcResponse()).params?.result?.event;
            if (event === 'initialized' && initialized === null)
                initialized = (Date.now() - t0) / 1000;
        }
    })().catch(() => { });
    await new Promise((resolve) => setTimeout(resolve, seconds * 1000));
    await client.terminate().catch(() => { });

    const links = linksOf(lines);
    const summary = links.map((l, i) => `link ${i + 1}: ${refusedAtOpen(l).length} refused at once, GRANDPA ${l.grandpa === null ? 'never' : `+${(l.grandpa - l.open).toFixed(2)}s`}, ${l.closed === null ? 'kept' : `closed by the node ${(l.closed - (l.refusals.at(-1) ?? l.open)).toFixed(2)}s after the refusals`}, ${l.mismatches} JustificationEngineMismatch`);
    console.log(`attempt ${attempt}: follow initialized ${initialized === null ? 'never' : `after ${initialized.toFixed(1)}s`}; ${summary.join('; ') || 'no link'}`);
    const bad = links.find((l) => lost(l) && l.grandpa === null) ?? links.find(lost);
    if (bad) {
        console.log(`\nREPRODUCED: the node refused ${refusedAtOpen(bad).length} secondary substreams as the link opened and closed the link ${(bad.closed - refusedAtOpen(bad).at(-1)).toFixed(2)} s later${bad.grandpa === null ? ', with no GRANDPA on it' : ''}. The link's events:\n`);
        console.log(bad.lines.join('\n'));
        console.log(`\n(dials to anything but the node, refused: ${refusedDials})`);
        process.exit(1);
    }
}
console.log(`\nnot reproduced in ${attempts} attempts (dials to anything but the node, refused: ${refusedDials})`);
process.exit(0);
