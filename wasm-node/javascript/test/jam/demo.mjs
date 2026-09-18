// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Browser regression for the manual frontend, with controlled RPC streams.
// Run: node --test test/jam/demo.mjs (no WASM or PolkaJam required).
import assert from 'node:assert/strict';
import test from 'node:test';
import { chromium } from 'playwright';

function fixtureStart() {
    const queue = [];
    let wake;
    let removed = false;
    const push = message => { queue.push(JSON.stringify(message)); wake?.(); };
    window.emitFollow = result => push({
        method: 'chainHead_v1_followEvent', params: { subscription: 'fixture', result },
    });
    return {
        async addChain() {
            return {
                get jsonRpcResponses() {
                    return (async function* () {
                        while (!removed) {
                            if (!queue.length) await new Promise(resolve => { wake = resolve; });
                            while (queue.length) yield queue.shift();
                        }
                    })();
                },
                sendJsonRpc(text) {
                    const { id, method } = JSON.parse(text);
                    // A six-validator epoch mark under a twelve-validator maximum.
                    const bytes = new Uint8Array(553);
                    bytes[100] = 1;
                    bytes[165] = 6;
                    new DataView(bytes.buffer).setUint16(551, 5, true);
                    new DataView(bytes.buffer).setUint32(96, 42, true);
                    const header = '0x' + [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
                    push({ id, result: method === 'chainHead_v1_follow' ? 'fixture' :
                        method === 'chainHead_v1_header' ? header : null });
                },
                remove() { removed = true; wake?.(); },
            };
        },
        async terminate() {},
    };
}

test('manual finality view distinguishes node reports, client events and forks, and resets', async () => {
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
    try {
        const page = await browser.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        const hash = byte => '0x' + byte.repeat(32);
        const anchor = hash('00'), a = hash('11'), fork = hash('22'), b = hash('33');
        const params = Buffer.alloc(122);
        params.writeUInt32LE(12, 30);
        params.writeUInt16LE(6, 80);
        params.writeUInt16LE(4, 24);
        const status = {
            node0Alive: true, processes: [], nodeBestBlock: { hash: b, slot: 43 },
            nodeFinalizedBlock: { hash: fork, slot: 42 },
        };
        await page.route('http://localhost/**', async route => {
            const pathname = new URL(route.request().url()).pathname;
            if (pathname === '/jam-demo/control')
                return route.fulfill({ json: { ok: true, status } });
            if (pathname === '/jam-demo/spec.json')
                return route.fulfill({ json: { protocol_parameters: params.toString('hex') } });
            if (pathname === '/dist/mjs/index-browser.js')
                return route.fulfill({ contentType: 'text/javascript', body: 'export const start = ' + fixtureStart.toString() });
            if (['/demo/jam.html', '/demo/jam.mjs'].includes(pathname))
                return route.fulfill({ path: new URL('../..' + pathname, import.meta.url).pathname });
            return route.fulfill({ status: 404 });
        });
        await page.goto('http://localhost/demo/jam.html');
        await page.evaluate(() => window.jamDemo.start());
        const emit = value => page.evaluate(value => window.emitFollow(value), value);
        await emit({ event: 'initialized', finalizedBlockHashes: [anchor] });
        for (const [blockHash, parentBlockHash] of [[a, anchor], [fork, anchor], [b, a]])
            await emit({ event: 'newBlock', blockHash, parentBlockHash });
        await page.waitForFunction(() => window.jamDemo.live().rows.every(row => row.decoded));
        let live = await page.evaluate(() => window.jamDemo.live());
        assert.equal(live.finalized.hash, anchor);
        assert.equal(live.finalityCount, 0);
        assert.ok(live.rows.every(row => row.finality === 'Unfinalized'));
        assert.ok(live.rows.every(row => row.decoded.epochMark && row.decoded.authorIndex === 5));
        assert.match(await page.locator('#finality-node').innerText(), /node report only/);
        assert.equal(await page.locator('#finality-node-gap').innerText(), '1 slot(s)');

        await emit({ event: 'finalized', finalizedBlockHashes: [a, b], prunedBlockHashes: [fork] });
        await page.waitForFunction(() => window.jamDemo.live().finalityCount === 1);
        live = await page.evaluate(() => window.jamDemo.live());
        assert.equal(live.finalized.hash, b);
        assert.equal(live.finalized.slot, 42);
        assert.deepEqual(live.rows.map(row => row.finality), ['Finalized', 'Pruned', 'Finalized']);
        assert.ok(!live.leaves.includes(fork));
        // Pruning is not unpinning: header availability is a separate lifecycle.
        assert.ok((await page.evaluate(() => window.jamDemo.snapshot())).pins.includes(fork));
        assert.match(await page.locator('#blocks-body').innerText(), /Pruned/);

        // Losing the node RPC must clear its old head without altering client finality.
        status.nodeFinalizedBlock = null;
        status.nodeFinalizedBlockError = 'fixture unavailable';
        await page.waitForFunction(() => document.getElementById('finality-node').textContent.includes('fixture unavailable'));
        assert.equal(await page.locator('#finality-node-gap').innerText(), '–');
        assert.equal((await page.evaluate(() => window.jamDemo.live())).finalized.hash, b);
        await page.evaluate(() => window.jamDemo.unfollow());
        assert.match(await page.locator('#finality-state').innerText(), /last observation/);
        await page.evaluate(() => window.jamDemo.stop());
        assert.equal(await page.locator('#finality-head').innerText(), '–');
        assert.equal(await page.locator('#finality-count').innerText(), '0');
        await page.evaluate(() => window.jamDemo.start());
        assert.equal((await page.evaluate(() => window.jamDemo.live())).finalized, undefined);
        assert.equal(await page.locator('#finality-age').innerText(), '–');
        await page.evaluate(() => window.jamDemo.stop());
        assert.deepEqual(errors, []);
    } finally {
        await browser.close();
    }
});
