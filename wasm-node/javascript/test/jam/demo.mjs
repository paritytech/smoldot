// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Browser regression for the manual frontend, with controlled RPC streams.
// Run: node --test test/jam/demo.mjs (controlled streams only).
// Add live warp acceptance: node test/jam/demo.mjs --live (WASM + PolkaJam).
import assert from 'node:assert/strict';
import test from 'node:test';
import { chromium } from 'playwright';
import blake from 'blakejs';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

function fixtureStart(options) {
    const queue = [];
    let wake;
    let removed = false;
    const push = message => { queue.push(JSON.stringify(message)); wake?.(); };
    let subscription;
    let followCount = 0;
    const held = [];
    window.fixture = { calls: [], hold: [], removed: false, terminated: false };
    window.fixture.release = () => { for (const message of held.splice(0)) push(message); };
    window.fixture.log = message => options.logCallback(3, 'sync', message);
    window.emitFollow = (result, id = subscription) => push({
        method: 'chainHead_v1_followEvent', params: { subscription: id, result },
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
                    const { id, method, params } = JSON.parse(text);
                    window.fixture.calls.push({ method, params });
                    // A six-validator epoch mark under a twelve-validator maximum.
                    const bytes = new Uint8Array(553);
                    bytes[100] = 1;
                    bytes[165] = 6;
                    new DataView(bytes.buffer).setUint16(551, 5, true);
                    new DataView(bytes.buffer).setUint32(96, 42, true);
                    const header = '0x' + [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
                    if (method === 'chainHead_v1_follow') subscription = 'fixture-' + (++followCount);
                    const response = { id, result: method === 'chainHead_v1_follow' ? subscription :
                        method === 'chainHead_v1_header' ? header : null };
                    if (window.fixture.hold.includes(method)) held.push(response);
                    else push(response);
                },
                remove() { removed = true; window.fixture.removed = true; wake?.(); },
            };
        },
        async terminate() { window.fixture.terminated = true; },
    };
}

const hash = byte => '0x' + byte.repeat(32);

async function setupFixture(page) {
    const params = Buffer.alloc(122);
    params.writeUInt32LE(12, 30);
    params.writeUInt16LE(6, 80);
    params.writeUInt16LE(4, 24);
    const status = {
        node0Alive: true, processes: [], nodeBestBlock: { hash: hash('33'), slot: 43 },
        nodeFinalizedBlock: { hash: hash('22'), slot: 42 },
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
    return status;
}

test('manual finality view distinguishes node reports, client events and forks, and resets', async () => {
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
    try {
        const page = await browser.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        const hash = byte => '0x' + byte.repeat(32);
        const anchor = hash('00'), a = hash('11'), fork = hash('22'), b = hash('33');
        const status = await setupFixture(page);
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


test('re-follow resets subscription state, ignores late replies and bounds repeated stops', async () => {
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
    try {
        const page = await browser.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        await setupFixture(page);
        await page.evaluate(() => window.jamDemo.start());
        const emit = value => page.evaluate(value => window.emitFollow(value), value);
        await emit({ event: 'initialized', finalizedBlockHashes: [hash('00')] });
        await emit({ event: 'newBlock', blockHash: hash('11'), parentBlockHash: hash('00') });
        await page.waitForFunction(() => window.jamDemo.live().rows[0]?.decoded);
        // Hold both header paths and an unpin across tree replacement.
        await page.evaluate(() => {
            window.fixture.hold = ['chainHead_v1_header', 'chainHead_v1_unpin', 'chainHead_v1_follow'];
            void window.jamDemo.header();
        });
        await emit({ event: 'newBlock', blockHash: hash('22'), parentBlockHash: hash('11') });
        await page.evaluate(() => document.getElementById('unpin').onclick());
        await emit({ event: 'stop' });
        await page.waitForFunction(() => window.jamDemo.live().refollows === 1);
        let live = await page.evaluate(() => window.jamDemo.live());
        assert.equal(live.initialized, undefined);
        assert.equal(live.finalized, undefined);
        assert.equal(live.best, undefined);
        assert.equal(live.latestNewBlock, undefined);
        assert.equal(live.blockCount, 2);
        assert.ok(live.rows.every(row => row.finality === 'Superseded'));
        assert.deepEqual(live.leaves, []);
        assert.deepEqual((await page.evaluate(() => window.jamDemo.snapshot())).pins, []);
        for (const id of ['header', 'unpin', 'unfollow']) assert.ok(await page.locator('#' + id).isDisabled());
        await page.evaluate(() => {
            window.fixture.hold = [];
            window.fixture.release();
        });
        await page.waitForFunction(() => window.jamDemo.snapshot().subscription === 'fixture-2');
        // Delayed old events must not populate the replacement follow either.
        await page.evaluate(() => window.emitFollow({ event: 'stop' }, 'fixture-1'));
        await emit({ event: 'initialized', finalizedBlockHashes: [hash('33')] });
        await page.waitForFunction(() => window.jamDemo.live().initialized?.slot === 42);
        assert.match(await page.locator('#live-reanchor').innerText(), /count 1 · slot 42/);
        assert.equal(await page.locator('#live-reanchor code').getAttribute('title'), hash('33') + ' (click to copy)');
        await emit({ event: 'newBlock', blockHash: hash('44'), parentBlockHash: hash('33') });
        await page.waitForFunction(() => window.jamDemo.live().rows[0]?.decoded);
        for (const id of ['header', 'unpin', 'unfollow']) assert.ok(await page.locator('#' + id).isEnabled());
        assert.equal((await page.evaluate(() => window.jamDemo.live())).blockCount, 3);
        assert.ok(!(await page.locator('#logs').innerText()).includes('Error:'));
        assert.equal(await page.evaluate(() => window.fixture.terminated), false);
        for (const message of ['jam-warp-applied set_id=1', 'jam-anchor-unserved']) {
            await page.evaluate(message => window.fixture.log(message), message);
            assert.equal(await page.locator('#live-warp-status').innerText(), message);
        }
        await emit({ event: 'stop' });
        await page.waitForFunction(() => window.jamDemo.snapshot().subscription === 'fixture-3');
        await emit({ event: 'stop' });
        await page.waitForFunction(() => document.getElementById('status').textContent === 'Stopped');
        assert.match(await page.locator('#logs').innerText(), /Follow stopped 3 times within 30 seconds; re-follow limit reached/);
        assert.equal(await page.evaluate(() => window.fixture.calls.filter(call => call.method === 'chainHead_v1_follow').length), 3);
        assert.deepEqual(errors, []);
    } finally { await browser.close(); }
});

test('manual Unfollow and Stop during startup or re-follow cannot restart following', async () => {
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
    try {
        const page = await browser.newPage();
        await setupFixture(page);
        await page.evaluate(() => window.jamDemo.start());
        await page.evaluate(() => {
            window.fixture.hold = ['chainHead_v1_unfollow'];
            void window.jamDemo.unfollow();
            window.emitFollow({ event: 'stop' });
            window.fixture.release();
        });
        await page.waitForFunction(() => window.jamDemo.live().connection.startsWith('Unfollowed'));
        assert.equal(await page.evaluate(() => window.fixture.calls.filter(call => call.method === 'chainHead_v1_follow').length), 1);
        assert.equal((await page.evaluate(() => window.jamDemo.live())).refollows, 0);
        await page.evaluate(() => window.jamDemo.stop());
        // Delay the spec fetch so Stop deterministically lands mid-startup.
        let specRequested;
        const requested = new Promise(resolve => { specRequested = resolve; });
        let releaseSpec;
        const blocked = new Promise(resolve => { releaseSpec = resolve; });
        await page.route('**/jam-demo/spec.json', async route => {
            specRequested();
            await blocked;
            await route.fulfill({ json: {} }).catch(() => {});
        });
        await page.evaluate(() => { void window.jamDemo.start(); });
        await requested;
        await page.evaluate(() => window.jamDemo.stop());
        releaseSpec();
        await page.unroute('**/jam-demo/spec.json');
        assert.equal(await page.locator('#status').innerText(), 'Stopped');
        assert.ok(await page.locator('#start').isEnabled());
        await page.evaluate(() => window.jamDemo.start());
        await page.evaluate(() => {
            window.fixture.hold = ['chainHead_v1_follow'];
            window.emitFollow({ event: 'stop' });
        });
        await page.waitForFunction(() => window.jamDemo.live().refollows === 1);
        await page.evaluate(() => window.jamDemo.stop());
        await page.evaluate(() => window.fixture.release());
        assert.equal(await page.locator('#status').innerText(), 'Stopped');
        assert.equal((await page.evaluate(() => window.jamDemo.snapshot())).running, false);
        assert.ok(await page.locator('#start').isEnabled());
    } finally { await browser.close(); }
});

if (process.argv.includes('--live')) test('aged harness: warp re-follow, blocks, finality, manual Unfollow and the wrong authority set', { timeout: 420000 }, async () => {
    const harness = spawn(process.execPath, ['demo/jam-harness.mjs'], {
        cwd: new URL('../..', import.meta.url), env: process.env, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    harness.stdout.on('data', chunk => { output += chunk; });
    harness.stderr.on('data', chunk => { output += chunk; });
    const exited = new Promise(resolve => harness.on('exit', (code, signal) => resolve({ code, signal })));
    let browser;
    try {
        const readyDeadline = Date.now() + 30000;
        while (!output.includes('Ctrl-C to stop')) {
            if (harness.exitCode !== null || harness.signalCode !== null || Date.now() > readyDeadline)
                throw new Error('Harness did not start:\n' + output);
            await delay(100);
        }
        const url = output.match(/http:\/\/127\.0\.0\.1:\d+\/demo\/jam\.html/)?.[0];
        assert.ok(url, output);
        console.log('Harness ready; aging network for 80 seconds.');
        await delay(80000);
        browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
        console.log('Live browser: ' + browser.version());
        const page = await browser.newPage();
        await page.goto(url);
        await page.locator('#dev-bootnode').check();
        await page.locator('#start').click();
        try {
            await page.waitForFunction(() => window.jamDemo.live().refollows === 1 &&
                window.jamDemo.live().initialized?.slot !== undefined, null, { timeout: 60000 });
            const snapshot = await page.evaluate(() => window.jamDemo.snapshot());
            const events = snapshot.events.map(line => JSON.parse(line.slice(line.indexOf(' ') + 1)))
                .filter(message => message.method === 'chainHead_v1_followEvent').map(message => message.params.result);
            assert.equal(events.filter(event => event.event === 'stop').length, 1);
            const anchors = events.filter(event => event.event === 'initialized');
            assert.equal(anchors.length, 2);
            const spec = await page.evaluate(async () => (await fetch('/jam-demo/spec.json')).json());
            const genesis = '0x' + blake.blake2bHex(Buffer.from(spec.genesis_header.replace(/^0x/, ''), 'hex'), undefined, 32);
            assert.equal(anchors[0].finalizedBlockHashes.at(-1), genesis);
            assert.ok(events.indexOf(anchors[0]) < events.findIndex(event => event.event === 'stop'));
            assert.ok(events.indexOf(anchors[1]) > events.findIndex(event => event.event === 'stop'));
            assert.notEqual(anchors[1].finalizedBlockHashes.at(-1), genesis);
            assert.match(await page.locator('#live-reanchor').innerText(), /count 1 · slot \d+/);
            const before = (await page.evaluate(() => window.jamDemo.live())).blockCount;
            await page.waitForFunction(before => window.jamDemo.live().blockCount > before &&
                window.jamDemo.live().finalityCount > 0, before, { timeout: 60000 });
            const live = await page.evaluate(() => window.jamDemo.live());
            assert.equal(live.refollows, 1);
            assert.match(await page.locator('#live-warp-status').innerText(), /jam-warp-applied/);
            assert.ok((await page.locator('#events').innerText()).includes('"event":"finalized"'));
            console.log(JSON.stringify({ anchors: anchors.map(event => event.finalizedBlockHashes.at(-1)),
                slot: live.initialized.slot, blocks: live.blockCount, finality: live.finalityCount, refollows: live.refollows }));
            for (const id of ['header', 'unpin', 'unfollow']) assert.ok(await page.locator('#' + id).isEnabled());
            await page.locator('#unfollow').click();
            await page.waitForFunction(() => window.jamDemo.live().connection.startsWith('Unfollowed'));
            const unfollowed = await page.evaluate(() => window.jamDemo.live());
            await delay(14000); // More than two dev slots: a live follow would advance.
            const after = await page.evaluate(() => window.jamDemo.live());
            assert.equal(after.blockCount, unfollowed.blockCount);
            assert.equal(after.refollows, 1);
            assert.equal((await page.evaluate(() => window.jamDemo.snapshot())).subscription, undefined);
            await page.locator('#stop').click();
            await page.waitForFunction(() => document.getElementById('status').textContent === 'Stopped');

            // Walkthrough step 10 on the live GRANDPA network, aged past a set
            // change by everything above: a spec whose genesis authority set
            // differs from the network's must be refused while warping, not
            // after a lucky NoData. A spec differing only in its genesis hash
            // would be followed; see demo/jam.md step 10 and planning
            // followups.md U7 (chain identity over WebTransport).
            await page.locator('#spec-url').fill('/jam-demo/spec-wrong-authorities.json');
            await page.locator('#start').click();
            await page.waitForFunction(
                () => window.jamDemo.snapshot().logs.some(line => line.includes('jam-warp-rejected')),
                null, { timeout: 120000 });
            const wrongSpec = await page.evaluate(async () => (await fetch('/jam-demo/spec-wrong-authorities.json')).json());
            const wrongGenesis = '0x' + blake.blake2bHex(Buffer.from(wrongSpec.genesis_header.replace(/^0x/, ''), 'hex'), undefined, 32);
            assert.notEqual(wrongGenesis, genesis);
            // The page keeps only the last 100 log lines, so read the rejection
            // before waiting; the block count is run state and does not roll.
            const rejections = (await page.evaluate(() => window.jamDemo.snapshot().logs))
                .filter(line => line.includes('jam-warp-rejected'));
            assert.ok(rejections.length > 0);
            const refused = await page.evaluate(() => window.jamDemo.live());
            assert.equal(refused.initialized?.anchors.at(-1), wrongGenesis);
            assert.equal(refused.blockCount, 0);
            assert.equal(refused.warpStatus, undefined);
            await delay(30000); // Five dev slots: a client that joined would have blocks.
            const settled = await page.evaluate(() => window.jamDemo.live());
            assert.equal(settled.blockCount, 0);
            assert.equal(settled.refollows, 0);
            console.log(JSON.stringify({ wrongGenesis, blocks: settled.blockCount,
                rejections: rejections.length, firstRejection: rejections[0] }));
            await page.locator('#stop').click();
            await page.waitForFunction(() => document.getElementById('status').textContent === 'Stopped');
        } catch (error) {
            console.error(JSON.stringify(await page.evaluate(() => window.jamDemo.snapshot()), null, 2));
            throw error;
        }
    } finally {
        await browser?.close();
        harness.kill('SIGINT');
        const result = await exited;
        console.log(output);
        if (output.includes('Ctrl-C to stop')) {
            assert.equal(result.code, 130, 'harness must finish its SIGINT cleanup');
            assert.match(output, /teardown complete; no PolkaJam process left behind/);
        }
    }
});
