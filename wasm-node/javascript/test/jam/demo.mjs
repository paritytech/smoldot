// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Browser regression for the manual frontend.
// Run: node --test test/jam/demo.mjs (controlled RPC streams only, no network).
// `--live` adds the live page regression against a running GRANDPA network the
// harness attaches to (`JAM_SPEC_PATH`, `JAM_RPC_PORT`). It is the JavaScript
// step of the `jam_demo` scenario in `e2e-tests`, which spawns that network
// on zombienet and ages it past a set change:
//   cargo test --manifest-path e2e-tests/Cargo.toml --test jam_demo -- --nocapture
import assert from 'node:assert/strict';
import test from 'node:test';
import { chromium } from 'playwright';
import blake from 'blakejs';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { corruptGenesisAuthorities } from '../../../../e2e-tests/shared/jam.js';
import { BLOCK_SLOT_EVENTS, CATEGORIES, blake2b256Hex as pageBlake2b256Hex, createEventStore, parseJamLog } from '../../demo/jam-events.mjs';

const live = process.argv.includes('--live');
const LIVE_SPEC_PATH = process.env.JAM_SPEC_PATH;
const LIVE_RPC_PORT = process.env.JAM_RPC_PORT;
if (live && (!LIVE_SPEC_PATH || !LIVE_RPC_PORT)) {
    throw new Error('--live needs JAM_SPEC_PATH and JAM_RPC_PORT of a running GRANDPA network; ' +
        'run it through `cargo test --manifest-path e2e-tests/Cargo.toml --test jam_demo`');
}

/** The node's JSON-RPC, as the harness's oracle calls it. */
async function nodeRpc(method, params = []) {
    const response = await fetch(`http://127.0.0.1:${LIVE_RPC_PORT}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal: AbortSignal.timeout(3000),
    });
    const body = await response.json();
    if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
    return body.result;
}

const blake2b256Hex = hex => '0x' + blake.blake2bHex(Buffer.from(hex.replace(/^0x/, ''), 'hex'), undefined, 32);

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
/** The fixture spec's genesis header: the page only hashes it for the events download. */
const FIXTURE_GENESIS_HEADER = '0x' + '5a'.repeat(140);

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
            return route.fulfill({ json: { protocol_parameters: params.toString('hex'), genesis_header: FIXTURE_GENESIS_HEADER } });
        if (pathname === '/dist/mjs/index-browser.js')
            return route.fulfill({ contentType: 'text/javascript', body: 'export const start = ' + fixtureStart.toString() });
        if (['/demo/jam.html', '/demo/jam.mjs', '/demo/jam-events.mjs'].includes(pathname))
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
        for (const message of [
            'jam-warp-applied; set_id=1, slot=42, fragments=1, state_bytes=9, state_responses=1, fragment_finality=true, conn=0, hash=' + hash('33'),
            'jam-anchor-unserved; reason=NoData, error=anchor [1, 2] at slot 42 is unserved, hash=[1, 2], slot=42',
        ]) {
            await page.evaluate(message => window.fixture.log(message), message);
            await page.waitForFunction(message => document.getElementById('live-warp-status').textContent === message, message);
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

// --------------------------------------------------------------------------
// Client events (D20, debug events on the demo page): the parser against the
// docs table and the driver's source, free text, request pairing, the cap and
// the filters in Node; then the page's section, live rows and download.
// --------------------------------------------------------------------------

/** The rows of demo/jam.md's "Client events" table: name, category, field keys. */
async function documentedEvents() {
    const docs = await fs.readFile(new URL('../../demo/jam.md', import.meta.url), 'utf8');
    const table = docs.slice(docs.indexOf('### Events'), docs.indexOf('### Why a connection ended'));
    return [...table.matchAll(/^\| `(jam-[a-z0-9-]+)` \| (\w+) \| (.*?) \| .* \|$/gm)].map(match => ({
        name: match[1], category: match[2], fields: [...match[3].matchAll(/`([a-z_0-9]+)`/g)].map(field => field[1]),
    }));
}

/** A line with every documented field, free text where the grammar allows it. */
function synthesize({ name, fields }) {
    const value = key => key === 'message' ? 'jamnp-stream-reset:6 the peer said, no=data, twice'
        : ['hash', 'target', 'block'].includes(key) ? hash('ab')
            : ['slot', 'conn'].includes(key) ? '1' : key === 'req' ? '42' : 'v-' + key;
    return fields.length === 0 ? name : name + '; ' + fields.map(key => key + '=' + value(key)).join(', ');
}

test('client events: every documented event parses, and the docs list exactly what the driver logs', async () => {
    const documented = await documentedEvents();
    assert.ok(documented.length >= 39, `${documented.length} documented events`);
    for (const row of documented) {
        assert.ok(CATEGORIES.includes(row.category), row.name);
        const line = synthesize(row);
        const event = parseJamLog('jam-dev-0', line, 7);
        assert.ok(event, line);
        assert.equal(event.name, row.name);
        assert.equal(event.category, row.category, row.name);
        assert.deepEqual(Object.keys(event.fields), row.fields, row.name);
        const connection = BLOCK_SLOT_EVENTS.has(row.name) ? 'conn' : 'slot';
        assert.equal(event.slot, row.fields.includes(connection) ? 1 : null, row.name);
        assert.equal(event.req, row.fields.includes('req') ? 42 : null, row.name);
        if (row.fields.includes('message')) assert.equal(event.rest, 'jamnp-stream-reset:6 the peer said, no=data, twice');
    }
    // Every `"jam-..."` literal of the driver is an event name; all are documented.
    const rust = await fs.readFile(new URL('../../../../light-base/src/sync_service/jam.rs', import.meta.url), 'utf8');
    const logged = [...new Set([...rust.matchAll(/"(jam-[a-z0-9-]+)"/g)].map(match => match[1]))].sort();
    assert.deepEqual(logged, documented.map(row => row.name).sort());
});

test('client events: free text, byte lists, non-events, request pairing, the cap and filters', () => {
    const reset = parseJamLog('t', 'jam-stream-reset; slot=0, stream=state, req=4, reason=NoData, message=jamnp-stream-reset:6 a, b=c, d', 1);
    assert.equal(reset.fields.reason, 'NoData');
    assert.equal(reset.fields.message, 'jamnp-stream-reset:6 a, b=c, d');
    assert.equal(reset.fields.b, undefined);
    const unserved = parseJamLog('t', 'jam-anchor-unserved; reason=NoData, error=anchor [1, 2] at slot 9 is unserved, hash=[1, 2, 3], slot=9', 1);
    assert.deepEqual(unserved.fields, { reason: 'NoData', error: 'anchor [1, 2] at slot 9 is unserved', hash: '[1, 2, 3]', slot: '9' });
    assert.equal(unserved.slot, null, 'a block slot is not a connection slot');
    assert.equal(parseJamLog('t', 'jam-connect', 1).slot, null);
    for (const line of ['sync-service: something', 'jam-', 'jam-unknownarea-x', 'jam-peer-connected; no fields here', 'jam-peer connected']) {
        assert.equal(parseJamLog('t', line, 1), null, line);
    }

    const store = createEventStore({ max: 5 });
    store.add('t', 'jam-block-request-queued; slot=0, req=1, purpose=ascending, hash=' + hash('aa') + ', direction=ascending, max_blocks=4', 100);
    store.add('t', 'jam-state-request-queued; slot=1, req=2, purpose=discovery, block=' + hash('bb') + ', trust=authenticated, keys=C8, max_size=800000', 110);
    store.add('t', 'jam-justification-request-queued; slot=1, req=3, purpose=finality, target=' + hash('cc') + ', target_slot=-, set_id=2', 120);
    assert.equal(store.rows.length, 3);
    assert.equal(store.pending(), 3);
    store.add('t', 'jam-block-request-ended; slot=0, req=1, purpose=ascending, outcome=ok, blocks=4, bytes=900, elapsed_ms=35', 135);
    assert.equal(store.rows.length, 3, 'an outcome updates its request row in place');
    assert.deepEqual({ ...store.rows[0].request, end: undefined }, {
        pending: false, purpose: 'ascending', endName: 'jam-block-request-ended', endAt: 135, outcome: 'ok', elapsedMs: 35, end: undefined,
        endLine: 'jam-block-request-ended; slot=0, req=1, purpose=ascending, outcome=ok, blocks=4, bytes=900, elapsed_ms=35',
    });
    assert.ok(store.rows[0].line.startsWith('jam-block-request-queued; slot=0, req=1'));
    // A request cut short by preemption has no outcome line; the disconnect closes it.
    store.add('t', 'jam-peer-disconnected; slot=1, source=genesis, address=127.0.0.1:1, lasted_ms=5000, reason=preempted', 400);
    assert.equal(store.pending(), 0);
    assert.equal(store.rows[1].request.outcome, 'cancelled');
    assert.equal(store.rows[1].request.end.reason, 'preempted');
    // An outcome whose start was never seen is kept as its own row.
    store.add('t', 'jam-warp-request-ended; slot=0, req=77, purpose=warp-join, outcome=failed, error=NoData, elapsed_ms=3', 410);
    assert.equal(store.rows.at(-1).request.outcome, 'failed');
    // The cap drops the oldest rows and counts them; totals cover everything.
    for (let index = 0; index < 4; index += 1) store.add('t', 'jam-announcement; slot=0, block_slot=' + index + ', final_slot=0', 500 + index);
    assert.equal(store.rows.length, 5);
    assert.equal(store.dropped, 4);
    assert.equal(store.total, 10, 'outcome lines count, though they update rows in place');
    assert.equal(store.byCategory.blocks, 6);
    assert.equal(store.byName['jam-announcement'], 4);
    // The block request row was dropped with its pairing: a late outcome stands alone.
    store.add('t', 'jam-block-request-ended; slot=0, req=1, purpose=ascending, outcome=ok, blocks=1, bytes=9, elapsed_ms=1', 600);
    assert.equal(store.rows.at(-1).request.endName, 'jam-block-request-ended');
    store.add('t', 'jam-nonsense here', 601);
    assert.equal(store.unparsed, 1);
    assert.deepEqual(store.unparsedSamples, ['jam-nonsense here']);
    // Filters: categories and text, newest first.
    assert.deepEqual(store.view({ categories: new Set(['warp']) }), [], 'the warp row was the oldest and is gone');
    assert.deepEqual(store.view({ categories: new Set(['blocks']) }).map(row => row.name),
        ['jam-block-request-ended', ...Array(4).fill('jam-announcement')]);
    assert.deepEqual(store.view({ text: 'BLOCK_SLOT=3' }).map(row => row.fields.block_slot), ['3']);
    assert.equal(store.view({ categories: new Set(CATEGORIES), text: '' })[0].at, 600);
    const snapshot = store.snapshot();
    assert.equal(JSON.parse(JSON.stringify(snapshot)).events.length, 5);

    for (const length of [0, 1, 127, 128, 129, 300, 1000]) {
        const bytes = Uint8Array.from({ length }, (_, index) => (index * 31 + 7) & 255);
        assert.equal(pageBlake2b256Hex(bytes), '0x' + blake.blake2bHex(bytes, undefined, 32), `${length} bytes`);
    }
});

test('client events section: request rows, filters, peers and warp status from events, cap, download', async () => {
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
    try {
        const context = await browser.newContext({ acceptDownloads: true });
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        await setupFixture(page);
        await page.evaluate(() => window.jamDemo.start());
        const log = lines => page.evaluate(lines => { for (const line of lines) window.fixture.log(line); }, lines);
        const summary = () => page.locator('#client-events-summary').innerText();
        await log([
            'jam-pool-initial; bootnodes=1, genesis=5, max_discovered=12, slots=2',
            'jam-pool-candidate; index=0, source=bootnode, address=127.0.0.1:40000, p256=fixture',
            'jam-slot-assigned; slot=0, source=bootnode, address=127.0.0.1:40000, p256=fixture',
            'jam-connect',
            'jam-peer-connected; slot=0, source=bootnode, address=127.0.0.1:40000, final_slot=40, handshake_ms=12',
            'jam-block-request-queued; slot=0, req=1, purpose=ascending, hash=' + hash('aa') + ', direction=ascending, max_blocks=4',
            'jam-justification-request-queued; slot=0, req=2, purpose=finality, target=' + hash('bb') + ', target_slot=41, set_id=1',
        ]);
        await page.waitForFunction(() => document.querySelectorAll('#client-events-body tr').length === 7);
        assert.match(await summary(), /^7 event\(s\) kept of at most 1000 · 0 dropped · 2 request\(s\) pending · 7 since Start$/);
        assert.equal(await page.locator('#client-events-body tr[data-request="pending"]').count(), 2);
        assert.match(await page.locator('#client-events-body tr').first().innerText(), /jam-justification-request.*#2.*pending/s);
        const hashCode = page.locator('#client-events-body code[title^="' + hash('aa') + '"]');
        assert.equal(await hashCode.count(), 1, 'hashes are shortened and copy on click');
        assert.equal(await hashCode.innerText(), hash('aa').slice(0, 10) + '…' + hash('aa').slice(-8));
        let live = await page.evaluate(() => window.jamDemo.live());
        assert.deepEqual(live.peers.map(({ slot, source, state }) => ({ slot, source, state })), [{ slot: 0, source: 'bootnode', state: 'connected' }]);

        await log([
            'jam-block-request-ended; slot=0, req=1, purpose=ascending, outcome=ok, blocks=4, bytes=2000, elapsed_ms=35',
            'jam-stream-reset; slot=0, stream=justification, req=2, reason=Rejected, message=jamnp-stream-reset:1 closed, code=1',
            'jam-justification-request-ended; slot=0, req=2, purpose=finality, outcome=failed, error=Rejected, elapsed_ms=50',
            'jam-warp-rejected; slot=0, step=fragments, req=3, error=Decode(LengthLimit)',
            'jam-peer-disconnected; slot=0, source=bootnode, address=127.0.0.1:40000, lasted_ms=900, reason=warp-rejected',
        ]);
        await page.waitForFunction(() => document.querySelectorAll('#client-events-body tr').length === 10);
        assert.equal(await page.locator('#client-events-body tr[data-request="pending"]').count(), 0);
        assert.match(await page.locator('#client-events-body tr[data-request="ok"]').innerText(), /ok in 35 ms blocks 4 bytes 2000/);
        assert.match(await page.locator('#client-events-body tr[data-request="failed"]').innerText(), /failed in 50 ms error Rejected/);
        assert.match(await page.locator('#client-events-body tr', { hasText: 'jam-stream-reset' }).innerText(),
            /message jamnp-stream-reset:1 closed, code=1/);
        live = await page.evaluate(() => window.jamDemo.live());
        assert.equal(live.peers[0].state, 'disconnected');
        assert.equal(live.peers[0].reason, 'warp-rejected');
        assert.match(await page.locator('#live-peers').innerText(), /disconnected \(warp-rejected\)/);
        assert.equal(live.warp.event, 'jam-warp-rejected');
        assert.match(await page.locator('#live-warp-status').innerText(),
            /^rejected at step fragments on slot 0: Decode\(LengthLimit\) · 1 rejection\(s\) since Start · jam-warp-rejected; /);

        // Category toggles and the text filter.
        await page.locator('#client-events-peers').uncheck();
        await page.waitForFunction(() => !document.querySelector('#client-events-body tr[data-category="peers"]'));
        assert.equal(await page.locator('#client-events-body tr').count(), 5);
        assert.match(await summary(), /· 5 shown$/);
        await page.locator('#client-events-peers').check();
        await page.locator('#client-events-filter').fill('finality');
        await page.waitForFunction(() => document.querySelectorAll('#client-events-body tr').length === 1);
        assert.match(await page.locator('#client-events-body tr').innerText(), /jam-justification-request/);
        await page.locator('#client-events-filter').fill('');
        await page.waitForFunction(() => document.querySelectorAll('#client-events-body tr').length === 10);

        // The cap: 1,000 events, the oldest dropped and counted.
        await page.evaluate(() => {
            for (let index = 0; index < 1005; index += 1)
                window.fixture.log('jam-announcement; slot=1, block_slot=' + index + ', final_slot=0');
        });
        await page.waitForFunction(() => document.getElementById('client-events-summary').textContent.includes('15 dropped'));
        assert.equal(await page.locator('#client-events-body tr').count(), 1000);
        const kept = await page.evaluate(() => window.jamDemo.clientEvents());
        assert.equal(kept.retained, 1000);
        assert.equal(kept.total, 1017);
        assert.equal(kept.byCategory.blocks, 1007);
        assert.equal(kept.unparsed, 0);

        // The download: the kept events, the genesis hash and the start time.
        await page.evaluate(() => window.jamDemo.stop());
        assert.ok(await page.locator('#client-events-download').isEnabled(), 'the last run stays downloadable after Stop');
        const [download] = await Promise.all([page.waitForEvent('download'), page.locator('#client-events-download').click()]);
        assert.match(download.suggestedFilename(), /^jam-client-events-\d{4}-\d\d-\d\dT[\d-]+Z\.json$/);
        const saved = JSON.parse(await fs.readFile(await download.path(), 'utf8'));
        assert.equal(saved.format, 'smoldot-jam-client-events/1');
        assert.equal(saved.genesisHash, '0x' + blake.blake2bHex(Buffer.from(FIXTURE_GENESIS_HEADER.slice(2), 'hex'), undefined, 32));
        assert.ok(!Number.isNaN(Date.parse(saved.startedAt)));
        assert.equal(saved.events.length, 1000);
        assert.equal(saved.dropped, 15);
        assert.equal(saved.events.at(-1).fields.block_slot, '1004');
        await page.evaluate(() => window.jamDemo.start());
        await page.waitForFunction(() => document.getElementById('client-events-summary').textContent.startsWith('0 event(s) kept'));
        await page.evaluate(() => window.jamDemo.stop());
        assert.deepEqual(errors, []);
    } finally {
        await browser.close();
    }
});

if (live) test('aged network: warp re-follow, blocks, finality, manual Unfollow and the wrong authority set', { timeout: 420000 }, async () => {
    // The network is already aged past a set change by `jam_demo`.
    const run = await startHarness({ JAM_SPEC_PATH: LIVE_SPEC_PATH, JAM_RPC_PORT: LIVE_RPC_PORT });
    const { harness, exited } = run;
    let browser;
    try {
        const url = run.url;
        assert.ok(url, run.output);
        browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
        console.log('Live browser: ' + browser.version());
        const page = await browser.newPage();
        await page.goto(url);
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
            const genesis = blake2b256Hex(spec.genesis_header);
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

            // Client events: every `jam-*` line of the run parsed, and every
            // category has events. `state` comes from the warp join's reads and
            // the C(8) refresh after the first finality advance; `warp` from
            // the aged network. Only the pool's wait line may never fire.
            await page.waitForFunction(() => (window.jamDemo.clientEvents()?.byName['jam-pool-changed'] ?? 0) > 0,
                null, { timeout: 60000 });
            const clientEvents = await page.evaluate(() => window.jamDemo.clientEvents());
            assert.equal(clientEvents.unparsed, 0, JSON.stringify(clientEvents.unparsedSamples));
            for (const category of CATEGORIES) assert.ok(clientEvents.byCategory[category] > 0, `no ${category} event`);
            for (const name of ['jam-pool-initial', 'jam-pool-candidate', 'jam-slot-assigned', 'jam-peer-connected',
                'jam-warp-request-ended', 'jam-warp-join-selected', 'jam-warp-head-fetched', 'jam-warp-item-read',
                'jam-warp-applied', 'jam-block-request-ended', 'jam-justification-request-ended',
                'jam-state-request-ended', 'jam-finalized', 'jam-pool-changed'])
                assert.ok(clientEvents.byName[name] > 0, `no ${name}`);
            assert.equal(clientEvents.genesisHash, genesis);
            const requestRows = clientEvents.events.filter(event => event.request);
            assert.ok(requestRows.some(event => !event.request.pending && event.request.outcome === 'ok'
                && Number.isInteger(event.request.elapsedMs)), 'a request row from start to outcome');
            assert.match(await page.locator('#client-events-summary').innerText(), /event\(s\) kept of at most 1000/);
            console.log(JSON.stringify({ clientEvents: { total: clientEvents.total, retained: clientEvents.retained,
                pending: clientEvents.pending, byCategory: clientEvents.byCategory, byName: clientEvents.byName } }));
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
            await reportClientEvents(page, 'aged network');

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
            const wrongGenesis = blake2b256Hex(wrongSpec.genesis_header);
            assert.notEqual(wrongGenesis, genesis);
            // The page keeps only the last 100 log lines, so read the rejection
            // before waiting; the block count is run state and does not roll.
            const rejections = (await page.evaluate(() => window.jamDemo.snapshot().logs))
                .filter(line => line.includes('jam-warp-rejected'));
            assert.ok(rejections.length > 0);
            const refused = await page.evaluate(() => window.jamDemo.live());
            assert.equal(refused.initialized?.anchors.at(-1), wrongGenesis);
            assert.equal(refused.blockCount, 0);
            // O20 (demo Warp status should show a rejected warp): the status
            // names the rejection instead of staying empty.
            assert.equal(refused.warp?.event, 'jam-warp-rejected');
            assert.match(await page.locator('#live-warp-status').innerText(), /^rejected at step \S+ on slot \d: \S+ · \d+ rejection/);
            await delay(30000); // Five dev slots: a client that joined would have blocks.
            const settled = await page.evaluate(() => window.jamDemo.live());
            assert.equal(settled.blockCount, 0);
            assert.equal(settled.refollows, 0);
            assert.ok(!(await page.evaluate(() => window.jamDemo.live().warpStatus)).startsWith('jam-warp-applied'));
            console.log(JSON.stringify({ wrongGenesis, blocks: settled.blockCount,
                rejections: rejections.length, firstRejection: rejections[0],
                warpStatus: await page.locator('#live-warp-status').innerText() }));
            await page.locator('#stop').click();
            await page.waitForFunction(() => document.getElementById('status').textContent === 'Stopped');
            await reportClientEvents(page, 'wrong authority set');
        } catch (error) {
            console.error(JSON.stringify(await page.evaluate(() => window.jamDemo.snapshot()), null, 2));
            throw error;
        }
    } finally {
        await browser?.close();
        harness.kill('SIGINT');
        const result = await exited;
        console.log(run.output);
        assert.equal(result.code, 130, 'harness must finish its SIGINT cleanup');
        assert.match(run.output, /the network was not ours and keeps running/);
    }
});

/** One page run's client events for the record: totals, volume and one raw line per event. */
async function reportClientEvents(page, label) {
    const saved = await page.evaluate(() => window.jamDemo.clientEvents());
    const examples = {};
    for (const event of saved.events) {
        examples[event.name] ??= event.line;
        if (event.request?.endName) examples[event.request.endName] ??= event.request.endLine;
    }
    const count = (map, key) => { map[key] = (map[key] ?? 0) + 1; };
    const reasons = {};
    const outcomes = {};
    for (const event of saved.events) {
        if (event.name === 'jam-peer-disconnected') count(reasons, event.fields.reason);
        if (event.request) count(outcomes, event.name.replace(/-request-(queued|ended)$/, '') + ' ' +
            (event.request.purpose ?? '-') + ' ' + (event.request.pending ? 'pending' : event.request.outcome));
    }
    console.log(JSON.stringify({ clientEventsReport: label, seconds: (Date.now() - Date.parse(saved.startedAt)) / 1000,
        total: saved.total, bytes: saved.bytes, dropped: saved.dropped, clientLog: saved.clientLog,
        byName: saved.byName, reasons, outcomes, examples }));
}

/** Starts `demo/jam-harness.mjs` with `env` and resolves once its banner is out. */
async function startHarness(env) {
    const harness = spawn(process.execPath, ['demo/jam-harness.mjs'], {
        cwd: new URL('../..', import.meta.url), env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    const state = { harness, output: '' };
    harness.stdout.on('data', chunk => { state.output += chunk; });
    harness.stderr.on('data', chunk => { state.output += chunk; });
    state.exited = new Promise(resolve => harness.on('exit', (code, signal) => resolve({ code, signal })));
    const readyDeadline = Date.now() + 30000;
    while (!state.output.includes('Ctrl-C to stop')) {
        if (harness.exitCode !== null || harness.signalCode !== null || Date.now() > readyDeadline)
            throw new Error('Harness did not start:\n' + state.output);
        await delay(100);
    }
    state.url = state.output.match(/http:\/\/127\.0\.0\.1:\d+\/demo\/jam\.html/)?.[0];
    return state;
}

// The zombienet flow (`just zombie-jam`, then `just demo-jam-attach`): the
// harness only gets a spec through `JAM_SPEC_PATH`. Three variants of the
// network's spec: as zombienet writes it (every validator a bootnode), with
// jam0 as its only bootnode, and with `bootnodes` stripped, so the client must
// find every peer in the genesis C(8).
if (live) test('attach mode: spec from JAM_SPEC_PATH with all, one or no bootnodes, no network managed', { timeout: 420000 }, async () => {
    const runtimeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'jam-demo-attach-'));
    const spec = JSON.parse(await fs.readFile(LIVE_SPEC_PATH, 'utf8'));
    assert.equal(spec.bootnodes.length, 6, 'zombienet writes every validator as a bootnode');
    const oneBootnodePath = path.join(runtimeDir, 'spec-one-bootnode.json');
    await fs.writeFile(oneBootnodePath, JSON.stringify({ ...spec, bootnodes: [spec.bootnodes[0]] }));
    const genesisOnlyPath = path.join(runtimeDir, 'spec-genesis-only.json');
    await fs.writeFile(genesisOnlyPath, JSON.stringify({ ...spec, bootnodes: [] }));
    let browser;
    try {
        browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
        for (const [variant, file, expected] of [
            ['all bootnodes', LIVE_SPEC_PATH, ['bootnode']],
            ['one bootnode', oneBootnodePath, ['bootnode', 'genesis']],
            ['genesis only', genesisOnlyPath, ['genesis']],
        ]) {
            const run = await startHarness({ JAM_SPEC_PATH: file, JAM_RPC_PORT: LIVE_RPC_PORT });
            const page = await browser.newPage();
            const errors = [];
            page.on('pageerror', error => errors.push(error.message));
            try {
                assert.match(run.output, /attach mode: spec .*; no network is managed/);
                assert.doesNotMatch(run.output, /runtime dir:/);
                assert.ok(run.url, run.output);
                await page.goto(run.url);
                const served = await page.evaluate(async () => (await fetch('/jam-demo/spec.json')).text());
                assert.equal(served, await fs.readFile(file, 'utf8'), 'the spec is served unchanged');
                // Walkthrough step 10's fixture is built from the attached spec.
                const wrong = await page.evaluate(async () => {
                    const response = await fetch('/jam-demo/spec-wrong-authorities.json');
                    return { status: response.status, body: await response.json() };
                });
                assert.equal(wrong.status, 200);
                assert.deepEqual(wrong.body, corruptGenesisAuthorities(JSON.parse(served)).spec);
                await page.waitForFunction(() => window.jamDemo.live().harness.status?.attach === true);
                assert.equal(await page.locator('#dev-bootnode').count(), 0, 'the dev-bootnode checkbox is gone');
                const started = Date.now();
                await page.locator('#start').click();
                const sources = new Map();
                const timings = {};
                while (Date.now() - started < 120000) {
                    const state = await page.evaluate(() => window.jamDemo.live());
                    for (const peer of state.peers) if (peer.state === 'connected' && !sources.has(peer.source))
                        sources.set(peer.source, peer.address);
                    if (timings.block === undefined && state.blockCount > 0) timings.block = Date.now() - started;
                    if (timings.finalized === undefined && state.finalityCount > 0) timings.finalized = Date.now() - started;
                    if (timings.block !== undefined && timings.finalized !== undefined &&
                        expected.every(source => sources.has(source))) break;
                    await delay(200);
                }
                const state = await page.evaluate(() => window.jamDemo.live());
                console.log(JSON.stringify({ variant, timings, sources: [...sources], warp: state.warpStatus,
                    blocks: state.blockCount, finality: state.finalityCount }));
                assert.ok(state.blockCount > 0 && state.finalityCount > 0, `${variant}: no block or no finality`);
                const clientEvents = await page.evaluate(() => window.jamDemo.clientEvents());
                assert.equal(clientEvents.unparsed, 0, `${variant}: ${JSON.stringify(clientEvents.unparsedSamples)}`);
                assert.deepEqual([...sources.keys()].filter(source => source !== 'discovered').sort(), [...expected].sort(),
                    `${variant}: peer sources ${JSON.stringify([...sources])}`);
                // The RPC oracle works without a managed network.
                const status = state.harness.status;
                assert.equal(status.attach, true);
                assert.equal(status.specPath, file);
                assert.ok(status.nodeBestBlock?.hash, JSON.stringify(status));
                assert.match(await page.locator('#live-node-best').innerText(), /external network \(attach mode\)/);
                // Node actions answer an error that stays next to the buttons.
                await page.locator('#kill-node0').click();
                await page.waitForFunction(() => document.getElementById('network-status').textContent
                    .includes('not managed by this harness in attach mode'));
                await delay(2500); // One status poll later, the reason is still shown.
                assert.match(await page.locator('#network-status').innerText(), /kill-node0 FAILED: .*not managed by this harness in attach mode/);
                assert.ok((await nodeRpc('bestBlock')).slot > 0, 'the network is untouched');
                await page.locator('#stop').click();
                await page.waitForFunction(() => document.getElementById('status').textContent === 'Stopped');
                await reportClientEvents(page, 'attach, ' + variant);
                assert.deepEqual(errors, []);
            } finally {
                await page.close();
                run.harness.kill('SIGINT');
                const result = await run.exited;
                if (result.code !== 130) console.log(run.output);
                assert.equal(result.code, 130, 'harness must finish its SIGINT cleanup');
                assert.match(run.output, /the network was not ours and keeps running/);
            }
            // Ctrl-C stopped only the server.
            assert.ok((await nodeRpc('bestBlock')).slot > 0, 'the network outlives the attached harness');
        }
    } finally {
        await browser?.close();
        await fs.rm(runtimeDir, { recursive: true, force: true });
    }
});
