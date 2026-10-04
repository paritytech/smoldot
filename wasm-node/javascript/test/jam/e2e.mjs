// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Playwright orchestration and assertions for the JAM browser end-to-end test.
//
// Phases:
//   1. positive  - follow the live network: initialized anchor, >= 5 newBlock
//                  within 5 slots, parent links, bestBlockChanged, no finalized
//                  event, and chainHead_v1_header hashing to the reported hash;
//   2. restart   - node0 is killed and restarted against the same data
//                  directory; a new block must link to a pre-restart hash;
//   3. unfollow  - chainHead_v1_unfollow resolves and the event stream stops;
//   4. negative  - a second client whose spec carries a corrupted genesis
//                  authority set gets the wrong anchor, is refused by the
//                  network, and never sees a newBlock.
//
// The page and the smoldot bundle are served from disk through `page.route`;
// no HTTP server is involved.

import { chromium } from 'playwright';
import blakejs from 'blakejs';
import fs from 'node:fs/promises';
import path from 'node:path';
import url from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { SLOT_SECONDS } from './network.mjs';

const { blake2bHex } = blakejs;

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const PACKAGE_DIR = path.resolve(__dirname, '..', '..');
const DIST_DIR = path.join(PACKAGE_DIR, 'dist');
const PAGE_URL = 'http://localhost/';

const MAX_REPORT_EVENTS = 400;
const MAX_REPORT_LOGS = 500;

function hashOfHeaderHex(headerHex) {
    const bytes = Buffer.from(headerHex.startsWith('0x') ? headerHex.slice(2) : headerHex, 'hex');
    return '0x' + blake2bHex(bytes, undefined, 32);
}

async function waitFor(check, timeoutMs, intervalMs = 250) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const value = await check();
        if (value) return value;
        if (Date.now() >= deadline) return undefined;
        await delay(intervalMs);
    }
}

// Serialized into the page: each reconnect gets its own identity, even at the
// same URL. A request records how many advertisements preceded its transmission.
function installJamWireCapture() {
    const wire = window.__jamWire = { connections: [], requests: [] };
    const Native = window.WebTransport;
    if (!Native) return;
    window.WebTransport = new Proxy(Native, { construct(target, args) {
        const transport = new target(...args);
        const connection = { id: wire.connections.length, url: String(args[0]), initialFinal: null, finals: [] };
        wire.connections.push(connection);
        const create = transport.createBidirectionalStream.bind(transport);
        transport.createBidirectionalStream = async (...args) => {
            const stream = await create(...args);
            const bytes = [];
            let incoming = [], messages = 0;
            const getReader = stream.readable.getReader.bind(stream.readable);
            stream.readable.getReader = () => {
                const reader = getReader();
                const read = reader.read.bind(reader);
                reader.read = async () => {
                    const result = await read();
                    if (bytes[0] === 0 && result.value) {
                        for (const byte of result.value) incoming.push(byte);
                        while (incoming.length >= 4) {
                            const length = new DataView(Uint8Array.from(incoming.slice(0, 4)).buffer).getUint32(0, true);
                            if (length > 1024 * 1024) throw new Error('UP0 capture exceeds frame budget');
                            if (incoming.length < length + 4) break;
                            const payload = incoming.splice(0, length + 4).slice(4);
                            const initial = messages++ === 0;
                            const final = initial ? payload.slice(0, 36) : payload.slice(-36);
                            if (final.length !== 36) throw new Error('Truncated UP0 finalized advertisement');
                            const advertised = {
                                t: Date.now(),
                                hash: final.slice(0, 32).map(b => b.toString(16).padStart(2, '0')).join(''),
                                slot: new DataView(Uint8Array.from(final.slice(32)).buffer).getUint32(0, true),
                            };
                            if (initial) connection.initialFinal = advertised;
                            connection.finals.push(advertised);
                        }
                    }
                    return result;
                };
                return reader;
            };
            const getWriter = stream.writable.getWriter.bind(stream.writable);
            stream.writable.getWriter = () => {
                const writer = getWriter();
                const write = writer.write.bind(writer);
                const close = writer.close.bind(writer);
                writer.write = chunk => { if (bytes.length < 42) bytes.push(...new Uint8Array(chunk).slice(0, 42 - bytes.length)); return write(chunk); };
                writer.close = () => {
                    wire.requests.push({ connection: connection.id, t: Date.now(), bytes, finalsSeen: connection.finals.length });
                    return close();
                };
                return writer;
            };
            return stream;
        };
        return transport;
    }});
}

export async function runE2E({ network, specPath, wrongSpecPath, report, log }) {
    const spec = JSON.parse(await fs.readFile(specPath, 'utf8'));
    const wrongSpec = JSON.parse(await fs.readFile(wrongSpecPath, 'utf8'));
    const genesisHash = hashOfHeaderHex(spec.genesis_header);
    const wrongGenesisHash = hashOfHeaderHex(wrongSpec.genesis_header);

    const assertions = [];
    const check = (phase, name, passed, detail) => {
        const entry = { phase, name, passed: !!passed, detail: detail === undefined ? null : String(detail) };
        assertions.push(entry);
        console.log(`${entry.passed ? 'PASS' : 'FAIL'}: [${phase}] ${name}${entry.detail ? ` - ${entry.detail}` : ''}`);
        return entry.passed;
    };

    const launchArgs = ['--disable-features=LocalNetworkAccessChecks'];
    if (typeof process.getuid === 'function' && process.getuid() === 0) launchArgs.push('--no-sandbox');

    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH, args: launchArgs });
    const browserVersion = browser.version();
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.addInitScript(installJamWireCapture);
    page.on('pageerror', (error) => console.error(`[browser:pageerror] ${error.message}`));
    page.on('console', (message) => {
        if (message.type() === 'error') console.error(`[browser:error] ${message.text()}`);
    });

    const mounts = [
        { prefix: '/dist/', dir: DIST_DIR },
        { prefix: '/jam/', dir: __dirname },
    ];
    await page.route('**/*', async (route) => {
        const { pathname } = new URL(route.request().url());
        if (pathname === '/' || pathname === '/index.html') {
            return route.fulfill({ path: path.join(__dirname, 'page.html') });
        }
        const mount = mounts.find((candidate) => pathname.startsWith(candidate.prefix));
        if (!mount) return route.fulfill({ status: 404, body: 'not found' });
        const root = path.resolve(mount.dir);
        const file = path.resolve(root, pathname.slice(mount.prefix.length));
        if (file !== root && !file.startsWith(root + path.sep)) {
            return route.fulfill({ status: 403, body: 'forbidden' });
        }
        try {
            await route.fulfill({ path: file });
        } catch {
            await route.fulfill({ status: 404, body: 'not found' });
        }
    });

    const jam = {
        startClient: (name, options) => page.evaluate(
            ({ name, options }) => window.__jam.startClient(name, options), { name, options }),
        addChain: (client, chain, chainSpec) => page.evaluate(
            ({ client, chain, chainSpec }) => window.__jam.addChain(client, chain, chainSpec), { client, chain, chainSpec }),
        rpc: (client, chain, method, params) => page.evaluate(
            ({ client, chain, method, params }) => window.__jam.rpc(client, chain, method, params), { client, chain, method, params }),
        events: (client, chain, since) => page.evaluate(
            ({ client, chain, since }) => window.__jam.events(client, chain, since), { client, chain, since }),
        logs: (client, since) => page.evaluate(
            ({ client, since }) => window.__jam.logs(client, since), { client, since }),
        terminateClient: (name) => page.evaluate((name) => window.__jam.terminateClient(name), name),
    };

    const phases = [];
    const phase = async (name, body) => {
        const started = Date.now();
        log(`phase ${name}: start`);
        const before = assertions.length;
        try {
            await body();
        } catch (error) {
            check(name, `${name} phase completed without an unexpected error`, false, String(error && (error.stack || error.message || error)));
        }
        const entry = {
            name,
            durationMs: Date.now() - started,
            assertions: assertions.slice(before),
        };
        entry.passed = entry.assertions.length > 0 && entry.assertions.every((assertion) => assertion.passed);
        phases.push(entry);
        log(`phase ${name}: ${entry.passed ? 'done' : 'FAILED'} in ${entry.durationMs}ms`);
    };

    let mainEvents = [];
    let mainLogs = [];
    let negativeEvents = [];
    let negativeLogs = [];

    try {
        await page.goto(PAGE_URL);
        await page.waitForFunction(() => window.__ready === true, { timeout: 30_000 });

        const supportsWebTransport = await page.evaluate(() => window.__jam.webTransportSupported());
        if (!supportsWebTransport) {
            check('positive', 'WebTransport is available in the page', false, 'the browser does not expose WebTransport');
            throw new Error('WebTransport is unavailable; the negative path cannot be faked and the run is aborted');
        }
        check('positive', 'WebTransport is available in the page', true);
        check('positive', 'spec genesis hash is derived from the generated spec', genesisHash !== wrongGenesisHash,
            `${genesisHash} vs corrupted ${wrongGenesisHash}`);

        await jam.startClient('main', { maxLogLevel: 4, cpuRateLimit: 1 });
        await jam.addChain('main', 'main', JSON.stringify(spec));

        let sub;
        let initialized;
        let newBlocks = [];
        let allEvents = [];

        await phase('positive', async () => {
            sub = await jam.rpc('main', 'main', 'chainHead_v1_follow', [false]);
            check('positive', 'chainHead_v1_follow returns a subscription id', typeof sub === 'string' && sub.length > 0, sub);

            initialized = await waitFor(async () => {
                const { entries } = await jam.events('main', 'main', 0);
                return entries.find((entry) => entry.event === 'initialized');
            }, 30_000);
            check('positive', 'initialized event received', !!initialized);
            check('positive', 'initialized anchor equals the spec genesis hash',
                initialized && initialized.finalizedBlockHashes && initialized.finalizedBlockHashes[0] === genesisHash,
                initialized && initialized.finalizedBlockHashes && initialized.finalizedBlockHashes[0]);

            await waitFor(async () => {
                const { entries } = await jam.events('main', 'main', 0);
                newBlocks = entries.filter((entry) => entry.event === 'newBlock');
                return newBlocks.length >= 5;
            }, 60_000);
            allEvents = (await jam.events('main', 'main', 0)).entries;
            check('positive', 'at least 5 newBlock events received', newBlocks.length >= 5, `received ${newBlocks.length}`);
            if (newBlocks.length >= 5) {
                const spanMs = newBlocks[4].t - newBlocks[0].t;
                check('positive', `5th newBlock within 5 slots (${5 * SLOT_SECONDS}s) of the first`,
                    spanMs <= 5 * SLOT_SECONDS * 1000, `${spanMs}ms`);
            }

            const known = new Set(initialized ? initialized.finalizedBlockHashes : []);
            let parentFailure = null;
            for (const block of newBlocks) {
                if (!known.has(block.parentBlockHash)) {
                    parentFailure = `${block.blockHash} has unreported parent ${block.parentBlockHash}`;
                    break;
                }
                known.add(block.blockHash);
            }
            check('positive', 'every newBlock parent is a previously reported hash or the anchor',
                !parentFailure, parentFailure || `${newBlocks.length} blocks linked`);

            const firstNewBlock = newBlocks[0];
            const bestAfterBlock = firstNewBlock
                && allEvents.find((entry) => entry.event === 'bestBlockChanged' && entry.t >= firstNewBlock.t);
            check('positive', 'bestBlockChanged received after the first newBlock', !!bestAfterBlock,
                bestAfterBlock ? `${bestAfterBlock.bestBlockHash}` : 'none');

            const target = (newBlocks[newBlocks.length - 1] || {}).blockHash || genesisHash;
            const headerHex = await jam.rpc('main', 'main', 'chainHead_v1_header', [sub, target]);
            check('positive', 'chainHead_v1_header returns hexadecimal bytes',
                typeof headerHex === 'string' && /^0x(?:[0-9a-fA-F]{2})+$/.test(headerHex),
                typeof headerHex === 'string' ? `${headerHex.length} chars` : String(headerHex));
            check('positive', 'blake2b-256 of the header bytes equals the requested hash',
                typeof headerHex === 'string' && hashOfHeaderHex(headerHex) === target,
                typeof headerHex === 'string' ? `${hashOfHeaderHex(headerHex)} vs ${target}` : 'no header');
        });

        await phase('restart', async () => {
            await network.killNode0();
            // Only pre-restart *block* hashes are accepted as catch-up parents.
            // The anchor is excluded so that a re-sync from genesis cannot make
            // this pass vacuously; the positive phase guarantees >= 5 blocks.
            const eventsBefore = (await jam.events('main', 'main', 0)).entries;
            const eventsBeforeRestart = eventsBefore.length;
            const preRestartHashes = new Set();
            const preRestartAnchors = new Set();
            for (const entry of eventsBefore) {
                if (entry.event === 'initialized') entry.finalizedBlockHashes.forEach((hash) => preRestartAnchors.add(hash));
                if (entry.event === 'newBlock') preRestartHashes.add(entry.blockHash);
            }
            check('restart', 'pre-restart block hashes are available as catch-up parents',
                preRestartHashes.size >= 5, `${preRestartHashes.size} block hashes`);
            const restartStarted = Date.now();
            await network.startNode0();

            const firstAfterRestart = await waitFor(async () => {
                const { entries } = await jam.events('main', 'main', eventsBeforeRestart);
                return entries.find((entry) => entry.event === 'newBlock');
            }, 60_000);
            check('restart', 'a newBlock arrives within 60s of the node0 restart',
                !!firstAfterRestart, firstAfterRestart ? `after ${firstAfterRestart.t - restartStarted}ms` : 'timeout');
            const parent = firstAfterRestart && firstAfterRestart.parentBlockHash;
            check('restart', 'the newBlock parent links to a pre-restart reported block (not just the anchor)',
                !!parent && preRestartHashes.has(parent),
                parent
                    ? `${parent} (pre-restart block: ${preRestartHashes.has(parent)}, anchor: ${preRestartAnchors.has(parent)})`
                    : 'no post-restart newBlock');

            const bestAfterRestart = await waitFor(async () => {
                const { entries } = await jam.events('main', 'main', eventsBeforeRestart);
                return entries.find((entry) => entry.event === 'bestBlockChanged'
                    && firstAfterRestart && entry.t >= firstAfterRestart.t);
            }, 30_000);
            check('restart', 'bestBlockChanged follows the post-restart newBlock', !!bestAfterRestart,
                bestAfterRestart ? bestAfterRestart.bestBlockHash : 'none');
        });

        await phase('unfollow', async () => {
            const eventsBeforeUnfollow = (await jam.events('main', 'main', 0)).total;
            const unfollowResult = await jam.rpc('main', 'main', 'chainHead_v1_unfollow', [sub]);
            check('unfollow', 'chainHead_v1_unfollow resolves', unfollowResult === null || unfollowResult === undefined,
                JSON.stringify(unfollowResult));
            await delay(2500);
            const eventsAfterUnfollow = (await jam.events('main', 'main', 0)).total;
            check('unfollow', 'no follow events arrive in the 2s after unfollow',
                eventsAfterUnfollow === eventsBeforeUnfollow, `${eventsBeforeUnfollow} -> ${eventsAfterUnfollow}`);
        });

        // What this phase does and does not establish. The fixture alters the
        // genesis authority set (`corruptGenesisAuthorities` in network.mjs),
        // so set 0 differs from the network's and a warp fragment cannot be
        // authenticated; the genesis hash differs as a side effect, which is
        // what the Dummy network detects when CE 128 answers an unknown hash
        // with NoData. A spec that differed only in its genesis hash would NOT
        // be rejected after a successful warp: GRANDPA precommits sign
        // (round, set_id, vote) and nothing chain-specific, and the headers
        // below the first set change are never fetched. Real chain identity
        // belongs in the connection and in the vote payload: planning
        // followups.md U7 (chain identity over WebTransport) and U13
        // (chain-bound GRANDPA votes).
        await phase('negative', async () => {
            await jam.startClient('negative', { maxLogLevel: 4, cpuRateLimit: 1 });
            await jam.addChain('negative', 'wrong', JSON.stringify(wrongSpec));
            await jam.rpc('negative', 'wrong', 'chainHead_v1_follow', [false]);

            const negativeInitialized = await waitFor(async () => {
                const { entries } = await jam.events('negative', 'wrong', 0);
                return entries.find((entry) => entry.event === 'initialized');
            }, 30_000);
            check('negative', 'the corrupted spec still loads and anchors at its own genesis hash',
                negativeInitialized && negativeInitialized.finalizedBlockHashes
                && negativeInitialized.finalizedBlockHashes[0] === wrongGenesisHash,
                negativeInitialized && negativeInitialized.finalizedBlockHashes
                && negativeInitialized.finalizedBlockHashes[0]);

            const drop = await waitFor(async () => {
                const { entries } = await jam.logs('negative', 0);
                const rejected = entries.find((entry) => entry.message.startsWith('jam-warp-rejected'));
                if (rejected) return { entries, signature: `jam-warp-rejected: ${rejected.message}` };
                const connectIndex = entries.findIndex((entry) => entry.message === 'jam-connect');
                const reconnectIndex = entries.findIndex((entry, index) => index > connectIndex && entry.message === 'jam-reconnect');
                if (connectIndex >= 0 && reconnectIndex > connectIndex)
                    return { entries, signature: `NoData reconnect: ${entries[connectIndex].t} -> ${entries[reconnectIndex].t}` };
                return undefined;
            }, 90_000);
            check('negative', 'corrupted authority set is rejected within 90s', !!drop,
                drop ? drop.signature : 'neither jam-warp-rejected nor a jam-connect/jam-reconnect pair observed');
        });

        await phase('final', async () => {
            const wire = await page.evaluate(() => window.__jamWire);
            const logs = (await jam.logs('main', 0)).entries;
            check('positive', 'Dummy CE153 terminates with typed NoData',
                wire.requests.some(r => r.bytes[0] === 153)
                && logs.some(e => e.message.startsWith('jam-warp-fragmentless;') && e.message.includes('reason=NoData')));
            check('positive', 'Dummy makes zero CE129 requests',
                wire.requests.every(r => r.bytes[0] !== 129));
            // D3 (peer discovery) reads the active set only after a verified
            // finality advance, which a Dummy network never produces. Since
            // D18 (zombienet demo) the pool starts with the spec's bootnodes
            // and its genesis C(8) validators, so slots may hold either; a
            // `discovered` peer, a CE 129 discovery read or a pool merge would
            // mean a live read happened. `npm run test:jam:discovery` covers GRANDPA.
            const assigned = logs.filter(e => e.message.startsWith('jam-slot-assigned;'));
            const sources = [...new Set(assigned.map(e => /source=([a-z]+)/.exec(e.message)?.[1]))];
            check('positive', 'Dummy reads no live C(8): every slot assignment comes from the spec (bootnode or genesis), none from a live discovery read',
                assigned.length > 0 && sources.every(source => source === 'bootnode' || source === 'genesis')
                && !logs.some(e => /^jam-(discovery-read-started|pool-changed)/.test(e.message)),
                `${assigned.length} assignment(s), sources ${sources.join('+')}`);
            report.wire = wire;
            const { entries: mainSessionEvents } = await jam.events('main', 'main', 0);
            check('positive', 'no finalized event after initialized for the whole session',
                !mainSessionEvents.some((entry) => entry.event === 'finalized'),
                `${mainSessionEvents.length} events`);

            const { entries: negativeSessionEvents } = await jam.events('negative', 'wrong', 0);
            check('negative', 'no newBlock is ever emitted under the corrupted authority set',
                !negativeSessionEvents.some((entry) => entry.event === 'newBlock'),
                `${negativeSessionEvents.length} events`);
        });

        mainEvents = (await jam.events('main', 'main', 0)).entries;
        mainLogs = (await jam.logs('main', 0)).entries;
        negativeEvents = (await jam.events('negative', 'wrong', 0)).entries;
        negativeLogs = (await jam.logs('negative', 0)).entries;
    } finally {
        await jam.terminateClient('negative').catch(() => {});
        await jam.terminateClient('main').catch(() => {});
        await browser.close().catch(() => {});
    }

    report.assertions = assertions;
    report.phases = phases;
    report.genesisHash = genesisHash;
    report.wrongGenesisHash = wrongGenesisHash;
    report.browser = { version: browserVersion };
    report.events = {
        positive: mainEvents.slice(-MAX_REPORT_EVENTS),
        negative: negativeEvents.slice(-MAX_REPORT_EVENTS),
    };
    report.logs = {
        positive: mainLogs.slice(-MAX_REPORT_LOGS),
        negative: negativeLogs.slice(-MAX_REPORT_LOGS),
    };

    const failed = assertions.filter((assertion) => !assertion.passed);
    log(`assertions: ${assertions.length - failed.length}/${assertions.length} passed`);
    return failed.length === 0;
}
/** Manual aged-network acceptance, independent of the short CI gate. */
export async function runAged({ network, specPath, report, log = console.log, signal }) {
    const spec = JSON.parse(await fs.readFile(specPath, 'utf8'));
    const genesis = hashOfHeaderHex(spec.genesis_header).slice(2);
    const hashHex = hash => Buffer.from(hash, 'base64').toString('hex');
    const minimum = Number(process.env.JAM_AGED_BLOCKS ?? 201);
    if (!Number.isSafeInteger(minimum) || minimum < 201 || minimum > 100000) throw new Error('JAM_AGED_BLOCKS must be at least 201 for D7 acceptance');
    const ageStarted = Date.now();
    let count, tip, ageSeconds;
    // Count actual ancestors: the first live slot can be millions past genesis.
    for (;;) {
        signal?.throwIfAborted();
        tip = await network.rpc('bestBlock');
        let hash = tip.header_hash;
        count = 0;
        let earliestSlot = tip.slot;
        while (hashHex(hash) !== genesis) {
            if (++count > 100000) throw new Error('Aged ancestry exceeds measurement budget');
            const parent = await network.rpc('parent', [hash]);
            if (hashHex(parent.header_hash) !== genesis) earliestSlot = parent.slot;
            hash = parent.header_hash;
        }
        ageSeconds = (tip.slot - earliestSlot) * SLOT_SECONDS;
        if (count >= minimum && ageSeconds >= 1200) break;
        if (Date.now() - ageStarted > minimum * SLOT_SECONDS * 2000 + 120000) throw new Error('Network did not age in time');
        log(`aging: ${count}/${minimum} blocks`);
        await delay(30000, undefined, { signal });
    }
    const boundMs = Number(process.env.JAM_AGED_BOUND_MS ?? 180000);
    if (!Number.isSafeInteger(boundMs) || boundMs < 1) throw new Error('Invalid JAM_AGED_BOUND_MS');
    const launchArgs = ['--disable-features=LocalNetworkAccessChecks'];
    if (typeof process.getuid === 'function' && process.getuid() === 0) launchArgs.push('--no-sandbox');
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH, args: launchArgs });
    let page;
    try {
        page = await browser.newPage();
        await page.addInitScript(installJamWireCapture);
        await page.route('http://localhost/**', async route => {
            const pathname = new URL(route.request().url()).pathname;
            const relative = pathname === '/' ? 'test/jam/page.html' : pathname.startsWith('/jam/') ? 'test' + pathname : pathname.slice(1);
            await route.fulfill({ path: path.join(PACKAGE_DIR, relative) });
        });
        await page.goto(PAGE_URL);
        await page.waitForFunction(() => window.__ready);
        const finalizedBeforeConnect = await network.rpc('finalizedBlock');
        const started = Date.now();
        await page.evaluate(async spec => {
            window.__jam.startClient('aged', { maxLogLevel: 4, cpuRateLimit: 1 });
            await window.__jam.addChain('aged', 'jam', spec);
            window.__agedSub = await window.__jam.rpc('aged', 'jam', 'chainHead_v1_follow', [false]);
        }, JSON.stringify(spec));
        let cursor = 0, imported = 0, firstMs, firstAt, best, finalized = 0, stops = 0, root;
        const reached = await waitFor(async () => {
            signal?.throwIfAborted();
            const batch = await page.evaluate(async since => {
                const batch = window.__jam.events('aged', 'jam', since);
                const hashes = batch.entries.filter(e => e.event === 'newBlock').map(e => e.blockHash);
                if (batch.entries.some(e => e.event === 'stop')) {
                    window.__agedSub = await window.__jam.rpc('aged', 'jam', 'chainHead_v1_follow', [false]);
                } else if (hashes.length) await window.__jam.rpc('aged', 'jam', 'chainHead_v1_unpin', [window.__agedSub, hashes]);
                return batch;
            }, cursor);
            cursor = batch.total;
            for (const event of batch.entries) {
                if (event.event === 'stop') { if (++stops > 1) throw new Error('Repeated stop after warp'); }
                if (event.event === 'initialized') root = event.finalizedBlockHashes[0];
                if (event.event === 'newBlock') { imported++; firstAt ??= event.t; firstMs ??= event.t - started; }
                if (event.event === 'bestBlockChanged') best = event.bestBlockHash;
                if (event.event === 'finalized') finalized++;
            }
            const live = await network.rpc('bestBlock');
            return best === '0x' + hashHex(live.header_hash);
        }, boundMs, 100);
        if (!reached) throw new Error(`Fresh client failed to reach live tip in ${boundMs}ms`);
        const elapsedMs = Date.now() - started;
        const wire = await page.evaluate(() => window.__jamWire);
        const requestsToTip = wire.requests;
        const ascendingBatches = requestsToTip.filter(r => r.bytes[0] === 128 && r.bytes[37] === 0).length;
        const logs = (await page.evaluate(() => window.__jam.logs('aged'))).entries;
        const applied = logs.find(e => e.message.startsWith('jam-warp-applied'));
        const connect = logs.find(e => e.message === 'jam-connect');
        const setId = Number(applied?.message.match(/set_id[=:]\s*(\d+)/)?.[1]);
        const rootSlot = Number(applied?.message.match(/(?:root_slot|slot)[=:]\s*(\d+)/)?.[1]);
        if (!applied || !Number.isInteger(setId) || setId < 3) throw new Error('Missing jam-warp-applied with set id >= 3');
        if (!connect || firstAt - connect.t > 5000) throw new Error('First newBlock exceeded 5 seconds after connecting');
        if (ascendingBatches > 2) throw new Error(`Warp catch-up used ${ascendingBatches} ascending CE128 batches`);
        const finalizedAfterWarp = await network.rpc('finalizedBlock');
        if (rootSlot > finalizedAfterWarp.slot) throw new Error('RPC has not yet finalized the join root');
        let appliedRoot = finalizedAfterWarp;
        while (appliedRoot.slot > rootSlot) appliedRoot = await network.rpc('parent', [appliedRoot.header_hash]);
        const appliedHash = hashHex(appliedRoot.header_hash);
        if (appliedRoot.slot !== rootSlot || root !== '0x' + appliedHash) throw new Error('Follower did not reinitialize at finalized join head');
        const requestHash = r => Buffer.from(r.bytes.slice(5, 37)).toString('hex');
        const descending = requestsToTip.filter(r => r.bytes[0] === 128 && r.bytes[37] === 1);
        const joinBlocksFetched = descending.length === 1 ? Buffer.from(descending[0].bytes).readUInt32LE(38) : undefined;
        if (descending.length !== 1 || requestHash(descending[0]) !== appliedHash || joinBlocksFetched !== 1) throw new Error('Join must fetch only F with one descending max=1 request at F');
        const selection = descending[0];
        const servingConnection = wire.connections.find(c => c.id === selection.connection);
        // Policy: freeze the latest UP0 final processed at chain_done. It may be
        // newer than this connection's initial final, but cannot come from a
        // different connection or an advertisement received after selection.
        const frozen = logs.find(e => e.message.startsWith('jam-warp-join-selected;'));
        const advertisementRevision = Number(frozen?.message.match(/advertisement[=:]\s*(\d+)/)?.[1]);
        const frozenSlot = Number(frozen?.message.match(/slot[=:]\s*(\d+)/)?.[1]);
        const selectedFinal = servingConnection?.finals[advertisementRevision - 1];
        if (!Number.isSafeInteger(advertisementRevision) || advertisementRevision < 1
            || advertisementRevision > selection.finalsSeen || !servingConnection?.initialFinal
            || !selectedFinal || selectedFinal.slot !== frozenSlot || frozenSlot !== rootSlot
            || selectedFinal.hash !== requestHash(selection)) throw new Error('Frozen join F does not match its exact serving-connection UP0 advertisement');
        const fragmentFinality = /fragment_finality[=:]\s*true/.test(applied.message);
        if (!fragmentFinality && !requestsToTip.some(r => r.connection === selection.connection && r.bytes[0] === 130 && requestHash(r) === appliedHash)) throw new Error('Join head has neither consumed fragment finality nor CE130 on its serving connection');
        // Since D15 (pin move) the read is at F itself, against the posterior root F's justification signs.
        const stateRequests = requestsToTip.filter(r => r.bytes[0] === 129);
        if (!stateRequests.length || stateRequests.some(r => r.connection !== selection.connection || r.t < selection.t || requestHash(r) !== appliedHash)) throw new Error('Join state reads were not bound to frozen F and its serving connection');
        const stateResponses = Number(applied.message.match(/state_responses[=:]\s*(\d+)/)?.[1]);
        if (!Number.isInteger(stateResponses) || stateResponses < 1 || stateResponses > 2) throw new Error('Join exceeded two CE129 responses');
        const finalitySeen = await waitFor(async () => {
            const events = (await page.evaluate(() => window.__jam.events('aged', 'jam'))).entries;
            finalized = events.filter(e => e.event === 'finalized').length;
            return finalized > 0;
        }, 30000);
        if (!finalitySeen) throw new Error('No finalized events after warp');
        report.aged = { blocksAtStart: count, ageSeconds, tipSlotAtStart: tip.slot, firstNewBlockMs: firstMs,
            timeToTipMs: elapsedMs, imported, blocksPerSecond: imported * 1000 / elapsedMs,
            finalizedEvents: finalized, boundMs, cpuRateLimit: 1, best, browser: browser.version(),
            setId, rootSlot, root, appliedRootHash: '0x' + hashHex(appliedRoot.header_hash),
            finalizedBeforeConnect, finalizedAfterWarp, servingConnection, selectedFinal, advertisementRevision,
            selectionPolicy: 'latest UP0 final processed at chain_done, frozen for the join',
            fragmentFinality, stateResponses, joinBlocksFetched, stateReadAt: '0x' + appliedHash, stops, ascendingBatches, firstBlockAfterConnectMs: firstAt - connect.t };
        report.logs = (await page.evaluate(() => window.__jam.logs('aged'))).entries;
        log('PASS aged: ' + JSON.stringify(report.aged));
    } finally {
        if (page) report.logs = (await page.evaluate(() => window.__jam?.logs('aged')))?.entries;
        await browser.close();
    }
}

// `node test/jam/e2e.mjs --aged` starts a GRANDPA network and ages it 20 minutes.
// JAM_AGED_ATTACH_DIR + JAM_RPC_PORT reuse an already running network.
if (process.argv[1] && url.pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url && process.argv.includes('--aged')) {
    const { JamNetwork, generateSpecs, resolveBinaries } = await import('./network.mjs');
    const os = await import('node:os');
    const runtimeDir = process.env.JAM_AGED_ATTACH_DIR ?? await fs.mkdtemp(path.join(os.tmpdir(), 'jam-aged-'));
    const { binDir } = await resolveBinaries();
    const network = new JamNetwork({ binDir, runtimeDir, rpcPort: Number(process.env.JAM_RPC_PORT ?? 25800), finalityMode: 'grandpa', log: console.log });
    const report = { startedAt: new Date().toISOString() };
    const abort = new AbortController();
    for (const [name, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
        process.once(name, () => { process.exitCode = code; abort.abort(new Error(name)); });
    }
    try {
        const { specPath } = await generateSpecs({ runtimeDir });
        if (!process.env.JAM_AGED_ATTACH_DIR) await network.start();
        await runAged({ network, specPath, report, signal: abort.signal });
    } catch (error) {
        report.error = String(error.stack ?? error);
        console.error(report.error);
        process.exitCode ??= 1;
    } finally {
        if (!process.env.JAM_AGED_ATTACH_DIR) await network.stop();
        await fs.writeFile(path.join(runtimeDir, process.env.JAM_AGED_REPORT ?? 'aged-report.json'), JSON.stringify(report, null, 2) + '\n');
    }
}
