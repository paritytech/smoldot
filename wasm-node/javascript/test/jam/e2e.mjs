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
//   4. negative  - a second client with a corrupted genesis gets the wrong
//                  anchor, logs jam-connect then jam-reconnect, and never sees
//                  a newBlock.
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

        await phase('negative', async () => {
            await jam.startClient('negative', { maxLogLevel: 4, cpuRateLimit: 1 });
            await jam.addChain('negative', 'wrong', JSON.stringify(wrongSpec));
            await jam.rpc('negative', 'wrong', 'chainHead_v1_follow', [false]);

            const negativeInitialized = await waitFor(async () => {
                const { entries } = await jam.events('negative', 'wrong', 0);
                return entries.find((entry) => entry.event === 'initialized');
            }, 30_000);
            check('negative', 'initialized anchor equals the corrupted genesis hash',
                negativeInitialized && negativeInitialized.finalizedBlockHashes
                && negativeInitialized.finalizedBlockHashes[0] === wrongGenesisHash,
                negativeInitialized && negativeInitialized.finalizedBlockHashes
                && negativeInitialized.finalizedBlockHashes[0]);

            const drop = await waitFor(async () => {
                const { entries } = await jam.logs('negative', 0);
                const connectIndex = entries.findIndex((entry) => entry.message === 'jam-connect');
                const reconnectIndex = entries.findIndex((entry, index) => index > connectIndex && entry.message === 'jam-reconnect');
                return connectIndex >= 0 && reconnectIndex > connectIndex ? { entries, connectIndex, reconnectIndex } : undefined;
            }, 90_000);
            check('negative', 'client logs jam-connect then jam-reconnect within 90s', !!drop,
                drop ? `${drop.entries[drop.connectIndex].t} -> ${drop.entries[drop.reconnectIndex].t}` : 'not observed');
        });

        await phase('final', async () => {
            const { entries: mainSessionEvents } = await jam.events('main', 'main', 0);
            check('positive', 'no finalized event after initialized for the whole session',
                !mainSessionEvents.some((entry) => entry.event === 'finalized'),
                `${mainSessionEvents.length} events`);

            const { entries: negativeSessionEvents } = await jam.events('negative', 'wrong', 0);
            check('negative', 'no newBlock is ever emitted for the corrupted spec',
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