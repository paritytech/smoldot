// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Entry point of `npm run test:jam:discovery`: live peer discovery from the
// active validator set (D3, peer discovery), on a GRANDPA network.
//
// Runs the demo harness (`demo/jam-harness.mjs`, FinalityMode::Grandpa) and
// drives the demo page in Chromium, so the page's peer list, the harness
// `status` and the kill/start buttons are exercised exactly as a human uses
// them in `demo/jam.md`:
//
//   1. a fresh client whose only bootnode is node0 starts, follows the chain,
//      sees verified finality and reads the active set C(8);
//   2. at the tip, node0 is killed; the client must reconnect to other
//      validators, keep receiving verified headers and finalized events, and
//      the harness `status` must list two connected peers, neither node0. Since
//      D18 (zombienet demo) a slot may hold a validator from the spec's genesis
//      C(8) (`genesis`) or from a live read (`discovered`); what is proven is
//      that the client continues through validators that are not the dead
//      bootnode, so the check is on the held peers' addresses;
//   3. node0 is started again and must eventually be used again.
//
// Discovery waits for finality, so a Dummy network cannot exercise it. Writes
// discovery-report.json with the timings into the runtime directory.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import url from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';
import { BASE_PORT } from './network.mjs';

const PACKAGE_DIR = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), '..', '..');
const NODE0_ADDRESS = `127.0.0.1:${BASE_PORT}`;
/** Non-bootnode candidates: the spec's genesis C(8), or a verified live read. */
const VALIDATOR_SOURCES = ['genesis', 'discovered'];
const log = (message) => console.log(`[jam-discovery] ${message}`);
/** Optional network age before Start, so the client warps before it discovers. */
const AGE_SECONDS = Number(process.env.JAM_DISCOVERY_AGE_SECONDS ?? 0);

const runtimeDir = process.env.JAM_RUNTIME_DIR
    ? path.resolve(process.env.JAM_RUNTIME_DIR)
    : await fs.mkdtemp(path.join(os.tmpdir(), 'jam-discovery-'));
await fs.mkdir(runtimeDir, { recursive: true });
const report = { startedAt: new Date().toISOString(), runtimeDir, timings: {}, refreshes: [], phases: [] };

let output = '';
const harness = spawn(process.execPath, ['demo/jam-harness.mjs'], {
    cwd: PACKAGE_DIR,
    env: { ...process.env, JAM_RUNTIME_DIR: path.join(runtimeDir, 'harness') },
    stdio: ['ignore', 'pipe', 'pipe'],
});
harness.stdout.on('data', (chunk) => { output += chunk; });
harness.stderr.on('data', (chunk) => { output += chunk; });
const exited = new Promise((resolve) => harness.on('exit', (code, signal) => resolve({ code, signal })));
for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
    process.once(signal, () => {
        harness.kill('SIGINT');
        void exited.then(() => process.exit(code));
    });
}

let browser;
let page;
let controlUrl;

async function harnessStatus() {
    const response = await fetch(controlUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ action: 'status' }),
        signal: AbortSignal.timeout(10000),
    });
    const body = await response.json();
    if (!body.ok) throw new Error(`harness status failed: ${body.error}`);
    return body.status;
}

const live = () => page.evaluate(() => window.jamDemo.live());

/** Polls `check` until it returns a truthy value; fails with `what` on timeout. */
async function until(what, check, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    let last;
    for (;;) {
        last = await check();
        if (last) return last;
        if (Date.now() > deadline) throw new Error(`timed out after ${timeoutMs / 1000}s waiting for ${what}`);
        await delay(250);
    }
}

function phase(name, detail) {
    report.phases.push({ name, at: Date.now(), ...detail });
    log(`${name}${detail ? ' ' + JSON.stringify(detail) : ''}`);
}

try {
    const readyDeadline = Date.now() + 180000;
    while (!output.includes('Ctrl-C to stop')) {
        if (harness.exitCode !== null || harness.signalCode !== null || Date.now() > readyDeadline)
            throw new Error('Harness did not start:\n' + output);
        await delay(100);
    }
    const pageUrl = output.match(/http:\/\/127\.0\.0\.1:\d+\/demo\/jam\.html/)?.[0];
    assert.ok(pageUrl, output);
    controlUrl = new URL('/jam-demo/control', pageUrl).href;
    if (AGE_SECONDS > 0) {
        log(`aging the network for ${AGE_SECONDS} s before Start`);
        await delay(AGE_SECONDS * 1000);
    }
    report.ageSeconds = AGE_SECONDS;

    browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
    report.browser = browser.version();
    page = await browser.newPage();
    await page.goto(pageUrl);
    await page.locator('#dev-bootnode').check();
    const t0 = Date.now();
    await page.locator('#start').click();
    phase('started', { browser: report.browser });

    // 1. Fresh client: blocks, verified finality, the active set read, and
    //    both slots connected: node0 as bootnode, one other validator
    //    (`genesis` from the spec, or `discovered` from a live read).
    let firstBlock;
    let firstFinality;
    const ready = await until('blocks, finality, a C(8) read and two connected slots', async () => {
        const state = await live();
        if (firstBlock === undefined && state.blockCount > 0) firstBlock = Date.now();
        if (firstFinality === undefined && state.finalityCount > 0) firstFinality = Date.now();
        const connected = state.peers.filter((peer) => peer.state === 'connected');
        return state.blockCount > 0 && state.finalityCount > 0 && state.refreshes.length > 0 &&
            connected.some((peer) => peer.source === 'bootnode' && peer.address === NODE0_ADDRESS) &&
            connected.some((peer) => VALIDATOR_SOURCES.includes(peer.source) && peer.address !== NODE0_ADDRESS) && state;
    }, 240000);
    const firstRefresh = ready.refreshes[0];
    assert.equal(firstRefresh.validators, 6);
    assert.equal(firstRefresh.discovered, 5, 'node0 is the bootnode; five validators are discovered');
    report.timings.firstBlockMs = firstBlock - t0;
    report.timings.firstFinalityMs = firstFinality - t0;
    report.timings.firstRefreshMs = firstRefresh.at - t0;
    report.timings.secondSlotConnectedMs = Date.now() - t0;
    phase('discovered', { refresh: firstRefresh, peers: ready.peers });

    // At the tip: the client's latest slot matches the node's best slot.
    await until('the client at the node tip', async () => {
        const state = await live();
        const best = state.harness?.status?.nodeBestBlock?.slot;
        return state.decoded?.slot !== undefined && Number.isInteger(best) && best - state.decoded.slot <= 1;
    }, 60000);

    // 2. node0 dies.
    const before = await live();
    const killStarted = Date.now();
    await page.evaluate(() => window.jamDemo.network('kill-node0'));
    const killed = Date.now();
    assert.equal((await harnessStatus()).node0Alive, false, 'node0 must be down');
    report.timings.killMs = killed - killStarted;
    phase('node0-killed', { blocks: before.blockCount, finality: before.finalityCount });

    let firstBlockAfterKill;
    let firstFinalityAfterKill;
    const track = async () => {
        const state = await live();
        if (firstBlockAfterKill === undefined && state.blockCount > before.blockCount) firstBlockAfterKill = Date.now();
        if (firstFinalityAfterKill === undefined && state.finalityCount > before.finalityCount) firstFinalityAfterKill = Date.now();
        return state;
    };
    const switched = await until('two connected validators other than node0 in the harness status', async () => {
        await track();
        const status = await harnessStatus();
        const connected = status.browserPeers.peers.filter((peer) => peer.state === 'connected');
        return connected.length >= 2 && new Set(connected.map((peer) => peer.address)).size === connected.length &&
            connected.every((peer) => VALIDATOR_SOURCES.includes(peer.source) && peer.address !== NODE0_ADDRESS) && status;
    }, 120000);
    report.timings.twoDiscoveredAfterKillMs = Date.now() - killed;
    phase('two-discovered', { peersLine: switched.peersLine });

    const continued = await until('three verified headers and two finalized events after the kill', async () => {
        const state = await track();
        return state.blockCount >= before.blockCount + 3 && state.finalityCount >= before.finalityCount + 2 && state;
    }, 120000);
    report.timings.firstBlockAfterKillMs = firstBlockAfterKill - killed;
    report.timings.firstFinalityAfterKillMs = firstFinalityAfterKill - killed;
    phase('continued', { blocks: continued.blockCount - before.blockCount, finality: continued.finalityCount - before.finalityCount });

    // 3. node0 comes back and is eventually used again.
    const startRequested = Date.now();
    await page.evaluate(() => window.jamDemo.network('start-node0'));
    const started = Date.now();
    report.timings.startNode0Ms = started - startRequested;
    phase('node0-started');
    const back = await until('node0 connected again as bootnode', async () => {
        const status = await harnessStatus();
        if (!status.node0Alive) throw new Error('node0 died after its restart (planning unrelated_bugs.md PJ1); rerun once');
        return status.browserPeers.peers.some((peer) => peer.state === 'connected' && peer.source === 'bootnode' &&
            peer.address === NODE0_ADDRESS) && status;
    }, 420000);
    report.timings.node0UsedAgainMs = Date.now() - started;
    phase('node0-used-again', { peersLine: back.peersLine });

    const settled = await live();
    assert.ok(settled.blockCount > continued.blockCount, 'headers keep arriving');
    report.refreshes = settled.refreshes.map((entry) => ({ ...entry, at: entry.at - t0 }));
    report.blocks = settled.blockCount;
    report.finalized = settled.finalityCount;
    report.refollows = settled.refollows;
    report.passed = true;
    console.log(JSON.stringify({ timings: report.timings, refreshes: report.refreshes }, null, 2));
    console.log(`PASS: ${report.blocks} headers, ${report.finalized} finalized events, ` +
        `${report.refreshes.length} C(8) refresh(es); two non-node0 validators after ${report.timings.twoDiscoveredAfterKillMs} ms, ` +
        `node0 used again after ${report.timings.node0UsedAgainMs} ms`);
} catch (error) {
    report.error = String(error && (error.stack || error));
    process.exitCode = 1;
    console.error(report.error);
    if (page) {
        report.snapshot = await page.evaluate(() => ({ live: window.jamDemo.live(), logs: window.jamDemo.snapshot().logs }))
            .catch(() => undefined);
    }
} finally {
    await browser?.close();
    harness.kill('SIGINT');
    const result = await exited;
    report.harnessExit = result;
    report.harnessOutput = output.split('\n').slice(-200).join('\n');
    if (output.includes('Ctrl-C to stop') &&
        (result.code !== 130 || !output.includes('teardown complete; no PolkaJam process left behind'))) {
        report.passed = false;
        report.error ??= 'harness teardown left processes behind or did not finish its SIGINT cleanup';
        process.exitCode = 1;
        console.error(report.error);
    }
    report.finishedAt = new Date().toISOString();
    await fs.writeFile(path.join(runtimeDir, 'discovery-report.json'), JSON.stringify(report, null, 2));
    console.log('Report:', path.join(runtimeDir, 'discovery-report.json'));
    console.log(report.passed ? 'RESULT: PASS' : 'RESULT: FAIL');
}
