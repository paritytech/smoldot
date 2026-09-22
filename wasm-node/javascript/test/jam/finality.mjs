// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Live GRANDPA acceptance and CE130 capture. C2's Dummy-mode runner is unchanged.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';
import blakejs from 'blakejs';
const { blake2b } = blakejs;
import { JamNetwork, generateSpecs, listProcesses, resolveBinaries, BASE_PORT, POLKAJAM_COMMIT } from './network.mjs';

const packageDir = fileURLToPath(new URL('../../', import.meta.url));
const runtimeDir = process.env.JAM_RUNTIME_DIR ?? await fs.mkdtemp(path.join(os.tmpdir(), 'jam-finality-'));
await fs.mkdir(runtimeDir, { recursive: true });
const basePort = BASE_PORT;
const rpcPort = Number(process.env.JAM_RPC_PORT ?? 24800);
const { binDir } = await resolveBinaries();
console.log(`PolkaJam binaries: ${binDir}`);
const network = new JamNetwork({ binDir, rpcPort, runtimeDir, finalityMode: 'grandpa', log: console.log });
const report = { pinnedCommit: POLKAJAM_COMMIT, runtimeDir, headers: {}, proofs: [], events: [], logs: [] };
let browser, page, fixture;
for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
    process.once(signal, () => {
        void (async () => {
            try { await browser?.close(); }
            finally { await network.stop(); process.exit(code); }
        })();
    });
}
try {
    const { specPath } = await generateSpecs({ runtimeDir });
    await network.start();
    browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH, args: ['--disable-features=LocalNetworkAccessChecks'] });
    page = await browser.newPage();
    await page.addInitScript(() => {
        window.__proofs = [];
        const create = WebTransport.prototype.createBidirectionalStream;
        WebTransport.prototype.createBidirectionalStream = async function (...args) {
            const stream = await create.apply(this, args);
            const request = [];
            const writer = stream.writable.getWriter();
            const writable = new WritableStream({
                write(bytes) { if (request.length < 64) request.push(...bytes); return writer.write(bytes); },
                close() { return writer.close(); }, abort(reason) { return writer.abort(reason); },
            });
            const [readable, capture] = stream.readable.tee();
            void (async () => {
                const reader = capture.getReader();
                const chunks = []; let length = 0;
                try {
                    for (;;) {
                        const { value, done } = await reader.read();
                        if (done) break;
                        length += value.length;
                        if (length > 2 * 1024 * 1024) { void reader.cancel(); return; }
                        chunks.push(value);
                    }
                    if (request[0] !== 130 || window.__proofs.length >= 256) return;
                    const bytes = new Uint8Array(length); let offset = 0;
                    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
                    const hex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
                    window.__proofs.push({ request: hex(request), response: hex(bytes) });
                } catch { /* Reset means no proof; the client handles that separately. */ }
            })();
            return { readable, writable };
        };
    });
    await page.route('http://localhost/**', async route => {
        const pathname = new URL(route.request().url()).pathname;
        const relative = pathname === '/' ? 'test/jam/page.html' : pathname.startsWith('/jam/') ? 'test' + pathname : pathname.slice(1);
        await route.fulfill({ path: path.join(packageDir, relative) });
    });
    await page.goto('http://localhost/');
    await page.waitForFunction(() => window.__ready);
    await page.evaluate(async spec => {
        window.__jam.startClient('finality');
        await window.__jam.addChain('finality', 'jam', spec);
        window.__subscription = await window.__jam.rpc('finality', 'jam', 'chainHead_v1_follow', [false]);
    }, await fs.readFile(specPath, 'utf8'));
    let cursor = 0;
    let retainedPin;
    const collect = async () => {
        const events = await page.evaluate(since => window.__jam.events('finality', 'jam', since), cursor);
        cursor = events.total;
        for (const event of events.entries) {
            report.events.push(event);
            assert.notEqual(event.event, 'stop', 'follow must survive root advancement');
            if (event.event === 'newBlock') {
                report.headers[event.blockHash] = await page.evaluate(hash => window.__jam.rpc('finality', 'jam', 'chainHead_v1_header', [window.__subscription, hash]), event.blockHash);
                assert.ok(report.headers[event.blockHash]);
                if (!retainedPin) retainedPin = event.blockHash;
                else await page.evaluate(hash => window.__jam.rpc('finality', 'jam', 'chainHead_v1_unpin', [window.__subscription, [hash]]), event.blockHash);
            }
        }
        report.logs = (await page.evaluate(() => window.__jam.logs('finality'))).entries;
        report.proofs = await page.evaluate(() => window.__proofs);
    };
    const waitUntil = async (condition, timeout = 210000) => {
        const deadline = Date.now() + timeout;
        while (Date.now() < deadline) {
            await collect();
            if (condition()) return;
            await delay(500);
        }
        throw new Error('Finality acceptance timed out; inspect capture.json and network.log');
    };
    await waitUntil(() => report.logs.some(l => /jam-finalized/.test(l.message) && /set_id=3\b/.test(l.message)));
    const finalized = () => report.events.filter(e => e.event === 'finalized');
    assert.ok(finalized().length >= 3);
    assert.ok(report.proofs.length > 0);
    const before = finalized().at(-1).finalizedBlockHashes.at(-1);
    const pinned = await page.evaluate(hash => window.__jam.rpc('finality', 'jam', 'chainHead_v1_header', [window.__subscription, hash]), retainedPin);
    assert.equal(pinned, report.headers[retainedPin], 'pin survives removal of old tree ancestors');
    console.log('Verified three authority sets; restarting node0 across advancing finality');
    await network.killNode0();
    await delay(12000);
    await network.startNode0();
    await waitUntil(() => finalized().at(-1)?.finalizedBlockHashes.at(-1) !== before, 90000);
    await waitUntil(() => finalized().length >= 20, 90000);
    if (process.env.JAM_FINALITY_FIXTURE) {
        const spec = JSON.parse(await fs.readFile(specPath, 'utf8'));
        // Preserve captured bytes exactly. Only omit genesis state the client never reads.
        spec.genesis_state = Object.fromEntries(Object.entries(spec.genesis_state)
            .filter(([key]) => [4, 6, 8, 11].some(index => key === index.toString(16).padStart(2, '0') + '00'.repeat(30))));
        assert.equal(Object.keys(spec.genesis_state).length, 4);
        const headers = Object.entries(report.headers).sort(([, a], [, b]) =>
            Buffer.from(a.slice(2), 'hex').readUInt32LE(96) - Buffer.from(b.slice(2), 'hex').readUInt32LE(96));
        const known = new Set(['0x' + Buffer.from(blake2b(Buffer.from(spec.genesis_header.replace(/^0x/, ''), 'hex'), undefined, 32)).toString('hex')]);
        for (const [hash, encoded] of headers) {
            const bytes = Buffer.from(encoded.slice(2), 'hex');
            assert.equal('0x' + Buffer.from(blake2b(bytes, undefined, 32)).toString('hex'), hash);
            assert.ok(known.has('0x' + bytes.subarray(0, 32).toString('hex')), 'captured parent must be present');
            known.add(hash);
        }
        const finalizedHashes = new Set(finalized().flatMap(event => event.finalizedBlockHashes));
        const proofs = new Map();
        for (const { request, response } of report.proofs) {
            const frame = Buffer.from(response, 'hex');
            if (frame.length < 4 || frame.readUInt32LE(0) === 0) continue;
            assert.equal(frame.readUInt32LE(0), frame.length - 4, 'one complete CE130 frame');
            const payload = frame.subarray(4);
            assert.ok(payload.length >= 48);
            const hash = '0x' + payload.subarray(12, 44).toString('hex');
            assert.equal(Buffer.from(request, 'hex').subarray(5, 37).toString('hex'), hash.slice(2));
            if (finalizedHashes.has(hash)) proofs.set(hash, payload);
        }
        const justifications = [...proofs.values()].sort((a, b) => a.readUInt32LE(44) - b.readUInt32LE(44));
        assert.ok(justifications.length >= 20, 'retain at least twenty verified live proofs');
        assert.ok(new Set(justifications.map(bytes => bytes.readUInt32LE(8))).size >= 3);
        fixture = {
            polkajam_commit: POLKAJAM_COMMIT,
            description: 'Live FinalityMode::Grandpa capture; three or more authority sets and node0 restart. Headers and CE130 payloads are unmodified network bytes.',
            spec, headers: headers.map(([, encoded]) => encoded),
            justifications: justifications.map(bytes => bytes.toString('hex')),
        };
    }
    report.passed = true;
    console.log(`PASS: ${Object.keys(report.headers).length} headers, ${finalized().length} finalized events, ${report.proofs.length} captured proofs`);
} catch (error) {
    report.error = String(error.stack ?? error);
    process.exitCode = 1;
    console.error(report.error);
    if (page) {
        report.logs = await page.evaluate(() => window.__jam?.logs('finality').entries).catch(() => report.logs);
        report.proofs = await page.evaluate(() => window.__proofs).catch(() => report.proofs);
    }
} finally {
    if (browser) await browser.close();
    await network.stop();
    report.leftovers = await listProcesses(runtimeDir);
    if (report.leftovers.length) { report.passed = false; process.exitCode = 1; }
    if (report.passed && fixture) {
        try {
            await fs.writeFile(process.env.JAM_FINALITY_FIXTURE, JSON.stringify(fixture, null, 2) + '\n');
            console.log('Fixture:', process.env.JAM_FINALITY_FIXTURE);
        } catch (error) {
            report.passed = false; report.error = String(error); process.exitCode = 1;
            console.error(report.error);
        }
    }
    await fs.writeFile(path.join(runtimeDir, 'capture.json'), JSON.stringify(report, null, 2));
    console.log('Capture:', path.join(runtimeDir, 'capture.json'));
}
