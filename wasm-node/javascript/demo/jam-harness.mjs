// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Entry point of `npm run demo:jam`: the one-command local JAM demo.
//
// Starts a local PolkaJam dev network (C2's `test/jam/network.mjs`, unchanged),
// serves `wasm-node/javascript/` over plain HTTP on loopback, exposes the
// checked-in genesis with browser bootnodes and a tiny control endpoint, prints one URL, and
// tears everything down on Ctrl-C.
//
// This is a manual-QA tool for the local dev network only. It is not a server:
// it binds 127.0.0.1, refuses non-loopback peers and foreign Host headers, and
// has no authentication beyond that.
//
// Loopback is a secure context, so WebTransport and `serverCertificateHashes`
// work over plain HTTP. No TLS is configured and no certificate check is
// disabled anywhere in this file.

import http from 'node:http';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import url from 'node:url';
import {
    BASE_PORT,
    DEFAULT_RPC_PORT,
    JamNetwork,
    POLKAJAM_COMMIT,
    formatBootnode,
    generateSpecs,
    listProcesses,
    readTail,
    resolveBinaries,
} from '../test/jam/network.mjs';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const PACKAGE_DIR = path.resolve(__dirname, '..');
const DIST_ENTRY = path.join(PACKAGE_DIR, 'dist', 'mjs', 'index-browser.js');

const log = (message) => console.log(`[jam-demo] ${message}`);

const runtimeDir = process.env.JAM_RUNTIME_DIR
    ? path.resolve(process.env.JAM_RUNTIME_DIR)
    : await fs.mkdtemp(path.join(os.tmpdir(), 'jam-demo-'));
const basePort = BASE_PORT;
const rpcPort = Number(process.env.JAM_RPC_PORT ?? DEFAULT_RPC_PORT);
const httpPort = Number(process.env.JAM_HTTP_PORT ?? 8080);

const CONTENT_TYPES = new Map(Object.entries({
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.mjs': 'text/javascript; charset=utf-8',
    '.cjs': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.map': 'application/json; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.wasm': 'application/wasm',
    '.txt': 'text/plain; charset=utf-8',
    '.md': 'text/plain; charset=utf-8',
    '.ts': 'text/plain; charset=utf-8',
}));

const LOOPBACK = /^(?:127\.\d+\.\d+\.\d+|::1|::ffff:127\.\d+\.\d+\.\d+)$/;
const MAX_CONTROL_BODY = 4096;

let network;
let server;
let specPath;
let wrongSpecPath;
let cleanupPromise;
/** Serialises control actions so two clicks cannot interleave kill/restart. */
let controlChain = Promise.resolve();

/**
 * Idempotent, and deliberately returns the *same* promise every time: npm
 * forwards Ctrl-C to this process as well as sending it itself, so the handler
 * runs twice and the second call must wait for the first teardown instead of
 * exiting on top of it.
 */
function cleanup() {
    if (!cleanupPromise) cleanupPromise = teardown();
    return cleanupPromise;
}

async function teardown() {
    if (server) {
        // Close idle and in-flight sockets first: a browser's keep-alive
        // connection would otherwise hold `close()` open forever.
        const closed = new Promise((resolve) => server.close(() => resolve()));
        server.closeAllConnections?.();
        await closed;
    }
    if (network) {
        try {
            await network.stop();
        } catch (error) {
            log(`teardown error: ${error && (error.stack || error.message || error)}`);
        }
    }
    const leftovers = await listProcesses(runtimeDir).catch(() => []);
    if (leftovers.length > 0) {
        console.error(`[jam-demo] LEFTOVER PROCESSES: ${leftovers.map((entry) => `${entry.pid} ${entry.cmdline}`).join(' | ')}`);
    } else {
        log('teardown complete; no PolkaJam process left behind');
    }
    return leftovers.length;
}

function shutdown(code) {
    void cleanup().then((leftovers) => process.exit(leftovers ? 1 : code));
}

let interrupted = false;
process.on('SIGINT', () => {
    if (!interrupted) {
        interrupted = true;
        console.log('');
        log('Ctrl-C: stopping the network and the server');
    }
    shutdown(130);
});
process.on('SIGTERM', () => shutdown(143));

function sendJson(response, status, body) {
    const text = JSON.stringify(body);
    response.writeHead(status, {
        'content-type': 'application/json; charset=utf-8',
        'content-length': Buffer.byteLength(text),
        'cache-control': 'no-store',
    });
    response.end(text);
}

/** node0 is the only `--dev-validator 0` process of this run. */
async function processes() {
    const entries = await listProcesses(runtimeDir).catch(() => []);
    return entries.map((entry) => ({
        pid: entry.pid,
        node0: entry.cmdline.includes('--dev-validator 0'),
        cmdline: entry.cmdline,
    }));
}

/**
 * PolkaJam's `BlockDesc` reports `header_hash` as base64; smoldot reports block
 * hashes as `0x`-prefixed hex. Convert so the page can compare them directly,
 * and keep the raw value so nothing is silently reinterpreted.
 */
function normalizeBlockDesc(desc) {
    if (!desc || typeof desc !== 'object') return null;
    const slot = Number(desc.slot);
    let hash;
    if (typeof desc.header_hash === 'string') {
        const bytes = Buffer.from(desc.header_hash, 'base64');
        if (bytes.length === 32) hash = '0x' + bytes.toString('hex');
    } else if (typeof desc.hash === 'string') {
        hash = desc.hash;
    }
    return { slot: Number.isFinite(slot) ? slot : undefined, hash, raw: desc };
}

async function status() {
    const alive = await processes();
    // Independent reads: a finality RPC failure must not hide the best head.
    const readBlock = async (method) => {
        try {
            const block = normalizeBlockDesc(await network.rpc(method));
            if (!block?.hash || block.slot === undefined) throw new Error('Invalid block descriptor');
            return { block, error: null };
        } catch (error) {
            return { block: null, error: String(error && (error.message || error)) };
        }
    };
    const [best, finalized] = await Promise.all([readBlock('bestBlock'), readBlock('finalizedBlock')]);
    return {
        pinnedCommit: POLKAJAM_COMMIT,
        basePort,
        rpcPort,
        bootnode: formatBootnode(),
        runtimeDir,
        networkLog: network.networkLog,
        processes: alive,
        node0Alive: alive.some((entry) => entry.node0),
        nodeBestBlock: best.block,
        nodeBestBlockError: best.error,
        nodeFinalizedBlock: finalized.block,
        nodeFinalizedBlockError: finalized.error,
    };
}

async function control(action) {
    switch (action) {
        case 'status':
            return { action, ok: true, status: await status() };
        case 'kill-node0':
            await network.killNode0();
            return { action, ok: true, status: await status() };
        case 'start-node0':
            await network.startNode0();
            return { action, ok: true, status: await status() };
        case 'restart-node0':
            await network.restartNode0();
            return { action, ok: true, status: await status() };
        default:
            throw new Error(`unknown action ${JSON.stringify(action)}`);
    }
}

async function readBody(request) {
    let size = 0;
    const chunks = [];
    for await (const chunk of request) {
        size += chunk.length;
        if (size > MAX_CONTROL_BODY) throw new Error('control request body too large');
        chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString('utf8');
}

async function serveFile(response, file, { noStore = false } = {}) {
    let data;
    try {
        data = await fs.readFile(file);
    } catch {
        response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        response.end('not found');
        return;
    }
    const headers = {
        'content-type': CONTENT_TYPES.get(path.extname(file)) ?? 'application/octet-stream',
        'content-length': data.length,
    };
    // A rebuild or a network restart must never be masked by a cached asset.
    if (noStore) headers['cache-control'] = 'no-store';
    response.writeHead(200, headers);
    response.end(data);
}

function localOnly(request) {
    const remote = request.socket.remoteAddress ?? '';
    if (!LOOPBACK.test(remote)) return false;
    // Defends against DNS rebinding: a page on another origin cannot make the
    // browser send one of these Host headers.
    const host = (request.headers.host ?? '').toLowerCase();
    const hostname = host.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
    return hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '::1';
}

async function handle(request, response) {
    if (!localOnly(request)) {
        response.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
        response.end('this demo server only answers loopback requests');
        return;
    }
    const { pathname } = new URL(request.url, `http://127.0.0.1:${httpPort}`);

    if (pathname === '/jam-demo/control') {
        if (request.method !== 'POST') {
            sendJson(response, 405, { ok: false, error: 'use POST with {"action": ...}' });
            return;
        }
        let action;
        try {
            const body = await readBody(request);
            action = JSON.parse(body || '{}').action;
        } catch (error) {
            sendJson(response, 400, { ok: false, error: String(error && (error.message || error)) });
            return;
        }
        // Chain the action onto the previous one, whatever its outcome.
        const result = controlChain.catch(() => {}).then(() => control(action));
        controlChain = result.catch(() => {});
        try {
            sendJson(response, 200, await result);
        } catch (error) {
            const message = String(error && (error.message || error));
            log(`control ${action} failed: ${message}`);
            sendJson(response, 500, { action, ok: false, error: message, status: await status().catch(() => null) });
        }
        return;
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
        response.writeHead(405, { 'content-type': 'text/plain; charset=utf-8' });
        response.end('method not allowed');
        return;
    }

    // Read from the runtime directory on every request, so the page always gets
    // the identity and ports of the network that is actually running.
    if (pathname === '/jam-demo/spec.json') return serveFile(response, specPath, { noStore: true });
    if (pathname === '/jam-demo/spec-wrong-genesis.json') return serveFile(response, wrongSpecPath, { noStore: true });

    // The browser asks for this on every load; 404s in the console are noise.
    if (pathname === '/favicon.ico') {
        response.writeHead(204);
        response.end();
        return;
    }

    if (pathname === '/' || pathname === '/demo/' || pathname === '/index.html') {
        response.writeHead(302, { location: '/demo/jam.html' });
        response.end();
        return;
    }

    const file = path.resolve(PACKAGE_DIR, `.${pathname}`);
    if (file !== PACKAGE_DIR && !file.startsWith(PACKAGE_DIR + path.sep)) {
        response.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
        response.end('forbidden');
        return;
    }
    return serveFile(response, file, { noStore: true });
}

try {
    await fs.mkdir(runtimeDir, { recursive: true });
    try {
        await fs.access(DIST_ENTRY);
    } catch {
        throw new Error(
            `${DIST_ENTRY} is missing; build the browser bundle first:\n` +
            '  cd wasm-node/javascript && node prepare.mjs --debug && npm run buildModules\n' +
            '(use `npm run build` instead for the slower min-size release bundle)',
        );
    }
    log(`runtime dir: ${runtimeDir}`);

    // The demo never clones or builds anything: `resolveBinaries()` finds the
    // binaries the operator already built, or stops with the build commands.
    const { binDir } = await resolveBinaries();
    log(`PolkaJam binaries: ${binDir}`);

    ({ specPath, wrongSpecPath } = await generateSpecs({ runtimeDir }));

    network = new JamNetwork({ binDir, rpcPort, runtimeDir, log, finalityMode: 'grandpa' });
    await network.start();

    server = http.createServer((request, response) => {
        void handle(request, response).catch((error) => {
            log(`request ${request.method} ${request.url} failed: ${error && (error.message || error)}`);
            if (!response.headersSent) response.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
            response.end('internal error');
        });
    });
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(httpPort, '127.0.0.1', resolve);
    });

    console.log('');
    console.log('====================================================================');
    console.log(`  Open:          http://127.0.0.1:${httpPort}/demo/jam.html`);
    console.log(`  Chain spec:    http://127.0.0.1:${httpPort}/jam-demo/spec.json`);
    console.log(`  Bootnode:      ${formatBootnode()}`);
    console.log(`  Runtime dir:   ${runtimeDir}`);
    console.log(`  Network log:   ${network.networkLog}`);
    console.log(`  PolkaJam:      ${POLKAJAM_COMMIT} (pinned)`);
    console.log('  Ctrl-C to stop the network and this server.');
    console.log('====================================================================');
    console.log('');
} catch (error) {
    console.error(`[jam-demo] startup failed: ${error && (error.stack || error.message || error)}`);
    if (network) console.error(`--- network.log tail ---\n${await readTail(network.networkLog, 40)}`);
    shutdown(1);
}
