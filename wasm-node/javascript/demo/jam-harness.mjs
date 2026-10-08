// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Entry point of `npm run demo:jam`: serves the manual JAM demo for a running
// network.
//
// The harness starts no network. Since D19 (e2e scenarios on zombienet) the
// network always comes from zombienet: `just zombie-jam` (zombie-cli and the
// checked-in TOML) or `just demo-jam-dev` (the `DEV_MODE` route of the
// `e2e-tests` JAM scenarios). The harness serves `wasm-node/javascript/` over
// plain HTTP on loopback, serves the network's spec (`JAM_SPEC_PATH`) unchanged
// at `/jam-demo/spec.json` and the wrong-authority variant of walkthrough step
// 10 next to it, runs the RPC oracle against `JAM_RPC_PORT`, keeps the page's
// peer reports, and answers every node action with an error, because the
// network belongs to whoever started it. Ctrl-C stops only the server.
//
// This is a manual-QA tool for a local dev network only. It is not a server:
// it binds 127.0.0.1, refuses non-loopback peers and foreign Host headers, and
// has no authentication beyond that.
//
// Loopback is a secure context, so WebTransport and `serverCertificateHashes`
// work over plain HTTP. No TLS is configured and no certificate check is
// disabled anywhere in this file.

import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import url from 'node:url';
// The wrong-authorities builder is shared with the end-to-end scenarios.
import { WRONG_SPEC_FILENAME, corruptGenesisAuthorities } from '../../../e2e-tests/shared/jam.js';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const PACKAGE_DIR = path.resolve(__dirname, '..');
const DIST_ENTRY = path.join(PACKAGE_DIR, 'dist', 'mjs', 'index-browser.js');

const log = (message) => console.log(`[jam-demo] ${message}`);

/** The spec of the network this harness attaches to. */
const attachSpecPath = process.env.JAM_SPEC_PATH ? path.resolve(process.env.JAM_SPEC_PATH) : undefined;
const NOT_MANAGED = 'not managed by this harness in attach mode';
/** The RPC port of `wasm-node/javascript/test/jam/zombienet/tiny-grandpa.toml`. */
const DEFAULT_RPC_PORT = 19800;
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

let server;
let specPath;
let cleanupPromise;
/** Serialises control actions so two clicks cannot interleave kill/restart. */
let controlChain = Promise.resolve();
/**
 * What the demo page last reported its client to be connected to (D3, peer
 * discovery). The harness cannot see the browser's WebTransport sessions, so
 * the page mirrors the client's own slot log lines here; `status` returns them.
 */
let browserPeers = { reportedAt: null, peers: [], pool: null };
const MAX_REPORTED_PEERS = 8;

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
    log('teardown complete; attach mode, the network was not ours and keeps running');
    return 0;
}

function shutdown(code) {
    void cleanup().then((leftovers) => process.exit(leftovers ? 1 : code));
}

let interrupted = false;
process.on('SIGINT', () => {
    if (!interrupted) {
        interrupted = true;
        console.log('');
        log('Ctrl-C: stopping the server (attach mode: the network keeps running)');
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

/** The RPC oracle: one JSON-RPC call to the node at `rpcPort`. */
async function rpcCall(method, params = []) {
    const response = await fetch(`http://127.0.0.1:${rpcPort}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal: AbortSignal.timeout(3000),
    });
    const body = await response.json();
    if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
    return body.result;
}

async function status() {
    // Independent reads: a finality RPC failure must not hide the best head.
    const readBlock = async (method) => {
        try {
            const block = normalizeBlockDesc(await rpcCall(method));
            if (!block?.hash || block.slot === undefined) throw new Error('Invalid block descriptor');
            return { block, error: null };
        } catch (error) {
            return { block: null, error: String(error && (error.message || error)) };
        }
    };
    const [best, finalized] = await Promise.all([readBlock('bestBlock'), readBlock('finalizedBlock')]);
    return {
        attach: true,
        specPath: attachSpecPath,
        browserPeers,
        peersLine: describePeers(browserPeers),
        rpcPort,
        processes: [],
        nodeBestBlock: best.block,
        nodeBestBlockError: best.error,
        nodeFinalizedBlock: finalized.block,
        nodeFinalizedBlockError: finalized.error,
    };
}

/** One line naming each connected peer and its source, for humans. */
function describePeers(report) {
    if (report.reportedAt === null) return 'browser peers: no report yet';
    const connected = report.peers.filter((peer) => peer.state === 'connected');
    const pool = report.pool ? `; validator set read ${report.pool.refreshes} time(s), ${report.pool.discovered} discovered` : '';
    return `browser peers: ${connected.length === 0 ? 'none connected'
        : connected.map((peer) => `slot ${peer.slot} ${peer.source} ${peer.address}`).join(', ')}${pool}`;
}

/** Accepts only the small, typed shape `demo/jam.mjs` sends. */
function acceptPeers(body) {
    const text = (value) => typeof value === 'string' && value.length <= 64 && /^[\x20-\x7e]*$/.test(value);
    const peers = Array.isArray(body.peers) ? body.peers.slice(0, MAX_REPORTED_PEERS) : [];
    const accepted = peers.filter((peer) => peer && Number.isInteger(peer.slot) && peer.slot >= 0 &&
        ['bootnode', 'genesis', 'discovered'].includes(peer.source) && text(peer.address) &&
        ['dialing', 'connected', 'disconnected'].includes(peer.state))
        .map(({ slot, source, address, state }) => ({ slot, source, address, state }));
    const pool = body.pool && typeof body.pool === 'object' ? body.pool : null;
    const count = (value) => (Number.isSafeInteger(value) && value >= 0 ? value : null);
    const next = {
        reportedAt: new Date().toISOString(),
        peers: accepted,
        pool: pool ? { validators: count(pool.validators), discovered: count(pool.discovered), refreshes: count(pool.refreshes) } : null,
    };
    const before = describePeers(browserPeers);
    browserPeers = next;
    const after = describePeers(browserPeers);
    if (after !== before) log(after);
    return next;
}

async function control(action) {
    if (['kill-node0', 'start-node0', 'restart-node0'].includes(action))
        throw new Error(`${action}: ${NOT_MANAGED}; the network belongs to whoever started it`);
    switch (action) {
        case 'status':
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
        let body;
        try {
            body = JSON.parse((await readBody(request)) || '{}');
            action = body?.action;
        } catch (error) {
            sendJson(response, 400, { ok: false, error: String(error && (error.message || error)) });
            return;
        }
        // Peer reports are bookkeeping, not network actions: never queue them
        // behind a kill or restart that takes seconds.
        if (action === 'peers') {
            sendJson(response, 200, { action, ok: true, browserPeers: acceptPeers(body ?? {}) });
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

    // Read from disk on every request, so the page always gets the spec of
    // the network that is actually running.
    if (pathname === '/jam-demo/spec.json') return serveFile(response, specPath, { noStore: true });
    // The negative fixture of step 10: the same spec with an altered genesis
    // authority set, built from the attached spec on every request by the
    // builder the end-to-end scenarios use, so they cannot drift apart.
    if (pathname === `/jam-demo/${WRONG_SPEC_FILENAME}`) {
        let text;
        try {
            const { spec } = corruptGenesisAuthorities(JSON.parse(await fs.readFile(specPath, 'utf8')));
            text = JSON.stringify(spec);
        } catch (error) {
            sendJson(response, 500, { ok: false, error: String(error && (error.message || error)) });
            return;
        }
        response.writeHead(200, {
            'content-type': 'application/json; charset=utf-8',
            'content-length': Buffer.byteLength(text),
            'cache-control': 'no-store',
        });
        response.end(text);
        return;
    }

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
    try {
        await fs.access(DIST_ENTRY);
    } catch {
        throw new Error(
            `${DIST_ENTRY} is missing; build the browser bundle first:\n` +
            '  cd wasm-node/javascript && node prepare.mjs --debug && npm run buildModules\n' +
            '(use `npm run build` instead for the slower min-size release bundle)',
        );
    }
    if (!attachSpecPath) {
        throw new Error(
            'JAM_SPEC_PATH is not set: the harness serves the demo for a running network and starts none.\n' +
            '  Start one with `just zombie-jam`, then run `just demo-jam-attach`;\n' +
            '  or run `just demo-jam-dev` and follow the command it prints.',
        );
    }
    // Fail early on a missing or unreadable spec; the page reads the same
    // file again on every request, unchanged.
    await fs.access(attachSpecPath);
    specPath = attachSpecPath;
    log(`attach mode: spec ${specPath}, RPC oracle on 127.0.0.1:${rpcPort}; no network is managed`);

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

    const banner = [
        `  Open:          http://127.0.0.1:${httpPort}/demo/jam.html`,
        `  Chain spec:    http://127.0.0.1:${httpPort}/jam-demo/spec.json`,
        `  Attach mode:   ${specPath} (served unchanged)`,
        `  RPC oracle:    127.0.0.1:${rpcPort}`,
        '  No network is managed by this harness; the node buttons answer an error.',
        '  Ctrl-C to stop this server; the network keeps running.',
    ];
    const rule = '====================================================================';
    console.log(['', rule, ...banner, rule, ''].join('\n'));
} catch (error) {
    console.error(`[jam-demo] startup failed: ${error && (error.stack || error.message || error)}`);
    shutdown(1);
}
