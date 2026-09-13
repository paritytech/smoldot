// Serves the browser smoldot runner page and relays JSON-RPC between it and
// WebSocket clients such as polkadot.js apps (browsers can't listen on sockets,
// so the page alone can't be an RPC endpoint).
//
//   static files : http://127.0.0.1:<port>/browser/       (runner page)
//   runner link  : ws://127.0.0.1:<port>/runner           (the page connects here)
//   JSON-RPC     : ws://127.0.0.1:<port>/rpc              (polkadot.js connects here)
//
// Usage:
//   node browser/relay.mjs <chainspec.json> <bootnode-multiaddr> [--port <port>]
//
// The chain spec is re-read on every page load, so regenerating the checkpoint
// only requires a page reload, not a relay restart.

import { WebSocketServer } from 'ws';
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// --- Command line parsing ---

const positional = [];
let port = 9946;

const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--port') {
        port = parseInt(argv[++i], 10);
    } else {
        positional.push(argv[i]);
    }
}

const [chainSpecPath, bootnode] = positional;
if (!chainSpecPath || !bootnode || !Number.isInteger(port)) {
    console.error('Usage: node browser/relay.mjs <chainspec.json> <bootnode-multiaddr> [--port <port>]');
    process.exit(1);
}

const isLocalhostWs = /^\/(ip4\/127(\.\d{1,3}){3}|ip6\/::1)\/tcp\/\d+\/ws\/p2p\/[1-9A-HJ-NP-Za-km-z]+$/.test(bootnode);
const isWebRtc = /^\/(ip4|ip6)\/[^/]+\/udp\/\d+\/webrtc-direct\/certhash\/[^/]+\/p2p\/[1-9A-HJ-NP-Za-km-z]+$/.test(bootnode);
if (!isLocalhostWs && !isWebRtc) {
    console.error('The bootnode multiaddr must be either localhost non-secure WebSocket');
    console.error('(/ip4/127.0.0.1/tcp/<port>/ws/p2p/<peer-id>) or WebRTC');
    console.error('(/ip4/<ip>/udp/<port>/webrtc-direct/certhash/<hash>/p2p/<peer-id>)');
    process.exit(1);
}
fs.accessSync(chainSpecPath, fs.constants.R_OK);

const timestamp = () => new Date().toISOString();
const log = (...args) => console.log(`[${timestamp()}] [relay]`, ...args);

// --- Static file server ---

const MIME = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.mjs': 'text/javascript',
    '.json': 'application/json',
    '.wasm': 'application/wasm',
};

const httpServer = http.createServer((req, res) => {
    const pathname = decodeURIComponent(new URL(req.url, 'http://x').pathname);

    if (pathname === '/config.json') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ bootnode }));
        return;
    }
    if (pathname === '/chainspec.json') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(fs.readFileSync(chainSpecPath));
        return;
    }

    const fsPath = path.normalize(path.join(ROOT, pathname === '/' ? '/browser/index.html' : pathname));
    if (!fsPath.startsWith(ROOT + path.sep)) {
        res.writeHead(403);
        res.end();
        return;
    }
    fs.readFile(fsPath, (err, data) => {
        if (err) {
            // Not one of our files: reverse-proxy from polkadot.js.org, so the
            // apps UI runs on this loopback origin. Browsers block WebSockets
            // from the public https origin to 127.0.0.1 (mixed content in
            // Firefox, Local Network Access in Chrome); loopback-to-loopback
            // from an insecure origin is allowed everywhere.
            proxyUpstream(req, res);
            return;
        }
        res.writeHead(200, { 'Content-Type': MIME[path.extname(fsPath)] ?? 'application/octet-stream' });
        res.end(data);
    });
});

const APPS_UPSTREAM = 'https://polkadot.js.org';

const proxyUpstream = async (req, res) => {
    try {
        const url = new URL(req.url, APPS_UPSTREAM);
        const upstream = await fetch(url, { headers: { accept: req.headers['accept'] ?? '*/*' } });
        // Only forward the content type: fetch already decompressed the body,
        // and upstream CSP/HSTS headers must not reach this origin.
        res.writeHead(upstream.status, {
            'Content-Type': upstream.headers.get('content-type') ?? 'application/octet-stream',
        });
        const body = new Uint8Array(await upstream.arrayBuffer());
        res.end(body);
    } catch (error) {
        res.writeHead(502);
        res.end('upstream fetch failed: ' + error.message);
    }
};

// --- WebSocket relay ---

let runner = null;
const rpcClients = new Map();
let nextClientId = 1;

const wssRunner = new WebSocketServer({ noServer: true });
const wssRpc = new WebSocketServer({ noServer: true });

const closeAllRpcClients = (code, reason) => {
    for (const [id, client] of rpcClients) {
        client.close(code, reason);
        rpcClients.delete(id);
    }
};

wssRunner.on('connection', (socket, request) => {
    log(`runner user-agent: ${request.headers['user-agent'] ?? '?'}`);
    if (runner !== null) {
        log('runner page replaced (old page reloaded or duplicate tab closed)');
        runner.close(4000, 'replaced by a new runner page');
    }
    // Chains added for previous clients died with the old page; force clients
    // to reconnect and get fresh ones.
    closeAllRpcClients(1012, 'runner page restarted');
    runner = socket;
    log('runner page connected');

    socket.on('message', (data, isBinary) => {
        if (isBinary) return;
        let msg;
        try {
            msg = JSON.parse(data.toString('utf8'));
        } catch (_error) {
            return;
        }
        if (msg.kind === 'rpc-message') {
            rpcClients.get(msg.id)?.send(msg.message);
        } else if (msg.kind === 'log') {
            console.log(msg.line);
        }
    });

    socket.on('close', () => {
        if (runner !== socket) return;
        runner = null;
        log('runner page disconnected');
        closeAllRpcClients(1012, 'runner page disconnected');
    });
});

wssRpc.on('connection', (socket, request) => {
    if (runner === null) {
        log('rejecting JSON-RPC client: no runner page connected');
        socket.close(1013, 'runner page not connected; open the runner page first');
        return;
    }
    const id = nextClientId++;
    rpcClients.set(id, socket);
    log(`JSON-RPC client ${id} connected: ${request.socket.remoteAddress} (${request.headers['user-agent'] ?? '?'})`);
    runner.send(JSON.stringify({ kind: 'rpc-connected', id }));

    socket.on('message', (data, isBinary) => {
        if (isBinary) {
            socket.close(1002);
            return;
        }
        runner?.send(JSON.stringify({ kind: 'rpc-message', id, message: data.toString('utf8') }));
    });

    socket.on('close', () => {
        if (!rpcClients.delete(id)) return;
        log(`JSON-RPC client ${id} disconnected`);
        runner?.send(JSON.stringify({ kind: 'rpc-disconnected', id }));
    });
});

httpServer.on('upgrade', (request, socket, head) => {
    const pathname = new URL(request.url, 'http://x').pathname;
    const wss = pathname === '/runner' ? wssRunner : pathname === '/rpc' ? wssRpc : null;
    if (!wss) {
        socket.destroy();
        return;
    }
    wss.handleUpgrade(request, socket, head, (ws) => wss.emit('connection', ws, request));
});

httpServer.listen(port, '127.0.0.1', () => {
    log(`bootnode: ${bootnode} (${isWebRtc ? 'WebRTC' : 'localhost WebSocket'})`);
    log(`runner page:  http://127.0.0.1:${port}/`);
    log(`JSON-RPC:     ws://127.0.0.1:${port}/rpc`);
    log(`polkadot.js:  http://127.0.0.1:${port}/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A${port}%2Frpc  (proxied to avoid browser local-network blocking)`);
});
