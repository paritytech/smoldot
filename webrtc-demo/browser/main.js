// Browser smoldot runner. Fetches config + chain spec from the relay, runs
// smoldot locked to the single configured bootnode, and serves JSON-RPC clients
// (polkadot.js) connected to the relay's /rpc endpoint.
//
// Transport is derived from the bootnode multiaddr: `/webrtc-direct/` allows
// only WebRTC dialing, localhost `/ws` allows only localhost non-secure
// WebSocket. Query params: ?verbose=1 disables the debug-log filter.

import { start } from '/node_modules/smoldot/dist/mjs/index-browser.js';

const statusEl = document.getElementById('status');
const bannerEl = document.getElementById('banner');
const logEl = document.getElementById('log');
const verbose = new URLSearchParams(location.search).get('verbose') === '1';

const MAX_LOG_LINES = 2000;
const appendLog = (line, cls) => {
    const span = document.createElement('span');
    span.textContent = line + '\n';
    if (cls) span.className = cls;
    const follow = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 10;
    logEl.appendChild(span);
    while (logEl.childNodes.length > MAX_LOG_LINES) logEl.removeChild(logEl.firstChild);
    if (follow) logEl.scrollTop = logEl.scrollHeight;
};

let relaySocket = null;
const relayLog = (line) => {
    if (relaySocket?.readyState === WebSocket.OPEN)
        relaySocket.send(JSON.stringify({ kind: 'log', line }));
};

let mode = '?';
let rpcClientCount = 0;
let relayConnected = false;
const renderStatus = (extra) => {
    statusEl.textContent = extra ??
        `running — transport: ${mode}, relay: ${relayConnected ? 'connected' : 'DISCONNECTED'}, RPC clients: ${rpcClientCount}` +
        (verbose ? ', verbose logs' : '');
};

const fail = (message) => {
    renderStatus('FAILED');
    bannerEl.textContent = message;
    throw new Error(message);
};

// --- Config and chain spec ---

renderStatus('fetching config…');
const { bootnode } = await (await fetch('/config.json')).json();
const parsedSpec = JSON.parse(await (await fetch('/chainspec.json')).text());
parsedSpec.bootNodes = [bootnode];
const chainSpec = JSON.stringify(parsedSpec);
const expectedRemoteAddr = bootnode.replace(/\/p2p\/.*$/, '');

let forbidFlags;
if (bootnode.includes('/webrtc-direct/')) {
    mode = 'webrtc';
    forbidFlags = { forbidWs: true, forbidNonLocalWs: true, forbidWss: true };
    const loopbackTarget = /^\/(ip4\/127\.|ip6\/::1\/)/.test(bootnode);
    if (loopbackTarget && navigator.userAgent.includes('Firefox'))
        bannerEl.textContent = 'Firefox cannot connect to a localhost WebRTC server (Mozilla bug 1659672); use Chromium or a non-loopback IP of this machine.';
} else {
    mode = 'localhost-ws';
    forbidFlags = { forbidNonLocalWs: true, forbidWss: true };
}

// --- Smoldot ---

renderStatus('starting smoldot…');
const client = start({
    ...forbidFlags,
    maxLogLevel: 4,
    logCallback: (level, target, message) => {
        const LEVELS = ['', 'ERROR', 'WARN', 'INFO', 'DEBUG'];
        const line = `[${new Date().toISOString()}] [${LEVELS[level] ?? level}] [${target}] ${message}`;
        if (message.includes('connection-started') && !message.includes(expectedRemoteAddr)) {
            appendLog('!!! dialed an unexpected address: ' + line, 'err');
            relayLog('!!! dialed an unexpected address: ' + line);
            return;
        }
        // Same filter as the Node.js demo: keep sync-service lines plus
        // isolation/bootstrap-relevant network lines.
        if (level >= 4 && !verbose
            && !target.startsWith('sync-service')
            && !/connect|discover|gossip|grandpa|slot|announce|handshake|ban|error|failed|rejected|no-address|warp/i.test(message)) return;
        appendLog(line, level === 2 ? 'warn' : level === 1 ? 'err' : undefined);
        relayLog(line);
    },
});

// Background chain: starts syncing before any JSON-RPC client connects and
// keeps the chain alive between clients.
client.addChain({ chainSpec, disableJsonRpc: true }).catch((error) => {
    fail('addChain failed: ' + error);
});
renderStatus();

// --- Relay connection ---

// id -> { chainPromise, gone }; `gone` stops the response pump after removal.
const rpcChains = new Map();

const onRpcConnected = (id) => {
    const entry = { gone: false };
    entry.chainPromise = client
        .addChain({ chainSpec })
        .then((chain) => {
            (async () => {
                try {
                    for await (const response of chain.jsonRpcResponses) {
                        if (entry.gone) break;
                        relaySocket?.send(JSON.stringify({ kind: 'rpc-message', id, message: response }));
                    }
                } catch (_error) { }
            })();
            return chain;
        })
        .catch((error) => {
            appendLog(`addChain for RPC client ${id} failed: ${error}`, 'err');
            return null;
        });
    rpcChains.set(id, entry);
    rpcClientCount++;
    renderStatus();
};

const onRpcDisconnected = (id) => {
    const entry = rpcChains.get(id);
    if (!entry) return;
    rpcChains.delete(id);
    entry.gone = true;
    entry.chainPromise.then((chain) => chain?.remove()).catch(() => { });
    rpcClientCount--;
    renderStatus();
};

const dropAllRpcChains = () => {
    for (const id of [...rpcChains.keys()]) onRpcDisconnected(id);
};

const connectRelay = () => {
    const socket = new WebSocket(`ws://${location.host}/runner`);
    socket.onopen = () => {
        relaySocket = socket;
        relayConnected = true;
        renderStatus();
        appendLog('relay connected');
    };
    socket.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.kind === 'rpc-connected') {
            onRpcConnected(msg.id);
        } else if (msg.kind === 'rpc-message') {
            rpcChains.get(msg.id)?.chainPromise.then((chain) => {
                try {
                    chain?.sendJsonRpc(msg.message);
                } catch (error) {
                    appendLog(`sendJsonRpc for RPC client ${msg.id} failed: ${error}`, 'err');
                }
            });
        } else if (msg.kind === 'rpc-disconnected') {
            onRpcDisconnected(msg.id);
        }
    };
    socket.onclose = () => {
        if (relaySocket === socket) relaySocket = null;
        relayConnected = false;
        renderStatus();
        dropAllRpcChains();
        setTimeout(connectRelay, 2000);
    };
};
connectRelay();
