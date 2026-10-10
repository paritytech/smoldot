// Runs a smoldot light client that can only connect to a single full node on localhost
// over non-secure WebSocket, and exposes a JSON-RPC WebSocket server that polkadot.js
// apps (or any other UI) can connect to.
//
// Isolation is guaranteed by two mechanisms:
// - The chain spec's `bootNodes` are replaced with the single provided multiaddr.
// - All transports except non-secure-WebSocket-to-localhost are forbidden. Smoldot
//   filters every address (bootnode or DHT-discovered) through
//   `supports_connection_type()` before dialing, so peers discovered through the full
//   node's DHT are unreachable and never dialed.
//
// Usage:
//   node demo-ws.mjs <chainspec.json> <bootnode-multiaddr> [--rpc-port <port>] [--verbose]
//
// The bootnode multiaddr must be a localhost non-secure-WebSocket address:
//   /ip4/127.0.0.1/tcp/<port>/ws/p2p/<peer-id>
// i.e. the full node must listen with e.g. `--listen-addr /ip4/127.0.0.1/tcp/30333/ws`.

import { start } from 'smoldot';
import { WebSocketServer } from 'ws';
import * as fs from 'node:fs';
import process from 'node:process';

// --- Command line parsing ---

const positional = [];
let rpcPort = 9944;
let verbose = false;

const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--rpc-port') {
        rpcPort = parseInt(argv[++i], 10);
    } else if (argv[i] === '--verbose') {
        verbose = true;
    } else {
        positional.push(argv[i]);
    }
}

const [chainSpecPath, bootnode] = positional;
if (!chainSpecPath || !bootnode || !Number.isInteger(rpcPort)) {
    console.error('Usage: node demo-ws.mjs <chainspec.json> <bootnode-multiaddr> [--rpc-port <port>] [--verbose]');
    process.exit(1);
}

// Only loopback WS addresses pass smoldot's connection-type filter below; reject
// anything else upfront rather than let smoldot silently never dial it.
if (!/^\/(ip4\/127(\.\d{1,3}){3}|ip6\/::1)\/tcp\/\d+\/ws\/p2p\/[1-9A-HJ-NP-Za-km-z]+$/.test(bootnode)) {
    console.error('The bootnode multiaddr must be of the form /ip4/127.0.0.1/tcp/<port>/ws/p2p/<peer-id>');
    process.exit(1);
}

// `remote_addr` in logs has the `/p2p/...` suffix stripped.
const expectedRemoteAddr = bootnode.replace(/\/p2p\/.*$/, '');

// --- Chain spec ---

const parsedSpec = JSON.parse(fs.readFileSync(chainSpecPath, 'utf8'));
if (parsedSpec.relay_chain) {
    console.error('This chain spec is a parachain (relay_chain: ' + parsedSpec.relay_chain + '); this demo only handles solo/relay chains.');
    process.exit(1);
}
console.log('Chain: ' + parsedSpec.id + '; replacing ' + (parsedSpec.bootNodes?.length ?? 0) + ' bootnode(s) with ' + bootnode);
parsedSpec.bootNodes = [bootnode];
const chainSpec = JSON.stringify(parsedSpec);

// --- Smoldot client ---

const LEVELS = ['', 'ERROR', 'WARN', 'INFO', 'DEBUG'];

const client = start({
    // Together these leave exactly one dialable transport: non-secure WebSocket to
    // localhost (gated only by `forbidWs`).
    forbidTcp: true,
    forbidWss: true,
    forbidNonLocalWs: true,

    maxLogLevel: 4,
    logCallback: (level, target, message) => {
        // A dial to anything other than the provided node would be a bug in the
        // isolation setup; make it loud.
        const now = new Date().toISOString();
        if (message.includes('connection-started') && !message.includes(expectedRemoteAddr)) {
            console.warn('\x1b[31m!!! dialed an unexpected address: [%s] [%s] %s\x1b[0m', now, target, message);
            return;
        }
        // By default, of the debug-level spam keep everything from the sync service
        // (mode decision, warp progress) plus the network lines relevant to isolation
        // (dials, discovery) and sync bootstrap (gossip substreams, grandpa, failures).
        if (level >= 4 && !verbose
            && !target.startsWith('sync-service')
            && !/connect|discover|gossip|grandpa|slot|announce|handshake|ban|error|failed|rejected|no-address|warp/i.test(message)) return;
        console.log('[%s] [%s] [%s] %s', now, LEVELS[level] ?? level, target, message);
    },
});

// Add the chain right away (without JSON-RPC) so syncing starts before the first
// client connects. Later `addChain` calls with the same spec are de-duplicated by
// smoldot and share the network/sync services.
const backgroundChain = client
    .addChain({ chainSpec, disableJsonRpc: true })
    .catch((error) => {
        console.error('Error while adding chain: ' + error);
        process.exit(1);
    });

process.on('SIGINT', () => {
    backgroundChain
        .then((chain) => chain.remove())
        .then(() => client.terminate())
        .then(() => process.exit(0));
});

// --- JSON-RPC WebSocket server ---

const wsServer = new WebSocketServer({ host: '127.0.0.1', port: rpcPort });

console.log('JSON-RPC server listening on ws://127.0.0.1:' + rpcPort);
console.log('polkadot.js apps: https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A' + rpcPort);
console.log('');

wsServer.on('connection', (connection, request) => {
    console.log('(rpc) client connected: ' + request.socket.remoteAddress);

    // Each client gets its own chain handle so that its subscriptions and pending
    // requests die with the connection.
    const chainPromise = client
        .addChain({ chainSpec })
        .then((chain) => {
            (async () => {
                try {
                    for await (const response of chain.jsonRpcResponses) {
                        connection.send(response);
                    }
                } catch (_error) { }
            })();
            return chain;
        })
        .catch((error) => {
            console.error('(rpc) error while adding chain: ' + error);
            connection.close(1011); // Internal error.
            return null;
        });

    connection.on('message', (data, isBinary) => {
        if (isBinary) {
            connection.close(1002); // Protocol error.
            return;
        }
        const message = data.toString('utf8');
        chainPromise.then((chain) => {
            if (!chain) return;
            try {
                chain.sendJsonRpc(message);
            } catch (error) {
                // e.g. QueueFullError; drop the client rather than the process.
                console.error('(rpc) sendJsonRpc failed: ' + error);
                connection.close(1011);
            }
        });
    });

    connection.on('close', () => {
        console.log('(rpc) client disconnected');
        chainPromise.then((chain) => chain?.remove()).catch(() => { });
    });
});
