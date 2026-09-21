// Smoldot
// Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// A minimal Node.js light client for Polkadot Asset Hub — or for the Polkadot relay chain alone —
// with database persistence, pinned to a fixed set of nodes, able to run several independent
// clients in one process.
//
// Asset Hub is a parachain, so the Polkadot relay chain is mandatory: `addChain` rejects the
// parachain spec with `NoRelayChainFound` unless a matching relay chain is passed through
// `potentialRelayChains`. Nearly all of the startup cost is the relay chain's warp sync, which
// is precisely what persisting its database avoids paying twice.
//
// Pinning takes two pieces, and both are needed. `nodes.json` maps each chain's `id` to the
// multiaddrs of the only nodes the client may talk to; they replace the chain's `bootNodes`,
// which decides who is contacted first. `connectionFilter` then refuses every dial to any other
// address, which is what makes the restriction hold: peer discovery keeps surfacing other nodes
// for as long as the client runs, and bootnodes lose their slot preference as soon as the chain
// first connects.

import { startWithBytecode } from '../../wasm-node/javascript/dist/mjs/no-auto-bytecode-nodejs.js';
import { compileBytecode } from '../../wasm-node/javascript/dist/mjs/bytecode-nodejs.js';
import { loadQueryConfig, startReviveReads } from './revive-reads.mjs';
import * as fs from 'node:fs';
import * as path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SPECS_DIR = path.join(HERE, '..', '..', 'demo-chain-specs');
const DB_DIR = process.env.SMOLDOT_DB_DIR || path.join(HERE, '.db');

const SAVE_INTERVAL_MS = 30_000;

// What to print per block: `finalized` (default), `imported`, or `both`.
//
// "imported" is every block header the light client receives and verifies
// (`chain_subscribeAllHeads`, forks included), stamped with the wall-clock time it arrived;
// "finalized" is each block as it becomes finalized. Comparing the two kinds of line across
// instances says where a delay comes from: a block imported late means its announcement reached
// this instance late, while a block imported on time but finalized late means the GRANDPA
// commit did.
const REPORT = process.env.SMOLDOT_REPORT || 'finalized';
if (!['finalized', 'imported', 'both'].includes(REPORT))
    throw new Error(`SMOLDOT_REPORT must be "finalized", "imported" or "both" (got "${REPORT}")`);

// Which chain the lines above are about. By default the client follows Polkadot Asset Hub and
// reports its blocks; the relay chain is added only because the parachain needs it, and nothing
// is printed about it. With SMOLDOT_RELAY_ONLY=1 the parachain is not added at all, and the
// lines report Polkadot's own blocks instead — a relay-chain light client on its own.
const RELAY_ONLY = process.env.SMOLDOT_RELAY_ONLY === '1';

// How many light clients this process runs. Each one is a complete, independent smoldot client
// — its own Wasm instance, connections and therefore peer identity, database directory and
// worker thread — so N clients in one process are N separate light clients as far as the
// network is concerned. What they share is the Node.js runtime and the compiled Wasm module,
// which is the memory that one process per client would pay N times over.
const CLIENTS = Number(process.env.SMOLDOT_CLIENTS || 1);
if (!Number.isInteger(CLIENTS) || CLIENTS < 1)
    throw new Error(`SMOLDOT_CLIENTS must be a positive integer (got "${process.env.SMOLDOT_CLIENTS}")`);

// How much of smoldot's own logging is printed verbatim: 1 errors, 2 warnings, 3 info,
// 4 debug, 5 trace.
const LOG_LEVEL = Number(process.env.SMOLDOT_LOG_LEVEL) || 2;

// Connection diagnostics: which peers the client is actually talking to, the identity it
// presents to them, and why a peer goes away. smoldot reports all of that on its `network` log
// target at debug level, so seeing any of it means running the client at level 4 and picking
// the interesting events out here; the rest of level 4 is not printed.
//
// That is not free. `maxLogLevel` exists so the client can skip building messages nobody will
// read, and the formatting it now does happens inside the client's `cpuRateLimit` budget.
// `SMOLDOT_NET_LOG=0` turns it off and restores the previous behaviour exactly.
const NET_LOG = process.env.SMOLDOT_NET_LOG !== '0';

// Upper bound on how long to wait for a database to be handed over. See `persistDatabases`.
const SAVE_DEADLINE_MS = 15_000;

// Upper bound on each serialized database. When the content doesn't fit, smoldot drops the
// cached `:code` runtime first and only then starts halving the peer list, so a value that is
// too small silently costs you the most valuable part, without failing. Asset Hub currently
// serializes to ~3.2 MiB and Polkadot to ~2.3 MiB, both dominated by that base64-encoded
// runtime, so this leaves room for them to grow.
const MAX_DB_BYTES = 8 * 1024 * 1024;

// How often each client reads a `pallet-revive` contract's storage, in milliseconds; 0 turns it
// off and leaves the client following the chain and nothing else, exactly as it did before.
//
// Following a chain asks a node for almost nothing. This is what asks it for something: each
// read set is one main-trie proof and one child-trie proof, and a child-trie proof over contract
// storage is about the most expensive thing a light client can ask for. See `revive-reads.mjs`
// for the shape and where it comes from.
const QUERY_INTERVAL_MS = Number(process.env.SMOLDOT_QUERY_INTERVAL_MS ?? 30_000);
if (!Number.isInteger(QUERY_INTERVAL_MS) || QUERY_INTERVAL_MS < 0)
    throw new Error(`SMOLDOT_QUERY_INTERVAL_MS must be a non-negative integer (got "${process.env.SMOLDOT_QUERY_INTERVAL_MS}")`);

// Where the contract and its keys come from. Written by `discover-revive-contracts.mjs`.
const QUERY_CONFIG = process.env.SMOLDOT_QUERY_CONFIG || path.join(HERE, 'revive-queries.json');

// Spread the ticks out instead of firing them all on the same beat. Instances started together
// -- which is how `run-instances.sh` starts them -- would otherwise arrive at the node as a
// burst once per period rather than as a steady rate, which measures something else entirely.
const QUERY_JITTER = process.env.SMOLDOT_QUERY_JITTER !== '0';

// How many of the configured keys to read per set. The full set stands in for a cold resolution;
// a handful stands in for a warm one that only revalidates.
const QUERY_KEYS = process.env.SMOLDOT_QUERY_KEYS === undefined
    ? undefined
    : Number(process.env.SMOLDOT_QUERY_KEYS);
if (QUERY_KEYS !== undefined && (!Number.isInteger(QUERY_KEYS) || QUERY_KEYS < 1))
    throw new Error(`SMOLDOT_QUERY_KEYS must be a positive integer (got "${process.env.SMOLDOT_QUERY_KEYS}")`);

// `batched` puts every key in one `chainHead_v1_storage` call, which smoldot turns into a single
// proof request; `serial` sends one call per key and therefore one proof request per key. The
// node's work differs by much more than the request count, so which one a real client does is
// worth being able to measure rather than assume.
const QUERY_BATCH = (process.env.SMOLDOT_QUERY_BATCH || 'batched').toLowerCase();
if (!['batched', 'serial'].includes(QUERY_BATCH))
    throw new Error(`SMOLDOT_QUERY_BATCH must be "batched" or "serial" (got "${QUERY_BATCH}")`);

// Exit after this long so that whatever supervises the process starts it again. `"900000"` is a
// fixed lifetime; `"720000-1200000"` picks one uniformly from that range, once, at startup.
// Unset (the default) means run until something else stops it.
//
// This exists because a long run grows: reading contract storage on a short period retains
// roughly 115 KiB per read set, so at a 0.1 s period a process adds ~127 MiB a minute and the
// latency of every read climbs with the garbage collector's work until the pod is throttled or
// killed. Recycling is not a fix for that, it just bounds it -- the leak is worth finding -- but
// it keeps a load test producing a flat number instead of a decay curve.
//
// Pick the range rather than a single value when several instances start together, for the same
// reason `SMOLDOT_QUERY_JITTER` exists: identical lifetimes make them all leave at once, and a
// pinned node then sees the whole fleet drop its connections and ask for its light-client slots
// back on the same beat. Restarting costs little -- following the chain again takes about 3 s
// from a database this process saved seconds earlier -- so a short spread is enough.
const MAX_LIFETIME_MS = (() => {
    const raw = process.env.SMOLDOT_MAX_LIFETIME_MS;
    if (raw === undefined || raw === '')
        return undefined;
    const bounds = raw.split('-').map((part) => Number(part.trim()));
    if (bounds.length > 2 || bounds.some((n) => !Number.isInteger(n) || n <= 0))
        throw new Error(`SMOLDOT_MAX_LIFETIME_MS must be a positive integer or "min-max" (got "${raw}")`);
    const [min, max = min] = bounds;
    if (max < min)
        throw new Error(`SMOLDOT_MAX_LIFETIME_MS range is backwards (got "${raw}")`);
    return min + Math.floor(Math.random() * (max - min + 1));
})();

// The nodes to pin to, as `{ "<chain id>": "<multiaddr>" | ["<multiaddr>", ...] }`.
// `SMOLDOT_NODES` points at a different file; `SMOLDOT_UNPINNED=1` turns pinning off and lets
// the client roam the network like any other light client. A missing `nodes.json` does the same,
// and says so: the file is git-ignored, since which nodes to pin to is up to whoever runs this,
// and `nodes.example.json` is its template.
function loadPinnedNodes() {
    if (process.env.SMOLDOT_UNPINNED === '1')
        return undefined;

    const file = process.env.SMOLDOT_NODES || path.join(HERE, 'nodes.json');
    let content;
    try {
        content = fs.readFileSync(file, 'utf8');
    } catch (error) {
        if (error.code === 'ENOENT' && !process.env.SMOLDOT_NODES) {
            console.log('pinning: off, there is no nodes.json (nodes.example.json is the template)');
            return undefined;
        }
        throw error;
    }

    const nodes = {};
    for (const [chainId, addresses] of Object.entries(JSON.parse(content)))
        nodes[chainId] = Array.isArray(addresses) ? addresses : [addresses];
    return nodes;
}

// The `host:port` that `connectionFilter` will be shown for a multiaddr of the form
// `/ip4|ip6|dns|dns4|dns6/<host>/tcp/<port>[/ws|/wss]/p2p/<peer id>`.
//
// The peer id is deliberately not part of the key: it isn't known when the dial happens, and
// smoldot verifies it itself during the handshake — a node answering at the right address with
// the wrong identity is dropped.
function dialTargetOfMultiaddr(multiaddr) {
    const [, hostProtocol, host, transport, port] = multiaddr.split('/');
    if (!['ip4', 'ip6', 'dns', 'dns4', 'dns6'].includes(hostProtocol)
        || transport !== 'tcp' || !/^\d+$/.test(port ?? ''))
        throw new Error(`unsupported multiaddr in nodes.json: ${multiaddr}`);
    return `${host.toLowerCase()}:${port}`;
}

// The same key, computed from the address smoldot is about to dial.
function dialTargetOfAddress(address) {
    switch (address.ty) {
        case 'tcp':
            return `${address.hostname.toLowerCase()}:${address.port}`;
        case 'websocket': {
            const url = new URL(address.url);
            // `URL` drops the port when it is the default one for the scheme, and keeps the
            // brackets around an IPv6 literal.
            const port = url.port || (url.protocol === 'wss:' ? 443 : 80);
            return `${url.hostname.replace(/^\[|\]$/g, '')}:${port}`;
        }
        case 'webrtc':
            return `${address.targetIp}:${address.targetPort}`;
    }
}

// Databases live directly in DB_DIR for a single client, and in `DB_DIR/client-<n>/` for each
// client of a multi-client process. Each client always *saves* into its own directory.
//
// Loading is more liberal, and deliberately so. A database carries no identity — only chain
// information, a peer list and the runtime code — so any client's database is as good as any
// other's, and the only thing that distinguishes them is age. A client therefore loads the
// newest usable database it can find: its own directory, the other client directories under the
// same database directory, that directory itself, the seed (`SMOLDOT_SEED_DB`, default `.db`,
// the same variable run-instances.sh uses), and every `.db*` directory next to the example —
// which is where the launcher keeps its per-instance databases. Setting SMOLDOT_SEED_DB to the
// empty string confines the search to the client's own directory. Without this, a per-instance
// database written days ago by an instance that has never since managed to follow the chain is
// reused forever, and the older it gets the longer a single pruned node takes to bring it up.
//
// "Usable" means it contains the runtime code. smoldot serializes a database *without* it when
// a save lands while it has no known runtime — a ~45 s window that follows a large finality
// jump. Such a database is worse than none: on the next start the runtime has to be fetched at
// the database's finalized block, which a pruned node can no longer serve once that block has
// aged out of its state history, and the client stalls with no warning. Those databases are
// never loaded here, and `saveOne` never writes one.
const SEED_DIR = process.env.SMOLDOT_SEED_DB === undefined
    ? path.join(HERE, '.db')
    : process.env.SMOLDOT_SEED_DB === '' ? undefined : path.resolve(HERE, process.env.SMOLDOT_SEED_DB);

function databaseDirOf(clientIndex) {
    return CLIENTS === 1 ? DB_DIR : path.join(DB_DIR, `client-${clientIndex}`);
}

function subdirectories(base, pattern) {
    try {
        return fs.readdirSync(base, { withFileTypes: true })
            .filter((entry) => entry.isDirectory() && pattern.test(entry.name))
            .map((entry) => path.join(base, entry.name));
    } catch (error) {
        if (error.code === 'ENOENT') return [];
        throw error;
    }
}

// Every place a database for this chain may live, nearest first. The set is wide on purpose:
// runs switch between one and several clients per process and between `node index.mjs` and
// run-instances.sh, and each of those writes to a different place. Setting SMOLDOT_SEED_DB to
// the empty string confines the search to this client's own database directory.
function databaseCandidates(dir, name) {
    const dirs = new Set([dir]);
    const addWithClients = (base) => {
        dirs.add(base);
        for (const sub of subdirectories(base, /^client-\d+$/))
            dirs.add(sub);
    };
    addWithClients(DB_DIR);
    if (SEED_DIR) {
        // The seed itself, and every database directory next to the example: `.db`, the
        // launcher's `.db_<n>`, and their per-client subdirectories.
        addWithClients(SEED_DIR);
        for (const sibling of subdirectories(HERE, /^\.db/))
            addWithClients(sibling);
    }
    return [...dirs].map((d) => path.join(d, `${name}.json`));
}

function databaseHasRuntime(content) {
    try {
        const database = JSON.parse(content);
        return typeof database.runtimeCode === 'string' && database.runtimeCode.length > 0
            && database.chain !== null && database.chain !== undefined;
    } catch (_) {
        return false;
    }
}

// Paths inside the example directory are shown relative to it; anything else as given.
function describePath(file) {
    const relative = path.relative(HERE, file);
    return relative.startsWith('..') ? file : relative;
}

function describeAge(mtimeMs) {
    const minutes = (Date.now() - mtimeMs) / 60_000;
    return minutes < 90 ? `${minutes.toFixed(0)} min old` : `${(minutes / 60).toFixed(1)} h old`;
}

// A database is trusted input: smoldot applies its content without verifying it against the
// chain spec. Only ever reload one that was written by this process, from a location no other
// program can write to.
function loadDatabase(dir, name, log) {
    const found = [];
    for (const file of databaseCandidates(dir, name)) {
        try {
            found.push({ file, mtime: fs.statSync(file).mtimeMs });
        } catch (error) {
            if (error.code !== 'ENOENT')
                throw error;
        }
    }
    found.sort((a, b) => b.mtime - a.mtime);   // Newest first; stop at the first usable one.

    const own = path.join(dir, `${name}.json`);
    const skipped = [];
    for (const { file, mtime } of found) {
        const content = fs.readFileSync(file, 'utf8');
        if (!databaseHasRuntime(content)) {
            skipped.push(`${describePath(file)} (no runtime code)`);
            continue;
        }
        if (file !== own || skipped.length !== 0) {
            log(`${name} database: using ${describePath(file)} (${describeAge(mtime)})`
                + (skipped.length !== 0 ? `; skipped ${skipped.join(', ')}` : ''));
        }
        return content;
    }
    if (skipped.length !== 0)
        log(`${name} database: none usable; skipped ${skipped.join(', ')}`);
    return undefined;  // First run: smoldot falls back to the chain spec's checkpoint.
}

// Written through a temporary file so that a crash midway can't leave behind a half-written
// database, which would be silently discarded on the next start.
function saveDatabase(dir, name, content) {
    const target = path.join(dir, `${name}.json`);
    const temporary = `${target}.tmp`;
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(temporary, content);
    fs.renameSync(temporary, target);
}

// Responses and subscription notifications share a single queue per chain, so requests have to
// be matched back to their `id`. Anything that isn't a response to a pending request is a
// notification and goes to `onNotification`.
function jsonRpcRouter(chain, onNotification) {
    const pending = new Map();
    let nextId = 0;

    (async () => {
        while (true) {
            let response;
            try {
                response = await chain.nextJsonRpcResponse();
            } catch (error) {
                // The chain was removed or the client terminated.
                for (const { reject } of pending.values())
                    reject(error);
                pending.clear();
                return;
            }

            const message = JSON.parse(response);
            const request = message.id !== undefined ? pending.get(message.id) : undefined;
            if (request) {
                pending.delete(message.id);
                if (message.error)
                    request.reject(new Error(message.error.message));
                else
                    request.resolve(message.result);
            } else if (onNotification) {
                onNotification(message);
            }
        }
    })();

    return function request(method, params = []) {
        const id = `req-${nextId++}`;
        const result = new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
        chain.sendJsonRpc(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
        return result;
    };
}

// `chainHead_unstable_finalizedDatabase` is answered from whatever the chain currently holds,
// with one sharp edge: on a parachain it does not answer at all until the chain has a finalized
// runtime, i.e. not until the initial sync completes. (The relay chain answers straight away,
// with the chain spec's checkpoint and an empty peer list.) Saves are therefore gated on the
// chain actually following, and a deadline is kept as a backstop so that Ctrl+C during a sync
// exits rather than hanging.
function withDeadline(promise, milliseconds, what) {
    let timer;
    const deadline = new Promise((_, reject) => {
        timer = setTimeout(
            () => reject(new Error(`${what} did not answer within ${milliseconds / 1000}s`)),
            milliseconds,
        );
    });
    return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

// Read once, at startup, so that a missing or malformed file fails immediately and loudly
// rather than on the first tick of every client. A client that is only meant to follow the chain
// does not need the file at all.
const queryConfig = QUERY_INTERVAL_MS > 0 && !RELAY_ONLY ? loadQueryConfig(QUERY_CONFIG) : undefined;
if (QUERY_INTERVAL_MS > 0 && RELAY_ONLY)
    console.log('not reading contract storage: SMOLDOT_RELAY_ONLY=1 means there is no Asset Hub to read it from');

const relaySpec = JSON.parse(fs.readFileSync(path.join(SPECS_DIR, 'polkadot.json'), 'utf8'));
const assetHubSpec = JSON.parse(fs.readFileSync(path.join(SPECS_DIR, 'polkadot_asset_hub.json'), 'utf8'));
const chainsInUse = RELAY_ONLY ? [relaySpec] : [relaySpec, assetHubSpec];
const reportedSpec = RELAY_ONLY ? relaySpec : assetHubSpec;

const pinnedNodes = loadPinnedNodes();
if (pinnedNodes) {
    // Every chain in use has to be listed: a chain that isn't would keep its public bootnodes,
    // all of which the filter below would then refuse, leaving it with nobody to talk to. An
    // entry for the parachain is simply unused in relay-only mode.
    const specsById = new Map(chainsInUse.map((spec) => [spec.id, spec]));
    for (const spec of chainsInUse) {
        if (!pinnedNodes[spec.id])
            throw new Error(`nodes.json has no entry for chain "${spec.id}"`);
    }
    for (const [chainId, addresses] of Object.entries(pinnedNodes)) {
        const spec = specsById.get(chainId);
        if (!spec) {
            if (chainId === assetHubSpec.id && RELAY_ONLY)
                continue;
            throw new Error(`nodes.json names chain "${chainId}", which is not one of: ${[...specsById.keys()].join(', ')}`);
        }
        spec.bootNodes = addresses;
        console.log(`${chainId}: pinned to ${addresses.join(', ')}`);
    }
}

// A single relay-chain node can't carry a *cold* warp sync. Before the sync completes, smoldot
// fetches the runtime at the chain spec's checkpoint block; a node with `--state-pruning` no
// longer has state that old and says so, smoldot answers with a 10 s ban, and the ban drops the
// connection along with the warp-sync request in flight. With nobody to fall back on, the cycle
// repeats. A saved database carries the runtime code and a recent finalized block, so nothing
// has to be fetched at an old block and the problem doesn't arise — see README.md, "First run".
const databases = Array.from({ length: CLIENTS }, (_, i) => {
    const dir = databaseDirOf(i + 1);
    const log = (line) => console.log((CLIENTS === 1 ? '' : `[${i + 1}] `) + line);
    return {
        relay: loadDatabase(dir, 'polkadot', log),
        assetHub: RELAY_ONLY ? undefined : loadDatabase(dir, 'asset-hub-polkadot', log),
    };
});
if (pinnedNodes && pinnedNodes[relaySpec.id].length === 1 && !databases.some((d) => d.relay !== undefined)) {
    console.warn(
        `warning: ${relaySpec.id} is pinned to a single node and has no saved database yet; `
        + 'a cold warp sync through one pruned node is likely to stall. Bootstrap once with '
        + 'SMOLDOT_NODES=nodes-bootstrap.json (see README.md).',
    );
}

const allowedDialTargets = pinnedNodes
    && new Set(chainsInUse.flatMap((spec) => pinnedNodes[spec.id]).map(dialTargetOfMultiaddr));

// Node.js implements the raw TCP transport, and every `forbid*` option defaults to `false`, so
// the client already dials the `/tcp/` bootnodes alongside the `/ws/` and `/wss/` ones. Setting
// SMOLDOT_TCP_ONLY=1 rules the other transports out entirely, which is useful for checking that
// a deployment restricted to TCP can still reach the chain.
const tcpOnly = process.env.SMOLDOT_TCP_ONLY === '1';

// Compiled once and shared by every client of this process: the module is the same for all of
// them, and a `WebAssembly.Module` sent to a worker is shared, not copied.
const bytecode = compileBytecode();

// smoldot renders a log event as `<message>; key=value, key=value`. The event name is the part
// before the separator. A value can itself contain `, ` — a `Debug`-formatted error, say — so
// the tail is split on the `key=` boundaries rather than on the commas.
function logEventName(message) {
    const separator = message.indexOf('; ');
    return separator === -1 ? message : message.slice(0, separator);
}

function logFields(message) {
    const separator = message.indexOf('; ');
    if (separator === -1)
        return {};
    const tail = message.slice(separator + 2);
    const keys = [...tail.matchAll(/(?:^|, )([a-z_]+)=/g)];
    const fields = {};
    keys.forEach((match, index) => {
        const from = match.index + match[0].length;
        const to = index + 1 < keys.length ? keys[index + 1].index : tail.length;
        fields[match[1]] = tail.slice(from, to);
    });
    return fields;
}

// Every peer id begins `12D3KooW`, so a prefix alone doesn't identify one: keep both ends.
function shortPeerId(peerId) {
    return peerId && peerId.length > 20 ? `${peerId.slice(0, 12)}\u2026${peerId.slice(-5)}` : peerId;
}

// One line per notification, as `<kind> #<number>  <time seen>  <state root>`, both kinds padded
// to the same width so the columns line up in mixed output.
const LINE_KIND = { chain_finalizedHead: 'finalized', chain_allHead: 'imported ' };

async function startClient(index) {
    // In a multi-client process every line carries the client's index, in the same `[n] `
    // style run-instances.sh uses for its live output.
    const prefix = CLIENTS === 1 ? '' : `[${index}] `;
    const log = (line) => console.log(prefix + line);
    const dbDir = databaseDirOf(index);

    // The Wasm runs on a worker thread, so that clients don't compete for one event loop and
    // each one's `cpuRateLimit` means what it says. This thread keeps JSON-RPC and logging —
    // and the connections: even with a worker, smoldot opens them on this side of the port,
    // which is also where `connectionFilter` runs.
    const { port1, port2 } = new MessageChannel();
    const worker = new Worker(new URL('./worker.mjs', import.meta.url));
    worker.on('error', (error) => log(`worker error: ${error.stack ?? error.message}`));
    worker.postMessage(port2, [port2]);

    const refusedDials = new Map();   // dial target -> number of refusals

    // The local peer id is generated per connection -- one fresh Noise key per dial -- so there
    // is no such thing as "this client's peer id", and nothing in the JSON-RPC API exposes it.
    // `connection-started` is the only place it ever appears. It is remembered against the
    // address and printed once that dial completes a handshake, because `connection-started`
    // also fires for every dial the pin refuses, which is the overwhelming majority of them.
    const localPeerIds = new Map();   // remote multiaddr -> local peer id offered on that dial

    // `connectionFilter` turns away most dials, and each refusal reaches smoldot as a connection
    // reset: one `connection-shutdown` and one `slot-unassigned` per refused address, thousands
    // of them over a run. Those are this client's own doing and are already summarised by
    // `pinning: refused N dials`, so they are dropped here instead of burying the events that
    // describe the nodes it is actually pinned to.
    const refusedPeers = new Set();   // peer ids whose dial the filter turned away

    function dialWasRefused(multiaddr) {
        if (!allowedDialTargets || !multiaddr)
            return false;
        try {
            return !allowedDialTargets.has(dialTargetOfMultiaddr(multiaddr));
        } catch (_) {
            return false;   // Not a shape the filter understands either; show the event.
        }
    }

    // smoldot records neither a reason nor an initiator for a connection ending:
    // `connection-shutdown` says only whether the handshake had completed. What does carry a
    // cause is the `slot-unassigned` that follows it, and above all that event's `user_reason`,
    // which is set when this client's own sync or runtime service asked for the ban -- the
    // difference between "the peer went away" and "we dropped it, for this".
    //
    // Note that `slot-unassigned`'s own `reason` is not trustworthy for telling those apart:
    // the `pre-handshake-disconnect` path emits that string without checking whether the
    // handshake had in fact finished (there is a TODO to that effect in network_service.rs).
    // The preceding `connection-shutdown` is the reliable signal.
    function onNetworkEvent(message) {
        const fields = logFields(message);
        const peer = shortPeerId(fields.peer_id);

        switch (logEventName(message)) {
            case 'connection-started':
                if (dialWasRefused(fields.remote_addr)) {
                    if (refusedPeers.size > 512)
                        refusedPeers.clear();
                    refusedPeers.add(fields.expected_peer_id);
                    break;
                }
                // Entries are dropped on handshake or shutdown, and a refused dial gets a
                // shutdown too; the cap only guards a leak that has not been observed.
                if (localPeerIds.size > 512)
                    localPeerIds.clear();
                localPeerIds.set(fields.remote_addr, fields.local_peer_id);
                break;

            case 'handshake-finished': {
                const local = localPeerIds.get(fields.remote_addr);
                localPeerIds.delete(fields.remote_addr);
                log(`net: connected to ${peer} at ${fields.remote_addr}`
                    + (local ? `, presenting ${shortPeerId(local)}` : ''));
                break;
            }

            case 'handshake-finished-peer-id-mismatch':
                localPeerIds.delete(fields.remote_addr);
                log(`net: identity mismatch at ${fields.remote_addr}: expected `
                    + `${shortPeerId(fields.expected_peer_id)}, got ${shortPeerId(fields.actual_peer_id)}`);
                break;

            case 'connection-shutdown':
                localPeerIds.delete(fields.address);
                if (refusedPeers.has(fields.peer_id) || dialWasRefused(fields.address))
                    break;
                log(`net: disconnected from ${peer} at ${fields.address} `
                    + (fields.handshake_finished === 'true'
                        ? '(the connection had been established; smoldot does not record which side closed it)'
                        : '(during the handshake)'));
                break;

            case 'slot-unassigned':
                // `delete` both suppresses the event and forgets the peer: this is the last one
                // a refused dial produces.
                if (refusedPeers.delete(fields.peer_id))
                    break;
                log(`net: dropped ${peer} from ${fields.chain}, banned ${fields.ban_duration} -- `
                    + (fields.user_reason
                        ? `this client banned it: ${fields.user_reason}`
                        : fields.reason));
                break;

            // A peer that is connected but never opens this substream is not a peer of the
            // chain at all: it serves nothing and the chain sits at 0 peers while looking
            // connected. A node whose light-peer slots are full refuses here.
            case 'gossip-open-error':
                log(`net: ${fields.chain}: ${peer} would not open the block-announces substream: ${fields.error}`);
                break;

            case 'gossip-open-success':
                log(`net: ${fields.chain}: ${peer} is now serving the chain, at #${fields.best_number}`);
                break;

            case 'gossip-closed':
                log(`net: ${fields.chain}: ${peer} stopped serving the chain`);
                break;

            default:
                break;
        }
    }

    const client = startWithBytecode({
        bytecode,
        portToWorker: port1,
        // Level 4 when connection diagnostics are wanted, so that the `network` target's debug
        // events reach the callback at all; what is actually printed is decided there.
        maxLogLevel: NET_LOG ? Math.max(LOG_LEVEL, 4) : LOG_LEVEL,
        cpuRateLimit: 0.5,
        forbidWs: tcpOnly,
        forbidWss: tcpOnly,
        forbidWebRtc: tcpOnly,
        // Anything within the requested level is printed as smoldot wrote it; above it, only
        // the connection events, rephrased. Raising SMOLDOT_LOG_LEVEL to 4 therefore replaces
        // the rephrased lines with the raw ones rather than printing both.
        logCallback: (level, target, message) => {
            if (level <= LOG_LEVEL)
                log(`[${target}] ${message}`);
            else if (NET_LOG && target === 'network')
                onNetworkEvent(message);
        },
        // Refusals cost nothing: no socket is opened, smoldot is simply told the connection was
        // reset, bans that peer for a couple of seconds and moves on to the next candidate.
        connectionFilter: allowedDialTargets && ((address) => {
            const target = dialTargetOfAddress(address);
            if (allowedDialTargets.has(target))
                return true;
            refusedDials.set(target, (refusedDials.get(target) ?? 0) + 1);
            return false;
        }),
    });

    // The relay chain keeps its JSON-RPC system enabled at least for reading its database back
    // out; `chainHead_unstable_finalizedDatabase` is a JSON-RPC function like any other, and
    // `disableJsonRpc: true` would make it unreachable. It gets subscriptions only when it is
    // the chain being reported on.
    const relayChain = await client.addChain({
        chainSpec: JSON.stringify(relaySpec),
        databaseContent: databases[index - 1].relay,
        jsonRpcMaxSubscriptions: RELAY_ONLY ? 4 : 0,
        jsonRpcMaxPendingRequests: 4,
    });

    const assetHub = RELAY_ONLY ? undefined : await client.addChain({
        chainSpec: JSON.stringify(assetHubSpec),
        databaseContent: databases[index - 1].assetHub,
        potentialRelayChains: [relayChain],
        // Two head subscriptions, `lifecycle_unstable_follow`, and the `chainHead_v1_follow` the
        // contract reads need -- with room to re-follow before the old one is dropped.
        jsonRpcMaxSubscriptions: 8,
    });

    const startedAt = Date.now();
    let blocksReported = 0;   // Of either kind. The first one means the chain is being followed.

    let lastLifecycle = '';
    let reviveReads;   // Set below, once the chain has a JSON-RPC router to talk through.
    const onNotification = (message) => {
        // `chainHead_v1_follow` reports everything -- new blocks and the results of every storage
        // operation -- on one subscription, so the reader has to be offered each notification
        // before anything else looks at it.
        if (reviveReads?.onNotification(message))
            return;

        if (message.method === 'lifecycle_unstable_followEvent') {
            const state = message.params?.result;
            if (!state) return;
            const peers = state.numPeers ?? state.num_peers ?? 0;
            const phase = state.phase?.kind === 'syncing'
                ? `syncing #${state.phase.at} -> #${state.phase.target}`
                : (state.phase?.kind ?? 'unknown');
            const stall = state.health?.kind === 'stalled'
                ? (state.health.reason === 'noPeers'
                    ? ' — STALLED: no peer has served this chain for 30s (either the client is rebuilding its subscription after a large finality jump — self-healing, ~45s, see README; or no node is serving it: unreachable, or the block-announces substream was refused because its light-peer slots are full)'
                    : ' — STALLED: warp sync has not advanced for 45s')
                : '';
            const line = `lifecycle: ${phase}, ${peers} peer${peers === 1 ? '' : 's'}${stall}`;
            if (line !== lastLifecycle) {
                lastLifecycle = line;
                log(line);
            }
            return;
        }

        const header = message.params?.result;
        const kind = LINE_KIND[message.method];
        if (!kind || !header)
            return;

        blocksReported += 1;
        if (blocksReported === 1) {
            const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
            log(`${reportedSpec.name} is following the chain after ${elapsed}s.`);
        }
        // The wall-clock time at which *this* client saw the block, not the block's own timestamp:
        // the header carries no timestamp (it is `Timestamp::Now` in the block's storage), and the
        // legacy head subscriptions do not report the block hash needed to read it. Comparing this
        // across instances is what shows which one is lagging.
        log(`${kind} #${parseInt(header.number, 16)}  ${new Date().toISOString()}  ${header.stateRoot}`);
    };

    // One router per chain: a chain's responses can only be read by one loop.
    const relayRequest = jsonRpcRouter(relayChain, RELAY_ONLY ? onNotification : undefined);
    const assetHubRequest = assetHub && jsonRpcRouter(assetHub, onNotification);
    const reportedRequest = RELAY_ONLY ? relayRequest : assetHubRequest;

    if (REPORT !== 'imported')
        await reportedRequest('chain_subscribeFinalizedHeads');
    if (REPORT !== 'finalized')
        await reportedRequest('chain_subscribeAllHeads');
    // The chain's lifecycle: connecting / syncing / ready, how many peers are actually serving
    // it, and smoldot's own stall verdict. This is what tells a stuck start apart from a slow
    // one: a client whose block-announces substream the pinned node refused (its light-peer
    // slots being full) keeps its connection and its discovery traffic, but shows 0 peers here
    // and never leaves `connecting`.
    //
    // `lifecycle_unstable_follow` is recent (September 2026). A client running Wasm built before
    // that answers "method does not exist"; the same signal is then taken from `system_health`,
    // polled every 10 s, with the 30 s no-peer verdict computed here.
    let healthPoll;
    try {
        await reportedRequest('lifecycle_unstable_follow');
    } catch (error) {
        if (!/does not exist|not available/i.test(error.message))
            throw error;
        let lastHealth = '';
        let peerlessSince = Date.now();
        healthPoll = setInterval(async () => {
            let health;
            try {
                health = await reportedRequest('system_health');
            } catch (_) {
                return;   // Shutting down.
            }
            if (health.peers > 0)
                peerlessSince = Date.now();
            const stalled = health.peers === 0 && Date.now() - peerlessSince >= 30_000;
            const line = `lifecycle (system_health): ${health.peers} peer${health.peers === 1 ? '' : 's'}, `
                + (health.isSyncing ? 'syncing' : 'in sync')
                + (stalled ? ' — STALLED: no peer has served this chain for 30s (either the client is rebuilding its subscription after a large finality jump — self-healing, ~45s, see README; or no node is serving it: unreachable, or the block-announces substream was refused because its light-peer slots are full)' : '');
            if (line !== lastHealth) {
                lastHealth = line;
                log(line);
            }
        }, 10_000);
    }

    // The reader opens its own `chainHead_v1_follow` straight away and skips its ticks until
    // that subscription reports a finalized block, so starting it here rather than waiting for
    // the chain costs nothing and keeps startup in one place.
    if (queryConfig && assetHubRequest) {
        reviveReads = startReviveReads({
            request: assetHubRequest,
            log,
            config: queryConfig,
            options: {
                intervalMs: QUERY_INTERVAL_MS,
                jitter: QUERY_JITTER,
                keyCount: QUERY_KEYS,
                batch: QUERY_BATCH === 'batched',
            },
        });
        const keys = QUERY_KEYS ?? queryConfig.keys.length;
        log(`revive: reading ${keys} key${keys === 1 ? '' : 's'} of ${queryConfig.contract} `
            + `every ${QUERY_INTERVAL_MS / 1000}s (${QUERY_BATCH}`
            + `${QUERY_JITTER ? ', jittered' : ''})`);
    }

    async function saveOne(name, request) {
        try {
            const content = await withDeadline(
                request('chainHead_unstable_finalizedDatabase', [MAX_DB_BYTES]),
                SAVE_DEADLINE_MS,
                `${name} database`,
            );
            // `<too-large>` is what smoldot returns when it could not shrink the database enough to
            // fit. Storing it would mean silently starting from scratch on the next run.
            if (content === '<too-large>' || content === '')
                throw new Error(`did not fit in ${MAX_DB_BYTES} bytes`);
            // See the note above `loadDatabase`: a database without the runtime code would stall
            // the next start, so it must not replace the one on disk.
            if (!databaseHasRuntime(content)) {
                log(`not saving ${name} database: smoldot has no known runtime right now, the database would lack the runtime code`);
                return;
            }
            saveDatabase(dbDir, name, content);
            log(`saved database: ${name} (${(content.length / 1024).toFixed(0)} kiB)`);
        } catch (error) {
            log(`failed to save ${name} database: ${error.message}`);
        }
    }

    // Both databases are worth keeping. The relay chain's is what lets warp sync resume from the
    // last finalized block instead of the chain spec's checkpoint; Asset Hub's saves re-downloading
    // its runtime and rediscovering its collators.
    let saveInFlight = false;
    async function persistDatabases(reason) {
        if (blocksReported === 0) {
            log(`not saving databases (${reason}): the chain is not following yet`);
            return;
        }
        // Requests count against `jsonRpcMaxPendingRequests` until they are answered, so never let
        // a slow save pile up behind the previous one.
        if (saveInFlight)
            return;

        saveInFlight = true;
        try {
            const saves = [saveOne('polkadot', relayRequest)];
            if (assetHubRequest)
                saves.push(saveOne('asset-hub-polkadot', assetHubRequest));
            await Promise.all(saves);
        } finally {
            saveInFlight = false;
        }
    }

    // Evidence that the pin is doing its job: discovery hands smoldot other nodes to try, and each
    // attempt ends up here instead of on the network.
    function reportRefusedDials() {
        if (refusedDials.size === 0)
            return;
        const total = [...refusedDials.values()].reduce((sum, count) => sum + count, 0);
        log(`pinning: refused ${total} dials to ${refusedDials.size} other addresses`);
    }

    // How many peers are actually serving each chain, and which. `system_peers` is a plain
    // request, so it works on the relay chain even when that chain is added with no
    // subscriptions at all -- which is the case whenever the parachain is the one being
    // reported on. That configuration is precisely where the relay chain is otherwise
    // invisible, while still being the chain that has to finalize before the parachain can.
    //
    // The count is peers with an open block-announces substream for that chain, not open
    // connections: a chain can sit at 0 here while the connection to the pinned node is up.
    async function reportPeers() {
        const chains = [['polkadot', relayRequest]];
        if (assetHubRequest)
            chains.push(['asset-hub-polkadot', assetHubRequest]);

        const parts = await Promise.all(chains.map(async ([name, request]) => {
            let peers;
            try {
                // A deadline, because a chain that has wedged is exactly when this line matters
                // most: without one the request never settles and nothing is printed at all,
                // which is indistinguishable from the timer not running.
                peers = await withDeadline(request('system_peers'), 5_000, `${name} system_peers`);
            } catch (error) {
                return `${name} unknown (${error.message})`;
            }
            if (!Array.isArray(peers) || peers.length === 0)
                return `${name} 0 peers`;
            const who = peers
                .map((entry) => `${shortPeerId(entry.peerId)} ${String(entry.roles).toLowerCase()} #${entry.bestNumber}`)
                .join('; ');
            return `${name} ${peers.length} peer${peers.length === 1 ? '' : 's'} (${who})`;
        }));
        log(`peers: ${parts.join(', ')}`);
    }

    return {
        persistDatabases,
        reportRefusedDials,
        reportPeers,

        // The window's failure rate and percentiles, on the same timer as the other periodic
        // reports. Undefined until the first read set has been attempted.
        reportReads() {
            const line = reviveReads?.summary();
            if (line)
                log(line);
        },

        async terminate() {
            if (healthPoll)
                clearInterval(healthPoll);
            reviveReads?.stop();
            await client.terminate();
            await worker.terminate();
        },
    };
}

const clients = await Promise.all(Array.from({ length: CLIENTS }, (_, i) => startClient(i + 1)));

const saveTimer = setInterval(() => {
    for (const client of clients) {
        client.persistDatabases('periodic');
        client.reportRefusedDials();
        client.reportPeers();
        client.reportReads();
    }
    // Resident set of the whole process, worker threads included — the number that answers
    // "what does running N clients in one process cost".
    console.log(`memory: rss ${(process.memoryUsage().rss / 1048576).toFixed(0)} MiB for ${CLIENTS} client${CLIENTS === 1 ? '' : 's'}`);
}, SAVE_INTERVAL_MS);

let shuttingDown = false;
process.on('SIGINT', async () => {
    if (shuttingDown) process.exit(1);   // A second Ctrl+C gives up on saving.
    shuttingDown = true;
    console.log('\nSaving databases before exit...');
    clearInterval(saveTimer);
    await Promise.all(clients.map((client) => client.persistDatabases('exit')));
    for (const client of clients)
        client.reportRefusedDials();
    await Promise.all(clients.map((client) => client.terminate()));
    process.exit(0);
});

// See `SMOLDOT_MAX_LIFETIME_MS`. Raising SIGINT rather than exiting directly is the point: the
// handler above is what saves the databases, and a process that goes without saving hands the
// next start an older one, which is precisely what makes a restart expensive.
if (MAX_LIFETIME_MS !== undefined) {
    console.log(`lifetime: exiting after ${(MAX_LIFETIME_MS / 1000).toFixed(0)}s so that the supervisor starts a fresh process`);
    setTimeout(() => {
        console.log(`lifetime: ${(MAX_LIFETIME_MS / 1000).toFixed(0)}s reached`);
        process.kill(process.pid, 'SIGINT');
    }, MAX_LIFETIME_MS).unref();
}
