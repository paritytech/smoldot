// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

const field = id => document.getElementById(id);
const DEV_BOOTNODE = 'p256:oqov2a57d7etnpzb6aerv64y5j622ejkkvqjencdrwln4qhnoqvqb@127.0.0.1:40000';
const MAX_PINS = 16;
const MAX_PENDING = 32;
const MAX_HEADER_CHARS = 2 * 1024 * 1024;
const MAX_SPEC_BYTES = 16 * 1024 * 1024;
const entries = { events: [], logs: [] };
let current;
let stopping = false;

function print(panel, text) {
    const lines = entries[panel];
    const value = String(text);
    lines.push(new Date().toISOString() + ' ' + value.slice(0, 4096) + (value.length > 4096 ? ' [truncated]' : ''));
    if (lines.length > 100) lines.shift();
    field(panel).textContent = lines.join('\n');
}

function controls() {
    const following = current?.subscription !== undefined && !current?.unfollowing;
    const pinned = following && current.pins.has(current.latest);
    field('start').disabled = !!current || stopping;
    field('stop').disabled = !current;
    field('header').disabled = !pinned || current.headerBusy;
    field('unpin').disabled = !pinned || current.headerBusy || current.unpinBusy;
    field('unfollow').disabled = !following;
}

function rpc(run, method, params) {
    if (current !== run) return Promise.reject(new Error('Stopped'));
    if (run.pending.size >= MAX_PENDING) return Promise.reject(new Error('Pending RPC limit reached; stop and restart'));
    return new Promise((resolve, reject) => {
        const id = ++run.id;
        const timer = setTimeout(() => {
            run.pending.delete(id);
            reject(new Error(method + ' timed out'));
        }, 15000);
        run.pending.set(id, { resolve, reject, timer });
        try {
            run.chain.sendJsonRpc(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
        } catch (error) {
            clearTimeout(timer);
            run.pending.delete(id);
            reject(error);
        }
    });
}

async function stop() {
    const run = current;
    if (!run) return;
    stopping = true;
    current = undefined;
    run.abort.abort();
    for (const request of run.pending.values()) {
        clearTimeout(request.timer);
        request.reject(new Error('Stopped'));
    }
    run.pending.clear();
    run.pins.clear();
    // Keep Start disabled until this client's teardown is complete.
    field('stop').disabled = true;
    field('header').disabled = true;
    field('unpin').disabled = true;
    field('unfollow').disabled = true;
    field('status').textContent = 'Stopping';
    try {
        try { run.chain?.remove(); }
        finally { await run.client?.terminate(); }
    } catch (error) {
        print('logs', 'Cleanup: ' + error);
    }
    field('status').textContent = 'Stopped';
    stopping = false;
    controls();
}

function fail(run, error) {
    if (current !== run) return;
    print('logs', 'Error: ' + error);
    void stop();
}

async function header(run = current) {
    if (!run || run.headerBusy || run.unfollowing || !run.pins.has(run.latest)) return;
    const hash = run.latest;
    run.headerBusy = true;
    controls();
    try {
        const hex = await rpc(run, 'chainHead_v1_header', [run.subscription, hash]);
        if (current !== run || run.unfollowing) return;
        if (hex !== null && (typeof hex !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(hex)))
            throw new Error('Header response is not hexadecimal bytes');
        if (hex?.length > MAX_HEADER_CHARS) throw new Error('Header exceeds demo display limit');
        field('header-output').textContent = hash + '\n' + (hex ?? 'null (header unavailable)');
    } catch (error) {
        fail(run, error);
    } finally {
        run.headerBusy = false;
        controls();
        // Coalesce arrivals while one header request is outstanding.
        if (current === run && run.latest !== hash) void header(run);
    }
}

async function unpin(run, hashes) {
    // A submitted unpin makes the hash unavailable immediately, not at its reply.
    for (const hash of hashes) run.pins.delete(hash);
    controls();
    await rpc(run, 'chainHead_v1_unpin', [run.subscription, hashes]);
    if (current !== run) return;
    controls();
}

function event(run, value) {
    if (value.event === 'stop') {
        print('logs', 'Subscription stopped by client; restart to follow again.');
        void stop();
        return;
    }
    if (value.event === 'finalized') {
        fail(run, new Error('Unexpected live finalized event: C1 promises trusted anchor only'));
        return;
    }
    const hashes = value.event === 'initialized' ? value.finalizedBlockHashes :
        value.event === 'newBlock' ? [value.blockHash] : [];
    for (const hash of hashes ?? []) run.pins.add(hash);
    if (value.event === 'newBlock') {
        run.latest = value.blockHash;
        void header(run);
    }
    if (run.pins.size > MAX_PINS) {
        const old = [...run.pins].slice(0, run.pins.size - MAX_PINS);
        void unpin(run, old).catch(error => fail(run, error));
    }
    controls();
}

async function responses(run) {
    try {
        for await (const text of run.chain.jsonRpcResponses) {
            if (current !== run) return;
            print('events', text);
            const message = JSON.parse(text);
            const request = run.pending.get(message.id);
            if (request) {
                clearTimeout(request.timer);
                run.pending.delete(message.id);
                if (message.error) request.reject(new Error(JSON.stringify(message.error)));
                else request.resolve(message.result);
            } else if (message.method === 'chainHead_v1_followEvent' &&
                message.params?.subscription === run.subscription && !run.unfollowing) {
                event(run, message.params.result);
            }
        }
        if (current === run) throw new Error('JSON-RPC response stream ended');
    } catch (error) { fail(run, error); }
}

async function start() {
    if (current || field('start').disabled) return;
    const run = { abort: new AbortController(), pending: new Map(), pins: new Set(), id: 0 };
    current = run;
    for (const panel of ['events', 'logs']) {
        entries[panel].length = 0;
        field(panel).textContent = '';
    }
    field('header-output').textContent = 'No header requested.';
    field('status').textContent = 'Loading spec and WASM';
    controls();
    const file = field('spec-file').files[0];
    const url = field('spec-url').value.trim();
    const devBootnode = field('dev-bootnode').checked;
    try {
        let text;
        if (file) {
            if (file.size > MAX_SPEC_BYTES) throw new Error('Spec exceeds 16 MiB');
            text = await file.text();
        } else {
            const response = await fetch(url, { signal: run.abort.signal });
            if (!response.ok) throw new Error('Spec HTTP ' + response.status);
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let size = 0;
            text = '';
            try {
                while (true) {
                    const chunk = await reader.read();
                    if (chunk.done) break;
                    size += chunk.value.length;
                    if (size > MAX_SPEC_BYTES) throw new Error('Spec exceeds 16 MiB');
                    text += decoder.decode(chunk.value, { stream: true });
                }
                text += decoder.decode();
            } finally { await reader.cancel(); }
        }
        if (current !== run) return;
        const spec = JSON.parse(text);
        if (!spec || typeof spec !== 'object' || Array.isArray(spec)) throw new Error('Expected a JSON spec object');
        if (devBootnode) {
            if (spec.bootnodes !== undefined && !Array.isArray(spec.bootnodes)) throw new Error('bootnodes must be an array');
            spec.bootnodes ??= [];
            if (!spec.bootnodes.includes(DEV_BOOTNODE)) spec.bootnodes.push(DEV_BOOTNODE);
            print('logs', 'Opted in to public local dev bootnode: ' + DEV_BOOTNODE);
        }
        const smoldot = await import('../dist/mjs/index-browser.js');
        if (current !== run) return;
        run.client = smoldot.start({
            maxLogLevel: 4,
            cpuRateLimit: 0.5,
            logCallback: (_level, target, message) => {
                if (current === run) print('logs', '[' + target + '] ' + message);
            },
        });
        run.chain = await run.client.addChain({ chainSpec: JSON.stringify(spec) });
        if (current !== run) return;
        void responses(run);
        run.subscription = await rpc(run, 'chainHead_v1_follow', [false]);
        if (current !== run) return;
        field('status').textContent = 'Following (withRuntime: false) - trusted anchor only, no live finality';
        controls();
    } catch (error) { fail(run, error); }
}

async function unfollow() {
    const run = current;
    if (run?.subscription === undefined || run.unfollowing) return;
    run.unfollowing = true;
    controls();
    try {
        await rpc(run, 'chainHead_v1_unfollow', [run.subscription]);
        if (current !== run) return;
        run.subscription = undefined;
        run.pins.clear();
        run.latest = undefined;
        field('status').textContent = 'Unfollowed. Stop removes the chain and terminates WASM; Start can then follow again.';
        controls();
    } catch (error) { fail(run, error); }
}

field('start').onclick = start;
field('stop').onclick = stop;
field('header').onclick = () => { void header(); };
field('unpin').onclick = () => {
    const run = current;
    if (!run?.pins.has(run.latest) || run.unpinBusy) return;
    run.unpinBusy = true;
    controls();
    void unpin(run, [run.latest]).catch(error => fail(run, error)).finally(() => {
        run.unpinBusy = false;
        controls();
    });
};
field('unfollow').onclick = unfollow;
window.jamDemo = {
    start, stop, header, unfollow,
    snapshot: () => ({
        running: !!current,
        subscription: current?.subscription,
        latestNewBlock: current?.latest,
        pins: [...(current?.pins ?? [])],
        pending: current?.pending.size ?? 0,
        events: [...entries.events],
        logs: [...entries.logs],
    }),
};
