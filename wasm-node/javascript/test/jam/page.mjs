// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// In-page driver for the JAM browser end-to-end test. Served at /jam/page.mjs
// and imported by page.html; e2e.mjs drives it through `window.__jam`.
//
// The driver owns the smoldot clients, the per-chain JSON-RPC plumbing and the
// bounded event/log journals that the Node side asserts on. It performs no
// assertions itself and never reads node logs.

const MAX_LOGS = 20000;
const MAX_EVENTS = 20000;
const MAX_MESSAGE_CHARS = 400;

const clients = new Map();

function clientState(name) {
    const state = clients.get(name);
    if (!state) throw new Error(`unknown smoldot client: ${name}`);
    return state;
}

function chainState(clientName, chainName) {
    const state = clientState(clientName).chains.get(chainName);
    if (!state) throw new Error(`unknown chain: ${clientName}/${chainName}`);
    return state;
}

function pushBounded(entries, entry) {
    entries.push(entry);
    if (entries.length > MAX_EVENTS) entries.splice(0, entries.length - MAX_EVENTS);
}

/** Starts a smoldot client and begins capturing its log callback. */
function startClient(name, options = {}) {
    if (clients.has(name)) throw new Error(`smoldot client already started: ${name}`);
    const state = { client: undefined, logs: [], chains: new Map() };
    state.client = window.__smoldot.start({
        maxLogLevel: options.maxLogLevel ?? 4,
        cpuRateLimit: options.cpuRateLimit ?? 1,
        logCallback: (level, target, message) => {
            state.logs.push({
                t: Date.now(),
                level,
                target: String(target),
                message: String(message).slice(0, MAX_MESSAGE_CHARS),
            });
            if (state.logs.length > MAX_LOGS) state.logs.splice(0, state.logs.length - MAX_LOGS);
        },
    });
    clients.set(name, state);
    return { name };
}

/** Consumes a chain's JSON-RPC response stream until the chain is removed. */
async function consume(clientName, chainName) {
    const state = chainState(clientName, chainName);
    try {
        for await (const text of state.chain.jsonRpcResponses) {
            const message = JSON.parse(text);
            if (message.id !== undefined && state.pending.has(message.id)) {
                const pending = state.pending.get(message.id);
                state.pending.delete(message.id);
                clearTimeout(pending.timer);
                if (message.error) pending.reject(new Error(JSON.stringify(message.error)));
                else pending.resolve(message.result);
            } else if (message.method === 'chainHead_v1_followEvent') {
                pushBounded(state.events, {
                    t: Date.now(),
                    subscription: message.params.subscription,
                    ...message.params.result,
                });
            }
        }
        pushBounded(state.events, { t: Date.now(), event: 'driver-stream-ended' });
    } catch (error) {
        pushBounded(state.events, { t: Date.now(), event: 'driver-error', message: String(error) });
    }
}

async function addChain(clientName, chainName, chainSpec) {
    const client = clientState(clientName);
    const chain = await client.client.addChain({ chainSpec });
    const state = {
        chain,
        events: [],
        pending: new Map(),
        nextId: 0,
    };
    client.chains.set(chainName, state);
    void consume(clientName, chainName);
    return { chainName };
}

function rpc(clientName, chainName, method, params, timeoutMs = 30000) {
    const state = chainState(clientName, chainName);
    return new Promise((resolve, reject) => {
        const id = ++state.nextId;
        const timer = setTimeout(() => {
            state.pending.delete(id);
            reject(new Error(`${method} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
        state.pending.set(id, { resolve, reject, timer });
        try {
            state.chain.sendJsonRpc(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
        } catch (error) {
            clearTimeout(timer);
            state.pending.delete(id);
            reject(error);
        }
    });
}

/** Returns follow events with index >= `since`. */
function events(clientName, chainName, since = 0) {
    const state = chainState(clientName, chainName);
    return { total: state.events.length, entries: state.events.slice(since) };
}

/** Returns captured client logs with index >= `since`. */
function logs(clientName, since = 0) {
    const state = clientState(clientName);
    return { total: state.logs.length, entries: state.logs.slice(since) };
}

async function terminateClient(name) {
    const state = clients.get(name);
    if (!state) return;
    clients.delete(name);
    await state.client.terminate();
}

window.__jam = {
    startClient,
    addChain,
    rpc,
    events,
    logs,
    terminateClient,
    webTransportSupported: () => typeof WebTransport === 'function',
};