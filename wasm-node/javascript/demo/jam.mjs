// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

const field = id => document.getElementById(id);
const MAX_PINS = 16;
const MAX_PENDING = 32;
const MAX_HEADER_CHARS = 2 * 1024 * 1024;
const MAX_SPEC_BYTES = 16 * 1024 * 1024;
const MAX_TRACKED_BLOCKS = 256;
/** How many blocks the explorer list keeps. Older rows are dropped. */
const MAX_BLOCK_ROWS = 20;
const CONTROL_URL = '/jam-demo/control';
const POLL_MS = 2000;
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
    renderLive();
    try {
        try { run.chain?.remove(); }
        finally { await run.client?.terminate(); }
    } catch (error) {
        print('logs', 'Cleanup: ' + error);
    }
    field('status').textContent = 'Stopped';
    stopping = false;
    controls();
    renderLive();
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
        describeHeader(run, hash, hex);
    } catch (error) {
        fail(run, error);
    } finally {
        run.headerBusy = false;
        controls();
        // Coalesce arrivals while one header request is outstanding.
        if (current === run && run.latest !== hash) void header(run);
    }
}

// --------------------------------------------------------------------------
// Explorer list: the last MAX_BLOCK_ROWS blocks, newest first.
//
// Every `newBlock` gets one row immediately (hash, parent, arrival time) and is
// queued for its header, which fills in slot, epoch, author and marks. Rows
// whose header could not be fetched say so; they are never filled with guesses.
// This is display only, exactly like the decoder it uses: a failed row is
// recorded in the row, not turned into a session error.
// --------------------------------------------------------------------------

function addRow(run, hash, parent) {
    run.rows.unshift({ hash, parent, at: Date.now(), finality: 'Unfinalized' });
    run.rows.length = Math.min(run.rows.length, MAX_BLOCK_ROWS);
    run.headerQueue.push(hash);
    // A catch-up burst must not build an unbounded backlog; rows that fall off
    // the list are not worth a request any more.
    if (run.headerQueue.length > MAX_BLOCK_ROWS) run.headerQueue.splice(0, run.headerQueue.length - MAX_BLOCK_ROWS);
}

async function pumpHeaders(run) {
    if (run.headerPumpBusy) return;
    run.headerPumpBusy = true;
    try {
        while (current === run && !run.unfollowing && run.headerQueue.length > 0) {
            const hash = run.headerQueue.shift();
            const row = run.rows.find(entry => entry.hash === hash);
            if (!row || row.hex !== undefined || row.note !== undefined) continue;
            if (!run.pins.has(hash)) {
                row.note = 'unpinned before its header was fetched';
                continue;
            }
            try {
                const hex = await rpc(run, 'chainHead_v1_header', [run.subscription, hash]);
                if (current !== run) return;
                if (typeof hex !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(hex)) {
                    row.note = hex === null ? 'header unavailable' : 'header is not hexadecimal bytes';
                } else {
                    row.hex = hex;
                    row.decoded = run.params ? decodeRow(hex, run.params) : { error: 'spec parameters unreadable' };
                    // Keep the existing panel behaviour: the latest new block's
                    // header is shown without pressing anything.
                    if (hash === run.latest) {
                        field('header-output').textContent = hash + '\n' + hex;
                        describeHeader(run, hash, hex);
                    }
                }
            } catch (error) {
                row.note = String(error && (error.message || error));
            }
            renderLive();
        }
    } finally {
        run.headerPumpBusy = false;
        if (current === run) renderLive();
    }
}

function decodeRow(hex, params) {
    try {
        return decodeHeaderForDisplay(hexToBytes(hex), params);
    } catch (error) {
        return { error: String(error && (error.message || error)) };
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
    run.lastEventAt = Date.now();
    const hashes = value.event === 'initialized' ? value.finalizedBlockHashes :
        value.event === 'newBlock' ? [value.blockHash] : [];
    for (const hash of hashes ?? []) run.pins.add(hash);
    if (value.event === 'initialized') {
        for (const hash of value.finalizedBlockHashes ?? []) trackBlock(run, hash, null);
        // The events panel keeps only the last 100 entries, and a catch-up
        // burst can push `initialized` out of it within a second; record it.
        run.initialized = { anchors: [...(value.finalizedBlockHashes ?? [])], at: Date.now() };
        run.finalized = { hash: run.initialized.anchors.at(-1), source: 'anchor' };
    }
    if (value.event === 'finalized') {
        // Only the client's follow stream can advance this view. Node RPC
        // reports and slot comparisons must never change client finality.
        const finalized = new Set(value.finalizedBlockHashes ?? []);
        const pruned = new Set(value.prunedBlockHashes ?? []);
        for (const row of run.rows) {
            if (finalized.has(row.hash)) row.finality = 'Finalized';
            else if (pruned.has(row.hash)) row.finality = 'Pruned';
        }
        for (const hash of pruned) run.blocks.delete(hash);
        const hash = value.finalizedBlockHashes?.at(-1);
        if (hash) {
            const decoded = run.rows.find(row => row.hash === hash)?.decoded;
            run.finalized = { hash, source: 'follow', slot: decoded?.slot };
            run.finalityCount += 1;
            run.lastFinalityAt = Date.now();
        }
    }
    if (value.event === 'newBlock') {
        run.latest = value.blockHash;
        run.blockCount += 1;
        trackBlock(run, value.blockHash, value.parentBlockHash ?? null);
        addRow(run, value.blockHash, value.parentBlockHash ?? null);
        // The explorer list fetches this block's header; when it is still the
        // latest on arrival it also refreshes the header panel, so each block
        // still costs exactly one `chainHead_v1_header` call.
        void pumpHeaders(run);
    }
    if (value.event === 'bestBlockChanged') run.best = value.bestBlockHash;
    if (run.pins.size > MAX_PINS) {
        const old = [...run.pins].slice(0, run.pins.size - MAX_PINS);
        void unpin(run, old).catch(error => fail(run, error));
    }
    controls();
    renderLive();
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
    const run = {
        abort: new AbortController(), pending: new Map(), pins: new Set(), id: 0,
        blockCount: 0, blocks: new Map(), bootnodes: [], startedAt: Date.now(),
        rows: [], headerQueue: [], finalityCount: 0,
    };
    current = run;
    for (const panel of ['events', 'logs']) {
        entries[panel].length = 0;
        field(panel).textContent = '';
    }
    field('header-output').textContent = 'No header requested.';
    field('status').textContent = 'Loading spec and WASM';
    controls();
    renderLive();
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
            // The address is deliberately not written down here: it comes from
            // the harness that started the network, which formats it in exactly
            // one place (test/jam/network.mjs `formatBootnode`).
            const status = await controlRequest('status');
            if (current !== run) return;
            const bootnode = status?.bootnode;
            if (typeof bootnode !== 'string' || bootnode.length === 0)
                throw new Error('The demo harness did not report a bootnode address');
            if (spec.bootnodes !== undefined && !Array.isArray(spec.bootnodes)) throw new Error('bootnodes must be an array');
            spec.bootnodes ??= [];
            if (!spec.bootnodes.includes(bootnode)) spec.bootnodes.push(bootnode);
            print('logs', "Added the running network's node0 bootnode: " + bootnode);
        }
        run.bootnodes = Array.isArray(spec.bootnodes) ? spec.bootnodes.slice() : [];
        run.params = specParams(spec);
        if (!run.params) print('logs', 'Spec protocol_parameters could not be read; the slot/epoch display stays empty.');
        renderLive();
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
        field('status').textContent = 'Following (withRuntime: false)';
        controls();
        renderLive();
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
        renderLive();
    } catch (error) { fail(run, error); }
}

// --------------------------------------------------------------------------
// Display-only header decoding.
//
// The offsets mirror `lib/src/jam/codec.rs::read_header` (Gray Paper 0.8.0):
// parent (32) | prior state root (32) | extrinsic hash (32) | slot (u32 LE) |
// epoch-mark option | tickets-mark option | author index (u16 LE) | ...
// Option payload sizes come from the spec's own parameters: an epoch mark is
// 64 + natural(count) + count * 64 bytes, a tickets mark epoch_len * 33 bytes.
//
// NOTHING here gates a control, decides correctness, or constitutes
// verification; that all happens in Rust inside the client. Anything that does
// not decode is displayed as unreadable rather than guessed.
// --------------------------------------------------------------------------

function hexToBytes(hex) {
    const text = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) throw new Error('not hexadecimal');
    const bytes = new Uint8Array(text.length / 2);
    for (let index = 0; index < bytes.length; index += 1)
        bytes[index] = parseInt(text.slice(index * 2, index * 2 + 2), 16);
    return bytes;
}

/** `epoch_len`, `slot_seconds` and `max_validators` from the encoded PolkaJam `ProtocolParameters`. */
function specParams(spec) {
    try {
        const bytes = hexToBytes(String(spec.protocol_parameters ?? ''));
        if (bytes.length !== 122) return undefined;
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        const params = {
            epochLen: view.getUint32(30, true),
            slotSeconds: view.getUint16(80, true),
            maxValidators: 3 * view.getUint16(24, true),
        };
        return params.epochLen > 0 ? params : undefined;
    } catch {
        return undefined;
    }
}

function decodeHeaderForDisplay(bytes, params) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const need = (offset, length) => {
        if (offset + length > bytes.length) throw new Error('header bytes end early');
    };
    need(0, 100);
    const slot = view.getUint32(96, true);
    let offset = 100;
    need(offset, 1);
    const epochTag = bytes[offset];
    offset += 1;
    if (epochTag > 1) throw new Error('epoch-mark option tag is ' + epochTag);
    if (epochTag === 1) {
        offset += 64;
        need(offset, 1);
        const first = bytes[offset++];
        let count = first;
        if (first >= 128) {
            // The maximum set has 1023 keys, so only one- or two-byte naturals fit.
            if (first >= 192) throw new Error('validator count exceeds supported bound');
            need(offset, 1);
            count = (first & 63) * 256 + bytes[offset++];
            if (count < 128) throw new Error('noncanonical validator count');
        }
        if (count > params.maxValidators) throw new Error('validator count exceeds chain bound');
        offset += count * 64;
    }
    need(offset, 1);
    const ticketsTag = bytes[offset];
    offset += 1;
    if (ticketsTag > 1) throw new Error('tickets-mark option tag is ' + ticketsTag);
    if (ticketsTag === 1) offset += params.epochLen * 33;
    need(offset, 2);
    return {
        slot,
        epochMark: epochTag === 1,
        ticketsMark: ticketsTag === 1,
        authorIndex: view.getUint16(offset, true),
    };
}

function describeHeader(run, hash, hex) {
    if (typeof hex !== 'string' || !run.params) return;
    try {
        run.decoded = Object.assign({ hash }, decodeHeaderForDisplay(hexToBytes(hex), run.params));
        // An epoch boundary lasts one block; remember it so the operator can
        // see that one went past without staring at the page for 72 seconds.
        if (run.decoded.epochMark) run.lastEpochMark = run.decoded.slot;
        if (run.decoded.ticketsMark) run.lastTicketsMark = run.decoded.slot;
    } catch (error) {
        run.decoded = { hash, error: String(error && (error.message || error)) };
    }
    renderLive();
}

// --------------------------------------------------------------------------
// Live view
// --------------------------------------------------------------------------

function trackBlock(run, hash, parent) {
    run.blocks.set(hash, parent);
    while (run.blocks.size > MAX_TRACKED_BLOCKS) run.blocks.delete(run.blocks.keys().next().value);
}

/** Tracked hashes that no tracked block claims as its parent. */
function leaves(run) {
    const parents = new Set(run.blocks.values());
    return [...run.blocks.keys()].filter(hash => !parents.has(hash));
}

const abbreviate = hash => typeof hash === 'string' && hash.length > 18
    ? hash.slice(0, 10) + '…' + hash.slice(-8) : String(hash ?? '');

function setText(id, text) {
    field(id).textContent = text === undefined || text === null || text === '' ? '–' : String(text);
}

function setHash(id, hash, suffix) {
    const cell = field(id);
    cell.textContent = '';
    if (typeof hash !== 'string' || hash.length === 0) {
        cell.textContent = '–';
        return;
    }
    const code = document.createElement('code');
    code.textContent = abbreviate(hash);
    code.title = hash + ' (click to copy)';
    code.tabIndex = 0;
    code.style.cursor = 'copy';
    code.onclick = () => { void navigator.clipboard?.writeText(hash).catch(() => {}); };
    cell.append(code);
    if (suffix) cell.append(document.createTextNode(' ' + suffix));
}

function connectionState(run) {
    if (stopping) return 'Stopping';
    if (!run) return 'Stopped';
    if (run.subscription === undefined) return run.unfollowing ? 'Unfollowed (chain still running)' : 'Starting';
    if (run.blockCount === 0) return 'Connecting (following, no block yet)';
    return 'Following';
}

function renderLive() {
    const run = current;
    setText('live-connection', connectionState(run));
    setText('live-bootnode', run?.bootnodes?.length ? run.bootnodes.join(', ') : undefined);
    if (!run || run.lastEventAt === undefined) setText('live-last-event', undefined);
    else setText('live-last-event', Math.round((Date.now() - run.lastEventAt) / 1000) + 's ago');
    const anchors = run?.initialized?.anchors ?? [];
    setHash('live-anchor', anchors[0], anchors.length > 1 ? '(+' + (anchors.length - 1) + ' more)' :
        (run?.initialized ? 'at ' + new Date(run.initialized.at).toLocaleTimeString() : undefined));
    setText('live-count', run ? String(run.blockCount) : '0');
    setHash('live-block', run?.latest);
    setHash('live-parent', run && run.latest ? run.blocks.get(run.latest) ?? undefined : undefined);
    const decoded = run?.decoded && run.decoded.hash === run.latest ? run.decoded : undefined;
    if (decoded && !decoded.error) {
        const epochLen = run.params.epochLen;
        setText('live-slot', decoded.slot + ' (' + run.params.slotSeconds + 's per slot)');
        setText('live-epoch', 'epoch ' + Math.floor(decoded.slot / epochLen) +
            ', position ' + (decoded.slot % epochLen) + ' of ' + epochLen);
        const marks = [decoded.epochMark ? 'epoch mark' : null, decoded.ticketsMark ? 'tickets mark' : null].filter(Boolean);
        setText('live-marks', marks.length ? marks.join(' + ') : 'none');
        setText('live-author', decoded.authorIndex);
    } else {
        setText('live-slot', decoded?.error ? 'header bytes not readable: ' + decoded.error : undefined);
        setText('live-epoch', undefined);
        setText('live-marks', undefined);
        setText('live-author', undefined);
    }
    const seen = [
        run?.lastEpochMark !== undefined ? 'last epoch mark at slot ' + run.lastEpochMark : null,
        run?.lastTicketsMark !== undefined ? 'last tickets mark at slot ' + run.lastTicketsMark : null,
    ].filter(Boolean);
    setText('live-marks-seen', !run ? undefined : (seen.length ? seen.join(' · ') : 'none yet'));
    setHash('live-best', run?.best, run?.best && run.best === run?.latest ? '(= latest new block)' : undefined);
    const known = run ? leaves(run) : [];
    if (known.length === 0) setText('live-leaves', undefined);
    else field('live-leaves').textContent = known.length + (known.length === 1 ? ' leaf: ' : ' leaves: ') +
        known.slice(0, 6).map(abbreviate).join(', ') + (known.length > 6 ? ', …' : '');
    renderNodeView(decoded && !decoded.error ? decoded : undefined);
    renderFinality(run);
    renderBlocks(run);
}

function renderFinality(run) {
    setText('finality-state', !run ? connectionState(run) : run.unfollowing ? 'Unfollowed (last observation)' :
        !run.finalized?.hash ? 'Waiting for initialized' : run.finalized.source === 'anchor'
            ? 'Trusted anchor; awaiting verified finality' : 'Finality reported by the client follow stream');
    setHash('finality-head', run?.finalized?.hash);
    // Preserve the slot when a finalized row ages out of the bounded table.
    const decoded = run?.rows.find(row => row.hash === run.finalized?.hash)?.decoded;
    if (decoded && !decoded.error) run.finalized.slot = decoded.slot;
    setText('finality-slot', run?.finalized?.slot);
    setText('finality-count', run?.finalityCount ?? 0);
    setText('finality-age', run?.lastFinalityAt === undefined ? undefined :
        Math.round((Date.now() - run.lastFinalityAt) / 1000) + 's ago');
    const finalized = harness.available ? harness.status?.nodeFinalizedBlock : undefined;
    if (!harness.available) {
        setText('finality-node', harness.error ? 'harness unavailable' : undefined);
    } else if (!finalized?.hash) {
        setText('finality-node', harness.status?.nodeFinalizedBlockError
            ? 'node RPC error: ' + harness.status.nodeFinalizedBlockError : 'unavailable');
    } else {
        setHash('finality-node', finalized.hash, '· slot ' + (finalized.slot ?? '–') + ' · node report only');
    }
    const best = harness.available ? nodeBest() : undefined;
    setText('finality-node-gap', Number.isSafeInteger(best?.slot) && Number.isSafeInteger(finalized?.slot)
        ? (best.slot >= finalized.slot ? (best.slot - finalized.slot) + ' slot(s)' : 'heads sampled across an update; waiting for next poll')
        : undefined);
}

function cell(row, text, { mono = false } = {}) {
    const td = document.createElement('td');
    if (mono) {
        const code = document.createElement('code');
        code.textContent = text;
        td.append(code);
    } else {
        td.textContent = text;
    }
    row.append(td);
    return td;
}

function hashCell(row, hash) {
    const td = cell(row, abbreviate(hash), { mono: true });
    const code = td.firstChild;
    code.title = hash + ' (click to copy)';
    code.tabIndex = 0;
    code.style.cursor = 'copy';
    code.onclick = () => { void navigator.clipboard?.writeText(hash).catch(() => {}); };
    return td;
}

function renderBlocks(run) {
    const body = field('blocks-body');
    const empty = field('blocks-empty');
    const rows = run?.rows ?? [];
    empty.hidden = rows.length > 0;
    if (rows.length === 0) {
        body.textContent = '';
        return;
    }
    const table = document.createDocumentFragment();
    for (const entry of rows) {
        const row = document.createElement('tr');
        const decoded = entry.decoded && !entry.decoded.error ? entry.decoded : undefined;
        if (decoded) {
            const epochLen = run.params.epochLen;
            cell(row, String(decoded.slot));
            cell(row, Math.floor(decoded.slot / epochLen) + ' + ' + (decoded.slot % epochLen));
            cell(row, String(decoded.authorIndex));
            const marks = [decoded.epochMark ? 'epoch' : null, decoded.ticketsMark ? 'tickets' : null].filter(Boolean);
            cell(row, marks.length ? marks.join(' + ') : '–');
        } else {
            // No header yet, or one that did not decode. Say which; guess nothing.
            const reason = entry.note ?? (entry.decoded?.error ? 'header not readable' : 'header pending');
            cell(row, '–');
            cell(row, '–');
            cell(row, '–');
            cell(row, reason);
        }
        cell(row, entry.finality);
        hashCell(row, entry.hash);
        if (entry.parent) hashCell(row, entry.parent); else cell(row, '–');
        cell(row, Math.round((Date.now() - entry.at) / 1000) + 's');
        table.append(row);
    }
    body.textContent = '';
    body.append(table);
}

// --------------------------------------------------------------------------
// Harness control endpoint: the independent oracle, and the fault buttons.
// --------------------------------------------------------------------------

const harness = { status: undefined, available: false, busy: false, error: undefined };

async function controlRequest(action) {
    const response = await fetch(CONTROL_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ action }),
    });
    let body;
    try { body = await response.json(); } catch { body = undefined; }
    if (!response.ok || !body?.ok) throw new Error(body?.error ?? ('control endpoint HTTP ' + response.status));
    return body.status;
}

function nodeBest() {
    const best = harness.status?.nodeBestBlock;
    if (!best || typeof best !== 'object') return undefined;
    const slot = Number(best.slot);
    return { slot: Number.isFinite(slot) ? slot : undefined, hash: typeof best.hash === 'string' ? best.hash : undefined };
}

function renderNodeView(decoded) {
    if (!harness.available) {
        setText('live-node-best', harness.error ? 'harness unavailable' : undefined);
        setText('live-agreement', undefined);
        return;
    }
    const alive = harness.status?.node0Alive ? 'node0 running' : 'node0 NOT running';
    const best = nodeBest();
    if (!best) {
        setText('live-node-best', harness.status?.nodeBestBlockError
            ? 'node RPC error: ' + harness.status.nodeBestBlockError + ' · ' + alive
            : alive);
        setText('live-agreement', undefined);
        return;
    }
    setHash('live-node-best', best.hash, '· slot ' + best.slot + ' · ' + alive);
    if (!decoded || best.slot === undefined) {
        setText('live-agreement', undefined);
        return;
    }
    const delta = best.slot - decoded.slot;
    setText('live-agreement', delta === 0
        ? (best.hash === decoded.hash ? 'in step: same slot and same block' : 'same slot, different block hash')
        : (delta > 0 ? 'client is ' + delta + ' slot(s) behind the node' : 'client is ' + (-delta) + ' slot(s) ahead of the node'));
}

function setNetworkButtons() {
    for (const id of ['kill-node0', 'start-node0', 'restart-node0'])
        field(id).disabled = !harness.available || harness.busy;
}

function describeHarness(status) {
    const all = status?.processes ?? [];
    const node0 = all.find(entry => entry.node0);
    return 'PolkaJam ' + String(status?.pinnedCommit ?? '').slice(0, 8) +
        ' · base port ' + status?.basePort + ' · RPC port ' + status?.rpcPort +
        ' · ' + all.length + ' node process(es) alive · ' +
        (node0 ? 'node0 pid ' + node0.pid : 'node0 NOT running');
}

async function poll() {
    if (harness.busy) return;
    try {
        harness.status = await controlRequest('status');
        harness.available = true;
        harness.error = undefined;
        field('network-status').textContent = describeHarness(harness.status);
    } catch (error) {
        harness.available = false;
        harness.error = String(error && (error.message || error));
        field('network-status').textContent =
            'Demo harness not reachable at ' + CONTROL_URL + ' (' + harness.error +
            '). Start it with: cd wasm-node/javascript && npm run demo:jam';
    }
    setNetworkButtons();
    renderLive();
}

async function networkAction(action) {
    if (harness.busy || !harness.available) return;
    harness.busy = true;
    setNetworkButtons();
    field('network-status').textContent = action + ': running…';
    try {
        harness.status = await controlRequest(action);
        field('network-status').textContent = action + ': done · ' + describeHarness(harness.status);
    } catch (error) {
        field('network-status').textContent = action + ' FAILED: ' + String(error && (error.message || error));
    } finally {
        harness.busy = false;
        setNetworkButtons();
        renderLive();
    }
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
for (const action of ['kill-node0', 'start-node0', 'restart-node0'])
    field(action).onclick = () => { void networkAction(action); };

setInterval(() => { void poll(); }, POLL_MS);
setInterval(renderLive, 1000);
void poll();
renderLive();

window.jamDemo = {
    start, stop, header, unfollow,
    network: networkAction,
    snapshot: () => ({
        running: !!current,
        subscription: current?.subscription,
        latestNewBlock: current?.latest,
        pins: [...(current?.pins ?? [])],
        pending: current?.pending.size ?? 0,
        events: [...entries.events],
        logs: [...entries.logs],
    }),
    live: () => ({
        connection: connectionState(current),
        bootnodes: [...(current?.bootnodes ?? [])],
        blockCount: current?.blockCount ?? 0,
        initialized: current?.initialized,
        latestNewBlock: current?.latest,
        parent: current?.latest ? current.blocks.get(current.latest) ?? null : undefined,
        best: current?.best,
        finalized: current?.finalized ? { ...current.finalized } : undefined,
        finalityCount: current?.finalityCount ?? 0,
        lastFinalityAt: current?.lastFinalityAt,
        decoded: current?.decoded,
        lastEpochMark: current?.lastEpochMark,
        lastTicketsMark: current?.lastTicketsMark,
        params: current?.params,
        leaves: current ? leaves(current) : [],
        rows: (current?.rows ?? []).map(entry => ({
            hash: entry.hash, parent: entry.parent, at: entry.at, finality: entry.finality,
            decoded: entry.decoded, note: entry.note, headerChars: entry.hex?.length,
        })),
        maxBlockRows: MAX_BLOCK_ROWS,
        lastEventAt: current?.lastEventAt,
        harness: { available: harness.available, busy: harness.busy, error: harness.error, status: harness.status },
    }),
};
