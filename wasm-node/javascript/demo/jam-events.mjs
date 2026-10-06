// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// The JAM driver's debug events, as the demo page shows them.
//
// `light-base/src/sync_service/jam.rs` logs every decision of its sync driver
// as one line `jam-<area>-<what>[; key=value, key=value, ...]` at Debug; the
// grammar and the table of every event are in `demo/jam.md`, "Client events".
// This module is the grammar's only implementation on the JavaScript side:
// `parseJamLog` reads one line, `createEventStore` pairs request lines and
// bounds what is kept. It runs unchanged in the browser and in Node and has no
// dependency. Display only: nothing here influences the client.

/** The page's category toggles, in display order. */
export const CATEGORIES = ['peers', 'pool', 'blocks', 'justification', 'state', 'warp', 'finality'];

/** The first word after `jam-` decides the category. */
const AREA_CATEGORY = {
    peer: 'peers', slot: 'peers', connect: 'peers', reconnect: 'peers', stream: 'peers',
    pool: 'pool', discovery: 'pool',
    block: 'blocks', announcement: 'blocks', header: 'blocks',
    justification: 'justification',
    state: 'state',
    warp: 'warp', anchor: 'warp',
    finality: 'finality', finalized: 'finality',
};

/**
 * Older lines whose `slot=` was a block slot before the grammar existed and
 * stays one for their consumers. The first three carry the connection slot as
 * `conn=`.
 */
export const BLOCK_SLOT_EVENTS = new Set([
    'jam-warp-join-selected', 'jam-warp-applied', 'jam-finalized',
    'jam-anchor-unserved', 'jam-discovery-read-started',
]);

/** The one field whose value is free text: always last, read verbatim. */
const FREE_TEXT_FIELD = 'message';

const NAME = /^jam-([a-z0-9]+)(?:-[a-z0-9]+)*$/;
const FIELD = /^([a-z_][a-z0-9_]*)=(.*)$/s;
const NUMBER = /^\d+$/;

/**
 * `key=value, key=value` as smoldot's log formatter writes fields. A part
 * without `key=` continues the previous value (a byte list such as
 * `hash=[1, 2]`); `message=` takes the rest of the text verbatim, commas
 * included. `null` when the text does not start with a field.
 */
export function parseFields(text) {
    const fields = {};
    let rest = null;
    let last;
    let offset = 0;
    while (offset <= text.length) {
        const next = text.indexOf(', ', offset);
        const part = text.slice(offset, next < 0 ? text.length : next);
        const match = FIELD.exec(part);
        if (match && match[1] === FREE_TEXT_FIELD) {
            rest = text.slice(offset + FREE_TEXT_FIELD.length + 1);
            fields[FREE_TEXT_FIELD] = rest;
            break;
        }
        if (match) {
            last = match[1];
            fields[last] = match[2];
        } else if (last !== undefined) {
            fields[last] += ', ' + part;
        } else {
            return null;
        }
        if (next < 0) break;
        offset = next + 2;
    }
    return { fields, rest };
}

/**
 * One log line of the client as an event, or `null` when it is not a JAM
 * driver event. `slot` is the connection slot (0 or 1) or `null`; `req` the
 * request id or `null`; `fields` every field as text; `rest` the free text of
 * a `message=` field.
 */
export function parseJamLog(target, message, at) {
    if (typeof message !== 'string' || !message.startsWith('jam-')) return null;
    const split = message.indexOf('; ');
    const name = split < 0 ? message : message.slice(0, split);
    const area = NAME.exec(name)?.[1];
    const category = AREA_CATEGORY[area];
    if (!category) return null;
    const parsed = split < 0 ? { fields: {}, rest: null } : parseFields(message.slice(split + 2));
    if (!parsed) return null;
    const { fields, rest } = parsed;
    const conn = BLOCK_SLOT_EVENTS.has(name) ? fields.conn : fields.slot;
    return {
        at,
        target: String(target ?? ''),
        name,
        category,
        slot: NUMBER.test(conn ?? '') ? Number(conn) : null,
        req: NUMBER.test(fields.req ?? '') ? Number(fields.req) : null,
        fields,
        rest,
    };
}

/** `start` for a request's first line, `end` for its outcome, else `event`. */
export function phase(name) {
    if (name.endsWith('-request-queued')) return 'start';
    if (name.endsWith('-request-ended')) return 'end';
    return 'event';
}

/**
 * A bounded, newest-last list of events in which a request's start and
 * outcome lines become one row, updated in place. At most `max` rows are kept;
 * the oldest go first and are counted in `dropped`. Totals per category and
 * name cover every event ever added, dropped or not.
 */
export function createEventStore({ max = 1000 } = {}) {
    const rows = [];
    const requests = new Map();
    const store = {
        rows,
        max,
        dropped: 0,
        total: 0,
        /** Characters of every parsed line, for the log volume. */
        bytes: 0,
        byCategory: Object.fromEntries(CATEGORIES.map(category => [category, 0])),
        byName: {},
        /** `jam-` lines the parser refused, with the first few kept verbatim. */
        unparsed: 0,
        unparsedSamples: [],
        nextId: 1,
        /** Adds one log line; returns the parsed event, or `null`. */
        add(target, message, at = Date.now()) {
            const event = parseJamLog(target, message, at);
            if (!event) {
                if (typeof message === 'string' && message.startsWith('jam-')) {
                    store.unparsed += 1;
                    if (store.unparsedSamples.length < 10) store.unparsedSamples.push(message);
                }
                return null;
            }
            store.total += 1;
            store.bytes += message.length;
            store.byCategory[event.category] += 1;
            store.byName[event.name] = (store.byName[event.name] ?? 0) + 1;
            const kind = phase(event.name);
            const open = event.req !== null ? requests.get(event.req) : undefined;
            if (kind === 'end' && open) {
                finish(open, event, message);
                return event;
            }
            const row = {
                id: store.nextId++, at: event.at, name: event.name, category: event.category,
                slot: event.slot, req: event.req, fields: event.fields, rest: event.rest, line: message,
            };
            if (kind === 'start') {
                row.request = { pending: true, purpose: event.fields.purpose ?? null };
                requests.set(event.req, row);
            } else if (kind === 'end') {
                // The start line was dropped or never seen: keep the outcome.
                row.request = { pending: false, purpose: event.fields.purpose ?? null };
                finish(row, event, message);
            }
            if (event.name === 'jam-peer-disconnected' && event.slot !== null) {
                // A request the pool cut short by moving its slot
                // (`reason=preempted`) has no outcome line of its own.
                for (const pending of requests.values()) {
                    if (pending.slot === event.slot && pending.request.pending) {
                        finish(pending, { at: event.at, name: event.name, fields: {
                            outcome: 'cancelled', reason: event.fields.reason ?? 'disconnected',
                            elapsed_ms: String(event.at - pending.at),
                        } }, message);
                    }
                }
            }
            rows.push(row);
            while (rows.length > store.max) {
                const old = rows.shift();
                store.dropped += 1;
                if (old.req !== null && requests.get(old.req) === old) requests.delete(old.req);
            }
            return event;
        },
        pending() {
            return rows.filter(row => row.request?.pending).length;
        },
        /** Newest first, filtered by category set and case-insensitive text. */
        view({ categories, text } = {}) {
            const needle = String(text ?? '').trim().toLowerCase();
            const out = [];
            for (let index = rows.length - 1; index >= 0; index -= 1) {
                const row = rows[index];
                if (categories && !categories.has(row.category)) continue;
                if (needle && !searchText(row).includes(needle)) continue;
                out.push(row);
            }
            return out;
        },
        /** What the page's download writes, minus the run metadata. */
        snapshot() {
            return {
                retained: rows.length, max: store.max, dropped: store.dropped, total: store.total, bytes: store.bytes,
                pending: store.pending(), byCategory: { ...store.byCategory }, byName: { ...store.byName },
                unparsed: store.unparsed, unparsedSamples: [...store.unparsedSamples],
                events: rows.map(row => JSON.parse(JSON.stringify(row))),
            };
        },
    };
    function finish(row, event, line) {
        row.request.pending = false;
        row.request.endName = event.name;
        row.request.endLine = line;
        row.request.endAt = event.at;
        row.request.outcome = event.fields.outcome ?? null;
        row.request.elapsedMs = NUMBER.test(event.fields.elapsed_ms ?? '') ? Number(event.fields.elapsed_ms) : null;
        row.request.end = event.fields;
    }
    return store;
}

function searchText(row) {
    return [row.name, row.category, row.slot ?? '', row.req ?? '',
        ...Object.entries(row.fields).map(([key, value]) => key + '=' + value),
        ...Object.entries(row.request?.end ?? {}).map(([key, value]) => key + '=' + value),
    ].join(' ').toLowerCase();
}

// --------------------------------------------------------------------------
// BLAKE2b-256 (RFC 7693), for the genesis hash in the events download. The
// header is a few hundred bytes, so BigInt arithmetic is fast enough.
// --------------------------------------------------------------------------

const IV = [
    0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
    0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
const MASK = (1n << 64n) - 1n;
const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & MASK;

/** The 32-byte unkeyed BLAKE2b digest of `bytes`, as `0x` hex. */
export function blake2b256Hex(bytes) {
    const h = IV.slice();
    h[0] ^= 0x01010020n;
    const blocks = Math.max(1, Math.ceil(bytes.length / 128));
    let counter = 0n;
    for (let block = 0; block < blocks; block += 1) {
        const chunk = new Uint8Array(128);
        chunk.set(bytes.subarray(block * 128, block * 128 + 128));
        counter += BigInt(Math.min(128, bytes.length - block * 128));
        const m = [];
        for (let word = 0; word < 16; word += 1) {
            let value = 0n;
            for (let byte = 7; byte >= 0; byte -= 1) value = (value << 8n) | BigInt(chunk[word * 8 + byte]);
            m.push(value);
        }
        const v = h.concat(IV);
        v[12] ^= counter & MASK;
        v[13] ^= counter >> 64n;
        if (block === blocks - 1) v[14] ^= MASK;
        const g = (a, b, c, d, x, y) => {
            v[a] = (v[a] + v[b] + x) & MASK; v[d] = rotr(v[d] ^ v[a], 32n);
            v[c] = (v[c] + v[d]) & MASK; v[b] = rotr(v[b] ^ v[c], 24n);
            v[a] = (v[a] + v[b] + y) & MASK; v[d] = rotr(v[d] ^ v[a], 16n);
            v[c] = (v[c] + v[d]) & MASK; v[b] = rotr(v[b] ^ v[c], 63n);
        };
        for (let round = 0; round < 12; round += 1) {
            const s = SIGMA[round % 10];
            g(0, 4, 8, 12, m[s[0]], m[s[1]]); g(1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(2, 6, 10, 14, m[s[4]], m[s[5]]); g(3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(0, 5, 10, 15, m[s[8]], m[s[9]]); g(1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(2, 7, 8, 13, m[s[12]], m[s[13]]); g(3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (let index = 0; index < 8; index += 1) h[index] ^= v[index] ^ v[index + 8];
    }
    let hex = '0x';
    for (let word = 0; word < 4; word += 1)
        for (let byte = 0; byte < 8; byte += 1) hex += Number((h[word] >> BigInt(8 * byte)) & 0xffn).toString(16).padStart(2, '0');
    return hex;
}
