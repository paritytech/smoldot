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

import test from 'ava';
import { connect } from '../dist/mjs/internals/browser-connect.js';
import { connectToInstanceServer, startInstanceServer } from '../dist/mjs/internals/remote-instance.js';
import { decodeWebTransportAddress, encodeMultistreamHandshakeInfo, startLocalInstance } from '../dist/mjs/internals/local-instance.js';

const tick = () => new Promise(resolve => setImmediate(resolve));

function deferred() {
    let resolve, reject;
    const promise = new Promise((a, b) => {
        resolve = a;
        reject = b;
    });
    return { promise, resolve, reject };
}

function rawStream(write = () => { }) {
    const events = [];
    let controller, writerController;
    const stream = {
        readable: new ReadableStream({
            type: 'bytes',
            start(c) {
                controller = {
                    enqueue(bytes) { c.enqueue(bytes); },
                    close() {
                        c.close();
                        c.byobRequest?.respond(0);
                    },
                    error(error) { c.error(error); },
                };
            },
            cancel() { events.push('cancel'); },
        }),
        writable: new WritableStream({
            start(c) { writerController = c; },
            write(bytes) {
                events.push([...bytes]);
                return write(bytes);
            },
            close() { events.push('fin'); },
            abort() { events.push('abort'); },
        }),
    };
    return { stream, events, controller, writerController };
}

function config() {
    const events = [];
    return {
        events,
        address: { ty: 'webtransport', ip: '127.0.0.1', port: 40000, certHashes: [new Uint8Array(32).fill(7)] },
        onMultistreamHandshakeInfo: info => events.push(['handshake-info', info]),
        onConnectionReset: reason => events.push(['reset', reason]),
        onStreamOpened: (id, direction) => events.push(['open', id, direction]),
        onStreamReset: (id, reason, code) => events.push(['stream-reset', id, reason, code]),
        onWritableBytes: (bytes, id) => events.push(['credit', bytes, id]),
        onMessage: (bytes, id) => events.push(['data', [...bytes], id]),
    };
}

function mockWebTransport(t) {
    const original = globalThis.WebTransport;
    const sessions = [];
    globalThis.WebTransport = class {
        constructor(url, options) {
            this.url = url;
            this.options = options;
            this.readyControl = deferred();
            this.ready = this.readyControl.promise;
            this.closedControl = deferred();
            this.closed = this.closedControl.promise;
            this.incomingBidirectionalStreams = new ReadableStream({ start: c => { this.incoming = c; } });
            this.created = [];
            sessions.push(this);
        }
        createBidirectionalStream() {
            const pending = deferred();
            this.created.push(pending);
            return pending.promise;
        }
        close() { this.closedControl.resolve(); }
    };
    t.teardown(() => { globalThis.WebTransport = original; });
    return sessions;
}

function start(t, cfg = config()) {
    const sessions = mockWebTransport(t);
    const connection = connect(cfg);
    t.teardown(() => connection.reset());
    return { cfg, connection, sessions };
}

async function setup(t) {
    const { cfg, connection, sessions } = start(t);
    await tick();
    const session = sessions[0];
    session.readyControl.resolve();
    await tick();
    return { cfg, connection, session };
}

async function open(connection, session, raw) {
    connection.openOutSubstream();
    await tick();
    session.created.at(-1).resolve(raw.stream);
    await tick();
}

// A WebTransport address in the Rust ABI: tag, port 40000, one 32-byte hash per fill byte, IP.
function encodeWebTransportAddress(ip = '127.0.0.1', tag = 20, fills = [7]) {
    const count = [fills.length, 0, 0, 0];
    return new Uint8Array([tag, 0x9c, 0x40, ...count, ...fills.flatMap(fill => new Array(32).fill(fill)), ...new TextEncoder().encode(ip)]);
}

const instanceConfig = { maxLogLevel: 0, cpuRateLimit: 1, performanceNow: () => 0 };

// Stubs `WebAssembly.instantiate` with `exports`; `wasm.bindings` are the instance's imports.
function fakeWasm(t, exports = {}) {
    const original = WebAssembly.instantiate;
    const memory = new WebAssembly.Memory({ initial: 1 });
    const wasm = { memory, bindings: undefined };
    WebAssembly.instantiate = async (_, imports) => {
        wasm.bindings = imports.smoldot;
        return { exports: { memory, init() { }, advance_execution() { }, ...exports } };
    };
    t.teardown(() => { WebAssembly.instantiate = original; });
    return wasm;
}

function newConnection({ memory, bindings }, id, bytes, offset) {
    new Uint8Array(memory.buffer).set(bytes, offset);
    bindings.connection_new(id, offset, bytes.length);
}

async function startInstance(t, wasm, worker, eventCallback) {
    const configuration = { ...instanceConfig, envVars: [], getRandomValues() { } };
    if (!worker) {
        const instance = await startLocalInstance(configuration, {}, eventCallback);
        t.teardown(() => instance.shutdownExecutor());
        return instance;
    }
    const { port1, port2 } = new MessageChannel();
    const server = startInstanceServer(configuration, port2);
    const instance = await connectToInstanceServer({
        ...configuration, wasmModule: Promise.resolve({}), portToServer: port1, eventCallback,
    });
    while (!wasm.bindings) await tick();
    t.teardown(async () => {
        instance.shutdownExecutor();
        await server;
        port1.close();
        port2.close();
    });
    return instance;
}

test('address decoding copies certificate hashes; handshake tags match Rust', t => {
    for (const [ip, tag] of [['127.0.0.1', 20], ['::1', 21]]) {
        const bytes = encodeWebTransportAddress(ip, tag, [7, 9]);
        const decoded = decodeWebTransportAddress(bytes);
        t.deepEqual(decoded, { ty: 'webtransport', ip, port: 40000, certHashes: [new Uint8Array(32).fill(7), new Uint8Array(32).fill(9)] });
        bytes.fill(0);
        t.is(decoded.certHashes[0][0], 7);
    }
    t.deepEqual([...encodeMultistreamHandshakeInfo({ handshake: 'webtransport' })], [2]);
    t.deepEqual([...encodeMultistreamHandshakeInfo({ handshake: 'webrtc', localTlsCertificateSha256: new Uint8Array(32).fill(7) })], [0, ...new Array(32).fill(7)]);
});

test('rejects malformed WebTransport addresses and handshake metadata', t => {
    const valid = encodeWebTransportAddress();
    for (let length = 0; length < 40; length++)
        t.throws(() => decodeWebTransportAddress(valid.slice(0, length)));
    for (const count of [0, 2, 0xffffffff]) {
        const invalid = valid.slice();
        new DataView(invalid.buffer).setUint32(3, count, true);
        t.throws(() => decodeWebTransportAddress(invalid));
    }
    for (const [tag, ip] of [[20, 'localhost'], [20, '999.0.0.1'], [20, '127.1'], [21, '::gg'], [21, '::::'], [21, '::1/path'], [21, '[::1]']])
        t.throws(() => decodeWebTransportAddress(encodeWebTransportAddress(ip, tag)));
    t.throws(() => encodeMultistreamHandshakeInfo({ handshake: 'webrtc', localTlsCertificateSha256: new Uint8Array(31) }));
});

test.serial('passes certificate hashes and IPv6 URL; remote FIN leaves sending open', async t => {
    const cfg = config();
    cfg.address.ip = '::1';
    const { connection, sessions } = start(t, cfg);
    await tick();
    const session = sessions[0];
    t.deepEqual(cfg.events, [['handshake-info', { handshake: 'webtransport' }]]);
    t.is(session.url, 'https://[::1]:40000/');
    t.is(session.options.serverCertificateHashes[0].algorithm, 'sha-256');
    t.deepEqual(new Uint8Array(session.options.serverCertificateHashes[0].value), cfg.address.certHashes[0]);
    session.readyControl.resolve();
    await tick();
    const raw = rawStream();
    session.incoming.enqueue(raw.stream);
    await tick();
    raw.controller.enqueue(new Uint8Array([1, 2]));
    raw.controller.close();
    await tick();
    t.deepEqual(cfg.events.filter(e => e[0] === 'data'), [['data', [1, 2], 0], ['data', [], 0]]);
    t.deepEqual(cfg.events[1], ['open', 0, 'inbound']);
    connection.send([new Uint8Array([3])], 0);
    await tick();
    t.deepEqual(raw.events, [[3]]);
    t.false(cfg.events.some(e => e[0].includes('reset')));
});

test.serial('write backpressure copies data and FIN follows pending writes without new credit', async t => {
    const { cfg, connection, session } = await setup(t);
    const writing = deferred();
    const raw = rawStream(() => writing.promise);
    await open(connection, session, raw);
    const bytes = new Uint8Array([8, 9]);
    connection.send([bytes], 0);
    bytes.fill(0);
    await tick();
    t.deepEqual(raw.events, [[8, 9]]);
    t.deepEqual(cfg.events.filter(e => e[0] === 'credit'), [['credit', 65536, 0]]);
    connection.closeSend(0);
    await tick();
    t.false(raw.events.includes('fin'));
    writing.resolve();
    await tick();
    t.deepEqual(raw.events, [[8, 9], 'fin']);
    t.deepEqual(cfg.events.filter(e => e[0] === 'credit'), [['credit', 65536, 0]]);
    raw.controller.enqueue(new Uint8Array([4]));
    await tick();
    t.true(cfg.events.some(e => e[0] === 'data' && e[1][0] === 4));
});

test.serial('completed writes return exact credit and excessive writes reset only the stream', async t => {
    const { cfg, connection, session } = await setup(t);
    const raw = rawStream();
    await open(connection, session, raw);
    connection.send([new Uint8Array([1, 2]), new Uint8Array([3])], 0);
    await tick();
    t.deepEqual(cfg.events.filter(e => e[0] === 'credit'), [['credit', 65536, 0], ['credit', 3, 0]]);
    connection.send([new Uint8Array(65537)], 0);
    // `send` is called by Rust, which must not be re-entered.
    t.false(cfg.events.some(e => e[0] === 'stream-reset'));
    await tick();
    t.is(cfg.events.filter(e => e[0] === 'stream-reset').length, 1);
    t.false(cfg.events.some(e => e[0] === 'reset'));
    t.true(raw.events.includes('cancel'));
    t.true(raw.events.includes('abort'));
});

test.serial('local reset suppresses callbacks, including streams created after reset', async t => {
    const { cfg, connection, session } = await setup(t);
    const raw = rawStream();
    await open(connection, session, raw);
    const before = cfg.events.length;
    connection.reset(0);
    await tick();
    t.is(cfg.events.length, before);
    t.deepEqual(raw.events.sort(), ['abort', 'cancel']);
    connection.openOutSubstream();
    await tick();
    connection.reset();
    const late = rawStream();
    session.created.at(-1).resolve(late.stream);
    await tick();
    t.deepEqual(late.events.sort(), ['abort', 'cancel']);
    t.is(cfg.events.length, before);
});

for (const side of ['reader', 'writer']) {
    const transportError = (message, fields) => Object.assign(new Error(message), fields);
    for (const [name, error, reason, code] of [
        ['application code', transportError('no data', { source: 'stream', streamErrorCode: 6 }), 'no data', 6],
        ['no source', transportError('busy', { streamErrorCode: 2 }), 'busy', 2],
        ['code 0', transportError('zero', { source: 'stream', streamErrorCode: 0 }), 'zero', 0],
        ['largest code', transportError('largest', { source: 'stream', streamErrorCode: 0xffffffff }), 'largest', 0xffffffff],
        ['plain', new Error('plain reset'), 'plain reset', undefined],
        // Firefox fails the read with a plain TypeError and no code.
        ['TypeError without a code', new TypeError('Error in input stream'), 'Error in input stream', undefined],
        ['session', transportError('session reset', { source: 'session', streamErrorCode: 6 }), 'session reset', undefined],
    ]) {
        test.serial(`${side} reset reports ${name} error once`, async t => {
            const { cfg, connection, session } = await setup(t);
            const raw = rawStream();
            await open(connection, session, raw);
            (side === 'reader' ? raw.controller : raw.writerController).error(error);
            await tick();
            await tick();
            t.deepEqual(cfg.events.filter(e => e[0] === 'stream-reset'), [['stream-reset', 0, reason, code]]);
            t.false(cfg.events.some(e => e[0] === 'reset'));
            t.true(raw.events.includes(side === 'reader' ? 'abort' : 'cancel'));
        });
    }
}

test.serial('invalid application error codes are omitted', async t => {
    const { cfg, connection, session } = await setup(t);
    const errors = [null, '6', 6.5, -1, 2 ** 32].map(streamErrorCode =>
        Object.assign(new Error('peer reset'), { source: 'stream', streamErrorCode }));
    errors.push(null);
    for (const error of errors) {
        const raw = rawStream();
        await open(connection, session, raw);
        raw.controller.error(error);
        await tick();
    }
    t.deepEqual(cfg.events.filter(event => event[0] === 'stream-reset'),
        errors.map((error, id) => ['stream-reset', id, error?.message ?? 'null', undefined]));
});

test.serial('failed stream creation and duplicate session failures report one connection reset', async t => {
    const { cfg, connection, session } = await setup(t);
    connection.openOutSubstream();
    await tick();
    session.created[0].reject(new Error('stream limit'));
    session.closedControl.reject(new Error('closed'));
    await tick();
    t.is(cfg.events.filter(e => e[0] === 'reset').length, 1);
});

test.serial('connection setup errors are reported asynchronously', async t => {
    const { cfg, sessions } = start(t);
    await tick();
    sessions[0].readyControl.reject(new Error('certificate rejected'));
    sessions[0].closedControl.reject(new Error('session failed'));
    await tick();
    t.is(cfg.events.filter(e => e[0] === 'reset').length, 1);
    for (const ctor of [undefined, class { constructor() { throw new Error('constructor'); } }]) {
        globalThis.WebTransport = ctor;
        const cfg = config();
        connect(cfg);
        t.deepEqual(cfg.events, []);
        await tick();
        t.is(cfg.events.filter(e => e[0] === 'reset').length, 1);
        const cancelled = config();
        const connection = connect(cancelled);
        connection.reset();
        await tick();
        t.deepEqual(cancelled.events, []);
    }
});

test.serial('local instance decodes transport tags, handshake metadata and FIN', async t => {
    const calls = [];
    const events = [];
    const readBuffer = index => {
        const length = wasm.bindings.buffer_size(index);
        wasm.bindings.buffer_copy(index, 0);
        return [...new Uint8Array(wasm.memory.buffer, 0, length)];
    };
    const wasm = fakeWasm(t, {
        connection_multi_stream_set_handshake_info(id, index) { calls.push(['metadata', id, readBuffer(index)]); },
        stream_message(id, stream, index) { calls.push(['message', id, stream, readBuffer(index)]); },
    });
    const instance = await startLocalInstance({ ...instanceConfig, forbidWebRtc: true }, {}, event => events.push(event));
    t.teardown(() => instance.shutdownExecutor());
    for (const tag of [16, 17, 18]) t.is(wasm.bindings.connection_type_supported(tag), 0);
    for (const tag of [20, 21]) t.is(wasm.bindings.connection_type_supported(tag), 1);
    const dns = new Uint8Array([18, 0x9c, 0x40, 4, ...new Array(32).fill(7), ...new TextEncoder().encode('example.com')]);
    newConnection(wasm, 1, dns, 100);
    newConnection(wasm, 5, encodeWebTransportAddress(), 200);
    t.deepEqual(events.filter(event => event.ty === 'new-connection'), [
        { ty: 'new-connection', connectionId: 1, address: { ty: 'webrtc', targetPort: 40000, hostname: 'example.com', family: 4, remoteTlsCertificateSha256: new Uint8Array(32).fill(7) } },
        { ty: 'new-connection', connectionId: 5, address: { ty: 'webtransport', ip: '127.0.0.1', port: 40000, certHashes: [new Uint8Array(32).fill(7)] } },
    ]);
    t.throws(() => decodeWebTransportAddress(dns));
    instance.connectionMultiStreamSetHandshakeInfo(5, { handshake: 'webtransport' });
    instance.streamMessage(5, new Uint8Array([9]), 0);
    instance.streamMessage(5, new Uint8Array(0), 0);
    t.deepEqual(calls, [['metadata', 5, [2]], ['message', 5, 0, [9]], ['message', 5, 0, []]]);
    const forbidding = await startLocalInstance({ ...instanceConfig, forbidWebTransport: true }, {}, () => { });
    t.teardown(() => forbidding.shutdownExecutor());
    for (const tag of [20, 21]) t.is(wasm.bindings.connection_type_supported(tag), 0);
});

test.serial('reports handshake metadata before the session is ready', async t => {
    const { cfg, connection, sessions } = start(t);
    connection.openOutSubstream();
    await tick();
    t.deepEqual(cfg.events, [['handshake-info', { handshake: 'webtransport' }]]);
    t.is(sessions[0].created.length, 0);
    sessions[0].readyControl.resolve();
    await tick();
    t.is(sessions[0].created.length, 1);
    connection.reset();
    const raw = rawStream();
    sessions[0].created[0].resolve(raw.stream);
    await tick();
});

test.serial('WebRTC grants no credit when an opened stream is rejected', async t => {
    const original = globalThis.RTCPeerConnection;
    let pc;
    globalThis.RTCPeerConnection = class {
        static async generateCertificate() { return { getFingerprints: () => [{ algorithm: 'sha-256', value: new Array(32).fill('07').join(':') }] }; }
        constructor() { pc = this; }
        close() { }
    };
    t.teardown(() => { globalThis.RTCPeerConnection = original; });
    const cfg = config();
    cfg.address = { ty: 'webrtc', targetIp: '192.0.2.1', targetPort: 1, ipVersion: 4, remoteTlsCertificateSha256: new Uint8Array(32) };
    let connection;
    cfg.onStreamOpened = id => connection.reset(id);
    connection = connect(cfg);
    t.teardown(() => connection.reset());
    await tick();
    const channel = { close() { } };
    pc.ondatachannel({ channel });
    channel.onopen();
    t.false(cfg.events.some(event => event[0] === 'credit'));
});

for (const worker of [false, true]) for (const { name, blocked, unclaimed } of [
    { name: 'response', blocked: false, unclaimed: false },
    { name: 'blocked response', blocked: true, unclaimed: false },
    { name: 'response with an unclaimed stream', blocked: false, unclaimed: true },
    { name: 'blocked response with an unclaimed stream', blocked: true, unclaimed: true },
]) {
    test.serial(`${worker ? 'worker' : 'local'} graceful reset drains ${name} without callbacks to dropped handles`, async t => {
        const sessions = mockWebTransport(t);
        let connection, instance;
        const callbacksAfterDrop = [];
        const openedStreams = new Set();
        const droppedStreams = new Set();
        let dropped = false;
        const wasm = fakeWasm(t, {
            connection_multi_stream_set_handshake_info() { },
            connection_stream_opened(_, stream) { openedStreams.add(stream); },
            stream_reset(_, stream) { if (dropped || droppedStreams.has(stream)) callbacksAfterDrop.push('reset'); },
            stream_writable_bytes(_, stream) { if (dropped || droppedStreams.has(stream)) callbacksAfterDrop.push('credit'); },
            stream_message(id, stream, index) {
                if (dropped || droppedStreams.has(stream)) callbacksAfterDrop.push('message');
                const { bindings, memory } = wasm;
                if (bindings.buffer_size(index) !== 0) return;
                new Uint8Array(memory.buffer)[200] = 42;
                new DataView(memory.buffer).setUint32(100, 200, true);
                new DataView(memory.buffer).setUint32(104, 1, true);
                bindings.stream_send(id, stream, 100, 1);
                bindings.stream_send_close(id, stream);
                droppedStreams.add(stream);
                bindings.connection_stream_reset(id, stream);
                if (!unclaimed) {
                    dropped = true;
                    bindings.reset_connection(id);
                }
            },
        });
        t.teardown(() => connection?.reset());
        const events = [];
        const eventCallback = event => {
            events.push(event);
            if (event.ty === 'new-connection') {
                connection = connect({
                    address: event.address,
                    onMultistreamHandshakeInfo: info => instance.connectionMultiStreamSetHandshakeInfo(1, info),
                    onStreamOpened: (id, direction) => instance.streamOpened(1, id, direction),
                    onMessage: (data, id) => instance.streamMessage(1, data, id),
                    onWritableBytes: (bytes, id) => instance.streamWritableBytes(1, bytes, id),
                    onStreamReset: (id, reason, code) => instance.streamReset(1, id, reason, code),
                    onConnectionReset: () => { if (dropped) callbacksAfterDrop.push('connection-reset'); },
                });
            } else if (event.ty === 'stream-send') connection.send(event.data, event.streamId);
            else if (event.ty === 'stream-send-close') connection.closeSend(event.streamId);
            else if (event.ty === 'connection-stream-reset') connection.reset(event.streamId, event.graceful);
            else if (event.ty === 'connection-reset') connection.reset(undefined, event.graceful);
        };
        instance = await startInstance(t, wasm, worker, eventCallback);
        newConnection(wasm, 1, encodeWebTransportAddress(), 1000);
        while (!sessions.length) await tick();
        sessions[0].readyControl.resolve();
        await tick();
        const write = deferred();
        const raw = rawStream(() => blocked ? write.promise : undefined);
        sessions[0].incoming.enqueue(raw.stream);
        await tick();
        raw.controller.close();
        let unclaimedStream;
        if (unclaimed) {
            while (!events.some(event => event.ty === 'connection-stream-reset' && event.streamId === 0)) await tick();
            unclaimedStream = rawStream();
            sessions[0].incoming.enqueue(unclaimedStream.stream);
            while (!openedStreams.has(1)) await tick();
            // Simulate dropping an unclaimed stream and then the connection in Rust.
            droppedStreams.add(1);
            wasm.bindings.connection_stream_reset(1, 1);
            dropped = true;
            wasm.bindings.reset_connection(1);
        }
        while (!events.some(event => event.ty === 'connection-reset')) await tick();
        await tick();
        t.true(events.some(event => event.ty === 'connection-stream-reset' && event.graceful === true));
        t.true(events.some(event => event.ty === 'connection-reset' && event.graceful === true));
        t.deepEqual(raw.events.filter(Array.isArray), [[42]]);
        if (blocked) t.false(raw.events.includes('fin'));
        write.resolve();
        await tick();
        t.true(raw.events.includes('fin'));
        if (unclaimed) {
            t.true(unclaimedStream.events.includes('abort'));
            t.true(unclaimedStream.events.includes('cancel'));
            t.false(unclaimedStream.events.includes('fin'));
            const drops = events.filter(event => event.ty === 'connection-stream-reset' || event.ty === 'connection-reset');
            t.deepEqual(drops.map(event => event.streamId), [0, 1, undefined]);
            t.is(drops[1].graceful, undefined);
            t.is(drops[2].graceful, true);
        }
        t.deepEqual(callbacksAfterDrop, []);
    });
}

for (const worker of [false, true]) {
    test.serial(`${worker ? 'worker' : 'local'} preserves optional reset codes across the Wasm ABI`, async t => {
        const sessions = mockWebTransport(t);
        const resets = [];
        const wasm = fakeWasm(t, {
            connection_multi_stream_set_handshake_info() { },
            connection_stream_opened() { },
            stream_writable_bytes() { },
            stream_reset(id, stream, index, hasCode, code) {
                const length = wasm.bindings.buffer_size(index);
                wasm.bindings.buffer_copy(index, 0);
                const message = new TextDecoder().decode(new Uint8Array(wasm.memory.buffer, 0, length));
                resets.push([id, stream, message, hasCode, code]);
            },
        });
        let connection, instance;
        const eventCallback = event => {
            if (event.ty !== 'new-connection') return;
            connection = connect({
                address: event.address,
                onMultistreamHandshakeInfo: info => instance.connectionMultiStreamSetHandshakeInfo(1, info),
                onStreamOpened: (id, direction) => instance.streamOpened(1, id, direction),
                onMessage: (data, id) => instance.streamMessage(1, data, id),
                onWritableBytes: (bytes, id) => instance.streamWritableBytes(1, bytes, id),
                onStreamReset: (id, reason, code) => instance.streamReset(1, id, reason, code),
                onConnectionReset: () => { },
            });
        };
        t.teardown(() => connection?.reset());
        instance = await startInstance(t, wasm, worker, eventCallback);
        newConnection(wasm, 1, encodeWebTransportAddress(), 1000);
        while (!sessions.length) await tick();
        sessions[0].readyControl.resolve();
        await tick();
        const streamWithCode = rawStream();
        const streamWithoutCode = rawStream();
        sessions[0].incoming.enqueue(streamWithCode.stream);
        await tick();
        sessions[0].incoming.enqueue(streamWithoutCode.stream);
        await tick();
        streamWithCode.controller.error(Object.assign(new Error('Received RESET_STREAM.'), { source: 'stream', streamErrorCode: 6 }));
        while (resets.length < 1) await tick();
        streamWithoutCode.controller.error(new TypeError('Error in input stream'));
        while (resets.length < 2) await tick();
        t.deepEqual(resets, [[1, 0, 'Received RESET_STREAM.', 1, 6], [1, 1, 'Error in input stream', 0, 0]]);
    });
}

test.serial('receiving waits for delivery acknowledgement', async t => {
    const { cfg, connection, session } = await setup(t);
    const ack = deferred();
    const received = [];
    cfg.onMessage = bytes => {
        received.push([...bytes]);
        return ack.promise;
    };
    const raw = rawStream();
    await open(connection, session, raw);
    for (let i = 0; i < 10; ++i) raw.controller.enqueue(new Uint8Array([i]));
    await tick();
    t.deepEqual(received, [[0]]);
    connection.reset();
    ack.resolve();
    await tick();
    t.deepEqual(received, [[0]]);
});

test.serial('BYOB bounds each read even when the peer writes a larger buffer', async t => {
    const { cfg, connection, session } = await setup(t);
    const sizes = [];
    cfg.onMessage = bytes => { sizes.push(bytes.length); };
    const raw = rawStream();
    await open(connection, session, raw);
    raw.controller.enqueue(new Uint8Array(131073));
    await tick();
    t.deepEqual(sizes, [65536, 65536, 1]);
    t.false(cfg.events.some(event => event[0].includes('reset')));
});

test.serial('write failure after dropping handles closes the session without callbacks', async t => {
    const { cfg, connection, session } = await setup(t);
    const writing = deferred();
    const raw = rawStream(() => writing.promise);
    await open(connection, session, raw);
    raw.controller.close();
    await tick();
    connection.send([new Uint8Array([42])], 0);
    connection.closeSend(0);
    connection.reset(0, true);
    connection.reset(undefined, true);
    const count = cfg.events.length;
    writing.reject(new Error('peer stopped receiving'));
    await session.closed;
    await tick();
    t.is(cfg.events.length, count);
});

test.serial('pending outbound streams count towards the admission limit', async t => {
    const { cfg, connection, session } = await setup(t);
    for (let i = 0; i < 64; ++i) connection.openOutSubstream();
    await tick();
    t.is(session.created.length, 64);
    connection.openOutSubstream();
    // `openOutSubstream` is called by Rust, which must not be re-entered.
    t.false(cfg.events.some(event => event[0] === 'reset'));
    await tick();
    t.is(cfg.events.filter(event => event[0] === 'reset').length, 1);
    for (const pending of session.created) pending.resolve(rawStream().stream);
    await tick();
    t.false(cfg.events.some(event => event[0] === 'open'));
});

test.serial('dropping the connection cancels a pending reset report', async t => {
    const { cfg, connection, session } = await setup(t);
    for (let i = 0; i < 65; ++i) connection.openOutSubstream();
    connection.reset();
    await tick();
    t.false(cfg.events.some(event => event[0] === 'reset'));
    await session.closed;
});

test.serial('dropping a stream cancels its pending reset report', async t => {
    const { cfg, connection, session } = await setup(t);
    const raw = rawStream();
    await open(connection, session, raw);
    connection.send([new Uint8Array(65537)], 0);
    connection.reset(0);
    await tick();
    t.false(cfg.events.some(event => event[0] === 'stream-reset'));
    t.true(raw.events.includes('abort'));
});

test.serial('reset streams count towards the admission limit until acknowledged', async t => {
    const { cfg, session } = await setup(t);
    const ack = deferred();
    cfg.onStreamReset = () => ack.promise;
    for (let i = 0; i < 64; ++i) {
        const raw = rawStream();
        session.incoming.enqueue(raw.stream);
        await tick();
        raw.controller.error(new Error('peer reset'));
        await tick();
    }
    t.is(cfg.events.filter(event => event[0] === 'open').length, 64);
    session.incoming.enqueue(rawStream().stream);
    await tick();
    t.is(cfg.events.filter(event => event[0] === 'reset').length, 1);
    t.is(cfg.events.filter(event => event[0] === 'open').length, 64);
    ack.resolve();
    await tick();
});

for (const { name, size, limit } of [
    { name: 'byte', size: 65536, limit: 64 },
    { name: 'event', size: 1, limit: 256 },
]) {
    test.serial(`worker delivery pauses at the ${name} limit until acknowledged`, async t => {
        const { port1, port2 } = new MessageChannel();
        const pending = connectToInstanceServer({ wasmModule: Promise.resolve({}), portToServer: port1, eventCallback() {} });
        const server = await new Promise(resolve => { port2.onmessage = event => resolve(event.data.serverToClient); });
        const instance = await pending;
        const messages = [];
        server.onmessage = event => messages.push(event.data);
        t.teardown(() => {
            port1.close();
            port2.close();
            server.close();
        });
        server.postMessage({ ty: 'new-connection', connectionId: 1, address: config().address });
        await tick();
        await tick();
        const deliveries = Array.from({ length: limit + 1 }, () => instance.streamMessage(1, new Uint8Array(size), 0));
        while (messages.length < limit) await tick();
        await tick();
        t.is(messages.length, limit);

        server.postMessage({ ty: 'transport-delivered', deliveryId: messages[0].deliveryId });
        while (messages.length < limit + 1) await tick();
        t.is(messages.length, limit + 1);
        for (const message of messages.slice(1))
            server.postMessage({ ty: 'transport-delivered', deliveryId: message.deliveryId });
        await Promise.all(deliveries);
    });
}
