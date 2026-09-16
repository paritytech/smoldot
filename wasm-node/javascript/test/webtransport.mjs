// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

import test from 'ava';
import { connectWebTransport, connect as browserConnect } from '../dist/mjs/no-auto-bytecode-browser.js';
import { connectToInstanceServer, startInstanceServer } from '../dist/mjs/internals/remote-instance.js';
import { connect as nodeConnect } from '../dist/mjs/no-auto-bytecode-nodejs.js';
import { connect as denoConnect } from '../dist/mjs/no-auto-bytecode-deno.js';
import { decodeWebTransportAddress, encodeMultistreamHandshakeInfo, startLocalInstance } from '../dist/mjs/internals/local-instance.js';

const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
    let resolve, reject;
    const promise = new Promise((a, b) => { resolve = a; reject = b; });
    return { promise, resolve, reject };
}
function rawStream(write = () => {}) {
    const events = [];
    let controller, writerController;
    const stream = {
        readable: new ReadableStream({ type: 'bytes', start(c) {
            controller = {
                enqueue(bytes) { if (bytes.length) c.enqueue(bytes); },
                close() { c.close(); c.byobRequest?.respond(0); },
                error(error) { c.error(error); },
            };
        }, cancel() { events.push('cancel'); } }),
        writable: new WritableStream({
            start(c) { writerController = c; },
            write(bytes) { events.push([...bytes]); return write(bytes); },
            close() { events.push('fin'); },
            abort() { events.push('abort'); },
        }),
    };
    return { stream, events, get controller() { return controller; }, get writerController() { return writerController; } };
}
function config() {
    const events = [];
    return {
        events,
        address: { ty: 'webtransport', ip: '127.0.0.1', port: 40000, certHashes: [new Uint8Array(32).fill(7)] },
        onMultistreamHandshakeInfo: info => events.push(['ready', info]),
        onConnectionReset: reason => events.push(['reset', reason]),
        onStreamOpened: (id, direction) => events.push(['open', id, direction]),
        onStreamReset: (id, reason) => events.push(['stream-reset', id, reason]),
        onWritableBytes: (bytes, id) => events.push(['credit', bytes, id]),
        onMessage: (bytes, id) => events.push(['data', [...bytes], id]),
    };
}
function host(t) {
    const original = globalThis.WebTransport;
    const sessions = [];
    globalThis.WebTransport = class {
        constructor(url, options) {
            this.url = url; this.options = options;
            this.readyControl = deferred(); this.ready = this.readyControl.promise;
            this.closedControl = deferred(); this.closed = this.closedControl.promise;
            this.incomingBidirectionalStreams = new ReadableStream({ start: c => { this.incoming = c; } });
            this.created = [];
            sessions.push(this);
        }
        createBidirectionalStream() {
            const d = deferred(); this.created.push(d); return d.promise;
        }
        close() { this.closedControl.resolve(); }
    };
    t.teardown(() => { globalThis.WebTransport = original; });
    return sessions;
}
async function setup(t) {
    const sessions = host(t);
    const cfg = config();
    const connection = connectWebTransport(cfg);
    t.teardown(() => connection.reset());
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

test('address and metadata ABI matches Rust vectors; pins are owned', t => {
    for (const [ip, tag] of [['127.0.0.1', 18], ['::1', 19]]) {
        const bytes = new Uint8Array([tag, 0x9c, 0x40, 2, 0, 0, 0, ...new Array(32).fill(7), ...new Array(32).fill(9), ...new TextEncoder().encode(ip)]);
        const decoded = decodeWebTransportAddress(bytes);
        t.deepEqual(decoded, { ty: 'webtransport', ip, port: 40000, certHashes: [new Uint8Array(32).fill(7), new Uint8Array(32).fill(9)] });
        bytes.fill(0);
        t.is(decoded.certHashes[0][0], 7);
    }
    t.deepEqual([...encodeMultistreamHandshakeInfo({ handshake: 'webtransport' })], [2]);
    t.deepEqual([...encodeMultistreamHandshakeInfo({ handshake: 'webrtc', localTlsCertificateSha256: new Uint8Array(32).fill(7) })], [0, ...new Array(32).fill(7)]);
});

test('malformed WebTransport ABI inputs fail before allocation', t => {
    const valid = new Uint8Array([18, 0x9c, 0x40, 1, 0, 0, 0, ...new Array(32).fill(7), ...new TextEncoder().encode('127.0.0.1')]);
    for (let length = 0; length < 40; length++)
        t.throws(() => decodeWebTransportAddress(valid.slice(0, length)));
    for (const count of [0, 2, 0xffffffff]) {
        const invalid = valid.slice(); new DataView(invalid.buffer).setUint32(3, count, true);
        t.throws(() => decodeWebTransportAddress(invalid));
    }
    for (const [tag, ip] of [[18, 'localhost'], [18, '999.0.0.1'], [18, '127.1'], [19, '::gg'], [19, '::::'], [19, '::1/path'], [19, '[::1]']]) {
        const invalid = new Uint8Array([...valid.slice(0, 39), ...new TextEncoder().encode(ip)]); invalid[0] = tag;
        t.throws(() => decodeWebTransportAddress(invalid));
    }
    t.throws(() => encodeMultistreamHandshakeInfo({ handshake: 'webrtc', localTlsCertificateSha256: new Uint8Array(31) }));
});

test.serial('ready, pins and IPv6 URL; incoming FIN leaves writing usable', async t => {
    const sessions = host(t), cfg = config(); cfg.address.ip = '::1';
    const connection = connectWebTransport(cfg); t.teardown(() => connection.reset());
    await tick(); const session = sessions[0];
    t.deepEqual(cfg.events, [['ready', { handshake: 'webtransport' }]]);
    t.is(session.url, 'https://[::1]:40000/');
    t.is(session.options.serverCertificateHashes[0].algorithm, 'sha-256');
    t.deepEqual(new Uint8Array(session.options.serverCertificateHashes[0].value), cfg.address.certHashes[0]);
    session.readyControl.resolve(); await tick();
    const raw = rawStream(); session.incoming.enqueue(raw.stream); await tick();
    raw.controller.enqueue(new Uint8Array());
    raw.controller.enqueue(new Uint8Array([1, 2])); raw.controller.close(); await tick();
    t.deepEqual(cfg.events.filter(e => e[0] === 'data'), [['data', [1, 2], 0], ['data', [], 0]]);
    t.deepEqual(cfg.events[0], ['ready', { handshake: 'webtransport' }]);
    t.deepEqual(cfg.events[1], ['open', 0, 'inbound']);
    connection.send([new Uint8Array([3])], 0); await tick();
    t.deepEqual(raw.events, [[3]]);
    t.false(cfg.events.some(e => e[0].includes('reset')));
});

test.serial('write backpressure copies data and FIN follows pending writes without new credit', async t => {
    const { cfg, connection, session } = await setup(t);
    const writing = deferred(); const raw = rawStream(() => writing.promise);
    await open(connection, session, raw);
    const bytes = new Uint8Array([8, 9]); connection.send([bytes], 0); bytes.fill(0);
    await tick();
    t.deepEqual(raw.events, [[8, 9]]);
    t.deepEqual(cfg.events.filter(e => e[0] === 'credit'), [['credit', 65536, 0]]);
    connection.closeSend(0); await tick(); t.false(raw.events.includes('fin'));
    writing.resolve(); await tick();
    t.deepEqual(raw.events, [[8, 9], 'fin']);
    t.deepEqual(cfg.events.filter(e => e[0] === 'credit'), [['credit', 65536, 0]]);
    raw.controller.enqueue(new Uint8Array([4])); await tick();
    t.true(cfg.events.some(e => e[0] === 'data' && e[1][0] === 4));
});

test.serial('completed writes return exact credit and excessive writes reset only the stream', async t => {
    const { cfg, connection, session } = await setup(t); const raw = rawStream();
    await open(connection, session, raw);
    connection.send([new Uint8Array([1, 2]), new Uint8Array([3])], 0); await tick();
    t.deepEqual(cfg.events.filter(e => e[0] === 'credit'), [['credit', 65536, 0], ['credit', 3, 0]]);
    connection.send([new Uint8Array(65537)], 0); await tick();
    t.is(cfg.events.filter(e => e[0] === 'stream-reset').length, 1);
    t.false(cfg.events.some(e => e[0] === 'reset'));
    t.true(raw.events.includes('cancel')); t.true(raw.events.includes('abort'));
});

test.serial('local reset suppresses callbacks, including streams created after reset', async t => {
    const { cfg, connection, session } = await setup(t); const raw = rawStream();
    await open(connection, session, raw);
    const before = cfg.events.length; connection.reset(0); await tick();
    t.is(cfg.events.length, before);
    t.deepEqual(raw.events.sort(), ['abort', 'cancel']);
    connection.openOutSubstream(); await tick(); connection.reset();
    const late = rawStream(); session.created.at(-1).resolve(late.stream); await tick();
    t.deepEqual(late.events.sort(), ['abort', 'cancel']);
    t.is(cfg.events.length, before);
});

test.serial('read errors and idle STOP_SENDING reset both stream directions once', async t => {
    const { cfg, connection, session } = await setup(t);
    const raw = rawStream(); await open(connection, session, raw);
    raw.controller.error(new Error('read reset')); await tick();
    t.is(cfg.events.filter(e => e[0] === 'stream-reset').length, 1);
    t.true(raw.events.includes('abort'));
    const second = rawStream(); await open(connection, session, second);
    second.writerController.error(new Error('stop sending')); await tick();
    t.is(cfg.events.filter(e => e[0] === 'stream-reset').length, 2);
    t.true(second.events.includes('cancel'));
});

test.serial('failed stream creation and duplicate session failures report one connection reset', async t => {
    const { cfg, connection, session } = await setup(t);
    connection.openOutSubstream(); await tick();
    session.created[0].reject(new Error('stream limit')); session.closedControl.reject(new Error('closed')); await tick();
    t.is(cfg.events.filter(e => e[0] === 'reset').length, 1);
});

test.serial('ready failure, unavailable API and constructor throws are asynchronous clean failures', async t => {
    const sessions = host(t); const cfg = config(); connectWebTransport(cfg);
    await tick(); sessions[0].readyControl.reject(new Error('certificate rejected'));
    sessions[0].closedControl.reject(new Error('session failed')); await tick();
    t.is(cfg.events.filter(e => e[0] === 'reset').length, 1);
    for (const ctor of [undefined, class { constructor() { throw new Error('constructor'); } }]) {
        globalThis.WebTransport = ctor;
        const cfg = config(); connectWebTransport(cfg); t.deepEqual(cfg.events, []);
        await tick(); t.is(cfg.events.filter(e => e[0] === 'reset').length, 1);
        const cancelled = config(); const connection = connectWebTransport(cancelled); connection.reset();
        await tick(); t.deepEqual(cancelled.events, []);
    }
});

test.serial('Node and Deno reject WT asynchronously and support cancellation', async t => {
    for (const connect of [nodeConnect, denoConnect]) {
        const cfg = config(); connect(cfg); t.deepEqual(cfg.events, []);
        await tick(); t.is(cfg.events.filter(e => e[0] === 'reset').length, 1);
        const cancelled = config(); connect(cancelled).reset(); await tick(); t.deepEqual(cancelled.events, []);
    }
});

test.serial('local instance passes WT metadata and empty FIN through the real ABI adapter', async t => {
    const original = WebAssembly.instantiate;
    let bindings;
    const calls = [], events = [];
    const memory = new WebAssembly.Memory({ initial: 1 });
    const readBuffer = index => {
        const length = bindings.buffer_size(index);
        bindings.buffer_copy(index, 0);
        return [...new Uint8Array(memory.buffer, 0, length)];
    };
    WebAssembly.instantiate = async (_, imports) => {
        bindings = imports.smoldot;
        return { exports: {
            memory, init() {}, advance_execution() {},
            connection_multi_stream_set_handshake_info(id, index) { calls.push(['metadata', id, readBuffer(index)]); },
            stream_message(id, stream, index) { calls.push(['message', id, stream, readBuffer(index)]); },
        } };
    };
    t.teardown(() => { WebAssembly.instantiate = original; });
    const instance = await startLocalInstance({ maxLogLevel: 0, cpuRateLimit: 1, performanceNow: () => 0 }, {}, event => events.push(event));
    t.teardown(() => instance.shutdownExecutor());
    const vector = new Uint8Array([18, 0x9c, 0x40, 1, 0, 0, 0, ...new Array(32).fill(7), ...new TextEncoder().encode('127.0.0.1')]);
    new Uint8Array(memory.buffer).set(vector, 100);
    bindings.connection_new(5, 100, vector.length);
    t.deepEqual(events[0], { ty: 'new-connection', connectionId: 5, address: decodeWebTransportAddress(vector) });
    t.is(bindings.connection_type_supported(18), 1);
    t.is(bindings.connection_type_supported(19), 1);
    instance.connectionMultiStreamSetHandshakeInfo(5, { handshake: 'webtransport' });
    instance.streamMessage(5, new Uint8Array([9]), 0);
    instance.streamMessage(5, new Uint8Array(0), 0);
    t.deepEqual(calls, [['metadata', 5, [2]], ['message', 5, 0, [9]], ['message', 5, 0, []]]);
});

test.serial('WT metadata is prompt while ready is unresolved; stream creation still waits', async t => {
    const sessions = host(t), cfg = config();
    const connection = connectWebTransport(cfg); t.teardown(() => connection.reset());
    connection.openOutSubstream(); await tick();
    t.deepEqual(cfg.events, [['ready', { handshake: 'webtransport' }]]);
    t.is(sessions[0].created.length, 0);
    sessions[0].readyControl.resolve(); await tick();
    t.is(sessions[0].created.length, 1);
    connection.reset(); const raw = rawStream(); sessions[0].created[0].resolve(raw.stream); await tick();
});

test.serial('RTC onopen does not grant credit after synchronous rejection', async t => {
    const original = globalThis.RTCPeerConnection;
    let pc;
    globalThis.RTCPeerConnection = class {
        static async generateCertificate() { return { getFingerprints: () => [{ algorithm: 'sha-256', value: new Array(32).fill('07').join(':') }] }; }
        constructor() { pc = this; }
        close() {}
    };
    t.teardown(() => { globalThis.RTCPeerConnection = original; });
    const cfg = config(); cfg.address = { ty: 'webrtc', targetIp: '192.0.2.1', targetPort: 1, ipVersion: '4', remoteTlsCertificateSha256: new Uint8Array(32) };
    let connection;
    cfg.onStreamOpened = id => connection.reset(id);
    connection = browserConnect(cfg); t.teardown(() => connection.reset()); await tick();
    const channel = { close() {} };
    pc.ondatachannel({ channel }); channel.onopen();
    t.false(cfg.events.some(event => event[0] === 'credit'));
});

for (const worker of [false, true]) for (const blocked of [false, true]) for (const unclaimed of [false, true]) {
    test.serial(`final response + FIN + immediate drop survives ${worker ? 'worker' : 'local'} delivery, blocked=${blocked}, unclaimed B=${unclaimed}`, async t => {
        const sessions = host(t), original = WebAssembly.instantiate;
        let bindings, connection, instance;
        const memory = new WebAssembly.Memory({ initial: 1 });
        const callbacksAfterDrop = [];
        const openedStreams = new Set(), droppedStreams = new Set();
        let dropped = false;
        WebAssembly.instantiate = async (_, imports) => {
            bindings = imports.smoldot;
            return { exports: {
                memory, init() {}, advance_execution() {},
                connection_multi_stream_set_handshake_info() {},
                connection_stream_opened(_, stream) { openedStreams.add(stream); },
                stream_reset(_, stream) { if (dropped || droppedStreams.has(stream)) callbacksAfterDrop.push('reset'); },
                stream_writable_bytes(_, stream) { if (dropped || droppedStreams.has(stream)) callbacksAfterDrop.push('credit'); },
                stream_message(id, stream, index) {
                    if (dropped || droppedStreams.has(stream)) callbacksAfterDrop.push('message');
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
            } };
        };
        t.teardown(() => { WebAssembly.instantiate = original; connection?.reset(); instance?.shutdownExecutor(); });
        const events = [];
        const eventCallback = event => {
            events.push(event);
            if (event.ty === 'new-connection') {
                connection = connectWebTransport({
                    address: event.address,
                    onMultistreamHandshakeInfo: info => instance.connectionMultiStreamSetHandshakeInfo(1, info),
                    onStreamOpened: (id, direction) => instance.streamOpened(1, id, direction),
                    onMessage: (data, id) => instance.streamMessage(1, data, id),
                    onWritableBytes: (bytes, id) => instance.streamWritableBytes(1, bytes, id),
                    onStreamReset: (id, reason) => instance.streamReset(1, id, reason),
                    onConnectionReset: () => { if (dropped) callbacksAfterDrop.push('connection-reset'); },
                });
            } else if (event.ty === 'stream-send') connection.send(event.data, event.streamId);
            else if (event.ty === 'stream-send-close') connection.closeSend(event.streamId);
            else if (event.ty === 'connection-stream-reset') connection.reset(event.streamId, event.graceful);
            else if (event.ty === 'connection-reset') connection.reset(undefined, event.graceful);
        };
        const configuration = { maxLogLevel: 0, cpuRateLimit: 1, performanceNow: () => 0, envVars: [], getRandomValues() {} };
        if (worker) {
            const { port1, port2 } = new MessageChannel();
            const server = startInstanceServer(configuration, port2);
            instance = await connectToInstanceServer({ ...configuration, wasmModule: Promise.resolve({}), portToServer: port1, eventCallback });
            while (!bindings) await tick();
            t.teardown(async () => { instance.shutdownExecutor(); await server; port1.close(); port2.close(); });
        } else instance = await startLocalInstance(configuration, {}, eventCallback);
        const address = new Uint8Array([18, 0x9c, 0x40, 1, 0, 0, 0, ...new Array(32).fill(7), ...new TextEncoder().encode('127.0.0.1')]);
        new Uint8Array(memory.buffer).set(address, 1000); bindings.connection_new(1, 1000, address.length);
        while (!sessions.length) await tick();
        sessions[0].readyControl.resolve(); await tick();
        const write = deferred(), raw = rawStream(() => blocked ? write.promise : undefined);
        sessions[0].incoming.enqueue(raw.stream); await tick();
        raw.controller.close();
        let rawB;
        if (unclaimed) {
            while (!events.some(event => event.ty === 'connection-stream-reset' && event.streamId === 0)) await tick();
            rawB = rawStream();
            sessions[0].incoming.enqueue(rawB.stream);
            while (!openedStreams.has(1)) await tick();
            // B was reported to Rust but remains unclaimed. Model MultiStreamWrapper's
            // drop imports: reset B BEFORE the final connection reset, even when final.
            droppedStreams.add(1);
            bindings.connection_stream_reset(1, 1);
            dropped = true;
            bindings.reset_connection(1);
        }
        while (!events.some(event => event.ty === 'connection-reset')) await tick();
        await tick();
        t.true(events.some(event => event.ty === 'connection-stream-reset' && event.graceful === true));
        t.true(events.some(event => event.ty === 'connection-reset' && event.graceful === true));
        t.deepEqual(raw.events.filter(Array.isArray), [[42]]);
        if (blocked) t.false(raw.events.includes('fin'));
        write.resolve(); await tick();
        t.true(raw.events.includes('fin'));
        if (unclaimed) {
            t.true(rawB.events.includes('abort'));
            t.true(rawB.events.includes('cancel'));
            t.false(rawB.events.includes('fin'));
            const drops = events.filter(event => event.ty === 'connection-stream-reset' || event.ty === 'connection-reset');
            t.deepEqual(drops.map(event => event.streamId), [0, 1, undefined]);
            t.is(drops[1].graceful, undefined);
            t.is(drops[2].graceful, true);
        }
        t.deepEqual(callbacksAfterDrop, []);
    });
}

test.serial('WT receive loop pauses until delivery acknowledgement', async t => {
    const { cfg, connection, session } = await setup(t);
    const ack = deferred(), received = [];
    cfg.onMessage = bytes => { received.push([...bytes]); return ack.promise; };
    const raw = rawStream(); await open(connection, session, raw);
    for (let i = 0; i < 10; ++i) raw.controller.enqueue(new Uint8Array([i]));
    await tick(); t.deepEqual(received, [[0]]);
    connection.reset(); ack.resolve(); await tick(); t.deepEqual(received, [[0]]);
});

test.serial('BYOB bounds each read even when the peer writes a larger buffer', async t => {
    const { cfg, connection, session } = await setup(t), sizes = [];
    cfg.onMessage = bytes => { sizes.push(bytes.length); };
    const raw = rawStream(); await open(connection, session, raw);
    raw.controller.enqueue(new Uint8Array(131073)); await tick();
    t.deepEqual(sizes, [65536, 65536, 1]);
    t.false(cfg.events.some(event => event[0].includes('reset')));
});

test.serial('retired writer failure closes the detached session without late callbacks', async t => {
    const { cfg, connection, session } = await setup(t), writing = deferred();
    const raw = rawStream(() => writing.promise); await open(connection, session, raw);
    raw.controller.close(); await tick();
    connection.send([new Uint8Array([42])], 0); connection.closeSend(0);
    connection.reset(0, true); connection.reset(undefined, true);
    const count = cfg.events.length;
    writing.reject(new Error('peer stopped receiving'));
    await session.closed; await tick();
    t.is(cfg.events.length, count);
});

test.serial('outbound stream creation requests have bounded admission too', async t => {
    const { cfg, connection, session } = await setup(t);
    for (let i = 0; i < 64; ++i) connection.openOutSubstream();
    await tick(); t.is(session.created.length, 64);
    connection.openOutSubstream(); await tick();
    t.is(cfg.events.filter(event => event[0] === 'reset').length, 1);
    for (const pending of session.created) pending.resolve(rawStream().stream);
    await tick(); t.false(cfg.events.some(event => event[0] === 'open'));
});

test.serial('inbound reset churn holds bounded admission slots until reset delivery', async t => {
    const { cfg, session } = await setup(t), ack = deferred();
    cfg.onStreamReset = () => ack.promise;
    const rawStreams = [];
    for (let i = 0; i < 64; ++i) {
        const raw = rawStream(); rawStreams.push(raw);
        session.incoming.enqueue(raw.stream); await tick(); raw.controller.error(new Error('peer reset')); await tick();
    }
    t.is(cfg.events.filter(event => event[0] === 'open').length, 64);
    session.incoming.enqueue(rawStream().stream); await tick();
    t.is(cfg.events.filter(event => event[0] === 'reset').length, 1);
    t.is(cfg.events.filter(event => event[0] === 'open').length, 64);
    ack.resolve(); await tick();
});

test.serial('worker delivery credits bound outstanding bytes and resume after acknowledgement', async t => {
    const { port1, port2 } = new MessageChannel();
    const pending = connectToInstanceServer({ wasmModule: Promise.resolve({}), portToServer: port1, eventCallback() {} });
    const server = await new Promise(resolve => { port2.onmessage = event => resolve(event.data.serverToClient); });
    const instance = await pending, messages = [];
    server.onmessage = event => messages.push(event.data);
    t.teardown(() => { port1.close(); port2.close(); server.close(); });
    server.postMessage({ ty: 'new-connection', connectionId: 1, address: config().address });
    await tick(); await tick();
    const writes = Array.from({ length: 65 }, () => instance.streamMessage(1, new Uint8Array(65536), 0));
    while (messages.length < 64) await tick();
    await tick(); t.is(messages.length, 64);
    server.postMessage({ ty: 'transport-delivered', deliveryId: messages[0].deliveryId });
    while (messages.length < 65) await tick();
    t.is(messages.length, 65);
    for (const message of messages.slice(1)) server.postMessage({ ty: 'transport-delivered', deliveryId: message.deliveryId });
    await Promise.all(writes);
    const tiny = Array.from({ length: 257 }, () => instance.streamMessage(1, new Uint8Array([1]), 0));
    while (messages.length < 65 + 256) await tick();
    await tick(); t.is(messages.length, 65 + 256);
    for (const message of messages.slice(65)) server.postMessage({ ty: 'transport-delivered', deliveryId: message.deliveryId });
    while (messages.length < 65 + 257) await tick();
    server.postMessage({ ty: 'transport-delivered', deliveryId: messages.at(-1).deliveryId });
    await Promise.all(tiny);
});
