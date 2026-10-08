// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
import test from 'ava';
import { fromHex, probe, frameReader } from '../demo/webtransport-probe.mjs';

test('UP 0 probe has stream kind outside its 37-byte frame', t => {
    const bytes = probe(fromHex('07'.repeat(32)));
    t.is(bytes.length, 42);
    t.deepEqual([...bytes.slice(0, 5)], [0, 37, 0, 0, 0]);
    t.deepEqual([...bytes.slice(5, 37)], new Array(32).fill(7));
    t.deepEqual([...bytes.slice(37)], [0, 0, 0, 0, 0]);
    t.throws(() => fromHex('00')); t.throws(() => fromHex('zz'.repeat(32)));
});

test('probe frame reader tolerates every split and rejects oversized frames', t => {
    const bytes = new Uint8Array([3, 0, 0, 0, 4, 5, 6, 1, 0, 0, 0, 7]);
    for (let split = 0; split <= bytes.length; split++) {
        const frames = []; const feed = frameReader(frame => frames.push([...frame]));
        feed(bytes.slice(0, split)); feed(bytes.slice(split));
        t.deepEqual(frames, [[4, 5, 6], [7]]);
    }
    const feed = frameReader(() => {}, 100);
    t.throws(() => feed(new Uint8Array([101, 0, 0, 0])));
});
