// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

export function fromHex(text) {
    if (!/^[0-9a-fA-F]{64}$/.test(text)) throw new Error('Expected 32 bytes as 64 hexadecimal digits');
    return Uint8Array.from(text.match(/../g), byte => parseInt(byte, 16));
}

export function probe(genesisHash) {
    if (genesisHash.length !== 32) throw new Error('Expected a 32-byte genesis hash');
    const bytes = new Uint8Array(42);
    // Stream kind 0 precedes the 37-byte framed handshake (it is not part of the frame).
    new DataView(bytes.buffer).setUint32(1, 37, true);
    bytes.set(genesisHash, 5);
    // Slot zero and zero leaves are already zero-filled.
    return bytes;
}

export function frameReader(onFrame, limit = 1024 * 1024) {
    let pending = new Uint8Array(0);
    return bytes => {
        const joined = new Uint8Array(pending.length + bytes.length);
        joined.set(pending); joined.set(bytes, pending.length);
        let offset = 0;
        while (joined.length - offset >= 4) {
            const length = new DataView(joined.buffer).getUint32(offset, true);
            if (length > limit) throw new Error('Peer frame exceeds probe limit');
            if (joined.length - offset - 4 < length) break;
            onFrame(joined.slice(offset + 4, offset + 4 + length));
            offset += 4 + length;
        }
        pending = joined.slice(offset);
        if (pending.length > limit + 4) throw new Error('Peer buffer exceeds probe limit');
    };
}
