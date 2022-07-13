// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

export function utf8BytesToString(buffer: Uint8Array, offset: number, length: number): string {
    checkRange(buffer, offset, length)

    // The `TextDecoder` API is supported by all major browsers and by NodeJS.
    // <https://developer.mozilla.org/en-US/docs/Web/API/TextDecoder>
    return new TextDecoder().decode(buffer.slice(offset, offset + length))
}

export function readUInt32LE(buffer: Uint8Array, offset: number): number {
    checkRange(buffer, offset, 4)
    return (buffer[offset]! | (buffer[offset + 1]! << 8) | (buffer[offset + 2]! << 16)) + (buffer[offset + 3]! * 0x1000000)
}

export function writeUInt32LE(buffer: Uint8Array, offset: number, value: number) {
    checkRange(buffer, offset, 4);
    buffer[offset + 3] = (value >>> 24) & 0xff
    buffer[offset + 2] = (value >>> 16) & 0xff
    buffer[offset + 1] = (value >>> 8) & 0xff
    buffer[offset] = value & 0xff
}

function checkRange(buffer: Uint8Array, offset: number, length: number) {
    if (!Number.isInteger(offset) || offset < 0)
        throw new RangeError()
    if (offset + length > buffer.length)
        throw new RangeError()
}

/**
 * Decodes a base64 string.
 *
 * The input is assumed to be correct.
 */
export function trustedBase64Decode(base64: string): Uint8Array {
    // This implementation was mostly copy-pasted (with some adjustments)
    // from <https://developer.mozilla.org/en-US/docs/Glossary/Base64>. As indicated in the
    // about section (<https://developer.mozilla.org/en-US/docs/MDN/About>), this code is in the
    // public domain.

    function b64ToUint6(nChr: number) {
        return nChr > 64 && nChr < 91 ?
            nChr - 65
            : nChr > 96 && nChr < 123 ?
                nChr - 71
                : nChr > 47 && nChr < 58 ?
                    nChr + 4
                    : nChr === 43 ?
                        62
                        : nChr === 47 ?
                            63
                            :
                            0;
    
    }

    const nInLen = base64.length
    const nOutLen = nInLen * 3 + 1 >> 2
    const taBytes = new Uint8Array(nOutLen);

    for (var nMod3, nMod4, nUint24 = 0, nOutIdx = 0, nInIdx = 0; nInIdx < nInLen; nInIdx++) {
        nMod4 = nInIdx & 3;
        nUint24 |= b64ToUint6(base64.charCodeAt(nInIdx)) << 6 * (3 - nMod4);
        if (nMod4 === 3 || nInLen - nInIdx === 1) {
            for (nMod3 = 0; nMod3 < 3 && nOutIdx < nOutLen; nMod3++, nOutIdx++) {
                taBytes[nOutIdx] = nUint24 >>> (16 >>> nMod3 & 24) & 255;
            }
            nUint24 = 0;

        }
    }

    return taBytes;
}
