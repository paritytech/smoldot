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
let rfc4648Alphabet = new Map();
const rfc4648AlphabetAsStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
for (let i = 0; i < rfc4648AlphabetAsStr.length; ++i) {
    rfc4648Alphabet.set(rfc4648AlphabetAsStr[i], i);
}
let urlSafeAlphabet = new Map();
const urlSafeAlphabetAsStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
for (let i = 0; i < urlSafeAlphabetAsStr.length; ++i) {
    urlSafeAlphabet.set(urlSafeAlphabetAsStr[i], i);
}
/**
 * Decodes a multibase-encoded string.
 *
 * Throws an exception if the encoding isn't base64 or one of its variants.
 */
export function multibaseBase64Decode(input) {
    if (input.length === 0)
        throw new Error("Invalid multibase");
    switch (input[0]) {
        case 'm':
        case 'M':
            return classicDecode(input.slice(1));
        case 'u':
        case 'U':
            return urlSafeDecode(input.slice(1));
        default:
            throw new Error('Unknown multibase prefix: ' + input[0]);
    }
}
/**
 * Decodes a base64-encoded string into bytes using the original alphabet from RFC4648.
 *
 * See <https://datatracker.ietf.org/doc/html/rfc4648#section-4>.
 */
export function classicDecode(input) {
    return base64Decode(input, rfc4648Alphabet);
}
/**
 * Decodes a base64-encoded string into bytes using the URL-safe alphabet.
 *
 * See <https://datatracker.ietf.org/doc/html/rfc4648#section-5>.
 */
export function urlSafeDecode(input) {
    return base64Decode(input, urlSafeAlphabet);
}
/**
 * Decodes a base64-encoded string into bytes using the given alphabet.
 */
export function base64Decode(input, alphabet) {
    // Remove the padding bytes at the end of the string. We don't check whether the padding is
    // accurate.
    while (input.length !== 0 && input[input.length - 1] === '=')
        input = input.slice(0, -1);
    // Contains the output data.
    const out = new Uint8Array(Math.floor(input.length * 6 / 8));
    // Position within `out` of the next byte to write.
    let outPos = 0;
    // The bits decoded from the input are added to the right of this value.
    let currentByte = 0;
    // The left-most `validBitsInCurrentByte` bits of `currentByte` must be written out.
    let validBitsInCurrentByte = 0;
    for (let i = 0; i < input.length; ++i) {
        const inputChr = input[i];
        const bitsToAppend = alphabet.get(inputChr);
        if (bitsToAppend === undefined)
            throw new Error('Invalid base64 character: ' + inputChr);
        console.assert(bitsToAppend < (1 << 6));
        currentByte = (currentByte << 6) | bitsToAppend;
        validBitsInCurrentByte += 6;
        if (validBitsInCurrentByte >= 8) {
            let outByte = currentByte >> (validBitsInCurrentByte - 8);
            out[outPos] = outByte;
            outPos += 1;
            validBitsInCurrentByte -= 8;
        }
        console.assert(validBitsInCurrentByte < 8);
        currentByte &= 0xff;
    }
    if ((currentByte & ((1 << validBitsInCurrentByte) - 1)) !== 0)
        throw new Error("Unexpected EOF");
    if (validBitsInCurrentByte >= 6)
        throw new Error("Unexpected EOF");
    return out;
}
