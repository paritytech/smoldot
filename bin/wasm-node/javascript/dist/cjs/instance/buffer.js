"use strict";
// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
Object.defineProperty(exports, "__esModule", { value: true });
exports.writeUInt32LE = exports.writeUInt8 = exports.readUInt32LE = exports.utf8BytesToString = void 0;
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
function utf8BytesToString(buffer, offset, length) {
    checkRange(buffer, offset, length);
    // The `TextDecoder` API is supported by all major browsers and by NodeJS.
    // <https://developer.mozilla.org/en-US/docs/Web/API/TextDecoder>
    return new TextDecoder().decode(buffer.slice(offset, offset + length));
}
exports.utf8BytesToString = utf8BytesToString;
function readUInt32LE(buffer, offset) {
    checkRange(buffer, offset, 4);
    return (buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16)) + (buffer[offset + 3] * 0x1000000);
}
exports.readUInt32LE = readUInt32LE;
/**
 * Sets the value of a given byte in the buffer.
 *
 * This function is equivalent to `buffer[offset] = value`, except that an exception is thrown
 * if `offset` is out of range.
 */
function writeUInt8(buffer, offset, value) {
    checkRange(buffer, offset, 1);
    buffer[offset] = value & 0xff;
}
exports.writeUInt8 = writeUInt8;
function writeUInt32LE(buffer, offset, value) {
    checkRange(buffer, offset, 4);
    buffer[offset + 3] = (value >>> 24) & 0xff;
    buffer[offset + 2] = (value >>> 16) & 0xff;
    buffer[offset + 1] = (value >>> 8) & 0xff;
    buffer[offset] = value & 0xff;
}
exports.writeUInt32LE = writeUInt32LE;
function checkRange(buffer, offset, length) {
    if (!Number.isInteger(offset) || offset < 0)
        throw new RangeError();
    if (offset + length > buffer.length)
        throw new RangeError();
}
