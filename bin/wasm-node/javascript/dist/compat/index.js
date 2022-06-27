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
// This small dummy module re-exports types and functions from NodeJS.
//
// A rule in the `package.json` overrides it with `index-browser-override.js` when in a browser.
import { parentPort } from 'node:worker_threads';
import { hrtime } from 'node:process';
import { createConnection as nodeCreateConnection } from 'node:net';
import { randomFillSync } from 'node:crypto';
export function workerOnMessage(worker, callback) {
    worker.on('message', callback);
}
export function workerOnError(worker, callback) {
    worker.on('error', callback);
}
export function workerTerminate(worker) {
    return worker.terminate().then(() => { });
}
export function postMessage(msg) {
    parentPort.postMessage(msg);
}
export function setOnMessage(callback) {
    parentPort.on('message', callback);
}
export function performanceNow() {
    const time = hrtime();
    return ((time[0] * 1e3) + (time[1] / 1e6));
}
export function isTcpAvailable() {
    return true;
}
export function createConnection(opts, connectionListener) {
    return nodeCreateConnection(opts, connectionListener);
}
export function getRandomValues(buffer) {
    if (buffer.length >= 65536)
        throw new Error('getRandomValues buffer too large');
    randomFillSync(buffer);
}
