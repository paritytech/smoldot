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
// Overrides `index.js` when in a browser.
export function workerOnMessage(worker, callback) {
    worker.onmessage = (event) => callback(event.data);
}
export function workerOnError(worker, callback) {
    worker.onerror = (event) => {
        // For reference:
        // https://html.spec.whatwg.org/multipage/indices.html#event-error
        // https://html.spec.whatwg.org/multipage/webappapis.html#errorevent
        // If `event.error` exists, then it will likely be an instance of `Error`.
        // However, that's not guaranteed by the spec and it could also be
        // something else. So, our second best try is the `event.message`
        // property. Finally, our last resort is to create an Error from the event.
        if (event.error instanceof Error)
            callback(event.error);
        else
            callback(new Error(event.message || event));
    };
}
export function workerTerminate(worker) {
    worker.terminate();
    return Promise.resolve();
}
export function postMessage(msg) {
    self.postMessage(msg);
}
export function setOnMessage(callback) {
    self.onmessage = (event) => callback(event.data);
}
export function performanceNow() {
    return performance.now();
}
export function isTcpAvailable() {
    return false;
}
export function createConnection(_opts, _connectionListener) {
    throw new Error('TCP connections not available');
}
export function getRandomValues(buffer) {
    const crypto = globalThis.crypto;
    if (!crypto)
        throw new Error('randomness not available');
    crypto.getRandomValues(buffer);
}
