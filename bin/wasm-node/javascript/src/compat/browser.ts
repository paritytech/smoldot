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

/// <reference lib="dom" />

// Overrides `compat-nodejs` when in a browser.

import { Timeout, CompatWorker } from './index.js';

export function compatSetTimeout(callback: () => void, timeout: number): Timeout {
    return setTimeout(callback, timeout)
}

export function compatClearTimeout(timeout: Timeout) {
    clearTimeout(timeout as number)
}

export function workerOnMessage(worker: CompatWorker, callback: (message: any) => void) {
    (worker as Worker).onmessage = (event: MessageEvent) => callback(event.data)
}

export function workerOnError(worker: CompatWorker, callback: (error: any) => void) {
    (worker as Worker).onerror = callback;
}

export async function workerTerminate(worker: CompatWorker): Promise<void> {
    (worker as Worker).terminate();
    return Promise.resolve();
}

export function isTcpAvailable(): boolean {
    return false;
}

export function postMessage(msg: any) {
    self.postMessage(msg)
}

export function setOnMessage(callback: (message: any) => void) {
    self.onmessage = (event: MessageEvent) => callback(event.data)
}
