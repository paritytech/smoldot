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

// This small dummy module re-exports some types from NodeJS.
//
// A rule in the `package.json` overrides it with `compat-browser` when in a browser.

import { Timeout, CompatWorker, TcpConnectionOptions } from './index';
import { parentPort, MessagePort, Worker as NodeJsWorker } from 'worker_threads';

import * as net from 'net';

export function compatSetTimeout(callback: () => void, timeout: number): Timeout {
    return setTimeout(callback, timeout)
}

export function compatClearTimeout(timeout: Timeout) {
    clearTimeout(timeout as NodeJS.Timeout)
}

export function workerOnMessage(worker: CompatWorker, callback: (message: any) => void) {
    (worker as NodeJsWorker).on('message', callback)
}

export function workerOnError(worker: CompatWorker, callback: (error: any) => void) {
    (worker as NodeJsWorker).on('error', callback)
}

export async function workerTerminate(worker: CompatWorker): Promise<void> {
    (worker as NodeJsWorker).terminate().then(() => { })
}

export function isTcpAvailable(): boolean {
    return true;
}

export function createTcpConnection(opts: TcpConnectionOptions) {
    return net.createConnection(opts);
}

export function postMessage(msg: any) {
    // TODO: this `as` is a bit of a hack, but solving this properly is not worth the effort at this time
    (parentPort as MessagePort).postMessage(msg)
}

export function setOnMessage(callback: (message: any) => void) {
    // TODO: this `as` is a bit of a hack, but solving this properly is not worth the effort at this time
    (parentPort as MessagePort).on('message', callback)
}
