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

// TODO: remove this reference thing /!\ it's completely wrong
/// <reference lib="dom" />

import type { Socket as TcpSocket, NetConnectOpts } from 'net';

export type WasmModuleImports = WebAssembly.ModuleImports;

export interface CompatWorker {
    postMessage(value: any, transferList?: ReadonlyArray<ArrayBuffer | MessagePort | Blob>): void;
    addListener(event: 'error', listener: (err: Error) => void): this;
    addListener(event: 'message', listener: (value: any) => void): this;
    removeListener(event: 'error', listener: (err: Error) => void): this;
    removeListener(event: 'message', listener: (value: any) => void): this;
}

export function workerTerminate(worker: CompatWorker): Promise<void>;

export function postMessage(message: any): void;

export function setOnMessage(callback: (message: any) => void): void;

export function performanceNow(): number;

export function isTcpAvailable(): boolean;

export function createConnection(options: NetConnectOpts, connectionListener?: () => void): TcpSocket;

export function getRandomValues<T extends ArrayBufferView>(buffer: T): void;
