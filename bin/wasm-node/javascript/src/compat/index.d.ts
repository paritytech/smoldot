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

export type WasmModuleImports = WebAssembly.ModuleImports;

declare class CompatWorker {

}

// TODO: worker shouldn't be any
export function workerOnMessage(worker: any, callback: (message: any) => void): void;
export function workerOnError(worker: any, callback: (error: Error) => void): void;
export function workerTerminate(worker: any): Promise<void>;

export function postMessage(message: any): void;
export function setOnMessage(callback: (message: any) => void): void;

export function performanceNow(): number;

export function isTcpAvailable(): boolean;
