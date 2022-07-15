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

// TODO: the line below is completely wrong but necessary for WebAssembly; see https://github.com/microsoft/TypeScript-DOM-lib-generator/issues/826
/// <reference lib="dom" />

import type { Socket as TcpSocket, NetConnectOpts } from 'node:net';

export type WasmModuleImports = WebAssembly.ModuleImports;

export function isTcpAvailable(): boolean;

export function createConnection(options: NetConnectOpts, connectionListener?: () => void): TcpSocket;

export function getRandomValues<T extends ArrayBufferView>(buffer: T): void;
