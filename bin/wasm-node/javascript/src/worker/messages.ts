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

/**
 * Message to the worker.
 *
 * The first ever message sent to the worker must be a `ToWorkerConfig`, then all subsequent
 * messages must be `ToWorkerNonConfig`s.
 */
export type ToWorker = ToWorkerConfig | ToWorkerNonConfig;
export type ToWorkerNonConfig = ToWorkerRpcRequest | ToWorkerAddChain | ToWorkerRemoveChain | ToWorkerDatabaseContent;

export type FromWorker = FromWorkerChainAddedOk | FromWorkerChainAddedError | FromWorkerChainRemoved | FromWorkerLog | FromWorkerJsonRpc | FromWorkerDatabaseContent | FromWorkerLivenessPing;

export interface ToWorkerConfig {
  maxLogLevel: number;
  forbidTcp: boolean;
  forbidWs: boolean;
  forbidNonLocalWs: boolean;
  forbidWss: boolean;
}

export interface ToWorkerRpcRequest {
  ty: 'request',
  request: string,
  chainId: number,
}

export interface ToWorkerAddChain {
  ty: 'addChain',
  chainSpec: string,
  databaseContent: string,
  potentialRelayChains: number[],
  jsonRpcRunning: boolean,
}

export interface ToWorkerRemoveChain {
  ty: 'removeChain',
  chainId: number,
}

export interface ToWorkerDatabaseContent {
  ty: 'databaseContent',
  chainId: number,
  maxUtf8BytesSize: number,
}

export interface FromWorkerChainAddedOk {
  kind: 'chainAddedOk',
  chainId: number,
}

export interface FromWorkerChainAddedError {
  kind: 'chainAddedErr',
  error: Error,
}

export interface FromWorkerChainRemoved {
  kind: 'chainRemoved',
}

export interface FromWorkerLog {
  kind: 'log',
  level: number,
  target: string,
  message: string,
}

export interface FromWorkerJsonRpc {
  kind: 'jsonrpc',
  data: string,
  chainId: number,
}

export interface FromWorkerDatabaseContent {
  kind: 'databaseContent',
  data: string,
  chainId: number,
}

export interface FromWorkerLivenessPing {
  kind: 'livenessPing',
}
