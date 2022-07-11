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

/**
 * Message that the worker can send to the outside.
 */
export type FromWorker = FromWorkerChainAddedOk | FromWorkerChainAddedError | FromWorkerLog | FromWorkerJsonRpc | FromWorkerDatabaseContent | FromWorkerCurrentTask;

/**
 * Contains the initial configuration of the worker.
 *
 * This message is only ever sent once, and it is always the first ever message sent to the
 * worker.
 */
export interface ToWorkerConfig {
  maxLogLevel: number;
  enableCurrentTask: boolean;
  cpuRateLimit: number,
  forbidTcp: boolean;
  forbidWs: boolean;
  forbidNonLocalWs: boolean;
  forbidWss: boolean;
}

/**
 * Start a JSON-RPC request.
 */
export interface ToWorkerRpcRequest {
  ty: 'request',
  request: string,
  chainId: number,
}

/**
 * Add a new chain.
 *
 * The worker must reply with either a `FromWorkerChainAddedOk` or a `FromWorkerChainAddedError`.
 */
export interface ToWorkerAddChain {
  ty: 'addChain',
  chainSpec: string,
  databaseContent: string,
  potentialRelayChains: number[],
  jsonRpcRunning: boolean,
}

/**
 * Remove a chain.
 *
 * The worker must reply with a `FromWorkerChainRemoved`.
 */
export interface ToWorkerRemoveChain {
  ty: 'removeChain',
  chainId: number,
}

/**
 * Get the database content of a chain.
 *
 * The worker must reply with a `FromWorkerDatabaseContent`.
 */
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
  error: string,
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

export interface FromWorkerCurrentTask {
  kind: 'currentTask',
  taskName: string | null,
}
