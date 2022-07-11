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
export type ToWorkerNonConfig = ToWorkerRpcRequest | ToWorkerAddChain | ToWorkerRemoveChain;

/**
 * Contains the initial configuration of the worker.
 *
 * This message is only ever sent once, and it is always the first ever message sent to the
 * worker.
 */
export interface ToWorkerConfig {
  logCallback: (level: number, target: string, message: string) => void
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
  jsonRpcCallback?: (response: string) => void,
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
