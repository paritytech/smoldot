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

import { Client, ClientOptions, start as innerStart } from './client.js'

import { hrtime } from 'node:process';
import { createConnection as nodeCreateConnection } from 'node:net';
import { randomFillSync } from 'node:crypto';

export {
  AddChainError,
  AddChainOptions,
  AlreadyDestroyedError,
  Chain,
  Client,
  ClientOptions,
  CrashError,
  JsonRpcCallback,
  JsonRpcDisabledError,
  LogCallback
} from './client.js';

/**
 * Initializes a new client. This is a pre-requisite to connecting to a blockchain.
 *
 * Can never fail.
 *
 * @param options Configuration of the client. Defaults to `{}`.
 */
export function start(options?: ClientOptions): Client {
  return innerStart(options || {}, {
    performanceNow: () => {
      const time = hrtime();
      return ((time[0] * 1e3) + (time[1] / 1e6));
    },
    getRandomValues: (buffer) => {
      if (buffer.length >= 65536)
        throw new Error('getRandomValues buffer too large')
      randomFillSync(buffer)
    },
    isTcpAvailable: () => {
      return true;
    },
    createConnection: (opts, connectionListener) => {
      return nodeCreateConnection(opts, connectionListener)
    },
  })
}
