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

import { Client, ClientOptions } from './public-types.js'
import { startWithBytecode } from './no-auto-bytecode-browser.js'
import { compileBytecode } from './bytecode-browser.js'

export {
    AddChainError,
    AddChainOptions,
    AlreadyDestroyedError,
    Chain,
    Client,
    ClientOptions,
    ClientOptionsWithBytecode,
    SmoldotBytecode,
    CrashError,
    JsonRpcDisabledError,
    QueueFullError,
    LogCallback,
    SyncProgress
} from './public-types.js';

/**
 * Initializes a new client. This is a pre-requisite to connecting to a blockchain.
 *
 * Can never fail.
 *
 * @param options Configuration of the client. Defaults to `{}`.
 */
export function start(options?: ClientOptions): Client {
    options = options || {};
    return startWithBytecode({ bytecode: compileBytecode(), ... options })
}
