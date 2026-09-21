// Smoldot
// Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
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

// Runs one smoldot client's Wasm on a worker thread. `index.mjs` starts one of these per client
// and hands it one end of a `MessageChannel`; the other end goes to `startWithBytecode`, whose
// returned client is then only a frontend to what runs here.

import { parentPort } from 'node:worker_threads';
import { run } from '../../wasm-node/javascript/dist/mjs/worker-nodejs.js';

const port = await new Promise((resolve) => parentPort.once('message', resolve));
// The outer promise resolves once the client is running, the inner one once it is terminated.
await run(port);
