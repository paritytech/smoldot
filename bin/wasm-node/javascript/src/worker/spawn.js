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

import { Worker } from 'worker_threads';

export default function () {
    // The line of code below (`new Worker(...)`) is designed to hopefully work across all
    // platforms and bundlers.
    // Because this line is precisely recognized by bundlers, we extract it to a separate
    // JavaScript file.
    // See also the README.md for more context.
    const worker = new Worker(new URL('./worker.js', import.meta.url));
    return worker;
}
