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

export default function () {
    if (!window.Worker)
        throw new Error("Workers not available");

    // The line of code below (`new Worker(...)`) is designed to hopefully work across all
    // platforms and bundlers.
    // Because this line is precisely recognized by bundlers, we extract it to a separate
    // JavaScript file.
    // See also the README.md for more context.

    // Note that, at the time of writing, Firefox doesn't support the `type: "module"` option.
    // Because browsers don't fully support modules yet, this code is expected to be run through
    // a bundler (e.g. WebPack) before being given to a browser, which will remove all usage of
    // modules in the worker code. It is thus also the role of this bundler to tweak or remove
    // the value of this `type` property to indicate to the browser that modules aren't in use.
    //
    // It is unclear whether bundlers actually do this. Whether bundlers actually do this or not,
    // it is nonetheless more correct to indicate `type: "module"` and doing so doesn't have any
    // drawback.
    const worker = new Worker(new URL('./worker.js', import.meta.url), { name: "smoldot", type: "module" });
    return worker;
}
