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

import * as child_process from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as zlib from 'node:zlib';

// Which Cargo profile to use to compile the Rust. Should be either `debug` or `release`, based
// on the CLI options passed by the user.
let buildProfile;
if (process.argv.slice(2).indexOf("--debug") !== -1) {
    buildProfile = 'debug';
}
if (process.argv.slice(2).indexOf("--release") !== -1) {
    if (buildProfile)
        throw new Error("Can't pass both --debug and --release");
    buildProfile = 'min-size-release';
}
if (buildProfile != 'debug' && buildProfile != 'min-size-release')
    throw new Error("Either --debug or --release must be passed");

// Pick the wasm target by probing the installed Rust toolchain.
const sysroot = child_process.execSync('rustc --print sysroot', { encoding: 'utf-8' }).trim();
const isTargetInstalled = (target) =>
    fs.existsSync(path.join(sysroot, 'lib', 'rustlib', target, 'lib'));
let wasmTarget;
if (isTargetInstalled('wasm32v1-none')) {
    wasmTarget = 'wasm32v1-none';
} else if (isTargetInstalled('wasm32-unknown-unknown')) {
    wasmTarget = 'wasm32-unknown-unknown';
} else {
    throw new Error(
        "Neither `wasm32v1-none` nor `wasm32-unknown-unknown` is installed for the current Rust " +
        "toolchain. Install one of them (e.g. `rustup target add wasm32v1-none`) and retry."
    );
}

// The important step in this script is running `cargo build --target <wasmTarget>` on the Rust
// code. This generates a `wasm` file in `target/<wasmTarget>`.
// No optional Wasm features is enabled due to being an unstable part of the Rust compiler.
// Additionally, SIMD should not be enabled, because WASM engines seem to allow only SIMD
// instructions on specific hardware. See for example <https://bugzilla.mozilla.org/show_bug.cgi?id=1625130#c11>
// and <https://bugzilla.mozilla.org/show_bug.cgi?id=1840710>.
child_process.execSync(
    "cargo build --package smoldot-light-wasm --target " + wasmTarget + " --no-default-features " +
    (buildProfile == 'debug' ? '' : ("--profile " + buildProfile)),
    { 'stdio': 'inherit' }
);
const rustOutput = "../../target/" + wasmTarget + "/" + buildProfile + "/smoldot_light_wasm.wasm";

// The code below will write a variable number of files to the `src/internals/bytecode` directory.
// Start by clearing all existing files from this directory in case there are some left from past
// builds.
const filesToRemove = fs.readdirSync('./src/internals/bytecode');
for (const file of filesToRemove) {
    if (!file.startsWith('.')) // Don't want to remove the `.gitignore` or `.npmignore` or similar
        fs.unlinkSync(path.join("./src/internals/bytecode", file));
}

// At the time of writing, there is unfortunately no standard cross-platform solution to the
// problem of importing WebAssembly files. We base64-encode the .wasm file and integrate it as
// a string. It is the safe but non-optimal solution.
// Because raw .wasm compresses better than base64-encoded .wasm, we deflate the .wasm before
// base64 encoding it. For some reason, `deflate(base64(deflate(wasm)))` is 15% to 20% smaller
// than `deflate(base64(wasm))`.
// Additionally, because the Mozilla extension store refuses packages containing individual
// files that are more than 4 MiB, we have to split our base64-encoded deflate-encoded wasm
// into multiple small size files.
const finalWasmData = fs.readFileSync(rustOutput);
let base64Data = zlib.deflateSync(finalWasmData).toString('base64');
let imports = '';
let fileNum = 0;
let chunksSum = '""';
while (base64Data.length != 0) {
    const chunk = base64Data.slice(0, 1024 * 1024);
    // We could simply export the chunk instead of a function that returns the chunk, but that
    // would cause TypeScript to generate a definitions file containing a copy of the entire chunk.
    fs.writeFileSync('./src/internals/bytecode/wasm' + fileNum + '.ts', 'export default function(): string { return "' + chunk + '"; }');
    imports += 'import { default as wasm' + fileNum + ' } from \'./wasm' + fileNum + '.js\';\n';
    chunksSum += ' + wasm' + fileNum + '()';
    fileNum += 1;
    base64Data = base64Data.slice(1024 * 1024);
}
fs.writeFileSync(
    './src/internals/bytecode/wasm.ts',
    imports +
    'export default ' + chunksSum
);
