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

import * as child_process from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as zlib from 'zlib';

// Which Cargo profile to use to compile the Rust. Should be either `debug` or `release`, based
// on the CLI options passed by the user.
let build_profile;
if (process.argv.slice(2).indexOf("--debug") !== -1) {
    build_profile = 'debug';
}
if (process.argv.slice(2).indexOf("--release") !== -1) {
    if (build_profile)
        throw new Error("Can't pass both --debug and --release");
    build_profile = 'min-size-release';
}
if (build_profile != 'debug' && build_profile != 'min-size-release')
    throw new Error("Either --debug or --release must be passed");

// The Rust version to use.
// The Rust version is pinned because the wasi target is still unstable. Without pinning, it is
// possible for the wasm-js bindings to change between two Rust versions. Feel free to update
// this version pin whenever you like, provided it continues to build.
const rust_version = '1.57.0';

// Assume that the user has `rustup` installed and make sure that `rust_version` is available.
// Because `rustup install` requires an Internet connection, check whether the toolchain is
// already installed before attempting it.
try {
    child_process.execSync(
        "rustup which --toolchain " + rust_version + " cargo",
        { 'stdio': 'inherit' }
    );
} catch (error) {
    child_process.execSync(
        "rustup install --no-self-update --profile=minimal " + rust_version,
        { 'stdio': 'inherit' }
    );
}
// `rustup target add` doesn't require an Internet connection if the target is already installed.
child_process.execSync(
    "rustup target add --toolchain=" + rust_version + " wasm32-wasi",
    { 'stdio': 'inherit' }
);

// The important step in this script is running `cargo build --target wasm32-wasi` on the Rust
// code. This generates a `wasm` file in `target/wasm32-wasi`.
child_process.execSync(
    "cargo +" + rust_version + " build --package smoldot-light-wasm --target wasm32-wasi --no-default-features " +
    (build_profile == 'debug' ? '' : ("--profile " + build_profile)),
    { 'stdio': 'inherit' }
);

// The code below will write a variable number of files to the `src/worker/autogen` directory.
// Start by clearing all existing files from this directory in case there are some left from past
// builds.
const filesToRemove = fs.readdirSync('./src/worker/autogen');
for (const file of filesToRemove) {
    if (!file.startsWith('.')) // Don't want to remove the `.gitignore` or `.npmignore` or similar
        fs.unlinkSync(path.join("./src/worker/autogen", file));
}

// It is then picked up by `wasm-opt`, which optimizes it and generates
// `./src/worker/autogen/tmp.wasm`. `wasm_opt` is purely about optimizing. If it isn't available,
// it is also possible to directly use the `.wasm` generated by the Rust compiler.
let fallback_copy = false;
try {
    if (build_profile == 'min-size-release') {
        child_process.execSync(
            "wasm-opt -o src/worker/autogen/tmp.wasm -Oz --strip-debug --vacuum --dce "
            + "../../../target/wasm32-wasi/" + build_profile + "/smoldot_light_wasm.wasm",
            { 'stdio': 'inherit' }
        );
    } else {
        fallback_copy = true;
    }
} catch (error) {
    console.warn("Failed to run `wasm-opt`. Using the direct Rust output instead.");
    console.warn(error);
    fallback_copy = true;
}
if (fallback_copy) {
    fs.copyFileSync("../../../target/wasm32-wasi/" + build_profile + "/smoldot_light_wasm.wasm", "./src/worker/autogen/tmp.wasm");
}

// At the time of writing, there is unfortunately no standard cross-platform solution to the
// problem of importing WebAssembly files. We base64-encode the .wasm file and integrate it as a
// string. It is the safe but non-optimal solution.
// Because raw .wasm compresses better than base64-encoded .wasm, we gzip the .wasm before base64
// encoding it. For some reason, `gzip(base64(gzip(wasm)))` is 15% to 20% smaller than
// `gzip(base64(wasm))`.
// Additionally, because the Mozilla extension store refuses packages containing individual files
// that are more than 4 MiB, we have to split our base64-encoded gzip-encoded wasm into multiple
// small size files.
const wasm_opt_out = fs.readFileSync('./src/worker/autogen/tmp.wasm');
let base64Data = zlib.deflateSync(wasm_opt_out).toString('base64');
let imports = '';
let fileNum = 0;
let chunksSum = '""';
while (base64Data.length != 0) {
    const chunk = base64Data.slice(0, 1024 * 1024);
    // We could simply export the chunk instead of a function that returns the chunk, but that
    // would cause TypeScript to generate a definitions file containing a copy of the entire chunk.
    fs.writeFileSync('./src/worker/autogen/wasm' + fileNum + '.ts', 'export default function(): string { return "' + chunk + '"; }');
    imports += 'import { default as wasm' + fileNum + ' } from \'./wasm' + fileNum + '.js\';\n';
    chunksSum += ' + wasm' + fileNum + '()';
    fileNum += 1;
    base64Data = base64Data.slice(1024 * 1024);
}
fs.writeFileSync('./src/worker/autogen/wasm.ts', imports + 'export default ' + chunksSum + ';');
fs.unlinkSync("./src/worker/autogen/tmp.wasm");
