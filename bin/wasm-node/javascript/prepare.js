// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
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

// Which Cargo profile to use to compile the Rust. Should be either `debug` or `release`.
const build_profile = 'release';

// The Rust version to use.
// The Rust version is pinned because the wasi target is still unstable. Without pinning, it is
// possible for the wasm-js bindings to change between two Rust versions. Feel free to update
// this version pin whenever you like, provided it continues to build.
const rust_version = '1.51.0';

// Assume that the user has `rustup` installed and make sure that `rust_version` is available.
// Because `rustup install` requires an Internet connection, check whether the toolchain is
// already installed before attempting it.
try {
    child_process.execSync("rustup which --toolchain " + rust_version + " cargo");
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
    "cargo +" + rust_version + " build --package smoldot-js --target wasm32-wasi --no-default-features"
    + (build_profile == 'debug' ? '' : ' --' + build_profile),
    { 'stdio': 'inherit' }
);

// It is then picked up by `wasm-opt`, which optimizes it and generates `./src/autogen/tmp.wasm`.
// `wasm_opt` is purely about optimizing. If it isn't available, it is also possible to directly
// use the `.wasm` generated by the Rust compiler.
let fallback_copy = false;
try {
    if (build_profile == 'release') {
        child_process.execSync(
            "wasm-opt -o src/autogen/tmp.wasm -Os --strip-debug --vacuum --dce "
            + "../../../target/wasm32-wasi/" + build_profile + "/smoldot_js.wasm",
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
    fs.copyFileSync("../../../target/wasm32-wasi/" + build_profile + "/smoldot_js.wasm", "./src/autogen/tmp.wasm");
}

// We then base64-encode the `.wasm` file, and put this base64 string as a constant in
// `./src/autogen/wasm.js`. It will be decoded at runtime.
let wasm_opt_out = fs.readFileSync('./src/autogen/tmp.wasm');
let base64_data = wasm_opt_out.toString('base64');
fs.writeFileSync('./src/autogen/wasm.js', 'export default "' + base64_data + '";');
fs.unlinkSync("./src/autogen/tmp.wasm");

// The reason for this script is that at the time of writing, there isn't any standard
// cross-platform solution to the problem of importing WebAssembly files. Base64-encoding the
// .wasm file and integrating it as a string is the safe but non-optimal solution.
