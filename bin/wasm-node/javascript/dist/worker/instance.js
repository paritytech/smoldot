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
import pako from 'pako';
import { Buffer } from 'buffer';
import { default as smolditLightBindingsBuilder } from './bindings-smoldot-light.js';
import { default as wasiBindingsBuilder } from './bindings-wasi.js';
import { default as wasmBase64 } from './autogen/wasm.js';
export async function startInstance(config) {
    // The actual Wasm bytecode is base64-decoded then gzip-decoded from a constant found in a
    // different file.
    // This is suboptimal compared to using `instantiateStreaming`, but it is the most
    // cross-platform cross-bundler approach.
    const wasmBytecode = pako.inflate(new Uint8Array(Buffer.from(wasmBase64, 'base64')));
    // Used to bind with the smoldot-light bindings. See the `bindings-smoldot-light.js` file.
    const smoldotJsConfig = {
        ...config
    };
    // Used to bind with the Wasi bindings. See the `bindings-wasi.js` file.
    const wasiConfig = {
        envVars: [],
    };
    // Start the Wasm virtual machine.
    // The Rust code defines a list of imports that must be fulfilled by the environment. The second
    // parameter provides their implementations.
    const result = await WebAssembly.instantiate(wasmBytecode, {
        // The functions with the "smoldot" prefix are specific to smoldot.
        "smoldot": smolditLightBindingsBuilder(smoldotJsConfig),
        // As the Rust code is compiled for wasi, some more wasi-specific imports exist.
        "wasi_snapshot_preview1": wasiBindingsBuilder(wasiConfig),
    });
    const instance = result.instance;
    smoldotJsConfig.instance = instance;
    wasiConfig.instance = instance;
    return instance;
}
