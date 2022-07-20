"use strict";
// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.startInstance = exports.ConnectionError = void 0;
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
const bindings_smoldot_light_js_1 = require("./bindings-smoldot-light.js");
const bindings_wasi_js_1 = require("./bindings-wasi.js");
const wasm_js_1 = require("./autogen/wasm.js");
var bindings_smoldot_light_js_2 = require("./bindings-smoldot-light.js");
Object.defineProperty(exports, "ConnectionError", { enumerable: true, get: function () { return bindings_smoldot_light_js_2.ConnectionError; } });
function startInstance(config, platformBindings) {
    return __awaiter(this, void 0, void 0, function* () {
        // The actual Wasm bytecode is base64-decoded then deflate-decoded from a constant found in a
        // different file.
        // This is suboptimal compared to using `instantiateStreaming`, but it is the most
        // cross-platform cross-bundler approach.
        const wasmBytecode = yield platformBindings.base64DecodeAndZlibInflate(wasm_js_1.default);
        let killAll;
        // Used to bind with the smoldot-light bindings. See the `bindings-smoldot-light.js` file.
        const smoldotJsConfig = Object.assign({ performanceNow: platformBindings.performanceNow, connect: platformBindings.connect, onPanic: (message) => {
                killAll();
                config.onWasmPanic(message);
                throw new Error();
            } }, config);
        // Used to bind with the Wasi bindings. See the `bindings-wasi.js` file.
        const wasiConfig = {
            envVars: [],
            getRandomValues: platformBindings.getRandomValues,
            onProcExit: (retCode) => {
                killAll();
                config.onWasmPanic(`proc_exit called: ${retCode}`);
                throw new Error();
            }
        };
        const { imports: smoldotBindings, killAll: smoldotBindingsKillAll } = (0, bindings_smoldot_light_js_1.default)(smoldotJsConfig);
        killAll = smoldotBindingsKillAll;
        // Start the Wasm virtual machine.
        // The Rust code defines a list of imports that must be fulfilled by the environment. The second
        // parameter provides their implementations.
        const result = yield WebAssembly.instantiate(wasmBytecode, {
            // The functions with the "smoldot" prefix are specific to smoldot.
            "smoldot": smoldotBindings,
            // As the Rust code is compiled for wasi, some more wasi-specific imports exist.
            "wasi_snapshot_preview1": (0, bindings_wasi_js_1.default)(wasiConfig),
        });
        const instance = result.instance;
        smoldotJsConfig.instance = instance;
        wasiConfig.instance = instance;
        return instance;
    });
}
exports.startInstance = startInstance;
