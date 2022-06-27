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
import { Buffer } from 'buffer';
import * as compat from './../compat/index.js';
import * as instance from './instance.js';
// This variable represents the state of the worker, and serves three different purposes:
//
// - At initialization, it is set to `null`.
// - Once the first message, containing the configuration, has been received from the parent, it
//   becomes an array filled with the messages that are received while the Wasm VM is still
//   initializing.
// - After the Wasm VM has finished initialization, contains the `WebAssembly.Instance` object.
//
let state = null;
// Inject a message coming from `index.js` to a running Wasm VM.
function injectMessage(instance, message) {
    switch (message.ty) {
        case 'request': {
            const len = Buffer.byteLength(message.request, 'utf8');
            const ptr = instance.exports.alloc(len) >>> 0;
            Buffer.from(instance.exports.memory.buffer).write(message.request, ptr);
            instance.exports.json_rpc_send(ptr, len, message.chainId);
            break;
        }
        case 'addChain': {
            // Write the chain specification into memory.
            const chainSpecLen = Buffer.byteLength(message.chainSpec, 'utf8');
            const chainSpecPtr = instance.exports.alloc(chainSpecLen) >>> 0;
            Buffer.from(instance.exports.memory.buffer)
                .write(message.chainSpec, chainSpecPtr);
            // Write the database content into memory.
            const databaseContentLen = Buffer.byteLength(message.databaseContent, 'utf8');
            const databaseContentPtr = instance.exports.alloc(databaseContentLen) >>> 0;
            Buffer.from(instance.exports.memory.buffer)
                .write(message.databaseContent, databaseContentPtr);
            // Write the potential relay chains into memory.
            const potentialRelayChainsLen = message.potentialRelayChains.length;
            const potentialRelayChainsPtr = instance.exports.alloc(potentialRelayChainsLen * 4) >>> 0;
            for (let idx = 0; idx < message.potentialRelayChains.length; ++idx) {
                Buffer.from(instance.exports.memory.buffer)
                    .writeUInt32LE(message.potentialRelayChains[idx], potentialRelayChainsPtr + idx * 4);
            }
            // `add_chain` unconditionally allocates a chain id. If an error occurs, however, this chain
            // id will refer to an *erroneous* chain. `chain_is_ok` is used below to determine whether it
            // has succeeeded or not.
            // Note that `add_chain` properly de-allocates buffers even if it failed.
            const chainId = instance.exports.add_chain(chainSpecPtr, chainSpecLen, databaseContentPtr, databaseContentLen, message.jsonRpcRunning ? 1 : 0, potentialRelayChainsPtr, potentialRelayChainsLen);
            if (instance.exports.chain_is_ok(chainId) != 0) {
                postMessage({ kind: 'chainAddedOk', chainId });
            }
            else {
                const errorMsgLen = instance.exports.chain_error_len(chainId) >>> 0;
                const errorMsgPtr = instance.exports.chain_error_ptr(chainId) >>> 0;
                const errorMsg = Buffer.from(instance.exports.memory.buffer)
                    .toString('utf8', errorMsgPtr, errorMsgPtr + errorMsgLen);
                instance.exports.remove_chain(chainId);
                postMessage({ kind: 'chainAddedErr', error: errorMsg });
            }
            break;
        }
        case 'removeChain': {
            instance.exports.remove_chain(message.chainId);
            break;
        }
        case 'databaseContent': {
            // The value of `maxUtf8BytesSize` is guaranteed (by `index.js`) to always fit in 32 bits, in
            // other words, that `maxUtf8BytesSize < (1 << 32)`.
            // We need to perform a conversion in such a way that the the bits of the output of
            // `ToInt32(converted)`, when interpreted as u32, is equal to `maxUtf8BytesSize`.
            // See ToInt32 here: https://tc39.es/ecma262/#sec-toint32
            // Note that the code below has been tested against example values. Please be very careful
            // if you decide to touch it. Ideally it would be unit-tested, but since it concerns the FFI
            // layer between JS and Rust, writing unit tests would be extremely complicated.
            const twoPower31 = (1 << 30) * 2; // `1 << 31` in JavaScript doesn't give the value that you expect.
            const converted = (message.maxUtf8BytesSize >= twoPower31) ?
                (message.maxUtf8BytesSize - (twoPower31 * 2)) : message.maxUtf8BytesSize;
            instance.exports.database_content(message.chainId, converted);
            break;
        }
        default: {
            // Exhaustive check.
            const _exhaustiveCheck = message;
            return _exhaustiveCheck;
        }
    }
}
;
function postMessage(message) {
    // `compat.postMessage` is the same as `postMessage`, but works across environments.
    compat.postMessage(message);
}
// `compat.setOnMessage` is the same as `onmessage = ...`, but works across environments.
compat.setOnMessage((message) => {
    // What to do depends on the type of `state`.
    // See the documentation of the `state` variable for information.
    if (state == null) {
        // First ever message received by the worker. Always contains the initial configuration.
        const configMessage = message;
        // Transition to the next phase: an array during which messages are stored while the
        // initialization is in progress.
        state = [];
        // Start initialization of the Wasm VM.
        const config = {
            logCallback: (level, target, message) => {
                postMessage({ kind: 'log', level, target, message });
            },
            jsonRpcCallback: (data, chainId) => {
                postMessage({ kind: 'jsonrpc', data, chainId });
            },
            databaseContentCallback: (data, chainId) => {
                postMessage({ kind: 'databaseContent', data, chainId });
            },
            currentTaskCallback: (taskName) => {
                postMessage({ kind: 'currentTask', taskName });
            },
            cpuRateLimit: configMessage.cpuRateLimit,
            forbidTcp: configMessage.forbidTcp,
            forbidWs: configMessage.forbidWs,
            forbidNonLocalWs: configMessage.forbidNonLocalWs,
            forbidWss: configMessage.forbidWss,
        };
        instance.startInstance(config).then((instance) => {
            // `config.cpuRateLimit` is a floating point that should be between 0 and 1, while the value
            // to pass as parameter must be between `0` and `2^32-1`.
            // The few lines of code below should handle all possible values of `number`, including
            // infinites and NaN.
            let cpuRateLimit = Math.round(config.cpuRateLimit * 4294967295); // `2^32 - 1`
            if (cpuRateLimit < 0)
                cpuRateLimit = 0;
            if (cpuRateLimit > 4294967295)
                cpuRateLimit = 4294967295;
            if (!Number.isFinite(cpuRateLimit))
                cpuRateLimit = 4294967295; // User might have passed NaN
            // Smoldot requires an initial call to the `init` function in order to do its internal
            // configuration.
            instance.exports.init(configMessage.maxLogLevel, configMessage.enableCurrentTask ? 1 : 0, cpuRateLimit);
            // Smoldot has finished initializing.
            // Since this function is an asynchronous function, it is possible that messages have been
            // received from the parent while it was executing. These messages are now handled.
            state.forEach((message) => {
                injectMessage(instance, message);
            });
            state = instance;
        });
    }
    else if (Array.isArray(state)) {
        // A message has been received while the Wasm VM is still initializing. Queue it for when
        // initialization is over.
        state.push(message);
    }
    else {
        // Everything is already initialized. Process the message synchronously.
        injectMessage(state, message);
    }
});
// Periodically send a ping message to the outside, as a way to report liveness.
setInterval(() => {
    postMessage({ kind: 'livenessPing' });
}, 2500);
