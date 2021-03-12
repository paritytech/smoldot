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

// Contains a worker spawned by `bindings-smoldot`.
//
// # Interface
//
// After spawning, the worker expects one initial message (through `postMessage`) containing an
// object with the following keys:
//
// - `module`: The `WebAssembly.Module` to instantiate.
// - `requestedImports`: An array of values associated to the imports to pass when instantiating.
// For each import, if it is a memory, then the corresponding element must be the number of pages
// of memory to allocate (for both initial and maximum). If it is a function, then the
// corresponding element must be an opaque identifier to pass back when the function is called.
// - `communicationsSab`: A `SharedArrayBuffer` used for further communication between this
// worker and the outside.
//
// After this initial message, all further communication is done through the `communicationsSab`.
//
// The `communicationsSab` has the following layout:
//
// - First four bytes are an integer used to determine who has ownership of the rest of the
// content of the buffer. They are always accessed through an `Int32Array`. If 1 (the initial
// value), then it's this worker. If 0, then it's the outside. Each side reads the content of
// the buffer, then writes it, then switches the first four bytes and uses `Atomics.notify` to
// wake up the other side.
//
// - Fifth byte and follow-up contain a SCALE-encoded enum defined below.
//
// ```
// enum Message {
//     // 0 if initialization was successful, non-0 otherwise.
//     InitializationResult(u8),
//
//     // Must start executing the function with the given name, with the given parameters.
//     // Must answer with a `StartResult`.
//     StartFunction(String, Vec<WasmValue>),
//
//     // If 0, the start has succeeded. If 1, the function doesn't exist. If 2, the requested
//     // function isn't actually a function. If 3, the signature of the function doesn't match
//     // the parameters.
//     StartResult(u8),
//
//     // Execution has finished, either successully or with an error. If error, contains a
//     // human-readable message. If success, contains the return value.
//     Finished(Result<Option<WasmValue>, String>),
//
//     // Send when Wasm VM has been interrupted by host function call. Must be answered with
//     // a `Resume`.
//     Interrupted {
//         // Value initially passed through the `requestedImports`.
//         function_id: u32,
//         params: Vec<WasmValue>,
//     },
//
//     // Contains the return value of the host function.
//     Resume(Option<WasmValue>),
//
//     // Must write data at given memory offset.
//     WriteMemory(u32, Vec<u8>),
//
//     // Must read data from memory. Offset is first `u32`. Size is second `u32`. Must answer
//     // with `ReadMemoryResult`.
//     ReadMemory(u32, u32),
//
//     ReadMemoryResult(Vec<u8>),
//
//     // Must respond with a `MemorySizeResult`.
//     MemorySize,
//
//     // Contains number of bytes of memory of the child Wasm VM.
//     MemorySizeResult(u32),
//
//     // Must read the value of the global whose name is in parameter. Must respond with either
//     // `GetGlobalOk` or `GetGlobalErr`.
//     GetGlobal(String),
//
//     GetGlobalOk(u32),
//
//     GetGlobalErr,
// }
//
// enum WasmValue {
//     I32(i32),
//     I64(i64),
// }
// ```
//
// The `communicationsSab` is initially owner by this worker and must be answered with an
// "Initialization result" message. If initialization has failed, the worker shuts down.
//

import * as compat from './compat-nodejs.js';

// Filled with information about the state of the worker. All fields are initially null before
// the first message is received.
let state = {
  instance: null,
  communicationsSab: null,
  int32Array: null,
  startedFeedback: false
};

// Decodes a SCALE-encoded `WasmValue`.
//
// Returns an object of the form `{ offsetAfter: ..., value: ... }`.
const decodeWasmValue = (memory, offset) => {
  const ty = memory.readUInt8(offset);
  if (ty == 0) {
    const value = memory.readInt32LE(offset + 1);
    return {
      offsetAfter: offset + 5,
      value
    };
  } else {
    const value = memory.readInt64LE(offset + 1);
    return {
      offsetAfter: offset + 9,
      value
    };
  }
};

/*
/// Returns a buffer containing the SCALE-compact encoding of the parameter.
pub(crate) fn encode_scale_compact_usize(mut value: usize) -> impl AsRef<[u8]> + Clone {
    // TODO: use usize::BITS after https://github.com/rust-lang/rust/issues/76904 is stable
    let mut array = arrayvec::ArrayVec::<[u8; 1 + 64 / 8]>::new();

    if value < 64 {
        array.push(u8::try_from(value).unwrap() << 2);
    } else if value < (1 << 14) {
        array.push((u8::try_from(value & 0b111111).unwrap() << 2) | 0b01);
        array.push(u8::try_from((value >> 6) & 0xff).unwrap());
    } else if value < (1 << 30) {
        array.push((u8::try_from(value & 0b111111).unwrap() << 2) | 0b10);
        array.push(u8::try_from((value >> 6) & 0xff).unwrap());
        array.push(u8::try_from((value >> 14) & 0xff).unwrap());
        array.push(u8::try_from((value >> 22) & 0xff).unwrap());
    } else {
        array.push(0);
        while value != 0 {
            array.push(u8::try_from(value & 0xff).unwrap());
            value >>= 8;
        }
        array[0] = (u8::try_from(array.len() - 1 - 4).unwrap() << 2) | 0b11;
    }

    array
}
*/

/*const encodeScaleCompactUsize = (value, bufferOut) => {
  if 
};*/

const sendStartFeedbackIfNeeded = () => {
  if (startedFeedback)
    return;

  communicationsSab.writeUInt8(0, 4);
  int32Array[0] = 0;
  Atomics.notify(int32Array, 0);

  Atomics.wait(int32Array, 0, 0);

  startedFeedback = true;
};

compat.setOnMessage((incomingMessage) => {
  state.communicationsSab = Buffer.from(incomingMessage.communicationsSab);
  state.int32Array = new Int32Array(incomingMessage.communicationsSab);
  if (state.int32Array[0] != 1)
    throw "Invalid communicationsSab state";

  let constructedImports = {};
  WebAssembly.Module.imports(incomingMessage.module).forEach((moduleImport, i) => {
    if (!constructedImports[moduleImport.module])
      constructedImports[moduleImport.module] = {};

    if (moduleImport.kind == 'function') {
      constructedImports[moduleImport.module][moduleImport.name] = () => {
        sendStartFeedbackIfNeeded();

        // TODO: write params

        int32Array[0] = 0;
        Atomics.notify(int32Array, 0);

        Atomics.wait(int32Array, 0, 0);
        const returnValue = decodeWasmValue(state.communicationsSab, 4);
        return returnValue;
      };

    } else if (moduleImport.kind == 'memory') {
      constructedImports[moduleImport.module][moduleImport.name] =
        new WebAssembly.Memory({
          initial: incomingMessage.requestedImports[i],
          maximum: incomingMessage.requestedImports[i]
        });

    } else {
      throw "Unknown kind: " + kind;
    }
  })

  state.communicationsSab.writeUInt8(0, 4); // `InitializationResult` variant
  try {
    state.instance = new WebAssembly.Instance(incomingMessage.module, constructedImports);
    state.communicationsSab.writeUInt8(0, 5); // Sucess
  } catch (error) {
    state.communicationsSab.writeUInt8(1, 5); // Error
  }

  // Send the message and wait for further instruction.
  int32Array[0] = 0;
  Atomics.notify(int32Array, 0);
  Atomics.wait(int32Array, 0, 0);
});

/*compat.setOnMessage((incomingMessage) => {
  if (!state.instance) {
    // The first message that is expected to come is of the form
    // `{ module: <some Wasm module>, requestedImports: [..] }`. We instantiate this module.
    startInstance(incomingMessage);
  } else {
    // The second message that is expected to come is of the form
    // `{ functionName: "foo", params: [..] }`.
    startedFeedback = false;
    const toStart = state.instance.exports[incomingMessage.functionName];

    if (!toStart) {
      communicationsSab.writeUInt8(1, 4);
      int32Array[0] = 0;
      Atomics.notify(int32Array, 0);
      return;
    }

    let returnValue;
    try {
      returnValue = toStart(incomingMessage.params);
    } catch (error) {
      // TODO:
      throw error;
    }

    sendStartFeedbackIfNeeded();

    communicationsSab.writeUInt8(0, 4); // `Finished` variant
    communicationsSab.writeUInt8(0, 5); // `Ok` variant
    if (typeof returnValue === "bigint") {
      communicationsSab.writeUInt8(1, 6); // `Some` variant
      communicationsSab.writeUInt8(1, 7); // `I64` variant
      communicationsSab.writeUInt64LE(returnValue, 8);
    } else if (typeof returnValue === "number") {
      communicationsSab.writeUInt8(1, 6); // `Some` variant
      communicationsSab.writeUInt8(0, 7); // `I32` variant
      communicationsSab.writeUInt32LE(returnValue, 8);
    } else {
      communicationsSab.writeUInt8(0, 6); // `None` variant
    }

    int32Array[0] = 0;
    Atomics.notify(int32Array, 0);
  }
});*/
