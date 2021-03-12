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
//     // Must be answered with `StartFunction`, `GetGlobal`, `MemorySize`, `WriteMemory`,
//     // `ReadMemory`, or `Resume`.
//     InitializationResult(u8),
//
//     // Must start executing the function with the given name, with the given parameters,
//     // interrupting the current execution if any is in progress.
//     // Must be answered with a `StartResult`.
//     StartFunction(String, Vec<WasmValue>),
//
//     // If 0, the start has succeeded. If 1, the function doesn't exist. If 2, the requested
//     // function isn't actually a function. If 3, the signature of the function doesn't match
//     // the parameters.
//     // Must be answered with `StartFunction`, `GetGlobal`, `MemorySize`, `WriteMemory`,
//     // `ReadMemory`, or `Resume`.
//     // Most likely, to start execution, use `Resume(None)`.
//     StartResult(u8),
//
//     // Execution has finished, either successully or with an error. If error, contains a
//     // human-readable message. If success, contains the return value.
//     // Must be answered with a `StartFunction`, `GetGlobal`, `MemorySize`, `WriteMemory`,
//     // `ReadMemory`, or `Resume`.
//     Finished(Result<Option<WasmValue>, String>),
//
//     // Send when Wasm VM has been interrupted by host function call.
//     // Must be answered with `StartFunction`, `GetGlobal`, `MemorySize`, `WriteMemory`,
//     // `ReadMemory`, or `Resume`.
//     Interrupted {
//         // Value initially passed through the `requestedImports`.
//         function_id: u32,
//         params: Vec<WasmValue>,
//     },
//
//     // Contains the return value of the host function.
//     // If this is the first time `Resume` is called after a `StartFunction`, must contain
//     // `None`.
//     // Must be answered with `Interrupted` or `Finished`.
//     Resume(Option<WasmValue>),
//
//     // Must write data at given memory offset. Must be answered with `WriteMemoryOk`.
//     WriteMemory(u32, Vec<u8>),
//
//     // Confirmation that `WriteMemory` has been done.
//     // Must be answered with `StartFunction`, `GetGlobal`, `MemorySize`, `WriteMemory`,
//     // `ReadMemory`, or `Resume`.
//     WriteMemoryOk,
//
//     // Must read data from memory. Offset is first `u32`. Size is second `u32`. Must answer
//     // with `ReadMemoryResult`.
//     ReadMemory(u32, u32),
//
//     // Must be answered with `StartFunction`, `GetGlobal`, `MemorySize`, `WriteMemory`,
//     // `ReadMemory`, or `Resume`.
//     ReadMemoryResult(Vec<u8> /* NO LENGTH PREFIX */),
//
//     // Must respond with a `MemorySizeResult`.
//     MemorySize,
//
//     // Contains number of bytes of memory of the child Wasm VM.
//     // Must be answered with `StartFunction`, `GetGlobal`, `MemorySize`, `WriteMemory`,
//     // `ReadMemory`, or `Resume`.
//     MemorySizeResult(u32),
//
//     // Must read the value of the global whose name is in parameter. Must respond with either
//     // `GetGlobalOk` or `GetGlobalErr`.
//     GetGlobal(String),
//
//     // Must be answered with `StartFunction`, `GetGlobal`, `MemorySize`, `WriteMemory`,
//     // `ReadMemory`, or `Resume`.
//     GetGlobalOk(u32),
//
//     // Must be answered with `StartFunction`, `GetGlobal`, `MemorySize`, `WriteMemory`,
//     // `ReadMemory`, or `Resume`.
//     // Contains 1 if the export wasn't found. Contains 2 if the export isn't a global value
//     // of type `i32`.
//     GetGlobalErr(u8),
// }
//
// enum WasmValue {
//     I32(i32),
//     I64(i64),
// }
// ```
//
// The `communicationsSab` is initially owned by this worker and must be answered with an
// "InitializationResult" message. If initialization has failed, the worker shuts down.
//

import * as compat from './compat-nodejs.js';

// Filled with information about the state of the worker. All fields are initially null before
// the first message is received.
let state = {
  instance: null,
  communicationsSab: null,
  int32Array: null,
  startedFeedback: false,
  memory: null,
};

// Decodes a SCALE-compact-encoded integer.
//
// Returns an object of the form `{ offsetAfter: ..., value: ... }`.
const decodeScaleCompactInt = (buffer, offset) => {
  const firstByte = buffer.readUInt8(offset);
  if ((firstByte & 0b11) == 0b00) {
    return {
      offsetAfter: offset + 1,
      value: (firstByte >> 2)
    };
  } else if ((firstByte & 0b11) == 0b01) {
    const byte0 = (firstByte >> 2);
    const byte1 = buffer.readUInt8(offset + 1);
    return {
      offsetAfter: offset + 2,
      value: (byte1 << 6) | byte0
    };
  } else if ((firstByte & 0b11) == 0b10) {
    const byte0 = (firstByte >> 2);
    const byte1 = buffer.readUInt8(offset + 1);
    const byte2 = buffer.readUInt8(offset + 2);
    const byte3 = buffer.readUInt8(offset + 3);
    return {
      offsetAfter: offset + 4,
      value: (byte3 << 22) | (byte2 << 14) | (byte1 << 6) | byte0
    };
  } else {
    throw "unimplemented"; // TODO:
  }
}

// Decodes a SCALE-encoded `String`.
//
// Returns an object of the form `{ offsetAfter: ..., value: ... }`.
const decodeString = (buffer, offset) => {
  const { offsetAfter, value: numBytes } = decodeScaleCompactInt(buffer, offset);
  const string = buffer.toString('utf8', offsetAfter, offsetAfter + numBytes);
  return { offsetAfter: offsetAfter + numBytes, value: string };
};

// Decodes a SCALE-encoded `WasmValue`.
//
// Returns an object of the form `{ offsetAfter: ..., value: ... }`.
const decodeWasmValue = (buffer, offset) => {
  const ty = buffer.readUInt8(offset);
  if (ty == 0) {
    const value = buffer.readInt32LE(offset + 1);
    return {
      offsetAfter: offset + 5,
      value
    };
  } else {
    const value = buffer.readInt64LE(offset + 1);
    return {
      offsetAfter: offset + 9,
      value
    };
  }
};

// Decodes a SCALE-encoded `Vec<WasmValue>`. Returns the decoded value.
const decodeVecWasmValue = (buffer, offset) => {
  const { offsetAfter, value: numElems } = decodeScaleCompactInt(buffer, offset);

  let out = [];
  let currentOffset = offsetAfter;
  for (let i = 0; i < numElems; ++i) {
    const { offsetAfter, value } = decodeWasmValue(buffer, currentOffset);
    currentOffset = offsetAfter;
    out.push(value);
  }

  return out;
};

// Gives back hand to the outside and waits for a response to be written on the
// `communicationsSab`.
const sendMessageWaitReply = () => {
  state.int32Array[0] = 0;
  Atomics.notify(state.int32Array, 0);
  Atomics.wait(state.int32Array, 0, 0);
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
  if (state.startedFeedback)
    return;

  state.communicationsSab.writeUInt8(2, 4); // `StartResult`
  state.communicationsSab.writeUInt8(0, 5); // Success
  sendMessageWaitReply();

  state.startedFeedback = true;

  // TODO: !!!
  const receivedMessage = processMessages();
};

// Function that builds a host function.
const buildHostFunction = (id) => {
  // The function returned here is what is called by the Wasm VM for all its host functions.
  // Must send an `Interrupted` message and wait for the `Resume`.
  return () => {
    sendStartFeedbackIfNeeded();

    // TODO: write params

    int32Array[0] = 0;
    Atomics.notify(int32Array, 0);

    Atomics.wait(int32Array, 0, 0);
    const returnValue = decodeWasmValue(state.communicationsSab, 4);
    return returnValue;
  };
};

// Builds the imports to pass when instantiating the Wasm module.
// See documentation at the top of the file for the meaning of `requestedImports`.
const buildImports = (wasmModule, requestedImports) => {
  let constructedImports = {};
  let memory = null;

  WebAssembly.Module.imports(wasmModule).forEach((moduleImport, i) => {
    if (!constructedImports[moduleImport.module])
      constructedImports[moduleImport.module] = {};

    if (moduleImport.kind == 'function') {
      constructedImports[moduleImport.module][moduleImport.name] =
        buildHostFunction(requestedImports[i]);

    } else if (moduleImport.kind == 'memory') {
      if (memory)
        throw "Can't have multiple memory objects";
      memory = new WebAssembly.Memory({
        initial: requestedImports[i],
        maximum: requestedImports[i]
      });
      constructedImports[moduleImport.module][moduleImport.name] = memory;

    } else {
      throw "Unknown kind: " + kind;
    }
  })

  return { constructedImports, memory };
};

// Reads the message in the `communicationsSab`, answering them if possible.
//
// Doesn't return until the message is either `StartFunction` or `Resume`.
// If the message is `StartFunction`, returns `{kind:'StartFunction', name:'...', params:[...]}`.
// If the message is `Resume`, returns `{kind:'Resume', value:...}`.
const processMessages = () => {
  while (true) {
    const messageTy = state.communicationsSab.readUInt8(4);

    if (messageTy == 1) { // `StartFunction`.
      const { offsetAfter, value: name } = decodeString(state.communicationsSab, 5);
      const { value: params } = decodeVecWasmValue(state.communicationsSab, offsetAfter);
      return {
        kind: 'StartFunction',
        name,
        params,
      };
    }

    if (messageTy == 5) { // `Resume`.
      const optValue = state.communicationsSab.readUInt8(5);
      const value = optValue != 0 ? decodeWasmValue(state.communicationsSab, 6) : null;
      return {
        kind: 'Resume',
        value
      };
    }

    if (messageTy == 10) { // `MemorySize`.
      state.communicationsSab.writeUInt8(11, 5); // `MemorySizeResult`.
      state.communicationsSab.writeUInt32LE(state.memory ? state.memory.byteLength : 0, 6);
      sendMessageWaitReply();
      continue;
    }

    if (messageTy == 12) { // `GetGlobal`.
      const { value: globalName } = decodeString(state.communicationsSab, 5);
      const globalVal = state.instance.exports[globalName];
      if (globalVal === undefined) {
        state.communicationsSab.writeUInt8(14, 4); // `GetGlobalErr`.
        state.communicationsSab.writeUInt8(1, 5);
      } else if (typeof globalVal.value != 'number') {
        state.communicationsSab.writeUInt8(14, 4); // `GetGlobalErr`.
        state.communicationsSab.writeUInt8(2, 5);
      } else {
        state.communicationsSab.writeUInt8(13, 4); // `GetGlobalOk`.
        state.communicationsSab.writeUInt32LE(globalVal.value, 5);
      }
      sendMessageWaitReply();
      continue;
    }

    throw "Unknown message type: " + messageTy;
  }
};

compat.setOnMessage((initializationMessage) => {
  state.communicationsSab = Buffer.from(initializationMessage.communicationsSab);
  state.int32Array = new Int32Array(initializationMessage.communicationsSab);
  if (state.int32Array[0] != 1)
    throw "Invalid communicationsSab state";

  // Try instantiate the VM and send back the `InitializationResult`.
  state.communicationsSab.writeUInt8(0, 4); // `InitializationResult` variant
  try {
    const { constructedImports, memory } = buildImports(initializationMessage.module, initializationMessage.requestedImports);
    state.instance = new WebAssembly.Instance(initializationMessage.module, constructedImports);
    state.memory = memory;
    if (!state.memory) {
      state.memory = state.instance.exports.memory;
    }
    state.communicationsSab.writeUInt8(0, 5); // Sucess
  } catch (error) {
    state.communicationsSab.writeUInt8(1, 5); // Error
    return;
  }

  // Send the message and wait for further instruction.
  sendMessageWaitReply();

  // Main execution loop. Despite being JavaScript, this is entirely synchronous.
  while (true) {
    const receivedMessage = processMessages();
    if (receivedMessage.kind != 'StartFunction')
      throw "Invalid state: received Resume when not calling anything";

    // Start executing the requested function.
    state.startedFeedback = false;
    const toStart = state.instance.exports[receivedMessage.name];

    if (!toStart) {
      state.communicationsSab.writeUInt8(2, 4); // `StartResult`
      state.communicationsSab.writeUInt8(1, 5);
      sendMessageWaitReply();
      continue;
    }

    // TODO: check if toStart is indeed a function

    let returnValue;
    try {
      returnValue = toStart(receivedMessage.params);
    } catch (error) {
      // TODO: can also be interrupted by host function
      state.communicationsSab.writeUInt8(2, 4); // `StartResult`
      state.communicationsSab.writeUInt8(3, 5);
      sendMessageWaitReply();
      continue;
    }

    // Function has successfully ended.

    // Send back a `StartResult` if necessary.
    sendStartFeedbackIfNeeded();

    state.communicationsSab.writeUInt8(3, 4); // `Finished`
    state.communicationsSab.writeUInt8(0, 5); // `Ok` variant
    if (typeof returnValue === "bigint") {
      state.communicationsSab.writeUInt8(1, 6); // `Some` variant
      state.communicationsSab.writeUInt8(1, 7); // `I64` variant
      state.communicationsSab.writeUInt64LE(returnValue, 8);
    } else if (typeof returnValue === "number") {
      state.communicationsSab.writeUInt8(1, 6); // `Some` variant
      state.communicationsSab.writeUInt8(0, 7); // `I32` variant
      state.communicationsSab.writeUInt32LE(returnValue, 8);
    } else {
      state.communicationsSab.writeUInt8(0, 6); // `None` variant
    }

    sendMessageWaitReply();
  }
});
