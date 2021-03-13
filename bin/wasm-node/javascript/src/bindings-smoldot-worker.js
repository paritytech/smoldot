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
//     // Must write data at given memory offset. Parameters are offset and size.
//     // Must be answered with `WriteMemoryOk`.
//     WriteMemory(u32, u32, Vec<u8> /* NO LENGTH PREFIX */),
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
import { Buffer } from 'buffer';

// Filled with information about the state of the worker. All fields are initially null before
// the first message is received.
let state = {
  instance: null,
  communicationsSab: null,
  int32Array: null,
  memory: null,
};

// For an unclear reason, in the browser the `Buffer` object doesn't have `writeBigInt64LE` and
// `readBigInt64LE`. Might be a bundler bug. We redefine these operations locally as a work-around.
// TODO: figure this out ^ or, in the future, remove these functions and try if it works if we use `Buffer.writeBigInt64LE` and `Buffer.readBigInt64LE`
const writeBigInt64LE = (value, buffer, offset) => {
  const lo = Number(value & BigInt(0xffffffff));
  const hi = Number(value >> BigInt(32) & BigInt(0xffffffff));
  buffer.writeUInt32LE(lo, offset);
  buffer.writeUInt32LE(hi, offset + 4);
};
const readBigInt64LE = (buffer, offset) => {
  const lo = buffer.readUint32LE(offset);
  const hi = buffer.readUint32LE(offset + 4);
  return (BigInt(hi) << BigInt(32)) + BigInt(lo)
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
    const value = readBigInt64LE(buffer, offset + 1);
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

  return {
    value: out,
    offsetAfter: currentOffset
  };
};

// Gives back hand to the outside and waits for a response to be written on the
// `communicationsSab`.
const sendMessageWaitReply = () => {
  state.int32Array[0] = 0;
  Atomics.notify(state.int32Array, 0);
  Atomics.wait(state.int32Array, 0, 0);
};

// Encodes a number in its SCALE-compact encoding.
//
// Returns an object of the form `{ offsetAfter: ... }`.
const encodeScaleCompactUsize = (value, bufferOut, bufferOutOffset) => {
  if (value < 64) {
    bufferOut.writeUInt8(value << 2, bufferOutOffset);
    return { offsetAfter: bufferOutOffset + 1 };

  } else if (value < (1 << 14)) {
    bufferOut.writeUInt8(((value & 0b111111) << 2) | 0b01, bufferOutOffset);
    bufferOut.writeUInt8((value >> 6) & 0xff, bufferOutOffset + 1);
    return { offsetAfter: bufferOutOffset + 2 };

  } else if (value < (1 << 30)) {
    bufferOut.writeUInt8(((value & 0b111111) << 2) | 0b10, bufferOutOffset);
    bufferOut.writeUInt8((value >> 6) & 0xff, bufferOutOffset + 1);
    bufferOut.writeUInt8((value >> 14) & 0xff, bufferOutOffset + 2);
    bufferOut.writeUInt8((value >> 22) & 0xff, bufferOutOffset + 3);
    return { offsetAfter: bufferOutOffset + 4 };

  } else {
    let off = 1;
    while (value != 0) {
      bufferOut.writeUInt8(value & 0xff, bufferOutOffset + off);
      off += 1;
      value >>= 8;
    }
    bufferOut.writeUInt8(((off - 1 - 4) << 2) | 0b11, bufferOutOffset);
    return { offsetAfter: bufferOutOffset + off };
  }
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
      const value = optValue != 0 ? decodeWasmValue(state.communicationsSab, 6).value : null;
      return {
        kind: 'Resume',
        value
      };
    }

    if (messageTy == 6) { // `WriteMemory`.
      const writeOffset = state.communicationsSab.readUint32LE(5);
      const writeSize = state.communicationsSab.readUint32LE(9);
      state.communicationsSab.copy(state.memory, writeOffset, 13, 13 + writeSize);
      state.communicationsSab.writeUInt8(7, 4); // `WriteMemoryOk`.
      sendMessageWaitReply();
      continue;
    }

    if (messageTy == 8) { // `ReadMemory`.
      const readOffset = state.communicationsSab.readUint32LE(5);
      const readSize = state.communicationsSab.readUint32LE(9);
      state.communicationsSab.writeUInt8(9, 4); // `ReadMemoryResult`.
      state.memory.copy(state.communicationsSab, 5, readOffset, readOffset + readSize);
      sendMessageWaitReply();
      continue;
    }

    if (messageTy == 10) { // `MemorySize`.
      state.communicationsSab.writeUInt8(11, 4); // `MemorySizeResult`.
      state.communicationsSab.writeUInt32LE(state.memory ? state.memory.byteLength : 0, 5);
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

// Function that builds a host function.
const buildHostFunction = (id) => {
  // The function returned here is what is called by the Wasm VM for all its host functions.
  return (...args) => {
    // Must send an `Interrupted` message and wait for the `Resume`.
    state.communicationsSab.writeUInt8(4, 4); // `Interrupted`
    state.communicationsSab.writeUInt32LE(id, 5);
    let { offsetAfter } = encodeScaleCompactUsize(args.length, state.communicationsSab, 9);
    args.forEach((value) => {
      if (typeof value === "bigint") {
        state.communicationsSab.writeUInt8(1, offsetAfter); // `I64` variant
        writeBigInt64LE(value, state.communicationsSab, offsetAfter + 1);
        offsetAfter += 9;
      } else if (typeof value === "number") {
        state.communicationsSab.writeUInt8(0, offsetAfter); // `I32` variant
        state.communicationsSab.writeUInt32LE(value, offsetAfter + 1);
        offsetAfter += 5;
      } else {
        throw 'Expected i32 or i64 host function argument';
      }
    });
    sendMessageWaitReply();

    // Now processing the reply from the outside.
    const receivedMessage = processMessages();
    if (receivedMessage.kind == 'Resume') {
      return receivedMessage.value;

    } else {
      // `StartFunction` interrupting the execution.
      // TODO:
      throw 'not implemented yet!';
    }
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
      // TODO: heap_pages is actually "additional" memory?
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
    state.memory = Buffer.from(memory.buffer);
    if (!state.memory) {
      state.memory = Buffer.from(state.instance.exports.memory.buffer);
    }
    state.communicationsSab.writeUInt8(0, 5); // Sucess
  } catch (error) {
    state.communicationsSab.writeUInt8(1, 5); // Error
    return;
  }

  // Send the message and wait for further instruction.
  sendMessageWaitReply();

  // Main execution loop. Despite being JavaScript, this is entirely synchronous.
  const toStart = { function: null, params: null };
  while (true) {
    const receivedMessage = processMessages();

    if (receivedMessage.kind == 'StartFunction') {
      // Start executing the requested function.
      toStart.function = state.instance.exports[receivedMessage.name];
      toStart.params = receivedMessage.params;

      if (!toStart.function) {
        state.communicationsSab.writeUInt8(2, 4); // `StartResult`
        state.communicationsSab.writeUInt8(1, 5);
        sendMessageWaitReply();
        continue;
      }

      // TODO: check if toStart.function is indeed a function

      // Send back start success.
      state.communicationsSab.writeUInt8(2, 4); // `StartResult`
      state.communicationsSab.writeUInt8(0, 5); // Success
      sendMessageWaitReply();

    } else { // Resume
      let returnValue;
      try {
        returnValue = toStart.function(...toStart.params);
      } catch (error) {
        // TODO: can also be interruption from host function because of a StartFunction
        const errorMsg = error.toString();
        const errorMsgLen = Buffer.byteLength(errorMsg, 'utf8');
        state.communicationsSab.writeUInt8(3, 4); // `Finished`
        state.communicationsSab.writeUInt8(1, 5); // `Err`
        state.communicationsSab.writeUInt32LE(errorMsgLen, 6);
        state.communicationsSab.write(errorMsg, 10);
        sendMessageWaitReply();
        continue;
      }

      // Function has successfully ended.
      state.communicationsSab.writeUInt8(3, 4); // `Finished`
      state.communicationsSab.writeUInt8(0, 5); // `Ok` variant
      if (typeof returnValue === "bigint") {
        state.communicationsSab.writeUInt8(1, 6); // `Some` variant
        state.communicationsSab.writeUInt8(1, 7); // `I64` variant
        writeBigInt64LE(returnValue, state.communicationsSab, 8);
      } else if (typeof returnValue === "number") {
        state.communicationsSab.writeUInt8(1, 6); // `Some` variant
        state.communicationsSab.writeUInt8(0, 7); // `I32` variant
        state.communicationsSab.writeUInt32LE(returnValue, 8);
      } else {
        state.communicationsSab.writeUInt8(0, 6); // `None` variant
      }

      sendMessageWaitReply();
    }
  }
});
