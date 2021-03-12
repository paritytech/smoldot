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

throw 'test';

import * as compat from './compat-nodejs.js';

let instance = null;
let sharedArrayBuffer = null;
let int32Array = null;

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

startInstance = (incomingMessage) => {
  const moduleImports = WebAssembly.Module.imports(incomingMessage.module);
  let constructedImports = {};
  sharedArrayBuffer = Buffer.from(incomingMessage.sharedArrayBuffer);
  int32Array = new Int32Array(incomingMessage.sharedArrayBuffer);

  moduleImports.forEach((moduleImport, i) => {
    if (!constructedImports[moduleImport.module])
      constructedImports[moduleImport.module] = {};

    if (moduleImport.kind == 'function') {
      constructedImports[moduleImport.module][moduleImport.name] = () => {

        int32Array[0] = 0;
        Atomics.notify(int32Array, 0);

        Atomics.wait(int32Array, 0, 0);
        const returnValue = decodeWasmValue(sharedArrayBuffer, 4);
        return returnValue;
      };

    } else if (moduleImport.kind == 'memory') {
      constructedImports[moduleImport.module][moduleImport.name] =
        new WebAssembly.Memory({ initial: requestedImports[i], maximum: requestedImports[i], shared: true });

    } else {
      throw "Unknown kind: " + kind;
    }
  })

  // TODO: must handle errors
  instance = new WebAssembly.Instance(incomingMessage.module, constructedImports);
};

compat.setOnMessage((incomingMessage) => {
  if (!instance) {
    // The first message that is expected to come is of the form
    // `{ module: <some Wasm module>, requestedImports: [..] }`. We instantiate this module.
    startInstance(incomingMessage);
  } else {
    // The second message that is expected to come is of the form
    // `{ functionName: "foo", params: [..] }`.
    const toStart = instance.exports[incomingMessage.functionName];
    const returnValue = toStart(incomingMessage.params);

    sharedArrayBuffer.writeUInt8(0, 4); // `Finished` variant
    sharedArrayBuffer.writeUInt8(0, 5); // `Ok` variant
    if (typeof returnValue === "bigint") {
      sharedArrayBuffer.writeUInt8(1, 6); // `Some` variant
      sharedArrayBuffer.writeUInt8(1, 7); // `I64` variant
      sharedArrayBuffer.writeUInt64LE(returnValue, 8);
    } else if (typeof returnValue === "number") {
      sharedArrayBuffer.writeUInt8(1, 6); // `Some` variant
      sharedArrayBuffer.writeUInt8(0, 7); // `I32` variant
      sharedArrayBuffer.writeUInt32LE(returnValue, 8);
    } else {
      sharedArrayBuffer.writeUInt8(0, 6); // `None` variant
    }

    int32Array[0] = 0;
    Atomics.notify(int32Array, 0);
  }
});
