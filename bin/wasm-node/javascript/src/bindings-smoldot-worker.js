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

let instance = null;

startInstance = (incomingMessage) => {
  const moduleImports = WebAssembly.Module.imports(incomingMessage.module);
  let constructedImports = {};
  const sharedArrayBuffer = new Int32Array(incomingMessage.sharedArrayBuffer);

  moduleImports.forEach((moduleImport, i) => {
    if (!constructedImports[moduleImport.module])
      constructedImports[moduleImport.module] = {};

    if (moduleImport.kind == 'function') {
      constructedImports[moduleImport.module][moduleImport.name] = () => {
        postMessage({ functionId: requestedImports[i] });
        Atomics.wait(sharedArrayBuffer, 0, 0);
        sharedArrayBuffer[0] = 0;
        var returnValue = sharedArrayBuffer[1];
        throw requestedImports[i];
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

onmessage = (incomingMessage) => {
  if (!instance) {
    // The first message that is expected to come is of the form
    // `{ module: <some Wasm module> , requestedImports: [..] }`. We instantiate this module.
    startInstance(incomingMessage);
  } else {
    // The second message that is expected to come is of the form
    // `{ functionName: "foo", params: [..] }`.
    const to_start = instance.exports[incomingMessage.functionName];
    to_start(incomingMessage.params);
  }
};
