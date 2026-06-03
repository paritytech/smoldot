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

import test from "ava";
import { startWithBytecode } from "../dist/mjs/no-auto-bytecode-browser.js";

const bytecode = new Promise(() => {});

function withBrowserLocation(href, isSecureContext, callback) {
  const previousIsSecureContext = Object.getOwnPropertyDescriptor(
    globalThis,
    "isSecureContext",
  );
  const previousLocation = Object.getOwnPropertyDescriptor(
    globalThis,
    "location",
  );

  Object.defineProperty(globalThis, "isSecureContext", {
    configurable: true,
    value: isSecureContext,
  });
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: new URL(href),
  });

  try {
    callback();
  } finally {
    restoreGlobal("isSecureContext", previousIsSecureContext);
    restoreGlobal("location", previousLocation);
  }
}

function restoreGlobal(name, descriptor) {
  if (descriptor) {
    Object.defineProperty(globalThis, name, descriptor);
  } else {
    delete globalThis[name];
  }
}

for (const { title, href, isSecureContext, expectedForbidNonLocalWs } of [
  {
    title: "secure browser context on remote host forbids non-local WebSockets",
    href: "https://example.com/app",
    isSecureContext: true,
    expectedForbidNonLocalWs: true,
  },
  {
    title: "secure browser context on another remote host forbids non-local WebSockets",
    href: "https://rpc.example.org:443/ws",
    isSecureContext: true,
    expectedForbidNonLocalWs: true,
  },
  {
    title: "secure browser context on localhost keeps non-local WebSockets allowed",
    href: "http://localhost:9090",
    isSecureContext: true,
    expectedForbidNonLocalWs: undefined,
  },
  {
    title: "secure browser context on IPv4 loopback keeps non-local WebSockets allowed",
    href: "http://127.0.0.1:9090",
    isSecureContext: true,
    expectedForbidNonLocalWs: undefined,
  },
  {
    title: "secure browser context on IPv6 loopback keeps non-local WebSockets allowed",
    href: "http://[::1]:9090",
    isSecureContext: true,
    expectedForbidNonLocalWs: undefined,
  },
  {
    title: "insecure browser context on remote host keeps non-local WebSockets allowed",
    href: "http://example.com/app",
    isSecureContext: false,
    expectedForbidNonLocalWs: undefined,
  },
]) {
  test(title, (t) => {
    withBrowserLocation(href, isSecureContext, () => {
      const options = {
        bytecode,
        logCallback: () => {},
      };

      startWithBytecode(options);

      t.is(options.forbidNonLocalWs, expectedForbidNonLocalWs);
    });
  });
}
