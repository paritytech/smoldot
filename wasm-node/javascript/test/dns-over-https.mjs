// Smoldot
// Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
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

// Unit tests for the DNS-over-HTTPS resolver that browsers use for
// `/dns/<host>/udp/<port>/webrtc-direct/...` multiaddresses. No network is
// involved: `fetch` is stubbed, and the URLs and abort signals it is called
// with are recorded.

import test from "ava";
import { parseDnsJsonAnswer, resolveDnsOverHttps } from "../dist/mjs/internals/dns-over-https.js";

const A = (data) => ({ name: "example.com", type: 1, TTL: 60, data });
const AAAA = (data) => ({ name: "example.com", type: 28, TTL: 60, data });
const CNAME = (data) => ({ name: "example.com", type: 5, TTL: 60, data });

const CLOUDFLARE = (type) => `https://cloudflare-dns.com/dns-query?name=example.com&type=${type}`;
const GOOGLE = (type) => `https://dns.google/resolve?name=example.com&type=${type}`;
const isCloudflare = (url) => url.startsWith("https://cloudflare-dns.com/");

const answer = (records) => ({ body: { Status: 0, Answer: records } });

/**
 * Builds a `fetch` stub. `handler(url)` returns `{ status?, body }`, an
 * `Error` to make the call reject, or a promise of either to answer later.
 * A pending call rejects with an `AbortError` when its signal is aborted.
 * The URLs and the signals are recorded in call order.
 */
function fakeFetch(handler) {
  const urls = [];
  const signals = [];
  const fetchImpl = (url, init) => {
    urls.push(String(url));
    const signal = init?.signal;
    signals.push(signal);
    return new Promise((resolve, reject) => {
      const onAbort = () =>
        reject(Object.assign(new Error("The operation was aborted"), { name: "AbortError" }));
      if (signal?.aborted) return onAbort();
      signal?.addEventListener("abort", onAbort, { once: true });
      Promise.resolve(handler(String(url))).then(
        (reply) => {
          signal?.removeEventListener("abort", onAbort);
          if (reply instanceof Error) return reject(reply);
          const { status = 200, body } = reply;
          resolve({ ok: status >= 200 && status < 300, status, json: async () => body });
        },
        (error) => {
          signal?.removeEventListener("abort", onAbort);
          reject(error);
        },
      );
    });
  };
  return { urls, signals, fetchImpl };
}

const signal = () => new AbortController().signal;

/** A promise settled by hand from the test. */
function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Stagger used by the tests that exercise the race, short so that they run fast.
const STAGGER_MS = 5;

test("parseDnsJsonAnswer keeps only the records of the wanted family", (t) => {
  const body = {
    Status: 0,
    Answer: [CNAME("alias.example.com."), A("93.184.216.34"), AAAA("2606:2800:220:1:248:1893:25c8:1946")],
  };
  t.deepEqual(parseDnsJsonAnswer(body, 4), ["93.184.216.34"]);
  t.deepEqual(parseDnsJsonAnswer(body, 6), ["2606:2800:220:1:248:1893:25c8:1946"]);
});

test("parseDnsJsonAnswer yields nothing for failures and malformed input", (t) => {
  t.deepEqual(parseDnsJsonAnswer({ Status: 3, Answer: [A("1.2.3.4")] }, 4), []);
  t.deepEqual(parseDnsJsonAnswer({ Status: 0 }, 4), []);
  t.deepEqual(parseDnsJsonAnswer({ Status: 0, Answer: [A(42), { type: 1 }, null, "x"] }, 4), []);
  t.deepEqual(parseDnsJsonAnswer({ Status: 0, Answer: [A("not-an-ip"), AAAA("1.2.3.4")] }, 4), []);
  t.deepEqual(parseDnsJsonAnswer({ Status: 0, Answer: [A("1.2.3.4")] }, 6), []);
  t.deepEqual(parseDnsJsonAnswer(null, 4), []);
  t.deepEqual(parseDnsJsonAnswer("Status: 0", 4), []);
  t.deepEqual(parseDnsJsonAnswer(undefined, 6), []);
});

test("falls back to the next provider when the first one fails", async (t) => {
  const { urls, fetchImpl } = fakeFetch((url) =>
    isCloudflare(url) ? { status: 502, body: null } : answer([A("1.2.3.4")]),
  );
  t.is(await resolveDnsOverHttps("example.com", 4, signal(), fetchImpl), "1.2.3.4");
  t.deepEqual(urls, [CLOUDFLARE("A"), GOOGLE("A")]);
});

test("/dns/ asks for A records first and stops at the first answer", async (t) => {
  const { urls, fetchImpl } = fakeFetch(() => answer([A("1.2.3.4"), A("5.6.7.8")]));
  t.is(await resolveDnsOverHttps("example.com", undefined, signal(), fetchImpl), "1.2.3.4");
  t.deepEqual(urls, [CLOUDFLARE("A")]);
});

test("/dns/ falls back to AAAA records when there is no A record", async (t) => {
  const { urls, fetchImpl } = fakeFetch((url) =>
    url.endsWith("type=A") ? answer([]) : answer([AAAA("2001:db8::1")]),
  );
  t.is(await resolveDnsOverHttps("example.com", undefined, signal(), fetchImpl), "2001:db8::1");
  t.deepEqual(urls, [CLOUDFLARE("A"), GOOGLE("A"), CLOUDFLARE("AAAA")]);
});

test("/dns6/ never asks for A records", async (t) => {
  const { urls, fetchImpl } = fakeFetch(() => answer([AAAA("2001:db8::1")]));
  t.is(await resolveDnsOverHttps("example.com", 6, signal(), fetchImpl), "2001:db8::1");
  t.deepEqual(urls, [CLOUDFLARE("AAAA")]);
});

test("rejects with the last provider's error when every provider fails", async (t) => {
  const { urls, fetchImpl } = fakeFetch(() => new Error("network down"));
  await t.throwsAsync(resolveDnsOverHttps("example.com", 4, signal(), fetchImpl), {
    message: "dns.google: network down",
  });
  t.deepEqual(urls, [CLOUDFLARE("A"), GOOGLE("A")]);
});

test("localhost resolves to the loopback address without any request", async (t) => {
  const { urls, fetchImpl } = fakeFetch(() => new Error("must not be called"));
  t.is(await resolveDnsOverHttps("localhost", undefined, signal(), fetchImpl), "127.0.0.1");
  t.is(await resolveDnsOverHttps("LocalHost", 4, signal(), fetchImpl), "127.0.0.1");
  t.is(await resolveDnsOverHttps("node.localhost", 6, signal(), fetchImpl), "::1");
  t.deepEqual(urls, []);
});

test("an IP literal of an acceptable family is returned as is", async (t) => {
  const { urls, fetchImpl } = fakeFetch(() => new Error("must not be called"));
  t.is(await resolveDnsOverHttps("1.2.3.4", undefined, signal(), fetchImpl), "1.2.3.4");
  t.is(await resolveDnsOverHttps("2001:db8::1", 6, signal(), fetchImpl), "2001:db8::1");
  t.deepEqual(urls, []);
});

test("hostnames are URL-encoded", async (t) => {
  const { urls, fetchImpl } = fakeFetch(() => answer([A("1.2.3.4")]));
  await resolveDnsOverHttps("a&b=c.example", 4, signal(), fetchImpl);
  t.deepEqual(urls, ["https://cloudflare-dns.com/dns-query?name=a%26b%3Dc.example&type=A"]);
});

test("an aborted signal rejects without any request", async (t) => {
  const controller = new AbortController();
  controller.abort();
  const { urls, fetchImpl } = fakeFetch(() => answer([A("1.2.3.4")]));
  await t.throwsAsync(resolveDnsOverHttps("example.com", 4, controller.signal, fetchImpl), {
    message: /aborted/,
  });
  t.deepEqual(urls, []);
});

test("a provider that doesn't answer in time is overtaken by the next one", async (t) => {
  const cloudflare = deferred();
  const { urls, signals, fetchImpl } = fakeFetch((url) =>
    isCloudflare(url) ? cloudflare.promise : answer([A("5.6.7.8")]),
  );
  const result = resolveDnsOverHttps("example.com", 4, signal(), fetchImpl, STAGGER_MS);
  t.is(await result, "5.6.7.8");
  t.deepEqual(urls, [CLOUDFLARE("A"), GOOGLE("A")]);
  // The loser is cancelled, and its late answer changes nothing.
  t.true(signals[0].aborted);
  cloudflare.resolve(answer([A("1.2.3.4")]));
  await sleep(STAGGER_MS * 4);
  t.is(await result, "5.6.7.8");
  t.deepEqual(urls, [CLOUDFLARE("A"), GOOGLE("A")]);
});

test("a failure starts the next provider without waiting for the stagger", async (t) => {
  const { urls, fetchImpl } = fakeFetch((url) =>
    isCloudflare(url) ? new Error("network down") : answer([A("5.6.7.8")]),
  );
  // A stagger far longer than the test timeout: the second request must not depend on it.
  t.is(await resolveDnsOverHttps("example.com", 4, signal(), fetchImpl, 60_000), "5.6.7.8");
  t.deepEqual(urls, [CLOUDFLARE("A"), GOOGLE("A")]);
});

test("the first answer wins while several providers are in flight", async (t) => {
  const cloudflare = deferred();
  const { urls, signals, fetchImpl } = fakeFetch((url) => {
    if (isCloudflare(url)) return cloudflare.promise;
    // Google has just been started because of the stagger; Cloudflare answers now, Google never.
    cloudflare.resolve(answer([A("1.2.3.4")]));
    return deferred().promise;
  });
  t.is(await resolveDnsOverHttps("example.com", 4, signal(), fetchImpl, STAGGER_MS), "1.2.3.4");
  t.deepEqual(urls, [CLOUDFLARE("A"), GOOGLE("A")]);
  t.true(signals[1].aborted);
});

test("no second request when the first provider answers within the stagger", async (t) => {
  const { urls, fetchImpl } = fakeFetch(() => answer([A("1.2.3.4")]));
  t.is(await resolveDnsOverHttps("example.com", 4, signal(), fetchImpl, STAGGER_MS), "1.2.3.4");
  await sleep(STAGGER_MS * 4);
  t.deepEqual(urls, [CLOUDFLARE("A")]);
});

test("aborting the signal while a request is pending rejects and starts nothing else", async (t) => {
  const controller = new AbortController();
  const { urls, signals, fetchImpl } = fakeFetch(() => deferred().promise);
  const result = resolveDnsOverHttps("example.com", undefined, controller.signal, fetchImpl, STAGGER_MS);
  t.deepEqual(urls, [CLOUDFLARE("A")]);
  controller.abort();
  await t.throwsAsync(result, { message: /aborted/ });
  t.true(signals[0].aborted);
  // Neither the next provider nor the AAAA lookup is started afterwards.
  await sleep(STAGGER_MS * 4);
  t.deepEqual(urls, [CLOUDFLARE("A")]);
});
