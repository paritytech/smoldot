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
// involved: `fetch` is stubbed, and the URLs, headers and abort signals it is
// called with are recorded. Queries and answers are RFC 8484 wire-format
// messages, built by hand below.

import test from "ava";
import {
  encodeDnsQuery,
  parseDnsMessageAnswer,
  resolveDnsOverHttps,
} from "../dist/mjs/internals/dns-over-https.js";

// Queries for `example.com`, base64url-encoded as the `dns` parameter carries them.
const QUERY = {
  A: "AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE",
  AAAA: "AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAAcAAE",
};

const CLOUDFLARE = (type) => `https://cloudflare-dns.com/dns-query?dns=${QUERY[type]}`;
const QUAD9 = (type) => `https://dns.quad9.net/dns-query?dns=${QUERY[type]}`;
const DNSSB = (type) => `https://doh.dns.sb/dns-query?dns=${QUERY[type]}`;
const GOOGLE = (type) => `https://dns.google/dns-query?dns=${QUERY[type]}`;
const isCloudflare = (url) => url.startsWith("https://cloudflare-dns.com/");
const asksFor = (url, type) => url.endsWith(QUERY[type]);

const u16 = (n) => [n >> 8, n & 0xff];

/** Wire form of a domain name: length-prefixed labels ending with the root label. */
function encodeName(name) {
  const bytes = [];
  for (const label of name.split(".")) {
    bytes.push(label.length);
    for (const c of label) bytes.push(c.charCodeAt(0));
  }
  bytes.push(0);
  return bytes;
}

// The question of every message below is `example.com`, at offset 12. Records refer to it with
// a compression pointer, like real resolvers do.
const POINTER = [0xc0, 0x0c];

/** A resource record of the answer section. `name` defaults to a pointer to the question. */
const record = (type, data, name = POINTER) => ({ type, data, name });
const A = (ip) => record(1, ip.split(".").map(Number));
const AAAA = (groups) => record(28, groups.flatMap(u16));
const CNAME = (target) => record(5, encodeName(target));
const RRSIG = () => record(46, new Array(20).fill(0xab));

/**
 * Builds a DNS response message: a header with the given flags, the `example.com` question,
 * and the given answer records.
 */
function message({ rcode = 0, tc = false, qr = true, answers = [] } = {}) {
  // QR, RD and RA, plus the optional TC and the RCODE.
  const flags = (qr ? 0x8000 : 0) | 0x0180 | (tc ? 0x0200 : 0) | rcode;
  const bytes = [0, 0, ...u16(flags), ...u16(1), ...u16(answers.length), 0, 0, 0, 0];
  bytes.push(...encodeName("example.com"), ...u16(1), ...u16(1));
  for (const { type, data, name } of answers)
    bytes.push(...name, ...u16(type), ...u16(1), 0, 0, 0, 60, ...u16(data.length), ...data);
  return new Uint8Array(bytes);
}

const answer = (records) => ({ body: message({ answers: records }) });

/**
 * Builds a `fetch` stub. `handler(url)` returns `{ status?, body }`, an
 * `Error` to make the call reject, or a promise of either to answer later.
 * A pending call rejects with an `AbortError` when its signal is aborted.
 * The URLs, headers and signals are recorded in call order.
 */
function fakeFetch(handler) {
  const urls = [];
  const headers = [];
  const signals = [];
  const fetchImpl = (url, init) => {
    urls.push(String(url));
    headers.push(init?.headers);
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
          resolve({
            ok: status >= 200 && status < 300,
            status,
            arrayBuffer: async () => body.buffer,
          });
        },
        (error) => {
          signal?.removeEventListener("abort", onAbort);
          reject(error);
        },
      );
    });
  };
  return { urls, headers, signals, fetchImpl };
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

test("encodeDnsQuery builds the query of the RFC 8484 example", (t) => {
  // Section 4.1.1 of the RFC.
  t.is(encodeDnsQuery("www.example.com", 4), "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB");
  t.is(encodeDnsQuery("example.com", 4), QUERY.A);
  t.is(encodeDnsQuery("example.com", 6), QUERY.AAAA);
  t.is(encodeDnsQuery("example.com.", 4), QUERY.A);
});

test("encodeDnsQuery rejects names that don't fit the wire format", (t) => {
  const label = (length) => "a".repeat(length);
  t.notThrows(() => encodeDnsQuery(`${label(63)}.example`, 4));
  t.throws(() => encodeDnsQuery(`${label(64)}.example`, 4), { message: "invalid hostname" });
  t.throws(() => encodeDnsQuery("a..example", 4), { message: "invalid hostname" });
  t.throws(() => encodeDnsQuery("", 4), { message: "invalid hostname" });
  t.throws(() => encodeDnsQuery("bücher.example", 4), { message: "invalid hostname" });
  t.throws(() => encodeDnsQuery("a b.example", 4), { message: "invalid hostname" });
  // Four 60-byte labels make a 243-byte name, five a 304-byte one.
  t.notThrows(() => encodeDnsQuery(new Array(4).fill(label(60)).join("."), 4));
  t.throws(() => encodeDnsQuery(new Array(5).fill(label(60)).join("."), 4), { message: "invalid hostname" });
});

test("parseDnsMessageAnswer keeps only the records of the wanted family", (t) => {
  const body = message({
    answers: [
      CNAME("alias.example.com"),
      A("93.184.216.34"),
      RRSIG(),
      AAAA([0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946]),
      // A record whose name is spelled out instead of pointing at the question.
      record(1, [1, 2, 3, 4], encodeName("alias.example.com")),
    ],
  });
  t.deepEqual(parseDnsMessageAnswer(body, 4), ["93.184.216.34", "1.2.3.4"]);
  t.deepEqual(parseDnsMessageAnswer(body, 6), ["2606:2800:220:1:248:1893:25c8:1946"]);
});

test("parseDnsMessageAnswer writes IPv6 addresses in their conventional form", (t) => {
  const ipv6 = (groups) => parseDnsMessageAnswer(message({ answers: [AAAA(groups)] }), 6)[0];
  t.is(ipv6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]), "2001:db8::1");
  t.is(ipv6([0, 0, 0, 0, 0, 0, 0, 1]), "::1");
  t.is(ipv6([0, 0, 0, 0, 0, 0, 0, 0]), "::");
  t.is(ipv6([1, 2, 3, 4, 5, 6, 7, 8]), "1:2:3:4:5:6:7:8");
  t.is(ipv6([0, 0, 1, 2, 3, 4, 5, 6]), "::1:2:3:4:5:6");
  t.is(ipv6([1, 2, 3, 4, 5, 6, 0, 0]), "1:2:3:4:5:6::");
  // The first run of two or more zero groups is collapsed. A single zero group isn't.
  t.is(ipv6([1, 0, 0, 2, 0, 0, 0, 3]), "1::2:0:0:0:3");
  t.is(ipv6([1, 0, 2, 3, 4, 5, 6, 7]), "1:0:2:3:4:5:6:7");
  t.is(ipv6([1, 2, 0, 0, 3, 4, 5, 6]), "1:2::3:4:5:6");
});

test("parseDnsMessageAnswer yields nothing for error codes and empty answers", (t) => {
  const ok = message({ answers: [A("1.2.3.4")] });
  t.deepEqual(parseDnsMessageAnswer(ok, 4), ["1.2.3.4"]);
  t.deepEqual(parseDnsMessageAnswer(ok, 6), []);
  t.deepEqual(parseDnsMessageAnswer(message({ rcode: 3, answers: [A("1.2.3.4")] }), 4), []);
  t.deepEqual(parseDnsMessageAnswer(message(), 4), []);
  // Records whose data doesn't have the size of an address are skipped.
  t.deepEqual(parseDnsMessageAnswer(message({ answers: [record(1, [1, 2, 3, 4, 5]), record(28, [1, 2, 3, 4])] }), 4), []);
});

test("parseDnsMessageAnswer throws on malformed messages", (t) => {
  const malformed = (bytes) => t.throws(() => parseDnsMessageAnswer(bytes, 4), { message: "malformed answer" });
  malformed(message({ tc: true, answers: [A("1.2.3.4")] }));
  malformed(message({ qr: false, answers: [A("1.2.3.4")] }));
  // Cut short at every possible length.
  const ok = message({ answers: [A("1.2.3.4")] });
  for (let length = 0; length < ok.length; length++) malformed(ok.subarray(0, length));
  // A name with a reserved label type, and a compression pointer cut in half.
  malformed(message({ answers: [record(1, [1, 2, 3, 4], [0x80, 0x0c])] }));
  malformed(new Uint8Array([...message().subarray(0, 12), 0xc0]));
});

test("requests carry the wire-format query and ask for a DNS message back", async (t) => {
  const { urls, headers, fetchImpl } = fakeFetch(() => answer([A("1.2.3.4")]));
  t.is(await resolveDnsOverHttps("example.com", 4, signal(), fetchImpl), "1.2.3.4");
  t.deepEqual(urls, [CLOUDFLARE("A")]);
  t.deepEqual(headers, [{ accept: "application/dns-message" }]);
});

test("falls back to the next provider when the first one fails", async (t) => {
  const { urls, fetchImpl } = fakeFetch((url) =>
    isCloudflare(url) ? { status: 502, body: null } : answer([A("1.2.3.4")]),
  );
  t.is(await resolveDnsOverHttps("example.com", 4, signal(), fetchImpl), "1.2.3.4");
  t.deepEqual(urls, [CLOUDFLARE("A"), QUAD9("A")]);
});

test("a malformed answer counts as a failure of that provider", async (t) => {
  const { urls, fetchImpl } = fakeFetch((url) =>
    isCloudflare(url) ? { body: new Uint8Array([1, 2, 3]) } : answer([A("1.2.3.4")]),
  );
  t.is(await resolveDnsOverHttps("example.com", 4, signal(), fetchImpl), "1.2.3.4");
  t.deepEqual(urls, [CLOUDFLARE("A"), QUAD9("A")]);
  const { fetchImpl: garbage } = fakeFetch(() => ({ body: new Uint8Array([1, 2, 3]) }));
  await t.throwsAsync(resolveDnsOverHttps("example.com", 4, signal(), garbage), {
    message: "dns.google: malformed answer",
  });
});

test("/dns/ asks for A records first and stops at the first answer", async (t) => {
  const { urls, fetchImpl } = fakeFetch(() => answer([A("1.2.3.4"), A("5.6.7.8")]));
  t.is(await resolveDnsOverHttps("example.com", undefined, signal(), fetchImpl), "1.2.3.4");
  t.deepEqual(urls, [CLOUDFLARE("A")]);
});

test("/dns/ falls back to AAAA records when there is no A record", async (t) => {
  const { urls, fetchImpl } = fakeFetch((url) =>
    asksFor(url, "A") ? answer([]) : answer([AAAA([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])]),
  );
  t.is(await resolveDnsOverHttps("example.com", undefined, signal(), fetchImpl), "2001:db8::1");
  t.deepEqual(urls, [CLOUDFLARE("A"), QUAD9("A"), DNSSB("A"), GOOGLE("A"), CLOUDFLARE("AAAA")]);
});

test("/dns6/ never asks for A records", async (t) => {
  const { urls, fetchImpl } = fakeFetch(() => answer([AAAA([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])]));
  t.is(await resolveDnsOverHttps("example.com", 6, signal(), fetchImpl), "2001:db8::1");
  t.deepEqual(urls, [CLOUDFLARE("AAAA")]);
});

test("rejects with the last provider's error when every provider fails", async (t) => {
  const { urls, fetchImpl } = fakeFetch(() => new Error("network down"));
  await t.throwsAsync(resolveDnsOverHttps("example.com", 4, signal(), fetchImpl), {
    message: "dns.google: network down",
  });
  t.deepEqual(urls, [CLOUDFLARE("A"), QUAD9("A"), DNSSB("A"), GOOGLE("A")]);
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

test("an invalid hostname is rejected without any request", async (t) => {
  const { urls, fetchImpl } = fakeFetch(() => new Error("must not be called"));
  await t.throwsAsync(resolveDnsOverHttps("a..example", undefined, signal(), fetchImpl), {
    message: "invalid hostname",
  });
  await t.throwsAsync(resolveDnsOverHttps("bücher.example", 4, signal(), fetchImpl), {
    message: "invalid hostname",
  });
  t.deepEqual(urls, []);
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
  t.deepEqual(urls, [CLOUDFLARE("A"), QUAD9("A")]);
  // The loser is cancelled, and its late answer changes nothing.
  t.true(signals[0].aborted);
  cloudflare.resolve(answer([A("1.2.3.4")]));
  await sleep(STAGGER_MS * 4);
  t.is(await result, "5.6.7.8");
  t.deepEqual(urls, [CLOUDFLARE("A"), QUAD9("A")]);
});

test("a failure starts the next provider without waiting for the stagger", async (t) => {
  const { urls, fetchImpl } = fakeFetch((url) =>
    isCloudflare(url) ? new Error("network down") : answer([A("5.6.7.8")]),
  );
  // A stagger far longer than the test timeout: the second request must not depend on it.
  t.is(await resolveDnsOverHttps("example.com", 4, signal(), fetchImpl, 60_000), "5.6.7.8");
  t.deepEqual(urls, [CLOUDFLARE("A"), QUAD9("A")]);
});

test("the first answer wins while several providers are in flight", async (t) => {
  const cloudflare = deferred();
  const { urls, signals, fetchImpl } = fakeFetch((url) => {
    if (isCloudflare(url)) return cloudflare.promise;
    // Quad9 has just been started because of the stagger; Cloudflare answers now, Quad9 never.
    cloudflare.resolve(answer([A("1.2.3.4")]));
    return deferred().promise;
  });
  t.is(await resolveDnsOverHttps("example.com", 4, signal(), fetchImpl, STAGGER_MS), "1.2.3.4");
  t.deepEqual(urls, [CLOUDFLARE("A"), QUAD9("A")]);
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
