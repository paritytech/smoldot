#!/usr/bin/env node
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

// Checks every bootnode listed in one or more chain specs by starting a
// separate smoldot light client per bootnode address, with a copy of the chain
// spec whose `bootNodes` contains only that address. The outcome is decided
// from smoldot's `network` / `connections` log events for that address:
//   - `handshake-finished`                           -> OK
//   - `connection-shutdown handshake_finished=false` -> FAIL (dial or handshake)
//   - nothing within the timeout                     -> FAIL (timeout)
// A plain DNS + TCP probe runs alongside so that a failure can be attributed
// to DNS, to the TCP port, or to the libp2p handshake. smoldot's Node.js TCP
// transport does not report socket errors (only its 4s handshake timeout
// ends such a connection), so without the probe every TCP failure would look
// the same.
// tcp, ws and wss addresses are dialed with the Node.js build of smoldot.
// webrtc-direct addresses are dialed with the browser build inside headless
// Chromium (see browser.mjs), when Playwright is installed.
// By default the check then waits for `chainHead_v1_follow` to report
// `initialized` and records how long that took; `--handshake-only` stops at the
// handshake.
// With `--discover <s>`, the client keeps running for `s` seconds after the
// bootnode handshake and the peers smoldot learns about through it
// (`peer-discovered` events) are reported, marked with whether smoldot dialed
// and connected to each of their addresses.

import { start } from "smoldot";
import { createBrowserHost } from "./browser.mjs";
import dns from "node:dns/promises";
import fs from "node:fs";
import net from "node:net";
import process from "node:process";

const USAGE = `Usage: node inspect.mjs [options] <chain-spec.json> [<chain-spec.json> ...]

Checks each bootnode of each given chain spec individually.
A parachain spec (one with a "relay_chain" field) needs its relay chain spec
passed as well.

Requirements:
  Node.js 18 or newer. tcp, ws and wss addresses are dialed with the Node
  build of smoldot. webrtc-direct addresses need headless Chromium, which
  comes from Playwright (optional dependency):
    npm install playwright && npx playwright install chromium-headless-shell

Options:
  --timeout <s>      Seconds to wait per bootnode (default 300, or 30 with --handshake-only)
  --concurrency <n>  Bootnodes checked at the same time (default 4)
  --handshake-only   Stop at the libp2p handshake instead of waiting for
                     chainHead_v1_follow "initialized"
  --discover <s>     Keep running <s> seconds after the handshake and list the
                     peers discovered through the bootnode, marking the ones
                     smoldot connected to
  --host <h>         auto (default): Node for tcp/ws/wss, Chromium for
                     webrtc-direct, WebRTC skipped if Chromium is missing;
                     node: Node only, WebRTC skipped;
                     browser: Chromium only, tcp skipped, exit 2 if missing
  --bootnode <addr>  Check this multiaddr (with /p2p/<peer id>) instead of the
                     spec's bootNodes; repeatable. Applies to the single spec
                     given, or to the parachain when a relay spec is given
                     too. Error with several parachain or unrelated specs.
  --json             Print results as JSON instead of text
  --verbose          Print every smoldot network log line
  -h, --help         Show this help
`;

const TCP_PROBE_TIMEOUT_MS = 10_000;

function parseArgs(argv) {
  const opts = {
    timeoutMs: null,
    concurrency: 4,
    sync: true,
    discoverMs: 0,
    host: "auto",
    bootnodes: [],
    json: false,
    verbose: false,
    specs: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--timeout":
        opts.timeoutMs = Number.parseFloat(argv[++i]) * 1000;
        break;
      case "--concurrency":
        opts.concurrency = Number.parseInt(argv[++i], 10);
        break;
      case "--handshake-only":
        opts.sync = false;
        break;
      case "--discover":
        opts.discoverMs = Number.parseFloat(argv[++i]) * 1000;
        if (!(opts.discoverMs > 0)) {
          process.stderr.write("--discover needs a positive number of seconds\n");
          process.exit(2);
        }
        break;
      case "--host":
        opts.host = argv[++i];
        if (!["auto", "node", "browser"].includes(opts.host)) {
          process.stderr.write("--host must be auto, node or browser\n");
          process.exit(2);
        }
        break;
      case "--bootnode": {
        const addr = argv[++i];
        if (!addr || !/\/p2p\/[^/]+$/.test(addr)) {
          process.stderr.write(`--bootnode needs a multiaddr ending in /p2p/<peer id>, got: ${addr}\n`);
          process.exit(2);
        }
        opts.bootnodes.push(addr);
        break;
      }
      case "--json":
        opts.json = true;
        break;
      case "--verbose":
        opts.verbose = true;
        break;
      case "-h":
      case "--help":
        process.stdout.write(USAGE);
        process.exit(0);
        break;
      default:
        if (a.startsWith("-")) {
          process.stderr.write(`Unknown option: ${a}\n\n${USAGE}`);
          process.exit(2);
        }
        opts.specs.push(a);
    }
  }
  if (opts.specs.length === 0) {
    process.stderr.write(USAGE);
    process.exit(2);
  }
  if (opts.timeoutMs == null || Number.isNaN(opts.timeoutMs)) {
    opts.timeoutMs = (opts.sync ? 300_000 : 30_000) + opts.discoverMs;
  }
  if (!Number.isInteger(opts.concurrency) || opts.concurrency < 1) {
    process.stderr.write("--concurrency must be a positive integer\n");
    process.exit(2);
  }
  return opts;
}

function loadSpecs(paths) {
  const specs = new Map();
  for (const p of paths) {
    const text = fs.readFileSync(p, "utf8");
    const json = JSON.parse(text);
    if (!json.id) throw new Error(`${p}: chain spec has no "id"`);
    specs.set(json.id, { path: p, json, text, bootNodes: json.bootNodes ?? [] });
  }
  for (const spec of specs.values()) {
    if (spec.json.relay_chain) {
      const relay = specs.get(spec.json.relay_chain);
      if (!relay) {
        throw new Error(
          `${spec.path}: relay chain "${spec.json.relay_chain}" not among the given specs`,
        );
      }
      spec.relay = relay;
    }
  }
  return specs;
}

// `/dns/host/tcp/30333/wss/p2p/12D3...` -> `/dns/host/tcp/30333/wss`.
// smoldot's log lines carry the address without the trailing `/p2p/<peer id>`.
function stripPeerId(addr) {
  return addr.replace(/\/p2p\/[^/]+$/, "");
}

// Formats an IPv6 address the way Rust's `Ipv6Addr` Display does (RFC 5952):
// lowercase, no leading zeros, longest run of two or more zero groups
// compressed to `::`, IPv4-mapped addresses as `::ffff:a.b.c.d`. smoldot
// prints addresses in that form, so a spec written differently would never
// match the log lines. Returns the input unchanged if it does not parse.
function canonicalIpv6(ip) {
  let s = ip.toLowerCase();
  let v4 = null;
  const dot = s.lastIndexOf(":");
  if (s.includes(".") && dot >= 0) {
    const tail = s.slice(dot + 1).split(".").map(Number);
    if (tail.length !== 4 || tail.some((n) => !(n >= 0 && n <= 255))) return ip;
    v4 = tail;
    s = `${s.slice(0, dot + 1)}${((tail[0] << 8) | tail[1]).toString(16)}:${((tail[2] << 8) | tail[3]).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return ip;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return ip;
  const groups = [...head, ...Array(missing).fill("0"), ...tail].map((g) => {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return NaN;
    return parseInt(g, 16);
  });
  if (groups.some(Number.isNaN)) return ip;
  if (v4 && groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    return `::ffff:${v4.join(".")}`;
  }
  let bestStart = -1;
  let bestLen = 1;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart < 0) return hex.join(":");
  return `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLen).join(":")}`;
}

// Normalizes a multiaddr for comparison with smoldot's log output.
function canonicalMultiaddr(addr) {
  return addr
    .replace(/^\/ip6\/([^/]+)/, (m, ip) => `/ip6/${canonicalIpv6(ip)}`)
    .replace(/^\/(dns|dns4|dns6|dnsaddr)\/([^/]+)/, (m, kind, host) => `/${kind}/${host.toLowerCase()}`);
}

// Returns { host, port, family, transport } with transport one of tcp, ws,
// wss, webrtc; or null for an address type smoldot cannot dial.
function parseAddress(addr) {
  const a = stripPeerId(addr);
  const fam = (kind) => (kind === "dns4" || kind === "ip4" ? 4 : kind === "dns6" || kind === "ip6" ? 6 : 0);
  let m = a.match(/^\/(dns|dns4|dns6|dnsaddr|ip4|ip6)\/([^/]+)\/tcp\/(\d+)(?:\/(ws|wss|tls\/ws))?$/);
  if (m) {
    const [, kind, host, port, ws] = m;
    return { host, port: Number(port), family: fam(kind), transport: ws ? (ws === "ws" ? "ws" : "wss") : "tcp" };
  }
  m = a.match(/^\/(dns|dns4|dns6|ip4|ip6)\/([^/]+)\/udp\/(\d+)\/webrtc-direct\/certhash\/[^/]+$/);
  if (m) {
    const [, kind, host, port] = m;
    return { host, port: Number(port), family: fam(kind), transport: "webrtc" };
  }
  return null;
}

// Which host dials this transport under the given --host setting, or null.
function hostFor(transport, mode) {
  if (mode === "node") return transport === "webrtc" ? null : "node";
  if (mode === "browser") return transport === "tcp" ? null : "browser";
  return transport === "webrtc" ? "browser" : "node";
}

const nodeHost = {
  name: "node",
  startClient: async ({ maxLogLevel, logCallback }) => start({ maxLogLevel, logCallback }),
  close: async () => {},
};

function logParam(message, key) {
  const m = message.match(new RegExp(`(?:^|[;,] )${key}=(.*?)(?:, [a-z_]+=|$)`));
  return m ? m[1] : null;
}

// `addrs=["/ip4/1.2.3.4/tcp/30333", "/dns/x/tcp/443/wss"]` -> array of strings.
function parseAddrList(value) {
  if (!value) return [];
  try {
    const arr = JSON.parse(value);
    return Array.isArray(arr) ? arr.filter((a) => typeof a === "string") : [];
  } catch {
    return [...value.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  }
}

// Tracks peers learnt through the bootnode and what happened to their addresses.
class Discovery {
  constructor() {
    this.peers = new Map();
  }

  peer(peerId) {
    let p = this.peers.get(peerId);
    if (!p) {
      p = { peerId, obtainedFrom: null, addresses: new Map() };
      this.peers.set(peerId, p);
    }
    return p;
  }

  addr(peerId, addr) {
    const p = this.peer(peerId);
    const key = canonicalMultiaddr(addr);
    let a = p.addresses.get(key);
    if (!a) {
      a = { addr, status: "not dialed", reason: null };
      p.addresses.set(key, a);
    }
    return a;
  }

  onLog(message) {
    if (message.startsWith("peer-discovered")) {
      const peerId = logParam(message, "peer_id");
      if (!peerId) return;
      const p = this.peer(peerId);
      p.obtainedFrom ??= logParam(message, "obtained_from");
      for (const addr of parseAddrList(logParam(message, "addrs"))) this.addr(peerId, addr);
    } else if (message.startsWith("connection-started")) {
      const peerId = logParam(message, "expected_peer_id");
      const addr = logParam(message, "remote_addr");
      if (!peerId || !addr || !this.peers.has(peerId)) return;
      const a = this.addr(peerId, addr);
      if (a.status === "not dialed") a.status = "dialed";
    } else if (message.startsWith("handshake-finished-peer-id-mismatch")) {
      const peerId = logParam(message, "expected_peer_id");
      const addr = logParam(message, "remote_addr");
      if (!peerId || !addr || !this.peers.has(peerId)) return;
      const a = this.addr(peerId, addr);
      a.status = "failed";
      a.reason = `peer id mismatch, got ${logParam(message, "actual_peer_id")}`;
    } else if (message.startsWith("handshake-finished")) {
      const peerId = logParam(message, "peer_id");
      const addr = logParam(message, "remote_addr");
      if (!peerId || !addr || !this.peers.has(peerId)) return;
      this.addr(peerId, addr).status = "connected";
    } else if (message.startsWith("connection-shutdown")) {
      const peerId = logParam(message, "peer_id");
      const addr = logParam(message, "address");
      if (!peerId || !addr || !this.peers.has(peerId)) return;
      const a = this.addr(peerId, addr);
      if (logParam(message, "handshake_finished") === "false" && a.status !== "connected") {
        a.status = "failed";
        a.reason ??= "handshake not completed";
      }
    }
  }

  toJSON() {
    const rank = { connected: 0, failed: 1, dialed: 2, "not dialed": 3 };
    const peers = [...this.peers.values()].map((p) => {
      const addresses = [...p.addresses.values()]
        .map((a) => ({ ...a, multiaddr: `${a.addr}/p2p/${p.peerId}` }))
        .sort((x, y) => rank[x.status] - rank[y.status]);
      const best = addresses.length ? addresses[0].status : "not dialed";
      return {
        peerId: p.peerId,
        obtainedFrom: p.obtainedFrom,
        connected: best === "connected",
        status: best,
        addresses,
      };
    });
    peers.sort((x, y) => rank[x.status] - rank[y.status] || x.peerId.localeCompare(y.peerId));
    return peers;
  }
}

// Plain DNS lookup plus TCP connect, independent of smoldot. WebRTC is UDP,
// so only the DNS part applies there.
async function probeTcp({ host, port, family, transport }) {
  const out = { dnsMs: null, ip: null, tcpMs: null, error: null };
  const t0 = Date.now();
  let ip = host;
  if (!net.isIP(host)) {
    try {
      const res = await dns.lookup(host, { family: family || undefined });
      ip = res.address;
      out.dnsMs = Date.now() - t0;
    } catch (e) {
      out.error = `dns: ${e.code ?? e.message}`;
      return out;
    }
  }
  out.ip = ip;
  if (transport === "webrtc") return out;
  await new Promise((resolve) => {
    const t1 = Date.now();
    const socket = net.createConnection({ host: ip, port });
    const finish = (err) => {
      socket.destroy();
      if (err) out.error = `tcp: ${err}`;
      else out.tcpMs = Date.now() - t1;
      resolve();
    };
    socket.setTimeout(TCP_PROBE_TIMEOUT_MS, () => finish(`connect timeout after ${TCP_PROBE_TIMEOUT_MS / 1000}s`));
    socket.once("connect", () => finish(null));
    socket.once("error", (e) => finish(e.code ?? e.message));
  });
  return out;
}

// Runs one check: a fresh smoldot client whose target chain has a single bootnode.
async function checkBootnode({ spec, address, opts, log, hosts }) {
  const target = canonicalMultiaddr(stripPeerId(address));
  const parsed = parseAddress(address);
  const hostName = parsed ? hostFor(parsed.transport, opts.host) : null;
  const host = hostName === "browser" ? hosts.browser : hostName === "node" ? nodeHost : null;
  const result = {
    chain: spec.json.id,
    address,
    transport: parsed?.transport ?? null,
    host: host?.name ?? null,
    ok: false,
    outcome: null,
    reason: null,
    dnsMs: null,
    tcpMs: null,
    handshakeMs: null,
    initializedMs: null,
    discovered: opts.discoverMs > 0 ? [] : undefined,
  };
  if (!parsed) {
    result.outcome = "skipped";
    result.reason = "address type smoldot cannot dial";
    return result;
  }
  if (!hostName) {
    result.outcome = "skipped";
    result.reason = `${parsed.transport} not dialed with --host ${opts.host}`;
    return result;
  }
  if (!host) {
    result.outcome = "skipped";
    result.reason = "headless Chromium not available: npm install playwright && npx playwright install chromium-headless-shell";
    return result;
  }

  const probe = probeTcp(parsed);

  const t0 = Date.now();
  let resolveDone;
  const done = new Promise((r) => (resolveDone = r));
  let finished = false;
  let dialedAt = null;
  const finish = (outcome, reason) => {
    if (finished) return;
    finished = true;
    result.outcome = outcome;
    result.reason = reason ?? null;
    resolveDone();
  };
  let lastResetReason = null;
  let webrtcResetTimer = null;
  const discovery = opts.discoverMs > 0 ? new Discovery() : null;
  let discoverDone = opts.discoverMs === 0;
  let discoverTimer = null;
  const maybeFinishOk = () => {
    if (result.handshakeMs == null) return;
    if (opts.sync && result.initializedMs == null) return;
    if (!discoverDone) return;
    finish("ok");
  };

  const client = await host.startClient({
    maxLogLevel: 5,
    logCallback: (level, logTarget, message) => {
      if (logTarget !== "network" && logTarget !== "connections") return;
      if (message.startsWith("connection-activity")) return;
      if (opts.verbose) log(`    ${Date.now() - t0}ms [${logTarget}] ${message}`);
      if (discovery && logTarget === "network") discovery.onLog(message);
      const addr = logParam(message, "remote_addr") ?? logParam(message, "address");
      if (addr == null || canonicalMultiaddr(addr) !== target) return;
      if (message.startsWith("connection-started")) {
        if (dialedAt == null) dialedAt = Date.now();
      } else if (message.startsWith("handshake-finished-peer-id-mismatch")) {
        finish(
          "fail",
          `peer id mismatch: expected ${logParam(message, "expected_peer_id")}, got ${logParam(message, "actual_peer_id")}`,
        );
      } else if (message.startsWith("handshake-finished")) {
        if (result.handshakeMs != null) return;
        if (webrtcResetTimer) clearTimeout(webrtcResetTimer);
        result.handshakeMs = Date.now() - t0;
        if (!discoverDone) {
          discoverTimer = setTimeout(() => {
            discoverDone = true;
            maybeFinishOk();
          }, opts.discoverMs);
        }
        maybeFinishOk();
      } else if (logTarget === "connections" && message.startsWith("reset")) {
        lastResetReason = logParam(message, "reason");
        // A WebRTC attempt can be reset and retried within a few seconds, and
        // smoldot is slow to report the shutdown; give a retry a chance first.
        if (parsed.transport === "webrtc" && result.handshakeMs == null && !webrtcResetTimer) {
          webrtcResetTimer = setTimeout(() => {
            if (result.handshakeMs == null) {
              finish("fail", lastResetReason ?? "WebRTC connection failed: UDP port unreachable or certhash no longer matches the node");
            }
          }, 8_000);
        }
      } else if (message.startsWith("connection-shutdown")) {
        if (logParam(message, "handshake_finished") === "false") {
          finish("fail", lastResetReason ?? "handshake not completed");
        } else if (opts.sync && result.initializedMs == null) {
          finish("fail", "connection closed after handshake, before initialized");
        }
      }
    },
  });

  let chain = null;
  let pump = null;
  try {
    const targetSpec = { ...spec.json, bootNodes: [address] };
    let potentialRelayChains;
    if (spec.relay) {
      const relay = await client.addChain({ chainSpec: spec.relay.text });
      potentialRelayChains = [relay];
    }
    chain = await client.addChain({
      chainSpec: JSON.stringify(targetSpec),
      potentialRelayChains,
    });

    if (opts.sync) {
      chain.sendJsonRpc(
        JSON.stringify({ jsonrpc: "2.0", id: 1, method: "chainHead_v1_follow", params: [false] }),
      );
      pump = (async () => {
        while (!finished) {
          let raw;
          try {
            raw = await chain.nextJsonRpcResponse();
          } catch {
            return;
          }
          let msg;
          try {
            msg = JSON.parse(raw);
          } catch {
            continue;
          }
          if (msg.method === "chainHead_v1_followEvent" && msg.params?.result?.event === "initialized") {
            if (result.initializedMs == null) result.initializedMs = Date.now() - t0;
            maybeFinishOk();
          }
        }
      })();
    }

    const timer = setTimeout(() => {
      if (dialedAt == null) {
        finish("fail", "smoldot never dialed the address within the timeout");
      } else if (result.handshakeMs == null) {
        finish("fail", "timeout before handshake");
      } else if (opts.sync && result.initializedMs == null) {
        finish("fail", "timeout before initialized");
      } else {
        discoverDone = true;
        finish("ok");
      }
    }, opts.timeoutMs);
    await done;
    clearTimeout(timer);
    if (discoverTimer) clearTimeout(discoverTimer);
    if (webrtcResetTimer) clearTimeout(webrtcResetTimer);
  } catch (e) {
    finish("fail", `error: ${e.message ?? e}`);
  } finally {
    try {
      await client.terminate();
    } catch {
      // ignore
    }
    if (pump) await pump;
  }

  if (discovery) result.discovered = discovery.toJSON();
  const tcp = await probe;
  result.dnsMs = tcp.dnsMs;
  result.tcpMs = tcp.tcpMs;
  result.ok = result.outcome === "ok";
  if (!result.ok && result.outcome === "fail") {
    if (tcp.error) {
      result.reason = tcp.error;
    } else if (result.reason === "handshake not completed") {
      const dialMs = dialedAt == null ? null : Date.now() - dialedAt;
      result.reason = `tcp connect ok (${tcp.tcpMs}ms) but libp2p handshake not completed${dialMs != null ? `, smoldot gave up after ${Math.round(dialMs / 1000)}s` : ""}`;
    }
  }
  return result;
}

async function runAll(jobs, concurrency, onResult) {
  const results = new Array(jobs.length);
  let next = 0;
  const worker = async () => {
    while (next < jobs.length) {
      const idx = next++;
      const r = await jobs[idx]();
      results[idx] = r;
      onResult(r, idx);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, jobs.length) }, worker));
  return results;
}

function fmtMs(ms) {
  return ms == null ? "-" : `${ms}ms`;
}

// ANSI colors on a terminal only; NO_COLOR disables them.
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, text) => (useColor ? `\x1b[${code}m${text}\x1b[0m` : text);
const green = (t) => paint(32, t);
const red = (t) => paint(31, t);
const yellow = (t) => paint(33, t);
const statusLabel = (status) =>
  status === "connected" || status === "ok" ? green("OK") :
  status === "failed" || status === "fail" ? red("FAIL") :
  status === "skipped" ? yellow("SKIP") : status;

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const specs = loadSpecs(opts.specs);
  const log = (s) => process.stderr.write(`${s}\n`);

  if (opts.bootnodes.length > 0) {
    const relayIds = new Set([...specs.values()].map((s) => s.json.relay_chain).filter(Boolean));
    const targets = [...specs.values()].filter((s) => !relayIds.has(s.json.id));
    if (targets.length !== 1) {
      log(`--bootnode needs exactly one chain to apply to, but ${targets.length} were given: ${targets.map((s) => s.json.id).join(", ")}`);
      process.exit(2);
    }
    for (const spec of specs.values()) if (spec !== targets[0]) spec.bootNodes = [];
    targets[0].bootNodes = opts.bootnodes;
  }

  const hosts = { browser: null };
  const needsBrowser = [...specs.values()].some((spec) =>
    spec.bootNodes.some((a) => hostFor(parseAddress(a)?.transport, opts.host) === "browser"),
  );
  if (needsBrowser) {
    hosts.browser = await createBrowserHost();
    if (!hosts.browser && opts.host === "browser") {
      log("--host browser needs headless Chromium: npm install playwright && npx playwright install chromium-headless-shell");
      process.exit(2);
    }
    if (!hosts.browser) log("Headless Chromium not available, WebRTC addresses will be skipped.");
  }

  const jobs = [];
  for (const spec of specs.values()) {
    for (const address of spec.bootNodes) {
      jobs.push(() => checkBootnode({ spec, address, opts, log, hosts }));
    }
  }
  if (jobs.length === 0) {
    log("No bootnodes to check.");
    process.exit(2);
  }

  const total = jobs.length;
  log(
    `Checking ${total} bootnode address(es) across ${specs.size} chain(s), timeout ${opts.timeoutMs / 1000}s, concurrency ${opts.concurrency}${opts.sync ? ", waiting for chainHead initialized" : ""}`,
  );
  // Print in spec order, grouped per chain, flushing as soon as every earlier
  // job has finished; under concurrency results arrive out of order.
  const pending = new Array(total);
  let cursor = 0;
  let group = null;
  const hostsUsed = new Set(
    [...specs.values()].flatMap((spec) => spec.bootNodes.map((a) => hostFor(parseAddress(a)?.transport, opts.host))).filter(Boolean),
  );
  const render = (r, idx) => {
    const status = r.ok ? `${statusLabel("ok")}  ` : statusLabel(r.outcome);
    // Fixed-width columns: tcp=1234ms, handshake=1234ms, initialized=123456ms.
    const parts = [`tcp=${fmtMs(r.tcpMs)}`.padEnd(10), `handshake=${fmtMs(r.handshakeMs)}`.padEnd(17)];
    if (opts.sync) parts.push(`initialized=${fmtMs(r.initializedMs)}`.padEnd(20));
    if (hostsUsed.size > 1 || r.host === "browser") parts.push(r.host === "browser" ? "via=browser" : "via=node   ");
    const reason = r.reason ? `  (${r.reason})` : "";
    let out = "";
    if (!group || group.chain !== r.chain) {
      const addrs = specs.get(r.chain).bootNodes;
      const size = addrs.length;
      group = { chain: r.chain, size, seen: 0, width: Math.max(...addrs.map((a) => a.length)) };
      out += `${idx === 0 ? "" : "\n"}${r.chain} (${size} bootnode address${size === 1 ? "" : "es"})\n`;
    }
    group.seen++;
    const num = `[${group.seen}/${group.size}]`.padEnd(`[${group.size}/${group.size}]`.length);
    out += `  ${num} ${status} ${r.address.padEnd(group.width)}  ${parts.join(" ").trimEnd()}${reason}\n`;
    if (r.discovered) {
      const peers = r.discovered;
      const connectedPeers = peers.filter((p) => p.connected).length;
      const failedPeers = peers.filter((p) => p.status === "failed").length;
      const triedPeers = peers.filter((p) => p.status === "dialed").length;
      const untriedPeers = peers.length - connectedPeers - failedPeers - triedPeers;
      out += `    discovered ${peers.length} peer(s) through this bootnode: ${connectedPeers} connected, ${failedPeers} failed, ${triedPeers} still dialing, ${untriedPeers} not dialed\n`;
      const width = Math.max(0, ...peers.flatMap((p) => p.addresses.map((a) => a.multiaddr.length)));
      for (const p of peers) {
        out += `\n      ${p.peerId}\n`;
        for (const a of p.addresses) {
          const note = a.status === "failed" && a.reason ? `  ${a.reason}` : "";
          out += `        ${a.multiaddr.padEnd(width)}  ${statusLabel(a.status)}${note}\n`;
        }
      }
    }
    process.stdout.write(out);
  };
  const results = await runAll(jobs, opts.concurrency, (r, idx) => {
    if (opts.json) return;
    pending[idx] = r;
    while (cursor < total && pending[cursor]) {
      render(pending[cursor], cursor);
      pending[cursor] = undefined;
      cursor++;
    }
  });
  if (hosts.browser) await hosts.browser.close();
  const failed = results.filter((r) => r.outcome === "fail");
  if (opts.json) {
    process.stdout.write(
      `${JSON.stringify({ checkedAt: new Date().toISOString(), sync: opts.sync, timeoutMs: opts.timeoutMs, results }, null, 2)}\n`,
    );
  }
  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch((e) => {
  process.stderr.write(`${e.stack ?? e}\n`);
  process.exit(2);
});
