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
// By default the check then waits for `chainHead_v1_follow` to report
// `initialized` and records how long that took; `--handshake-only` stops at the
// handshake.
// With `--discover <s>`, the client keeps running for `s` seconds after the
// bootnode handshake and the peers smoldot learns about through it
// (`peer-discovered` events) are reported, marked with whether smoldot dialed
// and connected to each of their addresses.

import { start } from "smoldot";
import dns from "node:dns/promises";
import fs from "node:fs";
import net from "node:net";
import process from "node:process";

const USAGE = `Usage: node inspect.mjs [options] <chain-spec.json> [<chain-spec.json> ...]

Checks each bootnode of each given chain spec individually.
A parachain spec (one with a "relay_chain" field) needs its relay chain spec
passed as well.

Options:
  --timeout <s>      Seconds to wait per bootnode (default 300, or 30 with --handshake-only)
  --concurrency <n>  Bootnodes checked at the same time (default 4)
  --handshake-only   Stop at the libp2p handshake instead of waiting for
                     chainHead_v1_follow "initialized"
  --discover <s>     Keep running <s> seconds after the handshake and list the
                     peers discovered through the bootnode, marking the ones
                     smoldot connected to
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

// Returns { host, port, family, transport } for the address types the Node.js
// build of smoldot dials, or null for anything else (WebRTC, ...).
function parseTcpAddress(addr) {
  const m = stripPeerId(addr).match(
    /^\/(dns|dns4|dns6|dnsaddr|ip4|ip6)\/([^/]+)\/tcp\/(\d+)(?:\/(ws|wss|tls\/ws))?$/,
  );
  if (!m) return null;
  const [, kind, host, port, ws] = m;
  const family = kind === "dns4" || kind === "ip4" ? 4 : kind === "dns6" || kind === "ip6" ? 6 : 0;
  return { host, port: Number(port), family, transport: ws ? (ws === "ws" ? "ws" : "wss") : "tcp" };
}

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
    let a = p.addresses.get(addr);
    if (!a) {
      a = { addr, status: "not dialed", reason: null };
      p.addresses.set(addr, a);
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

// Plain DNS lookup plus TCP connect, independent of smoldot.
async function probeTcp({ host, port, family }) {
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
async function checkBootnode({ spec, address, opts, log }) {
  const target = stripPeerId(address);
  const parsed = parseTcpAddress(address);
  const result = {
    chain: spec.json.id,
    address,
    transport: parsed?.transport ?? null,
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
    result.reason = "address type not dialed by the Node.js build of smoldot";
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
  const discovery = opts.discoverMs > 0 ? new Discovery() : null;
  let discoverDone = opts.discoverMs === 0;
  let discoverTimer = null;
  const maybeFinishOk = () => {
    if (result.handshakeMs == null) return;
    if (opts.sync && result.initializedMs == null) return;
    if (!discoverDone) return;
    finish("ok");
  };

  const client = start({
    maxLogLevel: 5,
    logCallback: (level, logTarget, message) => {
      if (logTarget !== "network" && logTarget !== "connections") return;
      if (message.startsWith("connection-activity")) return;
      if (opts.verbose) log(`    ${Date.now() - t0}ms [${logTarget}] ${message}`);
      if (discovery && logTarget === "network") discovery.onLog(message);
      const addr = logParam(message, "remote_addr") ?? logParam(message, "address");
      if (addr !== target) return;
      if (message.startsWith("connection-started")) {
        if (dialedAt == null) dialedAt = Date.now();
      } else if (message.startsWith("handshake-finished-peer-id-mismatch")) {
        finish(
          "fail",
          `peer id mismatch: expected ${logParam(message, "expected_peer_id")}, got ${logParam(message, "actual_peer_id")}`,
        );
      } else if (message.startsWith("handshake-finished")) {
        if (result.handshakeMs != null) return;
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

  const jobs = [];
  for (const spec of specs.values()) {
    for (const address of spec.bootNodes) {
      jobs.push(() => checkBootnode({ spec, address, opts, log }));
    }
  }
  if (jobs.length === 0) {
    log("No bootnodes to check.");
    process.exit(2);
  }

  const total = jobs.length;
  let doneCount = 0;
  log(
    `Checking ${total} bootnode address(es) across ${specs.size} chain(s), timeout ${opts.timeoutMs / 1000}s, concurrency ${opts.concurrency}${opts.sync ? ", waiting for chainHead initialized" : ""}`,
  );
  const results = await runAll(jobs, opts.concurrency, (r) => {
    doneCount++;
    if (opts.json) return;
    const status = r.ok ? "OK  " : r.outcome === "skipped" ? "SKIP" : "FAIL";
    const parts = [`tcp=${fmtMs(r.tcpMs)}`, `handshake=${fmtMs(r.handshakeMs)}`];
    if (opts.sync) parts.push(`initialized=${fmtMs(r.initializedMs)}`);
    const reason = r.reason ? `  (${r.reason})` : "";
    let out = `[${doneCount}/${total}] ${status} ${r.chain} ${r.address}  ${parts.join(" ")}${reason}\n`;
    if (r.discovered) {
      const peers = r.discovered;
      const connectedPeers = peers.filter((p) => p.connected).length;
      const failedPeers = peers.filter((p) => p.status === "failed").length;
      const triedPeers = peers.filter((p) => p.status === "dialed").length;
      const untriedPeers = peers.length - connectedPeers - failedPeers - triedPeers;
      out += `    discovered ${peers.length} peer(s) through this bootnode: ${connectedPeers} connected, ${failedPeers} failed, ${triedPeers} still dialing, ${untriedPeers} not dialed\n`;
      const mark = { connected: "OK", failed: "FAIL", dialed: "dialing", "not dialed": "not dialed" };
      const width = Math.max(0, ...peers.flatMap((p) => p.addresses.map((a) => a.multiaddr.length)));
      for (const p of peers) {
        out += `\n      ${p.peerId}\n`;
        for (const a of p.addresses) {
          const note = a.status === "failed" && a.reason ? `  ${a.reason}` : "";
          out += `        ${a.multiaddr.padEnd(width)}  ${mark[a.status]}${note}\n`;
        }
      }
    }
    process.stdout.write(out);
  });

  const failed = results.filter((r) => r.outcome === "fail");
  if (opts.json) {
    process.stdout.write(
      `${JSON.stringify({ checkedAt: new Date().toISOString(), sync: opts.sync, timeoutMs: opts.timeoutMs, results }, null, 2)}\n`,
    );
  } else {
    process.stdout.write("\n");
    for (const spec of specs.values()) {
      const mine = results.filter((r) => r.chain === spec.json.id);
      if (mine.length === 0) continue;
      const okCount = mine.filter((r) => r.ok).length;
      const skipped = mine.filter((r) => r.outcome === "skipped").length;
      process.stdout.write(
        `${spec.json.id}: ${okCount}/${mine.length - skipped} bootnode addresses OK${skipped ? ` (${skipped} skipped)` : ""}\n`,
      );
    }
    if (failed.length > 0) {
      process.stdout.write("\nFailed:\n");
      for (const r of failed) process.stdout.write(`  ${r.chain} ${r.address}  ${r.reason}\n`);
    }
  }
  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch((e) => {
  process.stderr.write(`${e.stack ?? e}\n`);
  process.exit(2);
});
