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

// Helpers shared by the JAM bodies (`jam_*.js`) and by the manual demo harness
// (`wasm-node/javascript/demo/jam-harness.mjs`, which serves the wrong-authority
// spec built here). Host-agnostic like the rest of `shared/`: no Node APIs, only
// relative sibling imports.
//
// - BLAKE2b-256 for header hashes (the JAM header hash);
// - the wrong-authorities spec builder of F7 (chain-identity negative test);
// - a chainHead driver for one JAM chain (events with arrival times, requests);
// - the ordinary PolkaJam node's JSON-RPC over `fetch` (it answers CORS `*`);
// - WebTransport captures: request kinds per connection with the UP0 finalized
//   advertisements seen on it, and raw CE 130 exchanges;
// - the client's peer slots and `C(8)` refreshes, from its own log lines, as
//   the demo page shows them.

import { hexToBytes } from "./codec.js";

// ---------------------------------------------------------------------------
// Bytes and hashes

export function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const M64 = (1n << 64n) - 1n;
const IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & M64;

function mix(v, a, b, c, d, x, y) {
  v[a] = (v[a] + v[b] + x) & M64;
  v[d] = rotr(v[d] ^ v[a], 32n);
  v[c] = (v[c] + v[d]) & M64;
  v[b] = rotr(v[b] ^ v[c], 24n);
  v[a] = (v[a] + v[b] + y) & M64;
  v[d] = rotr(v[d] ^ v[a], 16n);
  v[c] = (v[c] + v[d]) & M64;
  v[b] = rotr(v[b] ^ v[c], 63n);
}

function compress(h, block, counter, last) {
  const view = new DataView(block.buffer, block.byteOffset, 128);
  const m = [];
  for (let i = 0; i < 16; i += 1) m.push(view.getBigUint64(i * 8, true));
  const v = [...h, ...IV];
  v[12] ^= counter & M64;
  v[13] ^= counter >> 64n;
  if (last) v[14] ^= M64;
  for (let round = 0; round < 12; round += 1) {
    const s = SIGMA[round % 10];
    mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (let i = 0; i < 8; i += 1) h[i] ^= v[i] ^ v[i + 8];
}

/** Unkeyed BLAKE2b with a 32-byte output (RFC 7693), the JAM hash. */
export function blake2b256(input) {
  const h = IV.slice();
  h[0] ^= 0x01010000n ^ 32n;
  const blocks = Math.max(1, Math.ceil(input.length / 128));
  let counter = 0n;
  for (let i = 0; i < blocks; i += 1) {
    const chunk = input.subarray(i * 128, i * 128 + 128);
    const block = new Uint8Array(128);
    block.set(chunk);
    counter += BigInt(chunk.length);
    compress(h, block, counter, i === blocks - 1);
  }
  const out = new Uint8Array(32);
  const view = new DataView(out.buffer);
  for (let i = 0; i < 4; i += 1) view.setBigUint64(i * 8, h[i], true);
  return out;
}

/** `0x`-prefixed BLAKE2b-256 of a hex-encoded header: its hash. */
export function hashOfHeaderHex(headerHex) {
  return "0x" + bytesToHex(blake2b256(hexToBytes(headerHex)));
}

/** The slot of an encoded header: after parent, prior state root and extrinsic hash. */
export function slotOfHeaderHex(headerHex) {
  const bytes = hexToBytes(headerHex);
  return new DataView(bytes.buffer).getUint32(96, true);
}

export const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Polls `check` until it returns a truthy value or `timeoutMs` passes (then `undefined`). */
export async function waitFor(check, timeoutMs, intervalMs = 250) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() >= deadline) return undefined;
    await delay(intervalMs);
  }
}

// ---------------------------------------------------------------------------
// Specs

/** File name the demo harness serves the negative fixture under. */
export const WRONG_SPEC_FILENAME = "spec-wrong-authorities.json";

/** One Ed25519 validator key; its size fixes every offset computed below. */
const ED25519_KEY_BYTES = 32;
/** Bandersnatch key in front of the Ed25519 key, in both the mark and C(4)/C(8). */
const BANDERSNATCH_KEY_BYTES = 32;
/** A full validator record: bandersnatch(32) ++ ed25519(32) ++ bls(144) ++ metadata(128). */
const VALIDATOR_RECORD_BYTES = 336;
/** parent(32) ++ prior_state_root(32) ++ extrinsic_hash(32) ++ slot(4). */
const HEADER_PREFIX_BYTES = 100;
/** The epoch mark's own prefix: entropy(32) ++ tickets_entropy(32). */
const EPOCH_MARK_ENTROPY_BYTES = 64;
/** Which byte of a key the fixture flips, and with what. One bit is enough. */
const KEY_BYTE_INDEX = ED25519_KEY_BYTES - 1;
const KEY_BYTE_MASK = 0x01;

/**
 * Decodes one Gray Paper appendix C natural number, the length prefix every
 * validator list carries since Gray Paper 0.8.0. Mirrors `Decoder::natural` in
 * `lib/src/jam/codec.rs`; the canonicality rule is irrelevant here because the
 * fixture only ever re-reads bytes PolkaJam wrote.
 */
function readNatural(bytes, offset) {
  const first = bytes[offset];
  if (first === undefined) throw new Error("truncated natural number");
  let extra = 0;
  while (extra < 8 && (first & (0x80 >> extra)) !== 0) extra += 1;
  if (extra === 8) {
    let value = 0n;
    for (let i = 0; i < 8; i += 1) value |= BigInt(bytes[offset + 1 + i]) << BigInt(8 * i);
    return { value: Number(value), next: offset + 9 };
  }
  let value = (first & (0x7f >> extra)) * 2 ** (8 * extra);
  for (let i = 0; i < extra; i += 1) value += bytes[offset + 1 + i] * 2 ** (8 * i);
  return { value, next: offset + 1 + extra };
}

/**
 * Where validator `index`'s Ed25519 key sits inside the genesis header's epoch
 * mark. Header wire order (planning `briefs/contracts.md` contract 1, Gray
 * Paper 0.8.0 `encode{header}`): parent, prior_state_root, extrinsic_hash,
 * slot, then the optional `epoch_mark`: entropy, tickets_entropy, a natural
 * count and that many (bandersnatch, ed25519) pairs.
 */
function epochMarkEd25519(header, index) {
  let offset = HEADER_PREFIX_BYTES;
  const present = header[offset];
  offset += 1;
  if (present !== 1) throw new Error(`genesis header carries no epoch mark (option tag ${present})`);
  offset += EPOCH_MARK_ENTROPY_BYTES;
  const { value: count, next } = readNatural(header, offset);
  if (index >= count) throw new Error(`epoch mark lists ${count} validators, no index ${index}`);
  const pair = next + index * (BANDERSNATCH_KEY_BYTES + ED25519_KEY_BYTES);
  return { offset: pair + BANDERSNATCH_KEY_BYTES, count };
}

/**
 * Where validator `index`'s Ed25519 key sits inside a validator list state
 * item: a natural count followed by 336-byte records. Used for C(8), the
 * active set, and for C(4), whose pending validator list is its first field.
 */
function validatorListEd25519(item, index) {
  const { value: count, next } = readNatural(item, 0);
  if (index >= count) throw new Error(`validator list holds ${count} records, no index ${index}`);
  return { offset: next + index * VALIDATOR_RECORD_BYTES + BANDERSNATCH_KEY_BYTES, count };
}

/** Key `C(i)`: the index byte followed by 30 zero bytes (`codec::state_key`). */
export function stateKey(index) {
  return index.toString(16).padStart(2, "0") + "00".repeat(30);
}

/**
 * How many validator keys the negative fixture alters: `count - quorum + 1`,
 * which denies the quorum `count * 2 / 3 + 1` that `lib/src/jam/finality.rs`
 * requires, so the rejection does not depend on who happened to sign a
 * fragment's justification. On the dev network that is 2 of 6.
 */
function alteredKeyCount(count) {
  return count - (Math.floor((count * 2) / 3) + 1) + 1;
}

const strip0x = (text) => (text.startsWith("0x") ? text.slice(2) : text);

/**
 * Builds the negative fixture of F7 (chain-identity negative test): a spec
 * whose genesis authority set is not the running network's, while every
 * field still decodes.
 *
 * The same byte of the same validators' Ed25519 keys is flipped in three
 * places that must agree: the genesis header's epoch mark, from which
 * `Finality::from_genesis` derives GRANDPA set 0; `C(8)`, the active
 * validators; and the pending validators at the head of `C(4)`. The genesis
 * hash changes as a side effect, which is what a Dummy network detects (CE 128
 * answers an unknown hash with NoData); the authority set is what a GRANDPA
 * network detects (the first warp fragment fails to authenticate).
 *
 * A spec that differed only in its genesis hash would NOT be rejected after a
 * warp: GRANDPA precommits sign (round, set_id, vote) and nothing chain
 * specific. See planning `followups.md` U7 (chain identity over WebTransport)
 * and U13 (chain-bound GRANDPA votes).
 */
export function corruptGenesisAuthorities(spec) {
  const wrong = JSON.parse(JSON.stringify(spec));
  const header = hexToBytes(strip0x(wrong.genesis_header));
  const active = hexToBytes(strip0x(wrong.genesis_state[stateKey(8)]));
  const safrole = hexToBytes(strip0x(wrong.genesis_state[stateKey(4)]));

  const { count } = epochMarkEd25519(header, 0);
  const altered = alteredKeyCount(count);
  if (altered < 1) throw new Error(`cannot deny a quorum among ${count} validators`);
  for (let index = 0; index < altered; index += 1) {
    for (const [bytes, where] of [
      [header, epochMarkEd25519(header, index)],
      [active, validatorListEd25519(active, index)],
      [safrole, validatorListEd25519(safrole, index)],
    ]) {
      bytes[where.offset + KEY_BYTE_INDEX] ^= KEY_BYTE_MASK;
    }
  }

  wrong.genesis_header = bytesToHex(header);
  wrong.genesis_state[stateKey(8)] = bytesToHex(active);
  wrong.genesis_state[stateKey(4)] = bytesToHex(safrole);
  if (wrong.genesis_header === strip0x(spec.genesis_header)) {
    throw new Error("failed to corrupt the genesis authority set");
  }
  // The three copies of each altered key must still agree, or the spec would
  // be rejected for a reason that has nothing to do with chain identity.
  const key = (bytes, offset) => bytesToHex(bytes.subarray(offset, offset + ED25519_KEY_BYTES));
  for (let index = 0; index < count; index += 1) {
    const inMark = key(header, epochMarkEd25519(header, index).offset);
    for (const item of [active, safrole]) {
      if (key(item, validatorListEd25519(item, index).offset) !== inMark) {
        throw new Error(`validator ${index} differs between the mark and a state item`);
      }
    }
  }
  return { spec: wrong, alteredKeys: altered, validatorCount: count };
}

/** `host:port` of a combined bootnode `<ed25519>[+<p256>]@host:port`. */
export function bootnodeAddress(bootnode) {
  return bootnode.slice(bootnode.lastIndexOf("@") + 1);
}

// ---------------------------------------------------------------------------
// One JAM chain on a smoldot client

const MAX_EVENTS = 20_000;

/**
 * Adds a chain and drives its JSON-RPC: `request(method, params)` resolves with
 * the result, follow events land in `events` with their arrival time `t`.
 */
export async function addJamChain(client, spec) {
  const chain = await client.addChain({
    chainSpec: typeof spec === "string" ? spec : JSON.stringify(spec),
  });
  const state = { chain, events: [], pending: new Map(), nextId: 0, ended: false };
  void (async () => {
    try {
      for await (const text of chain.jsonRpcResponses) {
        const message = JSON.parse(text);
        if (message.id !== undefined && state.pending.has(message.id)) {
          const pending = state.pending.get(message.id);
          state.pending.delete(message.id);
          clearTimeout(pending.timer);
          if (message.error) pending.reject(new Error(JSON.stringify(message.error)));
          else pending.resolve(message.result);
        } else if (message.method === "chainHead_v1_followEvent") {
          state.events.push({
            t: Date.now(),
            subscription: message.params.subscription,
            ...message.params.result,
          });
          if (state.events.length > MAX_EVENTS) state.events.splice(0, state.events.length - MAX_EVENTS);
        }
      }
    } catch (error) {
      state.events.push({ t: Date.now(), event: "driver-error", message: String(error) });
    }
    state.ended = true;
  })();
  state.request = (method, params = [], timeoutMs = 30_000) =>
    new Promise((resolve, reject) => {
      const id = ++state.nextId;
      const timer = setTimeout(() => {
        state.pending.delete(id);
        reject(new Error(`${method} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      state.pending.set(id, { resolve, reject, timer });
      try {
        chain.sendJsonRpc(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
      } catch (error) {
        clearTimeout(timer);
        state.pending.delete(id);
        reject(error);
      }
    });
  return state;
}

// ---------------------------------------------------------------------------
// The ordinary node's JSON-RPC

const base64ToHex = (text) => "0x" + bytesToHex(Uint8Array.from(atob(text), (c) => c.charCodeAt(0)));
const hexToBase64 = (hex) => btoa(String.fromCharCode(...hexToBytes(strip0x(hex))));

/** PolkaJam's RPC at `url`; block descriptors come back as `{ hash: "0x…", slot }`. */
export function nodeRpc(url) {
  const call = async (method, params = []) => {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(5000),
    });
    const body = await response.json();
    if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
    return body.result;
  };
  const block = (desc) => ({ hash: base64ToHex(desc.header_hash), slot: Number(desc.slot) });
  return {
    call,
    bestBlock: async () => block(await call("bestBlock")),
    finalizedBlock: async () => block(await call("finalizedBlock")),
    parent: async (hash) => block(await call("parent", [hexToBase64(hash)])),
  };
}

// ---------------------------------------------------------------------------
// WebTransport captures

/**
 * Wraps `WebTransport` so each session gets its own record, even at the same
 * URL. For every request stream it keeps the first 42 bytes written (kind,
 * then the request) and how many UP0 finalized advertisements the session had
 * delivered before the request went out; for UP0 it decodes each message's
 * finalized `(hash, slot)`. Must run before the client opens a connection.
 */
export function installJamWireCapture() {
  const wire = { connections: [], requests: [] };
  const Native = globalThis.WebTransport;
  if (!Native) return wire;
  globalThis.WebTransport = new Proxy(Native, {
    construct(target, args) {
      const transport = new target(...args);
      const connection = { id: wire.connections.length, url: String(args[0]), initialFinal: null, finals: [] };
      wire.connections.push(connection);
      const create = transport.createBidirectionalStream.bind(transport);
      transport.createBidirectionalStream = async (...createArgs) => {
        const stream = await create(...createArgs);
        const bytes = [];
        let incoming = [];
        let messages = 0;
        const getReader = stream.readable.getReader.bind(stream.readable);
        stream.readable.getReader = (...readerArgs) => {
          const reader = getReader(...readerArgs);
          const read = reader.read.bind(reader);
          reader.read = async (...readArgs) => {
            const result = await read(...readArgs);
            if (bytes[0] === 0 && result.value) {
              for (const byte of new Uint8Array(result.value.buffer, result.value.byteOffset, result.value.byteLength)) incoming.push(byte);
              while (incoming.length >= 4) {
                const length = new DataView(Uint8Array.from(incoming.slice(0, 4)).buffer).getUint32(0, true);
                if (length > 1024 * 1024) throw new Error("UP0 capture exceeds frame budget");
                if (incoming.length < length + 4) break;
                const payload = incoming.splice(0, length + 4).slice(4);
                const initial = messages++ === 0;
                const final = initial ? payload.slice(0, 36) : payload.slice(-36);
                if (final.length !== 36) throw new Error("Truncated UP0 finalized advertisement");
                const advertised = {
                  t: Date.now(),
                  hash: bytesToHex(final.slice(0, 32)),
                  slot: new DataView(Uint8Array.from(final.slice(32)).buffer).getUint32(0, true),
                };
                if (initial) connection.initialFinal = advertised;
                connection.finals.push(advertised);
              }
            }
            return result;
          };
          return reader;
        };
        const getWriter = stream.writable.getWriter.bind(stream.writable);
        stream.writable.getWriter = () => {
          const writer = getWriter();
          const write = writer.write.bind(writer);
          const close = writer.close.bind(writer);
          writer.write = (chunk) => {
            if (bytes.length < 42) bytes.push(...new Uint8Array(chunk).slice(0, 42 - bytes.length));
            return write(chunk);
          };
          writer.close = () => {
            wire.requests.push({ connection: connection.id, t: Date.now(), bytes, finalsSeen: connection.finals.length });
            return close();
          };
          return writer;
        };
        return stream;
      };
      return transport;
    },
  });
  return wire;
}

/**
 * Records every CE 130 (justification) exchange as `{ request, response }` hex,
 * at most 256 of them. Must run before the client opens a connection.
 */
export function installProofCapture() {
  const proofs = [];
  const proto = globalThis.WebTransport?.prototype;
  if (!proto) return proofs;
  const create = proto.createBidirectionalStream;
  proto.createBidirectionalStream = async function (...args) {
    const stream = await create.apply(this, args);
    const request = [];
    const writer = stream.writable.getWriter();
    const writable = new WritableStream({
      write(bytes) {
        if (request.length < 64) request.push(...new Uint8Array(bytes));
        return writer.write(bytes);
      },
      close() { return writer.close(); },
      abort(reason) { return writer.abort(reason); },
    });
    const [readable, capture] = stream.readable.tee();
    void (async () => {
      const reader = capture.getReader();
      const chunks = [];
      let length = 0;
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          length += value.length;
          if (length > 2 * 1024 * 1024) { void reader.cancel(); return; }
          chunks.push(value);
        }
        if (request[0] !== 130 || proofs.length >= 256) return;
        const bytes = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
        proofs.push({ request: bytesToHex(request), response: bytesToHex(bytes) });
      } catch {
        // A reset means no proof; the client handles that separately.
      }
    })();
    return { readable, writable };
  };
  return proofs;
}

// ---------------------------------------------------------------------------
// Peer slots, as the demo page shows them

const PEER_LOG = /^(jam-slot-assigned|jam-peer-connected|jam-peer-disconnected|jam-pool-changed|jam-discovery-failed)(?:; (.*))?$/;

/** `k=v, k=v` as the smoldot log formatter writes fields. */
export function logFields(text) {
  const fields = {};
  for (const part of text.split(", ")) {
    const at = part.indexOf("=");
    if (at > 0) fields[part.slice(0, at)] = part.slice(at + 1);
  }
  return fields;
}

/**
 * Folds the client's slot and pool log lines into the demo page's view: each
 * slot's peer (`source` bootnode, genesis or discovered; `address`; `state`
 * dialing, connected or disconnected) and every `C(8)` merge. Call `update()`
 * whenever new lines may have arrived; it reads `logs` incrementally.
 */
export function peerTracker(logs) {
  const view = { peers: [], refreshes: [], discoveryError: undefined };
  let cursor = 0;
  view.update = () => {
    // `logs` is bounded and may drop its oldest lines; never re-read.
    if (cursor > logs.length) cursor = logs.length;
    for (; cursor < logs.length; cursor += 1) {
      const match = PEER_LOG.exec(logs[cursor].message);
      if (!match) continue;
      const [, kind, rest] = match;
      const fields = logFields(rest ?? "");
      const at = logs[cursor].t;
      if (kind === "jam-pool-changed") {
        const number = (key) => (Number.isFinite(Number(fields[key])) ? Number(fields[key]) : undefined);
        view.refreshes.push({
          at, validators: number("validators"), usable: number("usable"),
          discovered: number("discovered"), added: number("added"), removed: number("removed"),
          retired: number("retired"), valueBytes: number("value_bytes"), elapsedMs: number("elapsed_ms"),
        });
        view.discoveryError = undefined;
      } else if (kind === "jam-discovery-failed") {
        view.discoveryError = fields.reason ?? "unknown";
      } else {
        const slot = Number(fields.slot);
        if (!Number.isInteger(slot) || slot < 0) continue;
        if (kind === "jam-peer-disconnected") {
          if (view.peers[slot]) Object.assign(view.peers[slot], { state: "disconnected", since: at });
        } else {
          view.peers[slot] = {
            slot, source: fields.source, address: fields.address,
            state: kind === "jam-peer-connected" ? "connected" : "dialing", since: at,
          };
        }
      }
    }
    return view;
  };
  view.connected = () => view.peers.filter((peer) => peer && peer.state === "connected");
  return view;
}
