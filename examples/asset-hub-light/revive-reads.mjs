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

// Reads a `pallet-revive` contract's storage on a period, the way a name resolution does.
//
// Following a chain costs a node almost nothing: headers are announced to everyone anyway. What
// costs it real CPU is being asked for proofs, and the most expensive proofs a light client asks
// for are contract reads, because contract storage lives in a child trie and each read becomes a
// `RemoteReadChildRequest` the node has to build a Merkle proof for. That is the load this module
// generates.
//
// The shape is taken from dotli, which resolves `.dot` names by reading the dotNS resolver
// contract's storage directly rather than executing it. Each resolution is:
//
//   1. one main-trie read of `Revive::AccountInfoOf[address]`, to learn the contract's trie id,
//   2. one child-trie read of that trie, for the storage slots the name maps to.
//
// Step 1 looks redundant and is not: the trie id is what names the child trie, and dotli
// deliberately re-reads it every time rather than caching, because a redeployed contract would
// otherwise be served from a trie that no longer exists. Keeping it here keeps the request mix
// honest — a third of a resolution's round trips are this lookup.
//
// The contract and the keys come from `revive-queries.json`, written by
// `discover-revive-contracts.mjs`. Nothing is derived at run time: the keys of a contract's child
// trie are `blake2_256` of an EVM storage slot, and Node has no blake2_256 — nor keccak256, nor
// the twox128 the main-trie prefix needs. Precomputing them is what lets this example keep having
// no dependencies, and it keeps hashing out of a hot loop that is supposed to be measuring a node.

import * as fs from 'node:fs';

// `twox128("Revive") ++ twox128("AccountInfoOf")`. `AccountInfoOf` is
// `StorageMap<_, Identity, H160, AccountInfo<T>>`, and the Identity hasher means the 20 address
// bytes are appended raw, so this constant is the whole of the hashing a main-trie read needs.
// `discover-revive-contracts.mjs` records the prefix it actually found on the chain, and that is
// what gets used; this is the fallback and the documentation of where it comes from.
const ACCOUNT_INFO_OF_PREFIX =
    '0x735f040a5d490f1107ad9c56f5ca00d2ae37ff0591fdbbcd9c2406df7147a9dc';

// How long a single read set may take before it is given up on. Past this the answer has stopped
// being interesting: a resolution still running after 30 s has failed as far as anyone waiting on
// it is concerned, whatever it eventually returns, and letting it run would let slow read sets
// pile up on top of each other.
const READ_SET_DEADLINE_MS = 30_000;

// How many read-set durations the percentiles are computed over. The counts in the periodic line
// are for the whole run, but the percentiles are a rolling window: a process that runs for days
// should not report a p99 dominated by what happened while it was still warp-syncing, and one
// number per read set kept forever is a leak, however slow.
const DURATION_WINDOW = 1000;

export function loadQueryConfig(file) {
    const config = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (typeof config.contract !== 'string' || !/^0x[0-9a-f]{40}$/i.test(config.contract))
        throw new Error(`${file}: "contract" must be a 0x-prefixed 20-byte address`);
    if (!Array.isArray(config.keys) || config.keys.length === 0)
        throw new Error(`${file}: "keys" must be a non-empty array`);
    for (const entry of config.keys) {
        if (typeof entry?.key !== 'string' || !/^0x[0-9a-f]+$/i.test(entry.key))
            throw new Error(`${file}: every key must be a 0x-prefixed hex string`);
    }
    return config;
}

// A storage read that did not produce a value for a key is not an error: smoldot reports an unset
// key by simply not mentioning it, so a read set has to distinguish "absent" from "failed". These
// are the failures.
class ReadError extends Error {
    constructor(kind, message) {
        super(message);
        this.kind = kind;
    }
}

function percentile(sorted, fraction) {
    if (sorted.length === 0)
        return 0;
    const index = Math.min(sorted.length - 1, Math.ceil(fraction * sorted.length) - 1);
    return sorted[Math.max(0, index)];
}

// `AccountInfo { account_type: AccountType, dust: u32 }` with `AccountType::Contract` as variant
// 0, carrying `ContractInfo { trie_id: Vec<u8>, … }`. Only the trie id is wanted, so this decodes
// the variant tag and the SCALE compact length in front of it and stops.
function decodeTrieId(value) {
    const bytes = Buffer.from(value.slice(2), 'hex');
    if (bytes.length === 0)
        throw new ReadError('decode', 'AccountInfoOf is empty: no such revive account');
    if (bytes[0] !== 0x00)
        throw new ReadError('decode',
            `AccountInfoOf variant is 0x${bytes[0].toString(16).padStart(2, '0')}, not a contract`);

    const first = bytes[1];
    let length;
    let offset;
    switch (first & 0b11) {
        case 0b00: length = first >>> 2; offset = 2; break;
        case 0b01: length = ((first >>> 2) | (bytes[2] << 6)) >>> 0; offset = 3; break;
        case 0b10:
            length = ((first >>> 2) | (bytes[2] << 6) | (bytes[3] << 14) | (bytes[4] << 22)) >>> 0;
            offset = 5;
            break;
        default:
            throw new ReadError('decode', 'trie id length is a big integer, which cannot be right');
    }
    if (offset + length > bytes.length)
        throw new ReadError('decode', `trie id of ${length} bytes does not fit in the value`);
    return '0x' + bytes.subarray(offset, offset + length).toString('hex');
}

/**
 * Starts issuing read sets on a period. Returns the handle `index.mjs` drives it with:
 * `onNotification` must be given every JSON-RPC notification from the chain — it returns true
 * when it consumed one — and `summary` produces the aggregate line for the periodic report.
 */
export function startReviveReads({ request, log, config, options }) {
    const accountInfoKey = (config.accountInfoPrefix ?? ACCOUNT_INFO_OF_PREFIX)
        + config.contract.slice(2).toLowerCase();

    let followSubscription;         // null while re-following.
    let currentBlock;               // Hash every read set pins to, or undefined before the first.
    const pinned = new Set();       // Hashes smoldot has pinned for us and we have not released.
    const held = new Map();         // hash -> how many read sets are currently using it.
    const operations = new Map();   // operationId -> the promise waiting on it.
    let stopped = false;
    let inFlight = false;           // One read set at a time; a tick that overlaps is dropped.

    const stats = {
        started: 0, ok: 0, failed: 0, dropped: 0, skipped: 0, durations: [], failures: new Map(),
    };
    let timer;                      // The pending tick, so that `stop` can cancel it.

    // A block must not be unpinned while a read set is still reading at it, or the reads fail
    // with "unknown or unpinned block" — so unpins that arrive at the wrong moment are deferred
    // until the last reader lets go.
    const unpinQueue = new Set();

    function flushUnpins() {
        const ready = [...unpinQueue].filter((hash) => !held.has(hash) && hash !== currentBlock);
        if (ready.length === 0 || !followSubscription)
            return;
        for (const hash of ready) {
            unpinQueue.delete(hash);
            pinned.delete(hash);
        }
        // Nothing useful can be done if this fails: the subscription is going away anyway, and
        // smoldot will drop the pins with it.
        request('chainHead_v1_unpin', [followSubscription, ready]).catch(() => {});
    }

    function release(hash) {
        const count = held.get(hash);
        if (count === undefined)
            return;
        if (count <= 1)
            held.delete(hash);
        else
            held.set(hash, count - 1);
        flushUnpins();
    }

    function retire(hashes) {
        for (const hash of hashes) {
            if (pinned.has(hash) && hash !== currentBlock)
                unpinQueue.add(hash);
        }
        flushUnpins();
    }

    function resetFollowState(reason) {
        for (const operation of operations.values())
            operation.reject(new ReadError('follow', `the follow subscription ${reason}`));
        operations.clear();
        pinned.clear();
        unpinQueue.clear();
        held.clear();
        followSubscription = undefined;
        currentBlock = undefined;
    }

    async function follow() {
        if (stopped)
            return;
        try {
            followSubscription = await request('chainHead_v1_follow', [false]);
        } catch (error) {
            log(`revive: chainHead_v1_follow failed: ${error.message}`);
            followSubscription = undefined;
        }
    }

    function onFollowEvent(event) {
        switch (event.event) {
            case 'initialized': {
                const hashes = event.finalizedBlockHashes ?? [];
                for (const hash of hashes)
                    pinned.add(hash);
                currentBlock = hashes[hashes.length - 1];
                retire(hashes);
                break;
            }

            case 'newBlock':
                pinned.add(event.blockHash);
                break;

            // `bestBlockChanged` is ignored on purpose. Reading at the finalized block is what
            // dotli does, and it is also what makes a read set reproducible: a best block can be
            // forked away underneath a multi-call read, a finalized one cannot.
            case 'bestBlockChanged':
                break;

            case 'finalized': {
                const finalized = event.finalizedBlockHashes ?? [];
                if (finalized.length > 0)
                    currentBlock = finalized[finalized.length - 1];
                retire([...finalized, ...(event.prunedBlockHashes ?? [])]);
                break;
            }

            case 'operationStorageItems': {
                const operation = operations.get(event.operationId);
                if (operation)
                    operation.items.push(...event.items);
                break;
            }

            case 'operationStorageDone': {
                const operation = operations.get(event.operationId);
                if (operation) {
                    operations.delete(event.operationId);
                    operation.resolve(operation.items);
                }
                break;
            }

            case 'operationError': {
                const operation = operations.get(event.operationId);
                if (operation) {
                    operations.delete(event.operationId);
                    operation.reject(new ReadError('operationError', event.error));
                }
                break;
            }

            // smoldot could not get the proof from any peer. Distinct from `operationError`:
            // nothing is wrong with the request, the network just did not answer.
            case 'operationInaccessible': {
                const operation = operations.get(event.operationId);
                if (operation) {
                    operations.delete(event.operationId);
                    operation.reject(new ReadError('inaccessible', 'no peer served the proof'));
                }
                break;
            }

            // smoldot gives up on a subscription after a large finality jump, and everything
            // pinned under it is gone. Start a new one; the next tick uses it.
            case 'stop':
                resetFollowState('was stopped by the client');
                log('revive: the chainHead subscription stopped, following again');
                follow();
                break;

            default:
                break;
        }
    }

    function onNotification(message) {
        if (message.method !== 'chainHead_v1_followEvent')
            return false;
        // After a `stop` and re-follow, late events from the old subscription must not be
        // mistaken for the new one's.
        if (message.params?.subscription !== followSubscription)
            return true;
        onFollowEvent(message.params.result);
        return true;
    }

    // One `chainHead_v1_storage` call: start the operation, then wait for the events it produces.
    // Every item of one call is served by a single proof request to the node, which is what makes
    // batching visible in the node's load.
    async function storageRead(hash, items, childTrie) {
        const outcome = await request(
            'chainHead_v1_storage',
            [followSubscription, hash, items, childTrie ?? null],
        );

        if (outcome?.result === 'limitReached') {
            throw new ReadError('limitReached',
                'the subscription has no free operation slot (all 32 are in use or leaked)');
        }
        if (outcome?.result !== 'started')
            throw new ReadError('protocol', `unexpected response ${JSON.stringify(outcome)}`);

        const collected = [];
        const promise = new Promise((resolve, reject) => {
            operations.set(outcome.operationId, { resolve, reject, items: collected });
        });

        // A non-zero count means the operation started for only some of the items. The rest were
        // silently dropped, so the read set is incomplete even though it will report success —
        // wait for what did start, then say so.
        if (outcome.discardedItems > 0) {
            await promise.catch(() => {});
            throw new ReadError('discarded',
                `${outcome.discardedItems} of ${items.length} items were discarded for lack of `
                + 'operation slots');
        }
        return promise;
    }

    async function readSet() {
        const hash = currentBlock;
        held.set(hash, (held.get(hash) ?? 0) + 1);
        const startedAt = Date.now();
        try {
            // 1. Main trie: which child trie does this contract own?
            const accountInfo = await storageRead(hash, [{ key: accountInfoKey, type: 'value' }], null);
            if (accountInfo.length === 0)
                throw new ReadError('absent', `no Revive::AccountInfoOf entry for ${config.contract}`);
            const trieId = decodeTrieId(accountInfo[0].value);
            const trieIdMs = Date.now() - startedAt;

            // 2. Child trie: the contract's own storage.
            const keys = config.keys.slice(0, options.keyCount ?? config.keys.length);
            let present = 0;
            let calls = 0;
            if (options.batch) {
                const items = keys.map((entry) => ({ key: entry.key, type: 'value' }));
                present = (await storageRead(hash, items, trieId)).length;
                calls = 1;
            } else {
                for (const entry of keys) {
                    present += (await storageRead(hash, [{ key: entry.key, type: 'value' }], trieId)).length;
                    calls += 1;
                }
            }

            return {
                totalMs: Date.now() - startedAt,
                trieIdMs,
                keys: keys.length,
                calls,
                present,
            };
        } finally {
            release(hash);
        }
    }

    // A read set that timed out leaves its operations running: this side stops waiting, but
    // smoldot keeps the operation and the slots it holds. Only one read set runs at a time, so
    // anything still registered once one has failed belongs to it and can be stopped.
    function cancelOutstandingOperations() {
        if (operations.size === 0 || !followSubscription)
            return;
        for (const operationId of [...operations.keys()]) {
            operations.delete(operationId);
            request('chainHead_v1_stopOperation', [followSubscription, operationId]).catch(() => {});
        }
    }

    function recordFailure(kind) {
        stats.failed += 1;
        stats.failures.set(kind, (stats.failures.get(kind) ?? 0) + 1);
    }

    async function tick() {
        if (stopped)
            return;
        // Before the chain is followed there is no block to read at. Such a tick is not counted
        // at all: it never reached the node, and putting the warp-sync period into the failure
        // rate would make that rate describe this client's startup rather than the node.
        if (!followSubscription || !currentBlock) {
            stats.skipped += 1;
            return;
        }
        // Read sets are not allowed to overlap: if one is still running when the next is due, the
        // node is already slower than the configured rate and adding a second would measure this
        // client's queueing rather than the node's latency.
        if (inFlight) {
            stats.dropped += 1;
            return;
        }

        inFlight = true;
        stats.started += 1;
        const startedAt = Date.now();
        let timer;
        try {
            const deadline = new Promise((_, reject) => {
                timer = setTimeout(
                    () => reject(new ReadError('timeout', `no answer within ${READ_SET_DEADLINE_MS / 1000}s`)),
                    READ_SET_DEADLINE_MS,
                );
            });
            const result = await Promise.race([readSet(), deadline]);
            stats.ok += 1;
            stats.durations.push(result.totalMs);
            if (stats.durations.length > DURATION_WINDOW)
                stats.durations.shift();
            log(`revive: read set ok in ${result.totalMs}ms — trie id ${result.trieIdMs}ms, `
                + `${result.keys} key${result.keys === 1 ? '' : 's'} in ${result.calls} `
                + `child-trie call${result.calls === 1 ? '' : 's'}, `
                + `${result.present} present / ${result.keys - result.present} absent`);
        } catch (error) {
            const kind = error instanceof ReadError ? error.kind : 'error';
            cancelOutstandingOperations();
            recordFailure(kind);
            log(`revive: read set FAILED in ${Date.now() - startedAt}ms — ${kind}: ${error.message}`);
        } finally {
            clearTimeout(timer);
            inFlight = false;
        }
    }

    // Instances started together would otherwise tick in lockstep and arrive at the node as a
    // burst every period rather than as a steady arrival rate — and a synchronised stampede is
    // something to test for on purpose, not to build by accident.
    function schedule() {
        if (stopped)
            return;
        const interval = options.intervalMs;
        const delay = options.jitter
            ? interval * (0.5 + Math.random())
            : interval;
        timer = setTimeout(async () => {
            await tick();
            schedule();
        }, delay);
    }

    follow().then(() => {
        if (stopped)
            return;
        // The first tick is spread over a whole period, so that N instances starting at once do
        // not all fire immediately.
        const first = options.jitter ? Math.random() * options.intervalMs : options.intervalMs;
        timer = setTimeout(async () => {
            await tick();
            schedule();
        }, first);
    });

    return {
        onNotification,

        summary() {
            if (stats.started === 0)
                return undefined;
            const sorted = [...stats.durations].sort((a, b) => a - b);
            const failureRate = (100 * stats.failed / stats.started).toFixed(1);
            const failures = [...stats.failures.entries()]
                .map(([kind, count]) => `${count} ${kind}`)
                .join(', ');
            const line = `revive: ${stats.started} read set${stats.started === 1 ? '' : 's'}, `
                + `${stats.failed} failure${stats.failed === 1 ? '' : 's'} (${failureRate}%), `
                + `p50 ${percentile(sorted, 0.5)}ms p99 ${percentile(sorted, 0.99)}ms`;
            return line
                + (failures ? ` — ${failures}` : '')
                + (stats.dropped ? `, ${stats.dropped} tick(s) dropped while busy` : '')
                + (stats.skipped ? `, ${stats.skipped} before the chain was followed` : '');
        },

        stop() {
            stopped = true;
            clearTimeout(timer);
            resetFollowState('is shutting down');
        },
    };
}
