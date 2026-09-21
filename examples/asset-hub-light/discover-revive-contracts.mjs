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

// Finds the `pallet-revive` contract on Polkadot Asset Hub with the most populated child trie,
// and writes `revive-queries.json` — the contract address and a sample of real child-trie keys
// that `index.mjs` then reads on a period. Run it by hand, not from the client:
//
//     node discover-revive-contracts.mjs
//     node discover-revive-contracts.mjs --top 20 --keys 12 --rpc https://…
//
// It talks to a full node over HTTP JSON-RPC rather than through smoldot, because neither half
// of the job is something a light client can do. Ranking means reading every entry of
// `Revive::AccountInfoOf`, and picking keys means *enumerating* a child trie — which
// `chainHead_v1_storage` cannot do at all, as child-trie queries there are restricted to `value`
// and `hash` (see `light-base/src/json_rpc_service/background.rs`). Discovery is a one-off; the
// load it generates is not the load being measured.

import * as fs from 'node:fs';
import * as path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

// `AccountInfoOf` is `StorageMap<_, Identity, H160, AccountInfo<T>>`, so its keys are
// `twox128("Revive") ++ twox128("AccountInfoOf") ++ <the 20 address bytes, unhashed>`. The
// Identity hasher is why the address appears verbatim and why the prefix below is the whole of
// the hashing involved. Both halves are constants, which is what lets this example — and
// `index.mjs`, which has no hash function at all — work without a crypto dependency.
const TWOX128_REVIVE = '735f040a5d490f1107ad9c56f5ca00d2';
const MAPS = {
    // The current name, as of the `AccountInfoOf` migration.
    AccountInfoOf: '0x' + TWOX128_REVIVE + 'ae37ff0591fdbbcd9c2406df7147a9dc',
    // What the same data was called before it. Probed as a fallback so that this script keeps
    // working against a chain running an older revive than the one it was written against.
    ContractInfoOf: '0x' + TWOX128_REVIVE + '060e99e5378e562537cf3bc983e17b91',
};

// `ChildInfo::new_default(trie_id)`, i.e. what `childstate_*` calls a `PrefixedStorageKey`.
// Note that this is the opposite convention to smoldot's `chainHead_v1_storage`, whose
// `childTrie` parameter takes the bare trie id and prepends this itself.
const CHILD_STORAGE_PREFIX = Buffer.from(':child_storage:default:').toString('hex');

const DEFAULT_RPC = 'https://polkadot-asset-hub-rpc.polkadot.io';
const KEYS_PER_PAGE = 1000;   // `state_getKeysPaged` caps the page; 1000 is the usual limit.
const VALUES_PER_BATCH = 250; // How many keys to hand `state_queryStorageAt` at once.

function parseArguments(argv) {
    const options = {
        rpc: DEFAULT_RPC,
        top: 10,
        keys: 8,
        out: path.join(HERE, 'revive-queries.json'),
        write: true,
    };
    for (let i = 0; i < argv.length; i += 1) {
        const argument = argv[i];
        const next = () => {
            const value = argv[i + 1];
            if (value === undefined)
                throw new Error(`${argument} needs a value`);
            i += 1;
            return value;
        };
        switch (argument) {
            case '--rpc': options.rpc = next(); break;
            case '--top': options.top = Number(next()); break;
            case '--keys': options.keys = Number(next()); break;
            case '--out': options.out = path.resolve(next()); break;
            case '--dry-run': options.write = false; break;
            case '--help': case '-h': options.help = true; break;
            default: throw new Error(`unknown argument "${argument}"`);
        }
    }
    return options;
}

const USAGE = `Usage: node discover-revive-contracts.mjs [options]

  --rpc <url>    HTTP JSON-RPC endpoint of an Asset Hub node (default ${DEFAULT_RPC})
  --top <n>      how many contracts to print, ranked by stored item count (default 10)
  --keys <n>     how many child-trie keys to sample from the winner (default 8)
  --out <path>   where to write the config (default ./revive-queries.json)
  --dry-run      print the ranking, write nothing
`;

function createRpc(url) {
    let nextId = 0;
    return async function rpc(method, params = []) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, params }),
        });
        if (!response.ok)
            throw new Error(`${method}: HTTP ${response.status} ${response.statusText}`);
        const body = await response.json();
        if (body.error)
            throw new Error(`${method}: ${body.error.message}`);
        return body.result;
    };
}

// SCALE compact integer. Returns the value and how many bytes it took.
function decodeCompact(bytes, offset) {
    const first = bytes[offset];
    switch (first & 0b11) {
        case 0b00:
            return { value: first >>> 2, length: 1 };
        case 0b01:
            return { value: ((first >>> 2) | (bytes[offset + 1] << 6)) >>> 0, length: 2 };
        case 0b10:
            return {
                value: ((first >>> 2)
                    | (bytes[offset + 1] << 6)
                    | (bytes[offset + 2] << 14)
                    | (bytes[offset + 3] << 22)) >>> 0,
                length: 4,
            };
        default: {
            // Big-integer mode: the top six bits say how many bytes follow, minus four.
            const length = (first >>> 2) + 4;
            let value = 0n;
            for (let i = length; i >= 1; i -= 1)
                value = (value << 8n) | BigInt(bytes[offset + i]);
            return { value: Number(value), length: length + 1 };
        }
    }
}

// `AccountInfo { account_type: AccountType, dust: u32 }`, where `AccountType::Contract` is
// variant 0 and carries `ContractInfo { trie_id: Vec<u8>, code_hash: H256, storage_bytes: u32,
// storage_items: u32, … }`. Only the leading fields are needed: the trie id names the child
// trie, and `storage_items` is the ranking key — the number this whole script exists to read.
//
// An older `ContractInfoOf` holds a bare `ContractInfo` with no variant tag, hence `tagged`.
function decodeContractInfo(value, tagged) {
    const bytes = Buffer.from(value.slice(2), 'hex');
    let offset = 0;
    if (tagged) {
        if (bytes[0] !== 0x00)
            return null;   // An EOA or a delegated EOA: no child trie, nothing to read.
        offset = 1;
    }
    const trieIdLength = decodeCompact(bytes, offset);
    offset += trieIdLength.length;
    const trieId = bytes.subarray(offset, offset + trieIdLength.value);
    offset += trieIdLength.value;
    offset += 32;   // code_hash: H256
    if (offset + 8 > bytes.length)
        return null;   // Not the layout expected; skip rather than report a bogus ranking.
    return {
        trieId: '0x' + trieId.toString('hex'),
        storageBytes: bytes.readUInt32LE(offset),
        storageItems: bytes.readUInt32LE(offset + 4),
    };
}

function addressOfKey(key, prefix) {
    return '0x' + key.slice(prefix.length);
}

// Picks keys that are spread across the child trie rather than adjacent in it.
//
// This matters more than it looks. Contract storage keys are `blake2_256` of an EVM slot, so they
// are uniformly distributed 32-byte hashes, and asking for the *first* N of them in lexicographic
// order -- which is what one page of `childstate_getKeysPaged` gives -- returns N keys that all
// begin with the same nibble or two. In a radix-16 trie those keys share their whole path from
// the root, so the proof covering all of them is barely larger than a proof for one: measured on
// the winning contract, 12 adjacent keys produced a 4.5 kiB proof where 12 spread ones produced
// 14.2 kiB. A read set built from one page would therefore understate the node's work by about
// three times, and a real resolution reads scattered slots -- a content hash under one namehash,
// manifest records under others -- not neighbours.
//
// So the trie is sampled at N evenly spaced points of the 256-bit key space and the first real
// key at or after each point is taken. Because the keys are hashes, evenly spaced points land on
// evenly spaced keys, and the first nibble of point i is roughly i*16/N -- the paths diverge at
// the root, which is the property being bought. It costs N round trips rather than a walk of the
// whole trie, so it does not care how large the contract is.
async function sampleChildKeys(rpc, prefixedTrie, count, at) {
    const keys = [];
    const seen = new Set();
    for (let i = 0; i < count; i += 1) {
        // floor(i * 2^256 / count) as 32 bytes, big-endian.
        const point = (1n << 256n) * BigInt(i) / BigInt(count);
        const startKey = '0x' + point.toString(16).padStart(64, '0');
        let page = await rpc('childstate_getKeysPaged', [prefixedTrie, null, 1, startKey, at]);
        // Past the last key: wrap around to the start of the trie.
        if (page.length === 0)
            page = await rpc('childstate_getKeysPaged', [prefixedTrie, null, 1, null, at]);
        for (const key of page) {
            if (!seen.has(key)) {
                seen.add(key);
                keys.push(key);
            }
        }
    }
    return keys.sort();
}

// How many distinct nibble prefixes the sampled keys have, by depth. It is a proxy for how many
// distinct trie nodes their proof has to carry, and the quickest way to see whether a sample is
// actually spread: keys that diverge at the root show `count` at depth 1, keys off one page show 1.
function describeSpread(keys) {
    return [1, 2, 3]
        .map((depth) => {
            const prefixes = new Set(keys.map((key) => key.slice(2, 2 + depth)));
            return `d${depth}=${prefixes.size}`;
        })
        .join(' ');
}

async function main() {
    const options = parseArguments(process.argv.slice(2));
    if (options.help) {
        process.stdout.write(USAGE);
        return;
    }

    const rpc = createRpc(options.rpc);
    const chain = await rpc('system_chain');
    // Everything is read at one block, so the ranking and the sampled values are consistent with
    // each other even if the chain moves on mid-run.
    const at = await rpc('chain_getFinalizedHead');
    console.log(`${chain} via ${options.rpc}, at finalized ${at}`);

    // Which name the deployed runtime uses is not knowable from the source tree alone, so ask
    // the chain: whichever prefix has keys is the one this runtime has.
    let mapName;
    let prefix;
    for (const [name, candidate] of Object.entries(MAPS)) {
        const probe = await rpc('state_getKeysPaged', [candidate, 1, null, at]);
        console.log(`  ${name}: ${probe.length > 0 ? 'present' : 'empty'}`);
        if (probe.length > 0 && mapName === undefined) {
            mapName = name;
            prefix = candidate;
        }
    }
    if (mapName === undefined) {
        console.error('\nNeither Revive::AccountInfoOf nor Revive::ContractInfoOf holds any key on '
            + 'this chain: pallet-revive is present but has no accounts. There is no contract to '
            + 'read, so no config was written.');
        process.exitCode = 1;
        return;
    }
    console.log(`\nRanking Revive::${mapName} by stored item count...`);

    // Page the whole map. `state_getKeysPaged` returns at most `count` keys and is resumed by
    // handing back the last one, so a short page means the end.
    const keys = [];
    let startKey = null;
    for (;;) {
        const page = await rpc('state_getKeysPaged', [prefix, KEYS_PER_PAGE, startKey, at]);
        keys.push(...page);
        process.stdout.write(`\r  ${keys.length} accounts`);
        if (page.length < KEYS_PER_PAGE)
            break;
        startKey = page[page.length - 1];
    }
    process.stdout.write('\n');

    const contracts = [];
    for (let i = 0; i < keys.length; i += VALUES_PER_BATCH) {
        const batch = keys.slice(i, i + VALUES_PER_BATCH);
        const [snapshot] = await rpc('state_queryStorageAt', [batch, at]);
        for (const [key, value] of snapshot.changes) {
            if (value === null)
                continue;
            const info = decodeContractInfo(value, mapName === 'AccountInfoOf');
            if (info)
                contracts.push({ address: addressOfKey(key, prefix), ...info });
        }
        process.stdout.write(`\r  ${Math.min(i + VALUES_PER_BATCH, keys.length)}/${keys.length} decoded, `
            + `${contracts.length} contracts`);
    }
    process.stdout.write('\n\n');

    if (contracts.length === 0) {
        console.error(`Revive::${mapName} holds ${keys.length} account(s) but none of them is a `
            + 'contract, so there is no child trie to read. No config was written.');
        process.exitCode = 1;
        return;
    }

    contracts.sort((a, b) => b.storageItems - a.storageItems || b.storageBytes - a.storageBytes);
    console.log(`${contracts.length} contract(s) among ${keys.length} revive account(s). Top ${Math.min(options.top, contracts.length)}:\n`);
    console.log('    items      bytes  address');
    for (const contract of contracts.slice(0, options.top)) {
        console.log(`  ${String(contract.storageItems).padStart(7)}  `
            + `${String(contract.storageBytes).padStart(9)}  ${contract.address}`);
    }

    const winner = contracts[0];
    console.log(`\nSampling up to ${options.keys} key(s) from ${winner.address}`);
    if (winner.storageItems === 0) {
        console.warn('  warning: the most populated contract stores nothing. The read set will '
            + 'still produce genuine RemoteReadChildRequest proofs, but against an empty child '
            + 'trie, which is cheaper for the node than a real resolution would be.');
    }

    // `childstate_*` wants the prefixed form, unlike smoldot's `childTrie`.
    const prefixedTrie = '0x' + CHILD_STORAGE_PREFIX + winner.trieId.slice(2);
    const childKeys = await sampleChildKeys(rpc, prefixedTrie, options.keys, at);
    const sampled = [];
    for (const key of childKeys) {
        const value = await rpc('childstate_getStorage', [prefixedTrie, key, at]);
        sampled.push({ key, expect: value });
    }
    console.log(`  got ${sampled.length} key(s), spread ${describeSpread(childKeys)}`);

    const config = {
        chain,
        map: mapName,
        rpc: options.rpc,
        discoveredAt: new Date().toISOString(),
        discoveredAtBlock: at,
        accountInfoPrefix: prefix,
        contract: winner.address,
        trieId: winner.trieId,
        storageItems: winner.storageItems,
        storageBytes: winner.storageBytes,
        keys: sampled,
    };

    if (!options.write) {
        console.log('\n--dry-run: not writing. The config would have been:\n');
        console.log(JSON.stringify(config, null, 2));
        return;
    }
    fs.writeFileSync(options.out, JSON.stringify(config, null, 2) + '\n');
    console.log(`\nWrote ${options.out}`);
}

main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
});
