// Benchmark: warm start vs cold start across Polkadot, Kusama, and Westend.
//
// Measures the time for `addChain` to complete (chain initialization) with and
// without a saved database. The database from the previous run (if any) is saved
// to /tmp and reloaded on the next run.
//
// Usage:
//   # First run (cold start — no saved database):
//   node test/bench-warm-start.mjs
//
//   # Second run (warm start — uses saved database from first run):
//   node test/bench-warm-start.mjs
//
//   Compare the "addChain" times between the two runs.
//   On the fix branch, warm should be equal to or faster than cold.
//   On main (before fix), warm is ~2x slower than cold.

import { start } from '../dist/mjs/index-nodejs.js';
import * as fs from 'node:fs';
import * as path from 'node:path';

const DB_DIR = '/tmp/smoldot-bench-db';

const RELAY_CHAINS = [
    { name: 'polkadot', spec: '../../demo-chain-specs/polkadot.json' },
    { name: 'kusama',   spec: '../../demo-chain-specs/ksmcc3.json' },
    { name: 'westend',  spec: '../../demo-chain-specs/westend2.json' },
];

const PARACHAINS = {
    polkadot: { name: 'polkadot-asset-hub', spec: '../../demo-chain-specs/polkadot_asset_hub.json' },
    kusama:   { name: 'kusama-asset-hub',   spec: '../../demo-chain-specs/ksmcc3_asset_hub.json' },
    westend:  { name: 'westend-asset-hub',  spec: '../../demo-chain-specs/westend2_asset_hub.json' },
};

function loadDb(name) {
    const dbPath = path.join(DB_DIR, `${name}.json`);
    try {
        return fs.readFileSync(dbPath, 'utf8');
    } catch {
        return undefined;
    }
}

async function saveDb(chain, name) {
    fs.mkdirSync(DB_DIR, { recursive: true });
    const dbPath = path.join(DB_DIR, `${name}.json`);
    const content = await chain.databaseContent();
    fs.writeFileSync(dbPath, content, 'utf8');
    const sizeKB = (Buffer.byteLength(content, 'utf8') / 1024).toFixed(1);
    return sizeKB;
}

async function main() {
    const results = [];

    for (const relay of RELAY_CHAINS) {
        const client = start({
            logCallback: (_level, _target, message) => {
                // Uncomment to debug:
                // if (_target.includes('network') || _target.includes('sync'))
                //     console.log(`  [${_target}] ${message}`);
            }
        });

        const relaySpec = fs.readFileSync(relay.spec, 'utf8');
        const relayDb = loadDb(relay.name);
        const para = PARACHAINS[relay.name];
        const paraSpec = fs.readFileSync(para.spec, 'utf8');
        const paraDb = loadDb(para.name);

        console.log(`\n=== ${relay.name} ===`);
        console.log(`  relay DB: ${relayDb ? (relayDb.length / 1024).toFixed(1) + ' KB' : 'none (cold start)'}`);
        console.log(`  para  DB: ${paraDb ? (paraDb.length / 1024).toFixed(1) + ' KB' : 'none (cold start)'}`);

        // Time relay chain addChain
        const relayStart = performance.now();
        const relayChain = await client.addChain({
            chainSpec: relaySpec,
            databaseContent: relayDb,
        });
        const relayMs = (performance.now() - relayStart).toFixed(0);
        console.log(`  relay addChain: ${relayMs}ms`);

        // Time parachain addChain
        const paraStart = performance.now();
        const paraChain = await client.addChain({
            chainSpec: paraSpec,
            databaseContent: paraDb,
            potentialRelayChains: [relayChain],
        });
        const paraMs = (performance.now() - paraStart).toFixed(0);
        console.log(`  para  addChain: ${paraMs}ms`);

        // Wait briefly for sync to start, then save databases for next run
        await new Promise(r => setTimeout(r, 3000));

        const relaySizeKB = await saveDb(relayChain, relay.name);
        const paraSizeKB = await saveDb(paraChain, para.name);
        console.log(`  saved relay DB: ${relaySizeKB} KB`);
        console.log(`  saved para  DB: ${paraSizeKB} KB`);

        results.push({
            network: relay.name,
            relayDb: relayDb ? 'warm' : 'cold',
            relayAddChainMs: relayMs,
            paraDb: paraDb ? 'warm' : 'cold',
            paraAddChainMs: paraMs,
            relayDbSizeKB: relaySizeKB,
            paraDbSizeKB: paraSizeKB,
        });

        await client.terminate();
    }

    console.log('\n=== Summary ===');
    console.log('Network          | Relay (ms) | Para (ms) | Relay DB   | Para DB');
    console.log('-----------------|------------|-----------|------------|--------');
    for (const r of results) {
        console.log(
            `${r.network.padEnd(16)} | ${r.relayAddChainMs.toString().padStart(6)} ${r.relayDb.padEnd(4)} | ${r.paraAddChainMs.toString().padStart(5)} ${r.paraDb.padEnd(4)} | ${r.relayDbSizeKB.toString().padStart(7)} KB | ${r.paraDbSizeKB.toString().padStart(5)} KB`
        );
    }
}

main().catch(e => { console.error(e); process.exit(1); });
