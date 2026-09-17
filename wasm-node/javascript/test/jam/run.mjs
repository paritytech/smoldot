// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Entry point of `npm run test:jam`.
//
// Starts (and always tears down) a local PolkaJam dev network, runs the
// Playwright browser test against it, and writes report.json plus the raw logs
// into the runtime directory.
//
// Exit code is non-zero if any assertion failed, the run aborted, or a spawned
// process survived teardown.

import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import url from 'node:url';
import {
    BASE_PORT,
    DEFAULT_RPC_PORT,
    JamNetwork,
    POLKAJAM_COMMIT,
    generateSpecs,
    listProcesses,
    readTail,
    resolveBinaries,
} from './network.mjs';
import { runE2E } from './e2e.mjs';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const PACKAGE_DIR = path.resolve(__dirname, '..', '..');
const DIST_ENTRY = path.join(PACKAGE_DIR, 'dist', 'mjs', 'index-browser.js');

const log = (message) => console.log(`[jam-e2e] ${message}`);

const runtimeDir = process.env.JAM_RUNTIME_DIR
    ? path.resolve(process.env.JAM_RUNTIME_DIR)
    : await fs.mkdtemp(path.join(os.tmpdir(), 'jam-e2e-'));
const basePort = BASE_PORT;
const rpcPort = Number(process.env.JAM_RPC_PORT ?? DEFAULT_RPC_PORT);

const report = {
    startedAt: new Date().toISOString(),
    runtimeDir,
    pinnedCommit: POLKAJAM_COMMIT,
    basePort,
    rpcPort,
    assertions: [],
    phases: [],
};

let network;
let cleanedUp = false;

async function cleanup() {
    if (cleanedUp) return;
    cleanedUp = true;
    if (network) {
        try {
            await network.stop();
        } catch (error) {
            log(`teardown error: ${error && (error.stack || error.message || error)}`);
        }
    }
}

process.on('SIGINT', () => {
    void cleanup().finally(() => process.exit(130));
});
process.on('SIGTERM', () => {
    void cleanup().finally(() => process.exit(143));
});

try {
    await fs.mkdir(runtimeDir, { recursive: true });
    try {
        await fs.access(DIST_ENTRY);
    } catch {
        throw new Error(
            `${DIST_ENTRY} is missing; build the browser bundle first (cd wasm-node/javascript && npm run build)`,
        );
    }
    log(`runtime dir: ${runtimeDir}`);

    const { binDir } = await resolveBinaries();
    report.binDir = binDir;
    log(`PolkaJam binaries: ${binDir}`);

    const { specPath, wrongSpecPath } = await generateSpecs({ runtimeDir });
    report.specPath = specPath;
    report.wrongSpecPath = wrongSpecPath;

    network = new JamNetwork({ binDir, rpcPort, runtimeDir, log });
    await network.start();
    report.network = network.summary();

    await runE2E({ network, specPath, wrongSpecPath, report, log });
} catch (error) {
    const message = String(error && (error.stack || error.message || error));
    console.error(`FAIL: run aborted: ${message}`);
    report.error = message;
    if (network) {
        report.networkLogTail = await readTail(network.networkLog, 40);
    }
} finally {
    await cleanup();
    const leftovers = await listProcesses(runtimeDir).catch(() => []);
    report.leftoverProcesses = leftovers;

    const failed = report.assertions.filter((assertion) => !assertion.passed);
    const passed = !report.error && report.assertions.length > 0 && failed.length === 0 && leftovers.length === 0;
    report.passed = passed;
    report.finishedAt = new Date().toISOString();
    report.durationMs = Date.now() - new Date(report.startedAt).getTime();

    await fs.writeFile(path.join(runtimeDir, 'report.json'), JSON.stringify(report, null, 2));

    console.log('');
    console.log('=== JAM browser end-to-end summary ===');
    console.log(`assertions: ${report.assertions.length - failed.length} passed, ${failed.length} failed`);
    for (const assertion of failed) {
        console.log(`  FAIL: [${assertion.phase}] ${assertion.name}${assertion.detail ? ` - ${assertion.detail}` : ''}`);
    }
    if (report.error) console.log(`  ERROR: ${report.error}`);
    if (leftovers.length > 0) {
        console.log(`  LEFTOVER PROCESSES: ${leftovers.map((entry) => `${entry.pid} ${entry.cmdline}`).join(' | ')}`);
    }
    console.log(`duration: ${(report.durationMs / 1000).toFixed(1)}s`);
    console.log(`runtime dir: ${runtimeDir}`);
    console.log(`report: ${path.join(runtimeDir, 'report.json')}`);
    console.log(`network log: ${path.join(runtimeDir, 'network.log')}`);
    console.log(passed ? 'RESULT: PASS' : 'RESULT: FAIL');

    process.exit(passed ? 0 : 1);
}