// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Local PolkaJam dev-network lifecycle for the browser end-to-end test.
//
// Responsibilities:
//  - locate the already-built binaries (POLKAJAM_BIN_DIR, else PATH; nothing is
//    cloned, built or inferred from another path);
//  - read the checked-in spec and prepare browser bootnodes and the
//    wrong-genesis variant for the negative phase;
//  - launch six validators and one ordinary RPC node, assert node0's startup
//    line against its deterministic identity, and wait for RPC readiness;
//  - restart node0 against its existing data directory (catch-up path);
//  - tear everything down through detached process groups.
//
// The bootnode address is a *constant* (fixtures/local-network.md); the log
// line is only asserted, never parsed to build the spec or the assertions.

import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { constants, createWriteStream } from 'node:fs';
import { createSocket } from 'node:dgram';
import fs from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

/** A5 capture base; see fixtures/local-network.md. */
export const POLKAJAM_COMMIT = '8ceedf46c4828137c8835e4227d7f3a62ada0463';

/** The only executable needed during a run. */
export const REQUIRED_BINARIES = ['polkajam'];

/** Nodes always load these checked-in bytes, including on restart. */
export const CHAIN_SPEC_PATH = fileURLToPath(new URL('./dev-chain-spec.json', import.meta.url));

/** Deterministic dev-validator 0 P-256 identity (SecretKeyset::trivial(0..6)). */
export const NODE0_P256_ID = 'oqov2a57d7etnpzb6aerv64y5j622ejkkvqjencdrwln4qhnoqvqb';

/** Matching node0 Ed25519 identity (A5 genesis-state.json, active validator 0).
 * Both identities follow the pinned SecretKeyset::trivial(0) derivation.
 */
export const NODE0_ED25519_ID = 'eecgwpgwq3noky4ijm4jmvjtmuzv44qvigciusxakq5epnrfj2utb';

/** ProtocolParameters::tiny() slot duration. */
export const SLOT_SECONDS = 6;

export const BASE_PORT = 40000;
export const DEFAULT_RPC_PORT = 19800;

/**
 * The one place that knows how a JAM bootnode address is spelled.
 *
 * JIPs PR #18 requires an Ed25519 identity and permits additional identities
 * separated by `+`. Native `v`/`o` P-256 text is our local convention, not a
 * standardized JIP identity format. Both keys identify the same dev node.
 * The demo page reads this result over HTTP instead of spelling its own entry.
 */
export function formatBootnode() {
    return `${NODE0_ED25519_ID}+${NODE0_P256_ID}@127.0.0.1:${BASE_PORT}`;
}

const STARTUP_TIMEOUT_MS = 120 * 1000;
const RPC_READY_TIMEOUT_MS = 120 * 1000;
const SHUTDOWN_TIMEOUT_MS = 15 * 1000;

async function isExecutable(filePath) {
    try {
        await fs.access(filePath, constants.X_OK);
        return (await fs.stat(filePath)).isFile();
    } catch {
        return false;
    }
}

async function readTail(filePath, lines = 30) {
    try {
        const text = await fs.readFile(filePath, 'utf8');
        return text.split('\n').slice(-lines).join('\n');
    } catch {
        return '<log unavailable>';
    }
}

/** Spawns `command` detached (its own process group) with output appended to `logPath`. */
function spawnDetached(command, args, { env, logPath }) {
    const out = createWriteStream(logPath, { flags: 'a' });
    const child = spawn(command, args, {
        env,
        detached: true,
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.pipe(out, { end: false });
    child.stderr.pipe(out, { end: false });
    child.on('error', (error) => {
        out.write(`\n[e2e] failed to spawn ${command}: ${error}\n`);
    });
    return { child, out };
}

function killGroup(pid, signal) {
    if (!pid) return;
    try {
        process.kill(-pid, signal);
    } catch (error) {
        if (error.code !== 'ESRCH') throw error;
    }
}

async function waitForExit(pid, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        try {
            process.kill(pid, 0);
        } catch (error) {
            if (error.code === 'ESRCH') return true;
            throw error;
        }
        await delay(100);
    }
    return false;
}

/** Only the explicit binary directory, or PATH, is searched. Nothing is built. */
export async function resolveBinaries() {
    if (Object.hasOwn(process.env, 'JAM_BASE_PORT')) {
        throw new Error('JAM_BASE_PORT is no longer supported: validator ports 40000–40005 are fixed by ' +
            'dev-chain-spec.json. Unset it. To change the network port, regenerate the checked-in ' +
            'spec and update BASE_PORT together; see test/jam/CHAIN_SPEC.md.');
    }
    const fromEnv = process.env.POLKAJAM_BIN_DIR;
    const searched = (fromEnv !== undefined
        ? [fromEnv]
        : (process.env.PATH ?? '').split(path.delimiter).filter(Boolean)
    ).map((dir) => path.resolve(dir));
    for (const dir of searched) {
        if (await isExecutable(path.join(dir, REQUIRED_BINARIES[0]))) return { binDir: dir };
    }
    throw new Error([
        'Missing JAM binary: polkajam (an executable file is required).',
        fromEnv !== undefined
            ? `Looked only in POLKAJAM_BIN_DIR=${searched[0]}; setting it replaces the PATH search.`
            : `Looked in each of the ${searched.length} PATH directories.`,
        'Nothing is cloned or built during a run.',
        `Build polkajam once from ${POLKAJAM_COMMIT} using test/jam/README.md,`,
        'then put it on PATH or set POLKAJAM_BIN_DIR to its directory.',
    ].join('\n'));
}

// Refuse a second local network before starting any processes. Hold all six
// sockets until the check is complete, then release them for the validators.
async function checkValidatorPorts() {
    const sockets = [];
    try {
        for (let port = BASE_PORT; port < BASE_PORT + 6; port += 1) {
            const socket = createSocket('udp4');
            await new Promise((resolve, reject) => {
                socket.once('error', error => {
                    socket.close();
                    reject(new Error(`Validator port 127.0.0.1:${port} is unavailable (${error.code}); ` +
                        'stop the other network before starting this fixed-spec network.'));
                });
                socket.bind(port, '127.0.0.1', resolve);
            });
            sockets.push(socket);
        }
    } finally {
        await Promise.all(sockets.map(socket => new Promise(resolve => socket.close(resolve))));
    }
}

function stripHexPrefix(text) {
    return text.startsWith('0x') ? text.slice(2) : text;
}

/** Read the fixed genesis; only browser bootnodes and the negative case vary. */
export async function generateSpecs({ runtimeDir }) {
    const specPath = path.join(runtimeDir, 'spec.json');
    const wrongSpecPath = path.join(runtimeDir, 'spec-wrong-genesis.json');
    const spec = JSON.parse(await fs.readFile(CHAIN_SPEC_PATH, 'utf8'));
    // PolkaJam cannot yet parse combined identities (planning followups.md U1).
    // This browser-only bootnode patch collapses into one shared file when it can.
    // Nodes receive CHAIN_SPEC_PATH unchanged; genesis is never recomputed.
    spec.bootnodes = [formatBootnode()];
    await fs.writeFile(specPath, JSON.stringify(spec));

    const wrong = JSON.parse(JSON.stringify(spec));
    const header = stripHexPrefix(wrong.genesis_header);
    const last = parseInt(header.slice(-2), 16) ^ 0x01;
    wrong.genesis_header = header.slice(0, -2) + last.toString(16).padStart(2, '0');
    if (wrong.genesis_header === header) throw new Error('failed to corrupt the genesis header');
    await fs.writeFile(wrongSpecPath, JSON.stringify(wrong));

    return { specPath, wrongSpecPath };
}

/**
 * A running six-validator PolkaJam network plus the helpers the test needs.
 * All spawned processes live in their own process groups and are killed as a
 * group on `stop()`, which is idempotent.
 */
export class JamNetwork {
    constructor({ binDir, rpcPort, runtimeDir, log, finalityMode = 'dummy' }) {
        if (!['dummy', 'grandpa'].includes(finalityMode)) throw new Error('Unknown finality mode: ' + finalityMode);
        this.finalityMode = finalityMode;
        this.nodes = [];
        this.binDir = binDir;
        this.basePort = BASE_PORT;
        this.rpcPort = rpcPort;
        this.runtimeDir = runtimeDir;
        this.log = log;
        this.restartChild = undefined;
        this.restartLog = path.join(runtimeDir, 'node0-restart.log');
        this.networkLog = path.join(runtimeDir, 'network.log');
        this.stopping = false;
        this.startedAt = undefined;
        this.rpcReadyAt = undefined;
        this.workdirPath = path.join(runtimeDir, 'net', 'testnet');
    }

    env() {
        return {
            ...process.env,
            POLKAVM_BACKEND: 'interpreter',
            RUST_LOG: 'info',
            TMPDIR: path.join(this.runtimeDir, 'net'),
        };
    }

    async start() {
        await fs.mkdir(path.join(this.runtimeDir, 'net'), { recursive: true });
        // A reused JAM_RUNTIME_DIR must not satisfy the startup gate with stale output.
        await fs.writeFile(this.networkLog, '');
        await checkValidatorPorts();
        this.startedAt = Date.now();
        this.log(`starting PolkaJam ${this.finalityMode} nodes (base port ${BASE_PORT}, rpc port ${this.rpcPort})`);
        for (let index = 0; index < 7; index += 1) {
            const node = path.join(this.workdirPath, 'node' + index);
            await fs.mkdir(path.join(node, 'conf', 'dev', 'keys'), { recursive: true });
            await fs.mkdir(path.join(node, 'data'), { recursive: true });
            this.nodes.push(spawnDetached(path.join(this.binDir, 'polkajam'), [
                '--config-path', path.join(node, 'conf'), '--chain', CHAIN_SPEC_PATH,
                'run', '--data-path', path.join(node, 'data'), '--finality-mode', this.finalityMode,
                ...(index < 6 ? ['--dev-validator', String(index)] : ['--mode=ordinary', '--rpc-port', String(this.rpcPort)]),
            ], { env: this.env(), logPath: this.networkLog }));
        }

        const expected = `For WebTransport, use ${NODE0_P256_ID}@127.0.0.1:${this.basePort}`;
        const gate = await this.waitForLog(this.networkLog, expected, STARTUP_TIMEOUT_MS);
        if (!gate) {
            throw new Error(
                `node0 WebTransport startup line was not observed within ${STARTUP_TIMEOUT_MS / 1000}s; ` +
                `expected "${expected}".\n--- network.log tail ---\n${await readTail(this.networkLog)}`,
            );
        }
        this.log(`startup gate passed: "${expected}"`);

        await this.waitForRpc();
        this.rpcReadyAt = Date.now();
        this.log(`network ready in ${((this.rpcReadyAt - this.startedAt) / 1000).toFixed(1)}s`);
    }

    async waitForLog(file, needle, timeoutMs) {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            try {
                const text = await fs.readFile(file, 'utf8');
                if (text.includes(needle)) return true;
            } catch {
                // Log not created yet.
            }
            await delay(200);
        }
        return false;
    }

    async rpc(method, params = []) {
        const response = await fetch(`http://127.0.0.1:${this.rpcPort}`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
            signal: AbortSignal.timeout(3000),
        });
        const body = await response.json();
        if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
        return body.result;
    }

    async waitForRpc() {
        const deadline = Date.now() + RPC_READY_TIMEOUT_MS;
        let lastError = 'no attempt';
        while (Date.now() < deadline) {
            try {
                await this.rpc('parameters');
                const best = await this.rpc('bestBlock');
                if (best && Number(best.slot) > 0) return;
                lastError = `bestBlock slot ${best && best.slot}`;
            } catch (error) {
                lastError = String(error && error.message);
            }
            await delay(500);
        }
        throw new Error(`RPC at 127.0.0.1:${this.rpcPort} not ready within ${RPC_READY_TIMEOUT_MS / 1000}s (${lastError})`);
    }

    /** The fixed per-run node directory, shared by initial startup and restart. */
    async workdir() {
        return this.workdirPath;
    }

    /** Finds the node0 child process by cmdline, stops it and waits for exit. */
    async killNode0() {
        const workdir = await this.workdir();
        const pid = await findNode0Pid(workdir);
        if (!pid) throw new Error(`could not find a --dev-validator 0 process under ${workdir}`);
        this.log(`stopping node0 (pid ${pid})`);
        // polkajam only installs a SIGINT handler (`tokio::signal::ctrl_c`); a
        // SIGTERM bypasses `node.shutdown()` and the restarted node comes back
        // with an empty database ("Writing genesis block"), which would defeat
        // the catch-up phase. Use SIGINT, falling back to SIGTERM then SIGKILL.
        try {
            process.kill(pid, 'SIGINT');
        } catch (error) {
            if (error.code !== 'ESRCH') throw error;
        }
        if (await waitForExit(pid, SHUTDOWN_TIMEOUT_MS)) return;
        this.log(`node0 (pid ${pid}) did not exit after SIGINT; sending SIGTERM`);
        try {
            process.kill(pid, 'SIGTERM');
        } catch (error) {
            if (error.code !== 'ESRCH') throw error;
        }
        if (await waitForExit(pid, 5000)) return;
        this.log(`node0 (pid ${pid}) did not exit after SIGTERM; sending SIGKILL`);
        try {
            process.kill(pid, 'SIGKILL');
        } catch (error) {
            if (error.code !== 'ESRCH') throw error;
        }
        if (!(await waitForExit(pid, 5000))) throw new Error(`node0 (pid ${pid}) is still alive`);
    }

    /**
     * Restarts node0 against its existing config/data directory. The restarted
     * process is its own process group and is tracked for teardown.
     */
    async startNode0() {
        const workdir = await this.workdir();
        const node0 = path.join(workdir, 'node0');
        const bin = path.join(this.binDir, 'polkajam');
        const args = [
            '--config-path', path.join(node0, 'conf'),
            '--chain', CHAIN_SPEC_PATH,
            'run',
            '--data-path', path.join(node0, 'data'),
            '--dev-validator', '0',
            '--finality-mode', this.finalityMode,
        ];
        this.log(`restarting node0: ${bin} ${args.join(' ')}`);
        await fs.writeFile(this.restartLog, '');
        // Give the killed process a moment to release its UDP port before rebinding.
        await delay(500);
        this.restartChild = spawnDetached(bin, args, { env: this.env(), logPath: this.restartLog });

        const expected = `For WebTransport, use ${NODE0_P256_ID}@127.0.0.1:${this.basePort}`;
        const ready = await this.waitForLog(this.restartLog, expected, STARTUP_TIMEOUT_MS);
        if (!ready) {
            throw new Error(
                `node0 did not restart within ${STARTUP_TIMEOUT_MS / 1000}s.\n` +
                `--- node0-restart.log tail ---\n${await readTail(this.restartLog)}`,
            );
        }
        if (this.restartChild.child.exitCode !== null) {
            throw new Error(`node0 exited immediately with code ${this.restartChild.child.exitCode}`);
        }
        this.log('node0 restarted');
    }

    /** Kill + restart in one call. */
    async restartNode0() {
        await this.killNode0();
        await this.startNode0();
    }

    /** Processes belonging to this run (used to verify teardown). */
    async listProcesses() {
        return listProcesses(this.runtimeDir);
    }

    /** Idempotent teardown: kills node process groups and removes their workdir. */
    async stop() {
        if (this.stopping) return;
        this.stopping = true;
        const children = [this.restartChild, ...this.nodes].filter(Boolean);
        const pids = children.map(entry => entry.child.pid)
            .filter((pid) => typeof pid === 'number');
        for (const pid of pids) killGroup(pid, 'SIGTERM');
        for (const pid of pids) {
            if (!(await waitForExit(pid, SHUTDOWN_TIMEOUT_MS))) {
                this.log(`process group ${pid} did not exit after SIGTERM; sending SIGKILL`);
                killGroup(pid, 'SIGKILL');
                await waitForExit(pid, 5000);
            }
        }
        for (const child of children) {
            if (child) child.out.end();
        }
        await fs.rm(path.join(this.runtimeDir, 'net'), { recursive: true, force: true });
        this.log('network stopped');
    }

    summary() {
        return {
            binDir: this.binDir,
            finalityMode: this.finalityMode,
            basePort: this.basePort,
            rpcPort: this.rpcPort,
            startupMs: this.startedAt && this.rpcReadyAt ? this.rpcReadyAt - this.startedAt : null,
            networkLog: this.networkLog,
            node0RestartLog: this.restartLog,
        };
    }
}

/** Scans /proc for processes whose cmdline mentions `needle`. */
async function findPids(needle) {
    const pids = [];
    for (const entry of await fs.readdir('/proc')) {
        if (!/^\d+$/.test(entry)) continue;
        let cmdline;
        try {
            cmdline = await fs.readFile(`/proc/${entry}/cmdline`, 'utf8');
        } catch {
            continue;
        }
        if (cmdline.split('\0').join(' ').includes(needle)) pids.push(Number(entry));
    }
    return pids;
}

async function findNode0Pid(workdir) {
    for (const pid of await findPids(workdir)) {
        let cmdline;
        try {
            cmdline = await fs.readFile(`/proc/${pid}/cmdline`, 'utf8');
        } catch {
            continue;
        }
        if (cmdline.split('\0').join(' ').includes('--dev-validator 0')) return pid;
    }
    return undefined;
}

/** All polkajam processes spawned by this run that are still alive. */
export async function listProcesses(runtimeDir) {
    const found = [];
    for (const pid of await findPids(runtimeDir)) {
        let cmdline = '';
        try {
            cmdline = (await fs.readFile(`/proc/${pid}/cmdline`, 'utf8')).split('\0').join(' ').trim();
        } catch {
            continue;
        }
        // The invoking shell may also mention the runtime directory; only count
        // actual polkajam invocations.
        if (!/(^|\/| )polkajam( |$)/.test(cmdline)) continue;
        found.push({ pid, cmdline });
    }
    return found;
}

export { readTail };
