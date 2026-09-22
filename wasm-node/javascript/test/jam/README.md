# JAM browser end-to-end test (`npm run test:jam`)

Runs the smoldot **browser** build in a real headless Chromium against a real
local PolkaJam dev network and asserts the live-network acceptance criteria of
the JAM light client (M11b): follow/catch-up, header authenticity, node restart
catch-up, unfollow, and the wrong-genesis negative path.

Node has no WebTransport, so this is the only way to exercise the JAM network
stack end to end.

## Quick start

```sh
cd wasm-node/javascript

# The browser bundle must already be built (do not rebuild it here).
test -f dist/mjs/index-browser.js || npm run build

# Playwright's Chromium (once per machine; browsers are cached in ~/.cache/ms-playwright).
npx playwright install chromium

# Point at a directory holding the prebuilt `polkajam` executable.
POLKAJAM_BIN_DIR=/path/to/polkajam/target/release npm run test:jam
```

## Binaries

Only `polkajam` is required. It is located in `POLKAJAM_BIN_DIR` if set,
otherwise on `PATH`. There is no third source: nothing is cloned or compiled
during a run, and no path is inferred from another path. A missing executable
stops the run before any node starts and points to these build instructions.

Build it once, from a PolkaJam checkout at the pinned commit:

```sh
SKIP_PVM_BUILDS=1 RUSTC_BOOTSTRAP=1 \
  RUSTFLAGS='-Zcrate-attr=feature(array_windows,substr_range)' \
  cargo build --locked --release -p polkajam
```

Then put `polkajam` on `PATH`, or point `POLKAJAM_BIN_DIR` at its directory.
Every node reads [dev-chain-spec.json](dev-chain-spec.json). A run never
constructs genesis from the executable's embedded service blobs. See
[CHAIN_SPEC.md](CHAIN_SPEC.md) for provenance and the regeneration check.

## What it does

1. **Network** (`network.mjs`): directly launches six dev validators and one
   ordinary RPC node with the checked-in spec, in Dummy finality mode. There
   are no proxy nodes. Validator UDP ports are fixed at 40000–40005; an occupied
   port fails startup. Only one test/demo network can run at a time.
   JavaScript adds the deterministic combined Ed25519+P-256 node0 bootnode to
   smoldot's copy of the spec and writes a wrong-genesis variant (last header
   byte XOR `0x01`). Genesis is otherwise unchanged. The node-side spec has
   empty bootnodes because PolkaJam cannot yet parse combined identities.
   The startup gate asserts node0's WebTransport advertisement against the
   fixed identity and port; it never derives them from logs. RPC readiness
   polls `parameters`/`bestBlock` until a live block exists.
2. **Page** (`page.html`, `page.mjs`): loads `/dist/mjs/index-browser.js`, sets
   `window.__smoldot`, and exposes an in-page driver that starts smoldot
   clients, adds chains, follows, records events/logs with timestamps, requests
   headers, and unfollows.
3. **Phases** (`e2e.mjs`, Playwright):
   - **positive**: `chainHead_v1_follow [false]` -> `initialized` whose
     `finalizedBlockHashes[0]` is the spec genesis hash; >= 5 `newBlock` events
     with the 5th within `5 x 6s` of the first; every `parentBlockHash` is a
     previously reported hash or the anchor; a `bestBlockChanged` after the
     first `newBlock`; no `finalized` event for the whole session;
     `chainHead_v1_header` bytes hash (BLAKE2b-256, `blakejs`) to the requested
     hash.
   - **restart**: node0 is stopped (SIGINT, see Notes) and restarted against the
     same config/data directory; a `newBlock` within 60 s whose
     `parentBlockHash` was reported before the restart, followed by
     `bestBlockChanged`.
   - **unfollow**: `chainHead_v1_unfollow` resolves and no further follow events
     arrive for ~2 s.
   - **negative**: a second client with the corrupted-genesis spec gets
     `initialized` with the wrong anchor, logs `jam-connect` then
     `jam-reconnect` within 90 s, and never emits a `newBlock`.
4. **Entry point** (`run.mjs`): creates the runtime directory, wires the phases,
   always tears the network down in a `finally`, verifies that no PolkaJam
   process survived, writes `report.json`, prints `PASS:`/`FAIL:` per assertion
   and exits non-zero on any failure.

The page, the smoldot bundle and the driver are served from disk with
Playwright `page.route` interception at `http://localhost/` (a secure context
for WebTransport); no HTTP server is started.

## Environment knobs

| Variable | Default | Meaning |
|---|---|---|
| `POLKAJAM_BIN_DIR` | search `PATH` | directory holding the `polkajam` executable |
| `JAM_RUNTIME_DIR` | fresh `mkdtemp` under `os.tmpdir()` | where logs, specs and `report.json` are written |
| `JAM_RPC_PORT` | `19800` | ordinary-node JSON-RPC port |
| `CHROMIUM_PATH` | Playwright Chromium | optional system Chrome executable, e.g. on NixOS |

## Pinned PolkaJam

`POLKAJAM_COMMIT = 8ceedf46c4828137c8835e4227d7f3a62ada0463` (A5 capture base,
`polkajam 0.1.29 / GP 0.8.0`). The checked-in spec was generated at that pin
with `SKIP_PVM_BUILDS=1`. Binary provenance is not checked during a run.
Regenerate and diff the spec whenever the pin changes, following
[CHAIN_SPEC.md](CHAIN_SPEC.md).

## Teardown and evidence

- Every spawned process is started with `detached: true` (its own process group)
  and killed as a group; teardown is idempotent and runs in a `finally`, plus on
  `SIGINT`/`SIGTERM`.
- The per-run `net/testnet` node directory is removed.
- Retained in the runtime directory: `report.json`, `network.log`,
  `node0-restart.log`, `spec.json`, `spec-wrong-genesis.json`. The runtime
  directory path is printed at the end.
- `report.json` contains every assertion with its phase, per-phase durations,
  the observed events and client logs (bounded), the genesis hashes, the
  browser version and any leftover processes.

## Historical timings (0.7.2 pin)

Local Linux, 32 cores, prebuilt PolkaJam binaries, Playwright Chromium
(headless, bundled with `playwright@1.63.0`):

| Step | Time |
|---|---|
| PolkaJam cold build (32 cores, A5 flags) | 114 s (A5: 55 s with warm deps) |
| Network startup (launcher -> WebTransport line + live RPC) | 1.7-7.3 s |
| Positive phase (5 blocks) | 17-23 s |
| Restart phase | 5.9 s (SIGINT path) |
| Unfollow phase | 2.5 s |
| Negative phase | 0.6 s |
| **Whole run** | **34-37 s** |

The negative phase is fast because the corrupted anchor exhausts the bounded
catch-up (`gap_limit`) and the connection is dropped within ~50 ms of the first
connect; the 90 s budget is a safety margin.

## Notes

- **Headless Chromium and local network access**: Chromium blocks requests from
  a page to loopback/LAN addresses unless the origin is allowed, which surfaces
  as `net::ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS`. The test launches
  Chromium with `--disable-features=LocalNetworkAccessChecks`; without it,
  WebTransport never reaches the node (verified: the handshake reaches the node
  and then fails only on the expected fake certificate hash).
- **node0 restart uses SIGINT, not SIGTERM**: PolkaJam only installs a SIGINT
  handler (`tokio::signal::ctrl_c`). With SIGTERM the node dies without
  `node.shutdown()`, its database is not flushed, and the restarted node logs
  `Writing genesis block` and forks from genesis instead of catching up
  (observed: first post-restart block 53.8 s later with the genesis as parent).
  With SIGINT the node resumes its chain (`Best final block: ...`, no genesis
  rewrite) and catch-up completes in ~6 s. `killNode0()` sends SIGINT and falls
  back to SIGTERM/SIGKILL if the process does not exit.
- The `ava` configuration in `package.json` excludes `test/jam/**`, so
  `npm test` never starts a network.
- The test does not rebuild the browser bundle; it fails fast with instructions
  if `dist/mjs/index-browser.js` is missing.
## Aged-network catch-up (D14)

After building the browser bundle, run `node test/jam/e2e.mjs --aged` from
`wasm-node/javascript`. This manual runner starts GRANDPA nodes, counts actual
ancestors until the network has at least 130 blocks, then starts a fresh browser
client at `cpuRateLimit: 0.5`. It requires reaching the current RPC tip within
180 seconds and records first-block latency, time to tip, imported blocks per
second, and finality events in `aged-report.json` in its temporary runtime
directory. Allow about fourteen minutes for network aging.

Use `JAM_AGED_ATTACH_DIR=/path/to/running/runtime JAM_RPC_PORT=25800` to measure
an existing network without restarting it. `JAM_AGED_BLOCKS` changes the minimum
age in actual blocks; `JAM_AGED_BOUND_MS` changes the catch-up deadline.
`CHROMIUM_PATH` selects an installed browser, including on NixOS. The short
`npm run test:jam` CI gate remains separate from this deliberate aging wait.
