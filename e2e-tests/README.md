# smoldot end-to-end tests

End-to-end tests that spin up a Zombienet network and drive smoldot light
clients against it. Each test has two halves, paired by name:

- `tests/<name>.rs` — Rust orchestration: spawns the network, seeds state,
  runs the JS body, checks metrics.
- `shared/<name>.js` — the test body: boots a smoldot light client and
  exercises the scenario. Bodies are host-agnostic and run unchanged on
  **two hosts**: the Node.js build over TCP, and the browser build in
  headless browser over WebRTC (`forbidTcp`).


## Layout

```
shared/         host-agnostic test bodies + helper libs
                (rpc.js, codec.js, ctx-primitives.js)
hosts/node/     generic Node runner (run.js) + ctx builder (ctx.js)
hosts/browser/  generic Playwright runner + in-page ctx builder
tests/          Rust orchestration (zombienet, metrics, snapshots)
src/            harness (run_shared_test, network builders, SyncFile, …)
```


## Prerequisites

- **Rust** with either the `wasm32v1-none` (preferred, requires Rust 1.84+) or
  `wasm32-unknown-unknown` target installed.
- **Node.js 22+**.
- **Polkadot binaries on `$PATH`**: `polkadot`, `polkadot-parachain`,
  `polkadot-execute-worker`, `polkadot-prepare-worker`, `test-parachain`.
  CI pins the release tag in `.github/zombienet-env`. Locally, download
  that release from polkadot-sdk or build from source.


## How to run

```sh
# All tests
cargo test --manifest-path e2e-tests/Cargo.toml -- --nocapture

# Single test
cargo test --manifest-path e2e-tests/Cargo.toml \
  --test statement_store_submission -- --nocapture
```

What happens inside:

1. The harness builds the smoldot WASM bundle and installs JS
   dependencies on first run.
2. Zombienet brings up the relay and parachain.
3. The Rust side seeds state on full nodes over JSON-RPC.
4. A JS script boots a smoldot light client, attaches it to the network,
   and exercises the test scenario.
5. The Rust side reads metrics and checks outcomes over JSON-RPC.
6. Rust and JS synchronise through a file-backed channel — `SyncFile` and
   `ctx.waitSync`.


## Writing a new shared test

Create `shared/<name>.js`:

```js
import { createRpc } from "./rpc.js";

// Env vars whose values are file *paths*. The runner reads each file and
// exposes its contents as ctx.files[NAME] (string, or null when unset), so
// unset optional inputs need no special handling.
export const fileInputs = ["RELAY_CHAIN_SPEC", "PARA_CHAIN_SPEC"];

export default async function myTest(ctx) {
  const { report, env, files, log } = ctx;
  const rpc = createRpc(ctx.client);

  if (!files.RELAY_CHAIN_SPEC) throw new Error("RELAY_CHAIN_SPEC required");

  const relay = await rpc.addChain({ chainSpec: files.RELAY_CHAIN_SPEC });
  report("addChain relay", true);

  // ...drive JSON-RPC, then for every check:
  report("what was checked", ok, `detail=${value}`);
  if (!ok) throw new Error("give a reason");
}
```

Wire it from Rust in `tests/<name>.rs` after spawning the network:

```rust
run_test("my_test", &env_vars).await?;                    // both hosts
run_shared_test(Host::Node, "my_test", &env_vars).await?; // one host
```

### Rules for bodies

The same module is imported by Node from disk and served to a browser page
(`/shared/*` via Playwright interception), so:

- **No Node APIs** — no `fs`, `process`, `Buffer`, `node:` imports. All
  inputs arrive pre-resolved: `ctx.env` (env var strings) and `ctx.files`
  (file contents for `fileInputs`). Use `shared/codec.js` helpers
  (`hexToBytes`, `decodeHeader`, `sha256Hex`, …) instead of Node
  equivalents.
- **Only relative sibling imports** (`./rpc.js`, `./codec.js`) — both hosts
  resolve those; anything else won't load in the page.
- **Outcome**: `ctx.report(name, passed, detail?)` prints a PASS/FAIL line
  and a FAIL makes the run exit non-zero; throwing anywhere also fails the
  test (the runner reports it). Never call `process.exit`.

### The ctx contract

`shared/ctx-primitives.js` is the single source of truth; both runners call
`assertCtx` at startup so a drifted key fails loudly. Every body receives:

| key | meaning |
| --- | --- |
| `host` | `"node"` or `"browser"`, for the rare host-specific branch |
| `client` | started smoldot client (browser: WebRTC only) |
| `env` | environment variables (strings) |
| `files` | `fileInputs` contents: `string` or `null` |
| `report(name, ok, detail?)` | PASS/FAIL sink |
| `log(msg)` | free-form log line |
| `waitSync(label, timeoutMs?)` | resolves when Rust sends `label` (below) |
| `dumpDb({name: content})` | write files to `SMOLDOT_DB_DUMP_DIR`; no-op when unset |
| `cleanup()` | called by the runner in `finally` |

Optional extensions, checked by `assertCtx` after they run:
- `export async function prepareCtx(base)` in the body — host-agnostic
  augmentation (extra helpers on top of the primitives).
- `hosts/<host>/prepare/<name>.js` — host-specific augmentation,
  auto-discovered only when the file exists (rare).

### JSON-RPC

`createRpc(ctx.client)` returns `{ addChain, sendRpc, readJsonRpcUntil,
sendRpcAndWait, waitForJsonRpcMatch }`. It drains each added chain's
responses into a per-chain FIFO — so if a body needs to be the *sole*
consumer of a chain's response stream (e.g. the `JsonRpcMux` in
`chainhead_v1_follow.js`), add that chain via `ctx.client.addChain(...)`
directly instead of `rpc.addChain`.

### Synchronising with Rust mid-test

Create a `SyncFile` on the Rust side, pass `("SYNC_PATH", sync.path())` in
the env vars, and pair `sync.send("label")` with
`await ctx.waitSync("label")` in the body.

### Running one body by hand

```sh
cd e2e-tests && npm install
TEST_NAME=smoke RELAY_CHAIN_SPEC=… PARA_CHAIN_SPEC=… REQUIRED_BLOCKS=5 \
  node hosts/node/run.js        # or hosts/browser/run.js
```


## chainHead against live networks

[`run_chainhead_test.sh`](run_chainhead_test.sh) drives the shared
[`chainhead_v1_follow`](shared/chainhead_v1_follow.js) body via
`hosts/node/run.js` against a live public network, attaching a smoldot light
client to bundled chain specs from
[`demo-chain-specs/`](../demo-chain-specs) and following `chainHead_v1`
until it sees enough new and finalized blocks. Unlike the Zombienet tests
above, it needs no local Polkadot binaries — only Node.js 22+ and npm. The
script builds the smoldot JS bundle and installs `e2e-tests/` dependencies
on first run (set `SKIP_BUILD=true` to skip the rebuild on repeat runs).

```sh
# Relay-only:
./run_chainhead_test.sh paseo

# Relay + asset-hub parachain:
./run_chainhead_test.sh paseo-ah
```

The network argument selects the mode: a bare relay name (`paseo`, `polkadot`,
`kusama`, `westend`) runs relay-only, while an `-ah`/`-ah-next` variant also
adds the matching asset-hub parachain. When an RPC URL is configured for the
network, the script first queries its finalized height so the validator's
lag-regression check is meaningful.

Useful overrides (see the script header for the full list):
- `WITH_RUNTIME=true` — subscribe with runtime (default `false`).
- `RELAY_CHAIN_SPEC` / `PARA_CHAIN_SPEC` — override the bundled specs.
- `SMOLDOT_DB_DUMP_DIR` — dump smoldot DBs on success and warm-load them on
  later runs from the same directory.


## Bulletin / bitswap snapshots

The `bulletin_fetch` test drives smoldot's `bitswap_unstable_get` JSON-RPC
(plus an alias-coverage call to the legacy `bitswap_v1_get` name) against a
polkadot-bulletin-chain network with pre-built DB snapshots.
The URLs CI fetches from are hardcoded in
[`src/harness.rs`](src/harness.rs) (used by both `bulletin_fetch` and
`bulletin_batch`) and point at the `zombienet-db-snaps` GCS bucket under
`smoldot/bulletin_fetch/`. To
refresh those snapshots, regenerate them with
`bulletin_generate_snapshot` and upload via `gsutil` (only needed when
the bulletin runtime or `bulletin::payloads()` changes).

### Generating snapshots locally

Prerequisites: `polkadot` and `polkadot-parachain` on `$PATH`. The bulletin
chain runtime is loaded from the vendored
[`chain-specs/bulletin-westend-local-spec.json`](chain-specs/bulletin-westend-local-spec.json)
(generated upstream via
[`polkadot-bulletin-chain/scripts/create_bulletin_westend_spec.sh`](https://github.com/paritytech/polkadot-bulletin-chain/blob/main/scripts/create_bulletin_westend_spec.sh)).
Override with `BULLETIN_CHAIN_SPEC=/path/to/spec.json` when iterating on a
newer bulletin runtime.

```sh
# Outputs relay.tgz, bulletin-full.tgz, bulletin-partial.tgz, and
# manifest.json under e2e-tests/target/snapshots/.
cargo test --manifest-path e2e-tests/Cargo.toml \
  -- --ignored bulletin_generate_snapshot --nocapture

# Tag the archives with the generation date and upload. Bump the date in
# the DB_SNAPSHOT_* constants in src/harness.rs to match. The
# `--canned-acl=publicRead` flag ensures anonymous HTTPS access works for
# CI (the bucket uses fine-grained per-object ACLs and doesn't default to
# public read).
DATE=$(date +%F)
cd e2e-tests/target/snapshots
for f in relay bulletin-full bulletin-partial; do
  gcloud storage cp --canned-acl=publicRead \
    "$f.tgz" "gs://zombienet-db-snaps/smoldot/bulletin_fetch/$f-$DATE.tgz"
done
```

### Iterating against local snapshots

`bulletin_fetch` defaults to fetching from GCS. To test against a locally-
generated snapshot bundle, point the override env vars at file paths:

```sh
export DB_SNAPSHOT_RELAY_OVERRIDE=$PWD/e2e-tests/target/snapshots/relay.tgz
export DB_SNAPSHOT_BULLETIN_FULL_OVERRIDE=$PWD/e2e-tests/target/snapshots/bulletin-full.tgz
export DB_SNAPSHOT_BULLETIN_PARTIAL_OVERRIDE=$PWD/e2e-tests/target/snapshots/bulletin-partial.tgz
cargo test --manifest-path e2e-tests/Cargo.toml --test bulletin_fetch -- --nocapture
```
