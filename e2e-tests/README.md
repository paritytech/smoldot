# smoldot end-to-end tests

End-to-end tests that spin up a Zombienet network and drive a Node.js-hosted smoldot light client against it. Each test has two halves, paired by file name:
- `tests/smoke.rs` orchestrates the network and runs the test logic.
- `js/smoke.js` runs the smoldot light client.


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
   `waitForMessage`.


## chainHead against live networks

[`run_chainhead_test.sh`](run_chainhead_test.sh) drives
[`js/chainhead_v1_follow_test.js`](js/chainhead_v1_follow_test.js) against a
live public network, attaching a smoldot light client to bundled chain specs
from [`demo-chain-specs/`](../demo-chain-specs) and following `chainHead_v1`
until it sees enough new and finalized blocks. Unlike the Zombienet tests
above, it needs no local Polkadot binaries — only Node.js 22+ and npm. The
script builds the smoldot JS bundle and installs `js/` dependencies on first
run (set `SKIP_BUILD=true` to skip the rebuild on repeat runs).

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
