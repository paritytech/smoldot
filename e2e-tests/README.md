# smoldot end-to-end tests

End-to-end tests that spin up a Zombienet network and drive a Node.js-hosted smoldot light client against it. Each test has two halves, paired by file name:
- `tests/smoke.rs` orchestrates the network and runs the test logic.
- `js/smoke.js` runs the smoldot light client.


## Prerequisites

- **Rust** with the wasm32-unknown-unknown target.
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


## Bulletin / bitswap snapshots

The `bulletin_fetch` test drives smoldot's `bitswap_v1_get` JSON-RPC
against a polkadot-bulletin-chain network with pre-built DB snapshots.
The URLs CI fetches from are hardcoded in
[`tests/bulletin_fetch.rs`](tests/bulletin_fetch.rs) and point at the
`zombienet-db-snaps` GCS bucket under `smoldot/bulletin_fetch/`. To
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
# the DB_SNAPSHOT_* constants in tests/bulletin_fetch.rs to match.
DATE=$(date +%F)
cd e2e-tests/target/snapshots
for f in relay bulletin-full bulletin-partial; do
  gsutil cp "$f.tgz" "gs://zombienet-db-snaps/smoldot/bulletin_fetch/$f-$DATE.tgz"
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
