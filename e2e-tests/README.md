# smoldot end-to-end tests

End-to-end tests that spin up a Zombienet network and drive a Node.js-hosted smoldot light client against it. Each test has two halves, paired by file name:
- `tests/smoke.rs` orchestrates the network and runs the test logic.
- `js/smoke.js` runs the smoldot light client.


## Prerequisites

- **Rust** with the wasm32-unknown-unknown target.
- **Node.js 22+**.
- **Polkadot binaries on `$PATH`**: `polkadot`, `polkadot-parachain`,
  `polkadot-execute-worker`, `polkadot-prepare-worker`. CI pins the
  release tag in `.github/zombienet-env`. Locally, download that release
  from polkadot-sdk or build from source.


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
