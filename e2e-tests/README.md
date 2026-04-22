# e2e-tests

End-to-end tests that spawn a real relay chain + parachain via
[zombienet-sdk](https://crates.io/crates/zombienet-sdk) and exercise the
smoldot light node (JS) against it. These tests are not part of the main
workspace (see the `exclude = ["e2e-tests"]` in the root `Cargo.toml`) and
must be invoked with an explicit `--manifest-path`.

CI is in `.github/workflows/zombienet.yml`.

## Running locally

The tests require `polkadot` and `polkadot-parachain` to be available.
Pick one of the two modes below.

### Docker provider (matches CI, Linux only)

Lets zombienet-sdk run each node as a container.

```fish
env ZOMBIE_PROVIDER=docker \
    POLKADOT_IMAGE=docker.io/parity/polkadot:polkadot-stable2603 \
    CUMULUS_IMAGE=docker.io/parity/polkadot-parachain:polkadot-stable2603 \
    RUST_LOG=info \
    cargo test --manifest-path e2e-tests/Cargo.toml --test light_node_submission -- --nocapture
```

Requires Linux: the smoldot JS process runs on the host and dials the
parachain bootnode at its Docker bridge IP (`172.17.0.x`), which routes
directly from the host only on Linux. On macOS/Windows Docker Desktop this
will not work — use the native provider instead.

### Native provider (local dev, any OS)

Assumes you have a local build of [polkadot-sdk][psdk] (e.g.
`~/code/polkadot-sdk`) and produce the binaries via
`cargo build --release -p polkadot -p polkadot-parachain-bin`.

```fish
env PATH="$HOME/code/polkadot-sdk/target/release:$PATH" \
    ZOMBIE_PROVIDER=native \
    RUST_LOG=info \
    cargo test --manifest-path e2e-tests/Cargo.toml --test light_node_submission -- --nocapture
```

[psdk]: https://github.com/paritytech/polkadot-sdk

## Bumping the pinned image / binary version

The workflow pins `polkadot-stable2603`. When bumping:

1. Update `POLKADOT_IMAGE` and `CUMULUS_IMAGE` in `.github/workflows/zombienet.yml`.
2. If the runtime has diverged, regenerate `e2e-tests/chain-specs/people-westend-local-spec.json`
   against the new version.
3. Run the smoke test locally (Docker provider) before merging.
