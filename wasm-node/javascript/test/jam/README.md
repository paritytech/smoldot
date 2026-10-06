# JAM test assets

The live JAM tests are scenarios of the `e2e-tests` crate since D19 (e2e
scenarios on zombienet): zombienet-sdk spawns the PolkaJam network, Rust injects
the faults through zombienet's node handles, and a JavaScript body runs the
smoldot browser build in headless Chrome. See
[`e2e-tests/docs/jam-scenarios.md`](../../../../e2e-tests/docs/jam-scenarios.md)
for the five scenarios, the aged snapshot and the `DEV_MODE` route to the
manual demo.

```sh
cargo test --manifest-path e2e-tests/Cargo.toml --test jam_follow -- --nocapture
```

What stays here:

| File | Purpose |
|---|---|
| `demo.mjs` | Browser regression of the manual demo page. `node --test test/jam/demo.mjs` runs the controlled-stream cases (no network); `--live` is the JavaScript step of the `jam_demo` scenario and needs `JAM_SPEC_PATH` and `JAM_RPC_PORT` of a running GRANDPA network |
| `zombienet/tiny-grandpa.toml` | The six-validator GRANDPA network `just zombie-jam` spawns with `zombie-cli` for the manual demo (`demo/jam.md`) |
| `dev-chain-spec.json` | A fixed tiny dev spec, kept as a fixture for the drift check in [CHAIN_SPEC.md](CHAIN_SPEC.md); no test network reads it any more |
| `FINALITY.md` | GRANDPA finality design notes and the provenance of the committed CE 130 fixture |

The `ava` configuration in `package.json` excludes `test/jam/**`, so
`npm test` never starts a browser for these files.

## PolkaJam binaries

The scenarios and the manual demo need `polkajam` from the PolkaJam branch
`skunert/polkajam-light-client` at `3ccb03b7dc5ca54b16de81db7fdf7076de083ad0`
(main of 2026-09-30, `27d63b8d`, plus `gen-spec` writing each validator's P-256
id into its metadata, the restored `SKIP_PVM_BUILDS` switch, and combined
`<ed25519>+<p256>@ip:port` bootnodes in specs and `gen-spec`;
`polkajam 0.1.29 / GP 0.8.0`; GRANDPA votes sign the header hash with its
posterior state root since PR #1261). The version string does not distinguish
it from earlier pins. Build it once in that checkout:

```sh
SKIP_PVM_BUILDS=1 CARGO_PROFILE_RELEASE_DEBUG=line-tables-only RUSTC_BOOTSTRAP=1 \
  RUSTFLAGS='-Zcrate-attr=feature(array_windows,substr_range)' \
  cargo build --locked --release -p polkajam
```

Rust 1.93.0, no nightly toolchain and no RISC-V target. With `SKIP_PVM_BUILDS=1`
PolkaJam's `crates/node/build.rs` embeds an empty bootstrap-service guest blob
and never builds one, so `gen-spec` and `dump-spec` run from any directory and
the drift check in [CHAIN_SPEC.md](CHAIN_SPEC.md) reproduces the checked-in
spec. Line tables keep backtraces readable in an optimized binary.
`RUSTC_BOOTSTRAP` and the crate attribute enable two library features that are
still unstable in 1.93.0. On a Nix host add `NIX_ENFORCE_PURITY=0`, or the first
build script fails to link.

Then put its `target/release` first on `PATH`: zombienet starts `polkajam` from
`PATH`, and `just zombie-jam` and `just demo-jam-dev` prepend `POLKAJAM_BIN_DIR`.

## Notes

- **Headless Chromium and local network access**: Chromium blocks requests from
  a page to loopback/LAN addresses unless the origin is allowed, which surfaces
  as `net::ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS`. The `e2e-tests` browser
  host launches Chromium with `--disable-features=LocalNetworkAccessChecks`;
  without it, WebTransport never reaches the node.
- **Stopping a node uses SIGINT, not SIGTERM or SIGKILL**: PolkaJam only
  installs a SIGINT handler (`tokio::signal::ctrl_c`) and flushes its database
  in it. The scenarios stop a node through zombienet's `kill` with a grace
  period, which sends SIGINT first; a restarted node then resumes its chain
  instead of writing a new genesis block, and the scenarios check that.
