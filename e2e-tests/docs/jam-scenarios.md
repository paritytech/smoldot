# JAM scenarios

The JAM light client (`lib/src/jam/`, `light-base/src/sync_service/jam*`) is
tested end to end against a PolkaJam network that zombienet-sdk spawns: six
validators `jam0`..`jam5` and the ordinary node `jam-or`, the only one serving
JSON-RPC. Each scenario is one `tests/jam_<name>.rs` plus
one body `shared/jam_<name>.js`; helpers are in `src/jam.rs` and
`shared/jam.js`.

The client has a browser transport only (WebTransport), so the bodies run on the
browser host only. They read the client's `jam-*` debug log lines
(`ctx.clientLogs`), its follow events, the WebTransport requests it makes
(`installJamWireCapture`), and the node's JSON-RPC over `fetch` (PolkaJam
answers CORS `*`). The doc comment on each test function describes its
scenario in full.

| Scenario | Finality | What it proves |
|---|---|---|
| `jam_follow` | Dummy | follow, header hashes, slots and parent links, `chainHead_v1` refused, catch-up after a jam0 restart, unfollow, a spec with the wrong genesis authorities refused, no finality on the wire |
| `jam_finality` | GRANDPA | three authority sets verified, a pinned header survives pruning, finality continues across a jam0 restart; regenerates the committed finality fixture |
| `jam_discovery` | GRANDPA | with jam0 as its only `bootnodes_p256` entry, the client reads the validator set, holds two other validators while jam0 is down, and returns to jam0 |
| `jam_aged` | GRANDPA | a fresh client warps onto a restored aged chain, reads state at the join head, and reaches the tip within two minutes |

```sh
cargo test --manifest-path e2e-tests/Cargo.toml --features jam --test jam_follow -- --nocapture
```

## Prerequisites

- `polkajam` from the PolkaJam branch `skunert/polkajam-light-client`, first on
  `PATH` (see "Building PolkaJam" below).
- The `jam` feature, and a `zombienet-sdk` that generates JAM specs with P-256
  ids and both bootnode lists, kills and starts a JAM node on its own database,
  and fixes a JAM node's p2p port. No release does yet: until one does, point a
  `[patch.crates-io]` entry for `zombienet-sdk` at its branch
  `skunert/polkajam-light-client`, and repeat that branch's own
  `[patch.crates-io]` entries for the `jam-*` crates, which do not apply to this
  workspace.
- `ZOMBIE_PROVIDER=native`.
- Chrome: Playwright's, or an installed one through `CHROMIUM_PATH` (then
  `playwright install` is skipped).
- `SKIP_SMOLDOT_BUILD=1` uses the bundle already in `wasm-node/javascript/dist`
  instead of running `npm run build`.

## Building PolkaJam

The scenarios need `polkajam` from the PolkaJam branch
`skunert/polkajam-light-client` at `78fbf75e6e5a11380fadd70daf302f2a81930b4d`:
PolkaJam main plus `gen-spec` writing each validator's P-256 id into its
metadata, `gen-spec` writing JIP-4's `bootnodes` and `bootnodes_p256` lists,
the `SKIP_PVM_BUILDS` switch, and WebTransport certificates with the node's
P-256 id as issuer and the validity period as serial number. It reports
`polkajam 0.1.29 / GP 0.8.0`, which does not distinguish it from other builds.
Build it once in that checkout:

```sh
SKIP_PVM_BUILDS=1 CARGO_PROFILE_RELEASE_DEBUG=line-tables-only RUSTC_BOOTSTRAP=1 \
  RUSTFLAGS='-Zcrate-attr=feature(array_windows,substr_range)' \
  cargo build --locked --release -p polkajam
```

This needs Rust 1.93.0, but no nightly toolchain and no RISC-V target.
`SKIP_PVM_BUILDS=1` embeds an empty bootstrap-service guest blob instead of
building one, so `gen-spec` and `dump-spec` run from any directory. Line tables
keep backtraces readable.
`RUSTC_BOOTSTRAP` and the crate attribute enable two library features that are
still unstable in 1.93.0. On a Nix host add `NIX_ENFORCE_PURITY=0`, or the first
build script fails to link.

Then put its `target/release` first on `PATH`: zombienet starts `polkajam` from
`PATH`.

## How faults are injected

Rust and the body coordinate through the `SyncFile`: Rust sends labels the body
awaits with `ctx.waitSync`, and the body sends labels Rust awaits with
`SyncFile::wait_for_js` (`ctx.sendSync`, browser host only). Rust stops a node
through zombienet-sdk's node handle with SIGINT and a 15-second grace, because
PolkaJam flushes its database only on Ctrl-C, and starts it again on the same
directory. Every scenario checks that the restarted node wrote no second
genesis block.

After the body, Rust checks node-side facts over the RPC and tears the network
down: no `polkajam` process of the run may survive, and the base directory is
removed. A failed run leaves its base directory for inspection.

## The aged snapshot

`jam_aged` restores a snapshot instead of aging a network for twenty minutes.
`jam_generate_snapshot` (`#[ignore]`) produces it:

```sh
cargo test --manifest-path e2e-tests/Cargo.toml --features jam \
  --test jam_generate_snapshot -- --ignored --nocapture
```

It spawns the GRANDPA network with fixed ports (`AGED_PORTS`: validators
47210 to 47215, RPC 47216), waits until three set changes are finalized, then
two more epochs, and until the finalized chain holds `JAM_SNAPSHOT_MIN_BLOCKS`
blocks (default 201), stops every node with SIGINT and writes into
`JAM_SNAPSHOT_OUT` (default `~/.cache/smoldot-e2e/jam/`):

- `jam-aged-snapshot.tar.gz`: `<node>/data` and `<node>/cfg` of all seven
  nodes, plus `snapshot-jam_spec.json`, the generated spec;
- `manifest.json`: format, archive name, SHA-256 and size, the spec's canonical SHA-256,
  the ports, the last finalized slot and hash, the best slot, the set id at the
  finalized head, the finalized block count, the PolkaJam commit and the date.

Last, the generator restores the archive once and requires the restored
network to finalize past the snapshot within 90 s. Some archives never resume
finality; the generator refuses those, and also fails when finality stands
still for three minutes while aging. Run it again then.

`jam_aged` reads `JAM_SNAPSHOT_DIR` (default the same directory), checks the
archive against the manifest, unpacks it into a fresh base directory, spawns
the same config (zombienet keeps the restored `data` and `cfg`), and fails
unless zombienet regenerated the archived spec: the validator addresses are part
of the genesis, which is why the ports are fixed. The client starts once the
restored nodes finalize past the snapshot again. Without the snapshot the test
fails with the generator command; the snapshot is local only and never
downloaded.

JAM slots are wall-clock slots, so the restored network resumes at the current
slot: the gap since the snapshot is skipped slots and epochs, and the finalized
head the client joins at is far from genesis with many set changes behind it.

## DEV_MODE

`DEV_MODE=1` on any scenario spawns its network, skips the body, prints how to
run the body by hand, and keeps the
network up for `KEEP_ALIVE_SECS` (default 36000) or until Ctrl-C:

```sh
DEV_MODE=1 cargo test --manifest-path e2e-tests/Cargo.toml --features jam --test jam_follow -- --nocapture
```
