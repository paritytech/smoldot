# JAM scenarios

The JAM light client (`lib/src/jam/`, `light-base/src/sync_service/jam*`) is
tested end to end against a PolkaJam network that zombienet-sdk spawns: six
validators `jam0`..`jam5` and the ordinary node `jam-or`, the only one serving
JSON-RPC. Each scenario is one `tests/jam_<name>.rs` plus, except `jam_demo`,
one body `shared/jam_<name>.js`; helpers are in `src/jam.rs` and
`shared/jam.js`.

The client has a browser transport only (WebTransport), so the bodies run on the
browser host only. They read the client's `jam-*` debug log lines
(`ctx.clientLogs`), its follow events, the WebTransport requests it makes
(`installJamWireCapture`), and the node's JSON-RPC over `fetch` (PolkaJam
answers CORS `*`).

| Scenario | Finality | What it proves | Time here |
|---|---|---|---|
| `jam_follow` | Dummy | the browser gate of C2 (browser end-to-end test and CI gate): follow, five blocks within five slots, parent links, header hash, jam0 restart catch-up, unfollow, the wrong-authority spec refused, and the Dummy wire facts (typed NoData for CE 153, no CE 129, no live `C(8)` read, no finalized event) | 36 s |
| `jam_finality` | GRANDPA | D1 (GRANDPA finality): three authority sets verified, a pin survives pruning, finality continues while jam0 is down for 12 s and back; `JAM_FINALITY_FIXTURE=<path>` regenerates `lib/src/jam/finality/fixtures/polkajam-grandpa.json` | 2 min 40 s |
| `jam_discovery` | GRANDPA | D3 (peer discovery): with jam0 as its only bootnode the client reads `C(8)`, holds two other validators while jam0 is down, keeps verifying headers and finality, and returns to jam0 after its restart; `JAM_DISCOVERY_AGE_SECONDS` ages the network first | 1 min 25 s |
| `jam_aged` | GRANDPA | D7 (GRANDPA warp sync), D2 (verified state reads), D14 (ascending catch-up): a fresh client joins a restored aged chain by warp, reads state at the frozen join head, and reaches the tip; must finish within two minutes | 19 s |
| `jam_demo` | GRANDPA | C3 (manual demo), D18 (zombienet demo): `node wasm-node/javascript/test/jam/demo.mjs --live` with the harness attached, after the network passed a set change | 1 min 40 s |

```sh
cargo test --manifest-path e2e-tests/Cargo.toml --test jam_follow -- --nocapture
```

## Prerequisites

- `polkajam` from the PolkaJam branch `skunert/polkajam-light-client`, first on
  `PATH` (build recipe in `wasm-node/javascript/test/jam/README.md`).
- `zombienet-sdk` from its branch `skunert/polkajam-light-client`, checked out
  where `Cargo.toml` points: only that branch generates JAM specs with P-256 ids
  and combined bootnodes, kills and starts a JAM node on its own database, and
  fixes a JAM node's p2p port. `Cargo.toml` repeats its `[patch.crates-io]` for
  the `jam-*` crates.
- `ZOMBIE_PROVIDER=native`.
- Chrome: Playwright's, or an installed one through `CHROMIUM_PATH` (then
  `playwright install` is skipped). The browser host disables Chrome's local
  network access checks, without which WebTransport cannot reach loopback.
- `SKIP_SMOLDOT_BUILD=1` uses the bundle already in `wasm-node/javascript/dist`
  instead of running `npm run build`.

## How faults are injected

Rust and the body coordinate through the `SyncFile`: Rust sends labels the body
awaits with `ctx.waitSync`, and the body sends labels Rust awaits with
`SyncFile::wait_for_js` (`ctx.sendSync`, browser host only, written as `js:`
lines). Rust stops and starts a node through zombienet-sdk's node handle
(`kill_node`, `start_node` in `src/jam.rs`): SIGINT with a 15-second grace,
because PolkaJam flushes its database only on Ctrl-C, and a start on the same
directory. Every scenario checks that the restarted node wrote no second
genesis block.

| Scenario | Body sends | Rust then | Rust sends |
|---|---|---|---|
| `jam_follow` | `POSITIVE_DONE` | kills jam0 | `KILLED` |
| `jam_follow` | `RESTART_READY` | starts jam0 | `RESTARTED` |
| `jam_finality` | `THREE_SETS` | checks three finalized set changes on the RPC, kills jam0, waits 12 s, starts it | `RESTARTED` |
| `jam_discovery` | `AT_TIP` | kills jam0 | `KILLED` |
| `jam_discovery` | `CONTINUED` | starts jam0 | `STARTED` |

After the body, Rust checks node-side facts over the RPC (best and finalized
heads advancing, set changes on the finalized chain) and tears the network
down: no `polkajam` process of the run may survive, and the base directory is
removed. A failed run leaves its base directory for inspection.

The finalized set changes are counted on the RPC as epoch changes along the
finalized chain; the first block after genesis carries an epoch mark, so the
count equals the set id the client logs (`jam-finalized; set_id=N`).

## The aged snapshot

`jam_aged` restores a snapshot instead of aging a network for twenty minutes.
`jam_generate_snapshot` (`#[ignore]`) produces it:

```sh
cargo test --manifest-path e2e-tests/Cargo.toml \
  --test jam_generate_snapshot -- --ignored --nocapture
```

It spawns the GRANDPA network with fixed ports (`AGED_PORTS`: validators
47210 to 47215, RPC 47216), waits until three set changes are finalized, then
two more epochs, and until the finalized chain holds `JAM_SNAPSHOT_MIN_BLOCKS`
blocks (default 201, the D7 aged acceptance), stops every node with SIGINT and
writes into `JAM_SNAPSHOT_OUT` (default `~/.cache/smoldot-e2e/jam/`):

- `jam-aged-snapshot.tar.gz`: `<node>/data` and `<node>/cfg` of all seven
  nodes, plus `snapshot-jam_spec.json`, the generated spec (`tar.gz`, since the
  host has no `zip`);
- `manifest.json`: format, archive name, SHA-256 and size, the spec's canonical SHA-256,
  the ports, the last finalized slot and hash, the best slot, the set id at the
  finalized head, the finalized block count, the PolkaJam commit and the date.

Last, the generator restores the archive once into a scratch directory and
requires the restored network to finalize past the snapshot within 90 s.
PolkaJam's GRANDPA sometimes stops finalizing for good while blocks keep
coming (after a restore, with GRANDPA debug logs: every validator casts the
next round's prevote and none is counted). On this host it happened once on a running network after 18 minutes, and on
every one of four restores of one archive, while three other archives resumed
on every restore, including after five skipped epochs. The generator therefore
fails fast when finality stands still for three minutes and refuses an archive
that does not resume; run it again then.

`jam_aged` reads `JAM_SNAPSHOT_DIR` (default the same directory), checks the
archive against the manifest, unpacks it into a fresh base directory, spawns
the same config (zombienet keeps the restored `data` and `cfg`), and fails
unless zombienet regenerated the archived spec: the validator addresses are part
of the genesis, which is why the ports are fixed. The specs are compared by the
SHA-256 of their canonical JSON (keys sorted), because `gen-spec` writes
`genesis_state` in hash-map order, which differs between runs. The client
starts once the restored nodes finalize past the snapshot again, as on a
network that never stopped.
Without the snapshot it fails with the generator command. Nothing is downloaded
yet: a `TODO` in `JamSnapshot::resolve` marks where the GCS download and SHA-256
pin go once the archive is uploaded, as `src/snapshot.rs` does for the smoke
bundle.

JAM slots are wall-clock slots, so the restored network resumes at the current
slot: the gap since the snapshot is skipped slots and epochs, and the finalized
head the client joins at is far from genesis with many set changes behind it.

## DEV_MODE

`DEV_MODE=1` on any scenario spawns its network, skips the body, prints how to
run the body by hand and how to attach the manual demo page, and keeps the
network up for `KEEP_ALIVE_SECS` (default 36000) or until Ctrl-C:

```sh
DEV_MODE=1 cargo test --manifest-path e2e-tests/Cargo.toml --test jam_follow -- --nocapture
# prints, among others:
just demo-jam-attach '/tmp/zombienet-<pid>/jam_spec.json' <rpc port>
```

`just demo-jam-dev [scenario]` does the same for `jam_demo` (GRANDPA) by
default. The other route to the manual demo, `just zombie-jam` then
`just demo-jam-attach`, spawns the network with `zombie-cli` and the checked-in
TOML (`wasm-node/javascript/demo/jam.md`).
