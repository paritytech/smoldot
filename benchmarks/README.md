# smoldot benchmarks

## Cold startup

Time from `start()` to the first `chainHead_v1_follow` notification with
`event: "initialized"`. Each iteration spawns a fresh `node` subprocess.

### Run

Zombienet-local (fully reproducible, no internet):

```sh
cd benchmarks

# westend-local relay
ZOMBIE_PROVIDER=native cargo run --release --bin cold-startup -- --target relay --iterations 10

# people-westend-local parachain
ZOMBIE_PROVIDER=native cargo run --release --bin cold-startup -- --target para --iterations 10
```

Real public network (uses the `lightSyncState` checkpoint + bootnodes
shipped in the chain spec):

```sh
# Polkadot relay
cargo run --release --bin cold-startup -- \
  --target relay --relay-chain-spec polkadot --iterations 5

# Polkadot AssetHub parachain
cargo run --release --bin cold-startup -- \
  --target para \
  --relay-chain-spec polkadot \
  --para-chain-spec polkadot_asset_hub \
  --iterations 5
```

### Flags

- `--iterations N`, `--warmup N` — sample counts
- `--target relay|para` — which chain's `chainHead_v1_follow` to subscribe to
  (default `para` — exercises the full flow; `relay` is faster + cleaner baseline)
- `--relay-chain-spec <PATH|NAME>` / `--para-chain-spec <PATH|NAME>` —
  skip zombienet and use given specs. Short name resolves to
  `demo-chain-specs/<name>.json`
- `--no-with-runtime` — `withRuntime: false` (fires earlier)
- `--timeout-secs N` — per-iteration timeout (default 120)
- `--json` — also emit a machine-readable JSON line

### Caveat

The zombienet chain has no `lightSyncState` checkpoint, so the number
does **not** reflect mainnet cold start (which is dominated by
warp-sync-from-checkpoint). Treat it as a regression canary for the
init-path code. On zombienet, the `para finalized: 0 -> 0` drift row is
structurally always zero — westend-local has no para-side finality
pallet; smoldot derives para finality from the relay.

## Warm startup

Same measurement window as cold, but smoldot is given a pre-saved DB
(`addChain({databaseContent})`) so it skips warp-sync and resumes from a
snapshot. Mirrors the browser page-reload case where IndexedDB has the
prior session's state.

The runner does the save-DB step automatically:

1. Spawn zombienet (or use user-supplied specs), wait for relay finality.
2. Once: start smoldot, addChain, wait for `initialized`, call
   `chainHead_unstable_finalizedDatabase`, write `<chainId>.db`.
3. N iterations: fresh Node subprocess, `addChain({databaseContent})`,
   measure time-to-initialized.

### Run

```sh
# zombienet: westend-local relay
ZOMBIE_PROVIDER=native cargo run --release --bin warm-startup -- --target relay --iterations 10

# zombienet: people-westend-local parachain
ZOMBIE_PROVIDER=native cargo run --release --bin warm-startup -- --target para --iterations 10

# real network: Polkadot relay
cargo run --release --bin warm-startup -- \
  --target relay --relay-chain-spec polkadot --iterations 5
```

### Extra flags (on top of cold-startup's)

- `--db-dir PATH` — where to read/write `<chainId>.db`. Defaults to the
  zombienet base dir for zombienet runs, or a tempdir for user-supplied
  specs.
- `--reuse-db` — reuse existing DB files in `--db-dir` instead of
  regenerating. Useful for fast iteration on a real network; **not**
  recommended on zombienet (each spawn is a fresh network, the saved DB
  is stale).

### DB scope

- `--target relay` saves only the relay DB.
- `--target para` saves both relay and para DBs (smoldot needs both to
  resolve para finality).
