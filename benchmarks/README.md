# smoldot benchmarks

## Startup

Time from `start()` until polkadot-api `client.getFinalizedBlock()` resolves
— i.e. an app sitting on top of smoldot has its first finalized block in
hand. Each iteration spawns a fresh `node` subprocess.

This matches what `wasm-node/javascript/bench/time-to-initialized.mjs`
measures and is later than the bare `chainHead_v1_follow` `"initialized"`
notification (which fires before polkadot-api fetches the block details).

Two modes (selected with `--mode`):

- `cold` (default): smoldot starts with no DB. On a real network this is
  dominated by warp-sync from the chain spec's `lightSyncState` checkpoint.
- `warm`: smoldot is given a pre-saved DB (`addChain({ databaseContent })`)
  so it skips warp-sync and resumes from the snapshot. Mirrors the browser
  page-reload case where IndexedDB has the prior session's state.

In warm mode the runner does the save-DB step automatically:

1. Spawn zombienet (or use user-supplied specs), wait for relay finality
   (and para finality when `--target para`).
2. Once: start smoldot, addChain, wait for `chainHead_v1_follow`
   `"initialized"`, call `chainHead_unstable_finalizedDatabase`, write
   `<chainId>.db`.
3. N iterations: fresh Node subprocess, `addChain({ databaseContent })`,
   measure time-to-finalized-block.

### Run

Zombienet-local (fully reproducible, no internet):

```sh
cd benchmarks

# cold, westend-local relay
ZOMBIE_PROVIDER=native cargo run --release --bin startup -- --target relay --iterations 10

# cold, people-westend-local parachain
ZOMBIE_PROVIDER=native cargo run --release --bin startup -- --target para --iterations 10

# warm, parachain
ZOMBIE_PROVIDER=native cargo run --release --bin startup -- --mode warm --target para --iterations 10
```

Real public network (uses the `lightSyncState` checkpoint + bootnodes
shipped in the chain spec):

```sh
# cold, Polkadot relay
cargo run --release --bin startup -- \
  --target relay --relay-chain-spec polkadot --iterations 5

# cold, Polkadot AssetHub parachain
cargo run --release --bin startup -- \
  --target para \
  --relay-chain-spec polkadot \
  --para-chain-spec polkadot_asset_hub \
  --iterations 5

# warm, Polkadot relay
cargo run --release --bin startup -- \
  --mode warm --target relay --relay-chain-spec polkadot --iterations 5
```

Run with `--help` for the full flag list.

### DB scope (warm)

- `--target relay` saves only the relay DB.
- `--target para` saves both relay and para DBs (smoldot needs both to
  resolve para finality).

### Caveat (cold on zombienet)

The zombienet chain has no `lightSyncState` checkpoint, so the cold number
does **not** reflect mainnet cold start (which is dominated by
warp-sync-from-checkpoint). Treat it as a regression canary for the
init-path code. On zombienet, the `para finalized: 0 -> 0` drift row is
structurally always zero — westend-local has no para-side finality
pallet; smoldot derives para finality from the relay.
