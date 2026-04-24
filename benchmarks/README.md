# smoldot benchmarks

Startup benchmarks for the smoldot light client, driven by zombienet.

## Cold startup

Measures the time from `start()` to the first `chainHead_v1_follow`
notification with `event: "initialized"`. Each iteration spawns a fresh
`node` subprocess — cold = fresh V8, fresh WASM bring-up, fresh client,
no reused state.

### Run

```sh
cd benchmarks
cargo run --release --bin cold-startup -- --iterations 10
```

Common flags:

- `--iterations N` — measured iterations (default 10)
- `--warmup N` — discarded warmup iterations (default 0)
- `--target relay|para` — which chain's `chainHead_v1_follow` to
  subscribe to (default `para`)
- `--no-with-runtime` — pass `withRuntime: false` (fires earlier; default
  is `true`, which waits for the runtime to be fetched)
- `--json` — emit a single JSON object in addition to the human report
- `--relay-chain-spec PATH` / `--para-chain-spec PATH` — skip zombienet
  spawn and use provided specs (e.g. `demo-chain-specs/polkadot.json` to
  bench against a live network — note that this depends on external
  bootnodes being reachable)

### What this measures

With the default zombienet setup (people-westend-local + statement-store
parachain, see `e2e-tests/src/statement.rs`), the bench measures the
time for smoldot to: initialize WASM + libp2p, connect to a bootnode,
grandpa-warp-sync to the finalized head, fetch the runtime, and emit
`initialized`.

### What this does NOT measure

The zombienet chain has no `lightSyncState` checkpoint and only a few
blocks of history. Real mainnet cold-start is dominated by
warp-sync-from-checkpoint over the public network — that is **not**
captured here. Use this number as a regression canary for the init-path
code, not as a mainnet latency estimate.

### Readiness gate

Before iterations start, the bench waits for the **relay** finalized
block to reach `--min-finalized-before-bench` (default 1), with timeout
`--finalized-wait-secs` (default 180). Readiness is always gated on the
relay — parachain finality derives from relay finality and can lag
significantly on a fresh local network, so gating on the para would
frequently time out even though the chain is healthy.

### Drift across iterations

The zombienet chain keeps producing blocks while we iterate. The report
prints `relay finalized: before -> after` and `para finalized: before
-> after` so drift is visible on both chains. Over ~10 iterations this
is typically under ten blocks — negligible — but if it ever grows
noticeably, the per-iteration numbers are no longer apples-to-apples.
