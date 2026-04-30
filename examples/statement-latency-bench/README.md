# statement-latency-bench

Smoldot-based Node.js port of `polkadot-sdk/substrate/client/statement-store/statement-latency-bench`.

Each virtual client runs an in-process smoldot light client and joins the
statement-store libp2p network as its own peer. There is no `--rpc-endpoints`:
smoldot is a peer, not an RPC client of a node.

## Build smoldot first

```bash
cd ../../wasm-node/javascript
npm install && npm run build
cd -
npm install
```

## Usage

`--parachain-spec` and `--relay-chain-spec` each accept either a local file
path or an `http(s)://` URL. Bootnodes are expected to be embedded in the
spec; the canonical source is the [paritytech/chainspecs](https://github.com/paritytech/chainspecs)
repo, and smoldot bundles popular ones under `../../demo-chain-specs/`.

```bash
# bundled spec from the smoldot repo
node bench.js \
  --parachain-spec ../../demo-chain-specs/polkadot_asset_hub.json \
  --relay-chain-spec ../../demo-chain-specs/polkadot.json \
  --num-clients 4 --num-rounds 2 --messages-pattern "3:128" \
  --receive-timeout-ms 30000 --interval-ms 5000

# raw URL straight from polkadot-sdk (paritytech/chainspecs is a symlink-only
# index repo; raw.githubusercontent doesn't follow its symlinks across submodules,
# so point at the underlying files directly)
node bench.js \
  --parachain-spec https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/cumulus/parachains/chain-specs/asset-hub-polkadot.json \
  --relay-chain-spec https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/polkadot/node/service/chain-specs/polkadot.json \
  --num-clients 4 --num-rounds 2 --messages-pattern "3:128"
```

For a local dev network, splice your bootnode into the parachain spec once
(e.g. with `jq`, like `examples/statement-chat/dev.sh`) and pass the result
as `--parachain-spec`.

## Flags

| Flag | Default | Notes |
|---|---|---|
| `--parachain-spec` | required | Parachain raw chain spec — file path or `http(s)://` URL. |
| `--relay-chain-spec` | required | Relay chain raw chain spec — file path or `http(s)://` URL. |
| `--false-positive-rate` | `0.01` | Statement-store affinity bloom filter rate. |
| `--num-clients` | `100` | Each spawns its own smoldot instance. |
| `--num-rounds` | `1` | |
| `--messages-pattern` | `5:512` | `count:size,count:size,…` |
| `--receive-timeout-ms` | `5000` | |
| `--interval-ms` | `10000` | Wall-clock pacing between rounds. |
| `--statement-expiry-ms` | `600000` | |
| `--warmup-ms` | `15000` | Fixed sleep after `addChain` before round 1. |
| `--fail-fast` | `false` | First failure aborts all clients via AbortController. |
| `--log-level` | `info` | error/warn/info/debug/trace |

## Differences from `bench.rs`

- **Connection model.** Rust connects to N WS endpoints; smoldot joins the
  network directly. Chain specs (with embedded bootnodes) replace
  `--rpc-endpoints` as the wiring point.
- **One smoldot per client.** Smoldot dedupes within a client, so one peer per
  client requires one `start()` per client. Each is ~tens of MB resident; for
  N=100 expect multi-GB RAM. Use the same K8s-shard pattern as the Rust bench.
- **No barrier.** Smoldot startup is variable (5–30s) and gossip readiness is
  not observable from JSON-RPC, so a barrier on a code line gives false
  confidence. We use a fixed `--warmup-ms` instead and pace rounds by wall clock.
- **`--seed` removed.** Always derives sr25519 keys via `//StatementClient//${idx}`,
  matching `sc_statement_store::test_utils::get_keypair`.
- **Output lines** otherwise match `bench.rs` verbatim so log parsers keep
  working: `Starting Statement Store Latency Benchmark: …`, `Spawning {N}
  client tasks... {testRunId}`, `Benchmark Results: send_min=…`, `Benchmark
  Failed: failed_clients=…`, `Benchmark Finished: rounds_with_any_success=…`.
