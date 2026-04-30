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

```bash
node bench.js \
  --parachain-spec ./chain-specs/parachain.json \
  --relay-chain-spec ./chain-specs/relay.json \
  --bootnodes /ip4/127.0.0.1/tcp/30333/ws/p2p/12D3KooW… \
  --num-clients 4 \
  --num-rounds 2 \
  --messages-pattern "3:128" \
  --receive-timeout-ms 30000 \
  --interval-ms 5000
```

Both `--parachain-spec` (parachain) and `--relay-chain-spec` are required.
Bootnodes in `--bootnodes` are appended to whatever is already in the
parachain spec's `bootNodes` field.

## Flags

| Flag | Default | Notes |
|---|---|---|
| `--parachain-spec` | required | Parachain raw chain spec JSON path. |
| `--relay-chain-spec` | required | Relay chain raw chain spec JSON path. |
| `--bootnodes` | — | Comma-separated multiaddrs, appended to the spec. |
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
  network directly. Bootnodes replace `--rpc-endpoints` as the wiring point.
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
