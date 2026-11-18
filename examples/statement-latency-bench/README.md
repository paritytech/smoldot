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
| `--client-offset` | `0` | Id of the first client. Client `i` uses the account `//StatementClient//<offset + i>`. |
| `--offset-by-pod-index` | `false` | Adds `JOB_COMPLETION_INDEX * num-clients` to the offset, so that every pod of a Kubernetes Indexed job gets its own accounts. |
| `--topics-per-round` | `false` | Use new topics and a new subscription every round. By default a client subscribes once before round 1 and keeps its topics for the whole run. |
| `--workers` | `1` | If >1, fork that many child processes; clients distributed evenly. Use to scale past one event loop's capacity (~150 clients). |
| `--num-rounds` | `1` | |
| `--messages-pattern` | `5:512` | `count:size,count:size,…`, sizes of at least 8 bytes. |
| `--receive-timeout-ms` | `5000` | A statement that arrives later in a fixed-topic run still counts as arrived, and as late. |
| `--interval-ms` | `10000` | Wall-clock pacing between rounds. |
| `--statement-expiry-ms` | `600000` | |
| `--warmup-ms` | `120000` | Max wait for `system_health` to report `peers > 0 && !isSyncing` before round 1; on timeout the client proceeds anyway. |
| `--fail-fast` | `false` | First failure aborts all clients via AbortController. |
| `--log-level` | `info` | error/warn/info/debug/trace |

## Topics and accounts

The clients form a ring, and client `i` listens to the topics of client
`i + 1`. The ring stays inside one bench process tree, so a pod of an Indexed
job is a ring of its own. With `--offset-by-pod-index` pod `p` uses the
accounts `p * num-clients` to `(p + 1) * num-clients - 1`, and all of them
need an allowance.

By default a client has one topic per message of the pattern and keeps it
for the whole run, as an app does. Every statement carries its round and its
message index in the first 8 bytes of its data, so the receiver knows which
round a statement belongs to. A statement of a later round replaces the
statement of the earlier round on the same channel.

## Delivery report

The run ends with one line per client and one line of totals:

```
Client 3: expected=90 arrived=87 missing=3 late=0 silent_topics=1 gaps_by_round=[4:1,5:1,6:1]
Client 3: silent topic 0x…
Benchmark Delivery: expected=1440 arrived=1437 missing=3 late=0 silent_topics=1 clients_with_loss=1
```

A silent topic received no statement in the whole run, which points at the
peer steering. A gap on a topic that received other statements points at
propagation.

## Differences from `bench.rs`

- **Connection model.** Rust connects to N WS endpoints; smoldot joins the
  network directly. Chain specs (with embedded bootnodes) replace
  `--rpc-endpoints` as the wiring point.
- **One smoldot per client.** Smoldot dedupes within a client, so one peer per
  client requires one `start()` per client. Each is ~tens of MB resident; for
  N=100 expect multi-GB RAM. For larger N, use `--workers <K>` to fork K child
  processes (each gets its own event loop and runs N/K clients), or follow the
  same K8s-shard pattern as the Rust bench.
- **Warmup + barrier.** Smoldot startup is variable (5–30s) and gossip
  readiness isn't directly observable from JSON-RPC. Each client polls
  `system_health` until `peers > 0 && !isSyncing` (capped by `--warmup-ms`),
  then arrives at a global barrier so round 1 starts on every client at the
  same time (across worker children too). Subsequent rounds are paced by
  `--interval-ms` per client.
- **`--seed` removed.** Always derives sr25519 keys via `//StatementClient//${idx}`,
  matching `sc_statement_store::test_utils::get_keypair`.
- **Output line prefixes** match `bench.rs` so log parsers keyed on the leading
  tokens keep working: `Spawning {N} client tasks... {testRunId}`, `Benchmark
  Results: send_min=…`, `Benchmark Failed: failed_clients=…`, `Benchmark
  Finished: rounds_with_any_success=…`. The smoldot port also adds a
  `Starting Statement Store Latency Benchmark:` config line, an `errors=[…]`
  segment to `Benchmark Failed` and the `Benchmark Delivery:` line, none of
  which exists in `bench.rs`.
- **Fixed topics and payload.** `bench.rs` uses new topics every round and
  zero-filled data. `--topics-per-round` gives the same topics as `bench.rs`.
