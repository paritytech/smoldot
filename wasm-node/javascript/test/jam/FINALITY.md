# JAM GRANDPA finality

`npm run test:jam:finality` runs a fresh six-validator PolkaJam GRANDPA network,
verifies three authority sets through the browser's real smoldot bundle, checks
that pinned headers survive tree pruning, and reconnects node0 while finality
advances. It writes `capture.json` (headers, raw framed CE130 exchanges, follow
events and client logs) to its printed runtime directory and tears down all nodes.

Build the browser bundle first, then run from `wasm-node/javascript`:

```sh
node prepare.mjs --debug
npm run buildModules
POLKAJAM_BIN_DIR=/path/to/pinned/binaries npm run test:jam:finality
```

`POLKAJAM_BIN_DIR` is optional: without it `polkajam` is taken from `PATH`.
It is the only required executable and must be built beforehand; nothing is
built during a run. A missing executable stops startup. Build instructions for
PolkaJam `8ceedf46c4828137c8835e4227d7f3a62ada0463` are in
[README.md](README.md). Every node reads [dev-chain-spec.json](dev-chain-spec.json),
with validator ports fixed at 40000–40005. Stop other test/demo networks first.
`CHROMIUM_PATH` optionally selects a system Chrome executable.
`JAM_RPC_PORT` (24800) and `JAM_RUNTIME_DIR` override the independent defaults.
To regenerate the committed fixture from a successful run, set
`JAM_FINALITY_FIXTURE` to its output path. The exporter keeps the original header
and CE130 payload bytes, checks frame lengths, hashes and captured ancestry, and
retains proofs whose targets the browser finalized. It requires at least twenty
proofs across three authority sets. Raw exchanges remain in `capture.json`.

C2's `npm run test:jam` retains its Dummy-mode default and no-finality assertions.
The manual demo's harness explicitly selects GRANDPA.

Both finality modes launch six validators and one ordinary RPC node directly,
using the same checked-in genesis. From `wasm-node/javascript`:

```sh
polkajam --config-path "$NODE/conf" --chain test/jam/dev-chain-spec.json run \
  --data-path "$NODE/data" --finality-mode grandpa --dev-validator 0
# Repeat with validator indices 1 through 5 and separate NODE directories.
polkajam --config-path "$RPC_NODE/conf" --chain test/jam/dev-chain-spec.json run \
  --data-path "$RPC_NODE/data" --finality-mode grandpa \
  --mode=ordinary --rpc-port 24800
```

Use `POLKAVM_BACKEND=interpreter` with the existing header-only dev binaries.
The runner does not build or modify PolkaJam. Restarts preserve GRANDPA mode and
node0's database. The C3 harness owns the separate manual-demo server.

## Trusted checkpoints

A non-genesis `checkpoint` must contain `finality` with:

- `set_id`: a u32, after finalizing the checkpoint header;
- `current`: 6 through `max_validators` Ed25519 public keys, in multiples of 3,
  each 32-byte hex;
- `next`: the next authorities, in the same representation and legal count range;
  its length may differ from `current`.

This is trusted input. Missing fields produce named configuration errors; set IDs
are never inferred from slots or supplied by peers. No stored round is required.
The ordinary checkpoint `header` and four post-state fields are unchanged.
The captured-proof regression resumes from mid-epoch, post-transition, and the
first anchor after a large skipped-epoch jump. Authority rotation is
`current <- old next`, `next <- finalized epoch mark`, followed by `set_id += 1`.

## Fetching and retention

Peer advertisements trigger requests only for authenticated retained headers.
The earliest unfinalized epoch-mark ancestor is fetched first, so proofs cannot
skip authority transitions. Catch-up batches headers and requests a proof before
the tree fills. One shared reservation serializes proof requests across peers;
attempted-peer records are bounded by retained targets. A missing/reset proof
leaves the header connection usable and permits another configured peer to try.
Invalid proofs fault the connection and never change the root or authorities.
If no available peer can bridge a transition, finality stays unchanged; operators
need another peer or a trusted checkpoint before existing bounds are exhausted.

Root advancement removes old ancestors and discarded forks, but preserves all
descendants of the new root. RPC owns its header pins independently; a finalize
notification does not unpin them. Snapshots start at the current finalized root.

The existing 16 MiB tree budget and per-node representation are unchanged.
Proofs are limited to 1 MiB on the wire, with explicit witness/ancestry-work bounds.
The revised conservative chain-task estimate is about 68 MiB plus less than
32 KiB of attempted-target records. This includes transient copies and is not
process RSS. RPC and platform-owned buffers are accounted separately in the code.

## Evidence

The committed `lib/src/jam/finality/fixtures/polkajam-grandpa.json` was captured
from the pinned GRANDPA dev network on 2026-09-22. It contains 21 authenticated
headers and 20 raw justification payloads across three authority sets and a
node0 restart. The spec retains only the four genesis-state items the light
client consumes. Tests verify real header seals and proofs, reject mutated set
IDs/signatures/quorums and unknown targets, and restore trusted checkpoints.
Synthetic tests additionally cover nonempty vote ancestries, forks, missing
transition proofs, duplicate votes, malformed input, and allocation/work limits.

The live run emitted 20 finalized events and retained one or two nodes after each
advancement. A separate 720-block retention replay with 1,023-validator, 600-slot
state shapes retained at most four nodes and measured 668,896 inline/vector bytes
at peak (excluding allocator/ForkTree metadata). That replay uses a test header
verifier and repeated authority keys: it is storage evidence, not a live network
run at full protocol parameters. Full-parameter live-network acceptance remains
an explicit validation limitation.
