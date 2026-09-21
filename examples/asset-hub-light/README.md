# asset-hub-light

The smallest useful smoldot setup: a Node.js light client following Polkadot Asset Hub — or the
Polkadot relay chain on its own — pinned to one validator and one Asset Hub collator of your
choosing, which saves its databases to disk so that restarts skip most of the warp sync, and can
run several independent clients in one process.

## Running

The example imports the locally built client from `../../wasm-node/javascript/dist/`, so build
it once first:

```sh
cd ../../wasm-node/javascript && npm install && npm run build
```

Then:

```sh
node index.mjs
```

Ctrl+C saves the databases and exits. There are no npm dependencies — the chain specs come from
`demo-chain-specs/` in this repository.

With a `nodes.json` next to it, the client talks only to the nodes listed there (see "Pinning to
two nodes"); without one, or with `SMOLDOT_UNPINNED=1`, it roams the public network like any other
light client. `SMOLDOT_NODES=/path/to/file.json` pins it to a different set.

Each block is reported as one line, `<kind> #<number>  <time this instance saw it>  <state root>`.
`SMOLDOT_REPORT` picks the kind:

| `SMOLDOT_REPORT` | Prints | Source |
|---|---|---|
| `finalized` (default) | each block as it becomes finalized | `chain_subscribeFinalizedHeads` |
| `imported` | each block header as it is received and verified, forks included | `chain_subscribeAllHeads` |
| `both` | both, interleaved, padded to the same width | |

Alongside the block lines, the client reports its lifecycle whenever it changes —
`lifecycle: connecting, 0 peers`, `lifecycle: syncing #33027236 -> #33051363, 1 peer`,
`lifecycle: ready, 1 peer` — using smoldot's `lifecycle_unstable_follow`. The peer count is the
number of nodes actually serving the chain (an open block-announces substream), and smoldot's own
watchdog verdict is appended when it trips: `STALLED: no connected peer for 30s` means the node
accepted the connection but never opened (or dropped) the block-announces substream — typically
because its light-peer slots are full — while discovery traffic may well continue. This is the
line to look at when an instance "never follows". `lifecycle_unstable_follow` only exists in Wasm
built from September 2026 or later; with an older build (the client then announces itself as
smoldot v3.1.x in the logs) the same information comes from `system_health` polled every 10 s,
printed as `lifecycle (system_health): 0 peers, syncing`, with the 30-s no-peer verdict computed
by the example.

The time is the wall clock of *this* instance, not the block's own timestamp — a header carries
none. Comparing lines across instances shows where a delay comes from: a block **imported** late
means its announcement reached that instance late; a block imported on time but **finalized** late
means the GRANDPA commit did. The "`<chain> is following the chain after …`" line, which
`run-instances.sh` waits for, is printed on the first block of whichever kind is enabled, so every
mode works with it.

### Relay chain only

`SMOLDOT_RELAY_ONLY=1` doesn't add the parachain at all: the client follows Polkadot itself and
the lines above report Polkadot's blocks (`#3302…`, one every 6 s, plus the occasional fork under
`imported`). Only the relay database is saved, and only the `polkadot` entry of the node file is
used — an `asset-hub-polkadot` entry is ignored rather than rejected, so the same `nodes.json`
serves both modes. Measured: following after 1.4 s from a warm database, 217 MiB resident versus
~304 MiB with the parachain.

### Several clients in one process

`SMOLDOT_CLIENTS=3` runs three light clients in a single Node.js process. Each is a complete,
independent smoldot client — its own Wasm instance, connections and therefore peer identity,
database directory and worker thread — so to the pinned nodes they are three light clients, not
one. What they share is the Node.js runtime and the compiled Wasm module, which is what one
process per client pays for every time.

Measured resident memory, 140 s into a run against the same nodes:

| | RSS | per client |
|---|---|---|
| 1 client per process | 304 MiB | 304 MiB |
| 3 clients in one process | 538 MiB | 179 MiB |

Three separate processes would have been ~912 MiB, so the saving is about 40 %; each additional
client costs ~117 MiB, essentially its Wasm memory plus a worker isolate. The process prints
`memory: rss … MiB for N clients` every 30 s so you can see the number for your own setup.

With more than one client, every line is prefixed with the client's index in the same `[n] `
style `run-instances.sh` uses (`[2] finalized #…`), and databases move to `<db dir>/client-<n>/`.
A client directory that has no database yet falls back to the top-level files, so a database
seeded once — by the launcher, or by a single-client run — warms every client; each then saves
into its own directory. Each client's Wasm runs on its own worker thread (`worker.mjs`), so
their `cpuRateLimit`s don't compete for one event loop; connections and logging stay on the main
thread.

## Why the relay chain is there

Asset Hub is a parachain. `addChain` rejects its spec with `NoRelayChainFound`
(`light-base/src/lib.rs:560`) unless a matching relay chain is passed in `potentialRelayChains`,
because a parachain has no finality of its own — it follows the relay chain's.

Almost none of the cost is Asset Hub itself. Its chain spec is 2.9 KB, just bootnodes and a
`stateRootHash`. All the weight is `polkadot.json` (268 KB) and the warp sync from its
checkpoint.

## What the database gives you

`chainHead_unstable_finalizedDatabase` serializes, per chain: the finalized chain information
(finalized block plus GRANDPA authority set), the list of known peers, and the cached `:code`
runtime blob. Feeding it back through `databaseContent` on the next run means warp sync resumes
from the last finalized block rather than from the chain spec's checkpoint, and the client
starts with a peer list instead of only the bootnodes.

This matters more than it might seem: the checkpoint baked into `demo-chain-specs/polkadot.json`
is block 29,378,183, from around February 2026. Every start without a database pays for the gap
between that block and the current head.

### Which database gets loaded, and which gets saved

A database carries no identity — only chain information, a peer list and the runtime code — so
any client's database is as good as any other's, and the only thing that distinguishes them is
age. Each client therefore loads the **newest usable** database it can find: its own directory,
the other `client-<n>/` directories under the same database directory, that directory itself,
the seed (`SMOLDOT_SEED_DB`, default `.db`, the same variable `run-instances.sh` uses), and every
`.db*` directory next to the example — which is where the launcher keeps its per-instance
databases, so a run of 2 instances benefits from what a run of 100 saved an hour ago, and a
single-client run picks up what a multi-client run left in `client-<n>/`. Setting
`SMOLDOT_SEED_DB` to the empty string confines the search to the client's own directory. It
always saves into its own directory. When the choice isn't simply its own file, it says so:

```
polkadot database: using .db_2/client-1/polkadot.json (25 min old); skipped .db_2/polkadot.json (no runtime code)
```

This is what stops a per-instance database from going stale forever: an instance that never
manages to follow the chain never re-saves its own database, and the older that file gets, the
longer a single pruned validator takes to bring it up — a 40-hour-old one was still not following
after 34 s while a fresh one takes 4 s.

"Usable" means the file contains the runtime code. smoldot serializes a database **without** it
when a save lands while it has no known runtime — a ~45 s window after a large finality jump
(see "Running several instances at once"). Such a file is worse than none: the next start has to
fetch the runtime at the database's finalized block, which a pruned node can't serve once that
block has aged out of its state history, and the client stalls without a warning. Across your
runs 37 instances saved one at least once. The example now refuses to write such a database
(`not saving polkadot database: smoldot has no known runtime right now …`) and never loads one.

Two details worth knowing:

- The relay chain keeps JSON-RPC **enabled** here. `disableJsonRpc: true` would save a little,
  but `chainHead_unstable_finalizedDatabase` is an ordinary JSON-RPC function, and the relay
  chain's database is the valuable one. It is configured with `jsonRpcMaxSubscriptions: 0`
  instead, since nothing ever subscribes to it.
- On a parachain, `chainHead_unstable_finalizedDatabase` **does not answer** until the chain has
  a finalized runtime — that is, not until the initial sync finishes. Measured here: the relay
  chain answers in 0.2 s from a cold start, Asset Hub had not answered after 110 s of syncing.
  So saving is gated on the chain actually following, with a 15 s deadline as a backstop; without
  that, a Ctrl+C during warp sync hangs instead of exiting.
- A database is **trusted input**. Smoldot applies its content without checking it against the
  chain spec, so a tampered file is a security issue, not just a corrupt cache. Reload only
  databases this process wrote, from a directory nothing else can write to.

Set `SMOLDOT_DB_DIR` to change where they are stored (default `.db/`, git-ignored).

## Transports

Under Node.js the client speaks raw TCP, WebSocket, secure WebSocket and WebRTC, and all four are
enabled by default — every `forbid*` option in `ClientOptions` defaults to `false`. Both chain
specs carry a mixture (`polkadot.json`: 36 `/tcp/`, 6 `/ws/`, 17 `/wss/`), so TCP is already in
use without any configuration.

`SMOLDOT_TCP_ONLY=1 node index.mjs` forbids everything but TCP. Measured cold start that way:
34.9 s, versus ~48 s with all transports available.

This only applies outside the browser. A web page can reach `/ws/`, `/wss/` and WebRTC addresses
but never raw TCP, which is why `forbidTcp` exists in the first place — it lets a Node process
reproduce what a browser would actually be able to dial.

## Roughly what to expect

Measured against the bundled chain specs, over several runs:

| | |
|---|---|
| Time to the first Asset Hub head, unpinned, no database | 35–48 s |
| Time to the first Asset Hub head, unpinned, warm database | 4–27 s |
| Pinned to three validators + one collator, no database | ~56 s |
| Pinned to one validator + one collator, database up to 5 h old | 9–20 s, one run >70 s |
| Pinned to one validator + one collator, no database | does not complete (see below) |
| Steady-state memory | ~35 MiB |
| Steady-state bandwidth | 3–7 kiB/s down, ~400 B/s up |
| Warp-sync burst | ~1 MiB/s for a few seconds |
| Database size on disk | 2.3 MiB relay, 3.2 MiB Asset Hub |

Both figures vary a lot between runs — which peers answer first dominates everything else. The
fast warm starts come from the database's peer list as much as from its checkpoint: the client
begins with known-good addresses instead of working through the bootnodes.

Smoldot runs on the main thread here — `portToWorker` is left unset, which is what keeps this to
a single file. `cpuRateLimit: 0.5` bounds what that costs. Pass a `MessagePort` and run
`smoldot/worker` in a `node:worker_threads` worker if the main thread needs to stay responsive;
`wasm-node/javascript/demo/demo.mjs` shows that arrangement.

## Pinning to two nodes

`nodes.json` maps each chain's `id` to the only node(s) the client may talk to. Which nodes those
are is up to whoever runs this, so the file is git-ignored; start from the template:

```sh
cp nodes.example.json nodes.json
```

```json
{
  "polkadot": "/ip4/<validator ip>/tcp/30333/p2p/<validator peer id>",
  "asset-hub-polkadot": "/dns/<collator host>/tcp/443/wss/p2p/<collator peer id>"
}
```

An address is `/ip4`, `/ip6`, `/dns`, `/dns4` or `/dns6`, then `/tcp/<port>`, then `/ws` or
`/wss` for a node reached over WebSocket, then `/p2p/<peer id>`. A value may also be an array, to
pin a chain to several nodes at once.

If all you have is a node's address, its peer id can be read off the wire: point smoldot at the
address with a deliberately wrong `/p2p/` and it logs the real one at debug level as
`handshake-finished-peer-id-mismatch; … actual_peer_id=…`.

### Why two mechanisms

Setting `bootNodes` alone is not a restriction. It only decides who is contacted first: Kademlia
discovery (`light-base/src/network_service.rs:2297`) keeps surfacing other nodes for as long as
the client runs, they all become candidates for the four out-slots, and bootnodes lose their
slot preference the moment the chain first connects (`network_service.rs:1317`). There is no
reserved-peer mode; `system_addReservedPeer` is an unimplemented stub.

So the example also passes a `connectionFilter` to `smoldot.start`. This is a `ClientOptions`
hook added in this tree: it is consulted for every outgoing dial, at the single point where
connections are opened (`wasm-node/javascript/src/internals/client.ts`), so it behaves the same
on every platform and also when smoldot runs in a worker. A refused dial opens no socket —
smoldot is simply told the connection was reset, bans that peer for a couple of seconds and moves
on. Discovery therefore still runs, but every node it finds is refused before any network
activity; the client prints `pinning: refused N dials to M other addresses` every 30 s as
evidence.

The filter keys on `host:port`. The peer id is not available at dial time, but that is not a
gap: smoldot verifies it during the handshake against the `/p2p/` in `bootNodes`, so a node
answering at the right address with the wrong identity is dropped.

### First run: bootstrap a database

A single validator cannot get the relay chain through a *cold* warp sync, and the reason shapes
how to run this.

Before warp sync completes, smoldot's runtime service fetches `:code` at the chain spec's
checkpoint block (#29,378,183 here, months old) so that it has a runtime to work with. A
validator runs with `--state-pruning 256` and no longer has that state, so it answers
`RemoteCouldntAnswer`. Smoldot treats that as misbehaviour and bans the peer for 10 s
(`slot-unassigned; … user_reason=storage-request-failed`), which drops the connection and, with
it, the warp-sync request in flight. With one peer there is nobody to continue with, so the
cycle repeats: in a 150 s cold run, 138 fragments were verified and then the same request was
restarted seven times from the same hash, never finishing. On the public network this goes
unnoticed — a banned peer is simply replaced by another.

A saved database changes the picture completely. It carries the runtime code and a recent
finalized block, so nothing has to be fetched at an old block, and warp sync starts a handful of
fragments from the head. Measured: a single validator with a saved database was following Asset
Hub after **8.6 s** and **19.7 s** in two runs, with zero `storage-request-failed` bans, and
three parallel instances seeded from a five-hour-old database were all following after 9.0 s; a third
run had a healthy relay connection (blocks fetched, runtime compiled, GRANDPA finality advancing)
but no Asset Hub head yet when it was stopped at 70 s. With one peer, finality advances only as
fast as that node's GRANDPA messages arrive, so the first head is less predictable than on the
public network.

So the first run needs a database, and `nodes-bootstrap.json` provides one without going out to
the public network — it pins the relay chain to several validators (three were enough), so the
bans rotate and warp sync gets through. It is git-ignored too; `nodes-bootstrap.example.json` is
its template:

```sh
# Once. Ctrl+C after the first "saved database" lines, about a minute in.
SMOLDOT_NODES=nodes-bootstrap.json node index.mjs

# From then on the single-node pin runs off the saved database.
node index.mjs
```

Measured cold start with the three validators: following after **56 s**. `SMOLDOT_UNPINNED=1`
works for the bootstrap run too, but then the database's peer list is the public network's, and
every one of those peers is refused again on later runs — harmless, but it shows in the counter
(250 refusals to 57 addresses in one run, versus 20 to 4 after a pinned bootstrap).

The example prints a warning when it is about to start the relay chain cold on a single node.

### What to expect

The client has exactly one peer per chain, so everything — warp sync, block announces, storage
proofs — comes from that node. If it is down, or refuses light clients (`--in-peers-light 0`),
the chain simply never syncs; there is no fallback by design.

The same goes for smoldot's other bans. It bans a peer for 40 s when it sends a GRANDPA
justification for a block smoldot doesn't have yet (`user_reason=bad-justification`); this was
seen against one of the validators shortly after connecting, while its view of the chain was
ahead of the warp sync. On the public network another peer takes over; here the relay chain goes
quiet for 40 s and then reconnects to the same node.

### Connection diagnostics

By default the example prints a short account of what happens at the connection level, which is
what tells a chain that has no peer apart from one that has a peer serving it and is stuck
anyway:

```
net: connected to 12D3KooWAbCd…WxYz1 at /ip4/192.0.2.1/tcp/30333, presenting 12D3KooWCgkq…dQ5Q4
net: polkadot: 12D3KooWAbCd…WxYz1 is now serving the chain, at #33095682
net: dropped 12D3KooWAbCd…WxYz1 from polkadot, banned 40s -- this client banned it: bad-justification
peers: polkadot 1 peer (12D3KooWAbCd…WxYz1 authority #33095682), asset-hub-polkadot 0 peers
```

Three things are worth knowing about those lines.

The `presenting …` half of a connection line is **smoldot's own peer id on that connection**, and
it is different every time: there is one freshly generated Noise key per dial, so there is no
such thing as this client's peer id, and no JSON-RPC method returns one (`system_localPeerId` is
not implemented). This log is the only place it is observable, which matters when correlating
against a validator's own logs.

A disconnect line says whether the connection had been established or died during the handshake,
and nothing more: smoldot records neither a reason nor which side closed it. The cause, when
there is one, is on the `dropped …` line that follows — and in particular `this client banned
it: <reason>`, which is the case where *this* client's sync or runtime service asked for the ban.

`peers:` counts peers with an open block-announces substream per chain, not open connections, and
it covers the relay chain too — including when the parachain is the chain being reported on and
the relay chain is otherwise entirely silent, despite being the chain that has to finalize first.

`SMOLDOT_NET_LOG=0` turns all of this off. It is not free: smoldot has to run at debug level for
these events to reach the example at all, and the formatting it then does comes out of each
client's `cpuRateLimit` budget. The events this example does not use are dropped rather than
printed.

`SMOLDOT_LOG_LEVEL=4` shows all of the above. To confirm that only the pinned addresses are ever
reached, look at `handshake-finished; remote_addr=…` lines — a handshake needs a live socket.
`connection-started` is *not* evidence: smoldot logs it when it asks the platform for a
connection, which is before the filter refuses it, so refused addresses show up there too. In
every run above, all handshakes were with pinned addresses.

## Reading contract storage on a period

Following a chain asks the node it is pinned to for almost nothing: block announcements go out to
everyone anyway, and a light client verifies them on its own. What costs a node real CPU is being
asked for *proofs*, and the most expensive proof a light client asks for is a contract read —
contract storage lives in a child trie, so each read becomes a `RemoteReadChildRequest` the node
has to walk the trie for and build a Merkle proof from.

With `SMOLDOT_QUERY_INTERVAL_MS` this example generates that load: every client reads a
`pallet-revive` contract's storage once per period, so a fleet started by `run-instances.sh`
becomes a load generator rather than a set of passive followers.

The shape comes from [dotli](https://github.com/paritytech/dotli-community), which resolves `.dot`
names by reading the dotNS resolver contract's storage rather than executing it. One resolution is:

1. one **main-trie** read of `Revive::AccountInfoOf[address]`, to learn the contract's trie id,
2. one **child-trie** read of that trie, for the slots the name maps to.

Step 1 is not redundant. The trie id is what names the child trie, and dotli deliberately re-reads
it every time instead of caching it, because a redeployed contract would otherwise be served out
of a trie that no longer exists. Keeping it here keeps the request mix honest: a third of a
resolution's round trips are that lookup.

dotNS itself is only deployed on Paseo, so what is read here is not a name — it is whichever
contract on Polkadot Asset Hub has the most populated child trie. The read costs the node the
same either way, which is the point.

### Choosing the contract

`discover-revive-contracts.mjs` finds it and writes `revive-queries.json`:

```sh
node discover-revive-contracts.mjs
```

```
Polkadot Asset Hub via https://polkadot-asset-hub-rpc.polkadot.io, at finalized 0x3415c1c5…
  AccountInfoOf: present
  ContractInfoOf: empty

Ranking Revive::AccountInfoOf by stored item count...
  430 accounts
  430/430 decoded, 380 contracts

380 contract(s) among 430 revive account(s). Top 15:

    items      bytes  address
     4370     279680  0xc2eb191fb75246667226a5d5db9d821f95a5f793
     4359     278976  0x590ebe304e0c7672e2abf3161177d2b94a2ac3fc
     3803     243392  0xa85af867b5f573176f49f0d6a827f61a5cee4e37
...
```

It talks to a full node over HTTP JSON-RPC rather than through smoldot, because neither half of
the job is something a light client can do: ranking means reading every entry of
`Revive::AccountInfoOf`, and picking keys means *enumerating* a child trie, which
`chainHead_v1_storage` cannot do at all — child-trie queries there are restricted to `value` and
`hash`. It is a one-off that takes about two seconds; the load it makes is not the load being
measured.

`AccountInfoOf` is a `StorageMap<_, Identity, H160, AccountInfo<T>>`, so its values *are*
`ContractInfo`, and `ContractInfo` carries `storage_items`. The ranking is therefore read straight
off the chain rather than inferred. Which name the map has is asked rather than assumed: the
script probes `AccountInfoOf` and falls back to the older `ContractInfoOf`, and reports which one
answered.

The keys are sampled at twelve evenly spaced points of the 256-bit key space rather than taken
from one page of `childstate_getKeysPaged`, and that is not a detail. Contract storage keys are
`blake2_256` of an EVM slot, so they are uniform hashes; the *first* twelve in lexicographic
order all begin with the same nibble, share their whole path from the root of a radix-16 trie,
and are covered by a proof barely larger than a single key's. Measured on this contract through
the light client, twelve adjacent keys produce a **4.5 kiB** child proof where twelve spread ones
produce **14.0 kiB** — the same request count, 3.1x the bytes and the trie walking behind them.
A read set off one page would understate the node's work by about three times, and it would not
resemble a resolution either: those read scattered slots, a content hash under one namehash and
manifest records under others, never neighbours.

The script prints the spread it achieved as `d1=12 d2=12 d3=12` — the number of distinct nibble
prefixes at each depth. `d1` equal to the key count means every key diverges at the root, which
is the property being bought; `d1=1` would mean they all came off one page.

Nothing is derived at run time. A contract's child-trie keys are `blake2_256` of an EVM storage
slot, and Node has neither blake2\_256 nor keccak256 nor the twox128 that the main-trie prefix
needs — so the keys are precomputed into the config. That is what lets this example keep having no
npm dependencies, and it keeps hashing out of a loop whose job is to measure a node rather than a
CPU.

### Running it

```sh
node index.mjs                                    # every 30 s, the default
SMOLDOT_QUERY_INTERVAL_MS=5000 node index.mjs     # every 5 s
SMOLDOT_QUERY_INTERVAL_MS=0 node index.mjs        # off: follow the chain and nothing else
```

| Variable | Default | Meaning |
|---|---|---|
| `SMOLDOT_QUERY_INTERVAL_MS` | `30000` | Period per client; `0` turns the reads off entirely |
| `SMOLDOT_QUERY_JITTER` | on | Spread the ticks out; `0` makes every client tick on the same beat |
| `SMOLDOT_QUERY_KEYS` | all | How many of the configured keys to read per set |
| `SMOLDOT_QUERY_BATCH` | `batched` | `batched` sends one request for all keys, `serial` one per key |
| `SMOLDOT_QUERY_CONFIG` | `./revive-queries.json` | A different config file |

Each read set is one line, and the periodic report adds the window's aggregate next to the
`peers:` and `memory:` lines:

```
revive: reading 12 keys of 0xc2eb191f…5a5f793 every 30s (batched, jittered)
revive: read set ok in 412ms — trie id 118ms, 12 keys in 1 child-trie call, 12 present / 0 absent
revive: 58 read sets, 0 failures (0.0%), p50 380ms p99 1240ms
```

The aggregate gives the failure rate and the latency percentiles directly, so a run can be judged
without post-processing the log.

`SMOLDOT_QUERY_KEYS` is how the two ends of a resolver's cache are compared: the full key set
stands in for a cold resolution, a handful for a warm one that only revalidates.

### Jitter, and why it is on

Instances started together — which is how `run-instances.sh` starts them — would otherwise tick on
the same beat and arrive at the node as a burst once per period rather than as a steady rate.
That measures this client's synchronisation, not the node's behaviour under load. Jitter spreads
the first tick over a whole period and every later one over ±50 %. Turning it off with
`SMOLDOT_QUERY_JITTER=0` is a way to build a stampede *deliberately*, when that is what is being
tested.

### Batched or serial

Every item of one `chainHead_v1_storage` call is served by a single proof request, so twelve keys
in one call is one `RemoteReadChildRequest` where twelve calls are twelve. The node's work differs
by much more than the request count — one proof shares its trie nodes, twelve repeat them — which
is why `SMOLDOT_QUERY_BATCH` exists rather than the example simply picking one.

Two constraints are worth knowing before changing the read set. Child-trie queries support only
`value` and `hash`, not `descendantsValues` or `closestDescendantMerkleValue`: those resolve
against a trie root that, for a child trie, is not known until its proof arrives. And a follow
subscription has 32 operation slots, one per *item*, so a read set of more than 32 keys cannot be
sent as a single call whatever else is in flight.

### Reading at the finalized block

Every read set pins one finalized block hash and uses it for all of its calls. Reading at the best
block would be faster by a block or two and wrong: a best block can be forked away underneath a
multi-call read, leaving half the set read from a chain that no longer exists. Blocks are unpinned
as they are superseded, but never while a read set still holds one — an unpinned block makes every
read against it fail with `unknown or unpinned block`.

### In the container

`revive-reads.mjs` and `revive-queries.json` are baked into the image next to `index.mjs`, so a
container needs no configuration to read contract storage — only the period:

```sh
docker run --rm -e SMOLDOT_QUERY_INTERVAL_MS=30000 <image>
docker run --rm <image>                              # same thing: 30 s is the default
docker run --rm -e SMOLDOT_QUERY_INTERVAL_MS=0 <image>   # off, follow the chain only
```

In a deployment, setting `SMOLDOT_QUERY_INTERVAL_MS` to `"0"` keeps a newly deployed image from
generating load on its own until the reads are switched on deliberately.

The arrival rate is `replicas × SMOLDOT_INSTANCES × SMOLDOT_CLIENTS × 60000 / interval` read sets
a minute. Raise it with replicas rather than by shortening the period: a client runs one read set
at a time and drops a tick that arrives while the previous one is still going, so a period shorter
than the node's response time measures this client's queueing instead of the node.

`bootstrap-db.sh` forces the reads off regardless of the environment. That run exists to produce
a database, and asking the node for storage proofs while doing it is load nothing measures.

## Running several instances at once

`run-instances.sh` starts a configurable number of `index.mjs` processes, each with its own
database directory, and starts them **one at a time**: the next one is spawned only once the
previous one has printed a finalized Asset Hub head, which is the point at which it is following
the chain rather than still warp-syncing.

```sh
./run-instances.sh 3
```

Output goes to the terminal and to `logs/` at the same time: `logs/instance-N.log` holds one
instance's raw output, and `logs/all.log` holds everything the terminal showed, prefixes and all.
The script's own lines are framed by `---`:

```
--- instance 1/3: starting with .db_1, database seeded from .db ---
[1] polkadot: pinned to /ip4/192.0.2.1/tcp/30333/p2p/12D3KooWAbCd…
[1] Polkadot Asset Hub is following the chain after 4.7s.
--- instance 1/3: following the chain after 5s ---
--- instance 2/3: starting with .db_2, database seeded from .db ---
...
--- all 3 instances are following the chain; Ctrl+C to stop them ---
```

Ctrl+C sends one SIGINT to each instance so that they all save their databases, then waits up to
30 s for them to exit. Each instance is started under `setsid`, in its own session, precisely so
that the terminal's Ctrl+C reaches the script only — otherwise each would get the terminal's
SIGINT *and* the script's, and `index.mjs` treats a second SIGINT as "give up on saving". Because
a script runs without job control, the instance is not a process group leader and `setsid` execs
in place rather than forking, which is what keeps `$!` pointing at node itself.

Do **not** pipe the script through `tee` yourself. Ctrl+C reaches every process in the terminal's
foreground process group, `tee` dies on SIGINT immediately, and the script's first shutdown message
then hits a closed pipe — SIGPIPE kills it before it can tell a single instance to save, leaving
orphaned light clients behind. Measured: with `| tee`, the shutdown trap produced no output at all
and all three instances survived the script. `logs/all.log` exists so that you do not need to: it
is written by a `tee` that ignores SIGINT, which is what lets the shutdown outlive the Ctrl+C.

### Why one at a time

A fresh `.db_N` would mean a cold warp sync, and pinned to a single validator that does not
complete at all (see "First run" above), so the script copies `SMOLDOT_SEED_DB` (default `.db`)
into any instance directory that does not exist yet. Waiting for each instance to actually follow
the chain before starting the next then keeps N warp syncs off the wire at the same time, and
makes a failure attributable to one instance instead of showing up as a slow pile-up.

If an instance exits, or has not reached a finalized head within `SMOLDOT_READY_TIMEOUT` seconds
(default 180), it is started again — a stuck one is stopped first — up to `SMOLDOT_START_RETRIES`
times (default 3, so four attempts in all). Each attempt's output is appended to the same
`logs/instance-N.log`, separated by an `--- attempt N/M ---` line, and only the current attempt's
output counts as progress. Once the retries are exhausted the script stops what it has already
started and exits non-zero rather than starting the rest.

### What the instances share

Nothing but the pinned nodes. Each is a separate process with its own Wasm client and its own
database directory, and — worth knowing given the pinning — they do not share a network identity
either: smoldot generates a fresh key, and therefore a fresh `PeerId`, for **every connection**
it opens (`light-base/src/network_service.rs`), which is also why `system_localPeerId` is
unimplemented. So the pinned node sees every connection as a different light client, whether it
came from one instance or ten, and N instances occupy N times the light-client slots on it
(`--in-peers-light`). A handful is fine; a few dozen against one validator is not.

| Environment variable | Default | |
|---|---|---|
| `SMOLDOT_INSTANCES` | `2` | Instance count, when not given as the first argument |
| `SMOLDOT_DB_PREFIX` | `.db_` | Gives `.db_1`, `.db_2`, … |
| `SMOLDOT_SEED_DB` | `.db` | Copied into an instance directory that does not exist yet; set empty to always start cold |
| `SMOLDOT_READY_TIMEOUT` | `180` | Seconds to wait for an instance to follow the chain |
| `SMOLDOT_START_RETRIES` | `3` | Times an instance that exits or times out is started again before the script gives up |
| `SMOLDOT_LOG_DIR` | `logs/` | One file per instance, plus `all.log` with everything the terminal showed |

`SMOLDOT_NODES`, `SMOLDOT_UNPINNED`, `SMOLDOT_TCP_ONLY`, `SMOLDOT_LOG_LEVEL`, `SMOLDOT_NET_LOG`,
`SMOLDOT_REPORT`, `SMOLDOT_RELAY_ONLY` and `SMOLDOT_CLIENTS` are passed through to every instance. `SMOLDOT_DB_DIR`
is the exception: it is set per instance, and any inherited value is ignored. `SMOLDOT_REPORT=both`
is the setting for telling announcement latency from finality latency across instances.

With `SMOLDOT_CLIENTS=5`, `./run-instances.sh 10` gives 50 light clients for the memory of ten
processes; the launcher considers an instance started as soon as its first client follows the
chain, and each instance's log carries the `[n] ` client prefixes.
