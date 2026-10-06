# JAM light client — local demo and manual QA walkthrough

The demo is a PolkaJam network that zombienet starts and a small harness that
serves this page, with the embedded smoldot browser build, against it. The
harness starts no network itself. There are two ways to get one, each in two
terminals, from the smoldot root:

```sh
# Route 1: zombie-cli and the checked-in TOML.
# terminal 1
ZOMBIE_CLI=<zombienet-sdk>/target/release/zombie-cli \
POLKAJAM_BIN_DIR=<polkajam>/target/release just zombie-jam
# terminal 2, once terminal 1 prints "network is up"
just demo-jam-attach
```

```sh
# Route 2: the DEV_MODE of the e2e-tests JAM scenarios (zombienet-sdk).
# terminal 1
POLKAJAM_BIN_DIR=<polkajam>/target/release just demo-jam-dev
# terminal 2: the command terminal 1 prints, for example
just demo-jam-attach '/tmp/zombienet-<pid>/jam_spec.json' <rpc port>
```

The harness prints one URL. Open it, press **Start**, and watch a JAM chain
arrive in the browser. Ctrl-C in terminal 2 stops only the server; Ctrl-C in
terminal 1 stops the network.

**Trusted starting point; verified live finality.** The spec supplies a trusted
anchor header and its post-state. `initialized` describes that anchor; later
`finalized` events follow verified GRANDPA proofs and ordered authority
transitions. Both routes start every PolkaJam node in GRANDPA mode, and the page
follows with `[false]` (`withRuntime: false`), without runtime execution.
Finalization prunes old ancestors and discarded forks. If proofs cannot be
obtained, the client keeps its last verified head and eventually reaches its
resource bound. The automated scenarios live in `e2e-tests` (see
`e2e-tests/docs/jam-scenarios.md`): `jam_follow` runs Dummy finality,
`jam_finality` the GRANDPA acceptance and proof capture.

## Prerequisites

- **A browser bundle.** `npm run demo:jam` (what `just demo-jam-attach` runs)
  checks for `dist/mjs/index-browser.js` and refuses to start without it.
  `npm run demo:jam:rebuild` rebuilds the WASM in debug mode, clears `dist`,
  compiles the JavaScript, and starts the harness only if the build succeeds
  (set `JAM_SPEC_PATH` and `JAM_RPC_PORT` for it as `demo-jam-attach` does).
  Building requires JavaScript dependencies (`npm ci`) and a Rust toolchain
  with the `wasm32v1-none` or `wasm32-unknown-unknown` target. For a min-size
  release bundle, use `npm run build`. After editing Rust or JavaScript, stop
  the harness, rebuild, and reload the page.
- **The `polkajam` executable, already built**, from the PolkaJam branch
  `skunert/polkajam-light-client` at `3ccb03b7dc5ca54b16de81db7fdf7076de083ad0`.
  Both routes take it from `POLKAJAM_BIN_DIR` if set, otherwise from `PATH`.
  A `polkajam` older than this pin signs GRANDPA votes without the posterior
  state root: the client logs `jam-finality-rejected` and `jam-warp-rejected`
  with `Decode(LengthLimit)`, reconnects, and never shows `jam-warp-applied` or
  a finalized update. Build once in the PolkaJam checkout:

  ```sh
  SKIP_PVM_BUILDS=1 CARGO_PROFILE_RELEASE_DEBUG=line-tables-only RUSTC_BOOTSTRAP=1 \
    RUSTFLAGS='-Zcrate-attr=feature(array_windows,substr_range)' \
    cargo build --locked --release -p polkajam
  ```

  `SKIP_PVM_BUILDS=1` stops PolkaJam's build script from building the guest
  blob, so stable Rust 1.93.0 suffices; on a Nix host add `NIX_ENFORCE_PURITY=0`.
- **zombienet-sdk** from its branch `skunert/polkajam-light-client`: route 1
  needs its `zombie-cli` (`cargo build --release -p zombie-cli`, then
  `ZOMBIE_CLI`, else `zombie-cli` from `PATH`); route 2 builds `e2e-tests`,
  which takes the SDK from that checkout by path. Only that branch writes each
  validator's P-256 id into the genesis `C(8)` and every validator into the
  spec's `bootnodes` as `<ed25519>+<p256>@127.0.0.1:<port>`, and only that
  PolkaJam parses the combined form.
- Node 22 or newer. The demo adds no npm dependency.

`just zombie-jam` runs `zombie-cli spawn --provider native --dir /tmp/jam-zombie
--node-verifier none test/jam/zombienet/tiny-grandpa.toml`: six GRANDPA
validators `jam0`..`jam5` on ports zombienet picks, and the ordinary node
`jam-or` with RPC on 19800. `just demo-jam-dev` runs
`DEV_MODE=1 cargo test --manifest-path e2e-tests/Cargo.toml --test jam_demo`,
which spawns the same topology through zombienet-sdk on free ports and prints
the harness command with its spec path and RPC port; `just demo-jam-dev
jam_follow` gives the Dummy network of the browser gate instead. Either way the
validator ports live in the generated spec, so nothing in this repository fixes
them.

`just demo-jam-attach` takes the spec path and the RPC port as arguments,
defaulting to `JAM_SPEC_PATH` and `JAM_RPC_PORT`, then to
`/tmp/jam-zombie/jam_spec.json` and 19800, which are route 1's. `JAM_HTTP_PORT`
(8080) moves this page.

## Browsers

- **Chrome / Chromium** — verified for this walkthrough. WebTransport with
  `serverCertificateHashes` reaches the loopback validators with no command-line flags
  when the page is served from `127.0.0.1`, as the harness does.
- **Firefox** — verified by earlier rounds against the C1 page; see the note at
  the end of this file and `notes/C3-M11c-manual_demo.md` in the planning
  repository for exactly what was driven here.
- **Safari** — untested; there is no Linux host for it.

Do not open the page as `file://`, do not put it behind a proxy or a hostname
other than loopback, and do not disable certificate checks: loopback is already
a secure context, which is exactly what WebTransport needs.

## What the harness serves

| Path | What it is |
|---|---|
| `/demo/jam.html` | this page |
| `/jam-demo/spec.json` | the attached network's spec (`JAM_SPEC_PATH`), unchanged, re-read from disk on every request |
| `/jam-demo/spec-wrong-authorities.json` | the same spec with a corrupted genesis authority set (step 10), built from it on every request by `corruptGenesisAuthorities` in `e2e-tests/shared/jam.js`, the builder the browser gate uses |
| `/jam-demo/control` | `POST {"action": "status" \| "kill-node0" \| "start-node0" \| "restart-node0"}`; the node actions answer `not managed by this harness in attach mode`, because the network belongs to zombienet. The page also posts `{"action": "peers", ...}` with its client's connected peers, which `status` returns as `browserPeers` and summarizes in `peersLine` |
| everything else | files under `wasm-node/javascript/` |

The server binds `127.0.0.1` only and rejects non-loopback peers and foreign
`Host` headers. There is no authentication beyond that, so do not expose it.

The page never writes a bootnode address itself: the spec zombienet generated
names every validator as a combined Ed25519 and P-256 bootnode, and its genesis
`C(8)` carries the same validators.

## Reading the live view

*Slot*, *epoch*, *marks* and *author index* are decoded in JavaScript from the
bytes `chainHead_v1_header` returned, **for display only**. They gate no control,
decide no correctness, and are not verification — verification happens in Rust
inside the client. A dash means "not known yet", never a guess, and bytes that do
not decode are reported as unreadable.

*Node's own best block* comes from the node's own JSON-RPC through the control
endpoint. It is the independent oracle — what the network really did — and
*Client vs node* compares it with what the client verified. That comparison is
the most useful check on this page: it catches a client that is happily
following nothing.

*Connected peers* lists the client's two connection slots: each slot's
address, where the candidate came from — the spec's `bootnodes` (`bootnode`),
the spec's genesis active set `C(8)` (`genesis`), or a verified read of the
current active set (`discovered`) — and whether it is dialing, connected (the UP0
handshake arrived) or disconnected. *Validator set (C(8))* says how often the
client has read the active set and what the last read cost. Both rows mirror
the client's own `jam-slot-assigned`, `jam-peer-connected`,
`jam-peer-disconnected` and `jam-pool-changed` log lines; the page decides
nothing; a disconnected slot shows its `reason` (see "Client events"). The
harness has no view of the browser's connections, so the page
reports the list to it, and the harness prints a `browser peers:` line whenever
it changes.

**Recent blocks** is an explorer-style list of the last **20** blocks the follow
subscription reported, newest first, with slot, epoch (`number + position`),
author index, marks, block hash, parent hash and age. Block and parent hashes are
the follow events' own values; the other columns come from that block's
`chainHead_v1_header` bytes through the same display-only decoder. Each block
costs exactly one header call, made as it arrives. A row whose header has not
come back, or did not decode, says so in its Marks column ("header pending",
"header not readable", "unpinned before its header was fetched") instead of
showing a number — the list never guesses. Older rows drop off the bottom; this
is a recent window, not a chain history.

**Finality** separates the client's finalized head from the node's own
`finalizedBlock` RPC report. The client starts at the trusted anchor, then shows
verified finality updates with hash, slot, count and age. The node can advance
independently; its report never advances the client head or marks a client block
finalized. The node best/finalized gap is measured in slots, not a block count.
RPC errors clear the node display instead of leaving a stale head visible.

The frontend handles `finalized` follow events: it records the last hash in `finalizedBlockHashes`, its decoded
slot if available, the update count and age. The recent-block table's
**Finality (client)** column marks exactly the hashes named by the event as
*Finalized* or *Pruned*. Other rows remain *Unfinalized*; neither slot ordering
nor a matching node report is evidence of client finality. Unfollow retains
the last observation and labels it; Stop and a new Start clear session data.

Reading that list is the quickest way to see a healthy chain: slots decreasing by
exactly one down the table, each row's Parent equal to the hash of the row below
it, the author index moving around the validator set, and an `epoch` mark on the
row whose epoch position is 0.

## Peers: bootnodes, genesis set, live set

The client puts every source into one candidate pool: the spec's bootnodes
first, then the genesis `C(8)` validators (a validator that is also a bootnode
is one candidate, the bootnode), replaced by the live `C(8)` after the first
verified finality advance. All of them are liveness sources only; whatever they
serve is verified the same way. A spec with neither a P-256 bootnode nor a
P-256 id in its genesis `C(8)` is refused at load with an error naming both.
To try a spec with fewer bootnodes, edit a copy's `bootnodes` and pass it:
`just demo-jam-attach /abs/path/spec.json <rpc port>`.

## Checklist

Each step says what to do, what you should see, and what a failure looks like.
The dev network runs 6-second slots and 12-slot epochs, so an epoch boundary
passes about every 72 seconds and you will see several in a normal session.

1. **Start.**
   *Do:* leave the spec URL at `/jam-demo/spec.json` and press **Start**.
   *See:* an `initialized` event, then a `newBlock` about every six seconds with
   a `bestBlockChanged` after it. Connection becomes *Following*, *Trusted
   anchor* shows the anchor hash, *Blocks since Start* climbs, and *Client vs
   node* settles on "in step: same slot and same block" or one slot either way.
   On a network older than one epoch (wait about 80 seconds before Start), the
   log shows `jam-warp-join-selected`, then `jam-warp-applied`. One `stop` and an
   automatic re-follow are expected: a second `initialized` moves *Trusted
   anchor (from the latest initialized)* from genesis to the peer's finalized
   head. *Re-anchored (warp)* shows count 1, the new hash and its decoded slot;
   blocks and verified `finalized` events then arrive from that anchor. The
   client and chain stay running throughout. Old unfinalized rows become
   *Superseded*, retaining the visible history without claiming finality.
   *Warp status* retains `jam-warp-applied`, the latest `jam-warp-rejected`
   with its step and error, or `jam-anchor-unserved`; the last means the
   configured peers could not serve the anchor. **Client events** shows each
   step of the join (`jam-warp-request-queued` to `jam-warp-applied`).
   *Failure:* `Failed to decode chain specification` (check that the spec matches
   the current client; run `npm run demo:jam:rebuild` and reload after source changes);
   Connection stuck at *Connecting (following, no block yet)* while the log
   repeats `jam-connect` / `jam-reconnect` (the client cannot reach the
   bootnodes); *Client vs node* drifting further behind with every poll.
   Three `stop` events within 30 seconds are an error: the log names the count
   and the page stops instead of retrying indefinitely.
   *Note:* every Start warps to the peer's finalized head and syncs the suffix
   on an aged network. Ascending catch-up verifies the remaining headers, with
   verified finality pruning the tree. The `jam_aged` scenario in `e2e-tests`
   checks exactly that join on a restored aged network.

2. **Slots advance.**
   *Do:* watch for half a minute.
   *See:* *Slot* increases by one about every 6 seconds and *Blocks since Start*
   increases by the same amount, so no gap is left behind. In **Recent blocks**
   the slots run consecutively down the table and each row's Parent is the hash
   of the row beneath it. *Last follow event* stays in single-digit seconds.
   *Failure:* the slot jumps forward by several while the block count does not
   (skipped blocks that never fill in), or *Last follow event* keeps growing past
   ~15 seconds while the node's own best block keeps moving.

3. **An epoch boundary.**
   *Do:* watch for up to ~80 seconds.
   *See:* the *Epoch* line's epoch number increments and its position wraps back
   to 0, and *Marks on this header* reads `epoch mark` for exactly that block.
   *Marks seen this session* keeps the slot it happened at, and the row stays
   visible in **Recent blocks** with `epoch` in its Marks column and position 0
   in its Epoch column — so you can confirm it after the fact instead of having
   to catch the six-second window.
   *Failure:* the epoch number never increments although slots advance, or a mark
   is reported somewhere other than position 0 of an epoch.

4. **Header, then Unpin.**
   *Do:* press **Header: latest new block**, then **Unpin: latest new block**.
   *See:* the header panel prints the block hash and the returned bytes as hex.
   After Unpin, **Header** and **Unpin** are unavailable for that block until the
   next block arrives; the printed header stays on screen as historical output,
   not as a currently pinned block.
   *Failure:* Header returns `null` or a non-hex value; the buttons stay enabled
   after Unpin; an error appears in the log panel and the session stops.

5. **Kill jam0: the client finds the other validators.**
   *Do:* wait until *Connected peers* lists two connected slots and note the
   address of one of them, `127.0.0.1:<port>`; jam0's port is in its line
   `For WebTransport, use …@…:<port>` in `<base dir>/jam0/jam0.log` (route 1:
   `/tmp/jam-zombie`). *Validator set (C(8))* reads `6 validator(s), …` after
   the first verified finality advance, usually within seconds of Start. Stop
   jam0 the way PolkaJam expects, with Ctrl-C's signal:
   `pkill -INT -f '<base dir>/jam0/cfg'`. The harness buttons answer an error
   by design.
   *See:* within a few seconds the slot that held jam0 reconnects to another
   validator, and *Connected peers* shows two entries, neither on jam0's port;
   the network line ends with the harness's own `browser peers: …` line.
   Blocks keep arriving, *Client vs node* stays in step, and verified
   `finalized` events continue. The browser console shows connection failures
   to jam0's address; that is the client honestly failing to reach a dead peer
   before moving on. Nothing about trust changed: every header, finality proof
   and state proof another validator serves is verified exactly as jam0's were.
   The client found these validators in the active set `C(8)`: first in the
   spec, then in the finalized state, read with a verified proof; each record
   carries the validator's address and its P-256 WebTransport identity.
   *Failure:* *Blocks since Start* freezing for more than about ten seconds
   after the kill; the same address in both slots; *Connected peers* claiming a
   connection the log never showed.

6. **Start jam0 again.**
   *Do:* start jam0 with the command zombienet spawned it with, on its own
   directory and database: the `🚀 jam0, spawning.... with command: polkajam …`
   line in terminal 1 (route 2 logs it at the start), run from `<base dir>/jam0`
   with `POLKAVM_BACKEND=interpreter` in its environment.
   *See:* blocks never stopped, so there is nothing to catch up. A slot holding
   a `genesis` or `discovered` peer returns to a bootnode only after that
   bootnode's backoff: a failed bootnode is retried after 30 seconds, then 60,
   120, 240 and at most every 300 seconds, and the log has
   `jam-slot-preempted`. The client prefers bootnodes, but it does not cut a
   working connection every few seconds to probe a dead one. With every
   validator a bootnode, as zombienet writes the spec, both slots usually stay
   on bootnodes throughout.
   *Failure:* jam0 dying again right after its start (planning
   `unrelated_bugs.md` PJ1, node dies on restart when a GRANDPA commit arrives
   early); or, with a spec naming jam0 as its only peer, no block within a
   minute of the start.

   Steps 5 and 6 run unattended, with jam0 as the client's only bootnode, as
   the `jam_discovery` scenario in `e2e-tests`; the kill and the start go
   through zombienet-sdk's node handle there.

7. **Unfollow, then Start again.**
   *Do:* press **Unfollow**, wait a few seconds, then **Stop** and **Start**.
   *See:* after Unfollow, Connection reads *Unfollowed (chain still running)* and
   no further follow events are appended, while the node's own best block keeps
   moving. A manual Unfollow is never automatically re-followed.
   Start re-subscribes and blocks flow again from a fresh
   `initialized`.
   *Failure:* follow events keep arriving after Unfollow; Start does nothing, or
   reports a pending-RPC error.

8. **Stop, including mid-startup.**
   *Do:* press **Stop** while following. Then press **Start** and press **Stop**
   again within a second, before the first block.
   *See:* both times the status settles on *Stopped*, Start becomes available
   again, and nothing is left running.
   *Failure:* the page hangs on *Stopping*, or Start stays disabled.

9. **Finality view.**
   *Do:* watch **Finality** across two epoch boundaries, then stop and start
   jam0 as in steps 5 and 6.
   *See:* the client finalized head advances, *Live finality updates* grows,
   and recent rows become *Finalized*. Epoch transitions are verified before
   later heads advance. After reconnecting, finality resumes without restarting
   the subscription. Unfollow labels the last observation; Stop clears it.
   *Failure:* finality remains at the anchor on the GRANDPA network; a node
   report changes client finality without a client event; or old data survives
   Stop/Start. A finality RPC error must leave the client's verified head intact.

10. **Wrong authority set.**
    *Do:* press **Stop**, set the spec URL to
    `/jam-demo/spec-wrong-authorities.json`, press **Start**, and wait
    ~45 seconds.
    *See:* *Trusted anchor* shows a **different** hash from step 1, and then
    nothing: no `newBlock` ever, *Blocks since Start* stays 0, and the **Log**
    panel shows `jam-warp-rejected` with a verification error, followed by
    `jam-reconnect` lines at a growing backoff as the client keeps treating the
    peer as faulty and retrying. *Warp status* shows the rejection, its step
    (`fragments`) and error, and counts the rejections; no warp is ever
    applied.
    *Failure:* any `newBlock`, or `jam-warp-applied` — either would mean the
    client joined a chain it cannot authenticate.

    *Why this fixture:* the served spec flips one byte of the first two
    validators' Ed25519 keys in the genesis header's epoch mark and in the
    matching records of the state items `C(4)` and `C(8)`, so every copy still
    decodes and the spec still loads. The client derives GRANDPA set 0 from
    that mark, so the first warp fragment's justification cannot be
    authenticated: the real validators are unknown authorities and the
    remaining four cannot reach the five-of-six quorum. The genesis hash
    changes as a side effect, which is what a network without GRANDPA (the
    `jam_follow` scenario, which runs Dummy finality) detects instead, as a
    `NoData` answer to the first block request for an unknown genesis.

    **What the client cannot detect.** A spec that differed *only* in its
    genesis hash would be followed quite happily. GRANDPA precommits sign
    `(round, set_id, vote)` and nothing chain-specific, and the headers between
    genesis and the first set change are never fetched — they may be pruned —
    so after a warp a client cannot tell apart two chains that share their
    genesis validators and their set sequence. Nothing in the WebTransport
    handshake states which chain the browser wants either: JAMNP-S puts the
    chain identity in the QUIC ALPN, `jamnp-s/<version>/<genesis-hash prefix>`,
    which the `h3` path this demo uses does not carry. Until that is fixed this
    step proves that the client checks the authority set, not that it checks
    the chain. The two upstream asks are U7 (chain identity over WebTransport)
    and U13 (chain-bound GRANDPA votes) in the planning repository's
    `followups.md`.

Afterwards press Ctrl-C in terminal 2: the harness stops its server and prints
"teardown complete; attach mode, the network was not ours and keeps running".
Ctrl-C in terminal 1 tears the network down.

## Client events

The **Client events** section shows the client's own debug log as events: one
row per event, newest first, with the time since Start, the connection slot,
the category and the fields. A request is one row from its start to its
outcome: it reads *pending* until the outcome line arrives, then the outcome
and the duration. Category toggles (peers, pool, blocks, justification, state,
warp, finality) and a text filter narrow the table; at most 1,000 events are
kept, the oldest go first, and the line above the table counts the dropped
ones. **Download events** saves the kept events, the spec's genesis hash
(BLAKE2b-256 of `genesis_header`, computed in the page), the run's start time
and the totals per category as JSON. The section keeps the last run's events
after Stop until the next Start. The raw lines stay in **Client logs**.

The events come from `light-base/src/sync_service/jam.rs`; `demo/jam-events.mjs`
parses them, and the live rows for peers, the validator set and *Warp status*
read the same parsed events. *Warp status* shows the latest applied join, the
latest rejection (with its step, error and how many rejections there were since
Start) or an unserved anchor.

### Grammar

```
jam-<area>-<what>[; key=value, key=value, ...]
```

- **Area and category.** The first word after `jam-` picks the category:
  `peer`, `slot`, `connect`, `reconnect`, `stream` are *peers*; `pool`,
  `discovery` *pool*; `block`, `announcement`, `header` *blocks*;
  `justification`; `state`; `warp`, `anchor` *warp*; `finality`, `finalized`
  *finality*. Every line is logged at Debug, except `jam-anchor-unserved` at
  Warn. The page starts the client with `maxLogLevel: 4` (Debug).
- **Values are tokens:** decimal numbers, `0x` hashes in full, `true`/`false`,
  `ip:port`, the driver's own kebab-case words, and error variant names such as
  `NoData` or `Decode(LengthLimit)` (struct-variant fields are dropped, so
  `WrongSetId { expected, received }` logs as `WrongSetId`). A value never
  contains `, ` or `=`. Two exceptions, both handled by the parser: `message=`
  of `jam-stream-reset` is the platform's free text and always the last field,
  so everything after `message=` is its value; and `hash=` of
  `jam-anchor-unserved` (Warn, left as it was) is a byte list, so a part
  without `key=` continues the previous value. `-` means "does not apply".
- **`slot=`** is the connection slot (0 or 1) on every line about one
  connection, except on five older lines whose `slot=` was already a block
  slot and stays one for their consumers: `jam-warp-join-selected`,
  `jam-warp-applied`, `jam-finalized`, `jam-anchor-unserved` and
  `jam-discovery-read-started`. The first three carry the connection slot as
  `conn=`; the page shows their `slot` as `block_slot`. `jam-connect` and
  `jam-reconnect` have no fields, because e2e bodies match them exactly; the
  `jam-slot-assigned` before `jam-connect` and the `jam-peer-disconnected`
  before `jam-reconnect` name the slot.
- **`req=`** names one request for the whole client run. The start line
  `jam-<area>-request-queued` and the outcome line `jam-<area>-request-ended`
  share it, and so do the lines about the request in between
  (`jam-stream-reset`, `jam-warp-rejected`, `jam-finalized`, ...).
- **Outcome lines** carry `outcome=` and `elapsed_ms=` (since the request was
  queued): `ok`; `failed` with the transport's `error=` (`NoData`,
  `Transient`, `Rejected`, ...); `rejected` with the verifier's `error=`;
  `timeout` or `cancelled` with the connection's end `reason=`. A request in
  flight when the pool moves its slot to a bootnode gets no outcome line;
  `jam-peer-disconnected` with `reason=preempted` ends it, and the page closes
  the row as `cancelled`.
- **Purposes:** blocks `warp-join-head`, `root-probe`, `repair`, `ascending`;
  justifications `warp-join`, `finality`; state `warp-join` (the four items
  `C4..C11` at the join head), `discovery` (`C8` at the finalized head); warp
  `warp-join`.

### Events

| Event | Category | Fields | When it fires |
|---|---|---|---|
| `jam-pool-initial` | pool | `bootnodes`, `genesis`, `max_discovered`, `slots` | once at start: the pool's counts |
| `jam-pool-candidate` | pool | `index`, `source`, `address`, `p256` | once per candidate at start, bootnodes first (at most 16 plus `max_validators`) |
| `jam-pool-waiting` | pool | `slot`, `ready_in_ms` | a slot finds no candidate to dial; once per wait, `-` = until the pool changes |
| `jam-pool-changed` | pool | `validators`, `usable`, `discovered`, `added`, `removed`, `retired`, `value_bytes`, `elapsed_ms` | a verified `C(8)` read was merged into the pool |
| `jam-discovery-read-started` | pool | `slot` (block slot) | the `C(8)` refresh starts at the finalized head of that slot |
| `jam-discovery-failed` | pool | `reason` | the refresh gave up: `Released`, `Unavailable`, `Cancelled`, `Provenance`, `Absent`, `Decode` |
| `jam-slot-assigned` | peers | `slot`, `source`, `address`, `p256` | a slot took a candidate and dials it |
| `jam-connect` | peers | none | the dial starts (right after `jam-slot-assigned`) |
| `jam-slot-unsupported` | peers | `slot`, `address` | the platform cannot dial that address type |
| `jam-peer-connected` | peers | `slot`, `source`, `address`, `final_slot`, `handshake_ms` | the peer's UP0 handshake arrived |
| `jam-peer-disconnected` | peers | `slot`, `source`, `address`, `lasted_ms`, `reason` | the connection ended; `reason` below |
| `jam-slot-preempted` | peers | `slot`, `from`, `to` | the pool moved a slot from a validator to a due bootnode |
| `jam-reconnect` | peers | none | the slot asks the pool for its next candidate |
| `jam-stream-reset` | peers | `slot`, `stream`, `req`, `reason`, `message` | the peer reset a stream; `stream` is `block`, `justification`, `state`, `warp` or `other` |
| `jam-peer-protocol-error` | peers | `slot`, `error` | a JAMNP-S protocol error other than an oversized message |
| `jam-announcement` | blocks | `slot`, `block_slot`, `final_slot` | a UP0 announcement arrived |
| `jam-header-inserted` | blocks | `slot`, `via`, `block_slot`, `hash`, `known` | a header went into the tree (`via` `ascending`, `announcement` or `repair`; `known` if it was there already) |
| `jam-block-request-queued` | blocks | `slot`, `req`, `purpose`, `hash`, `direction`, `max_blocks` | a CE 128 request is queued |
| `jam-block-request-ended` | blocks | `slot`, `req`, `purpose`, `outcome`, `blocks`, `bytes`, `error`, `reason`, `elapsed_ms` | its outcome |
| `jam-block-size-halved` | blocks | `slot`, `req`, `max_blocks`, `next_max_blocks`, `ceiling` | a response was too large; later ascending requests ask for fewer blocks |
| `jam-justification-request-queued` | justification | `slot`, `req`, `purpose`, `target`, `target_slot`, `set_id` | a CE 130 request is queued (`set_id` for `finality` only) |
| `jam-justification-request-ended` | justification | `slot`, `req`, `purpose`, `outcome`, `bytes`, `error`, `reason`, `elapsed_ms` | its outcome; the verdict follows as `jam-finalized`, `jam-finality-rejected` or a warp line |
| `jam-state-request-queued` | state | `slot`, `req`, `purpose`, `block`, `trust`, `keys`, `max_size` | a CE 129 read is queued |
| `jam-state-request-ended` | state | `slot`, `req`, `purpose`, `outcome`, `entries`, `nodes`, `bytes`, `error`, `reason`, `elapsed_ms` | its outcome; `rejected` carries the proof error |
| `jam-state-rejected` | state | `slot`, `req`, `error` | the range proof did not verify (kept from before; the outcome line says the same) |
| `jam-state-unavailable` | state | `slot`, `purpose` | the read itself gave up: every slot was tried (`discovery`, slot `-`) or the warp join's read failed |
| `jam-warp-request-queued` | warp | `set_id`, `slot`, `req`, `purpose` | a CE 153 request from set `set_id` is queued |
| `jam-warp-request-ended` | warp | `slot`, `req`, `purpose`, `outcome`, `start_set_id`, `bytes`, `fragments`, `set_id`, `chain_done`, `error`, `reason`, `elapsed_ms` | its outcome: fragments verified and the set reached, or the error |
| `jam-warp-fragmentless` | warp | `reason`, `slot`, `req` | the first warp request answered `NoData`: nothing to warp |
| `jam-warp-join-selected` | warp | `advertisement`, `slot` (block slot), `conn`, `hash`, `fragments`, `set_id` | the join freezes the peer's finalized head F |
| `jam-warp-head-fetched` | warp | `slot`, `req`, `hash`, `block_slot`, `authenticated` | F's header arrived; `by-fragment` when the last fragment already finalized it, else `needs-justification` |
| `jam-warp-justification-verified` | warp | `slot`, `req`, `hash`, `set_id` | F's justification verified |
| `jam-warp-item-read` | warp | `slot`, `item`, `bytes` | one of the state items 4, 6, 8, 11 was read at F |
| `jam-warp-applied` | warp | `set_id`, `slot` (block slot), `fragments`, `state_bytes`, `state_responses`, `fragment_finality`, `conn`, `hash` | the client re-anchored at F |
| `jam-warp-rejected` | warp | `slot`, `step`, `req`, `error`, `reason` | a join step failed verification (`step` `fragments`, `head`, `justification` or `apply`; `reason` for a failed request) |
| `jam-warp-abandoned` | warp | `slot`, `step`, `fragments`, `reason` | the connection ended during a join for another reason than a rejection |
| `jam-anchor-unserved` | warp | `reason`, `error`, `hash`, `slot` (block slot) | Warn: every slot refused the anchor; the client stops |
| `jam-finalized` | finality | `slot` (block slot), `set_id`, `retained`, `conn`, `req`, `hash` | a justification verified and finality advanced |
| `jam-finality-rejected` | finality | `slot`, `req`, `target`, `set_id`, `error` | a justification did not verify |

### Why a connection ended

`jam-peer-disconnected` names one `reason` for every end of a connection:

| `reason` | Meaning |
|---|---|
| `connect-timeout` | the transport did not connect within 20 s |
| `transport` | the platform closed the connection (for example the peer died) |
| `handshake-timeout` | no UP0 handshake within 20 s |
| `idle` | nothing was read for 90 s |
| `stream-open-timeout`, `stream-timeout` | a stream did not open, or outlived 20 s |
| `block-timeout`, `justification-timeout`, `state-timeout`, `warp-timeout` | that request took more than 20 s |
| `stream-reset` | the peer reset its UP0 stream, or the warp join's justification stream |
| `block-failed`, `justification-failed`, `state-failed`, `warp-failed` | that request failed in a way that ends the connection |
| `state-rejected`, `warp-rejected`, `warp-invalid`, `finality-rejected` | a response did not verify |
| `state-unavailable`, `state-cancelled` | the warp join's state read ended without a result |
| `root-refused`, `root-unextendable`, `anchor-unserved` | the peer does not serve our finalized root |
| `unexpected-response`, `protocol-error`, `message-too-large`, `limit`, `request-refused`, `setup` | protocol or bound violations |
| `insert-failed`, `tree-full` | the header tree refused a header or is full |
| `warp-revision` | another slot applied a warp join; every connection restarts on the new anchor |
| `stopped` | the chain stopped |
| `preempted` | the pool moved the slot to a due bootnode |

On the tiny network (six validators, 6-second slots) a client at the tip logs
one announcement and one inserted header per block per slot, plus one
justification request, its outcome and `jam-finalized` per finality advance:
measured over five minutes on 2026-10-06, 73 `jam-*` lines (8.8 kB) a minute,
of 140 client lines (25 kB) a minute at Debug in all.

## What this does not prove

- **No execution proof.** GRANDPA finality authenticates headers; it does not verify runtime execution.
- **No general state reads and no block bodies.** Headers only; `withRuntime: false`.
  The client reads only the four items its warp join needs and the active set `C(8)`.
- **Dev parameters only.** 6 validators, 2 cores, 6-second slots, 12-slot epochs,
  no guest services (the fixed spec has empty guest blobs). Real parameters are far larger.
- **No chain identity.** Step 10 shows that a wrong *authority set* is
  refused. Two chains that share their genesis validators are
  indistinguishable to this client after a warp; see step 10's "What the client
  cannot detect".
- **Loopback validators.** The spec names every validator as a bootnode and
  carries the same set in its genesis `C(8)`; the client replaces the latter
  with the live set later. On the dev network every validator
  advertises `127.0.0.1`, so the browser can dial all of them; a real network
  needs validators whose advertised addresses are reachable from the browser.
  The P-256 identity's position in the metadata is PolkaJam's convention, not
  yet the specification's.
- **Not a soak test.** A few minutes in a browser says nothing about memory over
  hours; retained state remains subject to explicit resource limits.
- **Not a security review.** The demo server, the control endpoint and the
  display-only decoder are QA scaffolding, not production code.

## Named elements and automation handles

DOM ids: `spec-url`, `spec-file`, `start`, `stop`, `header`,
`unpin`, `unfollow`, `status`, `header-output`, `events`, `logs`, `kill-node0`,
`start-node0`, `restart-node0`, `network-status`, and the live view's
`live-connection`, `live-bootnode`, `live-peers`, `live-pool`, `live-last-event`, `live-anchor`,
`live-reanchor`, `live-warp-status`,
`live-count`, `live-block`, `live-parent`, `live-slot`, `live-epoch`,
`live-marks`, `live-marks-seen`, `live-author`, `live-best`, `live-leaves`,
`live-node-best`, `live-agreement`, plus the block list's `blocks-body` (its
`<tbody>`) and `blocks-empty`. Finality fields: `finality-state`, `finality-head`,
`finality-slot`, `finality-count`, `finality-age`, `finality-node`,
`finality-node-gap`. Client events: `client-events-categories` with one
checkbox `client-events-<category>` per category, `client-events-filter`,
`client-events-download`, `client-events-summary`, `client-events-body` and
`client-events-empty`.

`window.jamDemo` exposes `.start()`, `.stop()`, `.header()`, `.unfollow()`,
`.network('kill-node0' | 'start-node0' | 'restart-node0')`,
`.clientEvents()` (what **Download events** saves), `.downloadEvents()`, `.snapshot()` (a
bounded copy of the session state) and `.live()` (the live view's values,
including the decoded header, the tracked leaves, the block rows behind
**Recent blocks**, and the harness status).
The live snapshot also includes `finalized` (hash, source and optional slot),
`finalityCount`, `lastFinalityAt`, `refollows`, `warpStatus` and `warp` (the
event behind it: name, slot, step, error, rejections), `peers` (per
slot: source, address, state, since, the disconnect reason), `refreshes` (the last 32 `C(8)` merges
with their counts, bytes and milliseconds), `discoveryError`, the latest
`initialized` anchor's decoded slot, and each row's `finality` status.
Rendered RPC and log content uses `textContent`, never HTML.

Demo-side bounds, unchanged from C1 except the last three: 100 entries per panel,
4,096 characters per entry, one header in the header panel, at most 16 locally
tracked pins, at most 32 pending RPC calls with 15-second timeouts, at most 256
tracked block hashes behind the leaf view, 20 rows in **Recent blocks**, and a
header-fetch queue capped at those same 20 so a catch-up burst cannot build a
backlog, and 1,000 client events. These are demo bounds, **not** a measurement of the
client's memory use.

Syntax check (does not execute WASM or connect to the network):

```sh
node --check demo/jam.mjs && node --check demo/jam-events.mjs && node --check demo/jam-harness.mjs
```

Browser regression with controlled client/node RPC streams (no WASM or dev
network required): `node --test test/jam/demo.mjs`. Set `CHROMIUM_PATH` to a
system Chrome executable if Playwright's bundled browser is unavailable. This
checks finality rendering, fork pruning, independent RPC errors, re-follow
limits, stale replies, manual Unfollow and Stop during startup, and the client
events: every event of the table above parses, free text with commas, request
pairing, the 1,000-event cap, the filters, the section and its download.

The live page regression is the `jam_demo` scenario in `e2e-tests`: it spawns a
GRANDPA network through zombienet-sdk, ages it past a set change, and runs
`node test/jam/demo.mjs --live` with `JAM_SPEC_PATH` and `JAM_RPC_PORT`:

```sh
cargo test --manifest-path e2e-tests/Cargo.toml --test jam_demo -- --nocapture
```

The live cases assert one `stop`, a different second anchor, resumed blocks and
finality, no automatic re-follow after manual Unfollow, that every `jam-*` line
parses and every category shows events, the refusal of step 10 in *Warp
status*, and attach mode with every, one or no bootnode in the spec.

## Firefox note

If Firefox shows the page but never leaves *Connecting*, check that it supports
WebTransport with `serverCertificateHashes`: that is the feature this client
depends on, and it is the usual difference between browsers here. Everything else
on the page — the live view, the control buttons, the panels — is ordinary DOM
and works the same everywhere.
