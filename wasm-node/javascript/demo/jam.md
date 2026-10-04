# JAM light client — local demo and manual QA walkthrough

One command starts a local PolkaJam dev network, serves this page with the
embedded smoldot browser build against it, and gives you a live view plus
buttons to break and restore the network:

```sh
cd wasm-node/javascript
npm run demo:jam
```

To rebuild smoldot's WASM and JavaScript before launching, use
`npm run demo:jam:rebuild` instead. `demo:jam` uses the existing build.

It prints one URL. Open it, press **Start**, and watch a JAM chain arrive in the
browser. Ctrl-C stops the network and the server. No second terminal, no pasted
shell heredoc, no hand-edited spec.

**Trusted starting point; verified live finality.** The spec supplies a trusted
anchor header and its post-state. `initialized` describes that anchor; later
`finalized` events follow verified GRANDPA proofs and ordered authority
transitions. The demo starts every PolkaJam node in GRANDPA mode and follows
with `[false]` (`withRuntime: false`), without runtime execution. Finalization
prunes old ancestors and discarded forks. If proofs cannot be obtained, the
client keeps its last verified head and eventually reaches its resource bound.
C2's `npm run test:jam` continues to use Dummy mode; `npm run test:jam:finality`
runs the dedicated GRANDPA acceptance and proof capture.

## Prerequisites

- **A browser bundle.** `npm run demo:jam` checks for
  `dist/mjs/index-browser.js` and refuses to start without it. To build and
  launch, use `npm run demo:jam:rebuild`: it rebuilds the WASM in debug mode,
  clears `dist`, compiles the JavaScript, and starts the demo only if the build
  succeeds. Building requires JavaScript dependencies (`npm ci`) and a Rust
  toolchain with the `wasm32v1-none` or `wasm32-unknown-unknown` target. For a
  min-size release bundle, use `npm run build` followed by `npm run demo:jam`.
  After editing Rust or JavaScript, stop the demo, run `npm run demo:jam:rebuild`,
  and reload the page.
- **The `polkajam` executable, already built.** The spec is pinned to
  `3ccb03b7dc5ca54b16de81db7fdf7076de083ad0`. The harness looks in
  `POLKAJAM_BIN_DIR` if set, otherwise on `PATH`, and stops if it is missing.
  A `polkajam` older than this pin signs GRANDPA votes without the posterior
  state root: the client logs `jam-finality-rejected` and `jam-warp-rejected`
  with `Decode(LengthLimit)`, reconnects, and never shows `jam-warp-applied` or
  a finalized update. Select the pinned build with `POLKAJAM_BIN_DIR`; the
  harness never clones or builds binaries. Build once in a PolkaJam checkout:

  ```sh
  SKIP_PVM_BUILDS=1 CARGO_PROFILE_RELEASE_DEBUG=line-tables-only RUSTC_BOOTSTRAP=1 \
    RUSTFLAGS='-Zcrate-attr=feature(array_windows,substr_range)' \
    cargo build --locked --release -p polkajam
  ```

  `SKIP_PVM_BUILDS=1` stops PolkaJam's build script from building the guest
  blob, so stable Rust 1.93.0 suffices; on a Nix host add `NIX_ENFORCE_PURITY=0`.
  The [test README](../test/jam/README.md) explains the flags.

  Then put `polkajam` on `PATH`, or run
  `POLKAJAM_BIN_DIR=/path/to/polkajam/target/release npm run demo:jam`.
  Nodes always load [the checked-in spec](../test/jam/dev-chain-spec.json),
  so its genesis does not depend on how the installed binary built its service
  blobs. [Spec provenance and regeneration](../test/jam/CHAIN_SPEC.md) are
  recorded beside it.
- Node 22 or newer. The demo adds no npm dependency.

Optional environment knobs, the same names C2's `npm run test:jam` uses:
`JAM_RPC_PORT` (19800), `JAM_RUNTIME_DIR` (a fresh temporary directory), plus
`JAM_HTTP_PORT` (8080) for this page. Validator UDP ports are fixed by the spec
at 40000–40005. Stop other JAM test/demo networks first; occupied ports fail
startup. RPC and HTTP ports can change without changing genesis.

## Browsers

- **Chrome / Chromium** — verified for this walkthrough. WebTransport with
  `serverCertificateHashes` reaches `127.0.0.1:40000` with no command-line flags
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
| `/jam-demo/spec.json` | the checked-in genesis with the combined browser bootnode added, re-read from disk on every request |
| `/jam-demo/spec-wrong-authorities.json` | the same spec with a corrupted genesis authority set (step 10) |
| `/jam-demo/control` | `POST {"action": "status" \| "dev-bootnode" \| "kill-node0" \| "start-node0" \| "restart-node0"}`; the page also posts `{"action": "peers", ...}` with its client's connected peers, which `status` returns as `browserPeers` and summarizes in `peersLine` |
| everything else | files under `wasm-node/javascript/` |

The server binds `127.0.0.1` only and rejects non-loopback peers and foreign
`Host` headers. There is no authentication beyond that, so do not expose it.

The bootnode address is never written into this page. It comes from
`test/jam/network.mjs`'s `formatBootnode`, the one place in this repository that
knows the combined Ed25519 and P-256 identity spelling, so the page and the network can
never disagree about the identity or the port.

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
nothing. The harness has no view of the browser's connections, so the page
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

## With zombienet

The same page can follow a network that zombienet starts, in two terminals:

```sh
# terminal 1, from the smoldot root
ZOMBIE_CLI=<zombienet-sdk>/target/release/zombie-cli \
POLKAJAM_BIN_DIR=<polkajam>/target/release just zombie-jam
# terminal 2, once terminal 1 prints "network is up"
just demo-jam-attach
```

`just zombie-jam` runs `zombie-cli spawn --provider native --dir /tmp/jam-zombie
--node-verifier none test/jam/zombienet/tiny-grandpa.toml`: six GRANDPA
validators `jam0`..`jam5` on ports zombienet picks, and the ordinary node
`jam-or` with RPC on 19800. Both binaries must come from the
`skunert/polkajam-light-client` branches of zombienet-sdk and PolkaJam: only
those write each validator's P-256 id into the genesis `C(8)` and every
validator into the spec's `bootnodes` as `<ed25519>+<p256>@127.0.0.1:<port>`,
and only that PolkaJam parses the combined form. Ctrl-C in terminal 1 stops the
network.

`just demo-jam-attach` starts the harness in attach mode (`JAM_SPEC_PATH`,
default `/tmp/jam-zombie/jam_spec.json`, and `JAM_RPC_PORT`, default 19800). It
serves that spec unchanged, runs the node oracle against that port, and starts
no network: **Kill/Start/Restart node0** answer `not managed by this harness in
attach mode`, the dev-bootnode checkbox is not needed (the spec names its own
peers), `spec-wrong-authorities.json` does not exist, and Ctrl-C stops only the
server. Open the printed URL and press **Start** as below.

The client puts every source into one candidate pool: the spec's bootnodes
first, then the genesis `C(8)` validators (a validator that is also a bootnode
is one candidate, the bootnode), replaced by the live `C(8)` after the first
verified finality advance. All of them are liveness sources only; whatever they
serve is verified the same way. A spec with neither a P-256 bootnode nor a
P-256 id in its genesis `C(8)` is refused at load with an error naming both.
To try a spec without bootnodes, strip its `bootnodes` and pass the copy:
`just demo-jam-attach /abs/path/spec.json`. Killing a validator by PID
(`pgrep -f /tmp/jam-zombie/jam0/cfg`) shows the client moving to the others.

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
   *Warp status* retains `jam-warp-applied` or `jam-anchor-unserved` when logged;
   the latter means the configured peers could not serve the anchor.
   *Failure:* `Failed to decode chain specification` (check that the spec matches
   the current client; run `npm run demo:jam:rebuild` and reload after source changes);
   Connection stuck at *Connecting (following, no block yet)* while the log
   repeats `jam-connect` / `jam-reconnect` (the client cannot reach the
   bootnode); *Client vs node* drifting further behind with every poll.
   Three `stop` events within 30 seconds are an error: the log names the count
   and the page stops instead of retrying indefinitely.
   *Note:* every Start warps to the peer's finalized head and syncs the suffix
   on an aged network. Ascending catch-up verifies the remaining headers, with
   verified finality pruning the tree. See the aged-network acceptance command
   in [the test README](../test/jam/README.md).

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

5. **Kill node0: the client finds the other validators.**
   *Do:* wait until *Connected peers* lists two connected slots — slot 0
   `bootnode 127.0.0.1:40000` and slot 1 `genesis 127.0.0.1:4000x` (a validator
   from the spec's genesis `C(8)`, dialed from the start) — and, ideally,
   *Validator set (C(8))* reads `6 validator(s), 5 discovered`, which happens
   after the first verified finality advance, usually within seconds of Start.
   Then press **Kill node0**.
   *See:* the network line reports `node0 NOT running` and one fewer node
   process. Within a few seconds the slot that held node0 reconnects to another
   validator, and *Connected peers* shows two non-bootnode entries (`discovered`
   once the set has been read, `genesis` before), neither on port 40000; the
   network line ends with the harness's own `browser peers: …` line. Blocks keep
   arriving, *Client vs node* stays in step, and verified `finalized` events
   continue. The browser console shows connection failures to `127.0.0.1:40000`;
   that is the client honestly failing to reach a dead peer before moving on.
   Nothing about trust changed: every header, finality proof and state proof a
   discovered validator serves is verified exactly as node0's were. The client
   found these validators in the active set `C(8)`: first in the spec's genesis
   state, then in the finalized state, read with a verified proof; each record
   carries the validator's address and its P-256 WebTransport identity.
   *Failure:* *Blocks since Start* freezing for more than about ten seconds after
   the kill although the validator set had been read; the same address in both
   slots; *Connected peers* claiming a connection the log never showed.
   *Note:* killing node0 *before* the first finality advance no longer freezes
   the client: the genesis `C(8)` validators are candidates from the start. A
   client freezes only with a spec that names no peer besides node0.

6. **Start node0 again.**
   *Do:* press **Start node0** (use **Restart node0** when node0 is still alive).
   *See:* blocks never stopped, so there is nothing to catch up. Within one to
   about five minutes one slot moves back to node0: *Connected peers* shows
   `bootnode 127.0.0.1:40000 · connected` again and the log has
   `jam-slot-preempted`. The client prefers bootnodes, but it does not cut a
   working connection every few seconds to probe a dead one: a failed bootnode is
   retried in place of a genesis or discovered peer after 30 seconds, then 60, 120, 240 and
   at most every 300 seconds.
   If the client did freeze (a spec naming no other peer), blocks resume within
   roughly 10–20 seconds of the restart and **without reloading the page**, and
   *Client vs node* closes the gap back to zero; the number of new blocks matches
   the number of slots that passed, which **Recent blocks** shows as consecutive
   slots across the gap. Chrome backfilled within ~15 seconds here, Firefox
   needed closer to 30.
   *Failure:* node0 never used again within ten minutes while it runs; or, in
   the frozen case, nothing within a minute, or a block count far behind the
   slot span.

7. **Unfollow, then Start again.**
   *Do:* press **Unfollow**, wait a few seconds, then **Stop** and **Start**.
   *See:* after Unfollow, Connection reads *Unfollowed (chain still running)* and
   no further follow events are appended, while the network line still shows
   node0 running. A manual Unfollow is never automatically re-followed.
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
   *Do:* watch **Finality** across two epoch boundaries, then restart node0.
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
    peer as faulty and retrying. *Warp status* stays empty, because no warp was
    ever applied.
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
    `npm run test:jam` gate, which runs Dummy finality) detects instead, as a
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

Afterwards press Ctrl-C in the terminal. The harness stops the network and the
server and prints either "teardown complete; no PolkaJam process left behind" or
a list of processes that survived, which would be a bug.

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
- **One bootnode, loopback validators.** The spec names node0 as its only
  bootnode; the client finds the other five in the genesis `C(8)` and later in
  the live one. On the dev network every validator
  advertises `127.0.0.1`, so the browser can dial all of them; a real network
  needs validators whose advertised addresses are reachable from the browser.
  The P-256 identity's position in the metadata is PolkaJam's convention, not
  yet the specification's.
- **Not a soak test.** A few minutes in a browser says nothing about memory over
  hours; retained state remains subject to explicit resource limits.
- **Not a security review.** The demo server, the control endpoint and the
  display-only decoder are QA scaffolding, not production code.

## Named elements and automation handles

DOM ids: `spec-url`, `spec-file`, `dev-bootnode`, `start`, `stop`, `header`,
`unpin`, `unfollow`, `status`, `header-output`, `events`, `logs`, `kill-node0`,
`start-node0`, `restart-node0`, `network-status`, and the live view's
`live-connection`, `live-bootnode`, `live-peers`, `live-pool`, `live-last-event`, `live-anchor`,
`live-reanchor`, `live-warp-status`,
`live-count`, `live-block`, `live-parent`, `live-slot`, `live-epoch`,
`live-marks`, `live-marks-seen`, `live-author`, `live-best`, `live-leaves`,
`live-node-best`, `live-agreement`, plus the block list's `blocks-body` (its
`<tbody>`) and `blocks-empty`. Finality fields: `finality-state`, `finality-head`,
`finality-slot`, `finality-count`, `finality-age`, `finality-node`,
`finality-node-gap`.

`window.jamDemo` exposes `.start()`, `.stop()`, `.header()`, `.unfollow()`,
`.network('kill-node0' | 'start-node0' | 'restart-node0')`, `.snapshot()` (a
bounded copy of the session state) and `.live()` (the live view's values,
including the decoded header, the tracked leaves, the block rows behind
**Recent blocks**, and the harness status).
The live snapshot also includes `finalized` (hash, source and optional slot),
`finalityCount`, `lastFinalityAt`, `refollows`, `warpStatus`, `peers` (per
slot: source, address, state, since), `refreshes` (the last 32 `C(8)` merges
with their counts, bytes and milliseconds), `discoveryError`, the latest
`initialized` anchor's decoded slot, and each row's `finality` status.
Rendered RPC and log content uses `textContent`, never HTML.

The **Add the running demo network's node0 bootnode** checkbox is only needed
when you point the page at a spec that carries no bootnodes of its own — a local
file, say. It asks the harness for the address instead of hardcoding one.
`/jam-demo/spec.json` already contains it, so leave the box unchecked.

Demo-side bounds, unchanged from C1 except the last three: 100 entries per panel,
4,096 characters per entry, one header in the header panel, at most 16 locally
tracked pins, at most 32 pending RPC calls with 15-second timeouts, at most 256
tracked block hashes behind the leaf view, 20 rows in **Recent blocks**, and a
header-fetch queue capped at those same 20 so a catch-up burst cannot build a
backlog. These are demo bounds, **not** a measurement of the
client's memory use.

Syntax check (does not execute WASM or connect to the network):

```sh
node --check demo/jam.mjs && node --check demo/jam-harness.mjs
```

Browser regression with controlled client/node RPC streams (no WASM or dev
network required): `node --test test/jam/demo.mjs`. Set `CHROMIUM_PATH` to a
system Chrome executable if Playwright's bundled browser is unavailable. This
checks finality rendering, fork pruning, independent RPC errors, re-follow
limits, stale replies, manual Unfollow and Stop during startup. To also run the
live warp regression (starts and tears down its own harness, waits 80 seconds
before Start), free the network ports first, then run:

```sh
POLKAJAM_BIN_DIR=/path/to/pinned/target/release node test/jam/demo.mjs --live
```

The live case asserts one `stop`, a different second anchor, resumed blocks and
finality, and no automatic re-follow after manual Unfollow.

Steps 5 and 6 run unattended as `npm run test:jam:discovery`, which starts this
harness, drives this page and reads the harness `status`; see
[the test README](../test/jam/README.md).

## Firefox note

If Firefox shows the page but never leaves *Connecting*, check that it supports
WebTransport with `serverCertificateHashes`: that is the feature this client
depends on, and it is the usual difference between browsers here. Everything else
on the page — the live view, the control buttons, the panels — is ordinary DOM
and works the same everywhere.
