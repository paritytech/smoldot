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
  `8ceedf46c4828137c8835e4227d7f3a62ada0463`. The harness looks in
  `POLKAJAM_BIN_DIR` if set, otherwise on `PATH`, and stops if it is missing.
  The harness never clones or builds binaries. Build once in a PolkaJam checkout:

  ```sh
  SKIP_PVM_BUILDS=1 RUSTC_BOOTSTRAP=1 \
    RUSTFLAGS='-Zcrate-attr=feature(array_windows,substr_range)' \
    cargo build --locked --release -p polkajam
  ```

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
| `/jam-demo/spec-wrong-genesis.json` | the same spec with one genesis-header byte flipped (step 10) |
| `/jam-demo/control` | `POST {"action": "status" \| "kill-node0" \| "start-node0" \| "restart-node0"}` |
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
   If the network has been up for a while, the first seconds are a fast catch-up
   burst of many blocks, which pushes `initialized` out of the 100-entry events
   panel almost immediately — that is why the anchor has its own field.
   *Failure:* `Failed to decode chain specification` (check that the spec matches
   the current client; run `npm run demo:jam:rebuild` and reload after source changes);
   Connection stuck at *Connecting (following, no block yet)* while the log
   repeats `jam-connect` / `jam-reconnect` (the client cannot reach the
   bootnode); *Client vs node* drifting further behind with every poll.
   *Note:* every Start syncs from the anchor again. Ascending catch-up imports
   and verifies headers as they arrive, with verified finality pruning the tree
   during catch-up. An older network no longer requires restarting the network
   to get past the former 128-block join limit. See the manual aged-network
   acceptance command in [the test README](../test/jam/README.md).

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

5. **Kill node0.**
   *Do:* press **Kill node0**.
   *See:* the network line reports `node0 NOT running` and one fewer node
   process. The client stops advancing: *Blocks since Start* and *Slot* freeze
   while *Last follow event* keeps counting up. The other five validators keep
   producing, so *Node's own best block* keeps climbing and *Client vs node*
   shows a gap that grows by one slot every six seconds — that is exactly the
   reading you want: the client knows it is behind rather than pretending. The
   browser console shows connection failures to `127.0.0.1:40000`; that is the
   client honestly failing to reach a dead peer. **Recent blocks** stops growing:
   the top row's Age just counts up.
   *Failure:* **any** new block appearing while node0 is down — the client must
   never invent one — finality may still advance from a proof already in flight.

6. **Restart node0.**
   *Do:* press **Start node0** (use **Restart node0** when node0 is still alive).
   *See:* within roughly 10–20 seconds and **without reloading the page**, blocks
   resume, and *Client vs node* closes the gap back to zero. The catch-up is
   real: the number of new blocks matches the number of slots that passed while
   node0 was down, so the chain is continuous rather than resuming after a hole.
   **Recent blocks** shows the backfill directly: when it has finished, the slots
   at the top of the table are consecutive again across the gap. Give it time
   before judging — Chrome backfilled within ~15 seconds of the restart here,
   Firefox needed closer to 30, so an incomplete table a few seconds in is not
   yet a failure.
   *Failure:* nothing arrives within a minute; or blocks resume but the block
   count lags far behind the slot span, meaning missed slots were skipped rather
   than caught up.

7. **Unfollow, then Start again.**
   *Do:* press **Unfollow**, wait a few seconds, then **Stop** and **Start**.
   *See:* after Unfollow, Connection reads *Unfollowed (chain still running)* and
   no further follow events are appended, while the network line still shows
   node0 running. Start re-subscribes and blocks flow again from a fresh
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

10. **A wrong chain is refused.**
    *Do:* press **Stop**, set the spec URL to
    `/jam-demo/spec-wrong-genesis.json`, press **Start**, and wait ~45 seconds.
    *See:* *Trusted anchor* shows a **different** hash from step 1 (the corrupted
    genesis), and then nothing: no `newBlock` ever, *Blocks since Start* stays 0,
    and the log repeats `jam-connect` / `jam-reconnect` as the peer drops a
    client that is on another chain.
    *Failure:* any `newBlock` — that would mean the client followed a chain that
    does not descend from the anchor it was given.

Afterwards press Ctrl-C in the terminal. The harness stops the network and the
server and prints either "teardown complete; no PolkaJam process left behind" or
a list of processes that survived, which would be a bug.

## What this does not prove

- **No execution proof.** GRANDPA finality authenticates headers; it does not verify runtime execution.
- **No state reads and no block bodies.** Headers only; `withRuntime: false`.
- **Dev parameters only.** 6 validators, 2 cores, 6-second slots, 12-slot epochs,
  `SKIP_PVM_BUILDS=1` guest blobs. Real parameters are far larger.
- **One bootnode.** The client is pointed at node0 alone, which is what makes
  step 5 a clean fault injection; it is not a test of peer discovery.
- **Not a soak test.** A few minutes in a browser says nothing about memory over
  hours; retained state remains subject to explicit resource limits.
- **Not a security review.** The demo server, the control endpoint and the
  display-only decoder are QA scaffolding, not production code.

## Named elements and automation handles

DOM ids: `spec-url`, `spec-file`, `dev-bootnode`, `start`, `stop`, `header`,
`unpin`, `unfollow`, `status`, `header-output`, `events`, `logs`, `kill-node0`,
`start-node0`, `restart-node0`, `network-status`, and the live view's
`live-connection`, `live-bootnode`, `live-last-event`, `live-anchor`,
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
`finalityCount`, `lastFinalityAt`, and each row's `finality` status.
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
checks finality rendering, fork pruning, independent RPC errors and session
reset; it does not test the Rust verifier or establish live client finality.

## Firefox note

If Firefox shows the page but never leaves *Connecting*, check that it supports
WebTransport with `serverCertificateHashes`: that is the feature this client
depends on, and it is the usual difference between browsers here. Everything else
on the page — the live view, the control buttons, the panels — is ordinary DOM
and works the same everywhere.
