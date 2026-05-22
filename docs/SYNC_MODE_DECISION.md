# Sync mode decision at bootstrap

Design for coordinating warp-sync and all-forks during smoldot startup.
Replaces the patching approach in PRs #3246 and #3266.

## Problem

`lib/src/sync/all.rs:AllSync` constructs both `warp_sync` and `all_forks`
state machines on startup. They effectively race:

- warp-sync starts from chain spec, downloads fragments + runtime + storage
  proofs, jumps to a tip-adjacent finalized block.
- all-forks starts from chain spec, walks header-by-header. Has no runtime
  download; `runtime_service` downloads runtime separately for whichever
  finalized block all-forks produces.

Whoever finishes first determines the initial finalized block exposed to
downstream consumers (`runtime_service`, parachain bootstrap). The race can
finish with all-forks "winning" on a chain-spec-adjacent block, which then
forces parachain bootstrap to catch up from a parahead that is far behind tip.

PR #3266 papers this over with:
- a counter (10 all-forks verifies → "warp-sync not needed"),
- a side channel (`WarpSyncState` smuggled into `SubscribeAll` for
  `runtime_service` to introspect),
- a force-resubscribe that clears in-flight runtime downloads when the state
  flips.

PR #3246 trusts `runtime_service.subscribe_all`'s snapshot
`finalized_block_scale_encoded_header` as authoritative. This depends on
#3266's plumbing to guarantee the snapshot is post-warp.

Both should be removed in favor of an upfront mode decision.

## v1 design — upfront pick

### Mode decision (sync_service)

Deciding phase at startup:

- Wait for first peer best-block via `block_announce` or handshake, up to
  3 peers, with 5s timeout.
- Decide trigger: first to fire — 3 peers reported, or 5s timeout with ≥1
  peer, or 5s timeout with 0 peers.
- `gap = max(sampled_peer_best) - chain_spec_finalized`.
- `gap < 32` → `AllForksOnly`. `gap >= 32` → `WarpAhead`. 0 peers → `AllForksOnly`.
- The threshold is the existing `warp_sync_minimum_gap` (`lib/src/sync/all.rs:202`).
- One-way commit. Mode switch requires sync_service restart.

### AllForksOnly mode

- Construct `all_forks` only. Do not start `warp_sync`.
- Sync_service emits `Notification::Finalized { chain-spec-block, runtime: None }`
  immediately on commit.
- `runtime_service` downloads chain-spec runtime as today.

### WarpAhead mode

- Construct `warp_sync` only. Do not construct `all_forks`.
- Block announces parse the header (reject malformed → ban peer) and update
  `(best_number, best_hash)` in `AllSync.shared.sources`. No disjoint-blocks
  tree.
- Sync_service emits no `Notification::Finalized` until `WarpSyncFinished`.
- On `WarpSyncFinished`:
  1. Instantiate `all_forks` from `warp_sync.as_chain_information()`.
  2. Re-attach sources from `shared.sources` to the new `all_forks`.
  3. Emit `Notification::Finalized { post-warp-block, runtime: Some(warp_payload) }`.
  4. Drop `warp_sync`.

### Fallback

WarpAhead stuck (no warp-sync progress past timeout) → drop `warp_sync`,
instantiate `all_forks` from chain spec, emit
`Notification::Finalized { chain-spec-block, runtime: None }`. Same code path
as the AllForksOnly transition; treat it as a delayed AllForksOnly commit.

### Subscribe contract change

Move "first finalized block" from snapshot to event:

- `SubscribeAll.finalized_block_scale_encoded_header` becomes informational
  (initial state, may be stale).
- Callers must read the first `Notification::Finalized` from the channel.
  That is the authoritative starting point.
- Touched call sites for the contract change: `runtime_service`,
  `sync_service/parachain.rs`, `sync_service/paraheads.rs`, `json_rpc_service`.

### Cleanups

- Revert PR #3246: parachain bootstrap returns to "wait for first
  `Notification::Finalized`" loop in `fetch_parachain_head_from_relay`.
- Revert PR #3266: drop `WarpSyncTracker`, `WarpSyncState`, `WarpSyncEvent`,
  the runtime_service `Tree::FinalizedBlockRuntimeUnknown if InProgress`
  guard, and the `force_resubscribe` / `all_notifications.clear()` paths
  added for warp coordination.
- `runtime_service` becomes purely reactive to notifications; no warp-sync
  awareness.

### Where state moves

- Best-block tracking per source: lift out of `all_forks::AllForksSync` into
  `AllSync.shared.sources` so it works in both modes and in WarpAhead before
  `all_forks` exists.
- Finalized-height tracking per source: stays in `warp_sync::WarpSync.sources`
  during WarpAhead; lifts to `all_forks` on transition.

### What goes away

- `WARP_SYNC_NOT_NEEDED_AFTER_ALLFORKS_VERIFIES = 10` heuristic.
- `runtime_service` introspecting sync_service's warp state.
- Forced re-subscribe to flush stale data.
- Parachain bootstrap's dependence on the `SubscribeAll` snapshot being post-warp.

## Costs

- Mode-decision phase adds startup latency: typically sub-second; up to 5s
  with no peers.
- `SubscribeAll` ABI change: callers move from "read
  `.finalized_block_scale_encoded_header`" to "read first notification."
- WarpAhead post-warp re-requests headers it could have learned from
  block-announces during the warp phase (a few KB per peer). Negligible
  versus the warp-sync runtime download.
- No mid-session mode switch. Sync_service restart resets the decision.

## v2 — Racing mode (future)

In the gap=32-to-~few-hundred band, warp-sync pays its full fixed cost
(fragment download, runtime download, storage proofs) for very few blocks,
while all-forks could finish in 1-5s. Upfront-pick spends ~10s extra in
this band.

Racing mode runs both machines in parallel and resolves dynamically:

- Both `warp_sync` and `all_forks` constructed and active.
- Subscribe_all still gated — no `Notification::Finalized` emitted until
  resolution.
- Resolver: `min(WarpSyncFinished_event, all_forks.finalized >= warp_sync.target)`
  fires.
  - All-forks wins → emit `Notification::Finalized { all_forks.finalized, runtime: None }`,
    drop `warp_sync`.
  - Warp wins → as today's WarpAhead transition.

What v1 should preserve to make v2 cheap to add:

- Keep `gap` as data, not collapsed to a boolean. The deciding phase returns
  `(gap, mode)`; v2 only adds a second threshold mapping
  `gap → {AllForksOnly | Racing | WarpAhead}` without re-plumbing.
- Gate emissions on a mode-agnostic trigger. v1 triggers: commit
  (AllForksOnly), `WarpSyncFinished` (WarpAhead). v2 adds the racing
  resolver. Same gate, different trigger source.
- `AllSync` already supports both machines coexisting via `Option<>`
  wrappers. v1's "drop the unused machine" is just choosing not to construct
  it; v2 keeps both alive.
- `warp_sync.target_block_number()` is not exposed publicly; only v2 needs
  it. Add when v2 lands.

Add v2 only if telemetry shows the gap=32-to-few-hundred band is common in
production parachain bootstraps.
