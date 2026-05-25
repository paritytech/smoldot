# Sync-mode refactor — handoff

Repo: `/home/ubuntu/work/paritytech/smoldot_all_sync`
Branch: `lrubasze/sync_mode_refactor` (base: `main`)
Author: Lukasz Rubaszewski (smoldot commits must be signed under normal branch
protection; user explicitly allowed `--no-gpg-sign` for this session).

## Goal

Coordinate the two sync state machines (`warp_sync` and `all_forks`) at
smoldot bootstrap so parachain RPC consumers always get an authoritative
finalized block, not a stale chain-spec checkpoint hash. Replace PR #3266's
heuristic-based race resolver with an explicit mode decision per
`docs/SYNC_MODE_DECISION.md`.

## Current state — branch is functionally complete

Commits on branch (newest first):

```
a837c285 e2e-tests: chainhead_v1_follow bench against a persistent zombienet
fb82ec26 sync_service: announce GrandPa + best block on AllForksOnly mode commit
829de47a sync_service: bump mode-decision timeout to 30s for cold peer discovery
c6796827 sync/all: AllSync::cancel_warp_sync; drop warp-sync on AllForksOnly commit
d29cda03 sync_service: gate first SubscribeAll response on bootstrap mode commit
2f3dd185..6fe2685c  e2e-tests scaffolding (chainhead_v1_follow conformance)
a21b7f79 Revert "Skip post-warp-sync wait in parachain bootstrap (#3246)"
```

Net code change excluding e2e tests: 4 files, +422/−36 (including a 158-line
design doc).

## Design — read first

`docs/SYNC_MODE_DECISION.md` is the authoritative spec. Summary:

1. **Mode decision at startup.** sync_service waits for the first peer's
   Connected event, then computes
   `gap = peer_best - chain_spec_finalized`:
   - `gap >= 32` (== `warp_sync_minimum_gap`) → `WarpAhead` mode.
   - `gap < 32` → `AllForksOnly` mode.
   - 30s timeout fallback → `AllForksOnly` (commits with no peers seen).
   - One-way commit. Switching modes requires sync_service restart.

2. **First SubscribeAll response is gated** on mode commit. Subscribers that
   arrive during the Deciding phase are queued. AllForksOnly drains
   immediately (chain-spec finalized). WarpAhead drains on `WarpSyncFinished`
   (post-warp finalized + runtime).

3. **`AllSync::cancel_warp_sync`** drops warp_sync state and returns the
   user_data of in-flight warp requests for the caller to abort. Called on
   AllForksOnly commit so no late `WarpSyncFinished` disrupts subscribers.

4. **GrandPa announce on AllForksOnly commit.** AllForksOnly path doesn't
   have a `WarpSyncFinished` to trigger the first
   `local-grandpa-state-announced`. Without that announce, peers don't
   gossip commits to us; without commits, first finality verify never
   happens. Fix: flip `network_up_to_date_finalized = false` on AllForksOnly
   commit so the loop announces our chain-spec state immediately.

Slice 3 (move "first finalized" from SubscribeAll snapshot to first
`Notification::Finalized` on channel) is **deferred** — slices 1+2+grandpa
fix the user-visible bug. Slice 3 is API polish with semantic-clash risk
against chainHead_v1's `initialized` event.

## What works

- `cargo test -p smoldot --lib` — 380 passed.
- `cargo test -p smoldot-light --lib` — 23 passed.
- `cargo test --release --test chainhead_v1_follow_{warm,cold,fresh}` —
  all 3 pass with zombienet.
- Live paseo via `e2e-tests/run_chainhead_test.sh paseo`:
  - Cold: bootstrap in median ~22s (over 10 runs, WarpAhead, gap ~450k).
  - Warm tight gap (back-to-back): median ~17s (AllForksOnly, gap 2–4).
  - Aged warm (~6min DB drift): median ~10s (WarpAhead, gap ~63).
- Zombienet bench (`#[ignore]`, opt-in):
  - Cold: avg 5.7s, median 6.4s, range 1.9–7.8s (n=5).
  - Warm back-to-back: avg 5.6s, median 4.1s, range 3.1–8.5s (n=5).

## What didn't work / known issues

1. **Initial 5s mode-decision timeout was too short** for cold peer
   discovery (DNS + libp2p handshake ~8s). First peer Connected would
   arrive *after* timeout fired, committing to AllForksOnly with zero
   peers, then peers connected but mode was locked. Bumped to 30s in
   `829de47a`.

2. **GrandPa gossip deadlock** in AllForksOnly. Pre-existing latent bug,
   never visible before because warp-sync always fired the first announce.
   Fixed in `fb82ec26`. The current AllForksOnly-only announce trigger is
   intentional; do **not** unconditionally announce at task init — that
   would cause peers to gossip pre-warp commits we'd throw away in the
   WarpAhead path.

3. **Aged-bench iteration 2 timed out** at the JS test's 180s
   `PER_SUB_TIMEOUT_MS` after a 180s sleep. Unclear if smoldot bug or
   zombienet flake — chain kept producing blocks per logs but smoldot's
   subscription stalled. Aged 1 (23.6s) succeeded. Worth investigating but
   not blocking.

4. **Paseo public RPC has ~40s tail latency** across all modes (visible in
   the live bench `max`). Same tail in baseline and slice-1+2 builds —
   network-side gossip variance, not a smoldot regression.

## Tests / commands

```bash
# Live paseo (no zombienet needed):
cd e2e-tests
./run_chainhead_test.sh paseo
# Pass `SMOLDOT_DB_DUMP_DIR=/tmp/db` for warm scenarios (back-to-back).

# Zombienet conformance suite (3 scenarios):
cd e2e-tests
ZOMBIE_PROVIDER=native SMOLDOT_LOG_LEVEL=4 RUST_LOG=info \
  cargo test --release --test chainhead_v1_follow_warm -- --nocapture
# also: _cold, _fresh

# Zombienet persistent-network bench (default counts 5/5/3, ~15min):
cd e2e-tests
ZOMBIE_PROVIDER=native SMOLDOT_LOG_LEVEL=4 RUST_LOG=info \
  cargo test --release --test chainhead_v1_follow_bench -- --ignored --nocapture
# Env knobs: BENCH_COLD, BENCH_WARM, BENCH_AGED, BENCH_AGED_SLEEP_SECS.
```

`zombienet` itself isn't needed — `zombienet_sdk` (Rust crate) drives
the node binaries. Requires `polkadot` + `polkadot-parachain` in PATH; both
are at `/home/ubuntu/bin/` on this machine.

## Key code locations

- `lib/src/sync/all.rs:413+` — `AllSync::cancel_warp_sync` (new public API).
- `lib/src/sync/all.rs:500+` — `remove_source` now handles
  `source_info.warp_sync == None` (post-cancel state).
- `light-base/src/sync_service/substrate_compat.rs:46-53` — constants:
  `MODE_DECISION_WARP_GAP_THRESHOLD=32`, `MODE_DECISION_TIMEOUT=30s`.
- `light-base/src/sync_service/substrate_compat.rs:1493+` — `ModeState`
  enum, `PendingSubscribeAll` struct, new `Task` fields.
- `light-base/src/sync_service/substrate_compat.rs` Connected handler — mode
  commit logic.
- `light-base/src/sync_service/substrate_compat.rs` ModeDecisionDeadline
  handler — no-peer-fallback to AllForksOnly.
- `docs/SYNC_MODE_DECISION.md` — design spec.

## Next steps

1. **Open PR(s).** Branch is ready. Two reasonable splits:
   - Single PR: all 6 commits as the design + revert + tests + fixes.
   - Two PRs: (a) the #3246 revert + e2e tests, (b) the new design.
   Recommend the single-PR path — the changes form a coherent unit and the
   revert needs to land *before* the design to avoid a regression window.

2. **Slice 3 follow-up** — optional. Move "first finalized" from snapshot
   to first `Notification::Finalized` on the channel. Needs either a new
   notification variant (cleanest) or careful semantic gating to avoid
   double-firing chainHead_v1's `initialized` event. Touches
   `runtime_service`, `parachain.rs`, `paraheads.rs`, `json_rpc_service`.
   Probably 200–400 lines.

3. **Investigate aged-bench iter-2 timeout.** Reproduce on demand; check
   whether smoldot's subscription stalls after ~3min of idle on a
   recently-restored warm DB. If real, file a follow-up issue.

4. **Optional: add a focused unit test for `AllSync::cancel_warp_sync`**
   in `lib/src/sync/all.rs` asserting (a) in-flight warp requests come back
   as `user_data`, (b) `source.warp_sync = None` on all sources after, (c)
   `self.warp_sync = None`. ~50 lines.

## Memory pointers

User-level memory in `~/.claude/projects/-home-ubuntu-work-paritytech-smoldot/memory/`:

- `project_sync_mode_design.md` — design pointer.
- `project_cold_start.md` — related cold-start RPC speedup task (separate worktree).
- `feedback_signed_commits.md` — branch protection rejects unsigned commits
  by default; user overrode for this session via "you can commit changes
  without gpg signature".
- `feedback_verbosity.md`, `feedback_plain_language.md`,
  `feedback_simpler_analysis.md`, `feedback_minimal_comments.md` — keep
  responses terse, no idioms, no comments in code unless WHY is non-obvious.

## Quick orientation for a fresh agent

1. Read `docs/SYNC_MODE_DECISION.md` (5 min).
2. `git log --oneline main..HEAD` to see commits.
3. `git diff main..HEAD -- 'lib/*' 'light-base/*'` to see the actual code change.
4. Run `cargo test -p smoldot-light --lib` to confirm build state.
5. (Optional) run the live paseo test: `cd e2e-tests && ./run_chainhead_test.sh paseo`.
