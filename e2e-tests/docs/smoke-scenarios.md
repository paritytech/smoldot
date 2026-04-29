# Smoldot smoke-test scenarios

Plan for extending `e2e-tests/tests/smoke.rs` from a single fresh-network case to three scenarios that better reflect real smoldot startup conditions.

Status: planning. Nothing in this doc is implemented yet.

## Scenarios

| Scenario | Chain spec | Smoldot DB | Network |
|---|---|---|---|
| Fresh  | vanilla (no `lightSyncState`) | none | spawned from genesis |
| Cold   | with `lightSyncState`         | none | spawned from DB snapshot |
| Warm   | with `lightSyncState`         | preloaded `databaseContent` | spawned from DB snapshot |

- **Fresh** = current `smoke.rs` behaviour. Full warp sync from genesis against a young chain.
- **Cold** = first visit, but spec carries a checkpoint. Smoldot honours `lightSyncState` and warp-syncs from there to current head.
- **Warm** = returning user. Smoldot resumes from persisted `databaseContent` and warp-syncs the gap to current head.

Note on warm: warp sync still runs in warm. `databaseContent` only persists the latest known finalized header + GrandPa authority set; it does not bridge to the current head. The difference vs fresh is the warp-sync **starting point**, not the presence of warp.

## Chain choice

`westend-local` relay + `people-westend-local` parachain, same as the existing fresh smoke. Keeps the three scenarios comparable (only start state differs). Real runtimes, not synthetic ones — closer to what ships to users.

The `full_node_warp_sync` test in polkadot-sdk uses `rococo-local` + `cumulus-test-runtime`; not adopted here because we want production-shape runtimes.

## Test structure

Three separate `#[tokio::test]` functions, sharing helpers:

- `e2e-tests/tests/smoke_fresh.rs`  — current `smoke.rs` slimmed down
- `e2e-tests/tests/smoke_cold.rs`
- `e2e-tests/tests/smoke_warm.rs`

Reasoning: different setup costs, isolated failure attribution, can run individually via `nextest run -- smoke_warm`.

All three are must-run in CI. Cold/warm depend on snapshot artifacts being available; failures are intentional loud signals, not `#[ignore]`-gated.

## Artifact set

Versioned as a unit. Bumping the version is a single-line change.

```
SNAPSHOT_VERSION = "v1"
```

### Hosted on GCS (large)

Bucket: `zombienet-db-snaps`
Prefix: `zombienet/smoldot_smoke_db/v1/`

- `relaychain-db.tgz`
- `parachain-db.tgz`

URLs:
- `https://storage.googleapis.com/zombienet-db-snaps/zombienet/smoldot_smoke_db/v1/relaychain-db.tgz`
- `https://storage.googleapis.com/zombienet-db-snaps/zombienet/smoldot_smoke_db/v1/parachain-db.tgz`

### Committed in repo (small)

Under `e2e-tests/artifacts/v1/`:

- `relay-spec.json`            — westend-local raw spec with `lightSyncState`
- `para-spec.json`             — people-westend-local raw spec with `lightSyncState`
- `smoldot-db-relay.json`      — `client.databaseContent(relay)` output
- `smoldot-db-para.json`       — `client.databaseContent(para)` output

Specs and smoldot-db JSONs are produced together with the GCS tarballs and must match. Mismatch surfaces as a sync failure — that is the right signal.

### Local override (dev)

Env vars skip the GCS download and SHA check:

- `DB_SNAPSHOT_RELAY_OVERRIDE` — path to local `relaychain-db.tgz`
- `DB_SNAPSHOT_PARA_OVERRIDE`  — path to local `parachain-db.tgz`

Mirrors polkadot-sdk's `full_node_warp_sync` convention.

## Rust helper surface

New module `e2e-tests/src/network.rs` (or extend `lib.rs`):

```rust
pub enum StartMode {
    Fresh,
    FromSnapshot { relay_db_tgz: PathBuf, para_db_tgz: PathBuf },
}

pub enum SpecMode {
    Vanilla,
    WithLightSyncState { relay: PathBuf, para: PathBuf },
}

pub enum SmoldotState {
    None,
    FromDb { relay_db_json: PathBuf, para_db_json: PathBuf },
}

pub struct ScenarioConfig {
    pub start: StartMode,
    pub spec: SpecMode,
    pub smoldot: SmoldotState,
}

pub struct LiveNetwork {
    pub network: zombienet_sdk::Network<LocalFileSystem>,
    pub relay_spec: PathBuf,
    pub para_spec: PathBuf,
    pub finalized_floor: u64,
}

pub async fn spawn_scenario(cfg: &ScenarioConfig) -> Result<LiveNetwork, anyhow::Error>;

pub async fn run_smoke_js(
    live: &LiveNetwork,
    cfg: &ScenarioConfig,
    required_blocks: u32,
) -> Result<(), anyhow::Error>;
```

Behaviour of `spawn_scenario`:

1. Build `NetworkConfig`. For `FromSnapshot`, attach `with_db_snapshot()` per node (mirror `full_node_warp_sync/common.rs`). For `Fresh`, current `smoke.rs:46-77` shape.
2. Spawn, `wait_until_is_up`.
3. For `Fresh`, run the existing `WARP_SYNC_GAP` wait against `validator-0`. Skipped for snapshot starts (history is already aged).
4. Resolve `relay_spec` / `para_spec`:
   - `Vanilla` → zombienet-emitted JSON from `network.base_dir()`.
   - `WithLightSyncState { relay, para }` → use the artifact specs as-is.
5. Compute `finalized_floor`:
   - Fresh: `0`.
   - Cold:  `lightSyncState.finalized_block_height` parsed from the spec.
   - Warm:  `max(lightSyncState height, finalized height encoded in the smoldot-db JSON)`.

New module `e2e-tests/src/snapshot.rs`:

```rust
pub const ARTIFACTS_VERSION: &str = "v1";

const GCS_BASE: &str =
    "https://storage.googleapis.com/zombienet-db-snaps/zombienet/smoldot_smoke_db";
const RELAY_DB_URL: &str = /* GCS_BASE/v1/relaychain-db.tgz */;
const PARA_DB_URL:  &str = /* GCS_BASE/v1/parachain-db.tgz  */;
const RELAY_DB_SHA256: &str = "<filled when v1 is generated>";
const PARA_DB_SHA256:  &str = "<filled when v1 is generated>";

pub fn relay_db() -> Result<PathBuf, anyhow::Error>;  // override env -> cache -> download+sha-verify
pub fn para_db()  -> Result<PathBuf, anyhow::Error>;
pub fn relay_spec() -> PathBuf;                       // committed artifact
pub fn para_spec()  -> PathBuf;
pub fn smoldot_db_relay() -> PathBuf;                 // committed artifact
pub fn smoldot_db_para()  -> PathBuf;
```

## JS smoke harness changes

`e2e-tests/js/smoke.js` gains three optional behaviours, all controlled by env:

- `SMOLDOT_DB_RELAY` / `SMOLDOT_DB_PARA` — paths read into `databaseContent` and forwarded to `addChain` (warm).
- `FINALIZED_FLOOR` — number; on the `chainHead_v1_follow` `initialized` event, fetch the first finalised header and assert `header.number >= FINALIZED_FLOOR`. Fresh runs with `0` (no-op).
- `SMOLDOT_DB_DUMP_DIR` — generator-only. After seeing the required blocks, write `client.databaseContent(relay)` and `client.databaseContent(para)` into the dir.

`e2e-tests/js/helpers.js`: `addChainFromSpec` forwards a `databaseContent` option (one-line spread of `opts`).

## Env-var matrix passed to `js/smoke.js`

| Env | Fresh | Cold | Warm |
|---|---|---|---|
| `RELAY_CHAIN_SPEC` | zombienet-emitted | artifact spec | artifact spec |
| `PARA_CHAIN_SPEC`  | zombienet-emitted | artifact spec | artifact spec |
| `REQUIRED_BLOCKS`  | 5 | 5 | 5 |
| `FINALIZED_FLOOR`  | 0 | from spec | from db json |
| `SMOLDOT_DB_RELAY` | — | — | committed json |
| `SMOLDOT_DB_PARA`  | — | — | committed json |

## Snapshot generator

`e2e-tests/src/bin/generate_snapshots.rs`. Manual / scheduled job, never invoked from `cargo test`.

Outline:

1. Spawn `westend-local` + `people-westend-local` from genesis with **archive pruning** on the nodes whose DBs will be snapshotted.
2. `wait_until_is_up`, then poll relay finalised height until `--target-finalized` (default ≥1500 — past 2 sessions, covers an authority-set rotation).
3. Pause all relay validators and parachain collators.
4. `tar -czf {out}/relaychain-db.tgz` over each snapshot-source node's data dir under `network.base_dir()`. Same for parachain.
5. Call `state_genSyncSpec(true)` (substrate JSON-RPC) against a still-RPC-reachable full node. Write returned spec — already raw, already containing `lightSyncState` — to `{out}/relay-spec.json`. Repeat for parachain.
6. Resume one relay node + one collator. Run `js/smoke.js` with `SMOLDOT_DB_DUMP_DIR={out}/smoldot-db`, `REQUIRED_BLOCKS=5`. JS dumps `relay.json` / `para.json`.
7. Print manifest: file list + sha256s + the `SNAPSHOT_VERSION` string the test code should pin.

A `generate-snapshots.sh` wrapper handles `cargo build` + invocation + GCS upload. Upload step is manual — generator binary never pushes to GCS itself.

## Regeneration procedure

When runtimes change in a way that breaks the pinned snapshots:

1. Bump `ARTIFACTS_VERSION` in code (e.g. `v1` → `v2`).
2. Run `generate-snapshots.sh` locally. Inspect the manifest.
3. Upload the two `.tgz` files to `gs://zombienet-db-snaps/zombienet/smoldot_smoke_db/v2/`.
4. Replace committed artifacts under `e2e-tests/artifacts/v2/`.
5. Update `RELAY_DB_SHA256` / `PARA_DB_SHA256` in `snapshot.rs`.
6. Delete the previous `e2e-tests/artifacts/v{N-1}/` dir.

## CI integration

Existing setup (`.github/workflows/zombienet.yml` + `.github/zombienet-env`):

- GitHub Actions, Parity self-hosted runners (`parity-zombienet-native-default` / `-large`).
- Tests run inside the `paritytech/ci-unified` container.
- `actions/cache@v4` already used for cargo registry/target and JS `node_modules`. Keys derived via `hashFiles(...)` of relevant lockfiles.
- 4-job matrix: `smoke` + 3 statement-store tests.

### Cache strategy

Add one cache step to the test job, before "Run test":

```yaml
- name: Cache smoldot e2e snapshots
  uses: actions/cache@v4
  with:
    path: ~/.cache/smoldot-e2e
    key: smoldot-e2e-snapshots-${{ hashFiles('e2e-tests/src/snapshot.rs') }}
```

- Key derived from `snapshot.rs` — bumping `ARTIFACTS_VERSION` or any SHA constant invalidates the cache automatically. Same pattern as the existing cargo-cache step.
- Path is inside the container's `~`. Container filesystem is ephemeral per job, so the explicit cache step is needed even on self-hosted runners.
- Matrix-wide step. Statement-store jobs never touch the path; their cache save is empty/no-op.
- No `restore-keys`: a stale partial restore could mask a SHA mismatch.

Test matrix grows by two entries (`smoke_cold`, `smoke_warm`); rename existing `smoke` → `smoke_fresh` for symmetry.

### Zombienet-sdk caching — confirmed not sufficient

Inspected `zombienet-provider-0.4.9/src/native/node.rs:278-337` (`initialize_db_snapshot`):

- Tarball stored at `{namespace_base_dir}/{sha256(URL_or_path)}.tgz`. Skipped if present.
- `namespace_base_dir` is per-spawn → no cross-run reuse.
- No SHA verification of contents — only the URL string is hashed for the cache-path key.
- `ZOMBIE_RM_TGZ_AFTER_EXTRACT=1` deletes the tarball post-extract.

So the explicit `actions/cache@v4` step is needed, and our resolver should:

1. Download the tarball into `~/.cache/smoldot-e2e/{ARTIFACTS_VERSION}/{relaychain-db,parachain-db}.tgz` if missing.
2. Verify SHA256 against the pinned constant (zombienet doesn't).
3. Hand the local path to `with_db_snapshot()` via `AssetLocation::FilePath(...)`, not the URL.

## Landing sequence

1. Helpers + JS changes + refactor existing smoke onto the new shape. Verifiable now — fresh path passes, no snapshots required.
2. Run the generator binary locally → produce v1 artifact set.
3. Commit specs + smoldot-db JSONs under `artifacts/v1/`. Upload tarballs to GCS. Pin SHAs and `ARTIFACTS_VERSION` in `snapshot.rs`.
4. Add `smoke_cold` + `smoke_warm` tests + workflow cache step + matrix entries.
5. Short README under `e2e-tests/artifacts/` documenting regen.

## Open items

- Confirm write access to `gs://zombienet-db-snaps/`.
- Future: add a 4th case exercising a runtime upgrade scheduled mid-snapshot-generation.
