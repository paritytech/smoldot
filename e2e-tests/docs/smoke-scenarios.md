# Smoldot smoke-test scenarios

Three smoke tests exercise distinct smoldot startup conditions:

| Test            | Network                | Smoldot spec                              | Smoldot DB                |
|-----------------|------------------------|-------------------------------------------|---------------------------|
| `smoke_fresh`   | spawned from genesis   | vanilla                                   | none                      |
| `smoke_cold`    | spawned from snapshot  | with `lightSyncState` + `stateRootHash`   | none                      |
| `smoke_warm`    | spawned from snapshot  | with `lightSyncState` + `stateRootHash`   | preloaded `databaseContent` |

Cold/warm both rely on smoldot's real warp sync (gap from `lightSyncState` to current head exceeds `warp_sync_minimum_gap=32`) so authority-set rotations along the way are handled by warp-sync proof fragments.

Chain: `westend-local` relay + `people-westend-local` parachain. Same as fresh, so all three scenarios are directly comparable.

## Artifact layout

Everything ships in a single self-contained `BundleBuilder` bundle on GCS:

```
gs://zombienet-db-snaps/zombienet/smoldot_smoke_db/{ARTIFACTS_VERSION}/bundle.tar.gz
```

Contains:

- `relaychain-db-{i}.tgz` (one per relay validator), `parachain-db.tgz` — node DB snapshots produced by `NetworkNode::snapshot_db` (excludes `keystore/` + `network/`). Every relay validator is snapshotted (element `i` restored onto `validator-i`) so all erasure chunks and every backing group's full data survive the restore, letting availability recovery reconstruct candidates that were in flight at snapshot time. The parachain tarball also carries the collator's embedded relay node DB (`relay-data/`).
- `manifest.json` — `SnapshotManifest` with per-archive checksums and a `user_data` blob holding every non-tarball artifact (all JSON, inlined). `BundleBuilder` only packs `NodeSnapshot` tarballs as files, so these ride in `user_data`:
  - `relay_full_spec`, `para_full_spec` — full chain specs (with `genesis.raw`, loaded by substrate)
  - `relay_spec_light_sync_state`, `para_spec_light_sync_state` — slim smoldot specs (`genesis.stateRootHash` instead of `genesis.raw`)
  - `smoldot_db_relay`, `smoldot_db_para` — `chainHead_unstable_finalizedDatabase` dumps for warm

  The consumer (`snapshot::materialize`) writes each back out to disk by key on first use. The bundle SHA pins the full specs to the exact genesis the DB snapshot was built against — nothing is committed to the repo.

`ARTIFACTS_VERSION` and `BUNDLE_SHA256` live in `e2e-tests/src/snapshot.rs`. On first use the bundle is downloaded into `~/.cache/smoldot-e2e/{ARTIFACTS_VERSION}/`, SHA-verified, and extracted in place.

For local iteration: `ARTIFACTS_DIR_OVERRIDE=/path/to/dir` skips download/verify and reads the loose files directly from the generator output directory.

## Regenerating the artifact bundle

Triggered when:
- Runtime/binary changes invalidate the snapshot DB (genesis hash mismatch or block-format break).
- Adjusting `--target-finalized` / `--spec-at-finalized` to change the warp-sync gap or chain age.
- Upgrading smoldot in a way that changes its `databaseContent` format.

Steps (from `e2e-tests/`):

1. **Bump version** in `src/snapshot.rs`:
   ```rust
   pub const ARTIFACTS_VERSION: &str = "v2";   // or whatever
   ```

2. **Run the generator test** to produce a fresh bundle. Either start from genesis (~3 h for `TARGET_FINALIZED=2000`) or resume from an existing source DB (~50 min):

   ```bash
   # from genesis:
   ZOMBIE_PROVIDER=native \
   SMOKE_SNAPSHOT_OUT=/tmp/smoldot-snap-v2 \
   SMOKE_SNAPSHOT_TARGET_FINALIZED=2500 \
   SMOKE_SNAPSHOT_SPEC_AT_FINALIZED=1250 \
   cargo test --release --test smoke_generate_snapshots -- --ignored --nocapture

   # or resume:
   ZOMBIE_PROVIDER=native \
   SMOKE_SNAPSHOT_OUT=/tmp/smoldot-snap-v2 \
   SMOKE_SNAPSHOT_TARGET_FINALIZED=2000 \
   SMOKE_SNAPSHOT_SPEC_AT_FINALIZED=1525 \
   SMOKE_SNAPSHOT_RELAY_DB=/path/to/old/relaychain-db.tgz \
   SMOKE_SNAPSHOT_PARA_DB=/path/to/old/parachain-db.tgz \
   cargo test --release --test smoke_generate_snapshots -- --ignored --nocapture
   ```

   Required: `ZOMBIE_PROVIDER=native`, polkadot/polkadot-parachain on `PATH`. The module-level docstring in `tests/smoke_generate_snapshots.rs` lists every env var.

   It produces a self-contained `bundle.tar.gz` under `SMOKE_SNAPSHOT_OUT` and prints the bundle SHA256.

3. **Verify locally** before publishing:

   ```bash
   ARTIFACTS_DIR_OVERRIDE=/tmp/smoldot-snap-v2 cargo test --test smoke_cold -- --nocapture
   ARTIFACTS_DIR_OVERRIDE=/tmp/smoldot-snap-v2 cargo test --test smoke_warm -- --nocapture
   ```

   Both must pass. If they don't, it's almost certainly the chain spec / runtime version or the `--spec-at-finalized` choice — fix and retry before uploading.

4. **Publish**:
   ```bash
   gsutil cp /tmp/smoldot-snap-v2/bundle.tar.gz \
     gs://zombienet-db-snaps/zombienet/smoldot_smoke_db/v2/bundle.tar.gz
   ```

5. **Pin the new SHA** in `src/snapshot.rs` (copy the value from the generator manifest):
   ```rust
   const BUNDLE_SHA256: &str = "<hash>";
   ```

6. **CI cache key** invalidates automatically — the workflow's cache step keys on `hashFiles('e2e-tests/src/snapshot.rs')`, so bumping the constant is enough.

7. Commit the bumped version + SHA, open PR, run cold/warm tests in CI to confirm the GCS download + extract path works end-to-end.

## Notes on common pitfalls

- **Sibling nodes with identical session keys equivocate.** `NetworkNode::snapshot_db` excludes `keystore/` (and `network/`); zombienet inserts per-node keys via `author_insertKey` after startup. Don't reintroduce keystore into the snapshot.
- **Full specs must match the DB genesis.** The `*_full_spec` blobs in the bundle pin the genesis (including the elastic-scaling `scheduler_params` override) the DB snapshot was generated against. They're regenerated with the bundle, so a version bump keeps them in lockstep — no stale committed spec can drift from the DB.
- **Same tarball path passed to multiple zombienet nodes** triggers a TOCTOU race in zombienet-provider's `with_db_snapshot` cache. The generator and `network::stage_per_node_snapshots` work around this by copying the tarball once per consuming node.
- **Spec-at-finalized too close to target-finalized**: gap ≤ 32 means smoldot uses follow-forward instead of warp sync, which can't traverse GRANDPA rotations. Default `M = N/2` keeps it safe.
- **Bootnode multiaddrs are per-spawn** (zombienet picks free ports). The committed specs ship with empty `bootNodes`; `network::prepare_runtime_specs` injects current multiaddrs into a runtime copy before handing the spec to smoldot.
