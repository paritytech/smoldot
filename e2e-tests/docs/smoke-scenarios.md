# Smoldot smoke-test scenarios

Three smoke tests exercise distinct smoldot startup conditions:

| Test            | Network                | Smoldot spec                              | Smoldot DB                |
|-----------------|------------------------|-------------------------------------------|---------------------------|
| `smoke_fresh`   | spawned from genesis   | vanilla                                   | none                      |
| `smoke_cold`    | spawned from snapshot  | with `lightSyncState` + `stateRootHash`   | none                      |
| `smoke_warm`    | spawned from snapshot  | with `lightSyncState` + `stateRootHash`   | preloaded `databaseContent` |

Cold/warm both rely on smoldot's real warp sync (gap from `lightSyncState` to current head exceeds `warp_sync_minimum_gap=32`) so authority-set rotations along the way are handled by warp-sync proof fragments.

Chain: `westend-local` relay + `people-westend-local` parachain. Same as fresh, so all three scenarios are directly comparable.

## Artifact bundle

Single GCS object per version:

```
gs://zombienet-db-snaps/zombienet/smoldot_smoke_db/{ARTIFACTS_VERSION}/bundle.tar.gz
```

Contains:

- `relaychain-db.tgz`, `parachain-db.tgz` — node DB snapshots; keystore stripped
- `relay-spec.json`, `para-spec.json` — full chain specs (substrate side)
- `relay-spec-lightSyncState.json`, `para-spec-lightSyncState.json` — slim chain specs (smoldot side, `genesis.stateRootHash` instead of `genesis.raw`)
- `smoldot-db/relay.json`, `smoldot-db/para.json` — `chainHead_unstable_finalizedDatabase` dumps for warm

`ARTIFACTS_VERSION` and `BUNDLE_SHA256` live in `e2e-tests/src/snapshot.rs`. On first use the bundle is downloaded into `~/.cache/smoldot-e2e/{ARTIFACTS_VERSION}/`, SHA-verified, and extracted in place.

For local iteration: `ARTIFACTS_DIR_OVERRIDE=/path/to/dir` skips download/verify and uses files directly from that directory.

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

2. **Build the generator** and **run it** to produce a fresh bundle. Either start from genesis (~3 h for `--target-finalized=2000`) or resume from an existing source DB (~50 min):

   ```bash
   cargo build --release --bin generate_snapshots

   # from genesis:
   ./target/release/generate_snapshots \
     --out /tmp/smoldot-snap-v2 \
     --target-finalized 2000

   # or resume:
   ./target/release/generate_snapshots \
     --out /tmp/smoldot-snap-v2 \
     --target-finalized 2000 --spec-at-finalized 1525 \
     --relay-db-snapshot /path/to/old/relaychain-db.tgz \
     --para-db-snapshot  /path/to/old/parachain-db.tgz
   ```

   Required: `ZOMBIE_PROVIDER=native`, polkadot/polkadot-parachain on `PATH`. The generator's `--help` lists all flags.

   It produces `bundle.tar.gz` under `--out` and prints the SHA256 in the manifest at the end.

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

7. Commit, open PR, run cold/warm tests in CI to confirm GCS download + extract path works end-to-end.

## Notes on common pitfalls

- **Sibling nodes with identical session keys equivocate.** The generator excludes `keystore/` when tarring; zombienet inserts per-node keys via `author_insertKey` after startup. Don't add keystore back into the snapshot.
- **Same tarball path passed to multiple zombienet nodes** triggers a TOCTOU race in zombienet-provider's `with_db_snapshot` cache. The generator and `network::stage_per_node_snapshots` work around this by copying the tarball once per consuming node.
- **Spec-at-finalized too close to target-finalized**: gap ≤ 32 means smoldot uses follow-forward instead of warp sync, which can't traverse GRANDPA rotations. Default `M = N/2` keeps it safe.
- **Bootnode multiaddrs are per-spawn** (zombienet picks free ports). The committed specs ship with empty `bootNodes`; `network::prepare_runtime_specs` injects current multiaddrs into a runtime copy before handing the spec to smoldot.
