---
description: Cut a smoldot release per docs/RELEASING.md
argument-hint: [next-npm-version]
---

Drive a release of the smoldot npm package and Rust crates by following
@docs/RELEASING.md verbatim. That file is the source of truth — read it
fully before doing anything, and prefer its instructions over your
memory of past releases.

## Operating rules

- Read `docs/RELEASING.md` first. If it has changed since you last saw
  it, the changes win.
- Walk the user through steps 1–11 in order. Pause for explicit
  confirmation before any shared-state action (commit, push).
- Step 1: use `git log --oneline <prev-tag>..HEAD` and
  `git diff --stat <prev-tag>..HEAD -- lib/ light-base/ wasm-node/ full-node/`
  to detect which packages need bumping. Propose the bump levels via
  `AskUserQuestion` and wait for confirmation.
- Step 4: regenerate all three Cargo lockfiles (root + `e2e-tests/` +
  `benchmarks/`) plus `wasm-node/javascript/package-lock.json`. Diff
  each lockfile and confirm the only changes are the version bumps —
  unrelated drift means a lockfile was already stale on `main`; stop
  and surface it.
- Step 5: insert the new section *below* `## Unreleased`. Skip
  test-only / CI / docs / internal-refactor commits from the changelog.
  Read the actual PR diffs before classifying entries; PR titles can
  mislead (e.g. `wasm32v1-unknown` in title vs `wasm32v1-none` in code).
- Step 6: run `cargo publish --dry-run --locked --allow-dirty -p smoldot`.
  Skip the `smoldot-light` dry-run when `smoldot` is also being bumped
  (it fails on path-dep resolution against crates.io).
- Step 7 (commit): stage the nine files listed in the doc yourself, then
  show the staged diff stat and the exact commit message
  (`npm smoldot v<X.Y.Z>`) and let the user run `git commit` in their own
  shell. smoldot's branch protection on `main` rejects unsigned commits
  and this session cannot sign, so the commit itself must come from the
  user.
- Pushing the release branch: the user runs `git push` in their own shell
  (SSH keys live there, not in this session). Print the exact command
  and wait for them to confirm.
- Step 10: before sanity-checking, verify the `deploy.yml` run for the
  merge SHA completed via `gh run list --workflow=deploy.yml --branch=main`.
- Step 11: tags are pushed automatically by the `tags-publish` and
  `deno-publish` jobs. Verify only — don't push any tags manually.

## Announcement

After step 11 succeeds, draft an announcement in this exact shape:

```
smoldot-v<X.Y.Z> is out - https://www.npmjs.com/package/smoldot/v/<X.Y.Z>

[Changelog](https://github.com/paritytech/smoldot/blob/<merge-sha>/wasm-node/CHANGELOG.md#<anchor>)
```

The anchor is the changelog heading lowercased, with dots stripped and
` - ` (space-dash-space) becoming `---`. Example:
`## 3.1.3 - 2026-05-13` → `#313---2026-05-13`.

## Arguments

Optional target npm version (e.g. `3.1.3`): $ARGUMENTS — if provided,
use it as the new npm version after sanity-checking that it's a
reasonable bump from the current `wasm-node/javascript/package.json`
`.version`; otherwise compute the bump from scope detection.
