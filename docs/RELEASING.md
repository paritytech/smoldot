# Releasing smoldot

Runbook for cutting a release of the smoldot **npm package** and the Rust crates
(`smoldot`, `smoldot-light`). Written to be mechanical enough to automate.

---

## 0. What a release actually ships

`deploy.yml` runs on **every** push to `main`, but only a version-bumping push
produces new published artifacts. Non-bumping pushes are idempotent: npm
rejects duplicate versions, `crates-io-publish` absorbs the "already uploaded"
error (`continue-on-error: true`), and the Deno tag is created only if
missing. So the release is effectively keyed on the version bump, not the
merge itself.

A version-bumping release commit drives four outputs:

| Output | Job in `.github/workflows/deploy.yml` |
|---|---|
| npm package `smoldot` | `npm-publish` (dispatches `paritytech/npm_publish_automation`) |
| Deno git-tag `light-js-deno-v<npm>` | `deno-publish` (creates tag if missing) |
| crates.io `smoldot` | `crates-io-publish` (runs `cargo publish --no-verify`; `continue-on-error: true`) |
| crates.io `smoldot-light` | `crates-io-publish` (same) |
| Docs (gh-pages) | `docs-publish` (force-pushes fresh tree every run, regardless of version) |

Three git tags are created **manually** on the release commit after merge:
`npm-smoldot-v<X.Y.Z>`, `smoldot-v<A.B.C>`, `smoldot-light-v<A.B.C>`. Create
only the ones whose version actually changed. The `light-js-deno-v<X.Y.Z>` tag
is created by CI, not manually.

---

## 1. Decide version bumps

Check what changed since the last release tag (usually `npm-smoldot-v<prev>`):

```sh
git log --oneline <prev-tag>..HEAD
git diff --stat <prev-tag>..HEAD -- lib/ light-base/ wasm-node/ full-node/
```

Apply these rules per package:

| Package | Version file | Bump iff… |
|---|---|---|
| `smoldot` (rust lib) | `lib/Cargo.toml` | any commit touched `lib/` since last publish |
| `smoldot-light` (rust) | `light-base/Cargo.toml` | any commit touched `light-base/` since last publish |
| `smoldot-light-wasm` | `wasm-node/rust/Cargo.toml` | bump whenever the npm package bumps (mirrors npm version; `publish = false` so it is metadata only) |
| `smoldot` (npm) | `wasm-node/javascript/package.json` | any commit that reaches the Wasm artifact — i.e. changes to `lib/`, `light-base/`, `wasm-node/` |

Why `lib/` or `light-base/` alone forces an npm bump:
`wasm-node/javascript/prepare.mjs` compiles `smoldot-light-wasm` at pack time.
That crate path-depends on `smoldot-light` → `smoldot`, so any change in
`lib/` or `light-base/` ends up in the embedded `.wasm` (base64'd into
`src/internals/bytecode/*.ts`) even when `wasm-node/` itself is untouched.

Semver level:

- `fix(...)` / bug-fix only → **patch**
- `feat(...)` or new public API → **minor**
- Breaking API change → **major**

Version streams are independent; do not force lockstep. `crates-io-publish`
wraps each publish in `continue-on-error: true`, so a re-publish attempt at
the same version is tolerated.

---

## 2. Open a release branch

```sh
git checkout -b release/npm-smoldot-v<X.Y.Z>
```

The `release/` prefix is required: the post-merge tag will be
`npm-smoldot-v<X.Y.Z>`, so the branch must not share that exact name (git
resolves tags before branches and ambiguous refs break `git push`, `git
checkout`, etc.). The branch follows the npm version even when the rust crate
versions differ.

---

## 3. Edit the version files

Edit exactly these fields (do not edit anything else in the same commit):

1. `wasm-node/javascript/package.json` — `"version": "<X.Y.Z>"`
2. `wasm-node/rust/Cargo.toml` — `version = "<X.Y.Z>"` *(mirror npm)*
3. `lib/Cargo.toml` — `version = "<A.B.C>"` *(if bumping `smoldot`)*
4. `light-base/Cargo.toml` — `version = "<A.B.C>"` *(if bumping `smoldot-light`)*

**Path-dep `version` strings: bump only on major crosses.** Leave the
`version = "..."` on `smoldot` / `smoldot-light` path-deps in
`full-node/Cargo.toml`, `light-base/Cargo.toml`, and `wasm-node/rust/Cargo.toml`
alone on patch and minor releases. Bump them only when the dep crosses a major
boundary (e.g. `smoldot 1.x.y` → `2.0.0`). Rationale: the `path` resolves the
source locally regardless of the string; the string is a tripwire that only
needs to track the current compatibility range, not the exact version.

**CI-enforced invariant:** `wasm-node/javascript/package.json` `.version` and
`wasm-node/rust/Cargo.toml` `[package].version` must match exactly. The
`wasm-node-versions-match` job fails the build on any mismatch.

---

## 4. Regenerate lockfiles

```sh
cargo check -p smoldot -p smoldot-light        # updates Cargo.lock
cd wasm-node/javascript && npm install --package-lock-only && cd -
```

Both lockfiles must diff to version bumps only. If either pulls in unrelated
updates, abort and investigate.

---

## 5. Update `wasm-node/CHANGELOG.md`

Insert a new section **below** the `## Unreleased` heading (leave `Unreleased`
in place). Use the current date in `YYYY-MM-DD`. Group entries under
`### Added` / `### Changed` / `### Fixed` / `### Removed`. Each bullet must
link to its PR.

Template:

```md
## <X.Y.Z> - <YYYY-MM-DD>

### Fixed

- <user-facing description>. ([#<PR>](https://github.com/paritytech/smoldot/pull/<PR>))
```

Rules of thumb:

- Describe the observable change, not the code path.
- Skip internal refactors, test-only changes, CI tweaks, and doc updates.

---

## 6. Verify locally

Required:

```sh
cargo check -p smoldot -p smoldot-light
```

Optional dry-runs:

```sh
cargo publish --dry-run --locked -p smoldot
```

Run this every release; it only validates packaging and local build.

```sh
cargo publish --dry-run --locked -p smoldot-light
```

Run this **only if `smoldot` is not being bumped**. Otherwise it fails on
`smoldot` path-dep resolution against crates.io — harmless

---

## 7. Commit and push the release branch

```sh
git add lib/Cargo.toml light-base/Cargo.toml wasm-node/rust/Cargo.toml \
        wasm-node/javascript/package.json wasm-node/javascript/package-lock.json \
        wasm-node/CHANGELOG.md Cargo.lock
git --no-gpg-sign commit -m "npm smoldot v<X.Y.Z>"
git push origin release/npm-smoldot-v<X.Y.Z>
```

Open a PR. Body template:

```md
This is to:
- publish `smoldot-v<X.Y.Z>` npm.
- publish crates `smoldot-light v<A.B.C>`[, `smoldot v<A.B.C>`]

## Changes

[Paste the CHANGELOG entries.]
```

Past PRs for reference: #3208 (3.1.0), #3166 (3.0.0). Only list crates that
are actually bumped.

---

## 8. Beg for approval

Ping reviewers. Address review comments. Wait for the required approvals per
branch protection. This is the slowest step and the least automatable.

---

## 9. Merge to `main`

Squash-merge. Record the resulting commit SHA on `main` — tags will point at it.

---

## 10. Sanity check after deployment job is finished

Once the `deploy.yml` run on the release commit completes, perform these steps:

```sh
# npm package
npm view smoldot@<X.Y.Z>

# crates.io — requires a User-Agent with contact info
curl -sS -A "some-agent" https://crates.io/api/v1/crates/smoldot       | jq .crate.max_version
curl -sS -A "some-agent" https://crates.io/api/v1/crates/smoldot-light | jq .crate.max_version

# Deno tag pushed by CI
git fetch --tags
git tag -l 'light-js-deno-v<X.Y.Z>'
```

Expected quirk: the `crates-io-publish` job's `smoldot` step fails with
"version already exists" when `smoldot` wasn't bumped this release — benign
(`continue-on-error: true`).

---

## 11. Create and push the manual tags

On the release commit SHA (the merged squash on `main`):

```sh
git fetch origin main
git checkout <release-commit-sha>

git tag npm-smoldot-v<X.Y.Z>                # always
git tag smoldot-light-v<A.B.C>              # if smoldot-light bumped
git tag smoldot-v<A.B.C>                    # if smoldot bumped

git push origin \
    npm-smoldot-v<X.Y.Z> \
    [smoldot-light-v<A.B.C>] \
    [smoldot-v<A.B.C>]
```

Tags are lightweight (no `-a`/`-m`). Verify they landed on origin:

```sh
git fetch --tags
git tag -l '*<X.Y.Z>*'   # should list the CI-pushed light-js-deno-v tag plus the manual ones
```

On any post-publish failure, do not delete published versions — yank
(`npm deprecate smoldot@<X.Y.Z> '...'`, `cargo yank --version <A.B.C>`) and
cut a new release.

---

## Appendix A — Manual dev publish

`deploy.yml` has a `workflow_dispatch` trigger with a single input,
`npm_tag_suffix`. Use it to publish a dev build from any branch without
editing `package.json` by hand.

**Trigger.** Actions → "deploy" → "Run workflow" → pick the branch, optionally
enter an `npm_tag_suffix`. The suffix must match `[A-Za-z0-9-]+`. Leave it
blank for a generic dated dev publish.

**What gets published.** The workflow rewrites `wasm-node/javascript/package.json`
and `wasm-node/rust/Cargo.toml` in-memory to a computed version, packs, and
dispatches to `npm_publish_automation`. Nothing is committed back to git.

- **Version** always bumps patch — never minor or major
- **With suffix** (e.g. `test123`):
  - Version: `<next-patch>-dev-<YYYYMMDD>-<suffix>.<N>` → `3.1.2-dev-20260422-test123.0`
  - Dist-tag: `dev-<YYYYMMDD>-<suffix>` → `dev-20260422-test123`
- **Without suffix** (blank):
  - Version: `<next-patch>-dev-<YYYYMMDD>.<N>` → `3.1.2-dev-20260422.0`
  - Dist-tag: `dev-<YYYYMMDD>` → `dev-20260422`
- **`N` counter** auto-increments. The workflow queries `npm view --json
  smoldot versions` for prior publishes matching the prefix and uses
  `max(N) + 1`. First dispatch of a new tuple starts at `0`.

**Install a dev build:**

```sh
npm install smoldot@dev-20260422-test123   # by dist-tag (moves with each publish)
npm install smoldot@3.1.2-dev-20260422-test123.0   # by exact version (immutable)
```

**Every dispatch gets a fresh version.** `N` is derived from npm state, not
from a workflow-run counter, so any dispatch (fresh or "Re-run jobs" after a
successful publish) queries npm and publishes `N+1`. To publish new code,
push your commits and dispatch again. Reruns reuse the same version *only* if
the first attempt failed before reaching the publish step (nothing on npm
yet) — in which case the next dispatch computes the same `N` and retries.

**Why the dist-tag can't be `latest`.** The final dist-tag always starts with
`dev-<YYYYMMDD>`. Suffix validation rejects anything outside `[A-Za-z0-9-]`.
Even `suffix=""` produces `dev-<YYYYMMDD>`, not `latest`.

## Appendix B — Files for future automation

- Version reads: `wasm-node/javascript/package.json` (`.version`),
  `lib/Cargo.toml`, `light-base/Cargo.toml`, `wasm-node/rust/Cargo.toml`
  (each `package.version`).
- Version writes: same four, plus `wasm-node/javascript/package-lock.json`
  (two occurrences) and `Cargo.lock` (regenerate via `cargo check`).
- Changelog: insert new section in `wasm-node/CHANGELOG.md` between
  `## Unreleased` and the previous version heading.
- Scope detection: `git diff --stat <prev-tag>..HEAD -- <path>` for
  `lib/`, `light-base/`, `wasm-node/`.
- Commit message: `npm smoldot v<X.Y.Z>`.
- Tags (lightweight): `npm-smoldot-v<X.Y.Z>`, `smoldot-light-v<A.B.C>`,
  `smoldot-v<A.B.C>`.
