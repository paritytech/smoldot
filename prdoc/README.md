# prdoc

Each PR with a user-visible change adds `prdoc/pr_<PR number>.prdoc`. The
release writes `wasm-node/CHANGELOG.md` from these files, so PRs never edit
`CHANGELOG.md` and never conflict on it.

## Format

```yaml
changes:
  - section: fixed # added | changed | fixed | removed
    description: |
      A `chainHead_v1_storage` call now gives back every operation slot it took.
  - section: added
    description: |
      A PR can have more than one entry.
fixes: [3393]   # optional, issues the PR closes
related: [3412] # optional, issues the PR only touches
```

Start from `prdoc/.template.prdoc`. The PR number is known only once the PR is
open, so add the file after opening it.

Validate locally (needs PyYAML):

```sh
python3 .github/scripts/prdoc.py check
```

## No changelog entry

Add the `no-changelog` label to PRs without a user-visible change: refactors,
tests, CI, docs, dependency bumps with no effect for users. Dependabot PRs are
skipped automatically. Release PRs also carry the label.

## CI

`.github/workflows/check-prdoc.yml` fails a PR when:

- `prdoc/pr_<PR number>.prdoc` is missing or invalid, unless the PR has the
  `no-changelog` label.
- The PR edits `wasm-node/CHANGELOG.md` without the `no-changelog` label.

On failure it posts a comment on the PR explaining the fix, with a link that
creates the file from the template. The comment is updated on each run and
deleted once the check passes.

The workflow uses `pull_request_target`, so it can comment on PRs from forks.
It runs the version of the workflow and scripts from `main` and never checks
out the PR's code: it reads the PR's files through the GitHub API. Changes to
these files take effect only once merged.

## Release

`python3 .github/scripts/prdoc.py release <X.Y.Z>` inserts the new section under
`## Unreleased` in `wasm-node/CHANGELOG.md` and deletes the files. Git history
keeps them. See `docs/RELEASING.md`.
