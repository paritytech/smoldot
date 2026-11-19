# prdoc

Each PR with a user-visible change adds a `prdoc/<name>.prdoc` file. The
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

Start from `prdoc/.template.prdoc`. The name must match
`[a-z0-9][a-z0-9._-]*.prdoc`. Pick a short descriptive name or the branch name,
so it doesn't clash with another PR. The file can be pushed together with the
code, before the PR exists: at release, the PR number is read from the subject
of the commit that added the file (`... (#1234)` for squash merges). A file
named `pr_<PR number>.prdoc` uses that number directly.

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

- The PR adds no `prdoc/<name>.prdoc` file, or one of its prdoc files is
  invalid, unless the PR has the `no-changelog` label.
- The PR edits `wasm-node/CHANGELOG.md` without the `no-changelog` label.
- The PR deletes or renames a prdoc file that is already on `main`, without
  the `no-changelog` label.
- The PR adds a `pr_<N>.prdoc` file where `N` is not this PR's number.

A description must be one paragraph without lists, since it becomes one
CHANGELOG line.

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
