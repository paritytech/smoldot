# Publishing a dev build

Manual npm publish for testing. **Never moves `latest`.** No version commit needed.

## Prepare a branch

- Create or check out a branch off whatever base you want to publish from.
- Commit and push the changes you want in the dev build. The branch does not
  need a bumped `package.json` / `Cargo.toml` — the workflow handles versions.

## Trigger

- Open the workflow page:
  <https://github.com/paritytech/smoldot/actions/workflows/deploy.yml>
- Click **Run workflow**
- Select your branch
- `npm_tag_suffix`: short label (e.g. `smoke`), or leave blank
- Click **Run workflow**

## What you get

| Input | Published version | Dist-tag |
|---|---|---|
| `suffix = smoke` | `<next-patch>-dev.<YYYYMMDD>.smoke.<N>` | `dev-<YYYYMMDD>-smoke` |
| blank | `<next-patch>-dev.<YYYYMMDD>.<N>` | `dev-<YYYYMMDD>` |

Example, dispatched 2026-04-22 while stable is `3.1.1`, suffix `smoke`:
- Version: `3.1.2-dev.20260422.smoke.0`
- Dist-tag: `dev-20260422-smoke`

Rules of thumb:
- **`N` counter** — `0` on the first dispatch of a new `(next-patch, date, suffix)`; `+1` on every subsequent dispatch, including "Re-run jobs".
- **Dist-tag follows the latest publish** in that tuple. Earlier versions stay installable by exact version.
- **Version bumps patch only** (never minor/major).

## Install

```sh
npm install smoldot@dev-20260422-smoke            # follow the tag (moves)
npm install smoldot@3.1.2-dev.20260422.smoke.0    # pin to exact (immutable)
```

Full release flow: see [`RELEASING.md`](./RELEASING.md).
