# Publishing a dev build

## How

1. Push your changes to any branch — no `package.json` / `Cargo.toml` bumps
   needed, the workflow handles versions.
2. Open [Actions → deploy → Run workflow](https://github.com/paritytech/smoldot/actions/workflows/deploy.yml),
   pick your branch, optionally enter `npm_tag_suffix` (e.g. `smoke`), click
   **Run workflow**.

## What you get

Examples (dispatched 2026-04-22, stable `3.1.1`):

- `npm_tag_suffix=smoke` → version `3.1.2-dev-20260422-smoke.0`, dist-tag `dev-20260422-smoke`
- `npm_tag_suffix=smoke` again, same day → version `3.1.2-dev-20260422-smoke.1`, dist-tag `dev-20260422-smoke` (moved to `.1`)
- blank `npm_tag_suffix` → version `3.1.2-dev-20260422.0`, dist-tag `dev-20260422`

## Install

```sh
npm install smoldot@dev-20260422-smoke           # follow the tag (moves)
npm install smoldot@3.1.2-dev-20260422-smoke.0   # pin to exact (immutable)
```

Full release flow: [`RELEASING.md`](./RELEASING.md).
