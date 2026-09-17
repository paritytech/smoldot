# Fixed tiny dev chain spec

`dev-chain-spec.json` was generated on 2026-09-23 from PolkaJam commit
`8ceedf46c4828137c8835e4227d7f3a62ada0463`, built with `SKIP_PVM_BUILDS=1`
and the flags in [README.md](README.md). The spec uses six deterministic dev
validators at 127.0.0.1:40000–40005. RPC and HTTP ports are runtime settings
outside the spec. Only one local test/demo network can run at a time.

Every node, including a restarted node, reads this file unchanged. The browser
copy differs only in its combined-identity bootnode; PolkaJam cannot parse that
identity yet (upstream follow-up U1). The negative browser case additionally
flips the last genesis-header byte. Neither step computes genesis.

## Regeneration and drift check

Run this command from the smoldot repository root **when the pin changes**,
with the correctly built pinned `polkajam` on PATH. This is an operator action,
never part of a test or demo run. Python only sorts JSON object keys and formats
whitespace, making the native export's unordered maps byte-for-byte reproducible.

```sh
(
  set -eu
  generated=$(mktemp)
  trap 'rm -f "$generated" "$generated.sorted"' EXIT
  polkajam --chain=dev:40000 dump-spec "$generated"
  python3 -m json.tool --sort-keys "$generated" > "$generated.sorted"
  diff -u wasm-node/javascript/test/jam/dev-chain-spec.json "$generated.sorted"
)
```

The initial checked-in bytes were produced by the same dump and normalization,
with the normalized output written to `dev-chain-spec.json`. A successful drift
check prints nothing and exits zero. Review any diff before replacing the file
and updating this provenance. A binary built without `SKIP_PVM_BUILDS=1` produces
a different dev genesis and must not be used for regeneration; it can still run
the checked-in spec.

To deliberately change the validator ports, change `40000` in the regeneration
command, replace the reviewed spec, and update `BASE_PORT` in `network.mjs`
together. Runtime base-port overrides are rejected. Update the provenance and
rerun the browser and finality gates after either a pin or port change.
