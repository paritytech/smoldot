# Fixed tiny dev chain spec

`dev-chain-spec.json` was generated on 2026-09-23 from PolkaJam commit
`1445c6cebf0557aa7f2d7ade851364f880f303c9`, built with `SKIP_PVM_BUILDS=1`
and the flags in [README.md](README.md). The spec uses six deterministic dev
validators at 127.0.0.1:40000–40005.

Since D19 (e2e scenarios on zombienet) no test network reads it: zombienet
generates each network's spec with `gen-spec`, with the ports it picked, and
the light client takes that spec unchanged. The file stays as a fixture for
unit tests that want a real PolkaJam genesis and for the drift check below,
which tells at a pin move whether PolkaJam's dev genesis changed.

## Drift check

The pinned PolkaJam, the head of the branch `skunert/polkajam-light-client`,
has `SKIP_PVM_BUILDS=1` again: a binary built with it and the
[README.md](README.md) flags embeds empty guest blobs, as the `1445c6ce` build
that generated the file did, and its `dump-spec` runs from any directory.
Run the check from the smoldot root with that `polkajam` on PATH after every
pin move. Python only sorts JSON object keys and formats whitespace, making the
native export's unordered maps byte-for-byte reproducible.

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
check prints nothing and exits zero; it does at the current pin. Review any diff
before replacing the file and updating this provenance. A binary built without
`SKIP_PVM_BUILDS=1` embeds real guest blobs, produces a different dev genesis and
must not be used for regeneration.
