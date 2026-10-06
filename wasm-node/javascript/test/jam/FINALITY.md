# JAM GRANDPA finality fixture

`lib/src/jam/finality/fixtures/polkajam-grandpa.json` is captured from a run
of the `jam_finality` scenario in `e2e-tests`. To regenerate it, set
`JAM_FINALITY_FIXTURE` to the output path:

```sh
JAM_FINALITY_FIXTURE=$PWD/lib/src/jam/finality/fixtures/polkajam-grandpa.json \
  cargo test --manifest-path e2e-tests/Cargo.toml --features jam --test jam_finality -- --nocapture
```

The run writes the fixture there, and the raw capture (headers, CE 130
exchanges, follow events, client logs) next to it as
`polkajam-grandpa.capture.json`. The export fails unless the run captured at
least twenty proofs across three authority sets.
