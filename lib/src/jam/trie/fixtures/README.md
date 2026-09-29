# State-read fixtures

- `public-trie.json`: four vectors of `trie/trie.json` from w3f/jamtestvectors
  `1dc503af37ae8ecc7b6e24a393f6102801c0c80c`, unchanged (the whole file is in
  `../../fixtures/jamtestvectors/`).
- `polkajam-ce129.json`: CE 129 state reads a browser made over WebTransport
  to a local, uninstrumented six-validator GRANDPA network at PolkaJam
  `1445c6cebf0557aa7f2d7ade851364f880f303c9` on 2026-09-29: a single C(8)
  read, an early-stopping range, an absent key and an unknown-block reset,
  cut unchanged from a larger capture together with the child header whose
  prior state root they prove against.
- `ce129.capture`: the full capture at PolkaJam
  `27d63b8d1b8527459c8dc513b770e4f3c603de8f`, 2026-10-04, same setup: CE 130
  and CE 128 for the finalized head F, the CE 129 reads at F that a light
  client joins with (C(4), C(6), C(8), C(11) one by one and as one range),
  F's child, more reads against the child's prior state root (a single
  C(8), C(1) to C(16), an early stop, an absent key) and an unknown-block
  reset. Frames are a little-endian u32 length and the payload, without the
  stream-kind byte. One field, `runtime`, the capture's working directory, is
  shortened to its path relative to the smoldot checkout, and the spec's one
  bootnode is split into JIP-4's `bootnodes` and `bootnodes_p256` lists, with
  `spec_sha256` (of the spec as sorted, compact JSON) recomputed; everything
  else is as captured.
