# w3f JAM test vectors, subset

Taken from <https://github.com/w3f/jamtestvectors> at commit
`1dc503af37ae8ecc7b6e24a393f6102801c0c80c` (Gray Paper 0.7.1), licensed
CC0 1.0 (`LICENSE`). Paths follow the upstream repository.

- `codec/tiny/`, `codec/full/`: the two headers, the block, its extrinsic and
  the tickets extrinsic of each parameter set, unchanged.
- `traces/fallback.json`, `traces/safrole.json`: every header of the upstream
  `traces/fallback/` and `traces/safrole/` block-import traces, genesis first.
  Each record holds the step name, the step's header object as upstream's JSON
  has it (`block.header`, or `header` for genesis), unchanged, and
  `header_bin`, the header's bytes cut from the step's `.bin`: right after
  the pre-state (a 32-byte root, then a counted list of 31-byte keys with
  length-prefixed values), as long as the header that the JSON describes
  under the tiny parameters (six validators, twelve-slot epochs, the Gray
  Paper 0.7.1 epoch mark without a validator count). Each header's parent is
  the BLAKE2b-256 hash of the previous record's bytes. The six other traces
  use the same parameters and header kinds and are left out.
- `trie/trie.json`: the state-trie root vectors, unchanged.
