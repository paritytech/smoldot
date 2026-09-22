# Synthetic signed chain

`synthetic.json` is generated, not captured from PolkaJam. A small program
built on this crate's JAM types made it from the chain spec of the library's
PolkaJam capture (`lib/src/jam/fixtures/polkajam/`), keeping its tiny
parameters:

- six validators with fixed Bandersnatch and Ed25519 keys replace the genesis
  set, with fixed entropy and fallback sealing, and no bootnodes;
- 600 fallback-sealed headers follow, slots 1 to 600, each checked with
  `verify_header` as it was made; every header's prior state root is zero;
- each header has a GRANDPA justification, round 17, signed by all six
  authorities, whose target carries the posterior state root (zero); the set
  id rises by one after each epoch change;
- `dead_header` is a valid sibling at slot 4 on another branch.

The file holds the resulting chain spec (`spec`), the encoded headers in
order (`headers`), the justifications by header hash (`proofs`) and
`dead_header`.
