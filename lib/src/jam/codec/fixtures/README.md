# CE 128 captures

Block requests a browser sent over WebTransport to a local, uninstrumented
PolkaJam network at commit `8ceedf46c4828137c8835e4227d7f3a62ada0463`
(Gray Paper 0.8.0), captured on 2026-09-23. Request and response frames are
as the browser wrote and read them: a little-endian u32 length, then the
payload, without the stream-kind byte. A reset records the browser's
`streamErrorCode`.

- `ce128.json`: ascending one and 64 blocks from genesis, ascending 64 from a
  parent near the tip (fewer come back), descending two, and two requests
  reset with code 6 (no data): an unknown hash and the tip.
- `ce128-early-genesis.json`: ascending 64 from genesis while the chain was
  15 blocks long; 15 blocks come back.

`../../finality/fixtures/polkajam-ce128.json` is a five-block cut of
`ce128.json`'s `ascending-64-genesis` exchange.
