# PolkaJam live capture

Captured on 2026-09-22 from a local PolkaJam network at commit
`8ceedf46c4828137c8835e4227d7f3a62ada0463` (PolkaJam 0.1.29, Gray Paper
0.8.0): six validators and one ordinary node with tiny parameters and fresh
databases, run for 212 seconds by `polkajam-testnet` (the exact command is in
`capture-manifest.json`). The binaries were built with `SKIP_PVM_BUILDS=1`,
which embeds empty guest blobs, so the chain runs consensus only. A local
logging patch recorded the encoded headers, states and stream bytes the nodes
handled; it does not change consensus. The node's JSON-RPC confirmed the last
header, its parent, slot and posterior state root. Byte fields are hex.

- `chain-spec.polkajam.json`: the node's chain spec: protocol parameters,
  genesis header and genesis state.
- `params.json`: the 122-byte protocol parameter blob and each field as the
  node's JSON-RPC decodes it.
- `genesis-state.json`: the genesis header's bytes and hash, the state root,
  and the light state with the raw items C(4), C(6), C(8) and C(11).
- `headers/0000.json` to `headers/0035.json`: 36 consecutive live headers in
  parent order, slots 9059167 to 9059202. Each has the header's bytes and
  hash, parent, slot, author, prior and posterior state roots, the parent and
  posterior light states, the sealing key or ticket, and both VRF inputs,
  signatures and outputs. 17 headers are fallback-sealed and 19
  ticket-sealed; epochs change at slots 9059167, 9059172, 9059184 and
  9059196; tickets marks are at 9059182 and 9059194.
- `epoch-transitions.json`: the four epoch-changing headers with their parent
  and posterior states.
- `messages/up0.json`, `messages/ce128.json`: one UP 0 handshake and
  announcement, and one single-block CE 128 request and response, as read
  from and written to the stream buffers (a little-endian u32 length, then
  the payload; the stream-kind byte is not included).
- `capture-manifest.json`: commit, command, start time, duration and counts.
