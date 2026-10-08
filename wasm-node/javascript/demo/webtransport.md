# Raw PolkaJam WebTransport probe

The JAM demo harness serves this page at
`http://127.0.0.1:8080/demo/webtransport.html`. Start it with
`just demo-jam-attach` against a running network (see `demo/jam.md`); the recipe
also rebuilds the browser bundle the page imports.

Fill in:

- a validator's IP and UDP port: the part after `@` of one of the
  `bootnodes_p256` entries in the attached spec (`/jam-demo/spec.json`);
- the genesis header hash: what `chainSpec_v1_genesisHash` returns for the
  spec, or the first trusted anchor the demo page shows on a fresh network;
- current SHA-256 hashes of the validator's complete DER server certificates
  (64 hexadecimal digits each). These are not the textual P-256 identity or
  public-key hashes. PolkaJam derives one certificate per validity period from
  the validator's P-256 key; the light client computes the same hashes
  (`light-base/src/jam_webtransport_cert.rs`, `certificate_hashes`).

No TLS validation bypass or browser security flags are needed. The page does
not generate certificates or implement the JAM codec.

The page uses the actual browser transport implementation, sends stream kind
`0x00` followed by a u32 little-endian length of 37 and a handshake consisting
of the genesis hash, slot zero, and zero leaves. It prints each peer frame's
length and first 48 bytes, without interpreting or verifying its JAM contents.
It handles fragmented/coalesced frames with a 1 MiB per-frame bound, retries
after session failure or stream FIN/reset, and has an explicit Stop button.
