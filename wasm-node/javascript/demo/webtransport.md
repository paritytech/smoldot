# Raw PolkaJam WebTransport probe

From `wasm-node/javascript`:

```sh
npm ci --ignore-scripts
node prepare.mjs --debug
npm run buildModules
python3 -m http.server 8080 --bind 127.0.0.1
```

Open `http://localhost:8080/demo/webtransport.html` in a browser with
WebTransport and `serverCertificateHashes` support. Enter the genesis header
hash from the PolkaJam chain spec/log, and current SHA-256 hashes of the
complete DER server certificates (64 hexadecimal digits each). These are not
the textual P-256 identity or public-key hashes. No TLS validation bypass or
browser security flags are needed.

The external planning fixture `fixtures/local-network.md` documents the
six-validator launcher and certificate generation. Its stable node0 endpoint
is `127.0.0.1:40000`. Fixed historical certificate vectors may have expired;
use currently valid pins. The demo does not generate certificates or implement
the JAM codec.

The page uses the actual browser transport implementation, sends stream kind
`0x00` followed by a u32 little-endian length of 37 and a handshake consisting
of the genesis hash, slot zero, and zero leaves. It prints each peer frame's
length and first 48 bytes, without interpreting or verifying its JAM contents.
It handles fragmented/coalesced frames with a 1 MiB per-frame bound, retries
after session failure or stream FIN/reset, and has an explicit Stop button.

Live acceptance still requires recording a handshake and at least one
announcement, stopping/restarting the node and observing reconnection, checking
Chrome and Firefox, and recording Safari status. Unit tests are not evidence
of browser compatibility or a successful live session.
