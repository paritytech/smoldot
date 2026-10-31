# smoldot browser WebRTC demo

Browser smoldot connected to a single full node over WebRTC, with polkadot.js apps on top.
Transport is forced WebRTC, so no WS connectians are made.

```sh
# 1. Polkdot node: take certhash + peer id from its startup log
polkadot -d . --sync=warp --rpc-port 9955

# 2. One-time setup + checkpoint chain spec (regenerate when stale, then reload the page)
npm install
./generate_checkpoint.sh

# 3. Relay
node browser/relay.mjs debug/polkadot-checkpoint.json \
  /ip4/<node-ip>/udp/30333/webrtc-direct/certhash/<certhash>/p2p/<peer-id>
```

Open in a browser:

1. <http://127.0.0.1:9946/> — runs smoldot; keep the tab open and foregrounded
2. <http://127.0.0.1:9946/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9946%2Frpc> — polkadot.js served
   from localhost, so requests to 127.0.0.1 are allowed by a browser.

Firefox doesn't allow loopback WebRTC — use Chromium or a non-loopback/public IP.
`?verbose=1` enables full logs. Red log lines = dialed something other than the configured node.
