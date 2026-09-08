# smoldot bootnode inspector

Checks each bootnode of a chain spec on its own, using the `smoldot` npm
package. For every address it starts a fresh light client whose only bootnode
is that address, then reports:

- **handshake**: smoldot completed the libp2p handshake with the node.
- **initialized**: `chainHead_v1_follow` reported a finalized block, so the
  node served warp sync and block data. Skipped with `--handshake-only`.

A plain DNS lookup and TCP connect run alongside, so a failure is labelled
`dns: ENOTFOUND`, `tcp: ECONNREFUSED`, `tcp: connect timeout`, `peer id
mismatch`, or `tcp connect ok but libp2p handshake not completed`.

## Install

Needs Node.js 18 or newer.

```sh
cd tools/bootnode-inspector
npm install
npx playwright install chromium-headless-shell   # only needed for WebRTC addresses
```

tcp, ws and wss addresses are dialed with the Node.js build of smoldot.
`webrtc-direct` addresses need the browser build, which the tool runs inside
headless Chromium through Playwright. Without Chromium they are reported as
skipped.

## Usage

```sh
node inspect.mjs [options] <chain-spec.json> [<chain-spec.json> ...]
```

| Option              | Meaning                                                              |
| ------------------- | -------------------------------------------------------------------- |
| `--timeout <s>`     | Seconds to wait per bootnode. Default 300, or 30 with `--handshake-only`. |
| `--concurrency <n>` | Bootnodes checked at the same time. Default 4.                       |
| `--handshake-only`  | Stop at the handshake, do not wait for a finalized block.            |
| `--host <h>`        | `auto` (default): Node for tcp/ws/wss, Chromium for webrtc-direct. `node`: WebRTC skipped. `browser`: everything through Chromium, plain tcp skipped. |
| `--discover <s>`    | Keep running `s` seconds after the handshake and list the peers found through the bootnode, marking the ones smoldot connected to. |
| `--bootnode <addr>` | Check this multiaddr (ending in `/p2p/<peer id>`) instead of the spec's list. Repeatable. |
| `--json`            | Print results as JSON.                                               |
| `--verbose`         | Print every smoldot network log line.                                |

Exit code 0 when every address passed, 1 when one failed, 2 on bad input.

Parachains: pass the parachain spec together with its relay chain spec. The
relay runs with its full bootnode list; only the parachain's bootnodes are
checked. `--bootnode` then applies to the parachain. Several parachain specs
with `--bootnode` is an error.

## Examples

```sh
# Paseo relay and Asset Hub bootnodes
node inspect.mjs ../../demo-chain-specs/paseo.json ../../demo-chain-specs/paseo_asset_hub.json

# Reachability only, about a second per address
node inspect.mjs --handshake-only ../../demo-chain-specs/paseo.json

# Everything through headless Chromium, as a web page would dial it
node inspect.mjs --host browser ../../demo-chain-specs/paseo.json ../../demo-chain-specs/paseo_asset_hub_next.json

# One Asset Hub Next address, plus the peers it hands out in 4 seconds
node inspect.mjs --discover 4 \
  --bootnode "/ip4/34.158.101.242/tcp/32728/ws/p2p/12D3KooWFjpVdBnfJFntogWhinn15WW2n8Fd2DiAcqU6i9rg47Yg" \
  ../../demo-chain-specs/paseo.json ../../demo-chain-specs/paseo_asset_hub_next.json
```

Output of the `--host browser` command, Asset Hub Next part:

```
next-asset-hub-paseo (6 bootnode addresses)
  [1/6] OK   /dns/paseo-asset-hub-next-collator-node-0.parity-testnet.parity.io/tcp/443/wss/p2p/12D3KooWKT5DcVLoBbVDAM6N5ujDVknPfQWHk8SGJqJPyAM8Z4Y4                        tcp=18ms   handshake=665ms   initialized=2246ms   via=browser
  [2/6] OK   /dns/paseo-asset-hub-next-collator-node-1.parity-testnet.parity.io/tcp/443/wss/p2p/12D3KooWFjpVdBnfJFntogWhinn15WW2n8Fd2DiAcqU6i9rg47Yg                        tcp=16ms   handshake=585ms   initialized=2274ms   via=browser
  [3/6] FAIL /ip4/34.7.179.66/udp/32208/webrtc-direct/certhash/uEiBsqkcr8pOaNjl6px_v1nBatWMfXB9C_sU8fDat3mZWfQ/p2p/12D3KooWK8TtC31jkC9u5EfHPx7MGRCdE1kFSFXW43qdDWqdKMum     tcp=-      handshake=-       initialized=-        via=browser  (WebRTC connection failed: UDP port unreachable or certhash no longer matches the node)
  [4/6] FAIL /ip4/34.91.159.79/udp/32039/webrtc-direct/certhash/uEiB5itUMGibt92QYT7-bsTz7zMTR8v7GZlJJ0RUIbNd0HA/p2p/12D3KooWK2X3GytbTgeBwFJ3mHMkpkB3u7JPu7zyTuWiuqp99UHK    tcp=-      handshake=-       initialized=-        via=browser  (WebRTC connection failed: UDP port unreachable or certhash no longer matches the node)
  [5/6] OK   /ip4/212.47.243.221/udp/32722/webrtc-direct/certhash/uEiDXCKDlo5yWmgjR-8YA6NOcxIpXl4luqKZ45Tf6k9pwcA/p2p/12D3KooWQS94VydqyueCzoonSHQ3HGbSTDkWFsndh6VcDj5d4uFb  tcp=-      handshake=658ms   initialized=2479ms   via=browser
  [6/6] OK   /ip4/62.210.236.55/udp/31209/webrtc-direct/certhash/uEiCqoiSD8PeOZa8CXQ9UnB7o8WbIPUM82p6pXDKhqDi1oA/p2p/12D3KooWAp8x8ivveZ5Geb7GtnP38BXdi63YcxVmLSCwo9Ng62zR   tcp=-      handshake=632ms   initialized=2362ms   via=browser
```

Output of the `--discover` command:

```
Checking 1 bootnode address(es) across 2 chain(s), timeout 304s, concurrency 4, waiting for chainHead initialized
next-asset-hub-paseo (1 bootnode address)
  [1/1] OK   /ip4/34.158.101.242/tcp/32728/ws/p2p/12D3KooWFjpVdBnfJFntogWhinn15WW2n8Fd2DiAcqU6i9rg47Yg  tcp=46ms   handshake=303ms   initialized=1445ms
    discovered 50 peer(s) through this bootnode: 1 connected, 0 failed, 2 still dialing, 47 not dialed

      12D3KooWKT5DcVLoBbVDAM6N5ujDVknPfQWHk8SGJqJPyAM8Z4Y4
        /ip4/34.6.234.169/tcp/30150/p2p/12D3KooWKT5DcVLoBbVDAM6N5ujDVknPfQWHk8SGJqJPyAM8Z4Y4                                                                     OK
        /dns/paseo-asset-hub-next-collator-p2p-node-0.parity-testnet.parity.io/tcp/30333/p2p/12D3KooWKT5DcVLoBbVDAM6N5ujDVknPfQWHk8SGJqJPyAM8Z4Y4                not dialed
        /dns/paseo-asset-hub-next-collator-node-0.parity-testnet.parity.io/tcp/443/wss/p2p/12D3KooWKT5DcVLoBbVDAM6N5ujDVknPfQWHk8SGJqJPyAM8Z4Y4                  not dialed
        ...

      12D3KooWAp8x8ivveZ5Geb7GtnP38BXdi63YcxVmLSCwo9Ng62zR
        /ip4/62.210.236.55/tcp/32735/p2p/12D3KooWAp8x8ivveZ5Geb7GtnP38BXdi63YcxVmLSCwo9Ng62zR                                                                    dialing
        /ip4/62.210.236.55/tcp/30305/ws/p2p/12D3KooWAp8x8ivveZ5Geb7GtnP38BXdi63YcxVmLSCwo9Ng62zR                                                                 not dialed
        ...
```

A failing address looks like this:

```
  [2/6] FAIL /dns/paseo-boot-ng.dwellir.com/tcp/443/wss/p2p/12D3KooWBLLFKDGBxCwq3QmU3YwWKXUx953WwprRshJQicYu4Cfr  tcp=-      handshake=-       initialized=-        (dns: ENOTFOUND)
```
