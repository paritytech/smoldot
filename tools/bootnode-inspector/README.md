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

# One Asset Hub Next address, plus the peers it hands out in 4 seconds
node inspect.mjs --discover 4 \
  --bootnode "/ip4/34.158.101.242/tcp/32728/ws/p2p/12D3KooWFjpVdBnfJFntogWhinn15WW2n8Fd2DiAcqU6i9rg47Yg" \
  ../../demo-chain-specs/paseo.json ../../demo-chain-specs/paseo_asset_hub_next.json
```

Output of the last command:

```
Checking 1 bootnode address(es) across 2 chain(s), timeout 304s, concurrency 4, waiting for chainHead initialized
[1/1] OK   next-asset-hub-paseo /ip4/34.158.101.242/tcp/32728/ws/p2p/12D3KooWFjpVdBnfJFntogWhinn15WW2n8Fd2DiAcqU6i9rg47Yg  tcp=137ms handshake=218ms initialized=1949ms
    discovered 3 peer(s) through this bootnode: 0 connected, 0 failed, 3 still dialing, 0 not dialed

      12D3KooWAp8x8ivveZ5Geb7GtnP38BXdi63YcxVmLSCwo9Ng62zR
        /dns4/paseo-asset-hub-next-rpc-scw-node-0-para-chain-p2p.paseo-rpc.svc.cluster.local/tcp/30334/p2p/12D3KooWAp8x8ivveZ5Geb7GtnP38BXdi63YcxVmLSCwo9Ng62zR  dialing
        /ip4/62.210.236.55/tcp/30305/ws/p2p/12D3KooWAp8x8ivveZ5Geb7GtnP38BXdi63YcxVmLSCwo9Ng62zR                                                                 not dialed
        /ip4/62.210.236.55/tcp/32735/p2p/12D3KooWAp8x8ivveZ5Geb7GtnP38BXdi63YcxVmLSCwo9Ng62zR                                                                    not dialed

      12D3KooWQS94VydqyueCzoonSHQ3HGbSTDkWFsndh6VcDj5d4uFb
        /ip4/212.47.236.96/tcp/30709/ws/p2p/12D3KooWQS94VydqyueCzoonSHQ3HGbSTDkWFsndh6VcDj5d4uFb                                                                 dialing
        /ip4/212.47.236.96/tcp/31711/p2p/12D3KooWQS94VydqyueCzoonSHQ3HGbSTDkWFsndh6VcDj5d4uFb                                                                    not dialed
        ...

next-asset-hub-paseo: 1/1 bootnode addresses OK
```

A failing address looks like this:

```
[2/2] FAIL paseo /dns/paseo-boot-ng.dwellir.com/tcp/443/wss/p2p/12D3KooWBLLFKDGBxCwq3QmU3YwWKXUx953WwprRshJQicYu4Cfr  tcp=- handshake=- initialized=-  (dns: ENOTFOUND)
```
