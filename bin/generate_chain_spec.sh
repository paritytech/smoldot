#!/bin/sh

# Small script to grab the chain specification of a running node.

echo '{"id":53,"jsonrpc":"2.0","method":"sync_state_genSyncSpec","params":[true]}' |
    websocat -n1 -B 99999999 wss://node-address-here |
    jq .result > chain_spec.json
