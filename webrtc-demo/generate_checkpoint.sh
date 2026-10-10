#!/usr/bin/env bash
# Generate a chainspec with a lightSyncState checkpoint from a running node.
# Usage: ./generate_checkpoint.sh [rpc-url] [output-file]
set -euo pipefail

RPC_URL="${1:-http://127.0.0.1:9955}"
OUT="${2:-debug/polkadot-checkpoint.json}"

curl -s -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"sync_state_genSyncSpec","params":[true]}' \
    "$RPC_URL" | python3 -c "
import json, sys
r = json.load(sys.stdin)
if 'error' in r:
    sys.exit('RPC error: %s' % r['error'])
spec = r['result']
if 'lightSyncState' not in spec:
    sys.exit('node returned a spec without lightSyncState')
json.dump(spec, open('$OUT', 'w'))
print('wrote $OUT (id: %s)' % spec.get('id'))
"
