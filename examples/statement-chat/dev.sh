#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "Extracting chain specs from running node..."
OMNI_CMD=$(ps aux | awk '/polkadot-(parachain|omni-node)/ && /--bootnodes/ && !/awk/ {print; exit}')

if [ -z "$OMNI_CMD" ]; then
    echo "Error: No running polkadot-parachain with --bootnodes found"
    exit 1
fi

PARACHAIN_SPEC=$(echo "$OMNI_CMD" | sed 's/ -- .*//' | sed -n 's/.*--chain \([^ ]*\).*/\1/p; q')
RELAY_SPEC=$(echo "$OMNI_CMD" | sed 's/.* -- //' | sed -n 's/.*--chain \([^ ]*\).*/\1/p; q')
BOOTNODE=$(echo "$OMNI_CMD" | sed 's/ -- .*//' | sed -n 's/.*--bootnodes \([^ ]*\).*/\1/p; q')
RPC_PORT=$(echo "$OMNI_CMD" | sed -n 's/.*--rpc-port \([^ ]*\).*/\1/p; q')
RPC_PORT=${RPC_PORT:-9944}

echo "Parachain spec: $PARACHAIN_SPEC"
echo "Relay chain spec: $RELAY_SPEC"
echo "Bootnode: $BOOTNODE"
echo "RPC port: $RPC_PORT"

mkdir -p public/chain-specs

cp "$RELAY_SPEC" public/chain-specs/relay.json
echo "Copied relay chain spec to public/chain-specs/relay.json"

jq ".id = \"parachain\" | .bootNodes = [\"$BOOTNODE\"]" "$PARACHAIN_SPEC" > public/chain-specs/parachain.json
echo "Copied parachain spec to public/chain-specs/parachain.json (id changed to 'parachain', bootnode added)"

echo ""
echo "Building smoldot..."
cd ../../wasm-node/javascript
npm run build

echo ""
echo "Installing dependencies with npm..."
npm install

echo ""
echo "Starting dev server with npm..."
cd ../../examples/statement-chat
echo "Installing statement-chat dependencies with npm..."
npm install

pkill -f "server.js" 2>/dev/null || true
sleep 1
npm run dev
