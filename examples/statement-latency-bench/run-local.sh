#!/usr/bin/env bash
# Local helper: scrape chain specs + bootnodes out of a running zombienet
# (or polkadot-omni-node) network, then run the bench against it.
# Discovers ALL collators (and ALL relay validators) and adds each as a
# bootnode in the chain specs handed to smoldot.
set -euo pipefail

cd "$(dirname "$0")"

# Query a node's libp2p PeerId via the legacy `system_localPeerId` JSON-RPC.
peer_id_of() {
    local rpc_port="$1"
    curl -sS -m 5 -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","method":"system_localPeerId","params":[],"id":1}' \
        "http://127.0.0.1:${rpc_port}" \
        | jq -r '.result // empty'
}

# Extract the tcp port from a `--listen-addr` value like
# `/ip4/0.0.0.0/tcp/54115/ws`.
tcp_port_of_listen_addr() {
    echo "$1" | sed -n 's,.*tcp/\([0-9][0-9]*\).*,\1,p'
}

# --- discover running collators ----------------------------------------------
echo "Looking for running polkadot-parachain / polkadot-omni-node processes ..."
COLLATORS=()
while IFS= read -r line; do
    [ -n "$line" ] && COLLATORS+=("$line")
done < <(ps -axww -o command= \
    | grep -E 'polkadot-(parachain|omni-node)' \
    | grep -v grep || true)

if [ "${#COLLATORS[@]}" -eq 0 ]; then
    echo "Error: no polkadot-parachain/omni-node process found." >&2
    echo "       Is your zombienet network up?" >&2
    exit 1
fi

PARACHAIN_SPEC=""
RELAY_SPEC=""
parachain_bootnodes=()

for cmd in "${COLLATORS[@]}"; do
    parachain_part=$(echo "$cmd" | sed 's/ -- .*//')
    relay_part=$(echo "$cmd" | sed 's/.* -- //')

    [ -z "$PARACHAIN_SPEC" ] && \
        PARACHAIN_SPEC=$(echo "$parachain_part" | sed -n 's/.*--chain \([^ ]*\).*/\1/p; q')
    [ -z "$RELAY_SPEC" ] && \
        RELAY_SPEC=$(echo "$relay_part" | sed -n 's/.*--chain \([^ ]*\).*/\1/p; q')

    rpc_port=$(echo "$parachain_part" | sed -n 's/.*--rpc-port \([0-9][0-9]*\).*/\1/p')
    listen_addr=$(echo "$parachain_part" | sed -n 's/.*--listen-addr \([^ ]*\).*/\1/p')
    p2p_port=$(tcp_port_of_listen_addr "$listen_addr")

    if [ -z "$rpc_port" ] || [ -z "$p2p_port" ]; then
        echo "  skipping collator (no rpc-port or listen-addr): $parachain_part" >&2
        continue
    fi

    peer_id=$(peer_id_of "$rpc_port" || true)
    if [ -z "$peer_id" ]; then
        echo "  skipping collator on rpc :$rpc_port (failed to fetch peer id)" >&2
        continue
    fi

    parachain_bootnodes+=("/ip4/127.0.0.1/tcp/${p2p_port}/ws/p2p/${peer_id}")
done

if [ -z "$PARACHAIN_SPEC" ] || [ -z "$RELAY_SPEC" ]; then
    echo "Error: failed to extract --chain paths from collator commands." >&2
    exit 1
fi

# --- discover running relay validators ---------------------------------------
VALIDATORS=()
while IFS= read -r line; do
    [ -n "$line" ] && VALIDATORS+=("$line")
done < <(ps -axww -o command= \
    | awk '/(^|\/)polkadot / && !/polkadot-(parachain|omni-node|prepare-worker|execute-worker)/' \
    | grep -v grep || true)

relay_bootnodes=()
for cmd in "${VALIDATORS[@]}"; do
    rpc_port=$(echo "$cmd" | sed -n 's/.*--rpc-port \([0-9][0-9]*\).*/\1/p')
    listen_addr=$(echo "$cmd" | sed -n 's/.*--listen-addr \([^ ]*\).*/\1/p')
    p2p_port=$(tcp_port_of_listen_addr "$listen_addr")

    if [ -z "$rpc_port" ] || [ -z "$p2p_port" ]; then
        continue
    fi

    peer_id=$(peer_id_of "$rpc_port" || true)
    if [ -z "$peer_id" ]; then
        continue
    fi

    relay_bootnodes+=("/ip4/127.0.0.1/tcp/${p2p_port}/ws/p2p/${peer_id}")
done

echo "Parachain spec      : $PARACHAIN_SPEC"
echo "Relay spec          : $RELAY_SPEC"
echo "Parachain bootnodes : ${#parachain_bootnodes[@]}"
if [ "${#parachain_bootnodes[@]}" -gt 0 ]; then
    for n in "${parachain_bootnodes[@]}"; do echo "  - $n"; done
fi
echo "Relay bootnodes     : ${#relay_bootnodes[@]}"
if [ "${#relay_bootnodes[@]}" -gt 0 ]; then
    for n in "${relay_bootnodes[@]}"; do echo "  - $n"; done
fi

# --- copy + patch specs ------------------------------------------------------
mkdir -p chain-specs

if [ "${#parachain_bootnodes[@]}" -gt 0 ]; then
    para_bn_json=$(printf '%s\n' "${parachain_bootnodes[@]}" | jq -R . | jq -s .)
else
    para_bn_json='[]'
fi
if [ "${#relay_bootnodes[@]}" -gt 0 ]; then
    relay_bn_json=$(printf '%s\n' "${relay_bootnodes[@]}" | jq -R . | jq -s .)
else
    relay_bn_json='[]'
fi

# Parachain: id renamed to "parachain" so it's stable across runs (matches
# examples/statement-chat/dev.sh) and discovered bootnodes appended.
jq --argjson bn "$para_bn_json" \
    '.id = "parachain" | .bootNodes = ((.bootNodes // []) + $bn)' \
    "$PARACHAIN_SPEC" > chain-specs/parachain.json
echo "Wrote chain-specs/parachain.json"

jq --argjson bn "$relay_bn_json" \
    '.bootNodes = ((.bootNodes // []) + $bn)' \
    "$RELAY_SPEC" > chain-specs/relay.json
echo "Wrote chain-specs/relay.json"

# --- build smoldot if needed --------------------------------------------------
if [ ! -d ../../wasm-node/javascript/dist ]; then
    echo ""
    echo "Building smoldot ..."
    (cd ../../wasm-node/javascript && npm install && npm run build)
fi

# --- npm install bench deps ---------------------------------------------------
if [ ! -d node_modules ]; then
    echo ""
    echo "Installing bench deps ..."
    npm install
fi

# --- run ----------------------------------------------------------------------
echo ""
echo "Running bench ..."
exec node bench.js \
    --parachain-spec ./chain-specs/parachain.json \
    --relay-chain-spec ./chain-specs/relay.json \
    --num-clients "${NUM_CLIENTS:-4}" \
    --num-rounds "${NUM_ROUNDS:-2}" \
    --messages-pattern "${MESSAGES_PATTERN:-3:128}" \
    --receive-timeout-ms "${RECEIVE_TIMEOUT_MS:-30000}" \
    --interval-ms "${INTERVAL_MS:-5000}" \
    --warmup-ms "${WARMUP_MS:-15000}" \
    --workers "${WORKERS:-1}" \
    --log-level "${LOG_LEVEL:-info}" \
    "$@"
