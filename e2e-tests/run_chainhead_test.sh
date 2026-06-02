#!/usr/bin/env bash
# Launches chainhead_v1_follow_test.js against a live public network. Picks
# bundled chain specs from demo-chain-specs/ by network name and (when an RPC
# URL is configured) queries the parachain's current finalized height so the
# validator's lag-regression check is meaningful.
#
# Usage:
#   ./run_chainhead_test.sh <network>
#
# A relay network name runs relay-only; an `-ah`/`-next` variant also adds the
# corresponding asset-hub parachain (relay = the matching relay chain).
#   relay-only: paseo, polkadot, kusama, westend
#   with para:  paseo-ah, paseo-ah-next, polkadot-ah, kusama-ah, westend-ah
#
# Set WITH_RUNTIME=true to subscribe with runtime (default false).

set -euo pipefail

network="${1:-paseo}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SPECS_DIR="${REPO_ROOT}/demo-chain-specs"

# A network without a `para_spec` is treated as relay-only.
relay_spec=""
para_spec=""
relay_rpc=""
para_rpc=""

case "${network}" in
  paseo)
    relay_spec="${SPECS_DIR}/paseo.json"
    relay_rpc="https://paseo-rpc.n.dwellir.com"
    ;;
  paseo-ah)
    relay_spec="${SPECS_DIR}/paseo.json"
    para_spec="${SPECS_DIR}/paseo_asset_hub.json"
    relay_rpc="https://paseo-rpc.n.dwellir.com"
    para_rpc="https://asset-hub-paseo-rpc.n.dwellir.com"
    ;;
  paseo-ah-next)
    relay_spec="${SPECS_DIR}/paseo.json"
    para_spec="${SPECS_DIR}/paseo_asset_hub_next.json"
    relay_rpc="https://paseo-rpc.n.dwellir.com"
    para_rpc="" # TODO
    ;;
  polkadot)
    relay_spec="${SPECS_DIR}/polkadot.json"
    relay_rpc=""  # TODO: set Polkadot relay RPC URL
    ;;
  polkadot-ah)
    relay_spec="${SPECS_DIR}/polkadot.json"
    para_spec="${SPECS_DIR}/polkadot_asset_hub.json"
    relay_rpc=""  # TODO: set Polkadot relay RPC URL
    para_rpc=""  # TODO: set Polkadot Asset Hub RPC URL
    ;;
  kusama)
    relay_spec="${SPECS_DIR}/ksmcc3.json"
    relay_rpc=""  # TODO: set Kusama relay RPC URL
    ;;
  kusama-ah)
    relay_spec="${SPECS_DIR}/ksmcc3.json"
    para_spec="${SPECS_DIR}/ksmcc3_asset_hub.json"
    relay_rpc=""  # TODO: set Kusama relay RPC URL
    para_rpc=""  # TODO: set Kusama Asset Hub RPC URL
    ;;
  westend)
    relay_spec="${SPECS_DIR}/westend2.json"
    relay_rpc=""  # TODO: set Westend relay RPC URL
    ;;
  westend-ah)
    relay_spec="${SPECS_DIR}/westend2.json"
    para_spec="${SPECS_DIR}/westend2_asset_hub.json"
    relay_rpc=""  # TODO: set Westend relay RPC URL
    para_rpc=""  # TODO: set Westend Asset Hub RPC URL
    ;;
  *)
    echo "Unknown network: ${network}" >&2
    echo "Supported: paseo[-ah[-next]], polkadot[-ah], kusama[-ah], westend[-ah]" >&2
    exit 1
    ;;
esac

RELAY_CHAIN_SPEC="${RELAY_CHAIN_SPEC:-${relay_spec}}"
PARA_CHAIN_SPEC="${PARA_CHAIN_SPEC:-${para_spec}}"
RELAY_RPC_URL="${RELAY_RPC_URL:-${relay_rpc}}"
PARA_RPC_URL="${PARA_RPC_URL:-${para_rpc}}"

if [[ ! -f "${RELAY_CHAIN_SPEC}" ]]; then
  echo "Relay chain spec not found: ${RELAY_CHAIN_SPEC}" >&2
  exit 1
fi
if [[ -n "${PARA_CHAIN_SPEC}" && ! -f "${PARA_CHAIN_SPEC}" ]]; then
  echo "Para chain spec not found: ${PARA_CHAIN_SPEC}" >&2
  exit 1
fi

# Echoes the decimal block number for the head returned by `${head_method}` on
# `${url}`, or empty string on failure.
fetch_head_number() {
  local url="$1" head_method="$2"
  local hash number_hex
  hash=$(curl -fsS -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${head_method}\"}" \
    "${url}" | jq -r '.result' 2>/dev/null || true)
  [[ -z "${hash}" || "${hash}" == "null" ]] && return 0
  number_hex=$(curl -fsS -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"chain_getHeader\",\"params\":[\"${hash}\"]}" \
    "${url}" | jq -r '.result.number' 2>/dev/null || true)
  [[ -z "${number_hex}" || "${number_hex}" == "null" ]] && return 0
  printf '%d' "${number_hex}"
}

RELAY_FINALIZED_AT_LAUNCH="${RELAY_FINALIZED_AT_LAUNCH:-0}"
RELAY_BEST_AT_LAUNCH="${RELAY_BEST_AT_LAUNCH:-0}"
if [[ -n "${RELAY_RPC_URL}" ]]; then
  echo "Fetching relay best + finalized from ${RELAY_RPC_URL}..." >&2
  if [[ "${RELAY_FINALIZED_AT_LAUNCH}" == "0" ]]; then
    RELAY_FINALIZED_AT_LAUNCH=$(fetch_head_number "${RELAY_RPC_URL}" "chain_getFinalizedHead")
    RELAY_FINALIZED_AT_LAUNCH="${RELAY_FINALIZED_AT_LAUNCH:-0}"
  fi
  if [[ "${RELAY_BEST_AT_LAUNCH}" == "0" ]]; then
    RELAY_BEST_AT_LAUNCH=$(fetch_head_number "${RELAY_RPC_URL}" "chain_getHead")
    RELAY_BEST_AT_LAUNCH="${RELAY_BEST_AT_LAUNCH:-0}"
  fi
  echo "Relay at launch: best=#${RELAY_BEST_AT_LAUNCH} finalized=#${RELAY_FINALIZED_AT_LAUNCH}" >&2
fi
if [[ "${RELAY_FINALIZED_AT_LAUNCH}" == "0" ]]; then
  echo "Relay lag-regression check disabled (no RELAY_FINALIZED_AT_LAUNCH)." >&2
fi

PARA_FINALIZED_AT_LAUNCH="${PARA_FINALIZED_AT_LAUNCH:-0}"
PARA_BEST_AT_LAUNCH="${PARA_BEST_AT_LAUNCH:-0}"
if [[ -n "${PARA_RPC_URL}" ]]; then
  echo "Fetching para best + finalized from ${PARA_RPC_URL}..." >&2
  if [[ "${PARA_FINALIZED_AT_LAUNCH}" == "0" ]]; then
    PARA_FINALIZED_AT_LAUNCH=$(fetch_head_number "${PARA_RPC_URL}" "chain_getFinalizedHead")
    PARA_FINALIZED_AT_LAUNCH="${PARA_FINALIZED_AT_LAUNCH:-0}"
  fi
  if [[ "${PARA_BEST_AT_LAUNCH}" == "0" ]]; then
    PARA_BEST_AT_LAUNCH=$(fetch_head_number "${PARA_RPC_URL}" "chain_getHead")
    PARA_BEST_AT_LAUNCH="${PARA_BEST_AT_LAUNCH:-0}"
  fi
  echo "Para at launch: best=#${PARA_BEST_AT_LAUNCH} finalized=#${PARA_FINALIZED_AT_LAUNCH}" >&2
fi
if [[ "${PARA_FINALIZED_AT_LAUNCH}" == "0" ]]; then
  echo "Para lag-regression check disabled (no PARA_FINALIZED_AT_LAUNCH)." >&2
fi

# Opt-in DB caching: set SMOLDOT_DB_DUMP_DIR to dump on success and to auto-load
# any previously-dumped DBs from the same directory on subsequent runs.
if [[ -n "${SMOLDOT_DB_DUMP_DIR:-}" ]]; then
  if [[ -z "${SMOLDOT_DB_RELAY:-}" && -f "${SMOLDOT_DB_DUMP_DIR}/relay.json" ]]; then
    SMOLDOT_DB_RELAY="${SMOLDOT_DB_DUMP_DIR}/relay.json"
  fi
  if [[ -z "${SMOLDOT_DB_PARA:-}" && -f "${SMOLDOT_DB_DUMP_DIR}/para.json" ]]; then
    SMOLDOT_DB_PARA="${SMOLDOT_DB_DUMP_DIR}/para.json"
  fi
  if [[ -n "${SMOLDOT_DB_RELAY:-}" || -n "${SMOLDOT_DB_PARA:-}" ]]; then
    echo "Warm-loading smoldot DBs from ${SMOLDOT_DB_DUMP_DIR}" >&2
  else
    echo "Cold start. DBs will be dumped to ${SMOLDOT_DB_DUMP_DIR} on success." >&2
  fi
fi

cd "${SCRIPT_DIR}"
exec env \
  WITH_RUNTIME="${WITH_RUNTIME:-false}" \
  RELAY_CHAIN_SPEC="${RELAY_CHAIN_SPEC}" \
  PARA_CHAIN_SPEC="${PARA_CHAIN_SPEC}" \
  RELAY_FINALIZED_AT_LAUNCH="${RELAY_FINALIZED_AT_LAUNCH}" \
  RELAY_BEST_AT_LAUNCH="${RELAY_BEST_AT_LAUNCH}" \
  PARA_FINALIZED_AT_LAUNCH="${PARA_FINALIZED_AT_LAUNCH}" \
  PARA_BEST_AT_LAUNCH="${PARA_BEST_AT_LAUNCH}" \
  SMOLDOT_DB_RELAY="${SMOLDOT_DB_RELAY:-}" \
  SMOLDOT_DB_PARA="${SMOLDOT_DB_PARA:-}" \
  SMOLDOT_DB_DUMP_DIR="${SMOLDOT_DB_DUMP_DIR:-}" \
  MIN_NEW_BLOCKS="${MIN_NEW_BLOCKS:-5}" \
  MIN_FINALIZED_EVENTS="${MIN_FINALIZED_EVENTS:-2}" \
  PER_SUB_TIMEOUT_MS="${PER_SUB_TIMEOUT_MS:-600000}" \
  OVERALL_TIMEOUT_MS="${OVERALL_TIMEOUT_MS:-900000}" \
  SMOLDOT_LOG_LEVEL="${SMOLDOT_LOG_LEVEL:-2}" \
  node js/chainhead_v1_follow_test.js
