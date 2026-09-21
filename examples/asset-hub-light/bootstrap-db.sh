#!/usr/bin/env bash
# Smoldot
# Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
# SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
#
# Produces a current database for `index.mjs`:
#
#   ./bootstrap-db.sh [--from DIR] [directory] [deadline-seconds]
#
# With `--from`, this is a refresh: warm-start from DIR and save what the client has caught up
# to. A warm start needs only the single validator of `nodes.json`, so the refresh runs the
# same pinning the cluster does -- which means a database that comes out of it has been shown
# to work on that path, not just to exist.
#
# Without `--from`, or if the refresh fails, this is the README's bootstrap: a cold start
# pinned to the three validators of `nodes-bootstrap.json`. A cold warp sync earns a 10 s ban
# every time a pruned node refuses the `:code` request at the chain spec's checkpoint; with
# three validators the bans rotate and the sync gets through, with one it never does.
#
# Both chains are always written, the relay chain and Asset Hub, so that one database serves
# `SMOLDOT_RELAY_ONLY=1` and the default mode alike.
#
# The output directory always starts empty and `index.mjs` writes to it while reading the seed
# from elsewhere, so a file appearing there is proof that this run saved one -- never that the
# seed was copied across.

set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# A warm start that has not caught up in this long is not slow, it is broken; fall back to a
# cold one rather than sitting on the full deadline.
WARM_DEADLINE_CAP=180

FROM_DIR=

while (( $# > 0 )); do
    case "$1" in
        --from) FROM_DIR="${2:?--from needs a directory}"; shift 2 ;;
        --)     shift; break ;;
        -*)     echo "unknown option: $1" >&2; exit 2 ;;
        *)      break ;;
    esac
done

DB_DIR="${1:-$HERE/.db}"
DEADLINE_SECS="${2:-420}"

[[ "$DB_DIR" = /* ]] || DB_DIR="$PWD/$DB_DIR"
[[ -z "$FROM_DIR" || "$FROM_DIR" = /* ]] || FROM_DIR="$PWD/$FROM_DIR"

RELAY_DB="$DB_DIR/polkadot.json"
PARA_DB="$DB_DIR/asset-hub-polkadot.json"

if [[ ! "$DEADLINE_SECS" =~ ^[1-9][0-9]*$ ]]; then
    echo "deadline must be a positive integer (got \"$DEADLINE_SECS\")" >&2
    exit 2
fi

if [[ -n "$FROM_DIR" && ! -s "$FROM_DIR/polkadot.json" ]]; then
    echo "--- $FROM_DIR holds no relay chain database; starting cold instead ---" >&2
    FROM_DIR=
fi

child=

cleanup() {
    [[ -n "$child" ]] && kill -INT "$child" 2>/dev/null || true
}
trap cleanup INT TERM

# Runs index.mjs until both chains' databases have been written, then sends the single SIGINT
# that makes it write a last, current copy -- a second one tells it to give up on saving, so
# exactly one is sent. $1 is the directory to warm-start from, empty for a cold start; $2 the
# node list to pin to; $3 the deadline. Returns non-zero if nothing was written in time.
run_attempt() {
    local seed="$1" nodes="$2" deadline_secs="$3"
    local started deadline

    rm -rf "$DB_DIR"
    mkdir -p "$DB_DIR"

    # SMOLDOT_SEED_DB set-but-empty is the documented way to turn off the search that would
    # otherwise warm-start from any `.db*` directory next to index.mjs, which is what makes a
    # cold start genuinely cold. Set to a directory, it is where this run reads its seed from,
    # while SMOLDOT_DB_DIR stays the empty directory it writes to.
    #
    # The contract reads are off here whatever the environment says: this run exists to produce
    # a database, and asking the node for storage proofs while doing it is load that nothing
    # measures and that the bootstrap does not need.
    SMOLDOT_NODES="$nodes" \
    SMOLDOT_DB_DIR="$DB_DIR" \
    SMOLDOT_SEED_DB="$seed" \
    SMOLDOT_QUERY_INTERVAL_MS=0 \
        node "$HERE/index.mjs" &
    child=$!

    started=$SECONDS
    deadline=$(( SECONDS + deadline_secs ))
    while :; do
        if [[ -s "$RELAY_DB" && -s "$PARA_DB" ]]; then
            echo "--- both databases written after $(( SECONDS - started ))s; asking for a final save ---"
            break
        fi
        if ! kill -0 "$child" 2>/dev/null; then
            echo "--- index.mjs exited before both databases were written ---" >&2
            wait "$child" || true
            child=
            return 1
        fi
        if (( SECONDS >= deadline )); then
            echo "--- nothing written after ${deadline_secs}s ---" >&2
            kill -INT "$child" 2>/dev/null || true
            wait "$child" || true
            child=
            return 1
        fi
        sleep 2
    done

    kill -INT "$child" 2>/dev/null || true
    wait "$child" || true
    child=

    [[ -s "$RELAY_DB" && -s "$PARA_DB" ]]
}

warm_deadline=$(( DEADLINE_SECS < WARM_DEADLINE_CAP ? DEADLINE_SECS : WARM_DEADLINE_CAP ))
ok=

if [[ -n "$FROM_DIR" ]]; then
    echo "--- refreshing $DB_DIR from $FROM_DIR, pinned to nodes.json, deadline ${warm_deadline}s ---"
    if run_attempt "$FROM_DIR" "$HERE/nodes.json" "$warm_deadline"; then
        ok=1
    else
        echo "--- the refresh produced nothing; falling back to a cold bootstrap ---" >&2
    fi
fi

if [[ -z "$ok" ]]; then
    echo "--- bootstrapping $DB_DIR cold, pinned to nodes-bootstrap.json, deadline ${DEADLINE_SECS}s ---"
    run_attempt "" "$HERE/nodes-bootstrap.json" "$DEADLINE_SECS" || {
        echo "--- could not produce a database ---" >&2
        exit 1
    }
fi

ls -l "$DB_DIR"
echo "--- wrote $DB_DIR ---"
