#!/usr/bin/env bash
# Smoldot
# Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
# SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
#
# Builds the container image for this example with a current database baked in.
#
#   ./build-image.sh                  # refresh the newest database we have, build, don't push
#   ./build-image.sh --push           # and push
#   ./build-image.sh --cold           # ignore what we have and warp-sync a new one from scratch
#   ./build-image.sh --from DIR       # refresh that database rather than the newest one
#   ./build-image.sh --keep-db        # bake seed-db/ as it stands, don't run anything
#   ./build-image.sh --tag v3 --repo someone/smoldot-asset-hub-light --push
#
# By default the bootstrap warm-starts from the newest database on hand -- seed-db/ from the
# last build, or the .db/ left by a local run -- and only brings it up to date, which takes
# seconds against the minute and a half a cold warp sync costs. That refresh runs pinned to the
# single validator of nodes.json, exactly as the cluster does, so a database that comes out of
# it has been shown to work on that path. If the refresh fails, or there is nothing to refresh,
# it falls back to a cold start pinned to the three validators of nodes-bootstrap.json.
#
# Each refresh is verified forward from the last one by GRANDPA, which is the ordinary light
# client trust model, but the chain is never re-anchored to the chain spec. Run --cold now and
# again to start that chain over from the checkpoint.
#
# The bootstrap runs inside the image that was just built, not on the host, so the database is
# produced by exactly the code that will consume it -- in particular by this working tree's
# `connectionFilter`, which is what makes pinning real and which no published smoldot has.
#
# Environment: SMOLDOT_IMAGE_REPO, SMOLDOT_IMAGE_TAG, SMOLDOT_IMAGE_PLATFORM,
# SMOLDOT_BOOTSTRAP_TIMEOUT override the defaults below.

set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/../.." && pwd)"

REPO="${SMOLDOT_IMAGE_REPO:-alexandrugheorghe248/smoldot-asset-hub-light}"
TAG="${SMOLDOT_IMAGE_TAG:-$(date -u +%Y%m%d-%H%M)}"
PLATFORM="${SMOLDOT_IMAGE_PLATFORM:-linux/amd64}"
BOOTSTRAP_TIMEOUT="${SMOLDOT_BOOTSTRAP_TIMEOUT:-420}"
SEED_DIR="$HERE/seed-db"

push=
keep_db=
cold=
from_dir=

while (( $# > 0 )); do
    case "$1" in
        --push)     push=1 ;;
        --keep-db)  keep_db=1 ;;
        --cold)     cold=1 ;;
        --from)     from_dir="${2:?--from needs a directory}"; shift ;;
        --tag)      TAG="${2:?--tag needs a value}"; shift ;;
        --repo)     REPO="${2:?--repo needs a value}"; shift ;;
        --platform) PLATFORM="${2:?--platform needs a value}"; shift ;;
        -h|--help)  sed -n '6,14p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *)          echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

if [[ -n "$cold" && -n "$from_dir" ]]; then
    echo "--cold and --from are mutually exclusive" >&2
    exit 2
fi

# The image bakes in both node lists, and both are git-ignored. Checked up front so that a fresh
# checkout fails here rather than at the image's COPY.
for nodes in nodes.json nodes-bootstrap.json; do
    if [[ ! -s "$HERE/$nodes" ]]; then
        echo "$HERE/$nodes is missing: copy ${nodes%.json}.example.json and fill in the nodes to pin to" >&2
        exit 1
    fi
done

IMAGE="$REPO:$TAG"
NODB_IMAGE="$REPO:$TAG-nodb"

has_both_chains() {
    [[ -s "$1/polkadot.json" && -s "$1/asset-hub-polkadot.json" ]]
}

# The newest database among the ones a build can reasonably find. Only directories holding both
# chains qualify, because the baked seed has to serve the relay-only and the relay + Asset Hub
# profiles alike. `index.mjs` writes these files itself, so their mtime is the moment that data
# was current -- which is not true of `.db_<n>` directories, whose top-level copies carry the
# mtime of the `cp` that made them, so those are deliberately not considered.
newest_database() {
    local best= best_time=0 dir t
    for dir in "$@"; do
        has_both_chains "$dir" || continue
        t=$(stat -c %Y "$dir/polkadot.json")
        if (( t > best_time )); then
            best_time=$t
            best="$dir"
        fi
    done
    [[ -n "$best" ]] || return 1
    printf '%s\n' "$best"
}

# The `nodb` target is the whole runtime image except the database, so bootstrapping in it
# exercises the same client, chain specs and node lists that the final image ships.
echo "=== building $NODB_IMAGE (no database) ==="
docker buildx build --platform "$PLATFORM" --target nodb \
    --file "$HERE/Dockerfile" --tag "$NODB_IMAGE" --load "$ROOT"

if [[ -n "$keep_db" ]] && has_both_chains "$SEED_DIR"; then
    echo "=== baking $SEED_DIR as it stands ==="
else
    start_from=
    if [[ -n "$from_dir" ]]; then
        [[ "$from_dir" = /* ]] || from_dir="$PWD/$from_dir"
        has_both_chains "$from_dir" || {
            echo "$from_dir does not hold both chains' databases" >&2
            exit 1
        }
        start_from="$from_dir"
    elif [[ -z "$cold" ]]; then
        start_from="$(newest_database "$SEED_DIR" "$HERE/.db" || true)"
    fi

    if [[ -n "$start_from" ]]; then
        echo "=== refreshing the database from $start_from ($(date -u -d "@$(stat -c %Y "$start_from/polkadot.json")" +%Y-%m-%dT%H:%MZ)) ==="
    else
        echo "=== no database to refresh; bootstrapping cold (up to ${BOOTSTRAP_TIMEOUT}s) ==="
    fi

    container="smoldot-asset-hub-light-bootstrap-$$"
    trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT

    bootstrap=(./bootstrap-db.sh)
    [[ -n "$start_from" ]] && bootstrap+=(--from /seed-in)
    bootstrap+=(/seed "$BOOTSTRAP_TIMEOUT")

    # Created rather than run, so that the seed can be copied in before it starts. Outbound
    # only: the validators on tcp/30333 and the collator on tcp/443. Nothing listens.
    docker create --name "$container" --platform "$PLATFORM" \
        "$NODB_IMAGE" "${bootstrap[@]}" >/dev/null

    if [[ -n "$start_from" ]]; then
        docker cp "$start_from" "$container:/seed-in"
    fi

    docker start --attach "$container"

    rm -rf "$SEED_DIR"
    mkdir -p "$SEED_DIR"
    docker cp "$container:/seed/." "$SEED_DIR/"

    docker rm -f "$container" >/dev/null
    trap - EXIT
fi

has_both_chains "$SEED_DIR" || {
    echo "$SEED_DIR does not hold both chains' databases; cannot bake one in" >&2
    exit 1
}
echo "=== seed database: $(du -sh "$SEED_DIR" | cut -f1) ==="

echo "=== building $IMAGE (database baked in) ==="
# An array, not "${push:+--push}": quoted, that expands to an empty argument rather than to
# nothing, and docker counts it as a second positional argument.
publish=(--load)
if [[ -n "$push" ]]; then
    publish=(--push)
fi
docker buildx build --platform "$PLATFORM" --target seeded \
    --file "$HERE/Dockerfile" --tag "$IMAGE" "${publish[@]}" "$ROOT"

echo
if [[ -n "$push" ]]; then
    echo "pushed $IMAGE"
    echo "set this tag in the deployment that runs it:"
    echo "  tag: \"$TAG\""
else
    echo "built $IMAGE locally; re-run with --push to publish it"
fi
