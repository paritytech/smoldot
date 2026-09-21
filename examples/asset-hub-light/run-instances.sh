#!/usr/bin/env bash
# Smoldot
# Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
# SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
#
# Runs several `index.mjs` instances side by side, each with its own database directory.
#
# Instances are started strictly one at a time: the next one is spawned only once the previous one
# has printed a finalized Asset Hub head, which is the point at which it is actually following the
# chain rather than still warp-syncing. An instance that exits first, or takes too long to get
# there, is started again a few times before the script gives up.
#
#   ./run-instances.sh 4
#
# Environment:
#   SMOLDOT_INSTANCES       number of instances, when not given as the first argument (default 2)
#   SMOLDOT_DB_PREFIX       database directory prefix (default `.db_`, giving `.db_1`, `.db_2`, …)
#   SMOLDOT_SEED_DB         database directory copied into an instance's directory when it has
#                           none yet (default `.db`); set to empty to always start cold
#   SMOLDOT_READY_TIMEOUT   seconds to wait for an instance to follow the chain (default 180)
#   SMOLDOT_LOG_DIR         where the logs go (default `logs/`): one file per instance, plus
#                           `all.log` with everything the terminal showed
#   SMOLDOT_START_RETRIES   how many times an instance that exits, or is still not following the
#                           chain after SMOLDOT_READY_TIMEOUT, is started again before the script
#                           gives up and stops everything (default 3)
#
# Everything else in the environment is passed through, so SMOLDOT_NODES, SMOLDOT_UNPINNED,
# SMOLDOT_TCP_ONLY and SMOLDOT_LOG_LEVEL work as they do for `index.mjs`. SMOLDOT_DB_DIR is the
# exception: it is set per instance and any inherited value is ignored.

set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

COUNT="${1:-${SMOLDOT_INSTANCES:-2}}"
DB_PREFIX="${SMOLDOT_DB_PREFIX:-.db_}"
SEED_DB="${SMOLDOT_SEED_DB-.db}"          # Unset means `.db`; set-but-empty means "always cold".
READY_TIMEOUT="${SMOLDOT_READY_TIMEOUT:-180}"
START_RETRIES="${SMOLDOT_START_RETRIES:-3}"
LOG_DIR="${SMOLDOT_LOG_DIR:-$HERE/logs}"
COMBINED_LOG="$LOG_DIR/all.log"      # Everything, as shown on the terminal, prefixes included.

# `index.mjs` saves both databases on SIGINT, and gives each chain 15 s to hand one over.
SHUTDOWN_DEADLINE=30

# What `index.mjs` prints once the chain it reports on has a first head: either the "following"
# line (whatever the chain's name, and with an optional `[n] ` client prefix when the instance
# runs several clients) or a block line.
FOLLOWING='^(\[[0-9]+\] )?([A-Za-z ]+ is following the chain|finalized #|imported  #)'

if [[ ! "$COUNT" =~ ^[1-9][0-9]*$ ]]; then
    echo "usage: ${0##*/} [count]   (got \"$COUNT\")" >&2
    exit 2
fi
if [[ ! "$START_RETRIES" =~ ^[0-9]+$ ]]; then
    echo "SMOLDOT_START_RETRIES must be a non-negative integer (got \"$START_RETRIES\")" >&2
    exit 2
fi

pids=()          # Instances that are following the chain.
starting_pid=    # The instance currently being brought up, if any.
shutting_down=

is_running() {
    local state
    state="$(ps -o stat= -p "$1" 2>/dev/null)" || return 1
    [[ -n "$state" && "$state" != Z* ]]
}

any_running() {
    local pid
    for pid in "$@"; do is_running "$pid" && return 0; done
    return 1
}

# A warm database is what makes the pinned setup work at all: pinned to a single validator, a cold
# warp sync stalls, because the runtime fetch at the chain spec's months-old checkpoint is answered
# with `RemoteCouldntAnswer` by a pruned node and earns that node a ban, taking the warp-sync
# request down with it. Copying an existing database into a fresh instance directory is the same
# thing the README's bootstrap step produces, just without re-running it per instance. It carries
# no identity — only chain information, a peer list and the `:code` blob.
provision_database() {
    local db="$1" seed
    if [[ -d "$db" ]]; then
        echo "existing database"
    elif [[ -z "$SEED_DB" ]]; then
        echo "no database (cold start)"
    else
        [[ "$SEED_DB" = /* ]] && seed="$SEED_DB" || seed="$HERE/$SEED_DB"
        if [[ -d "$seed" ]]; then
            cp -r "$seed" "$db"
            echo "database seeded from $SEED_DB"
        else
            echo "no database (cold start; $SEED_DB does not exist)"
        fi
    fi
}

# One SIGINT per instance is what makes them save their databases before exiting.
shutdown() {
    local exit_code="$1" reason="$2" pid deadline running=()

    [[ -n "$shutting_down" ]] && exit "$exit_code"
    shutting_down=1
    trap - INT TERM

    for pid in ${pids[@]+"${pids[@]}"} ${starting_pid:+"$starting_pid"}; do
        is_running "$pid" && running+=("$pid")
    done

    if (( ${#running[@]} > 0 )); then
        echo
        echo "--- stopping ${#running[@]} instance(s) ($reason); each saves its databases first ---"
        kill -INT "${running[@]}" 2>/dev/null || true

        deadline=$(( SECONDS + SHUTDOWN_DEADLINE ))
        while (( SECONDS < deadline )) && any_running "${running[@]}"; do
            sleep 1
        done

        for pid in "${running[@]}"; do
            if is_running "$pid"; then
                echo "--- instance $pid did not exit within ${SHUTDOWN_DEADLINE}s; killing it ---" >&2
                kill -KILL "$pid" 2>/dev/null || true
            fi
        done
    fi

    sleep 1   # Let the `tail` readers above print the instances' last lines.
    exit "$exit_code"
}

# Stops an attempt that is still running but not following the chain. It has nothing to save, so
# it exits on SIGINT right away; the SIGKILL is only for the case where it doesn't.
stop_instance() {
    local pid="$1" deadline
    kill -INT "$pid" 2>/dev/null || true
    deadline=$(( SECONDS + 10 ))
    while (( SECONDS < deadline )) && is_running "$pid"; do
        sleep 1
    done
    if is_running "$pid"; then
        kill -KILL "$pid" 2>/dev/null || true
    fi
}

trap 'shutdown 0 SIGINT' INT
trap 'shutdown 0 SIGTERM' TERM

mkdir -p "$LOG_DIR"
: > "$COMBINED_LOG"

# From here on everything goes to the terminal *and* to `logs/all.log`. The `tee` ignores SIGINT on
# purpose: a Ctrl+C reaches every process in the terminal's foreground process group, and if `tee`
# died first this script's own shutdown messages would hit a closed pipe and SIGPIPE would kill it
# before it could tell the instances to save — leaving them orphaned and unsaved. That is precisely
# what `./run-instances.sh | tee somewhere` does, which is why the combined log is written here.
exec > >(trap '' INT TERM; tee -a "$COMBINED_LOG") 2>&1

for (( i = 1; i <= COUNT; i++ )); do
    db="$HERE/$DB_PREFIX$i"
    provisioned="$(provision_database "$db")"
    log="$LOG_DIR/instance-$i.log"
    : > "$log"

    echo "--- instance $i/$COUNT: starting with $DB_PREFIX$i, $provisioned ---"

    attempts=$(( START_RETRIES + 1 ))
    for (( attempt = 1; attempt <= attempts; attempt++ )); do
        if (( attempt > 1 )); then
            echo "--- instance $i/$COUNT: starting again, attempt $attempt/$attempts ---"
            echo "--- attempt $attempt/$attempts ---" >> "$log"
        fi

        # Only what this attempt writes counts as progress. Earlier attempts' output stays in the
        # log for diagnosis, but must not be mistaken for the new process following the chain.
        log_start=$(wc -c < "$log")

        # `setsid` puts the instance in its own session, so that a Ctrl+C on the terminal reaches
        # this script only. Otherwise every instance would get one SIGINT from the terminal and a
        # second one from `shutdown`, and `index.mjs` treats a second SIGINT as "give up on
        # saving". Without job control the instance is not a process group leader, so `setsid`
        # execs in place rather than forking, which is what keeps `$!` pointing at node itself.
        SMOLDOT_DB_DIR="$db" setsid node "$HERE/index.mjs" >> "$log" 2>&1 &
        pid=$!
        starting_pid=$pid

        # Live output, prefixed with the instance number. `--pid` makes each reader exit on its
        # own once its instance is gone, so there is nothing to clean up. A retry's reader starts
        # at the end of the log: the earlier attempts' lines have already been shown.
        if (( attempt == 1 )); then
            tail -n +1 -f --pid="$pid" "$log" | sed -u "s/^/[$i] /" &
        else
            tail -n 0 -f --pid="$pid" "$log" | sed -u "s/^/[$i] /" &
        fi

        started=$SECONDS
        outcome=
        while :; do
            if tail -c +"$(( log_start + 1 ))" "$log" | grep -qE "$FOLLOWING"; then
                echo "--- instance $i/$COUNT: following the chain after $(( SECONDS - started ))s ---"
                outcome=following
                break
            fi
            if ! is_running "$pid"; then
                sleep 1   # Let the reader print whatever the instance died complaining about.
                echo "--- instance $i/$COUNT: exited before it started following the chain (attempt $attempt/$attempts) ---" >&2
                outcome=exited
                break
            fi
            if (( SECONDS - started >= READY_TIMEOUT )); then
                echo "--- instance $i/$COUNT: still not following the chain after ${READY_TIMEOUT}s (attempt $attempt/$attempts) ---" >&2
                stop_instance "$pid"
                outcome=timeout
                break
            fi
            sleep 1
        done

        starting_pid=
        if [[ "$outcome" = following ]]; then
            pids+=("$pid")
            break
        fi
        if (( attempt == attempts )); then
            echo "--- instance $i/$COUNT: giving up after $attempts attempts ---" >&2
            shutdown 1 "an instance failed to start"
        fi
    done
done

echo "--- all $COUNT instances are following the chain; Ctrl+C to stop them ---"

# Nothing left to do but keep the instances company, and notice if they all go away.
while any_running "${pids[@]}"; do
    sleep 5
done

# Why the instances went is what decides this script's own status. An instance that reached its
# `SMOLDOT_MAX_LIFETIME_MS` saved its databases and exited 0, and a supervisor meant to start a
# fresh one should not be told that the container failed -- under Kubernetes a non-zero exit is
# what turns a planned recycle into a recorded crash, and eventually into CrashLoopBackOff. Any
# other status still fails, because an instance dying on its own terms is a real fault.
worst=0
for pid in "${pids[@]}"; do
    wait "$pid" || worst=$?
done

if (( worst == 0 )); then
    echo "--- every instance exited cleanly ---"
else
    echo "--- every instance has exited; worst status $worst ---" >&2
fi
shutdown "$worst" "every instance exited"
