# syntax=docker/dockerfile:1

# Smoldot
# Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
# SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
#
# Runs `examples/asset-hub-light` the way `./run-instances.sh` runs it locally: pinned to the
# single validator and single collator of `nodes.json`, off a warm database.
#
# The build context is the repository root, not this directory -- building the client's Wasm
# needs the cargo workspace. Use the script rather than calling docker directly:
#
#     ./examples/asset-hub-light/build-image.sh --push
#
# Two targets. `nodb` is the image without a database, which is what the bootstrap itself runs
# in; `seeded` is that image with a freshly bootstrapped database baked in, and is what runs in
# the cluster.

########################################  build  ########################################

FROM rust:1.92-bookworm AS build

# `prepare.mjs` shells out to cargo and `buildModules` to tsc, so the build stage needs both
# toolchains. The repository's CI pins Node 18 as the oldest still-maintained version; newer is
# fine, and tsc wants the memory.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

# `prepare.mjs` probes the toolchain and prefers wasm32v1-none, falling back to
# wasm32-unknown-unknown.
RUN rustup target add wasm32v1-none

WORKDIR /src

# Only what building the client's Wasm and its JavaScript needs. Deliberately not `COPY . .`:
# that would pull in `examples/asset-hub-light/seed-db`, so every database refresh would change
# this layer and send the whole cargo build -- several minutes of it -- through again. The
# example's own files are copied straight from the context into the runtime stage instead.
# `full-node` earns its place by being a workspace member: the manifest does not parse without
# it, even though nothing here builds it.
COPY Cargo.toml Cargo.lock ./
COPY lib lib
COPY full-node full-node
COPY light-base light-base
COPY wasm-node wasm-node

# `npm run build` is `prepare.mjs --release` -- which runs `cargo build --package
# smoldot-light-wasm --profile min-size-release` and then deflates and base64s the resulting
# Wasm into src/internals/bytecode/ -- followed by tsc for both module systems. It has to be
# run explicitly: there is no `prepare` script, so `npm install` alone builds nothing.
#
# The second `npm ci` drops the devDependencies, leaving `ws`, which is the only package the
# built code needs at runtime.
WORKDIR /src/wasm-node/javascript
RUN npm ci && npm run build && npm ci --omit=dev

########################################  nodb  #########################################

FROM node:22-bookworm-slim AS nodb

# bash, because the cronjob chart this runs under starts containers with
# `command: [ "/bin/bash" ]`, and run-instances.sh is a bash script. It supervises its instances
# with setsid (util-linux), ps (procps) and GNU `tail --pid`, none of which busybox provides --
# hence Debian, not Alpine. ca-certificates is for the collator, which is reached over WSS
# through a TLS front.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash ca-certificates procps util-linux \
 && rm -rf /var/lib/apt/lists/*

# index.mjs resolves everything from its own directory rather than from the working directory,
# so the layout it expects has to survive into the image: the client two levels up under
# wasm-node/javascript/dist/mjs, and the chain specs under demo-chain-specs. Only the ESM build
# and the two specs the example actually reads are copied.
COPY --from=build /src/wasm-node/javascript/dist/mjs     /app/wasm-node/javascript/dist/mjs
COPY --from=build /src/wasm-node/javascript/node_modules /app/wasm-node/javascript/node_modules
COPY demo-chain-specs/polkadot.json                      /app/demo-chain-specs/polkadot.json
COPY demo-chain-specs/polkadot_asset_hub.json            /app/demo-chain-specs/polkadot_asset_hub.json
COPY examples/asset-hub-light/index.mjs                  /app/examples/asset-hub-light/
COPY examples/asset-hub-light/worker.mjs                 /app/examples/asset-hub-light/
# `index.mjs` imports revive-reads.mjs unconditionally, so it is needed whether or not the
# contract reads are switched on; revive-queries.json is only read when they are, but it is
# what makes the image work with no configuration, so it is baked in like the chain specs.
COPY examples/asset-hub-light/revive-reads.mjs           /app/examples/asset-hub-light/
COPY examples/asset-hub-light/revive-queries.json        /app/examples/asset-hub-light/
COPY examples/asset-hub-light/package.json               /app/examples/asset-hub-light/
# Git-ignored, so they have to exist in the checkout being built: copy them from the
# `.example.json` templates and fill in the nodes to pin to.
COPY examples/asset-hub-light/nodes.json                 /app/examples/asset-hub-light/
COPY examples/asset-hub-light/nodes-bootstrap.json       /app/examples/asset-hub-light/
COPY examples/asset-hub-light/run-instances.sh           /app/examples/asset-hub-light/
COPY examples/asset-hub-light/bootstrap-db.sh            /app/examples/asset-hub-light/

# The cronjob chart this runs under hard-codes `workingDir: /data`, which has to exist. Nothing
# is written there: run-instances.sh works relative to the script's own directory.
RUN mkdir -p /data

WORKDIR /app/examples/asset-hub-light

# run-instances.sh rather than index.mjs directly. Kubernetes terminates pods with SIGTERM,
# which index.mjs does not handle -- it saves its databases on SIGINT only, so as PID 1 it
# would be killed after the grace period with nothing written. The launcher traps SIGTERM and
# sends each instance the one SIGINT it wants. It is also what `npm run start:many` runs, so
# the container does what the example does.
STOPSIGNAL SIGINT
CMD ["./run-instances.sh"]

#######################################  seeded  ########################################

FROM nodb AS seeded

# A warm database is not optional when pinned to a single validator. Before warp sync
# completes, smoldot fetches `:code` at the chain spec's months-old checkpoint; a validator
# running --state-pruning 256 answers RemoteCouldntAnswer; smoldot reads that as misbehaviour
# and bans the peer for 10 s, which drops the in-flight warp-sync request with it. With one
# peer there is no fallback, so it never finishes.
#
# `.db` is exactly where run-instances.sh looks for a seed by default, so the container needs
# no configuration to find it, and `cp -r .db .db_<i>` gives every instance a warm start. The
# database carries no identity -- only chain information, a peer list and the `:code` blob.
#
# Databases age: regenerate with ./build-image.sh, which bootstraps a fresh one inside the
# `nodb` image above and then builds this target.
COPY examples/asset-hub-light/seed-db /app/examples/asset-hub-light/.db
