# Build & run the statement-latency-bench Node.js tool.
#
# The bench depends on the local `smoldot` npm package
# (wasm-node/javascript), whose `prepack` step compiles Rust → wasm.
# So the builder stage needs rust + the wasm32 target + node.

FROM rust:1 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown

COPY ./.. /build
WORKDIR /build/examples/statement-latency-bench
# --install-links materializes the `file:../../wasm-node/javascript`
# dep as a real copy in node_modules instead of a symlink, so the
# runtime stage can be a self-contained copy of just this directory.
RUN npm install --omit=dev --install-links


FROM alpine:latest

RUN apk add --no-cache nodejs bash

WORKDIR /app
COPY --from=builder /build/examples/statement-latency-bench /app

ENTRYPOINT ["node", "/app/bench.js"]
