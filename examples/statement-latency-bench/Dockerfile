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
RUN npm install --omit=dev


FROM alpine:latest

RUN apk add --no-cache nodejs

WORKDIR /app
COPY --from=builder /build/examples/statement-latency-bench /app

ENTRYPOINT ["node", "/app/bench.js"]
