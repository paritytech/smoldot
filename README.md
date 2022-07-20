Lightweight Substrate and Polkadot client.

# Introduction

`smoldot` is a prototype of an alternative client of [Substrate](https://github.com/paritytech/substrate)-based chains, including [Polkadot](https://github.com/paritytech/polkadot/).

In order to simplify the code, two main design decisions have been made compared to Substrate:

- No native runtime. The execution time of the `wasmtime` library is satisfying enough that having a native runtime isn't critical anymore.

- No pluggable architecture. `smoldot` supports a certain hard coded list of consensus algorithms, at the moment Babe, Aura, and GrandPa. Support for other algorithms can only be added by modifying the code of smoldot, and it is not possible to plug a custom algorithm from outside.

There exists two clients: the full client and the wasm light node.

The main development focus is currently around the wasm light node. Using https://github.com/polkadot-js/api/ and https://github.com/paritytech/substrate-connect/ (which uses smoldot as an implementation detail), one can easily connect to a chain and interact in a fully trust-less way with it, from JavaScript.

### Full client

The full client is a binary similar to the official Polkadot client, and can be tested with `cargo run`.

> Note: The `Cargo.toml` contains a section `[profile.dev] opt-level = 2`, and as such `cargo run` alone should give performances close to the ones in release mode.

The following list is a best-effort list of packages that must be available on the system in order to compile the full node:

- `clang` or `gcc`
- `pkg-config`
- `sqlite`

The full client is currently a work in progress and doesn't support many features that the official client supports.

### Wasm light node

Pre-requisite: in order to run the wasm light node, you must have installed [rustup](https://rustup.rs/).

The wasm light node can be tested with `cd bin/wasm-node/javascript` and `npm install; npm start`. This will compile the smoldot wasm light node and start a WebSocket server capable of answering JSON-RPC requests. This demo will print a list of URLs that you can navigate to in order to connect to a certain chain. For example you can navigate to <https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944%2Fwestend> in order to interact with the Westend chain.

> Note: The `npm start` command starts a small JavaScript shim, on top of the wasm light node, that hard codes the chain to Westend and starts the WebSocket server. The wasm light node itself can connect to a variety of different chains (not only Westend) and doesn't start any server.

The Wasm light node is published:

- On NPM: https://www.npmjs.com/package/@substrate/smoldot-light
- On Deno.land/x: https://deno.land/x/smoldot (URL to import: `https://deno.land/x/smoldot/index-deno.js`)

# Objectives

There exists multiple objectives behind this repository:

- Write a client implementation that is as comprehensive as possible, to make it easier to understand the various components of a Substrate/Polkadot client. A large emphasis is put on documentation.
- Implement a client that is lighter than Substrate, in terms of memory consumption, number of threads, and code size, in order to compile it to WebAssembly and distribute it in web pages.
- Experiment with a new code architecture, to maybe upstream some components to Substrate and Polkadot.
