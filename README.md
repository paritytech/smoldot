Lightweight Substrate and Polkadot client.

# Introduction

`substrate-lite` is a prototype of an alternative client of [Substrate](https://github.com/paritytech/substrate)-based chains, including [Polkadot](https://github.com/paritytech/polkadot/).

In order to simplify the code, two main design decisions have been made compared to Substrate:

- No native runtime. The execution time of the `wasmtime` library is satisfying enough that having a native runtime isn't critical anymore.

- No pluggable architecture. `substrate-lite` supports a certain hardcoded list of consensus algorithms, at the moment Babe, Aura, and GrandPa. Support for other algorithms can only be added by modifying the code of substrate-lite, and it is not possible to plug a custom algorithm from outside.

# Objectives

There exists multiple objectives behind this repository:

- Write a client implementation that is as comprehensive as possible, to make it easier to understand the various components of a Substrate/Polkadot client.
- Implement a client that is lighter than Substrate, in terms of memory consumption, number of threads, and code size, in order to compile it to WebAssembly and distribute it in webpages.
- Experiment with a new code architecture, to maybe upstream some components to Substrate and Polkadot.

# Status

As a quick overview, at the time of writing of this README, the following is supported:

- Verifying Babe and Aura blocks.
- "Executing" blocks, by calling `Core_execute_block`.
- Verifying GrandPa justifications.
- "Optimistic syncing", in other words syncing by assuming that there isn't any fork.
- Verifying storage trie proofs.
- The WebSocket JSON-RPC server is in progress, but its design is still changing.
- An informant.
- A telemetry client (mostly copy-pasted from Substrate and substrate-telemetry).
- An unfinished new networking stack.

The following isn't done yet:

- Authoring blocks isn't supported.
- There is no transaction pool.
- Anything related to GrandPa networking messages. Finality can only be determined by asking a full node for a justification.
- No actual database for the full client.
- The changes trie isn't implemented (it is not enabled on Westend, Kusama and Polkadot at the moment).
- A Prometheus server. While not difficult to implement, it seems a bit overkill to have one at the moment.

## How to test

There exists two clients.

The full client can be tested with `cargo run`.

> Note: The `Cargo.toml` contains a section `[profile.dev] opt-level = 2`, and as such `cargo run` alone should give performances close to the ones in release mode.

The light client running in a browser can be tested with `cd browser-node` and `./build.sh`.

# Coding rules

This code base proposed a few opinionated approaches. Highlighted below are the ones that differ from Substrate.

## Readability

The number one objective of this code base is to conform to the Substrate/Polkadot specs and not have any bug or security issue.
But beyond that, the most important metric of quality of this source code is how easy it is to understand.

The reference point of this metric is the documentation generated by `cargo doc`. It can more or less be seen as cargo-doc-driven development.

In practice:

- Code must be properly documented, and the context for why the code exists should be given.
- Examples must be written as much as possible.
- When possible, use types found in the standard library rather than types defined locally or defined in other libraries. For example, always use `[u8; 32]` rather than `H256`. In particular, try as much as possible to not expose types of third-party libraries in the public API.
- Do not try too hard to apply the "Don't Repeat Yourself" principle. Having to jump to a different file to understand what is going on is a big hit to the objective of readability.
- Trait definitions are only ever allowed for implementation details. Custom traits **must not** be exposed in any public API.
- The code base should not be split into multiple crates unless there is a good reason to (improving the compilation time would be considered a good reason only if objective measurements show huge differences).
- Macros, custom derives, and procedural macros are allowed only if it is straight-forward for a human being to understand which code the macro generates on usage.

## Purity

When applicable, code must not have any side effect and must only ever return an output that directly depends on its inputs.

In particular, it must (when applicable) not perform any operation that directly or indirectly requires help from the operating system, such as getting the current time, accessing files, or sleeping a thread. One must strive to make the code compile for `no_std` contexts if theoretically possible. Any code that bypasses this restriction must be optional and disableable at compilation time.

In practice:

- No global variables (except for niche optimizations).
- No thread-local variables (except for niche optimizations).
- Never sleep the current thread (directly or indirectly). Everything must be asynchronous.
- Don't use the `log`, `tracing`, `slog`, or similar library.
- Do not perform memory allocations unless the logic of the code you're writing requires storing data for later or passing data between tasks/threads. Memory allocations aren't a bad thing, but we should try to fight against the lazy habit of adding a `.to_vec()` or `.clone()` here and there to make the code compile and without thinking about it. Adding `to_vec()` or `clone()` is often the wrong solution to the problem.

## Reusability: don't mix concerns

Substrate is based on an architecture where each piece of code plays a specific role in a grander vision. The author of *substrate-lite* considers that this grander vision is too complicated for this kind of architecture.

In *substrate-lite*, almost all the modules of the source code are provided as tools, as if they were small libraries that are available to be used. When writing code, focus on providing a specific tool, and do not think about the position the code you're writing will have in the client as a whole. For example, do not assume that the struct you're writing will only be instantiated once, or that it will be shared through an `Arc`.

> **Note**: One exception to the previous paragraph is the code located inside or close to the `main` function of the binary, as long as it is documented.

For example, features such as Prometheus metrics or the RPC endpoints **must not** be rooted in the code. It **must** be theoretically easy to remove support for this kind of feature from the source code. Prefer *pulling* information from components from a higher-level rather than passing `Arc` objects around.

Other example: the module that verifies whether a block respects the Babe algorithm must be passed as input the information required for this verification, and doesn't try, for example, to load the information from a database. The Babe verification code should only not be concerned with the concept of a database.

In practice:

- Dependency injection is almost always a bad thing. Any complex trait definition ("complex" here meaning "more complex than the ones found in the standard library such as `Clone` or `Eq`") is forbidden.
- Exposing `Arc`s or `Mutex`es in your public API is almost always a bad thing.

## Assumption that specs will not change

Substrate is organized around core components that are almost impossible to extract: a database, a client, the networking, a transaction pool, and so on. These components are tightly coupled together.

The blockchain-related logic is plugged on top of these core components and can, however, be changed. One can, for example, remove everything related to the Babe consensus algorithm and replace with by another consensus algorithm.

*substrate-lite*, on the other hand, is implemented following the current state of the Substrate/Polkadot specifications, and assumes that these specifications will never change. This assumption allows, in turn, for better readability and more flexibility when it comes to the purely engineering aspects of the codebase.

For example, the code that decodes block headers is written in a way that would be quite annoying (though straight-forward) to modify if the format of a block header ever changed. However, we simply assume that the format of block headers will rarely, if ever, change.

In particular, there is an assumption that the list of consensus algorithms is known in advance and will rarely change. Substrate-lite prefers the explicitness of code specific to every single consensus code, rather than giving the fake impression to the user that they can simply plug their own algorithm and expect everything to work.

## Fail fast

Code **must not** panic as a result of unexpected input from the user or from the network.

However, code **must** panic if its internal consistency is compromised. In other words, if the only possible reason for the panic is a bug in the logic of the code.

The author of this crate considers that it is dangerous to try to continue running the program if it is known that it does not run according to expectations. Node operators are expected to setup their node in such a way that it automatically restarts in case of a crash. Additionally, crashing the node increases the chances of an issue being reported rather than ignored.

While there is no rule in this source code about `unwrap`, the programmer is expected to think about every single `unwrap()` that they write and is concious that a `None` or an `Err` cannot happen unless a bug is present.
