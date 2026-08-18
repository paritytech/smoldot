# Introduction

`smoldot` is an alternative client of [Substrate](https://github.com/paritytech/substrate)-based chains, including [Polkadot](https://github.com/paritytech/polkadot/).

This repository contains the following components:

- `smoldot-light-js` (`/wasm-node`): A JavaScript package that can connect to a Substrate-based chains as a light client. Works both in the browser and in NodeJS/Deno. **This is the main component of this repository. The development mostly focuses around it, and the name `smoldot` generally refers to this component in particular.**
  - 📦 NPM: <https://www.npmjs.com/package/smoldot>. Only versions of NodeJS that [are still maintained](https://nodejs.dev/en/about/releases/) are guaranteed to be supported.
  - 📦 Deno.land/x: <https://deno.land/x/smoldot2> (URL to import: `https://deno.land/x/smoldot2/index-deno.js`)
  - 📄 CHANGELOG: <https://github.com/paritytech/smoldot/blob/main/wasm-node/CHANGELOG.md>
  - 📚 <https://paritytech.github.io/smoldot/doc-javascript/> (latest commit)
  - Has a stable API that rarely changes.

- `smoldot` (`/lib`): An unopinionated Rust library of general-purpose primitives that relate to Substrate and Polkadot. Serves as a base for the other components.
  - 📦 <https://crates.io/crates/smoldot>
  - 📚 <https://docs.rs/smoldot> (latest published version)
  - 📚 <https://paritytech.github.io/smoldot/doc-rust/smoldot/index.html> (latest commit)
  - Tests coverage: <https://paritytech.github.io/smoldot/tests-coverage/index.html> (latest commit)
  - Has an unstable API.

- `smoldot-light` (`/light-base`): A platform-agnostic Rust library that can connect to a Substrate-based chain as a light client. Serves as the base for the `smoldot-light-js` component explained above.
  - 📦 <https://crates.io/crates/smoldot-light>
  - 📚 <https://docs.rs/smoldot-light> (latest published version)
  - 📚 <https://paritytech.github.io/smoldot/doc-rust/smoldot_light/index.html> (latest commit)
  - Has a semi-stable API that might change occasionally in minor ways.

- `smoldot-full-node` (`/full-node`): A work-in-progress prototype of a full node binary that can connect to Substrate-base chains. Doesn't yet support many features that the official client supports.
  - 🐳 <https://github.com/paritytech/smoldot/pkgs/container/full-node>
  - 📦 `cargo install --locked smoldot-full-node`
  - Has semi-stable CLI commands that might change occasionally in minor ways.
  - Can also be used as a library to be embedded in other programs:
    - 📦 <https://crates.io/crates/smoldot-full-node>
    - 📚 <https://docs.rs/smoldot-full-node> (latest published version)
    - 📚 <https://paritytech.github.io/smoldot/doc-rust/smoldot_full_node/index.html> (latest commit)

[![dependency status](https://deps.rs/repo/github/paritytech/smoldot/status.svg)](https://deps.rs/repo/github/paritytech/smoldot)

# Frequently asked questions

## Does smoldot support &lt;blockchain&gt;?

Smoldot pledges to support the Polkadot, Kusama, Westend, and Rococo chains, where "support" means "everything works as intended".

Because Polkadot, Kusama, Westend, and Rococo were built using the Substrate framework, smoldot has to support most features found in the Substrate repository. Consequently, smoldot is able to connect to most Substrate-based chains.

However, given that Substrate is a very generic framework that doesn't offer any specification, and that any user of Substrate can in principle modify most aspects of it in any way they want. 

It is not possible to offer a guarantee that smoldot is compatible with all Substrate-based chains.

## Can I embed smoldot into a mobile application or an application in general?

Yes! There exists two ways of doing that:

- If your application is in Rust, use the `smoldot-light` library (see above). You can find a usage example in the `examples` directory. If your application uses a language or technology other than Rust (Flutter, React Native, C++, etc.), you can also embed ̀`smoldot-light` by writing a small Rust library that uses `smoldot-light` then writing bindings from your technology that makes it possible to call into your Rust code.
- If your application is in JavaScript or can embed JavaScript (for example in a `WebView`), use the `smoldot-light-js` package (see above). `smoldot-light-js` is itself built on top of `smoldot-light`.

For technologies other than Rust or JavaScript, the second solution has obviously more overhead since there are more layers, but is easier.

While it is not excluded to add Flutter/React Native/etc. packages to this repository that make it as easy as possible to integrate smoldot. 

The main maintainer of this repository unfortunately doesn't know enough about mobile development to create or maintain these packages.

## How can I attack smoldot?

Smoldot has the following known vulnerabilities:

- **Eclipse attacks** (full nodes and light clients both affected). A blockchain consists in a peer-to-peer network, and smoldot tries to connect to a variety of nodes of this network. If all the nodes smoldot is connected to were to refuse sending data to smoldot, it would effectively isolate smoldot from the network. While smoldot tries to remedy to the situation by connecting to multiple randomly-chosen nodes, the way it learns which nodes exist is from the nodes themselves. If smoldot is only ever connected to malicious nodes, it won't ever be able to reach non-malicious nodes. This is important in the case of bootnodes, as they are the set of nodes that smoldot initially knows. In other words, if the list of bootnodes only contains malicious nodes, smoldot will never be able to reach any non-malicious node. If the list of bootnodes contains a single honest node, then smoldot will be able to reach the whole network. Unless it is combined with one of the other attacks explained below, this attack is effectively a denial-of-service, as it will prevent smoldot from accessing the chain.

- **Long-range attacks** (full nodes and light clients both affected). If more than 2/3rds of the validators collaborate they can fork a chain starting from a block where they were validator, even if they are no longer part of the active validators at the head of the chain. If some validators were to fork a chain, the equivocation system would punish them by stealing their staked tokens. However, they cannot be punished if they unstake their tokens (which takes 7 days for Kusama or 28 days for Polkadot) before creating the fork. If smoldot hasn't been online since the starting point of the fork, it can be tricked (through an eclipse attack) into following the illegitimate fork. In order to not be vulnerable, smoldot shouldn't stay offline for more than the unstaking delay (7 days for Kusama or 28 days for Polkadot) in a row. Alternatively, smoldot isn't vulnerable if the checkpoint provided in the chain specification is not older than the unstaking delay. Given that this attack requires the collaboration of many validators, is "all-in", detectable ahead of time, requires being combined with an eclipse attack, and that it doesn't offer any direct reward, it is considered not a realistic threat.

- **Invalid best block** (light clients only). Light clients don't verify whether blocks are valid but only whether blocks are *authentic*. A block is authentic if it has been authored by a legitimate validator at a time when it was authorized to author a block. A validator could author a block that smoldot considers as authentic, but that contains completely arbitrary data. Invalid blocks aren't propagated by honest full nodes on the gossiping network, but it is possible for the validator to send the block to the smoldot instance(s) that are directly connected to it or its complicits. While this attack requires a validator to be malicious and that it doesn't offer any direct reward it is unlikely to happen, but it is still a realistic threat. For this reason, when using a light client, **do not assume any storage data coming from a best that hasn't been finalized yet to be accurate**. Once a block has been finalized, it means that at least 2/3rds of the validators consider the block valid. While it is still possible for a finalized block to be invalid, this would require the collaboration of 2/3rds of the validators. If that happens, then the chain has basically been taken over, and whether smoldot shows inaccurate data doesn't really matter anymore. When it comes to UIs built on top of a light client, it is suggested to always show the state of the finalized block, and show the state of the best block *in addition to* the one of the finalized block if it differs.

- **Finality stalls** (mostly light clients). Because any block that hasn't been finalized yet can become part of the canonical chain in the future, a node, in order to function properly, needs to keep track of all the valid (for full nodes) or authentic (for light clients) non-finalized blocks that it has learned the existence of. Under normal circumstances, the number of such blocks is rather low (typically 3 blocks). If, however, blocks cease to be finalized but new blocks are still being authored, then the memory consumption of the node will slowly increase over time for each newly-authored block until there is no more memory available and the node is forced to stop. Since it is normally not possible for finality to stall unless there is a bug or the chain is misconfigured, this is not really an attack but rather the consequences of an attack. Full nodes are less affected by this problem because they typically have more memory available than a light client, and have the possibility to store blocks on the disk.

Note that none of these attacks are specific to the smoldot implementation, but are rather known ways to attack a Substrate/Polkadot node in general. All implementations are affected by all these attacks.

## Is it safe to use smoldot?

The smoldot light client does in no way have access to any private key (with the exception of the networking private key, which is automatically rotated and isn't sensitive). Any transaction (such as a balance transfer) is signed *before* being provided to smoldot. While it is possible for smoldot to contain for example a remote code execution issue that could lead to an attacker reading a private key, this type of issue is extremely unlikely to happen. When it comes to getting your keys/funds stolen, using the smoldot light client isn't inherently more risky than using a JSON-RPC server.

On the other hand, when connecting to a chain through a JSON-RPC server (like is the case for example on PolkadotJS by default) you run the risk of being shown inaccurate data, as the UI blindly trusts the JSON-RPC server to be honest. Smoldot does in no way trust the full nodes to be honest.

In most likelihood, the worst that could happen when using smoldot is "it's not working".

## I've tried using smoldot and it's very slow!

If you are using smoldot through PolkadotJS, it is likely that the issue you are suffering from isn't smoldot's fault. The JSON-RPC protocol used by PolkadotJS to talk to smoldot is generally poorly designed and is completely inadapted to light clients, and the smoldot light client has to use a lot of guesswork to understand what PolkadotJS desires. [A new JSON-RPC protocol](https://github.com/paritytech/json-rpc-interface-spec/) has been developed and is supported by both smoldot and Substrate, but higher-level libraries or UIs haven't updated to it yet.

However, please open an issue nonetheless. We unfortunately can't magically discover the issues that you see, especially when it comes to poor performances.

# About the repository

## License

The source code in this repository is distributed under the GPLv3 license. See the &lt;LICENSE&gt; file.

This source code comes with absolutely no warranty. Use at your own risk.

Due to the history of this repository, the code written in 2022 and before belongs to Parity Technologies. Code written in 2023 and later belongs to individual contributors.

## Governance and contributions

This project operates under the typical "benevolent dictator" model. The main maintainer, @tomaka, is being remunerated to work on the source code through Polkadot treasury proposals.

Pull requests are welcome. However, if your changes are substantial, you are strongly encouraged to first discuss the nature of the changes through an issue or discussion. In general, unless the changes you are making are trivial, you are never wrong if you first open an issue instead of a pull request. Keep in mind that changes that might seem easy are often harder than they look. Changes that are *actually* easy have a high chance of having already been completed.

Anyone contributing to this project pledges to propose a welcoming, constructive, and respectful environment for everyone. Trolling, harassment, or sexual advances aren't tolerated.

## Security

While the light client is fully maintained, please be aware that at the moment the full node is completely experimental. While none of the source code in this repository comes with any guarantee, it is even more true for the full node. You are at the moment strongly encouraged to not run a validator using the smoldot full node in a production environment, as it could result in a loss of money.

**The following are considered critical security issues**. If you find such an issue, please use the GitHub private disclosure feature found at <https://github.com/paritytech/smoldot/security/advisories>:

- Smoldot believes that a certain block has been finalized, when it is not actually the case on the blockchain it is connected to.
- Remote arbitrary memory accesses.
- Remote code executions.

**The following are considered security issues and are given particular attention**. Given the extreme difficulty, monetary risk, and extremely low potential of reward for an attacker to exploit these issues, it is not problematic to publicly disclose them:

- Smoldot crashes due to a certain exchange of messages on the libp2p networking level, including a high volume of data.
- Smoldot crashes due to a certain exchange of messages on the JSON-RPC requests level, including a high volume of requests or responses.
- A response to a JSON-RPC request provides incorrect or incomplete information. In the context of the light client, this doesn't apply to the legacy JSON-RPC requests that can't be implemented properly due to technical reasons. A warning is printed when a legacy JSON-RPC request is called.

Where "crash" includes: Rust panics, JavaScript exceptions (except for the ones documented), infinite loops, or allocating an ever increasing amount of memory (a.k.a. a "memory leak").

**Is not considered a security issue**:

- **The smoldot light client believes that a certain block exists or is valid, while in reality it isn't valid**. A light client has no way to determine for sure whether a block is valid. Only finality should be relied upon when accuracy is critical.
- Smoldot crashes due to an unintended use of its API. Note that "API" here doesn't include the content or volume of JSON-RPC requests, as smoldot is meant to be resilient to malicious JSON-RPC requests or to a huge volume of JSON-RPC requests.
- Smoldot runs out of memory because it is being asked to connect to a high number of chains at the same time. The precise limit to the number of chains depends on the amount of memory available.
- Being able to determine the identity (including the IP address) of the sender of a transaction sent using smoldot. This aspect could be improved in the future, but at the moment the Polkadot network protocol doesn't provide enough tools to make anonymity possible.
- Smoldot failing to connect to a certain chain. While this isn't a *security* issue, please open an issue regardless.
- A transaction sent through smoldot not being included in the chain in a certain time period. While this isn't a *security* issue, please open an issue regardless.
- The best block and/or finalized block reported by smoldot lags behind the one on the chain.

## Building manually

### Wasm light node

In order to run the wasm light node, you must have installed [rustup](https://rustup.rs/).

The wasm light node can be tested with `cd wasm-node/javascript` and `npm install; npm start`. This will compile the smoldot wasm light node and start a WebSocket server capable of answering JSON-RPC requests. This demo will print a list of URLs that you can navigate to in order to connect to a certain chain. For example you can navigate to <https://ipfs.io/ipns/dotapps.io/?rpc=ws%3A%2F%2F127.0.0.1%3A9944%2Fwestend2> in order to interact with the Westend chain.

> Note: The `npm start` command starts a small JavaScript shim, on top of the wasm light node, that hard codes the chain to Westend and starts the WebSocket server. The wasm light node itself can connect to a variety of different chains (not only Westend) and doesn't start any server.

### Full client

The full client is a binary similar to the official Polkadot client, and can be tested with `cargo run`.

> Note: The `Cargo.toml` contains a section `[profile.dev] opt-level = 2`, and as such `cargo run` alone should give performances close to the ones in release mode.

The following list is a best-effort list of packages that must be available on the system in order to compile the full node:

- `clang` or `gcc`
- `pkg-config`
- `sqlite`
