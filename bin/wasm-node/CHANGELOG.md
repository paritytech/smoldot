# Changelog

## Unreleased

## 0.7.3 - 2022-10-19

### Changed

- The WebRTC protocol implementation is now up to date with the specification. While the specification hasn't been finalized yet and could still evolve, the current version is believed to be likely to be final. ([#2896](https://github.com/paritytech/smoldot/pull/2896))

### Fixed

- Fix timeout not being checked when opening a notifications substream. ([#2323](https://github.com/paritytech/smoldot/pull/2323))
- Fix inbound notifications substreams close requests being ignored. ([#2323](https://github.com/paritytech/smoldot/pull/2323))
- Fix closed inbound notifications substreams still being considered as open when closed gracefully by the remote. ([#2323](https://github.com/paritytech/smoldot/pull/2323))

## 0.7.2 - 2022-10-12

### Changed

- The warp syncing algorithm no longer downloads the runtime code and the runtime call proofs at the same time. Instead, it now first downloads the runtime, then checks the list of available functions, then downloads runtime call proofs. While this slightly degrades the warp syncing time by adding a round-trip time, it is more correct to first analyze the runtime instead of blindly assuming that it supports a certain set of functions. ([#2845](https://github.com/paritytech/smoldot/pull/2845))

### Fixed

- Fix smoldot trying to send requests to peers whose connection is shutting down, leading to a panic. ([#2847](https://github.com/paritytech/smoldot/pull/2847))
- Fix the responses to libp2p identify requests being wrongly empty. ([#2840](https://github.com/paritytech/smoldot/pull/2840))
- Fix some Merkle proofs and SCALE-encoded structures being accepted as correct when they are actually invalid. This is a very minor fix that can presumably not be used as an attack vector. ([#2819](https://github.com/paritytech/smoldot/pull/2819))

## 0.7.1 - 2022-10-04

### Fixed

- Syncing no longer stalls if the gap between the finalized and latest block is more than 100 blocks. ([#2801](https://github.com/paritytech/smoldot/pull/2801))
- No longer silently discard justifications when receive a block from the network that was already known locally. ([#2800](https://github.com/paritytech/smoldot/pull/2800))
- CPU-heavy operations such as verifying finality proofs or compiling the runtime will now better respect the CPU rate limit. ([#2803](https://github.com/paritytech/smoldot/pull/2803))
- Fix the `finalizedBlockHashes` and `prunedBlockHashes` fields having wrong names in `chainHead_unstable_followEvent` events. ([#2812](https://github.com/paritytech/smoldot/pull/2812))
- Remove "type" parameter from `chainHead_unstable_storage` JSON-RPC method, in accordance with the update in the JSON-RPC specification. ([#2818](https://github.com/paritytech/smoldot/pull/2818))
- The `chainHead_unstable_storage` JSON-RPC method now returns an `error` notification if the block's header couldn't be decoded instead of a `disjoint` notification. ([#2818](https://github.com/paritytech/smoldot/pull/2818))

## 0.7.0 - 2022-09-28

### Removed

- Removed `Chain.databaseContent` function. Use the `chainHead_unstable_finalizedDatabase` JSON-RPC function to obtain the database content instead. ([#2791](https://github.com/paritytech/smoldot/pull/2791))

### Changed

- `Chain.sendJsonRpc` now throws a `MalformedJsonRpcError` exception if the JSON-RPC request is too large or malformed, or a `QueueFullError` if the queue of JSON-RPC requests of the chain is full. ([#2778](https://github.com/paritytech/smoldot/pull/2778))
- Removed `AddChainOptions.jsonRpcCallback`. Use the new `Chain.nextJsonRpcResponse` asynchronous function to pull JSON-RPC responses instead of registering a callback. A `AddChainOptions.disableJsonRpc` flag is now supported in order to bring the same effects as not passing any `jsonRpcCallback`. ([#2778](https://github.com/paritytech/smoldot/pull/2778))
- Removed the `version` field of the struct returned by the `rpc_methods` function. ([#2756](https://github.com/paritytech/smoldot/pull/2756))

### Fixed

- Fix several panics related to cancelling the opening of incoming substreams. ([#2785](https://github.com/paritytech/smoldot/pull/2785))
- Fix old runtimes not being cleaned up properly and runtimes being downloaded multiple times after an on-chain runtime upgrade. ([#2781](https://github.com/paritytech/smoldot/pull/2781))

## 0.6.34 - 2022-09-20

### Added

- Add experimental support for WebRTC according to the in-progress specification for libp2p-webrtc. For now this feature must explicitly be enabled by passing `enableExperimentalWebRTC: true` as part of the ̀`ClientConfig`. The multiaddress format for WebRTC is `/ip4/.../udp/.../webrtc/certhash/...` (or `/ip6/...`), where the payload behind `/certhash` is a multibase-encoded multihash-encoded SHA256 of the DTLS certificate used by the remote. ([#2579](https://github.com/paritytech/smoldot/pull/2579))
- Add support for the `chainHead_unstable_finalizedDatabase` JSON-RPC method. This JSON-RPC method aims to be a replacement for the `databaseContent` method of the `Chain` and is expected to remain a permanently unstable smoldot-specific function. ([#2749](https://github.com/paritytech/smoldot/pull/2749))

### Changed

- No longer try to connect to a peer for 20 seconds after failing to connect to it. This prevents loops where we keep trying to connect to the same address(es) over and over again. ([#2747](https://github.com/paritytech/smoldot/pull/2747))

### Fixed

- Fix potential infinite loop in networking connection task. ([#2751](https://github.com/paritytech/smoldot/pull/2751))
- Fix panic when trying to perform a runtime call on an old block while having no networking connection. ([#2764](https://github.com/paritytech/smoldot/pull/2764))

## 0.6.33 - 2022-09-13

### Added

- Add support for the `system_nodeRoles` JSON-RPC method. ([#2725](https://github.com/paritytech/smoldot/pull/2725))

### Changed

- A limit to the number of substreams a remote can maintain open over a connection is now enforced. ([#2724](https://github.com/paritytech/smoldot/pull/2724))

### Fixed

- No longer panic when calling `state_getRuntimeVersion` is unable to download the runtime code of an old block from the network. ([#2736](https://github.com/paritytech/smoldot/pull/2736))

## 0.6.32 - 2022-09-07

### Fixed

- Fix occasional panic when connecting to a parachain with forks and/or missed slots. ([#2703](https://github.com/paritytech/smoldot/pull/2703))
- Fix parachain initialization unnecessarily waiting for its corresponding relay chain initialization to be finished. ([#2705](https://github.com/paritytech/smoldot/pull/2705))
- Fix panic when broadcasting a transaction to a peer while its connection is shutting down. ([#2717](https://github.com/paritytech/smoldot/pull/2717))
- Fix crash when receiving a Yamux GoAway frame. ([#2708](https://github.com/paritytech/smoldot/pull/2708))

## 0.6.31 - 2022-08-30

### Changed

- In case of protocol error, or if a peer refuses a block announces substream, no new substream with the same peer will be attempted for 20 seconds. This avoids loops where the same peer is tried over and over again. ([#2633](https://github.com/paritytech/smoldot/pull/2633))

### Fixed

- Fix inability to decode addresses with prefixes longer than 1 byte when calling `system_accountNextIndex`. ([#2686](https://github.com/paritytech/smoldot/pull/2686))

## 0.6.30 - 2022-08-12

### Fixed

- Fix panic that occured when connecting to a peer, then discovering it through the background discovery process, then disconnecting from it. ([#2616](https://github.com/paritytech/smoldot/pull/2616))
- Fix circular dependency between JavaScript modules. ([#2614](https://github.com/paritytech/smoldot/pull/2614))
- Fix panic when a handshake timeout or protocol error happens on a connection at the same time as the local node tries to shut it down. ([#2620](https://github.com/paritytech/smoldot/pull/2620))
- Fix panic when a runtime call is made at the same time as a warp sync succeeds or that the limit to the number of blocks in memory is exceeded. ([#2621](https://github.com/paritytech/smoldot/pull/2621))

## 0.6.29 - 2022-08-09

### Fixed

- Fix sometimes erroneously reporting a very old `parent_hash` (usually the genesis block hash) in `chainHead_unstable_follow` when following a parachain. ([#2602](https://github.com/paritytech/smoldot/pull/2602))
- After smoldot has downloaded the runtime of an old parachain block, it would sometimes erroneously consider that this runtime hasn't changed since then. This would lead to issues such as `state_getRuntimeVersion` and `state_subscribeRuntimeVersion` returning information about an old runtime, or `state_getMetadata` or `state_call` using an old runtime. ([#2602](https://github.com/paritytech/smoldot/pull/2602))
- Fix WebSocket errors leading to the program stopping while running in NodeJS. ([#2604](https://github.com/paritytech/smoldot/pull/2604))

## 0.6.28 - 2022-08-08

### Changed

- The GRANDPA warp sync algorithm now downloads Merkle proofs of all the necessary storage items at once, rather than one by one sequentially. This removes approximately 11 networking round-trips and thus significantly reduces the time the warp syncing takes. ([#2578](https://github.com/paritytech/smoldot/pull/2578))
- The GRANDPA warp sync algorithm now works on AURA-based chains. It previously only worked for chains that are using BABE. Note that GRANDPA warp sync is irrelevant for parachains. ([#2581](https://github.com/paritytech/smoldot/pull/2581))
- The GRANDPA warp sync implementation has been considerably refactored. It is possible that unintended changes in behaviour have accidentally been introduced. ([#2578](https://github.com/paritytech/smoldot/pull/2578))
- A warning is now printed if the `badBlocks` field in a chain specification is not empty. Bad blocks are not supported by the smoldot light client. ([#2585](https://github.com/paritytech/smoldot/pull/2585))

### Fixed

- Fix WebSockets not working in the CommonJS bindings for NodeJS due to a problematic import. ([#2589](https://github.com/paritytech/smoldot/pull/2589)).

## 0.6.27 - 2022-07-29

### Changed

- The JavaScript code now targets ES6. This should ensure compatibility on a wider range of platforms. ([#2565](https://github.com/paritytech/smoldot/pull/2565))

## 0.6.26 - 2022-07-20

### Added

- Add support for Deno. Smoldot is now available on the deno.land/x package registry. This doesn't modify anything to the behaviour of the smoldot NPM package. ([#2522](https://github.com/paritytech/smoldot/pull/2522))

### Fixed

- Exceptions thrown in the JSON-RPC callback no longer crash smoldot. ([#2527](https://github.com/paritytech/smoldot/pull/2527))

## 0.6.25 - 2022-07-18

### Added

- Add an optional `blockNumberBytes` field to chain specifications indicating the number of bytes used to encode the block number of the chain. If the field is missing, the value defaults to 4. Prior to this change, the value was always hardcoded to 4. This field is at the moment specific to smoldot, and Substrate will fail to parse chain specifications containing it. ([#2512](https://github.com/paritytech/smoldot/pull/2512))

### Changed

- Refactored the `package.json` file. The `browser` field has been removed. The library now exports by default code reliant on web platform APIs. An `exports` -> `node` field has been added (supported since NodeJS v13.2.0 and NodeJS v12.16.0) in order to export code reliant on NodeJS APIs when NodeJS is importing the library. ([#2519](https://github.com/paritytech/smoldot/pull/2519))

## 0.6.24 - 2022-07-14

### Added

- Add support for CommonJS projects. ([#2487](https://github.com/paritytech/smoldot/pull/2487))

### Changed

- No WebWorker/worker thread is spawned anymore by the JavaScript code. The WebAssembly virtual machine that runs smoldot is now directly instantiated by the `start` function. This should fix compatibility issues with various JavaScript bundlers. ([#2498](https://github.com/paritytech/smoldot/pull/2498))

## 0.6.23 - 2022-07-11

### Fixed

- Fix `state_getKeys` and `state_getKeysPaged` almost always erroneously returning an empty result. ([#2491](https://github.com/paritytech/smoldot/pull/2491))

## 0.6.22 - 2022-07-11

### Changed

- Block headers with an unknown consensus engine now parse successfully. This adds support for parachains using consensus engines that smoldot doesn't recognize. As smoldot cannot verify the validity of their blocks, standalone/relay chains using an unrecognized consensus engine remain unsupported. ([#2481](https://github.com/paritytech/smoldot/pull/2481))
- Standalone/relay chains that use neither Aura nor Babe are no longer supported as they are vulnerable to DoS attacks. Parachains that don't use Aura/Babe continue to work. ([#2481](https://github.com/paritytech/smoldot/pull/2481))
- No warning is generated anymore if the discovery process doesn't work due to having 0 peers, or failed due to a benign networking issue. ([#2476](https://github.com/paritytech/smoldot/pull/2476))

### Fixed

- Changes in the current best block of a parachain are now taken into account if the new best block had already been reported in the past. ([#2457](https://github.com/paritytech/smoldot/pull/2457))
- Fix active `chain_subscribeAllHeads` subscriptions silently freezing when the number of non-finalized blocks gets above a certain threshold, which typically happens if Internet connectivity is lost for a long time. ([#2465](https://github.com/paritytech/smoldot/pull/2465))

## 0.6.21 - 2022-06-30

### Added

- Block headers with a digest item of type `Other` no longer fail to parse. ([#2425](https://github.com/paritytech/smoldot/pull/2425))
- Add support for the `state_getKeys` JSON-RPC method. ([#2438](https://github.com/paritytech/smoldot/pull/2438))

### Fixed

- The `chain_subscribeAllHeads`, `chain_subscribeNewHeads`, and `chain_subscribeFinalizedHeads` JSON-RPC functions no longer panic if connected to a chain whose headers are in a format that can't be decoded. Instead, no notification is sent and a warning is printed. ([#2442](https://github.com/paritytech/smoldot/pull/2442))

### Changed

- The format of the database returned by `Client.databaseContent` has been changed to include the list of nodes that are known to be present on the peer-to-peer network. When the database is restored, these nodes are immediately discovered. This change aims at reducing the importance of bootnodes. This change is a breaking change, meaning that providing a database that has been obtained from a previous version of smoldot will have no effect. ([#2439](https://github.com/paritytech/smoldot/pull/2439))

## 0.6.20 - 2022-06-23

### Changed

- `new Worker` is now called with the `{ type: "module" }` option. Despite not being supported by NodeJS or Firefox, indicating this option is technically more correct and is necessary in order for smoldot to run with Deno. ([#2426](https://github.com/paritytech/smoldot/pull/2426))
- When a database and a chain specification checkpoint are both provided to `addChain`, the block in the database is used only if it has a higher block number than the block in the chain specification checkpoint. This makes it possible to bypass issues where smoldot is incapable of syncing over a certain block by updating the chain specification, without having to manually clear existing databases. ([#2401](https://github.com/paritytech/smoldot/pull/2401))

### Fixed

- Fix errors about verifying justifications. Justifications and Grandpa commits that can't be verified yet are now properly stored in memory in order to be verified later, instead of producing errors. ([#2400](https://github.com/paritytech/smoldot/pull/2400))
- Fix issue where unverified justifications would overwrite one another, meaning that an invalid justification could potentially prevent a valid justification from being taken into account. ([#2400](https://github.com/paritytech/smoldot/pull/2400))

## 0.6.19 - 2022-06-14

### Fixed

- Fix panic introduced in v0.6.18 in case of a fork in the chain related to tracking the number of blocks kept alive in the node's memory. ([#2386](https://github.com/paritytech/smoldot/pull/2386))

## 0.6.18 - 2022-06-14

### Added

- Add support for the `state_call` JSON-RPC function. ([#2374](https://github.com/paritytech/smoldot/pull/2374))
- The `relay_chain` and `para_id` fields in chain specifications can now alternatively be named respectively `relayChain` and `paraId`. This increases consistency with the other fields of chain specifications, which are all camelCase. ([#2366](https://github.com/paritytech/smoldot/pull/2366))

### Fixed

- Fix another panic in case of a carefully-crafted LEB128 length. ([#2337](https://github.com/paritytech/smoldot/pull/2337))
- Fix a panic when decoding a block header containing a large number of Aura authorities. ([#2338](https://github.com/paritytech/smoldot/pull/2338))
- Fix multiple panics when decoding network messages in case where these messages were truncated. ([#2340](https://github.com/paritytech/smoldot/pull/2340), [#2355](https://github.com/paritytech/smoldot/pull/2355))
- Fix panic when the Kademlia random discovery process initiates a request on a connection that has just started shutting down. ([#2369](https://github.com/paritytech/smoldot/pull/2369))
- Fix subscriptions to `chainHead_unstable_follow` being immediately shut down if the gap between the finalized block and the best block is above a certain threshold. This could lead to loops where the JSON-RPC client tries to re-open a subscription, only for it to be immediately shut down again.

## 0.6.17 - 2022-05-31

### Changed

- The networking code has been considerably refactored. Due to the large size of the change it is possible that unintended changes in behaviour have been introduced. ([#2264](https://github.com/paritytech/smoldot/pull/2264))

### Fixed

- Fix a panic in case of a Noise message with an invalid length. ([#2321](https://github.com/paritytech/smoldot/pull/2321))
- Fix a panic in case of a carefully-crafted LEB128 length. ([#2326](https://github.com/paritytech/smoldot/pull/2326))

## 0.6.16 - 2022-05-16

### Added

- Added support for version 1 of the trie. Previously, it wasn't possible to connect to chains that were using version 1. ([#2277](https://github.com/paritytech/smoldot/pull/2277))

### Changed

- The runtime of the genesis block is now only compiled once when a chain is added, decreasing the time this operation takes. ([#2270](https://github.com/paritytech/smoldot/pull/2270))
- Block announces are now propagated to other peers that are also light clients. Light clients should try to connect to as few full nodes as possible (to save resources), but doing so can leave them vulnerable to eclipse attacks. By having light clients connect to other light clients and making them gossip block announces to each other, we increase the likelihood that they detect situations where a given validator generates two blocks during the same slot and is trying to show one of the block only to some peers and the other block to the rest. ([#2226](https://github.com/paritytech/smoldot/pull/2226))

## 0.6.15 - 2022-04-07

### Fixed

- Backport change to checkpoints format (generated by the `sync_state_genSyncSpec` JSON-RPC function of Substrate nodes). Smoldot maintains compatibility with checkpoints generated earlier. ([#2219](https://github.com/paritytech/smoldot/pull/2219))

## 0.6.14 - 2022-04-07

### Fixed

- No longer panic if passed a chain specification containing an invalid bootnode address. Because the specification of the format of a multiaddress is flexible, invalid bootnode addresses do not trigger a hard error but instead are ignored and a warning is printed. ([#2207](https://github.com/paritytech/smoldot/pull/2207))
- Make sure that the tasks of the nodes that have a lot of CPU-heavy operations to perform periodically yield to other tasks, ensuring that the less busy tasks still make progress. This fixes a variety of issues such as chains taking a long time to initialize, or simple JSON-RPC requests taking a long time to be answered. ([#2213](https://github.com/paritytech/smoldot/pull/2213))
- Fix several potential infinite loops when finality lags behind too much ([#2215](https://github.com/paritytech/smoldot/pull/2215)).

## 0.6.13 - 2022-04-05

### Fixed

- Properly fix the regression that version 0.6.12 was supposed to fix. ([#2210](https://github.com/paritytech/smoldot/pull/2210))

## 0.6.12 - 2022-04-04

### Fixed

- Fix regression introduced in version 0.6.11 causing some JSON-RPC functions to never produce a result if they were sent before the runtime of the chain has been downloaded. ([#2201](https://github.com/paritytech/smoldot/pull/2201))

## 0.6.11 - 2022-03-31

### Fixed

- Fix the `ClientOptions.cpuRateLimit` feature being misimplemented and treating any value other than 1.0 as extremely low. ([#2189](https://github.com/paritytech/smoldot/pull/2189))
- Fixed a `TimeoutOverflowWarning` caused by calling `setTimeout` with a value that is too large. ([#2188](https://github.com/paritytech/smoldot/pull/2188))

## 0.6.10 - 2022-03-29

### Fixed

- Fix parachain blocks being reported multiple times in case they have been finalized in-between ([#2182](https://github.com/paritytech/smoldot/pull/2182)).

## 0.6.9 - 2022-03-25

### Fixed

- Properly display error messages when smoldot crashes when in a browser, instead of showing `[object ErrorEvent]`. ([#2171](https://github.com/paritytech/smoldot/pull/2171))

## 0.6.8 - 2022-03-23

### Fixed

- Fix regression introduced in version 0.6.5 where we erroneously removed entries in the mapping of which peer knows which blocks, leading to failures to request data. ([#2168](https://github.com/paritytech/smoldot/pull/2168))

## 0.6.7 - 2022-03-22

### Changed

- Add more details to the debug and trace logs that happen in case of errors such as networking errors or block verification failures ([#2161](https://github.com/paritytech/smoldot/pull/2161)).

### Fixed

- Increase the threshold after which smoldot considers that a protocol name sent through multistream-select is an attempt at a DoS attack, to accomodate for the change in the GrandPa protocol name in Substrate. ([#2162](https://github.com/paritytech/smoldot/pull/2162))

## 0.6.6 - 2022-03-18

### Added

- Add `ClientOptions.cpuRateLimit`, which lets the user put an upper bound on the amount of CPU that the client uses on average ([#2151](https://github.com/paritytech/smoldot/pull/2151)).
- Add support for parsing the "fron" (Frontier) consensus log items in headers. The content of these log items is ignored by the client. ([#2150](https://github.com/paritytech/smoldot/pull/2150))

## 0.6.5 - 2022-03-17

### Changed

- Chain specifications with a `codeSubstitutes` field containing a block hash are no longer supported ([#2127](https://github.com/paritytech/smoldot/pull/2127)).
- Prune list of unverified blocks if it grows too much in order to resist spam attacks ([#2114](https://github.com/paritytech/smoldot/pull/2114)).
- Log block's parent hash in case of block announce ([#2105](https://github.com/paritytech/smoldot/pull/2105)).
- Only call `console.error` once in case of a Rust panic ([#2093](https://github.com/paritytech/smoldot/pull/2093)).

### Fixed

- Fix parachain blocks being reported multiple times in case of a relay chain fork ([#2106](https://github.com/paritytech/smoldot/pull/2106)).
- Implement the `ext_crypto_ecdsa_sign_version_1` host function ([#2120](https://github.com/paritytech/smoldot/pull/2120)).
- Implement the `ext_crypto_ecdsa_verify_version_1` host function ([#2120](https://github.com/paritytech/smoldot/pull/2120)).
- Implement the `ext_crypto_ecdsa_sign_prehashed_version_1` host function ([#2120](https://github.com/paritytech/smoldot/pull/2120)).
- Implement the `ext_crypto_ecdsa_verify_prehashed_version_1` host function ([#2120](https://github.com/paritytech/smoldot/pull/2120)).
- Properly mark all descendants as bad when a block is determined to be bad ([#2121](https://github.com/paritytech/smoldot/pull/2121)).
