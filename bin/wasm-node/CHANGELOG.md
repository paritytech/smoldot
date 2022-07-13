# Changelog

## Unreleased

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
