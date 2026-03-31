# Changelog

## Unreleased

### Fixed

- Fix execution proofs with inputs bigger than 1MiB failing due to protocol limits. Smoldot now uses storage-on-demand for large inputs. ([#2196](https://github.com/smol-dot/smoldot/pull/2196))

## 2.0.40 - 2025-12-02

### Added

- Add support for the `ext_transaction_index_index_version_1` and `ext_transaction_index_renew_version_1` host functions as no-op. ([#2189](https://github.com/smol-dot/smoldot/pull/2189))

## 2.0.39 - 2025-09-15

### Fixed

- Fix panic when executing proofs in some situations caused by the proof analysis not producing a correct value. ([#2176](https://github.com/smol-dot/smoldot/pull/2176))
- When smoldot panics, this will now lead to exceptions being thrown from the public API in most situations, rather than the whole JavaScript process terminating. ([#2177](https://github.com/smol-dot/smoldot/pull/2177))

## 2.0.38 - 2025-09-03

### Fixed

- Fix panic when an invalid SR25519 signature is passed to `ext_crypto_sr25519_verify_version_2`. ([#2170](https://github.com/smol-dot/smoldot/pull/2170))

## 2.0.37 - 2025-08-29

### Changed

- The `state_getReadProof` legacy JSON-RPC function is now properly implemented. ([#2136](https://github.com/smol-dot/smoldot/pull/2136))

## 2.0.36 - 2025-06-06

### Fixed

- A "parse error" JSON-RPC response is no longer erroneously sent back in case of an unrecognized JSON-RPC function name or wrong parameter types. ([#2138](https://github.com/smol-dot/smoldot/pull/2138))

## 2.0.35 - 2025-05-27

### Changed

- The handshake of the transactions notifications protocol substream now contains the "role" of the node, similar to what Substrate does and expects. ([#2130](https://github.com/smol-dot/smoldot/pull/2130))

## 2.0.34 - 2024-11-24

### Fixed

- Fix a `RangeError` exception sometimes being thrown due the smoldot Wasm instance growing its memory at an unexpected time. ([#2047](https://github.com/smol-dot/smoldot/pull/2047))

## 2.0.33 - 2024-11-19

### Fixed

- Fix another bug concerning incomplete Merkle proofs, similar to the one fixed in v2.0.32. ([#2039](https://github.com/smol-dot/smoldot/pull/2039), [#2041](https://github.com/smol-dot/smoldot/pull/2041))

## 2.0.32 - 2024-11-18

### Fixed

- Fix smoldot sometimes considering some Merkle proofs as incomplete when storage nodes are being enumerated by a runtime call, and that a branch node immediately follows a storage node in lexicographic order. ([#2037](https://github.com/smol-dot/smoldot/pull/2037))

## 2.0.31 - 2024-11-08

### Fixed

- Fix panic in transactions service when the runtime service resets after having lost track of the head of the chain. ([#2029](https://github.com/smol-dot/smoldot/pull/2029))

## 2.0.30 - 2024-08-16

### Added

- Add `jsonRpcResponses` async iterable iterator to `Chain`, as a more convenient alternative to the `nextJsonRpcResponse` function. ([#1937](https://github.com/smol-dot/smoldot/pull/1937))

### Fixed

- Fix potential panic in parachain syncing code. ([#1912](https://github.com/smol-dot/smoldot/pull/1912))

## 2.0.29 - 2024-06-17

### Fixed

- Fix runtime service getting stuck if it was subscribed to before the GrandPa warp sync finishes, and that the runtime of the finalized block in the chain specification is available on the peer-to-peer network. ([#1874](https://github.com/smol-dot/smoldot/pull/1874))

## 2.0.28 - 2024-05-30

### Changed

- For parachains, the `system_peers` legacy JSON-RPC function now always returns the best block that each peer gave in its initial block announce handshake. In the past, smoldot tried to track the best block of each peer through its block announce handshakes. This has been removed in order to simplify the code. In practice, however, parachain peers always announce blocks that are not their best block, and this tracking didn't have any effect. ([#1855](https://github.com/smol-dot/smoldot/pull/1855))

### Fixed

- Fix storage queries not working on parachains a few seconds after initialization. ([#1855](https://github.com/smol-dot/smoldot/pull/1855))

## 2.0.27 - 2024-05-29

Maintenance release with no significant changes.

## 2.0.26 - 2024-05-07

### Changed

- When it comes to determining which peers know which block, smoldot now assumes that all parachain nodes know all paraheads found in the relay chain. This solves some issues when. ([#1812](https://github.com/smol-dot/smoldot/pull/1812))

## 2.0.25 - 2024-04-29

### Changed

- All `transactionWatch_unstable`-prefixed JSON-RPC functions have been renamed to `transactionWatch_v1`, in accordance with the latest changes in the JSON-RPC API specification. ([#1771](https://github.com/smol-dot/smoldot/pull/1771))

### Fixed

- Fix the wrong `parentBlockHash` value being sent in `chainHead_v1_followEvent` notifications. ([#1791](https://github.com/smol-dot/smoldot/pull/1791))
- Fix the `forbidWs` option being ignored when connecting to non-localhost addresses. Smoldot erroneously only took the value of `forbidNonLocalWs` in that situation. Connecting to a non-localhost address is now only done if both `forbidWs` and `forbidNonLocalWs` are `false`. ([#1790](https://github.com/smol-dot/smoldot/pull/1790))
- The `finalizedBlockHash` field of the `initialized` event of `chainHead_v1_followEvent` notifications is now properly named `finalizedBlockHashes` and is now properly an array. ([#1792](https://github.com/smol-dot/smoldot/pull/1792))
- Fix panic when calling the `system_health` JSON-RPC function when the finalized block is equal to the best block. ([#1798](https://github.com/smol-dot/smoldot/pull/1798))

## 2.0.24 - 2024-04-16

### Changed

- All `chainHead_unstable`-prefixed JSON-RPC functions have been renamed to `chainHead_v1`, in accordance with the latest changes in the JSON-RPC API specification. ([#1748](https://github.com/smol-dot/smoldot/pull/1748))

### Fixed

- Fix `QueueFullError` being thrown even when the number of requests is way below the value passed to `jsonRpcMaxPendingRequests`. ([#1747](https://github.com/smol-dot/smoldot/pull/1747))
- The `state_getKeysPaged` JSON-RPC function no longer includes in its results the key that passed as the `startKey` parameter. ([#1762](https://github.com/smol-dot/smoldot/pull/1762))

## 2.0.23 - 2024-03-20

### Changed

- Add support for the `transaction_v1_broadcast` and `transaction_v1_stop` JSON-RPC functions. ([#1724](https://github.com/smol-dot/smoldot/pull/1724))
- The JSON-RPC server has been rewritten in order to simplify the code flow. It is unfortunately possible for new bugs to have appeared. ([#1685](https://github.com/smol-dot/smoldot/pull/1685))
- JSON-RPC functions that require access to the runtime (for example `state_call`) now cache older runtimes that had to be downloaded, rather than downloading the runtime from scratch every single time. ([#1685](https://github.com/smol-dot/smoldot/pull/1685))
- Smoldot is no longer compiled with the `bulk-memory-operations` and `sign-extensions-ops` WebAssembly features enabled due to the Rust compiler considering target features as unstable. ([#1716](https://github.com/smol-dot/smoldot/pull/1716))

### Fixed

- The `chainHead_unstable_unpin` JSON-RPC function no longer panics if multiple identical block hashes are passed. ([#1728](https://github.com/smol-dot/smoldot/pull/1728))

## 2.0.22 - 2024-03-04

### Fixed

- Fix crash when extracting the database of a chain when the current Babe epoch number doesn't immediately follow the previous Babe epoch number. ([#1695](https://github.com/smol-dot/smoldot/pull/1695))
- Fix `isSyncing` is always being equal to `true` in the return value of the `system_health` JSON-RPC function. ([#1697](https://github.com/smol-dot/smoldot/pull/1697))

## 2.0.21 - 2024-02-06

### Changed

- Update back to wasmi v0.32. The wasmi version was downgraded to v0.31 in smoldot v2.0.20 due to performance issues. These performance issues turned out to be simply caused by `debug-assertions = true`. ([#1667](https://github.com/smol-dot/smoldot/pull/1667))
- Clarify the value of `isSyncing` returned by `system_health`. The value will be equal to `false` if no peer that smoldot is connected to is more than 10 blocks ahead, and that the highest block would runtime code has been downloaded is no more than 12 blocks ahead of the highest block of the local chain. ([#1658](https://github.com/smol-dot/smoldot/pull/1658))

### Fixed

- The warp syncing process no longer repeats itself every 32 blocks, which was causing unnecessary bandwidth and CPU usage. ([#1656](https://github.com/smol-dot/smoldot/pull/1656))

## 2.0.20 - 2024-01-30

### Fixed

- Fix "Justification targets block not in the chain" errors, leading to peers being erroneously banned. ([#1618](https://github.com/smol-dot/smoldot/pull/1618))
- Revert wasmi version to v0.31 due to performance issues with the experimental v0.32. The WebAssembly runtime is no longer compiled lazily as was the same since smoldot v2.0.17. ([#1642](https://github.com/smol-dot/smoldot/pull/1624))
- Fix blocks not being marked as bad when they are downloaded in an unusual order. ([#1631](https://github.com/smol-dot/smoldot/pull/1631))
- Fix some Merkle proofs being considered as invalid due to nodes having an invalid format when they are in reality storage nodes. ([#1634](https://github.com/smol-dot/smoldot/pull/1634))

## 2.0.19 - 2024-01-26

### Fixed

- Non-Grandpa justifications are now silently ignored, instead of leading to a ban of the peer that sent the justification. This makes smoldot work better on chains that use BEEFY. ([#1614](https://github.com/smol-dot/smoldot/pull/1614))

## 2.0.18 - 2024-01-24

### Changed

- The `transaction_unstable_submitAndWatch` and `transaction_unstable_unwatch` JSON-RPC functions have been renamed to respectively `transactionWatch_unstable_submitAndWatch` and `transactionWatch_unstable_unwatch`, and the corresponding event has been renamed from `transaction_unstable_watchEvent` to `transactionWatch_unstable_watchEvent`, in accordance with the latest changes in the JSON-RPC API specification. ([#1604](https://github.com/smol-dot/smoldot/pull/1604))
- The warp syncing and regular syncing algorithms now run in parallel, meaning that smoldot will now try to perform a warp sync against peers whose finalized block is (or pretends to be) far ahead from the local finalized block, while at the same time continuing to sync normally from other peers. Additionally, smoldot will no longer try to warp sync to peers whose finalized block is too close to the local finalized block, and will instead sync normally. ([#1591](https://github.com/smol-dot/smoldot/pull/1591))
- The `system_health` JSON-RPC function now returns `isSyncing: true` if any of the peers smoldot is connected to is more than 10 blocks ahead of smoldot, and `false` in any other situation including having no peer. ([#1591](https://github.com/smol-dot/smoldot/pull/1591))
- The `chainHead_unstable_storage` JSON-RPC function now yields results progressively as soon as they are received from the peer-to-peer networking, instead of buffering every item and yielding them all at once ([#1605](https://github.com/smol-dot/smoldot/pull/1605)).

### Fixed

- The syncing no longer gets stuck when connecting to a chain whose head is at the same block height as the checkpoint in the chain specification. ([#1591](https://github.com/smol-dot/smoldot/pull/1591))

## 2.0.17 - 2024-01-17

### Changed

- The WebAssembly runtime is now compiled lazily, meaning that only the code that is executed is validated and translated. Thanks to this, compiling a runtime is now four times faster and the time to head of the chain is around 200ms faster. ([#1488](https://github.com/smol-dot/smoldot/pull/1488), [#1577](https://github.com/smol-dot/smoldot/pull/1577))
- Most of the log messages emitted by smoldot have been modified in order to unify their syntax and be easier to parse programatically. ([#1560](https://github.com/smol-dot/smoldot/pull/1560))
- Added support for the `ext_panic_handler_abort_on_panic_version_1` host function. ([#1573](https://github.com/smol-dot/smoldot/pull/1573))

### Fixed

- Fix the nodes discovery process being slow for chains that are added long after the smoldot client has started. This was caused by the fact that the discovery was started at the same time for all chains, and that this discovery intentionally slows down over time. The discovery is now performed and slowed down for each chain individually. ([#1544](https://github.com/smol-dot/smoldot/pull/1544))
- Fix panic when a JSON-RPC function call requires executing an old runtime that smoldot considers as invalid. ([#1570](https://github.com/smol-dot/smoldot/pull/1570))
- Runtime calls no longer fail instantly when a peer sends back an invalid Merkle proof. Instead, the call proof is requested again from a different peer. ([#1570](https://github.com/smol-dot/smoldot/pull/1570))
- The `chainHead_unstable_call` JSON-RPC function now produces a `operationInaccessible` event instead of an `operationError` event when peers send back bad or incomplete Merkle proofs. ([#1570](https://github.com/smol-dot/smoldot/pull/1570))

## 2.0.16 - 2023-12-29

### Changed

- Decoding and analyzing a Merkle proof is now around 10% to 50% faster. ([#1462](https://github.com/smol-dot/smoldot/pull/1462))

### Fixed

- Fix state mismatch during warp syncing if a peer sends a bad header, justification, or proof. ([#1498](https://github.com/smol-dot/smoldot/pull/1498))
- Fix bugs in various corner cases when decoding and analyzing a Merkle proof. ([#1462](https://github.com/smol-dot/smoldot/pull/1462))
- Fix Merkle proofs being considered as invalid if they contain a storage value that happens to successfully decode as a trie node with an inline child. ([#1504](https://github.com/smol-dot/smoldot/pull/1504))
- Fix crash when using a worker due to race condition when a chain is removed while a JSON-RPC response is generated for it. ([#1512](https://github.com/smol-dot/smoldot/pull/1512))

## 2.0.15 - 2023-12-20

### Changed

- When a network request fails, or when a block or justification fails to verify, smoldot now closes the gossip link with the peer it tried to send the request to or obtained the block or justification from, and will not re-open a new gossip link for a little while. ([#1482](https://github.com/smol-dot/smoldot/pull/1482))

## 2.0.14 - 2023-12-11

### Fixed

- Fix pings never being sent to peers, which means that smoldot would fail to detect when a connection is no longer responsive. ([#1461](https://github.com/smol-dot/smoldot/pull/1461))
- Fix connection being properly killed when the ping substream fails to be negotiated. ([#1459](https://github.com/smol-dot/smoldot/pull/1459))
- Fix Merkle proofs with nodes that have one child and no storage value being considered as valid.
- Fix Merkle proofs with nodes that have no children or storage value and aren't the root being considered as valid.

## 2.0.13 - 2023-11-28

### Changed

- The order in which smoldot connects to peers is now random rather than depending on the peer. ([#1424](https://github.com/smol-dot/smoldot/pull/1424))
- Increase the rate at which connections are opened to 10 per second, with a pool of 8 simultaneous connections openings. ([#1425](https://github.com/smol-dot/smoldot/pull/1425))

### Fixed

- Fix panic when disconnecting from a peer whose identity didn't match the identity that was expected when connecting to it. ([#1431](https://github.com/smol-dot/smoldot/pull/1431))

## 2.0.12 - 2023-11-27

### Fixed

- Fix panic in network service when all chains are removed. ([#1422](https://github.com/smol-dot/smoldot/pull/1422))

## 2.0.11 - 2023-11-27

### Changed

- A single networking service is now shared between all chains. This means that the same connection (such as a WebSocket or WebRTC connection) can now be used to open multiple block announces substreams for multiple different chains. ([#1398](https://github.com/smol-dot/smoldot/pull/1398))
- Addresses that are not supported by the host platform are now ignored during the discovery process. For example, TCP/IP connections are ignored while in a browser. This avoids populating the address book with peers that we know we can't connect to anyway. ([#1359](https://github.com/smol-dot/smoldot/pull/1359), [#1360](https://github.com/smol-dot/smoldot/pull/1360))
- Smoldot will no longer try to connect to the same address over and over again. ([#1358](https://github.com/smol-dot/smoldot/pull/1358))

### Fixed

- Fix panic when the runtime of a chain provides consensus information that is inconsistent with the information found in the finalized block. ([#1317](https://github.com/smol-dot/smoldot/pull/1317))
- Incoming notification substreams are now properly when accepted when a peer doesn't have a slot or gets a slot later on. ([#1369](https://github.com/smol-dot/smoldot/pull/1369))
- Fix panic when `chainHead_unstable_follow` is called too many times. ([#1392](https://github.com/smol-dot/smoldot/pull/1392))
- Fix panic when opening a gossiping link to a peer that we were previously connected to. ([#1395](https://github.com/smol-dot/smoldot/pull/1395))
- Fix panic when the discovery system finds same address attributed to two different peers. ([#1412](https://github.com/smol-dot/smoldot/pull/1412))
- Fix sending a block announce handshake when accepting an inbound transactions or grandpa substream in some rare situations. ((#1417)[https://github.com/smol-dot/smoldot/pull/1417])
- Fix automatically refusing inbound notification substreams if a different inbound substream of the same protocol existed on the same connection, even when that other substream has been closed. ((#1417)[https://github.com/smol-dot/smoldot/pull/1417])
- Inbound notification substreams opened by the remote and that are no longer wanted are now forcefully closed if the remote doesn't close them gracefully. ((#1417)[https://github.com/smol-dot/smoldot/pull/1417])
- Fix panic when a connection is shutting down after the notification substreams of that connection were opened in an unconventional order. ((#1417)[https://github.com/smol-dot/smoldot/pull/1417])

## 2.0.10 - 2023-11-17

### Fixed

- Fix several WebRTC-related panics and bugs. ([#1348](https://github.com/smol-dot/smoldot/pull/1348), [#1350](https://github.com/smol-dot/smoldot/pull/1350), [#1354](https://github.com/smol-dot/smoldot/pull/1354))

## 2.0.9 - 2023-11-16

### Changed

- Smoldot will now only try opening a maximum of five connections simultaneously, then one per second. This avoids possible situations where a server is being accidentally hammered by smoldot, and avoids potentially making traffic suspicious to some ISPs. ([#1340](https://github.com/smol-dot/smoldot/pull/1340))

### Fixed

- Fix panic when verifying Babe signatures when the invalid SR25519 public key is invalid. ([#1344](https://github.com/smol-dot/smoldot/pull/1344))

## 2.0.8 - 2023-11-15

### Changed

- The `hash` parameter of `chainHead_unstable_unpin` has been renamed to `hashOrHashes`, in accordance with the latest changes in the JSON-RPC API specification. ([#1329](https://github.com/smol-dot/smoldot/pull/1329))

### Fixed

- Fix panic when requesting a block with a specific hash from the peer-to-peer network and none of the peers has the block. ([#1303](https://github.com/smol-dot/smoldot/pull/1303))
- Fix panic when discovery has been running for some time and decides to purge from the address book a peer we are still connected to. ([#1332](https://github.com/smol-dot/smoldot/pull/1332))

## 2.0.7 - 2023-11-02

### Changed

- Smoldot will now generate an individual network key every time it initiates a connection. This prevents the full nodes it connects to from being able to maintain a mapping of network key <-> IP address and thus being able to track where the machine running a light client moves around the world. It also makes it harder for colluding full nodes from coordinating an eclipse attack against a specific light client user. Note that this is not completely fool-proof, as it assumes that connections are shut down and reopened during the IP address change, which is generally only the case if connectivity is lost or if the machine is put to sleep. It is unfortunately not technically possible for smoldot to reliably detect IP address changes. ([#1255](https://github.com/smol-dot/smoldot/pull/1255))
- As a consequence of the previous change, the `system_localPeerId` JSON-RPC function is no longer supported. ([#1255](https://github.com/smol-dot/smoldot/pull/1255))
- The `chain_getBlock` JSON-RPC function now always returns an empty list of justifications, because there is no (reasonable) way for smoldot to verify whether the justifications sent by full nodes are valid. ([#1238](https://github.com/smol-dot/smoldot/pull/1238))

## 2.0.6 - 2023-10-13

### Fixed

- Fix iterating over storage keys through Merkle proofs considering incomplete proofs as invalid even when said proofs are intentionally invalid. ([#1221](https://github.com/smol-dot/smoldot/pull/1221))

## 2.0.5 - 2023-10-12

### Fixed

- Fix storage items requested through JSON-RPC functions not being sent to the JSON-RPC client when the full node doesn't send it back in the Merkle proof. ([#1216](https://github.com/smol-dot/smoldot/pull/1216))

## 2.0.4 - 2023-10-11

### Changed

- When asking for Merkle proofs from full nodes, smoldot will now automatically and dynamically split big requests into multiple smaller requests. This should avoid timeout errors in case of big requests. ([#1209](https://github.com/smol-dot/smoldot/pull/1209))

## 2.0.3 - 2023-09-28

### Fixed

- Fix JavaScript error being thrown when `Client.terminate` is called while the client is not idle. ([#1197](https://github.com/smol-dot/smoldot/pull/1197))

## 2.0.2 - 2023-09-25

### Changed

- During the warp syncing process, smoldot will now download the runtime and call proofs from any peer whose finalized block is superior or equal to the target block, rather than always the peer that was used to download the warp sync fragments. ([#1060](https://github.com/smol-dot/smoldot/pull/1060))
- During the warp syncing process, smoldot will now download warp sync fragments in parallel of verifying previously-downloaded fragments. This is expected to speed up the warp syncing process. ([#1060](https://github.com/smol-dot/smoldot/pull/1060))
- When a warp sync response contains an invalid warp sync fragment, the earlier valid fragments are now still used to make the warp syncing progress instead of being thrown away. ([#1060](https://github.com/smol-dot/smoldot/pull/1060))
- During the warp sync process, the runtime call Merkle proofs are now downloaded in parallel of the runtime. This should save several networking round trips. Because the list of runtime calls to perform depend on the runtime version, starting to download the Merkle proofs before the runtime has been fully obtained is built upon the assumption that the runtime is at the latest version. ([#1060](https://github.com/smol-dot/smoldot/pull/1060))
- The `index` field of `bestChainBlockIncluded` events of `transaction_unstable_submitAndWatch` subscriptions is now a number rather than a string, in accordance with the latest changes in the JSON-RPC API specification. ([#1097](https://github.com/smol-dot/smoldot/pull/1097))

### Fixed

- Justifications are no longer downloaded for blocks that can't be finalized because an earlier block needs to be finalized first. ([#1127](https://github.com/smol-dot/smoldot/pull/1127))
- Fix warp sync process stagnating if a source sends a header whose height is inferior or equal to the currently warp synced block. ([#1060](https://github.com/smol-dot/smoldot/pull/1060))

## 2.0.1 - 2023-09-08

### Fixed

- Fix panic in Yamux state machine when a remote closes a substream with an active timeout. ([#1122](https://github.com/smol-dot/smoldot/pull/1122))

## 2.0.0 - 2023-09-07

### Remove

- Removed `MalformedJsonRpcError`. Malformed JSON-RPC requests now later generate an error JSON-RPC response where the `id` field is equal to `null`, in accordance with the JSON-RPC 2.0 specification. ([#1116](https://github.com/smol-dot/smoldot/pull/1116))

### Changed

- Transactions submitted through the JSON-RPC server before the warp syncing process is finished will now immediately be dropped. ([#1110](https://github.com/smol-dot/smoldot/pull/1110))
- JSON-RPC requests that are very large are no longer rejected. In case where the JSON-RPC client is trusted, then there is nothing to do, and the potential lack of memory space will become a non-issue once the `Memory64` WebAssembly proposal becomes widely available. In case where the JSON-RPC client is not trusted, the API user is encouraged to manually implement a limit to the size of JSON-RPC requests, as it should do already right now anyway. ([#1115](https://github.com/smol-dot/smoldot/pull/1115))

### Fixed

- Fix `Chain.remove()` not actually removing the chain until the warp syncing process is finished (which might never happen if for example bootnodes are misconfigured). ([#1110](https://github.com/smol-dot/smoldot/pull/1110))
- Fix JSON-RPC server not processing requests if many transactions are submitted before the warp syncing process is finished. ([#1110](https://github.com/smol-dot/smoldot/pull/1110))

## 1.0.17 - 2023-08-25

### Changed

- It is now possible for parachain chain specifications to include just a `genesis.stateRootHash` field (and no `genesis.raw` field). A warning in the logs is now printed for all chain specifications that include a `genesis.raw` field. ([#1034](https://github.com/smol-dot/smoldot/pull/1034))

### Fixed

- Fix WebRTC addresses failing to be be parsed. ([#1036](https://github.com/smol-dot/smoldot/pull/1036))

## 1.0.16 - 2023-08-14

### Changed

- Removed the `chainHead_unstable_genesisHash` JSON-RPC function, in accordance with the latest changes in the JSON-RPC API specification. ([#1010](https://github.com/smol-dot/smoldot/pull/1010))
- The database of a parachain now contains a list of known peer-to-peer nodes and a cache of the runtime code of the parachain, similar to the database of a relay chain. The database of a parachain was previously always empty. ([#1018](https://github.com/smol-dot/smoldot/pull/1018))

### Fixed

- The block announces substream handshake of a parachain peer-to-peer network now properly contains the block that smoldot thinks is the best. The genesis block was previously always reported. ([#1012](https://github.com/smol-dot/smoldot/pull/1012))
- Fix panic when removing a chain while a networking connection is being opened. ([#1011](https://github.com/smol-dot/smoldot/pull/1011))
- Fix epoch start slot calculation when epochs have been skipped. ([#1015](https://github.com/smol-dot/smoldot/pull/1015))
- Fix timeouts not working properly in the networking. ([#1023](https://github.com/smol-dot/smoldot/pull/1023), [#1026](https://github.com/smol-dot/smoldot/pull/1026))
- Fix panic when calling `Chain.remove` while `Chain.nextJsonRpcResponse` is in progress. ([#1025](https://github.com/smol-dot/smoldot/pull/1025))

## 1.0.15 - 2023-08-08

### Changed

- The `operation-body-done`, `operation-call-done`, `operation-storage-done`, `operation-storage-items`, `operation-waiting-for-continue`, `operation-inaccessible`, and `operation-error` events, and the `closest-descendant-merkle-value`, `descendants-values`, and `descendants-hashes` item types of the new JSON-RPC API have been renamed and are now camelCased (`operationBodyDone`, `operationStorageItems`, `descendantsValues`, etc.), in accordance with the latest changes in the JSON-RPC API specification. ([#973](https://github.com/smol-dot/smoldot/pull/973))
- The `chainSpec_unstable` JSON-RPC functions have been renamed to `chainSpec_v1`, in accordance with the latest changes in the JSON-RPC API specification. ([#989](https://github.com/smol-dot/smoldot/pull/989))

### Fixed

- A change in the logic of BABE has been backported. Smoldot no longer considers blocks as invalid after no block has been authored for an entire epoch. ([#991](https://github.com/smol-dot/smoldot/pull/991))

## 1.0.14 - 2023-07-26

### Changed

- Remove `networkConfig` parameter from all `chainHead` JSON-RPC functions, in accordance with the latest changes to the JSON-RPC API specification. ([#963](https://github.com/smol-dot/smoldot/pull/963))
- A JSON-RPC error is now returned if the JSON-RPC client tries to open more than two simultaneous `chainHead_unstable_follow` subscriptions, in accordance with the latest changes in the JSON-RPC API specification. ([#962](https://github.com/smol-dot/smoldot/pull/962))
- Rename `chainHead_unstable_storageContinue` to `chainHead_unstable_continue`, in accordance with the latest changes in the JSON-RPC API specification. ([#965](https://github.com/smol-dot/smoldot/pull/965))
- Merge `chainHead_unstable_stopBody`, `chainHead_unstable_stopCall`, and `chainHead_unstable_stopStorage` into `chainHead_unstable_stopOperation`, in accordance with the latest changes in the JSON-RPC API specification. ([#966](https://github.com/smol-dot/smoldot/pull/966))
- Merge `chainHead_unstable_body`, `chainHead_unstable_call`, and `chainHead_unstable_storage` are now simple request-response functions that generate their notifications onto the corresponding `chainHead_unstable_follow` subscription, in accordance with the latest changes in the JSON-RPC API specification. ([#966](https://github.com/smol-dot/smoldot/pull/966))

### Fixed

- Fix several potential panics due to mismatches in the state of the networking. ([#967](https://github.com/smol-dot/smoldot/pull/967))

## 1.0.13 - 2023-07-16

### Added

- Add support for the `ext_trie_keccak_256_root_version_1`, `ext_trie_keccak_256_root_version_2`, `ext_trie_keccak_256_ordered_root_version_1`, and `ext_trie_keccak_256_ordered_root_version_2` host functions. ([#906](https://github.com/smol-dot/smoldot/pull/906))
- Add support for the `ext_crypto_ed25519_batch_verify_version_1`, `ext_crypto_sr25519_batch_verify_version_1`, `ext_crypto_ecdsa_batch_verify_version_1`, `ext_crypto_start_batch_verify_version_1`, and `ext_crypto_finish_batch_verify_version_1` host functions. ([#920](https://github.com/smol-dot/smoldot/pull/920))

### Changed

- The smoldot binary now longer has SIMD enabled, in order to make it work on a greater range of hardware. It was previously assumed that SIMD instructions were emulated on hardware that doesn't natively support them, but this doesn't seem to be the case for some browser engines. ([#903](https://github.com/smol-dot/smoldot/pull/903))

### Fixed

- Fix regression introduced in version 1.0.12 where only WebSocket secure and WebRTC connections were ever opened, regardless of the `forbid*` configuration flags. ([#923](https://github.com/smol-dot/smoldot/pull/923))

## 1.0.12 - 2023-07-10

### Changed

- The runtime code of the finalized block is now stored in the database. At initialization, smoldot now only downloads the hash of the runtime and compares it with the one in cache. If the hashes match (which is the case if no runtime update has happened on the chain since the database has been created), smoldot doesn't download the runtime code but uses the value in the cache. This saves a relatively heavy download (typically around 1 MiB to 1.5 MiB depending on the chain) and speeds up the loading time. ([#863](https://github.com/smol-dot/smoldot/pull/863))
- The `chainHead_unstable_storage` JSON-RPC function now supports a `type` equal to `closest-descendant-merkle-value` and no longer supports `closest-ancestor-merkle-value`, in accordance with the latest changes in the JSON-RPC API specification. ([#824](https://github.com/smol-dot/smoldot/pull/824))
- Blocks are now reported to `chain_subscribeAllHeads` and `chain_subscribeNewHeads` subscribers only after they have been put in the cache, preventing race conditions where JSON-RPC clients suffer from a cache miss if they ask information about these blocks too quickly. ([#854](https://github.com/smol-dot/smoldot/pull/854))
- Runtime updates are now always reported to `state_subscribeRuntimeVersion` subscribers immediately after the `chain_subscribeNewHeads` notification corresponding to the block containing the runtime update. They were previously reported in a pseudo-random order. ([#854](https://github.com/smol-dot/smoldot/pull/854))
- All the storage subscriptions made using `state_subscribeStorage` are now queried together into a single networking request per block, instead of sending one networking query per storage key and per subscription. ([#854](https://github.com/smol-dot/smoldot/pull/854))
- An `AddChainError` is now thrown if the `databaseContent` parameter is not of type `string`. The database was previously silently ignored. ([#861](https://github.com/smol-dot/smoldot/pull/861))

### Fixed

- Fix downloading the runtime code twice during the warp syncing process. ([#863](https://github.com/smol-dot/smoldot/pull/863))
- Fix a "One or more entries are missing from the call proof" error when validating some transactions. ([#879](https://github.com/smol-dot/smoldot/pull/879))

## 1.0.11 - 2023-06-25

### Changed

- The runtime specification yielded by the `chainHead_unstable_follow` JSON-RPC function no longer includes the `authoringVersion` field, in accordance with the latest changes in the JSON-RPC API specification. ([#815](https://github.com/smol-dot/smoldot/pull/815))
- The `chainHead_unstable_unpin` JSON-RPC function now accepts either a single hash or an array of hashes, in accordance with the latest changes in the JSON-RPC API specification. ([#814](https://github.com/smol-dot/smoldot/pull/814))
- Add support for the `descendants-values`, `descendants-hashes`, and `closest-ancestor-merkle-value` types for the `chainHead_unstable_storage` JSON-RPC function. ([#813](https://github.com/smol-dot/smoldot/pull/813))
- The `chainHead_unstable_storage` JSON-RPC function now accepts an array of `items` as parameter instead of a `key` and `type`, in accordance with the latest changes in the JSON-RPC API specification. ([#813](https://github.com/smol-dot/smoldot/pull/813))
- The `chainHead_unstable_storage` JSON-RPC function now generates `items` notifications containin an array of multiple `items`, in accordance with the latest changes in the JSON-RPC API specification. ([#813](https://github.com/smol-dot/smoldot/pull/813))

### Fixed

- Fix not absorbing the JavaScript exception triggered by the browser when connecting to a `ws://` node when smoldot is embedded in a web page served over `https://`. ([#795](https://github.com/smol-dot/smoldot/pull/795), [#800](https://github.com/smol-dot/smoldot/pull/800))
- Fix potential panic due to race condition when smoldot wants to abort connecting to a peer that we have just failed connecting to. ([#801](https://github.com/smol-dot/smoldot/pull/801))
- Smoldot no longer calls `close()` on WebSockets that aren't fully established yet (even though it is legal to do so according to the WHATWG specification) in order to avoid browsers printing warnings in the console when you do so. ([#799](https://github.com/smol-dot/smoldot/pull/799))
- Fix panic-inducing race condition when a networking event happens right when the warp syncing finishes. ([#808](https://github.com/smol-dot/smoldot/pull/808))

## 1.0.10 - 2023-06-19

### Changed

- Multiaddresses that can't be parsed during the discovery process are now silently ignored instead of causing the entire list of discovered nodes to be discarded. ([#705](https://github.com/smol-dot/smoldot/pull/705))

### Fixed

- Smoldot no longer assumes that the runtime calls `ext_default_child_storage_root` in order to properly update the hashes of the child tries that have been modified. ([#743](https://github.com/smol-dot/smoldot/pull/743))
- Fix various mishandlings of child tries. ([#763](https://github.com/smol-dot/smoldot/pull/763))
- Fix panic when the `ext_default_child_storage_clear_prefix_version_1` and `ext_default_child_storage_clear_prefix_version_2` functions are called. ([#764](https://github.com/smol-dot/smoldot/pull/764))
- Fix wrong trie root hash calculation with `state_version = 1`. ([#711](https://github.com/smol-dot/smoldot/pull/711))
- Fix bug when decoding BABE configuration produced by runtimes using version 1 of the `BabeApi` API. In practice, this should concern only old Kusama blocks. ([#739](https://github.com/smol-dot/smoldot/pull/739))
- No longer panic when `state_getKeysPaged` is called with a `prefix` parameter equal to `null`. ([#776](https://github.com/smol-dot/smoldot/pull/776))

## 1.0.9 - 2023-06-08

### Added

- Add support for child tries, meaning that errors will no longer be returned when performing runtime calls on chains that use child tries. In practice, this typically concerns contracts chains. ([#680](https://github.com/smol-dot/smoldot/pull/680), [#684](https://github.com/smol-dot/smoldot/pull/684))
- The checksum of the SS58 address passed to the `system_accountNextIndex` JSON-RPC function is now verified. Note that its prefix isn't compared against the one of the current chain, because there is no straight-forward way for smoldot to determine the SS58 prefix of the chain that it is running. ([#691](https://github.com/smol-dot/smoldot/pull/691))
- Add `AddChainOptions.jsonRpcMaxPendingRequests` and `AddChainOptions.jsonRpcMaxSubscriptions`, allowing you to specify the maximum number of pending JSON-RPC requests and the maximum number of active JSON-RPC subscriptions. These two limits were previously implicitly set to respectively 128 and 1024. Not passing any value defaults to "infinity". You are strongly encouraged to specify a value for these two options if the source of the JSON-RPC requests is untrusted. ([#694](https://github.com/smol-dot/smoldot/pull/694))

### Fixed

- A `validated` event is now properly generated when watching a transaction using `transaction_unstable_submitAndWatch`. ([#676](https://github.com/smol-dot/smoldot/pull/676))
- Fix `author_submitAndWatchExtrinsic` erroneously generating `transaction_unstable_watchEvent` notifications, and `transaction_unstable_submitAndWatch` erroneously generating `author_extrinsicUpdate` notifications. ([#677](https://github.com/smol-dot/smoldot/pull/677))

### Changed

- TCP NODELAY is now enabled on Deno. The minimum required Deno version is now v1.29.0, which was released on 2022-12-14. ([#665](https://github.com/smol-dot/smoldot/pull/665))

## 1.0.8 - 2023-06-05

### Changed

- Instead of manually decompressing the WebAssembly bytecode in JavaScript, smoldot will now use the native `DecompressionStream` API within browsers and the native `zlib.inflate` function in NodeJS. This should speed up the initialization and reduce the size of the package. The new `DecompressionStream` API has been stable since February 2020 on Chrome and Edge, since March 2023 on Safari, and since May 2023 on Firefox. ([#640](https://github.com/smol-dot/smoldot/pull/640))
- The parameter of `chainHead_unstable_follow` has been renamed from `runtimeUpdates` to `withRuntime` in accordance with the latest JSON-RPC specification changes. ([#624](https://github.com/smol-dot/smoldot/pull/624))
- Errors while building the runtime and errors while building the consensus-related information that can happen during the warp syncing process are now printed in the logs. ([#644](https://github.com/smol-dot/smoldot/pull/644))
- The `chainHead_unstable_storage` JSON-RPC method has been updated according to the latest changes to the JSON-RPC specification. These changes can be found [here](https://github.com/paritytech/json-rpc-interface-spec/pull/37). The `descendants-values`, `descendants-hashes`, and `closest-ancestor-merkle-value` types aren't implemented yet and produce an error. ([#647](https://github.com/smol-dot/smoldot/pull/647))

### Fixed

- Smoldot will no longer produce errors when calling a runtime function (such as with `state_call` or `chainHead_unstable_call`) that calls the `ext_storage_root` host function. ([#670](https://github.com/smol-dot/smoldot/pull/670))
- Fix panic when receiving a networking request of a protocol not supported by smoldot. ([#635](https://github.com/smol-dot/smoldot/pull/635))
- Fix `chainHead_unstable_stopStorage` and `chainHead_unstable_stopBody` being mixed. In other words, storage requests were interrupted by `chainHead_unstable_stopBody` and body requests were interrupted by `chainHead_unstable_stopStorage` ([#648](https://github.com/smol-dot/smoldot/pull/648))

## 1.0.7 - 2023-05-25

### Fixed

- When a runtime contains a `runtime_apis` custom section but no `runtime_version` custom section, or vice-versa, smoldot now falls back to calling `Core_version`. ([#607](https://github.com/smol-dot/smoldot/pull/607))
- Fix panic when the checkpoint in the chain specification is invalid, which can normally only happen if the checkpoint was modified manually. ([#603](https://github.com/smol-dot/smoldot/pull/603))
- Fix panic when the checkpoint in the chain specification contains zero or one Babe epochs, which can happen if the checkpoint was generated before any block was authored. ([#603](https://github.com/smol-dot/smoldot/pull/603))
- The notifications generated by the `author_extrinsicUpdate` JSON-RPC function are now properly camelCased (`future`, `ready`, `broadcast`, `inBlock`, `retracted`, `finalityTimeout`, `finalized`, `usurped`, `dropped`, and `invalid`). They were previously PascalCased (`Future`, `Ready`, `Broadcast`, `InBlock`, `Retracted`, `FinalityTimeout`, `Finalized`, `Usurped`, `Dropped`, and `Invalid`). ([#611](https://github.com/smol-dot/smoldot/pull/611))

## 1.0.6 - 2023-05-09

### Changed

- The version numbers of the `BabeApi`, `GrandpaApi` and `AuraApi` runtime APIs is now checked during the warp sync process. An error is returned if these version numbers aren't equal to known values. These version numbers are changed when the logic of the API has changed, and returning an error in that situation ensures that smoldot will not do the wrong thing such as running with a weakened security. ([#549](https://github.com/smol-dot/smoldot/pull/549))

### Fixed

- The `Promise` returned by `terminate()` now correctly waits for everything to be completely shut down before yielding instead of letting the shutdown continue happening in the background. ([#538](https://github.com/smol-dot/smoldot/pull/538))

## 1.0.5 - 2023-05-05

It is now possible to run the CPU-heavy tasks of smoldot within a worker (WebWorker, worker threads, etc.). To do so, create two ports using `new MessageChannel()`, pass one of the two ports in the `ClientOptions.portToWorker` field and send the other port to a web worker, then call `run(port)` from within that worker. The `run` function can be found by importing `import { run } from 'smoldot/worker'`. If a `portToWorker` is provided, then the `cpuRateLimit` setting applies to the worker.

It is also now possible to load the smoldot bytecode separately or within a worker. To do so, import the `compileBytecode` function using `import { compileBytecode } from 'smoldot/bytecode';`, call it, optionally send it from a worker to the main thread if necessary, then pass the object to the options of the new `startWithBytecode` function. The new `startWithBytecode` function can be imported with `import { startWithBytecode } from 'smoldot/no-auto-bytecode';`. It is equivalent to `start`, except that its configuration must contains a `bytecode` field.

See the README of the JavaScript package for more information.

### Added

- Add `ClientOptions.portToWorker` field. ([#529](https://github.com/smol-dot/smoldot/pull/529))
- Add a new `worker` entry point to the library (for Deno: `worker-deno.ts`) containing a `run` function ([#529](https://github.com/smol-dot/smoldot/pull/529))
- Add a new `SmoldotBytecode` public interface. ([#532](https://github.com/smol-dot/smoldot/pull/532))
- Add a new `ClientOptionsWithBytecode` interface that extends `ClientOptions` with an extra `bytecode` field. ([#532](https://github.com/smol-dot/smoldot/pull/532))
- Add a new `bytecode` entry point to the library (for Deno: `bytecode-deno.ts`) containin a `comileBytecode` function. ([#532](https://github.com/smol-dot/smoldot/pull/532))
- Add a new `no-auto-bytecode` entry point to the library (for Deno: `no-auto-bytecode-deno.ts`) containin a `startWithBytecode` function. This function is equivalent to `start`, but accepts a `ClientOptionsWithBytecode` rather than a `ClientOptions`. ([#532](https://github.com/smol-dot/smoldot/pull/532))

### Changed

- When in the browser, smoldot no longer uses `document.visibilityState` to determine whether to reduce the number of calls to `setTimeout`. Instead, the execution dynamically adjusts based on the time `setTimeout` actually takes compared to how much was passed as parameter. ([#518](https://github.com/smol-dot/smoldot/pull/518))

### Fixed

- Fix panic when a remote opens a substream then immediately resets it before smoldot has been able to determine asynchronously whether to accept it or not. ([#521](https://github.com/smol-dot/smoldot/pull/521))

## 1.0.4 - 2023-05-03

### Added

- Support v2 of the `Metadata` runtime API. ([#514](https://github.com/smol-dot/smoldot/pull/514))

### Changed

- The size of the read buffer of TCP connections on Deno has been increased from 1kiB to 32kiB. This should improve the performance by reducing the number of function calls. ([#501](https://github.com/smol-dot/smoldot/pull/501))

### Fixed

- Fix panic when the best block of a chain switches to being equal to the current finalized block. This can occasionally happen for parachains in case of a reorg on the relay chain. ([#497](https://github.com/smol-dot/smoldot/pull/497))
- Fix panic when failing to find the desired runtime API in a runtime. ([#512](https://github.com/smol-dot/smoldot/pull/512))

## 1.0.3 - 2023-04-27

### Changed

- As NodeJS v14 reaches its end of life on April 30th 2023, the minimum NodeJS version required to run smoldot is now v16. The smoldot Wasm binary now has SIMD enabled, meaning that the minimum Deno version required to run smoldot is now v1.9.
- When receiving an identify request through the libp2p protocol, smoldot now sends back `smoldot-light-wasm vX.X.X` (with proper version numbers) as its agent name and version, instead of previously just `smoldot`. ([#417](https://github.com/smol-dot/smoldot/pull/417))
- Yielding to the browser using `setTimeout` and `setImmediate` is now done less frequently in order to reduce the overhead of doing so. ([#481](https://github.com/smol-dot/smoldot/pull/481))

### Fixed

- Fix finality stalling on epoch change by explicitly requesting justifications of blocks that a peer has reported as finalized but that isn't finalized locally. ([#441](https://github.com/smol-dot/smoldot/pull/441))
- Fix `AlreadyDestroyedError` not being properly thrown if a function is called after `terminate()`. ([#438](https://github.com/smol-dot/smoldot/pull/438))

## 1.0.2 - 2023-04-12

### Changed

- Removed support for the `ls` message in the multistream-select protocol, in accordance with the rest of the libp2p ecosystem. This message was in practice never used, and removing support for it simplifies the implementation. ([#379](https://github.com/smol-dot/smoldot/pull/379))
- Yamux now considers answering pings in the wrong order as invalid. ([#383](https://github.com/smol-dot/smoldot/pull/383))

### Fixed

- Fix the JSON-RPC service not being deallocated when a chain is removed with some subscriptions still active. ([#408](https://github.com/smol-dot/smoldot/pull/408), [#410](https://github.com/smol-dot/smoldot/pull/410), [#409](https://github.com/smol-dot/smoldot/pull/409))
- Calling the `chainHead_unstable_call`, `chainHead_unstable_storage`, or `chainHead_unstable_body` JSON-RPC functions with the hash of an unpinned block no longer silently kills the `chainHead_follow` subscription. ([#409](https://github.com/smol-dot/smoldot/pull/409))
- No longer generate a `chainHead_unstable_followEvent` notification with a `stop` event in response to a call to `chainHead_unstable_unfollow`. ([#409](https://github.com/smol-dot/smoldot/pull/409))
- Fix a potential undefined behavior in the way the Rust and JavaScript communicate. ([#396](https://github.com/smol-dot/smoldot/pull/396))
- Properly check whether Yamux substream IDs allocated by the remote are valid. ([#383](https://github.com/smol-dot/smoldot/pull/383))
- Fix the size of the data of Yamux frames with the `SYN` flag not being verified against the allowed credits. ([#383](https://github.com/smol-dot/smoldot/pull/383))
- Fix Yamux repeatedly sending empty data frames when the allowed window size is 0. ([#383](https://github.com/smol-dot/smoldot/pull/383))
- Post-MVP WebAssembly features are now properly disabled when compiling runtimes. This rejects runtimes that Substrate would consider as invalid as well. ([#386](https://github.com/smol-dot/smoldot/pull/386))

## 1.0.1 - 2023-03-29

### Changed

- No longer panic when a libp2p networking request emitted by smoldot exceeds the maximum size allowed by the protocol. Instead, either a warning is printed (similar to consensus-related issues) or a JSON-RPC error is returned. ([#318](https://github.com/smol-dot/smoldot/pull/318))
- Add an arbitrary limit to the size of unprocessed networking packets, in order to avoid DoS attacks. This limit is necessary in order to bypass limitations in the networking APIs exposed by browsers. ([#312](https://github.com/smol-dot/smoldot/pull/312))
- Rename `/webrtc` to `/webrtc-direct` in multiaddresses, in accordance with the rest of the libp2p ecosystem. ([#326](https://github.com/smol-dot/smoldot/pull/326))
- Improved the ganularity of the tasks that handle JSON-RPC requests and libp2p connections. Smoldot now yields more often to the browser, reducing the chances and the severity of freezes during the rendering of the web page. ([#349](https://github.com/smol-dot/smoldot/pull/349))
- Smoldot is now compiled with the `bulk-memory-operations` and `sign-extensions-ops` WebAssembly features enabled. This is expected to considerably speed up its execution. The minimum version required to run smoldot is now Chrome 75, Firefox 79, NodeJS v12.5, and Deno v0.4. ([#356](https://github.com/smol-dot/smoldot/pull/356))
- When the `state_getKeysPaged` JSON-RPC function is called, and the list of keys returned in the response is truncated (due to the `count` and `startKey` parameters), the rest of the keys are now put in a cache with the expectation that `state_getKeysPaged` is called again in order to obtain the rest of the keys. The `state_getKeysPaged` JSON-RPC function is unfortunately very often used by PolkadotJS despite being completely unsuitable for light clients. ([#361](https://github.com/smol-dot/smoldot/pull/361))
- Significantly optimize the performance of the proof verification in `state_getKeys` and `state_getKeysPaged`. ([#363](https://github.com/smol-dot/smoldot/pull/363))

### Fixed

- Fix runtime transactions not being handled properly when multiple transactions are stacked. ([#335](https://github.com/smol-dot/smoldot/pull/335))
- No longer generate a JavaScript exception due to `document` being undefined when executing inside of a WebWorker. ([#340](https://github.com/smol-dot/smoldot/pull/340))
- Fix JavaScript errors being thrown if a peer resets a libp2p connection abruptly. ([#315](https://github.com/smol-dot/smoldot/pull/315))
- TCP connections are now properly closed gracefully (with a FIN flag) on NodeJS and Deno. ([#315](https://github.com/smol-dot/smoldot/pull/315))
- Outbound data on libp2p connections is now properly back-pressured if the remote doesn't accept to receive more data. ([#315](https://github.com/smol-dot/smoldot/pull/315))

## 1.0.0 - 2023-03-12

### Fixed

- Fix Deno throwing an exception when failing to connect to an unreachable node through a TCP/IP multiaddr. ([#246](https://github.com/smol-dot/smoldot/pull/246))

## 0.7.13 - 2023-03-03

### Added

- Add support for the `ext_hashing_keccak_512_version_1` host function. ([#231](https://github.com/smol-dot/smoldot/pull/231))

### Changed

- When a full node refuses an outbound transactions or GrandPa substream even though a block announces substream has been established, smoldot now tries to reopen the failed substream. This bypasses a Substrate issue. ([#240](https://github.com/smol-dot/smoldot/pull/240))
- Runtime functions called through the JSON-RPC function `state_call` are now allowed to modify the storage of the chain. These storage modifications are silently discarded. Previously, a JSON-RPC error was returned. ([#259](https://github.com/smol-dot/smoldot/pull/259))

### Fixed

- Fix panic when connecting to a chain that hasn't finalized any block yet. ([#258](https://github.com/smol-dot/smoldot/pull/258))
- Fix the signatures of the `ext_default_child_storage_read_version_1` and `ext_default_child_storage_root_version_2` host functions. This would lead to a warning about these function being unresolved. ([#244](https://github.com/smol-dot/smoldot/pull/244))
- Fix panic when the input data of a Wasm function call is larger than a Wasm page. ([#218](https://github.com/smol-dot/smoldot/pull/218))
- Subscriptions to the `chain_subscribeAllHeads` JSON-RPC function now generate notifications named `chain_allHead`, like in Substrate. They were erroneously named `chain_newHead`. ([#227](https://github.com/smol-dot/smoldot/pull/227))

## 0.7.12 - 2023-02-22

### Changed

- The Wasm virtual machine no longer tries to grab a table symbol named `__indirect_function_table`. This removes support for an old Substrate feature that no longer exists. ([#181](https://github.com/smol-dot/smoldot/pull/181))
- The signature of host functions called by the Wasm runtime is now checked when the Wasm code is compiled rather than when the functions are called. ([#183](https://github.com/smol-dot/smoldot/pull/183))
- When a Wasm function is being called, the parameters of the function are now allocated using the same allocator as used during the execution (`ext_allocator_malloc_version_1` and `ext_allocator_free_version_1`) rather than being written at a specific location in memory. This is consistent with what Substrate is doing, and makes it legal for a Wasm runtime to call `ext_allocator_free_version_1` on the input data if desired. ([#188](https://github.com/smol-dot/smoldot/pull/188))

### Fixed

- The memory of the Wasm virtual machine is now properly zeroed between runs. This should fix a rare `MemoryAccessOutOfBounds` error occasionally appearing. ([#211](https://github.com/smol-dot/smoldot/pull/211))
- Fix the Wasm virtual machine not working properly if it exports its memory rather than import it. ([#207](https://github.com/smol-dot/smoldot/pull/207))

## 0.7.11 - 2023-02-13

### Changed

- Update the network protocol names used on the wire to use the `forkId` field used in the chain specification (if present) and no longer the `protocolId` (which is deprecated). Blockchains based off of Substrate versions later than October 2022 fully support either version. ([#155](https://github.com/smol-dot/smoldot/pull/155))

### Fixed

- Fix `state_getKeys` and `state_getKeysPaged` missing entries under certain conditions. ([#178](https://github.com/smol-dot/smoldot/pull/178))
- The alternative spellings `relayChain` and `paraId` for the `relay_chain` and `para_id` fields in chain specifications are now properly accepted as intended. ([#160](https://github.com/smol-dot/smoldot/pull/160))

## 0.7.10 - 2023-02-10

### Fixed

- Fix randomness not being implemented properly, leading to the same random numbers always being generated. This issue lead to all instances of smoldot (even on different machines) always using the same networking key, which would lead to connectivity issues when multiple instances of smoldot connect to the same full node. Note that because perfect forward secrecy is used (and the randomness on the full node side was still functionning properly), it is not possible to retroactively decipher networking communications. Additionally, the fact that the same random numbers are always generated made smoldot vulnerable to HashDoS attacks. ([#142](https://github.com/smol-dot/smoldot/pull/142))
- JSON-RPC requests without a `params` field are no longer invalid. ([#13](https://github.com/smol-dot/smoldot/pull/13))
- Fix Merkle proofs whose trie root node has a size inferior to 32 bytes being considered as invalid. ([#3046](https://github.com/paritytech/smoldot/pull/3046))

## 0.7.9 - 2022-11-28

### Fixed

- Fix wrong block being reported in the logs when printing the status of the Grandpa warp syncing, giving the impression that the warp syncing wasn't advancing. ([#3044](https://github.com/paritytech/smoldot/pull/3044))
- Fix panic introduced in v0.7.8 when verifying a Merkle proof of a trie related to a chain whose `state_version` is equal to `1`. ([#3043](https://github.com/paritytech/smoldot/pull/3043))

## 0.7.8 - 2022-11-23

### Changed

- In earlier versions of smoldot, `setTimeout(callback, 0)` was frequently used in order split execution of CPU-intensive tasks in multiple smaller ones while still giving back control to the execution environment (such as NodeJS or the browser). Unfortunately, when a web page is in the background, browsers set a minimum delay of one second for `setTimeout`. For this reason, the usage of ̀`setTimeout` has now been reduced to the strict minimum, except when the environment is browser and `document.visibilityState` is equal to `visible`. ([#2999](https://github.com/paritytech/smoldot/pull/2999))
- Optimize the Merkle proof verification. The complexity has been reduced from `O(n^2)` to `O(n * log n)`. ([#3013](https://github.com/paritytech/smoldot/pull/3013))

### Fixed

- Fix `ProtobufDecode` errors appearing while the Grandpa warp syncing is still in progress. ([#3018](https://github.com/paritytech/smoldot/pull/3018))

## 0.7.7 - 2022-11-11

### Added

- Add support for version 2 of the `TransactionPaymentApi` runtime API. This fixes the `payment_queryInfo` JSON-RPC call with newer runtime versions. ([#2995](https://github.com/paritytech/smoldot/pull/2995))

### Changed

- The `enableExperimentalWebRTC` field has been removed from `ClientConfig`, and replaced with a `forbidWebRtc` option. WebRTC is now considered stable enough to be enabled by default. ([#2977](https://github.com/paritytech/smoldot/pull/2977))
- The version of the runtime API is now verified to match the excepted value when the `payment_queryInfo`, `state_getMetadata`, and `system_accountNextIndex` JSON-RPC functions are called. This means that without an update to the smoldot source code these JSON-RPC functions will stop working if the runtime API is out of range. However, this eliminates the likelihood that smoldot returns accidentally parses a value in a different way than intended and an incorrect result. ([#2995](https://github.com/paritytech/smoldot/pull/2995))
- Reduced the number of networking round-trips after a connection has been opened by assuming that the remote supports the desired networking protocols instead of waiting for its confirmation. ([#2984](https://github.com/paritytech/smoldot/pull/2984))

## 0.7.6 - 2022-11-04

### Fixed

- On NodeJS, the usage of `hrtime` has been replaced with `performance.now()`. While this doesn't change anything for NodeJS users, Deno users that were importing smoldot through the <https://esm.sh> website will no longer get an error due to Deno's compatibility layer not supporting `hrtime`. As a reminder, smoldot is also published on the Deno/x registry and using <https://esm.sh> is unnecessary. ([#2964](https://github.com/paritytech/smoldot/pull/2964))
- Fix the `ext_crypto_ecdsa_verify_version_1` and `ext_crypto_ecdsa_verify_prehashed_version_1` host functions mixing their parameters and thus always failing. ([#2955](https://github.com/paritytech/smoldot/pull/2955))
- Fix an occasional panic in `runtime_service.rs` when adding a parachain. ([#2965](https://github.com/paritytech/smoldot/pull/2965))

## 0.7.5 - 2022-10-31

### Fixed

- Fix the `state_getKeysPaged` JSON-RPC function returning incorrect results in some situations. ([#2947](https://github.com/paritytech/smoldot/pull/2947))
- When opening a WebRTC connection, the ufrag and password of SDP requests are now properly set according to the WebRTC libp2p specification. ([#2924](https://github.com/paritytech/smoldot/pull/2924))

## 0.7.4 - 2022-10-27

### Changed

- The `payment_queryInfo` JSON-RPC function now works with runtimes that have defined the type of `Balance` to be less than 16 bytes. ([#2914](https://github.com/paritytech/smoldot/pull/2914))
- The parameter of `chainHead_unstable_finalizedDatabase` has been renamed from `max_size_bytes` to `maxSizeBytes`. ([#2923](https://github.com/paritytech/smoldot/pull/2923))
- The database now contains the hash of the genesis block header. This hash is verified when the database is loaded, and the database is ignored if there is a mismatch. This prevents accidents where the wrong database is provided, which would lead to the chain not working and would be hard to debug. ([#2928](https://github.com/paritytech/smoldot/pull/2928))

### Fixed

- Fix panic on Deno when a WebSocket connection abruptly closes. ([#2939](https://github.com/paritytech/smoldot/pull/2939))
- Fix errors showing in the browser's console about WebSockets being already in the CLOSING or CLOSED state. ([#2925](https://github.com/paritytech/smoldot/pull/2925))
- No longer panic when a WebRTC connection fails to open due to the browser calling callbacks in an unexpected order. ([#2936](https://github.com/paritytech/smoldot/pull/2936))

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
