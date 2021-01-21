// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Contains a light client implementation usable from a browser environment, using the
//! `wasm-bindgen` library.

#![recursion_limit = "512"]
#![deny(broken_intra_doc_links)]
#![deny(unused_crate_dependencies)]

use futures::prelude::*;
use smoldot::{
    chain, chain_spec,
    json_rpc::{self, methods},
    libp2p::{multiaddr, peer_id::PeerId},
    network::protocol,
    trie::proof_verify,
};
use std::{
    collections::{BTreeMap, HashSet},
    convert::TryFrom as _,
    iter,
    sync::Arc,
    time::Duration,
};

pub mod ffi;

mod network_service;
mod sync_service;

// Use the default "system" allocator. In the context of Wasm, this uses the `dlmalloc` library.
// See <https://github.com/rust-lang/rust/tree/1.47.0/library/std/src/sys/wasm>.
//
// While the `wee_alloc` crate is usually the recommended choice in WebAssembly, testing has shown
// that using it makes memory usage explode from ~100MiB to ~2GiB and more (the environment then
// refuses to allocate 4GiB).
#[global_allocator]
static ALLOC: std::alloc::System = std::alloc::System;

// TODO: several places in this module where we unwrap when we shouldn't

/*
# Implementation notes

TODO: remove this block after this code is production-ready

The objective of the wasm-node is to do two things:

- Synchronizing the chain(s).
- Answer JSON-RPC queries made by the user.

---

Synchronizing the chain(s) consists in:

  - At initialization, loading the chain specs (that potentially contain a checkpoint) and
optionally loading an existing database.
- Connecting and staying connected to a set of full nodes.
- Still at initialization, sending GrandPa warp sync queries to "jump" to the latest finalized
  block (https://github.com/paritytech/smoldot/issues/270). We would end up with a
  `ChainInformation` object containing an almost up-to-chain chain.
- Listening to incoming block announces (block announces contain block headers) and verifying them
  (https://github.com/paritytech/smoldot/issues/271).
- Listening to incoming GrandPa gossiping messages in order to be up-to-date with blocks being
  finalized.
- Every time the current best block is updated, downloading the values of a certain list of
  storage items (see JSON-RPC section below).

In other words, we should constantly be up-to-date with the best and finalized blocks of the
chain(s) we're connected to.

Depending on the chain specs being loaded, the node should either connect only to one chain, or,
if the chain is a parachain, to that one chain and Polkadot. In that second situation, all the
steps above should be done for both the chain and Polkadot.

The node, notably, doesn't store any block body, and doesn't hold the entire storage.

---

Answering JSON-RPC queries consists, well, in answering the requests made by the user.

An important thing to keep in mind is that the code here should be optimized for usage with a UI
whose objective is to look at the head of the chain and send transactions. For example, the code
below keeps a cache of the recent blocks, because we expect the UI to mostly query recent blocks.
It is for example not part of the objective right now to properly serve a UI that repeatedly
queries blocks that are months old.

Here is an overview of what the JSON-RPC queries consist of (without going in details):

- Submitting a transaction. It is unclear to me what this involves. In the case of
`author_submitAndWatchExtrinsic`, this theoretically means keeping track of this transaction in
order to check, in new blocks, whether this transaction has been included, and notifying the user
when that is the case.
- Getting notified when the best block or the finalized block changes.
- Requesting the headers of recent blocks, in particular the current best block and finalized
block. Because everything is asynchronous, it is possible that the user requests what they believe
is the latest finalized block while the latest finalized block has in reality in the meanwhile
been updated.
- Requesting storage items of blocks. This should be implemented by asking that information from
a full node (a so-called "storage proof").
- Requesting the metadata. The metadata is a piece of information that can be obtained from the
runtime code (see the `metadata` module), which is itself the storage item whose key is `:code`.
- Watching for changes in a storage item, where the user wants to be notified when the value of a
storage item is modified. This should also be implemented by sending, for each block we receive,
a storage proof requesting the value of every single storage item being watched, and comparing the
result with the one of the previous block. Note that "has changed" means "has changed compared to
the previous best block", and the "previous best block" can have the same height as the current
best block, notably in case of a reorg.
- Watching for changes in the runtime version. The runtime version is also a piece of information
that can be obtained from the runtime code. In order to watch for changes in the runtime version,
one has to watch for changes in the `:code` storage item, similar to the previous bullet point.

In order to be able to implement watching for storage items and runtime versions, the node should
therefore download, for each new best block, the value of each of these storage items being
watched and of the `:code` key.

*/

/// Starts a client running the given chain specifications.
///
/// > **Note**: This function returns a `Result`. The return value according to the JavaScript
/// >           function is what is in the `Ok`. If an `Err` is returned, a JavaScript exception
/// >           is thrown.
pub async fn start_client(chain_spec: String, database_content: Option<String>) {
    std::panic::set_hook(Box::new(|info| {
        ffi::throw(info.to_string());
    }));

    // Fool-proof check to make sure that randomness is properly implemented.
    assert_ne!(rand::random::<u64>(), 0);
    assert_ne!(rand::random::<u64>(), rand::random::<u64>());

    let chain_spec = match chain_spec::ChainSpec::from_json_bytes(&chain_spec) {
        Ok(cs) => cs,
        Err(err) => ffi::throw(format!("Error while opening chain specs: {}", err)),
    };

    // The database passed from the user is decoded. Any error while decoding is treated as if
    // there was no database.
    let database_content = if let Some(database_content) = database_content {
        if let Ok(parsed) =
            smoldot::database::finalized_serialize::decode_chain_information(&database_content)
        {
            Some(parsed)
        } else {
            None
        }
    } else {
        None
    };

    // Load the information about the chain from the chain specs. If a light sync state is
    // present in the chain specs, it is possible to start sync at the finalized block it
    // describes.
    let genesis_chain_information =
        chain::chain_information::ChainInformation::from_genesis_storage(
            chain_spec.genesis_storage(),
        )
        .unwrap();
    let chain_information = {
        let base = if let Some(light_sync_state) = chain_spec.light_sync_state() {
            light_sync_state.as_chain_information()
        } else {
            genesis_chain_information.clone()
        };

        // Only use the existing database if it is ahead of `base`.
        if let Some(database_content) = database_content {
            if database_content.finalized_block_header.number > base.finalized_block_header.number {
                database_content
            } else {
                base
            }
        } else {
            base
        }
    };

    // TODO: un-Arc-ify
    let network_service = network_service::NetworkService::new(network_service::Config {
        tasks_executor: Box::new(|fut| ffi::spawn_task(fut)),
        bootstrap_nodes: {
            let mut list = Vec::with_capacity(chain_spec.boot_nodes().len());
            for node in chain_spec.boot_nodes() {
                let mut address: multiaddr::Multiaddr = node.parse().unwrap(); // TODO: don't unwrap?
                if let Some(multiaddr::Protocol::P2p(peer_id)) = address.pop() {
                    let peer_id = PeerId::from_multihash(peer_id).unwrap(); // TODO: don't unwrap
                    list.push((peer_id, address));
                } else {
                    panic!() // TODO:
                }
            }
            list
        },
        genesis_block_hash: genesis_chain_information.finalized_block_header.hash(),
        best_block: (
            chain_information.finalized_block_header.number,
            chain_information.finalized_block_header.hash(),
        ),
        protocol_id: chain_spec.protocol_id().to_string(),
    })
    .await
    .unwrap();

    let sync_service = Arc::new(
        sync_service::SyncService::new(sync_service::Config {
            chain_information: chain_information.clone(),
            tasks_executor: Box::new(|fut| ffi::spawn_task(fut)),
        })
        .await,
    );

    let genesis_storage = chain_spec
        .genesis_storage()
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect::<BTreeMap<_, _>>();

    let best_block_metadata = {
        let code = genesis_storage.get(&b":code"[..]).unwrap();
        let heap_pages = 1024; // TODO: laziness
        smoldot::metadata::metadata_from_runtime_code(code, heap_pages).unwrap()
    };

    let mut client = {
        let finalized_block_hash = chain_information.finalized_block_header.hash();

        let mut known_blocks = lru::LruCache::new(256);
        known_blocks.put(
            finalized_block_hash,
            chain_information.finalized_block_header.clone(),
        );

        Client {
            chain_spec,
            network_service: network_service.clone(),
            peers: Vec::new(),
            known_blocks,
            best_block: finalized_block_hash,
            finalized_block: finalized_block_hash,
            genesis_storage,
            best_block_metadata,
            next_subscription: 0,
            runtime_version: HashSet::new(),
            all_heads: HashSet::new(),
            new_heads: HashSet::new(),
            finalized_heads: HashSet::new(),
            storage: HashSet::new(),
        }
    };

    // This implementation of `futures::Stream` fires at a regular time interval.
    // The state of the chain is saved every time it fires.
    let mut database_save_timer = stream::unfold((), move |_| {
        ffi::Delay::new(Duration::from_secs(15)).map(|_| Some(((), ())))
    })
    .map(|_| ());

    loop {
        futures::select! {
            network_message = network_service.next_event().fuse() => {
                match network_message {
                    network_service::Event::Connected { peer_id, best_block_number } => {
                        client.peers.push(peer_id.clone());
                        sync_service.add_source(peer_id, best_block_number).await;
                    }
                    network_service::Event::Disconnected(peer_id) => {
                        client.peers.retain(|p| *p != peer_id);
                        sync_service.remove_source(peer_id).await;
                    }
                    network_service::Event::BlockAnnounce { peer_id, announce } => {
                        let decoded = announce.decode();
                        sync_service.raise_source_best_block(peer_id, decoded.header.number).await;
                    }
                }
            },

            sync_message = sync_service.next_event().fuse() => {
                match sync_message {
                    sync_service::Event::BlocksRequest { id, target, request } => {
                        let block_request = network_service.clone().blocks_request(
                            target,
                            request
                        );

                        ffi::spawn_task({
                            let sync_service = sync_service.clone();
                            async move {
                                let result = block_request.await;
                                sync_service.answer_blocks_request(id, result.map_err(|_| ())).await;
                            }
                        });
                    },
                    sync_service::Event::NewBest { scale_encoded_header } => {
                        // TODO: this is also triggered if we reset the sync to a previous point, which isn't correct

                        let decoded = smoldot::header::decode(&scale_encoded_header).unwrap();
                        let header = header_conv(decoded.clone());

                        for subscription_id in &client.new_heads {
                            let notification = smoldot::json_rpc::parse::build_subscription_event(
                                "chain_newHead",
                                subscription_id,
                                &serde_json::to_string(&header).unwrap(),
                            );
                            ffi::emit_json_rpc_response(&notification);
                        }
                        for subscription_id in &client.all_heads {
                            let notification = smoldot::json_rpc::parse::build_subscription_event(
                                "chain_newHead",
                                subscription_id,
                                &serde_json::to_string(&header).unwrap(),
                            );
                            ffi::emit_json_rpc_response(&notification);
                        }

                        // Load the entry of the finalized block in order to guarantee that it
                        // remains in the LRU cache when `put` is called below.
                        let _ = client.known_blocks.get(&client.finalized_block).unwrap();

                        client.best_block = decoded.hash();
                        client.known_blocks.put(client.best_block, decoded.into());

                        debug_assert!(client.known_blocks.get(&client.finalized_block).is_some());

                        // TODO: need to update `best_block_metadata` if necessary, and notify the runtime version subscriptions
                    },
                    sync_service::Event::NewFinalized { scale_encoded_header } => {
                        let decoded = smoldot::header::decode(&scale_encoded_header).unwrap();
                        let header = header_conv(decoded.clone());

                        for subscription_id in &client.finalized_heads {
                            let notification = smoldot::json_rpc::parse::build_subscription_event(
                                "chain_finalizedHead",
                                subscription_id,
                                &serde_json::to_string(&header).unwrap(),
                            );
                            ffi::emit_json_rpc_response(&notification);
                        }

                        client.finalized_block = decoded.hash();
                        client.known_blocks.put(client.finalized_block, decoded.into());
                    },
                }
            },

            json_rpc_request = ffi::next_json_rpc().fuse() => {
                // TODO: don't unwrap
                // TODO: don't await here; use a queue
                let (response1, response2) = handle_rpc(&String::from_utf8(Vec::from(json_rpc_request)).unwrap(), &mut client).await;
                ffi::emit_json_rpc_response(&response1);
                if let Some(response2) = response2 {
                    ffi::emit_json_rpc_response(&response2);
                }
            },

            _interval = database_save_timer.next().fuse() => {
                debug_assert!(_interval.is_some());
                // A new task is spawned specifically for the saving, in order to not block the
                // main processing while waiting for the serialization.
                let sync_service = sync_service.clone();
                ffi::spawn_task(async move {
                    let database_content = sync_service.serialize_chain().await;
                    ffi::database_save(&database_content);
                });
            }
        }
    }
}

struct Client {
    chain_spec: chain_spec::ChainSpec,

    network_service: Arc<network_service::NetworkService>,

    /// Blocks that are temporarily saved in order to serve JSON-RPC requests.
    ///
    /// Always contains `best_block` and `finalized_block`.
    known_blocks: lru::LruCache<[u8; 32], smoldot::header::Header>,

    /// Hash of the current best block.
    best_block: [u8; 32],
    /// Hash of the latest finalized block.
    finalized_block: [u8; 32],

    // TODO: this is a hack before an actual requests distribution system is implemented
    peers: Vec<PeerId>,

    // TODO: remove; unnecessary
    genesis_storage: BTreeMap<Vec<u8>, Vec<u8>>,

    best_block_metadata: Vec<u8>,

    next_subscription: u64,

    runtime_version: HashSet<String>,
    all_heads: HashSet<String>,
    new_heads: HashSet<String>,
    finalized_heads: HashSet<String>,
    storage: HashSet<String>,
}

async fn handle_rpc(rpc: &str, client: &mut Client) -> (String, Option<String>) {
    let (request_id, call) = methods::parse_json_call(rpc).expect("bad request"); // TODO: don't unwrap
    match call {
        methods::MethodCall::author_pendingExtrinsics {} => {
            let response = methods::Response::author_pendingExtrinsics(Vec::new())
                .to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::chain_getBlockHash { height } => {
            // TODO: implement correctly
            let response = if height.is_some() {
                methods::Response::chain_getBlockHash(methods::HashHexString(client.best_block))
                    .to_json_response(request_id)
            } else {
                json_rpc::parse::build_success_response(request_id, "null")
            };
            (response, None)
        }
        methods::MethodCall::chain_getFinalizedHead {} => {
            let response = methods::Response::chain_getFinalizedHead(methods::HashHexString(
                client.finalized_block,
            ))
            .to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::chain_getHeader { hash } => {
            let hash = hash.as_ref().map(|h| &h.0).unwrap_or(&client.best_block);
            let response = if let Some(header) = client.known_blocks.get(hash) {
                methods::Response::chain_getHeader(header_conv(header)).to_json_response(request_id)
            } else {
                json_rpc::parse::build_success_response(request_id, "null")
            };

            (response, None)
        }
        methods::MethodCall::chain_subscribeAllHeads {} => {
            let subscription = client.next_subscription.to_string();
            client.next_subscription += 1;

            let response = methods::Response::chain_subscribeAllHeads(&subscription)
                .to_json_response(request_id);

            let response2 = smoldot::json_rpc::parse::build_subscription_event(
                "chain_allHeads", // TODO: is this string correct?
                &subscription,
                &serde_json::to_string(&header_conv(
                    client.known_blocks.get(&client.best_block).unwrap(),
                ))
                .unwrap(),
            );

            client.all_heads.insert(subscription.clone());

            (response, Some(response2))
        }
        methods::MethodCall::chain_subscribeNewHeads {} => {
            let subscription = client.next_subscription.to_string();
            client.next_subscription += 1;

            let response = methods::Response::chain_subscribeNewHeads(&subscription)
                .to_json_response(request_id);

            let response2 = smoldot::json_rpc::parse::build_subscription_event(
                "chain_newHead",
                &subscription,
                &serde_json::to_string(&header_conv(
                    client.known_blocks.get(&client.best_block).unwrap(),
                ))
                .unwrap(),
            );

            client.new_heads.insert(subscription.clone());

            (response, Some(response2))
        }
        methods::MethodCall::chain_subscribeFinalizedHeads {} => {
            let subscription = client.next_subscription.to_string();
            client.next_subscription += 1;

            let response = methods::Response::chain_subscribeFinalizedHeads(&subscription)
                .to_json_response(request_id);

            let response2 = smoldot::json_rpc::parse::build_subscription_event(
                "chain_finalizedHead",
                &subscription,
                &serde_json::to_string(&header_conv(
                    client.known_blocks.get(&client.finalized_block).unwrap(),
                ))
                .unwrap(),
            );

            client.finalized_heads.insert(subscription.clone());

            (response, Some(response2))
        }
        methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription } => {
            let valid = client.finalized_heads.remove(&subscription);
            let response = methods::Response::chain_unsubscribeFinalizedHeads(valid)
                .to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::rpc_methods {} => {
            let response = methods::Response::rpc_methods(methods::RpcMethods {
                version: 1,
                methods: methods::MethodCall::method_names()
                    .map(|n| n.into())
                    .collect(),
            })
            .to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::state_queryStorageAt { keys, at } => {
            let at = at.as_ref().map(|h| h.0).unwrap_or(client.best_block);

            // TODO: have no idea what this describes actually
            let mut out = methods::StorageChangeSet {
                block: methods::HashHexString(client.best_block),
                changes: Vec::new(),
            };

            for key in keys {
                // TODO: parallelism?
                if let Ok(value) = storage_query(client, &key.0, &at).await {
                    out.changes.push((key, value.map(methods::HexString)));
                }
            }

            let response =
                methods::Response::state_queryStorageAt(vec![out]).to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::state_getKeysPaged {
            prefix,
            count,
            start_key,
            hash,
        } => {
            assert!(hash.is_none()); // TODO:

            let mut out = Vec::new();
            // TODO: check whether start_key should be included of the set
            for (k, _) in client
                .genesis_storage
                .range(start_key.map(|p| p.0).unwrap_or(Vec::new())..)
            {
                if out.len() >= usize::try_from(count).unwrap_or(usize::max_value()) {
                    break;
                }

                if prefix
                    .as_ref()
                    .map_or(false, |prefix| !k.starts_with(&prefix.0))
                {
                    break;
                }

                out.push(methods::HexString(k.to_vec()));
            }

            let response = methods::Response::state_getKeysPaged(out).to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::state_getMetadata {} => {
            let response = methods::Response::state_getMetadata(methods::HexString(
                client.best_block_metadata.clone(),
            ))
            .to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::state_getStorage { key, hash } => {
            let hash = hash.as_ref().map(|h| h.0).unwrap_or(client.best_block);

            let response = match storage_query(client, &key.0, &hash).await {
                Ok(Some(value)) => {
                    methods::Response::state_getStorage(methods::HexString(value.to_owned())) // TODO: overhead
                        .to_json_response(request_id)
                }
                Ok(None) => json_rpc::parse::build_success_response(request_id, "null"),
                Err(()) => todo!(), // TODO:
            };

            (response, None)
        }
        methods::MethodCall::state_subscribeRuntimeVersion {} => {
            let subscription = client.next_subscription.to_string();
            client.next_subscription += 1;

            let response = methods::Response::state_subscribeRuntimeVersion(&subscription)
                .to_json_response(request_id);
            client.runtime_version.insert(subscription.clone());

            // FIXME: hack
            let response2 = methods::Response::state_getRuntimeVersion(methods::RuntimeVersion {
                spec_name: "polkadot".to_string(),
                impl_name: "smoldot".to_string(),
                authoring_version: 0,
                spec_version: 23,
                impl_version: 0,
                transaction_version: 4,
            })
            .to_json_response(request_id);

            (response, Some(response2))
        }
        methods::MethodCall::state_subscribeStorage { list } => {
            let subscription = client.next_subscription.to_string();
            client.next_subscription += 1;

            let response1 = methods::Response::state_subscribeStorage(&subscription)
                .to_json_response(request_id);
            client.storage.insert(subscription.clone());

            // TODO: have no idea what this describes actually
            let mut out = methods::StorageChangeSet {
                block: methods::HashHexString(client.best_block),
                changes: Vec::new(),
            };

            let best_block_hash = client.best_block;

            for key in list {
                // TODO: parallelism?
                if let Ok(value) = storage_query(client, &key.0, &best_block_hash).await {
                    out.changes.push((key, value.map(methods::HexString)));
                }
            }

            // TODO: hack
            let response2 = smoldot::json_rpc::parse::build_subscription_event(
                "state_storage",
                &subscription,
                &serde_json::to_string(&out).unwrap(),
            );

            // TODO: subscription not actually implemented

            (response1, Some(response2))
        }
        methods::MethodCall::state_unsubscribeStorage { subscription } => {
            let valid = client.storage.remove(&subscription);
            let response =
                methods::Response::state_unsubscribeStorage(valid).to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::state_getRuntimeVersion {} => {
            // FIXME: hack
            let response = methods::Response::state_getRuntimeVersion(methods::RuntimeVersion {
                spec_name: "polkadot".to_string(),
                impl_name: "smoldot".to_string(),
                authoring_version: 0,
                spec_version: 23,
                impl_version: 0,
                transaction_version: 4,
            })
            .to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::system_chain {} => {
            let response = methods::Response::system_chain(client.chain_spec.name())
                .to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::system_chainType {} => {
            let response = methods::Response::system_chainType(client.chain_spec.chain_type())
                .to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::system_health {} => {
            let response = methods::Response::system_health(methods::SystemHealth {
                is_syncing: true,        // TODO:
                peers: 1,                // TODO:
                should_have_peers: true, // TODO:
            })
            .to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::system_name {} => {
            let response = methods::Response::system_name("smoldot!").to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::system_peers {} => {
            // TODO: return proper response
            let response = methods::Response::system_peers(vec![]).to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::system_properties {} => {
            let response = methods::Response::system_properties(
                serde_json::from_str(client.chain_spec.properties()).unwrap(),
            )
            .to_json_response(request_id);
            (response, None)
        }
        methods::MethodCall::system_version {} => {
            let response = methods::Response::system_version("1.0.0").to_json_response(request_id);
            (response, None)
        }
        _ => {
            println!("unimplemented: {:?}", call);
            panic!(); // TODO:
        }
    }
}

async fn storage_query(
    client: &mut Client,
    key: &[u8],
    hash: &[u8; 32],
) -> Result<Option<Vec<u8>>, ()> {
    let trie_root_hash = if let Some(header) = client.known_blocks.get(hash) {
        Some(header.state_root)
    } else {
        None
    };

    let mut result = Err(());

    for target in client.peers.iter().take(3) {
        if trie_root_hash.is_none() || result.is_ok() {
            break;
        }

        result = client
            .network_service
            .clone()
            .storage_proof_request(
                target.clone(),
                protocol::StorageProofRequestConfig {
                    block_hash: *hash,
                    keys: iter::once(key),
                },
            )
            .await
            .map_err(|_| ())
            .and_then(|outcome| {
                proof_verify::verify_proof(proof_verify::Config {
                    proof: outcome.iter().map(|nv| &nv[..]),
                    requested_key: key,
                    trie_root_hash: trie_root_hash.as_ref().unwrap(),
                })
                .map_err(|_| ())
                .map(|v| v.map(|v| v.to_owned()))
            });
    }

    result
}

fn header_conv<'a>(header: impl Into<smoldot::header::HeaderRef<'a>>) -> methods::Header {
    let header = header.into();

    methods::Header {
        parent_hash: methods::HashHexString(*header.parent_hash),
        extrinsics_root: methods::HashHexString(*header.extrinsics_root),
        state_root: methods::HashHexString(*header.state_root),
        number: header.number,
        digest: methods::HeaderDigest {
            logs: header
                .digest
                .logs()
                .map(|log| {
                    methods::HexString(log.scale_encoding().fold(Vec::new(), |mut a, b| {
                        a.extend_from_slice(b.as_ref());
                        a
                    }))
                })
                .collect(),
        },
    }
}

/// Use in an asynchronous context to interrupt the current task execution and schedule it back.
///
/// This function is useful in order to guarantee a fine granularity of tasks execution time in
/// situations where a CPU-heavy task is being performed.
async fn yield_once() {
    let mut pending = true;
    futures::future::poll_fn(move |cx| {
        if pending {
            pending = false;
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        } else {
            core::task::Poll::Ready(())
        }
    })
    .await
}
