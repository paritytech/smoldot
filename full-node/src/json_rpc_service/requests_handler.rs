// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

use futures_lite::future;
use smol::stream::StreamExt as _;
use smoldot::{
    executor,
    json_rpc::{methods, parse, service},
    trie,
};
use std::{
    iter,
    pin::{self, Pin},
    sync::Arc,
};

use crate::{
    LogCallback, LogLevel, consensus_service, database_thread,
    json_rpc_service::{legacy_api_subscriptions, runtime_caches_service},
    network_service,
};

pub struct Config {
    /// Function that can be used to spawn background tasks.
    ///
    /// The tasks passed as parameter must be executed until they shut down.
    pub tasks_executor: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,

    /// Function called in order to notify of something.
    pub log_callback: Arc<dyn LogCallback + Send + Sync>,

    pub receiver: async_channel::Receiver<Message>,

    /// Database to access blocks.
    pub database: Arc<database_thread::DatabaseThread>,

    /// Access to the network, and identifier of the chain from the point of view of the network
    /// service.
    pub network_service: (
        Arc<network_service::NetworkService>,
        network_service::ChainId,
    ),

    /// Name of the chain, as found in the chain specification.
    pub chain_name: String,

    /// Type of the chain, as found in the chain specification.
    pub chain_type: String,

    /// JSON-encoded properties of the chain, as found in the chain specification.
    pub chain_properties_json: String,

    /// Whether the chain is a live network. Found in the chain specification.
    pub chain_is_live: bool,

    /// Hash of the genesis block.
    // TODO: load from database maybe?
    pub genesis_block_hash: [u8; 32],

    /// Consensus service of the chain.
    pub consensus_service: Arc<consensus_service::ConsensusService>,

    /// Runtime caches service of the JSON-RPC service.
    pub runtime_caches_service: Arc<runtime_caches_service::RuntimeCachesService>,
}

pub enum Message {
    Request(service::RequestProcess),
    SubscriptionStart(service::SubscriptionStartProcess),
}

pub fn spawn_requests_handler(config: Config) {
    let tasks_executor = config.tasks_executor.clone();
    tasks_executor(Box::pin(async move {
        let mut receiver = pin::pin!(config.receiver);
        loop {
            match receiver.next().await {
                Some(Message::Request(request)) => match request.request() {
                    methods::MethodCall::rpc_methods {} => {
                        request.respond(methods::Response::rpc_methods(methods::RpcMethods {
                            methods: methods::MethodCall::method_names()
                                .map(|n| n.into())
                                .collect(),
                        }));
                    }

                    methods::MethodCall::chainSpec_v1_chainName {} => {
                        request.respond(methods::Response::chainSpec_v1_chainName(
                            (&config.chain_name).into(),
                        ));
                    }
                    methods::MethodCall::chainSpec_v1_genesisHash {} => {
                        request.respond(methods::Response::chainSpec_v1_genesisHash(
                            methods::HashHexString(config.genesis_block_hash),
                        ));
                    }
                    methods::MethodCall::chainSpec_v1_properties {} => {
                        request.respond(methods::Response::chainSpec_v1_properties(
                            serde_json::from_str(&config.chain_properties_json).unwrap(),
                        ));
                    }

                    methods::MethodCall::chain_getBlockHash { height: Some(0) } => {
                        // In the case where the database was populated through a warp sync, it
                        // might not store block 0 in it. However, the hash of block 0 is
                        // particularly important for JSON-RPC clients, and as such we make sure
                        // to always respond successfully to block 0 requests, even if it isn't
                        // in the database.
                        request.respond(methods::Response::chain_getBlockHash(
                            methods::HashHexString(config.genesis_block_hash),
                        ))
                    }
                    methods::MethodCall::chain_getBlockHash { height } => {
                        let outcome = config
                            .database
                            .with_database(move |database| match height {
                                Some(height) => database.best_block_hash_by_number(height),
                                None => database.best_block_hash().map(Some),
                            })
                            .await;
                        match outcome {
                            Ok(Some(hash)) => request.respond(
                                methods::Response::chain_getBlockHash(methods::HashHexString(hash)),
                            ),
                            Ok(None) => request.respond_null(),
                            Err(error) => {
                                config.log_callback.log(LogLevel::Warn, format!("json-rpc; request=chain_getBlockHash; height={:?}; database_error={}", height, error));
                                request.fail(parse::ErrorResponse::InternalError)
                            }
                        }
                    }
                    methods::MethodCall::chain_getHeader { hash } => {
                        let hash = match hash {
                            Some(h) => h.0,
                            None => match config
                                .database
                                .with_database(|db| db.best_block_hash())
                                .await
                            {
                                Ok(b) => b,
                                Err(_) => {
                                    request.fail(service::ErrorResponse::InternalError);
                                    continue;
                                }
                            },
                        };

                        let result = config
                            .database
                            .with_database(move |db| db.block_scale_encoded_header(&hash))
                            .await;

                        match result {
                            Ok(Some(encoded_header)) => {
                                match methods::Header::from_scale_encoded_header(
                                    &encoded_header,
                                    config.consensus_service.block_number_bytes(),
                                ) {
                                    Ok(header) => {
                                        request.respond(methods::Response::chain_getHeader(header))
                                    }
                                    Err(_) => {
                                        request.fail(service::ErrorResponse::InternalError);
                                    }
                                }
                            }
                            Ok(None) => {
                                request.respond_null();
                            }
                            Err(_) => {
                                request.fail(service::ErrorResponse::InternalError);
                            }
                        }
                    }
                    methods::MethodCall::state_getKeysPaged {
                        prefix,
                        count,
                        start_key,
                        hash,
                    } => {
                        // As an undocumented thing, a count strictly superior to 1000 isn't
                        // accepted by Substrate.
                        // See <https://github.com/paritytech/polkadot-sdk/blob/61be78c621ab2fa390cd3bfc79c8307431d0ea90/substrate/client/rpc/src/state/mod.rs#L238>.
                        if count > 1000 {
                            request.fail(service::ErrorResponse::InvalidParams(None));
                            continue;
                        }

                        // Turn the parameters into a format suitable for the database query.
                        let prefix_nibbles = prefix.map_or(Vec::new(), |p| {
                            trie::bytes_to_nibbles(p.0.iter().copied())
                                .map(u8::from)
                                .collect()
                        });
                        let mut start_key_nibbles = start_key.map_or(Vec::new(), |p| {
                            trie::bytes_to_nibbles(p.0.iter().copied())
                                .map(u8::from)
                                .collect()
                        });

                        // There's a difference of semantics between `state_getKeysPaged` and
                        // the database query we perform below in the situation where `start_key`
                        // isn't within `prefix`: the database request will return nothing while
                        // the JSON-RPC request expects the first key within `prefix`. As such,
                        // we adjust the start key if necessary.
                        // TODO: add documentation and a test in the database code regarding this behavior
                        if start_key_nibbles < prefix_nibbles {
                            start_key_nibbles = prefix_nibbles.clone();
                        }

                        // Continue in the background.
                        let result = config
                            .database
                            .with_database(
                                move |db| -> Result<_, database_thread::StorageAccessError> {
                                    let hash = match hash {
                                        Some(h) => h.0,
                                        None => db.best_block_hash()?,
                                    };

                                    let mut out =
                                        Vec::with_capacity(usize::try_from(count).unwrap());

                                    let mut key_iter = start_key_nibbles;

                                    // The query is performed by repeatedly asking for the next
                                    // key.
                                    while out.len() < usize::try_from(count).unwrap() {
                                        let next_key_nibbles = db.block_storage_next_key(
                                            &hash,
                                            iter::empty::<iter::Empty<_>>(),
                                            key_iter.iter().copied(),
                                            prefix_nibbles.iter().copied(),
                                            false,
                                        )?;

                                        let Some(next_key_nibbles) = next_key_nibbles else {
                                            break;
                                        };

                                        out.push(methods::HexString(
                                            trie::nibbles_to_bytes_truncate(
                                                next_key_nibbles
                                                    .iter()
                                                    .copied()
                                                    .map(|n| trie::Nibble::try_from(n).unwrap()),
                                            )
                                            .collect::<Vec<_>>(),
                                        ));

                                        // Push an extra nibble as otherwise `block_storage_next_key`
                                        // will return the same key again.
                                        key_iter = next_key_nibbles;
                                        key_iter.push(0);
                                    }

                                    Ok(out)
                                },
                            )
                            .await;

                        // Send back outcome.
                        match result {
                            Ok(out) => {
                                request.respond(methods::Response::state_getKeysPaged(out));
                            }
                            Err(database_thread::StorageAccessError::IncompleteStorage)
                            | Err(database_thread::StorageAccessError::UnknownBlock) => {
                                // Note that it is unclear how the function should behave in
                                // that situation.
                                request.fail(service::ErrorResponse::InvalidParams(None));
                            }
                            Err(database_thread::StorageAccessError::Corrupted(_)) => {
                                request.fail(service::ErrorResponse::InternalError);
                            }
                        }
                    }
                    methods::MethodCall::state_getMetadata { hash } => {
                        let hash = match hash {
                            Some(h) => h.0,
                            None => match config
                                .database
                                .with_database(|db| db.best_block_hash())
                                .await
                            {
                                Ok(b) => b,
                                Err(_) => {
                                    request.fail(service::ErrorResponse::InternalError);
                                    continue;
                                }
                            },
                        };

                        let runtime = match config.runtime_caches_service.get(hash).await {
                            Ok(runtime) => (*runtime).clone(),
                            Err(runtime_caches_service::GetError::UnknownBlock)
                            | Err(runtime_caches_service::GetError::Pruned) => {
                                request.respond_null();
                                continue;
                            } // TODO: unclear if correct error
                            Err(runtime_caches_service::GetError::InvalidRuntime(_))
                            | Err(runtime_caches_service::GetError::NoCode)
                            | Err(runtime_caches_service::GetError::InvalidHeapPages)
                            | Err(runtime_caches_service::GetError::CorruptedDatabase) => {
                                request.fail(service::ErrorResponse::InternalError);
                                continue;
                            }
                        };

                        let mut call =
                            match executor::runtime_call::run(executor::runtime_call::Config {
                                virtual_machine: runtime,
                                function_to_call: "Metadata_metadata",
                                parameter: iter::empty::<&'static [u8]>(),
                                max_log_level: 0,
                                storage_proof_size_behavior: executor::runtime_call::StorageProofSizeBehavior::proof_recording_disabled(),
                                storage_main_trie_changes: Default::default(),
                                calculate_trie_changes: false,
                            }) {
                                Ok(c) => c,
                                Err(_) => {
                                    request.fail(service::ErrorResponse::InternalError);
                                    continue;
                                }
                            };

                        loop {
                            match call {
                                executor::runtime_call::RuntimeCall::Finished(Ok(success)) => {
                                    match methods::remove_metadata_length_prefix(success.virtual_machine.value().as_ref()) {
                                        Ok(m) => request.respond(methods::Response::state_getMetadata(methods::HexString(m.to_vec()))),
                                        Err(_) => {
                                            request.fail(service::ErrorResponse::InternalError);
                                        }
                                    }
                                    break;
                                }
                                executor::runtime_call::RuntimeCall::Finished(Err(_)) => {
                                    request.fail(service::ErrorResponse::InternalError);
                                    break;
                                }
                                executor::runtime_call::RuntimeCall::StorageGet(req) => {
                                    let parent_paths = req.child_trie().map(|child_trie| {
                                        trie::bytes_to_nibbles(
                                            b":child_storage:default:".iter().copied(),
                                        )
                                        .chain(trie::bytes_to_nibbles(
                                            child_trie.as_ref().iter().copied(),
                                        ))
                                        .map(u8::from)
                                        .collect::<Vec<_>>()
                                    });
                                    let key =
                                        trie::bytes_to_nibbles(req.key().as_ref().iter().copied())
                                            .map(u8::from)
                                            .collect::<Vec<_>>();
                                    let value = config
                                        .database
                                        .with_database(move |db| {
                                            db.block_storage_get(
                                                &hash,
                                                parent_paths.into_iter().map(|p| p.into_iter()),
                                                key.iter().copied(),
                                            )
                                        })
                                        .await;
                                    let Ok(value) = value else {
                                        request.fail(service::ErrorResponse::InternalError);
                                        break;
                                    };
                                    let value = value.as_ref().map(|(val, vers)| {
                                        (
                                            iter::once(&val[..]),
                                            executor::runtime_call::TrieEntryVersion::try_from(*vers)
                                                .expect("corrupted database"),
                                        )
                                    });

                                    call = req.inject_value(value);
                                }
                                executor::runtime_call::RuntimeCall::ClosestDescendantMerkleValue(req) => {
                                    let parent_paths = req.child_trie().map(|child_trie| {
                                        trie::bytes_to_nibbles(
                                            b":child_storage:default:".iter().copied(),
                                        )
                                        .chain(trie::bytes_to_nibbles(
                                            child_trie.as_ref().iter().copied(),
                                        ))
                                        .map(u8::from)
                                        .collect::<Vec<_>>()
                                    });
                                    let key_nibbles = req.key().map(u8::from).collect::<Vec<_>>();

                                    let merkle_value = config
                                        .database
                                        .with_database(move |db| {
                                            db.block_storage_closest_descendant_merkle_value(
                                                &hash,
                                                parent_paths.into_iter().map(|p| p.into_iter()),
                                                key_nibbles.iter().copied(),
                                            )
                                        })
                                        .await;

                                    let Ok(merkle_value) = merkle_value else {
                                        request.fail(service::ErrorResponse::InternalError);
                                        break;
                                    };

                                    call = req
                                        .inject_merkle_value(merkle_value.as_ref().map(|v| &v[..]));
                                }
                                executor::runtime_call::RuntimeCall::NextKey(req) => {
                                    let parent_paths = req.child_trie().map(|child_trie| {
                                        trie::bytes_to_nibbles(
                                            b":child_storage:default:".iter().copied(),
                                        )
                                        .chain(trie::bytes_to_nibbles(
                                            child_trie.as_ref().iter().copied(),
                                        ))
                                        .map(u8::from)
                                        .collect::<Vec<_>>()
                                    });
                                    let key_nibbles = req
                                        .key()
                                        .map(u8::from)
                                        .chain(if req.or_equal() { None } else { Some(0u8) })
                                        .collect::<Vec<_>>();
                                    let prefix_nibbles =
                                        req.prefix().map(u8::from).collect::<Vec<_>>();

                                    let branch_nodes = req.branch_nodes();
                                    let next_key = config
                                        .database
                                        .with_database(move |db| {
                                            db.block_storage_next_key(
                                                &hash,
                                                parent_paths.into_iter().map(|p| p.into_iter()),
                                                key_nibbles.iter().copied(),
                                                prefix_nibbles.iter().copied(),
                                                branch_nodes,
                                            )
                                        })
                                        .await;

                                    let Ok(next_key) = next_key else {
                                        request.fail(service::ErrorResponse::InternalError);
                                        break;
                                    };

                                    call = req.inject_key(next_key.map(|k| {
                                        k.into_iter().map(|b| trie::Nibble::try_from(b).unwrap())
                                    }));
                                }
                                executor::runtime_call::RuntimeCall::OffchainStorageSet(req) => {
                                    call = req.resume();
                                }
                                executor::runtime_call::RuntimeCall::SignatureVerification(req) => {
                                    call = req.verify_and_resume();
                                }
                                executor::runtime_call::RuntimeCall::Offchain(_) => {
                                    request.fail(service::ErrorResponse::InternalError);
                                    break;
                                }
                                executor::runtime_call::RuntimeCall::LogEmit(req) => {
                                    // Logs are ignored.
                                    call = req.resume();
                                }
                            }
                        }
                    }
                    methods::MethodCall::state_getRuntimeVersion { at } => {
                        let at = match at {
                            Some(h) => h.0,
                            None => match config
                                .database
                                .with_database(|db| db.best_block_hash())
                                .await
                            {
                                Ok(b) => b,
                                Err(_) => {
                                    request.fail(service::ErrorResponse::InternalError);
                                    continue;
                                }
                            },
                        };

                        match config.runtime_caches_service.get(at).await {
                            Ok(runtime) => {
                                request.respond(methods::Response::state_getRuntimeVersion(
                                    convert_runtime_version(runtime.runtime_version()),
                                ));
                            }
                            Err(runtime_caches_service::GetError::UnknownBlock)
                            | Err(runtime_caches_service::GetError::Pruned) => {
                                request.respond_null()
                            } // TODO: unclear if correct error
                            Err(runtime_caches_service::GetError::InvalidRuntime(_))
                            | Err(runtime_caches_service::GetError::NoCode)
                            | Err(runtime_caches_service::GetError::InvalidHeapPages)
                            | Err(runtime_caches_service::GetError::CorruptedDatabase) => {
                                request.fail(service::ErrorResponse::InternalError)
                            }
                        }
                    }
                    methods::MethodCall::state_queryStorageAt { keys, at } => {
                        // TODO: add a limit to the number of keys?

                        // Convert the list of keys into a format suitable for the database.
                        let keys_nibbles = keys
                            .iter()
                            .map(|key| {
                                trie::bytes_to_nibbles(key.0.iter().copied())
                                    .map(u8::from)
                                    .collect::<Vec<_>>()
                            })
                            .collect::<Vec<_>>();

                        // The bulk of the request is performed in the database thread.
                        let result = config
                            .database
                            .with_database(move |db| {
                                let at = match at {
                                    Some(h) => h.0,
                                    None => db.best_block_hash()?,
                                };

                                let parent = db
                                    .block_parent(&at)?
                                    .ok_or(database_thread::StorageAccessError::UnknownBlock)?;

                                let mut out = methods::StorageChangeSet {
                                    block: methods::HashHexString(at),
                                    changes: Vec::with_capacity(keys_nibbles.len()),
                                };

                                for (key_nibbles, key) in
                                    keys_nibbles.into_iter().zip(keys.into_iter())
                                {
                                    let before = match db.block_storage_get(
                                        &parent,
                                        iter::empty::<iter::Empty<_>>(),
                                        key_nibbles.iter().copied(),
                                    ) {
                                        Ok(v) => v,
                                        Err(database_thread::StorageAccessError::UnknownBlock)
                                            if parent == [0; 32] =>
                                        {
                                            // In case where `at` is the genesis block, we
                                            // assume that its "parent" (which doesn't exist)
                                            // has an empty storage.
                                            None
                                        }
                                        Err(err) => return Err(err),
                                    };

                                    let after = db.block_storage_get(
                                        &at,
                                        iter::empty::<iter::Empty<_>>(),
                                        key_nibbles.iter().copied(),
                                    )?;

                                    if before != after {
                                        out.changes
                                            .push((key, after.map(|(v, _)| methods::HexString(v))));
                                    }
                                }

                                Ok(out)
                            })
                            .await;

                        // Send back the response.
                        match result {
                            Ok(out) => {
                                request.respond(methods::Response::state_queryStorageAt(vec![out]));
                            }
                            Err(database_thread::StorageAccessError::IncompleteStorage)
                            | Err(database_thread::StorageAccessError::UnknownBlock) => {
                                // Note that it is unclear how the function should behave in
                                // that situation.
                                request.fail(service::ErrorResponse::InvalidParams(None));
                            }
                            Err(database_thread::StorageAccessError::Corrupted(_)) => {
                                request.fail(service::ErrorResponse::InternalError);
                            }
                        }
                    }
                    methods::MethodCall::system_chain {} => {
                        request
                            .respond(methods::Response::system_chain((&config.chain_name).into()));
                    }
                    methods::MethodCall::system_chainType {} => {
                        request.respond(methods::Response::system_chainType(
                            (&config.chain_type).into(),
                        ));
                    }
                    methods::MethodCall::system_health {} => {
                        let (is_syncing, peers) = future::zip(
                            config.consensus_service.is_major_syncing_hint(),
                            config.network_service.0.num_peers(config.network_service.1),
                        )
                        .await;

                        request.respond(methods::Response::system_health(methods::SystemHealth {
                            is_syncing,
                            peers: u64::try_from(peers).unwrap_or(u64::MAX),
                            should_have_peers: config.chain_is_live,
                        }));
                    }
                    methods::MethodCall::system_localPeerId {} => {
                        let peer_id = config.network_service.0.local_peer_id().to_base58();
                        request.respond(methods::Response::system_localPeerId(peer_id.into()));
                    }
                    methods::MethodCall::system_name {} => {
                        request.respond(methods::Response::system_version(
                            env!("CARGO_PKG_NAME").into(),
                        ));
                    }
                    methods::MethodCall::system_properties {} => {
                        request.respond(methods::Response::system_properties(
                            serde_json::from_str(&config.chain_properties_json).unwrap(),
                        ));
                    }
                    methods::MethodCall::system_version {} => {
                        request.respond(methods::Response::system_version(
                            env!("CARGO_PKG_VERSION").into(),
                        ));
                    }

                    _ => request.fail(service::ErrorResponse::ServerError(
                        -32000,
                        "Not implemented in smoldot yet",
                    )),
                },
                Some(Message::SubscriptionStart(request)) => match request.request() {
                    methods::MethodCall::chain_subscribeAllHeads {} => {
                        let block_number_bytes = config.consensus_service.block_number_bytes();
                        let mut blocks_to_report = legacy_api_subscriptions::SubscribeAllHeads::new(
                            config.consensus_service.clone(),
                        );

                        (config.tasks_executor)(Box::pin(async move {
                            let mut subscription = request.accept();
                            let subscription_id = subscription.subscription_id().to_owned();

                            loop {
                                let scale_encoded_header =
                                    blocks_to_report.next_scale_encoded_header().await;

                                let json_rpc_header =
                                    match methods::Header::from_scale_encoded_header(
                                        &scale_encoded_header,
                                        block_number_bytes,
                                    ) {
                                        Ok(h) => h,
                                        Err(_) => {
                                            // TODO: consider reporting to logs
                                            continue;
                                        }
                                    };

                                subscription
                                    .send_notification(methods::ServerToClient::chain_allHead {
                                        subscription: (&subscription_id).into(),
                                        result: json_rpc_header.clone(),
                                    })
                                    .await
                            }
                        }));
                    }

                    methods::MethodCall::chain_subscribeFinalizedHeads {} => {
                        let block_number_bytes = config.consensus_service.block_number_bytes();
                        let mut blocks_to_report =
                            legacy_api_subscriptions::SubscribeFinalizedHeads::new(
                                config.consensus_service.clone(),
                            );

                        (config.tasks_executor)(Box::pin(async move {
                            let mut subscription = request.accept();
                            let subscription_id = subscription.subscription_id().to_owned();

                            loop {
                                let scale_encoded_header =
                                    blocks_to_report.next_scale_encoded_header().await;

                                let json_rpc_header =
                                    match methods::Header::from_scale_encoded_header(
                                        &scale_encoded_header,
                                        block_number_bytes,
                                    ) {
                                        Ok(h) => h,
                                        Err(_) => {
                                            // TODO: consider reporting to logs
                                            continue;
                                        }
                                    };

                                subscription
                                    .send_notification(
                                        methods::ServerToClient::chain_finalizedHead {
                                            subscription: (&subscription_id).into(),
                                            result: json_rpc_header.clone(),
                                        },
                                    )
                                    .await
                            }
                        }));
                    }

                    methods::MethodCall::chain_subscribeNewHeads {} => {
                        let block_number_bytes = config.consensus_service.block_number_bytes();
                        let mut blocks_to_report = legacy_api_subscriptions::SubscribeNewHeads::new(
                            config.consensus_service.clone(),
                        );

                        (config.tasks_executor)(Box::pin(async move {
                            let mut subscription = request.accept();
                            let subscription_id = subscription.subscription_id().to_owned();

                            loop {
                                let scale_encoded_header =
                                    blocks_to_report.next_scale_encoded_header().await;

                                let json_rpc_header =
                                    match methods::Header::from_scale_encoded_header(
                                        scale_encoded_header,
                                        block_number_bytes,
                                    ) {
                                        Ok(h) => h,
                                        Err(_) => {
                                            // TODO: consider reporting to logs
                                            continue;
                                        }
                                    };

                                subscription
                                    .send_notification(methods::ServerToClient::chain_newHead {
                                        subscription: (&subscription_id).into(),
                                        result: json_rpc_header.clone(),
                                    })
                                    .await
                            }
                        }));
                    }

                    methods::MethodCall::state_subscribeRuntimeVersion {} => {
                        let mut runtime_versions_to_report =
                            legacy_api_subscriptions::SubscribeRuntimeVersion::new(
                                config.consensus_service.clone(),
                            );

                        (config.tasks_executor)(Box::pin(async move {
                            let mut subscription = request.accept();
                            let subscription_id = subscription.subscription_id().to_owned();

                            loop {
                                let runtime_version =
                                    runtime_versions_to_report.next_runtime_version().await;

                                subscription
                                    .send_notification(
                                        methods::ServerToClient::state_runtimeVersion {
                                            subscription: (&subscription_id).into(),
                                            result: Some(convert_runtime_version(runtime_version)),
                                        },
                                    )
                                    .await
                            }
                        }));
                    }

                    methods::MethodCall::state_subscribeStorage { list } => {
                        let mut notifications_to_report =
                            legacy_api_subscriptions::SubscribeStorage::new(
                                config.consensus_service.clone(),
                                config.database.clone(),
                                list.into_iter().map(|item| item.0).collect(),
                            );

                        (config.tasks_executor)(Box::pin(async move {
                            let mut subscription = request.accept();
                            let subscription_id = subscription.subscription_id().to_owned();

                            loop {
                                let (block_hash, storage_changes) =
                                    notifications_to_report.next_storage_update().await;

                                subscription
                                    .send_notification(methods::ServerToClient::state_storage {
                                        subscription: (&subscription_id).into(),
                                        result: methods::StorageChangeSet {
                                            block: methods::HashHexString(block_hash),
                                            changes: storage_changes
                                                .map(|(key, value)| {
                                                    (
                                                        methods::HexString(key),
                                                        value.map(methods::HexString),
                                                    )
                                                })
                                                .collect(),
                                        },
                                    })
                                    .await
                            }
                        }));
                    }

                    _ => request.fail(service::ErrorResponse::ServerError(
                        -32000,
                        "Not implemented in smoldot yet",
                    )),
                },
                None => return,
            }
        }
    }));
}

fn convert_runtime_version(runtime_spec: &'_ executor::CoreVersion) -> methods::RuntimeVersion<'_> {
    let runtime_spec = runtime_spec.decode();
    methods::RuntimeVersion {
        spec_name: runtime_spec.spec_name.into(),
        impl_name: runtime_spec.impl_name.into(),
        authoring_version: u64::from(runtime_spec.authoring_version),
        spec_version: u64::from(runtime_spec.spec_version),
        impl_version: u64::from(runtime_spec.impl_version),
        transaction_version: runtime_spec.transaction_version.map(u64::from),
        state_version: runtime_spec.state_version.map(u8::from).map(u64::from),
        apis: runtime_spec
            .apis
            .map(|api| (methods::HexString(api.name_hash.to_vec()), api.version))
            .collect(),
    }
}
