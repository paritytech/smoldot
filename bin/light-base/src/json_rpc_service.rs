// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

//! Background JSON-RPC service.
//!
//! # Usage
//!
//! Create a new JSON-RPC service using [`JsonRpcService::new`]. Creating a JSON-RPC service
//! spawns a background task (through [`Config::tasks_executor`]) dedicated to processing JSON-RPC
//! requests.
//!
//! In order to process a JSON-RPC request, call [`JsonRpcService::queue_rpc_request`]. Later, the
//! JSON-RPC service can queue a response or, in the case of subscriptions, a notification on the
//! channel passed through [`Config::responses_sender`].
//!
//! In the situation where an attacker finds a JSON-RPC request that takes a long time to be
//! processed and continuously submits this same expensive request over and over again, the queue
//! of pending requests will start growing and use more and more memory. For this reason, if this
//! queue grows past [`Config::max_pending_requests`] items, [`JsonRpcService::queue_rpc_request`]
//! will instead return an error.
//!

// TODO: doc
// TODO: re-review this once finished

use crate::{runtime_service, sync_service, transactions_service, Platform};

use futures::{channel::mpsc, lock::Mutex, prelude::*};
use smoldot::{
    chain::fork_tree,
    chain_spec,
    executor::{self, host, read_only_runtime_host},
    header,
    json_rpc::{self, methods, requests_subscriptions},
    libp2p::{multiaddr, PeerId},
    network::protocol,
};
use std::{
    collections::HashMap,
    iter,
    marker::PhantomData,
    num::NonZeroU32,
    str,
    sync::{atomic, Arc},
};

/// Configuration for a JSON-RPC service.
pub struct Config<'a, TPlat: Platform> {
    /// Name of the chain, for logging purposes.
    ///
    /// > **Note**: This name will be directly printed out. Any special character should already
    /// >           have been filtered out from this name.
    pub log_name: String,

    /// Channel to send the responses to.
    pub responses_sender: mpsc::Sender<String>,

    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(String, future::BoxFuture<'static, ()>) + Send>,

    /// Service responsible for synchronizing the chain.
    pub sync_service: Arc<sync_service::SyncService<TPlat>>,

    /// Service responsible for emitting transactions and tracking their state.
    pub transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,

    /// Service that provides a ready-to-be-called runtime for the current best block.
    pub runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,

    /// Specification of the chain.
    pub chain_spec: &'a chain_spec::ChainSpec,

    /// Network identity of the node.
    pub peer_id: &'a PeerId,

    /// Value to return when the `system_name` RPC is called. Should be set to the name of the
    /// final executable.
    pub system_name: String,

    /// Value to return when the `system_version` RPC is called. Should be set to the version of
    /// the final executable.
    pub system_version: String,

    /// Hash of the genesis block of the chain.
    ///
    /// > **Note**: This can be derived from a [`chain_spec::ChainSpec`]. While the
    /// >           [`JsonRpcService::new`] function could in theory use the [`Config::chain_spec`]
    /// >           parameter to derive this value, doing so is quite expensive. We prefer to
    /// >           require this value from the upper layer instead, as it is most likely needed
    /// >           anyway.
    pub genesis_block_hash: [u8; 32],

    /// Hash of the storage trie root of the genesis block of the chain.
    ///
    /// > **Note**: This can be derived from a [`chain_spec::ChainSpec`]. While the
    /// >           [`JsonRpcService::new`] function could in theory use the [`Config::chain_spec`]
    /// >           parameter to derive this value, doing so is quite expensive. We prefer to
    /// >           require this value from the upper layer instead.
    pub genesis_block_state_root: [u8; 32],

    /// Maximum number of JSON-RPC requests that can be processed simultaneously.
    ///
    /// This parameter is necessary in order to prevent users from using up too much memory within
    /// the client.
    pub max_parallel_requests: NonZeroU32,

    /// Maximum number of JSON-RPC requests that can be added to a queue if it is not ready to be
    /// processed immediately. Any additional request will be immediately rejected.
    ///
    /// This parameter is necessary in order to prevent users from using up too much memory within
    /// the client.
    pub max_pending_requests: NonZeroU32,

    /// Maximum number of active subscriptions. Any additional subscription will be immediately
    /// rejected.
    ///
    /// This parameter is necessary in order to prevent users from using up too much memory within
    /// the client.
    pub max_subscriptions: u32,
}

pub struct JsonRpcService<TPlat: Platform> {
    /// State machine holding all the clients, requests, and subscriptions.
    ///
    /// Shared with the [`Background`].
    requests_subscriptions: Arc<requests_subscriptions::RequestsSubscriptions>,

    /// Identifier of the unique client within the [`JsonRpcService::requests_subscriptions`].
    client_id: requests_subscriptions::ClientId,

    /// Target to use when emitting logs.
    log_target: String,

    /// Pins the `TPlat` generic.
    platform: PhantomData<fn() -> TPlat>,
}

impl<TPlat: Platform> JsonRpcService<TPlat> {
    /// Creates a new JSON-RPC service with the given configuration.
    pub fn new(mut config: Config<'_, TPlat>) -> JsonRpcService<TPlat> {
        let mut requests_subscriptions =
            requests_subscriptions::RequestsSubscriptions::new(requests_subscriptions::Config {
                max_clients: 1,
                max_requests_per_client: config.max_pending_requests,
                max_subscriptions_per_client: config.max_subscriptions,
            });

        let client_id = requests_subscriptions.add_client_mut().unwrap(); // Adding a client can fail only if the limit is reached.
        let requests_subscriptions = Arc::new(requests_subscriptions);

        let log_target = format!("json-rpc-{}", config.log_name);
        let client = JsonRpcService {
            log_target: log_target.clone(),
            requests_subscriptions: requests_subscriptions.clone(),
            client_id: client_id.clone(),
            platform: PhantomData,
        };

        // Channel used in the background in order to spawn new tasks scoped to the background.
        let (new_child_tasks_tx, mut new_child_tasks_rx) = mpsc::unbounded();

        let background = Arc::new(Background {
            log_target,
            requests_subscriptions,
            client_id,
            new_child_tasks_tx: Mutex::new(new_child_tasks_tx),
            chain_name: config.chain_spec.name().to_owned(),
            chain_ty: config.chain_spec.chain_type().to_owned(),
            chain_is_live: config.chain_spec.has_live_network(),
            chain_properties_json: config.chain_spec.properties().to_owned(),
            peer_id_base58: config.peer_id.to_base58(),
            system_name: config.system_name,
            system_version: config.system_version,
            sync_service: config.sync_service,
            runtime_service: config.runtime_service,
            transactions_service: config.transactions_service,
            cache: Mutex::new(Cache {
                recent_pinned_blocks: lru::LruCache::with_hasher(32, Default::default()),
                subscription_id: None,
                block_state_root_hashes: lru::LruCache::with_hasher(32, Default::default()),
            }),
            genesis_block: config.genesis_block_hash,
            next_subscription_id: atomic::AtomicU64::new(0),
            subscriptions: Mutex::new(Subscriptions {
                misc: HashMap::with_capacity_and_hasher(
                    usize::try_from(config.max_subscriptions).unwrap_or(usize::max_value()),
                    Default::default(),
                ),
                chain_head_follow: HashMap::with_capacity_and_hasher(
                    usize::try_from(config.max_subscriptions).unwrap_or(usize::max_value()),
                    Default::default(),
                ),
            }),
        });

        // Spawns the background task that actually runs the logic of that JSON-RPC service.
        let max_parallel_requests = config.max_parallel_requests;
        (config.tasks_executor)(
            "json-rpc-service".into(),
            async move {
                let mut main_tasks = stream::FuturesUnordered::new();
                let mut secondary_tasks = stream::FuturesUnordered::new();

                main_tasks.push({
                    let background = background.clone();
                    let mut responses_sender = config.responses_sender;
                    async move {
                        loop {
                            let message = background
                                .requests_subscriptions
                                .next_response(&background.client_id)
                                .await;

                            log::debug!(
                                target: &background.log_target,
                                "JSON-RPC <= {}{}",
                                if message.len() > 100 {
                                    &message[..100]
                                } else {
                                    &message[..]
                                },
                                if message.len() > 100 { "…" } else { "" }
                            );

                            let _ = responses_sender.send(message).await;
                        }
                    }
                    .boxed()
                });

                for _ in 0..max_parallel_requests.get() {
                    let background = background.clone();
                    main_tasks.push(
                        async move {
                            // TODO: shut down task when foreground is closed
                            loop {
                                background.handle_request().await
                            }
                        }
                        .boxed(),
                    );
                }

                main_tasks.push(
                    async move {
                        loop {
                            let mut cache = background.cache.lock().await;

                            // Subscribe to new runtime service blocks in order to push them in the
                            // cache as soon as they are available.
                            let mut subscribe_all = background
                                .runtime_service
                                .subscribe_all(8, cache.recent_pinned_blocks.cap())
                                .await;

                            cache.subscription_id = Some(subscribe_all.new_blocks.id());
                            cache.recent_pinned_blocks.clear();
                            debug_assert!(cache.recent_pinned_blocks.cap() >= 1);

                            let finalized_block_hash = header::hash_from_scale_encoded_header(
                                &subscribe_all.finalized_block_scale_encoded_header,
                            );
                            cache.recent_pinned_blocks.put(
                                finalized_block_hash,
                                subscribe_all.finalized_block_scale_encoded_header,
                            );

                            for block in subscribe_all.non_finalized_blocks_ancestry_order {
                                if cache.recent_pinned_blocks.len()
                                    == cache.recent_pinned_blocks.cap()
                                {
                                    let (hash, _) = cache.recent_pinned_blocks.pop_lru().unwrap();
                                    subscribe_all.new_blocks.unpin_block(&hash).await;
                                }

                                let hash = header::hash_from_scale_encoded_header(
                                    &block.scale_encoded_header,
                                );
                                cache
                                    .recent_pinned_blocks
                                    .put(hash, block.scale_encoded_header);
                            }

                            drop(cache);

                            loop {
                                let notification = subscribe_all.new_blocks.next().await;
                                match notification {
                                    Some(runtime_service::Notification::Block(block)) => {
                                        let mut cache = background.cache.try_lock().unwrap();

                                        if cache.recent_pinned_blocks.len()
                                            == cache.recent_pinned_blocks.cap()
                                        {
                                            let (hash, _) =
                                                cache.recent_pinned_blocks.pop_lru().unwrap();
                                            subscribe_all.new_blocks.unpin_block(&hash).await;
                                        }

                                        let hash = header::hash_from_scale_encoded_header(
                                            &block.scale_encoded_header,
                                        );
                                        cache
                                            .recent_pinned_blocks
                                            .put(hash, block.scale_encoded_header);
                                    }
                                    Some(runtime_service::Notification::Finalized { .. }) => {}
                                    None => break,
                                }
                            }
                        }
                    }
                    .boxed(),
                );

                loop {
                    if main_tasks.is_empty() {
                        break;
                    }

                    futures::select! {
                        () = main_tasks.select_next_some() => {},
                        () = secondary_tasks.select_next_some() => {},
                        task = new_child_tasks_rx.next() => {
                            let task = task.unwrap();
                            secondary_tasks.push(task);
                        }
                    }
                }
            }
            .boxed(),
        );

        client
    }

    /// Queues the given JSON-RPC request to be processed in the background.
    ///
    /// An error is returned if [`Config::max_pending_requests`] is exceeded, which can happen
    /// if the requests take a long time to process or if the [`Config::responses_sender`] channel
    /// isn't polled often enough. Use [`HandleRpcError::into_json_rpc_error`] to build the
    /// JSON-RPC response to immediately send back to the user.
    pub fn queue_rpc_request(&mut self, json_rpc_request: String) -> Result<(), HandleRpcError> {
        log::debug!(
            target: &self.log_target,
            "JSON-RPC => {:?}{}",
            if json_rpc_request.len() > 100 {
                &json_rpc_request[..100]
            } else {
                &json_rpc_request[..]
            },
            if json_rpc_request.len() > 100 {
                "…"
            } else {
                ""
            }
        );

        match self
            .requests_subscriptions
            .try_queue_client_request(&self.client_id, json_rpc_request)
        {
            Ok(()) => Ok(()),
            Err(err) => {
                log::warn!(
                    target: &self.log_target,
                    "Request denied due to JSON-RPC service being overloaded. This will likely \
                    cause the JSON-RPC client to malfunction."
                );

                Err(HandleRpcError::Overloaded {
                    json_rpc_request: err.request,
                })
            }
        }
    }
}

/// Error potentially returned by [`JsonRpcService::queue_rpc_request`].
#[derive(Debug, derive_more::Display)]
pub enum HandleRpcError {
    /// The JSON-RPC service cannot process this request, as it is already too busy.
    #[display(
        fmt = "The JSON-RPC service cannot process this request, as it is already too busy."
    )]
    Overloaded {
        /// Value that was passed as parameter to [`JsonRpcService::queue_rpc_request`].
        json_rpc_request: String,
    },
}

impl HandleRpcError {
    /// Builds the JSON-RPC error string corresponding to this error.
    ///
    /// Returns `None` if the JSON-RPC requests isn't valid JSON-RPC or if the call was a
    /// notification.
    pub fn into_json_rpc_error(self) -> Option<String> {
        let HandleRpcError::Overloaded { json_rpc_request } = self;

        match json_rpc::parse::parse_call(&json_rpc_request) {
            Ok(call) => match call.id_json {
                Some(id) => Some(json_rpc::parse::build_error_response(
                    id,
                    json_rpc::parse::ErrorResponse::ServerError(-32000, "Too busy"),
                    None,
                )),
                None => None,
            },
            Err(_) => None,
        }
    }
}

/// Fields used to process JSON-RPC requests in the background.
struct Background<TPlat: Platform> {
    /// Target to use for all the logs.
    log_target: String,

    /// State machine holding all the clients, requests, and subscriptions.
    requests_subscriptions: Arc<requests_subscriptions::RequestsSubscriptions>,

    /// Identifier of the unique client within the [`Background::requests_subscriptions`].
    client_id: requests_subscriptions::ClientId,

    /// Whenever a task is sent on this channel, an executor runs it to completion.
    new_child_tasks_tx: Mutex<mpsc::UnboundedSender<future::BoxFuture<'static, ()>>>,

    /// Name of the chain, as found in the chain specification.
    chain_name: String,
    /// Type of chain, as found in the chain specification.
    chain_ty: String,
    /// JSON-encoded properties of the chain, as found in the chain specification.
    chain_properties_json: String,
    /// Whether the chain is a live network. Found in the chain specification.
    chain_is_live: bool,
    /// See [`Config::peer_id`]. The only use for this field is to send the base58 encoding of
    /// the [`PeerId`]. Consequently, we store the conversion to base58 ahead of time.
    peer_id_base58: String,
    /// Value to return when the `system_name` RPC is called.
    system_name: String,
    /// Value to return when the `system_version` RPC is called.
    system_version: String,

    /// See [`Config::sync_service`].
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    /// See [`Config::runtime_service`].
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    /// See [`Config::transactions_service`].
    transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,

    /// Various information caches about blocks, to potentially reduce the number of network
    /// requests to perform.
    cache: Mutex<Cache>,

    /// Hash of the genesis block.
    /// Keeping the genesis block is important, as the genesis block hash is included in
    /// transaction signatures, and must therefore be queried by upper-level UIs.
    genesis_block: [u8; 32],

    /// Identifier to use for the next subscription.
    ///
    /// Note that this is reasonable because we only have one single JSON-RPC client. In case of
    /// multiple clients, it might be unwise to have a linearly increasing counter shared between
    /// all clients, as it could leak to clients the information as to how many other clients are
    /// connected.
    next_subscription_id: atomic::AtomicU64,

    subscriptions: Mutex<Subscriptions>,
}

struct Subscriptions {
    /// For each active subscription (the key), an abort handle and the id of the subscription in
    /// the state machine. The abort handle is linked to the task dedicated to handling that
    /// subscription.
    misc: HashMap<
        (String, SubscriptionTy),
        (future::AbortHandle, requests_subscriptions::SubscriptionId),
        fnv::FnvBuildHasher,
    >,

    chain_head_follow: HashMap<String, FollowSubscription, fnv::FnvBuildHasher>,
}

struct FollowSubscription {
    /// Tree of hashes of all the current non-finalized blocks. This includes unpinned blocks.
    non_finalized_blocks: fork_tree::ForkTree<[u8; 32]>,

    /// For each pinned block hash, the SCALE-encoded header of the block.
    pinned_blocks_headers: HashMap<[u8; 32], Vec<u8>, fnv::FnvBuildHasher>,

    runtime_subscribe_all: Option<runtime_service::SubscriptionId>,

    abort_handle: future::AbortHandle,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum SubscriptionTy {
    AllHeads,
    NewHeads,
    FinalizedHeads,
    Storage,
    TransactionLegacy,
    Transaction,
    RuntimeSpec,
    ChainHeadBody,
    ChainHeadCall,
    ChainHeadStorage,
}

struct Cache {
    /// When the runtime service reports a new block, it is kept pinned and inserted in this LRU
    /// cache. When an entry in removed from the cache, it is unpinned.
    ///
    /// JSON-RPC clients are more likely to ask for information about recent blocks and perform
    /// calls on them, hence a cache of recent blocks.
    recent_pinned_blocks: lru::LruCache<[u8; 32], Vec<u8>, fnv::FnvBuildHasher>,

    /// Subscription on the runtime service under which the blocks of
    /// [`Cache::recent_pinned_blocks`] are pinned.
    ///
    /// Contains `None` only at initialization, in which case [`Cache::recent_pinned_blocks`]
    /// is guaranteed to be empty. In other words, if a block is found in
    /// [`Cache::recent_pinned_blocks`] then this field is guaranteed to be `Some`.
    subscription_id: Option<runtime_service::SubscriptionId>,

    /// State trie root hashes of blocks that were not in [`Cache::recent_pinned_blocks`].
    ///
    /// The state trie root hash can also be an `Err` if the network request failed or if the
    /// header is of an invalid format.
    ///
    /// The state trie root hash is wrapped in a `Shared` future. When multiple requests need the
    /// state trie root hash of the same block, it is only queried once and the query is
    /// inserted in the cache while in progress. This way, the multiple requests can all wait on
    /// that single future.
    ///
    /// Most of the time, the JSON-RPC client will query blocks that are found in
    /// [`Cache::recent_pinned_blocks`], but occasionally it will query older blocks. When the
    /// storage of an older block is queried, it is common for the JSON-RPC client to make several
    /// storage requests to that same old block. In order to avoid having to retrieve the state
    /// trie root hash multiple, we store these hashes in this LRU cache.
    block_state_root_hashes: lru::LruCache<
        [u8; 32],
        future::MaybeDone<future::Shared<future::BoxFuture<'static, Result<[u8; 32], ()>>>>,
        fnv::FnvBuildHasher,
    >,
}

impl<TPlat: Platform> Background<TPlat> {
    async fn handle_request(self: &Arc<Self>) {
        let (json_rpc_request, state_machine_request_id) =
            self.requests_subscriptions.next_request().await;

        // Check whether the JSON-RPC request is correct, and bail out if it isn't.
        let (request_id, call) = match methods::parse_json_call(&json_rpc_request) {
            Ok((request_id, call)) => {
                log::debug!(target: &self.log_target, "Handler <= Request(id_json={:?})", request_id);
                (request_id, call)
            }
            Err(methods::ParseError::Method { request_id, error }) => {
                log::warn!(
                    target: &self.log_target,
                    "Error in JSON-RPC method call: {}", error
                );
                self.requests_subscriptions
                    .respond(&state_machine_request_id, error.to_json_error(request_id))
                    .await;
                return;
            }
            Err(error) => {
                log::warn!(
                    target: &self.log_target,
                    "Ignoring malformed JSON-RPC call: {}", error
                );
                return;
            }
        };

        // Most calls are handled directly in this method's body. The most voluminous (in terms
        // of lines of code) have their dedicated methods.
        match call {
            methods::MethodCall::author_pendingExtrinsics {} => {
                // TODO: ask transactions service
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::author_pendingExtrinsics(Vec::new())
                            .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::author_submitExtrinsic { transaction } => {
                // Note that this function is misnamed. It should really be called
                // "author_submitTransaction".

                // In Substrate, `author_submitExtrinsic` returns the hash of the transaction. It
                // is unclear whether it has to actually be the hash of the transaction or if it
                // could be any opaque value. Additionally, there isn't any other JSON-RPC method
                // that accepts as parameter the value returned here. When in doubt, we return
                // the hash as well.
                let mut hash_context = blake2_rfc::blake2b::Blake2b::new(32);
                hash_context.update(&transaction.0);
                let mut transaction_hash: [u8; 32] = Default::default();
                transaction_hash.copy_from_slice(hash_context.finalize().as_bytes());

                // Send the transaction to the transactions service. It will be sent to the
                // rest of the network asynchronously.
                self.transactions_service
                    .submit_transaction(transaction.0)
                    .await;

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::author_submitExtrinsic(methods::HashHexString(
                            transaction_hash,
                        ))
                        .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::author_submitAndWatchExtrinsic { transaction } => {
                self.submit_and_watch_transaction(
                    request_id,
                    &state_machine_request_id,
                    transaction,
                    true,
                )
                .await
            }
            methods::MethodCall::author_unwatchExtrinsic { subscription } => {
                let state_machine_subscription =
                    if let Some((abort_handle, state_machine_subscription)) = self
                        .subscriptions
                        .lock()
                        .await
                        .misc
                        .remove(&(subscription.to_owned(), SubscriptionTy::TransactionLegacy))
                    {
                        abort_handle.abort();
                        Some(state_machine_subscription)
                    } else {
                        None
                    };

                if let Some(state_machine_subscription) = &state_machine_subscription {
                    self.requests_subscriptions
                        .stop_subscription(state_machine_subscription)
                        .await;
                }

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::author_unwatchExtrinsic(
                            state_machine_subscription.is_some(),
                        )
                        .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::chain_getBlock { hash } => {
                // `hash` equal to `None` means "the current best block".
                let hash = match hash {
                    Some(h) => h.0,
                    None => header::hash_from_scale_encoded_header(&self.runtime_service.subscribe_best().await.0),
                };

                // Block bodies and justifications aren't stored locally. Ask the network.
                let result = self
                    .sync_service
                    .clone()
                    .block_query(
                        hash,
                        protocol::BlocksRequestFields {
                            header: true,
                            body: true,
                            justifications: true,
                        },
                    )
                    .await;

                // The `block_query` function guarantees that the header and body are present and
                // are correct.

                let response = if let Ok(block) = result {
                    methods::Response::chain_getBlock(methods::Block {
                        extrinsics: block
                            .body
                            .unwrap()
                            .into_iter()
                            .map(methods::HexString)
                            .collect(),
                        header: methods::Header::from_scale_encoded_header(&block.header.unwrap())
                            .unwrap(),
                        justifications: block.justifications,
                    })
                    .to_json_response(request_id)
                } else {
                    json_rpc::parse::build_success_response(request_id, "null")
                };

                self.requests_subscriptions
                    .respond(&state_machine_request_id, response)
                    .await;
            }
            methods::MethodCall::chain_getBlockHash { height } => {
                self.get_block_hash(request_id, &state_machine_request_id, height)
                    .await;
            }
            methods::MethodCall::chain_getFinalizedHead {} => {
                // TODO: maybe optimize?
                let response = methods::Response::chain_getFinalizedHead(methods::HashHexString(
                    header::hash_from_scale_encoded_header(&self.runtime_service.subscribe_finalized().await.0),
                ))
                .to_json_response(request_id);

                self.requests_subscriptions
                    .respond(&state_machine_request_id, response)
                    .await;
            }
            methods::MethodCall::chain_getHeader { hash } => {
                let hash = match hash {
                    Some(h) => h.0,
                    None => header::hash_from_scale_encoded_header(&self.runtime_service.subscribe_best().await.0),
                };

                let fut = self.header_query(&hash);
                let header = fut.await;
                let response = match header {
                    Ok(header) => {
                        // In the case of a parachain, it is possible for the header to be in
                        // a format that smoldot isn't capable of parsing. In that situation,
                        // we take of liberty of returning a JSON-RPC error.
                        match methods::Header::from_scale_encoded_header(&header) {
                            Ok(decoded) => methods::Response::chain_getHeader(decoded)
                                .to_json_response(request_id),
                            Err(error) => json_rpc::parse::build_error_response(
                                request_id,
                                json_rpc::parse::ErrorResponse::ServerError(
                                    -32000,
                                    &format!("Failed to decode header: {}", error),
                                ),
                                None,
                            ),
                        }
                    }
                    Err(()) => {
                        // Failed to retreive the header.
                        // TODO: error or null?
                        json_rpc::parse::build_success_response(request_id, "null")
                    }
                };

                self.requests_subscriptions
                    .respond(&state_machine_request_id, response)
                    .await;
            }
            methods::MethodCall::chain_subscribeAllHeads {} => {
                self.subscribe_all_heads(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::chain_subscribeFinalizedHeads {} => {
                self.subscribe_finalized_heads(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::chain_subscribeNewHeads {} => {
                self.subscribe_new_heads(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::chain_unsubscribeAllHeads { subscription } => {
                let state_machine_subscription =
                    if let Some((abort_handle, state_machine_subscription)) = self
                        .subscriptions
                        .lock()
                        .await
                        .misc
                        .remove(&(subscription.to_owned(), SubscriptionTy::AllHeads))
                    {
                        abort_handle.abort();
                        Some(state_machine_subscription)
                    } else {
                        None
                    };

                if let Some(state_machine_subscription) = &state_machine_subscription {
                    self.requests_subscriptions
                        .stop_subscription(state_machine_subscription)
                        .await;
                }

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chain_unsubscribeAllHeads(
                            state_machine_subscription.is_some(),
                        )
                        .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription } => {
                let state_machine_subscription =
                    if let Some((abort_handle, state_machine_subscription)) = self
                        .subscriptions
                        .lock()
                        .await
                        .misc
                        .remove(&(subscription.to_owned(), SubscriptionTy::FinalizedHeads))
                    {
                        abort_handle.abort();
                        Some(state_machine_subscription)
                    } else {
                        None
                    };

                if let Some(state_machine_subscription) = &state_machine_subscription {
                    self.requests_subscriptions
                        .stop_subscription(state_machine_subscription)
                        .await;
                }

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chain_unsubscribeFinalizedHeads(
                            state_machine_subscription.is_some(),
                        )
                        .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::chain_unsubscribeNewHeads { subscription } => {
                let state_machine_subscription =
                    if let Some((abort_handle, state_machine_subscription)) = self
                        .subscriptions
                        .lock()
                        .await
                        .misc
                        .remove(&(subscription.to_owned(), SubscriptionTy::NewHeads))
                    {
                        abort_handle.abort();
                        Some(state_machine_subscription)
                    } else {
                        None
                    };

                if let Some(state_machine_subscription) = &state_machine_subscription {
                    self.requests_subscriptions
                        .stop_subscription(state_machine_subscription)
                        .await;
                }

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chain_unsubscribeNewHeads(
                            state_machine_subscription.is_some(),
                        )
                        .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::payment_queryInfo { extrinsic, hash } => {
                assert!(hash.is_none()); // TODO: handle when hash != None

                let response = match payment_query_info(&self.runtime_service, &extrinsic.0).await {
                    Ok(info) => {
                        methods::Response::payment_queryInfo(info).to_json_response(request_id)
                    }
                    Err(error) => json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                        None,
                    ),
                };

                self.requests_subscriptions
                    .respond(&state_machine_request_id, response)
                    .await;
            }
            methods::MethodCall::rpc_methods {} => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::rpc_methods(methods::RpcMethods {
                            version: 1,
                            methods: methods::MethodCall::method_names()
                                .map(|n| n.into())
                                .collect(),
                        })
                        .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::state_getKeysPaged {
                prefix,
                count,
                start_key,
                hash,
            } => {
                assert!(hash.is_none()); // TODO: not implemented

                let block_hash = header::hash_from_scale_encoded_header(&self.runtime_service.subscribe_best().await.0);

                let mut cache = self.cache.lock().await;
                let (state_root, block_number) = {
                    // TODO: no /!\
                    let block = cache.recent_pinned_blocks.get(&block_hash).unwrap();
                    match header::decode(block) {
                        Ok(d) => (*d.state_root, d.number),
                        Err(_) => {
                            json_rpc::parse::build_error_response(
                                request_id,
                                json_rpc::parse::ErrorResponse::ServerError(
                                    -32000,
                                    "Failed to decode block header",
                                ),
                                None,
                            );
                            return;
                        }
                    }
                };
                drop(cache);

                let outcome = self
                    .sync_service
                    .clone()
                    .storage_prefix_keys_query(
                        block_number,
                        &block_hash,
                        &prefix.unwrap().0, // TODO: don't unwrap! what is this Option?
                        &state_root,
                    )
                    .await;

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        match outcome {
                            Ok(keys) => {
                                // TODO: instead of requesting all keys with that prefix from the network, pass `start_key` to the network service
                                let out = keys
                                    .into_iter()
                                    .filter(|k| {
                                        start_key.as_ref().map_or(true, |start| k >= &start.0)
                                    }) // TODO: not sure if start should be in the set or not?
                                    .map(methods::HexString)
                                    .take(usize::try_from(count).unwrap_or(usize::max_value()))
                                    .collect::<Vec<_>>();
                                methods::Response::state_getKeysPaged(out)
                                    .to_json_response(request_id)
                            }
                            Err(error) => json_rpc::parse::build_error_response(
                                request_id,
                                json_rpc::parse::ErrorResponse::ServerError(
                                    -32000,
                                    &error.to_string(),
                                ),
                                None,
                            ),
                        },
                    )
                    .await;
            }
            methods::MethodCall::state_queryStorageAt { keys, at } => {
                let best_block= header::hash_from_scale_encoded_header(&self.runtime_service.subscribe_best().await.0);

                let cache = self.cache.lock().await;

                let at = at.as_ref().map(|h| h.0).unwrap_or(best_block);

                // TODO: have no idea what this describes actually
                let mut out = methods::StorageChangeSet {
                    block: methods::HashHexString(best_block),
                    changes: Vec::new(),
                };

                drop(cache);

                let fut = self.storage_query(keys.iter(), &at);
                if let Ok(values) = fut.await {
                    for (value, key) in values.into_iter().zip(keys) {
                        out.changes.push((key, value.map(methods::HexString)));
                    }
                }

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::state_queryStorageAt(vec![out])
                            .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::state_getMetadata { hash } => {
                let result = if let Some(hash) = hash {
                    self.runtime_service.clone().metadata(&hash.0).await
                } else {
                    self.runtime_service.clone().best_block_metadata().await
                };

                let response = match result {
                    Ok(metadata) => {
                        methods::Response::state_getMetadata(methods::HexString(metadata))
                            .to_json_response(request_id)
                    }
                    Err(error) => {
                        log::warn!(
                            target: &self.log_target,
                            "Returning error from `state_getMetadata`. \
                            API user might not function properly. Error: {}",
                            error
                        );
                        json_rpc::parse::build_error_response(
                            request_id,
                            json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                            None,
                        )
                    }
                };

                self.requests_subscriptions
                    .respond(&state_machine_request_id, response)
                    .await;
            }
            methods::MethodCall::state_getStorage { key, hash } => {
                let hash = hash
                    .as_ref()
                    .map(|h| h.0)
                    .unwrap_or(header::hash_from_scale_encoded_header(&self.runtime_service.subscribe_best().await.0));

                let fut = self.storage_query(iter::once(&key.0), &hash);
                let response = fut.await;
                let response = match response.map(|mut r| r.pop().unwrap()) {
                    Ok(Some(value)) => {
                        methods::Response::state_getStorage(methods::HexString(value.to_owned())) // TODO: overhead
                            .to_json_response(request_id)
                    }
                    Ok(None) => json_rpc::parse::build_success_response(request_id, "null"),
                    Err(error) => json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                        None,
                    ),
                };

                self.requests_subscriptions
                    .respond(&state_machine_request_id, response)
                    .await;
            }
            methods::MethodCall::state_subscribeRuntimeVersion {} => {
                let state_machine_subscription = match self
                    .requests_subscriptions
                    .start_subscription(&state_machine_request_id, 1)
                    .await
                {
                    Ok(v) => v,
                    Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                        self.requests_subscriptions
                            .respond(
                                &state_machine_request_id,
                                json_rpc::parse::build_error_response(
                                    request_id,
                                    json_rpc::parse::ErrorResponse::ServerError(
                                        -32000,
                                        "Too many active subscriptions",
                                    ),
                                    None,
                                ),
                            )
                            .await;
                        return;
                    }
                };

                let subscription_id = self
                    .next_subscription_id
                    .fetch_add(1, atomic::Ordering::Relaxed)
                    .to_string();

                let abort_registration = {
                    let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
                    let mut subscriptions_list = self.subscriptions.lock().await;
                    subscriptions_list.misc.insert(
                        (subscription_id.clone(), SubscriptionTy::RuntimeSpec),
                        (abort_handle, state_machine_subscription.clone()),
                    );
                    abort_registration
                };

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::state_subscribeRuntimeVersion(&subscription_id)
                            .to_json_response(request_id),
                    )
                    .await;

                let task = {
                    let me = self.clone();
                    async move {
                        let (current_spec, spec_changes) =
                            me.runtime_service.subscribe_runtime_version().await;
                        let spec_changes =
                            stream::iter(iter::once(current_spec)).chain(spec_changes);
                        futures::pin_mut!(spec_changes);

                        loop {
                            let new_runtime = spec_changes.next().await;
                            let notification_body = if let Ok(runtime_spec) = new_runtime.unwrap() {
                                let runtime_spec = runtime_spec.decode();
                                methods::ServerToClient::state_runtimeVersion {
                                    subscription: &subscription_id,
                                    result: Some(methods::RuntimeVersion {
                                        spec_name: runtime_spec.spec_name.into(),
                                        impl_name: runtime_spec.impl_name.into(),
                                        authoring_version: u64::from(
                                            runtime_spec.authoring_version,
                                        ),
                                        spec_version: u64::from(runtime_spec.spec_version),
                                        impl_version: u64::from(runtime_spec.impl_version),
                                        transaction_version: runtime_spec
                                            .transaction_version
                                            .map(u64::from),
                                        apis: runtime_spec
                                            .apis
                                            .map(|api| {
                                                (
                                                    methods::HexString(api.name_hash.to_vec()),
                                                    api.version,
                                                )
                                            })
                                            .collect(),
                                    }),
                                }
                                .to_json_call_object_parameters(None)
                            } else {
                                methods::ServerToClient::state_runtimeVersion {
                                    subscription: &subscription_id,
                                    result: None,
                                }
                                .to_json_call_object_parameters(None)
                            };

                            me.requests_subscriptions
                                .set_queued_notification(
                                    &state_machine_subscription,
                                    0,
                                    notification_body,
                                )
                                .await;
                        }
                    }
                };

                self.new_child_tasks_tx
                    .lock()
                    .await
                    .unbounded_send(Box::pin(
                        future::Abortable::new(task, abort_registration).map(|_| ()),
                    ))
                    .unwrap();
            }
            methods::MethodCall::state_unsubscribeRuntimeVersion { subscription } => {
                let state_machine_subscription =
                    if let Some((abort_handle, state_machine_subscription)) = self
                        .subscriptions
                        .lock()
                        .await
                        .misc
                        .remove(&(subscription.to_owned(), SubscriptionTy::RuntimeSpec))
                    {
                        abort_handle.abort();
                        Some(state_machine_subscription)
                    } else {
                        None
                    };

                if let Some(state_machine_subscription) = &state_machine_subscription {
                    self.requests_subscriptions
                        .stop_subscription(state_machine_subscription)
                        .await;
                }

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::state_unsubscribeRuntimeVersion(
                            state_machine_subscription.is_some(),
                        )
                        .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::state_subscribeStorage { list } => {
                if list.is_empty() {
                    // When the list of keys is empty, that means we want to subscribe to *all*
                    // storage changes. It is not possible to reasonably implement this in a
                    // light client.
                    self.requests_subscriptions
                        .respond(
                            &state_machine_request_id,
                            json_rpc::parse::build_error_response(
                                request_id,
                                json_rpc::parse::ErrorResponse::ServerError(
                                    -32000,
                                    "Subscribing to all storage changes isn't supported",
                                ),
                                None,
                            ),
                        )
                        .await;
                } else {
                    self.subscribe_storage(request_id, &state_machine_request_id, list)
                        .await;
                }
            }
            methods::MethodCall::state_unsubscribeStorage { subscription } => {
                let state_machine_subscription =
                    if let Some((abort_handle, state_machine_subscription)) = self
                        .subscriptions
                        .lock()
                        .await
                        .misc
                        .remove(&(subscription.to_owned(), SubscriptionTy::Storage))
                    {
                        abort_handle.abort();
                        Some(state_machine_subscription)
                    } else {
                        None
                    };

                if let Some(state_machine_subscription) = &state_machine_subscription {
                    self.requests_subscriptions
                        .stop_subscription(state_machine_subscription)
                        .await;
                }

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::state_unsubscribeStorage(
                            state_machine_subscription.is_some(),
                        )
                        .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::state_getRuntimeVersion { at } => {
                let runtime_spec = if let Some(at) = at {
                    self.runtime_service.runtime_version_of_block(&at.0).await
                } else {
                    self.runtime_service
                        .best_block_runtime()
                        .await
                        .map_err(runtime_service::RuntimeCallError::InvalidRuntime)
                };

                let response = match runtime_spec {
                    Ok(runtime_spec) => {
                        let runtime_spec = runtime_spec.decode();
                        methods::Response::state_getRuntimeVersion(methods::RuntimeVersion {
                            spec_name: runtime_spec.spec_name.into(),
                            impl_name: runtime_spec.impl_name.into(),
                            authoring_version: u64::from(runtime_spec.authoring_version),
                            spec_version: u64::from(runtime_spec.spec_version),
                            impl_version: u64::from(runtime_spec.impl_version),
                            transaction_version: runtime_spec.transaction_version.map(u64::from),
                            apis: runtime_spec
                                .apis
                                .map(|api| {
                                    (methods::HexString(api.name_hash.to_vec()), api.version)
                                })
                                .collect(),
                        })
                        .to_json_response(request_id)
                    }
                    Err(error) => json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                        None,
                    ),
                };

                self.requests_subscriptions
                    .respond(&state_machine_request_id, response)
                    .await;
            }
            methods::MethodCall::system_accountNextIndex { account } => {
                let response = match account_nonce(&self.runtime_service, account).await {
                    Ok(nonce) => {
                        // TODO: we get a u32 when expecting a u64; figure out problem
                        // TODO: don't unwrap
                        let index = u32::from_le_bytes(<[u8; 4]>::try_from(&nonce[..]).unwrap());
                        methods::Response::system_accountNextIndex(u64::from(index))
                            .to_json_response(request_id)
                    }
                    Err(error) => json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                        None,
                    ),
                };

                self.requests_subscriptions
                    .respond(&state_machine_request_id, response)
                    .await;
            }
            methods::MethodCall::system_chain {} => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::system_chain(&self.chain_name)
                            .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::system_chainType {} => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::system_chainType(&self.chain_ty)
                            .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::system_health {} => {
                let response = methods::Response::system_health(methods::SystemHealth {
                    // In smoldot, `is_syncing` equal to `false` means that GrandPa warp sync
                    // is finished and that the block notifications report blocks that are
                    // believed to be near the head of the chain.
                    is_syncing: !self.runtime_service.is_near_head_of_chain_heuristic().await,
                    peers: u64::try_from(self.sync_service.syncing_peers().await.len())
                        .unwrap_or(u64::max_value()),
                    should_have_peers: self.chain_is_live,
                })
                .to_json_response(request_id);

                self.requests_subscriptions
                    .respond(&state_machine_request_id, response)
                    .await;
            }
            methods::MethodCall::system_localListenAddresses {} => {
                // Wasm node never listens on any address.
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::system_localListenAddresses(Vec::new())
                            .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::system_localPeerId {} => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::system_localPeerId(&self.peer_id_base58)
                            .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::system_name {} => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::system_name(&self.system_name)
                            .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::system_peers {} => {
                let response = methods::Response::system_peers(
                    self.sync_service
                        .syncing_peers()
                        .await
                        .map(
                            |(peer_id, role, best_number, best_hash)| methods::SystemPeer {
                                peer_id: peer_id.to_string(),
                                roles: match role {
                                    protocol::Role::Authority => methods::SystemPeerRole::Authority,
                                    protocol::Role::Full => methods::SystemPeerRole::Full,
                                    protocol::Role::Light => methods::SystemPeerRole::Light,
                                },
                                best_hash: methods::HashHexString(best_hash),
                                best_number,
                            },
                        )
                        .collect(),
                )
                .to_json_response(request_id);

                self.requests_subscriptions
                    .respond(&state_machine_request_id, response)
                    .await;
            }
            methods::MethodCall::system_properties {} => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::system_properties(
                            serde_json::from_str(&self.chain_properties_json).unwrap(),
                        )
                        .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::system_version {} => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::system_version(&self.system_version)
                            .to_json_response(request_id),
                    )
                    .await;
            }

            methods::MethodCall::chainHead_unstable_stopBody { subscription_id } => {
                let state_machine_subscription =
                    if let Some((abort_handle, state_machine_subscription)) = self
                        .subscriptions
                        .lock()
                        .await
                        .misc
                        .remove(&(subscription_id.to_owned(), SubscriptionTy::ChainHeadBody))
                    {
                        abort_handle.abort();
                        Some(state_machine_subscription)
                    } else {
                        None
                    };

                if let Some(state_machine_subscription) = &state_machine_subscription {
                    self.requests_subscriptions
                        .stop_subscription(state_machine_subscription)
                        .await;
                }

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainHead_unstable_stopBody(())
                            .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::chainHead_unstable_body {
                follow_subscription_id,
                hash,
                .. // TODO: network_config
            } => {
                // Determine whether the requested block hash is valid.
                let block_is_valid = {
                    let lock = self.subscriptions.lock().await;
                    if let Some(subscription) = lock.chain_head_follow.get(follow_subscription_id) {
                        if !subscription.pinned_blocks_headers.contains_key(&hash.0) {
                            self.requests_subscriptions
                                .respond(
                                    &state_machine_request_id,
                                    json_rpc::parse::build_error_response(
                                        request_id,
                                        json_rpc::parse::ErrorResponse::InvalidParams,
                                        None,
                                    ),
                                )
                                .await;
                            return;
                        }

                        true
                    } else {
                        false
                    }
                };

                let state_machine_subscription = match self
                    .requests_subscriptions
                    .start_subscription(&state_machine_request_id, 1)
                    .await
                {
                    Ok(v) => v,
                    Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                        self.requests_subscriptions
                            .respond(
                                &state_machine_request_id,
                                json_rpc::parse::build_error_response(
                                    request_id,
                                    json_rpc::parse::ErrorResponse::ServerError(
                                        -32000,
                                        "Too many active subscriptions",
                                    ),
                                    None,
                                ),
                            )
                            .await;
                        return;
                    }
                };

                let subscription_id = self
                    .next_subscription_id
                    .fetch_add(1, atomic::Ordering::Relaxed)
                    .to_string();

                let abort_registration = {
                    let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
                    let mut subscriptions_list = self.subscriptions.lock().await;
                    subscriptions_list.misc.insert(
                        (subscription_id.clone(), SubscriptionTy::ChainHeadBody),
                        (abort_handle, state_machine_subscription.clone()),
                    );
                    abort_registration
                };

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainHead_unstable_body(&subscription_id)
                            .to_json_response(request_id),
                    )
                    .await;

                let task = {
                    let me = self.clone();
                    async move {
                        let response = if block_is_valid {
                            // TODO: right now we query the header because the underlying function returns an error if we don't
                            let response = me.sync_service.clone()
                                .block_query(hash.0, protocol::BlocksRequestFields { header: true, body: true, justifications: false  }).await;
                            match response {
                                Ok(block_data) => {
                                    methods::ServerToClient::chainHead_unstable_bodyEvent {
                                        subscription: &subscription_id,
                                        result: methods::ChainHeadBodyEvent::Done {
                                            value: block_data.body.unwrap()
                                                .into_iter()
                                                .map(methods::HexString)
                                                .collect()
                                        },
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                                Err(()) => {
                                    methods::ServerToClient::chainHead_unstable_bodyEvent {
                                        subscription: &subscription_id,
                                        result: methods::ChainHeadBodyEvent::Inaccessible {},
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                            }
                        } else {
                            methods::ServerToClient::chainHead_unstable_bodyEvent {
                                subscription: &subscription_id,
                                result: methods::ChainHeadBodyEvent::Disjoint {},
                            }
                            .to_json_call_object_parameters(None)
                        };

                        me.requests_subscriptions.set_queued_notification(&state_machine_subscription, 0, response).await;

                        me.requests_subscriptions.stop_subscription(&state_machine_subscription).await;
                        let _ = me.subscriptions.lock().await.misc
                            .remove(&(subscription_id.to_owned(), SubscriptionTy::ChainHeadBody));
                    }
                };

                self.new_child_tasks_tx
                    .lock()
                    .await
                    .unbounded_send(Box::pin(
                        future::Abortable::new(task, abort_registration).map(|_| ()),
                    ))
                    .unwrap();
            }
            methods::MethodCall::chainHead_unstable_call {
                follow_subscription_id,
                hash,
                function,
                call_parameters,
                .. // TODO: network_config
            } => {
                self.chain_head_call(request_id, &state_machine_request_id, follow_subscription_id, hash, function, call_parameters).await;
            }
            methods::MethodCall::chainHead_unstable_stopCall { subscription_id } => {
                let state_machine_subscription =
                    if let Some((abort_handle, state_machine_subscription)) = self
                        .subscriptions
                        .lock()
                        .await
                        .misc
                        .remove(&(subscription_id.to_owned(), SubscriptionTy::ChainHeadCall))
                    {
                        abort_handle.abort();
                        Some(state_machine_subscription)
                    } else {
                        None
                    };

                if let Some(state_machine_subscription) = &state_machine_subscription {
                    self.requests_subscriptions
                        .stop_subscription(state_machine_subscription)
                        .await;
                }

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainHead_unstable_stopCall(())
                            .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::chainHead_unstable_stopStorage { subscription_id } => {
                let state_machine_subscription =
                    if let Some((abort_handle, state_machine_subscription)) = self
                        .subscriptions
                        .lock()
                        .await
                        .misc
                        .remove(&(subscription_id.to_owned(), SubscriptionTy::ChainHeadStorage))
                    {
                        abort_handle.abort();
                        Some(state_machine_subscription)
                    } else {
                        None
                    };

                if let Some(state_machine_subscription) = &state_machine_subscription {
                    self.requests_subscriptions
                        .stop_subscription(state_machine_subscription)
                        .await;
                }

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainHead_unstable_stopStorage(())
                            .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::chainHead_unstable_storage {
                follow_subscription_id,
                hash,
                key,
                child_key,
                r#type: ty,
                .. // TODO: network_config
            } => {
                self.chain_head_storage(request_id, &state_machine_request_id, follow_subscription_id, hash, key, child_key, ty).await;
            }
            methods::MethodCall::chainHead_unstable_follow { runtime_updates } => {
                self.chain_head_follow(request_id, &state_machine_request_id, runtime_updates)
                    .await;
            }
            methods::MethodCall::chainHead_unstable_genesisHash {} => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainHead_unstable_genesisHash(methods::HashHexString(
                            self.genesis_block,
                        ))
                        .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::chainHead_unstable_header {
                follow_subscription_id,
                hash,
            } => {
                let response = {
                    let lock = self.subscriptions.lock().await;
                    if let Some(subscription) = lock.chain_head_follow.get(follow_subscription_id) {
                        subscription
                            .pinned_blocks_headers
                            .get(&hash.0)
                            .cloned()
                            .map(Some)
                    } else {
                        Some(None)
                    }
                };

                if let Some(response) = response {
                    self.requests_subscriptions
                        .respond(
                            &state_machine_request_id,
                            methods::Response::chainHead_unstable_header(
                                response.map(methods::HexString),
                            )
                            .to_json_response(request_id),
                        )
                        .await;
                } else {
                    // Reached if the subscription is valid but the block couldn't be found in
                    // `pinned_blocks_headers`.
                    self.requests_subscriptions
                        .respond(
                            &state_machine_request_id,
                            json_rpc::parse::build_error_response(
                                request_id,
                                json_rpc::parse::ErrorResponse::InvalidParams,
                                None,
                            ),
                        )
                        .await;
                }
            }
            methods::MethodCall::chainHead_unstable_unpin {
                follow_subscription_id,
                hash,
            } => {
                let valid = {
                    let mut lock = self.subscriptions.lock().await;
                    if let Some(subscription) =
                        lock.chain_head_follow.get_mut(follow_subscription_id)
                    {
                        if subscription.pinned_blocks_headers.remove(&hash.0).is_some() {
                            if let Some(runtime_subscribe_all) = subscription.runtime_subscribe_all {
                                self.runtime_service.unpin_block(runtime_subscribe_all, &hash.0).await;
                            }
                            true
                        } else {
                            false
                        }
                    } else {
                        true
                    }
                };

                if valid {
                    self.requests_subscriptions
                        .respond(
                            &state_machine_request_id,
                            methods::Response::chainHead_unstable_unpin(())
                                .to_json_response(request_id),
                        )
                        .await;
                } else {
                    self.requests_subscriptions
                        .respond(
                            &state_machine_request_id,
                            json_rpc::parse::build_error_response(
                                request_id,
                                json_rpc::parse::ErrorResponse::InvalidParams,
                                None,
                            ),
                        )
                        .await;
                }
            }
            methods::MethodCall::chainHead_unstable_unfollow {
                follow_subscription_id,
            } => {
                if let Some(subscription) = self
                    .subscriptions
                    .lock()
                    .await
                    .chain_head_follow
                    .remove(follow_subscription_id)
                {
                    subscription.abort_handle.abort();
                }

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainHead_unstable_unfollow(())
                            .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::chainSpec_unstable_chainName {} => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainSpec_unstable_chainName(&self.chain_name)
                            .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::chainSpec_unstable_genesisHash {} => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainSpec_unstable_genesisHash(methods::HashHexString(
                            self.genesis_block,
                        ))
                        .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::chainSpec_unstable_properties {} => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainSpec_unstable_properties(
                            serde_json::from_str(&self.chain_properties_json).unwrap(),
                        )
                        .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::sudo_unstable_p2pDiscover { multiaddr } => {
                let response = match multiaddr.parse::<multiaddr::Multiaddr>() {
                    Ok(addr)
                        if matches!(addr.iter().last(), Some(multiaddr::ProtocolRef::P2p(_))) =>
                    {
                        // TODO: actually use address
                        methods::Response::sudo_unstable_p2pDiscover(())
                            .to_json_response(request_id)
                    }
                    Ok(_) => json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        Some(&serde_json::to_string("multiaddr doesn't end with /p2p").unwrap()),
                    ),
                    Err(err) => json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        Some(&serde_json::to_string(&err.to_string()).unwrap()),
                    ),
                };

                self.requests_subscriptions
                    .respond(&state_machine_request_id, response)
                    .await;
            }
            methods::MethodCall::sudo_unstable_version {} => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::sudo_unstable_version(&format!(
                            "{} {}",
                            self.system_name, self.system_version
                        ))
                        .to_json_response(request_id),
                    )
                    .await;
            }
            methods::MethodCall::transaction_unstable_submitAndWatch { transaction } => {
                self.submit_and_watch_transaction(
                    request_id,
                    &state_machine_request_id,
                    transaction,
                    false,
                )
                .await
            }
            methods::MethodCall::transaction_unstable_unwatch { subscription } => {
                let state_machine_subscription =
                    if let Some((abort_handle, state_machine_subscription)) = self
                        .subscriptions
                        .lock()
                        .await
                        .misc
                        .remove(&(subscription.to_owned(), SubscriptionTy::Transaction))
                    {
                        abort_handle.abort();
                        Some(state_machine_subscription)
                    } else {
                        None
                    };

                if let Some(state_machine_subscription) = &state_machine_subscription {
                    self.requests_subscriptions
                        .stop_subscription(state_machine_subscription)
                        .await;
                }

                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::transaction_unstable_unwatch(())
                            .to_json_response(request_id),
                    )
                    .await;
            }

            _method => {
                log::error!(target: &self.log_target, "JSON-RPC call not supported yet: {:?}", _method);
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        json_rpc::parse::build_error_response(
                            request_id,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Not implemented in smoldot yet",
                            ),
                            None,
                        ),
                    )
                    .await;
            }
        }
    }

    /// Handles a call to [`methods::MethodCall::author_submitAndWatchExtrinsic`] (if `is_legacy`
    /// is `true`) or to [`methods::MethodCall::transaction_unstable_submitAndWatch`] (if
    /// `is_legacy` is `false`).
    async fn submit_and_watch_transaction(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        transaction: methods::HexString,
        is_legacy: bool,
    ) {
        let state_machine_subscription = match self
            .requests_subscriptions
            .start_subscription(state_machine_request_id, 16)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                self.requests_subscriptions
                    .respond(
                        state_machine_request_id,
                        json_rpc::parse::build_error_response(
                            request_id,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Too many active subscriptions",
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        let subscription_id = self
            .next_subscription_id
            .fetch_add(1, atomic::Ordering::Relaxed)
            .to_string();

        let abort_registration = {
            let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
            let mut subscriptions_list = self.subscriptions.lock().await;
            let ty = if is_legacy {
                SubscriptionTy::TransactionLegacy
            } else {
                SubscriptionTy::Transaction
            };
            subscriptions_list.misc.insert(
                (subscription_id.clone(), ty),
                (abort_handle, state_machine_subscription.clone()),
            );
            abort_registration
        };

        self.requests_subscriptions
            .respond(
                &state_machine_request_id,
                if is_legacy {
                    methods::Response::author_submitAndWatchExtrinsic(&subscription_id)
                        .to_json_response(request_id)
                } else {
                    methods::Response::transaction_unstable_submitAndWatch(&subscription_id)
                        .to_json_response(request_id)
                },
            )
            .await;

        // Spawn a separate task for the transaction updates.
        let task = {
            let mut transaction_updates = self
                .transactions_service
                .submit_and_watch_transaction(transaction.0, 16)
                .await;
            let me = self.clone();
            async move {
                let mut included_block = None;
                let mut num_broadcasted_peers = 0;

                // TODO: doesn't reported `validated` events

                loop {
                    match transaction_updates.next().await {
                        Some(update) => {
                            let update = match (update, is_legacy) {
                                (transactions_service::TransactionStatus::Broadcast(peers), false) => {
                                    methods::ServerToClient::author_extrinsicUpdate {
                                        subscription: &subscription_id,
                                        result: methods::TransactionStatus::Broadcast(
                                            peers.into_iter().map(|peer| peer.to_base58()).collect(),
                                        )
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                                (transactions_service::TransactionStatus::Broadcast(peers), true) => {
                                    num_broadcasted_peers += peers.len();
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::Broadcasted {
                                            num_peers: u32::try_from(num_broadcasted_peers).unwrap_or(u32::max_value()),
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                }

                                (transactions_service::TransactionStatus::IncludedBlockUpdate {
                                    block_hash: Some((block_hash, _)),
                                }, true) => {
                                    included_block = Some(block_hash);
                                    methods::ServerToClient::author_extrinsicUpdate {
                                        subscription: &subscription_id,
                                        result: methods::TransactionStatus::InBlock(methods::HashHexString(
                                            block_hash,
                                        ))
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                                (transactions_service::TransactionStatus::IncludedBlockUpdate {
                                    block_hash: None,
                                }, true) => {
                                    if let Some(block_hash) = included_block.take() {
                                        methods::ServerToClient::author_extrinsicUpdate {
                                            subscription: &subscription_id,
                                            result: methods::TransactionStatus::Retracted(
                                                methods::HashHexString(block_hash),
                                            )
                                        }
                                        .to_json_call_object_parameters(None)

                                    } else {
                                        continue;
                                    }
                                }
                                (transactions_service::TransactionStatus::IncludedBlockUpdate {
                                    block_hash: Some((block_hash, index)),
                                }, false) => {
                                    included_block = Some(block_hash);
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::BestChainBlockIncluded {
                                            block: Some(methods::TransactionWatchEventBlock {
                                                hash: methods::HashHexString(block_hash),
                                                index: methods::NumberAsString(index),
                                            })
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                                (transactions_service::TransactionStatus::IncludedBlockUpdate {
                                    block_hash: None,
                                }, false) => {
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::BestChainBlockIncluded {
                                            block: None,
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                }

                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::GapInChain,
                                ), true)
                                | (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::MaxPendingTransactionsReached,
                                ), true)
                                | (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Invalid(_),
                                ), true)
                                | (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::ValidateError(_),
                                ), true) => {
                                    methods::ServerToClient::author_extrinsicUpdate {
                                        subscription: &subscription_id,
                                        result: methods::TransactionStatus::Dropped,
                                    }
                                    .to_json_call_object_parameters(None)
                                },
                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::GapInChain,
                                ), false) => {
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::Dropped {
                                            error: "gap in chain of blocks",
                                            broadcasted: num_broadcasted_peers != 0,
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                },
                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::MaxPendingTransactionsReached,
                                ), false) => {
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::Dropped {
                                            error: "transactions pool full",
                                            broadcasted: num_broadcasted_peers != 0,
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                },
                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Invalid(error),
                                ), false) => {
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::Invalid {
                                            error: &error.to_string(),
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                },
                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::ValidateError(error),
                                ), false) => {
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::Error {
                                            error: &error.to_string(),
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                },

                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Finalized { block_hash, .. },
                                ), true) => {
                                    methods::ServerToClient::author_extrinsicUpdate {
                                        subscription: &subscription_id,
                                        result: methods::TransactionStatus::Finalized(methods::HashHexString(
                                            block_hash,
                                        ))
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Finalized { block_hash, index },
                                ), false) => {
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::Finalized {
                                            block: methods::TransactionWatchEventBlock {
                                                hash: methods::HashHexString(block_hash),
                                                index: methods::NumberAsString(index),
                                            },
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                            };

                            // TODO: handle situation where buffer is full
                            let _ = me
                                .requests_subscriptions
                                .try_push_notification(&state_machine_subscription, update)
                                .await;
                        }
                        None => {
                            // Channel from the transactions service has been closed.
                            // Stop the task.
                            // There is nothing more that can be done except hope that the
                            // client understands that no new notification is expected and
                            // unsubscribes.
                            break;
                        }
                    }
                }
            }
        };

        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(Box::pin(
                future::Abortable::new(task, abort_registration).map(|_| ()),
            ))
            .unwrap();
    }

    /// Handles a call to [`methods::MethodCall::chain_getBlockHash`].
    async fn get_block_hash(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        height: Option<u64>,
    ) {
        // TODO: maybe store values in cache?
        let response = {
            match height {
                Some(0) => methods::Response::chain_getBlockHash(methods::HashHexString(
                    self.genesis_block,
                ))
                .to_json_response(request_id),
                None => {
                    let best_block = header::hash_from_scale_encoded_header(
                        &self.runtime_service.subscribe_best().await.0,
                    );
                    methods::Response::chain_getBlockHash(methods::HashHexString(best_block))
                        .to_json_response(request_id)
                }
                Some(_) => {
                    // While the block could be found in `known_blocks`, there is no guarantee
                    // that blocks in `known_blocks` are canonical, and we have no choice but to
                    // return null.
                    // TODO: ask a full node instead? or maybe keep a list of canonical blocks?
                    json_rpc::parse::build_success_response(request_id, "null")
                }
            }
        };

        self.requests_subscriptions
            .respond(&state_machine_request_id, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::chain_subscribeAllHeads`].
    async fn subscribe_all_heads(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        let state_machine_subscription = match self
            .requests_subscriptions
            .start_subscription(state_machine_request_id, 16)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                self.requests_subscriptions
                    .respond(
                        state_machine_request_id,
                        json_rpc::parse::build_error_response(
                            request_id,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Too many active subscriptions",
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        let subscription_id = self
            .next_subscription_id
            .fetch_add(1, atomic::Ordering::Relaxed)
            .to_string();

        let abort_registration = {
            let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
            let mut subscriptions_list = self.subscriptions.lock().await;
            subscriptions_list.misc.insert(
                (subscription_id.clone(), SubscriptionTy::AllHeads),
                (abort_handle, state_machine_subscription.clone()),
            );
            abort_registration
        };

        self.requests_subscriptions
            .respond(
                &state_machine_request_id,
                methods::Response::chain_subscribeAllHeads(&subscription_id)
                    .to_json_response(request_id),
            )
            .await;

        let mut new_blocks = {
            let subscribe_all = self.runtime_service.subscribe_all(16, 32).await;

            // The finalized and already-known blocks aren't reported to the user, but we need
            // unpin them on to the runtime service.
            subscribe_all
                .new_blocks
                .unpin_block(&header::hash_from_scale_encoded_header(
                    &subscribe_all.finalized_block_scale_encoded_header,
                ))
                .await;
            for block in subscribe_all.non_finalized_blocks_ancestry_order {
                subscribe_all
                    .new_blocks
                    .unpin_block(&header::hash_from_scale_encoded_header(
                        &block.scale_encoded_header,
                    ))
                    .await;
            }

            subscribe_all.new_blocks
        };

        // Spawn a separate task for the subscription.
        let task = {
            let me = self.clone();
            async move {
                loop {
                    match new_blocks.next().await {
                        Some(runtime_service::Notification::Block(block)) => {
                            new_blocks
                                .unpin_block(&header::hash_from_scale_encoded_header(
                                    &block.scale_encoded_header,
                                ))
                                .await;

                            let _ = me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
                                    methods::ServerToClient::chain_newHead {
                                        subscription: &subscription_id,
                                        result: methods::Header::from_scale_encoded_header(
                                            &block.scale_encoded_header,
                                        )
                                        .unwrap(),
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await;
                        }
                        Some(runtime_service::Notification::Finalized { .. }) => {}
                        None => {
                            // TODO: ?!
                            return;
                        }
                    }
                }
            }
        };

        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(Box::pin(
                future::Abortable::new(task, abort_registration).map(|_| ()),
            ))
            .unwrap();
    }

    /// Handles a call to [`methods::MethodCall::chain_subscribeNewHeads`].
    async fn subscribe_new_heads(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        let state_machine_subscription = match self
            .requests_subscriptions
            .start_subscription(state_machine_request_id, 1)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                self.requests_subscriptions
                    .respond(
                        state_machine_request_id,
                        json_rpc::parse::build_error_response(
                            request_id,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Too many active subscriptions",
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        let subscription_id = self
            .next_subscription_id
            .fetch_add(1, atomic::Ordering::Relaxed)
            .to_string();

        let abort_registration = {
            let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
            let mut subscriptions_list = self.subscriptions.lock().await;
            subscriptions_list.misc.insert(
                (subscription_id.clone(), SubscriptionTy::NewHeads),
                (abort_handle, state_machine_subscription.clone()),
            );
            abort_registration
        };

        self.requests_subscriptions
            .respond(
                &state_machine_request_id,
                methods::Response::chain_subscribeNewHeads(&subscription_id)
                    .to_json_response(request_id),
            )
            .await;

        let mut blocks_list = {
            let (block_header, blocks_subscription) = self.runtime_service.subscribe_best().await;
            stream::once(future::ready(block_header)).chain(blocks_subscription)
        };

        // Spawn a separate task for the subscription.
        let task = {
            let me = self.clone();
            async move {
                loop {
                    match blocks_list.next().await {
                        Some(block) => {
                            let header =
                                methods::Header::from_scale_encoded_header(&block).unwrap();
                            me.requests_subscriptions
                                .set_queued_notification(
                                    &state_machine_subscription,
                                    0,
                                    methods::ServerToClient::chain_newHead {
                                        subscription: &subscription_id,
                                        result: header,
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await;
                        }
                        None => {
                            // TODO: ?!
                            return;
                        }
                    }
                }
            }
        };

        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(Box::pin(
                future::Abortable::new(task, abort_registration).map(|_| ()),
            ))
            .unwrap();
    }

    /// Handles a call to [`methods::MethodCall::chain_subscribeFinalizedHeads`].
    async fn subscribe_finalized_heads(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        let state_machine_subscription = match self
            .requests_subscriptions
            .start_subscription(state_machine_request_id, 1)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                self.requests_subscriptions
                    .respond(
                        state_machine_request_id,
                        json_rpc::parse::build_error_response(
                            request_id,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Too many active subscriptions",
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        let subscription_id = self
            .next_subscription_id
            .fetch_add(1, atomic::Ordering::Relaxed)
            .to_string();

        let abort_registration = {
            let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
            let mut subscriptions_list = self.subscriptions.lock().await;
            subscriptions_list.misc.insert(
                (subscription_id.clone(), SubscriptionTy::FinalizedHeads),
                (abort_handle, state_machine_subscription.clone()),
            );
            abort_registration
        };

        self.requests_subscriptions
            .respond(
                &state_machine_request_id,
                methods::Response::chain_subscribeFinalizedHeads(&subscription_id)
                    .to_json_response(request_id),
            )
            .await;

        let mut blocks_list = {
            let (finalized_block_header, finalized_blocks_subscription) =
                self.runtime_service.subscribe_finalized().await;
            stream::once(future::ready(finalized_block_header)).chain(finalized_blocks_subscription)
        };

        // Spawn a separate task for the subscription.
        let task = {
            let me = self.clone();
            async move {
                loop {
                    match blocks_list.next().await {
                        Some(block) => {
                            let header =
                                methods::Header::from_scale_encoded_header(&block).unwrap();

                            me.requests_subscriptions
                                .set_queued_notification(
                                    &state_machine_subscription,
                                    0,
                                    methods::ServerToClient::chain_finalizedHead {
                                        subscription: &subscription_id,
                                        result: header,
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await;
                        }
                        None => {
                            // TODO: ?!
                            return;
                        }
                    }
                }
            }
        };

        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(Box::pin(
                future::Abortable::new(task, abort_registration).map(|_| ()),
            ))
            .unwrap();
    }

    /// Handles a call to [`methods::MethodCall::state_subscribeStorage`].
    async fn subscribe_storage(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        list: Vec<methods::HexString>,
    ) {
        let state_machine_subscription = match self
            .requests_subscriptions
            .start_subscription(state_machine_request_id, 1)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                self.requests_subscriptions
                    .respond(
                        state_machine_request_id,
                        json_rpc::parse::build_error_response(
                            request_id,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Too many active subscriptions",
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        let subscription_id = self
            .next_subscription_id
            .fetch_add(1, atomic::Ordering::Relaxed)
            .to_string();

        let abort_registration = {
            let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
            let mut subscriptions_list = self.subscriptions.lock().await;
            subscriptions_list.misc.insert(
                (subscription_id.clone(), SubscriptionTy::Storage),
                (abort_handle, state_machine_subscription.clone()),
            );
            abort_registration
        };

        self.requests_subscriptions
            .respond(
                &state_machine_request_id,
                methods::Response::state_subscribeStorage(&subscription_id)
                    .to_json_response(request_id),
            )
            .await;

        // Build a stream of `methods::StorageChangeSet` items to send back to the user.
        let storage_updates = {
            let known_values = (0..list.len()).map(|_| None).collect::<Vec<_>>();
            let runtime_service = self.runtime_service.clone();
            let sync_service = self.sync_service.clone();
            let log_target = self.log_target.clone();

            stream::unfold(
                (None, list, known_values),
                move |(mut blocks_stream, list, mut known_values)| {
                    let sync_service = sync_service.clone();
                    let runtime_service = runtime_service.clone();
                    let log_target = log_target.clone();
                    async move {
                        loop {
                            if blocks_stream.is_none() {
                                // TODO: why is this done against the runtime_service and not the sync_service? clarify
                                let (block_header, blocks_subscription) =
                                    runtime_service.subscribe_best().await;
                                blocks_stream = Some(
                                    stream::once(future::ready(block_header))
                                        .chain(blocks_subscription),
                                );
                            }

                            let block = match blocks_stream.as_mut().unwrap().next().await {
                                Some(b) => b,
                                None => {
                                    blocks_stream = None;
                                    continue;
                                }
                            };

                            let block_hash = header::hash_from_scale_encoded_header(&block);
                            let state_trie_root = header::decode(&block).unwrap().state_root;

                            let mut out = methods::StorageChangeSet {
                                block: methods::HashHexString(block_hash),
                                changes: Vec::new(),
                            };

                            for (key_index, key) in list.iter().enumerate() {
                                // TODO: parallelism?
                                match sync_service
                                    .clone()
                                    .storage_query(&block_hash, state_trie_root, iter::once(&key.0))
                                    .await
                                {
                                    Ok(mut values) => {
                                        let value = values.pop().unwrap();
                                        match &mut known_values[key_index] {
                                            Some(v) if *v == value => {}
                                            v @ _ => {
                                                *v = Some(value.clone());
                                                out.changes.push((
                                                    key.clone(),
                                                    value.map(methods::HexString),
                                                ));
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        log::log!(
                                            target: &log_target,
                                            if error.is_network_problem() {
                                                log::Level::Debug
                                            } else {
                                                log::Level::Warn
                                            },
                                            "state_subscribeStorage changes check failed: {}",
                                            error
                                        );
                                    }
                                }
                            }

                            if !out.changes.is_empty() {
                                return Some((out, (blocks_stream, list, known_values)));
                            }
                        }
                    }
                },
            )
        };

        // Spawn a separate task for the subscription.
        let task = {
            let me = self.clone();
            async move {
                futures::pin_mut!(storage_updates);

                loop {
                    match storage_updates.next().await {
                        Some(changes) => {
                            me.requests_subscriptions
                                .set_queued_notification(
                                    &state_machine_subscription,
                                    0,
                                    methods::ServerToClient::state_storage {
                                        subscription: &subscription_id,
                                        result: changes,
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await;
                        }
                        None => {
                            // The stream created above is infinite.
                            unreachable!()
                        }
                    }
                }
            }
        };

        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(Box::pin(
                future::Abortable::new(task, abort_registration).map(|_| ()),
            ))
            .unwrap();
    }

    /// Obtain the state trie root hash of the given block, and make sure to put it in cache.
    // TODO: better error return type
    async fn state_trie_root_hash(&self, hash: &[u8; 32]) -> Result<[u8; 32], ()> {
        let fetch = {
            // Try to find an existing entry in cache, and if not create one.
            let mut cache_lock = self.cache.lock().await;

            // Look in `recent_pinned_blocks`.
            match cache_lock
                .recent_pinned_blocks
                .get(hash)
                .map(|h| header::decode(h))
            {
                Some(Ok(header)) => return Ok(*header.state_root),
                Some(Err(_)) => return Err(()),
                None => {}
            }

            // Look in `block_state_root_hashes`.
            match cache_lock.block_state_root_hashes.get(hash) {
                Some(future::MaybeDone::Done(Ok(val))) => return Ok(*val),
                Some(future::MaybeDone::Future(f)) => f.clone(),
                Some(future::MaybeDone::Gone) => unreachable!(), // We never use `Gone`.
                Some(future::MaybeDone::Done(Err(()))) | None => {
                    // TODO: filter by error      ^ ; invalid header for example should be returned immediately
                    // No existing cache entry. Create the future that will perform the fetch
                    // but do not actually start doing anything now.
                    let fetch = {
                        let sync_service = self.sync_service.clone();
                        let hash = *hash;
                        async move {
                            // The sync service knows which peers are potentially aware of
                            // this block.
                            let result = sync_service
                                .block_query(
                                    hash,
                                    protocol::BlocksRequestFields {
                                        header: true,
                                        body: false,
                                        justifications: false,
                                    },
                                )
                                .await;

                            if let Ok(block) = result {
                                // If successful, the `block_query` function guarantees that the
                                // header is present and valid.
                                let header = block.header.unwrap();
                                debug_assert_eq!(
                                    header::hash_from_scale_encoded_header(&header),
                                    hash
                                );
                                let decoded = header::decode(&header).unwrap();
                                Ok(*decoded.state_root)
                            } else {
                                Err(())
                            }
                        }
                    };

                    // Insert the future in the cache, so that any other call will use the same
                    // future.
                    let wrapped = fetch.boxed().shared();
                    cache_lock
                        .block_state_root_hashes
                        .put(*hash, future::maybe_done(wrapped.clone()));
                    wrapped
                }
            }
        };

        // We await separately to be certain that the lock isn't held anymore.
        fetch.await
    }

    async fn storage_query(
        &self,
        keys: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
        hash: &[u8; 32],
    ) -> Result<Vec<Option<Vec<u8>>>, StorageQueryError> {
        let state_trie_root_hash = self
            .state_trie_root_hash(&hash)
            .await
            .map_err(|()| StorageQueryError::FindStorageRootHashError)?;

        let result = self
            .sync_service
            .clone()
            .storage_query(hash, &state_trie_root_hash, keys)
            .await
            .map_err(StorageQueryError::StorageRetrieval)?;

        Ok(result)
    }

    fn header_query(&'_ self, hash: &[u8; 32]) -> impl Future<Output = Result<Vec<u8>, ()>> + '_ {
        // TODO: had to go through hoops to make it compile; clean up
        let hash = *hash;
        let sync_service = self.sync_service.clone();

        async move {
            // TODO: risk of deadlock here?
            {
                let mut cache = self.cache.lock().await;
                let cache = &mut *cache;

                if let Some(header) = cache.recent_pinned_blocks.get(&hash) {
                    return Ok(header.clone());
                }
            }

            // Header isn't known locally. Ask the networ
            let fut = sync_service.block_query(
                hash,
                protocol::BlocksRequestFields {
                    header: true,
                    body: false,
                    justifications: false,
                },
            );
            let result = fut.await;

            // Note that the `block_query` method guarantees that the header is present
            // and valid.
            if let Ok(block) = result {
                let header = block.header.unwrap();
                debug_assert_eq!(header::hash_from_scale_encoded_header(&header), hash);
                Ok(header)
            } else {
                Err(())
            }
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_follow`].
    async fn chain_head_follow(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        runtime_updates: bool,
    ) {
        let state_machine_subscription = match self
            .requests_subscriptions
            .start_subscription(state_machine_request_id, 16)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                self.requests_subscriptions
                    .respond(
                        state_machine_request_id,
                        json_rpc::parse::build_error_response(
                            request_id,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Too many active subscriptions",
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        let (mut subscribe_all, runtime_subscribe_all) = if runtime_updates {
            let subscribe_all = self.runtime_service.subscribe_all(32, 48).await;
            let id = subscribe_all.new_blocks.id();
            (either::Left(subscribe_all), Some(id))
        } else {
            (
                either::Right(self.sync_service.subscribe_all(32, false).await),
                None,
            )
        };

        let (subscription_id, initial_notifications, abort_registration) = {
            let subscription_id = self
                .next_subscription_id
                .fetch_add(1, atomic::Ordering::Relaxed)
                .to_string();

            self.requests_subscriptions
                .respond(
                    &state_machine_request_id,
                    methods::Response::chainHead_unstable_follow(&subscription_id)
                        .to_json_response(request_id),
                )
                .await;

            let mut initial_notifications = Vec::with_capacity(match &subscribe_all {
                either::Left(sa) => 1 + sa.non_finalized_blocks_ancestry_order.len(),
                either::Right(sa) => 1 + sa.non_finalized_blocks_ancestry_order.len(),
            });

            let mut pinned_blocks_headers =
                HashMap::with_capacity_and_hasher(0, Default::default());
            let mut non_finalized_blocks = fork_tree::ForkTree::new();

            match &subscribe_all {
                either::Left(subscribe_all) => {
                    let finalized_block_hash = header::hash_from_scale_encoded_header(
                        &subscribe_all.finalized_block_scale_encoded_header[..],
                    );

                    pinned_blocks_headers.insert(
                        finalized_block_hash,
                        subscribe_all.finalized_block_scale_encoded_header.clone(),
                    );

                    initial_notifications.push({
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: &subscription_id,
                            result: methods::FollowEvent::Initialized {
                                finalized_block_hash: methods::HashHexString(finalized_block_hash),
                                finalized_block_runtime: Some(convert_runtime_spec(
                                    &subscribe_all.finalized_block_runtime,
                                )),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    });

                    for block in &subscribe_all.non_finalized_blocks_ancestry_order {
                        let hash =
                            header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                        let _was_in =
                            pinned_blocks_headers.insert(hash, block.scale_encoded_header.clone());
                        debug_assert!(_was_in.is_none());

                        let parent_node_index = if block.parent_hash == finalized_block_hash {
                            None
                        } else {
                            // TODO: O(n)
                            Some(
                                non_finalized_blocks
                                    .find(|b| *b == block.parent_hash)
                                    .unwrap(),
                            )
                        };
                        non_finalized_blocks.insert(parent_node_index, hash);

                        initial_notifications.push(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: &subscription_id,
                                result: methods::FollowEvent::NewBlock {
                                    block_hash: methods::HashHexString(hash),
                                    new_runtime: if let Some(new_runtime) = &block.new_runtime {
                                        Some(convert_runtime_spec(new_runtime))
                                    } else {
                                        None
                                    },
                                    parent_block_hash: methods::HashHexString(block.parent_hash),
                                },
                            }
                            .to_json_call_object_parameters(None),
                        );

                        if block.is_new_best {
                            initial_notifications.push(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: &subscription_id,
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_call_object_parameters(None),
                            );
                        }
                    }
                }
                either::Right(subscribe_all) => {
                    let finalized_block_hash = header::hash_from_scale_encoded_header(
                        &subscribe_all.finalized_block_scale_encoded_header[..],
                    );

                    pinned_blocks_headers.insert(
                        finalized_block_hash,
                        subscribe_all.finalized_block_scale_encoded_header.clone(),
                    );

                    initial_notifications.push(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: &subscription_id,
                            result: methods::FollowEvent::Initialized {
                                finalized_block_hash: methods::HashHexString(finalized_block_hash),
                                finalized_block_runtime: None,
                            },
                        }
                        .to_json_call_object_parameters(None),
                    );

                    for block in &subscribe_all.non_finalized_blocks_ancestry_order {
                        let hash =
                            header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                        let _was_in =
                            pinned_blocks_headers.insert(hash, block.scale_encoded_header.clone());
                        debug_assert!(_was_in.is_none());

                        let parent_node_index = if block.parent_hash == finalized_block_hash {
                            None
                        } else {
                            // TODO: O(n)
                            Some(
                                non_finalized_blocks
                                    .find(|b| *b == block.parent_hash)
                                    .unwrap(),
                            )
                        };
                        non_finalized_blocks.insert(parent_node_index, hash);

                        initial_notifications.push(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: &subscription_id,
                                result: methods::FollowEvent::NewBlock {
                                    block_hash: methods::HashHexString(hash),
                                    new_runtime: None,
                                    parent_block_hash: methods::HashHexString(block.parent_hash),
                                },
                            }
                            .to_json_call_object_parameters(None),
                        );

                        if block.is_new_best {
                            initial_notifications.push(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: &subscription_id,
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_call_object_parameters(None),
                            );
                        }
                    }
                }
            }

            let (abort_handle, abort_registration) = future::AbortHandle::new_pair();

            let mut lock = self.subscriptions.lock().await;

            lock.chain_head_follow.insert(
                subscription_id.clone(),
                FollowSubscription {
                    non_finalized_blocks,
                    pinned_blocks_headers,
                    runtime_subscribe_all,
                    abort_handle: abort_handle,
                },
            );

            (subscription_id, initial_notifications, abort_registration)
        };

        // Spawn a separate task for the subscription.
        let task = {
            let me = self.clone();
            async move {
                // Send back to the user the initial notifications.
                for notif in initial_notifications {
                    me.requests_subscriptions
                        .push_notification(&state_machine_subscription, notif)
                        .await;
                }

                loop {
                    let next_block = match &mut subscribe_all {
                        either::Left(subscribe_all) => {
                            future::Either::Left(subscribe_all.new_blocks.next().map(either::Left))
                        }
                        either::Right(subscribe_all) => future::Either::Right(
                            subscribe_all.new_blocks.next().map(either::Right),
                        ),
                    };
                    futures::pin_mut!(next_block);

                    // TODO: doesn't enforce any maximum number of pinned blocks
                    match next_block.await {
                        either::Left(None) | either::Right(None) => {
                            // TODO: clear queue of notifications?
                            break;
                        }
                        either::Left(Some(runtime_service::Notification::Finalized {
                            best_block_hash,
                            hash,
                            ..
                        }))
                        | either::Right(Some(sync_service::Notification::Finalized {
                            best_block_hash,
                            hash,
                        })) => {
                            let mut finalized_blocks_hashes = Vec::new();
                            let mut pruned_blocks_hashes = Vec::new();

                            let mut subscriptions = me.subscriptions.lock().await;
                            if let Some(sub) =
                                subscriptions.chain_head_follow.get_mut(&subscription_id)
                            {
                                let node_index =
                                    sub.non_finalized_blocks.find(|b| *b == hash).unwrap();
                                for pruned in sub.non_finalized_blocks.prune_ancestors(node_index) {
                                    if pruned.is_prune_target_ancestor {
                                        finalized_blocks_hashes
                                            .push(methods::HashHexString(pruned.user_data));
                                    } else {
                                        pruned_blocks_hashes
                                            .push(methods::HashHexString(pruned.user_data));
                                    }
                                }
                            }

                            // TODO: don't always generate
                            if me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
                                    methods::ServerToClient::chainHead_unstable_followEvent {
                                        subscription: &subscription_id,
                                        result: methods::FollowEvent::BestBlockChanged {
                                            best_block_hash: methods::HashHexString(
                                                best_block_hash,
                                            ),
                                        },
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await
                                .is_err()
                            {
                                break;
                            }

                            if me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
                                    methods::ServerToClient::chainHead_unstable_followEvent {
                                        subscription: &subscription_id,
                                        result: methods::FollowEvent::Finalized {
                                            finalized_blocks_hashes,
                                            pruned_blocks_hashes,
                                        },
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        either::Left(Some(runtime_service::Notification::Block(block))) => {
                            let hash =
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                            let mut subscriptions = me.subscriptions.lock().await;
                            if let Some(sub) =
                                subscriptions.chain_head_follow.get_mut(&subscription_id)
                            {
                                let _was_in = sub
                                    .pinned_blocks_headers
                                    .insert(hash, block.scale_encoded_header);
                                debug_assert!(_was_in.is_none());

                                // TODO: check if it matches current finalized block
                                // TODO: O(n)
                                let parent_node_index =
                                    sub.non_finalized_blocks.find(|b| *b == block.parent_hash);
                                sub.non_finalized_blocks.insert(parent_node_index, hash);
                            }

                            if me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
                                    methods::ServerToClient::chainHead_unstable_followEvent {
                                        subscription: &subscription_id,
                                        result: methods::FollowEvent::NewBlock {
                                            block_hash: methods::HashHexString(hash),
                                            parent_block_hash: methods::HashHexString(
                                                block.parent_hash,
                                            ),
                                            new_runtime: if let Some(new_runtime) =
                                                &block.new_runtime
                                            {
                                                Some(convert_runtime_spec(new_runtime))
                                            } else {
                                                None
                                            },
                                        },
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await
                                .is_err()
                            {
                                break;
                            }

                            if block.is_new_best {
                                if me
                                    .requests_subscriptions
                                    .try_push_notification(
                                        &state_machine_subscription,
                                        methods::ServerToClient::chainHead_unstable_followEvent {
                                            subscription: &subscription_id,
                                            result: methods::FollowEvent::BestBlockChanged {
                                                best_block_hash: methods::HashHexString(hash),
                                            },
                                        }
                                        .to_json_call_object_parameters(None),
                                    )
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                        either::Right(Some(sync_service::Notification::Block(block))) => {
                            let hash =
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                            let mut subscriptions = me.subscriptions.lock().await;
                            if let Some(sub) =
                                subscriptions.chain_head_follow.get_mut(&subscription_id)
                            {
                                let _was_in = sub
                                    .pinned_blocks_headers
                                    .insert(hash, block.scale_encoded_header);
                                debug_assert!(_was_in.is_none());

                                // TODO: check if it matches current finalized block
                                // TODO: O(n)
                                let parent_node_index =
                                    sub.non_finalized_blocks.find(|b| *b == block.parent_hash);
                                sub.non_finalized_blocks.insert(parent_node_index, hash);
                            }
                            if me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
                                    methods::ServerToClient::chainHead_unstable_followEvent {
                                        subscription: &subscription_id,
                                        result: methods::FollowEvent::NewBlock {
                                            block_hash: methods::HashHexString(hash),
                                            parent_block_hash: methods::HashHexString(
                                                block.parent_hash,
                                            ),
                                            new_runtime: None, // TODO:
                                        },
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await
                                .is_err()
                            {
                                break;
                            }

                            if block.is_new_best {
                                if me
                                    .requests_subscriptions
                                    .try_push_notification(
                                        &state_machine_subscription,
                                        methods::ServerToClient::chainHead_unstable_followEvent {
                                            subscription: &subscription_id,
                                            result: methods::FollowEvent::BestBlockChanged {
                                                best_block_hash: methods::HashHexString(hash),
                                            },
                                        }
                                        .to_json_call_object_parameters(None),
                                    )
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                }

                let _ = me
                    .subscriptions
                    .lock()
                    .await
                    .chain_head_follow
                    .remove(&subscription_id);

                me.requests_subscriptions
                    .push_notification(
                        &state_machine_subscription,
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: &subscription_id,
                            result: methods::FollowEvent::Stop {},
                        }
                        .to_json_call_object_parameters(None),
                    )
                    .await;
                me.requests_subscriptions
                    .stop_subscription(&state_machine_subscription)
                    .await;
            }
        };

        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(Box::pin(
                future::Abortable::new(task, abort_registration).map(|_| ()),
            ))
            .unwrap();
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_call`].
    async fn chain_head_call(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        follow_subscription_id: &str,
        hash: methods::HashHexString,
        function_to_call: &str,
        call_parameters: methods::HexString,
    ) {
        let task = {
            let me = self.clone();
            let request_id = request_id.to_owned();
            let function_to_call = function_to_call.to_owned();
            let state_machine_request_id = state_machine_request_id.clone();
            let follow_subscription_id = follow_subscription_id.to_owned();
            async move {
                // Determine whether the requested block hash is valid and start the call.
                let pre_runtime_call = {
                    let lock = me.subscriptions.lock().await;
                    if let Some(subscription) = lock.chain_head_follow.get(&follow_subscription_id)
                    {
                        let runtime_service_subscribe_all = match subscription.runtime_subscribe_all
                        {
                            Some(sa) => sa,
                            None => {
                                me.requests_subscriptions
                                    .respond(
                                        &state_machine_request_id,
                                        json_rpc::parse::build_error_response(
                                            &request_id,
                                            json_rpc::parse::ErrorResponse::InvalidParams,
                                            None,
                                        ),
                                    )
                                    .await;
                                return;
                            }
                        };

                        if !subscription.pinned_blocks_headers.contains_key(&hash.0) {
                            me.requests_subscriptions
                                .respond(
                                    &state_machine_request_id,
                                    json_rpc::parse::build_error_response(
                                        &request_id,
                                        json_rpc::parse::ErrorResponse::InvalidParams,
                                        None,
                                    ),
                                )
                                .await;
                            return;
                        }

                        Some(
                            me.runtime_service
                                .pinned_block_runtime_call_lock(
                                    runtime_service_subscribe_all,
                                    &hash.0,
                                )
                                .await,
                        )
                    } else {
                        None
                    }
                };

                let state_machine_subscription = match me
                    .requests_subscriptions
                    .start_subscription(&state_machine_request_id, 1)
                    .await
                {
                    Ok(v) => v,
                    Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                        me.requests_subscriptions
                            .respond(
                                &state_machine_request_id,
                                json_rpc::parse::build_error_response(
                                    &request_id,
                                    json_rpc::parse::ErrorResponse::ServerError(
                                        -32000,
                                        "Too many active subscriptions",
                                    ),
                                    None,
                                ),
                            )
                            .await;
                        return;
                    }
                };

                let subscription_id = me
                    .next_subscription_id
                    .fetch_add(1, atomic::Ordering::Relaxed)
                    .to_string();

                // TODO: make use of this
                let _abort_registration = {
                    let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
                    let mut subscriptions_list = me.subscriptions.lock().await;
                    subscriptions_list.misc.insert(
                        (subscription_id.clone(), SubscriptionTy::ChainHeadCall),
                        (abort_handle, state_machine_subscription.clone()),
                    );
                    abort_registration
                };

                me.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainHead_unstable_call(&subscription_id)
                            .to_json_response(&request_id),
                    )
                    .await;

                let pre_runtime_call = if let Some(pre_runtime_call) = pre_runtime_call {
                    Some(
                        pre_runtime_call
                            .start(&function_to_call, iter::once(&call_parameters.0))
                            .await,
                    )
                } else {
                    None
                };

                let final_notif = match pre_runtime_call {
                    Some(Ok((runtime_call_lock, virtual_machine))) => {
                        match read_only_runtime_host::run(read_only_runtime_host::Config {
                            virtual_machine,
                            function_to_call: &function_to_call,
                            parameter: iter::once(&call_parameters.0),
                        }) {
                            Err((error, prototype)) => {
                                runtime_call_lock.unlock(prototype);
                                methods::ServerToClient::chainHead_unstable_callEvent {
                                    subscription: &subscription_id,
                                    result: methods::ChainHeadCallEvent::Error {
                                        error: &error.to_string(),
                                    },
                                }
                                .to_json_call_object_parameters(None)
                            }
                            Ok(mut runtime_call) => {
                                loop {
                                    match runtime_call {
                                        read_only_runtime_host::RuntimeHostVm::Finished(Ok(
                                            success,
                                        )) => {
                                            let output =
                                                success.virtual_machine.value().as_ref().to_owned();
                                            runtime_call_lock
                                                .unlock(success.virtual_machine.into_prototype());
                                            break methods::ServerToClient::chainHead_unstable_callEvent {
                                                    subscription: &subscription_id,
                                                    result: methods::ChainHeadCallEvent::Done {
                                                        output: methods::HexString(output),
                                                    },
                                                }
                                                .to_json_call_object_parameters(None);
                                        }
                                        read_only_runtime_host::RuntimeHostVm::Finished(Err(
                                            error,
                                        )) => {
                                            runtime_call_lock.unlock(error.prototype);
                                            break methods::ServerToClient::chainHead_unstable_callEvent {
                                                    subscription: &subscription_id,
                                                    result: methods::ChainHeadCallEvent::Error {
                                                        error: &error.detail.to_string(),
                                                    },
                                                }
                                                .to_json_call_object_parameters(None);
                                        }
                                        read_only_runtime_host::RuntimeHostVm::StorageGet(get) => {
                                            // TODO: what if the remote lied to us?
                                            let storage_value = match runtime_call_lock
                                                .storage_entry(&get.key_as_vec())
                                            {
                                                Ok(v) => v,
                                                Err(error) => {
                                                    runtime_call_lock.unlock(
                                                            read_only_runtime_host::RuntimeHostVm::StorageGet(
                                                                get,
                                                            )
                                                            .into_prototype(),
                                                        );
                                                    break methods::ServerToClient::chainHead_unstable_callEvent {
                                                            subscription: &subscription_id,
                                                            result: methods::ChainHeadCallEvent::Inaccessible {
                                                                error: &error.to_string(),
                                                            },
                                                        }
                                                        .to_json_call_object_parameters(None);
                                                }
                                            };
                                            runtime_call =
                                                get.inject_value(storage_value.map(iter::once));
                                        }
                                        read_only_runtime_host::RuntimeHostVm::NextKey(_) => {
                                            todo!() // TODO:
                                        }
                                        read_only_runtime_host::RuntimeHostVm::StorageRoot(
                                            storage_root,
                                        ) => {
                                            runtime_call = storage_root
                                                .resume(runtime_call_lock.block_storage_root());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Some(Err(runtime_service::RuntimeCallError::InvalidRuntime(error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadCallEvent::Error {
                                error: &error.to_string(),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    Some(Err(runtime_service::RuntimeCallError::StorageRetrieval(error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadCallEvent::Error {
                                error: &error.to_string(),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    Some(Err(runtime_service::RuntimeCallError::CallProof(error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadCallEvent::Error {
                                error: &error.to_string(),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    Some(Err(runtime_service::RuntimeCallError::NetworkBlockRequest)) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadCallEvent::Inaccessible {
                                error: "couldn't retrieve proof from network",
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    Some(Err(runtime_service::RuntimeCallError::InvalidBlockHeader(error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadCallEvent::Error {
                                error: &format!("invalid block header format: {}", error),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    Some(Err(runtime_service::RuntimeCallError::StorageQuery(error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadCallEvent::Error {
                                error: &format!("failed to fetch call proof: {}", error),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    None => methods::ServerToClient::chainHead_unstable_callEvent {
                        subscription: &subscription_id,
                        result: methods::ChainHeadCallEvent::Disjoint {},
                    }
                    .to_json_call_object_parameters(None),
                };

                me.requests_subscriptions
                    .push_notification(&state_machine_subscription, final_notif)
                    .await;

                me.requests_subscriptions
                    .stop_subscription(&state_machine_subscription)
                    .await;
                let _ = me
                    .subscriptions
                    .lock()
                    .await
                    .misc
                    .remove(&(subscription_id.to_owned(), SubscriptionTy::ChainHeadCall));
            }
        };

        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(task.boxed())
            .unwrap();
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_storage`].
    async fn chain_head_storage(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        follow_subscription_id: &str,
        hash: methods::HashHexString,
        key: methods::HexString,
        child_key: Option<methods::HexString>,
        ty: methods::StorageQueryType,
    ) {
        if child_key.is_some() {
            self.requests_subscriptions
                .respond(
                    &state_machine_request_id,
                    json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::ServerError(
                            -32000,
                            "Child key storage queries not supported yet",
                        ),
                        None,
                    ),
                )
                .await;
            log::warn!(
                target: &self.log_target,
                "chainHead_unstable_storage with a non-null childKey has been called. \
                This isn't supported by smoldot yet."
            );
            return;
        }

        // Determine whether the requested block hash is valid, and if so its state trie root.
        let block_storage_root = {
            let lock = self.subscriptions.lock().await;
            if let Some(subscription) = lock.chain_head_follow.get(follow_subscription_id) {
                if let Some(header) = subscription.pinned_blocks_headers.get(&hash.0) {
                    if let Ok(decoded) = header::decode(&header) {
                        Some(*decoded.state_root)
                    } else {
                        None // TODO: what to return?!
                    }
                } else {
                    self.requests_subscriptions
                        .respond(
                            &state_machine_request_id,
                            json_rpc::parse::build_error_response(
                                request_id,
                                json_rpc::parse::ErrorResponse::InvalidParams,
                                None,
                            ),
                        )
                        .await;
                    return;
                }
            } else {
                None
            }
        };

        let state_machine_subscription = match self
            .requests_subscriptions
            .start_subscription(&state_machine_request_id, 1)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        json_rpc::parse::build_error_response(
                            request_id,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Too many active subscriptions",
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        let subscription_id = self
            .next_subscription_id
            .fetch_add(1, atomic::Ordering::Relaxed)
            .to_string();

        let abort_registration = {
            let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
            let mut subscriptions_list = self.subscriptions.lock().await;
            subscriptions_list.misc.insert(
                (subscription_id.clone(), SubscriptionTy::ChainHeadStorage),
                (abort_handle, state_machine_subscription.clone()),
            );
            abort_registration
        };

        self.requests_subscriptions
            .respond(
                &state_machine_request_id,
                methods::Response::chainHead_unstable_storage(&subscription_id)
                    .to_json_response(request_id),
            )
            .await;

        let task = {
            let me = self.clone();
            async move {
                let response = if let Some(block_storage_root) = block_storage_root {
                    let response = me
                        .sync_service
                        .clone()
                        .storage_query(&hash.0, &block_storage_root, iter::once(&key.0))
                        .await;
                    match response {
                        Ok(values) => {
                            // `storage_query` returns a list of values because it can perform
                            // multiple queries at once. In our situation, we only start one query
                            // and as such the outcome only ever contains one element.
                            debug_assert_eq!(values.len(), 1);
                            let value = values.into_iter().next().unwrap();

                            let output = match ty {
                                methods::StorageQueryType::Value => {
                                    value.map(|v| methods::HexString(v).to_string())
                                }
                                methods::StorageQueryType::Size => {
                                    value.map(|v| v.len().to_string())
                                }
                                methods::StorageQueryType::Hash => value.map(|v| {
                                    methods::HexString(
                                        blake2_rfc::blake2b::blake2b(32, &[], &v)
                                            .as_bytes()
                                            .to_vec(),
                                    )
                                    .to_string()
                                }),
                            };

                            methods::ServerToClient::chainHead_unstable_storageEvent {
                                subscription: &subscription_id,
                                result: methods::ChainHeadStorageEvent::Done { value: output },
                            }
                            .to_json_call_object_parameters(None)
                        }
                        Err(_) => methods::ServerToClient::chainHead_unstable_storageEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadStorageEvent::Inaccessible {},
                        }
                        .to_json_call_object_parameters(None),
                    }
                } else {
                    methods::ServerToClient::chainHead_unstable_storageEvent {
                        subscription: &subscription_id,
                        result: methods::ChainHeadStorageEvent::Disjoint {},
                    }
                    .to_json_call_object_parameters(None)
                };

                me.requests_subscriptions
                    .set_queued_notification(&state_machine_subscription, 0, response)
                    .await;

                me.requests_subscriptions
                    .stop_subscription(&state_machine_subscription)
                    .await;
                let _ = me
                    .subscriptions
                    .lock()
                    .await
                    .misc
                    .remove(&(subscription_id.to_owned(), SubscriptionTy::ChainHeadStorage));
            }
        };

        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(Box::pin(
                future::Abortable::new(task, abort_registration).map(|_| ()),
            ))
            .unwrap();
    }
}

fn convert_runtime_spec(
    runtime: &Result<executor::CoreVersion, runtime_service::RuntimeError>,
) -> methods::MaybeRuntimeSpec {
    match &runtime {
        Ok(runtime) => {
            let runtime = runtime.decode();
            methods::MaybeRuntimeSpec::Valid {
                spec: methods::RuntimeSpec {
                    impl_name: runtime.impl_name,
                    spec_name: runtime.spec_name,
                    impl_version: runtime.impl_version,
                    spec_version: runtime.spec_version,
                    authoring_version: runtime.authoring_version,
                    transaction_version: runtime.transaction_version,
                    apis: runtime
                        .apis
                        .map(|api| (methods::HexString(api.name_hash.to_vec()), api.version))
                        .collect(),
                },
            }
        }
        Err(error) => methods::MaybeRuntimeSpec::Invalid {
            error: error.to_string(),
        },
    }
}

#[derive(Debug, derive_more::Display)]
enum StorageQueryError {
    /// Error while finding the storage root hash of the requested block.
    #[display(fmt = "Unknown block")]
    FindStorageRootHashError,
    /// Error while retrieving the storage item from other nodes.
    #[display(fmt = "{}", _0)]
    StorageRetrieval(sync_service::StorageQueryError),
}

async fn account_nonce<TPlat: Platform>(
    relay_chain_sync: &Arc<runtime_service::RuntimeService<TPlat>>,
    account: methods::AccountId,
) -> Result<Vec<u8>, AnnounceNonceError> {
    // For each relay chain block, call `ParachainHost_persisted_validation_data` in
    // order to know where the parachains are.
    let (runtime_call_lock, virtual_machine) = relay_chain_sync
        .recent_best_block_runtime_lock()
        .await
        .start("AccountNonceApi_account_nonce", iter::once(&account.0))
        .await
        .map_err(AnnounceNonceError::Call)?;

    // TODO: move the logic below in the `src` directory

    let mut runtime_call = match read_only_runtime_host::run(read_only_runtime_host::Config {
        virtual_machine,
        function_to_call: "AccountNonceApi_account_nonce",
        parameter: iter::once(&account.0),
    }) {
        Ok(vm) => vm,
        Err((err, prototype)) => {
            runtime_call_lock.unlock(prototype);
            return Err(AnnounceNonceError::StartError(err));
        }
    };

    loop {
        match runtime_call {
            read_only_runtime_host::RuntimeHostVm::Finished(Ok(success)) => {
                let output = success.virtual_machine.value().as_ref().to_owned();
                runtime_call_lock.unlock(success.virtual_machine.into_prototype());
                break Ok(output);
            }
            read_only_runtime_host::RuntimeHostVm::Finished(Err(error)) => {
                runtime_call_lock.unlock(error.prototype);
                break Err(AnnounceNonceError::ReadOnlyRuntime(error.detail));
            }
            read_only_runtime_host::RuntimeHostVm::StorageGet(get) => {
                let storage_value = match runtime_call_lock.storage_entry(&get.key_as_vec()) {
                    Ok(v) => v,
                    Err(err) => {
                        runtime_call_lock.unlock(
                            read_only_runtime_host::RuntimeHostVm::StorageGet(get).into_prototype(),
                        );
                        return Err(AnnounceNonceError::Call(err));
                    }
                };
                runtime_call = get.inject_value(storage_value.map(iter::once));
            }
            read_only_runtime_host::RuntimeHostVm::NextKey(_) => {
                todo!() // TODO:
            }
            read_only_runtime_host::RuntimeHostVm::StorageRoot(storage_root) => {
                runtime_call = storage_root.resume(runtime_call_lock.block_storage_root());
            }
        }
    }
}

#[derive(derive_more::Display)]
enum AnnounceNonceError {
    Call(runtime_service::RuntimeCallError),
    StartError(host::StartErr),
    ReadOnlyRuntime(read_only_runtime_host::ErrorDetail),
}

async fn payment_query_info<TPlat: Platform>(
    relay_chain_sync: &Arc<runtime_service::RuntimeService<TPlat>>,
    extrinsic: &[u8],
) -> Result<methods::RuntimeDispatchInfo, PaymentQueryInfoError> {
    // For each relay chain block, call `ParachainHost_persisted_validation_data` in
    // order to know where the parachains are.
    let (runtime_call_lock, virtual_machine) = relay_chain_sync
        .recent_best_block_runtime_lock()
        .await
        .start(
            json_rpc::payment_info::PAYMENT_FEES_FUNCTION_NAME,
            json_rpc::payment_info::payment_info_parameters(extrinsic),
        )
        .await
        .map_err(PaymentQueryInfoError::Call)?;

    // TODO: move the logic below in the `src` directory

    let mut runtime_call = match read_only_runtime_host::run(read_only_runtime_host::Config {
        virtual_machine,
        function_to_call: json_rpc::payment_info::PAYMENT_FEES_FUNCTION_NAME,
        parameter: json_rpc::payment_info::payment_info_parameters(extrinsic),
    }) {
        Ok(vm) => vm,
        Err((err, prototype)) => {
            runtime_call_lock.unlock(prototype);
            return Err(PaymentQueryInfoError::StartError(err));
        }
    };

    loop {
        match runtime_call {
            read_only_runtime_host::RuntimeHostVm::Finished(Ok(success)) => {
                let decoded = json_rpc::payment_info::decode_payment_info(
                    success.virtual_machine.value().as_ref(),
                );

                runtime_call_lock.unlock(success.virtual_machine.into_prototype());
                match decoded {
                    Ok(d) => break Ok(d),
                    Err(err) => {
                        return Err(PaymentQueryInfoError::DecodeError(err));
                    }
                }
            }
            read_only_runtime_host::RuntimeHostVm::Finished(Err(error)) => {
                runtime_call_lock.unlock(error.prototype);
                break Err(PaymentQueryInfoError::ReadOnlyRuntime(error.detail));
            }
            read_only_runtime_host::RuntimeHostVm::StorageGet(get) => {
                let storage_value = match runtime_call_lock.storage_entry(&get.key_as_vec()) {
                    Ok(v) => v,
                    Err(err) => {
                        runtime_call_lock.unlock(
                            read_only_runtime_host::RuntimeHostVm::StorageGet(get).into_prototype(),
                        );
                        return Err(PaymentQueryInfoError::Call(err));
                    }
                };
                runtime_call = get.inject_value(storage_value.map(iter::once));
            }
            read_only_runtime_host::RuntimeHostVm::NextKey(_) => {
                todo!() // TODO:
            }
            read_only_runtime_host::RuntimeHostVm::StorageRoot(storage_root) => {
                runtime_call = storage_root.resume(runtime_call_lock.block_storage_root());
            }
        }
    }
}

#[derive(derive_more::Display)]
enum PaymentQueryInfoError {
    Call(runtime_service::RuntimeCallError),
    StartError(host::StartErr),
    ReadOnlyRuntime(read_only_runtime_host::ErrorDetail),
    DecodeError(json_rpc::payment_info::DecodeError),
}
