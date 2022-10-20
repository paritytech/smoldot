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
//! Create a new JSON-RPC service by calling [`service`] then [`ServicePrototype::start`].
//! Creating a JSON-RPC service spawns a background task (through [`StartConfig::tasks_executor`])
//! dedicated to processing JSON-RPC requests.
//!
//! In order to process a JSON-RPC request, call [`Frontend::queue_rpc_request`]. Later, the
//! JSON-RPC service can queue a response or, in the case of subscriptions, a notification. They
//! can be retrieved by calling [`Frontend::next_json_rpc_response`].
//!
//! In the situation where an attacker finds a JSON-RPC request that takes a long time to be
//! processed and continuously submits this same expensive request over and over again, the queue
//! of pending requests will start growing and use more and more memory. For this reason, if this
//! queue grows past [`Config::max_pending_requests`] items, [`Frontend::queue_rpc_request`]
//! will instead return an error.
//!

// TODO: doc
// TODO: re-review this once finished

mod chain_head;
mod getters;
mod state_chain;
mod transactions;

use crate::{
    network_service, platform::Platform, runtime_service, sync_service, transactions_service,
};

use alloc::{
    borrow::ToOwned as _,
    boxed::Box,
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec::Vec,
};
use core::{
    iter,
    num::{NonZeroU32, NonZeroUsize},
    sync::atomic,
    time::Duration,
};
use futures::{channel::mpsc, lock::Mutex, prelude::*};
use hashbrown::HashMap;
use smoldot::{
    chain::fork_tree,
    chain_spec,
    executor::{host, read_only_runtime_host},
    header,
    json_rpc::{self, methods, requests_subscriptions},
    libp2p::{multiaddr, PeerId},
    network::protocol,
};

/// Configuration for [`service`].
pub struct Config {
    /// Name of the chain, for logging purposes.
    ///
    /// > **Note**: This name will be directly printed out. Any special character should already
    /// >           have been filtered out from this name.
    pub log_name: String,

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

/// Creates a new JSON-RPC service with the given configuration.
///
/// Returns a handler that allows sending requests, and a [`ServicePrototype`] that must later
/// be initialized using [`ServicePrototype::start`].
///
/// Destroying the [`Frontend`] automatically shuts down the service.
pub fn service(config: Config) -> (Frontend, ServicePrototype) {
    let mut requests_subscriptions =
        requests_subscriptions::RequestsSubscriptions::new(requests_subscriptions::Config {
            max_clients: 1,
            max_requests_per_client: config.max_pending_requests,
            max_subscriptions_per_client: config.max_subscriptions,
        });

    let client_id = requests_subscriptions.add_client_mut().unwrap(); // Adding a client can fail only if the limit is reached.
    let requests_subscriptions = Arc::new(requests_subscriptions);

    let log_target = format!("json-rpc-{}", config.log_name);

    let (background_abort, background_abort_registration) = future::AbortHandle::new_pair();

    let frontend = Frontend {
        log_target: log_target.clone(),
        requests_subscriptions: requests_subscriptions.clone(),
        client_id,
        background_abort: Arc::new(background_abort),
    };

    let prototype = ServicePrototype {
        background_abort_registration,
        log_target,
        requests_subscriptions,
        max_subscriptions: config.max_subscriptions,
    };

    (frontend, prototype)
}

/// Handle that allows sending JSON-RPC requests on the service.
///
/// The [`Frontend`] can be cloned, in which case the clone will refer to the same JSON-RPC
/// service.
///
/// Destroying all the [`Frontend`]s automatically shuts down the associated service.
#[derive(Clone)]
pub struct Frontend {
    /// State machine holding all the clients, requests, and subscriptions.
    ///
    /// Shared with the [`Background`].
    requests_subscriptions: Arc<requests_subscriptions::RequestsSubscriptions>,

    /// Identifier of the unique client within the [`Frontend::requests_subscriptions`].
    client_id: requests_subscriptions::ClientId,

    /// Target to use when emitting logs.
    log_target: String,

    /// Handle to abort the background task that holds and processes the
    /// [`Frontend::requests_subscriptions`].
    background_abort: Arc<future::AbortHandle>,
}

impl Frontend {
    /// Queues the given JSON-RPC request to be processed in the background.
    ///
    /// An error is returned if [`Config::max_pending_requests`] is exceeded, which can happen
    /// if the requests take a long time to process or if [`Frontend::next_json_rpc_response`]
    /// isn't called often enough. Use [`HandleRpcError::into_json_rpc_error`] to build the
    /// JSON-RPC response to immediately send back to the user.
    pub fn queue_rpc_request(&self, json_rpc_request: String) -> Result<(), HandleRpcError> {
        // If the request isn't even a valid JSON-RPC request, we can't even send back a response.
        // We have no choice but to immediately refuse the request.
        if let Err(error) = json_rpc::parse::parse_call(&json_rpc_request) {
            log::warn!(
                target: &self.log_target,
                "Refused malformed JSON-RPC request: {}", error
            );
            return Err(HandleRpcError::MalformedJsonRpc(error));
        }

        // Logging the request before it is queued.
        if log::log_enabled!(log::Level::Debug) {
            log::debug!(
                target: &self.log_target,
                "PendingRequestsQueue <= {}",
                crate::util::truncate_str_iter(
                    json_rpc_request.chars().filter(|c| !c.is_control()),
                    100,
                ).collect::<String>()
            );
        }

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

    /// Waits until a JSON-RPC response has been generated, then returns it.
    ///
    /// If this function is called multiple times in parallel, the order in which the calls are
    /// responded to is unspecified.
    pub async fn next_json_rpc_response(&self) -> String {
        let message = self
            .requests_subscriptions
            .next_response(&self.client_id)
            .await;

        if log::log_enabled!(log::Level::Debug) {
            log::debug!(
                target: &self.log_target,
                "JSON-RPC <= {}",
                crate::util::truncate_str_iter(
                    message.chars().filter(|c| !c.is_control()),
                    100,
                ).collect::<String>()
            );
        }

        message
    }
}

impl Drop for Frontend {
    fn drop(&mut self) {
        // Call `abort()` if this was the last instance of the `Arc<AbortHandle>` (and thus the
        // last instance of `Frontend`).
        if let Some(background_abort) = Arc::get_mut(&mut self.background_abort) {
            background_abort.abort();
        }
    }
}

/// Prototype for a JSON-RPC service. Must be initialized using [`ServicePrototype::start`].
pub struct ServicePrototype {
    /// State machine holding all the clients, requests, and subscriptions.
    ///
    /// Shared with the [`Background`].
    requests_subscriptions: Arc<requests_subscriptions::RequestsSubscriptions>,

    /// Target to use when emitting logs.
    log_target: String,

    background_abort_registration: future::AbortRegistration,

    /// Same as [`Config::max_subscriptions`].
    max_subscriptions: u32,
}

/// Configuration for a JSON-RPC service.
pub struct StartConfig<'a, TPlat: Platform> {
    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(String, future::BoxFuture<'static, ()>) + Send>,

    /// Access to the network, and index of the chain to sync from the point of view of the
    /// network service.
    pub network_service: (Arc<network_service::NetworkService<TPlat>>, usize),

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
    /// >           [`ServicePrototype::start`] function could in theory use the
    /// >           [`StartConfig::chain_spec`] parameter to derive this value, doing so is quite
    /// >           expensive. We prefer to require this value from the upper layer instead, as
    /// >           it is most likely needed anyway.
    pub genesis_block_hash: [u8; 32],

    /// Hash of the storage trie root of the genesis block of the chain.
    ///
    /// > **Note**: This can be derived from a [`chain_spec::ChainSpec`]. While the
    /// >           [`ServicePrototype::start`] function could in theory use the
    /// >           [`StartConfig::chain_spec`] parameter to derive this value, doing so is quite
    /// >           expensive. We prefer to require this value from the upper layer instead, as
    /// >           it is most likely needed anyway.
    pub genesis_block_state_root: [u8; 32],

    /// Maximum number of JSON-RPC requests that can be processed simultaneously.
    ///
    /// This parameter is necessary in order to prevent users from using up too much memory within
    /// the client.
    pub max_parallel_requests: NonZeroU32,
}

impl ServicePrototype {
    /// Consumes this prototype and starts the service through [`StartConfig::tasks_executor`].
    pub fn start<TPlat: Platform>(self, mut config: StartConfig<'_, TPlat>) {
        // Channel used in the background in order to spawn new tasks scoped to the background.
        let (new_child_tasks_tx, new_child_tasks_rx) = mpsc::unbounded();

        let background = Arc::new(Background {
            log_target: self.log_target.clone(),
            requests_subscriptions: self.requests_subscriptions,
            new_child_tasks_tx: Mutex::new(new_child_tasks_tx),
            chain_name: config.chain_spec.name().to_owned(),
            chain_ty: config.chain_spec.chain_type().to_owned(),
            chain_is_live: config.chain_spec.has_live_network(),
            chain_properties_json: config.chain_spec.properties().to_owned(),
            peer_id_base58: config.peer_id.to_base58(),
            system_name: config.system_name,
            system_version: config.system_version,
            network_service: config.network_service,
            sync_service: config.sync_service,
            runtime_service: config.runtime_service,
            transactions_service: config.transactions_service,
            cache: Mutex::new(Cache {
                recent_pinned_blocks: lru::LruCache::with_hasher(
                    NonZeroUsize::new(32).unwrap(),
                    Default::default(),
                ),
                subscription_id: None,
                block_state_root_hashes_numbers: lru::LruCache::with_hasher(
                    NonZeroUsize::new(32).unwrap(),
                    Default::default(),
                ),
            }),
            genesis_block: config.genesis_block_hash,
            next_subscription_id: atomic::AtomicU64::new(0),
            subscriptions: Mutex::new(Subscriptions {
                misc: HashMap::with_capacity_and_hasher(
                    usize::try_from(self.max_subscriptions).unwrap_or(usize::max_value()),
                    Default::default(),
                ),
                chain_head_follow: HashMap::with_capacity_and_hasher(
                    usize::try_from(self.max_subscriptions).unwrap_or(usize::max_value()),
                    Default::default(),
                ),
            }),
        });

        // Spawns the background task that actually runs the logic of that JSON-RPC service.
        // This background task is abortable through the `background_abort` handle.
        (config.tasks_executor)(self.log_target, {
            let max_parallel_requests = config.max_parallel_requests;
            future::Abortable::new(
                async move {
                    background
                        .run(new_child_tasks_rx, max_parallel_requests)
                        .await
                },
                self.background_abort_registration,
            )
            .map(|_| ())
            .boxed()
        });
    }
}

/// Error potentially returned when queuing a JSON-RPC request.
#[derive(Debug, derive_more::Display)]
pub enum HandleRpcError {
    /// The JSON-RPC service cannot process this request, as it is already too busy.
    #[display(
        fmt = "The JSON-RPC service cannot process this request, as it is already too busy."
    )]
    Overloaded {
        /// Request that was being queued.
        json_rpc_request: String,
    },
    /// The request isn't a valid JSON-RPC request.
    #[display(fmt = "The request isn't a valid JSON-RPC request: {}", _0)]
    MalformedJsonRpc(json_rpc::parse::ParseError),
}

impl HandleRpcError {
    /// Builds the JSON-RPC error string corresponding to this error.
    ///
    /// Returns `None` if the JSON-RPC requests isn't valid JSON-RPC or if the call was a
    /// notification.
    pub fn into_json_rpc_error(self) -> Option<String> {
        let json_rpc_request = match self {
            HandleRpcError::Overloaded { json_rpc_request } => json_rpc_request,
            HandleRpcError::MalformedJsonRpc(_) => return None,
        };

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
    ///
    /// Only requests that are valid JSON-RPC are insert into the state machine. However, requests
    /// can try to call an unknown method, or have invalid parameters.
    requests_subscriptions: Arc<requests_subscriptions::RequestsSubscriptions>,

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
    /// See [`StartConfig::peer_id`]. The only use for this field is to send the Base58 encoding of
    /// the [`PeerId`]. Consequently, we store the conversion to Base58 ahead of time.
    peer_id_base58: String,
    /// Value to return when the `system_name` RPC is called.
    system_name: String,
    /// Value to return when the `system_version` RPC is called.
    system_version: String,

    /// See [`StartConfig::network_service`].
    network_service: (Arc<network_service::NetworkService<TPlat>>, usize),
    /// See [`StartConfig::sync_service`].
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    /// See [`StartConfig::runtime_service`].
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    /// See [`StartConfig::transactions_service`].
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

    /// State trie root hashes and numbers of blocks that were not in
    /// [`Cache::recent_pinned_blocks`].
    ///
    /// The state trie root hash can also be an `Err` if the network request failed or if the
    /// header is of an invalid format.
    ///
    /// The state trie root hash and number are wrapped in a `Shared` future. When multiple
    /// requests need the state trie root hash and number of the same block, they are only queried
    /// once and the query is inserted in the cache while in progress. This way, the multiple
    /// requests can all wait on that single future.
    ///
    /// Most of the time, the JSON-RPC client will query blocks that are found in
    /// [`Cache::recent_pinned_blocks`], but occasionally it will query older blocks. When the
    /// storage of an older block is queried, it is common for the JSON-RPC client to make several
    /// storage requests to that same old block. In order to avoid having to retrieve the state
    /// trie root hash multiple, we store these hashes in this LRU cache.
    block_state_root_hashes_numbers: lru::LruCache<
        [u8; 32],
        future::MaybeDone<
            future::Shared<
                future::BoxFuture<'static, Result<([u8; 32], u64), StateTrieRootHashError>>,
            >,
        >,
        fnv::FnvBuildHasher,
    >,
}

impl<TPlat: Platform> Background<TPlat> {
    /// Runs the background task forever.
    ///
    /// This should only ever be called once for each service.
    async fn run(
        self: Arc<Self>,
        mut new_child_tasks_rx: mpsc::UnboundedReceiver<future::BoxFuture<'static, ()>>,
        max_parallel_requests: NonZeroU32,
    ) -> ! {
        // The body of this function consists in building a list of tasks, then running them.
        let mut tasks = stream::FuturesUnordered::new();

        // A certain number of tasks (`max_parallel_requests`) are dedicated to pulling requests
        // from the inner state machine and processing them.
        // Each task can only process one request at a time, which is why we spawn one task per
        // desired level of parallelism.
        for _ in 0..max_parallel_requests.get() {
            let me = self.clone();
            tasks.push(
                async move {
                    loop {
                        me.handle_request().await;

                        // We yield once between each request in order to politely let other tasks
                        // do some work and not monopolize the CPU.
                        crate::util::yield_twice().await;
                    }
                }
                .boxed(),
            );
        }

        // Spawn one task dedicated to filling the `Cache` with new blocks from the runtime
        // service.
        // TODO: this is actually racy, as a block subscription task could report a new block to a client, and then client can query it, before this block has been been added to the cache
        // TODO: extract to separate function
        tasks.push({
            let me = self.clone();
            async move {
                loop {
                    let mut cache = me.cache.lock().await;

                    // Subscribe to new runtime service blocks in order to push them in the
                    // cache as soon as they are available.
                    // The buffer size should be large enough so that, if the CPU is busy, it
                    // doesn't become full before the execution of this task resumes.
                    // The maximum number of pinned block is ignored, as this maximum is a way to
                    // avoid malicious behaviors. This code is by definition not considered
                    // malicious.
                    let mut subscribe_all = me
                        .runtime_service
                        .subscribe_all(
                            "json-rpc-blocks-cache",
                            32,
                            NonZeroUsize::new(usize::max_value()).unwrap(),
                        )
                        .await;

                    cache.subscription_id = Some(subscribe_all.new_blocks.id());
                    cache.recent_pinned_blocks.clear();
                    debug_assert!(cache.recent_pinned_blocks.cap().get() >= 1);

                    let finalized_block_hash = header::hash_from_scale_encoded_header(
                        &subscribe_all.finalized_block_scale_encoded_header,
                    );
                    cache.recent_pinned_blocks.put(
                        finalized_block_hash,
                        subscribe_all.finalized_block_scale_encoded_header,
                    );

                    for block in subscribe_all.non_finalized_blocks_ancestry_order {
                        if cache.recent_pinned_blocks.len()
                            == cache.recent_pinned_blocks.cap().get()
                        {
                            let (hash, _) = cache.recent_pinned_blocks.pop_lru().unwrap();
                            subscribe_all.new_blocks.unpin_block(&hash).await;
                        }

                        let hash =
                            header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                        cache
                            .recent_pinned_blocks
                            .put(hash, block.scale_encoded_header);
                    }

                    drop(cache);

                    loop {
                        let notification = subscribe_all.new_blocks.next().await;
                        match notification {
                            Some(runtime_service::Notification::Block(block)) => {
                                let mut cache = me.cache.lock().await;

                                if cache.recent_pinned_blocks.len()
                                    == cache.recent_pinned_blocks.cap().get()
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
                            Some(runtime_service::Notification::Finalized { .. })
                            | Some(runtime_service::Notification::BestBlockChanged { .. }) => {}
                            None => break,
                        }
                    }
                }
            }
            .boxed()
        });

        // Now that `tasks` is full, we start running them forever.
        // The `new_child_tasks_rx` channel is also polled, in order to be able to spawn new
        // tasks.
        // TODO: consider removing this `new_child_tasks_rx` mechanism, in order to be guaranteed a fixed number of tasks
        loop {
            futures::select! {
                () = tasks.select_next_some() => {},
                task = new_child_tasks_rx.next() => {
                    let task = task.unwrap();
                    tasks.push(task);
                }
            }
        }
    }

    /// Pulls one request from the inner state machine, and processes it.
    async fn handle_request(self: &Arc<Self>) {
        let (json_rpc_request, state_machine_request_id) =
            self.requests_subscriptions.next_request().await;
        log::debug!(target: &self.log_target, "PendingRequestsQueue => {}", 
            crate::util::truncate_str_iter(
                json_rpc_request.chars().filter(|c| !c.is_control()),
                100,
            ).collect::<String>());

        // Check whether the JSON-RPC request is correct, and bail out if it isn't.
        let (request_id, call) = match methods::parse_json_call(&json_rpc_request) {
            Ok((request_id, call)) => (request_id, call),
            Err(methods::ParseError::Method { request_id, error }) => {
                log::warn!(
                    target: &self.log_target,
                    "Error in JSON-RPC method call with id {:?}: {}", request_id, error
                );
                self.requests_subscriptions
                    .respond(&state_machine_request_id, error.to_json_error(request_id))
                    .await;
                return;
            }
            Err(_) => {
                // We make sure to not insert in the state machine requests that are not valid
                // JSON-RPC requests.
                unreachable!()
            }
        };

        // Each call is handled in a separate method.
        match call {
            methods::MethodCall::author_pendingExtrinsics {} => {
                self.author_pending_extrinsics(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::author_submitExtrinsic { transaction } => {
                self.author_submit_extrinsic(request_id, &state_machine_request_id, transaction)
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
                self.author_unwatch_extrinsic(
                    request_id,
                    &state_machine_request_id,
                    &*subscription,
                )
                .await;
            }
            methods::MethodCall::chain_getBlock { hash } => {
                self.chain_get_block(request_id, &state_machine_request_id, hash)
                    .await;
            }
            methods::MethodCall::chain_getBlockHash { height } => {
                self.chain_get_block_hash(request_id, &state_machine_request_id, height)
                    .await;
            }
            methods::MethodCall::chain_getFinalizedHead {} => {
                self.chain_get_finalized_head(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::chain_getHeader { hash } => {
                self.chain_get_header(request_id, &state_machine_request_id, hash)
                    .await;
            }
            methods::MethodCall::chain_subscribeAllHeads {} => {
                self.chain_subscribe_all_heads(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::chain_subscribeFinalizedHeads {} => {
                self.chain_subscribe_finalized_heads(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::chain_subscribeNewHeads {} => {
                self.chain_subscribe_new_heads(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::chain_unsubscribeAllHeads { subscription } => {
                self.chain_unsubscribe_all_heads(
                    request_id,
                    &state_machine_request_id,
                    subscription,
                )
                .await;
            }
            methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription } => {
                self.chain_unsubscribe_finalized_heads(
                    request_id,
                    &state_machine_request_id,
                    subscription,
                )
                .await;
            }
            methods::MethodCall::chain_unsubscribeNewHeads { subscription } => {
                self.chain_unsubscribe_new_heads(
                    request_id,
                    &state_machine_request_id,
                    subscription,
                )
                .await;
            }
            methods::MethodCall::payment_queryInfo { extrinsic, hash } => {
                self.payment_query_info(
                    request_id,
                    &state_machine_request_id,
                    &extrinsic.0,
                    hash.as_ref().map(|h| &h.0),
                )
                .await;
            }
            methods::MethodCall::rpc_methods {} => {
                self.rpc_methods(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::state_call {
                name,
                parameters,
                hash,
            } => {
                self.state_call(
                    request_id,
                    &state_machine_request_id,
                    &name,
                    parameters,
                    hash,
                )
                .await;
            }
            methods::MethodCall::state_getKeys { prefix, hash } => {
                self.state_get_keys(request_id, &state_machine_request_id, prefix, hash)
                    .await;
            }
            methods::MethodCall::state_getKeysPaged {
                prefix,
                count,
                start_key,
                hash,
            } => {
                self.state_get_keys_paged(
                    request_id,
                    &state_machine_request_id,
                    prefix,
                    count,
                    start_key,
                    hash,
                )
                .await;
            }
            methods::MethodCall::state_queryStorageAt { keys, at } => {
                self.state_query_storage_at(request_id, &state_machine_request_id, keys, at)
                    .await;
            }
            methods::MethodCall::state_getMetadata { hash } => {
                self.state_get_metadata(request_id, &state_machine_request_id, hash)
                    .await;
            }
            methods::MethodCall::state_getStorage { key, hash } => {
                self.state_get_storage(request_id, &state_machine_request_id, key, hash)
                    .await;
            }
            methods::MethodCall::state_subscribeRuntimeVersion {} => {
                self.state_subscribe_runtime_version(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::state_unsubscribeRuntimeVersion { subscription } => {
                self.state_unsubscribe_runtime_version(
                    request_id,
                    &state_machine_request_id,
                    &*subscription,
                )
                .await;
            }
            methods::MethodCall::state_subscribeStorage { list } => {
                self.state_subscribe_storage(request_id, &state_machine_request_id, list)
                    .await;
            }
            methods::MethodCall::state_unsubscribeStorage { subscription } => {
                self.state_unsubscribe_storage(
                    request_id,
                    &state_machine_request_id,
                    &*subscription,
                )
                .await;
            }
            methods::MethodCall::state_getRuntimeVersion { at } => {
                self.state_get_runtime_version(
                    request_id,
                    &state_machine_request_id,
                    at.as_ref().map(|h| &h.0),
                )
                .await;
            }
            methods::MethodCall::system_accountNextIndex { account } => {
                self.account_next_index(request_id, &state_machine_request_id, account)
                    .await;
            }
            methods::MethodCall::system_chain {} => {
                self.system_chain(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::system_chainType {} => {
                self.system_chain_type(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::system_health {} => {
                self.system_health(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::system_localListenAddresses {} => {
                self.system_local_listen_addresses(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::system_localPeerId {} => {
                self.system_local_peer_id(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::system_name {} => {
                self.system_name(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::system_nodeRoles {} => {
                self.system_node_roles(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::system_peers {} => {
                self.system_peers(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::system_properties {} => {
                self.system_properties(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::system_version {} => {
                self.system_version(request_id, &state_machine_request_id)
                    .await;
            }

            methods::MethodCall::chainHead_unstable_stopBody { subscription } => {
                self.chain_head_unstable_stop_body(
                    request_id,
                    &state_machine_request_id,
                    &*subscription,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_body {
                follow_subscription,
                hash,
                network_config,
            } => {
                self.chain_head_unstable_body(
                    request_id,
                    &state_machine_request_id,
                    &*follow_subscription,
                    hash,
                    network_config,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_call {
                follow_subscription,
                hash,
                function,
                call_parameters,
                network_config,
            } => {
                self.chain_head_call(
                    request_id,
                    &state_machine_request_id,
                    &*follow_subscription,
                    hash,
                    &*function,
                    call_parameters,
                    network_config,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_stopCall { subscription } => {
                self.chain_head_unstable_stop_call(
                    request_id,
                    &state_machine_request_id,
                    &*subscription,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_stopStorage { subscription } => {
                self.chain_head_unstable_stop_storage(
                    request_id,
                    &state_machine_request_id,
                    &*subscription,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_storage {
                follow_subscription,
                hash,
                key,
                child_key,
                network_config,
            } => {
                self.chain_head_storage(
                    request_id,
                    &state_machine_request_id,
                    &*follow_subscription,
                    hash,
                    key,
                    child_key,
                    network_config,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_follow { runtime_updates } => {
                self.chain_head_follow(request_id, &state_machine_request_id, runtime_updates)
                    .await;
            }
            methods::MethodCall::chainHead_unstable_genesisHash {} => {
                self.chain_head_unstable_genesis_hash(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::chainHead_unstable_header {
                follow_subscription,
                hash,
            } => {
                self.chain_head_unstable_header(
                    request_id,
                    &state_machine_request_id,
                    &*follow_subscription,
                    hash,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_unpin {
                follow_subscription,
                hash,
            } => {
                self.chain_head_unstable_unpin(
                    request_id,
                    &state_machine_request_id,
                    &*follow_subscription,
                    hash,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_unfollow {
                follow_subscription,
            } => {
                self.chain_head_unstable_unfollow(
                    request_id,
                    &state_machine_request_id,
                    &*follow_subscription,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_finalizedDatabase { max_size_bytes } => {
                self.chain_head_unstable_finalized_database(
                    request_id,
                    &state_machine_request_id,
                    max_size_bytes,
                )
                .await;
            }
            methods::MethodCall::chainSpec_unstable_chainName {} => {
                self.chain_spec_unstable_chain_name(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::chainSpec_unstable_genesisHash {} => {
                self.chain_spec_unstable_genesis_hash(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::chainSpec_unstable_properties {} => {
                self.chain_spec_unstable_properties(request_id, &state_machine_request_id)
                    .await;
            }
            methods::MethodCall::sudo_unstable_p2pDiscover { multiaddr } => {
                self.sudo_unstable_p2p_discover(request_id, &state_machine_request_id, &*multiaddr)
                    .await;
            }
            methods::MethodCall::sudo_unstable_version {} => {
                self.sudo_unstable_version(request_id, &state_machine_request_id)
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
                self.transaction_unstable_unwatch(
                    request_id,
                    &state_machine_request_id,
                    &*subscription,
                )
                .await;
            }

            _method @ (methods::MethodCall::account_nextIndex { .. }
            | methods::MethodCall::author_hasKey { .. }
            | methods::MethodCall::author_hasSessionKeys { .. }
            | methods::MethodCall::author_insertKey { .. }
            | methods::MethodCall::author_removeExtrinsic { .. }
            | methods::MethodCall::author_rotateKeys { .. }
            | methods::MethodCall::babe_epochAuthorship { .. }
            | methods::MethodCall::childstate_getKeys { .. }
            | methods::MethodCall::childstate_getStorage { .. }
            | methods::MethodCall::childstate_getStorageHash { .. }
            | methods::MethodCall::childstate_getStorageSize { .. }
            | methods::MethodCall::grandpa_roundState { .. }
            | methods::MethodCall::offchain_localStorageGet { .. }
            | methods::MethodCall::offchain_localStorageSet { .. }
            | methods::MethodCall::state_getPairs { .. }
            | methods::MethodCall::state_getReadProof { .. }
            | methods::MethodCall::state_getStorageHash { .. }
            | methods::MethodCall::state_getStorageSize { .. }
            | methods::MethodCall::state_queryStorage { .. }
            | methods::MethodCall::system_addReservedPeer { .. }
            | methods::MethodCall::system_dryRun { .. }
            | methods::MethodCall::system_networkState { .. }
            | methods::MethodCall::system_removeReservedPeer { .. }
            | methods::MethodCall::network_unstable_subscribeEvents { .. }
            | methods::MethodCall::network_unstable_unsubscribeEvents { .. }) => {
                // TODO: implement the ones that make sense to implement ^
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

    /// Handles a call to [`methods::MethodCall::sudo_unstable_p2pDiscover`].
    async fn sudo_unstable_p2p_discover(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        multiaddr: &str,
    ) {
        let response = match multiaddr.parse::<multiaddr::Multiaddr>() {
            Ok(mut addr) if matches!(addr.iter().last(), Some(multiaddr::ProtocolRef::P2p(_))) => {
                let peer_id_bytes = match addr.iter().last() {
                    Some(multiaddr::ProtocolRef::P2p(peer_id)) => peer_id.into_owned(),
                    _ => unreachable!(),
                };
                addr.pop();

                match PeerId::from_bytes(peer_id_bytes) {
                    Ok(peer_id) => {
                        self.network_service
                            .0
                            .discover(
                                &TPlat::now(),
                                self.network_service.1,
                                iter::once((peer_id, iter::once(addr))),
                                false,
                            )
                            .await;
                        methods::Response::sudo_unstable_p2pDiscover(())
                            .to_json_response(request_id)
                    }
                    Err(_) => json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        Some(&serde_json::to_string("multiaddr doesn't end with /p2p").unwrap()),
                    ),
                }
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
            .respond(state_machine_request_id, response)
            .await;
    }

    /// Obtain the state trie root hash and number of the given block, and make sure to put it
    /// in cache.
    async fn state_trie_root_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<([u8; 32], u64), StateTrieRootHashError> {
        let fetch = {
            // Try to find an existing entry in cache, and if not create one.
            let mut cache_lock = self.cache.lock().await;

            // Look in `recent_pinned_blocks`.
            match cache_lock
                .recent_pinned_blocks
                .get(hash)
                .map(|h| header::decode(h, self.sync_service.block_number_bytes()))
            {
                Some(Ok(header)) => return Ok((*header.state_root, header.number)),
                Some(Err(err)) => return Err(StateTrieRootHashError::HeaderDecodeError(err)), // TODO: can this actually happen? unclear
                None => {}
            }

            // Look in `block_state_root_hashes`.
            match cache_lock.block_state_root_hashes_numbers.get(hash) {
                Some(future::MaybeDone::Done(Ok(val))) => return Ok(*val),
                Some(future::MaybeDone::Future(f)) => f.clone(),
                Some(future::MaybeDone::Gone) => unreachable!(), // We never use `Gone`.
                Some(future::MaybeDone::Done(Err(
                    err @ StateTrieRootHashError::HeaderDecodeError(_),
                ))) => {
                    // In case of a fatal error, return immediately.
                    return Err(err.clone());
                }
                Some(future::MaybeDone::Done(Err(StateTrieRootHashError::NetworkQueryError)))
                | None => {
                    // No existing cache entry. Create the future that will perform the fetch
                    // but do not actually start doing anything now.
                    let fetch = {
                        let sync_service = self.sync_service.clone();
                        let hash = *hash;
                        async move {
                            // The sync service knows which peers are potentially aware of
                            // this block.
                            let result = sync_service
                                .clone()
                                .block_query_unknown_number(
                                    hash,
                                    protocol::BlocksRequestFields {
                                        header: true,
                                        body: false,
                                        justifications: false,
                                    },
                                    4,
                                    Duration::from_secs(8),
                                    NonZeroU32::new(2).unwrap(),
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
                                let decoded =
                                    header::decode(&header, sync_service.block_number_bytes())
                                        .unwrap();
                                Ok((*decoded.state_root, decoded.number))
                            } else {
                                // TODO: better error details?
                                Err(StateTrieRootHashError::NetworkQueryError)
                            }
                        }
                    };

                    // Insert the future in the cache, so that any other call will use the same
                    // future.
                    let wrapped = fetch.boxed().shared();
                    cache_lock
                        .block_state_root_hashes_numbers
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
        keys: impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone,
        hash: &[u8; 32],
        total_attempts: u32,
        timeout_per_request: Duration,
        max_parallel: NonZeroU32,
    ) -> Result<Vec<Option<Vec<u8>>>, StorageQueryError> {
        let (state_trie_root_hash, block_number) = self
            .state_trie_root_hash(&hash)
            .await
            .map_err(StorageQueryError::FindStorageRootHashError)?;

        let result = self
            .sync_service
            .clone()
            .storage_query(
                block_number,
                hash,
                &state_trie_root_hash,
                keys,
                total_attempts,
                timeout_per_request,
                max_parallel,
            )
            .await
            .map_err(StorageQueryError::StorageRetrieval)?;

        Ok(result)
    }

    /// Obtain a lock to the runtime of the given block against the runtime service.
    // TODO: return better error?
    async fn runtime_lock<'a>(
        self: &'a Arc<Self>,
        block_hash: &[u8; 32],
    ) -> Result<runtime_service::RuntimeLock<'a, TPlat>, RuntimeCallError> {
        let cache_lock = self.cache.lock().await;

        // Try to find the block in the cache of recent blocks. Most of the time, the call target
        // should be in there.
        let lock = if cache_lock.recent_pinned_blocks.contains(block_hash) {
            // The runtime service has the block pinned, meaning that we can ask the runtime
            // service to perform the call.
            self.runtime_service
                .pinned_block_runtime_lock(cache_lock.subscription_id.clone().unwrap(), block_hash)
                .await
                .ok()
        } else {
            None
        };

        Ok(if let Some(lock) = lock {
            lock
        } else {
            // Second situation: the block is not in the cache of recent blocks. This isn't great.
            drop::<futures::lock::MutexGuard<_>>(cache_lock);

            // The only solution is to download the runtime of the block in question from the network.

            // TODO: considering caching the runtime code the same way as the state trie root hash

            // In order to grab the runtime code and perform the call network request, we need
            // to know the state trie root hash and the height of the block.
            let (state_trie_root_hash, block_number) = self
                .state_trie_root_hash(block_hash)
                .await
                .map_err(RuntimeCallError::FindStorageRootHashError)?;

            // Download the runtime of this block. This takes a long time as the runtime is rather
            // big (around 1MiB in general).
            let (storage_code, storage_heap_pages) = {
                let mut code_query_result = self
                    .sync_service
                    .clone()
                    .storage_query(
                        block_number,
                        block_hash,
                        &state_trie_root_hash,
                        iter::once(&b":code"[..]).chain(iter::once(&b":heappages"[..])),
                        3,
                        Duration::from_secs(20),
                        NonZeroU32::new(1).unwrap(),
                    )
                    .await
                    .map_err(runtime_service::RuntimeCallError::StorageQuery)
                    .map_err(RuntimeCallError::Call)?;
                let heap_pages = code_query_result.pop().unwrap();
                let code = code_query_result.pop().unwrap();
                (code, heap_pages)
            };

            // Give the code and heap pages to the runtime service. The runtime service will
            // try to find any similar runtime it might have, and if not will compile it.
            let pinned_runtime_id = self
                .runtime_service
                .compile_and_pin_runtime(storage_code, storage_heap_pages)
                .await;

            let precall = self
                .runtime_service
                .pinned_runtime_lock(
                    pinned_runtime_id.clone(),
                    *block_hash,
                    block_number,
                    state_trie_root_hash,
                )
                .await;

            // TODO: consider keeping pinned runtimes in a cache instead
            self.runtime_service.unpin_runtime(pinned_runtime_id).await;

            precall
        })
    }

    /// Performs a runtime call to a random block.
    // TODO: maybe add a parameter to check for a runtime API?
    async fn runtime_call(
        self: &Arc<Self>,
        block_hash: &[u8; 32],
        function_to_call: &str,
        call_parameters: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
        total_attempts: u32,
        timeout_per_request: Duration,
        max_parallel: NonZeroU32,
    ) -> Result<Vec<u8>, RuntimeCallError> {
        // This function contains two steps: obtaining the runtime of the block in question,
        // then performing the actual call. The first step is the longest and most difficult.
        let precall = self.runtime_lock(block_hash).await?;

        let (runtime_call_lock, virtual_machine) = precall
            .start(
                function_to_call,
                call_parameters.clone(),
                total_attempts,
                timeout_per_request,
                max_parallel,
            )
            .await
            .unwrap(); // TODO: don't unwrap

        // Now that we have obtained the virtual machine, we can perform the call.
        // This is a CPU-only operation that executes the virtual machine.
        // The virtual machine might access the storage.
        // TODO: finish doc

        let mut runtime_call = match read_only_runtime_host::run(read_only_runtime_host::Config {
            virtual_machine,
            function_to_call,
            parameter: call_parameters,
        }) {
            Ok(vm) => vm,
            Err((err, prototype)) => {
                runtime_call_lock.unlock(prototype);
                return Err(RuntimeCallError::StartError(err));
            }
        };

        loop {
            match runtime_call {
                read_only_runtime_host::RuntimeHostVm::Finished(Ok(success)) => {
                    let output = success.virtual_machine.value().as_ref().to_vec();
                    runtime_call_lock.unlock(success.virtual_machine.into_prototype());
                    break Ok(output);
                }
                read_only_runtime_host::RuntimeHostVm::Finished(Err(error)) => {
                    runtime_call_lock.unlock(error.prototype);
                    break Err(RuntimeCallError::ReadOnlyRuntime(error.detail));
                }
                read_only_runtime_host::RuntimeHostVm::StorageGet(get) => {
                    let storage_value = match runtime_call_lock.storage_entry(&get.key_as_vec()) {
                        Ok(v) => v,
                        Err(err) => {
                            runtime_call_lock.unlock(
                                read_only_runtime_host::RuntimeHostVm::StorageGet(get)
                                    .into_prototype(),
                            );
                            break Err(RuntimeCallError::Call(err));
                        }
                    };
                    runtime_call = get.inject_value(storage_value.map(iter::once));
                }
                read_only_runtime_host::RuntimeHostVm::NextKey(nk) => {
                    // TODO:
                    runtime_call_lock.unlock(
                        read_only_runtime_host::RuntimeHostVm::NextKey(nk).into_prototype(),
                    );
                    break Err(RuntimeCallError::NextKeyForbidden);
                }
                read_only_runtime_host::RuntimeHostVm::StorageRoot(storage_root) => {
                    runtime_call = storage_root.resume(runtime_call_lock.block_storage_root());
                }
            }
        }
    }
}

#[derive(Debug, derive_more::Display)]
enum StorageQueryError {
    /// Error while finding the storage root hash of the requested block.
    #[display(fmt = "Failed to obtain block state trie root: {}", _0)]
    FindStorageRootHashError(StateTrieRootHashError),
    /// Error while retrieving the storage item from other nodes.
    #[display(fmt = "{}", _0)]
    StorageRetrieval(sync_service::StorageQueryError),
}

// TODO: doc and properly derive Display
#[derive(Debug, derive_more::Display, Clone)]
enum RuntimeCallError {
    /// Error while finding the storage root hash of the requested block.
    #[display(fmt = "Failed to obtain block state trie root: {}", _0)]
    FindStorageRootHashError(StateTrieRootHashError),
    Call(runtime_service::RuntimeCallError),
    StartError(host::StartErr),
    ReadOnlyRuntime(read_only_runtime_host::ErrorDetail),
    NextKeyForbidden,
}

/// Error potentially returned by [`Background::state_trie_root_hash`].
#[derive(Debug, derive_more::Display, Clone)]
enum StateTrieRootHashError {
    /// Failed to decode block header.
    HeaderDecodeError(header::Error),
    /// Error while fetching block header from network.
    NetworkQueryError,
}
