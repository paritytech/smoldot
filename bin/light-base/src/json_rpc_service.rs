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

use futures::{
    channel::{mpsc, oneshot},
    future::FusedFuture as _,
    lock::Mutex,
    prelude::*,
};
use smoldot::{
    chain_spec,
    executor::{host, read_only_runtime_host},
    header,
    json_rpc::{self, methods},
    libp2p::PeerId,
    network::protocol,
};
use std::{
    collections::HashMap,
    iter,
    marker::PhantomData,
    num::NonZeroU32,
    str,
    sync::{atomic, Arc},
    time::Duration,
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
    /// Channel to send JSON-RPC requests to the background task.
    ///
    /// Limited to [`Config::max_pending_requests`] elements.
    new_requests_in: mpsc::Sender<String>,

    /// Target to use when emitting logs.
    log_target: String,

    /// Pins the `TPlat` generic.
    platform: PhantomData<fn() -> TPlat>,
}

impl<TPlat: Platform> JsonRpcService<TPlat> {
    /// Creates a new JSON-RPC service with the given configuration.
    pub fn new(mut config: Config<'_, TPlat>) -> JsonRpcService<TPlat> {
        // Channel from the foreground to the background.
        // Requests are dropped if the channel is full.
        let (new_requests_in, new_requests_rx) = mpsc::channel(
            usize::try_from(config.max_pending_requests.get()).unwrap_or(usize::max_value()) - 1,
        );

        let log_target = format!("json-rpc-{}", config.log_name);
        let client = JsonRpcService {
            log_target: log_target.clone(),
            new_requests_in,
            platform: PhantomData,
        };

        // Channel used in the background in order to spawn new tasks scoped to the background.
        let (new_child_tasks_tx, mut new_child_tasks_rx) = mpsc::unbounded();

        let background = Arc::new(Background {
            log_target,
            new_requests_rx: Mutex::new(new_requests_rx),
            responses_sender: Mutex::new(config.responses_sender),
            new_child_tasks_tx: Mutex::new(new_child_tasks_tx),
            max_subscriptions: usize::try_from(config.max_subscriptions)
                .unwrap_or(usize::max_value()),
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
            blocks: Mutex::new(Blocks {
                known_blocks: lru::LruCache::new(256),
                best_block: [0; 32],      // Filled below.
                finalized_block: [0; 32], // Filled below.
            }),
            genesis_block: config.genesis_block_hash,
            next_subscription: atomic::AtomicU64::new(0),
            subscriptions: Mutex::new(HashMap::with_capacity_and_hasher(
                usize::try_from(config.max_subscriptions).unwrap_or(usize::max_value()),
                Default::default(),
            )),
        });

        // Spawns the background task that actually runs the logic of that JSON-RPC service.
        let max_parallel_requests = config.max_parallel_requests;
        (config.tasks_executor)(
            "json-rpc-service".into(),
            async move {
                // TODO: use subscribe_all?
                let (finalized_block_header, mut finalized_blocks_subscription) =
                    background.runtime_service.subscribe_finalized().await;
                let finalized_block_hash =
                    header::hash_from_scale_encoded_header(&finalized_block_header);
                let (best_block_header, mut best_blocks_subscription) =
                    background.runtime_service.subscribe_best().await;
                let best_block_hash = header::hash_from_scale_encoded_header(&best_block_header);

                {
                    let mut blocks = background.blocks.try_lock().unwrap();
                    blocks
                        .known_blocks
                        .put(finalized_block_hash, finalized_block_header);
                    blocks.known_blocks.put(best_block_hash, best_block_header);
                    blocks.finalized_block = finalized_block_hash;
                    blocks.best_block = best_block_hash;
                }

                let mut main_tasks = stream::FuturesUnordered::new();
                let mut secondary_tasks = stream::FuturesUnordered::new();

                for _ in 0..max_parallel_requests.get() {
                    let background = background.clone();
                    main_tasks.push(
                        async move {
                            loop {
                                let message = background.new_requests_rx.lock().await.next().await;
                                // It is important for `new_requests_rx` to be unlocked before
                                // awaiting on `handle_request`.
                                match message {
                                    Some(m) => {
                                        with_long_time_warning::<TPlat, _>(
                                            background.handle_request(&m),
                                            &m,
                                        )
                                        .await
                                    }
                                    None => return, // Foreground is closed.
                                }
                            }
                        }
                        .boxed(),
                    );
                }

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
                        block = best_blocks_subscription.next() => {
                            match block {
                                Some(block) => {
                                    let hash = header::hash_from_scale_encoded_header(&block);
                                    let mut blocks = background.blocks.lock().await;
                                    let blocks = &mut *blocks;
                                    blocks.best_block = hash;
                                    // As a small trick, we re-query the finalized block from
                                    // `known_blocks` in order to ensure that it never leaves the
                                    // LRU cache.
                                    blocks.known_blocks.get(&blocks.finalized_block);
                                    blocks.known_blocks.put(hash, block);
                                },
                                None => return,
                            }
                        },
                        block = finalized_blocks_subscription.next() => {
                            match block {
                                Some(block) => {
                                    let hash = header::hash_from_scale_encoded_header(&block);
                                    let mut blocks = background.blocks.lock().await;
                                    blocks.finalized_block = hash;
                                    blocks.known_blocks.put(hash, block);
                                },
                                None => return,
                            }
                        },
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
        log::log!(
            target: &self.log_target,
            log::Level::Debug,
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

        match self.new_requests_in.try_send(json_rpc_request) {
            Ok(()) => Ok(()),
            Err(err) => {
                assert!(err.is_full());
                let json_rpc_request = err.into_inner();
                Err(HandleRpcError::Overloaded { json_rpc_request })
            }
        }
    }
}

/// Runs a future but prints a warning if it takes a long time to complete.
fn with_long_time_warning<'a, TPlat: Platform, T: Future + 'a>(
    future: T,
    json_rpc_request: &'a str,
) -> impl Future<Output = T::Output> + 'a {
    let now = TPlat::now();
    let mut warn_after = TPlat::sleep(Duration::from_secs(1)).fuse();

    async move {
        let future = future.fuse();
        futures::pin_mut!(future);

        loop {
            futures::select! {
                _ = warn_after => {
                    log::warn!(
                        "JSON-RPC request is taking a long time: {:?}{}",
                        if json_rpc_request.len() > 100 { &json_rpc_request[..100] }
                            else { &json_rpc_request[..] },
                        if json_rpc_request.len() > 100 { "…" } else { "" }
                    );
                }
                out = future => {
                    if warn_after.is_terminated() {
                        log::info!(
                            "JSON-RPC request has finished after {}ms: {:?}{}",
                            (TPlat::now() - now).as_millis(),
                            if json_rpc_request.len() > 100 { &json_rpc_request[..100] }
                                else { &json_rpc_request[..] },
                            if json_rpc_request.len() > 100 { "…" } else { "" }
                        );
                    }
                    return out
                },
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

    /// Receiver for new incoming JSON-RPC requests.
    new_requests_rx: Mutex<mpsc::Receiver<String>>,

    /// Channel to send out responses.
    responses_sender: Mutex<mpsc::Sender<String>>,

    /// Whenever a task is sent on this channel, an executor runs it to completion.
    new_child_tasks_tx: Mutex<mpsc::UnboundedSender<future::BoxFuture<'static, ()>>>,

    /// See [`Config::max_subscriptions`].
    max_subscriptions: usize,

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

    /// Blocks that are temporarily saved in order to serve JSON-RPC requests.
    // TODO: move somewhere else?
    blocks: Mutex<Blocks>,

    /// Hash of the genesis block.
    /// Keeping the genesis block is important, as the genesis block hash is included in
    /// transaction signatures, and must therefore be queried by upper-level UIs.
    genesis_block: [u8; 32],

    next_subscription: atomic::AtomicU64,

    /// For each active subscription (the key), a sender. If the user unsubscribes, send the
    /// unsubscription request ID of the channel in order to close the subscription.
    subscriptions:
        Mutex<HashMap<(String, SubscriptionTy), oneshot::Sender<String>, fnv::FnvBuildHasher>>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum SubscriptionTy {
    AllHeads,
    NewHeads,
    FinalizedHeads,
    Storage,
    Transaction,
    RuntimeSpec,
}

struct Blocks {
    /// Blocks that are temporarily saved in order to serve JSON-RPC requests.
    ///
    /// Always contains `best_block` and `finalized_block`.
    known_blocks: lru::LruCache<[u8; 32], Vec<u8>>,

    /// Hash of the current best block.
    best_block: [u8; 32],

    /// Hash of the latest finalized block.
    finalized_block: [u8; 32],
}

fn log_and_respond<'a>(
    responses_sender: &'a Mutex<mpsc::Sender<String>>,
    log_target: &str,
    message: String,
) -> impl Future<Output = ()> + 'a {
    log::debug!(
        target: log_target,
        "JSON-RPC <= {}{}",
        if message.len() > 100 {
            &message[..100]
        } else {
            &message[..]
        },
        if message.len() > 100 { "…" } else { "" }
    );

    async move {
        let _ = responses_sender.lock().await.send(message).await;
    }
}

fn log_and_respond_no_mutex<'a>(
    responses_sender: &'a mut mpsc::Sender<String>,
    log_target: &str,
    message: String,
) -> impl Future<Output = ()> + 'a {
    log::debug!(
        target: log_target,
        "JSON-RPC <= {}{}",
        if message.len() > 100 {
            &message[..100]
        } else {
            &message[..]
        },
        if message.len() > 100 { "…" } else { "" }
    );

    async move {
        let _ = responses_sender.send(message).await;
    }
}

impl<TPlat: Platform> Background<TPlat> {
    async fn handle_request(&self, json_rpc_request: &str) {
        // Check whether the JSON-RPC request is correct, and bail out if it isn't.
        let (request_id, call) = match methods::parse_json_call(json_rpc_request) {
            Ok(v) => v,
            Err(methods::ParseError::Method { request_id, error }) => {
                log::warn!(
                    target: &self.log_target,
                    "Error in JSON-RPC method call: {}", error
                );
                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
                    error.to_json_error(request_id),
                )
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
                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
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

                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
                    methods::Response::author_submitExtrinsic(methods::HashHexString(
                        transaction_hash,
                    ))
                    .to_json_response(request_id),
                )
                .await;
            }
            methods::MethodCall::author_submitAndWatchExtrinsic { transaction } => {
                self.submit_and_watch_transaction(request_id, transaction)
                    .await
            }
            methods::MethodCall::author_unwatchExtrinsic { subscription } => {
                let invalid = if let Some(cancel_tx) = self
                    .subscriptions
                    .lock()
                    .await
                    .remove(&(subscription.to_owned(), SubscriptionTy::Transaction))
                {
                    // `cancel_tx` might have been closed if the channel from the transactions
                    // service has been closed too. This is not an error.
                    let _ = cancel_tx.send(request_id.to_owned());
                    false
                } else {
                    true
                };

                if invalid {
                    log_and_respond(
                        &self.responses_sender,
                        &self.log_target,
                        methods::Response::author_unwatchExtrinsic(false)
                            .to_json_response(request_id),
                    )
                    .await;
                } else {
                }
            }
            methods::MethodCall::chain_getBlock { hash } => {
                // `hash` equal to `None` means "the current best block".
                let hash = match hash {
                    Some(h) => h.0,
                    None => self.blocks.lock().await.best_block,
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
                            justification: true,
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
                        justification: block.justification.map(methods::HexString),
                    })
                    .to_json_response(request_id)
                } else {
                    json_rpc::parse::build_success_response(request_id, "null")
                };

                log_and_respond(&self.responses_sender, &self.log_target, response).await;
            }
            methods::MethodCall::chain_getBlockHash { height } => {
                self.get_block_hash(request_id, height).await;
            }
            methods::MethodCall::chain_getFinalizedHead {} => {
                let response = methods::Response::chain_getFinalizedHead(methods::HashHexString(
                    self.blocks.lock().await.finalized_block,
                ))
                .to_json_response(request_id);

                log_and_respond(&self.responses_sender, &self.log_target, response).await;
            }
            methods::MethodCall::chain_getHeader { hash } => {
                let hash = match hash {
                    Some(h) => h.0,
                    None => self.blocks.lock().await.best_block,
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

                log_and_respond(&self.responses_sender, &self.log_target, response).await;
            }
            methods::MethodCall::chain_subscribeAllHeads {} => {
                self.subscribe_all_heads(request_id).await;
            }
            methods::MethodCall::chain_subscribeFinalizedHeads {} => {
                self.subscribe_finalized_heads(request_id).await;
            }
            methods::MethodCall::chain_subscribeNewHeads {} => {
                self.subscribe_new_heads(request_id).await;
            }
            methods::MethodCall::chain_unsubscribeAllHeads { subscription } => {
                let invalid = if let Some(cancel_tx) = self
                    .subscriptions
                    .lock()
                    .await
                    .remove(&(subscription, SubscriptionTy::AllHeads))
                {
                    cancel_tx.send(request_id.to_owned()).is_err()
                } else {
                    true
                };

                if invalid {
                    log_and_respond(
                        &self.responses_sender,
                        &self.log_target,
                        methods::Response::chain_unsubscribeAllHeads(false)
                            .to_json_response(request_id),
                    )
                    .await;
                }
            }
            methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription } => {
                let invalid = if let Some(cancel_tx) = self
                    .subscriptions
                    .lock()
                    .await
                    .remove(&(subscription, SubscriptionTy::FinalizedHeads))
                {
                    cancel_tx.send(request_id.to_owned()).is_err()
                } else {
                    true
                };

                if invalid {
                    log_and_respond(
                        &self.responses_sender,
                        &self.log_target,
                        methods::Response::chain_unsubscribeFinalizedHeads(false)
                            .to_json_response(request_id),
                    )
                    .await;
                }
            }
            methods::MethodCall::chain_unsubscribeNewHeads { subscription } => {
                let invalid = if let Some(cancel_tx) = self
                    .subscriptions
                    .lock()
                    .await
                    .remove(&(subscription, SubscriptionTy::NewHeads))
                {
                    cancel_tx.send(request_id.to_owned()).is_err()
                } else {
                    true
                };

                if invalid {
                    log_and_respond(
                        &self.responses_sender,
                        &self.log_target,
                        methods::Response::chain_unsubscribeNewHeads(false)
                            .to_json_response(request_id),
                    )
                    .await;
                }
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

                log_and_respond(&self.responses_sender, &self.log_target, response).await;
            }
            methods::MethodCall::rpc_methods {} => {
                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
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

                let mut blocks = self.blocks.lock().await;
                let block_hash = blocks.best_block;
                let (state_root, block_number) = {
                    let block = blocks.known_blocks.get(&block_hash).unwrap();
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
                drop(blocks);

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

                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
                    match outcome {
                        Ok(keys) => {
                            // TODO: instead of requesting all keys with that prefix from the network, pass `start_key` to the network service
                            let out = keys
                                .into_iter()
                                .filter(|k| start_key.as_ref().map_or(true, |start| k >= &start.0)) // TODO: not sure if start should be in the set or not?
                                .map(methods::HexString)
                                .take(usize::try_from(count).unwrap_or(usize::max_value()))
                                .collect::<Vec<_>>();
                            methods::Response::state_getKeysPaged(out).to_json_response(request_id)
                        }
                        Err(error) => json_rpc::parse::build_error_response(
                            request_id,
                            json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                            None,
                        ),
                    },
                )
                .await;
            }
            methods::MethodCall::state_queryStorageAt { keys, at } => {
                let blocks = self.blocks.lock().await;

                let at = at.as_ref().map(|h| h.0).unwrap_or(blocks.best_block);

                // TODO: have no idea what this describes actually
                let mut out = methods::StorageChangeSet {
                    block: methods::HashHexString(blocks.best_block),
                    changes: Vec::new(),
                };

                drop(blocks);

                for key in keys {
                    // TODO: parallelism?
                    let fut = self.storage_query(&key.0, &at);
                    if let Ok(value) = fut.await {
                        out.changes.push((key, value.map(methods::HexString)));
                    }
                }

                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
                    methods::Response::state_queryStorageAt(vec![out]).to_json_response(request_id),
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

                log_and_respond(&self.responses_sender, &self.log_target, response).await;
            }
            methods::MethodCall::state_getStorage { key, hash } => {
                let hash = hash
                    .as_ref()
                    .map(|h| h.0)
                    .unwrap_or(self.blocks.lock().await.best_block);

                let fut = self.storage_query(&key.0, &hash);
                let response = fut.await;
                let response = match response {
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

                log_and_respond(&self.responses_sender, &self.log_target, response).await;
            }
            methods::MethodCall::state_subscribeRuntimeVersion {} => {
                let (subscription, mut unsubscribe_rx) =
                    match self.alloc_subscription(SubscriptionTy::RuntimeSpec).await {
                        Ok(v) => v,
                        Err(()) => {
                            log_and_respond(
                                &self.responses_sender,
                                &self.log_target,
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

                let (current_specs, spec_changes) =
                    self.runtime_service.subscribe_runtime_version().await;

                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
                    methods::Response::state_subscribeRuntimeVersion(&subscription)
                        .to_json_response(request_id),
                )
                .await;

                if let Some(current_specs) = current_specs {
                    let notification = if let Ok(runtime_spec) = current_specs {
                        let runtime_spec = runtime_spec.decode();
                        methods::ServerToClient::state_runtimeVersion {
                            subscription: &subscription,
                            result: Some(methods::RuntimeVersion {
                                spec_name: runtime_spec.spec_name.into(),
                                impl_name: runtime_spec.impl_name.into(),
                                authoring_version: u64::from(runtime_spec.authoring_version),
                                spec_version: u64::from(runtime_spec.spec_version),
                                impl_version: u64::from(runtime_spec.impl_version),
                                transaction_version: runtime_spec
                                    .transaction_version
                                    .map(u64::from),
                                apis: runtime_spec
                                    .apis
                                    .map(|api| {
                                        (methods::HexString(api.name_hash.to_vec()), api.version)
                                    })
                                    .collect(),
                            }),
                        }
                        .to_json_call_object_parameters(None)
                    } else {
                        methods::ServerToClient::state_runtimeVersion {
                            subscription: &subscription,
                            result: None,
                        }
                        .to_json_call_object_parameters(None)
                    };

                    log_and_respond(&self.responses_sender, &self.log_target, notification).await;
                }

                let mut responses_sender = self.responses_sender.lock().await.clone();
                let log_target = self.log_target.clone();
                self.new_child_tasks_tx
                    .lock()
                    .await
                    .unbounded_send(Box::pin(async move {
                        futures::pin_mut!(spec_changes);

                        loop {
                            // Wait for either a new storage update, or for the subscription to be canceled.
                            let next_change = spec_changes.next();
                            futures::pin_mut!(next_change);
                            match future::select(next_change, &mut unsubscribe_rx).await {
                                future::Either::Left((new_runtime, _)) => {
                                    let notification_body = if let Ok(runtime_spec) =
                                        new_runtime.unwrap()
                                    {
                                        let runtime_spec = runtime_spec.decode();
                                        methods::ServerToClient::state_runtimeVersion {
                                            subscription: &subscription,
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
                                                            methods::HexString(
                                                                api.name_hash.to_vec(),
                                                            ),
                                                            api.version,
                                                        )
                                                    })
                                                    .collect(),
                                            }),
                                        }
                                        .to_json_call_object_parameters(None)
                                    } else {
                                        methods::ServerToClient::state_runtimeVersion {
                                            subscription: &subscription,
                                            result: None,
                                        }
                                        .to_json_call_object_parameters(None)
                                    };

                                    log_and_respond_no_mutex(
                                        &mut responses_sender,
                                        &log_target,
                                        notification_body,
                                    )
                                    .await;
                                }
                                future::Either::Right((Ok(unsub_request_id), _)) => {
                                    let response =
                                        methods::Response::state_unsubscribeRuntimeVersion(true)
                                            .to_json_response(&unsub_request_id);
                                    log_and_respond_no_mutex(
                                        &mut responses_sender,
                                        &log_target,
                                        response,
                                    )
                                    .await;
                                    break;
                                }
                                future::Either::Right((Err(_), _)) => break,
                            }
                        }
                    }))
                    .unwrap();
            }
            methods::MethodCall::state_unsubscribeRuntimeVersion { subscription } => {
                let invalid = if let Some(cancel_tx) = self
                    .subscriptions
                    .lock()
                    .await
                    .remove(&(subscription.to_owned(), SubscriptionTy::RuntimeSpec))
                {
                    cancel_tx.send(request_id.to_owned()).is_err()
                } else {
                    true
                };

                if invalid {
                    log_and_respond(
                        &self.responses_sender,
                        &self.log_target,
                        methods::Response::state_unsubscribeRuntimeVersion(false)
                            .to_json_response(request_id),
                    )
                    .await;
                }
            }
            methods::MethodCall::state_subscribeStorage { list } => {
                if list.is_empty() {
                    // When the list of keys is empty, that means we want to subscribe to *all*
                    // storage changes. It is not possible to reasonably implement this in a
                    // light client.
                    log_and_respond(
                        &self.responses_sender,
                        &self.log_target,
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
                    self.subscribe_storage(request_id, list).await;
                }
            }
            methods::MethodCall::state_unsubscribeStorage { subscription } => {
                let invalid = if let Some(cancel_tx) = self
                    .subscriptions
                    .lock()
                    .await
                    .remove(&(subscription.to_owned(), SubscriptionTy::Storage))
                {
                    cancel_tx.send(request_id.to_owned()).is_err()
                } else {
                    true
                };

                if invalid {
                    log_and_respond(
                        &self.responses_sender,
                        &self.log_target,
                        methods::Response::state_unsubscribeStorage(false)
                            .to_json_response(request_id),
                    )
                    .await;
                }
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

                log_and_respond(&self.responses_sender, &self.log_target, response).await;
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

                log_and_respond(&self.responses_sender, &self.log_target, response).await;
            }
            methods::MethodCall::system_chain {} => {
                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
                    methods::Response::system_chain(&self.chain_name).to_json_response(request_id),
                )
                .await;
            }
            methods::MethodCall::system_chainType {} => {
                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
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

                log_and_respond(&self.responses_sender, &self.log_target, response).await;
            }
            methods::MethodCall::system_localListenAddresses {} => {
                // Wasm node never listens on any address.
                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
                    methods::Response::system_localListenAddresses(Vec::new())
                        .to_json_response(request_id),
                )
                .await;
            }
            methods::MethodCall::system_localPeerId {} => {
                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
                    methods::Response::system_localPeerId(&self.peer_id_base58)
                        .to_json_response(request_id),
                )
                .await;
            }
            methods::MethodCall::system_name {} => {
                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
                    methods::Response::system_name(&self.system_name).to_json_response(request_id),
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

                log_and_respond(&self.responses_sender, &self.log_target, response).await;
            }
            methods::MethodCall::system_properties {} => {
                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
                    methods::Response::system_properties(
                        serde_json::from_str(&self.chain_properties_json).unwrap(),
                    )
                    .to_json_response(request_id),
                )
                .await;
            }
            methods::MethodCall::system_version {} => {
                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
                    methods::Response::system_version(&self.system_version)
                        .to_json_response(request_id),
                )
                .await;
            }
            _method => {
                log::error!(target: &self.log_target, "JSON-RPC call not supported yet: {:?}", _method);
                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
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

    /// Handles a call to [`methods::MethodCall::author_submitAndWatchExtrinsic`].
    async fn submit_and_watch_transaction(
        &self,
        request_id: &str,
        transaction: methods::HexString,
    ) {
        let (subscription, mut unsubscribe_rx) =
            match self.alloc_subscription(SubscriptionTy::Transaction).await {
                Ok(v) => v,
                Err(()) => {
                    log_and_respond(
                        &self.responses_sender,
                        &self.log_target,
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

        let mut transaction_updates = self
            .transactions_service
            .submit_and_watch_transaction(transaction.0, 16)
            .await;

        let confirmation = methods::Response::author_submitAndWatchExtrinsic(&subscription)
            .to_json_response(request_id);

        // Spawn a separate task for the transaction updates.
        let mut responses_sender = self.responses_sender.lock().await.clone();
        let log_target = self.log_target.clone();
        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(Box::pin(async move {
                // Send back to the user the confirmation of the registration.
                log_and_respond_no_mutex(&mut responses_sender, &log_target, confirmation).await;

                loop {
                    // Wait for either a status update block, or for the subscription to
                    // be canceled.
                    let next_update = transaction_updates.next();
                    futures::pin_mut!(next_update);
                    match future::select(next_update, &mut unsubscribe_rx).await {
                        future::Either::Left((Some(update), _)) => {
                            let update = match update {
                                transactions_service::TransactionStatus::Broadcast(peers) => {
                                    methods::TransactionStatus::Broadcast(
                                        peers.into_iter().map(|peer| peer.to_base58()).collect(),
                                    )
                                }
                                transactions_service::TransactionStatus::InBlock(block) => {
                                    methods::TransactionStatus::InBlock(methods::HashHexString(block))
                                }
                                transactions_service::TransactionStatus::Retracted(block) => {
                                    methods::TransactionStatus::Retracted(methods::HashHexString(block))
                                }
                                transactions_service::TransactionStatus::GapInChain |
                                transactions_service::TransactionStatus::MaxPendingTransactionsReached |
                                transactions_service::TransactionStatus::Invalid(_) |
                                transactions_service::TransactionStatus::ValidateError(_) => {
                                    methods::TransactionStatus::Dropped
                                }
                                transactions_service::TransactionStatus::Finalized(block) => {
                                    methods::TransactionStatus::Finalized(methods::HashHexString(block))
                                }
                            };

                            log_and_respond_no_mutex(&mut responses_sender, &log_target, methods::ServerToClient::author_extrinsicUpdate {
                                subscription: &subscription,
                                result: update,
                            }.to_json_call_object_parameters(None))
                                .await;
                        }
                        future::Either::Right((Ok(unsub_request_id), _)) => {
                            let response = methods::Response::chain_unsubscribeNewHeads(true)
                                .to_json_response(&unsub_request_id);
                            log_and_respond_no_mutex(&mut responses_sender, &log_target, response).await;
                            break;
                        }
                        future::Either::Left((None, _)) => {
                            // Channel from the transactions service has been closed.
                            // Stop the task.
                            // There is nothing more that can be done except hope that the
                            // client understands that no new notification is expected and
                            // unsubscribes.
                            break;
                        }
                        future::Either::Right((Err(_), _)) => break,
                    }
                }
            }))
            .unwrap();
    }

    /// Handles a call to [`methods::MethodCall::chain_getBlockHash`].
    async fn get_block_hash(&self, request_id: &str, height: Option<u64>) {
        let response = {
            let mut blocks = self.blocks.lock().await;
            let blocks = &mut *blocks;

            match height {
                Some(0) => methods::Response::chain_getBlockHash(methods::HashHexString(
                    self.genesis_block,
                ))
                .to_json_response(request_id),
                None => {
                    methods::Response::chain_getBlockHash(methods::HashHexString(blocks.best_block))
                        .to_json_response(request_id)
                }
                Some(n)
                    if blocks
                        .known_blocks
                        .get(&blocks.best_block)
                        .map_or(false, |h| {
                            header::decode(&h).map_or(false, |h| h.number == n)
                        }) =>
                {
                    methods::Response::chain_getBlockHash(methods::HashHexString(blocks.best_block))
                        .to_json_response(request_id)
                }
                Some(n)
                    if blocks
                        .known_blocks
                        .get(&blocks.finalized_block)
                        .map_or(false, |h| {
                            header::decode(&h).map_or(false, |h| h.number == n)
                        }) =>
                {
                    methods::Response::chain_getBlockHash(methods::HashHexString(
                        blocks.finalized_block,
                    ))
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

        log_and_respond(&self.responses_sender, &self.log_target, response).await;
    }

    /// Handles a call to [`methods::MethodCall::chain_subscribeAllHeads`].
    async fn subscribe_all_heads(&self, request_id: &str) {
        let (subscription, mut unsubscribe_rx) =
            match self.alloc_subscription(SubscriptionTy::AllHeads).await {
                Ok(v) => v,
                Err(()) => {
                    log_and_respond(
                        &self.responses_sender,
                        &self.log_target,
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

        let mut blocks_list = {
            let subscribe_all = self.runtime_service.subscribe_all(16).await;
            // TODO: is it correct to return all non-finalized blocks first? have to compare with PolkadotJS
            stream::iter(subscribe_all.non_finalized_blocks_ancestry_order)
                .chain(subscribe_all.new_blocks.filter_map(|notif| {
                    future::ready(match notif {
                        runtime_service::Notification::Block(b) => Some(b),
                        _ => None,
                    })
                }))
                .map(|notif| notif.scale_encoded_header)
        };

        let confirmation =
            methods::Response::chain_subscribeAllHeads(&subscription).to_json_response(request_id);

        let mut responses_sender = self.responses_sender.lock().await.clone();
        let log_target = self.log_target.clone();

        // Spawn a separate task for the subscription.
        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(Box::pin(async move {
                // Send back to the user the confirmation of the registration.
                log_and_respond_no_mutex(&mut responses_sender, &log_target, confirmation).await;

                loop {
                    // Wait for either a new block, or for the subscription to be canceled.
                    let next_block = blocks_list.next();
                    futures::pin_mut!(next_block);
                    match future::select(next_block, &mut unsubscribe_rx).await {
                        future::Either::Left((block, _)) => {
                            // TODO: don't unwrap `block`! channel can be legitimately closed if full
                            let header =
                                methods::Header::from_scale_encoded_header(&block.unwrap())
                                    .unwrap();
                            log_and_respond_no_mutex(
                                &mut responses_sender,
                                &log_target,
                                methods::ServerToClient::chain_newHead {
                                    subscription: &subscription,
                                    result: header,
                                }
                                .to_json_call_object_parameters(None),
                            )
                            .await;
                        }
                        future::Either::Right((Ok(unsub_request_id), _)) => {
                            let response = methods::Response::chain_unsubscribeAllHeads(true)
                                .to_json_response(&unsub_request_id);
                            log_and_respond_no_mutex(&mut responses_sender, &log_target, response)
                                .await;
                            break;
                        }
                        future::Either::Right((Err(_), _)) => break,
                    }
                }
            }))
            .unwrap();
    }

    /// Handles a call to [`methods::MethodCall::chain_subscribeNewHeads`].
    async fn subscribe_new_heads(&self, request_id: &str) {
        let (subscription, mut unsubscribe_rx) =
            match self.alloc_subscription(SubscriptionTy::NewHeads).await {
                Ok(v) => v,
                Err(()) => {
                    log_and_respond(
                        &self.responses_sender,
                        &self.log_target,
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

        let mut blocks_list = {
            let (block_header, blocks_subscription) = self.runtime_service.subscribe_best().await;
            stream::once(future::ready(block_header)).chain(blocks_subscription)
        };

        let confirmation =
            methods::Response::chain_subscribeNewHeads(&subscription).to_json_response(request_id);

        let mut responses_sender = self.responses_sender.lock().await.clone();
        let log_target = self.log_target.clone();

        // Spawn a separate task for the subscription.
        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(Box::pin(async move {
                // Send back to the user the confirmation of the registration.
                log_and_respond_no_mutex(&mut responses_sender, &log_target, confirmation).await;

                loop {
                    // Wait for either a new block, or for the subscription to be canceled.
                    let next_block = blocks_list.next();
                    futures::pin_mut!(next_block);
                    match future::select(next_block, &mut unsubscribe_rx).await {
                        future::Either::Left((block, _)) => {
                            let header =
                                methods::Header::from_scale_encoded_header(&block.unwrap())
                                    .unwrap();
                            log_and_respond_no_mutex(
                                &mut responses_sender,
                                &log_target,
                                methods::ServerToClient::chain_newHead {
                                    subscription: &subscription,
                                    result: header,
                                }
                                .to_json_call_object_parameters(None),
                            )
                            .await;
                        }
                        future::Either::Right((Ok(unsub_request_id), _)) => {
                            let response = methods::Response::chain_unsubscribeNewHeads(true)
                                .to_json_response(&unsub_request_id);
                            log_and_respond_no_mutex(&mut responses_sender, &log_target, response)
                                .await;
                            break;
                        }
                        future::Either::Right((Err(_), _)) => break,
                    }
                }
            }))
            .unwrap();
    }

    /// Handles a call to [`methods::MethodCall::chain_subscribeFinalizedHeads`].
    async fn subscribe_finalized_heads(&self, request_id: &str) {
        let (subscription, mut unsubscribe_rx) = match self
            .alloc_subscription(SubscriptionTy::FinalizedHeads)
            .await
        {
            Ok(v) => v,
            Err(()) => {
                log_and_respond(
                    &self.responses_sender,
                    &self.log_target,
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

        let mut blocks_list = {
            let (finalized_block_header, finalized_blocks_subscription) =
                self.runtime_service.subscribe_finalized().await;
            stream::once(future::ready(finalized_block_header)).chain(finalized_blocks_subscription)
        };

        let confirmation = methods::Response::chain_subscribeFinalizedHeads(&subscription)
            .to_json_response(request_id);

        let mut responses_sender = self.responses_sender.lock().await.clone();
        let log_target = self.log_target.clone();

        // Spawn a separate task for the subscription.
        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(Box::pin(async move {
                // Send back to the user the confirmation of the registration.
                log_and_respond_no_mutex(&mut responses_sender, &log_target, confirmation).await;

                loop {
                    // Wait for either a new block, or for the subscription to be canceled.
                    let next_block = blocks_list.next();
                    futures::pin_mut!(next_block);
                    match future::select(next_block, &mut unsubscribe_rx).await {
                        future::Either::Left((block, _)) => {
                            let header =
                                methods::Header::from_scale_encoded_header(&block.unwrap())
                                    .unwrap();

                            log_and_respond_no_mutex(
                                &mut responses_sender,
                                &log_target,
                                methods::ServerToClient::chain_finalizedHead {
                                    subscription: &subscription,
                                    result: header,
                                }
                                .to_json_call_object_parameters(None),
                            )
                            .await;
                        }
                        future::Either::Right((Ok(unsub_request_id), _)) => {
                            let response = methods::Response::chain_unsubscribeFinalizedHeads(true)
                                .to_json_response(&unsub_request_id);
                            log_and_respond_no_mutex(&mut responses_sender, &log_target, response)
                                .await;
                            break;
                        }
                        future::Either::Right((Err(_), _)) => break,
                    }
                }
            }))
            .unwrap();
    }

    /// Handles a call to [`methods::MethodCall::state_subscribeStorage`].
    async fn subscribe_storage(&self, request_id: &str, list: Vec<methods::HexString>) {
        let (subscription, mut unsubscribe_rx) =
            match self.alloc_subscription(SubscriptionTy::Storage).await {
                Ok(v) => v,
                Err(()) => {
                    log_and_respond(
                        &self.responses_sender,
                        &self.log_target,
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

        // Build a stream of `methods::StorageChangeSet` items to send back to the user.
        let storage_updates = {
            let known_values = (0..list.len()).map(|_| None).collect::<Vec<_>>();
            let (block_header, blocks_subscription) = self.runtime_service.subscribe_best().await;
            let blocks_stream =
                stream::once(future::ready(block_header)).chain(blocks_subscription);
            let sync_service = self.sync_service.clone();
            let log_target = self.log_target.clone();

            stream::unfold(
                (blocks_stream, list, known_values),
                move |(mut blocks_stream, list, mut known_values)| {
                    let sync_service = sync_service.clone();
                    let log_target = log_target.clone();
                    async move {
                        loop {
                            let block = blocks_stream.next().await?;
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

        let confirmation =
            methods::Response::state_subscribeStorage(&subscription).to_json_response(request_id);

        let mut responses_sender = self.responses_sender.lock().await.clone();
        let log_target = self.log_target.clone();

        // Spawn a separate task for the subscription.
        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(Box::pin(async move {
                futures::pin_mut!(storage_updates);

                // Send back to the user the confirmation of the registration.
                log_and_respond_no_mutex(&mut responses_sender, &log_target, confirmation).await;

                loop {
                    // Wait for either a new storage update, or for the subscription to be canceled.
                    let next_block = storage_updates.next();
                    futures::pin_mut!(next_block);
                    match future::select(next_block, &mut unsubscribe_rx).await {
                        future::Either::Left((Some(changes), _)) => {
                            log_and_respond_no_mutex(
                                &mut responses_sender,
                                &log_target,
                                methods::ServerToClient::state_storage {
                                    subscription: &subscription,
                                    result: changes,
                                }
                                .to_json_call_object_parameters(None),
                            )
                            .await;
                        }
                        future::Either::Left((None, _)) => {
                            // TODO: do something?
                        }
                        future::Either::Right((Ok(unsub_request_id), _)) => {
                            let response = methods::Response::state_unsubscribeStorage(true)
                                .to_json_response(&unsub_request_id);
                            log_and_respond_no_mutex(&mut responses_sender, &log_target, response)
                                .await;
                            break;
                        }
                        future::Either::Right((Err(_), _)) => break,
                    }
                }
            }))
            .unwrap();
    }

    fn storage_query(
        &'_ self,
        key: &[u8],
        hash: &[u8; 32],
    ) -> impl Future<Output = Result<Option<Vec<u8>>, StorageQueryError>> + '_ {
        // TODO: had to go through hoops to make it compile; clean up
        let key = key.to_owned();
        let hash = *hash;
        let sync_service = self.sync_service.clone();
        let fut = self.header_query(&hash);

        async move {
            // TODO: risk of deadlock here?
            let header = fut
                .await
                .map_err(|_| StorageQueryError::FindStorageRootHashError)?;
            let trie_root_hash = header::decode(&header).unwrap().state_root;

            let mut result = sync_service
                .storage_query(&hash, &trie_root_hash, iter::once(key))
                .await
                .map_err(StorageQueryError::StorageRetrieval)?;
            Ok(result.pop().unwrap())
        }
    }

    fn header_query(&'_ self, hash: &[u8; 32]) -> impl Future<Output = Result<Vec<u8>, ()>> + '_ {
        // TODO: had to go through hoops to make it compile; clean up
        let hash = *hash;
        let sync_service = self.sync_service.clone();

        async move {
            // TODO: risk of deadlock here?
            {
                let mut blocks = self.blocks.lock().await;
                let blocks = &mut *blocks;

                if let Some(header) = blocks.known_blocks.get(&hash) {
                    return Ok(header.clone());
                }
            }

            // Header isn't known locally. Ask the networ
            let fut = sync_service.block_query(
                hash,
                protocol::BlocksRequestFields {
                    header: true,
                    body: false,
                    justification: false,
                },
            );
            let result = fut.await;

            // Note that the `block_query` method guarantees that the header is present
            // and valid.
            if let Ok(block) = result {
                let header = block.header.unwrap();
                debug_assert_eq!(header::hash_from_scale_encoded_header(&header), hash);

                let mut blocks = self.blocks.lock().await;
                blocks.known_blocks.put(hash, header.clone());
                Ok(header)
            } else {
                Err(())
            }
        }
    }

    /// Allocates a new subscription ID. Also checks the maximum number of subscriptions.
    async fn alloc_subscription(
        &self,
        ty: SubscriptionTy,
    ) -> Result<(String, oneshot::Receiver<String>), ()> {
        let subscription = self
            .next_subscription
            .fetch_add(1, atomic::Ordering::Relaxed)
            .to_string();

        let (unsubscribe_tx, unsubscribe_rx) = oneshot::channel();
        let mut lock = self.subscriptions.lock().await;
        if lock.len() >= self.max_subscriptions {
            return Err(());
        }

        lock.insert((subscription.clone(), ty), unsubscribe_tx);

        Ok((subscription, unsubscribe_rx))
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
