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

use crate::{
    log, network_service,
    platform::PlatformRef,
    runtime_service, sync_service, transactions_service,
    util::{self, SipHasherBuild},
};

use alloc::{
    borrow::{Cow, ToOwned as _},
    boxed::Box,
    collections::{BTreeSet, VecDeque},
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{iter, mem, num::NonZero, pin::Pin, time::Duration};
use futures_lite::{FutureExt as _, StreamExt as _};
use futures_util::{future, stream};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore as _, SeedableRng as _},
};
use smoldot::{
    header,
    informant::HashDisplay,
    json_rpc::{self, methods, parse},
    libp2p::{PeerId, multiaddr},
    network::codec,
    trie::{minimize_proof, proof_decode},
};

/// Configuration for a JSON-RPC service.
pub(super) struct Config<TPlat: PlatformRef> {
    /// Access to the platform's capabilities.
    // TODO: redundant with Config above?
    pub platform: TPlat,

    /// Access to the network, and identifier of the chain from the point of view of the network
    /// service.
    pub network_service: Arc<network_service::NetworkServiceChain<TPlat>>,

    /// Service responsible for synchronizing the chain.
    pub sync_service: Arc<sync_service::SyncService<TPlat>>,

    /// Service responsible for emitting transactions and tracking their state.
    pub transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,

    /// Service that provides a ready-to-be-called runtime for the current best block.
    pub runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,

    /// Name of the chain, as found in the chain specification.
    pub chain_name: String,
    /// Type of chain, as found in the chain specification.
    pub chain_ty: String,
    /// JSON-encoded properties of the chain, as found in the chain specification.
    pub chain_properties_json: String,
    /// Whether the chain is a live network. Found in the chain specification.
    pub chain_is_live: bool,

    /// Value to return when the `system_name` RPC is called. Should be set to the name of the
    /// final executable.
    pub system_name: String,

    /// Value to return when the `system_version` RPC is called. Should be set to the version of
    /// the final executable.
    pub system_version: String,

    /// Hash of the genesis block of the chain.
    pub genesis_block_hash: [u8; 32],
}

/// Fields used to process JSON-RPC requests in the background.
struct Background<TPlat: PlatformRef> {
    /// Target to use for all the logs.
    log_target: String,

    /// Access to the platform's capabilities.
    platform: TPlat,

    /// Name of the chain, as found in the chain specification.
    chain_name: String,
    /// Type of chain, as found in the chain specification.
    chain_ty: String,
    /// JSON-encoded properties of the chain, as found in the chain specification.
    chain_properties_json: String,
    /// Whether the chain is a live network. Found in the chain specification.
    chain_is_live: bool,
    /// Value to return when the `system_name` RPC is called.
    system_name: String,
    /// Value to return when the `system_version` RPC is called.
    system_version: String,
    /// Hash of the genesis block.
    /// Keeping the genesis block is important, as the genesis block hash is included in
    /// transaction signatures, and must therefore be queried by upper-level UIs.
    genesis_block_hash: [u8; 32],

    /// Randomness used for various purposes, such as generating subscription IDs.
    randomness: ChaCha20Rng,

    /// See [`Config::network_service`].
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
    /// See [`Config::sync_service`].
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    /// See [`Config::runtime_service`].
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    /// See [`Config::transactions_service`].
    transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,

    /// Tasks that are spawned by the service and running in the background.
    background_tasks: stream::FuturesUnordered<Pin<Box<dyn Future<Output = Event<TPlat>> + Send>>>,

    /// Channel where serialized JSON-RPC requests are pulled from.
    requests_rx: Pin<Box<async_channel::Receiver<String>>>,
    /// Channel to send serialized JSON-RPC responses and notifications to the foreground.
    responses_tx: async_channel::Sender<String>,

    /// State of each `chainHead_follow` subscription indexed by its ID.
    chain_head_follow_subscriptions:
        hashbrown::HashMap<String, ChainHeadFollow, fnv::FnvBuildHasher>,

    /// If `true`, we have already printed a warning about usage of the legacy JSON-RPC API. This
    /// flag prevents printing this message multiple times.
    printed_legacy_json_rpc_warning: bool,

    /// Next time to do some memory reclaims.
    next_garbage_collection: Pin<Box<TPlat::Delay>>,

    /// State of the runtime service subscription. Used for legacy JSON-RPC API subscriptions.
    runtime_service_subscription: RuntimeServiceSubscription<TPlat>,
    /// List of all active `chain_subscribeAllHeads` subscriptions, indexed by the subscription ID.
    all_heads_subscriptions: hashbrown::HashSet<String, fnv::FnvBuildHasher>,
    /// List of all active `chain_subscribeNewHeads` subscriptions, indexed by the subscription ID.
    new_heads_subscriptions: hashbrown::HashSet<String, fnv::FnvBuildHasher>,
    /// List of all active `chain_subscribeFinalizedHeads` subscriptions, indexed by the
    /// subscription ID.
    finalized_heads_subscriptions: hashbrown::HashSet<String, fnv::FnvBuildHasher>,
    /// List of all active `state_subscribeRuntimeVersion` subscriptions, indexed by the
    /// subscription ID.
    runtime_version_subscriptions: hashbrown::HashSet<String, fnv::FnvBuildHasher>,
    /// List of all active `author_submitAndWatchExtrinsic`, `transaction_v1_broadcast`, and
    /// `transactionWatch_v1_submitAndWatch` subscriptions, indexed by the subscription ID.
    /// When it comes to `author_submitAndWatchExtrinsic` and
    /// `transactionWatch_v1_submitAndWatch`, transactions are removed from this list when
    /// they are dropped from the transactions service. When it comes
    /// to  `transaction_v1_broadcast`, transactions are left forever until the API user
    /// unsubscribes.
    transactions_subscriptions: hashbrown::HashMap<String, TransactionWatch, fnv::FnvBuildHasher>,

    /// List of all active `state_subscribeStorage` subscriptions, indexed by the subscription ID.
    /// Values are the list of keys requested by this subscription.
    legacy_api_storage_subscriptions: BTreeSet<(Arc<str>, Vec<u8>)>,
    /// Identical to [`Background::legacy_api_storage_subscriptions`] but indexed by requested key.
    legacy_api_storage_subscriptions_by_key: BTreeSet<(Vec<u8>, Arc<str>)>,
    /// List of storage subscriptions whose latest sent notification isn't about the current
    /// best block.
    legacy_api_stale_storage_subscriptions: hashbrown::HashSet<Arc<str>, fnv::FnvBuildHasher>,
    /// `true` if there exists a background task in [`Background::background_tasks`] currently
    /// fetching storage items for storage subscriptions.
    legacy_api_storage_query_in_progress: bool,

    /// List of multi-stage requests (i.e. JSON-RPC requests that require multiple asynchronous
    /// operations) that are ready to make progress.
    multistage_requests_to_advance: VecDeque<(String, MultiStageRequestStage, MultiStageRequestTy)>,
    /// Multi-stage requests that are waiting for the best block hash to be known in order
    /// to progress.
    best_block_hash_pending: Vec<(String, MultiStageRequestTy)>,
    /// List of request IDs of `chain_getFinalizedHash` requests that are waiting for the
    /// finalized block hash to be known.
    pending_get_finalized_head: Vec<String>,
    /// Requests for blocks headers, state root hash and numbers that are still in progress.
    /// For each block hash, contains a list of multi-stage requests that are interested in the
    /// response. Once the operation has been finished, the value is inserted in
    /// [`Background::block_headers_cache`].
    block_headers_pending:
        hashbrown::HashMap<[u8; 32], Vec<(String, MultiStageRequestTy)>, fnv::FnvBuildHasher>,
    /// Requests for block runtimes that are still in progress.
    /// For each block hash, contains a list of requests that are interested in the response.
    /// Once the operation has been finished, the value is inserted in
    /// [`Background::block_runtimes_cache`].
    block_runtimes_pending:
        hashbrown::HashMap<[u8; 32], Vec<(String, MultiStageRequestTy)>, fnv::FnvBuildHasher>,

    /// Cache of known headers, state trie root hashes and numbers of blocks. Used only for the
    /// legacy JSON-RPC API.
    ///
    /// Can also be an `Err` if the header is in an invalid format.
    block_headers_cache: lru::LruCache<
        [u8; 32],
        Result<(Vec<u8>, [u8; 32], u64), header::Error>,
        fnv::FnvBuildHasher,
    >,
    /// Cache of known runtimes of blocks. Used only for the legacy JSON-RPC API.
    ///
    /// Note that runtimes that have failed to compile can be found here as well.
    block_runtimes_cache:
        lru::LruCache<[u8; 32], runtime_service::PinnedRuntime, fnv::FnvBuildHasher>,
    /// When `state_getKeysPaged` is called and the response is truncated, the response is
    /// inserted in this cache. The API user is likely to call `state_getKeysPaged` again with
    /// the same parameters, in which case we hit the cache and avoid the networking requests.
    /// The values are list of keys.
    state_get_keys_paged_cache:
        lru::LruCache<GetKeysPagedCacheKey, Vec<Vec<u8>>, util::SipHasherBuild>,

    /// Active statement subscriptions. Maps subscription ID to topic filter.
    statement_subscriptions:
        hashbrown::HashMap<String, network_service::TopicFilter, fnv::FnvBuildHasher>,

    /// Set of peers connected via Statement Protocol V2.
    v2_statement_peers: hashbrown::HashSet<PeerId, fnv::FnvBuildHasher>,

    /// Receiver for network events (statements from peers).
    network_events_rx: Option<async_channel::Receiver<network_service::Event>>,
}

/// State of the subscription towards the runtime service.
/// See [`Background::runtime_service_subscription`].
enum RuntimeServiceSubscription<TPlat: PlatformRef> {
    /// Subscription is active.
    Active {
        /// Object representing the subscription.
        subscription: runtime_service::Subscription<TPlat>,

        /// Hash of the current best block. Guaranteed to be in
        /// [`RuntimeServiceSubscription::Active::pinned_blocks`].
        current_best_block: [u8; 32],

        /// If `Some`, the new heads and runtime version subscriptions haven't been updated about
        /// the new current best block yet. Contains the previous best block that the
        /// subscriptions are aware of. The previous best block is guaranteed to be in
        /// [`RuntimeServiceSubscription::Active::pinned_blocks`].
        new_heads_and_runtime_subscriptions_stale: Option<Option<[u8; 32]>>,

        /// Hash of the current finalized block. Guaranteed to be in
        /// [`RuntimeServiceSubscription::Active::pinned_blocks`].
        current_finalized_block: [u8; 32],

        /// If `true`, the finalized heads subscriptions haven't been updated about the new
        /// current finalized block yet.
        finalized_heads_subscriptions_stale: bool,

        /// When the runtime service reports a new block, it is kept pinned and inserted in this
        /// list.
        ///
        /// Blocks are removed from this container and unpinned when they leave
        /// [`RuntimeServiceSubscription::Active::finalized_and_pruned_lru`].
        ///
        /// JSON-RPC clients are more likely to ask for information about recent blocks and
        /// perform calls on them, hence a cache of recent blocks.
        pinned_blocks: hashbrown::HashMap<[u8; 32], RecentBlock, fnv::FnvBuildHasher>,

        /// When a block is finalized or pruned, it is inserted into this LRU cache. The least
        /// recently used blocks are removed and unpinned.
        finalized_and_pruned_lru: lru::LruCache<[u8; 32], (), fnv::FnvBuildHasher>,
    },

    /// Waiting for the runtime service to start the subscription. Can potentially take a long
    /// time.
    Pending(Pin<Box<dyn Future<Output = runtime_service::SubscribeAll<TPlat>> + Send>>),

    /// Subscription not requested yet. Should transition to
    /// [`RuntimeServiceSubscription::Pending`] as soon as possible.
    NotCreated,
}

struct RecentBlock {
    scale_encoded_header: Vec<u8>,
    // TODO: do we really need to keep the runtime version here, given that the block is still pinned in the runtime service?
    runtime_version: Arc<Result<smoldot::executor::CoreVersion, runtime_service::RuntimeError>>,
}

struct ChainHeadFollow {
    /// For each pinned block hash, the SCALE-encoded header of the block.
    pinned_blocks_headers: hashbrown::HashMap<[u8; 32], Vec<u8>, fnv::FnvBuildHasher>,

    /// List of body/call/storage operations currently in progress. Keys are operation IDs.
    operations_in_progress: hashbrown::HashMap<String, ChainHeadOperation, fnv::FnvBuildHasher>,

    /// Remaining number of operation slots that the JSON-RPC client can occupy.
    available_operation_slots: u32,

    /// If the subscription was created with `withRuntime: true`, contains the subscription ID
    /// according to the runtime service.
    ///
    /// Contains `None` if `withRuntime` was `false`, or if the subscription hasn't been
    /// initialized yet.
    runtime_service_subscription_id: Option<runtime_service::SubscriptionId>,
}

struct ChainHeadOperation {
    /// Number of slots that this operation occupies.
    /// See [`ChainHeadFollow::available_operation_slots`].
    occupied_slots: u32,

    /// Event connected to the background task in [`Background::background_tasks`] that is
    /// currently executing the operation. Cancels the task when notified.
    interrupt: event_listener::Event,
}

enum MultiStageRequestStage {
    BlockHashNotKnown,
    BlockHashKnown {
        block_hash: [u8; 32],
    },
    BlockInfoKnown {
        block_hash: [u8; 32],
        block_state_trie_root_hash: [u8; 32],
        block_number: u64,
    },
}

enum MultiStageRequestTy {
    ChainGetBestBlockHash,
    ChainGetBlock,
    ChainGetHeader,
    StateCall {
        name: String,
        parameters: Vec<u8>,
    },
    StateGetKeys {
        prefix: Vec<u8>,
    },
    StateGetKeysPaged {
        prefix: Vec<u8>,
        count: u32,
        start_key: Option<Vec<u8>>,
    },
    StateQueryStorageAt {
        keys: Vec<methods::HexString>,
    },
    StateGetMetadata,
    StateGetReadProof {
        keys: Vec<methods::HexString>,
    },
    StateGetStorage {
        key: Vec<u8>,
    },
    StateGetRuntimeVersion,
    PaymentQueryInfo {
        extrinsic: Vec<u8>,
    },
    SystemAccountNextIndex {
        account_id: Vec<u8>,
    },
}

enum StorageRequestInProgress {
    StateGetKeys {
        in_progress_results: Vec<methods::HexString>,
    },
    StateGetKeysPaged {
        block_hash: [u8; 32],
        prefix: Vec<u8>,
        count: u32,
        start_key: Option<Vec<u8>>,
        in_progress_results: Vec<Vec<u8>>,
    },
    StateQueryStorageAt {
        block_hash: [u8; 32],
        in_progress_results: Vec<(methods::HexString, Option<methods::HexString>)>,
    },
    StateGetReadProof {
        block_hash: [u8; 32],
        in_progress_results: Vec<Vec<u8>>,
    },
    StateGetStorage,
}

enum RuntimeCallRequestInProgress {
    StateCall,
    StateGetMetadata,
    PaymentQueryInfo,
    SystemAccountNextIndex,
}

/// Event generated by a task in [`Background::background_tasks`] when it finishes.
enum Event<TPlat: PlatformRef> {
    TransactionEvent {
        subscription_id: String,
        event: transactions_service::TransactionStatus,
        watcher: Pin<Box<transactions_service::TransactionWatcher>>,
    },
    ChainGetBlockResult {
        request_id_json: String,
        result: Result<codec::BlockData, ()>,
        expected_block_hash: [u8; 32],
    },
    ChainHeadSubscriptionWithRuntimeReady {
        subscription_id: String,
        subscription: runtime_service::SubscribeAll<TPlat>,
    },
    ChainHeadSubscriptionWithRuntimeNotification {
        subscription_id: String,
        notification: runtime_service::Notification,
        stream: runtime_service::Subscription<TPlat>,
    },
    ChainHeadSubscriptionWithoutRuntimeReady {
        subscription_id: String,
        subscription: sync_service::SubscribeAll,
    },
    ChainHeadSubscriptionWithoutRuntimeNotification {
        subscription_id: String,
        notification: sync_service::Notification,
        stream: Pin<Box<async_channel::Receiver<sync_service::Notification>>>,
    },
    ChainHeadSubscriptionDeadSubcription {
        subscription_id: String,
    },
    ChainHeadStorageOperationProgress {
        subscription_id: String,
        operation_id: String,
        progress: sync_service::StorageQueryProgress<TPlat>,
    },
    ChainHeadCallOperationDone {
        subscription_id: String,
        operation_id: String,
        result: Result<runtime_service::RuntimeCallSuccess, runtime_service::RuntimeCallError>,
    },
    ChainHeadBodyOperationDone {
        subscription_id: String,
        operation_id: String,
        expected_extrinsics_root: [u8; 32],
        result: Result<codec::BlockData, ()>,
    },
    ChainHeadOperationCancelled,
    BlockInfoRetrieved {
        block_hash: [u8; 32],
        result: Result<Result<(Vec<u8>, [u8; 32], u64), header::Error>, ()>,
    },
    RuntimeDownloaded {
        block_hash: [u8; 32],
        result: Result<runtime_service::PinnedRuntime, String>,
    },
    LegacyApiFunctionStorageRequestProgress {
        request_id_json: String,
        request: StorageRequestInProgress,
        progress: sync_service::StorageQueryProgress<TPlat>,
    },
    LegacyApiFunctionRuntimeCallResult {
        request_id_json: String,
        request: RuntimeCallRequestInProgress,
        result: Result<runtime_service::RuntimeCallSuccess, runtime_service::RuntimeCallError>,
    },
    LegacyApiStorageSubscriptionsUpdate {
        block_hash: [u8; 32],
        result: Result<Vec<sync_service::StorageResultItem>, sync_service::StorageQueryError>,
    },
    TopicAffinitySent,
}

struct TransactionWatch {
    included_block: Option<[u8; 32]>,
    num_broadcasted_peers: usize,
    ty: TransactionWatchTy,
}

enum TransactionWatchTy {
    /// `author_submitAndWatchExtrinsic`.
    Legacy,
    /// `transaction_v1_broadcast`.
    NewApi {
        /// A copy of the body of the transaction is kept, as it might be necessary to re-insert
        /// it in the transactions service later, for example if it reports having crashed.
        transaction_bytes: Vec<u8>,
    },
    /// `transactionWatch_v1_submitAndWatch`.
    NewApiWatch,
}

/// See [`Background::state_get_keys_paged_cache`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GetKeysPagedCacheKey {
    /// Value of the `hash` parameter of the call to `state_getKeysPaged`.
    hash: [u8; 32],
    /// Value of the `prefix` parameter of the call to `state_getKeysPaged`.
    prefix: Vec<u8>,
}

pub(super) async fn run<TPlat: PlatformRef>(
    log_target: String,
    config: Config<TPlat>,
    requests_rx: async_channel::Receiver<String>,
    responses_tx: async_channel::Sender<String>,
) {
    let mut me = Background {
        log_target,
        chain_name: config.chain_name,
        chain_ty: config.chain_ty,
        chain_is_live: config.chain_is_live,
        chain_properties_json: config.chain_properties_json,
        system_name: config.system_name.clone(),
        system_version: config.system_version.clone(),
        randomness: ChaCha20Rng::from_seed({
            let mut seed = [0; 32];
            config.platform.fill_random_bytes(&mut seed);
            seed
        }),
        next_garbage_collection: Box::pin(config.platform.sleep(Duration::new(0, 0))),
        network_service: config.network_service.clone(),
        sync_service: config.sync_service.clone(),
        runtime_service: config.runtime_service.clone(),
        transactions_service: config.transactions_service.clone(),
        background_tasks: stream::FuturesUnordered::new(),
        runtime_service_subscription: RuntimeServiceSubscription::NotCreated,
        all_heads_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
            2,
            Default::default(),
        ),
        new_heads_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
            2,
            Default::default(),
        ),
        finalized_heads_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
            2,
            Default::default(),
        ),
        runtime_version_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
            2,
            Default::default(),
        ),
        transactions_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
            2,
            Default::default(),
        ),
        chain_head_follow_subscriptions: hashbrown::HashMap::with_hasher(Default::default()),
        legacy_api_storage_subscriptions: BTreeSet::new(),
        legacy_api_storage_subscriptions_by_key: BTreeSet::new(),
        legacy_api_stale_storage_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
            0,
            Default::default(),
        ),
        legacy_api_storage_query_in_progress: false,
        requests_rx: Box::pin(requests_rx),
        responses_tx,
        multistage_requests_to_advance: VecDeque::new(),
        block_headers_cache: lru::LruCache::with_hasher(
            NonZero::<usize>::new(32).unwrap_or_else(|| unreachable!()),
            Default::default(),
        ),
        best_block_hash_pending: Vec::new(),
        pending_get_finalized_head: Vec::new(),
        block_headers_pending: hashbrown::HashMap::with_capacity_and_hasher(0, Default::default()),
        block_runtimes_cache: lru::LruCache::with_hasher(
            NonZero::<usize>::new(32).unwrap_or_else(|| unreachable!()),
            Default::default(),
        ),
        block_runtimes_pending: hashbrown::HashMap::with_capacity_and_hasher(0, Default::default()),
        state_get_keys_paged_cache: lru::LruCache::with_hasher(
            NonZero::<usize>::new(2).unwrap(),
            util::SipHasherBuild::new({
                let mut seed = [0; 16];
                config.platform.fill_random_bytes(&mut seed);
                seed
            }),
        ),
        genesis_block_hash: config.genesis_block_hash,
        printed_legacy_json_rpc_warning: false,
        statement_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
            2,
            Default::default(),
        ),
        v2_statement_peers: hashbrown::HashSet::with_capacity_and_hasher(8, Default::default()),
        network_events_rx: None,
        platform: config.platform,
    };

    // Subscribe to network events for receiving statements
    me.network_events_rx = Some(me.network_service.subscribe().await);

    loop {
        // Yield at every loop in order to provide better tasks granularity.
        futures_lite::future::yield_now().await;

        enum WakeUpReason<'a, TPlat: PlatformRef> {
            ForegroundDead,
            GarbageCollection,
            IncomingJsonRpcRequest(String),
            AdvanceMultiStageRequest {
                request_id_json: String,
                stage: MultiStageRequestStage,
                request_ty: MultiStageRequestTy,
            },
            Event(Event<TPlat>),
            RuntimeServiceSubscriptionReady(runtime_service::SubscribeAll<TPlat>),
            RuntimeServiceSubscriptionNotification {
                notification: runtime_service::Notification,
                subscription: &'a mut runtime_service::Subscription<TPlat>,
                pinned_blocks:
                    &'a mut hashbrown::HashMap<[u8; 32], RecentBlock, fnv::FnvBuildHasher>,
                finalized_and_pruned_lru: &'a mut lru::LruCache<[u8; 32], (), fnv::FnvBuildHasher>,
                current_best_block: &'a mut [u8; 32],
                new_heads_and_runtime_subscriptions_stale: &'a mut Option<Option<[u8; 32]>>,
                current_finalized_block: &'a mut [u8; 32],
                finalized_heads_subscriptions_stale: &'a mut bool,
            },
            RuntimeServiceSubscriptionDead,
            StartStorageSubscriptionsUpdates,
            NotifyFinalizedHeads,
            NotifyNewHeadsRuntimeSubscriptions(Option<[u8; 32]>),
            NetworkStatementReceived(Vec<u8>),
            StatementPeerConnected {
                peer_id: PeerId,
                version: network_service::StatementProtocolVersion,
            },
            StatementPeerDisconnected {
                peer_id: PeerId,
            },
        }

        // Wait until there is something to do.
        let wake_up_reason = {
            async {
                match &mut me.runtime_service_subscription {
                    RuntimeServiceSubscription::NotCreated => {
                        // TODO: only do this if there is a need for the subscription
                        WakeUpReason::RuntimeServiceSubscriptionDead
                    }
                    RuntimeServiceSubscription::Active {
                        subscription,
                        pinned_blocks,
                        finalized_and_pruned_lru,
                        current_best_block,
                        new_heads_and_runtime_subscriptions_stale,
                        current_finalized_block,
                        finalized_heads_subscriptions_stale,
                    } => {
                        if !me.legacy_api_storage_query_in_progress
                            && !me.legacy_api_stale_storage_subscriptions.is_empty()
                        {
                            return WakeUpReason::StartStorageSubscriptionsUpdates;
                        }

                        if *finalized_heads_subscriptions_stale {
                            return WakeUpReason::NotifyFinalizedHeads;
                        }

                        if let Some(previous_best_block) =
                            new_heads_and_runtime_subscriptions_stale.take()
                        {
                            return WakeUpReason::NotifyNewHeadsRuntimeSubscriptions(
                                previous_best_block,
                            );
                        }

                        match subscription.next().await {
                            Some(notification) => {
                                WakeUpReason::RuntimeServiceSubscriptionNotification {
                                    notification,
                                    subscription,
                                    pinned_blocks,
                                    finalized_and_pruned_lru,
                                    current_best_block,
                                    new_heads_and_runtime_subscriptions_stale,
                                    current_finalized_block,
                                    finalized_heads_subscriptions_stale,
                                }
                            }
                            None => WakeUpReason::RuntimeServiceSubscriptionDead,
                        }
                    }
                    RuntimeServiceSubscription::Pending(pending) => {
                        WakeUpReason::RuntimeServiceSubscriptionReady(pending.await)
                    }
                }
            }
            .or(async {
                if let Some((request_id_json, stage, request_ty)) =
                    me.multistage_requests_to_advance.pop_front()
                {
                    WakeUpReason::AdvanceMultiStageRequest {
                        request_id_json,
                        stage,
                        request_ty,
                    }
                } else {
                    future::pending().await
                }
            })
            .or(async {
                if let Some(event) = me.background_tasks.next().await {
                    WakeUpReason::Event(event)
                } else {
                    future::pending().await
                }
            })
            .or(async {
                // Pulling new requests is one of the lowest priority tasks, in order to avoid
                // doing so if the task is overloaded.
                me.requests_rx.next().await.map_or(
                    WakeUpReason::ForegroundDead,
                    WakeUpReason::IncomingJsonRpcRequest,
                )
            })
            .or(async {
                (&mut me.next_garbage_collection).await;
                me.next_garbage_collection = Box::pin(me.platform.sleep(Duration::from_secs(10)));
                WakeUpReason::GarbageCollection
            })
            .or(async {
                // Poll for network events (incoming statements and peer connections)
                let Some(rx) = &me.network_events_rx else {
                    return future::pending().await;
                };
                loop {
                    let Ok(event) = rx.recv().await else {
                        return future::pending().await;
                    };
                    match event {
                        network_service::Event::StatementNotification { statements, .. } => {
                            return WakeUpReason::NetworkStatementReceived(
                                statements.as_encoded().to_vec(),
                            );
                        }
                        network_service::Event::StatementProtocolConnected { peer_id, version } => {
                            return WakeUpReason::StatementPeerConnected { peer_id, version };
                        }
                        network_service::Event::Disconnected { peer_id } => {
                            return WakeUpReason::StatementPeerDisconnected { peer_id };
                        }
                        _ => {}
                    }
                }
            })
            .await
        };

        match wake_up_reason {
            WakeUpReason::ForegroundDead => {
                // Service foreground has been destroyed. Stop the background task.
                return;
            }

            WakeUpReason::GarbageCollection => {
                // Periodically shrink all the shrinkable containers, in order to make sure that
                // a temporary peak in memory usage doesn't keep memory allocated forever.
                me.chain_head_follow_subscriptions.shrink_to_fit();
                me.all_heads_subscriptions.shrink_to_fit();
                me.new_heads_subscriptions.shrink_to_fit();
                me.finalized_heads_subscriptions.shrink_to_fit();
                me.runtime_version_subscriptions.shrink_to_fit();
                me.transactions_subscriptions.shrink_to_fit();
                me.statement_subscriptions.shrink_to_fit();
                me.legacy_api_stale_storage_subscriptions.shrink_to_fit();
                me.multistage_requests_to_advance.shrink_to_fit();
                me.block_headers_pending.shrink_to_fit();
                me.block_runtimes_pending.shrink_to_fit();
            }

            WakeUpReason::NetworkStatementReceived(notification_data) => {
                // If there is no statement subscription, we can skip decoding the notification entirely.
                if me.statement_subscriptions.is_empty() {
                    continue;
                }

                match codec::decode_statement_notification(&notification_data) {
                    Ok(statements) => {
                        for statement in statements {
                            let Ok(encoded) = codec::encode_statement(&statement) else {
                                continue;
                            };

                            for (sub_id, topic_filter) in &me.statement_subscriptions {
                                if topic_filter.matches(&statement.topics) {
                                    let notification =
                                        methods::ServerToClient::statement_notification {
                                            subscription: Cow::Borrowed(sub_id),
                                            statement: methods::HexString(encoded.clone()),
                                        }
                                        .to_json_request_object_parameters(None);
                                    if me.responses_tx.send(notification).await.is_err() {
                                        log!(
                                            &me.platform,
                                            Debug,
                                            &me.log_target,
                                            "Failed to send statement notification: response channel closed"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => {
                        log!(
                            &me.platform,
                            Warn,
                            &me.log_target,
                            format!("Failed to decode statement notification: {:?}", err)
                        );
                    }
                }
            }

            WakeUpReason::StatementPeerConnected { peer_id, version } => {
                if version == network_service::StatementProtocolVersion::V2 {
                    me.v2_statement_peers.insert(peer_id.clone());

                    if !me.statement_subscriptions.is_empty() {
                        let filter = build_combined_affinity_filter(&me.statement_subscriptions);

                        let network = me.network_service.clone();
                        me.background_tasks.push(Box::pin(async move {
                            let _ = network.send_topic_affinity(&peer_id, filter).await;
                            Event::TopicAffinitySent
                        }));
                    }
                }
            }

            WakeUpReason::StatementPeerDisconnected { peer_id } => {
                me.v2_statement_peers.remove(&peer_id);
            }

            WakeUpReason::IncomingJsonRpcRequest(request_json) => {
                // New JSON-RPC request pulled from the channel.
                let (request_id_json, request_parsed) =
                    match methods::parse_jsonrpc_client_to_server(&request_json) {
                        Ok(r) => r,
                        Err(methods::ParseClientToServerError::JsonRpcParse(_)) => {
                            // Request has failed to parse. Immediately return an answer.
                            let _ = me
                                .responses_tx
                                .send(parse::build_parse_error_response())
                                .await;
                            continue;
                        }
                        Err(methods::ParseClientToServerError::Method { request_id, error }) => {
                            // Invalid method or parameters. Immediately return an answer.
                            let _ = me.responses_tx.send(error.to_json_error(request_id)).await;
                            continue;
                        }
                        Err(methods::ParseClientToServerError::UnknownNotification { .. }) => {
                            // Invalid notification-style request. As per spec, we simply
                            // ignore them.
                            continue;
                        }
                    };

                // Print a warning for legacy JSON-RPC API functions.
                match request_parsed {
                    // Legacy API functions.
                    methods::MethodCall::account_nextIndex { .. }
                    | methods::MethodCall::author_hasKey { .. }
                    | methods::MethodCall::author_hasSessionKeys { .. }
                    | methods::MethodCall::author_insertKey { .. }
                    | methods::MethodCall::author_pendingExtrinsics { .. }
                    | methods::MethodCall::author_removeExtrinsic { .. }
                    | methods::MethodCall::author_rotateKeys { .. }
                    | methods::MethodCall::author_submitAndWatchExtrinsic { .. }
                    | methods::MethodCall::author_submitExtrinsic { .. }
                    | methods::MethodCall::author_unwatchExtrinsic { .. }
                    | methods::MethodCall::babe_epochAuthorship { .. }
                    | methods::MethodCall::chain_getBlock { .. }
                    | methods::MethodCall::chain_getBlockHash { .. }
                    | methods::MethodCall::chain_getFinalizedHead { .. }
                    | methods::MethodCall::chain_getHeader { .. }
                    | methods::MethodCall::chain_subscribeAllHeads { .. }
                    | methods::MethodCall::chain_subscribeFinalizedHeads { .. }
                    | methods::MethodCall::chain_subscribeNewHeads { .. }
                    | methods::MethodCall::chain_unsubscribeAllHeads { .. }
                    | methods::MethodCall::chain_unsubscribeFinalizedHeads { .. }
                    | methods::MethodCall::chain_unsubscribeNewHeads { .. }
                    | methods::MethodCall::childstate_getKeys { .. }
                    | methods::MethodCall::childstate_getStorage { .. }
                    | methods::MethodCall::childstate_getStorageHash { .. }
                    | methods::MethodCall::childstate_getStorageSize { .. }
                    | methods::MethodCall::grandpa_roundState { .. }
                    | methods::MethodCall::offchain_localStorageGet { .. }
                    | methods::MethodCall::offchain_localStorageSet { .. }
                    | methods::MethodCall::payment_queryInfo { .. }
                    | methods::MethodCall::state_call { .. }
                    | methods::MethodCall::state_getKeys { .. }
                    | methods::MethodCall::state_getKeysPaged { .. }
                    | methods::MethodCall::state_getMetadata { .. }
                    | methods::MethodCall::state_getPairs { .. }
                    | methods::MethodCall::state_getReadProof { .. }
                    | methods::MethodCall::state_getRuntimeVersion { .. }
                    | methods::MethodCall::state_getStorage { .. }
                    | methods::MethodCall::state_getStorageHash { .. }
                    | methods::MethodCall::state_getStorageSize { .. }
                    | methods::MethodCall::state_queryStorage { .. }
                    | methods::MethodCall::state_queryStorageAt { .. }
                    | methods::MethodCall::state_subscribeRuntimeVersion { .. }
                    | methods::MethodCall::state_subscribeStorage { .. }
                    | methods::MethodCall::state_unsubscribeRuntimeVersion { .. }
                    | methods::MethodCall::state_unsubscribeStorage { .. }
                    | methods::MethodCall::system_accountNextIndex { .. }
                    | methods::MethodCall::system_addReservedPeer { .. }
                    | methods::MethodCall::system_chain { .. }
                    | methods::MethodCall::system_chainType { .. }
                    | methods::MethodCall::system_dryRun { .. }
                    | methods::MethodCall::system_health { .. }
                    | methods::MethodCall::system_localListenAddresses { .. }
                    | methods::MethodCall::system_localPeerId { .. }
                    | methods::MethodCall::system_name { .. }
                    | methods::MethodCall::system_networkState { .. }
                    | methods::MethodCall::system_nodeRoles { .. }
                    | methods::MethodCall::system_peers { .. }
                    | methods::MethodCall::system_properties { .. }
                    | methods::MethodCall::system_removeReservedPeer { .. }
                    | methods::MethodCall::system_version { .. } => {
                        if !me.printed_legacy_json_rpc_warning {
                            me.printed_legacy_json_rpc_warning = true;
                            log!(
                                &me.platform,
                                Warn,
                                &me.log_target,
                                format!(
                                    "The JSON-RPC client has just called a JSON-RPC function from \
                                    the legacy JSON-RPC API ({}). Legacy JSON-RPC functions have \
                                    loose semantics and cannot be properly implemented on a light \
                                    client. You are encouraged to use the new JSON-RPC API \
                                    <https://github.com/paritytech/json-rpc-interface-spec/> \
                                    instead. The legacy JSON-RPC API functions will be deprecated \
                                    and removed in the distant future.",
                                    request_parsed.name()
                                )
                            )
                        }
                    }

                    // Non-legacy-API functions.
                    methods::MethodCall::chainHead_v1_body { .. }
                    | methods::MethodCall::chainHead_v1_call { .. }
                    | methods::MethodCall::chainHead_v1_continue { .. }
                    | methods::MethodCall::chainHead_v1_follow { .. }
                    | methods::MethodCall::chainHead_v1_header { .. }
                    | methods::MethodCall::chainHead_v1_stopOperation { .. }
                    | methods::MethodCall::chainHead_v1_storage { .. }
                    | methods::MethodCall::chainHead_v1_unfollow { .. }
                    | methods::MethodCall::chainHead_v1_unpin { .. }
                    | methods::MethodCall::chainSpec_v1_chainName { .. }
                    | methods::MethodCall::chainSpec_v1_genesisHash { .. }
                    | methods::MethodCall::chainSpec_v1_properties { .. }
                    | methods::MethodCall::rpc_methods { .. }
                    | methods::MethodCall::sudo_unstable_p2pDiscover { .. }
                    | methods::MethodCall::sudo_unstable_version { .. }
                    | methods::MethodCall::transaction_v1_broadcast { .. }
                    | methods::MethodCall::transaction_v1_stop { .. }
                    | methods::MethodCall::transactionWatch_v1_submitAndWatch { .. }
                    | methods::MethodCall::transactionWatch_v1_unwatch { .. }
                    | methods::MethodCall::sudo_network_unstable_watch { .. }
                    | methods::MethodCall::sudo_network_unstable_unwatch { .. }
                    | methods::MethodCall::chainHead_unstable_finalizedDatabase { .. }
                    | methods::MethodCall::statement_submit { .. }
                    | methods::MethodCall::statement_subscribe { .. }
                    | methods::MethodCall::statement_unsubscribe { .. } => {}
                }

                // Actual requests handler.
                match request_parsed {
                    methods::MethodCall::author_pendingExtrinsics {} => {
                        // Because multiple different chains ("chain" in the context of the
                        // public API of smoldot) might share the same transactions service, it
                        // could be possible for chain A to submit a transaction and then for
                        // chain B to read it by calling `author_pendingExtrinsics`. This would
                        // make it possible for the API user of chain A to be able to communicate
                        // with the API user of chain B. While the implications of permitting
                        // this are unclear, it is not a bad idea to prevent this communication
                        // from happening. Consequently, we always return an empty list of
                        // pending extrinsics.
                        // TODO: could store the list of pending transactions in the JSON-RPC service instead
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::author_pendingExtrinsics(Vec::new())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::author_submitExtrinsic { transaction } => {
                        // Note that this function is misnamed. It should really be called
                        // "author_submitTransaction".

                        // In Substrate, `author_submitExtrinsic` returns the hash of the
                        // transaction. It is unclear whether it has to actually be the hash of
                        // the transaction or if it could be any opaque value. Additionally, there
                        // isn't any other JSON-RPC method that accepts as parameter the value
                        // returned here. When in doubt, we return the hash as well.

                        let mut hash_context = blake2_rfc::blake2b::Blake2b::new(32);
                        hash_context.update(&transaction.0);
                        let mut transaction_hash: [u8; 32] = Default::default();
                        transaction_hash.copy_from_slice(hash_context.finalize().as_bytes());
                        me.transactions_service
                            .submit_transaction(transaction.0)
                            .await;
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::author_submitExtrinsic(methods::HashHexString(
                                    transaction_hash,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::author_submitAndWatchExtrinsic { transaction } => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        let mut transaction_updates = Box::pin(
                            me.transactions_service
                                .submit_and_watch_transaction(transaction.0, 16, true)
                                .await,
                        );

                        let _prev_value = me.transactions_subscriptions.insert(
                            subscription_id.clone(),
                            TransactionWatch {
                                included_block: None,
                                num_broadcasted_peers: 0,
                                ty: TransactionWatchTy::Legacy,
                            },
                        );
                        debug_assert!(_prev_value.is_none());

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::author_submitAndWatchExtrinsic(Cow::Borrowed(
                                    &subscription_id,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;

                        // Push a task that will generate an event whenever the transactions
                        // service sends a notification.
                        me.background_tasks.push(Box::pin(async move {
                            let Some(status) = transaction_updates.as_mut().next().await else {
                                unreachable!()
                            };
                            Event::TransactionEvent {
                                subscription_id,
                                event: status,
                                watcher: transaction_updates,
                            }
                        }));
                    }

                    methods::MethodCall::author_unwatchExtrinsic { subscription } => {
                        let exists = me
                            .transactions_subscriptions
                            .get(&*subscription)
                            .map_or(false, |sub| matches!(sub.ty, TransactionWatchTy::Legacy));
                        if exists {
                            me.transactions_subscriptions.remove(&*subscription);
                        }
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::author_unwatchExtrinsic(exists)
                                    .to_json_response(request_id_json),
                            )
                            .await;

                        // Note that this doesn't remove the transaction from the transactions
                        // service.
                        // We don't cancel the task in `background_tasks` that will
                        // generate events about this transaction. Instead, the task will stop
                        // renewing itself the next time it generates a notification.
                    }

                    methods::MethodCall::chain_getBlock { hash } => {
                        // Because this request requires asynchronous operations, we push it
                        // to a list of "multi-stage requests" that are processed later.
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            match hash {
                                Some(methods::HashHexString(block_hash)) => {
                                    MultiStageRequestStage::BlockHashKnown { block_hash }
                                }
                                None => MultiStageRequestStage::BlockHashNotKnown,
                            },
                            MultiStageRequestTy::ChainGetBlock,
                        ));
                    }

                    methods::MethodCall::chain_getBlockHash { height } => {
                        // TODO: maybe store values in cache?
                        match height {
                            Some(0) => {
                                // Block 0 is important for the JSON-RPC client to be able
                                // to generate transactions for the chain. Make sure that it is
                                // always queriable
                                let _ = me
                                    .responses_tx
                                    .send(
                                        methods::Response::chain_getBlockHash(
                                            methods::HashHexString(me.genesis_block_hash),
                                        )
                                        .to_json_response(request_id_json),
                                    )
                                    .await;
                            }
                            None => {
                                // Because finding the best block might require an asynchronous
                                // operation, we push it to a list of "multi-stage requests"
                                // that are processed later.
                                me.multistage_requests_to_advance.push_back((
                                    request_id_json.to_owned(),
                                    MultiStageRequestStage::BlockHashNotKnown,
                                    MultiStageRequestTy::ChainGetBestBlockHash,
                                ));
                            }
                            Some(_) => {
                                // TODO: look into some list of known blocks

                                // While could ask a full node for the block with a specific
                                // number, there is absolutely no way to verify the answer of
                                // the full node.
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_success_response(request_id_json, "null"))
                                    .await;
                            }
                        }
                    }

                    methods::MethodCall::chain_getFinalizedHead {} => {
                        if let RuntimeServiceSubscription::Active {
                            current_finalized_block,
                            ..
                        } = &me.runtime_service_subscription
                        {
                            // The finalized block hash is known. Send back an answer immediately.
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::chain_getFinalizedHead(
                                        methods::HashHexString(*current_finalized_block),
                                    )
                                    .to_json_response(request_id_json),
                                )
                                .await;
                        } else {
                            // Finalized block hash not known yet. Push the request to a list of
                            // requests that will be answered once it is known.
                            me.pending_get_finalized_head
                                .push(request_id_json.to_owned());
                        }
                    }

                    methods::MethodCall::chain_getHeader { hash } => {
                        // Because this request requires asynchronous operations, we push it
                        // to a list of "multi-stage requests" that are processed later.
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            match hash {
                                Some(methods::HashHexString(block_hash)) => {
                                    MultiStageRequestStage::BlockHashKnown { block_hash }
                                }
                                None => MultiStageRequestStage::BlockHashNotKnown,
                            },
                            MultiStageRequestTy::ChainGetHeader,
                        ));
                    }

                    methods::MethodCall::chain_subscribeAllHeads {} => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chain_subscribeAllHeads(Cow::Borrowed(
                                    &subscription_id,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;

                        let _was_inserted = me.all_heads_subscriptions.insert(subscription_id);
                        debug_assert!(_was_inserted);

                        // Note that, contrary to other similar subscriptions, we don't send
                        // any notification immediately.
                    }

                    methods::MethodCall::chain_subscribeFinalizedHeads {} => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chain_subscribeFinalizedHeads(Cow::Borrowed(
                                    &subscription_id,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;

                        // If the finalized block hash is known, send a notification immediately.
                        // Otherwise, one will be sent once the finalized block hash is known.
                        if let RuntimeServiceSubscription::Active {
                            current_finalized_block,
                            pinned_blocks,
                            ..
                        } = &me.runtime_service_subscription
                        {
                            match methods::Header::from_scale_encoded_header(
                                &pinned_blocks
                                    .get(current_finalized_block)
                                    .unwrap()
                                    .scale_encoded_header,
                                me.runtime_service.block_number_bytes(),
                            ) {
                                Ok(h) => {
                                    let _ = me
                                        .responses_tx
                                        .send(
                                            methods::ServerToClient::chain_finalizedHead {
                                                subscription: Cow::Borrowed(&subscription_id),
                                                result: h,
                                            }
                                            .to_json_request_object_parameters(None),
                                        )
                                        .await;
                                }
                                Err(error) => {
                                    log!(
                                        &me.platform,
                                        Warn,
                                        &me.log_target,
                                        format!(
                                            "`chain_subscribeFinalizedHeads` subscription has \
                                                skipped block due to undecodable header. Hash: {}. \
                                                Error: {}",
                                            HashDisplay(current_finalized_block),
                                            error
                                        )
                                    );
                                }
                            }
                        }

                        let _was_inserted =
                            me.finalized_heads_subscriptions.insert(subscription_id);
                        debug_assert!(_was_inserted);
                    }

                    methods::MethodCall::chain_subscribeNewHeads {} => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chain_subscribeNewHeads(Cow::Borrowed(
                                    &subscription_id,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;

                        // If the best block hash is known, send a notification immediately.
                        // Otherwise, one will be sent once the best block hash is known.
                        if let RuntimeServiceSubscription::Active {
                            current_best_block,
                            pinned_blocks,
                            ..
                        } = &me.runtime_service_subscription
                        {
                            match methods::Header::from_scale_encoded_header(
                                &pinned_blocks
                                    .get(current_best_block)
                                    .unwrap()
                                    .scale_encoded_header,
                                me.runtime_service.block_number_bytes(),
                            ) {
                                Ok(h) => {
                                    let _ = me
                                        .responses_tx
                                        .send(
                                            methods::ServerToClient::chain_newHead {
                                                subscription: Cow::Borrowed(&subscription_id),
                                                result: h,
                                            }
                                            .to_json_request_object_parameters(None),
                                        )
                                        .await;
                                }
                                Err(error) => {
                                    log!(
                                        &me.platform,
                                        Warn,
                                        &me.log_target,
                                        format!(
                                            "`chain_subscribeNewHeads` subscription has \
                                                skipped block due to undecodable header. Hash: {}. \
                                                Error: {}",
                                            HashDisplay(current_best_block),
                                            error
                                        )
                                    );
                                }
                            }
                        }

                        let _was_inserted = me.new_heads_subscriptions.insert(subscription_id);
                        debug_assert!(_was_inserted);
                    }

                    methods::MethodCall::chain_unsubscribeAllHeads { subscription } => {
                        let exists = me.all_heads_subscriptions.remove(&subscription);
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chain_unsubscribeAllHeads(exists)
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription } => {
                        let exists = me.finalized_heads_subscriptions.remove(&subscription);
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chain_unsubscribeFinalizedHeads(exists)
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chain_unsubscribeNewHeads { subscription } => {
                        let exists = me.new_heads_subscriptions.remove(&subscription);
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chain_unsubscribeNewHeads(exists)
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::payment_queryInfo {
                        extrinsic: methods::HexString(extrinsic),
                        hash,
                    } => {
                        // Because this request requires asynchronous operations, we push it
                        // to a list of "multi-stage requests" that are processed later.
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            match hash {
                                Some(methods::HashHexString(block_hash)) => {
                                    MultiStageRequestStage::BlockHashKnown { block_hash }
                                }
                                None => MultiStageRequestStage::BlockHashNotKnown,
                            },
                            MultiStageRequestTy::PaymentQueryInfo { extrinsic },
                        ));
                    }

                    methods::MethodCall::rpc_methods {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::rpc_methods(methods::RpcMethods {
                                    methods: methods::MethodCall::method_names()
                                        .map(|n| n.into())
                                        .collect(),
                                })
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::state_call {
                        name,
                        parameters,
                        hash,
                    } => {
                        // Because this request requires asynchronous operations, we push it
                        // to a list of "multi-stage requests" that are processed later.
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            match hash {
                                Some(methods::HashHexString(block_hash)) => {
                                    MultiStageRequestStage::BlockHashKnown { block_hash }
                                }
                                None => MultiStageRequestStage::BlockHashNotKnown,
                            },
                            MultiStageRequestTy::StateCall {
                                name: name.into_owned(),
                                parameters: parameters.0,
                            },
                        ));
                    }

                    methods::MethodCall::state_getKeys {
                        prefix: methods::HexString(prefix),
                        hash,
                    } => {
                        // Because this request requires asynchronous operations, we push it
                        // to a list of "multi-stage requests" that are processed later.
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            match hash {
                                Some(methods::HashHexString(block_hash)) => {
                                    MultiStageRequestStage::BlockHashKnown { block_hash }
                                }
                                None => MultiStageRequestStage::BlockHashNotKnown,
                            },
                            MultiStageRequestTy::StateGetKeys { prefix },
                        ));
                    }

                    methods::MethodCall::state_getKeysPaged {
                        prefix,
                        count,
                        start_key,
                        hash,
                    } => {
                        // Because this request requires asynchronous operations, we push it
                        // to a list of "multi-stage requests" that are processed later.
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            match hash {
                                Some(methods::HashHexString(block_hash)) => {
                                    MultiStageRequestStage::BlockHashKnown { block_hash }
                                }
                                None => MultiStageRequestStage::BlockHashNotKnown,
                            },
                            MultiStageRequestTy::StateGetKeysPaged {
                                prefix: prefix.map_or(Vec::new(), |p| p.0),
                                count,
                                start_key: start_key.map(|p| p.0),
                            },
                        ));
                    }

                    methods::MethodCall::state_queryStorageAt { keys, at } => {
                        // Because this request requires asynchronous operations, we push it
                        // to a list of "multi-stage requests" that are processed later.
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            match at {
                                Some(methods::HashHexString(block_hash)) => {
                                    MultiStageRequestStage::BlockHashKnown { block_hash }
                                }
                                None => MultiStageRequestStage::BlockHashNotKnown,
                            },
                            MultiStageRequestTy::StateQueryStorageAt { keys },
                        ));
                    }

                    methods::MethodCall::state_getMetadata { hash } => {
                        // Because this request requires asynchronous operations, we push it
                        // to a list of "multi-stage requests" that are processed later.
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            match hash {
                                Some(methods::HashHexString(block_hash)) => {
                                    MultiStageRequestStage::BlockHashKnown { block_hash }
                                }
                                None => MultiStageRequestStage::BlockHashNotKnown,
                            },
                            MultiStageRequestTy::StateGetMetadata,
                        ));
                    }

                    methods::MethodCall::state_getReadProof { keys, at } => {
                        // Because this request requires asynchronous operations, we push it
                        // to a list of "multi-stage requests" that are processed later.
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            match at {
                                Some(methods::HashHexString(block_hash)) => {
                                    MultiStageRequestStage::BlockHashKnown { block_hash }
                                }
                                None => MultiStageRequestStage::BlockHashNotKnown,
                            },
                            MultiStageRequestTy::StateGetReadProof { keys },
                        ));
                    }

                    methods::MethodCall::state_getStorage { key, hash } => {
                        // Because this request requires asynchronous operations, we push it
                        // to a list of "multi-stage requests" that are processed later.
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            match hash {
                                Some(methods::HashHexString(block_hash)) => {
                                    MultiStageRequestStage::BlockHashKnown { block_hash }
                                }
                                None => MultiStageRequestStage::BlockHashNotKnown,
                            },
                            MultiStageRequestTy::StateGetStorage { key: key.0 },
                        ));
                    }

                    methods::MethodCall::state_getRuntimeVersion { at } => {
                        // Because this request requires asynchronous operations, we push it
                        // to a list of "multi-stage requests" that are processed later.
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            match at {
                                Some(methods::HashHexString(block_hash)) => {
                                    MultiStageRequestStage::BlockHashKnown { block_hash }
                                }
                                None => MultiStageRequestStage::BlockHashNotKnown,
                            },
                            MultiStageRequestTy::StateGetRuntimeVersion,
                        ));
                    }

                    methods::MethodCall::state_subscribeRuntimeVersion {} => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::state_subscribeRuntimeVersion(Cow::Borrowed(
                                    &subscription_id,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;

                        // If the finalized block runtime is known, immediately send back
                        // a notification.
                        if let RuntimeServiceSubscription::Active {
                            current_best_block,
                            pinned_blocks,
                            ..
                        } = &me.runtime_service_subscription
                        {
                            // TODO: we don't send None in case of error; remove the Option altogether
                            if let Ok(runtime_version) = &*pinned_blocks
                                .get(current_best_block)
                                .unwrap()
                                .runtime_version
                            {
                                let _ = me
                                    .responses_tx
                                    .send(
                                        methods::ServerToClient::state_runtimeVersion {
                                            subscription: Cow::Borrowed(&subscription_id),
                                            result: Some(convert_runtime_version_legacy(
                                                runtime_version,
                                            )),
                                        }
                                        .to_json_request_object_parameters(None),
                                    )
                                    .await;
                            }
                        }

                        let _was_inserted =
                            me.runtime_version_subscriptions.insert(subscription_id);
                        debug_assert!(_was_inserted);
                    }

                    methods::MethodCall::state_subscribeStorage { list } => {
                        // TODO: limit the size of `list` to avoid DoS attacks; this is out of scope of this module and should be done "externally"
                        if list.is_empty() {
                            // When the list of keys is empty, that means we want to subscribe
                            // to *all* storage changes. It is not possible to reasonably
                            // implement this in a light client.
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::ServerError(
                                        -32000,
                                        "Subscribing to all storage changes isn't supported",
                                    ),
                                    None,
                                ))
                                .await;
                            continue;
                        }

                        let subscription_id = Arc::<str>::from({
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        });

                        for key in list {
                            let _was_inserted = me
                                .legacy_api_storage_subscriptions_by_key
                                .insert((key.0.clone(), subscription_id.clone()));
                            debug_assert!(_was_inserted);
                            let _was_inserted = me
                                .legacy_api_storage_subscriptions
                                .insert((subscription_id.clone(), key.0));
                            debug_assert!(_was_inserted);
                        }

                        // The subscription is inserted in a list of "stale" subscriptions.
                        // It will be picked up as soon as possible.
                        let _was_inserted = me
                            .legacy_api_stale_storage_subscriptions
                            .insert(subscription_id.clone());
                        debug_assert!(_was_inserted);

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::state_subscribeStorage(Cow::Borrowed(
                                    &*subscription_id,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::state_unsubscribeRuntimeVersion { subscription } => {
                        let exists = me.runtime_version_subscriptions.remove(&*subscription);
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::state_unsubscribeRuntimeVersion(exists)
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::state_unsubscribeStorage { subscription } => {
                        let subscription = Arc::<str>::from(&*subscription);

                        // Remove the subscription from the state. This is a bit complicated due
                        // to the use of `BTreeSet`s.
                        let subscribed_keys = {
                            let mut after = me
                                .legacy_api_storage_subscriptions
                                .split_off(&(subscription.clone(), Vec::new()));
                            if let Some(first_entry_after) =
                                after.iter().find(|(s, _)| *s != subscription).cloned()
                            // TODO: O(n) ^
                            {
                                me.legacy_api_storage_subscriptions
                                    .append(&mut after.split_off(&first_entry_after));
                            }
                            after
                        };
                        let exists = !subscribed_keys.is_empty();
                        for (_, key) in subscribed_keys {
                            let _was_removed = me
                                .legacy_api_storage_subscriptions_by_key
                                .remove(&(key, subscription.clone()));
                            debug_assert!(_was_removed);
                        }

                        let _ = me
                            .legacy_api_stale_storage_subscriptions
                            .remove(&subscription);

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::state_unsubscribeStorage(exists)
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_accountNextIndex { account } => {
                        // Because this request requires asynchronous operations, we push it
                        // to a list of "multi-stage requests" that are processed later.
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            MultiStageRequestStage::BlockHashNotKnown,
                            MultiStageRequestTy::SystemAccountNextIndex {
                                account_id: account.0,
                            },
                        ));
                    }

                    methods::MethodCall::system_chain {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_chain((&me.chain_name).into())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_chainType {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_chainType((&me.chain_ty).into())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_health {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_health(methods::SystemHealth {
                                    is_syncing: !me
                                        .runtime_service
                                        .is_near_head_of_chain_heuristic()
                                        .await,
                                    peers: u64::try_from(
                                        me.sync_service.syncing_peers().await.len(),
                                    )
                                    .unwrap_or(u64::MAX),
                                    should_have_peers: me.chain_is_live,
                                })
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_localListenAddresses {} => {
                        // Light client never listens on any address.
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_localListenAddresses(Vec::new())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_name {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_name((&me.system_name).into())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_nodeRoles {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_nodeRoles(Cow::Borrowed(&[
                                    methods::NodeRole::Light,
                                ]))
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_peers {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_peers(
                                    me.sync_service
                                        .syncing_peers()
                                        .await
                                        .map(|(peer_id, role, best_number, best_hash)| {
                                            methods::SystemPeer {
                                                peer_id: peer_id.to_string(),
                                                roles: match role {
                                                    sync_service::Role::Authority => {
                                                        methods::SystemPeerRole::Authority
                                                    }
                                                    sync_service::Role::Full => {
                                                        methods::SystemPeerRole::Full
                                                    }
                                                    sync_service::Role::Light => {
                                                        methods::SystemPeerRole::Light
                                                    }
                                                },
                                                best_hash: methods::HashHexString(best_hash),
                                                best_number,
                                            }
                                        })
                                        .collect(),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_properties {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_properties(
                                    serde_json::from_str(&me.chain_properties_json).unwrap(),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_version {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_version((&me.system_version).into())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainHead_v1_body {
                        follow_subscription,
                        hash,
                    } => {
                        let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .get_mut(&*follow_subscription)
                        else {
                            // Subscription doesn't exist.
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::chainHead_v1_body(
                                        methods::ChainHeadBodyCallReturn::LimitReached {},
                                    )
                                    .to_json_response(request_id_json),
                                )
                                .await;
                            continue;
                        };

                        // Determine whether the requested block hash is valid, and if yes its
                        // number and extrinsics trie root. The extrinsics trie root is used to
                        // verify whether the body we download is correct.
                        let (block_number, extrinsics_root) = {
                            if let Some(header) = subscription.pinned_blocks_headers.get(&hash.0) {
                                let decoded =
                                    header::decode(header, me.sync_service.block_number_bytes())
                                        .unwrap(); // TODO: unwrap?
                                (decoded.number, *decoded.extrinsics_root)
                            } else {
                                // Block isn't pinned. Request is invalid.
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        request_id_json,
                                        parse::ErrorResponse::ApplicationDefined(
                                            -32801,
                                            "unknown or unpinned block",
                                        ),
                                        None,
                                    ))
                                    .await;
                                continue;
                            }
                        };

                        // Check whether there is an operation slot available.
                        subscription.available_operation_slots =
                            match subscription.available_operation_slots.checked_sub(1) {
                                Some(s) => s,
                                None => {
                                    let _ = me
                                        .responses_tx
                                        .send(
                                            methods::Response::chainHead_v1_body(
                                                methods::ChainHeadBodyCallReturn::LimitReached {},
                                            )
                                            .to_json_response(request_id_json),
                                        )
                                        .await;
                                    continue;
                                }
                            };

                        // Build the future that will grab the block body.
                        let body_download_future = me.sync_service.clone().block_query(
                            block_number,
                            hash.0,
                            codec::BlocksRequestFields {
                                header: false,
                                body: true,
                                justifications: false,
                            },
                            3,
                            Duration::from_secs(20),
                            NonZero::<u32>::new(2).unwrap(),
                        );

                        // Allocate an operation ID, update the local state, and notify the
                        // JSON-RPC client.
                        let operation_id = {
                            let mut operation_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut operation_id);
                            bs58::encode(operation_id).into_string()
                        };
                        let interrupt = event_listener::Event::new();
                        let on_interrupt = interrupt.listen();
                        let _was_in = subscription.operations_in_progress.insert(
                            operation_id.clone(),
                            ChainHeadOperation {
                                occupied_slots: 1,
                                interrupt,
                            },
                        );
                        debug_assert!(_was_in.is_none());
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_v1_body(
                                    methods::ChainHeadBodyCallReturn::Started {
                                        operation_id: (&operation_id).into(),
                                    },
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;

                        // Finish the download asynchronously.
                        let subscription_id = follow_subscription.into_owned();
                        me.background_tasks.push(Box::pin(async move {
                            async move {
                                on_interrupt.await;
                                // This event is necessary only because tasks can't finish without
                                // generating an event.
                                Event::ChainHeadOperationCancelled
                            }
                            .or(async move {
                                Event::ChainHeadBodyOperationDone {
                                    subscription_id,
                                    operation_id,
                                    expected_extrinsics_root: extrinsics_root,
                                    result: body_download_future.await,
                                }
                            })
                            .await
                        }));
                    }

                    methods::MethodCall::chainHead_v1_call {
                        follow_subscription,
                        hash,
                        function,
                        call_parameters: methods::HexString(call_parameters),
                    } => {
                        let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .get_mut(&*follow_subscription)
                        else {
                            // Subscription doesn't exist.
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::chainHead_v1_call(
                                        methods::ChainHeadBodyCallReturn::LimitReached {},
                                    )
                                    .to_json_response(request_id_json),
                                )
                                .await;
                            continue;
                        };

                        // Determine whether the requested block hash is valid.
                        if !subscription.pinned_blocks_headers.contains_key(&hash.0) {
                            // Block isn't pinned. Request is invalid.
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::ApplicationDefined(
                                        -32801,
                                        "unknown or unpinned block",
                                    ),
                                    None,
                                ))
                                .await;
                            continue;
                        }

                        // Check whether there is an operation slot available.
                        subscription.available_operation_slots =
                            match subscription.available_operation_slots.checked_sub(1) {
                                Some(s) => s,
                                None => {
                                    let _ = me
                                        .responses_tx
                                        .send(
                                            methods::Response::chainHead_v1_call(
                                                methods::ChainHeadBodyCallReturn::LimitReached {},
                                            )
                                            .to_json_response(request_id_json),
                                        )
                                        .await;
                                    continue;
                                }
                            };

                        // Make sure that the subscription is `withRuntime: true`.
                        let Some(runtime_service_subscription_id) =
                            subscription.runtime_service_subscription_id
                        else {
                            // Subscription is "without runtime".
                            // This path is in principle also reachable if the subscription isn't
                            // initialized yet, but in that case the block hash can't possibly be
                            // pinned.
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::InvalidParams,
                                    None,
                                ))
                                .await;
                            continue;
                        };

                        // Extract information about the block.
                        let (pinned_runtime, block_state_trie_root_hash, block_number) = match me
                            .runtime_service
                            .pin_pinned_block_runtime(runtime_service_subscription_id, hash.0)
                            .await
                        {
                            Ok(info) => info,
                            Err(runtime_service::PinPinnedBlockRuntimeError::BlockNotPinned) => {
                                // This has been verified above.
                                unreachable!()
                            }
                            Err(
                                runtime_service::PinPinnedBlockRuntimeError::ObsoleteSubscription,
                            ) => {
                                // The runtime service subscription is dead.
                                let _ = me
                                    .responses_tx
                                    .send(
                                        methods::Response::chainHead_v1_call(
                                            methods::ChainHeadBodyCallReturn::LimitReached {},
                                        )
                                        .to_json_response(request_id_json),
                                    )
                                    .await;
                                continue;
                            }
                        };

                        // Create a future that will perform the runtime call.
                        let runtime_call_future = {
                            let runtime_service = me.runtime_service.clone();
                            let function = function.into_owned();
                            async move {
                                runtime_service
                                    .clone()
                                    .runtime_call(
                                        pinned_runtime,
                                        hash.0,
                                        block_number,
                                        block_state_trie_root_hash,
                                        function,
                                        None,
                                        call_parameters,
                                        3,
                                        Duration::from_secs(20),
                                        NonZero::<u32>::new(2).unwrap(),
                                    )
                                    .await
                            }
                        };

                        // Allocate a new operation ID, update the local state, and send the
                        // confirmation to the JSON-RPC client.
                        let operation_id = {
                            let mut operation_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut operation_id);
                            bs58::encode(operation_id).into_string()
                        };
                        let interrupt = event_listener::Event::new();
                        let on_interrupt = interrupt.listen();
                        let _was_in = subscription.operations_in_progress.insert(
                            operation_id.clone(),
                            ChainHeadOperation {
                                occupied_slots: 1,
                                interrupt,
                            },
                        );
                        debug_assert!(_was_in.is_none());
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_v1_call(
                                    methods::ChainHeadBodyCallReturn::Started {
                                        operation_id: (&operation_id).into(),
                                    },
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;

                        // Finish the call asynchronously.
                        let subscription_id = follow_subscription.into_owned();
                        me.background_tasks.push(Box::pin(async move {
                            async move {
                                on_interrupt.await;
                                // This event is necessary only because tasks can't finish without
                                // generating an event.
                                Event::ChainHeadOperationCancelled
                            }
                            .or(async move {
                                Event::ChainHeadCallOperationDone {
                                    subscription_id,
                                    operation_id,
                                    result: runtime_call_future.await,
                                }
                            })
                            .await
                        }));
                    }

                    methods::MethodCall::chainHead_v1_continue { .. } => {
                        // TODO: not implemented properly
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_v1_continue(())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainHead_v1_storage {
                        follow_subscription,
                        hash,
                        items,
                        child_trie,
                    } => {
                        let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .get_mut(&*follow_subscription)
                        else {
                            // Subscription doesn't exist.
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::chainHead_v1_storage(
                                        methods::ChainHeadStorageReturn::LimitReached {},
                                    )
                                    .to_json_response(request_id_json),
                                )
                                .await;
                            continue;
                        };

                        // Determine whether the requested block hash is valid, and if yes its
                        // number and state trie root. The extrinsics trie root is used to
                        // verify whether the body we download is correct.
                        let (block_number, block_state_trie_root) = {
                            if let Some(header) = subscription.pinned_blocks_headers.get(&hash.0) {
                                let decoded =
                                    header::decode(header, me.sync_service.block_number_bytes())
                                        .unwrap(); // TODO: unwrap?
                                (decoded.number, *decoded.state_root)
                            } else {
                                // Block isn't pinned. Request is invalid.
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        request_id_json,
                                        parse::ErrorResponse::ApplicationDefined(
                                            -32801,
                                            "unknown or unpinned block",
                                        ),
                                        None,
                                    ))
                                    .await;
                                continue;
                            }
                        };

                        if child_trie.is_some() {
                            // TODO: implement this
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::ServerError(
                                        -32000,
                                        "Child key storage queries not supported yet",
                                    ),
                                    None,
                                ))
                                .await;
                            log!(
                                &me.platform,
                                Warn,
                                &me.log_target,
                                "chainHead_v1_storage has been called with a non-null childTrie. \
                                This isn't supported by smoldot yet."
                            );
                            continue;
                        }

                        // Build the list of storage operations that are effectively started.
                        // This reads from the list that the API user requests, and stops if there
                        // is no available operation slot.
                        let mut storage_operations = Vec::with_capacity(items.len());
                        let mut items = items.into_iter();
                        loop {
                            if subscription.available_operation_slots == 0 {
                                break;
                            }
                            let Some(item) = items.next() else { break };
                            subscription.available_operation_slots -= 1;
                            storage_operations.push(sync_service::StorageRequestItem {
                                    key: item.key.0,
                                    ty: match item.ty {
                                        methods::ChainHeadStorageType::Value => {
                                            sync_service::StorageRequestItemTy::Value
                                        }
                                        methods::ChainHeadStorageType::Hash => {
                                            sync_service::StorageRequestItemTy::Hash
                                        }
                                        methods::ChainHeadStorageType::ClosestDescendantMerkleValue => {
                                            sync_service::StorageRequestItemTy::ClosestDescendantMerkleValue
                                        }
                                        methods::ChainHeadStorageType::DescendantsValues => {
                                            sync_service::StorageRequestItemTy::DescendantsValues
                                        }
                                        methods::ChainHeadStorageType::DescendantsHashes => {
                                            sync_service::StorageRequestItemTy::DescendantsHashes
                                        }
                                    },
                                });
                        }

                        // Abort immediately if nothing was started.
                        if storage_operations.is_empty() {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::chainHead_v1_storage(
                                        methods::ChainHeadStorageReturn::LimitReached {},
                                    )
                                    .to_json_response(request_id_json),
                                )
                                .await;
                            continue;
                        }

                        // Initialize the storage query operation.
                        let fetch_operation = me.sync_service.clone().storage_query(
                            block_number,
                            hash.0,
                            block_state_trie_root,
                            storage_operations.into_iter(),
                            3,
                            Duration::from_secs(20),
                            NonZero::<u32>::new(2).unwrap(),
                        );

                        let operation_id = {
                            let mut operation_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut operation_id);
                            bs58::encode(operation_id).into_string()
                        };

                        let interrupt = event_listener::Event::new();
                        let on_interrupt = interrupt.listen();

                        let _was_in = subscription.operations_in_progress.insert(
                            operation_id.clone(),
                            ChainHeadOperation {
                                occupied_slots: 1,
                                interrupt,
                            },
                        );
                        debug_assert!(_was_in.is_none());
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_v1_storage(
                                    methods::ChainHeadStorageReturn::Started {
                                        operation_id: (&operation_id).into(),
                                        discarded_items: items.len(),
                                    },
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;

                        let subscription_id = follow_subscription.into_owned();
                        me.background_tasks.push(Box::pin(async move {
                            async {
                                on_interrupt.await;
                                // This event is necessary only because tasks can't finish without
                                // generating an event.
                                Event::ChainHeadOperationCancelled
                            }
                            .or(async {
                                Event::ChainHeadStorageOperationProgress {
                                    subscription_id,
                                    operation_id,
                                    progress: fetch_operation.advance().await,
                                }
                            })
                            .await
                        }));
                    }

                    methods::MethodCall::chainHead_v1_stopOperation {
                        follow_subscription,
                        operation_id,
                    } => {
                        // Stopping an operation is done by notifying an event so that the
                        // background task stops.
                        if let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .get_mut(&*follow_subscription)
                        {
                            if let Some(operation) =
                                subscription.operations_in_progress.remove(&*operation_id)
                            {
                                operation.interrupt.notify(usize::MAX);
                                subscription.available_operation_slots += operation.occupied_slots;
                            }
                        }

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_v1_stopOperation(())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainHead_v1_follow { with_runtime } => {
                        // Check that the number of existing subscriptions is below the limit.
                        // TODO: configurable limit
                        if me.chain_head_follow_subscriptions.len() >= 2 {
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::ApplicationDefined(
                                        -32800,
                                        "too many active follow subscriptions",
                                    ),
                                    None,
                                ))
                                .await;
                            continue;
                        }

                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        let _prev_value = me.chain_head_follow_subscriptions.insert(
                            subscription_id.clone(),
                            ChainHeadFollow {
                                pinned_blocks_headers: hashbrown::HashMap::with_capacity_and_hasher(
                                    0,
                                    Default::default(),
                                ), // TODO: capacity?
                                operations_in_progress:
                                    hashbrown::HashMap::with_capacity_and_hasher(
                                        32,
                                        Default::default(),
                                    ),
                                available_operation_slots: 32, // TODO: make configurable? adjust dynamically?
                                runtime_service_subscription_id: None,
                            },
                        );
                        debug_assert!(_prev_value.is_none());

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_v1_follow(Cow::Borrowed(
                                    &subscription_id,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;

                        // Subscription asynchronously either to the runtime service or the
                        // sync service.
                        if with_runtime {
                            let runtime_service = me.runtime_service.clone();
                            me.background_tasks.push(Box::pin(async move {
                                Event::ChainHeadSubscriptionWithRuntimeReady {
                                    subscription_id,
                                    subscription: runtime_service
                                        .subscribe_all(
                                            32,
                                            NonZero::<usize>::new(32)
                                                .unwrap_or_else(|| unreachable!()),
                                        )
                                        .await,
                                }
                            }))
                        } else {
                            let sync_service = me.sync_service.clone();
                            me.background_tasks.push(Box::pin(async move {
                                Event::ChainHeadSubscriptionWithoutRuntimeReady {
                                    subscription_id,
                                    subscription: sync_service.subscribe_all(32, false).await,
                                }
                            }))
                        }
                    }

                    methods::MethodCall::chainHead_v1_unfollow {
                        follow_subscription,
                    } => {
                        if let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .remove(&*follow_subscription)
                        {
                            for (_, operation) in subscription.operations_in_progress {
                                operation.interrupt.notify(usize::MAX);
                            }
                        };

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_v1_unfollow(())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainHead_v1_header {
                        follow_subscription,
                        hash,
                    } => {
                        let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .get_mut(&*follow_subscription)
                        else {
                            // Subscription doesn't exist.
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::chainHead_v1_header(None)
                                        .to_json_response(request_id_json),
                                )
                                .await;
                            continue;
                        };

                        let Some(block) = subscription.pinned_blocks_headers.get(&hash.0) else {
                            // Block isn't pinned.
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::ApplicationDefined(
                                        -32801,
                                        "unknown or unpinned block",
                                    ),
                                    None,
                                ))
                                .await;
                            continue;
                        };

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_v1_header(Some(methods::HexString(
                                    block.clone(),
                                )))
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainHead_v1_unpin {
                        follow_subscription,
                        hash_or_hashes,
                    } => {
                        let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .get_mut(&*follow_subscription)
                        else {
                            // Subscription doesn't exist.
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::chainHead_v1_unpin(())
                                        .to_json_response(request_id_json),
                                )
                                .await;
                            continue;
                        };

                        let all_hashes = match &hash_or_hashes {
                            methods::HashHexStringSingleOrArray::Single(hash) => {
                                either::Left(iter::once(&hash.0))
                            }
                            methods::HashHexStringSingleOrArray::Array(hashes) => {
                                either::Right(hashes.iter().map(|h| &h.0))
                            }
                        };

                        let checks_passed = {
                            let mut dedup_check = hashbrown::HashSet::with_capacity_and_hasher(
                                0,
                                SipHasherBuild::new({
                                    let mut seed = [0; 16];
                                    me.randomness.fill_bytes(&mut seed);
                                    seed
                                }),
                            );
                            let mut all_hashes = all_hashes.clone();

                            loop {
                                let Some(hash) = all_hashes.next() else {
                                    break true;
                                };

                                if !dedup_check.insert(hash) {
                                    let _ = me
                                        .responses_tx
                                        .send(parse::build_error_response(
                                            request_id_json,
                                            parse::ErrorResponse::ApplicationDefined(
                                                -32804,
                                                "duplicate block hash",
                                            ),
                                            None,
                                        ))
                                        .await;
                                    break false;
                                }

                                if !subscription.pinned_blocks_headers.contains_key(hash) {
                                    let _ = me
                                        .responses_tx
                                        .send(parse::build_error_response(
                                            request_id_json,
                                            parse::ErrorResponse::InvalidParams,
                                            None,
                                        ))
                                        .await;
                                    break false;
                                }
                            }
                        };

                        if !checks_passed {
                            continue;
                        }

                        // The logic below assumes that all hashes are unique, which is ensured
                        // above.
                        for hash in all_hashes {
                            subscription.pinned_blocks_headers.remove(hash);
                            if let Some(subscription_id) =
                                subscription.runtime_service_subscription_id
                            {
                                me.runtime_service.unpin_block(subscription_id, *hash).await;
                            }
                        }

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_v1_unpin(())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainHead_unstable_finalizedDatabase {
                        max_size_bytes,
                    } => {
                        let response = crate::database::encode_database(
                            &me.network_service,
                            &me.sync_service,
                            &me.runtime_service,
                            &me.genesis_block_hash,
                            usize::try_from(max_size_bytes.unwrap_or(u64::MAX))
                                .unwrap_or(usize::MAX),
                        )
                        .await;

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_unstable_finalizedDatabase(
                                    response.into(),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainSpec_v1_chainName {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainSpec_v1_chainName((&me.chain_name).into())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainSpec_v1_genesisHash {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainSpec_v1_genesisHash(
                                    methods::HashHexString(me.genesis_block_hash),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainSpec_v1_properties {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainSpec_v1_properties(
                                    serde_json::from_str(&me.chain_properties_json).unwrap(),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::sudo_unstable_p2pDiscover { multiaddr } => {
                        match multiaddr.parse::<multiaddr::Multiaddr>() {
                            Ok(mut addr)
                                if matches!(
                                    addr.iter().last(),
                                    Some(multiaddr::Protocol::P2p(_))
                                ) =>
                            {
                                let peer_id_bytes = match addr.iter().last() {
                                    Some(multiaddr::Protocol::P2p(peer_id)) => {
                                        peer_id.into_bytes().to_owned()
                                    }
                                    _ => unreachable!(),
                                };
                                addr.pop();

                                match PeerId::from_bytes(peer_id_bytes) {
                                    Ok(peer_id) => {
                                        me.network_service
                                            .discover(
                                                iter::once((peer_id, iter::once(addr))),
                                                false,
                                            )
                                            .await;
                                        let _ = me
                                            .responses_tx
                                            .send(
                                                methods::Response::sudo_unstable_p2pDiscover(())
                                                    .to_json_response(request_id_json),
                                            )
                                            .await;
                                    }
                                    Err(_) => {
                                        let _ = me
                                            .responses_tx
                                            .send(parse::build_error_response(
                                                request_id_json,
                                                parse::ErrorResponse::InvalidParams,
                                                Some(
                                                    &serde_json::to_string(
                                                        "multiaddr doesn't end with /p2p",
                                                    )
                                                    .unwrap_or_else(|_| unreachable!()),
                                                ),
                                            ))
                                            .await;
                                    }
                                }
                            }
                            Ok(_) => {
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        request_id_json,
                                        parse::ErrorResponse::InvalidParams,
                                        Some(
                                            &serde_json::to_string(
                                                "multiaddr doesn't end with /p2p",
                                            )
                                            .unwrap_or_else(|_| unreachable!()),
                                        ),
                                    ))
                                    .await;
                            }
                            Err(err) => {
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        request_id_json,
                                        parse::ErrorResponse::InvalidParams,
                                        Some(
                                            &serde_json::to_string(&err.to_string())
                                                .unwrap_or_else(|_| unreachable!()),
                                        ),
                                    ))
                                    .await;
                            }
                        }
                    }

                    methods::MethodCall::sudo_unstable_version {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::sudo_unstable_version(
                                    format!("{} {}", me.system_name, me.system_version).into(),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    request_parsed @ (methods::MethodCall::transaction_v1_broadcast { .. }
                    | methods::MethodCall::transactionWatch_v1_submitAndWatch {
                        ..
                    }) => {
                        let (transaction, watched) = match request_parsed {
                            methods::MethodCall::transaction_v1_broadcast {
                                transaction: methods::HexString(transaction),
                            } => (transaction, false),
                            methods::MethodCall::transactionWatch_v1_submitAndWatch {
                                transaction: methods::HexString(transaction),
                            } => (transaction, true),
                            _ => unreachable!(),
                        };

                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        let _prev_value = me.transactions_subscriptions.insert(
                            subscription_id.clone(),
                            TransactionWatch {
                                included_block: None,
                                num_broadcasted_peers: 0,
                                ty: if watched {
                                    TransactionWatchTy::NewApiWatch
                                } else {
                                    TransactionWatchTy::NewApi {
                                        transaction_bytes: transaction.clone(),
                                    }
                                },
                            },
                        );
                        debug_assert!(_prev_value.is_none());

                        let mut transaction_updates = Box::pin(
                            me.transactions_service
                                .submit_and_watch_transaction(transaction, 16, watched)
                                .await,
                        );

                        let _ = me
                            .responses_tx
                            .send(
                                if watched {
                                    methods::Response::transactionWatch_v1_submitAndWatch(
                                        Cow::Borrowed(&subscription_id),
                                    )
                                } else {
                                    methods::Response::transaction_v1_broadcast(Cow::Borrowed(
                                        &subscription_id,
                                    ))
                                }
                                .to_json_response(request_id_json),
                            )
                            .await;

                        // A task is started that will yield when the transactions service
                        // generates a notification.
                        // Note that we do that even for `transaction_v1_broadcast`, as it is
                        // important to pull notifications from the channel in order to not
                        // clog it.
                        me.background_tasks.push(Box::pin(async move {
                            let Some(status) = transaction_updates.as_mut().next().await else {
                                unreachable!()
                            };
                            Event::TransactionEvent {
                                subscription_id,
                                event: status,
                                watcher: transaction_updates,
                            }
                        }));
                    }

                    methods::MethodCall::transaction_v1_stop { operation_id } => {
                        let exists = me
                            .transactions_subscriptions
                            .get(&*operation_id)
                            .map_or(false, |sub| {
                                matches!(sub.ty, TransactionWatchTy::NewApi { .. })
                            });
                        if exists {
                            me.transactions_subscriptions.remove(&*operation_id);
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::transaction_v1_stop(())
                                        .to_json_response(request_id_json),
                                )
                                .await;
                        } else {
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    json_rpc::parse::ErrorResponse::InvalidParams,
                                    None,
                                ))
                                .await;
                        }
                    }

                    methods::MethodCall::transactionWatch_v1_unwatch { subscription } => {
                        let exists = me
                            .transactions_subscriptions
                            .get(&*subscription)
                            .map_or(false, |sub| {
                                matches!(sub.ty, TransactionWatchTy::NewApiWatch)
                            });
                        if exists {
                            me.transactions_subscriptions.remove(&*subscription);
                        }
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::transactionWatch_v1_unwatch(())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::statement_submit { encoded } => {
                        let network = me.network_service.clone();
                        let peers: Vec<_> = network.peers_list().await.collect();
                        let total_peers = peers.len();

                        log!(
                            &me.platform,
                            Debug,
                            &me.log_target,
                            format!(
                                "statement_submit: attempting broadcast to {} peers",
                                total_peers
                            )
                        );

                        if total_peers == 0 {
                            if me
                                .responses_tx
                                .send(
                                    methods::Response::statement_submit(
                                        methods::StatementSubmitResult::Error(
                                            "No connected peers".to_string(),
                                        ),
                                    )
                                    .to_json_response(request_id_json),
                                )
                                .await
                                .is_err()
                            {
                                log!(
                                    &me.platform,
                                    Debug,
                                    &me.log_target,
                                    "Failed to send response for statement_submit: response channel closed"
                                );
                            }
                            continue;
                        }

                        let mut sent_count = 0;
                        for peer in &peers {
                            match network
                                .clone()
                                .send_statements(peer, encoded.0.clone())
                                .await
                            {
                                Ok(_) => {
                                    log!(
                                        &me.platform,
                                        Debug,
                                        &me.log_target,
                                        format!("statement_submit: successfully sent to {}", peer)
                                    );
                                    sent_count += 1;
                                }
                                Err(e) => log!(
                                    &me.platform,
                                    Warn,
                                    &me.log_target,
                                    format!(
                                        "statement_submit: failed to send to {}: {:?}",
                                        peer, e
                                    )
                                ),
                            }
                        }

                        let result = if sent_count == 0 {
                            methods::StatementSubmitResult::Error(
                                "Failed to send to any peers".to_string(),
                            )
                        } else {
                            methods::StatementSubmitResult::OkBroadcast {
                                sent: sent_count,
                                total: total_peers,
                            }
                        };

                        if me
                            .responses_tx
                            .send(
                                methods::Response::statement_submit(result)
                                    .to_json_response(request_id_json),
                            )
                            .await
                            .is_err()
                        {
                            log!(
                                &me.platform,
                                Debug,
                                &me.log_target,
                                "Failed to send response for statement_submit: response channel closed"
                            );
                        }
                    }

                    methods::MethodCall::statement_subscribe { filter } => {
                        let subscription_id: String = {
                            let mut id = [0u8; 32];
                            me.randomness.fill_bytes(&mut id);
                            hex::encode(id)
                        };

                        me.statement_subscriptions
                            .insert(subscription_id.clone(), filter);

                        let combined_filter =
                            build_combined_affinity_filter(&me.statement_subscriptions);

                        for peer_id in me.v2_statement_peers.iter().cloned() {
                            let network = me.network_service.clone();
                            let filter = combined_filter.clone();
                            me.background_tasks.push(Box::pin(async move {
                                let _ = network.send_topic_affinity(&peer_id, filter).await;
                                Event::TopicAffinitySent
                            }));
                        }

                        if me
                            .responses_tx
                            .send(
                                methods::Response::statement_subscribe(Cow::Owned(subscription_id))
                                    .to_json_response(request_id_json),
                            )
                            .await
                            .is_err()
                        {
                            log!(
                                &me.platform,
                                Debug,
                                &me.log_target,
                                "Failed to send response for statement_subscribe: response channel closed"
                            );
                        }
                    }

                    methods::MethodCall::statement_unsubscribe { subscription } => {
                        let existed = me.statement_subscriptions.remove(&subscription).is_some();

                        if existed && !me.v2_statement_peers.is_empty() {
                            let combined_filter =
                                build_combined_affinity_filter(&me.statement_subscriptions);
                            for peer_id in me.v2_statement_peers.iter().cloned() {
                                let network = me.network_service.clone();
                                let filter = combined_filter.clone();
                                me.background_tasks.push(Box::pin(async move {
                                    let _ = network.send_topic_affinity(&peer_id, filter).await;
                                    Event::TopicAffinitySent
                                }));
                            }
                        }

                        if me
                            .responses_tx
                            .send(
                                methods::Response::statement_unsubscribe(existed)
                                    .to_json_response(request_id_json),
                            )
                            .await
                            .is_err()
                        {
                            log!(
                                &me.platform,
                                Debug,
                                &me.log_target,
                                "Failed to send response for statement_unsubscribe: response channel closed"
                            );
                        }
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
                    | methods::MethodCall::state_getStorageHash { .. }
                    | methods::MethodCall::state_getStorageSize { .. }
                    | methods::MethodCall::state_queryStorage { .. }
                    | methods::MethodCall::system_addReservedPeer { .. }
                    | methods::MethodCall::system_dryRun { .. }
                    | methods::MethodCall::system_localPeerId { .. }
                    | methods::MethodCall::system_networkState { .. }
                    | methods::MethodCall::system_removeReservedPeer { .. }
                    | methods::MethodCall::sudo_network_unstable_watch { .. }
                    | methods::MethodCall::sudo_network_unstable_unwatch { .. }) => {
                        // TODO: implement the ones that make sense to implement ^
                        log!(
                            &me.platform,
                            Warn,
                            &me.log_target,
                            format!("JSON-RPC call not supported yet: {:?}", _method)
                        );
                        let _ = me
                            .responses_tx
                            .send(parse::build_error_response(
                                request_id_json,
                                json_rpc::parse::ErrorResponse::ServerError(
                                    -32000,
                                    "Not implemented in smoldot yet",
                                ),
                                None,
                            ))
                            .await;
                    }
                }
            }

            WakeUpReason::AdvanceMultiStageRequest {
                request_id_json,
                stage: MultiStageRequestStage::BlockHashNotKnown,
                request_ty,
            } => {
                // A "multi-stage" request needs to know the best block hash.
                // If it is known, we switch it to the next stage, otherwise we push it in a
                // different list.
                match me.runtime_service_subscription {
                    RuntimeServiceSubscription::Pending { .. }
                    | RuntimeServiceSubscription::NotCreated => {
                        me.best_block_hash_pending
                            .push((request_id_json, request_ty));
                    }
                    RuntimeServiceSubscription::Active {
                        current_best_block, ..
                    } => {
                        // We special-case `state_getKeysPaged` as the results of previous similar
                        // requests are put in a cache. Perform a cache lookup now.
                        if let MultiStageRequestTy::StateGetKeysPaged {
                            prefix,
                            start_key,
                            count,
                        } = &request_ty
                        {
                            if let Some(cache_entry) =
                                me.state_get_keys_paged_cache.get(&GetKeysPagedCacheKey {
                                    hash: current_best_block,
                                    prefix: prefix.clone(),
                                })
                            {
                                // Cache hit!
                                // Filter by start key and count.
                                let results_to_client = cache_entry
                                    .iter()
                                    .filter(|&k| start_key.as_ref().map_or(true, |s| *k > *s))
                                    .cloned()
                                    .map(methods::HexString)
                                    .take(usize::try_from(*count).unwrap_or(usize::MAX))
                                    .collect::<Vec<_>>();
                                let _ = me
                                    .responses_tx
                                    .send(
                                        methods::Response::state_getKeysPaged(results_to_client)
                                            .to_json_response(&request_id_json),
                                    )
                                    .await;
                                continue;
                            }
                        }

                        me.multistage_requests_to_advance.push_back((
                            request_id_json,
                            MultiStageRequestStage::BlockHashKnown {
                                block_hash: current_best_block,
                            },
                            request_ty,
                        ));
                    }
                }
            }

            WakeUpReason::AdvanceMultiStageRequest {
                request_id_json,
                stage:
                    MultiStageRequestStage::BlockHashKnown { block_hash, .. }
                    | MultiStageRequestStage::BlockInfoKnown { block_hash, .. },
                request_ty: MultiStageRequestTy::ChainGetBestBlockHash,
            } => {
                // Handling `chain_getBlockHash` for the best block.
                let _ = me
                    .responses_tx
                    .send(
                        methods::Response::chain_getBlockHash(methods::HashHexString(block_hash))
                            .to_json_response(&request_id_json),
                    )
                    .await;
            }

            WakeUpReason::AdvanceMultiStageRequest {
                request_id_json,
                stage:
                    MultiStageRequestStage::BlockHashKnown { block_hash, .. }
                    | MultiStageRequestStage::BlockInfoKnown { block_hash, .. },
                request_ty: MultiStageRequestTy::ChainGetBlock,
            } => {
                // Handling `chain_getBlock`.

                // Try to determine the block number by looking for the block in cache.
                // The request can be fulfilled no matter whether the block number is
                // known or not, but knowing it will lead to a better selection of peers,
                // and thus increase the chances of the requests succeeding.
                let block_number = me
                    .block_headers_cache
                    .get(&block_hash)
                    .and_then(|result| result.as_ref().ok().map(|(_, _, n)| *n));

                // Block bodies and headers aren't stored locally. Ask the network.
                me.background_tasks.push({
                    let sync_service = me.sync_service.clone();
                    let request_id_json = request_id_json.to_owned();
                    Box::pin(async move {
                        let result = if let Some(block_number) = block_number {
                            sync_service
                                .block_query(
                                    block_number,
                                    block_hash,
                                    codec::BlocksRequestFields {
                                        header: true,
                                        body: true,
                                        justifications: false,
                                    },
                                    3,
                                    Duration::from_secs(8),
                                    NonZero::<u32>::new(1).unwrap(),
                                )
                                .await
                        } else {
                            sync_service
                                .block_query_unknown_number(
                                    block_hash,
                                    codec::BlocksRequestFields {
                                        header: true,
                                        body: true,
                                        justifications: false,
                                    },
                                    3,
                                    Duration::from_secs(8),
                                    NonZero::<u32>::new(1).unwrap(),
                                )
                                .await
                        };
                        Event::ChainGetBlockResult {
                            request_id_json,
                            result,
                            expected_block_hash: block_hash,
                        }
                    })
                });
            }

            WakeUpReason::AdvanceMultiStageRequest {
                request_id_json: request_id,
                stage: MultiStageRequestStage::BlockHashKnown { block_hash },
                request_ty,
            } => {
                // A "multi-stage request" needs to know the information about the block with
                // the given hash.

                // If the block's information is available in cache, switch it to the next stage.
                if let Some(in_cache) = me.block_headers_cache.get(&block_hash) {
                    let &Ok((ref scale_encoded_header, block_state_trie_root_hash, block_number)) =
                        in_cache
                    else {
                        // Block is known to not be decodable.
                        let _ = me
                            .responses_tx
                            .send(parse::build_error_response(
                                &request_id,
                                parse::ErrorResponse::ServerError(-32000, "invalid block header"),
                                None,
                            ))
                            .await;
                        continue;
                    };

                    // Special-case `chain_getHeader`, as it is only needs to know the header
                    // of the block and doesn't need to be switched to a next stage.
                    if matches!(request_ty, MultiStageRequestTy::ChainGetHeader) {
                        match methods::Header::from_scale_encoded_header(
                            scale_encoded_header,
                            me.runtime_service.block_number_bytes(),
                        ) {
                            Ok(header) => {
                                let _ = me
                                    .responses_tx
                                    .send(
                                        methods::Response::chain_getHeader(header)
                                            .to_json_response(&request_id),
                                    )
                                    .await;
                            }
                            Err(error) => {
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        &request_id,
                                        json_rpc::parse::ErrorResponse::ServerError(
                                            -32000,
                                            &format!("Failed to decode block header: {error}"),
                                        ),
                                        None,
                                    ))
                                    .await;
                            }
                        }
                        continue;
                    }

                    me.multistage_requests_to_advance.push_back((
                        request_id,
                        MultiStageRequestStage::BlockInfoKnown {
                            block_hash,
                            block_state_trie_root_hash,
                            block_number,
                        },
                        request_ty,
                    ));
                    continue;
                }

                // Value is not available in cache.
                match me.block_headers_pending.entry(block_hash) {
                    hashbrown::hash_map::Entry::Occupied(entry) => {
                        // We are already in the process of asking the networking service for
                        // the block information.
                        // Keep track of the request.
                        debug_assert!(!entry.get().is_empty());
                        entry.into_mut().push((request_id, request_ty));
                    }
                    hashbrown::hash_map::Entry::Vacant(entry) => {
                        // No network request is in progress yet. Start one.
                        me.background_tasks.push({
                            let block_info_retrieve_future =
                                me.sync_service.clone().block_query_unknown_number(
                                    block_hash,
                                    codec::BlocksRequestFields {
                                        header: true,
                                        body: false,
                                        justifications: false,
                                    },
                                    3,
                                    Duration::from_secs(5),
                                    NonZero::<u32>::new(1).unwrap_or_else(|| unreachable!()),
                                );
                            let block_number_bytes = me.runtime_service.block_number_bytes();
                            Box::pin(async move {
                                let result = match block_info_retrieve_future.await {
                                    Ok(result) => match result.header {
                                        Some(scale_header) => {
                                            if header::hash_from_scale_encoded_header(&scale_header)
                                                == block_hash
                                            {
                                                Ok(header::decode(
                                                    &scale_header,
                                                    block_number_bytes,
                                                )
                                                .map(|header| {
                                                    (
                                                        scale_header.clone(),
                                                        *header.state_root,
                                                        header.number,
                                                    )
                                                }))
                                            } else {
                                                Err(())
                                            }
                                        }
                                        None => Err(()),
                                    },
                                    Err(()) => Err(()),
                                };
                                Event::BlockInfoRetrieved { block_hash, result }
                            })
                        });

                        // Keep track of the request.
                        let mut list = Vec::with_capacity(4);
                        list.push((request_id, request_ty));
                        entry.insert(list);
                    }
                }
            }

            WakeUpReason::AdvanceMultiStageRequest {
                stage: MultiStageRequestStage::BlockInfoKnown { .. },
                request_ty: MultiStageRequestTy::ChainGetHeader,
                ..
            } => {
                // `chain_getHeader` should never reach this stage.
                unreachable!()
            }

            WakeUpReason::AdvanceMultiStageRequest {
                request_id_json,
                stage:
                    MultiStageRequestStage::BlockInfoKnown {
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                    },
                request_ty:
                    request_ty @ (MultiStageRequestTy::StateGetRuntimeVersion
                    | MultiStageRequestTy::StateCall { .. }
                    | MultiStageRequestTy::StateGetMetadata
                    | MultiStageRequestTy::PaymentQueryInfo { .. }
                    | MultiStageRequestTy::SystemAccountNextIndex { .. }),
            } => {
                // A runtime-related JSON-RPC function needs access to the runtime of the
                // given block.

                // If the value is available in cache, do the runtime call.
                if let Some(in_cache) = me.block_runtimes_cache.get(&block_hash) {
                    // Special-case `state_getRuntimeVersion` as it only needs access to the
                    // runtime but not do any call.
                    if let MultiStageRequestTy::StateGetRuntimeVersion = &request_ty {
                        match me
                            .runtime_service
                            .pinned_runtime_specification(in_cache.clone())
                            .await
                        {
                            Ok(spec) => {
                                let _ = me
                                    .responses_tx
                                    .send(
                                        methods::Response::state_getRuntimeVersion(
                                            convert_runtime_version_legacy(&spec),
                                        )
                                        .to_json_response(&request_id_json),
                                    )
                                    .await;
                            }
                            Err(error) => {
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        &request_id_json,
                                        json_rpc::parse::ErrorResponse::ServerError(
                                            -32000,
                                            &error.to_string(),
                                        ),
                                        None,
                                    ))
                                    .await;
                            }
                        }
                        continue;
                    }

                    // Determine the parameters of the runtime call to start.
                    let (function_name, required_api_version, parameters_vectored, request_update) =
                        match request_ty {
                            MultiStageRequestTy::StateCall { name, parameters } => (
                                name,
                                None,
                                parameters,
                                RuntimeCallRequestInProgress::StateCall,
                            ),
                            MultiStageRequestTy::StateGetMetadata => (
                                "Metadata_metadata".to_owned(),
                                Some(("Metadata".to_owned(), 1..=2)),
                                Vec::new(),
                                RuntimeCallRequestInProgress::StateGetMetadata,
                            ),
                            MultiStageRequestTy::PaymentQueryInfo { extrinsic } => {
                                (
                                    json_rpc::payment_info::PAYMENT_FEES_FUNCTION_NAME.to_owned(),
                                    Some(("TransactionPaymentApi".to_owned(), 1..=2)),
                                    json_rpc::payment_info::payment_info_parameters(&extrinsic)
                                        .fold(Vec::new(), |mut a, b| {
                                            a.extend_from_slice(b.as_ref());
                                            a
                                        }),
                                    RuntimeCallRequestInProgress::PaymentQueryInfo,
                                )
                            }
                            MultiStageRequestTy::SystemAccountNextIndex { account_id } => (
                                "AccountNonceApi_account_nonce".to_owned(),
                                Some(("AccountNonceApi".to_owned(), 1..=1)),
                                account_id,
                                RuntimeCallRequestInProgress::SystemAccountNextIndex,
                            ),
                            _ => unreachable!(),
                        };

                    // Start the runtime call in the background.
                    let runtime_service = me.runtime_service.clone();
                    let in_cache = in_cache.clone();
                    me.background_tasks.push(Box::pin(async move {
                        Event::LegacyApiFunctionRuntimeCallResult {
                            request_id_json,
                            request: request_update,
                            result: runtime_service
                                .runtime_call(
                                    in_cache,
                                    block_hash,
                                    block_number,
                                    block_state_trie_root_hash,
                                    function_name,
                                    required_api_version,
                                    parameters_vectored,
                                    3,
                                    Duration::from_secs(5),
                                    NonZero::<u32>::new(1).unwrap_or_else(|| unreachable!()),
                                )
                                .await,
                        }
                    }));
                    continue;
                }

                // Runtime is not available in cache. Download it from the network.
                match me.block_runtimes_pending.entry(block_hash) {
                    hashbrown::hash_map::Entry::Occupied(entry) => {
                        // We are already in the process of asking the networking service for
                        // the runtime.
                        // Keep track of the request.
                        debug_assert!(!entry.get().is_empty());
                        entry.into_mut().push((request_id_json, request_ty));
                    }
                    hashbrown::hash_map::Entry::Vacant(entry) => {
                        // No network request is in progress yet. Start one.
                        me.background_tasks.push(Box::pin({
                            let sync_service = me.sync_service.clone();
                            let runtime_service = me.runtime_service.clone();
                            // TODO: move to separate function
                            async move {
                                let (
                                    storage_code,
                                    storage_heap_pages,
                                    code_merkle_value,
                                    code_closest_ancestor_excluding,
                                ) = {
                                    let mut storage_code = None;
                                    let mut storage_heap_pages = None;
                                    let mut code_merkle_value = None;
                                    let mut code_closest_ancestor_excluding = None;

                                    let mut query =
                                        sync_service
                                        .storage_query(
                                            block_number,
                                            block_hash,
                                            block_state_trie_root_hash,
                                            [
                                                sync_service::StorageRequestItem {
                                                    key: b":code".to_vec(),
                                                    ty: sync_service::StorageRequestItemTy::ClosestDescendantMerkleValue,
                                                },
                                                sync_service::StorageRequestItem {
                                                    key: b":code".to_vec(),
                                                    ty: sync_service::StorageRequestItemTy::Value,
                                                },
                                                sync_service::StorageRequestItem {
                                                    key: b":heappages".to_vec(),
                                                    ty: sync_service::StorageRequestItemTy::Value,
                                                },
                                            ]
                                            .into_iter(),
                                            3,
                                            Duration::from_secs(20),
                                            NonZero::<u32>::new(1).unwrap(),
                                        )
                                        .advance()
                                        .await;

                                    loop {
                                        match query {
                                            sync_service::StorageQueryProgress::Finished => {
                                                break (
                                                    storage_code,
                                                    storage_heap_pages,
                                                    code_merkle_value,
                                                    code_closest_ancestor_excluding,
                                                )
                                            }
                                            sync_service::StorageQueryProgress::Progress {
                                                request_index: 0,
                                                item:
                                                    sync_service::StorageResultItem::ClosestDescendantMerkleValue {
                                                        closest_descendant_merkle_value,
                                                        found_closest_ancestor_excluding,
                                                        ..
                                                    },
                                                query: next,
                                            } => {
                                                code_merkle_value = closest_descendant_merkle_value;
                                                code_closest_ancestor_excluding = found_closest_ancestor_excluding;
                                                query = next.advance().await;
                                            }
                                            sync_service::StorageQueryProgress::Progress {
                                                request_index: 1,
                                                item: sync_service::StorageResultItem::Value { value, .. },
                                                query: next,
                                            } => {
                                                storage_code = value;
                                                query = next.advance().await;
                                            }
                                            sync_service::StorageQueryProgress::Progress {
                                                request_index: 2,
                                                item: sync_service::StorageResultItem::Value { value, .. },
                                                query: next,
                                            } => {
                                                storage_heap_pages = value;
                                                query = next.advance().await;
                                            }
                                            sync_service::StorageQueryProgress::Progress { .. } => unreachable!(),
                                            sync_service::StorageQueryProgress::Error(error) => {
                                                return Event::RuntimeDownloaded {
                                                    block_hash,
                                                    result: Err(error.to_string()),
                                                }
                                            }
                                        }
                                    }
                                };

                                // Give the code and heap pages to the runtime service. The runtime service will
                                // try to find any similar runtime it might have, and if not will compile it.
                                let pinned_runtime = runtime_service
                                    .compile_and_pin_runtime(
                                        storage_code,
                                        storage_heap_pages,
                                        code_merkle_value,
                                        code_closest_ancestor_excluding,
                                    )
                                    .await;

                                Event::RuntimeDownloaded {
                                    block_hash,
                                    result: pinned_runtime.map_err(|error| error.to_string()),
                                }
                            }
                        }));

                        // Keep track of the request.
                        let mut list = Vec::with_capacity(4);
                        list.push((request_id_json, request_ty));
                        entry.insert(list);
                    }
                }
            }

            WakeUpReason::Event(Event::LegacyApiFunctionRuntimeCallResult {
                request_id_json,
                request,
                result,
            }) => {
                // A runtime-call-related JSON-RPC API has finished its runtime call.
                match (result, request) {
                    (Ok(result), RuntimeCallRequestInProgress::StateCall) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::state_call(methods::HexString(result.output))
                                    .to_json_response(&request_id_json),
                            )
                            .await;
                    }
                    (Ok(result), RuntimeCallRequestInProgress::StateGetMetadata) => {
                        match methods::remove_metadata_length_prefix(&result.output) {
                            Ok(metadata) => {
                                let _ = me
                                    .responses_tx
                                    .send(
                                        methods::Response::state_getMetadata(methods::HexString(
                                            metadata.to_owned(),
                                        ))
                                        .to_json_response(&request_id_json),
                                    )
                                    .await;
                            }
                            Err(error) => {
                                log!(
                                    &me.platform,
                                    Warn,
                                    &me.log_target,
                                    format!("Failed to decode metadata. Error: {error}")
                                );
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        &request_id_json,
                                        parse::ErrorResponse::ServerError(
                                            -32000,
                                            &error.to_string(),
                                        ),
                                        None,
                                    ))
                                    .await;
                            }
                        }
                    }
                    (Ok(result), RuntimeCallRequestInProgress::PaymentQueryInfo) => {
                        match json_rpc::payment_info::decode_payment_info(
                            &result.output,
                            // `api_version` is guaranteed to be `Some` if we passed an API
                            // requirement when calling `runtime_call`, which we always do.
                            result.api_version.unwrap(),
                        ) {
                            Ok(info) => {
                                let _ = me
                                    .responses_tx
                                    .send(
                                        methods::Response::payment_queryInfo(info)
                                            .to_json_response(&request_id_json),
                                    )
                                    .await;
                            }
                            Err(error) => {
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        &request_id_json,
                                        parse::ErrorResponse::ServerError(
                                            -32000,
                                            &format!("Failed to decode runtime output: {error}"),
                                        ),
                                        None,
                                    ))
                                    .await;
                            }
                        }
                    }
                    (Ok(result), RuntimeCallRequestInProgress::SystemAccountNextIndex) => {
                        // TODO: we get a u32 when expecting a u64; figure out problem
                        match <[u8; 4]>::try_from(&result.output[..]) {
                            Ok(index) => {
                                let _ = me
                                    .responses_tx
                                    .send(
                                        methods::Response::system_accountNextIndex(u64::from(
                                            u32::from_le_bytes(index),
                                        ))
                                        .to_json_response(&request_id_json),
                                    )
                                    .await;
                            }
                            Err(_) => {
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        &request_id_json,
                                        parse::ErrorResponse::ServerError(
                                            -32000,
                                            &"Failed to decode runtime output".to_string(),
                                        ),
                                        None,
                                    ))
                                    .await;
                            }
                        }
                    }
                    (Err(error), request) => {
                        if matches!(request, RuntimeCallRequestInProgress::StateGetMetadata) {
                            log!(
                                &me.platform,
                                Warn,
                                &me.log_target,
                                format!(
                                    "Returning error from `state_getMetadata`. API user might \
                                    not function properly. Error: {error}"
                                )
                            );
                        }

                        let _ = me
                            .responses_tx
                            .send(parse::build_error_response(
                                &request_id_json,
                                parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                                None,
                            ))
                            .await;
                    }
                }
            }

            WakeUpReason::AdvanceMultiStageRequest {
                request_id_json,
                stage:
                    MultiStageRequestStage::BlockInfoKnown {
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                    },
                request_ty:
                    request_ty @ (MultiStageRequestTy::StateGetKeys { .. }
                    | MultiStageRequestTy::StateGetKeysPaged { .. }
                    | MultiStageRequestTy::StateQueryStorageAt { .. }
                    | MultiStageRequestTy::StateGetStorage { .. }
                    | MultiStageRequestTy::StateGetReadProof { .. }),
            } => {
                let is_state_get_read_proof =
                    matches!(request_ty, MultiStageRequestTy::StateGetReadProof { .. });

                // A storage-related JSON-RPC function can make progress.
                // Build and start a background task that performs the actual storage request.
                let (request, storage_request) = match request_ty {
                    MultiStageRequestTy::StateGetKeys { prefix } => (
                        StorageRequestInProgress::StateGetKeys {
                            in_progress_results: Vec::with_capacity(32),
                        },
                        either::Left(iter::once(sync_service::StorageRequestItem {
                            key: prefix.clone(),
                            ty: sync_service::StorageRequestItemTy::DescendantsHashes,
                        })),
                    ),
                    MultiStageRequestTy::StateGetKeysPaged {
                        prefix,
                        start_key,
                        count,
                    } => (
                        StorageRequestInProgress::StateGetKeysPaged {
                            in_progress_results: Vec::with_capacity(32),
                            block_hash,
                            prefix: prefix.clone(),
                            start_key,
                            count,
                        },
                        either::Left(iter::once(sync_service::StorageRequestItem {
                            key: prefix,
                            ty: sync_service::StorageRequestItemTy::DescendantsHashes,
                        })),
                    ),
                    MultiStageRequestTy::StateQueryStorageAt { keys }
                    | MultiStageRequestTy::StateGetReadProof { keys } => (
                        if is_state_get_read_proof {
                            StorageRequestInProgress::StateGetReadProof {
                                block_hash,
                                in_progress_results: Vec::with_capacity(keys.len()),
                            }
                        } else {
                            StorageRequestInProgress::StateQueryStorageAt {
                                block_hash,
                                in_progress_results: Vec::with_capacity(keys.len()),
                            }
                        },
                        either::Right(keys.into_iter().map(|key| {
                            sync_service::StorageRequestItem {
                                key: key.0,
                                ty: if is_state_get_read_proof {
                                    sync_service::StorageRequestItemTy::MerkleProof
                                } else {
                                    sync_service::StorageRequestItemTy::Value
                                },
                            }
                        })),
                    ),
                    MultiStageRequestTy::StateGetStorage { key } => (
                        StorageRequestInProgress::StateGetStorage {},
                        either::Left(iter::once(sync_service::StorageRequestItem {
                            key,
                            ty: sync_service::StorageRequestItemTy::Value,
                        })),
                    ),
                    _ => unreachable!(),
                };

                let storage_query = me.sync_service.clone().storage_query(
                    block_number,
                    block_hash,
                    block_state_trie_root_hash,
                    storage_request,
                    3,
                    Duration::from_secs(10),
                    NonZero::<u32>::new(1).unwrap_or_else(|| unreachable!()),
                );

                me.background_tasks.push(Box::pin(async move {
                    Event::LegacyApiFunctionStorageRequestProgress {
                        request_id_json,
                        request,
                        progress: storage_query.advance().await,
                    }
                }));
            }

            WakeUpReason::Event(Event::LegacyApiFunctionStorageRequestProgress {
                request_id_json,
                request,
                progress,
            }) => {
                // The background task of a storage-related JSON-RPC function has made progress.
                match (progress, request) {
                    (
                        sync_service::StorageQueryProgress::Progress {
                            item: sync_service::StorageResultItem::DescendantHash { key, .. },
                            query: next,
                            ..
                        },
                        StorageRequestInProgress::StateGetKeys {
                            mut in_progress_results,
                        },
                    ) => {
                        // Continue finding descendants.
                        in_progress_results.push(methods::HexString(key));
                        me.background_tasks.push(Box::pin(async move {
                            Event::LegacyApiFunctionStorageRequestProgress {
                                request_id_json,
                                request: StorageRequestInProgress::StateGetKeys {
                                    in_progress_results,
                                },
                                progress: next.advance().await,
                            }
                        }));
                    }
                    (
                        sync_service::StorageQueryProgress::Finished,
                        StorageRequestInProgress::StateGetKeys {
                            in_progress_results,
                        },
                    ) => {
                        // Finished.
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::state_getKeys(in_progress_results)
                                    .to_json_response(&request_id_json),
                            )
                            .await;
                    }
                    (
                        sync_service::StorageQueryProgress::Progress {
                            item: sync_service::StorageResultItem::DescendantHash { key, .. },
                            query: next,
                            ..
                        },
                        StorageRequestInProgress::StateGetKeysPaged {
                            mut in_progress_results,
                            block_hash,
                            prefix,
                            start_key,
                            count,
                        },
                    ) => {
                        // Continue finding descendants.
                        in_progress_results.push(key);
                        me.background_tasks.push(Box::pin(async move {
                            Event::LegacyApiFunctionStorageRequestProgress {
                                request_id_json,
                                request: StorageRequestInProgress::StateGetKeysPaged {
                                    in_progress_results,
                                    block_hash,
                                    prefix,
                                    start_key,
                                    count,
                                },
                                progress: next.advance().await,
                            }
                        }));
                    }
                    (
                        sync_service::StorageQueryProgress::Finished,
                        StorageRequestInProgress::StateGetKeysPaged {
                            block_hash,
                            in_progress_results: final_results,
                            prefix,
                            start_key,
                            count,
                        },
                    ) => {
                        // Finished.

                        // Filter by start key and count.
                        let results_to_client = final_results
                            .iter()
                            .filter(|&k| start_key.as_ref().map_or(true, |s| *k > *s))
                            .cloned()
                            .map(methods::HexString)
                            .take(usize::try_from(count).unwrap_or(usize::MAX))
                            .collect::<Vec<_>>();

                        // If the returned response is somehow truncated, it is very likely that the
                        // JSON-RPC client will call the function again with the exact same parameters.
                        // Thus, store the results in a cache.
                        if results_to_client.len() != final_results.len() {
                            me.state_get_keys_paged_cache.push(
                                GetKeysPagedCacheKey {
                                    hash: block_hash,
                                    prefix,
                                },
                                final_results,
                            );
                        }

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::state_getKeysPaged(results_to_client)
                                    .to_json_response(&request_id_json),
                            )
                            .await;
                    }
                    (
                        sync_service::StorageQueryProgress::Progress {
                            item: sync_service::StorageResultItem::Value { key, value },
                            query: next,
                            ..
                        },
                        StorageRequestInProgress::StateQueryStorageAt {
                            block_hash,
                            mut in_progress_results,
                        },
                    ) => {
                        // Continue finding keys.
                        in_progress_results
                            .push((methods::HexString(key), value.map(methods::HexString)));
                        me.background_tasks.push(Box::pin(async move {
                            Event::LegacyApiFunctionStorageRequestProgress {
                                request_id_json,
                                request: StorageRequestInProgress::StateQueryStorageAt {
                                    block_hash,
                                    in_progress_results,
                                },
                                progress: next.advance().await,
                            }
                        }));
                    }
                    (
                        sync_service::StorageQueryProgress::Finished,
                        StorageRequestInProgress::StateQueryStorageAt {
                            block_hash,
                            in_progress_results,
                        },
                    ) => {
                        // Finished.
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::state_queryStorageAt(vec![
                                    methods::StorageChangeSet {
                                        block: methods::HashHexString(block_hash),
                                        changes: in_progress_results,
                                    },
                                ])
                                .to_json_response(&request_id_json),
                            )
                            .await;
                    }
                    (
                        sync_service::StorageQueryProgress::Progress {
                            item: sync_service::StorageResultItem::MerkleProof { proof, .. },
                            query: next,
                            ..
                        },
                        StorageRequestInProgress::StateGetReadProof {
                            block_hash,
                            mut in_progress_results,
                        },
                    ) => {
                        in_progress_results.push(proof);
                        me.background_tasks.push(Box::pin(async move {
                            Event::LegacyApiFunctionStorageRequestProgress {
                                request_id_json,
                                request: StorageRequestInProgress::StateGetReadProof {
                                    block_hash,
                                    in_progress_results,
                                },
                                progress: next.advance().await,
                            }
                        }));
                    }
                    (
                        sync_service::StorageQueryProgress::Finished,
                        StorageRequestInProgress::StateGetReadProof {
                            block_hash,
                            in_progress_results,
                        },
                    ) => {
                        // Finished.
                        let _ = me
                            .responses_tx
                            .send(
                                if let Ok(merged_proof) = minimize_proof::merge_proofs(
                                    in_progress_results.iter().map(|v| &v[..]),
                                ) {
                                    let decoded =
                                        proof_decode::decode_proof(&merged_proof).unwrap();
                                    methods::Response::state_getReadProof(methods::ReadProof {
                                        at: methods::HashHexString(block_hash),
                                        proof: decoded
                                            .map(|e| methods::HexString(e.to_owned()))
                                            .collect(),
                                    })
                                    .to_json_response(&request_id_json)
                                } else {
                                    parse::build_error_response(
                                        &request_id_json,
                                        parse::ErrorResponse::ServerError(
                                            -32000,
                                            "A proof could not be decoded",
                                        ),
                                        None,
                                    )
                                },
                            )
                            .await;
                    }
                    (
                        sync_service::StorageQueryProgress::Progress {
                            item:
                                sync_service::StorageResultItem::Value {
                                    value: Some(value), ..
                                },
                            ..
                        },
                        StorageRequestInProgress::StateGetStorage {},
                    ) => {
                        // Finished. We throw away the object that continues the request, as we
                        // know that nothing else will come after.
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::state_getStorage(methods::HexString(value))
                                    .to_json_response(&request_id_json),
                            )
                            .await;
                    }
                    (
                        sync_service::StorageQueryProgress::Progress {
                            item: sync_service::StorageResultItem::Value { value: None, .. },
                            ..
                        },
                        StorageRequestInProgress::StateGetStorage {},
                    ) => {
                        // Finished. We throw away the object that continues the request, as we
                        // know that nothing else will come after.
                        let _ = me
                            .responses_tx
                            .send(parse::build_success_response(&request_id_json, "null"))
                            .await;
                    }
                    (sync_service::StorageQueryProgress::Error(error), _) => {
                        // All errors are sent back the same way.
                        let _ = me
                            .responses_tx
                            .send(parse::build_error_response(
                                &request_id_json,
                                parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                                None,
                            ))
                            .await;
                    }
                    _ => unreachable!(),
                }
            }

            WakeUpReason::Event(
                event @ (Event::ChainHeadSubscriptionWithRuntimeReady { .. }
                | Event::ChainHeadSubscriptionWithoutRuntimeReady { .. }),
            ) => {
                // A `chainHead_follow` subscription has finished subscribing to either the
                // runtime service or the sync service.

                // Both "with runtime" and "without runtime" events are handled together here,
                // but they use different types.
                // Extract the event information.
                let (
                    subscription_id,
                    new_blocks,
                    finalized_block_scale_encoded_header,
                    finalized_block_runtime,
                    non_finalized_blocks_ancestry_order,
                ) = match event {
                    Event::ChainHeadSubscriptionWithRuntimeReady {
                        subscription_id,
                        subscription,
                    } => (
                        subscription_id,
                        either::Left(subscription.new_blocks),
                        subscription.finalized_block_scale_encoded_header,
                        Some(subscription.finalized_block_runtime),
                        either::Left(
                            subscription
                                .non_finalized_blocks_ancestry_order
                                .into_iter()
                                .map(either::Left),
                        ),
                    ),
                    Event::ChainHeadSubscriptionWithoutRuntimeReady {
                        subscription_id,
                        subscription,
                    } => (
                        subscription_id,
                        either::Right(Box::pin(subscription.new_blocks)),
                        subscription.finalized_block_scale_encoded_header,
                        None,
                        either::Right(
                            subscription
                                .non_finalized_blocks_ancestry_order
                                .into_iter()
                                .map(either::Right),
                        ),
                    ),
                    _ => unreachable!(),
                };

                // It might be that the JSON-RPC client has unsubscribed before the subscription
                // was initialized.
                let Some(subscription_info) =
                    me.chain_head_follow_subscriptions.get_mut(&subscription_id)
                else {
                    continue;
                };

                // Store the subscription ID in the subscription.
                if let either::Left(new_blocks) = &new_blocks {
                    subscription_info.runtime_service_subscription_id = Some(new_blocks.id());
                }

                // Send the `initialized` event and pin the finalized block.
                let finalized_block_hash =
                    header::hash_from_scale_encoded_header(&finalized_block_scale_encoded_header); // TODO: indicate hash in subscription?
                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_v1_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::Initialized {
                                finalized_block_hashes: vec![methods::HashHexString(
                                    finalized_block_hash,
                                )],
                                finalized_block_runtime: finalized_block_runtime.as_ref().map(
                                    |runtime| match runtime {
                                        Ok(rt) => methods::MaybeRuntimeSpec::Valid {
                                            spec: convert_runtime_version(rt),
                                        },
                                        Err(error) => methods::MaybeRuntimeSpec::Invalid {
                                            error: error.to_string(),
                                        },
                                    },
                                ),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
                subscription_info
                    .pinned_blocks_headers
                    .insert(finalized_block_hash, finalized_block_scale_encoded_header);

                // Send an event for each non-finalized block.
                for block in non_finalized_blocks_ancestry_order {
                    let parent_block_hash = match &block {
                        either::Left(b) => b.parent_hash,
                        either::Right(b) => b.parent_hash,
                    };
                    let hash = header::hash_from_scale_encoded_header(match &block {
                        either::Left(b) => &b.scale_encoded_header,
                        either::Right(b) => &b.scale_encoded_header,
                    }); // TODO: indicate hash in subscription?
                    let _ = me
                        .responses_tx
                        .send(
                            methods::ServerToClient::chainHead_v1_followEvent {
                                subscription: Cow::Borrowed(&subscription_id),
                                result: methods::FollowEvent::NewBlock {
                                    block_hash: methods::HashHexString(hash),
                                    parent_block_hash: methods::HashHexString(parent_block_hash),
                                    new_runtime: if let either::Left(block) = &block {
                                        if let Some(rt) = &block.new_runtime {
                                            match rt {
                                                Ok(spec) => {
                                                    Some(methods::MaybeRuntimeSpec::Valid {
                                                        spec: convert_runtime_version(spec),
                                                    })
                                                }
                                                Err(error) => {
                                                    Some(methods::MaybeRuntimeSpec::Invalid {
                                                        error: error.to_string(),
                                                    })
                                                }
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    },
                                },
                            }
                            .to_json_request_object_parameters(None),
                        )
                        .await;
                    if match &block {
                        either::Left(b) => b.is_new_best,
                        either::Right(b) => b.is_new_best,
                    } {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_v1_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    subscription_info.pinned_blocks_headers.insert(
                        hash,
                        match block {
                            either::Left(b) => b.scale_encoded_header,
                            either::Right(b) => b.scale_encoded_header,
                        },
                    );
                }

                // Push a new background task that will yield an event when the newly-created
                // susbcription generates its first event.
                me.background_tasks.push({
                    match new_blocks {
                        either::Left(mut new_blocks) => Box::pin(async move {
                            if let Some(notification) = new_blocks.next().await {
                                Event::ChainHeadSubscriptionWithRuntimeNotification {
                                    subscription_id,
                                    notification,
                                    stream: new_blocks,
                                }
                            } else {
                                Event::ChainHeadSubscriptionDeadSubcription { subscription_id }
                            }
                        }),
                        either::Right(mut new_blocks) => Box::pin(async move {
                            if let Some(notification) = new_blocks.next().await {
                                Event::ChainHeadSubscriptionWithoutRuntimeNotification {
                                    subscription_id,
                                    notification,
                                    stream: new_blocks,
                                }
                            } else {
                                Event::ChainHeadSubscriptionDeadSubcription { subscription_id }
                            }
                        }),
                    }
                });
            }

            WakeUpReason::Event(Event::ChainHeadSubscriptionWithRuntimeNotification {
                subscription_id,
                notification,
                mut stream,
            }) => {
                // It might be that the JSON-RPC client has unsubscribed.
                let Some(subscription_info) =
                    me.chain_head_follow_subscriptions.get_mut(&subscription_id)
                else {
                    continue;
                };

                match notification {
                    runtime_service::Notification::Finalized {
                        hash,
                        best_block_hash_if_changed,
                        pruned_blocks,
                    } => {
                        if let Some(new_best_block_hash) = best_block_hash_if_changed {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::ServerToClient::chainHead_v1_followEvent {
                                        subscription: Cow::Borrowed(&subscription_id),
                                        result: methods::FollowEvent::BestBlockChanged {
                                            best_block_hash: methods::HashHexString(
                                                new_best_block_hash,
                                            ),
                                        },
                                    }
                                    .to_json_request_object_parameters(None),
                                )
                                .await;
                        }

                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_v1_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::Finalized {
                                        finalized_blocks_hashes: vec![methods::HashHexString(hash)],
                                        pruned_blocks_hashes: pruned_blocks
                                            .into_iter()
                                            .map(methods::HashHexString)
                                            .collect(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    runtime_service::Notification::BestBlockChanged { hash } => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_v1_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    runtime_service::Notification::Block(block) => {
                        // TODO: pass hash through notification
                        let block_hash =
                            header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                        subscription_info
                            .pinned_blocks_headers
                            .insert(block_hash, block.scale_encoded_header);

                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_v1_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::NewBlock {
                                        block_hash: methods::HashHexString(block_hash),
                                        parent_block_hash: methods::HashHexString(
                                            block.parent_hash,
                                        ),
                                        new_runtime: match &block.new_runtime {
                                            Some(Ok(rt)) => {
                                                Some(methods::MaybeRuntimeSpec::Valid {
                                                    spec: convert_runtime_version(rt),
                                                })
                                            }
                                            Some(Err(error)) => {
                                                Some(methods::MaybeRuntimeSpec::Invalid {
                                                    error: error.to_string(),
                                                })
                                            }
                                            None => None,
                                        },
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;

                        if block.is_new_best {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::ServerToClient::chainHead_v1_followEvent {
                                        subscription: Cow::Borrowed(&subscription_id),
                                        result: methods::FollowEvent::BestBlockChanged {
                                            best_block_hash: methods::HashHexString(block_hash),
                                        },
                                    }
                                    .to_json_request_object_parameters(None),
                                )
                                .await;
                        }
                    }
                }

                // Push a new task that will yield when the runtime service subscription generates
                // the next notification.
                me.background_tasks.push(Box::pin(async move {
                    if let Some(notification) = stream.next().await {
                        Event::ChainHeadSubscriptionWithRuntimeNotification {
                            subscription_id,
                            notification,
                            stream,
                        }
                    } else {
                        Event::ChainHeadSubscriptionDeadSubcription { subscription_id }
                    }
                }))
            }

            WakeUpReason::Event(Event::ChainHeadSubscriptionWithoutRuntimeNotification {
                subscription_id,
                notification,
                mut stream,
            }) => {
                // It might be that the JSON-RPC client has unsubscribed.
                let Some(subscription_info) =
                    me.chain_head_follow_subscriptions.get_mut(&subscription_id)
                else {
                    continue;
                };

                match notification {
                    sync_service::Notification::Finalized {
                        hash,
                        best_block_hash_if_changed,
                        pruned_blocks,
                    } => {
                        if let Some(new_best_block_hash) = best_block_hash_if_changed {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::ServerToClient::chainHead_v1_followEvent {
                                        subscription: Cow::Borrowed(&subscription_id),
                                        result: methods::FollowEvent::BestBlockChanged {
                                            best_block_hash: methods::HashHexString(
                                                new_best_block_hash,
                                            ),
                                        },
                                    }
                                    .to_json_request_object_parameters(None),
                                )
                                .await;
                        }

                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_v1_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::Finalized {
                                        finalized_blocks_hashes: vec![methods::HashHexString(hash)],
                                        pruned_blocks_hashes: pruned_blocks
                                            .into_iter()
                                            .map(methods::HashHexString)
                                            .collect(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    sync_service::Notification::BestBlockChanged { hash } => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_v1_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    sync_service::Notification::Block(block) => {
                        // TODO: pass hash through notification
                        let block_hash =
                            header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                        subscription_info
                            .pinned_blocks_headers
                            .insert(block_hash, block.scale_encoded_header);

                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_v1_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::NewBlock {
                                        block_hash: methods::HashHexString(block_hash),
                                        parent_block_hash: methods::HashHexString(
                                            block.parent_hash,
                                        ),
                                        new_runtime: None,
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;

                        if block.is_new_best {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::ServerToClient::chainHead_v1_followEvent {
                                        subscription: Cow::Borrowed(&subscription_id),
                                        result: methods::FollowEvent::BestBlockChanged {
                                            best_block_hash: methods::HashHexString(block_hash),
                                        },
                                    }
                                    .to_json_request_object_parameters(None),
                                )
                                .await;
                        }
                    }
                }

                // Push a new task that will yield when the sync service subscription generates
                // the next notification.
                me.background_tasks.push(Box::pin(async move {
                    if let Some(notification) = stream.next().await {
                        Event::ChainHeadSubscriptionWithoutRuntimeNotification {
                            subscription_id,
                            notification,
                            stream,
                        }
                    } else {
                        Event::ChainHeadSubscriptionDeadSubcription { subscription_id }
                    }
                }))
            }

            WakeUpReason::Event(Event::ChainHeadCallOperationDone {
                subscription_id,
                operation_id,
                result,
            }) => {
                // A `chainHead_call` operation has finished.

                let Some(subscription_info) =
                    me.chain_head_follow_subscriptions.get_mut(&subscription_id)
                else {
                    unreachable!()
                };
                let Some(operation_info) = subscription_info
                    .operations_in_progress
                    .remove(&operation_id)
                else {
                    // If the operation was cancelled, then a `ChainHeadOperationCancelled`
                    // event should have been generated instead.
                    unreachable!()
                };

                subscription_info.available_operation_slots += operation_info.occupied_slots;

                let result = match result {
                    Ok(success) => methods::FollowEvent::OperationCallDone {
                        operation_id: operation_id.clone().into(),
                        output: methods::HexString(success.output),
                    },
                    Err(runtime_service::RuntimeCallError::InvalidRuntime(error)) => {
                        methods::FollowEvent::OperationError {
                            operation_id: operation_id.clone().into(),
                            error: error.to_string().into(),
                        }
                    }
                    Err(runtime_service::RuntimeCallError::ApiVersionRequirementUnfulfilled) => {
                        // We pass `None` for the API requirement, thus this error can never happen.
                        unreachable!()
                    }
                    Err(
                        runtime_service::RuntimeCallError::Crash
                        | runtime_service::RuntimeCallError::Inaccessible(_),
                    ) => methods::FollowEvent::OperationInaccessible {
                        operation_id: operation_id.clone().into(),
                    },
                    Err(runtime_service::RuntimeCallError::Execution(
                        runtime_service::RuntimeCallExecutionError::ForbiddenHostFunction,
                    )) => methods::FollowEvent::OperationError {
                        operation_id: operation_id.clone().into(),
                        error: "Runtime has called an offchain host function"
                            .to_string()
                            .into(),
                    },
                    Err(runtime_service::RuntimeCallError::Execution(
                        runtime_service::RuntimeCallExecutionError::Start(error),
                    )) => methods::FollowEvent::OperationError {
                        operation_id: operation_id.clone().into(),
                        error: error.to_string().into(),
                    },
                    Err(runtime_service::RuntimeCallError::Execution(
                        runtime_service::RuntimeCallExecutionError::Execution(error),
                    )) => methods::FollowEvent::OperationError {
                        operation_id: operation_id.clone().into(),
                        error: error.to_string().into(),
                    },
                };

                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_v1_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result,
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadBodyOperationDone {
                subscription_id,
                operation_id,
                expected_extrinsics_root,
                result,
            }) => {
                // A `chainHead_body` operation has finished.

                let Some(subscription_info) =
                    me.chain_head_follow_subscriptions.get_mut(&subscription_id)
                else {
                    unreachable!()
                };
                let Some(operation_info) = subscription_info
                    .operations_in_progress
                    .remove(&operation_id)
                else {
                    // If the operation was cancelled, then a `ChainHeadOperationCancelled`
                    // event should have been generated instead.
                    unreachable!()
                };

                subscription_info.available_operation_slots += operation_info.occupied_slots;

                // We must check whether the body is present in the response and valid.
                // TODO: should try the request again with a different peer instead of failing immediately
                let body = match result {
                    Ok(result) => {
                        if let Some(body) = result.body {
                            if header::extrinsics_root(&body) == expected_extrinsics_root {
                                Ok(body)
                            } else {
                                Err(())
                            }
                        } else {
                            Err(())
                        }
                    }
                    Err(err) => Err(err),
                };

                // Send back the response.
                match body {
                    Ok(body) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_v1_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::OperationBodyDone {
                                        operation_id: operation_id.clone().into(),
                                        value: body.into_iter().map(methods::HexString).collect(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    Err(()) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_v1_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::OperationInaccessible {
                                        operation_id: operation_id.clone().into(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                }
            }

            WakeUpReason::Event(Event::ChainHeadStorageOperationProgress {
                subscription_id,
                operation_id,
                progress:
                    sync_service::StorageQueryProgress::Progress {
                        request_index,
                        item,
                        mut query,
                    },
            }) => {
                // A `chainHead_storage` operation has made progress.
                let mut items_chunk = Vec::with_capacity(16);

                for (_, item) in
                    iter::once((request_index, item)).chain(iter::from_fn(|| query.try_advance()))
                {
                    // Perform some API conversion.
                    let item = match item {
                        sync_service::StorageResultItem::Value {
                            key,
                            value: Some(value),
                        } => Some(methods::ChainHeadStorageResponseItem {
                            key: methods::HexString(key),
                            value: Some(methods::HexString(value)),
                            hash: None,
                            closest_descendant_merkle_value: None,
                        }),
                        sync_service::StorageResultItem::Value { value: None, .. } => None,
                        sync_service::StorageResultItem::Hash {
                            key,
                            hash: Some(hash),
                        } => Some(methods::ChainHeadStorageResponseItem {
                            key: methods::HexString(key),
                            value: None,
                            hash: Some(methods::HexString(hash.to_vec())),
                            closest_descendant_merkle_value: None,
                        }),
                        sync_service::StorageResultItem::Hash { hash: None, .. } => None,
                        sync_service::StorageResultItem::DescendantValue { key, value, .. } => {
                            Some(methods::ChainHeadStorageResponseItem {
                                key: methods::HexString(key),
                                value: Some(methods::HexString(value)),
                                hash: None,
                                closest_descendant_merkle_value: None,
                            })
                        }
                        sync_service::StorageResultItem::DescendantHash { key, hash, .. } => {
                            Some(methods::ChainHeadStorageResponseItem {
                                key: methods::HexString(key),
                                value: None,
                                hash: Some(methods::HexString(hash.to_vec())),
                                closest_descendant_merkle_value: None,
                            })
                        }
                        sync_service::StorageResultItem::ClosestDescendantMerkleValue {
                            requested_key,
                            closest_descendant_merkle_value: Some(merkle_value),
                            ..
                        } => Some(methods::ChainHeadStorageResponseItem {
                            key: methods::HexString(requested_key),
                            value: None,
                            hash: None,
                            closest_descendant_merkle_value: Some(methods::HexString(merkle_value)),
                        }),
                        sync_service::StorageResultItem::ClosestDescendantMerkleValue {
                            closest_descendant_merkle_value: None,
                            ..
                        } => None,
                        // chainhead_v1 doesn't have merkle proof queries.
                        sync_service::StorageResultItem::MerkleProof { .. } => unreachable!(),
                    };

                    if let Some(item) = item {
                        items_chunk.push(item);
                    }
                }

                // Send the gathered items to the JSON-RPC client.
                if !items_chunk.is_empty() {
                    let _ = me
                        .responses_tx
                        .send(
                            methods::ServerToClient::chainHead_v1_followEvent {
                                subscription: Cow::Borrowed(&subscription_id),
                                result: methods::FollowEvent::OperationStorageItems {
                                    operation_id: Cow::Borrowed(&operation_id),
                                    items: items_chunk,
                                },
                            }
                            .to_json_request_object_parameters(None),
                        )
                        .await;
                }

                // TODO: generate a waitingForContinue here and wait for user to continue

                // Re-queue the operation for the follow-up items.
                let on_interrupt = me
                    .chain_head_follow_subscriptions
                    .get(&subscription_id)
                    .unwrap_or_else(|| unreachable!())
                    .operations_in_progress
                    .get(&operation_id)
                    .unwrap_or_else(|| unreachable!())
                    .interrupt
                    .listen();
                me.background_tasks.push(Box::pin(async move {
                    async {
                        on_interrupt.await;
                        // This event is necessary only because tasks can't finish without
                        // generating an event.
                        Event::ChainHeadOperationCancelled
                    }
                    .or(async {
                        Event::ChainHeadStorageOperationProgress {
                            subscription_id,
                            operation_id,
                            progress: query.advance().await,
                        }
                    })
                    .await
                }));
            }

            WakeUpReason::Event(Event::ChainHeadStorageOperationProgress {
                subscription_id,
                operation_id,
                progress: sync_service::StorageQueryProgress::Finished,
            }) => {
                // A `chainHead_storage` operation has finished successfully.

                let Some(subscription_info) =
                    me.chain_head_follow_subscriptions.get_mut(&subscription_id)
                else {
                    unreachable!()
                };
                let Some(operation_info) = subscription_info
                    .operations_in_progress
                    .remove(&operation_id)
                else {
                    // If the operation was cancelled, then a `ChainHeadOperationCancelled`
                    // event should have been generated instead.
                    unreachable!()
                };

                subscription_info.available_operation_slots += operation_info.occupied_slots;

                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_v1_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::OperationStorageDone {
                                operation_id: Cow::Borrowed(&operation_id),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadStorageOperationProgress {
                subscription_id,
                operation_id,
                progress: sync_service::StorageQueryProgress::Error(_),
            }) => {
                // A `chainHead_storage` operation has finished failed.

                let Some(subscription_info) =
                    me.chain_head_follow_subscriptions.get_mut(&subscription_id)
                else {
                    unreachable!()
                };
                let Some(operation_info) = subscription_info
                    .operations_in_progress
                    .remove(&operation_id)
                else {
                    // If the operation was cancelled, then a `ChainHeadOperationCancelled`
                    // event should have been generated instead.
                    unreachable!()
                };

                subscription_info.available_operation_slots += operation_info.occupied_slots;

                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_v1_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::OperationInaccessible {
                                operation_id: Cow::Borrowed(&operation_id),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadSubscriptionDeadSubcription {
                subscription_id,
            }) => {
                // The runtime service or sync service subscription of a `chainHead_follow`
                // subscription has died.

                // It might be that the JSON-RPC client has already unsubscribed.
                let Some(subscription_info) =
                    me.chain_head_follow_subscriptions.remove(&subscription_id)
                else {
                    continue;
                };

                // Cancel operations isn't necessary, but is also not a bad idea, to
                // save resources.
                for (_, operation) in subscription_info.operations_in_progress {
                    operation.interrupt.notify(usize::MAX);
                }

                // Send a stop event.
                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_v1_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::Stop {},
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadOperationCancelled) => {
                // Nothing to do.
            }

            WakeUpReason::RuntimeServiceSubscriptionReady(subscribe_all) => {
                // Runtime service is now ready to give us blocks.
                // This only relates to the legacy JSON-RPC API.

                // Transition to `RuntimeServiceSubscription::Active`.
                let mut pinned_blocks =
                    hashbrown::HashMap::with_capacity_and_hasher(32, Default::default());
                let mut finalized_and_pruned_lru = lru::LruCache::with_hasher(
                    NonZero::<usize>::new(32).unwrap(),
                    fnv::FnvBuildHasher::default(),
                );

                let finalized_block_hash = header::hash_from_scale_encoded_header(
                    &subscribe_all.finalized_block_scale_encoded_header,
                );
                pinned_blocks.insert(
                    finalized_block_hash,
                    RecentBlock {
                        scale_encoded_header: subscribe_all.finalized_block_scale_encoded_header,
                        runtime_version: Arc::new(subscribe_all.finalized_block_runtime),
                    },
                );
                finalized_and_pruned_lru.put(finalized_block_hash, ());

                let mut current_best_block = finalized_block_hash;

                for block in subscribe_all.non_finalized_blocks_ancestry_order {
                    let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                    pinned_blocks.insert(
                        hash,
                        RecentBlock {
                            scale_encoded_header: block.scale_encoded_header,
                            runtime_version: match block.new_runtime {
                                Some(r) => Arc::new(r),
                                None => pinned_blocks
                                    .get(&block.parent_hash)
                                    .unwrap()
                                    .runtime_version
                                    .clone(),
                            },
                        },
                    );

                    if block.is_new_best {
                        current_best_block = hash;
                    }
                }

                me.runtime_service_subscription = RuntimeServiceSubscription::Active {
                    subscription: subscribe_all.new_blocks,
                    pinned_blocks,
                    finalized_and_pruned_lru,
                    current_best_block,
                    new_heads_and_runtime_subscriptions_stale: Some(None),
                    current_finalized_block: finalized_block_hash,
                    finalized_heads_subscriptions_stale: true,
                };

                // Advance all the requests that are waiting for the best block hash to be known.
                // We use `mem::take` as this de-allocates the memory of the `Vec`.
                for (request_id, request_ty) in mem::take(&mut me.best_block_hash_pending) {
                    me.multistage_requests_to_advance.push_back((
                        request_id,
                        MultiStageRequestStage::BlockHashKnown {
                            block_hash: current_best_block,
                        },
                        request_ty,
                    ));
                }

                // Answer all the pending `chain_getFinalizedHash` requests.
                // We use `mem::take` as this de-allocates the memory of the `Vec`.
                for request_id in mem::take(&mut me.pending_get_finalized_head) {
                    let _ = me
                        .responses_tx
                        .send(
                            methods::Response::chain_getFinalizedHead(methods::HashHexString(
                                finalized_block_hash,
                            ))
                            .to_json_response(&request_id),
                        )
                        .await;
                }
            }

            WakeUpReason::RuntimeServiceSubscriptionDead => {
                // The subscription towards the runtime service needs to be renewed.

                // The buffer size should be large enough so that, if the CPU is busy, it
                // doesn't become full before the execution of this task resumes.
                // The maximum number of pinned block is ignored, as this maximum is a way to
                // avoid malicious behaviors. This code is by definition not considered
                // malicious.
                let runtime_service = me.runtime_service.clone();
                me.runtime_service_subscription =
                    RuntimeServiceSubscription::Pending(Box::pin(async move {
                        runtime_service
                            .subscribe_all(
                                32,
                                NonZero::<usize>::new(usize::MAX).unwrap_or_else(|| unreachable!()),
                            )
                            .await
                    }));
            }

            WakeUpReason::RuntimeServiceSubscriptionNotification {
                notification:
                    runtime_service::Notification::BestBlockChanged {
                        hash: new_best_hash,
                        ..
                    },
                current_best_block,
                new_heads_and_runtime_subscriptions_stale,
                ..
            } => {
                // Runtime service has notified that the best block has changed.
                // This only relates to the legacy JSON-RPC API.
                // This is handled by marking subscriptions as stale.
                *new_heads_and_runtime_subscriptions_stale = Some(Some(*current_best_block));
                *current_best_block = new_best_hash;
            }

            WakeUpReason::RuntimeServiceSubscriptionNotification {
                notification: runtime_service::Notification::Block(block),
                pinned_blocks,
                current_best_block,
                new_heads_and_runtime_subscriptions_stale,
                ..
            } => {
                // Runtime service has notified of a new best block.
                // This only relates to the legacy JSON-RPC API.
                let json_rpc_header = match methods::Header::from_scale_encoded_header(
                    &block.scale_encoded_header,
                    me.runtime_service.block_number_bytes(),
                ) {
                    Ok(h) => h,
                    Err(error) => {
                        log!(
                            &me.platform,
                            Warn,
                            &me.log_target,
                            format!(
                                "`chain_subscribeAllHeads` subscription has skipped block \
                                due to undecodable header. Hash: {}. Error: {}",
                                HashDisplay(&header::hash_from_scale_encoded_header(
                                    &block.scale_encoded_header
                                )),
                                error
                            )
                        );
                        continue;
                    }
                };

                let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                // The JSON-RPC client is likely to query things about the new block. We thus
                // put it in cache.
                me.block_headers_cache.put(
                    hash,
                    Ok((
                        block.scale_encoded_header.clone(),
                        json_rpc_header.state_root.0,
                        json_rpc_header.number,
                    )),
                );

                let _was_in = pinned_blocks.insert(
                    hash,
                    RecentBlock {
                        scale_encoded_header: block.scale_encoded_header,
                        runtime_version: match block.new_runtime {
                            Some(r) => Arc::new(r),
                            None => pinned_blocks
                                .get(&block.parent_hash)
                                .unwrap()
                                .runtime_version
                                .clone(),
                        },
                    },
                );
                debug_assert!(_was_in.is_none());

                for subscription_id in &me.all_heads_subscriptions {
                    let _ = me
                        .responses_tx
                        .send(
                            methods::ServerToClient::chain_allHead {
                                subscription: subscription_id.as_str().into(),
                                result: json_rpc_header.clone(),
                            }
                            .to_json_request_object_parameters(None),
                        )
                        .await;
                }

                if block.is_new_best {
                    *new_heads_and_runtime_subscriptions_stale = Some(Some(*current_best_block));
                    *current_best_block = hash;
                }
            }

            WakeUpReason::RuntimeServiceSubscriptionNotification {
                notification:
                    runtime_service::Notification::Finalized {
                        hash: finalized_hash,
                        pruned_blocks,
                        best_block_hash_if_changed,
                    },
                pinned_blocks,
                finalized_and_pruned_lru,
                subscription,
                current_best_block,
                new_heads_and_runtime_subscriptions_stale,
                current_finalized_block,
                finalized_heads_subscriptions_stale,
            } => {
                // Runtime service has notified a new finalized block.
                // This only relates to the legacy JSON-RPC API.

                *current_finalized_block = finalized_hash;
                *finalized_heads_subscriptions_stale = true;

                debug_assert!(
                    pruned_blocks
                        .iter()
                        .all(|hash| pinned_blocks.contains_key(hash))
                );

                // Add the pruned and finalized blocks to the LRU cache. The least-recently used
                // entries in the cache are unpinned and no longer tracked.
                //
                // An important detail here is that the newly-finalized block is added to the list
                // at the end, in order to guarantee that it doesn't get removed. This is
                // necessary in order to guarantee that the current finalized (and current best,
                // if the best block is also the finalized block) remains pinned until at least
                // a different block gets finalized.
                for block_hash in pruned_blocks.into_iter().chain(iter::once(finalized_hash)) {
                    if finalized_and_pruned_lru.len() == finalized_and_pruned_lru.cap().get() {
                        let (hash_to_unpin, _) = finalized_and_pruned_lru.pop_lru().unwrap();
                        subscription.unpin_block(hash_to_unpin).await;
                        pinned_blocks.remove(&hash_to_unpin).unwrap();
                    }
                    finalized_and_pruned_lru.put(block_hash, ());
                }

                if let Some(new_best_block_hash) = best_block_hash_if_changed {
                    *new_heads_and_runtime_subscriptions_stale = Some(Some(*current_best_block));
                    *current_best_block = new_best_block_hash;
                }
            }

            WakeUpReason::Event(Event::BlockInfoRetrieved {
                block_hash,
                result: Ok(result),
            }) => {
                // A block header necessary for a "multi-stage request" has successfully been
                // retrieved.

                me.block_headers_cache.put(block_hash, result);

                for (request_id, request) in me
                    .block_headers_pending
                    .remove(&block_hash)
                    .into_iter()
                    .flatten()
                {
                    // Note that we push_front in order to guarantee that the information is
                    // not removed from cache before the request is processed.
                    me.multistage_requests_to_advance.push_front((
                        request_id,
                        MultiStageRequestStage::BlockHashKnown { block_hash },
                        request,
                    ));
                }
            }

            WakeUpReason::Event(Event::BlockInfoRetrieved {
                block_hash,
                result: Err(()),
            }) => {
                // A block header necessary for a "multi-stage request" has failed to be
                // retrieved.
                for (request_id, _) in me
                    .block_headers_pending
                    .remove(&block_hash)
                    .into_iter()
                    .flatten()
                {
                    let _ = me
                        .responses_tx
                        .send(parse::build_error_response(
                            &request_id,
                            parse::ErrorResponse::ApplicationDefined(
                                -32800,
                                "Failed to retrieve block information from the network",
                            ),
                            None,
                        ))
                        .await;
                }
            }

            WakeUpReason::Event(Event::RuntimeDownloaded {
                block_hash,
                result: Ok(result),
            }) => {
                // A block runtime necessary for a "multi-stage request" has successfully been
                // retrieved.

                me.block_runtimes_cache.put(block_hash, result);

                for (request_id, request) in me
                    .block_runtimes_pending
                    .remove(&block_hash)
                    .into_iter()
                    .flatten()
                {
                    // Note that we push_front in order to guarantee that the information is
                    // not removed from cache before the request is processed.
                    me.multistage_requests_to_advance.push_front((
                        request_id,
                        MultiStageRequestStage::BlockHashKnown { block_hash },
                        request,
                    ));
                }
            }

            WakeUpReason::Event(Event::RuntimeDownloaded {
                block_hash,
                result: Err(error_message),
            }) => {
                // A block runtime necessary for a "multi-stage request" has failed to be
                // retrieved.
                for (request_id, _) in me
                    .block_runtimes_pending
                    .remove(&block_hash)
                    .into_iter()
                    .flatten()
                {
                    let _ = me
                        .responses_tx
                        .send(parse::build_error_response(
                            &request_id,
                            parse::ErrorResponse::ApplicationDefined(
                                -32800,
                                &format!(
                                    "Failed to retrieve runtime from the \
                                    network: {error_message}"
                                ),
                            ),
                            None,
                        ))
                        .await;
                }
            }

            WakeUpReason::Event(Event::TransactionEvent {
                subscription_id,
                event: transactions_service::TransactionStatus::Dropped(drop_reason),
                ..
            }) => {
                // Transactions service has notified that a transaction has left its pool.
                let Some(transaction_watch) =
                    me.transactions_subscriptions.remove(&subscription_id)
                else {
                    // JSON-RPC client has unsubscribed from this transaction and is no longer
                    // interested in events.
                    continue;
                };

                match (drop_reason, &transaction_watch.ty) {
                    (
                        transactions_service::DropReason::GapInChain
                        | transactions_service::DropReason::Crashed,
                        TransactionWatchTy::NewApi { transaction_bytes },
                    ) => {
                        // In case of `transaction_v1_broadcast`, we re-submit the transaction
                        // if it was dropped for a temporary reasons.
                        let mut new_watcher = Box::pin(
                            me.transactions_service
                                .submit_and_watch_transaction(transaction_bytes.clone(), 16, false)
                                .await,
                        );

                        let _prev_value = me
                            .transactions_subscriptions
                            .insert(subscription_id.clone(), transaction_watch);
                        debug_assert!(_prev_value.is_none());

                        // Push a new background task that waits for the next notification.
                        me.background_tasks.push(Box::pin(async move {
                            let Some(status) = new_watcher.as_mut().next().await else {
                                unreachable!()
                            };
                            Event::TransactionEvent {
                                subscription_id,
                                event: status,
                                watcher: new_watcher,
                            }
                        }));
                    }

                    (
                        transactions_service::DropReason::Finalized { .. }
                        | transactions_service::DropReason::Invalid(_)
                        | transactions_service::DropReason::MaxPendingTransactionsReached
                        | transactions_service::DropReason::ValidateError(_),
                        TransactionWatchTy::NewApi { .. },
                    ) => {
                        // In case of `transaction_v1_broadcast`, the transaction is re-inserted
                        // in the list, but no new notification-generating task is pushed, making
                        // the transaction effectively dead and waiting for `transaction_v1_stop`
                        // to be called to remove it.
                        let _prev_value = me
                            .transactions_subscriptions
                            .insert(subscription_id.clone(), transaction_watch);
                        debug_assert!(_prev_value.is_none());
                    }

                    (transactions_service::DropReason::GapInChain, TransactionWatchTy::Legacy)
                    | (
                        transactions_service::DropReason::MaxPendingTransactionsReached,
                        TransactionWatchTy::Legacy,
                    )
                    | (transactions_service::DropReason::Invalid(_), TransactionWatchTy::Legacy)
                    | (
                        transactions_service::DropReason::ValidateError(_),
                        TransactionWatchTy::Legacy,
                    )
                    | (transactions_service::DropReason::Crashed, TransactionWatchTy::Legacy) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::author_extrinsicUpdate {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionStatus::Dropped,
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::DropReason::GapInChain,
                        TransactionWatchTy::NewApiWatch,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_v1_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Dropped {
                                        error: "gap in chain of blocks".into(),
                                        broadcasted: transaction_watch.num_broadcasted_peers != 0,
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::DropReason::MaxPendingTransactionsReached,
                        TransactionWatchTy::NewApiWatch,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_v1_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Dropped {
                                        error: "transactions pool full".into(),
                                        broadcasted: transaction_watch.num_broadcasted_peers != 0,
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::DropReason::Invalid(error),
                        TransactionWatchTy::NewApiWatch,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_v1_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Invalid {
                                        error: error.to_string().into(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::DropReason::ValidateError(error),
                        TransactionWatchTy::NewApiWatch,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_v1_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Error {
                                        error: error.to_string().into(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::DropReason::Crashed,
                        TransactionWatchTy::NewApiWatch,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_v1_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Error {
                                        error: "transactions service has crashed".into(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }

                    (
                        transactions_service::DropReason::Finalized { block_hash, .. },
                        TransactionWatchTy::Legacy,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::author_extrinsicUpdate {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionStatus::Finalized(
                                        methods::HashHexString(block_hash),
                                    ),
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::DropReason::Finalized { block_hash, index },
                        TransactionWatchTy::NewApiWatch,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_v1_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Finalized {
                                        block: methods::TransactionWatchEventBlock {
                                            hash: methods::HashHexString(block_hash),
                                            index,
                                        },
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                }
            }

            WakeUpReason::Event(Event::TransactionEvent {
                subscription_id,
                event,
                mut watcher,
            }) => {
                // Event (other than `Dropped`, as it's handled above) from the
                // transactions service.
                let Some(transaction_watch) =
                    me.transactions_subscriptions.get_mut(&subscription_id)
                else {
                    // JSON-RPC client has unsubscribed from this transaction and is no longer
                    // interested in events.
                    continue;
                };

                match (event, &transaction_watch.ty) {
                    (_, TransactionWatchTy::NewApi { .. }) => {
                        // Events are ignored when it comes to `transaction_v1_broadcast`.
                    }

                    (
                        transactions_service::TransactionStatus::Broadcast(peers),
                        TransactionWatchTy::Legacy,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::author_extrinsicUpdate {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionStatus::Broadcast(
                                        peers.into_iter().map(|peer| peer.to_base58()).collect(),
                                    ),
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::TransactionStatus::Broadcast(peers),
                        TransactionWatchTy::NewApiWatch,
                    ) => {
                        transaction_watch.num_broadcasted_peers += peers.len();
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_v1_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Broadcasted {
                                        num_peers: u32::try_from(
                                            transaction_watch.num_broadcasted_peers,
                                        )
                                        .unwrap_or(u32::MAX),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }

                    (
                        transactions_service::TransactionStatus::Validated,
                        TransactionWatchTy::Legacy,
                    ) => {
                        // Nothing to do.
                    }
                    (
                        transactions_service::TransactionStatus::Validated,
                        TransactionWatchTy::NewApiWatch,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_v1_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Validated {},
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }

                    (
                        transactions_service::TransactionStatus::IncludedBlockUpdate {
                            block_hash: Some((block_hash, _)),
                        },
                        TransactionWatchTy::Legacy,
                    ) => {
                        transaction_watch.included_block = Some(block_hash);
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::author_extrinsicUpdate {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionStatus::InBlock(
                                        methods::HashHexString(block_hash),
                                    ),
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::TransactionStatus::IncludedBlockUpdate {
                            block_hash: None,
                        },
                        TransactionWatchTy::Legacy,
                    ) => {
                        if let Some(block_hash) = transaction_watch.included_block.take() {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::ServerToClient::author_extrinsicUpdate {
                                        subscription: Cow::Borrowed(&subscription_id),
                                        result: methods::TransactionStatus::Retracted(
                                            methods::HashHexString(block_hash),
                                        ),
                                    }
                                    .to_json_request_object_parameters(None),
                                )
                                .await;
                        }
                    }
                    (
                        transactions_service::TransactionStatus::IncludedBlockUpdate {
                            block_hash: Some((block_hash, index)),
                        },
                        TransactionWatchTy::NewApiWatch,
                    ) => {
                        transaction_watch.included_block = Some(block_hash);
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_v1_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result:
                                        methods::TransactionWatchEvent::BestChainBlockIncluded {
                                            block: Some(methods::TransactionWatchEventBlock {
                                                hash: methods::HashHexString(block_hash),
                                                index,
                                            }),
                                        },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::TransactionStatus::IncludedBlockUpdate {
                            block_hash: None,
                        },
                        TransactionWatchTy::NewApiWatch,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_v1_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result:
                                        methods::TransactionWatchEvent::BestChainBlockIncluded {
                                            block: None,
                                        },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }

                    // `Dropped` was handle above separately.
                    (transactions_service::TransactionStatus::Dropped(_), _) => unreachable!(),
                }

                // Push a new background task that waits for the next notification.
                me.background_tasks.push(Box::pin(async move {
                    let Some(status) = watcher.as_mut().next().await else {
                        unreachable!()
                    };
                    Event::TransactionEvent {
                        subscription_id,
                        event: status,
                        watcher,
                    }
                }));
            }

            WakeUpReason::Event(Event::ChainGetBlockResult {
                request_id_json,
                mut result,
                expected_block_hash,
            }) => {
                // A network request necessary to fulfill `chain_getBlock` has finished.

                // Check whether the header and body are present and valid.
                // TODO: try the request again with a different peerin case the response is invalid, instead of returning null
                if let Ok(block) = &result {
                    if let (Some(header), Some(body)) = (&block.header, &block.body) {
                        if header::hash_from_scale_encoded_header(header) == expected_block_hash {
                            if let Ok(decoded) =
                                header::decode(header, me.sync_service.block_number_bytes())
                            {
                                if header::extrinsics_root(body) != *decoded.extrinsics_root {
                                    result = Err(());
                                }
                            } else {
                                // Note that if the header is undecodable it doesn't necessarily mean
                                // that the header and/or body is bad, but given that we have no way to
                                // check this we return an error.
                                result = Err(());
                            }
                        } else {
                            result = Err(());
                        }
                    } else {
                        result = Err(());
                    }
                }

                // Send the response.
                if let Ok(block) = result {
                    let _ = me
                        .responses_tx
                        .send(
                            methods::Response::chain_getBlock(methods::Block {
                                extrinsics: block
                                    .body
                                    .unwrap()
                                    .into_iter()
                                    .map(methods::HexString)
                                    .collect(),
                                header: methods::Header::from_scale_encoded_header(
                                    &block.header.unwrap(),
                                    me.sync_service.block_number_bytes(),
                                )
                                .unwrap(),
                                // There's no way to verify the correctness of the justifications, consequently
                                // we always return an empty list.
                                justifications: None,
                            })
                            .to_json_response(&request_id_json),
                        )
                        .await;
                } else {
                    let _ = me
                        .responses_tx
                        .send(parse::build_success_response(&request_id_json, "null"))
                        .await;
                }
            }

            WakeUpReason::StartStorageSubscriptionsUpdates => {
                // Some existing `state_storageSubscribe` haven't been notified of subscription
                // changes of the latest best block. Start storage requests on the network.

                let RuntimeServiceSubscription::Active {
                    pinned_blocks,
                    current_best_block,
                    ..
                } = &mut me.runtime_service_subscription
                else {
                    unreachable!()
                };

                // If the header of the current best block can't be decoded, we don't do anything.
                let (block_number, state_trie_root) = match header::decode(
                    &pinned_blocks
                        .get(current_best_block)
                        .unwrap()
                        .scale_encoded_header,
                    me.runtime_service.block_number_bytes(),
                ) {
                    Ok(header) => (header.number, *header.state_root),
                    Err(_) => {
                        // Can't decode the header of the current best block.
                        // All the subscriptions are marked as non-stale, since they are up-to-date
                        // with the current best block.
                        // TODO: print warning?
                        me.legacy_api_stale_storage_subscriptions.clear();
                        continue;
                    }
                };

                // Build the list of keys that must be requested by aggregating the keys requested
                // by all stale storage subscriptions.
                let mut keys = hashbrown::HashSet::with_hasher(SipHasherBuild::new({
                    let mut seed = [0; 16];
                    me.platform.fill_random_bytes(&mut seed);
                    seed
                }));
                keys.extend(
                    me.legacy_api_stale_storage_subscriptions
                        .iter()
                        .map(|s_id| {
                            me.legacy_api_storage_subscriptions
                                .range((s_id.clone(), Vec::new())..)
                                .take_while(move |(s, _)| s == s_id)
                                .map(|(_, key)| key)
                        })
                        .flat_map(|keys_list| keys_list.cloned()),
                );

                // If the list of keys to query is empty, we mark all subscriptions as no longer
                // stale and loop again. This is necessary in order to prevent infinite loops if
                // the JSON-RPC client subscribes to an empty list of items.
                if keys.is_empty() {
                    me.legacy_api_stale_storage_subscriptions.clear();
                    continue;
                }

                // Start the task in the background.
                // The task will generate a
                // `Event::LegacyApiStorageSubscriptionsUpdate` once it is done.
                me.legacy_api_storage_query_in_progress = true;
                me.background_tasks.push(Box::pin({
                    let block_hash = *current_best_block;
                    let sync_service = me.sync_service.clone();
                    async move {
                        let mut out = Vec::with_capacity(keys.len());
                        let mut query = sync_service
                            .storage_query(
                                block_number,
                                block_hash,
                                state_trie_root,
                                keys.into_iter()
                                    .map(|key| sync_service::StorageRequestItem {
                                        key,
                                        ty: sync_service::StorageRequestItemTy::Value,
                                    }),
                                4,
                                Duration::from_secs(12),
                                NonZero::<u32>::new(2).unwrap(),
                            )
                            .advance()
                            .await;
                        loop {
                            match query {
                                sync_service::StorageQueryProgress::Progress {
                                    item,
                                    query: next,
                                    ..
                                } => {
                                    out.push(item);
                                    query = next.advance().await;
                                }
                                sync_service::StorageQueryProgress::Finished => {
                                    break Event::LegacyApiStorageSubscriptionsUpdate {
                                        block_hash,
                                        result: Ok(out),
                                    };
                                }
                                sync_service::StorageQueryProgress::Error(error) => {
                                    break Event::LegacyApiStorageSubscriptionsUpdate {
                                        block_hash,
                                        result: Err(error),
                                    };
                                }
                            }
                        }
                    }
                }));
            }

            WakeUpReason::Event(Event::LegacyApiStorageSubscriptionsUpdate {
                block_hash,
                result: Ok(result),
            }) => {
                // Background task dedicated to performing a storage query for the storage
                // subscriptions has finished.

                debug_assert!(me.legacy_api_storage_query_in_progress);
                me.legacy_api_storage_query_in_progress = false;

                // Determine whether another storage query targeting a more up-to-date block
                // must be started afterwards.
                let is_up_to_date = match me.runtime_service_subscription {
                    RuntimeServiceSubscription::Active {
                        current_best_block, ..
                    } => current_best_block == block_hash,
                    RuntimeServiceSubscription::NotCreated
                    | RuntimeServiceSubscription::Pending(_) => true,
                };

                // Because all the keys of all the subscriptions are merged into one network
                // request, we must now attribute each item in the result back to its subscription.
                // While this solution is a bit CPU-heavy, it is a more elegant solution than
                // keeping track of subscription in the background task.
                let mut notifications_to_send = hashbrown::HashMap::<
                    Arc<str>,
                    Vec<(methods::HexString, Option<methods::HexString>)>,
                    _,
                >::with_capacity_and_hasher(
                    me.legacy_api_storage_subscriptions.len(),
                    fnv::FnvBuildHasher::default(),
                );
                for item in result {
                    let sync_service::StorageResultItem::Value { key, value } = item else {
                        unreachable!()
                    };
                    for subscription_id in me
                        .legacy_api_storage_subscriptions_by_key
                        .range((key.clone(), Arc::from(String::new()))..)
                        .take_while(|(k, _)| *k == key)
                        .map(|(_, s_id)| s_id.clone())
                    {
                        notifications_to_send
                            .entry(subscription_id)
                            .or_insert_with(Vec::new)
                            .push((
                                methods::HexString(key.clone()),
                                value.clone().map(methods::HexString),
                            ));
                    }
                }

                // Send the notifications and mark the subscriptions as no longer stale if
                // relevant.
                for (subscription_id, changes) in notifications_to_send {
                    if is_up_to_date {
                        me.legacy_api_stale_storage_subscriptions
                            .remove(&subscription_id);
                    }
                    let _ = me
                        .responses_tx
                        .send(
                            methods::ServerToClient::state_storage {
                                subscription: Cow::Borrowed(&*subscription_id),
                                result: methods::StorageChangeSet {
                                    block: methods::HashHexString(block_hash),
                                    changes,
                                },
                            }
                            .to_json_request_object_parameters(None),
                        )
                        .await;
                }
            }

            // Background task dedicated to performing a storage query for the storage
            // subscription has finished but was unsuccessful.
            WakeUpReason::Event(Event::LegacyApiStorageSubscriptionsUpdate {
                result: Err(_),
                ..
            }) => {
                // Background task dedicated to performing a storage query for the storage
                // subscriptions has failed.
                debug_assert!(me.legacy_api_storage_query_in_progress);
                me.legacy_api_storage_query_in_progress = false;
                // TODO: add a delay or something?
            }

            WakeUpReason::Event(Event::TopicAffinitySent) => {}

            WakeUpReason::NotifyFinalizedHeads => {
                // All `chain_subscribeFinalizedHeads` subscriptions must be notified of the
                // latest finalized block.

                let RuntimeServiceSubscription::Active {
                    pinned_blocks,
                    current_finalized_block,
                    finalized_heads_subscriptions_stale,
                    ..
                } = &mut me.runtime_service_subscription
                else {
                    unreachable!()
                };

                let finalized_block_header = &pinned_blocks
                    .get(current_finalized_block)
                    .unwrap()
                    .scale_encoded_header;
                let finalized_block_json_rpc_header =
                    match methods::Header::from_scale_encoded_header(
                        finalized_block_header,
                        me.runtime_service.block_number_bytes(),
                    ) {
                        Ok(h) => h,
                        Err(error) => {
                            log!(
                                &me.platform,
                                Warn,
                                &me.log_target,
                                format!(
                                    "`chain_subscribeFinalizedHeads` subscription has skipped \
                                    block due to undecodable header. Hash: {}. Error: {}",
                                    HashDisplay(current_finalized_block),
                                    error,
                                )
                            );
                            continue;
                        }
                    };

                for subscription_id in &me.finalized_heads_subscriptions {
                    let _ = me
                        .responses_tx
                        .send(
                            methods::ServerToClient::chain_finalizedHead {
                                subscription: Cow::Borrowed(subscription_id),
                                result: finalized_block_json_rpc_header.clone(),
                            }
                            .to_json_request_object_parameters(None),
                        )
                        .await;
                }

                *finalized_heads_subscriptions_stale = false;
            }

            WakeUpReason::NotifyNewHeadsRuntimeSubscriptions(previous_best_block) => {
                // All `chain_subscribeNewHeads` subscriptions must be notified of the
                // latest best block.

                let RuntimeServiceSubscription::Active {
                    pinned_blocks,
                    current_best_block,
                    ..
                } = &mut me.runtime_service_subscription
                else {
                    unreachable!()
                };

                let best_block_header = &pinned_blocks
                    .get(current_best_block)
                    .unwrap()
                    .scale_encoded_header;
                let best_block_json_rpc_header = match methods::Header::from_scale_encoded_header(
                    best_block_header,
                    me.runtime_service.block_number_bytes(),
                ) {
                    Ok(h) => h,
                    Err(error) => {
                        log!(
                            &me.platform,
                            Warn,
                            &me.log_target,
                            format!(
                                "`chain_subscribeNewHeads` subscription has skipped block due to \
                                undecodable header. Hash: {}. Error: {}",
                                HashDisplay(current_best_block),
                                error
                            )
                        );
                        continue;
                    }
                };

                for subscription_id in &me.new_heads_subscriptions {
                    let _ = me
                        .responses_tx
                        .send(
                            methods::ServerToClient::chain_newHead {
                                subscription: Cow::Borrowed(subscription_id),
                                result: best_block_json_rpc_header.clone(),
                            }
                            .to_json_request_object_parameters(None),
                        )
                        .await;
                }

                let new_best_runtime = &pinned_blocks
                    .get(current_best_block)
                    .unwrap()
                    .runtime_version;
                if previous_best_block.map_or(true, |prev_best_block| {
                    !Arc::ptr_eq(
                        new_best_runtime,
                        &pinned_blocks.get(&prev_best_block).unwrap().runtime_version,
                    )
                }) {
                    if let Ok(new_best_runtime) = &**new_best_runtime {
                        for subscription_id in &me.runtime_version_subscriptions {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::ServerToClient::state_runtimeVersion {
                                        subscription: subscription_id.as_str().into(),
                                        result: Some(convert_runtime_version_legacy(
                                            new_best_runtime,
                                        )),
                                    }
                                    .to_json_request_object_parameters(None),
                                )
                                .await;
                        }
                    }
                }

                // The `state_subscribeStorage` subscriptions are marked as stale after sending
                // out the notifications.
                me.legacy_api_stale_storage_subscriptions.extend(
                    me.legacy_api_storage_subscriptions
                        .iter()
                        .map(|(s_id, _)| s_id.clone()),
                );
            }
        }
    }
}

fn convert_runtime_version_legacy(
    runtime_spec: &'_ smoldot::executor::CoreVersion,
) -> methods::RuntimeVersion<'_> {
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

fn convert_runtime_version(
    runtime_spec: &'_ smoldot::executor::CoreVersion,
) -> methods::RuntimeSpec<'_> {
    let runtime_spec = runtime_spec.decode();
    methods::RuntimeSpec {
        spec_name: runtime_spec.spec_name.into(),
        impl_name: runtime_spec.impl_name.into(),
        spec_version: runtime_spec.spec_version,
        impl_version: runtime_spec.impl_version,
        transaction_version: runtime_spec.transaction_version,
        apis: runtime_spec
            .apis
            .map(|api| (methods::HexString(api.name_hash.to_vec()), api.version))
            .collect(),
    }
}

fn build_combined_affinity_filter(
    subscriptions: &hashbrown::HashMap<String, network_service::TopicFilter, fnv::FnvBuildHasher>,
) -> network_service::AffinityFilter {
    let seed: u128 = 0x5EED_5EED_5EED_5EED;
    let mut all_topics: Vec<[u8; 32]> = Vec::new();
    for filter in subscriptions.values() {
        match filter {
            network_service::TopicFilter::Any => {
                return network_service::AffinityFilter::from_topic_filter(
                    seed,
                    &network_service::TopicFilter::Any,
                );
            }
            network_service::TopicFilter::MatchAll(topics)
            | network_service::TopicFilter::MatchAny(topics) => {
                all_topics.extend_from_slice(topics);
            }
        }
    }
    let count = all_topics.len().max(1);
    let mut combined = network_service::AffinityFilter::new(seed, 0.01, count);
    for topic in &all_topics {
        combined.insert(topic);
    }
    combined
}
