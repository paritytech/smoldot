// Smoldot
// Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
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

//! Background Bitswap service.
//!
//! The role of Bitswap service is to handle Bitswap RPC requests, specifically
//! `bitswap_v1_get(cid)`.
//!
//! In order to handle a request for a Bitswap block with a given CID, [`BitswapService`] issues
//! Bitswap "have" request to all the connected Bitswap peers, then issues Bitswap "block" request
//! to the first peer that answered "yes" to that request.
//!
//! Note that we have [`BitswapService`] per chain, even though currently
//! [`NetworkService`](crate::network_service::NetworkService) doesn't track what chain the Bitswap
//! request is destined to, and doesn't track what chain peers responded to it to forward the
//! response to specific chain's [`BitswapService`]. As a result, [`BitswapService`] receives the
//! responses intended for all the other Bitswap services as well. This should be fixed in
//! [`NetworkService`](crate::network_service::NetworkService), but it is somewhat mitigated in
//! [`BitswapService`] by not decoding the incoming Bitswap messages when there are no active
//! requests.
//
// TODO: backpressure.
//
// TODO: wait a bit longer after receiving the first "have" response and randomly select the peer
// for "block" request to distribute the load.
//
// TODO: do we need to retry the request with another peer if the first one didn't return the data
// within the given time?
//
// TODO: do we need to ban peers that do not return the requested data after answering "yes" to
// a "have" request? How much to wait for a response?
//
// TODO: do we need a "reputation system" to prefer peers that respond faster then others?

use crate::{
    log,
    network_service::{self, BitswapEvent, PeerId, SendBitswapMessageError},
    platform::PlatformRef,
    util,
};
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::{BTreeSet, VecDeque},
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec::Vec,
};
use core::{iter, pin::Pin, str::FromStr, time::Duration};
use futures_channel::oneshot;
use futures_lite::FutureExt as _;
use futures_util::{StreamExt as _, future, stream::FuturesUnordered};
use itertools::Itertools;
use rand::RngCore;
use rand_chacha::rand_core::SeedableRng as _;
use smoldot::{
    json_rpc::parse,
    libp2p::cid::{self, Cid, CidPrefix},
    network::codec::{
        Block, BlockPresence, BlockPresenceType, WantType, build_bitswap_cancel_message,
        build_bitswap_message,
    },
};

// TODO: how many parallel requests to expect?
const PARALLEL_REQUESTS: usize = 50; // 100 MiB of 2 MiB chunks.

/// Maximum number of CIDs accepted in a single `bitswap_v1_getMany` or `bitswap_v1_stream` call.
/// Mirrors the limit used by the polkadot-sdk full-node implementation. The spec requires
/// implementations to accept at least 16 CIDs.
pub const MAX_CIDS_PER_REQUEST: usize = 64;

/// Configuration for a [`BitswapService`].
pub struct Config<TPlat: PlatformRef> {
    /// Name of the chain, for logging purposes.
    ///
    /// > **Note**: This name will be directly printed out. Any special character should already
    /// >           have been filtered out from this name.
    pub log_name: String,
    /// Access to the platform's capabilities.
    pub platform: TPlat,
    /// Access to the network.
    pub network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
}

/// A service handling Bitswap RPC requests.
pub struct BitswapService {
    /// Channel connected to the background service.
    messages_tx: async_channel::Sender<ToBackground>,
}

impl BitswapService {
    /// Initializes the Bitswap service with the given configuration.
    pub fn new<TPlat: PlatformRef>(
        Config {
            log_name,
            platform,
            network_service,
        }: Config<TPlat>,
    ) -> Self {
        let (messages_tx, messages_rx) = async_channel::bounded(32);

        let log_target = format!("bitswap-service-{}", log_name);

        let task = Box::pin(background_task(BackgroundTask {
            log_target: log_target.clone(),
            messages_rx: Box::pin(messages_rx),
            network_service,
            from_network_service: None,
            pending_have_broadcast: None,
            pending_block_requests: FuturesUnordered::new(),
            platform: platform.clone(),
            next_request_id_inner: 0,
            next_batch_id_inner: 0,
            randomness: rand_chacha::ChaCha20Rng::from_seed({
                let mut seed = [0; 32];
                platform.fill_random_bytes(&mut seed);
                seed
            }),
            requests: hashbrown::HashMap::with_capacity_and_hasher(
                PARALLEL_REQUESTS,
                fnv::FnvBuildHasher::default(),
            ),
            requests_by_timeout: BTreeSet::new(),
            requests_by_cid: hashbrown::HashMap::with_capacity_and_hasher(
                PARALLEL_REQUESTS,
                util::SipHasherBuild::new({
                    let mut seed = [0; 16];
                    platform.fill_random_bytes(&mut seed);
                    seed
                }),
            ),
            batches: hashbrown::HashMap::with_capacity_and_hasher(
                PARALLEL_REQUESTS,
                fnv::FnvBuildHasher::default(),
            ),
        }));

        platform.spawn_task(log_target.clone().into(), {
            let platform = platform.clone();
            async move {
                task.await;
                log!(&platform, Debug, &log_target, "shutdown");
            }
        });

        BitswapService { messages_tx }
    }

    /// Request a Bitswap block.
    pub async fn bitswap_get(&self, cid: String) -> Result<Vec<u8>, BitswapGetError> {
        // Decoding CID is fast, so we can fail early on the API user side.
        let cid = Cid::from_str(&cid).map_err(BitswapGetError::InvalidCid)?;

        let (result_tx, result_rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::BitswapBlock { cid, result_tx })
            .await
            .unwrap();

        result_rx.await.unwrap()
    }

    /// Request multiple Bitswap blocks in a single batched want-list. Resolves once every CID has
    /// been decided (Ok block, NotFound, or Timeout). The returned `Vec` echoes input CIDs in input
    /// order with a [`BlockResult`] per slot.
    ///
    /// Top-level errors (`-32602 InvalidParams`): empty input is allowed (returns empty vec);
    /// duplicate CIDs or batch size > [`MAX_CIDS_PER_REQUEST`] are rejected before any wire I/O.
    pub async fn bitswap_get_many(
        &self,
        cids: Vec<String>,
    ) -> Result<Vec<(String, BlockResult)>, BitswapGetError> {
        let entries = parse_and_dedup(cids)?;

        if entries.is_empty() {
            return Ok(Vec::new());
        }

        let (result_tx, result_rx) = oneshot::channel();
        let (batch_id_tx, batch_id_rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::BitswapBatch {
                entries,
                mode: BatchMode::GetMany { result_tx },
                batch_id_tx,
            })
            .await
            .unwrap();

        let batch_id = batch_id_rx.await.unwrap();

        // RAII guard: if the caller's future is dropped before result_rx resolves, the guard
        // drops and sends `CancelBatch` to the service so peers receive a Cancel wantlist.
        let _cancel_guard = BatchCancelGuard {
            batch_id,
            messages_tx: self.messages_tx.clone(),
        };

        Ok(result_rx.await.unwrap())
    }

    /// Subscribe to a stream of Bitswap blocks. Returns immediately with a [`BitswapStreamHandle`]
    /// whose `events_rx` yields one `(cid_string, BlockResult)` event per input CID, in arrival
    /// order (the order in which each CID resolves), not input order.
    ///
    /// Dropping the returned handle (explicit unsubscribe or client disconnect) cancels remaining
    /// work and emits a Bitswap Cancel wantlist to peers we previously contacted.
    pub async fn bitswap_stream(
        &self,
        cids: Vec<String>,
    ) -> Result<BitswapStreamHandle, BitswapGetError> {
        let entries = parse_and_dedup(cids)?;

        // Channel size matches typical batch sizes; events_rx is drained promptly by the JSON-RPC
        // layer so back-pressure here is unlikely.
        let (events_tx, events_rx) = async_channel::bounded(MAX_CIDS_PER_REQUEST);
        let (batch_id_tx, batch_id_rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::BitswapBatch {
                entries,
                mode: BatchMode::Stream { events_tx },
                batch_id_tx,
            })
            .await
            .unwrap();

        let batch_id = batch_id_rx.await.unwrap();

        Ok(BitswapStreamHandle {
            events_rx,
            _cancel_guard: BatchCancelGuard {
                batch_id,
                messages_tx: self.messages_tx.clone(),
            },
        })
    }
}

/// Per-CID outcome of [`BitswapService::bitswap_get_many`] / [`BitswapService::bitswap_stream`].
#[derive(Debug, Clone)]
pub enum BlockResult {
    /// Block bytes received from a peer.
    Ok(Vec<u8>),
    /// Per-CID failure. The variant carries the same retry semantics as the top-level error of
    /// [`BitswapService::bitswap_get`].
    Err(BitswapGetError),
}

/// Active subscription handle for [`BitswapService::bitswap_stream`].
///
/// `events_rx` yields one event per input CID in arrival order. After all events have been
/// emitted, the channel closes naturally. Dropping the handle before then signals the service to
/// abort remaining work and emit a Bitswap Cancel wantlist for in-flight CIDs.
pub struct BitswapStreamHandle {
    /// Receiver of per-CID events. `(cid_string, BlockResult)` per spec.
    pub events_rx: async_channel::Receiver<(String, BlockResult)>,
    _cancel_guard: BatchCancelGuard,
}

/// Internal RAII guard that fires `ToBackground::CancelBatch` on drop. Held by both
/// [`BitswapStreamHandle`] (covers explicit unsubscribe and client disconnect) and the inner
/// future of [`BitswapService::bitswap_get_many`] (covers caller cancellation mid-await).
struct BatchCancelGuard {
    batch_id: BatchId,
    messages_tx: async_channel::Sender<ToBackground>,
}

impl Drop for BatchCancelGuard {
    fn drop(&mut self) {
        // Best-effort. If the service's channel is closed (service shut down already) or full
        // (extremely unlikely — bounded(32)), we have no recourse since Drop can't await.
        // A no-op CancelBatch on an already-finished batch is harmless: the service will look up
        // the batch_id, find nothing, and ignore the message.
        let _ = self.messages_tx.try_send(ToBackground::CancelBatch {
            batch_id: self.batch_id,
        });
    }
}

/// Error by [`BitswapService::bitswap_get`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum BitswapGetError {
    /// Invalid/unsupported CID.
    #[display("Invalid CID: {_0}")]
    InvalidCid(cid::ParseError),
    /// No Bitswap peers connected, can't issue "have" request.
    #[display("No Bitswap peers connected, can't issue \"have\" request.")]
    NoPeers,
    /// "Block" request to selected peer failed after successful "have" request.
    #[display("\"Block\" request to selected peer failed after successful \"have\" request.")]
    BlockRequestFailed,
    /// Network sending queue is full.
    #[display("Network sending queue is full.")]
    QueueFull,
    /// Requested CID not found.
    #[display("No connected peers have the CID requested.")]
    NotFound,
    /// Request timeout.
    #[display("Request timeout.")]
    Timeout,
    /// Too many CIDs in a single batch request.
    #[display("Too many CIDs in batch request: max {max}, got {got}.")]
    TooManyCids {
        /// Configured limit.
        max: usize,
        /// Number of CIDs in the rejected request.
        got: usize,
    },
    /// Same CID appears more than once in the input. Two-stage detection: literal-string match,
    /// or two distinct strings decoding to the same content digest.
    #[display("Input contains duplicate CIDs.")]
    DuplicateCids,
}

/// JSON-RPC error categories for `bitswap_v1_get` method.
///
/// Clients should use the error code to determine recovery action,
/// not parse the human-readable message string.
enum BitswapJsonRpcError {
    /// Permanent failure for this request. E.g., there is no requested data in the network.
    /// Doesn't make sense to retry until you put the data on chain.
    Fail = -32810,
    /// Transient failure. Can retry immediately.
    ///
    /// Even though the client can retry immediately, the clients are encouraged to rate-limit the
    /// retry attempts and retry count, e.g. introducing a delay of 50ms between retries.
    FailRetry = -32811,
    /// Transient failure. Retry after a backoff delay.
    ///
    /// The recommended backoff delay is 5s.
    FailRetryBackoff = -32812,
}

impl BitswapGetError {
    /// Build a complete JSON-RPC error response string for this error.
    pub fn to_json_rpc_error(&self, request_id_json: &str) -> String {
        let message = self.to_string();

        // Even though the spec says the error variants like `NoPeers` etc. are not stable and
        // provided for debugging purposes only, any changes to the variant names should be avoided
        // to not surprise anybody.
        let (variant, category) = match self {
            BitswapGetError::InvalidCid(_) => ("InvalidCid", None),
            BitswapGetError::NotFound => ("NotFound", Some(BitswapJsonRpcError::Fail)),
            BitswapGetError::BlockRequestFailed => {
                ("BlockRequestFailed", Some(BitswapJsonRpcError::FailRetry))
            }
            BitswapGetError::Timeout => ("Timeout", Some(BitswapJsonRpcError::FailRetry)),
            BitswapGetError::QueueFull => {
                ("QueueFull", Some(BitswapJsonRpcError::FailRetryBackoff))
            }
            BitswapGetError::NoPeers => ("NoPeers", Some(BitswapJsonRpcError::FailRetryBackoff)),
            BitswapGetError::TooManyCids { .. } => ("TooManyCids", None),
            BitswapGetError::DuplicateCids => ("DuplicateCids", None),
        };

        let data = format!("{{\"variant\":\"{variant}\"}}");

        let error_response = match category {
            None => parse::ErrorResponse::InvalidParams(Some(&message)),
            Some(cat) => parse::ErrorResponse::ApplicationDefined(cat as i64, &message),
        };

        parse::build_error_response(request_id_json, error_response, Some(&data))
    }

    /// Returns the JSON-RPC `(code, message)` pair to embed inside a per-CID `BlockResult::Err`
    /// in `bitswap_v1_getMany` / `bitswap_v1_streamEvent`. The code uses the same four categories
    /// as the top-level error of `bitswap_v1_get`, so callers can reuse retry logic.
    pub fn to_block_result_err(&self) -> (i32, String) {
        const INVALID_PARAMS: i32 = -32602;
        let code = match self {
            BitswapGetError::InvalidCid(_)
            | BitswapGetError::TooManyCids { .. }
            | BitswapGetError::DuplicateCids => INVALID_PARAMS,
            BitswapGetError::NotFound => BitswapJsonRpcError::Fail as i32,
            BitswapGetError::BlockRequestFailed | BitswapGetError::Timeout => {
                BitswapJsonRpcError::FailRetry as i32
            }
            BitswapGetError::QueueFull | BitswapGetError::NoPeers => {
                BitswapJsonRpcError::FailRetryBackoff as i32
            }
        };
        (code, self.to_string())
    }
}

impl From<SendBitswapMessageError> for BitswapGetError {
    fn from(error: SendBitswapMessageError) -> BitswapGetError {
        match error {
            SendBitswapMessageError::NoConnection => BitswapGetError::NoPeers,
            SendBitswapMessageError::QueueFull => BitswapGetError::QueueFull,
        }
    }
}

/// Validates and de-duplicates the input CIDs of `bitswap_v1_getMany` / `bitswap_v1_stream`.
///
/// On success returns one entry per input CID, in input order, preserving the original string and
/// the parse result. Caller-side per-CID `Err(InvalidCid)` reporting is left to the JSON-RPC layer
/// since the spec emits invalid CIDs as per-CID errors rather than aborting the whole call.
///
/// Failure cases (returned as `Err(_)` so the caller emits a top-level JSON-RPC error):
/// * `TooManyCids` if the input exceeds [`MAX_CIDS_PER_REQUEST`].
/// * `DuplicateCids` if two inputs are literally-equal strings, **or** if two valid-but-different
///   strings decode to the same [`Cid`] (digest collision).
pub fn parse_and_dedup(
    cids: Vec<String>,
) -> Result<Vec<(String, Result<Cid, cid::ParseError>)>, BitswapGetError> {
    if cids.len() > MAX_CIDS_PER_REQUEST {
        return Err(BitswapGetError::TooManyCids {
            max: MAX_CIDS_PER_REQUEST,
            got: cids.len(),
        });
    }

    let mut seen_strings: hashbrown::HashSet<String> =
        hashbrown::HashSet::with_capacity(cids.len());
    let mut seen_cids: hashbrown::HashSet<Cid> = hashbrown::HashSet::with_capacity(cids.len());
    let mut out = Vec::with_capacity(cids.len());

    for cid_str in cids {
        if !seen_strings.insert(cid_str.clone()) {
            return Err(BitswapGetError::DuplicateCids);
        }

        let parsed = Cid::from_str(&cid_str);
        if let Ok(c) = &parsed {
            if !seen_cids.insert(c.clone()) {
                return Err(BitswapGetError::DuplicateCids);
            }
        }

        out.push((cid_str, parsed));
    }

    Ok(out)
}

enum ToBackground {
    BitswapBlock {
        cid: Cid,
        result_tx: oneshot::Sender<Result<Vec<u8>, BitswapGetError>>,
    },
    /// Submit a batched request. The service allocates a [`BatchId`], reports it back via
    /// `batch_id_tx`, then issues a single Have broadcast covering all valid input CIDs.
    BitswapBatch {
        /// Validated and de-duplicated entries from [`parse_and_dedup`]. Per-slot `Err` carries
        /// an `InvalidCid` ParseError that gets surfaced as a per-CID error event.
        entries: Vec<(String, Result<Cid, cid::ParseError>)>,
        mode: BatchMode,
        batch_id_tx: oneshot::Sender<BatchId>,
    },
    /// Cancel an in-flight batch. Idempotent: if the batch already finished, this is a no-op.
    CancelBatch {
        batch_id: BatchId,
    },
}

/// Mode of a batched request. `GetMany` collects all outcomes and replies once; `Stream` pushes
/// each outcome to `events_tx` as it becomes available.
enum BatchMode {
    GetMany {
        result_tx: oneshot::Sender<Vec<(String, BlockResult)>>,
    },
    Stream {
        events_tx: async_channel::Sender<(String, BlockResult)>,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct RequestId(u64);

impl RequestId {
    const _MIN: RequestId = RequestId(u64::MIN);
    const MAX: RequestId = RequestId(u64::MAX);
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct BatchId(u64);

#[derive(Debug)]
enum RequestStage {
    /// We are waiting for peers to respond to our "have" request. `HashSet<PeerId>` are the peers
    /// we sent the "have" request to.
    Have(hashbrown::HashSet<PeerId, util::SipHasherBuild>),
    /// At least one peer has responded to a "have" request and we requested the data from it.
    Block,
}

/// Per-request output destination. A request resolves into either a single oneshot reply
/// (for `bitswap_get`) or a slot of a `Batch` (for `bitswap_get_many` / `bitswap_stream`).
#[derive(Debug)]
enum SlotOutput {
    Single(oneshot::Sender<Result<Vec<u8>, BitswapGetError>>),
    Batch { batch_id: BatchId, slot_idx: usize },
}

#[derive(Debug)]
struct Request<TPlat: PlatformRef> {
    result_tx: SlotOutput,
    timeout: TPlat::Instant,
    stage: RequestStage,
    cid: Cid,
}

/// State for an in-flight batch. Allocated when `BitswapBatch` is received and removed once all
/// slots have been resolved (or the batch is explicitly cancelled).
struct Batch {
    mode: BatchMode,
    /// Per-slot CID strings, indexed by slot index. Echoed back in outcomes/events.
    cid_strs: Vec<String>,
    /// `Some(RequestId)` while a slot is in-flight; `None` once the slot has been resolved.
    /// Invalid-CID slots start as `None` (resolved synchronously when the batch is created).
    slots: Vec<Option<RequestId>>,
    /// Per-slot collected outcomes. For `BatchMode::GetMany` this fills in until `pending_count`
    /// reaches zero, then is drained into the response. For `BatchMode::Stream` outcomes go
    /// directly to `events_tx` and these slots stay `None` (kept allocated to mirror `cid_strs`
    /// for diagnostic readability — checked by `pending_count`).
    outcomes: Vec<Option<BlockResult>>,
    /// Peers we sent this batch's Have broadcast to. Used to address Cancel wantlist on
    /// `CancelBatch`. Empty until `HaveBroadcastResult` arrives successfully.
    peers_for_cancel: Vec<PeerId>,
    /// Number of slots still pending resolution. When this reaches zero, finalize the batch.
    pending_count: usize,
}

/// Outcome of an issued Have broadcast. Carries enough context to either finalize a single
/// request or register N sub-requests for a batch.
enum HaveContext {
    Single {
        cid: Cid,
        result_tx: oneshot::Sender<Result<Vec<u8>, BitswapGetError>>,
    },
    Batch {
        batch_id: BatchId,
        /// Valid (slot_idx, cid) pairs. Invalid-CID slots are pre-resolved before the broadcast
        /// is queued and don't appear here.
        cids: Vec<(usize, Cid)>,
    },
}

type HaveBroadcastResult = (Result<Vec<PeerId>, SendBitswapMessageError>, HaveContext);

struct BackgroundTask<TPlat: PlatformRef> {
    /// Log target.
    log_target: String,
    /// Messages from [`BitswapService`].
    messages_rx: Pin<Box<async_channel::Receiver<ToBackground>>>,
    /// Underlying network to send/receive Bitswap messages.
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
    /// Events coming from the network service. `None` if not subscribed yet.
    from_network_service: Option<Pin<Box<async_channel::Receiver<network_service::BitswapEvent>>>>,
    /// Initiated Bitswap "have" broadcast.
    // TODO: consider handling more than one have broadcast at a time to not backpressure the RPC
    // layer.
    pending_have_broadcast:
        Option<Pin<Box<dyn Future<Output = HaveBroadcastResult> + Send + Sync>>>,
    /// Initiated Bitswap "block" requests.
    pending_block_requests: FuturesUnordered<
        Pin<Box<dyn Future<Output = (Result<(), SendBitswapMessageError>, Cid)> + Send + Sync>>,
    >,
    /// Platform access.
    platform: TPlat,
    /// Next request ID to use.
    next_request_id_inner: u64,
    /// Next batch ID to use.
    next_batch_id_inner: u64,
    /// RNG.
    randomness: rand_chacha::ChaCha20Rng,

    // The fields below are populated if the broadcast of the "have" message was successfully
    // forwarded to the network. Request is tracked from this moment until the requested data is
    // received or the request time-outs.
    //
    /// All tracked requests.
    requests: hashbrown::HashMap<RequestId, Request<TPlat>, fnv::FnvBuildHasher>,
    /// Requests ordered by timeout.
    requests_by_timeout: BTreeSet<(TPlat::Instant, RequestId)>,
    /// Requests ordered by CID. The request IDs in the `VecDeque` are ordered by their timeout if
    /// the platform implementation of `now` is monothonic (true for
    /// [`crate::platform::DefaultPlatform`]).
    requests_by_cid: hashbrown::HashMap<Cid, VecDeque<RequestId>, util::SipHasherBuild>,
    /// In-flight batches. Each entry corresponds to a `bitswap_get_many` / `bitswap_stream` call.
    batches: hashbrown::HashMap<BatchId, Batch, fnv::FnvBuildHasher>,
}

impl<TPlat: PlatformRef> BackgroundTask<TPlat> {
    fn allocate_request_id(&mut self) -> RequestId {
        let request_id = RequestId(self.next_request_id_inner);
        self.next_request_id_inner += 1;

        request_id
    }

    fn allocate_batch_id(&mut self) -> BatchId {
        let batch_id = BatchId(self.next_batch_id_inner);
        self.next_batch_id_inner += 1;
        batch_id
    }

    /// Final disposition of a single request slot. Routes the resolution either to the original
    /// `bitswap_get` caller (`Single`) or to the owning batch (`Batch`).
    fn deliver_slot(&mut self, slot_output: SlotOutput, result: Result<Vec<u8>, BitswapGetError>) {
        match slot_output {
            SlotOutput::Single(tx) => {
                let _ = tx.send(result);
            }
            SlotOutput::Batch { batch_id, slot_idx } => {
                self.deliver_batch_slot(batch_id, slot_idx, result);
            }
        }
    }

    /// Deliver one resolved slot to its owning batch and finalize the batch if all slots are now
    /// resolved.
    fn deliver_batch_slot(
        &mut self,
        batch_id: BatchId,
        slot_idx: usize,
        result: Result<Vec<u8>, BitswapGetError>,
    ) {
        let block_result = match result {
            Ok(data) => BlockResult::Ok(data),
            Err(e) => BlockResult::Err(e),
        };

        // Touch state in two passes so we can release the borrow before potentially calling
        // `cancel_batch` (which also borrows `self.batches`).
        let (cid_str, should_cancel, should_finalize) = {
            let Some(batch) = self.batches.get_mut(&batch_id) else {
                // The batch was already finalized or cancelled; the resolution is stale.
                return;
            };

            // Mark this slot as no longer in-flight regardless of mode.
            batch.slots[slot_idx] = None;
            batch.pending_count = batch.pending_count.saturating_sub(1);

            let cid_str = batch.cid_strs[slot_idx].clone();
            let mut should_cancel = false;

            match &mut batch.mode {
                BatchMode::Stream { events_tx } => {
                    match events_tx.try_send((cid_str.clone(), block_result)) {
                        Ok(()) => {}
                        Err(async_channel::TrySendError::Closed(_)) => {
                            // Receiver dropped — JSON-RPC client disconnected or unsubscribed.
                            // Cancel the rest of the batch and emit a Bitswap Cancel wantlist.
                            should_cancel = true;
                        }
                        Err(async_channel::TrySendError::Full(_)) => {
                            // Bounded channel saturated. With a `bounded(MAX_CIDS_PER_REQUEST)`
                            // channel and a JSON-RPC pump that drains it eagerly this should be
                            // unreachable in practice. Log and drop the event rather than
                            // blocking the service.
                            log!(
                                &self.platform,
                                Warn,
                                &self.log_target,
                                "stream events channel full, dropping per-CID event"
                            );
                        }
                    }
                }
                BatchMode::GetMany { .. } => {
                    batch.outcomes[slot_idx] = Some(block_result);
                }
            }

            let should_finalize = !should_cancel && batch.pending_count == 0;
            (cid_str, should_cancel, should_finalize)
        };
        let _ = cid_str;

        if should_cancel {
            self.cancel_batch(batch_id);
        } else if should_finalize {
            self.finalize_batch(batch_id);
        }
    }

    /// Finalize a batch whose slots have all been resolved. Drains accumulated outcomes for
    /// `GetMany` mode and closes the events channel for `Stream` mode.
    fn finalize_batch(&mut self, batch_id: BatchId) {
        let Some(batch) = self.batches.remove(&batch_id) else {
            return;
        };
        debug_assert_eq!(batch.pending_count, 0);

        match batch.mode {
            BatchMode::GetMany { result_tx } => {
                let mut out = Vec::with_capacity(batch.cid_strs.len());
                for (cid_str, outcome) in batch.cid_strs.into_iter().zip(batch.outcomes.into_iter())
                {
                    out.push((
                        cid_str,
                        outcome.expect("pending_count == 0 implies all slots resolved; qed"),
                    ));
                }
                let _ = result_tx.send(out);
            }
            BatchMode::Stream { events_tx } => {
                // Dropping the sender closes the channel. The JSON-RPC pump task will see the
                // channel close and end its loop after the last event has been delivered.
                drop(events_tx);
            }
        }
    }

    /// Cancel a batch: tear down all its still-pending slots, then send a Bitswap Cancel wantlist
    /// to every peer we contacted on its behalf. Idempotent.
    fn cancel_batch(&mut self, batch_id: BatchId) {
        let Some(batch) = self.batches.remove(&batch_id) else {
            return;
        };

        // Walk pending slots, evict their `RequestId`s from the global tracking maps, and gather
        // the CIDs to be cancelled on the wire.
        let mut pending_cids: Vec<Cid> = Vec::new();
        for slot in batch.slots.into_iter() {
            let Some(request_id) = slot else { continue };
            let Some(request) = self.requests.remove(&request_id) else {
                continue;
            };
            let _ = self
                .requests_by_timeout
                .remove(&(request.timeout, request_id));

            if let hashbrown::hash_map::Entry::Occupied(mut entry) =
                self.requests_by_cid.entry(request.cid.clone())
            {
                entry.get_mut().retain(|id| *id != request_id);
                if entry.get().is_empty() {
                    entry.remove();
                }
            }

            pending_cids.push(request.cid);
        }

        if pending_cids.is_empty() || batch.peers_for_cancel.is_empty() {
            return;
        }

        // One Cancel wantlist message containing all pending CIDs, sent to every peer this
        // batch's Have broadcast reached. Cancel for an unknown CID is harmless on the receiver
        // side — the peer no-ops.
        let message = build_bitswap_cancel_message(pending_cids.iter());

        for peer in batch.peers_for_cancel {
            let network_service = self.network_service.clone();
            let msg = message.clone();
            // Fire-and-forget. Cancel is best-effort and does not need to be awaited; if it
            // fails the peer will eventually expire its want-list state on its own.
            self.platform.spawn_task(self.log_target.clone().into(), async move {
                let _ = network_service.send_bitswap_message(peer, msg).await;
            });
        }
    }
}

fn bitswap_have_message(cid: &Cid) -> Vec<u8> {
    build_bitswap_message(iter::once(cid), WantType::Have, true, false)
}

fn bitswap_block_message(cid: &Cid) -> Vec<u8> {
    build_bitswap_message(iter::once(cid), WantType::Block, false, false)
}

async fn background_task<TPlat: PlatformRef>(mut task: BackgroundTask<TPlat>) {
    loop {
        // Make sure to yield at every loop to provide better tasks granularity.
        futures_lite::future::yield_now().await;

        enum WakeUpReason {
            MustSubscribeNetworkEvents,
            NetworkEvent(network_service::BitswapEvent),
            Message(ToBackground),
            HaveBroadcastResult(HaveBroadcastResult),
            BlockRequestResult((Result<(), SendBitswapMessageError>, Cid)),
            RequestTimeout,
            ForegroundClosed,
        }

        let wake_up_reason = {
            let backpressure_messages = task.pending_have_broadcast.is_some();

            async {
                if let Some(from_network_service) = task.from_network_service.as_mut() {
                    match from_network_service.next().await {
                        Some(ev) => WakeUpReason::NetworkEvent(ev),
                        None => {
                            task.from_network_service = None;
                            WakeUpReason::MustSubscribeNetworkEvents
                        }
                    }
                } else {
                    WakeUpReason::MustSubscribeNetworkEvents
                }
            }
            .or(async {
                if !backpressure_messages {
                    task.messages_rx
                        .next()
                        .await
                        .map_or(WakeUpReason::ForegroundClosed, WakeUpReason::Message)
                } else {
                    future::pending().await
                }
            })
            .or(async {
                if let Some(pending_have_broadcast) = &mut task.pending_have_broadcast {
                    let result = pending_have_broadcast.await;
                    task.pending_have_broadcast = None;
                    WakeUpReason::HaveBroadcastResult(result)
                } else {
                    future::pending().await
                }
            })
            .or(async {
                if !task.pending_block_requests.is_empty() {
                    let result = task
                        .pending_block_requests
                        .next()
                        .await
                        .expect("non-empty; qed");
                    WakeUpReason::BlockRequestResult(result)
                } else {
                    future::pending().await
                }
            })
            .or(async {
                if let Some((first_timeout, _request_id)) = task.requests_by_timeout.first() {
                    let now = task.platform.now();

                    if now < *first_timeout {
                        task.platform.sleep(first_timeout.clone() - now).await;
                    }

                    WakeUpReason::RequestTimeout
                } else {
                    future::pending().await
                }
            })
            .await
        };

        // The handlers below are mostly in the order of a typical flow.
        match wake_up_reason {
            WakeUpReason::MustSubscribeNetworkEvents => {
                debug_assert!(task.from_network_service.is_none());
                task.from_network_service = Some(Box::pin(
                    // As documented, `subscribe().await` is expected to return quickly.
                    task.network_service.subscribe_bitswap().await,
                ));
            }
            WakeUpReason::Message(ToBackground::BitswapBlock { cid, result_tx }) => {
                debug_assert!(task.pending_have_broadcast.is_none());

                let message = bitswap_have_message(&cid);
                let network_service = task.network_service.clone();

                // TODO: does it make sense to group the new request with the existing ones for the
                //       same CID and don't actually broadcast the "have" request?

                // Network service can be back-pressuring, so we run this in the background.
                task.pending_have_broadcast = Some(Box::pin(async move {
                    let result = network_service.broadcast_bitswap_message(message).await;
                    (result, HaveContext::Single { cid, result_tx })
                }));
            }
            WakeUpReason::Message(ToBackground::BitswapBatch {
                entries,
                mode,
                batch_id_tx,
            }) => {
                debug_assert!(task.pending_have_broadcast.is_none());

                // Allocate the batch up front and report the BatchId back so the caller's RAII
                // cancel guard can address us if the call is dropped before resolution.
                let batch_id = task.allocate_batch_id();
                let _ = batch_id_tx.send(batch_id);

                let total = entries.len();
                let mut cid_strs: Vec<String> = Vec::with_capacity(total);
                let mut slots: Vec<Option<RequestId>> = Vec::with_capacity(total);
                let mut outcomes: Vec<Option<BlockResult>> = Vec::with_capacity(total);
                // Slots whose CID parsed successfully — these will have their RequestId set
                // after the Have broadcast lands. (slot_idx, cid).
                let mut valid_cids: Vec<(usize, Cid)> = Vec::with_capacity(total);
                // Slots whose CID failed to parse — pre-resolve as `InvalidCid` per spec.
                // (slot_idx, cid_str, err).
                let mut invalid_slots: Vec<(usize, String, BitswapGetError)> = Vec::new();

                for (slot_idx, (cid_str, parsed)) in entries.into_iter().enumerate() {
                    cid_strs.push(cid_str.clone());
                    slots.push(None);
                    outcomes.push(None);
                    match parsed {
                        Ok(c) => valid_cids.push((slot_idx, c)),
                        Err(e) => {
                            invalid_slots.push((slot_idx, cid_str, BitswapGetError::InvalidCid(e)));
                        }
                    }
                }

                let mut batch = Batch {
                    mode,
                    cid_strs,
                    slots,
                    outcomes,
                    peers_for_cancel: Vec::new(),
                    pending_count: total,
                };

                // Pre-resolve invalid-CID slots. For Stream we push events immediately; for
                // GetMany we accumulate in `outcomes`.
                for (slot_idx, cid_str, err) in invalid_slots {
                    batch.pending_count -= 1;
                    let block_result = BlockResult::Err(err);
                    match &mut batch.mode {
                        BatchMode::Stream { events_tx } => {
                            let _ = events_tx.try_send((cid_str, block_result));
                        }
                        BatchMode::GetMany { .. } => {
                            batch.outcomes[slot_idx] = Some(block_result);
                        }
                    }
                }

                // Insert the batch before the broadcast: if the caller drops mid-await and a
                // CancelBatch arrives, it must find an entry to cancel.
                task.batches.insert(batch_id, batch);

                if valid_cids.is_empty() {
                    // No wire I/O needed. If everything resolved (all-invalid case), finalize
                    // immediately. If empty input slipped through somehow, also finalize.
                    if task
                        .batches
                        .get(&batch_id)
                        .map_or(true, |b| b.pending_count == 0)
                    {
                        task.finalize_batch(batch_id);
                    }
                    continue;
                }

                let message = build_bitswap_message(
                    valid_cids.iter().map(|(_, c)| c),
                    WantType::Have,
                    true,
                    false,
                );
                let network_service = task.network_service.clone();
                task.pending_have_broadcast = Some(Box::pin(async move {
                    let result = network_service.broadcast_bitswap_message(message).await;
                    (
                        result,
                        HaveContext::Batch {
                            batch_id,
                            cids: valid_cids,
                        },
                    )
                }));
            }
            WakeUpReason::Message(ToBackground::CancelBatch { batch_id }) => {
                task.cancel_batch(batch_id);
            }
            WakeUpReason::HaveBroadcastResult((result, ctx)) => match ctx {
                HaveContext::Single { cid, result_tx } => {
                    let broadcast_to = match result {
                        Ok(peers) => peers,
                        Err(err) => {
                            let _ = result_tx.send(Err(err.into()));
                            continue;
                        }
                    };

                    let request_id = task.allocate_request_id();
                    let timeout = task.platform.now() + Duration::from_secs(10);

                    let have_peers = {
                        let mut have_peers = hashbrown::HashSet::with_capacity_and_hasher(
                            broadcast_to.len(),
                            util::SipHasherBuild::new({
                                let mut seed = [0; 16];
                                task.randomness.fill_bytes(&mut seed);
                                seed
                            }),
                        );
                        have_peers.extend(broadcast_to.into_iter());
                        have_peers
                    };

                    task.requests.insert(
                        request_id,
                        Request {
                            result_tx: SlotOutput::Single(result_tx),
                            timeout: timeout.clone(),
                            stage: RequestStage::Have(have_peers),
                            cid: cid.clone(),
                        },
                    );
                    task.requests_by_timeout.insert((timeout, request_id));
                    task.requests_by_cid
                        .entry(cid)
                        .or_default()
                        .push_back(request_id);
                }
                HaveContext::Batch { batch_id, cids } => {
                    let broadcast_to = match result {
                        Ok(peers) => peers,
                        Err(err) => {
                            // Whole-broadcast failure: every still-pending slot fails with the
                            // same error. We resolve them via `deliver_batch_slot` so that
                            // Stream events fire and GetMany finalizes at zero.
                            let bsw_err: BitswapGetError = err.into();
                            for (slot_idx, _) in cids {
                                task.deliver_batch_slot(
                                    batch_id,
                                    slot_idx,
                                    Err(bsw_err.clone()),
                                );
                            }
                            continue;
                        }
                    };

                    if let Some(batch) = task.batches.get_mut(&batch_id) {
                        batch.peers_for_cancel = broadcast_to.clone();
                    } else {
                        // The batch was cancelled while we were broadcasting. Don't bother
                        // registering per-CID requests; the cancel handler will have cleaned up
                        // any state already, and we have nothing to track.
                        continue;
                    }

                    // Register one Request per valid slot, sharing the same Have peer set.
                    let timeout = task.platform.now() + Duration::from_secs(10);
                    for (slot_idx, cid) in cids {
                        let request_id = task.allocate_request_id();
                        let have_peers = {
                            let mut have_peers = hashbrown::HashSet::with_capacity_and_hasher(
                                broadcast_to.len(),
                                util::SipHasherBuild::new({
                                    let mut seed = [0; 16];
                                    task.randomness.fill_bytes(&mut seed);
                                    seed
                                }),
                            );
                            have_peers.extend(broadcast_to.iter().cloned());
                            have_peers
                        };

                        task.requests.insert(
                            request_id,
                            Request {
                                result_tx: SlotOutput::Batch { batch_id, slot_idx },
                                timeout: timeout.clone(),
                                stage: RequestStage::Have(have_peers),
                                cid: cid.clone(),
                            },
                        );
                        task.requests_by_timeout.insert((timeout.clone(), request_id));
                        task.requests_by_cid
                            .entry(cid)
                            .or_default()
                            .push_back(request_id);

                        if let Some(batch) = task.batches.get_mut(&batch_id) {
                            batch.slots[slot_idx] = Some(request_id);
                        }
                    }
                }
            },
            WakeUpReason::NetworkEvent(BitswapEvent::BitswapMessage { peer_id, message }) => {
                let message = message.decode();

                // Slots that have just resolved and need to be delivered after the per-block-
                // presence borrow on `task.requests_by_cid` is released.
                let mut deliveries: Vec<(SlotOutput, Result<Vec<u8>, BitswapGetError>)> = Vec::new();

                for BlockPresence { cid, presence_type } in message.block_presences {
                    let cid = match Cid::from_bytes(cid.to_owned()) {
                        Ok(cid) => cid,
                        Err(error) => {
                            log!(
                                &task.platform,
                                Debug,
                                &task.log_target,
                                "error decoding CID",
                                peer_id,
                                error,
                            );
                            // TODO: Discard entire message? Ban peer? On what errors?
                            continue;
                        }
                    };

                    let hashbrown::hash_map::Entry::Occupied(mut entry) =
                        task.requests_by_cid.entry(cid.clone())
                    else {
                        log!(
                            &task.platform,
                            Trace,
                            &task.log_target,
                            "stale/unsolicited have response",
                            peer_id
                        );
                        continue;
                    };

                    let mut needs_block_request = false;
                    let request_ids = entry.get_mut();

                    for i in (0..request_ids.len()).rev() {
                        let request_id = request_ids[i];
                        let request = task.requests.get_mut(&request_id).unwrap();

                        match (&mut request.stage, presence_type) {
                            (RequestStage::Have(peers), BlockPresenceType::Have) => {
                                if peers.contains(&peer_id) {
                                    request.stage = RequestStage::Block;
                                    needs_block_request = true;
                                }
                            }
                            (RequestStage::Have(peers), BlockPresenceType::DontHave) => {
                                let _ = peers.remove(&peer_id);
                                if peers.is_empty() {
                                    // All peers responded "don't have", fail request.
                                    // Normally we shouldn't have more than one request per CID.
                                    request_ids.remove(i);
                                    let request = task.requests.remove(&request_id).unwrap();
                                    let _was_in = task
                                        .requests_by_timeout
                                        .remove(&(request.timeout, request_id));
                                    debug_assert!(_was_in);

                                    // Defer delivery: dispatching now would re-borrow `task` while
                                    // we still hold `entry` on `task.requests_by_cid`.
                                    deliveries
                                        .push((request.result_tx, Err(BitswapGetError::NotFound)));
                                }
                            }
                            (RequestStage::Block, _) => {}
                        }

                        // TODO: if at least one request above is in the `Block` stage
                        //       already, does this mean we can skip sending another
                        //       "block" request?
                    }

                    if entry.get().is_empty() {
                        entry.remove();
                    }

                    if needs_block_request {
                        let message = bitswap_block_message(&cid);
                        let network_service = task.network_service.clone();
                        let peer_id = peer_id.clone();

                        task.pending_block_requests.push(Box::pin(async move {
                            let result =
                                network_service.send_bitswap_message(peer_id, message).await;
                            (result, cid)
                        }));
                    }
                }

                for Block { prefix, data } in message.payload {
                    let prefix = match CidPrefix::from_bytes(prefix.to_owned()) {
                        Ok(prefix) => prefix,
                        Err(error) => {
                            log!(
                                &task.platform,
                                Debug,
                                &task.log_target,
                                "error decoding CID prefix",
                                peer_id,
                                error,
                            );
                            // TODO: ban peer? On what errors?
                            continue;
                        }
                    };

                    let cid = prefix.with_digest_of(data);

                    // Respond to requests asking for this CID regardless of the request stage and
                    // remove these requests from internal structures.
                    if let Some(request_ids) = task.requests_by_cid.remove(&cid) {
                        for request_id in request_ids {
                            let request = task.requests.remove(&request_id).unwrap();
                            let _was_in = task
                                .requests_by_timeout
                                .remove(&(request.timeout, request_id));
                            debug_assert!(_was_in);

                            task.deliver_slot(request.result_tx, Ok(data.to_owned()));
                        }
                    }
                }

                // Dispatch deferred deliveries from the block_presences loop.
                for (slot_output, result) in deliveries {
                    task.deliver_slot(slot_output, result);
                }
            }
            WakeUpReason::BlockRequestResult((result, cid)) => {
                // We either succeeded or failed in sending the "block" request.
                // Nothing to do on success, but we must respond to requests & cleanup on failure.
                if let Err(err) = result {
                    // Requests might have timed out while we were waiting for a response from
                    // network service.
                    if let Some(request_ids) = task.requests_by_cid.remove(&cid) {
                        let err = match err {
                            SendBitswapMessageError::QueueFull => BitswapGetError::QueueFull,
                            SendBitswapMessageError::NoConnection => {
                                BitswapGetError::BlockRequestFailed
                            }
                        };

                        for request_id in request_ids {
                            let request = task.requests.remove(&request_id).unwrap();
                            let _was_in = task
                                .requests_by_timeout
                                .remove(&(request.timeout, request_id));
                            debug_assert!(_was_in);

                            task.deliver_slot(request.result_tx, Err(err.clone()));
                        }
                    }
                }
            }
            WakeUpReason::RequestTimeout => {
                let now = task.platform.now();

                let requests = task
                    .requests_by_timeout
                    .range(..=(now, RequestId::MAX))
                    .cloned()
                    .collect::<Vec<_>>();

                for (timeout, request_id) in requests {
                    task.requests_by_timeout.remove(&(timeout, request_id));

                    let request = task.requests.remove(&request_id).unwrap();

                    match task.requests_by_cid.entry(request.cid) {
                        hashbrown::hash_map::Entry::Occupied(mut entry) => {
                            // The next request to timeout should be always at the front of the
                            // queue, but in order to be resistant to platform bugs where `now` is
                            // not monothonic (and requests are ordered incorrectly), we use find &
                            // remove. It should be almost as fast as `pop_front` if the element is
                            // indeed at the front.
                            let (index, _) = entry
                                .get()
                                .iter()
                                .find_position(|id| **id == request_id)
                                .unwrap();
                            entry.get_mut().remove(index);

                            if entry.get().is_empty() {
                                entry.remove();
                            }
                        }
                        hashbrown::hash_map::Entry::Vacant(_) => unreachable!(),
                    }

                    task.deliver_slot(request.result_tx, Err(BitswapGetError::Timeout));
                }
            }
            WakeUpReason::ForegroundClosed => {
                // Foreground closed the control channel, end the task.
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the error code from the JSON-RPC error response string.
    fn extract_error_code(json: &str) -> i64 {
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        parsed["error"]["code"].as_i64().unwrap()
    }

    /// Parse the data.variant field from the JSON-RPC error response string.
    fn extract_variant(json: &str) -> String {
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        parsed["error"]["data"]["variant"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn error_invalid_cid_maps_to_invalid_params() {
        let err = BitswapGetError::InvalidCid(Cid::from_str("not-a-cid").unwrap_err());
        let json = err.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32602); // InvalidParams
        assert_eq!(extract_variant(&json), "InvalidCid");
    }

    #[test]
    fn error_not_found_maps_to_fail() {
        let json = BitswapGetError::NotFound.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32810); // Fail
        assert_eq!(extract_variant(&json), "NotFound");
    }

    #[test]
    fn error_block_request_failed_maps_to_fail_retry() {
        let json = BitswapGetError::BlockRequestFailed.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32811); // FailRetry
        assert_eq!(extract_variant(&json), "BlockRequestFailed");
    }

    #[test]
    fn error_timeout_maps_to_fail_retry() {
        let json = BitswapGetError::Timeout.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32811); // FailRetry
        assert_eq!(extract_variant(&json), "Timeout");
    }

    #[test]
    fn error_queue_full_maps_to_fail_retry_backoff() {
        let json = BitswapGetError::QueueFull.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32812); // FailRetryBackoff
        assert_eq!(extract_variant(&json), "QueueFull");
    }

    #[test]
    fn error_no_peers_maps_to_fail_retry_backoff() {
        let json = BitswapGetError::NoPeers.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32812); // FailRetryBackoff
        assert_eq!(extract_variant(&json), "NoPeers");
    }

    #[test]
    fn error_response_is_valid_jsonrpc() {
        let json = BitswapGetError::NotFound.to_json_rpc_error("42");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 42);
        assert!(parsed["error"]["message"].is_string());
    }

    #[test]
    fn from_send_error_no_connection() {
        let err: BitswapGetError = SendBitswapMessageError::NoConnection.into();
        assert!(matches!(err, BitswapGetError::NoPeers));
    }

    #[test]
    fn from_send_error_queue_full() {
        let err: BitswapGetError = SendBitswapMessageError::QueueFull.into();
        assert!(matches!(err, BitswapGetError::QueueFull));
    }

    #[test]
    fn error_too_many_cids_maps_to_invalid_params() {
        let err = BitswapGetError::TooManyCids { max: 64, got: 100 };
        let json = err.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32602);
        assert_eq!(extract_variant(&json), "TooManyCids");
    }

    #[test]
    fn error_duplicate_cids_maps_to_invalid_params() {
        let json = BitswapGetError::DuplicateCids.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32602);
        assert_eq!(extract_variant(&json), "DuplicateCids");
    }

    #[test]
    fn block_result_err_codes_match_top_level_codes() {
        // Per spec, per-CID error codes use the same retry categories as `bitswap_v1_get`.
        assert_eq!(BitswapGetError::NotFound.to_block_result_err().0, -32810);
        assert_eq!(BitswapGetError::Timeout.to_block_result_err().0, -32811);
        assert_eq!(
            BitswapGetError::BlockRequestFailed.to_block_result_err().0,
            -32811
        );
        assert_eq!(BitswapGetError::QueueFull.to_block_result_err().0, -32812);
        assert_eq!(BitswapGetError::NoPeers.to_block_result_err().0, -32812);
        // Invalid CIDs surface as -32602 InvalidParams per the spec.
        assert_eq!(
            BitswapGetError::InvalidCid(Cid::from_str("not-a-cid").unwrap_err())
                .to_block_result_err()
                .0,
            -32602
        );
    }

    /// A known-valid CIDv1 in base32 multibase encoding (sha2-256 over an empty input).
    const VALID_CID_A: &str = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
    const VALID_CID_B: &str = "bafkreigh2akiscaildc3rdvuwhszwgrtgvybsh7lhxavhgqitanwh4kc6q";

    #[test]
    fn parse_and_dedup_empty_input_is_ok() {
        let out = parse_and_dedup(vec![]).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn parse_and_dedup_happy_path() {
        let out = parse_and_dedup(vec![VALID_CID_A.into(), VALID_CID_B.into()]).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, VALID_CID_A);
        assert!(out[0].1.is_ok());
        assert_eq!(out[1].0, VALID_CID_B);
        assert!(out[1].1.is_ok());
    }

    #[test]
    fn parse_and_dedup_preserves_invalid_inputs_per_slot() {
        // Invalid-but-unique strings must not abort the call — they surface as per-CID `Err` later.
        let out = parse_and_dedup(vec![
            VALID_CID_A.into(),
            "garbage".into(),
            VALID_CID_B.into(),
        ])
        .unwrap();
        assert_eq!(out.len(), 3);
        assert!(out[0].1.is_ok());
        assert!(out[1].1.is_err());
        assert!(out[2].1.is_ok());
    }

    #[test]
    fn parse_and_dedup_rejects_literal_string_duplicate() {
        // Stage 1: identical input strings, both garbage. Caught before parsing.
        let err = parse_and_dedup(vec!["garbage".into(), "garbage".into()]).unwrap_err();
        assert!(matches!(err, BitswapGetError::DuplicateCids));
    }

    #[test]
    fn parse_and_dedup_rejects_valid_string_duplicate() {
        // Stage 1: identical valid CID strings.
        let err = parse_and_dedup(vec![VALID_CID_A.into(), VALID_CID_A.into()]).unwrap_err();
        assert!(matches!(err, BitswapGetError::DuplicateCids));
    }

    #[test]
    fn parse_and_dedup_rejects_too_many_cids() {
        let cids = (0..MAX_CIDS_PER_REQUEST + 1)
            .map(|_| VALID_CID_A.into())
            .collect();
        let err = parse_and_dedup(cids).unwrap_err();
        assert!(matches!(
            err,
            BitswapGetError::TooManyCids { max: MAX_CIDS_PER_REQUEST, got } if got == MAX_CIDS_PER_REQUEST + 1
        ));
    }

    #[test]
    fn parse_and_dedup_accepts_max_size() {
        let cids: Vec<String> = (0..MAX_CIDS_PER_REQUEST).map(|i| format!("invalid-{i}")).collect();
        let out = parse_and_dedup(cids).unwrap();
        assert_eq!(out.len(), MAX_CIDS_PER_REQUEST);
    }
}
