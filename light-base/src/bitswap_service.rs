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
//! `bitswap_unstable_get(cid)` and `bitswap_unstable_stream(cids)`.
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

/// Maximum number of CIDs accepted in a single `bitswap_unstable_stream` call.
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

    /// Subscribe to a stream of Bitswap blocks. On success, returns a [`BitswapStreamHandle`]
    /// whose `events_rx` yields one `(cid_string, BlockResult)` event per input CID, in arrival
    /// order (the order in which each CID resolves), not input order.
    ///
    /// Top-level errors:
    /// - `-32801 TooManyCids`, `-32802 EmptyCids`, `-32803 DuplicateCids`: batch-input
    ///   validation, surfaced before any subscription state is created.
    /// - `-32812 FailRetryBackoff`: wholesale Have-broadcast failure at subscription-open time
    ///   (no Bitswap peers connected, or network send queue full).
    ///
    /// Per-CID failures observed *after* the subscription has opened (e.g. all peers
    /// disconnect mid-stream, individual `Block` request errors) still surface as
    /// `streamItemError` events, as per the spec.
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
        let (ready_tx, ready_rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::BitswapBatch {
                entries,
                events_tx,
                ready_tx,
            })
            .await
            .unwrap();

        let batch_id = ready_rx.await.unwrap()?;

        Ok(BitswapStreamHandle {
            events_rx,
            _cancel_guard: BatchCancelGuard {
                batch_id,
                messages_tx: self.messages_tx.clone(),
            },
        })
    }
}

/// Per-CID outcome of [`BitswapService::bitswap_stream`].
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

/// Internal RAII guard that fires `ToBackground::CancelBatch` on drop. Held by
/// [`BitswapStreamHandle`] (covers explicit unsubscribe and client disconnect).
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
    /// Input array is empty.
    #[display("Input array is empty.")]
    EmptyCids,
    /// Same CID appears more than once in the input. Two-stage detection: literal-string match,
    /// or two distinct strings decoding to the same content digest.
    #[display("Input contains duplicate CIDs.")]
    DuplicateCids,
}

/// JSON-RPC error codes used by the `bitswap_*` namespace.
///
/// Clients should use the numeric code to determine recovery action, not parse the
/// human-readable message string. Top-level batch-input validation codes
/// (`TooManyCids`, `EmptyCids`, `DuplicateCids`) only appear as top-level errors of
/// `bitswap_unstable_stream`. Per-request/per-event codes (`Fail`, `FailRetry`,
/// `FailRetryBackoff`) appear both as the top-level error of `bitswap_unstable_get`
/// and inside `streamItemError` events.
enum BitswapJsonRpcError {
    /// Batch-input validation: `cids.len()` exceeds the implementation maximum.
    TooManyCids = -32801,
    /// Batch-input validation: `cids` is empty.
    EmptyCids = -32802,
    /// Batch-input validation: duplicate CID in input.
    DuplicateCids = -32803,
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

        let error_response = match self {
            BitswapGetError::InvalidCid(_) => parse::ErrorResponse::InvalidParams(Some(&message)),
            BitswapGetError::NotFound => {
                parse::ErrorResponse::ApplicationDefined(BitswapJsonRpcError::Fail as i64, &message)
            }
            BitswapGetError::BlockRequestFailed | BitswapGetError::Timeout => {
                parse::ErrorResponse::ApplicationDefined(
                    BitswapJsonRpcError::FailRetry as i64,
                    &message,
                )
            }
            BitswapGetError::QueueFull | BitswapGetError::NoPeers => {
                parse::ErrorResponse::ApplicationDefined(
                    BitswapJsonRpcError::FailRetryBackoff as i64,
                    &message,
                )
            }
            BitswapGetError::TooManyCids { .. } => parse::ErrorResponse::ApplicationDefined(
                BitswapJsonRpcError::TooManyCids as i64,
                &message,
            ),
            BitswapGetError::EmptyCids => parse::ErrorResponse::ApplicationDefined(
                BitswapJsonRpcError::EmptyCids as i64,
                &message,
            ),
            BitswapGetError::DuplicateCids => parse::ErrorResponse::ApplicationDefined(
                BitswapJsonRpcError::DuplicateCids as i64,
                &message,
            ),
        };

        parse::build_error_response(request_id_json, error_response, None)
    }

    /// Returns the JSON-RPC `(code, message)` pair to embed inside a per-CID `streamItemError`
    /// event of `bitswap_unstable_streamEvent`. The code uses the same retry categories as the
    /// top-level error of `bitswap_unstable_get`, so callers can reuse retry logic.
    ///
    /// The top-level batch-validation variants (`TooManyCids`, `EmptyCids`, `DuplicateCids`)
    /// never appear per-event — they reject the subscription before any event is emitted.
    pub fn to_block_result_err(&self) -> (i32, String) {
        const INVALID_PARAMS: i32 = -32602;
        let code = match self {
            BitswapGetError::InvalidCid(_) => INVALID_PARAMS,
            BitswapGetError::NotFound => BitswapJsonRpcError::Fail as i32,
            BitswapGetError::BlockRequestFailed | BitswapGetError::Timeout => {
                BitswapJsonRpcError::FailRetry as i32
            }
            BitswapGetError::QueueFull | BitswapGetError::NoPeers => {
                BitswapJsonRpcError::FailRetryBackoff as i32
            }
            BitswapGetError::TooManyCids { .. }
            | BitswapGetError::EmptyCids
            | BitswapGetError::DuplicateCids => {
                unreachable!("top-level batch-validation error, never emitted per-CID")
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

/// Validates and de-duplicates the input CIDs of `bitswap_unstable_stream`.
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
    if cids.is_empty() {
        return Err(BitswapGetError::EmptyCids);
    }
    if cids.len() > MAX_CIDS_PER_REQUEST {
        return Err(BitswapGetError::TooManyCids {
            max: MAX_CIDS_PER_REQUEST,
            got: cids.len(),
        });
    }

    let mut seen_strings: hashbrown::HashSet<String> =
        hashbrown::HashSet::with_capacity(cids.len());
    // Dedup by 32-byte content digest, matching the literal spec wording (and the polkadot-sdk
    // reference impl). Two cosmetically different CID strings that decode to the same digest
    // collide here, regardless of multicodec or multihash type.
    let mut seen_digests: hashbrown::HashSet<[u8; 32]> =
        hashbrown::HashSet::with_capacity(cids.len());
    let mut out = Vec::with_capacity(cids.len());

    for cid_str in cids {
        if !seen_strings.insert(cid_str.clone()) {
            return Err(BitswapGetError::DuplicateCids);
        }

        let parsed = Cid::from_str(&cid_str);
        if let Ok(c) = &parsed {
            if !seen_digests.insert(*c.digest()) {
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
    /// Submit a batched request. The service allocates a [`BatchId`], issues the Have broadcast,
    /// and reports the outcome back via `ready_tx`: `Ok(BatchId)` once the broadcast has landed
    /// (so the caller can construct its cancel guard and start receiving results), or
    /// `Err(BitswapGetError)` if the broadcast failed wholesale. Wholesale failures surface as
    /// top-level JSON-RPC errors (`-32812 FailRetryBackoff` for `NoPeers` / `QueueFull`).
    BitswapBatch {
        /// Validated and de-duplicated entries from [`parse_and_dedup`]. Per-slot `Err` carries
        /// an `InvalidCid` ParseError that gets surfaced as a per-CID error event.
        entries: Vec<(String, Result<Cid, cid::ParseError>)>,
        /// Per-CID outcomes are pushed here as they become available, in arrival order.
        events_tx: async_channel::Sender<(String, BlockResult)>,
        ready_tx: oneshot::Sender<Result<BatchId, BitswapGetError>>,
    },
    /// Cancel an in-flight batch. Idempotent: if the batch already finished, this is a no-op.
    CancelBatch { batch_id: BatchId },
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
/// (for `bitswap_get`) or a slot of a `Batch` (for `bitswap_stream`).
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
    /// Sender for per-CID outcomes, in arrival order. Dropping it closes the channel, signalling
    /// end-of-stream to the JSON-RPC pump.
    events_tx: async_channel::Sender<(String, BlockResult)>,
    /// Per-slot CID strings, indexed by slot index. Echoed back in events.
    cid_strs: Vec<String>,
    /// `Some(RequestId)` while a slot is in-flight; `None` once the slot has been resolved.
    /// Invalid-CID slots start as `None` (resolved synchronously when the batch is created).
    slots: Vec<Option<RequestId>>,
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
        /// Channel for signalling subscription readiness back to the caller of
        /// [`BitswapService::bitswap_stream`].
        ready_tx: oneshot::Sender<Result<BatchId, BitswapGetError>>,
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
    /// In-flight batches. Each entry corresponds to a `bitswap_stream` call.
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
        let (should_cancel, should_finalize) = {
            let Some(batch) = self.batches.get_mut(&batch_id) else {
                // The batch was already finalized or cancelled; the resolution is stale.
                return;
            };

            // Mark this slot as no longer in-flight regardless of mode.
            batch.slots[slot_idx] = None;
            batch.pending_count = batch.pending_count.saturating_sub(1);

            let cid_str = batch.cid_strs[slot_idx].clone();
            let mut should_cancel = false;

            match batch.events_tx.try_send((cid_str, block_result)) {
                Ok(()) => {}
                Err(async_channel::TrySendError::Closed(_)) => {
                    // Receiver dropped — JSON-RPC client disconnected or unsubscribed.
                    // Cancel the rest of the batch and emit a Bitswap Cancel wantlist.
                    should_cancel = true;
                }
                Err(async_channel::TrySendError::Full(_)) => {
                    // Invariant: parse_and_dedup caps entries.len() at MAX_CIDS_PER_REQUEST
                    // and events_tx is bounded(MAX_CIDS_PER_REQUEST). At most `total` items
                    // are ever pushed for a batch, so the buffer cannot saturate.
                    log!(
                        &self.platform,
                        Error,
                        &self.log_target,
                        "BUG: stream events channel full — invariant violated"
                    );
                    unreachable!()
                }
            }

            let should_finalize = !should_cancel && batch.pending_count == 0;
            (should_cancel, should_finalize)
        };

        if should_cancel {
            self.cancel_batch(batch_id);
        } else if should_finalize {
            self.finalize_batch(batch_id);
        }
    }

    /// Finalize a batch whose slots have all been resolved. Closes the events channel so the
    /// JSON-RPC pump can emit the spec-required `streamDone` event.
    fn finalize_batch(&mut self, batch_id: BatchId) {
        let Some(batch) = self.batches.remove(&batch_id) else {
            return;
        };
        debug_assert_eq!(batch.pending_count, 0);

        log!(
            &self.platform,
            Trace,
            &self.log_target,
            "batch finalized",
            batch_id = batch_id.0,
            slots = batch.cid_strs.len()
        );

        // Dropping the sender closes the channel. The JSON-RPC pump task will see the channel
        // close and end its loop after the last event has been delivered.
        drop(batch.events_tx);
    }

    /// Cancel a batch: tear down its still-pending slots, then send a wire-level `Cancel(cid)`
    /// for each CID this batch was the *last* local requester of. Idempotent.
    ///
    /// Only the last-reference case emits a Cancel — `requests_by_cid` is a multi-map and peers
    /// track want-state per-CID, not per-requester, so an unconditional Cancel would starve any
    /// concurrent batch or `bitswap_get` waiting on the same CID.
    fn cancel_batch(&mut self, batch_id: BatchId) {
        let Some(batch) = self.batches.remove(&batch_id) else {
            return;
        };

        // Walk pending slots, evict their `RequestId`s from the global tracking maps, and gather
        // the CIDs whose last local reference just went away (those are the ones safe to Cancel
        // on the wire).
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
                    pending_cids.push(request.cid);
                }
            }
        }

        if pending_cids.is_empty() || batch.peers_for_cancel.is_empty() {
            log!(
                &self.platform,
                Trace,
                &self.log_target,
                "batch cancelled (nothing to cancel on wire)",
                batch_id = batch_id.0,
                pending_cids = pending_cids.len(),
                peers = batch.peers_for_cancel.len()
            );
            return;
        }

        log!(
            &self.platform,
            Trace,
            &self.log_target,
            "sending cancel wantlist",
            batch_id = batch_id.0,
            cids = ?pending_cids,
            peers = batch.peers_for_cancel.len()
        );

        // One Cancel wantlist message containing all pending CIDs, sent to every peer this
        // batch's Have broadcast reached. Substrate Bitswap servers don't track pending
        // want-lists today, so Cancel is a no-op there; we send it for IPFS-spec conformance.
        let message = build_bitswap_cancel_message(pending_cids.iter());

        for peer in batch.peers_for_cancel {
            let network_service = self.network_service.clone();
            let msg = message.clone();
            // Fire-and-forget. Cancel is best-effort and does not need to be awaited; if it
            // fails the peer will eventually expire its want-list state on its own.
            self.platform
                .spawn_task(self.log_target.clone().into(), async move {
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

                log!(
                    &task.platform,
                    Trace,
                    &task.log_target,
                    "queueing have wantlist (single)",
                    cid
                );

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
                events_tx,
                ready_tx,
            }) => {
                debug_assert!(task.pending_have_broadcast.is_none());

                // Allocate the batch up front. The BatchId is reported back via `ready_tx` only
                // after the Have broadcast resolves (success or wholesale failure), so wholesale
                // failures surface as top-level JSON-RPC errors instead of per-slot ones.
                let batch_id = task.allocate_batch_id();

                let total = entries.len();
                let mut cid_strs: Vec<String> = Vec::with_capacity(total);
                let mut slots: Vec<Option<RequestId>> = Vec::with_capacity(total);
                // Slots whose CID parsed successfully — these will have their RequestId set
                // after the Have broadcast lands. (slot_idx, cid).
                let mut valid_cids: Vec<(usize, Cid)> = Vec::with_capacity(total);
                // Slots whose CID failed to parse — pre-resolve as `InvalidCid` per spec.
                // (cid_str, err).
                let mut invalid_slots: Vec<(String, BitswapGetError)> = Vec::new();

                for (slot_idx, (cid_str, parsed)) in entries.into_iter().enumerate() {
                    cid_strs.push(cid_str.clone());
                    slots.push(None);
                    match parsed {
                        Ok(c) => valid_cids.push((slot_idx, c)),
                        Err(e) => {
                            invalid_slots.push((cid_str, BitswapGetError::InvalidCid(e)));
                        }
                    }
                }

                let mut batch = Batch {
                    events_tx,
                    cid_strs,
                    slots,
                    peers_for_cancel: Vec::new(),
                    pending_count: total,
                };

                // Pre-resolve invalid-CID slots by pushing them straight into the events channel.
                // try_send cannot fail here: events_tx is bounded(MAX_CIDS_PER_REQUEST) and the
                // total events ever pushed for this batch is bounded by entries.len(); the
                // receiver is also held by BitswapStreamHandle so the channel cannot be Closed.
                for (cid_str, err) in invalid_slots {
                    batch.pending_count = batch.pending_count.saturating_sub(1);
                    batch
                        .events_tx
                        .try_send((cid_str, BlockResult::Err(err)))
                        .unwrap_or_else(|_| unreachable!());
                }

                log!(
                    &task.platform,
                    Trace,
                    &task.log_target,
                    "batch queued",
                    batch_id = batch_id.0,
                    total,
                    valid = valid_cids.len(),
                    invalid = total - valid_cids.len()
                );

                // Insert the batch before the broadcast: if the caller drops mid-await and a
                // CancelBatch arrives, it must find an entry to cancel.
                task.batches.insert(batch_id, batch);

                if valid_cids.is_empty() {
                    // No wire I/O needed. Signal Ok(batch_id) so the caller can construct its
                    // cancel guard / stream handle, then finalize immediately (all-invalid case)
                    // or leave the batch to await ordinary resolution paths.
                    let _ = ready_tx.send(Ok(batch_id));
                    if task
                        .batches
                        .get(&batch_id)
                        .map_or(true, |b| b.pending_count == 0)
                    {
                        task.finalize_batch(batch_id);
                    }
                    continue;
                }

                log!(
                    &task.platform,
                    Trace,
                    &task.log_target,
                    "queueing have wantlist (batch)",
                    batch_id = batch_id.0,
                    cids = ?valid_cids.iter().map(|(_, c)| c).collect::<Vec<_>>()
                );

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
                            ready_tx,
                        },
                    )
                }));
            }
            WakeUpReason::Message(ToBackground::CancelBatch { batch_id }) => {
                log!(
                    &task.platform,
                    Trace,
                    &task.log_target,
                    "cancel requested",
                    batch_id = batch_id.0
                );
                task.cancel_batch(batch_id);
            }
            WakeUpReason::HaveBroadcastResult((result, ctx)) => match ctx {
                HaveContext::Single { cid, result_tx } => {
                    let broadcast_to = match result {
                        Ok(peers) => peers,
                        Err(err) => {
                            log!(
                                &task.platform,
                                Trace,
                                &task.log_target,
                                "have broadcast failed (single)",
                                cid,
                                ?err
                            );
                            let _ = result_tx.send(Err(err.into()));
                            continue;
                        }
                    };

                    log!(
                        &task.platform,
                        Trace,
                        &task.log_target,
                        "have broadcast sent (single)",
                        cid,
                        peers = broadcast_to.len()
                    );

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
                HaveContext::Batch {
                    batch_id,
                    cids,
                    ready_tx,
                } => {
                    let broadcast_to = match result {
                        Ok(peers) => peers,
                        Err(err) => {
                            let err: BitswapGetError = err.into();
                            log!(
                                &task.platform,
                                Trace,
                                &task.log_target,
                                "have broadcast failed (batch), rejecting subscription",
                                batch_id = batch_id.0,
                                ?err
                            );
                            task.batches.remove(&batch_id);
                            let _ = ready_tx.send(Err(err));
                            continue;
                        }
                    };

                    log!(
                        &task.platform,
                        Trace,
                        &task.log_target,
                        "have broadcast sent (batch)",
                        batch_id = batch_id.0,
                        cid_count = cids.len(),
                        peers = broadcast_to.len()
                    );

                    // Under the new ready-handshake protocol, the batch cannot have been
                    // cancelled before this point: cancel requires the caller's
                    // `BatchCancelGuard`, which is only constructed after we send `Ok(batch_id)`
                    // below.
                    debug_assert!(task.batches.contains_key(&batch_id));
                    if let Some(batch) = task.batches.get_mut(&batch_id) {
                        batch.peers_for_cancel = broadcast_to.clone();
                    } else {
                        // Drop `ready_tx` without sending — the caller's `ready_rx.await.unwrap()`
                        // will surface the broken invariant.
                        continue;
                    }

                    // Register one Request per valid slot, sharing the same Have peer set.
                    // SipHasher seed drawn once per batch — each slot's HashSet uses the same
                    // randomness. Reseeding per slot would only add cost: the seed is for
                    // intra-set collision distribution, not cross-set isolation, and the
                    // contents (broadcast peer IDs) aren't secrets.
                    let timeout = task.platform.now() + Duration::from_secs(10);
                    let have_peers_seed = {
                        let mut seed = [0; 16];
                        task.randomness.fill_bytes(&mut seed);
                        seed
                    };
                    for (slot_idx, cid) in cids {
                        let request_id = task.allocate_request_id();
                        let have_peers = {
                            let mut have_peers = hashbrown::HashSet::with_capacity_and_hasher(
                                broadcast_to.len(),
                                util::SipHasherBuild::new(have_peers_seed),
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
                        task.requests_by_timeout
                            .insert((timeout.clone(), request_id));
                        task.requests_by_cid
                            .entry(cid)
                            .or_default()
                            .push_back(request_id);

                        if let Some(batch) = task.batches.get_mut(&batch_id) {
                            batch.slots[slot_idx] = Some(request_id);
                        }
                    }

                    // Signal broadcast success only after per-slot Requests are registered, so
                    // events can resolve immediately once the caller installs its handle.
                    let _ = ready_tx.send(Ok(batch_id));
                }
            },
            WakeUpReason::NetworkEvent(BitswapEvent::BitswapMessage { peer_id, message }) => {
                let message = message.decode();

                // Slots that have just resolved and need to be delivered after the per-block-
                // presence borrow on `task.requests_by_cid` is released.
                let mut deliveries: Vec<(SlotOutput, Result<Vec<u8>, BitswapGetError>)> =
                    Vec::new();

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

                    log!(
                        &task.platform,
                        Trace,
                        &task.log_target,
                        "presence response",
                        peer_id,
                        cid,
                        presence = match presence_type {
                            BlockPresenceType::Have => "have",
                            BlockPresenceType::DontHave => "dont_have",
                        }
                    );

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

                                    log!(
                                        &task.platform,
                                        Trace,
                                        &task.log_target,
                                        "all peers dont have, NotFound",
                                        cid = request.cid
                                    );

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
                        log!(
                            &task.platform,
                            Trace,
                            &task.log_target,
                            "sending block request",
                            peer_id,
                            cid
                        );

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

                    log!(
                        &task.platform,
                        Trace,
                        &task.log_target,
                        "block payload received",
                        peer_id,
                        cid,
                        bytes = data.len()
                    );

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
                    log!(
                        &task.platform,
                        Trace,
                        &task.log_target,
                        "block request failed",
                        cid,
                        ?err
                    );

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
                    let cid = request.cid.clone();

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

                    log!(
                        &task.platform,
                        Trace,
                        &task.log_target,
                        "request timeout",
                        cid
                    );

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

    /// Assert that the JSON-RPC error response carries no `data` field. Per the revised spec,
    /// bitswap errors are bare `{ code, message }` like every other method in this repo.
    fn assert_no_error_data(json: &str) {
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        assert!(
            parsed["error"].get("data").is_none(),
            "error object must not carry `data`: {json}"
        );
    }

    #[test]
    fn error_invalid_cid_maps_to_invalid_params() {
        let err = BitswapGetError::InvalidCid(Cid::from_str("not-a-cid").unwrap_err());
        let json = err.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32602); // InvalidParams
        assert_no_error_data(&json);
    }

    #[test]
    fn error_not_found_maps_to_fail() {
        let json = BitswapGetError::NotFound.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32810); // Fail
        assert_no_error_data(&json);
    }

    #[test]
    fn error_block_request_failed_maps_to_fail_retry() {
        let json = BitswapGetError::BlockRequestFailed.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32811); // FailRetry
        assert_no_error_data(&json);
    }

    #[test]
    fn error_timeout_maps_to_fail_retry() {
        let json = BitswapGetError::Timeout.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32811); // FailRetry
        assert_no_error_data(&json);
    }

    #[test]
    fn error_queue_full_maps_to_fail_retry_backoff() {
        let json = BitswapGetError::QueueFull.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32812); // FailRetryBackoff
        assert_no_error_data(&json);
    }

    #[test]
    fn error_no_peers_maps_to_fail_retry_backoff() {
        let json = BitswapGetError::NoPeers.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32812); // FailRetryBackoff
        assert_no_error_data(&json);
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
    fn error_too_many_cids_maps_to_too_many_cids() {
        let err = BitswapGetError::TooManyCids { max: 64, got: 100 };
        let json = err.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32801); // TooManyCids
        assert_no_error_data(&json);
    }

    #[test]
    fn error_empty_cids_maps_to_empty_cids() {
        let json = BitswapGetError::EmptyCids.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32802); // EmptyCids
        assert_no_error_data(&json);
    }

    #[test]
    fn error_duplicate_cids_maps_to_duplicate_cids() {
        let json = BitswapGetError::DuplicateCids.to_json_rpc_error("\"1\"");
        assert_eq!(extract_error_code(&json), -32803); // DuplicateCids
        assert_no_error_data(&json);
    }

    #[test]
    fn block_result_err_codes_match_top_level_codes() {
        // Per-CID error codes use the same retry categories as `bitswap_unstable_get`.
        // Top-level batch-validation variants (TooManyCids / EmptyCids / DuplicateCids) are
        // intentionally absent here — they reject the subscription before any per-CID event is
        // emitted.
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
    fn parse_and_dedup_empty_input_is_rejected() {
        // Per the revised spec, an empty `cids` array is rejected at the top level with
        // -32802 EmptyCids.
        let err = parse_and_dedup(vec![]).unwrap_err();
        assert!(matches!(err, BitswapGetError::EmptyCids));
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
        let cids: Vec<String> = (0..MAX_CIDS_PER_REQUEST)
            .map(|i| format!("invalid-{i}"))
            .collect();
        let out = parse_and_dedup(cids).unwrap();
        assert_eq!(out.len(), MAX_CIDS_PER_REQUEST);
    }
}
