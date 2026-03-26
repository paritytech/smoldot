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
//! Note that we have [`BitswapService`] per chain, even though currently [`NetworkService`]
//! doesn't track what chain the Bitswap request is destined to, and doesn't track what chain peers
//! responded to it to forward the response to specific chain's [`BitswapService`]. As a result,
//! [`BitswapService`] receives the responses intended for all the other Bitswap services as well.
//! This should be fixed in [`NetworkService`], but it is somewhat mitigated in [`BitswapService`]
//! by not decoding the incoming Bitswap messages when there are no active requests.
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
    network::codec::{Block, BlockPresence, BlockPresenceType, WantType, build_bitswap_message},
};

// TODO: how many parallel requests to expect?
const PARALLEL_REQUESTS: usize = 50; // 100 MiB of 2 MiB chunks.

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
        let cid = Cid::from_str(&cid).map_err(BitswapGetError::CidParsingError)?;

        let (result_tx, result_rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::BitswapBlock { cid, result_tx })
            .await
            .unwrap();

        result_rx.await.unwrap()
    }
}

/// Error by [`BitswapService::bitswap_get`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum BitswapGetError {
    /// Invalid/unsupported CID.
    #[display("Invalid/unsupported CID: {_0}")]
    CidParsingError(cid::ParseError),
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
        // to not surprize anybody.
        let (variant, category) = match self {
            BitswapGetError::CidParsingError(_) => ("CidParsingError", None),
            BitswapGetError::NotFound => ("NotFound", Some(BitswapJsonRpcError::Fail)),
            BitswapGetError::BlockRequestFailed => {
                ("BlockRequestFailed", Some(BitswapJsonRpcError::FailRetry))
            }
            BitswapGetError::Timeout => ("Timeout", Some(BitswapJsonRpcError::FailRetry)),
            BitswapGetError::QueueFull => {
                ("QueueFull", Some(BitswapJsonRpcError::FailRetryBackoff))
            }
            BitswapGetError::NoPeers => ("NoPeers", Some(BitswapJsonRpcError::FailRetryBackoff)),
        };

        let data = format!("{{\"variant\":\"{variant}\"}}");

        let error_response = match category {
            None => parse::ErrorResponse::InvalidParams(Some(&message)),
            Some(cat) => parse::ErrorResponse::ApplicationDefined(cat as i64, &message),
        };

        parse::build_error_response(request_id_json, error_response, Some(&data))
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

enum ToBackground {
    BitswapBlock {
        cid: Cid,
        result_tx: oneshot::Sender<Result<Vec<u8>, BitswapGetError>>,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct RequestId(u64);

impl RequestId {
    const _MIN: RequestId = RequestId(u64::MIN);
    const MAX: RequestId = RequestId(u64::MAX);
}

#[derive(Debug)]
enum RequestStage {
    /// We are waiting for peers to respond to our "have" request. `HashSet<PeerId>` are the peers
    /// we sent the "have" request to.
    Have(hashbrown::HashSet<PeerId, util::SipHasherBuild>),
    /// At least one peer has responded to a "have" request and we requested the data from it.
    Block,
}

#[derive(Debug)]
struct Request<TPlat: PlatformRef> {
    result_tx: oneshot::Sender<Result<Vec<u8>, BitswapGetError>>,
    timeout: TPlat::Instant,
    stage: RequestStage,
    cid: Cid,
}

type HaveBroadcastResult = (
    Result<Vec<PeerId>, SendBitswapMessageError>,
    Cid,
    oneshot::Sender<Result<Vec<u8>, BitswapGetError>>,
);

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
}

impl<TPlat: PlatformRef> BackgroundTask<TPlat> {
    fn allocate_request_id(&mut self) -> RequestId {
        let request_id = RequestId(self.next_request_id_inner);
        self.next_request_id_inner += 1;

        request_id
    }
}

fn bitswap_have_message(cid: &Cid) -> Vec<u8> {
    build_bitswap_message(iter::once(cid), WantType::Have, false, true)
}

fn bitswap_block_message(cid: &Cid) -> Vec<u8> {
    build_bitswap_message(iter::once(cid), WantType::Block, false, true)
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
                    (result, cid, result_tx)
                }));
            }
            WakeUpReason::HaveBroadcastResult((result, cid, result_tx)) => {
                // We either succeeded or failed in broadcasting the "have" request.

                let broadcast_to = match result {
                    Ok(peers) => peers,
                    Err(err) => {
                        // The request is not tracked yet, so we just report the failure.
                        let _ = result_tx.send(Err(err.into()));
                        continue;
                    }
                };

                // Start tracking the request.
                let request_id = task.allocate_request_id();
                let timeout = task.platform.now() + Duration::from_secs(10); // TODO: 5? 20?

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
                        result_tx,
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
            WakeUpReason::NetworkEvent(BitswapEvent::BitswapMessage { peer_id, message }) => {
                let message = message.decode();

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

                                    let _ = request.result_tx.send(Err(BitswapGetError::NotFound));
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

                            let _ = request.result_tx.send(Ok(data.to_owned()));
                        }
                    }
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

                            let _ = request.result_tx.send(Err(err.clone()));
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

                    let _ = request.result_tx.send(Err(BitswapGetError::Timeout));
                }
            }
            WakeUpReason::ForegroundClosed => {
                // Foreground closed the control channel, end the task.
                return;
            }
        }
    }
}
