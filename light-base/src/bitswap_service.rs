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
//! `bitswap_block(cid)`.
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

use crate::{log, network_service, platform::PlatformRef, util};
use core::str::FromStr;
use futures_channel::oneshot;
use smoldot::libp2p::cid::{self, Cid};
use std::{collections::BTreeSet, sync::Arc};

// TODO: how many parallel requests to expect?
const PARALLEL_REQUESTS: usize = 32;

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
            messages_rx,
            network_service,
            next_request_id: RequestId(0),
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
    pub async fn bitswap_block(&self, cid: String) -> Result<Vec<u8>, BitswapBlockError> {
        // Decoding CID is fast, so we can fail early on the API user side.
        let cid = Cid::from_str(&cid).map_err(BitswapBlockError::CidParsingError)?;

        let (result_tx, result_rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::BitswapBlock { cid, result_tx })
            .await
            .unwrap();

        result_rx.await.unwrap()
    }
}

/// Error by [`BitswapService::bitswap_block`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
enum BitswapBlockError {
    /// Invalid/unsupported CID.
    CidParsingError(cid::ParseError),
    /// No Bitswap peers connected.
    NoPeers,
    // TODO: other errors.
}

enum ToBackground {
    BitswapBlock {
        cid: Cid,
        result_tx: oneshot::Sender<Result<Vec<u8>, BitswapBlockError>>,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct RequestId(u64);

impl RequestId {
    const MIN: u64 = u64::MIN;
    const MAX: u64 = u64::MAX;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum RequestStage {
    /// We are waiting for peers to respond to our "have" request.
    Have,
    /// At least one peer has responded to a "have" request and we requested the actual data from
    /// one of the peers.
    Block,
}

#[derive(Debug)]
struct Request<TPlat: PlatformRef> {
    result_tx: oneshot::Sender<Result<Vec<u8>, BitswapBlockError>>,
    timeout: TPlat::Instant,
    stage: RequestStage,
    cid: Cid,
}

struct BackgroundTask<TPlat: PlatformRef> {
    /// Log target.
    log_target: String,
    /// Messages from [`BitswapService`].
    messages_rx: async_channel::Receiver<ToBackground>,
    /// Underlying network to send/receive Bitswap messages.
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
    /// Next request ID to use.
    next_request_id: RequestId,
    /// All active requests. The values are (result_tx, timeout).
    requests: hashbrown::HashMap<RequestId, Request<TPlat>, fnv::FnvBuildHasher>,
    /// Requests ordered by timeout.
    requests_by_timeout: BTreeSet<(TPlat::Instant, RequestId)>,
    /// Requests ordered by CID.
    requests_by_cid: hashbrown::HashMap<Cid, Vec<RequestId>, util::SipHasherBuild>,
}

impl<TPlat: PlatformRef> BackgroundTask<TPlat> {}

async fn background_task<TPlat: PlatformRef>(task: BackgroundTask<TPlat>) {
    todo!()
}
