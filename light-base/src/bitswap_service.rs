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
use futures_channel::oneshot;
use hashbrown::{HashMap, HashSet};
use std::{collections::BTreeSet, sync::Arc};

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
    pub fn new<TPlat: PlatformRef>(config: Config<TPlat>) -> Self {
        todo!()
    }

    /// Request a Bitswap block.
    pub async fn bitswap_block(&self, cid: String) -> Result<Vec<u8>, BitswapBlockError> {
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
    /// No Bitswap peers connected.
    NoPeers,
    // TODO: other errors.
}

enum ToBackground {
    BitswapBlock {
        cid: String,
        result_tx: oneshot::Sender<Result<Vec<u8>, BitswapBlockError>>,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct RequestId(u64);

impl RequestId {
    const MIN: u64 = u64::MIN;
    const MAX: u64 = u64::MAX;
}

// TODO: replace with a binary CID representation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Cid(String);

struct BackgroundTask<TPlat: PlatformRef> {
    /// Messages from [`BitswapService`].
    messages_rx: async_channel::Receiver<ToBackground>,
    /// Underlying network to send/receive Bitswap messages.
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
    /// Next request ID to use.
    next_request_id: RequestId,
    /// All active requests. The values are (result_tx, timeout).
    requests: HashMap<
        RequestId,
        (
            oneshot::Sender<Result<Vec<u8>, BitswapBlockError>>,
            TPlat::Instant,
        ),
        fnv::FnvBuildHasher,
    >,
    /// Request timeouts ordered by time.
    timeouts_by_time: BTreeSet<(TPlat::Instant, RequestId)>,
    /// Requests in a "have" stage.
    have_requests: HashMap<RequestId, Cid, fnv::FnvBuildHasher>,
    /// Requests in a "have" stage ordered by CID.
    have_requests_by_cid: HashMap<Cid, Vec<RequestId>, util::SipHasherBuild>,
    /// Requests in a "block" stage.
    block_requests: HashMap<RequestId, Cid, fnv::FnvBuildHasher>,
    /// Requests in a "block" stage ordered by CID.
    block_requests_by_cid: HashMap<Cid, Vec<RequestId>, util::SipHasherBuild>,
}

fn background_task<TPlat: PlatformRef>(task: BackgroundTask<TPlat>) {
    todo!()
}
