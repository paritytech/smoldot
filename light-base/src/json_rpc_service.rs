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
//! Create a new JSON-RPC service by calling [`service()`].
//! Creating a JSON-RPC service spawns a background task (through [`PlatformRef::spawn_task`])
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

mod background;

use crate::{
    bitswap_service, log, network_service, platform::PlatformRef, runtime_service, sync_service,
    transactions_service,
};

use alloc::{
    borrow::Cow,
    boxed::Box,
    format,
    string::{String, ToString as _},
    sync::Arc,
};
use core::{num::NonZero, pin::Pin};
use futures_lite::StreamExt as _;

/// Configuration for [`service()`].
pub struct Config<TPlat: PlatformRef> {
    /// Access to the platform's capabilities.
    pub platform: TPlat,

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
    // TODO: unused at the moment
    #[allow(unused)]
    pub max_pending_requests: NonZero<u32>,

    /// Maximum number of active subscriptions. Any additional subscription will be immediately
    /// rejected.
    ///
    /// This parameter is necessary in order to prevent users from using up too much memory within
    /// the client.
    // TODO: unused at the moment
    #[allow(unused)]
    pub max_subscriptions: u32,

    /// Access to the network, and identifier of the chain from the point of view of the network
    /// service.
    pub network_service: Arc<network_service::NetworkServiceChain<TPlat>>,

    /// Service responsible for synchronizing the chain.
    pub sync_service: Arc<sync_service::SyncService<TPlat>>,

    /// Service responsible for emitting transactions and tracking their state.
    pub transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,

    /// Service that provides a ready-to-be-called runtime for the current best block.
    pub runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,

    /// Service that fulfills IPFS CID requests.
    pub bitswap_service: Arc<bitswap_service::BitswapService>,

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

/// Creates a new JSON-RPC service with the given configuration.
///
/// Returns a handler that allows sending requests and receiving responses.
///
/// Destroying the [`Frontend`] automatically shuts down the service.
pub fn service<TPlat: PlatformRef>(config: Config<TPlat>) -> Frontend<TPlat> {
    let log_target = format!("json-rpc-{}", config.log_name);

    let (requests_tx, requests_rx) = async_channel::unbounded(); // TODO: capacity?
    let (responses_tx, responses_rx) = async_channel::bounded(16); // TODO: capacity?

    let frontend = Frontend {
        platform: config.platform.clone(),
        log_target: log_target.clone(),
        responses_rx: Arc::new(async_lock::Mutex::new(Box::pin(responses_rx))),
        requests_tx,
    };

    let platform = config.platform.clone();
    platform.spawn_task(
        Cow::Owned(log_target.clone()),
        background::run(
            log_target,
            background::Config {
                platform: config.platform,
                network_service: config.network_service,
                sync_service: config.sync_service,
                transactions_service: config.transactions_service,
                runtime_service: config.runtime_service,
                bitswap_service: config.bitswap_service,
                chain_name: config.chain_name,
                chain_ty: config.chain_ty,
                chain_properties_json: config.chain_properties_json,
                chain_is_live: config.chain_is_live,
                system_name: config.system_name,
                system_version: config.system_version,
                genesis_block_hash: config.genesis_block_hash,
            },
            requests_rx,
            responses_tx,
        ),
    );

    frontend
}

/// Handle that allows sending JSON-RPC requests on the service.
///
/// The [`Frontend`] can be cloned, in which case the clone will refer to the same JSON-RPC
/// service.
///
/// Destroying all the [`Frontend`]s automatically shuts down the associated service.
#[derive(Clone)]
pub struct Frontend<TPlat> {
    /// See [`Config::platform`].
    platform: TPlat,

    /// How to send requests to the background task.
    requests_tx: async_channel::Sender<String>,

    /// How to receive responses coming from the background task.
    // TODO: we use an Arc so that it's clonable, but that's questionnable
    responses_rx: Arc<async_lock::Mutex<Pin<Box<async_channel::Receiver<String>>>>>,

    /// Target to use when emitting logs.
    log_target: String,
}

impl<TPlat: PlatformRef> Frontend<TPlat> {
    /// Queues the given JSON-RPC request to be processed in the background.
    ///
    /// An error is returned if [`Config::max_pending_requests`] is exceeded, which can happen
    /// if the requests take a long time to process or if [`Frontend::next_json_rpc_response`]
    /// isn't called often enough.
    pub fn queue_rpc_request(&self, json_rpc_request: String) -> Result<(), HandleRpcError> {
        let log_friendly_request =
            crate::util::truncated_str(json_rpc_request.chars().filter(|c| !c.is_control()), 250)
                .to_string();

        match self.requests_tx.try_send(json_rpc_request) {
            Ok(()) => {
                log!(
                    &self.platform,
                    Debug,
                    &self.log_target,
                    "json-rpc-request-queued",
                    request = log_friendly_request
                );
                Ok(())
            }
            Err(err) => Err(HandleRpcError::TooManyPendingRequests {
                json_rpc_request: err.into_inner(),
            }),
        }
    }

    /// Waits until a JSON-RPC response has been generated, then returns it.
    ///
    /// If this function is called multiple times in parallel, the order in which the calls are
    /// responded to is unspecified.
    pub async fn next_json_rpc_response(&self) -> String {
        let message = match self.responses_rx.lock().await.next().await {
            Some(m) => m,
            None => unreachable!(),
        };

        log!(
            &self.platform,
            Debug,
            &self.log_target,
            "json-rpc-response-yielded",
            response =
                crate::util::truncated_str(message.chars().filter(|c| !c.is_control()), 250,)
        );

        message
    }
}

/// Error potentially returned when queuing a JSON-RPC request.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum HandleRpcError {
    /// The JSON-RPC service cannot process this request, as too many requests are already being
    /// processed.
    #[display(
        "The JSON-RPC service cannot process this request, as too many requests are already being processed."
    )]
    TooManyPendingRequests {
        /// Request that was being queued.
        json_rpc_request: String,
    },
}
