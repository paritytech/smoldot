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

//! All JSON-RPC method handlers that do nothing but return a value already found in the node.

use super::{Background, Platform};

use smoldot::{
    header,
    json_rpc::{methods, requests_subscriptions},
    network::protocol,
};
use std::{num::NonZeroUsize, str, sync::Arc};

impl<TPlat: Platform> Background<TPlat> {
    /// Handles a call to [`methods::MethodCall::chain_getFinalizedHead`].
    pub(super) async fn chain_get_finalized_head(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        // TODO: maybe optimize?
        let response = methods::Response::chain_getFinalizedHead(methods::HashHexString(
            header::hash_from_scale_encoded_header(
                &self
                    .runtime_service
                    .subscribe_all("chain_getFinalizedHead", 16, NonZeroUsize::new(24).unwrap())
                    .await
                    .finalized_block_scale_encoded_header,
            ),
        ))
        .to_json_response(request_id);

        self.requests_subscriptions
            .respond(state_machine_request_id, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_genesisHash`].
    pub(super) async fn chain_head_unstable_genesis_hash(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::chainHead_unstable_genesisHash(methods::HashHexString(
                    self.genesis_block,
                ))
                .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::chainSpec_unstable_chainName`].
    pub(super) async fn chain_spec_unstable_chain_name(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::chainSpec_unstable_chainName((&self.chain_name).into())
                    .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::chainSpec_unstable_genesisHash`].
    pub(super) async fn chain_spec_unstable_genesis_hash(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::chainSpec_unstable_genesisHash(methods::HashHexString(
                    self.genesis_block,
                ))
                .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::chainSpec_unstable_properties`].
    pub(super) async fn chain_spec_unstable_properties(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::chainSpec_unstable_properties(
                    serde_json::from_str(&self.chain_properties_json).unwrap(),
                )
                .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::rpc_methods`].
    pub(super) async fn rpc_methods(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
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

    /// Handles a call to [`methods::MethodCall::sudo_unstable_version`].
    pub(super) async fn sudo_unstable_version(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::sudo_unstable_version(
                    format!("{} {}", self.system_name, self.system_version).into(),
                )
                .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::system_chain`].
    pub(super) async fn system_chain(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::system_chain((&self.chain_name).into())
                    .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::system_chainType`].
    pub(super) async fn system_chain_type(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::system_chainType((&self.chain_ty).into())
                    .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::system_health`].
    pub(super) async fn system_health(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
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
            .respond(state_machine_request_id, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::system_localListenAddresses`].
    pub(super) async fn system_local_listen_addresses(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        // Wasm node never listens on any address.
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::system_localListenAddresses(Vec::new())
                    .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::system_localPeerId`].
    pub(super) async fn system_local_peer_id(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::system_localPeerId((&self.peer_id_base58).into())
                    .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::system_name`].
    pub(super) async fn system_name(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::system_name((&self.system_name).into())
                    .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::system_peers`].
    pub(super) async fn system_peers(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
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
            .respond(state_machine_request_id, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::system_properties`].
    pub(super) async fn system_properties(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::system_properties(
                    serde_json::from_str(&self.chain_properties_json).unwrap(),
                )
                .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::system_version`].
    pub(super) async fn system_version(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::system_version((&self.system_version).into())
                    .to_json_response(request_id),
            )
            .await;
    }
}
