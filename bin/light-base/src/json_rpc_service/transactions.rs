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

//! All JSON-RPC method handlers that relate to transactions.

use super::{Background, Platform, SubscriptionTy};

use crate::transactions_service;

use futures::prelude::*;
use smoldot::json_rpc::{self, methods, requests_subscriptions};
use std::{
    str,
    sync::{atomic, Arc},
};

impl<TPlat: Platform> Background<TPlat> {
    /// Handles a call to [`methods::MethodCall::author_pendingExtrinsics`].
    pub(super) async fn author_pending_extrinsics(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
    ) {
        // TODO: ask transactions service
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::author_pendingExtrinsics(Vec::new())
                    .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::author_submitExtrinsic`].
    pub(super) async fn author_submit_extrinsic(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        transaction: methods::HexString,
    ) {
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
        self.transactions_service
            .submit_transaction(transaction.0)
            .await;
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::author_submitExtrinsic(methods::HashHexString(transaction_hash))
                    .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::author_unwatchExtrinsic`].
    pub(super) async fn author_unwatch_extrinsic(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        subscription: &str,
    ) {
        let state_machine_subscription = if let Some((abort_handle, state_machine_subscription)) =
            self.subscriptions
                .lock()
                .await
                .misc
                .remove(&(subscription.to_owned(), SubscriptionTy::TransactionLegacy))
        {
            abort_handle.abort();
            Some(state_machine_subscription)
        } else {
            None
        };
        if let Some(state_machine_subscription) = &state_machine_subscription {
            self.requests_subscriptions
                .stop_subscription(state_machine_subscription)
                .await;
        }
        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::author_unwatchExtrinsic(state_machine_subscription.is_some())
                    .to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::transaction_unstable_unwatch`].
    pub(super) async fn transaction_unstable_unwatch(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        subscription: &str,
    ) {
        let state_machine_subscription = if let Some((abort_handle, state_machine_subscription)) =
            self.subscriptions
                .lock()
                .await
                .misc
                .remove(&(subscription.to_owned(), SubscriptionTy::Transaction))
        {
            abort_handle.abort();
            Some(state_machine_subscription)
        } else {
            None
        };

        if let Some(state_machine_subscription) = &state_machine_subscription {
            self.requests_subscriptions
                .stop_subscription(state_machine_subscription)
                .await;
        }

        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::transaction_unstable_unwatch(()).to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::author_submitAndWatchExtrinsic`] (if `is_legacy`
    /// is `true`) or to [`methods::MethodCall::transaction_unstable_submitAndWatch`] (if
    /// `is_legacy` is `false`).
    pub(super) async fn submit_and_watch_transaction(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        transaction: methods::HexString,
        is_legacy: bool,
    ) {
        let state_machine_subscription = match self
            .requests_subscriptions
            .start_subscription(state_machine_request_id, 16)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                self.requests_subscriptions
                    .respond(
                        state_machine_request_id,
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

        let subscription_id = self
            .next_subscription_id
            .fetch_add(1, atomic::Ordering::Relaxed)
            .to_string();

        let abort_registration = {
            let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
            let mut subscriptions_list = self.subscriptions.lock().await;
            let ty = if is_legacy {
                SubscriptionTy::TransactionLegacy
            } else {
                SubscriptionTy::Transaction
            };
            subscriptions_list.misc.insert(
                (subscription_id.clone(), ty),
                (abort_handle, state_machine_subscription.clone()),
            );
            abort_registration
        };

        self.requests_subscriptions
            .respond(
                &state_machine_request_id,
                if is_legacy {
                    methods::Response::author_submitAndWatchExtrinsic(&subscription_id)
                        .to_json_response(request_id)
                } else {
                    methods::Response::transaction_unstable_submitAndWatch(&subscription_id)
                        .to_json_response(request_id)
                },
            )
            .await;

        // Spawn a separate task for the transaction updates.
        let task = {
            let mut transaction_updates = self
                .transactions_service
                .submit_and_watch_transaction(transaction.0, 16)
                .await;
            let me = self.clone();
            async move {
                let mut included_block = None;
                let mut num_broadcasted_peers = 0;

                // TODO: doesn't reported `validated` events

                loop {
                    match transaction_updates.next().await {
                        Some(update) => {
                            let update = match (update, is_legacy) {
                                (transactions_service::TransactionStatus::Broadcast(peers), false) => {
                                    methods::ServerToClient::author_extrinsicUpdate {
                                        subscription: &subscription_id,
                                        result: methods::TransactionStatus::Broadcast(
                                            peers.into_iter().map(|peer| peer.to_base58()).collect(),
                                        )
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                                (transactions_service::TransactionStatus::Broadcast(peers), true) => {
                                    num_broadcasted_peers += peers.len();
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::Broadcasted {
                                            num_peers: u32::try_from(num_broadcasted_peers).unwrap_or(u32::max_value()),
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                }

                                (transactions_service::TransactionStatus::IncludedBlockUpdate {
                                    block_hash: Some((block_hash, _)),
                                }, true) => {
                                    included_block = Some(block_hash);
                                    methods::ServerToClient::author_extrinsicUpdate {
                                        subscription: &subscription_id,
                                        result: methods::TransactionStatus::InBlock(methods::HashHexString(
                                            block_hash,
                                        ))
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                                (transactions_service::TransactionStatus::IncludedBlockUpdate {
                                    block_hash: None,
                                }, true) => {
                                    if let Some(block_hash) = included_block.take() {
                                        methods::ServerToClient::author_extrinsicUpdate {
                                            subscription: &subscription_id,
                                            result: methods::TransactionStatus::Retracted(
                                                methods::HashHexString(block_hash),
                                            )
                                        }
                                        .to_json_call_object_parameters(None)

                                    } else {
                                        continue;
                                    }
                                }
                                (transactions_service::TransactionStatus::IncludedBlockUpdate {
                                    block_hash: Some((block_hash, index)),
                                }, false) => {
                                    included_block = Some(block_hash);
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::BestChainBlockIncluded {
                                            block: Some(methods::TransactionWatchEventBlock {
                                                hash: methods::HashHexString(block_hash),
                                                index: methods::NumberAsString(index),
                                            })
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                                (transactions_service::TransactionStatus::IncludedBlockUpdate {
                                    block_hash: None,
                                }, false) => {
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::BestChainBlockIncluded {
                                            block: None,
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                }

                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::GapInChain,
                                ), true)
                                | (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::MaxPendingTransactionsReached,
                                ), true)
                                | (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Invalid(_),
                                ), true)
                                | (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::ValidateError(_),
                                ), true) => {
                                    methods::ServerToClient::author_extrinsicUpdate {
                                        subscription: &subscription_id,
                                        result: methods::TransactionStatus::Dropped,
                                    }
                                    .to_json_call_object_parameters(None)
                                },
                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::GapInChain,
                                ), false) => {
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::Dropped {
                                            error: "gap in chain of blocks",
                                            broadcasted: num_broadcasted_peers != 0,
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                },
                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::MaxPendingTransactionsReached,
                                ), false) => {
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::Dropped {
                                            error: "transactions pool full",
                                            broadcasted: num_broadcasted_peers != 0,
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                },
                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Invalid(error),
                                ), false) => {
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::Invalid {
                                            error: &error.to_string(),
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                },
                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::ValidateError(error),
                                ), false) => {
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::Error {
                                            error: &error.to_string(),
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                },

                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Finalized { block_hash, .. },
                                ), true) => {
                                    methods::ServerToClient::author_extrinsicUpdate {
                                        subscription: &subscription_id,
                                        result: methods::TransactionStatus::Finalized(methods::HashHexString(
                                            block_hash,
                                        ))
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                                (transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Finalized { block_hash, index },
                                ), false) => {
                                    methods::ServerToClient::transaction_unstable_watchEvent {
                                        subscription: &subscription_id,
                                        result: methods::TransactionWatchEvent::Finalized {
                                            block: methods::TransactionWatchEventBlock {
                                                hash: methods::HashHexString(block_hash),
                                                index: methods::NumberAsString(index),
                                            },
                                        }
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                            };

                            // TODO: handle situation where buffer is full
                            let _ = me
                                .requests_subscriptions
                                .try_push_notification(&state_machine_subscription, update)
                                .await;
                        }
                        None => {
                            // Channel from the transactions service has been closed.
                            // Stop the task.
                            // There is nothing more that can be done except hope that the
                            // client understands that no new notification is expected and
                            // unsubscribes.
                            break;
                        }
                    }
                }
            }
        };

        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(Box::pin(
                future::Abortable::new(task, abort_registration).map(|_| ()),
            ))
            .unwrap();
    }
}
