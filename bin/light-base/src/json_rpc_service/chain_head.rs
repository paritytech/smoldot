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

//! All JSON-RPC method handlers that related to the `chainHead` API.

use super::{convert_runtime_spec, Background, FollowSubscription, Platform, SubscriptionTy};

use crate::{runtime_service, sync_service};

use futures::prelude::*;
use smoldot::{
    chain::fork_tree,
    executor::read_only_runtime_host,
    header,
    json_rpc::{self, methods, requests_subscriptions},
    network::protocol,
};
use std::{
    collections::HashMap,
    iter, str,
    sync::{atomic, Arc},
};

impl<TPlat: Platform> Background<TPlat> {
    /// Handles a call to [`methods::MethodCall::chainHead_unstable_call`].
    pub(super) async fn chain_head_call(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        follow_subscription_id: &str,
        hash: methods::HashHexString,
        function_to_call: &str,
        call_parameters: methods::HexString,
    ) {
        let task = {
            let me = self.clone();
            let request_id = request_id.to_owned();
            let function_to_call = function_to_call.to_owned();
            let state_machine_request_id = state_machine_request_id.clone();
            let follow_subscription_id = follow_subscription_id.to_owned();
            async move {
                // Determine whether the requested block hash is valid and start the call.
                let pre_runtime_call = {
                    let lock = me.subscriptions.lock().await;
                    if let Some(subscription) = lock.chain_head_follow.get(&follow_subscription_id)
                    {
                        let runtime_service_subscribe_all = match subscription.runtime_subscribe_all
                        {
                            Some(sa) => sa,
                            None => {
                                me.requests_subscriptions
                                    .respond(
                                        &state_machine_request_id,
                                        json_rpc::parse::build_error_response(
                                            &request_id,
                                            json_rpc::parse::ErrorResponse::InvalidParams,
                                            None,
                                        ),
                                    )
                                    .await;
                                return;
                            }
                        };

                        if !subscription.pinned_blocks_headers.contains_key(&hash.0) {
                            me.requests_subscriptions
                                .respond(
                                    &state_machine_request_id,
                                    json_rpc::parse::build_error_response(
                                        &request_id,
                                        json_rpc::parse::ErrorResponse::InvalidParams,
                                        None,
                                    ),
                                )
                                .await;
                            return;
                        }

                        Some(
                            me.runtime_service
                                .pinned_block_runtime_lock(runtime_service_subscribe_all, &hash.0)
                                .await,
                        )
                    } else {
                        None
                    }
                };

                let state_machine_subscription = match me
                    .requests_subscriptions
                    .start_subscription(&state_machine_request_id, 1)
                    .await
                {
                    Ok(v) => v,
                    Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                        me.requests_subscriptions
                            .respond(
                                &state_machine_request_id,
                                json_rpc::parse::build_error_response(
                                    &request_id,
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

                let subscription_id = me
                    .next_subscription_id
                    .fetch_add(1, atomic::Ordering::Relaxed)
                    .to_string();

                // TODO: make use of this
                let _abort_registration = {
                    let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
                    let mut subscriptions_list = me.subscriptions.lock().await;
                    subscriptions_list.misc.insert(
                        (subscription_id.clone(), SubscriptionTy::ChainHeadCall),
                        (abort_handle, state_machine_subscription.clone()),
                    );
                    abort_registration
                };

                me.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainHead_unstable_call(&subscription_id)
                            .to_json_response(&request_id),
                    )
                    .await;

                let pre_runtime_call = if let Some(pre_runtime_call) = &pre_runtime_call {
                    Some(
                        pre_runtime_call
                            .start(&function_to_call, iter::once(&call_parameters.0))
                            .await,
                    )
                } else {
                    None
                };

                let final_notif = match pre_runtime_call {
                    Some(Ok((runtime_call_lock, virtual_machine))) => {
                        match read_only_runtime_host::run(read_only_runtime_host::Config {
                            virtual_machine,
                            function_to_call: &function_to_call,
                            parameter: iter::once(&call_parameters.0),
                        }) {
                            Err((error, prototype)) => {
                                runtime_call_lock.unlock(prototype);
                                methods::ServerToClient::chainHead_unstable_callEvent {
                                    subscription: &subscription_id,
                                    result: methods::ChainHeadCallEvent::Error {
                                        error: &error.to_string(),
                                    },
                                }
                                .to_json_call_object_parameters(None)
                            }
                            Ok(mut runtime_call) => {
                                loop {
                                    match runtime_call {
                                        read_only_runtime_host::RuntimeHostVm::Finished(Ok(
                                            success,
                                        )) => {
                                            let output =
                                                success.virtual_machine.value().as_ref().to_owned();
                                            runtime_call_lock
                                                .unlock(success.virtual_machine.into_prototype());
                                            break methods::ServerToClient::chainHead_unstable_callEvent {
                                                    subscription: &subscription_id,
                                                    result: methods::ChainHeadCallEvent::Done {
                                                        output: methods::HexString(output),
                                                    },
                                                }
                                                .to_json_call_object_parameters(None);
                                        }
                                        read_only_runtime_host::RuntimeHostVm::Finished(Err(
                                            error,
                                        )) => {
                                            runtime_call_lock.unlock(error.prototype);
                                            break methods::ServerToClient::chainHead_unstable_callEvent {
                                                    subscription: &subscription_id,
                                                    result: methods::ChainHeadCallEvent::Error {
                                                        error: &error.detail.to_string(),
                                                    },
                                                }
                                                .to_json_call_object_parameters(None);
                                        }
                                        read_only_runtime_host::RuntimeHostVm::StorageGet(get) => {
                                            // TODO: what if the remote lied to us?
                                            let storage_value = match runtime_call_lock
                                                .storage_entry(&get.key_as_vec())
                                            {
                                                Ok(v) => v,
                                                Err(error) => {
                                                    runtime_call_lock.unlock(
                                                            read_only_runtime_host::RuntimeHostVm::StorageGet(
                                                                get,
                                                            )
                                                            .into_prototype(),
                                                        );
                                                    break methods::ServerToClient::chainHead_unstable_callEvent {
                                                            subscription: &subscription_id,
                                                            result: methods::ChainHeadCallEvent::Inaccessible {
                                                                error: &error.to_string(),
                                                            },
                                                        }
                                                        .to_json_call_object_parameters(None);
                                                }
                                            };
                                            runtime_call =
                                                get.inject_value(storage_value.map(iter::once));
                                        }
                                        read_only_runtime_host::RuntimeHostVm::NextKey(nk) => {
                                            // TODO: implement somehow
                                            runtime_call_lock.unlock(
                                                read_only_runtime_host::RuntimeHostVm::NextKey(nk)
                                                    .into_prototype(),
                                            );
                                            break methods::ServerToClient::chainHead_unstable_callEvent {
                                                    subscription: &subscription_id,
                                                    result: methods::ChainHeadCallEvent::Inaccessible {
                                                        error: &"getting next key not implemented",
                                                    },
                                                }
                                                .to_json_call_object_parameters(None);
                                        }
                                        read_only_runtime_host::RuntimeHostVm::StorageRoot(
                                            storage_root,
                                        ) => {
                                            runtime_call = storage_root
                                                .resume(runtime_call_lock.block_storage_root());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Some(Err(runtime_service::RuntimeCallError::InvalidRuntime(error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadCallEvent::Error {
                                error: &error.to_string(),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    Some(Err(runtime_service::RuntimeCallError::StorageRetrieval(error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadCallEvent::Error {
                                error: &error.to_string(),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    Some(Err(runtime_service::RuntimeCallError::CallProof(error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadCallEvent::Error {
                                error: &error.to_string(),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    Some(Err(runtime_service::RuntimeCallError::StorageQuery(error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadCallEvent::Error {
                                error: &format!("failed to fetch call proof: {}", error),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    None => methods::ServerToClient::chainHead_unstable_callEvent {
                        subscription: &subscription_id,
                        result: methods::ChainHeadCallEvent::Disjoint {},
                    }
                    .to_json_call_object_parameters(None),
                };

                me.requests_subscriptions
                    .push_notification(&state_machine_subscription, final_notif)
                    .await;

                me.requests_subscriptions
                    .stop_subscription(&state_machine_subscription)
                    .await;
                let _ = me
                    .subscriptions
                    .lock()
                    .await
                    .misc
                    .remove(&(subscription_id.to_owned(), SubscriptionTy::ChainHeadCall));
            }
        };

        self.new_child_tasks_tx
            .lock()
            .await
            .unbounded_send(task.boxed())
            .unwrap();
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_follow`].
    pub(super) async fn chain_head_follow(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        runtime_updates: bool,
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

        let (mut subscribe_all, runtime_subscribe_all) = if runtime_updates {
            let subscribe_all = self.runtime_service.subscribe_all(32, 48).await;
            let id = subscribe_all.new_blocks.id();
            (either::Left(subscribe_all), Some(id))
        } else {
            (
                either::Right(self.sync_service.subscribe_all(32, false).await),
                None,
            )
        };

        let (subscription_id, initial_notifications, abort_registration) = {
            let subscription_id = self
                .next_subscription_id
                .fetch_add(1, atomic::Ordering::Relaxed)
                .to_string();

            self.requests_subscriptions
                .respond(
                    &state_machine_request_id,
                    methods::Response::chainHead_unstable_follow(&subscription_id)
                        .to_json_response(request_id),
                )
                .await;

            let mut initial_notifications = Vec::with_capacity(match &subscribe_all {
                either::Left(sa) => 1 + sa.non_finalized_blocks_ancestry_order.len(),
                either::Right(sa) => 1 + sa.non_finalized_blocks_ancestry_order.len(),
            });

            let mut pinned_blocks_headers =
                HashMap::with_capacity_and_hasher(0, Default::default());
            let mut non_finalized_blocks = fork_tree::ForkTree::new();

            match &subscribe_all {
                either::Left(subscribe_all) => {
                    let finalized_block_hash = header::hash_from_scale_encoded_header(
                        &subscribe_all.finalized_block_scale_encoded_header[..],
                    );

                    pinned_blocks_headers.insert(
                        finalized_block_hash,
                        subscribe_all.finalized_block_scale_encoded_header.clone(),
                    );

                    initial_notifications.push({
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: &subscription_id,
                            result: methods::FollowEvent::Initialized {
                                finalized_block_hash: methods::HashHexString(finalized_block_hash),
                                finalized_block_runtime: Some(convert_runtime_spec(
                                    &subscribe_all.finalized_block_runtime,
                                )),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    });

                    for block in &subscribe_all.non_finalized_blocks_ancestry_order {
                        let hash =
                            header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                        let _was_in =
                            pinned_blocks_headers.insert(hash, block.scale_encoded_header.clone());
                        debug_assert!(_was_in.is_none());

                        let parent_node_index = if block.parent_hash == finalized_block_hash {
                            None
                        } else {
                            // TODO: O(n)
                            Some(
                                non_finalized_blocks
                                    .find(|b| *b == block.parent_hash)
                                    .unwrap(),
                            )
                        };
                        non_finalized_blocks.insert(parent_node_index, hash);

                        initial_notifications.push(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: &subscription_id,
                                result: methods::FollowEvent::NewBlock {
                                    block_hash: methods::HashHexString(hash),
                                    new_runtime: if let Some(new_runtime) = &block.new_runtime {
                                        Some(convert_runtime_spec(new_runtime))
                                    } else {
                                        None
                                    },
                                    parent_block_hash: methods::HashHexString(block.parent_hash),
                                },
                            }
                            .to_json_call_object_parameters(None),
                        );

                        if block.is_new_best {
                            initial_notifications.push(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: &subscription_id,
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_call_object_parameters(None),
                            );
                        }
                    }
                }
                either::Right(subscribe_all) => {
                    let finalized_block_hash = header::hash_from_scale_encoded_header(
                        &subscribe_all.finalized_block_scale_encoded_header[..],
                    );

                    pinned_blocks_headers.insert(
                        finalized_block_hash,
                        subscribe_all.finalized_block_scale_encoded_header.clone(),
                    );

                    initial_notifications.push(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: &subscription_id,
                            result: methods::FollowEvent::Initialized {
                                finalized_block_hash: methods::HashHexString(finalized_block_hash),
                                finalized_block_runtime: None,
                            },
                        }
                        .to_json_call_object_parameters(None),
                    );

                    for block in &subscribe_all.non_finalized_blocks_ancestry_order {
                        let hash =
                            header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                        let _was_in =
                            pinned_blocks_headers.insert(hash, block.scale_encoded_header.clone());
                        debug_assert!(_was_in.is_none());

                        let parent_node_index = if block.parent_hash == finalized_block_hash {
                            None
                        } else {
                            // TODO: O(n)
                            Some(
                                non_finalized_blocks
                                    .find(|b| *b == block.parent_hash)
                                    .unwrap(),
                            )
                        };
                        non_finalized_blocks.insert(parent_node_index, hash);

                        initial_notifications.push(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: &subscription_id,
                                result: methods::FollowEvent::NewBlock {
                                    block_hash: methods::HashHexString(hash),
                                    new_runtime: None,
                                    parent_block_hash: methods::HashHexString(block.parent_hash),
                                },
                            }
                            .to_json_call_object_parameters(None),
                        );

                        if block.is_new_best {
                            initial_notifications.push(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: &subscription_id,
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_call_object_parameters(None),
                            );
                        }
                    }
                }
            }

            let (abort_handle, abort_registration) = future::AbortHandle::new_pair();

            let mut lock = self.subscriptions.lock().await;

            lock.chain_head_follow.insert(
                subscription_id.clone(),
                FollowSubscription {
                    non_finalized_blocks,
                    pinned_blocks_headers,
                    runtime_subscribe_all,
                    abort_handle: abort_handle,
                },
            );

            (subscription_id, initial_notifications, abort_registration)
        };

        // Spawn a separate task for the subscription.
        let task = {
            let me = self.clone();
            async move {
                // Send back to the user the initial notifications.
                for notif in initial_notifications {
                    me.requests_subscriptions
                        .push_notification(&state_machine_subscription, notif)
                        .await;
                }

                loop {
                    let next_block = match &mut subscribe_all {
                        either::Left(subscribe_all) => {
                            future::Either::Left(subscribe_all.new_blocks.next().map(either::Left))
                        }
                        either::Right(subscribe_all) => future::Either::Right(
                            subscribe_all.new_blocks.next().map(either::Right),
                        ),
                    };
                    futures::pin_mut!(next_block);

                    // TODO: doesn't enforce any maximum number of pinned blocks
                    match next_block.await {
                        either::Left(None) | either::Right(None) => {
                            // TODO: clear queue of notifications?
                            break;
                        }
                        either::Left(Some(runtime_service::Notification::Finalized {
                            best_block_hash,
                            hash,
                            ..
                        }))
                        | either::Right(Some(sync_service::Notification::Finalized {
                            best_block_hash,
                            hash,
                        })) => {
                            let mut finalized_blocks_hashes = Vec::new();
                            let mut pruned_blocks_hashes = Vec::new();

                            let mut subscriptions = me.subscriptions.lock().await;
                            if let Some(sub) =
                                subscriptions.chain_head_follow.get_mut(&subscription_id)
                            {
                                let node_index =
                                    sub.non_finalized_blocks.find(|b| *b == hash).unwrap();
                                for pruned in sub.non_finalized_blocks.prune_ancestors(node_index) {
                                    if pruned.is_prune_target_ancestor {
                                        finalized_blocks_hashes
                                            .push(methods::HashHexString(pruned.user_data));
                                    } else {
                                        pruned_blocks_hashes
                                            .push(methods::HashHexString(pruned.user_data));
                                    }
                                }
                            }

                            // TODO: don't always generate
                            if me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
                                    methods::ServerToClient::chainHead_unstable_followEvent {
                                        subscription: &subscription_id,
                                        result: methods::FollowEvent::BestBlockChanged {
                                            best_block_hash: methods::HashHexString(
                                                best_block_hash,
                                            ),
                                        },
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await
                                .is_err()
                            {
                                break;
                            }

                            if me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
                                    methods::ServerToClient::chainHead_unstable_followEvent {
                                        subscription: &subscription_id,
                                        result: methods::FollowEvent::Finalized {
                                            finalized_blocks_hashes,
                                            pruned_blocks_hashes,
                                        },
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        either::Left(Some(runtime_service::Notification::Block(block))) => {
                            let hash =
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                            let mut subscriptions = me.subscriptions.lock().await;
                            if let Some(sub) =
                                subscriptions.chain_head_follow.get_mut(&subscription_id)
                            {
                                let _was_in = sub
                                    .pinned_blocks_headers
                                    .insert(hash, block.scale_encoded_header);
                                debug_assert!(_was_in.is_none());

                                // TODO: check if it matches current finalized block
                                // TODO: O(n)
                                let parent_node_index =
                                    sub.non_finalized_blocks.find(|b| *b == block.parent_hash);
                                sub.non_finalized_blocks.insert(parent_node_index, hash);
                            }

                            if me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
                                    methods::ServerToClient::chainHead_unstable_followEvent {
                                        subscription: &subscription_id,
                                        result: methods::FollowEvent::NewBlock {
                                            block_hash: methods::HashHexString(hash),
                                            parent_block_hash: methods::HashHexString(
                                                block.parent_hash,
                                            ),
                                            new_runtime: if let Some(new_runtime) =
                                                &block.new_runtime
                                            {
                                                Some(convert_runtime_spec(new_runtime))
                                            } else {
                                                None
                                            },
                                        },
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await
                                .is_err()
                            {
                                break;
                            }

                            if block.is_new_best {
                                if me
                                    .requests_subscriptions
                                    .try_push_notification(
                                        &state_machine_subscription,
                                        methods::ServerToClient::chainHead_unstable_followEvent {
                                            subscription: &subscription_id,
                                            result: methods::FollowEvent::BestBlockChanged {
                                                best_block_hash: methods::HashHexString(hash),
                                            },
                                        }
                                        .to_json_call_object_parameters(None),
                                    )
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                        either::Right(Some(sync_service::Notification::Block(block))) => {
                            let hash =
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                            let mut subscriptions = me.subscriptions.lock().await;
                            if let Some(sub) =
                                subscriptions.chain_head_follow.get_mut(&subscription_id)
                            {
                                let _was_in = sub
                                    .pinned_blocks_headers
                                    .insert(hash, block.scale_encoded_header);
                                debug_assert!(_was_in.is_none());

                                // TODO: check if it matches current finalized block
                                // TODO: O(n)
                                let parent_node_index =
                                    sub.non_finalized_blocks.find(|b| *b == block.parent_hash);
                                sub.non_finalized_blocks.insert(parent_node_index, hash);
                            }
                            if me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
                                    methods::ServerToClient::chainHead_unstable_followEvent {
                                        subscription: &subscription_id,
                                        result: methods::FollowEvent::NewBlock {
                                            block_hash: methods::HashHexString(hash),
                                            parent_block_hash: methods::HashHexString(
                                                block.parent_hash,
                                            ),
                                            new_runtime: None, // TODO:
                                        },
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await
                                .is_err()
                            {
                                break;
                            }

                            if block.is_new_best {
                                if me
                                    .requests_subscriptions
                                    .try_push_notification(
                                        &state_machine_subscription,
                                        methods::ServerToClient::chainHead_unstable_followEvent {
                                            subscription: &subscription_id,
                                            result: methods::FollowEvent::BestBlockChanged {
                                                best_block_hash: methods::HashHexString(hash),
                                            },
                                        }
                                        .to_json_call_object_parameters(None),
                                    )
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                }

                let _ = me
                    .subscriptions
                    .lock()
                    .await
                    .chain_head_follow
                    .remove(&subscription_id);

                me.requests_subscriptions
                    .push_notification(
                        &state_machine_subscription,
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: &subscription_id,
                            result: methods::FollowEvent::Stop {},
                        }
                        .to_json_call_object_parameters(None),
                    )
                    .await;
                me.requests_subscriptions
                    .stop_subscription(&state_machine_subscription)
                    .await;
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

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_storage`].
    pub(super) async fn chain_head_storage(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        follow_subscription_id: &str,
        hash: methods::HashHexString,
        key: methods::HexString,
        child_key: Option<methods::HexString>,
        ty: methods::StorageQueryType,
    ) {
        if child_key.is_some() {
            self.requests_subscriptions
                .respond(
                    &state_machine_request_id,
                    json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::ServerError(
                            -32000,
                            "Child key storage queries not supported yet",
                        ),
                        None,
                    ),
                )
                .await;
            log::warn!(
                target: &self.log_target,
                "chainHead_unstable_storage with a non-null childKey has been called. \
                This isn't supported by smoldot yet."
            );
            return;
        }

        // Determine whether the requested block hash is valid, and if so its state trie root.
        let block_storage_root = {
            let lock = self.subscriptions.lock().await;
            if let Some(subscription) = lock.chain_head_follow.get(follow_subscription_id) {
                if let Some(header) = subscription.pinned_blocks_headers.get(&hash.0) {
                    if let Ok(decoded) = header::decode(&header) {
                        Some(*decoded.state_root)
                    } else {
                        None // TODO: what to return?!
                    }
                } else {
                    self.requests_subscriptions
                        .respond(
                            &state_machine_request_id,
                            json_rpc::parse::build_error_response(
                                request_id,
                                json_rpc::parse::ErrorResponse::InvalidParams,
                                None,
                            ),
                        )
                        .await;
                    return;
                }
            } else {
                None
            }
        };

        let state_machine_subscription = match self
            .requests_subscriptions
            .start_subscription(&state_machine_request_id, 1)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
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
            subscriptions_list.misc.insert(
                (subscription_id.clone(), SubscriptionTy::ChainHeadStorage),
                (abort_handle, state_machine_subscription.clone()),
            );
            abort_registration
        };

        self.requests_subscriptions
            .respond(
                &state_machine_request_id,
                methods::Response::chainHead_unstable_storage(&subscription_id)
                    .to_json_response(request_id),
            )
            .await;

        let task = {
            let me = self.clone();
            async move {
                let response = if let Some(block_storage_root) = block_storage_root {
                    let response = me
                        .sync_service
                        .clone()
                        .storage_query(&hash.0, &block_storage_root, iter::once(&key.0))
                        .await;
                    match response {
                        Ok(values) => {
                            // `storage_query` returns a list of values because it can perform
                            // multiple queries at once. In our situation, we only start one query
                            // and as such the outcome only ever contains one element.
                            debug_assert_eq!(values.len(), 1);
                            let value = values.into_iter().next().unwrap();

                            let output = match ty {
                                methods::StorageQueryType::Value => {
                                    value.map(|v| methods::HexString(v).to_string())
                                }
                                methods::StorageQueryType::Size => {
                                    value.map(|v| v.len().to_string())
                                }
                                methods::StorageQueryType::Hash => value.map(|v| {
                                    methods::HexString(
                                        blake2_rfc::blake2b::blake2b(32, &[], &v)
                                            .as_bytes()
                                            .to_vec(),
                                    )
                                    .to_string()
                                }),
                            };

                            methods::ServerToClient::chainHead_unstable_storageEvent {
                                subscription: &subscription_id,
                                result: methods::ChainHeadStorageEvent::Done { value: output },
                            }
                            .to_json_call_object_parameters(None)
                        }
                        Err(_) => methods::ServerToClient::chainHead_unstable_storageEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadStorageEvent::Inaccessible {},
                        }
                        .to_json_call_object_parameters(None),
                    }
                } else {
                    methods::ServerToClient::chainHead_unstable_storageEvent {
                        subscription: &subscription_id,
                        result: methods::ChainHeadStorageEvent::Disjoint {},
                    }
                    .to_json_call_object_parameters(None)
                };

                me.requests_subscriptions
                    .set_queued_notification(&state_machine_subscription, 0, response)
                    .await;

                me.requests_subscriptions
                    .stop_subscription(&state_machine_subscription)
                    .await;
                let _ = me
                    .subscriptions
                    .lock()
                    .await
                    .misc
                    .remove(&(subscription_id.to_owned(), SubscriptionTy::ChainHeadStorage));
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

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_body`].
    pub(super) async fn chain_head_unstable_body(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        follow_subscription_id: &str,
        hash: methods::HashHexString,
    ) {
        // Determine whether the requested block hash is valid.
        let block_is_valid = {
            let lock = self.subscriptions.lock().await;
            if let Some(subscription) = lock.chain_head_follow.get(follow_subscription_id) {
                if !subscription.pinned_blocks_headers.contains_key(&hash.0) {
                    self.requests_subscriptions
                        .respond(
                            &state_machine_request_id,
                            json_rpc::parse::build_error_response(
                                request_id,
                                json_rpc::parse::ErrorResponse::InvalidParams,
                                None,
                            ),
                        )
                        .await;
                    return;
                }

                true
            } else {
                false
            }
        };

        let state_machine_subscription = match self
            .requests_subscriptions
            .start_subscription(&state_machine_request_id, 1)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
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
            subscriptions_list.misc.insert(
                (subscription_id.clone(), SubscriptionTy::ChainHeadBody),
                (abort_handle, state_machine_subscription.clone()),
            );
            abort_registration
        };

        self.requests_subscriptions
            .respond(
                &state_machine_request_id,
                methods::Response::chainHead_unstable_body(&subscription_id)
                    .to_json_response(request_id),
            )
            .await;

        let task = {
            let me = self.clone();
            async move {
                let response = if block_is_valid {
                    // TODO: right now we query the header because the underlying function returns an error if we don't
                    let response = me
                        .sync_service
                        .clone()
                        .block_query(
                            hash.0,
                            protocol::BlocksRequestFields {
                                header: true,
                                body: true,
                                justifications: false,
                            },
                        )
                        .await;
                    match response {
                        Ok(block_data) => methods::ServerToClient::chainHead_unstable_bodyEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadBodyEvent::Done {
                                value: block_data
                                    .body
                                    .unwrap()
                                    .into_iter()
                                    .map(methods::HexString)
                                    .collect(),
                            },
                        }
                        .to_json_call_object_parameters(None),
                        Err(()) => methods::ServerToClient::chainHead_unstable_bodyEvent {
                            subscription: &subscription_id,
                            result: methods::ChainHeadBodyEvent::Inaccessible {},
                        }
                        .to_json_call_object_parameters(None),
                    }
                } else {
                    methods::ServerToClient::chainHead_unstable_bodyEvent {
                        subscription: &subscription_id,
                        result: methods::ChainHeadBodyEvent::Disjoint {},
                    }
                    .to_json_call_object_parameters(None)
                };

                me.requests_subscriptions
                    .set_queued_notification(&state_machine_subscription, 0, response)
                    .await;

                me.requests_subscriptions
                    .stop_subscription(&state_machine_subscription)
                    .await;
                let _ = me
                    .subscriptions
                    .lock()
                    .await
                    .misc
                    .remove(&(subscription_id.to_owned(), SubscriptionTy::ChainHeadBody));
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

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_header`].
    pub(super) async fn chain_head_unstable_header(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        follow_subscription_id: &str,
        hash: methods::HashHexString,
    ) {
        let response = {
            let lock = self.subscriptions.lock().await;
            if let Some(subscription) = lock.chain_head_follow.get(follow_subscription_id) {
                subscription
                    .pinned_blocks_headers
                    .get(&hash.0)
                    .cloned()
                    .map(Some)
            } else {
                Some(None)
            }
        };

        if let Some(response) = response {
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    methods::Response::chainHead_unstable_header(response.map(methods::HexString))
                        .to_json_response(request_id),
                )
                .await;
        } else {
            // Reached if the subscription is valid but the block couldn't be found in
            // `pinned_blocks_headers`.
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        None,
                    ),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_stopBody`].
    pub(super) async fn chain_head_unstable_stop_body(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        subscription_id: &str,
    ) {
        let state_machine_subscription = if let Some((abort_handle, state_machine_subscription)) =
            self.subscriptions
                .lock()
                .await
                .misc
                .remove(&(subscription_id.to_owned(), SubscriptionTy::ChainHeadBody))
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
                methods::Response::chainHead_unstable_stopBody(()).to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_stopCall`].
    pub(super) async fn chain_head_unstable_stop_call(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        subscription_id: &str,
    ) {
        let state_machine_subscription = if let Some((abort_handle, state_machine_subscription)) =
            self.subscriptions
                .lock()
                .await
                .misc
                .remove(&(subscription_id.to_owned(), SubscriptionTy::ChainHeadCall))
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
                methods::Response::chainHead_unstable_stopCall(()).to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_stopStorage`].
    pub(super) async fn chain_head_unstable_stop_storage(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        subscription_id: &str,
    ) {
        let state_machine_subscription = if let Some((abort_handle, state_machine_subscription)) =
            self.subscriptions
                .lock()
                .await
                .misc
                .remove(&(subscription_id.to_owned(), SubscriptionTy::ChainHeadStorage))
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
                methods::Response::chainHead_unstable_stopStorage(()).to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_unfollow`].
    pub(super) async fn chain_head_unstable_unfollow(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        follow_subscription_id: &str,
    ) {
        if let Some(subscription) = self
            .subscriptions
            .lock()
            .await
            .chain_head_follow
            .remove(follow_subscription_id)
        {
            subscription.abort_handle.abort();
        }

        self.requests_subscriptions
            .respond(
                state_machine_request_id,
                methods::Response::chainHead_unstable_unfollow(()).to_json_response(request_id),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_unpin`].
    pub(super) async fn chain_head_unstable_unpin(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        follow_subscription_id: &str,
        hash: methods::HashHexString,
    ) {
        let valid = {
            let mut lock = self.subscriptions.lock().await;
            if let Some(subscription) = lock.chain_head_follow.get_mut(follow_subscription_id) {
                if subscription.pinned_blocks_headers.remove(&hash.0).is_some() {
                    if let Some(runtime_subscribe_all) = subscription.runtime_subscribe_all {
                        self.runtime_service
                            .unpin_block(runtime_subscribe_all, &hash.0)
                            .await;
                    }
                    true
                } else {
                    false
                }
            } else {
                true
            }
        };

        if valid {
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    methods::Response::chainHead_unstable_unpin(()).to_json_response(request_id),
                )
                .await;
        } else {
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        None,
                    ),
                )
                .await;
        }
    }
}
