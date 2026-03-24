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

// TODO: doc

use crate::json_rpc::{methods, parse};
use alloc::{
    borrow::Cow,
    boxed::Box,
    collections::VecDeque,
    string::{String, ToString as _},
    sync::{Arc, Weak},
};
use async_lock::Mutex;
use core::{
    cmp, fmt, mem,
    num::NonZero,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use futures_lite::FutureExt as _;
use slab::Slab;

pub use crate::json_rpc::parse::{ErrorResponse, ParseError};

/// See [module-level-documentation](..).
pub struct ClientMainTask {
    /// Because we move the task around a lot, all the fields are actually within a `Box`.
    inner: Box<Inner>,
}

struct Inner {
    /// Identifier to allocate to the new subscription requested by the user.
    // TODO: better strategy than just integers?
    next_subscription_id: u64,

    /// List of all active subscriptions. Keys are subscription IDs.
    ///
    /// Given that the subscription IDs are allocated locally, there is no harm in using a
    /// non-HashDoS-resilient hash function.
    ///
    /// Entries are removed only when the [`SubscriptionStartProcess`] or [`Subscription`] object
    /// is destroyed. This is necessary given that the maximum number of subscriptions exists in
    /// order to avoid spam attacks, and that resources are free'd only when the
    /// [`SubscriptionStartProcess`] or [`Subscription`] is destroyed.
    active_subscriptions: hashbrown::HashMap<String, InnerSubscription, fnv::FnvBuildHasher>,
    /// Maximum size that [`Inner::active_subscriptions`] is allowed to reach. Beyond this,
    /// subscription start requests are automatically denied.
    max_active_subscriptions: u32,

    /// Structure shared with the [`SerializedRequestsIo`].
    serialized_io: Arc<SerializedIo>,

    /// Queue where responses and subscriptions push responses/notifications.
    responses_notifications_queue: Arc<ResponsesNotificationsQueue>,

    /// Event notified after the [`SerializedRequestsIo`] is destroyed.
    on_serialized_requests_io_destroyed: event_listener::EventListener,
}

struct InnerSubscription {
    /// Shared with the subscription. Used to notify the subscription that it should be killed.
    kill_channel: Arc<SubscriptionKillChannel>,
    /// Response to an unsubscribe request that must be sent out once the subscription is killed.
    unsubscribe_response: Option<String>,
}

struct SerializedIo {
    /// Queue of requests. The requests are guaranteed to be a valid request JSON, but not
    /// necessarily to use a known method.
    requests_queue: crossbeam_queue::SegQueue<String>,

    /// Event notified after an element has been pushed to [`SerializedIo::requests_queue`].
    on_request_pushed: event_listener::Event,

    /// Event notified after an element from [`SerializedIo::requests_queue`] has been pulled.
    on_request_pulled_or_task_destroyed: event_listener::Event,

    /// Number of requests that have have been received from the client but whose answer hasn't
    /// been pulled out from [`SerializedIo::requests_queue`] yet.
    num_requests_in_fly: AtomicU32,

    /// Maximum value that [`SerializedIo::num_requests_in_fly`] is allowed to reach.
    /// Beyond this, no more request should be added to [`SerializedIo::requests_queue`].
    max_requests_in_fly: NonZero<u32>,

    /// Queue of responses.
    responses_queue: Mutex<SerializedIoResponses>,

    /// Event notified after an element has been pushed to [`SerializedIo::responses_queue`], or
    /// when the [`ClientMainTask`] has been destroyed.
    on_response_pushed_or_task_destroyed: event_listener::Event,
}

struct SerializedIoResponses {
    /// Unordered list of responses and notifications to send back to the client.
    ///
    /// Each entry contains the response/notification, and a boolean equal to `true` if this is
    /// a request response or `false` if this is a notification.
    pending_serialized_responses: Slab<(String, bool)>,

    /// Ordered list of responses and notifications to send back to the client, as indices within
    /// [`SerializedIoResponses::pending_serialized_responses`].
    pending_serialized_responses_queue: VecDeque<usize>,
}

/// Queue where responses and subscriptions push responses/notifications.
struct ResponsesNotificationsQueue {
    /// The actual queue.
    queue: crossbeam_queue::SegQueue<ToMainTask>,
    /// Maximum size that [`ResponsesNotificationsQueue::queue`] should reach.
    /// This is however not a hard limit. Pushing a response to a request and pushing a
    /// subscription destroyed event ignore this maximum (as doing so must always be lock-free),
    /// and pushing a notification checks against this limit in a racy way. For this reason, in
    /// the worst case scenario the queue can reach up to
    /// `max_requests_in_fly + max_active_subscriptions` elements. What matters, however, is that
    /// the queue is bounded in a way or the other more than the exact bound.
    max_len: usize,
    /// Event notified after an element from [`ResponsesNotificationsQueue::queue`] has been pushed.
    on_pushed: event_listener::Event,
    /// Event notified after an element from [`ResponsesNotificationsQueue::queue`] has been popped.
    on_popped: event_listener::Event,
}

// TODO: weird enum
enum ToMainTask {
    RequestResponse(String),
    Notification(String),
    SubscriptionDestroyed { subscription_id: String },
}

/// Configuration for [`client_main_task`].
pub struct Config {
    /// Maximum number of requests that have been sent by the [`SerializedRequestsIo`] but whose
    /// response hasn't been pulled through the [`SerializedRequestsIo`] yet.
    ///
    /// If this limit is reached, it is not possible to send further requests without pulling
    /// responses first.
    pub max_pending_requests: NonZero<u32>,

    /// Maximum number of simultaneous subscriptions allowed. Trying to create a subscription will
    /// be automatically rejected if this limit is reached.
    pub max_active_subscriptions: u32,
}

/// Creates a new [`ClientMainTask`] and a [`SerializedRequestsIo`] connected to it.
pub fn client_main_task(config: Config) -> (ClientMainTask, SerializedRequestsIo) {
    let buffers_capacity = usize::try_from(config.max_pending_requests.get())
        .unwrap_or(usize::MAX)
        .saturating_add(usize::try_from(config.max_active_subscriptions).unwrap_or(usize::MAX));

    let on_serialized_requests_io_destroyed = event_listener::Event::new();

    let task = ClientMainTask {
        inner: Box::new(Inner {
            next_subscription_id: 1,
            active_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                cmp::min(
                    usize::try_from(config.max_active_subscriptions).unwrap_or(usize::MAX),
                    32,
                ),
                Default::default(),
            ),
            max_active_subscriptions: config.max_active_subscriptions,
            serialized_io: Arc::new(SerializedIo {
                requests_queue: crossbeam_queue::SegQueue::new(),
                on_request_pushed: event_listener::Event::new(),
                on_request_pulled_or_task_destroyed: event_listener::Event::new(),
                num_requests_in_fly: AtomicU32::new(0),
                max_requests_in_fly: config.max_pending_requests,
                responses_queue: Mutex::new(SerializedIoResponses {
                    pending_serialized_responses_queue: VecDeque::with_capacity(cmp::min(
                        64,
                        buffers_capacity,
                    )),
                    pending_serialized_responses: Slab::with_capacity(cmp::min(
                        64,
                        buffers_capacity,
                    )),
                }),
                on_response_pushed_or_task_destroyed: event_listener::Event::new(),
            }),
            responses_notifications_queue: Arc::new(ResponsesNotificationsQueue {
                queue: crossbeam_queue::SegQueue::new(),
                max_len: buffers_capacity,
                on_pushed: event_listener::Event::new(),
                on_popped: event_listener::Event::new(),
            }),
            on_serialized_requests_io_destroyed: on_serialized_requests_io_destroyed.listen(),
        }),
    };

    let serialized_requests_io = SerializedRequestsIo {
        serialized_io: Arc::downgrade(&task.inner.serialized_io),
        on_serialized_requests_io_destroyed,
    };

    (task, serialized_requests_io)
}

impl ClientMainTask {
    /// Processes the task's internals and waits until something noteworthy happens.
    pub async fn run_until_event(mut self) -> Event {
        loop {
            enum WakeUpReason {
                NewRequest(String),
                Message(ToMainTask),
            }

            let wake_up_reason = {
                let serialized_requests_io_destroyed = async {
                    (&mut self.inner.on_serialized_requests_io_destroyed).await;
                    Err(())
                };

                let next_serialized_request = async {
                    let mut wait = None;
                    loop {
                        if let Some(elem) = self.inner.serialized_io.requests_queue.pop() {
                            self.inner
                                .serialized_io
                                .on_request_pulled_or_task_destroyed
                                .notify(usize::MAX);
                            break Ok(WakeUpReason::NewRequest(elem));
                        }
                        if let Some(wait) = wait.take() {
                            wait.await
                        } else {
                            wait = Some(self.inner.serialized_io.on_request_pushed.listen());
                        }
                    }
                };

                let response_notif = async {
                    let mut wait = None;
                    loop {
                        if let Some(elem) = self.inner.responses_notifications_queue.queue.pop() {
                            break Ok(WakeUpReason::Message(elem));
                        }
                        if let Some(wait) = wait.take() {
                            wait.await
                        } else {
                            wait =
                                Some(self.inner.responses_notifications_queue.on_pushed.listen());
                        }
                    }
                };

                match serialized_requests_io_destroyed
                    .or(next_serialized_request)
                    .or(response_notif)
                    .await
                {
                    Ok(wake_up_reason) => wake_up_reason,
                    Err(()) => return Event::SerializedRequestsIoClosed,
                }
            };

            // Immediately handle every event apart from `NewRequest`.
            let new_request = match wake_up_reason {
                WakeUpReason::NewRequest(request) => request,
                WakeUpReason::Message(ToMainTask::SubscriptionDestroyed { subscription_id }) => {
                    let InnerSubscription {
                        unsubscribe_response,
                        ..
                    } = self
                        .inner
                        .active_subscriptions
                        .remove(&subscription_id)
                        .unwrap();
                    // TODO: post a `stop`/`error` event for chainhead subscriptions
                    if let Some(unsubscribe_response) = unsubscribe_response {
                        let mut responses_queue =
                            self.inner.serialized_io.responses_queue.lock().await;
                        let pos = responses_queue
                            .pending_serialized_responses
                            .insert((unsubscribe_response, true));
                        responses_queue
                            .pending_serialized_responses_queue
                            .push_back(pos);
                        self.inner
                            .serialized_io
                            .on_response_pushed_or_task_destroyed
                            .notify(usize::MAX);
                    }

                    // Shrink the list of active subscriptions if necessary.
                    if self.inner.active_subscriptions.capacity()
                        >= 2 * self.inner.active_subscriptions.len() + 16
                    {
                        self.inner.active_subscriptions.shrink_to_fit();
                    }

                    return Event::SubscriptionDestroyed {
                        task: self,
                        subscription_id,
                    };
                }
                WakeUpReason::Message(ToMainTask::RequestResponse(response)) => {
                    let mut responses_queue = self.inner.serialized_io.responses_queue.lock().await;
                    let pos = responses_queue
                        .pending_serialized_responses
                        .insert((response, true));
                    responses_queue
                        .pending_serialized_responses_queue
                        .push_back(pos);
                    self.inner
                        .serialized_io
                        .on_response_pushed_or_task_destroyed
                        .notify(usize::MAX);
                    continue;
                }
                WakeUpReason::Message(ToMainTask::Notification(notification)) => {
                    // TODO: filter out redundant notifications, as it's the entire point of this module
                    let mut responses_queue = self.inner.serialized_io.responses_queue.lock().await;
                    let pos = responses_queue
                        .pending_serialized_responses
                        .insert((notification, false));
                    responses_queue
                        .pending_serialized_responses_queue
                        .push_back(pos);
                    self.inner
                        .serialized_io
                        .on_response_pushed_or_task_destroyed
                        .notify(usize::MAX);
                    continue;
                }
            };

            let (request_id, parsed_request) =
                match methods::parse_jsonrpc_client_to_server(&new_request) {
                    Ok((request_id, method)) => (request_id, method),
                    Err(methods::ParseClientToServerError::Method { request_id, error }) => {
                        let response = error.to_json_error(request_id);
                        let mut responses_queue =
                            self.inner.serialized_io.responses_queue.lock().await;
                        let pos = responses_queue
                            .pending_serialized_responses
                            .insert((response, true));
                        responses_queue
                            .pending_serialized_responses_queue
                            .push_back(pos);
                        self.inner
                            .serialized_io
                            .on_response_pushed_or_task_destroyed
                            .notify(usize::MAX);
                        continue;
                    }
                    Err(methods::ParseClientToServerError::UnknownNotification { .. }) => continue,
                    Err(methods::ParseClientToServerError::JsonRpcParse(_)) => {
                        let response = parse::build_parse_error_response();
                        let mut responses_queue =
                            self.inner.serialized_io.responses_queue.lock().await;
                        let pos = responses_queue
                            .pending_serialized_responses
                            .insert((response, true));
                        responses_queue
                            .pending_serialized_responses_queue
                            .push_back(pos);
                        self.inner
                            .serialized_io
                            .on_response_pushed_or_task_destroyed
                            .notify(usize::MAX);
                        continue;
                    }
                };

            // There exists three types of requests:
            //
            // - Requests that follow a simple one-request-one-response schema.
            // - Requests that, if accepted, start a subscription.
            // - Requests that unsubscribe from a subscription.
            //
            match &parsed_request {
                methods::MethodCall::account_nextIndex { .. }
                | methods::MethodCall::author_hasKey { .. }
                | methods::MethodCall::author_hasSessionKeys { .. }
                | methods::MethodCall::author_insertKey { .. }
                | methods::MethodCall::author_pendingExtrinsics { .. }
                | methods::MethodCall::author_removeExtrinsic { .. }
                | methods::MethodCall::author_rotateKeys { .. }
                | methods::MethodCall::author_submitExtrinsic { .. }
                | methods::MethodCall::babe_epochAuthorship { .. }
                | methods::MethodCall::bitswap_v1_get { .. }
                | methods::MethodCall::chain_getBlock { .. }
                | methods::MethodCall::chain_getBlockHash { .. }
                | methods::MethodCall::chain_getFinalizedHead { .. }
                | methods::MethodCall::chain_getHeader { .. }
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
                | methods::MethodCall::system_version { .. }
                | methods::MethodCall::chainSpec_v1_chainName { .. }
                | methods::MethodCall::chainSpec_v1_genesisHash { .. }
                | methods::MethodCall::chainSpec_v1_properties { .. }
                | methods::MethodCall::rpc_methods { .. }
                | methods::MethodCall::sudo_unstable_p2pDiscover { .. }
                | methods::MethodCall::sudo_unstable_version { .. }
                | methods::MethodCall::chainHead_v1_body { .. }
                | methods::MethodCall::chainHead_v1_call { .. }
                | methods::MethodCall::chainHead_v1_continue { .. }
                | methods::MethodCall::chainHead_unstable_finalizedDatabase { .. }
                | methods::MethodCall::chainHead_v1_header { .. }
                | methods::MethodCall::chainHead_v1_stopOperation { .. }
                | methods::MethodCall::chainHead_v1_storage { .. }
                | methods::MethodCall::chainHead_v1_unpin { .. } => {
                    // Simple one-request-one-response.
                    return Event::HandleRequest {
                        request_process: RequestProcess {
                            responses_notifications_queue: self
                                .inner
                                .responses_notifications_queue
                                .clone(),
                            request: new_request,
                            has_sent_response: false,
                        },
                        task: self,
                    };
                }

                methods::MethodCall::author_submitAndWatchExtrinsic { .. }
                | methods::MethodCall::chain_subscribeAllHeads { .. }
                | methods::MethodCall::chain_subscribeFinalizedHeads { .. }
                | methods::MethodCall::chain_subscribeNewHeads { .. }
                | methods::MethodCall::state_subscribeRuntimeVersion { .. }
                | methods::MethodCall::state_subscribeStorage { .. }
                | methods::MethodCall::transaction_v1_broadcast { .. }
                | methods::MethodCall::transactionWatch_v1_submitAndWatch { .. }
                | methods::MethodCall::sudo_network_unstable_watch { .. }
                | methods::MethodCall::chainHead_v1_follow { .. } => {
                    // Subscription starting requests.

                    // We must check the maximum number of subscriptions.
                    let max_subscriptions =
                        usize::try_from(self.inner.max_active_subscriptions).unwrap_or(usize::MAX);
                    debug_assert!(self.inner.active_subscriptions.len() <= max_subscriptions);
                    if self.inner.active_subscriptions.len() >= max_subscriptions {
                        let response = parse::build_error_response(
                            request_id,
                            ErrorResponse::ServerError(-32000, "Too many active subscriptions"),
                            None,
                        );
                        let mut responses_queue =
                            self.inner.serialized_io.responses_queue.lock().await;
                        let pos = responses_queue
                            .pending_serialized_responses
                            .insert((response, true));
                        responses_queue
                            .pending_serialized_responses_queue
                            .push_back(pos);
                        self.inner
                            .serialized_io
                            .on_response_pushed_or_task_destroyed
                            .notify(usize::MAX);
                        continue;
                    }

                    // Allocate the new subscription ID.
                    let subscription_id = self.allocate_subscription_id();
                    debug_assert!(
                        !self
                            .inner
                            .active_subscriptions
                            .contains_key(&subscription_id)
                    );

                    // Insert an "kill channel" in the local state. This kill channel is shared
                    // with the subscription object and is used to notify when a subscription
                    // should be killed.
                    let kill_channel = Arc::new(SubscriptionKillChannel {
                        dead: AtomicBool::new(false),
                        on_dead_changed: event_listener::Event::new(),
                    });
                    self.inner.active_subscriptions.insert(
                        subscription_id.clone(),
                        InnerSubscription {
                            kill_channel: kill_channel.clone(),
                            unsubscribe_response: None,
                        },
                    );

                    return Event::HandleSubscriptionStart {
                        subscription_start: SubscriptionStartProcess {
                            responses_notifications_queue: self
                                .inner
                                .responses_notifications_queue
                                .clone(),
                            request: new_request,
                            kill_channel,
                            subscription_id,
                            has_sent_response: false,
                        },
                        task: self,
                    };
                }

                methods::MethodCall::author_unwatchExtrinsic { subscription, .. }
                | methods::MethodCall::state_unsubscribeRuntimeVersion { subscription, .. }
                | methods::MethodCall::state_unsubscribeStorage { subscription, .. }
                | methods::MethodCall::transaction_v1_stop {
                    operation_id: subscription,
                }
                | methods::MethodCall::transactionWatch_v1_unwatch { subscription, .. }
                | methods::MethodCall::sudo_network_unstable_unwatch { subscription, .. }
                | methods::MethodCall::chainHead_v1_unfollow {
                    follow_subscription: subscription,
                    ..
                } => {
                    // TODO: must check whether type of subscription matches
                    match self.inner.active_subscriptions.get_mut(&**subscription) {
                        Some(InnerSubscription {
                            kill_channel,
                            unsubscribe_response,
                        }) if unsubscribe_response.is_none() => {
                            *unsubscribe_response = Some(
                                match parsed_request {
                                    methods::MethodCall::author_unwatchExtrinsic { .. } => {
                                        methods::Response::author_unwatchExtrinsic(true)
                                    }
                                    methods::MethodCall::state_unsubscribeRuntimeVersion {
                                        ..
                                    } => methods::Response::state_unsubscribeRuntimeVersion(true),
                                    methods::MethodCall::state_unsubscribeStorage { .. } => {
                                        methods::Response::state_unsubscribeStorage(true)
                                    }
                                    methods::MethodCall::transaction_v1_stop { .. } => {
                                        methods::Response::transaction_v1_stop(())
                                    }
                                    methods::MethodCall::transactionWatch_v1_unwatch { .. } => {
                                        methods::Response::transactionWatch_v1_unwatch(())
                                    }
                                    methods::MethodCall::sudo_network_unstable_unwatch {
                                        ..
                                    } => methods::Response::sudo_network_unstable_unwatch(()),
                                    methods::MethodCall::chainHead_v1_unfollow { .. } => {
                                        methods::Response::chainHead_v1_unfollow(())
                                    }
                                    _ => unreachable!(),
                                }
                                .to_json_response(request_id),
                            );

                            kill_channel.dead.store(true, Ordering::Release);
                            kill_channel.on_dead_changed.notify(usize::MAX);
                        }
                        _ => {
                            let response = match parsed_request {
                                methods::MethodCall::author_unwatchExtrinsic { .. } => {
                                    methods::Response::author_unwatchExtrinsic(false)
                                        .to_json_response(request_id)
                                }
                                methods::MethodCall::state_unsubscribeRuntimeVersion { .. } => {
                                    methods::Response::state_unsubscribeRuntimeVersion(false)
                                        .to_json_response(request_id)
                                }
                                methods::MethodCall::state_unsubscribeStorage { .. } => {
                                    methods::Response::state_unsubscribeStorage(false)
                                        .to_json_response(request_id)
                                }
                                _ => parse::build_error_response(
                                    request_id,
                                    ErrorResponse::InvalidParams,
                                    None,
                                ),
                            };

                            let mut responses_queue =
                                self.inner.serialized_io.responses_queue.lock().await;
                            let pos = responses_queue
                                .pending_serialized_responses
                                .insert((response, true));
                            responses_queue
                                .pending_serialized_responses_queue
                                .push_back(pos);
                            self.inner
                                .serialized_io
                                .on_response_pushed_or_task_destroyed
                                .notify(usize::MAX);
                        }
                    }
                }
                methods::MethodCall::chain_unsubscribeAllHeads { subscription, .. }
                | methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription, .. }
                | methods::MethodCall::chain_unsubscribeNewHeads { subscription, .. } => {
                    // TODO: DRY with above
                    // TODO: must check whether type of subscription matches
                    match self.inner.active_subscriptions.get_mut(&**subscription) {
                        Some(InnerSubscription {
                            unsubscribe_response,
                            kill_channel,
                        }) if unsubscribe_response.is_none() => {
                            *unsubscribe_response = Some(match parsed_request {
                                methods::MethodCall::chain_unsubscribeAllHeads { .. } => {
                                    methods::Response::chain_unsubscribeAllHeads(true)
                                        .to_json_response(request_id)
                                }
                                methods::MethodCall::chain_unsubscribeFinalizedHeads { .. } => {
                                    methods::Response::chain_unsubscribeFinalizedHeads(true)
                                        .to_json_response(request_id)
                                }
                                methods::MethodCall::chain_unsubscribeNewHeads { .. } => {
                                    methods::Response::chain_unsubscribeNewHeads(true)
                                        .to_json_response(request_id)
                                }
                                _ => unreachable!(),
                            });

                            kill_channel.dead.store(true, Ordering::Release);
                            kill_channel.on_dead_changed.notify(usize::MAX);
                        }
                        _ => {
                            let response = match parsed_request {
                                methods::MethodCall::chain_unsubscribeAllHeads { .. } => {
                                    methods::Response::chain_unsubscribeAllHeads(false)
                                        .to_json_response(request_id)
                                }
                                methods::MethodCall::chain_unsubscribeFinalizedHeads { .. } => {
                                    methods::Response::chain_unsubscribeFinalizedHeads(false)
                                        .to_json_response(request_id)
                                }
                                methods::MethodCall::chain_unsubscribeNewHeads { .. } => {
                                    methods::Response::chain_unsubscribeNewHeads(false)
                                        .to_json_response(request_id)
                                }
                                _ => unreachable!(),
                            };

                            let mut responses_queue =
                                self.inner.serialized_io.responses_queue.lock().await;
                            let pos = responses_queue
                                .pending_serialized_responses
                                .insert((response, true));
                            responses_queue
                                .pending_serialized_responses_queue
                                .push_back(pos);
                            self.inner
                                .serialized_io
                                .on_response_pushed_or_task_destroyed
                                .notify(usize::MAX);
                        }
                    }
                }
            }
        }
    }

    fn allocate_subscription_id(&mut self) -> String {
        let subscription_id = self.inner.next_subscription_id.to_string();
        self.inner.next_subscription_id += 1;
        subscription_id
    }
}

impl fmt::Debug for ClientMainTask {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ClientMainTask").finish()
    }
}

impl Drop for ClientMainTask {
    fn drop(&mut self) {
        // Notify the `SerializedRequestsIo`.
        self.inner
            .serialized_io
            .on_response_pushed_or_task_destroyed
            .notify(usize::MAX);
        self.inner
            .serialized_io
            .on_request_pulled_or_task_destroyed
            .notify(usize::MAX);

        // Mark all active subscriptions as dead.
        for (_, InnerSubscription { kill_channel, .. }) in self.inner.active_subscriptions.drain() {
            kill_channel.dead.store(true, Ordering::Release);
            kill_channel.on_dead_changed.notify(usize::MAX);
        }
    }
}

/// Outcome of the processing of [`ClientMainTask::run_until_event`].
#[derive(Debug)]
pub enum Event {
    /// JSON-RPC client has sent a plain request (i.e. that isn't related to subscriptions).
    HandleRequest {
        /// The task that generated the event.
        task: ClientMainTask,
        /// Object connected to the [`ClientMainTask`] and containing the information about the
        /// request to process.
        request_process: RequestProcess,
    },

    /// JSON-RPC client desires starting a new subscription.
    ///
    /// Note that the [`ClientMainTask`] automatically enforces a limit to the maximum number of
    /// subscriptions. If this event is generated, this check has already passed.
    HandleSubscriptionStart {
        /// The task that generated the event.
        task: ClientMainTask,
        /// Object connected to the [`ClientMainTask`] and containing the information about the
        /// request to process.
        subscription_start: SubscriptionStartProcess,
    },

    /// A [`SubscriptionStartProcess`] object or a [`Subscription`] object has been destroyed.
    SubscriptionDestroyed {
        /// The task that generated the event.
        task: ClientMainTask,
        /// Id of the subscription that was destroyed. Equals to the value that
        /// [`Subscription::subscription_id`] would have returned for the now-dead subscription.
        subscription_id: String,
    },

    /// The [`SerializedRequestsIo`] has been dropped. The [`ClientMainTask`] has been destroyed.
    SerializedRequestsIoClosed,
}

/// Object connected to the [`ClientMainTask`] that allows sending requests to the task and
/// receiving responses.
pub struct SerializedRequestsIo {
    serialized_io: Weak<SerializedIo>,

    /// Event notified after the [`SerializedRequestsIo`] is destroyed.
    on_serialized_requests_io_destroyed: event_listener::Event,
}

impl SerializedRequestsIo {
    /// Waits for a response or a notification to send to the JSON-RPC client to be available,
    /// and returns it.
    ///
    /// Returns `None` if the [`ClientMainTask`] has been destroyed.
    ///
    /// > **Note**: It is important to run [`ClientMainTask::run_until_event`] concurrently to
    /// >           this function, otherwise it might never return.
    pub async fn wait_next_response(&self) -> Result<String, WaitNextResponseError> {
        let mut wait = None;

        loop {
            let Some(queue) = self.serialized_io.upgrade() else {
                return Err(WaitNextResponseError::ClientMainTaskDestroyed);
            };

            // Lock the responses queue.
            {
                let mut responses_queue = queue.responses_queue.lock().await;

                if let Some(response_index) = responses_queue
                    .pending_serialized_responses_queue
                    .pop_front()
                {
                    let (response_or_notif, is_response) = responses_queue
                        .pending_serialized_responses
                        .remove(response_index);

                    if is_response {
                        let _prev_val = queue.num_requests_in_fly.fetch_sub(1, Ordering::Release);
                        debug_assert_ne!(_prev_val, u32::MAX); // Check underflows.
                    }

                    // Shrink containers if necessary in order to reduce memory usage after a
                    // burst of requests.
                    if responses_queue.pending_serialized_responses.capacity()
                        > responses_queue
                            .pending_serialized_responses
                            .len()
                            .saturating_mul(4)
                    {
                        responses_queue.pending_serialized_responses.shrink_to_fit();
                    }
                    if responses_queue
                        .pending_serialized_responses_queue
                        .capacity()
                        > responses_queue
                            .pending_serialized_responses_queue
                            .len()
                            .saturating_mul(4)
                    {
                        responses_queue
                            .pending_serialized_responses_queue
                            .shrink_to_fit();
                    }

                    return Ok(response_or_notif);
                }
            }

            if let Some(wait) = wait.take() {
                wait.await
            } else {
                wait = Some(queue.on_response_pushed_or_task_destroyed.listen());
            }
        }
    }

    /// Adds a JSON-RPC request to the queue of requests of the [`ClientMainTask`]. Waits if the
    /// queue is full.
    ///
    /// This might cause a call to [`ClientMainTask::run_until_event`] to return
    /// [`Event::HandleRequest`] or [`Event::HandleSubscriptionStart`].
    pub async fn send_request(&self, request: String) -> Result<(), SendRequestError> {
        // Wait until it is possible to increment `num_requests_in_fly`.
        let mut wait = None;
        let queue = loop {
            let Some(queue) = self.serialized_io.upgrade() else {
                return Err(SendRequestError {
                    request,
                    cause: SendRequestErrorCause::ClientMainTaskDestroyed,
                });
            };

            if queue
                .num_requests_in_fly
                .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |old_value| {
                    if old_value < queue.max_requests_in_fly.get() {
                        // Considering that `old_value < max`, and `max` fits in a `u32` by
                        // definition, then `old_value + 1` also always fits in a `u32`. QED.
                        // There's no risk of overflow.
                        Some(old_value + 1)
                    } else {
                        None
                    }
                })
                .is_ok()
            {
                break queue;
            }

            if let Some(wait) = wait.take() {
                wait.await;
            } else {
                wait = Some(queue.on_request_pulled_or_task_destroyed.listen());
            }
        };

        // Everything successful.
        queue.requests_queue.push(request);
        queue.on_request_pushed.notify(usize::MAX);
        Ok(())
    }

    /// Tries to add a JSON-RPC request to the queue of requests of the [`ClientMainTask`].
    ///
    /// This might cause a call to [`ClientMainTask::run_until_event`] to return
    /// [`Event::HandleRequest`] or [`Event::HandleSubscriptionStart`].
    pub fn try_send_request(&self, request: String) -> Result<(), TrySendRequestError> {
        let Some(queue) = self.serialized_io.upgrade() else {
            return Err(TrySendRequestError {
                request,
                cause: TrySendRequestErrorCause::ClientMainTaskDestroyed,
            });
        };

        // Try to increment `num_requests_in_fly`. Return an error if it is past the maximum.
        if queue
            .num_requests_in_fly
            .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |old_value| {
                if old_value < queue.max_requests_in_fly.get() {
                    // Considering that `old_value < max`, and `max` fits in a `u32` by
                    // definition, then `old_value + 1` also always fits in a `u32`. QED.
                    // There's no risk of overflow.
                    Some(old_value + 1)
                } else {
                    None
                }
            })
            .is_err()
        {
            return Err(TrySendRequestError {
                request,
                cause: TrySendRequestErrorCause::TooManyPendingRequests,
            });
        }

        // Everything successful.
        queue.requests_queue.push(request);
        queue.on_request_pushed.notify(usize::MAX);
        Ok(())
    }
}

impl fmt::Debug for SerializedRequestsIo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SerializedRequestsIo").finish()
    }
}

impl Drop for SerializedRequestsIo {
    fn drop(&mut self) {
        self.on_serialized_requests_io_destroyed.notify(usize::MAX);
    }
}

/// See [`SerializedRequestsIo::wait_next_response`].
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub enum WaitNextResponseError {
    /// The attached [`ClientMainTask`] has been destroyed.
    ClientMainTaskDestroyed,
}

/// Error returned by [`SerializedRequestsIo::send_request`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display("{cause}")]
pub struct SendRequestError {
    /// The JSON-RPC request that was passed as parameter.
    pub request: String,
    /// Reason for the error.
    #[error(source)]
    pub cause: SendRequestErrorCause,
}

/// See [`SendRequestError::cause`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum SendRequestErrorCause {
    /// The attached [`ClientMainTask`] has been destroyed.
    ClientMainTaskDestroyed,
}

/// Error returned by [`SerializedRequestsIo::try_send_request`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display("{cause}")]
pub struct TrySendRequestError {
    /// The JSON-RPC request that was passed as parameter.
    pub request: String,
    /// Reason for the error.
    #[error(source)]
    pub cause: TrySendRequestErrorCause,
}

/// See [`TrySendRequestError::cause`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum TrySendRequestErrorCause {
    /// Limit to the maximum number of pending requests that was passed as
    /// [`Config::max_pending_requests`] has been reached. No more requests can be sent before
    /// some responses have been pulled.
    TooManyPendingRequests,
    /// The attached [`ClientMainTask`] has been destroyed.
    ClientMainTaskDestroyed,
}

/// Object connected to the [`ClientMainTask`] and containing a request expecting an answer.
///
/// If this object is dropped before the request has been answered, an automatic "internal error"
/// error response is automatically sent back.
pub struct RequestProcess {
    /// Queue where responses and subscriptions push responses/notifications.
    responses_notifications_queue: Arc<ResponsesNotificationsQueue>,
    /// Request in JSON form. Guaranteed to decode successfully.
    request: String,
    /// `true` if a response has already been sent.
    has_sent_response: bool,
}

impl RequestProcess {
    /// Returns the request which must be processed.
    ///
    /// The request is guaranteed to not be related to subscriptions in any way.
    // TODO: with stronger typing users wouldn't have to worry about the type of request
    pub fn request(&'_ self) -> methods::MethodCall<'_> {
        methods::parse_jsonrpc_client_to_server(&self.request)
            .unwrap()
            .1
    }

    /// Indicate the response to the request to the [`ClientMainTask`].
    ///
    /// Has no effect if the [`ClientMainTask`] has been destroyed.
    pub fn respond(mut self, response: methods::Response) {
        let request_id = methods::parse_jsonrpc_client_to_server(&self.request)
            .unwrap()
            .0;
        let serialized = response.to_json_response(request_id);
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::RequestResponse(serialized));
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::MAX);
        self.has_sent_response = true;
    }

    /// Indicate to the [`ClientMainTask`] that the response to the request is `null`.
    ///
    /// Has no effect if the [`ClientMainTask`] has been destroyed.
    // TODO: the necessity for this function is basically a hack
    pub fn respond_null(mut self) {
        let request_id = methods::parse_jsonrpc_client_to_server(&self.request)
            .unwrap()
            .0;
        let serialized = parse::build_success_response(request_id, "null");
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::RequestResponse(serialized));
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::MAX);
        self.has_sent_response = true;
    }

    /// Indicate to the [`ClientMainTask`] that the request should return an error.
    ///
    /// Has no effect if the [`ClientMainTask`] has been destroyed.
    pub fn fail(mut self, error: ErrorResponse) {
        let request_id = methods::parse_jsonrpc_client_to_server(&self.request)
            .unwrap()
            .0;
        let serialized = parse::build_error_response(request_id, error, None);
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::RequestResponse(serialized));
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::MAX);
        self.has_sent_response = true;
    }

    /// Indicate to the [`ClientMainTask`] that the request should return an error.
    ///
    /// This function is similar to [`RequestProcess`], except that an additional JSON payload is
    /// attached to the error.
    ///
    /// Has no effect if the [`ClientMainTask`] has been destroyed.
    pub fn fail_with_attached_json(mut self, error: ErrorResponse, json: &str) {
        let request_id = methods::parse_jsonrpc_client_to_server(&self.request)
            .unwrap()
            .0;
        let serialized = parse::build_error_response(request_id, error, Some(json));
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::RequestResponse(serialized));
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::MAX);
        self.has_sent_response = true;
    }
}

impl fmt::Debug for RequestProcess {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.request, f)
    }
}

impl Drop for RequestProcess {
    fn drop(&mut self) {
        if !self.has_sent_response {
            let request_id = methods::parse_jsonrpc_client_to_server(&self.request)
                .unwrap()
                .0;
            let serialized =
                parse::build_error_response(request_id, ErrorResponse::InternalError, None);
            self.responses_notifications_queue
                .queue
                .push(ToMainTask::RequestResponse(serialized));
            self.responses_notifications_queue
                .on_pushed
                .notify(usize::MAX);
        }
    }
}

/// Object connected to the [`ClientMainTask`] and containing a request that leads to the creation
/// of a subscription.
///
/// If this object is dropped before the request has been answered, an automatic "internal error"
/// error response is automatically sent back.
pub struct SubscriptionStartProcess {
    /// Queue where responses and subscriptions push responses/notifications.
    responses_notifications_queue: Arc<ResponsesNotificationsQueue>,
    /// `Arc` shared with the client main task and that is used to notify that the subscription
    /// should be killed.
    kill_channel: Arc<SubscriptionKillChannel>,
    /// Request in JSON form. Guaranteed to decode successfully.
    request: String,
    /// Identifier of the subscription. Assigned by the client task.
    subscription_id: String,
    /// `true` if a response has already been sent.
    has_sent_response: bool,
}

impl SubscriptionStartProcess {
    /// Returns the request which must be processed.
    ///
    /// The request is guaranteed to be a request that starts a subscription.
    // TODO: with stronger typing users wouldn't have to worry about the type of request
    pub fn request(&'_ self) -> methods::MethodCall<'_> {
        methods::parse_jsonrpc_client_to_server(&self.request)
            .unwrap()
            .1
    }

    /// Indicate to the [`ClientMainTask`] that the subscription is accepted.
    ///
    /// The [`ClientMainTask`] will send the confirmation to the JSON-RPC client.
    ///
    /// Has no effect if the [`ClientMainTask`] has been destroyed.
    pub fn accept(mut self) -> Subscription {
        let (request_id, parsed_request) =
            methods::parse_jsonrpc_client_to_server(&self.request).unwrap();

        let serialized_response = match parsed_request {
            methods::MethodCall::author_submitAndWatchExtrinsic { .. } => {
                methods::Response::author_submitAndWatchExtrinsic(Cow::Borrowed(
                    &self.subscription_id,
                ))
            }
            methods::MethodCall::chain_subscribeAllHeads { .. } => {
                methods::Response::chain_subscribeAllHeads(Cow::Borrowed(&self.subscription_id))
            }
            methods::MethodCall::chain_subscribeFinalizedHeads { .. } => {
                methods::Response::chain_subscribeFinalizedHeads(Cow::Borrowed(
                    &self.subscription_id,
                ))
            }
            methods::MethodCall::chain_subscribeNewHeads { .. } => {
                methods::Response::chain_subscribeNewHeads(Cow::Borrowed(&self.subscription_id))
            }
            methods::MethodCall::state_subscribeRuntimeVersion { .. } => {
                methods::Response::state_subscribeRuntimeVersion(Cow::Borrowed(
                    &self.subscription_id,
                ))
            }
            methods::MethodCall::state_subscribeStorage { .. } => {
                methods::Response::state_subscribeStorage(Cow::Borrowed(&self.subscription_id))
            }
            methods::MethodCall::transactionWatch_v1_submitAndWatch { .. } => {
                methods::Response::transactionWatch_v1_submitAndWatch(Cow::Borrowed(
                    &self.subscription_id,
                ))
            }
            methods::MethodCall::sudo_network_unstable_watch { .. } => {
                methods::Response::sudo_network_unstable_watch(Cow::Borrowed(&self.subscription_id))
            }
            methods::MethodCall::chainHead_v1_follow { .. } => {
                methods::Response::chainHead_v1_follow(Cow::Borrowed(&self.subscription_id))
            }
            _ => unreachable!(),
        }
        .to_json_response(request_id);

        self.responses_notifications_queue
            .queue
            .push(ToMainTask::RequestResponse(serialized_response));
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::MAX);
        self.has_sent_response = true;

        Subscription {
            responses_notifications_queue: self.responses_notifications_queue.clone(),
            kill_channel: self.kill_channel.clone(),
            subscription_id: mem::take(&mut self.subscription_id),
        }
    }

    /// Indicate to the [`ClientMainTask`] that the subscription start request should return an
    /// error.
    ///
    /// Has no effect if the [`ClientMainTask`] has been destroyed.
    pub fn fail(mut self, error: ErrorResponse) {
        let request_id = methods::parse_jsonrpc_client_to_server(&self.request)
            .unwrap()
            .0;
        let serialized = parse::build_error_response(request_id, error, None);
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::RequestResponse(serialized));
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::SubscriptionDestroyed {
                subscription_id: mem::take(&mut self.subscription_id),
            });
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::MAX);
        self.has_sent_response = true;
    }
}

impl fmt::Debug for SubscriptionStartProcess {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.request, f)
    }
}

impl Drop for SubscriptionStartProcess {
    fn drop(&mut self) {
        if !self.has_sent_response {
            let request_id = methods::parse_jsonrpc_client_to_server(&self.request)
                .unwrap()
                .0;
            let serialized =
                parse::build_error_response(request_id, ErrorResponse::InternalError, None);
            self.responses_notifications_queue
                .queue
                .push(ToMainTask::RequestResponse(serialized));
            self.responses_notifications_queue
                .queue
                .push(ToMainTask::SubscriptionDestroyed {
                    subscription_id: mem::take(&mut self.subscription_id),
                });
            self.responses_notifications_queue
                .on_pushed
                .notify(usize::MAX);
        }
    }
}

/// Object connected to the [`ClientMainTask`] representing an active subscription.
pub struct Subscription {
    /// Queue where responses and subscriptions push responses/notifications.
    responses_notifications_queue: Arc<ResponsesNotificationsQueue>,
    /// `Arc` shared with the client main task and that is used to notify that the subscription
    /// should be killed.
    kill_channel: Arc<SubscriptionKillChannel>,
    /// Identifier of the subscription. Assigned by the client task.
    subscription_id: String,
}

/// See [`Subscription::kill_channel`].
struct SubscriptionKillChannel {
    /// `true` if this subscription should be destroyed as soon as possible.
    dead: AtomicBool,
    /// Notified whenever [`SubscriptionKillChannel::dead`] is modified.
    on_dead_changed: event_listener::Event,
}

impl Subscription {
    /// Return the identifier of this subscription. Necessary in order to generate answers.
    pub fn subscription_id(&self) -> &str {
        &self.subscription_id
    }

    /// Send a notification the [`ClientMainTask`].
    ///
    /// Has no effect if [`Subscription::is_stale`] would return `true`.
    ///
    /// This notification might end up being discarded if the queue of responses to send back to
    /// the JSON-RPC client is full and/or if the notification is redundant with another
    /// notification sent earlier.
    ///
    /// While this function is asynchronous, it is expected to not take very long provided that
    /// [`ClientMainTask::run_until_event`] is called in parallel.
    ///
    /// > **Note**: It is important to run [`ClientMainTask::run_until_event`] concurrently to
    /// >           this function, otherwise it might never return.
    // TODO: with stronger typing we could automatically fill the subscription_id
    pub async fn send_notification(&mut self, notification: methods::ServerToClient<'_>) {
        let serialized = notification.to_json_request_object_parameters(None);

        // Wait until there is space in the queue or that the subscription is dead.
        // Note that this is intentionally racy.
        {
            let mut wait = None;
            loop {
                // If the subscription is dead, simply do nothing. This is purely an optimization.
                if self.kill_channel.dead.load(Ordering::Relaxed) {
                    return;
                }

                // If there is space, break out of the loop in order to send.
                if self.responses_notifications_queue.queue.len()
                    < self.responses_notifications_queue.max_len
                {
                    break;
                }

                if let Some(wait) = wait.take() {
                    wait.await
                } else {
                    wait = Some(
                        self.responses_notifications_queue
                            .on_popped
                            .listen()
                            .or(self.kill_channel.on_dead_changed.listen()),
                    );
                }
            }
        }

        // Actually push the element.
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::Notification(serialized));
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::MAX);
    }

    /// Returns `true` if the JSON-RPC client has unsubscribed, or the [`ClientMainTask`] has been
    /// destroyed, or the queue of responses to send to the JSON-RPC client is clogged and the
    /// logic of the subscription requires that it stops altogether in that situation.
    ///
    /// Due to the racy nature of this function, a value of `false` can at any moment switch to
    /// `true` and thus should be interpreted as "maybe". A value of `true`, however, actually
    /// means "yes", as it can't ever switch back to `false`.
    pub fn is_stale(&self) -> bool {
        self.kill_channel.dead.load(Ordering::Relaxed)
    }

    /// Run indefinitely until [`Subscription::is_stale`] returns `true`.
    pub async fn wait_until_stale(&mut self) {
        // The control flow of this function is a bit magic, but simple enough that it should be
        // easy to understand.
        let mut wait = None;
        loop {
            if self.kill_channel.dead.load(Ordering::Acquire) {
                return;
            }

            if let Some(wait) = wait.take() {
                wait.await;
            } else {
                wait = Some(self.kill_channel.on_dead_changed.listen());
            }
        }
    }
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Subscription")
            .field(&self.subscription_id)
            .finish()
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::SubscriptionDestroyed {
                subscription_id: mem::take(&mut self.subscription_id),
            });
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::MAX);
    }
}
