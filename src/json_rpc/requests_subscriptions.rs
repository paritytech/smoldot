// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
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

//! The [`RequestsSubscriptions`] state machine holds a list of clients, pending outgoing messages,
//! pending requests, and active subscriptions.
//!
//! The code in this module is the frontline of the JSON-RPC server. It can be subject to DoS
//! attacks, and should therefore make sure to properly distribute resources between JSON-RPC
//! clients.

use alloc::{
    collections::{BTreeMap, VecDeque},
    string::String,
    sync::{Arc, Weak},
};
use core::{
    cmp, fmt, hash,
    sync::atomic::{AtomicUsize, Ordering},
};
use futures::lock::Mutex;

#[derive(Clone)]
pub struct ClientId(u64, Weak<ClientInner>);

#[derive(Clone)]
pub struct RequestId(u64, Weak<ClientInner>);

#[derive(Clone)]
pub struct SubscriptionId(u64, Weak<ClientInner>);

pub struct RequestsSubscriptions {
    clients: Mutex<Clients>,

    /// List of requests sent by a client and not yet pulled by
    /// [`RequestsSubscriptions::next_request`].
    ///
    /// Can contain obsolete clients, in which case the entry should simply be ignored.
    unpulled_requests: crossbeam_queue::ArrayQueue<(String, Weak<ClientInner>)>,

    /// Event notified whenever an element is pushed to [`RequestsSubscriptions::unpulled_requests`].
    new_unpulled_request: event_listener::Event,

    /// Next identifier to assign to the next request.
    ///
    /// Matches the values found in [`Mutex<ClientInnerQueue>::pending_requests`].
    next_request_id: atomic::Atomic<u64>,

    /// Next identifier to assign to the next subscription.
    ///
    /// Matches the values found in TODO.
    next_subscription_id: atomic::Atomic<u64>,

    /// Maximum number of clients simultaneously allowed.
    ///
    /// The value here can change at runtime.
    max_clients: AtomicUsize,

    /// Maximum number of requests each client can send before having to wait for some of its
    /// earlier requests to have been answered.
    max_requests_per_client: usize,

    /// Maximum number of subscriptions each client can have active before new subscriptions are
    /// rejected.
    max_subscriptions_per_client: usize,
}
impl RequestsSubscriptions {
    /// Creates a new empty state machine.
    pub fn new() -> Self {
        let max_requests_per_client = 8;
        let max_clients = 128;
        let max_subscriptions_per_client = 32;

        Self {
            clients: Mutex::new(Clients {
                list: hashbrown::HashMap::with_capacity_and_hasher(8, Default::default()),
                next_id: 0,
            }),
            unpulled_requests: crossbeam_queue::ArrayQueue::new(
                max_requests_per_client * max_clients,
            ),
            new_unpulled_request: event_listener::Event::new(),
            next_request_id: atomic::Atomic::new(0),
            next_subscription_id: atomic::Atomic::new(0),
            max_clients: AtomicUsize::new(max_clients),
            max_requests_per_client,
            max_subscriptions_per_client,
        }
    }

    /// Changes the maximum number of allowed clients.
    ///
    /// Note that the ordering of this operation is `Relaxed`, meaning that this change will apply
    /// some time in the future and not necessarily immediately.
    ///
    /// Lowering the maximum number of allowed clients below the current number will *not*
    /// remove existing clients. If this is desired, this must be done manually by calling
    /// [`RequestsSubscriptions::remove_client`].
    ///
    /// > **Note**: This function can typically be used at runtime to adjust the maximum number
    /// >           of clients based on the resource consumptions of the binary.
    pub fn set_max_clients(&self, max_clients: usize) {
        // TODO: this doesn't update the capacityu of `unpulled_requests`; is this a problem?
        self.max_clients.store(max_clients, Ordering::Relaxed)
    }

    /// Adds a new client to the state machine. A new [`ClientId`] is attributed.
    ///
    /// Can return an error if the maximum simultaneous number of clients has been reached.
    ///
    /// A single instance of [`RequestsSubscriptions`] will never allocate multiple times the same
    /// [`ClientId`].
    pub async fn add_client(&self) -> Result<ClientId, AddClientError> {
        let mut clients = self.clients.lock().await;
        if clients.list.len() == self.max_clients.load(Ordering::Relaxed) {
            return Err(AddClientError::LimitReached);
        }

        let arc = Arc::new(ClientInner {
            request_answered: event_listener::Event::new(),
            total_requests_in_fly: AtomicUsize::new(0),
            guarded: Mutex::new(ClientInnerGuarded {
                pending_requests: hashbrown::HashSet::with_capacity_and_hasher(
                    self.max_requests_per_client,
                    Default::default(),
                ),
                responses_send_back: VecDeque::with_capacity(self.max_requests_per_client),
                notification_messages: BTreeMap::new(),
                message_pushed: event_listener::Event::new(),
                active_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
                    self.max_subscriptions_per_client,
                    Default::default(),
                ),
            }),
        });

        let new_client_id = clients.next_id;
        clients.next_id += 1;

        let ret = ClientId(new_client_id, Arc::downgrade(&arc));
        clients.list.insert(new_client_id, arc);
        Ok(ret)
    }

    /// Similar to [`RequestsSubscriptions::add_client`], but non-async and takes `self` as `&mut`.
    ///
    /// > **Note**: This function is notably useful for adding clients at initialization, when
    /// >           outside of an asynchronous context.
    pub fn add_client_mut(&mut self) -> Result<ClientId, AddClientError> {
        // TODO: DRY with add_client
        let clients = self.clients.get_mut();
        if clients.list.len() == self.max_clients.load(Ordering::Relaxed) {
            return Err(AddClientError::LimitReached);
        }

        let arc = Arc::new(ClientInner {
            request_answered: event_listener::Event::new(),
            total_requests_in_fly: AtomicUsize::new(0),
            guarded: Mutex::new(ClientInnerGuarded {
                pending_requests: hashbrown::HashSet::with_capacity_and_hasher(
                    self.max_requests_per_client,
                    Default::default(),
                ),
                responses_send_back: VecDeque::with_capacity(self.max_requests_per_client),
                notification_messages: BTreeMap::new(),
                message_pushed: event_listener::Event::new(),
                active_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
                    self.max_subscriptions_per_client,
                    Default::default(),
                ),
            }),
        });

        let new_client_id = clients.next_id;
        clients.next_id += 1;

        let ret = ClientId(new_client_id, Arc::downgrade(&arc));
        clients.list.insert(new_client_id, arc);
        Ok(ret)
    }

    /// Removes from the state machine the client with the given id.
    ///
    /// This function invalidates all active requests and subscriptions that related to this
    /// client. The concerned [`RequestId`]s and [`SubscriptionId`]s are returned by this
    /// function.
    ///
    /// Note however that functions such as [`RequestSubscriptions::respond`] and
    /// [`RequestSubscriptions::push_notification`] have no effect if you pass an invalid
    /// [`RequestId`] or [`SubscriptionId`]. There is therefore no need to cancel any parallel
    /// task that might currently be responding to requests or pushing notification messages.
    // TODO: return all active requests and subscriptions
    pub async fn remove_client(&self, client: &ClientId) {
        let mut clients = self.clients.lock().await;

        if let Some(removed) = clients.list.remove(&client.0) {
            debug_assert!(Arc::ptr_eq(&removed, &client.1.upgrade().unwrap()));
        }

        // Shrink `clients.list` in order to potentially reclaim memory after a huge spike in
        // number of clients.
        if clients.list.capacity() >= clients.list.len() * 2 {
            clients.list.shrink_to_fit();
        }
    }

    /// Waits until a message is available in the queue of messages to send back to the given
    /// client, then extracts it.
    ///
    /// This asynchronous function can take a long time, as it blocks until a message is
    /// available.
    ///
    /// If the [`ClientId`] no longer exists because of a call to [`RequestsSubscriptions`], then
    /// this function never returns. It is the responsibility of the API user to not call this
    /// function or to interrupt a pending function call with a stale [`ClientId`].
    pub async fn next_response(&self, client: &ClientId) -> String {
        loop {
            let client = match client.1.upgrade() {
                Some(c) => c,
                None => {
                    // Freeze forever.
                    futures::pending!();
                    continue;
                }
            };

            let sleep_until = {
                let mut queue_lock = client.guarded.lock().await;
                match queue_lock.responses_send_back.pop_front() {
                    Some(ResponseSendBack::Response(message)) => {
                        let _new_val = client.total_requests_in_fly.fetch_sub(1, Ordering::Release);
                        debug_assert_ne!(_new_val, usize::max_value()); // Check for underflows
                        client.request_answered.notify_additional(1);
                        return message;
                    }
                    Some(ResponseSendBack::SubscriptionMessage(index)) => {
                        todo!()
                    }
                    None => {}
                }

                queue_lock.message_pushed.listen()
            };

            sleep_until.await
        }
    }

    /// Waits until a slot in the queue of requests is available, then queues the given request
    /// passed as parameter.
    ///
    /// The request can later be retrieved by calling [`RequestsSubscriptions::next_request`].
    ///
    /// This asynchronous function can take a long time, as it blocks until a queue entry is
    /// available.
    ///
    /// Has no effect if the [`ClientId`] is stale or invalid.
    pub async fn queue_client_request(&self, client: &ClientId, request: String) {
        let client = match client.1.upgrade() {
            Some(c) => c,
            None => return,
        };

        // Try increase `client.total_requests_in_fly`. If the limit is reached, wait until
        // `request_answered`.
        //
        // Because `request_answered` is notified *after* `total_requests_in_fly` is decremented,
        // we *must* check the value of `total_requests_in_fly` after calling
        // `request_answered.listen()` and before sleeping.
        // However, since `listen()` is rather heavy, we try to avoid calling it as much as
        // possible.
        //
        // This has been implemented as a loop, so that the behaviour is:
        //
        // - Try increase counter.
        // - If limit is reached, call `listen()`.
        // - Try increase counter again (mandatory to prevent race conditions).
        // - Actually wait for the notification, and jump back to step 1.
        let mut sleep_until = None;
        loop {
            if client
                .total_requests_in_fly
                .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |old_value| {
                    if old_value >= self.max_requests_per_client {
                        return None;
                    }

                    // Considering that `old_value < max`, and `max` fits in a `usize` by
                    // definition, then `old_value + 1` also always fits in a `usize`. QED.
                    // There's no risk of overflow.
                    Some(old_value + 1)
                })
                .is_ok()
            {
                break;
            }

            if let Some(sleep_until) = sleep_until.take() {
                sleep_until.await
            } else {
                sleep_until = Some(client.request_answered.listen());
            }
        }

        // We can now insert the request.
        // TODO: what if failure? failures could happen because the queue can contain obsolete entries
        self.unpulled_requests
            .push((request, Arc::downgrade(&client)));
        self.new_unpulled_request.notify_additional(1);
    }

    /// Similar to [`RequestsSubscriptions::queue_client_request`], but succeeds or fails
    /// instantly depending on whether there is enough room in the queue.
    ///
    /// Returns `Ok` if the [`ClientId`] is stale or invalid.
    pub fn try_queue_client_request(&self, client: &ClientId, request: String) -> Result<(), ()> {
        let client = match client.1.upgrade() {
            Some(c) => c,
            None => return Ok(()),
        };

        if client
            .total_requests_in_fly
            .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |old_value| {
                if old_value >= self.max_requests_per_client {
                    return None;
                }

                // Considering that `old_value < max`, and `max` fits in a `usize` by
                // definition, then `old_value + 1` also always fits in a `usize`. QED.
                // There's no risk of overflow.
                Some(old_value + 1)
            })
            .is_err()
        {
            return Err(());
        }

        // TODO: what if failure? failures could happen because the queue can contain obsolete entries
        self.unpulled_requests
            .push((request, Arc::downgrade(&client)));
        self.new_unpulled_request.notify_additional(1);
        Ok(())
    }

    /// Waits until a request has been queued using
    /// [`RequestsSubscriptions::queue_client_request`] and returns it, alongside with an
    /// identifier to later pass back when answering the request.
    ///
    /// Note that the request's body, as a `String` has no guarantee to be valid. The `String` is
    /// simply the value that was passed to [`RequestsSubscriptions::queue_client_request`] and
    /// isn't parsed or validated by the state machine in any way.
    pub async fn next_request(&self) -> (String, RequestId) {
        // Try to pull a request from the queue. If there is none, wait for
        // `new_unpulled_request`.
        let (request_message, client) = loop {
            // Because `new_unpulled_request` is notified *after* new items are pushed to the queue,
            // we *must* check the queue after calling `new_unpulled_request.listen()` and before
            // sleeping.
            // However, since `listen()` is rather heavy, we try to avoid calling it as much as
            // possible.
            //
            // This has been implemented as a loop, so that the behaviour is:
            //
            // - Try pull from queue.
            // - If limit is reached, call `listen()`.
            // - Try pull from queue again (mandatory to prevent race conditions).
            // - Actually wait for the notification, and jump back to step 1.
            let mut sleep_until = None;
            let (request_message, client) = loop {
                if let Some(item) = self.unpulled_requests.pop() {
                    break item;
                }

                if let Some(sleep_until) = sleep_until.take() {
                    sleep_until.await
                } else {
                    sleep_until = Some(self.new_unpulled_request.listen());
                }
            };

            // The queue might contain obsolete entries. Check that the client still exist, and
            // if not throw away the entry and pull another one.
            if let Some(client) = client.upgrade() {
                break (request_message, client);
            }
        };

        // Allocate a new identifier for this request.
        let request_id_num = self.next_request_id.fetch_add(1, Ordering::Relaxed);

        // Insert the request in the client's state.
        {
            let mut lock = client.guarded.lock().await;
            let _was_inserted = lock.pending_requests.insert(request_id_num);
            debug_assert!(_was_inserted);
        }

        // Success.
        let request_id = RequestId(request_id_num, Arc::downgrade(&client));
        (request_message, request_id)
    }

    /// Sets the response to a request previously returned by
    /// [`RequestsSubscriptions::next_request`].
    ///
    /// Has no effect if the [`RequestId`] is invalid, for example if it has already been
    /// responded or if the client has been removed.
    pub async fn respond(&self, request: &RequestId, response: String) {
        let client = match request.1.upgrade() {
            Some(c) => c,
            None => return,
        };

        {
            let mut lock = client.guarded.lock().await;
            if !lock.pending_requests.remove(&request.0) {
                // The request ID is invalid.
                return;
            }

            lock.responses_send_back
                .push_back(ResponseSendBack::Response(response));
            lock.message_pushed.notify_additional(1);
        }
    }

    /// Adds a new subscription to the state machine, associated with the client that started
    /// the given request.
    ///
    /// Returns an error if the client has reached the maximum number of allowed subscriptions
    /// per client.
    ///
    /// If the given [`RequestId`] is stale or invalid, this function always succeeds and returns
    /// a stale [`SubscriptionId`].
    pub async fn start_subscription(
        &self,
        client: &RequestId,
        messages_capacity: usize,
    ) -> Result<SubscriptionId, StartSubscriptionError> {
        let client_arc = match client.1.upgrade() {
            Some(c) => c,
            None => {
                let new_subscription_num =
                    self.next_subscription_id.fetch_add(1, Ordering::Relaxed);
                return Ok(SubscriptionId(new_subscription_num, Weak::new()));
            }
        };

        let mut lock = client_arc.guarded.lock().await;
        if lock.active_subscriptions.len() >= self.max_subscriptions_per_client {
            return Err(StartSubscriptionError::LimitReached);
        }

        let new_subscription_num = self.next_subscription_id.fetch_add(1, Ordering::Relaxed);
        let _was_inserted = lock.active_subscriptions.insert(new_subscription_num);
        debug_assert!(_was_inserted);

        Ok(SubscriptionId(
            new_subscription_num,
            Arc::downgrade(&client_arc),
        ))
    }

    /// Destroys the given subscription.
    ///
    /// All messages already queued will still be available through
    /// [`RequestsSubscriptions::next_response`].
    ///
    /// This function should be seen as a way to clean up the internal state of the state machine
    /// and prevent new notifications from being pushed.
    pub async fn stop_subscription(&self, subscription: &SubscriptionId) {}

    /// If the queue.
    pub async fn set_queued_notification(
        &self,
        subscription: &SubscriptionId,
        index: usize,
        message: String,
    ) {
    }

    pub async fn push_notification(&self, subscription: &SubscriptionId, message: String) {
        todo!()
    }

    pub async fn try_push_notification(
        &self,
        subscription: &SubscriptionId,
        message: String,
    ) -> Result<(), ()> {
        Ok(())
    }
}

/// Error returned by [`RequestsSubscriptions::add_client`] and
/// [`RequestsSubscriptions::add_client_mut`].
pub enum AddClientError {
    /// Reached maximum number of allowed clients.
    LimitReached,
}

/// Error returned by [`RequestsSubscriptions::start_subscription`].
pub enum StartSubscriptionError {
    /// Reached maximum number of subscriptions allowed per user.
    LimitReached,
}

struct Clients {
    list: hashbrown::HashMap<u64, Arc<ClientInner>, fnv::FnvBuildHasher>,

    next_id: u64,
}

struct ClientInner {
    /// Fields that are behind a `Mutex`.
    guarded: Mutex<ClientInnerGuarded>,

    /// Total number of requests that are either unpulled or pending.
    /// In other words, this is the number of requests that have been injected in this state
    /// machine but not fully processed yet. They can be in one of
    /// [`RequestsSubscriptions::unpulled_requests`], [`ClientInnerGuarded::pending_requests`],
    /// or [`ClientInnerGuarded::responses_send_back`].
    ///
    /// Due to the racy nature of everything, a request might have increased the counter here but
    /// not be present yet in [`RequestsSubscriptions::unpulled_requests`].
    total_requests_in_fly: AtomicUsize,

    /// Notified every time [`ClientInner::total_requests_in_fly`] is decremented.
    ///
    /// Note that the notification is done *after* the decrementation.
    request_answered: event_listener::Event,
}

struct ClientInnerGuarded {
    /// List of requests that have been pulled by [`RequestsSubscriptions::next_request`] and
    /// waiting to be responded.
    ///
    /// A FNV hasher is used because the keys of this map are allocated locally.
    pending_requests: hashbrown::HashSet<u64, fnv::FnvBuildHasher>,

    /// Queue of responses to regular requests to send back to the client.
    responses_send_back: VecDeque<ResponseSendBack>,

    /// Queue of notification messages to send back to the client.
    notification_messages: BTreeMap<(u64, usize), String>,

    /// Every time an entry is pushed on [`ClientInnerQueue::requests_send_back`] or
    /// [`ClientInnerQueue::notification_messages`], one listener of this event is notified.
    ///
    /// Also notified if the client is destroyed. TODO: necessary?
    message_pushed: event_listener::Event,

    /// List of active subscriptions.
    ///
    /// A FNV hasher is used because the keys of this map are allocated locally.
    active_subscriptions: hashbrown::HashSet<u64, fnv::FnvBuildHasher>,
}

enum ResponseSendBack {
    Response(String),
    SubscriptionMessage(usize),
}

// Common traits derivation on the id types.
macro_rules! traits_impl {
    ($ty:ty) => {
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_tuple(stringify!($ty)).finish()
            }
        }

        impl cmp::PartialEq for $ty {
            fn eq(&self, other: &$ty) -> bool {
                self.0 == other.0
            }
        }

        impl cmp::Eq for $ty {}

        impl cmp::PartialOrd for $ty {
            fn partial_cmp(&self, other: &$ty) -> Option<cmp::Ordering> {
                self.0.partial_cmp(&other.0)
            }
        }

        impl cmp::Ord for $ty {
            fn cmp(&self, other: &$ty) -> cmp::Ordering {
                self.0.cmp(&other.0)
            }
        }

        impl hash::Hash for $ty {
            fn hash<H>(&self, state: &mut H)
            where
                H: hash::Hasher,
            {
                hash::Hash::hash(&self.0, state)
            }
        }
    };
}

traits_impl!(ClientId);
traits_impl!(RequestId);
traits_impl!(SubscriptionId);
