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
    clients: Mutex<hashbrown::HashMap<u64, Arc<ClientInner>, fnv::FnvBuildHasher>>,

    /// Every time an element is pushed in [`ClientInnerQueue::unpulled_requests`], the client in
    /// question is also pushed here. Similarly, elements removed from one are also removed from
    /// the other.
    /// This allows knowing in `O(1)` complexity which client has a request available for
    /// processing.
    unpulled_requests: Mutex<UnpulledRequests>,

    /// Next identifier to assign to the next request.
    ///
    /// Matches the values found in [`ClientInner::pending_requests`].
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
            clients: Mutex::new(hashbrown::HashMap::with_capacity_and_hasher(
                8,
                Default::default(),
            )),
            unpulled_requests: Mutex::new(UnpulledRequests {
                queue: VecDeque::with_capacity(max_requests_per_client * 8),
                new_queue_element: event_listener::Event::new(),
            }),
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
        self.max_clients.store(max_clients, Ordering::Relaxed)
    }

    /// Adds a new client to the state machine. A new [`ClientId`] is attributed.
    ///
    /// Can return an error if the maximum simultaneous number of clients has been reached.
    ///
    /// A single instance of [`RequestsSubscriptions`] will never allocate multiple times the same
    /// [`ClientId`].
    pub async fn add_client(&self) -> Result<ClientId, ()> {
        let mut clients = self.clients.lock().await;
        if clients.len() == self.max_clients.load(Ordering::Relaxed) {
            return Err(());
        }

        let arc = Arc::new(ClientInner {
            queue: Mutex::new(ClientInnerQueue {
                unpulled_requests: VecDeque::with_capacity(self.max_requests_per_client),
                pending_requests: hashbrown::HashSet::with_capacity_and_hasher(
                    self.max_requests_per_client,
                    Default::default(),
                ),
                request_answered: event_listener::Event::new(),
                responses_send_back: VecDeque::with_capacity(self.max_requests_per_client),
                notification_messages: BTreeMap::new(),
                message_pushed: event_listener::Event::new(),
                active_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
                    self.max_subscriptions_per_client,
                    Default::default(),
                ),
            }),
        });

        let new_client_id = 0; // TODO:

        let ret = ClientId(new_client_id, Arc::downgrade(&arc));
        clients.insert(new_client_id, arc);
        Ok(ret)
    }

    /// Similar to [`RequestsSubscriptions::add_client`], but non-async and takes `self` as `&mut`.
    ///
    /// > **Note**: This function is notably useful for adding clients at initialization, when
    /// >           outside of an asynchronous context.
    pub fn add_client_mut(&mut self) -> Result<ClientId, ()> {
        // TODO: DRY with add_client
        let clients = self.clients.get_mut();
        if clients.len() == self.max_clients.load(Ordering::Relaxed) {
            return Err(());
        }

        let arc = Arc::new(ClientInner {
            queue: Mutex::new(ClientInnerQueue {
                unpulled_requests: VecDeque::with_capacity(self.max_requests_per_client),
                pending_requests: hashbrown::HashSet::with_capacity_and_hasher(
                    self.max_requests_per_client,
                    Default::default(),
                ),
                request_answered: event_listener::Event::new(),
                responses_send_back: VecDeque::with_capacity(self.max_requests_per_client),
                notification_messages: BTreeMap::new(),
                message_pushed: event_listener::Event::new(),
                active_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
                    self.max_subscriptions_per_client,
                    Default::default(),
                ),
            }),
        });

        let new_client_id = 0; // TODO:

        let ret = ClientId(new_client_id, Arc::downgrade(&arc));
        clients.insert(new_client_id, arc);
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

        if let Some(removed) = clients.remove(&client.0) {
            debug_assert!(Arc::ptr_eq(&removed, &client.1.upgrade().unwrap()));
        }

        // Shrink `clients` in order to potentially reclaim memory after a huge spike in number of
        // clients.
        if clients.capacity() >= clients.len() * 2 {
            clients.shrink_to_fit();
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
                let mut queue_lock = client.queue.lock().await;

                // TODO: this order where we always try requests_send_back first is sketchy and might cause races when subscribing/unsubscribing
                if let Some(message) = queue_lock.responses_send_back.pop_front() {
                    return message;
                }

                // TODO: instead use `BTreeMap::pop_first` after it is stabilized: https://github.com/rust-lang/rust/issues/62924
                if let Some(key) = queue_lock.notification_messages.keys().next().cloned() {
                    let message = queue_lock.notification_messages.remove(&key).unwrap();
                    return message;
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
    // TODO: provide a non-async alternative?
    pub async fn queue_client_request(&self, client: &ClientId, request: String) {
        let client = match client.1.upgrade() {
            Some(c) => c,
            None => return,
        };

        // Try insert the request in that client's queue. Can take a long time.
        loop {
            let sleep_until = {
                let mut lock = client.queue.lock().await;

                if lock
                    .pending_requests
                    .len()
                    .saturating_add(lock.unpulled_requests.len())
                    < self.max_requests_per_client
                {
                    lock.unpulled_requests.push_back(request);
                    debug_assert_eq!(
                        lock.unpulled_requests.capacity(),
                        self.max_requests_per_client
                    );
                    break;
                }

                lock.request_answered.listen()
            };

            sleep_until.await
        }

        // Now that the request is in the client's queue, add a corresponding entry in the global
        // queue of requests.
        let mut unpulled_requests = self.unpulled_requests.lock().await;
        unpulled_requests.queue.push_back(Arc::downgrade(&client));
        unpulled_requests
            .new_queue_element
            .notify_additional_relaxed(1);
    }

    /// Similar to [`RequestsSubscriptions::queue_client_request`], but succeeds or fails
    /// instantly depending on whether there is enough room in the queue.
    pub fn try_queue_client_request(&self, client: &ClientId, request: String) -> Result<(), ()> {
        todo!()
    }

    /// Waits until a request has been queued using
    /// [`RequestsSubscriptions::queue_client_request`] and returns it, alongside with an
    /// identifier to later pass back when answering the request.
    ///
    /// Note that the request's body, as a `String` has no guarantee to be valid. The `String` is
    /// simply the value that was passed to [`RequestsSubscriptions::queue_client_request`] and
    /// isn't parsed or validated by the state machine in any way.
    pub async fn next_request(&self) -> (String, RequestId) {
        // Find which client, if any, has a request available.
        let client_with_request = loop {
            let sleep_until = {
                let mut unpulled_requests = self.unpulled_requests.lock().await;
                if let Some(client) = unpulled_requests.queue.pop_front() {
                    // Shrink `unpulled_requests.queue` in order to potentially recover memory
                    // after a big spike of requests.
                    if unpulled_requests.queue.len() * 2 < unpulled_requests.queue.capacity() {
                        unpulled_requests.queue.shrink_to_fit();
                    }

                    match client.upgrade() {
                        Some(c) => break c,
                        None => continue,
                    }
                }
                unpulled_requests.new_queue_element.listen()
            };

            sleep_until.await
        };

        // Found a client with a request available.

        // Allocate a new identifier for this request.
        let request_id_num = self.next_request_id.fetch_add(1, Ordering::Relaxed);

        // Insert the new request in that client's state, and extract the body of the request.
        let request_message = {
            let mut client_lock = client_with_request.queue.lock().await;
            debug_assert_eq!(
                client_lock.unpulled_requests.capacity(),
                self.max_requests_per_client
            );
            debug_assert_eq!(
                client_lock.pending_requests.capacity(),
                self.max_requests_per_client
            );
            let _was_inserted = client_lock.pending_requests.insert(request_id_num);
            debug_assert!(_was_inserted);
            // Because it was found in an entry of `unpulled_requests`, then this client **must**
            // always have an entry in its local `unpulled_requests`.
            client_lock.unpulled_requests.pop_front().unwrap()
        };

        // Success.
        let request_id = RequestId(request_id_num, Arc::downgrade(&client_with_request));
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

        let mut lock = client.queue.lock().await;

        debug_assert_eq!(
            lock.pending_requests.capacity(),
            self.max_requests_per_client
        );

        if !lock.pending_requests.remove(&request.0) {
            // The request ID is invalid.
            return;
        }

        lock.responses_send_back.push_back(response);

        lock.request_answered.notify_additional_relaxed(1);
        lock.message_pushed.notify_additional_relaxed(1);
    }

    /// Adds a new subscription to the state machine, associated with the client that started
    /// the given request.
    ///
    /// Returns an error if the client has reached the maximum number of allowed subscriptions
    /// per client.
    ///
    /// If the given [`RequestId`] is stale or invalid, this function always succeeds and returns
    /// a stale [`SubscriptionId`].
    // TODO: return error if limit to number of subscriptions
    pub async fn start_subscription(
        &self,
        client: &RequestId,
        messages_capacity: usize,
    ) -> Result<SubscriptionId, ()> {
        let client_arc = match client.1.upgrade() {
            Some(c) => c,
            None => {
                let new_subscription_num =
                    self.next_subscription_id.fetch_add(1, Ordering::Relaxed);
                return Ok(SubscriptionId(new_subscription_num, Weak::new()));
            }
        };

        let lock = client_arc.queue.lock().await;
        debug_assert_eq!(
            lock.active_subscriptions.capacity(),
            self.max_subscriptions_per_client
        );
        if lock.active_subscriptions.len() >= self.max_subscriptions_per_client {
            return Err(());
        }

        let new_subscription_num = self.next_subscription_id.fetch_add(1, Ordering::Relaxed);

        todo!()
    }

    /// Destroys the given subscription.
    ///
    /// All messages already queued will still be available through
    /// [`RequestsSubscriptions::next_response`].
    ///
    /// This function should be seen as a way to clean up the internal state of the state machine.
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

struct UnpulledRequests {
    /// Queue of clients with an element in [`ClientInnerQueue::unpulled_requests`]. Can contain
    /// obsolete clients, in which case the queue element should be ignored.
    queue: VecDeque<Weak<ClientInner>>,

    /// Event notified whenever an element is pushed to [`UnpulledRequests::queue`].
    new_queue_element: event_listener::Event,
}

struct ClientInner {
    queue: Mutex<ClientInnerQueue>,
}

struct ClientInnerQueue {
    /// List of requests sent by the client and not yet pulled by
    /// [`RequestsSubscriptions::next_request`].
    unpulled_requests: VecDeque<String>,

    /// List of requests that have been pulled by [`RequestsSubscriptions::next_request`] and
    /// waiting to be responded.
    pending_requests: hashbrown::HashSet<u64, fnv::FnvBuildHasher>,

    /// Every time an entry is pushed on [`ClientInnerQueue::requests_send_back`] or
    /// [`ClientInnerQueue::notification_messages`], one listener of this event is notified.
    request_answered: event_listener::Event,

    /// Queue of responses to regular requests to send back to the client.
    responses_send_back: VecDeque<String>,

    /// Queue of notification messages to send back to the client.
    notification_messages: BTreeMap<(u64, usize), String>,

    /// Every time an entry is pushed on [`ClientInnerQueue::requests_send_back`] or
    /// [`ClientInnerQueue::notification_messages`], one listener of this event is notified.
    ///
    /// Also notified if the client is destroyed. TODO: necessary?
    message_pushed: event_listener::Event,

    /// List of active subscriptions.
    active_subscriptions: hashbrown::HashSet<u64, fnv::FnvBuildHasher>,
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
