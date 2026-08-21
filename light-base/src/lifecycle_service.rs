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

//! Per-chain lifecycle event broadcaster.
//!
//! Exposes a typed stream of lifecycle events (peer discovery, warp sync progress,
//! bootstrap completion, stall detection) so consumers can drive UI or health
//! monitoring without parsing debug log text. See issue #3301.
//!
//! The last `HISTORY_CAPACITY` events are retained in a ring buffer so that late
//! subscribers receive a snapshot before starting to receive live events. A
//! subscriber whose bounded channel is full is dropped on the next
//! [`LifecycleService::emit`]. Syncing is never blocked on a slow consumer.
//!
//! The event schema is unstable and versioned.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use async_lock::Mutex;
use core::sync::atomic::{AtomicBool, Ordering};

/// Sync mode picked by the client after startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Warp sync: jump forward via GRANDPA authority-set proofs to a recent finalized
    /// block, skipping historical block verification.
    WarpSync,
    /// All-forks catch-up: verify every block from the checkpoint upward. Used when
    /// warp sync is unavailable (no GRANDPA, no checkpoint, or explicit override).
    AllForks,
}

/// Reason a chain was reported as stalled by the watchdog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallReason {
    /// No peer connected for longer than the watchdog threshold.
    NoPeers,
    /// Warp sync has been in progress but its target hasn't advanced for the
    /// watchdog threshold.
    WarpNoProgress,
    /// The bootstrap window (from chain-add to `BootstrapComplete`) exceeded the
    /// watchdog threshold without completing.
    BootstrapTimeout,
}

/// A single lifecycle transition of a chain.
///
/// The schema is unstable and versioned.
#[derive(Debug, Clone)]
pub enum LifecycleEvent {
    /// The chain has been added and is starting up. Emitted exactly once, and
    /// before every other event.
    Connecting,

    /// The chain has observed at least one peer. Emitted at most once.
    FirstPeer,

    /// The sync service has committed to a bootstrap mode. Emitted once,
    /// before `WarpSyncProgress` (if applicable) or `BootstrapComplete`.
    ///
    /// A relay chain reports [`SyncMode::WarpSync`] if it commits to warp
    /// before the mode-decision deadline, [`SyncMode::AllForks`] otherwise.
    /// Parachains always report [`SyncMode::AllForks`].
    ModeDecision { mode: SyncMode },

    /// Warp sync progress update. Only emitted when the mode is
    /// [`SyncMode::WarpSync`].
    ///
    /// `at` is the height of the highest block whose finality has been proven
    /// by the warp-sync fragments verified so far. `target` is the highest
    /// best-block height advertised by any currently-connected peer (not
    /// necessarily a GRANDPA-finalized value). Values are polled at ~500 ms
    /// cadence and only re-emitted when `(at, target)` changes. Both are
    /// monotonically non-decreasing while warp is in progress. `target` is
    /// additionally clamped upward to `at`.
    WarpSyncProgress { at: u64, target: u64 },

    /// Warp sync has finished. Only emitted when the mode is
    /// [`SyncMode::WarpSync`]. `finalized` is the block height decoded from
    /// the sync service's initial finalized-block header, or `0` if that
    /// decode fails.
    WarpSyncFinished { finalized: u64 },

    /// Initial bootstrap has completed and the client is ready to serve
    /// queries. Emitted at most once, after warp (if any) and once the sync
    /// service starts streaming new blocks.
    BootstrapComplete,

    /// The client's health watchdog considers the chain stalled. See
    /// [`StallReason`] for the individual conditions.
    ///
    /// The watchdog re-arms after emitting: once the tripping condition
    /// clears, a matching [`LifecycleEvent::Recovered`] is emitted. If the
    /// stall reason changes without an intervening healthy interval, a
    /// `Recovered` for the previous reason is emitted immediately before the
    /// new `Stalled`.
    Stalled { reason: StallReason },

    /// The most recent [`LifecycleEvent::Stalled`] condition has cleared.
    /// `previously` echoes its reason so consumers can correlate the two
    /// without holding state.
    Recovered { previously: StallReason },

    /// Terminal event: no further lifecycle events will be delivered on this
    /// subscription. Lets clients distinguish "still subscribed" from
    /// "silently dropped".
    Stopped { reason: StopReason },
}

/// Reason a subscription was terminated with [`LifecycleEvent::Stopped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The subscriber's bounded channel filled up and the broadcaster dropped its
    /// sender on a subsequent [`LifecycleService::emit`].
    Lagged,
    /// The broadcaster has been dropped, typically because the chain was
    /// removed from the client.
    ChainRemoved,
}

/// Broadcaster of lifecycle events for a single chain.
///
/// Cheap to clone via `Arc`. Stored in `ChainServices` and shared with the
/// projection tasks that emit into it.
pub struct LifecycleService {
    inner: Mutex<Inner>,
}

/// Number of past events retained for snapshot-on-subscribe replay and for
/// [`LifecycleService::bug_report_trace`].
const HISTORY_CAPACITY: usize = 128;

/// Per-subscriber channel capacity. Must be `>= HISTORY_CAPACITY` so that the
/// replay in [`LifecycleService::subscribe`] cannot fill the channel before
/// the subscriber's `Sender` is registered for live delivery.
const SUBSCRIBER_CHANNEL_CAPACITY: usize = HISTORY_CAPACITY + 64;

struct Inner {
    /// Bounded ring buffer of past events, replayed to late subscribers and
    /// returned by [`LifecycleService::bug_report_trace`].
    history: VecDeque<LifecycleEvent>,
    /// Active subscribers. A `try_send` failure marks a subscriber as dropped.
    subscribers: Vec<Subscriber>,
}

struct Subscriber {
    tx: async_channel::Sender<LifecycleEvent>,
    /// Set to `true` when the broadcaster drops this subscriber for lagging.
    /// The pump reads it after seeing a closed channel to distinguish a
    /// [`StopReason::Lagged`] from a [`StopReason::ChainRemoved`].
    lagged: Arc<AtomicBool>,
}

/// Handle returned by [`LifecycleService::subscribe`].
pub struct Subscription {
    receiver: async_channel::Receiver<LifecycleEvent>,
    /// Shared with the broadcaster. `true` iff this subscriber was dropped for lagging.
    lagged: Arc<AtomicBool>,
}

impl Subscription {
    /// Awaits the next event. Returns `None` when the broadcaster drops this subscriber.
    pub async fn recv(&self) -> Option<LifecycleEvent> {
        self.receiver.recv().await.ok()
    }

    /// Tries to receive an event without blocking. Returns an error when the channel
    /// is empty or closed.
    pub fn try_recv(&self) -> Result<LifecycleEvent, async_channel::TryRecvError> {
        self.receiver.try_recv()
    }

    /// True if the broadcaster dropped this subscriber for lagging. Meaningful only after
    /// [`Subscription::recv`] yields `None`.
    pub fn was_lagged(&self) -> bool {
        self.lagged.load(Ordering::SeqCst)
    }
}

impl LifecycleService {
    /// Creates a fresh broadcaster with no history and no subscribers.
    pub fn new() -> Arc<Self> {
        Arc::new(LifecycleService {
            inner: Mutex::new(Inner {
                history: VecDeque::with_capacity(HISTORY_CAPACITY),
                subscribers: Vec::new(),
            }),
        })
    }

    /// Emits an event to every active subscriber and appends it to the
    /// history. Subscribers whose channel is full are dropped and marked as
    /// lagged so the pump can report [`StopReason::Lagged`] instead of
    /// [`StopReason::ChainRemoved`].
    pub async fn emit(&self, event: LifecycleEvent) {
        let mut inner = self.inner.lock().await;
        if inner.history.len() == HISTORY_CAPACITY {
            inner.history.pop_front();
        }
        inner.history.push_back(event.clone());
        inner
            .subscribers
            .retain(|sub| match sub.tx.try_send(event.clone()) {
                Ok(()) => true,
                Err(async_channel::TrySendError::Full(_)) => {
                    sub.lagged.store(true, Ordering::SeqCst);
                    false
                }
                Err(async_channel::TrySendError::Closed(_)) => false,
            });
    }

    /// Subscribes to lifecycle events. The returned [`Subscription`] first yields the
    /// retained history in emission order, then live events. If the subscriber falls
    /// behind on the live tail it is dropped on the next [`LifecycleService::emit`],
    /// with `was_lagged()` set to `true`.
    pub async fn subscribe(&self) -> Subscription {
        debug_assert!(SUBSCRIBER_CHANNEL_CAPACITY >= HISTORY_CAPACITY);
        let (tx, rx) = async_channel::bounded(SUBSCRIBER_CHANNEL_CAPACITY);
        let lagged = Arc::new(AtomicBool::new(false));
        let mut inner = self.inner.lock().await;
        // The capacity invariant plus the outer `Mutex` held here guarantees
        // that every `try_send` in this loop succeeds. If a future edit
        // breaks the invariant, drop the subscription rather than blocking.
        for event in &inner.history {
            if tx.try_send(event.clone()).is_err() {
                debug_assert!(false, "subscribe replay try_send failed under invariant");
                return Subscription {
                    receiver: rx,
                    lagged,
                };
            }
        }
        inner.subscribers.push(Subscriber {
            tx,
            lagged: lagged.clone(),
        });
        Subscription {
            receiver: rx,
            lagged,
        }
    }

    /// Returns a snapshot of the retained event history, without subscribing
    /// to live events. Intended for bug-report traces at the moment of
    /// failure.
    pub async fn bug_report_trace(&self) -> Vec<LifecycleEvent> {
        let inner = self.inner.lock().await;
        inner.history.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::block_on;

    /// Builds a `LifecycleEvent` carrying an integer tag `i` so tests can
    /// assert emission order without pattern-matching every variant.
    fn make_event(i: u64) -> LifecycleEvent {
        LifecycleEvent::WarpSyncProgress { at: i, target: i }
    }

    fn tag_of(ev: &LifecycleEvent) -> u64 {
        match ev {
            LifecycleEvent::WarpSyncProgress { at, .. } => *at,
            other => panic!("unexpected event variant: {:?}", other),
        }
    }

    #[test]
    fn replay_within_capacity() {
        block_on(async {
            // Given
            let svc = LifecycleService::new();
            let n: u64 = 10;
            assert!((n as usize) < HISTORY_CAPACITY);
            for i in 0..n {
                svc.emit(make_event(i)).await;
            }

            // When
            let rx = svc.subscribe().await;
            let mut received = Vec::new();
            for _ in 0..n {
                received.push(rx.recv().await.unwrap());
            }

            // Then
            assert_eq!(received.len(), n as usize);
            for (idx, ev) in received.iter().enumerate() {
                assert_eq!(tag_of(ev), idx as u64);
            }
        });
    }

    #[test]
    fn ring_buffer_eviction() {
        block_on(async {
            // Given
            let svc = LifecycleService::new();
            let total = HISTORY_CAPACITY + 10;
            for i in 0..total {
                svc.emit(make_event(i as u64)).await;
            }

            // When
            let rx = svc.subscribe().await;
            let mut received = Vec::new();
            for _ in 0..HISTORY_CAPACITY {
                received.push(rx.recv().await.unwrap());
            }

            // Then
            assert_eq!(received.len(), HISTORY_CAPACITY);
            for (idx, ev) in received.iter().enumerate() {
                assert_eq!(tag_of(ev), (idx + 10) as u64);
            }
            assert!(rx.try_recv().is_err());
        });
    }

    #[test]
    fn replay_at_capacity_boundary() {
        block_on(async {
            // Given
            let svc = LifecycleService::new();
            for i in 0..HISTORY_CAPACITY {
                svc.emit(make_event(i as u64)).await;
            }

            // When
            let rx = svc.subscribe().await;
            svc.emit(make_event(HISTORY_CAPACITY as u64)).await;
            let expected = HISTORY_CAPACITY + 1;
            let mut received = Vec::new();
            for _ in 0..expected {
                received.push(rx.recv().await.unwrap());
            }

            // Then
            assert_eq!(received.len(), expected);
            for (idx, ev) in received.iter().enumerate() {
                assert_eq!(tag_of(ev), idx as u64);
            }
        });
    }

    #[test]
    fn slow_subscriber_isolation() {
        block_on(async {
            // Given
            let svc = LifecycleService::new();
            let healthy = svc.subscribe().await;
            let slow = svc.subscribe().await;

            // When
            let total = SUBSCRIBER_CHANNEL_CAPACITY + 1;
            let mut healthy_received = Vec::new();
            for i in 0..total {
                svc.emit(make_event(i as u64)).await;
                while let Ok(ev) = healthy.try_recv() {
                    healthy_received.push(ev);
                }
            }
            while let Ok(ev) = healthy.try_recv() {
                healthy_received.push(ev);
            }

            // Then
            assert_eq!(healthy_received.len(), total);
            for (idx, ev) in healthy_received.iter().enumerate() {
                assert_eq!(tag_of(ev), idx as u64);
            }
            let mut slow_count = 0;
            while slow.try_recv().is_ok() {
                slow_count += 1;
            }
            assert_eq!(slow_count, SUBSCRIBER_CHANNEL_CAPACITY);
            assert!(slow.was_lagged());
            assert!(!healthy.was_lagged());
        });
    }

    #[test]
    fn bug_report_trace_returns_history() {
        block_on(async {
            // Given
            let svc = LifecycleService::new();
            let n: u64 = 5;
            for i in 0..n {
                svc.emit(make_event(i)).await;
            }

            // When
            let trace = svc.bug_report_trace().await;
            let extra = HISTORY_CAPACITY as u64 + 5;
            for i in n..(n + extra) {
                svc.emit(make_event(i)).await;
            }
            let trace2 = svc.bug_report_trace().await;

            // Then
            assert_eq!(trace.len(), n as usize);
            for (idx, ev) in trace.iter().enumerate() {
                assert_eq!(tag_of(ev), idx as u64);
            }
            assert_eq!(trace2.len(), HISTORY_CAPACITY);
            let last_tag = n + extra - 1;
            let first_tag = last_tag - (HISTORY_CAPACITY as u64 - 1);
            for (idx, ev) in trace2.iter().enumerate() {
                assert_eq!(tag_of(ev), first_tag + idx as u64);
            }
        });
    }
}
