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
//! monitoring without matching debug log text. See issue #3301.
//!
//! # Semantics
//!
//! The last N events are retained in a ring buffer so late subscribers receive a
//! snapshot before live events. Slow subscribers whose bounded channel is full are
//! dropped; there is no lag marker yet - a dropped subscriber simply stops
//! receiving events. This mirrors the "slow consumers must never block syncing"
//! requirement.
//!
//! The event schema is unstable and versioned.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use async_lock::Mutex;

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
    /// Post-bootstrap sync has produced no new block notifications for the
    /// watchdog threshold. Suggests all connected peers have gone quiet.
    SyncNoProgress,
    /// The bootstrap window (from chain-add to `BootstrapComplete`) exceeded the
    /// watchdog threshold without completing.
    BootstrapTimeout,
}

/// A single lifecycle transition of a chain.
///
/// The schema is unstable and versioned. New variants may be added; consumers that
/// don't recognise a variant should treat it as a no-op.
#[derive(Debug, Clone)]
pub enum LifecycleEvent {
    /// The chain has been added and is starting up. Emitted exactly once, first.
    Connecting,

    /// The chain has observed at least one peer for the first time.
    /// Emitted at most once per instance.
    FirstPeer,

    /// The client has decided on a bootstrap mode for the chain. Emitted once,
    /// before `WarpSyncProgress` (if applicable) or `BootstrapComplete`.
    ///
    /// The reported `mode` is the mode the sync service actually committed to
    /// (see [`crate::sync_service::SyncService::bootstrap_mode`]): a relay chain
    /// starts in [`SyncMode::WarpSync`] if it commits to warp before the
    /// deadline and [`SyncMode::AllForks`] otherwise; parachains are always
    /// [`SyncMode::AllForks`].
    ModeDecision { mode: SyncMode },

    /// Warp sync progress update. Not emitted when the mode is
    /// [`SyncMode::AllForks`].
    ///
    /// `at` is the height of the highest block whose finality has been proven
    /// by the warp-sync fragments verified so far (from
    /// [`crate::sync_service::SyncService::warp_sync_position`]). `target` is
    /// the highest best-block height advertised by any currently-connected
    /// peer (not necessarily a GRANDPA-finalized value). Values are polled at
    /// ~500 ms cadence and only re-emitted when `(at, target)` changes; both
    /// are monotonically non-decreasing while warp is in progress, and
    /// `target` is clamped so it is never below `at`.
    WarpSyncProgress { at: u64, target: u64 },

    /// Warp sync has finished. `finalized` is the block height decoded from
    /// the sync service's initial finalized-block header snapshot, or `0` if
    /// that decode fails. Not emitted when the mode is [`SyncMode::AllForks`].
    WarpSyncFinished { finalized: u64 },

    /// Initial bootstrap has completed and the client considers the chain ready
    /// to serve queries. Emitted at most once per instance, after warp (if any)
    /// and once the sync service starts streaming new blocks.
    BootstrapComplete,

    /// The client's health watchdog considers the chain stalled.
    ///
    /// Emitted by a periodic watchdog task that tracks [`StallReason::NoPeers`]
    /// (no live peer for the watchdog window), [`StallReason::BootstrapTimeout`]
    /// (bootstrap has not completed within the watchdog window from chain-add),
    /// and [`StallReason::SyncNoProgress`] (after `BootstrapComplete`, the sync
    /// service has not looked near-head for the watchdog window).
    /// [`StallReason::WarpNoProgress`] is reserved by the schema but not
    /// emitted yet. The watchdog re-arms after emitting: once the tripping
    /// condition clears, a matching [`LifecycleEvent::Recovered`] is emitted.
    Stalled { reason: StallReason },

    /// The condition that produced the most recent [`LifecycleEvent::Stalled`]
    /// has cleared. `previously` echoes the reason from the paired `Stalled`
    /// event so consumers can correlate the two without holding state.
    ///
    /// Not emitted spontaneously — always follows a matching `Stalled` event.
    Recovered { previously: StallReason },

    /// Terminal event: no further lifecycle events will be delivered on this
    /// subscription. Lets clients distinguish "still subscribed, chain is idle"
    /// from "silently dropped by the broadcaster".
    ///
    /// After emitting this event the pump tears down the subscription entry.
    /// See [`StopReason`] for the distinction between the two cases.
    Stopped { reason: StopReason },
}

/// Reason a subscription was terminated with [`LifecycleEvent::Stopped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The subscriber's bounded channel filled up and the broadcaster reaped
    /// the [`async_channel::Sender`] on a subsequent [`LifecycleService::emit`].
    ///
    /// Note: because [`Vec::retain`] drops the reaped Sender before we can send
    /// through it, this variant is only observable if a slow subscriber later
    /// wakes up its receiver enough to see the channel closed and the pump
    /// synthesises the marker on the client side. For the MVP the pump only
    /// emits [`StopReason::ChainRemoved`] via the None branch on the receiver;
    /// this variant is reserved for future use once the broadcaster gains a
    /// way to signal reaping without a live Sender.
    Lagged,
    /// The broadcaster (`LifecycleService`) itself has been dropped, typically
    /// because the chain was removed from the client. All subscribers observe
    /// their receiver closing.
    ChainRemoved,
}

/// Broadcaster of lifecycle events for a single chain.
///
/// Cheap to clone via `Arc`. Stored in `ChainServices` and shared between the
/// projection tasks that emit into it (peer watcher, sync mode watcher, warp
/// progress poller, watchdog).
pub struct LifecycleService {
    inner: Mutex<Inner>,
}

/// Maximum number of past events retained for snapshot-on-subscribe replay and
/// for `bug_report_trace()`. Sized to comfortably hold a full lifecycle plus a
/// long tail of Stalled/recovery events.
const HISTORY_CAPACITY: usize = 128;

/// Per-subscriber channel capacity. Must be `>= HISTORY_CAPACITY` so that the
/// replay burst in [`LifecycleService::subscribe`] cannot fill the channel
/// before the subscriber's Sender is registered for live delivery. If the
/// channel filled during replay, `subscribe` would return with the Sender
/// dropped and the client would silently receive a truncated snapshot with no
/// live events.
const SUBSCRIBER_CHANNEL_CAPACITY: usize = HISTORY_CAPACITY + 64;

struct Inner {
    /// Bounded ring buffer of past events. Late subscribers get this replayed
    /// before the live stream begins; bug-report tooling can dump it via
    /// [`LifecycleService::bug_report_trace`].
    history: VecDeque<LifecycleEvent>,
    /// Active subscribers. A `try_send` failure marks a subscriber as dropped.
    subscribers: Vec<async_channel::Sender<LifecycleEvent>>,
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

    /// Emits an event to every active subscriber and appends it to the history
    /// ring buffer for future subscribers. Subscribers whose channel is full
    /// are removed.
    ///
    /// Note on [`LifecycleEvent::Stopped`] with [`StopReason::Lagged`]: when
    /// [`Vec::retain`] drops a full-channel Sender we no longer have a handle
    /// to deliver a synthetic terminal event through it, so `Lagged` is only
    /// observable if a slow subscriber later wakes up its receiver enough to
    /// notice the channel closed. For the MVP that terminal signal is emitted
    /// by the JSON-RPC pump on the None branch as
    /// [`StopReason::ChainRemoved`]; the broadcaster itself does not currently
    /// emit `Lagged`.
    pub async fn emit(&self, event: LifecycleEvent) {
        let mut inner = self.inner.lock().await;
        if inner.history.len() == HISTORY_CAPACITY {
            inner.history.pop_front();
        }
        inner.history.push_back(event.clone());
        inner
            .subscribers
            .retain(|tx| tx.try_send(event.clone()).is_ok());
    }

    /// Subscribes to lifecycle events. The returned receiver first yields a
    /// replay of the retained history (in emission order) and then receives
    /// live events. The channel buffer is bounded; if a subscriber falls too
    /// far behind on the live tail it is silently dropped by the next
    /// [`LifecycleService::emit`] call.
    ///
    /// The channel is sized so the replay burst cannot exhaust it: with
    /// `SUBSCRIBER_CHANNEL_CAPACITY >= HISTORY_CAPACITY` and the outer Mutex
    /// held for the whole call (so no concurrent `emit` can run), every
    /// replay `try_send` is guaranteed to succeed.
    pub async fn subscribe(&self) -> async_channel::Receiver<LifecycleEvent> {
        debug_assert!(SUBSCRIBER_CHANNEL_CAPACITY >= HISTORY_CAPACITY);
        let (tx, rx) = async_channel::bounded(SUBSCRIBER_CHANNEL_CAPACITY);
        let mut inner = self.inner.lock().await;
        for event in &inner.history {
            // Under the capacity invariant above, this cannot fail. If it
            // does (invariant violated by a future edit), silently drop the
            // subscription rather than block sync.
            if tx.try_send(event.clone()).is_err() {
                debug_assert!(false, "subscribe replay try_send failed under invariant");
                return rx;
            }
        }
        inner.subscribers.push(tx);
        rx
    }

    /// Returns a snapshot of the retained event history without subscribing to
    /// live events. Intended for bug-report tooling: dump the last N events at
    /// the moment of failure so a support engineer can reconstruct the timeline
    /// without needing megabytes of debug logs.
    pub async fn bug_report_trace(&self) -> Vec<LifecycleEvent> {
        let inner = self.inner.lock().await;
        inner.history.iter().cloned().collect()
    }
}
