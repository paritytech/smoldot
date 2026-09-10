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

//! Per-chain lifecycle state.
//!
//! Holds a small [`LifecycleState`] value (bootstrap phase, peer presence, stall verdict) and
//! lets consumers subscribe to changes, so that an embedder can show what the light client is
//! doing without parsing log output. See issue #3301.
//!
//! This is a "latest value" broadcast, not an event log. A subscriber receives the current
//! state when it subscribes and then the newest state after every change. A subscriber that
//! reads slowly simply skips intermediate states. Nothing is buffered, so a slow subscriber
//! can never fall behind or slow down syncing.
//!
//! [`start`] creates the service of a chain together with the two tasks that keep it up to
//! date: one maps the sync service's status to the phase, the other polls the network service
//! for the peer count and derives the stall verdict.
//!
//! The schema is unstable.

use crate::{network_service, platform::PlatformRef, sync_service};
use alloc::sync::{Arc, Weak};
use async_lock::Mutex;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

/// Time without any connected peer after which the chain is reported as stalled.
const NO_PEERS_TIMEOUT: Duration = Duration::from_secs(30);

/// Time without warp sync progress after which the chain is reported as stalled.
const NO_PROGRESS_TIMEOUT: Duration = Duration::from_secs(45);

/// Decides the [`Health`] from how long the chain has had no peer and, if a warp sync is in
/// progress, how long it has not advanced.
fn health_verdict(no_peers_for: Duration, no_progress_for: Option<Duration>) -> Health {
    if no_peers_for >= NO_PEERS_TIMEOUT {
        Health::Stalled {
            reason: StallReason::NoPeers,
        }
    } else if no_progress_for.is_some_and(|d| d >= NO_PROGRESS_TIMEOUT) {
        Health::Stalled {
            reason: StallReason::NoProgress,
        }
    } else {
        Health::Ok
    }
}

/// Bootstrap progress of the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The chain has been added and no block is being streamed yet.
    Connecting,
    /// A GrandPa warp sync is in progress.
    Syncing {
        /// Highest block proven finalized by the warp sync fragments verified so far.
        at: u64,
        /// Highest best block advertised by a connected peer. Never below `at`.
        target: u64,
    },
    /// The sync service is streaming new blocks. Not terminal: a later warp sync moves the
    /// chain back to [`Phase::Syncing`], then to `Ready` again.
    Ready,
}

/// Why the watchdog considers the chain stalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallReason {
    /// No peer has been connected for a while.
    NoPeers,
    /// A warp sync is in progress but hasn't advanced for a while.
    NoProgress,
}

/// Verdict of the stall watchdog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Ok,
    Stalled { reason: StallReason },
}

/// Lifecycle state of a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleState {
    pub phase: Phase,
    /// Number of peers currently connected on this chain.
    pub num_peers: u32,
    pub health: Health,
}

impl Default for LifecycleState {
    fn default() -> Self {
        LifecycleState {
            phase: Phase::Connecting,
            num_peers: 0,
            health: Health::Ok,
        }
    }
}

/// Creates the [`LifecycleService`] of a chain and spawns the two tasks that keep it up to date.
/// Both tasks hold only weak references so that they stop, rather than keep the chain alive,
/// once the chain is removed.
pub(crate) fn start<TPlat: PlatformRef>(
    platform: &TPlat,
    sync_service: &Arc<sync_service::SyncService<TPlat>>,
    network_service_chain: &Arc<network_service::NetworkServiceChain<TPlat>>,
) -> Arc<LifecycleService> {
    let lifecycle_service = LifecycleService::new();

    // Drives `LifecycleState::phase` from the sync service's own status: `Syncing` while a warp
    // sync is in progress, `Ready` once the sync service serves the chain. Ends when the sync
    // service is gone.
    platform.spawn_task("lifecycle-phase".into(), {
        let lifecycle_service = Arc::downgrade(&lifecycle_service);
        let sync_service = Arc::downgrade(sync_service);
        let platform = platform.clone();
        async move {
            // Warp sync fragments can verify at dozens per second. Every status is applied
            // as soon as it is received, but after a progress update the task pauses for
            // this interval and then applies only the newest status that arrived meanwhile,
            // so that consumers see at most a couple of progress updates per second while
            // still seeing the start of a warp sync and its end without delay.
            const PROGRESS_BATCH_INTERVAL: Duration = Duration::from_millis(500);

            let sync_status = {
                let Some(sync_service) = sync_service.upgrade() else {
                    return;
                };
                sync_service.subscribe_sync_status().await
            };

            let apply = |status: sync_service::SyncStatus| {
                let lifecycle_service = lifecycle_service.clone();
                async move {
                    let lifecycle_service = lifecycle_service.upgrade()?;
                    let phase = match status {
                        sync_service::SyncStatus::WarpSyncing { at, target } => {
                            Phase::Syncing { at, target }
                        }
                        sync_service::SyncStatus::Ready => Phase::Ready,
                    };
                    lifecycle_service.update(|s| s.phase = phase).await;
                    Some(())
                }
            };

            while let Ok(status) = sync_status.recv().await {
                if apply(status).await.is_none() {
                    return;
                }
                if matches!(status, sync_service::SyncStatus::WarpSyncing { .. }) {
                    platform.sleep(PROGRESS_BATCH_INTERVAL).await;
                    let mut newest = None;
                    while let Ok(newer) = sync_status.try_recv() {
                        newest = Some(newer);
                    }
                    if let Some(newest) = newest
                        && apply(newest).await.is_none()
                    {
                        return;
                    }
                }
            }
        }
    });

    // Drives `LifecycleState::num_peers` and `LifecycleState::health` by polling the network
    // service. Polling (rather than subscribing to network events) keeps this task from ever
    // slowing down the networking. The poll is frequent during the first minutes after a
    // subscriber appears, where an embedder is most likely to display the state, and relaxed
    // afterwards or once the chain is running with peers. Nothing is polled while the state
    // has no subscriber.
    platform.spawn_task("lifecycle-watchdog".into(), {
        let lifecycle_service = Arc::downgrade(&lifecycle_service);
        let network_service_chain = Arc::downgrade(network_service_chain);
        let platform = platform.clone();
        async move {
            const FAST_POLL_WINDOW: Duration = Duration::from_secs(120);

            let mut started = platform.now();
            let mut last_peer_seen = started.clone();
            // Warp sync height last observed, and when it was first observed.
            let mut last_progress: Option<(u64, TPlat::Instant)> = None;

            loop {
                let wait = {
                    let Some(lifecycle_service) = lifecycle_service.upgrade() else {
                        return;
                    };
                    lifecycle_service.wait_for_subscriber()
                };
                if let Some(wait) = wait {
                    wait.await;
                    // The time spent without a subscriber was not observed, so the stall
                    // clocks restart.
                    started = platform.now();
                    last_peer_seen = started.clone();
                    last_progress = None;
                    continue;
                }

                let num_peers = {
                    let Some(network_service_chain) = network_service_chain.upgrade() else {
                        return;
                    };
                    u32::try_from(network_service_chain.peers_list().await.count())
                        .unwrap_or(u32::MAX)
                };
                let has_peers = num_peers > 0;
                let Some(lifecycle_service) = lifecycle_service.upgrade() else {
                    return;
                };

                let now = platform.now();
                if has_peers {
                    last_peer_seen = now.clone();
                }

                let state = lifecycle_service.current().await;
                let no_progress_for = match (state.phase, &last_progress) {
                    (Phase::Syncing { at, .. }, Some((seen_at, since))) if *seen_at == at => {
                        Some(now.clone() - since.clone())
                    }
                    (Phase::Syncing { at, .. }, _) => {
                        last_progress = Some((at, now.clone()));
                        Some(Duration::ZERO)
                    }
                    _ => {
                        last_progress = None;
                        None
                    }
                };
                let health = health_verdict(now.clone() - last_peer_seen.clone(), no_progress_for);

                lifecycle_service
                    .update(|s| {
                        s.num_peers = num_peers;
                        s.health = health;
                    })
                    .await;
                drop(lifecycle_service);

                let settled = has_peers && matches!(state.phase, Phase::Ready);
                let fast = !settled && now - started.clone() < FAST_POLL_WINDOW;
                platform
                    .sleep(Duration::from_secs(if fast { 1 } else { 5 }))
                    .await;
            }
        }
    });

    lifecycle_service
}

/// Holder of the [`LifecycleState`] of one chain.
pub struct LifecycleService {
    state: Mutex<LifecycleState>,
    changed: event_listener::Event,
    /// Number of live [`Subscription`]s.
    num_subscribers: AtomicUsize,
    /// Notified when [`LifecycleService::num_subscribers`] goes from zero to one, and when the
    /// service is dropped.
    subscribed: event_listener::Event,
}

impl LifecycleService {
    pub fn new() -> Arc<Self> {
        Arc::new(LifecycleService {
            state: Mutex::new(LifecycleState::default()),
            changed: event_listener::Event::new(),
            num_subscribers: AtomicUsize::new(0),
            subscribed: event_listener::Event::new(),
        })
    }

    /// If no [`Subscription`] exists, returns a listener that resolves once one is created or
    /// the service is dropped. Returns `None` if a subscription already exists and there is
    /// nothing to wait for.
    ///
    /// Lets the tasks that maintain the state stay idle while nobody is watching.
    pub fn wait_for_subscriber(&self) -> Option<event_listener::EventListener> {
        let listener = self.subscribed.listen();
        if self.num_subscribers.load(Ordering::Acquire) > 0 {
            None
        } else {
            Some(listener)
        }
    }

    /// Returns the current state.
    pub async fn current(&self) -> LifecycleState {
        *self.state.lock().await
    }

    /// Modifies the state in place. Subscribers are woken up only if the state actually changed.
    pub async fn update(&self, f: impl FnOnce(&mut LifecycleState)) {
        let mut state = self.state.lock().await;
        let before = *state;
        f(&mut state);
        if *state != before {
            self.changed.notify(usize::MAX);
        }
    }

    /// Subscribes to state changes. The subscription holds only a weak reference, so it never
    /// keeps the chain alive.
    pub fn subscribe(self: &Arc<Self>) -> Subscription {
        if self.num_subscribers.fetch_add(1, Ordering::AcqRel) == 0 {
            self.subscribed.notify(usize::MAX);
        }
        Subscription {
            service: Arc::downgrade(self),
            last_seen: None,
        }
    }
}

impl Drop for LifecycleService {
    fn drop(&mut self) {
        // Wake up subscribers waiting in `Subscription::next` and tasks waiting in
        // `wait_for_subscriber` so that they observe the end.
        self.changed.notify(usize::MAX);
        self.subscribed.notify(usize::MAX);
    }
}

/// Handle returned by [`LifecycleService::subscribe`].
pub struct Subscription {
    service: Weak<LifecycleService>,
    /// Last state returned by [`Subscription::next`]. `None` before the first call.
    last_seen: Option<LifecycleState>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(service) = self.service.upgrade() {
            service.num_subscribers.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl Subscription {
    /// Returns the current state on the first call, then the newest state after each change.
    /// Returns `None` once the [`LifecycleService`] has been dropped, which happens when the
    /// chain is removed.
    pub async fn next(&mut self) -> Option<LifecycleState> {
        loop {
            let service = self.service.upgrade()?;
            let listener = {
                let state = service.state.lock().await;
                if self.last_seen != Some(*state) {
                    self.last_seen = Some(*state);
                    return Some(*state);
                }
                // The listener is created while the lock is held, so a change that happens after
                // the comparison above is guaranteed to wake it up.
                service.changed.listen()
            };
            drop(service);
            listener.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::{block_on, poll_once};

    #[test]
    fn first_next_returns_current_state() {
        block_on(async {
            let svc = LifecycleService::new();
            svc.update(|s| s.num_peers = 3).await;

            let mut sub = svc.subscribe();
            let state = sub.next().await.unwrap();

            assert_eq!(state.num_peers, 3);
            assert_eq!(state.phase, Phase::Connecting);
            assert!(poll_once(sub.next()).await.is_none());
        });
    }

    #[test]
    fn updates_are_coalesced_to_the_latest_state() {
        block_on(async {
            let svc = LifecycleService::new();
            let mut sub = svc.subscribe();
            assert_eq!(sub.next().await.unwrap(), LifecycleState::default());

            svc.update(|s| s.phase = Phase::Syncing { at: 1, target: 10 })
                .await;
            svc.update(|s| s.phase = Phase::Syncing { at: 2, target: 10 })
                .await;
            svc.update(|s| s.phase = Phase::Ready).await;

            assert_eq!(sub.next().await.unwrap().phase, Phase::Ready);
            assert!(poll_once(sub.next()).await.is_none());
        });
    }

    #[test]
    fn unchanged_update_does_not_wake_subscribers() {
        block_on(async {
            let svc = LifecycleService::new();
            let mut sub = svc.subscribe();
            sub.next().await.unwrap();

            svc.update(|s| s.num_peers = 0).await;

            assert!(poll_once(sub.next()).await.is_none());
        });
    }

    #[test]
    fn subscribers_are_independent() {
        block_on(async {
            let svc = LifecycleService::new();
            let mut fast = svc.subscribe();
            let mut slow = svc.subscribe();
            fast.next().await.unwrap();
            slow.next().await.unwrap();

            svc.update(|s| s.num_peers = 3).await;
            assert_eq!(fast.next().await.unwrap().num_peers, 3);
            svc.update(|s| s.phase = Phase::Ready).await;
            assert_eq!(fast.next().await.unwrap().phase, Phase::Ready);

            let seen_by_slow = slow.next().await.unwrap();
            assert_eq!(seen_by_slow.num_peers, 3);
            assert_eq!(seen_by_slow.phase, Phase::Ready);
            assert!(poll_once(slow.next()).await.is_none());
        });
    }

    #[test]
    fn wait_for_subscriber_tracks_live_subscriptions() {
        block_on(async {
            let svc = LifecycleService::new();
            let listener = svc.wait_for_subscriber().unwrap();
            assert!(poll_once(listener).await.is_none());

            let listener = svc.wait_for_subscriber().unwrap();
            let sub = svc.subscribe();
            assert!(poll_once(listener).await.is_some());
            assert!(svc.wait_for_subscriber().is_none());

            drop(sub);
            assert!(svc.wait_for_subscriber().is_some());
        });
    }

    #[test]
    fn wait_for_subscriber_wakes_when_service_is_dropped() {
        block_on(async {
            let svc = LifecycleService::new();
            let listener = svc.wait_for_subscriber().unwrap();
            drop(svc);
            assert!(poll_once(listener).await.is_some());
        });
    }

    #[test]
    fn next_returns_none_after_service_is_dropped() {
        block_on(async {
            let svc = LifecycleService::new();
            let mut sub = svc.subscribe();
            sub.next().await.unwrap();

            let pending = poll_once(sub.next()).await;
            assert!(pending.is_none());

            drop(svc);
            assert!(sub.next().await.is_none());
        });
    }

    #[test]
    fn health_verdict_thresholds() {
        let ok = Health::Ok;
        let no_peers = Health::Stalled {
            reason: StallReason::NoPeers,
        };
        let no_progress = Health::Stalled {
            reason: StallReason::NoProgress,
        };
        let just_under = |d: Duration| d - Duration::from_millis(1);

        assert_eq!(health_verdict(Duration::ZERO, None), ok);
        assert_eq!(health_verdict(just_under(NO_PEERS_TIMEOUT), None), ok);
        assert_eq!(health_verdict(NO_PEERS_TIMEOUT, None), no_peers);
        assert_eq!(
            health_verdict(Duration::ZERO, Some(just_under(NO_PROGRESS_TIMEOUT))),
            ok
        );
        assert_eq!(
            health_verdict(Duration::ZERO, Some(NO_PROGRESS_TIMEOUT)),
            no_progress
        );
        // No peers explains the missing progress, so it wins.
        assert_eq!(
            health_verdict(NO_PEERS_TIMEOUT, Some(NO_PROGRESS_TIMEOUT)),
            no_peers
        );
    }

    #[test]
    fn late_subscriber_sees_only_the_latest_state() {
        block_on(async {
            let svc = LifecycleService::new();
            svc.update(|s| s.phase = Phase::Syncing { at: 5, target: 9 })
                .await;
            svc.update(|s| {
                s.health = Health::Stalled {
                    reason: StallReason::NoProgress,
                }
            })
            .await;

            let mut sub = svc.subscribe();
            let state = sub.next().await.unwrap();

            assert_eq!(state.phase, Phase::Syncing { at: 5, target: 9 });
            assert_eq!(
                state.health,
                Health::Stalled {
                    reason: StallReason::NoProgress
                }
            );
        });
    }
}
