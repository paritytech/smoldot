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
//! The schema is unstable.

use alloc::sync::{Arc, Weak};
use async_lock::Mutex;
use core::time::Duration;

/// Time without any connected peer after which the chain is reported as stalled.
pub(crate) const NO_PEERS_TIMEOUT: Duration = Duration::from_secs(30);

/// Time without warp sync progress after which the chain is reported as stalled.
pub(crate) const NO_PROGRESS_TIMEOUT: Duration = Duration::from_secs(45);

/// Decides the [`Health`] from how long the chain has had no peer and, if a warp sync is in
/// progress, how long it has not advanced.
pub(crate) fn health_verdict(no_peers_for: Duration, no_progress_for: Option<Duration>) -> Health {
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
    /// `true` if at least one peer is currently connected on this chain.
    pub has_peers: bool,
    pub health: Health,
}

impl Default for LifecycleState {
    fn default() -> Self {
        LifecycleState {
            phase: Phase::Connecting,
            has_peers: false,
            health: Health::Ok,
        }
    }
}

/// Holder of the [`LifecycleState`] of one chain.
pub struct LifecycleService {
    state: Mutex<LifecycleState>,
    changed: event_listener::Event,
}

impl LifecycleService {
    pub fn new() -> Arc<Self> {
        Arc::new(LifecycleService {
            state: Mutex::new(LifecycleState::default()),
            changed: event_listener::Event::new(),
        })
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
        Subscription {
            service: Arc::downgrade(self),
            last_seen: None,
        }
    }
}

impl Drop for LifecycleService {
    fn drop(&mut self) {
        // Wake up subscribers waiting in `Subscription::next` so that they observe the end.
        self.changed.notify(usize::MAX);
    }
}

/// Handle returned by [`LifecycleService::subscribe`].
pub struct Subscription {
    service: Weak<LifecycleService>,
    /// Last state returned by [`Subscription::next`]. `None` before the first call.
    last_seen: Option<LifecycleState>,
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
            svc.update(|s| s.has_peers = true).await;

            let mut sub = svc.subscribe();
            let state = sub.next().await.unwrap();

            assert!(state.has_peers);
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

            svc.update(|s| s.has_peers = false).await;

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

            svc.update(|s| s.has_peers = true).await;
            assert!(fast.next().await.unwrap().has_peers);
            svc.update(|s| s.phase = Phase::Ready).await;
            assert_eq!(fast.next().await.unwrap().phase, Phase::Ready);

            let seen_by_slow = slow.next().await.unwrap();
            assert!(seen_by_slow.has_peers);
            assert_eq!(seen_by_slow.phase, Phase::Ready);
            assert!(poll_once(slow.next()).await.is_none());
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
