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

//! This module provides the `Delay` struct, which implement `Future` and becomes ready after a
//! certain time.
//!
//! In order to optimize performances, we avoid invoking the ffi once per timer. Instead, the ffi
//! is only used in order to wake up when the earliest timer finishes, then restarted for the next
//! timer.

use core::{
    cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd},
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};
use futures::{lock::Mutex, prelude::*};
use std::collections::BinaryHeap;

pub(crate) fn timer_finished(timer_id: u32) {
    let callback = {
        let ptr = timer_id as *mut Box<dyn FnOnce() + 'static>;
        unsafe { Box::from_raw(ptr) }
    };

    callback();
}

use super::Instant;

/// `Future` that automatically wakes up after a certain amount of time has elapsed.
pub struct Delay {
    /// Index in `TIMERS::timers`. Guaranteed to have `is_obsolete` equal to `false`.
    /// If `None`, then this timer is already ready.
    timer_id: Option<usize>,
}

impl Delay {
    pub fn new(after: Duration) -> Self {
        let now = Instant::now();
        Self::new_inner(now + after, now)
    }

    pub fn new_at(when: Instant) -> Self {
        Self::new_inner(when, Instant::now())
    }

    fn new_inner(when: Instant, now: Instant) -> Self {
        // Small optimization because sleeps of 0 seconds are frequent.
        if when <= now {
            return Delay { timer_id: None };
        }

        // Because we're in a single-threaded environment, `try_lock()` should always succeed.
        let mut lock = TIMERS.try_lock().unwrap();

        let timer_id = lock.timers.insert(Timer {
            is_finished: false,
            is_obsolete: false,
            waker: None,
        });

        let when_from_time_zero = when - lock.time_zero;
        lock.timers_queue.push(QueuedTimer {
            when_from_time_zero,
            timer_id,
        });

        // If the timer that has just been inserted is the one that ends the soonest, then
        // actually start the callback that will process timers.
        // Ideally we would instead cancel or update the deadline of the previous call to
        // `start_timer_wrap`, but this isn't possible.
        if lock.timers_queue.peek().unwrap().timer_id == timer_id {
            super::start_timer_wrap(when - now, process_timers);
        }

        Delay {
            timer_id: Some(timer_id),
        }
    }
}

impl Future for Delay {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let timer_id = match self.timer_id {
            Some(id) => id,
            None => return Poll::Ready(()),
        };

        // Because we're in a single-threaded environment, `try_lock()` should always succeed.
        let mut lock = TIMERS.try_lock().unwrap();
        debug_assert!(!lock.timers[timer_id].is_obsolete);

        if lock.timers[timer_id].is_finished {
            lock.timers.remove(timer_id);
            self.timer_id = None;
            return Poll::Ready(());
        }

        lock.timers[timer_id].waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl future::FusedFuture for Delay {
    fn is_terminated(&self) -> bool {
        self.timer_id.is_none()
    }
}

impl Drop for Delay {
    fn drop(&mut self) {
        let timer_id = match self.timer_id {
            Some(id) => id,
            None => return,
        };

        // Because we're in a single-threaded environment, `try_lock()` should always succeed.
        let mut lock = TIMERS.try_lock().unwrap();
        debug_assert!(!lock.timers[timer_id].is_obsolete);

        if lock.timers[timer_id].is_finished {
            lock.timers.remove(timer_id);
            return;
        }

        lock.timers[timer_id].is_obsolete = true;
        lock.timers[timer_id].waker = None;
    }
}

lazy_static::lazy_static! {
    static ref TIMERS: Mutex<Timers> = Mutex::new(Timers {
        timers_queue: BinaryHeap::new(),
        timers: slab::Slab::new(),
        time_zero: Instant::now(),
    });
}

struct Timers {
    /// Same entries as `timer`, but ordered based on when they're finished. Items are only ever
    /// removed from [`process_timers`], even if the corresponding [`Delay`] is destroyed.
    timers_queue: BinaryHeap<QueuedTimer>,

    /// List of all timers.
    timers: slab::Slab<Timer>,

    /// Arbitrary point in time set at initialization and that never changes. All moments in time
    /// are represented by `Duration`s relative to this value.
    time_zero: Instant,
}

struct Timer {
    /// If `true`, then this timer has elapsed.
    is_finished: bool,
    /// If `true`, then the corresponding `Delay` has been destroyed or no longer points to this
    /// item.
    is_obsolete: bool,
    /// How to wake up the `Delay`.
    waker: Option<Waker>,
}

struct QueuedTimer {
    when_from_time_zero: Duration,

    // Entry in `TIMERS::timers`. Guaranteed to always have `is_finished` equal to `false`.
    timer_id: usize,
}

impl PartialEq for QueuedTimer {
    fn eq(&self, other: &Self) -> bool {
        self.when_from_time_zero == other.when_from_time_zero
    }
}

impl Eq for QueuedTimer {}

impl PartialOrd for QueuedTimer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl Ord for QueuedTimer {
    fn cmp(&self, other: &Self) -> Ordering {
        // Since the `BinaryHeap` puts the highest item first, we reverse the ordering so that
        // the minimum `when_from_time_zero` is actually first.
        self.when_from_time_zero
            .cmp(&other.when_from_time_zero)
            .reverse()
    }
}

/// Marks as ready all the timers in `TIMERS` that are finished.
fn process_timers() {
    // Because we're in a single-threaded environment, `try_lock()` should always succeed.
    let mut lock = TIMERS.try_lock().unwrap();
    let now = Instant::now();

    // Note that this function can be called spuriously.
    // For example, `process_timers` can be scheduled twice from two different timers, and the
    // first call leads to both timers being finished, after which the second call will be
    // spurious.

    // Figure out the next time (relative to `time_zero`) we should call `process_timers`.
    //
    // This iterates through all the elements in `timers_queue` until a valid one is found.
    let next_wakeup: Option<Duration> = loop {
        let next_timer = match lock.timers_queue.peek() {
            Some(t) => t,
            None => break None,
        };

        // The `Delay` corresponding to the iterated timer has been destroyed. Removing it and
        // `continue`.
        if lock.timers[next_timer.timer_id].is_obsolete {
            let next_timer_id = next_timer.timer_id;
            lock.timers.remove(next_timer_id);
            lock.timers_queue.pop().unwrap();
            continue;
        }

        // Iterated timer is ready. Wake up the `Waker`, remove from the queue, and `continue`.
        if lock.time_zero + next_timer.when_from_time_zero <= now {
            let next_timer_id = next_timer.timer_id;
            debug_assert!(!lock.timers[next_timer_id].is_obsolete);
            lock.timers[next_timer_id].is_finished = true;
            if let Some(waker) = lock.timers[next_timer_id].waker.take() {
                waker.wake();
            }
            let _ = lock.timers_queue.pop().unwrap();
            continue;
        }

        // Iterated timer is not ready.
        break Some(next_timer.when_from_time_zero);
    };

    if let Some(next_wakeup) = next_wakeup {
        super::start_timer_wrap(lock.time_zero + next_wakeup - now, process_timers);
    } else {
        // Clean up memory a bit. Hopefully this doesn't impact performances too much.
        lock.timers_queue.shrink_to_fit();
        lock.timers.shrink_to_fit();
    }
}
