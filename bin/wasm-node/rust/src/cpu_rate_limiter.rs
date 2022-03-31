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

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Wraps around a `Future` and enforces an upper bound to the CPU consumed by the polling of
/// this `Future`.
///
/// This works by enforcing a delay after a polling operation has happened, so that the average
/// polling time respects the upper bound. This struct doesn't protect against infinite loops or
/// a single polling taking a long time.
#[pin_project::pin_project]
pub struct CpuRateLimiter<T> {
    #[pin]
    inner: T,
    max_divided_by_rate_limit_minus_one: f64,

    /// Prevent `self.inner.poll` from being called before this `Delay` is ready.
    #[pin]
    prevent_poll_until: crate::timers::Delay,
}

impl<T> CpuRateLimiter<T> {
    /// Wraps around `inner`. The `rate_limit` represents the upper bound, where
    /// `u32::max_value()` represents "one CPU". For example passing `rate_limit / 2` represents
    /// "50% of one CPU".
    pub fn new(inner: T, rate_limit: u32) -> Self {
        let max_divided_by_rate_limit_minus_one =
            (f64::from(u32::max_value()) / f64::from(rate_limit)) - 1.0;
        debug_assert!(
            max_divided_by_rate_limit_minus_one.is_finite()
                && max_divided_by_rate_limit_minus_one >= 0.0
        );

        CpuRateLimiter {
            inner,
            max_divided_by_rate_limit_minus_one,
            prevent_poll_until: crate::timers::Delay::new(Duration::new(0, 0)),
        }
    }
}

impl<T: Future> Future for CpuRateLimiter<T> {
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut this = self.project();

        // Note that `crate::times::Delay` is a `FusedFuture`, making it ok to call `poll` even
        // if it is possible for the `Delay` to already be resolved.
        // We add a small zero-cost shim to ensure at compile time that this is indeed the case.
        fn enforce_fused<T: futures::future::FusedFuture>(_: &T) {}
        enforce_fused(&this.prevent_poll_until);
        if let Poll::Pending = Future::poll(this.prevent_poll_until.as_mut(), cx) {
            return Poll::Pending;
        }

        let before_polling = crate::Instant::now();

        match this.inner.poll(cx) {
            Poll::Ready(value) => return Poll::Ready(value),
            Poll::Pending => {
                let after_polling = crate::Instant::now();

                // Time it took to execute `poll`.
                let poll_duration = after_polling - before_polling;

                // In order to enforce the rate limiting, we prevent `poll` from executing
                // for a certain amount of time.
                // The base equation here is: `(after_poll_sleep + poll_duration) * rate_limit == poll_duration * u32::max_value()`.
                // Because `Duration::mul_f64` panics in case of overflow, we need to do the
                // operation of multiplying and checking the bounds manually.
                let mut after_poll_sleep =
                    poll_duration.as_secs_f64() * *this.max_divided_by_rate_limit_minus_one;
                let max_duration_float: f64 = Duration::MAX.as_secs_f64();  // TODO: turn this into a `const` once `as_secs_f64` is `const`
                if !(after_poll_sleep < max_duration_float) {
                    after_poll_sleep = max_duration_float;
                }
                // TODO: use try_from_secs_f64 when it's stable https://github.com/rust-lang/rust/issues/83400

                this.prevent_poll_until.set(crate::timers::Delay::new_at(
                    after_polling + Duration::from_secs_f64(after_poll_sleep),
                ));
                Poll::Pending
            }
        }
    }
}

impl<T: futures::future::FusedFuture> futures::future::FusedFuture for CpuRateLimiter<T> {
    fn is_terminated(&self) -> bool {
        self.inner.is_terminated()
    }
}
