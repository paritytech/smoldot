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

use crate::{alloc, bindings, cpu_rate_limiter, platform, timers::Delay};

use core::{future::Future, pin::Pin, time::Duration};
use futures::{channel::mpsc, prelude::*};
use smoldot::informant::BytesDisplay;
use std::{panic, sync::atomic::Ordering, task};

pub(crate) struct Client<TPlat: smoldot_light::platform::Platform, TChain> {
    pub(crate) smoldot: smoldot_light::Client<TPlat, TChain>,

    /// List of all chains that have been added by the user.
    pub(crate) chains: slab::Slab<Chain>,

    pub(crate) periodically_yield: bool,

    /// Infinite-running task that must be executed in order to drive the execution of the client.
    pub(crate) main_task: future::BoxFuture<'static, core::convert::Infallible>, // TODO: use `!` once stable
}

pub(crate) enum Chain {
    Healthy {
        smoldot_chain_id: smoldot_light::ChainId,

        /// JSON-RPC responses that is at the front of the queue according to the API. If `Some`,
        /// a pointer to the string is referenced to within
        /// [`Chain::Healthy::json_rpc_response_info`].
        json_rpc_response: Option<String>,
        /// Information about [`Chain::Healthy::json_rpc_response`]. A pointer to this struct is
        /// sent over the FFI layer to the JavaScript. As such, the pointer must never be
        /// invalidated.
        json_rpc_response_info: Box<bindings::JsonRpcResponseInfo>,
        /// Receiver for JSON-RPC responses sent by the client. `None` if JSON-RPC requests are
        /// disabled on this chain.
        /// While this could in principle be a [`smoldot_light::JsonRpcResponses`], we wrap it
        /// within a [`futures::Stream`] in order to guarantee that the `waker` that we register
        /// doesn't get cleaned up.
        json_rpc_responses_rx: Option<stream::BoxStream<'static, String>>,
    },
    Erroneous {
        error: String,
    },
}

pub(crate) fn init<TPlat: smoldot_light::platform::Platform, TChain>(
    max_log_level: u32,
    enable_current_task: bool,
    cpu_rate_limit: u32,
    periodically_yield: bool,
) -> Client<TPlat, TChain> {
    // Try initialize the logging and the panic hook.
    let _ = log::set_boxed_logger(Box::new(Logger)).map(|()| {
        log::set_max_level(match max_log_level {
            0 => log::LevelFilter::Off,
            1 => log::LevelFilter::Error,
            2 => log::LevelFilter::Warn,
            3 => log::LevelFilter::Info,
            4 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        })
    });
    panic::set_hook(Box::new(|info| {
        panic(info.to_string());
    }));

    // First things first, print the version in order to make it easier to debug issues by
    // reading logs provided by third parties.
    log::info!(
        target: "smoldot",
        "Smoldot v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Simple fool-proof check to make sure that randomness is properly implemented.
    assert_ne!(rand::random::<u64>(), 0);
    assert_ne!(rand::random::<u64>(), rand::random::<u64>());

    // A channel needs to be passed to the client in order for it to spawn background tasks.
    // Since "spawning a task" isn't really something that a browser or Node environment can do
    // efficiently, we instead combine all the asynchronous tasks into one `FuturesUnordered`
    // below.
    let (new_task_tx, mut new_task_rx) =
        mpsc::unbounded::<(String, future::BoxFuture<'static, ()>)>();

    // This is the main future that executes the entire client.
    // It receives new tasks from `new_task_rx` and runs them.
    let main_task = cpu_rate_limiter::CpuRateLimiter::new(
        async move {
            let mut all_tasks = stream::FuturesUnordered::new();

            // The code below processes tasks that have names.
            #[pin_project::pin_project]
            struct FutureAdapter<F> {
                name: String,
                enable_current_task: bool,
                #[pin]
                future: F,
            }

            impl<F: Future> Future for FutureAdapter<F> {
                type Output = F::Output;
                fn poll(self: Pin<&mut Self>, cx: &mut task::Context) -> task::Poll<Self::Output> {
                    let this = self.project();
                    if *this.enable_current_task {
                        unsafe {
                            bindings::current_task_entered(
                                u32::try_from(this.name.as_bytes().as_ptr() as usize).unwrap(),
                                u32::try_from(this.name.as_bytes().len()).unwrap(),
                            )
                        }
                    }
                    let out = this.future.poll(cx);
                    if *this.enable_current_task {
                        unsafe {
                            bindings::current_task_exit();
                        }
                    }
                    out
                }
            }

            loop {
                futures::select! {
                    (new_task_name, new_task) = new_task_rx.select_next_some() => {
                        all_tasks.push(FutureAdapter {
                            name: new_task_name,
                            enable_current_task,
                            future: new_task,
                        });
                    },
                    () = all_tasks.select_next_some() => {},
                }
            }
        },
        cpu_rate_limit,
    )
    .boxed();

    // Spawn a constantly-running task that periodically prints the total memory usage of
    // the node.
    new_task_tx
        .unbounded_send((
            "memory-printer".to_owned(),
            Box::pin(async move {
                let mut previous_read_bytes = 0;
                let mut previous_sent_bytes = 0;
                let interval = 60;

                loop {
                    Delay::new(Duration::from_secs(interval)).await;

                    // For the unwrap below to fail, the quantity of allocated would have to
                    // not fit in a `u64`, which as of 2021 is basically impossible.
                    let mem = u64::try_from(alloc::total_alloc_bytes()).unwrap();

                    // Due to the way the calculation below is performed, sending or receiving
                    // more than `type_of(TOTAL_BYTES_RECEIVED or TOTAL_BYTES_SENT)::max_value`
                    // bytes within an interval will lead to an erroneous value being shown to the
                    // user. At the time of writing of this comment, they are 64bits, so we just
                    // assume that this can't happen. If it does happen, the fix would consist in
                    // increasing the size of `TOTAL_BYTES_RECEIVED` or `TOTAL_BYTES_SENT`.

                    let bytes_rx = platform::TOTAL_BYTES_RECEIVED.load(Ordering::Relaxed);
                    let avg_dl = u64::try_from(bytes_rx.wrapping_sub(previous_read_bytes)).unwrap() / interval;
                    previous_read_bytes = bytes_rx;

                    let bytes_tx = platform::TOTAL_BYTES_SENT.load(Ordering::Relaxed);
                    let avg_up = u64::try_from(bytes_tx.wrapping_sub(previous_sent_bytes)).unwrap() / interval;
                    previous_sent_bytes = bytes_tx;

                    // Note that we also print the version at every interval, in order to increase
                    // the chance of being able to know the version in case of truncated logs.
                    log::info!(
                        target: "smoldot",
                        "Smoldot v{}. Current memory usage: {}. Average download: {}/s. Average upload: {}/s.",
                        env!("CARGO_PKG_VERSION"),
                        BytesDisplay(mem),
                        BytesDisplay(avg_dl),
                        BytesDisplay(avg_up)
                    );
                }
            }),
        ))
        .unwrap();

    let client = smoldot_light::Client::new(smoldot_light::ClientConfig {
        tasks_spawner: Box::new(move |name, task| {
            new_task_tx.unbounded_send((name, task)).unwrap()
        }),
        system_name: env!("CARGO_PKG_NAME").into(),
        system_version: env!("CARGO_PKG_VERSION").into(),
    });

    Client {
        smoldot: client,
        chains: slab::Slab::with_capacity(8),
        periodically_yield,
        main_task,
    }
}

/// Stops execution, providing a string explaining what happened.
fn panic(message: String) -> ! {
    unsafe {
        bindings::panic(
            u32::try_from(message.as_bytes().as_ptr() as usize).unwrap(),
            u32::try_from(message.as_bytes().len()).unwrap(),
        );

        // Even though this code is intended to only ever be compiled for Wasm, it might, for
        // various reasons, be compiled for the host platform as well. We use platform-specific
        // code to make sure that it compiles for all platforms.
        #[cfg(target_arch = "wasm32")]
        core::arch::wasm32::unreachable();
        #[cfg(not(target_arch = "wasm32"))]
        unreachable!();
    }
}

/// Implementation of [`log::Log`] that sends out logs to the FFI.
struct Logger;

impl log::Log for Logger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let target = record.target();
        let message = format!("{}", record.args());

        unsafe {
            bindings::log(
                record.level() as usize as u32,
                u32::try_from(target.as_bytes().as_ptr() as usize).unwrap(),
                u32::try_from(target.as_bytes().len()).unwrap(),
                u32::try_from(message.as_bytes().as_ptr() as usize).unwrap(),
                u32::try_from(message.as_bytes().len()).unwrap(),
            )
        }
    }

    fn flush(&self) {}
}
