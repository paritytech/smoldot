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

// TODO: the quality of this module is sub-par

use crate::{alloc, bindings, timers::Delay};

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use futures::{channel::mpsc, prelude::*};
use smoldot::informant::BytesDisplay;
use std::{
    sync::{atomic, Arc, Mutex},
    task,
};

pub(crate) fn init(max_log_level: u32) {
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
    std::panic::set_hook(Box::new(|info| {
        panic(info.to_string());
    }));

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
    spawn_background_task(async move {
        let mut all_tasks = stream::FuturesUnordered::new();

        // The code below processes tasks that have names.
        #[pin_project::pin_project]
        struct FutureAdapter<F> {
            name: String,
            #[pin]
            future: F,
        }

        impl<F: Future> Future for FutureAdapter<F> {
            type Output = F::Output;
            fn poll(self: Pin<&mut Self>, cx: &mut task::Context) -> task::Poll<Self::Output> {
                let this = self.project();
                log::trace!(target: "smoldot", "enter: {}", &this.name);
                let out = this.future.poll(cx);
                log::trace!(target: "smoldot", "leave");
                out
            }
        }

        loop {
            futures::select! {
                (new_task_name, new_task) = new_task_rx.select_next_some() => {
                    all_tasks.push(FutureAdapter {
                        name: new_task_name,
                        future: new_task,
                    });
                },
                () = all_tasks.select_next_some() => {},
            }
        }
    });

    // Spawn a constantly-running task that periodically prints the total memory usage of
    // the node.
    new_task_tx
        .unbounded_send((
            "memory-printer".to_owned(),
            Box::pin(async move {
                loop {
                    Delay::new(Duration::from_secs(60)).await;

                    // For the unwrap below to fail, the quantity of allocated would have to
                    // not fit in a `u64`, which as of 2021 is basically impossible.
                    let mem = u64::try_from(alloc::total_alloc_bytes()).unwrap();
                    log::info!(target: "smoldot", "Node memory usage: {}", BytesDisplay(mem));
                }
            }),
        ))
        .unwrap();

    let client = smoldot_light_base::Client::new(new_task_tx.clone());

    let mut client_lock = crate::CLIENT.lock().unwrap();
    assert!(client_lock.is_none());
    *client_lock = Some((client, new_task_tx));
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

fn spawn_background_task(future: impl Future<Output = ()> + Send + 'static) {
    struct Waker {
        done: atomic::AtomicBool,
        wake_up_registered: atomic::AtomicBool,
        future: Mutex<future::BoxFuture<'static, ()>>,
    }

    impl task::Wake for Waker {
        fn wake(self: Arc<Self>) {
            if self
                .wake_up_registered
                .swap(true, atomic::Ordering::Relaxed)
            {
                return;
            }

            crate::start_timer_wrap(Duration::new(0, 0), move || {
                if self.done.load(atomic::Ordering::SeqCst) {
                    return;
                }

                let mut future = self.future.try_lock().unwrap();
                self.wake_up_registered
                    .store(false, atomic::Ordering::SeqCst);
                match Future::poll(
                    future.as_mut(),
                    &mut Context::from_waker(&task::Waker::from(self.clone())),
                ) {
                    Poll::Ready(()) => {
                        self.done.store(true, atomic::Ordering::SeqCst);
                    }
                    Poll::Pending => {}
                }
            })
        }
    }

    let waker = Arc::new(Waker {
        done: false.into(),
        wake_up_registered: false.into(),
        future: Mutex::new(Box::pin(future)),
    });

    task::Wake::wake(waker);
}
