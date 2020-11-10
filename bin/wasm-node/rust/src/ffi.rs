// Substrate-lite
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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
    convert::TryFrom as _,
    future::Future,
    pin::Pin,
    slice,
    task::{Context, Poll},
    time::Duration,
};
use std::sync::{atomic, Arc, Mutex};

pub mod bindings;

/// Stops execution, throwing a string exception with the given content.
pub(crate) fn throw(message: String) -> ! {
    unsafe {
        bindings::throw(
            u32::try_from(message.as_bytes().as_ptr() as usize).unwrap(),
            u32::try_from(message.as_bytes().len()).unwrap(),
        );

        // Note: we could theoretically use `unreachable_unchecked` here, but this relies on the
        // fact that `ffi::throw` is correctly implemented, which isn't 100% guaranteed.
        unreachable!();
    }
}

pub(crate) fn unix_time() -> Duration {
    Duration::from_secs_f64(unsafe { bindings::unix_time_ms() } / 1000.0)
}

/// Spawn a background task that runs forever.
pub(crate) fn spawn_task(future: impl Future<Output = ()> + Send + 'static) {
    struct Waker {
        done: atomic::AtomicBool,
        wake_up_registered: atomic::AtomicBool,
        future: Mutex<Pin<Box<dyn Future<Output = ()> + Send>>>,
    }

    impl futures::task::ArcWake for Waker {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            if arc_self
                .wake_up_registered
                .swap(true, atomic::Ordering::Relaxed)
            {
                return;
            }

            let arc_self = arc_self.clone();
            start_timer_wrap(Duration::from_millis(1), move || {
                if arc_self.done.load(atomic::Ordering::SeqCst) {
                    return;
                }

                let mut future = arc_self.future.try_lock().unwrap();
                arc_self
                    .wake_up_registered
                    .store(false, atomic::Ordering::SeqCst);
                match Future::poll(
                    future.as_mut(),
                    &mut Context::from_waker(&futures::task::waker_ref(&arc_self)),
                ) {
                    Poll::Ready(()) => {
                        arc_self.done.store(true, atomic::Ordering::SeqCst);
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

    futures::task::ArcWake::wake(waker);
}

/// Uses the environment to invoke `closure` after `duration` has elapsed.
fn start_timer_wrap(duration: Duration, closure: impl FnOnce()) {
    let callback: Box<Box<dyn FnOnce()>> = Box::new(Box::new(closure));
    let timer_id = u32::try_from(Box::into_raw(callback) as usize).unwrap();
    let milliseconds = u64::try_from(duration.as_millis())
        .unwrap_or(u64::max_value())
        .saturating_add(1);
    unsafe { bindings::start_timer(timer_id, milliseconds as f64) }
}

pub struct WebSocket {}

impl WebSocket {
    pub fn new(url: &str) -> Result<Pin<Box<Self>>, ()> {
        let mut pointer = Box::pin(WebSocket {});
        let id = u32::try_from(&*pointer as *const WebSocket as usize).unwrap();
        let ret_code = unsafe {
            bindings::websocket_new(
                id,
                u32::try_from(url.as_bytes().as_ptr() as usize).unwrap(),
                u32::try_from(url.as_bytes().len()).unwrap(),
            )
        };
        if ret_code == 0 {
            Ok(pointer)
        } else {
            Err(())
        }
    }
}

fn alloc(len: u32) -> u32 {
    let len = usize::try_from(len).unwrap();
    let mut vec = Vec::<u8>::with_capacity(len);
    unsafe {
        vec.set_len(len);
    }
    let ptr: *mut [u8] = Box::into_raw(vec.into_boxed_slice());
    u32::try_from(ptr as *mut u8 as usize).unwrap()
}

fn init(
    chain_specs_ptr: u32,
    chain_specs_len: u32,
    database_content_ptr: u32,
    database_content_len: u32,
) {
    let chain_specs_ptr = usize::try_from(chain_specs_ptr).unwrap();
    let chain_specs_len = usize::try_from(chain_specs_len).unwrap();
    let database_content_ptr = usize::try_from(database_content_ptr).unwrap();
    let database_content_len = usize::try_from(database_content_len).unwrap();

    let chain_specs: Box<[u8]> = unsafe {
        Box::from_raw(slice::from_raw_parts_mut(
            chain_specs_ptr as *mut u8,
            chain_specs_len,
        ))
    };

    // TODO: don't unwrap
    let chain_specs = String::from_utf8(Vec::from(chain_specs)).unwrap();

    let database_content = if database_content_ptr != 0 {
        Some(unsafe {
            Box::from_raw(slice::from_raw_parts_mut(
                database_content_ptr as *mut u8,
                database_content_len,
            ))
        })
    } else {
        None
    };

    spawn_task(super::start_client(chain_specs));
}

fn timer_finished(timer_id: u32) {
    let callback = {
        let ptr = timer_id as *mut Box<dyn FnOnce()>;
        unsafe { Box::from_raw(ptr) }
    };

    callback();
}

fn websocket_open(id: u32) {
    let websocket = unsafe { &mut *(usize::try_from(id).unwrap() as *mut WebSocket) };
}

fn websocket_message(id: u32, ptr: u32, len: u32) {
    let websocket = unsafe { &mut *(usize::try_from(id).unwrap() as *mut WebSocket) };

    let ptr = usize::try_from(ptr).unwrap();
    let len = usize::try_from(len).unwrap();

    let message: Box<[u8]> =
        unsafe { Box::from_raw(slice::from_raw_parts_mut(ptr as *mut u8, len)) };
}

fn websocket_closed(id: u32) {
    let websocket = unsafe { &mut *(usize::try_from(id).unwrap() as *mut WebSocket) };
}
