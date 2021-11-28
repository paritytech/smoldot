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

use super::ConnectError;

use core::{
    cmp::Ordering,
    fmt,
    future::Future,
    marker,
    ops::{Add, Sub},
    pin::Pin,
    slice, str,
    task::{Context, Poll},
    time::Duration,
};
use futures::{
    channel::{mpsc, oneshot},
    prelude::*,
};
use std::{
    collections::VecDeque,
    sync::{atomic, Arc, Mutex},
    task,
};

use timers::Delay;

pub mod bindings;
mod timers;

/// Stops execution, providing a string explaining what happened.
pub(crate) fn panic(message: String) -> ! {
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

/// Uses the environment to invoke `closure` after at least `duration` has elapsed.
fn start_timer_wrap(duration: Duration, closure: impl FnOnce()) {
    let callback: Box<Box<dyn FnOnce()>> = Box::new(Box::new(closure));
    let timer_id = u32::try_from(Box::into_raw(callback) as usize).unwrap();
    // Note that ideally `duration` should be rounded up in order to make sure that it is not
    // truncated, but the precision of an `f64` is so high and the precision of the operating
    // system generally so low that this is not worth dealing with.
    unsafe { bindings::start_timer(timer_id, duration.as_secs_f64() * 1000.0) }
}

#[derive(Debug, Copy, Clone)]
pub struct Instant {
    /// Milliseconds.
    inner: f64,
}

impl PartialEq for Instant {
    fn eq(&self, other: &Instant) -> bool {
        self.inner == other.inner
    }
}

impl Eq for Instant {}

impl PartialOrd for Instant {
    fn partial_cmp(&self, other: &Instant) -> Option<Ordering> {
        self.inner.partial_cmp(&other.inner)
    }
}

impl Ord for Instant {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.partial_cmp(&other.inner).unwrap()
    }
}

impl Instant {
    pub fn now() -> Instant {
        Instant {
            inner: unsafe { bindings::monotonic_clock_ms() },
        }
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, other: Duration) -> Instant {
        let new_val = self.inner + other.as_millis() as f64;
        Instant {
            inner: new_val as f64,
        }
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, other: Duration) -> Instant {
        let new_val = self.inner - other.as_millis() as f64;
        Instant {
            inner: new_val as f64,
        }
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, other: Instant) -> Duration {
        let ms = self.inner - other.inner;
        assert!(ms >= 0.0);
        Duration::from_millis(ms as u64)
    }
}

/// Implementation of [`log::Log`] that sends out logs to the FFI.
pub(crate) struct Logger;

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

            start_timer_wrap(Duration::new(0, 0), move || {
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

/// Connection connected to a target.
struct Connection {
    /// If `Some`, [`bindings::connection_close`] must be called. Set to a value after
    /// [`bindings::connection_new`] returns success.
    id: Option<u32>,
    /// True if [`bindings::connection_open`] has been called.
    open: bool,
    /// `Some` if [`bindings::connection_closed`] has been called.
    closed_message: Option<String>,
    /// List of messages received through [`bindings::connection_message`]. Must never contain
    /// empty messages.
    messages_queue: VecDeque<Box<[u8]>>,
    /// Position of the read cursor within the first element of [`Connection::messages_queue`].
    messages_queue_first_offset: usize,
    /// Channels to send a message on whenever one of the fields above is modified.
    // TODO: SmallVec instead?
    // TODO: use something better than a `Sender`?
    wakers: Vec<oneshot::Sender<()>>,
    /// Prevents the [`Connection`] from being unpinned.
    _pinned: marker::PhantomPinned,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Connection")
            .field(self.id.as_ref().unwrap())
            .finish()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            unsafe {
                bindings::connection_close(id);
            }
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

fn init(max_log_level: u32) {
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

    let client = super::Client::new(
        match max_log_level {
            0 => log::LevelFilter::Off,
            1 => log::LevelFilter::Error,
            2 => log::LevelFilter::Warn,
            3 => log::LevelFilter::Info,
            4 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        },
        new_task_tx.clone(),
    );

    let mut client_lock = CLIENT.lock().unwrap();
    assert!(client_lock.is_none());
    *client_lock = Some((client, new_task_tx));
}

fn add_chain(
    chain_spec_pointer: u32,
    chain_spec_len: u32,
    json_rpc_running: u32,
    potential_relay_chains_ptr: u32,
    potential_relay_chains_len: u32,
) -> u32 {
    let chain_spec: Box<[u8]> = {
        let chain_spec_pointer = usize::try_from(chain_spec_pointer).unwrap();
        let chain_spec_len = usize::try_from(chain_spec_len).unwrap();
        unsafe {
            Box::from_raw(slice::from_raw_parts_mut(
                chain_spec_pointer as *mut u8,
                chain_spec_len,
            ))
        }
    };

    let potential_relay_chains: Vec<_> = {
        let allowed_relay_chains_ptr = usize::try_from(potential_relay_chains_ptr).unwrap();
        let allowed_relay_chains_len = usize::try_from(potential_relay_chains_len).unwrap();

        let raw_data = unsafe {
            Box::from_raw(slice::from_raw_parts_mut(
                allowed_relay_chains_ptr as *mut u8,
                allowed_relay_chains_len * 4,
            ))
        };

        raw_data
            .chunks(4)
            .map(|c| u32::from_le_bytes(<[u8; 4]>::try_from(c).unwrap()))
            .map(super::ChainId::from)
            .collect()
    };

    let mut client_lock = CLIENT.lock().unwrap();

    let (json_rpc_responses, responses_rx) = if json_rpc_running != 0 {
        let (tx, rx) = mpsc::channel::<String>(64);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let chain_id = client_lock
        .as_mut()
        .unwrap()
        .0
        .add_chain(super::AddChainConfig {
            specification: str::from_utf8(&chain_spec).unwrap(),
            json_rpc_responses,
            potential_relay_chains: potential_relay_chains.into_iter(),
        });

    // TODO: must make abortable and all
    if let Some(mut responses_rx) = responses_rx {
        let messages_out_task = async move {
            while let Some(response) = responses_rx.next().await {
                emit_json_rpc_response(&response, chain_id);
            }
        };

        client_lock
            .as_mut()
            .unwrap()
            .1
            .unbounded_send((
                "json-rpc-service-messages-out".to_owned(),
                messages_out_task.map(|_| ()).boxed(),
            ))
            .unwrap();
    }

    chain_id.into()
}

fn remove_chain(chain_id: u32) {
    let mut client_lock = CLIENT.lock().unwrap();
    client_lock
        .as_mut()
        .unwrap()
        .0
        .remove_chain(super::ChainId::from(chain_id))
}

fn chain_is_ok(chain_id: u32) -> u32 {
    let mut client_lock = CLIENT.lock().unwrap();
    if client_lock
        .as_mut()
        .unwrap()
        .0
        .chain_is_erroneous(super::ChainId::from(chain_id))
        .is_some()
    {
        0
    } else {
        1
    }
}

fn chain_error_len(chain_id: u32) -> u32 {
    let mut client_lock = CLIENT.lock().unwrap();
    let len = client_lock
        .as_mut()
        .unwrap()
        .0
        .chain_is_erroneous(super::ChainId::from(chain_id))
        .map(|msg| msg.as_bytes().len())
        .unwrap_or(0);
    u32::try_from(len).unwrap()
}

fn chain_error_ptr(chain_id: u32) -> u32 {
    let mut client_lock = CLIENT.lock().unwrap();
    let ptr = client_lock
        .as_mut()
        .unwrap()
        .0
        .chain_is_erroneous(super::ChainId::from(chain_id))
        .map(|msg| msg.as_bytes().as_ptr() as usize)
        .unwrap_or(0);
    u32::try_from(ptr).unwrap()
}

lazy_static::lazy_static! {
    static ref CLIENT: Mutex<Option<(super::Client<Platform>, mpsc::UnboundedSender<(String, future::BoxFuture<'static, ()>)>)>> = Mutex::new(None);
}

struct Platform;

impl super::Platform for Platform {
    type Delay = Delay;
    type Instant = Instant;
    type Connection = Pin<Box<Connection>>;
    type ConnectFuture = future::BoxFuture<'static, Result<Self::Connection, ConnectError>>;
    type ConnectionDataFuture = future::BoxFuture<'static, ()>;

    fn now_from_unix_epoch() -> Duration {
        Duration::from_secs_f64(unsafe { bindings::unix_time_ms() } / 1000.0)
    }

    fn now() -> Self::Instant {
        Instant::now()
    }

    fn sleep(duration: Duration) -> Self::Delay {
        Delay::new(duration)
    }

    fn sleep_until(when: Self::Instant) -> Self::Delay {
        Delay::new_at(when)
    }

    fn connect(url: &str) -> Self::ConnectFuture {
        let mut pointer = Box::pin(Connection {
            id: None,
            open: false,
            closed_message: None,
            messages_queue: VecDeque::with_capacity(32),
            messages_queue_first_offset: 0,
            wakers: Vec::with_capacity(1),
            _pinned: marker::PhantomPinned,
        });

        let id = u32::try_from(&*pointer as *const Connection as usize).unwrap();

        let mut error_ptr = [0u8; 9];

        let ret_code = unsafe {
            bindings::connection_new(
                id,
                u32::try_from(url.as_bytes().as_ptr() as usize).unwrap(),
                u32::try_from(url.as_bytes().len()).unwrap(),
                u32::try_from(&mut error_ptr as *mut [u8; 9] as usize).unwrap(),
            )
        };

        let err = if ret_code != 0 {
            let ptr = u32::from_le_bytes(<[u8; 4]>::try_from(&error_ptr[0..4]).unwrap());
            let len = u32::from_le_bytes(<[u8; 4]>::try_from(&error_ptr[4..8]).unwrap());
            let error_message: Box<[u8]> = unsafe {
                Box::from_raw(slice::from_raw_parts_mut(
                    usize::try_from(ptr).unwrap() as *mut u8,
                    usize::try_from(len).unwrap(),
                ))
            };

            Err(ConnectError {
                message: str::from_utf8(&error_message).unwrap().to_owned(),
                is_bad_addr: error_ptr[8] != 0,
            })
        } else {
            unsafe {
                Pin::get_unchecked_mut(pointer.as_mut()).id = Some(id);
            }

            Ok(())
        };

        async move {
            if let Err(err) = err {
                return Err(err);
            }

            loop {
                if pointer.closed_message.is_some() || pointer.open {
                    break;
                }

                let (tx, rx) = oneshot::channel();
                unsafe {
                    Pin::get_unchecked_mut(pointer.as_mut()).wakers.push(tx);
                }
                let _ = rx.await;
            }

            if pointer.open {
                Ok(pointer)
            } else {
                debug_assert!(pointer.closed_message.is_some());
                Err(ConnectError {
                    message: pointer.closed_message.as_ref().unwrap().clone(),
                    is_bad_addr: false,
                })
            }
        }
        .boxed()
    }

    fn wait_more_data(connection: &mut Self::Connection) -> Self::ConnectionDataFuture {
        if !connection.messages_queue.is_empty() || connection.closed_message.is_some() {
            return future::ready(()).boxed();
        }

        let (tx, rx) = oneshot::channel();
        unsafe {
            Pin::get_unchecked_mut(connection.as_mut()).wakers.push(tx);
        }
        rx.map(|_| ()).boxed()
    }

    fn read_buffer(connection: &mut Self::Connection) -> Option<&[u8]> {
        if let Some(buffer) = connection.messages_queue.front() {
            debug_assert!(!buffer.is_empty());
            debug_assert!(connection.messages_queue_first_offset < buffer.len());
            Some(&buffer[connection.messages_queue_first_offset..])
        } else if connection.closed_message.is_some() {
            None
        } else {
            Some(&[])
        }
    }

    fn advance_read_cursor(connection: &mut Self::Connection, bytes: usize) {
        let this = unsafe { Pin::get_unchecked_mut(connection.as_mut()) };

        this.messages_queue_first_offset += bytes;

        if let Some(buffer) = this.messages_queue.front() {
            assert!(this.messages_queue_first_offset <= buffer.len());
            if this.messages_queue_first_offset == buffer.len() {
                this.messages_queue.pop_front();
                this.messages_queue_first_offset = 0;
            }
        } else {
            assert_eq!(bytes, 0);
        };
    }

    fn send(connection: &mut Self::Connection, data: &[u8]) {
        unsafe {
            let this = Pin::get_unchecked_mut(connection.as_mut());

            // Connection might have been closed, but API user hasn't detected it yet.
            if this.closed_message.is_some() {
                return;
            }

            bindings::connection_send(
                this.id.unwrap(),
                u32::try_from(data.as_ptr() as usize).unwrap(),
                u32::try_from(data.len()).unwrap(),
            );
        }
    }
}

fn json_rpc_send(ptr: u32, len: u32, chain_id: u32) {
    let chain_id = super::ChainId::from(chain_id);

    let json_rpc_request: Box<[u8]> = {
        let ptr = usize::try_from(ptr).unwrap();
        let len = usize::try_from(len).unwrap();
        unsafe { Box::from_raw(slice::from_raw_parts_mut(ptr as *mut u8, len)) }
    };

    // As mentioned in the documentation, the bytes *must* be valid UTF-8.
    let json_rpc_request: String = String::from_utf8(json_rpc_request.into()).unwrap();

    let mut client_lock = CLIENT.lock().unwrap();
    client_lock
        .as_mut()
        .unwrap()
        .0
        .json_rpc_request(json_rpc_request, chain_id);
}

/// Emit a JSON-RPC response or subscription notification in destination to the JavaScript side.
// TODO: maybe tie the JSON-RPC system to a certain "client", instead of being global?
pub(crate) fn emit_json_rpc_response(rpc: &str, chain_id: super::ChainId) {
    unsafe {
        bindings::json_rpc_respond(
            u32::try_from(rpc.as_bytes().as_ptr() as usize).unwrap(),
            u32::try_from(rpc.as_bytes().len()).unwrap(),
            u32::from(chain_id),
        );
    }
}

fn timer_finished(timer_id: u32) {
    let callback = {
        let ptr = timer_id as *mut Box<dyn FnOnce()>;
        unsafe { Box::from_raw(ptr) }
    };

    callback();
}

fn connection_open(id: u32) {
    let connection = unsafe { &mut *(usize::try_from(id).unwrap() as *mut Connection) };
    connection.open = true;
    for waker in connection.wakers.drain(..) {
        let _ = waker.send(());
    }
}

fn connection_message(id: u32, ptr: u32, len: u32) {
    let connection = unsafe { &mut *(usize::try_from(id).unwrap() as *mut Connection) };

    let ptr = usize::try_from(ptr).unwrap();
    let len = usize::try_from(len).unwrap();

    let message: Box<[u8]> =
        unsafe { Box::from_raw(slice::from_raw_parts_mut(ptr as *mut u8, len)) };

    // Ignore empty message to avoid all sorts of problems.
    if message.is_empty() {
        return;
    }

    if connection.messages_queue.is_empty() {
        connection.messages_queue_first_offset = 0;
    }

    // TODO: add some limit to `messages_queue`, to avoid DoS attacks?

    connection.messages_queue.push_back(message);

    for waker in connection.wakers.drain(..) {
        let _ = waker.send(());
    }
}

fn connection_closed(id: u32, ptr: u32, len: u32) {
    let connection = unsafe { &mut *(usize::try_from(id).unwrap() as *mut Connection) };

    connection.closed_message = Some({
        let ptr = usize::try_from(ptr).unwrap();
        let len = usize::try_from(len).unwrap();
        let message: Box<[u8]> =
            unsafe { Box::from_raw(slice::from_raw_parts_mut(ptr as *mut u8, len)) };
        str::from_utf8(&message).unwrap().to_owned()
    });

    for waker in connection.wakers.drain(..) {
        let _ = waker.send(());
    }
}
