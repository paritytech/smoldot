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

use crate::{bindings, timers::Delay};

use futures_lite::future::FutureExt as _;

use smoldot_light::platform::{SubstreamDirection, read_write};

use alloc::{
    borrow::{Cow, ToOwned as _},
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    format,
    string::{String, ToString as _},
    vec::Vec,
};
use async_lock::Mutex;
use core::{
    fmt::{self, Write as _},
    future, iter, mem,
    net::IpAddr,
    ops, pin, str,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
    task,
    time::Duration,
};

/// Total number of bytes that all the connections created through [`PlatformRef`] combined have
/// received.
pub static TOTAL_BYTES_RECEIVED: AtomicU64 = AtomicU64::new(0);
/// Total number of bytes that all the connections created through [`PlatformRef`] combined have
/// sent.
pub static TOTAL_BYTES_SENT: AtomicU64 = AtomicU64::new(0);
/// Total number of microseconds that all the tasks have spent executing. A `u64` will overflow
/// after 584 542 years.
pub static TOTAL_CPU_USAGE_US: AtomicU64 = AtomicU64::new(0);

pub(crate) const PLATFORM_REF: PlatformRef = PlatformRef {};

/// Log level above which log entries aren't emitted.
pub static MAX_LOG_LEVEL: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Copy, Clone)]
pub(crate) struct PlatformRef {}

// TODO: this trait implementation was written before GATs were stable in Rust; now that the associated types have lifetimes, it should be possible to considerably simplify this code
impl smoldot_light::platform::PlatformRef for PlatformRef {
    type Delay = Delay;
    type Instant = Duration;
    type MultiStream = MultiStreamWrapper; // Entry in the ̀`CONNECTIONS` map.
    type Stream = StreamWrapper; // Entry in the ̀`STREAMS` map and a read buffer.
    type StreamConnectFuture = future::Ready<Self::Stream>;
    type ReadWriteAccess<'a> = ReadWriteAccess<'a>;
    type StreamErrorRef<'a> = StreamError;
    type MultiStreamConnectFuture = pin::Pin<
        Box<
            dyn Future<
                    Output = smoldot_light::platform::MultiStreamWebRtcConnection<
                        Self::MultiStream,
                    >,
                > + Send,
        >,
    >;
    type StreamUpdateFuture<'a> = pin::Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
    type NextSubstreamFuture<'a> = pin::Pin<
        Box<
            dyn Future<Output = Option<(Self::Stream, smoldot_light::platform::SubstreamDirection)>>
                + Send
                + 'a,
        >,
    >;

    fn now_from_unix_epoch(&self) -> Duration {
        let microseconds = bindings::unix_timestamp_us();
        Duration::from_micros(microseconds)
    }

    fn now(&self) -> Self::Instant {
        let microseconds = bindings::monotonic_clock_us();
        Duration::from_micros(microseconds)
    }

    fn fill_random_bytes(&self, buffer: &mut [u8]) {
        unsafe {
            bindings::random_get(
                u32::try_from(buffer.as_mut_ptr().addr()).unwrap(),
                u32::try_from(buffer.len()).unwrap(),
            )
        }
    }

    fn sleep(&self, duration: Duration) -> Self::Delay {
        Delay::new(duration)
    }

    fn sleep_until(&self, when: Self::Instant) -> Self::Delay {
        Delay::new_at_monotonic_clock(when)
    }

    fn spawn_task(&self, task_name: Cow<str>, task: impl Future<Output = ()> + Send + 'static) {
        // The code below processes tasks that have names.
        #[pin_project::pin_project]
        struct FutureAdapter<F> {
            name: String,
            #[pin]
            future: F,
        }

        impl<F: Future> Future for FutureAdapter<F> {
            type Output = F::Output;
            fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context) -> task::Poll<Self::Output> {
                let this = self.project();
                bindings::current_task_entered(
                    u32::try_from(this.name.as_bytes().as_ptr().addr()).unwrap(),
                    u32::try_from(this.name.as_bytes().len()).unwrap(),
                );

                let before_polling = bindings::monotonic_clock_us();
                let out = this.future.poll(cx);
                let poll_duration =
                    Duration::from_micros(bindings::monotonic_clock_us() - before_polling);
                TOTAL_CPU_USAGE_US.fetch_add(
                    u64::try_from(poll_duration.as_micros()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );

                bindings::current_task_exit();

                // Print a warning if polling the task takes a long time.
                // It has been noticed that sometimes in Firefox polling a task takes a 16ms + a
                // small amount. This most likely indicates that Firefox does something like
                // freezing the JS/Wasm execution before resuming it at the next frame, thus adding
                // 16ms to the execution time.
                // For this reason, the threshold above which a task takes too long must be
                // above 16ms no matter what.
                if poll_duration.as_millis() >= 20 {
                    smoldot_light::platform::PlatformRef::log(
                        &PLATFORM_REF,
                        smoldot_light::platform::LogLevel::Debug,
                        "smoldot",
                        "task-too-long-time",
                        [
                            ("name", this.name as &dyn fmt::Display),
                            (
                                "poll_duration_ms",
                                &poll_duration.as_millis() as &dyn fmt::Display,
                            ),
                        ]
                        .into_iter(),
                    );
                }
                if poll_duration.as_millis() >= 150 {
                    smoldot_light::platform::PlatformRef::log(
                        &PLATFORM_REF,
                        smoldot_light::platform::LogLevel::Warn,
                        "smoldot",
                        &format!(
                            "The task named `{}` has occupied the CPU for an \
                            unreasonable amount of time ({}ms).",
                            this.name,
                            poll_duration.as_millis(),
                        ),
                        iter::empty(),
                    );
                }

                out
            }
        }

        let task = FutureAdapter {
            name: task_name.into_owned(),
            future: task,
        };

        let (runnable, task) = async_task::spawn(task, |runnable| {
            super::TASKS_QUEUE.push(runnable);
            bindings::advance_execution_ready();
        });

        task.detach();
        runnable.schedule();
    }

    fn log<'a>(
        &self,
        log_level: smoldot_light::platform::LogLevel,
        log_target: &'a str,
        message: &'a str,
        key_values: impl Iterator<Item = (&'a str, &'a dyn fmt::Display)>,
    ) {
        let log_level = match log_level {
            smoldot_light::platform::LogLevel::Error => 1,
            smoldot_light::platform::LogLevel::Warn => 2,
            smoldot_light::platform::LogLevel::Info => 3,
            smoldot_light::platform::LogLevel::Debug => 4,
            smoldot_light::platform::LogLevel::Trace => 5,
        };

        if log_level > MAX_LOG_LEVEL.load(Ordering::Relaxed) {
            return;
        }

        let mut key_values = key_values.peekable();

        if key_values.peek().is_none() {
            bindings::log(
                log_level,
                u32::try_from(log_target.as_bytes().as_ptr().addr()).unwrap(),
                u32::try_from(log_target.as_bytes().len()).unwrap(),
                u32::try_from(message.as_bytes().as_ptr().addr()).unwrap(),
                u32::try_from(message.as_bytes().len()).unwrap(),
            )
        } else {
            let mut message_build = String::with_capacity(128);
            message_build.push_str(message);
            let mut first = true;
            for (key, value) in key_values {
                if first {
                    let _ = write!(message_build, "; ");
                    first = false;
                } else {
                    let _ = write!(message_build, ", ");
                }
                let _ = write!(message_build, "{}={}", key, value);
            }

            bindings::log(
                log_level,
                u32::try_from(log_target.as_bytes().as_ptr().addr()).unwrap(),
                u32::try_from(log_target.as_bytes().len()).unwrap(),
                u32::try_from(message_build.as_bytes().as_ptr().addr()).unwrap(),
                u32::try_from(message_build.as_bytes().len()).unwrap(),
            )
        }
    }

    fn client_name(&'_ self) -> Cow<'_, str> {
        env!("CARGO_PKG_NAME").into()
    }

    fn client_version(&'_ self) -> Cow<'_, str> {
        env!("CARGO_PKG_VERSION").into()
    }

    fn supports_connection_type(
        &self,
        connection_type: smoldot_light::platform::ConnectionType,
    ) -> bool {
        let ty = match connection_type {
            smoldot_light::platform::ConnectionType::TcpIpv4 => 0,
            smoldot_light::platform::ConnectionType::TcpIpv6 => 1,
            smoldot_light::platform::ConnectionType::TcpDns => 2,
            smoldot_light::platform::ConnectionType::WebSocketIpv4 {
                remote_is_localhost: true,
                ..
            }
            | smoldot_light::platform::ConnectionType::WebSocketIpv6 {
                remote_is_localhost: true,
                ..
            }
            | smoldot_light::platform::ConnectionType::WebSocketDns {
                secure: false,
                remote_is_localhost: true,
            } => 7,
            smoldot_light::platform::ConnectionType::WebSocketIpv4 { .. } => 4,
            smoldot_light::platform::ConnectionType::WebSocketIpv6 { .. } => 5,
            smoldot_light::platform::ConnectionType::WebSocketDns { secure: false, .. } => 6,
            smoldot_light::platform::ConnectionType::WebSocketDns { secure: true, .. } => 14,
            smoldot_light::platform::ConnectionType::WebRtcIpv4 => 16,
            smoldot_light::platform::ConnectionType::WebRtcIpv6 => 17,
            smoldot_light::platform::ConnectionType::WebRtcDns => 18,
        };

        bindings::connection_type_supported(ty) != 0
    }

    fn connect_stream(
        &self,
        address: smoldot_light::platform::Address,
    ) -> Self::StreamConnectFuture {
        let mut lock = STATE.try_lock().unwrap();

        let connection_id = lock.next_connection_id;
        lock.next_connection_id += 1;

        let encoded_address: Vec<u8> = match address {
            smoldot_light::platform::Address::TcpIp {
                ip: IpAddr::V4(ip),
                port,
            } => iter::once(0u8)
                .chain(port.to_be_bytes())
                .chain(ip.to_string().bytes())
                .collect(),
            smoldot_light::platform::Address::TcpIp {
                ip: IpAddr::V6(ip),
                port,
            } => iter::once(1u8)
                .chain(port.to_be_bytes())
                .chain(ip.to_string().bytes())
                .collect(),
            smoldot_light::platform::Address::TcpDns { hostname, port } => iter::once(2u8)
                .chain(port.to_be_bytes())
                .chain(hostname.as_bytes().iter().copied())
                .collect(),
            smoldot_light::platform::Address::WebSocketIp {
                ip: IpAddr::V4(ip),
                port,
            } => iter::once(4u8)
                .chain(port.to_be_bytes())
                .chain(ip.to_string().bytes())
                .collect(),
            smoldot_light::platform::Address::WebSocketIp {
                ip: IpAddr::V6(ip),
                port,
            } => iter::once(5u8)
                .chain(port.to_be_bytes())
                .chain(ip.to_string().bytes())
                .collect(),
            smoldot_light::platform::Address::WebSocketDns {
                hostname,
                port,
                secure: false,
            } => iter::once(6u8)
                .chain(port.to_be_bytes())
                .chain(hostname.as_bytes().iter().copied())
                .collect(),
            smoldot_light::platform::Address::WebSocketDns {
                hostname,
                port,
                secure: true,
            } => iter::once(14u8)
                .chain(port.to_be_bytes())
                .chain(hostname.as_bytes().iter().copied())
                .collect(),
        };

        let write_closable = match address {
            smoldot_light::platform::Address::TcpIp { .. }
            | smoldot_light::platform::Address::TcpDns { .. } => true,
            smoldot_light::platform::Address::WebSocketIp { .. }
            | smoldot_light::platform::Address::WebSocketDns { .. } => false,
        };

        bindings::connection_new(
            connection_id,
            u32::try_from(encoded_address.as_ptr().addr()).unwrap(),
            u32::try_from(encoded_address.len()).unwrap(),
        );

        let _prev_value = lock.connections.insert(
            connection_id,
            Connection {
                inner: ConnectionInner::SingleStreamMsNoiseYamux,
                something_happened: event_listener::Event::new(),
            },
        );
        debug_assert!(_prev_value.is_none());

        let _prev_value = lock.streams.insert(
            (connection_id, None),
            Stream {
                reset: None,
                messages_queue: VecDeque::with_capacity(8),
                messages_queue_total_size: 0,
                something_happened: event_listener::Event::new(),
                writable_bytes_extra: 0,
            },
        );
        debug_assert!(_prev_value.is_none());

        future::ready(StreamWrapper {
            connection_id,
            stream_id: None,
            read_buffer: Vec::new(),
            inner_expected_incoming_bytes: Some(1),
            is_reset: None,
            writable_bytes: 0,
            write_closable,
            write_closed: false,
            when_wake_up: None,
        })
    }

    fn connect_multistream(
        &self,
        address: smoldot_light::platform::MultiStreamAddress,
    ) -> Self::MultiStreamConnectFuture {
        let mut lock = STATE.try_lock().unwrap();

        let connection_id = lock.next_connection_id;
        lock.next_connection_id += 1;

        let encoded_address: Vec<u8> = match address {
            smoldot_light::platform::MultiStreamAddress::WebRtc {
                ip: IpAddr::V4(ip),
                port,
                remote_certificate_sha256,
            } => iter::once(16u8)
                .chain(port.to_be_bytes())
                .chain(remote_certificate_sha256.iter().copied())
                .chain(ip.to_string().bytes())
                .collect(),
            smoldot_light::platform::MultiStreamAddress::WebRtc {
                ip: IpAddr::V6(ip),
                port,
                remote_certificate_sha256,
            } => iter::once(17u8)
                .chain(port.to_be_bytes())
                .chain(remote_certificate_sha256.iter().copied())
                .chain(ip.to_string().bytes())
                .collect(),
            smoldot_light::platform::MultiStreamAddress::WebRtcDns {
                hostname,
                family,
                port,
                remote_certificate_sha256,
            } => iter::once(18u8)
                .chain(port.to_be_bytes())
                .chain(iter::once(match family {
                    smoldot_light::platform::DnsFamily::Any => 0u8,
                    smoldot_light::platform::DnsFamily::Ipv4 => 4u8,
                    smoldot_light::platform::DnsFamily::Ipv6 => 6u8,
                }))
                .chain(remote_certificate_sha256.iter().copied())
                .chain(hostname.as_bytes().iter().copied())
                .collect(),
        };

        bindings::connection_new(
            connection_id,
            u32::try_from(encoded_address.as_ptr().addr()).unwrap(),
            u32::try_from(encoded_address.len()).unwrap(),
        );

        let _prev_value = lock.connections.insert(
            connection_id,
            Connection {
                inner: ConnectionInner::MultiStreamUnknownHandshake {
                    opened_substreams_to_pick_up: VecDeque::with_capacity(0),
                    connection_handles_alive: 1,
                },
                something_happened: event_listener::Event::new(),
            },
        );
        debug_assert!(_prev_value.is_none());

        Box::pin(async move {
            // Wait until the connection state is no longer "unknown handshake".
            let mut lock = loop {
                let something_happened = {
                    let mut lock = STATE.try_lock().unwrap();
                    let connection = lock.connections.get_mut(&connection_id).unwrap();

                    if matches!(
                        connection.inner,
                        ConnectionInner::Reset { .. } | ConnectionInner::MultiStreamWebRtc { .. }
                    ) {
                        break lock;
                    }

                    connection.something_happened.listen()
                };

                something_happened.await
            };
            let lock = &mut *lock;

            let connection = lock.connections.get_mut(&connection_id).unwrap();

            match &mut connection.inner {
                ConnectionInner::SingleStreamMsNoiseYamux { .. }
                | ConnectionInner::MultiStreamUnknownHandshake { .. } => {
                    unreachable!()
                }
                ConnectionInner::MultiStreamWebRtc {
                    local_tls_certificate_sha256,
                    ..
                } => smoldot_light::platform::MultiStreamWebRtcConnection {
                    connection: MultiStreamWrapper(connection_id),
                    local_tls_certificate_sha256: *local_tls_certificate_sha256,
                },
                ConnectionInner::Reset { .. } => {
                    // If the connection was already reset, we proceed anyway but provide a fake
                    // certificate hash. This has absolutely no consequence.
                    smoldot_light::platform::MultiStreamWebRtcConnection {
                        connection: MultiStreamWrapper(connection_id),
                        local_tls_certificate_sha256: [0; 32],
                    }
                }
            }
        })
    }

    fn next_substream<'a>(
        &self,
        MultiStreamWrapper(connection_id): &'a mut Self::MultiStream,
    ) -> Self::NextSubstreamFuture<'a> {
        let connection_id = *connection_id;

        Box::pin(async move {
            let (stream_id, direction) = loop {
                let something_happened = {
                    let mut lock = STATE.try_lock().unwrap();
                    let connection = lock.connections.get_mut(&connection_id).unwrap();

                    match &mut connection.inner {
                        ConnectionInner::Reset { .. } => return None,
                        ConnectionInner::MultiStreamWebRtc {
                            opened_substreams_to_pick_up,
                            connection_handles_alive,
                            ..
                        }
                        | ConnectionInner::MultiStreamUnknownHandshake {
                            opened_substreams_to_pick_up,
                            connection_handles_alive,
                            ..
                        } => {
                            if let Some((substream, direction)) =
                                opened_substreams_to_pick_up.pop_front()
                            {
                                *connection_handles_alive += 1;
                                break (substream, direction);
                            }
                        }
                        ConnectionInner::SingleStreamMsNoiseYamux { .. } => {
                            unreachable!()
                        }
                    }

                    connection.something_happened.listen()
                };

                something_happened.await
            };

            Some((
                StreamWrapper {
                    connection_id,
                    stream_id: Some(stream_id),
                    read_buffer: Vec::new(),
                    inner_expected_incoming_bytes: Some(1),
                    is_reset: None,
                    writable_bytes: 0,
                    write_closable: false, // Note: this is currently hardcoded for WebRTC.
                    write_closed: false,
                    when_wake_up: None,
                },
                direction,
            ))
        })
    }

    fn open_out_substream(&self, MultiStreamWrapper(connection_id): &mut Self::MultiStream) {
        match STATE
            .try_lock()
            .unwrap()
            .connections
            .get(connection_id)
            .unwrap()
            .inner
        {
            ConnectionInner::MultiStreamWebRtc { .. }
            | ConnectionInner::MultiStreamUnknownHandshake { .. } => {
                bindings::connection_stream_open(*connection_id);
            }
            ConnectionInner::Reset { .. } => {}
            ConnectionInner::SingleStreamMsNoiseYamux { .. } => {
                unreachable!()
            }
        }
    }

    fn wait_read_write_again<'a>(
        &self,
        stream: pin::Pin<&'a mut Self::Stream>,
    ) -> Self::StreamUpdateFuture<'a> {
        Box::pin(async move {
            let stream = stream.get_mut();

            if stream.is_reset.is_some() {
                future::pending::<()>().await;
            }

            loop {
                let listener = {
                    let mut lock = STATE.try_lock().unwrap();
                    let stream_inner = lock
                        .streams
                        .get_mut(&(stream.connection_id, stream.stream_id))
                        .unwrap();

                    if let Some(msg) = &stream_inner.reset {
                        stream.is_reset = Some(msg.clone());
                        return;
                    }

                    let mut shall_return = false;

                    // Move the buffers from `STATE` into `read_buffer`.
                    if !stream_inner.messages_queue.is_empty() {
                        stream
                            .read_buffer
                            .reserve(stream_inner.messages_queue_total_size);

                        while let Some(msg) = stream_inner.messages_queue.pop_front() {
                            stream_inner.messages_queue_total_size -= msg.len();
                            // TODO: could be optimized by reworking the bindings
                            stream.read_buffer.extend_from_slice(&msg);
                            if stream
                                .inner_expected_incoming_bytes
                                .map_or(false, |expected| expected <= stream.read_buffer.len())
                            {
                                shall_return = true;
                                break;
                            }
                        }
                    }

                    if stream_inner.writable_bytes_extra != 0 {
                        // As documented, the number of writable bytes must never become
                        // exceedingly large (a few megabytes). As such, this can't overflow
                        // unless there is a bug on the JavaScript side.
                        stream.writable_bytes += stream_inner.writable_bytes_extra;
                        stream_inner.writable_bytes_extra = 0;
                        shall_return = true;
                    }

                    if shall_return {
                        return;
                    }

                    stream_inner.something_happened.listen()
                };

                let timer_stop = async move {
                    listener.await;
                    false
                }
                .or(async {
                    if let Some(when_wake_up) = stream.when_wake_up.as_mut() {
                        when_wake_up.await;
                        stream.when_wake_up = None;
                        true
                    } else {
                        future::pending().await
                    }
                })
                .await;

                if timer_stop {
                    return;
                }
            }
        })
    }

    fn read_write_access<'a>(
        &self,
        stream: pin::Pin<&'a mut Self::Stream>,
    ) -> Result<Self::ReadWriteAccess<'a>, Self::StreamErrorRef<'a>> {
        let stream = stream.get_mut();

        if let Some(message) = &stream.is_reset {
            return Err(StreamError {
                message: message.clone(),
            });
        }

        Ok(ReadWriteAccess {
            read_write: read_write::ReadWrite {
                now: Duration::from_micros(bindings::monotonic_clock_us()),
                incoming_buffer: mem::take(&mut stream.read_buffer),
                expected_incoming_bytes: Some(0),
                read_bytes: 0,
                write_buffers: Vec::new(),
                write_bytes_queued: 0,
                write_bytes_queueable: if !stream.write_closed {
                    Some(stream.writable_bytes)
                } else {
                    None
                },
                wake_up_after: None,
            },
            stream,
        })
    }
}

pub(crate) struct ReadWriteAccess<'a> {
    read_write: read_write::ReadWrite<Duration>,
    stream: &'a mut StreamWrapper,
}

impl<'a> ops::Deref for ReadWriteAccess<'a> {
    type Target = read_write::ReadWrite<Duration>;

    fn deref(&self) -> &Self::Target {
        &self.read_write
    }
}

impl<'a> ops::DerefMut for ReadWriteAccess<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.read_write
    }
}

impl<'a> Drop for ReadWriteAccess<'a> {
    fn drop(&mut self) {
        let mut lock = STATE.try_lock().unwrap();

        let stream_inner = lock
            .streams
            .get_mut(&(self.stream.connection_id, self.stream.stream_id))
            .unwrap();

        if (self.read_write.read_bytes != 0
            && self
                .read_write
                .expected_incoming_bytes
                .map_or(false, |expected| {
                    expected >= self.read_write.incoming_buffer.len()
                }))
            || (self.read_write.write_bytes_queued != 0
                && self.read_write.write_bytes_queueable.is_some())
        {
            self.read_write.wake_up_asap();
        }

        self.stream.when_wake_up = self
            .read_write
            .wake_up_after
            .map(Delay::new_at_monotonic_clock);

        self.stream.read_buffer = mem::take(&mut self.read_write.incoming_buffer);

        self.stream.inner_expected_incoming_bytes = self.read_write.expected_incoming_bytes;

        if !self.read_write.write_buffers.is_empty() && stream_inner.reset.is_none() {
            let mut io_vectors = Vec::with_capacity(self.read_write.write_buffers.len());
            let mut total_length = 0;

            for buffer in &self.read_write.write_buffers {
                io_vectors.push(bindings::StreamSendIoVector {
                    ptr: u32::try_from(buffer.as_ptr().addr()).unwrap(),
                    len: u32::try_from(buffer.len()).unwrap(),
                });
                total_length += buffer.len();
            }

            assert!(total_length <= self.stream.writable_bytes);
            self.stream.writable_bytes -= total_length;

            // `unwrap()` is ok as there's no way that `buffer.len()` doesn't fit in a `u64`.
            TOTAL_BYTES_SENT.fetch_add(u64::try_from(total_length).unwrap(), Ordering::Relaxed);

            bindings::stream_send(
                self.stream.connection_id,
                self.stream.stream_id.unwrap_or(0),
                u32::try_from(io_vectors.as_ptr().addr()).unwrap(),
                u32::try_from(io_vectors.len()).unwrap(),
            );

            self.read_write.write_buffers.clear();
        }

        if self.read_write.write_bytes_queueable.is_none() && !self.stream.write_closed {
            if stream_inner.reset.is_none() && self.stream.write_closable {
                bindings::stream_send_close(
                    self.stream.connection_id,
                    self.stream.stream_id.unwrap_or(0),
                );
            }

            self.stream.write_closed = true;
        }
    }
}

pub(crate) struct StreamWrapper {
    connection_id: u32,
    stream_id: Option<u32>,
    read_buffer: Vec<u8>,
    inner_expected_incoming_bytes: Option<usize>,
    /// `Some` if the remote has reset the stream and `update_stream` has since then been called.
    /// Contains the error message.
    is_reset: Option<String>,
    writable_bytes: usize,
    write_closable: bool,
    write_closed: bool,
    /// The stream should wake up after this delay.
    when_wake_up: Option<Delay>,
}

impl Drop for StreamWrapper {
    fn drop(&mut self) {
        let mut lock = STATE.try_lock().unwrap();
        let lock = &mut *lock;

        let connection = lock.connections.get_mut(&self.connection_id).unwrap();
        let removed_stream = lock
            .streams
            .remove(&(self.connection_id, self.stream_id))
            .unwrap();

        let remove_connection = match &mut connection.inner {
            ConnectionInner::SingleStreamMsNoiseYamux { .. } => {
                if removed_stream.reset.is_none() {
                    bindings::reset_connection(self.connection_id);
                }

                debug_assert!(self.stream_id.is_none());
                true
            }
            ConnectionInner::MultiStreamWebRtc {
                connection_handles_alive,
                ..
            }
            | ConnectionInner::MultiStreamUnknownHandshake {
                connection_handles_alive,
                ..
            } => {
                if removed_stream.reset.is_none() {
                    bindings::connection_stream_reset(self.connection_id, self.stream_id.unwrap());
                }
                *connection_handles_alive -= 1;
                let remove_connection = *connection_handles_alive == 0;
                if remove_connection {
                    bindings::reset_connection(self.connection_id);
                }
                remove_connection
            }
            ConnectionInner::Reset {
                connection_handles_alive,
                ..
            } => {
                *connection_handles_alive -= 1;
                *connection_handles_alive == 0
            }
        };

        if remove_connection {
            lock.connections.remove(&self.connection_id).unwrap();
        }
    }
}

pub(crate) struct MultiStreamWrapper(u32);

impl Drop for MultiStreamWrapper {
    fn drop(&mut self) {
        let mut lock = STATE.try_lock().unwrap();

        let connection = lock.connections.get_mut(&self.0).unwrap();
        let (remove_connection, reset_connection) = match &mut connection.inner {
            ConnectionInner::SingleStreamMsNoiseYamux { .. } => {
                unreachable!()
            }
            ConnectionInner::MultiStreamWebRtc {
                connection_handles_alive,
                ..
            }
            | ConnectionInner::MultiStreamUnknownHandshake {
                connection_handles_alive,
                ..
            } => {
                *connection_handles_alive -= 1;
                let v = *connection_handles_alive == 0;
                (v, v)
            }
            ConnectionInner::Reset { .. } => (true, false),
        };

        if remove_connection {
            lock.connections.remove(&self.0).unwrap();
        }
        if reset_connection {
            bindings::reset_connection(self.0);
        }
    }
}

#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
#[display("{message}")]
pub(crate) struct StreamError {
    message: String,
}

static STATE: Mutex<NetworkState> = Mutex::new(NetworkState {
    next_connection_id: 0,
    connections: hashbrown::HashMap::with_hasher(FnvBuildHasher),
    streams: BTreeMap::new(),
});

// TODO: we use a custom `FnvBuildHasher` because it's not possible to create `fnv::FnvBuildHasher` in a `const` context
struct FnvBuildHasher;
impl core::hash::BuildHasher for FnvBuildHasher {
    type Hasher = fnv::FnvHasher;
    fn build_hasher(&self) -> fnv::FnvHasher {
        fnv::FnvHasher::default()
    }
}

/// All the connections and streams that are alive.
///
/// Single-stream connections have one entry in `connections` and one entry in `streams` (with
/// a `stream_id` always equal to `None`).
/// Multi-stream connections have one entry in `connections` and zero or more entries in `streams`.
struct NetworkState {
    next_connection_id: u32,
    connections: hashbrown::HashMap<u32, Connection, FnvBuildHasher>,
    streams: BTreeMap<(u32, Option<u32>), Stream>,
}

struct Connection {
    /// Type of connection and extra fields that depend on the type.
    inner: ConnectionInner,
    /// Event notified whenever one of the fields above is modified.
    something_happened: event_listener::Event,
}

enum ConnectionInner {
    SingleStreamMsNoiseYamux,
    MultiStreamUnknownHandshake {
        /// List of substreams that the host (i.e. JavaScript side) has reported have been opened,
        /// but that haven't been reported through
        /// [`smoldot_light::platform::PlatformRef::next_substream`] yet.
        opened_substreams_to_pick_up: VecDeque<(u32, SubstreamDirection)>,
        /// Number of objects (connections and streams) in the [`PlatformRef`] API that reference
        /// this connection. If it switches from 1 to 0, the connection must be removed.
        connection_handles_alive: u32,
    },
    MultiStreamWebRtc {
        /// List of substreams that the host (i.e. JavaScript side) has reported have been opened,
        /// but that haven't been reported through
        /// [`smoldot_light::platform::PlatformRef::next_substream`] yet.
        opened_substreams_to_pick_up: VecDeque<(u32, SubstreamDirection)>,
        /// Number of objects (connections and streams) in the [`PlatformRef`] API that reference
        /// this connection. If it switches from 1 to 0, the connection must be removed.
        connection_handles_alive: u32,
        /// SHA256 hash of the TLS certificate used by the local node at the DTLS layer.
        local_tls_certificate_sha256: [u8; 32],
    },
    /// [`bindings::connection_reset`] has been called
    Reset {
        /// Message given by the bindings to justify the closure.
        // TODO: why is this unused? shouldn't it be not unused?
        _message: String,
        /// Number of objects (connections and streams) in the [`PlatformRef`] API that reference
        /// this connection. If it switches from 1 to 0, the connection must be removed.
        connection_handles_alive: u32,
    },
}

struct Stream {
    /// `Some` if [`bindings::stream_reset`] has been called. Contains the error message.
    reset: Option<String>,
    /// Sum of the writable bytes reported through [`bindings::stream_writable_bytes`] that
    /// haven't been processed yet in a call to `update_stream`.
    writable_bytes_extra: usize,
    /// List of messages received through [`bindings::stream_message`]. Must never contain
    /// empty messages.
    messages_queue: VecDeque<Box<[u8]>>,
    /// Total size of all the messages stored in [`Stream::messages_queue`].
    messages_queue_total_size: usize,
    /// Event notified whenever one of the fields above is modified, such as a new message being
    /// queued.
    something_happened: event_listener::Event,
}

pub(crate) fn connection_multi_stream_set_handshake_info(
    connection_id: u32,
    handshake_ty: Box<[u8]>,
) {
    let (_, local_tls_certificate_sha256) = nom::Parser::parse(
        &mut nom::sequence::preceded(
            nom::bytes::streaming::tag::<_, _, nom::error::Error<&[u8]>>(&[0][..]),
            nom::combinator::map(nom::bytes::streaming::take(32u32), |b| {
                <&[u8; 32]>::try_from(b).unwrap()
            }),
        ),
        &handshake_ty[..],
    )
    .expect("invalid handshake type provided to connection_multi_stream_set_handshake_info");

    let mut lock = STATE.try_lock().unwrap();
    let connection = lock.connections.get_mut(&connection_id).unwrap();

    let (opened_substreams_to_pick_up, connection_handles_alive) = match &mut connection.inner {
        ConnectionInner::MultiStreamUnknownHandshake {
            opened_substreams_to_pick_up,
            connection_handles_alive,
        } => (
            mem::take(opened_substreams_to_pick_up),
            *connection_handles_alive,
        ),
        _ => unreachable!(),
    };

    connection.inner = ConnectionInner::MultiStreamWebRtc {
        opened_substreams_to_pick_up,
        connection_handles_alive,
        local_tls_certificate_sha256: *local_tls_certificate_sha256,
    };
    connection.something_happened.notify(usize::MAX);
}

pub(crate) fn stream_writable_bytes(connection_id: u32, stream_id: u32, bytes: u32) {
    let mut lock = STATE.try_lock().unwrap();

    let connection = lock.connections.get_mut(&connection_id).unwrap();

    // For single stream connections, the docs of this function mentions that `stream_id` can be
    // any value.
    let actual_stream_id = match connection.inner {
        ConnectionInner::MultiStreamWebRtc { .. }
        | ConnectionInner::MultiStreamUnknownHandshake { .. } => Some(stream_id),
        ConnectionInner::SingleStreamMsNoiseYamux { .. } => None,
        ConnectionInner::Reset { .. } => unreachable!(),
    };

    let stream = lock
        .streams
        .get_mut(&(connection_id, actual_stream_id))
        .unwrap();
    debug_assert!(stream.reset.is_none());

    // As documented, the number of writable bytes must never become exceedingly large (a few
    // megabytes). As such, this can't overflow unless there is a bug on the JavaScript side.
    stream.writable_bytes_extra += usize::try_from(bytes).unwrap();
    stream.something_happened.notify(usize::MAX);
}

pub(crate) fn stream_message(connection_id: u32, stream_id: u32, message: Box<[u8]>) {
    let mut lock = STATE.try_lock().unwrap();

    let connection = lock.connections.get_mut(&connection_id).unwrap();

    // For single stream connections, the docs of this function mentions that `stream_id` can be
    // any value.
    let actual_stream_id = match connection.inner {
        ConnectionInner::MultiStreamWebRtc { .. }
        | ConnectionInner::MultiStreamUnknownHandshake { .. } => Some(stream_id),
        ConnectionInner::SingleStreamMsNoiseYamux { .. } => None,
        ConnectionInner::Reset { .. } => unreachable!(),
    };

    let stream = lock
        .streams
        .get_mut(&(connection_id, actual_stream_id))
        .unwrap();
    debug_assert!(stream.reset.is_none());

    TOTAL_BYTES_RECEIVED.fetch_add(u64::try_from(message.len()).unwrap(), Ordering::Relaxed);

    // Ignore empty message to avoid all sorts of problems.
    if message.is_empty() {
        return;
    }

    // There is unfortunately no way to instruct the browser to back-pressure connections to
    // remotes.
    //
    // In order to avoid DoS attacks, we refuse to buffer more than a certain amount of data per
    // connection. This limit is completely arbitrary, and this is in no way a robust solution
    // because this limit isn't in sync with any other part of the code. In other words, it could
    // be legitimate for the remote to buffer a large amount of data.
    //
    // This corner case is handled by discarding the messages that would go over the limit. While
    // this is not a great solution, going over that limit can be considered as a fault from the
    // remote, the same way as it would be a fault from the remote to forget to send some bytes,
    // and thus should be handled in a similar way by the higher level code.
    //
    // A better way to handle this would be to kill the connection abruptly. However, this would
    // add a lot of complex code in this module, and the effort is clearly not worth it for this
    // niche situation.
    //
    // While this problem is specific to browsers (Deno and NodeJS have ways to back-pressure
    // connections), we add this hack for all platforms, for consistency. If this limit is ever
    // reached, we want to be sure to detect it, even when testing on NodeJS or Deno.
    //
    // See <https://github.com/smol-dot/smoldot/issues/109>.
    // TODO: do this properly eventually ^
    if stream.messages_queue_total_size >= 25 * 1024 * 1024 {
        return;
    }

    stream.messages_queue_total_size += message.len();
    stream.messages_queue.push_back(message);
    stream.something_happened.notify(usize::MAX);
}

pub(crate) fn connection_stream_opened(connection_id: u32, stream_id: u32, outbound: u32) {
    let mut lock = STATE.try_lock().unwrap();
    let lock = &mut *lock;

    let connection = lock.connections.get_mut(&connection_id).unwrap();
    if let ConnectionInner::MultiStreamWebRtc {
        opened_substreams_to_pick_up,
        ..
    } = &mut connection.inner
    {
        let _prev_value = lock.streams.insert(
            (connection_id, Some(stream_id)),
            Stream {
                reset: None,
                messages_queue: VecDeque::with_capacity(8),
                messages_queue_total_size: 0,
                something_happened: event_listener::Event::new(),
                writable_bytes_extra: 0,
            },
        );

        if _prev_value.is_some() {
            panic!("same stream_id used multiple times in connection_stream_opened")
        }

        opened_substreams_to_pick_up.push_back((
            stream_id,
            if outbound != 0 {
                SubstreamDirection::Outbound
            } else {
                SubstreamDirection::Inbound
            },
        ));

        connection.something_happened.notify(usize::MAX);
    } else {
        panic!()
    }
}

pub(crate) fn connection_reset(connection_id: u32, message: Box<[u8]>) {
    let message = str::from_utf8(&message)
        .unwrap_or_else(|_| panic!("non-UTF-8 message"))
        .to_owned();

    let mut lock = STATE.try_lock().unwrap();
    let connection = lock.connections.get_mut(&connection_id).unwrap();

    let connection_handles_alive = match &connection.inner {
        ConnectionInner::SingleStreamMsNoiseYamux { .. } => 1, // TODO: I believe that this is correct but a bit confusing; might be helpful to refactor with an enum or something
        ConnectionInner::MultiStreamWebRtc {
            connection_handles_alive,
            ..
        }
        | ConnectionInner::MultiStreamUnknownHandshake {
            connection_handles_alive,
            ..
        } => *connection_handles_alive,
        ConnectionInner::Reset { .. } => unreachable!(),
    };

    connection.inner = ConnectionInner::Reset {
        connection_handles_alive,
        _message: message.clone(),
    };

    connection.something_happened.notify(usize::MAX);

    for ((_, _), stream) in lock
        .streams
        .range_mut((connection_id, Some(u32::MIN))..=(connection_id, Some(u32::MAX)))
    {
        stream.reset = Some(message.clone());
        stream.something_happened.notify(usize::MAX);
    }
    if let Some(stream) = lock.streams.get_mut(&(connection_id, None)) {
        stream.reset = Some(message);
        stream.something_happened.notify(usize::MAX);
    }
}

pub(crate) fn stream_reset(connection_id: u32, stream_id: u32, message: Box<[u8]>) {
    let message: String = str::from_utf8(&message)
        .unwrap_or_else(|_| panic!("non-UTF-8 message"))
        .to_owned();

    // Note that, as documented, it is illegal to call this function on single-stream substreams.
    // We can thus assume that the `stream_id` is valid.
    let mut lock = STATE.try_lock().unwrap();
    let stream = lock
        .streams
        .get_mut(&(connection_id, Some(stream_id)))
        .unwrap();
    stream.reset = Some(message);
    stream.something_happened.notify(usize::MAX);
}
