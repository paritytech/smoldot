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

use smoldot::libp2p::multihash;
use smoldot_light::platform::{ConnectError, PlatformSubstreamDirection};

use core::{cmp, mem, slice, str, time::Duration};
use futures::prelude::*;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

/// Total number of bytes that all the connections created through [`Platform`] combined have
/// received.
pub static TOTAL_BYTES_RECEIVED: AtomicUsize = AtomicUsize::new(0);
/// Total number of bytes that all the connections created through [`Platform`] combined have
/// sent.
pub static TOTAL_BYTES_SENT: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct Platform;

// TODO: this trait implementation was written before GATs were stable in Rust; now that the associated types have lifetimes, it should be possible to considerably simplify this code
impl smoldot_light::platform::Platform for Platform {
    type Delay = Delay;
    type Instant = crate::Instant;
    type Connection = ConnectionWrapper; // Entry in the ̀`CONNECTIONS` map.
    type Stream = StreamWrapper; // Entry in the ̀`STREAMS` map and a read buffer.
    type ConnectFuture = future::BoxFuture<
        'static,
        Result<
            smoldot_light::platform::PlatformConnection<Self::Stream, Self::Connection>,
            ConnectError,
        >,
    >;
    type StreamDataFuture<'a> = future::BoxFuture<'a, ()>;
    type NextSubstreamFuture<'a> = future::BoxFuture<
        'a,
        Option<(
            Self::Stream,
            smoldot_light::platform::PlatformSubstreamDirection,
        )>,
    >;

    fn now_from_unix_epoch() -> Duration {
        Duration::from_secs_f64(unsafe { bindings::unix_time_ms() } / 1000.0)
    }

    fn now() -> Self::Instant {
        crate::Instant::now()
    }

    fn sleep(duration: Duration) -> Self::Delay {
        Delay::new(duration)
    }

    fn sleep_until(when: Self::Instant) -> Self::Delay {
        Delay::new_at(when)
    }

    fn connect(url: &str) -> Self::ConnectFuture {
        let mut lock = STATE.try_lock().unwrap();

        let connection_id = lock.next_connection_id;
        lock.next_connection_id += 1;

        let mut error_ptr = [0u8; 9];

        let ret_code = unsafe {
            bindings::connection_new(
                connection_id,
                u32::try_from(url.as_bytes().as_ptr() as usize).unwrap(),
                u32::try_from(url.as_bytes().len()).unwrap(),
                u32::try_from(&mut error_ptr as *mut [u8; 9] as usize).unwrap(),
            )
        };

        let result = if ret_code != 0 {
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
            let _prev_value = lock.connections.insert(
                connection_id,
                Connection {
                    inner: ConnectionInner::NotOpen,
                    something_happened: event_listener::Event::new(),
                },
            );
            debug_assert!(_prev_value.is_none());

            Ok(())
        };

        async move {
            if let Err(err) = result {
                return Err(err);
            }

            let mut lock = loop {
                let something_happened = {
                    let mut lock = STATE.try_lock().unwrap();
                    let connection = lock.connections.get_mut(&connection_id).unwrap();

                    if !matches!(connection.inner, ConnectionInner::NotOpen) {
                        break lock;
                    }

                    connection.something_happened.listen()
                };

                something_happened.await
            };

            let connection = lock.connections.get_mut(&connection_id).unwrap();

            match &mut connection.inner {
                ConnectionInner::NotOpen => unreachable!(),
                ConnectionInner::SingleStreamMsNoiseYamux => {
                    let read_buffer = ReadBuffer {
                        buffer: Vec::new().into(),
                        buffer_first_offset: 0,
                    };

                    Ok(smoldot_light::platform::PlatformConnection::SingleStreamMultistreamSelectNoiseYamux(
                        StreamWrapper((connection_id, 0), read_buffer),
                    ))
                }
                ConnectionInner::MultiStreamWebRtc {
                    connection_handles_alive,
                    local_tls_certificate_multihash,
                    remote_tls_certificate_multihash, ..
                } => {
                    *connection_handles_alive += 1;
                    Ok(smoldot_light::platform::PlatformConnection::MultiStreamWebRtc {
                        connection: ConnectionWrapper(connection_id),
                        local_tls_certificate_multihash: local_tls_certificate_multihash.clone(),
                        remote_tls_certificate_multihash: remote_tls_certificate_multihash.clone(),
                    })
                }
                ConnectionInner::Reset {
                    message,
                    connection_handles_alive,
                } => {
                    debug_assert_eq!(*connection_handles_alive, 0);
                    let message = mem::take(message);
                    lock.connections.remove(&connection_id).unwrap();
                    Err(ConnectError {
                        message,
                        is_bad_addr: false,
                    })
                }
            }
        }
        .boxed()
    }

    fn next_substream(
        ConnectionWrapper(connection_id): &'_ mut Self::Connection,
    ) -> Self::NextSubstreamFuture<'_> {
        let connection_id = *connection_id;

        async move {
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
                        } => {
                            if let Some((substream, direction)) =
                                opened_substreams_to_pick_up.pop_front()
                            {
                                *connection_handles_alive += 1;
                                break (substream, direction);
                            }
                        }
                        ConnectionInner::NotOpen
                        | ConnectionInner::SingleStreamMsNoiseYamux { .. } => {
                            unreachable!()
                        }
                    }

                    connection.something_happened.listen()
                };

                something_happened.await
            };

            Some((
                StreamWrapper(
                    (connection_id, stream_id),
                    ReadBuffer {
                        buffer: Vec::<u8>::new().into(),
                        buffer_first_offset: 0,
                    },
                ),
                direction,
            ))
        }
        .boxed()
    }

    fn open_out_substream(ConnectionWrapper(connection_id): &mut Self::Connection) {
        debug_assert!(matches!(
            STATE
                .try_lock()
                .unwrap()
                .connections
                .get(connection_id)
                .unwrap()
                .inner,
            ConnectionInner::MultiStreamWebRtc { .. }
        ));

        unsafe { bindings::connection_stream_open(*connection_id) }
    }

    fn wait_more_data(
        StreamWrapper(stream_id, read_buffer): &'_ mut Self::Stream,
    ) -> Self::StreamDataFuture<'_> {
        if read_buffer.buffer_first_offset < read_buffer.buffer.len() {
            return async move {}.boxed();
        }

        let something_happened = {
            let mut lock = STATE.try_lock().unwrap();
            let stream = lock.streams.get_mut(stream_id).unwrap();

            if !stream.messages_queue.is_empty() || stream.reset {
                return future::ready(()).boxed();
            }

            stream.something_happened.listen()
        };

        something_happened.boxed()
    }

    fn read_buffer(
        StreamWrapper(stream_id, read_buffer): &mut Self::Stream,
    ) -> smoldot_light::platform::ReadBuffer {
        let mut lock = STATE.try_lock().unwrap();
        let stream = lock.streams.get_mut(stream_id).unwrap();

        if stream.reset {
            return smoldot_light::platform::ReadBuffer::Reset;
        }

        if read_buffer.buffer_first_offset < read_buffer.buffer.len() {
            return smoldot_light::platform::ReadBuffer::Open(
                &read_buffer.buffer[read_buffer.buffer_first_offset..],
            );
        }

        // Move the next buffer from `STATE` into `read_buffer`.
        if let Some(msg) = stream.messages_queue.pop_front() {
            read_buffer.buffer = msg;
            read_buffer.buffer_first_offset = 0;
            smoldot_light::platform::ReadBuffer::Open(&read_buffer.buffer[..])
        } else {
            smoldot_light::platform::ReadBuffer::Open(&[])
        }
    }

    fn advance_read_cursor(
        StreamWrapper(stream_id, read_buffer): &mut Self::Stream,
        mut bytes: usize,
    ) {
        loop {
            // Advance `read_buffer`.
            {
                let read_buffer_advance = cmp::min(
                    read_buffer.buffer.len() - read_buffer.buffer_first_offset,
                    bytes,
                );

                read_buffer.buffer_first_offset += read_buffer_advance;
                bytes -= read_buffer_advance;
            }

            // Avoid the whole locking process if `bytes` is 0.
            if bytes == 0 {
                return;
            }

            // Move the next buffer from `STATE` into `read_buffer`.
            let mut lock = STATE.try_lock().unwrap();
            let stream = lock.streams.get_mut(stream_id).unwrap();
            if let Some(msg) = stream.messages_queue.pop_front() {
                read_buffer.buffer = msg;
                read_buffer.buffer_first_offset = 0;
            } else {
                panic!() // User has passed more bytes than the size of the read buffer.
            }
        }
    }

    fn send(StreamWrapper((connection_id, stream_id), _): &mut Self::Stream, data: &[u8]) {
        let mut lock = STATE.try_lock().unwrap();
        let stream = lock.streams.get_mut(&(*connection_id, *stream_id)).unwrap();

        if stream.reset {
            return;
        }

        TOTAL_BYTES_SENT.fetch_add(data.len(), Ordering::Relaxed);

        unsafe {
            bindings::stream_send(
                *connection_id,
                *stream_id,
                u32::try_from(data.as_ptr() as usize).unwrap(),
                u32::try_from(data.len()).unwrap(),
            );
        }
    }
}

pub(crate) struct StreamWrapper((u32, u32), ReadBuffer);

impl Drop for StreamWrapper {
    fn drop(&mut self) {
        let mut lock = STATE.try_lock().unwrap();

        let connection = lock.connections.get_mut(&self.0 .0).unwrap();
        let remove_connection = match &mut connection.inner {
            ConnectionInner::NotOpen => unreachable!(),
            ConnectionInner::SingleStreamMsNoiseYamux => {
                unsafe {
                    bindings::reset_connection(self.0 .0);
                }

                debug_assert_eq!(self.0 .1, 0);
                true
            }
            ConnectionInner::MultiStreamWebRtc {
                connection_handles_alive,
                ..
            } => {
                unsafe { bindings::connection_stream_reset(self.0 .0, self.0 .1) }
                *connection_handles_alive -= 1;
                let remove_connection = *connection_handles_alive == 0;
                if remove_connection {
                    unsafe {
                        bindings::reset_connection(self.0 .0);
                    }
                }
                remove_connection
            }
            ConnectionInner::Reset {
                connection_handles_alive,
                ..
            } => {
                *connection_handles_alive -= 1;
                let remove_connection = *connection_handles_alive == 0;
                if remove_connection {
                    unsafe {
                        bindings::reset_connection(self.0 .0);
                    }
                }
                remove_connection
            }
        };

        lock.streams.remove(&(self.0 .0, self.0 .1)).unwrap();

        if remove_connection {
            lock.connections.remove(&self.0 .0).unwrap();
        }
    }
}

pub(crate) struct ConnectionWrapper(u32);

impl Drop for ConnectionWrapper {
    fn drop(&mut self) {
        let mut lock = STATE.try_lock().unwrap();

        let connection = lock.connections.get_mut(&self.0).unwrap();
        let remove_connection = match &mut connection.inner {
            ConnectionInner::NotOpen | ConnectionInner::SingleStreamMsNoiseYamux => unreachable!(),
            ConnectionInner::MultiStreamWebRtc {
                connection_handles_alive,
                ..
            }
            | ConnectionInner::Reset {
                connection_handles_alive,
                ..
            } => {
                *connection_handles_alive -= 1;
                *connection_handles_alive == 0
            }
        };

        if remove_connection {
            lock.connections.remove(&self.0).unwrap();
            if remove_connection {
                unsafe {
                    bindings::reset_connection(self.0);
                }
            }
        }
    }
}

lazy_static::lazy_static! {
    static ref STATE: Mutex<NetworkState> = Mutex::new(NetworkState {
        next_connection_id: 0,
        connections: hashbrown::HashMap::with_capacity_and_hasher(32, Default::default()),
        streams: BTreeMap::new(),
    });
}

/// All the connections and streams that are alive.
///
/// Single-stream connections have one entry in `connections` and one entry in `streams` (with
/// a `stream_id` always equal to 0).
/// Multi-stream connections have one entry in `connections` and zero or more entries in `streams`.
struct NetworkState {
    next_connection_id: u32,
    connections: hashbrown::HashMap<u32, Connection, fnv::FnvBuildHasher>,
    streams: BTreeMap<(u32, u32), Stream>,
}

struct Connection {
    /// Type of connection and extra fields that depend on the type.
    inner: ConnectionInner,
    /// Event notified whenever one of the fields above is modified.
    something_happened: event_listener::Event,
}

enum ConnectionInner {
    NotOpen,
    SingleStreamMsNoiseYamux,
    MultiStreamWebRtc {
        /// List of substreams that the host (i.e. JavaScript side) has reported have been opened,
        /// but that haven't been reported through
        /// [`smoldot_light::platform::Platform::next_substream`] yet.
        opened_substreams_to_pick_up: VecDeque<(u32, PlatformSubstreamDirection)>,
        /// Number of objects (connections and streams) in the [`Platform`] API that reference
        /// this connection. If it switches from 1 to 0, the connection must be removed.
        connection_handles_alive: u32,
        /// Multihash encoding of the TLS certificate used by the local node at the DTLS layer.
        local_tls_certificate_multihash: Vec<u8>,
        /// Multihash encoding of the TLS certificate used by the remote node at the DTLS layer.
        remote_tls_certificate_multihash: Vec<u8>,
    },
    /// [`bindings::connection_reset`] has been called
    Reset {
        /// Message given by the bindings to justify the closure.
        message: String,
        /// Number of objects (connections and streams) in the [`Platform`] API that reference
        /// this connection. If it switches from 1 to 0, the connection must be removed.
        connection_handles_alive: u32,
    },
}

struct Stream {
    /// `true` if the sending and receiving sides of the stream have been reset.
    reset: bool,
    /// List of messages received through [`bindings::stream_message`]. Must never contain
    /// empty messages.
    messages_queue: VecDeque<Box<[u8]>>,
    /// Event notified whenever one of the fields above is modified, such as a new message being
    /// queued.
    something_happened: event_listener::Event,
}

struct ReadBuffer {
    /// Buffer containing incoming data.
    buffer: Box<[u8]>,

    /// The first bytes of [`ReadBuffer::buffer`] have already been processed are not considered
    /// not part of the read buffer anymore.
    buffer_first_offset: usize,
}

pub(crate) fn connection_open_single_stream(connection_id: u32, handshake_ty: u32) {
    assert_eq!(handshake_ty, 0);

    let mut lock = STATE.try_lock().unwrap();
    let lock = &mut *lock;

    let connection = lock.connections.get_mut(&connection_id).unwrap();

    debug_assert!(matches!(connection.inner, ConnectionInner::NotOpen));
    connection.inner = ConnectionInner::SingleStreamMsNoiseYamux;

    let _prev_value = lock.streams.insert(
        (connection_id, 0),
        Stream {
            reset: false,
            messages_queue: VecDeque::with_capacity(8),
            something_happened: event_listener::Event::new(),
        },
    );
    debug_assert!(_prev_value.is_none());

    connection.something_happened.notify(usize::max_value());
}

pub(crate) fn connection_open_multi_stream(
    connection_id: u32,
    handshake_ty_ptr: u32,
    handshake_ty_len: u32,
) {
    let handshake_ty: Box<[u8]> = {
        let handshake_ty_ptr = usize::try_from(handshake_ty_ptr).unwrap();
        let handshake_ty_len = usize::try_from(handshake_ty_len).unwrap();
        unsafe {
            Box::from_raw(slice::from_raw_parts_mut(
                handshake_ty_ptr as *mut u8,
                handshake_ty_len,
            ))
        }
    };

    let (_, (local_tls_certificate_multihash, remote_tls_certificate_multihash)) =
        nom::sequence::preceded(
            nom::bytes::complete::tag::<_, _, nom::error::Error<&[u8]>>(&[0]),
            nom::sequence::tuple((
                move |b| {
                    multihash::MultihashRef::from_bytes_partial(b)
                        .map(|(a, b)| (b, a))
                        .map_err(|_| {
                            nom::Err::Failure(nom::error::make_error(
                                b,
                                nom::error::ErrorKind::Verify,
                            ))
                        })
                },
                move |b| {
                    multihash::MultihashRef::from_bytes_partial(b)
                        .map(|(a, b)| (b, a))
                        .map_err(|_| {
                            nom::Err::Failure(nom::error::make_error(
                                b,
                                nom::error::ErrorKind::Verify,
                            ))
                        })
                },
            )),
        )(&handshake_ty[..])
        .expect("invalid handshake type provided to connection_open_multi_stream");

    let mut lock = STATE.try_lock().unwrap();
    let connection = lock.connections.get_mut(&connection_id).unwrap();

    debug_assert!(matches!(connection.inner, ConnectionInner::NotOpen));

    connection.inner = ConnectionInner::MultiStreamWebRtc {
        opened_substreams_to_pick_up: VecDeque::with_capacity(8),
        connection_handles_alive: 0,
        local_tls_certificate_multihash: local_tls_certificate_multihash.to_vec(),
        remote_tls_certificate_multihash: remote_tls_certificate_multihash.to_vec(),
    };
    connection.something_happened.notify(usize::max_value());
}

pub(crate) fn stream_message(connection_id: u32, stream_id: u32, ptr: u32, len: u32) {
    let mut lock = STATE.try_lock().unwrap();

    let connection = lock.connections.get_mut(&connection_id).unwrap();

    // For single stream connections, the docs of this function mentions that `stream_id` can be
    // any value. However, internally we always use `0`.
    let actual_stream_id = match connection.inner {
        ConnectionInner::MultiStreamWebRtc { .. } => stream_id,
        ConnectionInner::SingleStreamMsNoiseYamux => 0,
        ConnectionInner::Reset { .. } | ConnectionInner::NotOpen => unreachable!(),
    };

    let stream = lock
        .streams
        .get_mut(&(connection_id, actual_stream_id))
        .unwrap();
    debug_assert!(!stream.reset);

    let ptr = usize::try_from(ptr).unwrap();
    let len = usize::try_from(len).unwrap();

    TOTAL_BYTES_RECEIVED.fetch_add(len, Ordering::Relaxed);

    let message: Box<[u8]> =
        unsafe { Box::from_raw(slice::from_raw_parts_mut(ptr as *mut u8, len)) };

    // Ignore empty message to avoid all sorts of problems.
    if message.is_empty() {
        return;
    }

    // TODO: add some limit to `messages_queue`, to avoid DoS attacks?
    stream.messages_queue.push_back(message);
    stream.something_happened.notify(usize::max_value());
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
            (connection_id, stream_id),
            Stream {
                reset: false,
                messages_queue: VecDeque::with_capacity(8),
                something_happened: event_listener::Event::new(),
            },
        );

        if _prev_value.is_some() {
            panic!("same stream_id used multiple times in connection_stream_opened")
        }

        opened_substreams_to_pick_up.push_back((
            stream_id,
            if outbound != 0 {
                PlatformSubstreamDirection::Outbound
            } else {
                PlatformSubstreamDirection::Inbound
            },
        ));

        connection.something_happened.notify(usize::max_value())
    } else {
        panic!()
    }
}

pub(crate) fn connection_reset(connection_id: u32, ptr: u32, len: u32) {
    let mut lock = STATE.try_lock().unwrap();
    let connection = lock.connections.get_mut(&connection_id).unwrap();

    let connection_handles_alive = match &connection.inner {
        ConnectionInner::NotOpen => 0,
        ConnectionInner::SingleStreamMsNoiseYamux => 1, // TODO: I believe that this is correct but a bit confusing; might be helpful to refactor with an enum or something
        ConnectionInner::MultiStreamWebRtc {
            connection_handles_alive,
            ..
        } => *connection_handles_alive,
        ConnectionInner::Reset { .. } => unreachable!(),
    };

    connection.inner = ConnectionInner::Reset {
        connection_handles_alive,
        message: {
            let ptr = usize::try_from(ptr).unwrap();
            let len = usize::try_from(len).unwrap();
            let message: Box<[u8]> =
                unsafe { Box::from_raw(slice::from_raw_parts_mut(ptr as *mut u8, len)) };
            str::from_utf8(&message).unwrap().to_owned()
        },
    };

    connection.something_happened.notify(usize::max_value());

    for ((_, _), stream) in lock
        .streams
        .range_mut((connection_id, u32::min_value())..=(connection_id, u32::max_value()))
    {
        stream.reset = true;
        stream.something_happened.notify(usize::max_value());
    }
}

pub(crate) fn stream_reset(connection_id: u32, stream_id: u32) {
    // Note that, as documented, it is illegal to call this function on single-stream substreams.
    // We can thus assume that the `stream_id` is valid.
    let mut lock = STATE.try_lock().unwrap();
    let stream = lock.streams.get_mut(&(connection_id, stream_id)).unwrap();
    stream.reset = true;
    stream.something_happened.notify(usize::max_value());
}
