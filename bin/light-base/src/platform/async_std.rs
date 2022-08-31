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

#![cfg(feature = "std")]
#![cfg_attr(docsrs, doc(cfg(feature = "std")))]

use super::{ConnectError, Platform, PlatformConnection, PlatformSubstreamDirection};

use alloc::{collections::VecDeque, sync::Arc};
use core::{pin::Pin, str, task::Poll, time::Duration};
use futures::{channel::mpsc, prelude::*};
use smoldot::libp2p::{
    multiaddr::{Multiaddr, ProtocolRef},
    websocket,
};
use std::{
    io::IoSlice,
    net::{IpAddr, SocketAddr},
};

/// Implementation of the [`Platform`] trait that uses the `async-std` library and provides TCP
/// and WebSocket connections.
pub struct AsyncStdTcpWebSocket;

impl Platform for AsyncStdTcpWebSocket {
    type Delay = future::BoxFuture<'static, ()>;
    type Instant = std::time::Instant;
    type Connection = std::convert::Infallible;
    type Stream = Stream;
    type ConnectFuture = future::BoxFuture<
        'static,
        Result<PlatformConnection<Self::Stream, Self::Connection>, ConnectError>,
    >;
    type StreamDataFuture = future::BoxFuture<'static, ()>;
    type NextSubstreamFuture = future::Pending<Option<(Self::Stream, PlatformSubstreamDirection)>>;

    fn now_from_unix_epoch() -> Duration {
        // Intentionally panic if the time is configured earlier than the UNIX EPOCH.
        std::time::UNIX_EPOCH.elapsed().unwrap()
    }

    fn now() -> Self::Instant {
        std::time::Instant::now()
    }

    fn sleep(duration: Duration) -> Self::Delay {
        async_std::task::sleep(duration).boxed()
    }

    fn sleep_until(when: Self::Instant) -> Self::Delay {
        let duration = when.saturating_duration_since(std::time::Instant::now());
        Self::sleep(duration)
    }

    fn connect(multiaddr: &str) -> Self::ConnectFuture {
        // We simply copy the address to own it. We could be more zero-cost here, but doing so
        // would considerably complicate the implementation.
        let multiaddr = multiaddr.to_owned();

        Box::pin(async move {
            let addr = multiaddr.parse::<Multiaddr>().map_err(|_| ConnectError {
                is_bad_addr: true,
                message: format!("Failed to parse address"),
            })?;

            let mut iter = addr.iter().fuse();
            let proto1 = iter.next().ok_or(ConnectError {
                is_bad_addr: true,
                message: format!("Unknown protocols combination"),
            })?;
            let proto2 = iter.next().ok_or(ConnectError {
                is_bad_addr: true,
                message: format!("Unknown protocols combination"),
            })?;
            let proto3 = iter.next();

            if iter.next().is_some() {
                return Err(ConnectError {
                    is_bad_addr: true,
                    message: format!("Unknown protocols combination"),
                });
            }

            // TODO: doesn't support WebSocket secure connections

            // Ensure ahead of time that the multiaddress is supported.
            let (addr, host_if_websocket) = match (&proto1, &proto2, &proto3) {
                (ProtocolRef::Ip4(ip), ProtocolRef::Tcp(port), None) => (
                    either::Left(SocketAddr::new(IpAddr::V4((*ip).into()), *port)),
                    None,
                ),
                (ProtocolRef::Ip6(ip), ProtocolRef::Tcp(port), None) => (
                    either::Left(SocketAddr::new(IpAddr::V6((*ip).into()), *port)),
                    None,
                ),
                (ProtocolRef::Ip4(ip), ProtocolRef::Tcp(port), Some(ProtocolRef::Ws)) => {
                    let addr = SocketAddr::new(IpAddr::V4((*ip).into()), *port);
                    (either::Left(addr), Some(addr.to_string()))
                }
                (ProtocolRef::Ip6(ip), ProtocolRef::Tcp(port), Some(ProtocolRef::Ws)) => {
                    let addr = SocketAddr::new(IpAddr::V6((*ip).into()), *port);
                    (either::Left(addr), Some(addr.to_string()))
                }

                // TODO: we don't care about the differences between Dns, Dns4, and Dns6
                (
                    ProtocolRef::Dns(addr) | ProtocolRef::Dns4(addr) | ProtocolRef::Dns6(addr),
                    ProtocolRef::Tcp(port),
                    None,
                ) => (either::Right((addr.to_string(), *port)), None),
                (
                    ProtocolRef::Dns(addr) | ProtocolRef::Dns4(addr) | ProtocolRef::Dns6(addr),
                    ProtocolRef::Tcp(port),
                    Some(ProtocolRef::Ws),
                ) => (
                    either::Right((addr.to_string(), *port)),
                    Some(format!("{}:{}", addr, *port)),
                ),

                _ => {
                    return Err(ConnectError {
                        is_bad_addr: true,
                        message: format!("Unknown protocols combination"),
                    })
                }
            };

            let tcp_socket = match addr {
                either::Left(socket_addr) => async_std::net::TcpStream::connect(socket_addr).await,
                either::Right((dns, port)) => {
                    async_std::net::TcpStream::connect((&dns[..], port)).await
                }
            };

            if let Ok(tcp_socket) = &tcp_socket {
                let _ = tcp_socket.set_nodelay(true);
            }

            let mut socket = match (tcp_socket, host_if_websocket) {
                (Ok(tcp_socket), Some(host)) => future::Either::Right(
                    websocket::websocket_client_handshake(websocket::Config {
                        tcp_socket,
                        host: &host,
                        url: "/",
                    })
                    .await
                    .map_err(|err| ConnectError {
                        message: format!("Failed to negotiate WebSocket: {}", err),
                        is_bad_addr: false,
                    })?,
                ),
                (Ok(tcp_socket), None) => future::Either::Left(tcp_socket),
                (Err(err), _) => {
                    return Err(ConnectError {
                        is_bad_addr: false,
                        message: format!("Failed to reach peer: {}", err),
                    })
                }
            };

            let shared = Arc::new(StreamShared {
                guarded: parking_lot::Mutex::new(StreamSharedGuarded {
                    write_queue: VecDeque::with_capacity(1024),
                }),
                write_queue_pushed: event_listener::Event::new(),
            });
            let shared_clone = shared.clone();

            let (mut read_data_tx, read_data_rx) = mpsc::channel(2);
            let mut read_buffer = vec![0; 4096];
            let mut write_queue_pushed_listener = shared.write_queue_pushed.listen();

            // TODO: this whole code is a mess, but the Platform trait must be modified to fix it
            // TODO: spawning a task per connection is necessary because the Platform trait isn't suitable for better strategies
            async_std::task::spawn(future::poll_fn(move |cx| {
                let mut lock = shared.guarded.lock();

                loop {
                    match Pin::new(&mut read_data_tx).poll_ready(cx) {
                        Poll::Ready(Ok(())) => {
                            match Pin::new(&mut socket).poll_read(cx, &mut read_buffer) {
                                Poll::Pending => break,
                                Poll::Ready(result) => {
                                    match result {
                                        Ok(0) | Err(_) => return Poll::Ready(()), // End the task
                                        Ok(bytes) => {
                                            let _ = read_data_tx
                                                .try_send(read_buffer[..bytes].to_vec());
                                        }
                                    }
                                }
                            }
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(()), // End the task
                        Poll::Pending => break,
                    }
                }

                loop {
                    if lock.write_queue.is_empty() {
                        if let Poll::Ready(Err(_)) = Pin::new(&mut socket).poll_flush(cx) {
                            // End the task
                            return Poll::Ready(());
                        }

                        break;
                    } else {
                        let write_queue_slices = lock.write_queue.as_slices();
                        if let Poll::Ready(result) = Pin::new(&mut socket).poll_write_vectored(
                            cx,
                            &[
                                IoSlice::new(write_queue_slices.0),
                                IoSlice::new(write_queue_slices.1),
                            ],
                        ) {
                            match result {
                                Ok(bytes) => {
                                    for _ in 0..bytes {
                                        lock.write_queue.pop_front();
                                    }
                                }
                                Err(_) => return Poll::Ready(()), // End the task
                            }
                        } else {
                            break;
                        }
                    }
                }

                loop {
                    if let Poll::Ready(()) = Pin::new(&mut write_queue_pushed_listener).poll(cx) {
                        write_queue_pushed_listener = shared.write_queue_pushed.listen();
                    } else {
                        break;
                    }
                }

                Poll::Pending
            }));

            Ok(PlatformConnection::SingleStream(Stream {
                shared: shared_clone,
                read_data_rx: Arc::new(parking_lot::Mutex::new(read_data_rx.peekable())),
                read_buffer: Some(Vec::with_capacity(4096)),
            }))
        })
    }

    fn open_out_substream(c: &mut Self::Connection) {
        // This function can only be called with so-called "multi-stream" connections. We never
        // open such connection.
        match *c {}
    }

    fn next_substream(c: &mut Self::Connection) -> Self::NextSubstreamFuture {
        // This function can only be called with so-called "multi-stream" connections. We never
        // open such connection.
        match *c {}
    }

    fn wait_more_data(stream: &mut Self::Stream) -> Self::StreamDataFuture {
        if stream.read_buffer.as_ref().map_or(true, |b| !b.is_empty()) {
            return Box::pin(future::ready(()));
        }

        let read_data_rx = stream.read_data_rx.clone();
        Box::pin(future::poll_fn(move |cx| {
            let mut lock = read_data_rx.lock();
            Pin::new(&mut *lock).poll_peek(cx).map(|_| ())
        }))
    }

    fn read_buffer(stream: &mut Self::Stream) -> Option<&[u8]> {
        if stream.read_buffer.is_none() {
            return None;
        }

        let mut lock = stream.read_data_rx.lock();
        while let Some(buf) = lock.next().now_or_never() {
            match buf {
                Some(b) => stream.read_buffer.as_mut().unwrap().extend(b),
                None => {
                    stream.read_buffer = None;
                    return None;
                }
            }
        }

        Some(stream.read_buffer.as_ref().unwrap())
    }

    fn advance_read_cursor(stream: &mut Self::Stream, bytes: usize) {
        if let Some(read_buffer) = &mut stream.read_buffer {
            // TODO: meh for copying
            *read_buffer = read_buffer[bytes..].to_vec();
        }
    }

    fn send(stream: &mut Self::Stream, data: &[u8]) {
        let mut lock = stream.shared.guarded.lock();
        lock.write_queue.reserve(data.len());
        lock.write_queue.extend(data.iter().copied());
        stream.shared.write_queue_pushed.notify(usize::max_value());
    }
}

/// Implementation detail of [`AsyncStdTcpWebSocket`].
pub struct Stream {
    shared: Arc<StreamShared>,
    read_data_rx: Arc<parking_lot::Mutex<stream::Peekable<mpsc::Receiver<Vec<u8>>>>>,
    read_buffer: Option<Vec<u8>>,
}

struct StreamShared {
    guarded: parking_lot::Mutex<StreamSharedGuarded>,
    write_queue_pushed: event_listener::Event,
}

struct StreamSharedGuarded {
    write_queue: VecDeque<u8>,
}
