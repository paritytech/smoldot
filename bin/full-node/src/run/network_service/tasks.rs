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

use super::Inner;

use core::time::Duration;
use futures::{channel::mpsc, prelude::*};
use futures_timer::Delay;
use smoldot::{
    libp2p::{
        async_std_connection::with_buffers,
        multiaddr::{Multiaddr, ProtocolRef},
        websocket,
    },
    network::service,
};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Instant,
};

/// Asynchronous task managing a specific connection, including the dialing process.
#[tracing::instrument(level = "trace", skip(start_connect, inner, connection_to_coordinator))]
pub(super) async fn opening_connection_task(
    start_connect: service::StartConnect<Instant>,
    inner: Arc<Inner>,
    connection_to_coordinator: mpsc::Sender<(
        service::ConnectionId,
        service::ConnectionToCoordinator,
    )>,
) {
    let span = tracing::debug_span!("start-connect", ?start_connect.id, %start_connect.multiaddr);
    let _enter = span.enter();

    // Convert the `multiaddr` (typically of the form `/ip4/a.b.c.d/tcp/d`) into
    // a `Future<dyn Output = Result<TcpStream, ...>>`.
    let socket = match multiaddr_to_socket(&start_connect.multiaddr) {
        Ok(socket) => socket,
        Err(_) => {
            tracing::debug!(%start_connect.multiaddr, "not-tcp");
            drop(_enter);

            let mut guarded = inner.guarded.lock().await;
            guarded.num_pending_out_attempts -= 1;
            guarded.network.pending_outcome_err(start_connect.id, true);
            for chain_index in 0..guarded.network.num_chains() {
                guarded.unassign_slot_and_ban(chain_index, start_connect.expected_peer_id.clone());
            }
            inner.wake_up_main_background_task.notify(1);
            return;
        }
    };
    drop(_enter);

    // Finishing ongoing connection process.
    let socket = {
        let now = Instant::now();
        let mut timeout = Delay::new(if start_connect.timeout >= now {
            start_connect.timeout - now
        } else {
            // `timeout - now` would panic
            Duration::new(0, 0)
        })
        .fuse();
        let socket = socket.fuse();
        futures::pin_mut!(socket);
        futures::select! {
            _ = timeout => {
                let mut guarded = inner.guarded.lock().await;
                guarded.num_pending_out_attempts -= 1;
                guarded.network.pending_outcome_err(start_connect.id, false);
                for chain_index in 0..guarded.network.num_chains() {
                    guarded.unassign_slot_and_ban(chain_index, start_connect.expected_peer_id.clone());
                }
                inner.wake_up_main_background_task.notify(1);
                return;
            }
            result = socket => {
                match result {
                    Ok(s) => s,
                    Err(_) => {
                        let mut guarded = inner.guarded.lock().await;
                        guarded.num_pending_out_attempts -= 1;
                        guarded.network.pending_outcome_err(start_connect.id, true);
                        for chain_index in 0..guarded.network.num_chains() {
                            guarded.unassign_slot_and_ban(chain_index, start_connect.expected_peer_id.clone());
                        }
                        inner.wake_up_main_background_task.notify(1);
                        return;
                    }
                }
            }
        }
    };

    // Inform the underlying network state machine that this dialing attempt
    // has succeeded.
    let mut guarded = inner.guarded.lock().await;
    guarded.num_pending_out_attempts -= 1;
    let (connection_id, connection_task) = guarded.network.pending_outcome_ok_single_stream(
        start_connect.id,
        service::SingleStreamHandshakeKind::MultistreamSelectNoiseYamux,
    );
    inner.wake_up_main_background_task.notify(1);

    let (tx, rx) = mpsc::channel(16); // TODO: ?!
    guarded.active_connections.insert(connection_id, tx);

    // Now run the connection.
    drop(guarded);
    established_connection_task(
        socket,
        inner,
        connection_id,
        connection_task,
        rx,
        connection_to_coordinator,
    )
    .await;
}

/// Asynchronous task managing a specific connection.
#[tracing::instrument(
    level = "trace",
    skip(
        socket,
        inner,
        connection_task,
        coordinator_to_connection,
        connection_to_coordinator
    )
)]
pub(super) async fn established_connection_task(
    socket: impl AsyncRead + AsyncWrite + Unpin,
    inner: Arc<Inner>,
    connection_id: service::ConnectionId,
    mut connection_task: service::SingleStreamConnectionTask<Instant>,
    coordinator_to_connection: mpsc::Receiver<service::CoordinatorToConnection<Instant>>,
    mut connection_to_coordinator: mpsc::Sender<(
        service::ConnectionId,
        service::ConnectionToCoordinator,
    )>,
) {
    // The socket is wrapped around a `WithBuffers` object containing a read buffer and a write
    // buffer. These are the buffers whose pointer is passed to `read(2)` and `write(2)` when
    // reading/writing the socket.
    //
    // Contains `None` if an I/O error has happened on the socket in the past.
    let mut socket_container = Some(with_buffers::WithBuffers::new(socket));

    // We need to use `peek()` on this future later down this function.
    let mut coordinator_to_connection = coordinator_to_connection.peekable();

    loop {
        // Inject in the connection task the messages coming from the coordinator, if any.
        loop {
            let message = match coordinator_to_connection.next().now_or_never() {
                Some(Some(msg)) => msg,
                _ => break,
            };
            connection_task.inject_coordinator_message(message);
        }

        let wake_up_after = if let Some(socket) = socket_container.as_mut() {
            let (read_buffer, write_buffer) = match socket.buffers() {
                Ok(b) => b,
                Err(error) => {
                    tracing::debug!(%error, "connection-error");
                    connection_task.reset();
                    socket_container = None;
                    continue;
                }
            };

            let outgoing_buffer_was_closed = write_buffer.is_none();

            let mut read_write = service::ReadWrite {
                now: Instant::now(),
                incoming_buffer: read_buffer.map(|b| b.0),
                outgoing_buffer: write_buffer,
                read_bytes: 0,
                written_bytes: 0,
                wake_up_after: None,
            };

            connection_task.read_write(&mut read_write);

            if read_write.read_bytes != 0
                || read_write.written_bytes != 0
                || read_write.outgoing_buffer.is_none()
            {
                tracing::event!(
                    tracing::Level::TRACE,
                    read = read_write.read_bytes,
                    written = read_write.written_bytes,
                    "wake-up" = ?read_write.wake_up_after,  // TODO: ugly display
                    "write-close" = read_write.outgoing_buffer.is_none(),
                );
            }

            // We need to destroy `read_write` in order to un-borrow `socket`.
            let read_bytes = read_write.read_bytes;
            let written_bytes = read_write.written_bytes;
            let wake_up_after = read_write.wake_up_after.take();
            let outgoing_buffer_now_closed = read_write.outgoing_buffer.is_none();

            if outgoing_buffer_now_closed && !outgoing_buffer_was_closed {
                socket.close();
            }

            socket.advance(read_bytes, written_bytes);

            if read_bytes != 0 || written_bytes != 0 {
                continue;
            }

            wake_up_after
        } else {
            None
        };

        // Try pull message to send to the coordinator.

        // Calling this method takes ownership of the task and returns that task if it has
        // more work to do. If `None` is returned, then the entire task is gone and the
        // connection must be abruptly closed, which is what happens when we return from
        // this function.
        let (mut task_update, message) = connection_task.pull_message_to_coordinator();

        // If `task_update` is `None`, the connection task is going to die as soon as the
        // message reaches the coordinator. Before returning, we need to do a bit of clean up
        // by removing the task from the list of active connections.
        // This is done before the message is sent to the coordinator, in order to be sure
        // that the connection id is still attributed to the current task, and not to a new
        // connection that the coordinator has assigned after receiving the message.
        if task_update.is_none() {
            let mut guarded = inner.guarded.lock().await;
            let _was_in = guarded.active_connections.remove(&connection_id);
            debug_assert!(_was_in.is_some());
        }

        if let Some(message) = message {
            // Sending this message might take a long time (in case the coordinator is busy),
            // but this is intentional and serves as a back-pressure mechanism.
            // However, it is important to continue processing the messages coming from the
            // coordinator, otherwise this could result in a deadlock.

            // We do this by waiting for `connection_to_coordinator` to be ready to accept
            // an element. Due to the way channels work, once a channel is ready it will
            // always remain ready until we push an element. While waiting, we process
            // incoming messages.
            loop {
                futures::select! {
                    _ = future::poll_fn(|cx| connection_to_coordinator.poll_ready(cx)).fuse() => break,
                    message = coordinator_to_connection.next() => {
                        if let Some(message) = message {
                            if let Some(task_update) = &mut task_update {
                                task_update.inject_coordinator_message(message);
                            }
                        } else {
                            return;
                        }
                    }
                }
            }
            let result = connection_to_coordinator.try_send((connection_id, message));
            inner.wake_up_main_background_task.notify(1);
            if result.is_err() {
                return;
            }
        }

        if let Some(task_update) = task_update {
            connection_task = task_update;
        } else {
            return;
        }

        // Starting from here, we block the current task until more processing needs to happen.

        // Future ready when the timeout indicated by the connection state machine is reached.
        let poll_after = if let Some(wake_up) = wake_up_after {
            let now = Instant::now();
            if wake_up > now {
                let dur = wake_up - now;
                future::Either::Left(futures_timer::Delay::new(dur))
            } else {
                // "Wake up" immediately.
                continue;
            }
        } else {
            future::Either::Right(future::pending())
        }
        .fuse();

        // Future that is woken up when new data is ready on the socket.
        let connection_ready = if let Some(socket) = socket_container.as_mut() {
            future::Either::Left(Pin::new(socket).process())
        } else {
            future::Either::Right(future::pending())
        };

        // Future that is woken up when a new message is coming from the coordinator.
        let message_from_coordinator = Pin::new(&mut coordinator_to_connection).peek();

        // Wait until either some data is ready on the socket, or the connection state machine
        // has requested to be polled again, or a message is coming from the coordinator.
        futures::pin_mut!(connection_ready);
        future::select(
            future::select(connection_ready, message_from_coordinator),
            poll_after,
        )
        .await;
    }
}

/// Builds a future that connects to the given multiaddress. Returns an error if the multiaddress
/// protocols aren't supported.
fn multiaddr_to_socket(
    addr: &Multiaddr,
) -> Result<impl Future<Output = Result<impl AsyncRead + AsyncWrite + Unpin, io::Error>>, ()> {
    let mut iter = addr.iter().fuse();
    let proto1 = iter.next().ok_or(())?;
    let proto2 = iter.next().ok_or(())?;
    let proto3 = iter.next();

    if iter.next().is_some() {
        return Err(());
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

        _ => return Err(()),
    };

    Ok(async move {
        let tcp_socket = match addr {
            either::Left(socket_addr) => async_std::net::TcpStream::connect(socket_addr).await,
            either::Right((dns, port)) => {
                async_std::net::TcpStream::connect((&dns[..], port)).await
            }
        };

        if let Ok(tcp_socket) = &tcp_socket {
            // The Nagle algorithm, implemented in the kernel, consists in buffering the
            // data to be sent out and waiting a bit before actually sending it out, in
            // order to potentially merge multiple writes in a row into one packet. In
            // the implementation below, it is guaranteed that the buffer in `WithBuffers`
            // is filled with as much data as possible before the operating system gets
            // involved. As such, we disable the Nagle algorithm, in order to avoid adding
            // an artificial delay to all sends.
            let _ = tcp_socket.set_nodelay(true);
        }

        match (tcp_socket, host_if_websocket) {
            (Ok(tcp_socket), Some(host)) => {
                websocket::websocket_client_handshake(websocket::Config {
                    tcp_socket,
                    host: &host,
                    url: "/",
                })
                .await
                .map(future::Either::Right)
            }
            (Ok(tcp_socket), None) => Ok(future::Either::Left(tcp_socket)),
            (Err(err), _) => Err(err),
        }
    })
}
