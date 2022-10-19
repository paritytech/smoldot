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

use super::Shared;
use crate::platform::{Platform, PlatformConnection, PlatformSubstreamDirection};

use alloc::{string::ToString as _, sync::Arc, vec, vec::Vec};
use core::{iter, pin::Pin};
use futures::{channel::mpsc, prelude::*};
use smoldot::{libp2p::read_write::ReadWrite, network::service};

/// Asynchronous task managing a specific connection, including the connection process and the
/// processing of the connection after it's been open.
pub(super) async fn connection_task<TPlat: Platform>(
    start_connect: service::StartConnect<TPlat::Instant>,
    shared: Arc<Shared<TPlat>>,
    connection_to_coordinator_tx: mpsc::Sender<(
        service::ConnectionId,
        service::ConnectionToCoordinator,
    )>,
    is_important: bool,
) {
    // Convert the `multiaddr` (typically of the form `/ip4/a.b.c.d/tcp/d/ws`)
    // into a `Future<dyn Output = Result<TcpStream, ...>>`.
    let socket = {
        log::debug!(
            target: "connections",
            "Pending({:?}, {}) started: {}",
            start_connect.id, start_connect.expected_peer_id,
            start_connect.multiaddr
        );
        TPlat::connect(&start_connect.multiaddr.to_string())
    };

    let socket = {
        let socket = socket.fuse();
        futures::pin_mut!(socket);
        let mut timeout = TPlat::sleep_until(start_connect.timeout).fuse();

        let result = futures::select! {
            _ = timeout => Err(None),
            result = socket => result.map_err(Some),
        };

        match (&result, is_important) {
            (Ok(_), _) => {}
            (Err(None), true) => {
                log::warn!(
                    target: "connections",
                    "Timeout when trying to reach bootnode {} through {}",
                    start_connect.expected_peer_id, start_connect.multiaddr
                );
            }
            (Err(None), false) => {
                log::debug!(
                    target: "connections",
                    "Pending({:?}, {}) => Timeout({})",
                    start_connect.id, start_connect.expected_peer_id,
                    start_connect.multiaddr
                );
            }
            (Err(Some(err)), true) if !err.is_bad_addr => {
                log::warn!(
                    target: "connections",
                    "Failed to reach bootnode {} through {}: {}",
                    start_connect.expected_peer_id, start_connect.multiaddr,
                    err.message
                );
            }
            (Err(Some(err)), _) => {
                log::debug!(
                    target: "connections",
                    "Pending({:?}, {}) => ReachFailed(addr={}, known-unreachable={:?}, error={:?})",
                    start_connect.id, start_connect.expected_peer_id,
                    start_connect.multiaddr, err.is_bad_addr, err.message
                );
            }
        }

        match result {
            Ok(connection) => connection,
            Err(err) => {
                let mut guarded = shared.guarded.lock().await;
                guarded.network.pending_outcome_err(
                    start_connect.id,
                    err.map_or(false, |err| err.is_bad_addr),
                ); // TODO: should pass a proper value for `is_unreachable`, but an error is sometimes returned despite a timeout https://github.com/paritytech/smoldot/issues/1531

                for chain_index in 0..guarded.network.num_chains() {
                    guarded
                        .unassign_slot_and_ban(chain_index, start_connect.expected_peer_id.clone());
                }

                // We wake up the background task so that the slot can potentially be
                // assigned to a different peer.
                shared.wake_up_main_background_task.notify(1);

                // Stop the task.
                return;
            }
        }
    };

    // Connection process is successful. Notify the network state machine.
    // There exists two different kind of connections: "single stream" (for example TCP) that is
    // then divided into substreams internally, or "multi stream" where the substreams management
    // is done by the user of the smoldot crate rather than by the smoldot crate itself.
    let mut guarded = shared.guarded.lock().await;
    let (connection_id, socket_and_task) = match socket {
        PlatformConnection::SingleStreamMultistreamSelectNoiseYamux(socket) => {
            let (id, task) = guarded.network.pending_outcome_ok_single_stream(
                start_connect.id,
                service::SingleStreamHandshakeKind::MultistreamSelectNoiseYamux,
            );
            (id, either::Left((socket, task)))
        }
        PlatformConnection::MultiStreamWebRtc {
            connection,
            local_tls_certificate_multihash,
            remote_tls_certificate_multihash,
        } => {
            let (id, task) = guarded.network.pending_outcome_ok_multi_stream(
                start_connect.id,
                service::MultiStreamHandshakeKind::WebRtc {
                    local_tls_certificate_multihash,
                    remote_tls_certificate_multihash,
                },
            );
            (id, either::Right((connection, task)))
        }
    };
    log::debug!(
        target: "connections",
        "Pending({:?}, {}) => Connection through {}",
        start_connect.id,
        start_connect.expected_peer_id,
        start_connect.multiaddr
    );

    let (coordinator_to_connection_tx, coordinator_to_connection_rx) = mpsc::channel(8);
    let _prev_value = guarded
        .active_connections
        .insert(connection_id, coordinator_to_connection_tx);
    debug_assert!(_prev_value.is_none());

    drop(guarded);

    match socket_and_task {
        either::Left((socket, task)) => {
            single_stream_connection_task::<TPlat>(
                socket,
                shared.clone(),
                connection_id,
                task,
                coordinator_to_connection_rx,
                connection_to_coordinator_tx,
            )
            .await
        }
        either::Right((socket, task)) => {
            multi_stream_connection_task::<TPlat>(
                socket,
                shared.clone(),
                connection_id,
                task,
                coordinator_to_connection_rx,
                connection_to_coordinator_tx,
            )
            .await
        }
    }
}

/// Asynchronous task managing a specific single-stream connection after it's been open.
// TODO: a lot of logging disappeared
async fn single_stream_connection_task<TPlat: Platform>(
    mut connection: TPlat::Stream,
    shared: Arc<Shared<TPlat>>,
    connection_id: service::ConnectionId,
    mut connection_task: service::SingleStreamConnectionTask<TPlat::Instant>,
    coordinator_to_connection: mpsc::Receiver<service::CoordinatorToConnection<TPlat::Instant>>,
    mut connection_to_coordinator: mpsc::Sender<(
        service::ConnectionId,
        service::ConnectionToCoordinator,
    )>,
) {
    // We need to use `peek()` on this future later down this function.
    let mut coordinator_to_connection = coordinator_to_connection.peekable();

    // In order to write data on a stream, we simply pass a slice, and the platform will copy
    // from this slice the data to send. Consequently, the write buffer is held locally. This is
    // suboptimal compared to writing to a write buffer provided by the platform, but it is easier
    // to implement it this way.
    let mut write_buffer = vec![0; 4096];

    // The main loop is as follows:
    // - Update the state machine.
    // - Wait until there's something to do.
    // - Repeat.
    loop {
        // Inject in the connection task the messages coming from the coordinator, if any.
        loop {
            let message = match coordinator_to_connection.next().now_or_never() {
                Some(Some(msg)) => msg,
                _ => break,
            };
            connection_task.inject_coordinator_message(message);
        }

        // Perform a read-write. This updates the internal state of the connection task.
        let now = TPlat::now();
        let mut read_write = ReadWrite {
            now: now.clone(),
            incoming_buffer: TPlat::read_buffer(&mut connection),
            outgoing_buffer: Some((&mut write_buffer, &mut [])), // TODO: this should be None if a previous read_write() produced None
            read_bytes: 0,
            written_bytes: 0,
            wake_up_after: None,
        };
        connection_task.read_write(&mut read_write);

        // Because the `read_write` object borrows the connection, we need to drop it before we
        // can modify the connection. Before dropping the `read_write`, clone some important
        // information from it.
        let read_buffer_has_data = read_write.incoming_buffer.map_or(false, |b| !b.is_empty());
        let read_buffer_closed = read_write.incoming_buffer.is_none();
        let read_bytes = read_write.read_bytes;
        let written_bytes = read_write.written_bytes;
        let wake_up_after = read_write.wake_up_after.clone();
        drop(read_write);

        // Now update the connection.
        if written_bytes != 0 {
            TPlat::send(&mut connection, &write_buffer[..written_bytes]);
        }
        TPlat::advance_read_cursor(&mut connection, read_bytes);

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
            let mut guarded = shared.guarded.lock().await;
            let _was_in = guarded.active_connections.remove(&connection_id);
            debug_assert!(_was_in.is_some());
        }

        let has_message = message.is_some();
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
            shared.wake_up_main_background_task.notify(1);
            if result.is_err() {
                return;
            }
        }

        if let Some(task_update) = task_update {
            connection_task = task_update;
        } else {
            return;
        }

        // We must call `read_write` and `pull_message_to_coordinator` repeatedly until nothing
        // happens anymore.
        if has_message || read_bytes != 0 || written_bytes != 0 {
            continue;
        }

        // Starting from here, we block the current task until more processing needs to happen.

        // Future ready when the timeout indicated by the connection state machine is reached.
        let poll_after = if let Some(wake_up) = wake_up_after {
            if wake_up > now {
                let dur = wake_up - now;
                future::Either::Left(TPlat::sleep(dur))
            } else {
                // "Wake up" immediately.
                continue;
            }
        } else {
            future::Either::Right(future::pending())
        }
        .fuse();

        // Future that is woken up when new data is ready on the socket.
        let read_buffer_ready = if !(read_buffer_has_data && read_bytes == 0) && !read_buffer_closed
        {
            future::Either::Left(TPlat::wait_more_data(&mut connection))
        } else {
            future::Either::Right(future::pending())
        };

        // Future that is woken up when a new message is coming from the coordinator.
        let message_from_coordinator = Pin::new(&mut coordinator_to_connection).peek();

        // Wait until either some data is ready on the socket, or the connection state machine
        // has requested to be polled again, or a message is coming from the coordinator.
        futures::pin_mut!(read_buffer_ready);
        future::select(
            future::select(read_buffer_ready, message_from_coordinator),
            poll_after,
        )
        .await;
    }
}

/// Asynchronous task managing a specific multi-stream connection after it's been open.
// TODO: a lot of logging disappeared
async fn multi_stream_connection_task<TPlat: Platform>(
    mut connection: TPlat::Connection,
    shared: Arc<Shared<TPlat>>,
    connection_id: service::ConnectionId,
    mut connection_task: service::MultiStreamConnectionTask<TPlat::Instant, usize>,
    coordinator_to_connection: mpsc::Receiver<service::CoordinatorToConnection<TPlat::Instant>>,
    mut connection_to_coordinator: mpsc::Sender<(
        service::ConnectionId,
        service::ConnectionToCoordinator,
    )>,
) {
    // We need to use `peek()` on this future later down this function.
    let mut coordinator_to_connection = coordinator_to_connection.peekable();

    // Number of substreams that are currently being opened by the `Platform` implementation
    // and that the `connection_task` state machine isn't aware of yet.
    let mut pending_opening_out_substreams = 0;
    // Newly-open substream that has just been yielded by the connection.
    let mut newly_open_substream = None;
    // `true` if the remote has force-closed our connection.
    let mut has_reset = false;
    // List of all currently open substreams. The index (as a `usize`) corresponds to the id
    // of this substream within the `connection_task` state machine.
    let mut open_substreams = slab::Slab::<TPlat::Stream>::with_capacity(16);

    // In order to write data on a stream, we simply pass a slice, and the platform will copy
    // from this slice the data to send. Consequently, the write buffer is held locally. This is
    // suboptimal compared to writing to a write buffer provided by the platform, but it is easier
    // to implement it this way.
    let mut write_buffer = vec![0; 16384]; // TODO: the write buffer must not exceed 16kiB due to the libp2p WebRTC spec; this should ideally be enforced through the connection task API

    loop {
        // Start opening new outbound substreams, if needed.
        for _ in 0..connection_task
            .desired_outbound_substreams()
            .saturating_sub(pending_opening_out_substreams)
        {
            TPlat::open_out_substream(&mut connection);
            pending_opening_out_substreams += 1;
        }

        // The previous wait might have ended when the connection has finished opening a new
        // substream. Notify the `connection_task` state machine.
        if let Some((stream, direction)) = newly_open_substream.take() {
            let outbound = match direction {
                PlatformSubstreamDirection::Outbound => true,
                PlatformSubstreamDirection::Inbound => false,
            };
            let id = open_substreams.insert(stream);
            connection_task.add_substream(id, outbound);
            if outbound {
                pending_opening_out_substreams -= 1;
            }
        }

        // Inject in the connection task the messages coming from the coordinator, if any.
        loop {
            let message = match coordinator_to_connection.next().now_or_never() {
                Some(Some(msg)) => msg,
                _ => break,
            };
            connection_task.inject_coordinator_message(message);
        }

        let now = TPlat::now();

        // When reading/writing substreams, the substream can ask to be woken up after a certain
        // time. This variable stores the earliest time when we should be waking up.
        let mut wake_up_after = None;

        // Perform a read-write on all substreams.
        // TODO: trying to read/write every single substream every single time is suboptimal, but making this not suboptimal is very complicated
        for substream_id in open_substreams.iter().map(|(id, _)| id).collect::<Vec<_>>() {
            loop {
                let substream = &mut open_substreams[substream_id];

                let mut read_write = ReadWrite {
                    now: now.clone(),
                    incoming_buffer: TPlat::read_buffer(substream),
                    outgoing_buffer: Some((&mut write_buffer, &mut [])), // TODO: this should be None if a previous read_write() produced None
                    read_bytes: 0,
                    written_bytes: 0,
                    wake_up_after,
                };

                let kill_substream =
                    connection_task.substream_read_write(&substream_id, &mut read_write);

                // Because the `read_write` object borrows the stream, we need to drop it before we
                // can modify the connection. Before dropping the `read_write`, clone some important
                // information from it.
                let read_bytes = read_write.read_bytes;
                let written_bytes = read_write.written_bytes;
                wake_up_after = read_write.wake_up_after.take();
                drop(read_write);

                // Now update the connection.
                if written_bytes != 0 {
                    TPlat::send(substream, &write_buffer[..written_bytes]);
                }
                TPlat::advance_read_cursor(substream, read_bytes);

                // If the `connection_task` requires this substream to be killed, we drop the `Stream`
                // object.
                if kill_substream {
                    open_substreams.remove(substream_id);
                    break;
                }

                if read_bytes == 0 && written_bytes == 0 {
                    break;
                }
            }
        }

        // Try pull message to send to the coordinator.
        {
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
                let mut guarded = shared.guarded.lock().await;
                let _was_in = guarded.active_connections.remove(&connection_id);
                debug_assert!(_was_in.is_some());
            }

            let has_message = message.is_some();
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
                shared.wake_up_main_background_task.notify(1);
                if result.is_err() {
                    return;
                }
            }

            if let Some(task_update) = task_update {
                connection_task = task_update;
            } else {
                return;
            }

            if has_message {
                continue;
            }
        }

        // Starting from here, we block the current task until more processing needs to happen.

        // Future ready when the timeout indicated by the connection state machine is reached.
        let mut poll_after = if let Some(wake_up) = wake_up_after.clone() {
            if wake_up > now {
                let dur = wake_up - now;
                future::Either::Left(TPlat::sleep(dur))
            } else {
                // "Wake up" immediately.
                continue;
            }
        } else {
            future::Either::Right(future::pending())
        }
        .fuse();

        // Future that is woken up when new data is ready on any of the streams.
        // TODO: very suboptimal
        // TODO: will loop infinitely if the remote closes its writing side because `wait_more_data` is immediately ready when that is the case
        let data_ready = iter::once(future::Either::Right(future::pending()))
            .chain(
                open_substreams
                    .iter_mut()
                    .map(|(_, stream)| future::Either::Left(TPlat::wait_more_data(stream))),
            )
            .collect::<future::SelectAll<_>>();

        // Future that is woken up when a new message is coming from the coordinator.
        let mut message_from_coordinator = Pin::new(&mut coordinator_to_connection).peek();

        // Do the actual waiting.
        debug_assert!(newly_open_substream.is_none());
        futures::select! {
            _ = message_from_coordinator => {}
            substream = if has_reset { either::Right(future::pending()) } else { either::Left(TPlat::next_substream(&mut connection)) }.fuse() => {
                match substream {
                    Some(s) => newly_open_substream = Some(s),
                    None => {
                        // `None` is returned if the remote has force-closed the connection.
                        connection_task.reset();
                        has_reset = true;
                    }
                }
            }
            _ = poll_after => {}
            _ = data_ready.fuse() => {}
        }
    }
}
