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

use crate::{
    log,
    platform::{PlatformRef, SubstreamDirection},
};

use alloc::{boxed::Box, string::String, sync::Arc};
use core::{pin, time::Duration};
use futures_lite::FutureExt as _;
use futures_util::{StreamExt as _, future, stream::FuturesUnordered};
use smoldot::{libp2p::collection::SubstreamFate, network::service};

/// Asynchronous task managing a specific single-stream connection.
pub(super) async fn single_stream_connection_task<TPlat: PlatformRef>(
    connection: TPlat::Stream,
    address_string: String,
    platform: TPlat,
    connection_id: service::ConnectionId,
    connection_task: service::SingleStreamConnectionTask<TPlat::Instant>,
    coordinator_to_connection: async_channel::Receiver<service::CoordinatorToConnection>,
    connection_to_coordinator: async_channel::Sender<(
        service::ConnectionId,
        service::ConnectionToCoordinator,
    )>,
) {
    // We need to pin the receiver, as the type doesn't implement `Unpin`.
    let mut coordinator_to_connection = pin::pin!(coordinator_to_connection);
    // We also need to pin the socket, as we don't know whether it implements `Unpin`.
    let mut socket = pin::pin!(connection);

    // Future that sends a message to the coordinator. Only one message is sent to the coordinator
    // at a time. `None` if no message is being sent.
    let mut message_sending = pin::pin!(None);

    // Wrap `connection_task` within an `Option`. It will become `None` if the connection task
    // wants to self-destruct.
    let mut connection_task = Some(connection_task);

    loop {
        // Yield at every loop in order to provide better tasks granularity.
        futures_lite::future::yield_now().await;

        // Because only one message should be sent to the coordinator at a time, and that
        // processing the socket might generate a message, we only process the socket if no
        // message is currently being sent.
        if message_sending.is_none() && connection_task.is_some() {
            let mut task = connection_task.take().unwrap();

            match platform.read_write_access(socket.as_mut()) {
                Ok(mut socket_read_write) => {
                    // The code in this block is a bit cumbersome due to the logging.
                    let read_bytes_before = socket_read_write.read_bytes;
                    let written_bytes_before = socket_read_write.write_bytes_queued;
                    let write_closed = socket_read_write.write_bytes_queueable.is_none();

                    task.read_write(&mut *socket_read_write);

                    if socket_read_write.read_bytes != read_bytes_before
                        || socket_read_write.write_bytes_queued != written_bytes_before
                        || (!write_closed && socket_read_write.write_bytes_queueable.is_none())
                    {
                        log!(
                            &platform,
                            Trace,
                            "connections",
                            "connection-activity",
                            address = address_string,
                            read = socket_read_write.read_bytes - read_bytes_before,
                            written = socket_read_write.write_bytes_queued - written_bytes_before,
                            wake_up_after = ?socket_read_write.wake_up_after.as_ref().map(|w| {
                                if *w > socket_read_write.now {
                                    w.clone() - socket_read_write.now.clone()
                                } else {
                                    Duration::new(0, 0)
                                }
                            }),
                            write_closed = socket_read_write.write_bytes_queueable.is_none(),
                        );
                    }
                }
                Err(err) => {
                    // Error on the socket.
                    if !task.is_reset_called() {
                        log!(
                            &platform,
                            Trace,
                            "connections",
                            "reset",
                            address = address_string,
                            reason = ?err
                        );
                        task.reset();
                    }
                }
            }

            // Try pull message to send to the coordinator.

            // Calling this method takes ownership of the task and returns that task if it has
            // more work to do. If `None` is returned, then the entire task is gone and the
            // connection must be abruptly closed, which is what happens when we return from
            // this function.
            let (task_update, message) = task.pull_message_to_coordinator();
            connection_task = task_update;

            debug_assert!(message_sending.is_none());
            if let Some(message) = message {
                message_sending.set(Some(
                    connection_to_coordinator.send((connection_id, message)),
                ));
            }
        }

        // Now wait for something interesting to happen before looping again.

        enum WakeUpReason {
            CoordinatorMessage(service::CoordinatorToConnection),
            CoordinatorDead,
            SocketEvent,
            MessageSent,
        }

        let wake_up_reason: WakeUpReason = {
            // If the connection task has self-destructed and that no message is being sent, stop
            // the task altogether as nothing will happen.
            if connection_task.is_none() && message_sending.is_none() {
                log!(
                    &platform,
                    Trace,
                    "connections",
                    "shutdown",
                    address = address_string
                );
                return;
            }

            let coordinator_message = async {
                match coordinator_to_connection.next().await {
                    Some(msg) => WakeUpReason::CoordinatorMessage(msg),
                    None => WakeUpReason::CoordinatorDead,
                }
            };

            let socket_event = {
                // The future returned by `wait_read_write_again` yields when `read_write_access`
                // must be called. Because we only call `read_write_access` when `message_sending`
                // is `None`, we also call `wait_read_write_again` only when `message_sending` is
                // `None`.
                let fut = if message_sending.as_ref().as_pin_ref().is_none() {
                    Some(platform.wait_read_write_again(socket.as_mut()))
                } else {
                    None
                };
                async {
                    if let Some(fut) = fut {
                        fut.await;
                        WakeUpReason::SocketEvent
                    } else {
                        future::pending().await
                    }
                }
            };

            let message_sent = async {
                let result = if let Some(message_sending) = message_sending.as_mut().as_pin_mut() {
                    message_sending.await
                } else {
                    future::pending().await
                };
                message_sending.set(None);
                if result.is_ok() {
                    WakeUpReason::MessageSent
                } else {
                    WakeUpReason::CoordinatorDead
                }
            };

            coordinator_message.or(socket_event).or(message_sent).await
        };

        match wake_up_reason {
            WakeUpReason::CoordinatorMessage(message) => {
                // The coordinator normally guarantees that no message is sent after the task
                // is destroyed.
                let connection_task = connection_task.as_mut().unwrap_or_else(|| unreachable!());
                connection_task.inject_coordinator_message(&platform.now(), message);
            }
            WakeUpReason::CoordinatorDead => {
                log!(
                    &platform,
                    Trace,
                    "connections",
                    "shutdown",
                    address = address_string
                );
                return;
            }
            WakeUpReason::SocketEvent => {}
            WakeUpReason::MessageSent => {}
        }
    }
}

/// Asynchronous task managing a specific multi-stream connection.
///
/// > **Note**: This function is specific to WebRTC in the sense that it checks whether the reading
/// >           and writing sides of substreams never close, and adjusts the size of the write
/// >           buffer to not go over the frame size limit of WebRTC. It can easily be made more
/// >           general-purpose.
pub(super) async fn webrtc_multi_stream_connection_task<TPlat: PlatformRef>(
    mut connection: TPlat::MultiStream,
    address_string: String,
    platform: TPlat,
    connection_id: service::ConnectionId,
    mut connection_task: service::MultiStreamConnectionTask<TPlat::Instant, usize>,
    coordinator_to_connection: async_channel::Receiver<service::CoordinatorToConnection>,
    connection_to_coordinator: async_channel::Sender<(
        service::ConnectionId,
        service::ConnectionToCoordinator,
    )>,
) {
    // Future that sends a message to the coordinator. Only one message is sent to the coordinator
    // at a time. `None` if no message is being sent.
    let mut message_sending = pin::pin!(None);
    // Number of substreams that are currently being opened by the `PlatformRef` implementation
    // and that the `connection_task` state machine isn't aware of yet.
    let mut pending_opening_out_substreams = 0;
    // Stream that yields an item whenever a substream is ready to be read-written.
    // TODO: we box the future because of the type checker being annoying
    let mut when_substreams_rw_ready = FuturesUnordered::<
        pin::Pin<Box<dyn Future<Output = (pin::Pin<Box<TPlat::Stream>>, usize)> + Send>>,
    >::new();
    // Identifier to assign to the next substream.
    // TODO: weird API
    let mut next_substream_id = 0;
    // We need to pin the receiver, as the type doesn't implement `Unpin`.
    let mut coordinator_to_connection = pin::pin!(coordinator_to_connection);
    // Shared event used to wake up all substream wait futures when
    // `inject_coordinator_message` queues write data (e.g. AcceptInNotifications).
    // Without this, the substream would never be re-polled since the platform's
    // `wait_read_write_again` only wakes on incoming data or timers.
    let coordinator_write_ready = Arc::new(event_listener::Event::new());

    loop {
        // Start opening new outbound substreams, if needed.
        for _ in 0..connection_task
            .desired_outbound_substreams()
            .saturating_sub(pending_opening_out_substreams)
        {
            log!(
                &platform,
                Trace,
                "connections",
                "substream-open-start",
                address = address_string
            );
            platform.open_out_substream(&mut connection);
            pending_opening_out_substreams += 1;
        }

        // Now wait for something interesting to happen before looping again.

        enum WakeUpReason<TPlat: PlatformRef> {
            CoordinatorMessage(service::CoordinatorToConnection),
            CoordinatorDead,
            SocketEvent(pin::Pin<Box<TPlat::Stream>>, usize),
            MessageSent,
            NewSubstream(TPlat::Stream, SubstreamDirection),
            ConnectionReset,
        }

        let wake_up_reason: WakeUpReason<TPlat> = {
            let coordinator_message = async {
                match coordinator_to_connection.next().await {
                    Some(msg) => WakeUpReason::CoordinatorMessage(msg),
                    None => WakeUpReason::CoordinatorDead,
                }
            };

            let socket_event = {
                // The future returned by `wait_read_write_again` yields when `read_write_access`
                // must be called. Because we only call `read_write_access` when `message_sending`
                // is `None`, we also call `wait_read_write_again` only when `message_sending` is
                // `None`.
                let fut = if message_sending.as_ref().as_pin_ref().is_none()
                    && !when_substreams_rw_ready.is_empty()
                {
                    Some(when_substreams_rw_ready.select_next_some())
                } else {
                    None
                };
                async move {
                    if let Some(fut) = fut {
                        let (stream, substream_id) = fut.await;
                        WakeUpReason::SocketEvent(stream, substream_id)
                    } else {
                        future::pending().await
                    }
                }
            };

            let message_sent = async {
                let result: Result<(), _> =
                    if let Some(message_sending) = message_sending.as_mut().as_pin_mut() {
                        message_sending.await
                    } else {
                        future::pending().await
                    };
                message_sending.set(None);
                if result.is_ok() {
                    WakeUpReason::MessageSent
                } else {
                    WakeUpReason::CoordinatorDead
                }
            };

            // Future that is woken up when a new substream is available.
            let next_substream = async {
                if connection_task.is_reset_called() {
                    future::pending().await
                } else {
                    match platform.next_substream(&mut connection).await {
                        Some((stream, direction)) => WakeUpReason::NewSubstream(stream, direction),
                        None => WakeUpReason::ConnectionReset,
                    }
                }
            };

            coordinator_message
                .or(socket_event)
                .or(message_sent)
                .or(next_substream)
                .await
        };

        match wake_up_reason {
            WakeUpReason::CoordinatorMessage(message) => {
                connection_task.inject_coordinator_message(&platform.now(), message);
                // Wake up all substream wait futures so they get re-polled.
                // This is necessary because inject_coordinator_message may have
                // queued write data (e.g. AcceptInNotifications queues a handshake
                // response) but the platform's wait_read_write_again only wakes on
                // incoming data or timers -- not on pending writes.
                coordinator_write_ready.notify(usize::MAX);
            }
            WakeUpReason::CoordinatorDead => {
                log!(
                    &platform,
                    Trace,
                    "connections",
                    "shutdown",
                    address = address_string
                );
                return;
            }
            WakeUpReason::SocketEvent(mut socket, substream_id) => {
                debug_assert!(message_sending.is_none());

                let substream_fate = match platform.read_write_access(socket.as_mut()) {
                    Ok(mut socket_read_write) => {
                        // The code in this block is a bit cumbersome due to the logging.
                        let read_bytes_before = socket_read_write.read_bytes;
                        let written_bytes_before = socket_read_write.write_bytes_queued;
                        let write_closed = socket_read_write.write_bytes_queueable.is_none();

                        let substream_fate = connection_task
                            .substream_read_write(&substream_id, &mut *socket_read_write);

                        if socket_read_write.read_bytes != read_bytes_before
                            || socket_read_write.write_bytes_queued != written_bytes_before
                            || (!write_closed && socket_read_write.write_bytes_queueable.is_none())
                        {
                            log!(
                                &platform,
                                Trace,
                                "connections",
                                "connection-activity",
                                address = address_string,
                                read = socket_read_write.read_bytes - read_bytes_before,
                                written = socket_read_write.write_bytes_queued - written_bytes_before,
                                wake_up_after = ?socket_read_write.wake_up_after.as_ref().map(|w| {
                                    if *w > socket_read_write.now {
                                        w.clone() - socket_read_write.now.clone()
                                    } else {
                                        Duration::new(0, 0)
                                    }
                                }),
                                write_close = ?socket_read_write.write_bytes_queueable.is_none(),
                            );
                        }

                        if let SubstreamFate::Reset = substream_fate {
                            log!(
                                &platform,
                                Trace,
                                "connections",
                                "reset-substream",
                                address = address_string,
                                substream_id
                            );
                        }

                        substream_fate
                    }
                    Err(err) => {
                        // Error on the substream.
                        log!(
                            &platform,
                            Trace,
                            "connections",
                            "substream-reset-by-remote",
                            address = address_string,
                            substream_id,
                            error = ?err
                        );
                        connection_task.reset_substream(&substream_id);
                        SubstreamFate::Reset
                    }
                };

                // Try pull message to send to the coordinator.

                // Calling this method takes ownership of the task and returns that task if it has
                // more work to do. If `None` is returned, then the entire task is gone and the
                // connection must be abruptly closed, which is what happens when we return from
                // this function.
                let (task_update, message) = connection_task.pull_message_to_coordinator();
                if let Some(task_update) = task_update {
                    connection_task = task_update;
                    debug_assert!(message_sending.is_none());
                    if let Some(message) = message {
                        message_sending.set(Some(
                            connection_to_coordinator.send((connection_id, message)),
                        ));
                    }
                } else {
                    log!(
                        &platform,
                        Trace,
                        "connections",
                        "shutdown",
                        address = address_string
                    );
                    return;
                }

                // Put back the stream in `when_substreams_rw_ready`.
                if let SubstreamFate::Continue = substream_fate {
                    when_substreams_rw_ready.push({
                        let platform = platform.clone();
                        let write_ready = coordinator_write_ready.clone();
                        let write_listener = write_ready.listen();
                        Box::pin(async move {
                            // Wait for either platform data or a coordinator write
                            // notification (e.g. after AcceptInNotifications queues a
                            // handshake response that needs to be flushed).
                            platform
                                .wait_read_write_again(socket.as_mut())
                                .or(write_listener)
                                .await;
                            (socket, substream_id)
                        })
                    });
                }
            }
            WakeUpReason::MessageSent => {}
            WakeUpReason::ConnectionReset => {
                debug_assert!(!connection_task.is_reset_called());
                log!(
                    &platform,
                    Trace,
                    "connections",
                    "reset",
                    address = address_string
                );
                connection_task.reset();
            }
            WakeUpReason::NewSubstream(substream, direction) => {
                let outbound = match direction {
                    SubstreamDirection::Outbound => true,
                    SubstreamDirection::Inbound => false,
                };
                let substream_id = next_substream_id;
                next_substream_id += 1;
                log!(
                    &platform,
                    Trace,
                    "connections",
                    "substream-opened",
                    address = address_string,
                    substream_id,
                    ?direction
                );
                connection_task.add_substream(substream_id, outbound);
                if outbound {
                    pending_opening_out_substreams -= 1;
                }

                when_substreams_rw_ready
                    .push(Box::pin(async move { (Box::pin(substream), substream_id) }));
            }
        }
    }
}
