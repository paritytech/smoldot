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

use super::{
    super::{
        connection::{established, single_stream_handshake},
        read_write::ReadWrite,
    },
    ConnectionToCoordinator, ConnectionToCoordinatorInner, CoordinatorToConnection,
    CoordinatorToConnectionInner, NotificationsOutErr, ShutdownCause, SubstreamId,
};

use alloc::{collections::VecDeque, string::ToString as _, sync::Arc};
use core::{
    mem,
    ops::{Add, Sub},
    time::Duration,
};

pub(super) struct Config<TNow> {
    pub(super) randomness_seed: [u8; 32],
    pub(super) handshake: single_stream_handshake::HealthyHandshake,
    pub(super) handshake_timeout: TNow,
    pub(super) max_inbound_substreams: usize,
    pub(super) substreams_capacity: usize,
    pub(super) max_protocol_name_len: usize,
    pub(super) ping_protocol: Arc<str>,
}

/// State machine dedicated to a single single-stream connection.
pub struct SingleStreamConnectionTask<TNow> {
    /// State machine of the underlying connection.
    connection: SingleStreamConnectionTaskInner<TNow>,

    /// Buffer of messages destined to the coordinator.
    ///
    /// Never goes above a few elements.
    pending_messages: VecDeque<ConnectionToCoordinatorInner>,
}

enum SingleStreamConnectionTaskInner<TNow> {
    /// Connection is still in its handshake phase.
    Handshake {
        handshake: single_stream_handshake::HealthyHandshake,

        /// Seed that will be used to initialize randomness when building the
        /// [`established::SingleStream`].
        /// This seed is computed during the handshake in order to avoid having to access a shared
        /// state when the handshake is over. While it seems a bit dangerous to leave a randomness
        /// seed in plain memory, the randomness isn't used for anything critical or related to
        /// cryptography, but only for example to avoid hash collision attacks.
        randomness_seed: [u8; 32],

        /// When the handshake phase times out.
        timeout: TNow,

        /// See [`super::Config::max_inbound_substreams`].
        max_inbound_substreams: usize,

        /// See [`Config::substreams_capacity`].
        substreams_capacity: usize,

        max_protocol_name_len: usize,

        /// See [`super::Config::ping_protocol`].
        ping_protocol: Arc<str>,
    },

    /// Connection has been fully established.
    Established {
        established: established::SingleStream<TNow, Option<SubstreamId>>,

        /// Because outgoing substream ids are assigned by the coordinator, we maintain a mapping
        /// of the "outer ids" to "inner ids".
        outbound_substreams_map:
            hashbrown::HashMap<SubstreamId, established::SubstreamId, fnv::FnvBuildHasher>,

        /// After a [`ConnectionToCoordinatorInner::NotificationsInOpenCancel`] or a
        /// [`ConnectionToCoordinatorInner::NotificationsInClose`] is emitted, an
        /// entry is added to this list. If the coordinator accepts or refuses a substream in this
        /// list, or closes a substream in this list, the acceptance/refusal/closing is dismissed.
        notifications_in_close_acknowledgments: VecDeque<established::SubstreamId>,

        /// After a `NotificationsInOpenCancel` is emitted by the connection, an
        /// entry is added to this list. If the coordinator accepts or refuses a substream in this
        /// list, the acceptance/refusal is dismissed.
        // TODO: this works only because SubstreamIds aren't reused
        inbound_negotiated_cancel_acknowledgments:
            hashbrown::HashSet<established::SubstreamId, fnv::FnvBuildHasher>,
    },

    /// Connection has finished its shutdown. A [`ConnectionToCoordinatorInner::ShutdownFinished`]
    /// message has been sent and is waiting to be acknowledged.
    ShutdownWaitingAck {
        /// What has initiated the shutdown.
        initiator: ShutdownInitiator,
    },

    /// Connection has finished its shutdown and its shutdown has been acknowledged. There is
    /// nothing more to do except stop the connection task.
    ShutdownAcked {
        /// What has initiated the shutdown.
        initiator: ShutdownInitiator,
    },

    /// Temporary state used to satisfy the borrow checker during state transitions.
    Poisoned,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ShutdownInitiator {
    /// The coordinator sent a [`CoordinatorToConnectionInner::StartShutdown`] message.
    Coordinator,
    /// [`SingleStreamConnectionTask::reset`] has been called.
    Api,
    /// The shutdown has been initiated due to a protocol error or because the connection has been
    /// shut down cleanly by the remote.
    Remote,
}

impl<TNow> SingleStreamConnectionTask<TNow>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    // Note that the parameters of this function are a bit rough and undocumented, as this is
    // a function only called from the parent module.
    pub(super) fn new(config: Config<TNow>) -> Self {
        SingleStreamConnectionTask {
            connection: SingleStreamConnectionTaskInner::Handshake {
                handshake: config.handshake,
                randomness_seed: config.randomness_seed,
                timeout: config.handshake_timeout,
                max_inbound_substreams: config.max_inbound_substreams,
                substreams_capacity: config.substreams_capacity,
                max_protocol_name_len: config.max_protocol_name_len,
                ping_protocol: config.ping_protocol,
            },
            pending_messages: VecDeque::with_capacity({
                // We never buffer more than a few messages.
                4
            }),
        }
    }

    /// Pulls a message to send back to the coordinator.
    ///
    /// This function takes ownership of `self` and optionally yields it back. If the first
    /// option contains `None`, then no more message will be generated and the
    /// [`SingleStreamConnectionTask`] has vanished. This will happen after the connection has been
    /// shut down or reset.
    /// It is possible for `self` to not be yielded back even if the [`ReadWrite`] that was last
    /// passed to [`SingleStreamConnectionTask::read_write`] is still fully open, in which case the
    /// API user should abruptly reset the connection, for example by sending a TCP RST flag. This
    /// can happen for example if the connection seems unresponsive and that an attempt at closing
    /// the connection in a clean way is futile.
    ///
    /// If any message is returned, it is the responsibility of the API user to send it to the
    /// coordinator.
    /// Do not attempt to buffer the message being returned, as it would work against the
    /// back-pressure strategy used internally. As soon as a message is returned, it should be
    /// delivered. If the coordinator is busy at the moment a message should be delivered, then
    /// the entire thread of execution dedicated to this [`SingleStreamConnectionTask`] should be
    /// paused until the coordinator is ready and the message delivered.
    ///
    /// Messages aren't generated spontaneously. In other words, you don't need to periodically
    /// call this function just in case there's a new message. Messages are always generated after
    /// either [`SingleStreamConnectionTask::read_write`] or [`SingleStreamConnectionTask::reset`]
    /// has been called. Multiple messages can happen in a row.
    ///
    /// Because this function frees space in a buffer, calling
    /// [`SingleStreamConnectionTask::read_write`] again after it has returned might read/write
    /// more data and generate an event again. In other words, the API user should call
    /// [`SingleStreamConnectionTask::read_write`] and
    /// [`SingleStreamConnectionTask::pull_message_to_coordinator`] repeatedly in a loop until no
    /// more message is generated.
    pub fn pull_message_to_coordinator(
        mut self,
    ) -> (Option<Self>, Option<ConnectionToCoordinator>) {
        // To be sure that there is no bug in the implementation, we make sure that the number of
        // buffered messages doesn't go above a certain small limit.
        debug_assert!(self.pending_messages.len() < 8);

        let message = self
            .pending_messages
            .pop_front()
            .map(|inner| ConnectionToCoordinator { inner });

        // The `ShutdownAcked` state causes the task to exit.
        let self_ret = if !matches!(
            self.connection,
            SingleStreamConnectionTaskInner::ShutdownAcked { .. }
        ) {
            Some(self)
        } else {
            None
        };

        (self_ret, message)
    }

    /// Injects a message that has been pulled from the coordinator.
    ///
    /// Calling this function might generate data to send to the connection. You should call
    /// [`SingleStreamConnectionTask::read_write`] after this function has returned (unless you
    /// have called [`SingleStreamConnectionTask::reset`] in the past).
    pub fn inject_coordinator_message(&mut self, now: &TNow, message: CoordinatorToConnection) {
        match (message.inner, &mut self.connection) {
            (
                CoordinatorToConnectionInner::AcceptInbound {
                    substream_id,
                    inbound_ty,
                },
                SingleStreamConnectionTaskInner::Established {
                    established,
                    inbound_negotiated_cancel_acknowledgments,
                    ..
                },
            ) => {
                if !inbound_negotiated_cancel_acknowledgments.remove(&substream_id) {
                    established.accept_inbound(substream_id, inbound_ty, None);
                } else {
                    self.pending_messages.push_back(
                        ConnectionToCoordinatorInner::InboundAcceptedCancel { id: substream_id },
                    )
                }
            }
            (
                CoordinatorToConnectionInner::RejectInbound { substream_id },
                SingleStreamConnectionTaskInner::Established {
                    established,
                    inbound_negotiated_cancel_acknowledgments,
                    ..
                },
            ) => {
                if !inbound_negotiated_cancel_acknowledgments.remove(&substream_id) {
                    established.reject_inbound(substream_id);
                }
            }
            (
                CoordinatorToConnectionInner::SetMaxProtocolNameLen { new_max_length },
                SingleStreamConnectionTaskInner::Handshake {
                    max_protocol_name_len,
                    ..
                },
            ) => {
                *max_protocol_name_len = new_max_length;
            }
            (
                CoordinatorToConnectionInner::SetMaxProtocolNameLen { new_max_length },
                SingleStreamConnectionTaskInner::Established { established, .. },
            ) => {
                established.set_max_protocol_name_len(new_max_length);
            }
            (
                CoordinatorToConnectionInner::StartRequest {
                    protocol_name,
                    request_data,
                    timeout,
                    max_response_size,
                    substream_id,
                },
                SingleStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                let inner_substream_id = established.add_request(
                    protocol_name,
                    request_data,
                    now.clone() + timeout,
                    max_response_size,
                    Some(substream_id),
                );

                let _prev_value = outbound_substreams_map.insert(substream_id, inner_substream_id);
                debug_assert!(_prev_value.is_none());
            }
            (
                CoordinatorToConnectionInner::OpenOutNotifications {
                    protocol_name,
                    max_handshake_size,
                    handshake,
                    handshake_timeout,
                    substream_id: outer_substream_id,
                },
                SingleStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                let inner_substream_id = established.open_notifications_substream(
                    protocol_name,
                    handshake,
                    max_handshake_size,
                    now.clone() + handshake_timeout,
                    Some(outer_substream_id),
                );

                let _prev_value =
                    outbound_substreams_map.insert(outer_substream_id, inner_substream_id);
                debug_assert!(_prev_value.is_none());
            }
            (
                CoordinatorToConnectionInner::CloseOutNotifications { substream_id },
                SingleStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                // It is possible that the remote has closed the outbound notification substream
                // while the `CloseOutNotifications` message was being delivered, or that the API
                // user close the substream before the message about the substream being closed
                // was delivered to the coordinator.
                if let Some(inner_substream_id) = outbound_substreams_map.remove(&substream_id) {
                    established.close_out_notifications_substream(inner_substream_id);
                }
            }
            (
                CoordinatorToConnectionInner::QueueNotification {
                    substream_id,
                    notification,
                },
                SingleStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                // It is possible that the remote has closed the outbound notification substream
                // while a `QueueNotification` message was being delivered, or that the API user
                // queued a notification before the message about the substream being closed was
                // delivered to the coordinator.
                // If that happens, we intentionally silently discard the message, causing the
                // notification to not be sent. This is consistent with the guarantees about
                // notifications delivered that are documented in the public API.
                if let Some(inner_substream_id) = outbound_substreams_map.get(&substream_id) {
                    established.write_notification_unbounded(*inner_substream_id, notification);
                }
            }
            (
                CoordinatorToConnectionInner::OpenOutBitswap {
                    substream_id: outer_substream_id,
                },
                SingleStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                let inner_substream_id =
                    established.open_bitswap_substream(Some(outer_substream_id));

                let _prev_value =
                    outbound_substreams_map.insert(outer_substream_id, inner_substream_id);
                debug_assert!(_prev_value.is_none());
            }
            (
                CoordinatorToConnectionInner::CloseOutBitswap { substream_id },
                SingleStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                // It is possible that the remote has closed the outbound Bitswap substream
                // while the `CloseOutBitswap` message was being delivered, or that the API
                // user closed the substream before the message about the substream being closed
                // was delivered to the coordinator.
                if let Some(inner_substream_id) = outbound_substreams_map.remove(&substream_id) {
                    established.close_out_bitswap_substream(inner_substream_id);
                }
            }
            (
                CoordinatorToConnectionInner::QueueBitswapMessage {
                    substream_id,
                    message,
                },
                SingleStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                // It is possible that the remote has closed the outbound Bitswap substream while
                // a `QueueBitswapMessage` message was being delivered, or that the API user
                // queued a Bitswap message before the message about the substream being closed was
                // delivered to the coordinator.
                // If that happens, we intentionally silently discard the message, causing the
                // Bitswap message to not be sent. This is consistent with the guarantees about
                // Bitswap messages deliverey that are documented in the public API.
                if let Some(inner_substream_id) = outbound_substreams_map.get(&substream_id) {
                    established.write_bitswap_message_unbounded(*inner_substream_id, notification);
                }
            }
            (
                CoordinatorToConnectionInner::CloseInBitswap { substream_id },
                SingleStreamConnectionTaskInner::Established { established, .. },
            ) => {
                established.close_in_bitswap_substream(substream_id);
            }
            (
                CoordinatorToConnectionInner::AnswerRequest {
                    substream_id,
                    response,
                },
                SingleStreamConnectionTaskInner::Established { established, .. },
            ) => match established.respond_in_request(substream_id, response) {
                Ok(()) => {}
                Err(established::RespondInRequestError::SubstreamClosed) => {
                    // As documented, answering an obsolete request is simply ignored.
                }
            },
            (
                CoordinatorToConnectionInner::AnswerRequest {
                    substream_id,
                    response,
                },
                SingleStreamConnectionTaskInner::Established { established, .. },
            ) => match established.respond_in_request(substream_id, response) {
                Ok(()) => {}
                Err(established::RespondInRequestError::SubstreamClosed) => {
                    // As documented, answering an obsolete request is simply ignored.
                }
            },
            (
                CoordinatorToConnectionInner::AcceptInNotifications {
                    substream_id,
                    handshake,
                    max_notification_size,
                },
                SingleStreamConnectionTaskInner::Established {
                    established,
                    notifications_in_close_acknowledgments,
                    ..
                },
            ) => {
                if let Some(idx) = notifications_in_close_acknowledgments
                    .iter()
                    .position(|s| *s == substream_id)
                {
                    notifications_in_close_acknowledgments.remove(idx);
                } else {
                    established.accept_in_notifications_substream(
                        substream_id,
                        handshake,
                        max_notification_size,
                    );
                }
            }
            (
                CoordinatorToConnectionInner::RejectInNotifications { substream_id },
                SingleStreamConnectionTaskInner::Established {
                    established,
                    notifications_in_close_acknowledgments,
                    ..
                },
            ) => {
                if let Some(idx) = notifications_in_close_acknowledgments
                    .iter()
                    .position(|s| *s == substream_id)
                {
                    notifications_in_close_acknowledgments.remove(idx);
                } else {
                    established.reject_in_notifications_substream(substream_id);
                }
            }
            (
                CoordinatorToConnectionInner::CloseInNotifications {
                    substream_id,
                    timeout,
                },
                SingleStreamConnectionTaskInner::Established {
                    established,
                    notifications_in_close_acknowledgments,
                    ..
                },
            ) => {
                if let Some(idx) = notifications_in_close_acknowledgments
                    .iter()
                    .position(|s| *s == substream_id)
                {
                    notifications_in_close_acknowledgments.remove(idx);
                } else {
                    established
                        .close_in_notifications_substream(substream_id, now.clone() + timeout);
                }
            }
            (
                CoordinatorToConnectionInner::StartShutdown { .. },
                SingleStreamConnectionTaskInner::Established { .. }
                | SingleStreamConnectionTaskInner::Handshake { .. },
            ) => {
                // TODO: implement proper shutdown
                self.pending_messages
                    .push_back(ConnectionToCoordinatorInner::StartShutdown(None));
                self.pending_messages
                    .push_back(ConnectionToCoordinatorInner::ShutdownFinished);
                self.connection = SingleStreamConnectionTaskInner::ShutdownWaitingAck {
                    initiator: ShutdownInitiator::Coordinator,
                };
            }
            (
                CoordinatorToConnectionInner::AcceptInbound { .. }
                | CoordinatorToConnectionInner::RejectInbound { .. }
                | CoordinatorToConnectionInner::SetMaxProtocolNameLen { .. }
                | CoordinatorToConnectionInner::AcceptInNotifications { .. }
                | CoordinatorToConnectionInner::RejectInNotifications { .. }
                | CoordinatorToConnectionInner::CloseInNotifications { .. }
                | CoordinatorToConnectionInner::StartRequest { .. }
                | CoordinatorToConnectionInner::AnswerRequest { .. }
                | CoordinatorToConnectionInner::OpenOutNotifications { .. }
                | CoordinatorToConnectionInner::CloseOutNotifications { .. }
                | CoordinatorToConnectionInner::QueueNotification { .. },
                SingleStreamConnectionTaskInner::Handshake { .. }
                | SingleStreamConnectionTaskInner::ShutdownAcked { .. },
            ) => unreachable!(),
            (
                CoordinatorToConnectionInner::AcceptInbound { .. }
                | CoordinatorToConnectionInner::RejectInbound { .. }
                | CoordinatorToConnectionInner::SetMaxProtocolNameLen { .. }
                | CoordinatorToConnectionInner::AcceptInNotifications { .. }
                | CoordinatorToConnectionInner::RejectInNotifications { .. }
                | CoordinatorToConnectionInner::CloseInNotifications { .. }
                | CoordinatorToConnectionInner::StartRequest { .. }
                | CoordinatorToConnectionInner::AnswerRequest { .. }
                | CoordinatorToConnectionInner::OpenOutNotifications { .. }
                | CoordinatorToConnectionInner::CloseOutNotifications { .. }
                | CoordinatorToConnectionInner::QueueNotification { .. },
                SingleStreamConnectionTaskInner::ShutdownWaitingAck { .. },
            )
            | (
                CoordinatorToConnectionInner::StartShutdown,
                SingleStreamConnectionTaskInner::ShutdownWaitingAck {
                    initiator: ShutdownInitiator::Api | ShutdownInitiator::Remote,
                },
            ) => {
                // There might still be some messages coming from the coordinator after the
                // connection task has sent a message indicating that it has shut down. This is
                // due to the concurrent nature of the API and doesn't indicate a bug. These
                // messages are simply ignored by the connection task.
            }
            (
                CoordinatorToConnectionInner::ShutdownFinishedAck,
                SingleStreamConnectionTaskInner::ShutdownWaitingAck { initiator },
            ) => {
                self.connection = SingleStreamConnectionTaskInner::ShutdownAcked {
                    initiator: *initiator,
                };
            }
            (
                CoordinatorToConnectionInner::StartShutdown,
                SingleStreamConnectionTaskInner::ShutdownWaitingAck {
                    initiator: ShutdownInitiator::Coordinator,
                    ..
                }
                | SingleStreamConnectionTaskInner::ShutdownAcked { .. },
            ) => unreachable!(),
            (CoordinatorToConnectionInner::ShutdownFinishedAck, _) => unreachable!(),
            (_, SingleStreamConnectionTaskInner::Poisoned) => unreachable!(),
        }
    }

    /// Sets the state of the connection to "reset".
    ///
    /// This should be called if the remote abruptly closes the connection, such as with a TCP/IP
    /// RST flag.
    ///
    /// After this function has been called, it is illegal to call
    /// [`SingleStreamConnectionTask::read_write`] or [`SingleStreamConnectionTask::reset`] again.
    ///
    /// Calling this function might have generated messages for the coordinator.
    /// [`SingleStreamConnectionTask::pull_message_to_coordinator`] should be called afterwards in
    /// order to process these messages.
    ///
    /// # Panic
    ///
    /// Panics if [`SingleStreamConnectionTask::reset`] has been called in the past.
    ///
    pub fn reset(&mut self) {
        match self.connection {
            SingleStreamConnectionTaskInner::ShutdownWaitingAck {
                initiator: ShutdownInitiator::Api,
            }
            | SingleStreamConnectionTaskInner::ShutdownAcked {
                initiator: ShutdownInitiator::Api,
            } => {
                // It is illegal to call `reset` a second time.
                panic!()
            }
            SingleStreamConnectionTaskInner::ShutdownWaitingAck { ref mut initiator }
            | SingleStreamConnectionTaskInner::ShutdownAcked { ref mut initiator } => {
                // Mark the initiator as being the API in order to track proper API usage.
                *initiator = ShutdownInitiator::Api;
            }
            _ => {
                self.pending_messages
                    .push_back(ConnectionToCoordinatorInner::StartShutdown(Some(
                        ShutdownCause::RemoteReset,
                    )));
                self.pending_messages
                    .push_back(ConnectionToCoordinatorInner::ShutdownFinished);
                self.connection = SingleStreamConnectionTaskInner::ShutdownWaitingAck {
                    initiator: ShutdownInitiator::Api,
                };
            }
        }
    }

    /// Returns `true` if [`SingleStreamConnectionTask::reset`] has been called in the past.
    pub fn is_reset_called(&self) -> bool {
        matches!(
            self.connection,
            SingleStreamConnectionTaskInner::ShutdownWaitingAck {
                initiator: ShutdownInitiator::Api,
            } | SingleStreamConnectionTaskInner::ShutdownAcked {
                initiator: ShutdownInitiator::Api,
            }
        )
    }

    /// Reads data coming from the connection, updates the internal state machine, and writes data
    /// destined to the connection through the [`ReadWrite`].
    ///
    /// Calling this function might have generated messages for the coordinator.
    /// [`SingleStreamConnectionTask::pull_message_to_coordinator`] should be called afterwards in
    /// order to process these messages.
    ///
    /// # Panic
    ///
    /// Panics if [`SingleStreamConnectionTask::reset`] has been called in the past.
    ///
    pub fn read_write(&mut self, read_write: &mut ReadWrite<TNow>) {
        // There is already at least one pending message. We back-pressure the connection by not
        // performing any reading or writing, as this might generate more messages and open the
        // door for a DoS attack by the remote. As documented, the API user is supposed to pull
        // messages after this function has returned, meaning that they will drain the messages.
        if !self.pending_messages.is_empty() {
            return;
        }

        match mem::replace(
            &mut self.connection,
            SingleStreamConnectionTaskInner::Poisoned,
        ) {
            SingleStreamConnectionTaskInner::Established {
                established,
                mut outbound_substreams_map,
                mut notifications_in_close_acknowledgments,
                mut inbound_negotiated_cancel_acknowledgments,
            } => match established.read_write(read_write) {
                Ok((connection, event)) => {
                    if read_write.is_dead() && read_write.wake_up_after.is_none() {
                        self.pending_messages.push_back(
                            ConnectionToCoordinatorInner::StartShutdown(Some(
                                ShutdownCause::CleanShutdown,
                            )),
                        );
                        self.pending_messages
                            .push_back(ConnectionToCoordinatorInner::ShutdownFinished);
                        self.connection = SingleStreamConnectionTaskInner::ShutdownWaitingAck {
                            initiator: ShutdownInitiator::Remote,
                        };
                        return;
                    }

                    match event {
                        Some(established::Event::NewOutboundSubstreamsForbidden) => {
                            // TODO: handle properly
                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::StartShutdown(Some(
                                    ShutdownCause::CleanShutdown,
                                )),
                            );
                            self.pending_messages
                                .push_back(ConnectionToCoordinatorInner::ShutdownFinished);
                            self.connection = SingleStreamConnectionTaskInner::ShutdownWaitingAck {
                                initiator: ShutdownInitiator::Remote,
                            };
                            return;
                        }
                        Some(established::Event::InboundError(err)) => {
                            self.pending_messages
                                .push_back(ConnectionToCoordinatorInner::InboundError(err));
                        }
                        Some(established::Event::InboundNegotiated { id, protocol_name }) => {
                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::InboundNegotiated {
                                    id,
                                    protocol_name,
                                },
                            );
                        }
                        Some(established::Event::InboundNegotiatedCancel { id, .. }) => {
                            inbound_negotiated_cancel_acknowledgments.insert(id);
                        }
                        Some(established::Event::InboundAcceptedCancel { id, .. }) => {
                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::InboundAcceptedCancel { id },
                            );
                        }
                        Some(established::Event::RequestIn { id, request, .. }) => {
                            self.pending_messages
                                .push_back(ConnectionToCoordinatorInner::RequestIn { id, request });
                        }
                        Some(established::Event::Response {
                            response,
                            user_data,
                            ..
                        }) => {
                            let Some(outer_substream_id) = user_data else {
                                panic!()
                            };
                            outbound_substreams_map.remove(&outer_substream_id).unwrap();
                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::Response {
                                    response,
                                    id: outer_substream_id,
                                },
                            );
                        }
                        Some(established::Event::NotificationsInOpen { id, handshake, .. }) => {
                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::NotificationsInOpen { id, handshake },
                            );
                        }
                        Some(established::Event::NotificationsInOpenCancel { id, .. }) => {
                            notifications_in_close_acknowledgments.push_back(id);
                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::NotificationsInOpenCancel { id },
                            );
                        }
                        Some(established::Event::NotificationIn { id, notification }) => {
                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::NotificationIn { id, notification },
                            );
                        }
                        Some(established::Event::NotificationsInClose { id, outcome, .. }) => {
                            // TODO: only do this if not sent by API user
                            notifications_in_close_acknowledgments.push_back(id);
                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::NotificationsInClose { id, outcome },
                            );
                        }
                        Some(established::Event::NotificationsOutResult { id, result }) => {
                            let (outer_substream_id, result) = match result {
                                Ok(r) => {
                                    let Some(outer_substream_id) = connection[id] else {
                                        panic!()
                                    };
                                    (outer_substream_id, Ok(r))
                                }
                                Err((err, ud)) => {
                                    let Some(outer_substream_id) = ud else {
                                        panic!()
                                    };
                                    outbound_substreams_map.remove(&outer_substream_id);
                                    (outer_substream_id, Err(NotificationsOutErr::Substream(err)))
                                }
                            };

                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::NotificationsOutResult {
                                    id: outer_substream_id,
                                    result,
                                },
                            );
                        }
                        Some(established::Event::NotificationsOutCloseDemanded { id }) => {
                            let Some(outer_substream_id) = connection[id] else {
                                panic!()
                            };
                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::NotificationsOutCloseDemanded {
                                    id: outer_substream_id,
                                },
                            );
                        }
                        Some(established::Event::NotificationsOutReset { user_data, .. }) => {
                            let Some(outer_substream_id) = user_data else {
                                panic!()
                            };
                            outbound_substreams_map.remove(&outer_substream_id);
                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::NotificationsOutReset {
                                    id: outer_substream_id,
                                },
                            );
                        }
                        Some(established::Event::PingOutSuccess { ping_time }) => {
                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::PingOutSuccess { ping_time },
                            );
                        }
                        Some(established::Event::PingOutFailed) => {
                            self.pending_messages
                                .push_back(ConnectionToCoordinatorInner::PingOutFailed);
                        }
                        Some(established::Event::BitswapIn { id, message }) => {
                            self.pending_messages
                                .push_back(ConnectionToCoordinatorInner::BitswapIn { id, message });
                        }
                        None => {}
                    }

                    self.connection = SingleStreamConnectionTaskInner::Established {
                        established: connection,
                        outbound_substreams_map,
                        notifications_in_close_acknowledgments,
                        inbound_negotiated_cancel_acknowledgments,
                    };
                }
                Err(err) => {
                    self.pending_messages
                        .push_back(ConnectionToCoordinatorInner::StartShutdown(Some(
                            ShutdownCause::ProtocolError(err),
                        )));
                    self.pending_messages
                        .push_back(ConnectionToCoordinatorInner::ShutdownFinished);
                    self.connection = SingleStreamConnectionTaskInner::ShutdownWaitingAck {
                        initiator: ShutdownInitiator::Remote,
                    };
                }
            },

            SingleStreamConnectionTaskInner::Handshake {
                mut handshake,
                randomness_seed,
                timeout,
                max_inbound_substreams,
                substreams_capacity,
                max_protocol_name_len,
                ping_protocol,
            } => {
                // Check that the handshake isn't taking too long.
                //
                // Note that we check this condition before looking into the incoming data,
                // and it is possible for the buffers to contain the data that leads to the
                // handshake being finished. If that is the case, however, it is impossible to
                // know whether this data arrived before or after the timeout.
                // Whether to put this check before or after reading the buffer is a choice
                // between having false negatives or having false positives for the timeout.
                // We are more strict than necessary by having the check before, but this
                // guarantees that no horrendously slow connections can accidentally make their
                // way through.
                if timeout < read_write.now {
                    self.pending_messages
                        .push_back(ConnectionToCoordinatorInner::StartShutdown(Some(
                            ShutdownCause::HandshakeTimeout,
                        )));
                    self.pending_messages
                        .push_back(ConnectionToCoordinatorInner::ShutdownFinished);
                    self.connection = SingleStreamConnectionTaskInner::ShutdownWaitingAck {
                        initiator: ShutdownInitiator::Remote,
                    };
                    return;
                }

                loop {
                    let (read_before, written_before) =
                        (read_write.read_bytes, read_write.write_bytes_queued);

                    let result = match handshake.read_write(read_write) {
                        Ok(rw) => rw,
                        Err(err) => {
                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::StartShutdown(Some(
                                    ShutdownCause::HandshakeError(err),
                                )),
                            );
                            self.pending_messages
                                .push_back(ConnectionToCoordinatorInner::ShutdownFinished);
                            self.connection = SingleStreamConnectionTaskInner::ShutdownWaitingAck {
                                initiator: ShutdownInitiator::Remote,
                            };
                            return;
                        }
                    };

                    match result {
                        single_stream_handshake::Handshake::Healthy(updated_handshake)
                            if (read_before, written_before)
                                == (read_write.read_bytes, read_write.write_bytes_queued) =>
                        {
                            // `read_write()` should be called again as soon as possible
                            // after `timeout`.
                            read_write.wake_up_after(&timeout);
                            self.connection = SingleStreamConnectionTaskInner::Handshake {
                                handshake: updated_handshake,
                                randomness_seed,
                                timeout,
                                max_inbound_substreams,
                                substreams_capacity,
                                max_protocol_name_len,
                                ping_protocol,
                            };
                            break;
                        }
                        single_stream_handshake::Handshake::Healthy(updated_handshake) => {
                            handshake = updated_handshake;
                        }
                        single_stream_handshake::Handshake::Success {
                            remote_peer_id,
                            connection,
                        } => {
                            self.pending_messages.push_back(
                                ConnectionToCoordinatorInner::HandshakeFinished(remote_peer_id),
                            );

                            self.connection = SingleStreamConnectionTaskInner::Established {
                                established: connection.into_connection(established::Config {
                                    max_inbound_substreams,
                                    substreams_capacity,
                                    max_protocol_name_len,
                                    randomness_seed,
                                    ping_protocol: ping_protocol.to_string(), // TODO: cloning :-/
                                    ping_interval: Duration::from_secs(20),   // TODO: hardcoded
                                    ping_timeout: Duration::from_secs(10),    // TODO: hardcoded
                                    first_out_ping: read_write.now.clone() + Duration::from_secs(2), // TODO: hardcoded
                                }),
                                outbound_substreams_map:
                                    hashbrown::HashMap::with_capacity_and_hasher(
                                        0,
                                        Default::default(),
                                    ), // TODO: capacity?
                                notifications_in_close_acknowledgments: VecDeque::with_capacity(4),
                                inbound_negotiated_cancel_acknowledgments:
                                    hashbrown::HashSet::with_capacity_and_hasher(
                                        2,
                                        Default::default(),
                                    ),
                            };
                            break;
                        }
                    }
                }
            }

            c @ (SingleStreamConnectionTaskInner::ShutdownWaitingAck {
                initiator: ShutdownInitiator::Coordinator | ShutdownInitiator::Remote,
            }
            | SingleStreamConnectionTaskInner::ShutdownAcked {
                initiator: ShutdownInitiator::Coordinator | ShutdownInitiator::Remote,
            }) => {
                // The user might legitimately call this function after the connection has
                // already shut down. In that case, just do nothing.
                self.connection = c;

                // This might have been done already during the shutdown process, but we do it
                // again just in case.
                read_write.close_write();
            }

            SingleStreamConnectionTaskInner::ShutdownWaitingAck {
                initiator: ShutdownInitiator::Api,
            }
            | SingleStreamConnectionTaskInner::ShutdownAcked {
                initiator: ShutdownInitiator::Api,
            } => {
                // As documented, it is illegal to call this function after calling `reset()`.
                panic!()
            }

            SingleStreamConnectionTaskInner::Poisoned => unreachable!(),
        }
    }
}
