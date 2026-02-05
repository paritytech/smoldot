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
        connection::{established, noise, webrtc_framing},
        read_write::ReadWrite,
    },
    BitswapOutOpenErr, ConnectionToCoordinator, ConnectionToCoordinatorInner,
    CoordinatorToConnection, CoordinatorToConnectionInner, NotificationsOutErr, PeerId,
    ShutdownCause, SubstreamFate, SubstreamId,
};

use alloc::{collections::VecDeque, string::ToString as _, sync::Arc};
use core::{
    hash::Hash,
    ops::{Add, Sub},
    time::Duration,
};

/// State machine dedicated to a single multi-stream connection.
pub struct MultiStreamConnectionTask<TNow, TSubId> {
    connection: MultiStreamConnectionTaskInner<TNow, TSubId>,
}
enum MultiStreamConnectionTaskInner<TNow, TSubId> {
    /// Connection is still in its handshake phase.
    Handshake {
        /// Substream that has been opened to perform the handshake, if any.
        opened_substream: Option<(TSubId, webrtc_framing::WebRtcFraming)>,

        /// Noise handshake in progress. Always `Some`, except to be temporarily extracted.
        handshake: Option<noise::HandshakeInProgress>,

        /// Other substreams, besides [`MultiStreamConnectionTaskInner::Handshake::opened_substream`],
        /// that have been opened. For each substream, contains a boolean indicating whether the
        /// substream is outbound (`true`) or inbound (`false`).
        ///
        /// Due to the asynchronous nature of the protocol, it is not a logic error to open
        /// additional substreams before the handshake has finished. The remote might think that
        /// the handshake has finished while the local node hasn't finished processing it yet.
        ///
        /// These substreams aren't processed as long as the handshake hasn't finished. It is,
        /// however, important to remember that substreams have been opened.
        extra_open_substreams: hashbrown::HashMap<TSubId, bool, fnv::FnvBuildHasher>,

        /// State machine used once the connection has been established. Unused during the
        /// handshake, but created ahead of time. Always `Some`, except to be temporarily
        /// extracted.
        established: Option<established::MultiStream<TNow, TSubId, Option<SubstreamId>>>,
    },

    /// Connection has been fully established.
    Established {
        established: established::MultiStream<TNow, TSubId, Option<SubstreamId>>,

        /// If `Some`, contains the substream that was used for the handshake. This substream
        /// is meant to be closed as soon as possible.
        handshake_substream: Option<TSubId>,

        /// If `Some`, then no `HandshakeFinished` message has been sent back yet.
        handshake_finished_message_to_send: Option<PeerId>,

        /// Because outgoing substream ids are assigned by the coordinator, we maintain a mapping
        /// of the "outer ids" to "inner ids".
        outbound_substreams_map:
            hashbrown::HashMap<SubstreamId, established::SubstreamId, fnv::FnvBuildHasher>,

        /// After a [`ConnectionToCoordinatorInner::NotificationsInOpenCancel`] or a
        /// [`ConnectionToCoordinatorInner::NotificationsInClose`] is emitted, an
        /// entry is added to this list. If the coordinator accepts or refuses a substream in this
        /// list, or closes a substream in this list, the acceptance/refusal/closing is dismissed.
        // TODO: this works only because SubstreamIds aren't reused
        notifications_in_close_acknowledgments:
            hashbrown::HashSet<established::SubstreamId, fnv::FnvBuildHasher>,

        /// Messages about inbound accept cancellations to send back.
        inbound_accept_cancel_events: VecDeque<established::SubstreamId>,
    },

    /// Connection has finished its shutdown. A [`ConnectionToCoordinatorInner::ShutdownFinished`]
    /// message has been sent and is waiting to be acknowledged.
    ShutdownWaitingAck {
        /// What has initiated the shutdown.
        initiator: ShutdownInitiator,

        /// `None` if the [`ConnectionToCoordinatorInner::StartShutdown`] message has already
        /// been sent to the coordinator. `Some` if the message hasn't been sent yet.
        start_shutdown_message_to_send: Option<Option<ShutdownCause>>,

        /// `true` if the [`ConnectionToCoordinatorInner::ShutdownFinished`] message has already
        /// been sent to the coordinator.
        shutdown_finish_message_sent: bool,
    },

    /// Connection has finished its shutdown and its shutdown has been acknowledged. There is
    /// nothing more to do except stop the connection task.
    ShutdownAcked {
        /// What has initiated the shutdown.
        initiator: ShutdownInitiator,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ShutdownInitiator {
    /// The coordinator sent a [`CoordinatorToConnectionInner::StartShutdown`] message.
    Coordinator,
    /// [`MultiStreamConnectionTask::reset`] has been called.
    Api,
}

impl<TNow, TSubId> MultiStreamConnectionTask<TNow, TSubId>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
    TSubId: Clone + PartialEq + Eq + Hash,
{
    // Note that the parameters of this function are a bit rough and undocumented, as this is
    // a function only called from the parent module.
    pub(super) fn new(
        randomness_seed: [u8; 32],
        when_connection_start: TNow,
        handshake: noise::HandshakeInProgress,
        max_inbound_substreams: usize,
        substreams_capacity: usize,
        max_protocol_name_len: usize,
        ping_protocol: Arc<str>,
    ) -> Self {
        MultiStreamConnectionTask {
            connection: MultiStreamConnectionTaskInner::Handshake {
                // TODO: the handshake doesn't have a timeout
                handshake: Some(handshake),
                opened_substream: None,
                extra_open_substreams: hashbrown::HashMap::with_capacity_and_hasher(
                    0,
                    Default::default(),
                ),
                established: Some(established::MultiStream::webrtc(established::Config {
                    max_inbound_substreams,
                    substreams_capacity,
                    max_protocol_name_len,
                    randomness_seed,
                    ping_protocol: ping_protocol.to_string(), // TODO: cloning :-/
                    ping_interval: Duration::from_secs(20),   // TODO: hardcoded
                    ping_timeout: Duration::from_secs(10),    // TODO: hardcoded
                    first_out_ping: when_connection_start, // TODO: only start the ping after the Noise handshake has ended
                })),
            },
        }
    }

    /// Pulls a message to send back to the coordinator.
    ///
    /// This function takes ownership of `self` and optionally yields it back. If the first
    /// option contains `None`, then no more message will be generated and the
    /// [`MultiStreamConnectionTask`] has vanished. This will happen after the connection has been
    /// shut down or reset.
    /// It is possible for `self` to not be yielded back even if substreams are still open, in
    /// which case the API user should abruptly reset the connection, for example by sending a
    /// TCP RST flag.
    ///
    /// If any message is returned, it is the responsibility of the API user to send it to the
    /// coordinator.
    /// Do not attempt to buffer the message being returned, as it would work against the
    /// back-pressure strategy used internally. As soon as a message is returned, it should be
    /// delivered. If the coordinator is busy at the moment a message should be delivered, then
    /// the entire thread of execution dedicated to this [`MultiStreamConnectionTask`] should be
    /// paused until the coordinator is ready and the message delivered.
    ///
    /// Messages aren't generated spontaneously. In other words, you don't need to periodically
    /// call this function just in case there's a new message. Messages are always generated after
    /// [`MultiStreamConnectionTask::substream_read_write`],
    /// [`MultiStreamConnectionTask::add_substream`], or [`MultiStreamConnectionTask::reset`]
    /// has been called. Multiple messages can happen in a row.
    ///
    /// Because this function frees space in a buffer, processing substreams again after it
    /// has returned might read/write more data and generate an event again. In other words,
    /// the API user should call [`MultiStreamConnectionTask::substream_read_write`] and
    /// [`MultiStreamConnectionTask::pull_message_to_coordinator`] repeatedly in a loop until no
    /// more message is generated.
    pub fn pull_message_to_coordinator(
        mut self,
    ) -> (Option<Self>, Option<ConnectionToCoordinator>) {
        match &mut self.connection {
            MultiStreamConnectionTaskInner::Handshake { .. } => (Some(self), None),
            MultiStreamConnectionTaskInner::Established {
                established,
                outbound_substreams_map,
                handshake_finished_message_to_send,
                notifications_in_close_acknowledgments,
                inbound_accept_cancel_events,
                ..
            } => {
                if let Some(remote_peer_id) = handshake_finished_message_to_send.take() {
                    return (
                        Some(self),
                        Some(ConnectionToCoordinator {
                            inner: ConnectionToCoordinatorInner::HandshakeFinished(remote_peer_id),
                        }),
                    );
                }

                if let Some(substream_id) = inbound_accept_cancel_events.pop_front() {
                    return (
                        Some(self),
                        Some(ConnectionToCoordinator {
                            inner: ConnectionToCoordinatorInner::InboundAcceptedCancel {
                                id: substream_id,
                            },
                        }),
                    );
                }

                let event = match established.pull_event() {
                    Some(established::Event::NewOutboundSubstreamsForbidden) => {
                        // TODO: handle properly
                        self.connection = MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                            start_shutdown_message_to_send: Some(None),
                            shutdown_finish_message_sent: false,
                            initiator: ShutdownInitiator::Coordinator,
                        };
                        Some(ConnectionToCoordinatorInner::StartShutdown(None))
                    }
                    Some(established::Event::InboundError(err)) => {
                        Some(ConnectionToCoordinatorInner::InboundError(err))
                    }
                    Some(established::Event::InboundNegotiated { id, protocol_name }) => {
                        Some(ConnectionToCoordinatorInner::InboundNegotiated { id, protocol_name })
                    }
                    Some(established::Event::InboundNegotiatedCancel { id, .. }) => {
                        notifications_in_close_acknowledgments.insert(id);
                        None
                    }
                    Some(established::Event::InboundAcceptedCancel { id, .. }) => {
                        Some(ConnectionToCoordinatorInner::InboundAcceptedCancel { id })
                    }
                    Some(established::Event::RequestIn { id, request, .. }) => {
                        Some(ConnectionToCoordinatorInner::RequestIn { id, request })
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
                        Some(ConnectionToCoordinatorInner::Response {
                            response,
                            id: outer_substream_id,
                        })
                    }
                    Some(established::Event::NotificationsInOpen { id, handshake, .. }) => {
                        Some(ConnectionToCoordinatorInner::NotificationsInOpen { id, handshake })
                    }
                    Some(established::Event::NotificationsInOpenCancel { id, .. }) => {
                        notifications_in_close_acknowledgments.insert(id);
                        Some(ConnectionToCoordinatorInner::NotificationsInOpenCancel { id })
                    }
                    Some(established::Event::NotificationIn { id, notification }) => {
                        Some(ConnectionToCoordinatorInner::NotificationIn { id, notification })
                    }
                    Some(established::Event::NotificationsInClose { id, outcome, .. }) => {
                        notifications_in_close_acknowledgments.insert(id);
                        Some(ConnectionToCoordinatorInner::NotificationsInClose { id, outcome })
                    }
                    Some(established::Event::NotificationsOutResult { id, result }) => {
                        let (outer_substream_id, result) = match result {
                            Ok(r) => {
                                let Some(outer_substream_id) = established[id] else {
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

                        Some(ConnectionToCoordinatorInner::NotificationsOutResult {
                            id: outer_substream_id,
                            result,
                        })
                    }
                    Some(established::Event::NotificationsOutCloseDemanded { id }) => {
                        let Some(outer_substream_id) = established[id] else {
                            panic!()
                        };
                        Some(
                            ConnectionToCoordinatorInner::NotificationsOutCloseDemanded {
                                id: outer_substream_id,
                            },
                        )
                    }
                    Some(established::Event::NotificationsOutReset { user_data, .. }) => {
                        let Some(outer_substream_id) = user_data else {
                            panic!()
                        };
                        outbound_substreams_map.remove(&outer_substream_id);
                        Some(ConnectionToCoordinatorInner::NotificationsOutReset {
                            id: outer_substream_id,
                        })
                    }
                    Some(established::Event::BitswapInOpen { id }) => {
                        Some(ConnectionToCoordinatorInner::BitswapInOpen { id })
                    }
                    Some(established::Event::BitswapIn { id, message }) => {
                        Some(ConnectionToCoordinatorInner::BitswapIn { id, message })
                    }
                    Some(established::Event::BitswapInClose { id, outcome }) => {
                        // TODO: Notifications protocol acknowledges close here. Might be not
                        // relevant.
                        Some(ConnectionToCoordinatorInner::BitswapInClose { id, outcome })
                    }
                    Some(established::Event::BitswapOutOpenResult { id, result }) => {
                        let (outer_substream_id, result) = match result {
                            Ok(r) => {
                                let Some(outer_substream_id) = established[id] else {
                                    panic!()
                                };

                                (outer_substream_id, Ok(r))
                            }
                            Err((err, ud)) => {
                                let Some(outer_substream_id) = ud else {
                                    panic!()
                                };
                                outbound_substreams_map.remove(&outer_substream_id);

                                (outer_substream_id, Err(BitswapOutOpenErr::Substream(err)))
                            }
                        };

                        Some(ConnectionToCoordinatorInner::BitswapOutOpenResult {
                            id: outer_substream_id,
                            result,
                        })
                    }
                    Some(established::Event::BitswapOutClose {
                        id: _,
                        error,
                        user_data,
                    }) => {
                        let Some(outer_substream_id) = user_data else {
                            panic!()
                        };
                        outbound_substreams_map.remove(&outer_substream_id);

                        Some(ConnectionToCoordinatorInner::BitswapOutClose {
                            id: outer_substream_id,
                            error,
                        })
                    }
                    Some(established::Event::PingOutSuccess { ping_time }) => {
                        Some(ConnectionToCoordinatorInner::PingOutSuccess { ping_time })
                    }
                    Some(established::Event::PingOutFailed) => {
                        Some(ConnectionToCoordinatorInner::PingOutFailed)
                    }
                    None => None,
                };

                (
                    Some(self),
                    event.map(|ev| ConnectionToCoordinator { inner: ev }),
                )
            }
            MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                start_shutdown_message_to_send,
                shutdown_finish_message_sent,
                ..
            } => {
                if let Some(reason) = start_shutdown_message_to_send.take() {
                    debug_assert!(!*shutdown_finish_message_sent);
                    (
                        Some(self),
                        Some(ConnectionToCoordinator {
                            inner: ConnectionToCoordinatorInner::StartShutdown(reason),
                        }),
                    )
                } else if !*shutdown_finish_message_sent {
                    debug_assert!(start_shutdown_message_to_send.is_none());
                    *shutdown_finish_message_sent = true;
                    (
                        Some(self),
                        Some(ConnectionToCoordinator {
                            inner: ConnectionToCoordinatorInner::ShutdownFinished,
                        }),
                    )
                } else {
                    (Some(self), None)
                }
            }
            MultiStreamConnectionTaskInner::ShutdownAcked { .. } => (None, None),
        }
    }

    /// Injects a message that has been pulled from the coordinator.
    ///
    /// Calling this function might generate data to send to the connection. You should call
    /// [`MultiStreamConnectionTask::desired_outbound_substreams`] and
    /// [`MultiStreamConnectionTask::substream_read_write`] after this function has returned.
    pub fn inject_coordinator_message(&mut self, now: &TNow, message: CoordinatorToConnection) {
        match (message.inner, &mut self.connection) {
            (
                CoordinatorToConnectionInner::AcceptInbound {
                    substream_id,
                    inbound_ty,
                },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    notifications_in_close_acknowledgments,
                    inbound_accept_cancel_events,
                    ..
                },
            ) => {
                if !notifications_in_close_acknowledgments.remove(&substream_id) {
                    established.accept_inbound(substream_id, inbound_ty, None);
                } else {
                    inbound_accept_cancel_events.push_back(substream_id)
                }
            }
            (
                CoordinatorToConnectionInner::RejectInbound { substream_id },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    notifications_in_close_acknowledgments,
                    ..
                },
            ) => {
                if !notifications_in_close_acknowledgments.remove(&substream_id) {
                    established.reject_inbound(substream_id);
                }
            }
            (
                CoordinatorToConnectionInner::SetMaxProtocolNameLen { new_max_length },
                MultiStreamConnectionTaskInner::Handshake {
                    established: Some(established),
                    ..
                }
                | MultiStreamConnectionTaskInner::Established { established, .. },
            ) => {
                established.set_max_protocol_name_len(new_max_length);
            }
            (
                CoordinatorToConnectionInner::SetMaxProtocolNameLen { .. },
                MultiStreamConnectionTaskInner::Handshake {
                    established: None, ..
                },
            ) => {
                unreachable!()
            }
            (
                CoordinatorToConnectionInner::StartRequest {
                    protocol_name,
                    request_data,
                    timeout,
                    max_response_size,
                    substream_id,
                },
                MultiStreamConnectionTaskInner::Established {
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
                    max_handshake_size,
                    protocol_name,
                    handshake,
                    handshake_timeout,
                    substream_id: outer_substream_id,
                },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                let inner_substream_id = established.open_notifications_substream(
                    protocol_name,
                    max_handshake_size,
                    handshake,
                    now.clone() + handshake_timeout,
                    Some(outer_substream_id),
                );

                let _prev_value =
                    outbound_substreams_map.insert(outer_substream_id, inner_substream_id);
                debug_assert!(_prev_value.is_none());
            }
            (
                CoordinatorToConnectionInner::CloseOutNotifications { substream_id },
                MultiStreamConnectionTaskInner::Established {
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
                MultiStreamConnectionTaskInner::Established {
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
                CoordinatorToConnectionInner::CloseInBitswap { substream_id },
                MultiStreamConnectionTaskInner::Established { established, .. },
            ) => {
                established.close_in_bitswap_substream(substream_id);
            }
            (
                CoordinatorToConnectionInner::OpenOutBitswap {
                    substream_id: outer_substream_id,
                },
                MultiStreamConnectionTaskInner::Established {
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
                CoordinatorToConnectionInner::QueueBitswapMessage {
                    substream_id,
                    message,
                },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                // It is possible that the remote has closed the outbound bitswap substream while
                // a `QueueBitswapMessage` message was being delivered, or that the API user
                // queued a Bitswap message before the message about the substream being closed was
                // delivered to the coordinator.
                // If that happens, we intentionally silently discard the message, causing the
                // message to not be sent. This is consistent with the guarantees about
                // Bitswap messages delivery that are documented in the public API.
                if let Some(inner_substream_id) = outbound_substreams_map.get(&substream_id) {
                    established.write_bitswap_message_unbounded(*inner_substream_id, message);
                }
            }
            (
                CoordinatorToConnectionInner::CloseOutBitswap { substream_id },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                // It is possible that the remote has closed the outbound Bitswap substream
                // while the `CloseOutBitswap` message was being delivered, or that the API
                // user close the substream before the message about the substream being closed
                // was delivered to the coordinator.
                if let Some(inner_substream_id) = outbound_substreams_map.remove(&substream_id) {
                    established.close_out_bitswap_substream(inner_substream_id);
                }
            }
            (
                CoordinatorToConnectionInner::AnswerRequest {
                    substream_id,
                    response,
                },
                MultiStreamConnectionTaskInner::Established { established, .. },
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
                MultiStreamConnectionTaskInner::Established {
                    established,
                    notifications_in_close_acknowledgments,
                    ..
                },
            ) => {
                if !notifications_in_close_acknowledgments.remove(&substream_id) {
                    established.accept_in_notifications_substream(
                        substream_id,
                        handshake,
                        max_notification_size,
                    );
                }
            }
            (
                CoordinatorToConnectionInner::RejectInNotifications { substream_id },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    notifications_in_close_acknowledgments,
                    ..
                },
            ) => {
                if !notifications_in_close_acknowledgments.remove(&substream_id) {
                    established.reject_in_notifications_substream(substream_id);
                }
            }
            (
                CoordinatorToConnectionInner::CloseInNotifications {
                    substream_id,
                    timeout,
                },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    notifications_in_close_acknowledgments,
                    ..
                },
            ) => {
                if !notifications_in_close_acknowledgments.remove(&substream_id) {
                    established
                        .close_in_notifications_substream(substream_id, now.clone() + timeout);
                }
            }
            (
                CoordinatorToConnectionInner::StartShutdown { .. },
                MultiStreamConnectionTaskInner::Handshake { .. }
                | MultiStreamConnectionTaskInner::Established { .. },
            ) => {
                // TODO: implement proper shutdown
                self.connection = MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                    start_shutdown_message_to_send: Some(None),
                    shutdown_finish_message_sent: false,
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
                | CoordinatorToConnectionInner::QueueNotification { .. }
                | CoordinatorToConnectionInner::CloseInBitswap { .. }
                | CoordinatorToConnectionInner::OpenOutBitswap { .. }
                | CoordinatorToConnectionInner::QueueBitswapMessage { .. }
                | CoordinatorToConnectionInner::CloseOutBitswap { .. },
                MultiStreamConnectionTaskInner::Handshake { .. }
                | MultiStreamConnectionTaskInner::ShutdownAcked { .. },
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
                | CoordinatorToConnectionInner::QueueNotification { .. }
                | CoordinatorToConnectionInner::CloseInBitswap { .. }
                | CoordinatorToConnectionInner::OpenOutBitswap { .. }
                | CoordinatorToConnectionInner::QueueBitswapMessage { .. }
                | CoordinatorToConnectionInner::CloseOutBitswap { .. },
                MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. },
            )
            | (
                CoordinatorToConnectionInner::StartShutdown,
                MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                    initiator: ShutdownInitiator::Api,
                    ..
                },
            ) => {
                // There might still be some messages coming from the coordinator after the
                // connection task has sent a message indicating that it has shut down. This is
                // due to the concurrent nature of the API and doesn't indicate a bug. These
                // messages are simply ignored by the connection task.
            }
            (
                CoordinatorToConnectionInner::ShutdownFinishedAck,
                MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                    start_shutdown_message_to_send: start_shutdown_message_sent,
                    shutdown_finish_message_sent,
                    initiator,
                },
            ) => {
                debug_assert!(
                    start_shutdown_message_sent.is_none() && *shutdown_finish_message_sent
                );
                self.connection = MultiStreamConnectionTaskInner::ShutdownAcked {
                    initiator: *initiator,
                };
            }
            (
                CoordinatorToConnectionInner::StartShutdown,
                MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                    initiator: ShutdownInitiator::Coordinator,
                    ..
                }
                | MultiStreamConnectionTaskInner::ShutdownAcked { .. },
            ) => unreachable!(),
            (CoordinatorToConnectionInner::ShutdownFinishedAck, _) => unreachable!(),
        }
    }

    /// Returns the number of new outbound substreams that the state machine would like to see
    /// opened.
    ///
    /// This value doesn't change automatically over time but only after a call to
    /// [`MultiStreamConnectionTask::substream_read_write`],
    /// [`MultiStreamConnectionTask::inject_coordinator_message`],
    /// [`MultiStreamConnectionTask::add_substream`], or
    /// [`MultiStreamConnectionTask::reset_substream`].
    ///
    /// Note that the user is expected to track the number of substreams that are currently being
    /// opened. For example, if this function returns 2 and there are already 2 substreams
    /// currently being opened, then there is no need to open any additional one.
    pub fn desired_outbound_substreams(&self) -> u32 {
        match &self.connection {
            MultiStreamConnectionTaskInner::Handshake {
                opened_substream, ..
            } => {
                if opened_substream.is_none() {
                    1
                } else {
                    0
                }
            }
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.desired_outbound_substreams()
            }
            MultiStreamConnectionTaskInner::ShutdownAcked { .. }
            | MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. } => 0,
        }
    }

    /// Notifies the state machine that a new substream has been opened.
    ///
    /// `outbound` indicates whether the substream has been opened by the remote (`false`) or
    /// locally (`true`).
    ///
    /// If `outbound` is `true`, then the value returned by
    /// [`MultiStreamConnectionTask::desired_outbound_substreams`] will decrease by one.
    ///
    /// # Panic
    ///
    /// Panics if there already exists a substream with an identical identifier.
    ///
    pub fn add_substream(&mut self, id: TSubId, outbound: bool) {
        match &mut self.connection {
            MultiStreamConnectionTaskInner::Handshake {
                opened_substream: opened_substream @ None,
                ..
            } if outbound => {
                *opened_substream = Some((id, webrtc_framing::WebRtcFraming::new()));
            }
            MultiStreamConnectionTaskInner::Handshake {
                opened_substream,
                extra_open_substreams,
                ..
            } => {
                assert!(
                    opened_substream
                        .as_ref()
                        .map_or(true, |(open, _)| *open != id)
                );
                // TODO: add a limit to the number allowed?
                let _was_in = extra_open_substreams.insert(id, outbound);
                assert!(_was_in.is_none());
            }
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.add_substream(id, outbound)
            }
            MultiStreamConnectionTaskInner::ShutdownAcked { .. }
            | MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. } => {
                // TODO: reset the substream or something?
            }
        }
    }

    /// Sets the state of the connection to "reset".
    ///
    /// This should be called if the remote abruptly closes the connection, such as with a TCP/IP
    /// RST flag.
    ///
    /// After this function has been called, it is illegal to call
    /// [`MultiStreamConnectionTask::substream_read_write`] or
    /// [`MultiStreamConnectionTask::reset`] again.
    ///
    /// Calling this function might have generated messages for the coordinator.
    /// [`MultiStreamConnectionTask::pull_message_to_coordinator`] should be called afterwards in
    /// order to process these messages.
    ///
    /// # Panic
    ///
    /// Panics if [`MultiStreamConnectionTask::reset`] has been called in the past.
    ///
    pub fn reset(&mut self) {
        match self.connection {
            MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                initiator: ShutdownInitiator::Api,
                ..
            }
            | MultiStreamConnectionTaskInner::ShutdownAcked {
                initiator: ShutdownInitiator::Api,
                ..
            } => {
                // It is illegal to call `reset` a second time.
                panic!()
            }
            MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                ref mut initiator, ..
            }
            | MultiStreamConnectionTaskInner::ShutdownAcked {
                ref mut initiator, ..
            } => {
                // Mark the initiator as being the API in order to track proper API usage.
                *initiator = ShutdownInitiator::Api;
            }
            _ => {
                self.connection = MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                    initiator: ShutdownInitiator::Api,
                    shutdown_finish_message_sent: false,
                    start_shutdown_message_to_send: Some(Some(ShutdownCause::RemoteReset)),
                };
            }
        }
    }

    /// Returns `true` if [`MultiStreamConnectionTask::reset`] has been called in the past.
    pub fn is_reset_called(&self) -> bool {
        matches!(
            self.connection,
            MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                initiator: ShutdownInitiator::Api,
                ..
            } | MultiStreamConnectionTaskInner::ShutdownAcked {
                initiator: ShutdownInitiator::Api,
                ..
            }
        )
    }

    /// Immediately destroys the substream with the given identifier.
    ///
    /// The given identifier is now considered invalid by the state machine.
    ///
    /// # Panic
    ///
    /// Panics if there is no substream with that identifier.
    ///
    pub fn reset_substream(&mut self, substream_id: &TSubId) {
        match &mut self.connection {
            MultiStreamConnectionTaskInner::Established {
                handshake_substream,
                ..
            } if handshake_substream
                .as_ref()
                .map_or(false, |s| s == substream_id) =>
            {
                *handshake_substream = None;
            }
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.reset_substream(substream_id)
            }
            MultiStreamConnectionTaskInner::Handshake {
                opened_substream: Some((opened_substream, _)),
                ..
            } if opened_substream == substream_id => {
                // TODO: the handshake has failed, kill the connection?
            }
            MultiStreamConnectionTaskInner::Handshake {
                extra_open_substreams,
                ..
            } => {
                let _was_in = extra_open_substreams.remove(substream_id).is_some();
                assert!(_was_in);
            }
            MultiStreamConnectionTaskInner::ShutdownAcked { .. }
            | MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. } => {
                // TODO: panic if substream id invalid?
            }
        }
    }

    /// Reads/writes data on the substream.
    ///
    /// If the method returns [`SubstreamFate::Reset`], then the substream is now considered dead
    /// according to the state machine and its identifier is now invalid. If the reading or
    /// writing side of the substream was still open, then the user should reset that substream.
    ///
    /// In the case of a WebRTC connection, the [`ReadWrite::incoming_buffer`] and
    /// [`ReadWrite::write_bytes_queueable`] must always be `Some`.
    ///
    /// # Panic
    ///
    /// Panics if there is no substream with that identifier.
    /// Panics if this is a WebRTC connection, and the reading or writing side is closed.
    ///
    #[must_use]
    pub fn substream_read_write(
        &mut self,
        substream_id: &TSubId,
        read_write: &mut ReadWrite<TNow>,
    ) -> SubstreamFate {
        // In WebRTC, the reading and writing sides are never closed.
        // Note that the `established::MultiStream` state machine also performs this check, but
        // we do it here again because we're not necessarily in the ̀`established` state.
        assert!(
            read_write.expected_incoming_bytes.is_some()
                && read_write.write_bytes_queueable.is_some()
        );

        match &mut self.connection {
            MultiStreamConnectionTaskInner::Handshake {
                handshake,
                opened_substream: Some((opened_handshake_substream, handshake_webrtc_framing)),
                established,
                extra_open_substreams,
            } if opened_handshake_substream == substream_id => {
                // TODO: check the handshake timeout

                // Progress the Noise handshake.
                let handshake_outcome = {
                    // The Noise data is not directly the data of the substream. Instead,
                    // everything is wrapped within a Protobuf frame.
                    let mut with_framing = match handshake_webrtc_framing.read_write(read_write) {
                        Ok(f) => f,
                        Err(_err) => {
                            // TODO: not great for diagnostic to just ignore the error; also, the connection should just reset entirely
                            return SubstreamFate::Reset;
                        }
                    };
                    handshake.take().unwrap().read_write(&mut with_framing)
                };

                match handshake_outcome {
                    Ok(noise::NoiseHandshake::InProgress(handshake_update)) => {
                        *handshake = Some(handshake_update);
                        SubstreamFate::Continue
                    }
                    Err(_err) => return SubstreamFate::Reset, // TODO: /!\
                    Ok(noise::NoiseHandshake::Success {
                        cipher: _,
                        remote_peer_id,
                    }) => {
                        // The handshake has succeeded and we will transition into "established"
                        // mode.
                        let mut established = established.take().unwrap();
                        for (substream_id, outbound) in extra_open_substreams.drain() {
                            established.add_substream(substream_id, outbound);
                        }

                        self.connection = MultiStreamConnectionTaskInner::Established {
                            established,
                            handshake_finished_message_to_send: Some(remote_peer_id),
                            handshake_substream: None, // TODO: do properly
                            outbound_substreams_map: hashbrown::HashMap::with_capacity_and_hasher(
                                0,
                                Default::default(),
                            ),
                            notifications_in_close_acknowledgments:
                                hashbrown::HashSet::with_capacity_and_hasher(2, Default::default()),
                            inbound_accept_cancel_events: VecDeque::with_capacity(2),
                        };

                        // TODO: hacky
                        SubstreamFate::Reset
                    }
                }
            }
            MultiStreamConnectionTaskInner::Established {
                handshake_substream,
                ..
            } if handshake_substream
                .as_ref()
                .map_or(false, |s| s == substream_id) =>
            {
                // Close the writing side. If the reading side is closed, we indicate that the
                // substream is dead. If the reading side is still open, we indicate that it's not
                // dead and simply wait for the remote to close it.
                // TODO: kill the connection if the remote sends more data?
                read_write.close_write();
                if read_write.expected_incoming_bytes.is_none() {
                    *handshake_substream = None;
                    SubstreamFate::Reset
                } else {
                    SubstreamFate::Continue
                }
            }
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.substream_read_write(substream_id, read_write)
            }
            MultiStreamConnectionTaskInner::Handshake {
                extra_open_substreams,
                ..
            } => {
                assert!(extra_open_substreams.contains_key(substream_id));
                // Don't do anything. Don't read or write. Instead we wait for the handshake to
                // be finished.
                SubstreamFate::Continue
            }
            MultiStreamConnectionTaskInner::ShutdownAcked { .. }
            | MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. } => {
                // TODO: panic if substream id invalid?
                SubstreamFate::Reset
            }
        }
    }
}
