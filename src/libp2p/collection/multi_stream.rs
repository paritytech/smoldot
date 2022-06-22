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
    super::{connection::established, read_write::ReadWrite},
    ConfigRequestResponse, ConnectionToCoordinator, ConnectionToCoordinatorInner,
    CoordinatorToConnection, CoordinatorToConnectionInner, NotificationsOutErr, OverlayNetwork,
    SubstreamId,
};

use alloc::{string::ToString as _, sync::Arc};
use core::{
    hash::Hash,
    iter,
    ops::{Add, Sub},
    time::Duration,
};

/// State machine dedicated to a single multi-stream connection.
pub struct MultiStreamConnectionTask<TNow, TSubId> {
    connection: MultiStreamConnectionTaskInner<TNow, TSubId>,
}
enum MultiStreamConnectionTaskInner<TNow, TSubId> {
    /// Connection has been fully established.
    Established {
        // TODO: user data of request redundant with the substreams mapping below
        established: established::MultiStream<TNow, TSubId, SubstreamId, ()>,

        /// Because outgoing substream ids are assigned by the coordinator, we maintain a mapping
        /// of the "outer ids" to "inner ids".
        outbound_substreams_map:
            hashbrown::HashMap<SubstreamId, established::SubstreamId, fnv::FnvBuildHasher>,

        /// Reverse mapping.
        // TODO: could be user datas in established?
        outbound_substreams_reverse:
            hashbrown::HashMap<established::SubstreamId, SubstreamId, fnv::FnvBuildHasher>,
    },

    /// Connection has finished its shutdown. A [`ConnectionToCoordinatorInner::ShutdownFinished`]
    /// message has been sent and is waiting to be acknowledged.
    ShutdownWaitingAck {
        /// If true, [`MultiStreamConnectionTask::reset`] has been called. This doesn't modify any
        /// of the behavior but is used to make sure that the API is used correctly.
        was_api_reset: bool,

        /// `true` if the [`ConnectionToCoordinatorInner::StartShutdown`] message has already
        /// been sent to the coordinator.
        start_shutdown_message_sent: bool,

        /// `true` if the [`ConnectionToCoordinatorInner::ShutdownFinished`] message has already
        /// been sent to the coordinator.
        shutdown_finish_message_sent: bool,
    },

    /// Connection has finished its shutdown and its shutdown has been acknowledged. There is
    /// nothing more to do except stop the connection task.
    ShutdownAcked {
        /// If true, [`MultiStreamConnectionTask::reset`] has been called. This doesn't modify any
        /// of the behavior but is used to make sure that the API is used correctly.
        was_api_reset: bool,
    },
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
        now: TNow,
        notification_protocols: Arc<[OverlayNetwork]>,
        request_response_protocols: Arc<[ConfigRequestResponse]>,
        ping_protocol: Arc<str>,
    ) -> Self {
        MultiStreamConnectionTask {
            connection: MultiStreamConnectionTaskInner::Established {
                established: established::MultiStream::new(established::Config {
                    notifications_protocols: notification_protocols
                        .iter()
                        .flat_map(|net| {
                            let max_handshake_size = net.config.max_handshake_size;
                            let max_notification_size = net.config.max_notification_size;
                            iter::once(&net.config.protocol_name)
                                .chain(net.config.fallback_protocol_names.iter())
                                .map(move |name| {
                                    established::ConfigNotifications {
                                        name: name.clone(), // TODO: cloning :-/
                                        max_handshake_size,
                                        max_notification_size,
                                    }
                                })
                        })
                        .collect(),
                    request_protocols: request_response_protocols.to_vec(), // TODO: overhead
                    randomness_seed,
                    ping_protocol: ping_protocol.to_string(), // TODO: cloning :-/
                    ping_interval: Duration::from_secs(20),   // TODO: hardcoded
                    ping_timeout: Duration::from_secs(10),    // TODO: hardcoded
                    first_out_ping: now + Duration::from_secs(2), // TODO: hardcoded
                }),
                outbound_substreams_map: hashbrown::HashMap::with_capacity_and_hasher(
                    0,
                    Default::default(),
                ), // TODO: capacity?
                outbound_substreams_reverse: hashbrown::HashMap::with_capacity_and_hasher(
                    0,
                    Default::default(),
                ), // TODO: capacity?
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
    /// Because this function frees space in a buffer, calling
    /// [`MultiStreamConnectionTask::ready_substreams`] and processing substreams again after it
    /// has returned might read/write more data and generate an event again. In other words,
    /// the API user should call
    ///  [`MultiStreamConnectionTask::ready_substreams`] and
    /// [`MultiStreamConnectionTask::substream_read_write`], and
    /// [`MultiStreamConnectionTask::pull_message_to_coordinator`] repeatedly in a loop until no
    /// more message is generated.
    pub fn pull_message_to_coordinator(
        mut self,
    ) -> (Option<Self>, Option<ConnectionToCoordinator>) {
        match &mut self.connection {
            MultiStreamConnectionTaskInner::Established {
                established,
                outbound_substreams_map,
                outbound_substreams_reverse,
            } => {
                let event = match established.pull_event() {
                    Some(established::Event::InboundError(err)) => {
                        Some(ConnectionToCoordinatorInner::InboundError(err))
                    }
                    Some(established::Event::RequestIn {
                        id,
                        protocol_index,
                        request,
                    }) => Some(ConnectionToCoordinatorInner::RequestIn {
                        id,
                        protocol_index,
                        request,
                    }),
                    Some(established::Event::Response { id, response, .. }) => {
                        let outer_substream_id = outbound_substreams_reverse.remove(&id).unwrap();
                        outbound_substreams_map.remove(&outer_substream_id).unwrap();
                        Some(ConnectionToCoordinatorInner::Response {
                            response,
                            id: outer_substream_id,
                        })
                    }
                    Some(established::Event::NotificationsInOpen {
                        id,
                        protocol_index,
                        handshake,
                    }) => Some(ConnectionToCoordinatorInner::NotificationsInOpen {
                        id,
                        protocol_index,
                        handshake,
                    }),
                    Some(established::Event::NotificationsInOpenCancel { id, .. }) => {
                        Some(ConnectionToCoordinatorInner::NotificationsInOpenCancel { id })
                    }
                    Some(established::Event::NotificationIn { id, notification }) => {
                        Some(ConnectionToCoordinatorInner::NotificationIn { id, notification })
                    }
                    Some(established::Event::NotificationsInClose { id, outcome, .. }) => {
                        Some(ConnectionToCoordinatorInner::NotificationsInClose { id, outcome })
                    }
                    Some(established::Event::NotificationsOutResult { id, result }) => {
                        let outer_substream_id = *outbound_substreams_reverse.get(&id).unwrap();

                        if result.is_err() {
                            outbound_substreams_map.remove(&outer_substream_id);
                            outbound_substreams_reverse.remove(&id);
                        }

                        Some(ConnectionToCoordinatorInner::NotificationsOutResult {
                            id: outer_substream_id,
                            result: result.map_err(|(err, _)| NotificationsOutErr::Substream(err)),
                        })
                    }
                    Some(established::Event::NotificationsOutCloseDemanded { id }) => {
                        let outer_substream_id = *outbound_substreams_reverse.get(&id).unwrap();
                        Some(
                            ConnectionToCoordinatorInner::NotificationsOutCloseDemanded {
                                id: outer_substream_id,
                            },
                        )
                    }
                    Some(established::Event::NotificationsOutReset { id, .. }) => {
                        let outer_substream_id = outbound_substreams_reverse.remove(&id).unwrap();
                        outbound_substreams_map.remove(&outer_substream_id);
                        Some(ConnectionToCoordinatorInner::NotificationsOutReset {
                            id: outer_substream_id,
                        })
                    }
                    Some(established::Event::PingOutSuccess) => {
                        Some(ConnectionToCoordinatorInner::PingOutSuccess)
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
                start_shutdown_message_sent,
                shutdown_finish_message_sent,
                ..
            } => {
                if !*start_shutdown_message_sent {
                    debug_assert!(!*shutdown_finish_message_sent);
                    *start_shutdown_message_sent = true;
                    (
                        Some(self),
                        Some(ConnectionToCoordinator {
                            inner: ConnectionToCoordinatorInner::StartShutdown,
                        }),
                    )
                } else if !*shutdown_finish_message_sent {
                    debug_assert!(*start_shutdown_message_sent);
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
    /// [`MultiStreamConnectionTask::ready_substreams`] after this function has returned.
    pub fn inject_coordinator_message(&mut self, message: CoordinatorToConnection<TNow>) {
        match (message.inner, &mut self.connection) {
            (
                CoordinatorToConnectionInner::StartRequest {
                    request_data,
                    timeout,
                    protocol_index,
                    substream_id,
                },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    outbound_substreams_reverse,
                },
            ) => {
                let inner_substream_id =
                    established.add_request(protocol_index, request_data, timeout, substream_id);
                let _prev_value = outbound_substreams_map.insert(substream_id, inner_substream_id);
                debug_assert!(_prev_value.is_none());
                let _prev_value =
                    outbound_substreams_reverse.insert(inner_substream_id, substream_id);
                debug_assert!(_prev_value.is_none());
            }
            (
                CoordinatorToConnectionInner::OpenOutNotifications {
                    handshake,
                    now,
                    overlay_network_index,
                    substream_id: outer_substream_id,
                },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    outbound_substreams_reverse,
                },
            ) => {
                let inner_substream_id = established.open_notifications_substream(
                    now,
                    overlay_network_index,
                    handshake,
                    (),
                );

                let _prev_value =
                    outbound_substreams_map.insert(outer_substream_id, inner_substream_id);
                debug_assert!(_prev_value.is_none());
                let _prev_value =
                    outbound_substreams_reverse.insert(inner_substream_id, outer_substream_id);
                debug_assert!(_prev_value.is_none());
            }
            (
                CoordinatorToConnectionInner::CloseOutNotifications { substream_id },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    outbound_substreams_reverse,
                },
            ) => {
                // It is possible that the remote has closed the outbound notification substream
                // while the `CloseOutNotifications` message was being delivered, or that the API
                // user close the substream before the message about the substream being closed
                // was delivered to the coordinator.
                if let Some(inner_substream_id) = outbound_substreams_map.remove(&substream_id) {
                    outbound_substreams_reverse.remove(&inner_substream_id);
                    established.close_notifications_substream(inner_substream_id);
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
                },
                MultiStreamConnectionTaskInner::Established { established, .. },
            ) => {
                // TODO: must verify that the substream is still valid
                established.accept_in_notifications_substream(substream_id, handshake, ());
            }
            (
                CoordinatorToConnectionInner::RejectInNotifications { substream_id },
                MultiStreamConnectionTaskInner::Established { established, .. },
            ) => {
                // TODO: must verify that the substream is still valid
                established.reject_in_notifications_substream(substream_id);
            }
            (
                CoordinatorToConnectionInner::StartShutdown { .. },
                MultiStreamConnectionTaskInner::Established { .. },
            ) => {
                // TODO: implement proper shutdown
                self.connection = MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                    start_shutdown_message_sent: false,
                    shutdown_finish_message_sent: false,
                    was_api_reset: false,
                };
            }
            (
                CoordinatorToConnectionInner::AcceptInNotifications { .. }
                | CoordinatorToConnectionInner::RejectInNotifications { .. }
                | CoordinatorToConnectionInner::StartRequest { .. }
                | CoordinatorToConnectionInner::AnswerRequest { .. }
                | CoordinatorToConnectionInner::OpenOutNotifications { .. }
                | CoordinatorToConnectionInner::CloseOutNotifications { .. }
                | CoordinatorToConnectionInner::QueueNotification { .. },
                MultiStreamConnectionTaskInner::ShutdownAcked { .. },
            ) => unreachable!(),
            (
                CoordinatorToConnectionInner::AcceptInNotifications { .. }
                | CoordinatorToConnectionInner::RejectInNotifications { .. }
                | CoordinatorToConnectionInner::StartRequest { .. }
                | CoordinatorToConnectionInner::AnswerRequest { .. }
                | CoordinatorToConnectionInner::OpenOutNotifications { .. }
                | CoordinatorToConnectionInner::CloseOutNotifications { .. }
                | CoordinatorToConnectionInner::QueueNotification { .. },
                MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. },
            )
            | (
                CoordinatorToConnectionInner::StartShutdown,
                MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                    was_api_reset: true,
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
                    start_shutdown_message_sent,
                    shutdown_finish_message_sent,
                    was_api_reset: was_reset,
                },
            ) => {
                debug_assert!(*start_shutdown_message_sent && *shutdown_finish_message_sent);
                self.connection = MultiStreamConnectionTaskInner::ShutdownAcked {
                    was_api_reset: *was_reset,
                };
            }
            (
                CoordinatorToConnectionInner::StartShutdown,
                MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. }
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
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.desired_outbound_substreams()
            }
            _ => 0,
        }
    }

    /// Notifies the state machine that a new substream has been opened.
    ///
    /// `inbound` indicates whether the substream has been opened by the remote (`true`) or
    /// locally (`false`).
    ///
    /// If `inbound` is `false`, then the value returned by
    /// [`MultiStreamConnectionTask::desired_outbound_substreams`] will decrease by one.
    ///
    /// # Panic
    ///
    /// Panics if there already exists a substream with an identical identifier.
    ///
    pub fn add_substream(&mut self, id: TSubId, inbound: bool) {
        match &mut self.connection {
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.add_substream(id, inbound)
            }
            _ => {
                // TODO: reset the substream or something?
            }
        }
    }

    /// Returns a list of substreams that the state machine would like to see reset. The user is
    /// encouraged to call [`MultiStreamConnectionTask::substream_read_write`] with this list of
    /// substream.
    ///
    /// This value doesn't change automatically over time but only after a call to
    /// [`MultiStreamConnectionTask::substream_read_write`],
    /// [`MultiStreamConnectionTask::inject_coordinator_message`],
    /// [`MultiStreamConnectionTask::add_substream`], or
    /// [`MultiStreamConnectionTask::reset_substream`].
    ///
    /// > **Note**: An example situation is: a notification is queued, which leads to a message
    /// >           being sent to a connection task, which, once injected, leads to a notifications
    /// >           substream being "ready" because it needs to send more data.
    pub fn ready_substreams(&self) -> impl Iterator<Item = &TSubId> {
        match &self.connection {
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                either::Left(established.ready_substreams())
            }
            _ => either::Right(iter::empty()),
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
        // It is illegal to call `reset` a second time. Verify that the user didn't do this.
        if let MultiStreamConnectionTaskInner::ShutdownWaitingAck {
            was_api_reset: true,
            ..
        }
        | MultiStreamConnectionTaskInner::ShutdownAcked {
            was_api_reset: true,
        } = self.connection
        {
            panic!()
        }

        self.connection = MultiStreamConnectionTaskInner::ShutdownWaitingAck {
            was_api_reset: true,
            shutdown_finish_message_sent: false,
            start_shutdown_message_sent: false,
        };
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
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.reset_substream(substream_id)
            }
            _ => {
                // TODO: panic if substream id invalid?
            }
        }
    }

    /// Reads/writes data on the substream.
    ///
    /// If the method returns `true`, then the substream is now considered dead according to the
    /// state machine and its identifier is now invalid. If the reading or writing side of the
    /// substream was still open, then the user should reset that substream.
    ///
    /// # Panic
    ///
    /// Panics if there is no substream with that identifier.
    ///
    // TODO: better return value
    pub fn substream_read_write(
        &mut self,
        substream_id: &TSubId,
        read_write: &'_ mut ReadWrite<'_, TNow>,
    ) -> bool {
        match &mut self.connection {
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.substream_read_write(substream_id, read_write)
            }
            _ => {
                // TODO: panic if substream id invalid?
                true
            }
        }
    }
}
