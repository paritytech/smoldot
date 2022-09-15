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
        connection::{established, noise},
        read_write::ReadWrite,
    },
    ConfigRequestResponse, ConnectionToCoordinator, ConnectionToCoordinatorInner,
    CoordinatorToConnection, CoordinatorToConnectionInner, NotificationsOutErr, OverlayNetwork,
    PeerId, ShutdownCause, SubstreamId,
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
    /// Connection is still in its handshake phase.
    Handshake {
        /// Substream that has been opened to perform the handshake, if any.
        opened_substream: Option<TSubId>,

        /// Noise handshake in progress. Always `Some`, except to be temporarily extracted.
        handshake: Option<noise::HandshakeInProgress>,

        /// State machine used once the connection has been established. Unused during the
        /// handshake, but created ahead of time. Always `Some`, except to be temporarily
        /// extracted.
        established: Option<established::MultiStream<TNow, TSubId, SubstreamId, ()>>,
    },

    /// Connection has been fully established.
    Established {
        // TODO: user data of request redundant with the substreams mapping below
        established: established::MultiStream<TNow, TSubId, SubstreamId, ()>,

        /// If `Some`, contains the substream that was used for the handshake. This substream
        /// is meant to be closed as soon as possible.
        handshake_substream: Option<TSubId>,

        /// If `Some`, then no `HandshakeFinished` message has been sent back yet.
        handshake_finished_message_to_send: Option<PeerId>,

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
        now: TNow,
        max_inbound_substreams: usize,
        noise_key: Arc<noise::NoiseKey>,
        notification_protocols: Arc<[OverlayNetwork]>,
        request_response_protocols: Arc<[ConfigRequestResponse]>,
        ping_protocol: Arc<str>,
    ) -> Self {
        MultiStreamConnectionTask {
            connection: MultiStreamConnectionTaskInner::Handshake {
                handshake: Some(noise::HandshakeInProgress::new(&noise_key, true)), // TODO: is_initiator?
                opened_substream: None,
                established: Some(established::MultiStream::new(established::Config {
                    notifications_protocols: notification_protocols
                        .iter()
                        .map(|net| established::ConfigNotifications {
                            name: net.config.protocol_name.clone(), // TODO: clone :-/
                            max_handshake_size: net.config.max_handshake_size,
                            max_notification_size: net.config.max_notification_size,
                        })
                        .collect(),
                    request_protocols: request_response_protocols.to_vec(), // TODO: overhead
                    max_inbound_substreams,
                    randomness_seed,
                    ping_protocol: ping_protocol.to_string(), // TODO: cloning :-/
                    ping_interval: Duration::from_secs(20),   // TODO: hardcoded
                    ping_timeout: Duration::from_secs(10),    // TODO: hardcoded
                    first_out_ping: now + Duration::from_secs(2), // TODO: hardcoded
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
            MultiStreamConnectionTaskInner::Handshake { .. } => (Some(self), None),
            MultiStreamConnectionTaskInner::Established {
                established,
                outbound_substreams_map,
                outbound_substreams_reverse,
                handshake_finished_message_to_send,
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
                    ..
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
                    ..
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
                    ..
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
                CoordinatorToConnectionInner::AcceptInNotifications { .. }
                | CoordinatorToConnectionInner::RejectInNotifications { .. }
                | CoordinatorToConnectionInner::StartRequest { .. }
                | CoordinatorToConnectionInner::AnswerRequest { .. }
                | CoordinatorToConnectionInner::OpenOutNotifications { .. }
                | CoordinatorToConnectionInner::CloseOutNotifications { .. }
                | CoordinatorToConnectionInner::QueueNotification { .. },
                MultiStreamConnectionTaskInner::Handshake { .. }
                | MultiStreamConnectionTaskInner::ShutdownAcked { .. },
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
            MultiStreamConnectionTaskInner::Handshake {
                opened_substream: ref mut opened_substream @ None,
                ..
            } if !inbound => {
                *opened_substream = Some(id);
            }
            MultiStreamConnectionTaskInner::Handshake { .. } => {
                // TODO: protocol has been violated, reset the connection?
            }
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.add_substream(id, inbound)
            }
            MultiStreamConnectionTaskInner::ShutdownAcked { .. }
            | MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. } => {
                // TODO: reset the substream or something?
            }
        }
    }

    /// Returns a list of substreams that the state machine would like to see processed. The user
    /// is encouraged to call [`MultiStreamConnectionTask::substream_read_write`] with this list of
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
            MultiStreamConnectionTaskInner::Handshake {
                opened_substream: Some(opened_substream),
                handshake,
                ..
            } => {
                let iter = if handshake.as_ref().unwrap().ready_to_write() {
                    Some(opened_substream)
                } else {
                    None
                }
                .into_iter();
                either::Right(either::Left(iter))
            }
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                // Note that the handshake substream is never ready as it never has anything
                // to write after the end of the handshake.
                either::Left(established.ready_substreams())
            }
            MultiStreamConnectionTaskInner::Handshake {
                opened_substream: None,
                ..
            }
            | MultiStreamConnectionTaskInner::ShutdownAcked { .. }
            | MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. } => {
                either::Right(either::Right(iter::empty()))
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
                opened_substream: Some(opened_substream),
                ..
            } if opened_substream == substream_id => {
                // TODO: the handshake has failed, kill the connection?
            }
            MultiStreamConnectionTaskInner::Handshake { .. }
            | MultiStreamConnectionTaskInner::ShutdownAcked { .. }
            | MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. } => {
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
            MultiStreamConnectionTaskInner::Handshake {
                handshake,
                opened_substream,
                established,
            } if opened_substream
                .as_ref()
                .map_or(false, |s| s == substream_id) =>
            {
                // TODO: check the handshake timeout
                match handshake.take().unwrap().read_write(read_write) {
                    Ok(noise::NoiseHandshake::InProgress(handshake_update)) => {
                        *handshake = Some(handshake_update);
                        false
                    }
                    Err(_err) => todo!(), // TODO: /!\
                    Ok(noise::NoiseHandshake::Success {
                        cipher: _,
                        remote_peer_id,
                    }) => {
                        // The handshake has succeeded and we will transition into "established"
                        // mode.
                        // However the rest of the body of this function still needs to deal with
                        // the substream used for the handshake.
                        // We close the writing side. If the reading side is closed, we indicate
                        // that the substream is dead. If the reading side is still open, we
                        // indicate that it's not dead and store it in the state machine while
                        // waiting for it to be closed by the remote.
                        read_write.close_write();
                        let handshake_substream_still_open = read_write.incoming_buffer.is_some();

                        self.connection = MultiStreamConnectionTaskInner::Established {
                            established: established.take().unwrap(),
                            handshake_finished_message_to_send: Some(remote_peer_id),
                            handshake_substream: if handshake_substream_still_open {
                                Some(opened_substream.take().unwrap())
                            } else {
                                None
                            },
                            outbound_substreams_map: hashbrown::HashMap::with_capacity_and_hasher(
                                0,
                                Default::default(),
                            ),
                            outbound_substreams_reverse:
                                hashbrown::HashMap::with_capacity_and_hasher(0, Default::default()),
                        };

                        !handshake_substream_still_open
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
                if read_write.incoming_buffer.is_none() {
                    *handshake_substream = None;
                    true
                } else {
                    false
                }
            }
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.substream_read_write(substream_id, read_write)
            }
            MultiStreamConnectionTaskInner::Handshake { .. }
            | MultiStreamConnectionTaskInner::ShutdownAcked { .. }
            | MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. } => {
                // TODO: panic if substream id invalid?
                true
            }
        }
    }
}
