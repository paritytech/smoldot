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

//! State machine handling a single TCP or WebSocket libp2p connection.
//!
//! # About resources allocation and back-pressure
//!
//! In order to avoid DoS attacks, it is important, in networking code, to make sure that the
//! amount of memory allocated directly or indirectly by a connection stays bounded.
//!
//! The situations in the [`SingleStream`] that lead to an increase in memory consumption are:
//!
//! 1- On incoming or outgoing substreams.
//! 2- When sending a request or receiving a response in a request-response protocol.
//! 3- When sending a notification.
//! 4- When receiving a request and sending back a response.
//! 5- When receiving a notification.
//! // TODO: 6- on Yamux ping frames
//!
//! In order to solve 1-, there exists a maximum number of simultaneous substreams allowed by the
//! protocol, thereby guaranteeing that the memory consumption doesn't exceed a certain bound.
//! Since receiving a request and a response is a one-time process that occupies an entire
//! substream, allocations referenced by points 2- and 4- are also bounded thanks to this limit.
//! Request-response protocols enforce a limit to the size of the request and response, again
//! guaranteeing a bound on the memory consumption.
//!
//! In order to solve 3-, always use [`SingleStream::notification_substream_queued_bytes`] in order
//! to check the current amount of buffered data before calling
//! [`SingleStream::write_notification_unbounded`]. See the documentation of
//! [`SingleStream::write_notification_unbounded`] for more details.
//!
//! In order to solve 5-, // TODO: .
//!

// TODO: expand docs ^

// TODO: consider implementing on top of multi_stream

use super::{
    super::{super::read_write::ReadWrite, noise, yamux},
    Config, Event, SubstreamId, SubstreamIdInner,
    substream::{self, RespondInRequestError},
};

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    fmt,
    num::NonZero,
    ops::{Add, Index, IndexMut, Sub},
    time::Duration,
};
use rand_chacha::rand_core::{RngCore as _, SeedableRng as _};

pub use substream::InboundTy;

/// State machine of a fully-established connection.
pub struct SingleStream<TNow, TSubUd> {
    /// Encryption layer applied directly on top of the incoming data and outgoing data.
    encryption: noise::Noise,

    /// Extra fields. Segregated in order to solve borrowing questions.
    inner: Box<Inner<TNow, TSubUd>>,
}

/// Extra fields. Segregated in order to solve borrowing questions.
struct Inner<TNow, TSubUd> {
    /// State of the various substreams of the connection.
    /// Consists in a collection of substreams, each of which holding a [`substream::Substream`]
    /// object, or `None` if the substream has been reset.
    yamux: yamux::Yamux<TNow, Option<(substream::Substream<TNow>, Option<TSubUd>)>>,

    /// Substream in [`Inner::yamux`] used for outgoing pings.
    ///
    /// Because of the API of [`substream::Substream`] concerning pings, there is no need to
    /// handle situations where the substream fails to negotiate, as this is handled by making
    /// outgoing pings error. This substream is therefore constant.
    ///
    /// It is possible, however, that the remote resets the ping substream. In other words, this
    /// substream might not be found in [`Inner::yamux`]. When that happens, all outgoing pings
    /// are immediately considered as failed.
    outgoing_pings: yamux::SubstreamId,
    /// When to start the next ping attempt.
    next_ping: TNow,
    /// Source of randomness to generate ping payloads.
    ///
    /// Note that we use ChaCha20 because the rest of the code base also uses ChaCha20. This avoids
    /// unnecessary code being included in the binary and reduces the binary size.
    ping_payload_randomness: rand_chacha::ChaCha20Rng,

    /// See [`Config::max_inbound_substreams`].
    max_inbound_substreams: usize,
    /// See [`Config::max_protocol_name_len`].
    max_protocol_name_len: usize,
    /// See [`Config::ping_interval`].
    ping_interval: Duration,
    /// See [`Config::ping_timeout`].
    ping_timeout: Duration,
}

impl<TNow, TSubUd> SingleStream<TNow, TSubUd>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Reads data coming from the socket, updates the internal state machine, and writes data
    /// destined to the socket through the [`ReadWrite`].
    ///
    /// In order to avoid unnecessary memory allocations, only one [`Event`] is returned at a time.
    /// Consequently, this method returns as soon as an event is available, even if the buffers
    /// haven't finished being read. Call this method in a loop until the number of bytes read and
    /// written are both 0, and the returned [`Event`] is `None`.
    ///
    /// If an error is returned, the socket should be entirely shut down.
    // TODO: consider exposing an API more similar to the one of substream::Substream::read_write?
    pub fn read_write(
        mut self,
        read_write: &mut ReadWrite<TNow>,
    ) -> Result<(SingleStream<TNow, TSubUd>, Option<Event<TSubUd>>), Error> {
        // Start any outgoing ping if necessary.
        if read_write.now >= self.inner.next_ping {
            self.inner.next_ping = read_write.now.clone() + self.inner.ping_interval;

            // It might be that the remote has reset the ping substream, in which case the out ping
            // substream no longer exists and we immediately consider the ping as failed.
            if self.inner.yamux.has_substream(self.inner.outgoing_pings) {
                let mut payload = [0u8; 32];
                self.inner.ping_payload_randomness.fill_bytes(&mut payload);
                self.inner.yamux[self.inner.outgoing_pings]
                    .as_mut()
                    .unwrap()
                    .0
                    .queue_ping(&payload, read_write.now.clone(), self.inner.ping_timeout);
                self.inner
                    .yamux
                    .mark_substream_write_ready(self.inner.outgoing_pings);
            } else {
                return Ok((self, Some(Event::PingOutFailed)));
            }
        }
        read_write.wake_up_after(&self.inner.next_ping);

        // If we have both sent and received a GoAway frame, that means that no new substream
        // can be opened. If in addition to this there is no substream in the connection,
        // then we can safely close it as a normal termination.
        // Note that, because we have no guarantee that the remote has received our GoAway
        // frame yet, it is possible to receive requests for new substreams even after having
        // sent the GoAway. Because we close the writing side, it is not possible to indicate
        // to the remote that these new substreams are denied. However, this is not a problem
        // as the remote interprets our GoAway frame as an automatic refusal of all its pending
        // substream requests.
        // TODO: review w.r.t. https://github.com/smol-dot/smoldot/issues/1121
        if (self.inner.yamux.len()
            == if self.inner.yamux.has_substream(self.inner.outgoing_pings) {
                1
            } else {
                0
            })
            && self.inner.yamux.goaway_sent()
            && self.inner.yamux.received_goaway().is_some()
        {
            read_write.close_write();
        }

        // Note that we treat the reading side being closed the same way as no data being
        // received. The fact that the remote has closed their writing side is no different
        // than them leaving their writing side open but no longer send any data at all.
        // The remote is free to close their writing side at any point if it judges that it
        // will no longer need to send anymore data.
        // Note, however, that in principle the remote should have sent a GoAway frame prior
        // to closing their writing side. But this is not something we check or really care
        // about.

        // Pass the `read_write` through the Noise state machine.
        let mut decrypted_read_write = self
            .encryption
            .read_write(read_write)
            .map_err(Error::Noise)?;

        // Pass the Noise decrypted stream through the Yamux state machine.
        let yamux_rw_outcome = self
            .inner
            .yamux
            .read_write(&mut decrypted_read_write)
            .map_err(Error::Yamux)?;

        match yamux_rw_outcome {
            yamux::ReadWriteOutcome::Idle { yamux } => {
                self.inner.yamux = yamux;

                // Nothing happened, and thus there is nothing more to do.
                drop(decrypted_read_write);
                return Ok((self, None));
            }
            yamux::ReadWriteOutcome::IncomingSubstream { mut yamux } => {
                debug_assert!(!yamux.goaway_queued_or_sent());

                // Receive a request from the remote for a new incoming substream.
                // These requests are automatically accepted unless the total limit to the
                // number of substreams has been reached.
                // Note that `num_inbound()` counts substreams that have been closed but not
                // yet removed from the state machine. This can affect the actual limit in a
                // subtle way. At the time of writing of this comment the limit should be
                // properly enforced, however it is not considered problematic if it weren't.
                if yamux.num_inbound() >= self.inner.max_inbound_substreams {
                    // Can only error if there's no incoming substream, which we know for sure
                    // is the case here.
                    yamux
                        .reject_pending_substream()
                        .unwrap_or_else(|_| panic!());
                } else {
                    // Can only error if there's no incoming substream, which we know for sure
                    // is the case here.
                    yamux
                        .accept_pending_substream(Some((
                            substream::Substream::ingoing(self.inner.max_protocol_name_len),
                            None,
                        )))
                        .unwrap_or_else(|_| panic!());
                }

                self.inner.yamux = yamux;

                drop(decrypted_read_write);
                return Ok((self, None));
            }
            yamux::ReadWriteOutcome::ProcessSubstream {
                mut substream_read_write,
            } => {
                // The Yamux state machine needs to process a substream.

                // Temporarily extract the substream's fields to put them back later.
                let (state_machine, mut substream_user_data) =
                    substream_read_write.user_data_mut().take().unwrap();
                let (state_machine_update, event) =
                    state_machine.read_write(substream_read_write.read_write());

                let event_to_yield = event.map(|ev| {
                    Self::pass_through_substream_event(
                        substream_read_write.substream_id(),
                        &mut substream_user_data,
                        ev,
                    )
                });

                match state_machine_update {
                    Some(s) => {
                        *substream_read_write.user_data_mut() = Some((s, substream_user_data));
                        self.inner.yamux = substream_read_write.finish();
                    }
                    None => {
                        self.inner.yamux = substream_read_write.reset();
                    }
                }

                if let Some(event_to_yield) = event_to_yield {
                    drop(decrypted_read_write);
                    return Ok((self, Some(event_to_yield)));
                }
            }
            yamux::ReadWriteOutcome::StreamReset { yamux, .. } => {
                self.inner.yamux = yamux;
                decrypted_read_write.wake_up_asap();
            }
            yamux::ReadWriteOutcome::GoAway { yamux, .. } => {
                self.inner.yamux = yamux;
                drop(decrypted_read_write);
                return Ok((self, Some(Event::NewOutboundSubstreamsForbidden)));
            }
            yamux::ReadWriteOutcome::PingResponse { .. } => {
                // Can only happen if we send out Yamux pings, which we never do.
                unreachable!()
            }
        }

        drop(decrypted_read_write);

        // Substreams that have been closed or reset aren't immediately removed the yamux state
        // machine. They must be removed manually, which is what is done here.
        // TODO: could be optimized by doing it only through a Yamux event? this is the case for StreamReset but not for graceful streams closures
        let dead_substream_ids = self
            .inner
            .yamux
            .dead_substreams()
            .map(|(id, death_ty, _)| (id, death_ty))
            .collect::<Vec<_>>();
        for (dead_substream_id, death_ty) in dead_substream_ids {
            match death_ty {
                yamux::DeadSubstreamTy::Reset => {
                    // If the substream was reset by the remote, then the substream state
                    // machine will still be `Some`.
                    if let Some((state_machine, mut user_data)) =
                        self.inner.yamux.remove_dead_substream(dead_substream_id)
                    {
                        // TODO: consider changing this `state_machine.reset()` function to be a state transition of the substream state machine (that doesn't take ownership), to simplify the implementation of both the substream state machine and this code
                        if let Some(event) = state_machine.reset() {
                            return Ok((
                                self,
                                Some(Self::pass_through_substream_event(
                                    dead_substream_id,
                                    &mut user_data,
                                    event,
                                )),
                            ));
                        }
                    };

                    // Removing a dead substream might lead to Yamux being able to process more
                    // incoming data. As such, we loop again.
                    read_write.wake_up_asap();
                }
                yamux::DeadSubstreamTy::ClosedGracefully => {
                    self.inner.yamux.remove_dead_substream(dead_substream_id);
                }
            }
        }

        Ok((self, None))
    }

    /// Turns an event from the [`substream`] module into an [`Event`].
    fn pass_through_substream_event(
        substream_id: yamux::SubstreamId,
        substream_user_data: &mut Option<TSubUd>,
        event: substream::Event,
    ) -> Event<TSubUd> {
        match event {
            substream::Event::InboundError {
                error,
                was_accepted: false,
            } => Event::InboundError(error),
            substream::Event::InboundError {
                was_accepted: true, ..
            } => Event::InboundAcceptedCancel {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                user_data: substream_user_data.take().unwrap(),
                // TODO: notify of the error?
            },
            substream::Event::InboundNegotiated(protocol_name) => Event::InboundNegotiated {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                protocol_name,
            },
            substream::Event::InboundNegotiatedCancel => Event::InboundNegotiatedCancel {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
            },
            substream::Event::RequestIn { request } => Event::RequestIn {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                request,
            },
            substream::Event::Response { response } => Event::Response {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                response,
                user_data: substream_user_data.take().unwrap(),
            },
            substream::Event::NotificationsInOpen { handshake } => Event::NotificationsInOpen {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                handshake,
            },
            substream::Event::NotificationsInOpenCancel => Event::NotificationsInOpenCancel {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
            },
            substream::Event::NotificationIn { notification } => Event::NotificationIn {
                notification,
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
            },
            substream::Event::NotificationsInClose { outcome } => Event::NotificationsInClose {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                outcome,
                user_data: substream_user_data.take().unwrap(),
            },
            substream::Event::NotificationsOutResult { result } => Event::NotificationsOutResult {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                result: match result {
                    Ok(r) => Ok(r),
                    Err(err) => Err((err, substream_user_data.take().unwrap())),
                },
            },
            substream::Event::NotificationsOutCloseDemanded => {
                Event::NotificationsOutCloseDemanded {
                    id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                }
            }
            substream::Event::NotificationsOutReset => Event::NotificationsOutReset {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                user_data: substream_user_data.take().unwrap(),
            },
            substream::Event::PingOutSuccess { ping_time } => Event::PingOutSuccess { ping_time },
            substream::Event::PingOutError { .. } => {
                // Because ping events are automatically generated by the external API without any
                // guarantee, it is safe to merge multiple failed pings into one.
                Event::PingOutFailed
            }
            substream::Event::BitswapIn { message } => Event::BitswapIn { message },
        }
    }

    /// Close the incoming substreams, automatically denying any new substream request from the
    /// remote.
    ///
    /// Note that this does not prevent incoming-substreams-related events
    /// (such as [`Event::RequestIn`]) from being generated, as it is possible that the remote has
    /// already opened a substream but has no sent all the necessary handshake messages yet.
    ///
    /// # Panic
    ///
    /// Panic if this function has been called before. It is illegal to call
    /// [`SingleStream::deny_new_incoming_substreams`] more than one on the same connections.
    ///
    pub fn deny_new_incoming_substreams(&mut self) {
        // TODO: arbitrary yamux error code
        self.inner
            .yamux
            .send_goaway(yamux::GoAwayErrorCode::NormalTermination)
            .unwrap()
    }

    /// Modifies the value that was initially passed through [`Config::max_protocol_name_len`].
    ///
    /// The new value only applies to substreams opened after this function has been called.
    pub fn set_max_protocol_name_len(&mut self, new_value: usize) {
        self.inner.max_protocol_name_len = new_value;
    }

    /// Sends a request to the remote.
    ///
    /// This method only inserts the request into the connection object. Use
    /// [`SingleStream::read_write`] in order to actually send out the request.
    ///
    /// Assuming that the remote is using the same implementation, an [`Event::RequestIn`] will
    /// be generated on its side.
    ///
    /// If `request` is `None`, then no request is sent to the remote at all. If `request` is
    /// `Some`, then a (potentially-empty) request is sent. If `Some(&[])` is provided, a
    /// length-prefix containing a 0 is sent to the remote.
    ///
    /// After the remote has sent back a response, an [`Event::Response`] event will be generated
    /// locally. The `user_data` parameter will be passed back.
    ///
    /// The timeout is the time between the moment the substream is opened and the moment the
    /// response is sent back. If the emitter doesn't send the request or if the receiver doesn't
    /// answer during this time window, the request is considered failed.
    ///
    /// # Panic
    ///
    /// Panics if a [`Event::NewOutboundSubstreamsForbidden`] event has been generated in the past.
    ///
    pub fn add_request(
        &mut self,
        protocol_name: String,
        request: Option<Vec<u8>>,
        timeout: TNow,
        max_response_size: usize,
        user_data: TSubUd,
    ) -> SubstreamId {
        let substream_id = self
            .inner
            .yamux
            .open_substream(Some((
                substream::Substream::request_out(
                    protocol_name,
                    timeout,
                    request,
                    max_response_size,
                ),
                Some(user_data),
            )))
            .unwrap(); // TODO: consider not panicking

        // TODO: we add some bytes due to the length prefix, this is a bit hacky as we should ask this information from the substream
        self.inner.yamux.add_remote_window_saturating(
            substream_id,
            u64::try_from(max_response_size)
                .unwrap_or(u64::MAX)
                .saturating_add(64)
                .saturating_sub(yamux::NEW_SUBSTREAMS_FRAME_SIZE),
        );

        SubstreamId(SubstreamIdInner::SingleStream(substream_id))
    }

    /// Opens a outgoing substream with the given protocol, destined for a stream of
    /// notifications.
    ///
    /// The remote must first accept (or reject) the substream before notifications can be sent
    /// on it.
    ///
    /// This method only inserts the opening handshake into the connection object. Use
    /// [`SingleStream::read_write`] in order to actually send out the request.
    ///
    /// Assuming that the remote is using the same implementation, an
    /// [`Event::NotificationsInOpen`] will be generated on its side.
    ///
    /// # Panic
    ///
    /// Panics if a [`Event::NewOutboundSubstreamsForbidden`] event has been generated in the past.
    ///
    pub fn open_notifications_substream(
        &mut self,
        protocol_name: String,
        handshake: Vec<u8>,
        max_handshake_size: usize,
        timeout: TNow,
        user_data: TSubUd,
    ) -> SubstreamId {
        let substream = self
            .inner
            .yamux
            .open_substream(Some((
                substream::Substream::notifications_out(
                    timeout,
                    protocol_name,
                    handshake,
                    max_handshake_size,
                ),
                Some(user_data),
            )))
            .unwrap(); // TODO: consider not panicking

        SubstreamId(SubstreamIdInner::SingleStream(substream))
    }

    /// Call after an [`Event::InboundNegotiated`] has been emitted in order to accept the protocol
    /// name and indicate the type of the protocol.
    ///
    /// # Panic
    ///
    /// Panics if the substream is not in the correct state.
    ///
    pub fn accept_inbound(&mut self, substream_id: SubstreamId, ty: InboundTy, user_data: TSubUd) {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => panic!(),
        };

        let (substream, ud) = self.inner.yamux[substream_id].as_mut().unwrap();
        substream.accept_inbound(ty);
        debug_assert!(ud.is_none());
        *ud = Some(user_data);
        self.inner.yamux.mark_substream_write_ready(substream_id);
    }

    /// Call after an [`Event::InboundNegotiated`] has been emitted in order to reject the
    /// protocol name as not supported.
    ///
    /// # Panic
    ///
    /// Panics if the substream is not in the correct state.
    ///
    pub fn reject_inbound(&mut self, substream_id: SubstreamId) {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => panic!(),
        };

        let (substream, ud) = self.inner.yamux[substream_id].as_mut().unwrap();
        substream.reject_inbound();
        debug_assert!(ud.is_none());
        self.inner.yamux.mark_substream_write_ready(substream_id);
    }

    /// Accepts an inbound notifications protocol. Must be called in response to a
    /// [`Event::NotificationsInOpen`].
    ///
    /// # Panic
    ///
    /// Panics if the substream id is not valid or the substream is of the wrong type.
    ///
    pub fn accept_in_notifications_substream(
        &mut self,
        substream_id: SubstreamId,
        handshake: Vec<u8>,
        max_notification_size: usize,
    ) {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => panic!(),
        };

        self.inner.yamux[substream_id]
            .as_mut()
            .unwrap()
            .0
            .accept_in_notifications_substream(handshake, max_notification_size);
        self.inner.yamux.mark_substream_write_ready(substream_id);
    }

    /// Rejects an inbound notifications protocol. Must be called in response to a
    /// [`Event::NotificationsInOpen`].
    ///
    /// # Panic
    ///
    /// Panics if the substream id is not valid or the substream is of the wrong type.
    ///
    pub fn reject_in_notifications_substream(&mut self, substream_id: SubstreamId) {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => panic!(),
        };

        self.inner.yamux[substream_id]
            .as_mut()
            .unwrap()
            .0
            .reject_in_notifications_substream();
        self.inner.yamux.mark_substream_write_ready(substream_id);
    }

    /// Queues a notification to be written out on the given substream.
    ///
    /// # About back-pressure
    ///
    /// This method unconditionally queues up data. You must be aware that the remote, however,
    /// can decide to delay indefinitely the sending of that data, which can potentially lead to
    /// an unbounded increase in memory.
    ///
    /// As such, you are encouraged to call this method only if the amount of queued data (as
    /// determined by calling [`SingleStream::notification_substream_queued_bytes`]) is below a
    /// certain threshold. If above, the notification should be silently discarded.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to a notifications substream, or if the
    /// notifications substream isn't in the appropriate state.
    ///
    pub fn write_notification_unbounded(
        &mut self,
        substream_id: SubstreamId,
        notification: Vec<u8>,
    ) {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => panic!(),
        };

        self.inner.yamux[substream_id]
            .as_mut()
            .unwrap()
            .0
            .write_notification_unbounded(notification);
        self.inner.yamux.mark_substream_write_ready(substream_id);
    }

    /// Returns the number of bytes waiting to be sent out on that substream.
    ///
    /// See the documentation of [`SingleStream::write_notification_unbounded`] for context.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to a notifications substream, or if the
    /// notifications substream isn't in the appropriate state.
    ///
    pub fn notification_substream_queued_bytes(&self, substream_id: SubstreamId) -> usize {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => panic!(),
        };

        // Note that this doesn't take into account data that the Yamux or Noise state machines
        // have extracted from the substream but hasn't sent out yet, because the objective of this
        // function is to provide a hint about when to stop sending more data, and the size of the
        // data that Noise and Yamux have extracted is always bounded anyway. It's not worth the
        // effort of reporting a 100% accurate information when a 100% accurate information isn't
        // needed.
        self.inner.yamux[substream_id]
            .as_ref()
            .unwrap()
            .0
            .notification_substream_queued_bytes()
    }

    /// Closes a notifications substream opened after a successful
    /// [`Event::NotificationsOutResult`].
    ///
    /// This can be done even when in the negotiation phase, in other words before the remote has
    /// accepted/refused the substream.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to a notifications substream, or if the
    /// notifications substream isn't in the appropriate state.
    ///
    pub fn close_out_notifications_substream(&mut self, substream_id: SubstreamId) {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => panic!(),
        };

        if !self.inner.yamux.has_substream(substream_id) {
            panic!()
        }

        self.inner.yamux[substream_id]
            .as_mut()
            .unwrap()
            .0
            .close_out_notifications_substream();
        self.inner.yamux.mark_substream_write_ready(substream_id);
    }

    /// Closes a notifications substream that was accepted using
    /// [`SingleStream::accept_in_notifications_substream`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to a notifications substream, or if the
    /// notifications substream isn't in the appropriate state.
    ///
    pub fn close_in_notifications_substream(&mut self, substream_id: SubstreamId, timeout: TNow) {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => panic!(),
        };

        if !self.inner.yamux.has_substream(substream_id) {
            panic!()
        }

        self.inner.yamux[substream_id]
            .as_mut()
            .unwrap()
            .0
            .close_in_notifications_substream(timeout);
        self.inner.yamux.mark_substream_write_ready(substream_id);
    }

    /// Responds to an incoming request. Must be called in response to a [`Event::RequestIn`].
    ///
    /// Passing an `Err` corresponds, on the other side, to a
    /// [`substream::RequestError::SubstreamClosed`].
    ///
    /// Returns an error if the [`SubstreamId`] is invalid.
    pub fn respond_in_request(
        &mut self,
        substream_id: SubstreamId,
        response: Result<Vec<u8>, ()>,
    ) -> Result<(), RespondInRequestError> {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => return Err(RespondInRequestError::SubstreamClosed),
        };

        if !self.inner.yamux.has_substream(substream_id) {
            return Err(RespondInRequestError::SubstreamClosed);
        }

        self.inner.yamux[substream_id]
            .as_mut()
            .unwrap()
            .0
            .respond_in_request(response)?;
        self.inner.yamux.mark_substream_write_ready(substream_id);
        Ok(())
    }
}

impl<TNow, TSubUd> Index<SubstreamId> for SingleStream<TNow, TSubUd> {
    type Output = TSubUd;

    fn index(&self, substream_id: SubstreamId) -> &Self::Output {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => panic!(),
        };

        self.inner.yamux[substream_id]
            .as_ref()
            .unwrap()
            .1
            .as_ref()
            .unwrap()
    }
}

impl<TNow, TSubUd> IndexMut<SubstreamId> for SingleStream<TNow, TSubUd> {
    fn index_mut(&mut self, substream_id: SubstreamId) -> &mut Self::Output {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => panic!(),
        };

        self.inner.yamux[substream_id]
            .as_mut()
            .unwrap()
            .1
            .as_mut()
            .unwrap()
    }
}

impl<TNow, TSubUd> fmt::Debug for SingleStream<TNow, TSubUd>
where
    TSubUd: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map()
            .entries(self.inner.yamux.user_datas())
            .finish()
    }
}

/// Error during a connection. The connection should be shut down.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum Error {
    /// Error in the noise cipher. Data has most likely been corrupted.
    #[display("Noise error: {_0}")]
    Noise(noise::CipherError),
    /// Error while encoding noise data.
    #[display("{_0}")]
    NoiseEncrypt(noise::EncryptError),
    /// Error in the Yamux multiplexing protocol.
    #[display("Yamux error: {_0}")]
    Yamux(yamux::Error),
}

/// Successfully negotiated connection. Ready to be turned into a [`SingleStream`].
pub struct ConnectionPrototype {
    encryption: noise::Noise,
}

impl ConnectionPrototype {
    /// Builds a new [`ConnectionPrototype`] of a connection using the Noise and Yamux protocols.
    pub(crate) fn from_noise_yamux(encryption: noise::Noise) -> Self {
        ConnectionPrototype { encryption }
    }

    /// Extracts the Noise state machine from this prototype.
    pub fn into_noise_state_machine(self) -> noise::Noise {
        self.encryption
    }

    /// Turns this prototype into an actual connection.
    pub fn into_connection<TNow, TSubUd>(self, config: Config<TNow>) -> SingleStream<TNow, TSubUd>
    where
        TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
    {
        let mut randomness = rand_chacha::ChaCha20Rng::from_seed(config.randomness_seed);

        let mut yamux = yamux::Yamux::new(yamux::Config {
            is_initiator: self.encryption.is_initiator(),
            capacity: config.substreams_capacity,
            randomness_seed: {
                let mut seed = [0; 32];
                randomness.fill_bytes(&mut seed);
                seed
            },
            max_out_data_frame_size: NonZero::<u32>::new(8192).unwrap(), // TODO: make configurable?
            max_simultaneous_queued_pongs: NonZero::<usize>::new(4).unwrap(),
            max_simultaneous_rst_substreams: NonZero::<usize>::new(1024).unwrap(),
        });

        let outgoing_pings = yamux
            .open_substream(Some((
                substream::Substream::ping_out(config.ping_protocol.clone()),
                None,
            )))
            // Can only panic if a `GoAway` has been received, or if there are too many substreams
            // already open, which we know for sure can't happen here
            .unwrap_or_else(|_| panic!());

        SingleStream {
            encryption: self.encryption,
            inner: Box::new(Inner {
                yamux,
                outgoing_pings,
                next_ping: config.first_out_ping,
                ping_payload_randomness: randomness,
                max_inbound_substreams: config.max_inbound_substreams,
                max_protocol_name_len: config.max_protocol_name_len,
                ping_interval: config.ping_interval,
                ping_timeout: config.ping_timeout,
            }),
        }
    }
}

impl fmt::Debug for ConnectionPrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ConnectionPrototype").finish()
    }
}
