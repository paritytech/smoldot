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
    substream::{self, RespondInRequestError},
    Config, ConfigNotifications, ConfigRequestResponse, ConfigRequestResponseIn, Event,
    SubstreamId, SubstreamIdInner,
};

use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::{
    fmt, iter,
    num::NonZeroUsize,
    ops::{Add, Sub},
    time::Duration,
};
use rand::{Rng as _, SeedableRng as _};

/// State machine of a fully-established connection.
pub struct SingleStream<TNow, TRqUd, TNotifUd> {
    /// Encryption layer applied directly on top of the incoming data and outgoing data.
    /// In addition to the cipher state, also contains a buffer of data received from the socket,
    /// decoded but yet to be parsed.
    // TODO: move this decoded-data buffer here
    encryption: noise::Noise,

    /// Extra fields. Segregated in order to solve borrowing questions.
    inner: Inner<TNow, TRqUd, TNotifUd>,
}

/// Extra fields. Segregated in order to solve borrowing questions.
struct Inner<TNow, TRqUd, TNotifUd> {
    /// State of the various substreams of the connection.
    /// Consists in a collection of substreams, each of which holding a [`substream::Substream`]
    /// object, or `None` if the substream has been reset.
    /// Also includes, for each substream, a collection of buffers whose data is to be written
    /// out.
    yamux: yamux::Yamux<Option<substream::Substream<TNow, TRqUd, TNotifUd>>>,

    /// If `Some`, contains the substream and number of bytes that [`Inner::yamux`] has already
    /// processed but haven't been consumed from the buffer of decoded data in
    /// [`SingleStream::encryption`] yet.
    ///
    /// After Yamux indicates that it has just processed a frame of data belonging to a certain
    /// substream, we set this value to `Some` but leave the data in the buffer. This way, we can
    /// process the data at a slower pace than Yamux.
    current_data_frame: Option<(yamux::SubstreamId, NonZeroUsize)>,

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
    /// See [`Config::request_protocols`].
    request_protocols: Vec<ConfigRequestResponse>,
    /// See [`Config::notifications_protocols`].
    notifications_protocols: Vec<ConfigNotifications>,
    /// See [`Config::ping_protocol`].
    ping_protocol: String,
    /// See [`Config::ping_interval`].
    ping_interval: Duration,
    /// See [`Config::ping_timeout`].
    ping_timeout: Duration,

    /// Buffer used for intermediary data. When it is necessary, data is first copied here before
    /// being turned into a `Vec`.
    ///
    /// While in theory this intermediary buffer could be shared between multiple different
    /// connections, since data present in this buffer isn't always zero-ed, it could be possible
    /// for a bug to cause data destined for connection A to be sent to connection B. Sharing this
    /// buffer is too dangerous.
    // TODO: remove; needs a lot of refactoring of noise and yamux
    intermediary_buffer: Box<[u8]>,
}

impl<TNow, TRqUd, TNotifUd> SingleStream<TNow, TRqUd, TNotifUd>
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
        read_write: &'_ mut ReadWrite<'_, TNow>,
    ) -> Result<
        (
            SingleStream<TNow, TRqUd, TNotifUd>,
            Option<Event<TRqUd, TNotifUd>>,
        ),
        Error,
    > {
        // First, update all the internal substreams.
        // This doesn't read data from `read_write`, but can potential write out data.
        for substream_id in self
            .inner
            .yamux
            .user_datas()
            .map(|(id, _)| id)
            .collect::<Vec<_>>()
        {
            let (_num_read, event) =
                Self::process_substream(&mut self.inner, substream_id, read_write, &[]);
            debug_assert_eq!(_num_read, 0);
            if let Some(event) = event {
                return Ok((self, Some(event)));
            }
        }

        // Start any outgoing ping if necessary.
        if read_write.now >= self.inner.next_ping {
            self.inner.next_ping = read_write.now.clone() + self.inner.ping_interval;

            // It might be that the remote has reset the ping substream, in which case the out ping
            // substream no longer exists and we immediately consider the ping as failed.
            if let Some(substream) = self
                .inner
                .yamux
                .substream_by_id_mut(self.inner.outgoing_pings)
            {
                let payload = self
                    .inner
                    .ping_payload_randomness
                    .sample(rand::distributions::Standard);
                substream
                    .into_user_data()
                    .as_mut()
                    .unwrap()
                    .queue_ping(&payload, read_write.now.clone() + self.inner.ping_timeout);
            } else {
                return Ok((self, Some(Event::PingOutFailed)));
            }
        }
        read_write.wake_up_after(&self.inner.next_ping);

        // Processing incoming data might be blocked on emitting data or on removing dead
        // substreams, and processing incoming data might lead to more data to emit. The easiest
        // way to implement this is a single loop that does everything.
        loop {
            // If we have both sent and received a GoAway frame, that means that no new substream
            // can be opened. If in addition to this there is no substream in the connection,
            // then we can safely close it as a normal termination.
            // Note that, because we have no guarantee that the remote has received our GoAway
            // frame yet, it is possible to receive requests for new substreams even after having
            // sent the GoAway. Because we close the writing side, it is not possible to indicate
            // to the remote that these new substreams are denied. However, this is not a problem
            // as the remote interprets our GoAway frame as an automatic refusal of all its pending
            // substream requests.
            if self.inner.yamux.is_empty()
                && self.inner.yamux.goaway_sent()
                && self.inner.yamux.received_goaway().is_some()
            {
                read_write.close_write_if_empty();
            }

            // Any meaningful activity within this loop can set this value to `true`. If this
            // value is still `false` at the end of the loop, we return from the function due to
            // having nothing more to do.
            let mut must_continue_looping = false;

            // If `self.inner.current_data_frame` is `Some`, that means that yamux has already
            // processed some of the data in the buffer of decrypted data and has determined that
            // it was data belonging to a certain substream. We now pass over this data again,
            // but this time update the state machine specific to that substream.
            if let Some((substream_id, bytes_remaining)) = self.inner.current_data_frame {
                // It might be that the substream has been closed in `process_substream`.
                if self.inner.yamux.substream_by_id_mut(substream_id).is_none() {
                    self.encryption.consume_inbound_data(bytes_remaining.get());
                    self.inner.current_data_frame = None;
                    continue;
                }

                let data = &self.encryption.decoded_inbound_data()[..bytes_remaining.get()];

                let (num_read, event) =
                    Self::process_substream(&mut self.inner, substream_id, read_write, data);

                if let Some(more_remaining) = NonZeroUsize::new(bytes_remaining.get() - num_read) {
                    self.inner.current_data_frame = Some((substream_id, more_remaining))
                } else {
                    self.inner.current_data_frame = None;
                }

                // Discard the data from the decrypted data buffer.
                self.encryption.consume_inbound_data(num_read);

                if let Some(event) = event {
                    return Ok((self, Some(event)));
                } else if num_read == 0 {
                    // Substream doesn't accept anymore data because it is blocked on writing out.
                    return Ok((self, None));
                } else {
                    // Jump back to the beginning of the loop. We don't want to read more data
                    // until this specific substream's data has been processed.
                    continue;
                }
            }

            // Transfer data from `incoming_data` to the internal buffer in `self.encryption`.
            // Note that we treat the reading side being closed the same way as no data being
            // received. The fact that the remote has closed their writing side is no different
            // than them leaving their writing side open but no longer send any data at all.
            // The remote is free to close their writing side at any point if it judges that it
            // will no longer need to send anymore data.
            // Note, however, that in principle the remote should have sent a GoAway frame prior
            // to closing their writing side. But this is not something we check or really care
            // about.
            if let Some(incoming_data) = read_write.incoming_buffer.as_mut() {
                let num_read = self
                    .encryption
                    .inject_inbound_data(*incoming_data)
                    .map_err(Error::Noise)?;
                read_write.advance_read(num_read);
            }

            // Ask the Yamux state machine to decode the buffer present in `self.encryption`.
            debug_assert!(self.inner.current_data_frame.is_none());
            let yamux_decode = self
                .inner
                .yamux
                .incoming_data(self.encryption.decoded_inbound_data())
                .map_err(Error::Yamux)?;
            self.inner.yamux = yamux_decode.yamux;

            // If bytes_read is 0 and detail is None, then Yamux can't do anything more. On the
            // other hand, if bytes_read is != 0 or detail is Some, then Yamux might have more
            // things to do, and we must loop again.
            if !(yamux_decode.bytes_read == 0 && yamux_decode.detail.is_none()) {
                must_continue_looping = true;
            }

            // Analyze how Yamux has parsed the data.
            // This still contains references to the data in `self.encryption`.
            match yamux_decode.detail {
                None if yamux_decode.bytes_read == 0 => {}
                None => {
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);
                }

                Some(yamux::IncomingDataDetail::IncomingSubstream) => {
                    debug_assert!(!self.inner.yamux.goaway_queued_or_sent());

                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);

                    // Receive a request from the remote for a new incoming substream.
                    // These requests are automatically accepted unless the total limit to the
                    // number of substreams has been reached.
                    // Note that `num_inbound()` counts substreams that have been closed but not
                    // yet removed from the state machine. This can affect the actual limit in a
                    // subtle way. At the time of writing of this comment the limit should be
                    // properly enforced, however it is not considered problematic if it weren't.
                    if self.inner.yamux.num_inbound() >= self.inner.max_inbound_substreams {
                        self.inner.yamux.reject_pending_substream();
                        continue;
                    }

                    let supported_protocols = self
                        .inner
                        .request_protocols
                        .iter()
                        .filter(|p| p.inbound_allowed)
                        .map(|p| p.name.clone())
                        .chain(
                            self.inner
                                .notifications_protocols
                                .iter()
                                .map(|p| p.name.clone()),
                        )
                        .chain(iter::once(self.inner.ping_protocol.clone()))
                        .collect::<Vec<_>>();

                    self.inner
                        .yamux
                        .accept_pending_substream(Some(substream::Substream::ingoing(
                            supported_protocols,
                        )));
                }

                Some(
                    yamux::IncomingDataDetail::StreamReset { .. }
                    | yamux::IncomingDataDetail::StreamClosed { .. },
                ) => {
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);
                }

                Some(yamux::IncomingDataDetail::DataFrame {
                    start_offset,
                    substream_id,
                }) => {
                    // Discard the data in `self.encryption` up to where the data frame starts.
                    self.encryption.consume_inbound_data(start_offset);

                    // The substream's data isn't immediately processed. Instead, we leave this
                    // data in the buffer and update our internal state so that it gets processed
                    // during the next loop.
                    debug_assert!(self.inner.current_data_frame.is_none());
                    if let Some(len) = NonZeroUsize::new(yamux_decode.bytes_read - start_offset) {
                        self.inner.current_data_frame = Some((substream_id, len));
                    }
                }

                Some(yamux::IncomingDataDetail::GoAway { .. }) => {
                    // TODO: somehow report the GoAway error code on the external API?
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);
                    return Ok((self, Some(Event::NewOutboundSubstreamsForbidden)));
                }

                Some(yamux::IncomingDataDetail::PingResponse) => {
                    // Can only happen if we send out pings, which we never do.
                    unreachable!()
                }
            };

            // Substreams that have been closed or reset aren't immediately removed the yamux state
            // machine. They must be removed manually, which is what is done here.
            let dead_substream_ids = self
                .inner
                .yamux
                .dead_substreams()
                .map(|(id, death_ty, _)| (id, death_ty))
                .collect::<Vec<_>>();
            for (dead_substream_id, death_ty) in dead_substream_ids {
                match death_ty {
                    yamux::DeadSubstreamTy::Reset => {
                        // If the substream has been reset, we simply remove it from the Yamux
                        // state machine.

                        // If the substream was reset by the remote, then the substream state
                        // machine will still be `Some`.
                        if let Some(state_machine) =
                            self.inner.yamux.remove_dead_substream(dead_substream_id)
                        {
                            // TODO: consider changing this `state_machine.reset()` function to be a state transition of the substream state machine (that doesn't take ownership), to simplify the implementation of both the substream state machine and this code
                            if let Some(event) = state_machine.reset() {
                                return Ok((
                                    self,
                                    Some(Self::pass_through_substream_event(
                                        dead_substream_id,
                                        event,
                                    )),
                                ));
                            }
                        };

                        // Removing a dead substream might lead to Yamux being able to process more
                        // incoming data. As such, we loop again.
                        must_continue_looping = true;
                    }
                    yamux::DeadSubstreamTy::ClosedGracefully => {
                        // If the substream has been closed gracefully, we don't necessarily
                        // remove it instantly. Instead, we continue processing the substream
                        // state machine until it tells us that there are no more events to
                        // return.

                        // Mutable reference to the substream state machine within the yamux
                        // state machine.
                        let state_machine_refmut = self
                            .inner
                            .yamux
                            .substream_by_id_mut(dead_substream_id)
                            .unwrap()
                            .into_user_data();

                        // Extract the substream state machine, maybe putting it back later.
                        let state_machine_extracted = match state_machine_refmut.take() {
                            Some(s) => s,
                            None => {
                                // We can only happen if substream state machine has been reset,
                                // in which case it can't be in the "closed gracefully" state.
                                // Reaching this would indicate a bug in yamux.
                                unreachable!()
                            }
                        };

                        // Now we run `state_machine_extracted.read_write`.
                        let mut substream_read_write = ReadWrite {
                            now: read_write.now.clone(),
                            incoming_buffer: None,
                            outgoing_buffer: None,
                            read_bytes: 0,
                            written_bytes: 0,
                            wake_up_after: None,
                        };

                        let (substream_update, event) =
                            state_machine_extracted.read_write(&mut substream_read_write);

                        debug_assert!(
                            substream_read_write.read_bytes == 0
                                && substream_read_write.written_bytes == 0
                        );

                        if let Some(wake_up_after) = substream_read_write.wake_up_after {
                            read_write.wake_up_after(&wake_up_after);
                        }

                        if let Some(substream_update) = substream_update {
                            // Put back the substream state machine. It will be picked up again
                            // the next time `read_write` is called.
                            *state_machine_refmut = Some(substream_update);
                        } else {
                            // Substream has no more events to give us. Remove it from the Yamux
                            // state machine.
                            self.inner.yamux.remove_dead_substream(dead_substream_id);

                            // Removing a dead substream might lead to Yamux being able to process more
                            // incoming data. As such, we loop again.
                            must_continue_looping = true;
                        }

                        if let Some(event) = event {
                            return Ok((
                                self,
                                Some(Self::pass_through_substream_event(dead_substream_id, event)),
                            ));
                        }
                    }
                }
            }

            // The yamux state machine contains the data that needs to be written out.
            // Try to flush it.

            // Calculate number of bytes that we can extract from yamux. This is similar but not
            // exactly the same as the size of the outgoing buffer, as noise adds some headers to
            // the data.
            let unencrypted_bytes_to_extract = self
                .encryption
                .encrypt_size_conv(read_write.outgoing_buffer_available());

            if unencrypted_bytes_to_extract != 0 {
                // Extract outgoing data that is buffered within yamux.
                // TODO: don't allocate an intermediary buffer, but instead pass them directly to the encryption
                let mut buffers = Vec::with_capacity(32);
                let mut extract_out = self.inner.yamux.extract_out(unencrypted_bytes_to_extract);
                while let Some(buffer) = extract_out.next() {
                    buffers.push(buffer.as_ref().to_vec()); // TODO: copy
                }

                if !buffers.is_empty() {
                    must_continue_looping = true;

                    // Pass the data to the encryption layer.
                    let (_read, written) = self.encryption.encrypt(
                        buffers.into_iter(),
                        match read_write.outgoing_buffer.as_mut() {
                            Some((a, b)) => (a, b),
                            None => (&mut [], &mut []),
                        },
                    );
                    debug_assert!(_read <= unencrypted_bytes_to_extract);
                    read_write.advance_write(written);
                }
            }

            // If `must_continue_looping` is still false, then we didn't do anything meaningful
            // during this iteration. Return due to idleness.
            if !must_continue_looping {
                return Ok((self, None));
            }
        }
    }

    /// Advances a single substream.
    ///
    /// Returns the number of bytes that have been read from `in_data`, and optionally returns an
    /// event to yield to the user.
    ///
    /// If the substream wants to wake up at a certain time or after a certain future,
    /// `outer_read_write` will be updated to also wake up at that moment.
    ///
    /// This function does **not** read incoming data from `outer_read_write`. Instead, the data
    /// destined to the substream is found in `in_data`.
    ///
    /// # Panic
    ///
    /// Panics if the substream has its read point closed and `in_data` isn't empty.
    ///
    fn process_substream(
        inner: &mut Inner<TNow, TRqUd, TNotifUd>,
        substream_id: yamux::SubstreamId,
        outer_read_write: &mut ReadWrite<TNow>,
        in_data: &[u8],
    ) -> (usize, Option<Event<TRqUd, TNotifUd>>) {
        let mut total_read = 0;

        loop {
            let mut substream = inner.yamux.substream_by_id_mut(substream_id).unwrap();

            let state_machine = match substream.user_data_mut().take() {
                Some(s) => s,
                None => break (total_read, None),
            };

            let read_is_closed = !substream.can_receive();
            let write_is_closed = !substream.can_send();

            let mut substream_read_write = ReadWrite {
                now: outer_read_write.now.clone(),
                incoming_buffer: if read_is_closed {
                    assert!(in_data.is_empty());
                    None
                } else {
                    Some(&in_data[total_read..])
                },
                outgoing_buffer: if !write_is_closed {
                    Some((&mut inner.intermediary_buffer, &mut []))
                } else {
                    None
                },
                read_bytes: 0,
                written_bytes: 0,
                wake_up_after: None,
            };

            let (substream_update, event) = state_machine.read_write(&mut substream_read_write);

            total_read += substream_read_write.read_bytes;
            if let Some(wake_up_after) = substream_read_write.wake_up_after {
                outer_read_write.wake_up_after(&wake_up_after);
            }

            let closed_after = substream_read_write.outgoing_buffer.is_none();
            let written_bytes = substream_read_write.written_bytes;
            if written_bytes != 0 {
                debug_assert!(!write_is_closed);
                substream.write(inner.intermediary_buffer[..written_bytes].to_vec());
            }
            if !write_is_closed && closed_after {
                debug_assert_eq!(written_bytes, 0);
                substream.close();
            }

            match substream_update {
                Some(s) => *substream.user_data_mut() = Some(s),
                None => {
                    if !closed_after || !read_is_closed {
                        // TODO: what we do here is definitely correct, but the docs of `reset()` seem sketchy, investigate
                        inner
                            .yamux
                            .substream_by_id_mut(substream_id)
                            .unwrap()
                            .reset();
                    }
                }
            };

            let event_to_yield = match event {
                None => None,
                Some(substream::Event::InboundNegotiated(protocol)) => {
                    let substream = inner
                        .yamux
                        .substream_by_id_mut(substream_id)
                        .unwrap()
                        .into_user_data()
                        .as_mut()
                        .unwrap();

                    if protocol == inner.ping_protocol {
                        substream.set_inbound_ty(substream::InboundTy::Ping);
                    } else if let Some(protocol_index) = inner
                        .request_protocols
                        .iter()
                        .position(|p| p.name == protocol)
                    {
                        substream.set_inbound_ty(substream::InboundTy::Request {
                            protocol_index,
                            request_max_size: if let ConfigRequestResponseIn::Payload { max_size } =
                                inner.request_protocols[protocol_index].inbound_config
                            {
                                Some(max_size)
                            } else {
                                None
                            },
                        });
                    } else if let Some(protocol_index) = inner
                        .notifications_protocols
                        .iter()
                        .position(|p| p.name == protocol)
                    {
                        substream.set_inbound_ty(substream::InboundTy::Notifications {
                            protocol_index,
                            max_handshake_size: inner.notifications_protocols[protocol_index]
                                .max_handshake_size,
                        });
                    } else {
                        unreachable!();
                    }

                    continue;
                }
                Some(other) => Some(Self::pass_through_substream_event(substream_id, other)),
            };

            break (total_read, event_to_yield);
        }
    }

    /// Turns an event from the [`substream`] module into an [`Event`].
    ///
    /// # Panics
    ///
    /// Intentionally panics on [`substream::Event::InboundNegotiated`]. Please handle this
    /// variant separately.
    ///
    fn pass_through_substream_event(
        substream_id: yamux::SubstreamId,
        event: substream::Event<TRqUd, TNotifUd>,
    ) -> Event<TRqUd, TNotifUd> {
        match event {
            substream::Event::InboundNegotiated(_) => panic!(),
            substream::Event::InboundError(error) => Event::InboundError(error),
            substream::Event::RequestIn {
                protocol_index,
                request,
            } => Event::RequestIn {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                protocol_index,
                request,
            },
            substream::Event::Response {
                response,
                user_data,
            } => Event::Response {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                response,
                user_data,
            },
            substream::Event::NotificationsInOpen {
                protocol_index,
                handshake,
            } => Event::NotificationsInOpen {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                protocol_index,
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
            },
            substream::Event::NotificationsOutResult { result } => Event::NotificationsOutResult {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                result,
            },
            substream::Event::NotificationsOutCloseDemanded => {
                Event::NotificationsOutCloseDemanded {
                    id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                }
            }
            substream::Event::NotificationsOutReset { user_data } => Event::NotificationsOutReset {
                id: SubstreamId(SubstreamIdInner::SingleStream(substream_id)),
                user_data,
            },
            substream::Event::PingOutSuccess => Event::PingOutSuccess,
            substream::Event::PingOutError { .. } => {
                // Because ping events are automatically generated by the external API without any
                // guarantee, it is safe to merge multiple failed pings into one.
                Event::PingOutFailed
            }
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
    }

    /// Sends a request to the remote.
    ///
    /// Must pass the index of the protocol within [`Config::request_protocols`].
    ///
    /// This method only inserts the request into the connection object. Use
    /// [`SingleStream::read_write`] in order to actually send out the request.
    ///
    /// Assuming that the remote is using the same implementation, an [`Event::RequestIn`] will
    /// be generated on its side.
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
        protocol_index: usize,
        request: Vec<u8>,
        timeout: TNow,
        user_data: TRqUd,
    ) -> SubstreamId {
        let has_length_prefix = match self.inner.request_protocols[protocol_index].inbound_config {
            ConfigRequestResponseIn::Payload { max_size } => {
                // TODO: turn this assert into something that can't panic?
                assert!(request.len() <= max_size);
                true
            }
            ConfigRequestResponseIn::Empty => {
                // TODO: turn this assert into something that can't panic?
                assert!(request.is_empty());
                false
            }
        };

        let mut substream =
            self.inner
                .yamux
                .open_substream(Some(substream::Substream::request_out(
                    self.inner.request_protocols[protocol_index].name.clone(), // TODO: clone :-/
                    timeout,
                    if has_length_prefix {
                        Some(request)
                    } else {
                        None
                    },
                    self.inner.request_protocols[protocol_index].max_response_size,
                    user_data,
                )));

        // TODO: we add some bytes due to the length prefix, this is a bit hacky as we should ask this information from the substream
        substream.reserve_window(
            u64::try_from(self.inner.request_protocols[protocol_index].max_response_size)
                .unwrap_or(u64::max_value())
                .saturating_add(64),
        );

        SubstreamId(SubstreamIdInner::SingleStream(substream.id()))
    }

    /// Returns the user data associated to a notifications substream.
    ///
    /// Returns `None` if the substream doesn't exist or isn't a notifications substream.
    pub fn notifications_substream_user_data_mut(
        &mut self,
        id: SubstreamId,
    ) -> Option<&mut TNotifUd> {
        let id = match id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => return None,
        };

        self.inner
            .yamux
            .substream_by_id_mut(id)?
            .into_user_data()
            .as_mut()
            .unwrap()
            .notifications_substream_user_data_mut()
    }

    /// Opens a outgoing substream with the given protocol, destined for a stream of
    /// notifications.
    ///
    /// Must pass the index of the protocol within [`Config::notifications_protocols`].
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
        protocol_index: usize,
        handshake: Vec<u8>,
        timeout: TNow,
        user_data: TNotifUd,
    ) -> SubstreamId {
        let max_handshake_size =
            self.inner.notifications_protocols[protocol_index].max_handshake_size;

        // TODO: turn this assert into something that can't panic?
        assert!(handshake.len() <= max_handshake_size);

        let substream =
            self.inner
                .yamux
                .open_substream(Some(substream::Substream::notifications_out(
                    timeout,
                    self.inner.notifications_protocols[protocol_index]
                        .name
                        .clone(), // TODO: clone :-/,
                    handshake,
                    max_handshake_size,
                    user_data,
                )));

        SubstreamId(SubstreamIdInner::SingleStream(substream.id()))
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
        user_data: TNotifUd,
    ) {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => panic!(),
        };

        let max_notification_size = 16 * 1024 * 1024; // TODO: hack
                                                      // TODO: self.inner.notifications_protocols[protocol_index].max_notification_size;
        self.inner
            .yamux
            .substream_by_id_mut(substream_id)
            .unwrap()
            .into_user_data()
            .as_mut()
            .unwrap()
            .accept_in_notifications_substream(handshake, max_notification_size, user_data);
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

        self.inner
            .yamux
            .substream_by_id_mut(substream_id)
            .unwrap()
            .into_user_data()
            .as_mut()
            .unwrap()
            .reject_in_notifications_substream();
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

        self.inner
            .yamux
            .substream_by_id_mut(substream_id)
            .unwrap()
            .into_user_data()
            .as_mut()
            .unwrap()
            .write_notification_unbounded(notification);
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

        let substream = self.inner.yamux.substream_by_id(substream_id).unwrap();
        let already_queued = substream.queued_bytes();
        let from_substream = substream
            .into_user_data()
            .as_ref()
            .unwrap()
            .notification_substream_queued_bytes();
        already_queued + from_substream
    }

    /// Closes a notifications substream opened after a successful
    /// [`Event::NotificationsOutResult`] or that was accepted using
    /// [`SingleStream::accept_in_notifications_substream`].
    ///
    /// In the case of an outbound substream, this can be done even when in the negotiation phase,
    /// in other words before the remote has accepted/refused the substream.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to a notifications substream, or if the
    /// notifications substream isn't in the appropriate state.
    ///
    pub fn close_notifications_substream(&mut self, substream_id: SubstreamId) {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::SingleStream(id) => id,
            _ => panic!(),
        };

        self.inner
            .yamux
            .substream_by_id_mut(substream_id)
            .unwrap()
            .into_user_data()
            .as_mut()
            .unwrap()
            .close_notifications_substream();
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

        self.inner
            .yamux
            .substream_by_id_mut(substream_id)
            .ok_or(RespondInRequestError::SubstreamClosed)?
            .into_user_data()
            .as_mut()
            .unwrap()
            .respond_in_request(response)
    }
}

impl<TNow, TRqUd, TNotifUd> fmt::Debug for SingleStream<TNow, TRqUd, TNotifUd>
where
    TRqUd: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map()
            .entries(self.inner.yamux.user_datas())
            .finish()
    }
}

/// Error during a connection. The connection should be shut down.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// Error in the noise cipher. Data has most likely been corrupted.
    #[display(fmt = "Noise error: {}", _0)]
    Noise(noise::CipherError),
    /// Error in the Yamux multiplexing protocol.
    #[display(fmt = "Yamux error: {}", _0)]
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
    pub fn into_connection<TNow, TRqUd, TNotifUd>(
        self,
        config: Config<TNow>,
    ) -> SingleStream<TNow, TRqUd, TNotifUd>
    where
        TNow: Clone + Ord,
    {
        // TODO: check conflicts between protocol names?

        let mut randomness = rand_chacha::ChaCha20Rng::from_seed(config.randomness_seed);

        let mut yamux = yamux::Yamux::new(yamux::Config {
            is_initiator: self.encryption.is_initiator(),
            capacity: 64, // TODO: ?
            randomness_seed: randomness.sample(rand::distributions::Standard),
        });

        let outgoing_pings = yamux
            .open_substream(Some(substream::Substream::ping_out(
                config.ping_protocol.clone(),
            )))
            .id();

        SingleStream {
            encryption: self.encryption,
            inner: Inner {
                yamux,
                current_data_frame: None,
                outgoing_pings,
                next_ping: config.first_out_ping,
                ping_payload_randomness: randomness,
                max_inbound_substreams: config.max_inbound_substreams,
                request_protocols: config.request_protocols,
                notifications_protocols: config.notifications_protocols,
                ping_protocol: config.ping_protocol,
                ping_interval: config.ping_interval,
                ping_timeout: config.ping_timeout,
                intermediary_buffer: vec![0u8; 2048].into_boxed_slice(),
            },
        }
    }
}

impl fmt::Debug for ConnectionPrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ConnectionPrototype").finish()
    }
}
