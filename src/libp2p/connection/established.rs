// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
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

// TODO: expand docs ^

use crate::util::leb128;

use super::{multistream_select, noise, yamux};

use alloc::{
    string::String,
    vec::{self, Vec},
};
use core::{
    cmp, fmt, iter, mem,
    ops::{Add, Sub},
    time::Duration,
};

/// State machine of a fully-established connection.
pub struct Established<TNow, TSub> {
    /// Encryption layer applied directly on top of the incoming data and outgoing data.
    /// In addition to the cipher state, also contains a buffer of data received from the socket,
    /// decoded but yet to be parsed.
    // TODO: move this decoded-data buffer here
    encryption: noise::Noise,

    /// Extra fields. Segregated in order to solve borrowing questions.
    inner: Inner<TNow, TSub>,
}

/// Extra fields. Segregated in order to solve borrowing questions.
struct Inner<TNow, TSub> {
    /// State of the various substreams of the connection.
    /// Consists in a collection of substreams, each of which holding a [`Substream`] object.
    /// Also includes, for each substream, a collection of buffers whose data is to be written
    /// out.
    yamux: yamux::Yamux<Substream<TNow, TSub>>,

    /// Next substream timeout. When the current time is superior to this value, means that one of
    /// the substreams in `yamux` might have timed out.
    ///
    /// This value is not updated when a timeout is no longer necessary. As such, the value in
    /// this field might correspond to nothing (i.e. is now obsolete).
    next_timeout: Option<TNow>,
}

enum Substream<TNow, TSub> {
    /// Temporary transition state.
    Poisoned,

    /// Incoming substream has failed to negotiate a protocol. Waiting for a close from the remote.
    /// In order to save a round-trip time, the remote might assume that the protocol negotiation
    /// would have succeeded. As such, it might send the data that it would have sent on this
    /// substream, had it been accepted. This data should be ignored.
    NegotiationFailed,

    /// Protocol negotiation in progress in an incoming substream.
    InboundNegotiating {
        /// State of the protocol negotiation.
        negotiation: multistream_select::InProgress<vec::IntoIter<String>, String>,
        /// User data decided by the user.
        user_data: TSub,
    },

    /// Negotiating a protocol for an outgoing substream.
    OutboundNegotiating {
        /// When the opening will time out in the absence of response.
        timeout: TNow,
        /// State of the protocol negotiation.
        negotiation: multistream_select::InProgress<vec::IntoIter<String>, String>,
        /// User data decided by the user.
        user_data: TSub,
    },

    /// Substream has succeeded negotiations in the past.
    Open {
        /// User data decided by the user.
        user_data: TSub,
    },
}

impl<TNow, TSub> Established<TNow, TSub>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Reads data coming from the socket from `incoming_data`, updates the internal state machine,
    /// and writes data destined to the socket to `outgoing_buffer`.
    ///
    /// `incoming_data` should be `None` if the remote has closed their writing side.
    ///
    /// The returned structure contains the number of bytes read and written from/to the two
    /// buffers. In order to avoid unnecessary memory allocations, only one [`Event`] is returned
    /// at a time. Consequently, this method returns as soon as an event is available, even if the
    /// buffers haven't finished being read. Call this method in a loop until these two values are
    /// both 0 and [`ReadWrite::event`] is `None`.
    ///
    /// If the remote isn't ready to accept new data, pass an empty slice as `outgoing_buffer`.
    ///
    /// The current time must be passed via the `now` parameter. This is used internally in order
    /// to keep track of ping times and timeouts. The returned structure optionally contains a
    /// `TNow` representing the moment after which this method should be called again.
    ///
    /// If an error is returned, the socket should be entirely shut down.
    // TODO: should take the in and out buffers as iterators, to allow for vectored reads/writes; tricky because an impl Iterator<Item = &mut [u8]> + Clone is impossible to build
    // TODO: in case of error, we're supposed to first send a yamux goaway frame
    pub fn read_write<'a>(
        mut self,
        now: TNow,
        mut incoming_buffer: Option<&[u8]>,
        mut outgoing_buffer: (&'a mut [u8], &'a mut [u8]),
    ) -> Result<ReadWrite<TNow, TSub>, Error> {
        let mut total_read = 0;
        let mut total_written = 0;

        // First, check for timeouts.
        // Note that this might trigger timeouts for requests whose response is available in
        // `incoming_buffer`. This is intentional, as from the perspective of `read_write` the
        // response arrived after the timeout. It is the responsibility of the user to call
        // `read_write` in an appropriate way for this to not happen.
        if let Some(event) = self.update_now(now) {
            let wake_up_after = self.inner.next_timeout.clone();
            return Ok(ReadWrite {
                connection: self,
                read_bytes: total_read,
                written_bytes: total_written,
                write_close: false,
                wake_up_after,
                event: Some(event),
            });
        }

        // Decoding the incoming data.
        loop {
            // Transfer data from `incoming_data` to the internal buffer in `self.encryption`.
            if let Some(incoming_data) = incoming_buffer.as_mut() {
                let num_read = self
                    .encryption
                    .inject_inbound_data(*incoming_data)
                    .map_err(Error::Noise)?;
                total_read += num_read;
                *incoming_data = &incoming_data[num_read..];
            } else {
                return Ok(ReadWrite {
                    connection: self,
                    read_bytes: total_read,
                    written_bytes: total_written,
                    write_close: true,
                    wake_up_after: None,
                    event: None,
                });
            }

            // TODO: handle incoming_data being None

            // Ask the Yamux state machine to decode the buffer present in `self.encryption`.
            let yamux_decode = self
                .inner
                .yamux
                .incoming_data(self.encryption.decoded_inbound_data())
                .map_err(Error::Yamux)?;
            self.inner.yamux = yamux_decode.yamux;

            // TODO: it is possible that the yamux reading is blocked on writing

            // Analyze how Yamux has parsed the data.
            // This still contains references to the data in `self.encryption`.
            match yamux_decode.detail {
                None if yamux_decode.bytes_read == 0 => break,
                None => {
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);
                }

                Some(yamux::IncomingDataDetail::IncomingSubstream) => {
                    // Receive a request from the remote for a new incoming substream.
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);
                    let wake_up_after = self.inner.next_timeout.clone();
                    return Ok(ReadWrite {
                        connection: self,
                        read_bytes: total_read,
                        written_bytes: total_written,
                        write_close: false,
                        wake_up_after,
                        event: Some(Event::NewSubstreamIn),
                    });
                }

                Some(yamux::IncomingDataDetail::StreamReset {
                    substream_id,
                    user_data: substream_ty,
                }) => {
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);

                    let user_data_to_report = match substream_ty {
                        Substream::NegotiationFailed => None,
                        Substream::InboundNegotiating { user_data, .. }
                        | Substream::OutboundNegotiating { user_data, .. }
                        | Substream::Open { user_data, .. } => Some(user_data),
                        Substream::Poisoned => unreachable!(),
                    };

                    if let Some(user_data_to_report) = user_data_to_report {
                        let wake_up_after = self.inner.next_timeout.clone();
                        return Ok(ReadWrite {
                            connection: self,
                            read_bytes: total_read,
                            written_bytes: total_written,
                            write_close: false,
                            wake_up_after,
                            event: Some(Event::SubstreamReset {
                                id: substream_id,
                                user_data: user_data_to_report,
                            }),
                        });
                    }
                }

                Some(yamux::IncomingDataDetail::StreamClosed {
                    substream_id,
                    user_data,
                }) => {
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);

                    let user_data = match user_data {
                        Some(ud) => ud,
                        None => {
                            match self
                                .inner
                                .yamux
                                .substream_by_id(substream_id)
                                .unwrap()
                                .into_user_data()
                            {
                                Substream::NotificationsOut { .. } => {
                                    // TODO: report to user
                                    todo!()
                                }
                                _ => {}
                            }

                            self.inner
                                .yamux
                                .substream_by_id(substream_id)
                                .unwrap()
                                .close()
                                .unwrap()
                        }
                    };

                    match user_data {
                        Substream::Poisoned => unreachable!(),
                        Substream::InboundNegotiating(_) => {}
                        Substream::NegotiationFailed => {}
                        Substream::OutboundNegotiating { user_data, .. }
                        | Substream::RequestOut { user_data, .. } => {
                            let wake_up_after = self.inner.next_timeout.clone();
                            return Ok(ReadWrite {
                                connection: self,
                                read_bytes: total_read,
                                written_bytes: total_written,
                                write_close: false,
                                wake_up_after,
                                event: Some(Event::Response {
                                    id: SubstreamId(substream_id),
                                    user_data,
                                    response: Err(RequestError::SubstreamClosed),
                                }),
                            });
                        }
                        Substream::RequestInRecv { .. } => {}
                        Substream::RequestInSend { .. } => {}
                        Substream::NotificationsInHandshake { .. } => {}
                        Substream::NotificationsInWait { protocol_index, .. } => {
                            let wake_up_after = self.inner.next_timeout.clone();
                            return Ok(ReadWrite {
                                connection: self,
                                read_bytes: total_read,
                                written_bytes: total_written,
                                write_close: false,
                                wake_up_after,
                                event: Some(Event::NotificationsInOpenCancel {
                                    id: SubstreamId(substream_id),
                                    protocol_index,
                                }),
                            });
                        }
                        Substream::NotificationsIn { .. } => {
                            // TODO: report to user
                            todo!()
                        }
                        Substream::PingIn(_) => {}
                        Substream::NotificationsOutClosed => {}
                        Substream::NotificationsOut { user_data, .. }
                        | Substream::NotificationsOutHandshakeRecv { user_data, .. }
                        | Substream::OutboundNegotiating { user_data, .. } => {
                            let wake_up_after = self.inner.next_timeout.clone();
                            return Ok(ReadWrite {
                                connection: self,
                                read_bytes: total_read,
                                written_bytes: total_written,
                                write_close: false,
                                wake_up_after,
                                event: Some(Event::SubstreamOutNegotiated {
                                    id: SubstreamId(substream_id),
                                    user_data,
                                }),
                            });
                        }
                    }
                }

                Some(yamux::IncomingDataDetail::DataFrame {
                    start_offset,
                    substream_id,
                }) => {
                    // Data belonging to a substream has been decoded.
                    let data = &self.encryption.decoded_inbound_data()
                        [start_offset..yamux_decode.bytes_read];

                    let event = self
                        .inner
                        .inject_substream_data(SubstreamId(substream_id), data);

                    // Now that the Yamux parsing has been processed, discard this data in
                    // `self.encryption`.
                    self.encryption
                        .consume_inbound_data(yamux_decode.bytes_read);

                    if let Some(event) = event {
                        let wake_up_after = self.inner.next_timeout.clone();
                        return Ok(ReadWrite {
                            connection: self,
                            read_bytes: total_read,
                            written_bytes: total_written,
                            write_close: false,
                            wake_up_after,
                            event: Some(event),
                        });
                    }

                    if yamux_decode.bytes_read == 0 {
                        break;
                    }
                }
            };
        }

        // The yamux state machine contains the data that needs to be written out.
        // Try to flush it.
        loop {
            let bytes_out = self
                .encryption
                .encrypt_size_conv(outgoing_buffer.0.len() + outgoing_buffer.1.len());
            if bytes_out == 0 {
                break;
            }

            let mut buffers = self.inner.yamux.extract_out(bytes_out);
            let mut buffers = buffers.buffers().peekable();
            if buffers.peek().is_none() {
                break;
            }

            let (_read, written) = self
                .encryption
                .encrypt(buffers, (&mut outgoing_buffer.0, &mut outgoing_buffer.1));
            debug_assert!(_read <= bytes_out);
            total_written += written;
            let out_buf_0_len = outgoing_buffer.0.len();
            outgoing_buffer = (
                &mut outgoing_buffer.0[cmp::min(written, out_buf_0_len)..],
                &mut outgoing_buffer.1[written.saturating_sub(out_buf_0_len)..],
            );
            if outgoing_buffer.0.is_empty() {
                outgoing_buffer = (outgoing_buffer.1, outgoing_buffer.0);
            }
        }

        // Nothing more can be done.
        let wake_up_after = self.inner.next_timeout.clone();
        Ok(ReadWrite {
            connection: self,
            read_bytes: total_read,
            written_bytes: total_written,
            write_close: false,
            wake_up_after,
            event: None,
        })
    }

    /// Updates the internal state machine, most notably `self.inner.next_timeout`, with the
    /// passage of time.
    ///
    /// Optionally returns an event that happened as a result of the passage of time.
    fn update_now(&mut self, now: TNow) -> Option<Event<TSub>> {
        if self.inner.next_timeout.as_ref().map_or(true, |t| *t > now) {
            return None;
        }

        // Find which substream has timed out. This can be `None`, as the value in
        // `self.inner.next_timeout` can be obsolete.
        let timed_out_substream = self
            .inner
            .yamux
            .user_datas()
            .find(|(_, substream)| match &substream {
                Substream::OutboundNegotiating { timeout, .. }
                | Substream::RequestOut { timeout, .. }
                    if *timeout <= now =>
                {
                    true
                }
                _ => false,
            })
            .map(|(id, _)| id);

        // Turn `timed_out_substream` into an `Event`.
        // The timed out substream (if any) is being reset'ted.
        let event = if let Some(timed_out_substream) = timed_out_substream {
            let substream = self
                .inner
                .yamux
                .substream_by_id(timed_out_substream)
                .unwrap()
                .reset();

            Some(match substream {
                Substream::OutboundNegotiating { user_data, .. }
                | Substream::RequestOut { user_data, .. } => Event::Response {
                    id: SubstreamId(timed_out_substream),
                    response: Err(RequestError::Timeout),
                    user_data,
                },
                _ => unreachable!(),
            })
        } else {
            None
        };

        // Update `next_timeout`. Note that some of the timeouts in `self.inner.yamux` aren't
        // necessarily strictly superior to `now`. This is normal. As only one event can be
        // returned at a time, any further timeout will be handled the next time `update_now` is
        // called.
        self.inner.next_timeout = self
            .inner
            .yamux
            .user_datas()
            .filter_map(|(_, substream)| match &substream {
                Substream::NotificationsOutNegotiating { timeout, .. }
                | Substream::OutboundNegotiating { timeout, .. }
                | Substream::RequestOut { timeout, .. } => Some(timeout),
                _ => None,
            })
            .min()
            .cloned();

        event
    }

    /// Returns the user data associated to a substream.
    ///
    /// Returns `None` if the substream doesn't exist.
    pub fn substream_user_data(&self, id: SubstreamId) -> Option<&TSub> {
        todo!()
        /*match self.inner.yamux.substream_by_id(id.0)?.into_user_data() {
            Substream::NotificationsOutNegotiating { user_data, .. } => Some(user_data),
            Substream::NotificationsOutHandshakeRecv { user_data, .. } => Some(user_data),
            Substream::NotificationsOut { user_data } => Some(user_data),
            Substream::NotificationsIn { user_data, .. } => Some(user_data),
            _ => None,
        }*/
    }

    /// Returns the user data associated to a substream.
    ///
    /// Returns `None` if the substream doesn't exist.
    pub fn substream_user_data_mut(&mut self, id: SubstreamId) -> Option<&mut TSub> {
        match self.inner.yamux.substream_by_id(id.0)?.into_user_data() {
            Substream::NotificationsOutNegotiating { user_data, .. } => Some(user_data),
            Substream::NotificationsOutHandshakeRecv { user_data, .. } => Some(user_data),
            Substream::NotificationsOut { user_data } => Some(user_data),
            Substream::NotificationsIn { user_data, .. } => Some(user_data),
            _ => None,
        }
    }

    /// Opens a outgoing substream with the given protocol.
    ///
    /// Must pass the index of the protocol within [`Config::notifications_protocols`].
    ///
    /// The remote must first accept (or reject) the substream before notifications can be sent
    /// on it.
    ///
    /// This method only inserts the opening handshake into the connection object. Use
    /// [`Established::read_write`] in order to actually send out the request.
    ///
    /// Assuming that the remote is using the same implementation, an
    /// [`Event::NotificationsInOpen`] will be generated on its side.
    ///
    pub fn open_substream(
        &mut self,
        now: TNow,
        protocol_name: String,
        user_data: TSub,
    ) -> SubstreamId {
        let mut negotiation =
            multistream_select::InProgress::new(multistream_select::Config::Dialer {
                requested_protocol: protocol_name,
            });

        let (new_state, _, out_buffer) = negotiation.read_write_vec(&[]).unwrap();
        match new_state {
            multistream_select::Negotiation::InProgress(n) => negotiation = n,
            _ => unreachable!(),
        }

        let timeout = now + Duration::from_secs(20); // TODO:

        if self
            .inner
            .next_timeout
            .as_ref()
            .map_or(true, |t| *t > timeout)
        {
            self.inner.next_timeout = Some(timeout.clone());
        }

        let mut substream = self
            .inner
            .yamux
            .open_substream(Substream::OutboundNegotiating {
                timeout,
                negotiation,
                user_data,
            });

        substream.write(out_buffer);

        SubstreamId(substream.id())
    }

    /// Accepts an inbound substream. Must be called in response to a [`Event::NewSubstreamIn`].
    ///
    /// # Panic
    ///
    /// Panics if there is no pending inbound substream.
    ///
    pub fn accept_in_substream(&mut self, user_data: TSub) -> SubstreamId {
        let negotiation =
            multistream_select::InProgress::new(multistream_select::Config::Listener {
                supported_protocols: self
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
                    .collect::<Vec<_>>()
                    .into_iter(),
            });

        let substream_id = self
            .inner
            .yamux
            .accept_pending_substream(Substream::InboundNegotiating {
                negotiation: todo!(),
                user_data,
            })
            .id();

        SubstreamId(substream_id)
    }

    /// Rejects an inbound substream. Must be called in response to a [`Event::NewSubstreamIn`].
    ///
    /// # Panic
    ///
    /// Panics if there is no pending inbound substream.
    ///
    pub fn reject_in_substream(&mut self) {
        self.inner.yamux.reject_pending_substream();
        todo!() // TODO:
    }

    /// Peaks at the data that has come on a substream.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to an open substream.
    ///
    pub fn peak_read_buffer(&'_ self, id: SubstreamId) -> impl Iterator<Item = &'_ [u8]> {
        let mut substream = self.inner.yamux.substream_by_id(id.0).unwrap();
        if !matches!(substream.user_data(), Substream::Open { .. }) {
            panic!()
        }
        todo!()
    }

    /// Discards the first bytes of the data that has come on a substream.
    ///
    /// This allows the remote to send additional data.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to an open substream.
    ///
    pub fn advance_read_buffer(&'_ self, id: SubstreamId, bytes: usize) {
        let mut substream = self.inner.yamux.substream_by_id(id.0).unwrap();
        if !matches!(substream.user_data(), Substream::Open { .. }) {
            panic!()
        }
        todo!()
    }

    /// Queues data to be written out on the given substream.
    ///
    /// # About back-pressure
    ///
    /// This method unconditionally queues up data. You must be aware that the remote, however,
    /// can decide to delay indefinitely the sending of that data, which can potentially lead to
    /// an unbounded increase in memory.
    ///
    /// As such, you are encouraged to call this method only if the amount of queued data (as
    /// determined by calling [`Established::substream_queued_bytes`]) is below a certain
    /// threshold. If above, what to do depends on the logic of the higher-level logic of the
    /// data.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to an open substream.
    ///
    pub fn write_unbounded(&mut self, id: SubstreamId, data: Vec<u8>) {
        let mut substream = self.inner.yamux.substream_by_id(id.0).unwrap();
        if !matches!(substream.user_data(), Substream::Open { .. }) {
            panic!()
        }
        substream.write(data)
    }

    /// Returns the number of bytes waiting to be sent out on that substream.
    ///
    /// See the documentation of [`Established::write_notification_unbounded`] for context.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to a full-open substream.
    ///
    pub fn queued_bytes(&self, id: SubstreamId) -> usize {
        let mut substream = self.inner.yamux.substream_by_id(id.0).unwrap();
        if !matches!(substream.user_data(), Substream::Open { .. }) {
            panic!()
        }
        substream.queued_bytes()
    }

    /// Closes a substream.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to a full-open substream.
    ///
    pub fn close_substream(&mut self, id: SubstreamId) {
        let mut substream = self.inner.yamux.substream_by_id(id.0).unwrap();
        if !matches!(substream.user_data(), Substream::Open { .. }) {
            panic!()
        }
        // TODO: return value?
        substream.close();
    }
}

impl<TNow, TSub> fmt::Debug for Established<TNow, TSub>
where
    TSub: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map()
            .entries(self.inner.yamux.user_datas())
            .finish()
    }
}

impl<TNow, TSub> Inner<TNow, TSub> {
    fn inject_substream_data(
        &mut self,
        substream_id: SubstreamId,
        mut data: &[u8],
    ) -> Option<Event<TSub>> {
        while !data.is_empty() {
            let mut substream = self.yamux.substream_by_id(substream_id.0).unwrap();

            // In order to solve borrowing-related issues, the block below temporarily
            // replaces the state of the substream with `Poisoned`, then later puts back a
            // proper state.
            match mem::replace(substream.user_data(), Substream::Poisoned) {
                Substream::Poisoned => unreachable!(),
                Substream::InboundNegotiating(nego) => match nego.read_write_vec(data) {
                    Ok((multistream_select::Negotiation::InProgress(nego), read, out_buffer)) => {
                        debug_assert_eq!(read, data.len());
                        data = &data[read..];
                        substream.write(out_buffer);
                        *substream.user_data() = Substream::InboundNegotiating(nego);
                    }
                    Ok((
                        multistream_select::Negotiation::Success(protocol),
                        num_read,
                        out_buffer,
                    )) => {
                        substream.write(out_buffer);
                        data = &data[num_read..];
                        if protocol == self.ping_protocol {
                            *substream.user_data() = Substream::PingIn(Default::default());
                        } else if let Some(protocol_index) = self
                            .request_protocols
                            .iter()
                            .position(|p| p.name == protocol)
                        {
                            if let ConfigRequestResponseIn::Payload { max_size } =
                                self.request_protocols[protocol_index].inbound_config
                            {
                                *substream.user_data() = Substream::RequestInRecv {
                                    protocol_index,
                                    request: leb128::FramedInProgress::new(max_size),
                                };
                            } else {
                                // TODO: make sure that data is empty?
                                *substream.user_data() = Substream::RequestInSend;
                                return Some(Event::RequestIn {
                                    id: substream_id,
                                    protocol_index,
                                    request: Vec::new(),
                                });
                            }
                        } else if let Some(protocol_index) = self
                            .notifications_protocols
                            .iter()
                            .position(|p| p.name == protocol)
                        {
                            *substream.user_data() = Substream::NotificationsInHandshake {
                                protocol_index,
                                handshake: leb128::FramedInProgress::new(
                                    self.notifications_protocols[protocol_index].max_handshake_size,
                                ),
                            };
                        } else {
                            unreachable!()
                        }
                    }
                    Ok((multistream_select::Negotiation::NotAvailable, num_read, out_buffer)) => {
                        data = &data[num_read..];
                        substream.write(out_buffer);
                        *substream.user_data() = Substream::NegotiationFailed;
                        substream.close();
                    }
                    Err(_) => {
                        substream.reset();
                    }
                },
                Substream::NegotiationFailed => {
                    // Substream is an inbound substream that has failed to negotiate a
                    // protocol. The substream is expected to close soon, but the remote might
                    // have been eagerly sending data (assuming that the negotiation would
                    // succeed), which should be silently discarded.
                    data = &[];
                    *substream.user_data() = Substream::NegotiationFailed;
                }
                Substream::NotificationsOutNegotiating {
                    negotiation,
                    timeout,
                    handshake,
                    user_data,
                } => {
                    match negotiation.read_write_vec(data) {
                        Ok((
                            multistream_select::Negotiation::InProgress(nego),
                            read,
                            out_buffer,
                        )) => {
                            debug_assert_eq!(read, data.len());
                            data = &data[read..];
                            substream.write(out_buffer);
                            *substream.user_data() = Substream::NotificationsOutNegotiating {
                                negotiation: nego,
                                timeout,
                                handshake,
                                user_data,
                            };
                        }
                        Ok((multistream_select::Negotiation::Success(_), num_read, out_buffer)) => {
                            substream.write(out_buffer);
                            data = &data[num_read..];
                            substream.write(leb128::encode_usize(handshake.len()).collect());
                            substream.write(handshake);
                            *substream.user_data() = Substream::NotificationsOutHandshakeRecv {
                                handshake: leb128::FramedInProgress::new(10 * 1024), // TODO: proper max size
                                user_data,
                            };
                        }
                        _err => todo!("{:?}", _err), // TODO:
                    }
                }
                Substream::NotificationsOutHandshakeRecv {
                    handshake,
                    user_data,
                } => {
                    match handshake.update(&data) {
                        Ok((num_read, leb128::Framed::Finished(remote_handshake))) => {
                            if num_read != data.len() {
                                todo!() // TODO:
                            }

                            *substream.user_data() = Substream::NotificationsOut { user_data };
                            return Some(Event::NotificationsOutAccept {
                                id: substream_id,
                                remote_handshake,
                            });
                        }
                        Ok((num_read, leb128::Framed::InProgress(handshake))) => {
                            data = &data[num_read..];
                            *substream.user_data() = Substream::NotificationsOutHandshakeRecv {
                                handshake,
                                user_data,
                            };
                        }
                        Err(_) => {
                            todo!() // TODO: report to user and all
                        }
                    }
                }
                Substream::NotificationsOut { user_data } => {
                    // Receiving data on an outgoing substream is forbidden by the protocol.
                    data = &[];
                    *substream.user_data() = Substream::NotificationsOut { user_data };
                }
                Substream::NotificationsOutClosed => {
                    data = &[];
                    *substream.user_data() = Substream::NotificationsOutClosed;
                }
                Substream::OutboundNegotiating {
                    negotiation,
                    timeout,
                    request,
                    user_data,
                } => {
                    match negotiation.read_write_vec(data) {
                        Ok((
                            multistream_select::Negotiation::InProgress(nego),
                            _read,
                            out_buffer,
                        )) => {
                            debug_assert_eq!(_read, data.len());
                            data = &data[_read..];
                            substream.write(out_buffer);
                            *substream.user_data() = Substream::OutboundNegotiating {
                                negotiation: nego,
                                timeout,
                                request,
                                user_data,
                            };
                        }
                        Ok((multistream_select::Negotiation::Success(_), num_read, out_buffer)) => {
                            substream.write(out_buffer);
                            data = &data[num_read..];
                            if let Some(request) = request {
                                substream.write(leb128::encode_usize(request.len()).collect());
                                substream.write(request);
                            }
                            *substream.user_data() = Substream::RequestOut {
                                timeout,
                                user_data,
                                response: leb128::FramedInProgress::new(128 * 1024 * 1024), // TODO: proper max size
                            };
                            let substream_id = substream.id();
                            let _already_closed = substream.close();
                            debug_assert!(_already_closed.is_none());
                            substream = self.yamux.substream_by_id(substream_id).unwrap();
                        }
                        Ok((multistream_select::Negotiation::NotAvailable, ..)) => {
                            substream.reset();
                            return Some(Event::Response {
                                id: substream_id,
                                user_data,
                                response: Err(RequestError::ProtocolNotAvailable),
                            });
                        }
                        Err(err) => {
                            substream.reset();
                            return Some(Event::Response {
                                id: substream_id,
                                user_data,
                                response: Err(RequestError::NegotiationError(err)),
                            });
                        }
                    }
                }
                Substream::RequestOut {
                    timeout,
                    user_data,
                    response,
                } => {
                    match response.update(&data) {
                        Ok((_num_read, leb128::Framed::Finished(response))) => {
                            // TODO: proper state transition
                            *substream.user_data() = Substream::NegotiationFailed;
                            return Some(Event::Response {
                                id: substream_id,
                                user_data,
                                response: Ok(response),
                            });
                        }
                        Ok((num_read, leb128::Framed::InProgress(response))) => {
                            debug_assert_eq!(num_read, data.len());
                            data = &data[num_read..];
                            *substream.user_data() = Substream::RequestOut {
                                timeout,
                                user_data,
                                response,
                            };
                        }
                        Err(err) => {
                            substream.reset();
                            return Some(Event::Response {
                                id: substream_id,
                                user_data,
                                response: Err(RequestError::ResponseLebError(err)),
                            });
                        }
                    }
                }
                Substream::RequestInRecv {
                    request,
                    protocol_index,
                } => {
                    match request.update(&data) {
                        Ok((_num_read, leb128::Framed::Finished(request))) => {
                            *substream.user_data() = Substream::RequestInSend;
                            return Some(Event::RequestIn {
                                id: substream_id,
                                protocol_index,
                                request,
                            });
                        }
                        Ok((num_read, leb128::Framed::InProgress(request))) => {
                            debug_assert_eq!(num_read, data.len());
                            data = &data[num_read..];
                            *substream.user_data() = Substream::RequestInRecv {
                                request,
                                protocol_index,
                            };
                        }
                        Err(_err) => {
                            substream.reset();
                            // TODO: report to user
                            todo!()
                        }
                    }
                }
                Substream::NotificationsInHandshake {
                    handshake,
                    protocol_index,
                } => match handshake.update(&data) {
                    Ok((num_read, leb128::Framed::Finished(handshake))) => {
                        *substream.user_data() = Substream::NotificationsInWait { protocol_index };
                        debug_assert_eq!(num_read, data.len());
                        return Some(Event::NotificationsInOpen {
                            id: substream_id,
                            protocol_index,
                            handshake,
                        });
                    }
                    Ok((num_read, leb128::Framed::InProgress(handshake))) => {
                        data = &data[num_read..];
                        *substream.user_data() = Substream::NotificationsInHandshake {
                            handshake,
                            protocol_index,
                        };
                    }
                    Err(_) => {
                        substream.reset();
                    }
                },
                Substream::NotificationsInWait { protocol_index } => {
                    // TODO: what to do with data?
                    data = &data[data.len()..];
                    *substream.user_data() = Substream::NotificationsInWait { protocol_index };
                }
                Substream::NotificationsIn {
                    mut next_notification,
                    protocol_index,
                    user_data,
                } => {
                    // TODO: rewrite this block to support sending one notification at a
                    // time

                    let mut notification = None;
                    let max_notification_size =
                        self.notifications_protocols[protocol_index].max_notification_size;

                    loop {
                        match next_notification.update(&data) {
                            Ok((num_read, leb128::Framed::Finished(notif))) => {
                                data = &data[num_read..];
                                next_notification =
                                    leb128::FramedInProgress::new(max_notification_size);
                                //assert!(notification.is_none()); // TODO: outside API doesn't support multiple notifications
                                notification = Some(notif);
                            }
                            Ok((num_read, leb128::Framed::InProgress(next))) => {
                                debug_assert_eq!(num_read, data.len());
                                next_notification = next;
                                break;
                            }
                            Err(_) => {
                                // TODO: report to user and all ; this is just a dummy
                                next_notification =
                                    leb128::FramedInProgress::new(max_notification_size);
                                break;
                            }
                        }
                    }

                    *substream.user_data() = Substream::NotificationsIn {
                        next_notification,
                        protocol_index,
                        user_data,
                    };

                    return Some(Event::NotificationIn {
                        id: substream_id,
                        notification: notification.unwrap(),
                    });
                }
                Substream::PingIn(mut payload) => {
                    // Inbound ping substream.
                    // The ping protocol consists in sending 32 bytes of data, which the
                    // remote has to send back.
                    // The `payload` field contains these 32 bytes being received.
                    while !data.is_empty() {
                        debug_assert!(payload.len() < 32);
                        payload.push(data[0]);
                        data = &data[1..];

                        if payload.len() == 32 {
                            substream.write(payload.to_vec());
                            payload.clear();
                        }
                    }

                    *substream.user_data() = Substream::PingIn(payload);
                }
                _ => todo!("other substream kind"),
            };
        }

        None
    }
}

impl<TNow, TSub> fmt::Debug for Substream<TNow, TSub>
where
    TSub: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Substream::Poisoned => f.debug_tuple("poisoned").finish(),
            Substream::InboundNegotiating { .. } => f.debug_tuple("inbound-negotiating").finish(),
            Substream::OutboundNegotiating { .. } => f.debug_tuple("outbound-negotiating").finish(),
            Substream::Open { .. } => f.debug_tuple("open").finish(),
            Substream::NegotiationFailed => f.debug_tuple("negotiation-failed").finish(),
        }
    }
}

/// Identifier of a request or a notifications substream.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubstreamId(yamux::SubstreamId);

/// Outcome of [`Established::read_write`].
#[must_use]
pub struct ReadWrite<TNow, TSub> {
    /// Connection object yielded back.
    pub connection: Established<TNow, TSub>,

    /// Number of bytes at the start of the incoming buffer that have been processed. These bytes
    /// should no longer be present the next time [`Established::read_write`] is called.
    pub read_bytes: usize,

    /// Number of bytes written to the outgoing buffer. These bytes should be sent out to the
    /// remote. The rest of the outgoing buffer is left untouched.
    pub written_bytes: usize,

    /// If `true`, the writing side the connection must be closed. Will always remain to `true`
    /// after it has been set.
    ///
    /// If, after calling [`Established::read_write`], the returned [`ReadWrite`] contains `true`
    /// here, and the inbound buffer is `None`, then the connection as a whole is useless and can
    /// be closed.
    pub write_close: bool,

    /// If `Some`, [`Established::read_write`] should be called again when the point in time
    /// reaches the value in the `Option`.
    pub wake_up_after: Option<TNow>,

    /// Event that happened on the connection.
    pub event: Option<Event<TSub>>,
}

/// Event that happened on the connection. See [`ReadWrite::event`].
#[must_use]
#[derive(Debug)]
pub enum Event<TSub> {
    /// Received a new incoming substream.
    ///
    /// The connection state machine can only have up to 1 new incoming substream at a time. This
    /// event indicates that the number of incoming substreams has switched to 1.
    ///
    /// The substream should either be accepted or refused by calling
    /// [`Established::accept_in_substream`] or [`Established::reject_in_substream`].
    ///
    /// The substream doesn't have any identifier assigned to it yet, as it will be assigned when
    /// it gets accepted.
    NewSubstreamIn,

    /// A substream has received some more data.
    // TODO: mention what to do in response to that
    DataIn {
        /// Identifier of the substream that has received data.
        id: SubstreamId,
    },

    /// Remote has reset a substream. No more data will arrive on this substream and it is
    /// instantenously closed on both sides.
    SubstreamReset {
        /// Identifier of the substream that has been reset.
        /// This identifier is no longer valid.
        id: SubstreamId,

        /// User data that was associated to this substream.
        user_data: TSub,
    },

    /// A substream that was accepted with [`Established::accept_substream`] has finished
    /// negotiating its protocol.
    SubstreamInNegotiated {
        /// Identifier of the outbound substream whose negotiation is over.
        id: SubstreamId,

        /// Outcome of the negotiation. If the negotiation is successful, contains the name of the
        /// negotiated protocol and the substream can now be used. If the negotiation has failed,
        /// the substream is automatically closed and should be considered as reset for
        /// API-related purposes.
        result: Result<String, ()>,
    },

    /// A substream that was opened with [`Established::open_substream`] has finished negotiating
    /// its protocol.
    SubstreamOutNegotiated {
        /// Identifier of the outbound substream whose negotiation is over.
        id: SubstreamId,

        /// Outcome of the negotiation. If the negotiation is successful, the substream can now be
        /// used. If the negotiation has failed, the substream is automatically closed and should
        /// be considered as reset for API-related purposes.
        result: Result<(), ()>,
    },
}

/// Error during a connection. The connection should be shut down.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// Error in the noise cipher. Data has most likely been corrupted.
    Noise(noise::CipherError),
    /// Error in the yamux multiplexing protocol.
    Yamux(yamux::Error),
}

/// Error that can happen during a request in a request-response scheme.
#[derive(Debug, derive_more::Display)]
pub enum RequestError {
    /// Remote hasn't answered in time.
    Timeout,
    /// Remote doesn't support this protocol.
    ProtocolNotAvailable,
    /// Remote has decided to close the substream. This most likely indicates that the remote
    /// is unwilling the respond to the request.
    SubstreamClosed,
    /// Remote has decided to RST the substream. This most likely indicates that the remote has
    /// detected a protocol error.
    SubstreamReset,
    /// Error during protocol negotiation.
    NegotiationError(multistream_select::Error),
    /// Error while receiving the response.
    ResponseLebError(leb128::FramedError),
}

/// Successfully negotiated connection. Ready to be turned into a [`Established`].
pub struct ConnectionPrototype {
    encryption: noise::Noise,
}

impl ConnectionPrototype {
    /// Builds a new [`ConnectionPrototype`] of a connection using the Noise and Yamux protocols.
    pub(crate) fn from_noise_yamux(encryption: noise::Noise) -> Self {
        ConnectionPrototype { encryption }
    }

    /// Turns this prototype into an actual connection.
    pub fn into_connection<TNow, TSub>(self, config: Config) -> Established<TNow, TSub> {
        let yamux = yamux::Yamux::new(yamux::Config {
            is_initiator: self.encryption.is_initiator(),
            capacity: 64, // TODO: ?
            randomness_seed: config.randomness_seed,
        });

        Established {
            encryption: self.encryption,
            inner: Inner {
                yamux,
                next_timeout: None,
            },
        }
    }
}

impl fmt::Debug for ConnectionPrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ConnectionPrototype").finish()
    }
}

/// Configuration to turn a [`ConnectionPrototype`] into a [`Established`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Entropy used for the randomness specific to this connection.
    pub randomness_seed: [u8; 32],
}
