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

// TODO: needs docs

use super::{
    super::super::read_write::ReadWrite, substream, Config, ConfigNotifications,
    ConfigRequestResponse, ConfigRequestResponseIn, Event, SubstreamId, SubstreamIdInner,
};
use crate::util::{self, protobuf};

use alloc::{collections::VecDeque, string::String, vec, vec::Vec};
use core::{
    cmp, fmt,
    hash::Hash,
    iter,
    ops::{Add, Sub},
    time::Duration,
};
use rand::{Rng as _, SeedableRng as _};

/// State machine of a fully-established connection where substreams are handled externally.
pub struct MultiStream<TNow, TSubId, TRqUd, TNotifUd> {
    /// Events that should be yielded from [`MultiStream::pull_event`].
    pending_events: VecDeque<Event<TRqUd, TNotifUd>>,

    /// List of all open substreams, both inbound and outbound.
    ///
    /// There are two substreams namespaces: "out substreams", used for API purposes when it comes
    /// to notifications and requests, and "in substreams", used for API purposes when it comes to
    /// raw data sent/received on a substream. When the user for example resets an "in substream",
    /// the "out substream" remains valid.
    in_substreams:
        hashbrown::HashMap<TSubId, Substream<TNow, TRqUd, TNotifUd>, util::SipHasherBuild>,

    out_in_substreams_map: hashbrown::HashMap<u32, TSubId, fnv::FnvBuildHasher>,

    next_out_substream_id: u32,

    /// List of outgoing substreams that aren't opened yet.
    ///
    /// Every time an outgoing substream is opened, an item is pulled from this list.
    ///
    /// Does not include the ping substream.
    desired_out_substreams: VecDeque<Substream<TNow, TRqUd, TNotifUd>>,

    /// Substream used for outgoing pings.
    ///
    /// Initially contains `None` as the substream for pings isn't opened yet.
    ///
    /// Because of the API of [`substream::Substream`] concerning pings, there is no need to
    /// handle situations where the substream fails to negotiate, as this is handled by making
    /// outgoing pings error. This substream is therefore constant.
    ping_substream: Option<TSubId>,
    /// When to start the next ping attempt.
    next_ping: TNow,
    /// Source of randomness to generate ping payloads.
    ///
    /// Note that we use ChaCha20 because the rest of the code base also uses ChaCha20. This avoids
    /// unnecessary code being included in the binary and reduces the binary size.
    ping_payload_randomness: rand_chacha::ChaCha20Rng,

    /// See [`Config::max_inbound_substreams`].
    // TODO: not enforced at the moment
    _max_inbound_substreams: usize,
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
}

struct Substream<TNow, TRqUd, TNotifUd> {
    id: u32,
    /// Underlying state machine for the substream. Always `Some` while the substream is alive,
    /// and `None` if it has been reset.
    inner: Option<substream::Substream<TNow, TRqUd, TNotifUd>>,
    /// All incoming data is first transferred to this buffer.
    // TODO: this is very suboptimal code, instead the parsing should be done in a streaming way
    read_buffer: Vec<u8>,
    /// The buffer within `read_buffer` might contain a full Protobuf frame, but not all of the
    /// data within that frame was processed by the underlying substream.
    /// Contains the number of bytes of the message in `read_buffer` that the substream state
    /// machine has already processed.
    read_buffer_partial_read: usize,
    remote_writing_side_closed: bool,
    local_writing_side_closed: bool,
}

const MAX_PENDING_EVENTS: usize = 4;

impl<TNow, TSubId, TRqUd, TNotifUd> MultiStream<TNow, TSubId, TRqUd, TNotifUd>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
    TSubId: Clone + PartialEq + Eq + Hash,
{
    /// Creates a new connection from the given configuration.
    pub fn new(config: Config<TNow>) -> MultiStream<TNow, TSubId, TRqUd, TNotifUd> {
        // TODO: check conflicts between protocol names?

        // We expect at maximum one parallel request per protocol, plus one substream per direction
        // (in and out) per notification substream, plus one ping substream per direction.
        let num_expected_substreams =
            config.request_protocols.len() + config.notifications_protocols.len() * 2 + 2;

        let mut randomness = rand_chacha::ChaCha20Rng::from_seed(config.randomness_seed);

        MultiStream {
            pending_events: {
                // Note that the capacity is higher than `MAX_PENDING_EVENTS` because resetting
                // substreams can unconditionally queue an event, and the API doesn't give the
                // possibility to not reset a substream (as that would introduce too much
                // complexity). For this reason, we reserve enough for the events that can happen
                // by reading/writing substreams plus events that can happen by resetting
                // substreams.
                let cap = MAX_PENDING_EVENTS + num_expected_substreams;
                VecDeque::with_capacity(cap)
            },
            in_substreams: hashbrown::HashMap::with_capacity_and_hasher(
                num_expected_substreams,
                util::SipHasherBuild::new(randomness.sample(rand::distributions::Standard)),
            ),
            out_in_substreams_map: hashbrown::HashMap::with_capacity_and_hasher(
                num_expected_substreams,
                Default::default(),
            ),
            next_out_substream_id: 0,
            desired_out_substreams: VecDeque::with_capacity(num_expected_substreams),
            ping_substream: None,
            next_ping: config.first_out_ping,
            ping_payload_randomness: randomness,
            _max_inbound_substreams: config.max_inbound_substreams,
            request_protocols: config.request_protocols,
            notifications_protocols: config.notifications_protocols,
            ping_protocol: config.ping_protocol,
            ping_interval: config.ping_interval,
            ping_timeout: config.ping_timeout,
        }
    }

    /// Removes an event from the queue of events and returns it.
    ///
    /// This method should be called after [`MultiStream::substream_read_write`] or
    /// [`MultiStream::reset_substream`] is called.
    pub fn pull_event(&mut self) -> Option<Event<TRqUd, TNotifUd>> {
        self.pending_events.pop_front()
    }

    /// Returns the number of new outbound substreams that the state machine would like to see
    /// opened.
    ///
    /// This value doesn't change automatically over time but only after a call to
    /// [`MultiStream::substream_read_write`], [`MultiStream::add_substream`],
    /// [`MultiStream::reset_substream`], [`MultiStream::add_request`], or
    /// [`MultiStream::open_notifications_substream`].
    ///
    /// Note that the user is expected to track the number of substreams that are currently being
    /// opened. For example, if this function returns 2 and there are already 2 substreams
    /// currently being opened, then there is no need to open any additional one.
    pub fn desired_outbound_substreams(&self) -> u32 {
        u32::try_from(self.desired_out_substreams.len())
            .unwrap_or(u32::max_value())
            .saturating_add(if self.ping_substream.is_none() { 1 } else { 0 })
    }

    /// Notifies the state machine that a new substream has been opened.
    ///
    /// `outbound` indicates whether the substream has been opened by the remote (`false`) or
    /// locally (`true`).
    ///
    /// If `outbound` is `true`, then the value returned by
    /// [`MultiStream::desired_outbound_substreams`] will decrease by one.
    ///
    /// # Panic
    ///
    /// Panics if there already exists a substream with an identical identifier.
    ///
    pub fn add_substream(&mut self, id: TSubId, outbound: bool) {
        let substream = if !outbound {
            let out_substream_id = self.next_out_substream_id;
            self.next_out_substream_id += 1;

            let supported_protocols = self
                .request_protocols
                .iter()
                .filter(|p| p.inbound_allowed)
                .map(|p| p.name.clone())
                .chain(self.notifications_protocols.iter().map(|p| p.name.clone()))
                .chain(iter::once(self.ping_protocol.clone()))
                .collect::<Vec<_>>();

            Substream {
                id: out_substream_id,
                inner: Some(substream::Substream::ingoing(supported_protocols)),
                read_buffer: Vec::new(),
                read_buffer_partial_read: 0,
                local_writing_side_closed: false,
                remote_writing_side_closed: false,
            }
        } else if self.ping_substream.is_none() {
            let out_substream_id = self.next_out_substream_id;
            self.next_out_substream_id += 1;

            self.ping_substream = Some(id.clone());

            Substream {
                id: out_substream_id,
                inner: Some(substream::Substream::ping_out(self.ping_protocol.clone())),
                read_buffer: Vec::new(),
                read_buffer_partial_read: 0,
                local_writing_side_closed: false,
                remote_writing_side_closed: false,
            }
        } else if let Some(desired) = self.desired_out_substreams.pop_front() {
            desired
        } else {
            // TODO: reset the new substream
            todo!()
        };

        let _prev_val = self.out_in_substreams_map.insert(substream.id, id.clone());
        debug_assert!(_prev_val.is_none());

        let previous_value = self.in_substreams.insert(id, substream);
        if previous_value.is_some() {
            // There is already a substream with that identifier. This is forbidden by the API of
            // this function.
            panic!()
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
        let substream = self.in_substreams.remove(substream_id).unwrap();
        let _was_in = self.out_in_substreams_map.remove(&substream.id);
        debug_assert!(!_was_in.is_some());

        if Some(substream_id) == self.ping_substream.as_ref() {
            self.ping_substream = None;
        }

        let maybe_event = substream.inner.unwrap().reset();
        if let Some(event) = maybe_event {
            Self::on_substream_event(&mut self.pending_events, substream.id, event);
        }
    }

    /// Reads/writes data on the substream.
    ///
    /// If the method returns `true`, then the substream is now considered dead according to the
    /// state machine and its identifier is now invalid. If the reading or writing side of the
    /// substream was still open, then the user should reset that substream.
    ///
    /// This method will refuse to accept data if too many events are already queued. Use
    /// [`MultiStream::pull_event`] to empty the queue of events between calls to this method.
    ///
    /// # Panic
    ///
    /// Panics if there is no substream with that identifier.
    ///
    // TODO: clarify docs to explain that in the case of WebRTC the reading and writing sides never close, and substream can only ever reset
    pub fn substream_read_write(
        &mut self,
        substream_id: &TSubId,
        read_write: &'_ mut ReadWrite<'_, TNow>,
    ) -> bool {
        let mut substream = self.in_substreams.get_mut(substream_id).unwrap();

        // Reading/writing the ping substream is used to queue new outgoing pings.
        if Some(substream_id) == self.ping_substream.as_ref() {
            if read_write.now >= self.next_ping {
                let payload = self
                    .ping_payload_randomness
                    .sample(rand::distributions::Standard);
                substream
                    .inner
                    .as_mut()
                    .unwrap()
                    .queue_ping(&payload, read_write.now.clone() + self.ping_timeout);
                self.next_ping = read_write.now.clone() + self.ping_interval;
            }

            read_write.wake_up_after(&self.next_ping);
        }

        // TODO: make it explicit in the API that this is indeed the WebRTC protocol, as almost everything below is WebRTC-specific

        loop {
            // Don't process any more data before events are pulled.
            if self.pending_events.len() >= MAX_PENDING_EVENTS {
                return false;
            }

            // In the situation where there's not enough space in the outgoing buffer to write an
            // outgoing Protobuf frame, we just return immediately.
            // This is necessary because calling `substream.read_write` can generate a write
            // close message.
            // TODO: this is error-prone, as we have no guarantee that the outgoing buffer will ever be > 6 bytes, for example in principle the API user could decide to use only a write buffer of 2 bytes, although that would be a very stupid thing to do
            if read_write.outgoing_buffer_available() < 6 {
                return false;
            }

            // If this flag is still `false` at the end of the loop, we break out of it.
            let mut continue_looping = false;

            // The incoming data is not directly the data of the substream. Instead, everything
            // is wrapped within a Protobuf frame. For this reason, we first transfer the data to
            // a buffer.
            //
            // According to the libp2p WebRTC spec, a frame and its length prefix must not be
            // larger than 16kiB, meaning that the read buffer never has to exceed this size.
            // TODO: this is very suboptimal; improve
            if let Some(incoming_buffer) = read_write.incoming_buffer {
                // TODO: reset the substream if `remote_writing_side_closed`
                let max_to_transfer =
                    cmp::min(incoming_buffer.len(), 16384 - substream.read_buffer.len());
                substream
                    .read_buffer
                    .extend_from_slice(&incoming_buffer[..max_to_transfer]);
                debug_assert!(substream.read_buffer.len() <= 16384);
                if max_to_transfer != incoming_buffer.len() {
                    continue_looping = true;
                }
                read_write.advance_read(max_to_transfer);
            }

            // Try to parse the content of `self.read_buffer`.
            // If the content of `self.read_buffer` is an incomplete frame, the flags will be
            // `None` and the message will be `&[]`.
            let (protobuf_frame_size, flags, message_within_frame) = {
                let mut parser = nom::combinator::complete::<_, _, nom::error::Error<&[u8]>, _>(
                    nom::combinator::map_parser(
                        nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                        protobuf::message_decode! {
                            #[optional] flags = 1 => protobuf::enum_tag_decode,
                            #[optional] message = 2 => protobuf::bytes_tag_decode,
                        },
                    ),
                );

                match nom::Finish::finish(parser(&substream.read_buffer)) {
                    Ok((rest, framed_message)) => {
                        let protobuf_frame_size = substream.read_buffer.len() - rest.len();
                        (
                            protobuf_frame_size,
                            framed_message.flags,
                            framed_message.message.unwrap_or(&[][..]),
                        )
                    }
                    Err(err) if err.code == nom::error::ErrorKind::Eof => {
                        // TODO: reset the substream if incoming_buffer is full, as it means that the frame is too large, and remove the debug_assert below
                        debug_assert!(substream.read_buffer.len() < 16384);
                        (0, None, &[][..])
                    }
                    Err(_) => {
                        // Message decoding error.
                        // TODO: no, must ask the state machine to reset
                        return true;
                    }
                }
            };

            let event = if protobuf_frame_size != 0
                && message_within_frame.len() <= substream.read_buffer_partial_read
            {
                // If the substream state machine has already processed all the data within
                // `read_buffer`, process the flags of the current protobuf frame, discard that
                // protobuf frame, and loop again.
                continue_looping = true;

                // Discard the data.
                substream.read_buffer_partial_read = 0;
                substream.read_buffer = substream
                    .read_buffer
                    .split_at(protobuf_frame_size)
                    .1
                    .to_vec();

                // Process the flags.
                // Note that the `STOP_SENDING` flag is ignored.

                // If the remote has sent a `FIN` or `RESET_STREAM` flag, mark the remote writing
                // side as closed.
                if flags.map_or(false, |f| f == 0 || f == 2) {
                    substream.remote_writing_side_closed = true;
                }

                // If the remote has sent a `RESET_STREAM` flag, also reset the substream.
                if flags.map_or(false, |f| f == 2) {
                    substream.inner.take().unwrap().reset()
                } else {
                    None
                }
            } else {
                // We allocate a buffer where the substream state machine will temporarily write
                // out its data. The size of the buffer is capped in order to prevent the substream
                // from generating data that wouldn't fit in a single protobuf frame.
                let mut intermediary_write_buffer =
                    vec![
                        0;
                        cmp::min(read_write.outgoing_buffer_available(), 16384).saturating_sub(10)
                    ]; // TODO: this -10 calculation is hacky because we need to account for the variable length prefixes everywhere

                let mut sub_read_write = ReadWrite {
                    now: read_write.now.clone(),
                    incoming_buffer: if substream.remote_writing_side_closed {
                        None
                    } else {
                        Some(&message_within_frame[substream.read_buffer_partial_read..])
                    },
                    outgoing_buffer: if substream.local_writing_side_closed {
                        None
                    } else {
                        Some((&mut intermediary_write_buffer, &mut []))
                    },
                    read_bytes: 0,
                    written_bytes: 0,
                    wake_up_after: None,
                };

                let (substream_update, event) = substream
                    .inner
                    .take()
                    .unwrap()
                    .read_write(&mut sub_read_write);

                substream.inner = substream_update;
                substream.read_buffer_partial_read += sub_read_write.read_bytes;
                if let Some(wake_up_after) = &sub_read_write.wake_up_after {
                    read_write.wake_up_after(wake_up_after)
                }

                // Continue looping as the substream might have more data to read or write.
                if sub_read_write.read_bytes != 0 || sub_read_write.written_bytes != 0 {
                    continue_looping = true;
                }

                // Determine whether we should send a message on that substream with a specific
                // flag.
                let flag_to_write_out = if substream.inner.is_none()
                    && (!substream.remote_writing_side_closed
                        || sub_read_write.outgoing_buffer.is_some())
                {
                    // Send a `RESET_STREAM` if the state machine has reset while a side was still
                    // open.
                    Some(2)
                } else if !substream.local_writing_side_closed
                    && sub_read_write.outgoing_buffer.is_none()
                {
                    // Send a `FIN` if the state machine has closed the writing side while it
                    // wasn't closed before.
                    substream.local_writing_side_closed = true;
                    Some(0)
                } else {
                    None
                };

                // Send out message.
                if flag_to_write_out.is_some() || sub_read_write.written_bytes != 0 {
                    let written_bytes = sub_read_write.written_bytes;
                    drop(sub_read_write);

                    debug_assert!(written_bytes <= intermediary_write_buffer.len());

                    let protobuf_frame = {
                        let flag_out = flag_to_write_out
                            .into_iter()
                            .flat_map(|f| protobuf::enum_tag_encode(1, f));
                        let message_out = if written_bytes != 0 {
                            Some(&intermediary_write_buffer[..written_bytes])
                        } else {
                            None
                        }
                        .into_iter()
                        .flat_map(|m| protobuf::bytes_tag_encode(2, m));
                        flag_out
                            .map(either::Left)
                            .chain(message_out.map(either::Right))
                    };

                    let protobuf_frame_len = protobuf_frame.clone().fold(0, |mut l, b| {
                        l += AsRef::<[u8]>::as_ref(&b).len();
                        l
                    });

                    // The spec mentions that a frame plus its length prefix shouldn't exceed
                    // 16kiB. This is normally ensured by forbidding the substream from writing
                    // more data than would fit in 16kiB.
                    debug_assert!(protobuf_frame_len <= 16384);
                    debug_assert!(
                        util::leb128::encode_usize(protobuf_frame_len).count() + protobuf_frame_len
                            <= 16384
                    );
                    for byte in util::leb128::encode_usize(protobuf_frame_len) {
                        read_write.write_out(&[byte]);
                    }
                    for buffer in protobuf_frame {
                        read_write.write_out(AsRef::<[u8]>::as_ref(&buffer));
                    }

                    // We continue looping because the substream might have more data to send.
                    continue_looping = true;
                }

                event
            };

            match event {
                None => {}

                Some(substream::Event::InboundNegotiated(protocol)) => {
                    continue_looping = true;

                    if protocol == self.ping_protocol {
                        substream
                            .inner
                            .as_mut()
                            .unwrap()
                            .set_inbound_ty(substream::InboundTy::Ping);
                    } else if let Some(protocol_index) = self
                        .request_protocols
                        .iter()
                        .position(|p| p.name == protocol)
                    {
                        substream.inner.as_mut().unwrap().set_inbound_ty(
                            substream::InboundTy::Request {
                                protocol_index,
                                request_max_size: if let ConfigRequestResponseIn::Payload {
                                    max_size,
                                } =
                                    self.request_protocols[protocol_index].inbound_config
                                {
                                    Some(max_size)
                                } else {
                                    None
                                },
                            },
                        );
                    } else if let Some(protocol_index) = self
                        .notifications_protocols
                        .iter()
                        .position(|p| p.name == protocol)
                    {
                        substream.inner.as_mut().unwrap().set_inbound_ty(
                            substream::InboundTy::Notifications {
                                protocol_index,
                                max_handshake_size: self.notifications_protocols[protocol_index]
                                    .max_handshake_size,
                            },
                        );
                    } else {
                        unreachable!();
                    }
                }

                Some(other) => {
                    continue_looping = true;
                    Self::on_substream_event(&mut self.pending_events, substream.id, other)
                }
            }

            if substream.inner.is_none() {
                if Some(substream_id) == self.ping_substream.as_ref() {
                    self.ping_substream = None;
                }
                self.out_in_substreams_map.remove(&substream.id);
                self.in_substreams.remove(&substream_id);
                break true;
            } else if !continue_looping {
                break false;
            }
        }
    }

    /// Turns an event from the [`substream`] module into an [`Event`] and adds it to the queue.
    ///
    /// # Panics
    ///
    /// Intentionally panics on [`substream::Event::InboundNegotiated`]. Please handle this
    /// variant separately.
    ///
    fn on_substream_event(
        pending_events: &mut VecDeque<Event<TRqUd, TNotifUd>>,
        substream_id: u32,
        event: substream::Event<TRqUd, TNotifUd>,
    ) {
        pending_events.push_back(match event {
            substream::Event::InboundNegotiated(_) => panic!(),
            substream::Event::InboundError(error) => Event::InboundError(error),
            substream::Event::RequestIn {
                protocol_index,
                request,
            } => Event::RequestIn {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                protocol_index,
                request,
            },
            substream::Event::Response {
                response,
                user_data,
            } => Event::Response {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                response,
                user_data,
            },
            substream::Event::NotificationsInOpen {
                protocol_index,
                handshake,
            } => Event::NotificationsInOpen {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                protocol_index,
                handshake,
            },
            substream::Event::NotificationsInOpenCancel => Event::NotificationsInOpenCancel {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
            },
            substream::Event::NotificationIn { notification } => Event::NotificationIn {
                notification,
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
            },
            substream::Event::NotificationsInClose { outcome } => Event::NotificationsInClose {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                outcome,
            },
            substream::Event::NotificationsOutResult { result } => Event::NotificationsOutResult {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                result,
            },
            substream::Event::NotificationsOutCloseDemanded => {
                Event::NotificationsOutCloseDemanded {
                    id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                }
            }
            substream::Event::NotificationsOutReset { user_data } => Event::NotificationsOutReset {
                id: SubstreamId(SubstreamIdInner::MultiStream(substream_id)),
                user_data,
            },
            substream::Event::PingOutSuccess => Event::PingOutSuccess,
            substream::Event::PingOutError { .. } => {
                // Because ping events are automatically generated by the external API without any
                // guarantee, it is safe to merge multiple failed pings into one.
                Event::PingOutFailed
            }
        });
    }

    /// Sends a request to the remote.
    ///
    /// Must pass the index of the protocol within [`Config::request_protocols`].
    ///
    /// This method only inserts the request into the connection object. The request will later
    /// be sent out through [`MultiStream::substream_read_write`].
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
    pub fn add_request(
        &mut self,
        protocol_index: usize,
        request: Vec<u8>,
        timeout: TNow,
        user_data: TRqUd,
    ) -> SubstreamId {
        let has_length_prefix = match self.request_protocols[protocol_index].inbound_config {
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

        let substream_id = self.next_out_substream_id;
        self.next_out_substream_id += 1;

        self.desired_out_substreams.push_back(Substream {
            id: substream_id,
            inner: Some(substream::Substream::request_out(
                self.request_protocols[protocol_index].name.clone(), // TODO: clone :-/
                timeout,
                if has_length_prefix {
                    Some(request)
                } else {
                    None
                },
                self.request_protocols[protocol_index].max_response_size,
                user_data,
            )),
            read_buffer: Vec::new(),
            read_buffer_partial_read: 0,
            local_writing_side_closed: false,
            remote_writing_side_closed: false,
        });

        // TODO: ? do this? substream.reserve_window(128 * 1024 * 1024 + 128); // TODO: proper max size

        SubstreamId(SubstreamIdInner::MultiStream(substream_id))
    }

    /// Returns the user data associated to a notifications substream.
    ///
    /// Returns `None` if the substream doesn't exist or isn't a notifications substream.
    pub fn notifications_substream_user_data_mut(
        &mut self,
        id: SubstreamId,
    ) -> Option<&mut TNotifUd> {
        let id = match id.0 {
            SubstreamIdInner::MultiStream(id) => id,
            _ => return None,
        };

        let inner_substream_id = self.out_in_substreams_map.get(&id).unwrap();

        self.in_substreams
            .get_mut(inner_substream_id)
            .unwrap()
            .inner
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
    /// This method only inserts the opening handshake into the connection object. The handshake
    /// will later be sent out through [`MultiStream::substream_read_write`].
    ///
    /// Assuming that the remote is using the same implementation, an
    /// [`Event::NotificationsInOpen`] will be generated on its side.
    ///
    pub fn open_notifications_substream(
        &mut self,
        now: TNow,
        protocol_index: usize,
        handshake: Vec<u8>,
        user_data: TNotifUd,
    ) -> SubstreamId {
        let max_handshake_size = self.notifications_protocols[protocol_index].max_handshake_size;

        // TODO: turn this assert into something that can't panic?
        assert!(handshake.len() <= max_handshake_size);

        let timeout = now + Duration::from_secs(20); // TODO:

        let substream_id = self.next_out_substream_id;
        self.next_out_substream_id += 1;

        self.desired_out_substreams.push_back(Substream {
            id: substream_id,
            inner: Some(substream::Substream::notifications_out(
                timeout,
                self.notifications_protocols[protocol_index].name.clone(), // TODO: clone :-/,
                handshake,
                max_handshake_size,
                user_data,
            )),
            read_buffer: Vec::new(),
            read_buffer_partial_read: 0,
            local_writing_side_closed: false,
            remote_writing_side_closed: false,
        });

        SubstreamId(SubstreamIdInner::MultiStream(substream_id))
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
            SubstreamIdInner::MultiStream(id) => id,
            _ => panic!(),
        };

        let inner_substream_id = self.out_in_substreams_map.get(&substream_id).unwrap();

        let max_notification_size = 16 * 1024 * 1024; // TODO: hack
                                                      // TODO: self.notifications_protocols[protocol_index].max_notification_size;
        self.in_substreams
            .get_mut(inner_substream_id)
            .unwrap()
            .inner
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
            SubstreamIdInner::MultiStream(id) => id,
            _ => panic!(),
        };

        // TODO: can panic if pending event hasn't been processed
        let inner_substream_id = self.out_in_substreams_map.get(&substream_id).unwrap();

        self.in_substreams
            .get_mut(inner_substream_id)
            .unwrap()
            .inner
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
    /// determined by calling [`MultiStream::notification_substream_queued_bytes`]) is below a
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
            SubstreamIdInner::MultiStream(id) => id,
            _ => panic!(),
        };

        let inner_substream_id = self.out_in_substreams_map.get(&substream_id).unwrap();

        self.in_substreams
            .get_mut(inner_substream_id)
            .unwrap()
            .inner
            .as_mut()
            .unwrap()
            .write_notification_unbounded(notification);
    }

    /// Returns the number of bytes waiting to be sent out on that substream.
    ///
    /// See the documentation of [`MultiStream::write_notification_unbounded`] for context.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] doesn't correspond to a notifications substream, or if the
    /// notifications substream isn't in the appropriate state.
    ///
    pub fn notification_substream_queued_bytes(&self, substream_id: SubstreamId) -> usize {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::MultiStream(id) => id,
            _ => panic!(),
        };

        let inner_substream_id = self.out_in_substreams_map.get(&substream_id).unwrap();

        self.in_substreams
            .get(inner_substream_id)
            .unwrap()
            .inner
            .as_ref()
            .unwrap()
            .notification_substream_queued_bytes()
    }

    /// Closes a notifications substream opened after a successful
    /// [`Event::NotificationsOutResult`] or that was accepted using
    /// [`MultiStream::accept_in_notifications_substream`].
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
            SubstreamIdInner::MultiStream(id) => id,
            _ => panic!(),
        };

        let inner_substream_id = self.out_in_substreams_map.get(&substream_id).unwrap();

        self.in_substreams
            .get_mut(inner_substream_id)
            .unwrap()
            .inner
            .as_mut()
            .unwrap()
            .close_notifications_substream();
    }

    /// Responds to an incoming request. Must be called in response to a [`Event::RequestIn`].
    ///
    /// Returns an error if the [`SubstreamId`] is invalid.
    pub fn respond_in_request(
        &mut self,
        substream_id: SubstreamId,
        response: Result<Vec<u8>, ()>,
    ) -> Result<(), substream::RespondInRequestError> {
        let substream_id = match substream_id.0 {
            SubstreamIdInner::MultiStream(id) => id,
            _ => return Err(substream::RespondInRequestError::SubstreamClosed),
        };

        let inner_substream_id = self.out_in_substreams_map.get(&substream_id).unwrap();

        self.in_substreams
            .get_mut(inner_substream_id)
            .ok_or(substream::RespondInRequestError::SubstreamClosed)?
            .inner
            .as_mut()
            .unwrap()
            .respond_in_request(response)
    }
}

impl<TNow, TSubId, TRqUd, TNotifUd> fmt::Debug for MultiStream<TNow, TSubId, TRqUd, TNotifUd> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Established").finish()
    }
}
