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

//! Yamux multiplexing protocol.
//!
//! The Yamux protocol is a multiplexing protocol. As such, it allows dividing a single stream of
//! data, typically a TCP socket, into multiple individual parallel substreams. The data sent and
//! received over that single stream is divided into frames which, with the exception of `ping`
//! and `goaway` frames, belong to a specific substream. In other words, the data transmitted
//! over the substreams is interleaved.
//!
//! Specification available at <https://github.com/hashicorp/yamux/blob/master/spec.md>
//!
//! # Usage
//!
//! The [`Yamux`] object holds the state of all yamux-specific information, and the list of
//! all currently-open substreams.
//!
//! The generic parameter of [`Yamux`] is an opaque "user data" associated to each substream.
//!

// TODO: more documentation

use crate::{
    libp2p::read_write::{self, ReadWrite},
    util::SipHasherBuild,
};

use alloc::{
    boxed::Box,
    collections::{BTreeSet, VecDeque},
    vec::Vec,
};
use core::{cmp, fmt, mem, num::NonZero, ops};
use rand::seq::IteratorRandom as _;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore as _, SeedableRng as _},
};

pub use header::GoAwayErrorCode;

mod header;
mod tests;

/// Name of the protocol, typically used when negotiated it using *multistream-select*.
pub const PROTOCOL_NAME: &str = "/yamux/1.0.0";

/// Configuration for a new [`Yamux`].
#[derive(Debug)]
pub struct Config {
    /// `true` if the local machine has initiated the connection. Otherwise, `false`.
    pub is_initiator: bool,

    /// Expected number of substreams simultaneously open, both inbound and outbound substreams
    /// combined.
    pub capacity: usize,

    /// Seed used for the randomness. Used to avoid HashDoS attack and determines the order in
    /// which the data on substreams is sent out.
    pub randomness_seed: [u8; 32],

    /// Maximum size of data frames to send out.
    ///
    /// A higher value increases the variance of the latency of the data sent on the substreams,
    /// which is undesirable. A lower value increases the overhead of the Yamux protocol. This
    /// overhead is equal to `1200 / (max_out_data_frame_size + 12)` per cent, for example setting
    /// `max_out_data_frame_size` to 24 incurs a `33%` overhead.
    ///
    /// The "best" value depends on the bandwidth speed of the underlying connection, and is thus
    /// impossible to tell.
    ///
    /// A typical value is `8192`.
    pub max_out_data_frame_size: NonZero<u32>,

    /// When the remote sends a ping, we need to send out a pong. However, the remote could refuse
    /// to read any additional data from the socket and continue sending pings, thus increasing
    /// the local buffer size indefinitely. In order to protect against this attack, there exists
    /// a maximum number of queued pongs, after which the connection will be shut down abruptly.
    pub max_simultaneous_queued_pongs: NonZero<usize>,

    /// When the remote sends a substream, and this substream gets rejected by the API user, some
    /// data needs to be sent out. However, the remote could refuse reading any additional data
    /// and continue sending new substream requests, thus increasing the local buffer size
    /// indefinitely. In order to protect against this attack, there exists a maximum number of
    /// queued substream rejections after which the connection will be shut down abruptly.
    pub max_simultaneous_rst_substreams: NonZero<usize>,
}

/// Yamux state machine. See [the module-level documentation](..) for more information.
pub struct Yamux<TNow, TSub> {
    /// The actual fields are wrapped in a `Box` because the `Yamux` object is moved around pretty
    /// often.
    inner: Box<YamuxInner<TNow, TSub>>,
}

struct YamuxInner<TNow, TSub> {
    /// List of substreams currently open in the Yamux state machine.
    ///
    /// A `SipHasher` is used in order to avoid hash collision attacks on substream IDs.
    substreams: hashbrown::HashMap<NonZero<u32>, Substream<TNow, TSub>, SipHasherBuild>,

    /// Subset of the content of [`YamuxInner::substreams`] that is considered "dead", meaning
    /// that it is returned by [`Yamux::dead_substreams`].
    dead_substreams: hashbrown::HashSet<NonZero<u32>, SipHasherBuild>,

    /// Subset of the content of [`YamuxInner::substreams`] that requires some process because
    /// they have data in their read buffer or their `wake_up_after` value is reached.
    ///
    /// All the substreams are always in the "healthy" state.
    ///
    /// Keys are the time after which this substream should be processed, which can be inferior or
    /// equal to "now" for an immediate wake up. A key equal to `None` means "right now".
    substreams_wake_up: BTreeSet<(Option<TNow>, NonZero<u32>)>,

    /// List of substreams that might want to write out additional data. Processed when it is
    /// possible to send out data.
    ///
    /// All the substreams are always in the "healthy" state.
    ///
    /// Contrary to [`YamuxInner::substreams_wake_up`], the substreams in this list are processed
    /// only if it is possible to queue out more data for sending.
    substreams_write_ready: hashbrown::HashSet<NonZero<u32>, SipHasherBuild>,

    /// List of window frames to send to the remote. For each substream, the amount of bytes to
    /// add to the window.
    window_frames_to_send: hashbrown::HashMap<NonZero<u32>, NonZero<u64>, SipHasherBuild>,

    /// Number of substreams within [`YamuxInner::substreams`] whose [`Substream::inbound`] is
    /// `true`.
    num_inbound: usize,

    /// `Some` if a `GoAway` frame has been received in the past.
    received_goaway: Option<GoAwayErrorCode>,

    /// Whether to send out a `GoAway` frame.
    outgoing_goaway: OutgoingGoAway,

    /// What kind of data is expected on the socket next.
    incoming: Incoming,

    /// What is currently being written out.
    outgoing: Outgoing,

    /// See [`Config::max_out_data_frame_size`].
    max_out_data_frame_size: NonZero<u32>,

    /// Id of the next outgoing substream to open.
    /// This implementation allocates identifiers linearly. Every time a substream is open, its
    /// value is incremented by two.
    next_outbound_substream: NonZero<u32>,

    /// Number of pings to send out that haven't been queued yet.
    pings_to_send: usize,

    /// List of pings that have been sent out but haven't been replied yet.
    pings_waiting_reply: VecDeque<u32>,

    /// List of opaque values corresponding to ping requests sent by the remote. For each entry,
    /// a PONG header should be sent to the remote.
    pongs_to_send: VecDeque<u32>,

    /// See [`Config::max_simultaneous_queued_pongs`].
    max_simultaneous_queued_pongs: NonZero<usize>,

    /// List of substream IDs that have been reset locally. For each entry, a RST header should
    /// be sent to the remote.
    rsts_to_send: VecDeque<NonZero<u32>>,

    /// See [`Config::max_simultaneous_rst_substreams`].
    max_simultaneous_rst_substreams: NonZero<usize>,

    /// Source of randomness used for various purposes.
    randomness: ChaCha20Rng,
}

struct Substream<TNow, TSub> {
    /// State of the substream.
    state: SubstreamState<TNow>,
    /// `true` if the substream has been opened by the remote.
    inbound: bool,
    /// Data chosen by the user.
    user_data: TSub,
}

enum SubstreamState<TNow> {
    Healthy {
        /// True if a message on this substream has already been sent since it has been opened. The
        /// first message on a substream must contain either a SYN or `ACK` flag.
        first_message_queued: bool,
        /// True if the remote has sent a message on this substream and has thus acknowledged that
        /// this substream exists.
        remote_syn_acked: bool,
        /// Amount of data the remote is allowed to transmit to the local node. Does not take into
        /// account window frames that haven't been sent out yet. In other words, this value is
        /// increased when a window frame is sent out.
        remote_allowed_window: u64,
        /// Amount of data the local node is allowed to transmit to the remote.
        allowed_window: u64,
        /// State of the local writing side of this substream.
        local_write_close: SubstreamStateLocalWrite,
        /// True if the writing side of the remote node is closed for this substream.
        remote_write_closed: bool,
        /// Buffer of incoming data that hasn't been processed by the substream yet.
        read_buffer: Vec<u8>,
        /// Value of [`ReadWrite::expected_incoming_bytes`] previously yielded by the substream.
        /// `None` means "unknown".
        expected_incoming_bytes: Option<usize>,
        /// If this substream is currently in [`YamuxInner::substreams_wake_up`], this contains
        /// the key where it is currently inserted.
        substreams_wake_up_key: Option<Option<TNow>>,
    },

    /// The substream has been reset, either locally or by the remote. Its entire purpose is to
    /// be removed by the API user.
    Reset,
}

enum SubstreamStateLocalWrite {
    Open,
    FinDesired,
    FinQueued,
}

enum Incoming {
    /// Expect a header. The field might contain some already-read bytes.
    Header,

    /// Expect the data of a previously-received data frame header.
    ///
    /// Note that the state of the reading side of the substream might already be closed. The
    /// implementation verifies that the remote is allowed to send data when processing the header,
    /// the immediately sets the reading side to "closed" if the FIN flag is set, even if there
    /// is still data to be received.
    DataFrame {
        /// Identifier of the substream the data belongs to.
        substream_id: NonZero<u32>,
        /// Number of bytes of data remaining before the frame ends.
        remaining_bytes: u32,
    },

    /// A header referring to a new substream has been received. The reception of any further data
    /// is blocked waiting for the API user to accept or reject this substream.
    PendingIncomingSubstream {
        /// Identifier of the pending substream.
        substream_id: NonZero<u32>,
        /// Extra local window size to give to this substream.
        extra_window: u32,
        /// If non-zero, must transition to a [`Incoming::DataFrame`].
        data_frame_size: u32,
        /// True if the remote writing side of the substream should immediately be closed.
        fin: bool,
    },
}

enum Outgoing {
    WritingOut {
        /// Buffers of data to write out.
        buffers: Vec<Vec<u8>>,
    },
    PreparingDataFrame {
        /// Substream concerned by the data frame. Always healthy.
        substream_id: NonZero<u32>,
        /// Buffers of data that the substream is producing. Does not include the Yamux header.
        /// Must never be empty.
        write_buffers: Vec<Vec<u8>>,
    },
}

enum OutgoingGoAway {
    /// No `GoAway` frame has been sent or requested. Normal mode of operations.
    NotRequired,

    /// API user has asked to send a `GoAway` frame. This frame hasn't been queued into
    /// [`YamuxInner::outgoing`] yet.
    Required(GoAwayErrorCode),

    /// A `GoAway` frame has been queued into [`YamuxInner::outgoing`] in the past.
    Queued,

    /// A `GoAway` frame has been extracted through [`Yamux::read_write`].
    Sent,
}

/// Maximum number of simultaneous outgoing pings allowed.
pub const MAX_PINGS: usize = 100000;

impl<TNow, TSub> Yamux<TNow, TSub> {
    /// Initializes a new Yamux state machine.
    pub fn new(config: Config) -> Yamux<TNow, TSub> {
        let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

        Yamux {
            inner: Box::new(YamuxInner {
                substreams: hashbrown::HashMap::with_capacity_and_hasher(
                    config.capacity,
                    SipHasherBuild::new({
                        let mut seed = [0; 16];
                        randomness.fill_bytes(&mut seed);
                        seed
                    }),
                ),
                dead_substreams: hashbrown::HashSet::with_capacity_and_hasher(
                    config.capacity,
                    SipHasherBuild::new({
                        let mut seed = [0; 16];
                        randomness.fill_bytes(&mut seed);
                        seed
                    }),
                ),
                substreams_wake_up: BTreeSet::new(),
                substreams_write_ready: hashbrown::HashSet::with_capacity_and_hasher(
                    config.capacity,
                    SipHasherBuild::new({
                        let mut seed = [0; 16];
                        randomness.fill_bytes(&mut seed);
                        seed
                    }),
                ),
                window_frames_to_send: hashbrown::HashMap::with_capacity_and_hasher(
                    config.capacity,
                    SipHasherBuild::new({
                        let mut seed = [0; 16];
                        randomness.fill_bytes(&mut seed);
                        seed
                    }),
                ),
                num_inbound: 0,
                received_goaway: None,
                incoming: Incoming::Header,
                outgoing: Outgoing::WritingOut {
                    // TODO: capacity?
                    buffers: Vec::with_capacity(16),
                },
                outgoing_goaway: OutgoingGoAway::NotRequired,
                max_out_data_frame_size: config.max_out_data_frame_size,
                next_outbound_substream: if config.is_initiator {
                    NonZero::<u32>::new(1).unwrap()
                } else {
                    NonZero::<u32>::new(2).unwrap()
                },
                pings_to_send: 0,
                // We leave the initial capacity at 0, as it is likely that no ping is sent at all.
                pings_waiting_reply: VecDeque::with_capacity(0),
                pongs_to_send: VecDeque::with_capacity(4),
                max_simultaneous_queued_pongs: config.max_simultaneous_queued_pongs,
                rsts_to_send: VecDeque::with_capacity(4),
                max_simultaneous_rst_substreams: config.max_simultaneous_rst_substreams,
                randomness,
            }),
        }
    }

    /// Returns `true` if there is no substream in the state machine.
    ///
    /// > **Note**: After a substream has been closed or reset, it must be removed using
    /// >           [`Yamux::remove_dead_substream`] before this function can return `true`.
    pub fn is_empty(&self) -> bool {
        self.inner.substreams.is_empty()
    }

    /// Returns the number of substreams in the Yamux state machine. Includes substreams that are
    /// dead but haven't been removed yet.
    pub fn len(&self) -> usize {
        self.inner.substreams.len()
    }

    /// Returns the number of inbound substreams in the Yamux state machine. Includes substreams
    /// that are dead but haven't been removed yet.
    pub fn num_inbound(&self) -> usize {
        debug_assert_eq!(
            self.inner.num_inbound,
            self.inner.substreams.values().filter(|s| s.inbound).count()
        );

        self.inner.num_inbound
    }

    /// Returns `Some` if a [`ReadWriteOutcome::GoAway`] event has been generated in the past,
    /// in which case the code is returned.
    ///
    /// If `Some` is returned, it is forbidden to open new outbound substreams.
    pub fn received_goaway(&self) -> Option<GoAwayErrorCode> {
        self.inner.received_goaway
    }

    /// Returns an iterator to the list of all substream user datas.
    pub fn user_datas(&self) -> impl ExactSizeIterator<Item = (SubstreamId, &TSub)> {
        self.inner
            .substreams
            .iter()
            .map(|(id, s)| (SubstreamId(*id), &s.user_data))
    }

    /// Returns an iterator to the list of all substream user datas.
    pub fn user_datas_mut(&mut self) -> impl ExactSizeIterator<Item = (SubstreamId, &mut TSub)> {
        self.inner
            .substreams
            .iter_mut()
            .map(|(id, s)| (SubstreamId(*id), &mut s.user_data))
    }

    /// Returns `true` if the given [`SubstreamId`] exists.
    ///
    /// Also returns `true` if the substream is in a dead state.
    pub fn has_substream(&self, substream_id: SubstreamId) -> bool {
        self.inner.substreams.contains_key(&substream_id.0)
    }

    /// Returns `true` if [`Yamux::send_goaway`] has been called in the past.
    ///
    /// In other words, returns `true` if a `GoAway` frame has been either queued for sending
    /// (and is available through [`Yamux::read_write`]) or has already been sent out.
    pub fn goaway_queued_or_sent(&self) -> bool {
        !matches!(self.inner.outgoing_goaway, OutgoingGoAway::NotRequired)
    }

    /// Returns `true` if [`Yamux::send_goaway`] has been called in the past and that this
    /// `GoAway` frame has been extracted through [`Yamux::read_write`].
    pub fn goaway_sent(&self) -> bool {
        matches!(self.inner.outgoing_goaway, OutgoingGoAway::Sent)
    }
}

impl<TNow, TSub> Yamux<TNow, TSub>
where
    TNow: Clone + cmp::Ord,
{
    /// Opens a new substream.
    ///
    /// This method only modifies the state of `self` and reserves an identifier. No message needs
    /// to be sent to the remote before data is actually being sent on the substream.
    ///
    /// The substream will be automatically processed by [`Yamux::read_write`] in the future.
    ///
    /// > **Note**: Importantly, the remote will not be notified of the substream being open
    /// >           before the local side sends data on this substream. As such, protocols where
    /// >           the remote is expected to send data in response to a substream being open,
    /// >           without the local side first sending some data on that substream, will not
    /// >           work. In practice, while this is technically out of concern of the Yamux
    /// >           protocol, all substreams in the context of libp2p start with a
    /// >           multistream-select negotiation, and this scenario can therefore never happen.
    ///
    /// Returns an error if a [`ReadWriteOutcome::GoAway`] event has been generated. This can
    /// also be checked by calling [`Yamux::received_goaway`].
    ///
    /// Returns an error if all possible substream IDs are already taken. This happen if there
    /// exists more than approximately `2^31` substreams, which is very unlikely to happen unless
    /// there exists a bug in the code.
    ///
    pub fn open_substream(&mut self, user_data: TSub) -> Result<SubstreamId, OpenSubstreamError> {
        if self.inner.received_goaway.is_some() {
            return Err(OpenSubstreamError::GoAwayReceived);
        }

        let substream_id = self.inner.next_outbound_substream;

        self.inner.next_outbound_substream = match self.inner.next_outbound_substream.checked_add(2)
        {
            Some(new_id) => new_id,
            None => return Err(OpenSubstreamError::NoFreeSubstreamId),
        };

        let _prev_value = self.inner.substreams.insert(
            substream_id,
            Substream {
                state: SubstreamState::Healthy {
                    first_message_queued: false,
                    remote_syn_acked: false,
                    remote_allowed_window: NEW_SUBSTREAMS_FRAME_SIZE,
                    allowed_window: NEW_SUBSTREAMS_FRAME_SIZE,
                    local_write_close: SubstreamStateLocalWrite::Open,
                    remote_write_closed: false,
                    expected_incoming_bytes: None,
                    read_buffer: Vec::new(), // TODO: capacity?
                    substreams_wake_up_key: Some(None),
                },
                inbound: false,
                user_data,
            },
        );
        debug_assert!(_prev_value.is_none());

        // The substream is added to `substreams_wake_up` rather than `substreams_write_ready`,
        // in case the substream processing does some magic such as generate events before having
        // even done anything.
        self.inner.substreams_wake_up.insert((None, substream_id));

        Ok(SubstreamId(substream_id))
    }

    /// Marks the given substream as being ready to write out data.
    ///
    /// Calling this function is necessary in situations where a substream didn't write any data
    /// in the past, but some sort of manual state update will make it write data in the future.
    ///
    /// Has no effect if the substream has been reset or closed.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid.
    ///
    pub fn mark_substream_write_ready(&mut self, substream_id: SubstreamId) {
        assert!(self.inner.substreams.contains_key(&substream_id.0));
        if !self.inner.dead_substreams.contains(&substream_id.0) {
            self.inner.substreams_write_ready.insert(substream_id.0);
        }
    }

    /// Feeds data coming from a socket and outputs data to write to the socket.
    ///
    /// Returns an object that implements `Deref<Target = ReadWrite>`. This object represents the
    /// decrypted stream of data.
    ///
    /// An error is returned if the protocol is being violated by the remote or if the nonce
    /// overflows. When that happens, the connection should be closed altogether.
    pub fn read_write(
        mut self,
        outer_read_write: &mut ReadWrite<TNow>,
    ) -> Result<ReadWriteOutcome<'_, TNow, TSub>, Error> {
        // Queue something for writing if necessary.
        if let Outgoing::WritingOut { buffers } = &mut self.inner.outgoing {
            // Make sure that it's not just a list of empty buffers.
            debug_assert_eq!(
                buffers.is_empty(),
                buffers.iter().fold(0, |sz, b| sz + b.len()) == 0
            );

            if buffers.is_empty() {
                if let OutgoingGoAway::Queued = self.inner.outgoing_goaway {
                    self.inner.outgoing_goaway = OutgoingGoAway::Sent;
                }

                if let OutgoingGoAway::Required(error_code) = self.inner.outgoing_goaway {
                    // Send a `GoAway` frame if demanded.
                    buffers.push(
                        header::encode(&header::DecodedYamuxHeader::GoAway { error_code }).to_vec(),
                    );
                    self.inner.outgoing_goaway = OutgoingGoAway::Queued;
                } else if let Some(substream_id) = self.inner.rsts_to_send.pop_front() {
                    // Send RST frame.
                    buffers.push(
                        header::encode(&header::DecodedYamuxHeader::Window {
                            syn: false,
                            ack: false,
                            fin: false,
                            rst: true,
                            stream_id: substream_id,
                            length: 0,
                        })
                        .to_vec(),
                    );
                } else if self.inner.pings_to_send > 0 {
                    // Send outgoing pings.
                    self.inner.pings_to_send -= 1;
                    let opaque_value: u32 = self.inner.randomness.next_u32();
                    self.inner.pings_waiting_reply.push_back(opaque_value);
                    buffers.push(
                        header::encode(&header::DecodedYamuxHeader::PingRequest { opaque_value })
                            .to_vec(),
                    );
                    debug_assert!(self.inner.pings_waiting_reply.len() <= MAX_PINGS);
                } else if let Some(opaque_value) = self.inner.pongs_to_send.pop_front() {
                    // Send outgoing pongs.
                    buffers.push(
                        header::encode(&header::DecodedYamuxHeader::PingResponse { opaque_value })
                            .to_vec(),
                    );
                } else if let Some(substream_id) = self
                    .inner
                    .window_frames_to_send
                    .keys()
                    .choose(&mut self.inner.randomness)
                    .copied()
                {
                    // Send window frame.
                    let Some(Substream {
                        inbound,
                        state:
                            SubstreamState::Healthy {
                                first_message_queued,
                                remote_allowed_window,
                                local_write_close,
                                ..
                            },
                        ..
                    }) = &mut self.inner.substreams.get_mut(&substream_id)
                    else {
                        unreachable!()
                    };

                    let mut pending_window_increase = self
                        .inner
                        .window_frames_to_send
                        .remove(&substream_id)
                        .unwrap()
                        .get();

                    let actual_window_update =
                        u32::try_from(pending_window_increase).unwrap_or(u32::MAX);
                    buffers.push(
                        header::encode(&header::DecodedYamuxHeader::Window {
                            syn: !*first_message_queued && !*inbound,
                            ack: !*first_message_queued && *inbound,
                            // Note that it is unclear whether `fin` should be set if the local
                            // writing state has been written before.
                            fin: matches!(local_write_close, SubstreamStateLocalWrite::FinDesired),
                            rst: false,
                            stream_id: substream_id,
                            length: actual_window_update,
                        })
                        .to_vec(),
                    );

                    *remote_allowed_window =
                        remote_allowed_window.saturating_add(u64::from(actual_window_update));
                    pending_window_increase -= u64::from(actual_window_update);
                    *first_message_queued = true;
                    if matches!(local_write_close, SubstreamStateLocalWrite::FinDesired) {
                        *local_write_close = SubstreamStateLocalWrite::FinQueued;
                    }

                    // In the rare situation where the window update doesn't fit in a `u32`, we
                    // have to send another window frame again later.
                    if let Some(pending_window_increase) =
                        NonZero::<u64>::new(pending_window_increase)
                    {
                        self.inner
                            .window_frames_to_send
                            .insert(substream_id, pending_window_increase);
                    }
                }
            }
        }

        // Try finish writing the data currently being written.
        if let Outgoing::WritingOut { buffers } = &mut self.inner.outgoing {
            let buffers_total_size = buffers.iter().fold(0, |count, buf| count + buf.len());

            if buffers_total_size == 0 {
                // Do nothing.
            } else if outer_read_write
                .write_bytes_queueable
                .map_or(false, |queuable| buffers_total_size <= queuable)
            {
                // We can directly push all the write buffers to the `ReadWrite`.
                if outer_read_write.write_buffers.is_empty() {
                    debug_assert_eq!(outer_read_write.write_bytes_queued, 0);
                    outer_read_write.write_buffers = mem::take(buffers);
                } else {
                    outer_read_write.write_buffers.append(buffers);
                }

                outer_read_write.write_bytes_queued += buffers_total_size;
                *outer_read_write.write_bytes_queueable.as_mut().unwrap() -= buffers_total_size;
            } else if outer_read_write.write_buffers.is_empty()
                && outer_read_write
                    .write_bytes_queueable
                    .map_or(false, |queueable| {
                        buffers.first().map_or(0, |b| b.len()) <= queueable
                    })
            {
                // Not enough space to push all the buffers at once, but enough space to push at
                // least the first one. Push as many buffers as possible.
                let limit = outer_read_write.write_bytes_queueable.unwrap_or(0);
                let (num_buffers, buffers_size) = buffers
                    .iter()
                    .scan(0, |count, buf| {
                        *count += buf.len();
                        Some(*count)
                    })
                    .enumerate()
                    .take_while(|(_, sz)| *sz <= limit)
                    .last()
                    .unwrap();

                outer_read_write
                    .write_buffers
                    .extend(buffers.drain(..num_buffers));
                outer_read_write.write_bytes_queued += buffers_size;
                *outer_read_write.write_bytes_queueable.as_mut().unwrap() -= buffers_size;
            } else if outer_read_write.write_buffers.is_empty() {
                // Not enough space to fully push even the first buffer.
                if let Some(first) = buffers.first_mut() {
                    outer_read_write.write_from_vec(first);
                }
            }
        }

        // Consume as much incoming data as possible until either the incoming data buffer is
        // empty or we reach a non-empty data frame.
        loop {
            match self.inner.incoming {
                Incoming::PendingIncomingSubstream { .. } => break,

                Incoming::DataFrame {
                    remaining_bytes: 0, ..
                } => {
                    // Nothing more to do.
                    self.inner.incoming = Incoming::Header;
                }

                Incoming::DataFrame {
                    substream_id,
                    ref mut remaining_bytes,
                    ..
                } => {
                    // It is possible that we are receiving data corresponding to a substream for
                    // which a RST has been sent out by the local node. Since the
                    // local state machine doesn't keep track of RST'ted substreams, any
                    // frame concerning a substream that has been RST or doesn't exist is
                    // discarded and doesn't result in an error, under the presumption that we
                    // are in this situation.
                    let Some(Substream {
                        state:
                            SubstreamState::Healthy {
                                expected_incoming_bytes,
                                read_buffer,
                                substreams_wake_up_key,
                                ..
                            },
                        ..
                    }) = self.inner.substreams.get_mut(&substream_id)
                    else {
                        // Substream doesn't exist (as it's likely been RST as explained above).
                        // Discard the next `remaining_bytes`.
                        // TODO: don't use `incoming_bytes_take` but instead simply discard as much as possible or something
                        match outer_read_write.incoming_bytes_take(
                            usize::try_from(*remaining_bytes).unwrap_or(usize::MAX),
                        ) {
                            Ok(Some(taken)) => {
                                debug_assert_eq!(taken.len() as u32, *remaining_bytes);
                                *remaining_bytes = 0;
                                continue;
                            }
                            // TODO: how to deal with the read closed?
                            Ok(None) | Err(read_write::IncomingBytesTakeError::ReadClosed) => break,
                        }
                    };

                    // We copy data from the main incoming buffer to the read buffer of that
                    // substream.
                    // If there isn't enough data in `outer_read_write.incoming_buffer`
                    // compared to the substream has previously requested with
                    // `expected_incoming_bytes`, then we request more data from the outside.
                    // If instead there is enough data, we copy all the data immediately
                    // in order to avoid the cost of splitting the buffer.

                    debug_assert_ne!(*remaining_bytes, 0);
                    let to_copy = if *expected_incoming_bytes == Some(0) {
                        // If the substream refuses to process more incoming data right now,
                        // we copy everything into its read buffer in order to free the outer
                        // incoming buffer.
                        // The window system of Yamux ensures that the read buffer size is capped.
                        usize::try_from(*remaining_bytes).unwrap_or(usize::MAX)
                    } else {
                        cmp::min(
                            expected_incoming_bytes
                                .unwrap_or(0)
                                .saturating_sub(read_buffer.len()),
                            usize::try_from(*remaining_bytes).unwrap_or(usize::MAX),
                        )
                    };

                    match outer_read_write.incoming_bytes_take(to_copy) {
                        Ok(Some(mut data)) => {
                            *remaining_bytes -= u32::try_from(data.len()).unwrap();
                            if read_buffer.is_empty() {
                                *read_buffer = data;
                            } else {
                                read_buffer.append(&mut data);
                            }
                        }
                        // TODO: how to deal with the read closed?
                        Ok(None) | Err(read_write::IncomingBytesTakeError::ReadClosed) => break,
                    }

                    // If the substream has enough data to read, or has never been processed
                    // before, make sure that it will wake up as soon as possible.
                    if expected_incoming_bytes.map_or(true, |expected| {
                        expected != 0 && read_buffer.len() >= expected
                    }) {
                        match substreams_wake_up_key {
                            Some(Some(when)) if *when <= outer_read_write.now => {}
                            Some(None) => {}
                            Some(Some(when)) => {
                                let _was_removed = self
                                    .inner
                                    .substreams_wake_up
                                    .remove(&(Some(when.clone()), substream_id));
                                debug_assert!(_was_removed);
                                self.inner.substreams_wake_up.insert((None, substream_id));
                                *substreams_wake_up_key = Some(None);
                            }
                            _ => {
                                self.inner.substreams_wake_up.insert((None, substream_id));
                                *substreams_wake_up_key = Some(None);
                            }
                        }

                        // Also stop processing incoming data so that we can process the substream.
                        break;
                    }

                    // Make sure that some progress was made, otherwise we might get into an
                    // infinite loop.
                    debug_assert_ne!(to_copy, 0);
                }

                Incoming::Header => {
                    // Try to grab a header from the incoming buffer.
                    let header_bytes = match outer_read_write.incoming_bytes_take_array::<12>() {
                        Ok(Some(hdr)) => hdr,
                        Ok(None) | Err(read_write::IncomingBytesTakeError::ReadClosed) => break,
                    };

                    // Decode the header in `header_bytes`.
                    let decoded_header = match header::decode_yamux_header(&header_bytes) {
                        Ok(h) => h,
                        Err(err) => return Err(Error::HeaderDecode(err)),
                    };

                    match decoded_header {
                        header::DecodedYamuxHeader::PingRequest { opaque_value } => {
                            if self.inner.pongs_to_send.len()
                                >= self.inner.max_simultaneous_queued_pongs.get()
                            {
                                return Err(Error::MaxSimultaneousPingsExceeded);
                            }

                            self.inner.pongs_to_send.push_back(opaque_value);
                            self.inner.incoming = Incoming::Header;
                        }

                        header::DecodedYamuxHeader::PingResponse { opaque_value } => {
                            if self.inner.pings_waiting_reply.pop_front() != Some(opaque_value) {
                                return Err(Error::PingResponseNotMatching);
                            }

                            self.inner.incoming = Incoming::Header;
                            return Ok(ReadWriteOutcome::PingResponse { yamux: self });
                        }

                        header::DecodedYamuxHeader::GoAway { error_code } => {
                            if self.inner.received_goaway.is_some() {
                                return Err(Error::MultipleGoAways);
                            }

                            self.inner.incoming = Incoming::Header;
                            self.inner.received_goaway = Some(error_code);

                            let mut reset_substreams =
                                Vec::with_capacity(self.inner.substreams.len());
                            for (substream_id, substream) in self.inner.substreams.iter_mut() {
                                let SubstreamState::Healthy {
                                    remote_syn_acked: false,
                                    substreams_wake_up_key,
                                    ..
                                } = &mut substream.state
                                else {
                                    continue;
                                };

                                reset_substreams.push(SubstreamId(*substream_id));

                                let _was_inserted =
                                    self.inner.dead_substreams.insert(*substream_id);
                                debug_assert!(_was_inserted);

                                self.inner.substreams_write_ready.remove(substream_id);
                                self.inner.window_frames_to_send.remove(substream_id);

                                if let Some(k) = substreams_wake_up_key.take() {
                                    let _was_removed =
                                        self.inner.substreams_wake_up.remove(&(k, *substream_id));
                                    debug_assert!(_was_removed);
                                }

                                if let Outgoing::PreparingDataFrame {
                                    substream_id: s,
                                    write_buffers,
                                } = &mut self.inner.outgoing
                                {
                                    if *substream_id == *s {
                                        write_buffers.clear();
                                        self.inner.outgoing = Outgoing::WritingOut {
                                            buffers: mem::take(write_buffers),
                                        }
                                    }
                                }

                                substream.state = SubstreamState::Reset;
                            }

                            outer_read_write.wake_up_asap();
                            return Ok(ReadWriteOutcome::GoAway {
                                yamux: self,
                                code: error_code,
                                reset_substreams,
                            });
                        }

                        header::DecodedYamuxHeader::Data {
                            rst: true,
                            ack,
                            stream_id,
                            length,
                            ..
                        }
                        | header::DecodedYamuxHeader::Window {
                            rst: true,
                            ack,
                            stream_id,
                            length,
                            ..
                        } => {
                            // Frame with the `RST` flag set. Destroy the substream.

                            // Sending a `RST` flag and data together is a weird corner case and
                            // is difficult to handle. It is unclear whether it is allowed at all.
                            // We thus consider it as invalid.
                            if matches!(decoded_header, header::DecodedYamuxHeader::Data { .. })
                                && length != 0
                            {
                                return Err(Error::DataWithRst);
                            }

                            self.inner.incoming = Incoming::Header;

                            // The remote might have sent a RST frame concerning a substream for
                            // which we have sent a RST frame earlier. Considering that we don't
                            // always keep traces of old substreams, we have no way to know whether
                            // this is the case or not.
                            let Some(substream) = self.inner.substreams.get_mut(&stream_id) else {
                                continue;
                            };
                            let SubstreamState::Healthy {
                                remote_syn_acked,
                                substreams_wake_up_key,
                                ..
                            } = &mut substream.state
                            else {
                                continue;
                            };

                            let _was_inserted = self.inner.dead_substreams.insert(stream_id);
                            debug_assert!(_was_inserted);

                            // Check whether the remote has ACKed multiple times.
                            if *remote_syn_acked && ack {
                                return Err(Error::UnexpectedAck);
                            }

                            if let Outgoing::PreparingDataFrame {
                                substream_id,
                                write_buffers,
                            } = &mut self.inner.outgoing
                            {
                                if *substream_id == stream_id {
                                    write_buffers.clear();
                                    self.inner.outgoing = Outgoing::WritingOut {
                                        buffers: mem::take(write_buffers),
                                    }
                                }
                            }

                            self.inner.window_frames_to_send.remove(&stream_id);
                            self.inner.substreams_write_ready.remove(&stream_id);

                            if let Some(k) = substreams_wake_up_key.take() {
                                let _was_removed =
                                    self.inner.substreams_wake_up.remove(&(k, stream_id));
                                debug_assert!(_was_removed);
                            }

                            substream.state = SubstreamState::Reset;

                            outer_read_write.wake_up_asap();
                            return Ok(ReadWriteOutcome::StreamReset {
                                yamux: self,
                                substream_id: SubstreamId(stream_id),
                            });
                        }

                        header::DecodedYamuxHeader::Data {
                            syn: true,
                            ack: true,
                            ..
                        }
                        | header::DecodedYamuxHeader::Window {
                            syn: true,
                            ack: true,
                            ..
                        } => {
                            // You're never supposed to send a SYN and ACK at the same time.
                            return Err(Error::UnexpectedAck);
                        }

                        header::DecodedYamuxHeader::Data {
                            syn: true,
                            fin,
                            rst: false,
                            stream_id,
                            length,
                            ..
                        }
                        | header::DecodedYamuxHeader::Window {
                            syn: true,
                            fin,
                            rst: false,
                            stream_id,
                            length,
                            ..
                        } => {
                            // The initiator should only allocate uneven substream IDs, and the
                            // other side only even IDs. We don't know anymore whether we're
                            // initiator at this point, but we can compare with the even-ness of
                            // the IDs that we allocate locally.
                            if (self.inner.next_outbound_substream.get() % 2)
                                == (stream_id.get() % 2)
                            {
                                return Err(Error::InvalidInboundStreamId { stream_id });
                            }

                            // Remote has sent a SYN flag. A new substream is to be opened.
                            match self.inner.substreams.get(&stream_id) {
                                None => {}
                                Some(Substream {
                                    state:
                                        SubstreamState::Healthy {
                                            local_write_close: SubstreamStateLocalWrite::FinQueued,
                                            remote_write_closed: true,
                                            ..
                                        },
                                    ..
                                })
                                | Some(Substream {
                                    state: SubstreamState::Reset,
                                    ..
                                }) => {
                                    // Because we don't immediately destroy substreams, the remote
                                    // might decide to re-use a substream ID that is still
                                    // allocated locally. If that happens, we block the reading.
                                    // It will be unblocked when the API user destroys the old
                                    // substream.
                                    break;
                                }
                                Some(Substream {
                                    state: SubstreamState::Healthy { .. },
                                    ..
                                }) => {
                                    return Err(Error::UnexpectedSyn { stream_id });
                                }
                            }

                            // When receiving a new substream, we might have to potentially queue
                            // a substream rejection message later.
                            // In order to ensure that there is enough space in `rsts_to_send`,
                            // we check it against the limit now.
                            if self.inner.rsts_to_send.len()
                                >= self.inner.max_simultaneous_rst_substreams.get()
                            {
                                return Err(Error::MaxSimultaneousRstSubstreamsExceeded);
                            }

                            let is_data =
                                matches!(decoded_header, header::DecodedYamuxHeader::Data { .. });

                            // If we have queued or sent a GoAway frame, then the substream is
                            // ignored. The remote understands when receiving the GoAway that the
                            // substream has been rejected.
                            if !matches!(self.inner.outgoing_goaway, OutgoingGoAway::NotRequired) {
                                self.inner.incoming = if !is_data {
                                    Incoming::Header
                                } else {
                                    Incoming::DataFrame {
                                        substream_id: stream_id,
                                        remaining_bytes: length,
                                    }
                                };

                                continue;
                            }

                            if is_data && u64::from(length) > NEW_SUBSTREAMS_FRAME_SIZE {
                                return Err(Error::CreditsExceeded);
                            }

                            self.inner.incoming = Incoming::PendingIncomingSubstream {
                                substream_id: stream_id,
                                extra_window: if !is_data { length } else { 0 },
                                data_frame_size: if is_data { length } else { 0 },
                                fin,
                            };

                            return Ok(ReadWriteOutcome::IncomingSubstream { yamux: self });
                        }

                        header::DecodedYamuxHeader::Data {
                            syn: false,
                            rst: false,
                            stream_id,
                            length,
                            ack,
                            fin,
                            ..
                        } => {
                            // Note that it is possible that the remote is referring to a substream
                            // for which a RST has been sent out by the local node. Since the
                            // local state machine doesn't keep track of RST'ted substreams, any
                            // frame concerning a substream that has been RST or with an unknown
                            // id is discarded and doesn't result in an error, under the
                            // presumption that we are in this situation.
                            if let Some(Substream {
                                state:
                                    SubstreamState::Healthy {
                                        remote_write_closed,
                                        remote_allowed_window,
                                        remote_syn_acked,
                                        substreams_wake_up_key,
                                        ..
                                    },
                                ..
                            }) = self.inner.substreams.get_mut(&stream_id)
                            {
                                match (ack, remote_syn_acked) {
                                    (false, true) => {}
                                    (true, acked @ false) => *acked = true,
                                    (true, true) => return Err(Error::UnexpectedAck),
                                    (false, false) => return Err(Error::ExpectedAck),
                                }

                                if *remote_write_closed {
                                    return Err(Error::WriteAfterFin);
                                }

                                if fin {
                                    *remote_write_closed = true;

                                    // No need to send window frames anymore if the remote has
                                    // sent a FIN.
                                    self.inner.window_frames_to_send.remove(&stream_id);

                                    // Wake up the substream.
                                    match substreams_wake_up_key {
                                        Some(Some(when)) if *when <= outer_read_write.now => {}
                                        Some(None) => {}
                                        Some(Some(when)) => {
                                            let _was_removed = self
                                                .inner
                                                .substreams_wake_up
                                                .remove(&(Some(when.clone()), stream_id));
                                            debug_assert!(_was_removed);
                                            self.inner.substreams_wake_up.insert((None, stream_id));
                                            *substreams_wake_up_key = Some(None);
                                        }
                                        _ => {
                                            self.inner.substreams_wake_up.insert((None, stream_id));
                                            *substreams_wake_up_key = Some(None);
                                        }
                                    }
                                }

                                // Check whether the remote has the right to send that much data.
                                // Note that the credits aren't checked in the case of an unknown
                                // substream.
                                *remote_allowed_window = remote_allowed_window
                                    .checked_sub(u64::from(length))
                                    .ok_or(Error::CreditsExceeded)?;
                            }

                            // Switch to the `DataFrame` state in order to process the frame, even
                            // if the substream no longer exists, in order to not duplicate code.
                            self.inner.incoming = Incoming::DataFrame {
                                substream_id: stream_id,
                                remaining_bytes: length,
                            };
                        }

                        header::DecodedYamuxHeader::Window {
                            syn: false,
                            rst: false,
                            stream_id,
                            length,
                            ack,
                            fin,
                            ..
                        } => {
                            // Note that it is possible that the remote is referring to a substream
                            // for which a RST has been sent out by the local node. Since the
                            // local state machine doesn't keep track of RST'ted substreams, any
                            // frame concerning a substream that has been RST or with an unknown
                            // id is discarded and doesn't result in an error, under the
                            // presumption that we are in this situation.
                            let Some(Substream {
                                state:
                                    SubstreamState::Healthy {
                                        remote_syn_acked,
                                        allowed_window,
                                        remote_write_closed,
                                        ..
                                    },
                                ..
                            }) = self.inner.substreams.get_mut(&stream_id)
                            else {
                                self.inner.incoming = Incoming::Header;
                                continue;
                            };

                            match (ack, remote_syn_acked) {
                                (false, true) => {}
                                (true, acked @ false) => *acked = true,
                                (true, true) => return Err(Error::UnexpectedAck),
                                (false, false) => return Err(Error::ExpectedAck),
                            }

                            // Note that the spec is unclear about whether the remote can or
                            // should continue sending FIN flags on window size frames after
                            // their side of the substream has already been closed before.
                            if fin {
                                *remote_write_closed = true;
                            }

                            // If a substream was processed with a non-zero queuable bytes
                            // value (i.e. `allowed_window` non-zero) but yields empty write
                            // buffers, then we can assume that the substream has nothing to write,
                            // and thus that simply increasing the queueable bytes will not change
                            // the situation. After all, we have no idea whether the remote will
                            // increase the window size of this substream any further in the
                            // future, and thus we must write data out no matter what the window
                            // size is as long as it is non-zero.
                            // On the other hand, if the queueable bytes were 0, we take the guess
                            // that the substream might have more to write.
                            if length != 0 && *allowed_window == 0 {
                                self.inner.substreams_write_ready.insert(stream_id);
                            }

                            *allowed_window = allowed_window
                                .checked_add(u64::from(length))
                                .ok_or(Error::LocalCreditsOverflow)?;

                            self.inner.incoming = Incoming::Header;
                        }
                    }
                }
            }
        }

        // Choose which substream to read/write (if any).
        let substream_id = match (
            &self.inner.outgoing,
            self.inner.substreams_write_ready.iter().next().copied(),
            self.inner.substreams_wake_up.first(),
        ) {
            (
                Outgoing::PreparingDataFrame {
                    substream_id,
                    write_buffers,
                },
                _,
                _,
            ) => {
                // Continue writing to the substream whose frame we're already preparing.
                debug_assert!(!write_buffers.is_empty());
                self.inner.substreams_write_ready.remove(substream_id);
                *substream_id
            }
            (Outgoing::WritingOut { buffers }, Some(substream_id), _) if buffers.is_empty() => {
                // Pull a substream from `substreams_write_ready`.
                self.inner.substreams_write_ready.remove(&substream_id);
                substream_id
            }
            (_, _, Some((when, substream_id)))
                if when
                    .as_ref()
                    .map_or(true, |when| *when <= outer_read_write.now) =>
            {
                *substream_id
            }
            _ => {
                // No substream to read/write.
                return Ok(ReadWriteOutcome::Idle { yamux: self });
            }
        };

        // Extract some fields from the substream state.
        let SubstreamState::Healthy {
            allowed_window,
            local_write_close,
            remote_write_closed,
            read_buffer,
            substreams_wake_up_key,
            ..
        } = &mut self.inner.substreams.get_mut(&substream_id).unwrap().state
        else {
            unreachable!()
        };

        // Remove the substream from `substreams_wake_up`, since we're processing it now.
        // If the processing produces a `wake_up_after` value when being processed, it will be
        // re-inserted.
        if let Some(substreams_wake_up_key) = substreams_wake_up_key.take() {
            let _was_removed = self
                .inner
                .substreams_wake_up
                .remove(&(substreams_wake_up_key, substream_id));
            debug_assert!(_was_removed);
        }

        let (write_buffers, can_queue_data) = match &mut self.inner.outgoing {
            Outgoing::WritingOut { buffers } if buffers.is_empty() => {
                let mut buffers = mem::take(buffers);
                // As a small optimization, we push an empty buffer at the front where the header
                // might later get written.
                buffers.push(Vec::with_capacity(12));
                (buffers, true)
            }
            Outgoing::PreparingDataFrame {
                substream_id: s,
                write_buffers,
            } if *s == substream_id => {
                let buffers = mem::take(write_buffers);
                self.inner.outgoing = Outgoing::WritingOut {
                    buffers: Vec::new(),
                };
                (buffers, true)
            }
            _ => (Vec::new(), false),
        };
        let write_buffers_len_before = write_buffers.iter().fold(0, |count, buf| count + buf.len());

        Ok(ReadWriteOutcome::ProcessSubstream {
            substream_read_write: SubstreamReadWrite {
                substream_id,
                write_buffers_len_before,
                inner_read_write: ReadWrite {
                    now: outer_read_write.now.clone(),
                    incoming_buffer: mem::take(read_buffer),
                    expected_incoming_bytes: if !*remote_write_closed { Some(0) } else { None },
                    read_bytes: 0,
                    write_buffers,
                    write_bytes_queued: write_buffers_len_before,
                    write_bytes_queueable: if matches!(
                        local_write_close,
                        SubstreamStateLocalWrite::Open
                    ) {
                        if can_queue_data {
                            Some(
                                usize::try_from(cmp::min(
                                    u64::from(self.inner.max_out_data_frame_size.get()),
                                    *allowed_window,
                                ))
                                .unwrap_or(usize::MAX)
                                .saturating_sub(write_buffers_len_before),
                            )
                        } else {
                            Some(0)
                        }
                    } else {
                        None
                    },
                    wake_up_after: None,
                },
                outer_read_write,
                yamux: self,
            },
        })
    }

    /// Adds `bytes` to the number of bytes the remote is allowed to send at once in the next
    /// packet.
    ///
    /// > **Note**: The [`SubstreamReadWrite`] object ensures that the remote window is big enough
    /// >           to receive the amount of bytes requested by the substream. Calling
    /// >           [`Yamux::add_remote_window_saturating`] is therefore not mandatory, but only an
    /// >           optimization to reduce the number of networking round trips.
    ///
    /// The counter saturates if its maximum is reached. This could cause stalls if the
    /// remote sends a ton of data. However, given that the number of bytes is stored in a `u64`,
    /// the remote would have to send at least  `2^64` bytes in order to reach this situation,
    /// making it basically impossible.
    ///
    /// It is, furthermore, a bad idea to increase this counter by an immense number ahead of
    /// time, as the remote can shut down the connection if its own counter overflows. The way
    /// this counter is supposed to be used in a "streaming" way.
    ///
    /// Increasing the window of a substream by `bytes` requires sending out `12 * bytes / 2^32`
    /// bytes. For example, increasing the window by `2^64` adds an overhead of 48 GiB. Please
    /// don't do that.
    ///
    /// > **Note**: When a substream has just been opened or accepted, it starts with an initial
    /// >           window of [`NEW_SUBSTREAMS_FRAME_SIZE`].
    ///
    /// > **Note**: It is only possible to add more bytes to the window and not set or reduce this
    /// >           number of bytes, and it is also not possible to obtain the number of bytes the
    /// >           remote is allowed. That's because it would be ambiguous whether bytes possibly
    /// >           in the send or receive queue should be counted or not.
    ///
    /// Has no effect if the remote has already closed their writing side.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid.
    ///
    pub fn add_remote_window_saturating(&mut self, substream_id: SubstreamId, bytes: u64) {
        if let SubstreamState::Healthy {
            remote_write_closed: false,
            ..
        } = &mut self
            .inner
            .substreams
            .get_mut(&substream_id.0)
            .unwrap_or_else(|| panic!())
            .state
        {
            let Some(bytes) = NonZero::<u64>::new(bytes) else {
                return;
            };

            self.inner
                .window_frames_to_send
                .entry(substream_id.0)
                .and_modify(|window| *window = window.saturating_add(bytes.get()))
                .or_insert(bytes);
        }
    }

    /// Abruptly shuts down the substream. Sends a frame with the `RST` flag to the remote.
    ///
    /// Use this method when a protocol error happens on a substream.
    ///
    /// Returns an error if [`Yamux::reset`] has already been called on this substream, or if the
    /// remote has reset the substream in the past, or if the substream was closed.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid.
    ///
    pub fn reset(&mut self, substream_id: SubstreamId) -> Result<(), ResetError> {
        // Add an entry to the list of RST headers to send to the remote.
        let SubstreamState::Healthy {
            substreams_wake_up_key,
            ..
        } = &mut self
            .inner
            .substreams
            .get_mut(&substream_id.0)
            .unwrap_or_else(|| panic!())
            .state
        else {
            return Err(ResetError::AlreadyReset);
        };

        if !self.inner.dead_substreams.insert(substream_id.0) {
            return Err(ResetError::AlreadyClosed);
        }

        self.inner.window_frames_to_send.remove(&substream_id.0);
        self.inner.substreams_write_ready.remove(&substream_id.0);

        if let Some(key) = substreams_wake_up_key.take() {
            let _was_removed = self.inner.substreams_wake_up.remove(&(key, substream_id.0));
            debug_assert!(_was_removed);
        }

        if let Outgoing::PreparingDataFrame {
            substream_id: id,
            write_buffers,
        } = &mut self.inner.outgoing
        {
            if *id == substream_id.0 {
                write_buffers.clear();
                self.inner.outgoing = Outgoing::WritingOut {
                    buffers: mem::take(write_buffers),
                }
            }
        }

        // Note that we intentionally don't check the size against
        // `max_simultaneous_rst_substreams`, as locally-emitted RST frames aren't the
        // remote's fault.
        self.inner.rsts_to_send.push_back(substream_id.0);

        self.inner
            .substreams
            .get_mut(&substream_id.0)
            .unwrap_or_else(|| panic!())
            .state = SubstreamState::Reset;

        Ok(())
    }

    /// Queues sending out a ping to the remote.
    ///
    /// # Panic
    ///
    /// Panics if there are already [`MAX_PINGS`] pings that have been queued and that the remote
    /// hasn't answered yet. [`MAX_PINGS`] is pretty large, and unless there is a bug in the API
    /// user's code causing pings to be allocated in a loop, this limit is not likely to ever be
    /// reached.
    ///
    pub fn queue_ping(&mut self) {
        // A maximum number of simultaneous pings (`MAX_PINGS`) is necessary because we don't
        // support sending multiple identical ping opaque values. Since the ping opaque values
        // are 32 bits, the actual maximum number of simultaneous pings is 2^32. But because we
        // allocate ping values by looping until we find a not-yet-allocated value, the arbitrary
        // self-enforced maximum needs to be way lower.
        assert!(self.inner.pings_to_send + self.inner.pings_waiting_reply.len() < MAX_PINGS);
        self.inner.pings_to_send += 1;
    }

    /// Queues a `GoAway` frame, requesting the remote to no longer open any substream.
    ///
    /// If the state of [`Yamux`] is currently waiting for a confirmation to accept/reject a
    /// substream, then this function automatically implies calling
    /// [`Yamux::reject_pending_substream`].
    ///
    /// All follow-up requests for new substreams from the remote are automatically rejected.
    /// [`ReadWriteOutcome::IncomingSubstream`] events can no longer happen.
    ///
    pub fn send_goaway(&mut self, code: GoAwayErrorCode) -> Result<(), SendGoAwayError> {
        match self.inner.outgoing_goaway {
            OutgoingGoAway::NotRequired => {
                self.inner.outgoing_goaway = OutgoingGoAway::Required(code)
            }
            _ => return Err(SendGoAwayError::AlreadySent),
        }

        // If the remote is currently opening a substream, ignore it. The remote understands when
        // receiving the GoAway that the substream has been rejected.
        if let Incoming::PendingIncomingSubstream {
            substream_id,
            data_frame_size,
            ..
        } = self.inner.incoming
        {
            self.inner.incoming = Incoming::DataFrame {
                substream_id,
                remaining_bytes: data_frame_size,
            };
        }

        Ok(())
    }

    /// Returns the list of all substreams that have been closed or reset.
    ///
    /// This function does not remove dead substreams from the state machine. In other words, if
    /// this function is called multiple times in a row, it will always return the same
    /// substreams. Use [`Yamux::remove_dead_substream`] to remove substreams.
    pub fn dead_substreams(&self) -> impl Iterator<Item = (SubstreamId, DeadSubstreamTy, &TSub)> {
        self.inner.dead_substreams.iter().map(|id| {
            let substream = self.inner.substreams.get(id).unwrap();
            match &substream.state {
                SubstreamState::Reset => (
                    SubstreamId(*id),
                    DeadSubstreamTy::Reset,
                    &substream.user_data,
                ),
                SubstreamState::Healthy {
                    local_write_close,
                    remote_write_closed,
                    ..
                } => {
                    debug_assert!(
                        matches!(local_write_close, SubstreamStateLocalWrite::FinQueued)
                            && *remote_write_closed
                    );

                    (
                        SubstreamId(*id),
                        DeadSubstreamTy::ClosedGracefully,
                        &substream.user_data,
                    )
                }
            }
        })
    }

    /// Removes a dead substream from the state machine.
    ///
    /// # Panic
    ///
    /// Panics if the substream with that id doesn't exist or isn't dead.
    ///
    pub fn remove_dead_substream(&mut self, id: SubstreamId) -> TSub {
        let was_in = self.inner.dead_substreams.remove(&id.0);
        if !was_in {
            panic!()
        }

        debug_assert!(
            !self
                .inner
                .substreams_wake_up
                .iter()
                .any(|(_, s)| s == &id.0)
        );
        debug_assert!(!self.inner.window_frames_to_send.contains_key(&id.0));
        debug_assert!(!self.inner.substreams_write_ready.contains(&id.0));

        let substream = self.inner.substreams.remove(&id.0).unwrap();

        if substream.inbound {
            self.inner.num_inbound -= 1;
        }

        substream.user_data
    }

    /// Accepts an incoming substream.
    ///
    /// Either [`Yamux::accept_pending_substream`] or [`Yamux::reject_pending_substream`] must be
    /// called after [`ReadWriteOutcome::IncomingSubstream`] is returned.
    ///
    /// Note that there is no expiration window after [`ReadWriteOutcome::IncomingSubstream`]
    /// is returned until the substream is no longer valid. However, reading will be blocked until
    /// the substream is either accepted or rejected. This function should thus be called as
    /// soon as possible.
    ///
    /// Returns an error if no incoming substream is currently pending.
    ///
    pub fn accept_pending_substream(
        &mut self,
        user_data: TSub,
    ) -> Result<SubstreamId, PendingSubstreamError> {
        let Incoming::PendingIncomingSubstream {
            substream_id,
            extra_window,
            data_frame_size,
            fin,
        } = self.inner.incoming
        else {
            return Err(PendingSubstreamError::NoPendingSubstream);
        };

        debug_assert!(u64::from(data_frame_size) <= NEW_SUBSTREAMS_FRAME_SIZE);

        let _was_before = self.inner.substreams.insert(
            substream_id,
            Substream {
                state: SubstreamState::Healthy {
                    first_message_queued: false,
                    remote_syn_acked: true,
                    remote_allowed_window: NEW_SUBSTREAMS_FRAME_SIZE - u64::from(data_frame_size),
                    allowed_window: NEW_SUBSTREAMS_FRAME_SIZE + u64::from(extra_window),
                    local_write_close: SubstreamStateLocalWrite::Open,
                    remote_write_closed: fin,
                    expected_incoming_bytes: None,
                    read_buffer: Vec::new(), // TODO: capacity?
                    // There is no need to insert the substream in `substreams_wake_up`, as we
                    // switch `self.inner.incoming` to a data frame below, which will cause the
                    // substream to be processed.
                    substreams_wake_up_key: None,
                },
                inbound: true,
                user_data,
            },
        );
        debug_assert!(_was_before.is_none());

        self.inner.num_inbound += 1;

        self.inner.incoming = Incoming::DataFrame {
            substream_id,
            remaining_bytes: data_frame_size,
        };

        Ok(SubstreamId(substream_id))
    }

    /// Rejects an incoming substream.
    ///
    /// Either [`Yamux::accept_pending_substream`] or [`Yamux::reject_pending_substream`] must be
    /// called after [`ReadWriteOutcome::IncomingSubstream`] is returned.
    ///
    /// Note that there is no expiration window after [`ReadWriteOutcome::IncomingSubstream`]
    /// is returned until the substream is no longer valid. However, reading will be blocked until
    /// the substream is either accepted or rejected. This function should thus be called as
    /// soon as possible.
    ///
    /// Returns an error if no incoming substream is currently pending.
    ///
    pub fn reject_pending_substream(&mut self) -> Result<(), PendingSubstreamError> {
        let Incoming::PendingIncomingSubstream {
            substream_id,
            data_frame_size,
            ..
        } = self.inner.incoming
        else {
            return Err(PendingSubstreamError::NoPendingSubstream);
        };

        self.inner.rsts_to_send.push_back(substream_id);
        self.inner.incoming = Incoming::DataFrame {
            substream_id,
            remaining_bytes: data_frame_size,
        };
        Ok(())
    }
}

impl<TNow, TSub> ops::Index<SubstreamId> for Yamux<TNow, TSub> {
    type Output = TSub;

    fn index(&self, substream_id: SubstreamId) -> &TSub {
        &self
            .inner
            .substreams
            .get(&substream_id.0)
            .unwrap_or_else(|| panic!("no substream with id {} in yamux state", substream_id.0))
            .user_data
    }
}

impl<TNow, TSub> ops::IndexMut<SubstreamId> for Yamux<TNow, TSub> {
    fn index_mut(&mut self, substream_id: SubstreamId) -> &mut TSub {
        &mut self
            .inner
            .substreams
            .get_mut(&substream_id.0)
            .unwrap_or_else(|| panic!("no substream with id {} in yamux state", substream_id.0))
            .user_data
    }
}

impl<TNow, TSub> fmt::Debug for Yamux<TNow, TSub>
where
    TSub: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct List<'a, TNow, TSub>(&'a Yamux<TNow, TSub>);
        impl<'a, TNow, TSub> fmt::Debug for List<'a, TNow, TSub>
        where
            TSub: fmt::Debug,
        {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_list()
                    .entries(self.0.inner.substreams.values().map(|v| &v.user_data))
                    .finish()
            }
        }

        f.debug_struct("Yamux")
            .field("substreams", &List(self))
            .finish()
    }
}

/// Identifier of a substream in the context of a connection.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, derive_more::From)]
pub struct SubstreamId(NonZero<u32>);

impl SubstreamId {
    /// Value that compares inferior or equal to all possible values.
    pub const MIN: Self = Self(match NonZero::<u32>::new(1) {
        Some(v) => v,
        None => unreachable!(),
    });

    /// Value that compares superior or equal to all possible values.
    pub const MAX: Self = Self(match NonZero::<u32>::new(u32::MAX) {
        Some(v) => v,
        None => unreachable!(),
    });
}

/// Details about the incoming data.
#[must_use]
#[derive(Debug)]
pub enum ReadWriteOutcome<'a, TNow, TSub>
where
    TNow: Clone + cmp::Ord,
{
    /// Nothing in particular happened.
    Idle {
        /// The [`Yamux`] state machine yielded back.
        yamux: Yamux<TNow, TSub>,
    },

    /// Remote has requested to open a new substream.
    ///
    /// After this has been received, either [`Yamux::accept_pending_substream`] or
    /// [`Yamux::reject_pending_substream`] needs to be called in order to accept or reject
    /// this substream. [`Yamux::read_write`] will stop reading incoming data before this is done.
    ///
    /// Note that this can never happen after [`Yamux::send_goaway`] has been called, as all
    /// substreams are then automatically rejected.
    IncomingSubstream {
        /// The [`Yamux`] state machine yielded back.
        // TODO: use an accept/reject wrapper instead
        yamux: Yamux<TNow, TSub>,
    },

    /// Received data corresponding to a substream.
    ProcessSubstream {
        /// Object allowing reading and writing data from/to the given substream.
        substream_read_write: SubstreamReadWrite<'a, TNow, TSub>,
    },

    /// Remote has asked to reset a substream.
    StreamReset {
        /// The [`Yamux`] state machine yielded back.
        yamux: Yamux<TNow, TSub>,
        /// Substream that has been reset.
        substream_id: SubstreamId,
    },

    /// Received a "go away" request. This means that it is now forbidden to open new outbound
    /// substreams. It is still allowed to send and receive data on existing substreams, and the
    /// remote is still allowed to open substreams.
    GoAway {
        /// The [`Yamux`] state machine yielded back.
        yamux: Yamux<TNow, TSub>,
        /// Error code sent by the remote.
        code: GoAwayErrorCode,
        /// List of all outgoing substreams that haven't been acknowledged by the remote yet.
        /// These substreams are considered as reset, similar to
        /// [`ReadWriteOutcome::StreamReset`].
        reset_substreams: Vec<SubstreamId>,
    },

    /// Received a response to a ping that has been sent out earlier.
    ///
    /// If multiple pings have been sent out simultaneously, they are always answered in the same
    /// order as they have been sent out.
    PingResponse {
        /// The [`Yamux`] state machine yielded back.
        yamux: Yamux<TNow, TSub>,
    },
}

pub struct SubstreamReadWrite<'a, TNow, TSub>
where
    TNow: Clone + cmp::Ord,
{
    outer_read_write: &'a mut ReadWrite<TNow>,
    inner_read_write: ReadWrite<TNow>,
    yamux: Yamux<TNow, TSub>,
    substream_id: NonZero<u32>,

    /// Size of the write buffers of the substream prior to its processing.
    write_buffers_len_before: usize,
}

impl<'a, TNow, TSub> SubstreamReadWrite<'a, TNow, TSub>
where
    TNow: Clone + cmp::Ord,
{
    /// Returns the identifier of the substream being read/written.
    pub fn substream_id(&self) -> SubstreamId {
        SubstreamId(self.substream_id)
    }

    pub fn read_write(&mut self) -> &mut ReadWrite<TNow> {
        &mut self.inner_read_write
    }

    /// Returns the user data associated to the substream being read/written.
    pub fn user_data(&self) -> &TSub {
        &self
            .yamux
            .inner
            .substreams
            .get(&self.substream_id)
            .unwrap()
            .user_data
    }

    /// Returns the user data associated to the substream being read/written.
    pub fn user_data_mut(&mut self) -> &mut TSub {
        &mut self
            .yamux
            .inner
            .substreams
            .get_mut(&self.substream_id)
            .unwrap()
            .user_data
    }

    pub fn finish(mut self) -> Yamux<TNow, TSub> {
        let Substream {
            inbound,
            state:
                SubstreamState::Healthy {
                    first_message_queued,
                    remote_allowed_window,
                    local_write_close,
                    remote_write_closed,
                    read_buffer,
                    expected_incoming_bytes,
                    substreams_wake_up_key,
                    ..
                },
            ..
        } = &mut self
            .yamux
            .inner
            .substreams
            .get_mut(&self.substream_id)
            .unwrap()
        else {
            unreachable!()
        };

        // Update the reading part of the substream's internal state.
        *read_buffer = mem::take(&mut self.inner_read_write.incoming_buffer);
        *expected_incoming_bytes = Some(self.inner_read_write.expected_incoming_bytes.unwrap_or(0));

        // If the substream requests more data than the remote is allowed to send, send out a
        // window frame. This ensures that the reading can never stall due to window frames issues.
        if let Some(mut missing_window_size) = NonZero::<usize>::new(
            expected_incoming_bytes
                .unwrap()
                .saturating_sub(usize::try_from(*remote_allowed_window).unwrap_or(usize::MAX)),
        ) {
            // Don't send super tiny window frames.
            if missing_window_size.get() < 1024 {
                missing_window_size = NonZero::<usize>::new(1024).unwrap();
            }

            let missing_window_size =
                NonZero::<u64>::new(u64::try_from(missing_window_size.get()).unwrap_or(u64::MAX))
                    .unwrap();

            self.yamux
                .inner
                .window_frames_to_send
                .entry(self.substream_id)
                .and_modify(|v| {
                    if *v < missing_window_size {
                        *v = missing_window_size;
                    }
                })
                .or_insert(missing_window_size);

            self.outer_read_write.wake_up_asap();
        }

        // When to wake up the substream for reading again.
        debug_assert!(substreams_wake_up_key.is_none());
        let will_wake_up_read_again = match (
            self.inner_read_write.read_bytes,
            &self.inner_read_write.wake_up_after,
        ) {
            (0, None) => {
                // Don't wake it up for reading.
                false
            }
            (0, Some(when)) if *when > self.outer_read_write.now => {
                // Wake it up at `when`.
                self.outer_read_write.wake_up_after(when);
                self.yamux
                    .inner
                    .substreams_wake_up
                    .insert((Some(when.clone()), self.substream_id));
                *substreams_wake_up_key = Some(Some(when.clone()));
                true
            }
            _ => {
                // Non-zero bytes written or `when <= now`.
                // Wake it up as soon as possible so it continues reading from its read buffer.
                self.outer_read_write.wake_up_asap();
                self.yamux
                    .inner
                    .substreams_wake_up
                    .insert((None, self.substream_id));
                *substreams_wake_up_key = Some(None);
                true
            }
        };

        // Update the `local_write_close` state of the substream.
        if matches!(*local_write_close, SubstreamStateLocalWrite::Open)
            && self.inner_read_write.write_bytes_queueable.is_none()
        {
            *local_write_close = SubstreamStateLocalWrite::FinDesired;
        }

        // Sanity check.
        debug_assert!(matches!(
            self.yamux.inner.outgoing,
            Outgoing::WritingOut { .. }
        ));

        // Process the writing side of the substream.
        if self.inner_read_write.write_bytes_queued != self.write_buffers_len_before
            && matches!(&self.yamux.inner.outgoing, Outgoing::WritingOut { buffers } if buffers.is_empty())
            && self
                .inner_read_write
                .write_bytes_queueable
                .map_or(false, |n| n != 0)
        {
            // Substream has written out data, but might have more to write. Put back the write
            // buffers for next time.
            // Note that there's no need to insert the substream in `substreams_write_read`, as
            // as the `Outgoing::PreparingDataFrame` state guarantees that this substream will be
            // processed again as soon as possible.
            self.yamux.inner.outgoing = Outgoing::PreparingDataFrame {
                substream_id: self.substream_id,
                write_buffers: mem::take(&mut self.inner_read_write.write_buffers),
            };
            self.outer_read_write.wake_up_asap();
        } else if self.inner_read_write.write_bytes_queued != 0
            || matches!(*local_write_close, SubstreamStateLocalWrite::FinDesired)
        {
            // Substream hasn't written anything more. A data frame is ready. Flush its data.

            // The substream should only have been able to write data if we're not currently
            // writing out. If this assertion fails, it indicates that the substream hasn't
            // respected the `ReadWrite` contract.
            debug_assert!(
                matches!(&self.yamux.inner.outgoing, Outgoing::WritingOut { buffers } if buffers.is_empty())
            );

            let mut write_buffers = mem::take(&mut self.inner_read_write.write_buffers);

            // When preparing the inner `ReadWrite` object, the `write_buffers` are set to
            // contain one empty entry of enough capacity to hold the header. There is a high
            // chance that this empty entry is still there, but if it's not we add it now.
            if write_buffers.first().map_or(true, |b| !b.is_empty()) {
                write_buffers.insert(0, Vec::with_capacity(12));
            }

            write_buffers[0].extend_from_slice(&header::encode(
                &header::DecodedYamuxHeader::Data {
                    syn: !*first_message_queued && !*inbound,
                    ack: !*first_message_queued && *inbound,
                    fin: matches!(*local_write_close, SubstreamStateLocalWrite::FinDesired),
                    rst: false,
                    stream_id: self.substream_id,
                    length: {
                        // Because the number of queuable bytes is capped by the value in
                        // `Config::max_out_data_frame_size`, we are guaranteed that the length
                        // to write out fits in a `u32`.
                        u32::try_from(self.inner_read_write.write_bytes_queued).unwrap()
                    },
                },
            ));
            if matches!(*local_write_close, SubstreamStateLocalWrite::FinDesired) {
                *local_write_close = SubstreamStateLocalWrite::FinQueued;
            }
            *first_message_queued = true;

            self.yamux.inner.outgoing = Outgoing::WritingOut {
                buffers: write_buffers,
            };

            self.outer_read_write.wake_up_asap();

            // Re-schedule the substream for writing, as it was maybe waiting for the queue to
            // be flushed before writing more data.
            self.yamux
                .inner
                .substreams_write_ready
                .insert(self.substream_id);
        } else if self.inner_read_write.write_bytes_queueable == Some(0) {
            // Substream hasn't written anything because it wasn't able to write anything.
            // Re-schedule the substream for when it is possible to write data out.
            self.yamux
                .inner
                .substreams_write_ready
                .insert(self.substream_id);
        } else {
            // Substream has nothing to write.
        }

        // Mark the substream as dead if it won't ever wake up again.
        if matches!(local_write_close, SubstreamStateLocalWrite::FinQueued)
            && *remote_write_closed
            && !will_wake_up_read_again
            && !self
                .yamux
                .inner
                .substreams_write_ready
                .contains(&self.substream_id)
            && !matches!(self.yamux.inner.outgoing,  Outgoing::PreparingDataFrame {
                substream_id,
                ..
            } if substream_id == self.substream_id)
        {
            let _was_inserted = self.yamux.inner.dead_substreams.insert(self.substream_id);
            debug_assert!(_was_inserted);
            debug_assert!(
                !self
                    .yamux
                    .inner
                    .substreams_wake_up
                    .iter()
                    .any(|(_, s)| *s == self.substream_id)
            );
            debug_assert!(
                !self
                    .yamux
                    .inner
                    .substreams_write_ready
                    .contains(&self.substream_id)
            );
            debug_assert!(
                !self
                    .yamux
                    .inner
                    .window_frames_to_send
                    .contains_key(&self.substream_id)
            );
        }

        self.yamux
    }

    /// Resets the substream being processed and returns the underlying [`Yamux`] object.
    pub fn reset(self) -> Yamux<TNow, TSub> {
        let substream_id = self.substream_id();
        let mut yamux = self.finish();
        match yamux.reset(substream_id) {
            Ok(()) => {}
            Err(ResetError::AlreadyClosed) => {}
            Err(ResetError::AlreadyReset) => debug_assert!(false),
        }
        yamux
    }
}

impl<'a, TNow, TSub> fmt::Debug for SubstreamReadWrite<'a, TNow, TSub>
where
    TNow: Clone + cmp::Ord,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SubstreamReadWrite")
            .field("substream_id", &self.substream_id)
            .finish()
    }
}

/// Error potentially returned by [`Yamux::open_substream`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum OpenSubstreamError {
    /// A `GoAway` frame has been received in the past.
    GoAwayReceived,
    /// Impossible to allocate a new substream.
    NoFreeSubstreamId,
}

/// Error potentially returned by [`Yamux::reset`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum ResetError {
    /// Substream was already reset.
    AlreadyReset,
    /// Substream was already closed.
    AlreadyClosed,
}

/// Error potentially returned by [`Yamux::send_goaway`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum SendGoAwayError {
    /// A `GoAway` has already been sent.
    AlreadySent,
}

/// Error potentially returned by [`Yamux::accept_pending_substream`] or
/// [`Yamux::reject_pending_substream`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum PendingSubstreamError {
    /// No substream is pending.
    NoPendingSubstream,
}

/// Error while decoding the Yamux stream.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum Error {
    /// Failed to decode an incoming Yamux header.
    HeaderDecode(header::YamuxHeaderDecodeError),
    /// Received a SYN flag with a substream ID that is of the same side as the local side.
    #[display("Received a SYN flag with a substream ID that is of the same side as the local side")]
    InvalidInboundStreamId { stream_id: NonZero<u32> },
    /// Received a SYN flag with a known substream ID.
    #[display("Received a SYN flag with a known substream ID")]
    UnexpectedSyn { stream_id: NonZero<u32> },
    /// Remote tried to send more data than it was allowed to.
    CreditsExceeded,
    /// Number of credits allocated to the local node has overflowed.
    LocalCreditsOverflow,
    /// Remote sent additional data on a substream after having sent the FIN flag.
    WriteAfterFin,
    /// Remote has sent a data frame containing data at the same time as a `RST` flag.
    DataWithRst,
    /// Remote has sent a ping response, but its opaque data didn't match any of the ping that
    /// have been sent out in the past.
    PingResponseNotMatching,
    /// Maximum number of simultaneous RST frames to send out has been exceeded.
    MaxSimultaneousRstSubstreamsExceeded,
    /// Maximum number of simultaneous PONG frames to send out has been exceeded.
    MaxSimultaneousPingsExceeded,
    /// The remote should have sent an ACK flag but didn't.
    ExpectedAck,
    /// The remote sent an ACK flag but shouldn't have.
    UnexpectedAck,
    /// Received multiple `GoAway` frames.
    MultipleGoAways,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DeadSubstreamTy {
    ClosedGracefully,
    Reset,
}

/// By default, all new substreams have this implicit window size.
pub const NEW_SUBSTREAMS_FRAME_SIZE: u64 = 256 * 1024;
