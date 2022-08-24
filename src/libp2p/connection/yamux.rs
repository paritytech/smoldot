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
//! Call [`Yamux::incoming_data`] when data is available on the socket. This function parses
//! the received data, updates the internal state machine, and possibly returns an
//! [`IncomingDataDetail`].
//! Call [`Yamux::extract_out`] when the remote is ready to accept more data.
//!
//! The generic parameter of [`Yamux`] is an opaque "user data" associated to each substream.
//!
//! When [`SubstreamMut::write`] is called, the buffer of data to send out is stored within the
//! [`Yamux`] object. This data will then be progressively returned by
//! [`Yamux::extract_out`].
//!
//! It is the responsibility of the user to enforce a bound to the amount of enqueued data, as
//! the [`Yamux`] itself doesn't enforce any limit. Enforcing such a bound must be done based
//! on the logic of the higher-level protocols. Failing to do so might lead to potential DoS
//! attack vectors.

// TODO: write example

// TODO: the code of this module is rather complicated; either simplify it or write a lot of tests, including fuzzing tests

use crate::util::SipHasherBuild;

use alloc::{collections::VecDeque, vec::Vec};
use core::{
    cmp, fmt, mem,
    num::{NonZeroU32, NonZeroUsize},
};
use hashbrown::hash_map::{Entry, OccupiedEntry};
use rand::Rng as _;
use rand_chacha::{rand_core::SeedableRng as _, ChaCha20Rng};

pub use header::GoAwayErrorCode;

mod header;

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
}

pub struct Yamux<T> {
    /// List of substreams currently open in the Yamux state machine.
    ///
    /// A `SipHasher` is used in order to avoid hash collision attacks on substream IDs.
    substreams: hashbrown::HashMap<NonZeroU32, Substream<T>, SipHasherBuild>,

    /// What kind of data is expected on the socket next.
    incoming: Incoming,

    /// What to write to the socket next.
    outgoing: Outgoing,

    /// Id of the next outgoing substream to open.
    /// This implementation allocates identifiers linearly. Every time a substream is open, its
    /// value is incremented by two.
    next_outbound_substream: NonZeroU32,

    /// Number of pings to send out that haven't been queued yet.
    pings_to_send: u32,

    /// List of pings that have been sent out but haven't been replied yet. For each ping,
    /// contains the opaque value that has been sent out and that must be matched by the remote.
    pings_waiting_reply: VecDeque<u32>,

    /// Source of randomness used for various purposes.
    randomness: ChaCha20Rng,
}

struct Substream<T> {
    /// True if a message on this substream has already been sent since it has been opened. The
    /// first message on a substream must contain either a SYN or `ACK` flag.
    first_message_queued: bool,
    /// Amount of data the remote is allowed to transmit to the local node.
    remote_allowed_window: u64,
    /// If non-zero, a window update frame must be sent to the remote to grant this number of
    /// bytes.
    remote_window_pending_increase: u64,
    /// Amount of data the local node is allowed to transmit to the remote.
    allowed_window: u64,
    /// True if the writing side of the local node is closed for this substream.
    /// Note that the data queued in [`Substream::write_buffers`] must still be sent out,
    /// alongside with a frame with a FIN flag.
    local_write_closed: bool,
    /// True if the writing side of the remote node is closed for this substream.
    remote_write_closed: bool,
    /// Buffer of buffers to be written out to the socket.
    // TODO: is it a good idea to have an unbounded Vec?
    // TODO: call shrink_to_fit from time to time?
    write_buffers: Vec<Vec<u8>>,
    /// Number of bytes in `self.write_buffers[0]` has have already been written out to the
    /// socket.
    first_write_buffer_offset: usize,
    /// `true` if a reset of the substreams has been performed, either locally or by the remote.
    was_reset: bool,
    /// Data chosen by the user.
    user_data: T,
}

enum Incoming {
    /// Expect a header. The field might contain some already-read bytes.
    Header(arrayvec::ArrayVec<u8, 12>),
    /// Expect the data of a previously-received data frame header.
    DataFrame {
        /// Identifier of the substream the data belongs to.
        substream_id: SubstreamId,
        /// Number of bytes of data remaining before the frame ends.
        remaining_bytes: u32,
        /// True if the remote writing side of the substream should be closed after receiving the
        /// data frame.
        fin: bool,
    },

    /// A header referring to a new substream has been received. The reception of any further data
    /// is blocked waiting for the API user to accept or reject this substream.
    ///
    /// Note that [`Yamux::outgoing`] must always be [`Outgoing::Idle`], in order to give the
    /// possibility to send back a RST frame for the new substream.
    PendingIncomingSubstream {
        /// Identifier of the pending substream.
        substream_id: SubstreamId,
        /// Extra local window size to give to this substream.
        extra_window: u32,
        /// If non-zero, must transition to a [`Incoming::DataFrame`].
        data_frame_size: u32,
        /// True if the remote writing side of the substream should be closed after receiving the
        /// `data_frame_size` bytes.
        fin: bool,
    },
}

enum Outgoing {
    /// Nothing to write out.
    Idle,

    /// Writing out a header.
    Header {
        /// Bytes of the header to write out.
        ///
        /// The length of this buffer might not be equal to 12 in case some parts of the header have
        /// already been written out but not all.
        ///
        /// Never empty (as otherwise the state must have been transitioned to something else).
        header: arrayvec::ArrayVec<u8, 12>,

        /// If `Some`, then the header is data frame header and we must then transition the
        /// state to [`Outgoing::SubstreamData`].
        substream_data_frame: Option<(SubstreamId, NonZeroUsize)>,
    },

    /// Writing out data from a substream.
    ///
    /// We have sent a data header in the past, and we must now send the associated data.
    SubstreamData {
        /// Which substream is being written out.
        id: SubstreamId,

        /// Number of bytes remaining to write.
        remaining_bytes: NonZeroUsize,
    },
}

impl<T> Yamux<T> {
    /// Initializes a new Yamux state machine.
    pub fn new(config: Config) -> Yamux<T> {
        let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

        Yamux {
            substreams: hashbrown::HashMap::with_capacity_and_hasher(
                config.capacity,
                SipHasherBuild::new(randomness.gen()),
            ),
            incoming: Incoming::Header(arrayvec::ArrayVec::new()),
            outgoing: Outgoing::Idle,
            next_outbound_substream: if config.is_initiator {
                NonZeroU32::new(1).unwrap()
            } else {
                NonZeroU32::new(2).unwrap()
            },
            pings_to_send: 0,
            // We leave the initial capacity at 0, as it is likely that no ping is sent at all.
            pings_waiting_reply: VecDeque::new(),
            randomness,
        }
    }

    /// Opens a new substream.
    ///
    /// This method only modifies the state of `self` and reserves an identifier. No message needs
    /// to be sent to the remote before data is actually being sent on the substream.
    ///
    /// > **Note**: Importantly, the remote will not be notified of the substream being open
    /// >           before the local side sends data on this substream. As such, protocols where
    /// >           the remote is expected to send data in response to a substream being open,
    /// >           without the local side first sending some data on that substream, will not
    /// >           work. In practice, while this is technically out of concern of the Yamux
    /// >           protocol, all substreams in the context of libp2p start with a
    /// >           multistream-select negotiation, and this scenario can therefore never happen.
    ///
    /// # Panic
    ///
    /// Panics if all possible substream IDs are already taken. This happen if there exists more
    /// than approximately `2^31` substreams, which is very unlikely to happen unless there exists a
    /// bug in the code.
    ///
    pub fn open_substream(&mut self, user_data: T) -> SubstreamMut<T> {
        // Make sure that the `loop` below can finish.
        assert!(usize::try_from(u32::max_value() / 2 - 1)
            .map_or(true, |full_len| self.substreams.len() < full_len));

        // Grab a `VacantEntry` in `self.substreams`.
        let entry = loop {
            // Allocating a substream ID is surprisingly difficult because overflows in the
            // identifier are possible if the software runs for a very long time.
            // Rather than naively incrementing the id by two and assuming that no substream with
            // this ID exists, the code below properly handles wrapping around and ignores IDs
            // already in use .
            // TODO: simply skill whole connection if overflow
            let id_attempt = self.next_outbound_substream;
            self.next_outbound_substream = {
                let mut id = self.next_outbound_substream.get();
                loop {
                    // Odd ids are reserved for the initiator and even ids are reserved for the
                    // listener. Assuming that the current id is valid, incrementing by 2 will
                    // lead to a valid id as well.
                    id = id.wrapping_add(2);
                    // However, the substream ID `0` is always invalid.
                    match NonZeroU32::new(id) {
                        Some(v) => break v,
                        None => continue,
                    }
                }
            };
            if let Entry::Vacant(e) = self.substreams.entry(id_attempt) {
                break e;
            }
        };

        // ID that was just allocated.
        let substream_id = SubstreamId(*entry.key());

        entry.insert(Substream {
            first_message_queued: false,
            remote_allowed_window: DEFAULT_FRAME_SIZE,
            remote_window_pending_increase: 0,
            allowed_window: DEFAULT_FRAME_SIZE,
            local_write_closed: false,
            remote_write_closed: false,
            write_buffers: Vec::with_capacity(16),
            first_write_buffer_offset: 0,
            was_reset: false,
            user_data,
        });

        match self.substreams.entry(substream_id.0) {
            Entry::Occupied(e) => SubstreamMut { substream: e },
            _ => unreachable!(),
        }
    }

    /// Returns an iterator to the list of all substream user datas.
    pub fn user_datas(&self) -> impl ExactSizeIterator<Item = (SubstreamId, &T)> {
        self.substreams
            .iter()
            .map(|(id, s)| (SubstreamId(*id), &s.user_data))
    }

    /// Returns an iterator to the list of all substream user datas.
    pub fn user_datas_mut(&mut self) -> impl ExactSizeIterator<Item = (SubstreamId, &mut T)> {
        self.substreams
            .iter_mut()
            .map(|(id, s)| (SubstreamId(*id), &mut s.user_data))
    }

    /// Returns a reference to a substream by its ID. Returns `None` if no substream with this ID
    /// is open.
    pub fn substream_by_id(&self, id: SubstreamId) -> Option<SubstreamRef<T>> {
        Some(SubstreamRef {
            id,
            substream: self.substreams.get(&id.0)?,
        })
    }

    /// Returns a reference to a substream by its ID. Returns `None` if no substream with this ID
    /// is open.
    pub fn substream_by_id_mut(&mut self, id: SubstreamId) -> Option<SubstreamMut<T>> {
        if let Entry::Occupied(e) = self.substreams.entry(id.0) {
            Some(SubstreamMut { substream: e })
        } else {
            None
        }
    }

    /// Queues sending out a ping to the remote.
    pub fn queue_ping(&mut self) {
        self.pings_to_send += 1;
    }

    /// Finds a substream that has been closed or reset, and removes it from this state machine.
    pub fn next_dead_substream(&mut self) -> Option<(SubstreamId, DeadSubstreamTy, T)> {
        // TODO: O(n)
        let id = self
            .substreams
            .iter()
            .filter(|(_, substream)| {
                substream.local_write_closed
                    && substream.remote_write_closed
                    && (substream.write_buffers.is_empty() // TODO: cumbersome
                        || (substream.write_buffers.len() == 1
                            && substream.write_buffers[0].len()
                                <= substream.first_write_buffer_offset))
            })
            .map(|(id, _)| *id)
            .next()?;

        let substream = self.substreams.remove(&id).unwrap();

        Some((
            SubstreamId(id),
            if substream.was_reset {
                DeadSubstreamTy::Reset
            } else {
                DeadSubstreamTy::ClosedGracefully
            },
            substream.user_data,
        ))
    }

    /// Process some incoming data.
    ///
    /// This function takes ownership of `self` and yields it back if everything goes well. If,
    /// on the other hand, a malformed packet is received, an error is yielded and `self` is
    /// destroyed.
    ///
    /// This function might not process all the data available for one of the following reasons:
    ///
    /// - Not all outgoing data has been extracted. In order to process incoming messages, the
    /// Yamux might have to queue data to be written out. For example, incoming pings must be
    /// replied to. In order to avoid queue an infinite amount of data, processing incoming
    /// messages might be blocked if there is data to be sent out.
    /// - It is currently waiting for either [`Yamux::accept_pending_substream`] or
    /// [`Yamux::reject_pending_substream`] to be called.
    ///
    /// If the return value contains [`IncomingDataDetail::IncomingSubstream`], then either
    /// [`Yamux::accept_pending_substream`] or [`Yamux::reject_pending_substream`] must be called
    /// in order to accept or reject the pending substream. API users are encouraged to enforce a
    /// limit to the total number of substreams in order to clamp the memory usage of this state
    /// machine.
    pub fn incoming_data(mut self, mut data: &[u8]) -> Result<IncomingDataOutcome<T>, Error> {
        let mut total_read: usize = 0;

        while !data.is_empty() {
            match self.incoming {
                Incoming::PendingIncomingSubstream { .. } => break,

                Incoming::DataFrame {
                    substream_id,
                    remaining_bytes: 0,
                    fin: true,
                } => {
                    self.incoming = Incoming::Header(arrayvec::ArrayVec::new());

                    let substream = match self.substreams.get_mut(&substream_id.0) {
                        Some(s) => s,
                        None => continue,
                    };

                    substream.remote_write_closed = true;

                    return Ok(IncomingDataOutcome {
                        yamux: self,
                        bytes_read: total_read,
                        detail: Some(IncomingDataDetail::StreamClosed { substream_id }),
                    });
                }

                Incoming::DataFrame {
                    substream_id,
                    ref mut remaining_bytes,
                    fin,
                } => {
                    let pulled_data = cmp::min(
                        *remaining_bytes,
                        u32::try_from(data.len()).unwrap_or(u32::max_value()),
                    );

                    let pulled_data_usize = usize::try_from(pulled_data).unwrap();
                    *remaining_bytes -= pulled_data;

                    let start_offset = total_read;
                    total_read += pulled_data_usize;
                    data = &data[pulled_data_usize..];

                    if let Some(substream) = self.substreams.get_mut(&substream_id.0) {
                        debug_assert!(!substream.remote_write_closed);
                        if *remaining_bytes == 0 {
                            if fin {
                                // If `fin`, leave `incoming` as `DataFrame`, so that it gets
                                // picked at the next iteration and a `StreamClosed` gets
                                // returned.
                                substream.remote_write_closed = true;
                            } else {
                                self.incoming = Incoming::Header(arrayvec::ArrayVec::new());
                            }
                        }

                        return Ok(IncomingDataOutcome {
                            yamux: self,
                            bytes_read: total_read,
                            detail: Some(IncomingDataDetail::DataFrame {
                                substream_id,
                                start_offset,
                            }),
                        });
                    }
                    if *remaining_bytes == 0 {
                        self.incoming = Incoming::Header(arrayvec::ArrayVec::new());
                    }
                }

                Incoming::Header(ref mut incoming_header) => {
                    // Try to copy as much as possible from `data` to `incoming_header`.
                    while !data.is_empty() && incoming_header.len() < 12 {
                        incoming_header.push(data[0]);
                        total_read += 1;
                        data = &data[1..];
                    }

                    // Not enough data to finish receiving header. Nothing more can be done.
                    if incoming_header.len() != 12 {
                        debug_assert!(data.is_empty());
                        break;
                    }

                    // Full header available to decode in `incoming_header`.
                    let decoded_header = match header::decode_yamux_header(&incoming_header) {
                        Ok(h) => h,
                        Err(err) => return Err(Error::HeaderDecode(err)),
                    };

                    // Handle any message other than data or window size.
                    match decoded_header {
                        header::DecodedYamuxHeader::PingRequest { .. } => {
                            // Ping. In order to queue the pong message, the outgoing queue must
                            // be empty. If it is not the case, we simply leave the ping header
                            // there and prevent any further data from being read.
                            if !matches!(self.outgoing, Outgoing::Idle) {
                                break;
                            }

                            self.outgoing = Outgoing::Header {
                                header: {
                                    let mut header = arrayvec::ArrayVec::new();
                                    header
                                        .try_extend_from_slice(
                                            &[
                                                0,
                                                2,
                                                0x0,
                                                0x2,
                                                0,
                                                0,
                                                0,
                                                0,
                                                incoming_header[8],
                                                incoming_header[9],
                                                incoming_header[10],
                                                incoming_header[11],
                                            ][..],
                                        )
                                        .unwrap();
                                    header
                                },
                                substream_data_frame: None,
                            };

                            self.incoming = Incoming::Header(arrayvec::ArrayVec::new());
                        }
                        header::DecodedYamuxHeader::PingResponse { opaque_value } => {
                            let pos = match self
                                .pings_waiting_reply
                                .iter()
                                .position(|v| *v == opaque_value)
                            {
                                Some(p) => p,
                                None => return Err(Error::PingResponseNotMatching),
                            };

                            self.pings_waiting_reply.remove(pos);
                            self.incoming = Incoming::Header(arrayvec::ArrayVec::new());
                            return Ok(IncomingDataOutcome {
                                yamux: self,
                                bytes_read: total_read,
                                detail: Some(IncomingDataDetail::PingResponse),
                            });
                        }
                        header::DecodedYamuxHeader::GoAway { error_code } => {
                            // TODO: error if we have received one in the past before?
                            // TODO: error if the remote then opens new substreams or something?
                            self.incoming = Incoming::Header(arrayvec::ArrayVec::new());
                            return Ok(IncomingDataOutcome {
                                yamux: self,
                                bytes_read: total_read,
                                detail: Some(IncomingDataDetail::GoAway(error_code)),
                            });
                        }
                        header::DecodedYamuxHeader::Data {
                            rst: true,
                            stream_id,
                            length,
                            ..
                        }
                        | header::DecodedYamuxHeader::Window {
                            rst: true,
                            stream_id,
                            length,
                            ..
                        } => {
                            // Handle `RST` flag separately.
                            if matches!(decoded_header, header::DecodedYamuxHeader::Data { .. })
                                && length != 0
                            {
                                return Err(Error::DataWithRst);
                            }

                            self.incoming = Incoming::Header(arrayvec::ArrayVec::new());

                            // The remote might have sent a RST frame concerning a substream for
                            // which we have sent a RST frame earlier. Considering that we don't
                            // keep traces of old substreams, we have no way to know whether this
                            // is the case or not.
                            if let Some(s) = self.substreams.get_mut(&stream_id) {
                                s.local_write_closed = true;
                                s.remote_write_closed = true;
                                s.write_buffers.clear();
                                s.first_write_buffer_offset = 0;
                                s.was_reset = true;
                            }
                        }

                        // Remote has sent a SYN flag. A new substream is to be opened.
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
                            if self.substreams.contains_key(&stream_id) {
                                return Err(Error::UnexpectedSyn(stream_id));
                            }

                            // As documented, when in the `Incoming::PendingIncomingSubstream`
                            // state, the outgoing state must always be `Outgoing::Idle`, in
                            // order to potentially queue the substream rejection message later.
                            // If it is not the case, we simply leave the header there and prevent
                            // any further data from being read.
                            if !matches!(self.outgoing, Outgoing::Idle) {
                                break;
                            }

                            let is_data =
                                matches!(decoded_header, header::DecodedYamuxHeader::Data { .. });
                            self.incoming = Incoming::PendingIncomingSubstream {
                                substream_id: SubstreamId(stream_id),
                                extra_window: if !is_data { length } else { 0 },
                                data_frame_size: if is_data { length } else { 0 },
                                fin,
                            };

                            return Ok(IncomingDataOutcome {
                                yamux: self,
                                bytes_read: total_read,
                                detail: Some(IncomingDataDetail::IncomingSubstream),
                            });
                        }

                        header::DecodedYamuxHeader::Data {
                            syn: false,
                            rst: false,
                            stream_id,
                            length,
                            fin,
                            ..
                        } => {
                            // Find the element in `self.substreams` corresponding to the substream
                            // requested by the remote.
                            // Note that it is possible that the remote is referring to a substream
                            // for which a RST has been sent out by the local node. Since the
                            // local state machine doesn't keep track of RST'ted substreams, any
                            // frame concerning a substream with an unknown id is discarded and
                            // doesn't result in an error, under the presumption that we are
                            // in this situation. When that is the case, the `substream` variable
                            // below is `None`.
                            let substream = self.substreams.get_mut(&stream_id);

                            // Data frame.
                            // Check whether the remote has the right to send that much data.
                            // Note that the credits aren't checked in the case of an unknown
                            // substream.
                            if let Some(substream) = substream {
                                if substream.remote_write_closed {
                                    return Err(Error::WriteAfterFin);
                                }

                                substream.remote_allowed_window = substream
                                    .remote_allowed_window
                                    .checked_sub(u64::from(length))
                                    .ok_or(Error::CreditsExceeded)?;

                                // TODO: make this behavior tweakable by the user!
                                substream.remote_window_pending_increase += 256 * 1024;
                            }

                            self.incoming = Incoming::DataFrame {
                                substream_id: SubstreamId(stream_id),
                                remaining_bytes: length,
                                fin,
                            };
                        }

                        header::DecodedYamuxHeader::Window {
                            syn: false,
                            rst: false,
                            stream_id,
                            length,
                            fin,
                            ..
                        } => {
                            // Note that it is possible that the remote is referring to a substream
                            // for which a RST has been sent out by the local node. Since the
                            // local state machine doesn't keep track of RST'ted substreams, any
                            // frame concerning a substream with an unknown id is discarded and
                            // doesn't result in an error, under the presumption that we are
                            // in this situation.
                            if let Some(substream) = self.substreams.get_mut(&stream_id) {
                                // Note that the specs are a unclear about whether the remote
                                // can or should continue sending FIN flags on window size
                                // frames after their side of the substream has already been
                                //closed before.
                                if fin {
                                    self.incoming = Incoming::DataFrame {
                                        substream_id: SubstreamId(stream_id),
                                        remaining_bytes: 0,
                                        fin: true,
                                    };
                                }

                                substream.allowed_window = substream
                                    .allowed_window
                                    .checked_add(u64::from(length))
                                    .ok_or(Error::LocalCreditsOverflow)?;
                            }

                            self.incoming = Incoming::Header(arrayvec::ArrayVec::new());
                        }
                    }
                }
            }
        }

        Ok(IncomingDataOutcome {
            yamux: self,
            bytes_read: total_read,
            detail: None,
        })
    }

    /// Returns an object that provides an iterator to a list of buffers whose content must be
    /// sent out on the socket.
    ///
    /// The buffers produced by the iterator will never yield more than `size_bytes` bytes of
    /// data. The user is expected to pass an exact amount of bytes that the next layer is ready
    /// to accept.
    ///
    /// After the [`ExtractOut`] has been destroyed, the Yamux state machine will automatically
    /// consider that these `size_bytes` have been sent out, even if the iterator has been
    /// destroyed before finishing. It is a logic error to `mem::forget` the [`ExtractOut`].
    ///
    /// > **Note**: Most other objects in the networking code have a "`read_write`" method that
    /// >           writes the outgoing data to a buffer. This is an idiomatic way to do things in
    /// >           situations where the data is generated on the fly. In the context of Yamux,
    /// >           however, this would be rather sub-optimal considering that buffers to send out
    /// >           are already stored in their final form in the state machine.
    pub fn extract_out(&mut self, size_bytes: usize) -> ExtractOut<T> {
        ExtractOut {
            yamux: self,
            size_bytes,
        }
    }

    /// Accepts an incoming substream.
    ///
    /// Either [`Yamux::accept_pending_substream`] or [`Yamux::reject_pending_substream`] must be
    /// called after [`IncomingDataDetail::IncomingSubstream`] is returned.
    ///
    /// Note that there is no expiration window after [`IncomingDataDetail::IncomingSubstream`]
    /// is returned until the substream is no longer valid. However, reading will be blocked until
    /// the substream is either accepted or rejected. This function should thus be called as
    /// soon as possible.
    ///
    /// # Panic
    ///
    /// Panics if no incoming substream is currently pending.
    ///
    pub fn accept_pending_substream(&mut self, user_data: T) -> SubstreamMut<T> {
        match self.incoming {
            Incoming::PendingIncomingSubstream {
                substream_id,
                extra_window,
                data_frame_size,
                fin,
            } => {
                let _was_before = self.substreams.insert(
                    substream_id.0,
                    Substream {
                        first_message_queued: false,
                        remote_allowed_window: DEFAULT_FRAME_SIZE,
                        remote_window_pending_increase: 0,
                        allowed_window: DEFAULT_FRAME_SIZE + u64::from(extra_window),
                        local_write_closed: false,
                        remote_write_closed: data_frame_size == 0 && fin,
                        write_buffers: Vec::new(),
                        first_write_buffer_offset: 0,
                        was_reset: false,
                        user_data,
                    },
                );
                debug_assert!(_was_before.is_none());

                self.incoming = if data_frame_size == 0 {
                    Incoming::Header(arrayvec::ArrayVec::new())
                } else {
                    Incoming::DataFrame {
                        substream_id,
                        remaining_bytes: data_frame_size,
                        fin,
                    }
                };

                SubstreamMut {
                    substream: match self.substreams.entry(substream_id.0) {
                        Entry::Occupied(e) => e,
                        _ => unreachable!(),
                    },
                }
            }
            _ => panic!(),
        }
    }

    /// Rejects an incoming substream.
    ///
    /// Either [`Yamux::accept_pending_substream`] or [`Yamux::reject_pending_substream`] must be
    /// called after [`IncomingDataDetail::IncomingSubstream`] is returned.
    ///
    /// Note that there is no expiration window after [`IncomingDataDetail::IncomingSubstream`]
    /// is returned until the substream is no longer valid. However, reading will be blocked until
    /// the substream is either accepted or rejected. This function should thus be called as
    /// soon as possible.
    ///
    /// # Panic
    ///
    /// Panics if no incoming substream is currently pending.
    ///
    pub fn reject_pending_substream(&mut self) {
        match self.incoming {
            Incoming::PendingIncomingSubstream {
                substream_id,
                data_frame_size,
                fin,
                ..
            } => {
                self.incoming = if data_frame_size == 0 {
                    Incoming::Header(arrayvec::ArrayVec::new())
                } else {
                    Incoming::DataFrame {
                        substream_id,
                        remaining_bytes: data_frame_size,
                        fin,
                    }
                };

                let mut header = arrayvec::ArrayVec::new();
                header.push(0);
                header.push(1);
                header.try_extend_from_slice(&0x8u16.to_be_bytes()).unwrap();
                header
                    .try_extend_from_slice(&substream_id.0.get().to_be_bytes())
                    .unwrap();
                header.try_extend_from_slice(&0u32.to_be_bytes()).unwrap();
                debug_assert_eq!(header.len(), 12);

                debug_assert!(matches!(self.outgoing, Outgoing::Idle));
                self.outgoing = Outgoing::Header {
                    header,
                    substream_data_frame: None,
                };
            }
            _ => panic!(),
        }
    }

    /// Writes a data frame header in `self.outgoing`.
    ///
    /// # Panic
    ///
    /// Panics if `self.outgoing` is not `Idle`.
    ///
    fn queue_data_frame_header(
        &mut self,
        syn_ack_flag: bool,
        fin_flag: bool,
        substream_id: NonZeroU32,
        data_length: u32,
    ) {
        assert!(matches!(self.outgoing, Outgoing::Idle));

        let mut flags: u16 = 0;
        if syn_ack_flag {
            if (substream_id.get() % 2) == (self.next_outbound_substream.get() % 2) {
                // SYN
                flags |= 0x1;
            } else {
                // ACK
                flags |= 0x2;
            }
        }
        if fin_flag {
            flags |= 0x4;
        }

        let mut header = arrayvec::ArrayVec::new();
        header.push(0);
        header.push(0);
        header.try_extend_from_slice(&flags.to_be_bytes()).unwrap();
        header
            .try_extend_from_slice(&substream_id.get().to_be_bytes())
            .unwrap();
        header
            .try_extend_from_slice(&data_length.to_be_bytes())
            .unwrap();
        debug_assert_eq!(header.len(), 12);

        self.outgoing = Outgoing::Header {
            header,
            substream_data_frame: if let Some(length) =
                NonZeroUsize::new(usize::try_from(data_length).unwrap())
            {
                Some((SubstreamId(substream_id), length))
            } else {
                None
            },
        };
    }

    /// Writes a window size update frame header in `self.outgoing`.
    ///
    /// # Panic
    ///
    /// Panics if `self.outgoing` is not `Idle`.
    ///
    fn queue_window_size_frame_header(
        &mut self,
        syn_ack_flag: bool,
        substream_id: NonZeroU32,
        window_size: u32,
    ) {
        assert!(matches!(self.outgoing, Outgoing::Idle));

        let mut flags: u16 = 0;
        if syn_ack_flag {
            if (substream_id.get() % 2) == (self.next_outbound_substream.get() % 2) {
                // SYN
                flags |= 0x1;
            } else {
                // ACK
                flags |= 0x2;
            }
        }

        let mut header = arrayvec::ArrayVec::new();
        header.push(0);
        header.push(1);
        header.try_extend_from_slice(&flags.to_be_bytes()).unwrap();
        header
            .try_extend_from_slice(&substream_id.get().to_be_bytes())
            .unwrap();
        header
            .try_extend_from_slice(&window_size.to_be_bytes())
            .unwrap();
        debug_assert_eq!(header.len(), 12);

        self.outgoing = Outgoing::Header {
            header,
            substream_data_frame: None,
        };
    }

    /// Writes a ping frame header in `self.outgoing`.
    ///
    /// # Panic
    ///
    /// Panics if `self.outgoing` is not `Idle`.
    ///
    fn queue_ping_request_header(&mut self, opaque_value: u32) {
        assert!(matches!(self.outgoing, Outgoing::Idle));

        let mut header = arrayvec::ArrayVec::new();
        header.push(0);
        header.push(2);
        header.try_extend_from_slice(&[0, 1]).unwrap();
        header.try_extend_from_slice(&[0, 0, 0, 0]).unwrap();
        header
            .try_extend_from_slice(&opaque_value.to_be_bytes())
            .unwrap();
        debug_assert_eq!(header.len(), 12);

        self.outgoing = Outgoing::Header {
            header,
            substream_data_frame: None,
        };
    }
}

impl<T> fmt::Debug for Yamux<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct List<'a, T>(&'a Yamux<T>);
        impl<'a, T> fmt::Debug for List<'a, T>
        where
            T: fmt::Debug,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list()
                    .entries(self.0.substreams.values().map(|v| &v.user_data))
                    .finish()
            }
        }

        f.debug_struct("Yamux")
            .field("substreams", &List(self))
            .finish()
    }
}

/// Reference to a substream within the [`Yamux`].
pub struct SubstreamRef<'a, T> {
    id: SubstreamId,
    substream: &'a Substream<T>,
}

impl<'a, T> SubstreamRef<'a, T> {
    /// Identifier of the substream.
    pub fn id(&self) -> SubstreamId {
        self.id
    }

    /// Returns the user data associated to this substream.
    pub fn user_data(&self) -> &T {
        &self.substream.user_data
    }

    /// Returns the user data associated to this substream.
    pub fn into_user_data(self) -> &'a T {
        &self.substream.user_data
    }

    /// Returns the number of bytes queued for writing on this substream.
    pub fn queued_bytes(&self) -> usize {
        self.substream
            .write_buffers
            .iter()
            .fold(0, |n, buf| n + buf.len())
    }

    /// Returns `true` if the remote has closed their writing side of this substream.
    pub fn is_remote_closed(&self) -> bool {
        self.substream.remote_write_closed
    }

    /// Returns `true` if [`SubstreamMut::close`] has been called on this substream.
    pub fn is_closed(&self) -> bool {
        self.substream.local_write_closed
    }
}

impl<'a, T> fmt::Debug for SubstreamRef<'a, T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Substream").field(self.user_data()).finish()
    }
}

/// Reference to a substream within the [`Yamux`].
pub struct SubstreamMut<'a, T> {
    substream: OccupiedEntry<'a, NonZeroU32, Substream<T>, SipHasherBuild>,
}

impl<'a, T> SubstreamMut<'a, T> {
    /// Identifier of the substream.
    pub fn id(&self) -> SubstreamId {
        SubstreamId(*self.substream.key())
    }

    /// Returns the user data associated to this substream.
    pub fn user_data(&self) -> &T {
        &self.substream.get().user_data
    }

    /// Returns the user data associated to this substream.
    pub fn user_data_mut(&mut self) -> &mut T {
        &mut self.substream.get_mut().user_data
    }

    /// Returns the user data associated to this substream.
    pub fn into_user_data(self) -> &'a mut T {
        &mut self.substream.into_mut().user_data
    }

    /// Appends data to the buffer of data to send out on this substream.
    ///
    /// # Panic
    ///
    /// Panics if [`SubstreamMut::close`] has already been called on this substream.
    ///
    pub fn write(&mut self, data: Vec<u8>) {
        let substream = self.substream.get_mut();
        assert!(!substream.local_write_closed);
        debug_assert!(
            !substream.write_buffers.is_empty() || substream.first_write_buffer_offset == 0
        );
        substream.write_buffers.push(data);
    }

    /// Allow the remote to send up to `bytes` bytes at once in the next packet.
    ///
    /// This method sets the number of allowed bytes to at least this value. In other words,
    /// if this method was to be twice with the same parameter, the second call would have no
    /// effect.
    ///
    /// # Context
    ///
    /// In order to properly handle back-pressure, the Yamux protocol only allows the remote to
    /// send a certain number of bytes before the local node grants the authorization to send more
    /// data.
    /// This method grants the authorization to the remote to send up to `bytes` bytes.
    ///
    /// Call this when you expect a large payload with the maximum size this payload is allowed
    /// to be.
    ///
    pub fn reserve_window(&mut self, bytes: u64) {
        let substream = self.substream.get_mut();
        substream.remote_window_pending_increase =
            cmp::max(substream.remote_window_pending_increase, bytes);
    }

    /// Returns the number of bytes queued for writing on this substream.
    pub fn queued_bytes(&self) -> usize {
        let substream = self.substream.get();
        substream
            .write_buffers
            .iter()
            .fold(0, |n, buf| n + buf.len())
    }

    /// Returns `true` if the remote has closed their writing side of this substream.
    pub fn is_remote_closed(&self) -> bool {
        self.substream.get().remote_write_closed
    }

    /// Returns `true` if [`SubstreamMut::close`] has been called on this substream.
    pub fn is_closed(&self) -> bool {
        self.substream.get().local_write_closed
    }

    /// Marks the substream as closed. It is no longer possible to write data on it.
    ///
    /// # Panic
    ///
    /// Panics if the local writing side is already closed, which can happen if
    /// [`SubstreamMut::close`] has already been called on this substream or if the remote has
    /// reset the substream in the past.
    ///
    pub fn close(&mut self) {
        let substream = self.substream.get_mut();
        assert!(!substream.local_write_closed);
        substream.local_write_closed = true;
        substream.remote_write_closed = true;
        // TODO: what is write_buffers is empty? need to send the close frame
    }

    /// Abruptly shuts down the substream. Sends a frame with the `RST` flag to the remote.
    ///
    /// Use this method when a protocol error happens on a substream.
    ///
    /// # Panic
    ///
    /// Panics if the local writing side is already closed, which can happen if
    /// [`SubstreamMut::close`] has already been called on this substream or if the remote has
    /// reset the substream in the past.
    ///
    pub fn reset(&mut self) {
        // TODO: doesn't send the RST frame
        let substream = self.substream.get_mut();
        substream.local_write_closed = true;
        substream.remote_write_closed = true;
        substream.write_buffers.clear();
        substream.first_write_buffer_offset = 0;
        substream.was_reset = true;
    }
}

impl<'a, T> fmt::Debug for SubstreamMut<'a, T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Substream").field(self.user_data()).finish()
    }
}

pub struct ExtractOut<'a, T> {
    yamux: &'a mut Yamux<T>,
    size_bytes: usize,
}

impl<'a, T> ExtractOut<'a, T> {
    /// Builds the next buffer to send out and returns it.
    pub fn next(&'_ mut self) -> Option<impl AsRef<[u8]> + '_> {
        while self.size_bytes != 0 {
            match self.yamux.outgoing {
                Outgoing::Header {
                    ref mut header,
                    ref substream_data_frame,
                } => {
                    // Finish writing the header.
                    debug_assert!(!header.is_empty());
                    if self.size_bytes >= header.len() {
                        self.size_bytes -= header.len();
                        let out = mem::take(header);
                        self.yamux.outgoing =
                            if let Some((id, remaining_bytes)) = substream_data_frame {
                                Outgoing::SubstreamData {
                                    id: *id,
                                    remaining_bytes: *remaining_bytes,
                                }
                            } else {
                                Outgoing::Idle
                            };
                        return Some(either::Left(out));
                    } else {
                        let to_add = header[..self.size_bytes].to_vec();
                        for _ in 0..self.size_bytes {
                            header.remove(0);
                        }
                        return Some(either::Right(VecWithOffset(to_add, 0)));
                    }
                }

                Outgoing::SubstreamData {
                    id: ref substream,
                    remaining_bytes: ref mut remain,
                } => {
                    let mut substream = self.yamux.substreams.get_mut(&substream.0).unwrap();

                    let first_buf_avail =
                        substream.write_buffers[0].len() - substream.first_write_buffer_offset;
                    let out =
                        if first_buf_avail <= remain.get() && first_buf_avail <= self.size_bytes {
                            let out = VecWithOffset(
                                substream.write_buffers.remove(0),
                                substream.first_write_buffer_offset,
                            );
                            self.size_bytes -= first_buf_avail;
                            substream.first_write_buffer_offset = 0;
                            match NonZeroUsize::new(remain.get() - first_buf_avail) {
                                Some(r) => *remain = r,
                                None => self.yamux.outgoing = Outgoing::Idle,
                            };
                            either::Right(out)
                        } else if remain.get() <= self.size_bytes {
                            self.size_bytes -= remain.get();
                            let out = VecWithOffset(
                                substream.write_buffers[0][substream.first_write_buffer_offset..]
                                    [..remain.get()]
                                    .to_vec(),
                                0,
                            );
                            substream.first_write_buffer_offset += remain.get();
                            self.yamux.outgoing = Outgoing::Idle;
                            either::Right(out)
                        } else {
                            let out = VecWithOffset(
                                substream.write_buffers[0][substream.first_write_buffer_offset..]
                                    [..self.size_bytes]
                                    .to_vec(),
                                0,
                            );
                            substream.first_write_buffer_offset += self.size_bytes;
                            *remain = NonZeroUsize::new(remain.get() - self.size_bytes).unwrap();
                            self.size_bytes = 0;
                            either::Right(out)
                        };

                    return Some(out);
                }

                Outgoing::Idle => {
                    // Send outgoing pings.
                    if self.yamux.pings_to_send > 0 {
                        self.yamux.pings_to_send -= 1;
                        let opaque_value: u32 = self.yamux.randomness.gen();
                        self.yamux.queue_ping_request_header(opaque_value);
                        self.yamux.pings_waiting_reply.push_back(opaque_value);
                        continue;
                    }

                    // Send window update frames.
                    // TODO: O(n)
                    if let Some((id, sub)) = self
                        .yamux
                        .substreams
                        .iter_mut()
                        .find(|(_, s)| s.remote_window_pending_increase != 0)
                        .map(|(id, sub)| (*id, sub))
                    {
                        let syn_ack_flag = !sub.first_message_queued;
                        sub.first_message_queued = true;

                        let update = u32::try_from(sub.remote_window_pending_increase)
                            .unwrap_or(u32::max_value());
                        sub.remote_window_pending_increase -= u64::from(update);
                        sub.remote_allowed_window += u64::from(update);
                        self.yamux
                            .queue_window_size_frame_header(syn_ack_flag, id, update);
                        continue;
                    }

                    // Start writing more data from another substream.
                    // TODO: O(n)
                    // TODO: choose substreams in some sort of round-robin way
                    if let Some((id, sub)) = self
                        .yamux
                        .substreams
                        .iter_mut()
                        .find(|(_, s)| !s.write_buffers.is_empty())
                        .map(|(id, sub)| (*id, sub))
                    {
                        let pending_len = sub.write_buffers.iter().fold(0, |l, b| l + b.len());
                        let len_out = cmp::min(
                            u32::try_from(pending_len).unwrap_or(u32::max_value()),
                            u32::try_from(sub.allowed_window).unwrap_or(u32::max_value()),
                        );
                        let len_out_usize = usize::try_from(len_out).unwrap();
                        sub.allowed_window -= u64::from(len_out);
                        let syn_ack_flag = !sub.first_message_queued;
                        sub.first_message_queued = true;
                        let fin_flag = sub.local_write_closed && len_out_usize == pending_len;
                        self.yamux
                            .queue_data_frame_header(syn_ack_flag, fin_flag, id, len_out);
                    } else {
                        break;
                    }
                }
            }
        }

        None
    }
}

#[derive(Clone)]
struct VecWithOffset(Vec<u8>, usize);
impl AsRef<[u8]> for VecWithOffset {
    fn as_ref(&self) -> &[u8] {
        &self.0[self.1..]
    }
}

/// Identifier of a substream in the context of a connection.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, derive_more::From)]
pub struct SubstreamId(NonZeroU32);

impl SubstreamId {
    /// Returns the value that compares inferior or equal to all possible values.
    pub fn min_value() -> Self {
        Self(NonZeroU32::new(1).unwrap())
    }

    /// Returns the value that compares superior or equal to all possible values.
    pub fn max_value() -> Self {
        Self(NonZeroU32::new(u32::max_value()).unwrap())
    }
}

#[must_use]
#[derive(Debug)]
pub struct IncomingDataOutcome<T> {
    /// Yamux object on which [`Yamux::incoming_data`] has been called.
    pub yamux: Yamux<T>,
    /// Number of bytes read from the incoming buffer. These bytes should no longer be present the
    /// next time [`Yamux::incoming_data`] is called.
    pub bytes_read: usize,
    /// Detail about the incoming data. `None` if nothing of interest has happened.
    pub detail: Option<IncomingDataDetail>,
}

/// Details about the incoming data.
#[must_use]
#[derive(Debug)]
pub enum IncomingDataDetail {
    /// Remote has requested to open a new substream.
    ///
    /// After this has been received, either [`Yamux::accept_pending_substream`] or
    /// [`Yamux::reject_pending_substream`] needs to be called in order to accept or reject
    /// this substream. Calling [`Yamux::incoming_data`] before this is done will lead to a
    /// panic.
    IncomingSubstream,
    /// Received data corresponding to a substream.
    DataFrame {
        /// Offset in the buffer passed to [`Yamux::incoming_data`] where the data frame
        /// starts. The data frame ends at the offset of [`IncomingDataOutcome::bytes_read`].
        start_offset: usize,
        /// Substream the data belongs to. Guaranteed to be valid.
        substream_id: SubstreamId,
    },
    /// Remote has closed its writing side of the substream.
    StreamClosed {
        /// Substream that got closed.
        substream_id: SubstreamId,
    },
    /// Remote has asked to reset a substream.
    ///
    /// The substream is now considered destroyed.
    StreamReset {
        /// Substream that has been destroyed. No longer valid.
        substream_id: SubstreamId,
    },
    /// Received a "go away" request.
    GoAway(GoAwayErrorCode),
    /// Received a response to a ping that has been sent out earlier.
    // TODO: associate some data with the ping? in case they're answered in a different order?
    PingResponse,
}

/// Error while decoding the Yamux stream.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// Failed to decode an incoming yamux header.
    HeaderDecode(header::YamuxHeaderDecodeError),
    /// Received a SYN flag with a known substream ID.
    #[display(fmt = "Received a SYN flag with a known substream ID")]
    UnexpectedSyn(NonZeroU32),
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
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DeadSubstreamTy {
    ClosedGracefully,
    Reset,
}

/// By default, all new substreams have this implicit window size.
const DEFAULT_FRAME_SIZE: u64 = 256 * 1024;
