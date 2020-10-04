// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Yamux multiplexing protocol.
//!
//! The yamux protocol is a multiplexing protocol. As such, it allows dividing a single stream of
//! data, typically a TCP socket, into multiple individual parallel substreams. The data sent and
//! received over that single stream is divided into frames which, with the exception of `ping`
//! and `goaway` frames, belong to a specific substream. In other words, the data transmitted
//! over the substreams is interleaved.
//!
//! Specifications available at https://github.com/hashicorp/yamux/blob/master/spec.md
//!
//! # Usage
//!

// TODO: finish usage

use core::{cmp, convert::TryFrom as _, fmt, mem, num::NonZeroU32};
use hashbrown::hash_map::{Entry, OccupiedEntry};

/// Name of the protocol, typically used when negotiated it using *multistream-select*.
pub const PROTOCOL_NAME: &str = "/yamux/1.0.0";

pub struct Connection<T> {
    /// List of substreams currently open in the yamux state machine.
    // TODO: there's an actual chance of collision attack here if we don't use a siphasher
    substreams: hashbrown::HashMap<NonZeroU32, Substream<T>, fnv::FnvBuildHasher>,

    /// If `Some`, the next incoming data belongs to a previously-received data frame concerning
    /// the given substream. Also contains the number of bytes remaining in this data frame.
    ///
    /// Can contain an invalid substream ID, and can contain the substream ID contained in
    /// [`Connection::pending_incoming_substream`].
    incoming_data_frame: Option<(SubstreamId, u32)>,

    /// Id of the next outgoing substream to open.
    /// This implementation allocates identifiers linearly. Every time a substream is open, its
    /// value is incremented by two.
    next_outbound_substream: NonZeroU32,

    /// Buffer for a partially read yamux header.
    incoming_header: arrayvec::ArrayVec<[u8; 12]>,

    /// Header currently being written out. Finishing to write this header is the first and
    /// foremost priority of [`Connection::read_write`].
    pending_out_header: arrayvec::ArrayVec<[u8; 12]>,

    /// If `Some`, contains a substream ID and a number of bytes. A data frame header has been
    /// written to the socket, and the number of bytes stored in there is the number of bytes
    /// remaining in this frame.
    ///
    /// Writing out the data of this substream is the second most highest priority after writing
    /// out [`Connection::pending_out_header`].
    writing_out_substream: Option<(SubstreamId, usize)>,

    /// If `Some`, the remote has requested to open the substream with the given ID. Contains
    /// additional credits that the remote allocates to us.
    pending_incoming_substream: Option<(SubstreamId, u32)>,
}

struct Substream<T> {
    /// Identifier of the substream.
    id: SubstreamId,
    /// True if a message on this substream has already been sent since it has been opened. The
    /// first message on a substream must contain either a SYN or ACK flag.
    first_message_queued: bool,
    /// Amount of data the remote is allowed to transmit to the local node.
    remote_allowed_window: u64,
    /// Amount of data the local node is allowed to transmit to the remote.
    allowed_window: u64,
    /// True if the writing side of the local node is closed for this substream.
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
    /// Data chosen by the user.
    user_data: T,
}

impl<T> Connection<T> {
    /// Initializes a new yamux state machine.
    ///
    /// Must be passed `true` if the local machine has initiated the connection.
    /// Otherwise, `false`.
    pub fn new(is_initiator: bool) -> Connection<T> {
        Self::with_capacity(is_initiator, 0)
    }

    /// Initializes a new yamux state machine with enough capacity for the given number of
    /// substreams.
    ///
    /// Must be passed `true` if the local machine has initiated the connection.
    /// Otherwise, `false`.
    pub fn with_capacity(is_initiator: bool, capacity: usize) -> Connection<T> {
        Connection {
            substreams: hashbrown::HashMap::with_capacity_and_hasher(capacity, Default::default()),
            incoming_data_frame: None,
            next_outbound_substream: if is_initiator {
                NonZeroU32::new(1).unwrap()
            } else {
                NonZeroU32::new(2).unwrap()
            },
            incoming_header: arrayvec::ArrayVec::new(),
            pending_out_header: arrayvec::ArrayVec::new(),
            writing_out_substream: None,
            pending_incoming_substream: None,
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
    /// >           work. In practice, while this is technically out of concern of the yamux
    /// >           protocol, all substreams in the context of libp2p start with a
    /// >           multistream-select negotiation, and this scenario can therefore never happen.
    ///
    /// # Panic
    ///
    /// Panics if all possible substream IDs are already taken. This happen if there exists more
    /// than approximately 2^31 substreams, which is very unlikely to happen unless there exists a
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
            id: substream_id,
            first_message_queued: false,
            remote_allowed_window: DEFAULT_FRAME_SIZE,
            allowed_window: DEFAULT_FRAME_SIZE,
            local_write_closed: false,
            remote_write_closed: false,
            write_buffers: Vec::with_capacity(16),
            first_write_buffer_offset: 0,
            user_data,
        });

        match self.substreams.entry(substream_id.0) {
            Entry::Occupied(e) => SubstreamMut { substream: e },
            _ => unreachable!(),
        }
    }

    /// Returns a reference to a substream by its ID. Returns `None` if no substream with this ID
    /// is open.
    pub fn substream_by_id(&mut self, id: SubstreamId) -> Option<SubstreamMut<T>> {
        if let Entry::Occupied(e) = self.substreams.entry(id.0) {
            Some(SubstreamMut { substream: e })
        } else {
            None
        }
    }

    /// Process some incoming data.
    ///
    /// # Panic
    ///
    /// Panics if pending incoming substream.
    ///
    // TODO: explain that reading might be blocked on writing
    // TODO: reword panic reason
    pub fn incoming_data(mut self, mut data: &[u8]) -> Result<IncomingDataOutcome<T>, Error> {
        assert!(self.pending_incoming_substream.is_none());

        let mut total_read: usize = 0;

        loop {
            if let Some((substream_id, ref mut remaining_bytes)) = self.incoming_data_frame {
                debug_assert!(self.incoming_header.is_empty());
                let pulled_data = cmp::min(
                    *remaining_bytes,
                    u32::try_from(data.len()).unwrap_or(u32::max_value()),
                );
                let pulled_data_usize = usize::try_from(pulled_data).unwrap();
                *remaining_bytes -= pulled_data;
                if *remaining_bytes == 0 {
                    self.incoming_data_frame = None;
                }

                let start_offset = total_read;
                total_read += pulled_data_usize;
                data = &data[pulled_data_usize..];

                if self.substreams.contains_key(&substream_id.0) {
                    return Ok(IncomingDataOutcome {
                        yamux: self,
                        bytes_read: total_read,
                        detail: Some(IncomingDataDetail::DataFrame {
                            substream_id,
                            start_offset,
                        }),
                    });
                } else {
                    continue;
                }
            }

            // The code below might require writing to it, and as such we can't proceed with any
            // reading if it isn't empty.
            if !self.pending_out_header.is_empty() {
                break;
            }

            // Try to copy as much as possible from `data` to `header`.
            while !data.is_empty() && self.incoming_header.len() < 12 {
                self.incoming_header.push(data[0]);
                total_read += 1;
                data = &data[1..];
            }

            // Not enough data to finish receiving header. Nothing more can be done.
            if self.incoming_header.len() != 12 {
                debug_assert!(data.is_empty());
                break;
            }

            // Full header available to decode in `incoming_header`.

            // Byte 0 of the header is the yamux version number. Return an error if it isn't 0.
            if self.incoming_header[0] != 0 {
                return Err(Error::UnknownVersion(self.incoming_header[0]));
            }

            // Decode the three other fields: flags, substream id, and length.
            let flags_field =
                u16::from_be_bytes(<[u8; 2]>::try_from(&self.incoming_header[2..4]).unwrap());
            let substream_id_field =
                u32::from_be_bytes(<[u8; 4]>::try_from(&self.incoming_header[4..8]).unwrap());
            let length_field =
                u32::from_be_bytes(<[u8; 4]>::try_from(&self.incoming_header[8..12]).unwrap());

            // Byte 1 of the header indicates the type of message.
            match self.incoming_header[1] {
                2 => {
                    // A ping or pong has been received.
                    // TODO: check flags more strongly?
                    if (flags_field & 0x1) != 0 {
                        // Ping. Write a pong message in `self.pending_out_header`.
                        debug_assert!(self.pending_out_header.is_empty());
                        self.pending_out_header
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
                                    self.incoming_header[8],
                                    self.incoming_header[9],
                                    self.incoming_header[10],
                                    self.incoming_header[11],
                                ][..],
                            )
                            .unwrap();
                        break;
                    }
                }
                3 => {
                    // TODO: go away
                    todo!()
                }
                // Handled below.
                0 | 1 => {}
                _ => return Err(Error::BadFrameType(self.incoming_header[1])),
            }

            // The frame is now either a data (`0`) or window size (`1`) frame.
            let substream_id = match NonZeroU32::new(substream_id_field) {
                Some(i) => SubstreamId(i),
                None => return Err(Error::ZeroSubstreamId),
            };

            // Find the element in `self.substreams` corresponding to the substream requested by
            // the remote.
            // It is possible that the remote is referring to a substream for which a RST has been
            // sent out. Since the local state machine doesn't keep track of RST'ted substreams,
            // any frame concerning a substream with an unknown id is discarded and doesn't
            // an error, under the presumption that we are in this situation. When that is the
            // case, the `substream` variable below is `None`.
            let substream: Option<_> = if (flags_field & 0x1) != 0 {
                if self.substreams.contains_key(&substream_id.0) {
                    return Err(Error::UnexpectedSyn(substream_id.0));
                } else {
                    debug_assert!(self.pending_incoming_substream.is_none());
                    self.pending_incoming_substream = Some((
                        substream_id,
                        if self.incoming_header[0] == 0 {
                            0
                        } else {
                            length_field
                        },
                    ));
                    if self.incoming_header[0] == 0 {
                        debug_assert!(self.incoming_data_frame.is_none());
                        self.incoming_data_frame = Some((substream_id, length_field));
                    }
                    self.incoming_header.clear();
                    return Ok(IncomingDataOutcome {
                        yamux: self,
                        bytes_read: total_read,
                        detail: Some(IncomingDataDetail::IncomingSubstream),
                    });
                }
            } else {
                self.substreams.get_mut(&substream_id.0)
            };

            if self.incoming_header[0] == 0 {
                // Data frame.
                // Check whether the remote has the right to send that much data.
                // Note that the credits aren't checked in the case of an unknown substream.
                if let Some(substream) = substream {
                    // TODO: allocate more size?
                    substream.remote_allowed_window = substream
                        .remote_allowed_window
                        .checked_sub(u64::from(length_field))
                        .ok_or(Error::CreditsExceeded)?;
                }
                debug_assert!(self.incoming_data_frame.is_none());
                self.incoming_data_frame = Some((substream_id, length_field));
                self.incoming_header.clear();
            } else if self.incoming_header[0] == 1 {
                // Window size frame.
                if let Some(substream) = substream {
                    substream.allowed_window = substream
                        .allowed_window
                        .checked_add(u64::from(length_field))
                        .ok_or(Error::LocalCreditsOverflow)?;
                }
                self.incoming_header.clear();
            } else {
                unreachable!()
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
    /// After the [`ExtractOut`] has been destroyed, the yamux state machine will automatically
    /// consider that these `size_bytes` have been sent out, even if the iterator has been
    /// destroyed before finishing. It is a logic error to `mem::forget` the [`ExtractOut`].
    ///
    /// > **Note**: Most other objects in the networking code have a "`read_write`" method that
    /// >           writes the outgoing data to a buffer. This is an idiomatic way to do things in
    /// >           situations where the data is generated on the fly. In the context of yamux,
    /// >           however, this would be rather suboptimal considering that buffers to send out
    /// >           are already stored in their final form in the state machine.
    pub fn extract_out(&mut self, size_bytes: usize) -> ExtractOut<T> {
        // TODO: this function has a zero-cost API, but its body isn't really zero-cost due to laziness

        // The implementation consists in filling a buffer of buffers, then calling `into_iter`.
        let mut buffers = Vec::with_capacity(32);

        // Copy of `size_bytes`, decremented over the iterations.
        let mut size_bytes_iter = size_bytes;

        while size_bytes_iter != 0 {
            // Finish writing `self.pending_out_header` if possible.
            if !self.pending_out_header.is_empty() {
                if size_bytes_iter >= self.pending_out_header.len() {
                    size_bytes_iter -= self.pending_out_header.len();
                    buffers.push(either::Left(mem::replace(
                        &mut self.pending_out_header,
                        Default::default(),
                    )));
                } else {
                    let to_copy = cmp::min(size_bytes_iter, self.pending_out_header.len());
                    let to_add = self.pending_out_header[..to_copy].to_vec();
                    size_bytes_iter -= to_copy;
                    for _ in 0..to_copy {
                        self.pending_out_header.remove(0);
                    }
                    buffers.push(either::Right(VecWithOffset(to_add, 0)));
                }
            }

            // Now update `writing_out_substream`.
            if let Some((substream, ref mut remain)) = self.writing_out_substream {
                let mut substream = self.substreams.get_mut(&substream.0).unwrap();

                let first_buf_avail =
                    substream.write_buffers[0].len() - substream.first_write_buffer_offset;
                if first_buf_avail <= *remain {
                    buffers.push(either::Right(VecWithOffset(
                        substream.write_buffers.remove(0),
                        substream.first_write_buffer_offset,
                    )));
                    size_bytes_iter -= first_buf_avail;
                    substream.first_write_buffer_offset = 0;
                    *remain -= first_buf_avail;
                    if *remain == 0 {
                        self.writing_out_substream = None;
                    }
                } else {
                    size_bytes_iter -= *remain;
                    buffers.push(either::Right(VecWithOffset(
                        substream.write_buffers[0][substream.first_write_buffer_offset..]
                            [..*remain]
                            .to_vec(),
                        0,
                    )));
                    substream.first_write_buffer_offset += *remain;
                    self.writing_out_substream = None;
                }

                continue;
            }

            // All frames in the process of being written have been written.
            debug_assert!(self.pending_out_header.is_empty());
            debug_assert!(self.writing_out_substream.is_none());

            // Start writing more data from another substream.
            // TODO: choose substreams in some sort of round-robin way
            if let Some((id, sub)) = self
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
                sub.allowed_window -= u64::from(len_out);
                let syn_ack_flag = !sub.first_message_queued;
                sub.first_message_queued = true;
                self.writing_out_substream =
                    Some((SubstreamId(id), usize::try_from(len_out).unwrap()));
                self.queue_data_frame_header(syn_ack_flag, id, len_out);
            } else {
                break;
            }
        }

        debug_assert!(
            buffers
                .iter()
                .fold(0, |n, b| n + AsRef::<[u8]>::as_ref(b).len())
                < size_bytes
        );

        ExtractOut {
            connection: self,
            buffers: Some(buffers),
        }
    }

    pub fn accept_pending_substream(&mut self, user_data: T) -> SubstreamMut<T> {
        let (pending_incoming_substream, credits) = self.pending_incoming_substream.take().unwrap();
        let _was_before = self.substreams.insert(
            pending_incoming_substream.0,
            Substream {
                id: pending_incoming_substream,
                first_message_queued: false,
                remote_allowed_window: DEFAULT_FRAME_SIZE + u64::from(credits),
                allowed_window: DEFAULT_FRAME_SIZE + u64::from(credits),
                local_write_closed: false,
                remote_write_closed: false,
                write_buffers: Vec::new(),
                first_write_buffer_offset: 0,
                user_data,
            },
        );
        debug_assert!(_was_before.is_none());

        SubstreamMut {
            substream: match self.substreams.entry(pending_incoming_substream.0) {
                Entry::Occupied(e) => e,
                _ => unreachable!(),
            },
        }
    }

    pub fn reject_pending_substream(&mut self) {
        let pending_incoming_substream = self.pending_incoming_substream.take().unwrap();
        debug_assert!(self.pending_out_header.is_empty());

        /*self.pending_out_header.push(0);
        self.pending_out_header.push(1);
        self.pending_out_header
            .try_extend_from_slice(&0x8u16.to_be_bytes()[..])
            .unwrap();
        self.pending_out_header
            .try_extend_from_slice(&pending_incoming_substream.0.get().to_be_bytes()[..])
            .unwrap();
        self.pending_out_header
            .try_extend_from_slice(&0u32.to_be_bytes()[..])
            .unwrap();

        let to_write = cmp::min(self.pending_out_header.len(), out.len());
        out[..to_write].copy_from_slice(&self.pending_out_header[..to_write]);
        for _ in 0..to_write {
            self.pending_out_header.remove(0);
        }
        to_write*/
        // TODO:
        todo!()
    }

    /// Writes a data frame header in `self.pending_out_header`.
    ///
    /// # Panic
    ///
    /// Panics if `!self.pending_out_header.is_empty()`.
    ///
    fn queue_data_frame_header(
        &mut self,
        syn_ack_flag: bool,
        substream_id: NonZeroU32,
        data_length: u32,
    ) {
        assert!(self.pending_out_header.is_empty());

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

        self.pending_out_header.push(0);
        self.pending_out_header.push(0);
        self.pending_out_header
            .try_extend_from_slice(&flags.to_be_bytes())
            .unwrap();
        self.pending_out_header
            .try_extend_from_slice(&substream_id.get().to_be_bytes())
            .unwrap();
        self.pending_out_header
            .try_extend_from_slice(&data_length.to_be_bytes())
            .unwrap();

        debug_assert_eq!(self.pending_out_header.len(), 12);
    }
}

impl<T> fmt::Debug for Connection<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct List<'a, T>(&'a Connection<T>);
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

        f.debug_struct("Connection")
            .field("substreams", &List(self))
            .finish()
    }
}

/// Reference to a substream within the [`Connection`].
// TODO: Debug
pub struct SubstreamMut<'a, T> {
    substream: OccupiedEntry<'a, NonZeroU32, Substream<T>, fnv::FnvBuildHasher>,
}

impl<'a, T> SubstreamMut<'a, T> {
    /// Identifier of the substream.
    pub fn id(&self) -> SubstreamId {
        SubstreamId(*self.substream.key())
    }

    /// Returns the user data associated to this substream.
    pub fn user_data(&mut self) -> &mut T {
        &mut self.substream.get_mut().user_data
    }

    /// Returns the user data associated to this substream.
    pub fn into_user_data(self) -> &'a mut T {
        &mut self.substream.into_mut().user_data
    }

    /// Appends data to the buffer of data to send out on this substream.
    pub fn write(&mut self, data: Vec<u8>) {
        let substream = self.substream.get_mut();
        debug_assert!(
            !substream.write_buffers.is_empty() || substream.first_write_buffer_offset == 0
        );
        substream.write_buffers.push(data);
    }
}

pub struct ExtractOut<'a, T> {
    connection: &'a mut Connection<T>,
    buffers: Option<Vec<either::Either<arrayvec::ArrayVec<[u8; 12]>, VecWithOffset>>>,
}

impl<'a, T> ExtractOut<'a, T> {
    /// Returns the list of buffers to write.
    ///
    /// Can only be called once.
    ///
    /// # Panic
    ///
    /// Panics if called multiple times.
    ///
    pub fn buffers(&mut self) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
        self.buffers.take().unwrap().into_iter()
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

pub struct IncomingDataOutcome<T> {
    /// Connection object on which [`Connection::incoming_data`] has been called.
    pub yamux: Connection<T>,
    /// Number of bytes read from the incoming buffer. These bytes should no longer be present the
    /// next time [`Connection::incoming_data`] is called.
    pub bytes_read: usize,
    /// Detail about the data in the incoming data. `None` if nothing of interest has happened.
    pub detail: Option<IncomingDataDetail>,
}

pub enum IncomingDataDetail {
    IncomingSubstream,
    /// Received data corresponding to a substream.
    DataFrame {
        /// Offset in the buffer passed to [`Connection::incoming_data`] where the data frame
        /// starts. The data frame ends at the offset of [`IncomingDataOutcome::bytes_read`].
        start_offset: usize,
        /// Substream the data belongs to. Guaranteed to be valid.
        substream_id: SubstreamId,
    },
}

/// Error while decoding the yamux stream.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// Unknown version number in a header.
    UnknownVersion(u8),
    /// Unrecognized value for the type of frame as indicated in the header.
    BadFrameType(u8),
    /// Substream ID was zero in a data of window update frame.
    ZeroSubstreamId,
    /// Received a SYN flag with a known substream ID.
    UnexpectedSyn(NonZeroU32),
    /// Remote tried to send more data than it was allowed to.
    CreditsExceeded,
    /// Number of credits allocated to the local node has overflowed.
    LocalCreditsOverflow,
}

/// By default, all new substreams have this implicit window size.
const DEFAULT_FRAME_SIZE: u64 = 256 * 1024;
