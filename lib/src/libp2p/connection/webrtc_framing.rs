// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

//!
//! See <https://github.com/libp2p/specs/blob/master/webrtc/README.md#multiplexing>.

use crate::{
    libp2p::read_write::ReadWrite,
    util::{leb128, protobuf},
};

use alloc::{borrow::ToOwned as _, vec::Vec};
use core::{cmp, fmt, mem, ops};

/// State of the framing.
pub struct WebRtcFraming {
    /// Value of [`ReadWrite::expected_incoming_bytes`] of the inner stream the last time that
    /// [`WebRtcFraming::read_write`] was called. `None` if unknown.
    inner_stream_expected_incoming_bytes: Option<usize>,

    /// Buffer containing data from a previous frame, but that doesn't contain enough data for
    /// the underlying substream to accept it.
    ///
    /// In other words, `receive_buffer.len() < inner_stream_expected_incoming_bytes`.
    // TODO: shrink_to_fit?
    receive_buffer: Vec<u8>,

    /// State of the writing side of the remote.
    remote_write_state: RemoteWriteState,

    /// State of the local writing side.
    local_write_state: LocalWriteState,
}

enum LocalWriteState {
    Open,
    FinBuffered,
    FinAcked,
}

enum RemoteWriteState {
    Open,
    /// The remote has sent a `FIN` in the past. Any data in [`WebRtcFraming::receive_buffer`]
    /// is still valid and was received before the remote writing side was closed.
    Closed,
    ClosedAckBuffered,
}

const RECEIVE_BUFFER_CAPACITY: usize = 2048;
/// Minimum size in bytes of the protobuf frame surrounding the message.
const PROTOBUF_FRAME_MIN_LEN: usize = 2;
/// Maximum size in bytes of the protobuf frame surrounding the message.
const PROTOBUF_FRAME_MAX_LEN: usize = 8; // TODO: calculate better?
/// Size in bytes of a protobuf frame that carries a flag and no data.
const PROTOBUF_FRAME_FLAG_ONLY_LEN: usize = 5;
const MAX_PROTOBUF_MESSAGE_LEN: usize = 16384;

impl WebRtcFraming {
    /// Initializes a new [`WebRtcFraming`].
    pub fn new() -> Self {
        WebRtcFraming {
            inner_stream_expected_incoming_bytes: None,
            receive_buffer: Vec::with_capacity(RECEIVE_BUFFER_CAPACITY),
            remote_write_state: RemoteWriteState::Open,
            local_write_state: LocalWriteState::Open,
        }
    }

    /// Feeds data coming from a socket and outputs data to write to the socket.
    ///
    /// Returns an object that implements `Deref<Target = ReadWrite>`. This object represents the
    /// decrypted stream of data.
    ///
    /// An error is returned if the protocol is being violated by the remote, if the remote wants
    /// to reset the substream.
    pub fn read_write<'a, TNow: Clone>(
        &'a mut self,
        outer_read_write: &'a mut ReadWrite<TNow>,
    ) -> Result<InnerReadWrite<'a, TNow>, Error> {
        // Read from the incoming buffer until we have enough data for the underlying substream.
        loop {
            // Immediately stop looping if there is enough data for the underlying substream.
            // Also stop looping if `inner_stream_expected_incoming_bytes` is `None`, as we always
            // want to process the inner substream the first time ever.
            if self
                .inner_stream_expected_incoming_bytes
                .map_or(true, |rq_bytes| rq_bytes <= self.receive_buffer.len())
            {
                break;
            }

            // Try to parse a frame from the incoming buffer.
            let bytes_to_discard = {
                // TODO: we could in theory demand from the outside just the protobuf header, and then later the data, which would save some copying but might considerably complexifies the code
                let mut parser = nom::combinator::map_parser::<_, _, nom::error::Error<&[u8]>, _, _>(
                    nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                    protobuf::message_decode! {
                        #[optional] flags = 1 => protobuf::enum_tag_decode,
                        #[optional] message = 2 => protobuf::bytes_tag_decode,
                    },
                );
                match nom::Parser::parse(&mut parser, &outer_read_write.incoming_buffer) {
                    Ok((rest, framed_message)) => {
                        // The remote has sent a `RESET_STREAM` flag, immediately stop with an error.
                        // The specification mentions that the receiver may discard any data already
                        // received, which we do.
                        if framed_message.flags.map_or(false, |f| f == 2) {
                            return Err(Error::RemoteResetDesired);
                        }

                        // Some protocol check.
                        if framed_message.message.map_or(false, |msg| !msg.is_empty())
                            && !matches!(self.remote_write_state, RemoteWriteState::Open)
                        {
                            return Err(Error::DataAfterFin);
                        }

                        // Process the `FIN_ACK` flag sent by the remote.
                        // Note that we don't treat it as an error if the remote sends the
                        // `FIN_ACK` flag multiple times, although this is opinionated.
                        if framed_message.flags.map_or(false, |f| f == 3) {
                            if matches!(self.local_write_state, LocalWriteState::Open) {
                                return Err(Error::FinAckWithoutFin);
                            }
                            self.local_write_state = LocalWriteState::FinAcked;
                        }

                        // Process the `FIN` flag sent by the remote.
                        if matches!(self.remote_write_state, RemoteWriteState::Open)
                            && framed_message.flags.map_or(false, |f| f == 0)
                        {
                            self.remote_write_state = RemoteWriteState::Closed;
                        }

                        // Note that any `STOP_SENDING` flag sent by the remote is ignored.

                        // Copy the message of the remote out from the incoming buffer.
                        if let Some(message) = framed_message.message {
                            self.receive_buffer.extend_from_slice(message);
                        }

                        // Number of bytes to discard is the size of the protobuf frame.
                        outer_read_write.incoming_buffer.len() - rest.len()
                    }
                    Err(nom::Err::Incomplete(needed)) => {
                        // Not enough data in the incoming buffer for a full frame. Requesting
                        // more.
                        let Some(expected_incoming_bytes) =
                            &mut outer_read_write.expected_incoming_bytes
                        else {
                            // TODO: is this correct anyway? substreams are never supposed to close?
                            return Err(Error::EofIncompleteFrame);
                        };
                        *expected_incoming_bytes = outer_read_write.incoming_buffer.len()
                            + match needed {
                                nom::Needed::Size(s) => s.get(),
                                nom::Needed::Unknown => 1,
                            };
                        break;
                    }
                    Err(_) => {
                        // Frame decoding error.
                        return Err(Error::InvalidFrame);
                    }
                }
            };

            // Discard the frame data.
            let _extract_result = outer_read_write.incoming_bytes_take(bytes_to_discard);
            debug_assert!(matches!(_extract_result, Ok(Some(_))));
        }

        Ok(InnerReadWrite {
            inner_read_write: ReadWrite {
                now: outer_read_write.now.clone(),
                incoming_buffer: mem::take(&mut self.receive_buffer),
                read_bytes: 0,
                expected_incoming_bytes: if matches!(
                    self.remote_write_state,
                    RemoteWriteState::Open
                ) {
                    Some(0)
                } else {
                    None
                },
                write_buffers: Vec::new(),
                write_bytes_queued: 0,
                write_bytes_queueable: if matches!(self.local_write_state, LocalWriteState::Open) {
                    outer_read_write
                        .write_bytes_queueable
                        .map(|outer_writable| {
                            cmp::min(
                                // The outer stream has `PROTOBUF_FRAME_MAX_LEN` bytes of room or
                                // less once data has filled it, and nothing is queued until it is
                                // writable again.
                                outer_writable.saturating_sub(PROTOBUF_FRAME_MAX_LEN),
                                MAX_PROTOBUF_MESSAGE_LEN - PROTOBUF_FRAME_MAX_LEN,
                            )
                        })
                } else {
                    None
                },
                wake_up_after: outer_read_write.wake_up_after.clone(),
            },
            framing: self,
            outer_read_write,
        })
    }
}

impl fmt::Debug for WebRtcFraming {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("WebRtcFraming").finish()
    }
}

/// Stream of data without the frames. See [`WebRtcFraming::read_write`].
pub struct InnerReadWrite<'a, TNow: Clone> {
    framing: &'a mut WebRtcFraming,
    outer_read_write: &'a mut ReadWrite<TNow>,
    inner_read_write: ReadWrite<TNow>,
}

impl<'a, TNow: Clone> ops::Deref for InnerReadWrite<'a, TNow> {
    type Target = ReadWrite<TNow>;

    fn deref(&self) -> &Self::Target {
        &self.inner_read_write
    }
}

impl<'a, TNow: Clone> ops::DerefMut for InnerReadWrite<'a, TNow> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner_read_write
    }
}

impl<'a, TNow: Clone> Drop for InnerReadWrite<'a, TNow> {
    fn drop(&mut self) {
        // It is possible that the inner stream processes some bytes of `self.receive_buffer`
        // and expects to be called again while no bytes was pulled from the outer `ReadWrite`.
        // If that happens, the API user will not call `read_write` again and we will have a stall.
        // For this reason, if the inner stream has read some bytes, we make sure that the outer
        // `ReadWrite` wakes up as soon as possible.
        // Additionally, we also do a first dummy substream processing without reading anything,
        // in order to populate `inner_stream_expected_incoming_bytes`. If this is the case, we
        // also immediately wake up again.
        if self.framing.inner_stream_expected_incoming_bytes.is_none()
            || self.inner_read_write.read_bytes != 0
        {
            self.outer_read_write.wake_up_asap();
        }

        // Updating the timer and reading side of things.
        self.outer_read_write.wake_up_after = self.inner_read_write.wake_up_after.clone();
        self.framing.receive_buffer = mem::take(&mut self.inner_read_write.incoming_buffer);
        self.framing.inner_stream_expected_incoming_bytes =
            Some(self.inner_read_write.expected_incoming_bytes.unwrap_or(0));
        if let Some(expected_incoming_bytes) = &mut self.outer_read_write.expected_incoming_bytes {
            *expected_incoming_bytes = cmp::max(
                *expected_incoming_bytes,
                self.inner_read_write.expected_incoming_bytes.unwrap_or(0) + PROTOBUF_FRAME_MIN_LEN,
            );
        }

        // Update the local state, and figure out the flag (if any) that we want to send out to
        // the remote.
        // Note that we never send the `RESET_STREAM` flag. It is unclear to me what purpose this
        // flag serves compares to simply closing the substream.
        // We also never send `STOP_SENDING`, as it doesn't fit in our API.
        // The flag must fit in the room of the outer `ReadWrite`. Without data, it needs
        // `PROTOBUF_FRAME_FLAG_ONLY_LEN` bytes, and if there are fewer, it is sent during a later
        // call instead, once the outer stream is writable again. With data, it always fits, as
        // the inner stream can queue at most `PROTOBUF_FRAME_MAX_LEN` bytes less than the outer
        // one.
        let room_for_flag = self
            .outer_read_write
            .write_bytes_queueable
            .map_or(false, |queueable| queueable >= PROTOBUF_FRAME_FLAG_ONLY_LEN);
        let flag_to_send_out: Option<u32> = if !room_for_flag {
            None
        } else if matches!(self.framing.local_write_state, LocalWriteState::Open)
            && self.inner_read_write.write_bytes_queueable.is_none()
        {
            self.framing.local_write_state = LocalWriteState::FinBuffered;
            Some(0)
        } else if matches!(self.framing.remote_write_state, RemoteWriteState::Closed) {
            // `FIN_ACK`
            self.framing.remote_write_state = RemoteWriteState::ClosedAckBuffered;
            Some(3)
        } else {
            None
        };

        // Write out a message only if there is anything to write.
        // TODO: consider buffering data more before flushing, to reduce the overhead of the protobuf frame?
        if flag_to_send_out.is_some() || self.inner_read_write.write_bytes_queued != 0 {
            // Reserve some space in `write_buffers` to later write the message length prefix.
            let message_length_prefix_index = self.outer_read_write.write_buffers.len();
            self.outer_read_write
                .write_buffers
                .push(Vec::with_capacity(4));

            // Total number of bytes written below, excluding the length prefix.
            let mut length_prefix_value = 0;

            // Write the flags, if any.
            if let Some(flag_to_send_out) = flag_to_send_out {
                for buffer in protobuf::uint32_tag_encode(1, flag_to_send_out) {
                    let buffer = buffer.as_ref();
                    length_prefix_value += buffer.len();
                    self.outer_read_write.write_buffers.push(buffer.to_owned());
                }
            }

            // Write the data. This consists in a protobuf tag, a length, and the data itself.
            let data_protobuf_tag = protobuf::tag_encode(2, 2).collect::<Vec<_>>();
            length_prefix_value += data_protobuf_tag.len();
            self.outer_read_write.write_buffers.push(data_protobuf_tag);
            let data_len =
                leb128::encode_usize(self.inner_read_write.write_bytes_queued).collect::<Vec<_>>();
            length_prefix_value += data_len.len();
            self.outer_read_write.write_buffers.push(data_len);
            length_prefix_value += self.inner_read_write.write_bytes_queued;
            self.outer_read_write
                .write_buffers
                .extend(mem::take(&mut self.inner_read_write.write_buffers));

            // Now write the length prefix.
            let length_prefix = leb128::encode_usize(length_prefix_value).collect::<Vec<_>>();
            let total_length = length_prefix_value + length_prefix.len();
            self.outer_read_write.write_buffers[message_length_prefix_index] = length_prefix;

            // Properly update the outer `ReadWrite`.
            self.outer_read_write.write_bytes_queued += total_length;
            *self
                .outer_read_write
                .write_bytes_queueable
                .as_mut()
                .unwrap() -= total_length;
        }
    }
}

/// Error while decoding data.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum Error {
    /// The remote wants to reset the substream. This is a normal situation.
    RemoteResetDesired,
    /// Failed to decode the protobuf header.
    InvalidFrame,
    /// Remote has sent data after having sent a `FIN` flag in the past.
    DataAfterFin,
    /// Outer substream has closed in the middle of a frame.
    EofIncompleteFrame,
    /// Received a `FIN_ACK` flag without having sent a `FIN` flag.
    FinAckWithoutFin,
}

#[cfg(test)]
mod tests {
    use super::WebRtcFraming;
    use crate::libp2p::read_write::ReadWrite;

    fn outer(incoming: &[u8], queueable: usize) -> ReadWrite<()> {
        ReadWrite {
            now: (),
            incoming_buffer: incoming.to_vec(),
            expected_incoming_bytes: Some(0),
            read_bytes: 0,
            write_buffers: Vec::new(),
            write_bytes_queued: 0,
            write_bytes_queueable: Some(queueable),
            wake_up_after: None,
        }
    }

    #[test]
    fn fin_ack_waits_for_room_in_the_outer_stream() {
        let mut framing = WebRtcFraming::new();

        // The inner substream waits for a byte, which makes the next call read frames.
        let mut read_write = outer(&[], 100);
        framing
            .read_write(&mut read_write)
            .unwrap()
            .expected_incoming_bytes = Some(1);
        assert_eq!(read_write.write_bytes_queued, 0);

        // The remote sends `FIN` while the outer stream has room for 4 bytes only: the `FIN_ACK`
        // frame (5 bytes) is not written.
        let mut read_write = outer(&[0x02, 0x08, 0x00], 4);
        drop(framing.read_write(&mut read_write).unwrap());
        assert!(read_write.write_buffers.concat().is_empty());
        assert_eq!(read_write.write_bytes_queued, 0);
        assert_eq!(read_write.write_bytes_queueable, Some(4));

        // With room for 5 bytes, it is.
        let mut read_write = outer(&[], 5);
        drop(framing.read_write(&mut read_write).unwrap());
        // Flags (field 1) = 3 (`FIN_ACK`), then an empty message (field 2).
        assert_eq!(
            read_write.write_buffers.concat(),
            [0x04, 0x08, 0x03, 0x12, 0x00]
        );
        assert_eq!(read_write.write_bytes_queued, 5);
        assert_eq!(read_write.write_bytes_queueable, Some(0));
    }

    #[test]
    fn fin_waits_for_room_in_the_outer_stream() {
        let mut framing = WebRtcFraming::new();
        let mut read_write = outer(&[], 100);
        drop(framing.read_write(&mut read_write).unwrap());

        // The inner substream closes its writing side while the outer stream has room for 4
        // bytes only: the `FIN` frame (5 bytes) is not written.
        let mut read_write = outer(&[], 4);
        framing.read_write(&mut read_write).unwrap().close_write();
        assert!(read_write.write_buffers.concat().is_empty());
        assert_eq!(read_write.write_bytes_queued, 0);
        assert_eq!(read_write.write_bytes_queueable, Some(4));

        // With room for 5 bytes, it is. Substreams close their writing side again at every call.
        let mut read_write = outer(&[], 5);
        framing.read_write(&mut read_write).unwrap().close_write();
        // Flags (field 1) = 0 (`FIN`), then an empty message (field 2).
        assert_eq!(
            read_write.write_buffers.concat(),
            [0x04, 0x08, 0x00, 0x12, 0x00]
        );
        assert_eq!(read_write.write_bytes_queued, 5);
        assert_eq!(read_write.write_bytes_queueable, Some(0));
    }
}
