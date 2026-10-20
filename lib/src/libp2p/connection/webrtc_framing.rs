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
    /// Data of the parsed frames that the underlying substream hasn't consumed yet. Can hold
    /// more than the substream currently wants, as frames are parsed as soon as they are
    /// complete (see [`WebRtcFraming::read_write`]).
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
/// Maximum size in bytes of the protobuf frame surrounding the message.
const PROTOBUF_FRAME_MAX_LEN: usize = 8; // TODO: calculate better?
/// Size in bytes of a frame carrying a flag and no data: length prefix, flag, empty data.
const FLAG_ONLY_FRAME_LEN: usize = 5;
const MAX_PROTOBUF_MESSAGE_LEN: usize = 16384;

impl WebRtcFraming {
    /// Initializes a new [`WebRtcFraming`].
    pub fn new() -> Self {
        WebRtcFraming {
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
        // Parse every complete frame, whatever the underlying substream expects. Many substream
        // states read nothing (an outbound notifications substream, a refused inbound one, ...),
        // and a `FIN` or `RESET_STREAM` arriving in such a state must still be processed:
        // otherwise no `FIN_ACK` is sent, the closing goes unreported, and the data channel stays
        // open until the remote resets it. The frames' data waits in `receive_buffer`.
        loop {
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
                                // TODO: what if the outer maximum queueable is <= PROTOBUF_FRAME_MAX_LEN? this will never happen in practice, but in theory it could
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
        // Copy the timer back first: the inner stream might have moved it closer, and it must
        // not overwrite the `wake_up_asap` below.
        //
        // If the inner stream consumed bytes of `receive_buffer`, it expects to be called again
        // although nothing was read from the outer `ReadWrite`, hence the immediate wake-up.
        //
        // The outer `expected_incoming_bytes` stays what the parsing loop set: what the next
        // frame needs. Raising it to what the inner stream expects would hold back a small
        // `FIN` or `RESET_STREAM` frame until that many bytes have arrived.
        self.outer_read_write.wake_up_after = self.inner_read_write.wake_up_after.clone();
        if self.inner_read_write.read_bytes != 0 {
            self.outer_read_write.wake_up_asap();
        }
        self.framing.receive_buffer = mem::take(&mut self.inner_read_write.incoming_buffer);

        // Flag to send out, if any: `FIN` once the inner stream closes its writing side,
        // `FIN_ACK` once the remote's `FIN` has been processed. `RESET_STREAM` is never sent, as
        // closing the substream serves the same purpose, nor is `STOP_SENDING`, which doesn't
        // fit in our API.
        //
        // A frame carrying data always fits in the outer credit, as the inner stream was given
        // that credit minus `PROTOBUF_FRAME_MAX_LEN`. A frame carrying only a flag might not,
        // right after a frame that used the credit up. It is then sent on a later call: the
        // inner stream asks for the close again, and `remote_write_state` stays `Closed`.
        let flag_fits = self.inner_read_write.write_bytes_queued != 0
            || self
                .outer_read_write
                .write_bytes_queueable
                .is_some_and(|queueable| queueable >= FLAG_ONLY_FRAME_LEN);
        let flag_to_send_out: Option<u32> = if !flag_fits {
            None
        } else if matches!(self.framing.local_write_state, LocalWriteState::Open)
            && self.inner_read_write.write_bytes_queueable.is_none()
        {
            self.framing.local_write_state = LocalWriteState::FinBuffered;
            Some(0)
        } else if matches!(self.framing.remote_write_state, RemoteWriteState::Closed) {
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
            debug_assert!(
                self.inner_read_write.write_bytes_queued != 0
                    || total_length == FLAG_ONLY_FRAME_LEN
            );
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

    /// Builds the outer `ReadWrite`, as the platform would: `incoming` has arrived from the data
    /// channel, and `queueable` bytes can be written to it.
    fn outer(incoming: &[u8], queueable: usize) -> ReadWrite<u64> {
        ReadWrite {
            now: 5,
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
    fn flag_waits_for_room_in_the_outer_stream() {
        let mut framing = WebRtcFraming::new();

        // The remote sends `FIN` while the outer stream has room for 3 bytes only: the `FIN_ACK`
        // frame (5 bytes) is not written.
        let mut read_write = outer(&[0x02, 0x08, 0x00], 3);
        drop(framing.read_write(&mut read_write).unwrap());
        assert_eq!(read_write.write_bytes_queued, 0);
        assert!(read_write.write_buffers.iter().all(|b| b.is_empty()));
        assert_eq!(read_write.write_bytes_queueable, Some(3));

        // Once there is room, it is.
        let mut read_write = outer(&[], 100);
        drop(framing.read_write(&mut read_write).unwrap());
        let written = read_write.write_buffers.concat();
        assert_eq!(written.len(), read_write.write_bytes_queued);
        assert!(!written.is_empty() && written.len() <= 8);
        assert_eq!(&written[1..3], &[0x08, 0x03]); // field 1 (flags) = 3, `FIN_ACK`
        assert_eq!(read_write.write_bytes_queueable, Some(100 - written.len()));
    }

    /// The inner substream does not ask for bytes (`NotificationsOut`, `NotificationsOutClosed`,
    /// `NotificationsInRefused`, ...). A remote `FIN` must still be parsed, the inner stream told
    /// that the remote closed its side, and a `FIN_ACK` written.
    #[test]
    fn fin_parsed_while_inner_expects_no_bytes() {
        let mut framing = WebRtcFraming::new();
        let mut rw = outer(&[], 100);
        // The inner substream leaves `expected_incoming_bytes` at `Some(0)`.
        drop(framing.read_write(&mut rw).unwrap());

        // Length-prefixed protobuf `Message { flag: FIN }`.
        let mut rw = outer(&[0x02, 0x08, 0x00], 100);
        let inner = framing.read_write(&mut rw).unwrap();
        let inner_expected = inner.expected_incoming_bytes;
        drop(inner);
        assert_eq!(rw.read_bytes, 3, "FIN frame left unparsed");
        assert_eq!(
            inner_expected, None,
            "inner stream not told that the remote closed"
        );
        // `Message { flag: FIN_ACK, message: "" }`.
        assert_eq!(
            rw.write_buffers.concat(),
            [0x04, 0x08, 0x03, 0x12, 0x00],
            "no FIN_ACK written"
        );
    }

    /// When the inner substream consumes bytes of `receive_buffer`, `InnerReadWrite::drop`
    /// requests an immediate wake-up of the outer `ReadWrite`. Copying the inner stream's timer
    /// back to the outer `ReadWrite` must not overwrite that wake-up.
    #[test]
    fn wake_up_asap_survives_drop() {
        let mut framing = WebRtcFraming::new();
        // A data frame carrying "abc" already arrived before the first processing.
        let mut rw = outer(&[0x05, 0x12, 0x03, b'a', b'b', b'c'], 100);
        {
            let mut inner = framing.read_write(&mut rw).unwrap();
            // The inner substream reads part of the data and expects to be called again.
            let _ = inner.incoming_bytes_take(3);
        }
        assert_eq!(rw.wake_up_after, Some(5), "wake-up lost");
    }

    /// While the inner substream waits for a large amount of data (e.g. a notification body),
    /// the outer stream must still be asked for what the *next frame* needs, so that a small
    /// `FIN` frame reaches the framing. Asking for the whole inner need makes the platform hold
    /// the `FIN` until that many bytes are buffered.
    #[test]
    fn outer_demand_is_next_frame_not_whole_inner_need() {
        let mut framing = WebRtcFraming::new();
        let mut rw = outer(&[], 100);
        {
            let mut inner = framing.read_write(&mut rw).unwrap();
            let _ = inner.incoming_bytes_take(1000);
        }
        assert!(
            rw.expected_incoming_bytes.unwrap() <= 8,
            "outer stream asked for {:?} bytes",
            rw.expected_incoming_bytes
        );
    }

    /// A frame carrying only a flag is not written while the outer credit can't hold it, as
    /// happens right after a data frame used the credit up, and is written once it can.
    #[test]
    fn flag_frame_waits_for_outer_credit() {
        let mut framing = WebRtcFraming::new();
        // `Message { flag: FIN }` arrives while only 3 bytes can be written.
        let mut rw = outer(&[0x02, 0x08, 0x00], 3);
        drop(framing.read_write(&mut rw).unwrap());
        assert!(
            rw.write_buffers.is_empty(),
            "FIN_ACK written without credit"
        );
        assert_eq!(rw.write_bytes_queueable, Some(3));

        let mut rw = outer(&[], 100);
        drop(framing.read_write(&mut rw).unwrap());
        assert_eq!(
            rw.write_buffers.concat(),
            [0x04, 0x08, 0x03, 0x12, 0x00],
            "no FIN_ACK written once there is credit"
        );
    }
}
